/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <channel.h>
#include <fidl/bsd.trace.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <tracecmp.h>

#include "tracecmp_test.h"

/*
 * The real per-session bsd.trace.v1 server runs in a forked child; the test
 * drives it with the generated client bindings (the encoder libtracecmp
 * uses), or with hand-built frames on a raw libservice session.
 */
struct fixture {
	struct fidl_bsd_connection *client;
	struct service_session *session;	/* raw-frame cases */
	pid_t child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
#define ORD_INFO	UINT64_C(0x2e66741ad337c4a3)
#define ORD_OPEN	UINT64_C(0x0e3e651227c85ded)

static void
channel_pair(int *client, int *provider)
{

	int pair[2];

	ATF_REQUIRE_EQ(0, mac_capability_channel_create(pair));
	*client = pair[0];
	*provider = pair[1];
}

/*
 * Core session fixture.  `rights` are the rights stamped onto the session's
 * grant (SERVICE_RIGHTS_ADMIN for the admin-bypass path, SERVICE_RIGHTS_NONE for
 * an ordinary label-scoped session).  `pin_consumer` models bsdtrace start_session:
 * the privileged DTrace consumer is opened, and thus a raw fd is available to
 * delegate, ONLY for a session that could ever be authorized (admin or an
 * allowlisted label).  An unauthorized session pins no consumer, so it is created
 * with pin_consumer == false to reflect that no privileged state exists on its
 * behalf.
 */
static void
fixture_create_full(struct fixture *fixture, bool authorized, int device_error,
    service_rights_t rights, bool pin_consumer)
{
	int client, provider, dtrace_fd;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	dtrace_fd = (pin_consumer && device_error == 0) ?
	    open("/dev/null", O_RDONLY | O_CLOEXEC) : -1;
	ATF_REQUIRE(!pin_consumer || device_error != 0 || dtrace_fd >= 0);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(tracecmp_test_serve(provider, dtrace_fd, authorized,
		    device_error, "org.test.trace", rights));
	}
	close(provider);
	if (dtrace_fd >= 0)
		close(dtrace_fd);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->client));
}

static void
fixture_raw(struct fixture *fixture)
{
	int client, provider, dtrace_fd;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	dtrace_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(dtrace_fd >= 0);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(tracecmp_test_serve(provider, dtrace_fd, true, 0,
		    "org.test.trace", SERVICE_RIGHTS_ADMIN));
	}
	close(provider);
	close(dtrace_fd);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create(struct fixture *fixture, bool authorized, int device_error)
{

	/*
	 * The session holds SERVICE_RIGHTS_ADMIN (P5): the capability replacement
	 * for the old root bypass the tests relied on (they run as root).  A
	 * session with the admin right obtains the raw DTrace fd regardless of the
	 * label allowlist, so the consumer is always pinned when the device is
	 * available.
	 */
	fixture_create_full(fixture, authorized, device_error,
	    SERVICE_RIGHTS_ADMIN, true);
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	if (fixture->client != NULL)
		fidl_bsd_connection_destroy(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

struct result {
	bool done;
	int error;		/* transport */
	int status;		/* application errno */
	uint32_t features;
	int fd;
	uint64_t opened, rejected;
};

static void
wait_for(struct fixture *fixture, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fixture->client, &r->done,
		    &deadline);
	ATF_REQUIRE_EQ_MSG(0, r->error, "call failed: %s", strerror(r->error));
}

static void
info_done(void *p, int error, struct bsd_trace_v1_ProtocolInfo *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error) {
		ATF_REQUIRE_EQ(TRACECMP_WIRE_VERSION, v->wire_version);
		r->features = v->features;
	}
}

static void
open_done(void *p, int error, struct bsd_trace_v1_Trace_Open_Result *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_trace_v1_Trace_Open_Result_err_tag)
		r->status = (int)v->value.err;
	else
		r->fd = fidl_bsd_take_fd(&v->value.response.dtrace);
}

static void
stats_done(void *p, int error, struct bsd_trace_v1_TraceStats *v)
{
	struct result *r = p;
	r->done = true;
	r->error = error;
	if (!error) {
		r->opened = v->opened;
		r->rejected = v->rejected;
	}
}

/* Negotiate; returns the advertised features. */
static uint32_t
hello(struct fixture *fixture)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_trace_v1_Trace_GetProtocolInfo(fixture->client, &empty,
	    info_done, &r, &txid);
	wait_for(fixture, &r);
	return (r.features);
}

/* Open; returns the application errno and the delivered descriptor. */
static int
open_consumer(struct fixture *fixture, int *fd)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_trace_v1_Trace_Open(fixture->client, &empty, open_done,
	    &r, &txid);
	wait_for(fixture, &r);
	*fd = r.fd;
	return (r.status);
}

static void
get_stats(struct fixture *fixture, uint64_t *opened, uint64_t *rejected)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_trace_v1_Trace_Stats(fixture->client, &empty,
	    stats_done, &r, &txid);
	wait_for(fixture, &r);
	*opened = r.opened;
	*rejected = r.rejected;
}

/* A raw frame (optionally with a descriptor); returns the call result. */
static int
raw_frame(struct service_session *session, const void *data, size_t length,
    int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[64];
	int received = -1, rc;

	outgoing = (struct service_message){
		.size = sizeof(outgoing), .data = data, .length = length,
		.fds = fd >= 0 ? &fd : NULL, .nfds = fd >= 0 ? 1 : 0,
	};
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &received;
	incoming.fd_capacity = 1;
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && incoming.nfds != 0 && received >= 0)
		close(received);
	return (rc);
}

ATF_TC(authorized_descriptor_is_one_shot);
ATF_TC_HEAD(authorized_descriptor_is_one_shot, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(authorized_descriptor_is_one_shot, tc)
{
	struct fixture fixture;
	uint64_t opened, rejected;
	int fd;

	fixture_create(&fixture, true, 0);
	ATF_CHECK_EQ(TRACECMP_FEATURE_RAW_DTRACE_FD, hello(&fixture));
	fd = -1;
	ATF_CHECK_EQ(0, open_consumer(&fixture, &fd));
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);
	ATF_CHECK_EQ(EALREADY, open_consumer(&fixture, &fd));
	ATF_CHECK_EQ(-1, fd);
	get_stats(&fixture, &opened, &rejected);
	ATF_CHECK_EQ(1, opened);
	ATF_CHECK_EQ(1, rejected);
	fixture_destroy(&fixture);
}

ATF_TC(authorization_and_device_failures);
ATF_TC_HEAD(authorization_and_device_failures, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC(unexpected_descriptor_poison_session);
ATF_TC_HEAD(unexpected_descriptor_poison_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unexpected_descriptor_poison_session, tc)
{
	struct wire_header info = { 1, { 2, 0, 0 }, 1, ORD_INFO };
	struct fixture fixture;
	int fd;

	/* A descriptor on any request ends the session, unanswered. */
	fixture_raw(&fixture);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(-1, raw_frame(fixture.session, &info, sizeof(info), fd));
	close(fd);
	ATF_CHECK_EQ(-1, raw_frame(fixture.session, &info, sizeof(info), -1));
	fixture_destroy(&fixture);
}

ATF_TC(malformed_frames_end_the_session);
ATF_TC_HEAD(malformed_frames_end_the_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(malformed_frames_end_the_session, tc)
{
	struct wire_header frame;
	struct tracecmp_msg legacy;
	struct fixture fixture;
	int fd, mode;

	for (mode = 0; mode < 5; mode++) {
		fixture_raw(&fixture);
		frame = (struct wire_header){ 2, { 2, 0, 0 }, 1, ORD_OPEN };
		if (mode > 0) {
			/* Negotiate first, so the rejection is the frame's. */
			struct wire_header info = { 1, { 2, 0, 0 }, 1,
				ORD_INFO };
			ATF_REQUIRE_EQ(0, raw_frame(fixture.session, &info,
			    sizeof(info), -1));
		}
		switch (mode) {
		case 0:	/* Open before negotiation. */
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &frame,
			    sizeof(frame), -1));
			break;
		case 1:	/* Unknown strict method. */
			frame.ordinal = 0x7fff;
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &frame,
			    sizeof(frame), -1));
			break;
		case 2:	/* Truncated header. */
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &frame, 8,
			    -1));
			break;
		case 3:	/* Trailing bytes on a body-less method. */
		{
			uint8_t bytes[24] = { 0 };
			memcpy(bytes, &frame, sizeof(frame));
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, bytes,
			    sizeof(bytes), -1));
			break;
		}
		case 4:	/* A pre-FIDL OPEN record. */
			memset(&legacy, 0, sizeof(legacy));
			legacy.magic = TRACECMP_MAGIC;
			legacy.opcode = TRACECMP_OP_OPEN;
			ATF_CHECK_EQ(-1, raw_frame(fixture.session, &legacy,
			    sizeof(legacy), -1));
			break;
		}
		/* No consumer was delivered and the session is over. */
		ATF_CHECK_EQ(-1, raw_frame(fixture.session, &frame,
		    sizeof(frame), -1));
		fixture_destroy(&fixture);
	}
	(void)fd;
}
ATF_TC_BODY(authorization_and_device_failures, tc)
{
	struct fixture fixture;
	int fd;

	/*
	 * A session holding SERVICE_RIGHTS_ADMIN bypasses the label allowlist:
	 * an unauthorized-label session still obtains the raw DTrace fd.
	 */
	fixture_create(&fixture, false, 0);
	(void)hello(&fixture);
	fd = -1;
	ATF_CHECK_EQ(0, open_consumer(&fixture, &fd));
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	fixture_destroy(&fixture);

	fixture_create(&fixture, true, ENXIO);
	ATF_CHECK_EQ(0, hello(&fixture));
	ATF_CHECK_EQ(ENXIO, open_consumer(&fixture, &fd));
	ATF_CHECK_EQ(-1, fd);
	fixture_destroy(&fixture);
}

/*
 * bsdtrace-2 hardening: a session whose label is NOT in the allowlist and which
 * holds no admin right must be refused OPEN with EACCES and must receive no
 * DTrace consumer descriptor.  The provider also pins no privileged consumer on
 * its behalf (modelled here by a fixture created without a consumer fd), so an
 * unauthorized client cannot cause a privileged /dev/dtrace consumer to be
 * opened or delegated.
 */
ATF_TC(unauthorized_open_is_denied_without_pinning_consumer);
ATF_TC_HEAD(unauthorized_open_is_denied_without_pinning_consumer, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unauthorized_open_is_denied_without_pinning_consumer, tc)
{
	struct fixture fixture;
	uint64_t opened, rejected;
	int fd;

	fixture_create_full(&fixture, false, 0, SERVICE_RIGHTS_NONE, false);
	/* Negotiation must not advertise the raw-fd feature. */
	ATF_CHECK_EQ(0, hello(&fixture));
	/* Open is refused EACCES with no descriptor delivered. */
	fd = -1;
	ATF_CHECK_EQ(EACCES, open_consumer(&fixture, &fd));
	ATF_CHECK_EQ(-1, fd);
	get_stats(&fixture, &opened, &rejected);
	ATF_CHECK_EQ(0, opened);
	ATF_CHECK_EQ(1, rejected);
	fixture_destroy(&fixture);
}

/*
 * The complement of the admin-bypass path (authorized_descriptor_is_one_shot):
 * an allowlisted label with NO admin right is authorized by the label alone and
 * is delegated the raw consumer fd on OPEN.  The harness delivers a plain fd, so
 * the 15-ioctl cap_ioctls allowlist (applied by open_dtrace_consumer in the
 * non-test build) is not reachable here; that limiting is deferred to a
 * privileged, real-/dev/dtrace harness.
 */
ATF_TC(authorized_label_open_delivers_consumer_fd);
ATF_TC_HEAD(authorized_label_open_delivers_consumer_fd, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(authorized_label_open_delivers_consumer_fd, tc)
{
	struct fixture fixture;
	int fd;

	fixture_create_full(&fixture, true, 0, SERVICE_RIGHTS_NONE, true);
	ATF_CHECK_EQ(TRACECMP_FEATURE_RAW_DTRACE_FD, hello(&fixture));
	fd = -1;
	ATF_CHECK_EQ(0, open_consumer(&fixture, &fd));
	ATF_CHECK(fd >= 0 && fcntl(fd, F_GETFD) >= 0);
	if (fd >= 0)
		close(fd);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_test_serve(-1, -1, false, 0, "test",
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_test_serve(0, -2, false, 0, "test",
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_test_serve(0, -1, false, -1, "test",
	    SERVICE_RIGHTS_ADMIN) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    tracecmp_test_serve(0, -1, false, 0, "",
	    SERVICE_RIGHTS_ADMIN) == -1);
}

ATF_TC_WITHOUT_HEAD(worker_descriptors_cross_exactly_one_fork);
ATF_TC_BODY(worker_descriptors_cross_exactly_one_fork, tc)
{
	pid_t child, grandchild, sibling;
	int fd, status;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tracecmp_test_prepare_worker_fd(fd));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (fcntl(fd, F_GETFD) == -1)
			_exit(1);
		grandchild = fork();
		if (grandchild == -1)
			_exit(2);
		if (grandchild == 0)
			_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 3);
		if (waitpid(grandchild, &status, 0) != grandchild ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));

	/* The first fork consumed the parent's one-fork allowance too. */
	sibling = fork();
	ATF_REQUIRE(sibling >= 0);
	if (sibling == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	ATF_REQUIRE_EQ(sibling, waitpid(sibling, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(fd);
}

/*
 * Exercise the production directory/open/hardening path without requiring
 * root or loaded DTrace modules. Capability lookup checks precede device open.
 */
ATF_TC_WITHOUT_HEAD(consumer_open_retains_only_delegated_rights);
ATF_TC_BODY(consumer_open_retains_only_delegated_rights, tc)
{
	cap_rights_t rights;
	int devdir, fd;

	ATF_REQUIRE_EQ(0, mkdir("dtrace", 0700));
	fd = open("dtrace/dtrace", O_CREAT | O_RDWR | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	/* Reproduce the old directory mask: O_RDWR fails before device open. */
	devdir = open("dtrace", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(devdir >= 0);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_FSTAT,
	    CAP_IOCTL);
	ATF_REQUIRE_EQ(0, cap_rights_limit(devdir, &rights));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    openat(devdir, "dtrace", O_RDWR | O_CLOEXEC | O_NOFOLLOW) == -1);
	close(devdir);
	devdir = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(devdir >= 0);
	fd = tracecmp_test_open_consumer(devdir);
	ATF_REQUIRE_MSG(fd >= 0, "consumer open: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ, CAP_WRITE, CAP_FSTAT,
	    CAP_IOCTL));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_SEEK));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_LOOKUP));
	close(fd);
	close(devdir);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, authorized_descriptor_is_one_shot);
	ATF_TP_ADD_TC(tp, authorization_and_device_failures);
	ATF_TP_ADD_TC(tp, unauthorized_open_is_denied_without_pinning_consumer);
	ATF_TP_ADD_TC(tp, authorized_label_open_delivers_consumer_fd);
	ATF_TP_ADD_TC(tp, unexpected_descriptor_poison_session);
	ATF_TP_ADD_TC(tp, malformed_frames_end_the_session);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, consumer_open_retains_only_delegated_rights);
	ATF_TP_ADD_TC(tp, worker_descriptors_cross_exactly_one_fork);
	return (atf_no_error());
}
