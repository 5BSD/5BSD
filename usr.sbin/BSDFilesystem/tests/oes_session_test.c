/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.OES broker session (bsdfilesystem_oes_serve, bsd.oes.v1) over a
 * real capability channel with a scripted descriptor factory: negotiation is
 * required, one OpenNotify is answered per session, a factory error carries no
 * descriptor, and malformed frames close the session without opening one.
 * The real factory is exercised by oes_handoff_test.
 */
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.oes.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <oes_broker_protocol.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The factory runs in the serving child; it reports each open on a pipe. */
static int open_error, open_report = -1;

static int
fake_factory(int root)
{
	int p[2];

	(void)root;
	(void)write(open_report, "o", 1);
	if (open_error)
		return (errno = open_error, -1);
	if (pipe(p) != 0)
		return (-1);
	close(p[1]);
	return (p[0]);
}
#define bsdfilesystem_oes_open_notify fake_factory
#include "../oes_session.c"

#define	ORD_INFO	UINT64_C(0x1ac6c3e65cdd78ba)
#define	ORD_NOTIFY	UINT64_C(0x4dba6398e6892924)

struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};

struct broker {
	pid_t child;
	int opens;			/* read end of the open reports */
	int fd;				/* the client's channel end */
};

static void
require_plane(int ends[2])
{
	if (mac_capability_channel_create(ends) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("capability channel syscall unavailable");
		atf_tc_fail("channel creation: %s", strerror(errno));
	}
}

static void
broker_start(struct broker *b)
{
	int ends[2], reports[2];

	require_plane(ends);
	ATF_REQUIRE_EQ(0, pipe(reports));
	b->child = fork();
	ATF_REQUIRE(b->child >= 0);
	if (b->child == 0) {
		close(ends[0]);
		close(reports[0]);
		open_report = reports[1];
		_exit(bsdfilesystem_oes_serve(-1, ends[1]));
	}
	close(ends[1]);
	close(reports[1]);
	b->opens = reports[0];
	b->fd = ends[0];
}

/* Reap the broker; returns how many descriptors its factory opened. */
static int
broker_finish(struct broker *b, int expected_status)
{
	char buf[8];
	ssize_t n;
	int status;

	ATF_REQUIRE_EQ(b->child, waitpid(b->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
	n = read(b->opens, buf, sizeof(buf));
	close(b->opens);
	return (n < 0 ? 0 : (int)n);
}

struct result {
	bool done;
	int error;
	int status;
	int fd;
};

static void
info_done(void *p, int error, struct bsd_oes_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		r->status = v->wire_version == OES_BROKER_VERSION ? 0 : -1;
}

static void
notify_done(void *p, int error, struct bsd_oes_v1_Broker_OpenNotify_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_oes_v1_Broker_OpenNotify_Result_err_tag)
		r->status = (int)v->value.err;
	else
		r->fd = fidl_bsd_take_fd(&v->value.response.client);
}

static void
wait_result(struct fidl_bsd_connection *c, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(c, &r->done, &deadline);
}

/* Negotiate, then one OpenNotify; returns its errno and descriptor. */
static int
open_notify(struct fidl_bsd_connection *c, int *fdp)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_oes_v1_Broker_GetProtocolInfo(c, &empty, info_done, &r,
	    &txid);
	wait_result(c, &r);
	ATF_REQUIRE_EQ(0, r.error);
	ATF_REQUIRE_EQ(0, r.status);
	r = (struct result){ .fd = -1 };
	r.error = bsd_oes_v1_Broker_OpenNotify(c, &empty, notify_done, &r,
	    &txid);
	wait_result(c, &r);
	ATF_REQUIRE_EQ(0, r.error);
	*fdp = r.fd;
	return (r.status);
}

/* Send raw bytes; -1 when the broker closed instead of answering. */
static int
send_raw(int fd, const void *data, size_t length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing = { .size = sizeof(outgoing),
		.data = data, .length = length };
	uint8_t reply[64];
	int received = -1;
	struct service_reply incoming = { .size = sizeof(incoming),
		.data = reply, .capacity = sizeof(reply), .fds = &received,
		.fd_capacity = 1 };
	struct service_session *session;
	int rc;

	ATF_REQUIRE_EQ(0, service_session_create(fd, &session));
	options.timeout_ms = 5000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	ATF_CHECK(rc == 0 || errno != ETIMEDOUT);
	if (received >= 0)
		close(received);
	service_session_close(session);
	return (rc);
}

static int
send_frame(int fd, uint64_t ordinal, const void *body, size_t length)
{
	uint8_t frame[64];
	struct wire_header h = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(h) + length <= sizeof(frame));
	memcpy(frame, &h, sizeof(h));
	if (length != 0)
		memcpy(frame + sizeof(h), body, length);
	return (send_raw(fd, frame, sizeof(h) + length));
}

ATF_TC_WITHOUT_HEAD(reject_before_open);
ATF_TC_BODY(reject_before_open, tc)
{
	struct broker b;
	uint64_t trailing = 0;

	/* OpenNotify before negotiation. */
	broker_start(&b);
	ATF_CHECK_EQ(-1, send_frame(b.fd, ORD_NOTIFY, NULL, 0));
	ATF_CHECK_EQ(0, broker_finish(&b, 1));
	/* OpenNotify with a body it does not have. */
	broker_start(&b);
	ATF_CHECK_EQ(-1, send_frame(b.fd, ORD_NOTIFY, &trailing,
	    sizeof(trailing)));
	ATF_CHECK_EQ(0, broker_finish(&b, 1));
	/* A pre-FIDL record. */
	broker_start(&b);
	{
		struct oes_broker_message legacy = { .magic = OES_BROKER_MAGIC,
			.version = OES_BROKER_VERSION,
			.operation = OES_BROKER_OPEN_NOTIFY };

		ATF_CHECK_EQ(-1, send_raw(b.fd, &legacy, sizeof(legacy)));
	}
	ATF_CHECK_EQ(0, broker_finish(&b, 1));
}

ATF_TC_WITHOUT_HEAD(one_grant_per_session);
ATF_TC_BODY(one_grant_per_session, tc)
{
	struct fidl_bsd_connection *c;
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	struct broker b;
	uint32_t txid;
	int fd = -1;

	broker_start(&b);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(b.fd, FIDL_BSD_CLIENT, &c));
	ATF_CHECK_EQ(0, open_notify(c, &fd));
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	close(fd);
	/* The session ends after its one grant. */
	r.error = bsd_oes_v1_Broker_OpenNotify(c, &empty, notify_done, &r,
	    &txid);
	wait_result(c, &r);
	ATF_CHECK(r.error != 0);
	ATF_CHECK_EQ(-1, r.fd);
	fidl_bsd_connection_destroy(c);
	ATF_CHECK_EQ(1, broker_finish(&b, 0));
}

ATF_TC_WITHOUT_HEAD(factory_error_has_no_descriptor);
ATF_TC_BODY(factory_error_has_no_descriptor, tc)
{
	struct fidl_bsd_connection *c;
	struct broker b;
	int fd = -1;

	open_error = ENXIO;
	broker_start(&b);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(b.fd, FIDL_BSD_CLIENT, &c));
	ATF_CHECK_EQ(ENXIO, open_notify(c, &fd));
	ATF_CHECK_EQ(-1, fd);
	fidl_bsd_connection_destroy(c);
	ATF_CHECK_EQ(1, broker_finish(&b, 0));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reject_before_open);
	ATF_TP_ADD_TC(tp, one_grant_per_session);
	ATF_TP_ADD_TC(tp, factory_error_has_no_descriptor);
	return (atf_no_error());
}
