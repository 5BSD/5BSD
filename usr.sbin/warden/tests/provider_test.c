/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Plane tests for warden(8)'s per-client request handler.
 *
 * A real capability channel is created through /dev/mac_capability; warden's
 * worker (warden_test_worker) runs the provider end in a forked child while the
 * test drives the client end with a libservice session, exactly as it would in
 * production over a held system.Namespace channel.
 *
 * The message-validation cases (bad length, unexpected descriptor, unknown
 * opcode/flag bits, relative path) are decided before any jail is touched, so
 * they need only the channel plane (root + the mac_capability device).  The
 * live-jail cases (definition-mismatch reuse -> EEXIST, a second ephemeral ENTER
 * on one channel -> EALREADY) additionally require the privilege to run
 * jail_set(2) against a real root path; where that is not available under the
 * harness they SKIP with a clear reason rather than fail.
 *
 * NOTE: in a non-root or plane-less environment (e.g. an unprivileged build
 * jail) every case here SKIPs at the channel-setup step.  The injectivity and
 * validation logic itself is covered without the plane by jailname_test.
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "warden_proto.h"
#include "warden_test.h"

#define	TEST_CLIENT_LABEL	"org.test.warden.client"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
};

/* Open a capability endpoint by well-known name, or -1 (errno preserved). */
static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (control < 0)
		return (-1);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

/*
 * The whole suite depends on being able to mint a channel pair through the
 * capability device.  When that is not possible (device absent, or no
 * permission because the test is unprivileged) the plane cases cannot run.
 */
static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
	close(fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE_MSG(*client >= 0, "connect channel: %s", strerror(errno));
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void
fixture_create(struct fixture *fixture)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(warden_test_worker(provider, TEST_CLIENT_LABEL));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

/*
 * Issue one request and collect the reply.  length lets a caller send a
 * deliberately wrong-sized message; fd optionally attaches a descriptor.  On a
 * successful transport, returns 0, fills *rp, and (when out_fd != NULL) reports
 * the returned descriptor or -1 if none.
 */
static int
request(struct fixture *fixture, const struct warden_request *rq, size_t length,
    int fd, struct warden_reply *rp, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t buffer[sizeof(struct warden_reply) + 16];
	int fdslot[1];

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = rq;
	outgoing.length = length;
	if (fd >= 0) {
		fdslot[0] = fd;
		outgoing.fds = fdslot;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = buffer;
	incoming.capacity = sizeof(buffer);
	incoming.fds = fdslot;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	if (service_session_call(fixture->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	ATF_REQUIRE(incoming.length >= sizeof(*rp));
	memcpy(rp, buffer, sizeof(*rp));
	if (out_fd != NULL)
		*out_fd = incoming.nfds >= 1 ? incoming.fds[0] : -1;
	return (0);
}

static void
init_request(struct warden_request *rq, uint32_t flags, const char *path,
    const char *hostname, const char *ip4)
{

	memset(rq, 0, sizeof(*rq));
	rq->op = WARDEN_OP_ENTER_JAIL;
	rq->flags = flags;
	(void)strlcpy(rq->path, path, sizeof(rq->path));
	(void)strlcpy(rq->hostname, hostname, sizeof(rq->hostname));
	(void)strlcpy(rq->ip4_addr, ip4, sizeof(rq->ip4_addr));
}

ATF_TC(rejects_unexpected_descriptor);
ATF_TC_HEAD(rejects_unexpected_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_unexpected_descriptor, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	int null, out_fd;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "/jails/example", "", "");
	null = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(null >= 0);
	out_fd = -1;
	/*
	 * An unexpected descriptor is a terminal protocol violation.  warden's
	 * worker channel accepts no descriptors (max_queued_fds == 0), so the
	 * transport rejects the message and tears the channel down rather than
	 * delivering it to the handler for a soft EPROTO reply -- the call
	 * therefore fails outright.  Fail-closed either way; this locks in the
	 * observed terminal behavior (cf. auditbrokerd's
	 * provider_unexpected_descriptor_is_terminal).
	 */
	ATF_CHECK(request(&fixture, &rq, sizeof(rq), null, &rp, &out_fd) == -1);
	ATF_CHECK_EQ(-1, out_fd);
	close(null);
	fixture_destroy(&fixture);
}

ATF_TC(rejects_short_message);
ATF_TC_HEAD(rejects_short_message, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_short_message, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "/jails/example", "", "");
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq.op) + sizeof(rq.flags),
	    -1, &rp, NULL));
	ATF_CHECK_EQ(EPROTO, rp.status);
	fixture_destroy(&fixture);
}

ATF_TC(rejects_unknown_opcode);
ATF_TC_HEAD(rejects_unknown_opcode, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_unknown_opcode, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "/jails/example", "", "");
	rq.op = 0x4242;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, NULL));
	ATF_CHECK_EQ(EINVAL, rp.status);
	fixture_destroy(&fixture);
}

ATF_TC(rejects_unknown_flag_bits);
ATF_TC_HEAD(rejects_unknown_flag_bits, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_unknown_flag_bits, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, WARDEN_F_EPHEMERAL | 0x2u, "/jails/example", "", "");
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, NULL));
	ATF_CHECK_EQ(EINVAL, rp.status);
	fixture_destroy(&fixture);
}

ATF_TC(rejects_relative_path);
ATF_TC_HEAD(rejects_relative_path, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_relative_path, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "relative/path", "", "");
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, NULL));
	ATF_CHECK_EQ(EINVAL, rp.status);
	fixture_destroy(&fixture);
}

/* Absolute jail root under the test work directory; caller must rmdir it. */
static void
make_jail_root(char *out, size_t outsz)
{
	char cwd[PATH_MAX];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	(void)snprintf(out, outsz, "%s/jailroot.XXXXXX", cwd);
	ATF_REQUIRE_MSG(mkdtemp(out) != NULL, "mkdtemp: %s", strerror(errno));
}

/* Best-effort removal of the persistent jail this suite may have created. */
static void
remove_named_jail(const char *label)
{
	char name[64];
	int jid;

	if (!warden_test_jail_name(label, name, sizeof(name)))
		return;
	jid = jail_getid(name);
	if (jid > 0)
		(void)jail_remove(jid);
}

/*
 * The full-definition reuse check: once a label's jail exists, a later request
 * from that same label whose definition DIFFERS (here: a different hostname)
 * must be refused with EEXIST, never silently attached into the mismatched jail.
 */
ATF_TC(reuse_definition_mismatch_is_eexist);
ATF_TC_HEAD(reuse_definition_mismatch_is_eexist, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reuse_definition_mismatch_is_eexist, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* First ENTER establishes the persistent jail (hostname host-one). */
	init_request(&rq, 0, root, "host-one", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live jail creation not available under harness: %s",
		    strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* Same channel/label, mismatched definition -> hard EEXIST. */
	init_request(&rq, 0, root, "host-two", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	ATF_CHECK_MSG(rp.status == EEXIST,
	    "reuse with mismatched hostname returned status %d (%s), want EEXIST",
	    rp.status, strerror(rp.status));
	ATF_CHECK_EQ(-1, out_fd);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * A channel that has already anchored an ephemeral jail must refuse a second
 * ENTER (EALREADY) rather than clobber its single owning-descriptor slot and
 * tear down the jail the consumer is still using.
 */
ATF_TC(second_ephemeral_enter_is_ealready);
ATF_TC_HEAD(second_ephemeral_enter_is_ealready, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(second_ephemeral_enter_is_ealready, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	init_request(&rq, WARDEN_F_EPHEMERAL, root, "", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live jail creation not available under harness: %s",
		    strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* Second ephemeral ENTER on the same channel is refused. */
	init_request(&rq, WARDEN_F_EPHEMERAL, root, "", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	ATF_CHECK_EQ(EALREADY, rp.status);
	ATF_CHECK_EQ(-1, out_fd);

	/* Worker exit closes the owning descriptor, tearing the jail down. */
	fixture_destroy(&fixture);
	(void)rmdir(root);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rejects_unexpected_descriptor);
	ATF_TP_ADD_TC(tp, rejects_short_message);
	ATF_TP_ADD_TC(tp, rejects_unknown_opcode);
	ATF_TP_ADD_TC(tp, rejects_unknown_flag_bits);
	ATF_TP_ADD_TC(tp, rejects_relative_path);
	ATF_TP_ADD_TC(tp, reuse_definition_mismatch_is_eexist);
	ATF_TP_ADD_TC(tp, second_ephemeral_enter_is_ealready);
	return (atf_no_error());
}
