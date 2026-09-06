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
    const char *hostname, const char *ip4, const char *ip6)
{

	memset(rq, 0, sizeof(*rq));
	rq->op = WARDEN_OP_ENTER_JAIL;
	rq->flags = flags;
	(void)strlcpy(rq->path, path, sizeof(rq->path));
	(void)strlcpy(rq->hostname, hostname, sizeof(rq->hostname));
	(void)strlcpy(rq->ip4_addr, ip4, sizeof(rq->ip4_addr));
	(void)strlcpy(rq->ip6_addr, ip6, sizeof(rq->ip6_addr));
}

/*
 * Issue a lifecycle-control request (DESTROY or LIST) and collect the reply.
 * length lets a caller send a deliberately wrong-sized message; fd optionally
 * attaches a descriptor.  On a successful transport returns 0 and copies up to
 * rpcap reply bytes into rp (storing the actual length in *rplen when non-NULL);
 * returns -1 when the transport rejects the message (terminal).
 */
static int
control_call(struct fixture *fixture, uint32_t op, size_t length, int fd,
    void *rp, size_t rpcap, size_t *rplen, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct warden_control_request creq;
	uint8_t buffer[sizeof(struct warden_list_reply) + 16];
	int fdslot[1];

	memset(&creq, 0, sizeof(creq));
	creq.op = op;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &creq;
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
	ATF_REQUIRE(incoming.length <= rpcap);
	memcpy(rp, buffer, incoming.length);
	if (rplen != NULL)
		*rplen = incoming.length;
	if (out_fd != NULL)
		*out_fd = incoming.nfds >= 1 ? incoming.fds[0] : -1;
	return (0);
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
	init_request(&rq, 0, "/jails/example", "", "", "");
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
	init_request(&rq, 0, "/jails/example", "", "", "");
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
	init_request(&rq, 0, "/jails/example", "", "", "");
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
	init_request(&rq, WARDEN_F_EPHEMERAL | 0x4u, "/jails/example", "", "", "");
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
	init_request(&rq, 0, "relative/path", "", "", "");
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
	init_request(&rq, 0, root, "host-one", "", "");
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
	init_request(&rq, 0, root, "host-two", "", "");
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

	init_request(&rq, WARDEN_F_EPHEMERAL, root, "", "", "");
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
	init_request(&rq, WARDEN_F_EPHEMERAL, root, "", "", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	ATF_CHECK_EQ(EALREADY, rp.status);
	ATF_CHECK_EQ(-1, out_fd);

	/* Worker exit closes the owning descriptor, tearing the jail down. */
	fixture_destroy(&fixture);
	(void)rmdir(root);
}

/*
 * The full jail lifecycle over the wire: ENTER creates the caller's persistent
 * jail; LIST reports present==1 with the matching path/hostname; DESTROY removes
 * it (status 0); a second LIST reports present==0; a second DESTROY is ENOENT.
 * This is the gap this change closes — before it a persistent jail could be
 * created but never enumerated or reclaimed.
 */
ATF_TC(lifecycle_list_then_destroy);
ATF_TC_HEAD(lifecycle_list_then_destroy, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lifecycle_list_then_destroy, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	struct warden_list_reply lr;
	char root[PATH_MAX];
	size_t len;
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes the persistent jail (hostname host-life). */
	init_request(&rq, 0, root, "host-life", "", "");
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

	/* LIST reports the jail present with its definition. */
	memset(&lr, 0, sizeof(lr));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
	    sizeof(struct warden_control_request), -1, &lr, sizeof(lr), &len,
	    NULL));
	ATF_REQUIRE_EQ(sizeof(lr), len);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(1, lr.present);
	ATF_CHECK(lr.jid > 0);
	ATF_CHECK_STREQ(root, lr.path);
	ATF_CHECK_STREQ("host-life", lr.hostname);
	/* A plain persistent jail reports neither vnet nor ephemeral. */
	ATF_CHECK_MSG((lr.flags & WARDEN_F_VNET) == 0,
	    "non-vnet jail reported flags 0x%x with WARDEN_F_VNET set", lr.flags);
	ATF_CHECK_MSG((lr.flags & WARDEN_F_EPHEMERAL) == 0,
	    "persistent jail reported flags 0x%x with WARDEN_F_EPHEMERAL set",
	    lr.flags);

	/* DESTROY removes it. */
	memset(&rp, 0, sizeof(rp));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_DESTROY_JAIL,
	    sizeof(struct warden_control_request), -1, &rp, sizeof(rp), NULL,
	    NULL));
	ATF_CHECK_EQ(0, rp.status);

	/* A second LIST now reports no jail. */
	memset(&lr, 0, sizeof(lr));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
	    sizeof(struct warden_control_request), -1, &lr, sizeof(lr), NULL,
	    NULL));
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(0, lr.present);

	/* A second DESTROY is ENOENT — nothing left to remove. */
	memset(&rp, 0, sizeof(rp));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_DESTROY_JAIL,
	    sizeof(struct warden_control_request), -1, &rp, sizeof(rp), NULL,
	    NULL));
	ATF_CHECK_EQ(ENOENT, rp.status);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * ENTER with an ip6 address creates the jail with that address, and LIST reads
 * it back: the ip6.addr field round-trips through create_jail (dynamic param
 * assembly) and handle_list_jails (jail_get_ip6).  Skips where the harness cannot
 * create a live jail with an ip6 address (e.g. no INET6, or no privilege).
 */
ATF_TC(enter_with_ip6_lists_back);
ATF_TC_HEAD(enter_with_ip6_lists_back, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enter_with_ip6_lists_back, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	struct warden_list_reply lr;
	char root[PATH_MAX];
	size_t len;
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent jail carrying an ip6 address. */
	init_request(&rq, 0, root, "host-v6", "", "fd00::1");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live ip6 jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* LIST reports the jail with its ip6 address filled in. */
	memset(&lr, 0, sizeof(lr));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
	    sizeof(struct warden_control_request), -1, &lr, sizeof(lr), &len,
	    NULL));
	ATF_REQUIRE_EQ(sizeof(lr), len);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(1, lr.present);
	ATF_CHECK_STREQ(root, lr.path);
	ATF_CHECK_MSG(strcmp(lr.ip6_addr, "fd00::1") == 0,
	    "LIST reported ip6_addr \"%s\", want \"fd00::1\"", lr.ip6_addr);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * ENTER with an ip4 address creates the jail with that address, and LIST reads it
 * back: the ip4.addr field round-trips through create_jail (dynamic param
 * assembly) and handle_list_jails (jail_get_ip4).  The ip6 path had this coverage
 * but ip4 did not; a non-vnet jail also lets LIST assert flags reports no vnet.
 * Skips where the harness cannot create a live jail with an ip4 address.
 */
ATF_TC(enter_with_ip4_lists_back);
ATF_TC_HEAD(enter_with_ip4_lists_back, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enter_with_ip4_lists_back, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	struct warden_list_reply lr;
	char root[PATH_MAX];
	size_t len;
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent jail carrying an ip4 address. */
	init_request(&rq, 0, root, "host-v4", "10.99.0.1", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live ip4 jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* LIST reports the jail with its ip4 address filled in and no vnet. */
	memset(&lr, 0, sizeof(lr));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
	    sizeof(struct warden_control_request), -1, &lr, sizeof(lr), &len,
	    NULL));
	ATF_REQUIRE_EQ(sizeof(lr), len);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(1, lr.present);
	ATF_CHECK_STREQ(root, lr.path);
	ATF_CHECK_MSG(strcmp(lr.ip4_addr, "10.99.0.1") == 0,
	    "LIST reported ip4_addr \"%s\", want \"10.99.0.1\"", lr.ip4_addr);
	ATF_CHECK_MSG((lr.flags & WARDEN_F_VNET) == 0,
	    "non-vnet ip4 jail reported flags 0x%x with WARDEN_F_VNET set",
	    lr.flags);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * The full-definition reuse rule, extended to ip6: once a label's jail exists
 * with one ip6 address, a later request from that same label carrying a DIFFERENT
 * ip6 (same path and hostname) must be refused EEXIST, never silently attached
 * into the mismatched jail.  This is the key regression for the ip6 widening —
 * the ip4 rule already enforced this for v4.
 */
ATF_TC(reuse_ip6_mismatch_is_eexist);
ATF_TC_HEAD(reuse_ip6_mismatch_is_eexist, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reuse_ip6_mismatch_is_eexist, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* First ENTER establishes the persistent jail with ip6 fd00::1. */
	init_request(&rq, 0, root, "host-v6", "", "fd00::1");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live ip6 jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* Same channel/label/path/host, mismatched ip6 -> hard EEXIST. */
	init_request(&rq, 0, root, "host-v6", "", "fd00::2");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	ATF_CHECK_MSG(rp.status == EEXIST,
	    "reuse with mismatched ip6 returned status %d (%s), want EEXIST",
	    rp.status, strerror(rp.status));
	ATF_CHECK_EQ(-1, out_fd);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * ENTER with WARDEN_F_VNET creates a jail with its own virtual network stack.
 * We assert two things: the jail's "vnet" parameter reads back as JAIL_SYS_NEW,
 * and — since vnet is part of the immutable definition — a reuse of the same
 * path/hostname WITHOUT the vnet flag is refused EEXIST (a non-vnet duplicate
 * differs).  Skips where the harness cannot create a vnet jail (no VIMAGE, or no
 * privilege).
 */
ATF_TC(enter_with_vnet_creates_vnet_jail);
ATF_TC_HEAD(enter_with_vnet_creates_vnet_jail, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enter_with_vnet_creates_vnet_jail, tc)
{
	struct fixture fixture;
	struct warden_request rq;
	struct warden_reply rp;
	char root[PATH_MAX], name[64], vbuf[16];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent vnet jail. */
	init_request(&rq, WARDEN_F_VNET, root, "host-vnet", "", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live vnet jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/*
	 * The jail's vnet parameter reads back as a new (own) network stack.
	 * "vnet" is a jailsys parameter, so it exports as the string
	 * "new"/"inherit"/"disable" -- compare the string, not strtol().
	 */
	ATF_REQUIRE(warden_test_jail_name(TEST_CLIENT_LABEL, name, sizeof(name)));
	vbuf[0] = '\0';
	ATF_REQUIRE(jail_getv(0, "name", name, "vnet", vbuf, NULL) >= 0);
	ATF_CHECK_MSG(strcmp(vbuf, "new") == 0,
	    "vnet jail's vnet param = \"%s\", want \"new\"", vbuf);

	/* LIST must report the vnet nature back in flags (WARDEN_F_VNET). */
	{
		struct warden_list_reply lr;
		size_t len;

		memset(&lr, 0, sizeof(lr));
		ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
		    sizeof(struct warden_control_request), -1, &lr, sizeof(lr),
		    &len, NULL));
		ATF_REQUIRE_EQ(sizeof(lr), len);
		ATF_CHECK_EQ(1, lr.present);
		ATF_CHECK_MSG((lr.flags & WARDEN_F_VNET) != 0,
		    "LIST of a vnet jail reported flags 0x%x without WARDEN_F_VNET",
		    lr.flags);
	}

	/*
	 * A reuse of the same path/hostname without the vnet flag differs in the
	 * (immutable) definition and must be refused, proving vnet is enforced.
	 */
	init_request(&rq, 0, root, "host-vnet", "", "");
	out_fd = -1;
	ATF_REQUIRE_EQ(0, request(&fixture, &rq, sizeof(rq), -1, &rp, &out_fd));
	ATF_CHECK_MSG(rp.status == EEXIST,
	    "non-vnet reuse of a vnet jail returned status %d (%s), want EEXIST",
	    rp.status, strerror(rp.status));
	ATF_CHECK_EQ(-1, out_fd);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * A DESTROY/LIST with a wrong message length (here: only the opcode word, one
 * byte short of a warden_control_request) is a soft EPROTO reply — it is decided
 * before any jail is touched, so it needs only the channel plane.
 */
ATF_TC(control_rejects_short_message);
ATF_TC_HEAD(control_rejects_short_message, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(control_rejects_short_message, tc)
{
	struct fixture fixture;
	struct warden_reply rp;

	require_plane();
	fixture_create(&fixture);

	memset(&rp, 0, sizeof(rp));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_DESTROY_JAIL,
	    sizeof(uint32_t), -1, &rp, sizeof(rp), NULL, NULL));
	ATF_CHECK_EQ(EPROTO, rp.status);

	memset(&rp, 0, sizeof(rp));
	ATF_REQUIRE_EQ(0, control_call(&fixture, WARDEN_OP_LIST_JAILS,
	    sizeof(uint32_t), -1, &rp, sizeof(rp), NULL, NULL));
	ATF_CHECK_EQ(EPROTO, rp.status);

	fixture_destroy(&fixture);
}

/*
 * An unexpected descriptor on a DESTROY is a terminal transport rejection, not
 * a soft reply: warden's worker channel accepts no descriptors, so the transport
 * tears the channel down (mirrors rejects_unexpected_descriptor for ENTER).
 */
ATF_TC(control_rejects_unexpected_descriptor);
ATF_TC_HEAD(control_rejects_unexpected_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(control_rejects_unexpected_descriptor, tc)
{
	struct fixture fixture;
	struct warden_reply rp;
	int null, out_fd;

	require_plane();
	fixture_create(&fixture);

	null = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(null >= 0);
	out_fd = -1;
	memset(&rp, 0, sizeof(rp));
	ATF_CHECK(control_call(&fixture, WARDEN_OP_DESTROY_JAIL,
	    sizeof(struct warden_control_request), null, &rp, sizeof(rp), NULL,
	    &out_fd) == -1);
	ATF_CHECK_EQ(-1, out_fd);
	close(null);

	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rejects_unexpected_descriptor);
	ATF_TP_ADD_TC(tp, rejects_short_message);
	ATF_TP_ADD_TC(tp, rejects_unknown_opcode);
	ATF_TP_ADD_TC(tp, rejects_unknown_flag_bits);
	ATF_TP_ADD_TC(tp, rejects_relative_path);
	ATF_TP_ADD_TC(tp, reuse_definition_mismatch_is_eexist);
	ATF_TP_ADD_TC(tp, enter_with_ip4_lists_back);
	ATF_TP_ADD_TC(tp, enter_with_ip6_lists_back);
	ATF_TP_ADD_TC(tp, reuse_ip6_mismatch_is_eexist);
	ATF_TP_ADD_TC(tp, enter_with_vnet_creates_vnet_jail);
	ATF_TP_ADD_TC(tp, second_ephemeral_enter_is_ealready);
	ATF_TP_ADD_TC(tp, lifecycle_list_then_destroy);
	ATF_TP_ADD_TC(tp, control_rejects_short_message);
	ATF_TP_ADD_TC(tp, control_rejects_unexpected_descriptor);
	return (atf_no_error());
}
