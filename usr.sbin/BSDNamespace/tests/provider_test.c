/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Plane tests for bsdnamespace(8)'s per-client bsd.namespace.v1 server.
 *
 * A real capability channel is created through /dev/mac_capability; bsdnamespace's
 * worker (bsdnamespace_test_worker) runs the provider end in a forked child while the
 * test drives the client end with the generated bsd.namespace.v1 client bindings
 * (the encoder libnamespacecmp uses), exactly as it would in production over a
 * held system.Namespace channel.  Adversarial frames go through a raw libservice
 * session.
 *
 * The message-validation cases (malformed frames, unexpected descriptor, unknown
 * method or flag bits, relative path, embedded NUL) are decided before any jail
 * is touched, so they need only the channel plane (root + the mac_capability
 * device).  The live-jail cases (definition-mismatch reuse -> EEXIST, a second
 * ephemeral Enter on one session -> EALREADY) additionally require the privilege
 * to run jail_set(2) against a real root path; where that is not available under
 * the harness they SKIP with a clear reason rather than fail.
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
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fidl/bsd.namespace.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>

#include "bsdnamespace_proto.h"
#include "bsdnamespace_test.h"

#define	TEST_CLIENT_LABEL	"org.test.bsdnamespace.client"

struct fixture {
	struct fidl_bsd_connection *client;	/* generated client */
	struct service_session	*session;	/* raw frames */
	pid_t			 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");

#define	ORD_INFO	UINT64_C(0x11468a93efb7d5cb)
#define	ORD_ENTER	UINT64_C(0x03c4615a24617c51)
#define	ORD_DESTROY	UINT64_C(0x7f330ab1fffed03c)
#define	ORD_LIST	UINT64_C(0x2e2c8e6b0182430d)

struct result {
	bool done;
	int error;		/* transport error */
	int status;		/* application errno */
	uint32_t value;
	int fd;
	struct bsdnamespace_list_reply *list;
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

/*
 * Mint a held SYS_GATE_JAIL token for the worker child, standing in for the one
 * switchboard delivers in production.  Claims JAIL on a fresh "system" connection
 * (the test image's plane is unclaimed), mints a token, and authorizes it for
 * this process's nonce so the worker's gated calls pass the per-call nonce check.
 * Returns the token fd, or -1 (the worker then runs without a jail capability and
 * every gated op returns ENOTCAPABLE).
 *
 * The "system" connection is left open ON PURPOSE: a gate claim lives on its
 * connection, and sys_holds_gate() requires a claim covering the gate at call
 * time (the token alone is not enough).  Closing it would release the JAIL claim
 * and every gated op would then fail EPERM.  In production capsule holds the
 * claim connection for its whole lifetime; here the short-lived worker child does
 * the same by leaking sysfd until it _exit()s.
 */
static int
mint_jail_token(void)
{
	struct mac_capability_call_args ca;
	struct sys_request req;
	int sysfd, tok = -1;

	sysfd = capability_connect("system");
	if (sysfd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = SYS_GATE_JAIL;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = &tok;
	ca.reply_nfds = 1;
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0 || tok < 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(tok, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(tok);
		goto fail;
	}
	return (tok);		/* keep sysfd open: the claim must outlive the token */
fail:
	close(sysfd);
	return (-1);
}

static void
wait_result(struct fixture *fixture, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 10000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fixture->client, &r->done,
		    &deadline);
}

static void
info_done(void *p, int error, struct bsd_namespace_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}

/*
 * Stand up a worker serving `label` on one end of a fresh channel.  The client
 * end is a negotiated generated client, or (raw) a libservice session.
 */
static void
fixture_start(struct fixture *fixture, const char *label, bool raw)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		int tok;

		close(client);
		/* Hold a jail capability before serving, as production does. */
		tok = mint_jail_token();
		if (tok >= 0)
			bsdnamespace_test_set_jail_token(tok);
		_exit(bsdnamespace_test_worker(provider, label));
	}
	close(provider);
	if (raw) {
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->client));
	r.error = bsd_namespace_v1_Namespace_GetProtocolInfo(fixture->client,
	    &empty, info_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	ATF_REQUIRE_EQ(BSDNAMESPACE_WIRE_VERSION, r.value);
}

static void
fixture_create(struct fixture *fixture)
{

	fixture_start(fixture, TEST_CLIENT_LABEL, false);
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

static void
init_request(struct bsdnamespace_request *rq, uint32_t flags, const char *path,
    const char *hostname, const char *ip4, const char *ip6)
{

	memset(rq, 0, sizeof(*rq));
	rq->op = BSDNAMESPACE_OP_ENTER_JAIL;
	rq->flags = flags;
	(void)strlcpy(rq->path, path, sizeof(rq->path));
	(void)strlcpy(rq->hostname, hostname, sizeof(rq->hostname));
	(void)strlcpy(rq->ip4_addr, ip4, sizeof(rq->ip4_addr));
	(void)strlcpy(rq->ip6_addr, ip6, sizeof(rq->ip6_addr));
}

static void
enter_done(void *p, int error, struct bsd_namespace_v1_Namespace_Enter_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_namespace_v1_Namespace_Enter_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	ATF_REQUIRE_EQ(bsd_namespace_v1_Namespace_Enter_Result_response_tag,
	    v->tag);
	r->fd = fidl_bsd_take_fd(&v->value.response.jail);
}

/*
 * Enter with the request's NUL-terminated fields (path_size overrides the
 * path length when nonzero, to carry an embedded NUL); returns the
 * application errno and the delivered descriptor (or -1) in *out_fd.
 */
static int
enter_sized(struct fixture *fixture, const struct bsdnamespace_request *rq,
    size_t path_size, int *out_fd)
{
	struct bsd_namespace_v1_EnterRequest request;
	struct result r = { .fd = -1 };
	uint32_t txid;

	memset(&request, 0, sizeof(request));
	request.flags = rq->flags;
	request.path = rq->path;
	request.path_size = path_size != 0 ? path_size : strlen(rq->path);
	request.hostname = rq->hostname;
	request.hostname_size = strlen(rq->hostname);
	request.ip4_addr = rq->ip4_addr;
	request.ip4_addr_size = strlen(rq->ip4_addr);
	request.ip6_addr = rq->ip6_addr;
	request.ip6_addr_size = strlen(rq->ip6_addr);
	r.error = bsd_namespace_v1_Namespace_Enter(fixture->client, &request,
	    enter_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	if (out_fd != NULL)
		*out_fd = r.fd;
	else if (r.fd >= 0)
		close(r.fd);
	return (r.status);
}

static int
enter(struct fixture *fixture, const struct bsdnamespace_request *rq,
    int *out_fd)
{

	return (enter_sized(fixture, rq, 0, out_fd));
}

static void
destroy_done(void *p, int error,
    struct bsd_namespace_v1_Namespace_Destroy_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error && v->tag == bsd_namespace_v1_Namespace_Destroy_Result_err_tag)
		r->status = (int)v->value.err;
}

static int
destroy_jail(struct fixture *fixture)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	r.error = bsd_namespace_v1_Namespace_Destroy(fixture->client, &empty,
	    destroy_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	return (r.status);
}

static void
copy_field(char *out, size_t outsz, const char *in, size_t len)
{

	ATF_REQUIRE(len < outsz);
	memcpy(out, in, len);
	out[len] = '\0';
}

static void
list_done(void *p, int error, struct bsd_namespace_v1_Namespace_List_Result *v)
{
	struct result *r = p;
	struct bsdnamespace_list_reply *lr = r->list;
	const struct bsd_namespace_v1_JailInfo *jail;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_namespace_v1_Namespace_List_Result_err_tag) {
		lr->status = (int32_t)v->value.err;
		return;
	}
	jail = v->value.response.jail;
	if (jail == NULL)
		return;
	lr->present = 1;
	lr->jid = jail->jid;
	lr->flags = jail->flags;
	copy_field(lr->path, sizeof(lr->path), jail->path, jail->path_size);
	copy_field(lr->hostname, sizeof(lr->hostname), jail->hostname,
	    jail->hostname_size);
	copy_field(lr->ip4_addr, sizeof(lr->ip4_addr), jail->ip4_addr,
	    jail->ip4_addr_size);
	copy_field(lr->ip6_addr, sizeof(lr->ip6_addr), jail->ip6_addr,
	    jail->ip6_addr_size);
}

/* List into *lr (status, present and the definition, as the legacy reply). */
static void
list_jail(struct fixture *fixture, struct bsdnamespace_list_reply *lr)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;

	memset(lr, 0, sizeof(*lr));
	r.list = lr;
	r.error = bsd_namespace_v1_Namespace_List(fixture->client, &empty,
	    list_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
}

/* Send raw bytes (and optionally one descriptor); return the call result. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[256];
	int fd, received = -1, rc;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &received;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && incoming.nfds != 0 && received >= 0)
		(void)close(received);
	return (rc);
}

/* A raw frame: header plus `body` bytes. */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t body_length, int attach_fd)
{
	uint8_t frame[256];
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	return (send_raw(session, frame, sizeof(header) + body_length,
	    attach_fd));
}

/*
 * The frame is refused by closing the session: no reply, and nothing later on
 * the session is honoured.  `negotiate` first answers GetProtocolInfo, so the
 * rejection is the provider's decoding, not the negotiation rule.
 */
static void
reject(bool negotiate, uint64_t ordinal, const void *body, size_t length,
    int attach_fd)
{
	struct fixture fixture;

	fixture_start(&fixture, TEST_CLIENT_LABEL, true);
	if (negotiate)
		ATF_REQUIRE_EQ(0, send_frame(fixture.session, ORD_INFO, NULL, 0,
		    -1));
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ordinal, body, length,
	    attach_fd));
	ATF_CHECK(errno != ETIMEDOUT);
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_INFO, NULL, 0, -1));
	fixture_destroy(&fixture);
}

/*
 * A well-formed Enter body for "/x" with every other string empty: flags,
 * then four string headers, then the out-of-line path bytes (padded).
 */
struct enter_frame {
	uint32_t flags;
	uint32_t pad;
	uint64_t path_size, path_presence;
	uint64_t host_size, host_presence;
	uint64_t ip4_size, ip4_presence;
	uint64_t ip6_size, ip6_presence;
	char path[8];
};

static const struct enter_frame good_enter = {
	0, 0, 2, UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX,
	"/x"
};

/*
 * Malformed frames close the session without touching a jail: a method before
 * negotiation, an unknown method, a truncated header, an Enter without or with
 * a short body, a Destroy or List with trailing bytes, a pre-FIDL record and an
 * attached descriptor (whose provider copy is closed).
 */
ATF_TC(malformed_frames_are_rejected);
ATF_TC_HEAD(malformed_frames_are_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(malformed_frames_are_rejected, tc)
{
	struct bsdnamespace_control_request legacy;
	struct fixture fixture;
	uint64_t trailing = 0;
	int pipefd[2];
	char byte;

	require_plane();
	/* The well-formed raw List is answered. */
	fixture_start(&fixture, TEST_CLIENT_LABEL, true);
	ATF_REQUIRE_EQ(0, send_frame(fixture.session, ORD_INFO, NULL, 0, -1));
	ATF_CHECK_EQ(0, send_frame(fixture.session, ORD_LIST, NULL, 0, -1));
	fixture_destroy(&fixture);

	/* Before negotiation. */
	reject(false, ORD_LIST, NULL, 0, -1);
	/* Unknown strict method. */
	reject(true, UINT64_C(0x7fff), NULL, 0, -1);
	/* Truncated header (8 of 16 bytes). */
	fixture_start(&fixture, TEST_CLIENT_LABEL, true);
	{
		struct wire_header h = { 3, { 2, 0, 0 }, 1, ORD_LIST };

		ATF_CHECK_EQ(-1, send_raw(fixture.session, &h, 8, -1));
	}
	fixture_destroy(&fixture);
	/* Enter without its body, and with the path bytes cut off. */
	reject(true, ORD_ENTER, NULL, 0, -1);
	reject(true, ORD_ENTER, &good_enter, sizeof(good_enter) - 8, -1);
	/* A path over the 1023-byte bound. */
	{
		struct enter_frame bad = good_enter;

		bad.path_size = 1024;
		reject(true, ORD_ENTER, &bad, sizeof(bad), -1);
	}
	/* Destroy and List carry no payload: trailing bytes. */
	reject(true, ORD_DESTROY, &trailing, sizeof(trailing), -1);
	reject(true, ORD_LIST, &trailing, sizeof(trailing), -1);
	/* A pre-FIDL LIST record. */
	memset(&legacy, 0, sizeof(legacy));
	legacy.op = BSDNAMESPACE_OP_LIST_JAILS;
	fixture_start(&fixture, TEST_CLIENT_LABEL, true);
	ATF_CHECK_EQ(-1, send_raw(fixture.session, &legacy, sizeof(legacy),
	    -1));
	fixture_destroy(&fixture);
	/* An attached descriptor: rejected, and the provider's copy closed. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	reject(true, ORD_DESTROY, NULL, 0, pipefd[1]);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);
}

ATF_TC(rejects_unknown_flag_bits);
ATF_TC_HEAD(rejects_unknown_flag_bits, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_unknown_flag_bits, tc)
{
	struct fixture fixture;
	struct bsdnamespace_request rq;
	int out_fd = -1;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, BSDNAMESPACE_F_EPHEMERAL | 0x4u, "/jails/example", "", "", "");
	ATF_CHECK_EQ(EINVAL, enter(&fixture, &rq, &out_fd));
	ATF_CHECK_EQ(-1, out_fd);
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
	struct bsdnamespace_request rq;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "relative/path", "", "", "");
	ATF_CHECK_EQ(EINVAL, enter(&fixture, &rq, NULL));
	/* The session survives an application error. */
	init_request(&rq, 0, "", "", "", "");
	ATF_CHECK_EQ(EINVAL, enter(&fixture, &rq, NULL));
	fixture_destroy(&fixture);
}

/* An embedded NUL would truncate the path: EINVAL, and the session lives. */
ATF_TC(rejects_embedded_nul);
ATF_TC_HEAD(rejects_embedded_nul, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rejects_embedded_nul, tc)
{
	struct fixture fixture;
	struct bsdnamespace_request rq;
	struct bsdnamespace_list_reply lr;

	require_plane();
	fixture_create(&fixture);
	init_request(&rq, 0, "/jails/x", "", "", "");
	rq.path[2] = '\0';
	ATF_CHECK_EQ(EINVAL, enter_sized(&fixture, &rq, 8, NULL));
	list_jail(&fixture, &lr);
	ATF_CHECK_EQ(0, lr.status);
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

	if (!bsdnamespace_test_jail_name(label, name, sizeof(name)))
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* First ENTER establishes the persistent jail (hostname host-one). */
	init_request(&rq, 0, root, "host-one", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live jail creation not available under harness: %s",
		    strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* Reconnect after an update: empty IP lists must match, not EEXIST. */
	fixture_destroy(&fixture);
	fixture_create(&fixture);
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	ATF_REQUIRE_MSG(rp.status == 0, "reuse with empty IP lists: %s",
	    strerror(rp.status));
	ATF_REQUIRE(out_fd >= 0);
	close(out_fd);

	/* Same channel/label, mismatched definition -> hard EEXIST. */
	init_request(&rq, 0, root, "host-two", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	init_request(&rq, BSDNAMESPACE_F_EPHEMERAL, root, "", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live jail creation not available under harness: %s",
		    strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* Second ephemeral ENTER on the same channel is refused. */
	init_request(&rq, BSDNAMESPACE_F_EPHEMERAL, root, "", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	struct bsdnamespace_list_reply lr;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes the persistent jail (hostname host-life). */
	init_request(&rq, 0, root, "host-life", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live jail creation not available under harness: %s",
		    strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* LIST reports the jail present with its definition. */
	list_jail(&fixture, &lr);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(1, lr.present);
	ATF_CHECK(lr.jid > 0);
	ATF_CHECK_STREQ(root, lr.path);
	ATF_CHECK_STREQ("host-life", lr.hostname);
	/* A plain persistent jail reports neither vnet nor ephemeral. */
	ATF_CHECK_MSG((lr.flags & BSDNAMESPACE_F_VNET) == 0,
	    "non-vnet jail reported flags 0x%x with BSDNAMESPACE_F_VNET set", lr.flags);
	ATF_CHECK_MSG((lr.flags & BSDNAMESPACE_F_EPHEMERAL) == 0,
	    "persistent jail reported flags 0x%x with BSDNAMESPACE_F_EPHEMERAL set",
	    lr.flags);

	/* DESTROY removes it. */
	rp.status = destroy_jail(&fixture);
	ATF_CHECK_EQ(0, rp.status);

	/* A second LIST now reports no jail. */
	list_jail(&fixture, &lr);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(0, lr.present);

	/* A second DESTROY is ENOENT — nothing left to remove. */
	rp.status = destroy_jail(&fixture);
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	struct bsdnamespace_list_reply lr;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent jail carrying an ip6 address. */
	init_request(&rq, 0, root, "host-v6", "", "fd00::1");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live ip6 jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* LIST reports the jail with its ip6 address filled in. */
	list_jail(&fixture, &lr);
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	struct bsdnamespace_list_reply lr;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent jail carrying an ip4 address. */
	init_request(&rq, 0, root, "host-v4", "10.99.0.1", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	if (rp.status != 0) {
		fixture_destroy(&fixture);
		(void)rmdir(root);
		atf_tc_skip("live ip4 jail creation not available under harness: "
		    "%s", strerror(rp.status));
	}
	if (out_fd >= 0)
		close(out_fd);

	/* LIST reports the jail with its ip4 address filled in and no vnet. */
	list_jail(&fixture, &lr);
	ATF_CHECK_EQ(0, lr.status);
	ATF_CHECK_EQ(1, lr.present);
	ATF_CHECK_STREQ(root, lr.path);
	ATF_CHECK_MSG(strcmp(lr.ip4_addr, "10.99.0.1") == 0,
	    "LIST reported ip4_addr \"%s\", want \"10.99.0.1\"", lr.ip4_addr);
	ATF_CHECK_MSG((lr.flags & BSDNAMESPACE_F_VNET) == 0,
	    "non-vnet ip4 jail reported flags 0x%x with BSDNAMESPACE_F_VNET set",
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	char root[PATH_MAX];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* First ENTER establishes the persistent jail with ip6 fd00::1. */
	init_request(&rq, 0, root, "host-v6", "", "fd00::1");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
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
	rp.status = enter(&fixture, &rq, &out_fd);
	ATF_CHECK_MSG(rp.status == EEXIST,
	    "reuse with mismatched ip6 returned status %d (%s), want EEXIST",
	    rp.status, strerror(rp.status));
	ATF_CHECK_EQ(-1, out_fd);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

/*
 * ENTER with BSDNAMESPACE_F_VNET creates a jail with its own virtual network stack.
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
	struct bsdnamespace_request rq;
	struct { int status; } rp;
	char root[PATH_MAX], name[64], vbuf[16];
	int out_fd;

	require_plane();
	make_jail_root(root, sizeof(root));
	fixture_create(&fixture);

	/* ENTER establishes a persistent vnet jail. */
	init_request(&rq, BSDNAMESPACE_F_VNET, root, "host-vnet", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
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
	ATF_REQUIRE(bsdnamespace_test_jail_name(TEST_CLIENT_LABEL, name, sizeof(name)));
	vbuf[0] = '\0';
	ATF_REQUIRE(jail_getv(0, "name", name, "vnet", vbuf, NULL) >= 0);
	ATF_CHECK_MSG(strcmp(vbuf, "new") == 0,
	    "vnet jail's vnet param = \"%s\", want \"new\"", vbuf);

	/* LIST must report the vnet nature back in flags (BSDNAMESPACE_F_VNET). */
	{
		struct bsdnamespace_list_reply lr;

		list_jail(&fixture, &lr);
		ATF_CHECK_EQ(1, lr.present);
		ATF_CHECK_MSG((lr.flags & BSDNAMESPACE_F_VNET) != 0,
		    "LIST of a vnet jail reported flags 0x%x without BSDNAMESPACE_F_VNET",
		    lr.flags);
	}

	/*
	 * A reuse of the same path/hostname without the vnet flag differs in the
	 * (immutable) definition and must be refused, proving vnet is enforced.
	 */
	init_request(&rq, 0, root, "host-vnet", "", "");
	out_fd = -1;
	rp.status = enter(&fixture, &rq, &out_fd);
	ATF_CHECK_MSG(rp.status == EEXIST,
	    "non-vnet reuse of a vnet jail returned status %d (%s), want EEXIST",
	    rp.status, strerror(rp.status));
	ATF_CHECK_EQ(-1, out_fd);

	fixture_destroy(&fixture);
	remove_named_jail(TEST_CLIENT_LABEL);
	(void)rmdir(root);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, malformed_frames_are_rejected);
	ATF_TP_ADD_TC(tp, rejects_unknown_flag_bits);
	ATF_TP_ADD_TC(tp, rejects_relative_path);
	ATF_TP_ADD_TC(tp, rejects_embedded_nul);
	ATF_TP_ADD_TC(tp, reuse_definition_mismatch_is_eexist);
	ATF_TP_ADD_TC(tp, enter_with_ip4_lists_back);
	ATF_TP_ADD_TC(tp, enter_with_ip6_lists_back);
	ATF_TP_ADD_TC(tp, reuse_ip6_mismatch_is_eexist);
	ATF_TP_ADD_TC(tp, enter_with_vnet_creates_vnet_jail);
	ATF_TP_ADD_TC(tp, second_ephemeral_enter_is_ealready);
	ATF_TP_ADD_TC(tp, lifecycle_list_then_destroy);
	return (atf_no_error());
}
