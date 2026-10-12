/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane tests for BSDVM's per-client bsd.vm.v1 server.  Each test wires a real
 * mac_capability channel pair and forks a child running the production worker
 * (vmd_test_worker -> vmd_worker).  Well-formed requests use the generated
 * bsd.vm.v1 client bindings (the encoder libvmcmp uses); adversarial frames go
 * through a raw libservice session.  When the AF_VSOCK transport is available,
 * Bind returns a concrete (cid,port) plus an accept-only, non-re-delegable
 * listening descriptor and Connect reaches it.
 */

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/vsock.h>
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

#include <fidl/bsd.vm.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>

#include "bsdvm_proto.h"
#include "bsdvm_test.h"

#define	TEST_LABEL	"org.test.vm.provider"

struct fixture {
	struct fidl_bsd_connection *client;	/* generated client */
	struct service_session	*session;	/* raw frames */
	pid_t			 child;
	uint32_t		 base;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");

#define	ORD_INFO	UINT64_C(0x5fb0a5d4bcec8055)
#define	ORD_BIND	UINT64_C(0x261268ba614cdbf4)
#define	ORD_CONNECT	UINT64_C(0x13fc03f59c62ccf2)
#define	ORD_LIST	UINT64_C(0x13829ccfc03499b6)

struct result {
	bool done;
	int error;		/* transport error */
	int status;		/* application errno */
	uint32_t value;
	int fd;
	uint32_t cid, port;
	struct bsd_vm_v1_Window window;
};

static void
require_capability_device(void)
{
	int fd;

	/*
	 * Probe with the open the fixture needs: on a live plane the node
	 * exists but Capsule's claim refuses the open unless the image boots
	 * with kern.mac_capability_isolation.enforce=0.
	 */
	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
	close(fd);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s", strerror(errno));
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

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
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
wait_result(struct fixture *fixture, struct result *r)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(0, fidl_bsd_sync_deadline(&deadline, 5000));
	if (r->error == 0)
		r->error = fidl_bsd_sync_wait(fixture->client, &r->done,
		    &deadline);
}

static void
info_done(void *p, int error, struct bsd_vm_v1_ProtocolInfo *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (!error)
		r->value = v->wire_version;
}

/*
 * Stand up a worker serving `label` on one end of a fresh channel, exactly as
 * the accept loop would: resolve the label's window in the parent's registry,
 * then hand the forked worker that base.  The client end is either a
 * negotiated generated client or (raw) a libservice session.  Does NOT reset
 * the registry, so a test can stand up two DISTINCT labels back to back and
 * observe their windows never alias (scoping regression).
 */
static void
fixture_start(struct fixture *fixture, const char *label, bool raw)
{
	struct fidl_bsd_empty empty = { 0 };
	struct result r = { .fd = -1 };
	uint32_t txid;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	require_capability_device();

	ATF_REQUIRE(vmd_test_resolve_window(label, &fixture->base));

	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(vmd_test_worker(provider, label, fixture->base));
	}
	close(provider);
	if (raw) {
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
		return;
	}
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &fixture->client));
	r.error = bsd_vm_v1_Vm_GetProtocolInfo(fixture->client, &empty,
	    info_done, &r, &txid);
	wait_result(fixture, &r);
	ATF_REQUIRE_EQ(0, r.error);
	ATF_REQUIRE_EQ(VMD_WIRE_VERSION, r.value);
}

static void
fixture_create(struct fixture *fixture)
{

	/* Clean-slate registry, then the canonical single-label fixture. */
	vmd_test_registry_reset();
	fixture_start(fixture, TEST_LABEL, false);
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
bind_done(void *p, int error, struct bsd_vm_v1_VM_Bind_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_vm_v1_VM_Bind_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	ATF_REQUIRE_EQ(bsd_vm_v1_VM_Bind_Result_response_tag, v->tag);
	r->fd = fidl_bsd_take_fd(&v->value.response.listener);
	r->cid = v->value.response.cid;
	r->port = v->value.response.port;
}

static void
connect_done(void *p, int error, struct bsd_vm_v1_VM_Connect_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_vm_v1_VM_Connect_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	ATF_REQUIRE_EQ(bsd_vm_v1_VM_Connect_Result_response_tag, v->tag);
	r->fd = fidl_bsd_take_fd(&v->value.response.socket);
}

static void
list_done(void *p, int error, struct bsd_vm_v1_VM_List_Result *v)
{
	struct result *r = p;

	r->done = true;
	r->error = error;
	if (error)
		return;
	if (v->tag == bsd_vm_v1_VM_List_Result_err_tag) {
		r->status = (int)v->value.err;
		return;
	}
	ATF_REQUIRE_EQ(bsd_vm_v1_VM_List_Result_response_tag, v->tag);
	r->window = v->value.response;
}

/* Bind; returns the application errno with the result in *r. */
static int
vm_bind(struct fixture *fixture, uint32_t index, uint32_t backlog,
    struct result *r)
{
	struct bsd_vm_v1_BindRequest request = { index, backlog };
	uint32_t txid;

	memset(r, 0, sizeof(*r));
	r->fd = -1;
	r->error = bsd_vm_v1_Vm_Bind(fixture->client, &request, bind_done, r,
	    &txid);
	wait_result(fixture, r);
	ATF_REQUIRE_EQ(0, r->error);
	return (r->status);
}

static int
vm_connect(struct fixture *fixture, uint32_t cid, uint32_t port,
    struct result *r)
{
	struct bsd_vm_v1_ConnectRequest request = { cid, port };
	uint32_t txid;

	memset(r, 0, sizeof(*r));
	r->fd = -1;
	r->error = bsd_vm_v1_Vm_Connect(fixture->client, &request,
	    connect_done, r, &txid);
	wait_result(fixture, r);
	ATF_REQUIRE_EQ(0, r->error);
	return (r->status);
}

static int
vm_list(struct fixture *fixture, struct result *r)
{
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;

	memset(r, 0, sizeof(*r));
	r->fd = -1;
	r->error = bsd_vm_v1_Vm_List(fixture->client, &empty, list_done, r,
	    &txid);
	wait_result(fixture, r);
	ATF_REQUIRE_EQ(0, r->error);
	return (r->status);
}

/* Send raw bytes (and optionally one descriptor); return the call result. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t reply[128];
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
	options.timeout_ms = 2000;
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
	uint8_t frame[128];
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_length <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	return (send_raw(session, frame, sizeof(header) + body_length,
	    attach_fd));
}

/*
 * A raw session that has negotiated, so a rejection is the provider's
 * decoding or validation, not the negotiation rule.
 */
static void
raw_negotiated(struct fixture *fixture)
{

	vmd_test_registry_reset();
	fixture_start(fixture, TEST_LABEL, true);
	ATF_REQUIRE_EQ(0, send_frame(fixture->session, ORD_INFO, NULL, 0, -1));
}

/*
 * The frame is refused by closing the session: no reply, and nothing later on
 * the session is honoured.
 */
static void
reject(bool negotiate, uint64_t ordinal, const void *body, size_t length,
    int attach_fd)
{
	struct fixture fixture;

	if (negotiate)
		raw_negotiated(&fixture);
	else {
		vmd_test_registry_reset();
		fixture_start(&fixture, TEST_LABEL, true);
	}
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ordinal, body, length,
	    attach_fd));
	ATF_CHECK(errno != ETIMEDOUT);
	ATF_CHECK_EQ(-1, send_frame(fixture.session, ORD_INFO, NULL, 0, -1));
	fixture_destroy(&fixture);
}

ATF_TC(bind_returns_accept_only_listener);
ATF_TC_HEAD(bind_returns_accept_only_listener, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "Bind returns a concrete (cid,port) and an accept-only, "
	    "non-re-delegable listening descriptor");
}
ATF_TC_BODY(bind_returns_accept_only_listener, tc)
{
	struct fixture fixture;
	struct result r;
	cap_rights_t rights, expected;

	fixture_create(&fixture);
	if (vm_bind(&fixture, 0, 0, &r) != 0) {
		/* No usable AF_VSOCK transport in this environment. */
		ATF_CHECK_EQ(-1, r.fd);
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK bind unavailable: %s",
		    strerror(r.status));
	}

	ATF_REQUIRE_MSG(r.fd >= 0, "success reply carried no descriptor");
	ATF_CHECK_EQ(VMADDR_CID_LOCAL, r.cid);
	ATF_CHECK_EQ(fixture.base + 0, r.port);

	/*
	 * The listener is limited to accept + the data-plane rights that
	 * accept(2) propagates to the accepted sockets (read/write/shutdown/
	 * {get,set}sockopt/event/fstat), so accepted connections are usable,
	 * while bind/connect/listen are withheld so it cannot be repurposed.
	 */
	ATF_REQUIRE_EQ(0, cap_rights_get(r.fd, &rights));
	cap_rights_init(&expected, CAP_ACCEPT, CAP_EVENT, CAP_FSTAT, CAP_READ,
	    CAP_WRITE, CAP_SHUTDOWN, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_ACCEPT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_LISTEN));

	close(r.fd);
	fixture_destroy(&fixture);
}

ATF_TC(connect_reaches_a_bound_listener);
ATF_TC_HEAD(connect_reaches_a_bound_listener, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "Connect to a peer's advertised (cid,port) delivers a live "
	    "connected socket that carries data end-to-end to the listener, "
	    "rights-limited to the accept-less data-plane set");
}
ATF_TC_BODY(connect_reaches_a_bound_listener, tc)
{
	struct fixture fixture;
	struct result r;
	cap_rights_t rights, expected;
	int listener, conn, accepted;
	char msg[] = "vsock-peer-ipc";
	char buf[sizeof(msg)];
	ssize_t n;

	fixture_create(&fixture);

	/* Bind a listener the way a peer would, to learn its concrete address. */
	if (vm_bind(&fixture, 0, 0, &r) != 0) {
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK bind unavailable: %s",
		    strerror(r.status));
	}
	ATF_REQUIRE_MSG(r.fd >= 0, "bind reply carried no descriptor");
	listener = r.fd;

	/* Dial that concrete (cid,port). */
	if (vm_connect(&fixture, r.cid, r.port, &r) != 0) {
		close(listener);
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK connect unavailable: %s",
		    strerror(r.status));
	}
	ATF_REQUIRE_MSG(r.fd >= 0, "connect reply carried no descriptor");
	conn = r.fd;

	/*
	 * The connected fd is limited to the accept-less data-plane rights:
	 * read/write/poll/shutdown/fstat/(get,set)sockopt, and NOT accept,
	 * bind, connect or listen.
	 */
	ATF_REQUIRE_EQ(0, cap_rights_get(conn, &rights));
	cap_rights_init(&expected, CAP_READ, CAP_WRITE, CAP_EVENT,
	    CAP_SHUTDOWN, CAP_FSTAT, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_ACCEPT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_LISTEN));

	/* End-to-end: accept the connection and prove bytes flow across it. */
	accepted = accept(listener, NULL, NULL);
	ATF_REQUIRE_MSG(accepted >= 0, "accept: %s", strerror(errno));

	n = write(conn, msg, sizeof(msg));
	ATF_REQUIRE_EQ((ssize_t)sizeof(msg), n);
	memset(buf, 0, sizeof(buf));
	n = read(accepted, buf, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(msg), n);
	ATF_CHECK_EQ(0, memcmp(msg, buf, sizeof(msg)));

	close(accepted);
	close(conn);
	close(listener);
	fixture_destroy(&fixture);
}

/*
 * List reports the CALLER'S OWN window and only its own.  The first fixture's
 * List must return the concrete range [base, base+PORTS) on the host-local CID,
 * matching the base the parent registry resolved for its label.  A second,
 * DISTINCT label -- stood up without resetting the registry -- owns a different
 * window, and its List reports that different window, never the first caller's.
 */
ATF_TC(list_reports_only_callers_window);
ATF_TC_HEAD(list_reports_only_callers_window, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "List reports the caller's own port window and a distinct "
	    "label sees a distinct window, never the caller's");
}
ATF_TC_BODY(list_reports_only_callers_window, tc)
{
	struct fixture fa, fb;
	struct result ra, rb;

	vmd_test_registry_reset();
	fixture_start(&fa, "org.test.vm.alpha", false);
	fixture_start(&fb, "org.test.vm.bravo", false);

	/* Two distinct labels must own two distinct windows. */
	ATF_REQUIRE(fa.base != fb.base);

	ATF_CHECK_EQ(0, vm_list(&fa, &ra));
	ATF_CHECK_EQ(VMADDR_CID_LOCAL, ra.window.cid);
	ATF_CHECK_EQ(fa.base, ra.window.port_base);
	ATF_CHECK_EQ(fa.base + VMD_PORTS_PER_LABEL, ra.window.port_limit);
	ATF_CHECK_EQ(VMD_PORTS_PER_LABEL, ra.window.port_count);

	ATF_CHECK_EQ(0, vm_list(&fb, &rb));
	ATF_CHECK_EQ(fb.base, rb.window.port_base);
	ATF_CHECK_EQ(fb.base + VMD_PORTS_PER_LABEL, rb.window.port_limit);

	/* Neither caller's List ever reports the other's window. */
	ATF_CHECK(ra.window.port_base != rb.window.port_base);
	ATF_CHECK(ra.window.port_base != fb.base);
	ATF_CHECK(rb.window.port_base != fa.base);

	fixture_destroy(&fb);
	fixture_destroy(&fa);
}

ATF_TC(invalid_arguments_are_refused);
ATF_TC_HEAD(invalid_arguments_are_refused, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "A Bind outside the caller's window and a Connect to the wildcard "
	    "CID are refused EINVAL without a descriptor; the session lives");
}
ATF_TC_BODY(invalid_arguments_are_refused, tc)
{
	struct fixture fixture;
	struct result r;

	fixture_create(&fixture);
	ATF_CHECK_EQ(EINVAL, vm_bind(&fixture, VMD_PORTS_PER_LABEL, 0, &r));
	ATF_CHECK_EQ(-1, r.fd);
	ATF_CHECK_EQ(EINVAL, vm_bind(&fixture, UINT32_MAX, 0, &r));
	ATF_CHECK_EQ(-1, r.fd);
	ATF_CHECK_EQ(EINVAL, vm_connect(&fixture, VMADDR_CID_ANY,
	    VMD_PORT_BASE, &r));
	ATF_CHECK_EQ(-1, r.fd);
	ATF_CHECK_EQ(0, vm_list(&fixture, &r));
	ATF_CHECK_EQ(fixture.base, r.window.port_base);
	fixture_destroy(&fixture);
}

ATF_TC(malformed_requests_are_rejected);
ATF_TC_HEAD(malformed_requests_are_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "A request before negotiation, an unknown method, a truncated "
	    "header, a missing or trailing body, a pre-FIDL record and an "
	    "attached descriptor all close the session");
}
ATF_TC_BODY(malformed_requests_are_rejected, tc)
{
	uint32_t body[2] = { 0, 0 };
	struct vmd_request legacy;
	struct fixture fixture;
	int pipefd[2];
	char byte;

	/* The well-formed raw List is answered. */
	raw_negotiated(&fixture);
	ATF_CHECK_EQ(0, send_frame(fixture.session, ORD_LIST, NULL, 0, -1));
	fixture_destroy(&fixture);

	/* Before negotiation. */
	reject(false, ORD_LIST, NULL, 0, -1);
	/* Unknown strict method. */
	reject(true, UINT64_C(0x7fff), NULL, 0, -1);
	/* Truncated header (8 of 16 bytes). */
	raw_negotiated(&fixture);
	{
		struct wire_header h = { 3, { 2, 0, 0 }, 1, ORD_LIST };

		ATF_CHECK_EQ(-1, send_raw(fixture.session, &h, 8, -1));
	}
	fixture_destroy(&fixture);
	/* Bind without its body. */
	reject(true, ORD_BIND, NULL, 0, -1);
	/* Connect with a truncated body. */
	reject(true, ORD_CONNECT, body, 4, -1);
	/* List (no payload) with trailing bytes. */
	reject(true, ORD_LIST, body, sizeof(body), -1);
	/* A pre-FIDL LIST record. */
	memset(&legacy, 0, sizeof(legacy));
	legacy.op = VMD_OP_VSOCK_LIST;
	vmd_test_registry_reset();
	fixture_start(&fixture, TEST_LABEL, true);
	ATF_CHECK_EQ(-1, send_raw(fixture.session, &legacy, sizeof(legacy),
	    -1));
	fixture_destroy(&fixture);
	/* An attached descriptor: rejected, and the provider's copy closed. */
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	reject(true, ORD_LIST, NULL, 0, pipefd[1]);
	close(pipefd[1]);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bind_returns_accept_only_listener);
	ATF_TP_ADD_TC(tp, connect_reaches_a_bound_listener);
	ATF_TP_ADD_TC(tp, list_reports_only_callers_window);
	ATF_TP_ADD_TC(tp, invalid_arguments_are_refused);
	ATF_TP_ADD_TC(tp, malformed_requests_are_rejected);
	return (atf_no_error());
}
