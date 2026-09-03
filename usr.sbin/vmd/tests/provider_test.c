/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane tests for vmd(8)'s per-client request handler.  Each test wires a real
 * mac_capability channel pair, forks a child running vmd's production worker
 * (vmd_test_worker -> vmd_worker -> vmd_request_handler), and drives it as a
 * client with libservice.  They cover request validation over the wire and, when
 * the AF_VSOCK transport is available, that a VSOCK_BIND returns a concrete
 * (cid,port) plus an accept-only, non-re-delegable listening descriptor.
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

#include <libservice.h>

#include "vmd_proto.h"
#include "vmd_test.h"

#define	TEST_LABEL	"org.test.vm.provider"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
	uint32_t		 base;
};

static void
require_capability_device(void)
{

	if (access("/dev/mac_capability", F_OK) != 0)
		atf_tc_skip("mac_capability device not available");
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
fixture_create(struct fixture *fixture)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	require_capability_device();

	/* Resolve the window the way the accept loop would before forking. */
	vmd_test_registry_reset();
	ATF_REQUIRE(vmd_test_resolve_window(TEST_LABEL, &fixture->base));

	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(vmd_test_worker(provider, TEST_LABEL, fixture->base));
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
 * Issue one request.  data/length are sent verbatim (so tests can forge a
 * wrong-length message); when send_fd >= 0 it rides along as an SCM descriptor.
 * On return the reply body and any single received descriptor are handed back.
 */
static int
call_raw(struct fixture *fixture, const void *data, size_t length, int send_fd,
    struct vmd_reply *reply, int *got_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	int fds[1] = { -1 };
	int rc;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (send_fd >= 0) {
		outgoing.fds = &send_fd;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	incoming.fds = fds;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	memset(reply, 0, sizeof(*reply));
	rc = service_session_call(fixture->session, &outgoing, &incoming,
	    &options);
	if (got_fd != NULL)
		*got_fd = (incoming.nfds == 1) ? fds[0] : -1;
	else if (incoming.nfds == 1)
		close(fds[0]);
	return (rc);
}

static struct vmd_request
bind_request(uint32_t port, uint32_t backlog)
{
	struct vmd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_BIND;
	rq.port = port;
	rq.backlog = backlog;
	rq.cid = 0;
	return (rq);
}

static struct vmd_request
connect_request(uint32_t cid, uint32_t port)
{
	struct vmd_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_CONNECT;
	rq.port = port;
	rq.backlog = 0;
	rq.cid = cid;
	return (rq);
}

ATF_TC(bind_returns_accept_only_listener);
ATF_TC_HEAD(bind_returns_accept_only_listener, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "A VSOCK_BIND returns a concrete (cid,port) and an accept-only, "
	    "non-re-delegable listening descriptor");
}
ATF_TC_BODY(bind_returns_accept_only_listener, tc)
{
	struct fixture fixture;
	struct vmd_request rq;
	struct vmd_reply reply;
	cap_rights_t rights, expected;
	int fd;

	fixture_create(&fixture);
	rq = bind_request(0, 0);
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, &fd));

	if (reply.status != 0) {
		/* No usable AF_VSOCK transport in this environment. */
		if (fd >= 0)
			close(fd);
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK bind unavailable: %s",
		    strerror(reply.status));
	}

	ATF_REQUIRE_MSG(fd >= 0, "success reply carried no descriptor");
	ATF_CHECK_EQ(VMADDR_CID_LOCAL, reply.cid);
	ATF_CHECK_EQ(fixture.base + 0, reply.port);

	/*
	 * The listener is limited to accept + the data-plane rights that
	 * accept(2) propagates to the accepted sockets (read/write/shutdown/
	 * {get,set}sockopt/event/fstat), so accepted connections are usable,
	 * while bind/connect/listen are withheld so it cannot be repurposed.
	 */
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	cap_rights_init(&expected, CAP_ACCEPT, CAP_EVENT, CAP_FSTAT, CAP_READ,
	    CAP_WRITE, CAP_SHUTDOWN, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_ACCEPT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_BIND));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_CONNECT));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_LISTEN));

	close(fd);
	fixture_destroy(&fixture);
}

ATF_TC(connect_reaches_a_bound_listener);
ATF_TC_HEAD(connect_reaches_a_bound_listener, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "A VSOCK_CONNECT to a peer's advertised (cid,port) delivers a live "
	    "connected socket that carries data end-to-end to the listener, "
	    "rights-limited to the accept-less data-plane set");
}
ATF_TC_BODY(connect_reaches_a_bound_listener, tc)
{
	struct fixture fixture;
	struct vmd_request rq;
	struct vmd_reply reply;
	cap_rights_t rights, expected;
	int listener, conn, accepted;
	uint32_t cid, port;
	char msg[] = "vsock-peer-ipc";
	char buf[sizeof(msg)];
	ssize_t n;

	fixture_create(&fixture);

	/* Bind a listener the way a peer would, to learn its concrete address. */
	rq = bind_request(0, 0);
	ATF_REQUIRE_EQ(0,
	    call_raw(&fixture, &rq, sizeof(rq), -1, &reply, &listener));
	if (reply.status != 0) {
		/* No usable AF_VSOCK transport in this environment. */
		if (listener >= 0)
			close(listener);
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK bind unavailable: %s",
		    strerror(reply.status));
	}
	ATF_REQUIRE_MSG(listener >= 0, "bind reply carried no descriptor");
	cid = reply.cid;
	port = reply.port;

	/* Dial that concrete (cid,port): the gap this closes. */
	rq = connect_request(cid, port);
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, &conn));
	if (reply.status != 0) {
		close(listener);
		if (conn >= 0)
			close(conn);
		fixture_destroy(&fixture);
		atf_tc_skip("AF_VSOCK connect unavailable: %s",
		    strerror(reply.status));
	}
	ATF_REQUIRE_MSG(conn >= 0, "connect reply carried no descriptor");
	/* The reply echoes the concrete target that was reached. */
	ATF_CHECK_EQ(cid, reply.cid);
	ATF_CHECK_EQ(port, reply.port);

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

ATF_TC(malformed_requests_are_rejected);
ATF_TC_HEAD(malformed_requests_are_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "descr",
	    "Wrong length, an unexpected descriptor, an unknown op, a BIND "
	    "naming a cid, an out-of-window port, and a CONNECT with a bad "
	    "backlog or wildcard cid are all refused");
}
ATF_TC_BODY(malformed_requests_are_rejected, tc)
{
	struct fixture fixture;
	struct vmd_request rq;
	struct vmd_reply reply;
	int nullfd;

	fixture_create(&fixture);

	/* Wrong message length: EPROTO before validation. */
	rq = bind_request(0, 0);
	ATF_REQUIRE_EQ(0,
	    call_raw(&fixture, &rq, sizeof(rq) - 1, -1, &reply, NULL));
	ATF_CHECK_EQ(EPROTO, reply.status);

	/* An unexpected descriptor on a correctly sized request: EPROTO. */
	nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(nullfd >= 0);
	rq = bind_request(0, 0);
	ATF_REQUIRE_EQ(0,
	    call_raw(&fixture, &rq, sizeof(rq), nullfd, &reply, NULL));
	ATF_CHECK_EQ(EPROTO, reply.status);
	close(nullfd);

	/* Unknown op: EINVAL. */
	rq = bind_request(0, 0);
	rq.op = VMD_OP_VSOCK_BIND + 99;
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, NULL));
	ATF_CHECK_EQ(EINVAL, reply.status);

	/* A BIND naming a nonzero cid: EINVAL. */
	rq = bind_request(0, 0);
	rq.cid = 0xdeadbeefu;
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, NULL));
	ATF_CHECK_EQ(EINVAL, reply.status);

	/* Port index outside the caller's window: EINVAL. */
	rq = bind_request(VMD_PORTS_PER_LABEL, 0);
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, NULL));
	ATF_CHECK_EQ(EINVAL, reply.status);

	/* A CONNECT with a nonzero backlog: EINVAL. */
	rq = connect_request(VMADDR_CID_LOCAL, VMD_PORT_BASE);
	rq.backlog = 1;
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, NULL));
	ATF_CHECK_EQ(EINVAL, reply.status);

	/* A CONNECT to the wildcard CID: EINVAL. */
	rq = connect_request(VMADDR_CID_ANY, VMD_PORT_BASE);
	ATF_REQUIRE_EQ(0, call_raw(&fixture, &rq, sizeof(rq), -1, &reply, NULL));
	ATF_CHECK_EQ(EINVAL, reply.status);

	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bind_returns_accept_only_listener);
	ATF_TP_ADD_TC(tp, connect_reaches_a_bound_listener);
	ATF_TP_ADD_TC(tp, malformed_requests_are_rejected);
	return (atf_no_error());
}
