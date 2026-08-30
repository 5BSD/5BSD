/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/capsicum.h>
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
#include <tracecmp.h>
#include <tracecmp_server.h>

#include "tracecmp_test.h"

union test_buffer {
	max_align_t align;
	uint8_t bytes[TRACECMP_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
};

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
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
fixture_create(struct fixture *fixture, bool authorized, int device_error)
{
	int client, provider, dtrace_fd;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	/*
	 * The provider opens the DTrace consumer fd whenever the device is
	 * available, independent of the label allowlist (traced start_session):
	 * per-request authorization (root, or an allowlisted label) is enforced
	 * in the handler, which delegates the held fd only on an authorized OPEN.
	 */
	dtrace_fd = device_error == 0 ?
	    open("/dev/null", O_RDONLY | O_CLOEXEC) : -1;
	ATF_REQUIRE(device_error != 0 || dtrace_fd >= 0);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		/*
		 * The session holds SERVICE_RIGHTS_ADMIN (P5): the capability
		 * replacement for the old root bypass the tests relied on (they
		 * run as root).  A session with the admin right obtains the raw
		 * DTrace fd regardless of the label allowlist.
		 */
		_exit(tracecmp_test_serve(provider, dtrace_fd, authorized,
		    device_error, "org.test.trace", SERVICE_RIGHTS_ADMIN));
	}
	close(provider);
	if (dtrace_fd >= 0)
		close(dtrace_fd);
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

static size_t
call(struct service_session *session, uint16_t opcode, union test_buffer *reply,
    int *fds, size_t fd_capacity, size_t *nfdsp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct tracecmp_msg request;

	ATF_REQUIRE_EQ(0, tracecmp_message_init(&request, opcode, 0));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &request;
	outgoing.length = sizeof(request);
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	incoming.fds = fds;
	incoming.fd_capacity = fd_capacity;
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ_MSG(0, service_session_call(session, &outgoing,
	    &incoming, &options), "call opcode %u: %s", opcode,
	    strerror(errno));
	ATF_REQUIRE_EQ(0, tracecmp_validate_message((const void *)reply,
	    incoming.length, TRACECMP_MESSAGE_REPLY));
	ATF_REQUIRE_EQ(0, tracecmp_validate_fds((const void *)reply,
	    incoming.nfds, TRACECMP_MESSAGE_REPLY));
	if (nfdsp != NULL)
		*nfdsp = incoming.nfds;
	return (incoming.length);
}

static int
call_with_attachment(struct service_session *session, uint16_t opcode, int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	union test_buffer reply;
	struct tracecmp_msg request;

	ATF_REQUIRE_EQ(0, tracecmp_message_init(&request, opcode, 0));
	outgoing = (struct service_message){
		.size = sizeof(outgoing), .data = &request,
		.length = sizeof(request), .fds = &fd, .nfds = 1,
	};
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	return (service_session_call(session, &outgoing, &incoming, &options));
}

ATF_TC(authorized_descriptor_is_one_shot);
ATF_TC_HEAD(authorized_descriptor_is_one_shot, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(authorized_descriptor_is_one_shot, tc)
{
	union test_buffer reply;
	struct fixture fixture;
	struct tracecmp_hello_reply *hello;
	struct tracecmp_stats *stats;
	struct tracecmp_msg *message;
	int fd;
	size_t length, nfds;

	fixture_create(&fixture, true, 0);
	length = call(fixture.session, TRACECMP_OP_HELLO, &reply, NULL, 0,
	    &nfds);
	ATF_CHECK_EQ(sizeof(*message) + sizeof(*hello), length);
	message = (void *)reply.bytes;
	hello = (void *)(message + 1);
	ATF_CHECK_EQ(TRACECMP_FEATURE_RAW_DTRACE_FD, hello->features);
	ATF_CHECK_EQ(0, nfds);
	fd = -1;
	(void)call(fixture.session, TRACECMP_OP_OPEN, &reply, &fd, 1, &nfds);
	ATF_CHECK_EQ(0, ((struct tracecmp_msg *)(void *)reply.bytes)->status);
	ATF_REQUIRE_EQ(1, nfds);
	ATF_CHECK(fcntl(fd, F_GETFD) >= 0);
	close(fd);
	(void)call(fixture.session, TRACECMP_OP_OPEN, &reply, NULL, 0, &nfds);
	ATF_CHECK_EQ(-EALREADY,
	    ((struct tracecmp_msg *)(void *)reply.bytes)->status);
	(void)call(fixture.session, TRACECMP_OP_STATS, &reply, NULL, 0, &nfds);
	message = (void *)reply.bytes;
	stats = (void *)(message + 1);
	ATF_CHECK_EQ(1, stats->opened);
	ATF_CHECK_EQ(1, stats->rejected);
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
	struct fixture fixture;
	int fd;

	fixture_create(&fixture, true, 0);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(call_with_attachment(fixture.session, TRACECMP_OP_HELLO,
	    fd) == -1);
	close(fd);
	fixture_destroy(&fixture);
}
ATF_TC_BODY(authorization_and_device_failures, tc)
{
	union test_buffer reply;
	struct fixture fixture;
	struct tracecmp_msg *message;
	int fd;
	size_t nfds;

	/*
	 * Root (this test runs as root) bypasses the label allowlist: an
	 * unauthorized-label session still obtains the raw DTrace fd on OPEN.
	 * (A non-root, non-allowlisted caller is denied EACCES; that path is not
	 * exercised here because the harness runs as root, and the label
	 * allowlist decision itself is covered by the policy tests.)
	 */
	fixture_create(&fixture, false, 0);
	fd = -1;
	(void)call(fixture.session, TRACECMP_OP_OPEN, &reply, &fd, 1, &nfds);
	message = (void *)reply.bytes;
	ATF_CHECK_EQ(0, message->status);
	ATF_CHECK_EQ(1, nfds);
	if (fd >= 0)
		close(fd);
	fixture_destroy(&fixture);

	fixture_create(&fixture, true, ENXIO);
	(void)call(fixture.session, TRACECMP_OP_HELLO, &reply, NULL, 0, NULL);
	message = (void *)reply.bytes;
	ATF_CHECK_EQ(0,
	    ((struct tracecmp_hello_reply *)(void *)(message + 1))->features);
	(void)call(fixture.session, TRACECMP_OP_OPEN, &reply, NULL, 0, NULL);
	ATF_CHECK_EQ(-ENXIO,
	    ((struct tracecmp_msg *)(void *)reply.bytes)->status);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, authorized_descriptor_is_one_shot);
	ATF_TP_ADD_TC(tp, authorization_and_device_failures);
	ATF_TP_ADD_TC(tp, unexpected_descriptor_poison_session);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, worker_descriptors_cross_exactly_one_fork);
	return (atf_no_error());
}
