/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "session.h"

static struct networkcmp_handle
create_socket(struct networkcmp_session *session, uint32_t family,
    uint32_t type)
{
	struct networkcmp_socket_request request;
	struct networkcmp_handle_reply reply;

	memset(&request, 0, sizeof(request));
	request.family = family;
	request.type = type;
	ATF_REQUIRE(networkcmp_session_socket(session, &request, &reply) == 0);
	return (reply.socket);
}

ATF_TC(lifecycle_and_stale_handles);
ATF_TC_HEAD(lifecycle_and_stale_handles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Socket handles are generation tagged and stale handles never alias");
}
ATF_TC_BODY(lifecycle_and_stale_handles, tc)
{
	struct networkcmp_session session;
	struct networkcmp_handle first, second;

	ATF_REQUIRE(networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS) == 0);
	first = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM);
	ATF_REQUIRE(networkcmp_session_lookup(&session, first) != NULL);
	ATF_REQUIRE(networkcmp_session_close(&session, first) == 0);
	ATF_CHECK_ERRNO(ESTALE,
	    networkcmp_session_lookup(&session, first) == NULL);
	second = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM);
	ATF_CHECK_EQ(first.handle, second.handle);
	ATF_CHECK(first.generation != second.generation);
	ATF_CHECK_ERRNO(ESTALE,
	    networkcmp_session_lookup(&session, first) == NULL);
	networkcmp_session_destroy(&session);
}

ATF_TC(exhaustion_is_atomic);
ATF_TC_HEAD(exhaustion_is_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The per-session socket bound is exact and failed allocation leaks no authority");
}
ATF_TC_BODY(exhaustion_is_atomic, tc)
{
	struct networkcmp_session session;
	struct networkcmp_handle handles[NETWORKCMP_SESSION_MAX_SOCKETS];
	struct networkcmp_handle extra;
	int fd;
	size_t i;

	ATF_REQUIRE(networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS) == 0);
	for (i = 0; i < nitems(handles); i++)
		handles[i] = create_socket(&session, NETWORKCMP_AF_INET4,
		    NETWORKCMP_SOCK_DGRAM);
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	ATF_REQUIRE(fd >= 0);
	memset(&extra, 0xa5, sizeof(extra));
	ATF_CHECK_ERRNO(EMFILE,
	    networkcmp_session_allocate(&session, fd, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM, &extra) == -1);
	ATF_CHECK_EQ(UINT64_C(0xa5a5a5a5a5a5a5a5), extra.handle);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	close(fd);
	for (i = 0; i < nitems(handles); i++)
		ATF_REQUIRE(networkcmp_session_close(&session, handles[i]) == 0);
	networkcmp_session_destroy(&session);
}

ATF_TC(invalid_requests);
ATF_TC_HEAD(invalid_requests, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Internal socket creation independently rejects malformed protocol combinations");
}
ATF_TC_BODY(invalid_requests, tc)
{
	struct networkcmp_session session;
	struct networkcmp_socket_request request;
	struct networkcmp_handle_reply reply;

	ATF_REQUIRE(networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS) == 0);
	memset(&request, 0, sizeof(request));
	request.family = NETWORKCMP_AF_UNSPEC;
	request.type = NETWORKCMP_SOCK_STREAM;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_session_socket(&session, &request, &reply) == -1);
	request.family = NETWORKCMP_AF_INET4;
	request.type = NETWORKCMP_SOCK_DGRAM;
	request.protocol = IPPROTO_TCP;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_session_socket(&session, &request, &reply) == -1);
	request.protocol = 0;
	request.flags = 1;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_session_socket(&session, &request, &reply) == -1);
	ATF_CHECK_ERRNO(EBADF,
	    networkcmp_session_lookup(&session,
	    (struct networkcmp_handle){ .handle = 0, .generation = 1 }) == NULL);
	networkcmp_session_destroy(&session);
}

ATF_TC(capability_mode);
ATF_TC_HEAD(capability_mode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A provider worker can create and retire kernel sockets after cap_enter");
}
ATF_TC_BODY(capability_mode, tc)
{
	struct networkcmp_session session;
	struct networkcmp_handle handle;
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (networkcmp_session_init(&session,
		    NETWORKCMP_SESSION_MAX_SOCKETS) == -1)
			_exit(1);
		if (cap_enter() == -1)
			_exit(2);
		handle = create_socket(&session, NETWORKCMP_AF_INET4,
		    NETWORKCMP_SOCK_DGRAM);
		if (networkcmp_session_close(&session, handle) == -1)
			_exit(3);
		networkcmp_session_destroy(&session);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "capability-mode socket worker exited with status %#x", status);
}

ATF_TC(destroy_closes_all);
ATF_TC_HEAD(destroy_closes_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Session destruction closes every provider-owned socket");
}
ATF_TC_BODY(destroy_closes_all, tc)
{
	struct networkcmp_session session;
	struct networkcmp_session_socket *socket;
	struct networkcmp_handle handle;
	int fd;

	ATF_REQUIRE(networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS) == 0);
	handle = create_socket(&session, NETWORKCMP_AF_INET6,
	    NETWORKCMP_SOCK_STREAM);
	socket = networkcmp_session_lookup(&session, handle);
	ATF_REQUIRE(socket != NULL);
	fd = socket->fd;
	networkcmp_session_destroy(&session);
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
}

ATF_TC(socket_options);
ATF_TC_HEAD(socket_options, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Only bounded, explicitly allow-listed socket options are accepted");
}

ATF_TC(sockets_are_nonblocking);
ATF_TC_HEAD(sockets_are_nonblocking, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "provider TCP/UDP sockets and accepted sockets cannot stall the session worker");
}
ATF_TC_BODY(sockets_are_nonblocking, tc)
{
	struct networkcmp_session session;
	struct networkcmp_session_socket *socket;
	struct networkcmp_handle tcp, udp;

	ATF_REQUIRE_EQ(0, networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS));
	tcp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_STREAM);
	udp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM);
	socket = networkcmp_session_lookup(&session, tcp);
	ATF_REQUIRE(socket != NULL);
	ATF_CHECK((fcntl(socket->fd, F_GETFL) & O_NONBLOCK) != 0);
	socket = networkcmp_session_lookup(&session, udp);
	ATF_REQUIRE(socket != NULL);
	ATF_CHECK((fcntl(socket->fd, F_GETFL) & O_NONBLOCK) != 0);
	networkcmp_session_destroy(&session);
}

ATF_TC(connect_status);
ATF_TC_HEAD(connect_status, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "connect completion polling is nonblocking and rejects invalid socket state");
}
ATF_TC_BODY(connect_status, tc)
{
	struct networkcmp_session session;
	struct networkcmp_session_socket *socket;
	struct networkcmp_handle tcp, udp;
	int pair[2];

	ATF_REQUIRE_EQ(0, networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS));
	tcp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_STREAM);
	udp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM);
	ATF_CHECK_ERRNO(ENOTCONN,
	    networkcmp_session_connect_status(&session, tcp) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP,
	    networkcmp_session_connect_status(&session, udp) == -1);
	socket = networkcmp_session_lookup(&session, tcp);
	ATF_REQUIRE(socket != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX,
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair));
	close(socket->fd);
	socket->fd = pair[0];
	socket->connect_started = true;
	socket->connect_complete = false;
	ATF_CHECK_EQ(0, networkcmp_session_connect_status(&session, tcp));
	ATF_CHECK(socket->connect_complete);
	close(pair[1]);
	ATF_REQUIRE_EQ(0, networkcmp_session_close(&session, tcp));
	ATF_CHECK_ERRNO(ESTALE,
	    networkcmp_session_connect_status(&session, tcp) == -1);
	networkcmp_session_destroy(&session);
}
ATF_TC_BODY(socket_options, tc)
{
	struct networkcmp_session session;
	struct networkcmp_handle tcp, udp;
	int setting;

	ATF_REQUIRE(networkcmp_session_init(&session,
	    NETWORKCMP_SESSION_MAX_SOCKETS) == 0);
	tcp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_STREAM);
	udp = create_socket(&session, NETWORKCMP_AF_INET4,
	    NETWORKCMP_SOCK_DGRAM);
	setting = 1;
	ATF_CHECK_EQ(0, networkcmp_session_setopt(&session, tcp, SOL_SOCKET,
	    SO_KEEPALIVE, &setting, sizeof(setting)));
	ATF_CHECK_EQ(0, networkcmp_session_setopt(&session, tcp, IPPROTO_TCP,
	    TCP_NODELAY, &setting, sizeof(setting)));
	ATF_CHECK_ERRNO(ENOPROTOOPT,
	    networkcmp_session_setopt(&session, udp, IPPROTO_TCP, TCP_NODELAY,
	    &setting, sizeof(setting)) == -1);
	setting = 32 * 1024 * 1024;
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_session_setopt(&session, tcp, SOL_SOCKET, SO_SNDBUF,
	    &setting, sizeof(setting)) == -1);
	setting = 1;
	ATF_CHECK_ERRNO(ENOPROTOOPT,
	    networkcmp_session_setopt(&session, tcp, SOL_SOCKET, SO_BROADCAST,
	    &setting, sizeof(setting)) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    networkcmp_session_setopt(&session, tcp, SOL_SOCKET, SO_KEEPALIVE,
	    &setting, sizeof(setting) - 1) == -1);
	networkcmp_session_destroy(&session);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lifecycle_and_stale_handles);
	ATF_TP_ADD_TC(tp, exhaustion_is_atomic);
	ATF_TP_ADD_TC(tp, invalid_requests);
	ATF_TP_ADD_TC(tp, capability_mode);
	ATF_TP_ADD_TC(tp, destroy_closes_all);
	ATF_TP_ADD_TC(tp, socket_options);
	ATF_TP_ADD_TC(tp, sockets_are_nonblocking);
	ATF_TP_ADD_TC(tp, connect_status);
	return (atf_no_error());
}
