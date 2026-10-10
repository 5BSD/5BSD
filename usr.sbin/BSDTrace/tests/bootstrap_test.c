/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

static int fragment, reads, writes;
static ssize_t
injected_recv(int fd, void *buffer, size_t length, int flags)
{
	if (fragment && ++reads == 1)
		return (errno = EINTR, -1);
	return (recv(fd, buffer, fragment ? 1 : length, flags));
}
static ssize_t
injected_send(int fd, const void *buffer, size_t length, int flags)
{
	ATF_CHECK((flags & MSG_NOSIGNAL) != 0);
	if (fragment && ++writes == 1)
		return (errno = EINTR, -1);
	return (send(fd, buffer, length, flags));
}
static int denied_protection(uint32_t flags)
{ (void)flags; return (errno = EACCES, -1); }
#define service_worker_enter_capability_mode denied_protection
#define recv injected_recv
#define send injected_send
int bsdtrace_main(void);
#define main bsdtrace_main
#include "../tracecmp.c"
#undef main
#undef recv
#undef send

ATF_TC_WITHOUT_HEAD(bootstrap_socket_errors);
ATF_TC_BODY(bootstrap_socket_errors, tc)
{
	int pair[2], child_error, expected;
	char byte;

	for (int mode = 0; mode < 6; mode++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
		fragment = mode == 1;
		reads = writes = 0;
		child_error = mode == 2 ? EACCES : mode == 3 ? -1 : 0;
		ATF_REQUIRE_EQ(mode == 4 ? 1 : sizeof(child_error),
		    write(pair[1], &child_error, mode == 4 ? 1 : sizeof(child_error)));
		if (mode >= 4) {
			close(pair[1]);
			pair[1] = -1;
		}
		expected = mode == 2 ? EACCES : mode == 3 ? EPROTO :
		    mode == 4 ? EIO : mode == 5 ? EPIPE : 0;
		if (expected != 0)
			ATF_CHECK_ERRNO(expected, bootstrap_parent(pair[0]) == -1);
		else {
			ATF_REQUIRE_EQ(0, bootstrap_parent(pair[0]));
			ATF_REQUIRE_EQ(1, read(pair[1], &byte, 1));
			ATF_CHECK_EQ(1, byte);
		}
		if (fragment) {
			ATF_CHECK_EQ(1 + sizeof(child_error), reads);
			ATF_CHECK_EQ(2, writes);
		}
		close(pair[0]);
		if (pair[1] >= 0)
			close(pair[1]);
	}
}
ATF_TC(bootstrap_retains_child);
ATF_TC_HEAD(bootstrap_retains_child, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bootstrap_retains_child, tc)
{
	struct trace_worker *head;
	int pair[2], pd = -1, liveness = -1, kq, status;
	pid_t pid = -1;
	size_t count;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	ATF_CHECK_ERRNO(EACCES, start_session(pair[0], -1, false,
	    "test.bootstrap", 0, &pd, &pid, &liveness) == -1);
	ATF_REQUIRE(pd >= 0 && liveness >= 0 && pid > 0);
	ATF_CHECK(fcntl(pd, F_GETFD) >= 0);
	ATF_CHECK(fcntl(liveness, F_GETFD) >= 0);
	close(pair[0]);
	close(pair[1]);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	head = calloc(1, sizeof(*head));
	ATF_REQUIRE(head != NULL);
	head->pd = pd;
	head->pid = pid;
	head->liveness = liveness;
	count = 1;
	ATF_REQUIRE_EQ(0, workers_shutdown(kq, &head, &count));
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_ERRNO(EBADF, fcntl(pd, F_GETFD) == -1);
	ATF_CHECK_ERRNO(EBADF, fcntl(liveness, F_GETFD) == -1);
	ATF_CHECK_ERRNO(ECHILD, waitpid(pid, &status, WNOHANG) == -1);
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bootstrap_socket_errors);
	ATF_TP_ADD_TC(tp, bootstrap_retains_child);
	return (atf_no_error());
}
