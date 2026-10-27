/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "nss_exchange.h"

static int mode, observer = -1;
static bool reject_fork, expire_setup;
static unsigned clock_calls, fork_calls;
static int
controlled_clock(clockid_t clock, struct timespec *time)
{
	int result = clock_gettime(clock, time);
	if (result == 0 && expire_setup && ++clock_calls > 1) time->tv_sec++;
	return (result);
}
static pid_t
tracked_fork(int *pd, int flags)
{
	pid_t pid;
	fork_calls++;
	if (flags != (PD_CLOEXEC | PD_NOWAITPID | PD_PROTECTED)) {
		errno = EINVAL; return (-1);
	}
	if (reject_fork) { errno = EINVAL; return (-1); }
	pid = pdfork(pd, flags);
	if (pid == -1 && (errno == EINVAL || errno == EOPNOTSUPP))
		atf_tc_skip("running kernel does not support required protected pdfork flags");
	if (pid > 0) {
		observer = dup(*pd);
		ATF_REQUIRE(observer >= 0);
	}
	return (pid);
}
static void __dead2
fixture(const char *path __unused, int input, int output, int diagnostic __unused)
{
	struct sb_nss_request request;
	struct sb_nss_reply reply = { .version = SB_NSS_VERSION, .uid = 100,
	    .gid = 200, .name = "account", .home = "/home/account", .shell = "/bin/sh" };
	if (dup2(input, 0) == -1 || dup2(output, 1) == -1) _exit(90);
	closefrom(3);
	if (read(0, &request, sizeof(request)) != sizeof(request)) _exit(91);
	if (mode == 1) for (;;) pause();
	if (mode == 2) _exit(1);
	if (mode == 3) reply.uid++;
	if (mode == 4) reply.version++;
	if (write(1, &reply, mode == 5 ? sizeof(reply) - 1 : sizeof(reply)) < 0) _exit(92);
	if (mode == 6 && write(1, "x", 1) != 1) _exit(93);
	if (mode == 7) for (;;) pause();
	close(1);
	if (mode == 8) for (;;) pause();
	_exit(0);
}
#define clock_gettime controlled_clock
#define pdfork tracked_fork
#define sb_nss_child_exec fixture
#include "../nss_exchange.c"
#undef clock_gettime
#undef pdfork
#undef sb_nss_child_exec

static void
exchange(int selected_mode, int expected_error)
{
	struct sb_nss_request req = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = 100 };
	struct sb_nss_reply reply, zero = {0};
	struct timespec start, end;
	int diagnostic, result, error, status;
	diagnostic = open("/dev/null", O_WRONLY | O_CLOEXEC);
	ATF_REQUIRE(diagnostic >= 0);
	mode = selected_mode;
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	result = sb_nss_exchange("/fixture", diagnostic, &req, 100, 100, &reply);
	error = errno;
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	ATF_REQUIRE(end.tv_sec - start.tv_sec < 5);
	if (expected_error == 0) {
		ATF_REQUIRE_MSG(result == 0, "exchange failed: errno=%d (%s), observer=%d", error, strerror(error), observer);
		ATF_REQUIRE_EQ(reply.uid, 100);
		ATF_REQUIRE_STREQ(reply.name, "account");
	} else {
		ATF_REQUIRE_EQ(result, -1);
		ATF_REQUIRE_EQ(error, expected_error);
		ATF_REQUIRE(memcmp(&reply, &zero, sizeof(reply)) == 0);
	}
	/* Hold an independent descriptor only in the test so we can observe
	 * eventual exit after the exchange has released its own descriptor. */
	ATF_REQUIRE(observer >= 0);
	struct pollfd pfd = { .fd = observer };
	ATF_REQUIRE(poll(&pfd, 1, 2000) > 0);
	ATF_REQUIRE_EQ(pdwait(observer, &status, WEXITED | WNOHANG, NULL, NULL), 0);
	if (expected_error == ETIMEDOUT) {
		ATF_REQUIRE(WIFSIGNALED(status));
		ATF_REQUIRE_EQ(WTERMSIG(status), SIGKILL);
	}
	close(observer); observer = -1;
	ATF_REQUIRE(fcntl(diagnostic, F_GETFD) >= 0);
	close(diagnostic);
}
ATF_TC_WITHOUT_HEAD(complete_reply);
ATF_TC_BODY(complete_reply, tc)
{
	exchange(0, 0);
}
ATF_TC_WITHOUT_HEAD(rejected_replies);
ATF_TC_BODY(rejected_replies, tc)
{
	exchange(2, EIO);
	exchange(3, EPERM);
	exchange(4, EPROTO);
	exchange(5, EPROTO);
	exchange(6, EPROTO);
}
ATF_TC_WITHOUT_HEAD(deadlines);
ATF_TC_BODY(deadlines, tc)
{
	exchange(1, ETIMEDOUT);
	exchange(7, ETIMEDOUT);
	exchange(8, ETIMEDOUT);
}
ATF_TC_WITHOUT_HEAD(launch_refusal);
ATF_TC_BODY(launch_refusal, tc)
{
	struct sb_nss_request req = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = 100 };
	struct sb_nss_reply reply, zero = {0};
	int diagnostic = open("/dev/null", O_WRONLY | O_CLOEXEC);
	ATF_REQUIRE(diagnostic >= 0);
	reject_fork = true;
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(sb_nss_exchange("/fixture", diagnostic, &req, 100, 100,
	    &reply), -1);
	ATF_REQUIRE_EQ(errno, EINVAL);
	ATF_REQUIRE(memcmp(&reply, &zero, sizeof(reply)) == 0);
	ATF_REQUIRE_EQ(observer, -1);
	ATF_REQUIRE(fcntl(diagnostic, F_GETFD) >= 0);
	close(diagnostic);
}
ATF_TC_WITHOUT_HEAD(setup_deadline);
ATF_TC_BODY(setup_deadline, tc)
{
	struct sb_nss_request req = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = 100 };
	struct sb_nss_reply reply, zero = {0};
	int diagnostic = open("/dev/null", O_WRONLY | O_CLOEXEC);
	ATF_REQUIRE(diagnostic >= 0);
	expire_setup = true;
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(sb_nss_exchange("/fixture", diagnostic, &req, 100, 100,
	    &reply), -1);
	ATF_REQUIRE_EQ(errno, ETIMEDOUT);
	ATF_REQUIRE(memcmp(&reply, &zero, sizeof(reply)) == 0);
	ATF_REQUIRE_EQ(fork_calls, 0);
	ATF_REQUIRE(fcntl(diagnostic, F_GETFD) >= 0);
	close(diagnostic);
}
/* Use a disposable ordinary child to avoid altering ATF's descriptors or
 * limits. The actual exchange setup runs; only pdfork is refused. A low fd
 * limit and repeated failures expose leaked pipe/diagnostic descriptors. */
static void
cleanup_child(bool closed_stdio, rlim_t fd_limit)
{
	struct rlimit limit = {fd_limit, fd_limit};
	struct sb_nss_request req = { .version = SB_NSS_VERSION,
	    .operation = SB_NSS_USER_UID, .id = 100 };
	struct sb_nss_reply reply, zero = {0};
	int fd, diagnostic;
	int expected_error = fd_limit < 9 ? EMFILE : EINVAL;

	closefrom(3);
	if (setrlimit(RLIMIT_NOFILE, &limit) == -1) _exit(10);
	fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (fd == -1) _exit(11);
	diagnostic = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (diagnostic == -1) _exit(12);
	close(fd);
	if (closed_stdio)
		for (int i = 0; i < 3; i++) close(i);
	reject_fork = true;
	for (int iteration = 0; iteration < 128; iteration++) {
		memset(&reply, 0xa5, sizeof(reply));
		if (sb_nss_exchange("/fixture", diagnostic, &req, 100, 1000,
		    &reply) != -1 || errno != expected_error) _exit(13);
		if (memcmp(&reply, &zero, sizeof(reply)) != 0) _exit(14);
		if (fcntl(diagnostic, F_GETFD) == -1) _exit(15);
		if (closed_stdio)
			for (int i = 0; i < 3; i++)
				if (fcntl(i, F_GETFD) != -1 || errno != EBADF)
					_exit(16);
	}
	if (fork_calls != (fd_limit < 9 ? 0U : 128U)) _exit(17);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(descriptor_cleanup);
ATF_TC_BODY(descriptor_cleanup, tc)
{
	for (int closed_stdio = 0; closed_stdio < 2; closed_stdio++) {
	    for (rlim_t fd_limit = 5; fd_limit <= 9; fd_limit++) {
		pid_t child = fork();
		int status;
		ATF_REQUIRE(child != -1);
		if (child == 0) cleanup_child(closed_stdio != 0, fd_limit);
		ATF_REQUIRE_EQ(waitpid(child, &status, 0), child);
		ATF_REQUIRE(WIFEXITED(status));
		ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
		    "cleanup child failed: closed_stdio=%d fd_limit=%ju status=%d",
		    closed_stdio, (uintmax_t)fd_limit, WEXITSTATUS(status));
	    }
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, descriptor_cleanup);
	ATF_TP_ADD_TC(tp, setup_deadline);
	ATF_TP_ADD_TC(tp, launch_refusal);
	ATF_TP_ADD_TC(tp, complete_reply);
	ATF_TP_ADD_TC(tp, rejected_replies);
	ATF_TP_ADD_TC(tp, deadlines);
	return (atf_no_error());
}
