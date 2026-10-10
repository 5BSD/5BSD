/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

static int denied_protection(uint32_t flags)
{ (void)flags; return (errno = EACCES, -1); }
#define service_worker_enter_capability_mode denied_protection
int bsdaudit_main(void);
#define main bsdaudit_main
#include "../auditcmp.c"
#undef main

ATF_TC(bootstrap_retains_child);
ATF_TC_HEAD(bootstrap_retains_child, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bootstrap_retains_child, tc)
{
	struct audit_worker *head;
	int pair[2], pd = -1, kq, status;
	pid_t pid = -1;
	size_t count;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	ATF_CHECK_ERRNO(EACCES, start_session(pair[0], "system.Log", &pd, &pid) == -1);
	ATF_REQUIRE(pd >= 0 && pid > 0);
	ATF_CHECK(fcntl(pd, F_GETFD) >= 0);
	close(pair[0]);
	close(pair[1]);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	head = calloc(1, sizeof(*head));
	ATF_REQUIRE(head != NULL);
	head->pd = pd;
	head->pid = pid;
	count = 1;
	ATF_REQUIRE_EQ(0, workers_shutdown(kq, &head, &count));
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_ERRNO(EBADF, fcntl(pd, F_GETFD) == -1);
	ATF_CHECK_ERRNO(ECHILD, waitpid(pid, &status, WNOHANG) == -1);
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bootstrap_retains_child);
	return (atf_no_error());
}
