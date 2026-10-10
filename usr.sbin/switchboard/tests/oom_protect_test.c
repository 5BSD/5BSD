/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/proc.h>
#include <sys/procctl.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
static unsigned calls;
static int injected_error;
static bool real_call;
static int
check_procctl(idtype_t type, id_t id, int command, void *data)
{
	calls++;
	ATF_CHECK_EQ(P_PID, type);
	ATF_CHECK(id > 0);
	ATF_CHECK_EQ(PROC_SPROTECT, command);
	ATF_CHECK_EQ(PPROT_SET, *(int *)data);
	if (real_call)
		return (procctl(type, id, command, data));
	if (injected_error != 0)
		return (errno = injected_error, -1);
	return (0);
}
#define procctl check_procctl
#include "../oom_protect.c"
#undef procctl
ATF_TC_WITHOUT_HEAD(authority_and_failures);
ATF_TC_BODY(authority_and_failures, tc)
{
	ATF_CHECK_EQ(0, svc_oom_protect(123, false, false));
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK_ERRNO(EPERM, svc_oom_protect(123, true, false) == -1);
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK_ERRNO(EINVAL, svc_oom_protect(0, true, true) == -1);
	ATF_CHECK_EQ(0, calls);
	ATF_CHECK_EQ(0, svc_oom_protect(123, true, true));
	ATF_CHECK_EQ(1, calls);
	injected_error = EPERM;
	ATF_CHECK_ERRNO(EPERM, svc_oom_protect(123, true, true) == -1);
	injected_error = ESRCH;
	ATF_CHECK_ERRNO(ESRCH, svc_oom_protect(123, true, true) == -1);
}
static bool
protected(pid_t pid)
{
	struct kinfo_proc info;
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
	size_t length = sizeof(info);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_EQ(0, sysctl(mib, 4, &info, &length, NULL, 0));
	ATF_REQUIRE_EQ(sizeof(info), length);
	return ((info.ki_flag & P_PROTECTED) != 0);
}
ATF_TC(kernel_lifetime);
ATF_TC_HEAD(kernel_lifetime, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "OOM exclusion survives credential/capmode transition but is not inherited by fork");
}
ATF_TC_BODY(kernel_lifetime, tc)
{
	int gate[2], reply[2], status;
	pid_t child, grandchild;
	char byte;
	ATF_REQUIRE_EQ(0, pipe(gate));
	ATF_REQUIRE_EQ(0, pipe(reply));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(gate[1]); close(reply[0]);
		if (read(gate[0], &byte, 1) != 1) _exit(1);
		if (!protected(getpid())) _exit(2);
		grandchild = fork();
		if (grandchild == 0) _exit(protected(getpid()) ? 3 : 0);
		if (grandchild < 0 || waitpid(grandchild, &status, 0) != grandchild || status != 0) _exit(4);
		if (setgid(65534) != 0 || setuid(65534) != 0 || cap_enter() != 0) _exit(5);
		int flags = PPROT_CLEAR;
		if (procctl(P_PID, 0, PROC_SPROTECT, &flags) != -1) _exit(8);
		if (write(reply[1], "R", 1) != 1) _exit(6);
		if (read(gate[0], &byte, 1) != 1) _exit(7);
		_exit(0);
	}
	close(gate[0]); close(reply[1]);
	real_call = true;
	ATF_REQUIRE_EQ(0, svc_oom_protect(child, true, true));
	ATF_REQUIRE(protected(child));
	ATF_REQUIRE_EQ(1, write(gate[1], "R", 1));
	ATF_REQUIRE_EQ(1, read(reply[0], &byte, 1));
	ATF_CHECK(protected(child));
	ATF_REQUIRE_EQ(1, write(gate[1], "X", 1));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(gate[1]); close(reply[0]);
}
ATF_TC(unprivileged_self_denied);
ATF_TC_HEAD(unprivileged_self_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(unprivileged_self_denied, tc)
{
	pid_t child;
	int flags = PPROT_SET, status;
	ATF_CHECK_ERRNO(EPERM, procctl(P_PID, 0, PROC_SPROTECT, &flags) == -1);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (cap_enter() != 0) _exit(1);
		int result = procctl(P_PID, 0, PROC_SPROTECT, &flags);
		_exit(result == -1 && (errno == EPERM || errno == ECAPMODE) ? 0 : 2);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unprivileged_self_denied);
	ATF_TP_ADD_TC(tp, authority_and_failures);
	ATF_TP_ADD_TC(tp, kernel_lifetime);
	return (atf_no_error());
}
