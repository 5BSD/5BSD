/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/cap_process.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static int step, fail_step, original[4];
static struct stat expected[3];
static void
check(bool condition)
{
	if (!condition) _exit(125);
}
static long
clear_authority(long number, ...)
{
	va_list ap;
	check((step == 0 || step == 1) && number == SYS_cap_process);
	va_start(ap, number);
	check(va_arg(ap, int) == (step == 0 ? CAP_AUTH_CLEAR : MAC_CAP_PROCESS_CLEAR));
	check(va_arg(ap, int) == -1);
	check(va_arg(ap, int) == 0);
	check(va_arg(ap, void *) == NULL);
	va_end(ap);
	step++;
	if (fail_step == step) { errno = EPERM; return (-1); }
	return (0);
}
static int
no_new_privs(idtype_t type, id_t id, int command, void *data)
{
	check(step == 2 && type == P_PID && id == (id_t)getpid() &&
	    command == PROC_NO_NEW_PRIVS_CTL &&
	    *(int *)data == PROC_NO_NEW_PRIVS_ENABLE);
	step = 3;
	if (fail_step == step) { errno = EPERM; return (-1); }
	return (procctl(type, id, command, data));
}
static int
replace_stdio(int from, int to)
{
	check(step >= 3 && step <= 5 && to == step - 3);
	step++;
	if (fail_step == step) { errno = EBADF; return (-1); }
	return (dup2(from, to));
}
static void
close_inherited(int low)
{
	check(step == 6 && low == 3);
	step = 7;
	closefrom(low);
}
static int
execute_helper(const char *path, char *const argv[], char *const env[])
{
	struct stat st;
	int state;
	check(step == 7 && strcmp(path, "/usr/bin/true") == 0 &&
	    strcmp(argv[0], path) == 0 && argv[1] == NULL && env[0] == NULL);
	step = 8;
	check(procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS, &state) == 0 &&
	    state == PROC_NO_NEW_PRIVS_ENABLE);
	for (int i = 0; i < 3; i++) {
		check(fstat(i, &st) == 0 && st.st_dev == expected[i].st_dev &&
		    st.st_ino == expected[i].st_ino);
		check((fcntl(i, F_GETFD) & FD_CLOEXEC) == 0);
	}
	for (size_t i = 0; i < nitems(original); i++) {
		errno = 0;
		check(fcntl(original[i], F_GETFD) == -1 && errno == EBADF);
	}
	if (fail_step == step) { errno = ENOENT; return (-1); }
	return (execve(path, argv, env));
}
static void __dead2
exit_child(int status)
{
	check(status == 126 && step == fail_step);
	_exit(status);
}
#define syscall clear_authority
#define procctl no_new_privs
#define dup2 replace_stdio
#define closefrom close_inherited
#define execve execute_helper
#define _exit exit_child
#include "../nss_child.c"
#undef syscall
#undef procctl
#undef dup2
#undef closefrom
#undef execve
#undef _exit

static void
run_child(int failure, bool invalid)
{
	int input[2], output[2], status;
	pid_t pid;
	ATF_REQUIRE(pipe(input) == 0);
	ATF_REQUIRE(pipe(output) == 0);
	original[0] = input[0]; original[1] = output[1];
	original[2] = open("/dev/null", O_WRONLY | O_CLOEXEC);
	original[3] = open("/dev/null", O_RDONLY | O_CLOEXEC);
	for (size_t i = 0; i < nitems(original); i++) ATF_REQUIRE(original[i] >= 3);
	for (int i = 0; i < 3; i++) ATF_REQUIRE(fstat(original[i], &expected[i]) == 0);
	fail_step = failure; step = 0;
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0)
		sb_nss_child_exec("/usr/bin/true", invalid ? original[1] : original[0],
		    original[1], original[2]);
	ATF_REQUIRE_EQ(waitpid(pid, &status, 0), pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(WEXITSTATUS(status), failure != 0 || invalid ? 126 : 0);
	for (size_t i = 0; i < nitems(original); i++) {
		/* Child cleanup must leave the parent's descriptors intact. */
		ATF_REQUIRE(fcntl(original[i], F_GETFD) >= 0);
		close(original[i]);
	}
	close(input[1]); close(output[0]);
}
ATF_TC_WITHOUT_HEAD(child_setup);
ATF_TC_BODY(child_setup, tc)
{
	run_child(0, false);
}
ATF_TC_WITHOUT_HEAD(setup_failures);
ATF_TC_BODY(setup_failures, tc)
{
	for (int failure = 1; failure <= 6; failure++) run_child(failure, false);
	run_child(8, false);
	run_child(0, true);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, child_setup);
	ATF_TP_ADD_TC(tp, setup_failures);
	return (atf_no_error());
}
