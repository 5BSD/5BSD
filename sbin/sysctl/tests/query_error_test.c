/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the actual command entry point; only selected kernel faults are fake. */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int fault_stage, fault_error, format_queries;
static int
query_sysctl(const int *name, u_int length, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	/* These command tests must never mutate the host. */
	if (newp != NULL && !(length == 2 && name[0] == CTL_SYSCTL &&
	    name[1] == CTL_SYSCTL_NAME2OID))
		return (errno = EPERM, -1);
	if (fault_stage == 4 && length == 4 && name[0] == CTL_SYSCTL &&
	    name[1] == CTL_SYSCTL_OIDFMT && ++format_queries == 2)
		return (errno = fault_error, -1);
	if (fault_stage == 3 && oldp != NULL && length == 2 &&
	    name[0] == CTL_KERN && name[1] == KERN_OSTYPE)
		return (errno = fault_error, -1);
	if (length == 2 &&
	    ((fault_stage == 1 && name[0] == CTL_SYSCTL && name[1] == CTL_SYSCTL_NAME2OID) ||
	    (fault_stage == 2 && name[0] == CTL_KERN && name[1] == KERN_OSTYPE)))
		return (errno = fault_error, -1);
	return (sysctl(name, length, oldp, oldlenp, newp, newlen));
}

int sysctl_command_main(int, char **);
#define main sysctl_command_main
#define sysctl query_sysctl
#include "../sysctl.c"
#undef sysctl
#undef main

static int
command_status(int stage, int error, bool ignore)
{
	pid_t child;
	int status, fd;
	char program[] = "sysctl", i[] = "-i", n[] = "-n", name[] = "kern.ostype";
	char *args[] = { program, i, n, name, NULL };

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		fault_stage = stage; fault_error = error;
		fd = open("/dev/null", O_WRONLY);
		if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
			_exit(99);
		if (fd > 2) close(fd);
		optind = optreset = 1;
		if (!ignore) { args[1] = n; args[2] = name; args[3] = NULL; }
		_exit(sysctl_command_main(ignore ? 4 : 3, args));
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(unknown_only);
ATF_TC_BODY(unknown_only, tc)
{
	(void)tc;
	ATF_CHECK_EQ(0, command_status(1, ENOENT, true));
	ATF_CHECK_EQ(1, command_status(1, ENOENT, false));
}
ATF_TC_WITHOUT_HEAD(lookup_failure);
ATF_TC_BODY(lookup_failure, tc)
{
	(void)tc;
	ATF_CHECK_EQ(1, command_status(1, EACCES, true));
	ATF_CHECK_EQ(1, command_status(1, EIO, true));
	ATF_CHECK_EQ(1, command_status(1, ENOMEM, true));
}
ATF_TC_WITHOUT_HEAD(read_failure);
ATF_TC_BODY(read_failure, tc)
{
	(void)tc;
	ATF_CHECK_EQ(1, command_status(2, EACCES, true));
	ATF_CHECK_EQ(1, command_status(2, EIO, true));
	ATF_CHECK_EQ(1, command_status(2, ENOENT, true));
	ATF_CHECK_EQ(1, command_status(2, EIO, false));
	ATF_CHECK_EQ(1, command_status(3, EIO, true));
	ATF_CHECK_EQ(1, command_status(4, EIO, true));
}
ATF_TC_WITHOUT_HEAD(actual_read);
ATF_TC_BODY(actual_read, tc)
{
	(void)tc;
	ATF_CHECK_EQ(0, command_status(0, 0, true));
	ATF_CHECK_EQ(0, command_status(0, 0, false));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unknown_only);
	ATF_TP_ADD_TC(tp, lookup_failure);
	ATF_TP_ADD_TC(tp, read_failure);
	ATF_TP_ADD_TC(tp, actual_read);
	return (atf_no_error());
}
