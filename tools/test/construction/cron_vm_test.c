/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
ATF_TC(cron_descriptors);
ATF_TC_HEAD(cron_descriptors, tc)
{
	atf_tc_set_md_var(tc, "descr", "Actual cron job descriptor and standard stream isolation");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
static void
run_image_test(const char *argument)
{
	pid_t child;
	int status;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (setenv("LD_LIBRARY_PATH", "/usr/local/lib", 1) != 0)
			_exit(126);
		if (argument != NULL)
			execl("/usr/local/bin/python3.12", "/usr/local/bin/python3.12", "-I", "-S", "-B",
			    "/tests/cron_descriptors.py", "--user-tables", "--pam-policy",
			    "/tests/pam-cron", "--pam-fallback", "/tests/pam-other",
			    strcmp(argument, "trace") == 0 ? "--debug-cron" : NULL,
			    "--ktrace", "/usr/bin/ktrace", "--kdump", "/usr/bin/kdump", NULL);
		else
			execl("/usr/local/bin/python3.12", "/usr/local/bin/python3.12", "-I", "-S", "-B",
			    "/tests/cron_descriptors.py", NULL);
		_exit(127);
	}
	while (waitpid(child, &status, 0) == -1)
		ATF_REQUIRE(errno == EINTR);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "cron descriptor test failed, status %d", status);
}
ATF_TC_BODY(cron_descriptors, tc)
{
	(void)tc;
	run_image_test(NULL);
}
ATF_TC(cron_user_tables);
ATF_TC_HEAD(cron_user_tables, tc)
{
	atf_tc_set_md_var(tc, "descr", "Actual cron per-user jobs through selected PAM policy");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(cron_user_tables, tc)
{
	(void)tc;
	run_image_test("user-tables");
}
ATF_TC(cron_user_trace);
ATF_TC_HEAD(cron_user_trace, tc)
{
	atf_tc_set_md_var(tc, "descr", "Diagnostic cron per-user execution tracing");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(cron_user_trace, tc)
{
	(void)tc;
	run_image_test("trace");
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cron_descriptors);
	ATF_TP_ADD_TC(tp, cron_user_tables);
	ATF_TP_ADD_TC(tp, cron_user_trace);
	return atf_no_error();
}
