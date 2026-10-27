/* SPDX-License-Identifier: BSD-2-Clause */
/* Real PAM dispatch and accounting in disposable child chroots. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>
#include "openpam_impl.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d errno %d: %s\n", __LINE__, errno, #x); return (1); } } while (0)

static int
exercise(int scenario)
{
	struct pam_conv conv = {0};
	pam_handle_t *pam = NULL;
	struct utmpx *record;
	FILE *f;
	int expected, status;

	CHECK(mkdir("var", 0755) == 0);
	CHECK(mkdir("var/run", 0755) == 0);
	CHECK(mkdir("var/log", 0755) == 0);
	CHECK(mkdir("etc", 0755) == 0);
	CHECK(mkdir("etc/pam.d", 0755) == 0);
	f = fopen("etc/pam.d/test", "w");
	CHECK(f != NULL);
	CHECK(fprintf(f, "session required pam_lastlog.so%s\n",
	    scenario >= 3 ? " no_fail" : "") > 0);
	CHECK(fclose(f) == 0);
	CHECK(chmod("etc/pam.d/test", 0600) == 0);
	CHECK(chroot(".") == 0 && chdir("/") == 0);
	CHECK(openpam_set_feature(OPENPAM_FALLBACK_TO_OTHER, 0) == PAM_SUCCESS);
	CHECK(pam_start("test", "alice", &conv, &pam) == PAM_SUCCESS);
	CHECK(pam_set_item(pam, PAM_TTY, "/dev/ttyv0") == PAM_SUCCESS);
	CHECK(pam_set_item(pam, PAM_RHOST, "") == PAM_SUCCESS);
	if (scenario == 1 || scenario == 3)
		CHECK(mkdir("/var/run/utx.active", 0700) == 0);
	expected = scenario == 1 ? PAM_SESSION_ERR : PAM_SUCCESS;
	status = pam_open_session(pam, PAM_SILENT);
	fprintf(stderr, "scenario %d open %d expected %d\n", scenario, status, expected);
	CHECK(status == expected);
	if (scenario == 1 || scenario == 3) {
		CHECK(pam_end(pam, status) == PAM_SUCCESS);
		return (0);
	}
	CHECK(setutxdb(UTXDB_ACTIVE, NULL) == 0);
	record = getutxent();
	CHECK(record != NULL && record->ut_type == USER_PROCESS &&
	    strcmp(record->ut_user, "alice") == 0);
	endutxent();
	if (scenario == 2 || scenario == 4) {
		CHECK(unlink("/var/run/utx.active") == 0);
		CHECK(mkdir("/var/run/utx.active", 0700) == 0);
	}
	expected = scenario == 2 ? PAM_SESSION_ERR : PAM_SUCCESS;
	status = pam_close_session(pam, 0);
	fprintf(stderr, "scenario %d close %d expected %d\n", scenario, status, expected);
	CHECK(status == expected);
	CHECK(pam_end(pam, status) == PAM_SUCCESS);
	if (scenario == 0) {
		CHECK(setutxdb(UTXDB_LOG, NULL) == 0);
		record = getutxent(); CHECK(record != NULL && record->ut_type == USER_PROCESS);
		record = getutxent(); CHECK(record != NULL && record->ut_type == DEAD_PROCESS);
		CHECK(getutxent() == NULL);
		endutxent();
	}
	return (0);
}

ATF_TC(session_accounting);
ATF_TC_HEAD(session_accounting, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(session_accounting, tc)
{
	char directory[32];
	pid_t pid;
	int status, scenario;

	for (scenario = 0; scenario < 5; scenario++) {
		snprintf(directory, sizeof(directory), "root-%d", scenario);
		ATF_REQUIRE_EQ(0, mkdir(directory, 0700));
		pid = fork();
		ATF_REQUIRE(pid >= 0);
		if (pid == 0) {
			if (chdir(directory) != 0)
				_exit(2);
			_exit(exercise(scenario));
		}
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "scenario %d status %#x", scenario, status);
	}
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, session_accounting);
	return (atf_no_error());
}
