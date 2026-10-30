/* SPDX-License-Identifier: BSD-2-Clause */
#include "includes.h"
#include <sys/wait.h>
#include <atf-c.h>
#include <utmpx.h>
#include "loginrec.h"
#include "sshbuf.h"

struct sshbuf *loginmsg;
int utmpx_write_entry(struct logininfo *);
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d errno %d: %s\n", __LINE__, errno, #x); return (1); } } while (0)

static int
exercise(int scenario)
{
	struct logininfo li = {0};
	struct utmpx *record;
	int result, public_api = scenario >= 3;
	struct stat st;

	CHECK(mkdir("var", 0755) == 0);
	CHECK(mkdir("var/run", 0755) == 0);
	CHECK(mkdir("var/log", 0755) == 0);
	CHECK(chroot(".") == 0 && chdir("/") == 0);
	li.type = LTYPE_LOGIN;
	li.pid = getpid();
	strcpy(li.username, "alice");
	strcpy(li.line, "ttyv0");
	if (scenario == 6 || scenario == 7) {
		if (scenario == 6) {
			CHECK(chmod("/", 0755) == 0);
			CHECK(setuid(65534) == 0);
		}
		else
			li.type = -1;
		CHECK(login_write(&li) == 0);
		CHECK(stat("/var/run/utx.active", &st) == -1 && errno == ENOENT);
		CHECK(stat("/var/log/utx.log", &st) == -1 && errno == ENOENT);
		return (0);
	}
	scenario %= 3;
	if (scenario == 1)
		CHECK(mkdir("/var/run/utx.active", 0700) == 0);
	result = public_api ? login_login(&li) : utmpx_write_entry(&li);
	fprintf(stderr, "scenario %d login %d expected %d\n", scenario, result, scenario == 1 ? 0 : 1);
	CHECK(result == (scenario == 1 ? 0 : 1));
	if (scenario == 1)
		return (0);
	if (scenario == 2) {
		CHECK(unlink("/var/run/utx.active") == 0);
		CHECK(mkdir("/var/run/utx.active", 0700) == 0);
	}
	li.type = LTYPE_LOGOUT;
	result = public_api ? login_logout(&li) : utmpx_write_entry(&li);
	fprintf(stderr, "scenario %d logout %d expected %d\n", scenario, result, scenario == 2 ? 0 : 1);
	CHECK(result == (scenario == 2 ? 0 : 1));
	if (scenario == 0) {
		CHECK(setutxdb(UTXDB_LOG, NULL) == 0);
		record = getutxent(); CHECK(record != NULL && record->ut_type == USER_PROCESS && strcmp(record->ut_user, "alice") == 0);
		record = getutxent(); CHECK(record != NULL && record->ut_type == DEAD_PROCESS);
		CHECK(getutxent() == NULL);
		endutxent();
	}
	return (0);
}
ATF_TC(accounting_io);
ATF_TC_HEAD(accounting_io, tc) { atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(accounting_io, tc)
{
	int scenario, status;
	pid_t pid;
	char directory[32];
	for (scenario = 0; scenario < 8; scenario++) {
		snprintf(directory, sizeof(directory), "root-%d", scenario);
		ATF_REQUIRE_EQ(0, mkdir(directory, 0700));
		pid = fork(); ATF_REQUIRE(pid >= 0);
		if (pid == 0) {
			if (chdir(directory) != 0) _exit(2);
			_exit(exercise(scenario));
		}
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "scenario %d status %#x", scenario, status);
	}
}
ATF_TP_ADD_TCS(tp) { ATF_TP_ADD_TC(tp, accounting_io); return (atf_no_error()); }
