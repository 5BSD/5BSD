/* SPDX-License-Identifier: BSD-2-Clause */
/* Real libc calls inside a disposable child chroot; never host login records. */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d errno %d: %s\n", __LINE__, errno, #x); return (1); } } while (0)

static int
session_writes(int scenario)
{
	struct utmpx entry = { .ut_type = USER_PROCESS }, *record;
	struct rlimit limit;
	struct stat st;
	off_t record_size, history_size;

	strcpy(entry.ut_id, "one");
	strcpy(entry.ut_user, "alice");
	CHECK(pututxline(&entry) != NULL);
	CHECK(stat("/var/run/utx.active", &st) == 0 && st.st_size > 0);
	record_size = st.st_size;
	CHECK(stat("/var/log/utx.log", &st) == 0);
	history_size = st.st_size;
	if (scenario != 10) {
		limit.rlim_cur = limit.rlim_max = record_size - (scenario == 9);
		CHECK(signal(SIGXFSZ, SIG_IGN) != SIG_ERR);
		CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
	}
	if (scenario == 7)
		strcpy(entry.ut_id, "two");
	else if (scenario == 8)
		strcpy(entry.ut_user, "bob");
	else
		entry.ut_type = DEAD_PROCESS;
	errno = 0;
	if (scenario != 10) {
		CHECK(pututxline(&entry) == NULL);
		CHECK(errno == EFBIG);
		if (scenario == 9) {
			CHECK(stat("/var/log/utx.log", &st) == 0);
			CHECK(st.st_size == history_size);
		}
		return (0);
	}
	CHECK(pututxline(&entry) != NULL);
	CHECK(setutxdb(UTXDB_ACTIVE, NULL) == 0);
	record = getutxent();
	CHECK(record != NULL && record->ut_type == DEAD_PROCESS);
	CHECK(getutxent() == NULL);
	endutxent();
	CHECK(setutxdb(UTXDB_LASTLOGIN, NULL) == 0);
	record = getutxent();
	CHECK(record != NULL && record->ut_type == USER_PROCESS &&
	    strcmp(record->ut_user, "alice") == 0);
	CHECK(getutxent() == NULL);
	endutxent();
	CHECK(setutxdb(UTXDB_LOG, NULL) == 0);
	record = getutxent(); CHECK(record != NULL && record->ut_type == USER_PROCESS);
	record = getutxent(); CHECK(record != NULL && record->ut_type == DEAD_PROCESS);
	CHECK(getutxent() == NULL);
	endutxent();
	return (0);
}

static int
exercise(int scenario)
{
	struct utmpx entry = { .ut_type = BOOT_TIME }, *record;
	struct stat st;
	struct timeval earliest, latest;
	int fd;

	if (scenario >= 7)
		return (session_writes(scenario));
	entry.ut_tv.tv_sec = 1;
	if (scenario == 1 || scenario == 2)
		CHECK(mkdir("/var/run/utx.active", 0700) == 0);
	if (scenario == 3)
		CHECK(mkdir("/var/log/utx.lastlogin", 0700) == 0);
	if (scenario == 4 || scenario == 6) {
		struct rlimit limit = { .rlim_cur = 1, .rlim_max = 1 };
		CHECK(signal(SIGXFSZ, SIG_IGN) != SIG_ERR);
		CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
	}
	if (scenario == 5) {
		fd = open("/var/log/utx.lastlogin", O_CREAT | O_WRONLY, 0644);
		CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
	}
	if (scenario == 6) {
		entry.ut_type = OLD_TIME;
		errno = 0;
		CHECK(pututxline(&entry) == NULL);
		CHECK(errno == EIO);
		CHECK(stat("/var/log/utx.log", &st) == 0 && st.st_size == 1);
		CHECK(stat("/var/run/utx.active", &st) == -1 && errno == ENOENT);
		return (0);
	}
	if (scenario == 2)
		entry.ut_type = SHUTDOWN_TIME;
	if (scenario >= 1 && scenario <= 4) {
		errno = 0;
		CHECK(pututxline(&entry) == NULL);
		CHECK(errno == (scenario == 4 ? EIO : EISDIR));
		CHECK(stat("/var/log/utx.log", &st) == -1 && errno == ENOENT);
		if (scenario == 4)
			CHECK(stat("/var/run/utx.active", &st) == 0 && st.st_size == 1);
		return (0);
	}
	CHECK(gettimeofday(&earliest, NULL) == 0);
	CHECK(pututxline(&entry) != NULL);
	CHECK(gettimeofday(&latest, NULL) == 0);
	CHECK(setutxdb(UTXDB_ACTIVE, NULL) == 0);
	record = getutxent();
	CHECK(record != NULL && record->ut_type == BOOT_TIME && record->ut_tv.tv_sec >= earliest.tv_sec && record->ut_tv.tv_sec <= latest.tv_sec);
	CHECK(getutxent() == NULL);
	endutxent();
	if (scenario == 5)
		CHECK(stat("/var/log/utx.lastlogin", &st) == 0 && st.st_size == 0);
	else
		CHECK(stat("/var/log/utx.lastlogin", &st) == -1 && errno == ENOENT);
	entry.ut_type = SHUTDOWN_TIME;
	CHECK(pututxline(&entry) != NULL);
	CHECK(stat("/var/run/utx.active", &st) == 0 && st.st_size == 0);
	CHECK(setutxdb(UTXDB_LOG, NULL) == 0);
	record = getutxent(); CHECK(record != NULL && record->ut_type == BOOT_TIME);
	record = getutxent(); CHECK(record != NULL && record->ut_type == SHUTDOWN_TIME);
	CHECK(getutxent() == NULL);
	endutxent();
	return (0);
}

static void
isolated(int scenario)
{
	char root[] = "utx-root.XXXXXX", path[128];
	pid_t child;
	int status;

	ATF_REQUIRE(mkdtemp(root) != NULL);
	snprintf(path, sizeof(path), "%s/var", root);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/run", root);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	snprintf(path, sizeof(path), "%s/var/log", root);
	ATF_REQUIRE(mkdir(path, 0755) == 0);
	child = fork(); ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (chdir(root) != 0 || chroot(".") != 0 || chdir("/") != 0)
			_exit(2);
		_exit(exercise(scenario));
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "isolated utx scenario %d failed: status %#x", scenario, status);
}

#define CASE(name, scenario) \
ATF_TC(name); \
ATF_TC_HEAD(name, tc) { atf_tc_set_md_var(tc, "require.user", "root"); } \
ATF_TC_BODY(name, tc) { (void)tc; isolated(scenario); }
CASE(boot_shutdown_records, 0)
CASE(boot_active_error, 1)
CASE(shutdown_active_error, 2)
CASE(lastlogin_error, 3)
CASE(short_boot_write, 4)
CASE(lastlogin_upgrade, 5)
CASE(short_history_write, 6)

CASE(active_flush_error, 7)

CASE(lastlogin_flush_error, 8)

CASE(logout_flush_error, 9)

CASE(session_records, 10)

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, boot_shutdown_records);
	ATF_TP_ADD_TC(tp, boot_active_error);
	ATF_TP_ADD_TC(tp, shutdown_active_error);
	ATF_TP_ADD_TC(tp, lastlogin_error);
	ATF_TP_ADD_TC(tp, short_boot_write);
	ATF_TP_ADD_TC(tp, lastlogin_upgrade);
	ATF_TP_ADD_TC(tp, short_history_write);
	ATF_TP_ADD_TC(tp, active_flush_error);
	ATF_TP_ADD_TC(tp, lastlogin_flush_error);
	ATF_TP_ADD_TC(tp, logout_flush_error);
	ATF_TP_ADD_TC(tp, session_records);
	return (atf_no_error());
}
