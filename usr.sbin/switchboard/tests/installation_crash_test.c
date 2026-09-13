/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Process-death and I/O-failure tests of the production publication path.
 * Linker wrappers exist only in this test binary; no production fault switches.
 */
#include <sys/stat.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "switchboard_lifecycle.h"

enum boundary {
	BEFORE_FILE_SYNC = 1, AFTER_FILE_SYNC, BEFORE_RENAME, AFTER_RENAME,
	BEFORE_DIR_SYNC, AFTER_DIR_SYNC, BEFORE_MARKER_SYNC, AFTER_MARKER_SYNC
};
static unsigned fault, sync_count;
static bool io_failure;
static const char label[] = "org.test/app";
static const char first[] = "11111111111111111111111111111111";
static const char second[] = "22222222222222222222222222222222";

int __real_fsync(int);
int __real_renameat(int, const char *, int, const char *);
int __wrap_fsync(int);
int __wrap_renameat(int, const char *, int, const char *);

static int
inject(unsigned point)
{
	if (fault != point)
		return (0);
	if (io_failure)
		return (errno = EIO, -1);
	(void)kill(getpid(), SIGKILL);
	_exit(120);
}

int
__wrap_fsync(int fd)
{
	unsigned before = 0, after = 0;
	int result;

	if (fault != 0) {
		sync_count++;
		if (sync_count == 1) { before = BEFORE_FILE_SYNC; after = AFTER_FILE_SYNC; }
		if (sync_count == 2) { before = BEFORE_DIR_SYNC; after = AFTER_DIR_SYNC; }
		if (sync_count == 3) { before = BEFORE_MARKER_SYNC; after = AFTER_MARKER_SYNC; }
	}
	if (before != 0 && inject(before) == -1)
		return (-1);
	result = __real_fsync(fd);
	if (result == 0 && after != 0 && inject(after) == -1)
		return (-1);
	return (result);
}

int
__wrap_renameat(int from, const char *old, int to, const char *name)
{
	int result;

	if (inject(BEFORE_RENAME) == -1)
		return (-1);
	result = __real_renameat(from, old, to, name);
	if (result == 0 && inject(AFTER_RENAME) == -1)
		return (-1);
	return (result);
}

static void
publication_boundaries(bool updating, bool fail_io)
{
	unsigned last = updating ? AFTER_DIR_SYNC : AFTER_MARKER_SYNC;

	for (unsigned point = BEFORE_FILE_SYNC; point <= last; point++) {
		struct sl_db db;
		struct sl_installation result;
		char directory[64];
		pid_t child;
		int status;

		snprintf(directory, sizeof(directory), "state-%u", point);
		ATF_REQUIRE_EQ(0, mkdir(directory, 0700));
		if (updating) {
			ATF_REQUIRE_EQ(0, sl_open(directory, &db));
			ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, "pkg.test", first));
			ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, first, false));
			ATF_REQUIRE_EQ(0, sl_commit(&db));
			sl_close(&db);
		}
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			if (sl_open(directory, &db) == -1)
				_exit(101);
			if ((updating ? sl_remove_begin(&db, label, "pkg.test", second) :
			    sl_install_begin(&db, label, "pkg.test", first)) == -1)
				_exit(102);
			fault = point;
			io_failure = fail_io;
			sync_count = 0;
			int rc = sl_commit(&db), error = errno;
			sl_close(&db);
			_exit(fail_io && rc == -1 && error == EIO ? 0 : 103);
		}
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		if (fail_io)
			ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			    "I/O boundary %u status %#x", point, status);
		else
			ATF_REQUIRE_MSG(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
			    "crash boundary %u status %#x", point, status);
		/* Reopening also proves the dead process did not leave its lock held. */
		ATF_REQUIRE_EQ(0, sl_open(directory, &db));
		ATF_REQUIRE_EQ(0, sl_query(&db, label, NULL, &result));
		if (point < AFTER_RENAME) {
			ATF_CHECK_EQ(updating ? SL_INSTALLED : SL_UNKNOWN, result.state);
			ATF_CHECK(sl_operation(&db, label, updating ? second : first) == NULL);
		} else {
			ATF_CHECK_EQ(updating ? SL_REMOVE_IN_PROGRESS : SL_INSTALL_IN_PROGRESS,
			    result.state);
			ATF_REQUIRE(sl_operation(&db, label, updating ? second : first) != NULL);
		}
		/* Exact retry is valid both before and after publication became visible. */
		if (updating) {
			ATF_REQUIRE_EQ(0, sl_remove_begin(&db, label, "pkg.test", second));
			ATF_REQUIRE_EQ(0, sl_remove_finish(&db, label, second, false));
		} else {
			ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, "pkg.test", first));
			ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, first, false));
		}
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_REQUIRE_EQ(0, sl_open_readonly(directory, &db));
		ATF_REQUIRE_EQ(0, sl_query(&db, label, NULL, &result));
		ATF_CHECK_EQ(updating ? SL_REMOVED : SL_INSTALLED, result.state);
		sl_close(&db);
	}
}

ATF_TC_WITHOUT_HEAD(first_publication_process_death);
ATF_TC_BODY(first_publication_process_death, tc) { publication_boundaries(false, false); }
ATF_TC_WITHOUT_HEAD(update_publication_process_death);
ATF_TC_BODY(update_publication_process_death, tc) { publication_boundaries(true, false); }
ATF_TC_WITHOUT_HEAD(first_publication_io_failures);
ATF_TC_BODY(first_publication_io_failures, tc) { publication_boundaries(false, true); }
ATF_TC_WITHOUT_HEAD(update_publication_io_failures);
ATF_TC_BODY(update_publication_io_failures, tc) { publication_boundaries(true, true); }

/* Expiry and the rejection fence must become visible in the same image. */
ATF_TC_WITHOUT_HEAD(prune_publication_process_death);
ATF_TC_BODY(prune_publication_process_death, tc)
{
	for (unsigned point = BEFORE_FILE_SYNC; point <= AFTER_DIR_SYNC; point++) {
		struct sl_db db;
		struct sl_installation result;
		char directory[64], install[33], remove[33], replacement[33];
		uint8_t generation[SL_GENERATION_SIZE];
		int status;
		pid_t child;

		snprintf(directory, sizeof(directory), "prune-%u", point);
		ATF_REQUIRE_EQ(0, mkdir(directory, 0700));
		ATF_REQUIRE_EQ(0, sl_open(directory, &db));
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, install));
		ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, "pkg.test", install));
		ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, install, false));
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, remove));
		ATF_REQUIRE_EQ(0, sl_remove_begin(&db, label, "pkg.test", remove));
		ATF_REQUIRE_EQ(0, sl_remove_finish(&db, label, remove, false));
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, replacement));
		ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, "pkg.test", replacement));
		ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, replacement, false));
		ATF_REQUIRE_EQ(0, sl_query(&db, label, NULL, &result));
		memcpy(generation, result.generation, sizeof(generation));
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			if (sl_open(directory, &db) == -1 ||
			    sl_prune_history(&db, 1, NULL) == -1)
				_exit(101);
			fault = point;
			sync_count = 0;
			(void)sl_commit(&db);
			_exit(102);
		}
		ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
		ATF_REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
		ATF_REQUIRE_EQ(0, sl_open(directory, &db));
		if (point < AFTER_RENAME) {
			ATF_REQUIRE(sl_operation(&db, label, remove) != NULL);
			ATF_REQUIRE_EQ(0, sl_remove_begin(&db, label, "pkg.test", remove));
		} else {
			ATF_REQUIRE(sl_operation(&db, label, remove) == NULL);
			ATF_REQUIRE_EQ(-1, sl_remove_begin(&db, label, "pkg.test", remove));
			ATF_REQUIRE_EQ(ESTALE, errno);
		}
		ATF_REQUIRE_EQ(0, sl_query(&db, label, generation, &result));
		ATF_CHECK_EQ(SL_INSTALLED, result.state);
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, prune_publication_process_death);
	ATF_TP_ADD_TC(tp, first_publication_process_death);
	ATF_TP_ADD_TC(tp, update_publication_process_death);
	ATF_TP_ADD_TC(tp, first_publication_io_failures);
	ATF_TP_ADD_TC(tp, update_publication_io_failures);
	return (atf_no_error());
}
