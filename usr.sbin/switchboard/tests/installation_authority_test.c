/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "switchboard_lifecycle.h"
#include "switchboard_reclamation.h"

static const char owner[] = "org.test.app/worker";

static void setup(struct sl_db *db)
{
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, sl_open("state", db));
}

static const char op1[] = "11111111111111111111111111111111";
static const char op2[] = "22222222222222222222222222222222";
static const char op3[] = "33333333333333333333333333333333";

ATF_TC_WITHOUT_HEAD(installation_authority_query);
ATF_TC_BODY(installation_authority_query, tc)
{
	struct sl_db db;
	struct sl_installation result;
	uint8_t old[16], fresh[16];
	size_t count;

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_CHECK_EQ(0, db.count);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", op1));
	ATF_REQUIRE_EQ(0, sl_record_source(&db, owner, op1, "pkg:example/app"));
	ATF_CHECK_ERRNO(EINVAL, sl_record_source(&db, owner, op1, "pkg:other/app") == -1);
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
	ATF_CHECK_EQ(SL_INSTALL_IN_PROGRESS, result.state);
	ATF_CHECK_EQ(1, result.staged_sources);
	memcpy(old, result.generation, sizeof(old));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op1, false));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, old, &result));
	ATF_CHECK_EQ(SL_INSTALLED, result.state);
	ATF_CHECK_EQ(1, result.live_sources);
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.slot", op2));
	ATF_REQUIRE_EQ(0, sl_record_source(&db, owner, op2, "pkg:example/app"));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, old, &result));
	ATF_CHECK_EQ(SL_REMOVE_IN_PROGRESS, result.state);
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, op2, false));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", op3));
	ATF_REQUIRE_EQ(0, sl_record_source(&db, owner, op3, "pkg:example/app"));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op3, false));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
	memcpy(fresh, result.generation, sizeof(fresh));
	ATF_CHECK(memcmp(old, fresh, sizeof(old)) != 0);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	count = db.count;
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, old, &result));
	ATF_CHECK_EQ(SL_REMOVED, result.state);
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, fresh, &result));
	ATF_CHECK_EQ(SL_INSTALLED, result.state);
	ATF_REQUIRE_EQ(0, sl_query(&db, "org.unknown/app", old, &result));
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_CHECK_EQ(count, db.count);
	ATF_CHECK(!db.dirty);
	ATF_CHECK_STREQ("pkg:example/app", sl_operation(&db, owner, op1)->source);
	ATF_CHECK_STREQ("pkg:example/app", sl_operation(&db, owner, op2)->source);
	ATF_CHECK_ERRNO(EROFS, sl_commit(&db) == -1);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, unlink("state/state"));
	ATF_CHECK_ERRNO(EIO, sl_open_readonly("state", &db) == -1);
	ATF_REQUIRE_EQ(0, mkdir("empty", 0700));
	ATF_CHECK_EQ(-1, sl_open_readonly("empty", &db));
	ATF_CHECK_ERRNO(ENOENT, access("empty/lock", F_OK) == -1);
}

ATF_TC_WITHOUT_HEAD(query_does_not_wait_for_writer);
ATF_TC_BODY(query_does_not_wait_for_writer, tc)
{
	struct sl_db writer, reader;
	uint8_t generation[16];

	setup(&writer);
	ATF_REQUIRE_EQ(0, sl_install(&writer, owner, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&writer));
	/* Separate open descriptions contend even inside one process. */
	ATF_CHECK_ERRNO(EWOULDBLOCK, sl_open_readonly("state", &reader) == -1);
	sl_close(&writer);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &reader));
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &writer));
	sl_close(&reader);
	sl_close(&writer);
}

static void
wait_success(pid_t child)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "writer status %#x", status);
}

ATF_TC(concurrent_writers_preserve_all_sources);
ATF_TC_HEAD(concurrent_writers_preserve_all_sources, tc)
{
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(concurrent_writers_preserve_all_sources, tc)
{
	struct sl_db db;
	struct sl_installation result;
	pid_t children[8];
	int gate[2];

	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, pipe(gate));
	for (unsigned i = 0; i < 8; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0) {
			char token[33], source[32], byte;
			close(gate[1]);
			if (read(gate[0], &byte, 1) != 0)
				_exit(1);
			close(gate[0]);
			snprintf(token, sizeof(token), "%032x", i + 1);
			snprintf(source, sizeof(source), "source.%u", i);
			if (sl_open("state", &db) == -1 ||
			    sl_install_begin(&db, owner, source, token) == -1 ||
			    sl_record_source(&db, owner, token, source) == -1 ||
			    sl_install_finish(&db, owner, token, false) == -1 ||
			    sl_commit(&db) == -1)
				_exit(2);
			sl_close(&db);
			_exit(0);
		}
	}
	close(gate[0]);
	close(gate[1]); /* Release every writer at once. */
	for (unsigned i = 0; i < 8; i++)
		wait_success(children[i]);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
	ATF_CHECK_EQ(SL_INSTALLED, result.state);
	ATF_CHECK_EQ(8, result.live_sources);
	ATF_CHECK_EQ(17, db.count); /* One owner, eight references, eight operations. */
	for (unsigned i = 0; i < 8; i++) {
		char token[33], source[32];
		snprintf(token, sizeof(token), "%032x", i + 1);
		snprintf(source, sizeof(source), "source.%u", i);
		struct sl_record *op = sl_operation(&db, owner, token);
		ATF_REQUIRE(op != NULL);
		ATF_CHECK_EQ(SL_INSTALL_COMMITTED, op->phase);
		ATF_CHECK_STREQ(source, op->source);
		ATF_CHECK_EQ(0, memcmp(result.generation, op->generation, 16));
	}
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(dead_writer_preserves_pending_barrier);
ATF_TC_BODY(dead_writer_preserves_pending_barrier, tc)
{
	struct sl_db db;
	struct sl_installation result;
	int ready[2], status;
	char byte;
	pid_t child;

	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, pipe(ready));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(ready[0]);
		if (sl_open("state", &db) == -1 ||
		    sl_install_begin(&db, owner, "pkg.first", op1) == -1 ||
		    sl_commit(&db) == -1)
			_exit(1);
		if (write(ready[1], "x", 1) != 1)
			_exit(2);
		for (;;)
			pause();
	}
	close(ready[1]);
	ATF_REQUIRE_EQ(1, read(ready[0], &byte, 1));
	close(ready[0]);
	ATF_CHECK_ERRNO(EWOULDBLOCK, sl_open_readonly("state", &db) == -1);
	ATF_REQUIRE_EQ(0, kill(child, SIGKILL));
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_ERRNO(EBUSY, sl_install_begin(&db, owner, "pkg.second", op2) == -1);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, op1, false));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
	ATF_CHECK_EQ(SL_INSTALLED, result.state);
	ATF_CHECK_EQ(1, result.live_sources);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(source_state_model);
ATF_TC_BODY(source_state_model, tc)
{
	struct sl_db db;
	struct sl_installation result;
	bool live[5] = {false};
	uint32_t seed = 0x519cbdU;
	uint8_t previous[16] = {0};
	unsigned total = 0;

	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	for (unsigned step = 1; step <= 160; step++) {
		char operation[33], reference[32];
		seed = seed * 1664525U + 1013904223U;
		unsigned source = (seed >> 16) % 5;
		bool installing = !live[source] || (seed & 4) != 0;
		bool cancel = (seed & 0x18) == 0;
		unsigned before = total;
		snprintf(operation, sizeof(operation), "%032x", step);
		snprintf(reference, sizeof(reference), "bundle.version.%u", source);
		ATF_REQUIRE_EQ(0, sl_open("state", &db));
		ATF_REQUIRE_EQ(0, installing ?
		    sl_install_begin(&db, owner, reference, operation) :
		    sl_remove_begin(&db, owner, reference, operation));
		ATF_REQUIRE_EQ(0, sl_record_source(&db, owner, operation, reference));
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_REQUIRE_EQ(0, sl_open("state", &db));
		ATF_REQUIRE_EQ(0, sl_query(&db, owner, NULL, &result));
		ATF_CHECK_EQ(installing ? SL_INSTALL_IN_PROGRESS : SL_REMOVE_IN_PROGRESS, result.state);
		ATF_CHECK_EQ(installing ? 1 : 0, result.staged_sources);
		ATF_CHECK_EQ(total - (installing && live[source] ? 1 : 0), result.live_sources);
		if (before != 0)
			ATF_CHECK_EQ(0, memcmp(previous, result.generation, 16));
		else
			ATF_CHECK(memcmp(previous, result.generation, 16) != 0);
		memcpy(previous, result.generation, 16);
		ATF_REQUIRE_EQ(0, installing ?
		    sl_install_finish(&db, owner, operation, cancel) :
		    sl_remove_finish(&db, owner, operation, cancel));
		if (!cancel) {
			live[source] = installing;
			total = 0;
			for (unsigned i = 0; i < 5; i++)
				total += live[i];
		}
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
		ATF_REQUIRE_EQ(0, sl_query(&db, owner, previous, &result));
		ATF_CHECK_EQ(total != 0 ? SL_INSTALLED : SL_REMOVED, result.state);
		ATF_CHECK_EQ(total, result.live_sources);
		ATF_CHECK_EQ(0, result.staged_sources);
		ATF_CHECK_EQ((installing ? SL_INSTALL_PENDING : SL_REMOVE_PENDING) +
		    (cancel ? 2 : 1), sl_operation(&db, owner, operation)->phase);
		sl_close(&db);
	}
}

ATF_TC_WITHOUT_HEAD(malformed_strings_are_rejected);
ATF_TC_BODY(malformed_strings_are_rejected, tc)
{
	struct sl_db db;
	uint8_t generation[16];

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, generation));
	/* A valid checksum must not bypass record validation. */
	memset(db.records[0].reference, 'x', sizeof(db.records[0].reference));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_CHECK_ERRNO(EINVAL, sl_open_readonly("state", &db) == -1);
	if (db.dirfd >= 0)
		sl_close(&db);
}

static void
install_issued(struct sl_db *db, const char *label, char operation[33])
{
	ATF_REQUIRE_EQ(0, sl_issue_operation(db, operation));
	ATF_REQUIRE_EQ(0, sl_install_begin(db, label, "pkg.slot", operation));
	ATF_REQUIRE_EQ(0, sl_record_source(db, label, operation, "pkg:example/app"));
	ATF_REQUIRE_EQ(0, sl_install_finish(db, label, operation, false));
}

ATF_TC_WITHOUT_HEAD(expired_history_cannot_target_replacement);
ATF_TC_BODY(expired_history_cannot_target_replacement, tc)
{
	struct sl_db db;
	struct sl_installation state;
	char install[33], remove[33], fresh[33], next[33];
	uint8_t old[16], replacement[16];
	size_t discarded;

	setup(&db);
	install_issued(&db, owner, install);
	memcpy(old, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, remove));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.slot", remove));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, remove, false));
	install_issued(&db, owner, fresh);
	memcpy(replacement, sl_owner(&db, owner)->generation, 16);
	ATF_REQUIRE(memcmp(old, replacement, 16) != 0);
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, &discarded));
	ATF_CHECK(discarded > 0);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, old, &state));
	/* Transaction history expires, but undispatched cleanup still needs
	 * the old installation identity even when no holdings were recorded. */
	ATF_CHECK_EQ(SL_REMOVED, state.state);
	ATF_CHECK(sl_operation(&db, owner, remove) == NULL);
	ATF_CHECK_ERRNO(ESTALE, sl_remove_begin(&db, owner, "pkg.slot", remove) == -1);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_ERRNO(ESTALE, sl_install_begin(&db, owner, "pkg.slot", install) == -1);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, replacement, &state));
	ATF_CHECK_EQ(SL_INSTALLED, state.state);
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, fresh, false));
	ATF_CHECK_STREQ("pkg:example/app", sl_operation(&db, owner, fresh)->source);
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, next));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, owner, "pkg.slot", next));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, owner, next, false));
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, NULL));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	/* Last-known state remains, so runtime discovery cannot silently resurrect it. */
	ATF_CHECK_ERRNO(ESTALE, sl_adopt(&db, owner, old) == -1);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(pending_transaction_retains_all_labels);
ATF_TC_BODY(pending_transaction_retains_all_labels, tc)
{
	struct sl_db db;
	struct sl_installation state;
	char grouped[33], newer[33];
	const char *other = "org.test.other/main";

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, grouped));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", grouped));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, other, "pkg.slot", grouped));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, grouped, false));
	install_issued(&db, "org.test.newest/main", newer);
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, NULL));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE(sl_operation(&db, owner, grouped) != NULL);
	ATF_REQUIRE(sl_operation(&db, other, grouped) != NULL);
	ATF_CHECK_EQ(SL_INSTALL_COMMITTED, sl_operation(&db, owner, grouped)->phase);
	ATF_CHECK_EQ(SL_INSTALL_PENDING, sl_operation(&db, other, grouped)->phase);
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", grouped));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, other, grouped, false));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, other, NULL, &state));
	ATF_CHECK_EQ(SL_INSTALLED, state.state);
	ATF_CHECK_ERRNO(EROFS, sl_prune_history(&db, 1, NULL) == -1);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(automatic_history_is_bounded);
ATF_TC_BODY(automatic_history_is_bounded, tc)
{
	struct sl_db db;
	struct sl_installation state;
	char operation[33], first[33];
	uint8_t generation[16];

	setup(&db);
	for (unsigned i = 0; i < SL_HISTORY_KEEP + 32; i++) {
		install_issued(&db, owner, operation);
		if (i == 0) {
			strlcpy(first, operation, sizeof(first));
			memcpy(generation, sl_owner(&db, owner)->generation, 16);
		}
		ATF_REQUIRE_EQ(0, sl_commit(&db));
		sl_close(&db);
		ATF_REQUIRE_EQ(0, sl_open("state", &db));
	}
	ATF_CHECK(db.count <= 2 * SL_HISTORY_KEEP + 3);
	ATF_CHECK(sl_operation(&db, owner, first) == NULL);
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, generation, &state));
	ATF_CHECK_EQ(SL_INSTALLED, state.state);
	ATF_CHECK_EQ(1, state.live_sources);
	ATF_CHECK_ERRNO(ESTALE, sl_install_begin(&db, owner, "pkg.slot", first) == -1);
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(version_three_preserves_state_on_upgrade);
ATF_TC_BODY(version_three_preserves_state_on_upgrade, tc)
{
	struct sl_db db;
	struct sl_installation state;
	uint8_t generation[16];
	uint32_t version = 3;
	int fd;

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, generation));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	/* v3 and v4 have identical record layout; v4 adds retention record kinds. */
	fd = open("state/state", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(version), pwrite(fd, &version, sizeof(version), 8));
	close(fd);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, NULL));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, generation, &state));
	ATF_CHECK_EQ(SL_INSTALLED, state.state);
	sl_close(&db);
	fd = open("state/state", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(version), pread(fd, &version, sizeof(version), 8));
	ATF_CHECK_EQ(4, version);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(unsupported_formats_preserve_store);
ATF_TC_BODY(unsupported_formats_preserve_store, tc)
{
	struct sl_db db;
	uint8_t identity[16];
	const uint32_t versions[] = { 0, 1, 2, 5 };
	unsigned char before[4096], after[4096];
	ssize_t length;
	int fd;

	setup(&db);
	ATF_REQUIRE_EQ(0, sl_install(&db, owner, identity));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	fd = open("state/state", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		ATF_REQUIRE_EQ(sizeof(versions[i]), pwrite(fd, &versions[i], sizeof(versions[i]), 8));
		length = pread(fd, before, sizeof(before), 0);
		ATF_REQUIRE(length > 0 && (size_t)length < sizeof(before));
		ATF_CHECK_ERRNO(EINVAL, sl_open_readonly("state", &db) == -1);
		ATF_CHECK_ERRNO(EINVAL, sl_open("state", &db) == -1);
		ATF_REQUIRE_EQ(length, pread(fd, after, sizeof(after), 0));
		ATF_CHECK_EQ(0, memcmp(before, after, length));
		ATF_CHECK_EQ(0, access("state/initialized", F_OK));
	}
	close(fd);
}

ATF_TC(capacity_recovery_preserves_state);
ATF_TC_HEAD(capacity_recovery_preserves_state, tc)
{
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(capacity_recovery_preserves_state, tc)
{
	struct sl_db db;
	struct sl_installation result;
	char operation[33];
	uint8_t newest[16];
	size_t removed;

	setup(&db);
	/* Construct the supported maximum of completed cleanup history without
	 * quadratic fixture insertion. Pending cleanup is never capacity relief. */
	db.records = calloc(SL_MAX_RECORDS, sizeof(*db.records));
	ATF_REQUIRE(db.records != NULL);
	db.count = SL_MAX_RECORDS;
	db.dirty = true;
	for (size_t i = 0; i < db.count; i++) {
		struct sl_record *r = &db.records[i];
		r->kind = SL_OWNER;
		r->phase = SL_COMPLETE;
		strlcpy(r->reference, SL_CLEANUP_COMPLETE, sizeof(r->reference));
		strlcpy(r->label, owner, sizeof(r->label));
		r->generation[0] = 1;
		memcpy(r->generation + 8, &i, sizeof(i));
		sl_generation_format(r->generation, operation);
		snprintf(r->provider, sizeof(r->provider), "install.%s", operation);
	}
	memcpy(newest, db.records[db.count - 1].generation, sizeof(newest));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_CHECK_ERRNO(ENOSPC, sl_issue_operation(&db, operation) == -1);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_prune_history(&db, 1, &removed));
	ATF_CHECK_EQ(SL_MAX_RECORDS - 1, removed);
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_CHECK_EQ(2, db.count);
	ATF_REQUIRE_EQ(0, sl_query(&db, owner, newest, &result));
	ATF_CHECK_EQ(SL_REMOVED, result.state);
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, operation));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, owner, "pkg.slot", operation));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, owner, operation, false));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unsupported_formats_preserve_store);
	ATF_TP_ADD_TC(tp, capacity_recovery_preserves_state);
	ATF_TP_ADD_TC(tp, expired_history_cannot_target_replacement);
	ATF_TP_ADD_TC(tp, pending_transaction_retains_all_labels);
	ATF_TP_ADD_TC(tp, automatic_history_is_bounded);
	ATF_TP_ADD_TC(tp, version_three_preserves_state_on_upgrade);
	ATF_TP_ADD_TC(tp, concurrent_writers_preserve_all_sources);
	ATF_TP_ADD_TC(tp, dead_writer_preserves_pending_barrier);
	ATF_TP_ADD_TC(tp, source_state_model);
	ATF_TP_ADD_TC(tp, malformed_strings_are_rejected);
	ATF_TP_ADD_TC(tp, query_does_not_wait_for_writer);
	ATF_TP_ADD_TC(tp, installation_authority_query);
	return (atf_no_error());
}
