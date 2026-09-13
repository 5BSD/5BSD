/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "switchboard_lifecycle.h"

static const char label[] = "org.test.cache/app";
static size_t bytes_read;
static bool coarse_times, edit_during_read, continual_edit;
static struct stat original_stat;

ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int, void *, size_t);
int __real_fstat(int, struct stat *);
int __wrap_fstat(int, struct stat *);

ssize_t
__wrap_read(int fd, void *buf, size_t size)
{
	ssize_t n = __real_read(fd, buf, size);
	if (n > 0)
		bytes_read += n;
	if (edit_during_read && n >= (ssize_t)sizeof(struct sl_record)) {
		uint8_t byte = ((uint8_t *)buf)[n - 1], changed = byte ^ 1;
		int writer = open("state/state", O_WRONLY);
		ATF_REQUIRE(writer >= 0);
		ATF_REQUIRE_EQ(1, pwrite(writer, &changed, 1, original_stat.st_size - 1));
		ATF_REQUIRE_EQ(1, pwrite(writer, &byte, 1, original_stat.st_size - 1));
		ATF_REQUIRE_EQ(0, close(writer));
		edit_during_read = continual_edit;
	}
	return (n);
}

/* Emulate unchanged timestamps so NOTE_WRITE must detect the corruption. */
int
__wrap_fstat(int fd, struct stat *st)
{
	int result = __real_fstat(fd, st);
	if (result == 0 && coarse_times && st->st_dev == original_stat.st_dev &&
	    st->st_ino == original_stat.st_ino) {
		st->st_mtim = original_stat.st_mtim;
		st->st_ctim = original_stat.st_ctim;
	}
	return (result);
}

static struct sl_query_cache *
setup(uint8_t id[16])
{
	struct sl_db db;
	struct sl_query_cache *cache;

	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install(&db, label, id));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE((cache = sl_query_cache_create()) != NULL);
	return (cache);
}

static void
check(struct sl_query_cache *cache, const uint8_t *id, enum sl_installation_state state)
{
	struct sl_installation result, fresh;
	struct sl_db db;

	ATF_REQUIRE_EQ(0, sl_query_cached(cache, "state", label, id, &result));
	ATF_CHECK_EQ(state, result.state);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	ATF_REQUIRE_EQ(0, sl_query(&db, label, id, &fresh));
	ATF_CHECK_EQ(0, memcmp(&fresh, &result, sizeof(fresh)));
	sl_close(&db);
}

ATF_TC_WITHOUT_HEAD(reuses_validated_snapshot);
ATF_TC_BODY(reuses_validated_snapshot, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	struct sl_db writer;
	uint8_t id[16];
	size_t cold;

	cache = setup(id);
	bytes_read = 0;
	ATF_REQUIRE_EQ(0, sl_query_cached(cache, "state", label, id, &result));
	cold = bytes_read;
	ATF_REQUIRE(cold > sizeof(struct sl_record));
	for (int i = 0; i < 100; i++) {
		bytes_read = 0;
		ATF_REQUIRE_EQ(0, sl_query_cached(cache, "state", label, id, &result));
		ATF_CHECK_EQ(SL_INSTALLED, result.state);
		ATF_CHECK_EQ(cold - sizeof(struct sl_record), bytes_read);
	}
	/* A retained snapshot must not retain its shared transaction lock. */
	ATF_REQUIRE_EQ(0, sl_open("state", &writer));
	memset(&result, 0xff, sizeof(result));
	ATF_CHECK_ERRNO(EWOULDBLOCK,
	    sl_query_cached(cache, "state", label, id, &result) == -1);
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	sl_close(&writer);
	check(cache, id, SL_INSTALLED);
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(publish_and_restore);
ATF_TC_BODY(publish_and_restore, tc)
{
	struct sl_query_cache *cache;
	struct sl_db db;
	uint8_t old[16], fresh[16], prepared[16];

	cache = setup(old);
	check(cache, old, SL_INSTALLED);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	/* Preserve the actual old inode, as well as its contents. */
	ATF_REQUIRE_EQ(0, rename("state/state", "saved"));
	ATF_REQUIRE_EQ(0, sl_prepare(&db, label, prepared));
	ATF_REQUIRE_EQ(0, sl_retire(&db, label, old));
	ATF_REQUIRE_EQ(0, sl_install(&db, label, fresh));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE(memcmp(old, fresh, sizeof(old)) != 0);
	check(cache, old, SL_REMOVED);
	check(cache, fresh, SL_INSTALLED);
	ATF_REQUIRE_EQ(0, rename("saved", "state/state"));
	check(cache, old, SL_INSTALLED);
	check(cache, fresh, SL_UNKNOWN);
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(corruption_with_unchanged_timestamps);
ATF_TC_BODY(corruption_with_unchanged_timestamps, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	uint8_t id[16], byte, damaged;
	int fd;

	cache = setup(id);
	ATF_REQUIRE_EQ(0, stat("state/state", &original_stat));
	check(cache, id, SL_INSTALLED);
	ATF_REQUIRE((fd = open("state/state", O_RDWR)) >= 0);
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, original_stat.st_size - 1));
	damaged = byte ^ 1;
	coarse_times = true;
	ATF_REQUIRE_EQ(1, pwrite(fd, &damaged, 1, original_stat.st_size - 1));
	ATF_CHECK_ERRNO(EILSEQ,
	    sl_query_cached(cache, "state", label, id, &result) == -1);
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, original_stat.st_size - 1));
	ATF_REQUIRE_EQ(0, close(fd));
	check(cache, id, SL_INSTALLED);
	coarse_times = false;
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(trust_and_missing_state);
ATF_TC_BODY(trust_and_missing_state, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	uint8_t id[16];
	const char *paths[] = { "state", "state/lock", "state/state" };

	cache = setup(id);
	for (size_t i = 0; i < nitems(paths); i++) {
		check(cache, id, SL_INSTALLED);
		ATF_REQUIRE_EQ(0, chmod(paths[i], 0777));
		ATF_CHECK_EQ(-1, sl_query_cached(cache, "state", label, id, &result));
		ATF_CHECK_EQ(SL_UNKNOWN, result.state);
		ATF_REQUIRE_EQ(0, chmod(paths[i], i == 0 ? 0700 : 0600));
	}
	check(cache, id, SL_INSTALLED);
	ATF_REQUIRE_EQ(0, rename("state/state", "saved"));
	ATF_CHECK_ERRNO(EIO,
	    sl_query_cached(cache, "state", label, id, &result) == -1);
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_REQUIRE_EQ(0, symlink("../saved", "state/state"));
	ATF_CHECK_EQ(-1, sl_query_cached(cache, "state", label, id, &result));
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_REQUIRE_EQ(0, unlink("state/state"));
	ATF_REQUIRE_EQ(0, rename("saved", "state/state"));
	check(cache, id, SL_INSTALLED);
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(pending_and_cancelled_transactions);
ATF_TC_BODY(pending_and_cancelled_transactions, tc)
{
	struct sl_query_cache *cache;
	struct sl_db db;
	uint8_t id[16];
	const char *op = "11111111111111111111111111111111";

	cache = setup(id);
	check(cache, id, SL_INSTALLED);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, "pkg.slot", op));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	check(cache, id, SL_INSTALL_IN_PROGRESS);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, op, true));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	check(cache, id, SL_INSTALLED);
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(edit_during_validation);
ATF_TC_BODY(edit_during_validation, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	uint8_t id[16];

	cache = setup(id);
	ATF_REQUIRE_EQ(0, stat("state/state", &original_stat));
	coarse_times = edit_during_read = true;
	bytes_read = 0;
	ATF_REQUIRE_EQ(0, sl_query_cached(cache, "state", label, id, &result));
	ATF_CHECK_EQ(SL_INSTALLED, result.state);
	ATF_CHECK(bytes_read >= 2 * (size_t)original_stat.st_size);
	ATF_CHECK(!edit_during_read);
	check(cache, id, SL_INSTALLED);
	sl_query_cache_destroy(cache);
}

ATF_TC_WITHOUT_HEAD(continuous_changes_are_bounded);
ATF_TC_BODY(continuous_changes_are_bounded, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	uint8_t id[16];

	cache = setup(id);
	ATF_REQUIRE_EQ(0, stat("state/state", &original_stat));
	coarse_times = edit_during_read = continual_edit = true;
	bytes_read = 0;
	ATF_CHECK_ERRNO(EAGAIN,
	    sl_query_cached(cache, "state", label, id, &result) == -1);
	ATF_CHECK_EQ(SL_UNKNOWN, result.state);
	ATF_CHECK_EQ(3 * (size_t)original_stat.st_size, bytes_read);
	edit_during_read = continual_edit = false;
	check(cache, id, SL_INSTALLED);
	sl_query_cache_destroy(cache);
}

static unsigned
open_fds(void)
{
	unsigned count = 0;

	for (int fd = 0; fd < 256; fd++)
		count += fcntl(fd, F_GETFD) != -1;
	return (count);
}

ATF_TC_WITHOUT_HEAD(path_changes_and_descriptor_lifetime);
ATF_TC_BODY(path_changes_and_descriptor_lifetime, tc)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	struct sl_db db;
	uint8_t old[16], fresh[16];
	unsigned before = open_fds();

	cache = setup(old);
	check(cache, old, SL_INSTALLED);
	ATF_REQUIRE_EQ(0, mkdir("other", 0700));
	ATF_REQUIRE_EQ(0, sl_open("other", &db));
	ATF_REQUIRE_EQ(0, sl_install(&db, label, fresh));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	for (int i = 0; i < 100; i++) {
		ATF_REQUIRE_MSG(sl_query_cached(cache, "other", label, old, &result) == 0,
		    "switch store iteration %d: %s", i, strerror(errno));
		ATF_CHECK_EQ(SL_UNKNOWN, result.state);
		ATF_REQUIRE_EQ(0, sl_query_cached(cache, "other", label, fresh, &result));
		ATF_CHECK_EQ(SL_INSTALLED, result.state);
		check(cache, old, SL_INSTALLED);
		ATF_CHECK_EQ(before + 2, open_fds()); /* queue and current state */
	}
	sl_query_cache_destroy(cache);
	ATF_CHECK_EQ(before, open_fds());
}

ATF_TC_WITHOUT_HEAD(index_matches_ledger);
ATF_TC_BODY(index_matches_ledger, tc)
{
	struct sl_query_cache *cache;
	struct sl_db db;
	struct sl_record owner, *r;
	struct sl_installation expected, actual;
	uint8_t id[16], other[16];
	const char *labels[] = { "aaa", label, "zzz", "absent" };

	cache = setup(id);
	memcpy(other, id, sizeof(other));
	other[0] ^= 1;
	other[1] = 1;
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	owner = db.records[0];
	free(db.records);
	db.count = 12;
	ATF_REQUIRE((db.records = calloc(db.count, sizeof(*db.records))) != NULL);
	for (size_t i = 0; i < db.count; i++) {
		r = &db.records[i];
		*r = owner;
		strlcpy(r->label, labels[i % 3], sizeof(r->label));
		if (i >= 3 && i < 6)
			memcpy(r->generation, other, sizeof(other));
		if (i >= 6 && i < 9) {
			r->kind = SL_REFERENCE;
			r->phase = i == 7 ? SL_REF_STAGED : SL_REF_LIVE;
			strlcpy(r->reference, "source", sizeof(r->reference));
		}
		if (i >= 9)
			r->phase = SL_RETIRED; /* Duplicate ID, later owner phase. */
	}
	db.dirty = true;
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_open_readonly("state", &db));
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 3; j++) {
			const uint8_t *generation = j == 0 ? NULL : j == 1 ? id : other;
			ATF_REQUIRE_EQ(0, sl_query(&db, labels[i], generation, &expected));
			ATF_REQUIRE_EQ(0, sl_query_cached(cache, "state", labels[i],
			    generation, &actual));
			ATF_CHECK_EQ(0, memcmp(&expected, &actual, sizeof(actual)));
		}
	}
	ATF_CHECK_ERRNO(EROFS, sl_install(&db, "new", other) == -1);
	sl_close(&db);
	sl_query_cache_destroy(cache);
}

static void
count_retired(const char *name, const uint8_t *id, void *context)
{
	ATF_CHECK_EQ(0, strcmp(name, label));
	ATF_CHECK(sl_generation_valid(id));
	(*(unsigned *)context)++;
}

ATF_TC_WITHOUT_HEAD(retired_visit_excludes_partial_removal);
ATF_TC_BODY(retired_visit_excludes_partial_removal, tc)
{
	struct sl_query_cache *cache;
	struct sl_db db;
	uint8_t id[16];
	char op[33];
	unsigned retired = 0;

	cache = setup(id);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	for (unsigned i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, sl_issue_operation(&db, op));
		ATF_REQUIRE_EQ(0, sl_install_begin(&db, label, i ? "two" : "one", op));
		ATF_REQUIRE_EQ(0, sl_install_finish(&db, label, op, false));
	}
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, op));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, label, "one", op));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_query_cached_retired(cache, "state", count_retired, &retired));
	ATF_CHECK_EQ(0, retired);
	check(cache, id, SL_REMOVE_IN_PROGRESS);
	ATF_REQUIRE_EQ(0, sl_open("state", &db));
	ATF_REQUIRE_EQ(0, sl_remove_finish(&db, label, op, false));
	ATF_REQUIRE_EQ(0, sl_issue_operation(&db, op));
	ATF_REQUIRE_EQ(0, sl_remove_begin(&db, label, "two", op));
	ATF_REQUIRE_EQ(0, sl_commit(&db));
	sl_close(&db);
	ATF_REQUIRE_EQ(0, sl_query_cached_retired(cache, "state", count_retired, &retired));
	ATF_CHECK_EQ(1, retired);
	sl_query_cache_destroy(cache);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, retired_visit_excludes_partial_removal);
	ATF_TP_ADD_TC(tp, index_matches_ledger);
	ATF_TP_ADD_TC(tp, continuous_changes_are_bounded);
	ATF_TP_ADD_TC(tp, edit_during_validation);
	ATF_TP_ADD_TC(tp, path_changes_and_descriptor_lifetime);
	ATF_TP_ADD_TC(tp, reuses_validated_snapshot);
	ATF_TP_ADD_TC(tp, publish_and_restore);
	ATF_TP_ADD_TC(tp, corruption_with_unchanged_timestamps);
	ATF_TP_ADD_TC(tp, trust_and_missing_state);
	ATF_TP_ADD_TC(tp, pending_and_cancelled_transactions);
	return (atf_no_error());
}
