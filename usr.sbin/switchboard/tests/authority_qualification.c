/* SPDX-License-Identifier: BSD-2-Clause */
/* Operator-invoked qualification helper; does not run on the host implicitly. */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <bsm/libbsm.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "switchboard_lifecycle.h"

static long
resident_kib(void)
{
	struct kinfo_proc process;
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
	size_t length = sizeof(process);

	if (sysctl(mib, 4, &process, &length, NULL, 0) == -1)
		err(1, "sample resident memory");
	return (process.ki_rssize * getpagesize() / 1024);
}

static double
now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (t.tv_sec + t.tv_nsec / 1e9);
}

static void
commit_close(struct sl_db *db)
{
	if (sl_commit(db) == -1)
		err(1, "commit churn");
	sl_close(db);
}

/* Durable begin/finish boundaries let concurrent readers observe pending work. */
static int
churn(const char *path, const char *count_text)
{
	struct sl_db db;
	struct sl_installation current;
	uint8_t identity[16];
	char operation[33], label[64];
	const char *error;
	unsigned count = strtonum(count_text, 0, 100000, &error);
	double start = now();
	size_t rows = 0;

	if (error != NULL)
		errx(64, "churn count: %s", error);
	if (sl_open(path, &db) == -1 ||
	    sl_query(&db, "org.test.load/subject", NULL, &current) == -1)
		err(1, "open churn subject");
	if (current.state == SL_UNKNOWN) {
		if (sl_issue_operation(&db, operation) == -1 ||
		    sl_install_begin(&db, "org.test.load/subject", "load.slot", operation) == -1 ||
		    sl_install_finish(&db, "org.test.load/subject", operation, false) == -1)
			err(1, "initialize churn subject");
		/* Long-lived pending transactions must survive subsequent pruning. */
		for (unsigned i = 0; i < 8; i++) {
			snprintf(label, sizeof(label), "org.test.pending%u/main", i);
			if (sl_issue_operation(&db, operation) == -1 ||
			    sl_install_begin(&db, label, "pending.slot", operation) == -1)
				err(1, "initialize pending operation");
		}
	}
	if (sl_query(&db, "org.test.load/subject", NULL, &current) == -1 ||
	    current.state != SL_INSTALLED)
		errx(1, "subject not installed");
	memcpy(identity, current.generation, sizeof(identity));
	commit_close(&db);
	for (unsigned i = 0; i < count; i++) {
		if (sl_open(path, &db) == -1 ||
		    sl_issue_operation(&db, operation) == -1 ||
		    sl_install_begin(&db, "org.test.load/subject", "load.slot", operation) == -1)
			err(1, "begin upgrade");
		commit_close(&db);
		usleep(2000);
		if (sl_open(path, &db) == -1 ||
		    sl_install_finish(&db, "org.test.load/subject", operation, i % 3 == 0) == -1 ||
		    sl_prune_history(&db, SL_HISTORY_KEEP, NULL) == -1 ||
		    sl_query(&db, "org.test.load/subject", identity, &current) == -1 ||
		    current.state != SL_INSTALLED)
			errx(1, "finish upgrade changed identity or state");
		rows = db.count;
		commit_close(&db);
		if ((i + 1) % 100 == 0) {
			printf("cycles=%u rows=%zu rss_kib=%ld elapsed_s=%.3f\n",
			    i + 1, rows, resident_kib(), now() - start);
			fflush(stdout);
		}
		usleep(2000);
	}
	if (sl_open(path, &db) == -1)
		err(1, "verify pending retention");
	for (unsigned i = 0; i < 8; i++) {
		snprintf(label, sizeof(label), "org.test.pending%u/main", i);
		if (sl_query(&db, label, NULL, &current) == -1 ||
		    current.state != SL_INSTALL_IN_PROGRESS)
			errx(1, "pending transaction lost");
	}
	rows = db.count;
	sl_close(&db);
	sl_generation_format(identity, operation);
	printf("PASS cycles=%u identity=%s rows=%zu elapsed_s=%.3f\n",
	    count, operation, rows, now() - start);
	return (0);
}

static void
zfs_step(const char *verb, const char *snapshot)
{
	pid_t child;
	int status;

	child = fork();
	if (child == -1)
		err(1, "fork zfs");
	if (child == 0) {
		execl("/sbin/zfs", "zfs", verb, snapshot, (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		errx(1, "zfs %s failed", verb);
}

/* Only invoke on a dedicated, disposable VM dataset with no other writers. */
static int
cache_zfs(const char *path, const char *dataset)
{
	struct sl_query_cache *cache;
	struct sl_installation result;
	struct sl_db db;
	struct statfs fs;
	uint8_t old[16], fresh[16], prepared[16];
	char snapshot[1024];
	const char *label = "org.test.cache/rollback";

	if (geteuid() != 0 || mkdir(path, 0700) == -1 || statfs(path, &fs) == -1)
		err(1, "create new cache rollback store as root");
	if (strcmp(fs.f_fstypename, "zfs") != 0 ||
	    strcmp(fs.f_mntfromname, dataset) != 0 ||
	    snprintf(snapshot, sizeof(snapshot), "%s@authority-query-cache", dataset)
	    >= (int)sizeof(snapshot))
		errx(1, "store must be on the specified disposable ZFS dataset");
	if (sl_open(path, &db) == -1 || sl_install(&db, label, old) == -1)
		err(1, "initialize rollback identity");
	commit_close(&db);
	cache = sl_query_cache_create();
	if (cache == NULL || sl_query_cached(cache, path, label, old, &result) == -1 ||
	    result.state != SL_INSTALLED)
		errx(1, "cache initial identity");
	zfs_step("snapshot", snapshot);
	if (sl_open(path, &db) == -1 || sl_prepare(&db, label, prepared) == -1 ||
	    sl_retire(&db, label, old) == -1 || sl_install(&db, label, fresh) == -1)
		err(1, "replace rollback identity");
	commit_close(&db);
	if (memcmp(old, fresh, sizeof(old)) == 0 ||
	    sl_query_cached(cache, path, label, fresh, &result) == -1 ||
	    result.state != SL_INSTALLED)
		errx(1, "cache replacement identity");
	zfs_step("rollback", snapshot);
	if (sl_query_cached(cache, path, label, old, &result) == -1 ||
	    result.state != SL_INSTALLED ||
	    sl_query_cached(cache, path, label, fresh, &result) == -1 ||
	    result.state != SL_UNKNOWN)
		errx(1, "cached identity survived rollback incorrectly");
	sl_query_cache_destroy(cache);
	puts("PASS live query cache across ZFS rollback: original installed, future unknown");
	return (0);
}

static int
compare_latency(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return ((x > y) - (x < y));
}

/* Cold means no validated userspace snapshot, not an evicted disk/ARC cache. */
static int
latency(const char *path, const char *label)
{
	struct sl_query_cache *cache = NULL;
	struct sl_installation result;
	double samples[100], start;
	long rss = 0;

	for (unsigned warm = 0; warm < 2; warm++) {
		unsigned count = warm ? 100 : 20;
		if (warm) {
			cache = sl_query_cache_create();
			if (cache == NULL || sl_query_cached(cache, path, label, NULL,
			    &result) == -1 || result.state != SL_INSTALLED)
				errx(1, "prime warm latency cache");
		}
		for (unsigned i = 0; i < count; i++) {
			if (cache == NULL && (cache = sl_query_cache_create()) == NULL)
				err(1, "create latency cache");
			start = now();
			if (sl_query_cached(cache, path, label, NULL, &result) == -1 ||
			    result.state != SL_INSTALLED)
				errx(1, "latency query failed or identity not installed");
			samples[i] = (now() - start) * 1000;
			long current = resident_kib();
			if (current > rss)
				rss = current;
			if (!warm) {
				sl_query_cache_destroy(cache);
				cache = NULL;
			}
		}
		qsort(samples, count, sizeof(samples[0]), compare_latency);
		printf("mode=%s count=%u p50_ms=%.3f p95_ms=%.3f max_ms=%.3f rss_kib=%ld\n",
		    warm ? "warm" : "cold", count, samples[(count - 1) / 2],
		    samples[(count * 95 + 99) / 100 - 1], samples[count - 1], rss);
		fflush(stdout);
	}
	sl_query_cache_destroy(cache);
	return (0);
}

int
main(int argc, char **argv)
{
	struct sl_db db;
	struct sl_installation result;
	long resident = 0;
	char identity[33], label[SL_LABEL_MAX];
	double elapsed[3], start;
	unsigned long count;
	char *end;
	bool capacity;

	if (argc == 4 && strcmp(argv[1], "latency") == 0)
		return (latency(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "cache-zfs") == 0)
		return (cache_zfs(argv[2], argv[3]));
	if (argc == 4 && strcmp(argv[1], "churn") == 0)
		return (churn(argv[2], argv[3]));
	if (argc >= 3 && strcmp(argv[1], "audit-exec") == 0) {
		struct auditinfo_addr ai;
		char flags[] = "ad,pc,lo,aa";
		if (getaudit_addr(&ai, sizeof(ai)) == -1 ||
		    getauditflagsbin(flags, &ai.ai_mask) == -1 ||
		    setaudit_addr(&ai, sizeof(ai)) == -1)
			err(1, "enable audit selection for qualification process");
		execvp(argv[2], &argv[2]);
		err(1, "audit-exec");
	}
	if (argc != 4 || (strcmp(argv[1], "scale") != 0 &&
	    strcmp(argv[1], "seed") != 0))
		errx(64, "usage: authority_qualification scale NEW_DIRECTORY RECORDS | seed EXISTING_DIRECTORY RECORDS_OR_capacity | churn DIRECTORY CYCLES | latency DIRECTORY LABEL | cache-zfs NEW_DIRECTORY DISPOSABLE_DATASET | audit-exec COMMAND ...");
	capacity = strcmp(argv[1], "seed") == 0 && strcmp(argv[3], "capacity") == 0;
	errno = 0;
	count = strtoul(argv[3], &end, 10);
	if (!capacity && (errno != 0 || *end != '\0' || count == 0 || count > SL_MAX_RECORDS))
		errx(64, "invalid record count");
	if ((strcmp(argv[1], "scale") == 0 && mkdir(argv[2], 0700) == -1) ||
	    sl_open(argv[2], &db) == -1)
		err(1, "new qualification store");
	size_t original = db.count;
	if (capacity)
		count = SL_MAX_RECORDS - original;
	if (count == 0)
		errx(64, "store is already at capacity");
	if (count > SL_MAX_RECORDS - original)
		errx(64, "seed exceeds record capacity");
	db.records = reallocarray(db.records, original + count, sizeof(*db.records));
	if (db.records == NULL)
		err(1, "records");
	memset(db.records + original, 0, count * sizeof(*db.records));
	db.count = original + count;
	db.dirty = true;
	for (size_t i = 0; i < count; i++) {
		struct sl_record *r = &db.records[original + i];
		r->kind = SL_OWNER;
		r->phase = SL_ACTIVE;
		snprintf(r->label, sizeof(r->label), "org.test.scale%zu/main", i);
		r->generation[0] = 1;
		memcpy(r->generation + 8, &i, sizeof(i));
		sl_generation_format(r->generation, identity);
		snprintf(r->provider, sizeof(r->provider), "install.%s", identity);
	}
	strlcpy(label, db.records[original + count / 2].label, sizeof(label));
	start = now();
	if (sl_commit(&db) == -1)
		err(1, "commit");
	printf("records=%lu bytes=%zu commit_ms=%.3f\n", count,
	    count * sizeof(*db.records), 1000 * (now() - start));
	resident = resident_kib();
	sl_close(&db);
	for (unsigned i = 0; i < 3; i++) {
		start = now();
		if (sl_open_readonly(argv[2], &db) == -1 ||
		    sl_query(&db, label, NULL, &result) == -1 ||
		    result.state != SL_INSTALLED)
			err(1, "query");
		long sample = resident_kib();
		if (sample > resident)
			resident = sample;
		sl_close(&db);
		elapsed[i] = 1000 * (now() - start);
	}
	printf("query_ms=%.3f,%.3f,%.3f sampled_rss_kib=%ld\n",
	    elapsed[0], elapsed[1], elapsed[2], resident);
	return (0);
}
