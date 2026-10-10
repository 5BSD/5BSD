/*- SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

/* Include the implementation to exercise generation exhaustion directly. */
#include "../notify_watch.c"

ATF_TC_WITHOUT_HEAD(snapshot_coalescing);
ATF_TC_BODY(snapshot_coalescing, tc)
{
	struct notify_watch *s;
	struct notify_watcher *a, *b;
	struct notify_watch_cursor cursor;
	uint64_t value, output;
	uint32_t flags;
	size_t length;

	ATF_REQUIRE_EQ(0, notify_watch_create(sizeof(value), 2, &s));
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &a));
	ATF_REQUIRE_EQ(0, notify_watch_begin(a));
	ATF_CHECK_EQ(0, notify_watch_take(a, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_ERRNO(EBUSY, notify_watch_begin(a) == -1);
	value = 1;
	ATF_REQUIRE_EQ(1, notify_watch_publish(s, &value, sizeof(value)));
	ATF_REQUIRE_EQ(1, notify_watch_take(a, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(1, output);
	ATF_CHECK_EQ(1, cursor.generation);
	ATF_CHECK_EQ(0, flags);
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &b));
	ATF_REQUIRE_EQ(0, notify_watch_begin(a));
	ATF_REQUIRE_EQ(0, notify_watch_begin(b));
	ATF_REQUIRE_EQ(0, notify_watch_publish(s, &value, sizeof(value)));
	ATF_CHECK_EQ(0, notify_watch_take(a, &output, sizeof(output), &length,
	    &cursor, &flags));
	for (value = 2; value <= 100; value++)
		ATF_REQUIRE_EQ(1, notify_watch_publish(s, &value, sizeof(value)));
	ATF_REQUIRE_EQ(1, notify_watch_take(a, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(100, output);
	ATF_CHECK_EQ(100, cursor.generation);
	ATF_REQUIRE_EQ(1, notify_watch_take(b, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(100, output);
	ATF_CHECK_ERRNO(ENOENT, notify_watch_take(b, &output, sizeof(output),
	    &length, &cursor, &flags) == -1);
	notify_watch_close(a);
	notify_watch_close(b);
	ATF_REQUIRE_EQ(0, notify_watch_destroy(s));
}

ATF_TC_WITHOUT_HEAD(cancel_retry_and_resume);
ATF_TC_BODY(cancel_retry_and_resume, tc)
{
	struct notify_watch *s, *restarted;
	struct notify_watcher *w;
	struct notify_watch_cursor cursor, saved;
	uint64_t value = 42, output;
	uint32_t flags;
	size_t length;

	ATF_REQUIRE_EQ(0, notify_watch_create(sizeof(value), 1, &s));
	ATF_REQUIRE_EQ(1, notify_watch_publish(s, &value, sizeof(value)));
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &w));
	ATF_REQUIRE_EQ(0, notify_watch_begin(w));
	ATF_REQUIRE_EQ(0, notify_watch_cancel(w));
	ATF_REQUIRE_EQ(0, notify_watch_begin(w));
	ATF_CHECK_ERRNO(EMSGSIZE, notify_watch_take(w, NULL, 0, &length,
	    &cursor, &flags) == -1);
	ATF_CHECK_EQ(sizeof(value), length);
	ATF_CHECK_ERRNO(EBUSY, notify_watch_begin(w) == -1);
	ATF_REQUIRE_EQ(1, notify_watch_take(w, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(value, output);
	saved = cursor;
	notify_watch_close(w);
	ATF_REQUIRE_EQ(0, notify_watch_open(s, &saved, &w));
	ATF_REQUIRE_EQ(0, notify_watch_begin(w));
	ATF_CHECK_EQ(0, notify_watch_take(w, &output, sizeof(output), &length,
	    &cursor, &flags));
	value++;
	ATF_REQUIRE_EQ(1, notify_watch_publish(s, &value, sizeof(value)));
	ATF_REQUIRE_EQ(1, notify_watch_take(w, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(value, output);
	ATF_CHECK_EQ(0, flags);
	notify_watch_close(w);
	ATF_REQUIRE_EQ(0, notify_watch_create(sizeof(value), 1, &restarted));
	ATF_REQUIRE_EQ(1, notify_watch_publish(restarted, &value, sizeof(value)));
	ATF_REQUIRE_EQ(0, notify_watch_open(restarted, &saved, &w));
	ATF_REQUIRE_EQ(0, notify_watch_begin(w));
	ATF_REQUIRE_EQ(1, notify_watch_take(w, &output, sizeof(output), &length,
	    &cursor, &flags));
	ATF_CHECK_EQ(NOTIFY_WATCH_RESET, flags);
	ATF_CHECK(cursor.epoch != saved.epoch);
	notify_watch_close(w);
	ATF_REQUIRE_EQ(0, notify_watch_destroy(s));
	ATF_REQUIRE_EQ(0, notify_watch_destroy(restarted));
}

ATF_TC_WITHOUT_HEAD(bounds_and_overflow);
ATF_TC_BODY(bounds_and_overflow, tc)
{
	struct notify_watch *s;
	struct notify_watcher *a, *b;
	struct notify_watch_cursor cursor;
	uint32_t flags;
	size_t length;
	char output;

	ATF_CHECK_ERRNO(EINVAL, notify_watch_create(0, 1, &s) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_watch_create(NOTIFY_WATCH_MAX_BYTES + 1,
	    1, &s) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_watch_create(1, 0, &s) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_watch_create(1,
	    NOTIFY_WATCH_MAX_SUBSCRIBERS + 1, &s) == -1);
	ATF_REQUIRE_EQ(0, notify_watch_create(1, 1, &s));
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &a));
	ATF_CHECK_ERRNO(ENOSPC, notify_watch_open(s, NULL, &b) == -1);
	ATF_CHECK_ERRNO(EBUSY, notify_watch_destroy(s) == -1);
	ATF_CHECK_ERRNO(EMSGSIZE, notify_watch_publish(s, "ab", 2) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_watch_publish(s, NULL, 1) == -1);
	ATF_REQUIRE_EQ(1, notify_watch_publish(s, NULL, 0));
	ATF_REQUIRE_EQ(0, notify_watch_begin(a));
	ATF_REQUIRE_EQ(1, notify_watch_take(a, NULL, 0, &length, &cursor, &flags));
	ATF_CHECK_EQ(0, length);
	notify_watch_close(a);
	cursor.generation++;
	ATF_CHECK_ERRNO(EINVAL, notify_watch_open(s, &cursor, &a) == -1);
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &a));
	s->cursor.generation = UINT64_MAX - 1;
	ATF_REQUIRE_EQ(1, notify_watch_publish(s, "a", 1));
	ATF_REQUIRE_EQ(0, notify_watch_publish(s, "a", 1));
	ATF_CHECK_ERRNO(EOVERFLOW, notify_watch_publish(s, "b", 1) == -1);
	ATF_REQUIRE_EQ(0, notify_watch_begin(a));
	ATF_REQUIRE_EQ(1, notify_watch_take(a, &output, 1, &length, &cursor, &flags));
	ATF_CHECK_EQ('a', output);
	ATF_CHECK_EQ(UINT64_MAX, cursor.generation);
	notify_watch_close(a);
	ATF_REQUIRE_EQ(0, notify_watch_destroy(s));
}

struct sample {
	uint64_t number;
	uint64_t inverse;
	uint64_t copies[30];
};

static void *
publish_thread(void *arg)
{
	struct sample sample;
	struct notify_watch *s = arg;
	size_t i;

	for (sample.number = 1; sample.number <= 10000; sample.number++) {
		sample.inverse = ~sample.number;
		for (i = 0; i < 30; i++)
			sample.copies[i] = sample.number;
		if (notify_watch_publish(s, &sample, sizeof(sample)) != 1)
			return ((void *)(uintptr_t)1);
	}
	return (NULL);
}

ATF_TC(concurrent_snapshot);
ATF_TC_HEAD(concurrent_snapshot, tc)
{
	atf_tc_set_md_var(tc, "timeout", "20");
}
ATF_TC_BODY(concurrent_snapshot, tc)
{
	struct notify_watch *s;
	struct notify_watcher *w;
	struct notify_watch_cursor cursor;
	struct sample sample;
	pthread_t thread;
	uint64_t previous = 0;
	uint32_t flags;
	size_t length, i;
	void *result;
	int ready;

	ATF_REQUIRE_EQ(0, notify_watch_create(sizeof(sample), 1, &s));
	ATF_REQUIRE_EQ(0, notify_watch_open(s, NULL, &w));
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, publish_thread, s));
	while (previous != 10000) {
		ATF_REQUIRE_EQ(0, notify_watch_begin(w));
		do {
			ready = notify_watch_take(w, &sample, sizeof(sample), &length,
			    &cursor, &flags);
			ATF_REQUIRE(ready >= 0);
		} while (ready == 0);
		ATF_CHECK_EQ(sizeof(sample), length);
		ATF_CHECK(sample.number > previous);
		ATF_CHECK_EQ(sample.number, cursor.generation);
		ATF_CHECK_EQ(~sample.number, sample.inverse);
		for (i = 0; i < 30; i++)
			ATF_CHECK_EQ(sample.number, sample.copies[i]);
		previous = sample.number;
	}
	ATF_REQUIRE_EQ(0, pthread_join(thread, &result));
	ATF_CHECK(result == NULL);
	notify_watch_close(w);
	ATF_REQUIRE_EQ(0, notify_watch_destroy(s));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, snapshot_coalescing);
	ATF_TP_ADD_TC(tp, cancel_retry_and_resume);
	ATF_TP_ADD_TC(tp, bounds_and_overflow);
	ATF_TP_ADD_TC(tp, concurrent_snapshot);
	return (atf_no_error());
}
