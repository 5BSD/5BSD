/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/wait.h>

#include <atf-c.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
static atomic_uint allocation_calls;
static void (*allocation_hook)(void);
static void *
counted_malloc(size_t size)
{
	atomic_fetch_add(&allocation_calls, 1);
	void *p = malloc(size);
	if (allocation_hook != NULL)
		allocation_hook();
	return (p);
}
#define malloc counted_malloc
#include "../bsd_cache.c"
#undef malloc
struct notify_client {
	unsigned last;
	uint64_t generation;
};
static struct notify_client fake_notify;
static atomic_uint fake_level, fake_closed, fake_open_calls;
static atomic_int fake_open_error;
int
notify_client_open(struct notify_client **out)
{
	atomic_fetch_add(&fake_open_calls, 1);
	int error = atomic_load(&fake_open_error);
	if (error != 0) {
		*out = NULL;
		return (errno = error, -1);
	}
	fake_notify.last = UINT32_MAX;
	fake_notify.generation = 0;
	*out = &fake_notify;
	return (0);
}
void
notify_client_close(struct notify_client *client)
{
	(void)client;
	atomic_fetch_add(&fake_closed, 1);
}
int
notify_state_watch(struct notify_client *client, const char *topic,
    struct notify_state_watch_reply *out, uint32_t timeout)
{
	(void)timeout;
	ATF_CHECK_STREQ(NOTIFY_PRESSURE_TOPIC, topic);
	unsigned level = atomic_load(&fake_level);
	if (level == UINT32_MAX - 1)
		return (errno = ECONNRESET, -1);
	if (client->last == level) {
		usleep(1000);
		return (errno = EAGAIN, -1);
	}
	client->last = level;
	memset(out, 0, sizeof(*out));
	out->watch_epoch = 1;
	out->generation = ++client->generation;
	out->present = level != UINT32_MAX;
	out->state = level;
	return (0);
}
static void
callback(const char *key, const void *value, size_t length,
    enum bsd_cache_reason reason, void *argument)
{
	struct bsd_cache_stats stats;
	struct bsd_cache **cache = argument;
	(void)key;
	(void)value;
	(void)length;
	(void)reason;
	/* A callback can re-enter for statistics: no cache mutex is held. */
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(*cache, &stats));
	if (reason == BSD_CACHE_DESTROYED)
		ATF_CHECK_ERRNO(EAGAIN,
		    bsd_cache_put(*cache, "reinsert", "x", 1, 1) == -1);
}
ATF_TC_WITHOUT_HEAD(lru_and_copy);
ATF_TC_BODY(lru_and_copy, tc)
{
	struct bsd_cache *cache;
	char value[] = "one", out[16] = "sentinel";
	size_t length;
	ATF_REQUIRE_EQ(0, bsd_cache_create(2, 16, 0, callback, &cache, &cache));
	ATF_REQUIRE_EQ(0,
	    bsd_cache_put(cache, "a", value, sizeof(value), sizeof(value)));
	value[0] = 'X';
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "b", "two", 4, 4));
	length = 1;
	ATF_CHECK_ERRNO(ENOMEM, bsd_cache_get(cache, "a", out, &length) == -1);
	ATF_CHECK_EQ(4, length);
	ATF_CHECK_EQ('s', out[0]);
	length = sizeof(out);
	ATF_REQUIRE_EQ(0, bsd_cache_get(cache, "a", out, &length));
	ATF_CHECK_STREQ("one", out);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "c", "new", 4, 4));
	length = sizeof(out);
	ATF_CHECK_ERRNO(ENOENT, bsd_cache_get(cache, "b", out, &length) == -1);
	ATF_CHECK_ERRNO(EINVAL, bsd_cache_put(cache, "a", "bad", 4, 3) == -1);
	ATF_REQUIRE_EQ(0, bsd_cache_get(cache, "a", out, &length));
	ATF_CHECK_STREQ("one", out);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
ATF_TC_WITHOUT_HEAD(pressure_and_limits);
ATF_TC_BODY(pressure_and_limits, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 16, 0, NULL, NULL, &cache));
	for (unsigned i = 0; i < 4; i++) {
		char key[] = { 'a' + i, 0 };
		ATF_REQUIRE_EQ(0, bsd_cache_put(cache, key, "abc", 4, 4));
	}
	ATF_REQUIRE_EQ(0,
	    bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_WARNING));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(2, stats.entries);
	ATF_CHECK_EQ(8, stats.cost);
	ATF_REQUIRE_EQ(0,
	    bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_CRITICAL));
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "a", "abc", 4, 4) == -1);
	ATF_REQUIRE_EQ(0,
	    bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_UNKNOWN));
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "a", "abc", 4, 4) == -1);
	ATF_REQUIRE_EQ(0,
	    bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_NORMAL));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "a", "abc", 4, 4));
	ATF_REQUIRE_EQ(0, bsd_cache_set_limits(cache, 1, 2));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(0, stats.entries);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
ATF_TC_WITHOUT_HEAD(fork_rejection);
ATF_TC_BODY(fork_rejection, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	pid_t child;
	int status;
	ATF_REQUIRE_EQ(0, bsd_cache_create(1, 1, 0, NULL, NULL, &cache));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(bsd_cache_get_stats(cache, &stats) == -1 &&
			    errno == ECHILD && bsd_cache_destroy(cache) == -1 &&
			    errno == ECHILD ?
			0 :
			1);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
static void *
churn(void *argument)
{
	struct bsd_cache *cache = argument;
	for (unsigned i = 0; i < 1000; i++) {
		char key[] = { 'a' + i % 16, 0 }, out[4];
		size_t length = sizeof(out);
		ATF_REQUIRE_EQ(0, bsd_cache_put(cache, key, "abc", 4, 4));
		int result = bsd_cache_get(cache, key, out, &length);
		ATF_CHECK(result == 0 || errno == ENOENT);
	}
	return (NULL);
}
ATF_TC_WITHOUT_HEAD(concurrent_bounds);
ATF_TC_BODY(concurrent_bounds, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	pthread_t threads[4];
	ATF_REQUIRE_EQ(0, bsd_cache_create(8, 32, 0, NULL, NULL, &cache));
	for (unsigned i = 0; i < 4; i++)
		ATF_REQUIRE_EQ(0,
		    pthread_create(&threads[i], NULL, churn, cache));
	for (unsigned i = 0; i < 4; i++)
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK(stats.entries <= 8 && stats.cost <= 32);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
static void
wait_level(struct bsd_cache *cache, unsigned level)
{
	struct bsd_cache_stats stats;
	for (unsigned i = 0; i < 3000; i++) {
		ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
		if (stats.pressure == level)
			return;
		usleep(1000);
	}
	atf_tc_fail("pressure notification not applied");
}
ATF_TC_WITHOUT_HEAD(automatic_pressure);
ATF_TC_BODY(automatic_pressure, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	atomic_store(&fake_level, NOTIFY_PRESSURE_NORMAL);
	ATF_REQUIRE_EQ(0, bsd_cache_open(4, 16, &cache));
	wait_level(cache, NOTIFY_PRESSURE_NORMAL);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "a", "abc", 4, 4));
	atomic_store(&fake_level, NOTIFY_PRESSURE_CRITICAL);
	wait_level(cache, NOTIFY_PRESSURE_CRITICAL);
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(0, stats.entries);
	atomic_store(&fake_level, UINT32_MAX);
	wait_level(cache, NOTIFY_PRESSURE_UNKNOWN);
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "a", "abc", 4, 4) == -1);
	atomic_store(&fake_level, UINT32_MAX - 1);
	for (unsigned i = 0; atomic_load(&fake_closed) == 0 && i < 3000; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(1, atomic_load(&fake_closed));
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "a", "abc", 4, 4) == -1);
	atomic_store(&fake_level, NOTIFY_PRESSURE_NORMAL);
	wait_level(cache, NOTIFY_PRESSURE_NORMAL);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "a", "abc", 4, 4));
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
	ATF_CHECK_EQ(2, atomic_load(&fake_closed));
}
ATF_TC_WITHOUT_HEAD(cost_overflow);
ATF_TC_BODY(cost_overflow, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	char out;
	size_t length = 1;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, SIZE_MAX, 0, NULL, NULL, &cache));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "a", "a", 1, SIZE_MAX));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "b", "b", 1, 1));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(1, stats.entries);
	ATF_CHECK_EQ(1, stats.cost);
	ATF_CHECK_ERRNO(ENOENT, bsd_cache_get(cache, "a", &out, &length) == -1);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "b", "b", 1, SIZE_MAX));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(SIZE_MAX, stats.cost);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
ATF_TC_WITHOUT_HEAD(lookup_contract);
ATF_TC_BODY(lookup_contract, tc)
{
	struct bsd_cache *cache;
	char out[8] = "keep";
	size_t length = sizeof(out);
	ATF_REQUIRE_EQ(0, bsd_cache_create(2, 16, 0, NULL, NULL, &cache));
	errno = EDOM;
	ATF_REQUIRE_EQ(BSD_CACHE_MISS,
	    bsd_cache_lookup(cache, "key", out, &length));
	ATF_CHECK_EQ(EDOM, errno);
	ATF_CHECK_STREQ("keep", out);
	ATF_CHECK_EQ(sizeof(out), length);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "key", "value", 6, 6));
	length = 1;
	ATF_CHECK_ERRNO(ENOMEM,
	    bsd_cache_lookup(cache, "key", out, &length) == BSD_CACHE_ERROR);
	ATF_CHECK_EQ(6, length);
	ATF_CHECK_STREQ("keep", out);
	length = sizeof(out);
	errno = EDOM;
	ATF_REQUIRE_EQ(BSD_CACHE_HIT,
	    bsd_cache_lookup(cache, "key", out, &length));
	ATF_CHECK_EQ(EDOM, errno);
	ATF_REQUIRE_EQ(0,
	    bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_CRITICAL));
	/* A returned copy survives eviction of its source entry. */
	ATF_CHECK_STREQ("value", out);
	ATF_REQUIRE_EQ(BSD_CACHE_MISS,
	    bsd_cache_lookup(cache, "key", out, &length));
	ATF_CHECK_STREQ("value", out);
	ATF_CHECK_ERRNO(EINVAL,
	    bsd_cache_lookup(cache, "", out, &length) == BSD_CACHE_ERROR);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
struct pending_build {
	struct bsd_cache *cache;
	pthread_barrier_t barrier;
	int result, error;
};
static void *
finish_build(void *argument)
{
	struct pending_build *work = argument;
	uint64_t generation;
	ATF_REQUIRE_EQ(0, bsd_cache_generation(work->cache, &generation));
	pthread_barrier_wait(&work->barrier);
	pthread_barrier_wait(&work->barrier);
	work->result = bsd_cache_put_if_current(work->cache, "key", "old", 4, 4,
	    generation);
	work->error = errno;
	return (NULL);
}
ATF_TC_WITHOUT_HEAD(invalidation_during_rebuild);
ATF_TC_BODY(invalidation_during_rebuild, tc)
{
	struct pending_build work;
	pthread_t thread;
	char out[8];
	size_t length = sizeof(out);
	uint64_t generation;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 32, 0, NULL, NULL, &work.cache));
	ATF_REQUIRE_EQ(0, pthread_barrier_init(&work.barrier, NULL, 2));
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, finish_build, &work));
	pthread_barrier_wait(&work.barrier);
	/* Rebuild has captured a token. Invalidation happens before insertion.
	 */
	ATF_REQUIRE_EQ(0, bsd_cache_purge(work.cache));
	ATF_REQUIRE_EQ(0, bsd_cache_put(work.cache, "key", "new", 4, 4));
	pthread_barrier_wait(&work.barrier);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ(-1, work.result);
	ATF_CHECK_EQ(ESTALE, work.error);
	ATF_REQUIRE_EQ(BSD_CACHE_HIT,
	    bsd_cache_lookup(work.cache, "key", out, &length));
	ATF_CHECK_STREQ("new", out);
	ATF_REQUIRE_EQ(0, bsd_cache_generation(work.cache, &generation));
	ATF_REQUIRE_EQ(0,
	    bsd_cache_put_if_current(work.cache, "key", "fresh", 6, 6,
		generation));
	ATF_CHECK_ERRNO(ESTALE,
	    bsd_cache_put_if_current(work.cache, "key", "old", 4, 4,
		generation) == -1);
	ATF_REQUIRE_EQ(0, pthread_barrier_destroy(&work.barrier));
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(work.cache));
}
ATF_TC_WITHOUT_HEAD(generation_invalidation);
ATF_TC_BODY(generation_invalidation, tc)
{
	struct bsd_cache *cache;
	uint64_t generation;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 32, 0, NULL, NULL, &cache));
	for (unsigned i = 0; i < 4; i++) {
		ATF_REQUIRE_EQ(0, bsd_cache_generation(cache, &generation));
		switch (i) {
		case 0:
			ATF_REQUIRE_EQ(0, bsd_cache_purge(cache));
			break;
		case 1:
			ATF_CHECK_ERRNO(ENOENT,
			    bsd_cache_remove(cache, "missing") == -1);
			break;
		case 2:
			ATF_REQUIRE_EQ(0, bsd_cache_set_limits(cache, 2, 16));
			break;
		case 3:
			ATF_REQUIRE_EQ(0,
			    bsd_cache_set_pressure(cache,
				NOTIFY_PRESSURE_WARNING));
			break;
		}
		ATF_CHECK_ERRNO(ESTALE,
		    bsd_cache_put_if_current(cache, "key", "x", 1, 1,
			generation) == -1);
	}
	/* Tokens must never wrap back to an old value. */
	cache->generation = UINT64_MAX;
	ATF_REQUIRE_EQ(0, bsd_cache_generation(cache, &generation));
	ATF_REQUIRE_EQ(0, bsd_cache_purge(cache));
	ATF_CHECK_ERRNO(EOVERFLOW,
	    bsd_cache_generation(cache, &generation) == -1);
	ATF_CHECK_ERRNO(ESTALE,
	    bsd_cache_put_if_current(cache, "key", "x", 1, 1, generation) ==
		-1);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
ATF_TC_WITHOUT_HEAD(coalesced_pressure);
ATF_TC_BODY(coalesced_pressure, tc)
{
	struct bsd_cache *cache;
	struct notify_state_watch_reply state = { .watch_epoch = 1,
		.generation = 1,
		.present = 1,
		.state = NOTIFY_PRESSURE_NORMAL };
	uint64_t epoch = 0, generation = 0, token;
	char out;
	size_t length = 1;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 32, 0, NULL, NULL, &cache));
	observe_pressure(cache, &state, &epoch, &generation);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "key", "x", 1, 1));
	ATF_REQUIRE_EQ(0, bsd_cache_generation(cache, &token));
	/* Critical followed by recovery before the watcher could run. */
	state.generation = 3;
	observe_pressure(cache, &state, &epoch, &generation);
	ATF_REQUIRE_EQ(BSD_CACHE_MISS,
	    bsd_cache_lookup(cache, "key", &out, &length));
	ATF_CHECK_ERRNO(ESTALE,
	    bsd_cache_put_if_current(cache, "key", "x", 1, 1, token) == -1);
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "key", "x", 1, 1));
	state.watch_epoch = 2;
	state.generation = 1;
	observe_pressure(cache, &state, &epoch, &generation);
	ATF_REQUIRE_EQ(BSD_CACHE_MISS,
	    bsd_cache_lookup(cache, "key", &out, &length));
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
ATF_TC_WITHOUT_HEAD(reject_without_allocation);
ATF_TC_BODY(reject_without_allocation, tc)
{
	struct bsd_cache *cache;
	uint64_t generation;
	unsigned before;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 32, 0, NULL, NULL, &cache));
	ATF_REQUIRE_EQ(0, bsd_cache_generation(cache, &generation));
	ATF_REQUIRE_EQ(0, bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_CRITICAL));
	before = atomic_load(&allocation_calls);
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "key", "x", 1, 1) == -1);
	ATF_CHECK_EQ(before, atomic_load(&allocation_calls));
	ATF_REQUIRE_EQ(0, bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_NORMAL));
	ATF_CHECK_ERRNO(ESTALE, bsd_cache_put_if_current(cache, "key", "x", 1, 1, generation) == -1);
	ATF_CHECK_EQ(before, atomic_load(&allocation_calls));
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(cache, "key", "x", 1, 33) == -1);
	ATF_CHECK_EQ(before, atomic_load(&allocation_calls));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "key", "x", 1, 1));
	ATF_CHECK_EQ(before + 1, atomic_load(&allocation_calls));
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}
static struct bsd_cache *allocating_cache;
static void
pressure_during_copy(void)
{
	ATF_REQUIRE_EQ(0, bsd_cache_set_pressure(allocating_cache, NOTIFY_PRESSURE_CRITICAL));
}
ATF_TC_WITHOUT_HEAD(pressure_during_allocation);
ATF_TC_BODY(pressure_during_allocation, tc)
{
	struct bsd_cache_stats stats;
	ATF_REQUIRE_EQ(0, bsd_cache_create(4, 32, 0, NULL, NULL, &allocating_cache));
	allocation_hook = pressure_during_copy;
	ATF_CHECK_ERRNO(EAGAIN, bsd_cache_put(allocating_cache, "key", "x", 1, 1) == -1);
	allocation_hook = NULL;
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(allocating_cache, &stats));
	ATF_CHECK_EQ(0, stats.entries);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(allocating_cache));
}
ATF_TC_WITHOUT_HEAD(large_cache_lifecycle);
ATF_TC_BODY(large_cache_lifecycle, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;
	char key[64];
	unsigned value;
	size_t length;
	const unsigned count = 8192;

	ATF_REQUIRE_EQ(0, bsd_cache_create(count, count * sizeof(value),
	    0, NULL, NULL, &cache));
	for (unsigned i = 0; i < count; i++) {
		snprintf(key, sizeof(key), "shared-prefix-%08u", i);
		ATF_REQUIRE_EQ(0, bsd_cache_put(cache, key, &i, sizeof(i), sizeof(i)));
	}
	/* Read oldest-first: this is quadratic with a linear LRU search. */
	for (unsigned i = 0; i < count; i++) {
		snprintf(key, sizeof(key), "shared-prefix-%08u", i);
		length = sizeof(value);
		ATF_REQUIRE_EQ(0, bsd_cache_get(cache, key, &value, &length));
		ATF_REQUIRE_EQ(i, value);
	}
	for (unsigned i = 0; i < count; i++) {
		snprintf(key, sizeof(key), "shared-prefix-%08u", i);
		if (i % 2 != 0)
			ATF_REQUIRE_EQ(0, bsd_cache_remove(cache, key));
		else {
			value = i + count;
			ATF_REQUIRE_EQ(0, bsd_cache_put(cache, key, &value,
			    sizeof(value), sizeof(value)));
		}
	}
	for (unsigned i = 0; i < count; i++) {
		snprintf(key, sizeof(key), "shared-prefix-%08u", i);
		length = sizeof(value);
		if (i % 2 != 0)
			ATF_REQUIRE_EQ(BSD_CACHE_MISS,
			    bsd_cache_lookup(cache, key, &value, &length));
		else {
			ATF_REQUIRE_EQ(BSD_CACHE_HIT,
			    bsd_cache_lookup(cache, key, &value, &length));
			ATF_REQUIRE_EQ(i + count, value);
		}
	}
	ATF_REQUIRE_EQ(0, bsd_cache_set_limits(cache, 16, 16 * sizeof(value)));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(16, stats.entries);
	ATF_REQUIRE_EQ(0, bsd_cache_purge(cache));
	length = sizeof(value);
	ATF_REQUIRE_EQ(BSD_CACHE_MISS,
	    bsd_cache_lookup(cache, "shared-prefix-00008190", &value, &length));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "shared-prefix-00008190", "x", 1, 1));
	ATF_REQUIRE_EQ(0, bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_CRITICAL));
	ATF_REQUIRE_EQ(0, bsd_cache_set_pressure(cache, NOTIFY_PRESSURE_NORMAL));
	ATF_REQUIRE_EQ(0, bsd_cache_put(cache, "shared-prefix-00008190", "y", 1, 1));
	length = sizeof(value);
	char byte;
	ATF_REQUIRE_EQ(0, bsd_cache_get(cache, "shared-prefix-00008190", &byte, &length));
	ATF_CHECK_EQ('y', byte);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
}

ATF_TC_WITHOUT_HEAD(discovery_eagain_backs_off);
ATF_TC_BODY(discovery_eagain_backs_off, tc)
{
	struct bsd_cache *cache;
	struct bsd_cache_stats stats;

	atomic_store(&fake_open_error, EAGAIN);
	atomic_store(&fake_level, NOTIFY_PRESSURE_NORMAL);
	ATF_REQUIRE_EQ(0, bsd_cache_open(4, 16, &cache));
	for (unsigned i = 0; atomic_load(&fake_open_calls) == 0 && i < 3000; i++)
		usleep(1000);
	ATF_REQUIRE(atomic_load(&fake_open_calls) != 0);
	usleep(100000);
	/* A failed discovery must not spin or masquerade as a watch timeout. */
	ATF_CHECK_EQ(1, atomic_load(&fake_open_calls));
	ATF_REQUIRE_EQ(0, bsd_cache_get_stats(cache, &stats));
	ATF_CHECK_EQ(EAGAIN, stats.notification_error);
	ATF_CHECK_EQ(NOTIFY_PRESSURE_UNKNOWN, stats.pressure);
	ATF_CHECK_EQ(0, atomic_load(&fake_closed));
	atomic_store(&fake_open_error, 0);
	wait_level(cache, NOTIFY_PRESSURE_NORMAL);
	ATF_REQUIRE_EQ(0, bsd_cache_destroy(cache));
	ATF_CHECK_EQ(1, atomic_load(&fake_closed));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, discovery_eagain_backs_off);
	ATF_TP_ADD_TC(tp, large_cache_lifecycle);
	ATF_TP_ADD_TC(tp, invalidation_during_rebuild);
	ATF_TP_ADD_TC(tp, generation_invalidation);
	ATF_TP_ADD_TC(tp, pressure_during_allocation);
	ATF_TP_ADD_TC(tp, reject_without_allocation);
	ATF_TP_ADD_TC(tp, coalesced_pressure);
	ATF_TP_ADD_TC(tp, lookup_contract);
	ATF_TP_ADD_TC(tp, cost_overflow);
	ATF_TP_ADD_TC(tp, lru_and_copy);
	ATF_TP_ADD_TC(tp, pressure_and_limits);
	ATF_TP_ADD_TC(tp, fork_rejection);
	ATF_TP_ADD_TC(tp, concurrent_bounds);
	ATF_TP_ADD_TC(tp, automatic_pressure);
	return (atf_no_error());
}
