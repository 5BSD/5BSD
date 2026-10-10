/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/wait.h>

#include <atf-c.h>

#include "../bsd_cache.c"
struct notify_client {
	unsigned last;
};
static struct notify_client fake_notify;
static atomic_uint fake_level, fake_closed;
int
notify_client_open(struct notify_client **out)
{
	fake_notify.last = UINT32_MAX;
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
	ATF_REQUIRE_EQ(0,
	    bsd_cache_create(4, 16, BSD_CACHE_AUTOMATIC, NULL, NULL, &cache));
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
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cost_overflow);
	ATF_TP_ADD_TC(tp, lru_and_copy);
	ATF_TP_ADD_TC(tp, pressure_and_limits);
	ATF_TP_ADD_TC(tp, fork_rejection);
	ATF_TP_ADD_TC(tp, concurrent_bounds);
	ATF_TP_ADD_TC(tp, automatic_pressure);
	return (atf_no_error());
}
