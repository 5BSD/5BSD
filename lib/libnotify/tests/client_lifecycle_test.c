/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <notify.h>

#include "fake_service.h"

struct publish_argument {
	struct notify_client *client;
	atomic_uint		*completion;
	unsigned		 rank;
	int			 result;
};

static void *
publish_thread(void *argument)
{
	struct publish_argument *publish = argument;

	publish->result = notify_publish(publish->client, "test.concurrent",
	    "x", 1);
	publish->rank = atomic_fetch_add(publish->completion, 1);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_concurrent_clients);
ATF_TC_BODY(independent_concurrent_clients, tc)
{
	struct notify_client *first, *second, *third;
	struct publish_argument arguments[2];
	atomic_uint completion;
	pthread_t threads[2];

	fake_service_reset();
	atomic_init(&completion, 0);
	ATF_REQUIRE_EQ(0, notify_client_open(&first));
	ATF_REQUIRE_EQ(0, notify_client_open(&second));
	ATF_CHECK_EQ(2, fake_service_created());
	memset(arguments, 0, sizeof(arguments));
	arguments[0].client = first;
	arguments[1].client = second;
	arguments[0].completion = arguments[1].completion = &completion;
	ATF_REQUIRE_EQ(0, pthread_create(&threads[0], NULL, publish_thread,
	    &arguments[0]));
	ATF_REQUIRE_EQ(0, pthread_create(&threads[1], NULL, publish_thread,
	    &arguments[1]));
	ATF_REQUIRE_EQ(0, pthread_join(threads[0], NULL));
	ATF_REQUIRE_EQ(0, pthread_join(threads[1], NULL));
	ATF_CHECK_EQ(0, arguments[0].result);
	ATF_CHECK_EQ(0, arguments[1].result);
	ATF_CHECK_EQ(1, arguments[0].rank);
	ATF_CHECK_EQ(0, arguments[1].rank);
	ATF_CHECK(fake_service_max_concurrent() >= 2);
	notify_client_close(first);
	notify_client_close(second);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_client_open(&third));
	ATF_CHECK_EQ(3, fake_service_created());
	notify_client_close(third);
	ATF_CHECK_EQ(3, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(binary_payload_and_same_client_serialization);
ATF_TC_BODY(binary_payload_and_same_client_serialization, tc)
{
	enum { THREADS = 8 };
	struct publish_argument arguments[THREADS];
	uint8_t expected[NOTIFY_MAX_PAYLOAD];
	uint8_t actual[NOTIFY_MAX_PAYLOAD];
	struct notify_client *client;
	atomic_uint completion;
	pthread_t threads[THREADS];
	size_t i;

	fake_service_reset();
	for (i = 0; i < sizeof(expected); i++)
		expected[i] = (uint8_t)(i * 43U);
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_REQUIRE_EQ(0, notify_publish(client, "test.binary", expected,
	    sizeof(expected)));
	ATF_REQUIRE_EQ(sizeof(expected),
	    fake_service_last_payload(actual, sizeof(actual)));
	ATF_CHECK_EQ(0, memcmp(expected, actual, sizeof(expected)));
	ATF_CHECK_ERRNO(EINVAL, notify_publish(client, "test.binary",
	    expected, sizeof(expected) + 1) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_publish(client, "test.binary", NULL, 1) == -1);
	ATF_CHECK_EQ(1, fake_service_publishes());

	atomic_init(&completion, 0);
	memset(arguments, 0, sizeof(arguments));
	for (i = 0; i < THREADS; i++) {
		arguments[i].client = client;
		arguments[i].completion = &completion;
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL,
		    publish_thread, &arguments[i]));
	}
	for (i = 0; i < THREADS; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ(0, arguments[i].result);
	}
	ATF_CHECK_EQ(1, fake_service_max_concurrent());
	ATF_CHECK_EQ(1 + THREADS, fake_service_publishes());
	notify_client_close(client);
}

ATF_TC_WITHOUT_HEAD(peer_death_reconnect_and_replay);
ATF_TC_BODY(peer_death_reconnect_and_replay, tc)
{
	struct notify_event event;
	struct notify_client *client;
	ssize_t length;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "test.changed"));
	ATF_CHECK_EQ(1, fake_service_subscriptions());
	fake_service_fail_next();
	length = notify_next(client, &event, sizeof(event), 100);
	ATF_REQUIRE_EQ(sizeof(event), length);
	ATF_CHECK_EQ(NOTIFY_EVENT_RESET, event.type);
	ATF_CHECK(event.router_epoch != 0);
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_CHECK_EQ(2, fake_service_subscriptions());
	notify_client_close(client);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct notify_client *client;
	int status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct notify_client *fresh;

		if (notify_publish(client, "test.child", NULL, 0) != -1 ||
		    errno != EINVAL)
			_exit(1);
		if (notify_client_open(&fresh) == -1)
			_exit(2);
		notify_client_close(fresh);
		notify_client_close(client);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0,
	    notify_publish(client, "test.parent", NULL, 0));
	notify_client_close(client);
}

ATF_TC_WITHOUT_HEAD(open_failure_is_retryable);
ATF_TC_BODY(open_failure_is_retryable, tc)
{
	struct notify_client *client;

	fake_service_reset();
	fake_service_fault_next(FAKE_SERVICE_FAULT_INVALID_HELLO);
	ATF_CHECK_ERRNO(EPROTO, notify_client_open(&client) == -1);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_CHECK_EQ(2, fake_service_created());
	notify_client_close(client);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(malformed_replies_invalidate_session);
ATF_TC_BODY(malformed_replies_invalidate_session, tc)
{
	static const enum fake_service_fault protocol_faults[] = {
		FAKE_SERVICE_FAULT_TRUNCATE,
		FAKE_SERVICE_FAULT_WRONG_OPCODE,
		FAKE_SERVICE_FAULT_ATTACHED_FD
	};
	struct notify_client *client;
	struct notify_state_reply state;
	struct notify_stats stats;
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "test.changed"));
	for (i = 0; i < nitems(protocol_faults); i++) {
		fake_service_fault_next(protocol_faults[i]);
		ATF_CHECK_ERRNO(EPROTO, notify_stats(client, &stats) == -1);
		ATF_CHECK_EQ(i + 1, fake_service_closed());
		ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
		ATF_CHECK_EQ(i + 2, fake_service_created());
	}
	ATF_CHECK_EQ(4, fake_service_subscriptions());
	fake_service_fault_next(FAKE_SERVICE_FAULT_INVALID_STATE);
	ATF_CHECK_ERRNO(EPROTO, notify_state_get(client, "test.changed",
	    &state) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
	ATF_CHECK_EQ(5, fake_service_created());
	fake_service_fault_next(FAKE_SERVICE_FAULT_STATUS);
	ATF_CHECK_ERRNO(EPERM, notify_stats(client, &stats) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
	fake_service_fault_next(FAKE_SERVICE_FAULT_TIMEOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT, notify_stats(client, &stats) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
	notify_client_close(client);
	ATF_CHECK_EQ(5, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(non_event_peer_death_recovers_without_replay);
ATF_TC_BODY(non_event_peer_death_recovers_without_replay, tc)
{
	struct notify_client *client;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "test.changed"));
	fake_service_fail_opcode(NOTIFY_OP_PUBLISH);
	ATF_CHECK_ERRNO(ECONNRESET,
	    notify_publish(client, "test.changed", "first", 5) == -1);
	ATF_CHECK_EQ(0, fake_service_publishes());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0,
	    notify_publish(client, "test.changed", "second", 6));
	ATF_CHECK_EQ(1, fake_service_publishes());
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(2, fake_service_subscriptions());
	fake_service_fail_opcode(NOTIFY_OP_UNSUBSCRIBE);
	ATF_CHECK_ERRNO(ECONNRESET,
	    notify_unsubscribe(client, "test.changed") == -1);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, notify_unsubscribe(client, "test.changed"));
	ATF_CHECK_EQ(3, fake_service_created());
	ATF_CHECK_EQ(3, fake_service_subscriptions());
	notify_client_close(client);
	ATF_CHECK_EQ(3, fake_service_closed());
}

static bool
info_has_topic(const struct notify_subscription_info *info, size_t count,
    const char *name)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (strcmp(info[i].topic, name) == 0)
			return (true);
	return (false);
}

ATF_TC_WITHOUT_HEAD(list_subscriptions_and_timers);
ATF_TC_BODY(list_subscriptions_and_timers, tc)
{
	struct notify_subscription_info subs[8];
	struct notify_timer_info timers[8];
	struct notify_client *client, *other;
	ssize_t count;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	ATF_REQUIRE_EQ(0, notify_client_open(&other));

	/* Empty to start. */
	ATF_CHECK_EQ(0, notify_list_subscriptions(client, subs, nitems(subs)));
	ATF_CHECK_EQ(0, notify_list_timers(client, timers, nitems(timers)));

	ATF_REQUIRE_EQ(0, notify_subscribe(client, "cli.alpha"));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "cli.beta"));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "cli.gamma"));
	/* A second, independent client subscribes to its own topic. */
	ATF_REQUIRE_EQ(0, notify_subscribe(other, "other.secret"));

	count = notify_list_subscriptions(client, subs, nitems(subs));
	ATF_REQUIRE_EQ(3, count);
	ATF_CHECK(info_has_topic(subs, count, "cli.alpha"));
	ATF_CHECK(info_has_topic(subs, count, "cli.beta"));
	ATF_CHECK(info_has_topic(subs, count, "cli.gamma"));
	/* Cross-session isolation: never another client's subscription. */
	ATF_CHECK(!info_has_topic(subs, count, "other.secret"));

	/* Unsubscription is reflected. */
	ATF_REQUIRE_EQ(0, notify_unsubscribe(client, "cli.beta"));
	count = notify_list_subscriptions(client, subs, nitems(subs));
	ATF_REQUIRE_EQ(2, count);
	ATF_CHECK(!info_has_topic(subs, count, "cli.beta"));

	/* Timers, likewise scoped to the calling session. */
	ATF_REQUIRE_EQ(0, notify_timer_add(client, 100, 250, 0));
	ATF_REQUIRE_EQ(0, notify_timer_add(client, 200, 500,
	    NOTIFY_TIMER_F_PERIODIC));
	count = notify_list_timers(client, timers, nitems(timers));
	ATF_REQUIRE_EQ(2, count);
	for (ssize_t i = 0; i < count; i++) {
		if (timers[i].timer_id == 100) {
			ATF_CHECK_EQ(250, timers[i].interval_ms);
			ATF_CHECK_EQ(0, timers[i].flags);
		} else {
			ATF_CHECK_EQ(200, timers[i].timer_id);
			ATF_CHECK_EQ(500, timers[i].interval_ms);
			ATF_CHECK_EQ(NOTIFY_TIMER_F_PERIODIC, timers[i].flags);
		}
	}
	ATF_CHECK_EQ(0, notify_list_timers(other, timers, nitems(timers)));

	ATF_REQUIRE_EQ(0, notify_timer_cancel(client, 100));
	count = notify_list_timers(client, timers, nitems(timers));
	ATF_REQUIRE_EQ(1, count);
	ATF_CHECK_EQ(200, timers[0].timer_id);

	notify_client_close(client);
	notify_client_close(other);
}

ATF_TC_WITHOUT_HEAD(list_subscriptions_paginate_and_truncate);
ATF_TC_BODY(list_subscriptions_paginate_and_truncate, tc)
{
	enum { COUNT = NOTIFY_LIST_MAX_ENTRIES + 7 };
	struct notify_subscription_info subs[COUNT];
	struct notify_client *client;
	char name[NOTIFY_MAX_TOPIC + 1];
	ssize_t count;
	size_t i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notify_client_open(&client));
	for (i = 0; i < COUNT; i++) {
		(void)snprintf(name, sizeof(name), "cli.p%02zu", i);
		ATF_REQUIRE_EQ(0, notify_subscribe(client, name));
	}
	/* Full enumeration reassembles every page. */
	count = notify_list_subscriptions(client, subs, COUNT);
	ATF_REQUIRE_EQ((ssize_t)COUNT, count);
	for (i = 0; i < COUNT; i++) {
		(void)snprintf(name, sizeof(name), "cli.p%02zu", i);
		ATF_CHECK(info_has_topic(subs, count, name));
	}
	/* Truncation: return value reports the true total, past capacity. */
	count = notify_list_subscriptions(client, subs, 5);
	ATF_CHECK_EQ((ssize_t)COUNT, count);
	/* A pure count query (NULL buffer, zero capacity) is allowed. */
	count = notify_list_subscriptions(client, NULL, 0);
	ATF_CHECK_EQ((ssize_t)COUNT, count);
	/* But a NULL buffer with nonzero capacity is rejected. */
	ATF_CHECK_ERRNO(EINVAL,
	    notify_list_subscriptions(client, NULL, 5) == -1);

	notify_client_close(client);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, independent_concurrent_clients);
	ATF_TP_ADD_TC(tp, binary_payload_and_same_client_serialization);
	ATF_TP_ADD_TC(tp, peer_death_reconnect_and_replay);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_client);
	ATF_TP_ADD_TC(tp, open_failure_is_retryable);
	ATF_TP_ADD_TC(tp, malformed_replies_invalidate_session);
	ATF_TP_ADD_TC(tp, non_event_peer_death_recovers_without_replay);
	ATF_TP_ADD_TC(tp, list_subscriptions_and_timers);
	ATF_TP_ADD_TC(tp, list_subscriptions_paginate_and_truncate);
	return (atf_no_error());
}
