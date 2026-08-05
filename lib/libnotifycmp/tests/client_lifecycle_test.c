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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <notifycmp.h>

#include "fake_service.h"

struct publish_argument {
	struct notifycmp_client *client;
	atomic_uint		*completion;
	unsigned		 rank;
	int			 result;
};

static void *
publish_thread(void *argument)
{
	struct publish_argument *publish = argument;

	publish->result = notifycmp_publish(publish->client, "test.concurrent",
	    "x", 1);
	publish->rank = atomic_fetch_add(publish->completion, 1);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_concurrent_clients);
ATF_TC_BODY(independent_concurrent_clients, tc)
{
	struct notifycmp_client *first, *second, *third;
	struct publish_argument arguments[2];
	atomic_uint completion;
	pthread_t threads[2];

	fake_service_reset();
	atomic_init(&completion, 0);
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&first));
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&second));
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
	notifycmp_client_close(first);
	notifycmp_client_close(second);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&third));
	ATF_CHECK_EQ(3, fake_service_created());
	notifycmp_client_close(third);
	ATF_CHECK_EQ(3, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(binary_payload_and_same_client_serialization);
ATF_TC_BODY(binary_payload_and_same_client_serialization, tc)
{
	enum { THREADS = 8 };
	struct publish_argument arguments[THREADS];
	uint8_t expected[NOTIFYCMP_MAX_PAYLOAD];
	uint8_t actual[NOTIFYCMP_MAX_PAYLOAD];
	struct notifycmp_client *client;
	atomic_uint completion;
	pthread_t threads[THREADS];
	size_t i;

	fake_service_reset();
	for (i = 0; i < sizeof(expected); i++)
		expected[i] = (uint8_t)(i * 43U);
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	ATF_REQUIRE_EQ(0, notifycmp_publish(client, "test.binary", expected,
	    sizeof(expected)));
	ATF_REQUIRE_EQ(sizeof(expected),
	    fake_service_last_payload(actual, sizeof(actual)));
	ATF_CHECK_EQ(0, memcmp(expected, actual, sizeof(expected)));
	ATF_CHECK_ERRNO(EINVAL, notifycmp_publish(client, "test.binary",
	    expected, sizeof(expected) + 1) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notifycmp_publish(client, "test.binary", NULL, 1) == -1);
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
	notifycmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(peer_death_reconnect_and_replay);
ATF_TC_BODY(peer_death_reconnect_and_replay, tc)
{
	struct notifycmp_event event;
	struct notifycmp_client *client;
	ssize_t length;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	ATF_REQUIRE_EQ(0, notifycmp_subscribe(client, "test.changed"));
	ATF_CHECK_EQ(1, fake_service_subscriptions());
	fake_service_fail_next();
	length = notifycmp_next(client, &event, sizeof(event), 100);
	ATF_REQUIRE_EQ(sizeof(event), length);
	ATF_CHECK_EQ(NOTIFYCMP_EVENT_RESET, event.type);
	ATF_CHECK(event.router_epoch != 0);
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_CHECK_EQ(2, fake_service_subscriptions());
	notifycmp_client_close(client);
	ATF_CHECK_EQ(2, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(fork_rejects_inherited_client);
ATF_TC_BODY(fork_rejects_inherited_client, tc)
{
	struct notifycmp_client *client;
	int status;
	pid_t pid;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct notifycmp_client *fresh;

		if (notifycmp_publish(client, "test.child", NULL, 0) != -1 ||
		    errno != EINVAL)
			_exit(1);
		if (notifycmp_client_open(&fresh) == -1)
			_exit(2);
		notifycmp_client_close(fresh);
		notifycmp_client_close(client);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0,
	    notifycmp_publish(client, "test.parent", NULL, 0));
	notifycmp_client_close(client);
}

ATF_TC_WITHOUT_HEAD(open_failure_is_retryable);
ATF_TC_BODY(open_failure_is_retryable, tc)
{
	struct notifycmp_client *client;

	fake_service_reset();
	fake_service_fault_next(FAKE_SERVICE_FAULT_INVALID_HELLO);
	ATF_CHECK_ERRNO(EPROTO, notifycmp_client_open(&client) == -1);
	ATF_CHECK_EQ(1, fake_service_created());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	ATF_CHECK_EQ(2, fake_service_created());
	notifycmp_client_close(client);
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
	struct notifycmp_client *client;
	struct notifycmp_state_reply state;
	struct notifycmp_stats stats;
	unsigned i;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	ATF_REQUIRE_EQ(0, notifycmp_subscribe(client, "test.changed"));
	for (i = 0; i < nitems(protocol_faults); i++) {
		fake_service_fault_next(protocol_faults[i]);
		ATF_CHECK_ERRNO(EPROTO, notifycmp_stats(client, &stats) == -1);
		ATF_CHECK_EQ(i + 1, fake_service_closed());
		ATF_REQUIRE_EQ(0, notifycmp_stats(client, &stats));
		ATF_CHECK_EQ(i + 2, fake_service_created());
	}
	ATF_CHECK_EQ(4, fake_service_subscriptions());
	fake_service_fault_next(FAKE_SERVICE_FAULT_INVALID_STATE);
	ATF_CHECK_ERRNO(EPROTO, notifycmp_state_get(client, "test.changed",
	    &state) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_stats(client, &stats));
	ATF_CHECK_EQ(5, fake_service_created());
	fake_service_fault_next(FAKE_SERVICE_FAULT_STATUS);
	ATF_CHECK_ERRNO(EPERM, notifycmp_stats(client, &stats) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_stats(client, &stats));
	fake_service_fault_next(FAKE_SERVICE_FAULT_TIMEOUT);
	ATF_CHECK_ERRNO(ETIMEDOUT, notifycmp_stats(client, &stats) == -1);
	ATF_CHECK_EQ(4, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_stats(client, &stats));
	notifycmp_client_close(client);
	ATF_CHECK_EQ(5, fake_service_closed());
}

ATF_TC_WITHOUT_HEAD(non_event_peer_death_recovers_without_replay);
ATF_TC_BODY(non_event_peer_death_recovers_without_replay, tc)
{
	struct notifycmp_client *client;

	fake_service_reset();
	ATF_REQUIRE_EQ(0, notifycmp_client_open(&client));
	ATF_REQUIRE_EQ(0, notifycmp_subscribe(client, "test.changed"));
	fake_service_fail_opcode(NOTIFYCMP_OP_PUBLISH);
	ATF_CHECK_ERRNO(ECONNRESET,
	    notifycmp_publish(client, "test.changed", "first", 5) == -1);
	ATF_CHECK_EQ(0, fake_service_publishes());
	ATF_CHECK_EQ(1, fake_service_closed());
	ATF_REQUIRE_EQ(0,
	    notifycmp_publish(client, "test.changed", "second", 6));
	ATF_CHECK_EQ(1, fake_service_publishes());
	ATF_CHECK_EQ(2, fake_service_created());
	ATF_CHECK_EQ(2, fake_service_subscriptions());
	fake_service_fail_opcode(NOTIFYCMP_OP_UNSUBSCRIBE);
	ATF_CHECK_ERRNO(ECONNRESET,
	    notifycmp_unsubscribe(client, "test.changed") == -1);
	ATF_CHECK_EQ(2, fake_service_closed());
	ATF_REQUIRE_EQ(0, notifycmp_unsubscribe(client, "test.changed"));
	ATF_CHECK_EQ(3, fake_service_created());
	ATF_CHECK_EQ(3, fake_service_subscriptions());
	notifycmp_client_close(client);
	ATF_CHECK_EQ(3, fake_service_closed());
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
	return (atf_no_error());
}
