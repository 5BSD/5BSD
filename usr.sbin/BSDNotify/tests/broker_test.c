/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "broker.h"

union event_buffer {
	max_align_t align;
	uint8_t bytes[NOTIFY_MAX_MESSAGE];
};

static const char *
event_publisher(const struct notify_event *event)
{

	return ((const char *)event->data);
}

static const char *
event_topic(const struct notify_event *event)
{

	return ((const char *)event->data + event->publisher_length);
}

static const void *
event_payload(const struct notify_event *event)
{

	return (event->data + event->publisher_length + event->topic_length);
}

ATF_TC_WITHOUT_HEAD(route_and_identity);
ATF_TC_BODY(route_and_identity, tc)
{
	struct notify_broker_client *publisher, *subscriber, *unrelated;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;
	ssize_t length;

	broker = notify_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "publisher", 4);
	subscriber = notify_broker_add(broker, "subscriber", 4);
	unrelated = notify_broker_add(broker, "unrelated", 4);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL &&
	    unrelated != NULL);
	ATF_REQUIRE_EQ(notify_broker_subscribe(broker, subscriber,
	    "system.ready", 12), 0);
	ATF_REQUIRE_EQ(notify_broker_publish(broker, publisher,
	    "system.ready", 12, "ok", 2), 0);
	length = notify_broker_next(subscriber, event, sizeof(buffer));
	ATF_REQUIRE(length > 0);
	ATF_CHECK_EQ(event->type, NOTIFY_EVENT_PUBLISH);
	ATF_CHECK_EQ(event->publisher_length, strlen("publisher"));
	ATF_CHECK_EQ(memcmp(event_publisher(event), "publisher",
	    event->publisher_length), 0);
	ATF_CHECK_EQ(memcmp(event_topic(event), "system.ready",
	    event->topic_length), 0);
	ATF_CHECK_EQ(memcmp(event_payload(event), "ok", 2), 0);
	ATF_CHECK_EQ(notify_broker_next(unrelated, event, sizeof(buffer)),
	    -1);
	ATF_CHECK_EQ(errno, EAGAIN);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(queue_pressure);
ATF_TC_BODY(queue_pressure, tc)
{
	struct notify_broker_client *publisher, *subscriber;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;
	struct notify_stats stats;
	unsigned int i, value;

	broker = notify_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "publisher", 2);
	subscriber = notify_broker_add(broker, "subscriber", 2);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL);
	ATF_REQUIRE_EQ(notify_broker_subscribe(broker, subscriber,
	    "pressure", 8), 0);
	for (i = 0; i < 5; i++)
		ATF_REQUIRE_EQ(notify_broker_publish(broker, publisher,
		    "pressure", 8, &i, sizeof(i)), 0);
	notify_broker_stats(subscriber, &stats);
	ATF_CHECK_EQ(stats.delivered, 2);
	ATF_CHECK_EQ(stats.dropped, 3);
	ATF_REQUIRE(notify_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	ATF_CHECK_EQ(event->type, NOTIFY_EVENT_GAP);
	ATF_CHECK_EQ(event->lost_count, 3);
	ATF_CHECK_EQ(event->router_epoch, notify_broker_epoch(broker));
	ATF_REQUIRE(notify_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	memcpy(&value, event_payload(event), sizeof(value));
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE(notify_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	memcpy(&value, event_payload(event), sizeof(value));
	ATF_CHECK_EQ(value, 1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(binary_payload_bounds_and_subscriber_isolation);
ATF_TC_BODY(binary_payload_bounds_and_subscriber_isolation, tc)
{
	struct notify_broker_client *publisher, *slow, *healthy;
	struct notify_broker *broker;
	uint8_t payload[NOTIFY_MAX_PAYLOAD + 1];
	union event_buffer buffer;
	struct notify_event *event;
	struct notify_stats stats;
	ssize_t length;
	size_t i;

	for (i = 0; i < NOTIFY_MAX_PAYLOAD; i++)
		payload[i] = (uint8_t)(i * 37U);
	broker = notify_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "binary.publisher", 2);
	slow = notify_broker_add(broker, "slow.subscriber", 1);
	healthy = notify_broker_add(broker, "healthy.subscriber", 4);
	ATF_REQUIRE(publisher != NULL && slow != NULL && healthy != NULL);
	ATF_REQUIRE_EQ(0, notify_broker_subscribe(broker, slow,
	    "binary.data", 11));
	ATF_REQUIRE_EQ(0, notify_broker_subscribe(broker, healthy,
	    "binary.data", 11));

	ATF_REQUIRE_EQ(0, notify_broker_publish(broker, publisher,
	    "binary.data", 11, payload, NOTIFY_MAX_PAYLOAD));
	ATF_REQUIRE_EQ(0, notify_broker_publish(broker, publisher,
	    "binary.data", 11, "second", 6));
	notify_broker_stats(slow, &stats);
	ATF_CHECK_EQ(1, stats.delivered);
	ATF_CHECK_EQ(1, stats.dropped);
	notify_broker_stats(healthy, &stats);
	ATF_CHECK_EQ(2, stats.delivered);
	ATF_CHECK_EQ(0, stats.dropped);

	/* Queue loss is local: the healthy subscriber receives both events. */
	length = notify_broker_next(healthy, event, sizeof(buffer));
	ATF_REQUIRE(length > 0);
	ATF_CHECK_EQ(NOTIFY_MAX_PAYLOAD, event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event_payload(event), payload,
	    NOTIFY_MAX_PAYLOAD));
	ATF_REQUIRE(notify_broker_next(healthy, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(6, event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event_payload(event), "second", 6));

	/* The slow subscriber gets an exact loss report, then retained data. */
	ATF_REQUIRE(notify_broker_next(slow, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(NOTIFY_EVENT_GAP, event->type);
	ATF_CHECK_EQ(1, event->lost_count);
	length = notify_broker_next(slow, event, sizeof(buffer));
	ATF_REQUIRE(length > 0);
	ATF_CHECK_EQ(NOTIFY_MAX_PAYLOAD, event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event_payload(event), payload,
	    NOTIFY_MAX_PAYLOAD));

	ATF_CHECK_ERRNO(EINVAL, notify_broker_publish(broker, publisher,
	    "binary.data", 11, payload, sizeof(payload)) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_broker_publish(broker, publisher,
	    "binary.data", 11, NULL, 1) == -1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(state_and_generation);
ATF_TC_BODY(state_and_generation, tc)
{
	struct notify_broker_client *publisher, *subscriber;
	struct notify_state_reply state;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	ATF_REQUIRE(notify_broker_epoch(broker) != 0);
	publisher = notify_broker_add(broker, "publisher", 4);
	subscriber = notify_broker_add(broker, "subscriber", 4);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL);
	ATF_REQUIRE_EQ(notify_broker_subscribe(broker, subscriber,
	    "system.state", 12), 0);
	ATF_REQUIRE_EQ(notify_broker_state_set(broker, publisher,
	    "system.state", 12, 41, &state), 0);
	ATF_CHECK_EQ(state.router_epoch, notify_broker_epoch(broker));
	ATF_CHECK_EQ(state.generation, 1);
	ATF_CHECK_EQ(state.state, 41);
	ATF_REQUIRE_EQ(notify_broker_state_set(broker, publisher,
	    "system.state", 12, 42, &state), 0);
	ATF_CHECK_EQ(state.generation, 2);
	ATF_REQUIRE_EQ(notify_broker_state_get(broker, "system.state", 12,
	    &state), 0);
	ATF_CHECK_EQ(state.generation, 2);
	ATF_CHECK_EQ(state.state, 42);
	event = (void *)buffer.bytes;
	ATF_REQUIRE(notify_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	ATF_CHECK_EQ(event->type, NOTIFY_EVENT_STATE);
	ATF_CHECK_EQ(event->generation, 1);
	ATF_CHECK_EQ(event->state, 41);
	ATF_CHECK_ERRNO(ENOENT, notify_broker_state_get(broker, "missing",
	    7, &state) == -1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(state_bound);
ATF_TC_BODY(state_bound, tc)
{
	struct notify_broker_client *publisher;
	struct notify_state_reply state;
	struct notify_broker *broker;
	char topic[32];
	unsigned int i;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "publisher", 1);
	ATF_REQUIRE(publisher != NULL);
	for (i = 0; i < NOTIFY_MAX_STATES; i++) {
		snprintf(topic, sizeof(topic), "state.t%u", i);
		ATF_REQUIRE_EQ(notify_broker_state_set(broker, publisher,
		    topic, strlen(topic), i, &state), 0);
	}
	ATF_CHECK_ERRNO(ENOSPC, notify_broker_state_set(broker, publisher,
	    "state.overflow", 14, 1, &state) == -1);
	ATF_REQUIRE_EQ(notify_broker_state_set(broker, publisher,
	    "state.t0", 8, 99, &state), 0);
	ATF_CHECK_EQ(state.generation, 2);
	ATF_CHECK_EQ(state.state, 99);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(subscriptions);
ATF_TC_BODY(subscriptions, tc)
{
	struct notify_broker_client *client;
	struct notify_broker *broker;
	char topic[32];
	unsigned int i;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	client = notify_broker_add(broker, "client", 2);
	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE_EQ(notify_broker_subscribe(broker, client,
	    "duplicate", 9), 0);
	ATF_CHECK_EQ(notify_broker_subscribe(broker, client,
	    "duplicate", 9), -1);
	ATF_CHECK_EQ(errno, EEXIST);
	ATF_REQUIRE_EQ(notify_broker_unsubscribe(broker, client,
	    "duplicate", 9), 0);
	ATF_CHECK_EQ(notify_broker_unsubscribe(broker, client,
	    "duplicate", 9), -1);
	ATF_CHECK_EQ(errno, ENOENT);
	for (i = 0; i < NOTIFY_MAX_SUBSCRIPTIONS; i++) {
		snprintf(topic, sizeof(topic), "topic.t%u", i);
		ATF_REQUIRE_EQ(notify_broker_subscribe(broker, client, topic,
		    strlen(topic)), 0);
	}
	ATF_CHECK_EQ(notify_broker_subscribe(broker, client, "overflow",
	    8), -1);
	ATF_CHECK_EQ(errno, ENOSPC);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(timer_and_cleanup);
ATF_TC_BODY(timer_and_cleanup, tc)
{
	struct notify_broker_client *client;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;

	broker = notify_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	client = notify_broker_add(broker, "timer-owner", 4);
	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE_EQ(notify_broker_timer(broker, client, 42), 0);
	ATF_REQUIRE(notify_broker_next(client, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(event->type, NOTIFY_EVENT_TIMER);
	ATF_CHECK_EQ(event->timer_id, 42);
	ATF_CHECK_EQ(event->topic_length, 0);
	ATF_CHECK_EQ(event->payload_length, 0);
	notify_broker_remove(broker, client);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(fanout_and_churn);
ATF_TC_BODY(fanout_and_churn, tc)
{
	enum { CLIENTS = 512, ROUNDS = 32 };
	struct notify_broker_client *clients[CLIENTS], *publisher, *churn;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;
	uint64_t sequence;
	unsigned int i, round;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "publisher", 4);
	ATF_REQUIRE(publisher != NULL);
	for (i = 0; i < CLIENTS; i++) {
		clients[i] = notify_broker_add(broker, "subscriber", 2);
		ATF_REQUIRE(clients[i] != NULL);
		ATF_REQUIRE_EQ(notify_broker_subscribe(broker, clients[i],
		    "fanout.event", 12), 0);
	}
	ATF_REQUIRE_EQ(notify_broker_publish(broker, publisher,
	    "fanout.event", 12, "x", 1), 0);
	event = (void *)buffer.bytes;
	sequence = 0;
	for (i = 0; i < CLIENTS; i++) {
		ATF_REQUIRE(notify_broker_next(clients[i], event,
		    sizeof(buffer)) > 0);
		if (i == 0)
			sequence = event->sequence;
		ATF_CHECK_EQ(event->sequence, sequence);
	}
	for (round = 0; round < ROUNDS; round++) {
		churn = notify_broker_add(broker, "churn", 1);
		ATF_REQUIRE(churn != NULL);
		ATF_REQUIRE_EQ(notify_broker_subscribe(broker, churn,
		    "fanout.event", 12), 0);
		ATF_REQUIRE_EQ(notify_broker_publish(broker, publisher,
		    "fanout.event", 12, &round, sizeof(round)), 0);
		notify_broker_remove(broker, churn);
		ATF_REQUIRE(notify_broker_next(clients[0], event,
		    sizeof(buffer)) > 0);
	}
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(sequence_exhaustion);
ATF_TC_BODY(sequence_exhaustion, tc)
{
	struct notify_broker_client *publisher, *subscriber;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	publisher = notify_broker_add(broker, "publisher", 2);
	subscriber = notify_broker_add(broker, "subscriber", 2);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL);
	ATF_REQUIRE_EQ(0, notify_broker_subscribe(broker, subscriber,
	    "sequence.test", 13));
	notify_broker_test_set_sequence(broker, UINT64_MAX - 1);
	ATF_REQUIRE_EQ(0, notify_broker_publish(broker, publisher,
	    "sequence.test", 13, NULL, 0));
	event = (void *)buffer.bytes;
	ATF_REQUIRE(notify_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	ATF_CHECK_EQ(UINT64_MAX, event->sequence);
	ATF_CHECK_ERRNO(EOVERFLOW, notify_broker_publish(broker, publisher,
	    "sequence.test", 13, NULL, 0) == -1);
	ATF_CHECK_ERRNO(EAGAIN, notify_broker_next(subscriber, event,
	    sizeof(buffer)) == -1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(state_clear_is_owner_scoped);
ATF_TC_BODY(state_clear_is_owner_scoped, tc)
{
	struct notify_broker_client *owner, *other;
	struct notify_state_reply state;
	struct notify_broker *broker;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	owner = notify_broker_add(broker, "org.a", 4);
	other = notify_broker_add(broker, "org.b", 4);
	ATF_REQUIRE(owner != NULL && other != NULL);

	/* org.a establishes the state; ownership is stamped server-side. */
	ATF_REQUIRE_EQ(0, notify_broker_state_set(broker, owner, "svc.state",
	    9, 7, &state));

	/* A different label may not clear a state it does not own. */
	ATF_CHECK_ERRNO(EACCES, notify_broker_state_clear(broker, other,
	    "svc.state", 9) == -1);
	/* The denied clear leaves the state present and unchanged. */
	ATF_REQUIRE_EQ(0, notify_broker_state_get(broker, "svc.state", 9,
	    &state));
	ATF_CHECK_EQ(7, state.state);

	/* The owning label clears it, and the state is gone. */
	ATF_REQUIRE_EQ(0, notify_broker_state_clear(broker, owner, "svc.state",
	    9));
	ATF_CHECK_ERRNO(ENOENT, notify_broker_state_get(broker, "svc.state", 9,
	    &state) == -1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(states_are_evicted_on_last_session_disconnect);
ATF_TC_BODY(states_are_evicted_on_last_session_disconnect, tc)
{
	struct notify_broker_client *first, *second, *bystander;
	struct notify_state_reply state;
	struct notify_broker *broker;

	broker = notify_broker_create();
	ATF_REQUIRE(broker != NULL);
	/* Two sessions share one owning label; a third holds a foreign label. */
	first = notify_broker_add(broker, "org.a", 4);
	second = notify_broker_add(broker, "org.a", 4);
	bystander = notify_broker_add(broker, "org.b", 4);
	ATF_REQUIRE(first != NULL && second != NULL && bystander != NULL);
	ATF_REQUIRE_EQ(0, notify_broker_state_set(broker, first, "svc.up", 6,
	    1, &state));

	/* Dropping one of the label's sessions must not reclaim its state. */
	notify_broker_remove(broker, first);
	ATF_REQUIRE_EQ(0, notify_broker_state_get(broker, "svc.up", 6, &state));
	ATF_CHECK_EQ(1, state.state);

	/* A foreign label disconnecting leaves the state intact as well. */
	notify_broker_remove(broker, bystander);
	ATF_REQUIRE_EQ(0, notify_broker_state_get(broker, "svc.up", 6, &state));

	/* The last session of the owning label going away reclaims the state. */
	notify_broker_remove(broker, second);
	ATF_CHECK_ERRNO(ENOENT, notify_broker_state_get(broker, "svc.up", 6,
	    &state) == -1);
	notify_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(publisher_identity_is_stamped_server_side);
ATF_TC_BODY(publisher_identity_is_stamped_server_side, tc)
{
	struct notify_broker_client *alpha, *beta, *subscriber;
	struct notify_broker *broker;
	union event_buffer buffer;
	struct notify_event *event;

	broker = notify_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	alpha = notify_broker_add(broker, "org.alpha", 4);
	beta = notify_broker_add(broker, "org.beta", 4);
	subscriber = notify_broker_add(broker, "subscriber", 4);
	ATF_REQUIRE(alpha != NULL && beta != NULL && subscriber != NULL);
	ATF_REQUIRE_EQ(0, notify_broker_subscribe(broker, subscriber,
	    "shared.topic", 12));

	/*
	 * The publisher is taken from the unforgeable session label, never
	 * from caller-controlled payload: org.alpha publishing a payload that
	 * spells "org.beta" is still attributed to org.alpha.
	 */
	ATF_REQUIRE_EQ(0, notify_broker_publish(broker, alpha, "shared.topic",
	    12, "org.beta", 8));
	ATF_REQUIRE(notify_broker_next(subscriber, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(strlen("org.alpha"), event->publisher_length);
	ATF_CHECK_EQ(0, memcmp(event_publisher(event), "org.alpha",
	    event->publisher_length));

	/* A second publisher's events carry its own label, not the first's. */
	ATF_REQUIRE_EQ(0, notify_broker_publish(broker, beta, "shared.topic",
	    12, "x", 1));
	ATF_REQUIRE(notify_broker_next(subscriber, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(strlen("org.beta"), event->publisher_length);
	ATF_CHECK_EQ(0, memcmp(event_publisher(event), "org.beta",
	    event->publisher_length));
	notify_broker_destroy(broker);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, route_and_identity);
	ATF_TP_ADD_TC(tp, queue_pressure);
	ATF_TP_ADD_TC(tp, binary_payload_bounds_and_subscriber_isolation);
	ATF_TP_ADD_TC(tp, state_and_generation);
	ATF_TP_ADD_TC(tp, state_bound);
	ATF_TP_ADD_TC(tp, subscriptions);
	ATF_TP_ADD_TC(tp, timer_and_cleanup);
	ATF_TP_ADD_TC(tp, fanout_and_churn);
	ATF_TP_ADD_TC(tp, sequence_exhaustion);
	ATF_TP_ADD_TC(tp, state_clear_is_owner_scoped);
	ATF_TP_ADD_TC(tp, states_are_evicted_on_last_session_disconnect);
	ATF_TP_ADD_TC(tp, publisher_identity_is_stamped_server_side);
	return (atf_no_error());
}
