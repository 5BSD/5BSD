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
	uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
};

static const char *
event_publisher(const struct notifycmp_event *event)
{

	return ((const char *)event->data);
}

static const char *
event_topic(const struct notifycmp_event *event)
{

	return ((const char *)event->data + event->publisher_length);
}

static const void *
event_payload(const struct notifycmp_event *event)
{

	return (event->data + event->publisher_length + event->topic_length);
}

ATF_TC_WITHOUT_HEAD(route_and_identity);
ATF_TC_BODY(route_and_identity, tc)
{
	struct notifycmp_broker_client *publisher, *subscriber, *unrelated;
	struct notifycmp_broker *broker;
	union event_buffer buffer;
	struct notifycmp_event *event;
	ssize_t length;

	broker = notifycmp_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	publisher = notifycmp_broker_add(broker, "publisher", 4);
	subscriber = notifycmp_broker_add(broker, "subscriber", 4);
	unrelated = notifycmp_broker_add(broker, "unrelated", 4);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL &&
	    unrelated != NULL);
	ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, subscriber,
	    "system.ready", 12), 0);
	ATF_REQUIRE_EQ(notifycmp_broker_publish(broker, publisher,
	    "system.ready", 12, "ok", 2), 0);
	length = notifycmp_broker_next(subscriber, event, sizeof(buffer));
	ATF_REQUIRE(length > 0);
	ATF_CHECK_EQ(event->type, NOTIFYCMP_EVENT_PUBLISH);
	ATF_CHECK_EQ(event->publisher_length, strlen("publisher"));
	ATF_CHECK_EQ(memcmp(event_publisher(event), "publisher",
	    event->publisher_length), 0);
	ATF_CHECK_EQ(memcmp(event_topic(event), "system.ready",
	    event->topic_length), 0);
	ATF_CHECK_EQ(memcmp(event_payload(event), "ok", 2), 0);
	ATF_CHECK_EQ(notifycmp_broker_next(unrelated, event, sizeof(buffer)),
	    -1);
	ATF_CHECK_EQ(errno, EAGAIN);
	notifycmp_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(queue_pressure);
ATF_TC_BODY(queue_pressure, tc)
{
	struct notifycmp_broker_client *publisher, *subscriber;
	struct notifycmp_broker *broker;
	union event_buffer buffer;
	struct notifycmp_event *event;
	struct notifycmp_stats stats;
	unsigned int i, value;

	broker = notifycmp_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	publisher = notifycmp_broker_add(broker, "publisher", 2);
	subscriber = notifycmp_broker_add(broker, "subscriber", 2);
	ATF_REQUIRE(publisher != NULL && subscriber != NULL);
	ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, subscriber,
	    "pressure", 8), 0);
	for (i = 0; i < 5; i++)
		ATF_REQUIRE_EQ(notifycmp_broker_publish(broker, publisher,
		    "pressure", 8, &i, sizeof(i)), 0);
	notifycmp_broker_stats(subscriber, &stats);
	ATF_CHECK_EQ(stats.delivered, 2);
	ATF_CHECK_EQ(stats.dropped, 3);
	ATF_REQUIRE(notifycmp_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	memcpy(&value, event_payload(event), sizeof(value));
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE(notifycmp_broker_next(subscriber, event,
	    sizeof(buffer)) > 0);
	memcpy(&value, event_payload(event), sizeof(value));
	ATF_CHECK_EQ(value, 1);
	notifycmp_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(subscriptions);
ATF_TC_BODY(subscriptions, tc)
{
	struct notifycmp_broker_client *client;
	struct notifycmp_broker *broker;
	char topic[32];
	unsigned int i;

	broker = notifycmp_broker_create();
	ATF_REQUIRE(broker != NULL);
	client = notifycmp_broker_add(broker, "client", 2);
	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, client,
	    "duplicate", 9), 0);
	ATF_CHECK_EQ(notifycmp_broker_subscribe(broker, client,
	    "duplicate", 9), -1);
	ATF_CHECK_EQ(errno, EEXIST);
	ATF_REQUIRE_EQ(notifycmp_broker_unsubscribe(broker, client,
	    "duplicate", 9), 0);
	ATF_CHECK_EQ(notifycmp_broker_unsubscribe(broker, client,
	    "duplicate", 9), -1);
	ATF_CHECK_EQ(errno, ENOENT);
	for (i = 0; i < NOTIFYCMP_MAX_SUBSCRIPTIONS; i++) {
		snprintf(topic, sizeof(topic), "topic.t%u", i);
		ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, client, topic,
		    strlen(topic)), 0);
	}
	ATF_CHECK_EQ(notifycmp_broker_subscribe(broker, client, "overflow",
	    8), -1);
	ATF_CHECK_EQ(errno, ENOSPC);
	notifycmp_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(timer_and_cleanup);
ATF_TC_BODY(timer_and_cleanup, tc)
{
	struct notifycmp_broker_client *client;
	struct notifycmp_broker *broker;
	union event_buffer buffer;
	struct notifycmp_event *event;

	broker = notifycmp_broker_create();
	event = (void *)buffer.bytes;
	ATF_REQUIRE(broker != NULL);
	client = notifycmp_broker_add(broker, "timer-owner", 4);
	ATF_REQUIRE(client != NULL);
	ATF_REQUIRE_EQ(notifycmp_broker_timer(broker, client, 42), 0);
	ATF_REQUIRE(notifycmp_broker_next(client, event, sizeof(buffer)) > 0);
	ATF_CHECK_EQ(event->type, NOTIFYCMP_EVENT_TIMER);
	ATF_CHECK_EQ(event->timer_id, 42);
	ATF_CHECK_EQ(event->topic_length, 0);
	ATF_CHECK_EQ(event->payload_length, 0);
	notifycmp_broker_remove(broker, client);
	notifycmp_broker_destroy(broker);
}

ATF_TC_WITHOUT_HEAD(fanout_and_churn);
ATF_TC_BODY(fanout_and_churn, tc)
{
	enum { CLIENTS = 512, ROUNDS = 32 };
	struct notifycmp_broker_client *clients[CLIENTS], *publisher, *churn;
	struct notifycmp_broker *broker;
	union event_buffer buffer;
	struct notifycmp_event *event;
	uint64_t sequence;
	unsigned int i, round;

	broker = notifycmp_broker_create();
	ATF_REQUIRE(broker != NULL);
	publisher = notifycmp_broker_add(broker, "publisher", 4);
	ATF_REQUIRE(publisher != NULL);
	for (i = 0; i < CLIENTS; i++) {
		clients[i] = notifycmp_broker_add(broker, "subscriber", 2);
		ATF_REQUIRE(clients[i] != NULL);
		ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, clients[i],
		    "fanout.event", 12), 0);
	}
	ATF_REQUIRE_EQ(notifycmp_broker_publish(broker, publisher,
	    "fanout.event", 12, "x", 1), 0);
	event = (void *)buffer.bytes;
	sequence = 0;
	for (i = 0; i < CLIENTS; i++) {
		ATF_REQUIRE(notifycmp_broker_next(clients[i], event,
		    sizeof(buffer)) > 0);
		if (i == 0)
			sequence = event->sequence;
		ATF_CHECK_EQ(event->sequence, sequence);
	}
	for (round = 0; round < ROUNDS; round++) {
		churn = notifycmp_broker_add(broker, "churn", 1);
		ATF_REQUIRE(churn != NULL);
		ATF_REQUIRE_EQ(notifycmp_broker_subscribe(broker, churn,
		    "fanout.event", 12), 0);
		ATF_REQUIRE_EQ(notifycmp_broker_publish(broker, publisher,
		    "fanout.event", 12, &round, sizeof(round)), 0);
		notifycmp_broker_remove(broker, churn);
		ATF_REQUIRE(notifycmp_broker_next(clients[0], event,
		    sizeof(buffer)) > 0);
	}
	notifycmp_broker_destroy(broker);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, route_and_identity);
	ATF_TP_ADD_TC(tp, queue_pressure);
	ATF_TP_ADD_TC(tp, subscriptions);
	ATF_TP_ADD_TC(tp, timer_and_cleanup);
	ATF_TP_ADD_TC(tp, fanout_and_churn);
	return (atf_no_error());
}
