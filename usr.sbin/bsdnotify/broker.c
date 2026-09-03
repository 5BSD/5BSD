/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "broker.h"

#define	NOTIFY_TOPIC_BUCKETS	257

struct broker_event {
	size_t		length;
	size_t		references;
	struct notify_event event;
};

struct broker_subscription {
	struct broker_subscription	*bucket_next;
	struct broker_subscription	*client_next;
	struct notify_broker_client	*client;
	size_t				 topic_length;
	char				 topic[NOTIFY_MAX_TOPIC];
};

struct notify_broker_client {
	struct notify_broker_client	*next;
	struct broker_subscription	*subscriptions;
	struct broker_event		**queue;
	size_t				 queue_depth;
	size_t				 queue_head;
	size_t				 queue_count;
	size_t				 subscription_count;
	char				 label[NOTIFY_MAX_PUBLISHER + 1];
	struct notify_stats		 stats;
	uint64_t			 lost_pending;
	uint64_t			 epoch;
};

struct broker_topic_state {
	struct broker_topic_state *next;
	size_t			 topic_length;
	uint64_t		 generation;
	uint64_t		 state;
	char			 owner[NOTIFY_MAX_PUBLISHER + 1];
	char			 topic[NOTIFY_MAX_TOPIC];
};

struct notify_broker {
	struct notify_broker_client	*clients;
	struct broker_subscription	*buckets[NOTIFY_TOPIC_BUCKETS];
	uint64_t			 sequence;
	uint64_t			 epoch;
	size_t				 nstates;
	struct broker_topic_state	*states[NOTIFY_TOPIC_BUCKETS];
};

static unsigned int
topic_hash(const char *topic, size_t length)
{
	uint32_t hash;
	size_t i;

	hash = 2166136261U;
	for (i = 0; i < length; i++) {
		hash ^= (unsigned char)topic[i];
		hash *= 16777619U;
	}
	return (hash % NOTIFY_TOPIC_BUCKETS);
}

static void
event_release(struct broker_event *event)
{

	if (--event->references == 0)
		free(event);
}

static struct broker_event *
event_create(struct notify_broker *broker, uint32_t type,
    const char *publisher, const char *topic, size_t topic_length,
    const void *payload, size_t payload_length, uint64_t timer_id)
{
	struct broker_event *event;
	struct timespec now;
	size_t publisher_length, length;
	uint8_t *cursor;

	publisher_length = strlen(publisher);
	if (broker->sequence == UINT64_MAX) {
		errno = EOVERFLOW;
		return (NULL);
	}
	length = sizeof(event->event) + publisher_length + topic_length +
	    payload_length;
	event = calloc(1, offsetof(struct broker_event, event) + length);
	if (event == NULL)
		return (NULL);
	event->length = length;
	event->references = 1;
	event->event.type = type;
	event->event.router_epoch = broker->epoch;
	event->event.sequence = ++broker->sequence;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
		event->event.timestamp_ns = (uint64_t)now.tv_sec *
		    UINT64_C(1000000000) + now.tv_nsec;
	event->event.timer_id = timer_id;
	event->event.publisher_length = publisher_length;
	event->event.topic_length = topic_length;
	event->event.payload_length = payload_length;
	cursor = event->event.data;
	memcpy(cursor, publisher, publisher_length);
	cursor += publisher_length;
	if (topic_length != 0) {
		memcpy(cursor, topic, topic_length);
		cursor += topic_length;
	}
	if (payload_length != 0)
		memcpy(cursor, payload, payload_length);
	return (event);
}

static void
enqueue(struct notify_broker_client *client, struct broker_event *event)
{
	size_t tail;

	if (client->queue_count == client->queue_depth) {
		client->stats.dropped++;
		if (client->lost_pending != UINT64_MAX)
			client->lost_pending++;
		return;
	}
	tail = (client->queue_head + client->queue_count) %
	    client->queue_depth;
	event->references++;
	client->queue[tail] = event;
	client->queue_count++;
	client->stats.delivered++;
}

struct notify_broker *
notify_broker_create(void)
{
	struct notify_broker *broker;

	broker = calloc(1, sizeof(*broker));
	if (broker != NULL) {
		arc4random_buf(&broker->epoch, sizeof(broker->epoch));
		if (broker->epoch == 0)
			broker->epoch = 1;
	}
	return (broker);
}

void
notify_broker_destroy(struct notify_broker *broker)
{
	struct broker_topic_state *state;
	size_t i;

	if (broker == NULL)
		return;
	while (broker->clients != NULL)
		notify_broker_remove(broker, broker->clients);
	for (i = 0; i < nitems(broker->states); i++)
		while ((state = broker->states[i]) != NULL) {
			broker->states[i] = state->next;
			free(state);
		}
	free(broker);
}

uint64_t
notify_broker_epoch(const struct notify_broker *broker)
{

	return (broker != NULL ? broker->epoch : 0);
}

void
notify_broker_test_set_sequence(struct notify_broker *broker,
    uint64_t sequence)
{

	if (broker != NULL)
		broker->sequence = sequence;
}

struct notify_broker_client *
notify_broker_add(struct notify_broker *broker, const char *label,
    size_t queue_depth)
{
	struct notify_broker_client *client;
	size_t label_length;

	if (broker == NULL || label == NULL || queue_depth == 0 ||
	    queue_depth > NOTIFY_DEFAULT_QUEUE) {
		errno = EINVAL;
		return (NULL);
	}
	label_length = strnlen(label, NOTIFY_MAX_PUBLISHER + 1);
	if (label_length == 0 || label_length > NOTIFY_MAX_PUBLISHER) {
		errno = EINVAL;
		return (NULL);
	}
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (NULL);
	client->queue = calloc(queue_depth, sizeof(*client->queue));
	if (client->queue == NULL) {
		free(client);
		return (NULL);
	}
	memcpy(client->label, label, label_length);
	client->queue_depth = queue_depth;
	client->epoch = broker->epoch;
	client->next = broker->clients;
	broker->clients = client;
	return (client);
}

static void
state_unlink(struct notify_broker *broker, struct broker_topic_state *state)
{
	struct broker_topic_state **cursor;

	cursor = &broker->states[topic_hash(state->topic, state->topic_length)];
	while (*cursor != NULL && *cursor != state)
		cursor = &(*cursor)->next;
	if (*cursor == state) {
		*cursor = state->next;
		broker->nstates--;
		free(state);
	}
}

static bool
label_in_use(const struct notify_broker *broker, const char *label,
    const struct notify_broker_client *except)
{
	const struct notify_broker_client *client;

	for (client = broker->clients; client != NULL; client = client->next)
		if (client != except && strcmp(client->label, label) == 0)
			return (true);
	return (false);
}

void
notify_broker_remove(struct notify_broker *broker,
    struct notify_broker_client *client)
{
	struct notify_broker_client **cursor;
	struct broker_subscription **bucket_cursor, *subscription;
	size_t bucket;

	if (broker == NULL || client == NULL)
		return;
	cursor = &broker->clients;
	while (*cursor != NULL && *cursor != client)
		cursor = &(*cursor)->next;
	if (*cursor == client)
		*cursor = client->next;
	/*
	 * Reclaim persistent states owned by this label once its last session
	 * is gone, so a client cannot permanently exhaust the global state
	 * table by setting topics and disconnecting.  States survive as long as
	 * any session sharing the owning label remains connected.
	 */
	if (client->label[0] != '\0' &&
	    !label_in_use(broker, client->label, NULL)) {
		for (bucket = 0; bucket < nitems(broker->states); bucket++) {
			struct broker_topic_state **state_cursor;
			struct broker_topic_state *state;

			state_cursor = &broker->states[bucket];
			while ((state = *state_cursor) != NULL) {
				if (strcmp(state->owner, client->label) == 0) {
					*state_cursor = state->next;
					broker->nstates--;
					free(state);
				} else
					state_cursor = &state->next;
			}
		}
	}
	while ((subscription = client->subscriptions) != NULL) {
		client->subscriptions = subscription->client_next;
		bucket = topic_hash(subscription->topic,
		    subscription->topic_length);
		bucket_cursor = &broker->buckets[bucket];
		while (*bucket_cursor != NULL && *bucket_cursor != subscription)
			bucket_cursor = &(*bucket_cursor)->bucket_next;
		if (*bucket_cursor == subscription)
			*bucket_cursor = subscription->bucket_next;
		free(subscription);
	}
	while (client->queue_count != 0) {
		event_release(client->queue[client->queue_head]);
		client->queue_head = (client->queue_head + 1) %
		    client->queue_depth;
		client->queue_count--;
	}
	free(client->queue);
	memset(client, 0, sizeof(*client));
	free(client);
}

int
notify_broker_subscribe(struct notify_broker *broker,
    struct notify_broker_client *client, const char *topic, size_t length)
{
	struct broker_subscription *subscription;
	unsigned int bucket;

	if (broker == NULL || client == NULL ||
	    notify_validate_topic(topic, length) == -1)
		return (-1);
	for (subscription = client->subscriptions; subscription != NULL;
	    subscription = subscription->client_next)
		if (subscription->topic_length == length &&
		    memcmp(subscription->topic, topic, length) == 0) {
			errno = EEXIST;
			return (-1);
		}
	if (client->subscription_count == NOTIFY_MAX_SUBSCRIPTIONS) {
		errno = ENOSPC;
		return (-1);
	}
	subscription = calloc(1, sizeof(*subscription));
	if (subscription == NULL)
		return (-1);
	subscription->client = client;
	subscription->topic_length = length;
	memcpy(subscription->topic, topic, length);
	bucket = topic_hash(topic, length);
	subscription->bucket_next = broker->buckets[bucket];
	broker->buckets[bucket] = subscription;
	subscription->client_next = client->subscriptions;
	client->subscriptions = subscription;
	client->subscription_count++;
	return (0);
}

int
notify_broker_unsubscribe(struct notify_broker *broker,
    struct notify_broker_client *client, const char *topic, size_t length)
{
	struct broker_subscription **client_cursor, **bucket_cursor;
	struct broker_subscription *subscription;
	unsigned int bucket;

	if (broker == NULL || client == NULL ||
	    notify_validate_topic(topic, length) == -1)
		return (-1);
	client_cursor = &client->subscriptions;
	while (*client_cursor != NULL &&
	    ((*client_cursor)->topic_length != length ||
	    memcmp((*client_cursor)->topic, topic, length) != 0))
		client_cursor = &(*client_cursor)->client_next;
	if (*client_cursor == NULL) {
		errno = ENOENT;
		return (-1);
	}
	subscription = *client_cursor;
	*client_cursor = subscription->client_next;
	bucket = topic_hash(topic, length);
	bucket_cursor = &broker->buckets[bucket];
	while (*bucket_cursor != NULL && *bucket_cursor != subscription)
		bucket_cursor = &(*bucket_cursor)->bucket_next;
	if (*bucket_cursor == subscription)
		*bucket_cursor = subscription->bucket_next;
	client->subscription_count--;
	free(subscription);
	return (0);
}

int
notify_broker_publish(struct notify_broker *broker,
    struct notify_broker_client *publisher, const char *topic,
    size_t topic_length, const void *payload, size_t payload_length)
{
	struct broker_subscription *subscription;
	struct broker_event *event;
	unsigned int bucket;

	if (broker == NULL || publisher == NULL ||
	    notify_validate_topic(topic, topic_length) == -1 ||
	    payload_length > NOTIFY_MAX_PAYLOAD ||
	    (payload_length != 0 && payload == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	event = event_create(broker, NOTIFY_EVENT_PUBLISH, publisher->label,
	    topic, topic_length, payload, payload_length, 0);
	if (event == NULL)
		return (-1);
	bucket = topic_hash(topic, topic_length);
	for (subscription = broker->buckets[bucket]; subscription != NULL;
	    subscription = subscription->bucket_next)
		if (subscription->topic_length == topic_length &&
		    memcmp(subscription->topic, topic, topic_length) == 0)
			enqueue(subscription->client, event);
	publisher->stats.published++;
	event_release(event);
	return (0);
}

static struct broker_topic_state *
state_find(struct notify_broker *broker, const char *topic, size_t length)
{
	struct broker_topic_state *state;

	for (state = broker->states[topic_hash(topic, length)]; state != NULL;
	    state = state->next)
		if (state->topic_length == length &&
		    memcmp(state->topic, topic, length) == 0)
			return (state);
	return (NULL);
}

int
notify_broker_state_set(struct notify_broker *broker,
    struct notify_broker_client *publisher, const char *topic,
    size_t topic_length, uint64_t value, struct notify_state_reply *reply)
{
	struct broker_subscription *subscription;
	struct broker_topic_state *state;
	struct broker_event *event;
	unsigned int bucket;

	if (broker == NULL || publisher == NULL || reply == NULL ||
	    notify_validate_topic(topic, topic_length) == -1)
		return (-1);
	bucket = topic_hash(topic, topic_length);
	state = state_find(broker, topic, topic_length);
	if (state != NULL && state->generation == UINT64_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	if (state == NULL && broker->nstates == NOTIFY_MAX_STATES) {
		errno = ENOSPC;
		return (-1);
	}
	event = event_create(broker, NOTIFY_EVENT_STATE, publisher->label,
	    topic, topic_length, NULL, 0, 0);
	if (event == NULL)
		return (-1);
	if (state == NULL) {
		state = calloc(1, sizeof(*state));
		if (state == NULL) {
			event_release(event);
			return (-1);
		}
		state->topic_length = topic_length;
		memcpy(state->topic, topic, topic_length);
		/*
		 * Bind ownership to the setting session's unforgeable label so
		 * only that publisher may clear the state, and so the state can
		 * be reclaimed when the owner disconnects.
		 */
		strlcpy(state->owner, publisher->label, sizeof(state->owner));
		state->next = broker->states[bucket];
		broker->states[bucket] = state;
		broker->nstates++;
	}
	state->state = value;
	state->generation++;
	event->event.generation = state->generation;
	event->event.state = state->state;
	for (subscription = broker->buckets[bucket]; subscription != NULL;
	    subscription = subscription->bucket_next)
		if (subscription->topic_length == topic_length &&
		    memcmp(subscription->topic, topic, topic_length) == 0)
			enqueue(subscription->client, event);
	publisher->stats.published++;
	reply->router_epoch = broker->epoch;
	reply->generation = state->generation;
	reply->state = state->state;
	event_release(event);
	return (0);
}

int
notify_broker_state_get(struct notify_broker *broker, const char *topic,
    size_t topic_length, struct notify_state_reply *reply)
{
	struct broker_topic_state *state;

	if (broker == NULL || reply == NULL ||
	    notify_validate_topic(topic, topic_length) == -1)
		return (-1);
	state = state_find(broker, topic, topic_length);
	if (state == NULL) {
		errno = ENOENT;
		return (-1);
	}
	reply->router_epoch = broker->epoch;
	reply->generation = state->generation;
	reply->state = state->state;
	return (0);
}

int
notify_broker_state_clear(struct notify_broker *broker,
    struct notify_broker_client *publisher, const char *topic,
    size_t topic_length)
{
	struct broker_topic_state *state;

	if (broker == NULL || publisher == NULL ||
	    notify_validate_topic(topic, topic_length) == -1)
		return (-1);
	state = state_find(broker, topic, topic_length);
	if (state == NULL) {
		errno = ENOENT;
		return (-1);
	}
	/* Owner-scoped: only the label that set the state may clear it. */
	if (strcmp(state->owner, publisher->label) != 0) {
		errno = EACCES;
		return (-1);
	}
	state_unlink(broker, state);
	publisher->stats.published++;
	return (0);
}

int
notify_broker_timer(struct notify_broker *broker,
    struct notify_broker_client *client, uint64_t timer_id)
{
	struct broker_event *event;

	if (broker == NULL || client == NULL || timer_id == 0) {
		errno = EINVAL;
		return (-1);
	}
	event = event_create(broker, NOTIFY_EVENT_TIMER, client->label, NULL,
	    0, NULL, 0, timer_id);
	if (event == NULL)
		return (-1);
	enqueue(client, event);
	client->stats.timer_events++;
	event_release(event);
	return (0);
}

ssize_t
notify_broker_next(struct notify_broker_client *client,
    struct notify_event *event, size_t capacity)
{
	struct broker_event *queued;
	size_t length;

	if (client == NULL || event == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (client->lost_pending != 0) {
		if (capacity < sizeof(*event)) {
			errno = EMSGSIZE;
			return (-1);
		}
		memset(event, 0, sizeof(*event));
		event->type = NOTIFY_EVENT_GAP;
		event->flags = NOTIFY_EVENT_F_GAP;
		event->router_epoch = client->epoch;
		event->lost_count = client->lost_pending;
		client->lost_pending = 0;
		return (sizeof(*event));
	}
	if (client->queue_count == 0) {
		errno = EAGAIN;
		return (-1);
	}
	queued = client->queue[client->queue_head];
	length = queued->length;
	if (capacity < length) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(event, &queued->event, length);
	client->queue[client->queue_head] = NULL;
	client->queue_head = (client->queue_head + 1) % client->queue_depth;
	client->queue_count--;
	event_release(queued);
	return ((ssize_t)length);
}

void
notify_broker_stats(const struct notify_broker_client *client,
    struct notify_stats *stats)
{

	if (client == NULL || stats == NULL)
		return;
	*stats = client->stats;
}
