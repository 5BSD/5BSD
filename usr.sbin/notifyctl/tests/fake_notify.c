/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <notify.h>
#include <notify_server.h>

struct notify_client { int open; };
static struct notify_client client;
static char subscribed[NOTIFY_MAX_TOPIC + 1];
static uint64_t active_timer;
static uint64_t timer_sequence;
static int timer_periodic;

int
notify_validate_topic(const char *topic, size_t length)
{
	size_t i, segment;
	unsigned char character;

	if (topic == NULL || length == 0 || length > NOTIFY_MAX_TOPIC) {
		errno = EINVAL;
		return (-1);
	}
	segment = 0;
	for (i = 0; i < length; i++) {
		character = (unsigned char)topic[i];
		if (character == '.') {
			if (segment == 0 || i + 1 == length) {
				errno = EINVAL;
				return (-1);
			}
			segment = 0;
			continue;
		}
		if (!((character >= 'a' && character <= 'z') ||
		    (character >= 'A' && character <= 'Z') ||
		    (segment != 0 && character >= '0' && character <= '9') ||
		    character == '_' || character == '-')) {
			errno = EINVAL;
			return (-1);
		}
		segment++;
	}
	return (0);
}

static int
fail(const char *operation)
{
	const char *requested;

	requested = getenv("CMP_TEST_FAIL");
	if (requested != NULL && strcmp(requested, operation) == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
notify_client_open(struct notify_client **result)
{
	if (result == NULL || fail("open") == -1)
		return (-1);
	client.open = 1;
	subscribed[0] = '\0';
	active_timer = 0;
	timer_periodic = 0;
	*result = &client;
	return (0);
}

void
notify_client_close(struct notify_client *value)
{
	if (value == &client) {
		client.open = 0;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

int
notify_subscribe(struct notify_client *value, const char *topic)
{
	if (value != &client || !client.open || topic == NULL ||
	    strlcpy(subscribed, topic, sizeof(subscribed)) >= sizeof(subscribed)) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("subscribe"));
}

int
notify_unsubscribe(struct notify_client *value, const char *topic)
{

	if (value != &client || !client.open || topic == NULL ||
	    strcmp(subscribed, topic) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("unsubscribe") == -1)
		return (-1);
	subscribed[0] = '\0';
	if (getenv("CMP_TEST_TRACE_UNSUBSCRIBE") != NULL)
		fprintf(stderr, "unsubscribed\n");
	return (0);
}

int
notify_publish(struct notify_client *value, const char *topic,
    const void *payload, size_t length)
{
	if (value != &client || !client.open ||
	    strcmp(topic, "org.5bsd.test.changed") != 0 || length != 7 ||
	    memcmp(payload, "payload", length) != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("publish"));
}

int
notify_state_set(struct notify_client *value, const char *topic,
    uint64_t state)
{
	if (value != &client || !client.open ||
	    strcmp(topic, "org.5bsd.test.changed") != 0 || state != 42) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("state-set"));
}

int
notify_state_get(struct notify_client *value, const char *topic,
    struct notify_state_reply *state)
{
	if (value != &client || !client.open || state == NULL ||
	    strcmp(topic, "org.5bsd.test.changed") != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("state-get") == -1)
		return (-1);
	*state = (struct notify_state_reply){
	    .router_epoch = 7, .generation = 8, .state = 42 };
	return (0);
}

ssize_t
notify_next(struct notify_client *value, struct notify_event *event,
    size_t capacity, uint32_t timeout)
{
	static const char publisher[] = "org.5bsd.provider/service";
	static const char payload[] = "payload-data";
	size_t length, topic_length;
	uint8_t *cursor;

	topic_length = strlen(subscribed);
	if (active_timer != 0) {
		if (value != &client || !client.open || event == NULL ||
		    capacity < sizeof(*event) || (timeout != 25 &&
		    timeout != NOTIFY_TIMEOUT_INFINITE)) {
			errno = EINVAL;
			return (-1);
		}
		if (getenv("CMP_TEST_TIMEOUT") != NULL) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if (fail("next") == -1)
			return (-1);
		memset(event, 0, sizeof(*event));
		event->type = NOTIFY_EVENT_TIMER;
		event->router_epoch = 7;
		event->sequence = ++timer_sequence;
		event->timestamp_ns = 123456789;
		event->timer_id = active_timer;
		if (getenv("CMP_TEST_BAD_TIMER_EVENT") != NULL)
			event->timer_id++;
		if (!timer_periodic)
			active_timer = 0;
		return (sizeof(*event));
	}
	length = sizeof(*event) + sizeof(publisher) - 1 + topic_length +
	    sizeof(payload) - 1;
	if (value != &client || !client.open || event == NULL ||
	    capacity < length || timeout != 25 || topic_length == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("next") == -1)
		return (-1);
	memset(event, 0, sizeof(*event));
	event->type = NOTIFY_EVENT_PUBLISH;
	event->router_epoch = 7;
	event->sequence = 9;
	event->generation = 8;
	event->state = 42;
	event->publisher_length = sizeof(publisher) - 1;
	event->topic_length = topic_length;
	event->payload_length = sizeof(payload) - 1;
	cursor = event->data;
	memcpy(cursor, publisher, sizeof(publisher) - 1);
	cursor += sizeof(publisher) - 1;
	memcpy(cursor, subscribed, topic_length);
	cursor += topic_length;
	memcpy(cursor, payload, sizeof(payload) - 1);
	return ((ssize_t)length);
}

int
notify_timer_add(struct notify_client *value, uint64_t timer_id,
    uint32_t interval, uint32_t flags)
{

	if (value != &client || !client.open || timer_id != 99 ||
	    interval != 10 || (flags != 0 && flags != NOTIFY_TIMER_F_PERIODIC)) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("timer-add") == -1)
		return (-1);
	active_timer = timer_id;
	timer_periodic = flags == NOTIFY_TIMER_F_PERIODIC;
	timer_sequence = 0;
	return (0);
}

int
notify_timer_cancel(struct notify_client *value, uint64_t timer_id)
{

	if (value != &client || !client.open || timer_id != active_timer ||
	    !timer_periodic) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("timer-cancel") == -1)
		return (-1);
	active_timer = 0;
	timer_periodic = 0;
	if (getenv("CMP_TEST_TRACE_TIMER_CANCEL") != NULL)
		fprintf(stderr, "timer-canceled\n");
	return (0);
}

int
notify_stats(struct notify_client *value, struct notify_stats *stats)
{
	if (value != &client || !client.open || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("stats") == -1)
		return (-1);
	memset(stats, 0, sizeof(*stats));
	stats->published = 1;
	stats->delivered = 2;
	stats->dropped = 3;
	stats->rejected = 4;
	stats->timer_events = 5;
	return (0);
}
