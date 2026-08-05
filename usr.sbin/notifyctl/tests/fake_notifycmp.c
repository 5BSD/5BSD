/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <notifycmp.h>
#include <notifycmp_server.h>

struct notifycmp_client { int open; };
static struct notifycmp_client client;
static char subscribed[NOTIFYCMP_MAX_TOPIC + 1];

int
notifycmp_validate_topic(const char *topic, size_t length)
{
	size_t i, segment;
	unsigned char character;

	if (topic == NULL || length == 0 || length > NOTIFYCMP_MAX_TOPIC) {
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
notifycmp_client_open(struct notifycmp_client **result)
{
	if (result == NULL || fail("open") == -1)
		return (-1);
	client.open = 1;
	*result = &client;
	return (0);
}

void
notifycmp_client_close(struct notifycmp_client *value)
{
	if (value == &client) {
		client.open = 0;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

int
notifycmp_subscribe(struct notifycmp_client *value, const char *topic)
{
	if (value != &client || !client.open || topic == NULL ||
	    strlcpy(subscribed, topic, sizeof(subscribed)) >= sizeof(subscribed)) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("subscribe"));
}

int
notifycmp_publish(struct notifycmp_client *value, const char *topic,
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
notifycmp_state_set(struct notifycmp_client *value, const char *topic,
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
notifycmp_state_get(struct notifycmp_client *value, const char *topic,
    struct notifycmp_state_reply *state)
{
	if (value != &client || !client.open || state == NULL ||
	    strcmp(topic, "org.5bsd.test.changed") != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("state-get") == -1)
		return (-1);
	*state = (struct notifycmp_state_reply){
	    .router_epoch = 7, .generation = 8, .state = 42 };
	return (0);
}

ssize_t
notifycmp_next(struct notifycmp_client *value, struct notifycmp_event *event,
    size_t capacity, uint32_t timeout)
{
	static const char publisher[] = "org.5bsd.provider/service";
	static const char payload[] = "payload-data";
	size_t length, topic_length;
	uint8_t *cursor;

	topic_length = strlen(subscribed);
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
	event->type = NOTIFYCMP_EVENT_PUBLISH;
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
notifycmp_stats(struct notifycmp_client *value, struct notifycmp_stats *stats)
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
