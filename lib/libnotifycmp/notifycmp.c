/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>

#include "notifycmp.h"
#include "notifycmp_probes.h"

union notifycmp_buffer {
	max_align_t align;
	uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
};

struct notifycmp_client {
	struct service_session	*channel;
	pid_t			 owner;
};

int
notifycmp_validate_topic(const char *topic, size_t length)
{
	size_t i, segment;
	unsigned char c;

	if (topic == NULL || length == 0 || length > NOTIFYCMP_MAX_TOPIC) {
		errno = EINVAL;
		return (-1);
	}
	segment = 0;
	for (i = 0; i < length; i++) {
		c = (unsigned char)topic[i];
		if (c == '.') {
			if (segment == 0 || i + 1 == length) {
				errno = EINVAL;
				return (-1);
			}
			segment = 0;
			continue;
		}
		if (!((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (segment != 0 && c >= '0' && c <= '9') ||
		    c == '_' || c == '-')) {
			errno = EINVAL;
			return (-1);
		}
		segment++;
	}
	return (0);
}

static int
validate_event(const struct notifycmp_event *event, size_t length)
{
	size_t expected, i;

	if (length < sizeof(*event) ||
	    (event->type != NOTIFYCMP_EVENT_PUBLISH &&
	    event->type != NOTIFYCMP_EVENT_TIMER) ||
	    event->flags != 0 ||
	    event->publisher_length == 0 ||
	    event->publisher_length > NOTIFYCMP_MAX_PUBLISHER ||
	    event->topic_length > NOTIFYCMP_MAX_TOPIC ||
	    event->payload_length > NOTIFYCMP_MAX_PAYLOAD)
		goto invalid;
	expected = sizeof(*event) + event->publisher_length +
	    event->topic_length + event->payload_length;
	if (expected != length ||
	    (event->publisher_length != 0 &&
	    memchr(event->data, '\0', event->publisher_length) != NULL) ||
	    (event->topic_length != 0 &&
	    notifycmp_validate_topic((const char *)event->data +
	    event->publisher_length, event->topic_length) == -1))
		goto invalid;
	for (i = 0; i < event->publisher_length; i++)
		if (event->data[i] < 0x20 || event->data[i] == 0x7f)
			goto invalid;
	if (event->type == NOTIFYCMP_EVENT_TIMER &&
	    (event->timer_id == 0 || event->topic_length != 0 ||
	    event->payload_length != 0))
		goto invalid;
	if (event->type == NOTIFYCMP_EVENT_PUBLISH &&
	    (event->timer_id != 0 || event->topic_length == 0))
		goto invalid;
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

static int
notifycmp_header_validate(const struct notifycmp_msg *msg, size_t length,
    enum notifycmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > NOTIFYCMP_MAX_MESSAGE ||
	    (role != NOTIFYCMP_MESSAGE_REQUEST &&
	    role != NOTIFYCMP_MESSAGE_REPLY &&
	    role != NOTIFYCMP_MESSAGE_EVENT) ||
	    msg->magic != NOTIFYCMP_MAGIC ||
	    msg->version != NOTIFYCMP_ABI_VERSION ||
	    msg->opcode < NOTIFYCMP_OP_HELLO ||
	    msg->opcode > NOTIFYCMP_OP_STATS ||
	    (msg->flags & ~NOTIFYCMP_MSG_F_MASK) != 0 ||
	    (role != NOTIFYCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == NOTIFYCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
notifycmp_message_init(struct notifycmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < NOTIFYCMP_OP_HELLO ||
	    opcode > NOTIFYCMP_OP_STATS ||
	    (flags & ~NOTIFYCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = NOTIFYCMP_MAGIC;
	msg->version = NOTIFYCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
notifycmp_message_init_reply(struct notifycmp_msg *reply,
    const struct notifycmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    notifycmp_header_validate(request, sizeof(*request),
	    NOTIFYCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = NOTIFYCMP_MAGIC;
	reply->version = NOTIFYCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
notifycmp_validate_message(const struct notifycmp_msg *msg, size_t length,
    enum notifycmp_message_role role)
{
	const struct notifycmp_publish_request *publish;
	const struct notifycmp_timer_request *timer;
	const struct notifycmp_topic_request *topic;
	const struct notifycmp_hello_reply *hello;
	size_t payload;

	if (notifycmp_header_validate(msg, length, role) == -1)
		goto invalid;
	payload = length - sizeof(*msg);
	if (role == NOTIFYCMP_MESSAGE_REPLY) {
		if (msg->status != 0 && payload != 0)
			goto invalid;
		if (msg->status != 0)
			return (0);
		switch (msg->opcode) {
		case NOTIFYCMP_OP_HELLO:
			if (payload != sizeof(*hello))
				goto invalid;
			hello = (const void *)(msg + 1);
			if (hello->version != NOTIFYCMP_ABI_VERSION ||
			    hello->features != (NOTIFYCMP_FEATURE_PUBSUB |
			    NOTIFYCMP_FEATURE_TIMERS |
			    NOTIFYCMP_FEATURE_BOUNDED_QUEUE) ||
			    hello->max_topic != NOTIFYCMP_MAX_TOPIC ||
			    hello->max_payload != NOTIFYCMP_MAX_PAYLOAD ||
			    hello->max_subscriptions !=
			    NOTIFYCMP_MAX_SUBSCRIPTIONS ||
			    hello->queue_depth == 0 ||
			    hello->queue_depth > NOTIFYCMP_DEFAULT_QUEUE ||
			    hello->max_timers != NOTIFYCMP_MAX_TIMERS ||
			    hello->reserved != 0)
				goto invalid;
			break;
		case NOTIFYCMP_OP_NEXT:
			if (validate_event((const void *)(msg + 1), payload) == -1)
				goto invalid;
			break;
		case NOTIFYCMP_OP_STATS:
			if (payload != sizeof(struct notifycmp_stats))
				goto invalid;
			break;
		default:
			if (payload != 0)
				goto invalid;
		}
		return (0);
	}
	if (msg->status != 0)
		goto invalid;
	switch (msg->opcode) {
	case NOTIFYCMP_OP_HELLO:
	case NOTIFYCMP_OP_STATS:
		if (payload != 0)
			goto invalid;
		break;
	case NOTIFYCMP_OP_SUBSCRIBE:
	case NOTIFYCMP_OP_UNSUBSCRIBE:
		if (payload != sizeof(*topic))
			goto invalid;
		topic = (const void *)(msg + 1);
		if (topic->reserved16 != 0 || topic->reserved32 != 0 ||
		    topic->topic_length == 0 ||
		    topic->topic_length > sizeof(topic->topic) ||
		    notifycmp_validate_topic(topic->topic,
		    topic->topic_length) == -1 ||
		    memchr(topic->topic, '\0', topic->topic_length) != NULL ||
		    memcmp(topic->topic + topic->topic_length,
		    (char[NOTIFYCMP_MAX_TOPIC]){}, sizeof(topic->topic) -
		    topic->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFYCMP_OP_PUBLISH:
		if (payload < sizeof(*publish))
			goto invalid;
		publish = (const void *)(msg + 1);
		if (publish->reserved16 != 0 || publish->topic_length == 0 ||
		    publish->topic_length > sizeof(publish->topic) ||
		    publish->payload_length > NOTIFYCMP_MAX_PAYLOAD ||
		    payload != sizeof(*publish) + publish->payload_length ||
		    notifycmp_validate_topic(publish->topic,
		    publish->topic_length) == -1 ||
		    memchr(publish->topic, '\0', publish->topic_length) != NULL ||
		    memcmp(publish->topic + publish->topic_length,
		    (char[NOTIFYCMP_MAX_TOPIC]){}, sizeof(publish->topic) -
		    publish->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFYCMP_OP_NEXT: {
		const struct notifycmp_next_request *next;

		if (payload != sizeof(*next))
			goto invalid;
		next = (const void *)(msg + 1);
		if (next->reserved != 0)
			goto invalid;
		break;
	}
	case NOTIFYCMP_OP_TIMER_ADD:
		if (payload != sizeof(*timer))
			goto invalid;
		timer = (const void *)(msg + 1);
		if (timer->timer_id == 0 || timer->interval_ms == 0 ||
		    timer->interval_ms > 86400000 ||
		    (timer->flags & ~NOTIFYCMP_TIMER_F_MASK) != 0)
			goto invalid;
		break;
	case NOTIFYCMP_OP_TIMER_CANCEL: {
		const struct notifycmp_timer_cancel_request *cancel;

		if (payload != sizeof(*cancel))
			goto invalid;
		cancel = (const void *)(msg + 1);
		if (cancel->timer_id == 0 || cancel->reserved != 0)
			goto invalid;
		break;
	}
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

static int
rpc(struct notifycmp_client *client, uint16_t opcode,
    const void *payload, size_t payload_length, union notifycmp_buffer *reply,
    size_t *reply_payload, uint32_t timeout_ms)
{
	union notifycmp_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct notifycmp_msg *message;
	size_t request_length;
	size_t received;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	request_length = sizeof(*message) + payload_length;
	if (notifycmp_message_init(message, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = message;
	outgoing.length = request_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply->bytes;
	incoming.capacity = sizeof(*reply);
	options.timeout_ms = timeout_ms;
	if (service_session_call(client->channel, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	received = incoming.length;
	message = (void *)reply->bytes;
	if (incoming.nfds != 0 ||
	    notifycmp_validate_message(message, received,
	    NOTIFYCMP_MESSAGE_REPLY) == -1 || message->opcode != opcode) {
		errno = EPROTO;
		return (-1);
	}
	if (message->status != 0) {
		errno = -message->status;
		return (-1);
	}
	*reply_payload = received - sizeof(*message);
	return (0);
}

static int
simple_rpc(struct notifycmp_client *client, uint16_t opcode,
    const void *payload, size_t payload_length)
{
	union notifycmp_buffer reply;
	size_t reply_payload;
	int result;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	result = rpc(client, opcode, payload, payload_length, &reply,
	    &reply_payload, 30000);
	if (result == 0 && reply_payload != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (result);
}

int
notifycmp_client_open(struct notifycmp_client **result)
{
	union notifycmp_buffer reply;
	struct notifycmp_client *client;
	struct service_context *service;
	size_t payload;
	int error, fd;

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	client->owner = getpid();
	if (service_acquire(&service) == -1)
		goto fail;
	error = service_connect(service, NOTIFYCMP_INTERFACE, &fd) == -1 ?
	    errno : 0;
	service_release(service);
	if (fd == -1) {
		errno = error;
		goto fail;
	}
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		goto fail;
	}
	if (rpc(client, NOTIFYCMP_OP_HELLO, NULL, 0, &reply, &payload,
	    30000) == -1)
		goto fail_channel;
	*result = client;
	return (0);

fail_channel:
	error = errno;
	service_session_close(client->channel);
	errno = error;
fail:
	error = errno;
	free(client);
	errno = error;
	return (-1);
}

void
notifycmp_client_close(struct notifycmp_client *client)
{

	if (client == NULL)
		return;
	service_session_close(client->channel);
	memset(client, 0, sizeof(*client));
	free(client);
}

static int
topic_rpc(struct notifycmp_client *client, uint16_t opcode, const char *name)
{
	struct notifycmp_topic_request request;
	size_t length;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(name, NOTIFYCMP_MAX_TOPIC + 1);
	if (notifycmp_validate_topic(name, length) == -1)
		return (-1);
	memset(&request, 0, sizeof(request));
	request.topic_length = length;
	memcpy(request.topic, name, length);
	return (simple_rpc(client, opcode, &request, sizeof(request)));
}

int
notifycmp_subscribe(struct notifycmp_client *client, const char *topic)
{

	return (topic_rpc(client, NOTIFYCMP_OP_SUBSCRIBE, topic));
}

int
notifycmp_unsubscribe(struct notifycmp_client *client, const char *topic)
{

	return (topic_rpc(client, NOTIFYCMP_OP_UNSUBSCRIBE, topic));
}

int
notifycmp_publish(struct notifycmp_client *client, const char *topic,
    const void *data, size_t length)
{
	union notifycmp_buffer payload;
	struct notifycmp_publish_request *request;
	size_t topic_length;
	int result;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    (length != 0 && data == NULL) || length > NOTIFYCMP_MAX_PAYLOAD) {
		errno = EINVAL;
		return (-1);
	}
	topic_length = strnlen(topic, NOTIFYCMP_MAX_TOPIC + 1);
	if (notifycmp_validate_topic(topic, topic_length) == -1)
		return (-1);
	memset(&payload, 0, sizeof(payload));
	request = (void *)payload.bytes;
	request->topic_length = topic_length;
	request->payload_length = length;
	memcpy(request->topic, topic, topic_length);
	if (length != 0)
		memcpy(request + 1, data, length);
	result = simple_rpc(client, NOTIFYCMP_OP_PUBLISH, request,
	    sizeof(*request) + length);
	NOTIFYCMP_PROBE_PUBLISH(__DECONST(char *, topic), length,
	    result == -1 ? errno : 0);
	return (result);
}

ssize_t
notifycmp_next(struct notifycmp_client *client, struct notifycmp_event *event,
    size_t capacity, uint32_t timeout_ms)
{
	union notifycmp_buffer reply;
	struct notifycmp_next_request request;
	struct notifycmp_msg *message;
	size_t payload;
	ssize_t result;
	int error;

	if (client == NULL || client->owner != getpid() || event == NULL ||
	    capacity < sizeof(*event)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.timeout_ms = timeout_ms;
	if (rpc(client, NOTIFYCMP_OP_NEXT, &request, sizeof(request),
	    &reply, &payload, timeout_ms == UINT32_MAX ? UINT32_MAX :
	    MIN(timeout_ms + 1000U, UINT32_MAX - 1)) == -1) {
		error = errno;
		result = -1;
	} else if (payload > capacity) {
		error = EMSGSIZE;
		result = -1;
	} else {
		message = (void *)reply.bytes;
		memcpy(event, message + 1, payload);
		error = 0;
		result = (ssize_t)payload;
	}
	NOTIFYCMP_PROBE_NEXT(timeout_ms, error);
	errno = error;
	return (result);
}

int
notifycmp_timer_add(struct notifycmp_client *client, uint64_t timer_id,
    uint32_t interval_ms, uint32_t flags)
{
	struct notifycmp_timer_request request;

	memset(&request, 0, sizeof(request));
	request.timer_id = timer_id;
	request.interval_ms = interval_ms;
	request.flags = flags;
	return (simple_rpc(client, NOTIFYCMP_OP_TIMER_ADD, &request,
	    sizeof(request)));
}

int
notifycmp_timer_cancel(struct notifycmp_client *client, uint64_t timer_id)
{
	struct notifycmp_timer_cancel_request request;

	memset(&request, 0, sizeof(request));
	request.timer_id = timer_id;
	return (simple_rpc(client, NOTIFYCMP_OP_TIMER_CANCEL, &request,
	    sizeof(request)));
}

int
notifycmp_stats(struct notifycmp_client *client, struct notifycmp_stats *stats)
{
	union notifycmp_buffer reply;
	size_t payload;
	int error, result;

	if (client == NULL || client->owner != getpid() || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	result = rpc(client, NOTIFYCMP_OP_STATS, NULL, 0, &reply, &payload,
	    30000);
	error = result == -1 ? errno : 0;
	if (result == 0) {
		if (payload != sizeof(*stats)) {
			result = -1;
			error = EPROTO;
		} else
			memcpy(stats, (struct notifycmp_msg *)reply.bytes + 1,
			    sizeof(*stats));
	}
	errno = error;
	return (result);
}
