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

#include <pthread.h>

#include <libservice.h>

#include "notify.h"
#include "notify_server.h"
#include "notify_internal.h"
#include "notify_probes.h"

union notify_buffer {
	max_align_t align;
	uint8_t bytes[NOTIFY_MAX_MESSAGE];
};

struct notify_client {
	struct service_session	*channel;
	pid_t			 owner;
	uint64_t		 router_epoch;
	pthread_mutex_t		 lock;
	size_t			 nsubscriptions;
	char			 subscriptions[NOTIFY_MAX_SUBSCRIPTIONS]
				     [NOTIFY_MAX_TOPIC + 1];
};

static int topic_rpc(struct notify_client *, uint16_t, const char *);
static bool connection_lost(int);
static bool connection_unusable(int);
static void disconnect_locked(struct notify_client *);
static int reconnect_locked(struct notify_client *);

int
notify_validate_topic(const char *topic, size_t length)
{
	size_t i, segment;
	unsigned char c;

	if (topic == NULL || length == 0 || length > NOTIFY_MAX_TOPIC) {
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
		    (i != 0 && c >= '0' && c <= '9') ||
		    c == '_' || c == '-')) {
			errno = EINVAL;
			return (-1);
		}
		segment++;
	}
	return (0);
}

static int
validate_event(const struct notify_event *event, size_t length)
{
	size_t expected, i;

	if (length < sizeof(*event) ||
	    (event->type < NOTIFY_EVENT_PUBLISH ||
	    event->type > NOTIFY_EVENT_RESET) ||
	    (event->flags & ~NOTIFY_EVENT_F_MASK) != 0 ||
	    event->router_epoch == 0 ||
	    event->publisher_length > NOTIFY_MAX_PUBLISHER ||
	    event->topic_length > NOTIFY_MAX_TOPIC ||
	    event->payload_length > NOTIFY_MAX_PAYLOAD)
		goto invalid;
	expected = sizeof(*event) + event->publisher_length +
	    event->topic_length + event->payload_length;
	if (expected != length ||
	    (event->publisher_length != 0 &&
	    memchr(event->data, '\0', event->publisher_length) != NULL) ||
	    (event->topic_length != 0 &&
	    notify_validate_topic((const char *)event->data +
	    event->publisher_length, event->topic_length) == -1))
		goto invalid;
	for (i = 0; i < event->publisher_length; i++)
		if (event->data[i] < 0x20 || event->data[i] == 0x7f)
			goto invalid;
	if ((event->type == NOTIFY_EVENT_PUBLISH ||
	    event->type == NOTIFY_EVENT_TIMER ||
	    event->type == NOTIFY_EVENT_STATE) &&
	    event->publisher_length == 0)
		goto invalid;
	if (event->type == NOTIFY_EVENT_TIMER &&
	    (event->timer_id == 0 || event->topic_length != 0 ||
	    event->payload_length != 0 || event->generation != 0 ||
	    event->lost_count != 0))
		goto invalid;
	if (event->type == NOTIFY_EVENT_PUBLISH &&
	    (event->timer_id != 0 || event->topic_length == 0 ||
	    event->generation != 0 || event->lost_count != 0))
		goto invalid;
	if (event->type == NOTIFY_EVENT_STATE &&
	    (event->timer_id != 0 || event->topic_length == 0 ||
	    event->payload_length != 0 || event->generation == 0 ||
	    event->lost_count != 0))
		goto invalid;
	if ((event->type == NOTIFY_EVENT_GAP ||
	    event->type == NOTIFY_EVENT_RESET) &&
	    (event->publisher_length != 0 || event->topic_length != 0 ||
	    event->payload_length != 0 || event->timer_id != 0 ||
	    event->generation != 0 || event->state != 0 ||
	    (event->type == NOTIFY_EVENT_GAP &&
	    (event->lost_count == 0 ||
	    (event->flags & NOTIFY_EVENT_F_GAP) == 0)) ||
	    (event->type == NOTIFY_EVENT_RESET &&
	    (event->lost_count != 0 || event->flags != 0))))
		goto invalid;
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

static int
notify_header_validate(const struct notify_msg *msg, size_t length,
    enum notify_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > NOTIFY_MAX_MESSAGE ||
	    (role != NOTIFY_MESSAGE_REQUEST &&
	    role != NOTIFY_MESSAGE_REPLY &&
	    role != NOTIFY_MESSAGE_EVENT) ||
	    msg->magic != NOTIFY_MAGIC ||
	    msg->version != NOTIFY_ABI_VERSION ||
	    msg->opcode < NOTIFY_OP_HELLO ||
	    msg->opcode > NOTIFY_OP_STATE_CLEAR ||
	    (msg->flags & ~NOTIFY_MSG_F_MASK) != 0 ||
	    (role != NOTIFY_MESSAGE_REPLY && msg->status != 0) ||
	    (role == NOTIFY_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
notify_message_init(struct notify_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < NOTIFY_OP_HELLO ||
	    opcode > NOTIFY_OP_STATE_CLEAR ||
	    (flags & ~NOTIFY_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = NOTIFY_MAGIC;
	msg->version = NOTIFY_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
notify_message_init_reply(struct notify_msg *reply,
    const struct notify_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    notify_header_validate(request, sizeof(*request),
	    NOTIFY_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = NOTIFY_MAGIC;
	reply->version = NOTIFY_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
notify_validate_message(const struct notify_msg *msg, size_t length,
    enum notify_message_role role)
{
	const struct notify_publish_request *publish;
	const struct notify_timer_request *timer;
	const struct notify_topic_request *topic;
	const struct notify_hello_reply *hello;
	const struct notify_state_set_request *state_set;
	size_t payload;

	if (notify_header_validate(msg, length, role) == -1)
		goto invalid;
	payload = length - sizeof(*msg);
	if (role == NOTIFY_MESSAGE_REPLY) {
		if (msg->status != 0 && payload != 0)
			goto invalid;
		if (msg->status != 0)
			return (0);
		switch (msg->opcode) {
		case NOTIFY_OP_HELLO:
			if (payload != sizeof(*hello))
				goto invalid;
			hello = (const void *)(msg + 1);
			if (hello->version != NOTIFY_ABI_VERSION ||
			    hello->features != (NOTIFY_FEATURE_PUBSUB |
			    NOTIFY_FEATURE_TIMERS |
			    NOTIFY_FEATURE_BOUNDED_QUEUE |
			    NOTIFY_FEATURE_STATE |
			    NOTIFY_FEATURE_LOSS_REPORTING) ||
			    hello->max_topic != NOTIFY_MAX_TOPIC ||
			    hello->max_payload != NOTIFY_MAX_PAYLOAD ||
			    hello->max_subscriptions !=
			    NOTIFY_MAX_SUBSCRIPTIONS ||
			    hello->queue_depth == 0 ||
			    hello->queue_depth > NOTIFY_DEFAULT_QUEUE ||
			    hello->max_timers != NOTIFY_MAX_TIMERS ||
			    hello->max_states != NOTIFY_MAX_STATES ||
			    hello->router_epoch == 0)
				goto invalid;
			break;
		case NOTIFY_OP_NEXT:
			if (validate_event((const void *)(msg + 1), payload) == -1)
				goto invalid;
			break;
		case NOTIFY_OP_STATS:
			if (payload != sizeof(struct notify_stats))
				goto invalid;
			break;
		case NOTIFY_OP_STATE_SET:
		case NOTIFY_OP_STATE_GET:
			if (payload != sizeof(struct notify_state_reply))
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
	case NOTIFY_OP_HELLO:
	case NOTIFY_OP_STATS:
		if (payload != 0)
			goto invalid;
		break;
	case NOTIFY_OP_SUBSCRIBE:
	case NOTIFY_OP_UNSUBSCRIBE:
	case NOTIFY_OP_STATE_GET:
	case NOTIFY_OP_STATE_CLEAR:
		if (payload != sizeof(*topic))
			goto invalid;
		topic = (const void *)(msg + 1);
		if (topic->reserved16 != 0 || topic->reserved32 != 0 ||
		    topic->topic_length == 0 ||
		    topic->topic_length > sizeof(topic->topic) ||
		    notify_validate_topic(topic->topic,
		    topic->topic_length) == -1 ||
		    memchr(topic->topic, '\0', topic->topic_length) != NULL ||
		    memcmp(topic->topic + topic->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(topic->topic) -
		    topic->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_STATE_SET:
		if (payload != sizeof(*state_set))
			goto invalid;
		state_set = (const void *)(msg + 1);
		if (state_set->reserved16 != 0 || state_set->reserved32 != 0 ||
		    state_set->topic_length == 0 ||
		    state_set->topic_length > sizeof(state_set->topic) ||
		    notify_validate_topic(state_set->topic,
		    state_set->topic_length) == -1 ||
		    memchr(state_set->topic, '\0', state_set->topic_length) != NULL ||
		    memcmp(state_set->topic + state_set->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(state_set->topic) -
		    state_set->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_PUBLISH:
		if (payload < sizeof(*publish))
			goto invalid;
		publish = (const void *)(msg + 1);
		if (publish->reserved16 != 0 || publish->topic_length == 0 ||
		    publish->topic_length > sizeof(publish->topic) ||
		    publish->payload_length > NOTIFY_MAX_PAYLOAD ||
		    payload != sizeof(*publish) + publish->payload_length ||
		    notify_validate_topic(publish->topic,
		    publish->topic_length) == -1 ||
		    memchr(publish->topic, '\0', publish->topic_length) != NULL ||
		    memcmp(publish->topic + publish->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(publish->topic) -
		    publish->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_NEXT: {
		const struct notify_next_request *next;

		if (payload != sizeof(*next))
			goto invalid;
		next = (const void *)(msg + 1);
		if (next->reserved != 0)
			goto invalid;
		break;
	}
	case NOTIFY_OP_TIMER_ADD:
		if (payload != sizeof(*timer))
			goto invalid;
		timer = (const void *)(msg + 1);
		if (timer->timer_id == 0 || timer->interval_ms == 0 ||
		    timer->interval_ms > 86400000 ||
		    (timer->flags & ~NOTIFY_TIMER_F_MASK) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_TIMER_CANCEL: {
		const struct notify_timer_cancel_request *cancel;

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
rpc_locked(struct notify_client *client, uint16_t opcode,
    const void *payload, size_t payload_length, union notify_buffer *reply,
    size_t *reply_payload, uint32_t timeout_ms)
{
	union notify_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct notify_msg *message;
	size_t request_length;
	size_t received;
	uint16_t received_opcode;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	request_length = sizeof(*message) + payload_length;
	if (notify_message_init(message, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	if (notify_validate_message(message, request_length,
	    NOTIFY_MESSAGE_REQUEST) == -1)
		return (-1);
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
	    &options) == -1) {
		NOTIFY_PROBE_RPC(opcode, errno);
		return (-1);
	}
	NOTIFY_PROBE_RPC(opcode, 0);
	received = incoming.length;
	message = (void *)reply->bytes;
	received_opcode = received >= sizeof(*message) ? message->opcode : 0;
	if (incoming.nfds != 0 ||
	    notify_validate_message(message, received,
	    NOTIFY_MESSAGE_REPLY) == -1 || message->opcode != opcode) {
		NOTIFY_PROBE_REJECT(received_opcode, EPROTO);
		errno = EPROTO;
		return (-1);
	}
	if (message->status != 0) {
		NOTIFY_PROBE_REJECT(message->opcode, -message->status);
		errno = -message->status;
		return (-1);
	}
	*reply_payload = received - sizeof(*message);
	return (0);
}

static int
simple_rpc_locked(struct notify_client *client, uint16_t opcode,
    const void *payload, size_t payload_length)
{
	union notify_buffer reply;
	size_t reply_payload;
	int result;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	result = rpc_locked(client, opcode, payload, payload_length, &reply,
	    &reply_payload, 30000);
	if (result == 0 && reply_payload != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (result);
}

static int
simple_rpc(struct notify_client *client, uint16_t opcode,
    const void *payload, size_t payload_length)
{
	int error, result;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	pthread_mutex_lock(&client->lock);
	if (client->channel == NULL && reconnect_locked(client) == -1)
		result = -1;
	else
		result = simple_rpc_locked(client, opcode, payload, payload_length);
	error = errno;
	if (result == -1 && connection_unusable(error))
		disconnect_locked(client);
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
notify_client_adopt(int fd, struct notify_client **result)
{
	union notify_buffer reply;
	struct notify_client *client;
	size_t payload;
	int error;

	if (fd < 0 || result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = NULL;
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		(void)close(fd);
		return (-1);
	}
	client->owner = getpid();
	if ((error = pthread_mutex_init(&client->lock, NULL)) != 0) {
		free(client);
		(void)close(fd);
		errno = error;
		return (-1);
	}
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		goto fail;
	}
	if (rpc_locked(client, NOTIFY_OP_HELLO, NULL, 0, &reply, &payload,
	    30000) == -1)
		goto fail_channel;
	{
		struct notify_hello_reply hello;

		memcpy(&hello, (struct notify_msg *)reply.bytes + 1,
		    sizeof(hello));
		client->router_epoch = hello.router_epoch;
	}
	*result = client;
	return (0);

fail_channel:
	error = errno;
	service_session_close(client->channel);
	errno = error;
fail:
	error = errno;
	(void)pthread_mutex_destroy(&client->lock);
	free(client);
	errno = error;
	return (-1);
}

int
notify_client_open(struct notify_client **result)
{
	int error, fd;

	if (result == NULL)
		return (errno = EINVAL, -1);
	*result = NULL;
	fd = -1;
	error = service_open(NOTIFY_INTERFACE, &fd) == -1 ? errno : 0;
	if (fd == -1)
		return (errno = error, -1);
	if (notify_client_adopt(fd, result) == -1)
		return (-1);
	return (0);
}

static bool
connection_lost(int error)
{

	return (error == ECONNRESET || error == EPIPE || error == ENOTCONN ||
	    error == ESHUTDOWN);
}

static bool
connection_unusable(int error)
{

	return (connection_lost(error) || error == EPROTO);
}

static void
disconnect_locked(struct notify_client *client)
{

	service_session_close(client->channel);
	client->channel = NULL;
}

static int
reconnect_locked(struct notify_client *client)
{
	union notify_buffer reply;
	struct notify_hello_reply hello;
	size_t i, payload;
	int error, fd;

	disconnect_locked(client);
	fd = -1;
	error = service_open(NOTIFY_INTERFACE, &fd) == -1 ? errno : 0;
	if (fd == -1) {
		errno = error;
		return (-1);
	}
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	if (rpc_locked(client, NOTIFY_OP_HELLO, NULL, 0, &reply, &payload,
	    30000) == -1)
		goto fail;
	memcpy(&hello, (struct notify_msg *)reply.bytes + 1, sizeof(hello));
	client->router_epoch = hello.router_epoch;
	for (i = 0; i < client->nsubscriptions; i++)
		if (topic_rpc(client, NOTIFY_OP_SUBSCRIBE,
		    client->subscriptions[i]) == -1)
			goto fail;
	NOTIFY_PROBE_RECONNECT(client->router_epoch, 0);
	return (0);
fail:
	error = errno;
	service_session_close(client->channel);
	client->channel = NULL;
	NOTIFY_PROBE_RECONNECT(0, error);
	errno = error;
	return (-1);
}

static int
topic_rpc_managed_locked(struct notify_client *client, uint16_t opcode,
    const char *topic)
{
	int error, result;

	if (client->channel == NULL && reconnect_locked(client) == -1)
		return (-1);
	result = topic_rpc(client, opcode, topic);
	error = result == -1 ? errno : 0;
	if (result == -1 && connection_unusable(error))
		disconnect_locked(client);
	errno = error;
	return (result);
}

void
notify_client_close(struct notify_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid()) {
		service_session_close(client->channel);
		(void)pthread_mutex_destroy(&client->lock);
	}
	memset(client, 0, sizeof(*client));
	free(client);
}

static int
topic_rpc(struct notify_client *client, uint16_t opcode, const char *name)
{
	struct notify_topic_request request;
	size_t length;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(name, NOTIFY_MAX_TOPIC + 1);
	if (notify_validate_topic(name, length) == -1)
		return (-1);
	memset(&request, 0, sizeof(request));
	request.topic_length = length;
	memcpy(request.topic, name, length);
	return (simple_rpc_locked(client, opcode, &request, sizeof(request)));
}

int
notify_subscribe(struct notify_client *client, const char *topic)
{
	size_t length;
	int error, result;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	pthread_mutex_lock(&client->lock);
	if (client->nsubscriptions == NOTIFY_MAX_SUBSCRIPTIONS) {
		result = -1;
		error = EOVERFLOW;
	} else {
		result = topic_rpc_managed_locked(client,
		    NOTIFY_OP_SUBSCRIBE, topic);
		error = errno;
		if (result == 0) {
			memcpy(client->subscriptions[client->nsubscriptions], topic,
			    length + 1);
			client->nsubscriptions++;
		}
	}
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
notify_unsubscribe(struct notify_client *client, const char *topic)
{
	size_t i;
	int error, result;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	pthread_mutex_lock(&client->lock);
	result = topic_rpc_managed_locked(client, NOTIFY_OP_UNSUBSCRIBE,
	    topic);
	error = errno;
	if (result == 0)
		for (i = 0; i < client->nsubscriptions; i++)
			if (strcmp(client->subscriptions[i], topic) == 0) {
				client->nsubscriptions--;
				memcpy(client->subscriptions[i],
				    client->subscriptions[client->nsubscriptions],
				    sizeof(client->subscriptions[i]));
				break;
			}
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
notify_publish(struct notify_client *client, const char *topic,
    const void *data, size_t length)
{
	union notify_buffer payload;
	struct notify_publish_request *request;
	size_t topic_length;
	int result;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    (length != 0 && data == NULL) || length > NOTIFY_MAX_PAYLOAD) {
		errno = EINVAL;
		return (-1);
	}
	topic_length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	if (notify_validate_topic(topic, topic_length) == -1)
		return (-1);
	memset(&payload, 0, sizeof(payload));
	request = (void *)payload.bytes;
	request->topic_length = topic_length;
	request->payload_length = length;
	memcpy(request->topic, topic, topic_length);
	if (length != 0)
		memcpy(request + 1, data, length);
	result = simple_rpc(client, NOTIFY_OP_PUBLISH, request,
	    sizeof(*request) + length);
	NOTIFY_PROBE_PUBLISH(__DECONST(char *, topic), length,
	    result == -1 ? errno : 0);
	return (result);
}

int
notify_state_set(struct notify_client *client, const char *topic,
    uint64_t value)
{
	union notify_buffer reply;
	struct notify_state_set_request request;
	struct notify_state_reply *state;
	size_t length, payload;
	int error, result;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	if (notify_validate_topic(topic, length) == -1)
		return (-1);
	memset(&request, 0, sizeof(request));
	request.state = value;
	request.topic_length = length;
	memcpy(request.topic, topic, length);
	pthread_mutex_lock(&client->lock);
	if (client->channel == NULL && reconnect_locked(client) == -1)
		result = -1;
	else
		result = rpc_locked(client, NOTIFY_OP_STATE_SET, &request,
		    sizeof(request), &reply, &payload, 30000);
	if (result == 0) {
		state = (void *)((struct notify_msg *)reply.bytes + 1);
		if (payload != sizeof(*state) ||
		    state->router_epoch != client->router_epoch ||
		    state->generation == 0 || state->state != value) {
			errno = EPROTO;
			result = -1;
		}
	}
	error = result == -1 ? errno : 0;
	if (result == -1 && connection_unusable(error))
		disconnect_locked(client);
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
notify_state_get(struct notify_client *client, const char *topic,
    struct notify_state_reply *state)
{
	union notify_buffer reply;
	struct notify_topic_request request;
	size_t length, payload;
	int error, result;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    state == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	if (notify_validate_topic(topic, length) == -1)
		return (-1);
	memset(&request, 0, sizeof(request));
	request.topic_length = length;
	memcpy(request.topic, topic, length);
	pthread_mutex_lock(&client->lock);
	if (client->channel == NULL && reconnect_locked(client) == -1)
		result = -1;
	else
		result = rpc_locked(client, NOTIFY_OP_STATE_GET, &request,
		    sizeof(request), &reply, &payload, 30000);
	if (result == 0) {
		if (payload != sizeof(*state)) {
			errno = EPROTO;
			result = -1;
		} else {
			memcpy(state, (struct notify_msg *)reply.bytes + 1,
			    sizeof(*state));
			if (state->router_epoch != client->router_epoch ||
			    state->generation == 0) {
				errno = EPROTO;
				result = -1;
			}
		}
	}
	error = result == -1 ? errno : 0;
	if (result == -1 && connection_unusable(error))
		disconnect_locked(client);
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}

int
notify_state_clear(struct notify_client *client, const char *topic)
{
	struct notify_topic_request request;
	size_t length;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	if (notify_validate_topic(topic, length) == -1)
		return (-1);
	memset(&request, 0, sizeof(request));
	request.topic_length = length;
	memcpy(request.topic, topic, length);
	return (simple_rpc(client, NOTIFY_OP_STATE_CLEAR, &request,
	    sizeof(request)));
}

ssize_t
notify_next(struct notify_client *client, struct notify_event *event,
    size_t capacity, uint32_t timeout_ms)
{
	union notify_buffer reply;
	struct notify_next_request request;
	struct notify_msg *message;
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
	pthread_mutex_lock(&client->lock);
	if (client->channel == NULL && reconnect_locked(client) == -1) {
		error = errno;
		result = -1;
	} else if (rpc_locked(client, NOTIFY_OP_NEXT, &request,
	    sizeof(request), &reply, &payload,
	    notify_rpc_timeout(timeout_ms)) == -1) {
		error = errno;
		if (connection_lost(error) && reconnect_locked(client) == 0) {
			memset(event, 0, sizeof(*event));
			event->type = NOTIFY_EVENT_RESET;
			event->router_epoch = client->router_epoch;
			result = sizeof(*event);
			error = 0;
		} else {
			if (connection_unusable(error))
				disconnect_locked(client);
			result = -1;
		}
	} else if (payload > capacity) {
		error = EMSGSIZE;
		result = -1;
	} else {
		message = (void *)reply.bytes;
		memcpy(event, message + 1, payload);
		if (event->router_epoch != client->router_epoch) {
			error = EPROTO;
			result = -1;
			disconnect_locked(client);
		} else {
			error = 0;
			result = (ssize_t)payload;
		}
	}
	pthread_mutex_unlock(&client->lock);
	NOTIFY_PROBE_NEXT(timeout_ms, error);
	errno = error;
	return (result);
}

int
notify_timer_add(struct notify_client *client, uint64_t timer_id,
    uint32_t interval_ms, uint32_t flags)
{
	struct notify_timer_request request;

	if (client == NULL || client->owner != getpid() || timer_id == 0 ||
	    interval_ms == 0 || interval_ms > NOTIFY_MAX_TIMER_INTERVAL_MS ||
	    (flags & ~NOTIFY_TIMER_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.timer_id = timer_id;
	request.interval_ms = interval_ms;
	request.flags = flags;
	return (simple_rpc(client, NOTIFY_OP_TIMER_ADD, &request,
	    sizeof(request)));
}

int
notify_timer_cancel(struct notify_client *client, uint64_t timer_id)
{
	struct notify_timer_cancel_request request;

	if (client == NULL || client->owner != getpid() || timer_id == 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.timer_id = timer_id;
	return (simple_rpc(client, NOTIFY_OP_TIMER_CANCEL, &request,
	    sizeof(request)));
}

int
notify_stats(struct notify_client *client, struct notify_stats *stats)
{
	union notify_buffer reply;
	size_t payload;
	int error, result;

	if (client == NULL || client->owner != getpid() || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	pthread_mutex_lock(&client->lock);
	if (client->channel == NULL && reconnect_locked(client) == -1)
		result = -1;
	else
		result = rpc_locked(client, NOTIFY_OP_STATS, NULL, 0, &reply,
		    &payload, 30000);
	if (result == -1)
		error = errno;
	else if (payload != sizeof(*stats)) {
		result = -1;
		error = EPROTO;
	} else {
		memcpy(stats, (struct notify_msg *)reply.bytes + 1,
		    sizeof(*stats));
		error = 0;
	}
	if (result == -1 && connection_unusable(error))
		disconnect_locked(client);
	pthread_mutex_unlock(&client->lock);
	errno = error;
	return (result);
}
