/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <notifycmp.h>
#include <notifycmp_server.h>

#include "fake_service.h"

struct service_context { int unused; };
struct service_session { unsigned ident; };

static struct service_context context;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, subscriptions, publishes, concurrent;
static unsigned max_concurrent;
static uint16_t fail_opcode;
static uint64_t epoch = 101;
static enum fake_service_fault next_fault;
static uint8_t last_payload[NOTIFYCMP_MAX_PAYLOAD];
static size_t last_payload_length;

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = subscriptions = publishes = concurrent = 0;
	max_concurrent = 0;
	last_payload_length = 0;
	fail_opcode = 0;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	epoch++;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fault_next(enum fake_service_fault fault)
{

	pthread_mutex_lock(&lock);
	next_fault = fault;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_next(void)
{
	pthread_mutex_lock(&lock);
	fail_opcode = NOTIFYCMP_OP_NEXT;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail_opcode(uint16_t opcode)
{

	pthread_mutex_lock(&lock);
	fail_opcode = opcode;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, field) \
	unsigned name(void) { unsigned value; pthread_mutex_lock(&lock); \
	value = field; pthread_mutex_unlock(&lock); return (value); }
COUNTER(fake_service_created, created)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_subscriptions, subscriptions)
COUNTER(fake_service_publishes, publishes)
COUNTER(fake_service_max_concurrent, max_concurrent)

ssize_t
fake_service_last_payload(void *buffer, size_t capacity)
{
	ssize_t result;

	pthread_mutex_lock(&lock);
	if (capacity < last_payload_length ||
	    (last_payload_length != 0 && buffer == NULL)) {
		errno = EMSGSIZE;
		result = -1;
	} else {
		memcpy(buffer, last_payload, last_payload_length);
		result = (ssize_t)last_payload_length;
	}
	pthread_mutex_unlock(&lock);
	return (result);
}

int
service_acquire(struct service_context **result)
{

	if (result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*result = &context;
	return (0);
}

void
service_release(struct service_context *service __unused)
{
}

int
service_connect(struct service_context *service, const char *name, int *fd)
{

	if (service != &context || name == NULL ||
	    strcmp(name, NOTIFYCMP_INTERFACE) != 0 || fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fd == -1 ? -1 : 0);
}

int
service_session_create(int fd, struct service_session **result)
{
	struct service_session *session;

	if (fd < 0 || result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	session = calloc(1, sizeof(*session));
	if (session == NULL)
		return (-1);
	close(fd);
	pthread_mutex_lock(&lock);
	session->ident = ++created;
	pthread_mutex_unlock(&lock);
	*result = session;
	return (0);
}

void
service_session_close(struct service_session *session)
{

	if (session == NULL)
		return;
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	free(session);
}

int
service_session_fail(struct service_session *session __unused, int error)
{

	errno = error;
	return (error > 0 && error <= ELAST ? 0 : -1);
}

static int
reply_copy(struct service_reply *reply, const void *data, size_t length)
{

	if (reply == NULL || reply->size != sizeof(*reply) ||
	    reply->capacity < length) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(reply->data, data, length);
	reply->length = length;
	reply->nfds = 0;
	return (0);
}

int
service_session_call(struct service_session *session,
    const struct service_message *outgoing, struct service_reply *reply,
    const struct service_call_options *options __unused)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
	} storage;
	struct notifycmp_hello_reply *hello;
	struct notifycmp_state_reply *state;
	struct notifycmp_state_set_request state_request;
	const struct notifycmp_msg *request;
	const struct notifycmp_publish_request *publish_request;
	struct notifycmp_msg *response;
	enum fake_service_fault fault;
	bool fail;
	int result;
	size_t length;

	if (session == NULL || outgoing == NULL || reply == NULL ||
	    outgoing->data == NULL || outgoing->length < sizeof(*request)) {
		errno = EINVAL;
		return (-1);
	}
	request = outgoing->data;
	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > max_concurrent)
		max_concurrent = concurrent;
	fail = fail_opcode == request->opcode;
	fault = next_fault;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	if (fail)
		fail_opcode = 0;
	if (request->opcode == NOTIFYCMP_OP_SUBSCRIBE)
		subscriptions++;
	if (!fail && request->opcode == NOTIFYCMP_OP_PUBLISH) {
		publishes++;
		publish_request = (const void *)(request + 1);
		if (outgoing->length >= sizeof(*request) +
		    sizeof(*publish_request) &&
		    publish_request->payload_length <= sizeof(last_payload) &&
		    outgoing->length == sizeof(*request) +
		    sizeof(*publish_request) + publish_request->payload_length) {
			last_payload_length = publish_request->payload_length;
			memcpy(last_payload, publish_request + 1,
			    last_payload_length);
		}
	}
	pthread_mutex_unlock(&lock);
	if (request->opcode != NOTIFYCMP_OP_HELLO)
		usleep((session->ident & 1U) != 0 ? 60000 : 5000);
	if (fail || fault == FAKE_SERVICE_FAULT_TIMEOUT) {
		pthread_mutex_lock(&lock);
		concurrent--;
		pthread_mutex_unlock(&lock);
		errno = fail ? ECONNRESET : ETIMEDOUT;
		return (-1);
	}
	memset(&storage, 0, sizeof(storage));
	response = (void *)storage.bytes;
	if (notifycmp_message_init_reply(response, request, 0) == -1)
		return (-1);
	length = sizeof(*response);
	switch (request->opcode) {
	case NOTIFYCMP_OP_HELLO:
		hello = (void *)(response + 1);
		hello->version = NOTIFYCMP_ABI_VERSION;
		hello->features = NOTIFYCMP_FEATURE_PUBSUB |
		    NOTIFYCMP_FEATURE_TIMERS | NOTIFYCMP_FEATURE_BOUNDED_QUEUE |
		    NOTIFYCMP_FEATURE_STATE | NOTIFYCMP_FEATURE_LOSS_REPORTING;
		hello->max_topic = NOTIFYCMP_MAX_TOPIC;
		hello->max_payload = NOTIFYCMP_MAX_PAYLOAD;
		hello->max_subscriptions = NOTIFYCMP_MAX_SUBSCRIPTIONS;
		hello->queue_depth = NOTIFYCMP_DEFAULT_QUEUE;
		hello->max_timers = NOTIFYCMP_MAX_TIMERS;
		hello->max_states = NOTIFYCMP_MAX_STATES;
		hello->router_epoch = epoch;
		length += sizeof(*hello);
		if (fault == FAKE_SERVICE_FAULT_INVALID_HELLO)
			hello->features = 0;
		break;
	case NOTIFYCMP_OP_STATS:
		length += sizeof(struct notifycmp_stats);
		break;
	case NOTIFYCMP_OP_STATE_SET:
	case NOTIFYCMP_OP_STATE_GET:
		state = (void *)(response + 1);
		state->router_epoch = epoch;
		state->generation = 1;
		if (request->opcode == NOTIFYCMP_OP_STATE_SET) {
			memcpy(&state_request, request + 1, sizeof(state_request));
			state->state = state_request.state;
		}
		if (fault == FAKE_SERVICE_FAULT_INVALID_STATE)
			state->generation = 0;
		length += sizeof(*state);
		break;
	case NOTIFYCMP_OP_NEXT:
		response->status = -EAGAIN;
		break;
	default:
		break;
	}
	if (fault == FAKE_SERVICE_FAULT_TRUNCATE)
		length = sizeof(*response) - 1;
	else if (fault == FAKE_SERVICE_FAULT_WRONG_OPCODE)
		response->opcode = request->opcode == NOTIFYCMP_OP_STATS ?
		    NOTIFYCMP_OP_PUBLISH : NOTIFYCMP_OP_STATS;
	else if (fault == FAKE_SERVICE_FAULT_STATUS) {
		response->status = -EPERM;
		length = sizeof(*response);
	}
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
	result = reply_copy(reply, storage.bytes, length);
	if (result == 0 && fault == FAKE_SERVICE_FAULT_ATTACHED_FD)
		reply->nfds = 1;
	return (result);
}

int
service_session_receive_event(struct service_session *session __unused,
    struct service_reply *reply __unused,
    const struct service_call_options *options __unused)
{

	errno = ENOTSUP;
	return (-1);
}
