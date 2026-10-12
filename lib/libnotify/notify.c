/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libnotify: the system.Notify client over the generated bsd.notify.v1
 * bindings (notify.fidl) on a native capability channel.  Calls on a client
 * are serialized.  A lost provider or a malformed reply drops the session;
 * the next call reconnects to the same endpoint and restores the client's
 * subscriptions (notify_next() reports that as a RESET event).
 */

#include <sys/param.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.notify.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

#include <libservice.h>
#include <service_runtime.h>

#include "notify.h"
#include "notify_server.h"
#include "notify_internal.h"
#include "notify_probes.h"

#define	NOTIFY_CALL_TIMEOUT_MS	30000U

struct notify_client {
	struct fidl_bsd_connection *connection;
	const char		*interface;	/* endpoint name for (re)connects */
	pid_t			 owner;
	uint64_t		 router_epoch;
	uint32_t		 features;
	pthread_mutex_t		 lock;
	size_t			 nsubscriptions;
	char			 subscriptions[NOTIFY_MAX_SUBSCRIPTIONS]
				     [NOTIFY_MAX_TOPIC + 1];
};

/* One call's completion, filled by the generated callbacks. */
struct call {
	bool		 done;
	bool		 malformed;
	int		 error;		/* transport or application errno */
	uint32_t	 txid;
	union {
		struct bsd_notify_v1_Limits limits;
		struct bsd_notify_v1_StateValue state;
		struct bsd_notify_v1_StateWatchValue watch;
		struct bsd_notify_v1_Stats stats;
		struct {
			struct notify_event *event;
			size_t capacity;
			size_t length;
		} next;
		struct {
			uint32_t cursor;	/* the cursor sent */
			uint32_t next_cursor;
			uint32_t total;
			size_t count;
			void *out;		/* subscription or timer info */
			size_t capacity;
			size_t offset;		/* entries enumerated so far */
		} list;
	} u;
};

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

static void
malformed(struct call *call)
{

	call->malformed = true;
	call->error = EPROTO;
}

/* A result union's error: an errno in 1..ELAST, anything else malformed. */
static void
domain_error(struct call *call, uint32_t error)
{

	if (error == 0 || error > ELAST)
		malformed(call);
	else
		call->error = (int)error;
}

/* The tag check every result union shares; true when value is a response. */
#define	RESULT_OK(call, value, type)					\
	((value) == NULL ? (malformed(call), false) :			\
	(value)->tag == type##_err_tag ?				\
	    (domain_error(call, (value)->value.err), false) :		\
	(value)->tag != type##_response_tag ?				\
	    (malformed(call), false) : true)

static void
info_reply(void *context, int error, struct bsd_notify_v1_ProtocolInfo *value)
{
	struct call *call = context;

	call->done = true;
	call->error = error;
	if (error == 0 && (value == NULL ||
	    value->wire_version != NOTIFY_WIRE_VERSION)) {
		call->malformed = true;
		call->error = EPROTONOSUPPORT;
	}
}

static void
hello_reply(void *context, int error,
    struct bsd_notify_v1_Notify_Hello_Result *value)
{
	struct call *call = context;
	const struct bsd_notify_v1_Limits *hello;

	call->done = true;
	call->error = error;
	if (error != 0 ||
	    !RESULT_OK(call, value, bsd_notify_v1_Notify_Hello_Result))
		return;
	hello = &value->value.response;
	/* The limits every release has advertised. */
	if ((hello->features & ~NOTIFY_FEATURE_STATE_WATCH) !=
	    (NOTIFY_FEATURE_PUBSUB | NOTIFY_FEATURE_TIMERS |
	    NOTIFY_FEATURE_BOUNDED_QUEUE | NOTIFY_FEATURE_STATE |
	    NOTIFY_FEATURE_LOSS_REPORTING) ||
	    hello->max_topic != NOTIFY_MAX_TOPIC ||
	    hello->max_payload != NOTIFY_MAX_PAYLOAD ||
	    hello->max_subscriptions != NOTIFY_MAX_SUBSCRIPTIONS ||
	    hello->queue_depth == 0 || hello->queue_depth > NOTIFY_DEFAULT_QUEUE ||
	    hello->max_timers != NOTIFY_MAX_TIMERS ||
	    hello->max_states != NOTIFY_MAX_STATES ||
	    hello->router_epoch == 0) {
		malformed(call);
		return;
	}
	call->u.limits = *hello;
}

#define	EMPTY_REPLY(name, type)						\
static void								\
name(void *context, int error, struct type *value)			\
{									\
	struct call *call = context;					\
									\
	call->done = true;						\
	call->error = error;						\
	if (error == 0)							\
		(void)RESULT_OK(call, value, type);			\
}
EMPTY_REPLY(subscribe_reply, bsd_notify_v1_Notify_Subscribe_Result)
EMPTY_REPLY(unsubscribe_reply, bsd_notify_v1_Notify_Unsubscribe_Result)
EMPTY_REPLY(publish_reply, bsd_notify_v1_Notify_Publish_Result)
EMPTY_REPLY(timer_add_reply, bsd_notify_v1_Notify_TimerAdd_Result)
EMPTY_REPLY(timer_cancel_reply, bsd_notify_v1_Notify_TimerCancel_Result)
EMPTY_REPLY(state_clear_reply, bsd_notify_v1_Notify_StateClear_Result)

#define	STATE_REPLY(name, type)						\
static void								\
name(void *context, int error, struct type *value)			\
{									\
	struct call *call = context;					\
									\
	call->done = true;						\
	call->error = error;						\
	if (error == 0 && RESULT_OK(call, value, type))			\
		call->u.state = value->value.response;			\
}
STATE_REPLY(state_set_reply, bsd_notify_v1_Notify_StateSet_Result)
STATE_REPLY(state_get_reply, bsd_notify_v1_Notify_StateGet_Result)

static void
state_watch_reply(void *context, int error,
    struct bsd_notify_v1_Notify_StateWatch_Result *value)
{
	struct call *call = context;
	const struct bsd_notify_v1_StateWatchValue *state;

	call->done = true;
	call->error = error;
	if (error != 0 ||
	    !RESULT_OK(call, value, bsd_notify_v1_Notify_StateWatch_Result))
		return;
	state = &value->value.response;
	if (state->watch_epoch == 0 || state->generation == 0 ||
	    (!state->present && state->state != 0)) {
		malformed(call);
		return;
	}
	call->u.watch = *state;
}

static void
stats_reply(void *context, int error,
    struct bsd_notify_v1_Notify_GetStats_Result *value)
{
	struct call *call = context;

	call->done = true;
	call->error = error;
	if (error == 0 &&
	    RESULT_OK(call, value, bsd_notify_v1_Notify_GetStats_Result))
		call->u.stats = value->value.response;
}

/*
 * Rebuild the historical notify_event record in the caller's buffer and
 * apply the same event rules as before.
 */
static void
next_reply(void *context, int error,
    struct bsd_notify_v1_Notify_Next_Result *value)
{
	struct call *call = context;
	const struct bsd_notify_v1_Event *in;
	struct notify_event *out;
	size_t length;

	call->done = true;
	call->error = error;
	if (error != 0 ||
	    !RESULT_OK(call, value, bsd_notify_v1_Notify_Next_Result))
		return;
	in = &value->value.response;
	length = sizeof(*out) + in->publisher_size + in->topic_size +
	    in->payload_size;
	if (length > call->u.next.capacity) {
		/* The caller's buffer, not the provider, is at fault. */
		call->error = EMSGSIZE;
		return;
	}
	out = call->u.next.event;
	memset(out, 0, sizeof(*out));
	out->type = in->type;
	out->flags = in->flags;
	out->router_epoch = in->router_epoch;
	out->sequence = in->sequence;
	out->timestamp_ns = in->timestamp_ns;
	out->timer_id = in->timer_id;
	out->generation = in->generation;
	out->state = in->state;
	out->lost_count = in->lost_count;
	out->publisher_length = (uint16_t)in->publisher_size;
	out->topic_length = (uint16_t)in->topic_size;
	out->payload_length = (uint32_t)in->payload_size;
	memcpy(out->data, in->publisher, in->publisher_size);
	memcpy(out->data + in->publisher_size, in->topic, in->topic_size);
	memcpy(out->data + in->publisher_size + in->topic_size, in->payload,
	    in->payload_size);
	if (notify_validate_event(out, length) == -1) {
		malformed(call);
		return;
	}
	call->u.next.length = length;
}

/* A page must report consistent counts and strictly advance the cursor. */
static bool
page_valid(const struct call *call, size_t count, uint32_t next_cursor,
    uint32_t total)
{

	return (count <= NOTIFY_LIST_MAX_ENTRIES && count <= total &&
	    next_cursor <= total &&
	    (next_cursor == 0 || next_cursor > call->u.list.cursor));
}

static void
subscriptions_reply(void *context, int error,
    struct bsd_notify_v1_Notify_ListSubscriptions_Result *value)
{
	struct call *call = context;
	const struct bsd_notify_v1_SubscriptionPage *page;
	struct notify_subscription_info *out = call->u.list.out;
	size_t i;

	call->done = true;
	call->error = error;
	if (error != 0 || !RESULT_OK(call, value,
	    bsd_notify_v1_Notify_ListSubscriptions_Result))
		return;
	page = &value->value.response;
	if (!page_valid(call, page->topics_size, page->next_cursor,
	    page->total)) {
		malformed(call);
		return;
	}
	for (i = 0; i < page->topics_size; i++)
		if (notify_validate_topic(page->topics[i].data,
		    page->topics[i].data_size) == -1) {
			malformed(call);
			return;
		}
	for (i = 0; i < page->topics_size; i++) {
		size_t index = call->u.list.offset + i;

		if (index < call->u.list.capacity) {
			memcpy(out[index].topic, page->topics[i].data,
			    page->topics[i].data_size);
			out[index].topic[page->topics[i].data_size] = '\0';
		}
	}
	call->u.list.count = page->topics_size;
	call->u.list.next_cursor = page->next_cursor;
	call->u.list.total = page->total;
}

static void
timers_reply(void *context, int error,
    struct bsd_notify_v1_Notify_ListTimers_Result *value)
{
	struct call *call = context;
	const struct bsd_notify_v1_TimerPage *page;
	struct notify_timer_info *out = call->u.list.out;
	size_t i;

	call->done = true;
	call->error = error;
	if (error != 0 ||
	    !RESULT_OK(call, value, bsd_notify_v1_Notify_ListTimers_Result))
		return;
	page = &value->value.response;
	if (!page_valid(call, page->timers_size, page->next_cursor,
	    page->total)) {
		malformed(call);
		return;
	}
	for (i = 0; i < page->timers_size; i++)
		if (page->timers[i].timer_id == 0 ||
		    page->timers[i].interval_ms == 0 ||
		    page->timers[i].interval_ms > NOTIFY_MAX_TIMER_INTERVAL_MS ||
		    (page->timers[i].flags & ~NOTIFY_TIMER_F_MASK) != 0) {
			malformed(call);
			return;
		}
	for (i = 0; i < page->timers_size; i++) {
		size_t index = call->u.list.offset + i;

		if (index < call->u.list.capacity) {
			out[index].timer_id = page->timers[i].timer_id;
			out[index].interval_ms = page->timers[i].interval_ms;
			out[index].flags = page->timers[i].flags;
			out[index].next_fire_ms = page->timers[i].next_fire_ms;
		}
	}
	call->u.list.count = page->timers_size;
	call->u.list.next_cursor = page->next_cursor;
	call->u.list.total = page->total;
}

/*
 * Wait for an issued call (client lock held).  timeout_ms bounds the wait;
 * NOTIFY_TIMEOUT_INFINITE waits without one, and a caller's
 * service_budget_begin() shortens either.  A timeout cancels just this call
 * and keeps the session.  Returns 0 or an errno value.
 */
static int
wait_locked(struct notify_client *client, uint16_t opcode, int issue_error,
    struct call *call, uint32_t timeout_ms)
{
	struct timespec deadline;
	int error;

	if (issue_error != 0) {
		NOTIFY_PROBE_RPC(opcode, issue_error);
		return (issue_error);
	}
	if (service_budget_timeout(&timeout_ms) == -1) {
		error = errno;
		(void)fidl_bsd_connection_cancel(client->connection, call->txid);
		return (error);
	}
	if (timeout_ms == NOTIFY_TIMEOUT_INFINITE) {
		error = 0;
		while (!call->done) {
			error = fidl_bsd_connection_poll(client->connection, -1);
			if (error != 0 && !call->done)
				break;
			error = 0;
		}
	} else {
		error = fidl_bsd_sync_deadline(&deadline, timeout_ms);
		if (error == 0)
			error = fidl_bsd_sync_wait_txid(client->connection,
			    &call->done, &deadline, call->txid);
	}
	NOTIFY_PROBE_RPC(opcode, error != 0 ? error : call->error);
	if (error == 0 && call->malformed) {
		NOTIFY_PROBE_REJECT(opcode, EPROTO);
		/* A malformed reply ends the session. */
		fidl_bsd_connection_close(client->connection, EPROTO);
		return (call->error);
	}
	if (error == 0 && call->error != 0)
		NOTIFY_PROBE_REJECT(opcode, call->error);
	return (error != 0 ? error : call->error);
}

/* The session cannot carry another call: reconnect before the next one. */
static bool
session_lost(struct notify_client *client, int error)
{

	return (error == EPROTO || error == EPROTONOSUPPORT ||
	    (client->connection != NULL &&
	    fidl_bsd_connection_error(client->connection) != 0));
}

static void
disconnect_locked(struct notify_client *client)
{

	if (client->connection != NULL)
		fidl_bsd_connection_destroy(client->connection);
	client->connection = NULL;
}

/* Negotiate the wire version and read the session limits. */
static int
hello_locked(struct notify_client *client, uint32_t features,
    struct bsd_notify_v1_Limits *limits)
{
	struct bsd_notify_v1_HelloRequest request = { features };
	struct call call = { 0 };
	int error;

	error = wait_locked(client, NOTIFY_OP_HELLO,
	    bsd_notify_v1_Notify_Hello(client->connection, &request,
	    hello_reply, &call, &call.txid), &call, NOTIFY_CALL_TIMEOUT_MS);
	if (error != 0)
		return (errno = error, -1);
	*limits = call.u.limits;
	return (0);
}

/* Adopt fd (consumed) as the client's session and negotiate it. */
static int
connect_locked(struct notify_client *client, int fd)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct bsd_notify_v1_Limits limits;
	struct fidl_bsd_empty empty = { 0 };
	struct call call = { 0 };
	int error;

	options.max_pending_requests = 1;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		(void)close(fd);
		client->connection = NULL;
		return (errno = error, -1);
	}
	error = wait_locked(client, NOTIFY_OP_HELLO,
	    bsd_notify_v1_Notify_GetProtocolInfo(client->connection, &empty,
	    info_reply, &call, &call.txid), &call, NOTIFY_CALL_TIMEOUT_MS);
	if (error != 0 || hello_locked(client, 0, &limits) == -1) {
		error = error != 0 ? error : errno;
		disconnect_locked(client);
		return (errno = error, -1);
	}
	client->router_epoch = limits.router_epoch;
	client->features = limits.features;
	return (0);
}

int
notify_client_adopt(int fd, struct notify_client **result)
{
	struct notify_client *client;
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
	client->interface = NOTIFY_INTERFACE;
	if ((error = pthread_mutex_init(&client->lock, NULL)) != 0) {
		free(client);
		(void)close(fd);
		errno = error;
		return (-1);
	}
	if (connect_locked(client, fd) == -1) {
		error = errno;
		(void)pthread_mutex_destroy(&client->lock);
		free(client);
		errno = error;
		return (-1);
	}
	*result = client;
	return (0);
}

/*
 * Open a session on one of the two bsdnotify endpoints.  The name is one of
 * the library's own constants, never caller-supplied: applications do not
 * name providers.  The client remembers which endpoint it was opened on so a
 * transparent reconnect lands on the same tier.
 */
static int
notify_client_open_interface(const char *interface,
    struct notify_client **result)
{
	int error, fd;

	if (result == NULL)
		return (errno = EINVAL, -1);
	*result = NULL;
	fd = -1;
	error = service_open(interface, &fd) == -1 ? errno : 0;
	if (fd == -1)
		return (errno = error, -1);
	if (notify_client_adopt(fd, result) == -1)
		return (-1);
	(*result)->interface = interface;
	return (0);
}

int
notify_client_open(struct notify_client **result)
{

	return (notify_client_open_interface(NOTIFY_INTERFACE, result));
}

int
notify_client_open_system(struct notify_client **result)
{

	return (notify_client_open_interface(NOTIFY_SYSTEM_INTERFACE, result));
}

static int topic_rpc_locked(struct notify_client *, uint16_t, const char *);

static int
reconnect_locked(struct notify_client *client)
{
	size_t i;
	int error, fd;

	disconnect_locked(client);
	fd = -1;
	error = service_open(client->interface, &fd) == -1 ? errno : 0;
	if (fd == -1) {
		errno = error;
		return (-1);
	}
	if (connect_locked(client, fd) == -1)
		goto fail;
	for (i = 0; i < client->nsubscriptions; i++)
		if (topic_rpc_locked(client, NOTIFY_OP_SUBSCRIBE,
		    client->subscriptions[i]) == -1)
			goto fail;
	NOTIFY_PROBE_RECONNECT(client->router_epoch, 0);
	return (0);
fail:
	error = errno;
	disconnect_locked(client);
	NOTIFY_PROBE_RECONNECT(0, error);
	errno = error;
	return (-1);
}

void
notify_client_close(struct notify_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid()) {
		disconnect_locked(client);
		(void)pthread_mutex_destroy(&client->lock);
	}
	memset(client, 0, sizeof(*client));
	free(client);
}

/*
 * Lock the client and make sure it has a session; on failure the lock is
 * released and -1 returned with errno set.
 */
static int
begin(struct notify_client *client) __no_lock_analysis
{
	int error;

	if (client == NULL || client->owner != getpid()) {
		errno = EINVAL;
		return (-1);
	}
	pthread_mutex_lock(&client->lock);
	if (client->connection == NULL && reconnect_locked(client) == -1) {
		error = errno;
		pthread_mutex_unlock(&client->lock);
		errno = error;
		return (-1);
	}
	return (0);
}

/* Unlock after a call; a lost session is dropped for the next reconnect. */
static int
finish(struct notify_client *client, int error) __no_lock_analysis
{

	if (error != 0 && session_lost(client, error))
		disconnect_locked(client);
	pthread_mutex_unlock(&client->lock);
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

static int
topic_check(const char *topic, size_t *length)
{

	if (topic == NULL)
		return (errno = EINVAL, -1);
	*length = strnlen(topic, NOTIFY_MAX_TOPIC + 1);
	return (notify_validate_topic(topic, *length));
}

/* SUBSCRIBE or UNSUBSCRIBE on the current session (lock held). */
static int
topic_rpc_locked(struct notify_client *client, uint16_t opcode,
    const char *topic)
{
	struct bsd_notify_v1_TopicRequest request;
	struct call call = { 0 };
	size_t length;
	int error;

	if (topic_check(topic, &length) == -1)
		return (-1);
	request.topic = topic;
	request.topic_size = length;
	error = wait_locked(client, opcode, opcode == NOTIFY_OP_SUBSCRIBE ?
	    bsd_notify_v1_Notify_Subscribe(client->connection, &request,
	    subscribe_reply, &call, &call.txid) :
	    bsd_notify_v1_Notify_Unsubscribe(client->connection, &request,
	    unsubscribe_reply, &call, &call.txid), &call,
	    NOTIFY_CALL_TIMEOUT_MS);
	return (error != 0 ? (errno = error, -1) : 0);
}

int
notify_subscribe(struct notify_client *client, const char *topic)
{
	size_t length;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (topic_check(topic, &length) == -1)
		return (-1);
	if (begin(client) == -1)
		return (-1);
	if (client->nsubscriptions == NOTIFY_MAX_SUBSCRIPTIONS)
		error = EOVERFLOW;
	else {
		error = topic_rpc_locked(client, NOTIFY_OP_SUBSCRIBE, topic) ==
		    -1 ? errno : 0;
		if (error == 0) {
			memcpy(client->subscriptions[client->nsubscriptions],
			    topic, length + 1);
			client->nsubscriptions++;
		}
	}
	return (finish(client, error));
}

int
notify_unsubscribe(struct notify_client *client, const char *topic)
{
	size_t i;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1)
		return (-1);
	error = topic_rpc_locked(client, NOTIFY_OP_UNSUBSCRIBE, topic) == -1 ?
	    errno : 0;
	if (error == 0)
		for (i = 0; i < client->nsubscriptions; i++)
			if (strcmp(client->subscriptions[i], topic) == 0) {
				client->nsubscriptions--;
				memcpy(client->subscriptions[i],
				    client->subscriptions[client->nsubscriptions],
				    sizeof(client->subscriptions[i]));
				break;
			}
	return (finish(client, error));
}

int
notify_publish(struct notify_client *client, const char *topic,
    const void *data, size_t length)
{
	struct bsd_notify_v1_PublishRequest request;
	struct call call = { 0 };
	size_t topic_length;
	int error, result;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    (length != 0 && data == NULL) || length > NOTIFY_MAX_PAYLOAD) {
		errno = EINVAL;
		return (-1);
	}
	if (topic_check(topic, &topic_length) == -1)
		return (-1);
	if (begin(client) == -1)
		result = -1;
	else {
		request.topic = topic;
		request.topic_size = topic_length;
		request.payload = __DECONST(uint8_t *, data);
		request.payload_size = length;
		error = wait_locked(client, NOTIFY_OP_PUBLISH,
		    bsd_notify_v1_Notify_Publish(client->connection, &request,
		    publish_reply, &call, &call.txid), &call,
		    NOTIFY_CALL_TIMEOUT_MS);
		result = finish(client, error);
	}
	NOTIFY_PROBE_PUBLISH(__DECONST(char *, topic), length,
	    result == -1 ? errno : 0);
	return (result);
}

int
notify_state_set(struct notify_client *client, const char *topic,
    uint64_t value)
{
	struct bsd_notify_v1_StateSetRequest request;
	struct call call = { 0 };
	size_t length;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (topic_check(topic, &length) == -1)
		return (-1);
	if (begin(client) == -1)
		return (-1);
	request.topic = topic;
	request.topic_size = length;
	request.state = value;
	error = wait_locked(client, NOTIFY_OP_STATE_SET,
	    bsd_notify_v1_Notify_StateSet(client->connection, &request,
	    state_set_reply, &call, &call.txid), &call, NOTIFY_CALL_TIMEOUT_MS);
	if (error == 0 && (call.u.state.router_epoch != client->router_epoch ||
	    call.u.state.generation == 0 || call.u.state.state != value))
		error = EPROTO;
	return (finish(client, error));
}

int
notify_state_get(struct notify_client *client, const char *topic,
    struct notify_state_reply *state)
{
	struct bsd_notify_v1_TopicRequest request;
	struct call call = { 0 };
	size_t length;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    state == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (topic_check(topic, &length) == -1)
		return (-1);
	if (begin(client) == -1)
		return (-1);
	request.topic = topic;
	request.topic_size = length;
	error = wait_locked(client, NOTIFY_OP_STATE_GET,
	    bsd_notify_v1_Notify_StateGet(client->connection, &request,
	    state_get_reply, &call, &call.txid), &call, NOTIFY_CALL_TIMEOUT_MS);
	if (error == 0 && (call.u.state.router_epoch != client->router_epoch ||
	    call.u.state.generation == 0))
		error = EPROTO;
	if (error == 0) {
		state->router_epoch = call.u.state.router_epoch;
		state->generation = call.u.state.generation;
		state->state = call.u.state.state;
	}
	return (finish(client, error));
}

int
notify_state_watch(struct notify_client *client, const char *topic,
    struct notify_state_watch_reply *state, uint32_t timeout_ms)
{
	struct bsd_notify_v1_StateWatchRequest request;
	struct bsd_notify_v1_Limits hello;
	struct call call = { 0 };
	size_t length;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL ||
	    state == NULL)
		return (errno = EINVAL, -1);
	if (topic_check(topic, &length) == -1)
		return (-1);
	if (begin(client) == -1)
		return (-1);
	error = 0;
	if ((client->features & NOTIFY_FEATURE_STATE_WATCH) == 0) {
		if (hello_locked(client, NOTIFY_FEATURE_STATE_WATCH,
		    &hello) == -1)
			error = errno;
		else if (hello.router_epoch != client->router_epoch)
			error = EPROTO;
		else {
			client->features = hello.features;
			if ((hello.features & NOTIFY_FEATURE_STATE_WATCH) == 0)
				error = EOPNOTSUPP;
		}
	}
	if (error == 0) {
		request.topic = topic;
		request.topic_size = length;
		request.timeout_ms = timeout_ms;
		error = wait_locked(client, NOTIFY_OP_STATE_WATCH,
		    bsd_notify_v1_Notify_StateWatch(client->connection,
		    &request, state_watch_reply, &call, &call.txid), &call,
		    notify_rpc_timeout(timeout_ms));
	}
	if (error == 0) {
		memset(state, 0, sizeof(*state));
		state->watch_epoch = call.u.watch.watch_epoch;
		state->generation = call.u.watch.generation;
		state->state = call.u.watch.state;
		state->present = call.u.watch.present ? 1 : 0;
	}
	/* A transport timeout cannot leave a hidden pending server watch. */
	if (error == ETIMEDOUT)
		disconnect_locked(client);
	return (finish(client, error));
}

int
notify_state_clear(struct notify_client *client, const char *topic)
{
	struct bsd_notify_v1_TopicRequest request;
	struct call call = { 0 };
	size_t length;
	int error;

	if (client == NULL || client->owner != getpid() || topic == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (topic_check(topic, &length) == -1)
		return (-1);
	if (begin(client) == -1)
		return (-1);
	request.topic = topic;
	request.topic_size = length;
	error = wait_locked(client, NOTIFY_OP_STATE_CLEAR,
	    bsd_notify_v1_Notify_StateClear(client->connection, &request,
	    state_clear_reply, &call, &call.txid), &call,
	    NOTIFY_CALL_TIMEOUT_MS);
	return (finish(client, error));
}

ssize_t
notify_next(struct notify_client *client, struct notify_event *event,
    size_t capacity, uint32_t timeout_ms) __no_lock_analysis
{
	struct bsd_notify_v1_NextRequest request = { timeout_ms };
	struct call call = { 0 };
	ssize_t result;
	int error;

	if (client == NULL || client->owner != getpid() || event == NULL ||
	    capacity < sizeof(*event)) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1) {
		NOTIFY_PROBE_NEXT(timeout_ms, errno);
		return (-1);
	}
	call.u.next.event = event;
	call.u.next.capacity = capacity;
	error = wait_locked(client, NOTIFY_OP_NEXT,
	    bsd_notify_v1_Notify_Next(client->connection, &request, next_reply,
	    &call, &call.txid), &call, notify_rpc_timeout(timeout_ms));
	result = -1;
	if (error == 0 && event->router_epoch != client->router_epoch)
		error = EPROTO;
	else if (error == 0)
		result = (ssize_t)call.u.next.length;
	else if (error != EPROTO && session_lost(client, error) &&
	    reconnect_locked(client) == 0) {
		/* The provider went away: report the fresh session. */
		memset(event, 0, sizeof(*event));
		event->type = NOTIFY_EVENT_RESET;
		event->router_epoch = client->router_epoch;
		result = sizeof(*event);
		error = 0;
	}
	if (error != 0)
		(void)finish(client, error);
	else
		pthread_mutex_unlock(&client->lock);
	NOTIFY_PROBE_NEXT(timeout_ms, error);
	errno = error;
	return (result);
}

int
notify_timer_add(struct notify_client *client, uint64_t timer_id,
    uint32_t interval_ms, uint32_t flags)
{
	struct bsd_notify_v1_TimerRequest request;
	struct call call = { 0 };

	if (client == NULL || client->owner != getpid() || timer_id == 0 ||
	    interval_ms == 0 || interval_ms > NOTIFY_MAX_TIMER_INTERVAL_MS ||
	    (flags & ~NOTIFY_TIMER_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1)
		return (-1);
	request.timer_id = timer_id;
	request.interval_ms = interval_ms;
	request.flags = flags;
	return (finish(client, wait_locked(client, NOTIFY_OP_TIMER_ADD,
	    bsd_notify_v1_Notify_TimerAdd(client->connection, &request,
	    timer_add_reply, &call, &call.txid), &call,
	    NOTIFY_CALL_TIMEOUT_MS)));
}

int
notify_timer_cancel(struct notify_client *client, uint64_t timer_id)
{
	struct bsd_notify_v1_TimerCancelRequest request;
	struct call call = { 0 };

	if (client == NULL || client->owner != getpid() || timer_id == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1)
		return (-1);
	request.timer_id = timer_id;
	return (finish(client, wait_locked(client, NOTIFY_OP_TIMER_CANCEL,
	    bsd_notify_v1_Notify_TimerCancel(client->connection, &request,
	    timer_cancel_reply, &call, &call.txid), &call,
	    NOTIFY_CALL_TIMEOUT_MS)));
}

/*
 * Enumerate the caller's own subscriptions or timers page by page.  Writes
 * up to capacity entries into out and returns the total the session holds
 * (more than capacity signals truncation).  Fails closed on any protocol or
 * transport error.
 */
static ssize_t
list_all(struct notify_client *client, uint16_t opcode, void *out,
    size_t capacity)
{
	struct bsd_notify_v1_ListRequest request;
	struct call call;
	size_t total;
	uint32_t cursor;
	int error;

	if (client == NULL || client->owner != getpid() ||
	    (out == NULL && capacity != 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1)
		return (-1);
	total = 0;
	cursor = 0;
	for (;;) {
		memset(&call, 0, sizeof(call));
		call.u.list.cursor = cursor;
		call.u.list.out = out;
		call.u.list.capacity = capacity;
		call.u.list.offset = total;
		request.cursor = cursor;
		error = wait_locked(client, opcode,
		    opcode == NOTIFY_OP_LIST_SUBSCRIPTIONS ?
		    bsd_notify_v1_Notify_ListSubscriptions(client->connection,
		    &request, subscriptions_reply, &call, &call.txid) :
		    bsd_notify_v1_Notify_ListTimers(client->connection,
		    &request, timers_reply, &call, &call.txid), &call,
		    NOTIFY_CALL_TIMEOUT_MS);
		if (error != 0)
			break;
		total += call.u.list.count;
		cursor = call.u.list.next_cursor;
		if (cursor == 0)
			break;
	}
	if (finish(client, error) == -1)
		return (-1);
	return ((ssize_t)total);
}

ssize_t
notify_list_subscriptions(struct notify_client *client,
    struct notify_subscription_info *out, size_t capacity)
{

	return (list_all(client, NOTIFY_OP_LIST_SUBSCRIPTIONS, out, capacity));
}

ssize_t
notify_list_timers(struct notify_client *client,
    struct notify_timer_info *out, size_t capacity)
{

	return (list_all(client, NOTIFY_OP_LIST_TIMERS, out, capacity));
}

int
notify_stats(struct notify_client *client, struct notify_stats *stats)
{
	struct fidl_bsd_empty empty = { 0 };
	struct call call = { 0 };
	int error;

	if (client == NULL || client->owner != getpid() || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (begin(client) == -1)
		return (-1);
	error = wait_locked(client, NOTIFY_OP_STATS,
	    bsd_notify_v1_Notify_GetStats(client->connection, &empty,
	    stats_reply, &call, &call.txid), &call, NOTIFY_CALL_TIMEOUT_MS);
	if (error == 0) {
		memset(stats, 0, sizeof(*stats));
		stats->published = call.u.stats.published;
		stats->delivered = call.u.stats.delivered;
		stats->dropped = call.u.stats.dropped;
		stats->rejected = call.u.stats.rejected;
		stats->timer_events = call.u.stats.timer_events;
	}
	return (finish(client, error));
}
