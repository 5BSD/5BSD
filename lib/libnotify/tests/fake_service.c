/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted system.Notify provider for the libnotify client tests.  It
 * replaces libservice's service_open(): each call creates a real capability
 * channel served by a bsd.notify.v1 server on its own thread, with
 * per-session subscription and timer bookkeeping for the LIST methods.
 * Faults are armed for the next request; malformed replies are written as
 * raw frames on the request's channel message.  service_budget_timeout() is
 * replaced so an armed timeout costs 300 ms, not the 30 s call deadline.
 */

#include <sys/types.h>

#include <assert.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.notify.v1/c/bsd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <notify.h>

#include "fake_service.h"

int service_open(const char *, int *);
int service_budget_timeout(uint32_t *);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned created, closed, subscriptions, publishes, concurrent;
static unsigned max_concurrent;
static uint16_t fail_opcode;
static uint64_t epoch = 101;
static enum fake_service_fault next_fault;
static uint8_t last_payload[NOTIFY_MAX_PAYLOAD];
static size_t last_payload_length;
static char last_interface[256];
static char refused_interface[256];
static int refused_error;
static unsigned open_connects, system_connects;

struct fake_timer {
	uint64_t	id;
	uint32_t	interval_ms;
	uint32_t	flags;
};

struct session {
	struct fidl_bsd_connection *connection;
	unsigned	ident;
	size_t		ntopics;
	char		topic[NOTIFY_MAX_SUBSCRIPTIONS][NOTIFY_MAX_TOPIC + 1];
	size_t		ntimers;
	struct fake_timer timers[NOTIFY_MAX_TIMERS];
};

void
fake_service_reset(void)
{
	struct timespec deadline;

	/* Let sessions of the previous case finish closing first. */
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	pthread_mutex_lock(&lock);
	while (closed < created &&
	    pthread_cond_timedwait(&changed, &lock, &deadline) == 0)
		;
	created = closed = subscriptions = publishes = concurrent = 0;
	max_concurrent = 0;
	last_payload_length = 0;
	fail_opcode = 0;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	last_interface[0] = '\0';
	refused_interface[0] = '\0';
	refused_error = 0;
	open_connects = system_connects = 0;
	epoch++;
	pthread_mutex_unlock(&lock);
}

void
fake_service_refuse_interface(const char *name, int error)
{
	pthread_mutex_lock(&lock);
	(void)strlcpy(refused_interface, name != NULL ? name : "",
	    sizeof(refused_interface));
	refused_error = error;
	pthread_mutex_unlock(&lock);
}

unsigned
fake_service_connects(const char *name)
{
	unsigned value;

	pthread_mutex_lock(&lock);
	value = strcmp(name, NOTIFY_SYSTEM_INTERFACE) == 0 ? system_connects :
	    strcmp(name, NOTIFY_INTERFACE) == 0 ? open_connects : 0;
	pthread_mutex_unlock(&lock);
	return (value);
}

const char *
fake_service_last_interface(void)
{
	return (last_interface);
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
	fail_opcode = NOTIFY_OP_NEXT;
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
COUNTER(fake_service_subscriptions, subscriptions)
COUNTER(fake_service_publishes, publishes)
COUNTER(fake_service_max_concurrent, max_concurrent)

/*
 * Sessions whose server has ended.  A client drops its channel without
 * waiting for the provider, so allow the server threads a moment to notice.
 */
unsigned
fake_service_closed(void)
{
	unsigned value;

	usleep(50000);
	pthread_mutex_lock(&lock);
	value = closed;
	pthread_mutex_unlock(&lock);
	return (value);
}

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
service_budget_timeout(uint32_t *ms)
{
	if (ms == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	if (next_fault == FAKE_SERVICE_FAULT_TIMEOUT && *ms > 300)
		*ms = 300;
	pthread_mutex_unlock(&lock);
	return (0);
}

/*
 * The scripted outcome for one request: 0 to reply, 1 to leave it
 * unanswered, -1 when the session was closed instead.
 */
static int
begin_request(struct session *s, struct fidl_bsd_request *request,
    uint16_t opcode, enum fake_service_fault *faultp)
{
	enum fake_service_fault fault;
	bool fail;

	pthread_mutex_lock(&lock);
	concurrent++;
	if (concurrent > max_concurrent)
		max_concurrent = concurrent;
	fail = fail_opcode == opcode;
	if (fail)
		fail_opcode = 0;
	fault = next_fault;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	if (opcode == NOTIFY_OP_SUBSCRIBE)
		subscriptions++;
	if (opcode == NOTIFY_OP_PUBLISH && !fail)
		publishes++;
	pthread_mutex_unlock(&lock);
	if (opcode != NOTIFY_OP_HELLO)
		usleep((s->ident & 1U) != 0 ? 60000 : 5000);
	*faultp = fault;
	if (fail) {
		fidl_bsd_connection_close(s->connection, ECONNRESET);
		return (-1);
	}
	if (fault == FAKE_SERVICE_FAULT_TIMEOUT)
		return (1);
	if (fault == FAKE_SERVICE_FAULT_TRUNCATE ||
	    fault == FAKE_SERVICE_FAULT_WRONG_OPCODE ||
	    fault == FAKE_SERVICE_FAULT_ATTACHED_FD) {
		/* A raw reply frame on the request's own reply token. */
		struct channel_message *native = __DECONST(
		    struct channel_message *, fidl_bsd_request_native(request));
		struct {
			uint32_t txid;
			uint8_t flags[3], magic;
			uint64_t ordinal;
		} header;
		struct channel_outgoing outgoing;
		int fd = -1;

		memcpy(&header, channel_message_data(native), sizeof(header));
		if (fault == FAKE_SERVICE_FAULT_WRONG_OPCODE)
			header.ordinal ^= 1;
		outgoing = (struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&header,
		    fault == FAKE_SERVICE_FAULT_TRUNCATE ? sizeof(header) - 1 :
		    sizeof(header));
		if (fault == FAKE_SERVICE_FAULT_ATTACHED_FD) {
			fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
			outgoing.fds = &fd;
			outgoing.nfds = 1;
		}
		(void)channel_send_reply(native, &outgoing);
		if (fd >= 0)
			close(fd);
		return (1);
	}
	return (0);
}

static void
end_request(void)
{
	pthread_mutex_lock(&lock);
	concurrent--;
	pthread_mutex_unlock(&lock);
}

#define	EMPTY_RESULT(type, fault) {					\
	.tag = (fault) == FAKE_SERVICE_FAULT_STATUS ? type##_err_tag :	\
	    type##_response_tag,					\
	.value.err = (fault) == FAKE_SERVICE_FAULT_STATUS ? EPERM : 0 }

static void
on_info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_notify_v1_ProtocolInfo v = { NOTIFY_WIRE_VERSION };
	(void)x;
	(void)e;
	assert(bsd_notify_v1_Notify_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
on_hello(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_HelloRequest *q)
{
	struct bsd_notify_v1_Notify_Hello_Result v = {
		.tag = bsd_notify_v1_Notify_Hello_Result_response_tag
	};
	enum fake_service_fault fault;
	int outcome = begin_request(x, r, NOTIFY_OP_HELLO, &fault);

	if (outcome == 0) {
		v.value.response = (struct bsd_notify_v1_Limits){
			.features = NOTIFY_FEATURE_PUBSUB | NOTIFY_FEATURE_TIMERS |
			    NOTIFY_FEATURE_BOUNDED_QUEUE | NOTIFY_FEATURE_STATE |
			    NOTIFY_FEATURE_LOSS_REPORTING |
			    (q->features & NOTIFY_FEATURE_STATE_WATCH),
			.max_topic = NOTIFY_MAX_TOPIC,
			.max_payload = NOTIFY_MAX_PAYLOAD,
			.max_subscriptions = NOTIFY_MAX_SUBSCRIPTIONS,
			.queue_depth = NOTIFY_DEFAULT_QUEUE,
			.max_timers = NOTIFY_MAX_TIMERS,
			.max_states = NOTIFY_MAX_STATES,
			.router_epoch = epoch
		};
		if (fault == FAKE_SERVICE_FAULT_INVALID_HELLO)
			v.value.response.features = 0;
		(void)bsd_notify_v1_Notify_Hello_reply(c, r, &v);
	}
	end_request();
}

static void
topic_update(struct session *s, const struct bsd_notify_v1_TopicRequest *q,
    bool subscribe)
{
	char name[NOTIFY_MAX_TOPIC + 1];
	size_t i;

	memcpy(name, q->topic, q->topic_size);
	name[q->topic_size] = '\0';
	for (i = 0; i < s->ntopics; i++)
		if (strcmp(s->topic[i], name) == 0)
			break;
	if (subscribe && i == s->ntopics && s->ntopics < NOTIFY_MAX_SUBSCRIPTIONS)
		strlcpy(s->topic[s->ntopics++], name, sizeof(s->topic[0]));
	else if (!subscribe && i < s->ntopics)
		memcpy(s->topic[i], s->topic[--s->ntopics], sizeof(s->topic[0]));
}

static void
on_subscribe(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_TopicRequest *q)
{
	enum fake_service_fault fault;

	if (begin_request(x, r, NOTIFY_OP_SUBSCRIBE, &fault) == 0) {
		struct bsd_notify_v1_Notify_Subscribe_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_Subscribe_Result, fault);

		topic_update(x, q, true);
		(void)bsd_notify_v1_Notify_Subscribe_reply(c, r, &v);
	}
	end_request();
}

static void
on_unsubscribe(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_TopicRequest *q)
{
	enum fake_service_fault fault;

	if (begin_request(x, r, NOTIFY_OP_UNSUBSCRIBE, &fault) == 0) {
		struct bsd_notify_v1_Notify_Unsubscribe_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_Unsubscribe_Result, fault);

		topic_update(x, q, false);
		(void)bsd_notify_v1_Notify_Unsubscribe_reply(c, r, &v);
	}
	end_request();
}

static void
on_publish(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_PublishRequest *q)
{
	enum fake_service_fault fault;

	if (begin_request(x, r, NOTIFY_OP_PUBLISH, &fault) == 0) {
		struct bsd_notify_v1_Notify_Publish_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_Publish_Result, fault);

		pthread_mutex_lock(&lock);
		last_payload_length = q->payload_size;
		memcpy(last_payload, q->payload, q->payload_size);
		pthread_mutex_unlock(&lock);
		(void)bsd_notify_v1_Notify_Publish_reply(c, r, &v);
	}
	end_request();
}

static void
on_next(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_NextRequest *q)
{
	struct bsd_notify_v1_Notify_Next_Result v = {
		.tag = bsd_notify_v1_Notify_Next_Result_err_tag,
		.value.err = EAGAIN
	};
	enum fake_service_fault fault;
	(void)q;

	if (begin_request(x, r, NOTIFY_OP_NEXT, &fault) == 0)
		(void)bsd_notify_v1_Notify_Next_reply(c, r, &v);
	end_request();
}

static void
on_timer_add(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_TimerRequest *q)
{
	struct session *s = x;
	enum fake_service_fault fault;

	if (begin_request(s, r, NOTIFY_OP_TIMER_ADD, &fault) == 0) {
		struct bsd_notify_v1_Notify_TimerAdd_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_TimerAdd_Result, fault);

		if (s->ntimers < NOTIFY_MAX_TIMERS)
			s->timers[s->ntimers++] = (struct fake_timer){
			    q->timer_id, q->interval_ms, q->flags };
		(void)bsd_notify_v1_Notify_TimerAdd_reply(c, r, &v);
	}
	end_request();
}

static void
on_timer_cancel(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_TimerCancelRequest *q)
{
	struct session *s = x;
	enum fake_service_fault fault;

	if (begin_request(s, r, NOTIFY_OP_TIMER_CANCEL, &fault) == 0) {
		struct bsd_notify_v1_Notify_TimerCancel_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_TimerCancel_Result, fault);

		for (size_t i = 0; i < s->ntimers; i++)
			if (s->timers[i].id == q->timer_id) {
				s->timers[i] = s->timers[--s->ntimers];
				break;
			}
		(void)bsd_notify_v1_Notify_TimerCancel_reply(c, r, &v);
	}
	end_request();
}

static void
on_stats(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	enum fake_service_fault fault;
	(void)e;

	if (begin_request(x, r, NOTIFY_OP_STATS, &fault) == 0) {
		struct bsd_notify_v1_Notify_GetStats_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_GetStats_Result, fault);

		if (fault != FAKE_SERVICE_FAULT_STATUS)
			v.value.response = (struct bsd_notify_v1_Stats){ 0 };
		(void)bsd_notify_v1_Notify_GetStats_reply(c, r, &v);
	}
	end_request();
}

static void
state_reply(struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    uint16_t opcode, uint64_t value, enum fake_service_fault fault)
{
	struct bsd_notify_v1_StateValue state = { epoch, 1, value };

	if (fault == FAKE_SERVICE_FAULT_INVALID_STATE)
		state.generation = 0;
	if (opcode == NOTIFY_OP_STATE_SET) {
		struct bsd_notify_v1_Notify_StateSet_Result v = {
			.tag = bsd_notify_v1_Notify_StateSet_Result_response_tag,
			.value.response = state
		};
		(void)bsd_notify_v1_Notify_StateSet_reply(c, r, &v);
	} else {
		struct bsd_notify_v1_Notify_StateGet_Result v = {
			.tag = bsd_notify_v1_Notify_StateGet_Result_response_tag,
			.value.response = state
		};
		(void)bsd_notify_v1_Notify_StateGet_reply(c, r, &v);
	}
}

static void
on_state_set(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_StateSetRequest *q)
{
	enum fake_service_fault fault;

	if (begin_request(x, r, NOTIFY_OP_STATE_SET, &fault) == 0)
		state_reply(c, r, NOTIFY_OP_STATE_SET, q->state, fault);
	end_request();
}

static void
on_state_get(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_notify_v1_TopicRequest *q)
{
	enum fake_service_fault fault;
	(void)q;

	if (begin_request(x, r, NOTIFY_OP_STATE_GET, &fault) == 0)
		state_reply(c, r, NOTIFY_OP_STATE_GET, 0, fault);
	end_request();
}

static void
on_state_clear(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_TopicRequest *q)
{
	enum fake_service_fault fault;
	(void)q;

	if (begin_request(x, r, NOTIFY_OP_STATE_CLEAR, &fault) == 0) {
		struct bsd_notify_v1_Notify_StateClear_Result v =
		    EMPTY_RESULT(bsd_notify_v1_Notify_StateClear_Result, fault);
		(void)bsd_notify_v1_Notify_StateClear_reply(c, r, &v);
	}
	end_request();
}

static void
on_state_watch(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_StateWatchRequest *q)
{
	struct session *s = x;
	enum fake_service_fault fault;
	(void)q;

	if (begin_request(s, r, NOTIFY_OP_STATE_WATCH, &fault) == 0) {
		struct bsd_notify_v1_Notify_StateWatch_Result v = {
			.tag = bsd_notify_v1_Notify_StateWatch_Result_response_tag,
			.value.response = { s->ident, 1, 42, true }
		};
		/* present = false with a state is the malformed variant. */
		if (fault == FAKE_SERVICE_FAULT_INVALID_STATE)
			v.value.response.present = false;
		(void)bsd_notify_v1_Notify_StateWatch_reply(c, r, &v);
	}
	end_request();
}

static void
on_list_subscriptions(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_ListRequest *q)
{
	static struct bsd_notify_v1_fidl_string page[NOTIFY_LIST_MAX_ENTRIES];
	struct session *s = x;
	enum fake_service_fault fault;
	size_t n = 0;

	if (begin_request(s, r, NOTIFY_OP_LIST_SUBSCRIPTIONS, &fault) == 0) {
		while (q->cursor + n < s->ntopics &&
		    n < NOTIFY_LIST_MAX_ENTRIES) {
			page[n] = (struct bsd_notify_v1_fidl_string){
			    s->topic[q->cursor + n],
			    strlen(s->topic[q->cursor + n]) };
			n++;
		}
		struct bsd_notify_v1_Notify_ListSubscriptions_Result v = {
			.tag =
			  bsd_notify_v1_Notify_ListSubscriptions_Result_response_tag,
			.value.response = { page, n,
			    q->cursor + n < s->ntopics ?
			    (uint32_t)(q->cursor + n) : 0,
			    (uint32_t)s->ntopics }
		};
		(void)bsd_notify_v1_Notify_ListSubscriptions_reply(c, r, &v);
	}
	end_request();
}

static void
on_list_timers(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct bsd_notify_v1_ListRequest *q)
{
	static struct bsd_notify_v1_TimerEntry page[NOTIFY_LIST_MAX_ENTRIES];
	struct session *s = x;
	enum fake_service_fault fault;
	size_t n = 0;

	if (begin_request(s, r, NOTIFY_OP_LIST_TIMERS, &fault) == 0) {
		while (q->cursor + n < s->ntimers &&
		    n < NOTIFY_LIST_MAX_ENTRIES) {
			const struct fake_timer *t = &s->timers[q->cursor + n];

			page[n] = (struct bsd_notify_v1_TimerEntry){
			    t->id, t->interval_ms, t->flags, t->interval_ms };
			n++;
		}
		struct bsd_notify_v1_Notify_ListTimers_Result v = {
			.tag = bsd_notify_v1_Notify_ListTimers_Result_response_tag,
			.value.response = { page, n,
			    q->cursor + n < s->ntimers ?
			    (uint32_t)(q->cursor + n) : 0,
			    (uint32_t)s->ntimers }
		};
		(void)bsd_notify_v1_Notify_ListTimers_reply(c, r, &v);
	}
	end_request();
}

static void *
serve(void *argument)
{
	static const struct bsd_notify_v1_Notify_server handlers = {
		.GetProtocolInfo = on_info,
		.Hello = on_hello,
		.Subscribe = on_subscribe,
		.Unsubscribe = on_unsubscribe,
		.Publish = on_publish,
		.Next = on_next,
		.TimerAdd = on_timer_add,
		.TimerCancel = on_timer_cancel,
		.GetStats = on_stats,
		.StateSet = on_state_set,
		.StateGet = on_state_get,
		.StateClear = on_state_clear,
		.ListSubscriptions = on_list_subscriptions,
		.ListTimers = on_list_timers,
		.StateWatch = on_state_watch
	};
	struct session *s = argument;

	assert(bsd_notify_v1_Notify_bind(s->connection, &handlers, s) == 0);
	while (fidl_bsd_connection_poll(s->connection, 10000) == 0)
		;
	fidl_bsd_connection_destroy(s->connection);
	free(s);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_cond_broadcast(&changed);
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fdp)
{
	struct session *s;
	pthread_t thread;
	int ends[2], error;

	if (name == NULL || fdp == NULL ||
	    (strcmp(name, NOTIFY_INTERFACE) != 0 &&
	    strcmp(name, NOTIFY_SYSTEM_INTERFACE) != 0))
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	(void)strlcpy(last_interface, name, sizeof(last_interface));
	if (strcmp(name, NOTIFY_SYSTEM_INTERFACE) == 0)
		system_connects++;
	else
		open_connects++;
	if (refused_interface[0] != '\0' &&
	    strcmp(name, refused_interface) == 0) {
		error = refused_error;
		pthread_mutex_unlock(&lock);
		*fdp = -1;
		return (errno = error, -1);
	}
	pthread_mutex_unlock(&lock);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	s = calloc(1, sizeof(*s));
	assert(s != NULL);
	assert(fidl_bsd_connection_create(ends[1], FIDL_BSD_SERVER,
	    &s->connection) == 0);
	pthread_mutex_lock(&lock);
	s->ident = ++created;
	pthread_mutex_unlock(&lock);
	assert(pthread_create(&thread, NULL, serve, s) == 0);
	assert(pthread_detach(thread) == 0);
	*fdp = ends[0];
	return (0);
}
