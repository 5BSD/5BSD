/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <auditcmp.h>
#include <auditcmp_server.h>
#include <channel.h>
#include <libservice.h>

#include "broker.h"
#include "notify.h"
#include <notify_server.h>
#include "bsdnotify_probes.h"
#include "policy.h"
#include "transport.h"

#define	NOTIFY_PROVIDER_NAME	NOTIFY_INTERFACE
#define	NOTIFY_POLICY_NAME	"bsdnotify.conf"
#define	ROUTER_CONTROL_MAGIC	0x4e524354U
#define	ROUTER_EVENT_CONTROL	1
#define	ROUTER_EVENT_SESSION	2
#define	ROUTER_EVENT_USER_TIMER	3
#define	ROUTER_EVENT_NEXT_TIMER	4
#define	ROUTER_MAX_SESSIONS	65536U

union notify_buffer {
	max_align_t align;
	uint8_t bytes[NOTIFY_MAX_MESSAGE];
};

struct router_control {
	uint32_t	magic;
	uint32_t	queue_depth;
	char		label[NOTIFY_MAX_PUBLISHER + 1];
};

struct router_control_reply {
	int32_t	status;
};

enum router_admission_result {
	ROUTER_ADMISSION_ACCEPTED = 0,
	ROUTER_ADMISSION_REJECTED = 1,
	ROUTER_ADMISSION_FATAL = -1
};

static enum router_admission_result
router_admission_classify(int call_result, size_t reply_length,
    size_t reply_nfds, int status, int *error)
{

	if (error == NULL)
		return (ROUTER_ADMISSION_FATAL);
	if (call_result == -1) {
		*error = errno != 0 ? errno : EIO;
		return (ROUTER_ADMISSION_FATAL);
	}
	if (reply_length != sizeof(struct router_control_reply) ||
	    reply_nfds != 0 || status < 0 || status > ELAST) {
		*error = EPROTO;
		return (ROUTER_ADMISSION_FATAL);
	}
	if (status == EPROTO || status == EINVAL) {
		*error = status;
		return (ROUTER_ADMISSION_FATAL);
	}
	if (status != 0) {
		*error = status;
		return (ROUTER_ADMISSION_REJECTED);
	}
	*error = 0;
	return (ROUTER_ADMISSION_ACCEPTED);
}

struct event_source {
	int	type;
};

struct router_session;

struct router_timer {
	struct event_source	 source;
	struct router_timer	*next;
	struct router_session	*session;
	uint64_t		 ident;
	uint64_t		 user_id;
	uint32_t		 flags;
};

struct router_session {
	struct event_source		 source;
	struct router_session		*next;
	struct notify_broker_client	*client;
	struct router			*router;
	struct channel			*channel;
	const struct notify_policy	*policy;
	struct router_timer		*timers;
	struct router_timer		*next_timer;
	struct channel_message		*pending;
	struct notify_msg		 pending_wire;
	bool				 pending_active;
	size_t				 timer_count;
	int				 terminal_error;
	int				 fd;
	char				 label[NOTIFY_MAX_PUBLISHER + 1];
};

struct router {
	struct notify_broker	*broker;
	struct router_session	*sessions;
	struct event_source	 control_source;
	struct router_session	*garbage_sessions;
	struct router_timer	*garbage_timers;
	const struct notify_policy_db *policy_db;
	struct auditcmp_client	*audit;
	struct channel		*control_channel;
	size_t			 nsessions;
	uint64_t		 next_ident;
	int			 control_error;
	int			 control;
	int			 kq;
};

struct router_watch_context {
	int		 process_fd;
	_Atomic bool	 expected_exit;
	_Atomic bool	 exited;
};

static bool
router_label_valid(const char *label)
{
	size_t length;

	if (label == NULL)
		return (false);
	length = strnlen(label, NOTIFY_MAX_PUBLISHER + 1);
	return (length != 0 && length <= NOTIFY_MAX_PUBLISHER);
}

#ifndef NOTIFY_ROUTER_TEST
static void router_channel_request(struct channel *, struct channel_message *,
    void *);
static void router_control_request(struct channel *, struct channel_message *,
    void *);
static int router_sync_write(struct router *, struct router_session *);

static void
audit_policy(struct auditcmp_client *audit, const char *label,
    const char *operation, int error)
{

	if (auditcmp_submit(audit, label, operation, error) == -1)
		syslog(LOG_WARNING, "audit %s for %s failed: %m", operation,
		    label);
}

static int
harden_channel(int fd, int clofork)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, clofork) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
harden_transfer_channel(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}
#endif

static int
send_reply(int fd, const struct notify_msg *request, int error,
    const void *payload, size_t payload_length)
{
	union notify_buffer buffer;
	struct notify_msg *reply;

	memset(&buffer, 0, sizeof(buffer));
	reply = (void *)buffer.bytes;
	if (notify_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	return (internal_send(fd, reply,
	    sizeof(*reply) + (error == 0 ? payload_length : 0),
	    NOTIFY_MESSAGE_REPLY));
}

static int
send_channel_reply(struct channel_message *request_message,
    const struct notify_msg *request, int error, const void *payload,
    size_t payload_length)
{
	union notify_buffer buffer;
	struct notify_msg *reply;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	reply = (void *)buffer.bytes;
	if (notify_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (notify_validate_message(reply, length,
	    NOTIFY_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(reply,
	    length)));
}

static int
router_send_reply(struct router_session *session,
    struct channel_message *request_message,
    const struct notify_msg *request, int error, const void *payload,
    size_t payload_length)
{
	int result;

	if (request_message != NULL) {
		result = send_channel_reply(request_message, request, error, payload,
		    payload_length);
#ifndef NOTIFY_ROUTER_TEST
		if (result == 0)
			result = router_sync_write(session->router, session);
#endif
		return (result);
	}
	return (send_reply(session->fd, request, error, payload, payload_length));
}

static int
router_change(struct router *router, uintptr_t ident, int16_t filter,
    uint16_t flags, uint32_t fflags, intptr_t data, void *udata)
{
	struct kevent change;

	EV_SET(&change, ident, filter, flags, fflags, data, udata);
	return (kevent(router->kq, &change, 1, NULL, 0, NULL));
}

#ifndef NOTIFY_ROUTER_TEST
static int
router_sync_write(struct router *router, struct router_session *session)
{
	int wants_write;

	wants_write = channel_wants_write(session->channel);
	if (wants_write == -1)
		return (-1);
	return (router_change(router, session->fd, EVFILT_WRITE,
	    wants_write ? EV_ENABLE : EV_DISABLE, 0, 0, session));
}
#endif

static void
router_delete_timer(struct router *router, struct router_timer *timer)
{
	struct router_timer **cursor;

	if (timer->ident != 0)
		(void)router_change(router, timer->ident, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);
	if (timer->source.type == ROUTER_EVENT_NEXT_TIMER)
		timer->session->next_timer = NULL;
	else {
		cursor = &timer->session->timers;
		while (*cursor != NULL && *cursor != timer)
			cursor = &(*cursor)->next;
		if (*cursor == timer)
			*cursor = timer->next;
		timer->session->timer_count--;
	}
	timer->source.type = 0;
	timer->next = router->garbage_timers;
	router->garbage_timers = timer;
}

static void
router_remove_session(struct router *router, struct router_session *session)
{
	struct router_session **cursor;
	int terminal_error;

	terminal_error = session->terminal_error;
	cursor = &router->sessions;
	while (*cursor != NULL && *cursor != session)
		cursor = &(*cursor)->next;
	if (*cursor == session)
		*cursor = session->next;
	(void)router_change(router, session->fd, EVFILT_READ, EV_DELETE, 0, 0,
	    NULL);
	if (session->next_timer != NULL)
		router_delete_timer(router, session->next_timer);
	while (session->timers != NULL)
		router_delete_timer(router, session->timers);
	if (session->pending != NULL)
		channel_message_free(session->pending);
	notify_broker_remove(router->broker, session->client);
	if (session->channel != NULL)
		channel_destroy(session->channel);
	else if (session->fd >= 0)
		close(session->fd);
	if (router->nsessions != 0)
		router->nsessions--;
	BSDNOTIFY_PROBE_SESSION_END(__DECONST(char *, session->label),
	    terminal_error);
	session->source.type = 0;
	session->next = router->garbage_sessions;
	router->garbage_sessions = session;
}

static void
router_collect_garbage(struct router *router)
{
	struct router_session *session;
	struct router_timer *timer;

	while ((timer = router->garbage_timers) != NULL) {
		router->garbage_timers = timer->next;
		free(timer);
	}
	while ((session = router->garbage_sessions) != NULL) {
		router->garbage_sessions = session->next;
		free(session);
	}
}

static int
router_allocate_ident(struct router *router, uint64_t *ident)
{
	struct router_session *session;
	struct router_timer *timer;
	uint64_t candidate;
	bool collision;

	for (;;) {
		candidate = ++router->next_ident;
		if (candidate == 0)
			continue;
		collision = false;
		for (session = router->sessions; session != NULL && !collision;
		    session = session->next) {
			if (session->next_timer != NULL &&
			    session->next_timer->ident == candidate)
				collision = true;
			for (timer = session->timers; timer != NULL && !collision;
			    timer = timer->next)
				if (timer->ident == candidate)
					collision = true;
		}
		if (!collision)
			break;
	}
	*ident = candidate;
	return (0);
}

static int
router_add_timer(struct router *router, struct router_session *session,
    uint64_t user_id, uint32_t interval_ms, uint32_t flags,
    int source_type)
{
	struct router_timer *timer;
	uint16_t event_flags;

	timer = calloc(1, sizeof(*timer));
	if (timer == NULL)
		return (-1);
	timer->source.type = source_type;
	timer->session = session;
	if (router_allocate_ident(router, &timer->ident) == -1) {
		free(timer);
		return (-1);
	}
	timer->user_id = user_id;
	timer->flags = flags;
	event_flags = EV_ADD | EV_ENABLE;
	if (source_type == ROUTER_EVENT_NEXT_TIMER ||
	    (flags & NOTIFY_TIMER_F_PERIODIC) == 0)
		event_flags |= EV_ONESHOT;
	if (router_change(router, timer->ident, EVFILT_TIMER, event_flags,
	    NOTE_MSECONDS, interval_ms, timer) == -1) {
		free(timer);
		return (-1);
	}
	if (source_type == ROUTER_EVENT_NEXT_TIMER)
		session->next_timer = timer;
	else {
		timer->next = session->timers;
		session->timers = timer;
		session->timer_count++;
	}
	return (0);
}

static int
router_deliver(struct router *router, struct router_session *session)
{
	union notify_buffer buffer;
	struct notify_event *event;
	ssize_t length;
	int error;

	if (!session->pending_active)
		return (0);
	event = (void *)buffer.bytes;
	length = notify_broker_next(session->client, event, sizeof(buffer));
	if (length == -1) {
		if (errno == EAGAIN)
			return (0);
		error = errno;
	} else
		error = 0;
	if (session->next_timer != NULL)
		router_delete_timer(router, session->next_timer);
	if (router_send_reply(session, session->pending,
	    session->pending != NULL ? channel_message_data(session->pending) :
	    &session->pending_wire, error,
	    error == 0 ? event : NULL, error == 0 ? (size_t)length : 0) == -1)
		return (-1);
	BSDNOTIFY_PROBE_DELIVER(__DECONST(char *, session->label),
	    error == 0 ? event->type : 0, error);
	if (session->pending != NULL)
		channel_message_free(session->pending);
	session->pending = NULL;
	session->pending_active = false;
	return (0);
}

static int
router_deliver_pending(struct router *router)
{
	struct router_session *session, *next;

	for (session = router->sessions; session != NULL; session = next) {
		next = session->next;
		if (router_deliver(router, session) == -1)
			router_remove_session(router, session);
	}
	return (0);
}

static int
router_handle_request(struct router *router, struct router_session *session,
    struct channel_message *request_message)
{
	union notify_buffer buffer;
	struct notify_hello_reply hello;
	const struct notify_msg *message;
	const struct notify_publish_request *publish;
	const struct notify_timer_cancel_request *cancel;
	const struct notify_timer_request *timer_request;
	const struct notify_topic_request *topic;
	struct notify_stats stats;
	struct notify_state_reply state_reply;
	const struct notify_state_set_request *state_set;
	struct router_timer *timer;
	char topic_name[NOTIFY_MAX_TOPIC + 1];
	int error;

	if (request_message == NULL) {
		ssize_t received;

		received = internal_receive(session->fd, buffer.bytes,
		    sizeof(buffer), NOTIFY_MESSAGE_REQUEST);
		if (received == -1)
			return (-1);
		message = (const void *)buffer.bytes;
	} else
		message = channel_message_data(request_message);
	/* Preserve the token of an outstanding long-poll NEXT request. */
	if (session->pending_active)
		return (router_send_reply(session, request_message, message, EBUSY,
		    NULL, 0));
	error = 0;
	switch (message->opcode) {
	case NOTIFY_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = NOTIFY_ABI_VERSION;
		hello.features = NOTIFY_FEATURE_PUBSUB |
		    NOTIFY_FEATURE_TIMERS |
		    NOTIFY_FEATURE_BOUNDED_QUEUE |
		    NOTIFY_FEATURE_STATE |
		    NOTIFY_FEATURE_LOSS_REPORTING;
		hello.max_topic = NOTIFY_MAX_TOPIC;
		hello.max_payload = NOTIFY_MAX_PAYLOAD;
		hello.max_subscriptions = NOTIFY_MAX_SUBSCRIPTIONS;
		hello.queue_depth = NOTIFY_DEFAULT_QUEUE;
		hello.max_timers = NOTIFY_MAX_TIMERS;
		hello.max_states = NOTIFY_MAX_STATES;
		hello.router_epoch = notify_broker_epoch(router->broker);
		return (router_send_reply(session, request_message, message, 0, &hello,
		    sizeof(hello)));
	case NOTIFY_OP_SUBSCRIBE:
	case NOTIFY_OP_UNSUBSCRIBE:
		topic = (const void *)(message + 1);
		if (message->opcode == NOTIFY_OP_SUBSCRIBE)
			error = notify_broker_subscribe(router->broker,
			    session->client, topic->topic,
			    topic->topic_length) == -1 ? errno : 0;
		else
			error = notify_broker_unsubscribe(router->broker,
			    session->client, topic->topic,
			    topic->topic_length) == -1 ? errno : 0;
		memcpy(topic_name, topic->topic, topic->topic_length);
		topic_name[topic->topic_length] = '\0';
		BSDNOTIFY_PROBE_SUBSCRIBE(
		    __DECONST(char *, session->label), topic_name, error);
		break;
	case NOTIFY_OP_PUBLISH:
		publish = (const void *)(message + 1);
		error = notify_broker_publish(router->broker,
		    session->client, publish->topic, publish->topic_length,
		    publish + 1, publish->payload_length) == -1 ? errno : 0;
		memcpy(topic_name, publish->topic, publish->topic_length);
		topic_name[publish->topic_length] = '\0';
		BSDNOTIFY_PROBE_PUBLISH(__DECONST(char *, session->label),
		    topic_name, publish->payload_length, error);
		if (error == 0)
			(void)router_deliver_pending(router);
		break;
	case NOTIFY_OP_NEXT: {
		const struct notify_next_request *next_request;

		next_request = (const void *)(message + 1);
		session->pending = request_message;
		session->pending_wire = *message;
		session->pending_active = true;
		if (router_deliver(router, session) == -1)
			return (-1);
		if (!session->pending_active)
			return (request_message != NULL ? 1 : 0);
		if (next_request->timeout_ms == 0) {
			session->pending = NULL;
			session->pending_active = false;
			return (router_send_reply(session, request_message, message, EAGAIN,
			    NULL, 0));
		}
		if (next_request->timeout_ms != NOTIFY_TIMEOUT_INFINITE &&
		    router_add_timer(router, session, 0,
		    next_request->timeout_ms, 0,
		    ROUTER_EVENT_NEXT_TIMER) == -1) {
			error = errno;
			session->pending = NULL;
			session->pending_active = false;
			return (router_send_reply(session, request_message, message, error,
			    NULL, 0));
		}
		return (request_message != NULL ? 1 : 0);
	}
	case NOTIFY_OP_TIMER_ADD:
		timer_request = (const void *)(message + 1);
		for (timer = session->timers; timer != NULL; timer = timer->next)
			if (timer->user_id == timer_request->timer_id) {
				error = EEXIST;
				break;
			}
		if (error == 0 &&
		    session->timer_count == NOTIFY_MAX_TIMERS)
			error = ENOSPC;
		if (error == 0 && router_add_timer(router, session,
		    timer_request->timer_id, timer_request->interval_ms,
		    timer_request->flags, ROUTER_EVENT_USER_TIMER) == -1)
			error = errno;
		break;
	case NOTIFY_OP_TIMER_CANCEL:
		cancel = (const void *)(message + 1);
		for (timer = session->timers; timer != NULL; timer = timer->next)
			if (timer->user_id == cancel->timer_id)
				break;
		if (timer == NULL)
			error = ENOENT;
		else
			router_delete_timer(router, timer);
		break;
	case NOTIFY_OP_STATS:
		notify_broker_stats(session->client, &stats);
		return (router_send_reply(session, request_message, message, 0, &stats,
		    sizeof(stats)));
	case NOTIFY_OP_STATE_SET:
		state_set = (const void *)(message + 1);
		error = notify_broker_state_set(router->broker,
		    session->client, state_set->topic, state_set->topic_length,
		    state_set->state, &state_reply) == -1 ? errno : 0;
		if (error == 0) {
			(void)router_deliver_pending(router);
			return (router_send_reply(session, request_message, message, 0, &state_reply,
			    sizeof(state_reply)));
		}
		break;
	case NOTIFY_OP_STATE_GET:
		topic = (const void *)(message + 1);
		error = notify_broker_state_get(router->broker, topic->topic,
		    topic->topic_length, &state_reply) == -1 ? errno : 0;
		if (error == 0)
			return (router_send_reply(session, request_message, message, 0, &state_reply,
			    sizeof(state_reply)));
		break;
	}
	if (error != 0)
		BSDNOTIFY_PROBE_REJECT(__DECONST(char *, session->label),
		    message->opcode, error);
	return (router_send_reply(session, request_message, message, error, NULL,
	    0));
}

#ifndef NOTIFY_ROUTER_TEST
static int
router_add_session(struct router *router, const struct router_control *control,
    int fd)
{
	static const struct notify_policy default_deny;
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct router_session *session;

	if (control == NULL || fd < 0 ||
	    control->magic != ROUTER_CONTROL_MAGIC ||
	    control->queue_depth == 0 ||
	    control->queue_depth > NOTIFY_DEFAULT_QUEUE ||
	    !router_label_valid(control->label)) {
		if (fd >= 0)
			close(fd);
		errno = EPROTO;
		return (-1);
	}
	if (router->nsessions >= ROUTER_MAX_SESSIONS) {
		close(fd);
		errno = ENOSPC;
		return (-1);
	}
	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		close(fd);
		return (-1);
	}
	session->source.type = ROUTER_EVENT_SESSION;
	session->fd = -1;
	session->router = router;
	memcpy(session->label, control->label, sizeof(session->label));
	session->policy = notify_policy_db_lookup(router->policy_db,
	    session->label);
	if (session->policy == NULL)
		session->policy = &default_deny;
	session->client = notify_broker_add(router->broker, session->label,
	    control->queue_depth);
	if (session->client == NULL ||
	    harden_channel(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    channel_create(fd, &options, &session->channel) == -1 ||
	    channel_set_request_handler(session->channel,
	    router_channel_request, session) == -1) {
		if (session->client != NULL)
			notify_broker_remove(router->broker, session->client);
		if (session->channel != NULL)
			channel_destroy(session->channel);
		else
			close(fd);
		free(session);
		return (-1);
	}
	session->fd = channel_fd(session->channel);
	if (router_change(router, session->fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, session) == -1 ||
	    router_change(router, session->fd, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, session) == -1) {
		notify_broker_remove(router->broker, session->client);
		channel_destroy(session->channel);
		free(session);
		return (-1);
	}
	session->next = router->sessions;
	router->sessions = session;
	router->nsessions++;
	return (0);
}

static void
router_control_request(struct channel *channel __unused,
    struct channel_message *request, void *argument)
{
	struct router_control_reply reply;
	const struct router_control *control;
	struct router *router;
	int fd;

	router = argument;
	fd = -1;
	reply.status = EPROTO;
	if (channel_message_length(request) == sizeof(*control) &&
	    channel_message_fd_count(request) == 1) {
		control = channel_message_data(request);
		fd = channel_message_take_fd(request, 0);
		if (router_add_session(router, control, fd) == 0) {
			reply.status = 0;
			BSDNOTIFY_PROBE_SESSION_START(
			    __DECONST(char *, control->label), 0, 0);
		} else {
			reply.status = errno != 0 ? errno : EIO;
			BSDNOTIFY_PROBE_SESSION_START(
			    __DECONST(char *, control->label), 0, reply.status);
		}
	}
	if (channel_send_reply(request,
	    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply))) == -1)
		router->control_error = errno != 0 ? errno : EIO;
	channel_message_free(request);
}

static int
router_main(int control, const struct notify_policy_db *policy_db,
    int audit_fd)
{
	struct channel_options control_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct router_control_reply ready;
	struct router router;
	struct kevent events[64];
	struct event_source *source;
	struct router_timer *timer;
	struct router_session *session;
	int count, i, error, wants_write;

	memset(&router, 0, sizeof(router));
	router.control = control;
	router.policy_db = policy_db;
	router.control_source.type = ROUTER_EVENT_CONTROL;
	router.broker = notify_broker_create();
	router.kq = kqueue();
	if (router.broker == NULL || router.kq == -1 ||
	    auditcmp_client_adopt(audit_fd, &router.audit) == -1 ||
	    harden_channel(control, CAP_CLOFORK_LOCKED) == -1 ||
	    channel_create(control, &control_options,
	    &router.control_channel) == -1 ||
	    channel_set_request_handler(router.control_channel,
	    router_control_request, &router) == -1 ||
	    (router.control = channel_fd(router.control_channel)) == -1 ||
	    router_change(&router, router.control, EVFILT_READ,
	    EV_ADD | EV_ENABLE,
	    0, 0, &router.control_source) == -1 ||
	    router_change(&router, router.control, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, &router.control_source) == -1 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1)
		return (1);
	ready.status = 0;
	if (channel_send_event(router.control_channel,
	    &(struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(&ready,
	    sizeof(ready))) == -1 || channel_flush(router.control_channel) == -1)
		return (1);
	for (;;) {
		count = kevent(router.kq, NULL, 0, events, nitems(events), NULL);
		if (count == -1) {
			if (errno == EINTR)
				continue;
			return (1);
		}
		for (i = 0; i < count; i++) {
			source = events[i].udata;
			if (source == NULL || source->type == 0)
				continue;
			if (source->type == ROUTER_EVENT_CONTROL) {
				if ((events[i].flags & EV_EOF) != 0)
					goto shutdown;
				if (events[i].filter == EVFILT_WRITE &&
				    channel_flush(router.control_channel) == -1)
					router.control_error = errno;
				else if (events[i].filter == EVFILT_READ &&
				    channel_dispatch(router.control_channel) == -1)
					router.control_error = errno;
				if (router.control_error != 0)
					goto shutdown;
				wants_write = channel_wants_write(
				    router.control_channel);
				if (wants_write == -1 || router_change(&router,
				    router.control, EVFILT_WRITE,
				    wants_write ? EV_ENABLE : EV_DISABLE,
				    0, 0, &router.control_source) == -1)
					goto shutdown;
				continue;
			}
			if (source->type == ROUTER_EVENT_SESSION) {
				session = (void *)source;
				if ((events[i].flags & EV_EOF) != 0) {
					router_remove_session(&router, session);
					continue;
				}
				if (events[i].filter == EVFILT_WRITE &&
				    channel_flush(session->channel) == -1)
					session->terminal_error = errno;
				else if (events[i].filter == EVFILT_READ &&
				    channel_dispatch(session->channel) == -1)
					session->terminal_error = errno;
				if (session->terminal_error != 0) {
					router_remove_session(&router, session);
					continue;
				}
				wants_write = channel_wants_write(session->channel);
				if (wants_write == -1 || router_change(&router, session->fd,
				    EVFILT_WRITE, wants_write ? EV_ENABLE : EV_DISABLE,
				    0, 0, session) == -1)
					router_remove_session(&router, session);
				continue;
			}
			timer = (void *)source;
			session = timer->session;
			if (source->type == ROUTER_EVENT_NEXT_TIMER) {
				error = router_send_reply(session, session->pending,
				    channel_message_data(session->pending), EAGAIN,
				    NULL, 0) == -1 ? errno : 0;
				channel_message_free(session->pending);
				session->pending = NULL;
				session->pending_active = false;
				timer->ident = 0;
				router_delete_timer(&router, timer);
				if (error != 0)
					router_remove_session(&router, session);
				continue;
			}
			(void)notify_broker_timer(router.broker,
			    session->client, timer->user_id);
			BSDNOTIFY_PROBE_TIMER(
			    __DECONST(char *, session->label),
			    timer->user_id, 0);
			if ((timer->flags & NOTIFY_TIMER_F_PERIODIC) == 0) {
				/* EV_ONESHOT has already removed the kevent. */
				timer->ident = 0;
				router_delete_timer(&router, timer);
			}
			if (router_deliver(&router, session) == -1)
				router_remove_session(&router, session);
		}
		router_collect_garbage(&router);
	}

shutdown:
	while ((session = router.sessions) != NULL) {
		if (session->pending_active) {
			(void)router_send_reply(session, session->pending,
			    channel_message_data(session->pending), ESHUTDOWN,
			    NULL, 0);
			channel_message_free(session->pending);
			session->pending = NULL;
			session->pending_active = false;
		}
		router_remove_session(&router, session);
	}
	router_collect_garbage(&router);
	channel_destroy(router.control_channel);
	return (0);
}

static void *
router_watch(void *argument)
{
	struct router_watch_context *context;
	int status;

	context = argument;
	while (pdwait(context->process_fd, &status, WEXITED, NULL, NULL) == -1)
		if (errno != EINTR)
			break;
	atomic_store_explicit(&context->exited, true, memory_order_release);
	if (!atomic_load_explicit(&context->expected_exit, memory_order_acquire))
		_exit(1);
	return (NULL);
}

static bool
relay_authorized(const struct notify_policy *policy,
    const struct notify_msg *message, const char **operation)
{
	const struct notify_publish_request *publish;
	const struct notify_topic_request *topic;
	const struct notify_state_set_request *state_set;

	switch (message->opcode) {
	case NOTIFY_OP_SUBSCRIBE:
	case NOTIFY_OP_UNSUBSCRIBE:
		*operation = message->opcode == NOTIFY_OP_SUBSCRIBE ?
		    "subscribe" : "unsubscribe";
		topic = (const void *)(message + 1);
		return (notify_policy_can_subscribe(policy, topic->topic,
		    topic->topic_length));
	case NOTIFY_OP_PUBLISH:
		*operation = "publish";
		publish = (const void *)(message + 1);
		return (notify_policy_can_publish(policy, publish->topic,
		    publish->topic_length));
	case NOTIFY_OP_STATE_SET:
		*operation = "state-set";
		state_set = (const void *)(message + 1);
		return (notify_policy_can_publish(policy, state_set->topic,
		    state_set->topic_length));
	case NOTIFY_OP_STATE_GET:
		*operation = "state-get";
		topic = (const void *)(message + 1);
		return (notify_policy_can_subscribe(policy, topic->topic,
		    topic->topic_length));
	case NOTIFY_OP_TIMER_ADD:
		*operation = "timer-add";
		return (policy->timers);
	case NOTIFY_OP_TIMER_CANCEL:
		*operation = "timer-cancel";
		return (policy->timers);
	default:
		*operation = "request";
		return (true);
	}
}

static void
router_channel_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct router_session *session;
	const struct notify_msg *message;
	const struct channel_sender *sender;
	const char *operation;
	int result;

	session = argument;
	message = channel_message_data(request_message);
	if (channel_message_fd_count(request_message) != 0 ||
	    notify_validate_message(message,
	    channel_message_length(request_message),
	    NOTIFY_MESSAGE_REQUEST) == -1) {
		audit_policy(session->router->audit, session->label,
		    channel_message_fd_count(request_message) != 0 ?
		    "descriptor-attachment" : "malformed-message", EPROTO);
		session->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}
	/*
	 * MIGRATION (docs/capability-authority-model.md, phase P2): this uid gate
	 * is transitional.  The end state authorizes by a presented topic
	 * capability (an endpoint whose rights carry publish/subscribe/etc.), not
	 * by the caller's uid; bsdnotify is the first service to convert.
	 *
	 * Until then, authorization gates on the caller's authenticated uid: root
	 * (uid 0) may perform any operation on any topic, every other uid is bound
	 * by its per-client topic policy.  The connection itself is always
	 * accepted; only privileged operations are restricted.  The uid is the
	 * kernel-stamped sender credential on this request, not a session-time
	 * cache, so it cannot be spoofed by the client.
	 */
	sender = channel_message_sender(request_message);
	if ((sender == NULL || sender->uid != 0) &&
	    !relay_authorized(session->policy, message, &operation)) {
		audit_policy(session->router->audit, session->label, operation,
		    EACCES);
		BSDNOTIFY_PROBE_REJECT(__DECONST(char *, session->label),
		    message->opcode, EACCES);
		if (send_channel_reply(request_message, message, EACCES, NULL, 0) ==
		    -1)
			session->terminal_error = errno;
		channel_message_free(request_message);
		return;
	}
	result = router_handle_request(session->router, session,
	    request_message);
	if (result == -1)
		session->terminal_error = errno != 0 ? errno : EIO;
	if (result <= 0 && session->pending != request_message)
		channel_message_free(request_message);
}


static int
router_start_session(int fd, const char *peer_label,
    struct service_session *router_session)
{
	struct router_control control;
	struct router_control_reply response;
	struct service_message message;
	struct service_reply reply;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	enum router_admission_result result;
	int call_result, error;

	result = ROUTER_ADMISSION_FATAL;
	if (fd < 0 || !router_label_valid(peer_label))
		return (errno = EINVAL, ROUTER_ADMISSION_FATAL);
	if (harden_transfer_channel(fd) == -1) {
		error = errno;
		goto reject;
	}
	memset(&control, 0, sizeof(control));
	control.magic = ROUTER_CONTROL_MAGIC;
	control.queue_depth = NOTIFY_DEFAULT_QUEUE;
	strlcpy(control.label, peer_label, sizeof(control.label));
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.data = &control;
	message.length = sizeof(control);
	message.fds = &fd;
	message.nfds = 1;
	memset(&reply, 0, sizeof(reply));
	reply.size = sizeof(reply);
	reply.data = &response;
	reply.capacity = sizeof(response);
	options.timeout_ms = 5000;
	response.status = EPROTO;
	call_result = service_session_call(router_session, &message, &reply,
	    &options);
	result = router_admission_classify(call_result, reply.length, reply.nfds,
	    response.status, &error);
	if (result != ROUTER_ADMISSION_ACCEPTED)
		goto reject;
	return (ROUTER_ADMISSION_ACCEPTED);

reject:
	errno = error;
	return (result);
}

static int
managed_policy_path(char *path, size_t path_size)
{
	const char *unit_dir;

	unit_dir = getenv(SERVICE_UNIT_DIR_ENV);
	if (unit_dir == NULL || unit_dir[0] == '\0')
		return (errno = ENOENT, -1);
	if (snprintf(path, path_size, "%s/Config/%s", unit_dir,
	    NOTIFY_POLICY_NAME) >= (int)path_size)
		return (errno = ENAMETOOLONG, -1);
	return (0);
}

int
main(void)
{
	struct notify_policy_db *policy_db;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct service_session *router_session;
	struct router_watch_context watch_context;
	pthread_t watcher;
	struct router_control_reply router_ready;
	struct service_reply ready_event;
	struct service_call_options ready_options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	char policy_path[PATH_MAX];
	int audit_fd, router_pair[2], router_pd, fd;
	int watcher_error;
	bool watcher_started;
	pid_t router_pid;

	openlog("bsdnotify", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	memset(&watch_context, 0, sizeof(watch_context));
	watch_context.process_fd = -1;
	watcher_started = false;
	router_session = NULL;
	atomic_init(&watch_context.expected_exit, false);
	atomic_init(&watch_context.exited, false);
	policy_db = calloc(1, sizeof(*policy_db));
	if (policy_db == NULL || managed_policy_path(policy_path,
	    sizeof(policy_path)) == -1 ||
	    notify_policy_db_load(policy_path, policy_db) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    auditcmp_client_prepare(&audit_fd) == -1 ||
	    service_provider_worker_channel(provider, &router_pair[0],
	    &router_pair[1]) == -1)
		goto fail;
	router_pid = pdfork(&router_pd, PD_CLOEXEC);
	if (router_pid == -1)
		goto fail;
	if (router_pid == 0) {
		close(router_pair[0]);
		_exit(router_main(router_pair[1], policy_db, audit_fd));
	}
	close(audit_fd);
	close(router_pair[1]);
	if (service_session_create(router_pair[0], &router_session) == -1)
		goto fail_router;
	memset(&ready_event, 0, sizeof(ready_event));
	ready_event.size = sizeof(ready_event);
	ready_event.data = &router_ready;
	ready_event.capacity = sizeof(router_ready);
	ready_options.timeout_ms = 5000;
	if (service_session_receive_event(router_session, &ready_event,
	    &ready_options) == -1 || ready_event.length != sizeof(router_ready) ||
	    ready_event.nfds != 0 || router_ready.status != 0)
		goto fail_router;
	watch_context.process_fd = router_pd;
	watcher_error = pthread_create(&watcher, NULL, router_watch,
	    &watch_context);
	if (watcher_error != 0) {
		errno = watcher_error;
		goto fail_router;
	}
	watcher_started = true;
	if (service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1 ||
	    service_provider_expose(provider, NOTIFY_PROVIDER_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail_router;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (errno == EINTR)
				continue;
			if (service_provider_quiescing(provider) == 1) {
				struct timespec pause;
				unsigned waits;
				int shutdown_error;

				atomic_store_explicit(&watch_context.expected_exit, true,
				    memory_order_release);
				service_session_close(router_session);
				router_session = NULL;
				pause.tv_sec = 0;
				pause.tv_nsec = 10000000L;
				for (waits = 0; waits < 500 &&
				    !atomic_load_explicit(&watch_context.exited,
				    memory_order_acquire); waits++)
					(void)nanosleep(&pause, NULL);
				shutdown_error = atomic_load_explicit(
				    &watch_context.exited, memory_order_acquire) ? 0 :
				    ETIMEDOUT;
				if (shutdown_error != 0)
					(void)pdkill(router_pd, SIGKILL);
				watcher_error = pthread_join(watcher, NULL);
				watcher_started = false;
				if (shutdown_error == 0 && watcher_error != 0)
					shutdown_error = watcher_error;
				if (service_provider_quiesce_complete(provider,
				    shutdown_error) == -1)
					return (1);
				close(router_pd);
				return (shutdown_error == 0 ? 0 : 1);
			}
			goto fail_router;
		}
		watcher_error = router_start_session(fd, identity.client_label,
		    router_session);
		close(fd);
		if (watcher_error == ROUTER_ADMISSION_FATAL)
			goto fail_router;
		if (watcher_error == ROUTER_ADMISSION_REJECTED)
			syslog(LOG_WARNING, "router rejected client %s: %m",
			    identity.client_label);
	}

fail_router:
	atomic_store_explicit(&watch_context.expected_exit, true,
	    memory_order_release);
	if (router_session != NULL)
		service_session_close(router_session);
	(void)pdkill(router_pd, SIGKILL);
	if (watcher_started)
		(void)pthread_join(watcher, NULL);
	close(router_pd);
fail:
	syslog(LOG_ERR, "provider failed: %m");
	return (1);
}
#endif
