/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "broker.h"
#include "notifycmp.h"
#include "notifycmp_probes.h"
#include "policy.h"
#include "transport.h"

#define	NOTIFYCMP_PROVIDER_NAME	NOTIFYCMP_INTERFACE
#define	ROUTER_CONTROL_MAGIC	0x4e524354U
#define	ROUTER_EVENT_CONTROL	1
#define	ROUTER_EVENT_SESSION	2
#define	ROUTER_EVENT_USER_TIMER	3
#define	ROUTER_EVENT_NEXT_TIMER	4

union notifycmp_buffer {
	max_align_t align;
	uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
};

struct router_control {
	uint32_t	magic;
	uint32_t	queue_depth;
	char		label[NOTIFYCMP_MAX_PUBLISHER + 1];
};

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
	struct notifycmp_broker_client	*client;
	struct router_timer		*timers;
	struct router_timer		*next_timer;
	struct notifycmp_msg		 pending;
	bool				 pending_active;
	size_t				 timer_count;
	int				 fd;
	char				 label[NOTIFYCMP_MAX_PUBLISHER + 1];
};

struct router {
	struct notifycmp_broker	*broker;
	struct router_session	*sessions;
	struct event_source	 control_source;
	struct router_session	*garbage_sessions;
	struct router_timer	*garbage_timers;
	uint64_t		 next_ident;
	int			 control;
	int			 kq;
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_NOTIFYCMP_POLICY, getuid(), (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

static int
harden_channel(int fd, int clofork)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, clofork) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
send_reply(int fd, const struct notifycmp_msg *request, int error,
    const void *payload, size_t payload_length)
{
	union notifycmp_buffer buffer;
	struct notifycmp_msg *reply;

	memset(&buffer, 0, sizeof(buffer));
	reply = (void *)buffer.bytes;
	if (notifycmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	return (internal_send(fd, reply,
	    sizeof(*reply) + (error == 0 ? payload_length : 0),
	    NOTIFYCMP_MESSAGE_REPLY));
}

static int
router_change(struct router *router, uintptr_t ident, int16_t filter,
    uint16_t flags, uint32_t fflags, intptr_t data, void *udata)
{
	struct kevent change;

	EV_SET(&change, ident, filter, flags, fflags, data, udata);
	return (kevent(router->kq, &change, 1, NULL, 0, NULL));
}

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
	notifycmp_broker_remove(router->broker, session->client);
	close(session->fd);
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
	timer->ident = ++router->next_ident;
	timer->user_id = user_id;
	timer->flags = flags;
	event_flags = EV_ADD | EV_ENABLE;
	if (source_type == ROUTER_EVENT_NEXT_TIMER ||
	    (flags & NOTIFYCMP_TIMER_F_PERIODIC) == 0)
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
	union notifycmp_buffer buffer;
	struct notifycmp_event *event;
	ssize_t length;
	int error;

	if (!session->pending_active)
		return (0);
	event = (void *)buffer.bytes;
	length = notifycmp_broker_next(session->client, event, sizeof(buffer));
	if (length == -1) {
		if (errno == EAGAIN)
			return (0);
		error = errno;
	} else
		error = 0;
	if (session->next_timer != NULL)
		router_delete_timer(router, session->next_timer);
	if (send_reply(session->fd, &session->pending, error,
	    error == 0 ? event : NULL, error == 0 ? (size_t)length : 0) == -1)
		return (-1);
	NOTIFYCMPD_PROBE_DELIVER(__DECONST(char *, session->label),
	    error == 0 ? event->type : 0, error);
	memset(&session->pending, 0, sizeof(session->pending));
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
router_handle_request(struct router *router, struct router_session *session)
{
	union notifycmp_buffer buffer;
	struct notifycmp_hello_reply hello;
	struct notifycmp_msg *message;
	struct notifycmp_publish_request *publish;
	struct notifycmp_timer_cancel_request *cancel;
	struct notifycmp_timer_request *timer_request;
	struct notifycmp_topic_request *topic;
	struct notifycmp_stats stats;
	struct router_timer *timer;
	ssize_t received;
	char topic_name[NOTIFYCMP_MAX_TOPIC + 1];
	int error;

	received = internal_receive(session->fd, buffer.bytes,
	    sizeof(buffer), NOTIFYCMP_MESSAGE_REQUEST);
	if (received == -1)
		return (-1);
	message = (void *)buffer.bytes;
	error = 0;
	switch (message->opcode) {
	case NOTIFYCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = NOTIFYCMP_ABI_VERSION;
		hello.features = NOTIFYCMP_FEATURE_PUBSUB |
		    NOTIFYCMP_FEATURE_TIMERS |
		    NOTIFYCMP_FEATURE_BOUNDED_QUEUE;
		hello.max_topic = NOTIFYCMP_MAX_TOPIC;
		hello.max_payload = NOTIFYCMP_MAX_PAYLOAD;
		hello.max_subscriptions = NOTIFYCMP_MAX_SUBSCRIPTIONS;
		hello.queue_depth = NOTIFYCMP_DEFAULT_QUEUE;
		hello.max_timers = NOTIFYCMP_MAX_TIMERS;
		return (send_reply(session->fd, message, 0, &hello,
		    sizeof(hello)));
	case NOTIFYCMP_OP_SUBSCRIBE:
	case NOTIFYCMP_OP_UNSUBSCRIBE:
		topic = (void *)(message + 1);
		if (message->opcode == NOTIFYCMP_OP_SUBSCRIBE)
			error = notifycmp_broker_subscribe(router->broker,
			    session->client, topic->topic,
			    topic->topic_length) == -1 ? errno : 0;
		else
			error = notifycmp_broker_unsubscribe(router->broker,
			    session->client, topic->topic,
			    topic->topic_length) == -1 ? errno : 0;
		audit_policy(session->label, message->opcode ==
		    NOTIFYCMP_OP_SUBSCRIBE ? "subscribe" : "unsubscribe",
		    error);
		memcpy(topic_name, topic->topic, topic->topic_length);
		topic_name[topic->topic_length] = '\0';
		NOTIFYCMPD_PROBE_SUBSCRIBE(
		    __DECONST(char *, session->label), topic_name, error);
		break;
	case NOTIFYCMP_OP_PUBLISH:
		publish = (void *)(message + 1);
		error = notifycmp_broker_publish(router->broker,
		    session->client, publish->topic, publish->topic_length,
		    publish + 1, publish->payload_length) == -1 ? errno : 0;
		audit_policy(session->label, "publish", error);
		memcpy(topic_name, publish->topic, publish->topic_length);
		topic_name[publish->topic_length] = '\0';
		NOTIFYCMPD_PROBE_PUBLISH(__DECONST(char *, session->label),
		    topic_name, publish->payload_length, error);
		if (error == 0)
			(void)router_deliver_pending(router);
		break;
	case NOTIFYCMP_OP_NEXT: {
		const struct notifycmp_next_request *next_request;

		next_request = (const void *)(message + 1);
		session->pending = *message;
		session->pending_active = true;
		if (router_deliver(router, session) == -1)
			return (-1);
		if (!session->pending_active)
			return (0);
		if (next_request->timeout_ms == 0) {
			session->pending = (struct notifycmp_msg){};
			session->pending_active = false;
			return (send_reply(session->fd, message, EAGAIN, NULL, 0));
		}
		if (next_request->timeout_ms != NOTIFYCMP_TIMEOUT_INFINITE &&
		    router_add_timer(router, session, 0,
		    next_request->timeout_ms, 0,
		    ROUTER_EVENT_NEXT_TIMER) == -1) {
			error = errno;
			session->pending = (struct notifycmp_msg){};
			session->pending_active = false;
			return (send_reply(session->fd, message, error, NULL, 0));
		}
		return (0);
	}
	case NOTIFYCMP_OP_TIMER_ADD:
		timer_request = (void *)(message + 1);
		for (timer = session->timers; timer != NULL; timer = timer->next)
			if (timer->user_id == timer_request->timer_id) {
				error = EEXIST;
				break;
			}
		if (error == 0 &&
		    session->timer_count == NOTIFYCMP_MAX_TIMERS)
			error = ENOSPC;
		if (error == 0 && router_add_timer(router, session,
		    timer_request->timer_id, timer_request->interval_ms,
		    timer_request->flags, ROUTER_EVENT_USER_TIMER) == -1)
			error = errno;
		audit_policy(session->label, "timer-add", error);
		break;
	case NOTIFYCMP_OP_TIMER_CANCEL:
		cancel = (void *)(message + 1);
		for (timer = session->timers; timer != NULL; timer = timer->next)
			if (timer->user_id == cancel->timer_id)
				break;
		if (timer == NULL)
			error = ENOENT;
		else
			router_delete_timer(router, timer);
		audit_policy(session->label, "timer-cancel", error);
		break;
	case NOTIFYCMP_OP_STATS:
		notifycmp_broker_stats(session->client, &stats);
		return (send_reply(session->fd, message, 0, &stats,
		    sizeof(stats)));
	}
	if (error != 0)
		NOTIFYCMPD_PROBE_REJECT(__DECONST(char *, session->label),
		    message->opcode, error);
	return (send_reply(session->fd, message, error, NULL, 0));
}

static int
router_add_session(struct router *router)
{
	struct router_control control;
	struct router_session *session;
	int fd;
	ssize_t received;

	fd = -1;
	received = internal_receive_fd(router->control, &control,
	    sizeof(control), &fd);
	if (received != sizeof(control) ||
	    control.magic != ROUTER_CONTROL_MAGIC ||
	    control.queue_depth == 0 ||
	    control.queue_depth > NOTIFYCMP_DEFAULT_QUEUE ||
	    strnlen(control.label, sizeof(control.label)) ==
	    sizeof(control.label)) {
		if (fd >= 0)
			close(fd);
		errno = EPROTO;
		return (-1);
	}
	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		close(fd);
		return (-1);
	}
	session->source.type = ROUTER_EVENT_SESSION;
	session->fd = fd;
	memcpy(session->label, control.label, sizeof(session->label));
	session->client = notifycmp_broker_add(router->broker, session->label,
	    control.queue_depth);
	if (session->client == NULL ||
	    harden_channel(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    router_change(router, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
	    session) == -1) {
		if (session->client != NULL)
			notifycmp_broker_remove(router->broker, session->client);
		close(fd);
		free(session);
		return (-1);
	}
	session->next = router->sessions;
	router->sessions = session;
	return (0);
}

static int
router_main(int control)
{
	struct router router;
	struct kevent events[64];
	struct event_source *source;
	struct router_timer *timer;
	struct router_session *session;
	int count, i, error;

	memset(&router, 0, sizeof(router));
	router.control = control;
	router.control_source.type = ROUTER_EVENT_CONTROL;
	router.broker = notifycmp_broker_create();
	router.kq = kqueue();
	if (router.broker == NULL || router.kq == -1 ||
	    harden_channel(control, CAP_CLOFORK_LOCKED) == -1 ||
	    router_change(&router, control, EVFILT_READ, EV_ADD | EV_ENABLE,
	    0, 0, &router.control_source) == -1 ||
	    service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1)
		return (1);
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1)
		return (1);
	error = 0;
	if (write(control, &error, sizeof(error)) != sizeof(error))
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
					return (0);
				if (router_add_session(&router) == -1) {
					error = errno;
					if (error != EPROTO)
						return (1);
				}
				continue;
			}
			if (source->type == ROUTER_EVENT_SESSION) {
				session = (void *)source;
				if ((events[i].flags & EV_EOF) != 0 ||
				    router_handle_request(&router, session) == -1)
					router_remove_session(&router, session);
				continue;
			}
			timer = (void *)source;
			session = timer->session;
			if (source->type == ROUTER_EVENT_NEXT_TIMER) {
				error = send_reply(session->fd, &session->pending,
				    EAGAIN, NULL, 0) == -1 ? errno : 0;
				memset(&session->pending, 0,
				    sizeof(session->pending));
				session->pending_active = false;
				timer->ident = 0;
				router_delete_timer(&router, timer);
				if (error != 0)
					router_remove_session(&router, session);
				continue;
			}
			(void)notifycmp_broker_timer(router.broker,
			    session->client, timer->user_id);
			NOTIFYCMPD_PROBE_TIMER(
			    __DECONST(char *, session->label),
			    timer->user_id, 0);
			if ((timer->flags & NOTIFYCMP_TIMER_F_PERIODIC) == 0) {
				/* EV_ONESHOT has already removed the kevent. */
				timer->ident = 0;
				router_delete_timer(&router, timer);
			}
			if (router_deliver(&router, session) == -1)
				router_remove_session(&router, session);
		}
		router_collect_garbage(&router);
	}
}

static void *
router_watch(void *argument)
{
	int status, router_pd;

	router_pd = *(const int *)argument;
	while (pdwait(router_pd, &status, 0, NULL, NULL) == -1)
		if (errno != EINTR)
			break;
	_exit(1);
}

static bool
relay_authorized(const struct notifycmp_policy *policy,
    const struct notifycmp_msg *message, const char **operation)
{
	const struct notifycmp_publish_request *publish;
	const struct notifycmp_topic_request *topic;

	switch (message->opcode) {
	case NOTIFYCMP_OP_SUBSCRIBE:
	case NOTIFYCMP_OP_UNSUBSCRIBE:
		*operation = message->opcode == NOTIFYCMP_OP_SUBSCRIBE ?
		    "subscribe" : "unsubscribe";
		topic = (const void *)(message + 1);
		return (notifycmp_policy_can_subscribe(policy, topic->topic,
		    topic->topic_length));
	case NOTIFYCMP_OP_PUBLISH:
		*operation = "publish";
		publish = (const void *)(message + 1);
		return (notifycmp_policy_can_publish(policy, publish->topic,
		    publish->topic_length));
	case NOTIFYCMP_OP_TIMER_ADD:
		*operation = "timer-add";
		return (policy->timers);
	case NOTIFYCMP_OP_TIMER_CANCEL:
		*operation = "timer-cancel";
		return (policy->timers);
	default:
		*operation = "request";
		return (true);
	}
}

static int
relay_deny(struct channel_message *request_message,
    const struct notifycmp_msg *request)
{
	struct notifycmp_msg reply;

	memset(&reply, 0, sizeof(reply));
	if (notifycmp_message_init_reply(&reply, request, -EACCES) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply))));
}

struct relay_state {
	int			 router;
	const struct notifycmp_policy *policy;
	const char		*label;
	int			 terminal_error;
};

static void
relay_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	union notifycmp_buffer buffer;
	struct relay_state *state;
	const struct notifycmp_msg *message;
	const char *operation;
	ssize_t received;

	state = argument;
	message = channel_message_data(request_message);
	received = (ssize_t)channel_message_length(request_message);
	if (channel_message_fd_count(request_message) != 0 ||
	    notifycmp_validate_message(message, (size_t)received,
	    NOTIFYCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		goto out;
	}
	if (!relay_authorized(state->policy, message, &operation)) {
		audit_policy(state->label, operation, EACCES);
		NOTIFYCMPD_PROBE_REJECT(__DECONST(char *, state->label),
		    message->opcode, EACCES);
		if (relay_deny(request_message, message) == -1)
			state->terminal_error = errno;
		goto out;
	}
	if (internal_send(state->router, message, (size_t)received,
	    NOTIFYCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = errno;
		goto out;
	}
	received = internal_receive(state->router, buffer.bytes,
	    sizeof(buffer), NOTIFYCMP_MESSAGE_REPLY);
	if (received == -1 ||
	    channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer.bytes,
	    (size_t)received)) == -1)
		state->terminal_error = errno;
out:
	channel_message_free(request_message);
}

static int
relay_worker(int client, int router, int barrier,
    const struct notifycmp_policy *policy, const char *label)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct relay_state state;
	struct channel *channel;
	struct pollfd descriptor;
	char byte;
	int error, result, wants_write;

	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		error = errno;
	else {
		service_worker_drop_inherited_authority();
		error = cap_enter() == -1 ? errno : 0;
	}
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    error != 0 || read(barrier, &byte, 1) != 1)
		return (1);
	close(barrier);
	memset(&state, 0, sizeof(state));
	state.router = router;
	state.policy = policy;
	state.label = label;
	if (channel_create(client, &options, &channel) == -1) {
		close(client);
		goto done;
	}
	if (channel_set_request_handler(channel, relay_request, &state) == -1) {
		channel_destroy(channel);
		goto done;
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, -1);
		} while (result == -1 && errno == EINTR);
		if (result == -1)
			break;
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}
	channel_destroy(channel);
done:
	close(router);
	return (0);
}

static int
start_session(int fd, const char *peer_label, int router_control)
{
	struct notifycmp_policy policy;
	struct router_control control;
	char byte;
	int relay[2], syncfd[2], pd, child_error, error;
	ssize_t received;
	pid_t pid;

	/*
	 * Global clients receive no publish, subscribe, or timer authority
	 * until serviced supplies an explicit identity-bound ACL.  HELLO,
	 * NEXT, and STATS remain available without granting routing authority.
	 */
	memset(&policy, 0, sizeof(policy));
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, relay) == -1) {
		error = errno;
		goto reject;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		close(relay[0]);
		close(relay[1]);
		goto reject;
	}
	if (harden_channel(fd, CAP_CLOFORK_ONCE) == -1 ||
	    harden_channel(relay[0], CAP_CLOFORK_ONCE) == -1 ||
	    cap_xfer_limit(relay[1], CAP_XFER_ONCE) == -1) {
		error = errno;
		close(relay[0]);
		close(relay[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	memset(&control, 0, sizeof(control));
	control.magic = ROUTER_CONTROL_MAGIC;
	control.queue_depth = NOTIFYCMP_DEFAULT_QUEUE;
	strlcpy(control.label, peer_label, sizeof(control.label));
	if (internal_send_fd(router_control, &control, sizeof(control),
	    relay[1]) == -1) {
		error = errno;
		close(relay[0]);
		close(relay[1]);
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	close(relay[1]);
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(relay[0]);
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		_exit(relay_worker(fd, relay[0], syncfd[1], &policy,
		    peer_label));
	}
	close(relay[0]);
	close(syncfd[1]);
	received = read(syncfd[0], &child_error, sizeof(child_error));
	if (received != sizeof(child_error) || child_error != 0) {
		error = received == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	NOTIFYCMPD_PROBE_SESSION(__DECONST(char *, peer_label),
	    0, 0);
	return (0);

reject:
	audit_policy(peer_label, "session-bootstrap", error);
	NOTIFYCMPD_PROBE_SESSION(__DECONST(char *, peer_label),
	    0, error);
	errno = error;
	return (-1);
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	pthread_t watcher;
	ssize_t received;
	int router_pair[2], router_pd, fd, router_error;
	pid_t router_pid;

	openlog("notifycmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
	    router_pair) == -1)
		goto fail;
	router_pid = pdfork(&router_pd, PD_CLOEXEC);
	if (router_pid == -1)
		goto fail;
	if (router_pid == 0) {
		close(router_pair[0]);
		_exit(router_main(router_pair[1]));
	}
	close(router_pair[1]);
	received = read(router_pair[0], &router_error, sizeof(router_error));
	if (received != sizeof(router_error) || router_error != 0 ||
	    pthread_create(&watcher, NULL, router_watch, &router_pd) != 0 ||
	    pthread_detach(watcher) != 0 ||
	    cap_clofork_limit(router_pair[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(router_pair[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, NOTIFYCMP_PROVIDER_NAME,
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
			goto fail_router;
		}
		(void)start_session(fd, identity.client_label, router_pair[0]);
		close(fd);
	}

fail_router:
	(void)pdkill(router_pd, SIGKILL);
	close(router_pd);
fail:
	syslog(LOG_ERR, "provider failed: %m");
	return (1);
}
