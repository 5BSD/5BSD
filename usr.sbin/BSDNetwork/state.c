/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>

#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.network.v1/c/bsd.h>
#include <libservice.h>
#include <service_runtime.h>
#include <network_state_protocol.h>
#include <notify_watch.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sysctlcmp.h>
#include <unistd.h>

#include "state.h"
#define STATE_CLIENTS	    128
#define STATE_LABEL_CLIENTS 16
#define STATE_IDLE_MS	    30000

struct state_session {
	struct network_state_server *server;
	struct fidl_bsd_connection *connection;
	struct fidl_bsd_request *pending;
	struct notify_watcher *watcher;
	char label[256];
	int error;
	bool negotiated;
	bool write_armed;
};
struct network_state_server {
	int kq, wake[2], stop[2];
	struct notify_watch *store;
	pthread_t sampler;
	bool started;
	struct state_session sessions[STATE_CLIENTS];
};

static int
arm_timer(struct state_session *s, uint32_t timeout)
{
	struct kevent change;
	if (timeout == NETWORK_STATE_TIMEOUT_INFINITE) {
		EV_SET(&change, (uintptr_t)s, EVFILT_TIMER, EV_DELETE, 0, 0,
		    s->server);
		if (kevent(s->server->kq, &change, 1, NULL, 0, NULL) == -1 &&
		    errno != ENOENT)
			return (-1);
		return (0);
	}
	EV_SET(&change, (uintptr_t)s, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_MSECONDS, timeout, s->server);
	return (kevent(s->server->kq, &change, 1, NULL, 0, NULL));
}
static int
write_interest(struct state_session *s)
{
	struct kevent change;
	int pending = fidl_bsd_connection_wants_write(s->connection);
	if (pending == s->write_armed)
		return (0);
	EV_SET(&change, fidl_bsd_connection_fd(s->connection), EVFILT_WRITE,
	    EV_ADD | (pending ? EV_ENABLE : EV_DISABLE), 0, 0, s->server);
	if (kevent(s->server->kq, &change, 1, NULL, 0, NULL) == -1)
		return (-1);
	s->write_armed = pending;
	return (0);
}
static void
close_session(struct state_session *s)
{
	if (s->connection == NULL)
		return;
	(void)arm_timer(s, NETWORK_STATE_TIMEOUT_INFINITE);
	if (s->pending != NULL)
		fidl_bsd_request_release(s->pending);
	notify_watch_close(s->watcher);
	fidl_bsd_connection_destroy(s->connection);
	memset(s, 0, sizeof(*s));
}
static int
send_error(struct state_session *s, struct fidl_bsd_request *request,
    int error)
{
	struct bsd_network_v1_NetworkState_Watch_Result result = {
		.tag = bsd_network_v1_NetworkState_Watch_Result_err_tag,
		.value.err = (uint32_t)error
	};
	int reply_error = bsd_network_v1_NetworkState_Watch_reply(
	    s->connection, request, &result);
	if (reply_error != 0)
		return (errno = reply_error, -1);
	return (write_interest(s));
}
static void
finish_pending(struct state_session *s)
{
	fidl_bsd_request_release(s->pending);
	s->pending = NULL;
	if (arm_timer(s, STATE_IDLE_MS) == -1)
		s->error = errno;
}
static void
deliver(struct state_session *s)
{
	static struct network_state_snapshot state;
	static struct bsd_network_v1_Interface interfaces[
	    NETWORK_STATE_MAX_INTERFACES];
	struct bsd_network_v1_NetworkState_Watch_Result result = {
		.tag = bsd_network_v1_NetworkState_Watch_Result_response_tag
	};
	struct notify_watch_cursor cursor;
	uint32_t flags;
	size_t length;
	int reply_error, take;
	if (s->pending == NULL)
		return;
	memset(&state, 0, sizeof(state));
	take = notify_watch_take(s->watcher, &state, sizeof(state), &length,
	    &cursor, &flags);
	if (take == 0)
		return;
	if (take == -1) {
		s->error = errno;
		return;
	}
	if (state.count > NETWORK_STATE_MAX_INTERFACES) {
		s->error = EIO;
		return;
	}
	for (size_t i = 0; i < state.count; i++) {
		const struct network_state_interface *e = &state.interfaces[i];
		interfaces[i] = (struct bsd_network_v1_Interface){
			.index = e->index,
			.flags = e->flags,
			.mtu = e->mtu,
			.link_state = e->link_state,
			.name = e->name,
			.name_size = strnlen(e->name, sizeof(e->name) - 1)
		};
	}
	result.value.response = (struct bsd_network_v1_Snapshot){
		.epoch = cursor.epoch,
		.generation = cursor.generation,
		.source_error = state.source_error,
		.interfaces = interfaces,
		.interfaces_size = state.count
	};
	reply_error = bsd_network_v1_NetworkState_Watch_reply(s->connection,
	    s->pending, &result);
	if (reply_error != 0)
		s->error = reply_error;
	else if (write_interest(s) == -1)
		s->error = errno;
	finish_pending(s);
}
static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct state_session *s = argument;
	struct bsd_network_v1_ProtocolInfo info = { NETWORK_STATE_WIRE_VERSION };
	int error = bsd_network_v1_NetworkState_GetProtocolInfo_reply(
	    connection, request, &info);
	if (error != 0)
		s->error = error;
	s->negotiated = error == 0;
}
static void
watch(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request,
    struct bsd_network_v1_WatchRequest *r)
{
	struct state_session *s = argument;
	if (s->error != 0)
		return;
	/* Every session negotiates the wire version first. */
	if (!s->negotiated) {
		s->error = EPROTO;
		fidl_bsd_connection_close(connection, EPROTO);
		return;
	}
	if (s->pending != NULL) {
		if (send_error(s, request, EBUSY) == -1)
			s->error = errno;
		return;
	}
	if (notify_watch_begin(s->watcher) == -1) {
		s->error = errno;
		return;
	}
	fidl_bsd_request_retain(request);
	s->pending = request;
	deliver(s);
	if (s->pending == NULL || s->error != 0)
		return;
	if (r->timeout_ms == 0) {
		(void)notify_watch_cancel(s->watcher);
		if (send_error(s, s->pending, EAGAIN) == -1)
			s->error = errno;
		finish_pending(s);
	} else if (arm_timer(s, r->timeout_ms) == -1)
		s->error = errno;
}
static int
publish(struct network_state_server *server,
    const struct network_state_snapshot *state)
{
	char byte = 1;
	int result = notify_watch_publish(server->store, state, sizeof(*state));
	if (result == 1) {
		ssize_t written;
		do {
			written = write(server->wake[1], &byte, 1);
		} while (written == -1 && errno == EINTR);
		/* EAGAIN means a prior notification already awaits dispatch. */
		if (written == -1 && errno != EAGAIN)
			return (-1);
	}
	return (result);
}
#ifndef NETWORK_STATE_TESTING
static void *
sample(void *argument)
{
	struct network_state_server *server = argument;
	struct sysctlcmp_client *client = NULL;
	struct sysctlcmp_interface entries[SYSCTLCMP_MAX_INTERFACES];
	struct network_state_snapshot state;
	struct pollfd stop = { .fd = server->stop[0], .events = POLLIN };
	size_t count;
	int error, result;
	for (;;) {
		memset(&state, 0, sizeof(state));
		count = nitems(entries);
		/* Discovery, HELLO and sampling share one shutdown-bounded wait. */
		result = service_budget_begin(1000);
		if (result == 0) {
			result = client == NULL ? sysctlcmp_client_open(&client) : 0;
			if (result == 0)
				result = sysctlcmp_interfaces(client, entries, &count);
			error = result == -1 ? (errno != 0 ? errno : EIO) : 0;
			service_budget_end();
		} else
			error = errno != 0 ? errno : EIO;
		if (result == -1) {
			if (client != NULL)
				sysctlcmp_client_close(client);
			client = NULL;
			state.source_error = error;
		} else {
			state.count = count;
			for (size_t i = 0; i < count; i++) {
				state.interfaces[i].index = entries[i].index;
				state.interfaces[i].flags = entries[i].flags;
				state.interfaces[i].mtu = entries[i].mtu;
				state.interfaces[i].link_state =
				    entries[i].link_state;
				memcpy(state.interfaces[i].name,
				    entries[i].name, sizeof(entries[i].name));
			}
		}
		(void)publish(server, &state);
		do {
			result = poll(&stop, 1, 1000);
		} while (result == -1 && errno == EINTR);
		if (result != 0)
			break;
	}
	if (client != NULL)
		sysctlcmp_client_close(client);
	return (NULL);
}
#endif
int
network_state_server_create(int kq, struct network_state_server **out)
{
	struct network_state_server *s;
	struct network_state_snapshot initial = { .source_error = EAGAIN };
	struct kevent change;
	int error;
	if (kq < 0 || out == NULL)
		return (errno = EINVAL, -1);
	*out = NULL;
	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return (-1);
	s->kq = kq;
	s->wake[0] = s->wake[1] = s->stop[0] = s->stop[1] = -1;
	if (notify_watch_create(sizeof(initial), STATE_CLIENTS, &s->store) ==
		-1 ||
	    pipe2(s->wake, O_CLOEXEC | O_CLOFORK | O_NONBLOCK) == -1 ||
	    pipe2(s->stop, O_CLOEXEC | O_CLOFORK | O_NONBLOCK) == -1 ||
	    publish(s, &initial) == -1)
		goto fail;
	EV_SET(&change, s->wake[0], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, s);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1)
		goto fail;
#ifndef NETWORK_STATE_TESTING
	error = pthread_create(&s->sampler, NULL, sample, s);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	s->started = true;
#endif
	*out = s;
	return (0);
fail:
	error = errno;
	network_state_server_destroy(s);
	return (errno = error, -1);
}
void
network_state_server_destroy(struct network_state_server *s)
{
	char byte = 1;
	if (s == NULL)
		return;
	if (s->started) {
		while (write(s->stop[1], &byte, 1) == -1 && errno == EINTR) {
		}
		pthread_join(s->sampler, NULL);
	}
	for (size_t i = 0; i < nitems(s->sessions); i++)
		close_session(&s->sessions[i]);
	if (s->wake[0] >= 0)
		close(s->wake[0]);
	if (s->wake[1] >= 0)
		close(s->wake[1]);
	if (s->stop[0] >= 0)
		close(s->stop[0]);
	if (s->stop[1] >= 0)
		close(s->stop[1]);
	if (s->store != NULL)
		(void)notify_watch_destroy(s->store);
	free(s);
}
int
network_state_server_add(struct network_state_server *server, int fd,
    const char *label)
{
	static const struct bsd_network_v1_NetworkState_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Watch = watch
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct state_session *s = NULL;
	struct kevent change;
	size_t same = 0;
	int error;
	if (server == NULL || fd < 0 || label == NULL || label[0] == 0 ||
	    strlen(label) >= sizeof(server->sessions[0].label)) {
		close(fd);
		return (errno = EINVAL, -1);
	}
	for (size_t i = 0; i < nitems(server->sessions); i++) {
		if (server->sessions[i].connection == NULL) {
			if (s == NULL)
				s = &server->sessions[i];
		} else if (strcmp(server->sessions[i].label, label) == 0)
			same++;
	}
	if (s == NULL || same >= STATE_LABEL_CLIENTS) {
		close(fd);
		return (errno = ENOSPC, -1);
	}
	s->server = server;
	strlcpy(s->label, label, sizeof(s->label));
	if (notify_watch_open(server->store, NULL, &s->watcher) == -1) {
		error = errno;
		close(fd);
		memset(s, 0, sizeof(*s));
		return (errno = error, -1);
	}
	/* A watch and a refused overlapping one; requests carry no fds. */
	options.max_queued_fds = 0;
	error = service_harden_fd(fd, 0) == -1 ? errno :
	    fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &s->connection);
	if (error != 0) {
		close(fd);
		notify_watch_close(s->watcher);
		memset(s, 0, sizeof(*s));
		return (errno = error, -1);
	}
	if ((error = bsd_network_v1_NetworkState_bind(s->connection, &handlers,
	    s)) != 0) {
		errno = error;
		goto fail;
	}
	EV_SET(&change, fidl_bsd_connection_fd(s->connection), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, server);
	if (kevent(server->kq, &change, 1, NULL, 0, NULL) == -1 ||
	    arm_timer(s, STATE_IDLE_MS) == -1)
		goto fail;
	return (0);
fail:
	error = errno;
	close_session(s);
	return (errno = error, -1);
}
int
network_state_server_event(struct network_state_server *server,
    const struct kevent *event)
{
	struct state_session *s;
	char bytes[256];
	int result;
	if (server == NULL || event->udata != server)
		return (0);
	if (event->filter == EVFILT_READ &&
	    event->ident == (uintptr_t)server->wake[0]) {
		while (read(server->wake[0], bytes, sizeof(bytes)) > 0) {
		}
		for (size_t i = 0; i < nitems(server->sessions); i++) {
			s = &server->sessions[i];
			if (s->connection == NULL)
				continue;
			deliver(s);
			if (s->error != 0)
				close_session(s);
		}
		return (1);
	}
	for (size_t i = 0; i < nitems(server->sessions); i++) {
		s = &server->sessions[i];
		if (s->connection == NULL)
			continue;
		if (event->filter == EVFILT_TIMER &&
		    event->ident == (uintptr_t)s) {
			if (s->pending == NULL)
				close_session(s);
			else {
				(void)notify_watch_cancel(s->watcher);
				if (send_error(s, s->pending, EAGAIN) == -1)
					s->error = errno;
				finish_pending(s);
				if (s->error != 0)
					close_session(s);
			}
			break;
		}
		if (event->filter == EVFILT_TIMER || event->ident !=
		    (uintptr_t)fidl_bsd_connection_fd(s->connection))
			continue;
		/* Reads and flushes in one bounded step; a refused frame
		 * (unknown method, malformed, pre-FIDL record) closes it. */
		result = (event->flags & EV_ERROR) != 0 ? EIO :
		    fidl_bsd_connection_dispatch(s->connection);
		if (result != 0 || s->error != 0 ||
		    ((event->flags & EV_EOF) != 0 &&
		    event->filter == EVFILT_READ) || write_interest(s) == -1)
			close_session(s);
		break;
	}
	return (1);
}
