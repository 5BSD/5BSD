/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
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
	struct channel *channel;
	struct channel_message *pending;
	struct notify_watcher *watcher;
	char label[256];
	int error;
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
	int pending = channel_wants_write(s->channel);
	if (pending == -1)
		return (-1);
	EV_SET(&change, channel_fd(s->channel), EVFILT_WRITE,
	    EV_ADD | (pending ? EV_ENABLE : EV_DISABLE), 0, 0, s->server);
	return (kevent(s->server->kq, &change, 1, NULL, 0, NULL));
}
static void
close_session(struct state_session *s)
{
	if (s->channel == NULL)
		return;
	(void)arm_timer(s, NETWORK_STATE_TIMEOUT_INFINITE);
	if (s->pending != NULL)
		channel_message_free(s->pending);
	notify_watch_close(s->watcher);
	channel_destroy(s->channel);
	memset(s, 0, sizeof(*s));
}
static int
send_error(struct state_session *s, struct channel_message *message, int error)
{
	struct network_state_header h = { .magic = NETWORK_STATE_MAGIC,
		.version = 1,
		.opcode = 1,
		.status = -error };
	struct channel_outgoing o = CHANNEL_OUTGOING_INITIALIZER(&h, sizeof(h));
	if (channel_send_reply(message, &o) == -1)
		return (-1);
	return (write_interest(s));
}
static void
finish_pending(struct state_session *s)
{
	channel_message_free(s->pending);
	s->pending = NULL;
	if (arm_timer(s, STATE_IDLE_MS) == -1)
		s->error = errno;
}
static void
deliver(struct state_session *s)
{
	struct network_state_reply r = { .header = {
					     .magic = NETWORK_STATE_MAGIC,
					     .version = 1,
					     .opcode = 1 } };
	struct notify_watch_cursor cursor;
	struct channel_outgoing o;
	uint32_t flags;
	size_t length;
	int result;
	if (s->pending == NULL)
		return;
	result = notify_watch_take(s->watcher, &r.state, sizeof(r.state),
	    &length, &cursor, &flags);
	if (result == 0)
		return;
	if (result == -1) {
		s->error = errno;
		return;
	}
	r.state.epoch = cursor.epoch;
	r.state.generation = cursor.generation;
	o = (struct channel_outgoing)CHANNEL_OUTGOING_INITIALIZER(&r,
	    NETWORK_STATE_REPLY_SIZE(r.state.count));
	if (channel_send_reply(s->pending, &o) == -1 || write_interest(s) == -1)
		s->error = errno;
	finish_pending(s);
}
static void
request(struct channel *channel __unused, struct channel_message *message,
    void *argument)
{
	struct state_session *s = argument;
	struct network_state_request r;
	if (s->error != 0) {
		channel_message_free(message);
		return;
	}
	if (channel_message_fd_count(message) != 0 ||
	    network_state_validate_request(channel_message_data(message),
		channel_message_length(message)) == -1) {
		s->error = EPROTO;
		channel_message_free(message);
		return;
	}
	memcpy(&r, channel_message_data(message), sizeof(r));
	if (s->pending != NULL) {
		if (send_error(s, message, EBUSY) == -1)
			s->error = errno;
		channel_message_free(message);
		return;
	}
	if (notify_watch_begin(s->watcher) == -1) {
		s->error = errno;
		channel_message_free(message);
		return;
	}
	s->pending = message;
	deliver(s);
	if (s->pending == NULL || s->error != 0)
		return;
	if (r.timeout_ms == 0) {
		(void)notify_watch_cancel(s->watcher);
		if (send_error(s, message, EAGAIN) == -1)
			s->error = errno;
		finish_pending(s);
	} else if (arm_timer(s, r.timeout_ms) == -1)
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
		result = client == NULL ? sysctlcmp_client_open(&client) : 0;
		if (result == 0)
			result = sysctlcmp_interfaces(client, entries, &count);
		if (result == -1) {
			error = errno != 0 ? errno : EIO;
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
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
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
		if (server->sessions[i].channel == NULL) {
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
	if (service_harden_fd(fd, 0) == -1 ||
	    channel_create(fd, &options, &s->channel) == -1) {
		error = errno;
		close(fd);
		notify_watch_close(s->watcher);
		memset(s, 0, sizeof(*s));
		return (errno = error, -1);
	}
	if (channel_set_request_handler(s->channel, request, s) == -1)
		goto fail;
	EV_SET(&change, channel_fd(s->channel), EVFILT_READ, EV_ADD | EV_ENABLE,
	    0, 0, server);
	if (kevent(server->kq, &change, 1, NULL, 0, NULL) == -1 ||
	    write_interest(s) == -1 || arm_timer(s, STATE_IDLE_MS) == -1)
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
			if (s->channel == NULL)
				continue;
			deliver(s);
			if (s->error != 0)
				close_session(s);
		}
		return (1);
	}
	for (size_t i = 0; i < nitems(server->sessions); i++) {
		s = &server->sessions[i];
		if (s->channel == NULL)
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
		if (event->filter == EVFILT_TIMER ||
		    event->ident != (uintptr_t)channel_fd(s->channel))
			continue;
		result = 0;
		if (event->flags & EV_ERROR)
			result = -1;
		else if (event->filter == EVFILT_READ)
			result = channel_dispatch(s->channel);
		else if (event->filter == EVFILT_WRITE)
			result = channel_flush(s->channel);
		if (result == -1 || s->error != 0 || (event->flags & EV_EOF) ||
		    write_interest(s) == -1)
			close_session(s);
		break;
	}
	return (1);
}
