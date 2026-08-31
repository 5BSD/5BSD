/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Blocking, thread-safe convenience adapter over asynchronous libchannel.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>

#include "libservice.h"
#include "service_bootstrap.h"
#include "serviced_ctl.h"
#include "serviced_svc_proto.h"

#define	CLIENT_EVENT_MAX	64
#define	CLIENT_POLL_MS		25
#define	CLIENT_FD_MAX		32

struct service_event {
	struct service_event	*next;
	struct service_message_metadata metadata;
	size_t			 length;
	size_t			 nfds;
	int			 fds[CLIENT_FD_MAX];
	unsigned char		 data[];
};

struct service_client {
	struct service_client	*registry_next;
	pthread_mutex_t		 lock;
	pthread_mutex_t		 channel_lock;
	pthread_cond_t		 idle;
	struct channel		*channel;
	struct service_event	*events_head;
	struct service_event	*events_tail;
	pid_t			 owner;
	unsigned		 active;
	unsigned		 nevents;
	int			 terminal_error;
	bool			 closing;
	bool			 event_overflow;
};

struct service_session {
	struct service_client *client;
};

static pthread_mutex_t client_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t client_atfork_once = PTHREAD_ONCE_INIT;
static struct service_client *client_registry;
static int client_atfork_error;

struct service_call {
	struct service_client	*client;
	pthread_cond_t		 cond;
	void			*reply;
	size_t			 reply_capacity;
	int			*reply_fds;
	size_t			*reply_nfds;
	size_t			 reply_fd_capacity;
	struct service_message_metadata *metadata;
	ssize_t			 received;
	int			 error;
	bool			 done;
};

static int
lock_mutex(pthread_mutex_t *lock) __no_lock_analysis
{
	int error;

	error = pthread_mutex_lock(lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static void
service_event_list_free(struct service_client *client)
{
	struct service_event *event;
	size_t i;

	while ((event = client->events_head) != NULL) {
		client->events_head = event->next;
		for (i = 0; i < event->nfds; i++)
			if (event->fds[i] >= 0)
				(void)close(event->fds[i]);
		free(event);
	}
	client->events_tail = NULL;
	client->nevents = 0;
}

static void
client_atfork_prepare(void) __no_lock_analysis
{
	struct service_client *client;

	(void)pthread_mutex_lock(&client_registry_lock);
	for (client = client_registry; client != NULL;
	    client = client->registry_next) {
		(void)pthread_mutex_lock(&client->channel_lock);
		(void)pthread_mutex_lock(&client->lock);
	}
}

static void
client_atfork_parent(void) __no_lock_analysis
{
	struct service_client *client;

	for (client = client_registry; client != NULL;
	    client = client->registry_next) {
		(void)pthread_mutex_unlock(&client->lock);
		(void)pthread_mutex_unlock(&client->channel_lock);
	}
	(void)pthread_mutex_unlock(&client_registry_lock);
}

static void
client_atfork_child(void) __no_lock_analysis
{
	struct service_client *client;

	for (client = client_registry; client != NULL;
	    client = client->registry_next) {
		if (client->channel != NULL)
			channel_abandon(client->channel);
		client->channel = NULL;
		service_event_list_free(client);
		client->active = 0;
		client->closing = true;
		client->terminal_error = ECHILD;
		client->owner = -1;
		(void)pthread_mutex_unlock(&client->lock);
		(void)pthread_mutex_unlock(&client->channel_lock);
	}
	client_registry = NULL;
	(void)pthread_mutex_unlock(&client_registry_lock);
}

static void
client_atfork_init(void)
{

	client_atfork_error = pthread_atfork(client_atfork_prepare,
	    client_atfork_parent, client_atfork_child);
}

static int
make_deadline(struct timespec *deadline, uint32_t timeout_ms)
{

	if (timeout_ms == SERVICE_CLIENT_TIMEOUT_INFINITE)
		return (0);
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (-1);
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return (0);
}

static bool
deadline_expired(const struct timespec *deadline, uint32_t timeout_ms)
{
	struct timespec now;

	if (timeout_ms == SERVICE_CLIENT_TIMEOUT_INFINITE)
		return (false);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (true);
	return (now.tv_sec > deadline->tv_sec ||
	    (now.tv_sec == deadline->tv_sec &&
	    now.tv_nsec >= deadline->tv_nsec));
}

static int
remaining_poll_ms(const struct timespec *deadline, uint32_t timeout_ms)
{
	struct timespec now;
	int64_t nanoseconds, milliseconds;

	if (timeout_ms == SERVICE_CLIENT_TIMEOUT_INFINITE)
		return (CLIENT_POLL_MS);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (0);
	nanoseconds = (deadline->tv_sec - now.tv_sec) * INT64_C(1000000000) +
	    deadline->tv_nsec - now.tv_nsec;
	if (nanoseconds <= 0)
		return (0);
	milliseconds = (nanoseconds + INT64_C(999999)) / INT64_C(1000000);
	return (milliseconds < CLIENT_POLL_MS ?
	    (int)milliseconds : CLIENT_POLL_MS);
}

static void
wait_slice(pthread_cond_t *condition, pthread_mutex_t *lock, int timeout_ms)
    __no_lock_analysis
{
	struct timespec until;

	if (timeout_ms <= 0)
		return;
	if (clock_gettime(CLOCK_REALTIME, &until) == -1)
		return;
	until.tv_sec += timeout_ms / 1000;
	until.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (until.tv_nsec >= 1000000000L) {
		until.tv_sec++;
		until.tv_nsec -= 1000000000L;
	}
	(void)pthread_cond_timedwait(condition, lock, &until);
}

static void
metadata_from_message(struct service_message_metadata *metadata,
    const struct channel_message *message)
{
	const struct channel_sender *sender;

	if (metadata == NULL)
		return;
	memset(metadata, 0, sizeof(*metadata));
	metadata->size = sizeof(*metadata);
	metadata->payload_length = channel_message_length(message);
	sender = channel_message_sender(message);
	if (sender != NULL) {
		metadata->sender_badge = sender->badge;
		metadata->sender_uid = sender->uid;
		metadata->sender_gid = sender->gid;
		metadata->sender_prison = sender->prison_id;
		metadata->sender_nonce = sender->nonce;
	}
}

static void
service_reply(struct channel_request *request,
    struct channel_message *message, int error, void *argument)
    __no_lock_analysis
{
	struct service_call *call;
	size_t i, nfds;

	call = argument;
	if (lock_mutex(&call->client->lock) == -1) {
		channel_message_free(message);
		channel_request_release(request);
		return;
	}
	if (error != 0) {
		call->error = error;
	} else {
		nfds = channel_message_fd_count(message);
		if (channel_message_length(message) > call->reply_capacity ||
		    nfds > call->reply_fd_capacity) {
			call->error = EMSGSIZE;
			*call->reply_nfds = nfds;
			metadata_from_message(call->metadata, message);
		} else {
			memcpy(call->reply, channel_message_data(message),
			    channel_message_length(message));
			for (i = 0; i < nfds; i++)
				call->reply_fds[i] =
				    channel_message_take_fd(message, i);
			*call->reply_nfds = nfds;
			metadata_from_message(call->metadata, message);
			call->received =
			    (ssize_t)channel_message_length(message);
		}
	}
	call->done = true;
	(void)pthread_cond_signal(&call->cond);
	(void)pthread_mutex_unlock(&call->client->lock);
	channel_message_free(message);
	channel_request_release(request);
}

static void
service_event(struct channel *channel, struct channel_message *message,
    void *argument) __no_lock_analysis
{
	struct service_client *client;
	struct service_event *event;
	size_t i, nfds;

	(void)channel;
	client = argument;
	if (lock_mutex(&client->lock) == -1) {
		channel_message_free(message);
		return;
	}
	nfds = channel_message_fd_count(message);
	if (client->closing || client->nevents >= CLIENT_EVENT_MAX ||
	    nfds > CLIENT_FD_MAX) {
		client->event_overflow |= !client->closing;
	} else {
		event = calloc(1, sizeof(*event) +
		    channel_message_length(message));
		if (event == NULL) {
			client->event_overflow = true;
		} else {
			metadata_from_message(&event->metadata, message);
			event->length = channel_message_length(message);
			event->nfds = nfds;
			memcpy(event->data, channel_message_data(message),
			    event->length);
			for (i = 0; i < nfds; i++)
				event->fds[i] = channel_message_take_fd(message, i);
			if (client->events_tail == NULL)
				client->events_head = event;
			else
				client->events_tail->next = event;
			client->events_tail = event;
			client->nevents++;
			(void)pthread_cond_broadcast(&client->idle);
		}
	}
	(void)pthread_mutex_unlock(&client->lock);
	channel_message_free(message);
}

static void
fail_client(struct service_client *client, int error) __no_lock_analysis
{

	if (lock_mutex(&client->lock) == -1)
		return;
	if (client->terminal_error == 0)
		client->terminal_error = error != 0 ? error : EIO;
	(void)pthread_cond_broadcast(&client->idle);
	(void)pthread_mutex_unlock(&client->lock);
}

static int
pump(struct service_client *client, int timeout_ms, bool *busy)
    __no_lock_analysis
{
	int error, result, ready, wants_write;

	*busy = false;
	error = pthread_mutex_trylock(&client->channel_lock);
	if (error == EBUSY) {
		*busy = true;
		return (0);
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	wants_write = channel_wants_write(client->channel);
	if (wants_write == -1) {
		error = errno;
		goto fail;
	}
	ready = channel_wait(client->channel, wants_write, timeout_ms);
	if (ready <= 0) {
		error = ready == -1 ? errno : 0;
		result = ready;
		goto out;
	}
	result = ready;
	if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
	    channel_flush(client->channel) == -1) {
		error = errno;
		goto fail;
	}
	if ((ready & CHANNEL_WAIT_READ) != 0) {
		result = channel_dispatch(client->channel);
		if (result == -1) {
			error = errno;
			goto fail;
		}
	}
	error = 0;
	goto out;
fail:
	fail_client(client, error);
	result = -1;
out:
	(void)pthread_mutex_unlock(&client->channel_lock);
	errno = error;
	return (result);
}

static int
service_client_create_internal(int fd, struct service_client **clientp)
    __no_lock_analysis
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct service_client *client;
	int error, initialized;
	bool channel_owns_fd;

	if (fd < 0 || clientp == NULL) {
		if (fd >= 0)
			(void)close(fd);
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	error = pthread_once(&client_atfork_once, client_atfork_init);
	if (error == 0)
		error = client_atfork_error;
	if (error != 0) {
		(void)close(fd);
		errno = error;
		return (-1);
	}
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		(void)close(fd);
		return (-1);
	}
	client->owner = getpid();
	initialized = 0;
	channel_owns_fd = false;
	error = pthread_mutex_init(&client->lock, NULL);
	if (error == 0) {
		initialized = 1;
		error = pthread_mutex_init(&client->channel_lock, NULL);
	}
	if (error == 0) {
		initialized = 2;
		error = pthread_cond_init(&client->idle, NULL);
	}
	if (error != 0)
		goto fail;
	initialized = 3;
	if (channel_create(fd, &options, &client->channel) == -1) {
		error = errno;
		goto fail;
	}
	channel_owns_fd = true;
	if (channel_set_event_handler(client->channel, service_event, client) ==
	    -1) {
		error = errno;
		channel_destroy(client->channel);
		goto fail;
	}
	error = pthread_mutex_lock(&client_registry_lock);
	if (error != 0) {
		channel_destroy(client->channel);
		goto fail;
	}
	client->registry_next = client_registry;
	client_registry = client;
	(void)pthread_mutex_unlock(&client_registry_lock);
	*clientp = client;
	return (0);
fail:
	if (!channel_owns_fd)
		(void)close(fd);
	if (initialized >= 3)
		(void)pthread_cond_destroy(&client->idle);
	if (initialized >= 2)
		(void)pthread_mutex_destroy(&client->channel_lock);
	if (initialized >= 1)
		(void)pthread_mutex_destroy(&client->lock);
	free(client);
	errno = error;
	return (-1);
}

static ssize_t
service_client_call_internal(struct service_client *client,
    const void *request_data,
    size_t request_length, const int *request_fds, size_t request_nfds,
    void *reply, size_t reply_capacity, int *reply_fds, size_t *reply_nfds,
    struct service_message_metadata *metadata,
    uint32_t timeout_ms) __no_lock_analysis
{
	struct channel_request *request;
	struct service_call call;
	struct timespec deadline;
	size_t i;
	ssize_t result;
	int cancel_state, error, poll_ms, pumped;
	bool busy, dispatch_attempted;

	if (client == NULL || request_data == NULL || request_length == 0 ||
	    reply == NULL || reply_capacity == 0 || reply_nfds == NULL ||
	    (request_nfds != 0 && request_fds == NULL) ||
	    (*reply_nfds != 0 && reply_fds == NULL) ||
	    request_nfds > CLIENT_FD_MAX || *reply_nfds > CLIENT_FD_MAX ||
	    (metadata != NULL && metadata->size != 0 &&
	    metadata->size != sizeof(*metadata))) {
		errno = EINVAL;
		return (-1);
	}
	if (make_deadline(&deadline, timeout_ms) == -1)
		return (-1);
	error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	memset(&call, 0, sizeof(call));
	call.client = client;
	call.reply = reply;
	call.reply_capacity = reply_capacity;
	call.reply_fds = reply_fds;
	call.reply_nfds = reply_nfds;
	call.reply_fd_capacity = *reply_nfds;
	call.metadata = metadata;
	for (i = 0; i < call.reply_fd_capacity; i++)
		reply_fds[i] = -1;
	*reply_nfds = 0;
	error = pthread_cond_init(&call.cond, NULL);
	if (error != 0)
		goto fail_cancel;
	if (lock_mutex(&client->lock) == -1) {
		error = errno;
		goto fail_cond;
	}
	if (client->owner != getpid()) {
		error = ECHILD;
		goto fail_locked;
	}
	if (client->closing || client->terminal_error != 0) {
		error = client->terminal_error != 0 ?
		    client->terminal_error : ECANCELED;
		goto fail_locked;
	}
	client->active++;
	(void)pthread_mutex_unlock(&client->lock);
	dispatch_attempted = false;

	if (lock_mutex(&client->channel_lock) == -1) {
		error = errno;
		goto fail_active;
	}
	if (channel_send_request(client->channel,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = request_data,
		.length = request_length,
		.fds = request_fds,
		.nfds = request_nfds
	    }, service_reply, &call, &request) == -1) {
		error = errno;
		(void)pthread_mutex_unlock(&client->channel_lock);
		goto fail_active;
	}
	(void)pthread_mutex_unlock(&client->channel_lock);

	for (;;) {
		if (lock_mutex(&client->lock) == -1) {
			error = errno;
			goto cancel;
		}
		if (call.done) {
			(void)pthread_mutex_unlock(&client->lock);
			break;
		}
		if (client->closing || client->terminal_error != 0 ||
		    (deadline_expired(&deadline, timeout_ms) &&
		    (timeout_ms != 0 || dispatch_attempted))) {
			error = client->terminal_error != 0 ?
			    client->terminal_error :
			    (client->closing ? ECANCELED : ETIMEDOUT);
			(void)pthread_mutex_unlock(&client->lock);
			goto cancel;
		}
		(void)pthread_mutex_unlock(&client->lock);
		poll_ms = remaining_poll_ms(&deadline, timeout_ms);
		pumped = pump(client, poll_ms, &busy);
		dispatch_attempted = true;
		if (pumped == -1) {
			error = errno;
			goto cancel;
		}
		if (pumped == 0 && busy && timeout_ms != 0) {
			if (lock_mutex(&client->lock) == -1) {
				error = errno;
				goto cancel;
			}
			if (!call.done)
				wait_slice(&call.cond, &client->lock, poll_ms);
			(void)pthread_mutex_unlock(&client->lock);
		}
	}
	error = call.error;
	result = error == 0 ? call.received : -1;
	goto complete;

cancel:
	if (lock_mutex(&client->channel_lock) == 0) {
		if (!call.done)
			(void)channel_request_cancel(request);
		(void)pthread_mutex_unlock(&client->channel_lock);
	}
	if (lock_mutex(&client->lock) == 0) {
		while (!call.done)
			(void)pthread_cond_wait(&call.cond, &client->lock);
		if (call.error != 0 && error == 0)
			error = call.error;
		(void)pthread_mutex_unlock(&client->lock);
	}
	result = -1;
complete:
	if (lock_mutex(&client->lock) == 0) {
		client->active--;
		if (client->active == 0)
			(void)pthread_cond_broadcast(&client->idle);
		(void)pthread_mutex_unlock(&client->lock);
	}
	(void)pthread_cond_destroy(&call.cond);
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = error;
	return (result);

fail_active:
	if (lock_mutex(&client->lock) == 0) {
		client->active--;
		if (client->active == 0)
			(void)pthread_cond_broadcast(&client->idle);
		(void)pthread_mutex_unlock(&client->lock);
	}
	goto fail_cond;
fail_locked:
	(void)pthread_mutex_unlock(&client->lock);
fail_cond:
	(void)pthread_cond_destroy(&call.cond);
fail_cancel:
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = error;
	return (-1);
}

static ssize_t
service_client_event_internal(struct service_client *client, void *data,
    size_t capacity, int *fds, size_t *nfdsp,
    struct service_message_metadata *metadata,
    uint32_t timeout_ms) __no_lock_analysis
{
	struct service_event *event;
	struct timespec deadline;
	size_t i;
	ssize_t result;
	int cancel_state, error, poll_ms, pumped;
	bool busy, dispatch_attempted;

	if (client == NULL || data == NULL || capacity == 0 || nfdsp == NULL ||
	    (*nfdsp != 0 && fds == NULL) || *nfdsp > CLIENT_FD_MAX ||
	    (metadata != NULL && metadata->size != 0 &&
	    metadata->size != sizeof(*metadata))) {
		errno = EINVAL;
		return (-1);
	}
	if (make_deadline(&deadline, timeout_ms) == -1)
		return (-1);
	error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (lock_mutex(&client->lock) == -1) {
		error = errno;
		goto fail;
	}
	if (client->owner != getpid()) {
		error = ECHILD;
		goto fail_locked;
	}
	if (client->closing) {
		error = ECANCELED;
		goto fail_locked;
	}
	client->active++;
	(void)pthread_mutex_unlock(&client->lock);
	dispatch_attempted = false;
	for (i = 0; i < *nfdsp; i++)
		fds[i] = -1;
	for (;;) {
		if (lock_mutex(&client->lock) == -1) {
			error = errno;
			goto fail_active;
		}
		event = client->events_head;
		if (event != NULL)
			break;
		if (client->event_overflow) {
			client->event_overflow = false;
			error = ENOBUFS;
			(void)pthread_mutex_unlock(&client->lock);
			goto fail_active;
		}
		if (client->terminal_error != 0 || client->closing) {
			error = client->terminal_error != 0 ?
			    client->terminal_error : ECANCELED;
			(void)pthread_mutex_unlock(&client->lock);
			goto fail_active;
		}
		if (deadline_expired(&deadline, timeout_ms) &&
		    (timeout_ms != 0 || dispatch_attempted)) {
			error = ETIMEDOUT;
			(void)pthread_mutex_unlock(&client->lock);
			goto fail_active;
		}
		(void)pthread_mutex_unlock(&client->lock);
		poll_ms = remaining_poll_ms(&deadline, timeout_ms);
		pumped = pump(client, poll_ms, &busy);
		dispatch_attempted = true;
		if (pumped == -1) {
			error = errno;
			goto fail_active;
		}
		if (pumped == 0 && busy && timeout_ms != 0) {
			if (lock_mutex(&client->lock) == -1) {
				error = errno;
				goto fail_active;
			}
			if (client->events_head == NULL)
				wait_slice(&client->idle, &client->lock, poll_ms);
			(void)pthread_mutex_unlock(&client->lock);
		}
	}
	if (event->length > capacity || event->nfds > *nfdsp) {
		*nfdsp = event->nfds;
		if (metadata != NULL) {
			*metadata = event->metadata;
			metadata->payload_length = event->length;
		}
		error = EMSGSIZE;
		(void)pthread_mutex_unlock(&client->lock);
		goto fail_active;
	}
	client->events_head = event->next;
	if (client->events_head == NULL)
		client->events_tail = NULL;
	client->nevents--;
	memcpy(data, event->data, event->length);
	for (i = 0; i < event->nfds; i++) {
		fds[i] = event->fds[i];
		event->fds[i] = -1;
	}
	*nfdsp = event->nfds;
	if (metadata != NULL)
		*metadata = event->metadata;
	result = (ssize_t)event->length;
	client->active--;
	if (client->active == 0)
		(void)pthread_cond_broadcast(&client->idle);
	(void)pthread_mutex_unlock(&client->lock);
	free(event);
	(void)pthread_setcancelstate(cancel_state, NULL);
	return (result);

fail_active:
	if (lock_mutex(&client->lock) == 0) {
		client->active--;
		if (client->active == 0)
			(void)pthread_cond_broadcast(&client->idle);
		(void)pthread_mutex_unlock(&client->lock);
	}
	goto fail;
fail_locked:
	(void)pthread_mutex_unlock(&client->lock);
fail:
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = error;
	return (-1);
}

static int
service_client_close_internal(struct service_client *client)
    __no_lock_analysis
{
	struct service_client **link;
	int error;

	if (client == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (client->owner != getpid()) {
		if (client->channel != NULL)
			channel_abandon(client->channel);
		service_event_list_free(client);
		(void)pthread_cond_destroy(&client->idle);
		(void)pthread_mutex_destroy(&client->channel_lock);
		(void)pthread_mutex_destroy(&client->lock);
		free(client);
		return (0);
	}
	if (lock_mutex(&client->lock) == -1)
		return (-1);
	client->closing = true;
	(void)pthread_cond_broadcast(&client->idle);
	while (client->active != 0)
		(void)pthread_cond_wait(&client->idle, &client->lock);
	service_event_list_free(client);
	(void)pthread_mutex_unlock(&client->lock);
	error = pthread_mutex_lock(&client_registry_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	if (lock_mutex(&client->channel_lock) == -1) {
		(void)pthread_mutex_unlock(&client_registry_lock);
		return (-1);
	}
	for (link = &client_registry; *link != NULL;
	    link = &(*link)->registry_next) {
		if (*link == client) {
			*link = client->registry_next;
			break;
		}
	}
	channel_destroy(client->channel);
	(void)pthread_mutex_unlock(&client->channel_lock);
	(void)pthread_mutex_unlock(&client_registry_lock);
	error = pthread_cond_destroy(&client->idle);
	(void)pthread_mutex_destroy(&client->channel_lock);
	(void)pthread_mutex_destroy(&client->lock);
	free(client);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
service_session_create(int fd, struct service_session **sessionp)
{
	struct service_session *session;
	int error, owned;

	if (fd < 0 || sessionp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*sessionp = NULL;
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1)
		return (-1);
	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		(void)close(owned);
		return (-1);
	}
	if (service_client_create_internal(owned, &session->client) == -1) {
		error = errno;
		free(session);
		errno = error;
		return (-1);
	}
	(void)close(fd);
	*sessionp = session;
	return (0);
}

int
service_session_fail(struct service_session *session, int error)
{

	if (session == NULL || session->client == NULL || error <= 0 ||
	    error > ELAST) {
		errno = EINVAL;
		return (-1);
	}
	if (session->client->owner != getpid()) {
		errno = ECHILD;
		return (-1);
	}
	fail_client(session->client, error);
	errno = error;
	return (0);
}

void
service_session_close(struct service_session *session)
{
	int error;

	if (session == NULL)
		return;
	error = errno;
	(void)service_client_close_internal(session->client);
	free(session);
	errno = error;
}

static int
service_structures_valid(const struct service_reply *reply,
    const struct service_call_options *options)
{

	if (reply == NULL || reply->size < sizeof(*reply) ||
	    reply->data == NULL || reply->capacity == 0 ||
	    (reply->fd_capacity != 0 && reply->fds == NULL) ||
	    reply->fd_capacity > CLIENT_FD_MAX || options == NULL ||
	    options->size < sizeof(*options) || options->flags != 0 ||
	    options->reserved[0] != 0 || options->reserved[1] != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
service_session_call(struct service_session *session,
    const struct service_message *message, struct service_reply *reply,
    const struct service_call_options *options)
{
	size_t fd_capacity;
	ssize_t received;

	if (session == NULL || session->client == NULL || message == NULL ||
	    message->size < sizeof(*message) || message->data == NULL ||
	    message->length == 0 ||
	    (message->nfds != 0 && message->fds == NULL) ||
	    message->nfds > CLIENT_FD_MAX) {
		errno = EINVAL;
		return (-1);
	}
	if (service_structures_valid(reply, options) == -1)
		return (-1);
	/* Calls need a deadline or an explicit infinite wait; events may poll. */
	if (options->timeout_ms == 0) {
		errno = EINVAL;
		return (-1);
	}
	fd_capacity = reply->fd_capacity;
	reply->length = 0;
	reply->nfds = fd_capacity;
	memset(&reply->metadata, 0, sizeof(reply->metadata));
	reply->metadata.size = sizeof(reply->metadata);
	received = service_client_call_internal(session->client,
	    message->data, message->length, message->fds, message->nfds,
	    reply->data, reply->capacity, reply->fds, &reply->nfds,
	    &reply->metadata, options->timeout_ms);
	if (received == -1) {
		reply->length = reply->metadata.payload_length;
		return (-1);
	}
	reply->length = (size_t)received;
	return (0);
}

int
service_session_receive_event(struct service_session *session,
    struct service_reply *event, const struct service_call_options *options)
{
	ssize_t received;

	if (session == NULL || session->client == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (service_structures_valid(event, options) == -1)
		return (-1);
	event->length = 0;
	event->nfds = event->fd_capacity;
	memset(&event->metadata, 0, sizeof(event->metadata));
	event->metadata.size = sizeof(event->metadata);
	received = service_client_event_internal(session->client, event->data,
	    event->capacity, event->fds, &event->nfds, &event->metadata,
	    options->timeout_ms);
	if (received == -1) {
		event->length = event->metadata.payload_length;
		return (-1);
	}
	event->length = (size_t)received;
	return (0);
}

/*
 * Ask serviced, over an inherited SYSTEM-domain lookup channel, to mint a
 * session lookup channel and return the caller's endpoint in *out_fd (§6/§21/
 * §22).  `kind` selects the scope: SERVICE_MINT_USER mints a per-uid scoped
 * channel; SERVICE_MINT_SYSTEM mints a full-discovery admin channel (uid is
 * ignored for SYSTEM).
 *
 * syschan is borrowed: this call neither closes it nor keeps a reference.  The
 * returned descriptor is ambient — serviced marks it CAP_CLOFORK_UNLOCKED and
 * clears its close-on-exec flag — so the login/session path can install it as
 * a session leader's inherited lookup channel and every descendant shares the
 * minted domain.  Because domains only narrow, the request succeeds only when
 * syschan is itself a SYSTEM-domain channel; serviced returns EPERM otherwise,
 * and likewise refuses a SERVICE_MINT_SYSTEM request from a non-SYSTEM channel.
 */
static int
mint_session_domain_impl(int syschan, enum service_mint_kind kind, uid_t uid,
    uint32_t reqflags, unsigned timeout_ms, int *out_fd)
{
	struct svc_mint_domain_req req;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
		.fds = NULL,
		.nfds = 0,
	};
	int reply_fd;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
		.fds = &reply_fd,
		.fd_capacity = 1,
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	int dupfd, error;

	if (syschan < 0 || out_fd == NULL ||
	    (kind != SERVICE_MINT_USER && kind != SERVICE_MINT_SYSTEM)) {
		errno = EINVAL;
		return (-1);
	}
	*out_fd = -1;
	reply_fd = -1;

	/*
	 * Bound the mint RPC so a wedged serviced can never hang the caller.
	 * login/su pass a generous cap (post-auth, watchdog disabled); the sshd
	 * listener passes a tight one because it mints synchronously in its
	 * single-threaded accept loop, where a long stall would serialize and
	 * throttle ALL new connections.  Either way a timeout is treated as "no
	 * ambient channel" and the caller proceeds.
	 */
	options.timeout_ms = timeout_ms;

	/*
	 * service_session_create() takes ownership of the descriptor it is
	 * given (it re-duplicates and closes it), so hand it a private
	 * duplicate and leave the borrowed syschan untouched.
	 */
	dupfd = fcntl(syschan, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (-1);
	if (service_session_create(dupfd, &session) == -1) {
		error = errno;
		(void)close(dupfd);
		errno = error;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_MINT_DOMAIN;
	req.flags = reqflags;
	req.uid = (uint32_t)uid;
	req.domain = kind == SERVICE_MINT_SYSTEM ?
	    SVC_MINT_DOMAIN_SYSTEM : SVC_MINT_DOMAIN_USER;

	if (service_session_call(session, &message, &reply, &options) == -1) {
		error = errno;
		service_session_close(session);
		errno = error;
		return (-1);
	}
	service_session_close(session);

	if (reply.length != sizeof(reply_data)) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = EBADMSG;
		return (-1);
	}
	if (reply_data.status != 0) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = reply_data.status;
		return (-1);
	}
	if (reply.nfds != 1 || reply_fd < 0) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = EBADMSG;
		return (-1);
	}
	*out_fd = reply_fd;
	return (0);
}

int
service_mint_session_domain(int syschan, enum service_mint_kind kind, uid_t uid,
    int *out_fd)
{

	return (mint_session_domain_impl(syschan, kind, uid, 0, 2000U, out_fd));
}

/*
 * Like service_mint_session_domain(), but the minted descriptor is delivered
 * transferable (default CAP_XFER_UNLIMITED) instead of install-only.  A caller
 * that must forward it over ONE more SCM_RIGHTS hop before installing it —
 * sshd's privileged monitor, which mints the session channel and then
 * mm_send_fd()s it to the unprivileged session child — needs this; the monitor
 * re-attenuates to CAP_XFER_ONCE before that send so the child still lands at
 * CAP_XFER_NONE.  Ordinary login/su sessions install by fork/exec inheritance
 * and must NOT use this.
 */
int
service_mint_session_domain_resend(int syschan, enum service_mint_kind kind,
    uid_t uid, int *out_fd)
{

	return (mint_session_domain_impl(syschan, kind, uid,
	    SVC_MINT_FLAG_RESEND, 2000U, out_fd));
}

/*
 * Connect to a named service over the ambient lookup channel.
 *
 * This is the client counterpart to service_connect().  service_connect()
 * resolves a name over the bootstrap dispatch channel serviced hands a
 * service it launches (SERVICE_BOOTSTRAP_FD); a program run from a shell has
 * no such bootstrap, only the §21 ambient lookup channel its login session
 * inherited (SERVICE_LOOKUP_FD).  This sends the same SVC_OP_LOOKUP over that
 * ambient channel: serviced's lookup_channel_request() dispatches it scoped to
 * the channel's domain and returns a connected session endpoint in the reply.
 *
 * On success *session_fdp is a caller-owned session channel to the provider.
 * ENOENT if the process has no ambient lookup channel, or if the name is not
 * resolvable in that channel's domain.  Bounded like the mint RPC so a wedged
 * serviced cannot stall a CLI forever.
 */
int
service_connect_ambient(const char *name, int *session_fdp)
{
	struct svc_lookup_req req;
	struct svc_reply reply_data;
	struct service_message message = {
		.size = sizeof(message),
		.data = &req,
		.length = sizeof(req),
		.fds = NULL,
		.nfds = 0,
	};
	int reply_fd;
	struct service_reply reply = {
		.size = sizeof(reply),
		.data = &reply_data,
		.capacity = sizeof(reply_data),
		.fds = &reply_fd,
		.fd_capacity = 1,
	};
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *session;
	int ambient, dupfd, error;

	if (name == NULL || session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;
	reply_fd = -1;
	if (strlen(name) > SERVICED_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	/* No ambient lookup channel -> not reachable this way (errno ENOENT). */
	ambient = service_ambient_lookup_fd();
	if (ambient < 0)
		return (-1);

	options.timeout_ms = 2000U;

	/*
	 * service_session_create() takes ownership of the descriptor it is
	 * given, so hand it a private duplicate and leave the shared ambient
	 * channel untouched.
	 */
	dupfd = fcntl(ambient, F_DUPFD_CLOEXEC, 0);
	if (dupfd == -1)
		return (-1);
	if (service_session_create(dupfd, &session) == -1) {
		error = errno;
		(void)close(dupfd);
		errno = error;
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, name, sizeof(req.name));

	if (service_session_call(session, &message, &reply, &options) == -1) {
		error = errno;
		service_session_close(session);
		errno = error;
		return (-1);
	}
	service_session_close(session);

	if (reply.length != sizeof(reply_data)) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = EBADMSG;
		return (-1);
	}
	if (reply_data.status != 0) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = reply_data.status;
		return (-1);
	}
	if (reply.nfds != 1 || reply_fd < 0) {
		if (reply_fd >= 0)
			(void)close(reply_fd);
		errno = EBADMSG;
		return (-1);
	}
	*session_fdp = reply_fd;
	return (0);
}

/*
 * Resolve a named service to a connected session channel, whichever context
 * the caller runs in.  A serviced-launched service carries a bootstrap
 * dispatch channel; a program run from a shell carries only the ambient
 * lookup channel.  Try the bootstrap path first (it is the richer context),
 * and fall back to the ambient channel when there is no bootstrap.  Consumer
 * libraries (libnetworkcmp, liblogcmp, ...) call this so their client_open()
 * works both when launched by serviced and when run as a CLI.
 */
int
service_open(const char *name, int *session_fdp)
{
	struct service_context *service;
	int rv, error;

	if (name == NULL || session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;

	/*
	 * Bootstrap context (serviced-launched service).  When present it is
	 * authoritative: resolve over it and return its result verbatim -- do
	 * not mask a genuine ENOENT by retrying on the ambient channel.
	 */
	if (service_acquire(&service) == 0) {
		rv = service_connect(service, name, session_fdp);
		error = errno;
		service_release(service);
		errno = error;
		return (rv);
	}

	/* No bootstrap: a CLI or ambient client.  Use the login lookup channel. */
	return (service_connect_ambient(name, session_fdp));
}

/*
 * Backward-compatible wrapper for existing USER-domain callers: mint a per-uid
 * scoped session channel.  See service_mint_session_domain().
 */
int
service_mint_user_domain(int syschan, uid_t uid, int *out_fd)
{

	return (service_mint_session_domain(syschan, SERVICE_MINT_USER, uid,
	    out_fd));
}

