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
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
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
#include "service_private.h"
#include "lookup_identity.h"
#include "service_runtime.h"
#include "switchboard_ctl.h"
#include "switchboard_svc_proto.h"

#define	CLIENT_EVENT_MAX	64
#define	CLIENT_FD_MAX		32

struct service_event {
	struct service_event	*next;
	struct service_message_metadata metadata;
	size_t			 length;
	size_t			 nfds;
	int			 fds[CLIENT_FD_MAX];
	unsigned char		 data[];
};

/*
 * Waiting on a session (service_runtime(3)).  One thread at a time is the
 * receiver: it sleeps in the kernel for the next message without any lock
 * (channel_receive_wait()), then dispatches it under channel_lock, which
 * completes the call it answers or queues the event, and broadcasts `wake`.
 * Every other waiter sleeps on `wake` until its own reply or event is there,
 * its deadline passes, or the receiver leaves (it takes over).  Senders take
 * channel_lock only to register a request and sleep in the kernel for queue
 * room under send_lock alone, so a sleeping receiver never delays them.
 * Lock order: channel_lock, then lock; send_lock is taken alone.
 */
struct service_client {
	struct service_client	*registry_next;
	pthread_mutex_t		 lock;
	pthread_mutex_t		 channel_lock;
	pthread_mutex_t		 send_lock;
	pthread_cond_t		 idle;
	pthread_cond_t		 wake;	/* (lock) a call, event or receiver changed */
	struct channel		*channel;
	struct service_event	*events_head;
	struct service_event	*events_tail;
	pid_t			 owner;
	unsigned		 active;
	unsigned		 nevents;
	int			 terminal_error;
	bool			 closing;
	bool			 event_overflow;
	bool			 receiving;	/* (lock) a thread is the receiver */
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
		/*
		 * Not send_lock: a sender may sleep in the kernel holding it
		 * for as long as the peer's queue stays full.  The child
		 * re-creates it.
		 */
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
		client->receiving = false;
		(void)pthread_mutex_init(&client->send_lock, NULL);
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

/* What is left of the call's deadline, for the kernel: -1 none, 0 passed. */
static int
remaining_ms(const struct timespec *deadline, uint32_t timeout_ms)
{
	struct timespec now;
	int64_t nanoseconds, milliseconds;

	if (timeout_ms == SERVICE_CLIENT_TIMEOUT_INFINITE)
		return (-1);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (0);
	nanoseconds = (deadline->tv_sec - now.tv_sec) * INT64_C(1000000000) +
	    deadline->tv_nsec - now.tv_nsec;
	if (nanoseconds <= 0)
		return (0);
	milliseconds = (nanoseconds + INT64_C(999999)) / INT64_C(1000000);
	return (milliseconds > INT_MAX ? INT_MAX : (int)milliseconds);
}

/* Every timed condition wait uses the session deadline's clock. */
static int
monotonic_cond_init(pthread_cond_t *condition)
{
	pthread_condattr_t attributes;
	int error;

	error = pthread_condattr_init(&attributes);
	if (error != 0)
		return (error);
	error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
	if (error == 0)
		error = pthread_cond_init(condition, &attributes);
	(void)pthread_condattr_destroy(&attributes);
	return (error);
}

/* Sleep on `wake` until signalled or the call's deadline (one deadline). */
static void
wait_wake(struct service_client *client, const struct timespec *deadline,
    uint32_t timeout_ms) __no_lock_analysis
{

	if (timeout_ms == SERVICE_CLIENT_TIMEOUT_INFINITE)
		(void)pthread_cond_wait(&client->wake, &client->lock);
	else
		(void)pthread_cond_timedwait(&client->wake, &client->lock,
		    deadline);
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
		metadata->sender_abi = sender->abi;
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
	(void)pthread_cond_broadcast(&call->client->wake);
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
			(void)pthread_cond_broadcast(&client->wake);
		}
	}
	(void)pthread_mutex_unlock(&client->lock);
	channel_message_free(message);
}

/*
 * End the session's channel so that a thread asleep in the kernel on it (the
 * receiver, or a sender waiting for room) wakes at once: the instance is
 * revoked.  The session has failed or is closing.
 */
static void
terminate_channel(struct service_client *client)
{

	if (client->channel != NULL)
		(void)ioctl(channel_fd(client->channel),
		    MAC_CAPABILITY_TERMINATE, NULL);
}

static void
fail_client(struct service_client *client, int error) __no_lock_analysis
{
	bool first;

	if (lock_mutex(&client->lock) == -1)
		return;
	first = client->terminal_error == 0;
	if (first)
		client->terminal_error = error != 0 ? error : EIO;
	(void)pthread_cond_broadcast(&client->idle);
	(void)pthread_cond_broadcast(&client->wake);
	(void)pthread_mutex_unlock(&client->lock);
	if (first)
		terminate_channel(client);
}

/*
 * Be the receiver once: called with client->lock held and no receiver;
 * returns with it held.  Sleeps in the kernel until a message comes or
 * `deadline` (none for SERVICE_CLIENT_TIMEOUT_INFINITE) passes, delivers it,
 * then gives the role up and wakes the other waiters, which re-check their
 * own replies (one of them takes the role over).  A signal ends the sleep as
 * for read(2): SA_RESTART restarts it in the kernel, otherwise this returns
 * EINTR for the caller; only the receiving thread sees it.  Other errors fail
 * the session.
 */
static int
receive_once(struct service_client *client, const struct timespec *deadline,
    uint32_t timeout_ms) __no_lock_analysis
{
	int dispatched, error, ready;

	client->receiving = true;
	(void)pthread_mutex_unlock(&client->lock);
	ready = channel_receive_wait(client->channel,
	    remaining_ms(deadline, timeout_ms));
	error = ready == -1 ? errno : 0;
	if (ready == 1) {
		if (lock_mutex(&client->channel_lock) == 0) {
			dispatched = channel_dispatch(client->channel);
			error = dispatched == -1 ? errno : 0;
			(void)pthread_mutex_unlock(&client->channel_lock);
		} else
			error = errno;
	}
	(void)lock_mutex(&client->lock);
	client->receiving = false;
	(void)pthread_cond_broadcast(&client->wake);
	/* A close revokes the channel to wake us: that is not a failure. */
	if (error != 0 && error != EINTR && !client->closing) {
		(void)pthread_mutex_unlock(&client->lock);
		fail_client(client, error);
		(void)lock_mutex(&client->lock);
	}
	return (error == EINTR ? EINTR : 0);
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
		error = monotonic_cond_init(&client->idle);
	}
	if (error == 0) {
		initialized = 3;
		error = monotonic_cond_init(&client->wake);
	}
	if (error == 0) {
		initialized = 4;
		error = pthread_mutex_init(&client->send_lock, NULL);
	}
	if (error != 0)
		goto fail;
	initialized = 5;
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
	if (initialized >= 5)
		(void)pthread_mutex_destroy(&client->send_lock);
	if (initialized >= 4)
		(void)pthread_cond_destroy(&client->wake);
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
	const struct channel_outgoing outgoing = {
		.size = sizeof(struct channel_outgoing),
		.data = request_data,
		.length = request_length,
		.fds = request_fds,
		.nfds = request_nfds
	};
	struct channel_request *request;
	struct service_call call;
	struct timespec deadline;
	size_t i;
	ssize_t result;
	int cancel_state, error, sent;
	bool attempted;

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
	if (service_budget_timeout(&timeout_ms) == -1 ||
	    make_deadline(&deadline, timeout_ms) == -1)
		return (-1);
	/* Session calls are not cancellation points (service_runtime(3)). */
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
	if (lock_mutex(&client->lock) == -1) {
		error = errno;
		goto fail_cancel;
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

	/* Register the reply token, then send without channel_lock. */
	if (lock_mutex(&client->channel_lock) == -1) {
		error = errno;
		goto fail_active;
	}
	if (channel_request_start(client->channel, &outgoing, service_reply,
	    &call, &request) == -1) {
		error = errno;
		(void)pthread_mutex_unlock(&client->channel_lock);
		goto fail_active;
	}
	(void)pthread_mutex_unlock(&client->channel_lock);
	if (lock_mutex(&client->send_lock) == -1) {
		error = errno;
		sent = -1;
	} else {
		sent = channel_request_send_wait(client->channel, request,
		    &outgoing);
		error = sent == -1 ? errno : 0;
		(void)pthread_mutex_unlock(&client->send_lock);
	}
	if (sent == -1) {
		/* Not sent: no reply can come; forget the request. */
		if (lock_mutex(&client->channel_lock) == 0) {
			channel_request_unsend(request, error);
			(void)pthread_mutex_unlock(&client->channel_lock);
		}
		/* A peer that is gone reads as on receive (ECONNRESET). */
		if (error == EPIPE)
			error = ECONNRESET;
		/* A close revoked the channel to wake the send. */
		if (error != EINTR && lock_mutex(&client->lock) == 0) {
			if (client->closing)
				error = ECANCELED;
			(void)pthread_mutex_unlock(&client->lock);
		}
		goto fail_active;
	}

	attempted = false;
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
		    (timeout_ms != 0 || attempted))) {
			error = client->terminal_error != 0 ?
			    client->terminal_error :
			    (client->closing ? ECANCELED : ETIMEDOUT);
			(void)pthread_mutex_unlock(&client->lock);
			goto cancel;
		}
		if (!client->receiving) {
			attempted = true;
			error = receive_once(client, &deadline, timeout_ms);
			(void)pthread_mutex_unlock(&client->lock);
			if (error != 0)
				goto cancel;
			continue;
		}
		/* A zero timeout never waits for another thread's receive. */
		if (timeout_ms == 0)
			attempted = true;
		else
			wait_wake(client, &deadline, timeout_ms);
		(void)pthread_mutex_unlock(&client->lock);
	}
	error = call.error;
	result = error == 0 ? call.received : -1;
	goto complete;

cancel:
	if (lock_mutex(&client->channel_lock) == 0) {
		if (lock_mutex(&client->lock) == 0) {
			if (!call.done) {
				(void)pthread_mutex_unlock(&client->lock);
				(void)channel_request_cancel(request);
			} else
				(void)pthread_mutex_unlock(&client->lock);
		}
		(void)pthread_mutex_unlock(&client->channel_lock);
	}
	if (lock_mutex(&client->lock) == 0) {
		while (!call.done)
			(void)pthread_cond_wait(&client->wake, &client->lock);
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
	goto fail_cancel;
fail_locked:
	(void)pthread_mutex_unlock(&client->lock);
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
	int cancel_state, error;
	bool attempted;

	if (client == NULL || data == NULL || capacity == 0 || nfdsp == NULL ||
	    (*nfdsp != 0 && fds == NULL) || *nfdsp > CLIENT_FD_MAX ||
	    (metadata != NULL && metadata->size != 0 &&
	    metadata->size != sizeof(*metadata))) {
		errno = EINVAL;
		return (-1);
	}
	if (service_budget_timeout(&timeout_ms) == -1 ||
	    make_deadline(&deadline, timeout_ms) == -1)
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
	attempted = false;
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
		    (timeout_ms != 0 || attempted)) {
			error = ETIMEDOUT;
			(void)pthread_mutex_unlock(&client->lock);
			goto fail_active;
		}
		if (!client->receiving) {
			attempted = true;
			error = receive_once(client, &deadline, timeout_ms);
			(void)pthread_mutex_unlock(&client->lock);
			if (error != 0)
				goto fail_active;
			continue;
		}
		if (timeout_ms == 0)
			attempted = true;
		else
			wait_wake(client, &deadline, timeout_ms);
		(void)pthread_mutex_unlock(&client->lock);
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
		(void)pthread_cond_destroy(&client->wake);
		(void)pthread_cond_destroy(&client->idle);
		(void)pthread_mutex_destroy(&client->send_lock);
		(void)pthread_mutex_destroy(&client->channel_lock);
		(void)pthread_mutex_destroy(&client->lock);
		free(client);
		return (0);
	}
	if (lock_mutex(&client->lock) == -1)
		return (-1);
	client->closing = true;
	(void)pthread_cond_broadcast(&client->idle);
	(void)pthread_cond_broadcast(&client->wake);
	/* Wake a receiver or a sender asleep in the kernel. */
	if (client->active != 0)
		terminate_channel(client);
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
	(void)pthread_cond_destroy(&client->wake);
	(void)pthread_mutex_destroy(&client->send_lock);
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

/*
 * A session that has hit a terminal error (the provider went away, or a
 * protocol violation ended it) never recovers: every later call fails with
 * the same errno.  Callers that cache a session use this to drop a dead one
 * and open a fresh session -- the provider may have been relaunched.
 */
bool
service_session_is_dead(const struct service_session *session)
    __no_lock_analysis
{
	struct service_client *client;
	bool dead;

	if (session == NULL || session->client == NULL)
		return (true);
	client = session->client;
	if (pthread_mutex_lock(&client->lock) != 0)
		return (true);
	dead = client->closing || client->terminal_error != 0;
	(void)pthread_mutex_unlock(&client->lock);
	return (dead);
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
 * Connect to a named service over the ambient lookup channel.
 *
 * This is the client counterpart to service_connect().  service_connect()
 * resolves a name over the bootstrap dispatch channel switchboard hands a
 * service it launches (SERVICE_BOOTSTRAP_FD); a program run from a shell has
 * no such bootstrap, only the §21 ambient lookup channel its login session
 * inherited through kernel process state.  This sends the same SVC_OP_LOOKUP over that
 * ambient channel: switchboard's lookup_channel_request() dispatches it scoped to
 * the channel's domain and returns a connected session endpoint in the reply.
 *
 * On success *session_fdp is a caller-owned session channel to the provider.
 * ENOENT if the process has no ambient lookup channel, or if the name is not
 * resolvable in that channel's domain.  The call waits for switchboard's
 * answer with no time limit (an on-demand activation is bounded by
 * switchboard itself); ECONNRESET if the switchboard serving the private
 * channel exits, EINTR as service_runtime(3) describes.
 *
 * The private channel belongs to this call alone, so the exchange is one raw
 * request and one raw reply rather than a session, whose waits are sliced.
 */
#define	LOOKUP_REQUEST_TOKEN	1ULL	/* any non-zero token: a request */

static int
service_lookup_over_channel(int lookup_chan, const char *name, int *session_fdp)
{
	struct mac_capability_sendmsg_args send;
	struct mac_capability_recvmsg_args recv;
	struct service_lookup_owned owned;
	struct svc_lookup_req req;
	struct svc_reply reply;
	int error, pd = -1, reply_fd = -1;

	*session_fdp = -1;
	if (lookup_chan < 0) {
		errno = ENOENT;
		return (-1);
	}
	memset(&req, 0, sizeof(req));
	req.op = SVC_OP_LOOKUP;
	strlcpy(req.name, name, sizeof(req.name));
	if (service_lookup_identity(&pd) == -1)
		return (-1);
	owned.process = &pd;
	owned.reply = &reply_fd;
	owned.session = NULL;
	/* The wait for room in a full queue is a cancellation point. */
	pthread_cleanup_push(service_lookup_cleanup, &owned);

	memset(&send, 0, sizeof(send));
	send.payload = &req;
	send.payload_len = sizeof(req);
	send.fds = pd >= 0 ? &pd : NULL;
	send.nfds = pd >= 0 ? 1 : 0;
	send.reply_token = LOOKUP_REQUEST_TOKEN;
	error = service_channel_send_wait(lookup_chan, &send) == -1 ? errno : 0;
	pthread_cleanup_pop(0);
	if (pd >= 0)
		(void)close(pd);
	if (error != 0)
		return (errno = error, -1);

	memset(&recv, 0, sizeof(recv));
	memset(&reply, 0, sizeof(reply));
	recv.payload = &reply;
	recv.payload_len = sizeof(reply);
	recv.fds = &reply_fd;
	recv.nfds = 1;
	if (service_channel_recv_wait(lookup_chan, &recv) == -1)
		return (-1);
	if (recv.reply_token != LOOKUP_REQUEST_TOKEN ||
	    recv.payload_len != sizeof(reply) || reply.status < 0 ||
	    reply.status > ELAST ||
	    (reply.status == 0 ? recv.nfds != 1 || reply_fd < 0 :
	    recv.nfds != 0)) {
		if (recv.nfds != 0 && reply_fd >= 0)
			(void)close(reply_fd);
		errno = EBADMSG;
		return (-1);
	}
	if (reply.status != 0) {
		errno = reply.status;
		return (-1);
	}
	*session_fdp = reply_fd;
	return (0);
}

static void
close_lookup_channel(void *arg)
{

	(void)close(*(int *)arg);
}

int
service_connect_ambient(const char *name, int *session_fdp)
{

	if (name == NULL || session_fdp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*session_fdp = -1;
	if (strlen(name) > SWITCHBOARD_NAME_MAX) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	/* An owned private reply channel keeps independent calls isolated. */
	{
		int fd, error, result;

		fd = service_ambient_lookup_channel();
		if (fd == -1)
			return (-1);
		pthread_cleanup_push(close_lookup_channel, &fd);
		result = service_lookup_over_channel(fd, name, session_fdp);
		pthread_cleanup_pop(0);
		error = errno;
		(void)close(fd);
		errno = error;
		return (result);
	}
}

/*
 * Resolve a named service to a connected session channel, whichever context
 * the caller runs in.  A switchboard-launched service carries a bootstrap
 * dispatch channel; a program run from a shell carries only the ambient
 * lookup channel.  Try the bootstrap path first (it is the richer context),
 * and fall back to the ambient channel when there is no bootstrap.  Consumer
 * libraries (libnetworkcmp, liblogcmp, ...) call this so their client_open()
 * works both when launched by switchboard and when run as a CLI.
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
	 * Bootstrap context (switchboard-launched service).  When present it is
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

