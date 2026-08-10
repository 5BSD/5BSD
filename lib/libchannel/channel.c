/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "channel.h"
#include "channel_probes.h"

#define	CHANNEL_DISPATCH_BATCH	64

struct channel_request {
	struct channel_request	*next;
	struct channel		*channel;
	channel_reply_handler	 handler;
	void			*context;
	uint64_t		 token;
	int			 status;
	bool			 pending;
	bool			 callback_active;
	bool			 free_pending;
};

struct channel_queue_entry {
	struct channel_queue_entry *next;
	struct channel_request	*request;
	void			*data;
	size_t			 length;
	int			*fds;
	size_t			 nfds;
	uint64_t		 token;
};

struct channel {
	int			 fd;
	int			 kqueue_fd;	/* lazy kqueue for channel_wait */
	pid_t			 owner;
	int			 error;
	enum channel_role	 role;
	size_t			 max_pending_requests;
	size_t			 max_queued_messages;
	size_t			 max_queued_bytes;
	size_t			 max_queued_fds;
	size_t			 npending;
	size_t			 nqueued;
	size_t			 queued_bytes;
	size_t			 queued_fds;
	struct channel_request	*requests;
	struct channel_queue_entry *out_head;
	struct channel_queue_entry *out_tail;
	channel_request_handler	 request_handler;
	void			*request_context;
	channel_event_handler	 event_handler;
	void			*event_context;
	unsigned		 dispatch_depth;
	bool			 destroy_pending;
	bool			 owner_released;
	unsigned		 references;
};

struct channel_message {
	struct channel		*channel;
	pid_t			 owner;
	enum channel_message_kind kind;
	struct channel_sender	 sender;
	void			*data;
	size_t			 length;
	int			*fds;
	size_t			 nfds;
	uint64_t		 token;
	bool			 responded;
};

static void
channel_retain(struct channel *channel)
{

	channel->references++;
}

static void
channel_release(struct channel *channel)
{

	if (--channel->references == 0)
		free(channel);
}

static bool
channel_owned(const struct channel *channel)
{

	if (channel == NULL) {
		errno = EINVAL;
		return (false);
	}
	if (channel->owner != getpid()) {
		errno = ECHILD;
		return (false);
	}
	return (true);
}

static bool
channel_terminal_error(int error)
{

	return (error == EBADF || error == ECONNRESET || error == ENOTCONN ||
	    error == ENXIO || error == EPIPE);
}

static void
channel_outgoing_free(struct channel_queue_entry *out)
{
	int error;
	size_t i;

	if (out == NULL)
		return;
	error = errno;
	for (i = 0; i < out->nfds; i++)
		if (out->fds[i] >= 0)
			(void)close(out->fds[i]);
	free(out->fds);
	free(out->data);
	free(out);
	errno = error;
}

static struct channel_request *
channel_request_find(struct channel *channel, uint64_t token,
    struct channel_request ***linkp)
{
	struct channel_request **link;

	for (link = &channel->requests; *link != NULL;
	    link = &(*link)->next) {
		if ((*link)->token == token) {
			if (linkp != NULL)
				*linkp = link;
			return (*link);
		}
	}
	return (NULL);
}

static uint64_t
channel_new_token(struct channel *channel)
{
	uint64_t token;

	do {
		arc4random_buf(&token, sizeof(token));
	} while (token == 0 || channel_request_find(channel, token, NULL) !=
	    NULL);
	return (token);
}

static void
channel_request_complete(struct channel_request *request,
    struct channel_message *message, int error)
{
	channel_reply_handler handler;
	void *context;

	request->pending = false;
	request->status = error;
	handler = request->handler;
	context = request->context;
	request->callback_active = true;
	LIBCHANNEL_PROBE_COMPLETE(request->token, error);
	if (handler != NULL)
		handler(request, message, error, context);
	request->callback_active = false;
	if (request->free_pending)
		free(request);
}

static void
channel_fail_requests(struct channel *channel, int error)
{
	struct channel_request *request;

	while ((request = channel->requests) != NULL) {
		channel->requests = request->next;
		request->next = NULL;
		channel->npending--;
		channel_request_complete(request, NULL, error);
	}
}

static void
channel_mark_dead(struct channel *channel, int error)
{
	struct channel_queue_entry *out;

	if (channel->error != 0)
		return;
	channel->error = error != 0 ? error : ECONNRESET;
	LIBCHANNEL_PROBE_PEER_DEATH(channel->error, channel->npending);
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		channel_outgoing_free(out);
	}
	channel->out_tail = NULL;
	channel->nqueued = channel->queued_bytes = channel->queued_fds = 0;
	/*
	 * Completion callbacks may request channel destruction.  Keep the
	 * object alive until the public operation which detected death unwinds.
	 */
	channel->dispatch_depth++;
	channel_fail_requests(channel, channel->error);
	channel->dispatch_depth--;
}

static int
channel_send_now(struct channel *channel, const void *data, size_t length,
    const int *fds, size_t nfds, uint64_t token)
{
	struct mac_capability_sendmsg_args send;

	memset(&send, 0, sizeof(send));
	send.payload = data;
	send.payload_len = (uint32_t)length;
	send.fds = fds;
	send.nfds = (uint32_t)nfds;
	send.reply_token = token;
	if (ioctl(channel->fd, MAC_CAPABILITY_SENDMSG, &send) == 0) {
		LIBCHANNEL_PROBE_SEND(token, length, nfds, 0);
		return (0);
	}
	LIBCHANNEL_PROBE_SEND(token, length, nfds, errno);
	return (-1);
}

static int
channel_queue(struct channel *channel, const void *data, size_t length,
    const int *fds, size_t nfds, uint64_t token,
    struct channel_request *request)
{
	struct channel_queue_entry *out;
	size_t i;

	if (channel->nqueued >= channel->max_queued_messages ||
	    length > channel->max_queued_bytes - channel->queued_bytes ||
	    nfds > channel->max_queued_fds - channel->queued_fds) {
		errno = ENOBUFS;
		return (-1);
	}
	out = calloc(1, sizeof(*out));
	if (out == NULL)
		return (-1);
	out->data = malloc(length);
	if (out->data == NULL)
		goto fail;
	memcpy(out->data, data, length);
	out->length = length;
	out->token = token;
	out->request = request;
	if (nfds != 0) {
		out->fds = malloc(nfds * sizeof(*out->fds));
		if (out->fds == NULL)
			goto fail;
		for (i = 0; i < nfds; i++)
			out->fds[i] = -1;
		for (i = 0; i < nfds; i++) {
			out->fds[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 0);
			if (out->fds[i] == -1)
				goto fail;
			out->nfds++;
			if (cap_clofork_limit(out->fds[i],
			    CAP_CLOFORK_LOCKED) == -1 ||
			    cap_cloexec_limit(out->fds[i],
			    CAP_CLOEXEC_LOCKED) == -1)
				goto fail;
		}
	}
	if (channel->out_tail == NULL)
		channel->out_head = out;
	else
		channel->out_tail->next = out;
	channel->out_tail = out;
	channel->nqueued++;
	channel->queued_bytes += length;
	channel->queued_fds += nfds;
	LIBCHANNEL_PROBE_QUEUE(token, length, nfds, channel->nqueued);
	return (0);
fail:
	channel_outgoing_free(out);
	return (-1);
}

static int
channel_send_or_queue(struct channel *channel, const void *data,
    size_t length, const int *fds, size_t nfds, uint64_t token,
    struct channel_request *request)
{

	if (channel->error != 0) {
		errno = channel->error;
		return (-1);
	}
	if (channel->out_head == NULL &&
	    channel_send_now(channel, data, length, fds, nfds, token) == 0)
		return (0);
	if (channel->error != 0)
		return (-1);
	if (errno != EAGAIN && errno != EWOULDBLOCK)
		return (-1);
	return (channel_queue(channel, data, length, fds, nfds, token,
	    request));
}

int
channel_create(int fd, const struct channel_options *options,
    struct channel **channelp)
{
	struct mac_capability_info_args info;
	struct channel *channel;
	int flags, owned;

	if (fd < 0 || options == NULL || channelp == NULL ||
	    options->size < sizeof(*options) ||
	    (options->role != CHANNEL_ROLE_CLIENT &&
	    options->role != CHANNEL_ROLE_PROVIDER) ||
	    options->max_pending_requests == 0 ||
	    options->max_queued_messages == 0 ||
	    options->max_queued_bytes == 0) {
		errno = EINVAL;
		return (-1);
	}
	*channelp = NULL;
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1)
		return (-1);
	if ((info.features & (MAC_CAPABILITY_INFO_F_SENDMSG |
	    MAC_CAPABILITY_INFO_F_RECVMSG | MAC_CAPABILITY_INFO_F_KQUEUE)) !=
	    (MAC_CAPABILITY_INFO_F_SENDMSG | MAC_CAPABILITY_INFO_F_RECVMSG |
	    MAC_CAPABILITY_INFO_F_KQUEUE)) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	channel = calloc(1, sizeof(*channel));
	if (channel == NULL)
		return (-1);
	/*
	 * Configure a private duplicate so any failure leaves the caller's
	 * descriptor untouched, as required by the ownership contract.
	 */
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned == -1) {
		free(channel);
		return (-1);
	}
	if (cap_clofork_limit(owned, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(owned, CAP_CLOEXEC_LOCKED) == -1) {
		(void)close(owned);
		free(channel);
		return (-1);
	}
	flags = fcntl(owned, F_GETFL);
	if (flags == -1 ||
	    fcntl(owned, F_SETFL, flags | O_NONBLOCK) == -1) {
		(void)close(owned);
		free(channel);
		return (-1);
	}
	(void)close(fd);
	channel->fd = owned;
	channel->kqueue_fd = -1;
	channel->owner = getpid();
	channel->role = options->role;
	channel->max_pending_requests = options->max_pending_requests;
	channel->max_queued_messages = options->max_queued_messages;
	channel->max_queued_bytes = options->max_queued_bytes;
	channel->max_queued_fds = options->max_queued_fds;
	channel->references = 1;
	*channelp = channel;
	LIBCHANNEL_PROBE_CREATE(owned, options->role, 0);
	return (0);
}

static void
channel_destroy_now(struct channel *channel)
{
	struct channel_queue_entry *out;

	channel_mark_dead(channel, ECANCELED);
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		channel_outgoing_free(out);
	}
	if (channel->fd >= 0)
		(void)close(channel->fd);
	channel->fd = -1;
	if (channel->kqueue_fd >= 0)
		(void)close(channel->kqueue_fd);
	channel->kqueue_fd = -1;
	/*
	 * A callback-owned message still references the channel.  When abandon
	 * is used during dispatch, defer the owner's release until dispatch
	 * unwinds so freeing that message cannot invalidate the active stack.
	 */
	if (channel->dispatch_depth == 0 && !channel->owner_released) {
		channel->owner_released = true;
		channel_release(channel);
	}
}

void
channel_destroy(struct channel *channel)
{

	if (channel == NULL)
		return;
	if (channel->owner != getpid()) {
		channel_abandon(channel);
		return;
	}
	if (channel->dispatch_depth != 0) {
		channel->destroy_pending = true;
		channel_mark_dead(channel, ECANCELED);
		return;
	}
	channel_destroy_now(channel);
}

void
channel_abandon(struct channel *channel)
{
	struct channel_queue_entry *out;
	struct channel_request *request;
	bool inherited;

	if (channel == NULL)
		return;
	inherited = channel->owner != getpid();
	while ((out = channel->out_head) != NULL) {
		channel->out_head = out->next;
		if (inherited) {
			free(out->fds);
			free(out->data);
			free(out);
		} else
			channel_outgoing_free(out);
	}
	channel->out_tail = NULL;
	while ((request = channel->requests) != NULL) {
		channel->requests = request->next;
		free(request);
	}
	channel->npending = channel->nqueued = 0;
	channel->queued_bytes = channel->queued_fds = 0;
	channel->error = ECANCELED;
	channel->destroy_pending = true;
	if (channel->fd >= 0 && !inherited)
		(void)close(channel->fd);
	channel->fd = -1;
	/* The kqueue is process-local and never inherited; always close it. */
	if (channel->kqueue_fd >= 0)
		(void)close(channel->kqueue_fd);
	channel->kqueue_fd = -1;
	if (!channel->owner_released) {
		channel->owner_released = true;
		channel_release(channel);
	}
}

int
channel_fd(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	return (channel->fd);
}

/*
 * Wait for the channel to become ready via kqueue.  Capability channels are
 * kqueue-only (poll(2)/select(2) are unsupported by the kernel), so this is
 * the sole readiness primitive.  A lazily-created kqueue is cached on the
 * channel with a persistent EVFILT_READ registration; EVFILT_WRITE is toggled
 * per call to match want_write.  timeout_ms < 0 blocks indefinitely, 0 polls
 * once.  Returns a CHANNEL_WAIT_READ|CHANNEL_WAIT_WRITE bitmask of ready
 * filters (0 on timeout), or -1 with errno set on error.  A dead/EOF channel
 * reports CHANNEL_WAIT_READ ready so the caller's dispatch observes the error.
 */
int
channel_wait(struct channel *channel, int want_write, int timeout_ms)
{
	struct kevent chg, out[2];
	struct timespec ts, *tsp;
	int n, i, ready;

	if (!channel_owned(channel) || channel->destroy_pending ||
	    channel->fd < 0) {
		errno = EBADF;
		return (-1);
	}
	if (channel->kqueue_fd < 0) {
		channel->kqueue_fd = kqueue();
		if (channel->kqueue_fd < 0)
			return (-1);
		(void)cap_cloexec_limit(channel->kqueue_fd, CAP_CLOEXEC_LOCKED);
		EV_SET(&chg, channel->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(channel->kqueue_fd, &chg, 1, NULL, 0, NULL) == -1) {
			(void)close(channel->kqueue_fd);
			channel->kqueue_fd = -1;
			return (-1);
		}
	}
	/*
	 * Match the write filter to want_write.  EV_DELETE of an absent filter
	 * returns ENOENT and EV_ADD on a recv-only channel may return
	 * EOPNOTSUPP; both are benign here, so the change result is ignored.
	 */
	EV_SET(&chg, channel->fd, EVFILT_WRITE,
	    want_write ? EV_ADD : EV_DELETE, 0, 0, NULL);
	(void)kevent(channel->kqueue_fd, &chg, 1, NULL, 0, NULL);

	if (timeout_ms < 0) {
		tsp = NULL;
	} else {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
		tsp = &ts;
	}
	do {
		n = kevent(channel->kqueue_fd, NULL, 0, out, 2, tsp);
	} while (n == -1 && errno == EINTR);
	if (n == -1)
		return (-1);
	ready = 0;
	for (i = 0; i < n; i++) {
		if (out[i].filter == EVFILT_READ)
			ready |= CHANNEL_WAIT_READ;
		else if (out[i].filter == EVFILT_WRITE)
			ready |= CHANNEL_WAIT_WRITE;
	}
	return (ready);
}

int
channel_error(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->error != 0) {
		errno = channel->error;
		return (-1);
	}
	return (0);
}

int
channel_wants_write(const struct channel *channel)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	return (channel->out_head != NULL);
}

int
channel_send_request(struct channel *channel,
    const struct channel_outgoing *outgoing, channel_reply_handler handler,
    void *context, struct channel_request **requestp)
{
	struct channel_request *request;
	struct channel_request **link;
	const void *data;
	const int *fds;
	size_t length, nfds;
	int error;

	if (outgoing == NULL || outgoing->size < sizeof(*outgoing)) {
		errno = EINVAL;
		return (-1);
	}
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (!channel_owned(channel))
		return (-1);
	if (data == NULL || length == 0 ||
	    length > MAC_CAPABILITY_MAX_MSG || nfds > MAC_CAPABILITY_MAX_FDS ||
	    (nfds != 0 && fds == NULL) || handler == NULL ||
	    requestp == NULL || channel->destroy_pending ||
	    channel->role != CHANNEL_ROLE_CLIENT) {
		errno = EINVAL;
		return (-1);
	}
	*requestp = NULL;
	if (channel->npending >= channel->max_pending_requests) {
		errno = ENOBUFS;
		return (-1);
	}
	request = calloc(1, sizeof(*request));
	if (request == NULL)
		return (-1);
	request->channel = channel;
	request->handler = handler;
	request->context = context;
	request->token = channel_new_token(channel);
	request->status = EINPROGRESS;
	request->pending = true;
	request->next = channel->requests;
	channel->requests = request;
	channel->npending++;
	if (channel_send_or_queue(channel, data, length, fds, nfds,
	    request->token, request) == -1) {
		error = errno;
		for (link = &channel->requests; *link != NULL;
		    link = &(*link)->next)
			if (*link == request) {
				*link = request->next;
				break;
			}
		channel->npending--;
		free(request);
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	*requestp = request;
	return (0);
}

int
channel_send_event(struct channel *channel,
    const struct channel_outgoing *outgoing)
{
	const void *data;
	const int *fds;
	size_t length, nfds;

	if (outgoing == NULL || outgoing->size < sizeof(*outgoing)) {
		errno = EINVAL;
		return (-1);
	}
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (!channel_owned(channel))
		return (-1);
	if (data == NULL || length == 0 ||
	    length > MAC_CAPABILITY_MAX_MSG || nfds > MAC_CAPABILITY_MAX_FDS ||
	    (nfds != 0 && fds == NULL) || channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	if (channel_send_or_queue(channel, data, length, fds, nfds, 0,
	    NULL) == -1) {
		int error;

		error = errno;
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	return (0);
}

int
channel_set_request_handler(struct channel *channel,
    channel_request_handler handler, void *context)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending || channel->role == CHANNEL_ROLE_CLIENT) {
		errno = EINVAL;
		return (-1);
	}
	channel->request_handler = handler;
	channel->request_context = context;
	return (0);
}

int
channel_set_event_handler(struct channel *channel,
    channel_event_handler handler, void *context)
{

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	channel->event_handler = handler;
	channel->event_context = context;
	return (0);
}

int
channel_flush(struct channel *channel)
{
	struct channel_queue_entry *out;
	int error;

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	while ((out = channel->out_head) != NULL) {
		if (channel_send_now(channel, out->data, out->length, out->fds,
		    out->nfds, out->token) == -1) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK)
				return (0);
			if (channel_terminal_error(error))
				channel_mark_dead(channel, error);
			if (channel->destroy_pending &&
			    channel->dispatch_depth == 0)
				channel_destroy_now(channel);
			errno = error;
			return (-1);
		}
		channel->out_head = out->next;
		if (channel->out_head == NULL)
			channel->out_tail = NULL;
		channel->nqueued--;
		channel->queued_bytes -= out->length;
		channel->queued_fds -= out->nfds;
		channel_outgoing_free(out);
	}
	return (0);
}

static struct channel_message *
channel_message_receive(struct channel *channel)
{
	struct mac_capability_recvmsg_args receive;
	struct channel_message *message;
	void *data;
	int error;
	int *fds;
	size_t i;

	data = malloc(MAC_CAPABILITY_MAX_MSG);
	fds = malloc(MAC_CAPABILITY_MAX_FDS * sizeof(*fds));
	message = calloc(1, sizeof(*message));
	if (data == NULL || fds == NULL || message == NULL)
		goto fail;
	for (i = 0; i < MAC_CAPABILITY_MAX_FDS; i++)
		fds[i] = -1;
	memset(&receive, 0, sizeof(receive));
	receive.payload = data;
	receive.payload_len = MAC_CAPABILITY_MAX_MSG;
	receive.fds = fds;
	receive.nfds = MAC_CAPABILITY_MAX_FDS;
	if (ioctl(channel->fd, MAC_CAPABILITY_RECVMSG, &receive) == -1)
		goto fail;
	message->channel = channel;
	message->owner = getpid();
	channel_retain(channel);
	message->data = data;
	message->length = receive.payload_len;
	message->fds = fds;
	message->nfds = receive.nfds;
	message->token = receive.reply_token;
	message->sender.badge = receive.badge;
	message->sender.uid = receive.trailer.uid;
	message->sender.gid = receive.trailer.gid;
	message->sender.prison_id = receive.trailer.prison_id;
	message->sender.nonce = receive.trailer.nonce;
	return (message);
fail:
	error = errno;
	for (i = 0; fds != NULL && i < MAC_CAPABILITY_MAX_FDS; i++)
		if (fds[i] >= 0)
			(void)close(fds[i]);
	free(message);
	free(fds);
	free(data);
	errno = error;
	return (NULL);
}

int
channel_dispatch(struct channel *channel)
{
	struct channel_message *message;
	struct channel_request *request, **link;
	int error, dispatched;

	if (!channel_owned(channel))
		return (-1);
	if (channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	channel->dispatch_depth++;
	error = 0;
	dispatched = 0;
	while (dispatched < CHANNEL_DISPATCH_BATCH) {
		message = channel_message_receive(channel);
		if (message == NULL) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK) {
				error = 0;
				break;
			}
			if (channel_terminal_error(error))
				channel_mark_dead(channel, error);
			break;
		}
		dispatched++;
		if (message->token == 0) {
			message->kind = CHANNEL_MESSAGE_EVENT;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			if (channel->event_handler != NULL) {
				channel->event_handler(channel, message,
				    channel->event_context);
				message = NULL;
			} else
				LIBCHANNEL_PROBE_DISCARD(message->token,
				    message->nfds, 1);
		} else if ((request = channel_request_find(channel,
		    message->token, &link)) != NULL) {
			message->kind = CHANNEL_MESSAGE_REPLY;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			*link = request->next;
			request->next = NULL;
			channel->npending--;
			channel_request_complete(request, message, 0);
			message = NULL;
		} else if (channel->role == CHANNEL_ROLE_PROVIDER) {
			message->kind = CHANNEL_MESSAGE_REQUEST;
			LIBCHANNEL_PROBE_RECEIVE(message->kind, message->token,
			    message->length, message->nfds);
			if (channel->request_handler != NULL) {
				channel->request_handler(channel, message,
				    channel->request_context);
				message = NULL;
			} else
				LIBCHANNEL_PROBE_DISCARD(message->token,
				    message->nfds, 2);
		} else
			LIBCHANNEL_PROBE_DISCARD(message->token, message->nfds,
			    3);
		if (message != NULL)
			channel_message_free(message);
		if (channel->destroy_pending)
			break;
	}
	channel->dispatch_depth--;
	if (channel->destroy_pending && channel->dispatch_depth == 0) {
		channel_destroy_now(channel);
		if (error != 0)
			errno = error;
		return (error == 0 ? dispatched : -1);
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (dispatched);
}

int
channel_send_reply(struct channel_message *request,
    const struct channel_outgoing *outgoing)
{
	struct channel *channel;
	const void *data;
	const int *fds;
	size_t length, nfds;

	if (request == NULL || request->channel == NULL ||
	    request->kind != CHANNEL_MESSAGE_REQUEST || request->token == 0 ||
	    request->responded || request->channel->destroy_pending) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (outgoing == NULL || outgoing->size < sizeof(*outgoing)) {
		errno = EINVAL;
		return (-1);
	}
	data = outgoing->data;
	length = outgoing->length;
	fds = outgoing->fds;
	nfds = outgoing->nfds;
	if (data == NULL || length == 0 || length > MAC_CAPABILITY_MAX_MSG ||
	    nfds > MAC_CAPABILITY_MAX_FDS || (nfds != 0 && fds == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	channel = request->channel;
	if (channel_send_or_queue(channel, data, length, fds, nfds,
	    request->token, NULL) == -1) {
		int error;

		error = errno;
		if (channel_terminal_error(error))
			channel_mark_dead(channel, error);
		if (channel->destroy_pending && channel->dispatch_depth == 0)
			channel_destroy_now(channel);
		errno = error;
		return (-1);
	}
	request->responded = true;
	return (0);
}

enum channel_message_kind
channel_message_kind(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->kind);
}

const void *
channel_message_data(const struct channel_message *message)
{

	return (message == NULL ? NULL : message->data);
}

size_t
channel_message_length(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->length);
}

uint64_t
channel_message_token(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->token);
}

const struct channel_sender *
channel_message_sender(const struct channel_message *message)
{

	return (message == NULL ? NULL : &message->sender);
}

size_t
channel_message_fd_count(const struct channel_message *message)
{

	return (message == NULL ? 0 : message->nfds);
}

int
channel_message_borrow_fd(const struct channel_message *message, size_t slot)
{

	if (message == NULL || slot >= message->nfds ||
	    message->fds[slot] < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (message->owner != getpid()) {
		errno = ECHILD;
		return (-1);
	}
	return (message->fds[slot]);
}

int
channel_message_take_fd(struct channel_message *message, size_t slot)
{
	int fd;

	if (message == NULL || slot >= message->nfds ||
	    message->fds[slot] < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (message->owner != getpid()) {
		errno = ECHILD;
		return (-1);
	}
	fd = message->fds[slot];
	message->fds[slot] = -1;
	return (fd);
}

void
channel_message_free(struct channel_message *message)
{
	struct channel *channel;
	size_t i;

	if (message == NULL)
		return;
	channel = message->channel;
	if (message->owner == getpid()) {
		for (i = 0; i < message->nfds; i++)
			if (message->fds[i] >= 0)
				(void)close(message->fds[i]);
	}
	free(message->fds);
	free(message->data);
	free(message);
	channel_release(channel);
}

int
channel_request_cancel(struct channel_request *request)
{
	struct channel *channel;
	struct channel_queue_entry **out_link, *out, *out_previous;
	struct channel_request **link;

	if (request == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (!request->pending || request->channel == NULL) {
		errno = EALREADY;
		return (-1);
	}
	channel = request->channel;
	out_previous = NULL;
	for (out_link = &channel->out_head; (out = *out_link) != NULL;
	    out_previous = out, out_link = &out->next) {
		if (out->request != request)
			continue;
		*out_link = out->next;
		if (channel->out_tail == out)
			channel->out_tail = out_previous;
		channel->nqueued--;
		channel->queued_bytes -= out->length;
		channel->queued_fds -= out->nfds;
		channel_outgoing_free(out);
		break;
	}
	for (link = &channel->requests; *link != NULL;
	    link = &(*link)->next)
		if (*link == request) {
			*link = request->next;
			request->next = NULL;
			channel->npending--;
			break;
		}
	channel_request_complete(request, NULL, ECANCELED);
	return (0);
}

int
channel_request_status(const struct channel_request *request)
{

	if (request == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (!channel_owned(request->channel))
		return (-1);
	if (request->pending)
		return (EINPROGRESS);
	return (request->status);
}

void
channel_request_release(struct channel_request *request)
{

	if (request == NULL)
		return;
	if (request->channel != NULL &&
	    request->channel->owner != getpid())
		return;
	if (request->pending) {
		request->free_pending = true;
		return;
	}
	if (request->callback_active) {
		request->free_pending = true;
		return;
	}
	free(request);
}
