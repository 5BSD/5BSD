/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Synchronous request/reply over a capability channel.
 *
 * A request issued with channel_send_request() and awaited with
 * channel_wait() and channel_dispatch() costs a send, a wait and a receive
 * system call, plus the clock reads that bound the wait.  Kernels with
 * MAC_CAPABILITY_CHANNEL_CALL do all of it in one call: the request is sent
 * and the calling thread sleeps until the message carrying its token
 * arrives, which the kernel hands to it directly while events and other
 * replies stay queued for channel_dispatch().  Everything the send path
 * checks (descriptor expectations, transfer authority, queue limits) is
 * checked exactly as for channel_send_request(); the two are the same request
 * seen from the kernel.
 *
 * Fallback.  Kernels without the ioctl (ENOTTY, or a descriptor whose ioctl
 * allowlist omits it, or a kernel whose GETINFO lacks
 * MAC_CAPABILITY_INFO_F_CHANNEL_CALL), channels with output queued behind
 * backpressure, and a kernel that refuses the request with EAGAIN all take
 * the ordinary path: the request is sent or queued and completes from
 * channel_dispatch(); channel_call() then runs that loop itself.  The
 * environment variable LIBCHANNEL_NO_CHANNEL_CALL (ignored for set-id
 * programs) forces the fallback for comparison.  Both paths have identical
 * semantics: a late reply to a timed-out call is discarded (by the kernel,
 * or by channel_dispatch() as a stale reply) with its descriptors closed.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "channel.h"
#include "channel_internal.h"

/*
 * Decide once per channel whether the kernel call is usable.  A descriptor
 * limited by cap_ioctls_limit(2) fails the command with ENOTCAPABLE, which a
 * call could not tell from a descriptor expectation failure, so the
 * allowlist is read here; the GETINFO feature bit covers kernels that
 * predate the command without ever issuing it.
 */
static int
channel_call_probe(struct channel *channel, int fd)
{
	struct mac_capability_info_args info;
	cap_ioctl_t *cmds;
	ssize_t count, i;
	int version;
	bool listed;

	version = channel_call_version(channel);
	if (version != CHANNEL_CALL_UNKNOWN)
		return (version);
	version = CHANNEL_CALL_PRESENT;
	if (issetugid() == 0 && getenv("LIBCHANNEL_NO_CHANNEL_CALL") != NULL)
		version = CHANNEL_CALL_ABSENT;
	count = version == CHANNEL_CALL_PRESENT ?
	    channel_ioctl_allowlist_count(fd) : -1;
	if (count >= 0) {
		listed = false;
		cmds = count > 0 ? calloc((size_t)count, sizeof(*cmds)) : NULL;
		if (cmds != NULL &&
		    cap_ioctls_get(fd, cmds, (size_t)count) == count)
			for (i = 0; i < count; i++)
				if (cmds[i] == MAC_CAPABILITY_CHANNEL_CALL)
					listed = true;
		free(cmds);
		if (!listed)
			version = CHANNEL_CALL_ABSENT;
	}
	if (version == CHANNEL_CALL_PRESENT) {
		memset(&info, 0, sizeof(info));
		if (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) != 0 ||
		    (info.features & MAC_CAPABILITY_INFO_F_CHANNEL_CALL) == 0)
			version = CHANNEL_CALL_ABSENT;
	}
	channel_call_set_version(channel, version);
	return (version);
}

int
channel_call_request(struct channel *channel,
    const struct channel_outgoing *outgoing, channel_reply_handler handler,
    void *context, struct channel_request **requestp, int timeout_ms)
{
	struct mac_capability_channel_call_args args;
	struct channel_call_fast fast;
	struct channel_request *request;
	int error, path;

	if (requestp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*requestp = NULL;
	path = channel_call_prepare(channel, outgoing, handler, context,
	    &request, &fast);
	if (path == -1)
		return (-1);
	if (path == 1 &&
	    channel_call_probe(channel, fast.fd) != CHANNEL_CALL_PRESENT) {
		channel_call_block_return(channel, fast.block);
		path = 0;
	}
	if (path == 1) {
		memset(&args, 0, sizeof(args));
		args.request.message.payload = outgoing->data;
		args.request.message.payload_len = (uint32_t)outgoing->length;
		args.request.message.fds = outgoing->fds;
		args.request.message.nfds = (uint32_t)outgoing->nfds;
		args.request.message.reply_token = fast.token;
		if (fast.flags & CHANNEL_SEND_MOVE)
			args.request.message.flags |= MAC_CAPABILITY_SEND_F_MOVE;
		if (fast.flags & CHANNEL_SEND_LOCK_INHERIT)
			args.request.message.flags |=
			    MAC_CAPABILITY_SEND_F_LOCK_INHERIT;
		args.request.fd_specs =
		    (const struct mac_capability_fd_spec *)fast.specs;
		args.reply.v3.message.payload = fast.data;
		args.reply.v3.message.payload_len = (uint32_t)fast.capacity;
		args.reply.v3.message.fds = fast.fds;
		args.reply.v3.message.nfds = MAC_CAPABILITY_MAX_FDS;
		args.reply.fd_info =
		    (struct mac_capability_fd_info *)fast.fd_info;
		args.timeout_ms = timeout_ms < 0 ?
		    MAC_CAPABILITY_RECV_WAIT_FOREVER : (uint32_t)timeout_ms;
		/*
		 * The handler may run before this returns and may release
		 * the handle, so the caller sees the same pointer it does.
		 */
		*requestp = request;
		if (ioctl(fast.fd, MAC_CAPABILITY_CHANNEL_CALL, &args) == 0) {
			channel_call_sent(channel);
			channel_call_complete(channel, request, fast.block,
			    &args.reply, 0);
			return (0);
		}
		error = errno;
		switch (error) {
		case ENOTTY:
			/* Not this kernel: decided once, nothing was sent. */
			channel_call_set_version(channel, CHANNEL_CALL_ABSENT);
			/* FALLTHROUGH */
		case EAGAIN:
			/* The peer is full; the ordinary path queues it. */
			channel_call_block_return(channel, fast.block);
			path = 0;
			break;
		case ETIMEDOUT:
			/* Sent; the kernel discards the late reply. */
			channel_call_sent(channel);
			channel_call_complete(channel, request, fast.block,
			    NULL, ETIMEDOUT);
			return (0);
		case EINTR:
		case EMSGSIZE:
			/*
			 * Sent, and the reply (still to come, or already at
			 * the head of the receive queue because it did not
			 * fit) completes the request from channel_dispatch().
			 */
			channel_call_sent(channel);
			channel_call_block_return(channel, fast.block);
			return (0);
		case ECONNRESET:
			/* Sent; the peer died before replying. */
			channel_call_sent(channel);
			channel_call_complete(channel, request, fast.block,
			    NULL, ECONNRESET);
			return (0);
		default:
			/* Refused before anything was sent. */
			channel_call_block_return(channel, fast.block);
			channel_call_abort(channel, request, error);
			*requestp = NULL;
			errno = error;
			return (-1);
		}
	}
	if (channel_call_fallback(channel, request, outgoing, fast.specs,
	    fast.flags) == -1) {
		*requestp = NULL;
		return (-1);
	}
	*requestp = request;
	return (0);
}

struct channel_call_state {
	struct channel_message	*reply;
	int			 error;
	bool			 done;
};

static void
channel_call_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *context)
{
	struct channel_call_state *state;

	state = context;
	state->done = true;
	state->error = error;
	state->reply = reply;
	channel_request_release(request);
}

int
channel_call(struct channel *channel, const struct channel_outgoing *outgoing,
    struct channel_message **replyp, int timeout_ms)
{
	struct channel_call_state state;
	struct channel_request *request;
	struct timespec deadline, now;
	int64_t left;
	int remaining, ready;
	bool cancelled;

	if (replyp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*replyp = NULL;
	memset(&state, 0, sizeof(state));
	if (timeout_ms >= 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
			return (-1);
		deadline.tv_sec += timeout_ms / 1000;
		deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000L;
		}
	}
	if (channel_call_request(channel, outgoing, channel_call_handler,
	    &state, &request, timeout_ms) == -1)
		return (-1);
	/*
	 * Not completed by the kernel: the ordinary loop, with one deadline
	 * for the whole call.  A timeout cancels the request, so the late
	 * reply is discarded as stale; nothing else is cancelled.
	 */
	cancelled = false;
	while (!state.done) {
		remaining = -1;
		if (timeout_ms >= 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
				state.error = errno;
				(void)channel_request_cancel(request);
				break;
			}
			left = (deadline.tv_sec - now.tv_sec) * INT64_C(1000) +
			    (deadline.tv_nsec - now.tv_nsec) / 1000000;
			if (left <= 0) {
				cancelled = true;
				(void)channel_request_cancel(request);
				break;
			}
			remaining = left > INT_MAX ? INT_MAX : (int)left;
		}
		ready = channel_wait(channel, channel_wants_write(channel),
		    remaining);
		if (ready == -1 && errno == EINTR)
			continue;
		if (ready == -1 && !state.done) {
			/* The channel is unusable; dispatch reports why. */
			if (channel_dispatch(channel) >= 0 && !state.done) {
				state.error = EIO;
				(void)channel_request_cancel(request);
			}
			break;
		}
		if (state.done)
			break;
		if (channel_dispatch(channel) == -1 && !state.done) {
			state.error = errno;
			(void)channel_request_cancel(request);
			break;
		}
		if (!state.done && channel_wants_write(channel))
			(void)channel_flush(channel);
	}
	if (cancelled)
		state.error = ETIMEDOUT;
	if (state.error != 0) {
		if (state.reply != NULL)
			channel_message_free(state.reply);
		errno = state.error;
		return (-1);
	}
	*replyp = state.reply;
	return (0);
}
