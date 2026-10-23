/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Private interface between channel.c, which owns the channel and message
 * layouts, and channel_call.c, which implements the synchronous call on top
 * of MAC_CAPABILITY_CHANNEL_CALL.  Not installed.
 */

#ifndef _CHANNEL_INTERNAL_H_
#define	_CHANNEL_INTERNAL_H_

#include <sys/types.h>
#include <sys/capsicum.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "channel.h"

/*
 * The length of a descriptor's ioctl allowlist, or -1 when it is unrestricted
 * or cannot be read.  cap_ioctls_get(2) reports CAP_IOCTLS_ALL (SSIZE_MAX)
 * for an unrestricted descriptor, but under a sanitizer the interposed call
 * has returned 2^32-1 instead, and a probe that trusted it allocated and
 * scanned four billion entries.  The kernel stores at most
 * IOCTLS_MAX_COUNT (256, sys/kern/sys_capability.c) commands, so any larger
 * count is implausible and treated as unrestricted.
 */
#define	CHANNEL_IOCTL_ALLOWLIST_MAX	256
static inline ssize_t
channel_ioctl_allowlist_count(int fd)
{
	ssize_t count;

	count = cap_ioctls_get(fd, NULL, 0);
	if (count < 0 || count > CHANNEL_IOCTL_ALLOWLIST_MAX)
		return (-1);
	return (count);
}

/* channel->call_version: kernel support for MAC_CAPABILITY_CHANNEL_CALL. */
#define	CHANNEL_CALL_UNKNOWN	0
#define	CHANNEL_CALL_ABSENT	1	/* or disabled: use the ordinary path */
#define	CHANNEL_CALL_PRESENT	2

/*
 * What channel_call.c needs to issue the ioctl: the kernel descriptor, the
 * registered request's token, the validated outgoing options, and a receive
 * block detached from the channel with the buffers the kernel fills.
 */
struct channel_call_fast {
	int			 fd;
	uint64_t		 token;
	const struct channel_fd_spec *specs;
	uint32_t		 flags;		/* CHANNEL_SEND_* */
	struct channel_message	*block;		/* NULL: no fast path */
	void			*data;
	size_t			 capacity;
	int			*fds;		/* MAC_CAPABILITY_MAX_FDS slots */
	struct channel_fd_info	*fd_info;	/* MAC_CAPABILITY_MAX_FDS slots */
};

/*
 * Validate the call as channel_send_request() would and register the request.
 * Returns 1 when the kernel call may be attempted (fast filled), 0 when the
 * ordinary send path must be used (request registered, no block), or -1 with
 * errno (nothing registered).
 */
int	channel_call_prepare(struct channel *, const struct channel_outgoing *,
	    channel_reply_handler, void *, struct channel_request **,
	    struct channel_call_fast *);
int	channel_call_version(const struct channel *);
void	channel_call_set_version(struct channel *, int);
/* Give an unused receive block back to the channel. */
void	channel_call_block_return(struct channel *, struct channel_message *);
/* The kernel accepted the request from the caller's memory (statistics). */
void	channel_call_sent(struct channel *);
/* Send or queue the registered request the ordinary way; aborts it on failure. */
int	channel_call_fallback(struct channel *, struct channel_request *,
	    const struct channel_outgoing *, const struct channel_fd_spec *,
	    uint32_t);
/* Nothing was sent: forget the request (terminal errors end the channel). */
void	channel_call_abort(struct channel *, struct channel_request *, int);
/*
 * Complete the request inline, as channel_dispatch() would: with the reply
 * the kernel wrote into block (error 0), or with error and no reply.  A
 * terminal error ends the channel and completes every pending request.
 */
void	channel_call_complete(struct channel *, struct channel_request *,
	    struct channel_message *,
	    const struct mac_capability_recvmsg_v4_args *, int);

#endif /* _CHANNEL_INTERNAL_H_ */
