/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Small userspace wrapper for synchronous kernel capability-service ABIs.
 */

#ifndef _CAPABILITY_H_
#define	_CAPABILITY_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#define	CAPABILITY_NAME_MAX	64
#define	CAPABILITY_CALL_MAX_FDS	32

struct capability_info {
	size_t		size;
	char		name[CAPABILITY_NAME_MAX];
	uint64_t	badge;
	uint32_t	message_limit;
	uint32_t	queue_depth;
	uint32_t	transmit_limit;
	uint32_t	max_fds;
	uint32_t	features;
	uint32_t	reserved[4];
};

__BEGIN_DECLS

int	capability_get_info(int fd, struct capability_info *);

/*
 * Invoke a synchronous kernel capability service.  Request descriptors are
 * borrowed.  On entry, *reply_length and *reply_nfds are capacities; on
 * success they are exact returned counts and the caller owns reply_fds[].
 */
int	capability_kernel_call(int fd, const void *request,
	    size_t request_length, const int *request_fds,
	    size_t request_nfds, void *reply, size_t *reply_length,
	    int *reply_fds, size_t *reply_nfds);

/*
 * Connect to a named kernel capability service on a /dev/mac_capability
 * descriptor.  Returns a close-on-exec service instance fd, or -1 with errno.
 */
int	capability_service_connect(int device_fd, const char *name);

/*
 * Exact synchronous service call.  Like capability_kernel_call(), but the reply
 * must be exactly reply_length bytes and expected_reply_nfds descriptors;
 * anything else is EPROTO (and any returned fds are closed).  The _fds form
 * passes/receives descriptors; capability_service_call() is the no-fd shorthand.
 */
int	capability_service_call(int fd, const void *request,
	    size_t request_length, void *reply, size_t reply_length);
int	capability_service_call_fds(int fd, const void *request,
	    size_t request_length, const int *request_fds, size_t request_nfds,
	    void *reply, size_t reply_length, int *reply_fds,
	    size_t expected_reply_nfds);

/*
 * Freeze a held authority descriptor into this process: non-transferable,
 * close-on-fork and close-on-exec locked.  A no-op for fd < 0.  0 or -1/errno.
 */
int	capability_confine_fd(int fd);

__END_DECLS

#endif /* !_CAPABILITY_H_ */
