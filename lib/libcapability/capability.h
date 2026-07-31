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

__END_DECLS

#endif /* !_CAPABILITY_H_ */
