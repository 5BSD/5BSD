/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "capability.h"

_Static_assert(CAPABILITY_CALL_MAX_FDS == MAC_CAPABILITY_MAX_FDS,
    "libcapability descriptor limit must match the kernel ABI");
_Static_assert(CAPABILITY_NAME_MAX == MAC_CAPABILITY_MAXNAME,
    "libcapability name limit must match the kernel ABI");

int
capability_get_info(int fd, struct capability_info *information)
{
	struct mac_capability_info_args kernel;

	if (fd < 0 || information == NULL ||
	    (information->size != 0 &&
	    information->size != sizeof(*information))) {
		errno = EINVAL;
		return (-1);
	}
	memset(&kernel, 0, sizeof(kernel));
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, &kernel) == -1)
		return (-1);
	if (memchr(kernel.name, '\0', sizeof(kernel.name)) == NULL) {
		errno = EPROTO;
		return (-1);
	}
	memset(information, 0, sizeof(*information));
	information->size = sizeof(*information);
	strlcpy(information->name, kernel.name, sizeof(information->name));
	information->badge = kernel.badge;
	information->message_limit = kernel.msg_limit;
	information->queue_depth = kernel.queue_depth;
	information->transmit_limit = kernel.tx_limit;
	information->max_fds = kernel.max_fds;
	information->features = kernel.features;
	return (0);
}

int
capability_kernel_call(int fd, const void *request, size_t request_length,
    const int *request_fds, size_t request_nfds, void *reply,
    size_t *reply_length, int *reply_fds, size_t *reply_nfds)
{
	struct mac_capability_call_args call;
	size_t fd_capacity, i, reply_capacity;
	int error;

	if (reply_length == NULL || reply_nfds == NULL) {
		errno = EINVAL;
		return (-1);
	}
	reply_capacity = *reply_length;
	fd_capacity = *reply_nfds;
	*reply_length = 0;
	*reply_nfds = 0;
	if (fd_capacity <= CAPABILITY_CALL_MAX_FDS &&
	    (fd_capacity == 0 || reply_fds != NULL)) {
		for (i = 0; i < fd_capacity; i++)
			reply_fds[i] = -1;
	}
	if (fd < 0 || request == NULL || request_length == 0 ||
	    request_length > UINT32_MAX || request_nfds > UINT32_MAX ||
	    request_nfds > CAPABILITY_CALL_MAX_FDS ||
	    (request_nfds != 0 && request_fds == NULL) ||
	    reply_capacity > UINT32_MAX ||
	    fd_capacity > CAPABILITY_CALL_MAX_FDS ||
	    (reply_capacity != 0 && reply == NULL) ||
	    (fd_capacity != 0 && reply_fds == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&call, 0, sizeof(call));
	call.req = request;
	call.req_len = (uint32_t)request_length;
	call.req_fds = request_fds;
	call.req_nfds = (uint32_t)request_nfds;
	call.reply = reply;
	call.reply_len = (uint32_t)reply_capacity;
	call.reply_fds = reply_fds;
	call.reply_nfds = (uint32_t)fd_capacity;
	if (ioctl(fd, MAC_CAPABILITY_CALL, &call) == -1) {
		error = errno;
		for (i = 0; i < fd_capacity; i++) {
			if (reply_fds[i] >= 0)
				close(reply_fds[i]);
			reply_fds[i] = -1;
		}
		errno = error;
		return (-1);
	}
	if (call.reply_len > reply_capacity || call.reply_nfds > fd_capacity) {
		for (i = 0; i < fd_capacity; i++) {
			if (reply_fds[i] >= 0)
				close(reply_fds[i]);
			reply_fds[i] = -1;
		}
		errno = EPROTO;
		return (-1);
	}
	*reply_length = call.reply_len;
	*reply_nfds = call.reply_nfds;
	return (0);
}
