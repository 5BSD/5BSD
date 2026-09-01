/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
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
	struct mac_capability_info_args *kernel;

	if (fd < 0 || information == NULL ||
	    (information->size != 0 &&
	    information->size != sizeof(*information))) {
		errno = EINVAL;
		return (-1);
	}
	kernel = calloc(1, sizeof(*kernel));
	if (kernel == NULL)
		return (-1);
	if (ioctl(fd, MAC_CAPABILITY_GETINFO, kernel) == -1) {
		free(kernel);
		return (-1);
	}
	if (memchr(kernel->name, '\0', sizeof(kernel->name)) == NULL) {
		free(kernel);
		errno = EPROTO;
		return (-1);
	}
	memset(information, 0, sizeof(*information));
	information->size = sizeof(*information);
	strlcpy(information->name, kernel->name, sizeof(information->name));
	information->badge = kernel->badge;
	information->message_limit = kernel->msg_limit;
	information->queue_depth = kernel->queue_depth;
	information->transmit_limit = kernel->tx_limit;
	information->max_fds = kernel->max_fds;
	information->features = kernel->features;
	free(kernel);
	return (0);
}

int
capability_kernel_call(int fd, const void *request, size_t request_length,
    const int *request_fds, size_t request_nfds, void *reply,
    size_t *reply_length, int *reply_fds, size_t *reply_nfds)
{
	struct mac_capability_call_args *call;
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
	/* The ioctl writes the complete ABI object; keep it off caller stacks. */
	call = calloc(1, sizeof(*call));
	if (call == NULL)
		return (-1);
	call->req = request;
	call->req_len = (uint32_t)request_length;
	call->req_fds = request_fds;
	call->req_nfds = (uint32_t)request_nfds;
	call->reply = reply;
	call->reply_len = (uint32_t)reply_capacity;
	call->reply_fds = reply_fds;
	call->reply_nfds = (uint32_t)fd_capacity;
	if (ioctl(fd, MAC_CAPABILITY_CALL, call) == -1) {
		error = errno;
		for (i = 0; i < fd_capacity; i++) {
			if (reply_fds[i] >= 0)
				close(reply_fds[i]);
			reply_fds[i] = -1;
		}
		free(call);
		errno = error;
		return (-1);
	}
	if (call->reply_len > reply_capacity || call->reply_nfds > fd_capacity) {
		for (i = 0; i < fd_capacity; i++) {
			if (reply_fds[i] >= 0)
				close(reply_fds[i]);
			reply_fds[i] = -1;
		}
		free(call);
		errno = EPROTO;
		return (-1);
	}
	*reply_length = call->reply_len;
	*reply_nfds = call->reply_nfds;
	free(call);
	return (0);
}

int
capability_service_connect(int device_fd, const char *name)
{
	struct mac_capability_connect_args conn;
	int error, fd;

	if (device_fd < 0 || name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&conn, 0, sizeof(conn));
	if (strlcpy(conn.name, name, sizeof(conn.name)) >= sizeof(conn.name)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (ioctl(device_fd, MAC_CAPABILITY_CONNECT, &conn) == -1)
		return (-1);
	fd = conn.fd;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		return (-1);
	}
	return (fd);
}

int
capability_service_call_fds(int fd, const void *request, size_t request_length,
    const int *request_fds, size_t request_nfds, void *reply,
    size_t reply_length, int *reply_fds, size_t expected_reply_nfds)
{
	size_t actual_length, actual_nfds, i;

	actual_length = reply_length;
	actual_nfds = expected_reply_nfds;
	if (capability_kernel_call(fd, request, request_length, request_fds,
	    request_nfds, reply, &actual_length, reply_fds, &actual_nfds) == -1)
		return (-1);
	if (actual_length == reply_length && actual_nfds == expected_reply_nfds)
		return (0);
	/* Wrong shape: surrender any descriptors the service handed back. */
	for (i = 0; i < actual_nfds; i++) {
		if (reply_fds != NULL && reply_fds[i] >= 0) {
			(void)close(reply_fds[i]);
			reply_fds[i] = -1;
		}
	}
	errno = EPROTO;
	return (-1);
}

int
capability_service_call(int fd, const void *request, size_t request_length,
    void *reply, size_t reply_length)
{
	return (capability_service_call_fds(fd, request, request_length, NULL, 0,
	    reply, reply_length, NULL, 0));
}

int
capability_confine_fd(int fd)
{
	if (fd < 0)
		return (0);
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1)
		return (-1);
	return (0);
}
