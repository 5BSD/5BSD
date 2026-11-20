/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libservice implementation-test hooks.  This header is not installed.
 */

#ifndef _LIBSERVICE_PRIVATE_H_
#define	_LIBSERVICE_PRIVATE_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct service_context;

int	service_private_control_fd(struct service_context *);

/*
 * Channel waits shared by the ambient registration and the ambient lookup
 * (service_ambient.c).  No time limit: see service_runtime(3) on EINTR.
 */
struct mac_capability_sendmsg_args;
struct mac_capability_recvmsg_args;
__hidden int	service_channel_wait_writable(int fd);
__hidden int	service_channel_send_wait(int fd,
		    struct mac_capability_sendmsg_args *send);
__hidden int	service_channel_recv_wait(int fd,
		    struct mac_capability_recvmsg_args *recv);

#endif
