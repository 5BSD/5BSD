/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_BACKEND_IO_H_
#define	_BHYVE_VIRTIO_FS_BACKEND_IO_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"

/*
 * A value of (uid_t)-1 or (gid_t)-1 disables that credential comparison.
 * The socket must be a connected local SOCK_SEQPACKET endpoint.
 */
int	virtio_fs_backend_connect_start(const char *, uid_t, gid_t, int *,
	    bool *);
int	virtio_fs_backend_connect_finish(int, uid_t, gid_t);
int	virtio_fs_backend_authenticate(int, uid_t, gid_t);
int	virtio_fs_backend_send_frame(int,
	    const struct virtio_fs_backend_header *, const void *);
int	virtio_fs_backend_receive_frame(int,
	    struct virtio_fs_backend_header *, void *, size_t, size_t *);

#endif
