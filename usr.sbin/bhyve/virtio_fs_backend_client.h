/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_BACKEND_CLIENT_H_
#define	_BHYVE_VIRTIO_FS_BACKEND_CLIENT_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#include "virtio_fs_backend.h"

#define	VIRTIO_FS_BACKEND_CLIENT_READ	(UINT32_C(1) << 0)
#define	VIRTIO_FS_BACKEND_CLIENT_WRITE	(UINT32_C(1) << 1)

struct virtio_fs_backend_client;

/*
 * The caller serializes these operations from its event loop.  The client
 * owns its descriptor until take_active() succeeds or the client is
 * destroyed.  connect() owns a newly opened descriptor on success.
 * adopt() takes ownership of the supplied descriptor only on success; the
 * caller retains it on failure.  No operation sleeps or polls.
 */
int	virtio_fs_backend_client_connect(const char *, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *,
	    struct virtio_fs_backend_client **);
int	virtio_fs_backend_client_adopt(int, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *,
	    struct virtio_fs_backend_client **);
void	virtio_fs_backend_client_destroy(struct virtio_fs_backend_client *);
int	virtio_fs_backend_client_fd(
	    const struct virtio_fs_backend_client *);
uint32_t virtio_fs_backend_client_events(
	    const struct virtio_fs_backend_client *);
int	virtio_fs_backend_client_progress(struct virtio_fs_backend_client *,
	    bool, bool);
bool	virtio_fs_backend_client_active(
	    const struct virtio_fs_backend_client *);
int	virtio_fs_backend_client_error(
	    const struct virtio_fs_backend_client *);
int	virtio_fs_backend_client_take_active(
	    struct virtio_fs_backend_client *,
	    struct virtio_fs_backend_session *, int *);

#endif
