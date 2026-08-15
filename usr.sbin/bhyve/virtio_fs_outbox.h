/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_OUTBOX_H_
#define	_BHYVE_VIRTIO_FS_OUTBOX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"

struct virtio_fs_outbox;

int	virtio_fs_outbox_create(uint32_t, uint32_t, uint32_t, uint32_t,
	    struct virtio_fs_outbox **);
void	virtio_fs_outbox_destroy(struct virtio_fs_outbox *);
int	virtio_fs_outbox_enqueue(struct virtio_fs_outbox *, bool,
	    const struct virtio_fs_backend_header *, const void *);
int	virtio_fs_outbox_enqueue_on(struct virtio_fs_outbox *, bool,
	    uint32_t, const struct virtio_fs_backend_header *, const void *);
int	virtio_fs_outbox_flush_one(struct virtio_fs_outbox *, int,
	    struct virtio_fs_backend_header *);
uint32_t virtio_fs_outbox_reset(struct virtio_fs_outbox *);
uint32_t virtio_fs_outbox_reset_queue(struct virtio_fs_outbox *, uint32_t);
uint32_t virtio_fs_outbox_count(struct virtio_fs_outbox *, bool);
uint64_t virtio_fs_outbox_bytes(struct virtio_fs_outbox *);

#endif
