/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_PENDING_H_
#define	_BHYVE_VIRTIO_FS_PENDING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_host.h"

struct virtio_fs_pending;

struct virtio_fs_pending_result {
	uint64_t request_id;
	uint64_t backend_incarnation;
	struct virtio_fs_request_context request;
	uintptr_t owner_cookie;
	uint32_t payload_len;
	uint32_t queue_id;
	bool cancel_requested;
	bool sent;
};

int	virtio_fs_pending_create(uint32_t, uint32_t,
	    struct virtio_fs_pending **);
void	virtio_fs_pending_destroy(struct virtio_fs_pending *);
int	virtio_fs_pending_insert(struct virtio_fs_pending *, uint64_t,
	    uint64_t, const struct virtio_fs_request_context *, uint32_t);
int	virtio_fs_pending_insert_owned(struct virtio_fs_pending *, uint64_t,
	    uint64_t, const struct virtio_fs_request_context *, uint32_t,
	    uintptr_t);
int	virtio_fs_pending_insert_owned_on(struct virtio_fs_pending *,
	    uint64_t, uint64_t, const struct virtio_fs_request_context *,
	    uint32_t, uintptr_t, uint32_t);
int	virtio_fs_pending_cancel(struct virtio_fs_pending *, uint64_t,
	    uint64_t);
int	virtio_fs_pending_cancel_next_queue(struct virtio_fs_pending *,
	    uint32_t, struct virtio_fs_pending_result *);
int	virtio_fs_pending_cancel_rollback(struct virtio_fs_pending *,
	    uint64_t, uint64_t);
int	virtio_fs_pending_mark_sent(struct virtio_fs_pending *, uint64_t,
	    uint64_t);
int	virtio_fs_pending_lookup(struct virtio_fs_pending *, uint64_t,
	    uint64_t, struct virtio_fs_pending_result *);
int	virtio_fs_pending_remove(struct virtio_fs_pending *, uint64_t,
	    uint64_t, struct virtio_fs_pending_result *);
uint32_t virtio_fs_pending_count(struct virtio_fs_pending *);
uint64_t virtio_fs_pending_bytes(struct virtio_fs_pending *);
bool	virtio_fs_pending_state_overlaps(struct virtio_fs_pending *,
	    const void *, size_t);
int	virtio_fs_pending_drain(struct virtio_fs_pending *,
	    struct virtio_fs_pending_result *, size_t, size_t *);
int	virtio_fs_pending_drain_queue(struct virtio_fs_pending *, uint32_t,
	    struct virtio_fs_pending_result *, size_t, size_t *);

#endif
