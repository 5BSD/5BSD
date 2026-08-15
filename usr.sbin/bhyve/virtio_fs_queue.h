/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_QUEUE_H_
#define	_BHYVE_VIRTIO_FS_QUEUE_H_

#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_host.h"

struct virtio_fs_queue;

typedef void (*virtio_fs_queue_complete_cb)(void *, uintptr_t, size_t);
typedef void (*virtio_fs_queue_discard_cb)(void *, uintptr_t);
typedef void (*virtio_fs_queue_reset_complete_cb)(void *, uint32_t, int);

int	virtio_fs_queue_create(const struct virtio_fs_backend_session *,
	    uint32_t, uint32_t, virtio_fs_queue_complete_cb, void *,
	    struct virtio_fs_queue **);
void	virtio_fs_queue_destroy(struct virtio_fs_queue *);
int	virtio_fs_queue_set_reset_complete(
	    struct virtio_fs_queue *, virtio_fs_queue_reset_complete_cb,
	    void *);
int	virtio_fs_queue_set_discard(
	    struct virtio_fs_queue *, virtio_fs_queue_discard_cb, void *);
int	virtio_fs_queue_submit(struct virtio_fs_queue *,
	    enum virtio_fs_queue_class, const struct iovec *, size_t, size_t,
	    size_t, bool, uintptr_t);
int	virtio_fs_queue_submit_on(struct virtio_fs_queue *, uint32_t,
	    enum virtio_fs_queue_class, const struct iovec *, size_t, size_t,
	    size_t, bool, uintptr_t);
int	virtio_fs_queue_flush_one(struct virtio_fs_queue *, int);
int	virtio_fs_queue_receive(struct virtio_fs_queue *,
	    const struct virtio_fs_backend_header *, const void *, size_t);
int	virtio_fs_queue_fail(struct virtio_fs_queue *, size_t *);
int	virtio_fs_queue_pause(struct virtio_fs_queue *,
	    struct virtio_fs_session *);
void	virtio_fs_queue_resume(struct virtio_fs_queue *);
int	virtio_fs_queue_restore_session(struct virtio_fs_queue *,
	    const struct virtio_fs_session *);
int	virtio_fs_queue_reset(struct virtio_fs_queue *, size_t *);
int	virtio_fs_queue_reset_one(struct virtio_fs_queue *, uint32_t,
	    size_t *);
uint32_t virtio_fs_queue_pending(struct virtio_fs_queue *);
uint32_t virtio_fs_queue_outgoing(struct virtio_fs_queue *);

#endif
