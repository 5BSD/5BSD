/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_PMEM_ASYNC_H_
#define	_BHYVE_VIRTIO_PMEM_ASYNC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A modern virtqueue size is represented in 16 bits and is at most 32768. */
#define	BHYVE_VIRTIO_PMEM_ASYNC_MAX	32768U

struct virtio_pmem_async;

struct virtio_pmem_async_job {
	uintptr_t token;
	uint64_t epoch;
};

/*
 * This ledger owns guest-request tokens, not worker threads or guest memory.
 * submit() transfers a token into a bounded FIFO.  One worker acquires and
 * completes one token at a time.  pause() closes admission but intentionally
 * leaves queued work acquirable so an event-driven worker can drain it.
 *
 * Callers must exclude concurrent API entry before destroy().  A successful
 * reset completion advances the epoch before token reuse; callers restoring a
 * suspended device pass resume=false and reopen admission explicitly later.
 */
int	virtio_pmem_async_create(size_t, struct virtio_pmem_async **);
int	virtio_pmem_async_destroy(struct virtio_pmem_async *);
int	virtio_pmem_async_submit(struct virtio_pmem_async *, uintptr_t,
	    uint64_t *);
int	virtio_pmem_async_acquire(struct virtio_pmem_async *,
	    struct virtio_pmem_async_job *);
int	virtio_pmem_async_complete(struct virtio_pmem_async *,
	    const struct virtio_pmem_async_job *);
int	virtio_pmem_async_pause(struct virtio_pmem_async *, size_t *);
int	virtio_pmem_async_abort_pause(struct virtio_pmem_async *);
int	virtio_pmem_async_resume(struct virtio_pmem_async *);
int	virtio_pmem_async_finish_reset(struct virtio_pmem_async *, bool);
int	virtio_pmem_async_defer_reset(struct virtio_pmem_async *, bool);
int	virtio_pmem_async_pending(struct virtio_pmem_async *, size_t *, bool *);

#endif
