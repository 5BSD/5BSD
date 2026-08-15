/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_PMEM_WORKER_H_
#define	_BHYVE_VIRTIO_PMEM_WORKER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_pmem_worker;

struct virtio_pmem_worker_ops {
	int (*flush)(void *);
	void (*complete)(void *, uintptr_t, uint64_t, int);
	void *arg;
};

/*
 * flush() runs only on the dedicated worker.  complete() runs while ledger
 * ownership remains active; ownership is released only after publication
 * returns, so a lifecycle drain cannot pass it.  The owner
 * must exclude API calls during destroy(), and complete() must not destroy its
 * own worker thread.
 */
int	virtio_pmem_worker_create(size_t,
	    const struct virtio_pmem_worker_ops *, struct virtio_pmem_worker **);
int	virtio_pmem_worker_destroy(struct virtio_pmem_worker *, uint32_t);
int	virtio_pmem_worker_submit(struct virtio_pmem_worker *, uintptr_t,
	    uint64_t *);
int	virtio_pmem_worker_pause(struct virtio_pmem_worker *, uint32_t);
int	virtio_pmem_worker_abort_pause(struct virtio_pmem_worker *);
int	virtio_pmem_worker_resume(struct virtio_pmem_worker *);
int	virtio_pmem_worker_reset(struct virtio_pmem_worker *, uint32_t, bool);
int	virtio_pmem_worker_defer_reset(struct virtio_pmem_worker *, bool);
int	virtio_pmem_worker_pending(struct virtio_pmem_worker *, size_t *, bool *);

#endif
