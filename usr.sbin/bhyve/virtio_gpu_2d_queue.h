/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_GPU_2D_QUEUE_H_
#define	_BHYVE_VIRTIO_GPU_2D_QUEUE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_gpu_2d_protocol.h"
#include "virtio_gpu_2d_state.h"

#define	BHYVE_VIRTIO_GPU_MAX_REQUEST_SIZE \
	(32U + BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES * \
	BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE)
#define	BHYVE_VIRTIO_GPU_MAX_CHAIN_SEGMENTS	4096U

struct virtio_gpu_2d_segment {
	void *base;
	size_t length;
	bool writable;
};

int	virtio_gpu_2d_queue_process(struct virtio_gpu_2d_state *,
	    enum virtio_gpu_2d_queue, const struct virtio_gpu_2d_segment *,
	    size_t, uint32_t, uint32_t, size_t *);
int	virtio_gpu_2d_queue_process_features(struct virtio_gpu_2d_state *,
	    enum virtio_gpu_2d_queue, const struct virtio_gpu_2d_segment *,
	    size_t, uint32_t, uint32_t, uint64_t, size_t *);

#endif
