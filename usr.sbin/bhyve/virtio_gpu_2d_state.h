/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_GPU_2D_STATE_H_
#define	_BHYVE_VIRTIO_GPU_2D_STATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_gpu_2d_protocol.h"

struct virtio_gpu_2d_state;

#define	VIRTIO_GPU_2D_CURSOR_WIDTH	64U
#define	VIRTIO_GPU_2D_CURSOR_HEIGHT	64U
#define	VIRTIO_GPU_2D_CURSOR_BYTES	(VIRTIO_GPU_2D_CURSOR_WIDTH * \
	    VIRTIO_GPU_2D_CURSOR_HEIGHT * sizeof(uint32_t))

struct virtio_gpu_2d_limits {
	uint32_t max_resources;
	uint64_t max_host_bytes;
	uint64_t max_blob_bytes;
	uint32_t blob_alignment;
	uint32_t scanout_width;
	uint32_t scanout_height;
};

enum virtio_gpu_2d_dma_access {
	VIRTIO_GPU_2D_DMA_DEVICE_READ = 1,
};

struct virtio_gpu_2d_ops {
	int (*dma_validate)(void *, uint64_t, size_t,
	    enum virtio_gpu_2d_dma_access);
	int (*dma_read)(void *, uint64_t, void *, size_t);
	void (*display_reset)(void *);
	/*
	 * Bind or disable a scanout.  A zero resource_id disables it and
	 * therefore carries a zero rectangle.  Pixel damage is reported
	 * separately through display_update().
	 */
	void (*scanout_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void (*display_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void (*cursor_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void *arg;
};

int	virtio_gpu_2d_state_create(const struct virtio_gpu_2d_limits *,
	    const struct virtio_gpu_2d_ops *, struct virtio_gpu_2d_state **);
/*
 * Destruction closes new command admission and drains externally executing
 * display/DMA callbacks.  A display callback may query state, but must not
 * destroy the same state recursively: it is itself the lifetime owner being
 * drained.
 */
void	virtio_gpu_2d_state_destroy(struct virtio_gpu_2d_state *);
void	virtio_gpu_2d_state_reset(struct virtio_gpu_2d_state *);
uint32_t virtio_gpu_2d_state_execute(struct virtio_gpu_2d_state *,
	    const struct virtio_gpu_2d_command *, const void *, size_t);
int	virtio_gpu_2d_state_read_resource(struct virtio_gpu_2d_state *,
	    uint32_t, size_t, void *, size_t);
int	virtio_gpu_2d_state_scanout(struct virtio_gpu_2d_state *, uint32_t *,
	    uint32_t *, uint32_t *, uint32_t *, uint32_t *);
int	virtio_gpu_2d_state_copy_scanout(struct virtio_gpu_2d_state *,
	    uint32_t, uint32_t, uint32_t, uint32_t, void *, size_t,
	    uint32_t *);
int	virtio_gpu_2d_state_capture_scanout(struct virtio_gpu_2d_state *,
	    void *, size_t, uint32_t *, uint32_t *, uint32_t *, size_t *);
int	virtio_gpu_2d_state_copy_cursor(struct virtio_gpu_2d_state *, void *,
	    size_t, uint32_t *, uint32_t *, uint32_t *, uint32_t *,
	    uint32_t *);
uint32_t virtio_gpu_2d_state_resource_count(struct virtio_gpu_2d_state *);
uint64_t virtio_gpu_2d_state_host_bytes(struct virtio_gpu_2d_state *);
uint64_t virtio_gpu_2d_state_blob_bytes(struct virtio_gpu_2d_state *);
bool	virtio_gpu_2d_state_storage_overlaps(struct virtio_gpu_2d_state *,
	    const void *, size_t);
int	virtio_gpu_2d_state_snapshot_size(struct virtio_gpu_2d_state *,
	    size_t *);
int	virtio_gpu_2d_state_snapshot_limit(struct virtio_gpu_2d_state *,
	    size_t *);
int	virtio_gpu_2d_state_snapshot_save(struct virtio_gpu_2d_state *,
	    void *, size_t);
int	virtio_gpu_2d_state_snapshot_validate(struct virtio_gpu_2d_state *,
	    const void *, size_t);
int	virtio_gpu_2d_state_snapshot_restore(struct virtio_gpu_2d_state *,
	    const void *, size_t);

#endif
