/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_GPU_2D_DISPLAY_H_
#define	_BHYVE_VIRTIO_GPU_2D_DISPLAY_H_

#include <stddef.h>
#include <stdint.h>

int	virtio_gpu_2d_pixel_to_argb(uint32_t, const uint8_t[4], uint32_t *);
/*
 * The destination presentation format is the architecture-independent byte
 * vector B8G8R8X8, with X written as zero.
 */
int	virtio_gpu_2d_convert_xrgb(uint32_t, const void *, size_t, void *,
	    size_t, uint32_t, uint32_t);
int	virtio_gpu_2d_composite_cursor_xrgb(uint32_t, const void *, size_t,
	    void *, size_t, uint32_t, uint32_t);

#endif
