/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_GPU_VIRTIO_GPU_GEOMETRY_H_
#define	_DEV_VIRTIO_GPU_VIRTIO_GPU_GEOMETRY_H_

#include <sys/types.h>

/*
 * Validate multiplication of device-provided geometry without relying on
 * native overflow behavior.  Limits are supplied by the consumer because
 * the wire protocol itself does not impose a framebuffer allocation policy.
 */
static inline bool
virtio_gpu_framebuffer_geometry(uint32_t width, uint32_t height,
    uint32_t bytes_per_pixel, uint64_t max_stride, uint64_t max_size,
    uint32_t *stridep, uint64_t *sizep)
{
	uint64_t size, stride;

	if (width == 0 || height == 0 || bytes_per_pixel == 0 ||
	    width > max_stride / bytes_per_pixel)
		return (false);
	stride = (uint64_t)width * bytes_per_pixel;
	if (height > max_size / stride)
		return (false);
	size = stride * height;
	if (stride > UINT32_MAX)
		return (false);
	if (stridep != NULL)
		*stridep = stride;
	if (sizep != NULL)
		*sizep = size;
	return (true);
}

static inline bool
virtio_gpu_rect_within(uint32_t fb_width, uint32_t fb_height, uint32_t x,
    uint32_t y, uint32_t width, uint32_t height)
{

	return (width != 0 && height != 0 && x <= fb_width &&
	    y <= fb_height && width <= fb_width - x &&
	    height <= fb_height - y);
}

#endif
