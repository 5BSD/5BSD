/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_gpu_2d_display.h"
#include "virtio_gpu_2d_protocol.h"

int
virtio_gpu_2d_pixel_to_argb(uint32_t format, const uint8_t pixel[4],
    uint32_t *argb)
{
	uint8_t alpha, blue, green, red;

	if (pixel == NULL || argb == NULL)
		return (EINVAL);
	switch (format) {
	case VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM:
		blue = pixel[0];
		green = pixel[1];
		red = pixel[2];
		alpha = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_B8G8R8X8_UNORM:
		blue = pixel[0];
		green = pixel[1];
		red = pixel[2];
		alpha = UINT8_MAX;
		break;
	case VIRTIO_GPU_2D_FORMAT_A8R8G8B8_UNORM:
		alpha = pixel[0];
		red = pixel[1];
		green = pixel[2];
		blue = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_X8R8G8B8_UNORM:
		alpha = UINT8_MAX;
		red = pixel[1];
		green = pixel[2];
		blue = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_R8G8B8A8_UNORM:
		red = pixel[0];
		green = pixel[1];
		blue = pixel[2];
		alpha = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_X8B8G8R8_UNORM:
		alpha = UINT8_MAX;
		blue = pixel[1];
		green = pixel[2];
		red = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_A8B8G8R8_UNORM:
		alpha = pixel[0];
		blue = pixel[1];
		green = pixel[2];
		red = pixel[3];
		break;
	case VIRTIO_GPU_2D_FORMAT_R8G8B8X8_UNORM:
		red = pixel[0];
		green = pixel[1];
		blue = pixel[2];
		alpha = UINT8_MAX;
		break;
	default:
		return (EINVAL);
	}
	*argb = (uint32_t)alpha << 24 | (uint32_t)red << 16 |
	    (uint32_t)green << 8 | blue;
	return (0);
}

int
virtio_gpu_2d_convert_xrgb(uint32_t format, const void *source,
    size_t source_stride, void *destination, size_t destination_stride,
    uint32_t width, uint32_t height)
{
	const uint8_t *input;
	uint8_t *output;
	uint32_t pixel;
	size_t row_bytes;
	int error;

	if (source == NULL || destination == NULL || width == 0 || height == 0)
		return (EINVAL);
	row_bytes = (size_t)width * sizeof(uint32_t);
	if (row_bytes / sizeof(uint32_t) != width)
		return (EOVERFLOW);
	if (source_stride < row_bytes || destination_stride < row_bytes)
		return (EMSGSIZE);
	if ((size_t)(height - 1) > (SIZE_MAX - row_bytes) / source_stride ||
	    (size_t)(height - 1) >
	    (SIZE_MAX - row_bytes) / destination_stride)
		return (EOVERFLOW);
	input = source;
	output = destination;
	for (uint32_t row = 0; row < height; row++) {
		for (uint32_t column = 0; column < width; column++) {
			error = virtio_gpu_2d_pixel_to_argb(format,
			    input + (size_t)column * sizeof(uint32_t), &pixel);
			if (error != 0)
				return (error);
			/*
			 * The presentation boundary uses one explicit byte layout:
			 * B8G8R8X8 with an all-zero X byte.  Storing the numeric
			 * 0x00RRGGBB value with memcpy() would make this buffer
			 * host-endian and would reverse its bytes on a big-endian
			 * display host.
			 */
			uint8_t *destination_pixel =
			    output + (size_t)column * sizeof(pixel);

			destination_pixel[0] = (uint8_t)pixel;
			destination_pixel[1] = (uint8_t)(pixel >> 8);
			destination_pixel[2] = (uint8_t)(pixel >> 16);
			destination_pixel[3] = 0;
		}
		input += source_stride;
		output += destination_stride;
	}
	return (0);
}

static uint8_t
gpu_blend_channel(uint8_t foreground, uint8_t background, uint8_t alpha)
{
	uint32_t mixed;

	/*
	 * The extra 127 implements round-to-nearest for division by 255.
	 * All operands are promoted before multiplication.
	 */
	mixed = (uint32_t)foreground * alpha +
	    (uint32_t)background * (UINT8_MAX - alpha) + 127;
	return ((uint8_t)(mixed / UINT8_MAX));
}

int
virtio_gpu_2d_composite_cursor_xrgb(uint32_t format, const void *source,
    size_t source_stride, void *destination, size_t destination_stride,
    uint32_t width, uint32_t height)
{
	const uint8_t *input;
	uint8_t *output;
	uint32_t foreground;
	size_t row_bytes;
	uint8_t alpha, blue, green, red;
	int error;

	if (source == NULL || destination == NULL || width == 0 || height == 0)
		return (EINVAL);
	row_bytes = (size_t)width * sizeof(uint32_t);
	if (row_bytes / sizeof(uint32_t) != width)
		return (EOVERFLOW);
	if (source_stride < row_bytes || destination_stride < row_bytes)
		return (EMSGSIZE);
	if ((size_t)(height - 1) > (SIZE_MAX - row_bytes) / source_stride ||
	    (size_t)(height - 1) >
	    (SIZE_MAX - row_bytes) / destination_stride)
		return (EOVERFLOW);

	input = source;
	output = destination;
	for (uint32_t row = 0; row < height; row++) {
		for (uint32_t column = 0; column < width; column++) {
			error = virtio_gpu_2d_pixel_to_argb(format,
			    input + (size_t)column * sizeof(uint32_t),
			    &foreground);
			if (error != 0)
				return (error);
			uint8_t *destination_pixel =
			    output + (size_t)column * sizeof(uint32_t);

			alpha = (uint8_t)(foreground >> 24);
			red = gpu_blend_channel((uint8_t)(foreground >> 16),
			    destination_pixel[2], alpha);
			green = gpu_blend_channel((uint8_t)(foreground >> 8),
			    destination_pixel[1], alpha);
			blue = gpu_blend_channel((uint8_t)foreground,
			    destination_pixel[0], alpha);
			destination_pixel[0] = blue;
			destination_pixel[1] = green;
			destination_pixel[2] = red;
			destination_pixel[3] = 0;
		}
		input += source_stride;
		output += destination_stride;
	}
	return (0);
}
