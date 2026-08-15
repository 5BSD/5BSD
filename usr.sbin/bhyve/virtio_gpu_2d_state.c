/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_gpu_2d_state.h"
#include "virtio_state_range.h"

#define	GPU_BYTES_PER_PIXEL	4U
#define	GPU_CURSOR_WIDTH	VIRTIO_GPU_2D_CURSOR_WIDTH
#define	GPU_CURSOR_HEIGHT	VIRTIO_GPU_2D_CURSOR_HEIGHT
#define	GPU_STATE_MAGIC		0x44324756U	/* "VG2D" */
#define	GPU_STATE_VERSION	3U
#define	GPU_STATE_HEADER_SIZE	72U
#define	GPU_STATE_RESOURCE_SIZE	72U
#define	GPU_STATE_BACKING_SIZE	16U

enum gpu_resource_kind {
	GPU_RESOURCE_EMPTY,
	GPU_RESOURCE_2D,
	GPU_RESOURCE_BLOB,
};

struct gpu_backing_entry {
	uint64_t address;
	uint32_t length;
};

struct gpu_resource {
	uint32_t id;
	enum gpu_resource_kind kind;
	uint32_t format;
	uint32_t width;
	uint32_t height;
	uint32_t stride;
	size_t host_bytes;
	uint8_t *pixels;
	struct gpu_backing_entry *backing;
	uint32_t backing_count;
	uint64_t backing_bytes;
	uint32_t blob_memory;
	uint32_t blob_flags;
	uint64_t blob_id;
	uint64_t blob_size;
	uint32_t blob_plane_offset;
};

struct gpu_scanout {
	uint32_t resource_id;
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
};

struct virtio_gpu_2d_state {
	pthread_mutex_t mutex;
	pthread_cond_t callback_drain;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	struct gpu_resource *resources;
	uint32_t resource_count;
	uint64_t host_bytes;
	uint64_t blob_bytes;
	struct gpu_scanout scanout;
	uint32_t cursor_resource_id;
	uint32_t cursor_x;
	uint32_t cursor_y;
	uint32_t cursor_hot_x;
	uint32_t cursor_hot_y;
	/*
	 * Presentation callbacks and snapshot DMA validation deliberately run with
	 * mutex dropped.  Keep the state allocated until the final external
	 * operation returns, and reject new commands once destruction has begun.
	 * This is a lifetime fence, not a guest-visible queue fence.
	 */
	unsigned int callbacks;
	bool destroying;
};

static bool gpu_state_overlaps_locked(struct virtio_gpu_2d_state *,
    const void *, size_t);
static void gpu_resource_clear(struct gpu_resource *);

static void
gpu_state_callback_done(struct virtio_gpu_2d_state *state)
{

	pthread_mutex_lock(&state->mutex);
	if (state->callbacks != 0)
		state->callbacks--;
	if (state->callbacks == 0)
		(void)pthread_cond_broadcast(&state->callback_drain);
	pthread_mutex_unlock(&state->mutex);
}

static void
gpu_state_clear_locked(struct virtio_gpu_2d_state *state)
{

	for (uint32_t i = 0; i < state->limits.max_resources; i++)
		gpu_resource_clear(&state->resources[i]);
	state->resource_count = 0;
	state->host_bytes = 0;
	state->blob_bytes = 0;
	memset(&state->scanout, 0, sizeof(state->scanout));
	state->cursor_resource_id = 0;
	state->cursor_x = 0;
	state->cursor_y = 0;
	state->cursor_hot_x = 0;
	state->cursor_hot_y = 0;
}

/*
 * Keep the resource-array extent explicit.  calloc(3) rejects an overflowing
 * product on supported hosts, but later state-overlap checks use this extent
 * too; accepting it here would make those checks depend on allocator-specific
 * overflow behavior on a future 32-bit build.
 */
static int
gpu_resource_array_size(uint32_t count, size_t *size)
{

	if (size == NULL)
		return (EINVAL);
#if SIZE_MAX <= UINT32_MAX
	if (count > SIZE_MAX / sizeof(struct gpu_resource))
		return (EOVERFLOW);
#endif
	*size = (size_t)count * sizeof(struct gpu_resource);
	return (0);
}

static int
gpu_transfer_size(uint32_t width, uint32_t height, size_t *row_size,
    size_t *transfer_size)
{
	size_t row;

	if (width == 0 || height == 0 || row_size == NULL ||
	    transfer_size == NULL)
		return (EINVAL);
	if (__builtin_mul_overflow((size_t)width,
	    (size_t)GPU_BYTES_PER_PIXEL, &row) ||
	    __builtin_mul_overflow(row, (size_t)height, transfer_size))
		return (EOVERFLOW);
	*row_size = row;
	return (0);
}

static struct gpu_resource *
gpu_find_resource(struct virtio_gpu_2d_state *state, uint32_t id)
{
	/* Resource ID zero denotes no resource and must not match a free slot. */
	if (id == 0)
		return (NULL);

	for (uint32_t i = 0; i < state->limits.max_resources; i++) {
		if (state->resources[i].id == id)
			return (&state->resources[i]);
	}
	return (NULL);
}

static struct gpu_resource *
gpu_find_empty(struct virtio_gpu_2d_state *state)
{

	for (uint32_t i = 0; i < state->limits.max_resources; i++) {
		if (state->resources[i].id == 0)
			return (&state->resources[i]);
	}
	return (NULL);
}

static bool
gpu_rect_inside(const struct virtio_gpu_2d_command *command,
    const struct gpu_resource *resource)
{

	return (command->width != 0 && command->height != 0 &&
	    command->x <= resource->width &&
	    command->y <= resource->height &&
	    command->width <= resource->width - command->x &&
	    command->height <= resource->height - command->y);
}

static void
gpu_resource_clear(struct gpu_resource *resource)
{

	free(resource->pixels);
	free(resource->backing);
	memset(resource, 0, sizeof(*resource));
}

static uint32_t
gpu_create_resource(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command)
{
	struct gpu_resource *resource;
	uint64_t stride, host_bytes;
	uint8_t *pixels;

	if (command->resource_id == 0 || command->width == 0 ||
	    command->height == 0 ||
	    !virtio_gpu_2d_format_valid(command->format))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (gpu_find_resource(state, command->resource_id) != NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	resource = gpu_find_empty(state);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	stride = (uint64_t)command->width * GPU_BYTES_PER_PIXEL;
	if (command->height > UINT64_MAX / stride)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	host_bytes = stride * command->height;
	if (stride > UINT32_MAX || host_bytes > SIZE_MAX ||
	    host_bytes > state->limits.max_host_bytes - state->host_bytes)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	pixels = calloc(1, (size_t)host_bytes);
	if (pixels == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	resource->id = command->resource_id;
	resource->kind = GPU_RESOURCE_2D;
	resource->format = command->format;
	resource->width = command->width;
	resource->height = command->height;
	resource->stride = (uint32_t)stride;
	resource->host_bytes = (size_t)host_bytes;
	resource->pixels = pixels;
	state->resource_count++;
	state->host_bytes += host_bytes;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_unref_resource(struct virtio_gpu_2d_state *state, uint32_t resource_id)
{
	struct gpu_resource *resource;

	resource = gpu_find_resource(state, resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (state->scanout.resource_id == resource_id)
		memset(&state->scanout, 0, sizeof(state->scanout));
	if (state->cursor_resource_id == resource_id) {
		state->cursor_resource_id = 0;
		state->cursor_hot_x = 0;
		state->cursor_hot_y = 0;
	}
	if (resource->kind == GPU_RESOURCE_BLOB) {
		state->blob_bytes -= resource->blob_size;
		state->host_bytes -= resource->host_bytes;
	} else
		state->host_bytes -= resource->host_bytes;
	state->resource_count--;
	gpu_resource_clear(resource);
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_attach_backing(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command, const void *request,
    size_t request_len)
{
	const uint8_t *bytes;
	struct gpu_backing_entry *entries;
	struct gpu_resource *resource;
	uint64_t total, address;
	uint32_t length;
	size_t expected, offset;

	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (resource->backing != NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
	if (request == NULL || command->entry_count == 0 ||
	    command->entry_count > BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	expected = 32 + (size_t)command->entry_count *
	    BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
	if (request_len != expected)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	entries = calloc(command->entry_count, sizeof(*entries));
	if (entries == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	bytes = request;
	if (le32dec(bytes + 24) != command->resource_id ||
	    le32dec(bytes + 28) != command->entry_count) {
		free(entries);
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	}
	total = 0;
	for (uint32_t i = 0; i < command->entry_count; i++) {
		offset = 32 + (size_t)i * BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
		address = le64dec(bytes + offset);
		length = le32dec(bytes + offset + 8);
		if (length == 0 || le32dec(bytes + offset + 12) != 0 ||
		    address > UINT64_MAX - length ||
		    total > UINT64_MAX - length) {
			free(entries);
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		}
		entries[i].address = address;
		entries[i].length = length;
		total += length;
	}
	resource->backing = entries;
	resource->backing_count = command->entry_count;
	resource->backing_bytes = total;
	if (resource->kind == GPU_RESOURCE_BLOB &&
	    total < resource->blob_size) {
		free(resource->backing);
		resource->backing = NULL;
		resource->backing_count = 0;
		resource->backing_bytes = 0;
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	}
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_detach_backing(struct virtio_gpu_2d_state *state, uint32_t resource_id)
{
	struct gpu_resource *resource;

	resource = gpu_find_resource(state, resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (resource->backing == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
	free(resource->backing);
	resource->backing = NULL;
	resource->backing_count = 0;
	resource->backing_bytes = 0;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_create_blob(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command, const void *request,
    size_t request_len)
{
	const uint8_t *bytes;
	struct gpu_backing_entry *entries;
	struct gpu_resource *resource;
	uint64_t address, total;
	uint32_t length;
	size_t expected, offset;

	if (command->resource_id == 0 ||
	    state->limits.max_blob_bytes == 0 ||
	    state->limits.blob_alignment == 0)
		return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
	if (command->blob_memory != VIRTIO_GPU_2D_BLOB_MEM_GUEST ||
	    (command->blob_flags & ~VIRTIO_GPU_2D_BLOB_FLAGS_MASK) != 0 ||
	    (command->blob_flags &
	    VIRTIO_GPU_2D_BLOB_FLAG_USE_MAPPABLE) != 0 ||
	    (command->blob_flags &
	    VIRTIO_GPU_2D_BLOB_FLAG_USE_CROSS_DEVICE) != 0 ||
	    command->blob_size == 0 ||
	    command->blob_size % state->limits.blob_alignment != 0 ||
	    command->blob_size > state->limits.max_blob_bytes -
	    state->blob_bytes)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (gpu_find_resource(state, command->resource_id) != NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	resource = gpu_find_empty(state);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	if (command->entry_count > BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	expected = 56 + (size_t)command->entry_count *
	    BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
	if (request == NULL || request_len != expected)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	bytes = request;
	if (le32dec(bytes) != VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB ||
	    le32dec(bytes + 24) != command->resource_id ||
	    le32dec(bytes + 28) != command->blob_memory ||
	    le32dec(bytes + 32) != command->blob_flags ||
	    le32dec(bytes + 36) != command->entry_count ||
	    le64dec(bytes + 40) != command->blob_id ||
	    le64dec(bytes + 48) != command->blob_size)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	entries = NULL;
	if (command->entry_count != 0) {
		entries = calloc(command->entry_count, sizeof(*entries));
		if (entries == NULL)
			return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	}
	total = 0;
	for (uint32_t i = 0; i < command->entry_count; i++) {
		offset = 56 + (size_t)i * BHYVE_VIRTIO_GPU_MEM_ENTRY_SIZE;
		address = le64dec(bytes + offset);
		length = le32dec(bytes + offset + 8);
		if (length == 0 || le32dec(bytes + offset + 12) != 0 ||
		    address > UINT64_MAX - length ||
		    total > UINT64_MAX - length) {
			free(entries);
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		}
		entries[i].address = address;
		entries[i].length = length;
		total += length;
	}
	if (command->entry_count != 0 && total < command->blob_size) {
		free(entries);
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	}
	resource->id = command->resource_id;
	resource->kind = GPU_RESOURCE_BLOB;
	resource->backing = entries;
	resource->backing_count = command->entry_count;
	resource->backing_bytes = total;
	resource->blob_memory = command->blob_memory;
	resource->blob_flags = command->blob_flags;
	resource->blob_id = command->blob_id;
	resource->blob_size = command->blob_size;
	state->resource_count++;
	state->blob_bytes += command->blob_size;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_map_blob(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command)
{
	struct gpu_resource *resource;

	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL || resource->kind != GPU_RESOURCE_BLOB)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	/* MAP_BLOB is defined for host-only blobs; this device has none. */
	return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
}

static uint32_t
gpu_unmap_blob(struct virtio_gpu_2d_state *state, uint32_t resource_id)
{
	struct gpu_resource *resource;

	resource = gpu_find_resource(state, resource_id);
	if (resource == NULL || resource->kind != GPU_RESOURCE_BLOB)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
}

static int
gpu_backing_read(struct virtio_gpu_2d_state *state,
    const struct gpu_resource *resource, uint64_t offset, void *destination,
    size_t length)
{
	uint8_t *output;
	uint64_t logical, available;
	size_t amount;
	int error;

	if (state->ops.dma_read == NULL ||
	    offset > resource->backing_bytes ||
	    length > resource->backing_bytes - offset)
		return (EFAULT);
	output = destination;
	logical = 0;
	for (uint32_t i = 0; i < resource->backing_count && length != 0; i++) {
		available = resource->backing[i].length;
		if (offset >= logical + available) {
			logical += available;
			continue;
		}
		available -= offset - logical;
		amount = length < available ? length : (size_t)available;
		error = state->ops.dma_read(state->ops.arg,
		    resource->backing[i].address + (offset - logical),
		    output, amount);
		if (error != 0)
			return (error);
		output += amount;
		length -= amount;
		offset += amount;
		logical += resource->backing[i].length;
	}
	return (length == 0 ? 0 : EFAULT);
}

static uint32_t
gpu_transfer(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command)
{
	struct gpu_resource *resource;
	uint8_t *staging;
	uint64_t row_source;
	size_t minimum_bytes, row_bytes, transfer_bytes;
	int error;

	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (resource->kind == GPU_RESOURCE_BLOB &&
	    (resource->width == 0 || resource->height == 0)) {
		if (resource->backing == NULL || command->width == 0 ||
		    command->height == 0 ||
		    __builtin_mul_overflow((size_t)command->width,
		    (size_t)GPU_BYTES_PER_PIXEL, &row_bytes) ||
		    __builtin_mul_overflow(row_bytes,
		    (size_t)command->height, &minimum_bytes) ||
		    command->offset > resource->backing_bytes ||
		    minimum_bytes >
		    resource->backing_bytes - command->offset)
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		/*
		 * Linux submits its first TRANSFER_TO_HOST_2D before the
		 * SET_SCANOUT_BLOB that supplies the image layout.  The later
		 * scanout command imports the complete backing transactionally.
		 */
		return (VIRTIO_GPU_2D_RESP_OK_NODATA);
	}
	if (resource->backing == NULL || !gpu_rect_inside(command, resource))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (gpu_transfer_size(command->width, command->height, &row_bytes,
	    &transfer_bytes) != 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	staging = malloc(transfer_bytes);
	if (staging == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	for (uint32_t row = 0; row < command->height; row++) {
		if (row > (UINT64_MAX - command->offset) / resource->stride) {
			free(staging);
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		}
		row_source = command->offset + (uint64_t)row *
		    resource->stride;
		error = gpu_backing_read(state, resource, row_source,
		    staging + (size_t)row * row_bytes, row_bytes);
		if (error != 0) {
			free(staging);
			return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
		}
	}
	for (uint32_t row = 0; row < command->height; row++) {
		memcpy(resource->pixels +
		    (size_t)(command->y + row) * resource->stride +
		    (size_t)command->x * GPU_BYTES_PER_PIXEL,
		    staging + (size_t)row * row_bytes, row_bytes);
	}
	free(staging);
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_import_blob_pixels(struct virtio_gpu_2d_state *state,
    struct gpu_resource *resource, uint32_t format, uint32_t width,
    uint32_t height, uint32_t stride, uint32_t plane_offset)
{
	uint8_t *pixels;
	uint64_t required, row_offset;
	size_t host_bytes, row_bytes;
	int error;

	if (resource->backing == NULL ||
	    !virtio_gpu_2d_format_valid(format) || width == 0 || height == 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (__builtin_mul_overflow((size_t)width,
	    (size_t)GPU_BYTES_PER_PIXEL, &row_bytes))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (stride < row_bytes ||
	    height > (UINT64_MAX - plane_offset - row_bytes) / stride)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	required = plane_offset + (uint64_t)(height - 1) * stride + row_bytes;
	if (required > resource->blob_size ||
	    required > resource->backing_bytes ||
	    __builtin_mul_overflow((size_t)stride, (size_t)height,
	    &host_bytes))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (host_bytes > state->limits.max_host_bytes ||
	    resource->host_bytes > state->host_bytes ||
	    host_bytes > state->limits.max_host_bytes -
	    (state->host_bytes - resource->host_bytes))
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	pixels = calloc(1, host_bytes);
	if (pixels == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
	for (uint32_t row = 0; row < height; row++) {
		row_offset = plane_offset + (uint64_t)row * stride;
		error = gpu_backing_read(state, resource, row_offset,
		    pixels + (size_t)row * stride, row_bytes);
		if (error != 0) {
			free(pixels);
			return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
		}
	}
	state->host_bytes -= resource->host_bytes;
	free(resource->pixels);
	resource->pixels = pixels;
	resource->host_bytes = host_bytes;
	resource->format = format;
	resource->width = width;
	resource->height = height;
	resource->stride = stride;
	resource->blob_plane_offset = plane_offset;
	state->host_bytes += host_bytes;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_set_scanout_blob(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command)
{
	struct gpu_resource *resource;
	uint32_t response;

	if (command->scanout_id != 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_SCANOUT);
	if (command->resource_id == 0) {
		memset(&state->scanout, 0, sizeof(state->scanout));
		return (VIRTIO_GPU_2D_RESP_OK_NODATA);
	}
	/*
	 * A zero-sized rectangle is only the disabled scanout representation
	 * above.  Retaining a nonzero resource with a zero row width would make
	 * presentation ambiguous and, more importantly, is not a state that the
	 * portable snapshot format accepts.
	 */
	if (command->width == 0 || command->height == 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL || resource->kind != GPU_RESOURCE_BLOB)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (command->x > command->resource_width ||
	    command->y > command->resource_height ||
	    command->width > command->resource_width - command->x ||
	    command->height > command->resource_height - command->y ||
	    command->width > state->limits.scanout_width ||
	    command->height > state->limits.scanout_height)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	for (uint32_t i = 1; i < 4; i++) {
		if (command->strides[i] != 0 ||
		    command->plane_offsets[i] != 0)
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	}
	/*
	 * A blob has no intrinsic pixel layout.  If one resource is reused for
	 * both presentation roles, the two views must be identical; otherwise
	 * replacing the retained layout would silently reinterpret the live
	 * cursor.
	 */
	if (state->cursor_resource_id == command->resource_id &&
	    (command->format != VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM ||
	    command->resource_width != GPU_CURSOR_WIDTH ||
	    command->resource_height != GPU_CURSOR_HEIGHT ||
	    command->strides[0] !=
	    GPU_CURSOR_WIDTH * GPU_BYTES_PER_PIXEL ||
	    command->plane_offsets[0] != 0))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	response = gpu_import_blob_pixels(state, resource, command->format,
	    command->resource_width, command->resource_height,
	    command->strides[0], command->plane_offsets[0]);
	if (response != VIRTIO_GPU_2D_RESP_OK_NODATA)
		return (response);
	state->scanout.resource_id = command->resource_id;
	state->scanout.x = command->x;
	state->scanout.y = command->y;
	state->scanout.width = command->width;
	state->scanout.height = command->height;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_set_scanout(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command)
{
	struct gpu_resource *resource;

	if (command->scanout_id != 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_SCANOUT);
	if (command->resource_id == 0) {
		memset(&state->scanout, 0, sizeof(state->scanout));
		return (VIRTIO_GPU_2D_RESP_OK_NODATA);
	}
	if (command->width == 0 || command->height == 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	/*
	 * VirtIO 1.4 section 5.7.6.1 requires the guest to attach backing
	 * storage before linking a resource to a scanout.  Do not infer that
	 * later detach is illegal: the host copy remains a valid scanout until
	 * the guest replaces or unreferences it.
	 */
	if (resource->backing == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
	if (!gpu_rect_inside(command, resource))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (command->width > state->limits.scanout_width ||
	    command->height > state->limits.scanout_height)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	state->scanout.resource_id = command->resource_id;
	state->scanout.x = command->x;
	state->scanout.y = command->y;
	state->scanout.width = command->width;
	state->scanout.height = command->height;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_flush(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command, bool *notify_display,
    uint32_t *update_x, uint32_t *update_y, uint32_t *update_width,
    uint32_t *update_height)
{
	struct gpu_resource *resource;
	uint8_t *staging;
	size_t row_bytes, staging_bytes;
	uint32_t end_x, end_y, start_x, start_y;

	resource = gpu_find_resource(state, command->resource_id);
	if (resource == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
	if (!gpu_rect_inside(command, resource))
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	if (resource->kind == GPU_RESOURCE_BLOB) {
		if (__builtin_mul_overflow((size_t)command->width,
		    (size_t)GPU_BYTES_PER_PIXEL, &row_bytes) ||
		    __builtin_mul_overflow(row_bytes, (size_t)command->height,
		    &staging_bytes))
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		staging = malloc(staging_bytes);
		if (staging == NULL)
			return (VIRTIO_GPU_2D_RESP_ERR_OUT_OF_MEMORY);
		for (uint32_t row = 0; row < command->height; row++) {
			uint64_t source;

			source = resource->blob_plane_offset +
			    (uint64_t)(command->y + row) * resource->stride +
			    (size_t)command->x * GPU_BYTES_PER_PIXEL;
			if (gpu_backing_read(state, resource, source,
			    staging + (size_t)row * row_bytes, row_bytes) != 0) {
				free(staging);
				return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
			}
		}
		/* Publish only after every source row has been read successfully. */
		for (uint32_t row = 0; row < command->height; row++) {
			size_t destination;

			destination =
			    (size_t)(command->y + row) * resource->stride +
			    (size_t)command->x * GPU_BYTES_PER_PIXEL;
			memcpy(resource->pixels + destination,
			    staging + (size_t)row * row_bytes, row_bytes);
		}
		free(staging);
	}
	if (state->scanout.resource_id != command->resource_id)
		return (VIRTIO_GPU_2D_RESP_OK_NODATA);
	start_x = command->x > state->scanout.x ?
	    command->x : state->scanout.x;
	start_y = command->y > state->scanout.y ?
	    command->y : state->scanout.y;
	end_x = command->x + command->width;
	if (end_x > state->scanout.x + state->scanout.width)
		end_x = state->scanout.x + state->scanout.width;
	end_y = command->y + command->height;
	if (end_y > state->scanout.y + state->scanout.height)
		end_y = state->scanout.y + state->scanout.height;
	if (start_x >= end_x || start_y >= end_y)
		return (VIRTIO_GPU_2D_RESP_OK_NODATA);
	*update_x = start_x - state->scanout.x;
	*update_y = start_y - state->scanout.y;
	*update_width = end_x - start_x;
	*update_height = end_y - start_y;
	*notify_display = true;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

static uint32_t
gpu_cursor(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command, bool *notify_cursor)
{
	struct gpu_resource *resource;

	if (command->scanout_id != 0)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_SCANOUT);
	if (command->type == VIRTIO_GPU_2D_UPDATE_CURSOR) {
		if (command->resource_id == 0) {
			state->cursor_resource_id = 0;
			state->cursor_hot_x = 0;
			state->cursor_hot_y = 0;
			goto moved;
		}
		resource = gpu_find_resource(state, command->resource_id);
		if (resource == NULL)
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_RESOURCE);
		if (command->hot_x >= GPU_CURSOR_WIDTH ||
		    command->hot_y >= GPU_CURSOR_HEIGHT)
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		if (resource->kind == GPU_RESOURCE_BLOB) {
			uint32_t response;

			if (state->scanout.resource_id == command->resource_id &&
			    (resource->format !=
			    VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM ||
			    resource->width != GPU_CURSOR_WIDTH ||
			    resource->height != GPU_CURSOR_HEIGHT ||
			    resource->stride !=
			    GPU_CURSOR_WIDTH * GPU_BYTES_PER_PIXEL ||
			    resource->blob_plane_offset != 0))
				return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
			response = gpu_import_blob_pixels(state, resource,
			    VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM,
			    GPU_CURSOR_WIDTH, GPU_CURSOR_HEIGHT,
			    GPU_CURSOR_WIDTH * GPU_BYTES_PER_PIXEL, 0);
			if (response != VIRTIO_GPU_2D_RESP_OK_NODATA)
				return (response);
		}
		if (resource->width != GPU_CURSOR_WIDTH ||
		    resource->height != GPU_CURSOR_HEIGHT)
			return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
		state->cursor_resource_id = command->resource_id;
		state->cursor_hot_x = command->hot_x;
		state->cursor_hot_y = command->hot_y;
	}
moved:
	state->cursor_x = command->x;
	state->cursor_y = command->y;
	*notify_cursor = true;
	return (VIRTIO_GPU_2D_RESP_OK_NODATA);
}

int
virtio_gpu_2d_state_create(const struct virtio_gpu_2d_limits *limits,
    const struct virtio_gpu_2d_ops *ops, struct virtio_gpu_2d_state **result)
{
	struct virtio_gpu_2d_state *state;
	size_t resource_array_size;
	int error;

	if (limits == NULL || ops == NULL || ops->dma_validate == NULL ||
	    ops->dma_read == NULL ||
	    result == NULL || limits->max_resources == 0 ||
	    limits->max_host_bytes == 0 || limits->scanout_width == 0 ||
	    limits->scanout_height == 0)
		return (EINVAL);
	if ((limits->max_blob_bytes != 0 || limits->blob_alignment != 0) &&
	    (limits->max_blob_bytes == 0 ||
	    limits->blob_alignment == 0 ||
	    (limits->blob_alignment & (limits->blob_alignment - 1)) != 0))
		return (EINVAL);
	error = gpu_resource_array_size(limits->max_resources,
	    &resource_array_size);
	if (error != 0)
		return (error);
	state = calloc(1, sizeof(*state));
	if (state == NULL)
		return (ENOMEM);
	state->resources = calloc(1, resource_array_size);
	if (state->resources == NULL) {
		free(state);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&state->mutex, NULL);
	if (error != 0) {
		free(state->resources);
		free(state);
		return (error);
	}
	error = pthread_cond_init(&state->callback_drain, NULL);
	if (error != 0) {
		(void)pthread_mutex_destroy(&state->mutex);
		free(state->resources);
		free(state);
		return (error);
	}
	state->limits = *limits;
	state->ops = *ops;
	*result = state;
	return (0);
}

void
virtio_gpu_2d_state_reset(struct virtio_gpu_2d_state *state)
{
	void (*display_reset)(void *);
	void *arg;

	if (state == NULL)
		return;
	pthread_mutex_lock(&state->mutex);
	if (state->destroying) {
		pthread_mutex_unlock(&state->mutex);
		return;
	}
	gpu_state_clear_locked(state);
	display_reset = state->ops.display_reset;
	arg = state->ops.arg;
	if (display_reset != NULL)
		state->callbacks++;
	pthread_mutex_unlock(&state->mutex);
	if (display_reset != NULL) {
		display_reset(arg);
		gpu_state_callback_done(state);
	}
}

void
virtio_gpu_2d_state_destroy(struct virtio_gpu_2d_state *state)
{
	void (*display_reset)(void *);
	void *arg;

	if (state == NULL)
		return;
	pthread_mutex_lock(&state->mutex);
	if (state->destroying) {
		pthread_mutex_unlock(&state->mutex);
		return;
	}
	state->destroying = true;
	gpu_state_clear_locked(state);
	display_reset = state->ops.display_reset;
	arg = state->ops.arg;
	if (display_reset != NULL)
		state->callbacks++;
	pthread_mutex_unlock(&state->mutex);
	if (display_reset != NULL) {
		display_reset(arg);
		gpu_state_callback_done(state);
	}
	pthread_mutex_lock(&state->mutex);
	while (state->callbacks != 0)
		(void)pthread_cond_wait(&state->callback_drain, &state->mutex);
	pthread_mutex_unlock(&state->mutex);
	(void)pthread_cond_destroy(&state->callback_drain);
	(void)pthread_mutex_destroy(&state->mutex);
	free(state->resources);
	free(state);
}

uint32_t
virtio_gpu_2d_state_execute(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_command *command, const void *request,
    size_t request_len)
{
	void (*cursor_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void (*display_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void (*scanout_update)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint32_t);
	void *callback_arg;
	bool notify_cursor, notify_display, notify_scanout;
	uint32_t callback_cursor_resource, callback_cursor_x;
	uint32_t callback_cursor_y, callback_hot_x, callback_hot_y;
	uint32_t callback_scanout_resource, callback_scanout_x;
	uint32_t callback_scanout_y, callback_scanout_width;
	uint32_t callback_scanout_height;
	uint32_t response, update_height, update_width, update_x, update_y;

	if (state == NULL || command == NULL)
		return (VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER);
	notify_cursor = false;
	notify_display = false;
	notify_scanout = false;
	callback_cursor_resource = 0;
	callback_cursor_x = 0;
	callback_cursor_y = 0;
	callback_hot_x = 0;
	callback_hot_y = 0;
	callback_scanout_resource = 0;
	callback_scanout_x = 0;
	callback_scanout_y = 0;
	callback_scanout_width = 0;
	callback_scanout_height = 0;
	update_x = 0;
	update_y = 0;
	update_width = 0;
	update_height = 0;
	pthread_mutex_lock(&state->mutex);
	if (state->destroying) {
		pthread_mutex_unlock(&state->mutex);
		return (VIRTIO_GPU_2D_RESP_ERR_UNSPEC);
	}
	switch (command->type) {
	case VIRTIO_GPU_2D_GET_DISPLAY_INFO:
		response = VIRTIO_GPU_2D_RESP_OK_DISPLAY_INFO;
		break;
	case VIRTIO_GPU_2D_GET_EDID:
		response = VIRTIO_GPU_2D_RESP_OK_EDID;
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE:
		response = gpu_create_resource(state, command);
		break;
	case VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB:
		response = gpu_create_blob(state, command, request, request_len);
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNREF:
		notify_scanout =
		    state->scanout.resource_id == command->resource_id;
		notify_cursor =
		    state->cursor_resource_id == command->resource_id;
		response = gpu_unref_resource(state, command->resource_id);
		if (response != VIRTIO_GPU_2D_RESP_OK_NODATA) {
			notify_scanout = false;
			notify_cursor = false;
		}
		break;
	case VIRTIO_GPU_2D_RESOURCE_ATTACH_BACKING:
		response = gpu_attach_backing(state, command, request,
		    request_len);
		break;
	case VIRTIO_GPU_2D_RESOURCE_DETACH_BACKING:
		response = gpu_detach_backing(state, command->resource_id);
		break;
	case VIRTIO_GPU_2D_RESOURCE_MAP_BLOB:
		response = gpu_map_blob(state, command);
		break;
	case VIRTIO_GPU_2D_RESOURCE_UNMAP_BLOB:
		response = gpu_unmap_blob(state, command->resource_id);
		break;
	case VIRTIO_GPU_2D_TRANSFER_TO_HOST:
		response = gpu_transfer(state, command);
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT:
		response = gpu_set_scanout(state, command);
		if (response == VIRTIO_GPU_2D_RESP_OK_NODATA)
			notify_scanout = true;
		break;
	case VIRTIO_GPU_2D_SET_SCANOUT_BLOB:
		response = gpu_set_scanout_blob(state, command);
		if (response == VIRTIO_GPU_2D_RESP_OK_NODATA)
			notify_scanout = true;
		break;
	case VIRTIO_GPU_2D_RESOURCE_FLUSH:
		response = gpu_flush(state, command, &notify_display, &update_x,
		    &update_y, &update_width, &update_height);
		break;
	case VIRTIO_GPU_2D_UPDATE_CURSOR:
	case VIRTIO_GPU_2D_MOVE_CURSOR:
		response = gpu_cursor(state, command, &notify_cursor);
		break;
	default:
		response = VIRTIO_GPU_2D_RESP_ERR_UNSPEC;
		break;
	}
	if (notify_cursor) {
		callback_cursor_resource = state->cursor_resource_id;
		callback_cursor_x = state->cursor_x;
		callback_cursor_y = state->cursor_y;
		callback_hot_x = state->cursor_hot_x;
		callback_hot_y = state->cursor_hot_y;
	}
	if (notify_scanout) {
		callback_scanout_resource = state->scanout.resource_id;
		callback_scanout_x = state->scanout.x;
		callback_scanout_y = state->scanout.y;
		callback_scanout_width = state->scanout.width;
		callback_scanout_height = state->scanout.height;
	}
	cursor_update = state->ops.cursor_update;
	display_update = state->ops.display_update;
	scanout_update = state->ops.scanout_update;
	callback_arg = state->ops.arg;
	if (response == VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    ((notify_scanout && scanout_update != NULL) ||
	    (notify_display && display_update != NULL) ||
	    (notify_cursor && cursor_update != NULL)))
		state->callbacks++;
	pthread_mutex_unlock(&state->mutex);
	if (response == VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    notify_scanout && scanout_update != NULL)
		scanout_update(callback_arg, 0,
		    callback_scanout_resource, callback_scanout_x,
		    callback_scanout_y, callback_scanout_width,
		    callback_scanout_height);
	if (response == VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    notify_display && display_update != NULL)
		display_update(callback_arg, 0,
		    command->resource_id, update_x, update_y,
		    update_width, update_height);
	if (response == VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    notify_cursor && cursor_update != NULL)
		cursor_update(callback_arg, 0,
		    callback_cursor_resource, callback_cursor_x,
		    callback_cursor_y,
		    callback_hot_x, callback_hot_y);
	if (response == VIRTIO_GPU_2D_RESP_OK_NODATA &&
	    ((notify_scanout && scanout_update != NULL) ||
	    (notify_display && display_update != NULL) ||
	    (notify_cursor && cursor_update != NULL)))
		gpu_state_callback_done(state);
	return (response);
}

int
virtio_gpu_2d_state_read_resource(struct virtio_gpu_2d_state *state,
    uint32_t resource_id, size_t offset, void *output, size_t length)
{
	struct gpu_resource *resource;
	int error;

	if (state == NULL || output == NULL)
		return (EINVAL);
	pthread_mutex_lock(&state->mutex);
	if (gpu_state_overlaps_locked(state, output, length))
		error = EINVAL;
	else if ((resource = gpu_find_resource(state, resource_id)) == NULL)
		error = ENOENT;
	else if (offset > resource->host_bytes ||
	    length > resource->host_bytes - offset)
		error = ERANGE;
	else {
		memcpy(output, resource->pixels + offset, length);
		error = 0;
	}
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

int
virtio_gpu_2d_state_scanout(struct virtio_gpu_2d_state *state,
    uint32_t *resource_id, uint32_t *x, uint32_t *y, uint32_t *width,
    uint32_t *height)
{

	if (state == NULL || resource_id == NULL || x == NULL || y == NULL ||
	    width == NULL || height == NULL)
		return (EINVAL);
	pthread_mutex_lock(&state->mutex);
	if (gpu_state_overlaps_locked(state, resource_id,
	    sizeof(*resource_id)) ||
	    gpu_state_overlaps_locked(state, x, sizeof(*x)) ||
	    gpu_state_overlaps_locked(state, y, sizeof(*y)) ||
	    gpu_state_overlaps_locked(state, width, sizeof(*width)) ||
	    gpu_state_overlaps_locked(state, height, sizeof(*height))) {
		pthread_mutex_unlock(&state->mutex);
		return (EINVAL);
	}
	*resource_id = state->scanout.resource_id;
	*x = state->scanout.x;
	*y = state->scanout.y;
	*width = state->scanout.width;
	*height = state->scanout.height;
	pthread_mutex_unlock(&state->mutex);
	return (0);
}

int
virtio_gpu_2d_state_copy_scanout(struct virtio_gpu_2d_state *state,
    uint32_t x, uint32_t y, uint32_t width, uint32_t height, void *output,
    size_t output_len, uint32_t *format)
{
	struct gpu_resource *resource;
	uint8_t *destination;
	size_t row_bytes, required;
	int error;

	if (state == NULL || output == NULL || format == NULL || width == 0 ||
	    height == 0)
		return (EINVAL);
	row_bytes = (size_t)width * GPU_BYTES_PER_PIXEL;
	if (row_bytes / GPU_BYTES_PER_PIXEL != width)
		return (EOVERFLOW);
	if (height > SIZE_MAX / row_bytes)
		return (EOVERFLOW);
	required = row_bytes * height;
	if (output_len != required)
		return (EMSGSIZE);

	pthread_mutex_lock(&state->mutex);
	if (gpu_state_overlaps_locked(state, output, required) ||
	    gpu_state_overlaps_locked(state, format, sizeof(*format)))
		error = EINVAL;
	else if ((resource = gpu_find_resource(state,
	    state->scanout.resource_id)) == NULL ||
	    state->scanout.resource_id == 0)
		error = ENOENT;
	else if (x > state->scanout.width ||
	    width > state->scanout.width - x ||
	    y > state->scanout.height ||
	    height > state->scanout.height - y)
		error = ERANGE;
	else {
		destination = output;
		for (uint32_t row = 0; row < height; row++) {
			memcpy(destination + (size_t)row * row_bytes,
			    resource->pixels +
			    (size_t)(state->scanout.y + y + row) *
			    resource->stride +
			    (size_t)(state->scanout.x + x) *
			    GPU_BYTES_PER_PIXEL, row_bytes);
		}
		*format = resource->format;
		error = 0;
	}
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

int
virtio_gpu_2d_state_capture_scanout(struct virtio_gpu_2d_state *state,
    void *output, size_t output_len, uint32_t *width, uint32_t *height,
    uint32_t *format, size_t *copied)
{
	struct gpu_resource *resource;
	uint8_t *destination;
	size_t required, row_bytes;
	int error;

	if (state == NULL || output == NULL || width == NULL || height == NULL ||
	    format == NULL || copied == NULL)
		return (EINVAL);

	pthread_mutex_lock(&state->mutex);
	if (gpu_state_overlaps_locked(state, output, output_len) ||
	    gpu_state_overlaps_locked(state, width, sizeof(*width)) ||
	    gpu_state_overlaps_locked(state, height, sizeof(*height)) ||
	    gpu_state_overlaps_locked(state, format, sizeof(*format)) ||
	    gpu_state_overlaps_locked(state, copied, sizeof(*copied))) {
		error = EINVAL;
		goto out;
	}
	if (state->scanout.resource_id == 0) {
		*width = 0;
		*height = 0;
		*format = 0;
		*copied = 0;
		error = 0;
		goto out;
	}
	resource = gpu_find_resource(state, state->scanout.resource_id);
	if (resource == NULL) {
		error = ENOENT;
		goto out;
	}
	/* Defensive validation for state imported from a future/older producer. */
	if (state->scanout.width == 0 || state->scanout.height == 0) {
		error = EINVAL;
		goto out;
	}
	row_bytes = (size_t)state->scanout.width * GPU_BYTES_PER_PIXEL;
	if (row_bytes / GPU_BYTES_PER_PIXEL != state->scanout.width ||
	    state->scanout.height > SIZE_MAX / row_bytes) {
		error = EOVERFLOW;
		goto out;
	}
	required = row_bytes * state->scanout.height;
	if (required > output_len) {
		error = EMSGSIZE;
		goto out;
	}
	destination = output;
	for (uint32_t row = 0; row < state->scanout.height; row++) {
		memcpy(destination + (size_t)row * row_bytes,
		    resource->pixels +
		    (size_t)(state->scanout.y + row) * resource->stride +
		    (size_t)state->scanout.x * GPU_BYTES_PER_PIXEL, row_bytes);
	}
	*width = state->scanout.width;
	*height = state->scanout.height;
	*format = resource->format;
	*copied = required;
	error = 0;
out:
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

int
virtio_gpu_2d_state_copy_cursor(struct virtio_gpu_2d_state *state,
    void *output, size_t output_len, uint32_t *format, uint32_t *x,
    uint32_t *y, uint32_t *hot_x, uint32_t *hot_y)
{
	struct gpu_resource *resource;
	int error;

	if (state == NULL || output == NULL || format == NULL || x == NULL ||
	    y == NULL || hot_x == NULL || hot_y == NULL)
		return (EINVAL);
	if (output_len != VIRTIO_GPU_2D_CURSOR_BYTES)
		return (EMSGSIZE);

	pthread_mutex_lock(&state->mutex);
	if (gpu_state_overlaps_locked(state, output, output_len) ||
	    gpu_state_overlaps_locked(state, format, sizeof(*format)) ||
	    gpu_state_overlaps_locked(state, x, sizeof(*x)) ||
	    gpu_state_overlaps_locked(state, y, sizeof(*y)) ||
	    gpu_state_overlaps_locked(state, hot_x, sizeof(*hot_x)) ||
	    gpu_state_overlaps_locked(state, hot_y, sizeof(*hot_y)))
		error = EINVAL;
	else if ((resource = gpu_find_resource(state,
	    state->cursor_resource_id)) == NULL ||
	    state->cursor_resource_id == 0)
		error = ENOENT;
	else if (resource->pixels == NULL ||
	    resource->host_bytes != VIRTIO_GPU_2D_CURSOR_BYTES ||
	    resource->width != GPU_CURSOR_WIDTH ||
	    resource->height != GPU_CURSOR_HEIGHT ||
	    resource->stride != GPU_CURSOR_WIDTH * GPU_BYTES_PER_PIXEL)
		error = EPROTO;
	else {
		memcpy(output, resource->pixels, VIRTIO_GPU_2D_CURSOR_BYTES);
		*format = resource->format;
		*x = state->cursor_x;
		*y = state->cursor_y;
		*hot_x = state->cursor_hot_x;
		*hot_y = state->cursor_hot_y;
		error = 0;
	}
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

uint32_t
virtio_gpu_2d_state_resource_count(struct virtio_gpu_2d_state *state)
{
	uint32_t count;

	if (state == NULL)
		return (0);
	pthread_mutex_lock(&state->mutex);
	count = state->resource_count;
	pthread_mutex_unlock(&state->mutex);
	return (count);
}

uint64_t
virtio_gpu_2d_state_host_bytes(struct virtio_gpu_2d_state *state)
{
	uint64_t bytes;

	if (state == NULL)
		return (0);
	pthread_mutex_lock(&state->mutex);
	bytes = state->host_bytes;
	pthread_mutex_unlock(&state->mutex);
	return (bytes);
}

uint64_t
virtio_gpu_2d_state_blob_bytes(struct virtio_gpu_2d_state *state)
{
	uint64_t bytes;

	if (state == NULL)
		return (0);
	pthread_mutex_lock(&state->mutex);
	bytes = state->blob_bytes;
	pthread_mutex_unlock(&state->mutex);
	return (bytes);
}

static int
gpu_snapshot_size_locked(struct virtio_gpu_2d_state *state, size_t *result)
{
	size_t length, resource_length;

	length = GPU_STATE_HEADER_SIZE;
	for (uint32_t i = 0; i < state->limits.max_resources; i++) {
		if (state->resources[i].id == 0)
			continue;
		if (state->resources[i].backing_count >
		    (SIZE_MAX - GPU_STATE_RESOURCE_SIZE -
		    state->resources[i].host_bytes) / GPU_STATE_BACKING_SIZE)
			return (EOVERFLOW);
		resource_length = GPU_STATE_RESOURCE_SIZE +
		    state->resources[i].host_bytes +
		    (size_t)state->resources[i].backing_count *
		    GPU_STATE_BACKING_SIZE;
		if (length > SIZE_MAX - resource_length)
			return (EOVERFLOW);
		length += resource_length;
	}
	*result = length;
	return (0);
}

static bool
gpu_state_overlaps_locked(struct virtio_gpu_2d_state *state,
    const void *buffer, size_t length)
{
	struct gpu_resource *resource;

	if (virtio_state_ranges_overlap(buffer, length, state, sizeof(*state)) ||
	    virtio_state_ranges_overlap(buffer, length, state->resources,
	    (size_t)state->limits.max_resources * sizeof(*state->resources)))
		return (true);
	for (uint32_t i = 0; i < state->limits.max_resources; i++) {
		resource = &state->resources[i];
		if (resource->id == 0)
			continue;
		if (virtio_state_ranges_overlap(buffer, length, resource->pixels,
		    resource->host_bytes) ||
		    virtio_state_ranges_overlap(buffer, length, resource->backing,
		    (size_t)resource->backing_count *
		    sizeof(*resource->backing)))
			return (true);
	}
	return (false);
}

bool
virtio_gpu_2d_state_storage_overlaps(struct virtio_gpu_2d_state *state,
    const void *storage, size_t length)
{
	bool overlaps;

	if (state == NULL || length == 0)
		return (false);
	pthread_mutex_lock(&state->mutex);
	overlaps = gpu_state_overlaps_locked(state, storage, length);
	pthread_mutex_unlock(&state->mutex);
	return (overlaps);
}

int
virtio_gpu_2d_state_snapshot_size(struct virtio_gpu_2d_state *state,
    size_t *result)
{
	int error;

	if (state == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&state->mutex);
	error = gpu_snapshot_size_locked(state, result);
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

int
virtio_gpu_2d_state_snapshot_limit(struct virtio_gpu_2d_state *state,
    size_t *result)
{
	uint64_t fixed, maximum;

	if (state == NULL || result == NULL)
		return (EINVAL);
	fixed = GPU_STATE_RESOURCE_SIZE +
	    (uint64_t)BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES *
	    GPU_STATE_BACKING_SIZE;
	pthread_mutex_lock(&state->mutex);
	if (state->limits.max_resources >
	    (UINT64_MAX - GPU_STATE_HEADER_SIZE -
	    state->limits.max_host_bytes) / fixed) {
		pthread_mutex_unlock(&state->mutex);
		return (EOVERFLOW);
	}
	maximum = GPU_STATE_HEADER_SIZE + state->limits.max_host_bytes +
	    (uint64_t)state->limits.max_resources * fixed;
	pthread_mutex_unlock(&state->mutex);
	if (maximum > SIZE_MAX)
		return (EOVERFLOW);
	*result = (size_t)maximum;
	return (0);
}

int
virtio_gpu_2d_state_snapshot_save(struct virtio_gpu_2d_state *state,
    void *buffer, size_t length)
{
	struct gpu_resource *resource;
	uint8_t *bytes;
	size_t expected, offset;
	int error;

	if (state == NULL || buffer == NULL)
		return (EINVAL);
	pthread_mutex_lock(&state->mutex);
	error = gpu_snapshot_size_locked(state, &expected);
	if (error != 0 || length != expected) {
		pthread_mutex_unlock(&state->mutex);
		return (error != 0 ? error : EMSGSIZE);
	}
	if (gpu_state_overlaps_locked(state, buffer, length)) {
		pthread_mutex_unlock(&state->mutex);
		return (EINVAL);
	}
	bytes = buffer;
	memset(bytes, 0, length);
	le32enc(bytes, GPU_STATE_MAGIC);
	le16enc(bytes + 4, GPU_STATE_VERSION);
	le16enc(bytes + 6, GPU_STATE_HEADER_SIZE);
	le32enc(bytes + 8, state->resource_count);
	le64enc(bytes + 16, state->host_bytes);
	le32enc(bytes + 24, state->scanout.resource_id);
	le32enc(bytes + 28, state->scanout.x);
	le32enc(bytes + 32, state->scanout.y);
	le32enc(bytes + 36, state->scanout.width);
	le32enc(bytes + 40, state->scanout.height);
	le32enc(bytes + 44, state->cursor_resource_id);
	le32enc(bytes + 48, state->cursor_x);
	le32enc(bytes + 52, state->cursor_y);
	le32enc(bytes + 56, state->cursor_hot_x);
	le32enc(bytes + 60, state->cursor_hot_y);
	le64enc(bytes + 64, state->blob_bytes);
	offset = GPU_STATE_HEADER_SIZE;
	for (uint32_t i = 0; i < state->limits.max_resources; i++) {
		resource = &state->resources[i];
		if (resource->id == 0)
			continue;
		le32enc(bytes + offset, resource->id);
		le32enc(bytes + offset + 4, resource->kind);
		le32enc(bytes + offset + 8, resource->format);
		le32enc(bytes + offset + 12, resource->width);
		le32enc(bytes + offset + 16, resource->height);
		le32enc(bytes + offset + 20, resource->stride);
		le32enc(bytes + offset + 24, resource->backing_count);
		le32enc(bytes + offset + 28, resource->blob_plane_offset);
		le64enc(bytes + offset + 32, resource->host_bytes);
		le64enc(bytes + offset + 40, resource->backing_bytes);
		le32enc(bytes + offset + 48, resource->blob_memory);
		le32enc(bytes + offset + 52, resource->blob_flags);
		le64enc(bytes + offset + 56, resource->blob_id);
		le64enc(bytes + offset + 64, resource->blob_size);
		offset += GPU_STATE_RESOURCE_SIZE;
		if (resource->host_bytes != 0)
			memcpy(bytes + offset, resource->pixels,
			    resource->host_bytes);
		offset += resource->host_bytes;
		for (uint32_t j = 0; j < resource->backing_count; j++) {
			le64enc(bytes + offset, resource->backing[j].address);
			le32enc(bytes + offset + 8,
			    resource->backing[j].length);
			offset += GPU_STATE_BACKING_SIZE;
		}
	}
	pthread_mutex_unlock(&state->mutex);
	return (0);
}

static void
gpu_resource_array_free(struct gpu_resource *resources, uint32_t count)
{

	if (resources == NULL)
		return;
	for (uint32_t i = 0; i < count; i++)
		gpu_resource_clear(&resources[i]);
	free(resources);
}

static struct gpu_resource *
gpu_find_in_array(struct gpu_resource *resources, uint32_t count, uint32_t id)
{

	for (uint32_t i = 0; i < count; i++) {
		if (resources[i].id == id)
			return (&resources[i]);
	}
	return (NULL);
}

static int
gpu_snapshot_decode(struct virtio_gpu_2d_state *state, const void *buffer,
    size_t length, bool publish)
{
	const uint8_t *bytes;
	struct gpu_resource *resource, *resources;
	struct gpu_scanout scanout;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	uint64_t backing_bytes, blob_bytes, host_bytes, total_backing, total_blob;
	uint64_t total_host;
	uint64_t address, calculated_bytes, required, row_bytes, stride;
	uint32_t backing_count, count, cursor_hot_x, cursor_hot_y;
	uint32_t cursor_resource, cursor_x, cursor_y;
	uint16_t version;
	size_t offset, resource_size;
	int error;

	if (state == NULL || buffer == NULL || length < GPU_STATE_HEADER_SIZE)
		return (EINVAL);
	resources = NULL;
	pthread_mutex_lock(&state->mutex);
	if (state->destroying) {
		pthread_mutex_unlock(&state->mutex);
		return (ECANCELED);
	}
	error = gpu_state_overlaps_locked(state, buffer, length) ? EINVAL : 0;
	limits = state->limits;
	ops = state->ops;
	/* DMA preflight and presentation reconstruction run after unlock. */
	state->callbacks++;
	pthread_mutex_unlock(&state->mutex);
	if (error != 0)
		goto fail;
	bytes = buffer;
	version = le16dec(bytes + 4);
	if (le32dec(bytes) != GPU_STATE_MAGIC ||
	    version != GPU_STATE_VERSION ||
	    le16dec(bytes + 6) != GPU_STATE_HEADER_SIZE) {
		error = EPROTO;
		goto fail;
	}
	for (size_t i = 12; i < 16; i++) {
		if (bytes[i] != 0) {
			error = EPROTO;
			goto fail;
		}
	}
	blob_bytes = le64dec(bytes + 64);
	resource_size = GPU_STATE_RESOURCE_SIZE;
	count = le32dec(bytes + 8);
	host_bytes = le64dec(bytes + 16);
	if (count > limits.max_resources ||
	    host_bytes > limits.max_host_bytes ||
	    blob_bytes > limits.max_blob_bytes) {
		error = E2BIG;
		goto fail;
	}
	resources = calloc(limits.max_resources, sizeof(*resources));
	if (resources == NULL) {
		error = ENOMEM;
		goto fail;
	}
	offset = GPU_STATE_HEADER_SIZE;
	total_host = 0;
	total_blob = 0;
	error = EPROTO;
	for (uint32_t i = 0; i < count; i++) {
		if (offset > length ||
		    resource_size > length - offset)
			goto fail;
		resource = &resources[i];
		resource->id = le32dec(bytes + offset);
		resource->kind = le32dec(bytes + offset + 4);
		resource->format = le32dec(bytes + offset + 8);
		resource->width = le32dec(bytes + offset + 12);
		resource->height = le32dec(bytes + offset + 16);
		resource->stride = le32dec(bytes + offset + 20);
		backing_count = le32dec(bytes + offset + 24);
		resource->blob_plane_offset = le32dec(bytes + offset + 28);
		calculated_bytes = le64dec(bytes + offset + 32);
		backing_bytes = le64dec(bytes + offset + 40);
		resource->blob_memory = le32dec(bytes + offset + 48);
		resource->blob_flags = le32dec(bytes + offset + 52);
		resource->blob_id = le64dec(bytes + offset + 56);
		resource->blob_size = le64dec(bytes + offset + 64);
		if (resource->id == 0 ||
		    gpu_find_in_array(resources, i, resource->id) != NULL ||
		    backing_count > BHYVE_VIRTIO_GPU_MAX_BACKING_ENTRIES)
			goto fail;
		if (resource->kind == GPU_RESOURCE_2D) {
			if (resource->width == 0 || resource->height == 0 ||
			    !virtio_gpu_2d_format_valid(resource->format))
				goto fail;
			stride = (uint64_t)resource->width * GPU_BYTES_PER_PIXEL;
			if (stride > UINT32_MAX ||
			    resource->height > UINT64_MAX / stride ||
			    resource->stride != stride ||
			    calculated_bytes != stride * resource->height ||
			    calculated_bytes > SIZE_MAX ||
			    calculated_bytes >
			    limits.max_host_bytes - total_host ||
			    resource->blob_memory != 0 ||
			    resource->blob_flags != 0 ||
			    resource->blob_id != 0 ||
			    resource->blob_size != 0 ||
			    resource->blob_plane_offset != 0)
				goto fail;
		} else if (resource->kind == GPU_RESOURCE_BLOB) {
			if (
			    limits.max_blob_bytes == 0 ||
			    limits.blob_alignment == 0 ||
			    resource->blob_memory !=
			    VIRTIO_GPU_2D_BLOB_MEM_GUEST ||
			    (resource->blob_flags &
			    ~VIRTIO_GPU_2D_BLOB_FLAGS_MASK) != 0 ||
			    (resource->blob_flags &
			    VIRTIO_GPU_2D_BLOB_FLAG_USE_CROSS_DEVICE) != 0 ||
			    (resource->blob_flags &
			    VIRTIO_GPU_2D_BLOB_FLAG_USE_MAPPABLE) != 0 ||
			    resource->blob_size == 0 ||
			    resource->blob_size %
			    limits.blob_alignment != 0 ||
			    resource->blob_size >
			    limits.max_blob_bytes - total_blob ||
			    (backing_count == 0 && backing_bytes != 0))
				goto fail;
			if (calculated_bytes == 0) {
				if (resource->format != 0 ||
				    resource->width != 0 ||
				    resource->height != 0 ||
				    resource->stride != 0 ||
				    resource->blob_plane_offset != 0)
					goto fail;
			} else {
				row_bytes = (uint64_t)resource->width *
				    GPU_BYTES_PER_PIXEL;
				if (resource->width == 0 ||
				    resource->height == 0 ||
				    !virtio_gpu_2d_format_valid(
				    resource->format) ||
				    resource->stride < row_bytes ||
				    resource->height >
				    UINT64_MAX / resource->stride ||
				    calculated_bytes !=
				    (uint64_t)resource->stride *
				    resource->height ||
				    resource->blob_plane_offset >
				    resource->blob_size ||
				    calculated_bytes >
				    limits.max_host_bytes - total_host)
					goto fail;
				if (row_bytes >
				    resource->blob_size -
				    resource->blob_plane_offset)
					goto fail;
				if (__builtin_mul_overflow(
				    (uint64_t)(resource->height - 1),
				    (uint64_t)resource->stride, &required) ||
				    __builtin_add_overflow(required, row_bytes,
				    &required) ||
				    required > resource->blob_size ||
				    resource->blob_plane_offset >
				    resource->blob_size - required ||
				    required > backing_bytes ||
				    resource->blob_plane_offset >
				    backing_bytes - required)
					goto fail;
			}
		} else
			goto fail;
		resource->host_bytes = (size_t)calculated_bytes;
		resource->backing_count = backing_count;
		resource->backing_bytes = backing_bytes;
		offset += resource_size;
		if (offset > length || resource->host_bytes > length - offset)
			goto fail;
		if (resource->host_bytes != 0) {
			resource->pixels = malloc(resource->host_bytes);
			if (resource->pixels == NULL) {
				error = ENOMEM;
				goto fail;
			}
			memcpy(resource->pixels, bytes + offset,
			    resource->host_bytes);
		}
		offset += resource->host_bytes;
		if (backing_count != 0) {
			if (backing_count > (length - offset) /
			    GPU_STATE_BACKING_SIZE)
				goto fail;
			resource->backing = calloc(backing_count,
			    sizeof(*resource->backing));
			if (resource->backing == NULL) {
				error = ENOMEM;
				goto fail;
			}
		}
		total_backing = 0;
		for (uint32_t j = 0; j < backing_count; j++) {
			address = le64dec(bytes + offset);
			resource->backing[j].length =
			    le32dec(bytes + offset + 8);
			for (size_t k = 12; k < GPU_STATE_BACKING_SIZE; k++) {
				if (bytes[offset + k] != 0)
					goto fail;
			}
			if (resource->backing[j].length == 0 ||
			    address > UINT64_MAX -
			    resource->backing[j].length ||
			    total_backing > UINT64_MAX -
			    resource->backing[j].length)
				goto fail;
			resource->backing[j].address = address;
			error = ops.dma_validate(ops.arg, address,
			    resource->backing[j].length,
			    VIRTIO_GPU_2D_DMA_DEVICE_READ);
			if (error != 0)
				goto fail;
			/*
			 * A successful destination-DMA preflight must not
			 * suppress a structural error found later in the
			 * portable record.
			 */
			error = EPROTO;
			total_backing += resource->backing[j].length;
			offset += GPU_STATE_BACKING_SIZE;
		}
		if (total_backing != backing_bytes ||
		    (resource->kind == GPU_RESOURCE_BLOB &&
		    backing_count != 0 &&
		    total_backing < resource->blob_size))
			goto fail;
		if (resource->host_bytes != 0)
			total_host += calculated_bytes;
		if (resource->kind == GPU_RESOURCE_BLOB)
			total_blob += resource->blob_size;
	}
	if (offset != length || total_host != host_bytes ||
	    total_blob != blob_bytes)
		goto fail;
	scanout = (struct gpu_scanout) {
		.resource_id = le32dec(bytes + 24),
		.x = le32dec(bytes + 28),
		.y = le32dec(bytes + 32),
		.width = le32dec(bytes + 36),
		.height = le32dec(bytes + 40),
	};
	cursor_resource = le32dec(bytes + 44);
	cursor_x = le32dec(bytes + 48);
	cursor_y = le32dec(bytes + 52);
	cursor_hot_x = le32dec(bytes + 56);
	cursor_hot_y = le32dec(bytes + 60);
	if (scanout.resource_id != 0) {
		resource = gpu_find_in_array(resources, count,
		    scanout.resource_id);
		if (resource == NULL ||
		    (resource->kind != GPU_RESOURCE_2D &&
		    resource->kind != GPU_RESOURCE_BLOB) ||
		    resource->host_bytes == 0 ||
		    scanout.width == 0 || scanout.height == 0 ||
		    scanout.width > limits.scanout_width ||
		    scanout.height > limits.scanout_height ||
		    scanout.x > resource->width ||
		    scanout.width > resource->width - scanout.x ||
		    scanout.y > resource->height ||
		    scanout.height > resource->height - scanout.y)
			goto fail;
	} else if (scanout.x != 0 || scanout.y != 0 ||
	    scanout.width != 0 || scanout.height != 0)
		goto fail;
	if (cursor_resource != 0) {
		resource = gpu_find_in_array(resources, count, cursor_resource);
		if (resource == NULL ||
		    (resource->kind != GPU_RESOURCE_2D &&
		    resource->kind != GPU_RESOURCE_BLOB) ||
		    resource->host_bytes == 0 ||
		    resource->width != GPU_CURSOR_WIDTH ||
		    resource->height != GPU_CURSOR_HEIGHT ||
		    (resource->kind == GPU_RESOURCE_BLOB &&
		    resource->format !=
		    VIRTIO_GPU_2D_FORMAT_B8G8R8A8_UNORM) ||
		    cursor_hot_x >= GPU_CURSOR_WIDTH ||
		    cursor_hot_y >= GPU_CURSOR_HEIGHT)
			goto fail;
	} else if (cursor_hot_x != 0 || cursor_hot_y != 0)
		goto fail;

	if (!publish) {
		gpu_resource_array_free(resources,
		    limits.max_resources);
		resources = NULL;
		error = 0;
		goto fail;
	}
	pthread_mutex_lock(&state->mutex);
	if (state->destroying) {
		pthread_mutex_unlock(&state->mutex);
		error = ECANCELED;
		goto fail;
	}
	for (uint32_t i = 0; i < limits.max_resources; i++)
		gpu_resource_clear(&state->resources[i]);
	free(state->resources);
	state->resources = resources;
	state->resource_count = count;
	state->host_bytes = host_bytes;
	state->blob_bytes = blob_bytes;
	state->scanout = scanout;
	state->cursor_resource_id = cursor_resource;
	state->cursor_x = cursor_x;
	state->cursor_y = cursor_y;
	state->cursor_hot_x = cursor_hot_x;
	state->cursor_hot_y = cursor_hot_y;
	pthread_mutex_unlock(&state->mutex);
	resources = NULL;
	/*
	 * Host display objects and cursor handles are deliberately not part of
	 * the portable record.  Reconstruct them only after every resource and
	 * visible-state field has been published, and never while holding the
	 * state mutex because a backend may read the restored scanout pixels.
	 */
	/*
	 * Destination-local presentation state is never serialized.  Clear it
	 * first even when the restored image has no active scanout or cursor;
	 * otherwise restoring an empty image over an active destination leaves
	 * stale pixels or a ghost cursor in a future host display backend.
	 */
	if (ops.display_reset != NULL)
		ops.display_reset(ops.arg);
	if (scanout.resource_id != 0 && ops.scanout_update != NULL)
		ops.scanout_update(ops.arg, 0,
		    scanout.resource_id, scanout.x, scanout.y,
		    scanout.width, scanout.height);
	if (scanout.resource_id != 0 && ops.display_update != NULL)
		ops.display_update(ops.arg, 0,
		    scanout.resource_id, 0, 0, scanout.width, scanout.height);
	if (cursor_resource != 0 && ops.cursor_update != NULL)
		ops.cursor_update(ops.arg, 0, cursor_resource,
		    cursor_x, cursor_y, cursor_hot_x, cursor_hot_y);
	error = 0;
	goto fail;

fail:
	gpu_resource_array_free(resources, limits.max_resources);
	gpu_state_callback_done(state);
	return (error);
}

int
virtio_gpu_2d_state_snapshot_validate(struct virtio_gpu_2d_state *state,
    const void *buffer, size_t length)
{

	return (gpu_snapshot_decode(state, buffer, length, false));
}

int
virtio_gpu_2d_state_snapshot_restore(struct virtio_gpu_2d_state *state,
    const void *buffer, size_t length)
{

	return (gpu_snapshot_decode(state, buffer, length, true));
}
