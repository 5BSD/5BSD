/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_gpu_2d_queue.h"
#include "virtio_state_range.h"

static int
gpu_chain_validate_ownership(struct virtio_gpu_2d_state *state,
    const struct virtio_gpu_2d_segment *segments, size_t segment_count,
    const size_t *used_length)
{
	size_t metadata_length;

	if (segments == NULL || used_length == NULL || segment_count == 0 ||
	    segment_count > BHYVE_VIRTIO_GPU_MAX_CHAIN_SEGMENTS)
		return (EINVAL);
	if (segment_count > SIZE_MAX / sizeof(*segments))
		return (EOVERFLOW);
	metadata_length = segment_count * sizeof(*segments);
	if (virtio_state_ranges_overlap(segments, metadata_length, used_length,
	    sizeof(*used_length)) ||
	    virtio_gpu_2d_state_storage_overlaps(state, segments,
	    metadata_length) ||
	    virtio_gpu_2d_state_storage_overlaps(state, used_length,
	    sizeof(*used_length)))
		return (EINVAL);
	for (size_t i = 0; i < segment_count; i++) {
		if (virtio_state_ranges_overlap(segments[i].base,
		    segments[i].length, segments, metadata_length) ||
		    virtio_state_ranges_overlap(segments[i].base,
		    segments[i].length, used_length, sizeof(*used_length)) ||
		    virtio_gpu_2d_state_storage_overlaps(state,
		    segments[i].base, segments[i].length))
			return (EINVAL);
		if (!segments[i].writable)
			continue;
		for (size_t j = i + 1; j < segment_count; j++) {
			if (segments[j].writable &&
			    virtio_state_ranges_overlap(segments[i].base,
			    segments[i].length, segments[j].base,
			    segments[j].length))
				return (EINVAL);
		}
	}
	return (0);
}

static int
gpu_chain_measure(const struct virtio_gpu_2d_segment *segments,
    size_t segment_count, size_t *readable, size_t *writable)
{
	bool saw_writable;

	if (segments == NULL || readable == NULL || writable == NULL ||
	    segment_count == 0 ||
	    segment_count > BHYVE_VIRTIO_GPU_MAX_CHAIN_SEGMENTS)
		return (EINVAL);
	*readable = 0;
	*writable = 0;
	saw_writable = false;
	for (size_t i = 0; i < segment_count; i++) {
		if (segments[i].base == NULL || segments[i].length == 0)
			return (EINVAL);
		if (segments[i].writable) {
			saw_writable = true;
			if (*writable > SIZE_MAX - segments[i].length)
				return (EOVERFLOW);
			*writable += segments[i].length;
		} else {
			if (saw_writable)
				return (EPROTO);
			if (*readable > SIZE_MAX - segments[i].length)
				return (EOVERFLOW);
			*readable += segments[i].length;
		}
	}
	if (*readable == 0)
		return (EPROTO);
	if (*readable > BHYVE_VIRTIO_GPU_MAX_REQUEST_SIZE)
		return (E2BIG);
	return (0);
}

static void
gpu_chain_gather(const struct virtio_gpu_2d_segment *segments,
    size_t segment_count, uint8_t *output)
{
	size_t offset;

	offset = 0;
	for (size_t i = 0; i < segment_count; i++) {
		if (segments[i].writable)
			break;
		memcpy(output + offset, segments[i].base, segments[i].length);
		offset += segments[i].length;
	}
}

static int
gpu_chain_scatter(const struct virtio_gpu_2d_segment *segments,
    size_t segment_count, const uint8_t *input, size_t length)
{
	size_t amount, offset;

	offset = 0;
	for (size_t i = 0; i < segment_count && offset != length; i++) {
		if (!segments[i].writable)
			continue;
		amount = segments[i].length;
		if (amount > length - offset)
			amount = length - offset;
		memcpy(segments[i].base, input + offset, amount);
		offset += amount;
	}
	return (offset == length ? 0 : EMSGSIZE);
}

static bool
gpu_command_features_negotiated(uint32_t type, uint64_t features)
{

	switch (type) {
	case VIRTIO_GPU_2D_GET_EDID:
		return ((features &
		    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_EDID)) != 0);
	case VIRTIO_GPU_2D_RESOURCE_CREATE_BLOB:
	case VIRTIO_GPU_2D_SET_SCANOUT_BLOB:
	case VIRTIO_GPU_2D_RESOURCE_MAP_BLOB:
	case VIRTIO_GPU_2D_RESOURCE_UNMAP_BLOB:
		return ((features &
		    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_RESOURCE_BLOB)) != 0);
	default:
		return (true);
	}
}

int
virtio_gpu_2d_queue_process_features(struct virtio_gpu_2d_state *state,
    enum virtio_gpu_2d_queue queue,
    const struct virtio_gpu_2d_segment *segments, size_t segment_count,
    uint32_t display_width, uint32_t display_height,
    uint64_t negotiated_features, size_t *used_length)
{
	struct virtio_gpu_2d_command command;
	uint8_t response[BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE];
	uint8_t *request;
	uint32_t response_type;
	size_t readable, response_length, writable;
	int error;

	if (state == NULL || used_length == NULL || display_width == 0 ||
	    display_height == 0)
		return (EINVAL);
	error = gpu_chain_validate_ownership(state, segments, segment_count,
	    used_length);
	if (error != 0)
		return (error);
	*used_length = 0;
	error = gpu_chain_measure(segments, segment_count, &readable, &writable);
	if (error != 0)
		return (error);
	if ((queue == VIRTIO_GPU_2D_CONTROL_QUEUE &&
	    writable < BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE) ||
	    (queue == VIRTIO_GPU_2D_CURSOR_QUEUE && writable != 0 &&
	    writable < BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE))
		return (EMSGSIZE);
	request = malloc(readable);
	if (request == NULL)
		return (ENOMEM);
	gpu_chain_gather(segments, segment_count, request);
	error = virtio_gpu_2d_command_decode(queue, request, readable,
	    writable, &command);
	if (error != 0) {
		/*
		 * Once a complete common header and response buffer are
		 * available, malformed commands are protocol errors, not
		 * transport failures.  Complete them with the standard error
		 * response and do not enter the state engine.
		 */
		if (readable >= BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE &&
		    writable >= BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE &&
		    (error == EPROTO || error == EMSGSIZE ||
		    error == EOVERFLOW || error == ENOTSUP)) {
			error = virtio_gpu_2d_response_encode(&command,
			    VIRTIO_GPU_2D_RESP_ERR_INVALID_PARAMETER,
			    response);
			if (error == 0)
				error = gpu_chain_scatter(segments,
				    segment_count, response,
				    BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE);
			if (error == 0)
				*used_length =
				    BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE;
		}
		free(request);
		return (error);
	}
	/*
	 * Optional command families are part of the guest ABI only after their
	 * defining feature is negotiated.  Host configuration controls what is
	 * offered, but must not silently grant an unnegotiated command access to
	 * resource, aperture, or display state.
	 */
	if (!gpu_command_features_negotiated(command.type,
	    negotiated_features))
		response_type = VIRTIO_GPU_2D_RESP_ERR_UNSPEC;
	else
		response_type = virtio_gpu_2d_state_execute(state, &command,
		    request, readable);
	if (queue == VIRTIO_GPU_2D_CURSOR_QUEUE && writable == 0) {
		free(request);
		return (0);
	}
	if (response_type == VIRTIO_GPU_2D_RESP_OK_DISPLAY_INFO) {
		response_length = BHYVE_VIRTIO_GPU_DISPLAY_INFO_SIZE;
		error = virtio_gpu_2d_display_info_encode(&command,
		    display_width, display_height, response);
	} else if (response_type == VIRTIO_GPU_2D_RESP_OK_EDID) {
		response_length = BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE;
		error = virtio_gpu_2d_edid_encode(&command, display_width,
		    display_height, response);
	} else {
		response_length = BHYVE_VIRTIO_GPU_CTRL_HEADER_SIZE;
		error = virtio_gpu_2d_response_encode(&command, response_type,
		    response);
	}
	free(request);
	if (error != 0)
		return (error);
	error = gpu_chain_scatter(segments, segment_count, response,
	    response_length);
	if (error == 0)
		*used_length = response_length;
	return (error);
}

int
virtio_gpu_2d_queue_process(struct virtio_gpu_2d_state *state,
    enum virtio_gpu_2d_queue queue,
    const struct virtio_gpu_2d_segment *segments, size_t segment_count,
    uint32_t display_width, uint32_t display_height, size_t *used_length)
{

	/* Compatibility entry point for feature-independent unit consumers. */
	return (virtio_gpu_2d_queue_process_features(state, queue, segments,
	    segment_count, display_width, display_height, UINT64_MAX,
	    used_length));
}
