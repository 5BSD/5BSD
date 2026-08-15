/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_iommu_protocol.h"
#include "virtio_iommu_request.h"
#include "virtio_iommu_state.h"
#include "virtio_state_range.h"

int
virtio_iommu_request_execute_bounded(struct virtio_iommu_state *state,
    const struct virtio_iommu_request_options *options, const void *input,
    size_t input_capacity, size_t input_length, void *output,
    size_t output_length, size_t *used_length)
{
	struct virtio_iommu_request request;
	enum virtio_iommu_status status;
	uint8_t *bytes;
	size_t response_length;
	int error;

	if (state == NULL || options == NULL || input == NULL ||
	    used_length == NULL || (output == NULL && output_length != 0))
		return (EINVAL);
	/*
	 * The queue adapter enforces this limit too, but this exported executor
	 * must retain the same bounded-response contract for direct callers.
	 */
	if (options->probe_size > BHYVE_VIOMMU_MAX_PROBE_SIZE)
		return (EINVAL);
	if (virtio_state_ranges_overlap(input, input_capacity, output,
	    output_length) ||
	    virtio_state_ranges_overlap(input, input_capacity, used_length,
	    sizeof(*used_length)) ||
	    virtio_state_ranges_overlap(output, output_length, used_length,
	    sizeof(*used_length)) ||
	    virtio_state_ranges_overlap(options, sizeof(*options), output,
	    output_length) ||
	    virtio_state_ranges_overlap(options, sizeof(*options), used_length,
	    sizeof(*used_length)) ||
	    virtio_iommu_state_storage_overlaps(state, input, input_capacity) ||
	    virtio_iommu_state_storage_overlaps(state, output, output_length) ||
	    virtio_iommu_state_storage_overlaps(state, options,
	    sizeof(*options)) ||
	    virtio_iommu_state_storage_overlaps(state, used_length,
	    sizeof(*used_length)))
		return (EINVAL);
	*used_length = 0;
	if (output_length < BHYVE_VIOMMU_REQUEST_TAIL_SIZE)
		return (0);
	error = virtio_iommu_request_decode_bounded(input, input_capacity,
	    input_length, &request);
	if (error == EOPNOTSUPP) {
		/*
		 * VirtIO 1.4 section 5.13.6.2 recommends that an
		 * unrecognized request type consume the chain without writing
		 * a response.  A zero used length is also how the driver
		 * distinguishes this case from a recognized request whose
		 * optional operation is unsupported.
		 */
		return (0);
	}
	if (error != 0) {
		status = BHYVE_VIOMMU_S_INVAL;
		response_length = BHYVE_VIOMMU_REQUEST_TAIL_SIZE;
		goto respond;
	}
	response_length = BHYVE_VIOMMU_REQUEST_TAIL_SIZE;
	switch (request.type) {
	case BHYVE_VIOMMU_T_ATTACH:
		/*
		 * ATTACH_F_BYPASS is defined by BYPASS_CONFIG.  Offering that
		 * feature identifies the flag, but the driver may use it only
		 * after negotiation.  Ordinary ATTACH remains part of the base
		 * device ABI.
		 */
		if ((request.flags & BHYVE_VIOMMU_ATTACH_F_BYPASS) != 0 &&
		    !options->bypass_config) {
			status = BHYVE_VIOMMU_S_INVAL;
			break;
		}
		status = virtio_iommu_attach(state, request.domain,
		    request.endpoint, request.flags);
		break;
	case BHYVE_VIOMMU_T_DETACH:
		status = virtio_iommu_detach(state, request.domain,
		    request.endpoint);
		break;
	case BHYVE_VIOMMU_T_MAP:
		if (!options->map_unmap) {
			status = BHYVE_VIOMMU_S_UNSUPP;
			break;
		}
		status = virtio_iommu_map(state, request.domain,
		    request.virtual_start, request.virtual_end,
		    request.physical_start, request.flags);
		break;
	case BHYVE_VIOMMU_T_UNMAP:
		if (!options->map_unmap) {
			status = BHYVE_VIOMMU_S_UNSUPP;
			break;
		}
		status = virtio_iommu_unmap(state, request.domain,
		    request.virtual_start, request.virtual_end);
		break;
	case BHYVE_VIOMMU_T_PROBE:
		/*
		 * Section 5.13.6.7.2 gives unnegotiated PROBE the same
		 * no-write, zero-used-length result as an unknown request.
		 */
		if (!options->probe)
			return (0);
#if SIZE_MAX == UINT32_MAX
		if (options->probe_size > SIZE_MAX -
		    BHYVE_VIOMMU_REQUEST_TAIL_SIZE)
			return (EOVERFLOW);
#endif
		response_length = options->probe_size +
		    BHYVE_VIOMMU_REQUEST_TAIL_SIZE;
		if (output_length < response_length) {
			status = BHYVE_VIOMMU_S_INVAL;
			response_length = BHYVE_VIOMMU_REQUEST_TAIL_SIZE;
			break;
		}
		status = virtio_iommu_endpoint_registered(state,
		    request.endpoint) ? BHYVE_VIOMMU_S_OK :
		    BHYVE_VIOMMU_S_NOENT;
		break;
	default:
		return (EPROTO);
	}
	if (status == BHYVE_VIOMMU_S_BUSY)
		/*
		 * There is no BUSY value in the VirtIO-IOMMU status ABI.
		 * Keep the descriptor device-owned and retry it when the
		 * endpoint's previously accepted DMA becomes idle.
		 */
		return (EAGAIN);
respond:
	bytes = output;
	if (response_length > BHYVE_VIOMMU_REQUEST_TAIL_SIZE)
		memset(bytes, 0, response_length -
		    BHYVE_VIOMMU_REQUEST_TAIL_SIZE);
	virtio_iommu_status_encode(status,
	    bytes + response_length - BHYVE_VIOMMU_REQUEST_TAIL_SIZE);
	*used_length = response_length;
	return (0);
}

int
virtio_iommu_request_execute(struct virtio_iommu_state *state,
    const struct virtio_iommu_request_options *options, const void *input,
    size_t input_length, void *output, size_t output_length,
    size_t *used_length)
{

	return (virtio_iommu_request_execute_bounded(state, options, input,
	    input_length, input_length, output, output_length, used_length));
}
