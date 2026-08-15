/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/uio.h>
#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_iommu_protocol.h"
#include "virtio_iommu_queue.h"
#include "virtio_iommu_request.h"
#include "virtio_iommu_state.h"
#include "virtio_state_range.h"

static int
viommu_iov_validate_ownership(struct virtio_iommu_state *state,
    const struct virtio_iommu_request_options *options,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    const size_t *used_length)
{
	size_t metadata_length;

	if (iov_count > SIZE_MAX / sizeof(*iov))
		return (EOVERFLOW);
	metadata_length = iov_count * sizeof(*iov);
	if (virtio_state_ranges_overlap(iov, metadata_length, options,
	    sizeof(*options)) ||
	    virtio_state_ranges_overlap(iov, metadata_length, used_length,
	    sizeof(*used_length)) ||
	    virtio_state_ranges_overlap(options, sizeof(*options), used_length,
	    sizeof(*used_length)) ||
	    virtio_iommu_state_storage_overlaps(state, iov, metadata_length) ||
	    virtio_iommu_state_storage_overlaps(state, options,
	    sizeof(*options)) ||
	    virtio_iommu_state_storage_overlaps(state, used_length,
	    sizeof(*used_length)))
		return (EINVAL);
	for (size_t i = 0; i < iov_count; i++) {
		if (virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    iov, metadata_length) ||
		    virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    options, sizeof(*options)) ||
		    virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    used_length, sizeof(*used_length)) ||
		    virtio_iommu_state_storage_overlaps(state, iov[i].iov_base,
		    iov[i].iov_len))
			return (EINVAL);
		if (i < readable_count)
			continue;
		for (size_t j = i + 1; j < iov_count; j++) {
			if (virtio_state_ranges_overlap(iov[i].iov_base,
			    iov[i].iov_len, iov[j].iov_base, iov[j].iov_len))
				return (EINVAL);
		}
	}
	return (0);
}

static int
viommu_iov_total(const struct iovec *iov, size_t count, size_t limit,
    size_t *result)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_base == NULL && iov[i].iov_len != 0)
			return (EFAULT);
		if (iov[i].iov_len > limit - total)
			return (limit == SIZE_MAX ? EOVERFLOW : EMSGSIZE);
		total += iov[i].iov_len;
	}
	*result = total;
	return (0);
}

static void
viommu_iov_gather(const struct iovec *iov, size_t count, uint8_t *buffer,
    size_t length)
{
	size_t fragment, offset;

	offset = 0;
	for (size_t i = 0; i < count && offset < length; i++) {
		fragment = MIN(iov[i].iov_len, length - offset);
		memcpy(buffer + offset, iov[i].iov_base, fragment);
		offset += fragment;
	}
}

static int
viommu_iov_scatter(const struct iovec *iov, size_t count,
    const uint8_t *buffer, size_t length)
{
	size_t copied, fragment;

	copied = 0;
	for (size_t i = 0; i < count && copied < length; i++) {
		fragment = MIN(iov[i].iov_len, length - copied);
		memcpy(iov[i].iov_base, buffer + copied, fragment);
		copied += fragment;
	}
	return (copied == length ? 0 : EMSGSIZE);
}

int
virtio_iommu_queue_process(struct virtio_iommu_state *state,
    const struct virtio_iommu_request_options *options,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    size_t writable_count, bool ordered, size_t *used_length)
{
	uint8_t request[BHYVE_VIOMMU_PROBE_INPUT_SIZE];
	uint8_t *response;
	size_t readable, response_size, writable;
	int error;

	if (state == NULL || options == NULL || iov == NULL ||
	    used_length == NULL || iov_count == 0 ||
	    iov_count > BHYVE_VIOMMU_MAX_CHAIN_SEGMENTS ||
	    readable_count == 0 || writable_count == 0 ||
	    readable_count > iov_count ||
	    writable_count > iov_count - readable_count ||
	    readable_count + writable_count != iov_count || !ordered ||
	    options->probe_size > BHYVE_VIOMMU_MAX_PROBE_SIZE)
		return (EINVAL);
	error = viommu_iov_validate_ownership(state, options, iov, iov_count,
	    readable_count, used_length);
	if (error != 0)
		return (error);
	*used_length = 0;
	error = viommu_iov_total(iov, readable_count, SIZE_MAX,
	    &readable);
	if (error != 0)
		return (error);
	error = viommu_iov_total(iov + readable_count, writable_count,
	    SIZE_MAX, &writable);
	if (error != 0)
		return (error);
	response_size = BHYVE_VIOMMU_REQUEST_TAIL_SIZE;
	if (options->probe)
		response_size += options->probe_size;
	response_size = MIN(response_size, writable);
	if (response_size == 0)
		return (0);
	response = calloc(1, response_size);
	if (response == NULL)
		return (ENOMEM);
	/*
	 * Oversized known requests are rejected from their length alone, and
	 * an unknown request requires only its type byte.  Gathering at most
	 * the largest defined request keeps malicious chains bounded while
	 * still allowing the executor to return a protocol status tail.
	 */
	viommu_iov_gather(iov, readable_count, request,
	    MIN(readable, sizeof(request)));
	error = virtio_iommu_request_execute_bounded(state, options, request,
	    MIN(readable, sizeof(request)), readable, response, response_size,
	    used_length);
	if (error == 0 && *used_length != 0)
		error = viommu_iov_scatter(iov + readable_count, writable_count,
		    response, *used_length);
	if (error != 0)
		*used_length = 0;
	free(response);
	return (error);
}
