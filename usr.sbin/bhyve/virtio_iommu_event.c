/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/uio.h>
#include <sys/param.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_iommu_event.h"
#include "virtio_iommu_protocol.h"
#include "virtio_iommu_queue.h"
#include "virtio_iommu_state.h"
#include "virtio_state_range.h"

int
virtio_iommu_event_process(struct virtio_iommu_state *state,
    const struct iovec *iov, size_t iov_count, size_t *used_length)
{
	struct virtio_iommu_fault fault;
	uint8_t event[BHYVE_VIOMMU_FAULT_SIZE];
	size_t capacity, copied, fragment;

	if (state == NULL || iov == NULL || used_length == NULL ||
	    iov_count == 0 || iov_count > BHYVE_VIOMMU_MAX_CHAIN_SEGMENTS)
		return (EINVAL);
	if (virtio_state_ranges_overlap(iov, iov_count * sizeof(*iov),
	    used_length, sizeof(*used_length)) ||
	    virtio_iommu_state_storage_overlaps(state, iov,
	    iov_count * sizeof(*iov)) ||
	    virtio_iommu_state_storage_overlaps(state, used_length,
	    sizeof(*used_length)))
		return (EINVAL);
	capacity = 0;
	for (size_t i = 0; i < iov_count; i++) {
		if (iov[i].iov_base == NULL && iov[i].iov_len != 0)
			return (EFAULT);
		if (iov[i].iov_len > SIZE_MAX - capacity)
			return (EOVERFLOW);
		if (virtio_state_ranges_overlap(iov, iov_count * sizeof(*iov),
		    iov[i].iov_base, iov[i].iov_len) ||
		    virtio_state_ranges_overlap(used_length,
		    sizeof(*used_length), iov[i].iov_base, iov[i].iov_len) ||
		    virtio_iommu_state_storage_overlaps(state,
		    iov[i].iov_base, iov[i].iov_len))
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (virtio_state_ranges_overlap(iov[j].iov_base,
			    iov[j].iov_len, iov[i].iov_base, iov[i].iov_len))
				return (EINVAL);
		}
		capacity += iov[i].iov_len;
	}
	*used_length = 0;
	if (capacity < sizeof(event))
		return (EMSGSIZE);
	if (!virtio_iommu_fault_pop(state, &fault))
		return (EAGAIN);
	virtio_iommu_fault_encode(&fault, event);
	copied = 0;
	for (size_t i = 0; i < iov_count && copied < sizeof(event); i++) {
		fragment = MIN(iov[i].iov_len, sizeof(event) - copied);
		memcpy(iov[i].iov_base, event + copied, fragment);
		copied += fragment;
	}
	if (copied != sizeof(event))
		return (EPROTO);
	*used_length = sizeof(event);
	return (0);
}
