/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_iommu_topology.h"
#include "virtio_state_range.h"

int
virtio_iommu_topology_build(
    const struct virtio_iommu_topology_entry *entries, size_t entry_count,
    uint16_t *iommu_requester_id, uint16_t *endpoints, size_t endpoint_capacity,
    size_t *endpoint_count)
{
	uint16_t requester_id;
	size_t count;
	bool found_iommu;

	if ((entry_count != 0 && entries == NULL) ||
	    iommu_requester_id == NULL || endpoints == NULL ||
	    endpoint_count == NULL)
		return (EINVAL);
	if (entry_count > SIZE_MAX / sizeof(*entries))
		return (EOVERFLOW);
	count = 0;
	found_iommu = false;
	for (size_t i = 0; i < entry_count; i++) {
		if (!entries[i].iommu)
			continue;
		if (!entries[i].virtio || !entries[i].modern)
			return (EINVAL);
		if (found_iommu)
			return (EEXIST);
		requester_id = entries[i].requester_id;
		found_iommu = true;
	}
	if (!found_iommu)
		return (ENODEV);

	for (size_t i = 0; i < entry_count; i++) {
		if (!entries[i].virtio || !entries[i].modern || entries[i].iommu ||
		    entries[i].access_platform_ineligible)
			continue;
		if (entries[i].requester_id == requester_id)
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (entries[j].virtio && entries[j].modern &&
			    !entries[j].iommu &&
			    !entries[j].access_platform_ineligible &&
			    entries[j].requester_id == entries[i].requester_id)
				return (EEXIST);
		}
		if (count == endpoint_capacity)
			return (E2BIG);
		count++;
	}
	if (count == 0)
		return (ENODEV);
	if (count > SIZE_MAX / sizeof(*endpoints))
		return (EOVERFLOW);
	if (virtio_state_ranges_overlap(entries,
	    entry_count * sizeof(*entries), endpoints,
	    count * sizeof(*endpoints)) ||
	    virtio_state_ranges_overlap(endpoints,
	    count * sizeof(*endpoints), iommu_requester_id,
	    sizeof(*iommu_requester_id)) ||
	    virtio_state_ranges_overlap(endpoints,
	    count * sizeof(*endpoints), endpoint_count,
	    sizeof(*endpoint_count)) ||
	    virtio_state_ranges_overlap(iommu_requester_id,
	    sizeof(*iommu_requester_id), endpoint_count,
	    sizeof(*endpoint_count)))
		return (EINVAL);

	/*
	 * Publish only after the complete topology is valid.  PCI post-init
	 * uses this helper as a transaction boundary; a rejected second IOMMU,
	 * duplicate requester ID, or undersized destination must not leave a
	 * plausible partial binding in caller-owned storage.
	 */
	count = 0;
	for (size_t i = 0; i < entry_count; i++) {
		if (!entries[i].virtio || !entries[i].modern || entries[i].iommu ||
		    entries[i].access_platform_ineligible)
			continue;
		endpoints[count++] = entries[i].requester_id;
	}
	*iommu_requester_id = requester_id;
	*endpoint_count = count;
	return (0);
}
