/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_TOPOLOGY_H_
#define	_BHYVE_VIRTIO_IOMMU_TOPOLOGY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_iommu_topology_entry {
	uint16_t requester_id;
	bool virtio;
	bool modern;
	bool iommu;
	bool access_platform_ineligible;
};

int	virtio_iommu_topology_build(
	    const struct virtio_iommu_topology_entry *, size_t, uint16_t *,
	    uint16_t *, size_t, size_t *);

#endif
