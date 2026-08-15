/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_CONFIG_H_
#define	_BHYVE_VIRTIO_IOMMU_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIOMMU_F_INPUT_RANGE	(1ULL << 0)
#define	BHYVE_VIOMMU_F_DOMAIN_RANGE	(1ULL << 1)
#define	BHYVE_VIOMMU_F_MAP_UNMAP	(1ULL << 2)
#define	BHYVE_VIOMMU_F_PROBE		(1ULL << 4)
#define	BHYVE_VIOMMU_F_MMIO		(1ULL << 5)
#define	BHYVE_VIOMMU_F_BYPASS_CONFIG	(1ULL << 6)

#define	BHYVE_VIOMMU_CONFIG_SIZE	40U
#define	BHYVE_VIOMMU_CONFIG_BYPASS_OFFSET 36U

struct virtio_iommu_state;

struct virtio_iommu_config_values {
	uint64_t page_size_mask;
	uint64_t input_start;
	uint64_t input_end;
	uint32_t domain_start;
	uint32_t domain_end;
	uint32_t probe_size;
};

int	virtio_iommu_config_encode(const struct virtio_iommu_config_values *,
	    uint64_t, bool, uint8_t[BHYVE_VIOMMU_CONFIG_SIZE]);
int	virtio_iommu_config_write(struct virtio_iommu_state *, uint64_t,
	    size_t, size_t, uint32_t);

#endif
