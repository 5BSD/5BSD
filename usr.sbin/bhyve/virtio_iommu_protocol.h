/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_PROTOCOL_H_
#define	_BHYVE_VIRTIO_IOMMU_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIOMMU_REQUEST_TAIL_SIZE	4U
#define	BHYVE_VIOMMU_ATTACH_INPUT_SIZE	20U
#define	BHYVE_VIOMMU_DETACH_INPUT_SIZE	20U
#define	BHYVE_VIOMMU_MAP_INPUT_SIZE	36U
#define	BHYVE_VIOMMU_UNMAP_INPUT_SIZE	28U
#define	BHYVE_VIOMMU_PROBE_INPUT_SIZE	72U
#define	BHYVE_VIOMMU_FAULT_SIZE		24U

struct virtio_iommu_fault;

enum virtio_iommu_request_type {
	BHYVE_VIOMMU_T_ATTACH = 1,
	BHYVE_VIOMMU_T_DETACH = 2,
	BHYVE_VIOMMU_T_MAP = 3,
	BHYVE_VIOMMU_T_UNMAP = 4,
	BHYVE_VIOMMU_T_PROBE = 5,
};

struct virtio_iommu_request {
	uint8_t type;
	uint32_t domain;
	uint32_t endpoint;
	uint32_t flags;
	uint64_t virtual_start;
	uint64_t virtual_end;
	uint64_t physical_start;
};

int	virtio_iommu_request_decode(const void *, size_t,
	    struct virtio_iommu_request *);
int	virtio_iommu_request_decode_bounded(const void *, size_t, size_t,
	    struct virtio_iommu_request *);
void	virtio_iommu_status_encode(uint8_t,
	    uint8_t[BHYVE_VIOMMU_REQUEST_TAIL_SIZE]);
void	virtio_iommu_fault_encode(const struct virtio_iommu_fault *,
	    uint8_t[BHYVE_VIOMMU_FAULT_SIZE]);

#endif
