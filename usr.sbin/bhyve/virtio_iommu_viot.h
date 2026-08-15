/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_VIOT_H_
#define	_BHYVE_VIRTIO_IOMMU_VIOT_H_

#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIOT_ACPI_HEADER_SIZE	36U
#define	BHYVE_VIOT_TABLE_PREFIX_SIZE	12U
#define	BHYVE_VIOT_PCI_RANGE_SIZE	24U
#define	BHYVE_VIOT_PCI_IOMMU_SIZE	16U

int	virtio_iommu_viot_size(size_t, size_t *);
int	virtio_iommu_viot_encode(uint16_t, const uint16_t *, size_t, void *,
	    size_t);

#endif
