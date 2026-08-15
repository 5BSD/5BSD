/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_PCI_VIRTIO_IOMMU_H_
#define	_BHYVE_PCI_VIRTIO_IOMMU_H_

#include <stddef.h>
#include <stdint.h>

struct pci_devinst;

int	pci_vtiommu_viot_info(struct pci_devinst *, uint16_t *,
	    const uint16_t **, size_t *);

#endif
