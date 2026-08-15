/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * VirtIO PCI shared-memory-region discovery for child drivers.
 */

#ifndef _DEV_VIRTIO_PCI_VIRTIO_PCI_SHMEM_H_
#define _DEV_VIRTIO_PCI_VIRTIO_PCI_SHMEM_H_

#include <sys/types.h>
#include <sys/bus.h>

#include <machine/bus.h>

struct virtio_pci_shmem_region {
	bus_addr_t	addr;
	bus_size_t	length;
};

/*
 * Resolve one modern VirtIO PCI shared-memory capability by its region ID.
 * The returned range is a guest physical range.  Callers own no resource and
 * must treat it as unavailable after their VirtIO parent is detached.
 */
int virtio_pci_get_shmem_region(device_t child, uint8_t id,
    struct virtio_pci_shmem_region *region);

#endif /* _DEV_VIRTIO_PCI_VIRTIO_PCI_SHMEM_H_ */
