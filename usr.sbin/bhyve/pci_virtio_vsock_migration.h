/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_PCI_VIRTIO_VSOCK_MIGRATION_H_
#define _BHYVE_PCI_VIRTIO_VSOCK_MIGRATION_H_

#include <stdint.h>
#include <stddef.h>

#include "vsock_migration_state.h"

struct pci_devinst;

/*
 * Capture while the device's checkpoint pause owns its mutex.  Buffer pointers
 * remain valid only until that pause ends; the caller must encode them first.
 */
int pci_vtvsock_migration_collect(struct pci_devinst *,
    struct vsock_migration_conn_state *, uint32_t, uint32_t *);

/*
 * Encode a paused device's connection table and return its matching source
 * sockets in table order.  The descriptors remain owned by the source device
 * and may be used by a relay only while that device remains paused.  The
 * caller owns *wire_out and must free it.
 */
int pci_vtvsock_migration_capture(struct pci_devinst *, uint8_t **, size_t *,
    int *, uint32_t, uint32_t *);

/*
 * Attach destination relay socket ends while the checkpoint pause is held.
 * Each fd is consumed (set to -1) when attached; the caller closes any fds
 * still nonnegative after failure.  Device state is rolled back on failure.
 */
int pci_vtvsock_migration_restore(struct pci_devinst *, const uint8_t *,
    size_t, int *, uint32_t);

#endif
