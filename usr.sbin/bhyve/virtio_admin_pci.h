/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_ADMIN_PCI_H_
#define	_BHYVE_VIRTIO_ADMIN_PCI_H_

#include <sys/types.h>

#include <stdint.h>

struct virtio_admin_pci_binding;
struct virtio_admin_pci_controller;
struct virtio_softc;
struct vqueue_info;

int	virtio_admin_pci_binding_create(struct virtio_admin_pci_binding **,
	    struct virtio_softc *, struct virtio_admin_pci_controller *,
	    struct vqueue_info *, uint16_t);
int	virtio_admin_pci_binding_destroy(struct virtio_admin_pci_binding *);
int	virtio_admin_pci_binding_enable(struct virtio_admin_pci_binding *,
	    struct vqueue_info *);
int	virtio_admin_pci_binding_drain(struct virtio_admin_pci_binding *,
	    struct vqueue_info *);
int	virtio_admin_pci_binding_quiesce(struct virtio_admin_pci_binding *);
int	virtio_admin_pci_binding_unquiesce(struct virtio_admin_pci_binding *);
int	virtio_admin_pci_binding_resume(struct virtio_admin_pci_binding *,
	    int (*)(void *), void *);
int	virtio_admin_pci_binding_state_size(struct virtio_admin_pci_binding *,
	    size_t *);
int	virtio_admin_pci_binding_state_save(struct virtio_admin_pci_binding *,
	    void *, size_t);
int	virtio_admin_pci_binding_state_restore(struct virtio_admin_pci_binding *,
	    const void *, size_t);
int	virtio_admin_pci_binding_state_restore_validate(
	    struct virtio_admin_pci_binding *, const void *, size_t);
void	virtio_admin_pci_binding_reset(struct virtio_admin_pci_binding *);

#endif /* _BHYVE_VIRTIO_ADMIN_PCI_H_ */
