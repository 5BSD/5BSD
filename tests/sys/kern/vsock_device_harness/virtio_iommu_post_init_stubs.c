/*
 * Link-only stubs for virtio_iommu_post_init_test.c.  The production VirtIO
 * core references MSI-X table emulation, administration-queue bindings, and
 * the snapshot serializer from paths that construction and PCI post-init never
 * reach.  This translation unit deliberately includes no bhyve headers: each
 * stub only satisfies the linker and aborts if it is ever called.
 */
#include <stdlib.h>

extern int raw_stdio;
int raw_stdio;

#define	UNREACHABLE_STUB(name)	void name(void); void name(void) { abort(); }
UNREACHABLE_STUB(pci_emul_msix_tread)
UNREACHABLE_STUB(pci_emul_msix_twrite)
UNREACHABLE_STUB(pci_msix_pba_bar)
UNREACHABLE_STUB(pci_msix_table_bar)
UNREACHABLE_STUB(virtio_admin_pci_binding_drain)
UNREACHABLE_STUB(virtio_admin_pci_binding_enable)
UNREACHABLE_STUB(virtio_admin_pci_binding_quiesce)
UNREACHABLE_STUB(virtio_admin_pci_binding_reset)
UNREACHABLE_STUB(virtio_admin_pci_binding_resume)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_restore)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_restore_validate)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_save)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_size)
UNREACHABLE_STUB(virtio_admin_pci_binding_unquiesce)
UNREACHABLE_STUB(vm_rev_map_gpa)
UNREACHABLE_STUB(vm_snapshot_buf)
UNREACHABLE_STUB(vm_snapshot_buf_err)
UNREACHABLE_STUB(vm_snapshot_guest2host_addr)
UNREACHABLE_STUB(vm_snapshot_le16)
UNREACHABLE_STUB(vm_snapshot_le32)
UNREACHABLE_STUB(vm_snapshot_le64)
UNREACHABLE_STUB(vm_snapshot_u8)
