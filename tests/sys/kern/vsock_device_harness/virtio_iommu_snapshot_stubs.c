/*
 * Link-only stubs for virtio_iommu_snapshot_test.c: as
 * virtio_iommu_post_init_stubs.c, without the snapshot serializer, which the
 * snapshot test implements.  Each stub aborts if it is ever called.
 */
#include <stdlib.h>
#include <unistd.h>

extern int raw_stdio;
int raw_stdio;

#define	UNREACHABLE_STUB(name)	void name(void); void name(void) {	\
	(void)write(STDERR_FILENO, #name "\n", sizeof(#name)); abort(); }
UNREACHABLE_STUB(pci_emul_msix_tread)
UNREACHABLE_STUB(pci_emul_msix_twrite)
UNREACHABLE_STUB(virtio_admin_pci_binding_drain)
UNREACHABLE_STUB(virtio_admin_pci_binding_enable)
UNREACHABLE_STUB(virtio_admin_pci_binding_quiesce)
UNREACHABLE_STUB(virtio_admin_pci_binding_resume)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_restore)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_restore_validate)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_save)
UNREACHABLE_STUB(virtio_admin_pci_binding_state_size)
UNREACHABLE_STUB(virtio_admin_pci_binding_unquiesce)
UNREACHABLE_STUB(vm_rev_map_gpa)
UNREACHABLE_STUB(vm_snapshot_guest2host_addr)
