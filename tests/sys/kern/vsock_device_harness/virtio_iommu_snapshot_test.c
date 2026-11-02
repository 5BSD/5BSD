/*
 * Checkpoint save of the virtio-iommu PCI model with the production VirtIO
 * core and modern transport (see virtio_iommu_post_init_test.c, whose host
 * topology this reuses), built with BHYVE_SNAPSHOT.
 */
#define	BHYVE_SNAPSHOT
#define	VIRTIO_IOMMU_POST_INIT_NO_TP
#include "virtio_iommu_post_init_test.c"

/* The snapshot serializer, as snapshot.c. */
void
vm_snapshot_buf_err(const char *bufname __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;
	if (buffer->buf_rem < data_size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, data, data_size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);
	buffer->buf += data_size;
	buffer->buf_rem -= data_size;
	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le16enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le16dec(bytes);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le32dec(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le64enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = le64dec(bytes);
	return (error);
}

/* As pci_emul.c: which BAR holds the MSI-X table and PBA. */
int
pci_msix_table_bar(struct pci_devinst *pi)
{

	return (pi->pi_msix.table != NULL ? pi->pi_msix.table_bar : -1);
}

int
pci_msix_pba_bar(struct pci_devinst *pi)
{

	return (pi->pi_msix.table != NULL ? pi->pi_msix.pba_bar : -1);
}

/* No device in this topology has an administration queue binding. */
void
virtio_admin_pci_binding_reset(struct virtio_admin_pci_binding *binding)
{

	ATF_REQUIRE(binding == NULL);
}

static uint8_t test_snapshot_image[1024 * 1024];

static int
test_save(struct pci_devinst *pi)
{
	struct vm_snapshot_meta meta = {
		.dev_data = pi,
		.dev_name = pi->pi_d->pe_emu,
		.buffer.buf_start = test_snapshot_image,
		.buffer.buf_size = sizeof(test_snapshot_image),
		.buffer.buf = test_snapshot_image,
		.buffer.buf_rem = sizeof(test_snapshot_image),
		.op = VM_SNAPSHOT_SAVE,
	};

	return (vi_pci_snapshot(&meta));
}

static void
test_checkpoint(struct pci_devinst *iommu, int expect)
{
	int error;

	ATF_REQUIRE_EQ(vi_pci_pause(iommu), 0);
	error = test_save(iommu);
	if (error != expect)
		fprintf(stderr, "virtio-iommu save: %d (%s)\n", error,
		    strerror(error));
	ATF_CHECK_EQ(error, expect);
	ATF_REQUIRE_EQ(vi_pci_resume(iommu), 0);
}

/*
 * A running checkpoint followed by a suspend, with no guest driver bound to
 * the IOMMU (the FreeBSD guest declines it unless hw.virtio_iommu.enable=1).
 */
ATF_TC_WITHOUT_HEAD(save_twice_without_guest_driver);
ATF_TC_BODY(save_twice_without_guest_driver, tc)
{
	struct pci_devinst *iommu, *ep;

	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_checkpoint(iommu, 0);
	test_checkpoint(iommu, 0);
}


static void
test_status(struct pci_devinst *pi, uint8_t status)
{

	vi_pci_write(pi, 2, VIRTIO_MODERN_COMMON_OFF + VIRTIO_PCI_COMMON_STATUS,
	    1, status);
}

static uint8_t
test_status_read(struct pci_devinst *pi)
{

	return ((uint8_t)vi_pci_read(pi, 2,
	    VIRTIO_MODERN_COMMON_OFF + VIRTIO_PCI_COMMON_STATUS, 1));
}

/* virtio_pci_modern attach when no child driver probes (vtiommu default). */
static void
test_guest_declines(struct pci_devinst *pi)
{

	test_status(pi, 0);
	test_status(pi, VIRTIO_CONFIG_STATUS_ACK);
}

/*
 * virtio_pci_modern attach of a child whose features omit ACCESS_PLATFORM:
 * the device refuses FEATURES_OK, the child attach fails, and the transport
 * marks FAILED, then resets and acknowledges again (child_detached).
 */
static void
test_guest_endpoint_fails(struct pci_devinst *pi)
{
	uint8_t status;

	test_status(pi, 0);
	test_status(pi, VIRTIO_CONFIG_STATUS_ACK);
	status = VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER;
	test_status(pi, status);
	vi_pci_write(pi, 2, VIRTIO_MODERN_COMMON_OFF +
	    VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_write(pi, 2, VIRTIO_MODERN_COMMON_OFF + VIRTIO_PCI_COMMON_GF,
	    4, (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
	test_status(pi, status | VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK_EQ(test_status_read(pi) & VIRTIO_CONFIG_S_FEATURES_OK, 0);
	test_status(pi, test_status_read(pi) | VIRTIO_CONFIG_STATUS_FAILED);
	test_status(pi, 0);
	test_status(pi, VIRTIO_CONFIG_STATUS_ACK);
}

ATF_TC_WITHOUT_HEAD(save_twice_after_guest_probe);
ATF_TC_BODY(save_twice_after_guest_probe, tc)
{
	struct pci_devinst *iommu, *ep;

	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_guest_declines(iommu);
	test_guest_endpoint_fails(ep);
	test_checkpoint(iommu, 0);
	test_checkpoint(iommu, 0);
	ATF_CHECK_EQ(test_save(ep), 0);
}

/*
 * vm_checkpoint() order: pause every device, save in PCI slot order (the
 * IOMMU at 0:5 before its endpoint at 0:7), resume every device.  Saving
 * the endpoint takes and drops a DMA lease on the IOMMU domain, which runs
 * the IOMMU's dma_idle callback while the IOMMU has no driver.
 */
static void
test_vm_checkpoint(struct pci_devinst *iommu, struct pci_devinst *ep)
{
	struct virtio_softc *vs;
	int error;

	ATF_REQUIRE_EQ(vi_pci_pause(iommu), 0);
	error = test_save(iommu);
	if (error != 0)
		fprintf(stderr, "virtio-iommu save: %d (%s)\n", error,
		    strerror(error));
	ATF_CHECK_EQ(error, 0);
	ATF_CHECK_EQ(test_save(ep), 0);
	ATF_REQUIRE_EQ(vi_pci_resume(iommu), 0);
	vs = vi_pci_get_softc(iommu);
	for (int i = 0; i < vs->vs_vc->vc_nvq; i++) {
		/* A disabled queue must never hold a deferred kick. */
		if (!vs->vs_queues[i].vq_enabled)
			ATF_CHECK(!vs->vs_queues[i].vq_notify_pending);
	}
}

ATF_TC_WITHOUT_HEAD(checkpoint_twice_endpoint_after_iommu);
ATF_TC_BODY(checkpoint_twice_endpoint_after_iommu, tc)
{
	struct pci_devinst *iommu, *ep;

	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_guest_declines(iommu);
	test_guest_endpoint_fails(ep);
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --checkpoint */
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --suspend */
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, msix_bar_does_not_overlap_modern_bar);
	ATF_TP_ADD_TC(tp, host_topology_post_init_binds_endpoint);
	ATF_TP_ADD_TC(tp, save_twice_without_guest_driver);
	ATF_TP_ADD_TC(tp, save_twice_after_guest_probe);
	ATF_TP_ADD_TC(tp, checkpoint_twice_endpoint_after_iommu);
	return (atf_no_error());
}
