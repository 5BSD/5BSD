/*
 * Checkpoint save of the virtio-iommu PCI model with the production VirtIO
 * core and modern transport (see virtio_iommu_post_init_test.c, whose host
 * topology this reuses), built with BHYVE_SNAPSHOT.
 */
#define	BHYVE_SNAPSHOT
#define	VIRTIO_IOMMU_POST_INIT_NO_TP
#define	VIRTIO_IOMMU_POST_INIT_GUEST_MEMORY
#include "virtio_iommu_post_init_test.c"

/* Guest RAM: the devices map ring and buffer addresses into this window. */
static uint8_t test_guest_mem[1024 * 1024] __aligned(PAGE_SIZE);

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t addr, size_t len)
{

	if (addr >= sizeof(test_guest_mem) ||
	    len > sizeof(test_guest_mem) - addr)
		return (NULL);
	return (test_guest_mem + addr);
}

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


/*
 * A FreeBSD guest with VIRTIO_F_ACCESS_PLATFORM support (sys/dev/virtio:
 * virtio_iommu_attach_identity, vtpci_modern_access_platform_features): the
 * vtiommu driver brings the IOMMU up and ATTACHes the endpoint RID with
 * ATTACH_F_BYPASS to the last domain of the range; only then does the
 * endpoint's transport accept ACCESS_PLATFORM and program guest-physical ring
 * and buffer addresses.
 */
#define	TEST_IOMMU_DESC		0x10000
#define	TEST_IOMMU_AVAIL	0x11000
#define	TEST_IOMMU_USED		0x12000
#define	TEST_IOMMU_QSIZE	8
#define	TEST_IOMMU_REQ		0x13000
#define	TEST_IOMMU_TAIL		0x13100
#define	TEST_EP_DESC		0x20000
#define	TEST_EP_AVAIL		0x21000
#define	TEST_EP_USED		0x22000
#define	TEST_EP_QSIZE		16
#define	TEST_EP_BUF		0x30000
#define	TEST_EP_BUFLEN		512

static void *
test_gpa(uint64_t gpa)
{

	return (test_guest_mem + gpa);
}

static void
test_common_write(struct pci_devinst *pi, int offset, int size,
    uint64_t value)
{

	vi_pci_write(pi, 2, VIRTIO_MODERN_COMMON_OFF + offset, size, value);
}

/* Driver side of feature negotiation; returns whether FEATURES_OK stuck. */
static bool
test_guest_negotiate(struct pci_devinst *pi, uint64_t features)
{
	uint8_t status;

	test_status(pi, 0);
	test_status(pi, VIRTIO_CONFIG_STATUS_ACK);
	status = VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER;
	test_status(pi, status);
	test_common_write(pi, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	test_common_write(pi, VIRTIO_PCI_COMMON_GF, 4, (uint32_t)features);
	test_common_write(pi, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	test_common_write(pi, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)(features >> 32));
	test_status(pi, status | VIRTIO_CONFIG_S_FEATURES_OK);
	return ((test_status_read(pi) & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
}

static void
test_guest_queue(struct pci_devinst *pi, uint16_t size, uint64_t desc,
    uint64_t avail, uint64_t used)
{

	test_common_write(pi, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_SIZE, 2, size);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_DESCLO, 4, (uint32_t)desc);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_DESCHI, 4, desc >> 32);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, (uint32_t)avail);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_AVAILHI, 4, avail >> 32);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_USEDLO, 4, (uint32_t)used);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_USEDHI, 4, used >> 32);
	test_common_write(pi, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
}

/* Post a readable and a writable descriptor as one chain. */
static void
test_post_chain(uint64_t desc_gpa, uint64_t avail_gpa, uint16_t qsize,
    uint64_t out, uint32_t outlen, uint64_t in, uint32_t inlen)
{
	struct vring_desc *desc;
	struct vring_avail *avail;
	uint16_t idx, head;

	desc = test_gpa(desc_gpa);
	avail = test_gpa(avail_gpa);
	idx = le16toh(avail->idx);
	head = (uint16_t)((idx * 2) % qsize);
	desc[head].addr = htole64(out);
	desc[head].len = htole32(outlen);
	desc[head].flags = htole16(VRING_DESC_F_NEXT);
	desc[head].next = htole16(head + 1);
	desc[head + 1].addr = htole64(in);
	desc[head + 1].len = htole32(inlen);
	desc[head + 1].flags = htole16(VRING_DESC_F_WRITE);
	desc[head + 1].next = 0;
	avail->ring[idx % qsize] = htole16(head);
	atomic_thread_fence(memory_order_release);
	avail->idx = htole16(idx + 1);
}

static void
test_iommu_up(struct pci_devinst *iommu)
{

	ATF_REQUIRE(test_guest_negotiate(iommu, VIRTIO_F_VERSION_1 |
	    BHYVE_VIOMMU_F_INPUT_RANGE | BHYVE_VIOMMU_F_DOMAIN_RANGE |
	    BHYVE_VIOMMU_F_MAP_UNMAP | BHYVE_VIOMMU_F_BYPASS_CONFIG));
	test_guest_queue(iommu, TEST_IOMMU_QSIZE, TEST_IOMMU_DESC,
	    TEST_IOMMU_AVAIL, TEST_IOMMU_USED);
	test_status(iommu, test_status_read(iommu) |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE_EQ(test_status_read(iommu) &
	    VIRTIO_CONFIG_S_NEEDS_RESET, 0);
}

/* Submit the request staged at TEST_IOMMU_REQ; returns the tail status. */
static uint8_t
test_iommu_submit(struct pci_devinst *iommu, uint32_t len)
{
	struct vring_used *used;
	uint16_t before;

	memset(test_gpa(TEST_IOMMU_TAIL), 0xff, BHYVE_VIOMMU_REQUEST_TAIL_SIZE);
	used = test_gpa(TEST_IOMMU_USED);
	before = le16toh(used->idx);
	test_post_chain(TEST_IOMMU_DESC, TEST_IOMMU_AVAIL, TEST_IOMMU_QSIZE,
	    TEST_IOMMU_REQ, len, TEST_IOMMU_TAIL,
	    BHYVE_VIOMMU_REQUEST_TAIL_SIZE);
	vi_pci_write(iommu, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_REQUIRE_EQ(le16toh(used->idx), (uint16_t)(before + 1));
	return (*(uint8_t *)test_gpa(TEST_IOMMU_TAIL));
}

/* ATTACH or DETACH. */
static uint8_t
test_iommu_request(struct pci_devinst *iommu, uint8_t type, uint32_t domain,
    uint32_t endpoint, uint32_t flags)
{
	uint8_t *req;

	req = test_gpa(TEST_IOMMU_REQ);
	memset(req, 0, BHYVE_VIOMMU_ATTACH_INPUT_SIZE);
	req[0] = type;
	le32enc(req + 4, domain);
	le32enc(req + 8, endpoint);
	le32enc(req + 12, flags);
	return (test_iommu_submit(iommu, BHYVE_VIOMMU_ATTACH_INPUT_SIZE));
}

static uint8_t
test_iommu_map(struct pci_devinst *iommu, uint32_t domain, uint64_t iova,
    uint64_t size, uint64_t gpa)
{
	uint8_t *req;

	req = test_gpa(TEST_IOMMU_REQ);
	memset(req, 0, BHYVE_VIOMMU_MAP_INPUT_SIZE);
	req[0] = BHYVE_VIOMMU_T_MAP;
	le32enc(req + 4, domain);
	le64enc(req + 8, iova);
	le64enc(req + 16, iova + size - 1);
	le64enc(req + 24, gpa);
	le32enc(req + 32, BHYVE_VIOMMU_MAP_F_READ | BHYVE_VIOMMU_MAP_F_WRITE);
	return (test_iommu_submit(iommu, BHYVE_VIOMMU_MAP_INPUT_SIZE));
}

static uint8_t
test_iommu_unmap(struct pci_devinst *iommu, uint32_t domain, uint64_t iova,
    uint64_t size)
{
	uint8_t *req;

	req = test_gpa(TEST_IOMMU_REQ);
	memset(req, 0, BHYVE_VIOMMU_UNMAP_INPUT_SIZE);
	req[0] = BHYVE_VIOMMU_T_UNMAP;
	le32enc(req + 4, domain);
	le64enc(req + 8, iova);
	le64enc(req + 16, iova + size - 1);
	return (test_iommu_submit(iommu, BHYVE_VIOMMU_UNMAP_INPUT_SIZE));
}

static uint32_t
test_identity_domain(struct pci_devinst *iommu)
{

	/* struct virtio_iommu_config domain_range.end */
	return ((uint32_t)vi_pci_read(iommu, 2, VIRTIO_MODERN_DEVICE_OFF + 28,
	    4));
}

/*
 * The endpoint driver programs device addresses: the guest-physical address
 * plus "bias" (zero through an identity domain).
 */
static void
test_endpoint_up(struct pci_devinst *ep, uint64_t bias)
{

	ATF_REQUIRE(test_guest_negotiate(ep, VIRTIO_F_VERSION_1 |
	    VIRTIO_F_ACCESS_PLATFORM));
	test_guest_queue(ep, TEST_EP_QSIZE, TEST_EP_DESC + bias,
	    TEST_EP_AVAIL + bias, TEST_EP_USED + bias);
	test_status(ep, test_status_read(ep) | VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

/*
 * Pop one endpoint request as the device would and check that both buffer
 * addresses reached the intended guest RAM; returns the vq_getchain count.
 */
static int
test_endpoint_chain(struct pci_devinst *ep, uint64_t bias)
{
	struct virtio_softc *vs;
	struct vqueue_info *vq;
	struct iovec iov[2];
	struct vi_req req;
	int n;

	vs = vi_pci_get_softc(ep);
	vq = &vs->vs_queues[0];
	test_post_chain(TEST_EP_DESC, TEST_EP_AVAIL, TEST_EP_QSIZE,
	    TEST_EP_BUF + bias, TEST_EP_BUFLEN,
	    TEST_EP_BUF + TEST_EP_BUFLEN + bias, TEST_EP_BUFLEN);
	if (!vq_has_descs(vq))
		return (0);
	n = vq_getchain(vq, iov, nitems(iov), &req);
	if (n != 2)
		return (n);
	ATF_CHECK(iov[0].iov_base == test_gpa(TEST_EP_BUF));
	ATF_CHECK(iov[1].iov_base == test_gpa(TEST_EP_BUF + TEST_EP_BUFLEN));
	ATF_CHECK_EQ(req.readable, 1);
	ATF_CHECK_EQ(req.writable, 1);
	vq_relchain_req(vq, &req, TEST_EP_BUFLEN);
	vq_endchains(vq, 1);
	return (n);
}

static void
test_guest_reset(void)
{

	memset(test_guest_mem, 0, sizeof(test_guest_mem));
}

/*
 * Without the identity ATTACH the endpoint still negotiates (bhyve requires
 * the feature), but its ring cannot be mapped through the unattached,
 * non-bypass endpoint: the queue never yields a chain.
 */
ATF_TC_WITHOUT_HEAD(access_platform_endpoint_requires_attach);
ATF_TC_BODY(access_platform_endpoint_requires_attach, tc)
{
	struct pci_devinst *iommu, *ep;

	test_guest_reset();
	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_iommu_up(iommu);
	/* Today's FreeBSD guest: no ACCESS_PLATFORM, FEATURES_OK refused. */
	ATF_CHECK(!test_guest_negotiate(ep, VIRTIO_F_VERSION_1));
	test_endpoint_up(ep, 0);
	ATF_CHECK(test_endpoint_chain(ep, 0) <= 0);
}

ATF_TC_WITHOUT_HEAD(access_platform_endpoint_identity_domain);
ATF_TC_BODY(access_platform_endpoint_identity_domain, tc)
{
	struct pci_devinst *iommu, *ep;
	uint32_t domain, rid;

	test_guest_reset();
	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_iommu_up(iommu);
	domain = test_identity_domain(iommu);
	ATF_CHECK_EQ(domain, UINT32_MAX);
	rid = 7 << 3;
	/* An endpoint the IOMMU does not manage is refused (next provider). */
	ATF_CHECK_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_ATTACH, domain,
	    6 << 3, BHYVE_VIOMMU_ATTACH_F_BYPASS), BHYVE_VIOMMU_S_NOENT);
	ATF_REQUIRE_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_ATTACH, domain,
	    rid, BHYVE_VIOMMU_ATTACH_F_BYPASS), BHYVE_VIOMMU_S_OK);
	/* Reattaching on endpoint reinit is idempotent. */
	ATF_REQUIRE_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_ATTACH, domain,
	    rid, BHYVE_VIOMMU_ATTACH_F_BYPASS), BHYVE_VIOMMU_S_OK);
	test_endpoint_up(ep, 0);
	ATF_CHECK_EQ(test_status_read(ep) & VIRTIO_CONFIG_S_NEEDS_RESET, 0);
	ATF_CHECK_EQ(test_endpoint_chain(ep, 0), 2);
	ATF_CHECK_EQ(test_endpoint_chain(ep, 0), 2);
}

/*
 * Checkpoint and suspend with the endpoint live behind its identity domain:
 * the endpoint's save takes a DMA lease on the domain, and requests continue
 * to map afterwards.
 */
ATF_TC_WITHOUT_HEAD(access_platform_endpoint_checkpoint);
ATF_TC_BODY(access_platform_endpoint_checkpoint, tc)
{
	struct pci_devinst *iommu, *ep;

	test_guest_reset();
	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_iommu_up(iommu);
	ATF_REQUIRE_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_ATTACH,
	    test_identity_domain(iommu), 7 << 3, BHYVE_VIOMMU_ATTACH_F_BYPASS),
	    BHYVE_VIOMMU_S_OK);
	test_endpoint_up(ep, 0);
	ATF_REQUIRE_EQ(test_endpoint_chain(ep, 0), 2);
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --checkpoint */
	ATF_CHECK_EQ(test_endpoint_chain(ep, 0), 2);
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --suspend */
	ATF_CHECK_EQ(test_endpoint_chain(ep, 0), 2);
	ATF_CHECK_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_DETACH,
	    test_identity_domain(iommu), 7 << 3, 0), BHYVE_VIOMMU_S_OK);
	ATF_CHECK(test_endpoint_chain(ep, 0) <= 0);
}


/*
 * A translated domain, as a future busdma back end would program it: the
 * endpoint's rings and buffers live at IOVAs MAPped onto their GPAs, survive
 * checkpoint and suspend, and stop resolving after UNMAP.
 */
#define	TEST_EP_IOVA		0x100000
#define	TEST_EP_IOVA_BIAS	(TEST_EP_IOVA - TEST_EP_DESC)

ATF_TC_WITHOUT_HEAD(access_platform_endpoint_translated_domain);
ATF_TC_BODY(access_platform_endpoint_translated_domain, tc)
{
	struct pci_devinst *iommu, *ep;

	test_guest_reset();
	test_host_topology(&iommu, &ep);
	ATF_REQUIRE_EQ(pci_vtiommu_post_init(iommu), 0);
	test_iommu_up(iommu);
	ATF_REQUIRE_EQ(test_iommu_request(iommu, BHYVE_VIOMMU_T_ATTACH, 1,
	    7 << 3, 0), BHYVE_VIOMMU_S_OK);
	ATF_REQUIRE_EQ(test_iommu_map(iommu, 1, TEST_EP_IOVA, 0x20000,
	    TEST_EP_DESC), BHYVE_VIOMMU_S_OK);
	test_endpoint_up(ep, TEST_EP_IOVA_BIAS);
	ATF_CHECK_EQ(test_status_read(ep) & VIRTIO_CONFIG_S_NEEDS_RESET, 0);
	ATF_CHECK_EQ(test_endpoint_chain(ep, TEST_EP_IOVA_BIAS), 2);
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --checkpoint */
	ATF_CHECK_EQ(test_endpoint_chain(ep, TEST_EP_IOVA_BIAS), 2);
	test_vm_checkpoint(iommu, ep);	/* bhyvectl --suspend */
	ATF_CHECK_EQ(test_endpoint_chain(ep, TEST_EP_IOVA_BIAS), 2);
	ATF_CHECK_EQ(test_iommu_unmap(iommu, 1, TEST_EP_IOVA, 0x20000),
	    BHYVE_VIOMMU_S_OK);
	ATF_CHECK(test_endpoint_chain(ep, TEST_EP_IOVA_BIAS) <= 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, msix_bar_does_not_overlap_modern_bar);
	ATF_TP_ADD_TC(tp, host_topology_post_init_binds_endpoint);
	ATF_TP_ADD_TC(tp, save_twice_without_guest_driver);
	ATF_TP_ADD_TC(tp, save_twice_after_guest_probe);
	ATF_TP_ADD_TC(tp, checkpoint_twice_endpoint_after_iommu);
	ATF_TP_ADD_TC(tp, access_platform_endpoint_requires_attach);
	ATF_TP_ADD_TC(tp, access_platform_endpoint_identity_domain);
	ATF_TP_ADD_TC(tp, access_platform_endpoint_checkpoint);
	ATF_TP_ADD_TC(tp, access_platform_endpoint_translated_domain);
	return (atf_no_error());
}
