/*
 * Unit tests for bhyve's modern Virtio PCI transport.  The real transport
 * source is included so its register-level behavior can be tested without a
 * VM or /dev/vmm.
 */
#include <sys/param.h>
#include <sys/nv.h>
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "pci_emul.h"
#include <bhyve/virtio.h>
#define	MOCK_VIRTIO_H
#include "virtio_pci_modern.c"

struct nvlist {
	int unused;
};

static const char *g_transport;
static uint8_t g_guest_mem[128 * 1024];
static int g_bar;
static enum pcibar_type g_bar_type;
static uint64_t g_bar_size;
static int g_notify_count;
static uint16_t g_notify_queue;
static int g_lintr_deasserts;
static int g_lintr_asserts;
static int g_msi_count;
static int g_msix_count;
static int g_msix_enabled;
static int g_msix_vector;
static uint64_t g_applied_features;
static uint8_t g_device_config[8];

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	return (strcmp(name, "transport") == 0 ? g_transport : NULL);
}

void
set_config_value_node(nvlist_t *nvl __unused, const char *name __unused,
    const char *value __unused)
{
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{

	if (gpa > sizeof(g_guest_mem) || len > sizeof(g_guest_mem) - gpa)
		return (NULL);
	return (&g_guest_mem[gpa]);
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{

	pi->pi_cfgdata[offset] = value;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t value)
{

	memcpy(&pi->pi_cfgdata[offset], &value, sizeof(value));
}

void
pci_set_cfgdata32(struct pci_devinst *pi, int offset, uint32_t value)
{

	memcpy(&pi->pi_cfgdata[offset], &value, sizeof(value));
}

uint8_t
pci_get_cfgdata8(struct pci_devinst *pi, int offset)
{

	return (pi->pi_cfgdata[offset]);
}

uint32_t
pci_get_cfgdata32(struct pci_devinst *pi, int offset)
{
	uint32_t value;

	memcpy(&value, &pi->pi_cfgdata[offset], sizeof(value));
	return (value);
}

int
pci_emul_alloc_bar(struct pci_devinst *pi __unused, int bar,
    enum pcibar_type type, uint64_t size)
{

	g_bar = bar;
	g_bar_type = type;
	g_bar_size = size;
	return (0);
}

int
pci_emul_add_capability(struct pci_devinst *pi, const u_char *data, int length)
{
	int offset, padded;

	padded = roundup2(length, 4);
	offset = pi->pi_prevcap == 0 ? 0x40 : pi->pi_capend + 1;
	if (offset + padded > (int)sizeof(pi->pi_cfgdata))
		return (-1);
	if (pi->pi_prevcap != 0)
		pi->pi_cfgdata[pi->pi_prevcap + 1] = offset;
	memcpy(&pi->pi_cfgdata[offset], data, length);
	pi->pi_cfgdata[offset + 1] = 0;
	pi->pi_prevcap = offset;
	pi->pi_capend = offset + padded - 1;
	return (0);
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{

	g_lintr_deasserts++;
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
	g_lintr_asserts++;
}

int
pci_msix_enabled(struct pci_devinst *pi __unused)
{
	return (g_msix_enabled);
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int vector __unused)
{
	g_msi_count++;
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int vector)
{
	g_msix_count++;
	g_msix_vector = vector;
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	if ((vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		vi_interrupt(vs, VIRTIO_PCI_ISR_CONFIG, vs->vs_msix_cfg_idx);
}

void
vi_pci_notify_queue(struct virtio_softc *vs, uint64_t queue)
{
	struct vqueue_info *vq;

	if (queue >= (unsigned int)vs->vs_vc->vc_nvq)
		return;
	vq = &vs->vs_queues[queue];
	if (!vq->vq_enabled)
		return;
	if ((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0) {
		vq->vq_notify_pending = true;
		return;
	}
	vq->vq_notify_pending = false;
	g_notify_count++;
	g_notify_queue = (uint16_t)queue;
}

void
vi_pci_notify_ready_queues(struct virtio_softc *vs)
{

	for (int i = 0; i < vs->vs_vc->vc_nvq; i++) {
		if (vs->vs_queues[i].vq_notify_pending)
			vi_pci_notify_queue(vs, i);
	}
}

static void
test_reset(void *arg)
{
	struct virtio_softc *vs;
	int i;

	vs = arg;
	for (i = 0; i < vs->vs_vc->vc_nvq; i++) {
		vs->vs_queues[i].vq_flags = 0;
		vs->vs_queues[i].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
		vs->vs_queues[i].vq_notify_pending = false;
	}
	vs->vs_negotiated_caps = 0;
	vs->vs_curq = 0;
	vs->vs_isr = 0;
	vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	vi_pci_modern_reset(vs);
}

static void
test_apply_features(void *arg __unused, uint64_t features)
{

	g_applied_features = features;
}

static int
test_cfgread(void *arg __unused, int offset, int size, uint32_t *value)
{

	*value = 0;
	memcpy(value, &g_device_config[offset], size);
	return (0);
}

static int
test_cfgwrite(void *arg __unused, int offset, int size, uint32_t value)
{

	memcpy(&g_device_config[offset], &value, size);
	return (0);
}

static struct virtio_consts test_consts = {
	.vc_name = "modern-test",
	.vc_nvq = 2,
	.vc_cfgsize = sizeof(g_device_config),
	.vc_reset = test_reset,
	.vc_cfgread = test_cfgread,
	.vc_cfgwrite = test_cfgwrite,
	.vc_apply_features = test_apply_features,
	.vc_hv_caps = 0x7 | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_NOTIFY_ON_EMPTY |
	    VIRTIO_F_ANY_LAYOUT |
	    VIRTIO_F_IOMMU_PLATFORM | (1ULL << 34) | (1ULL << 38) |
	    (1ULL << 40) | (1ULL << 41) | (1ULL << 43) | (1ULL << 50),
};

static void
setup_transport(struct virtio_softc *vs, struct pci_devinst *pi,
    struct vqueue_info *queues)
{

	memset(vs, 0, sizeof(*vs));
	memset(pi, 0, sizeof(*pi));
	memset(queues, 0, sizeof(*queues) * test_consts.vc_nvq);
	memset(g_guest_mem, 0, sizeof(g_guest_mem));
	memset(g_device_config, 0, sizeof(g_device_config));
	g_bar = -1;
	g_notify_count = 0;
	g_notify_queue = UINT16_MAX;
	g_lintr_deasserts = 0;
	g_lintr_asserts = 0;
	g_msi_count = 0;
	g_msix_count = 0;
	g_msix_enabled = 0;
	g_msix_vector = -1;
	g_applied_features = 0;
	queues[0].vq_qsize = 256;
	queues[1].vq_qsize = 128;
	ATF_REQUIRE(pthread_mutex_init(&vs->vs_isr_mtx, NULL) == 0);
	queues[0].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	queues[1].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	vs->vs_vc = &test_consts;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	queues[0].vq_vs = vs;
	queues[1].vq_vs = vs;
	queues[0].vq_num = 0;
	queues[1].vq_num = 1;
	vs->vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	pi->pi_arg = vs;
	pi->pi_msix.table_count = 2;
	g_transport = "modern";
	ATF_REQUIRE(vi_pci_select_transport(vs, NULL,
	    VIRTIO_PCI_LEGACY_DEFAULT) == 0);
	ATF_REQUIRE(vi_pci_modern_init(vs, 2) == 0);
}

ATF_TC_WITHOUT_HEAD(transport_policy);
ATF_TC_BODY(transport_policy, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&vc, 0, sizeof(vc));
	vc.vc_name = "policy-test";
	vs.vs_vc = &vc;
	g_transport = NULL;
	ATF_CHECK(vi_pci_select_transport(&vs, NULL,
	    VIRTIO_PCI_LEGACY_DEFAULT) == 0);
	ATF_CHECK(!vi_pci_is_modern(&vs));
	memset(&vq, 0, sizeof(vq));
	vq.vq_vs = &vs;
	vq.vq_flags = VQ_ALLOC;
	ATF_CHECK(!vq_ring_ready(&vq));
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK(vq_ring_ready(&vq));
	ATF_CHECK(vi_pci_select_transport(&vs, NULL,
	    VIRTIO_PCI_MODERN_DEFAULT) == 0);
	ATF_CHECK(vi_pci_is_modern(&vs));
	g_transport = "legacy";
	ATF_CHECK(vi_pci_select_transport(&vs, NULL,
	    VIRTIO_PCI_MODERN_ONLY) == EINVAL);
	g_transport = "bogus";
	ATF_CHECK(vi_pci_select_transport(&vs, NULL,
	    VIRTIO_PCI_LEGACY_DEFAULT) == EINVAL);
}

ATF_TC_WITHOUT_HEAD(capability_chain);
ATF_TC_BODY(capability_chain, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	static const uint8_t expected[] = {
		VIRTIO_PCI_CAP_COMMON_CFG,
		VIRTIO_PCI_CAP_NOTIFY_CFG,
		VIRTIO_PCI_CAP_ISR_CFG,
		VIRTIO_PCI_CAP_DEVICE_CFG,
		VIRTIO_PCI_CAP_PCI_CFG,
	};
	int i, offset;

	setup_transport(&vs, &pi, queues);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_BLOCK);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10421af4);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) == 0x00421af4);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_NETWORK);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10411af4);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) == 0x00411af4);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_SCSI);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10481af4);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) == 0x00481af4);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_CONSOLE);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10431af4);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) == 0x00431af4);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_9P);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10491af4);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) == 0x00491af4);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_VSOCK);
	ATF_CHECK(g_bar == 2);
	ATF_CHECK(g_bar_type == PCIBAR_MEM64);
	ATF_CHECK(g_bar_size == 0x4000);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) == 0x10531af4);
	ATF_CHECK(pi.pi_cfgdata[PCIR_REVID] == 1);
	offset = 0x40;
	for (i = 0; i < (int)nitems(expected); i++) {
		ATF_REQUIRE(offset != 0);
		ATF_CHECK(pi.pi_cfgdata[offset] == PCIY_VENDOR);
		ATF_CHECK(pi.pi_cfgdata[offset + 2] >=
		    sizeof(struct virtio_pci_cap));
		ATF_CHECK(pi.pi_cfgdata[offset + 3] == expected[i]);
		ATF_CHECK(pi.pi_cfgdata[offset + VIRTIO_PCI_CAP_BAR] == 2);
		offset = pi.pi_cfgdata[offset + 1];
	}
	ATF_CHECK(offset == 0);
}

ATF_TC_WITHOUT_HEAD(features_and_status);
ATF_TC_BODY(features_and_status, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint64_t value;

	setup_transport(&vs, &pi, queues);
	value = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK(value == (0x7 | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 1);
	value = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK(value == (1U | (1U << (50 - 32))));
	ATF_CHECK((value & ((1U << (34 - 32)) | (1U << (38 - 32)) |
	    (1U << (40 - 32)) | (1U << (41 - 32)) |
	    (1U << (43 - 32)))) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 2);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4) == 0);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    3 | VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK(g_applied_features == (VIRTIO_F_VERSION_1 | 3 |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX));
	ATF_CHECK(vs.vs_negotiated_caps == (3 | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK(vs.vs_status == 0);
	ATF_CHECK(vs.vs_modern->driver_features == 0);
}

ATF_TC_WITHOUT_HEAD(ring_features_require_device_opt_in);
ATF_TC_BODY(ring_features_require_device_opt_in, tc)
{
	struct virtio_consts vc;
	struct virtio_softc vs;
	uint64_t features;

	memset(&vs, 0, sizeof(vs));
	vc = test_consts;
	vs.vs_vc = &vc;

	/* A modern device gets VERSION_1, but no optional ring features. */
	vc.vc_hv_caps = 0;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == VIRTIO_F_VERSION_1);

	/* Each optional ring feature is exposed only when the device asks. */
	vc.vc_hv_caps = VIRTIO_RING_F_INDIRECT_DESC;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_RING_F_INDIRECT_DESC));
	vc.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 | VIRTIO_RING_F_EVENT_IDX));

	/* Unsupported device-independent bits remain filtered. */
	vc.vc_hv_caps = VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX | (1ULL << 34);
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX));
}

ATF_TC_WITHOUT_HEAD(queue_and_interrupts);
ATF_TC_BODY(queue_and_interrupts, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(g_notify_count == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_MSIX, 2, 2);
	ATF_CHECK(queues[0].vq_msix_idx == VIRTIO_MSI_NO_VECTOR);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_MSIX, 2, 1);
	ATF_CHECK(queues[0].vq_msix_idx == 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 64);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x5000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x6000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_CHECK(queues[0].vq_enabled == 1);
	ATF_CHECK(!vq_ring_ready(&queues[0]));
	ATF_CHECK(queues[0].vq_qsize == 64);
	ATF_CHECK(queues[0].vq_desc == (void *)&g_guest_mem[0x1000]);
	ATF_CHECK(queues[0].vq_avail == (void *)&g_guest_mem[0x5000]);
	ATF_CHECK(queues[0].vq_used == (void *)&g_guest_mem[0x6000]);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(g_notify_count == 0);
	ATF_CHECK(queues[0].vq_notify_pending);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(vq_ring_ready(&queues[0]));
	ATF_CHECK(g_notify_count == 1);
	ATF_CHECK(!queues[0].vq_notify_pending);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(g_notify_count == 2);
	ATF_CHECK(g_notify_queue == 0);

	vs.vs_isr = VIRTIO_PCI_ISR_INTR | VIRTIO_PCI_ISR_CONFIG;
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_MODERN_ISR_OFF, 1) == 3);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_MODERN_ISR_OFF, 1) == 0);
	ATF_CHECK(g_lintr_deasserts == 1);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1001);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x7000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x8000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_CHECK(queues[1].vq_enabled == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(g_msi_count == 1);
	ATF_CHECK(g_lintr_asserts == 1);
	ATF_CHECK((vs.vs_isr & VIRTIO_PCI_ISR_CONFIG) != 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	queues[0].vq_notify_pending = true;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK(queues[0].vq_enabled == 0);
	ATF_CHECK(!queues[0].vq_notify_pending);
	ATF_CHECK(queues[0].vq_qsize == 256);
	ATF_CHECK(queues[0].vq_desc_gpa == 0);
	ATF_CHECK(queues[0].vq_driver_gpa == 0);
	ATF_CHECK(queues[0].vq_device_gpa == 0);
	ATF_CHECK(queues[0].vq_msix_idx == VIRTIO_MSI_NO_VECTOR);
}

ATF_TC_WITHOUT_HEAD(queue_mapping_is_atomic);
ATF_TC_BODY(queue_mapping_is_atomic, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	struct vring_avail *old_avail;
	struct vring_desc *old_desc;
	struct vring_used *old_used;

	setup_transport(&vs, &pi, queues);
	old_desc = (struct vring_desc *)&g_guest_mem[16];
	old_avail = (struct vring_avail *)&g_guest_mem[32];
	old_used = (struct vring_used *)&g_guest_mem[48];
	queues[1].vq_desc = old_desc;
	queues[1].vq_avail = old_avail;
	queues[1].vq_used = old_used;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x7000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4,
	    sizeof(g_guest_mem));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_CHECK(queues[1].vq_enabled == 0);
	ATF_CHECK(queues[1].vq_desc == old_desc);
	ATF_CHECK(queues[1].vq_avail == old_avail);
	ATF_CHECK(queues[1].vq_used == old_used);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

ATF_TC_WITHOUT_HEAD(config_change_msix);
ATF_TC_BODY(config_change_msix, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	g_msix_enabled = 1;
	vs.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	vi_pci_modern_config_changed(&vs);
	ATF_CHECK(g_msix_count == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);
	vs.vs_msix_cfg_idx = 1;
	for (int i = 0; i < 256; i++)
		vi_pci_modern_config_changed(&vs);
	ATF_CHECK(g_msix_count == 1);
	ATF_CHECK(g_msix_vector == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 2);
}

ATF_TC_WITHOUT_HEAD(queue_size_validation);
ATF_TC_BODY(queue_size_validation, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(queues, 0, sizeof(queues));
	vs.vs_vc = &test_consts;
	vs.vs_pi = &pi;
	vs.vs_queues = queues;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pi.pi_arg = &vs;
	queues[0].vq_qsize = 3;
	queues[1].vq_qsize = 128;
	ATF_CHECK(vi_pci_modern_init(&vs, 2) == EINVAL);
	ATF_CHECK(vs.vs_modern == NULL);
	queues[0].vq_qsize = 0;
	ATF_CHECK(vi_pci_modern_init(&vs, 2) == 0);
	free(vs.vs_modern);
}

ATF_TC_WITHOUT_HEAD(pci_cfg_window);
ATF_TC_BODY(pci_cfg_window, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t value;
	int capoff, dataoff;

	setup_transport(&vs, &pi, queues);
	capoff = vs.vs_modern->pci_cfg_capoff;
	dataoff = capoff + offsetof(struct virtio_pci_cfg_cap, pci_cfg_data);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_BAR, 1, 2) == 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 4,
	    VIRTIO_PCI_COMMON_NUMQ) == 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_LENGTH, 4, 2) == 0);
	value = 0;
	ATF_REQUIRE(vi_pci_modern_cfgread(&pi, dataoff, 2, &value) == 0);
	ATF_CHECK(value == 2);

	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 4,
	    VIRTIO_PCI_COMMON_Q_SELECT) == 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi, dataoff, 2, 1) == 0);
	ATF_CHECK(vs.vs_curq == 1);

	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 4, 3) == 0);
	value = 0;
	ATF_REQUIRE(vi_pci_modern_cfgread(&pi, dataoff, 2, &value) == 0);
	ATF_CHECK(value == UINT32_MAX);
}

ATF_TC_WITHOUT_HEAD(register_edges);
ATF_TC_BODY(register_edges, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t seed;
	int i, size;

	setup_transport(&vs, &pi, queues);
	ATF_CHECK(vi_pci_modern_read(&pi, 0, VIRTIO_PCI_COMMON_NUMQ, 2) ==
	    UINT16_MAX);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2,
	    UINT16_MAX);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2) ==
	    0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 63);
	ATF_CHECK(queues[0].vq_qsize == 256);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 512);
	ATF_CHECK(queues[0].vq_qsize == 256);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCHI, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_DESCHI, 4) == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_DESCLO, 4) == 0x1000);

	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_DEVICE_OFF, 4,
	    0x12345678);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_MODERN_DEVICE_OFF, 4) ==
	    0x12345678);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF + 1, 4) == UINT32_MAX);

	/* Deterministic hostile-access sweep; ASan checks every range decision. */
	seed = 0x5eed1234;
	for (i = 0; i < 10000; i++) {
		seed = seed * 1664525U + 1013904223U;
		size = 1 << ((seed >> 16) & 3);
		(void)vi_pci_modern_read(&pi, 2, seed & 0x4fff, size);
		vi_pci_modern_write(&pi, 2, seed & 0x4fff, size, seed);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transport_policy);
	ATF_TP_ADD_TC(tp, capability_chain);
	ATF_TP_ADD_TC(tp, features_and_status);
	ATF_TP_ADD_TC(tp, ring_features_require_device_opt_in);
	ATF_TP_ADD_TC(tp, queue_and_interrupts);
	ATF_TP_ADD_TC(tp, queue_mapping_is_atomic);
	ATF_TP_ADD_TC(tp, config_change_msix);
	ATF_TP_ADD_TC(tp, queue_size_validation);
	ATF_TP_ADD_TC(tp, pci_cfg_window);
	ATF_TP_ADD_TC(tp, register_edges);
	return (atf_no_error());
}
