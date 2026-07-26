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
#include "virtio_1_4_spec.h"
#include <bhyve/virtio.h>
#define	MOCK_VIRTIO_H
#include "virtio_pci_modern.c"

/*
 * The device under test above was compiled with the production definitions.
 * From this point onward, every protocol value used by the test resolves to
 * the independent VirtIO 1.4 oracle.  A wrong production constant therefore
 * cannot make both the implementation and its test pass.
 */
#undef VIRTIO_CONFIG_STATUS_ACK
#define	VIRTIO_CONFIG_STATUS_ACK	VIRTIO14_STATUS_ACKNOWLEDGE
#undef VIRTIO_CONFIG_STATUS_DRIVER
#define	VIRTIO_CONFIG_STATUS_DRIVER	VIRTIO14_STATUS_DRIVER
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_FEATURES_OK
#define	VIRTIO_CONFIG_S_FEATURES_OK	VIRTIO14_STATUS_FEATURES_OK
#undef VIRTIO_CONFIG_STATUS_SUSPEND
#define	VIRTIO_CONFIG_STATUS_SUSPEND	VIRTIO14_STATUS_SUSPEND
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_F_NOTIFY_ON_EMPTY
#define	VIRTIO_F_NOTIFY_ON_EMPTY	VIRTIO14_F_NOTIFY_ON_EMPTY
#undef VIRTIO_F_ANY_LAYOUT
#define	VIRTIO_F_ANY_LAYOUT		VIRTIO14_F_ANY_LAYOUT
#undef VIRTIO_RING_F_INDIRECT_DESC
#define	VIRTIO_RING_F_INDIRECT_DESC	VIRTIO14_F_RING_INDIRECT_DESC
#undef VIRTIO_RING_F_EVENT_IDX
#define	VIRTIO_RING_F_EVENT_IDX		VIRTIO14_F_RING_EVENT_IDX
#undef VIRTIO_F_VERSION_1
#define	VIRTIO_F_VERSION_1		VIRTIO14_F_VERSION_1
#undef VIRTIO_F_ACCESS_PLATFORM
#define	VIRTIO_F_ACCESS_PLATFORM	VIRTIO14_F_ACCESS_PLATFORM
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED		VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER		VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_ORDER_PLATFORM
#define	VIRTIO_F_ORDER_PLATFORM		VIRTIO14_F_ORDER_PLATFORM
#undef VIRTIO_F_SR_IOV
#define	VIRTIO_F_SR_IOV			VIRTIO14_F_SR_IOV
#undef VIRTIO_F_NOTIFICATION_DATA
#define	VIRTIO_F_NOTIFICATION_DATA	VIRTIO14_F_NOTIFICATION_DATA
#undef VIRTIO_F_NOTIF_CONFIG_DATA
#define	VIRTIO_F_NOTIF_CONFIG_DATA	VIRTIO14_F_NOTIF_CONFIG_DATA
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_F_ADMIN_VQ
#define	VIRTIO_F_ADMIN_VQ		VIRTIO14_F_ADMIN_VQ
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND

#define	TEST_DEVICE_FEATURES_LOW					\
	(VIRTIO14_NET_F_CSUM | VIRTIO14_NET_F_GUEST_CSUM |	\
	 VIRTIO14_NET_F_CTRL_GUEST_OFFLOADS)
#define	TEST_DRIVER_FEATURES_LOW					\
	(VIRTIO14_NET_F_CSUM | VIRTIO14_NET_F_GUEST_CSUM)
#undef VIRTIO_PCI_ISR_INTR
#define	VIRTIO_PCI_ISR_INTR		VIRTIO14_ISR_QUEUE
#undef VIRTIO_PCI_ISR_CONFIG
#define	VIRTIO_PCI_ISR_CONFIG		VIRTIO14_ISR_CONFIG
#undef VIRTIO_MSI_NO_VECTOR
#define	VIRTIO_MSI_NO_VECTOR		VIRTIO14_MSI_NO_VECTOR

#undef VIRTIO_PCI_CAP_COMMON_CFG
#define	VIRTIO_PCI_CAP_COMMON_CFG	VIRTIO14_PCI_CAP_COMMON_CFG
#undef VIRTIO_PCI_CAP_NOTIFY_CFG
#define	VIRTIO_PCI_CAP_NOTIFY_CFG	VIRTIO14_PCI_CAP_NOTIFY_CFG
#undef VIRTIO_PCI_CAP_ISR_CFG
#define	VIRTIO_PCI_CAP_ISR_CFG		VIRTIO14_PCI_CAP_ISR_CFG
#undef VIRTIO_PCI_CAP_DEVICE_CFG
#define	VIRTIO_PCI_CAP_DEVICE_CFG	VIRTIO14_PCI_CAP_DEVICE_CFG
#undef VIRTIO_PCI_CAP_PCI_CFG
#define	VIRTIO_PCI_CAP_PCI_CFG		VIRTIO14_PCI_CAP_PCI_CFG
#undef VIRTIO_PCI_CAP_BAR
#define	VIRTIO_PCI_CAP_BAR		VIRTIO14_PCI_CAP_BAR_OFF
#undef VIRTIO_PCI_CAP_OFFSET
#define	VIRTIO_PCI_CAP_OFFSET		VIRTIO14_PCI_CAP_OFFSET_OFF
#undef VIRTIO_PCI_CAP_LENGTH
#define	VIRTIO_PCI_CAP_LENGTH		VIRTIO14_PCI_CAP_LENGTH_OFF

#undef VIRTIO_PCI_COMMON_DFSELECT
#define	VIRTIO_PCI_COMMON_DFSELECT \
	VIRTIO14_COMMON_DEVICE_FEATURE_SELECT
#undef VIRTIO_PCI_COMMON_DF
#define	VIRTIO_PCI_COMMON_DF		VIRTIO14_COMMON_DEVICE_FEATURE
#undef VIRTIO_PCI_COMMON_GFSELECT
#define	VIRTIO_PCI_COMMON_GFSELECT \
	VIRTIO14_COMMON_DRIVER_FEATURE_SELECT
#undef VIRTIO_PCI_COMMON_GF
#define	VIRTIO_PCI_COMMON_GF		VIRTIO14_COMMON_DRIVER_FEATURE
#undef VIRTIO_PCI_COMMON_NUMQ
#define	VIRTIO_PCI_COMMON_NUMQ		VIRTIO14_COMMON_NUM_QUEUES
#undef VIRTIO_PCI_COMMON_STATUS
#define	VIRTIO_PCI_COMMON_STATUS	VIRTIO14_COMMON_DEVICE_STATUS
#undef VIRTIO_PCI_COMMON_CFGGENERATION
#define	VIRTIO_PCI_COMMON_CFGGENERATION \
	VIRTIO14_COMMON_CONFIG_GENERATION
#undef VIRTIO_PCI_COMMON_Q_SELECT
#define	VIRTIO_PCI_COMMON_Q_SELECT	VIRTIO14_COMMON_QUEUE_SELECT
#undef VIRTIO_PCI_COMMON_Q_SIZE
#define	VIRTIO_PCI_COMMON_Q_SIZE	VIRTIO14_COMMON_QUEUE_SIZE
#undef VIRTIO_PCI_COMMON_Q_MSIX
#define	VIRTIO_PCI_COMMON_Q_MSIX	VIRTIO14_COMMON_QUEUE_MSIX_VECTOR
#undef VIRTIO_PCI_COMMON_Q_ENABLE
#define	VIRTIO_PCI_COMMON_Q_ENABLE	VIRTIO14_COMMON_QUEUE_ENABLE
#undef VIRTIO_PCI_COMMON_Q_DESCLO
#define	VIRTIO_PCI_COMMON_Q_DESCLO	VIRTIO14_COMMON_QUEUE_DESC
#undef VIRTIO_PCI_COMMON_Q_DESCHI
#define	VIRTIO_PCI_COMMON_Q_DESCHI	(VIRTIO14_COMMON_QUEUE_DESC + 4)
#undef VIRTIO_PCI_COMMON_Q_AVAILLO
#define	VIRTIO_PCI_COMMON_Q_AVAILLO	VIRTIO14_COMMON_QUEUE_DRIVER
#undef VIRTIO_PCI_COMMON_Q_USEDLO
#define	VIRTIO_PCI_COMMON_Q_USEDLO	VIRTIO14_COMMON_QUEUE_DEVICE
#undef VIRTIO_PCI_COMMON_Q_RESET
#define	VIRTIO_PCI_COMMON_Q_RESET	VIRTIO14_COMMON_QUEUE_RESET

#undef VIRTIO_ID_NETWORK
#define	VIRTIO_ID_NETWORK		VIRTIO14_DEVICE_NETWORK
#undef VIRTIO_ID_BLOCK
#define	VIRTIO_ID_BLOCK			VIRTIO14_DEVICE_BLOCK
#undef VIRTIO_ID_CONSOLE
#define	VIRTIO_ID_CONSOLE		VIRTIO14_DEVICE_CONSOLE
#undef VIRTIO_ID_SCSI
#define	VIRTIO_ID_SCSI			VIRTIO14_DEVICE_SCSI
#undef VIRTIO_ID_9P
#define	VIRTIO_ID_9P			VIRTIO14_DEVICE_9P
#undef VIRTIO_ID_VSOCK
#define	VIRTIO_ID_VSOCK			VIRTIO14_DEVICE_VSOCK

struct nvlist {
	int unused;
};

static const char *g_transport;
static uint8_t g_guest_mem[128 * 1024];
static size_t g_guest_mem_limit = sizeof(g_guest_mem);
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
static int g_qenable_count;
static int g_qenable_error;
static int g_qreset_count;
static int g_qreset_error;
static bool g_qreset_cross_reset;
static uint64_t g_qreset_generation;
static uint64_t g_applied_features;
static int g_apply_features_error;
static pthread_mutex_t g_reset_sync_mtx;
static pthread_cond_t g_reset_sync_cv;
static bool g_reset_callback_entered;
static bool g_reset_callback_fail;
static bool g_reset_callback_release;
static int g_suspend_count;
static int g_suspend_error;
static int g_resume_count;
static int g_resume_error;
static bool g_suspend_saw_queue_fenced;
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

	if (gpa > g_guest_mem_limit || len > g_guest_mem_limit - gpa)
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

	if (vs->vs_resetting) {
		vs->vs_reset_failed = true;
		return;
	}
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
	if (!vq->vq_enabled || vq_is_resetting(vq))
		return;
	if (vs->vs_quiescing || vs->vs_suspended ||
	    vs->vs_checkpoint_paused)
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

void
vi_pci_quiesce_enter(struct virtio_softc *vs)
{

	atomic_fetch_add(&vs->vs_quiescing, 1);
}

void
vi_pci_quiesce_exit(struct virtio_softc *vs)
{
	unsigned int owners;

	owners = atomic_fetch_sub(&vs->vs_quiescing, 1);
	ATF_REQUIRE_MSG(owners != 0, "unbalanced quiesce ownership");
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
test_blocking_reset(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	pthread_mutex_unlock(vs->vs_mtx);
	pthread_mutex_lock(&g_reset_sync_mtx);
	g_reset_callback_entered = true;
	pthread_cond_broadcast(&g_reset_sync_cv);
	while (!g_reset_callback_release)
		pthread_cond_wait(&g_reset_sync_cv, &g_reset_sync_mtx);
	pthread_mutex_unlock(&g_reset_sync_mtx);
	pthread_mutex_lock(vs->vs_mtx);
	test_reset(arg);
	if (g_reset_callback_fail)
		vi_set_needs_reset(vs);
}

static void *
test_write_device_reset(void *arg)
{
	struct pci_devinst *pi;

	pi = arg;
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	return (NULL);
}

static int
test_apply_features(void *arg __unused, uint64_t features)
{

	g_applied_features = features;
	return (g_apply_features_error);
}

static int
test_qenable(void *arg __unused, struct vqueue_info *vq __unused)
{

	g_qenable_count++;
	return (g_qenable_error);
}

static int
test_qreset(void *arg, struct vqueue_info *vq,
    uint64_t generation)
{

	g_qreset_count++;
	g_qreset_generation = generation;
	if (g_qreset_cross_reset) {
		/*
		 * vi_modern_status_write() clears transport status before
		 * invoking the device reset callback.
		 */
		((struct virtio_softc *)arg)->vs_status = 0;
		test_reset(arg);
		/*
		 * Model another vCPU beginning configuration of the new device
		 * incarnation while a backend callback had dropped vs_mtx.
		 */
		vq->vq_qsize = 64;
		vq->vq_desc_gpa = 0x3000;
	}
	return (g_qreset_error);
}

static int
test_suspend(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	g_suspend_count++;
	g_suspend_saw_queue_fenced = !vq_ring_ready(&vs->vs_queues[0]);
	return (g_suspend_error);
}

static int
test_resume(void *arg __unused)
{

	g_resume_count++;
	return (g_resume_error);
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
	.vc_qenable = test_qenable,
	.vc_qreset = test_qreset,
	.vc_hv_caps = TEST_DEVICE_FEATURES_LOW |
	    VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_NOTIFY_ON_EMPTY |
	    VIRTIO_F_ANY_LAYOUT |
	    VIRTIO_F_ACCESS_PLATFORM | VIRTIO_F_RING_PACKED |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_ORDER_PLATFORM | VIRTIO_F_SR_IOV |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_F_RING_RESET | VIRTIO_F_ADMIN_VQ | VIRTIO_F_SUSPEND |
	    VIRTIO14_DEVICE_FEATURE_HIGH_FIRST,
};

static void
setup_transport(struct virtio_softc *vs, struct pci_devinst *pi,
    struct vqueue_info *queues)
{

	memset(vs, 0, sizeof(*vs));
	memset(pi, 0, sizeof(*pi));
	memset(queues, 0, sizeof(*queues) * test_consts.vc_nvq);
	memset(g_guest_mem, 0, sizeof(g_guest_mem));
	g_guest_mem_limit = sizeof(g_guest_mem);
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
	g_qenable_count = 0;
	g_qenable_error = 0;
	g_qreset_count = 0;
	g_qreset_error = 0;
	g_qreset_cross_reset = false;
	g_qreset_generation = 0;
	g_applied_features = 0;
	g_apply_features_error = 0;
	g_suspend_count = 0;
	g_suspend_error = 0;
	g_resume_count = 0;
	g_resume_error = 0;
	g_suspend_saw_queue_fenced = false;
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
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_BLOCK) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK((pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) >> 16) >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_NETWORK);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_NETWORK) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK((pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) >> 16) >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_SCSI);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_SCSI) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK((pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) >> 16) >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_CONSOLE);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_CONSOLE) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK((pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) >> 16) >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_9P);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_9P) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK((pci_get_cfgdata32(&pi, PCIR_SUBVEND_0) >> 16) >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	vi_pci_modern_set_identity(&vs, VIRTIO_ID_VSOCK);
	ATF_CHECK(g_bar == 2);
	ATF_CHECK(g_bar_type == PCIBAR_MEM64);
	ATF_CHECK(g_bar_size == 0x4000);
	ATF_CHECK(pci_get_cfgdata32(&pi, PCIR_VENDOR) ==
	    ((VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_VSOCK) <<
	    16 | VIRTIO14_PCI_VENDOR_ID));
	ATF_CHECK(pi.pi_cfgdata[PCIR_REVID] == VIRTIO14_PCI_REVISION);
	offset = 0x40;
	for (i = 0; i < (int)nitems(expected); i++) {
		ATF_REQUIRE(offset != 0);
		ATF_CHECK(pi.pi_cfgdata[offset] == PCIY_VENDOR);
		ATF_CHECK(pi.pi_cfgdata[offset + 2] >=
		    VIRTIO14_PCI_CAP_SIZE);
		ATF_CHECK(pi.pi_cfgdata[offset + 3] == expected[i]);
		ATF_CHECK(pi.pi_cfgdata[offset + 3] !=
		    VIRTIO14_PCI_CAP_SHARED_MEMORY_CFG);
		ATF_CHECK(pi.pi_cfgdata[offset + 3] !=
		    VIRTIO14_PCI_CAP_VENDOR_CFG);
		ATF_CHECK(pi.pi_cfgdata[offset + VIRTIO_PCI_CAP_BAR] == 2);
		if (expected[i] == VIRTIO_PCI_CAP_COMMON_CFG)
			ATF_CHECK(pci_get_cfgdata32(&pi, offset +
			    VIRTIO_PCI_CAP_LENGTH) ==
			    VIRTIO_PCI_COMMON_Q_RESET +
			    VIRTIO14_CONFIG_FIELD_U16_SIZE);
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
	ATF_CHECK(value == (TEST_DEVICE_FEATURES_LOW |
	    VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 1);
	value = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK(value == ((uint32_t)(VIRTIO_F_VERSION_1 >> 32) |
	    (uint32_t)(VIRTIO_F_IN_ORDER >> 32) |
	    (uint32_t)(VIRTIO_F_NOTIFICATION_DATA >> 32) |
	    (uint32_t)(VIRTIO_F_RING_RESET >> 32) |
	    (uint32_t)(VIRTIO14_DEVICE_FEATURE_HIGH_FIRST >> 32)));
	ATF_CHECK((value & (uint32_t)((VIRTIO_F_ACCESS_PLATFORM |
	    VIRTIO_F_RING_PACKED | VIRTIO_F_ORDER_PLATFORM |
	    VIRTIO_F_SR_IOV | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_F_ADMIN_VQ | VIRTIO_F_SUSPEND) >> 32)) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 2);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4) == 0);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    TEST_DRIVER_FEATURES_LOW | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK(g_notify_count == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 | VIRTIO_F_RING_RESET) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK(g_applied_features == (VIRTIO_F_VERSION_1 |
	    TEST_DRIVER_FEATURES_LOW |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX |
	    VIRTIO_F_RING_RESET));
	ATF_CHECK(vs.vs_negotiated_caps == (VIRTIO_F_VERSION_1 |
	    TEST_DRIVER_FEATURES_LOW |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX |
	    VIRTIO_F_RING_RESET));

	/*
	 * Nonzero status writes cannot clear accepted bits.  SUSPEND is a
	 * document-defined status bit, but this device does not advertise its
	 * feature; distinguish that case from the actually reserved bit.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO14_STATUS_SUSPEND |
	    VIRTIO14_STATUS_RESERVED_MASK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK((vs.vs_status & VIRTIO14_STATUS_SUSPEND) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO14_STATUS_RESERVED_MASK) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4, 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_GF, 4) ==
	    (TEST_DRIVER_FEATURES_LOW | VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	ATF_CHECK((vs.vs_status & (VIRTIO_CONFIG_S_FEATURES_OK |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK)) ==
	    (VIRTIO_CONFIG_S_FEATURES_OK |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK));

	/* Invalid driver feature bits must make the device reject FEATURES_OK. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    TEST_DRIVER_FEATURES_LOW | VIRTIO14_DEVICE_FEATURE_LOW_LAST);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_GF, 4) ==
	    (TEST_DRIVER_FEATURES_LOW |
	    VIRTIO14_DEVICE_FEATURE_LOW_LAST));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK(g_notify_count == 0);

	/* Rewriting the page with a valid subset permits negotiation. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    TEST_DRIVER_FEATURES_LOW);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK(g_applied_features == (VIRTIO_F_VERSION_1 |
	    TEST_DRIVER_FEATURES_LOW));

	/*
	 * A device-specific rejection must be observable by clearing
	 * FEATURES_OK.  A combined FEATURES_OK|DRIVER_OK write must not bypass
	 * that rejection or start queues.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    TEST_DRIVER_FEATURES_LOW);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
	g_apply_features_error = EINVAL;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	g_apply_features_error = 0;

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

	/*
	 * The generic filter must preserve bits whose interpretation depends
	 * on the transport and device.  In particular, 41 and 42 are network
	 * feature bits only for the legacy interface, while 41 is ADMIN_VQ for
	 * a modern owner device.
	 */
	ATF_CHECK((VIRTIO_TRANSPORT_F_MASK & VIRTIO_F_ADMIN_VQ) == 0);
	ATF_CHECK((VIRTIO_TRANSPORT_F_MASK &
	    VIRTIO14_NET_F_GUEST_RSC6) == 0);
	ATF_CHECK((VIRTIO_TRANSPORT_F_MASK & VIRTIO_F_RING_RESET) != 0);
	ATF_CHECK((VIRTIO_TRANSPORT_F_MASK & VIRTIO_F_SUSPEND) != 0);

	/*
	 * The modern transport owns VERSION_1 and NOTIFICATION_DATA; no ring
	 * feature is added unless the device model opts in.
	 */
	vc.vc_hv_caps = 0;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA));
	ATF_CHECK_EQ(vi_modern_common_cfg_size(&vs),
	    VIRTIO14_COMMON_BASE_SIZE);
	ATF_CHECK((features & VIRTIO14_F_NOTIF_CONFIG_DATA) == 0);

	/* Each optional ring feature is exposed only when the device asks. */
	vc.vc_hv_caps = VIRTIO_RING_F_INDIRECT_DESC;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_RING_F_INDIRECT_DESC));
	vc.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_RING_F_EVENT_IDX));
	vc.vc_hv_caps = VIRTIO_F_RING_RESET;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_RING_RESET));
	ATF_CHECK_EQ(vi_modern_common_cfg_size(&vs),
	    VIRTIO14_COMMON_QUEUE_RESET + VIRTIO14_CONFIG_FIELD_U16_SIZE);
	vc.vc_hv_caps = VIRTIO_F_IN_ORDER;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_NOTIFICATION_DATA));
	vc.vc_hv_caps = VIRTIO14_NET_F_GUEST_RSC6;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA));

	/* Unsupported device-independent bits remain filtered. */
	vc.vc_hv_caps = VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_RING_RESET |
	    VIRTIO_F_ACCESS_PLATFORM | VIRTIO_F_RING_PACKED |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_ORDER_PLATFORM | VIRTIO_F_SR_IOV |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_F_ADMIN_VQ | VIRTIO_F_SUSPEND;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_F_RING_RESET));
}

ATF_TC_WITHOUT_HEAD(unsupported_optional_features);
ATF_TC_BODY(unsupported_optional_features, tc)
{
	static const struct {
		uint64_t bit;
		const char *name;
	} unsupported[] = {
		{ VIRTIO14_F_ACCESS_PLATFORM, "ACCESS_PLATFORM" },
		{ VIRTIO14_F_RING_PACKED, "RING_PACKED" },
		{ VIRTIO14_F_ORDER_PLATFORM, "ORDER_PLATFORM" },
		{ VIRTIO14_F_SR_IOV, "SR_IOV" },
		{ VIRTIO14_F_NOTIF_CONFIG_DATA, "NOTIF_CONFIG_DATA" },
		{ VIRTIO14_F_ADMIN_VQ, "ADMIN_VQ" },
	};
	struct virtio_softc vs;
	struct virtio_consts vc;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t offered;

	for (size_t i = 0; i < nitems(unsupported); i++) {
		setup_transport(&vs, &pi, queues);
		vc = test_consts;
		vc.vc_hv_caps = unsupported[i].bit;
		vs.vs_vc = &vc;

		/*
		 * Supplying an unsupported bit in a device model cannot bypass
		 * the common transport policy, and a driver which forces that
		 * bit cannot complete FEATURES_OK.  Values come solely from the
		 * independent VirtIO 1.4 oracle above.
		 */
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 1);
		offered = vi_pci_modern_read(&pi, 2,
		    VIRTIO_PCI_COMMON_DF, 4);
		ATF_CHECK_MSG((offered &
		    (uint32_t)(unsupported[i].bit >> 32)) == 0,
		    "%s was advertised", unsupported[i].name);

		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
		    (uint32_t)((VIRTIO14_F_VERSION_1 |
		    unsupported[i].bit) >> 32));
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
		    VIRTIO14_STATUS_FEATURES_OK |
		    VIRTIO14_STATUS_DRIVER_OK);
		ATF_CHECK_MSG((vs.vs_status &
		    VIRTIO14_STATUS_FEATURES_OK) == 0,
		    "%s forced negotiation was accepted", unsupported[i].name);
		ATF_CHECK_MSG((vs.vs_status &
		    VIRTIO14_STATUS_DRIVER_OK) == 0,
		    "%s made the device live", unsupported[i].name);
		free(vs.vs_modern);
		vs.vs_modern = NULL;
		ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
	}
}

static void
negotiate_ring_reset(struct virtio_softc *vs, struct pci_devinst *pi)
{

	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 | VIRTIO_F_RING_RESET) >> 32));
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE((vs->vs_negotiated_caps & VIRTIO_F_RING_RESET) != 0);
}

static void
negotiate_suspend(struct virtio_softc *vs, struct pci_devinst *pi)
{

	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 | VIRTIO_F_SUSPEND) >> 32));
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_REQUIRE((vs->vs_negotiated_caps & VIRTIO_F_SUSPEND) != 0);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE((vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
}

static void
configure_queue0(struct pci_devinst *pi)
{

	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 64);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x5000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x6000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
}

ATF_TC_WITHOUT_HEAD(device_suspend_lifecycle);
ATF_TC_BODY(device_suspend_lifecycle, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t config_value;
	uint64_t value;
	int interrupts;

	setup_transport(&vs, &pi, queues);
	vc = test_consts;
	vc.vc_suspend = test_suspend;
	vc.vc_resume_device = test_resume;
	vc.vc_hv_caps |= VIRTIO_F_SUSPEND;
	vs.vs_vc = &vc;

	/* The feature is visible only when both lifecycle hooks exist. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 1);
	value = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK((value & (uint32_t)(VIRTIO_F_SUSPEND >> 32)) != 0);
	vc.vc_resume_device = NULL;
	ATF_CHECK((vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4) &
	    (uint32_t)(VIRTIO_F_SUSPEND >> 32)) == 0);
	vc.vc_resume_device = test_resume;

	/* A request before complete initialization is ignored. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_suspend_count, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_SUSPEND) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);

	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vi_pci_notify_queue(&vs, 0);
	ATF_REQUIRE_EQ(g_notify_count, 1);

	/*
	 * Guest lifecycle and checkpoint transitions can overlap.  Releasing
	 * one owner must not reopen the queue while another owner is still
	 * draining or serializing it.
	 */
	vi_pci_quiesce_enter(&vs);
	vi_pci_quiesce_enter(&vs);
	ATF_CHECK_EQ(vs.vs_quiescing, 2);
	ATF_CHECK(!vq_ring_ready(&queues[0]));
	vi_pci_quiesce_exit(&vs);
	ATF_CHECK_EQ(vs.vs_quiescing, 1);
	ATF_CHECK(!vq_ring_ready(&queues[0]));
	vi_pci_quiesce_exit(&vs);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(vq_ring_ready(&queues[0]));

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_suspend_count, 1);
	ATF_CHECK(g_suspend_saw_queue_fenced);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK(!vs.vs_quiescing);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_SUSPEND) != 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);

	/* Queue and device-configuration writes are inert while suspended. */
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK_EQ(g_notify_count, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_DEVICE_OFF, 4,
	    0xfeedface);
	memcpy(&config_value, g_device_config, sizeof(config_value));
	ATF_CHECK_EQ(config_value, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 1);
	ATF_CHECK_EQ(vs.vs_curq, 0);

	/* A config change is latched, not signalled or consumed. */
	interrupts = g_msi_count + g_msix_count;
	vi_pci_modern_config_changed(&vs);
	ATF_CHECK_EQ(g_msi_count + g_msix_count, interrupts);
	value = vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1), value);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(g_resume_count, 1);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_SUSPEND) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
	ATF_CHECK_EQ(g_msi_count + g_msix_count, interrupts + 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) != value);

	/* Both lifecycle failures require a full device reset. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	g_suspend_error = EIO;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!vs.vs_suspended);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	g_suspend_error = 0;
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	g_resume_error = EIO;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vs.vs_suspended);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK_EQ(vs.vs_status, 0);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK(!vs.vs_quiescing);
}

ATF_TC_WITHOUT_HEAD(queue_reset_sync);
ATF_TC_BODY(queue_reset_sync, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint64_t generation;

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);
	ATF_REQUIRE(queues[0].vq_enabled == 1);
	ATF_CHECK(g_qenable_count == 1);

	/* The register is inert until the feature has been negotiated. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);
	ATF_CHECK(queues[0].vq_enabled == 1);
	ATF_CHECK(g_qreset_count == 0);

	negotiate_ring_reset(&vs, &pi);
	generation = queues[0].vq_generation;
	queues[0].vq_last_avail = 7;
	queues[0].vq_next_used = 5;
	queues[0].vq_save_used = 4;
	queues[0].vq_notify_pending = true;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);

	ATF_CHECK(g_qreset_count == 1);
	ATF_CHECK(g_qreset_generation == generation + 1);
	ATF_CHECK(queues[0].vq_generation == generation + 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_RESET, 2) == 0);
	ATF_CHECK(queues[0].vq_enabled == 0);
	ATF_CHECK(!queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_qsize == 256);
	ATF_CHECK(queues[0].vq_desc == NULL);
	ATF_CHECK(queues[0].vq_avail == NULL);
	ATF_CHECK(queues[0].vq_used == NULL);
	ATF_CHECK(queues[0].vq_desc_gpa == 0);
	ATF_CHECK(queues[0].vq_driver_gpa == 0);
	ATF_CHECK(queues[0].vq_device_gpa == 0);
	ATF_CHECK(queues[0].vq_msix_idx == VIRTIO_MSI_NO_VECTOR);
	ATF_CHECK(!queues[0].vq_notify_pending);

	/* The driver can provide a completely different queue after reset. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 128);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x2000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x7000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x8000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_CHECK(queues[0].vq_enabled == 1);
	ATF_CHECK(queues[0].vq_qsize == 128);
	ATF_CHECK(queues[0].vq_reset == 0);
	ATF_CHECK(g_qenable_count == 2);
}

ATF_TC_WITHOUT_HEAD(queue_reset_async);
ATF_TC_BODY(queue_reset_async, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint64_t generation;

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);
	negotiate_ring_reset(&vs, &pi);
	g_qreset_error = EINPROGRESS;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);
	generation = g_qreset_generation;

	ATF_CHECK(queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_reset == 1);
	ATF_CHECK(queues[0].vq_enabled == 1);
	ATF_CHECK(!vq_ring_ready(&queues[0]));
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_RESET, 2) == 1);

	/* Queue configuration and notifications are frozen while draining. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x3000);
	ATF_CHECK(queues[0].vq_desc_gpa == 0x1000);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(g_notify_count == 0);
	vi_pci_modern_queue_reset_complete(&queues[0], generation - 1, 0);
	ATF_CHECK(queues[0].vq_resetting);

	vi_pci_modern_queue_reset_complete(&queues[0], generation, 0);
	ATF_CHECK(!queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_reset == 0);
	ATF_CHECK(queues[0].vq_enabled == 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_failure);
ATF_TC_BODY(queue_reset_failure, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint64_t generation;

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);
	negotiate_ring_reset(&vs, &pi);
	g_qreset_error = EIO;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);
	generation = g_qreset_generation;
	ATF_CHECK(queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_reset == 1);
	ATF_CHECK(queues[0].vq_enabled == 1);
	ATF_CHECK(!vq_ring_ready(&queues[0]));
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_RESET, 2) == 1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK((vs.vs_isr & VIRTIO_PCI_ISR_CONFIG) != 0);

	/* Failed reset state is immutable, including to a late completion. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 128);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x2000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(queues[0].vq_qsize == 64);
	ATF_CHECK(queues[0].vq_desc_gpa == 0x1000);
	ATF_CHECK(g_qenable_count == 1);
	ATF_CHECK(g_notify_count == 0);
	vi_pci_modern_queue_reset_complete(&queues[0], generation, 0);
	ATF_CHECK(queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_reset == 1);

	/* The required full device reset restores the queue defaults. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK(!queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_reset == 0);
	ATF_CHECK(queues[0].vq_enabled == 0);
	ATF_CHECK(queues[0].vq_qsize == 256);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_crosses_full_reset);
ATF_TC_BODY(queue_reset_crosses_full_reset, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);
	negotiate_ring_reset(&vs, &pi);
	g_qreset_cross_reset = true;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);

	ATF_CHECK(vs.vs_status == 0);
	ATF_CHECK(!queues[0].vq_resetting);
	ATF_CHECK(queues[0].vq_qsize == 64);
	ATF_CHECK(queues[0].vq_desc_gpa == 0x3000);
}

ATF_TC_WITHOUT_HEAD(device_reset_waits_for_backend);
ATF_TC_BODY(device_reset_waits_for_backend, tc)
{
	struct virtio_consts vc;
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	pthread_mutex_t device_mtx;
	pthread_t reset_thread;

	setup_transport(&vs, &pi, queues);
	vc = test_consts;
	vc.vc_reset = test_blocking_reset;
	vs.vs_vc = &vc;
	ATF_REQUIRE(pthread_mutex_init(&device_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&g_reset_sync_mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&g_reset_sync_cv, NULL) == 0);
	vs.vs_mtx = &device_mtx;
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs.vs_curq = 1;
	g_reset_callback_entered = false;
	g_reset_callback_fail = true;
	g_reset_callback_release = false;

	ATF_REQUIRE(pthread_create(&reset_thread, NULL,
	    test_write_device_reset, &pi) == 0);
	pthread_mutex_lock(&g_reset_sync_mtx);
	while (!g_reset_callback_entered)
		pthread_cond_wait(&g_reset_sync_cv, &g_reset_sync_mtx);
	pthread_mutex_unlock(&g_reset_sync_mtx);

	/* Zero is not visible and queue configuration is frozen while draining. */
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_STATUS, 1) ==
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	ATF_CHECK_EQ(vs.vs_curq, 1);

	pthread_mutex_lock(&g_reset_sync_mtx);
	g_reset_callback_release = true;
	pthread_cond_broadcast(&g_reset_sync_cv);
	pthread_mutex_unlock(&g_reset_sync_mtx);
	ATF_REQUIRE(pthread_join(reset_thread, NULL) == 0);
	ATF_CHECK_EQ(vs.vs_status, 0);
	ATF_CHECK(!vs.vs_resetting);
	ATF_CHECK(vs.vs_reset_failed);
	ATF_CHECK_EQ(vs.vs_curq, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	ATF_CHECK((vs.vs_status & (VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_S_NEEDS_RESET)) ==
	    (VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_S_NEEDS_RESET));

	ATF_REQUIRE(pthread_cond_destroy(&g_reset_sync_cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&g_reset_sync_mtx) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&device_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(queue_reset_state_soak);
ATF_TC_BODY(queue_reset_state_soak, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	struct vqueue_info *vq;
	uint64_t generation;
	int i, q;

	setup_transport(&vs, &pi, queues);
	negotiate_ring_reset(&vs, &pi);
	for (i = 0; i < 4096; i++) {
		q = i & 1;
		vq = &queues[q];
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, q);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 64);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4,
		    0x1000 + q * 0x1000);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4,
		    0x5000 + q * 0x1000);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4,
		    0x8000 + q * 0x1000);
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
		ATF_REQUIRE(vq->vq_enabled == 1);

		g_qreset_error = (i % 3) == 0 ? EINPROGRESS : 0;
		vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);
		generation = g_qreset_generation;
		if (g_qreset_error == EINPROGRESS) {
			ATF_REQUIRE(vq->vq_resetting);
			vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2,
			    q);
			vi_pci_modern_queue_reset_complete(vq, generation - 1,
			    0);
			ATF_REQUIRE(vq->vq_resetting);
			if ((i % 31) == 0) {
				vi_pci_modern_write(&pi, 2,
				    VIRTIO_PCI_COMMON_STATUS, 1, 0);
				vi_pci_modern_queue_reset_complete(vq,
				    generation, 0);
				ATF_REQUIRE(!vq->vq_resetting);
				negotiate_ring_reset(&vs, &pi);
			} else {
				vi_pci_modern_queue_reset_complete(vq,
				    generation, 0);
			}
		}
		g_qreset_error = 0;
		ATF_REQUIRE(!vq->vq_resetting);
		ATF_REQUIRE(vq->vq_reset == 0);
		ATF_REQUIRE(vq->vq_enabled == 0);
		ATF_REQUIRE(vq->vq_qsize == vq->vq_qsize_max);
		ATF_REQUIRE(vq->vq_desc == NULL);
		ATF_REQUIRE(vq->vq_avail == NULL);
		ATF_REQUIRE(vq->vq_used == NULL);
	}
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
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(vq_ring_ready(&queues[0]));
	ATF_CHECK(g_notify_count == 1);
	ATF_CHECK(!queues[0].vq_notify_pending);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK(g_notify_count == 2);
	ATF_CHECK(g_notify_queue == 0);

	vs.vs_isr = VIRTIO_PCI_ISR_INTR | VIRTIO_PCI_ISR_CONFIG;
	ATF_CHECK(vi_pci_modern_read(&pi, 2, VIRTIO_MODERN_ISR_OFF, 1) ==
	    (VIRTIO14_ISR_QUEUE | VIRTIO14_ISR_CONFIG));
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

ATF_TC_WITHOUT_HEAD(linux_queue_activation_sequence);
ATF_TC_BODY(linux_queue_activation_sequence, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint64_t negotiated;

	setup_transport(&vs, &pi, queues);

	/*
	 * Mirror current Linux virtio core and virtio-pci-modern ordering:
	 * reset, ACKNOWLEDGE, DRIVER, write both feature pages, FEATURES_OK,
	 * configure and enable the queue, then DRIVER_OK.  Keeping this separate
	 * from queue_and_interrupts prevents a permissive out-of-order unit test
	 * from hiding an interoperability regression in the normal Linux path.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO14_STATUS_DRIVER);

	negotiated = TEST_DRIVER_FEATURES_LOW |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX |
	    VIRTIO_F_VERSION_1 | VIRTIO_F_IN_ORDER |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_RING_RESET;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)negotiated);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)(negotiated >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO14_STATUS_DRIVER |
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_REQUIRE((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK_EQ(g_applied_features, negotiated);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_MSIX, 2, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 64);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x5000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x6000);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_REQUIRE_EQ(queues[0].vq_enabled, 1);
	ATF_CHECK_EQ(g_qenable_count, 1);
	ATF_CHECK(!vq_ring_ready(&queues[0]));

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO14_STATUS_DRIVER |
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(vq_ring_ready(&queues[0]));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);

	/*
	 * Linux's split-ring doorbell is (next_avail << 16) | queue_index
	 * when NOTIFICATION_DATA is negotiated.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 4,
	    ((uint32_t)7 << VIRTIO14_NOTIFICATION_NEXT_OFF_SHIFT) | 0);
	ATF_CHECK_EQ(g_notify_count, 1);
	ATF_CHECK_EQ(g_notify_queue, 0);

	/*
	 * Linux queue_reset writes one and polls until queue_reset and
	 * queue_enable both read back zero.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_RESET, 2, 1);
	ATF_CHECK_EQ(g_qreset_count, 1);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_RESET, 2), 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_ENABLE, 2), 0);
}

ATF_TC_WITHOUT_HEAD(notification_data_width_and_queue);
ATF_TC_BODY(notification_data_width_and_queue, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE((vs.vs_negotiated_caps &
	    VIRTIO_F_NOTIFICATION_DATA) != 0);

	/* A negotiated notification-data doorbell is exactly 32 bits wide. */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 1, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 8, 0);
	ATF_CHECK_EQ(g_notify_count, 0);

	/*
	 * NOTIF_CONFIG_DATA is not offered, so the low half is the queue
	 * index.  The high half is the split-ring available index and is
	 * advisory; it must not change queue selection.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 4,
	    ((uint32_t)0xa55a << VIRTIO14_NOTIFICATION_NEXT_OFF_SHIFT) |
	    (0 & VIRTIO14_NOTIFICATION_VQ_INDEX_MASK));
	ATF_CHECK_EQ(g_notify_count, 1);
	ATF_CHECK_EQ(g_notify_queue, 0);

	/* Queue 1 is valid but disabled; an out-of-range low half is ignored. */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 4,
	    ((uint32_t)0x1234 << VIRTIO14_NOTIFICATION_NEXT_OFF_SHIFT) |
	    (1 & VIRTIO14_NOTIFICATION_VQ_INDEX_MASK));
	ATF_CHECK_EQ(g_notify_count, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 4,
	    UINT32_MAX);
	ATF_CHECK_EQ(g_notify_count, 1);
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

ATF_TC_WITHOUT_HEAD(queue_mapping_matches_negotiated_layout);
ATF_TC_BODY(queue_mapping_matches_negotiated_layout, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	struct vqueue_info *vq;
	size_t avail_size, used_size;

	setup_transport(&vs, &pi, queues);
	vq = &queues[0];
	vq->vq_qsize = 8;
	vq->vq_desc_gpa = 0x100;
	avail_size = VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    VIRTIO14_SPLIT_AVAIL_ELEM_SIZE * vq->vq_qsize;
	used_size = VIRTIO14_SPLIT_USED_HEADER_SIZE +
	    VIRTIO14_SPLIT_USED_ELEM_SIZE * vq->vq_qsize;

	/*
	 * Before feature finalization the device offers EVENT_IDX, so an early
	 * queue enable must conservatively validate its possible trailers.
	 */
	vs.vs_negotiated_caps = 0;
	vs.vs_status = 0;
	vq->vq_driver_gpa = g_guest_mem_limit - avail_size;
	vq->vq_device_gpa = 0x1000;
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == EFAULT);

	/* Without EVENT_IDX, neither optional event trailer is mapped. */
	vs.vs_negotiated_caps = 0;
	vs.vs_status = VIRTIO_CONFIG_S_FEATURES_OK;
	vq->vq_driver_gpa = g_guest_mem_limit - avail_size;
	vq->vq_device_gpa = 0x1000;
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == 0);
	ATF_CHECK(vq->vq_avail == (struct vring_avail *)
	    &g_guest_mem[g_guest_mem_limit - avail_size]);

	vq->vq_driver_gpa = 0x2000;
	vq->vq_device_gpa = g_guest_mem_limit - used_size;
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == 0);
	ATF_CHECK(vq->vq_used == (struct vring_used *)
	    &g_guest_mem[g_guest_mem_limit - used_size]);

	/* Negotiating EVENT_IDX makes both two-byte trailers part of the ring. */
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	vq->vq_driver_gpa = sizeof(g_guest_mem) - avail_size;
	vq->vq_device_gpa = 0x1000;
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == EFAULT);
	vq->vq_driver_gpa = sizeof(g_guest_mem) -
	    (avail_size + VIRTIO14_SPLIT_EVENT_FIELD_SIZE);
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == 0);

	/*
	 * Give the mapping an end address congruent to two modulo four so the
	 * EVENT_IDX used ring can both be four-byte aligned and end exactly at
	 * the boundary.
	 */
	g_guest_mem_limit = sizeof(g_guest_mem) - 2;
	vq->vq_driver_gpa = 0x2000;
	vq->vq_device_gpa = g_guest_mem_limit -
	    (used_size + VIRTIO14_SPLIT_EVENT_FIELD_SIZE);
	ATF_CHECK(vi_modern_map_vq(&vs, vq) == 0);
	g_guest_mem_limit = sizeof(g_guest_mem);
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
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);

	/*
	 * Model the normative stable-read sequence.  A change after the
	 * configuration bytes were read must be visible to the second
	 * generation read, even though no later configuration read occurs.
	 */
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	vi_pci_modern_config_changed(&vs);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 2);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);

	vs.vs_msix_cfg_idx = 1;
	for (int i = 0; i < 3; i++)
		vi_pci_modern_config_changed(&vs);
	ATF_CHECK(g_msix_count == 1);
	ATF_CHECK(g_msix_vector == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 3);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 3);

	/*
	 * More than 255 backend changes before the driver observes the epoch
	 * must not wrap the eight-bit generation back to its prior value.
	 */
	for (int i = 0; i < 256; i++)
		vi_pci_modern_config_changed(&vs);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 4);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 4);
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
	queues[0].vq_qsize = VIRTIO14_SPLIT_QUEUE_SIZE_MAX;
	ATF_CHECK(vi_pci_modern_init(&vs, 2) == 0);
	ATF_CHECK_EQ(queues[0].vq_qsize_max,
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX);
	free(vs.vs_modern);
	vs.vs_modern = NULL;
	queues[0].vq_qsize = 0;
	ATF_CHECK(vi_pci_modern_init(&vs, 2) == 0);
	free(vs.vs_modern);
}

ATF_TC_WITHOUT_HEAD(device_config_size_validation);
ATF_TC_BODY(device_config_size_validation, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(queues, 0, sizeof(queues));
	vc = test_consts;
	vc.vc_cfgsize = VIRTIO_MODERN_NOTIFY_OFF -
	    VIRTIO_MODERN_DEVICE_OFF + 1;
	vs.vs_vc = &vc;
	vs.vs_pi = &pi;
	vs.vs_queues = queues;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pi.pi_arg = &vs;
	queues[0].vq_qsize = 256;
	queues[1].vq_qsize = 128;

	ATF_CHECK_EQ(vi_pci_modern_init(&vs, 2), E2BIG);
	ATF_CHECK(vs.vs_modern == NULL);

	vc.vc_cfgsize--;
	ATF_CHECK_EQ(vi_pci_modern_init(&vs, 2), 0);
	ATF_REQUIRE(vs.vs_modern != NULL);
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
	dataoff = capoff + VIRTIO14_PCI_CFG_DATA_OFF;
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
	ATF_CHECK(vi_pci_modern_read(&pi, 2, UINT64_MAX, 1) == UINT8_MAX);
	ATF_CHECK(vi_pci_modern_read(&pi, 2, UINT64_MAX - 1, 4) ==
	    UINT32_MAX);
	vi_pci_modern_write(&pi, 2, UINT64_MAX, 1, 0xff);
	ATF_CHECK(g_device_config[0] == 0x78);

	/* Deterministic invalid-access sweep; ASan checks every range decision. */
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
	ATF_TP_ADD_TC(tp, unsupported_optional_features);
	ATF_TP_ADD_TC(tp, device_suspend_lifecycle);
	ATF_TP_ADD_TC(tp, queue_reset_sync);
	ATF_TP_ADD_TC(tp, queue_reset_async);
	ATF_TP_ADD_TC(tp, queue_reset_failure);
	ATF_TP_ADD_TC(tp, queue_reset_crosses_full_reset);
	ATF_TP_ADD_TC(tp, device_reset_waits_for_backend);
	ATF_TP_ADD_TC(tp, queue_reset_state_soak);
	ATF_TP_ADD_TC(tp, queue_and_interrupts);
	ATF_TP_ADD_TC(tp, linux_queue_activation_sequence);
	ATF_TP_ADD_TC(tp, notification_data_width_and_queue);
	ATF_TP_ADD_TC(tp, queue_mapping_is_atomic);
	ATF_TP_ADD_TC(tp, queue_mapping_matches_negotiated_layout);
	ATF_TP_ADD_TC(tp, config_change_msix);
	ATF_TP_ADD_TC(tp, queue_size_validation);
	ATF_TP_ADD_TC(tp, device_config_size_validation);
	ATF_TP_ADD_TC(tp, pci_cfg_window);
	ATF_TP_ADD_TC(tp, register_edges);
	return (atf_no_error());
}
