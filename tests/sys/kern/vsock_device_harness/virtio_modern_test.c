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

/* The administration ring adapter has its own focused harness. */
int
virtio_admin_pci_binding_enable(
    struct virtio_admin_pci_binding *binding __unused,
    struct vqueue_info *vq __unused)
{

	return (0);
}

int
virtio_admin_pci_binding_drain(
    struct virtio_admin_pci_binding *binding __unused,
    struct vqueue_info *vq __unused)
{

	return (0);
}

static int g_admin_quiesce_count;
static int g_admin_quiesce_error;
static int g_admin_unquiesce_count;
static int g_admin_unquiesce_error;

int
virtio_admin_pci_binding_quiesce(
    struct virtio_admin_pci_binding *binding __unused)
{

	g_admin_quiesce_count++;
	return (g_admin_quiesce_error);
}

int
virtio_admin_pci_binding_unquiesce(
    struct virtio_admin_pci_binding *binding __unused)
{

	g_admin_unquiesce_count++;
	return (g_admin_unquiesce_error);
}

int
virtio_admin_pci_binding_resume(
    struct virtio_admin_pci_binding *binding __unused,
    int (*resume)(void *), void *argument)
{

	g_admin_unquiesce_count++;
	return (resume(argument));
}

void
virtio_admin_pci_binding_reset(
    struct virtio_admin_pci_binding *binding __unused)
{
}

int
vq_packed_completions_init(struct vqueue_info *vq)
{

	if (vq->vq_packed_completions != NULL)
		return (vq->vq_packed_completion_count == vq->vq_qsize ? 0 :
		    EBUSY);
	vq->vq_packed_completions = calloc(vq->vq_qsize,
	    sizeof(*vq->vq_packed_completions));
	if (vq->vq_packed_completions == NULL)
		return (ENOMEM);
	vq->vq_packed_completion_count = vq->vq_qsize;
	return (0);
}

void
vq_packed_completions_fini(struct vqueue_info *vq)
{

	free(vq->vq_packed_completions);
	vq->vq_packed_completions = NULL;
	vq->vq_packed_completion_count = 0;
}

bool
vq_packed_completions_empty(const struct vqueue_info *vq)
{
	uint16_t i;

	if (vq->vq_packed_completions == NULL)
		return (vq->vq_packed_completion_count == 0);
	for (i = 0; i < vq->vq_packed_completion_count; i++) {
		if (vq->vq_packed_completions[i].valid ||
		    vq->vq_packed_completions[i].owner_state != 0)
			return (false);
	}
	return (true);
}

void
vq_packed_completions_reset(struct vqueue_info *vq)
{
	bool owners;
	uint16_t i;

	if (vq->vq_packed_completions == NULL)
		return;
	owners = false;
	for (i = 0; i < vq->vq_packed_completion_count; i++) {
		if (vq->vq_packed_completions[i].owner_state != 0) {
			owners = true;
			continue;
		}
		memset(&vq->vq_packed_completions[i], 0,
		    sizeof(vq->vq_packed_completions[i]));
	}
	if (!owners)
		vq_packed_completions_fini(vq);
}

bool
vq_split_owners_empty(const struct vqueue_info *vq)
{
	uint16_t i;

	if (vq->vq_split_owners == NULL)
		return (true);
	for (i = 0; i < vq->vq_split_owner_count; i++) {
		if (vq->vq_split_owners[i] != 0)
			return (false);
	}
	return (true);
}

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
#undef VIRTIO_PCI_COMMON_Q_NDATA
#define	VIRTIO_PCI_COMMON_Q_NDATA \
	VIRTIO14_COMMON_QUEUE_NOTIF_CONFIG_DATA
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
static struct {
	uint64_t address;
	size_t length;
	enum virtio_dma_direction direction;
} g_dma_maps[3];
static unsigned int g_dma_map_count;
static unsigned int g_dma_acquire_count;
static unsigned int g_dma_release_count;
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
static bool g_suspend_failure_saw_queue_fenced;
static bool g_expect_resume_failure_poison;
static bool g_resume_failure_poisoned_before_unquiesce;
static uint8_t g_device_config[8];
static bool g_cfgread_high_bits;
static struct {
	uint8_t bytes[4096];
	unsigned int reads;
	unsigned int writes;
	bool fail_read;
	bool fail_write;
	bool return_high_bits;
} g_shared_handler;

static int
shared_handler_read(void *arg, uint64_t offset, int size, uint64_t *value)
{
	typeof(g_shared_handler) *handler;

	handler = arg;
	handler->reads++;
	if (handler->fail_read)
		return (EIO);
	if (offset > sizeof(handler->bytes) ||
	    (uint64_t)size > sizeof(handler->bytes) - offset)
		return (ERANGE);
	switch (size) {
	case 1:
		*value = handler->bytes[offset];
		break;
	case 2:
		*value = le16dec(handler->bytes + offset);
		break;
	case 4:
		*value = le32dec(handler->bytes + offset);
		break;
	case 8:
		*value = le64dec(handler->bytes + offset);
		break;
	default:
		return (EINVAL);
	}
	if (handler->return_high_bits && size < 8)
		*value |= UINT64_C(0xffffffff00000000);
	return (0);
}

static int
shared_handler_write(void *arg, uint64_t offset, int size, uint64_t value)
{
	typeof(g_shared_handler) *handler;

	handler = arg;
	handler->writes++;
	if (handler->fail_write)
		return (EIO);
	if (offset > sizeof(handler->bytes) ||
	    (uint64_t)size > sizeof(handler->bytes) - offset)
		return (ERANGE);
	switch (size) {
	case 1:
		handler->bytes[offset] = value;
		break;
	case 2:
		le16enc(handler->bytes + offset, value);
		break;
	case 4:
		le32enc(handler->bytes + offset, value);
		break;
	case 8:
		le64enc(handler->bytes + offset, value);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

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

void *
vi_map_dma(struct virtio_softc *vs, uint64_t address, size_t len,
    enum virtio_dma_direction direction)
{

	if (g_dma_map_count < nitems(g_dma_maps)) {
		g_dma_maps[g_dma_map_count].address = address;
		g_dma_maps[g_dma_map_count].length = len;
		g_dma_maps[g_dma_map_count].direction = direction;
	}
	g_dma_map_count++;
	return (paddr_guest2host(vs->vs_pi->pi_vmctx, address, len));
}

bool
vi_dma_acquire(struct virtio_softc *vs __unused,
    struct virtio_dma_lease *lease)
{

	if (lease == NULL || lease->acquired)
		return (false);
	lease->acquired = true;
	g_dma_acquire_count++;
	return (true);
}

void
vi_dma_release(struct virtio_softc *vs __unused,
    struct virtio_dma_lease *lease)
{

	if (lease == NULL || !lease->acquired)
		return;
	lease->acquired = false;
	g_dma_release_count++;
}

bool
vi_platform_msix_enabled(struct virtio_softc *vs)
{

	return (pci_msix_enabled(vs->vs_pi));
}

void
vi_platform_raise_msix(struct virtio_softc *vs, uint16_t vector)
{

	pci_generate_msix(vs->vs_pi, vector);
}

void
vi_platform_raise_msi(struct virtio_softc *vs)
{

	pci_generate_msi(vs->vs_pi, 0);
}

void
vi_platform_set_intx(struct virtio_softc *vs, bool asserted)
{

	if (asserted)
		pci_lintr_assert(vs->vs_pi);
	else
		pci_lintr_deassert(vs->vs_pi);
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
pci_emul_alloc_bar(struct pci_devinst *pi, int bar,
    enum pcibar_type type, uint64_t size)
{

	g_bar = bar;
	g_bar_type = type;
	g_bar_size = size;
	pi->pi_bar[bar].type = type;
	pi->pi_bar[bar].size = size;
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

	if (g_suspend_error != 0)
		g_suspend_failure_saw_queue_fenced =
		    !vq_ring_ready(&vs->vs_queues[0]);
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
	    vs->vs_checkpoint_paused) {
		vq->vq_notify_pending = true;
		return;
	}
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

	if (g_expect_resume_failure_poison)
		g_resume_failure_poisoned_before_unquiesce =
		    (vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0;
	owners = atomic_fetch_sub(&vs->vs_quiescing, 1);
	ATF_REQUIRE_MSG(owners != 0, "unbalanced quiesce ownership");
}

/*
 * The transport harness includes virtio_pci_modern.c without linking the
 * common virtio.c object.  Model the common reset transaction here; the
 * transaction itself is exercised directly by virtio_core_test.
 */
void
vi_pci_reset_device(struct virtio_softc *vs)
{
	const struct virtio_consts *vc;

	vc = vs->vs_vc;
	vs->vs_reset_failed = false;
	vs->vs_restore_incomplete = false;
	atomic_fetch_add(&vs->vs_reset_epoch, 1);
	vi_pci_quiesce_enter(vs);
	vs->vs_resetting = true;
	(*vc->vc_reset)((void *)vs);
	vs->vs_status = 0;
	vs->vs_suspended = false;
	vs->vs_config_deferred = false;
	vi_pci_quiesce_exit(vs);
	vs->vs_resetting = false;
	atomic_fetch_add(&vs->vs_reset_epoch, 1);
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
	if (g_cfgread_high_bits && size < 4)
		*value |= UINT32_C(0xffff0000);
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
	memset(g_dma_maps, 0, sizeof(g_dma_maps));
	g_dma_map_count = 0;
	g_dma_acquire_count = 0;
	g_dma_release_count = 0;
	memset(g_device_config, 0, sizeof(g_device_config));
	g_cfgread_high_bits = false;
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
	g_admin_quiesce_count = 0;
	g_admin_quiesce_error = 0;
	g_admin_unquiesce_count = 0;
	g_admin_unquiesce_error = 0;
	g_resume_count = 0;
	g_resume_error = 0;
	g_suspend_saw_queue_fenced = false;
	g_suspend_failure_saw_queue_fenced = false;
	g_expect_resume_failure_poison = false;
	g_resume_failure_poisoned_before_unquiesce = false;
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

ATF_TC_WITHOUT_HEAD(shared_memory_capability);
ATF_TC_BODY(shared_memory_capability, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct virtio_pci_shared_memory_region source[2];
	struct vqueue_info queues[2];
	uint8_t backing[4096], readonly[4096];
	uint32_t value;
	uint64_t length, offset;
	int capoff;

	setup_transport(&vs, &pi, queues);
	memset(backing, 0, sizeof(backing));
	memset(readonly, 0xa5, sizeof(readonly));
	ATF_REQUIRE_EQ(pci_emul_alloc_bar(&pi, 4, PCIBAR_MEM64,
	    UINT64_C(0x400000000)), 0);
	offset = UINT64_C(0x100001000);
	length = UINT64_C(0x100002000);
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 7, 4, offset,
	    length), 0);
	capoff = pi.pi_prevcap;
	ATF_CHECK_EQ(pi.pi_cfgdata[capoff], PCIY_VENDOR);
	ATF_CHECK_EQ(pi.pi_cfgdata[capoff + 2],
	    VIRTIO14_PCI_CAP64_SIZE);
	ATF_CHECK_EQ(pi.pi_cfgdata[capoff + 3],
	    VIRTIO14_PCI_CAP_SHARED_MEMORY_CFG);
	ATF_CHECK_EQ(pi.pi_cfgdata[capoff + VIRTIO14_PCI_CAP_BAR_OFF], 4);
	ATF_CHECK_EQ(pi.pi_cfgdata[capoff + VIRTIO14_PCI_CAP_ID_OFF], 7);
	ATF_CHECK_EQ(le32dec(&pi.pi_cfgdata[
	    capoff + VIRTIO14_PCI_CAP_OFFSET_OFF]), (uint32_t)offset);
	ATF_CHECK_EQ(le32dec(&pi.pi_cfgdata[
	    capoff + VIRTIO14_PCI_CAP_LENGTH_OFF]), (uint32_t)length);
	ATF_CHECK_EQ(le32dec(&pi.pi_cfgdata[
	    capoff + VIRTIO14_PCI_CAP64_OFFSET_HI_OFF]),
	    (uint32_t)(offset >> 32));
	ATF_CHECK_EQ(le32dec(&pi.pi_cfgdata[
	    capoff + VIRTIO14_PCI_CAP64_LENGTH_HI_OFF]),
	    (uint32_t)(length >> 32));

	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(NULL, 8, 4, 0,
	    4096), EINVAL);
	vs.vs_pi = NULL;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4, 0,
	    4096), EINVAL);
	vs.vs_pi = &pi;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 7, 4, 0,
	    4096), EEXIST);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 6, 0,
	    4096), EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4, 0, 0),
	    EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4,
	    UINT64_C(0x400000000), 1), ERANGE);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4,
	    UINT64_C(0x3fffff000), 8192), ERANGE);
	pi.pi_bar[3].type = PCIBAR_IO;
	pi.pi_bar[3].size = 4096;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 3, 0,
	    4096), ERANGE);
	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4, 4096,
	    4096), EBUSY);
	vs.vs_status = 0;
	vs.vs_quiescing = 1;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 8, 4, 4096,
	    4096), EBUSY);
	vs.vs_quiescing = 0;

	/*
	 * Capability-space exhaustion must not reserve the region ID.  Restore
	 * only the mock allocator cursor; the failed call must not have touched
	 * either the chain or the transport registry.
	 */
	capoff = pi.pi_capend;
	pi.pi_capend = 240;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 3, 4, 0,
	    4096), ENOSPC);
	pi.pi_capend = capoff;
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 3, 4, 0,
	    4096), 0);
	ATF_CHECK_EQ(vs.vs_modern->shared_memory_count, 2);
	ATF_CHECK_EQ(vs.vs_modern->shared_memory[0].id, 3);
	ATF_CHECK_EQ(vs.vs_modern->shared_memory[1].id, 7);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(NULL, 3,
	    backing, sizeof(backing), true), EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 8,
	    backing, sizeof(backing), true), ENOENT);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing) - 1, true), ERANGE);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing), true), 0);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing), true), EEXIST);
	vi_pci_modern_write(&pi, 4, 8, 8, UINT64_C(0x8877665544332211));
	ATF_CHECK_EQ(le64dec(backing + 8),
	    UINT64_C(0x8877665544332211));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8, 8),
	    UINT64_C(0x8877665544332211));
	/* PCI_CFG must reach a region advertised in a non-transport BAR. */
	capoff = vs.vs_modern->pci_cfg_capoff;
	ATF_REQUIRE_EQ(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_BAR, 1, 4), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 4, 8), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_LENGTH, 4, 4), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO14_PCI_CFG_DATA_OFF, 4, 0x12345678), 0);
	ATF_CHECK_EQ(le32dec(backing + 8), UINT32_C(0x12345678));
	value = 0;
	ATF_REQUIRE_EQ(vi_pci_modern_cfgread(&pi,
	    capoff + VIRTIO14_PCI_CFG_DATA_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x12345678));
	ATF_REQUIRE_EQ(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO14_PCI_CFG_DATA_OFF, 4, 0x44332211), 0);
	vs.vs_suspended = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8, 8), UINT64_MAX);
	vi_pci_modern_write(&pi, 4, 8, 8, 0);
	ATF_CHECK_EQ(le64dec(backing + 8),
	    UINT64_C(0x8877665544332211));
	vs.vs_suspended = false;
	vs.vs_checkpoint_paused = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8, 8), UINT64_MAX);
	vi_pci_modern_write(&pi, 4, 8, 8, 0);
	ATF_CHECK_EQ(le64dec(backing + 8),
	    UINT64_C(0x8877665544332211));
	vs.vs_checkpoint_paused = false;
	vi_pci_modern_write(&pi, 4, 4095, 2, 0);
	ATF_CHECK_EQ(backing[4095], 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 4095, 2), UINT16_MAX);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK_EQ(vi_pci_modern_clear_shared_memory_backing(&vs, 3,
	    backing), EBUSY);
	/* Suspend and checkpoint own the BAR-access fence too. */
	vs.vs_suspended = true;
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_backing(&vs, 3,
	    backing), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing), true), 0);
	vs.vs_suspended = false;
	vs.vs_checkpoint_paused = true;
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_backing(&vs, 3,
	    backing), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing), true), 0);
	vs.vs_checkpoint_paused = false;
	vs.vs_quiescing = 1;
	ATF_CHECK_EQ(vi_pci_modern_clear_shared_memory_backing(&vs, 3,
	    readonly), EINVAL);
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_backing(&vs, 3,
	    backing), 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8, 8), UINT64_MAX);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 3,
	    backing, sizeof(backing), true), 0);
	vs.vs_quiescing = 0;
	vs.vs_status = 0;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8, 8),
	    UINT64_C(0x8877665544332211));

	/*
	 * The transport sorts registrations by shmid, then requires an exact
	 * immutable topology match before restore mutates live state.
	 */
	memcpy(source, vs.vs_modern->shared_memory, sizeof(source));
	ATF_CHECK(vi_modern_shared_memory_compatible(source, 2,
	    vs.vs_modern));
	ATF_CHECK(!vi_modern_shared_memory_compatible(source, 1,
	    vs.vs_modern));
	source[0].id ^= 1;
	ATF_CHECK(!vi_modern_shared_memory_compatible(source, 2,
	    vs.vs_modern));
	source[0] = vs.vs_modern->shared_memory[0];
	source[0].bar ^= 1;
	ATF_CHECK(!vi_modern_shared_memory_compatible(source, 2,
	    vs.vs_modern));
	source[0] = vs.vs_modern->shared_memory[0];
	source[0].offset++;
	ATF_CHECK(!vi_modern_shared_memory_compatible(source, 2,
	    vs.vs_modern));
	source[0] = vs.vs_modern->shared_memory[0];
	source[0].length--;
	ATF_CHECK(!vi_modern_shared_memory_compatible(source, 2,
	    vs.vs_modern));

	/*
	 * A region may be exposed read-only.  The guest can observe it, but a
	 * BAR write must not mutate destination-owned state.
	 */
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 9, 4, 8192,
	    sizeof(readonly)), 0);
	/*
	 * Sparse consumers such as GPU blob mappings cannot be represented by
	 * one permanent host pointer.  A callback-backed aperture preserves
	 * width, byte order, lifecycle fencing, and failure behavior.  Reuse
	 * this capability afterward to prove lifecycle replacement by a direct
	 * backing.
	 */
	memset(&g_shared_handler, 0, sizeof(g_shared_handler));
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_handler(NULL, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes) - 1, true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), ERANGE);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, NULL), EINVAL);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), 0);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), EEXIST);
	vi_pci_modern_write(&pi, 4, 8200, 8,
	    UINT64_C(0x0102030405060708));
	ATF_CHECK_EQ(g_shared_handler.writes, 1);
	ATF_CHECK_EQ(le64dec(g_shared_handler.bytes + 8),
	    UINT64_C(0x0102030405060708));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 8),
	    UINT64_C(0x0102030405060708));
	ATF_CHECK_EQ(g_shared_handler.reads, 1);
	vs.vs_checkpoint_paused = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 8), UINT64_MAX);
	vi_pci_modern_write(&pi, 4, 8200, 8, 0);
	ATF_CHECK_EQ(g_shared_handler.reads, 1);
	ATF_CHECK_EQ(g_shared_handler.writes, 1);
	vs.vs_checkpoint_paused = false;
	g_shared_handler.return_high_bits = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 1),
	    UINT64_C(0x08));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 2),
	    UINT64_C(0x0708));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 4),
	    UINT64_C(0x05060708));
	g_shared_handler.return_high_bits = false;
	g_shared_handler.fail_read = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 4), UINT32_MAX);
	g_shared_handler.fail_read = false;
	g_shared_handler.fail_write = true;
	vi_pci_modern_write(&pi, 4, 8200, 8, 0);
	ATF_CHECK_EQ(le64dec(g_shared_handler.bytes + 8),
	    UINT64_C(0x0102030405060708));
	vs.vs_suspended = true;
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_handler(&vs, 9,
	    &g_shared_handler), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), 0);
	vs.vs_suspended = false;
	vs.vs_checkpoint_paused = true;
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_handler(&vs, 9,
	    &g_shared_handler), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_handler(&vs, 9,
	    sizeof(g_shared_handler.bytes), true, &g_shared_handler,
	    shared_handler_read, shared_handler_write), 0);
	vs.vs_checkpoint_paused = false;
	vs.vs_quiescing = 1;
	ATF_CHECK_EQ(vi_pci_modern_clear_shared_memory_handler(&vs, 9,
	    backing), EINVAL);
	ATF_REQUIRE_EQ(vi_pci_modern_clear_shared_memory_handler(&vs, 9,
	    &g_shared_handler), 0);
	vs.vs_quiescing = 0;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8200, 8), UINT64_MAX);
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 9,
	    readonly, sizeof(readonly), false), 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 8192, 4),
	    UINT32_C(0xa5a5a5a5));
	vi_pci_modern_write(&pi, 4, 8192, 4, 0);
	ATF_CHECK_EQ(le32dec(readonly), UINT32_C(0xa5a5a5a5));
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 10, 4,
	    8192 + 1024, 1024), 0);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 10,
	    backing, 1024, false), EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 10,
	    readonly + 1024, 1024, true), EINVAL);
	ATF_CHECK_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 10,
	    readonly + 1024, 1024, false), 0);
	vi_pci_modern_seal_shared_memory(&vs);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 11, 4, 12288,
	    4096), EBUSY);
	vs.vs_status = 0;
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 11, 4, 12288,
	    4096), EBUSY);
}

ATF_TC_WITHOUT_HEAD(shared_memory_overlap_bounds);
ATF_TC_BODY(shared_memory_overlap_bounds, tc)
{
	struct virtio_pci_shared_memory_region a, b;

	/*
	 * Exercise the comparison directly at the uint64_t boundary.  These
	 * synthetic entries deliberately bypass registration: registration checks
	 * BAR containment, while this helper must remain safe if a future restore
	 * or parser supplies malformed topology.
	 */
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	a.bar = b.bar = 4;
	a.offset = UINT64_MAX - 15;
	a.length = 8;
	b.offset = UINT64_MAX - 7;
	b.length = 7;
	ATF_CHECK(!vi_modern_shared_memory_regions_overlap(&a, &b));
	b.offset = UINT64_MAX - 8;
	ATF_CHECK(vi_modern_shared_memory_regions_overlap(&a, &b));
	b.bar++;
	ATF_CHECK(!vi_modern_shared_memory_regions_overlap(&a, &b));
	b.bar = a.bar;
	b.length = 0;
	ATF_CHECK(!vi_modern_shared_memory_regions_overlap(&a, &b));
	ATF_CHECK(!vi_modern_shared_memory_regions_overlap(NULL, &b));
}

ATF_TC_WITHOUT_HEAD(shared_memory_status_seal);
ATF_TC_BODY(shared_memory_status_seal, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	ATF_REQUIRE_EQ(pci_emul_alloc_bar(&pi, 4, PCIBAR_MEM64, 16384), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 1, 4, 0,
	    4096), 0);

	/*
	 * Enumeration can precede the first nonzero status value.  Therefore
	 * every status write, including a full reset, permanently closes the
	 * construction-only capability registry.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK(vs.vs_modern->shared_memory_sealed);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 2, 4, 4096,
	    4096), EBUSY);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK_EQ(vi_pci_modern_add_shared_memory(&vs, 2, 4, 4096,
	    4096), EBUSY);
}

ATF_TC_WITHOUT_HEAD(shared_memory_alias_lookup_is_id_independent);
ATF_TC_BODY(shared_memory_alias_lookup_is_id_independent, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint8_t backing[4096];

	setup_transport(&vs, &pi, queues);
	ATF_REQUIRE_EQ(pci_emul_alloc_bar(&pi, 4, PCIBAR_MEM64,
	    sizeof(backing)), 0);
	/*
	 * Leave the lower ID unbound.  BAR access must still find the
	 * higher-ID alias which owns the identical bytes.
	 */
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 1, 4, 0,
	    sizeof(backing)), 0);
	ATF_REQUIRE_EQ(vi_pci_modern_add_shared_memory(&vs, 2, 4, 0,
	    sizeof(backing)), 0);
	memset(backing, 0, sizeof(backing));
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 2,
	    backing, sizeof(backing), true), 0);
	vi_pci_modern_write(&pi, 4, 16, 4, UINT32_C(0x44332211));
	ATF_CHECK_EQ(le32dec(backing + 16), UINT32_C(0x44332211));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 16, 4),
	    UINT32_C(0x44332211));

	/*
	 * Binding the lower alias to the same bytes and policy is legal and
	 * must preserve the result regardless of which ID is visited first.
	 */
	ATF_REQUIRE_EQ(vi_pci_modern_set_shared_memory_backing(&vs, 1,
	    backing, sizeof(backing), true), 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 4, 16, 4),
	    UINT32_C(0x44332211));
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
	    (uint32_t)(VIRTIO_F_RING_PACKED >> 32) |
	    (uint32_t)(VIRTIO_F_IN_ORDER >> 32) |
	    (uint32_t)(VIRTIO_F_NOTIFICATION_DATA >> 32) |
	    (uint32_t)(VIRTIO_F_NOTIF_CONFIG_DATA >> 32) |
	    (uint32_t)(VIRTIO_F_RING_RESET >> 32) |
	    (uint32_t)(VIRTIO14_DEVICE_FEATURE_HIGH_FIRST >> 32)));
	ATF_CHECK((value & (uint32_t)((VIRTIO_F_ACCESS_PLATFORM |
	    VIRTIO_F_ORDER_PLATFORM | VIRTIO_F_SR_IOV |
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
	 * The modern transport owns VERSION_1, NOTIFICATION_DATA, and the
	 * per-queue notification identifier; no ring feature is added unless
	 * the device model opts in.
	 */
	vc.vc_hv_caps = 0;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA));
	ATF_CHECK_EQ(vi_modern_common_cfg_size(&vs),
	    VIRTIO14_COMMON_QUEUE_NOTIF_CONFIG_DATA +
	    VIRTIO14_CONFIG_FIELD_U16_SIZE);

	/* Each optional ring feature is exposed only when the device asks. */
	vc.vc_hv_caps = VIRTIO_RING_F_INDIRECT_DESC;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_RING_F_INDIRECT_DESC));
	vc.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_RING_F_EVENT_IDX));
	vc.vc_hv_caps = VIRTIO_F_RING_RESET;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_F_RING_RESET));
	ATF_CHECK_EQ(vi_modern_common_cfg_size(&vs),
	    VIRTIO14_COMMON_QUEUE_RESET + VIRTIO14_CONFIG_FIELD_U16_SIZE);
	vc.vc_hv_caps = VIRTIO_F_IN_ORDER;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_IN_ORDER | VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_F_NOTIF_CONFIG_DATA));
	vc.vc_hv_caps = VIRTIO_F_RING_PACKED;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_RING_PACKED | VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_F_NOTIF_CONFIG_DATA));
	vc.vc_hv_caps = VIRTIO14_NET_F_GUEST_RSC6;
	features = vi_modern_device_features(&vs);
	ATF_CHECK(features == (VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA));

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
	    VIRTIO_F_RING_PACKED | VIRTIO_F_IN_ORDER |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_NOTIF_CONFIG_DATA |
	    VIRTIO_F_RING_RESET));
}

ATF_TC_WITHOUT_HEAD(access_platform_requires_domain_and_negotiation);
ATF_TC_BODY(access_platform_requires_domain_and_negotiation, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t high;

	setup_transport(&vs, &pi, queues);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_DFSELECT, 4, 1);
	high = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK_EQ(high & (uint32_t)(VIRTIO_F_ACCESS_PLATFORM >> 32), 0);

	/*
	 * A configured DMA domain makes ACCESS_PLATFORM both visible and
	 * mandatory.  Treat the non-NULL sentinel as an installed domain:
	 * this register-level test never dereferences its operations.
	 */
	vs.vs_dma_domain_ops =
	    (const struct virtio_dma_domain_ops *)(uintptr_t)1;
	high = vi_pci_modern_read(&pi, 2, VIRTIO_PCI_COMMON_DF, 4);
	ATF_CHECK((high &
	    (uint32_t)(VIRTIO_F_ACCESS_PLATFORM >> 32)) != 0);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)(VIRTIO_F_VERSION_1 >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 |
	    VIRTIO_F_ACCESS_PLATFORM) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) != 0);
	ATF_CHECK((vs.vs_negotiated_caps & VIRTIO_F_ACCESS_PLATFORM) != 0);
}

ATF_TC_WITHOUT_HEAD(unsupported_optional_features);
ATF_TC_BODY(unsupported_optional_features, tc)
{
	static const struct {
		uint64_t bit;
		const char *name;
	} unsupported[] = {
		{ VIRTIO14_F_ACCESS_PLATFORM, "ACCESS_PLATFORM" },
		{ VIRTIO14_F_ORDER_PLATFORM, "ORDER_PLATFORM" },
		{ VIRTIO14_F_SR_IOV, "SR_IOV" },
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

static void configure_queue0(struct pci_devinst *);

ATF_TC_WITHOUT_HEAD(queue_layout_must_match_late_features);
ATF_TC_BODY(queue_layout_must_match_late_features, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);

	/*
	 * Exercise a tolerated but nonconforming setup order.  The queue is
	 * mapped before FEATURES_OK and therefore uses the split layout.
	 * Finalizing RING_PACKED must fail instead of reinterpreting the
	 * already mapped guest memory under a different ring format.
	 */
	configure_queue0(&pi);
	ATF_REQUIRE_EQ(queues[0].vq_enabled, 1);
	ATF_REQUIRE_EQ(queues[0].vq_layout, VIRTIO_QUEUE_SPLIT);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 | VIRTIO_F_RING_PACKED) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER |
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_FEATURES_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, 0);
	ATF_CHECK_EQ(queues[0].vq_enabled, 1);
	ATF_CHECK_EQ(queues[0].vq_layout, VIRTIO_QUEUE_SPLIT);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	free(vs.vs_modern);
	vs.vs_modern = NULL;
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
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
	unsigned int acquires, releases;

	acquires = g_dma_acquire_count;
	releases = g_dma_release_count;
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 0);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 64);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_AVAILLO, 4, 0x5000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_USEDLO, 4, 0x6000);
	vi_pci_modern_write(pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_REQUIRE_EQ(g_dma_acquire_count, acquires + 1);
	ATF_REQUIRE_EQ(g_dma_release_count, releases + 1);
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
	int interrupts, unquiesces;

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
	vs.vs_negotiated_caps |= VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
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
	ATF_CHECK_EQ(g_admin_quiesce_count, 1);
	ATF_CHECK(g_suspend_saw_queue_fenced);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK(!vs.vs_quiescing);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_SUSPEND) != 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);

	/*
	 * SUSPEND is a state transition, not a repeated backend-drain request.
	 * A guest retry which observes the completed status must leave the already
	 * fenced device alone; otherwise an innocuous status write could release
	 * or duplicate device-private suspend work.
	 */
	interrupts = g_suspend_count;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_suspend_count, interrupts);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);

	/* Queue and device-configuration writes are inert while suspended. */
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK_EQ(g_notify_count, 1);
	ATF_CHECK(queues[0].vq_notify_pending);
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
	ATF_CHECK_EQ(g_notify_count, 2);
	ATF_CHECK_EQ(g_admin_unquiesce_count, 1);
	ATF_CHECK(!queues[0].vq_notify_pending);
	ATF_CHECK_EQ(g_msi_count + g_msix_count, interrupts + 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) != value);

	/* A repeated running-status write after resume must not resume twice. */
	interrupts = g_resume_count;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(g_resume_count, interrupts);

	/* A driver-declared failure is terminal and cannot also suspend. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	interrupts = g_suspend_count;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO14_STATUS_FAILED |
	    VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_suspend_count, interrupts);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK((vs.vs_status & VIRTIO14_STATUS_FAILED) != 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);

	/* Administration drain failure prevents the device callback. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vs.vs_negotiated_caps |= VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	g_admin_quiesce_error = EBUSY;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_admin_quiesce_count, 2);
	ATF_CHECK_EQ(g_suspend_count, 1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK_EQ(g_admin_unquiesce_count, 1);
	g_admin_quiesce_error = 0;

	/*
	 * A backend suspend error and a failed administration rollback still
	 * leave one terminal outcome: queues remain fenced and recovery needs a
	 * complete device reset.  In particular, an unmatched administration
	 * ownership depth must not reopen the normal queue admission path.
	 */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vs.vs_negotiated_caps |= VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	unquiesces = g_admin_unquiesce_count;
	g_suspend_error = EIO;
	g_admin_unquiesce_error = EBUSY;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK_EQ(g_admin_unquiesce_count, unquiesces + 1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK(g_suspend_failure_saw_queue_fenced);
	g_suspend_error = 0;
	g_admin_unquiesce_error = 0;

	/* Both lifecycle failures require a full device reset. */
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	g_suspend_error = EIO;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK(g_suspend_failure_saw_queue_fenced);

	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	g_suspend_error = 0;
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	g_resume_error = EIO;
	/*
	 * The resume failure must publish NEEDS_RESET while this final lifecycle
	 * owner still fences queue admission.  The test transport observes the
	 * status at vi_pci_quiesce_exit(), which made the historical reverse
	 * ordering fail even though the final status eventually looked correct.
	 */
	g_expect_resume_failure_poison = true;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	g_expect_resume_failure_poison = false;
	ATF_CHECK(g_resume_failure_poisoned_before_unquiesce);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vs.vs_suspended);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK_EQ(vs.vs_status, 0);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK(!vs.vs_quiescing);

	/* FAILED remains writable while the device is suspended. */
	g_resume_error = 0;
	configure_queue0(&pi);
	negotiate_suspend(&vs, &pi);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_SUSPEND);
	ATF_REQUIRE(vs.vs_suspended);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO14_STATUS_FAILED);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK((vs.vs_status & VIRTIO14_STATUS_FAILED) != 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	interrupts = g_resume_count;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    vs.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(g_resume_count, interrupts);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
}

ATF_TC_WITHOUT_HEAD(quiesce_fences_transport_access);
ATF_TC_BODY(quiesce_fences_transport_access, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];
	uint32_t value;

	setup_transport(&vs, &pi, queues);
	vs.vs_status = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_DRIVER;
	memcpy(g_device_config, &(uint32_t){ UINT32_C(0x11223344) },
	    sizeof(value));
	vi_pci_quiesce_enter(&vs);

	/* Status polling remains available while the lifecycle owner waits. */
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_STATUS, 1), vs.vs_status);

	/* All other reads are rejected without entering device callbacks. */
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 4), UINT32_MAX);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_SELECT, 2), UINT16_MAX);

	/* Writes, including a concurrent full reset, are inert. */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_DEVICE_OFF, 4,
	    UINT32_C(0xaabbccdd));
	memcpy(&value, g_device_config, sizeof(value));
	ATF_CHECK_EQ(value, UINT32_C(0x11223344));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1, 0);
	ATF_CHECK_EQ(vs.vs_status,
	    VIRTIO14_STATUS_ACKNOWLEDGE | VIRTIO14_STATUS_DRIVER);

	vi_pci_quiesce_exit(&vs);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 4), UINT32_C(0x11223344));
	g_cfgread_high_bits = true;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1), UINT64_C(0x44));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 2), UINT64_C(0x3344));
	g_cfgread_high_bits = false;
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
	    VIRTIO_F_NOTIFICATION_DATA |
	    VIRTIO_F_NOTIF_CONFIG_DATA) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE((vs.vs_negotiated_caps &
	    VIRTIO_F_NOTIFICATION_DATA) != 0);
	ATF_REQUIRE((vs.vs_negotiated_caps &
	    VIRTIO_F_NOTIF_CONFIG_DATA) != 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_NDATA, 2), 0);

	/* A negotiated notification-data doorbell is exactly 32 bits wide. */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 1, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 8, 0);
	ATF_CHECK_EQ(g_notify_count, 0);

	/*
	 * This implementation chooses the specification's trivial
	 * notification identifier: the queue index.  The high half is the
	 * split-ring available index and is advisory; it must not change
	 * queue selection.
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

ATF_TC_WITHOUT_HEAD(notification_config_data_without_notification_data);
ATF_TC_BODY(notification_config_data_without_notification_data, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	configure_queue0(&pi);

	/*
	 * Section 4.1.4.3 makes the field inaccessible until bit 39 is
	 * negotiated.  Bit 39 does not depend on bit 38.
	 */
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_NDATA, 2), UINT16_MAX);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GFSELECT, 4, 1);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_GF, 4,
	    (uint32_t)((VIRTIO_F_VERSION_1 |
	    VIRTIO_F_NOTIF_CONFIG_DATA) >> 32));
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_STATUS, 1,
	    VIRTIO_CONFIG_S_FEATURES_OK | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_REQUIRE((vs.vs_negotiated_caps &
	    VIRTIO_F_NOTIF_CONFIG_DATA) != 0);
	ATF_REQUIRE((vs.vs_negotiated_caps &
	    VIRTIO_F_NOTIFICATION_DATA) == 0);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_NDATA, 2), 0);

	/* Without bit 38 the notification remains exactly 16 bits wide. */
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 1, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 4, 0);
	ATF_CHECK_EQ(g_notify_count, 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_MODERN_NOTIFY_OFF, 2, 0);
	ATF_CHECK_EQ(g_notify_count, 1);
	ATF_CHECK_EQ(g_notify_queue, 0);
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
	queues[1].vq_layout = VIRTIO_QUEUE_PACKED;
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
	ATF_CHECK_EQ(queues[1].vq_layout, VIRTIO_QUEUE_PACKED);
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

	/*
	 * Some device fields (virtio-mem plugged_size) change as the direct
	 * result of a guest request.  They must invalidate a stable config
	 * read without generating the specification-discouraged interrupt.
	 */
	vi_pci_modern_config_dirty(&vs);
	ATF_CHECK_EQ(g_msi_count + g_msix_count, 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 1);

	vi_pci_modern_config_changed(&vs);
	ATF_CHECK(g_msix_count == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 2);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 2);

	/*
	 * Model the normative stable-read sequence.  A change after the
	 * configuration bytes were read must be visible to the second
	 * generation read, even though no later configuration read occurs.
	 */
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 2);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	vi_pci_modern_config_changed(&vs);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 3);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);

	vs.vs_msix_cfg_idx = 1;
	for (int i = 0; i < 3; i++)
		vi_pci_modern_config_changed(&vs);
	ATF_CHECK(g_msix_count == 1);
	ATF_CHECK(g_msix_vector == 1);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 4);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_MODERN_DEVICE_OFF, 1) == 0);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 4);

	/*
	 * More than 255 backend changes before the driver observes the epoch
	 * must not wrap the eight-bit generation back to its prior value.
	 */
	for (int i = 0; i < 256; i++)
		vi_pci_modern_config_changed(&vs);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 5);
	ATF_CHECK(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_CFGGENERATION, 1) == 5);
}

/*
 * A legacy device has no modern configuration-generation latch, but it still
 * uses the common checkpoint fence.  A backend configuration event received
 * under that fence must be replayed by vi_pci_resume(), not injected into the
 * stopped guest immediately.
 */
ATF_TC_WITHOUT_HEAD(legacy_config_change_defers_during_checkpoint);
ATF_TC_BODY(legacy_config_change_defers_during_checkpoint, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vs.vs_checkpoint_paused = true;
	vs.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;

	vi_pci_config_changed(&vs);
	ATF_CHECK(vs.vs_config_deferred);
	ATF_CHECK_EQ(g_msi_count, 0);
	ATF_CHECK_EQ(g_msix_count, 0);

	/* Model the common resume replay after it clears checkpoint ownership. */
	vs.vs_checkpoint_paused = false;
	vs.vs_config_deferred = false;
	vi_pci_config_changed(&vs);
	ATF_CHECK_EQ(g_msi_count, 1);
	ATF_CHECK_EQ(g_msix_count, 0);
}

/*
 * A lifecycle callback may drop the device mutex while checkpoint pause or
 * guest suspend is still being established.  Configuration changes arriving
 * in that interval must be latched, not injected into a guest which the
 * lifecycle owner is in the process of stopping.
 */
ATF_TC_WITHOUT_HEAD(config_change_defers_during_quiesce);
ATF_TC_BODY(config_change_defers_during_quiesce, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	vs.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;

	vi_pci_quiesce_enter(&vs);
	vi_pci_config_changed(&vs);
	ATF_CHECK(vs.vs_config_deferred);
	ATF_CHECK(vs.vs_modern->config_deferred);
	ATF_CHECK(vs.vs_modern->config_changed);
	ATF_CHECK_EQ(g_msi_count, 0);
	ATF_CHECK_EQ(g_msix_count, 0);

	/* Model the common failed-pause replay after the fence opens. */
	vi_pci_quiesce_exit(&vs);
	vs.vs_config_deferred = false;
	vi_pci_config_changed(&vs);
	ATF_CHECK(!vs.vs_config_deferred);
	ATF_CHECK(!vs.vs_modern->config_deferred);
	ATF_CHECK(vs.vs_modern->config_pending);
	ATF_CHECK_EQ(g_msi_count, 1);
	ATF_CHECK_EQ(g_msix_count, 0);
}

/*
 * Checkpoint and guest suspend are independent lifecycle owners.  Releasing
 * the former must not consume a configuration notification while the latter
 * still fences delivery: vi_pci_resume() re-latches it, and the guest resume
 * path is the only operation that may finally inject the interrupt.
 */
ATF_TC_WITHOUT_HEAD(config_change_survives_checkpoint_inside_suspend);
ATF_TC_BODY(config_change_survives_checkpoint_inside_suspend, tc)
{
	struct virtio_consts vc;
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	vc = test_consts;
	vc.vc_suspend = test_suspend;
	vc.vc_resume_device = test_resume;
	vs.vs_vc = &vc;
	vs.vs_negotiated_caps = VIRTIO_F_SUSPEND;
	vs.vs_status = VIRTIO_CONFIG_STATUS_SUSPEND;
	vs.vs_suspended = true;
	vs.vs_checkpoint_paused = true;
	vs.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;

	vi_pci_config_changed(&vs);
	ATF_CHECK(vs.vs_config_deferred);
	ATF_CHECK(vs.vs_modern->config_deferred);
	ATF_CHECK_EQ(g_msi_count, 0);

	/* Model the successful common checkpoint resume while still suspended. */
	vs.vs_checkpoint_paused = false;
	vs.vs_config_deferred = false;
	vi_pci_config_changed(&vs);
	ATF_CHECK(vs.vs_config_deferred);
	ATF_CHECK(vs.vs_modern->config_deferred);
	ATF_CHECK_EQ(g_msi_count, 0);

	vi_modern_resume(&vs);
	ATF_CHECK(!vs.vs_suspended);
	ATF_CHECK(!vs.vs_config_deferred);
	ATF_CHECK(!vs.vs_modern->config_deferred);
	ATF_CHECK_EQ(g_resume_count, 1);
	ATF_CHECK_EQ(g_msi_count, 1);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(queue_size_validation);
ATF_TC_BODY(queue_size_validation, tc)
{
	struct virtio_softc vs;
	struct virtio_consts packed_consts, split_consts;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(queues, 0, sizeof(queues));
	split_consts = test_consts;
	split_consts.vc_hv_caps &= ~VIRTIO_F_RING_PACKED;
	vs.vs_vc = &split_consts;
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

	/* VirtIO 1.4 section 2.8.10.1 permits non-power-of-two packed rings. */
	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(queues, 0, sizeof(queues));
	packed_consts = test_consts;
	packed_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vs.vs_vc = &packed_consts;
	vs.vs_pi = &pi;
	vs.vs_queues = queues;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	pi.pi_arg = &vs;
	queues[0].vq_qsize = 15;
	queues[1].vq_qsize = 5;
	ATF_REQUIRE_EQ(vi_pci_modern_init(&vs, 2), 0);
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1 | VIRTIO_F_RING_PACKED;
	vs.vs_curq = 0;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 5);
	ATF_CHECK_EQ(5, queues[0].vq_qsize);
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SIZE, 2, 7);
	ATF_CHECK_EQ(5, queues[0].vq_qsize);
	free(vs.vs_modern);
}

ATF_TC_WITHOUT_HEAD(packed_queue_mapping);
ATF_TC_BODY(packed_queue_mapping, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2];

	setup_transport(&vs, &pi, queues);
	queues[0].vq_qsize = 3;
	queues[0].vq_desc_gpa = 0x1000;
	queues[0].vq_driver_gpa = 0x3000;
	queues[0].vq_device_gpa = 0x4000;
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO_F_RING_PACKED;

	queues[0].vq_split_owners = calloc(queues[0].vq_qsize,
	    sizeof(*queues[0].vq_split_owners));
	ATF_REQUIRE(queues[0].vq_split_owners != NULL);
	queues[0].vq_split_owner_count = queues[0].vq_qsize;
	queues[0].vq_split_owners[0] = 1;
	ATF_CHECK_EQ(vi_modern_map_vq(&vs, &queues[0]), EBUSY);
	ATF_CHECK(queues[0].vq_packed_completions == NULL);
	queues[0].vq_split_owners[0] = 0;
	ATF_REQUIRE_EQ(vi_modern_map_vq(&vs, &queues[0]), 0);
	ATF_CHECK_EQ(queues[0].vq_layout, VIRTIO_QUEUE_PACKED);
	ATF_CHECK(queues[0].vq_desc == NULL);
	ATF_CHECK(queues[0].vq_avail == NULL);
	ATF_CHECK(queues[0].vq_used == NULL);
	ATF_CHECK(queues[0].vq_packed_desc ==
	    (void *)&g_guest_mem[0x1000]);
	ATF_CHECK(queues[0].vq_packed_driver_event ==
	    (void *)&g_guest_mem[0x3000]);
	ATF_CHECK(queues[0].vq_packed_device_event ==
	    (void *)&g_guest_mem[0x4000]);
	ATF_REQUIRE_EQ(g_dma_map_count, 3);
	ATF_CHECK_EQ(g_dma_maps[0].address, 0x1000);
	ATF_CHECK_EQ(g_dma_maps[0].length,
	    3 * VIRTIO14_PACKED_DESC_SIZE);
	ATF_CHECK_EQ(g_dma_maps[0].direction, VIRTIO_DMA_BIDIRECTIONAL);
	ATF_CHECK_EQ(g_dma_maps[1].address, 0x3000);
	ATF_CHECK_EQ(g_dma_maps[1].length, VIRTIO14_PACKED_EVENT_SIZE);
	ATF_CHECK_EQ(g_dma_maps[1].direction, VIRTIO_DMA_DEVICE_READ);
	ATF_CHECK_EQ(g_dma_maps[2].address, 0x4000);
	ATF_CHECK_EQ(g_dma_maps[2].length, VIRTIO14_PACKED_EVENT_SIZE);
	ATF_CHECK_EQ(g_dma_maps[2].direction, VIRTIO_DMA_DEVICE_WRITE);

	queues[0].vq_packed_completions[0].valid = true;
	queues[0].vq_packed_completions[1].owner_state = 2;
	vi_pci_modern_reset(&vs);
	ATF_CHECK_EQ(queues[0].vq_layout, VIRTIO_QUEUE_SPLIT);
	ATF_CHECK(queues[0].vq_packed_desc == NULL);
	ATF_CHECK(queues[0].vq_packed_driver_event == NULL);
	ATF_CHECK(queues[0].vq_packed_device_event == NULL);
	ATF_REQUIRE(queues[0].vq_packed_completions != NULL);
	ATF_CHECK(!queues[0].vq_packed_completions[0].valid);
	ATF_CHECK_EQ(queues[0].vq_packed_completions[1].owner_state, 2);
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1;
	ATF_CHECK_EQ(vi_modern_map_vq(&vs, &queues[0]), EBUSY);
	queues[0].vq_packed_completions[1].owner_state = 0;
	vq_packed_completions_reset(&queues[0]);
	ATF_CHECK(queues[0].vq_packed_completions == NULL);
	free(queues[0].vq_split_owners);
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

	/* All advertised RW capability fields retain partial PCI writes. */
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_BAR, 4, 0xa5a5a502) == 0);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi,
	    capoff + VIRTIO_PCI_CAP_BAR), 2);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi,
	    capoff + VIRTIO14_PCI_CAP_ID_OFF), 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 4, 0) == 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 2,
	    VIRTIO_PCI_COMMON_Q_SELECT) == 0);
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_LENGTH, 1, 2) == 0);
	ATF_CHECK_EQ(pci_get_cfgdata32(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET), VIRTIO_PCI_COMMON_Q_SELECT);
	ATF_CHECK_EQ(pci_get_cfgdata32(&pi,
	    capoff + VIRTIO_PCI_CAP_LENGTH), 2);

	/* A dword write triggers a two-byte window using pci_cfg_data[0..1]. */
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi, dataoff, 4, 1) == 0);
	ATF_CHECK_EQ(vs.vs_curq, 1);

	/* A partial data read refreshes the entire configured window first. */
	ATF_REQUIRE(vi_pci_modern_cfgwrite(&pi,
	    capoff + VIRTIO_PCI_CAP_OFFSET, 2,
	    VIRTIO_PCI_COMMON_Q_SIZE) == 0);
	value = 0;
	ATF_REQUIRE(vi_pci_modern_cfgread(&pi, dataoff + 1, 1, &value) == 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_get_cfgdata8(&pi, dataoff) |
	    pci_get_cfgdata8(&pi, dataoff + 1) << 8, 128);
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

ATF_TC_WITHOUT_HEAD(admin_queues_remain_fail_closed_while_staged);
ATF_TC_BODY(admin_queues_remain_fail_closed_while_staged, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info queues[2], admin[2];

	setup_transport(&vs, &pi, queues);
	memset(admin, 0, sizeof(admin));
	for (size_t i = 0; i < nitems(admin); i++) {
		admin[i].vq_vs = &vs;
		admin[i].vq_num = 5 + i;
		admin[i].vq_qsize = 64;
		admin[i].vq_qsize_max = 64;
		admin[i].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	}
	vs.vs_admin_queues = admin;
	vs.vs_admin_queue_index = 5;
	vs.vs_admin_queue_count = nitems(admin);

	ATF_CHECK_EQ(vi_modern_device_features(&vs) & VIRTIO14_F_ADMIN_VQ, 0);
	ATF_CHECK(vi_modern_common_cfg_size(&vs) <
	    VIRTIO14_COMMON_ADMIN_QUEUE_INDEX + sizeof(uint16_t));

	/*
	 * A live adapter binding completes the feature gate and publishes the
	 * two 1.4 common-configuration fields without changing num_queues.
	 */
	vs.vs_admin_binding = (struct virtio_admin_pci_binding *)(uintptr_t)1;
	ATF_CHECK((vi_modern_device_features(&vs) & VIRTIO14_F_ADMIN_VQ) != 0);
	ATF_CHECK_EQ(vi_modern_common_cfg_size(&vs),
	    VIRTIO14_COMMON_ADMIN_QUEUE_NUM + sizeof(uint16_t));
	/* The fields exist in the offered layout, but are invalid pre-negotiation. */
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO14_COMMON_ADMIN_QUEUE_INDEX, 2), UINT16_MAX);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO14_COMMON_ADMIN_QUEUE_NUM, 2), UINT16_MAX);
	vs.vs_negotiated_caps |= VIRTIO_F_ADMIN_VQ;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO14_COMMON_ADMIN_QUEUE_INDEX, 2), 5);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO14_COMMON_ADMIN_QUEUE_NUM, 2), nitems(admin));
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_NUMQ, 2), (uint64_t)test_consts.vc_nvq);
	vs.vs_negotiated_caps &= ~VIRTIO_F_ADMIN_VQ;
	vs.vs_admin_binding = NULL;
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_SELECT, 2, 5);
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_SIZE, 2), 0);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_DESCLO, 4, 0x1000);
	ATF_CHECK_EQ(admin[0].vq_desc_gpa, 0);

	/* A mask-only regression must still fail closed at queue activation. */
	vs.vs_negotiated_caps |= VIRTIO_F_ADMIN_VQ;
	ATF_CHECK_EQ(vi_pci_modern_read(&pi, 2,
	    VIRTIO_PCI_COMMON_Q_SIZE, 2), 64);
	vi_pci_modern_write(&pi, 2, VIRTIO_PCI_COMMON_Q_ENABLE, 2, 1);
	ATF_CHECK_EQ(admin[0].vq_enabled, 0);
	ATF_CHECK_EQ(g_qenable_count, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	admin[0].vq_desc_gpa = 0x1000;
	admin[0].vq_notify_pending = true;
	vi_pci_modern_reset(&vs);
	ATF_CHECK_EQ(admin[0].vq_desc_gpa, 0);
	ATF_CHECK(!admin[0].vq_notify_pending);
}

ATF_TC_WITHOUT_HEAD(admin_snapshot_topology_is_versioned_and_exact);
ATF_TC_BODY(admin_snapshot_topology_is_versioned_and_exact, tc)
{
	struct virtio_softc vs = { 0 };
	struct vqueue_info admin[2] = { 0 };

	vs.vs_admin_queues = admin;
	vs.vs_admin_queue_index = 5;
	vs.vs_admin_queue_count = nitems(admin);
	ATF_CHECK(vi_modern_admin_topology_compatible(&vs,
	    VIRTIO_F_VERSION_1, 0, 0));
	ATF_CHECK(vi_modern_admin_topology_compatible(&vs,
	    VIRTIO14_F_ADMIN_VQ, 5, 2));
	ATF_CHECK(!vi_modern_admin_topology_compatible(&vs,
	    VIRTIO14_F_ADMIN_VQ, 4, 2));
	ATF_CHECK(!vi_modern_admin_topology_compatible(&vs,
	    VIRTIO14_F_ADMIN_VQ, 5, 1));
	vs.vs_admin_queues = NULL;
	ATF_CHECK(!vi_modern_admin_topology_compatible(&vs,
	    VIRTIO14_F_ADMIN_VQ, 5, 2));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transport_policy);
	ATF_TP_ADD_TC(tp, capability_chain);
	ATF_TP_ADD_TC(tp, shared_memory_capability);
	ATF_TP_ADD_TC(tp, shared_memory_overlap_bounds);
	ATF_TP_ADD_TC(tp, shared_memory_status_seal);
	ATF_TP_ADD_TC(tp, shared_memory_alias_lookup_is_id_independent);
	ATF_TP_ADD_TC(tp, features_and_status);
	ATF_TP_ADD_TC(tp, ring_features_require_device_opt_in);
	ATF_TP_ADD_TC(tp, access_platform_requires_domain_and_negotiation);
	ATF_TP_ADD_TC(tp, unsupported_optional_features);
	ATF_TP_ADD_TC(tp, queue_layout_must_match_late_features);
	ATF_TP_ADD_TC(tp, device_suspend_lifecycle);
	ATF_TP_ADD_TC(tp, quiesce_fences_transport_access);
	ATF_TP_ADD_TC(tp, queue_reset_sync);
	ATF_TP_ADD_TC(tp, queue_reset_async);
	ATF_TP_ADD_TC(tp, queue_reset_failure);
	ATF_TP_ADD_TC(tp, queue_reset_crosses_full_reset);
	ATF_TP_ADD_TC(tp, device_reset_waits_for_backend);
	ATF_TP_ADD_TC(tp, queue_reset_state_soak);
	ATF_TP_ADD_TC(tp, queue_and_interrupts);
	ATF_TP_ADD_TC(tp, linux_queue_activation_sequence);
	ATF_TP_ADD_TC(tp, notification_data_width_and_queue);
	ATF_TP_ADD_TC(tp,
	    notification_config_data_without_notification_data);
	ATF_TP_ADD_TC(tp, queue_mapping_is_atomic);
	ATF_TP_ADD_TC(tp, queue_mapping_matches_negotiated_layout);
	ATF_TP_ADD_TC(tp, config_change_msix);
	ATF_TP_ADD_TC(tp, legacy_config_change_defers_during_checkpoint);
	ATF_TP_ADD_TC(tp, config_change_defers_during_quiesce);
	ATF_TP_ADD_TC(tp, config_change_survives_checkpoint_inside_suspend);
	ATF_TP_ADD_TC(tp, queue_size_validation);
	ATF_TP_ADD_TC(tp, packed_queue_mapping);
	ATF_TP_ADD_TC(tp, device_config_size_validation);
	ATF_TP_ADD_TC(tp, pci_cfg_window);
	ATF_TP_ADD_TC(tp, register_edges);
	ATF_TP_ADD_TC(tp, admin_queues_remain_fail_closed_while_staged);
	ATF_TP_ADD_TC(tp, admin_snapshot_topology_is_versioned_and_exact);
	return (atf_no_error());
}
