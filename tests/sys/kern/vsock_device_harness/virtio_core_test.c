/* Tests for the real bhyve split-ring parser and interrupt decision logic. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#define	BHYVE_SNAPSHOT
#include "pci_emul.h"
#include <bhyve/virtio.h>
#include <bhyve/virtio_admin_pci.h>
#include <bhyve/snapshot_portable.h>
#include "virtio_state_range.h"
#include "virtio_1_4_spec.h"
#define	MOCK_VIRTIO_H
#include "bhyve/virtio_packed.c"

/*
 * virtio.c and the modern transport are separate production translation
 * units.  This core-only harness supplies the transport query at that link
 * boundary; virtio_modern_test.c exercises the real implementation.
 */
uint64_t
vi_modern_device_features(const struct virtio_softc *vs)
{

	return (vs->vs_vc->vc_hv_caps | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_NOTIFICATION_DATA | VIRTIO14_F_NOTIF_CONFIG_DATA);
}

static int g_admin_quiesce_calls;
static int g_admin_quiesce_error;
static int g_admin_unquiesce_calls;
static int g_admin_unquiesce_error;
static uint32_t g_admin_controller_state;

int
virtio_admin_pci_binding_quiesce(
    struct virtio_admin_pci_binding *binding __unused)
{

	g_admin_quiesce_calls++;
	return (g_admin_quiesce_error);
}

int
virtio_admin_pci_binding_unquiesce(
    struct virtio_admin_pci_binding *binding __unused)
{

	g_admin_unquiesce_calls++;
	return (g_admin_unquiesce_error);
}

int
virtio_admin_pci_binding_resume(
    struct virtio_admin_pci_binding *binding __unused,
    int (*resume)(void *), void *argument)
{

	g_admin_unquiesce_calls++;
	return (resume(argument));
}

int
virtio_admin_pci_binding_state_size(
    struct virtio_admin_pci_binding *binding __unused, size_t *result)
{

	if (result == NULL)
		return (EINVAL);
	*result = sizeof(g_admin_controller_state);
	return (0);
}

int
virtio_admin_pci_binding_state_save(
    struct virtio_admin_pci_binding *binding __unused, void *buffer,
    size_t length)
{

	if (buffer == NULL || length != sizeof(g_admin_controller_state))
		return (EINVAL);
	memcpy(buffer, &g_admin_controller_state, length);
	return (0);
}

int
virtio_admin_pci_binding_state_restore(
    struct virtio_admin_pci_binding *binding __unused, const void *buffer,
    size_t length)
{

	if (buffer == NULL || length != sizeof(g_admin_controller_state))
		return (EINVAL);
	memcpy(&g_admin_controller_state, buffer, length);
	return (0);
}

int
virtio_admin_pci_binding_state_restore_validate(
    struct virtio_admin_pci_binding *binding __unused, const void *buffer,
    size_t length)
{

	if (buffer == NULL || length != sizeof(g_admin_controller_state))
		return (EINVAL);
	return (0);
}

#include "virtio.c"
#include "pci_virtio_net.c"
#include "virtio_1_4_wire.h"

/*
 * The core harness links the production network snapshot implementation but
 * deliberately does not instantiate a host network backend.  Keep that link
 * boundary explicit so a clean aggregate build exercises the snapshot code
 * without depending on net_backends.c.
 */
const char *
netbe_checkpoint_identity(net_backend_t *be __unused)
{

	return ("virtio-core-test-backend");
}

/* The real core is compiled above; test-side wire values are the 1.4 oracle. */
#undef VIRTIO_CONFIG_STATUS_ACK
#define	VIRTIO_CONFIG_STATUS_ACK	VIRTIO14_STATUS_ACKNOWLEDGE
#undef VIRTIO_CONFIG_STATUS_DRIVER
#define	VIRTIO_CONFIG_STATUS_DRIVER	VIRTIO14_STATUS_DRIVER
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_FEATURES_OK
#define	VIRTIO_CONFIG_S_FEATURES_OK	VIRTIO14_STATUS_FEATURES_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
#undef VIRTIO_CONFIG_STATUS_SUSPEND
#define	VIRTIO_CONFIG_STATUS_SUSPEND	VIRTIO14_STATUS_SUSPEND
#undef VIRTIO_F_VERSION_1
#define	VIRTIO_F_VERSION_1		VIRTIO14_F_VERSION_1
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND		VIRTIO14_F_SUSPEND
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED		VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_NOTIFY_ON_EMPTY
#define	VIRTIO_F_NOTIFY_ON_EMPTY	VIRTIO14_F_NOTIFY_ON_EMPTY
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET		VIRTIO14_F_RING_RESET
#undef VIRTIO_RING_F_INDIRECT_DESC
#define	VIRTIO_RING_F_INDIRECT_DESC	VIRTIO14_F_RING_INDIRECT_DESC
#undef VIRTIO_RING_F_EVENT_IDX
#define	VIRTIO_RING_F_EVENT_IDX		VIRTIO14_F_RING_EVENT_IDX
#undef VRING_DESC_F_NEXT
#define	VRING_DESC_F_NEXT		VIRTIO14_DESC_F_NEXT
#undef VRING_DESC_F_WRITE
#define	VRING_DESC_F_WRITE		VIRTIO14_DESC_F_WRITE
#undef VRING_DESC_F_INDIRECT
#define	VRING_DESC_F_INDIRECT		VIRTIO14_DESC_F_INDIRECT
#undef VRING_USED_F_NO_NOTIFY
#define	VRING_USED_F_NO_NOTIFY		VIRTIO14_USED_F_NO_NOTIFY
#undef VIRTIO_MSI_NO_VECTOR
#define	VIRTIO_MSI_NO_VECTOR		VIRTIO14_MSI_NO_VECTOR
#undef VIRTIO_PCI_HOST_FEATURES
#define	VIRTIO_PCI_HOST_FEATURES	VIRTIO14_LEGACY_DEVICE_FEATURES
#undef VIRTIO_PCI_GUEST_FEATURES
#define	VIRTIO_PCI_GUEST_FEATURES	VIRTIO14_LEGACY_DRIVER_FEATURES
#undef VIRTIO_PCI_QUEUE_PFN
#define	VIRTIO_PCI_QUEUE_PFN		VIRTIO14_LEGACY_QUEUE_ADDRESS
#undef VIRTIO_PCI_QUEUE_NUM
#define	VIRTIO_PCI_QUEUE_NUM		VIRTIO14_LEGACY_QUEUE_SIZE
#undef VIRTIO_PCI_QUEUE_SEL
#define	VIRTIO_PCI_QUEUE_SEL		VIRTIO14_LEGACY_QUEUE_SELECT
#undef VIRTIO_PCI_QUEUE_NOTIFY
#define	VIRTIO_PCI_QUEUE_NOTIFY		VIRTIO14_LEGACY_QUEUE_NOTIFY
#undef VIRTIO_PCI_STATUS
#define	VIRTIO_PCI_STATUS		VIRTIO14_LEGACY_DEVICE_STATUS
#undef VIRTIO_PCI_ISR
#define	VIRTIO_PCI_ISR			VIRTIO14_LEGACY_ISR_STATUS
#undef VIRTIO_PCI_ISR_INTR
#define	VIRTIO_PCI_ISR_INTR		VIRTIO14_ISR_QUEUE
#undef VIRTIO_PCI_ISR_CONFIG
#define	VIRTIO_PCI_ISR_CONFIG		VIRTIO14_ISR_CONFIG
#undef VIRTIO_MSI_CONFIG_VECTOR
#define	VIRTIO_MSI_CONFIG_VECTOR	VIRTIO14_LEGACY_CONFIG_MSIX_VECTOR
#undef VIRTIO_MSI_QUEUE_VECTOR
#define	VIRTIO_MSI_QUEUE_VECTOR		VIRTIO14_LEGACY_QUEUE_MSIX_VECTOR
#undef VIRTIO_PCI_CONFIG_OFF
#define	VIRTIO_PCI_CONFIG_OFF(msix)	((msix) ? \
	    VIRTIO14_LEGACY_MSIX_DEVICE_CFG_OFF : \
	    VIRTIO14_LEGACY_DEVICE_CFG_OFF)
#undef VRING_ALIGN
#define	VRING_ALIGN			VIRTIO14_LEGACY_QUEUE_ALIGN

struct vmctx { int unused; };

struct guest_region {
	uint64_t gpa;
	size_t len;
	void *host;
};

static struct guest_region g_regions[8];
static int g_region_count;
static int g_interrupts;
static int g_msix_cap_count;
static int g_msixcap_error;
static int g_notifications;
static int g_cfg_reads;
static int g_cfg_writes;
static int g_cfg_error;
static int g_apply_features;
static int g_apply_features_error;
static int g_config_changes;
static uint64_t g_applied_features;
static bool g_msix_enabled;
static bool g_lintr_asserted;
static bool g_hold_deassert;
static bool g_deassert_entered;
static bool g_reset_reports_failure;
static bool g_snapshot_restore_failure;
static bool g_snapshot_restore_incomplete;
static bool g_snapshot_consume_wire;
static bool g_snapshot_restore_length_mismatch;
static uint8_t g_snapshot_device_wire;
static uint8_t g_reset_observed_status;
static unsigned int g_map_calls;
static uint64_t g_last_map_address;
static size_t g_last_map_len;
static enum virtio_dma_direction g_last_map_direction;
static pthread_mutex_t g_intr_test_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_intr_test_cv = PTHREAD_COND_INITIALIZER;

static void add_region(uint64_t, void *, size_t);
static void setup_queue(struct virtio_softc *, struct virtio_consts *,
    struct pci_devinst *, struct vqueue_info *, struct vring_desc *,
    struct vring_avail *, struct vring_used *);
static void setup_packed_queue(struct virtio_softc *, struct virtio_consts *,
    struct pci_devinst *, struct vqueue_info *, struct virtio_packed_desc *,
    struct virtio_packed_event *, struct virtio_packed_event *, uint16_t);
static void own_test_packed_request(struct vqueue_info *, struct vi_req *);

static int
pause_with_racing_notify(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	vi_pci_notify_queue(vs, 0);
	return (EIO);
}

static int
pause_with_racing_notify_and_config(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	vi_pci_notify_queue(vs, 0);
	/* Model a backend configuration event arriving under the quiesce fence. */
	vs->vs_config_deferred = true;
	return (EIO);
}

static int g_resume_error;
static int g_resume_complete_count;
static int g_restore_suspended_count;
static bool g_restore_suspended_observed;
static int g_restore_resumed_count;
static bool g_restore_resumed_observed;

static int
pause_success(void *arg __unused)
{

	return (0);
}

static int
resume_success(void *arg __unused)
{

	return (0);
}

static int
resume_with_injected_error(void *arg __unused)
{

	return (g_resume_error);
}

static void
resume_complete_count(void *arg __unused)
{

	g_resume_complete_count++;
}

/*
 * The common restore path invokes this only after every common, queue, admin,
 * and device-specific restore stage has succeeded.  Devices with external
 * backend ownership use the corresponding production hook to retain their
 * guest-suspend fence across checkpoint resume.
 */
static void
restore_suspended_count(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	g_restore_suspended_count++;
	g_restore_suspended_observed = vs->vs_suspended;
}

static void
restore_resumed_count(void *arg)
{
	struct virtio_softc *vs;

	vs = arg;
	g_restore_resumed_count++;
	g_restore_resumed_observed = !vs->vs_suspended;
}

static int
pause_must_not_run(void *arg __unused)
{

	ATF_CHECK_MSG(false, "device pause ran after admin quiesce failed");
	return (0);
}

int
vm_snapshot_buf(void *data, size_t len, struct vm_snapshot_meta *meta)
{
	if (meta->buffer.buf_rem < len)
		return (ENOSPC);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, len);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, len);
	else
		return (EINVAL);
	meta->buffer.buf += len;
	meta->buffer.buf_rem -= len;
	return (0);
}

int
vm_snapshot_buf_cmp(void *data, size_t len, struct vm_snapshot_meta *meta)
{
	int error;

	if (vm_snapshot_is_loading(meta) &&
	    (meta->buffer.buf_rem < len ||
	    memcmp(data, meta->buffer.buf, len) != 0))
		return (EINVAL);
	error = vm_snapshot_buf(data, len, meta);
	return (error);
}

void
vm_snapshot_buf_err(const char *name __unused, enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le16(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le16(bytes);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le32(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le32(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le64(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le64(bytes);
	return (error);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx __unused, void **mapping,
	    size_t len, bool restore_null, struct vm_snapshot_meta *meta)
{
	uint64_t gpa, offset;
	void *host;
	int error;

	gpa = UINT64_MAX;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (int i = 0; i < g_region_count; i++) {
			if ((uintptr_t)*mapping < (uintptr_t)g_regions[i].host)
				continue;
			offset = (uintptr_t)*mapping -
			    (uintptr_t)g_regions[i].host;
			if (offset <= g_regions[i].len &&
			    len <= g_regions[i].len - offset) {
				gpa = g_regions[i].gpa + offset;
				break;
			}
		}
		if (gpa == UINT64_MAX && (!restore_null || *mapping != NULL))
			return (EFAULT);
	}
	error = vm_snapshot_le64(&gpa, meta);
	if (error != 0 || !vm_snapshot_is_loading(meta))
		return (error);
	if (gpa == UINT64_MAX) {
		if (!restore_null)
			return (EFAULT);
		host = NULL;
	} else {
		host = paddr_guest2host(ctx, gpa, len);
		if (host == NULL)
			return (EFAULT);
	}
	if (vm_snapshot_is_restoring(meta))
		*mapping = host;
	return (0);
}

int
vi_pci_modern_snapshot_transport(struct virtio_softc *vs __unused,
    struct vm_snapshot_meta *meta __unused)
{
	return (0);
}

void
vi_pci_config_changed(struct virtio_softc *vs __unused)
{

	g_config_changes++;
}

static int
test_device_snapshot(void *arg __unused, struct vm_snapshot_meta *meta)
{
	uint8_t wire;
	int error;

	if (meta->op == VM_SNAPSHOT_RESTORE && g_snapshot_restore_failure) {
		if (g_snapshot_restore_incomplete)
			vi_snapshot_restore_incomplete(arg);
		return (EIO);
	}
	if (g_snapshot_consume_wire &&
	    !(meta->op == VM_SNAPSHOT_RESTORE &&
	    g_snapshot_restore_length_mismatch)) {
		wire = g_snapshot_device_wire;
		error = vm_snapshot_u8(&wire, meta);
		if (error != 0)
			return (error);
		if (meta->op == VM_SNAPSHOT_RESTORE)
			g_snapshot_device_wire = wire;
	}
	return (0);
}

size_t
count_iov(const struct iovec *iov, size_t niov)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

void
netbe_rx_enable(net_backend_t *be __unused)
{
}

void
netbe_rx_disable(net_backend_t *be __unused)
{
}

int
netbe_set_cap(net_backend_t *be __unused, uint64_t features __unused,
    unsigned int header_len __unused)
{

	return (0);
}

size_t
netbe_get_vnet_hdr_len(net_backend_t *be __unused)
{

	return (0);
}

ssize_t
netbe_send(net_backend_t *be __unused, const struct iovec *iov __unused,
    int iovcnt __unused)
{

	return (-1);
}

void *
paddr_guest2host(struct vmctx *ctx __unused, uintptr_t gpa, size_t len)
{
	uint64_t offset;

	for (int i = 0; i < g_region_count; i++) {
		if (gpa < g_regions[i].gpa)
			continue;
		offset = gpa - g_regions[i].gpa;
		if (offset <= g_regions[i].len &&
		    len <= g_regions[i].len - offset)
			return ((uint8_t *)g_regions[i].host + offset);
	}
	return (NULL);
}

static void *
test_platform_map(void *arg, uint64_t gpa, size_t len,
    enum virtio_dma_direction direction)
{

	g_map_calls++;
	g_last_map_address = gpa;
	g_last_map_len = len;
	g_last_map_direction = direction;
	return (paddr_guest2host(arg, gpa, len));
}

static size_t g_ram_page_size;
static int g_discard_error;
static unsigned int g_discard_calls;
static uint64_t g_discard_address;
static size_t g_discard_len;
static unsigned int g_undiscard_calls;
static unsigned int g_reverse_calls;
static unsigned int g_dirty_mark_calls;
static void *g_dirty_mark_address;
static size_t g_dirty_mark_len;

vm_paddr_t
vm_rev_map_gpa(struct vmctx *ctx __unused, void *mapping __unused)
{

	return ((vm_paddr_t)-1);
}

static size_t
test_platform_ram_page_size(void *arg __unused)
{

	return (g_ram_page_size);
}

static int
test_platform_discard_ram(void *arg __unused, uint64_t address, size_t len)
{

	g_discard_calls++;
	g_discard_address = address;
	g_discard_len = len;
	return (g_discard_error);
}

static int
test_platform_undiscard_ram(void *arg __unused, uint64_t address, size_t len)
{

	g_undiscard_calls++;
	g_discard_address = address;
	g_discard_len = len;
	return (g_discard_error);
}

static int
test_platform_reverse_ram(void *arg __unused, void *mapping, size_t len,
    uint64_t *address)
{

	g_reverse_calls++;
	if (mapping == NULL || len == 0 || address == NULL)
		return (EINVAL);
	*address = UINT64_C(0x9000);
	return (0);
}

static void
test_platform_mark_dma_dirty(void *arg __unused, void *mapping, size_t len)
{

	g_dirty_mark_calls++;
	g_dirty_mark_address = mapping;
	g_dirty_mark_len = len;
}

static const struct virtio_platform_ops test_platform_ops = {
	.vpo_map_dma = test_platform_map,
	.vpo_reverse_ram = test_platform_reverse_ram,
	.vpo_mark_dma_dirty = test_platform_mark_dma_dirty,
	.vpo_ram_page_size = test_platform_ram_page_size,
	.vpo_discard_ram = test_platform_discard_ram,
	.vpo_undiscard_ram = test_platform_undiscard_ram,
	.vpo_msix_enabled = vi_pci_msix_enabled,
	.vpo_raise_msix = vi_pci_raise_msix,
	.vpo_raise_msi = vi_pci_raise_msi,
	.vpo_set_intx = vi_pci_set_intx,
};

static uint32_t g_domain_endpoint;
static uint64_t g_domain_address;
static size_t g_domain_len;
static enum virtio_dma_direction g_domain_direction;
static unsigned int g_domain_calls;
static uint64_t g_domain_generation;
static uint64_t g_domain_offset = 0x1000;
static bool g_domain_deny;
static unsigned int g_domain_acquires;
static unsigned int g_domain_releases;
static bool g_domain_acquire_allowed = true;

static bool
test_domain_acquire(void *arg __unused, uint32_t endpoint)
{

	g_domain_endpoint = endpoint;
	g_domain_acquires++;
	return (g_domain_acquire_allowed);
}

static void
test_domain_release(void *arg __unused, uint32_t endpoint)
{

	ATF_CHECK_EQ(endpoint, g_domain_endpoint);
	g_domain_releases++;
}

static void *
test_domain_map(void *arg, uint32_t endpoint, uint64_t address, size_t len,
    enum virtio_dma_direction direction)
{

	g_domain_calls++;
	g_domain_endpoint = endpoint;
	g_domain_address = address;
	g_domain_len = len;
	g_domain_direction = direction;
	if (g_domain_deny)
		return (NULL);
	return (paddr_guest2host(arg, address + g_domain_offset, len));
}

static uint64_t
test_domain_generation(void *arg __unused)
{

	return (g_domain_generation);
}

static const struct virtio_dma_domain_ops test_domain_ops = {
	.vddo_map = test_domain_map,
	.vddo_generation = test_domain_generation,
};

static const struct virtio_dma_domain_ops test_leased_domain_ops = {
	.vddo_acquire = test_domain_acquire,
	.vddo_release = test_domain_release,
	.vddo_map = test_domain_map,
	.vddo_generation = test_domain_generation,
};

struct dma_detach_race {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool acquire_entered;
	bool acquire_continue;
	bool request_acquired;
	struct virtio_softc *vs;
};

static bool
test_blocking_domain_acquire(void *arg, uint32_t endpoint __unused)
{
	struct dma_detach_race *race;

	race = arg;
	pthread_mutex_lock(&race->mutex);
	race->acquire_entered = true;
	pthread_cond_broadcast(&race->cond);
	while (!race->acquire_continue)
		pthread_cond_wait(&race->cond, &race->mutex);
	pthread_mutex_unlock(&race->mutex);
	return (true);
}

static void
test_blocking_domain_release(void *arg __unused, uint32_t endpoint __unused)
{
}

static void *
test_blocking_domain_map(void *arg, uint32_t endpoint __unused,
    uint64_t address __unused, size_t len __unused,
    enum virtio_dma_direction direction __unused)
{

	return (arg);
}

static const struct virtio_dma_domain_ops test_blocking_domain_ops = {
	.vddo_acquire = test_blocking_domain_acquire,
	.vddo_release = test_blocking_domain_release,
	.vddo_map = test_blocking_domain_map,
	.vddo_generation = test_domain_generation,
};

static void *
test_dma_acquire_thread(void *arg)
{
	struct dma_detach_race *race;
	struct vi_req request;

	race = arg;
	memset(&request, 0, sizeof(request));
	race->request_acquired = vi_req_dma_acquire(race->vs, &request);
	if (race->request_acquired)
		vi_req_dma_release(race->vs, &request);
	return (NULL);
}

#define	DOC_F_ACCESS_PLATFORM	(1ULL << 33)

ATF_TC_WITHOUT_HEAD(access_platform_domain_contract);
ATF_TC_BODY(access_platform_domain_contract, tc)
{
	struct virtio_dma_domain_ops bad_ops = { 0 };
	struct virtio_dma_domain_ops map_only_ops = {
		.vddo_map = test_domain_map,
	};
	struct virtio_dma_domain_ops acquire_only_ops = test_domain_ops;
	struct virtio_consts vc = { 0 };
	struct virtio_dma_lease lease;
	struct virtio_softc vs;
	struct vi_req req;
	struct vqueue_info queue;
	struct vmctx ctx;
	uint8_t guest[64];

	memset(&vs, 0, sizeof(vs));
	memset(&req, 0, sizeof(req));
	memset(&queue, 0, sizeof(queue));
	memset(&lease, 0, sizeof(lease));
	memset(&ctx, 0, sizeof(ctx));
	vs.vs_vc = &vc;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_region_count = 0;
	g_map_calls = 0;
	g_domain_calls = 0;
	g_domain_generation = 1;
	g_domain_offset = 0x1000;
	g_domain_deny = false;
	g_dirty_mark_calls = 0;
	add_region(0x3000, guest, sizeof(guest));
	vi_set_platform_ops(&vs, &test_platform_ops, &ctx);
	ATF_CHECK(vi_pci_access_platform_eligible(&vs));
	atomic_store_explicit(&vs.vs_dma_active_requests, UINT32_MAX,
	    memory_order_release);
	ATF_CHECK(!vi_dma_acquire(&vs, &lease));
	ATF_CHECK(!lease.acquired);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), UINT32_MAX);
	atomic_store_explicit(&vs.vs_dma_active_requests, 0,
	    memory_order_release);

	ATF_CHECK_EQ(vi_set_dma_domain(NULL, &test_domain_ops, &ctx, 0x20),
	    EINVAL);
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &bad_ops, &ctx, 0x20), EINVAL);
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &map_only_ops, &ctx, 0x20),
	    EINVAL);
	acquire_only_ops.vddo_acquire = test_domain_acquire;
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &acquire_only_ops, &ctx, 0x20),
	    EINVAL);
	vc.vc_access_platform_ineligible = true;
	ATF_CHECK(!vi_pci_access_platform_eligible(&vs));
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    EOPNOTSUPP);
	ATF_CHECK((vc.vc_hv_caps & DOC_F_ACCESS_PLATFORM) == 0);
	vc.vc_access_platform_ineligible = false;
	ATF_CHECK(vi_pci_access_platform_eligible(&vs));
	atomic_store_explicit(&vs.vs_dma_detaching, true,
	    memory_order_release);
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    EBUSY);
	atomic_store_explicit(&vs.vs_dma_detaching, false,
	    memory_order_release);
	atomic_store_explicit(&vs.vs_dma_active_requests, 1,
	    memory_order_release);
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    EBUSY);
	atomic_store_explicit(&vs.vs_dma_active_requests, 0,
	    memory_order_release);
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    0);
	ATF_CHECK((vc.vc_hv_caps & DOC_F_ACCESS_PLATFORM) != 0);
	ATF_CHECK_EQ(vi_map_dma(&vs, 0x2000, sizeof(guest),
	    VIRTIO_DMA_DEVICE_WRITE), guest);
	ATF_CHECK_EQ(g_domain_calls, 1);
	ATF_CHECK_EQ(g_domain_endpoint, 0x20);
	ATF_CHECK_EQ(g_domain_address, UINT64_C(0x2000));
	ATF_CHECK_EQ(g_domain_len, sizeof(guest));
	ATF_CHECK_EQ(g_domain_direction, VIRTIO_DMA_DEVICE_WRITE);
	ATF_CHECK_EQ(g_map_calls, 0);
	ATF_CHECK_EQ(g_dirty_mark_calls, 1);
	ATF_CHECK_EQ(g_dirty_mark_address, guest);
	ATF_CHECK_EQ(g_dirty_mark_len, sizeof(guest));
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x21),
	    EBUSY);

	/*
	 * A static domain has no provider callbacks, but an asynchronous
	 * request still holds a common-core lease.  Device reset may bring
	 * status to zero before that request completes; domain detach must
	 * remain blocked until its mapping is no longer in use.
	 */
	ATF_REQUIRE(vi_req_dma_acquire(&vs, &req));
	ATF_CHECK(req.dma_acquired);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 1);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	vi_req_dma_release(&vs, &req);
	ATF_CHECK(!req.dma_acquired);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 0);

	/*
	 * Device-private DMA, including a sparse shared-memory BAR access,
	 * holds the same detach fence without pretending to own a descriptor.
	 */
	ATF_REQUIRE(vi_dma_acquire(&vs, &lease));
	ATF_CHECK(lease.acquired);
	ATF_CHECK(!vi_dma_acquire(&vs, &lease));
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 1);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	vi_dma_release(&vs, &lease);
	ATF_CHECK(!lease.acquired);
	vi_dma_release(&vs, &lease);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 0);

	/*
	 * Modern compatibility permits queue enable before FEATURES_OK, so a
	 * zero device status alone does not prove that no persistent ring mapping
	 * exists.  Domain removal must wait for both enabled and allocated queues.
	 */
	vc.vc_nvq = 1;
	vs.vs_queues = &queue;
	queue.vq_enabled = 1;
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	queue.vq_enabled = 0;
	vq_set_allocated(&queue, true);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	vq_set_allocated(&queue, false);

	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK;
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	vs.vs_status = 0;
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&vs), 0);
	ATF_CHECK((vc.vc_hv_caps & DOC_F_ACCESS_PLATFORM) == 0);
	ATF_CHECK_EQ(vi_map_dma(&vs, 0x3000, sizeof(guest),
	    VIRTIO_DMA_DEVICE_READ), guest);
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(g_dirty_mark_calls, 1);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), ENOENT);
	/*
	 * Initial domain publication may follow early queue configuration.  The
	 * next queue access revalidates all persistent mappings against the new
	 * domain generation.  Removal is different: it cannot discard the only
	 * translation source while an enabled queue still owns those mappings.
	 */
	queue.vq_enabled = 1;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    0);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	queue.vq_enabled = 0;
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&vs), 0);

	/*
	 * A direct-DMA request accepted before a reset is still a domain-binding
	 * lease.  A hot-plug topology pass cannot install translated DMA until
	 * that completion releases its old direct address-space view.
	 */
	memset(&lease, 0, sizeof(lease));
	ATF_REQUIRE(vi_dma_acquire(&vs, &lease));
	ATF_CHECK(lease.acquired);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 1);
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    EBUSY);
	vi_dma_release(&vs, &lease);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 0);
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    0);
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&vs), 0);
	vc.vc_nvq = 0;
	vs.vs_queues = NULL;

	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_CHECK_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x20),
	    EOPNOTSUPP);
}

ATF_TC_WITHOUT_HEAD(dma_dirty_marks_cached_queue_writes);
ATF_TC_BODY(dma_dirty_marks_cached_queue_writes, tc)
{
	struct {
		struct vring_used used;
		struct vring_used_elem ring[4];
		uint16_t avail_event;
	} split;
	struct virtio_packed_desc packed_desc[4];
	struct virtio_packed_event device_event;
	struct virtio_softc vs;
	struct vqueue_info vq;

	memset(&split, 0, sizeof(split));
	memset(packed_desc, 0, sizeof(packed_desc));
	memset(&device_event, 0, sizeof(device_event));
	memset(&vs, 0, sizeof(vs));
	memset(&vq, 0, sizeof(vq));
	vs.vs_platform_ops = &test_platform_ops;
	vs.vs_platform_arg = NULL;
	vs.vs_negotiated_caps = VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_RING_EVENT_IDX;
	vq.vq_vs = &vs;
	vq.vq_qsize = 4;
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq.vq_used = &split.used;
	g_dirty_mark_calls = 0;
	vq_relchain_prepare(&vq, 3, 7);
	vq_relchain_publish(&vq);
	ATF_CHECK_EQ(g_dirty_mark_calls, 2);
	vq_kick_enable(&vq);
	ATF_CHECK_EQ(g_dirty_mark_calls, 4);

	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	vq.vq_packed_desc = packed_desc;
	vq.vq_packed_device_event = &device_event;
	vq.vq_packed_next_avail = 0;
	vq.vq_packed_avail_wrap = true;
	vi_mark_dma_dirty(&vs, &packed_desc[0], sizeof(packed_desc[0]));
	vq_kick_disable(&vq);
	ATF_CHECK_EQ(g_dirty_mark_calls, 6);
}

ATF_TC_WITHOUT_HEAD(access_platform_detach_acquire_race);
ATF_TC_BODY(access_platform_detach_acquire_race, tc)
{
	struct dma_detach_race race;
	struct virtio_consts vc = { 0 };
	struct virtio_softc vs;
	pthread_t thread;

	memset(&race, 0, sizeof(race));
	memset(&vs, 0, sizeof(vs));
	vs.vs_vc = &vc;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	race.vs = &vs;
	ATF_REQUIRE_EQ(pthread_mutex_init(&race.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&race.cond, NULL), 0);
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_blocking_domain_ops,
	    &race, 0x29), 0);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, test_dma_acquire_thread,
	    &race), 0);

	pthread_mutex_lock(&race.mutex);
	while (!race.acquire_entered)
		pthread_cond_wait(&race.cond, &race.mutex);
	pthread_mutex_unlock(&race.mutex);
	/*
	 * The common lease must already be visible while the provider's
	 * acquire callback is blocked.  The old callback-first ordering let
	 * detach clear the callback argument in this exact window.
	 */
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 1);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);

	pthread_mutex_lock(&race.mutex);
	race.acquire_continue = true;
	pthread_cond_broadcast(&race.cond);
	pthread_mutex_unlock(&race.mutex);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK(race.request_acquired);
	ATF_CHECK_EQ(atomic_load_explicit(&vs.vs_dma_active_requests,
	    memory_order_acquire), 0);
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&vs), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&race.cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&race.mutex), 0);
}

ATF_TC_WITHOUT_HEAD(access_platform_domain_lifecycle_mutex);
ATF_TC_BODY(access_platform_domain_lifecycle_mutex, tc)
{
	struct virtio_consts vc = { 0 };
	struct virtio_softc vs;
	struct vmctx ctx;
	pthread_mutex_t mutex;

	memset(&vs, 0, sizeof(vs));
	memset(&ctx, 0, sizeof(ctx));
	vs.vs_vc = &vc;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	ATF_REQUIRE_EQ(pthread_mutex_init(&mutex, NULL), 0);
	vs.vs_mtx = &mutex;

	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &ctx, 0x2a),
	    0);
	ATF_CHECK(!atomic_load_explicit(&vs.vs_dma_detaching,
	    memory_order_acquire));
	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK;
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	ATF_CHECK(!atomic_load_explicit(&vs.vs_dma_detaching,
	    memory_order_acquire));
	vs.vs_status = 0;
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&vs), 0);
	ATF_CHECK(!atomic_load_explicit(&vs.vs_dma_detaching,
	    memory_order_acquire));
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&mutex), 0);
}

ATF_TC_WITHOUT_HEAD(access_platform_request_dma_lifetime);
ATF_TC_BODY(access_platform_request_dma_lifetime, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct vring_desc desc[8];
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req group[2];
	struct vi_req duplicate, req;
	struct iovec iov;
	uint32_t group_lens[2] = { 0, 0 };
	uint16_t used_idx;
	uint8_t payload[16];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_domain_generation = 7;
	g_domain_offset = 0;
	g_domain_deny = false;
	g_domain_acquire_allowed = true;
	g_domain_acquires = 0;
	g_domain_releases = 0;
	add_region(0x1000, payload, sizeof(payload));
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_leased_domain_ops, &pi,
	    0x28), 0);
	vq.vq_dma_generation = g_domain_generation;
	vq.vq_dma_generation_valid = true;
	desc[0].addr = 0x1000;
	desc[0].len = sizeof(payload);
	desc[0].flags = VRING_DESC_F_WRITE;

	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(req.dma_acquired);
	ATF_CHECK_EQ(vi_clear_dma_domain(&vs), EBUSY);
	duplicate = req;
	ATF_CHECK_EQ(g_domain_acquires, 1);
	ATF_CHECK_EQ(g_domain_releases, 0);
	vq_relchain_req(&vq, &req, sizeof(payload));
	ATF_CHECK(!req.dma_acquired);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK_EQ(g_domain_releases, 1);
	used_idx = vq.vq_used->idx;
	/*
	 * A copied asynchronous token retains its local live bits, so only
	 * queue-owned split-head state can reject this duplicate without
	 * publishing or releasing the domain lease twice.
	 */
	vq_relchain_req(&vq, &duplicate, sizeof(payload));
	ATF_CHECK(!duplicate.dma_acquired);
	ATF_CHECK(!duplicate.outstanding);
	ATF_CHECK_EQ(g_domain_releases, 1);
	ATF_CHECK_EQ(vq.vq_used->idx, used_idx);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	vq.vq_last_avail = 0;
	vq.vq_next_used = 0;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(req.dma_acquired);
	vq_retchain_req(&vq, &req);
	ATF_CHECK(!req.dma_acquired);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK_EQ(g_domain_acquires, 2);
	ATF_CHECK_EQ(g_domain_releases, 2);

	/* Reset cancellation retires ownership without publishing the ring. */
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	used_idx = vq.vq_used->idx;
	vq_discard_req(&vq, &req);
	ATF_CHECK(!req.dma_acquired);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK_EQ(vq.vq_used->idx, used_idx);
	ATF_CHECK_EQ(g_domain_acquires, 3);
	ATF_CHECK_EQ(g_domain_releases, 3);

	vq.vq_last_avail = 0;
	vq.vq_next_used = 0;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(req.dma_acquired);
	ATF_CHECK_EQ(g_domain_acquires, 4);
	vq_relchain_req(&vq, &req, sizeof(payload));
	ATF_CHECK_EQ(g_domain_releases, 4);

	vq.vq_last_avail = 0;
	vq.vq_next_used = 0;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	vq.vq_generation++;
	vq_relchain_req(&vq, &req, 0);
	ATF_CHECK(!req.dma_acquired);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK_EQ(g_domain_releases, 5);

	vq.vq_last_avail = 0;
	vq.vq_generation = req.queue_generation;
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	desc[0].addr = UINT64_C(0xdead0000);
	ATF_CHECK_EQ(vq_getchain(&vq, &iov, 1, &req), -1);
	ATF_CHECK_EQ(g_domain_acquires, 6);
	ATF_CHECK_EQ(g_domain_releases, 6);

	/*
	 * A stale member in a packed completion group rejects the complete
	 * group, but still releases every independently acquired request
	 * lease.  This is an error path that cannot be covered by ordinary
	 * successful grouped publication.
	 */
	memset(group, 0, sizeof(group));
	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	ATF_REQUIRE(vi_req_dma_acquire(&vs, &group[0]));
	ATF_REQUIRE(vi_req_dma_acquire(&vs, &group[1]));
	group[0].queue_generation = vq.vq_generation;
	group[1].queue_generation = vq.vq_generation - 1;
	group[0].packed_head = 0;
	group[0].packed_wrap = true;
	group[1].packed_head = 1;
	group[1].packed_wrap = true;
	own_test_packed_request(&vq, &group[0]);
	own_test_packed_request(&vq, &group[1]);
	vq_relchain_group(&vq, group, group_lens, nitems(group));
	ATF_CHECK(!group[0].dma_acquired);
	ATF_CHECK(!group[1].dma_acquired);
	ATF_CHECK_EQ(g_domain_acquires, 8);
	ATF_CHECK_EQ(g_domain_releases, 8);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(access_platform_ring_mapping_revalidation);
ATF_TC_BODY(access_platform_ring_mapping_revalidation, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_a_mem;
	union { max_align_t align; uint8_t bytes[64]; } avail_b_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_a_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_b_mem;
	struct vring_desc desc_a[8], desc_b[8];
	struct vring_avail *avail_a, *avail_b;
	struct vring_used *used_a, *used_b;
	struct virtio_consts vc = {
		.vc_name = "dma-generation-test",
		.vc_nvq = 1,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	avail_a = (struct vring_avail *)avail_a_mem.bytes;
	avail_b = (struct vring_avail *)avail_b_mem.bytes;
	used_a = (struct vring_used *)used_a_mem.bytes;
	used_b = (struct vring_used *)used_b_mem.bytes;
	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	memset(desc_a, 0, sizeof(desc_a));
	memset(desc_b, 0, sizeof(desc_b));
	memset(avail_a, 0, sizeof(avail_a_mem));
	memset(avail_b, 0, sizeof(avail_b_mem));
	memset(used_a, 0, sizeof(used_a_mem));
	memset(used_b, 0, sizeof(used_b_mem));
	vs.vs_vc = &vc;
	vs.vs_pi = &pi;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vq.vq_vs = &vs;
	vq.vq_qsize = 8;
	vq.vq_flags = VQ_ALLOC;
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq.vq_desc_gpa = 0x1000;
	vq.vq_driver_gpa = 0x2000;
	vq.vq_device_gpa = 0x3000;
	g_region_count = 0;
	add_region(0x2000, desc_a,
	    nitems(desc_a) * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x3000, avail_a, sizeof(avail_a_mem));
	add_region(0x4000, used_a, sizeof(used_a_mem));
	add_region(0x6000, desc_b,
	    nitems(desc_b) * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x7000, avail_b, sizeof(avail_b_mem));
	add_region(0x8000, used_b, sizeof(used_b_mem));
	g_domain_generation = 1;
	g_domain_offset = 0x1000;
	g_domain_deny = false;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &pi, 0x20),
	    0);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	ATF_CHECK_EQ(vq_has_descs(&vq), 0);
	ATF_CHECK_EQ(vq.vq_avail, avail_a);
	ATF_CHECK_EQ(vq.vq_dma_generation, UINT64_C(1));
	avail_b->idx = 1;
	g_domain_offset = 0x5000;
	g_domain_generation++;
	ATF_CHECK_EQ(vq_has_descs(&vq), 1);
	ATF_CHECK_EQ(vq.vq_desc, desc_b);
	ATF_CHECK_EQ(vq.vq_avail, avail_b);
	ATF_CHECK_EQ(vq.vq_used, used_b);
	ATF_CHECK_EQ(vq.vq_dma_generation, UINT64_C(2));

	/*
	 * Revoking the ring mappings must not leave the old host pointers
	 * usable.  The next access fails closed and requests device reset.
	 */
	g_domain_deny = true;
	g_domain_generation++;
	ATF_CHECK_EQ(vq_has_descs(&vq), 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

ATF_TC_WITHOUT_HEAD(split_group_duplicate_retires_distinct_owners);
ATF_TC_BODY(split_group_duplicate_retires_distinct_owners, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct vring_desc desc[8];
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req first, second, group[3];
	struct iovec iov;
	uint32_t lengths[3] = { 0, 0, 0 };
	uint8_t payload[2];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	vq.vq_avail->idx = 2;
	vq.vq_avail->ring[0] = 0;
	vq.vq_avail->ring[1] = 1;
	desc[0].addr = 0x1000;
	desc[0].len = 1;
	desc[1].addr = 0x1001;
	desc[1].len = 1;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &first), 1);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &second), 1);
	group[0] = first;
	group[1] = first;
	group[2] = second;

	vq_relchain_group(&vq, group, lengths, nitems(group));
	ATF_CHECK_EQ(vq.vq_used->idx, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vq_split_owners_empty(&vq));
	ATF_CHECK(!group[0].outstanding);
	ATF_CHECK(!group[1].outstanding);
	ATF_CHECK(!group[2].outstanding);
}

ATF_TC_WITHOUT_HEAD(oversized_group_retires_all_owners);
ATF_TC_BODY(oversized_group_retires_all_owners, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_packed_desc packed_desc[2];
	struct virtio_packed_event driver_event, device_event;
	struct vring_desc desc[8];
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req first, second, group[3];
	struct iovec iov;
	uint32_t lengths[3] = { 0, 0, 0 };
	uint8_t payload[2];

	/*
	 * An invalid group cardinality must not bypass lease retirement.  Model
	 * two independently acquired split requests plus one malformed member;
	 * before the fix the early size rejection stranded both owner bytes.
	 */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vq.vq_qsize = 2;
	add_region(0x1000, payload, sizeof(payload));
	vq.vq_avail->idx = 2;
	vq.vq_avail->ring[0] = 0;
	vq.vq_avail->ring[1] = 1;
	desc[0].addr = 0x1000;
	desc[0].len = 1;
	desc[1].addr = 0x1001;
	desc[1].len = 1;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &first), 1);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &second), 1);
	memset(group, 0, sizeof(group));
	group[0] = first;
	group[1] = second;
	vq_relchain_group(&vq, group, lengths, nitems(group));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vq_split_owners_empty(&vq));
	for (size_t i = 0; i < nitems(group); i++)
		ATF_CHECK(!group[i].outstanding);
	free(vq.vq_split_owners);
	vq.vq_split_owners = NULL;
	vq.vq_split_owner_count = 0;
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);

	/* The packed reorder/owner bank has the identical failure contract. */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	memset(group, 0, sizeof(group));
	for (size_t i = 0; i < 2; i++) {
		group[i].descriptor_count = 1;
		group[i].completion_id = (uint16_t)(10 + i);
		group[i].packed_head = (uint16_t)i;
		group[i].packed_wrap = true;
		group[i].queue_generation = vq.vq_generation;
		own_test_packed_request(&vq, &group[i]);
	}
	vq_relchain_group(&vq, group, lengths, nitems(group));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	for (size_t i = 0; i < nitems(group); i++)
		ATF_CHECK(!group[i].outstanding);
	vq_packed_completions_fini(&vq);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(access_platform_packed_ring_revalidation);
ATF_TC_BODY(access_platform_packed_ring_revalidation, tc)
{
	struct virtio_packed_desc desc_a[4], desc_b[4];
	struct virtio_packed_event driver_a, driver_b, device_a, device_b;
	struct virtio_consts vc = {
		.vc_name = "packed-dma-generation-test",
		.vc_nvq = 1,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	memset(desc_a, 0, sizeof(desc_a));
	memset(desc_b, 0, sizeof(desc_b));
	memset(&driver_a, 0, sizeof(driver_a));
	memset(&driver_b, 0, sizeof(driver_b));
	memset(&device_a, 0, sizeof(device_a));
	memset(&device_b, 0, sizeof(device_b));
	vs.vs_vc = &vc;
	vs.vs_pi = &pi;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vq.vq_vs = &vs;
	vq.vq_qsize = nitems(desc_a);
	vq.vq_flags = VQ_ALLOC;
	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	vq.vq_packed_avail_wrap = true;
	vq.vq_packed_used_wrap = true;
	vq.vq_desc_gpa = 0x1000;
	vq.vq_driver_gpa = 0x2000;
	vq.vq_device_gpa = 0x3000;
	g_region_count = 0;
	add_region(0x2000, desc_a,
	    nitems(desc_a) * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x3000, &driver_a, VIRTIO14_PACKED_EVENT_SIZE);
	add_region(0x4000, &device_a, VIRTIO14_PACKED_EVENT_SIZE);
	add_region(0x6000, desc_b,
	    nitems(desc_b) * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x7000, &driver_b, VIRTIO14_PACKED_EVENT_SIZE);
	add_region(0x8000, &device_b, VIRTIO14_PACKED_EVENT_SIZE);
	g_domain_generation = 10;
	g_domain_offset = 0x1000;
	g_domain_deny = false;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_domain_ops, &pi, 0x21),
	    0);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	ATF_CHECK_EQ(vq_has_descs(&vq), 0);
	ATF_CHECK_EQ(vq.vq_packed_desc, desc_a);
	desc_b[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);
	g_domain_offset = 0x5000;
	g_domain_generation++;
	ATF_CHECK_EQ(vq_has_descs(&vq), 1);
	ATF_CHECK_EQ(vq.vq_packed_desc, desc_b);
	ATF_CHECK_EQ(vq.vq_packed_driver_event, &driver_b);
	ATF_CHECK_EQ(vq.vq_packed_device_event, &device_b);
	ATF_CHECK_EQ(vq.vq_dma_generation, UINT64_C(11));
}

ATF_TC_WITHOUT_HEAD(platform_ram_discard_contract);
ATF_TC_BODY(platform_ram_discard_contract, tc)
{
	struct virtio_platform_ops no_discard_ops;
	struct virtio_softc vs;
	struct vmctx ctx;

	memset(&vs, 0, sizeof(vs));
	memset(&ctx, 0, sizeof(ctx));
	g_ram_page_size = 4096;
	g_discard_error = 0;
	g_discard_calls = 0;
	g_undiscard_calls = 0;
	g_reverse_calls = 0;
	vi_set_platform_ops(&vs, &test_platform_ops, &ctx);

	ATF_CHECK_EQ(vi_platform_ram_page_size(&vs), 4096);
	ATF_CHECK_EQ(vi_platform_ram_page_size(NULL), 0);
	ATF_CHECK(!vi_platform_msix_enabled(NULL));
	/* Public notification shims treat an absent platform as a no-op. */
	vi_platform_raise_msix(NULL, 0);
	vi_platform_raise_msi(NULL);
	vi_platform_set_intx(NULL, true);
	ATF_CHECK_EQ(vi_platform_reverse_ram(&vs, &ctx, 4096,
	    &g_discard_address), 0);
	ATF_CHECK_EQ(g_reverse_calls, 1);
	ATF_CHECK_EQ(g_discard_address, UINT64_C(0x9000));
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0x2000, 0x3000), 0);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_discard_address, UINT64_C(0x2000));
	ATF_CHECK_EQ(g_discard_len, 0x3000);
	ATF_CHECK_EQ(vi_platform_undiscard_ram(&vs, 0x2000, 0x3000), 0);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_discard_address, UINT64_C(0x2000));
	ATF_CHECK_EQ(g_discard_len, 0x3000);

	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 1, 0x1000), EINVAL);
	ATF_CHECK_EQ(vi_platform_undiscard_ram(&vs, 1, 0x1000), EINVAL);
	ATF_CHECK_EQ(vi_platform_discard_ram(NULL, 0, 0x1000), EINVAL);
	ATF_CHECK_EQ(vi_platform_undiscard_ram(NULL, 0, 0x1000), EINVAL);
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0, 1), EINVAL);
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0, 0), EINVAL);
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs,
	    UINT64_MAX - UINT64_C(0xfff), 0x1000), EINVAL);
	ATF_CHECK_EQ(g_discard_calls, 1);

	g_ram_page_size = 3000;
	ATF_CHECK_EQ(vi_platform_ram_page_size(&vs), 0);
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0, 4096), EINVAL);
	ATF_CHECK_EQ(g_discard_calls, 1);

	g_ram_page_size = 4096;
	g_discard_error = EIO;
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0x4000, 0x1000), EIO);
	ATF_CHECK_EQ(g_discard_calls, 2);

	no_discard_ops = test_platform_ops;
	no_discard_ops.vpo_discard_ram = NULL;
	no_discard_ops.vpo_undiscard_ram = NULL;
	no_discard_ops.vpo_reverse_ram = NULL;
	vi_set_platform_ops(&vs, &no_discard_ops, &ctx);
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, 0x4000, 0x1000),
	    EOPNOTSUPP);
	ATF_CHECK_EQ(vi_platform_undiscard_ram(&vs, 0x4000, 0x1000),
	    EOPNOTSUPP);
	ATF_CHECK_EQ(vi_platform_reverse_ram(&vs, &ctx, 4096,
	    &g_discard_address), EOPNOTSUPP);
}

ATF_TC_WITHOUT_HEAD(snapshot_queue_mapping_contract);
ATF_TC_BODY(snapshot_queue_mapping_contract, tc)
{
	struct virtio_softc vs;
	struct vmctx ctx;
	uint8_t guest[64], wire[sizeof(uint64_t)];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = wire,
			.buf_size = sizeof(wire),
			.buf = wire,
			.buf_rem = sizeof(wire),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	void *mapping;
	const uint64_t gpa = UINT64_C(0x4000);

	memset(&vs, 0, sizeof(vs));
	memset(&ctx, 0, sizeof(ctx));
	g_region_count = 0;
	g_map_calls = 0;
	add_region(gpa, guest, sizeof(guest));
	vi_set_platform_ops(&vs, &test_platform_ops, &ctx);

	mapping = guest;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_BIDIRECTIONAL, &meta), 0);
	ATF_CHECK_EQ(snapshot_load_le64(wire), gpa);
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(g_last_map_address, gpa);
	ATF_CHECK_EQ(g_last_map_len, sizeof(guest));
	ATF_CHECK_EQ(g_last_map_direction, VIRTIO_DMA_BIDIRECTIONAL);

	mapping = NULL;
	meta.op = VM_SNAPSHOT_RESTORE;
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	g_map_calls = 0;
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_WRITE, &meta), 0);
	ATF_CHECK_EQ(mapping, guest);
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(g_last_map_direction, VIRTIO_DMA_DEVICE_WRITE);

	snapshot_store_le64(wire, gpa + 16);
	mapping = NULL;
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	g_map_calls = 0;
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_READ, &meta), EINVAL);
	ATF_CHECK_EQ(mapping, NULL);
	ATF_CHECK_EQ(g_map_calls, 0);

	snapshot_store_le64(wire, gpa);
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire) - 1;
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_READ, &meta), ENOSPC);

	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	g_region_count = 0;
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_READ, &meta), EFAULT);

	add_region(gpa, guest, sizeof(guest));
	mapping = guest + 1;
	meta.op = VM_SNAPSHOT_SAVE;
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_READ, &meta), EINVAL);

	mapping = guest;
	meta.op = (enum vm_snapshot_op)99;
	meta.buffer.buf = wire;
	meta.buffer.buf_rem = sizeof(wire);
	ATF_CHECK_EQ(vi_pci_snapshot_queue_mapping(&vs, &mapping, gpa,
	    sizeof(guest), VIRTIO_DMA_DEVICE_READ, &meta), EINVAL);
}

static int
run_full_virtio_snapshot(struct pci_devinst *pi, void *buffer, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = buffer,
			.buf_size = size,
			.buf = buffer,
			.buf_rem = size,
		},
		.dev_data = pi,
		.op = op,
	};
	int error;

	error = vi_pci_snapshot(&meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

ATF_TC_WITHOUT_HEAD(admin_controller_snapshot_section_is_transactional);
ATF_TC_BODY(admin_controller_snapshot_section_is_transactional, tc)
{
	struct virtio_softc vs;
	uint8_t image[32];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	size_t used;

	memset(&vs, 0, sizeof(vs));
	memset(image, 0, sizeof(image));
	vs.vs_negotiated_caps = VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	g_admin_controller_state = 0x12345678;
	ATF_REQUIRE_EQ(vi_pci_snapshot_admin_controller(&vs, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;
	ATF_CHECK_EQ(used, sizeof(uint64_t) + sizeof(uint32_t));
	ATF_CHECK_EQ(snapshot_load_le64(image), sizeof(uint32_t));

	g_admin_controller_state = 0xa5a5a5a5;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_REQUIRE_EQ(vi_pci_snapshot_admin_controller(&vs, &meta), 0);
	ATF_CHECK_EQ(g_admin_controller_state, 0xa5a5a5a5);

	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_REQUIRE_EQ(vi_pci_snapshot_admin_controller(&vs, &meta), 0);
	ATF_CHECK_EQ(g_admin_controller_state, 0x12345678);

	snapshot_store_le64(image, sizeof(uint32_t) + 1);
	g_admin_controller_state = 0xfeedface;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_admin_controller(&vs, &meta), ENOTSUP);
	ATF_CHECK_EQ(g_admin_controller_state, 0xfeedface);
}

ATF_TC_WITHOUT_HEAD(admin_restore_rolls_back_after_device_failure);
ATF_TC_BODY(admin_restore_rolls_back_after_device_failure, tc)
{
	struct virtio_pci_modern destination_modern, source_modern;
	struct virtio_softc destination, source;
	struct virtio_consts destination_vc, source_vc;
	struct pci_devinst destination_pi, source_pi;
	uint8_t image[512];
	size_t used;

	memset(&destination, 0, sizeof(destination));
	memset(&source, 0, sizeof(source));
	memset(&destination_vc, 0, sizeof(destination_vc));
	memset(&source_vc, 0, sizeof(source_vc));
	memset(&destination_pi, 0, sizeof(destination_pi));
	memset(&source_pi, 0, sizeof(source_pi));
	memset(&destination_modern, 0, sizeof(destination_modern));
	memset(&source_modern, 0, sizeof(source_modern));

	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_modern = &source_modern;
	source.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	source.vs_admin_binding = (void *)(uintptr_t)1;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO14_F_ADMIN_VQ;
	source_vc.vc_hv_caps = source.vs_negotiated_caps;
	/*
	 * The modern queue snapshot path must retain the ACCESS_PLATFORM
	 * binding even when this fixture has no enabled data queue.  This covers
	 * the administration-only form as well as the normal queue-bank path.
	 */
	g_domain_acquires = 0;
	g_domain_releases = 0;
	g_domain_acquire_allowed = true;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&source, &test_leased_domain_ops,
	    &source_pi, 0x301), 0);
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source_vc.vc_snapshot = test_device_snapshot;
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);

	g_admin_controller_state = 0x11223344;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(g_domain_acquires, 1);
	ATF_CHECK_EQ(g_domain_releases, 1);

	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_modern = &destination_modern;
	destination.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	destination.vs_admin_binding = (void *)(uintptr_t)1;
	destination.vs_negotiated_caps = source.vs_negotiated_caps;
	destination_vc.vc_hv_caps = destination.vs_negotiated_caps;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&destination,
	    &test_leased_domain_ops, &destination_pi, 0x302), 0);
	/*
	 * Keep a valid, deliberately distinct destination transport image.  The
	 * device callback below fails only after common, queue, and admin state
	 * have been decoded.  These values therefore prove that its failure rolls
	 * the whole transaction back, rather than merely compensating the admin
	 * controller.
	 */
	destination.vs_flags = VIRTIO_USE_MSIX;
	destination.vs_curq = 7;
	destination.vs_status = source.vs_status |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK;
	destination.vs_config_deferred = true;
	destination.vs_msix_cfg_idx = 0;
	destination_vc.vc_snapshot = test_device_snapshot;
	ATF_REQUIRE_EQ(pthread_mutex_init(&destination.vs_isr_mtx, NULL), 0);
	VS_ISR_LOCK(&destination);
	destination.vs_isr = VIRTIO_PCI_ISR_CONFIG;
	VS_ISR_UNLOCK(&destination);

	/*
	 * The incoming admin image is applied before device publication.  A
	 * later device error must restore the destination's original controller
	 * rather than leaving common and administration state from different
	 * checkpoint transactions.
	 */
	g_admin_controller_state = 0xaabbccdd;
	g_snapshot_restore_failure = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK_EQ(g_admin_controller_state, 0xaabbccdd);
	ATF_CHECK_EQ(destination.vs_flags, VIRTIO_USE_MSIX);
	ATF_CHECK_EQ(destination.vs_curq, 7);
	ATF_CHECK_EQ(destination.vs_status,
	    source.vs_status | VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(destination.vs_config_deferred);
	ATF_CHECK_EQ(destination.vs_msix_cfg_idx, 0);
	VS_ISR_LOCK(&destination);
	ATF_CHECK_EQ(destination.vs_isr, VIRTIO_PCI_ISR_CONFIG);
	VS_ISR_UNLOCK(&destination);

	g_snapshot_restore_failure = false;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(g_admin_controller_state, 0x11223344);

	/*
	 * A device codec whose validation and publication parsers consume
	 * different lengths could otherwise make the pre-restored controller
	 * come from a different byte range.  Detect that contract violation,
	 * compensate the controller, and quarantine the destination.
	 */
	g_snapshot_consume_wire = true;
	g_snapshot_device_wire = 0x5a;
	g_admin_controller_state = 0x55667788;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);
	g_snapshot_device_wire = 0xc3;
	g_admin_controller_state = 0x99aabbcc;
	g_snapshot_restore_length_mismatch = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EPROTO);
	ATF_CHECK_EQ(g_admin_controller_state, 0x99aabbcc);
	ATF_CHECK_EQ(g_snapshot_device_wire, 0xc3);
	ATF_CHECK(destination.vs_restore_incomplete);
	ATF_CHECK((destination.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	g_snapshot_restore_length_mismatch = false;
	g_snapshot_consume_wire = false;

	/* Drop the test-only bindings after taking the devices back to reset. */
	source.vs_status = 0;
	destination.vs_status = 0;
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&source), 0);
	ATF_REQUIRE_EQ(vi_clear_dma_domain(&destination), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

/*
 * Guest suspend and checkpoint pause are independent owners.  A checkpoint
 * image may therefore restore the former even though the latter is released
 * by vi_pci_resume().  The optional device hook is for backends which must
 * retain an external drain/freeze in that state.  It must not run on a failed
 * restore, because the surrounding common-state transaction rolls back.
 */
ATF_TC_WITHOUT_HEAD(snapshot_restore_retains_guest_suspend_ownership);
ATF_TC_BODY(snapshot_restore_retains_guest_suspend_ownership, tc)
{
	struct virtio_pci_modern destination_modern, source_modern;
	struct virtio_softc destination, source;
	struct virtio_consts destination_vc, source_vc;
	struct pci_devinst destination_pi, source_pi;
	uint8_t image[512];
	size_t used;

	memset(&destination, 0, sizeof(destination));
	memset(&source, 0, sizeof(source));
	memset(&destination_vc, 0, sizeof(destination_vc));
	memset(&source_vc, 0, sizeof(source_vc));
	memset(&destination_pi, 0, sizeof(destination_pi));
	memset(&source_pi, 0, sizeof(source_pi));
	memset(&destination_modern, 0, sizeof(destination_modern));
	memset(&source_modern, 0, sizeof(source_modern));

	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_modern = &source_modern;
	source.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1 | VIRTIO_F_SUSPEND;
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK |
	    VIRTIO_CONFIG_STATUS_SUSPEND;
	source.vs_suspended = true;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source_vc.vc_hv_caps = source.vs_negotiated_caps;
	source_vc.vc_snapshot = test_device_snapshot;
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);

	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_modern = &destination_modern;
	destination.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	destination.vs_negotiated_caps = source.vs_negotiated_caps;
	destination.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	destination.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vc.vc_hv_caps = destination.vs_negotiated_caps;
	destination_vc.vc_snapshot = test_device_snapshot;
	destination_vc.vc_restore_suspended = restore_suspended_count;
	ATF_REQUIRE_EQ(pthread_mutex_init(&destination.vs_isr_mtx, NULL), 0);

	g_restore_suspended_count = 0;
	g_restore_suspended_observed = false;
	g_snapshot_restore_failure = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK_EQ(g_restore_suspended_count, 0);
	ATF_CHECK(!destination.vs_suspended);

	g_snapshot_restore_failure = false;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(destination.vs_suspended);
	ATF_CHECK_EQ(g_restore_suspended_count, 1);
	ATF_CHECK(g_restore_suspended_observed);

	/*
	 * Replaying an identical suspended image must not accumulate a backend
	 * owner.  The original restored guest-suspend owner remains in force;
	 * checkpoint resume contributes and releases its own owner separately.
	 */
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(g_restore_suspended_count, 1);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

/*
 * Restore must reconcile both directions of guest suspend ownership.  In
 * particular, an image that is runnable may replace a destination that was
 * guest-suspended when checkpoint pause began.  Its old backend owner must be
 * released once, before common checkpoint resume releases its own owner.
 */
ATF_TC_WITHOUT_HEAD(snapshot_restore_releases_guest_suspend_ownership);
ATF_TC_BODY(snapshot_restore_releases_guest_suspend_ownership, tc)
{
	struct virtio_pci_modern destination_modern, source_modern;
	struct virtio_softc destination, source;
	struct virtio_consts destination_vc, source_vc;
	struct pci_devinst destination_pi, source_pi;
	uint8_t image[512];
	size_t used;

	memset(&destination, 0, sizeof(destination));
	memset(&source, 0, sizeof(source));
	memset(&destination_vc, 0, sizeof(destination_vc));
	memset(&source_vc, 0, sizeof(source_vc));
	memset(&destination_pi, 0, sizeof(destination_pi));
	memset(&source_pi, 0, sizeof(source_pi));
	memset(&destination_modern, 0, sizeof(destination_modern));
	memset(&source_modern, 0, sizeof(source_modern));

	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_modern = &source_modern;
	source.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1 | VIRTIO_F_SUSPEND;
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source_vc.vc_hv_caps = source.vs_negotiated_caps;
	source_vc.vc_snapshot = test_device_snapshot;
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);

	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_modern = &destination_modern;
	destination.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	destination.vs_negotiated_caps = source.vs_negotiated_caps;
	destination.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK |
	    VIRTIO_CONFIG_STATUS_SUSPEND;
	destination.vs_suspended = true;
	destination.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vc.vc_hv_caps = destination.vs_negotiated_caps;
	destination_vc.vc_snapshot = test_device_snapshot;
	destination_vc.vc_restore_resumed = restore_resumed_count;
	ATF_REQUIRE_EQ(pthread_mutex_init(&destination.vs_isr_mtx, NULL), 0);

	g_restore_resumed_count = 0;
	g_restore_resumed_observed = false;
	g_snapshot_restore_failure = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK_EQ(g_restore_resumed_count, 0);
	ATF_CHECK(destination.vs_suspended);

	g_snapshot_restore_failure = false;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(!destination.vs_suspended);
	ATF_CHECK_EQ(g_restore_resumed_count, 1);
	ATF_CHECK(g_restore_resumed_observed);

	/* Replaying the runnable image cannot release a nonexistent owner. */
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(g_restore_resumed_count, 1);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(legacy_snapshot_feature_preflight);
ATF_TC_BODY(legacy_snapshot_feature_preflight, tc)
{
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts destination_vc = {
		.vc_nvq = 1,
		.vc_cfgsize = 8,
		.vc_hv_caps = 0,
	}, source_vc = {
		.vc_nvq = 1,
		.vc_cfgsize = 8,
		.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX,
	};
	uint8_t image[64];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	size_t used;

	source.vs_vc = &source_vc;
	destination.vs_vc = &destination_vc;
	memset(image, 0xa5, sizeof(image));
	source.vs_negotiated_caps = VIRTIO_F_RING_PACKED;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&source, &meta), EINVAL);
	ATF_CHECK_EQ(meta.buffer.buf, image);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(image));
	ATF_CHECK_EQ(image[0], 0xa5);
	source.vs_negotiated_caps = 0;
	ATF_REQUIRE_EQ(vi_pci_snapshot_consts(&source, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;

	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&destination, &meta), ENOTSUP);

	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&destination, &meta), ENOTSUP);

	/*
	 * A destination feature superset remains compatible in both phases.
	 * The source capability word selects the serialized interpretation.
	 */
	destination_vc.vc_hv_caps = source_vc.vc_hv_caps |
	    VIRTIO_F_RING_PACKED | (UINT64_C(1) << 63);
	destination.vs_negotiated_caps = VIRTIO_F_RING_PACKED;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&destination, &meta), EINVAL);

	destination.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&destination, &meta), 0);
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts(&destination, &meta), 0);
}

ATF_TC_WITHOUT_HEAD(legacy_snapshot_save_rejects_wide_features_atomically);
ATF_TC_BODY(legacy_snapshot_save_rejects_wide_features_atomically, tc)
{
	struct virtio_softc vs = { 0 };
	uint8_t image[64];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	uint64_t negotiated;

	memset(image, 0xa5, sizeof(image));
	negotiated = VIRTIO_RING_F_EVENT_IDX | VIRTIO14_F_VERSION_1;
	vs.vs_negotiated_caps = negotiated;
	ATF_CHECK_EQ(vi_pci_snapshot_softc(&vs, &meta), EINVAL);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, negotiated);
	ATF_CHECK_EQ(meta.buffer.buf, image);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(image));
	ATF_CHECK_EQ(image[0], 0xa5);
}

/*
 * The device-local modern decoder is used during the non-publishing restore
 * preflight as well as below the complete checkpoint compatibility envelope.
 * It must therefore reject a negotiated bit which the image's own saved
 * offered-feature word cannot have selected; relying on the outer envelope
 * would make the direct decoder accept a malformed image on a feature-rich
 * destination.
 */
ATF_TC_WITHOUT_HEAD(modern_snapshot_rejects_unoffered_negotiation);
ATF_TC_BODY(modern_snapshot_rejects_unoffered_negotiation, tc)
{
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts destination_vc = {
		.vc_nvq = 1,
		.vc_cfgsize = 8,
		.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX | VIRTIO_F_RING_PACKED,
	}, source_vc = {
		.vc_nvq = 1,
		.vc_cfgsize = 8,
		.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX,
	};
	uint8_t image[64];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	size_t used;

	source.vs_vc = &source_vc;
	destination.vs_vc = &destination_vc;
	memset(image, 0xa5, sizeof(image));
	source.vs_negotiated_caps = VIRTIO_F_RING_PACKED;
	ATF_CHECK_EQ(vi_pci_snapshot_consts_modern(&source, &meta), EINVAL);
	ATF_CHECK_EQ(meta.buffer.buf, image);
	ATF_CHECK_EQ(meta.buffer.buf_rem, sizeof(image));
	ATF_CHECK_EQ(image[0], 0xa5);
	source.vs_negotiated_caps = VIRTIO14_F_VERSION_1;
	ATF_REQUIRE_EQ(vi_pci_snapshot_consts_modern(&source, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;

	/* This bit is supported by the destination but absent from the image. */
	destination.vs_negotiated_caps = VIRTIO14_F_VERSION_1 |
	    VIRTIO_F_RING_PACKED;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts_modern(&destination, &meta), EINVAL);

	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts_modern(&destination, &meta), EINVAL);

	/* A negotiated subset of the saved offer remains valid. */
	destination.vs_negotiated_caps = VIRTIO14_F_VERSION_1 |
	    VIRTIO_RING_F_EVENT_IDX;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_CHECK_EQ(vi_pci_snapshot_consts_modern(&destination, &meta), 0);
}

ATF_TC_WITHOUT_HEAD(legacy_snapshot_advances_destination_generation);
ATF_TC_BODY(legacy_snapshot_advances_destination_generation, tc)
{
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts destination_vc = { 0 }, source_vc = { 0 };
	struct pci_devinst destination_pi = { 0 }, source_pi = { 0 };
	struct vqueue_info destination_vq = { 0 }, source_vq = { 0 };
	uint8_t image[256];
	struct vm_snapshot_meta save_meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	struct vm_snapshot_meta restore_meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_RESTORE,
	};
	size_t used;

	source_pi.pi_arg = &source;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_queues = &source_vq;
	source_vc.vc_nvq = 1;
	source_vq.vq_vs = &source;
	source_vq.vq_qsize = 8;
	source_vq.vq_num = 0;
	source_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_vq.vq_generation = 77;

	ATF_REQUIRE_EQ(vi_pci_snapshot_queues(&source, &save_meta), 0);
	used = sizeof(image) - save_meta.buffer.buf_rem;

	destination_pi.pi_arg = &destination;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_queues = &destination_vq;
	destination_vc.vc_nvq = 1;
	destination_vq.vq_vs = &destination;
	destination_vq.vq_qsize = 8;
	destination_vq.vq_num = 0;
	destination_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vq.vq_generation = 9;

	restore_meta.buffer.buf = image;
	restore_meta.buffer.buf_rem = used;
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues(&destination, &restore_meta), 0);
	ATF_CHECK_EQ(destination_vq.vq_generation, 10);

	restore_meta.buffer.buf = image;
	restore_meta.buffer.buf_rem = used;
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues(&destination, &restore_meta), 0);
	ATF_CHECK_EQ(destination_vq.vq_generation, 11);

	destination_vq.vq_generation = UINT64_MAX;
	restore_meta.buffer.buf = image;
	restore_meta.buffer.buf_rem = used;
	ATF_CHECK_EQ(vi_pci_snapshot_queues(&destination, &restore_meta),
	    EOVERFLOW);
	ATF_CHECK_EQ(destination_vq.vq_generation, UINT64_MAX);
}

ATF_TC_WITHOUT_HEAD(legacy_snapshot_validate_does_not_write_guest_ring);
ATF_TC_BODY(legacy_snapshot_validate_does_not_write_guest_ring, tc)
{
	_Alignas(VRING_ALIGN) uint8_t destination_ring[8192];
	_Alignas(VRING_ALIGN) uint8_t source_ring[8192];
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts destination_vc = { 0 }, source_vc = { 0 };
	struct pci_devinst destination_pi = { 0 }, source_pi = { 0 };
	struct vqueue_info destination_vq = { 0 }, source_vq = { 0 };
	struct vmctx ctx = { 0 };
	uint8_t image[16384], before[sizeof(destination_ring)];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	size_t ring_size, used;

	memset(source_ring, 0x5a, sizeof(source_ring));
	memset(destination_ring, 0xc3, sizeof(destination_ring));
	ring_size = vring_size_aligned(8);
	ATF_REQUIRE(ring_size <= sizeof(source_ring));

	source_pi.pi_arg = &source;
	source_pi.pi_vmctx = &ctx;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_queues = &source_vq;
	source_vc.vc_nvq = 1;
	source_vq.vq_vs = &source;
	source_vq.vq_qsize = 8;
	source_vq.vq_num = 0;
	source_vq.vq_flags = VQ_ALLOC;
	source_vq.vq_pfn = 0x10;
	source_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_vq.vq_desc = (void *)source_ring;
	source_vq.vq_avail = (void *)(source_ring +
	    8 * VIRTIO14_SPLIT_DESC_SIZE);
	source_vq.vq_used = (void *)roundup2(
	    (uintptr_t)source_vq.vq_avail +
	    VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    8 * VIRTIO14_SPLIT_AVAIL_ELEM_SIZE +
	    VIRTIO14_SPLIT_EVENT_FIELD_SIZE, VRING_ALIGN);
	g_region_count = 0;
	add_region(UINT64_C(0x10000), source_ring, sizeof(source_ring));
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues(&source, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;
	ATF_REQUIRE(used >= ring_size);
	/* Make the redundant saved ring visibly differ from the destination. */
	image[used - ring_size] ^= 0xff;

	destination_pi.pi_arg = &destination;
	destination_pi.pi_vmctx = &ctx;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_queues = &destination_vq;
	destination_vc.vc_nvq = 1;
	destination_vq.vq_vs = &destination;
	destination_vq.vq_qsize = 8;
	destination_vq.vq_num = 0;
	destination_vq.vq_flags = VQ_ALLOC;
	destination_vq.vq_pfn = 0x10;
	destination_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vq.vq_desc = (void *)destination_ring;
	destination_vq.vq_avail = (void *)(destination_ring +
	    8 * VIRTIO14_SPLIT_DESC_SIZE);
	destination_vq.vq_used = (void *)roundup2(
	    (uintptr_t)destination_vq.vq_avail +
	    VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    8 * VIRTIO14_SPLIT_AVAIL_ELEM_SIZE +
	    VIRTIO14_SPLIT_EVENT_FIELD_SIZE, VRING_ALIGN);
	g_region_count = 0;
	add_region(UINT64_C(0x10000), destination_ring,
	    sizeof(destination_ring));
	memcpy(before, destination_ring, sizeof(before));
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.op = VM_SNAPSHOT_VALIDATE;
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues(&destination, &meta), 0);
	ATF_CHECK(memcmp(destination_ring, before, sizeof(before)) == 0);
}

ATF_TC_WITHOUT_HEAD(modern_snapshot_rejects_disabled_pending_notify);
ATF_TC_BODY(modern_snapshot_rejects_disabled_pending_notify, tc)
{
	struct virtio_softc vs = { 0 };
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi = { 0 };
	struct vqueue_info vq = { 0 };
	uint8_t image[256];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};

	pi.pi_arg = &vs;
	pi.pi_msix.table_count = 1;
	vs.vs_pi = &pi;
	vs.vs_vc = &vc;
	vs.vs_queues = &vq;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1;
	vc.vc_nvq = 1;
	vq.vq_vs = &vs;
	vq.vq_num = 0;
	vq.vq_qsize = 8;
	vq.vq_qsize_max = 8;
	vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;

	/*
	 * A disabled modern queue ignores notifications, so it cannot own a
	 * deferred kick.  Reject that impossible combination instead of
	 * restoring a latch which vi_pci_notify_queue() can never consume.
	 */
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues_modern(&vs, &meta), 0);
	vq.vq_notify_pending = true;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = sizeof(image);
	ATF_CHECK_EQ(vi_pci_snapshot_queues_modern(&vs, &meta), EINVAL);
}

ATF_TC_WITHOUT_HEAD(modern_snapshot_rejects_unreachable_status_prefix);
ATF_TC_BODY(modern_snapshot_rejects_unreachable_status_prefix, tc)
{
	/*
	 * The modern-common snapshot prefix is a bhyve format, not a C
	 * structure: magic(4), version(4), flags(4), features(8), queue(4),
	 * then the one-byte device status.  Keep the malformed stimulus local
	 * and literal so this check cannot inherit its expected offset from the
	 * production codec.
	 */
	enum {
		modern_common_status_offset = 24,
		modern_common_suspended_offset = 26,
	};
	const uint8_t ready = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_DRIVER | VIRTIO14_STATUS_FEATURES_OK |
	    VIRTIO14_STATUS_DRIVER_OK;
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts vc = { 0 };
	struct pci_devinst destination_pi = { 0 }, source_pi = { 0 };
	uint8_t image[64];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
	};
	size_t used;

	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_pi = &source_pi;
	source.vs_vc = &vc;
	source.vs_negotiated_caps = VIRTIO14_F_VERSION_1;
	source.vs_status = ready;
	source.vs_msix_cfg_idx = VIRTIO14_MSI_NO_VECTOR;
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);

	meta.dev_data = &source_pi;
	meta.op = VM_SNAPSHOT_SAVE;
	ATF_REQUIRE_EQ(vi_pci_snapshot_softc_modern(&source, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;
	ATF_REQUIRE_EQ(used > modern_common_status_offset, true);

	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &vc;
	destination.vs_negotiated_caps = VIRTIO14_F_VERSION_1;
	destination.vs_status = VIRTIO14_STATUS_ACKNOWLEDGE;
	destination.vs_msix_cfg_idx = VIRTIO14_MSI_NO_VECTOR;
	ATF_REQUIRE_EQ(pthread_mutex_init(&destination.vs_isr_mtx, NULL), 0);

	/* DRIVER_OK cannot exist without the completed feature handshake. */
	image[modern_common_status_offset] = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_DRIVER | VIRTIO14_STATUS_DRIVER_OK;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	meta.dev_data = &destination_pi;
	meta.op = VM_SNAPSHOT_RESTORE;
	ATF_CHECK_EQ(vi_pci_snapshot_softc_modern(&destination, &meta), EINVAL);
	ATF_CHECK_EQ(destination.vs_status, VIRTIO14_STATUS_ACKNOWLEDGE);

	/* FEATURES_OK likewise cannot precede the DRIVER acknowledgement. */
	image[modern_common_status_offset] = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_FEATURES_OK;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	ATF_CHECK_EQ(vi_pci_snapshot_softc_modern(&destination, &meta), EINVAL);
	ATF_CHECK_EQ(destination.vs_status, VIRTIO14_STATUS_ACKNOWLEDGE);

	/* A modern feature handshake always includes the mandatory VERSION_1. */
	virtio14_store_le64(image + 12, 0);
	image[modern_common_status_offset] = ready;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	ATF_CHECK_EQ(vi_pci_snapshot_softc_modern(&destination, &meta), EINVAL);
	ATF_CHECK_EQ(destination.vs_status, VIRTIO14_STATUS_ACKNOWLEDGE);

	/*
	 * Suspend is reached only after a successful feature handshake.  The
	 * live transition clears DRIVER_OK, but retains ACK, DRIVER, and
	 * FEATURES_OK; an isolated SUSPEND bit is not a resumable device state.
	 */
	virtio14_store_le64(image + 12,
	    VIRTIO14_F_VERSION_1 | VIRTIO14_F_SUSPEND);
	image[modern_common_status_offset] = VIRTIO14_STATUS_SUSPEND;
	image[modern_common_suspended_offset] = 1;
	meta.buffer.buf = image;
	meta.buffer.buf_rem = used;
	ATF_CHECK_EQ(vi_pci_snapshot_softc_modern(&destination, &meta), EINVAL);
	ATF_CHECK_EQ(destination.vs_status, VIRTIO14_STATUS_ACKNOWLEDGE);
	image[modern_common_suspended_offset] = 0;

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(modern_snapshot_has_little_endian_golden_encoding);
ATF_TC_BODY(modern_snapshot_has_little_endian_golden_encoding, tc)
{
	/*
	 * This is an independent on-disk fixture for the v2 common-modern
	 * record.  Do not derive either offsets or bytes from the production
	 * declarations: the purpose is to catch a regression back to native
	 * scalar or structure serialization on a future non-little-endian host.
	 */
	static const uint8_t expected[] = {
		0x31, 0x43, 0x54, 0x56, /* magic: VTC1 */
		0x02, 0x00, 0x00, 0x00, /* format version */
		0x01, 0x00, 0x00, 0x00, /* MSI-X flag */
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
					/* VERSION_1 */
		0x04, 0x03, 0x02, 0x01, /* selected queue */
		0x0f, /* ACK | DRIVER | FEATURES_OK | DRIVER_OK */
		0x01, /* reset failed */
		0x00, /* suspended */
		0x01, /* config notification deferred */
		0x03, /* ISR */
		0xff, 0xff, /* no MSI-X config vector */
	};
	struct virtio_softc source = { 0 };
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi = { 0 };
	uint8_t image[sizeof(expected) + 1];
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
	};
	size_t used;

	pi.pi_arg = &source;
	pi.pi_msix.table_count = 1;
	source.vs_pi = &pi;
	source.vs_vc = &vc;
	source.vs_flags = VIRTIO_USE_MSIX;
	source.vs_negotiated_caps = VIRTIO14_F_VERSION_1;
	source.vs_curq = 0x01020304;
	source.vs_status = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_DRIVER | VIRTIO14_STATUS_FEATURES_OK |
	    VIRTIO14_STATUS_DRIVER_OK;
	source.vs_reset_failed = 1;
	source.vs_config_deferred = 1;
	source.vs_isr = VIRTIO_PCI_ISR_INTR | VIRTIO_PCI_ISR_CONFIG;
	source.vs_msix_cfg_idx = VIRTIO14_MSI_NO_VECTOR;
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);

	meta.dev_data = &pi;
	meta.op = VM_SNAPSHOT_SAVE;
	ATF_REQUIRE_EQ(vi_pci_snapshot_softc_modern(&source, &meta), 0);
	used = sizeof(image) - meta.buffer.buf_rem;
	ATF_CHECK_EQ(used, sizeof(expected));
	ATF_CHECK(memcmp(image, expected, sizeof(expected)) == 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_compat_includes_admin_queue_shape);
ATF_TC_BODY(snapshot_compat_includes_admin_queue_shape, tc)
{
	struct pci_snapshot_compat compat;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi = { 0 };
	struct virtio_softc vs = { 0 };
	struct vqueue_info ordinary[1] = { 0 };
	struct vqueue_info admin[2] = { 0 };

	/*
	 * The compatibility shape is an independent decimal fixture.  queue_count
	 * identifies the one ordinary entry; the suffix then records the gapped
	 * admin selector base, its count, and both maximum sizes.
	 */
	pi.pi_arg = &vs;
	pi.pi_msix.table_count = 4;
	vs.vs_pi = &pi;
	vs.vs_vc = &vc;
	vs.vs_queues = ordinary;
	vs.vs_admin_queues = admin;
	vs.vs_admin_queue_index = 5;
	vs.vs_admin_queue_count = 2;
	vc.vc_nvq = 1;
	ordinary[0].vq_qsize_max = 8;
	admin[0].vq_qsize_max = 16;
	admin[1].vq_qsize_max = 32;

	ATF_REQUIRE_EQ(vi_pci_snapshot_compat(&pi, &compat), 0);
	ATF_CHECK(strcmp(compat.queue_sizes, "8,5,2,16,32") == 0);
	ATF_CHECK_EQ(compat.queue_count, 1);

	/* A selector change is a migration incompatibility, not an alias. */
	vs.vs_admin_queue_index = 6;
	ATF_REQUIRE_EQ(vi_pci_snapshot_compat(&pi, &compat), 0);
	ATF_CHECK(strcmp(compat.queue_sizes, "8,6,2,16,32") == 0);

	/* A count without storage is malformed before any manifest is emitted. */
	vs.vs_admin_queues = NULL;
	ATF_CHECK_EQ(vi_pci_snapshot_compat(&pi, &compat), EINVAL);
}

ATF_TC_WITHOUT_HEAD(snapshot_compat_includes_shared_memory_shape);
ATF_TC_BODY(snapshot_compat_includes_shared_memory_shape, tc)
{
	struct pci_snapshot_compat compat;
	struct virtio_pci_modern modern = { 0 };
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi = { 0 };
	struct virtio_softc vs = { 0 };
	struct vqueue_info queue = { 0 };

	/*
	 * This is an independent decimal fixture.  In particular, the second
	 * offset is above 32 bits so that field swaps or narrowing cannot alias a
	 * plausible region identifier, BAR, or length.
	 */
	pi.pi_arg = &vs;
	vs.vs_pi = &pi;
	vs.vs_vc = &vc;
	vs.vs_queues = &queue;
	vs.vs_modern = &modern;
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vc.vc_nvq = 1;
	queue.vq_qsize_max = 8;
	modern.shared_memory_count = 2;
	modern.shared_memory[0].id = 7;
	modern.shared_memory[0].bar = 4;
	modern.shared_memory[0].offset = 4096;
	modern.shared_memory[0].length = 8192;
	modern.shared_memory[1].id = 9;
	modern.shared_memory[1].bar = 5;
	modern.shared_memory[1].offset = UINT64_C(4294967296);
	modern.shared_memory[1].length = 12288;

	ATF_REQUIRE_EQ(vi_pci_snapshot_compat(&pi, &compat), 0);
	ATF_CHECK(strcmp(compat.shared_memory,
	    "7:4:4096:8192,9:5:4294967296:12288") == 0);

	/* Every extent field contributes independently to compatibility. */
	modern.shared_memory[0].offset = 16384;
	modern.shared_memory[1].length = 20480;
	ATF_REQUIRE_EQ(vi_pci_snapshot_compat(&pi, &compat), 0);
	ATF_CHECK(strcmp(compat.shared_memory,
	    "7:4:16384:8192,9:5:4294967296:20480") == 0);

	modern.shared_memory_count = VIRTIO_PCI_SHARED_MEMORY_MAX + 1;
	ATF_CHECK_EQ(vi_pci_snapshot_compat(&pi, &compat), EINVAL);
}

ATF_TC_WITHOUT_HEAD(modern_snapshot_includes_admin_queue_bank);
ATF_TC_BODY(modern_snapshot_includes_admin_queue_bank, tc)
{
	struct virtio_softc destination = { 0 }, source = { 0 };
	struct virtio_consts destination_vc = { 0 }, source_vc = { 0 };
	struct pci_devinst destination_pi = { 0 }, source_pi = { 0 };
	struct vqueue_info destination_queues[1] = { 0 };
	struct vqueue_info source_queues[1] = { 0 };
	struct vqueue_info destination_admin[1] = { 0 };
	struct vqueue_info source_admin[1] = { 0 };
	uint8_t image[2048];
	struct vm_snapshot_meta save_meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	struct vm_snapshot_meta restore_meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_RESTORE,
	};
	size_t used;

	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_queues = source_queues;
	source.vs_admin_queues = source_admin;
	source.vs_admin_queue_index = 5;
	source.vs_admin_queue_count = 1;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO14_F_ADMIN_VQ;
	source_vc.vc_nvq = 1;
	source_queues[0].vq_vs = &source;
	source_queues[0].vq_num = 0;
	source_queues[0].vq_qsize = 8;
	source_queues[0].vq_qsize_max = 8;
	source_queues[0].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_admin[0].vq_vs = &source;
	source_admin[0].vq_num = 5;
	source_admin[0].vq_qsize = 8;
	source_admin[0].vq_qsize_max = 8;
	source_admin[0].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_admin[0].vq_last_avail = 7;
	source_admin[0].vq_next_used = 6;
	source_admin[0].vq_generation = 41;

	ATF_REQUIRE_EQ(vi_pci_snapshot_queues_modern(&source, &save_meta), 0);
	used = sizeof(image) - save_meta.buffer.buf_rem;

	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_queues = destination_queues;
	destination.vs_admin_queues = destination_admin;
	destination.vs_admin_queue_index = 5;
	destination.vs_admin_queue_count = 1;
	destination.vs_negotiated_caps =
	    VIRTIO_F_VERSION_1 | VIRTIO14_F_ADMIN_VQ;
	destination_vc.vc_nvq = 1;
	destination_queues[0].vq_vs = &destination;
	destination_queues[0].vq_num = 0;
	destination_queues[0].vq_qsize = 8;
	destination_queues[0].vq_qsize_max = 8;
	destination_queues[0].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_admin[0].vq_vs = &destination;
	destination_admin[0].vq_num = 5;
	destination_admin[0].vq_qsize = 8;
	destination_admin[0].vq_qsize_max = 8;
	destination_admin[0].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_admin[0].vq_generation = 9;

	restore_meta.buffer.buf_rem = used;
	ATF_REQUIRE_EQ(vi_pci_snapshot_queues_modern(&destination,
	    &restore_meta), 0);
	ATF_CHECK_EQ(destination_admin[0].vq_last_avail, 7);
	ATF_CHECK_EQ(destination_admin[0].vq_next_used, 6);
	ATF_CHECK_EQ(destination_admin[0].vq_generation, 10);
	ATF_CHECK_EQ((size_t)(restore_meta.buffer.buf - image), used);
}

ATF_TC_WITHOUT_HEAD(packed_snapshot_cache_resize_transaction);
ATF_TC_BODY(packed_snapshot_cache_resize_transaction, tc)
{
	struct virtio_packed_desc destination_desc[5], source_desc[3];
	struct virtio_packed_event destination_driver_event;
	struct virtio_packed_event destination_device_event;
	struct virtio_packed_event source_driver_event, source_device_event;
	struct virtio_packed_completion *destination_original;
	struct virtio_softc destination, source;
	struct virtio_consts destination_vc = { 0 }, source_vc = { 0 };
	struct pci_devinst destination_pi, source_pi;
	struct vqueue_info destination_vq, source_vq;
	uint8_t image[1024];
	size_t used;

	setup_packed_queue(&source, &source_vc, &source_pi, &source_vq,
	    source_desc, &source_driver_event, &source_device_event,
	    nitems(source_desc));
	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_queues = &source_vq;
	source_vc.vc_snapshot = test_device_snapshot;
	source_vc.vc_hv_caps = VIRTIO_F_VERSION_1 | VIRTIO_F_RING_PACKED;
	source_vq.vq_qsize_max = 8;
	source_vq.vq_enabled = 1;
	source_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_vq.vq_desc_gpa = 0x1000;
	source_vq.vq_driver_gpa = 0x2000;
	source_vq.vq_device_gpa = 0x3000;
	source_vq.vq_generation = 77;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO_F_RING_PACKED;
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	add_region(0x1000, source_desc, 3U * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x2000, &source_driver_event,
	    sizeof(source_driver_event));
	add_region(0x3000, &source_device_event,
	    sizeof(source_device_event));
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);

	setup_packed_queue(&destination, &destination_vc, &destination_pi,
	    &destination_vq, destination_desc, &destination_driver_event,
	    &destination_device_event, nitems(destination_desc));
	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_queues = &destination_vq;
	destination_vc.vc_snapshot = test_device_snapshot;
	destination_vc.vc_hv_caps =
	    VIRTIO_F_VERSION_1 | VIRTIO_F_RING_PACKED;
	destination_vq.vq_qsize_max = 8;
	destination_vq.vq_enabled = 1;
	destination_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vq.vq_generation = 9;
	destination.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	destination.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO_F_RING_PACKED;
	destination.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	/*
	 * VALIDATE decodes the common section to drive the same structural
	 * checks as RESTORE, but it is a preflight operation.  Keep values which
	 * differ from the source so this case proves the outer common-state
	 * transaction restores every temporary decode, rather than merely
	 * preserving identical fields by accident.
	 */
	destination.vs_flags = VIRTIO_USE_MSIX;
	destination.vs_curq = 6;
	destination_original = destination_vq.vq_packed_completions;
	g_region_count = 0;
	add_region(0x1000, destination_desc,
	    3U * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x2000, &destination_driver_event,
	    sizeof(destination_driver_event));
	add_region(0x3000, &destination_device_event,
	    sizeof(destination_device_event));

	/*
	 * Preflight consumes and checks the exact restore representation while
	 * rolling every staged common, queue, and cache change back.  In
	 * particular, validating a differently sized packed queue must not
	 * replace the destination's reorder cache or advance its incarnation.
	 */
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK(destination_vq.vq_packed_completions ==
	    destination_original);
	ATF_CHECK_EQ(destination_vq.vq_packed_completion_count,
	    nitems(destination_desc));
	ATF_CHECK_EQ(destination_vq.vq_qsize, nitems(destination_desc));
	ATF_CHECK_EQ(destination_vq.vq_generation, 9);
	ATF_CHECK_EQ(destination.vs_flags, VIRTIO_USE_MSIX);
	ATF_CHECK_EQ(destination.vs_curq, 6);

	/*
	 * An owner acquired under an earlier split incarnation is still live
	 * even though this destination currently selects packed rings.  Restore
	 * must not replace the queue's cursors until that owner is retired.
	 */
	ATF_REQUIRE_EQ(vq_split_owners_init(&destination_vq), 0);
	destination_vq.vq_split_owners[0] = 1;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EBUSY);
	ATF_CHECK(destination_vq.vq_packed_completions ==
	    destination_original);
	ATF_CHECK_EQ(destination_vq.vq_qsize, nitems(destination_desc));
	ATF_CHECK_EQ(destination_vq.vq_generation, 9);
	destination_vq.vq_split_owners[0] = 0;

	/*
	 * A device-specific failure after queue staging restores the old
	 * differently-sized cache instead of leaking or publishing the stage.
	 */
	g_snapshot_restore_failure = true;
	g_snapshot_restore_incomplete = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK(destination_vq.vq_packed_completions ==
	    destination_original);
	ATF_CHECK_EQ(destination_vq.vq_packed_completion_count,
	    nitems(destination_desc));
	ATF_CHECK_EQ(destination_vq.vq_qsize, nitems(destination_desc));
	ATF_CHECK_EQ(destination_vq.vq_generation, 9);
	ATF_CHECK(destination.vs_restore_incomplete);
	ATF_CHECK((destination.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EIO);
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_SAVE, NULL), EIO);

	/* Model the full-reset recovery boundary before retrying the restore. */
	destination.vs_restore_incomplete = false;
	destination.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET;
	g_snapshot_restore_incomplete = false;

	g_snapshot_restore_failure = false;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(destination_vq.vq_packed_completions !=
	    destination_original);
	ATF_CHECK_EQ(destination_vq.vq_packed_completion_count,
	    nitems(source_desc));
	ATF_CHECK_EQ(destination_vq.vq_qsize, nitems(source_desc));
	ATF_CHECK_EQ(destination_vq.vq_generation, 10);

	/* Repeating the same restore reuses the correctly sized empty cache. */
	destination_original = destination_vq.vq_packed_completions;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(destination_vq.vq_packed_completions ==
	    destination_original);
	ATF_CHECK_EQ(destination_vq.vq_generation, 11);

	vq_packed_completions_fini(&destination_vq);
	vq_packed_completions_fini(&source_vq);
	free(destination_vq.vq_split_owners);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(modern_snapshot_split_restore_retires_packed_cache);
ATF_TC_BODY(modern_snapshot_split_restore_retires_packed_cache, tc)
{
	struct virtio_packed_desc destination_packed_desc[8];
	struct virtio_packed_event destination_driver_event;
	struct virtio_packed_event destination_device_event;
	struct vring_desc destination_desc[8], source_desc[8];
	struct vring_avail *destination_avail, *source_avail;
	struct vring_used *destination_used, *source_used;
	struct virtio_softc destination, source;
	struct virtio_consts destination_vc = { 0 }, source_vc = { 0 };
	struct pci_devinst destination_pi, source_pi;
	struct vqueue_info destination_vq, source_vq;
	uint8_t destination_avail_storage[64], destination_used_storage[128];
	uint8_t source_avail_storage[64], source_used_storage[128];
	uint8_t image[1024];
	void *destination_cache;
	size_t used;

	/* Save a normal modern split-ring queue. */
	source_avail = (struct vring_avail *)source_avail_storage;
	source_used = (struct vring_used *)source_used_storage;
	setup_queue(&source, &source_vc, &source_pi, &source_vq, source_desc,
	    source_avail, source_used);
	source_pi.pi_arg = &source;
	source_pi.pi_msix.table_count = 1;
	source.vs_queues = &source_vq;
	source.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	source.vs_negotiated_caps = VIRTIO_F_VERSION_1;
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source_vc.vc_nvq = 1;
	source_vc.vc_snapshot = test_device_snapshot;
	source_vq.vq_qsize_max = nitems(source_desc);
	source_vq.vq_num = 0;
	source_vq.vq_enabled = 1;
	source_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_vq.vq_desc_gpa = 0x1000;
	source_vq.vq_driver_gpa = 0x2000;
	source_vq.vq_device_gpa = 0x3000;
	add_region(0x1000, source_desc, 8U * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x2000, source_avail_storage, sizeof(source_avail_storage));
	add_region(0x3000, source_used_storage, sizeof(source_used_storage));
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);

	/*
	 * This destination was previously a packed queue.  The common restore
	 * decoder has already selected the source's split feature set before the
	 * queue bank is committed, so the old packed cache is destination-local
	 * state which must be retired, not preserved.
	 */
	setup_packed_queue(&destination, &destination_vc, &destination_pi,
	    &destination_vq, destination_packed_desc, &destination_driver_event,
	    &destination_device_event, nitems(destination_packed_desc));
	destination_pi.pi_arg = &destination;
	destination_pi.pi_msix.table_count = 1;
	destination.vs_queues = &destination_vq;
	destination_vc.vc_nvq = 1;
	destination_vq.vq_qsize_max = nitems(destination_packed_desc);
	destination_vq.vq_num = 0;
	destination_vq.vq_enabled = 1;
	destination_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination.vs_negotiated_caps = VIRTIO_F_VERSION_1;
	destination.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_S_FEATURES_OK;
	destination.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vc.vc_snapshot = test_device_snapshot;
	destination_cache = destination_vq.vq_packed_completions;
	destination_avail = (struct vring_avail *)destination_avail_storage;
	destination_used = (struct vring_used *)destination_used_storage;
	memset(destination_desc, 0, sizeof(destination_desc));
	memset(destination_avail_storage, 0, sizeof(destination_avail_storage));
	memset(destination_used_storage, 0, sizeof(destination_used_storage));
	g_region_count = 0;
	add_region(0x1000, destination_desc, 8U * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x2000, destination_avail_storage,
	    sizeof(destination_avail_storage));
	add_region(0x3000, destination_used_storage,
	    sizeof(destination_used_storage));
	/*
	 * Common state is staged before the device callback.  A private restore
	 * failure must roll that staging back, including the destination-only
	 * packed cache; otherwise the success-path retirement below would hide a
	 * rollback lifetime bug.
	 */
	g_snapshot_restore_failure = true;
	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK_EQ(destination_vq.vq_layout, VIRTIO_QUEUE_PACKED);
	ATF_CHECK(destination_vq.vq_packed_desc == destination_packed_desc);
	ATF_CHECK(destination_vq.vq_packed_completions == destination_cache);
	ATF_CHECK_EQ(destination_vq.vq_packed_completion_count,
	    nitems(destination_packed_desc));
	g_snapshot_restore_failure = false;

	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination_vq.vq_layout, VIRTIO_QUEUE_SPLIT);
	ATF_CHECK_EQ(destination_vq.vq_desc, destination_desc);
	ATF_CHECK_EQ(destination_vq.vq_avail, destination_avail);
	ATF_CHECK_EQ(destination_vq.vq_used, destination_used);
	ATF_CHECK(destination_cache != NULL);
	ATF_CHECK(destination_vq.vq_packed_completions == NULL);
	ATF_CHECK_EQ(destination_vq.vq_packed_completion_count, 0);

	ATF_REQUIRE_EQ(pthread_mutex_destroy(&destination.vs_isr_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vs_isr_mtx), 0);
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{
	pthread_mutex_lock(&g_intr_test_mtx);
	if (g_hold_deassert) {
		g_deassert_entered = true;
		pthread_cond_broadcast(&g_intr_test_cv);
		while (g_hold_deassert)
			pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	}
	g_lintr_asserted = false;
	pthread_mutex_unlock(&g_intr_test_mtx);
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{
	pthread_mutex_lock(&g_intr_test_mtx);
	g_lintr_asserted = true;
	pthread_mutex_unlock(&g_intr_test_mtx);
}

void
pci_generate_msi(struct pci_devinst *pi __unused, int vector __unused)
{
	g_interrupts++;
}

void
pci_generate_msix(struct pci_devinst *pi __unused, int vector __unused)
{
	g_interrupts++;
}

void vi_pci_modern_reset(struct virtio_softc *vs __unused) {}
int pci_emul_alloc_bar(struct pci_devinst *pi __unused, int bar __unused,
    enum pcibar_type type __unused, uint64_t size __unused) { return (0); }
int pci_emul_add_msixcap(struct pci_devinst *pi __unused, int count,
    int bar __unused)
{
	g_msix_cap_count = count;
	return (g_msixcap_error);
}
void pci_emul_add_msicap(struct pci_devinst *pi __unused, int count __unused) {}
void pci_lintr_request(struct pci_devinst *pi __unused) {}
bool vi_pci_is_modern(const struct virtio_softc *vs)
{ return (vs->vs_transport == VIRTIO_PCI_TRANSPORT_MODERN); }
uint64_t vi_pci_modern_read(struct pci_devinst *pi __unused,
    int bar __unused, uint64_t off __unused, int size __unused) { return (0); }
void vi_pci_modern_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
int pci_msix_table_bar(struct pci_devinst *pi __unused) { return (-1); }
int pci_msix_pba_bar(struct pci_devinst *pi __unused) { return (-1); }
uint64_t pci_emul_msix_tread(struct pci_devinst *pi __unused,
    uint64_t off __unused, int size __unused) { return (0); }
int pci_emul_msix_twrite(struct pci_devinst *pi __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused)
{

	return (0);
}
int pci_msix_enabled(struct pci_devinst *pi __unused)
{

	return (g_msix_enabled);
}

static void
add_region(uint64_t gpa, void *host, size_t len)
{
	ATF_REQUIRE(g_region_count < (int)nitems(g_regions));
	g_regions[g_region_count].gpa = gpa;
	g_regions[g_region_count].host = host;
	g_regions[g_region_count].len = len;
	g_region_count++;
}

static void
setup_queue(struct virtio_softc *vs, struct virtio_consts *vc,
    struct pci_devinst *pi, struct vqueue_info *vq, struct vring_desc *desc,
    struct vring_avail *avail, struct vring_used *used)
{
	memset(vs, 0, sizeof(*vs));
	memset(pi, 0, sizeof(*pi));
	memset(vq, 0, sizeof(*vq));
	memset(desc, 0, 8 * sizeof(*desc));
	memset(avail, 0, 64);
	memset(used, 0, 128);
	vc->vc_name = "core-test";
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vi_set_platform_ops(vs, &test_platform_ops, pi->pi_vmctx);
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	ATF_REQUIRE(vi_intr_init(vs, 1, 0) == 0);
	vq->vq_vs = vs;
	vq->vq_qsize = 8;
	vq->vq_flags = VQ_ALLOC;
	vq->vq_desc = desc;
	vq->vq_avail = avail;
	vq->vq_used = used;
	avail->idx = 1;
	avail->ring[0] = 0;
	g_region_count = 0;
	g_interrupts = 0;
	g_msix_enabled = false;
	g_lintr_asserted = false;
	g_hold_deassert = false;
	g_deassert_entered = false;
	g_map_calls = 0;
	g_last_map_address = 0;
	g_last_map_len = 0;
	g_last_map_direction = VIRTIO_DMA_BIDIRECTIONAL;
}

static void
setup_packed_queue(struct virtio_softc *vs, struct virtio_consts *vc,
    struct pci_devinst *pi, struct vqueue_info *vq,
    struct virtio_packed_desc *desc, struct virtio_packed_event *driver_event,
    struct virtio_packed_event *device_event, uint16_t qsize)
{

	memset(vs, 0, sizeof(*vs));
	memset(pi, 0, sizeof(*pi));
	memset(vq, 0, sizeof(*vq));
	memset(desc, 0, qsize * sizeof(*desc));
	memset(driver_event, 0, sizeof(*driver_event));
	memset(device_event, 0, sizeof(*device_event));
	vc->vc_name = "packed-core-test";
	vc->vc_nvq = 1;
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vi_set_platform_ops(vs, &test_platform_ops, pi->pi_vmctx);
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vs->vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_REQUIRE(vi_intr_init(vs, 1, 0) == 0);
	vq->vq_vs = vs;
	vq->vq_qsize = qsize;
	vq->vq_flags = VQ_ALLOC;
	vq->vq_layout = VIRTIO_QUEUE_PACKED;
	vq->vq_packed_desc = desc;
	vq->vq_packed_driver_event = driver_event;
	vq->vq_packed_device_event = device_event;
	vq->vq_packed_avail_wrap = true;
	vq->vq_packed_used_wrap = true;
	vq->vq_packed_save_used_wrap = true;
	ATF_REQUIRE_EQ(vq_packed_completions_init(vq), 0);
	g_region_count = 0;
	g_interrupts = 0;
	g_msix_enabled = false;
	g_lintr_asserted = false;
	g_map_calls = 0;
}

static void
own_test_packed_request(struct vqueue_info *vq, struct vi_req *req)
{

	ATF_REQUIRE(vq_packed_owner_claim(vq, req->packed_head,
	    req->packed_wrap));
	req->queue_layout = VIRTIO_QUEUE_PACKED;
	req->outstanding = true;
}

static void
notify_and_interrupt(void *arg, struct vqueue_info *vq)
{

	g_notifications++;
	vq_interrupt(arg, vq);
}

static void
reset_status(void *arg)
{
	struct virtio_softc *vs = arg;

	g_reset_observed_status = vs->vs_status;
	vs->vs_status = 0;
	if (g_reset_reports_failure)
		vi_set_needs_reset(vs);
}

static int
test_cfgread(void *arg __unused, int offset __unused, int size __unused,
    uint32_t *value)
{

	g_cfg_reads++;
	*value = 0x12345678;
	return (g_cfg_error);
}

static int
test_cfgwrite(void *arg __unused, int offset __unused, int size __unused,
    uint32_t value __unused)
{

	g_cfg_writes++;
	return (g_cfg_error);
}

static int
test_apply_features(void *arg __unused, uint64_t features)
{

	g_apply_features++;
	g_applied_features = features;
	return (g_apply_features_error);
}

ATF_TC_WITHOUT_HEAD(legacy_live_configuration_is_frozen);
ATF_TC_BODY(legacy_live_configuration_is_frozen, tc)
{
	struct virtio_consts vc = {
		.vc_name = "legacy-lifecycle-test",
		.vc_nvq = 1,
		.vc_reset = reset_status,
		.vc_apply_features = test_apply_features,
		.vc_hv_caps = VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_F_RING_RESET,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	g_apply_features = 0;
	g_apply_features_error = 0;
	g_applied_features = 0;

	/*
	 * A 32-bit feature register cannot negotiate the modern bit 40 even
	 * when a direct caller supplies high bits in the uint64_t argument.
	 */
	vi_pci_write(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4,
	    VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_F_RING_RESET);
	ATF_CHECK(vs.vs_negotiated_caps == VIRTIO_F_NOTIFY_ON_EMPTY);
	/*
	 * A legacy feature-register write records the selection but cannot
	 * yet change device-specific state.  VirtIO 1.4 section 5.2.5.3
	 * makes this observable for block cache mode: applying the selection
	 * before DRIVER_OK would violate its legacy initialization rule.
	 */
	ATF_CHECK(g_apply_features == 0);
	ATF_CHECK(g_applied_features == 0);

	vq.vq_pfn = 0x1234;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(g_apply_features == 1);
	ATF_CHECK(g_applied_features == VIRTIO_F_NOTIFY_ON_EMPTY);
	vi_pci_write(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4, 0);
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_PFN, 4, 0x5678);
	ATF_CHECK(vs.vs_negotiated_caps == VIRTIO_F_NOTIFY_ON_EMPTY);
	ATF_CHECK(g_apply_features == 1);
	ATF_CHECK(vq.vq_pfn == 0x1234);

	/* Nonzero status writes cannot clear an accepted status bit. */
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	ATF_CHECK((vs.vs_status & (VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK)) ==
	    (VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER_OK));

	/*
	 * Legacy has no FEATURES_OK handshake.  If the backend cannot apply
	 * the selected feature set at DRIVER_OK, keep the device stopped and
	 * require a reset.
	 */
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1, 0);
	vi_pci_write(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4,
	    VIRTIO_F_NOTIFY_ON_EMPTY);
	g_apply_features_error = EIO;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	g_apply_features_error = 0;
}

ATF_TC_WITHOUT_HEAD(legacy_quiesce_fences_transport_access);
ATF_TC_BODY(legacy_quiesce_fences_transport_access, tc)
{
	struct virtio_consts vc = {
		.vc_name = "legacy-quiesce-test",
		.vc_nvq = 1,
		.vc_cfgsize = 4,
		.vc_cfgread = test_cfgread,
		.vc_cfgwrite = test_cfgwrite,
		.vc_reset = reset_status,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	uint64_t config;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vs.vs_status = VIRTIO14_STATUS_ACKNOWLEDGE |
	    VIRTIO14_STATUS_DRIVER;
	config = VIRTIO_PCI_CONFIG_OFF(false);
	g_cfg_reads = 0;
	g_cfg_writes = 0;

	vi_pci_quiesce_enter(&vs);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_STATUS, 1),
	    vs.vs_status);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, config, 4), UINT32_MAX);
	ATF_CHECK_EQ(g_cfg_reads, 0);
	vi_pci_write(&pi, 0, config, 4, UINT32_C(0xaabbccdd));
	ATF_CHECK_EQ(g_cfg_writes, 0);
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1, 0);
	ATF_CHECK_EQ(vs.vs_status,
	    VIRTIO14_STATUS_ACKNOWLEDGE | VIRTIO14_STATUS_DRIVER);

	vi_pci_quiesce_exit(&vs);
	(void)vi_pci_read(&pi, 0, config, 4);
	ATF_CHECK_EQ(g_cfg_reads, 1);
	vi_pci_write(&pi, 0, config, 4, UINT32_C(0xaabbccdd));
	ATF_CHECK_EQ(g_cfg_writes, 1);
}

ATF_TC_WITHOUT_HEAD(legacy_config_offset_overflow);
ATF_TC_BODY(legacy_config_offset_overflow, tc)
{
	struct virtio_consts vc = {
		.vc_name = "config-range-test",
		.vc_nvq = 1,
		.vc_cfgsize = 4,
		.vc_cfgread = test_cfgread,
		.vc_cfgwrite = test_cfgwrite,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	uint64_t config;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	g_msix_enabled = false;
	config = VIRTIO_PCI_CONFIG_OFF(0);
	g_cfg_reads = 0;
	g_cfg_writes = 0;
	g_cfg_error = 0;

	ATF_CHECK(vi_pci_read(&pi, 0, config, 4) == 0x12345678);
	ATF_CHECK(vi_pci_read(&pi, 0, config, 2) == 0x5678);
	ATF_CHECK(vi_pci_read(&pi, 0, config, 1) == 0x78);
	vi_pci_write(&pi, 0, config, 4, 0xa5a5a5a5);
	ATF_CHECK(g_cfg_reads == 3);
	ATF_CHECK(g_cfg_writes == 1);

	ATF_CHECK(vi_pci_read(&pi, 0, UINT64_MAX, 1) == UINT8_MAX);
	ATF_CHECK(vi_pci_read(&pi, 0, UINT64_MAX - 1, 4) == UINT32_MAX);
	vi_pci_write(&pi, 0, UINT64_MAX, 1, 0xff);
	ATF_CHECK(g_cfg_reads == 3);
	ATF_CHECK(g_cfg_writes == 1);
}

ATF_TC_WITHOUT_HEAD(legacy_zero_length_device_config);
ATF_TC_BODY(legacy_zero_length_device_config, tc)
{
	struct virtio_consts vc = {
		.vc_name = "empty-config-test",
		.vc_nvq = 1,
		.vc_cfgsize = 0,
		.vc_cfgread = test_cfgread,
		.vc_cfgwrite = test_cfgwrite,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	uint64_t config;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	g_msix_enabled = false;
	config = VIRTIO_PCI_CONFIG_OFF(0);
	g_cfg_reads = 0;
	g_cfg_writes = 0;
	g_cfg_error = 0;

	ATF_CHECK(vi_pci_read(&pi, 0, config, 1) == UINT8_MAX);
	vi_pci_write(&pi, 0, config, 1, 0xa5);
	ATF_CHECK(g_cfg_reads == 0);
	ATF_CHECK(g_cfg_writes == 0);
}

ATF_TC_WITHOUT_HEAD(legacy_rejected_config_is_not_msix);
ATF_TC_BODY(legacy_rejected_config_is_not_msix, tc)
{
	struct virtio_consts vc = {
		.vc_name = "config-reject-test",
		.vc_nvq = 1,
		.vc_cfgsize = 4,
		.vc_cfgread = test_cfgread,
		.vc_cfgwrite = test_cfgwrite,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	uint64_t config;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vs.vs_msix_cfg_idx = 1;
	vq.vq_msix_idx = 1;
	g_msix_enabled = false;
	g_cfg_reads = 0;
	g_cfg_writes = 0;
	g_cfg_error = EINVAL;
	config = VIRTIO14_LEGACY_DEVICE_CFG_OFF;

	ATF_CHECK(vi_pci_read(&pi, 0, config, 2) == UINT16_MAX);
	ATF_CHECK(vi_pci_read(&pi, 0, config + 2, 2) == UINT16_MAX);
	vi_pci_write(&pi, 0, config, 2, 0);
	vi_pci_write(&pi, 0, config + 2, 2, 0);
	ATF_CHECK(vs.vs_msix_cfg_idx == 1);
	ATF_CHECK(vq.vq_msix_idx == 1);
	ATF_CHECK(g_cfg_reads == 2);
	ATF_CHECK(g_cfg_writes == 2);
	g_cfg_error = 0;
}

ATF_TC_WITHOUT_HEAD(legacy_msix_vector_validation);
ATF_TC_BODY(legacy_msix_vector_validation, tc)
{
	struct virtio_consts vc = {
		.vc_name = "legacy-msix-test",
		.vc_nvq = 1,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	pi.pi_msix.table_count = 2;
	g_msix_enabled = true;

	vi_pci_write(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2, 7);
	ATF_CHECK(vs.vs_msix_cfg_idx == VIRTIO_MSI_NO_VECTOR);
	vi_pci_write(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2, 1);
	ATF_CHECK(vs.vs_msix_cfg_idx == 1);

	vi_pci_write(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2, 7);
	ATF_CHECK(vq.vq_msix_idx == VIRTIO_MSI_NO_VECTOR);
	vi_pci_write(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2, 0);
	ATF_CHECK(vq.vq_msix_idx == 0);
	g_msix_enabled = false;
}

ATF_TC_WITHOUT_HEAD(legacy_status_preserves_needs_reset);
ATF_TC_BODY(legacy_status_preserves_needs_reset, tc)
{
	struct virtio_consts vc = {
		.vc_name = "status-test",
		.vc_nvq = 1,
		.vc_reset = reset_status,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_set_needs_reset(&vs);
	ATF_REQUIRE((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	g_reset_observed_status = 0;
	g_reset_reports_failure = true;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1, 0);
	ATF_CHECK((g_reset_observed_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vs.vs_status == 0);
	ATF_CHECK(vs.vs_reset_failed);
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_ACK);
	ATF_CHECK((vs.vs_status & (VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_S_NEEDS_RESET)) ==
	    (VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_S_NEEDS_RESET));
	g_reset_reports_failure = false;
}

ATF_TC_WITHOUT_HEAD(legacy_non_io_bar_is_ignored);
ATF_TC_BODY(legacy_non_io_bar_is_ignored, tc)
{
	struct virtio_consts vc = {
		.vc_name = "bar-test",
		.vc_nvq = 1,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	ATF_CHECK(vi_pci_read(&pi, 1, VIRTIO_PCI_STATUS, 1) == UINT8_MAX);
	ATF_CHECK(vi_pci_read(&pi, 1, VIRTIO_PCI_STATUS, 2) == UINT16_MAX);
	ATF_CHECK(vi_pci_read(&pi, 1, VIRTIO_PCI_STATUS, 4) == UINT32_MAX);
	ATF_CHECK(vi_pci_read(&pi, 1, VIRTIO_PCI_STATUS, 8) == UINT64_MAX);
	vi_pci_write(&pi, 1, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK(vs.vs_status == 0);
}

ATF_TC_WITHOUT_HEAD(notify_without_msix_does_not_relock_device);
ATF_TC_BODY(notify_without_msix_does_not_relock_device, tc)
{
	struct virtio_consts vc = {
		.vc_name = "notify-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	pthread_mutex_t device_mtx;
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		alarm(2);
		g_notifications = 0;
		memset(&vs, 0, sizeof(vs));
		memset(&pi, 0, sizeof(pi));
		memset(&vq, 0, sizeof(vq));
		if (pthread_mutex_init(&device_mtx, NULL) != 0)
			_exit(2);
		vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
		vs.vs_mtx = &device_mtx;
		g_msix_enabled = false;
		vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
		if (vi_intr_init(&vs, 1, 0) != 0)
			_exit(3);
		vq.vq_flags = VQ_ALLOC;
		if (vq_ring_ready(&vq))
			_exit(4);
		vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_NOTIFY, 2, 0);
		if (vs.vs_isr != 0 || g_notifications != 0 ||
		    !vq.vq_notify_pending)
			_exit(5);
		vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
		    VIRTIO_CONFIG_STATUS_DRIVER_OK);
		_exit(vq_ring_ready(&vq) && vs.vs_isr == VIRTIO_PCI_ISR_INTR &&
		    g_notifications == 1 && !vq.vq_notify_pending ? 0 : 6);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status));
	if (WIFEXITED(status))
		ATF_CHECK(WEXITSTATUS(status) == 0);
}

ATF_TC_WITHOUT_HEAD(lifecycle_fence_replays_queue_notify);
ATF_TC_BODY(lifecycle_fence_replays_queue_notify, tc)
{
	struct virtio_consts vc = {
		.vc_name = "lifecycle-notify-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	g_notifications = 0;

	vi_pci_quiesce_enter(&vs);
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK_EQ(g_notifications, 0);
	ATF_CHECK(vq.vq_notify_pending);
	vi_pci_notify_ready_queues(&vs);
	ATF_CHECK_EQ(g_notifications, 0);
	ATF_CHECK(vq.vq_notify_pending);
	vi_pci_quiesce_exit(&vs);
	vi_pci_notify_ready_queues(&vs);
	ATF_CHECK_EQ(g_notifications, 1);
	ATF_CHECK(!vq.vq_notify_pending);

	vs.vs_suspended = true;
	vs.vs_status &= ~VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK_EQ(g_notifications, 1);
	ATF_CHECK(vq.vq_notify_pending);
	vs.vs_status |= VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_notify_ready_queues(&vs);
	ATF_CHECK_EQ(g_notifications, 1);
	ATF_CHECK(vq.vq_notify_pending);
	vs.vs_suspended = false;
	vi_pci_notify_ready_queues(&vs);
	ATF_CHECK_EQ(g_notifications, 2);
	ATF_CHECK(!vq.vq_notify_pending);

	vs.vs_checkpoint_paused = true;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK_EQ(g_notifications, 2);
	ATF_CHECK(vq.vq_notify_pending);
	vs.vs_checkpoint_paused = false;
	vi_pci_notify_ready_queues(&vs);
	ATF_CHECK_EQ(g_notifications, 3);
	ATF_CHECK(!vq.vq_notify_pending);

	vs.vs_suspended = true;
	vi_pci_notify_queue(&vs, 0);
	ATF_REQUIRE(vq.vq_notify_pending);
	vi_reset_dev(&vs);
	ATF_CHECK(!vq.vq_notify_pending);
}

ATF_TC_WITHOUT_HEAD(failed_checkpoint_pause_replays_queue_notify);
ATF_TC_BODY(failed_checkpoint_pause_replays_queue_notify, tc)
{
	struct virtio_consts vc = {
		.vc_name = "failed-pause-notify-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
		.vc_pause = pause_with_racing_notify_and_config,
		.vc_resume = resume_success,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	g_notifications = 0;
	g_config_changes = 0;

	ATF_CHECK_EQ(vi_pci_pause(&pi), EIO);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	ATF_CHECK_EQ(g_notifications, 1);
	ATF_CHECK(!vq.vq_notify_pending);
	ATF_CHECK(!vs.vs_config_deferred);
	ATF_CHECK_EQ(g_config_changes, 1);
}

ATF_TC_WITHOUT_HEAD(missing_checkpoint_callbacks_fail_closed);
ATF_TC_BODY(missing_checkpoint_callbacks_fail_closed, tc)
{
	struct virtio_consts vc = {
		.vc_name = "missing-checkpoint-callback-test",
		.vc_nvq = 1,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);

	ATF_CHECK_EQ(vi_pci_pause(&pi), EOPNOTSUPP);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	/* A checkpoint lifecycle callback is an inseparable pause/resume pair. */
	vc.vc_pause = pause_success;
	ATF_CHECK_EQ(vi_pci_pause(&pi), EOPNOTSUPP);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	vc.vc_pause = NULL;
	vc.vc_resume = resume_success;
	ATF_CHECK_EQ(vi_pci_pause(&pi), EOPNOTSUPP);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	vc.vc_resume = NULL;
	/* Repeated pause cleanup is a no-op after ownership is already held. */
	vs.vs_checkpoint_paused = true;
	ATF_CHECK_EQ(vi_pci_pause(&pi), 0);
	ATF_CHECK(vs.vs_checkpoint_paused);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	vs.vs_checkpoint_paused = false;
	/* Cleanup may resume every PCI device after another pause failed. */
	ATF_CHECK_EQ(vi_pci_resume(&pi), 0);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	/* A device which did acquire pause ownership still fails closed. */
	vs.vs_checkpoint_paused = true;
	ATF_CHECK_EQ(vi_pci_resume(&pi), EOPNOTSUPP);
	ATF_CHECK(vs.vs_checkpoint_paused);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
}

/*
 * A failed backend resume must retain checkpoint ownership.  In particular,
 * the common lifecycle fence cannot replay a queued guest kick until a later
 * successful resume has reopened the same administration-controller fence.
 */
ATF_TC_WITHOUT_HEAD(failed_checkpoint_resume_stays_fenced_until_retry);
ATF_TC_BODY(failed_checkpoint_resume_stays_fenced_until_retry, tc)
{
	struct virtio_consts vc = {
		.vc_name = "failed-resume-fence-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
		.vc_pause = pause_success,
		.vc_resume = resume_with_injected_error,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs.vs_negotiated_caps = VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	g_admin_quiesce_calls = 0;
	g_admin_quiesce_error = 0;
	g_admin_unquiesce_calls = 0;
	g_notifications = 0;
	g_resume_error = EIO;

	ATF_REQUIRE_EQ(vi_pci_pause(&pi), 0);
	ATF_CHECK_EQ(g_admin_quiesce_calls, 1);
	ATF_CHECK(vs.vs_checkpoint_paused);
	vi_pci_notify_queue(&vs, 0);
	ATF_REQUIRE(vq.vq_notify_pending);

	ATF_CHECK_EQ(vi_pci_resume(&pi), EIO);
	ATF_CHECK_EQ(g_admin_unquiesce_calls, 1);
	ATF_CHECK(vs.vs_checkpoint_paused);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK_EQ(g_notifications, 0);
	ATF_CHECK(vq.vq_notify_pending);

	g_resume_error = 0;
	ATF_REQUIRE_EQ(vi_pci_resume(&pi), 0);
	ATF_CHECK_EQ(g_admin_unquiesce_calls, 2);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	ATF_CHECK_EQ(g_notifications, 1);
	ATF_CHECK(!vq.vq_notify_pending);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

/*
 * The common checkpoint resume owner must not discard a deferred device
 * configuration notification on a failed backend resume, and it must replay
 * the latch exactly once after the fence has opened.  The modern transport
 * unit test separately proves the resulting interrupt delivery; this test
 * exercises the snapshot-enabled common lifecycle path that owns the latch.
 */
ATF_TC_WITHOUT_HEAD(checkpoint_resume_replays_deferred_config_once);
ATF_TC_BODY(checkpoint_resume_replays_deferred_config_once, tc)
{
	struct virtio_consts vc = {
		.vc_name = "deferred-config-resume-test",
		.vc_nvq = 1,
		.vc_pause = pause_success,
		.vc_resume = resume_with_injected_error,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_checkpoint_paused = true;
	vs.vs_config_deferred = true;
	g_config_changes = 0;
	g_resume_error = EIO;

	ATF_CHECK_EQ(vi_pci_resume(&pi), EIO);
	ATF_CHECK(vs.vs_checkpoint_paused);
	ATF_CHECK(vs.vs_config_deferred);
	ATF_CHECK_EQ(g_config_changes, 0);

	g_resume_error = 0;
	ATF_REQUIRE_EQ(vi_pci_resume(&pi), 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	ATF_CHECK(!vs.vs_config_deferred);
	ATF_CHECK_EQ(g_config_changes, 1);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

/*
 * Checkpoint and guest suspend are independent lifecycle owners.  The common
 * checkpoint resume path must release only its own backend fence: a suspended
 * guest cannot have host queue sources restarted through resume_complete().
 * The modern transport test covers the paired configuration-generation latch;
 * this test invokes the production common checkpoint function directly.
 */
ATF_TC_WITHOUT_HEAD(checkpoint_resume_preserves_guest_suspend_fence);
ATF_TC_BODY(checkpoint_resume_preserves_guest_suspend_fence, tc)
{
	struct virtio_consts vc = {
		.vc_name = "checkpoint-inside-suspend-test",
		.vc_nvq = 1,
		.vc_pause = pause_success,
		.vc_resume = resume_with_injected_error,
		.vc_resume_complete = resume_complete_count,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_checkpoint_paused = true;
	vs.vs_suspended = true;
	vs.vs_config_deferred = true;
	g_config_changes = 0;
	g_resume_complete_count = 0;
	g_notifications = 0;
	g_resume_error = 0;

	ATF_REQUIRE_EQ(vi_pci_resume(&pi), 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	ATF_CHECK(vs.vs_suspended);
	ATF_CHECK_EQ(g_resume_complete_count, 0);
	ATF_CHECK_EQ(g_notifications, 0);
	/* The common layer hands the retained event back to the transport. */
	ATF_CHECK_EQ(g_config_changes, 1);
	ATF_CHECK(!vs.vs_config_deferred);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(admin_quiesce_failure_aborts_checkpoint);
ATF_TC_BODY(admin_quiesce_failure_aborts_checkpoint, tc)
{
	struct virtio_consts vc = {
		.vc_name = "admin-pause-test",
		.vc_nvq = 1,
		.vc_pause = pause_must_not_run,
		.vc_resume = resume_success,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs.vs_negotiated_caps = VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	g_admin_quiesce_calls = 0;
	g_admin_quiesce_error = EBUSY;
	g_admin_unquiesce_calls = 0;

	ATF_CHECK_EQ(vi_pci_pause(&pi), EBUSY);
	ATF_CHECK_EQ(g_admin_quiesce_calls, 1);
	ATF_CHECK_EQ(g_admin_unquiesce_calls, 0);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	g_admin_quiesce_error = 0;
}

ATF_TC_WITHOUT_HEAD(admin_pause_rollback_failure_needs_reset);
ATF_TC_BODY(admin_pause_rollback_failure_needs_reset, tc)
{
	struct virtio_consts vc = {
		.vc_name = "admin-pause-rollback-test",
		.vc_nvq = 1,
		.vc_pause = pause_with_racing_notify,
		.vc_resume = resume_success,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vs.vs_negotiated_caps = VIRTIO14_F_ADMIN_VQ;
	vs.vs_admin_binding = (void *)(uintptr_t)1;
	g_admin_quiesce_calls = 0;
	g_admin_quiesce_error = 0;
	g_admin_unquiesce_calls = 0;
	g_admin_unquiesce_error = EINVAL;
	g_notifications = 0;

	ATF_CHECK_EQ(vi_pci_pause(&pi), EIO);
	ATF_CHECK_EQ(g_admin_quiesce_calls, 1);
	ATF_CHECK_EQ(g_admin_unquiesce_calls, 1);
	ATF_CHECK_EQ(vs.vs_quiescing, 0);
	ATF_CHECK(!vs.vs_checkpoint_paused);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	/* NEEDS_RESET keeps the raced queue kick fenced until full reset. */
	ATF_CHECK_EQ(g_notifications, 0);
	ATF_CHECK(vq.vq_notify_pending);

	g_admin_unquiesce_error = 0;
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

struct interrupt_race_ctx {
	struct virtio_softc *vs;
	bool producer_started;
	bool producer_done;
};

static void *
read_isr_thread(void *arg)
{
	struct virtio_softc *vs = arg;

	(void)vi_isr_read(vs);
	return (NULL);
}

static void *
raise_interrupt_thread(void *arg)
{
	struct interrupt_race_ctx *ctx = arg;

	pthread_mutex_lock(&g_intr_test_mtx);
	ctx->producer_started = true;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);
	vi_interrupt(ctx->vs, VIRTIO_PCI_ISR_INTR, VIRTIO_MSI_NO_VECTOR);
	pthread_mutex_lock(&g_intr_test_mtx);
	ctx->producer_done = true;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(isr_read_serializes_intx);
ATF_TC_BODY(isr_read_serializes_intx, tc)
{
	struct interrupt_race_ctx ctx;
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct timespec deadline;
	pthread_t producer, reader;
	bool completed_while_deasserting;
	int error;

	memset(&ctx, 0, sizeof(ctx));
	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	vs.vs_pi = &pi;
	g_msix_enabled = false;
	ATF_REQUIRE(pthread_mutex_init(&vs.vs_isr_mtx, NULL) == 0);
	ctx.vs = &vs;
	vs.vs_isr = VIRTIO_PCI_ISR_INTR;
	pthread_mutex_lock(&g_intr_test_mtx);
	g_lintr_asserted = true;
	g_hold_deassert = true;
	g_deassert_entered = false;
	pthread_mutex_unlock(&g_intr_test_mtx);

	ATF_REQUIRE(pthread_create(&reader, NULL, read_isr_thread, &vs) == 0);
	pthread_mutex_lock(&g_intr_test_mtx);
	while (!g_deassert_entered)
		pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	pthread_mutex_unlock(&g_intr_test_mtx);
	ATF_REQUIRE(pthread_create(&producer, NULL, raise_interrupt_thread,
	    &ctx) == 0);

	pthread_mutex_lock(&g_intr_test_mtx);
	while (!ctx.producer_started)
		pthread_cond_wait(&g_intr_test_cv, &g_intr_test_mtx);
	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_nsec += 100000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	error = 0;
	while (!ctx.producer_done && error == 0)
		error = pthread_cond_timedwait(&g_intr_test_cv,
		    &g_intr_test_mtx, &deadline);
	completed_while_deasserting = ctx.producer_done;
	g_hold_deassert = false;
	pthread_cond_broadcast(&g_intr_test_cv);
	pthread_mutex_unlock(&g_intr_test_mtx);

	ATF_REQUIRE(pthread_join(reader, NULL) == 0);
	ATF_REQUIRE(pthread_join(producer, NULL) == 0);
	ATF_CHECK(!completed_while_deasserting);
	ATF_CHECK(error == ETIMEDOUT);
	ATF_CHECK(vs.vs_isr == VIRTIO_PCI_ISR_INTR);
	ATF_CHECK(g_lintr_asserted);
}

ATF_TC_WITHOUT_HEAD(direct_mapping_validation);
ATF_TC_BODY(direct_mapping_validation, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[16];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	desc[0].addr = 0x1000;
	desc[0].len = sizeof(payload);
	desc[0].flags = VRING_DESC_F_WRITE;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 1);
	ATF_CHECK(iov.iov_base == payload);
	ATF_CHECK(req.readable == 0 && req.writable == 1);
	/* Independent expected capacity encoded in desc[0] above. */
	ATF_CHECK_EQ(UINT64_C(16), req.writable_bytes);
	ATF_CHECK(req.lengths_known);
	ATF_CHECK_EQ(req.descriptor_count, 1);
	ATF_CHECK_EQ(req.completion_id, req.idx);
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(g_last_map_address, UINT64_C(0x1000));
	ATF_CHECK_EQ(g_last_map_len, sizeof(payload));
	ATF_CHECK_EQ(g_last_map_direction, VIRTIO_DMA_DEVICE_WRITE);
	vq_discard_req(&vq, &req);

	vq.vq_last_avail = 0;
	desc[0].flags = 0;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 1);
	ATF_CHECK_EQ(g_last_map_direction, VIRTIO_DMA_DEVICE_READ);
	vq_discard_req(&vq, &req);

	vq.vq_last_avail = 0;
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	desc[0].flags = VRING_DESC_F_WRITE;
	desc[0].addr = 0xdead0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vi_isr_read(&vs) == VIRTIO_PCI_ISR_CONFIG);
	ATF_CHECK(!g_lintr_asserted);

	vq.vq_last_avail = 0;
	desc[0].addr = 0x1000;
	desc[0].len = 4;
	desc[0].flags = VRING_DESC_F_NEXT;
	desc[0].next = 1;
	desc[1].addr = 0xdead0000;
	desc[1].len = 4;
	desc[1].flags = VRING_DESC_F_WRITE;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);
	ATF_CHECK(vi_isr_read(&vs) == 0);

	vq.vq_last_avail = 0;
	desc[1].addr = 0x1004;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 2);
	ATF_CHECK(req.readable == 1 && req.writable == 1);
	ATF_CHECK(req.ordered);
	vq_discard_req(&vq, &req);

	vq.vq_last_avail = 0;
	desc[0].flags = VRING_DESC_F_WRITE | VRING_DESC_F_NEXT;
	desc[1].flags = 0;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 2);
	ATF_CHECK(req.readable == 1 && req.writable == 1);
	ATF_CHECK(!req.ordered);
	vq_discard_req(&vq, &req);
}

ATF_TC_WITHOUT_HEAD(used_length_bounded_by_writable_capacity);
ATF_TC_BODY(used_length_bounded_by_writable_capacity, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_packed_desc packed_desc[2];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req, reqs[2];
	struct iovec iov, iovs[2];
	uint32_t lengths[2];
	uint8_t payload[16];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	desc[0].addr = 0x1000;
	desc[0].len = sizeof(payload);
	desc[0].flags = VRING_DESC_F_WRITE;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_REQUIRE_EQ(req.writable_bytes, sizeof(payload));
	vq_relchain_req(&vq, &req, sizeof(payload) + 1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(vq.vq_used->idx, 0);

	/*
	 * Grouped packed completion validates every independently parsed member
	 * before staging any used descriptor.  One oversized member therefore
	 * cannot make an otherwise valid prefix visible to the driver.
	 */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	add_region(0x2000, payload, sizeof(payload));
	for (size_t i = 0; i < nitems(packed_desc); i++) {
		packed_desc[i].address = htole64(0x2000 + i * 8);
		packed_desc[i].length = htole32(8);
		packed_desc[i].id = htole16((uint16_t)(20 + i));
		packed_desc[i].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
		    VIRTIO14_PACKED_DESC_F_WRITE);
		ATF_REQUIRE_EQ(vq_getchain(&vq, &iovs[i], 1, &reqs[i]), 1);
		ATF_REQUIRE(reqs[i].lengths_known);
		ATF_REQUIRE_EQ(reqs[i].writable_bytes, UINT64_C(8));
	}
	lengths[0] = 8;
	lengths[1] = 9;
	vq_relchain_group(&vq, reqs, lengths, nitems(reqs));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 0);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	for (size_t i = 0; i < nitems(packed_desc); i++) {
		ATF_CHECK_EQ(le16toh(packed_desc[i].flags),
		    VIRTIO14_PACKED_DESC_F_AVAIL |
		    VIRTIO14_PACKED_DESC_F_WRITE);
	}
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(indirect_mapping_validation);
ATF_TC_BODY(indirect_mapping_validation, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8], indirect[1];
	uint8_t oversized_indirect[9 * VIRTIO14_SPLIT_DESC_SIZE];
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[8];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX;
	/*
	 * VirtIO 1.4 §2.7.5.3.2 requires a device to handle zero or more
	 * normal chained descriptors followed by one indirect descriptor.  This
	 * is distinct from both an indirect-only chain and the invalid form that
	 * sets NEXT on the indirect descriptor itself.
	 */
	{
		uint8_t prefix[4], suffix[4];

		add_region(0x0800, prefix, sizeof(prefix));
		add_region(0x1800, suffix, sizeof(suffix));
		add_region(0x2800, indirect, VIRTIO14_SPLIT_DESC_SIZE);
		memset(desc, 0, sizeof(desc));
		memset(indirect, 0, sizeof(indirect));
		indirect[0].addr = 0x1800;
		indirect[0].len = sizeof(suffix);
		indirect[0].flags = VRING_DESC_F_WRITE;
		desc[0].addr = 0x0800;
		desc[0].len = sizeof(prefix);
		desc[0].flags = VRING_DESC_F_NEXT;
		desc[0].next = 1;
		desc[1].addr = 0x2800;
		desc[1].len = VIRTIO14_SPLIT_DESC_SIZE;
		desc[1].flags = VRING_DESC_F_INDIRECT;
		ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 2);
		ATF_CHECK_EQ(req.readable, 1);
		ATF_CHECK_EQ(req.writable, 1);
		ATF_CHECK(iov.iov_base == prefix);
		vq_discard_req(&vq, &req);
	}

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_F_VERSION_1 |
	    VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX;
	/*
	 * Linux's synchronous control command polls the used ring, but the
	 * device must still perform the normal EVENT_IDX interrupt decision.
	 * Put used_event at the documented trailing position and request the
	 * first completion.
	 */
	((struct vring_avail *)avail_mem.bytes)->ring[vq.vq_qsize] = 0;
	add_region(0x1000, payload, sizeof(payload));
	add_region(0x2000, indirect, VIRTIO14_SPLIT_DESC_SIZE);
	memset(indirect, 0, sizeof(indirect));
	indirect[0].addr = 0x1000;
	indirect[0].len = sizeof(payload);
	indirect[0].flags = VRING_DESC_F_WRITE;
	desc[0].addr = 0x2000;
	desc[0].len = VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 1);
	ATF_CHECK(iov.iov_base == payload && req.writable == 1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0xdead0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	vq.vq_last_avail = 0;
	desc[0].addr = 0x2000;
	indirect[0].addr = 0xbeef0000;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	vq.vq_last_avail = 0;
	indirect[0].addr = 0x1000;
	desc[0].flags = VRING_DESC_F_INDIRECT | VRING_DESC_F_NEXT;
	desc[0].next = 1;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == -1);

	/*
	 * An indirect table cannot contain more descriptors than the queue.
	 * Reject it before translating the guest-controlled table length.
	 */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(oversized_indirect, 0,
	    9 * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x3000, oversized_indirect,
	    9 * VIRTIO14_SPLIT_DESC_SIZE);
	desc[0].addr = 0x3000;
	desc[0].len = 9 * VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK_EQ(vq_getchain(&vq, &iov, 1, &req), -1);
	ATF_CHECK_EQ(g_map_calls, 0);
}

ATF_TC_WITHOUT_HEAD(zero_length_descriptor_mapping);
ATF_TC_BODY(zero_length_descriptor_mapping, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_packed_desc packed_desc[2], packed_indirect[1];
	struct virtio_packed_event driver_event, device_event;
	struct vring_desc desc[8], indirect[1];
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req req;
	struct iovec iov;

	/*
	 * Section 2.7.5 does not reserve a zero descriptor length.  No guest
	 * bytes are named, so the address is deliberately outside every test
	 * region and the platform mapper must not be called.
	 */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	desc[0].addr = UINT64_MAX;
	desc[0].len = 0;
	desc[0].flags = VRING_DESC_F_WRITE;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(iov.iov_base != NULL);
	ATF_CHECK_EQ(iov.iov_len, 0);
	ATF_CHECK_EQ(req.writable, 1);
	ATF_CHECK_EQ(g_map_calls, 0);
	ATF_CHECK_EQ(vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET, 0);

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	add_region(0x2000, indirect, VIRTIO14_SPLIT_DESC_SIZE);
	memset(indirect, 0, sizeof(indirect));
	indirect[0].addr = UINT64_MAX;
	indirect[0].flags = VRING_DESC_F_WRITE;
	desc[0].addr = 0x2000;
	desc[0].len = VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(iov.iov_base != NULL);
	ATF_CHECK_EQ(iov.iov_len, 0);
	ATF_CHECK_EQ(req.writable, 1);
	/* Only the nonempty indirect table itself needs translation. */
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET, 0);

	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	packed_desc[0].address = htole64(UINT64_MAX);
	packed_desc[0].length = htole32(0);
	packed_desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_WRITE);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(iov.iov_base != NULL);
	ATF_CHECK_EQ(iov.iov_len, 0);
	ATF_CHECK_EQ(req.writable, 1);
	ATF_CHECK_EQ(g_map_calls, 0);
	ATF_CHECK_EQ(vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET, 0);
	vq_packed_completions_fini(&vq);

	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	add_region(0x3000, packed_indirect, sizeof(packed_indirect));
	memset(packed_indirect, 0, sizeof(packed_indirect));
	packed_indirect[0].address = htole64(UINT64_MAX);
	packed_indirect[0].flags =
	    htole16(VIRTIO14_PACKED_DESC_F_WRITE);
	packed_desc[0].address = htole64(0x3000);
	packed_desc[0].length = htole32(sizeof(packed_indirect));
	packed_desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	ATF_CHECK(iov.iov_base != NULL);
	ATF_CHECK_EQ(iov.iov_len, 0);
	ATF_CHECK_EQ(req.writable, 1);
	ATF_CHECK_EQ(g_map_calls, 1);
	ATF_CHECK_EQ(vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET, 0);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(linux_control_indirect_chain);
ATF_TC_BODY(linux_control_indirect_chain, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8], indirect[4];
	struct vring_used *used;
	struct vi_req req;
	struct iovec iov[4];
	uint8_t control_header[2] = { 4, 1 };
	uint8_t rss_header[264] = { 0 };
	uint8_t rss_trailer[44] = { 0 };
	uint8_t ack = UINT8_MAX;

	/*
	 * Linux virtio-net submits its RSS control request as one indirect
	 * chain: control header, variable RSS header, aligned trailer, and a
	 * device-writable status byte.  Exercise that exact split-ring shape
	 * through the real parser and used-ring publication code.
	 */
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes, used);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	add_region(0x1000, control_header, sizeof(control_header));
	add_region(0x2000, rss_header, sizeof(rss_header));
	add_region(0x3000, rss_trailer, sizeof(rss_trailer));
	add_region(0x4000, &ack, sizeof(ack));
	add_region(0x5000, indirect,
	    4U * VIRTIO14_SPLIT_DESC_SIZE);

	memset(indirect, 0, sizeof(indirect));
	indirect[0].addr = 0x1000;
	indirect[0].len = sizeof(control_header);
	indirect[0].flags = VRING_DESC_F_NEXT;
	indirect[0].next = 1;
	indirect[1].addr = 0x2000;
	indirect[1].len = sizeof(rss_header);
	indirect[1].flags = VRING_DESC_F_NEXT;
	indirect[1].next = 2;
	indirect[2].addr = 0x3000;
	indirect[2].len = sizeof(rss_trailer);
	indirect[2].flags = VRING_DESC_F_NEXT;
	indirect[2].next = 3;
	indirect[3].addr = 0x4000;
	indirect[3].len = sizeof(ack);
	indirect[3].flags = VRING_DESC_F_WRITE;
	desc[0].addr = 0x5000;
	desc[0].len = 4U * VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;

	ATF_REQUIRE_EQ(vq_getchain(&vq, iov, nitems(iov), &req), 4);
	ATF_CHECK(req.ordered);
	ATF_CHECK_EQ(req.readable, 3);
	ATF_CHECK_EQ(req.writable, 1);
	ATF_CHECK(iov[0].iov_base == control_header);
	ATF_CHECK(iov[1].iov_base == rss_header);
	ATF_CHECK(iov[2].iov_base == rss_trailer);
	ATF_CHECK(iov[3].iov_base == &ack);
	ATF_CHECK_EQ(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len,
	    310);

	*(uint8_t *)iov[3].iov_base = 0;
	vq_relchain(&vq, req.idx, sizeof(ack));
	ATF_CHECK_EQ(ack, 0);
	ATF_CHECK_EQ(used->ring[0].id, 0);
	ATF_CHECK_EQ(used->ring[0].len, sizeof(ack));
	ATF_CHECK_EQ(atomic_load_acq_16(&used->idx), 1);
	vq_endchains(&vq, 1);
	ATF_CHECK_EQ(g_interrupts, 1);
}

ATF_TC_WITHOUT_HEAD(linux_rss_production_callback);
ATF_TC_BODY(linux_rss_production_callback, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct pci_vtnet_softc sc;
	struct pci_devinst pi;
	struct vqueue_info *vq;
	struct vring_desc desc[8], indirect[4];
	struct vring_avail *avail;
	struct vring_used *used;
	uint8_t control_header[2] = {
	    VIRTIO14_NET_CTRL_MQ, VIRTIO14_NET_CTRL_MQ_RSS_CONFIG
	};
	uint8_t rss_header[264] = { 0 };
	uint8_t rss_trailer[44] = { 0 };
	uint8_t ack = UINT8_MAX;
	uint16_t value;

	/*
	 * Join the two formerly separate tests: dispatch an exact Linux
	 * four-descriptor indirect RSS request through the real split-ring core
	 * and the real pci_vtnet_ping_ctlq() callback.  The callback only
	 * schedules work, so explicitly run the worker's bounded control batch
	 * before verifying queue state, acknowledgement, used-ring publication,
	 * and interrupt delivery.
	 */
	memset(&sc, 0, sizeof(sc));
	sc.vsc_consts = vtnet_vi_consts;
	sc.vsc_consts.vc_nvq = 5;
	sc.vsc_max_pairs = 2;
	sc.vsc_features = VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_NET_F_MQ |
	    VIRTIO14_NET_F_RSS;
	sc.features_negotiated = true;
	sc.tx_features_negotiated = true;
	sc.rx_active_pairs = 1;
	sc.rx_enabled_mask = 1;
	sc.tx_active_pairs = 1;
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.rx_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.tx_mtx, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&sc.tx_cond, NULL), 0);

	vq = &sc.vsc_queues[VIRTIO14_NET_MQ_CONTROLQ(2)];
	avail = (struct vring_avail *)(void *)avail_mem.bytes;
	used = (struct vring_used *)(void *)used_mem.bytes;
	setup_queue(&sc.vsc_vs, &sc.vsc_consts, &pi, vq, desc, avail, used);
	sc.vsc_vs.vs_queues = sc.vsc_queues;
	sc.vsc_vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	sc.vsc_vs.vs_status = VIRTIO14_STATUS_DRIVER_OK;
	sc.vsc_vs.vs_negotiated_caps = VIRTIO14_F_RING_INDIRECT_DESC |
	    VIRTIO14_F_RING_EVENT_IDX;
	vq->vq_num = VIRTIO14_NET_MQ_CONTROLQ(2);
	vq->vq_enabled = 1;
	vq->vq_notify = pci_vtnet_ping_ctlq;

	virtio14_store_le32(rss_header,
	    VIRTIO14_NET_RSS_HASH_TYPES_BASIC);
	virtio14_store_le16(rss_header + 4, 127);
	virtio14_store_le16(rss_header + 6, 0);
	for (size_t i = 0; i < VIRTIO14_NET_RSS_TABLE_SIZE_MIN; i++) {
		value = htole16(i & 1);
		memcpy(rss_header + 8 + i * sizeof(value), &value,
		    sizeof(value));
	}
	virtio14_store_le16(rss_trailer, 2);
	rss_trailer[2] = 40;
	for (size_t i = 0; i < 40; i++)
		rss_trailer[3 + i] = (uint8_t)i;

	add_region(0x1000, control_header, sizeof(control_header));
	add_region(0x2000, rss_header, sizeof(rss_header));
	add_region(0x3000, rss_trailer, sizeof(rss_trailer));
	add_region(0x4000, &ack, sizeof(ack));
	add_region(0x5000, indirect,
	    4U * VIRTIO14_SPLIT_DESC_SIZE);
	memset(indirect, 0, sizeof(indirect));
	indirect[0].addr = htole64(0x1000);
	indirect[0].len = htole32(sizeof(control_header));
	indirect[0].flags = htole16(VIRTIO14_DESC_F_NEXT);
	indirect[0].next = htole16(1);
	indirect[1].addr = htole64(0x2000);
	indirect[1].len = htole32(sizeof(rss_header));
	indirect[1].flags = htole16(VIRTIO14_DESC_F_NEXT);
	indirect[1].next = htole16(2);
	indirect[2].addr = htole64(0x3000);
	indirect[2].len = htole32(sizeof(rss_trailer));
	indirect[2].flags = htole16(VIRTIO14_DESC_F_NEXT);
	indirect[2].next = htole16(3);
	indirect[3].addr = htole64(0x4000);
	indirect[3].len = htole32(sizeof(ack));
	indirect[3].flags = htole16(VIRTIO14_DESC_F_WRITE);
	desc[0].addr = htole64(0x5000);
	desc[0].len = htole32(4U * VIRTIO14_SPLIT_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_DESC_F_INDIRECT);

	vi_pci_notify_queue(&sc.vsc_vs, vq->vq_num);
	ATF_REQUIRE(sc.ctl_pending);
	sc.ctl_pending = false;
	ATF_REQUIRE(!pci_vtnet_process_ctlq(&sc, vq));
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_OK);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rss_max_tx_vq, 2);
	ATF_CHECK_EQ(used->ring[0].id, 0);
	ATF_CHECK_EQ(used->ring[0].len, sizeof(ack));
	ATF_CHECK_EQ(atomic_load_acq_16(&used->idx), 1);
	ATF_CHECK_EQ(g_interrupts, 1);
	ATF_CHECK_EQ(vq_avail_event_idx(vq), 1);

	/*
	 * Feed a second, malformed Linux-shaped request through the same live
	 * control queue.  Model Linux's EVENT_IDX kick decision instead of
	 * directly calling the device callback: this request is delivered only
	 * if the first completion asked for the next available entry.  A table
	 * entry naming pair 2 is outside this two-pair device.  The device must
	 * publish ERR without partially changing the previously accepted RSS
	 * state.
	 */
	virtio14_store_le16(rss_header + 8, 2);
	ack = UINT8_MAX;
	desc[1].addr = htole64(0x5000);
	desc[1].len = htole32(4U * VIRTIO14_SPLIT_DESC_SIZE);
	desc[1].flags = htole16(VIRTIO14_DESC_F_INDIRECT);
	avail->ring[1] = htole16(1);
	atomic_store_rel_16(&avail->idx, htole16(2));
	if (vring_need_event(vq_avail_event_idx(vq), 2, 1))
		vi_pci_notify_queue(&sc.vsc_vs, vq->vq_num);
	ATF_REQUIRE(sc.ctl_pending);
	sc.ctl_pending = false;
	ATF_REQUIRE(!pci_vtnet_process_ctlq(&sc, vq));
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rss_indirection_table[0], 0);
	ATF_CHECK_EQ(used->ring[1].id, 1);
	ATF_CHECK_EQ(used->ring[1].len, sizeof(ack));
	ATF_CHECK_EQ(atomic_load_acq_16(&used->idx), 2);
	ATF_CHECK_EQ(vq_avail_event_idx(vq), 2);

	ATF_REQUIRE_EQ(pthread_cond_destroy(&sc.tx_cond), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.tx_mtx), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.rx_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(descriptor_chain_byte_limit);
ATF_TC_BODY(descriptor_chain_byte_limit, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req;
	struct iovec iov[3];
	uint8_t payload;

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	/* The parser maps these ranges but does not access their contents. */
	add_region(0x1000, &payload, UINT32_MAX);
	desc[0].addr = 0x1000;
	desc[0].len = UINT32_MAX;
	desc[0].flags = VRING_DESC_F_NEXT;
	desc[0].next = 1;
	desc[1].addr = 0x1000;
	desc[1].len = 1;
	desc[1].flags = 0;
	/* Section 2.7.5.2 permits exactly 2^32 aggregate bytes. */
	ATF_CHECK(vq_getchain(&vq, iov, nitems(iov), &req) == 2);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);

	/* One byte beyond the limit is malformed. */
	vq.vq_last_avail = 0;
	desc[1].flags = VRING_DESC_F_NEXT;
	desc[1].next = 2;
	desc[2].addr = 0x1000;
	desc[2].len = 1;
	ATF_CHECK(vq_getchain(&vq, iov, nitems(iov), &req) == -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

ATF_TC_WITHOUT_HEAD(fatal_ring_error_blocks_later_kicks);
ATF_TC_BODY(fatal_ring_error_blocks_later_kicks, tc)
{
	struct virtio_consts vc = {
		.vc_name = "fatal-notify-test",
		.vc_nvq = 1,
		.vc_qnotify = notify_and_interrupt,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK |
	    VIRTIO_CONFIG_S_NEEDS_RESET;
	g_notifications = 0;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK(g_notifications == 0);

	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK(g_notifications == 1);
}

ATF_TC_WITHOUT_HEAD(fatal_ring_error_stops_current_batch);
ATF_TC_BODY(fatal_ring_error_stops_current_batch, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vring_avail *avail;
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[2];

	avail = (struct vring_avail *)(void *)avail_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail,
	    (struct vring_used *)(void *)used_mem.bytes);
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	add_region(0x1000, payload, sizeof(payload));

	/*
	 * The first available chain becomes fatal only after its first valid
	 * descriptor.  A second, otherwise valid request is already visible.
	 * Once vq_getchain() poisons the device, the current callback's normal
	 * vq_has_descs() loop must not consume that second request.
	 */
	desc[0].addr = 0x1000;
	desc[0].len = 1;
	desc[0].flags = VRING_DESC_F_NEXT;
	desc[0].next = vq.vq_qsize;
	desc[1].addr = 0x1001;
	desc[1].len = 1;
	avail->ring[0] = 0;
	avail->ring[1] = 1;
	atomic_store_rel_16(&avail->idx, 2);

	ATF_REQUIRE(vq_has_descs(&vq));
	ATF_CHECK_EQ(vq_getchain(&vq, &iov, 1, &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(vq.vq_last_avail, 1);
	ATF_CHECK(!vq_has_descs(&vq));
	ATF_CHECK_EQ(vq.vq_last_avail, 1);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(chain_can_use_full_queue);
ATF_TC_BODY(chain_can_use_full_queue, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	struct vi_req req;
	struct iovec iov;
	uint8_t payload;
	const uint16_t qsize = 1024;
	const uint16_t chain_len = qsize;

	desc = calloc(qsize, VIRTIO14_SPLIT_DESC_SIZE);
	avail = calloc(1, VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    (qsize + 1) * VIRTIO14_SPLIT_AVAIL_ELEM_SIZE);
	used = calloc(1, VIRTIO14_SPLIT_USED_HEADER_SIZE +
	    (qsize + 1) * VIRTIO14_SPLIT_USED_ELEM_SIZE);
	ATF_REQUIRE(desc != NULL && avail != NULL && used != NULL);
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vq.vq_qsize = qsize;
	add_region(0x1000, &payload, sizeof(payload));
	for (uint16_t i = 0; i < chain_len; i++) {
		desc[i].addr = 0x1000;
		desc[i].len = sizeof(payload);
		if (i + 1 < chain_len) {
			desc[i].flags = VRING_DESC_F_NEXT;
			desc[i].next = i + 1;
		}
	}
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == chain_len);
	ATF_CHECK(req.readable == chain_len && req.writable == 0);
	free(used);
	free(avail);
	free(desc);
}
ATF_TC_WITHOUT_HEAD(legacy_queue_mapping_validation);
ATF_TC_BODY(legacy_queue_mapping_validation, tc)
{
	union { max_align_t align; uint8_t bytes[16384]; } ring_mem;
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	size_t ring_size;

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vc.vc_nvq = 1;
	vs.vs_queues = &vq;
	vs.vs_curq = 0;
	ring_size = vring_size_aligned(vq.vq_qsize);
	ATF_REQUIRE(ring_size < sizeof(ring_mem.bytes));

	/*
	 * A guest PFN only proves the wire layout is aligned.  A translated-DMA
	 * implementation can still return an unaligned host address, which must
	 * not be published through typed vring pointers.
	 */
	add_region(0x4000, ring_mem.bytes + 1, ring_size);
	vq.vq_notify_pending = true;
	vi_vq_init(&vs, 4);
	ATF_CHECK_EQ(vq.vq_pfn, 0);
	ATF_CHECK_EQ(vq.vq_flags, 0);
	ATF_CHECK(!vq.vq_notify_pending);
	ATF_CHECK(vq.vq_desc == NULL && vq.vq_avail == NULL &&
	    vq.vq_used == NULL);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	vs.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET;
	add_region(0x8000, ring_mem.bytes, ring_size);

	vi_vq_init(&vs, 8);
	ATF_CHECK(vq.vq_pfn == 8);
	ATF_CHECK((vq.vq_flags & VQ_ALLOC) != 0);
	ATF_CHECK(vq.vq_desc == (void *)ring_mem.bytes);

	ATF_REQUIRE(vq.vq_split_owners != NULL);
	vq.vq_split_owners[0] = 1;
	vi_vq_init(&vs, 0);
	ATF_CHECK_EQ(vq.vq_pfn, 8);
	ATF_CHECK((vq.vq_flags & VQ_ALLOC) != 0);
	ATF_CHECK(vq.vq_desc == (void *)ring_mem.bytes);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq.vq_split_owners[0] = 0;
	vs.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET;

	vq.vq_notify_pending = true;
	vi_vq_init(&vs, 0);
	ATF_CHECK(vq.vq_pfn == 0 && vq.vq_flags == 0);
	ATF_CHECK(!vq.vq_notify_pending);
	ATF_CHECK(vq.vq_desc == NULL && vq.vq_avail == NULL &&
	    vq.vq_used == NULL);

	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_vq_init(&vs, 0xdead);
	ATF_CHECK(vq.vq_pfn == 0 && vq.vq_flags == 0);
	ATF_CHECK(vq.vq_last_avail == 0 && vq.vq_next_used == 0 &&
	    vq.vq_save_used == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK((vs.vs_isr & VIRTIO_PCI_ISR_CONFIG) != 0);

	/* A rejected owner-store setup uses the same queue-clear contract. */
	vs.vs_status = 0;
	vq.vq_qsize = 0;
	vq.vq_pfn = 0xfeed;
	vq.vq_notify_pending = true;
	vq.vq_desc = (void *)ring_mem.bytes;
	vq.vq_avail = (void *)avail_mem.bytes;
	vq.vq_used = (void *)used_mem.bytes;
	vi_vq_init(&vs, 4);
	ATF_CHECK_EQ(vq.vq_pfn, 0);
	ATF_CHECK_EQ(vq.vq_flags, 0);
	ATF_CHECK(!vq.vq_notify_pending);
	ATF_CHECK(vq.vq_desc == NULL && vq.vq_avail == NULL &&
	    vq.vq_used == NULL);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	free(vq.vq_split_owners);
}

ATF_TC_WITHOUT_HEAD(event_idx_interrupts);
ATF_TC_BODY(event_idx_interrupts, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vring_avail *avail;
	struct vring_used *used;

	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vs.vs_negotiated_caps =
	    VIRTIO_F_VERSION_1 | VIRTIO_RING_F_EVENT_IDX;
	avail->ring[vq.vq_qsize] = 0;
	vq_relchain(&vq, 0, 0);
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 1);

	avail->ring[vq.vq_qsize] = 2;
	vq_relchain(&vq, 1, 0);
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 1);

	avail->ring[vq.vq_qsize] = 2;
	vq_relchain(&vq, 2, 0);
	vq_endchains(&vq, 0);
	ATF_CHECK(g_interrupts == 2);
}

ATF_TC_WITHOUT_HEAD(packed_direct_wrap_and_completion);
ATF_TC_BODY(packed_direct_wrap_and_completion, tc)
{
	uint8_t read_buffer[4], write_buffer[8];
	struct virtio_packed_desc desc[3];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov[2];
	struct vi_req req;
	int n;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x1000, read_buffer, sizeof(read_buffer));
	add_region(0x2000, write_buffer, sizeof(write_buffer));
	vq.vq_packed_next_avail = 2;
	vq.vq_packed_next_used = 2;
	vq.vq_packed_save_used = 2;

	/* The chain wraps from slot 2 to slot 0 in a three-entry queue. */
	desc[2].address = htole64(0x1000);
	desc[2].length = htole32(sizeof(read_buffer));
	desc[2].id = htole16(41);
	desc[2].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_NEXT);
	desc[0].address = htole64(0x2000);
	desc[0].length = htole32(sizeof(write_buffer));
	desc[0].id = htole16(77);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_USED |
	    VIRTIO14_PACKED_DESC_F_WRITE);

	ATF_CHECK(vq_has_descs(&vq));
	n = vq_getchain(&vq, iov, nitems(iov), &req);
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK_EQ(read_buffer, iov[0].iov_base);
	ATF_CHECK_EQ(nitems(read_buffer), iov[0].iov_len);
	ATF_CHECK_EQ(write_buffer, iov[1].iov_base);
	ATF_CHECK_EQ(nitems(write_buffer), iov[1].iov_len);
	ATF_CHECK_EQ(1, req.readable);
	ATF_CHECK_EQ(1, req.writable);
	/* Independent expected capacity encoded in the writable descriptor. */
	ATF_CHECK_EQ(UINT64_C(8), req.writable_bytes);
	ATF_CHECK(req.lengths_known);
	ATF_CHECK(req.ordered);
	ATF_CHECK_EQ(2, req.packed_head);
	ATF_CHECK(req.packed_wrap);
	ATF_CHECK_EQ(2, req.descriptor_count);
	ATF_CHECK_EQ(77, req.completion_id);
	ATF_CHECK_EQ(1, vq.vq_packed_next_avail);
	ATF_CHECK(!vq.vq_packed_avail_wrap);
	ATF_CHECK_EQ(2, g_map_calls);
	ATF_CHECK_EQ(0x2000, g_last_map_address);
	ATF_CHECK_EQ(nitems(write_buffer), g_last_map_len);
	ATF_CHECK_EQ(VIRTIO_DMA_DEVICE_WRITE, g_last_map_direction);

	driver_event.flags = htole16(VIRTIO14_PACKED_EVENT_F_ENABLE);
	vq_relchain_req(&vq, &req, nitems(write_buffer));
	ATF_CHECK_EQ(nitems(write_buffer), le32toh(desc[2].length));
	ATF_CHECK_EQ(77, le16toh(desc[2].id));
	ATF_CHECK_EQ(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED |
	    VIRTIO14_PACKED_DESC_F_WRITE, le16toh(desc[2].flags));
	/*
	 * A packed chained buffer has exactly one used descriptor: its head.
	 * Descriptor zero is the tail in this wrapping chain, so completion must
	 * leave its availability state and metadata untouched.
	 */
	ATF_CHECK_EQ(nitems(write_buffer), le32toh(desc[0].length));
	ATF_CHECK_EQ(77, le16toh(desc[0].id));
	ATF_CHECK_EQ(VIRTIO14_PACKED_DESC_F_USED |
	    VIRTIO14_PACKED_DESC_F_WRITE, le16toh(desc[0].flags));
	ATF_CHECK_EQ(1, vq.vq_packed_next_used);
	ATF_CHECK(!vq.vq_packed_used_wrap);
	vq_endchains(&vq, 0);
	ATF_CHECK_EQ(1, g_interrupts);
	ATF_CHECK_EQ(1, vq.vq_packed_save_used);
	ATF_CHECK(!vq.vq_packed_save_used_wrap);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_event_rollback_and_stale_completion);
ATF_TC_BODY(packed_event_rollback_and_stale_completion, tc)
{
	uint8_t buffer[8];
	struct virtio_packed_desc desc[3];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov;
	struct vi_req duplicate, req;
	uint16_t saved_flags;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x3000, buffer, sizeof(buffer));
	vs.vs_negotiated_caps =
	    VIRTIO_F_VERSION_1 | VIRTIO_RING_F_EVENT_IDX;
	vq.vq_packed_next_avail = 2;
	desc[2].address = htole64(0x3000);
	desc[2].length = htole32(sizeof(buffer));
	desc[2].id = htole16(9);
	desc[2].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);

	vq_kick_enable(&vq);
	ATF_CHECK_EQ(VIRTIO14_PACKED_EVENT_F_DESC,
	    le16toh(device_event.flags));
	ATF_CHECK_EQ(VIRTIO14_PACKED_EVENT_WRAP | 2,
	    le16toh(device_event.off_wrap));
	vq_kick_disable(&vq);
	ATF_CHECK_EQ(VIRTIO14_PACKED_EVENT_F_DISABLE,
	    le16toh(device_event.flags));

	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &req));
	ATF_CHECK_EQ(0, vq.vq_packed_next_avail);
	ATF_CHECK(!vq.vq_packed_avail_wrap);
	vq_retchain_req(&vq, &req);
	ATF_CHECK_EQ(2, vq.vq_packed_next_avail);
	ATF_CHECK(vq.vq_packed_avail_wrap);

	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &req));
	duplicate = req;
	saved_flags = desc[0].flags;
	vq.vq_generation++;
	/* Reset retains only the atomic lease for this late completion. */
	vq.vq_packed_completions[req.packed_head].iolen = 99;
	vq.vq_packed_completions[req.packed_head].descriptor_count = 1;
	vq.vq_packed_completions[req.packed_head].completion_id = 77;
	vq.vq_packed_completions[req.packed_head].group_count = 1;
	vq.vq_packed_completions[req.packed_head].packed_wrap =
	    req.packed_wrap;
	vq.vq_packed_completions[req.packed_head].valid = true;
	vq_packed_completions_reset(&vq);
	ATF_REQUIRE(vq.vq_packed_completions != NULL);
	ATF_CHECK(vq.vq_packed_completions[req.packed_head].owner_state != 0);
	ATF_CHECK(!vq.vq_packed_completions[req.packed_head].valid);
	ATF_CHECK_EQ(0, vq.vq_packed_completions[req.packed_head].iolen);
	ATF_CHECK_EQ(0,
	    vq.vq_packed_completions[req.packed_head].descriptor_count);
	ATF_CHECK_EQ(0,
	    vq.vq_packed_completions[req.packed_head].completion_id);
	/*
	 * A full reset changes the queue's configured layout before a stale
	 * asynchronous completion can arrive.  Retirement must use the
	 * acquisition layout recorded in the request, not the queue's current
	 * layout, or the packed owner would leak.
	 */
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq_relchain_req(&vq, &req, sizeof(buffer));
	/* A reset-generation stale token is retired, not a new device fault. */
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	ATF_CHECK_EQ(saved_flags, desc[0].flags);
	ATF_CHECK_EQ(0, vq.vq_packed_next_used);
	ATF_CHECK_EQ(0, vq.vq_packed_completions[req.packed_head].owner_state);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	ATF_CHECK_EQ(0, vq_packed_completions_init(&vq));
	/*
	 * Even rollback leaves the packed descriptors device-owned, so only
	 * host-side owner state can prevent a copied token from rewinding the
	 * acquisition cursor or releasing its lease twice.
	 */
	vq_retchain_req(&vq, &duplicate);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(0, vq.vq_packed_next_avail);
	ATF_CHECK(!duplicate.outstanding);
	vq_packed_completions_reset(&vq);
	ATF_CHECK(vq.vq_packed_completions == NULL);
}

ATF_TC_WITHOUT_HEAD(packed_out_of_order_return_needs_reset);
ATF_TC_BODY(packed_out_of_order_return_needs_reset, tc)
{
	uint8_t buffer[16];
	struct virtio_packed_desc desc[2];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov;
	struct vi_req first, second;
	unsigned int i;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x3400, buffer, sizeof(buffer));
	for (i = 0; i < nitems(desc); i++) {
		desc[i].address = htole64(0x3400 + i * sizeof(uint64_t));
		desc[i].length = htole32(sizeof(uint64_t));
		desc[i].id = htole16((uint16_t)i);
		desc[i].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);
	}

	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &first));
	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &second));
	ATF_REQUIRE_EQ(0, vq.vq_packed_next_avail);
	ATF_REQUIRE(!vq.vq_packed_avail_wrap);

	/* A return is a tail rollback, never general asynchronous cancellation. */
	vq_retchain_req(&vq, &first);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(0, vq.vq_packed_next_avail);
	ATF_CHECK(!vq.vq_packed_avail_wrap);
	ATF_CHECK(!first.outstanding);

	/* The later lease can still be retired during reset cleanup. */
	vq_discard_req(&vq, &second);
	ATF_CHECK(!second.outstanding);
	vq_packed_completions_fini(&vq);

	/* Layout is immutable for a generation; never reinterpret a live token. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x3400, buffer, sizeof(buffer));
	desc[0].address = htole64(0x3400);
	desc[0].length = htole32(sizeof(uint64_t));
	desc[0].id = htole16(0);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);
	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &first));
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq_retchain_req(&vq, &first);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!first.outstanding);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(split_out_of_order_return_needs_reset);
ATF_TC_BODY(split_out_of_order_return_needs_reset, tc)
{
	uint8_t buffer[16];
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct vring_avail *avail;
	struct vring_desc desc[8];
	struct vring_used *used;
	struct iovec iov;
	struct vi_req first, second;

	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	add_region(0x3500, buffer, sizeof(buffer));
	avail->idx = htole16(2);
	avail->ring[0] = htole16(0);
	avail->ring[1] = htole16(1);
	for (unsigned int i = 0; i < 2; i++) {
		desc[i].addr = htole64(0x3500 + i * sizeof(uint64_t));
		desc[i].len = htole32(sizeof(uint64_t));
		desc[i].flags = 0;
	}

	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &first));
	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &second));
	ATF_REQUIRE_EQ(2, vq.vq_last_avail);
	vq_retchain_req(&vq, &first);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(2, vq.vq_last_avail);
	ATF_CHECK(!first.outstanding);
	vq_discard_req(&vq, &second);
	ATF_CHECK(!second.outstanding);
}

ATF_TC_WITHOUT_HEAD(completion_layout_mismatch_needs_reset);
ATF_TC_BODY(completion_layout_mismatch_needs_reset, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct vring_avail *avail;
	struct vring_desc desc[8];
	struct vring_used *used;
	struct vi_req req, group[2];
	uint32_t group_lens[2] = { 0, 0 };
	uint16_t used_idx;

	/*
	 * Model a corrupted lifecycle transition which changes layout without
	 * advancing generation.  The completion token must retire its packed
	 * ownership and latch NEEDS_RESET rather than write the split used ring.
	 */
	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	memset(&req, 0, sizeof(req));
	req.packed_head = 0;
	req.packed_wrap = true;
	req.descriptor_count = 1;
	req.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &req);
	used_idx = used->idx;
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	ATF_REQUIRE_EQ(VIRTIO_QUEUE_PACKED, req.queue_layout);
	ATF_REQUIRE_EQ(VIRTIO_QUEUE_SPLIT, vq.vq_layout);
	vq_relchain_req(&vq, &req, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(used_idx, used->idx);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	vq_packed_completions_fini(&vq);

	/* The same invariant applies to atomic multi-chain publication. */
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	memset(group, 0, sizeof(group));
	for (unsigned int i = 0; i < nitems(group); i++) {
		group[i].packed_head = i;
		group[i].packed_wrap = true;
		group[i].descriptor_count = 1;
		group[i].queue_generation = vq.vq_generation;
		own_test_packed_request(&vq, &group[i]);
	}
	used_idx = used->idx;
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq_relchain_group(&vq, group, group_lens, nitems(group));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(used_idx, used->idx);
	ATF_CHECK(!group[0].outstanding);
	ATF_CHECK(!group[1].outstanding);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	vq_packed_completions_fini(&vq);

	/* A real reset advances generation, so stale grouped tokens are benign. */
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vq.vq_layout = VIRTIO_QUEUE_PACKED;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	memset(group, 0, sizeof(group));
	for (unsigned int i = 0; i < nitems(group); i++) {
		group[i].packed_head = i;
		group[i].packed_wrap = true;
		group[i].descriptor_count = 1;
		group[i].queue_generation = vq.vq_generation;
		own_test_packed_request(&vq, &group[i]);
	}
	used_idx = used->idx;
	vq.vq_generation++;
	vq.vq_layout = VIRTIO_QUEUE_SPLIT;
	vq_relchain_group(&vq, group, group_lens, nitems(group));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	ATF_CHECK_EQ(used_idx, used->idx);
	ATF_CHECK(!group[0].outstanding);
	ATF_CHECK(!group[1].outstanding);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_zero_length_completion_clears_write);
ATF_TC_BODY(packed_zero_length_completion_clears_write, tc)
{
	uint8_t write_buffer[8];
	struct virtio_packed_desc desc[1];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov;
	struct vi_req req;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x3800, write_buffer, sizeof(write_buffer));
	desc[0].address = htole64(0x3800);
	desc[0].length = htole32(sizeof(write_buffer));
	desc[0].id = htole16(19);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_WRITE);

	ATF_REQUIRE_EQ(1, vq_getchain(&vq, &iov, 1, &req));
	ATF_REQUIRE_EQ(1, req.writable);
	vq_relchain_req(&vq, &req, 0);

	/*
	 * VirtIO 1.4 sections 2.8.3 and 2.8.4 define WRITE on a used
	 * descriptor as evidence that the device wrote some data.  Merely
	 * receiving writable capacity is insufficient, and length is reserved
	 * when WRITE is clear.
	 */
	ATF_CHECK_EQ(0, le32toh(desc[0].length));
	ATF_CHECK_EQ(19, le16toh(desc[0].id));
	ATF_CHECK_EQ(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED, le16toh(desc[0].flags));
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_event_threshold_wrap);
ATF_TC_BODY(packed_event_threshold_wrap, tc)
{
	struct virtio_packed_desc desc[3];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req req;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	vq.vq_packed_next_used = 2;
	vq.vq_packed_save_used = 2;
	vq.vq_packed_next_avail = 0;
	vq.vq_packed_avail_wrap = false;
	memset(&req, 0, sizeof(req));
	req.descriptor_count = 1;
	req.completion_id = 13;
	req.packed_head = 2;
	req.packed_wrap = true;
	req.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &req);
	driver_event.off_wrap = htole16(VIRTIO14_PACKED_EVENT_WRAP | 2);
	driver_event.flags = htole16(VIRTIO14_PACKED_EVENT_F_DESC);

	vq_relchain_req(&vq, &req, 4);
	ATF_CHECK_EQ(0, vq.vq_packed_next_used);
	ATF_CHECK(!vq.vq_packed_used_wrap);
	vq_endchains(&vq, 0);
	ATF_CHECK_EQ(1, g_interrupts);

	/* A threshold beyond the next completion suppresses the interrupt. */
	req.completion_id = 14;
	req.packed_head = 0;
	req.packed_wrap = false;
	own_test_packed_request(&vq, &req);
	vq.vq_packed_next_avail = 1;
	driver_event.off_wrap = htole16(2);
	vq_relchain_req(&vq, &req, 4);
	vq_endchains(&vq, 0);
	ATF_CHECK_EQ(1, g_interrupts);

	driver_event.flags = htole16(VIRTIO14_PACKED_EVENT_F_RESERVED);
	vq_endchains(&vq, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_async_completions_publish_in_request_order);
ATF_TC_BODY(packed_async_completions_publish_in_request_order, tc)
{
	struct virtio_packed_desc desc[4];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req first, second;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	memset(&first, 0, sizeof(first));
	first.descriptor_count = 1;
	first.completion_id = 10;
	first.packed_head = 0;
	first.packed_wrap = true;
	first.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &first);
	memset(&second, 0, sizeof(second));
	second.descriptor_count = 2;
	second.completion_id = 20;
	second.packed_head = 1;
	second.packed_wrap = true;
	second.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &second);
	vq.vq_packed_next_avail = 3;

	/* Completing the later request must not expose it to the driver. */
	vq_relchain_req(&vq, &second, 200);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 0);
	ATF_CHECK_EQ(le16toh(desc[1].flags), 0);
	ATF_CHECK(!vq_packed_completions_empty(&vq));

	/* The missing head releases both completions with their own spans. */
	vq_relchain_req(&vq, &first, 100);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 3);
	ATF_CHECK(vq.vq_packed_used_wrap);
	ATF_CHECK_EQ(le32toh(desc[0].length), 100);
	ATF_CHECK_EQ(le16toh(desc[0].id), 10);
	ATF_CHECK_EQ(le32toh(desc[1].length), 200);
	ATF_CHECK_EQ(le16toh(desc[1].id), 20);
	ATF_CHECK_EQ(le16toh(desc[2].flags), 0);
	ATF_CHECK(vq_packed_completions_empty(&vq));

	/* Repeat across the wrap boundary with the later head completing first. */
	first.completion_id = 30;
	first.packed_head = 3;
	first.packed_wrap = true;
	own_test_packed_request(&vq, &first);
	second.completion_id = 40;
	second.packed_head = 0;
	second.packed_wrap = false;
	own_test_packed_request(&vq, &second);
	vq.vq_packed_next_avail = 2;
	vq.vq_packed_avail_wrap = false;
	vq_relchain_req(&vq, &second, 400);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 3);
	ATF_CHECK(vq.vq_packed_used_wrap);
	vq_relchain_req(&vq, &first, 300);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 2);
	ATF_CHECK(!vq.vq_packed_used_wrap);
	ATF_CHECK_EQ(le32toh(desc[3].length), 300);
	ATF_CHECK_EQ(le16toh(desc[3].id), 30);
	ATF_CHECK_EQ(le32toh(desc[0].length), 400);
	ATF_CHECK_EQ(le16toh(desc[0].id), 40);
	ATF_CHECK(vq_packed_completions_empty(&vq));

	/* A duplicate completion is a malformed backend action. */
	vq_relchain_req(&vq, &first, 100);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/*
	 * An unfilled head is a legal asynchronous gap, but a valid staged
	 * completion from the other wrap generation is not.  It cannot be a
	 * later request while this generation still owns the used cursor, and
	 * must not turn completion ordering into a permanent silent stall.
	 */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vq.vq_packed_completions[0].valid = true;
	vq.vq_packed_completions[0].packed_wrap = false;
	vq.vq_packed_completions[0].descriptor_count = 1;
	vq.vq_packed_completions[0].group_count = 1;
	memset(&second, 0, sizeof(second));
	second.descriptor_count = 1;
	second.completion_id = 50;
	second.packed_head = 1;
	second.packed_wrap = true;
	second.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &second);
	vq.vq_packed_next_avail = 2;
	vq_relchain_req(&vq, &second, 500);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_malformed_chains_need_reset);
ATF_TC_BODY(packed_malformed_chains_need_reset, tc)
{
	uint8_t buffer[8];
	struct virtio_packed_desc desc[3], indirect[1];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov[2];
	struct vi_req req;

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x4000, buffer, sizeof(buffer));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(sizeof(buffer));
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_NEXT);
	/* Slot 1 has not been transferred to the device. */
	desc[1].address = htole64(0x4000);
	desc[1].length = htole32(sizeof(buffer));
	desc[1].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED);
	ATF_CHECK_EQ(-1, vq_getchain(&vq, iov, nitems(iov), &req));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(0, vq.vq_packed_next_avail);
	vq_packed_completions_fini(&vq);

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(sizeof(buffer));
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_CHECK_EQ(-1, vq_getchain(&vq, iov, nitems(iov), &req));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/*
	 * Section 2.8.19 forbids mixing a direct chain and an indirect
	 * descriptor in one packed list.  Reject an indirect tail without
	 * consuming either main-ring descriptor.
	 */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x4000, buffer, sizeof(buffer));
	add_region(0x5000, indirect,
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	indirect[0].address = htole64(0x4000);
	indirect[0].length = htole32(sizeof(buffer));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(sizeof(buffer));
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_NEXT);
	desc[1].address = htole64(0x5000);
	desc[1].length = htole32(
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	desc[1].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_CHECK_EQ(-1, vq_getchain(&vq, iov, nitems(iov), &req));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(0, vq.vq_packed_next_avail);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_group_completion);
ATF_TC_BODY(packed_group_completion, tc)
{
	struct virtio_packed_desc desc[4];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req reqs[2];
	uint32_t lens[2] = { 100, 200 };

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	memset(reqs, 0, sizeof(reqs));
	reqs[0].descriptor_count = 1;
	reqs[0].completion_id = 10;
	reqs[0].packed_head = 0;
	reqs[0].packed_wrap = true;
	reqs[0].queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &reqs[0]);
	reqs[1].descriptor_count = 2;
	reqs[1].completion_id = 20;
	reqs[1].packed_head = 1;
	reqs[1].packed_wrap = true;
	reqs[1].queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &reqs[1]);
	vq.vq_packed_next_avail = 3;

	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_CHECK_EQ(vq.vq_packed_next_used, 3);
	ATF_CHECK(vq.vq_packed_used_wrap);
	ATF_CHECK_EQ(le32toh(desc[0].length), lens[0]);
	ATF_CHECK_EQ(le16toh(desc[0].id), reqs[0].completion_id);
	ATF_CHECK_EQ(le32toh(desc[1].length), lens[1]);
	ATF_CHECK_EQ(le16toh(desc[1].id), reqs[1].completion_id);
	ATF_CHECK(vq_packed_completions_empty(&vq));

	/* A two-chain group remains valid when it crosses the wrap boundary. */
	reqs[0].completion_id = 30;
	reqs[0].packed_head = 3;
	reqs[0].packed_wrap = true;
	own_test_packed_request(&vq, &reqs[0]);
	reqs[1].descriptor_count = 1;
	reqs[1].completion_id = 40;
	reqs[1].packed_head = 0;
	reqs[1].packed_wrap = false;
	own_test_packed_request(&vq, &reqs[1]);
	vq.vq_packed_next_avail = 1;
	vq.vq_packed_avail_wrap = false;
	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_CHECK_EQ(vq.vq_packed_next_used, 1);
	ATF_CHECK(!vq.vq_packed_used_wrap);
	ATF_CHECK_EQ(le32toh(desc[3].length), lens[0]);
	ATF_CHECK_EQ(le32toh(desc[0].length), lens[1]);

	/*
	 * A complete group may wait behind an earlier asynchronous request.
	 * Publishing that request must release the group without exposing a
	 * follower independently or leaving reorder metadata behind.
	 */
	vq_packed_completions_fini(&vq);
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	reqs[0].descriptor_count = 1;
	reqs[0].completion_id = 50;
	reqs[0].packed_head = 1;
	reqs[0].packed_wrap = true;
	reqs[0].queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &reqs[0]);
	reqs[1].descriptor_count = 1;
	reqs[1].completion_id = 60;
	reqs[1].packed_head = 2;
	reqs[1].packed_wrap = true;
	reqs[1].queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &reqs[1]);
	vq.vq_packed_next_avail = 3;
	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_CHECK_EQ(vq.vq_packed_next_used, 0);
	ATF_CHECK(!vq_packed_completions_empty(&vq));
	reqs[0].completion_id = 40;
	reqs[0].packed_head = 0;
	own_test_packed_request(&vq, &reqs[0]);
	vq_relchain_req(&vq, &reqs[0], 75);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 3);
	ATF_CHECK_EQ(le32toh(desc[0].length), 75);
	ATF_CHECK_EQ(le32toh(desc[1].length), lens[0]);
	ATF_CHECK_EQ(le32toh(desc[2].length), lens[1]);
	ATF_CHECK(vq_packed_completions_empty(&vq));

	/* A gap between group members is rejected before staging anything. */
	reqs[0].completion_id = 70;
	reqs[0].packed_head = 3;
	reqs[0].packed_wrap = true;
	own_test_packed_request(&vq, &reqs[0]);
	reqs[1].completion_id = 80;
	reqs[1].packed_head = 1;
	reqs[1].packed_wrap = false;
	own_test_packed_request(&vq, &reqs[1]);
	vq.vq_packed_next_avail = 2;
	vq.vq_packed_avail_wrap = false;
	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vq_packed_completions_empty(&vq));

	/* Duplicate heads are rejected before any completion is staged. */
	vs.vs_status = 0;
	reqs[0].packed_head = 3;
	reqs[0].packed_wrap = false;
	own_test_packed_request(&vq, &reqs[0]);
	reqs[1] = reqs[0];
	vq.vq_packed_next_avail = 0;
	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(vq_packed_completions_empty(&vq));
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(packed_malformed_staged_group_needs_reset);
ATF_TC_BODY(packed_malformed_staged_group_needs_reset, tc)
{
	struct virtio_packed_desc desc[4];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vi_req reqs[2], first;
	uint32_t lens[2] = { 100, 200 };

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	memset(reqs, 0, sizeof(reqs));
	for (size_t i = 0; i < nitems(reqs); i++) {
		reqs[i].descriptor_count = 1;
		reqs[i].completion_id = (uint16_t)(20 + i);
		reqs[i].packed_head = (uint16_t)(1 + i);
		reqs[i].packed_wrap = true;
		reqs[i].queue_generation = vq.vq_generation;
		own_test_packed_request(&vq, &reqs[i]);
	}
	vq.vq_packed_next_avail = 3;
	vq_relchain_group(&vq, reqs, lens, nitems(reqs));
	ATF_REQUIRE(vq.vq_packed_completions[1].valid);
	ATF_REQUIRE(vq.vq_packed_completions[2].valid);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 0);

	/*
	 * Group publication is atomic, so losing a staged follower is an
	 * impossible internal state rather than a completion which may arrive
	 * later.  Releasing the preceding request must fail closed instead of
	 * leaving the valid group head to block the queue forever.
	 */
	vq.vq_packed_completions[2].valid = false;
	memset(&first, 0, sizeof(first));
	first.descriptor_count = 1;
	first.completion_id = 10;
	first.packed_head = 0;
	first.packed_wrap = true;
	first.queue_generation = vq.vq_generation;
	own_test_packed_request(&vq, &first);
	vq_relchain_req(&vq, &first, 50);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(vq.vq_packed_next_used, 1);
	vq_packed_completions_fini(&vq);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(packed_indirect_sequential_table);
ATF_TC_BODY(packed_indirect_sequential_table, tc)
{
	uint8_t read_buffer[5], write_buffer[7];
	struct virtio_packed_desc desc[3], indirect[2];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov[2];
	struct vi_req req;
	const uint32_t used_length = sizeof(write_buffer);

	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x5000, indirect,
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x6000, read_buffer, sizeof(read_buffer));
	add_region(0x7000, write_buffer, sizeof(write_buffer));
	indirect[0].address = htole64(0x6000);
	indirect[0].length = htole32(sizeof(read_buffer));
	indirect[0].id = htole16(UINT16_MAX); /* Reserved and ignored. */
	indirect[1].address = htole64(0x7000);
	indirect[1].length = htole32(sizeof(write_buffer));
	indirect[1].id = htole16(UINT16_MAX);
	indirect[1].flags = htole16(VIRTIO14_PACKED_DESC_F_WRITE);
	desc[0].address = htole64(0x5000);
	desc[0].length = htole32(
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	desc[0].id = htole16(55);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);

	ATF_REQUIRE_EQ(2, vq_getchain(&vq, iov, nitems(iov), &req));
	ATF_CHECK_EQ(read_buffer, iov[0].iov_base);
	ATF_CHECK_EQ(write_buffer, iov[1].iov_base);
	ATF_CHECK_EQ(1, req.readable);
	ATF_CHECK_EQ(1, req.writable);
	ATF_CHECK(req.ordered);
	ATF_CHECK(req.outstanding);
	ATF_CHECK_EQ(1, req.descriptor_count);
	ATF_CHECK_EQ(55, req.completion_id);
	ATF_CHECK_EQ(1, vq.vq_packed_next_avail);
	ATF_CHECK(vq.vq_packed_avail_wrap);
	vq_relchain_req(&vq, &req, used_length);
	ATF_CHECK(!req.outstanding);
	ATF_CHECK_EQ(used_length, le32toh(desc[0].length));
	ATF_CHECK_EQ(55, le16toh(desc[0].id));
	ATF_CHECK_EQ(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_USED,
	    le16toh(desc[0].flags) &
	    (VIRTIO14_PACKED_DESC_F_AVAIL | VIRTIO14_PACKED_DESC_F_USED));
	vq_packed_completions_fini(&vq);

	/*
	 * The table is sequential.  Section 2.8.7 reserves every flag except
	 * WRITE in an indirect entry and requires the device to ignore them.
	 * Set all of those bits so this does not accidentally validate only
	 * NEXT while still rejecting ownership or future reserved bits.
	 */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	add_region(0x5000, indirect,
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	add_region(0x6000, read_buffer, sizeof(read_buffer));
	add_region(0x7000, write_buffer, sizeof(write_buffer));
	indirect[0].flags = htole16(
	    UINT16_MAX ^ VIRTIO14_PACKED_DESC_F_WRITE);
	desc[0].address = htole64(0x5000);
	desc[0].length = htole32(
	    nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_REQUIRE_EQ(2, vq_getchain(&vq, iov, nitems(iov), &req));
	ATF_CHECK_EQ(read_buffer, iov[0].iov_base);
	ATF_CHECK_EQ(write_buffer, iov[1].iov_base);
	ATF_CHECK_EQ(1, req.readable);
	ATF_CHECK_EQ(1, req.writable);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	vq_packed_completions_fini(&vq);
}

ATF_TC_WITHOUT_HEAD(event_idx_kick_suppression);
ATF_TC_BODY(event_idx_kick_suppression, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vring_avail *avail;
	struct vring_used *used;
	uint8_t *avail_event;

	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vs.vs_negotiated_caps =
	    VIRTIO_F_VERSION_1 | VIRTIO_RING_F_EVENT_IDX;
	vq.vq_last_avail = UINT16_C(0x1234);
	used->flags = UINT16_MAX;
	avail_event = (uint8_t *)&used->ring[vq.vq_qsize];

	vq_kick_enable(&vq);
	ATF_CHECK(le16toh(used->flags) == 0);
	ATF_CHECK_EQ(avail_event[0], UINT8_C(0x34));
	ATF_CHECK_EQ(avail_event[1], UINT8_C(0x12));
	ATF_CHECK(vq_avail_event_idx(&vq) == UINT16_C(0x1234));

	vq_kick_disable(&vq);
	ATF_CHECK(le16toh(used->flags) == 0);
	ATF_CHECK_EQ(avail_event[0], UINT8_C(0x33));
	ATF_CHECK_EQ(avail_event[1], UINT8_C(0x12));
	ATF_CHECK(vq_avail_event_idx(&vq) == UINT16_C(0x1233));
	/*
	 * The independent document formula must suppress every legal advance
	 * of this eight-entry ring, not merely the first seven entries.
	 */
	for (uint16_t advance = 1; advance <= vq.vq_qsize; advance++) {
		ATF_CHECK(!vring_need_event(vq_avail_event_idx(&vq),
		    (uint16_t)(vq.vq_last_avail + advance),
		    vq.vq_last_avail));
	}

	vs.vs_negotiated_caps = 0;
	vq_kick_disable(&vq);
	ATF_CHECK(le16toh(used->flags) == VRING_USED_F_NO_NOTIFY);
	vq_kick_enable(&vq);
	ATF_CHECK(le16toh(used->flags) == 0);
}

ATF_TC_WITHOUT_HEAD(msix_no_vector_suppressed);
ATF_TC_BODY(msix_no_vector_suppressed, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	vs.vs_pi = &pi;
	ATF_REQUIRE(pthread_mutex_init(&vs.vs_isr_mtx, NULL) == 0);
	g_interrupts = 0;
	g_msix_enabled = true;

	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	vi_interrupt(&vs, VIRTIO_PCI_ISR_INTR, VIRTIO_MSI_NO_VECTOR);
	ATF_CHECK(g_interrupts == 0);
	ATF_CHECK(vs.vs_isr == 0);
	vi_interrupt(&vs, VIRTIO_PCI_ISR_INTR, 0);
	ATF_CHECK(g_interrupts == 1);
	ATF_CHECK(vs.vs_isr == 0);

	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vi_interrupt(&vs, VIRTIO_PCI_ISR_CONFIG, VIRTIO_MSI_NO_VECTOR);
	ATF_CHECK(g_interrupts == 1);
	ATF_CHECK(vs.vs_isr == VIRTIO_PCI_ISR_CONFIG);
	ATF_CHECK(vi_isr_read(&vs) == VIRTIO_PCI_ISR_CONFIG);
	vi_interrupt(&vs, VIRTIO_PCI_ISR_CONFIG, 1);
	ATF_CHECK(g_interrupts == 2);
	ATF_CHECK(vs.vs_isr == VIRTIO_PCI_ISR_CONFIG);
	ATF_CHECK(vi_isr_read(&vs) == VIRTIO_PCI_ISR_CONFIG);
	g_msix_enabled = false;
	ATF_REQUIRE(pthread_mutex_destroy(&vs.vs_isr_mtx) == 0);
}

ATF_TC_WITHOUT_HEAD(little_endian_device_config_reads);
ATF_TC_BODY(little_endian_device_config_reads, tc)
{
	static const uint8_t bytes[] = {
		0x11, 0x22, 0x33, 0x44, 0x55,
	};
	uint32_t value;

	ATF_REQUIRE_EQ(vi_config_read_le(bytes, sizeof(bytes), 0, 1,
	    &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x11));
	ATF_REQUIRE_EQ(vi_config_read_le(bytes, sizeof(bytes), 1, 2,
	    &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x3322));
	ATF_REQUIRE_EQ(vi_config_read_le(bytes, sizeof(bytes), 1, 4,
	    &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0x55443322));
	ATF_CHECK_EQ(vi_config_read_le(bytes, sizeof(bytes), -1, 1,
	    &value), EINVAL);
	ATF_CHECK_EQ(vi_config_read_le(bytes, sizeof(bytes), 4, 2,
	    &value), EINVAL);
	ATF_CHECK_EQ(vi_config_read_le(bytes, sizeof(bytes), 0, 3,
	    &value), EINVAL);
	ATF_CHECK_EQ(vi_config_read_le(NULL, sizeof(bytes), 0, 1,
	    &value), EINVAL);
	ATF_CHECK_EQ(vi_config_read_le(bytes, sizeof(bytes), 0, 1,
	    NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(admin_queue_namespace_staging);
ATF_TC_BODY(admin_queue_namespace_staging, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc;
	struct pci_devinst pi;
	struct vqueue_info ordinary[2], admin[2], dirty[1];

	memset(&vs, 0, sizeof(vs));
	memset(&vc, 0, sizeof(vc));
	memset(&pi, 0, sizeof(pi));
	memset(ordinary, 0, sizeof(ordinary));
	memset(admin, 0, sizeof(admin));
	memset(dirty, 0, sizeof(dirty));
	vc.vc_name = "admin-stage";
	vc.vc_nvq = 2;
	vi_softc_linkup(&vs, &vc, &vs, &pi, ordinary);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;

	ATF_CHECK_EQ(vi_pci_stage_admin_queues(NULL, admin, 5, 2), EINVAL);
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, NULL, 5, 2), EINVAL);
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, admin, 1, 2), EINVAL);
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, admin, UINT16_MAX, 2),
	    EINVAL);
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, &ordinary[1], 2, 1),
	    EINVAL);
	dirty[0].vq_enabled = 1;
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, dirty, 5, 1), EBUSY);
	ATF_CHECK_EQ(vs.vs_admin_queues, NULL);
	ATF_CHECK_EQ(admin[0].vq_vs, NULL);

	ATF_REQUIRE_EQ(vi_pci_stage_admin_queues(&vs, admin, 5, 2), 0);
	ATF_CHECK_EQ(vs.vs_admin_queue_index, 5);
	ATF_CHECK_EQ(vs.vs_admin_queue_count, 2);
	ATF_CHECK_EQ(admin[0].vq_vs, &vs);
	ATF_CHECK_EQ(admin[0].vq_num, 5);
	ATF_CHECK_EQ(admin[1].vq_num, 6);
	ATF_CHECK(vi_pci_queue_is_admin(&vs, &admin[0]));
	ATF_CHECK(vi_pci_queue_is_admin(&vs, &admin[1]));
	ATF_CHECK(!vi_pci_queue_is_admin(&vs, &ordinary[1]));
	ATF_CHECK_EQ(vi_pci_queue_storage_count(&vs), 4);
	ATF_CHECK_EQ(vi_pci_queue_at(&vs, 0), &ordinary[0]);
	ATF_CHECK_EQ(vi_pci_queue_at(&vs, 1), &ordinary[1]);
	ATF_CHECK_EQ(vi_pci_queue_at(&vs, 2), &admin[0]);
	ATF_CHECK_EQ(vi_pci_queue_at(&vs, 3), &admin[1]);
	ATF_CHECK_EQ(vi_pci_queue_at(&vs, 4), NULL);

	/* Staged queues remain unreachable until the feature is negotiated. */
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 0), &ordinary[0]);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 5), NULL);
	vs.vs_negotiated_caps |= VIRTIO14_F_ADMIN_VQ;
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 0), &ordinary[0]);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 2), NULL);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 4), NULL);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 5), &admin[0]);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 6), &admin[1]);
	ATF_CHECK_EQ(vi_pci_queue_lookup(&vs, 7), NULL);
	ATF_CHECK_EQ(vi_pci_stage_admin_queues(&vs, dirty, 8, 1), EBUSY);

	/* Device reset visits storage, not the sparse selector namespace. */
	ordinary[0].vq_generation = 10;
	admin[0].vq_generation = 20;
	admin[1].vq_notify_pending = true;
	vi_reset_dev(&vs);
	ATF_CHECK_EQ(ordinary[0].vq_generation, 11);
	ATF_CHECK_EQ(admin[0].vq_generation, 21);
	ATF_CHECK(!admin[1].vq_notify_pending);

	/* MSI-X topology includes stored admin queues, never selector holes. */
	g_msix_cap_count = 0;
	ATF_REQUIRE_EQ(vi_intr_init(&vs, 1, 1), 0);
	ATF_CHECK_EQ(g_msix_cap_count, 5);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&vs.vs_isr_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(state_range_validation);
ATF_TC_BODY(state_range_validation, tc)
{
	uint8_t storage[16];
	const void *wrapping;

	ATF_CHECK(!virtio_state_ranges_overlap(storage, 4, storage + 4, 4));
	ATF_CHECK(virtio_state_ranges_overlap(storage, 5, storage + 4, 4));
	ATF_CHECK(virtio_state_ranges_overlap(storage, sizeof(storage),
	    storage, sizeof(storage)));
	ATF_CHECK(!virtio_state_ranges_overlap(NULL, 0, storage, 1));
	ATF_CHECK(!virtio_state_ranges_overlap(storage, 1, NULL, 0));
	ATF_CHECK(virtio_state_ranges_overlap(NULL, 1, storage, 1));
	ATF_CHECK(virtio_state_ranges_overlap(storage, 1, NULL, 1));
	wrapping = (const void *)(UINTPTR_MAX - 1);
	ATF_CHECK(virtio_state_ranges_overlap(wrapping, 3, storage, 1));
}

/*
 * vi_pci_get_softc is the transport-boundary accessor used to recover the
 * softc from a bare pci_devinst.  VirtIO 1.4 has no register for this; it is a
 * bhyve invariant that the pointer chain and the registered bar-write callback
 * must both match before the softc is trusted.
 */
ATF_TC_WITHOUT_HEAD(pci_softc_accessor_identity);
ATF_TC_BODY(pci_softc_accessor_identity, tc)
{
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct pci_devemu de_ok;
	struct pci_devemu de_other;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&de_ok, 0, sizeof(de_ok));
	memset(&de_other, 0, sizeof(de_other));
	de_ok.pe_barwrite = vi_pci_write;
	de_other.pe_barwrite = NULL;

	/* NULL device instance. */
	ATF_CHECK(vi_pci_get_softc(NULL) == NULL);
	/* No emulation descriptor. */
	pi.pi_d = NULL;
	ATF_CHECK(vi_pci_get_softc(&pi) == NULL);
	/* Emulation descriptor without the virtio bar-write callback. */
	pi.pi_d = &de_other;
	pi.pi_arg = &vs;
	ATF_CHECK(vi_pci_get_softc(&pi) == NULL);
	/* Correct callback but no back-pointer. */
	pi.pi_d = &de_ok;
	pi.pi_arg = NULL;
	ATF_CHECK(vi_pci_get_softc(&pi) == NULL);
	/* Correct callback, softc present, but softc does not point back. */
	pi.pi_arg = &vs;
	vs.vs_pi = NULL;
	ATF_CHECK(vi_pci_get_softc(&pi) == NULL);
	/* Fully consistent chain. */
	vs.vs_pi = &pi;
	ATF_CHECK(vi_pci_get_softc(&pi) == &vs);
}

/*
 * vi_set_io_bar sizes the legacy I/O BAR as VIRTIO_PCI_CONFIG_OFF(1) plus the
 * device configuration length, and vi_intr_init lays down the MSI-X capability
 * with one vector per stored queue plus the configuration vector.
 */
ATF_TC_WITHOUT_HEAD(io_bar_and_msix_interrupt_init);
ATF_TC_BODY(io_bar_and_msix_interrupt_init, tc)
{
	struct virtio_consts vc = {
		.vc_name = "intr-init-test",
		.vc_nvq = 3,
		.vc_cfgsize = 16,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq[3];

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, vq);

	/* Synchronous-device lifecycle no-op accepts any softc and succeeds. */
	ATF_CHECK_EQ(vi_pci_lifecycle_noop(&vs), 0);

	vi_set_io_bar(&vs, 0);

	/* MSI-X path: one vector per queue plus the configuration vector. */
	g_msixcap_error = 0;
	g_msix_cap_count = 0;
	ATF_REQUIRE_EQ(vi_intr_init(&vs, 0, 1), 0);
	ATF_CHECK((vs.vs_flags & VIRTIO_USE_MSIX) != 0);
	ATF_CHECK_EQ(g_msix_cap_count, (int)vc.vc_nvq + 1);
	pthread_mutex_destroy(&vs.vs_isr_mtx);

	/* MSI-X capability allocation failure unwinds and reports an error. */
	g_msixcap_error = 1;
	ATF_CHECK_EQ(vi_intr_init(&vs, 0, 1), 1);
	g_msixcap_error = 0;
}

/*
 * Exercise every legacy transport register in vi_pci_read/vi_pci_write.  The
 * legacy register map and semantics are defined in the VirtIO 0.9.5 / 1.x
 * transitional layout; offsets are asserted through the transitional macros.
 */
ATF_TC_WITHOUT_HEAD(legacy_transport_registers);
ATF_TC_BODY(legacy_transport_registers, tc)
{
	struct virtio_consts vc = {
		.vc_name = "legacy-regs-test",
		.vc_nvq = 1,
		.vc_cfgsize = 8,
		.vc_hv_caps = 0xf00d,
		.vc_reset = reset_status,
		.vc_apply_features = test_apply_features,
		.vc_qnotify = notify_and_interrupt,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	pi.pi_msix.table_count = 4;
	vq.vq_qsize = 8;
	vq.vq_pfn = 0x55;
	vq.vq_msix_idx = 2;
	/*
	 * With MSI-X active the device-configuration window starts after the
	 * MSI-X vector registers, so offsets 20/22 address the vector registers
	 * rather than device configuration.
	 */
	g_msix_enabled = true;
	g_apply_features = 0;
	g_apply_features_error = 0;

	/* Read every transport register. */
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_HOST_FEATURES, 4), 0xf00d);
	vs.vs_negotiated_caps = 0xbeef;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4), 0xbeef);
	vs.vs_curq = 0;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_PFN, 4), 0x55);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_NUM, 2), 8);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_SEL, 2), 0);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_NOTIFY, 2), 0);
	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_STATUS, 1),
	    VIRTIO_CONFIG_STATUS_ACK);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_ISR, 1), 0);
	vs.vs_msix_cfg_idx = 3;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2), 3);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2), 2);

	/*
	 * Selecting an out-of-range queue leaves QUEUE_PFN at the all-ones
	 * default read value, while QUEUE_NUM and the queue vector report their
	 * documented defaults.
	 */
	vs.vs_curq = 5;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_PFN, 4), UINT32_MAX);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_QUEUE_NUM, 2), 0);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2),
	    VIRTIO_MSI_NO_VECTOR);
	vs.vs_curq = 0;

	/* Bad size on a known register, and an unknown offset. */
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_HOST_FEATURES, 2),
	    UINT16_MAX);
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, VIRTIO_PCI_ISR + 1, 1), UINT8_MAX);

	/* Writes: feature selection is masked by the offered capabilities. */
	vi_pci_write(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4, 0xffff);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, 0xf00d);
	/* Once DRIVER_OK is latched, a feature rewrite is ignored. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_write(&pi, 0, VIRTIO_PCI_GUEST_FEATURES, 4, 0);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, 0xf00d);
	vs.vs_status = 0;

	/* Queue selection then PFN initialization. */
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_SEL, 2, 0);
	ATF_CHECK_EQ(vs.vs_curq, 0);
	/* PFN write while DRIVER_OK is latched must not reinitialize the ring. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_PFN, 4, 0x1000);
	vs.vs_status = 0;
	/* PFN write against an invalid queue index is rejected. */
	vs.vs_curq = 9;
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_PFN, 4, 0x1000);
	vs.vs_curq = 0;

	/* QueueNotify with a missing callback pair simply warns. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_write(&pi, 0, VIRTIO_PCI_QUEUE_NOTIFY, 2, 0);
	vs.vs_status = 0;

	/* MSI-X vector registers: valid, no-vector, and out-of-range. */
	vi_pci_write(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2, 1);
	ATF_CHECK_EQ(vs.vs_msix_cfg_idx, 1);
	vi_pci_write(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2, VIRTIO_MSI_NO_VECTOR);
	ATF_CHECK_EQ(vs.vs_msix_cfg_idx, VIRTIO_MSI_NO_VECTOR);
	vi_pci_write(&pi, 0, VIRTIO_MSI_CONFIG_VECTOR, 2, 99);
	ATF_CHECK_EQ(vs.vs_msix_cfg_idx, VIRTIO_MSI_NO_VECTOR);
	vi_pci_write(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2, 1);
	ATF_CHECK_EQ(vq.vq_msix_idx, 1);
	vi_pci_write(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2, 99);
	ATF_CHECK_EQ(vq.vq_msix_idx, VIRTIO_MSI_NO_VECTOR);
	/* QueueVector against an invalid queue index is rejected. */
	vs.vs_curq = 9;
	vi_pci_write(&pi, 0, VIRTIO_MSI_QUEUE_VECTOR, 2, 0);
	vs.vs_curq = 0;

	/* Read-only register write and bad-size write are both rejected. */
	vi_pci_write(&pi, 0, VIRTIO_PCI_HOST_FEATURES, 4, 0x1234);
	ATF_CHECK_EQ(vs.vs_negotiated_caps, 0xf00d);
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 2, 0);

	/* Status write reaching DRIVER_OK applies features successfully. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER;
	g_apply_features = 0;
	g_apply_features_error = 0;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(g_apply_features, 1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);

	/* A failing apply_features refuses to go live and demands a reset. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER;
	g_apply_features = 0;
	g_apply_features_error = -1;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1,
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	g_apply_features_error = 0;

	/* A status-zero write drives a full device reset. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vi_pci_write(&pi, 0, VIRTIO_PCI_STATUS, 1, 0);
	ATF_CHECK_EQ(vs.vs_status, 0);

	/*
	 * MSI-X BAR accesses are forwarded to the MSI-X emulation.  The mock
	 * table/PBA bar index is -1, so drive the access there.
	 */
	vs.vs_flags |= VIRTIO_USE_MSIX;
	ATF_CHECK_EQ(vi_pci_read(&pi, -1, 0, 4), 0);
	vi_pci_write(&pi, -1, 0, 4, 0);
	vs.vs_flags &= ~VIRTIO_USE_MSIX;

	/* A non-zero BAR index on the legacy path is inert. */
	ATF_CHECK_EQ(vi_pci_read(&pi, 1, 0, 4), UINT32_MAX);
	vi_pci_write(&pi, 1, 0, 4, 0);
}

/*
 * The modern transport register windows are implemented in a separate
 * translation unit; verify that vi_pci_read/write dispatch there when the
 * device is modern.
 */
ATF_TC_WITHOUT_HEAD(modern_transport_dispatch);
ATF_TC_BODY(modern_transport_dispatch, tc)
{
	struct virtio_consts vc = {
		.vc_name = "modern-dispatch-test",
		.vc_nvq = 1,
		.vc_cfgsize = 8,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	ATF_CHECK_EQ(vi_pci_read(&pi, 0, 0, 4), 0);
	vi_pci_write(&pi, 0, 0, 4, 0);
}

/*
 * vi_pci_notify_queue rejects an out-of-range queue, respects the
 * modern enable/reset gate and the DRIVER_OK gate, and warns when no notify
 * callback is registered.
 */
ATF_TC_WITHOUT_HEAD(notify_queue_edge_cases);
ATF_TC_BODY(notify_queue_edge_cases, tc)
{
	struct virtio_consts vc = {
		.vc_name = "notify-edge-test",
		.vc_nvq = 1,
		.vc_cfgsize = 8,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);

	/* Out-of-range queue index. */
	vi_pci_notify_queue(&vs, 99);
	vi_pci_notify_queue(&vs, (uint64_t)UINT32_MAX + 1);

	/* Modern device: a disabled queue swallows the notify. */
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vq.vq_enabled = false;
	vi_pci_notify_queue(&vs, 0);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;

	/* Before DRIVER_OK a legacy notify is latched, not delivered. */
	vs.vs_status = 0;
	vq.vq_notify_pending = false;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK(vq.vq_notify_pending);

	/* DRIVER_OK but neither vq nor vc notify callback registered. */
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vq.vq_notify = NULL;
	vc.vc_qnotify = NULL;
	vi_pci_notify_queue(&vs, 0);
	ATF_CHECK(!vq.vq_notify_pending);
}

/*
 * vq_discard_req and vq_relchain_req must fault the device when a request is
 * returned that was never outstanding or whose ownership token cannot be
 * consumed.
 */
ATF_TC_WITHOUT_HEAD(relchain_discard_ownership_faults);
ATF_TC_BODY(relchain_discard_ownership_faults, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req;

	/* discard: request not outstanding faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	memset(&req, 0, sizeof(req));
	req.outstanding = false;
	vq_discard_req(&vq, &req);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* discard: outstanding token that cannot be consumed faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	memset(&req, 0, sizeof(req));
	req.outstanding = true;
	req.queue_layout = VIRTIO_QUEUE_SPLIT;
	req.idx = 3;
	/* No matching owner was ever claimed, so consume fails. */
	vq_discard_req(&vq, &req);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!req.outstanding);

	/* relchain: request not outstanding faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	memset(&req, 0, sizeof(req));
	req.outstanding = false;
	vq_relchain_req(&vq, &req, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* relchain: outstanding token that cannot be consumed faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	memset(&req, 0, sizeof(req));
	req.outstanding = true;
	req.queue_layout = VIRTIO_QUEUE_SPLIT;
	req.idx = 4;
	vq_relchain_req(&vq, &req, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK(!req.outstanding);
}

/*
 * vq_relchain_group over a split ring publishes one used index after writing
 * every element (VirtIO 1.4 section 2.7.8), and it rejects an oversized or
 * empty group.
 */
ATF_TC_WITHOUT_HEAD(split_group_completion_publishes_once);
ATF_TC_BODY(split_group_completion_publishes_once, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req reqs[2];
	struct iovec iov;
	uint32_t lengths[2];
	uint8_t payload[16];

	/* Empty group is a no-op. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vq_relchain_group(&vq, reqs, lengths, 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);

	/* Two independent split requests completed as one group. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	((struct vring_avail *)avail_mem.bytes)->idx = 2;
	((struct vring_avail *)avail_mem.bytes)->ring[0] = 0;
	((struct vring_avail *)avail_mem.bytes)->ring[1] = 1;
	desc[0].addr = 0x1000;
	desc[0].len = 8;
	desc[0].flags = VRING_DESC_F_WRITE;
	desc[1].addr = 0x1008;
	desc[1].len = 8;
	desc[1].flags = VRING_DESC_F_WRITE;
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &reqs[0]), 1);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &reqs[1]), 1);
	lengths[0] = 4;
	lengths[1] = 8;
	vq_relchain_group(&vq, reqs, lengths, 2);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	ATF_CHECK_EQ(vq.vq_used->idx, 2);

	/* An oversized group (nreqs > qsize) faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vq.vq_qsize = 1;
	memset(reqs, 0, sizeof(reqs));
	reqs[0].outstanding = true;
	reqs[1].outstanding = true;
	vq_relchain_group(&vq, reqs, lengths, 2);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

/*
 * vq_kick_enable / vq_kick_disable on a packed ring must update the device
 * event suppression structure per VirtIO 1.4 section 2.8.10, honouring
 * EVENT_IDX, and must fault when the event area is missing.
 */
ATF_TC_WITHOUT_HEAD(packed_kick_suppression_paths);
ATF_TC_BODY(packed_kick_suppression_paths, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_packed_desc packed_desc[2];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;

	(void)avail_mem;
	(void)used_mem;

	/* Packed enable/disable without EVENT_IDX toggles the ENABLE/DISABLE flag. */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	vs.vs_negotiated_caps = 0;
	vq_kick_enable(&vq);
	ATF_CHECK_EQ(le16toh(device_event.flags), VIRTIO_PACKED_EVENT_F_ENABLE);
	vq_kick_disable(&vq);
	ATF_CHECK_EQ(le16toh(device_event.flags), VIRTIO_PACKED_EVENT_F_DISABLE);
	vq_packed_completions_fini(&vq);

	/* With EVENT_IDX, enable publishes a descriptor-position event. */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	vq.vq_packed_next_avail = 1;
	vq_kick_enable(&vq);
	ATF_CHECK_EQ(le16toh(device_event.flags), VIRTIO_PACKED_EVENT_F_DESC);
	vq_packed_completions_fini(&vq);

	/* A missing device event area faults the device on enable and disable. */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	vq.vq_packed_device_event = NULL;
	vq_kick_enable(&vq);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vs.vs_status = 0;
	vq_kick_disable(&vq);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq.vq_packed_device_event = &device_event;
	vq_packed_completions_fini(&vq);
}

/*
 * vq_packed_completions_init tolerates an idempotent re-init over an empty
 * table, refuses re-init while completions are outstanding (EBUSY), and
 * rejects an out-of-range queue size.
 */
ATF_TC_WITHOUT_HEAD(packed_completions_init_lifecycle);
ATF_TC_BODY(packed_completions_init_lifecycle, tc)
{
	struct vqueue_info vq;

	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = 0;
	ATF_CHECK_EQ(vq_packed_completions_init(&vq), EINVAL);

	vq.vq_qsize = 4;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	/* Idempotent re-init over an empty table succeeds without churn. */
	ATF_CHECK_EQ(vq_packed_completions_init(&vq), 0);

	/* Mark a completion outstanding: re-init must report EBUSY. */
	vq.vq_packed_completions[0].valid = true;
	ATF_CHECK_EQ(vq_packed_completions_init(&vq), EBUSY);
	vq.vq_packed_completions[0].valid = false;

	/*
	 * A resize request over a drained table replaces the allocation
	 * (covers the fini-and-realloc branch).
	 */
	vq.vq_qsize = 8;
	ATF_REQUIRE_EQ(vq_packed_completions_init(&vq), 0);
	ATF_CHECK_EQ(vq.vq_packed_completion_count, 8);
	vq_packed_completions_fini(&vq);
}

/*
 * A fatal ring error observed while the device is mid-reset (odd reset epoch)
 * is remembered as a deferred failure rather than immediately re-asserting
 * NEEDS_RESET, per the reset-epoch handshake.
 */
ATF_TC_WITHOUT_HEAD(needs_reset_during_reset_defers);
ATF_TC_BODY(needs_reset_during_reset_defers, tc)
{
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };

	memset(&vs, 0, sizeof(vs));
	vs.vs_vc = &vc;
	vc.vc_name = "reset-epoch-test";

	/* Odd epoch means a reset is in progress. */
	vs.vs_reset_epoch = 1;
	vs.vs_status = 0;
	vi_set_needs_reset(&vs);
	ATF_CHECK(vs.vs_reset_failed);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);

	/* vs_resetting also defers. */
	vs.vs_reset_epoch = 0;
	vs.vs_reset_failed = false;
	vs.vs_resetting = true;
	vi_set_needs_reset(&vs);
	ATF_CHECK(vs.vs_reset_failed);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
}

/*
 * Drive vi_pci_snapshot() end-to-end over a legacy-transport device for save,
 * validate, and restore, plus the restore-incomplete short circuit and the
 * unknown-operation label path.
 */
ATF_TC_WITHOUT_HEAD(legacy_full_snapshot_roundtrip);
ATF_TC_BODY(legacy_full_snapshot_roundtrip, tc)
{
	_Alignas(VRING_ALIGN) static uint8_t source_ring[8192];
	_Alignas(VRING_ALIGN) static uint8_t destination_ring[8192];
	struct virtio_softc source, destination;
	struct virtio_consts source_vc, destination_vc;
	struct pci_devinst source_pi, destination_pi;
	struct vqueue_info source_vq, destination_vq;
	struct vmctx ctx = { 0 };
	static uint8_t image[65536];
	size_t used;

	memset(&source, 0, sizeof(source));
	memset(&destination, 0, sizeof(destination));
	memset(&source_vc, 0, sizeof(source_vc));
	memset(&destination_vc, 0, sizeof(destination_vc));
	memset(&source_pi, 0, sizeof(source_pi));
	memset(&destination_pi, 0, sizeof(destination_pi));
	memset(&source_vq, 0, sizeof(source_vq));
	memset(&destination_vq, 0, sizeof(destination_vq));
	memset(source_ring, 0x5a, sizeof(source_ring));
	memset(destination_ring, 0xc3, sizeof(destination_ring));

	source_pi.pi_arg = &source;
	source_pi.pi_vmctx = &ctx;
	source.vs_pi = &source_pi;
	source.vs_vc = &source_vc;
	source.vs_queues = &source_vq;
	source.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	source.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	source.vs_status = VIRTIO_CONFIG_STATUS_ACK |
	    VIRTIO_CONFIG_STATUS_DRIVER | VIRTIO_CONFIG_STATUS_DRIVER_OK;
	source.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	source_vc.vc_name = "legacy-snap";
	source_vc.vc_nvq = 1;
	source_vc.vc_cfgsize = 8;
	source_vc.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX;
	source_vq.vq_vs = &source;
	source_vq.vq_qsize = 8;
	source_vq.vq_num = 0;
	source_vq.vq_flags = VQ_ALLOC;
	source_vq.vq_pfn = 0x10;
	source_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	source_vq.vq_desc = (void *)source_ring;
	source_vq.vq_avail = (void *)(source_ring +
	    8 * VIRTIO14_SPLIT_DESC_SIZE);
	source_vq.vq_used = (void *)roundup2(
	    (uintptr_t)source_vq.vq_avail +
	    VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    8 * VIRTIO14_SPLIT_AVAIL_ELEM_SIZE +
	    VIRTIO14_SPLIT_EVENT_FIELD_SIZE, VRING_ALIGN);
	ATF_REQUIRE_EQ(pthread_mutex_init(&source.vs_isr_mtx, NULL), 0);
	g_region_count = 0;
	add_region(UINT64_C(0x10000), source_ring, sizeof(source_ring));

	/* An unknown snapshot op still labels its lifecycle probe and saves. */
	{
		struct vm_snapshot_meta bad_meta = {
			.buffer = {
				.buf_start = image,
				.buf_size = sizeof(image),
				.buf = image,
				.buf_rem = sizeof(image),
			},
			.dev_data = &source_pi,
			.op = (enum vm_snapshot_op)99,
		};
		(void)vi_pci_snapshot(&bad_meta);
	}

	ATF_REQUIRE_EQ(run_full_virtio_snapshot(&source_pi, image,
	    sizeof(image), VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 0);

	destination_pi.pi_arg = &destination;
	destination_pi.pi_vmctx = &ctx;
	destination.vs_pi = &destination_pi;
	destination.vs_vc = &destination_vc;
	destination.vs_queues = &destination_vq;
	destination.vs_transport = VIRTIO_PCI_TRANSPORT_LEGACY;
	destination.vs_msix_cfg_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vc.vc_name = "legacy-snap";
	destination_vc.vc_nvq = 1;
	destination_vc.vc_cfgsize = 8;
	destination_vc.vc_hv_caps = VIRTIO_RING_F_EVENT_IDX;
	destination_vq.vq_vs = &destination;
	destination_vq.vq_qsize = 8;
	destination_vq.vq_num = 0;
	destination_vq.vq_flags = VQ_ALLOC;
	destination_vq.vq_pfn = 0x10;
	destination_vq.vq_msix_idx = VIRTIO_MSI_NO_VECTOR;
	destination_vq.vq_desc = (void *)destination_ring;
	destination_vq.vq_avail = (void *)(destination_ring +
	    8 * VIRTIO14_SPLIT_DESC_SIZE);
	destination_vq.vq_used = (void *)roundup2(
	    (uintptr_t)destination_vq.vq_avail +
	    VIRTIO14_SPLIT_AVAIL_HEADER_SIZE +
	    8 * VIRTIO14_SPLIT_AVAIL_ELEM_SIZE +
	    VIRTIO14_SPLIT_EVENT_FIELD_SIZE, VRING_ALIGN);
	ATF_REQUIRE_EQ(pthread_mutex_init(&destination.vs_isr_mtx, NULL), 0);
	g_region_count = 0;
	add_region(UINT64_C(0x10000), destination_ring, sizeof(destination_ring));

	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vs_negotiated_caps, VIRTIO_RING_F_EVENT_IDX);

	/* A device already marked restore-incomplete refuses further snapshots. */
	destination.vs_restore_incomplete = true;
	ATF_CHECK_EQ(run_full_virtio_snapshot(&destination_pi, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);

	pthread_mutex_destroy(&source.vs_isr_mtx);
	pthread_mutex_destroy(&destination.vs_isr_mtx);
}

static int g_pddo_mark_calls;
static int g_pddo_fail_calls;
static int g_pddo_last_error;

static int
test_pddo_mark(void *arg __unused, uint64_t gpa __unused, size_t len __unused)
{

	g_pddo_mark_calls++;
	return (0);
}

static void
test_pddo_fail(void *arg __unused, int error)
{

	g_pddo_fail_calls++;
	g_pddo_last_error = error;
}

static const struct pci_dma_dirty_ops test_pddo_ops = {
	.pddo_mark = test_pddo_mark,
	.pddo_fail = test_pddo_fail,
};

/*
 * The default bhyve PCI platform operations installed by vi_softc_linkup back
 * the device-facing DMA/RAM contract onto the guest address space.  Exercise
 * each of them through the public wrappers.
 */
ATF_TC_WITHOUT_HEAD(default_pci_platform_ops);
ATF_TC_BODY(default_pci_platform_ops, tc)
{
	struct virtio_consts vc = {
		.vc_name = "pci-ops-test",
		.vc_nvq = 1,
		.vc_cfgsize = 8,
	};
	struct virtio_softc vs;
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vmctx ctx = { 0 };
	size_t page;
	void *buf;
	uint64_t address;
	int error;

	memset(&vs, 0, sizeof(vs));
	memset(&pi, 0, sizeof(pi));
	memset(&vq, 0, sizeof(vq));
	vi_softc_linkup(&vs, &vc, &vs, &pi, &vq);
	pi.pi_vmctx = &ctx;

	page = (size_t)getpagesize();
	ATF_REQUIRE_EQ(posix_memalign(&buf, page, page), 0);
	g_region_count = 0;
	add_region(UINT64_C(0x10000), buf, page);

	/* Page size query reflects the host page size. */
	ATF_CHECK_EQ(vi_platform_ram_page_size(&vs), page);

	/*
	 * A device-write mapping resolves through the guest address space and
	 * then attempts to mark the range dirty.  With no dirty-tracking ops
	 * registered, the mark is a silent no-op.
	 */
	ATF_CHECK(vi_map_dma(&vs, UINT64_C(0x10000), 64,
	    VIRTIO_DMA_DEVICE_WRITE) == buf);
	/* An unmapped address returns NULL. */
	ATF_CHECK(vi_map_dma(&vs, UINT64_C(0x99990000), 64,
	    VIRTIO_DMA_DEVICE_READ) == NULL);

	/*
	 * With dirty-tracking ops present, a failed reverse translation is
	 * reported through the failure callback.  The reverse-map mock never
	 * resolves, so this exercises the failure path.
	 */
	pi.pi_dma_dirty_ops = &test_pddo_ops;
	pi.pi_dma_dirty_arg = &pi;
	g_pddo_mark_calls = 0;
	g_pddo_fail_calls = 0;
	vi_mark_dma_dirty(&vs, buf, 64);
	ATF_CHECK_EQ(g_pddo_mark_calls, 0);
	ATF_CHECK_EQ(g_pddo_fail_calls, 1);
	ATF_CHECK_EQ(g_pddo_last_error, EFAULT);
	pi.pi_dma_dirty_ops = NULL;

	/* Reverse translation: NULL argument and unresolved mapping. */
	ATF_CHECK_EQ(vi_platform_reverse_ram(&vs, NULL, 64, &address), EINVAL);
	ATF_CHECK_EQ(vi_platform_reverse_ram(&vs, buf, 64, &address), EFAULT);

	/* Discard and undiscard a page-aligned mapped range. */
	error = vi_platform_discard_ram(&vs, UINT64_C(0x10000), page);
	ATF_CHECK(error == 0 || error == EINVAL);
	error = vi_platform_undiscard_ram(&vs, UINT64_C(0x10000), page);
	ATF_CHECK(error == 0 || error == EINVAL);

	/* A page-aligned but unmapped range faults. */
	ATF_CHECK_EQ(vi_platform_discard_ram(&vs, UINT64_C(0x8000000), page),
	    EFAULT);
	ATF_CHECK_EQ(vi_platform_undiscard_ram(&vs, UINT64_C(0x8000000), page),
	    EFAULT);

	free(buf);
}

/*
 * Malformed and boundary conditions in the packed-ring descriptor parser
 * (VirtIO 1.4 section 2.8.6-2.8.7) must each fault the device and never
 * publish a partial request.
 */
ATF_TC_WITHOUT_HEAD(packed_getchain_error_paths);
ATF_TC_BODY(packed_getchain_error_paths, tc)
{
	uint8_t buffer[64];
	struct virtio_packed_desc desc[4], indirect[3];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov[4];
	struct vi_req req;

	/* A NULL descriptor area faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vq.vq_packed_desc = NULL;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* An out-of-range available cursor faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vq.vq_packed_next_avail = vq.vq_qsize;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A descriptor whose AVAIL bit is not yet set yields no request. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	desc[0].flags = htole16(0);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	vq_packed_completions_fini(&vq);

	/* An indirect table larger than the queue faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32((vq.vq_qsize + 1) * VIRTIO14_PACKED_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* An indirect table pointing outside guest memory faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	desc[0].address = htole64(0xdead0000);
	desc[0].length = htole32(2 * VIRTIO14_PACKED_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* An indirect entry that maps outside guest memory faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x5000, indirect, nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	indirect[0].address = htole64(0xbeef0000);
	indirect[0].length = htole32(8);
	desc[0].address = htole64(0x5000);
	desc[0].length = htole32(VIRTIO14_PACKED_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A valid indirect chain whose head is already outstanding faults. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x4000, buffer, sizeof(buffer));
	add_region(0x5000, indirect, nitems(indirect) * VIRTIO14_PACKED_DESC_SIZE);
	indirect[0].address = htole64(0x4000);
	indirect[0].length = htole32(8);
	desc[0].address = htole64(0x5000);
	desc[0].length = htole32(VIRTIO14_PACKED_DESC_SIZE);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_INDIRECT);
	ATF_REQUIRE(vq_packed_owner_claim(&vq, 0, true));
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A direct descriptor mapping outside guest memory faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	desc[0].address = htole64(0xdead0000);
	desc[0].length = htole32(8);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A valid direct chain whose head is already outstanding faults. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x4000, buffer, sizeof(buffer));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(8);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL);
	ATF_REQUIRE(vq_packed_owner_claim(&vq, 0, true));
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A chain that never terminates walks the whole ring and then faults. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x4000, buffer, sizeof(buffer));
	for (size_t i = 0; i < nitems(desc); i++) {
		desc[i].address = htole64(0x4000);
		desc[i].length = htole32(8);
		desc[i].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
		    VIRTIO14_PACKED_DESC_F_NEXT);
	}
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);
}

/*
 * Split-ring descriptor parser error and boundary paths (VirtIO 1.4 section
 * 2.7.5): empty ring, oversized available count, forbidden and malformed
 * indirect chains, and duplicate outstanding heads.
 */
ATF_TC_WITHOUT_HEAD(split_getchain_error_paths);
ATF_TC_BODY(split_getchain_error_paths, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8], indirect[4];
	struct vi_req req;
	struct iovec iov[4];
	uint8_t payload[32];

	/* No new descriptors: the parser reports an empty ring. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vq.vq_last_avail = 1;	/* equals avail->idx from setup_queue */
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), 0);

	/* An available count larger than the ring faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	((struct vring_avail *)avail_mem.bytes)->idx = 100;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* An INDIRECT flag without the negotiated feature faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = 0;
	desc[0].addr = 0x1000;
	desc[0].len = VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	add_region(0x1000, indirect, nitems(indirect) * VIRTIO14_SPLIT_DESC_SIZE);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* An indirect table entry carrying its own INDIRECT flag faults. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x2000, indirect, nitems(indirect) * VIRTIO14_SPLIT_DESC_SIZE);
	indirect[0].addr = 0x1000;
	indirect[0].len = 8;
	indirect[0].flags = VRING_DESC_F_INDIRECT;
	add_region(0x1000, payload, sizeof(payload));
	desc[0].addr = 0x2000;
	desc[0].len = 2 * VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* An indirect NEXT pointer beyond the table faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x2000, indirect, nitems(indirect) * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x1000, payload, sizeof(payload));
	indirect[0].addr = 0x1000;
	indirect[0].len = 8;
	indirect[0].flags = VRING_DESC_F_NEXT;
	indirect[0].next = 99;
	desc[0].addr = 0x2000;
	desc[0].len = 2 * VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* An indirect chain that loops longer than the queue faults. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC;
	memset(indirect, 0, sizeof(indirect));
	add_region(0x2000, indirect, nitems(indirect) * VIRTIO14_SPLIT_DESC_SIZE);
	add_region(0x1000, payload, sizeof(payload));
	for (size_t i = 0; i < nitems(indirect); i++) {
		indirect[i].addr = 0x1000;
		indirect[i].len = 8;
		indirect[i].flags = VRING_DESC_F_NEXT;
		indirect[i].next = (uint16_t)((i + 1) % nitems(indirect));
	}
	desc[0].addr = 0x2000;
	desc[0].len = nitems(indirect) * VIRTIO14_SPLIT_DESC_SIZE;
	desc[0].flags = VRING_DESC_F_INDIRECT;
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	/* A descriptor head already outstanding faults the device. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	add_region(0x1000, payload, sizeof(payload));
	desc[0].addr = 0x1000;
	desc[0].len = 8;
	desc[0].flags = VRING_DESC_F_WRITE;
	ATF_REQUIRE(vq_split_owner_claim(&vq, 0));
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
}

/*
 * A revocable DMA domain that denies the per-request lease, or whose mapping
 * generation cannot be pinned, must abort chain parsing safely.
 */
ATF_TC_WITHOUT_HEAD(getchain_dma_lease_failures);
ATF_TC_BODY(getchain_dma_lease_failures, tc)
{
	union { max_align_t align; uint8_t bytes[64]; } avail_mem;
	union { max_align_t align; uint8_t bytes[128]; } used_mem;
	struct virtio_packed_desc packed_desc[2];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct vring_desc desc[8];
	struct vi_req req;
	struct iovec iov[2];

	/*
	 * Split ring: a denied lease returns "no request" without a fault.  Each
	 * sub-case installs the domain on a freshly initialized softc, so no
	 * inter-case teardown is required (the queues stay allocated, which the
	 * removal path intentionally treats as busy).
	 */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	g_domain_acquire_allowed = false;
	g_domain_deny = false;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_leased_domain_ops, &pi,
	    0x41), 0);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	g_domain_acquire_allowed = true;

	/* Split ring: a lease that cannot pin a stable mapping faults. */
	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	vq.vq_desc_gpa = 0x1000;
	vq.vq_driver_gpa = 0x2000;
	vq.vq_device_gpa = 0x3000;
	g_domain_acquire_allowed = true;
	g_domain_deny = true;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_leased_domain_ops, &pi,
	    0x42), 0);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), -1);
	g_domain_deny = false;

	/* Packed ring: a denied lease returns "no request" without a fault. */
	setup_packed_queue(&vs, &vc, &pi, &vq, packed_desc, &driver_event,
	    &device_event, nitems(packed_desc));
	vs.vs_status = 0;
	g_domain_acquire_allowed = false;
	g_domain_deny = false;
	ATF_REQUIRE_EQ(vi_set_dma_domain(&vs, &test_leased_domain_ops, &pi,
	    0x43), 0);
	ATF_CHECK_EQ(vq_getchain(&vq, iov, nitems(iov), &req), 0);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	g_domain_acquire_allowed = true;
	vq_packed_completions_fini(&vq);
}

/*
 * vq_relchain_req on a packed ring rejects a structurally invalid request and
 * a duplicate completion at an already-staged head, faulting the device in
 * both cases rather than publishing corrupt ownership.
 */
ATF_TC_WITHOUT_HEAD(packed_relchain_req_validation);
ATF_TC_BODY(packed_relchain_req_validation, tc)
{
	uint8_t buffer[64];
	struct virtio_packed_desc desc[4];
	struct virtio_packed_event driver_event, device_event;
	struct virtio_softc vs;
	struct virtio_consts vc = { 0 };
	struct pci_devinst pi;
	struct vqueue_info vq;
	struct iovec iov;
	struct vi_req req;

	/* A structurally invalid (zero-length) request faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x4000, buffer, sizeof(buffer));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(8);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_WRITE);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	req.descriptor_count = 0;
	vq_relchain_req(&vq, &req, 8);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);

	/* A duplicate completion at an already-staged head faults the device. */
	setup_packed_queue(&vs, &vc, &pi, &vq, desc, &driver_event,
	    &device_event, nitems(desc));
	add_region(0x4000, buffer, sizeof(buffer));
	desc[0].address = htole64(0x4000);
	desc[0].length = htole32(8);
	desc[0].flags = htole16(VIRTIO14_PACKED_DESC_F_AVAIL |
	    VIRTIO14_PACKED_DESC_F_WRITE);
	ATF_REQUIRE_EQ(vq_getchain(&vq, &iov, 1, &req), 1);
	/* Pre-stage a completion at the request head to force the conflict. */
	vq.vq_packed_completions[req.packed_head].valid = true;
	vq_relchain_req(&vq, &req, 8);
	ATF_CHECK((vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vq_packed_completions_fini(&vq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, state_range_validation);
	ATF_TP_ADD_TC(tp, direct_mapping_validation);
	ATF_TP_ADD_TC(tp, used_length_bounded_by_writable_capacity);
	ATF_TP_ADD_TC(tp, indirect_mapping_validation);
	ATF_TP_ADD_TC(tp, zero_length_descriptor_mapping);
	ATF_TP_ADD_TC(tp, linux_control_indirect_chain);
	ATF_TP_ADD_TC(tp, linux_rss_production_callback);
	ATF_TP_ADD_TC(tp, descriptor_chain_byte_limit);
	ATF_TP_ADD_TC(tp, fatal_ring_error_blocks_later_kicks);
	ATF_TP_ADD_TC(tp, fatal_ring_error_stops_current_batch);
	ATF_TP_ADD_TC(tp, chain_can_use_full_queue);
	ATF_TP_ADD_TC(tp, legacy_queue_mapping_validation);
	ATF_TP_ADD_TC(tp, packed_direct_wrap_and_completion);
	ATF_TP_ADD_TC(tp, packed_event_rollback_and_stale_completion);
	ATF_TP_ADD_TC(tp, packed_out_of_order_return_needs_reset);
	ATF_TP_ADD_TC(tp, split_out_of_order_return_needs_reset);
	ATF_TP_ADD_TC(tp, completion_layout_mismatch_needs_reset);
	ATF_TP_ADD_TC(tp, packed_zero_length_completion_clears_write);
	ATF_TP_ADD_TC(tp, packed_event_threshold_wrap);
	ATF_TP_ADD_TC(tp, packed_async_completions_publish_in_request_order);
	ATF_TP_ADD_TC(tp, packed_group_completion);
	ATF_TP_ADD_TC(tp, packed_malformed_staged_group_needs_reset);
	ATF_TP_ADD_TC(tp, packed_malformed_chains_need_reset);
	ATF_TP_ADD_TC(tp, packed_indirect_sequential_table);
	ATF_TP_ADD_TC(tp, access_platform_domain_contract);
	ATF_TP_ADD_TC(tp, dma_dirty_marks_cached_queue_writes);
	ATF_TP_ADD_TC(tp, access_platform_detach_acquire_race);
	ATF_TP_ADD_TC(tp, access_platform_domain_lifecycle_mutex);
	ATF_TP_ADD_TC(tp, access_platform_request_dma_lifetime);
	ATF_TP_ADD_TC(tp, access_platform_ring_mapping_revalidation);
	ATF_TP_ADD_TC(tp, split_group_duplicate_retires_distinct_owners);
	ATF_TP_ADD_TC(tp, oversized_group_retires_all_owners);
	ATF_TP_ADD_TC(tp, access_platform_packed_ring_revalidation);
	ATF_TP_ADD_TC(tp, platform_ram_discard_contract);
	ATF_TP_ADD_TC(tp, snapshot_queue_mapping_contract);
	ATF_TP_ADD_TC(tp, admin_controller_snapshot_section_is_transactional);
	ATF_TP_ADD_TC(tp, admin_restore_rolls_back_after_device_failure);
	ATF_TP_ADD_TC(tp, snapshot_restore_retains_guest_suspend_ownership);
	ATF_TP_ADD_TC(tp, snapshot_restore_releases_guest_suspend_ownership);
	ATF_TP_ADD_TC(tp, legacy_snapshot_feature_preflight);
	ATF_TP_ADD_TC(tp,
	    legacy_snapshot_save_rejects_wide_features_atomically);
	ATF_TP_ADD_TC(tp, modern_snapshot_rejects_unoffered_negotiation);
	ATF_TP_ADD_TC(tp, legacy_snapshot_advances_destination_generation);
	ATF_TP_ADD_TC(tp,
	    legacy_snapshot_validate_does_not_write_guest_ring);
	ATF_TP_ADD_TC(tp, modern_snapshot_rejects_disabled_pending_notify);
	ATF_TP_ADD_TC(tp, modern_snapshot_rejects_unreachable_status_prefix);
	ATF_TP_ADD_TC(tp, modern_snapshot_has_little_endian_golden_encoding);
	ATF_TP_ADD_TC(tp, snapshot_compat_includes_admin_queue_shape);
	ATF_TP_ADD_TC(tp, snapshot_compat_includes_shared_memory_shape);
	ATF_TP_ADD_TC(tp, modern_snapshot_includes_admin_queue_bank);
	ATF_TP_ADD_TC(tp, packed_snapshot_cache_resize_transaction);
	ATF_TP_ADD_TC(tp, modern_snapshot_split_restore_retires_packed_cache);
	ATF_TP_ADD_TC(tp, event_idx_interrupts);
	ATF_TP_ADD_TC(tp, event_idx_kick_suppression);
	ATF_TP_ADD_TC(tp, msix_no_vector_suppressed);
	ATF_TP_ADD_TC(tp, little_endian_device_config_reads);
	ATF_TP_ADD_TC(tp, admin_queue_namespace_staging);
	ATF_TP_ADD_TC(tp, legacy_live_configuration_is_frozen);
	ATF_TP_ADD_TC(tp, legacy_quiesce_fences_transport_access);
	ATF_TP_ADD_TC(tp, legacy_config_offset_overflow);
	ATF_TP_ADD_TC(tp, legacy_zero_length_device_config);
	ATF_TP_ADD_TC(tp, legacy_rejected_config_is_not_msix);
	ATF_TP_ADD_TC(tp, legacy_msix_vector_validation);
	ATF_TP_ADD_TC(tp, legacy_non_io_bar_is_ignored);
	ATF_TP_ADD_TC(tp, legacy_status_preserves_needs_reset);
	ATF_TP_ADD_TC(tp, notify_without_msix_does_not_relock_device);
	ATF_TP_ADD_TC(tp, lifecycle_fence_replays_queue_notify);
	ATF_TP_ADD_TC(tp, failed_checkpoint_pause_replays_queue_notify);
	ATF_TP_ADD_TC(tp, missing_checkpoint_callbacks_fail_closed);
	ATF_TP_ADD_TC(tp, failed_checkpoint_resume_stays_fenced_until_retry);
	ATF_TP_ADD_TC(tp, checkpoint_resume_replays_deferred_config_once);
	ATF_TP_ADD_TC(tp, checkpoint_resume_preserves_guest_suspend_fence);
	ATF_TP_ADD_TC(tp, admin_quiesce_failure_aborts_checkpoint);
	ATF_TP_ADD_TC(tp, admin_pause_rollback_failure_needs_reset);
	ATF_TP_ADD_TC(tp, isr_read_serializes_intx);
	ATF_TP_ADD_TC(tp, pci_softc_accessor_identity);
	ATF_TP_ADD_TC(tp, io_bar_and_msix_interrupt_init);
	ATF_TP_ADD_TC(tp, legacy_transport_registers);
	ATF_TP_ADD_TC(tp, modern_transport_dispatch);
	ATF_TP_ADD_TC(tp, notify_queue_edge_cases);
	ATF_TP_ADD_TC(tp, relchain_discard_ownership_faults);
	ATF_TP_ADD_TC(tp, split_group_completion_publishes_once);
	ATF_TP_ADD_TC(tp, packed_kick_suppression_paths);
	ATF_TP_ADD_TC(tp, packed_completions_init_lifecycle);
	ATF_TP_ADD_TC(tp, needs_reset_during_reset_defers);
	ATF_TP_ADD_TC(tp, legacy_full_snapshot_roundtrip);
	ATF_TP_ADD_TC(tp, default_pci_platform_ops);
	ATF_TP_ADD_TC(tp, packed_getchain_error_paths);
	ATF_TP_ADD_TC(tp, split_getchain_error_paths);
	ATF_TP_ADD_TC(tp, getchain_dma_lease_failures);
	ATF_TP_ADD_TC(tp, packed_relchain_req_validation);
	return (atf_no_error());
}
