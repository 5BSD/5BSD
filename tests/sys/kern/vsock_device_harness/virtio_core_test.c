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

#include "pci_emul.h"
#include <bhyve/virtio.h>
#define	MOCK_VIRTIO_H
#include "virtio.c"
#include "pci_virtio_net.c"
#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

/* The real core is compiled above; test-side wire values are the 1.4 oracle. */
#undef VIRTIO_CONFIG_STATUS_ACK
#define	VIRTIO_CONFIG_STATUS_ACK	VIRTIO14_STATUS_ACKNOWLEDGE
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET
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

struct vmctx { int unused; };

struct guest_region {
	uint64_t gpa;
	size_t len;
	void *host;
};

static struct guest_region g_regions[8];
static int g_region_count;
static int g_interrupts;
static int g_notifications;
static int g_cfg_reads;
static int g_cfg_writes;
static int g_cfg_error;
static int g_apply_features;
static int g_apply_features_error;
static uint64_t g_applied_features;
static bool g_msix_enabled;
static bool g_lintr_asserted;
static bool g_hold_deassert;
static bool g_deassert_entered;
static bool g_reset_reports_failure;
static uint8_t g_reset_observed_status;
static pthread_mutex_t g_intr_test_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_intr_test_cv = PTHREAD_COND_INITIALIZER;

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
int pci_emul_add_msixcap(struct pci_devinst *pi __unused, int count __unused,
    int bar __unused) { return (0); }
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
void pci_emul_msix_twrite(struct pci_devinst *pi __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
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
	vi_pci_write(&pi, 0, config, 4, 0xa5a5a5a5);
	ATF_CHECK(g_cfg_reads == 1);
	ATF_CHECK(g_cfg_writes == 1);

	ATF_CHECK(vi_pci_read(&pi, 0, UINT64_MAX, 1) == UINT8_MAX);
	ATF_CHECK(vi_pci_read(&pi, 0, UINT64_MAX - 1, 4) == UINT32_MAX);
	vi_pci_write(&pi, 0, UINT64_MAX, 1, 0xff);
	ATF_CHECK(g_cfg_reads == 1);
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

	vq.vq_last_avail = 0;
	vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
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

	vq.vq_last_avail = 0;
	desc[0].flags = VRING_DESC_F_WRITE | VRING_DESC_F_NEXT;
	desc[1].flags = 0;
	ATF_CHECK(vq_getchain(&vq, &iov, 1, &req) == 2);
	ATF_CHECK(req.readable == 1 && req.writable == 1);
	ATF_CHECK(!req.ordered);
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
	struct vi_req req;
	struct iovec iov;
	uint8_t payload[8];

	setup_queue(&vs, &vc, &pi, &vq, desc,
	    (struct vring_avail *)avail_mem.bytes,
	    (struct vring_used *)used_mem.bytes);
	vs.vs_negotiated_caps = VIRTIO_RING_F_INDIRECT_DESC |
	    VIRTIO_RING_F_EVENT_IDX;
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
	 * and the real pci_vtnet_ping_ctlq() callback, then verify queue-state,
	 * acknowledgement, used-ring publication, and interrupt delivery.
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
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_OK);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rss_max_tx_vq, 2);
	ATF_CHECK_EQ(used->ring[0].id, 0);
	ATF_CHECK_EQ(used->ring[0].len, sizeof(ack));
	ATF_CHECK_EQ(atomic_load_acq_16(&used->idx), 1);
	ATF_CHECK_EQ(g_interrupts, 1);
	ATF_CHECK_EQ(VQ_AVAIL_EVENT_IDX(vq), 1);

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
	if (vring_need_event(VQ_AVAIL_EVENT_IDX(vq), 2, 1))
		vi_pci_notify_queue(&sc.vsc_vs, vq->vq_num);
	ATF_CHECK_EQ(ack, VIRTIO14_NET_CTRL_ERR);
	ATF_CHECK(sc.rss_enabled);
	ATF_CHECK_EQ(sc.rx_enabled_mask, 3);
	ATF_CHECK_EQ(sc.tx_active_pairs, 2);
	ATF_CHECK_EQ(sc.rss_indirection_table[0], 0);
	ATF_CHECK_EQ(used->ring[1].id, 1);
	ATF_CHECK_EQ(used->ring[1].len, sizeof(ack));
	ATF_CHECK_EQ(atomic_load_acq_16(&used->idx), 2);
	ATF_CHECK_EQ(VQ_AVAIL_EVENT_IDX(vq), 2);

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
	union { max_align_t align; uint8_t bytes[8192]; } ring_mem;
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
	ATF_REQUIRE(ring_size <= sizeof(ring_mem.bytes));
	add_region(0x4000, ring_mem.bytes, ring_size);

	vi_vq_init(&vs, 4);
	ATF_CHECK(vq.vq_pfn == 4);
	ATF_CHECK((vq.vq_flags & VQ_ALLOC) != 0);
	ATF_CHECK(vq.vq_desc == (void *)ring_mem.bytes);

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
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
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

	avail = (struct vring_avail *)avail_mem.bytes;
	used = (struct vring_used *)used_mem.bytes;
	setup_queue(&vs, &vc, &pi, &vq, desc, avail, used);
	vs.vs_negotiated_caps = VIRTIO_RING_F_EVENT_IDX;
	vq.vq_last_avail = 10;
	used->flags = UINT16_MAX;

	vq_kick_enable(&vq);
	ATF_CHECK(used->flags == 0);
	ATF_CHECK(VQ_AVAIL_EVENT_IDX(&vq) == 10);

	vq_kick_disable(&vq);
	ATF_CHECK(used->flags == 0);
	ATF_CHECK(VQ_AVAIL_EVENT_IDX(&vq) == 9);
	/*
	 * The independent document formula must suppress every legal advance
	 * of this eight-entry ring, not merely the first seven entries.
	 */
	for (uint16_t advance = 1; advance <= vq.vq_qsize; advance++) {
		ATF_CHECK(!vring_need_event(VQ_AVAIL_EVENT_IDX(&vq),
		    (uint16_t)(vq.vq_last_avail + advance),
		    vq.vq_last_avail));
	}

	vs.vs_negotiated_caps = 0;
	vq_kick_disable(&vq);
	ATF_CHECK(used->flags == VRING_USED_F_NO_NOTIFY);
	vq_kick_enable(&vq);
	ATF_CHECK(used->flags == 0);
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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, direct_mapping_validation);
	ATF_TP_ADD_TC(tp, indirect_mapping_validation);
	ATF_TP_ADD_TC(tp, linux_control_indirect_chain);
	ATF_TP_ADD_TC(tp, linux_rss_production_callback);
	ATF_TP_ADD_TC(tp, descriptor_chain_byte_limit);
	ATF_TP_ADD_TC(tp, fatal_ring_error_blocks_later_kicks);
	ATF_TP_ADD_TC(tp, fatal_ring_error_stops_current_batch);
	ATF_TP_ADD_TC(tp, chain_can_use_full_queue);
	ATF_TP_ADD_TC(tp, legacy_queue_mapping_validation);
	ATF_TP_ADD_TC(tp, event_idx_interrupts);
	ATF_TP_ADD_TC(tp, event_idx_kick_suppression);
	ATF_TP_ADD_TC(tp, msix_no_vector_suppressed);
	ATF_TP_ADD_TC(tp, legacy_live_configuration_is_frozen);
	ATF_TP_ADD_TC(tp, legacy_config_offset_overflow);
	ATF_TP_ADD_TC(tp, legacy_zero_length_device_config);
	ATF_TP_ADD_TC(tp, legacy_rejected_config_is_not_msix);
	ATF_TP_ADD_TC(tp, legacy_msix_vector_validation);
	ATF_TP_ADD_TC(tp, legacy_non_io_bar_is_ignored);
	ATF_TP_ADD_TC(tp, legacy_status_preserves_needs_reset);
	ATF_TP_ADD_TC(tp, notify_without_msix_does_not_relock_device);
	ATF_TP_ADD_TC(tp, isr_read_serializes_intx);
	return (atf_no_error());
}
