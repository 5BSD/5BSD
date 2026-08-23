/* Device-level tests for bhyve's traditional VirtIO balloon. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_balloon_host.c"
#define	BHYVE_SNAPSHOT
#define	mevent_add	test_mevent_add
#define	mevent_delete_sync	test_mevent_delete_sync
#include "pci_virtio_balloon.c"
#include "virtio_config_read_test_support.h"
#undef mevent_add
#undef mevent_delete_sync
#include "virtio_1_4_spec.h"

enum {
	DUT_BALLOON_DEVICE_ID = VIRTIO_ID_BALLOON,
};
static const uint64_t dut_balloon_hv_caps =
    VIRTIO_BALLOON_F_MUST_TELL_HOST | VIRTIO_F_RING_RESET |
    VIRTIO_F_SUSPEND;

/* Keep protocol expectations independent from the included implementation. */
#undef VIRTIO_ID_BALLOON
#define	VIRTIO_ID_BALLOON	VIRTIO14_DEVICE_BALLOON
#undef VIRTIO_BALLOON_F_MUST_TELL_HOST
#define	VIRTIO_BALLOON_F_MUST_TELL_HOST \
	VIRTIO14_BALLOON_F_MUST_TELL_HOST
#undef VIRTIO_BALLOON_F_STATS_VQ
#define	VIRTIO_BALLOON_F_STATS_VQ	VIRTIO14_BALLOON_F_STATS_VQ
#undef VIRTIO_BALLOON_F_DEFLATE_ON_OOM
#define	VIRTIO_BALLOON_F_DEFLATE_ON_OOM \
	VIRTIO14_BALLOON_F_DEFLATE_ON_OOM
#undef VIRTIO_BALLOON_F_FREE_PAGE_HINT
#define	VIRTIO_BALLOON_F_FREE_PAGE_HINT \
	VIRTIO14_BALLOON_F_FREE_PAGE_HINT
#undef VIRTIO_BALLOON_F_PAGE_REPORTING
#define	VIRTIO_BALLOON_F_PAGE_REPORTING \
	VIRTIO14_BALLOON_F_PAGE_REPORTING
#undef VIRTIO_BALLOON_F_PAGE_POISON
#define	VIRTIO_BALLOON_F_PAGE_POISON	VIRTIO14_BALLOON_F_PAGE_POISON
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER	VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET	VIRTIO14_F_RING_RESET
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND
#undef VIRTIO_CONFIG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VIRTIO14_STATUS_DRIVER_OK
#undef VIRTIO_CONFIG_S_NEEDS_RESET
#define	VIRTIO_CONFIG_S_NEEDS_RESET	VIRTIO14_STATUS_DEVICE_NEEDS_RESET

struct nvlist { int unused; };

static uint8_t g_pfn_bytes[BHYVE_BALLOON_REQUEST_MAX + sizeof(uint32_t)];
static size_t g_pfn_len;
static int g_descs, g_chain_n, g_readable, g_writable;
static bool g_ordered;
static int g_rel_calls, g_end_calls, g_reset_calls, g_needs_reset;
static unsigned int g_discard_calls;
static uint64_t g_discard_gpa;
static size_t g_discard_len;
static int g_discard_error;
static unsigned int g_discard_fail_call;
static unsigned int g_undiscard_calls;
static uint64_t g_undiscard_gpa;
static size_t g_undiscard_len;
static int g_undiscard_error;
static unsigned int g_undiscard_fail_call;
static const char *g_config_target;
static const char *g_config_stats_interval;
static bool g_config_deflate_on_oom;
static bool g_config_free_page_hinting;
static bool g_config_free_page_reporting;
static bool g_config_page_poison;
static bool g_config_packed;
static unsigned int g_reverse_calls;
static uint64_t g_reverse_gpa;
static int g_reverse_error;
static uint16_t g_identity;
static unsigned int g_timer_add_calls, g_timer_delete_calls;
static int g_timer_msecs;
static void (*g_timer_function)(int, enum ev_type, void *);
static void *g_timer_arg;
static bool g_timer_add_fail;
static unsigned int g_config_changed_calls;
static int g_snapshot_validate_calls;
static int g_snapshot_validate_result;
static bool g_snapshot_validate_saw_lock;
static bool g_transport_fail;
static bool g_intr_fail;
static bool g_modern_fail;

void
vm_snapshot_buf_err(const char *name __unused,
    const enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
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

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint16_t)bytes[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint32_t)bytes[i] << (i * 8);
	}
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		for (unsigned int i = 0; i < nitems(bytes); i++)
			bytes[i] = *value >> (i * 8);
	}
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (unsigned int i = 0; i < nitems(bytes); i++)
			*value |= (uint64_t)bytes[i] << (i * 8);
	}
	return (error);
}

static void
reset_mocks(void)
{

	memset(g_pfn_bytes, 0, sizeof(g_pfn_bytes));
	g_pfn_len = sizeof(uint32_t);
	g_descs = 1;
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 0;
	g_ordered = true;
	g_rel_calls = 0;
	g_end_calls = 0;
	g_reset_calls = 0;
	g_needs_reset = 0;
	g_discard_calls = 0;
	g_discard_gpa = UINT64_MAX;
	g_discard_len = 0;
	g_discard_error = 0;
	g_discard_fail_call = 0;
	g_undiscard_calls = 0;
	g_undiscard_gpa = UINT64_MAX;
	g_undiscard_len = 0;
	g_undiscard_error = 0;
	g_undiscard_fail_call = 0;
	g_config_target = NULL;
	g_config_stats_interval = NULL;
	g_config_deflate_on_oom = false;
	g_config_free_page_hinting = false;
	g_config_free_page_reporting = false;
	g_config_page_poison = false;
	g_config_packed = false;
	g_reverse_calls = 0;
	g_reverse_gpa = 0x4000;
	g_reverse_error = 0;
	g_identity = 0;
	g_timer_add_calls = 0;
	g_timer_delete_calls = 0;
	g_timer_msecs = 0;
	g_timer_function = NULL;
	g_timer_arg = NULL;
	g_timer_add_fail = false;
	g_config_changed_calls = 0;
	g_snapshot_validate_calls = 0;
	g_snapshot_validate_result = 0;
	g_snapshot_validate_saw_lock = false;
	g_transport_fail = false;
	g_intr_fail = false;
	g_modern_fail = false;
}

static void
setup_softc(struct pci_vtballoon_softc *sc, size_t host_page_size)
{
	size_t bitmap_size;

	memset(sc, 0, sizeof(*sc));
	ATF_REQUIRE_EQ(virtio_balloon_tracker_required(0x10000, 0, 0,
	    &bitmap_size), 0);
	sc->vbsc_bitmap = calloc(1, bitmap_size);
	ATF_REQUIRE(sc->vbsc_bitmap != NULL);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&sc->vbsc_tracker,
	    0x10000, 0, 0, host_page_size, sc->vbsc_bitmap,
	    bitmap_size), 0);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(
	    &sc->vbsc_accounting, 0x10000, 4), 0);
	sc->vbsc_lowmem_size = 0x10000;
	sc->vbsc_highmem_base = 0;
	sc->vbsc_highmem_size = 0;
	sc->vbsc_consts = vtballoon_vi_consts;
	sc->vbsc_vs.vs_vc = &sc->vbsc_consts;
	sc->vbsc_vs.vs_queues = sc->vbsc_vq;
	for (unsigned int i = 0; i < nitems(sc->vbsc_vq); i++)
		sc->vbsc_vq[i].vq_qsize = VTBALLOON_RINGSZ;
}

int
vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtballoon_softc *sc;
	int error;

	pi = meta->dev_data;
	if (pi == NULL || pi->pi_arg == NULL)
		return (EINVAL);
	sc = pi->pi_arg;
	error = pthread_mutex_trylock(&sc->vbsc_mtx);
	g_snapshot_validate_saw_lock = error == EBUSY;
	if (error == 0)
		pthread_mutex_unlock(&sc->vbsc_mtx);
	g_snapshot_validate_calls++;
	return (g_snapshot_validate_result);
}

static int
run_balloon_snapshot(struct pci_vtballoon_softc *sc, void *buffer,
    size_t size, enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = buffer,
			.buf_size = size,
			.buf = buffer,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtballoon_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (g_descs > 0);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *req)
{
	size_t first;

	if (g_chain_n <= 0)
		return (g_chain_n);
	ATF_REQUIRE(niov == VTBALLOON_RINGSZ);
	ATF_REQUIRE(g_chain_n <= niov);
	first = g_pfn_len / (size_t)g_chain_n;
	for (int i = 0; i < g_chain_n; i++) {
		size_t offset = (size_t)i * first;

		iov[i].iov_base = g_pfn_bytes + offset;
		iov[i].iov_len = i == g_chain_n - 1 ?
		    g_pfn_len - offset : first;
	}
	memset(req, 0, sizeof(*req));
	req->idx = 7;
	req->completion_id = 7;
	req->descriptor_count = (uint16_t)g_chain_n;
	req->packed_head = 3;
	req->packed_wrap = true;
	req->queue_generation = vq->vq_generation;
	req->outstanding = true;
	req->readable = g_readable;
	req->writable = g_writable;
	req->ordered = g_ordered;
	g_descs--;
	return (g_chain_n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	ATF_CHECK_EQ(idx, 7);
	ATF_CHECK_EQ(len, 0);
	g_rel_calls++;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail __unused)
{

	g_end_calls++;
}

int
vi_platform_discard_ram(struct virtio_softc *vs __unused, uint64_t gpa,
    size_t len)
{

	g_discard_calls++;
	g_discard_gpa = gpa;
	g_discard_len = len;
	if (g_discard_fail_call != 0 &&
	    g_discard_calls != g_discard_fail_call)
		return (0);
	return (g_discard_error);
}

int
vi_platform_undiscard_ram(struct virtio_softc *vs __unused, uint64_t gpa,
    size_t len)
{

	g_undiscard_calls++;
	g_undiscard_gpa = gpa;
	g_undiscard_len = len;
	if (g_undiscard_fail_call != 0 &&
	    g_undiscard_calls != g_undiscard_fail_call)
		return (0);
	return (g_undiscard_error);
}

int
vi_platform_reverse_ram(struct virtio_softc *vs __unused,
    void *mapping __unused, size_t len __unused, uint64_t *gpa)
{

	g_reverse_calls++;
	if (g_reverse_error != 0)
		return (g_reverse_error);
	*gpa = g_reverse_gpa;
	return (0);
}

size_t
vi_platform_ram_page_size(struct virtio_softc *vs __unused)
{

	return (4096);
}

int
vi_pci_lifecycle_noop(void *arg __unused)
{

	return (0);
}

void
vi_reset_dev(struct virtio_softc *vs)
{

	g_reset_calls++;
	vs->vs_status = 0;
	vs->vs_restore_incomplete = false;
}

void
vi_set_needs_reset(struct virtio_softc *vs)
{

	g_needs_reset++;
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}

void
vi_snapshot_restore_incomplete(struct virtio_softc *vs)
{

	vs->vs_restore_incomplete = true;
	vi_set_needs_reset(vs);
}

void
vi_pci_config_changed(struct virtio_softc *vs __unused)
{

	g_config_changed_calls++;
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused,
    const char *name, bool default_value)
{

	if (strcmp(name, "packed") == 0)
		return (g_config_packed);
	if (strcmp(name, "deflate_on_oom") == 0)
		return (g_config_deflate_on_oom);
	if (strcmp(name, "free_page_hinting") == 0)
		return (g_config_free_page_hinting);
	if (strcmp(name, "free_page_reporting") == 0)
		return (g_config_free_page_reporting);
	if (strcmp(name, "page_poison") == 0)
		return (g_config_page_poison);
	return (default_value);
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "target") == 0)
		return (g_config_target);
	if (strcmp(name, "stats_interval") == 0)
		return (g_config_stats_interval);
	return (NULL);
}

struct mevent *
test_mevent_add(int msecs, enum ev_type type,
    void (*function)(int, enum ev_type, void *), void *arg)
{

	ATF_CHECK_EQ(type, EVF_TIMER);
	ATF_CHECK(msecs > 0);
	g_timer_add_calls++;
	g_timer_msecs = msecs;
	g_timer_function = function;
	g_timer_arg = arg;
	if (g_timer_add_fail)
		return (NULL);
	return ((struct mevent *)(uintptr_t)1);
}

int
test_mevent_delete_sync(struct mevent *event)
{

	ATF_CHECK_EQ((uintptr_t)event, 1);
	g_timer_delete_calls++;
	return (0);
}

size_t
vm_get_lowmem_size(struct vmctx *ctx __unused)
{

	return (0x10000);
}

vm_paddr_t
vm_get_highmem_base(struct vmctx *ctx __unused)
{

	return (0);
}

size_t
vm_get_highmem_size(struct vmctx *ctx __unused)
{

	return (0);
}

int
vm_parse_memsize(const char *value, size_t *result)
{

	if (strcmp(value, "16K") != 0)
		return (EINVAL);
	*result = 0x4000;
	return (0);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *softc __unused, struct pci_devinst *pi, struct vqueue_info *queues)
{

	memset(vs, 0, sizeof(*vs));
	vs->vs_vc = vc;
	vs->vs_pi = pi;
	vs->vs_queues = queues;
	pi->pi_arg = vs;
	for (int i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

int
vi_pci_select_transport(struct virtio_softc *vs,
    const nvlist_t *nvl __unused, enum virtio_pci_transport_policy policy)
{

	ATF_CHECK_EQ(policy, VIRTIO_PCI_MODERN_ONLY);
	if (g_transport_fail)
		return (EINVAL);
	vs->vs_transport = VIRTIO_PCI_TRANSPORT_MODERN;
	return (0);
}

void vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t id) { g_identity = id; }
int vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{ return (g_modern_fail ? -1 : 0); }
int vi_intr_init(struct virtio_softc *vs __unused, int bar __unused,
    int msix __unused) { return (g_intr_fail ? -1 : 0); }
int fbsdrun_virtio_msix(void) { return (1); }
int vi_pci_modern_cfgread(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t *val __unused) { return (0); }
int vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused,
    int off __unused, int size __unused, uint32_t val __unused) { return (0); }
uint64_t vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused) { return (0); }
void vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t off __unused, int size __unused, uint64_t val __unused) {}
void pci_set_cfgdata8(struct pci_devinst *pi, int off, uint8_t val)
{ pi->pi_cfgdata[off] = val; }
void pci_set_cfgdata16(struct pci_devinst *pi, int off, uint16_t val)
{ memcpy(&pi->pi_cfgdata[off], &val, sizeof(val)); }

ATF_TC_WITHOUT_HEAD(inflate_deflate_and_host_granule);
ATF_TC_BODY(inflate_deflate_and_host_granule, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;

	setup_softc(&sc, 0x4000);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	vq.vq_qsize = VTBALLOON_RINGSZ;
	reset_mocks();
	g_pfn_len = 4 * sizeof(uint32_t);
	g_chain_n = 3;
	g_readable = g_chain_n;
	for (uint32_t i = 0; i < 4; i++)
		le32enc(g_pfn_bytes + i * sizeof(uint32_t), i);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_discard_gpa, 0);
	ATF_CHECK_EQ(g_discard_len, 0x4000);

	vq.vq_num = VTBALLOON_DEFLATE_QUEUE;
	reset_mocks();
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_undiscard_gpa, 0);
	ATF_CHECK_EQ(g_undiscard_len, 0x4000);

	reset_mocks();
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);

	reset_mocks();
	vq.vq_num = VTBALLOON_DEFLATE_QUEUE;
	g_undiscard_error = EIO;
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x02, 0);

	/* The completed deflate is idempotent despite the failed host hint. */
	reset_mocks();
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_undiscard_calls, 0);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x02, 0);

	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	reset_mocks();
	g_discard_error = EIO;
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x02, 0x02);

	/* A duplicate inflate cannot replay the failed reclamation hint. */
	reset_mocks();
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x02, 0x02);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(advertised_contract);
ATF_TC_BODY(advertised_contract, tc)
{

	ATF_CHECK_EQ(DUT_BALLOON_DEVICE_ID, VIRTIO_ID_BALLOON);
	ATF_CHECK_EQ(vtballoon_vi_consts.vc_hv_caps,
	    dut_balloon_hv_caps);
	ATF_CHECK_EQ(dut_balloon_hv_caps, VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND |
	    VIRTIO_BALLOON_F_MUST_TELL_HOST);
	/* The timer-driven statistics queue may complete asynchronously. */
	ATF_CHECK_EQ(dut_balloon_hv_caps & VIRTIO_F_IN_ORDER, 0);
	ATF_CHECK_EQ(vtballoon_vi_consts.vc_nvq, 2);
	ATF_CHECK_EQ(vtballoon_vi_consts.vc_cfgsize,
	    VIRTIO14_BALLOON_CONFIG_SIZE);
	ATF_CHECK(vtballoon_vi_consts.vc_qreset == pci_vtballoon_qreset);
	ATF_CHECK(vtballoon_vi_consts.vc_suspend ==
	    pci_vtballoon_suspend_device);
	ATF_CHECK(vtballoon_vi_consts.vc_access_platform_ineligible);
}

ATF_TC_WITHOUT_HEAD(notification_budget_is_queue_bounded);
ATF_TC_BODY(notification_budget_is_queue_bounded, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;

	setup_softc(&sc, 0x1000);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	vq.vq_qsize = 2;
	reset_mocks();
	g_descs = 3;
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK_EQ(g_end_calls, 1);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(pfn_duplicates_and_invalid_ranges);
ATF_TC_BODY(pfn_duplicates_and_invalid_ranges, tc)
{
	struct pci_vtballoon_softc sc;
	struct vtballoon_pfn_context context;
	struct virtio_balloon_pfn_result result;
	struct iovec iov;
	uint8_t pfns[4 * sizeof(uint32_t)];

	setup_softc(&sc, BHYVE_BALLOON_PAGE_SIZE);
	reset_mocks();
	le32enc(pfns + 0 * sizeof(uint32_t), 0);
	le32enc(pfns + 1 * sizeof(uint32_t), 0); /* Duplicate inflate. */
	le32enc(pfns + 2 * sizeof(uint32_t), 16); /* Just past RAM. */
	le32enc(pfns + 3 * sizeof(uint32_t), 1);
	iov.iov_base = pfns;
	iov.iov_len = sizeof(pfns);
	context.sc = &sc;
	context.inflate = true;
	ATF_REQUIRE_EQ(virtio_balloon_process_pfns(&iov, 1,
	    pci_vtballoon_pfn, &context, &result), 0);
	ATF_CHECK_EQ(result.vbpr_seen, 4);
	ATF_CHECK_EQ(result.vbpr_accepted, 3);
	ATF_CHECK_EQ(result.vbpr_rejected, 1);
	ATF_CHECK_EQ(g_discard_calls, 2);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x03, 0x03);

	/*
	 * Duplicate and never-inflated deflates are idempotent.  Neither may
	 * replay the host undiscard operation after ownership is gone.
	 */
	reset_mocks();
	le32enc(pfns + 0 * sizeof(uint32_t), 0);
	le32enc(pfns + 1 * sizeof(uint32_t), 0);
	le32enc(pfns + 2 * sizeof(uint32_t), 2);
	iov.iov_len = 3 * sizeof(uint32_t);
	context.inflate = false;
	ATF_REQUIRE_EQ(virtio_balloon_process_pfns(&iov, 1,
	    pci_vtballoon_pfn, &context, &result), 0);
	ATF_CHECK_EQ(result.vbpr_seen, 3);
	ATF_CHECK_EQ(result.vbpr_accepted, 3);
	ATF_CHECK_EQ(result.vbpr_rejected, 0);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x03, 0x02);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(statistics_retained_chain_lifecycle);
ATF_TC_BODY(statistics_retained_chain_lifecycle, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info *vq;
	static const uint8_t encoded[] = {
		/* MEMFREE (tag 4), 4096 bytes. */
		0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	setup_softc(&sc, 0x1000);
	vq = &sc.vbsc_vq[VTBALLOON_STATS_QUEUE];
	vq->vq_vs = &sc.vbsc_vs;
	vq->vq_num = VTBALLOON_STATS_QUEUE;
	vq->vq_qsize = 8;
	vq->vq_layout = VIRTIO_QUEUE_SPLIT;
	vq->vq_generation = 19;
	vq_set_allocated(vq, true);
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_STATS_VQ;

	reset_mocks();
	memcpy(g_pfn_bytes, encoded, sizeof(encoded));
	g_pfn_len = sizeof(encoded);
	pci_vtballoon_notify(&sc, vq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	ATF_REQUIRE(sc.vbsc_stats_valid);
	ATF_CHECK_EQ(sc.vbsc_stats.vbs_present, 1U << 4);
	ATF_CHECK_EQ(sc.vbsc_stats.vbs_value[4], UINT64_C(4096));
	ATF_CHECK_EQ(g_rel_calls, 0);

	/* A second notify cannot displace the one retained descriptor. */
	g_descs = 1;
	pci_vtballoon_notify(&sc, vq);
	ATF_CHECK_EQ(g_descs, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);

	/*
	 * Selective reset revokes the retained descriptor without publishing a
	 * completion.  A newly configured queue generation can immediately
	 * acquire a replacement sample.
	 */
	vq->vq_generation = 20;
	ATF_REQUIRE_EQ(pci_vtballoon_qreset(&sc, vq, 20), 0);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK(sc.vbsc_stats_valid);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK(!sc.vbsc_stats_req.outstanding);
	ATF_CHECK_EQ(sc.vbsc_stats_req.descriptor_count, 0);
	g_descs = 1;
	pci_vtballoon_notify(&sc, vq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	ATF_CHECK_EQ(sc.vbsc_stats_req.queue_generation, 20);

	sc.vbsc_vs.vs_quiescing = 1;
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 0);
	sc.vbsc_vs.vs_quiescing = 0;
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_end_calls, 1);

	/*
	 * The timer is independent asynchronous work.  It must honor every
	 * common lifecycle fence, not only the quiesce fence used above: guest
	 * suspend and a checkpoint pause both retain the descriptor until their
	 * owner explicitly drains it.  Exercise the two predicates separately
	 * so a future boolean simplification cannot accidentally reopen one.
	 */
	g_descs = 1;
	pci_vtballoon_notify(&sc, vq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	sc.vbsc_vs.vs_suspended = 1;
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 1);
	sc.vbsc_vs.vs_suspended = 0;

	sc.vbsc_vs.vs_checkpoint_paused = 1;
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 1);
	sc.vbsc_vs.vs_checkpoint_paused = 0;
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 2);
	ATF_CHECK_EQ(g_end_calls, 2);

	/*
	 * Guest suspend must also complete the retained buffer.  It runs with
	 * the common queue fence and device mutex already owned, unlike the
	 * checkpoint-pause wrapper.
	 */
	g_descs = 1;
	pci_vtballoon_notify(&sc, vq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	ATF_REQUIRE_EQ(pci_vtballoon_suspend_device(&sc), 0);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK(!sc.vbsc_stats_req.outstanding);
	ATF_CHECK_EQ(g_rel_calls, 3);
	ATF_CHECK_EQ(g_end_calls, 3);

	/* Reset drops ownership without completing an invalidated chain. */
	g_descs = 1;
	pci_vtballoon_notify(&sc, vq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	pci_vtballoon_reset(&sc);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK(!sc.vbsc_stats_valid);
	ATF_CHECK(!sc.vbsc_stats_req.outstanding);
	ATF_CHECK_EQ(g_rel_calls, 3);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(initialization_contract);
ATF_TC_BODY(initialization_contract, tc)
{
	struct pci_vtballoon_softc *sc;
	struct pci_devinst pi;
	struct nvlist nvl;

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	memset(&nvl, 0, sizeof(nvl));
	g_config_target = "16K";
	g_config_packed = true;
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(g_identity, VIRTIO_ID_BALLOON);
	ATF_CHECK_EQ(sc->vbsc_vs.vs_transport,
	    VIRTIO_PCI_TRANSPORT_MODERN);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_F_RING_PACKED) != 0);
	ATF_CHECK_EQ(sc->vbsc_accounting.vba_total_pages, 16);
	ATF_CHECK_EQ(sc->vbsc_accounting.vba_target_pages, 4);
	ATF_CHECK_EQ(sc->vbsc_accounting.vba_actual_pages, 0);
	ATF_CHECK_EQ(sc->vbsc_vq[0].vq_qsize, 128);
	ATF_CHECK_EQ(sc->vbsc_vq[1].vq_qsize, 128);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_stats_interval = "7";
	g_timer_add_fail = true;
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);
	ATF_CHECK_EQ(g_timer_add_calls, 1);
	ATF_CHECK_EQ(g_timer_delete_calls, 0);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_stats_interval = "7";
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_nvq, 3);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_STATS_VQ) != 0);
	ATF_CHECK_EQ(sc->vbsc_vq[2].vq_qsize, 128);
	ATF_CHECK_EQ(g_timer_add_calls, 1);
	ATF_CHECK_EQ(g_timer_msecs, 7000);
	ATF_REQUIRE(g_timer_function != NULL);
	ATF_CHECK_EQ(g_timer_arg, sc);
	g_timer_function(g_timer_msecs, EVF_TIMER, g_timer_arg);
	ATF_CHECK_EQ(test_mevent_delete_sync(sc->vbsc_stats_evp), 0);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_deflate_on_oom = true;
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_DEFLATE_ON_OOM) != 0);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_nvq, 2);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_free_page_reporting = true;
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_PAGE_REPORTING) != 0);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_nvq, 5);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_STATS_QUEUE].vq_qsize, 0);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE].vq_qsize, 0);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_REPORTING_QUEUE].vq_qsize,
	    VTBALLOON_RINGSZ);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_free_page_hinting = true;
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_nvq, 4);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE].vq_qsize,
	    VTBALLOON_RINGSZ);
	ATF_CHECK_EQ(sc->vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_FIRST);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_free_page_hinting = true;
	g_config_stats_interval = "7";
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_nvq, 4);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_STATS_QUEUE].vq_qsize,
	    VTBALLOON_RINGSZ);
	ATF_CHECK_EQ(sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE].vq_qsize,
	    VTBALLOON_RINGSZ);
	ATF_CHECK_EQ(test_mevent_delete_sync(sc->vbsc_stats_evp), 0);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_page_poison = true;
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK((sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_PAGE_POISON) != 0);
	ATF_CHECK_EQ(sc->vbsc_consts.vc_cfgsize,
	    VIRTIO14_BALLOON_CONFIG_SIZE);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_target = "invalid";
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);

	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_config_stats_interval = "0";
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);
}

ATF_TC_WITHOUT_HEAD(descriptor_and_config_validation);
ATF_TC_BODY(descriptor_and_config_validation, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;
	uint32_t value;

	setup_softc(&sc, 0x4000);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	vq.vq_qsize = VTBALLOON_RINGSZ;

	reset_mocks();
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 0);

	reset_mocks();
	g_pfn_len = 3;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 0);

	reset_mocks();
	g_pfn_len = BHYVE_BALLOON_REQUEST_MAX + sizeof(uint32_t);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_needs_reset, 1);

	reset_mocks();
	vq.vq_num = VTBALLOON_NVQ;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);

	ATF_REQUIRE_EQ(pci_vtballoon_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 4);
	ATF_CHECK_EQ(pci_vtballoon_cfgread(&sc, 0, 4, NULL), EINVAL);
	ATF_REQUIRE_EQ(pci_vtballoon_cfgwrite(&sc, 4, 4, 5), 0);
	ATF_CHECK_EQ(sc.vbsc_accounting.vba_actual_pages, 5);
	ATF_CHECK_EQ(pci_vtballoon_cfgwrite(&sc, 4, 4, 17),
	    ERANGE);
	ATF_CHECK_EQ(pci_vtballoon_cfgwrite(&sc, 0, 4, 0), EINVAL);
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_PAGE_POISON;
	ATF_REQUIRE_EQ(pci_vtballoon_cfgwrite(&sc,
	    VIRTIO14_BALLOON_POISON_VAL_OFF, 4, UINT32_C(0xa5a5a5a5)), 0);
	ATF_CHECK_EQ(sc.vbsc_poison_val, UINT32_C(0xa5a5a5a5));
	ATF_REQUIRE_EQ(pci_vtballoon_cfgread(&sc,
	    VIRTIO14_BALLOON_POISON_VAL_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, UINT32_C(0xa5a5a5a5));
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	ATF_CHECK_EQ(pci_vtballoon_cfgwrite(&sc,
	    VIRTIO14_BALLOON_POISON_VAL_OFF, 4, 0), EINVAL);
	ATF_CHECK_EQ(sc.vbsc_poison_val, UINT32_C(0xa5a5a5a5));
	sc.vbsc_vs.vs_status = 0;
	sc.vbsc_vs.vs_negotiated_caps = 0;
	ATF_CHECK_EQ(pci_vtballoon_cfgwrite(&sc,
	    VIRTIO14_BALLOON_POISON_VAL_OFF, 4, 0), EINVAL);
	ATF_REQUIRE_EQ(pci_vtballoon_cfgread(&sc,
	    VIRTIO14_BALLOON_FREE_PAGE_HINT_CMD_ID_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(free_page_hinting);
ATF_TC_BODY(free_page_hinting, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;
	uint32_t command, value;

	setup_softc(&sc, 4096);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	vq.vq_qsize = VTBALLOON_RINGSZ;
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	sc.vbsc_free_page_hint_cmd_id = VIRTIO14_BALLOON_CMD_ID_FIRST;

	/* Linux submits the matching command as its own readable buffer. */
	reset_mocks();
	command = htole32(VIRTIO14_BALLOON_CMD_ID_FIRST);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = sizeof(command);
	g_chain_n = 2;
	g_readable = 2;
	g_writable = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK(sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(g_reverse_calls, 0);
	ATF_CHECK_EQ(g_discard_calls, 0);

	/* Selective queue reset requires the current ID to start it again. */
	ATF_REQUIRE_EQ(pci_vtballoon_qreset(&sc, &vq, 0), 0);
	ATF_CHECK(!sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_FIRST);
	reset_mocks();
	command = htole32(VIRTIO14_BALLOON_CMD_ID_FIRST);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK(sc.vbsc_free_page_hint_active);

	/* Writable-only buffers are hints only after that command starts. */
	reset_mocks();
	g_pfn_len = 4096;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_reverse_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_discard_len, 4096);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_end_calls, 1);

	/* A command and writable range in one ordered chain is also valid. */
	reset_mocks();
	command = htole32(VIRTIO14_BALLOON_CMD_ID_FIRST);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = 8;
	g_chain_n = 2;
	g_readable = 1;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_reverse_calls, 1);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_discard_len, 4);

	/*
	 * A combined buffer associates its writable ranges with the command
	 * in that same chain.  A stale command must not inherit the otherwise
	 * active round and cause those ranges to be discarded.
	 */
	reset_mocks();
	command = htole32(VIRTIO14_BALLOON_CMD_ID_FIRST + 1);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = 8;
	g_chain_n = 2;
	g_readable = 1;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK(sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_FIRST);
	ATF_CHECK_EQ(g_reverse_calls, 0);
	ATF_CHECK_EQ(g_discard_calls, 0);

	/*
	 * A failed reverse-map or discard asks the driver to stop this round.
	 * The driver's STOP command then completes the handshake as DONE.
	 */
	reset_mocks();
	g_pfn_len = 4096;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_discard_error = EIO;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK(!sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_STOP);
	ATF_CHECK_EQ(g_config_changed_calls, 1);
	reset_mocks();
	command = htole32(VIRTIO14_BALLOON_CMD_ID_STOP);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = sizeof(command);
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_DONE);
	ATF_CHECK(!sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(g_config_changed_calls, 1);

	/* A stale ID cannot activate a new requested round. */
	reset_mocks();
	sc.vbsc_free_page_hint_cmd_id = VIRTIO14_BALLOON_CMD_ID_FIRST;
	sc.vbsc_free_page_hint_active = false;
	command = htole32(VIRTIO14_BALLOON_CMD_ID_FIRST + 1);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = sizeof(command);
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK(!sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(g_reverse_calls, 0);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);
	reset_mocks();
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);

	/* STOP ends the round, publishes DONE, and changes configuration. */
	reset_mocks();
	sc.vbsc_free_page_hint_active = true;
	command = htole32(VIRTIO14_BALLOON_CMD_ID_STOP);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_DONE);
	ATF_CHECK_EQ(g_config_changed_calls, 1);
	ATF_REQUIRE_EQ(pci_vtballoon_cfgread(&sc,
	    VIRTIO14_BALLOON_FREE_PAGE_HINT_CMD_ID_OFF, 4, &value), 0);
	ATF_CHECK_EQ(value, VIRTIO14_BALLOON_CMD_ID_DONE);

	/* Direction and command-size violations fail the queue closed. */
	reset_mocks();
	g_readable = 2;
	g_writable = 0;
	g_chain_n = 2;
	g_pfn_len = 8;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	g_pfn_len = 8;
	g_chain_n = 2;
	g_readable = 1;
	g_writable = 1;
	g_ordered = false;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_discard_calls, 0);

	reset_mocks();
	g_pfn_len = 3;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);

	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(free_page_reporting);
ATF_TC_BODY(free_page_reporting, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;

	reset_mocks();
	setup_softc(&sc, 4096);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_REPORTING_QUEUE;
	vq.vq_qsize = VTBALLOON_RINGSZ;
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_discard_gpa, 0x4000);
	ATF_CHECK_EQ(g_discard_len, 4096);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_end_calls, 1);

	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps = 0;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);

	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_pfn_len = 4096;
	g_readable = 1;
	g_writable = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	g_reverse_error = EFAULT;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	g_discard_error = EIO;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_REPORTING |
	    VIRTIO_BALLOON_F_PAGE_POISON;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_reverse_calls, 0);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 1);

	reset_mocks();
	vq.vq_num = VTBALLOON_STATS_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_pfn_len = VIRTIO14_BALLOON_STAT_SIZE;
	g_readable = 1;
	g_writable = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_calls, 0);

	reset_mocks();
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_rel_calls, 0);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(reset_retains_target);
ATF_TC_BODY(reset_retains_target, tc)
{
	struct pci_vtballoon_softc sc;
	uint64_t discard_gpa;
	size_t discard_len;
	bool ready;

	setup_softc(&sc, 0x4000);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_actual(
	    &sc.vbsc_accounting, 3), 0);
	for (uint64_t gpa = 0; gpa < 0x4000; gpa += 0x1000)
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(
		    &sc.vbsc_tracker, gpa, &discard_gpa, &discard_len,
		    &ready), 0);
	reset_mocks();
	pci_vtballoon_reset(&sc);
	ATF_CHECK_EQ(g_reset_calls, 1);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_undiscard_gpa, 0);
	ATF_CHECK_EQ(g_undiscard_len, 0x4000);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(sc.vbsc_accounting.vba_target_pages, 4);
	ATF_CHECK_EQ(sc.vbsc_accounting.vba_actual_pages, 0);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&sc.vbsc_tracker,
	    0x3000, &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(!ready);

	/* A failed cancellation retains both ownership and accounting. */
	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_actual(
	    &sc.vbsc_accounting, 4), 0);
	for (uint64_t gpa = 0; gpa < 0x3000; gpa += 0x1000)
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(
		    &sc.vbsc_tracker, gpa, &discard_gpa, &discard_len,
		    &ready), 0);
	reset_mocks();
	g_undiscard_error = EIO;
	pci_vtballoon_reset(&sc);
	ATF_CHECK_EQ(g_reset_calls, 1);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(sc.vbsc_vs.vs_restore_incomplete);
	ATF_CHECK((sc.vbsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ATF_CHECK_EQ(sc.vbsc_accounting.vba_actual_pages, 4);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x0f, 0x0f);

	reset_mocks();
	pci_vtballoon_reset(&sc);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(sc.vbsc_accounting.vba_actual_pages, 0);
	ATF_CHECK_EQ(sc.vbsc_bitmap[0] & 0x0f, 0);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(snapshot_preflight_is_locally_serialized);
ATF_TC_BODY(snapshot_preflight_is_locally_serialized, tc)
{
	struct pci_devinst pi;
	struct pci_vtballoon_softc sc;
	struct vm_snapshot_meta meta = {
		.op = VM_SNAPSHOT_VALIDATE,
	};

	reset_mocks();
	setup_softc(&sc, 0x1000);
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vbsc_mtx, NULL), 0);
	memset(&pi, 0, sizeof(pi));
	pi.pi_arg = &sc;
	meta.dev_data = &pi;

	ATF_REQUIRE_EQ(pci_vtballoon_snapshot_validate(&meta), 0);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	ATF_CHECK(g_snapshot_validate_saw_lock);
	ATF_CHECK_EQ(pthread_mutex_trylock(&sc.vbsc_mtx), 0);
	pthread_mutex_unlock(&sc.vbsc_mtx);

	meta.dev_data = NULL;
	ATF_CHECK_EQ(pci_vtballoon_snapshot_validate(&meta), EINVAL);
	ATF_CHECK_EQ(g_snapshot_validate_calls, 1);
	pthread_mutex_destroy(&sc.vbsc_mtx);
	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(snapshot_wire_validation_and_repeat);
ATF_TC_BODY(snapshot_wire_validation_and_repeat, tc)
{
	struct pci_vtballoon_softc destination, source;
	uint8_t damaged[256], image[256];
	uint64_t discard_gpa;
	size_t discard_len, used;
	bool ready;

	setup_softc(&source, 0x1000);
	source.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_POISON |
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	source.vbsc_free_page_hint_cmd_id =
	    VIRTIO14_BALLOON_CMD_ID_FIRST;
	source.vbsc_free_page_hint_active = true;
	source.vbsc_poison_val = UINT32_C(0x5a5a5a5a);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_actual(
	    &source.vbsc_accounting, 3), 0);
	for (uint64_t gpa = 0; gpa < 0x3000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(
		    &source.vbsc_tracker, gpa, &discard_gpa, &discard_len,
		    &ready), 0);
		ATF_REQUIRE(ready);
	}
	ATF_REQUIRE_EQ(run_balloon_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, 174);
	ATF_CHECK_EQ(image[0], 'B');
	ATF_CHECK_EQ(image[1], 'A');
	ATF_CHECK_EQ(image[2], 'L');
	ATF_CHECK_EQ(image[3], '1');
	ATF_CHECK_EQ(image[4], 6);
	ATF_CHECK_EQ(image[12], 4);
	ATF_CHECK_EQ(image[16], 3);
	ATF_CHECK_EQ(image[44], 2);
	ATF_CHECK_EQ(image[52], 0x07);
	ATF_CHECK_EQ(image[53], 0);
	ATF_CHECK_EQ(le32dec(image + 165), UINT32_C(0x5a5a5a5a));
	ATF_CHECK_EQ(le32dec(image + 169), VIRTIO14_BALLOON_CMD_ID_FIRST);
	ATF_CHECK_EQ(image[173], 1);

	setup_softc(&destination, 0x1000);
	destination.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_POISON |
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	for (uint64_t gpa = 0; gpa < 0x4000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(
		    &destination.vbsc_tracker, gpa, &discard_gpa,
		    &discard_len, &ready), 0);
	}
	ATF_REQUIRE(ready);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_actual(
	    &destination.vbsc_accounting, 4), 0);
	reset_mocks();
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 4);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 4);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0x0f);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_undiscard_calls, 0);
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_VALIDATE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 4);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0x0f);
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 4);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 3);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0x07);
	ATF_CHECK_EQ(destination.vbsc_bitmap[1], 0);
	ATF_CHECK_EQ(destination.vbsc_poison_val, UINT32_C(0x5a5a5a5a));
	ATF_CHECK_EQ(destination.vbsc_free_page_hint_cmd_id,
	    VIRTIO14_BALLOON_CMD_ID_FIRST);
	ATF_CHECK(destination.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_undiscard_gpa, 0x3000);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(
	    &destination.vbsc_tracker, 0, &discard_gpa, &discard_len,
	    &ready), 0);
	ATF_CHECK(!ready);
	ATF_CHECK_EQ(discard_gpa, 0);
	ATF_CHECK_EQ(discard_len, 0);

	/* An identical repeated restore performs no host memory operation. */
	reset_mocks();
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 3);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0x07);
	ATF_CHECK_EQ(g_discard_calls, 0);
	ATF_CHECK_EQ(g_undiscard_calls, 0);

	memcpy(damaged, image, used);
	damaged[16] = 2;
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 2);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0x07);
	/*
	 * Section 5.5.6.1 permits one actual update after multiple completed
	 * operations, so the field may legitimately lag PFN ownership at the
	 * instant a paused checkpoint is taken.
	 */
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 3);

	/*
	 * A later host discard failure undoes the successful prefix and does
	 * not publish staged ownership or counts.
	 */
	destination.vbsc_accounting.vba_target_pages = 2;
	destination.vbsc_accounting.vba_actual_pages = 0;
	memset(destination.vbsc_bitmap, 0,
	    destination.vbsc_tracker.vbpt_bitmap_size);
	reset_mocks();
	g_discard_error = EIO;
	g_discard_fail_call = 2;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EIO);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 2);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0);
	ATF_CHECK_EQ(g_discard_calls, 2);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_undiscard_gpa, 0);

	/* Truncation and corrupt metadata do not publish partial state. */
	reset_mocks();
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 2);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);

	memcpy(damaged, image, used);
	damaged[4] = 7;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	/* Unknown versions are rejected from their self-identifying prefix. */
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, 8,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	damaged[4] = 6;
	damaged[8] = 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[20] ^= 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[12] = 17;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[44] = 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[55] = 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[146] = 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	damaged[173] = 2;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	le32enc(damaged + 169, VIRTIO14_BALLOON_CMD_ID_STOP);
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	memcpy(damaged, image, used);
	destination.vbsc_vs.vs_negotiated_caps = 0;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	destination.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_POISON |
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 2);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);

	/* Unreleased predecessor encodings are intentionally unsupported. */
	memcpy(damaged, image, 44);
	damaged[4] = 1;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, 44,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);
	damaged[16] = 0;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, 44,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_target_pages, 2);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0);
	ATF_CHECK_EQ(destination.vbsc_bitmap[1], 0);

	/*
	 * If undo itself fails, fail closed and carry DEVICE_NEEDS_RESET
	 * through the common deferred reset latch.
	 */
	reset_mocks();
	destination.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_PAGE_POISON |
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	g_discard_error = EIO;
	g_discard_fail_call = 2;
	g_undiscard_error = EBUSY;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EBUSY);
	ATF_CHECK_EQ(destination.vbsc_accounting.vba_actual_pages, 0);
	ATF_CHECK_EQ(destination.vbsc_bitmap[0], 0);
	ATF_CHECK_EQ(g_discard_calls, 2);
	ATF_CHECK_EQ(g_undiscard_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(destination.vbsc_vs.vs_restore_incomplete);
	ATF_CHECK((destination.vbsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	free(destination.vbsc_bitmap);
	free(source.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(statistics_snapshot_ownership);
ATF_TC_BODY(statistics_snapshot_ownership, tc)
{
	struct pci_vtballoon_softc destination, source;
	struct vqueue_info *vq;
	uint8_t damaged[256], image[256];
	size_t used;

	setup_softc(&source, 0x1000);
	vq = &source.vbsc_vq[VTBALLOON_STATS_QUEUE];
	vq->vq_vs = &source.vbsc_vs;
	vq->vq_num = VTBALLOON_STATS_QUEUE;
	vq->vq_qsize = 8;
	vq->vq_layout = VIRTIO_QUEUE_PACKED;
	vq->vq_generation = 23;
	vq_set_allocated(vq, true);
	source.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_STATS_VQ;
	source.vbsc_stats_valid = true;
	source.vbsc_stats_held = true;
	source.vbsc_stats.vbs_present = 1U << 5;
	source.vbsc_stats.vbs_entries = 1;
	source.vbsc_stats.vbs_value[5] = UINT64_C(0x123456789);
	source.vbsc_stats_req.idx = 7;
	source.vbsc_stats_req.completion_id = 99;
	source.vbsc_stats_req.descriptor_count = 1;
	source.vbsc_stats_req.packed_head = 3;
	source.vbsc_stats_req.packed_wrap = true;
	source.vbsc_stats_req.queue_generation = 23;
	source.vbsc_stats_req.outstanding = true;

	/* Device snapshot cannot encode live queue ownership by itself. */
	ATF_CHECK_EQ(run_balloon_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), EBUSY);
	ATF_REQUIRE_EQ(pci_vtballoon_pause(&source), 0);
	ATF_CHECK(!source.vbsc_stats_held);
	ATF_CHECK(!source.vbsc_stats_req.outstanding);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_REQUIRE_EQ(run_balloon_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(used, 174);

	/*
	 * Checkpoint pause must not silently publish an image after retained
	 * queue ownership became stale.  Guest suspend already converts the
	 * same NEEDS_RESET result into failure in the common modern transport.
	 */
	source.vbsc_stats_held = true;
	source.vbsc_stats_req.outstanding = true;
	source.vbsc_stats_req.queue_generation = 22;
	source.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	reset_mocks();
	ATF_CHECK_EQ(pci_vtballoon_pause(&source), EIO);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(!source.vbsc_stats_held);
	ATF_CHECK(!source.vbsc_stats_req.outstanding);
	ATF_CHECK((source.vbsc_vs.vs_status &
	    VIRTIO_CONFIG_S_NEEDS_RESET) != 0);

	setup_softc(&destination, 0x1000);
	vq = &destination.vbsc_vq[VTBALLOON_STATS_QUEUE];
	vq->vq_vs = &destination.vbsc_vs;
	vq->vq_num = VTBALLOON_STATS_QUEUE;
	vq->vq_qsize = 8;
	vq->vq_layout = VIRTIO_QUEUE_PACKED;
	vq->vq_generation = 23;
	vq_set_allocated(vq, true);
	destination.vbsc_vs.vs_negotiated_caps =
	    VIRTIO_BALLOON_F_STATS_VQ;
	ATF_REQUIRE_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK(!destination.vbsc_stats_held);
	ATF_CHECK(destination.vbsc_stats_valid);
	ATF_CHECK_EQ(destination.vbsc_stats.vbs_present, 1U << 5);
	ATF_CHECK_EQ(destination.vbsc_stats.vbs_value[5],
	    UINT64_C(0x123456789));
	ATF_CHECK(!destination.vbsc_stats_req.outstanding);

	/* Older images carrying an unreconstructible live token fail closed. */
	memcpy(damaged, image, used);
	/* Version 3: two bitmap bytes end at 54, followed by stats_held. */
	damaged[54] = 1;
	destination.vbsc_stats.vbs_value[5] = 77;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), ENOTSUP);
	ATF_CHECK_EQ(destination.vbsc_stats.vbs_value[5], 77);
	ATF_CHECK(!destination.vbsc_stats_held);
	memcpy(damaged, image, used);
	/* Clearing stats_valid while preserving its sample is malformed. */
	damaged[55] = 0;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);
	destination.vbsc_vs.vs_negotiated_caps = 0;
	ATF_CHECK_EQ(run_balloon_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);

	free(destination.vbsc_bitmap);
	free(source.vbsc_bitmap);
}

/* Host-driven migration free-page-hint collection sink. */
struct migration_sink_capture {
	uint64_t gpa[8];
	size_t len[8];
	unsigned int count;
};

static int
migration_sink(void *arg, uint64_t gpa, size_t len)
{
	struct migration_sink_capture *cap = arg;

	if (cap->count < nitems(cap->gpa)) {
		cap->gpa[cap->count] = gpa;
		cap->len[cap->count] = len;
	}
	cap->count++;
	return (0);
}

static void
drive_hint_command(struct pci_vtballoon_softc *sc, struct vqueue_info *vq,
    uint32_t cmd)
{
	uint32_t command;

	reset_mocks();
	command = htole32(cmd);
	memcpy(g_pfn_bytes, &command, sizeof(command));
	g_pfn_len = sizeof(command);
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 0;
	pci_vtballoon_notify(sc, vq);
}

static void
drive_hint_range(struct pci_vtballoon_softc *sc, struct vqueue_info *vq,
    uint64_t gpa, size_t len)
{
	reset_mocks();
	g_reverse_gpa = gpa;
	g_pfn_len = len;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(sc, vq);
}

ATF_TC_WITHOUT_HEAD(free_page_migration_collect);
ATF_TC_BODY(free_page_migration_collect, tc)
{
	struct pci_vtballoon_softc sc;
	struct migration_sink_capture cap;
	struct vqueue_info vq;

	(void)tc;
	setup_softc(&sc, 4096);
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	vq.vq_qsize = VTBALLOON_RINGSZ;
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;

	/* Declined feature or not driver-OK: start fails, no round opens. */
	memset(&cap, 0, sizeof(cap));
	ATF_CHECK_EQ(virtio_balloon_migration_start(&sc, migration_sink, &cap),
	    ENXIO);
	ATF_CHECK(!sc.vbsc_migration_round);
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	ATF_CHECK_EQ(virtio_balloon_migration_start(&sc, migration_sink, &cap),
	    ENXIO);
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	/* A supported guest: start publishes a fresh command id and the sink. */
	reset_mocks();
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK(sc.vbsc_migration_round);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_FIRST);
	ATF_CHECK_EQ(g_config_changed_calls, 1);
	ATF_CHECK(!virtio_balloon_migration_complete(&sc));

	/* The guest starts the round, reports two ranges, then signals STOP. */
	drive_hint_command(&sc, &vq, sc.vbsc_free_page_hint_cmd_id);
	ATF_CHECK(sc.vbsc_free_page_hint_active);
	drive_hint_range(&sc, &vq, 0x8000, 4096);
	drive_hint_range(&sc, &vq, 0x9000, 8192);
	ATF_CHECK(!virtio_balloon_migration_complete(&sc));
	drive_hint_command(&sc, &vq, VTBALLOON_CMD_ID_STOP);

	/* The STOP marker completes the round without republishing config. */
	ATF_CHECK(virtio_balloon_migration_complete(&sc));
	ATF_CHECK_EQ(g_config_changed_calls, 0);
	ATF_CHECK_EQ(cap.count, 2u);
	ATF_CHECK_EQ(cap.gpa[0], 0x8000u);
	ATF_CHECK_EQ(cap.len[0], 4096u);
	ATF_CHECK_EQ(cap.gpa[1], 0x9000u);
	ATF_CHECK_EQ(cap.len[1], 8192u);
	/*
	 * Data-loss safety: the STOP descriptor is RETAINED, not completed, at
	 * this point.  The guest driver frees its reported pages back to the
	 * allocator only once this descriptor is returned, so holding it keeps
	 * those pages unwritten until the collector's initial snapshot.  A build
	 * that completed STOP here would reopen the reallocate-and-write window.
	 */
	ATF_CHECK(sc.vbsc_migration_stop_held);
	ATF_CHECK_EQ(g_rel_calls, 0);

	/* Finish publishes DONE, releases the STOP descriptor, closes the round. */
	reset_mocks();
	virtio_balloon_migration_finish(&sc);
	ATF_CHECK(!sc.vbsc_migration_round);
	ATF_CHECK(sc.vbsc_migration_sink == NULL);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_DONE);
	ATF_CHECK_EQ(g_config_changed_calls, 1);
	/* Only now is the guest released to reuse its reported pages. */
	ATF_CHECK(!sc.vbsc_migration_stop_held);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK(!virtio_balloon_migration_complete(&sc));

	/* A device reset abandons any in-flight round (skip nothing). */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK(sc.vbsc_migration_round);
	pci_vtballoon_migration_abandon(&sc);
	ATF_CHECK(!sc.vbsc_migration_round);
	ATF_CHECK(sc.vbsc_migration_sink == NULL);

	/*
	 * Abandoning a round that has already retained its STOP descriptor
	 * releases that descriptor (skip nothing) without leaking it or forcing
	 * a device reset.
	 */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	drive_hint_command(&sc, &vq, sc.vbsc_free_page_hint_cmd_id);
	drive_hint_command(&sc, &vq, VTBALLOON_CMD_ID_STOP);
	ATF_CHECK(sc.vbsc_migration_stop_held);
	reset_mocks();
	pci_vtballoon_migration_abandon(&sc);
	ATF_CHECK(!sc.vbsc_migration_round);
	ATF_CHECK(!sc.vbsc_migration_stop_held);
	ATF_CHECK_EQ(g_needs_reset, 0);
}

ATF_TC_WITHOUT_HEAD(migration_wait_and_lookup);
ATF_TC_BODY(migration_wait_and_lookup, tc)
{
	struct pci_vtballoon_softc sc;
	struct migration_sink_capture cap;

	(void)tc;
	setup_softc(&sc, 4096);
	memset(&cap, 0, sizeof(cap));

	/* NULL-argument contracts on the pre-copy bridge entry points. */
	ATF_CHECK_EQ(virtio_balloon_migration_wait(NULL, 0), EINVAL);
	ATF_CHECK(virtio_balloon_migration_complete(NULL) == false);
	ATF_CHECK_EQ(virtio_balloon_migration_start(NULL, migration_sink, &cap),
	    EINVAL);
	ATF_CHECK_EQ(virtio_balloon_migration_start(&sc, NULL, &cap), EINVAL);
	virtio_balloon_migration_finish(NULL);

	/* The registry publishes the live instance for the collector. */
	ATF_CHECK(virtio_balloon_migration_lookup() == NULL);
	pci_vtballoon_registry = &sc;
	ATF_CHECK(virtio_balloon_migration_lookup() == &sc);
	pci_vtballoon_registry = NULL;

	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	/* With no round in progress the wait reports the round was cancelled. */
	ATF_CHECK_EQ(virtio_balloon_migration_wait(&sc, 0), ECANCELED);

	/* An already-complete round returns immediately without blocking. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	sc.vbsc_migration_complete = true;
	ATF_CHECK_EQ(virtio_balloon_migration_wait(&sc, 100), 0);
	virtio_balloon_migration_finish(&sc);

	/* An incomplete round drains its deadline through the condition var. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(virtio_balloon_migration_wait(&sc, 1), ETIMEDOUT);
	virtio_balloon_migration_finish(&sc);

	/* collect() runs start+wait+finish; a timeout still finishes cleanly. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_CHECK_EQ(virtio_balloon_migration_collect(&sc, migration_sink,
	    &cap, 1), ETIMEDOUT);
	ATF_CHECK(!sc.vbsc_migration_round);

	/* collect() propagates a start failure without waiting or finishing. */
	reset_mocks();
	sc.vbsc_vs.vs_status = 0;
	ATF_CHECK_EQ(virtio_balloon_migration_collect(&sc, migration_sink,
	    &cap, 1), ENXIO);

	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(migration_cmd_id_rollover);
ATF_TC_BODY(migration_cmd_id_rollover, tc)
{
	struct pci_vtballoon_softc sc;
	struct migration_sink_capture cap;

	(void)tc;
	setup_softc(&sc, 4096);
	memset(&cap, 0, sizeof(cap));
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;

	/* A below-FIRST seed is lifted to the first legal command id. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_STOP;
	sc.vbsc_free_page_hint_cmd_id = VTBALLOON_CMD_ID_DONE;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_FIRST);
	virtio_balloon_migration_finish(&sc);

	/* Starting a second round while one is live is rejected as busy. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), EBUSY);
	virtio_balloon_migration_finish(&sc);

	/* A seed colliding with the visible id is bumped one past it. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	sc.vbsc_free_page_hint_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id,
	    VTBALLOON_CMD_ID_FIRST + 1);
	virtio_balloon_migration_finish(&sc);

	/* At the numeric ceiling a colliding seed wraps the publish to FIRST. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = UINT32_MAX;
	sc.vbsc_free_page_hint_cmd_id = UINT32_MAX;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_FIRST);
	virtio_balloon_migration_finish(&sc);

	/* A ceiling seed with no collision wraps only the stored seed. */
	reset_mocks();
	sc.vbsc_migration_next_cmd_id = UINT32_MAX;
	sc.vbsc_free_page_hint_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, UINT32_MAX);
	ATF_CHECK_EQ(sc.vbsc_migration_next_cmd_id, VTBALLOON_CMD_ID_FIRST);
	virtio_balloon_migration_finish(&sc);

	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(debug_logging_paths);
ATF_TC_BODY(debug_logging_paths, tc)
{
	struct pci_vtballoon_softc sc;
	struct vqueue_info vq;
	struct vqueue_info *sq;
	static const uint8_t encoded[] = {
		/* MEMFREE (tag 4), 4096 bytes. */
		0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	(void)tc;
	setup_softc(&sc, 4096);
	sc.vbsc_debug = 1;
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTBALLOON_RINGSZ;

	/* Inflate request completion logging. */
	reset_mocks();
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	le32enc(g_pfn_bytes, 1);
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);

	/* Free-page-hint start and per-range logging. */
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	sc.vbsc_free_page_hint_cmd_id = VIRTIO14_BALLOON_CMD_ID_FIRST;
	drive_hint_command(&sc, &vq, VIRTIO14_BALLOON_CMD_ID_FIRST);
	drive_hint_range(&sc, &vq, 0x8000, 4096);
	ATF_CHECK_EQ(g_discard_calls, 1);

	/* A failed discard logs the stop reason and ends the round. */
	reset_mocks();
	g_reverse_gpa = 0x8000;
	g_pfn_len = 4096;
	g_chain_n = 1;
	g_readable = 0;
	g_writable = 1;
	g_discard_error = EIO;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK(!sc.vbsc_free_page_hint_active);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_STOP);

	/* STOP round-done logging on the non-migration path. */
	drive_hint_command(&sc, &vq, VTBALLOON_CMD_ID_STOP);
	ATF_CHECK_EQ(sc.vbsc_free_page_hint_cmd_id, VTBALLOON_CMD_ID_DONE);

	/* Free-page report logging. */
	reset_mocks();
	vq.vq_num = VTBALLOON_REPORTING_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 1);

	/* Poison-preserving report logging (no discard applied). */
	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_PAGE_REPORTING |
	    VIRTIO_BALLOON_F_PAGE_POISON;
	g_pfn_len = 4096;
	g_readable = 0;
	g_writable = 1;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_discard_calls, 0);

	/* Poison config-write logging. */
	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_PAGE_POISON;
	sc.vbsc_vs.vs_status = 0;
	ATF_REQUIRE_EQ(pci_vtballoon_cfgwrite(&sc,
	    VIRTIO14_BALLOON_POISON_VAL_OFF, 4, UINT32_C(0x1234)), 0);

	/* Statistics sample and timer-driven refresh logging. */
	sq = &sc.vbsc_vq[VTBALLOON_STATS_QUEUE];
	sq->vq_vs = &sc.vbsc_vs;
	sq->vq_num = VTBALLOON_STATS_QUEUE;
	sq->vq_qsize = 8;
	sq->vq_layout = VIRTIO_QUEUE_SPLIT;
	sq->vq_generation = 11;
	vq_set_allocated(sq, true);
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_STATS_VQ;
	reset_mocks();
	memcpy(g_pfn_bytes, encoded, sizeof(encoded));
	g_pfn_len = sizeof(encoded);
	pci_vtballoon_notify(&sc, sq);
	ATF_REQUIRE(sc.vbsc_stats_held);
	pci_vtballoon_stats_timer(1000, EVF_TIMER, &sc);
	ATF_CHECK(!sc.vbsc_stats_held);
	ATF_CHECK_EQ(g_rel_calls, 1);

	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(error_and_edge_branches);
ATF_TC_BODY(error_and_edge_branches, tc)
{
	struct pci_vtballoon_softc sc;
	struct migration_sink_capture cap;
	struct vqueue_info vq;
	uint32_t value;

	(void)tc;
	setup_softc(&sc, 4096);
	memset(&cap, 0, sizeof(cap));
	memset(&vq, 0, sizeof(vq));
	vq.vq_qsize = VTBALLOON_RINGSZ;

	/* Releasing statistics with nothing retained is a no-op. */
	reset_mocks();
	sc.vbsc_stats_held = false;
	ATF_REQUIRE_EQ(pci_vtballoon_suspend_device(&sc), 0);
	ATF_CHECK_EQ(g_rel_calls, 0);

	/* A queue reset for a stale generation is refused. */
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	vq.vq_generation = 5;
	ATF_CHECK_EQ(pci_vtballoon_qreset(&sc, &vq, 6), ESTALE);

	/* cfgread rejects malformed offset/size tuples. */
	ATF_CHECK_EQ(pci_vtballoon_cfgread(&sc, -1, 4, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtballoon_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtballoon_cfgread(&sc, 4096, 4, &value), EINVAL);

	/* cfgwrite rejects a non-dword access width. */
	ATF_CHECK_EQ(pci_vtballoon_cfgwrite(&sc, 4, 2, 0), EINVAL);

	/* Snapshot validation rejects a device instance with no softc. */
	{
		struct pci_devinst pi;
		struct vm_snapshot_meta vmeta = { .op = VM_SNAPSHOT_VALIDATE };

		memset(&pi, 0, sizeof(pi));
		pi.pi_arg = NULL;
		vmeta.dev_data = &pi;
		ATF_CHECK_EQ(pci_vtballoon_snapshot_validate(&vmeta), EINVAL);
	}

	/* An empty descriptor chain ends the inflate/deflate drain loop. */
	reset_mocks();
	vq.vq_num = VTBALLOON_INFLATE_QUEUE;
	g_descs = 1;
	g_chain_n = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_end_calls, 1);

	/* An empty free-page-hint chain breaks that loop and ends chains. */
	reset_mocks();
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	g_descs = 1;
	g_chain_n = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_end_calls, 1);

	/* An empty reporting chain breaks that loop and ends chains. */
	reset_mocks();
	vq.vq_num = VTBALLOON_REPORTING_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_PAGE_REPORTING;
	g_descs = 1;
	g_chain_n = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_end_calls, 1);

	/* An empty statistics chain returns without endchains. */
	reset_mocks();
	vq.vq_num = VTBALLOON_STATS_QUEUE;
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_STATS_VQ;
	sc.vbsc_stats_held = false;
	g_descs = 1;
	g_chain_n = 0;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_end_calls, 0);

	/* A statistics chain carrying a writable buffer is rejected. */
	reset_mocks();
	g_descs = 1;
	g_chain_n = 1;
	g_readable = 1;
	g_writable = 1;
	g_pfn_len = VIRTIO14_BALLOON_STAT_SIZE;
	pci_vtballoon_notify(&sc, &vq);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK(!sc.vbsc_stats_held);

	/*
	 * STOP under a live migration round with a ready condition variable
	 * broadcasts to the collector; abandoning the round then releases the
	 * retained STOP descriptor and wakes any waiter without a device reset.
	 */
	reset_mocks();
	sc.vbsc_vs.vs_negotiated_caps = VIRTIO_BALLOON_F_FREE_PAGE_HINT;
	sc.vbsc_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vbsc_migration_cv_ready = true;
	sc.vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;
	ATF_REQUIRE_EQ(virtio_balloon_migration_start(&sc, migration_sink,
	    &cap), 0);
	vq.vq_num = VTBALLOON_FREE_PAGE_QUEUE;
	drive_hint_command(&sc, &vq, sc.vbsc_free_page_hint_cmd_id);
	drive_hint_command(&sc, &vq, VTBALLOON_CMD_ID_STOP);
	ATF_CHECK(virtio_balloon_migration_complete(&sc));
	ATF_CHECK(sc.vbsc_migration_stop_held);
	sc.vbsc_migration_cv_ready = true;
	pci_vtballoon_migration_abandon(&sc);
	ATF_CHECK(!sc.vbsc_migration_round);
	ATF_CHECK(!sc.vbsc_migration_stop_held);
	ATF_CHECK_EQ(g_needs_reset, 0);

	free(sc.vbsc_bitmap);
}

ATF_TC_WITHOUT_HEAD(initialization_failure_paths);
ATF_TC_BODY(initialization_failure_paths, tc)
{
	struct pci_devinst pi;
	struct nvlist nvl;
	struct pci_vtballoon_softc *sc;

	(void)tc;
	memset(&nvl, 0, sizeof(nvl));

	/* The debug environment override is parsed at construction. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	setenv("BHYVE_VIRTIO_DEBUG", "2", 1);
	ATF_REQUIRE_EQ(pci_vtballoon_init(&pi, &nvl), 0);
	sc = (struct pci_vtballoon_softc *)pi.pi_arg;
	ATF_REQUIRE(sc != NULL);
	ATF_CHECK_EQ(sc->vbsc_debug, 2u);
	pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc->vbsc_bitmap);
	free(sc);
	unsetenv("BHYVE_VIRTIO_DEBUG");

	/* Transport selection failure aborts construction. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_transport_fail = true;
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);

	/* Interrupt setup failure aborts construction. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_intr_fail = true;
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);

	/* Modern-PCI init failure aborts construction after interrupt setup. */
	reset_mocks();
	memset(&pi, 0, sizeof(pi));
	g_modern_fail = true;
	ATF_CHECK_EQ(pci_vtballoon_init(&pi, &nvl), 1);
}

ATF_TC_WITHOUT_HEAD(snapshot_bitmap_partial_byte);
ATF_TC_BODY(snapshot_bitmap_partial_byte, tc)
{
	struct pci_vtballoon_softc src, dst;
	uint8_t image[256];
	size_t used, bitmap_size;

	(void)tc;
	/* Seven pages: the final bitmap byte carries valid bits 0..6 only. */
	memset(&src, 0, sizeof(src));
	ATF_REQUIRE_EQ(virtio_balloon_tracker_required(0x7000, 0, 0,
	    &bitmap_size), 0);
	ATF_REQUIRE_EQ(bitmap_size, 1u);
	src.vbsc_bitmap = calloc(1, bitmap_size);
	ATF_REQUIRE(src.vbsc_bitmap != NULL);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&src.vbsc_tracker, 0x7000,
	    0, 0, 4096, src.vbsc_bitmap, bitmap_size), 0);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(&src.vbsc_accounting,
	    0x7000, 0), 0);
	src.vbsc_lowmem_size = 0x7000;
	src.vbsc_consts = vtballoon_vi_consts;
	src.vbsc_vs.vs_vc = &src.vbsc_consts;
	src.vbsc_vs.vs_queues = src.vbsc_vq;

	reset_mocks();
	ATF_REQUIRE_EQ(run_balloon_snapshot(&src, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	memset(&dst, 0, sizeof(dst));
	dst.vbsc_bitmap = calloc(1, bitmap_size);
	ATF_REQUIRE(dst.vbsc_bitmap != NULL);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&dst.vbsc_tracker, 0x7000,
	    0, 0, 4096, dst.vbsc_bitmap, bitmap_size), 0);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(&dst.vbsc_accounting,
	    0x7000, 0), 0);
	dst.vbsc_lowmem_size = 0x7000;
	dst.vbsc_consts = vtballoon_vi_consts;
	dst.vbsc_vs.vs_vc = &dst.vbsc_consts;
	dst.vbsc_vs.vs_queues = dst.vbsc_vq;

	/* A clean image with a partial trailing byte restores. */
	ATF_REQUIRE_EQ(run_balloon_snapshot(&dst, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);

	/* Setting an out-of-range bit in the trailing byte is rejected. */
	image[52] = (uint8_t)0x80;
	ATF_CHECK_EQ(run_balloon_snapshot(&dst, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), EINVAL);

	free(src.vbsc_bitmap);
	free(dst.vbsc_bitmap);

	/* A zero-page device carries an empty bitmap that always validates. */
	memset(&src, 0, sizeof(src));
	ATF_REQUIRE_EQ(virtio_balloon_tracker_required(0, 0, 0,
	    &bitmap_size), 0);
	ATF_REQUIRE_EQ(bitmap_size, 0u);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&src.vbsc_tracker, 0, 0, 0,
	    4096, NULL, 0), 0);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(&src.vbsc_accounting,
	    0, 0), 0);
	src.vbsc_consts = vtballoon_vi_consts;
	src.vbsc_vs.vs_vc = &src.vbsc_consts;
	src.vbsc_vs.vs_queues = src.vbsc_vq;
	reset_mocks();
	ATF_REQUIRE_EQ(run_balloon_snapshot(&src, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE_EQ(run_balloon_snapshot(&src, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, inflate_deflate_and_host_granule);
	ATF_TP_ADD_TC(tp, advertised_contract);
	ATF_TP_ADD_TC(tp, notification_budget_is_queue_bounded);
	ATF_TP_ADD_TC(tp, pfn_duplicates_and_invalid_ranges);
	ATF_TP_ADD_TC(tp, statistics_retained_chain_lifecycle);
	ATF_TP_ADD_TC(tp, initialization_contract);
	ATF_TP_ADD_TC(tp, descriptor_and_config_validation);
	ATF_TP_ADD_TC(tp, free_page_hinting);
	ATF_TP_ADD_TC(tp, free_page_migration_collect);
	ATF_TP_ADD_TC(tp, free_page_reporting);
	ATF_TP_ADD_TC(tp, reset_retains_target);
	ATF_TP_ADD_TC(tp, snapshot_preflight_is_locally_serialized);
	ATF_TP_ADD_TC(tp, snapshot_wire_validation_and_repeat);
	ATF_TP_ADD_TC(tp, statistics_snapshot_ownership);
	ATF_TP_ADD_TC(tp, migration_wait_and_lookup);
	ATF_TP_ADD_TC(tp, migration_cmd_id_rollover);
	ATF_TP_ADD_TC(tp, debug_logging_paths);
	ATF_TP_ADD_TC(tp, error_and_edge_branches);
	ATF_TP_ADD_TC(tp, initialization_failure_paths);
	ATF_TP_ADD_TC(tp, snapshot_bitmap_partial_byte);
	return (atf_no_error());
}
