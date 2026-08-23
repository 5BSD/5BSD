/* Device-composition tests for bhyve's VirtIO 1.4 memory device. */
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stdint.h>
#include <pthread_np.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "debug.h"
#include "virtio_mem_host.c"

/*
 * A rootless harness build can use the installed machine/vmm.h while testing
 * a newer source-tree vmmapi.h.  The API needs only this tag at the point
 * pci_virtio_mem.c includes vmmapi.h; production builds get its definition
 * from the matching source-tree machine header.
 */
struct vm_cpu_compat;

#define	BHYVE_SNAPSHOT
#include "pci_virtio_mem.c"
#include "virtio_config_read_test_support.h"
#include "virtio_1_4_spec.h"

enum {
	DUT_MEM_DEVICE_ID = VIRTIO_ID_MEM,
};

#define	DOC_REQ_PLUG	0U
#define	DOC_RESP_ACK	0U
#define	DOC_BLOCK	UINT64_C(0x200000)
#define	DOC_BASE	UINT64_C(0x40000000)
/*
 * Independent VirtIO 1.4 virtio-mem protocol constants (section 5.15.6).  These
 * are derived from the specification, never read back from the device, so an
 * accidental change in the implementation cannot make the tests agree with it.
 */
#define	DOC_REQ_UNPLUG		1U
#define	DOC_REQ_UNPLUG_ALL	2U
#define	DOC_REQ_STATE		3U
#define	DOC_RESP_NACK		1U
#define	DOC_RESP_BUSY		2U
#define	DOC_RESP_ERROR		3U
#define	DOC_STATE_PLUGGED	0U
#define	DOC_STATE_UNPLUGGED	1U
#define	DOC_STATE_MIXED		2U
/* Private checkpoint ABI fixture; do not take expected bytes from the DUT. */
#define	DOC_VTMEM_SNAPSHOT_MAGIC	UINT32_C(0x314d4556) /* "VEM1" */
#define	DOC_VTMEM_SNAPSHOT_VERSION	2U

#undef VIRTIO_ID_MEM
#define	VIRTIO_ID_MEM	VIRTIO14_DEVICE_MEM
#undef VIRTIO_F_IN_ORDER
#define	VIRTIO_F_IN_ORDER	VIRTIO14_F_IN_ORDER
#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED	VIRTIO14_F_RING_PACKED
#undef VIRTIO_F_RING_RESET
#define	VIRTIO_F_RING_RESET	VIRTIO14_F_RING_RESET
#undef VIRTIO_F_SUSPEND
#define	VIRTIO_F_SUSPEND	VIRTIO14_F_SUSPEND

struct nvlist {
	int unused;
};

static uint8_t g_request[BHYVE_VTMEM_REQUEST_SIZE];
static uint8_t g_response[BHYVE_VTMEM_RESPONSE_SIZE];
static int g_descs, g_chain_n, g_readable, g_writable;
static bool g_ordered;
static int g_rel_calls, g_end_calls, g_needs_reset, g_dirty_calls;
static uint32_t g_rel_len;
static unsigned int g_set_range_calls;
static int g_short_write;
static int g_bad_insize;
static int g_getchain_ret;	/* 0 = normal; <=0 forces early break */

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

int
vi_pci_snapshot(struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

int
vi_pci_snapshot_compat(struct pci_devinst *pi __unused,
    struct pci_snapshot_compat *compat __unused)
{

	return (0);
}

int
vi_pci_pause(struct pci_devinst *pi __unused)
{

	return (0);
}

int
vi_pci_resume(struct pci_devinst *pi __unused)
{

	return (0);
}

static int
model_set_range(void *arg __unused, uint64_t address, uint64_t length,
    bool plug)
{

	ATF_CHECK_EQ(address, DOC_BASE);
	ATF_CHECK_EQ(length, DOC_BLOCK);
	ATF_CHECK(plug);
	g_set_range_calls++;
	return (0);
}

static void
reset_mocks(void)
{

	memset(g_request, 0, sizeof(g_request));
	memset(g_response, 0xa5, sizeof(g_response));
	le16enc(g_request, DOC_REQ_PLUG);
	le64enc(g_request + 8, DOC_BASE);
	le16enc(g_request + 16, 1);
	g_descs = 1;
	g_chain_n = 4;
	g_readable = 2;
	g_writable = 2;
	g_ordered = true;
	g_rel_calls = 0;
	g_end_calls = 0;
	g_needs_reset = 0;
	g_dirty_calls = 0;
	g_rel_len = UINT32_MAX;
	g_set_range_calls = 0;
	g_short_write = 0;
	g_bad_insize = 0;
	g_getchain_ret = 0;
}

static void
setup_softc(struct pci_vtmem_softc *sc)
{
	const struct virtio_mem_host_limits limits = {
		.block_size = DOC_BLOCK,
		.address = DOC_BASE,
		.region_size = DOC_BLOCK * 2,
		.usable_region_size = DOC_BLOCK * 2,
		.requested_size = DOC_BLOCK,
		.max_blocks = 2,
	};
	struct virtio_mem_host_ops ops = {
		.set_range = model_set_range,
		.config_changed = pci_vtmem_config_changed,
		.arg = sc,
	};

	memset(sc, 0, sizeof(*sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc->vmsc_mtx, NULL), 0);
	sc->vmsc_vs.vs_mtx = &sc->vmsc_mtx;
	ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops,
	    &sc->vmsc_host), 0);
	sc->vmsc_consts = vtmem_vi_consts;
	sc->vmsc_vs.vs_vc = &sc->vmsc_consts;
	sc->vmsc_vq.vq_qsize = VTMEM_RINGSZ;
}

static void
teardown_softc(struct pci_vtmem_softc *sc)
{

	virtio_mem_host_destroy(sc->vmsc_host);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc->vmsc_mtx), 0);
}

static int
run_mem_snapshot(struct pci_vtmem_softc *sc, void *buffer, size_t size,
    enum vm_snapshot_op op, size_t *used)
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

	error = pci_vtmem_snapshot(sc, &meta);
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

	ATF_REQUIRE_EQ(niov, VTMEM_MAXSEGS);
	ATF_REQUIRE(g_chain_n <= niov);
	if (g_getchain_ret <= 0 && g_getchain_ret != 0) {
		g_descs--;
		return (g_getchain_ret);
	}
	memset(req, 0, sizeof(*req));
	req->idx = 11;
	req->readable = g_readable;
	req->writable = g_writable;
	req->ordered = g_ordered;
	iov[0].iov_base = g_request;
	iov[0].iov_len = 5;
	iov[1].iov_base = g_request + 5;
	iov[1].iov_len = sizeof(g_request) - 5;
	if (g_bad_insize != 0)
		iov[1].iov_len -= 1;	/* readable total != request size */
	iov[2].iov_base = g_response;
	iov[2].iov_len = 3;
	iov[3].iov_base = g_response + 3;
	iov[3].iov_len = sizeof(g_response) - 3;
	g_descs--;
	return (g_chain_n);
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx, uint32_t len)
{

	ATF_CHECK_EQ(idx, 11);
	g_rel_calls++;
	g_rel_len = len;
}

void
vq_endchains(struct vqueue_info *vq __unused, int all_avail)
{

	ATF_CHECK_EQ(all_avail, 1);
	g_end_calls++;
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

size_t
buf_to_iov(const void *buffer, size_t length, const struct iovec *iov,
    size_t niov)
{
	const uint8_t *source;
	size_t copied;

	source = buffer;
	copied = 0;
	for (size_t i = 0; i < niov && copied < length; i++) {
		size_t count;

		count = MIN(iov[i].iov_len, length - copied);
		memcpy(iov[i].iov_base, source + copied, count);
		copied += count;
	}
	if (g_short_write != 0 && copied == length)
		return (copied - 1);
	return (copied);
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	g_needs_reset++;
}

void
vi_snapshot_restore_incomplete(struct virtio_softc *vs)
{

	vs->vs_restore_incomplete = true;
	vi_set_needs_reset(vs);
}

void
vi_pci_modern_config_dirty(struct virtio_softc *vs __unused)
{

	g_dirty_calls++;
}

void
vi_pci_config_changed(struct virtio_softc *vs)
{
	int error;

	ATF_REQUIRE(vs->vs_mtx != NULL);
	error = pthread_mutex_trylock(vs->vs_mtx);
	ATF_REQUIRE_EQ(error, EBUSY);
	g_dirty_calls++;
}

void
vi_reset_dev(struct virtio_softc *vs __unused)
{
}

int
vi_pci_lifecycle_noop(void *arg __unused)
{

	return (0);
}

/*
 * Fault-injection controls and platform/transport stubs used to drive
 * pci_vtmem_init() and its unwind paths.  The device under test is
 * pci_virtio_mem.c only; these stubs stand in for the bhyve transport,
 * configuration, and vmmapi layers that a rootless harness cannot provide.
 */
static const char *g_cfg_size;
static const char *g_cfg_block;
static const char *g_cfg_requested;
static bool g_cfg_packed;
static int g_alloc_gpa_ret;
static bool g_gpa_unaligned;
static bool g_devmem_fail;
static bool g_devmem_undersize;
static int g_mmap_ret;
static int g_select_ret;
static int g_intr_ret;
static int g_modern_ret;
static void *g_devmem_map;
static int g_munmap_calls;
static bool g_fail_calloc;
static bool g_fail_malloc;
static bool g_fail_mutex_init;

extern void *__real_calloc(size_t, size_t);
extern void *__real_malloc(size_t);
extern int __real_pthread_mutex_init(pthread_mutex_t *,
    const pthread_mutexattr_t *);
void *__wrap_calloc(size_t, size_t);
void *__wrap_malloc(size_t);
int __wrap_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (g_fail_calloc)
		return (NULL);
	return (__real_calloc(nmemb, size));
}

void *
__wrap_malloc(size_t size)
{

	if (g_fail_malloc)
		return (NULL);
	return (__real_malloc(size));
}

int
__wrap_pthread_mutex_init(pthread_mutex_t *mtx, const pthread_mutexattr_t *attr)
{

	if (g_fail_mutex_init)
		return (EAGAIN);
	return (__real_pthread_mutex_init(mtx, attr));
}

static void
init_reset(void)
{

	g_cfg_size = "0x400000";	/* 4 MiB region */
	g_cfg_block = NULL;		/* default 2 MiB block size */
	g_cfg_requested = NULL;
	g_cfg_packed = false;
	g_alloc_gpa_ret = 0;
	g_gpa_unaligned = false;
	g_devmem_fail = false;
	g_devmem_undersize = false;
	g_mmap_ret = 0;
	g_select_ret = 0;
	g_intr_ret = 0;
	g_modern_ret = 0;
	g_devmem_map = MAP_FAILED;
	g_munmap_calls = 0;
	g_fail_calloc = false;
	g_fail_malloc = false;
	g_fail_mutex_init = false;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "size") == 0)
		return (g_cfg_size);
	if (strcmp(name, "block-size") == 0)
		return (g_cfg_block);
	if (strcmp(name, "requested") == 0)
		return (g_cfg_requested);
	return (NULL);
}

bool
get_config_bool_node_default(const nvlist_t *nvl __unused, const char *name,
    bool value)
{

	if (strcmp(name, "packed") == 0)
		return (g_cfg_packed);
	return (value);
}

int
vm_parse_memsize(const char *str, size_t *ret_memsize)
{

	if (strcmp(str, "BAD") == 0)
		return (-1);
	*ret_memsize = (size_t)strtoull(str, NULL, 0);
	return (0);
}

int
pci_emul_alloc_devmem_gpa(uint64_t size __unused, uint64_t alignment __unused,
    uint64_t *addr)
{

	if (g_alloc_gpa_ret != 0)
		return (g_alloc_gpa_ret);
	/* An unaligned base is accepted here but rejected by host_create(). */
	*addr = g_gpa_unaligned ? DOC_BASE + 0x1000 : DOC_BASE;
	return (0);
}

void *
vm_create_devmem_auto(struct vmctx *ctx __unused, const char *name __unused,
    size_t len, int *segid)
{
	size_t maplen;

	if (g_devmem_fail)
		return (MAP_FAILED);
	*segid = 7;
	maplen = g_devmem_undersize ? (size_t)getpagesize() : len;
	g_devmem_map = mmap(NULL, maplen, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (g_devmem_map == MAP_FAILED)
		return (MAP_FAILED);
	/*
	 * A NULL base (still distinct from MAP_FAILED) makes the region-wide
	 * madvise() in pci_vtmem_init() fail deterministically: madvise()
	 * rejects a NULL address with EINVAL.
	 */
	if (g_devmem_undersize)
		return (NULL);
	return (g_devmem_map);
}

int
vm_mmap_memseg(struct vmctx *ctx __unused, vm_paddr_t gpa __unused,
    int segid __unused, vm_ooffset_t segoff __unused, size_t len __unused,
    int prot __unused)
{

	return (g_mmap_ret);
}

int
vm_munmap_memseg(struct vmctx *ctx __unused, vm_paddr_t gpa __unused,
    size_t len __unused)
{

	g_munmap_calls++;
	return (0);
}

void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *dev_softc __unused, struct pci_devinst *pi,
    struct vqueue_info *queues __unused)
{

	vs->vs_vc = vc;
	vs->vs_pi = pi;
}

int
vi_pci_select_transport(struct virtio_softc *vs, const struct nvlist *nvl
    __unused, enum virtio_pci_transport_policy policy __unused)
{

	if (g_select_ret != 0)
		return (g_select_ret);
	vs->vs_modern = malloc(sizeof(void *));
	return (0);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t device_id __unused)
{
}

int
vi_intr_init(struct virtio_softc *vs, int barnum __unused, int use_msix __unused)
{

	if (g_intr_ret != 0)
		return (g_intr_ret);
	(void)pthread_mutex_init(&vs->vs_isr_mtx, NULL);
	return (0);
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int barnum __unused)
{

	return (g_modern_ret);
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t val)
{

	pi->pi_cfgdata[offset] = val;
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t value __unused)
{

	return (0);
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *value __unused)
{

	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int baridx __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

ATF_TC_WITHOUT_HEAD(fragmented_request_completes_once);
ATF_TC_BODY(fragmented_request_completes_once, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_set_range_calls, 1U);
	ATF_CHECK_EQ(le16dec(g_response), DOC_RESP_ACK);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, BHYVE_VTMEM_RESPONSE_SIZE);
	ATF_CHECK_EQ(g_end_calls, 1);
	ATF_CHECK_EQ(g_needs_reset, 0);
	/*
	 * VirtIO 1.4 section 5.15.4.2 says not to notify merely because
	 * plugged_size changed.
	 */
	ATF_CHECK_EQ(g_dirty_calls, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(composition_contract);
ATF_TC_BODY(composition_contract, tc)
{
	uint64_t expected;

	expected = VIRTIO14_F_RING_RESET | VIRTIO14_F_SUSPEND;
	ATF_CHECK_EQ(DUT_MEM_DEVICE_ID, VIRTIO14_DEVICE_MEM);
	ATF_CHECK_STREQ(pci_de_vtmem.pe_emu, "virtio-mem");
	ATF_CHECK_STREQ(vtmem_vi_consts.vc_name, "vtmem");
	ATF_CHECK_EQ(vtmem_vi_consts.vc_nvq, 1);
	ATF_CHECK_EQ(vtmem_vi_consts.vc_cfgsize, VIRTIO14_MEM_CONFIG_SIZE);
	ATF_CHECK_EQ(vtmem_vi_consts.vc_hv_caps, expected);
	/*
	 * Requests and platform range changes are synchronous under the common
	 * device lock, so no device-private drain is necessary.  Suspend still
	 * needs device callbacks to freeze the guest-visible configuration
	 * while a host requested-size update is retained for resume.
	 */
	ATF_CHECK(vtmem_vi_consts.vc_suspend == pci_vtmem_suspend);
	ATF_CHECK(vtmem_vi_consts.vc_resume_device ==
	    pci_vtmem_resume);
	ATF_CHECK(vtmem_vi_consts.vc_pause == vi_pci_lifecycle_noop);
	ATF_CHECK(vtmem_vi_consts.vc_resume == vi_pci_lifecycle_noop);
	ATF_CHECK(vtmem_vi_consts.vc_restore_suspended ==
	    pci_vtmem_restore_suspended);
	ATF_CHECK_EQ(VTMEM_RINGSZ, 128);
}

ATF_TC_WITHOUT_HEAD(malformed_chain_sets_needs_reset);
ATF_TC_BODY(malformed_chain_sets_needs_reset, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_ordered = false;
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_set_range_calls, 0U);
	ATF_CHECK_EQ(g_rel_calls, 1);
	ATF_CHECK_EQ(g_rel_len, 0U);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_dirty_calls, 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_preserves_plugged_state);
ATF_TC_BODY(reset_preserves_plugged_state, tc)
{
	struct pci_vtmem_softc sc;
	struct virtio_mem_host_config config;

	reset_mocks();
	setup_softc(&sc);
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	pci_vtmem_reset(&sc);
	virtio_mem_host_get_config(sc.vmsc_host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(reset_preserves_incomplete_restore_failure);
ATF_TC_BODY(reset_preserves_incomplete_restore_failure, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	/*
	 * The host model sets this only when rollback could not revoke a range
	 * reconstructed during restore.  Device reset must retain NEEDS_RESET
	 * until a later restore/system-reset operation repairs that ownership.
	 */
	sc.vmsc_host->restore_incomplete = true;
	ATF_CHECK(virtio_mem_host_restore_incomplete(sc.vmsc_host));
	pci_vtmem_reset(&sc);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK(sc.vmsc_host->restore_incomplete);
	ATF_CHECK(virtio_mem_host_restore_incomplete(sc.vmsc_host));
	ATF_CHECK(sc.vmsc_vs.vs_restore_incomplete);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(requested_size_notifies_under_device_lock);
ATF_TC_BODY(requested_size_notifies_under_device_lock, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(sc.vmsc_host,
	    DOC_BLOCK * 2), 0);
	ATF_CHECK_EQ(g_dirty_calls, 1);
	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(sc.vmsc_host,
	    DOC_BLOCK * 2), 0);
	ATF_CHECK_EQ(g_dirty_calls, 1);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(unplug_discards_but_keeps_mapping);
ATF_TC_BODY(unplug_discards_but_keeps_mapping, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t *mapping;

	memset(&sc, 0, sizeof(sc));
	mapping = mmap(NULL, (size_t)DOC_BLOCK, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	memset(mapping, 0x5a, (size_t)DOC_BLOCK);
	sc.vmsc_host_base = mapping;
	sc.vmsc_gpa = DOC_BASE;
	sc.vmsc_region_size = (size_t)DOC_BLOCK;
	ATF_CHECK_EQ(pci_vtmem_set_range(&sc, DOC_BASE, DOC_BLOCK, false), 0);
	mapping[0] = 0xa5;
	ATF_CHECK_EQ(mapping[0], 0xa5);
	ATF_CHECK_EQ(munmap(mapping, (size_t)DOC_BLOCK), 0);
}

ATF_TC_WITHOUT_HEAD(config_reads_decode_little_endian);
ATF_TC_BODY(config_reads_decode_little_endian, tc)
{
	struct pci_vtmem_softc sc;
	uint32_t value;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, (uint32_t)DOC_BLOCK);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 16, 4, &value), 0);
	ATF_CHECK_EQ(value, (uint32_t)DOC_BASE);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 8, 2, &value), 0);
	ATF_CHECK_EQ(value, 0U);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 10, 1, &value), 0);
	ATF_CHECK_EQ(value, 0U);
	ATF_CHECK_EQ(pci_vtmem_cfgread(&sc, 55, 2, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtmem_cfgread(&sc, 0, 3, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtmem_cfgread(&sc, 0, 4, NULL), EINVAL);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(suspend_freezes_guest_visible_configuration);
ATF_TC_BODY(suspend_freezes_guest_visible_configuration, tc)
{
	struct pci_vtmem_softc sc;
	uint32_t high, low;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pci_vtmem_suspend(&sc), 0);
	sc.vmsc_vs.vs_suspended = true;
	ATF_REQUIRE(sc.vmsc_suspended_config_valid);

	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(sc.vmsc_host,
	    DOC_BLOCK * 2), 0);
	ATF_CHECK_EQ(g_dirty_calls, 1);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 48, 4, &low), 0);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 52, 4, &high), 0);
	ATF_CHECK_EQ(low, (uint32_t)DOC_BLOCK);
	ATF_CHECK_EQ(high, 0U);

	ATF_REQUIRE_EQ(pci_vtmem_resume(&sc), 0);
	sc.vmsc_vs.vs_suspended = false;
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 48, 4, &low), 0);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&sc, 52, 4, &high), 0);
	ATF_CHECK_EQ(low, (uint32_t)(DOC_BLOCK * 2));
	ATF_CHECK_EQ(high, 0U);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(restore_suspended_preserves_transport_mutex_ownership);
ATF_TC_BODY(restore_suspended_preserves_transport_mutex_ownership, tc)
{
	struct pci_vtmem_softc sc;

	/* Common restore may invoke this transition while vs_mtx is owned. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(pthread_mutex_lock(&sc.vmsc_mtx), 0);
	ATF_REQUIRE(pthread_mutex_isowned_np(&sc.vmsc_mtx));
	pci_vtmem_restore_suspended(&sc);
	ATF_CHECK(pthread_mutex_isowned_np(&sc.vmsc_mtx));
	ATF_REQUIRE_EQ(pthread_mutex_unlock(&sc.vmsc_mtx), 0);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(restore_suspended_direct_caller_releases_transport_mutex);
ATF_TC_BODY(restore_suspended_direct_caller_releases_transport_mutex, tc)
{
	struct pci_vtmem_softc sc;

	/* A direct restore caller must not inherit the common restore lock. */
	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE(!pthread_mutex_isowned_np(&sc.vmsc_mtx));
	pci_vtmem_restore_suspended(&sc);
	ATF_CHECK(!pthread_mutex_isowned_np(&sc.vmsc_mtx));
	ATF_CHECK(sc.vmsc_suspended_config_valid);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_preserves_suspended_configuration);
ATF_TC_BODY(snapshot_preserves_suspended_configuration, tc)
{
	struct pci_vtmem_softc destination, source;
	uint8_t image[512];
	uint32_t high, low;
	size_t used;

	reset_mocks();
	setup_softc(&source);
	ATF_REQUIRE_EQ(pci_vtmem_suspend(&source), 0);
	source.vmsc_vs.vs_suspended = true;
	ATF_REQUIRE_EQ(virtio_mem_host_set_requested_size(source.vmsc_host,
	    DOC_BLOCK * 2), 0);
	ATF_REQUIRE_EQ(run_mem_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_CHECK_EQ(le32dec(image), DOC_VTMEM_SNAPSHOT_MAGIC);
	ATF_CHECK_EQ(le32dec(image + 4), DOC_VTMEM_SNAPSHOT_VERSION);
	ATF_CHECK_EQ(image[20], 1);

	setup_softc(&destination);
	destination.vmsc_vs.vs_suspended = true;
	ATF_REQUIRE_EQ(run_mem_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_REQUIRE_EQ(run_mem_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_REQUIRE(destination.vmsc_suspended_config_valid);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&destination, 48, 4, &low), 0);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&destination, 52, 4, &high), 0);
	ATF_CHECK_EQ(low, (uint32_t)DOC_BLOCK);
	ATF_CHECK_EQ(high, 0U);

	ATF_CHECK_EQ(run_mem_snapshot(&destination, image, used - 1,
	    VM_SNAPSHOT_RESTORE, NULL), E2BIG);
	ATF_REQUIRE(destination.vmsc_suspended_config_valid);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&destination, 48, 4, &low), 0);
	ATF_CHECK_EQ(low, (uint32_t)DOC_BLOCK);

	ATF_REQUIRE_EQ(pci_vtmem_resume(&destination), 0);
	destination.vmsc_vs.vs_suspended = false;
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&destination, 48, 4, &low), 0);
	ATF_REQUIRE_EQ(pci_vtmem_cfgread(&destination, 52, 4, &high), 0);
	ATF_CHECK_EQ(low, (uint32_t)(DOC_BLOCK * 2));
	ATF_CHECK_EQ(high, 0U);
	teardown_softc(&destination);
	teardown_softc(&source);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_unknown_version_prefix);
ATF_TC_BODY(snapshot_rejects_unknown_version_prefix, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t prefix[8];

	reset_mocks();
	setup_softc(&sc);
	le32enc(prefix, DOC_VTMEM_SNAPSHOT_MAGIC);
	le32enc(prefix + 4, DOC_VTMEM_SNAPSHOT_VERSION + 1);
	ATF_CHECK_EQ(run_mem_snapshot(&sc, prefix, sizeof(prefix),
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	teardown_softc(&sc);
}

static int
run_init(void)
{
	struct pci_devinst pi;
	struct nvlist nvl;

	memset(&pi, 0, sizeof(pi));
	memset(&nvl, 0, sizeof(nvl));
	pi.pi_bus = 0;
	pi.pi_slot = 3;
	pi.pi_func = 0;
	return (pci_vtmem_init(&pi, (nvlist_t *)&nvl));
}

/* A configurable range callback used to drive restore reconstruction. */
static int g_sr_calls;

static int
failing_set_range(void *arg __unused, uint64_t address __unused,
    uint64_t length __unused, bool plug __unused)
{

	g_sr_calls++;
	if (g_sr_calls == 1)
		return (0);	/* first reconstructed range plugs */
	return (EIO);		/* later plug fails; cleanup unplug also fails */
}

/* An unconstrained range callback for fixtures that plug arbitrary blocks. */
static int
model_set_range_any(void *arg __unused, uint64_t address __unused,
    uint64_t length __unused, bool plug __unused)
{

	return (0);
}

/* Drive a single request through the host model and return its response code. */
static uint16_t
issue_request(struct pci_vtmem_softc *sc, uint16_t type, uint64_t address,
    uint16_t nblocks, uint16_t *state_out)
{
	uint8_t req[BHYVE_VTMEM_REQUEST_SIZE];
	uint8_t resp[BHYVE_VTMEM_RESPONSE_SIZE];
	size_t used;

	memset(req, 0, sizeof(req));
	memset(resp, 0, sizeof(resp));
	le16enc(req, type);
	le64enc(req + 8, address);
	le16enc(req + 16, nblocks);
	ATF_REQUIRE_EQ(virtio_mem_host_request(sc->vmsc_host, req, sizeof(req),
	    resp, sizeof(resp), &used), 0);
	ATF_REQUIRE_EQ(used, sizeof(resp));
	if (state_out != NULL)
		*state_out = le16dec(resp + 8);
	return (le16dec(resp));
}

static void
plug_block(struct pci_vtmem_softc *sc, unsigned int block)
{

	ATF_REQUIRE_EQ(issue_request(sc, DOC_REQ_PLUG,
	    DOC_BASE + (uint64_t)block * DOC_BLOCK, 1, NULL), DOC_RESP_ACK);
}

ATF_TC_WITHOUT_HEAD(init_succeeds_with_valid_configuration);
ATF_TC_BODY(init_succeeds_with_valid_configuration, tc)
{

	init_reset();
	ATF_CHECK_EQ(run_init(), 0);
}

ATF_TC_WITHOUT_HEAD(init_succeeds_packed_and_debug);
ATF_TC_BODY(init_succeeds_packed_and_debug, tc)
{

	init_reset();
	g_cfg_packed = true;
	g_cfg_block = "0x200000";
	g_cfg_requested = "0x200000";
	ATF_REQUIRE_EQ(setenv("BHYVE_VIRTIO_DEBUG", "0", 1), 0);
	ATF_CHECK_EQ(run_init(), 0);
	/* atoi("0") < 1 clamps the debug level up to 1. */
	ATF_CHECK_EQ(pci_vtmem_debug, 1);
	ATF_REQUIRE_EQ(unsetenv("BHYVE_VIRTIO_DEBUG"), 0);
}

ATF_TC_WITHOUT_HEAD(init_rejects_bad_size);
ATF_TC_BODY(init_rejects_bad_size, tc)
{

	init_reset();
	g_cfg_size = NULL;
	ATF_CHECK_EQ(run_init(), 1);
	init_reset();
	g_cfg_size = "BAD";
	ATF_CHECK_EQ(run_init(), 1);
	init_reset();
	g_cfg_size = "0";
	ATF_CHECK_EQ(run_init(), 1);
}

ATF_TC_WITHOUT_HEAD(init_rejects_bad_block_and_requested);
ATF_TC_BODY(init_rejects_bad_block_and_requested, tc)
{

	init_reset();
	g_cfg_block = "BAD";
	ATF_CHECK_EQ(run_init(), 1);
	init_reset();
	g_cfg_requested = "BAD";
	ATF_CHECK_EQ(run_init(), 1);
}

ATF_TC_WITHOUT_HEAD(init_rejects_invalid_geometry);
ATF_TC_BODY(init_rejects_invalid_geometry, tc)
{

	/* Block size not a power of two. */
	init_reset();
	g_cfg_block = "0x300000";
	ATF_CHECK_EQ(run_init(), 1);
	/* Block size smaller than a page. */
	init_reset();
	g_cfg_block = "0x200";
	ATF_CHECK_EQ(run_init(), 1);
	/* Region size not a multiple of block size. */
	init_reset();
	g_cfg_size = "0x300000";
	g_cfg_block = "0x200000";
	ATF_CHECK_EQ(run_init(), 1);
	/* Requested size larger than the region. */
	init_reset();
	g_cfg_requested = "0x800000";
	ATF_CHECK_EQ(run_init(), 1);
}

ATF_TC_WITHOUT_HEAD(init_unwinds_on_platform_failures);
ATF_TC_BODY(init_unwinds_on_platform_failures, tc)
{

	init_reset();
	g_alloc_gpa_ret = ENOMEM;
	ATF_CHECK_EQ(run_init(), 1);

	init_reset();
	g_devmem_fail = true;
	ATF_CHECK_EQ(run_init(), 1);

	init_reset();
	g_mmap_ret = -1;
	ATF_CHECK_EQ(run_init(), 1);

	/* Undersized backing store makes the region-wide madvise() fail. */
	init_reset();
	g_devmem_undersize = true;
	ATF_CHECK_EQ(run_init(), 1);

	/* An unaligned GPA passes local checks but is refused by the backend. */
	init_reset();
	g_gpa_unaligned = true;
	ATF_CHECK_EQ(run_init(), 1);
}

ATF_TC_WITHOUT_HEAD(init_unwinds_on_transport_failures);
ATF_TC_BODY(init_unwinds_on_transport_failures, tc)
{

	init_reset();
	g_select_ret = -1;
	ATF_CHECK_EQ(run_init(), 1);
	ATF_CHECK(g_munmap_calls > 0);

	init_reset();
	g_intr_ret = -1;
	ATF_CHECK_EQ(run_init(), 1);

	/* Late failure exercises the interrupt-and-mapping unwind. */
	init_reset();
	g_modern_ret = -1;
	ATF_CHECK_EQ(run_init(), 1);
	ATF_CHECK(g_munmap_calls > 0);
}

ATF_TC_WITHOUT_HEAD(init_unwinds_on_allocation_failures);
ATF_TC_BODY(init_unwinds_on_allocation_failures, tc)
{

	/* The softc allocation itself can fail. */
	init_reset();
	g_fail_calloc = true;
	ATF_CHECK_EQ(run_init(), 1);

	/* The device mutex initialization can fail. */
	init_reset();
	g_fail_mutex_init = true;
	ATF_CHECK_EQ(run_init(), 1);
}

ATF_TC_WITHOUT_HEAD(snapshot_reports_buffer_allocation_failure);
ATF_TC_BODY(snapshot_reports_buffer_allocation_failure, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t image[512];

	reset_mocks();
	setup_softc(&sc);
	g_fail_malloc = true;	/* the private state buffer cannot be allocated */
	ATF_CHECK_EQ(run_mem_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), ENOMEM);
	g_fail_malloc = false;
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_handler_failure_sets_needs_reset);
ATF_TC_BODY(notify_handler_failure_sets_needs_reset, tc)
{
	struct pci_vtmem_softc sc;
	struct virtio_mem_host *host;

	reset_mocks();
	setup_softc(&sc);
	host = sc.vmsc_host;
	sc.vmsc_host = NULL;	/* forces virtio_mem_host_request() EINVAL */
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_len, 0U);
	sc.vmsc_host = host;
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_debug_path_logs_request);
ATF_TC_BODY(notify_debug_path_logs_request, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	pci_vtmem_debug = 1;
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	pci_vtmem_debug = 0;
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(g_rel_len, BHYVE_VTMEM_RESPONSE_SIZE);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_short_write_sets_needs_reset);
ATF_TC_BODY(notify_short_write_sets_needs_reset, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_short_write = 1;
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_len, 0U);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_bad_request_size_sets_needs_reset);
ATF_TC_BODY(notify_bad_request_size_sets_needs_reset, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_bad_insize = 1;
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_needs_reset, 1);
	ATF_CHECK_EQ(g_rel_len, 0U);
	ATF_CHECK_EQ(g_set_range_calls, 0U);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(notify_empty_chain_breaks);
ATF_TC_BODY(notify_empty_chain_breaks, tc)
{
	struct pci_vtmem_softc sc;

	reset_mocks();
	setup_softc(&sc);
	g_getchain_ret = -1;
	pci_vtmem_notify(&sc, &sc.vmsc_vq);
	ATF_CHECK_EQ(g_rel_calls, 0);
	ATF_CHECK_EQ(g_needs_reset, 0);
	ATF_CHECK_EQ(g_end_calls, 1);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(set_range_plug_is_a_noop);
ATF_TC_BODY(set_range_plug_is_a_noop, tc)
{
	struct pci_vtmem_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vmsc_gpa = DOC_BASE;
	sc.vmsc_region_size = (size_t)DOC_BLOCK * 2;
	/* A plug request never touches the mapping, so no base is required. */
	ATF_CHECK_EQ(pci_vtmem_set_range(&sc, DOC_BASE, DOC_BLOCK, true), 0);
}

ATF_TC_WITHOUT_HEAD(set_range_rejects_out_of_bounds);
ATF_TC_BODY(set_range_rejects_out_of_bounds, tc)
{
	struct pci_vtmem_softc sc;

	memset(&sc, 0, sizeof(sc));
	sc.vmsc_gpa = DOC_BASE;
	sc.vmsc_region_size = (size_t)DOC_BLOCK * 2;
	/* Address below the region base. */
	ATF_CHECK_EQ(pci_vtmem_set_range(&sc, DOC_BASE - 0x1000, DOC_BLOCK,
	    false), EINVAL);
	/* Length extends past the region end. */
	ATF_CHECK_EQ(pci_vtmem_set_range(&sc, DOC_BASE,
	    (uint64_t)DOC_BLOCK * 4, false), EINVAL);
}

ATF_TC_WITHOUT_HEAD(set_range_madvise_failure_returns_errno);
ATF_TC_BODY(set_range_madvise_failure_returns_errno, tc)
{
	struct pci_vtmem_softc sc;
	int error;

	memset(&sc, 0, sizeof(sc));
	/* A NULL base makes madvise() reject the range with EINVAL. */
	sc.vmsc_host_base = NULL;
	sc.vmsc_gpa = DOC_BASE;
	sc.vmsc_region_size = (size_t)DOC_BLOCK;
	error = pci_vtmem_set_range(&sc, DOC_BASE, DOC_BLOCK, false);
	ATF_CHECK(error != 0);
}

ATF_TC_WITHOUT_HEAD(cfgread_reports_encode_failure);
ATF_TC_BODY(cfgread_reports_encode_failure, tc)
{
	struct pci_vtmem_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vmsc_host = NULL;	/* config encode returns EINVAL */
	sc.vmsc_vs.vs_suspended = false;
	ATF_CHECK_EQ(pci_vtmem_cfgread(&sc, 0, 4, &value), EINVAL);
}

ATF_TC_WITHOUT_HEAD(snapshot_size_failure_is_reported);
ATF_TC_BODY(snapshot_size_failure_is_reported, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t image[64];

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vmsc_mtx, NULL), 0);
	sc.vmsc_vs.vs_mtx = &sc.vmsc_mtx;
	sc.vmsc_host = NULL;	/* snapshot_size returns EINVAL */
	ATF_CHECK_EQ(run_mem_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vmsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_corrupt_reserved_and_valid);
ATF_TC_BODY(snapshot_rejects_corrupt_reserved_and_valid, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t image[512];
	size_t used;

	reset_mocks();
	setup_softc(&sc);
	ATF_REQUIRE_EQ(run_mem_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	/* Non-zero reserved word (offset 8) must fail closed. */
	image[8] = 1;
	ATF_CHECK_EQ(run_mem_snapshot(&sc, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	image[8] = 0;	/* restore: reserved is defined to be zero */

	/* suspended_config_valid (offset 20) must be a canonical boolean. */
	image[20] = 2;
	ATF_CHECK_EQ(run_mem_snapshot(&sc, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_save_reports_backend_failure);
ATF_TC_BODY(snapshot_save_reports_backend_failure, tc)
{
	struct pci_vtmem_softc sc;
	uint8_t image[512];

	reset_mocks();
	setup_softc(&sc);
	/* An incomplete backend refuses to serialize its state. */
	sc.vmsc_host->restore_incomplete = true;
	ATF_CHECK_EQ(run_mem_snapshot(&sc, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, NULL), EBUSY);
	teardown_softc(&sc);
}

ATF_TC_WITHOUT_HEAD(snapshot_restore_failure_marks_incomplete);
ATF_TC_BODY(snapshot_restore_failure_marks_incomplete, tc)
{
	struct pci_vtmem_softc source, sc;
	uint8_t image[1024];
	size_t used;

	/*
	 * Build an image describing two non-contiguous plugged blocks, then
	 * restore it into a device whose platform callback fails partway
	 * through reconstruction.  Rollback also fails, so the backend stays
	 * incomplete and the device must latch that on the transport.
	 */
	reset_mocks();
	{
		const struct virtio_mem_host_limits limits = {
			.block_size = DOC_BLOCK,
			.address = DOC_BASE,
			.region_size = DOC_BLOCK * 4,
			.usable_region_size = DOC_BLOCK * 4,
			.requested_size = DOC_BLOCK * 4,
			.max_blocks = 4,
		};
		struct virtio_mem_host_ops ops = {
			.set_range = model_set_range_any,
			.config_changed = pci_vtmem_config_changed,
			.arg = &source,
		};

		memset(&source, 0, sizeof(source));
		ATF_REQUIRE_EQ(pthread_mutex_init(&source.vmsc_mtx, NULL), 0);
		source.vmsc_vs.vs_mtx = &source.vmsc_mtx;
		ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops,
		    &source.vmsc_host), 0);
		source.vmsc_consts = vtmem_vi_consts;
		source.vmsc_vs.vs_vc = &source.vmsc_consts;
	}
	/* Plug blocks 0 and 2 (non-contiguous) via guest requests. */
	plug_block(&source, 0);
	plug_block(&source, 2);
	ATF_REQUIRE_EQ(run_mem_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);

	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vmsc_mtx, NULL), 0);
	sc.vmsc_vs.vs_mtx = &sc.vmsc_mtx;
	{
		const struct virtio_mem_host_limits limits = {
			.block_size = DOC_BLOCK,
			.address = DOC_BASE,
			.region_size = DOC_BLOCK * 4,
			.usable_region_size = DOC_BLOCK * 4,
			.requested_size = 0,
			.max_blocks = 4,
		};
		struct virtio_mem_host_ops ops = {
			.set_range = failing_set_range,
			.config_changed = pci_vtmem_config_changed,
			.arg = &sc,
		};
		ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops,
		    &sc.vmsc_host), 0);
	}
	sc.vmsc_consts = vtmem_vi_consts;
	sc.vmsc_vs.vs_vc = &sc.vmsc_consts;

	g_sr_calls = 0;
	ATF_CHECK(run_mem_snapshot(&sc, image, used, VM_SNAPSHOT_RESTORE,
	    NULL) != 0);
	ATF_CHECK(virtio_mem_host_restore_incomplete(sc.vmsc_host));
	ATF_CHECK(sc.vmsc_vs.vs_restore_incomplete);

	virtio_mem_host_destroy(sc.vmsc_host);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vmsc_mtx), 0);
	virtio_mem_host_destroy(source.vmsc_host);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&source.vmsc_mtx), 0);
}

ATF_TC_WITHOUT_HEAD(mem_request_protocol_semantics);
ATF_TC_BODY(mem_request_protocol_semantics, tc)
{
	struct pci_vtmem_softc sc;
	struct virtio_mem_host_config config;
	uint16_t state;

	const struct virtio_mem_host_limits limits = {
		.block_size = DOC_BLOCK,
		.address = DOC_BASE,
		.region_size = DOC_BLOCK * 4,
		.usable_region_size = DOC_BLOCK * 4,
		.requested_size = DOC_BLOCK * 4,
		.max_blocks = 4,
	};
	struct virtio_mem_host_ops ops = {
		.set_range = model_set_range_any,
		.config_changed = pci_vtmem_config_changed,
		.arg = &sc,
	};

	reset_mocks();
	memset(&sc, 0, sizeof(sc));
	ATF_REQUIRE_EQ(pthread_mutex_init(&sc.vmsc_mtx, NULL), 0);
	sc.vmsc_vs.vs_mtx = &sc.vmsc_mtx;
	ATF_REQUIRE_EQ(virtio_mem_host_create(&limits, &ops, &sc.vmsc_host), 0);
	sc.vmsc_consts = vtmem_vi_consts;
	sc.vmsc_vs.vs_vc = &sc.vmsc_consts;

	/* A freshly created region reports all blocks unplugged. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_STATE, DOC_BASE, 4, &state),
	    DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_UNPLUGGED);

	/* PLUG two blocks and confirm the plugged accounting and state. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_PLUG, DOC_BASE, 2, NULL),
	    DOC_RESP_ACK);
	virtio_mem_host_get_config(sc.vmsc_host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK * 2);
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_STATE, DOC_BASE, 2, &state),
	    DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_PLUGGED);
	/* A span crossing the plug boundary is mixed. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_STATE, DOC_BASE, 4, &state),
	    DOC_RESP_ACK);
	ATF_CHECK_EQ(state, DOC_STATE_MIXED);

	/* UNPLUG one block, leaving one plugged. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_UNPLUG, DOC_BASE, 1, NULL),
	    DOC_RESP_ACK);
	virtio_mem_host_get_config(sc.vmsc_host, &config);
	ATF_CHECK_EQ(config.plugged_size, DOC_BLOCK);

	/* A PLUG that runs past the region is refused, not fatal. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_PLUG, DOC_BASE, 8, NULL),
	    DOC_RESP_ERROR);

	/* UNPLUG_ALL clears every plugged block. */
	ATF_CHECK_EQ(issue_request(&sc, DOC_REQ_UNPLUG_ALL, 0, 0, NULL),
	    DOC_RESP_ACK);
	virtio_mem_host_get_config(sc.vmsc_host, &config);
	ATF_CHECK_EQ(config.plugged_size, 0U);

	virtio_mem_host_destroy(sc.vmsc_host);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&sc.vmsc_mtx), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fragmented_request_completes_once);
	ATF_TP_ADD_TC(tp, composition_contract);
	ATF_TP_ADD_TC(tp, malformed_chain_sets_needs_reset);
	ATF_TP_ADD_TC(tp, reset_preserves_plugged_state);
	ATF_TP_ADD_TC(tp, reset_preserves_incomplete_restore_failure);
	ATF_TP_ADD_TC(tp, unplug_discards_but_keeps_mapping);
	ATF_TP_ADD_TC(tp, requested_size_notifies_under_device_lock);
	ATF_TP_ADD_TC(tp, config_reads_decode_little_endian);
	ATF_TP_ADD_TC(tp, suspend_freezes_guest_visible_configuration);
	ATF_TP_ADD_TC(tp,
	    restore_suspended_preserves_transport_mutex_ownership);
	ATF_TP_ADD_TC(tp,
	    restore_suspended_direct_caller_releases_transport_mutex);
	ATF_TP_ADD_TC(tp, snapshot_preserves_suspended_configuration);
	ATF_TP_ADD_TC(tp, snapshot_rejects_unknown_version_prefix);
	ATF_TP_ADD_TC(tp, init_succeeds_with_valid_configuration);
	ATF_TP_ADD_TC(tp, init_succeeds_packed_and_debug);
	ATF_TP_ADD_TC(tp, init_rejects_bad_size);
	ATF_TP_ADD_TC(tp, init_rejects_bad_block_and_requested);
	ATF_TP_ADD_TC(tp, init_rejects_invalid_geometry);
	ATF_TP_ADD_TC(tp, init_unwinds_on_platform_failures);
	ATF_TP_ADD_TC(tp, init_unwinds_on_transport_failures);
	ATF_TP_ADD_TC(tp, init_unwinds_on_allocation_failures);
	ATF_TP_ADD_TC(tp, snapshot_reports_buffer_allocation_failure);
	ATF_TP_ADD_TC(tp, notify_handler_failure_sets_needs_reset);
	ATF_TP_ADD_TC(tp, notify_debug_path_logs_request);
	ATF_TP_ADD_TC(tp, notify_short_write_sets_needs_reset);
	ATF_TP_ADD_TC(tp, notify_bad_request_size_sets_needs_reset);
	ATF_TP_ADD_TC(tp, notify_empty_chain_breaks);
	ATF_TP_ADD_TC(tp, set_range_plug_is_a_noop);
	ATF_TP_ADD_TC(tp, set_range_rejects_out_of_bounds);
	ATF_TP_ADD_TC(tp, set_range_madvise_failure_returns_errno);
	ATF_TP_ADD_TC(tp, cfgread_reports_encode_failure);
	ATF_TP_ADD_TC(tp, snapshot_size_failure_is_reported);
	ATF_TP_ADD_TC(tp, snapshot_rejects_corrupt_reserved_and_valid);
	ATF_TP_ADD_TC(tp, snapshot_save_reports_backend_failure);
	ATF_TP_ADD_TC(tp, snapshot_restore_failure_marks_incomplete);
	ATF_TP_ADD_TC(tp, mem_request_protocol_semantics);
	return (atf_no_error());
}
