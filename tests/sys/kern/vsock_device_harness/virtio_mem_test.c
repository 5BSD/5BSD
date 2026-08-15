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
	memset(req, 0, sizeof(*req));
	req->idx = 11;
	req->readable = g_readable;
	req->writable = g_writable;
	req->ordered = g_ordered;
	iov[0].iov_base = g_request;
	iov[0].iov_len = 5;
	iov[1].iov_base = g_request + 5;
	iov[1].iov_len = sizeof(g_request) - 5;
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
	return (atf_no_error());
}
