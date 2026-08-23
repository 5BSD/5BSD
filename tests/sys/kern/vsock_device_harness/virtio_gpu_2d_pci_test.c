/*
 * Independent VirtIO 1.4 section 5.7 PCI composition tests.
 */
#ifndef BHYVE_SNAPSHOT
#define	BHYVE_SNAPSHOT
#endif

#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "bhyvegc.h"
#include "console.h"
#include "pci_emul.h"
#include "virtio.h"
#undef PCI_EMUL_SET
#define	PCI_EMUL_SET(name)

#include "virtio_gpu_2d_protocol.c"
#include "virtio_gpu_2d_display.c"
#include "virtio_gpu_2d_state.c"
#include "virtio_gpu_2d_queue.c"

#include <dev/virtio/gpu/virtio_gpu.h>

static unsigned int blob_dma_acquires;
static unsigned int blob_dma_releases;
static unsigned int blob_dma_maps;
static bool blob_dma_acquire_allowed = true;
static uint8_t blob_guest[64];
static struct bhyvegc_image test_console_image;
struct bhyvegc {
	struct bhyvegc_image *image;
};

struct bhyvegc_image *
bhyvegc_get_image(struct bhyvegc *gc)
{

	return (gc == NULL ? NULL : gc->image);
}

static int stub_fb_register_ret;
static int stub_fb_register_calls;
static int stub_fb_unregister_calls;

int
console_fb_register(const char *owner __unused,
    fb_render_func_t render_cb __unused, void *arg __unused)
{

	stub_fb_register_calls++;
	return (stub_fb_register_ret);
}

int
console_fb_unregister(const char *owner __unused, void *arg __unused)
{

	stub_fb_unregister_calls++;
	return (0);
}

bool
vi_dma_acquire(struct virtio_softc *vs __unused,
    struct virtio_dma_lease *lease)
{

	if (!blob_dma_acquire_allowed || lease == NULL || lease->acquired)
		return (false);
	lease->acquired = true;
	blob_dma_acquires++;
	return (true);
}

void
vi_dma_release(struct virtio_softc *vs __unused,
    struct virtio_dma_lease *lease)
{

	if (lease == NULL || !lease->acquired)
		return;
	lease->acquired = false;
	blob_dma_releases++;
}

void *
vi_map_dma(struct virtio_softc *vs __unused, uint64_t address, size_t length,
    enum virtio_dma_direction direction __unused)
{

	blob_dma_maps++;
	if (address > sizeof(blob_guest) ||
	    length > sizeof(blob_guest) - address)
		return (NULL);
	return (blob_guest + address);
}

#include "pci_virtio_gpu.c"
#include "virtio_1_4_spec.h"
#include "virtio_config_read_test_support.h"

void
vm_snapshot_buf_err(const char *name __unused,
    enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (meta == NULL || meta->buffer.buf == NULL ||
	    meta->buffer.buf_rem < size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf = (uint8_t *)meta->buffer.buf + size;
	meta->buffer.buf_rem -= size;
	return (0);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le32dec(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le64enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le64dec(bytes);
	return (error);
}

static int
run_snapshot(struct pci_vtgpu_softc *sc, uint8_t *image, size_t size,
    enum vm_snapshot_op op, size_t *used)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf = image,
			.buf_rem = size,
		},
		.op = op,
	};
	int error;

	error = pci_vtgpu_snapshot(sc, &meta);
	if (used != NULL)
		*used = size - meta.buffer.buf_rem;
	return (error);
}

static int
blob_dma_validate(void *arg __unused, uint64_t address, size_t length,
    enum virtio_gpu_2d_dma_access access __unused)
{

	if (address > sizeof(blob_guest) ||
	    length > sizeof(blob_guest) - address)
		return (EFAULT);
	return (0);
}

static int
blob_dma_read(void *arg __unused, uint64_t address, void *output, size_t length)
{

	if (address > sizeof(blob_guest) ||
	    length > sizeof(blob_guest) - address)
		return (EFAULT);
	memcpy(output, blob_guest + address, length);
	return (0);
}

int
vi_pci_lifecycle_noop(void *argument __unused)
{

	return (0);
}

/*
 * Allocation fault injection.  Both malloc and calloc route through --wrap so
 * a test can fail a chosen allocation ordinal; the default is pure
 * pass-through, so unrelated allocations (ATF, libc) are unaffected.
 */
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t);
void *__wrap_calloc(size_t, size_t);
static int wrap_malloc_fail_at = -1;
static int wrap_malloc_calls;
static int wrap_calloc_fail_at = -1;
static int wrap_calloc_calls;

void *
__wrap_malloc(size_t size)
{

	if (wrap_malloc_fail_at >= 0 && wrap_malloc_calls++ == wrap_malloc_fail_at)
		return (NULL);
	return (__real_malloc(size));
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (wrap_calloc_fail_at >= 0 && wrap_calloc_calls++ == wrap_calloc_fail_at)
		return (NULL);
	return (__real_calloc(nmemb, size));
}

static void
alloc_fault_reset(void)
{

	wrap_malloc_fail_at = -1;
	wrap_malloc_calls = 0;
	wrap_calloc_fail_at = -1;
	wrap_calloc_calls = 0;
}

/*
 * Mock virtio queue transport.  Each notify test enqueues a fixed set of
 * descriptor chains; the device drains them under its own budget loop.  Used
 * lengths reported through vq_relchain are recorded for assertion against the
 * VirtIO GPU wire response sizes.
 */
#define	MOCKQ_MAX	8
struct mockq_chain {
	struct iovec iov[6];
	int n;
	int readable;
	bool ordered;
	bool fail_getchain;	/* return getchain_ret instead of serving */
	int getchain_ret;
};
static struct mockq_chain mockq[MOCKQ_MAX];
static int mockq_len;
static int mockq_pos;
static uint32_t mockq_used[MOCKQ_MAX];
static int mockq_used_n;
static int mock_relchain_calls;
static int mock_endchains_calls;
static int mock_needs_reset_calls;
static int mock_reset_dev_calls;

static void
mockq_reset(void)
{

	memset(mockq, 0, sizeof(mockq));
	memset(mockq_used, 0, sizeof(mockq_used));
	mockq_len = 0;
	mockq_pos = 0;
	mockq_used_n = 0;
	mock_relchain_calls = 0;
	mock_endchains_calls = 0;
	mock_needs_reset_calls = 0;
}

int
vq_has_descs(struct vqueue_info *vq __unused)
{

	return (mockq_pos < mockq_len);
}

int
vq_getchain(struct vqueue_info *vq __unused, struct iovec *iov, int niov,
    struct vi_req *request)
{
	struct mockq_chain *c;

	if (mockq_pos >= mockq_len)
		return (0);
	c = &mockq[mockq_pos++];
	if (c->fail_getchain)
		return (c->getchain_ret);
	memset(request, 0, sizeof(*request));
	for (int i = 0; i < c->n && i < niov; i++)
		iov[i] = c->iov[i];
	request->readable = c->readable;
	request->writable = c->n - c->readable;
	request->ordered = c->ordered;
	request->idx = (unsigned int)(mockq_pos - 1);
	return (c->n);
}

void
vq_relchain(struct vqueue_info *vq __unused, uint16_t idx __unused,
    uint32_t used)
{

	if (mockq_used_n < MOCKQ_MAX)
		mockq_used[mockq_used_n++] = used;
	mock_relchain_calls++;
}

void
vq_retchains(struct vqueue_info *vq __unused, uint16_t count __unused)
{
}

void
vq_endchains(struct vqueue_info *vq __unused, int used_all_avail __unused)
{

	mock_endchains_calls++;
}

void
vi_set_needs_reset(struct virtio_softc *vs __unused)
{

	mock_needs_reset_calls++;
}

void
vi_reset_dev(struct virtio_softc *vs)
{

	mock_reset_dev_calls++;
	vs->vs_status = 0;
}

/* Configurable post-init transport hooks retained by pci_de_vtgpu. */
static int stub_select_transport_ret;
static int stub_intr_init_ret;
static int stub_modern_init_ret;
static void *stub_linkup_softc;
static struct pci_devinst *stub_linkup_pi;

void
vi_softc_linkup(struct virtio_softc *vs __unused,
    struct virtio_consts *vc __unused, void *softc,
    struct pci_devinst *pi, struct vqueue_info *queues __unused)
{

	stub_linkup_softc = softc;
	stub_linkup_pi = pi;
}

int
vi_pci_select_transport(struct virtio_softc *vs __unused,
    const nvlist_t *nvl __unused,
    enum virtio_pci_transport_policy policy __unused)
{

	return (stub_select_transport_ret);
}

void
vi_pci_modern_set_identity(struct virtio_softc *vs __unused,
    uint16_t type __unused)
{
}

void
vi_pci_modern_seal_shared_memory(struct virtio_softc *vs __unused)
{
}

int
vi_pci_modern_init(struct virtio_softc *vs __unused, int bar __unused)
{

	return (stub_modern_init_ret);
}

int
vi_intr_init(struct virtio_softc *vs, int bar __unused, int use_msix __unused)
{

	if (stub_intr_init_ret != 0)
		return (stub_intr_init_ret);
	/* The device destroys this mutex on later init failures. */
	return (pthread_mutex_init(&vs->vs_isr_mtx, NULL));
}

int
vi_pci_modern_cfgread(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t *value __unused)
{

	return (0);
}

int
vi_pci_modern_cfgwrite(struct pci_devinst *pi __unused, int offset __unused,
    int size __unused, uint32_t value __unused)
{

	return (0);
}

uint64_t
vi_pci_read(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused)
{

	return (0);
}

void
vi_pci_write(struct pci_devinst *pi __unused, int bar __unused,
    uint64_t offset __unused, int size __unused, uint64_t value __unused)
{
}

#ifdef BHYVE_SNAPSHOT
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
#endif

void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{

	if (pi != NULL && offset >= 0 && (size_t)offset < sizeof(pi->pi_cfgdata))
		pi->pi_cfgdata[offset] = value;
}

int
fbsdrun_virtio_msix(void)
{

	return (1);
}

/* Host configuration surface driven by globals for the init tests. */
static bool cfg_blob;
static bool cfg_display;
static bool cfg_packed;
static const char *cfg_width;
static const char *cfg_height;

bool
get_config_bool_node_default(const nvlist_t *nvl __unused, const char *name,
    bool def)
{

	if (strcmp(name, "blob") == 0)
		return (cfg_blob);
	if (strcmp(name, "display") == 0)
		return (cfg_display);
	if (strcmp(name, "packed") == 0)
		return (cfg_packed);
	return (def);
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{

	if (strcmp(name, "width") == 0)
		return (cfg_width);
	if (strcmp(name, "height") == 0)
		return (cfg_height);
	return (NULL);
}

static void
init_config_reset(void)
{

	cfg_blob = false;
	cfg_display = false;
	cfg_packed = false;
	cfg_width = NULL;
	cfg_height = NULL;
	stub_select_transport_ret = 0;
	stub_intr_init_ret = 0;
	stub_modern_init_ret = 0;
	stub_fb_register_ret = 0;
	stub_fb_register_calls = 0;
	stub_fb_unregister_calls = 0;
	stub_linkup_softc = NULL;
	stub_linkup_pi = NULL;
	alloc_fault_reset();
}

/*
 * A GPU control/cursor request is a 24-byte common header followed by a
 * fixed command payload.  The offsets below are read directly from the VirtIO
 * 1.4 section 5.7 command structures, independent of the device's own decoder.
 */
#define	GPU_REQ_BYTES	64	/* every request scratch buffer in this file */
static void
gpu_hdr(uint8_t *b, uint32_t type)
{

	memset(b, 0, GPU_REQ_BYTES);
	le32enc(b, type);
}

/* Enqueue one control/cursor chain: one readable request, one writable sink. */
static void
mockq_push(const uint8_t *req, size_t reqlen, uint8_t *resp, size_t resplen)
{
	struct mockq_chain *c;

	ATF_REQUIRE(mockq_len < MOCKQ_MAX);
	c = &mockq[mockq_len++];
	c->iov[0].iov_base = (void *)(uintptr_t)req;
	c->iov[0].iov_len = reqlen;
	c->readable = 1;
	c->ordered = true;
	if (resp != NULL && resplen != 0) {
		c->iov[1].iov_base = resp;
		c->iov[1].iov_len = resplen;
		c->n = 2;
	} else
		c->n = 1;
}

static uint32_t
resp_type(const uint8_t *resp)
{

	return (le32dec(resp));
}

ATF_TC_WITHOUT_HEAD(config_read_and_write_to_clear);
ATF_TC_BODY(config_read_and_write_to_clear, tc)
{
	struct pci_vtgpu_softc sc;
	uint32_t value;

	memset(&sc, 0, sizeof(sc));
	sc.vsc_events_read = 1;
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 0, 4, &value), 0);
	ATF_CHECK_EQ(value, 1);
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 4, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 8, 4, &value), 0);
	ATF_CHECK_EQ(le32toh(value), 1);
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 12, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 16, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	sc.vsc_blob_enabled = true;
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 16, 4, &value), 0);
	ATF_CHECK_EQ(le32toh(value), 4096);

	/* Unknown clear bits are ignored; every written one is an action. */
	ATF_REQUIRE_EQ(pci_vtgpu_cfgwrite(&sc, 4, 4,
	    UINT32_MAX), 0);
	ATF_CHECK_EQ(sc.vsc_events_read, 0);
	ATF_REQUIRE_EQ(pci_vtgpu_cfgread(&sc, 4, 4, &value), 0);
	ATF_CHECK_EQ(value, 0);
	ATF_CHECK_EQ(pci_vtgpu_cfgwrite(&sc, 0, 4, 1), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_cfgwrite(&sc, 4, 2, 1), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_cfgread(&sc, -1, 1, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_cfgread(&sc, 20, 1, &value), EINVAL);
}

ATF_TC_WITHOUT_HEAD(device_lifecycle_contract);
ATF_TC_BODY(device_lifecycle_contract, tc)
{

	ATF_CHECK_STREQ(pci_de_vtgpu.pe_emu, "virtio-gpu");
	ATF_CHECK_STREQ(vtgpu_vi_consts.vc_name, "vtgpu");
	ATF_CHECK_EQ(vtgpu_vi_consts.vc_nvq, 2);
	ATF_CHECK_EQ(vtgpu_vi_consts.vc_hv_caps,
	    VIRTIO14_F_RING_RESET |
	    VIRTIO14_F_SUSPEND | (UINT64_C(1) << 1));
	/*
	 * The current 2D state model and backing copies are synchronous under
	 * the common device lock.  A future display thread or host renderer
	 * must replace these no-op hooks with an ownership drain.
	 */
	ATF_CHECK(vtgpu_vi_consts.vc_suspend == vi_pci_lifecycle_noop);
	ATF_CHECK(vtgpu_vi_consts.vc_resume_device ==
	    vi_pci_lifecycle_noop);
	ATF_CHECK(vtgpu_vi_consts.vc_pause == vi_pci_lifecycle_noop);
	ATF_CHECK(vtgpu_vi_consts.vc_resume == vi_pci_lifecycle_noop);
}

ATF_TC_WITHOUT_HEAD(device_private_dma_holds_domain_lease);
ATF_TC_BODY(device_private_dma_holds_domain_lease, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t input[8], output[8];

	memset(&sc, 0, sizeof(sc));
	memset(blob_guest, 0, sizeof(blob_guest));
	memcpy(input, "gpu-dma", sizeof(input));
	memcpy(blob_guest + 4, input, sizeof(input));
	blob_dma_acquires = 0;
	blob_dma_releases = 0;
	blob_dma_maps = 0;
	blob_dma_acquire_allowed = true;

	ATF_REQUIRE_EQ(pci_vtgpu_dma_read(&sc, 4, output, sizeof(output)), 0);
	ATF_CHECK_EQ(blob_dma_acquires, 1);
	ATF_CHECK_EQ(blob_dma_releases, 1);
	ATF_CHECK_EQ(blob_dma_maps, 1);
	ATF_CHECK_EQ(memcmp(output, input, sizeof(output)), 0);

	/* A closing domain gate prevents both mapping and copying. */
	blob_dma_acquire_allowed = false;
	memset(output, 0xa5, sizeof(output));
	ATF_CHECK_EQ(pci_vtgpu_dma_read(&sc, 4, output, sizeof(output)), EBUSY);
	ATF_CHECK_EQ(blob_dma_acquires, 1);
	ATF_CHECK_EQ(blob_dma_releases, 1);
	ATF_CHECK_EQ(blob_dma_maps, 1);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0xa5);

	/* Failed mappings release the lease exactly once. */
	blob_dma_acquire_allowed = true;
	ATF_CHECK_EQ(pci_vtgpu_dma_read(&sc, sizeof(blob_guest), output,
	    sizeof(output)), EFAULT);
	ATF_CHECK_EQ(blob_dma_acquires, 2);
	ATF_CHECK_EQ(blob_dma_releases, 2);
	ATF_CHECK_EQ(blob_dma_maps, 2);
}

ATF_TC_WITHOUT_HEAD(descriptor_direction_contract);
ATF_TC_BODY(descriptor_direction_contract, tc)
{
	struct vi_req request;

	memset(&request, 0, sizeof(request));
	request.readable = 2;
	request.writable = 1;
	request.ordered = true;
	ATF_CHECK(pci_vtgpu_chain_valid(3, 3, &request));

	/*
	 * The PCI adapter reconstructs per-segment permissions from these
	 * counts.  It must reject an interleaved device-writable descriptor
	 * before assigning those permissions to the protocol engine.
	 */
	request.ordered = false;
	ATF_CHECK(!pci_vtgpu_chain_valid(3, 3, &request));
	request.ordered = true;
	request.readable = 0;
	ATF_CHECK(!pci_vtgpu_chain_valid(1, 3, &request));
	request.readable = 2;
	request.writable = 2;
	ATF_CHECK(!pci_vtgpu_chain_valid(3, 3, &request));
	request.writable = 1;
	ATF_CHECK(!pci_vtgpu_chain_valid(3, 2, &request));
	ATF_CHECK(!pci_vtgpu_chain_valid(0, 3, &request));
	ATF_CHECK(!pci_vtgpu_chain_valid(3, 3, NULL));
}

ATF_TC_WITHOUT_HEAD(monitor_dimension_options);
ATF_TC_BODY(monitor_dimension_options, tc)
{
	struct pci_vtgpu_softc sc;
	uint32_t value;

	ATF_REQUIRE_EQ(pci_vtgpu_parse_dimension("1", &value), 0);
	ATF_CHECK_EQ(value, 1);
	ATF_REQUIRE_EQ(pci_vtgpu_parse_dimension("0x780", &value), 0);
	ATF_CHECK_EQ(value, 1920);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension(NULL, &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("", &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("0", &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("-1", &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("1024x", &value), EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("4294967296", &value),
	    EINVAL);
	ATF_CHECK_EQ(pci_vtgpu_parse_dimension("1024", NULL), EINVAL);

	memset(&sc, 0, sizeof(sc));
	sc.vsc_width = 1024;
	sc.vsc_height = 768;
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(&sc, 1, 0, 0));
	ATF_CHECK(pci_vtgpu_snapshot_identity_valid(&sc, 2, 1024, 768));
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(&sc, 2, 800, 600));
	sc.vsc_width = 800;
	sc.vsc_height = 600;
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(&sc, 1, 800, 600));
	ATF_CHECK(pci_vtgpu_snapshot_identity_valid(&sc, 2, 800, 600));
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(&sc, 0, 800, 600));
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(&sc, 3, 800, 600));
	ATF_CHECK(!pci_vtgpu_snapshot_identity_valid(NULL, 2, 800, 600));
}

ATF_TC_WITHOUT_HEAD(snapshot_callback_validates_before_event_publication);
ATF_TC_BODY(snapshot_callback_validates_before_event_publication, tc)
{
	struct pci_vtgpu_softc source, destination;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	uint8_t image[4096], damaged[4096];
	size_t used;

	memset(&source, 0, sizeof(source));
	memset(&destination, 0, sizeof(destination));
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 2,
		.max_host_bytes = 64,
		.scanout_width = 2,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = blob_dma_validate,
		.dma_read = blob_dma_read,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &source.vsc_state), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &destination.vsc_state), 0);
	source.vsc_width = destination.vsc_width = 2;
	source.vsc_height = destination.vsc_height = 1;
	source.vsc_events_read = 1;
	destination.vsc_events_read = 0;

	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 24);
	/* Validation reads the entire state image but cannot publish events. */
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_VALIDATE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_events_read, 0);
	memcpy(damaged, image, used);
	damaged[0] ^= 1;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, used,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_events_read, 0);
	/* A foreign discriminator is rejected before any layout-dependent read. */
	damaged[0] = image[0];
	damaged[4] = 3;
	ATF_CHECK_EQ(run_snapshot(&destination, damaged, 8,
	    VM_SNAPSHOT_VALIDATE, NULL), EINVAL);
	ATF_CHECK_EQ(destination.vsc_events_read, 0);
	ATF_REQUIRE_EQ(run_snapshot(&destination, image, used,
	    VM_SNAPSHOT_RESTORE, NULL), 0);
	ATF_CHECK_EQ(destination.vsc_events_read, 1);

	virtio_gpu_2d_state_destroy(destination.vsc_state);
	virtio_gpu_2d_state_destroy(source.vsc_state);
}

ATF_TC_WITHOUT_HEAD(display_renderer_copies_active_scanout);
ATF_TC_BODY(display_renderer_copies_active_scanout, tc)
{
	struct pci_vtgpu_softc sc;
	struct virtio_gpu_2d_command command;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	struct bhyvegc gc;
	uint8_t attach[48], output[8];

	memset(&sc, 0, sizeof(sc));
	memset(blob_guest, 0, sizeof(blob_guest));
	/* Two B8G8R8X8 pixels: red, then green. */
	memcpy(blob_guest, (uint8_t[]) {
	    0x00, 0x00, 0xff, 0x00,
	    0x00, 0xff, 0x00, 0x00,
	}, sizeof(output));
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 2,
		.max_host_bytes = sizeof(output) + VIRTIO_GPU_2D_CURSOR_BYTES,
		.scanout_width = 2,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = blob_dma_validate,
		.dma_read = blob_dma_read,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &sc.vsc_state), 0);
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0101,
		.resource_id = 1,
		.format = 2,
		.width = 2,
		.height = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);
	memset(attach, 0, sizeof(attach));
	le32enc(attach, 0x0106);
	le32enc(attach + 24, 1);
	le32enc(attach + 28, 1);
	le64enc(attach + 32, 0);
	le32enc(attach + 40, sizeof(output));
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0106,
		.resource_id = 1,
		.entry_count = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    attach, sizeof(attach)), 0x1100);
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0105,
		.resource_id = 1,
		.width = 2,
		.height = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0103,
		.resource_id = 1,
		.scanout_id = 0,
		.width = 2,
		.height = 1,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0101,
		.resource_id = 2,
		.format = 1,
		.width = VIRTIO_GPU_2D_CURSOR_WIDTH,
		.height = VIRTIO_GPU_2D_CURSOR_HEIGHT,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);
	/*
	 * Put an opaque red pixel at source column one.  A hotspot at column
	 * one positioned at x=0 must crop column zero and present this pixel
	 * at destination column zero.
	 */
	sc.vsc_state->resources[1].pixels[6] = 0xff;
	sc.vsc_state->resources[1].pixels[7] = 0xff;
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0300,
		.resource_id = 2,
		.scanout_id = 0,
		.x = 0,
		.y = 0,
		.hot_x = 1,
		.hot_y = 0,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);

	sc.vsc_width = 2;
	sc.vsc_height = 1;
	sc.vsc_display_staging_size = sizeof(output);
	sc.vsc_display_staging = malloc(sizeof(output));
	ATF_REQUIRE(sc.vsc_display_staging != NULL);
	sc.vsc_cursor_staging = malloc(VIRTIO_GPU_2D_CURSOR_BYTES);
	ATF_REQUIRE(sc.vsc_cursor_staging != NULL);
	memset(output, 0xa5, sizeof(output));
	test_console_image = (struct bhyvegc_image) {
		.width = 2,
		.height = 1,
		.data = (uint32_t *)(void *)output,
	};
	gc.image = &test_console_image;
	pci_vtgpu_render(&gc, &sc);
	ATF_CHECK_EQ(memcmp(output, (uint8_t[]) {
	    0x00, 0x00, 0xff, 0x00,
	    0x00, 0xff, 0x00, 0x00,
	}, sizeof(output)), 0);

	/* A mismatched sink is left untouched rather than overrun. */
	test_console_image.width = 1;
	memset(output, 0x5a, sizeof(output));
	pci_vtgpu_render(&gc, &sc);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0x5a);
	test_console_image.width = 2;

	/* A failed atomic capture preserves the last presented frame. */
	sc.vsc_display_staging_size = sizeof(output) - 1;
	memset(output, 0x6b, sizeof(output));
	pci_vtgpu_render(&gc, &sc);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0x6b);
	sc.vsc_display_staging_size = sizeof(output);

	/*
	 * With no cursor staging the scanout is still presented; cursor
	 * compositing is skipped rather than dereferencing a null overlay.
	 */
	{
		uint8_t *saved_cursor = sc.vsc_cursor_staging;

		sc.vsc_cursor_staging = NULL;
		memset(output, 0xa5, sizeof(output));
		pci_vtgpu_render(&gc, &sc);
		ATF_CHECK_EQ(memcmp(output, (uint8_t[]) {
		    0x00, 0x00, 0xff, 0x00,
		    0x00, 0xff, 0x00, 0x00,
		}, sizeof(output)), 0);
		sc.vsc_cursor_staging = saved_cursor;
	}

	/* An explicit scanout disable presents a blank display. */
	command = (struct virtio_gpu_2d_command) {
		.type = 0x0103,
		.resource_id = 0,
		.scanout_id = 0,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_execute(sc.vsc_state, &command,
	    NULL, 0), 0x1100);
	memset(output, 0x7c, sizeof(output));
	pci_vtgpu_render(&gc, &sc);
	for (size_t i = 0; i < sizeof(output); i++)
		ATF_CHECK_EQ(output[i], 0);
	free(sc.vsc_cursor_staging);
	free(sc.vsc_display_staging);
	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

/*
 * Build a device with a live 2D state engine whose DMA backing is the shared
 * blob_guest window, matching the display test's proven setup.  The scanout is
 * 2x1 so a single resource plus its backing fit the window.
 */
static void
notify_softc_setup(struct pci_vtgpu_softc *sc)
{
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;

	memset(sc, 0, sizeof(*sc));
	sc->vsc_consts = vtgpu_vi_consts;
	sc->vsc_vs.vs_vc = &sc->vsc_consts;
	sc->vsc_width = 2;
	sc->vsc_height = 1;
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 4,
		.max_host_bytes = UINT64_C(1) << 20,
		.scanout_width = 2,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = blob_dma_validate,
		.dma_read = blob_dma_read,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &sc->vsc_state), 0);
	memset(blob_guest, 0, sizeof(blob_guest));
}

static uint32_t
notify_one(struct pci_vtgpu_softc *sc, uint16_t queue_num)
{
	struct vqueue_info vq;

	memset(&vq, 0, sizeof(vq));
	vq.vq_num = queue_num;
	vq.vq_qsize = 16;
	mockq_pos = 0;
	mockq_used_n = 0;
	mock_relchain_calls = 0;
	mock_endchains_calls = 0;
	mock_needs_reset_calls = 0;
	pci_vtgpu_notify(sc, &vq);
	return (mockq_used_n > 0 ? mockq_used[0] : 0);
}

ATF_TC_WITHOUT_HEAD(device_private_dma_validate_gate);
ATF_TC_BODY(device_private_dma_validate_gate, tc)
{
	struct pci_vtgpu_softc sc;

	memset(&sc, 0, sizeof(sc));
	blob_dma_acquire_allowed = true;

	/* Only a device-read lease is a legal validation request. */
	ATF_CHECK_EQ(pci_vtgpu_dma_validate(&sc, 0, 8,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ), 0);
	ATF_CHECK_EQ(pci_vtgpu_dma_validate(&sc, 0, 8,
	    (enum virtio_gpu_2d_dma_access)0), EINVAL);

	/* A closed domain gate refuses before mapping. */
	blob_dma_acquire_allowed = false;
	ATF_CHECK_EQ(pci_vtgpu_dma_validate(&sc, 0, 8,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ), EBUSY);
	blob_dma_acquire_allowed = true;

	/* An out-of-window mapping is a fault, and the lease is still released. */
	ATF_CHECK_EQ(pci_vtgpu_dma_validate(&sc, sizeof(blob_guest), 8,
	    VIRTIO_GPU_2D_DMA_DEVICE_READ), EFAULT);
}

ATF_TC_WITHOUT_HEAD(device_reset_clears_events_and_state);
ATF_TC_BODY(device_reset_clears_events_and_state, tc)
{
	struct pci_vtgpu_softc sc;

	notify_softc_setup(&sc);
	sc.vsc_events_read = 1;
	sc.vsc_vs.vs_status = 0x7f;
	mock_reset_dev_calls = 0;
	pci_vtgpu_reset(&sc);
	ATF_CHECK_EQ(sc.vsc_events_read, 0);
	ATF_CHECK_EQ(mock_reset_dev_calls, 1);
	ATF_CHECK_EQ(sc.vsc_vs.vs_status, 0);
	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

ATF_TC_WITHOUT_HEAD(control_queue_returns_display_info_and_edid);
ATF_TC_BODY(control_queue_returns_display_info_and_edid, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t req[64], resp[BHYVE_VIRTIO_GPU_EDID_RESPONSE_SIZE];
	uint32_t used;

	notify_softc_setup(&sc);

	/* GET_DISPLAY_INFO yields the fixed 408-byte pmodes response. */
	gpu_hdr(req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
	mockq_reset();
	mockq_push(req, 24, resp, sizeof(resp));
	used = notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
	ATF_CHECK_EQ(used, 408);
	ATF_CHECK_EQ(mock_endchains_calls, 1);
	ATF_CHECK_EQ(mock_relchain_calls, 1);

	/* GET_EDID is gated on the negotiated EDID feature. */
	gpu_hdr(req, VIRTIO_GPU_CMD_GET_EDID);
	le32enc(req + 24, 0);
	sc.vsc_vs.vs_negotiated_caps =
	    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_EDID);
	mockq_reset();
	mockq_push(req, 32, resp, sizeof(resp));
	used = notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_OK_EDID);
	ATF_CHECK_EQ(used, 1056);

	/* Without the feature the same command is unsupported. */
	sc.vsc_vs.vs_negotiated_caps = 0;
	mockq_reset();
	mockq_push(req, 32, resp, sizeof(resp));
	used = notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_ERR_UNSPEC);
	ATF_CHECK_EQ(used, 24);

	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

ATF_TC_WITHOUT_HEAD(control_queue_runs_2d_resource_lifecycle);
ATF_TC_BODY(control_queue_runs_2d_resource_lifecycle, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t req[64], resp[64];

	notify_softc_setup(&sc);
	/* Two B8G8R8X8 pixels live at the base of the backing window. */
	memcpy(blob_guest, (uint8_t[]) {
	    0x00, 0x00, 0xff, 0x00,
	    0x00, 0xff, 0x00, 0x00,
	}, 8);

#define	RUN(len)	do {						\
	mockq_reset();							\
	mockq_push(req, (len), resp, sizeof(resp));			\
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);		\
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_OK_NODATA);	\
} while (0)

	/* RESOURCE_CREATE_2D: id 1, format B8G8R8X8 (2), 2x1. */
	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
	le32enc(req + 24, 1);
	le32enc(req + 28, 2);
	le32enc(req + 32, 2);
	le32enc(req + 36, 1);
	RUN(40);

	/* RESOURCE_ATTACH_BACKING: id 1, one 8-byte entry at guest addr 0. */
	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
	le32enc(req + 24, 1);
	le32enc(req + 28, 1);
	le64enc(req + 32, 0);
	le32enc(req + 40, 8);
	RUN(48);

	/* TRANSFER_TO_HOST_2D: whole 2x1 rect. */
	gpu_hdr(req, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
	le32enc(req + 32, 2);
	le32enc(req + 36, 1);
	le64enc(req + 40, 0);
	le32enc(req + 48, 1);
	RUN(56);

	/* SET_SCANOUT: bind resource 1 to scanout 0 over the 2x1 rect. */
	gpu_hdr(req, VIRTIO_GPU_CMD_SET_SCANOUT);
	le32enc(req + 32, 2);
	le32enc(req + 36, 1);
	le32enc(req + 40, 0);
	le32enc(req + 44, 1);
	RUN(48);

	/* RESOURCE_FLUSH: same rect. */
	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
	le32enc(req + 32, 2);
	le32enc(req + 36, 1);
	le32enc(req + 40, 1);
	RUN(48);

	/* Detach scanout before releasing the backing. */
	gpu_hdr(req, VIRTIO_GPU_CMD_SET_SCANOUT);
	le32enc(req + 40, 0);
	le32enc(req + 44, 0);
	RUN(48);

	/* RESOURCE_DETACH_BACKING then RESOURCE_UNREF. */
	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING);
	le32enc(req + 24, 1);
	RUN(32);

	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_UNREF);
	le32enc(req + 24, 1);
	RUN(32);
#undef RUN

	/* A well-formed command against a freed resource is a protocol error. */
	gpu_hdr(req, VIRTIO_GPU_CMD_RESOURCE_UNREF);
	le32enc(req + 24, 1);
	mockq_reset();
	mockq_push(req, 32, resp, sizeof(resp));
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID);

	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

ATF_TC_WITHOUT_HEAD(control_queue_error_and_transport_paths);
ATF_TC_BODY(control_queue_error_and_transport_paths, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t req[64], resp[64];
	uint8_t hdr_lo[2], hdr_hi[62];
	struct vqueue_info vq;

	notify_softc_setup(&sc);

	/* An unknown command type completes with the invalid-parameter error. */
	gpu_hdr(req, 0x4242);
	mockq_reset();
	mockq_push(req, 24, resp, sizeof(resp));
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_ERR_UNSPEC);

	/* A short response buffer is a transport EMSGSIZE: relchained with 0. */
	gpu_hdr(req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
	mockq_reset();
	mockq_push(req, 24, resp, 8);
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(mockq_used[0], 0);
	ATF_CHECK_EQ(mock_needs_reset_calls, 0);

	/* Header split across two readable segments exercises the copy clamp. */
	gpu_hdr(req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
	memcpy(hdr_lo, req, 2);
	memcpy(hdr_hi, req + 2, 22);
	mockq_reset();
	mockq[0].iov[0].iov_base = hdr_lo;
	mockq[0].iov[0].iov_len = 2;
	mockq[0].iov[1].iov_base = hdr_hi;
	mockq[0].iov[1].iov_len = 22;
	mockq[0].iov[2].iov_base = resp;
	mockq[0].iov[2].iov_len = sizeof(resp) < 408 ? sizeof(resp) : 408;
	mockq[0].iov[2].iov_len = 408;
	mockq[0].n = 3;
	mockq[0].readable = 2;
	mockq[0].ordered = true;
	mockq_len = 1;
	{
		uint8_t big[408];

		mockq[0].iov[2].iov_base = big;
		(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
		ATF_CHECK_EQ(resp_type(big), VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
		ATF_CHECK_EQ(mockq_used[0], 408);
	}

	/* An invalid descriptor chain forces a device reset. */
	mockq_reset();
	mockq[0].iov[0].iov_base = req;
	mockq[0].iov[0].iov_len = 24;
	mockq[0].n = 1;
	mockq[0].readable = 1;
	mockq[0].ordered = false;	/* rejected by chain_valid */
	mockq_len = 1;
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);
	ATF_CHECK_EQ(mockq_used[0], 0);

	/* A getchain returning nothing simply ends the drain. */
	mockq_reset();
	mockq[0].fail_getchain = true;
	mockq[0].getchain_ret = 0;
	mockq[0].n = 1;
	mockq_len = 1;
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	ATF_CHECK_EQ(mock_relchain_calls, 0);
	ATF_CHECK_EQ(mock_endchains_calls, 1);

	/* An unrecognised queue index is a fatal transport violation. */
	memset(&vq, 0, sizeof(vq));
	vq.vq_num = 7;
	vq.vq_qsize = 4;
	mock_needs_reset_calls = 0;
	pci_vtgpu_notify(&sc, &vq);
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);

	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

ATF_TC_WITHOUT_HEAD(control_queue_request_alloc_failure_resets);
ATF_TC_BODY(control_queue_request_alloc_failure_resets, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t req[64], resp[408];

	notify_softc_setup(&sc);
	gpu_hdr(req, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
	mockq_reset();
	mockq_push(req, 24, resp, sizeof(resp));
	/* Fail the request-gather allocation inside the queue processor. */
	wrap_malloc_calls = 0;
	wrap_malloc_fail_at = 0;
	(void)notify_one(&sc, VIRTIO_GPU_2D_CONTROL_QUEUE);
	wrap_malloc_fail_at = -1;
	ATF_CHECK_EQ(mock_needs_reset_calls, 1);
	ATF_CHECK_EQ(mockq_used[0], 0);

	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

ATF_TC_WITHOUT_HEAD(cursor_queue_updates_with_and_without_sink);
ATF_TC_BODY(cursor_queue_updates_with_and_without_sink, tc)
{
	struct pci_vtgpu_softc sc;
	uint8_t req[64], resp[64];
	uint32_t used;

	notify_softc_setup(&sc);

	/* UPDATE_CURSOR with no writable sink is consumed without a response. */
	gpu_hdr(req, VIRTIO_GPU_CMD_UPDATE_CURSOR);
	mockq_reset();
	mockq_push(req, 56, NULL, 0);
	used = notify_one(&sc, VIRTIO_GPU_2D_CURSOR_QUEUE);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(mock_relchain_calls, 1);

	/* MOVE_CURSOR with a sink returns a nodata acknowledgement. */
	gpu_hdr(req, VIRTIO_GPU_CMD_MOVE_CURSOR);
	mockq_reset();
	mockq_push(req, 56, resp, sizeof(resp));
	used = notify_one(&sc, VIRTIO_GPU_2D_CURSOR_QUEUE);
	ATF_CHECK_EQ(resp_type(resp), VIRTIO_GPU_RESP_OK_NODATA);
	ATF_CHECK_EQ(used, 24);

	virtio_gpu_2d_state_destroy(sc.vsc_state);
}

static void
init_cleanup(void)
{
	struct pci_vtgpu_softc *sc;

	sc = stub_linkup_softc;
	if (sc == NULL)
		return;
	if (sc->vsc_display_registered)
		(void)console_fb_unregister("virtio-gpu", sc);
	free(sc->vsc_cursor_staging);
	free(sc->vsc_display_staging);
	virtio_gpu_2d_state_destroy(sc->vsc_state);
	free(sc->vsc_vs.vs_modern);
	pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	stub_linkup_softc = NULL;
}

ATF_TC_WITHOUT_HEAD(device_init_construction_paths);
ATF_TC_BODY(device_init_construction_paths, tc)
{
	struct pci_devinst pi;

	/* Default construction with no options. */
	memset(&pi, 0, sizeof(pi));
	init_config_reset();
	ATF_REQUIRE_EQ(pci_vtgpu_init(&pi, NULL), 0);
	ATF_REQUIRE(stub_linkup_softc != NULL);
	ATF_CHECK_EQ(((struct pci_vtgpu_softc *)stub_linkup_softc)->vsc_width,
	    VTGPU_DEFAULT_WIDTH);
	ATF_CHECK_EQ(pi.pi_cfgdata[PCIR_CLASS], PCIC_DISPLAY);
	ATF_CHECK_EQ(pi.pi_cfgdata[PCIR_SUBCLASS], PCIS_DISPLAY_OTHER);
	init_cleanup();

	/* Explicit dimensions plus blob and packed feature options. */
	memset(&pi, 0, sizeof(pi));
	init_config_reset();
	cfg_width = "800";
	cfg_height = "600";
	cfg_blob = true;
	cfg_packed = true;
	ATF_REQUIRE_EQ(pci_vtgpu_init(&pi, NULL), 0);
	{
		struct pci_vtgpu_softc *sc = stub_linkup_softc;

		ATF_REQUIRE(sc != NULL);
		ATF_CHECK_EQ(sc->vsc_width, 800);
		ATF_CHECK_EQ(sc->vsc_height, 600);
		ATF_CHECK((sc->vsc_consts.vc_hv_caps &
		    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_RESOURCE_BLOB)) != 0);
		ATF_CHECK((sc->vsc_consts.vc_hv_caps & VIRTIO14_F_RING_PACKED) !=
		    0);
	}
	init_cleanup();

	/* Display option allocates staging and registers the framebuffer. */
	memset(&pi, 0, sizeof(pi));
	init_config_reset();
	cfg_display = true;
	ATF_REQUIRE_EQ(pci_vtgpu_init(&pi, NULL), 0);
	{
		struct pci_vtgpu_softc *sc = stub_linkup_softc;

		ATF_REQUIRE(sc != NULL);
		ATF_CHECK(sc->vsc_display_registered);
		ATF_CHECK(sc->vsc_display_staging != NULL);
		ATF_CHECK(sc->vsc_cursor_staging != NULL);
	}
	ATF_CHECK_EQ(stub_fb_register_calls, 1);
	init_cleanup();
}

ATF_TC_WITHOUT_HEAD(device_init_rejects_and_unwinds);
ATF_TC_BODY(device_init_rejects_and_unwinds, tc)
{
	struct pci_devinst pi;

	/* Malformed and out-of-range dimensions are rejected before setup. */
	init_config_reset();
	cfg_width = "-1";
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	init_config_reset();
	cfg_height = "notanumber";
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	init_config_reset();
	cfg_width = "5000";	/* exceeds the 4095 timing bound */
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	/* The initial softc allocation failing aborts immediately. */
	init_config_reset();
	wrap_calloc_fail_at = 0;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);
	alloc_fault_reset();

	/* State-engine allocation failing unwinds the mutex. */
	init_config_reset();
	wrap_calloc_fail_at = 1;	/* softc ok, state calloc fails */
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);
	alloc_fault_reset();

	/* Transport selection failure unwinds the mutex. */
	init_config_reset();
	stub_select_transport_ret = 1;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	/* Interrupt setup failure unwinds the created state. */
	init_config_reset();
	stub_intr_init_ret = 1;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	/* Modern transport init failure unwinds the interrupt mutex. */
	init_config_reset();
	stub_modern_init_ret = 1;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);

	/* Display staging allocation failure unwinds without registering. */
	init_config_reset();
	cfg_display = true;
	wrap_malloc_fail_at = 0;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);
	ATF_CHECK_EQ(stub_fb_register_calls, 0);
	alloc_fault_reset();

	/* Cursor staging allocation failure unwinds the display staging. */
	init_config_reset();
	cfg_display = true;
	wrap_malloc_fail_at = 1;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);
	alloc_fault_reset();

	/* Framebuffer registration failure unwinds everything. */
	init_config_reset();
	cfg_display = true;
	stub_fb_register_ret = 1;
	ATF_CHECK_EQ(pci_vtgpu_init(&pi, NULL), 1);
	ATF_CHECK_EQ(stub_fb_register_calls, 1);
}

ATF_TC_WITHOUT_HEAD(snapshot_envelope_and_body_negatives);
ATF_TC_BODY(snapshot_envelope_and_body_negatives, tc)
{
	struct pci_vtgpu_softc source, dest;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	uint8_t image[8192], scratch[8192];
	size_t used;

	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));
	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = 2,
		.max_host_bytes = 64,
		.scanout_width = 2,
		.scanout_height = 1,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = blob_dma_validate,
		.dma_read = blob_dma_read,
	};
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &source.vsc_state), 0);
	ATF_REQUIRE_EQ(virtio_gpu_2d_state_create(&limits, &ops,
	    &dest.vsc_state), 0);
	source.vsc_width = dest.vsc_width = 2;
	source.vsc_height = dest.vsc_height = 1;

	ATF_REQUIRE_EQ(run_snapshot(&source, image, sizeof(image),
	    VM_SNAPSHOT_SAVE, &used), 0);
	ATF_REQUIRE(used > 32);

	/* A mismatched scanout identity is rejected before the body is read. */
	memcpy(scratch, image, used);
	le32enc(scratch + 16, 999);
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), EINVAL);

	/* A non-zero reserved word is rejected. */
	memcpy(scratch, image, used);
	le32enc(scratch + 12, 1);
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), EINVAL);

	/* Undefined events bits are rejected. */
	memcpy(scratch, image, used);
	le32enc(scratch + 8, 2);
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), EINVAL);

	/* A body length below the fixed floor is too small. */
	memcpy(scratch, image, used);
	le64enc(scratch + 24, 10);
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), E2BIG);

	/* A body length beyond the state limit is too big. */
	memcpy(scratch, image, used);
	le64enc(scratch + 24, UINT64_C(1) << 40);
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), E2BIG);

	/* The working-buffer allocation failing is reported as out of memory. */
	memcpy(scratch, image, used);
	wrap_malloc_calls = 0;
	wrap_malloc_fail_at = 0;
	ATF_CHECK_EQ(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL), ENOMEM);
	alloc_fault_reset();

	/* A corrupt state body fails validation and restore, not the envelope. */
	memcpy(scratch, image, used);
	scratch[32] ^= 0xff;
	ATF_CHECK(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_VALIDATE,
	    NULL) != 0);
	memcpy(scratch, image, used);
	scratch[32] ^= 0xff;
	ATF_CHECK(run_snapshot(&dest, scratch, used, VM_SNAPSHOT_RESTORE,
	    NULL) != 0);

	virtio_gpu_2d_state_destroy(dest.vsc_state);
	virtio_gpu_2d_state_destroy(source.vsc_state);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, config_read_and_write_to_clear);
	ATF_TP_ADD_TC(tp, device_lifecycle_contract);
	ATF_TP_ADD_TC(tp, device_private_dma_holds_domain_lease);
	ATF_TP_ADD_TC(tp, descriptor_direction_contract);
	ATF_TP_ADD_TC(tp, monitor_dimension_options);
	ATF_TP_ADD_TC(tp, snapshot_callback_validates_before_event_publication);
	ATF_TP_ADD_TC(tp, display_renderer_copies_active_scanout);
	ATF_TP_ADD_TC(tp, device_private_dma_validate_gate);
	ATF_TP_ADD_TC(tp, device_reset_clears_events_and_state);
	ATF_TP_ADD_TC(tp, control_queue_returns_display_info_and_edid);
	ATF_TP_ADD_TC(tp, control_queue_runs_2d_resource_lifecycle);
	ATF_TP_ADD_TC(tp, control_queue_error_and_transport_paths);
	ATF_TP_ADD_TC(tp, control_queue_request_alloc_failure_resets);
	ATF_TP_ADD_TC(tp, cursor_queue_updates_with_and_without_sink);
	ATF_TP_ADD_TC(tp, device_init_construction_paths);
	ATF_TP_ADD_TC(tp, device_init_rejects_and_unwinds);
	ATF_TP_ADD_TC(tp, snapshot_envelope_and_body_negatives);
	return (atf_no_error());
}
