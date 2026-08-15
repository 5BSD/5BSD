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

int
console_fb_register(const char *owner __unused,
    fb_render_func_t render_cb __unused, void *arg __unused)
{

	return (0);
}

int
console_fb_unregister(const char *owner __unused, void *arg __unused)
{

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, config_read_and_write_to_clear);
	ATF_TP_ADD_TC(tp, device_lifecycle_contract);
	ATF_TP_ADD_TC(tp, device_private_dma_holds_domain_lease);
	ATF_TP_ADD_TC(tp, descriptor_direction_contract);
	ATF_TP_ADD_TC(tp, monitor_dimension_options);
	ATF_TP_ADD_TC(tp, snapshot_callback_validates_before_event_publication);
	ATF_TP_ADD_TC(tp, display_renderer_copies_active_scanout);
	return (atf_no_error());
}
