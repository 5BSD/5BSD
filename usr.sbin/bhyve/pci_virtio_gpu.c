/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/param.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/gpu/virtio_gpu.h>
#include <dev/virtio/virtio_ids.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bhyverun.h"
#include "bhyvegc.h"
#include "config.h"
#include "console.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_gpu_2d_protocol.h"
#include "virtio_gpu_2d_display.h"
#include "virtio_gpu_2d_queue.h"
#include "virtio_gpu_2d_state.h"
#include "virtio_pci_modern_probes.h"

#define	VTGPU_RINGSZ			256
#define	VTGPU_NUM_QUEUES		2
#define	VTGPU_DEFAULT_WIDTH		1024U
#define	VTGPU_DEFAULT_HEIGHT		768U
#define	VTGPU_DEFAULT_RESOURCES		256U
#define	VTGPU_DEFAULT_HOST_BYTES	(UINT64_C(256) * 1024 * 1024)
#define	VTGPU_DEFAULT_BLOB_BYTES	(UINT64_C(256) * 1024 * 1024)
#define	VTGPU_BLOB_ALIGNMENT		4096U
#define	VTGPU_SNAPSHOT_MAGIC		0x31555047U	/* "GPU1" */
#define	VTGPU_SNAPSHOT_VERSION		2U

struct pci_vtgpu_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_vq[VTGPU_NUM_QUEUES];
	struct virtio_consts vsc_consts;
	pthread_mutex_t vsc_mtx;
	struct virtio_gpu_2d_state *vsc_state;
	uint32_t vsc_width;
	uint32_t vsc_height;
	uint32_t vsc_events_read;
	uint32_t vsc_max_resources;
	uint64_t vsc_max_host_bytes;
	uint64_t vsc_max_blob_bytes;
	uint8_t *vsc_display_staging;
	size_t vsc_display_staging_size;
	uint8_t *vsc_cursor_staging;
	bool vsc_blob_enabled;
	bool vsc_display_enabled;
	bool vsc_display_registered;
};

static void pci_vtgpu_reset(void *);
static void pci_vtgpu_notify(void *, struct vqueue_info *);
static int pci_vtgpu_cfgread(void *, int, int, uint32_t *);
static int pci_vtgpu_cfgwrite(void *, int, int, uint32_t);
static void pci_vtgpu_render(struct bhyvegc *, void *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtgpu_snapshot(void *, struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtgpu_vi_consts = {
	.vc_name = "vtgpu",
	.vc_nvq = VTGPU_NUM_QUEUES,
	.vc_cfgsize = BHYVE_VIRTIO_GPU_CONFIG_SIZE,
	.vc_reset = pci_vtgpu_reset,
	.vc_qnotify = pci_vtgpu_notify,
	.vc_cfgread = pci_vtgpu_cfgread,
	.vc_cfgwrite = pci_vtgpu_cfgwrite,
	.vc_suspend = vi_pci_lifecycle_noop,
	.vc_resume_device = vi_pci_lifecycle_noop,
	.vc_pause = vi_pci_lifecycle_noop,
	.vc_resume = vi_pci_lifecycle_noop,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtgpu_snapshot,
#endif
	/*
	 * Keep the optional ordering promise disabled until the command queue is
	 * qualified across rendering and display-backend lifecycle transitions.
	 */
	.vc_hv_caps = VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND |
	    (UINT64_C(1) << VIRTIO_GPU_F_EDID),
};

static int
pci_vtgpu_dma_validate(void *arg, uint64_t address, size_t length,
    enum virtio_gpu_2d_dma_access access)
{
	struct pci_vtgpu_softc *sc;
	struct virtio_dma_lease lease;
	enum virtio_dma_direction direction;
	void *mapping;

	sc = arg;
	if (access != VIRTIO_GPU_2D_DMA_DEVICE_READ)
		return (EINVAL);
	direction = VIRTIO_DMA_DEVICE_READ;
	lease = (struct virtio_dma_lease) { 0 };
	if (!vi_dma_acquire(&sc->vsc_vs, &lease))
		return (EBUSY);
	mapping = vi_map_dma(&sc->vsc_vs, address, length, direction);
	vi_dma_release(&sc->vsc_vs, &lease);
	return (mapping == NULL ? EFAULT : 0);
}

static int
pci_vtgpu_dma_read(void *arg, uint64_t address, void *output, size_t length)
{
	struct pci_vtgpu_softc *sc;
	struct virtio_dma_lease lease;
	const void *mapping;
	int error;

	sc = arg;
	lease = (struct virtio_dma_lease) { 0 };
	if (!vi_dma_acquire(&sc->vsc_vs, &lease))
		return (EBUSY);
	mapping = vi_map_dma(&sc->vsc_vs, address, length,
	    VIRTIO_DMA_DEVICE_READ);
	if (mapping == NULL)
		error = EFAULT;
	else {
		memcpy(output, mapping, length);
		error = 0;
	}
	vi_dma_release(&sc->vsc_vs, &lease);
	return (error);
}

static void
pci_vtgpu_render(struct bhyvegc *gc, void *arg)
{
	struct pci_vtgpu_softc *sc;
	struct bhyvegc_image *image;
	uint32_t cursor_format, cursor_hot_x, cursor_hot_y, cursor_x, cursor_y;
	uint32_t format, height, width;
	uint32_t cursor_source_x, cursor_source_y, cursor_width, cursor_height;
	uint32_t cursor_destination_x, cursor_destination_y;
	size_t bytes, destination_stride, source_stride;
	int error;

	sc = arg;
	image = bhyvegc_get_image(gc);
	if (image == NULL || image->data == NULL ||
	    image->width <= 0 || image->height <= 0 ||
	    (uint32_t)image->width != sc->vsc_width ||
	    (uint32_t)image->height != sc->vsc_height)
		return;
	destination_stride = (size_t)image->width * sizeof(uint32_t);
	if (destination_stride / sizeof(uint32_t) != (size_t)image->width ||
	    (size_t)image->height > SIZE_MAX / destination_stride)
		return;
	error = virtio_gpu_2d_state_capture_scanout(sc->vsc_state,
	    sc->vsc_display_staging, sc->vsc_display_staging_size, &width,
	    &height, &format, &bytes);
	if (error != 0)
		return;
	if (width == 0 || height == 0) {
		memset(image->data, 0,
		    destination_stride * (size_t)image->height);
		return;
	}
	source_stride = (size_t)width * sizeof(uint32_t);
	if (source_stride / sizeof(uint32_t) != width ||
	    height > SIZE_MAX / source_stride ||
	    bytes != source_stride * height)
		return;
	memset(image->data, 0, destination_stride * (size_t)image->height);
	error = virtio_gpu_2d_convert_xrgb(format, sc->vsc_display_staging,
	    source_stride, image->data, destination_stride, width, height);
	if (error != 0 || sc->vsc_cursor_staging == NULL)
		return;
	error = virtio_gpu_2d_state_copy_cursor(sc->vsc_state,
	    sc->vsc_cursor_staging, VIRTIO_GPU_2D_CURSOR_BYTES,
	    &cursor_format, &cursor_x, &cursor_y, &cursor_hot_x,
	    &cursor_hot_y);
	if (error != 0)
		return;

	/*
	 * The cursor position names the hotspot.  Crop the source at the
	 * upper/left edge and crop the destination at the lower/right edge;
	 * never form a negative unsigned coordinate.
	 */
	cursor_source_x = cursor_hot_x > cursor_x ?
	    cursor_hot_x - cursor_x : 0;
	cursor_source_y = cursor_hot_y > cursor_y ?
	    cursor_hot_y - cursor_y : 0;
	cursor_destination_x = cursor_x >= cursor_hot_x ?
	    cursor_x - cursor_hot_x : 0;
	cursor_destination_y = cursor_y >= cursor_hot_y ?
	    cursor_y - cursor_hot_y : 0;
	cursor_width = VIRTIO_GPU_2D_CURSOR_WIDTH - cursor_source_x;
	cursor_height = VIRTIO_GPU_2D_CURSOR_HEIGHT - cursor_source_y;
	if (cursor_destination_x >= (uint32_t)image->width ||
	    cursor_destination_y >= (uint32_t)image->height)
		return;
	if (cursor_width > (uint32_t)image->width - cursor_destination_x)
		cursor_width = (uint32_t)image->width - cursor_destination_x;
	if (cursor_height > (uint32_t)image->height - cursor_destination_y)
		cursor_height = (uint32_t)image->height - cursor_destination_y;
	if (cursor_width == 0 || cursor_height == 0)
		return;
	(void)virtio_gpu_2d_composite_cursor_xrgb(cursor_format,
	    sc->vsc_cursor_staging +
	    ((size_t)cursor_source_y * VIRTIO_GPU_2D_CURSOR_WIDTH +
	    cursor_source_x) * sizeof(uint32_t),
	    VIRTIO_GPU_2D_CURSOR_WIDTH * sizeof(uint32_t),
	    (uint8_t *)image->data +
	    (size_t)cursor_destination_y * destination_stride +
	    (size_t)cursor_destination_x * sizeof(uint32_t),
	    destination_stride, cursor_width, cursor_height);
}

static void
pci_vtgpu_reset(void *arg)
{
	struct pci_vtgpu_softc *sc;

	sc = arg;
	virtio_gpu_2d_state_reset(sc->vsc_state);
	sc->vsc_events_read = 0;
	vi_reset_dev(&sc->vsc_vs);
}

static bool
pci_vtgpu_chain_valid(int n, size_t capacity, const struct vi_req *request)
{

	return (request != NULL && n > 0 && (size_t)n <= capacity &&
	    request->ordered && request->readable != 0 &&
	    request->readable + request->writable == n);
}

static void
pci_vtgpu_notify(void *arg, struct vqueue_info *vq)
{
	struct pci_vtgpu_softc *sc;
	struct virtio_gpu_2d_segment segments[VTGPU_RINGSZ];
	struct iovec iov[VTGPU_RINGSZ];
	struct vi_req request;
	enum virtio_gpu_2d_queue queue;
	uint8_t command_bytes[sizeof(uint32_t)];
	uint32_t command_type;
	size_t copied, used;
	uint16_t budget;
	int error, n;

	sc = arg;
	if (vq->vq_num == VIRTIO_GPU_2D_CONTROL_QUEUE)
		queue = VIRTIO_GPU_2D_CONTROL_QUEUE;
	else if (vq->vq_num == VIRTIO_GPU_2D_CURSOR_QUEUE)
		queue = VIRTIO_GPU_2D_CURSOR_QUEUE;
	else {
		vi_set_needs_reset(&sc->vsc_vs);
		return;
	}
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &request);
		if (n <= 0)
			break;
		if (!pci_vtgpu_chain_valid(n, nitems(iov), &request)) {
			VIRTIO_PROBE_ERROR(sc->vsc_vs.vs_vc->vc_name,
			    "invalid-gpu-chain");
			vi_set_needs_reset(&sc->vsc_vs);
			vq_relchain_req(vq, &request, 0);
			break;
		}
		for (int i = 0; i < n; i++) {
			segments[i] = (struct virtio_gpu_2d_segment) {
				.base = iov[i].iov_base,
				.length = iov[i].iov_len,
				.writable = i >= request.readable,
			};
		}
		copied = 0;
		for (int i = 0; i < request.readable &&
		    copied < sizeof(command_bytes); i++) {
			size_t amount;

			amount = iov[i].iov_len;
			if (amount > sizeof(command_bytes) - copied)
				amount = sizeof(command_bytes) - copied;
			memcpy(command_bytes + copied, iov[i].iov_base, amount);
			copied += amount;
		}
		command_type = copied == sizeof(command_bytes) ?
		    le32dec(command_bytes) : UINT32_MAX;
		used = 0;
		error = virtio_gpu_2d_queue_process_features(sc->vsc_state, queue,
		    segments, (size_t)n, sc->vsc_width, sc->vsc_height,
		    sc->vsc_vs.vs_negotiated_caps, &used);
		VIRTIO_PROBE_GPU_COMMAND(sc->vsc_consts.vc_name, vq->vq_num,
		    command_type, (uint32_t)used, error);
		if (error == ENOMEM)
			vi_set_needs_reset(&sc->vsc_vs);
		vq_relchain_req(vq, &request, (uint32_t)used);
		if (error == ENOMEM)
			break;
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static int
pci_vtgpu_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	struct pci_vtgpu_softc *sc;
	uint8_t config[BHYVE_VIRTIO_GPU_CONFIG_SIZE];
	int error;

	sc = arg;
	if (value == NULL || offset < 0 ||
	    (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(config) ||
	    (size_t)size > sizeof(config) - (size_t)offset)
		return (EINVAL);
	error = virtio_gpu_2d_config_encode(sc->vsc_events_read, 0,
	    sc->vsc_blob_enabled ? VTGPU_BLOB_ALIGNMENT : 0, config);
	if (error != 0)
		return (error);
	return (vi_config_read_le(config, sizeof(config), offset, size, value));
}

static int
pci_vtgpu_cfgwrite(void *arg, int offset, int size, uint32_t value)
{
	struct pci_vtgpu_softc *sc;

	sc = arg;
	if (offset != 4 || size != 4)
		return (EINVAL);
	sc->vsc_events_read &= ~value;
	return (0);
}

static int
pci_vtgpu_parse_dimension(const char *value, uint32_t *result)
{
	char *end;
	unsigned long number;

	if (value == NULL || result == NULL || value[0] == '-')
		return (EINVAL);
	errno = 0;
	number = strtoul(value, &end, 0);
	if (errno != 0 || end == value || *end != '\0' ||
	    number == 0 || number > UINT32_MAX)
		return (EINVAL);
	*result = (uint32_t)number;
	return (0);
}

static bool pci_vtgpu_snapshot_identity_valid(
    const struct pci_vtgpu_softc *, uint32_t, uint32_t, uint32_t) __unused;

static bool
pci_vtgpu_snapshot_identity_valid(const struct pci_vtgpu_softc *sc,
    uint32_t version, uint32_t width, uint32_t height)
{

	if (sc == NULL || version != VTGPU_SNAPSHOT_VERSION)
		return (false);
	return (width == sc->vsc_width && height == sc->vsc_height);
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtgpu_snapshot(void *arg, struct vm_snapshot_meta *meta)
{
	struct pci_vtgpu_softc *sc;
	uint8_t *buffer;
	uint64_t length, maximum;
	uint32_t events_read, height, magic, reserved, version, width;
	size_t state_length;
	int error;

	sc = arg;
	buffer = NULL;
	magic = VTGPU_SNAPSHOT_MAGIC;
	version = VTGPU_SNAPSHOT_VERSION;
	reserved = 0;
	events_read = sc->vsc_events_read;
	width = sc->vsc_width;
	height = sc->vsc_height;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_gpu_2d_state_snapshot_size(sc->vsc_state,
		    &state_length);
		if (error != 0)
			return (error);
		length = state_length;
	} else
		length = 0;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	/*
	 * The discriminator is sufficient to reject a foreign envelope.  Do so
	 * before selecting the version-specific fixed fields, so a truncated
	 * unknown image has the same malformed-envelope result as a complete
	 * unknown image.
	 */
	if (magic != VTGPU_SNAPSHOT_MAGIC ||
	    version != VTGPU_SNAPSHOT_VERSION) {
		error = EINVAL;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(events_read, meta, error, done);
	/* Reserved in all versions; events_clear is an action, not state. */
	SNAPSHOT_LE32_OR_LEAVE(reserved, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(width, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(height, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(length, meta, error, done);
	if (reserved != 0 || (events_read & ~UINT32_C(1)) != 0 ||
	    !pci_vtgpu_snapshot_identity_valid(sc, version, width, height)) {
		error = EINVAL;
		goto done;
	}
	error = virtio_gpu_2d_state_snapshot_limit(sc->vsc_state,
	    &state_length);
	if (error != 0)
		goto done;
	maximum = state_length;
	if (length < 72 || length > maximum || length > SIZE_MAX) {
		error = E2BIG;
		goto done;
	}
	buffer = malloc((size_t)length);
	if (buffer == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_gpu_2d_state_snapshot_save(sc->vsc_state,
		    buffer, (size_t)length);
		if (error != 0)
			goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(buffer, (size_t)length, meta, error, done);
	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		error = virtio_gpu_2d_state_snapshot_validate(sc->vsc_state,
		    buffer, (size_t)length);
		if (error != 0)
			goto done;
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		error = virtio_gpu_2d_state_snapshot_restore(sc->vsc_state,
		    buffer, (size_t)length);
		if (error != 0)
			goto done;
		sc->vsc_events_read = events_read;
	}
	error = 0;
done:
	free(buffer);
	return (error);
}
#endif

static int
pci_vtgpu_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtgpu_softc *sc;
	struct virtio_gpu_2d_limits limits;
	struct virtio_gpu_2d_ops ops;
	const char *value;
	bool intr_initialized, mutex_initialized, packed;
	int error;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	mutex_initialized = false;
	sc->vsc_width = VTGPU_DEFAULT_WIDTH;
	sc->vsc_height = VTGPU_DEFAULT_HEIGHT;
	sc->vsc_max_resources = VTGPU_DEFAULT_RESOURCES;
	sc->vsc_max_host_bytes = VTGPU_DEFAULT_HOST_BYTES;
	sc->vsc_blob_enabled = get_config_bool_node_default(nvl, "blob", false);
	sc->vsc_display_enabled = get_config_bool_node_default(nvl, "display",
	    false);
	if (sc->vsc_blob_enabled)
		sc->vsc_max_blob_bytes = VTGPU_DEFAULT_BLOB_BYTES;
	value = get_config_value_node(nvl, "width");
	if (value != NULL &&
	    pci_vtgpu_parse_dimension(value, &sc->vsc_width) != 0)
		goto fail;
	value = get_config_value_node(nvl, "height");
	if (value != NULL &&
	    pci_vtgpu_parse_dimension(value, &sc->vsc_height) != 0)
		goto fail;
	if (!virtio_gpu_2d_dimensions_valid(sc->vsc_width, sc->vsc_height))
		goto fail;
	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0)
		goto fail;
	mutex_initialized = true;

	sc->vsc_consts = vtgpu_vi_consts;
	if (sc->vsc_blob_enabled) {
		sc->vsc_consts.vc_hv_caps |=
		    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_RESOURCE_BLOB) |
		    (UINT64_C(1) << BHYVE_VIRTIO_GPU_F_BLOB_ALIGNMENT);
	}
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	for (int i = 0; i < VTGPU_NUM_QUEUES; i++)
		sc->vsc_vq[i].vq_qsize = VTGPU_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto fail;

	limits = (struct virtio_gpu_2d_limits) {
		.max_resources = sc->vsc_max_resources,
		.max_host_bytes = sc->vsc_max_host_bytes,
		.max_blob_bytes = sc->vsc_max_blob_bytes,
		.blob_alignment = sc->vsc_blob_enabled ?
		    VTGPU_BLOB_ALIGNMENT : 0,
		.scanout_width = sc->vsc_width,
		.scanout_height = sc->vsc_height,
	};
	ops = (struct virtio_gpu_2d_ops) {
		.dma_validate = pci_vtgpu_dma_validate,
		.dma_read = pci_vtgpu_dma_read,
		.arg = sc,
	};
	error = virtio_gpu_2d_state_create(&limits, &ops, &sc->vsc_state);
	if (error != 0)
		goto fail;
	if (sc->vsc_display_enabled) {
		if ((size_t)sc->vsc_width >
		    SIZE_MAX / sizeof(uint32_t) / sc->vsc_height)
			goto fail;
		sc->vsc_display_staging_size =
		    (size_t)sc->vsc_width * sc->vsc_height *
		    sizeof(uint32_t);
		sc->vsc_display_staging =
		    malloc(sc->vsc_display_staging_size);
		if (sc->vsc_display_staging == NULL)
			goto fail;
		sc->vsc_cursor_staging = malloc(VIRTIO_GPU_2D_CURSOR_BYTES);
		if (sc->vsc_cursor_staging == NULL)
			goto fail;
	}

	vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_GPU);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_DISPLAY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_DISPLAY_OTHER);
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()) != 0)
		goto fail;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
		goto fail;
	/*
	 * This renderer-less device supports GUEST blobs only.  The VirtIO GPU
	 * host-visible region and MAP_BLOB command are for host-only blobs, whose
	 * memory types require VIRGL.  Do not publish an unusable or misleading
	 * shared-memory capability for the guest-only implementation.
	 */
	vi_pci_modern_seal_shared_memory(&sc->vsc_vs);
	if (sc->vsc_display_enabled) {
		error = console_fb_register("virtio-gpu", pci_vtgpu_render, sc);
		if (error != 0)
			goto fail;
		sc->vsc_display_registered = true;
	}
	return (0);

fail:
	if (sc->vsc_display_registered)
		(void)console_fb_unregister("virtio-gpu", sc);
	free(sc->vsc_cursor_staging);
	free(sc->vsc_display_staging);
	virtio_gpu_2d_state_destroy(sc->vsc_state);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	if (mutex_initialized)
		pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtgpu = {
	.pe_emu = "virtio-gpu",
	.pe_init = pci_vtgpu_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = vi_pci_snapshot,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vtgpu);
