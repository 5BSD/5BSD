/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vmmapi.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_mem_host.h"
#include "virtio_pci_modern_probes.h"

/*
 * VIRTIO_ACTIVATION_ASSERTION: memory-request-result-observability
 */

#define	VTMEM_RINGSZ			128
#define	VTMEM_MAXSEGS			32
#define	VTMEM_DEFAULT_BLOCK_SIZE	(2U * 1024U * 1024U)
#define	VTMEM_MAX_BLOCKS		(1024U * 1024U)
#define	VTMEM_SNAPSHOT_MAGIC		0x314d4556U	/* "VEM1" */
#define	VTMEM_SNAPSHOT_VERSION		2U

static int pci_vtmem_debug;

struct pci_vtmem_softc {
	struct virtio_softc vmsc_vs;
	struct vqueue_info vmsc_vq;
	struct virtio_consts vmsc_consts;
	pthread_mutex_t vmsc_mtx;
	struct virtio_mem_host *vmsc_host;
	void *vmsc_host_base;
	uint64_t vmsc_gpa;
	size_t vmsc_region_size;
	int vmsc_segid;
	uint8_t vmsc_suspended_config[BHYVE_VTMEM_CONFIG_SIZE];
	bool vmsc_suspended_config_valid;
};

static void pci_vtmem_reset(void *);
static void pci_vtmem_notify(void *, struct vqueue_info *);
static int pci_vtmem_cfgread(void *, int, int, uint32_t *);
static int pci_vtmem_suspend(void *);
static int pci_vtmem_resume(void *);
/*
 * Common restore may transfer the virtio mutex into this callback; direct
 * restore callers do not.  The runtime ownership probe preserves both
 * contracts, but the static lock checker cannot model that conditional
 * ownership transfer.
 */
static void pci_vtmem_restore_suspended(void *) __no_lock_analysis;
#ifdef BHYVE_SNAPSHOT
static int pci_vtmem_snapshot(void *, struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtmem_vi_consts = {
	.vc_name = "vtmem",
	.vc_nvq = 1,
	.vc_cfgsize = BHYVE_VTMEM_CONFIG_SIZE,
	.vc_reset = pci_vtmem_reset,
	.vc_qnotify = pci_vtmem_notify,
	.vc_cfgread = pci_vtmem_cfgread,
	.vc_suspend = pci_vtmem_suspend,
	.vc_resume_device = pci_vtmem_resume,
	.vc_pause = vi_pci_lifecycle_noop,
	.vc_resume = vi_pci_lifecycle_noop,
	.vc_restore_suspended = pci_vtmem_restore_suspended,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtmem_snapshot,
#endif
	/* Host requested-size callbacks can arrive independently of requests. */
	.vc_hv_caps = VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
};

static int
pci_vtmem_set_range(void *arg, uint64_t address, uint64_t length, bool plug)
{
	struct pci_vtmem_softc *sc;
	uint64_t offset;

	sc = arg;
	if (address < sc->vmsc_gpa ||
	    address - sc->vmsc_gpa > sc->vmsc_region_size ||
	    length > sc->vmsc_region_size - (address - sc->vmsc_gpa))
		return (EINVAL);
	if (plug)
		return (0);

	/*
	 * VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE is intentionally not offered:
	 * unplugged blocks remain mapped and CPU-accessible.  Discard their
	 * undefined contents so an unplug also releases host physical pages.
	 */
	offset = address - sc->vmsc_gpa;
	if (madvise((uint8_t *)sc->vmsc_host_base + offset, (size_t)length,
	    MADV_FREE) != 0)
		return (errno);
	return (0);
}

static void
pci_vtmem_config_changed(void *arg,
    const struct virtio_mem_host_config *config __unused)
{
	struct pci_vtmem_softc *sc;

	sc = arg;
	/*
	 * vmsc_mtx is initialized before the host model and remains valid for
	 * the lifetime of its callback.  Use the concrete mutex here instead
	 * of the nullable VS_LOCK() adapter so the callback's locking contract
	 * is both explicit and visible to thread-safety analysis.
	 */
	pthread_mutex_lock(&sc->vmsc_mtx);
	vi_pci_config_changed(&sc->vmsc_vs);
	pthread_mutex_unlock(&sc->vmsc_mtx);
}

static void
pci_vtmem_reset(void *arg)
{
	struct pci_vtmem_softc *sc;
	int error;

	sc = arg;
	sc->vmsc_suspended_config_valid = false;
	/*
	 * VirtIO 1.4 section 5.15.6 requires ordinary device reset to retain
	 * plugged state.  The transport reset therefore does not unplug RAM.
	 * A failed restore-compensation pass is different: host ownership is
	 * then not known to match the published bitmap.  Carry that failure
	 * through vi_reset_dev() so the next driver initialization cannot
	 * silently proceed over unresolved device memory.
	 */
	error = virtio_mem_host_reset(sc->vmsc_host);
	if (error != 0) {
		VIRTIO_PROBE_ERROR(sc->vmsc_vs.vs_vc->vc_name,
		    "memory-backend-reset");
	}
	vi_reset_dev(&sc->vmsc_vs);
	/*
	 * vi_reset_dev() clears the previous incarnation's runtime latch.  If
	 * backend repair failed, publish the new incarnation as incomplete only
	 * after that reset so checkpoint admission cannot reopen over unresolved
	 * memory ownership.
	 */
	if (error != 0)
		vi_snapshot_restore_incomplete(&sc->vmsc_vs);
}

static int
pci_vtmem_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	struct pci_vtmem_softc *sc;
	uint8_t config[BHYVE_VTMEM_CONFIG_SIZE];
	int error;

	sc = arg;
	if (sc->vmsc_vs.vs_suspended &&
	    sc->vmsc_suspended_config_valid)
		return (vi_config_read_le(sc->vmsc_suspended_config,
		    sizeof(sc->vmsc_suspended_config), offset, size, value));
	error = virtio_mem_host_config_encode(sc->vmsc_host, config);
	if (error != 0)
		return (error);
	return (vi_config_read_le(config, sizeof(config), offset, size, value));
}

static int
pci_vtmem_suspend(void *arg)
{
	struct pci_vtmem_softc *sc;
	int error;

	sc = arg;
	error = virtio_mem_host_config_encode(sc->vmsc_host,
	    sc->vmsc_suspended_config);
	if (error == 0)
		sc->vmsc_suspended_config_valid = true;
	return (error);
}

static int
pci_vtmem_resume(void *arg)
{
	struct pci_vtmem_softc *sc;

	sc = arg;
	sc->vmsc_suspended_config_valid = false;
	return (0);
}

static void
pci_vtmem_restore_suspended(void *arg)
{
	struct pci_vtmem_softc *sc;
	bool already_locked;

	sc = arg;
	/*
	 * The current snapshot records the frozen configuration explicitly, so a
	 * normal restore has already populated it.  Keep this fallback for callers
	 * which enter the suspended lifecycle directly, without decoding a device
	 * image; it is lifecycle initialization, not an older-format decoder.
	 */
	/* Common restore may already own vs_mtx; direct restore callers do not. */
	already_locked = pthread_mutex_isowned_np(&sc->vmsc_mtx);
	if (!already_locked)
		pthread_mutex_lock(&sc->vmsc_mtx);
	if (!sc->vmsc_suspended_config_valid &&
	    virtio_mem_host_config_encode(sc->vmsc_host,
	    sc->vmsc_suspended_config) == 0)
		sc->vmsc_suspended_config_valid = true;
	if (!already_locked)
		pthread_mutex_unlock(&sc->vmsc_mtx);
}

static bool
pci_vtmem_copy_request(const struct iovec *iov, size_t niov,
    uint8_t request[BHYVE_VTMEM_REQUEST_SIZE])
{
	size_t copied;

	copied = 0;
	for (size_t i = 0; i < niov && copied < BHYVE_VTMEM_REQUEST_SIZE; i++) {
		size_t length;

		length = MIN(iov[i].iov_len, BHYVE_VTMEM_REQUEST_SIZE - copied);
		memcpy(request + copied, iov[i].iov_base, length);
		copied += length;
	}
	return (copied == BHYVE_VTMEM_REQUEST_SIZE);
}

static void
pci_vtmem_notify(void *arg, struct vqueue_info *vq)
{
	struct pci_vtmem_softc *sc;
	struct iovec iov[VTMEM_MAXSEGS];
	struct vi_req req;
	uint8_t request[BHYVE_VTMEM_REQUEST_SIZE];
	uint8_t response[BHYVE_VTMEM_RESPONSE_SIZE];
	size_t insize, outsize, response_size, written;
	uint16_t budget;
	int error, n;

	sc = arg;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (n > (int)nitems(iov) || !req.ordered ||
		    req.readable == 0 || req.writable == 0 ||
		    req.readable + req.writable != n) {
			VIRTIO_PROBE_ERROR(sc->vmsc_vs.vs_vc->vc_name,
			    "invalid-memory-chain");
			vi_set_needs_reset(&sc->vmsc_vs);
			vq_relchain_req(vq, &req, 0);
			break;
		}
		insize = count_iov(iov, req.readable);
		outsize = count_iov(&iov[req.readable], req.writable);
		if (insize != sizeof(request) || outsize < sizeof(response) ||
		    !pci_vtmem_copy_request(iov, req.readable, request)) {
			VIRTIO_PROBE_ERROR(sc->vmsc_vs.vs_vc->vc_name,
			    "invalid-memory-request-size");
			vi_set_needs_reset(&sc->vmsc_vs);
			vq_relchain_req(vq, &req, 0);
			break;
		}

		response_size = 0;
		error = virtio_mem_host_request(sc->vmsc_host, request,
		    sizeof(request), response, sizeof(response), &response_size);
		VIRTIO_PROBE_MEM_REQUEST(sc->vmsc_vs.vs_vc->vc_name,
		    le16dec(request), le64dec(request + 8),
		    le16dec(request + 16), error != 0 ? -error :
		    response_size == sizeof(response) ?
		    (int)le16dec(response) : -EPROTO);
		if (error != 0 || response_size != sizeof(response)) {
			VIRTIO_PROBE_ERROR(sc->vmsc_vs.vs_vc->vc_name,
			    "memory-request-handler-failure");
			vi_set_needs_reset(&sc->vmsc_vs);
			vq_relchain_req(vq, &req, 0);
			break;
		}
		if (pci_vtmem_debug != 0) {
			PRINTLN("vtmem: request type=%u address=%#jx blocks=%u "
			    "response=%u", le16dec(request),
			    (uintmax_t)le64dec(request + 8),
			    le16dec(request + 16), le16dec(response));
		}
		written = buf_to_iov(response, response_size,
		    &iov[req.readable], req.writable);
		if (written != response_size) {
			vi_set_needs_reset(&sc->vmsc_vs);
			vq_relchain_req(vq, &req, 0);
			break;
		}
		/*
		 * PLUG and UNPLUG change plugged_size, for which section
		 * 5.15.4.2 says the device SHOULD NOT send a configuration
		 * notification.  UNPLUG_ALL may also shrink
		 * usable_region_size, but that request is the explicit
		 * exception to the otherwise mandatory notification rule.
		 * A future host-side requested-size control must publish its
		 * own configuration interrupt when it changes requested_size
		 * or grows usable_region_size.
		 */
		vq_relchain_req(vq, &req, (uint32_t)written);
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtmem_snapshot(void *arg, struct vm_snapshot_meta *meta)
{
	struct pci_vtmem_softc *sc;
	uint8_t *buffer;
	uint8_t suspended_config[BHYVE_VTMEM_CONFIG_SIZE];
	uint8_t suspended_config_valid;
	uint64_t length;
	uint32_t magic, reserved, version;
	size_t state_length;
	int error;

	sc = arg;
	/*
	 * Checkpoint callbacks run after the common lifecycle fence, but without
	 * the device mutex.  Host requested-size updates take vmsc_mtx through
	 * pci_vtmem_config_changed(), so serialize both the frozen configuration
	 * and host-model image with that path.  Guest suspend/resume already run
	 * under vmsc_mtx through vs_mtx and must not lock it recursively.
	 */
	pthread_mutex_lock(&sc->vmsc_mtx);
	buffer = NULL;
	magic = VTMEM_SNAPSHOT_MAGIC;
	version = VTMEM_SNAPSHOT_VERSION;
	reserved = 0;
	suspended_config_valid = sc->vmsc_suspended_config_valid;
	memcpy(suspended_config, sc->vmsc_suspended_config,
	    sizeof(suspended_config));
	error = virtio_mem_host_snapshot_size(sc->vmsc_host, &state_length);
	if (error != 0)
		goto done;
	if (meta->op == VM_SNAPSHOT_SAVE)
		length = state_length;
	else
		length = 0;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	/*
	 * Accept the format discriminator before attempting to decode its
	 * version-specific body.  This makes an unsupported producer fail
	 * closed even when its record ends at the common prefix.
	 */
	if (magic != VTMEM_SNAPSHOT_MAGIC ||
	    version != VTMEM_SNAPSHOT_VERSION) {
		error = EINVAL;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(reserved, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(length, meta, error, done);
	if (reserved != 0 || length != state_length) {
		error = EINVAL;
		goto done;
	}
	SNAPSHOT_U8_OR_LEAVE(suspended_config_valid, meta, error, done);
	SNAPSHOT_BUF_OR_LEAVE(suspended_config,
	    sizeof(suspended_config), meta, error, done);
	if (suspended_config_valid > 1 ||
	    suspended_config_valid != (uint8_t)sc->vmsc_vs.vs_suspended) {
		error = EINVAL;
		goto done;
	}
	buffer = malloc((size_t)length);
	if (buffer == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_mem_host_snapshot(sc->vmsc_host, buffer,
		    (size_t)length);
		if (error != 0)
			goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(buffer, (size_t)length, meta, error, done);
	if (meta->op == VM_SNAPSHOT_VALIDATE)
		error = virtio_mem_host_restore_validate(sc->vmsc_host, buffer,
		    (size_t)length);
	else if (meta->op == VM_SNAPSHOT_RESTORE)
		error = virtio_mem_host_restore(sc->vmsc_host, buffer,
		    (size_t)length);
	else
		error = 0;
	if (error == 0 && meta->op == VM_SNAPSHOT_RESTORE) {
		sc->vmsc_suspended_config_valid = suspended_config_valid != 0;
		memcpy(sc->vmsc_suspended_config, suspended_config,
		    sizeof(sc->vmsc_suspended_config));
	} else if (error != 0 && meta->op == VM_SNAPSHOT_RESTORE &&
	    virtio_mem_host_restore_incomplete(sc->vmsc_host)) {
		vi_snapshot_restore_incomplete(&sc->vmsc_vs);
	}
done:
	free(buffer);
	pthread_mutex_unlock(&sc->vmsc_mtx);
	return (error);
}
#endif

static int
pci_vtmem_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtmem_softc *sc;
	struct virtio_mem_host_limits limits;
	struct virtio_mem_host_ops ops;
	const char *value;
	char segment_name[VM_MAX_SUFFIXLEN + 1];
	size_t block_size, region_size, requested_size;
	bool intr_initialized, mapped, mtx_initialized, packed;
	int error;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	mapped = false;
	mtx_initialized = false;
	sc->vmsc_host_base = MAP_FAILED;
	value = getenv("BHYVE_VIRTIO_DEBUG");
	if (value != NULL) {
		pci_vtmem_debug = atoi(value);
		if (pci_vtmem_debug < 1)
			pci_vtmem_debug = 1;
	}

	value = get_config_value_node(nvl, "size");
	if (value == NULL || vm_parse_memsize(value, &region_size) != 0 ||
	    region_size == 0)
		goto failed;
	block_size = VTMEM_DEFAULT_BLOCK_SIZE;
	value = get_config_value_node(nvl, "block-size");
	if (value != NULL &&
	    vm_parse_memsize(value, &block_size) != 0)
		goto failed;
	requested_size = 0;
	value = get_config_value_node(nvl, "requested");
	if (value != NULL &&
	    vm_parse_memsize(value, &requested_size) != 0)
		goto failed;
	if (block_size == 0 || !powerof2(block_size) ||
	    block_size < (size_t)getpagesize() ||
	    block_size % (size_t)getpagesize() != 0 ||
	    region_size % block_size != 0 ||
	    requested_size > region_size ||
	    requested_size % block_size != 0 ||
	    region_size / block_size > VTMEM_MAX_BLOCKS)
		goto failed;

	if (pthread_mutex_init(&sc->vmsc_mtx, NULL) != 0)
		goto failed;
	mtx_initialized = true;
	sc->vmsc_region_size = region_size;
	error = pci_emul_alloc_devmem_gpa(region_size, block_size,
	    &sc->vmsc_gpa);
	if (error != 0)
		goto failed;
	snprintf(segment_name, sizeof(segment_name), "vtmem%u.%u.%u",
	    pi->pi_bus, pi->pi_slot, pi->pi_func);
	sc->vmsc_host_base = vm_create_devmem_auto(pi->pi_vmctx, segment_name,
	    region_size, &sc->vmsc_segid);
	if (sc->vmsc_host_base == MAP_FAILED)
		goto failed;
	if (vm_mmap_memseg(pi->pi_vmctx, sc->vmsc_gpa, sc->vmsc_segid, 0,
	    region_size, PROT_READ | PROT_WRITE) != 0)
		goto failed;
	mapped = true;
	if (madvise(sc->vmsc_host_base, region_size, MADV_FREE) != 0)
		goto failed;

	memset(&limits, 0, sizeof(limits));
	limits.block_size = block_size;
	limits.address = sc->vmsc_gpa;
	limits.region_size = region_size;
	limits.usable_region_size = region_size;
	limits.requested_size = requested_size;
	limits.max_blocks = VTMEM_MAX_BLOCKS;
	memset(&ops, 0, sizeof(ops));
	ops.set_range = pci_vtmem_set_range;
	ops.config_changed = pci_vtmem_config_changed;
	ops.arg = sc;
	error = virtio_mem_host_create(&limits, &ops, &sc->vmsc_host);
	if (error != 0)
		goto failed;

	sc->vmsc_consts = vtmem_vi_consts;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vmsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vmsc_vs, &sc->vmsc_consts, sc, pi,
	    &sc->vmsc_vq);
	sc->vmsc_vs.vs_mtx = &sc->vmsc_mtx;
	sc->vmsc_vq.vq_qsize = VTMEM_RINGSZ;
	if (vi_pci_select_transport(&sc->vmsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto failed;
	vi_pci_modern_set_identity(&sc->vmsc_vs, VIRTIO_ID_MEM);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_MEMORY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_MEMORY_RAM);
	if (vi_intr_init(&sc->vmsc_vs, 1, fbsdrun_virtio_msix()) != 0)
		goto failed;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vmsc_vs, 2) != 0)
		goto failed;
	return (0);

failed:
	virtio_mem_host_destroy(sc->vmsc_host);
	free(sc->vmsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vmsc_vs.vs_isr_mtx);
	/*
	 * Kernel memsegs live for the VM lifetime.  Remove a guest mapping if
	 * initialization failed after it was installed; VM teardown reclaims
	 * the otherwise unreferenced segment.
	 */
	if (mapped)
		(void)vm_munmap_memseg(pi->pi_vmctx, sc->vmsc_gpa,
		    sc->vmsc_region_size);
	if (mtx_initialized)
		pthread_mutex_destroy(&sc->vmsc_mtx);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtmem = {
	.pe_emu = "virtio-mem",
	.pe_init = pci_vtmem_init,
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
PCI_EMUL_SET(pci_de_vtmem);
