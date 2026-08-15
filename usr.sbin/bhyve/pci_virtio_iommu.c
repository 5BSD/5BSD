/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/virtio_ids.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "pci_virtio_iommu.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_iommu_config.h"
#include "virtio_iommu_event.h"
#include "virtio_iommu_queue.h"
#include "virtio_iommu_request.h"
#include "virtio_iommu_state.h"
#include "virtio_iommu_topology.h"
#include "virtio_pci_modern_probes.h"

#define	VTIOMMU_RINGSZ		256
#define	VTIOMMU_NUM_QUEUES	2
#define	VTIOMMU_REQUESTQ	0
#define	VTIOMMU_EVENTQ		1
#define	VTIOMMU_MAX_ENDPOINTS	256
#define	VTIOMMU_MAX_DOMAINS	256
#define	VTIOMMU_MAX_MAPPINGS	8192
#define	VTIOMMU_MAX_FAULTS	256
#define	VTIOMMU_PROBE_SIZE	16
#define	VTIOMMU_SNAPSHOT_MAGIC	0x314d4f49U	/* "IOM1" */
#define	VTIOMMU_SNAPSHOT_VERSION	1U
#define	VTIOMMU_STATE_MIN_SIZE	96U
#define	VTIOMMU_STATE_MAX_SIZE	(VTIOMMU_STATE_MIN_SIZE + \
	    VTIOMMU_MAX_ENDPOINTS * 12U + VTIOMMU_MAX_DOMAINS * 16U + \
	    VTIOMMU_MAX_MAPPINGS * 40U + VTIOMMU_MAX_FAULTS * 24U)

struct pci_vtiommu_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_vq[VTIOMMU_NUM_QUEUES];
	struct virtio_consts vsc_consts;
	pthread_mutex_t vsc_mtx;
	struct virtio_iommu_state *vsc_state;
#ifdef BHYVE_SNAPSHOT
	_Atomic(struct virtio_iommu_state *) vsc_validation_state;
	/*
	 * The prepared fabric belongs only to the checkpoint-validation thread.
	 * A pthread_t is opaque and must not be read concurrently with its
	 * publication.  A thread-local object's address is a process-local,
	 * comparable ownership token that can be published atomically instead.
	 */
	_Atomic(const void *) vsc_validation_owner;
#endif
	struct virtio_iommu_config_values vsc_config;
	struct virtio_iommu_request_options vsc_request_options;
	uint16_t vsc_endpoints[VTIOMMU_MAX_ENDPOINTS];
	size_t vsc_endpoint_count;
};

static void pci_vtiommu_reset(void *);
static void pci_vtiommu_notify(void *, struct vqueue_info *);
static int pci_vtiommu_cfgread(void *, int, int, uint32_t *);
static int pci_vtiommu_cfgwrite(void *, int, int, uint32_t);
static int pci_vtiommu_apply_features(void *, uint64_t);
#ifdef BHYVE_SNAPSHOT
static int pci_vtiommu_snapshot(void *, struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtiommu_vi_consts = {
	.vc_name = "vtiommu",
	.vc_nvq = VTIOMMU_NUM_QUEUES,
	.vc_cfgsize = BHYVE_VIOMMU_CONFIG_SIZE,
	.vc_reset = pci_vtiommu_reset,
	.vc_qnotify = pci_vtiommu_notify,
	.vc_cfgread = pci_vtiommu_cfgread,
	.vc_cfgwrite = pci_vtiommu_cfgwrite,
	.vc_apply_features = pci_vtiommu_apply_features,
	.vc_suspend = vi_pci_lifecycle_noop,
	.vc_resume_device = vi_pci_lifecycle_noop,
	.vc_pause = vi_pci_lifecycle_noop,
	.vc_resume = vi_pci_lifecycle_noop,
	/*
	 * This device is the translation provider for the machine-wide
	 * VirtIO topology.  Treating another provider as one of its translated
	 * endpoints would create a circular DMA dependency.
	 */
	.vc_access_platform_ineligible = true,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtiommu_snapshot,
#endif
	.vc_hv_caps = BHYVE_VIOMMU_F_INPUT_RANGE |
	    BHYVE_VIOMMU_F_DOMAIN_RANGE | BHYVE_VIOMMU_F_MAP_UNMAP |
	    BHYVE_VIOMMU_F_PROBE | BHYVE_VIOMMU_F_BYPASS_CONFIG |
	    /* Event delivery and translated-DMA callbacks are asynchronous. */
	    VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
};

static uint16_t
pci_vtiommu_rid(const struct pci_devinst *pi)
{

	return ((uint16_t)((pi->pi_bus << 8) | (pi->pi_slot << 3) |
	    pi->pi_func));
}

static void
pci_vtiommu_limits_init(struct virtio_iommu_limits *limits)
{

	*limits = (struct virtio_iommu_limits) {
		.page_size_mask = UINT64_C(1) << 12,
		.input_start = 0,
		.input_end = UINT64_MAX,
		.domain_start = 0,
		.domain_end = UINT32_MAX,
		.max_domains = VTIOMMU_MAX_DOMAINS,
		.max_endpoints = VTIOMMU_MAX_ENDPOINTS,
		.max_mappings = VTIOMMU_MAX_MAPPINGS,
		.max_faults = VTIOMMU_MAX_FAULTS,
		.default_bypass = false,
		/*
		 * BYPASS_CONFIG defines ATTACH_F_BYPASS as well as the
		 * unattached-endpoint configuration byte.  Keep this enabled
		 * whenever the production feature set advertises bit 6.
		 */
		.bypass_domains = true,
	};
}

static bool
pci_vtiommu_validate_gpa(void *arg, uint64_t address, uint64_t length,
    uint32_t flags __unused)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	if (length == 0 || length > SIZE_MAX)
		return (false);
	return (paddr_guest2host(sc->vsc_vs.vs_pi->pi_vmctx, address,
	    (size_t)length) != NULL);
}

static void *
pci_vtiommu_map_gpa(void *arg, uint64_t address, size_t length,
    enum virtio_dma_direction direction __unused)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	return (paddr_guest2host(sc->vsc_vs.vs_pi->pi_vmctx, address, length));
}

static void pci_vtiommu_drain_events(struct pci_vtiommu_softc *);
static void pci_vtiommu_drain_requests(struct pci_vtiommu_softc *);

#ifdef BHYVE_SNAPSHOT
static _Thread_local uint8_t pci_vtiommu_validation_token;

static const void *
pci_vtiommu_validation_owner_token(void)
{

	return (&pci_vtiommu_validation_token);
}

/*
 * Publish a prepared restore fabric only to the thread which owns the
 * validation pass.  The restore coordinator is currently single-threaded,
 * but pe_snapshot_validate() is a callback boundary and must not make that
 * incidental serialization part of the memory-safety contract.  In
 * particular, a concurrent validator must not replace and destroy the view
 * against which the first validator is still checking endpoint DMA state.
 */
static int
pci_vtiommu_validation_publish(struct pci_vtiommu_softc *sc,
    struct virtio_iommu_state *prepared,
    struct virtio_iommu_state **replacedp)
{
	const void *expected, *token;

	if (sc == NULL || prepared == NULL || replacedp == NULL)
		return (EINVAL);
	token = pci_vtiommu_validation_owner_token();
	expected = NULL;
	if (!atomic_compare_exchange_strong_explicit(&sc->vsc_validation_owner,
	    &expected, token, memory_order_acq_rel, memory_order_acquire) &&
	    expected != token)
		return (EBUSY);
	*replacedp = atomic_exchange_explicit(&sc->vsc_validation_state,
	    prepared, memory_order_acq_rel);
	return (0);
}
#endif

static struct virtio_iommu_state *
pci_vtiommu_domain_state(struct pci_vtiommu_softc *sc)
{

#ifdef BHYVE_SNAPSHOT
	struct virtio_iommu_state *prepared;
	const void *owner;

	prepared = atomic_load_explicit(&sc->vsc_validation_state,
	    memory_order_acquire);
	owner = atomic_load_explicit(&sc->vsc_validation_owner,
	    memory_order_acquire);
	if (prepared != NULL && owner == pci_vtiommu_validation_owner_token())
		return (prepared);
#endif
	return (sc->vsc_state);
}

/*
 * Backend callbacks do not enter through vi_pci_notify(), so reproduce its
 * lifecycle fence before touching a guest ring.  Retain a non-fatal edge as
 * a pending notification: DRIVER_OK and checkpoint/guest resume replay
 * pending queues through the common transport path.
 */
static bool
pci_vtiommu_callback_ready_locked(struct pci_vtiommu_softc *sc,
    struct vqueue_info *vq)
{
	struct virtio_softc *vs;

	vs = &sc->vsc_vs;
	if (atomic_load_explicit(&vs->vs_resetting, memory_order_acquire) ||
	    (vs->vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		return (false);
	if (vs->vs_quiescing || vs->vs_suspended ||
	    vs->vs_checkpoint_paused ||
	    (vs->vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0) {
		vq->vq_notify_pending = true;
		return (false);
	}
	return (true);
}

static void
pci_vtiommu_fault(void *arg, uint32_t endpoint,
    enum virtio_iommu_fault_reason reason, uint64_t address,
    enum virtio_dma_direction direction)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	VIRTIO_PROBE_IOMMU_FAULT(sc->vsc_consts.vc_name, endpoint, reason,
	    address, direction);
	pci_vtiommu_drain_events(sc);
}

static void
pci_vtiommu_dma_idle(void *arg, uint32_t endpoint __unused)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	/*
	 * A revoking request which encountered older endpoint DMA was returned
	 * to the available ring.  Retry it from this edge; do not poll.
	 */
	pci_vtiommu_drain_requests(sc);
}

static bool
pci_vtiommu_domain_acquire(void *arg, uint32_t endpoint)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	return (virtio_iommu_dma_acquire(pci_vtiommu_domain_state(sc),
	    endpoint));
}

static void
pci_vtiommu_domain_release(void *arg, uint32_t endpoint)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	virtio_iommu_dma_release(pci_vtiommu_domain_state(sc), endpoint);
}

static void *
pci_vtiommu_domain_map(void *arg, uint32_t endpoint, uint64_t address,
    size_t length, enum virtio_dma_direction direction)
{
	struct pci_vtiommu_softc *sc;
	void *mapping;

	sc = arg;
	mapping = virtio_iommu_translate(pci_vtiommu_domain_state(sc),
	    endpoint, address, length, direction);
	VIRTIO_PROBE_IOMMU_TRANSLATE(sc->vsc_consts.vc_name, endpoint,
	    address, length, (mapping != NULL));
	return (mapping);
}

static uint64_t
pci_vtiommu_domain_generation(void *arg)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	return (virtio_iommu_generation(pci_vtiommu_domain_state(sc)));
}

static const struct virtio_dma_domain_ops vtiommu_dma_ops = {
	.vddo_acquire = pci_vtiommu_domain_acquire,
	.vddo_release = pci_vtiommu_domain_release,
	.vddo_map = pci_vtiommu_domain_map,
	.vddo_generation = pci_vtiommu_domain_generation,
};

static void
pci_vtiommu_drain_events_locked(struct pci_vtiommu_softc *sc)
{
	struct vqueue_info *vq;
	struct iovec iov[VTIOMMU_RINGSZ];
	struct vi_req request;
	size_t used;
	uint16_t budget;
	int error, n;

	vq = &sc->vsc_vq[VTIOMMU_EVENTQ];
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &request);
		if (n == 0)
			break;
		if (n < 0) {
			VIRTIO_PROBE_ERROR(sc->vsc_consts.vc_name,
			    "invalid IOMMU event chain");
			vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
		if (n > (int)nitems(iov) || request.readable != 0 ||
		    request.writable != n) {
			vq_relchain_req(vq, &request, 0);
			continue;
		}
		used = 0;
		error = virtio_iommu_event_process(sc->vsc_state, iov,
		    (size_t)n, &used);
		if (error == EAGAIN) {
			vq_retchain_req(vq, &request);
			break;
		}
		vq_relchain_req(vq, &request, (uint32_t)used);
		if (error == ENOMEM) {
			vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static void
pci_vtiommu_drain_events(struct pci_vtiommu_softc *sc)
{

	pthread_mutex_lock(&sc->vsc_mtx);
	if (pci_vtiommu_callback_ready_locked(sc,
	    &sc->vsc_vq[VTIOMMU_EVENTQ]))
		pci_vtiommu_drain_events_locked(sc);
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_vtiommu_drain_requests_locked(struct pci_vtiommu_softc *sc)
{
	struct vqueue_info *vq;
	struct iovec iov[VTIOMMU_RINGSZ];
	struct vi_req request;
	size_t used;
	uint16_t budget;
	uint8_t type;
	int error, n;

	vq = &sc->vsc_vq[VTIOMMU_REQUESTQ];
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &request);
		if (n == 0)
			break;
		if (n < 0) {
			VIRTIO_PROBE_ERROR(sc->vsc_consts.vc_name,
			    "invalid IOMMU request chain");
			vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
		if (n > (int)nitems(iov) ||
		    request.readable + request.writable != n) {
			vq_relchain_req(vq, &request, 0);
			continue;
		}
		used = 0;
		type = UINT8_MAX;
		for (int i = 0; i < request.readable; i++) {
			if (iov[i].iov_len == 0)
				continue;
			type = *(const uint8_t *)iov[i].iov_base;
			break;
		}
		error = virtio_iommu_queue_process(sc->vsc_state,
		    &sc->vsc_request_options, iov, (size_t)n,
		    (size_t)request.readable, (size_t)request.writable,
		    request.ordered, &used);
		VIRTIO_PROBE_IOMMU_REQUEST(sc->vsc_consts.vc_name,
		    vq->vq_num, type, used, error);
		if (error == EAGAIN) {
			vq_retchain_req(vq, &request);
			break;
		}
		vq_relchain_req(vq, &request, (uint32_t)used);
		if (error == ENOMEM) {
			vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static void
pci_vtiommu_drain_requests(struct pci_vtiommu_softc *sc)
{

	pthread_mutex_lock(&sc->vsc_mtx);
	if (pci_vtiommu_callback_ready_locked(sc,
	    &sc->vsc_vq[VTIOMMU_REQUESTQ]))
		pci_vtiommu_drain_requests_locked(sc);
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_vtiommu_notify(void *arg, struct vqueue_info *vq)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	if (vq->vq_num == VTIOMMU_EVENTQ) {
		pci_vtiommu_drain_events_locked(sc);
		return;
	}
	if (vq->vq_num == VTIOMMU_REQUESTQ) {
		pci_vtiommu_drain_requests_locked(sc);
		return;
	}
	vi_set_needs_reset(&sc->vsc_vs);
}

static void
pci_vtiommu_reset(void *arg)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	virtio_iommu_state_reset(sc->vsc_state);
	sc->vsc_request_options.map_unmap = false;
	sc->vsc_request_options.probe = false;
	sc->vsc_request_options.bypass_config = false;
	vi_reset_dev(&sc->vsc_vs);
}

static int
pci_vtiommu_apply_features(void *arg, uint64_t features)
{
	struct pci_vtiommu_softc *sc;

	sc = arg;
	sc->vsc_request_options.map_unmap =
	    (features & BHYVE_VIOMMU_F_MAP_UNMAP) != 0;
	sc->vsc_request_options.probe =
	    (features & BHYVE_VIOMMU_F_PROBE) != 0;
	sc->vsc_request_options.bypass_config =
	    (features & BHYVE_VIOMMU_F_BYPASS_CONFIG) != 0;
	return (0);
}

static int
pci_vtiommu_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	struct pci_vtiommu_softc *sc;
	uint8_t bytes[BHYVE_VIOMMU_CONFIG_SIZE];
	int error;

	sc = arg;
	error = virtio_iommu_config_encode(&sc->vsc_config,
	    sc->vsc_consts.vc_hv_caps,
	    virtio_iommu_default_bypass(sc->vsc_state), bytes);
	if (error != 0)
		return (error);
	return (vi_config_read_le(bytes, sizeof(bytes), offset, size, value));
}

static int
pci_vtiommu_cfgwrite(void *arg, int offset, int size, uint32_t value)
{
	struct pci_vtiommu_softc *sc;
	int error;

	sc = arg;
	if (offset < 0 || size < 0)
		return (EINVAL);
	error = virtio_iommu_config_write(sc->vsc_state,
	    sc->vsc_vs.vs_negotiated_caps, (size_t)offset, (size_t)size,
	    value);
	VIRTIO_PROBE_IOMMU_CONFIG(sc->vsc_consts.vc_name, offset, size,
	    value, error);
	return (error);
}

static int
pci_vtiommu_post_init(struct pci_devinst *pi)
{
	struct pci_vtiommu_softc *sc;
	struct pci_devinst *peer;
	struct virtio_iommu_topology_entry *entries;
	struct virtio_softc *vs;
	enum virtio_iommu_status status;
	uint16_t iommu_requester_id;
	size_t entry_capacity, entry_count, registered, bound;
	int error;

	sc = pi->pi_arg;
	entries = NULL;
	entry_count = 0;
	bound = 0;
	peer = NULL;
	while ((peer = pci_next(peer)) != NULL) {
		vs = vi_pci_get_softc(peer);
		if (vs == NULL || !vi_pci_is_modern(vs))
			continue;
		if (entry_count == SIZE_MAX)
			return (EOVERFLOW);
		entry_count++;
	}
	entry_capacity = entry_count;
	if (entry_capacity == 0)
		return (ENODEV);
	entries = calloc(entry_capacity, sizeof(*entries));
	if (entries == NULL)
		return (ENOMEM);
	entry_count = 0;
	peer = NULL;
	while ((peer = pci_next(peer)) != NULL) {
		vs = vi_pci_get_softc(peer);
		if (vs == NULL || !vi_pci_is_modern(vs))
			continue;
		/*
		 * PCI construction is single-threaded, so both discovery passes must
		 * observe the same immutable function list.  Retain and enforce the
		 * first-pass capacity anyway: a future hot-plug implementation or a
		 * broken iterator must fail closed instead of turning that lifecycle
		 * invariant into an out-of-bounds topology write.
		 */
		if (entry_count == entry_capacity) {
			free(entries);
			return (EAGAIN);
		}
		entries[entry_count++] =
		    (struct virtio_iommu_topology_entry) {
			.requester_id = pci_vtiommu_rid(peer),
			.virtio = true,
			.modern = true,
			/*
			 * Until PCI device groups can partition endpoints among
			 * providers, more than one provider is ambiguous.  Mark
			 * every provider so topology_build() rejects that shape
			 * instead of treating a provider as a DMA endpoint.
			 */
			.iommu = peer->pi_d != NULL &&
			    peer->pi_d->pe_post_init ==
			    pci_vtiommu_post_init,
			.access_platform_ineligible =
			    !vi_pci_access_platform_eligible(vs),
		};
	}
	error = virtio_iommu_topology_build(entries, entry_count,
	    &iommu_requester_id, sc->vsc_endpoints,
	    nitems(sc->vsc_endpoints), &sc->vsc_endpoint_count);
	free(entries);
	entries = NULL;
	if (error != 0)
		return (error);
	if (iommu_requester_id != pci_vtiommu_rid(pi)) {
		sc->vsc_endpoint_count = 0;
		return (EEXIST);
	}
	VIRTIO_PROBE_IOMMU_TOPOLOGY(sc->vsc_consts.vc_name,
	    iommu_requester_id, sc->vsc_endpoint_count);
	for (registered = 0; registered < sc->vsc_endpoint_count;
	    registered++) {
		status = virtio_iommu_endpoint_register(sc->vsc_state,
		    sc->vsc_endpoints[registered]);
		if (status != BHYVE_VIOMMU_S_OK) {
			error = EINVAL;
			goto fail;
		}
	}
	peer = NULL;
	while ((peer = pci_next(peer)) != NULL) {
		vs = vi_pci_get_softc(peer);
		if (peer == pi || vs == NULL ||
		    !vi_pci_access_platform_eligible(vs))
			continue;
		error = vi_set_dma_domain(vs, &vtiommu_dma_ops, sc,
		    pci_vtiommu_rid(peer));
		if (error != 0)
			goto fail;
		bound++;
	}
	return (0);

fail:
	peer = NULL;
	while (bound != 0 && (peer = pci_next(peer)) != NULL) {
		vs = vi_pci_get_softc(peer);
		if (peer == pi || vs == NULL ||
		    !vi_pci_access_platform_eligible(vs))
			continue;
		(void)vi_clear_dma_domain(vs);
		bound--;
	}
	while (registered != 0) {
		registered--;
		(void)virtio_iommu_endpoint_unregister(sc->vsc_state,
		    sc->vsc_endpoints[registered]);
	}
	sc->vsc_endpoint_count = 0;
	free(entries);
	return (error);
}

int
pci_vtiommu_viot_info(struct pci_devinst *pi, uint16_t *iommu_bdf,
    const uint16_t **endpoints, size_t *endpoint_count)
{
	struct pci_vtiommu_softc *sc;

	if (pi == NULL || iommu_bdf == NULL || endpoints == NULL ||
	    endpoint_count == NULL)
		return (EINVAL);
	if (pi->pi_d == NULL ||
	    pi->pi_d->pe_post_init != pci_vtiommu_post_init)
		return (ENODEV);
	sc = pi->pi_arg;
	if (sc == NULL || sc->vsc_endpoint_count == 0)
		return (ENODEV);
	*iommu_bdf = pci_vtiommu_rid(pi);
	*endpoints = sc->vsc_endpoints;
	*endpoint_count = sc->vsc_endpoint_count;
	return (0);
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtiommu_snapshot(void *arg, struct vm_snapshot_meta *meta)
{
	struct pci_vtiommu_softc *sc;
	struct virtio_iommu_state *old_validation, *prepared;
	uint8_t *buffer;
	uint64_t length;
	uint32_t magic, reserved, version;
	size_t state_length;
	int error;

	sc = arg;
	buffer = NULL;
	prepared = NULL;
	magic = VTIOMMU_SNAPSHOT_MAGIC;
	version = VTIOMMU_SNAPSHOT_VERSION;
	reserved = 0;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_iommu_state_snapshot_size(sc->vsc_state,
		    &state_length);
		if (error != 0)
			return (error);
		length = state_length;
	} else {
		length = 0;
	}

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	/* Reject a foreign envelope before consuming its payload header. */
	if (magic != VTIOMMU_SNAPSHOT_MAGIC ||
	    version != VTIOMMU_SNAPSHOT_VERSION) {
		error = EINVAL;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(reserved, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(length, meta, error, done);
	if (reserved != 0 ||
	    length < VTIOMMU_STATE_MIN_SIZE ||
	    length > VTIOMMU_STATE_MAX_SIZE || length > SIZE_MAX) {
		error = EINVAL;
		goto done;
	}
	buffer = malloc((size_t)length);
	if (buffer == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = virtio_iommu_state_snapshot(sc->vsc_state, buffer,
		    (size_t)length);
		if (error != 0)
			goto done;
	}
	SNAPSHOT_BUF_OR_LEAVE(buffer, (size_t)length, meta, error, done);
	if (meta->op == VM_SNAPSHOT_VALIDATE) {
		error = virtio_iommu_state_restore_prepare(sc->vsc_state,
		    buffer, (size_t)length, &prepared);
		if (error == 0) {
			/*
			 * A validation pass is reversible.  Do not discard a prior
			 * prepared fabric until the new image has been fully decoded,
			 * topology-checked, and mapped against destination memory.  In
			 * particular, a later malformed validation request must not turn a
			 * still-valid prepared view into the live fabric.
			 */
			error = pci_vtiommu_validation_publish(sc, prepared,
			    &old_validation);
			if (error == 0) {
				prepared = NULL;
				virtio_iommu_state_destroy(old_validation);
			}
		}
	} else if (meta->op == VM_SNAPSHOT_RESTORE)
		error = virtio_iommu_state_restore(sc->vsc_state, buffer,
		    (size_t)length);
	else
		error = 0;
done:
	virtio_iommu_state_destroy(prepared);
	free(buffer);
	return (error);
}

static void
pci_vtiommu_snapshot_validate_cleanup(struct pci_devinst *pi)
{
	struct pci_vtiommu_softc *sc;
	struct virtio_iommu_state *prepared;

	if (pi == NULL)
		return;
	sc = pi->pi_arg;
	if (sc == NULL)
		return;
	/* Only the thread which published the prepared view may retire it. */
	if (atomic_load_explicit(&sc->vsc_validation_owner,
	    memory_order_acquire) != pci_vtiommu_validation_owner_token())
		return;
	/* Unpublish the view before releasing ownership and destroying it. */
	prepared = atomic_exchange_explicit(&sc->vsc_validation_state, NULL,
	    memory_order_acq_rel);
	atomic_store_explicit(&sc->vsc_validation_owner, NULL,
	    memory_order_release);
	virtio_iommu_state_destroy(prepared);
}
#endif

static int
pci_vtiommu_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtiommu_softc *sc;
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	bool intr_initialized, packed;
	int error;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (ENOMEM);
#ifdef BHYVE_SNAPSHOT
	atomic_init(&sc->vsc_validation_state, NULL);
	atomic_init(&sc->vsc_validation_owner, NULL);
#endif
	intr_initialized = false;
	error = pthread_mutex_init(&sc->vsc_mtx, NULL);
	if (error != 0) {
		free(sc);
		return (error);
	}
	sc->vsc_consts = vtiommu_vi_consts;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	for (size_t i = 0; i < nitems(sc->vsc_vq); i++)
		sc->vsc_vq[i].vq_qsize = VTIOMMU_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0) {
		error = EINVAL;
		goto fail;
	}

	pci_vtiommu_limits_init(&limits);
	ops = (struct virtio_iommu_ops) {
		.validate_gpa = pci_vtiommu_validate_gpa,
		.map_gpa = pci_vtiommu_map_gpa,
		.fault = pci_vtiommu_fault,
		.dma_idle = pci_vtiommu_dma_idle,
		.arg = sc,
	};
	error = virtio_iommu_state_create(&limits, &ops, &sc->vsc_state);
	if (error != 0)
		goto fail;
	sc->vsc_config = (struct virtio_iommu_config_values) {
		.page_size_mask = limits.page_size_mask,
		.input_start = limits.input_start,
		.input_end = limits.input_end,
		.domain_start = limits.domain_start,
		.domain_end = limits.domain_end,
		.probe_size = VTIOMMU_PROBE_SIZE,
	};
	sc->vsc_request_options.probe_size = VTIOMMU_PROBE_SIZE;

	vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_IOMMU);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_BASEPERIPH);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_BASEPERIPH_IOMMU);
	if (vi_intr_init(&sc->vsc_vs, VTIOMMU_NUM_QUEUES + 1,
	    fbsdrun_virtio_msix()) != 0) {
		error = ENXIO;
		goto fail;
	}
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0) {
		error = ENXIO;
		goto fail;
	}
	return (0);

fail:
	virtio_iommu_state_destroy(sc->vsc_state);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	return (error);
}

static const struct pci_devemu pci_de_vtiommu = {
	.pe_emu = "virtio-iommu",
	.pe_init = pci_vtiommu_init,
	.pe_post_init = pci_vtiommu_post_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = vi_pci_snapshot,
	.pe_snapshot_validate_cleanup =
	    pci_vtiommu_snapshot_validate_cleanup,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
	.pe_restore_phase = PCI_RESTORE_FABRIC,
#endif
};
PCI_EMUL_SET(pci_de_vtiommu);
