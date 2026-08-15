/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/param.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/virtio/virtio_ids.h>

#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#include "snapshot_identity.h"
#endif
#include "virtio.h"
#include "virtio_pmem_host.h"
#include "virtio_pmem_queue.h"
#include "virtio_pmem_worker.h"
#include "virtio_pci_modern_probes.h"

#define	VTPMEM_RINGSZ		128U
#define	VTPMEM_MAX_IOV		VTPMEM_RINGSZ
#define	VTPMEM_SHMEM_BAR	4U
#define	VTPMEM_SHMEM_REGION_ID	0U
/*
 * A lifecycle drain is deliberately bounded in production.  Keep this a
 * compile-time default rather than baking it into each call site so the
 * direct state-machine tests can exercise the timeout/rollback path without
 * turning a deterministic negative test into a thirty-second wait.
 */
#ifndef VTPMEM_DRAIN_TIMEOUT_MS
#define	VTPMEM_DRAIN_TIMEOUT_MS	30000U
#endif
#define	VTPMEM_IDENTITY_MAX	255U
#define	VTPMEM_SNAPSHOT_MAGIC	0x314d4d50U	/* "PMM1" */
#define	VTPMEM_SNAPSHOT_VERSION	1U

struct pci_vtpmem_softc;

struct pci_vtpmem_request {
	struct vqueue_info *vq;
	struct vi_req req;
	struct virtio_pmem_chain chain;
	uint64_t queue_generation;
	uint64_t epoch;
	uint32_t trace_id;
	int completion_error;
	bool lifecycle_abandoned;
	bool lifecycle_completed;
	bool lifecycle_flush;
};

struct pci_vtpmem_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_vq;
	struct virtio_consts vsc_consts;
	pthread_mutex_t vsc_mtx;
	struct virtio_pmem_backing vsc_backing;
	struct virtio_pmem_worker *vsc_worker;
	char *vsc_path;
	char *vsc_identity;
};

static void pci_vtpmem_reset(void *);
static void pci_vtpmem_notify(void *, struct vqueue_info *);
static int pci_vtpmem_cfgread(void *, int, int, uint32_t *);
static int pci_vtpmem_apply_features(void *, uint64_t);
static int pci_vtpmem_qreset(void *, struct vqueue_info *, uint64_t);
static int pci_vtpmem_suspend(void *);
static int pci_vtpmem_resume_device(void *);
static void pci_vtpmem_resume_complete(void *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtpmem_pause(void *);
static int pci_vtpmem_resume(void *);
static int pci_vtpmem_snapshot(void *, struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtpmem_vi_consts = {
	.vc_name = "vtpmem",
	.vc_nvq = 1,
	.vc_cfgsize = BHYVE_VIRTIO_PMEM_CONFIG_SIZE,
	.vc_reset = pci_vtpmem_reset,
	.vc_qnotify = pci_vtpmem_notify,
	.vc_cfgread = pci_vtpmem_cfgread,
	.vc_apply_features = pci_vtpmem_apply_features,
	.vc_qreset = pci_vtpmem_qreset,
	.vc_suspend = pci_vtpmem_suspend,
	.vc_resume_device = pci_vtpmem_resume_device,
	.vc_resume_complete = pci_vtpmem_resume_complete,
	/*
	 * FLUSH completion is owned by the asynchronous durable-backing worker.
	 * Do not promise VIRTIO_F_IN_ORDER merely because the current worker happens
	 * to dequeue FIFO: reset, cancellation, and backend completion remain
	 * independent asynchronous transitions.  The common packed-ring completion
	 * cache preserves descriptor ownership, but it is not an IN_ORDER contract.
	 */
	.vc_hv_caps = (UINT64_C(1) << 0) | VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND,
#ifdef BHYVE_SNAPSHOT
	.vc_pause = pci_vtpmem_pause,
	.vc_resume = pci_vtpmem_resume,
	.vc_snapshot = pci_vtpmem_snapshot,
#endif
};

static int
pci_vtpmem_flush(void *arg)
{
	struct pci_vtpmem_softc *sc;

	sc = arg;
	return (virtio_pmem_backing_flush(&sc->vsc_backing));
}

static void
pci_vtpmem_complete(void *arg, uintptr_t token, uint64_t epoch, int error)
{
	struct pci_vtpmem_request *request;
	struct pci_vtpmem_softc *sc;
	size_t written;

	request = (struct pci_vtpmem_request *)token;
	sc = arg;
	VIRTIO_PROBE_PMEM_FLUSH(sc->vsc_consts.vc_name, "complete",
	    request->trace_id, epoch, error);
	if (request->lifecycle_flush) {
		bool abandoned;

		VS_LOCK(&sc->vsc_vs);
		request->completion_error = error;
		request->lifecycle_completed = true;
		abandoned = request->lifecycle_abandoned;
		VS_UNLOCK(&sc->vsc_vs);
		if (abandoned)
			free(request);
		return;
	}
	VS_LOCK(&sc->vsc_vs);
	if (request->epoch == epoch &&
	    request->vq->vq_generation == request->queue_generation) {
		if (virtio_pmem_chain_complete(&request->chain, error,
		    &written) == 0) {
			vq_relchain_req(request->vq, &request->req,
			    (uint32_t)written);
			vq_endchains(request->vq, 0);
		} else {
			vq_discard_req(request->vq, &request->req);
			vi_set_needs_reset(&sc->vsc_vs);
		}
	} else
		vq_discard_req(request->vq, &request->req);
	VS_UNLOCK(&sc->vsc_vs);
	free(request);
}

static int
pci_vtpmem_drain_locked(struct pci_vtpmem_softc *sc, bool resume)
{
	int error;

	assert(pthread_mutex_isowned_np(&sc->vsc_mtx));
	pthread_mutex_unlock(&sc->vsc_mtx);
	error = virtio_pmem_worker_reset(sc->vsc_worker,
	    VTPMEM_DRAIN_TIMEOUT_MS, resume);
	pthread_mutex_lock(&sc->vsc_mtx);
	return (error);
}

static void
pci_vtpmem_defer_reset_after_timeout(struct pci_vtpmem_softc *sc)
{
	int error;

	/*
	 * A full device reset has no error return, but it must not make the
	 * common transport look usable if the worker cannot retain ownership of
	 * a request that outlived the bounded drain.  The deferred reset is what
	 * keeps admission closed until that old owner retires.  Treat failure to
	 * install it as a terminal device error rather than merely diagnostic
	 * telemetry.
	 */
	error = virtio_pmem_worker_defer_reset(sc->vsc_worker, true);
	if (error != 0) {
		VIRTIO_PROBE_ERROR(sc->vsc_consts.vc_name,
		    "pmem-deferred-reset-failed");
		vi_set_needs_reset(&sc->vsc_vs);
	}
}

static void
pci_vtpmem_reset(void *arg)
{
	struct pci_vtpmem_softc *sc;
	int error;

	sc = arg;
	error = pci_vtpmem_drain_locked(sc, true);
	if (error != 0) {
		/*
		 * Full reset cannot report a timeout.  The queue generation fence
		 * makes a late completion discard-only, and the deferred ledger reset
		 * reopens admission only after every old owner has retired.
		 */
		pci_vtpmem_defer_reset_after_timeout(sc);
	}
	vi_reset_dev(&sc->vsc_vs);
}

static int
pci_vtpmem_qreset(void *arg, struct vqueue_info *vq __unused,
    uint64_t generation __unused)
{
	struct pci_vtpmem_softc *sc;

	sc = arg;
	return (pci_vtpmem_drain_locked(sc, true));
}

static int
pci_vtpmem_stabilize_locked(struct pci_vtpmem_softc *sc)
{
	struct pci_vtpmem_request *request;
	int error;

	/*
	 * First drain guest-owned requests.  Then briefly reopen the worker
	 * ledger under the already-published common queue fence and enqueue one
	 * lifecycle-only flush.  The second drain gives that fsync the same
	 * bounded, event-driven completion contract as a guest request.
	 */
	error = pci_vtpmem_drain_locked(sc, false);
	if (error != 0)
		return (error);
	error = virtio_pmem_worker_resume(sc->vsc_worker);
	if (error != 0)
		return (error);
	request = calloc(1, sizeof(*request));
	if (request == NULL) {
		(void)virtio_pmem_worker_pause(sc->vsc_worker, 0);
		return (ENOMEM);
	}
	request->lifecycle_flush = true;
	request->trace_id = UINT32_MAX;
	error = virtio_pmem_worker_submit(sc->vsc_worker,
	    (uintptr_t)request, &request->epoch);
	if (error != 0) {
		free(request);
		(void)virtio_pmem_worker_pause(sc->vsc_worker, 0);
		return (error);
	}
	VIRTIO_PROBE_PMEM_FLUSH(sc->vsc_consts.vc_name, "lifecycle-submit",
	    request->trace_id, request->epoch, 0);
	error = pci_vtpmem_drain_locked(sc, false);
	if (error != 0) {
		/*
		 * The callback may still be blocked in the backend or waiting for
		 * this lock.  Transfer reclamation to it without racing a callback
		 * that already published the result.
		 */
		if (request->lifecycle_completed)
			free(request);
		else
			request->lifecycle_abandoned = true;
		return (error);
	}
	if (!request->lifecycle_completed) {
		request->lifecycle_abandoned = true;
		return (EIO);
	}
	error = request->completion_error;
	free(request);
	return (error);
}

static int
pci_vtpmem_suspend(void *arg)
{
	struct pci_vtpmem_softc *sc;

	sc = arg;
	return (pci_vtpmem_stabilize_locked(sc));
}

static int
pci_vtpmem_resume_device(void *arg)
{
	struct pci_vtpmem_softc *sc;

	sc = arg;
	if (sc->vsc_vs.vs_checkpoint_paused)
		return (0);
	return (virtio_pmem_worker_resume(sc->vsc_worker));
}

static void
pci_vtpmem_resume_complete(void *arg)
{
	struct pci_vtpmem_softc *sc;

	sc = arg;
	vi_pci_notify_ready_queues(&sc->vsc_vs);
}

static int
pci_vtpmem_apply_features(void *arg __unused, uint64_t features __unused)
{

	/*
	 * VIRTIO_PMEM_F_SHMEM_REGION is optional.  Section 5.19.5.1 requires
	 * the device to expose the same range through start/size when a driver
	 * declines it, so every otherwise-valid feature subset is accepted.
	 */
	return (0);
}

static int
pci_vtpmem_cfgread(void *arg, int offset, int size, uint32_t *value)
{
	struct pci_vtpmem_softc *sc;
	uint8_t config[BHYVE_VIRTIO_PMEM_CONFIG_SIZE];
	uint64_t start;
	bool shared_memory_region;
	int error;

	sc = arg;
	shared_memory_region = (sc->vsc_vs.vs_negotiated_caps &
	    (UINT64_C(1) << 0)) != 0;
	if (shared_memory_region)
		start = 0;
	else {
		if (sc->vsc_vs.vs_pi == NULL ||
		    sc->vsc_vs.vs_pi->pi_bar[VTPMEM_SHMEM_BAR].type != PCIBAR_MEM64)
			return (ENXIO);
		start = sc->vsc_vs.vs_pi->pi_bar[VTPMEM_SHMEM_BAR].addr;
	}
	error = virtio_pmem_config_encode(start, sc->vsc_backing.size,
	    shared_memory_region,
	    config, sizeof(config));
	if (error != 0)
		return (error);
	return (vi_config_read_le(config, sizeof(config), offset, size, value));
}

static void
pci_vtpmem_bad_chain(struct pci_vtpmem_softc *sc, struct vqueue_info *vq,
    struct vi_req *req, const char *reason)
{

	VIRTIO_PROBE_ERROR(sc->vsc_consts.vc_name, reason);
	vq_relchain_req(vq, req, 0);
	vi_set_needs_reset(&sc->vsc_vs);
}

static void
pci_vtpmem_notify(void *arg, struct vqueue_info *vq)
{
	struct iovec iov[VTPMEM_MAX_IOV];
	struct pci_vtpmem_request *request;
	struct pci_vtpmem_softc *sc;
	struct virtio_pmem_chain chain;
	struct vi_req req;
	size_t written;
	uint16_t budget;
	int error, n;

	sc = arg;
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0) {
			if (n < 0)
				vi_set_needs_reset(&sc->vsc_vs);
			break;
		}
		if (n > (int)nitems(iov) || !req.ordered || req.readable == 0 ||
		    req.writable == 0 || req.readable + req.writable != n) {
			pci_vtpmem_bad_chain(sc, vq, &req,
			    "invalid-pmem-descriptor-order");
			break;
		}
		error = virtio_pmem_chain_prepare(iov, n, req.readable,
		    req.writable, &chain);
		if (error != 0) {
			pci_vtpmem_bad_chain(sc, vq, &req,
			    "short-pmem-request-or-response");
			break;
		}
		error = virtio_pmem_request_decode(chain.request,
		    sizeof(chain.request));
		if (error != 0) {
			(void)virtio_pmem_chain_complete(&chain, error,
			    &written);
			vq_relchain_req(vq, &req, (uint32_t)written);
			continue;
		}
		request = calloc(1, sizeof(*request));
		if (request == NULL) {
			(void)virtio_pmem_chain_complete(&chain, ENOMEM,
			    &written);
			vq_relchain_req(vq, &req, (uint32_t)written);
			continue;
		}
		request->chain = chain;
		request->vq = vq;
		request->req = req;
		request->queue_generation = req.queue_generation;
		request->trace_id = req.idx;
		error = virtio_pmem_worker_submit(sc->vsc_worker,
		    (uintptr_t)request, &request->epoch);
		if (error != 0) {
			(void)virtio_pmem_chain_complete(&request->chain, error,
			    &written);
			free(request);
			vq_relchain_req(vq, &req, (uint32_t)written);
		} else
			VIRTIO_PROBE_PMEM_FLUSH(sc->vsc_consts.vc_name, "submit",
			    request->trace_id, request->epoch, 0);
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

#ifdef BHYVE_SNAPSHOT
static int
pci_vtpmem_pause(void *arg)
{
	struct pci_vtpmem_softc *sc;
	int error, rollback_error;

	sc = arg;
	VS_LOCK(&sc->vsc_vs);
	error = pci_vtpmem_stabilize_locked(sc);
	if (error != 0) {
		rollback_error =
		    virtio_pmem_worker_abort_pause(sc->vsc_worker);
		if (rollback_error != 0) {
			/*
			 * A deferred full reset retains ownership of the worker
			 * admission fence.  If that state prevents checkpoint
			 * rollback, reopening the common queue gate would present a
			 * runnable device whose backend still rejects every request.
			 */
			vi_set_needs_reset(&sc->vsc_vs);
			error = EIO;
		}
	}
	VS_UNLOCK(&sc->vsc_vs);
	return (error);
}

static int
pci_vtpmem_resume(void *arg)
{
	struct pci_vtpmem_softc *sc;
	int error;

	sc = arg;
	VS_LOCK(&sc->vsc_vs);
	error = sc->vsc_vs.vs_suspended ? 0 :
	    virtio_pmem_worker_resume(sc->vsc_worker);
	VS_UNLOCK(&sc->vsc_vs);
	return (error);
}

static int
pci_vtpmem_snapshot(void *arg, struct vm_snapshot_meta *meta)
{
	struct pci_vtpmem_softc *sc;
	uint64_t size;
	uint32_t magic, version;
	int error;

	sc = arg;
	magic = VTPMEM_SNAPSHOT_MAGIC;
	version = VTPMEM_SNAPSHOT_VERSION;
	size = sc->vsc_backing.size;
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	/* Reject an unsupported record at its fixed discriminator prefix. */
	if (magic != VTPMEM_SNAPSHOT_MAGIC ||
	    version != VTPMEM_SNAPSHOT_VERSION) {
		error = EINVAL;
		goto done;
	}
	SNAPSHOT_LE64_OR_LEAVE(size, meta, error, done);
	if (size != sc->vsc_backing.size) {
		error = EINVAL;
		goto done;
	}
	error = vm_snapshot_identity_string(sc->vsc_identity,
	    VTPMEM_IDENTITY_MAX, meta);
done:
	return (error);
}
#endif

static int
pci_vtpmem_bar_size(size_t backing_size, uint64_t *result)
{
	uint64_t size;

	if (backing_size == 0 || result == NULL)
		return (EINVAL);
	size = 4096;
	while (size < backing_size) {
		if (size > UINT64_MAX / 2)
			return (EOVERFLOW);
		size *= 2;
	}
	*result = size;
	return (0);
}

static int
pci_vtpmem_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtpmem_softc *sc;
	struct virtio_pmem_worker_ops ops;
	const char *identity, *path;
	uint64_t bar_size;
	bool intr_initialized, mutex_initialized, packed;
	int error;

	path = get_config_value_node(nvl, "path");
	identity = get_config_value_node(nvl, "id");
	if (path == NULL || path[0] == '\0' || identity == NULL ||
	    identity[0] == '\0' || strlen(identity) > VTPMEM_IDENTITY_MAX)
		return (1);
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	virtio_pmem_backing_init(&sc->vsc_backing);
	intr_initialized = false;
	mutex_initialized = false;
	sc->vsc_path = strdup(path);
	sc->vsc_identity = strdup(identity);
	if (sc->vsc_path == NULL || sc->vsc_identity == NULL)
		goto fail;
	error = virtio_pmem_backing_open(&sc->vsc_backing, path);
	if (error != 0)
		goto fail;
	error = pci_vtpmem_bar_size(sc->vsc_backing.size, &bar_size);
	if (error != 0)
		goto fail;
	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0)
		goto fail;
	mutex_initialized = true;

	sc->vsc_consts = vtpmem_vi_consts;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, &sc->vsc_vq);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;
	sc->vsc_vq.vq_qsize = VTPMEM_RINGSZ;
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto fail;

	ops = (struct virtio_pmem_worker_ops) {
		.flush = pci_vtpmem_flush,
		.complete = pci_vtpmem_complete,
		.arg = sc,
	};
	error = virtio_pmem_worker_create(VTPMEM_RINGSZ, &ops,
	    &sc->vsc_worker);
	if (error != 0)
		goto fail;
	vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_PMEM);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_MEMORY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_MEMORY_RAM);
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()) != 0)
		goto fail;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
		goto fail;
	if (pci_emul_alloc_bar(pi, VTPMEM_SHMEM_BAR, PCIBAR_MEM64,
	    bar_size) != 0)
		goto fail;
	if (vi_pci_modern_add_shared_memory(&sc->vsc_vs,
	    VTPMEM_SHMEM_REGION_ID, VTPMEM_SHMEM_BAR, 0,
	    sc->vsc_backing.size) != 0)
		goto fail;
	if (vi_pci_modern_set_shared_memory_backing(&sc->vsc_vs,
	    VTPMEM_SHMEM_REGION_ID, sc->vsc_backing.mapping,
	    sc->vsc_backing.size, true) != 0)
		goto fail;
	vi_pci_modern_seal_shared_memory(&sc->vsc_vs);
	return (0);

fail:
	if (sc->vsc_worker != NULL)
		(void)virtio_pmem_worker_destroy(sc->vsc_worker,
		    VTPMEM_DRAIN_TIMEOUT_MS);
	free(sc->vsc_vs.vs_modern);
	if (intr_initialized)
		(void)pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	if (mutex_initialized)
		(void)pthread_mutex_destroy(&sc->vsc_mtx);
	virtio_pmem_backing_close(&sc->vsc_backing);
	free(sc->vsc_identity);
	free(sc->vsc_path);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtpmem = {
	.pe_emu = "virtio-pmem",
	.pe_init = pci_vtpmem_init,
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
PCI_EMUL_SET(pci_de_vtpmem);
