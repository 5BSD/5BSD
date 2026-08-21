/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Driver for VirtIO IOMMU devices (VirtIO device ID 23).
 *
 * This driver implements the guest side of the VirtIO-IOMMU protocol as
 * defined by the VirtIO 1.4 specification and the authoritative same-repo back
 * end in usr.sbin/bhyve/pci_virtio_iommu.c.  It owns two virtqueues -- a
 * request queue (index 0, driver->device commands: ATTACH, DETACH, MAP, UNMAP,
 * PROBE) and an event queue (index 1, device->driver fault reports) -- and
 * maintains a domain / endpoint / mapping model reflecting the state it has
 * programmed into the device.  Because it drives the queues exclusively
 * through the transport-agnostic virtqueue(9) API, it supports both split and
 * packed rings; the ring layout is chosen by feature negotiation
 * (VIRTIO_F_RING_PACKED) and is transparent here.
 *
 *
 * ---------------------------------------------------------------------------
 * INTEGRATION BOUNDARY: busdma / IOMMU-framework translation.
 * ---------------------------------------------------------------------------
 * The primary, complete deliverable of this driver is the VirtIO-IOMMU
 * PROTOCOL: feature negotiation, config parsing, request/event queue setup,
 * the full ATTACH/DETACH/MAP/UNMAP/PROBE request cycle with status handling
 * and a guest-side domain/endpoint/mapping model, plus asynchronous fault
 * event handling.  All of that is real and exercised end-to-end against the
 * device.
 *
 * What this driver deliberately does NOT do is transparently reprogram other
 * VirtIO endpoints' bus_dma(9) so their DMA is silently translated through
 * this IOMMU.  In FreeBSD that transparency is provided by the busdma/IOMMU
 * framework (sys/dev/iommu, sys/x86/iommu): the DMA tag layer calls the
 * per-platform iommu_find() to locate an iommu_unit for a device, then maps
 * every transfer through iommu_domain/iommu_ctx map/unmap ops, with the
 * device->unit binding supplied by firmware tables (x86 DMAR/IVRS, arm64 IORT;
 * for virtio-iommu specifically, the ACPI VIOT table).  That framework has NO
 * machine-independent hook for a loadable virtio child driver to register
 * itself as a translation provider: wiring it up requires (a) an ACPI VIOT
 * parser that binds endpoint RIDs to this unit, and (b) a busdma_iommu back
 * end implementing iommu_unit/iommu_domain/iommu_ctx whose ->map/->unmap call
 * into the request queue here.  Both live in the shared framework and platform
 * busdma files, which are explicitly out of this driver's file scope, so they
 * are not attempted rather than faked.
 *
 * The seam is left honest and usable: virtio_iommu_provider_lookup() (declared
 * in virtio_iommu.h) resolves an endpoint RID to this driver's protocol engine
 * via the vtable below, so a future in-tree VIOT/busdma_iommu back end can
 * drive real host translation without any change to this file's protocol core.
 * ---------------------------------------------------------------------------
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ids.h>

#include <dev/virtio/iommu/virtio_iommu.h>

#include "virtio_if.h"

/* Virtqueue indices, matching the bhyve device contract. */
#define	VTIOMMU_REQ_VQ		0
#define	VTIOMMU_EVENT_VQ	1
#define	VTIOMMU_NUM_VQS		2

/* Bound on a PROBE reply's properties region we are willing to allocate. */
#define	VTIOMMU_PROBE_MAX	4096U

/* Number of standing fault buffers we keep posted on the event queue. */
#define	VTIOMMU_EVENT_BUFS	64

/*
 * Upper bound on how long a synchronous request may wait for the device to
 * retire it.  A device that accepts the descriptor but never completes it must
 * not spin the caller (holding the softc lock) forever; the wait is bounded and
 * the request queue is then declared broken.
 */
#define	VTIOMMU_REQUEST_TIMEOUT	(5 * SBT_1S)

MALLOC_DEFINE(M_VTIOMMU, "vtiommu", "VirtIO IOMMU");

struct vtiommu_mapping {
	LIST_ENTRY(vtiommu_mapping)	vm_link;
	uint64_t			vm_start;	/* IOVA, inclusive */
	uint64_t			vm_end;		/* IOVA, inclusive */
	uint64_t			vm_phys;
	uint32_t			vm_flags;
};

struct vtiommu_domain {
	LIST_ENTRY(vtiommu_domain)	vd_link;
	uint32_t			vd_id;
	u_int				vd_refs;	/* attached endpoints */
	LIST_HEAD(, vtiommu_mapping)	vd_maps;
};

struct vtiommu_endpoint {
	LIST_ENTRY(vtiommu_endpoint)	ve_link;
	uint32_t			ve_rid;
	struct vtiommu_domain		*ve_domain;	/* NULL if detached */
	bool				ve_bypass;
};

struct vtiommu_event_buf {
	struct virtio_iommu_fault	eb_fault;
};

struct vtiommu_request_io {
	uint8_t	request[sizeof(struct virtio_iommu_req_probe)];
	uint8_t	pad;
	uint8_t	response[VTIOMMU_PROBE_MAX +
	    sizeof(struct virtio_iommu_req_tail)] __aligned(sizeof(uint64_t));
};
CTASSERT(offsetof(struct vtiommu_request_io, response) >=
    sizeof(((struct vtiommu_request_io *)0)->request) + 1);

struct vtiommu_softc {
	device_t		 vtiommu_dev;
	struct mtx		 vtiommu_mtx;
	uint64_t		 vtiommu_features;
	uint32_t		 vtiommu_flags;
#define	VTIOMMU_FLAG_DETACH	0x0001
#define	VTIOMMU_FLAG_MAP_UNMAP	0x0002
#define	VTIOMMU_FLAG_PROBE	0x0004
#define	VTIOMMU_FLAG_BYPASS_CFG	0x0008
#define	VTIOMMU_FLAG_REQ_BUSY	0x0010	/* request scratch in flight */
#define	VTIOMMU_FLAG_BROKEN	0x0020	/* request queue wedged/timed out */

	struct virtqueue	*vtiommu_req_vq;
	struct virtqueue	*vtiommu_event_vq;

	struct virtio_iommu_config vtiommu_cfg;
	uint32_t		 vtiommu_probe_cap;	/* clamped probe_size */

	/* Serialized request scratch (readable request + writable response). */
	struct sglist		*vtiommu_sg;
	struct vtiommu_request_io *vtiommu_io;
	uint8_t			*vtiommu_req;		/* max request bytes */
	uint8_t			*vtiommu_resp;		/* response + tail */
	size_t			 vtiommu_resp_len;

	/* Standing event (fault) buffers. */
	struct vtiommu_event_buf *vtiommu_ebufs;
	struct sglist		*vtiommu_esg;

	/* Guest-side model. */
	LIST_HEAD(, vtiommu_domain)	vtiommu_domains;
	LIST_HEAD(, vtiommu_endpoint)	vtiommu_endpoints;

	/* Statistics. */
	uint64_t		 vtiommu_stat_attach;
	uint64_t		 vtiommu_stat_detach;
	uint64_t		 vtiommu_stat_map;
	uint64_t		 vtiommu_stat_unmap;
	uint64_t		 vtiommu_stat_probe;
	uint64_t		 vtiommu_stat_faults;
	struct virtio_iommu_fault vtiommu_last_fault;

	struct virtio_iommu_provider vtiommu_provider;
};

#define	VTIOMMU_LOCK(sc)		mtx_lock(&(sc)->vtiommu_mtx)
#define	VTIOMMU_UNLOCK(sc)		mtx_unlock(&(sc)->vtiommu_mtx)
#define	VTIOMMU_LOCK_ASSERT(sc)		mtx_assert(&(sc)->vtiommu_mtx, MA_OWNED)
#define	VTIOMMU_LOCK_INIT(sc)		mtx_init(&(sc)->vtiommu_mtx, \
	device_get_nameunit((sc)->vtiommu_dev), "vtiommu", MTX_DEF)
#define	VTIOMMU_LOCK_DESTROY(sc)	mtx_destroy(&(sc)->vtiommu_mtx)

#define	vtiommu_modern(sc) \
	(((sc)->vtiommu_features & VIRTIO_F_VERSION_1) != 0)

/*
 * The offered feature set.  The host advertises INPUT_RANGE, DOMAIN_RANGE,
 * MAP_UNMAP, PROBE and BYPASS_CONFIG; we additionally negotiate the standard
 * ring-format transport features so both split and packed rings work.
 */
#define	VTIOMMU_FEATURES						\
	((1ULL << VIRTIO_IOMMU_F_INPUT_RANGE)		|		\
	 (1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE)		|		\
	 (1ULL << VIRTIO_IOMMU_F_MAP_UNMAP)		|		\
	 (1ULL << VIRTIO_IOMMU_F_PROBE)			|		\
	 (1ULL << VIRTIO_IOMMU_F_BYPASS_CONFIG)		|		\
	 VIRTIO_RING_F_INDIRECT_DESC			|		\
	 VIRTIO_RING_F_EVENT_IDX)

static struct virtio_feature_desc vtiommu_feature_desc[] = {
	{ (1ULL << VIRTIO_IOMMU_F_INPUT_RANGE),	"InputRange"	},
	{ (1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE), "DomainRange"	},
	{ (1ULL << VIRTIO_IOMMU_F_MAP_UNMAP),	"MapUnmap"	},
	{ (1ULL << VIRTIO_IOMMU_F_BYPASS),	"Bypass"	},
	{ (1ULL << VIRTIO_IOMMU_F_PROBE),	"Probe"		},
	{ (1ULL << VIRTIO_IOMMU_F_MMIO),	"Mmio"		},
	{ (1ULL << VIRTIO_IOMMU_F_BYPASS_CONFIG), "BypassConfig" },
	{ 0, NULL }
};

/* Global provider registry for the busdma/VIOT seam. */
static struct mtx vtiommu_providers_mtx;
static LIST_HEAD(, virtio_iommu_provider) vtiommu_providers =
    LIST_HEAD_INITIALIZER(vtiommu_providers);
MTX_SYSINIT(vtiommu_providers, &vtiommu_providers_mtx, "vtiommu providers",
    MTX_DEF);

static int	vtiommu_probe(device_t);
static int	vtiommu_attach(device_t);
static int	vtiommu_detach(device_t);
static int	vtiommu_config_change(device_t);

static int	vtiommu_setup_features(struct vtiommu_softc *);
static void	vtiommu_read_config(struct vtiommu_softc *,
		    struct virtio_iommu_config *);
static int	vtiommu_alloc_virtqueues(struct vtiommu_softc *);
static int	vtiommu_alloc_scratch(struct vtiommu_softc *);
static void	vtiommu_free_scratch(struct vtiommu_softc *);

static int	vtiommu_populate_event_vq(struct vtiommu_softc *);
static int	vtiommu_enqueue_event_buf(struct vtiommu_softc *,
		    struct vtiommu_event_buf *);
static void	vtiommu_event_vq_intr(void *);
static void	vtiommu_req_vq_intr(void *);
static void	vtiommu_handle_fault(struct vtiommu_softc *,
		    const struct virtio_iommu_fault *);

static int	vtiommu_send_request(struct vtiommu_softc *, size_t, size_t,
		    uint8_t *);
static int	vtiommu_status_to_errno(uint8_t);

/* Protocol operations (also exported through the provider vtable). */
static int	vtiommu_op_attach(device_t, uint32_t, uint32_t, uint32_t);
static int	vtiommu_op_detach(device_t, uint32_t, uint32_t);
static int	vtiommu_op_map(device_t, uint32_t, uint64_t, uint64_t,
		    uint64_t, uint32_t);
static int	vtiommu_op_unmap(device_t, uint32_t, uint64_t, uint64_t);
static int	vtiommu_op_probe(device_t, uint32_t);

/* Guest model helpers (require the softc lock). */
static struct vtiommu_domain *vtiommu_domain_find(struct vtiommu_softc *,
		    uint32_t);
static struct vtiommu_domain *vtiommu_domain_get(struct vtiommu_softc *,
		    uint32_t);
static void	vtiommu_domain_gc(struct vtiommu_softc *,
		    struct vtiommu_domain *);
static struct vtiommu_endpoint *vtiommu_endpoint_find(struct vtiommu_softc *,
		    uint32_t);
static struct vtiommu_endpoint *vtiommu_endpoint_get(struct vtiommu_softc *,
		    uint32_t);
static void	vtiommu_model_reset(struct vtiommu_softc *);
static void	vtiommu_domain_add_map(struct vtiommu_domain *, uint64_t,
		    uint64_t, uint64_t, uint32_t);
static void	vtiommu_domain_del_range(struct vtiommu_domain *, uint64_t,
		    uint64_t);

static void	vtiommu_setup_sysctl(struct vtiommu_softc *);

static device_method_t vtiommu_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtiommu_probe),
	DEVMETHOD(device_attach,	vtiommu_attach),
	DEVMETHOD(device_detach,	vtiommu_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_config_change,	vtiommu_config_change),

	DEVMETHOD_END
};

static driver_t vtiommu_driver = {
	"vtiommu",
	vtiommu_methods,
	sizeof(struct vtiommu_softc)
};

VIRTIO_DRIVER_MODULE(virtio_iommu, vtiommu_driver, NULL, NULL);
MODULE_VERSION(virtio_iommu, 1);
MODULE_DEPEND(virtio_iommu, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_iommu, VIRTIO_ID_IOMMU, "VirtIO IOMMU Adapter");

/*
 * This driver implements the virtio-iommu protocol but, on FreeBSD, does not
 * yet drive real busdma translation for other devices (see the INTEGRATION
 * BOUNDARY comment at the top of this file and virtio_iommu(4)).  Attaching a
 * non-translating IOMMU gives a guest no isolation, so the driver declines the
 * device by default and must be explicitly opted in.  It is intended for
 * exercising the protocol and the in-tree host model, not as a guest DMA
 * isolation facility; that capability lives in the bhyve host-side virtio-iommu
 * model, which presents a functional IOMMU to guests whose OS can consume one.
 */
static int vtiommu_enable = 0;
SYSCTL_NODE(_hw, OID_AUTO, virtio_iommu, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "VirtIO IOMMU guest driver");
SYSCTL_INT(_hw_virtio_iommu, OID_AUTO, enable, CTLFLAG_RDTUN, &vtiommu_enable,
    0,
    "Attach to virtio-iommu devices (default 0). The guest driver implements "
    "the protocol but does not provide busdma(9) translation, so it is "
    "disabled by default; set to 1 to exercise the protocol.");

static int
vtiommu_probe(device_t dev)
{

	if (vtiommu_enable == 0)
		return (ENXIO);
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_iommu));
}

static int
vtiommu_attach(device_t dev)
{
	struct vtiommu_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtiommu_dev = dev;
	virtio_set_feature_desc(dev, vtiommu_feature_desc);

	VTIOMMU_LOCK_INIT(sc);
	LIST_INIT(&sc->vtiommu_domains);
	LIST_INIT(&sc->vtiommu_endpoints);

	error = vtiommu_setup_features(sc);
	if (error != 0) {
		device_printf(dev, "cannot setup features\n");
		goto fail;
	}

	vtiommu_read_config(sc, &sc->vtiommu_cfg);

	sc->vtiommu_probe_cap = 0;
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_PROBE) != 0) {
		sc->vtiommu_probe_cap = MIN(sc->vtiommu_cfg.probe_size,
		    VTIOMMU_PROBE_MAX);
	}

	error = vtiommu_alloc_virtqueues(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	error = vtiommu_alloc_scratch(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate request scratch\n");
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error != 0) {
		device_printf(dev, "cannot setup interrupts\n");
		goto fail;
	}

	/*
	 * Requests complete synchronously via virtqueue_poll(); we do not want
	 * a spurious interrupt path racing the poller for the request queue.
	 * Fault events are interrupt-driven.
	 */
	virtqueue_disable_intr(sc->vtiommu_req_vq);

	error = vtiommu_populate_event_vq(sc);
	if (error != 0) {
		device_printf(dev, "cannot post fault event buffers\n");
		goto fail;
	}
	virtqueue_enable_intr(sc->vtiommu_event_vq);

	/* Publish the protocol engine to the busdma/VIOT seam. */
	sc->vtiommu_provider.dev = dev;
	sc->vtiommu_provider.attach = vtiommu_op_attach;
	sc->vtiommu_provider.detach = vtiommu_op_detach;
	sc->vtiommu_provider.map = vtiommu_op_map;
	sc->vtiommu_provider.unmap = vtiommu_op_unmap;
	sc->vtiommu_provider.probe_endpoint = vtiommu_op_probe;
	mtx_lock(&vtiommu_providers_mtx);
	LIST_INSERT_HEAD(&vtiommu_providers, &sc->vtiommu_provider, link);
	mtx_unlock(&vtiommu_providers_mtx);

	vtiommu_setup_sysctl(sc);

	if (bootverbose) {
		device_printf(dev, "page_size_mask 0x%jx input [0x%jx, 0x%jx] "
		    "domains [%u, %u] probe_size %u%s\n",
		    (uintmax_t)sc->vtiommu_cfg.page_size_mask,
		    (uintmax_t)sc->vtiommu_cfg.input_range.start,
		    (uintmax_t)sc->vtiommu_cfg.input_range.end,
		    sc->vtiommu_cfg.domain_range.start,
		    sc->vtiommu_cfg.domain_range.end,
		    sc->vtiommu_probe_cap,
		    (sc->vtiommu_flags & VTIOMMU_FLAG_BYPASS_CFG) ?
		    " bypass-config" : "");
	}

	return (0);

fail:
	vtiommu_detach(dev);
	return (error);
}

static int
vtiommu_detach(device_t dev)
{
	struct vtiommu_softc *sc;

	sc = device_get_softc(dev);

	VTIOMMU_LOCK(sc);
	sc->vtiommu_flags |= VTIOMMU_FLAG_DETACH;
	/*
	 * Wake any waiter and gated caller, then wait for an in-flight request to
	 * drain so the device is not reset (and the scratch not freed) while a
	 * descriptor is still outstanding against it.
	 */
	wakeup(sc);
	wakeup(&sc->vtiommu_req);
	while ((sc->vtiommu_flags & VTIOMMU_FLAG_REQ_BUSY) != 0)
		msleep(&sc->vtiommu_req, &sc->vtiommu_mtx, 0, "vtiomdt", 0);
	VTIOMMU_UNLOCK(sc);

	if (sc->vtiommu_provider.dev != NULL) {
		mtx_lock(&vtiommu_providers_mtx);
		LIST_REMOVE(&sc->vtiommu_provider, link);
		mtx_unlock(&vtiommu_providers_mtx);
		sc->vtiommu_provider.dev = NULL;
	}

	/*
	 * Reset the device unconditionally before freeing any host-visible
	 * memory.  This runs on the attach-failure unwind too (attach calls
	 * vtiommu_detach on error), where device_is_attached() is still false
	 * because newbus sets DF_ATTACHED only after attach returns 0.  Gating
	 * the reset on device_is_attached() would leave posted device-writable
	 * event buffers owned by the device while vtiommu_ebufs is freed below,
	 * a DMA-after-free.  virtio_stop() is safe even if no virtqueue was ever
	 * allocated.
	 */
	virtio_stop(dev);

	virtio_teardown_intr(dev);

	VTIOMMU_LOCK(sc);
	vtiommu_model_reset(sc);
	VTIOMMU_UNLOCK(sc);

	vtiommu_free_scratch(sc);

	if (sc->vtiommu_ebufs != NULL) {
		free(sc->vtiommu_ebufs, M_VTIOMMU);
		sc->vtiommu_ebufs = NULL;
	}
	if (sc->vtiommu_esg != NULL) {
		sglist_free(sc->vtiommu_esg);
		sc->vtiommu_esg = NULL;
	}

	VTIOMMU_LOCK_DESTROY(sc);
	return (0);
}

static int
vtiommu_config_change(device_t dev)
{
	struct vtiommu_softc *sc;

	sc = device_get_softc(dev);

	/*
	 * Only the BYPASS_CONFIG "bypass" byte is writable/observable at
	 * runtime; re-read the config so a subsequent bypass query reflects the
	 * device's current default.  Topology (page-size/domain/input ranges)
	 * is fixed for the life of the device.
	 */
	VTIOMMU_LOCK(sc);
	vtiommu_read_config(sc, &sc->vtiommu_cfg);
	VTIOMMU_UNLOCK(sc);
	return (0);
}

static int
vtiommu_setup_features(struct vtiommu_softc *sc)
{
	device_t dev;
	uint64_t features;
	int error;

	dev = sc->vtiommu_dev;
	features = VTIOMMU_FEATURES;

	sc->vtiommu_features = virtio_negotiate_features(dev, features);
	error = virtio_finalize_features(dev);
	if (error != 0)
		return (error);

	/*
	 * VIRTIO 1.4 section 5.13 defines the config layout only for modern
	 * (VERSION_1) devices, and the wire request encoding is little-endian
	 * regardless.  Refuse a transitional/legacy device rather than
	 * misinterpret its config space.
	 */
	if (!virtio_with_feature(dev, VIRTIO_F_VERSION_1)) {
		device_printf(dev, "legacy VirtIO-IOMMU is not supported\n");
		return (ENXIO);
	}

	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_MAP_UNMAP))
		sc->vtiommu_flags |= VTIOMMU_FLAG_MAP_UNMAP;
	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_PROBE))
		sc->vtiommu_flags |= VTIOMMU_FLAG_PROBE;
	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_BYPASS_CONFIG))
		sc->vtiommu_flags |= VTIOMMU_FLAG_BYPASS_CFG;

	return (0);
}

static void
vtiommu_read_config(struct vtiommu_softc *sc, struct virtio_iommu_config *cfg)
{
	device_t dev;

	dev = sc->vtiommu_dev;
	bzero(cfg, sizeof(*cfg));

	/*
	 * Each multi-byte field is read at its natural width; the transport
	 * already converts the little-endian (modern) or native (legacy) wire
	 * value to guest-native byte order, so no further byte-swap is applied
	 * here (matches vtmem_read_config()).
	 */
	virtio_read_device_config(dev,
	    offsetof(struct virtio_iommu_config, page_size_mask),
	    &cfg->page_size_mask, sizeof(cfg->page_size_mask));

	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_INPUT_RANGE)) {
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, input_range.start),
		    &cfg->input_range.start, sizeof(cfg->input_range.start));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, input_range.end),
		    &cfg->input_range.end, sizeof(cfg->input_range.end));
	} else {
		cfg->input_range.end = UINT64_MAX;
	}

	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_DOMAIN_RANGE)) {
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, domain_range.start),
		    &cfg->domain_range.start, sizeof(cfg->domain_range.start));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, domain_range.end),
		    &cfg->domain_range.end, sizeof(cfg->domain_range.end));
	} else {
		cfg->domain_range.end = UINT32_MAX;
	}

	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_PROBE)) {
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, probe_size),
		    &cfg->probe_size, sizeof(cfg->probe_size));
	}

	if (virtio_with_feature(dev, 1ULL << VIRTIO_IOMMU_F_BYPASS_CONFIG)) {
		virtio_read_device_config(dev,
		    offsetof(struct virtio_iommu_config, bypass),
		    &cfg->bypass, sizeof(cfg->bypass));
	}
}

static int
vtiommu_alloc_virtqueues(struct vtiommu_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info[VTIOMMU_NUM_VQS];
	int error;

	dev = sc->vtiommu_dev;

	VQ_ALLOC_INFO_INIT(&vq_info[VTIOMMU_REQ_VQ], 0,
	    vtiommu_req_vq_intr, sc, &sc->vtiommu_req_vq,
	    "%s request", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[VTIOMMU_EVENT_VQ], 0,
	    vtiommu_event_vq_intr, sc, &sc->vtiommu_event_vq,
	    "%s event", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, VTIOMMU_NUM_VQS, vq_info);
	return (error);
}

static int
vtiommu_alloc_scratch(struct vtiommu_softc *sc)
{
	size_t resp_len;

	/*
	 * The readable scratch must hold the largest request (PROBE, 72 bytes).
	 * The writable scratch holds a PROBE properties region plus the 4-byte
	 * request tail; non-PROBE requests use only the tail.
	 */
	resp_len = (size_t)sc->vtiommu_probe_cap +
	    sizeof(struct virtio_iommu_req_tail);
	if (resp_len < sizeof(struct virtio_iommu_req_tail))
		resp_len = sizeof(struct virtio_iommu_req_tail);
	sc->vtiommu_resp_len = resp_len;

	sc->vtiommu_io = malloc(sizeof(*sc->vtiommu_io), M_VTIOMMU,
	    M_WAITOK | M_ZERO);
	sc->vtiommu_req = sc->vtiommu_io->request;
	sc->vtiommu_resp = sc->vtiommu_io->response;

	/*
	 * sglist_append() splits a range at every physical-page boundary.  Do
	 * not assume an allocator-specific starting offset: both the request and
	 * response can begin near the end of a page.  Size each side for that
	 * worst case; vtiommu_send_request() derives the actual direction counts
	 * from the resulting segments.
	 */
	sc->vtiommu_sg = sglist_alloc(
	    howmany(sizeof(sc->vtiommu_io->request) + PAGE_SIZE - 1,
	    PAGE_SIZE) + howmany(resp_len + PAGE_SIZE - 1, PAGE_SIZE),
	    M_WAITOK);

	return (0);
}

static void
vtiommu_free_scratch(struct vtiommu_softc *sc)
{

	if (sc->vtiommu_io != NULL) {
		free(sc->vtiommu_io, M_VTIOMMU);
		sc->vtiommu_io = NULL;
	}
	sc->vtiommu_req = NULL;
	sc->vtiommu_resp = NULL;
	if (sc->vtiommu_sg != NULL) {
		sglist_free(sc->vtiommu_sg);
		sc->vtiommu_sg = NULL;
	}
}

/*
 * Submit a request that has already been marshalled into sc->vtiommu_req
 * (req_len readable bytes) and drive it to completion synchronously.  The
 * device writes resp_len bytes into sc->vtiommu_resp, the last four of which
 * are the request tail; the status byte is returned via *statusp.
 */
static int
vtiommu_send_request(struct vtiommu_softc *sc, size_t req_len, size_t resp_len,
    uint8_t *statusp)
{
	struct sglist *sg;
	struct virtio_iommu_req_tail *tail;
	sbintime_t deadline, remaining;
	void *cookie;
	uint32_t len;
	int readable, writable, error;

	VTIOMMU_LOCK_ASSERT(sc);

	if (resp_len < sizeof(struct virtio_iommu_req_tail) ||
	    resp_len > sc->vtiommu_resp_len)
		return (EINVAL);

	/*
	 * The request/response scratch is shared, and the softc lock is dropped
	 * while sleeping for completion, so concurrent callers must be serialized
	 * explicitly rather than by simply holding the lock across the wait.
	 */
	while ((sc->vtiommu_flags & VTIOMMU_FLAG_REQ_BUSY) != 0 &&
	    (sc->vtiommu_flags & (VTIOMMU_FLAG_DETACH | VTIOMMU_FLAG_BROKEN)) == 0)
		msleep(&sc->vtiommu_req, &sc->vtiommu_mtx, 0, "vtiombz", 0);
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_DETACH) != 0)
		return (ENXIO);
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_BROKEN) != 0)
		return (EIO);
	sc->vtiommu_flags |= VTIOMMU_FLAG_REQ_BUSY;

	sg = sc->vtiommu_sg;
	sglist_reset(sg);
	bzero(sc->vtiommu_resp, resp_len);

	/*
	 * The readable descriptors are the request; the writable descriptors
	 * are the response (the tail, optionally preceded by a PROBE properties
	 * region).  An explicit pad in their shared allocation prevents the
	 * opposite descriptor directions from coalescing.  Either range may still
	 * span more than one physical page, so derive the descriptor counts from
	 * the resulting segments rather than assuming one segment apiece.
	 */
	error = sglist_append(sg, sc->vtiommu_req, req_len);
	if (error != 0)
		goto release;
	readable = sg->sg_nseg;
	error = sglist_append_boundary(sg, sc->vtiommu_resp, resp_len);
	if (error != 0)
		goto release;
	writable = sg->sg_nseg - readable;
	KASSERT(writable > 0,
	    ("vtiommu: request and response collapsed into one descriptor"));
	if (writable == 0) {
		error = EFAULT;
		goto release;
	}

	error = virtqueue_enqueue(sc->vtiommu_req_vq, sc, sg, readable, writable);
	if (error != 0)
		goto release;
	virtqueue_notify(sc->vtiommu_req_vq);

	/*
	 * Wait for the device to retire the descriptor.  Enable the request
	 * interrupt and re-check before sleeping so a completion racing the
	 * enqueue is never missed; bound the wait so a wedged device cannot hang
	 * the caller (and the shared scratch buffers) indefinitely.
	 */
	deadline = sbinuptime() + VTIOMMU_REQUEST_TIMEOUT;
	for (;;) {
		cookie = virtqueue_dequeue(sc->vtiommu_req_vq, &len);
		if (cookie != NULL)
			break;
		if ((sc->vtiommu_flags &
		    (VTIOMMU_FLAG_DETACH | VTIOMMU_FLAG_BROKEN)) != 0) {
			error = (sc->vtiommu_flags & VTIOMMU_FLAG_DETACH) != 0 ?
			    ENXIO : EIO;
			break;
		}
		if (virtqueue_enable_intr(sc->vtiommu_req_vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = ETIMEDOUT;
			break;
		}
		error = msleep_sbt(sc, &sc->vtiommu_mtx, 0, "vtiomr",
		    remaining, 0, 0);
		if (error == EWOULDBLOCK) {
			error = ETIMEDOUT;
			break;
		}
		if (error != 0)
			break;
	}
	virtqueue_disable_intr(sc->vtiommu_req_vq);

	if (cookie == NULL) {
		/*
		 * The descriptor is still outstanding against the shared scratch
		 * buffers.  Declare the request queue broken so the buffers are
		 * never reused; the device is reset (reclaiming the descriptor)
		 * at detach before they are freed.
		 */
		device_printf(sc->vtiommu_dev,
		    "request did not complete (%d)\n", error);
		sc->vtiommu_flags |= VTIOMMU_FLAG_BROKEN;
		if (error == 0)
			error = EIO;
		goto release;
	}
	if (cookie != sc) {
		device_printf(sc->vtiommu_dev,
		    "request queue returned unexpected cookie\n");
		error = EIO;
		goto release;
	}
	if (len < sizeof(struct virtio_iommu_req_tail)) {
		/*
		 * Zero used length is the device's way of consuming an
		 * unrecognized request without answering.  Treat any short
		 * response as unsupported.
		 */
		error = EOPNOTSUPP;
		goto release;
	}

	tail = (struct virtio_iommu_req_tail *)
	    (sc->vtiommu_resp + resp_len - sizeof(*tail));
	if (statusp != NULL)
		*statusp = tail->status;
	error = 0;

release:
	sc->vtiommu_flags &= ~VTIOMMU_FLAG_REQ_BUSY;
	wakeup(&sc->vtiommu_req);
	return (error);
}

static int
vtiommu_status_to_errno(uint8_t status)
{

	switch (status) {
	case VIRTIO_IOMMU_S_OK:
		return (0);
	case VIRTIO_IOMMU_S_UNSUPP:
		return (EOPNOTSUPP);
	case VIRTIO_IOMMU_S_INVAL:
		return (EINVAL);
	case VIRTIO_IOMMU_S_RANGE:
		return (ERANGE);
	case VIRTIO_IOMMU_S_NOENT:
		return (ENOENT);
	case VIRTIO_IOMMU_S_NOMEM:
		return (ENOMEM);
	case VIRTIO_IOMMU_S_FAULT:
		return (EFAULT);
	case VIRTIO_IOMMU_S_IOERR:
	case VIRTIO_IOMMU_S_DEVERR:
	default:
		return (EIO);
	}
}

/*
 * Protocol operations.  Each marshals a request, submits it, and -- on a
 * successful device status -- updates the guest-side model.
 */

static int
vtiommu_op_attach(device_t dev, uint32_t domain, uint32_t endpoint,
    uint32_t flags)
{
	struct vtiommu_softc *sc;
	struct virtio_iommu_req_attach *req;
	struct vtiommu_domain *vd;
	struct vtiommu_endpoint *ve;
	uint8_t status;
	int error;

	sc = device_get_softc(dev);
	if ((flags & VIRTIO_IOMMU_ATTACH_F_BYPASS) != 0 &&
	    (sc->vtiommu_flags & VTIOMMU_FLAG_BYPASS_CFG) == 0)
		return (EOPNOTSUPP);

	VTIOMMU_LOCK(sc);
	req = (struct virtio_iommu_req_attach *)sc->vtiommu_req;
	bzero(req, sizeof(*req));
	req->head.type = VIRTIO_IOMMU_T_ATTACH;
	req->domain = htole32(domain);
	req->endpoint = htole32(endpoint);
	req->flags = htole32(flags);

	error = vtiommu_send_request(sc, sizeof(*req),
	    sizeof(struct virtio_iommu_req_tail), &status);
	if (error == 0)
		error = vtiommu_status_to_errno(status);
	if (error != 0) {
		VTIOMMU_UNLOCK(sc);
		return (error);
	}

	/* Update the model: bind the endpoint to the (possibly new) domain. */
	ve = vtiommu_endpoint_get(sc, endpoint);
	vd = vtiommu_domain_get(sc, domain);
	if (ve == NULL || vd == NULL) {
		/* Bookkeeping-only failure; the device state is authoritative. */
		VTIOMMU_UNLOCK(sc);
		return (0);
	}
	if (ve->ve_domain != NULL && ve->ve_domain != vd) {
		ve->ve_domain->vd_refs--;
		vtiommu_domain_gc(sc, ve->ve_domain);
	}
	if (ve->ve_domain != vd) {
		ve->ve_domain = vd;
		vd->vd_refs++;
	}
	ve->ve_bypass = (flags & VIRTIO_IOMMU_ATTACH_F_BYPASS) != 0;
	sc->vtiommu_stat_attach++;
	VTIOMMU_UNLOCK(sc);
	return (0);
}

static int
vtiommu_op_detach(device_t dev, uint32_t domain, uint32_t endpoint)
{
	struct vtiommu_softc *sc;
	struct virtio_iommu_req_detach *req;
	struct vtiommu_endpoint *ve;
	uint8_t status;
	int error;

	sc = device_get_softc(dev);

	VTIOMMU_LOCK(sc);
	req = (struct virtio_iommu_req_detach *)sc->vtiommu_req;
	bzero(req, sizeof(*req));
	req->head.type = VIRTIO_IOMMU_T_DETACH;
	req->domain = htole32(domain);
	req->endpoint = htole32(endpoint);

	error = vtiommu_send_request(sc, sizeof(*req),
	    sizeof(struct virtio_iommu_req_tail), &status);
	if (error == 0)
		error = vtiommu_status_to_errno(status);
	if (error != 0) {
		VTIOMMU_UNLOCK(sc);
		return (error);
	}

	ve = vtiommu_endpoint_find(sc, endpoint);
	if (ve != NULL && ve->ve_domain != NULL) {
		ve->ve_domain->vd_refs--;
		vtiommu_domain_gc(sc, ve->ve_domain);
		ve->ve_domain = NULL;
		ve->ve_bypass = false;
	}
	sc->vtiommu_stat_detach++;
	VTIOMMU_UNLOCK(sc);
	return (0);
}

static int
vtiommu_op_map(device_t dev, uint32_t domain, uint64_t iova_start,
    uint64_t iova_end, uint64_t phys_start, uint32_t prot)
{
	struct vtiommu_softc *sc;
	struct virtio_iommu_req_map *req;
	struct vtiommu_domain *vd;
	uint8_t status;
	int error;

	sc = device_get_softc(dev);
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_MAP_UNMAP) == 0)
		return (EOPNOTSUPP);
	if (iova_start > iova_end)
		return (EINVAL);
	if ((prot & ~(uint32_t)VIRTIO_IOMMU_MAP_F_MASK) != 0)
		return (EINVAL);

	VTIOMMU_LOCK(sc);
	req = (struct virtio_iommu_req_map *)sc->vtiommu_req;
	bzero(req, sizeof(*req));
	req->head.type = VIRTIO_IOMMU_T_MAP;
	req->domain = htole32(domain);
	req->virt_start = htole64(iova_start);
	req->virt_end = htole64(iova_end);
	req->phys_start = htole64(phys_start);
	req->flags = htole32(prot);

	error = vtiommu_send_request(sc, sizeof(*req),
	    sizeof(struct virtio_iommu_req_tail), &status);
	if (error == 0)
		error = vtiommu_status_to_errno(status);
	if (error != 0) {
		VTIOMMU_UNLOCK(sc);
		return (error);
	}

	vd = vtiommu_domain_get(sc, domain);
	if (vd != NULL) {
		vtiommu_domain_add_map(vd, iova_start, iova_end, phys_start,
		    prot);
		sc->vtiommu_stat_map++;
	}
	VTIOMMU_UNLOCK(sc);
	return (0);
}

static int
vtiommu_op_unmap(device_t dev, uint32_t domain, uint64_t iova_start,
    uint64_t iova_end)
{
	struct vtiommu_softc *sc;
	struct virtio_iommu_req_unmap *req;
	struct vtiommu_domain *vd;
	uint8_t status;
	int error;

	sc = device_get_softc(dev);
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_MAP_UNMAP) == 0)
		return (EOPNOTSUPP);
	if (iova_start > iova_end)
		return (EINVAL);

	VTIOMMU_LOCK(sc);
	req = (struct virtio_iommu_req_unmap *)sc->vtiommu_req;
	bzero(req, sizeof(*req));
	req->head.type = VIRTIO_IOMMU_T_UNMAP;
	req->domain = htole32(domain);
	req->virt_start = htole64(iova_start);
	req->virt_end = htole64(iova_end);

	error = vtiommu_send_request(sc, sizeof(*req),
	    sizeof(struct virtio_iommu_req_tail), &status);
	if (error == 0)
		error = vtiommu_status_to_errno(status);
	if (error != 0) {
		VTIOMMU_UNLOCK(sc);
		return (error);
	}

	vd = vtiommu_domain_find(sc, domain);
	if (vd != NULL) {
		vtiommu_domain_del_range(vd, iova_start, iova_end);
		sc->vtiommu_stat_unmap++;
	}
	VTIOMMU_UNLOCK(sc);
	return (0);
}

/*
 * Parse a PROBE reply's property list.  bhyve returns an all-zero properties
 * region (a single T_NONE terminator, i.e. no reserved regions), but a
 * conforming device may return RESV_MEM properties describing regions that
 * must not be used as IOVA (for example MSI doorbells).  We log those and stop
 * at the first malformed or terminating entry.
 */
static void
vtiommu_parse_probe(struct vtiommu_softc *sc, uint32_t endpoint,
    const uint8_t *props, size_t len)
{
	struct virtio_iommu_probe_property hdr;
	struct virtio_iommu_probe_resv_mem resv;
	size_t off;
	uint16_t type, plen;

	off = 0;
	while (off + sizeof(hdr) <= len) {
		memcpy(&hdr, props + off, sizeof(hdr));
		type = le16toh(hdr.type) & VIRTIO_IOMMU_PROBE_T_MASK;
		plen = le16toh(hdr.length);
		if (type == VIRTIO_IOMMU_PROBE_T_NONE)
			break;
		if (off + sizeof(hdr) + plen > len)
			break;
		if (type == VIRTIO_IOMMU_PROBE_T_RESV_MEM &&
		    plen + sizeof(hdr) >= sizeof(resv)) {
			memcpy(&resv, props + off, sizeof(resv));
			if (bootverbose) {
				device_printf(sc->vtiommu_dev,
				    "endpoint %u reserved region subtype %u "
				    "[0x%jx, 0x%jx]\n", endpoint, resv.subtype,
				    (uintmax_t)le64toh(resv.start),
				    (uintmax_t)le64toh(resv.end));
			}
		}
		off += sizeof(hdr) + plen;
	}
}

static int
vtiommu_op_probe(device_t dev, uint32_t endpoint)
{
	struct vtiommu_softc *sc;
	struct virtio_iommu_req_probe *req;
	size_t resp_len;
	uint8_t status;
	int error;

	sc = device_get_softc(dev);
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_PROBE) == 0)
		return (EOPNOTSUPP);

	VTIOMMU_LOCK(sc);
	req = (struct virtio_iommu_req_probe *)sc->vtiommu_req;
	bzero(req, sizeof(*req));
	req->head.type = VIRTIO_IOMMU_T_PROBE;
	req->endpoint = htole32(endpoint);

	resp_len = (size_t)sc->vtiommu_probe_cap +
	    sizeof(struct virtio_iommu_req_tail);

	error = vtiommu_send_request(sc, sizeof(*req), resp_len, &status);
	if (error == 0)
		error = vtiommu_status_to_errno(status);
	if (error != 0) {
		VTIOMMU_UNLOCK(sc);
		return (error);
	}

	/* Register the endpoint and record its reserved regions. */
	(void)vtiommu_endpoint_get(sc, endpoint);
	vtiommu_parse_probe(sc, endpoint, sc->vtiommu_resp,
	    sc->vtiommu_probe_cap);
	sc->vtiommu_stat_probe++;
	VTIOMMU_UNLOCK(sc);
	return (0);
}

/*
 * Event (fault) virtqueue.
 */
static int
vtiommu_enqueue_event_buf(struct vtiommu_softc *sc,
    struct vtiommu_event_buf *eb)
{
	struct sglist *sg;
	int error;

	sg = sc->vtiommu_esg;
	sglist_reset(sg);
	error = sglist_append(sg, &eb->eb_fault, sizeof(eb->eb_fault));
	if (error != 0)
		return (error);
	/* Entirely device-writable. */
	return (virtqueue_enqueue(sc->vtiommu_event_vq, eb, sg, 0, 1));
}

static int
vtiommu_populate_event_vq(struct vtiommu_softc *sc)
{
	int i, n, error;

	n = virtqueue_size(sc->vtiommu_event_vq);
	if (n <= 0)
		return (0);
	n = MIN(n, VTIOMMU_EVENT_BUFS);

	sc->vtiommu_ebufs = mallocarray(n, sizeof(struct vtiommu_event_buf),
	    M_VTIOMMU, M_WAITOK | M_ZERO);
	sc->vtiommu_esg = sglist_alloc(1, M_WAITOK);

	for (i = 0; i < n; i++) {
		error = vtiommu_enqueue_event_buf(sc, &sc->vtiommu_ebufs[i]);
		if (error != 0)
			return (error);
	}
	virtqueue_notify(sc->vtiommu_event_vq);
	return (0);
}

static void
vtiommu_handle_fault(struct vtiommu_softc *sc,
    const struct virtio_iommu_fault *wire)
{
	struct virtio_iommu_fault f;

	/* Convert the little-endian wire event to host order. */
	f.reason = wire->reason;
	f.flags = le32toh(wire->flags);
	f.endpoint = le32toh(wire->endpoint);
	f.address = le64toh(wire->address);

	sc->vtiommu_stat_faults++;
	sc->vtiommu_last_fault = f;

	device_printf(sc->vtiommu_dev,
	    "translation fault: endpoint %u reason %u flags 0x%x%s%s%s\n",
	    f.endpoint, f.reason, f.flags,
	    (f.flags & VIRTIO_IOMMU_FAULT_F_READ) ? " read" : "",
	    (f.flags & VIRTIO_IOMMU_FAULT_F_WRITE) ? " write" : "",
	    (f.flags & VIRTIO_IOMMU_FAULT_F_ADDRESS) ? " addr-valid" : "");
	if ((f.flags & VIRTIO_IOMMU_FAULT_F_ADDRESS) != 0)
		device_printf(sc->vtiommu_dev, "  faulting IOVA 0x%jx\n",
		    (uintmax_t)f.address);
}

static void
vtiommu_event_vq_intr(void *xsc)
{
	struct vtiommu_softc *sc;
	struct vtiommu_event_buf *eb;
	uint32_t len;

	sc = xsc;

	VTIOMMU_LOCK(sc);
again:
	while ((eb = virtqueue_dequeue(sc->vtiommu_event_vq, &len)) != NULL) {
		if (len >= sizeof(eb->eb_fault))
			vtiommu_handle_fault(sc, &eb->eb_fault);
		bzero(&eb->eb_fault, sizeof(eb->eb_fault));
		if ((sc->vtiommu_flags & VTIOMMU_FLAG_DETACH) == 0)
			(void)vtiommu_enqueue_event_buf(sc, eb);
	}
	if ((sc->vtiommu_flags & VTIOMMU_FLAG_DETACH) == 0) {
		if (virtqueue_enable_intr(sc->vtiommu_event_vq) != 0) {
			virtqueue_disable_intr(sc->vtiommu_event_vq);
			goto again;
		}
		virtqueue_notify(sc->vtiommu_event_vq);
	}
	VTIOMMU_UNLOCK(sc);
}

static void
vtiommu_req_vq_intr(void *xsc)
{
	struct vtiommu_softc *sc = xsc;

	/*
	 * vtiommu_send_request() enables this interrupt only while waiting for a
	 * completion.  Wake the waiter; it re-checks the used ring under the
	 * lock.
	 */
	VTIOMMU_LOCK(sc);
	wakeup(sc);
	VTIOMMU_UNLOCK(sc);
}

/*
 * Guest-side domain / endpoint / mapping model.
 */
static struct vtiommu_domain *
vtiommu_domain_find(struct vtiommu_softc *sc, uint32_t id)
{
	struct vtiommu_domain *vd;

	VTIOMMU_LOCK_ASSERT(sc);
	LIST_FOREACH(vd, &sc->vtiommu_domains, vd_link) {
		if (vd->vd_id == id)
			return (vd);
	}
	return (NULL);
}

static struct vtiommu_domain *
vtiommu_domain_get(struct vtiommu_softc *sc, uint32_t id)
{
	struct vtiommu_domain *vd;

	VTIOMMU_LOCK_ASSERT(sc);
	vd = vtiommu_domain_find(sc, id);
	if (vd != NULL)
		return (vd);
	vd = malloc(sizeof(*vd), M_VTIOMMU, M_NOWAIT | M_ZERO);
	if (vd == NULL)
		return (NULL);
	vd->vd_id = id;
	LIST_INIT(&vd->vd_maps);
	LIST_INSERT_HEAD(&sc->vtiommu_domains, vd, vd_link);
	return (vd);
}

static void
vtiommu_domain_gc(struct vtiommu_softc *sc, struct vtiommu_domain *vd)
{
	struct vtiommu_mapping *vm;

	VTIOMMU_LOCK_ASSERT(sc);
	if (vd->vd_refs != 0 || !LIST_EMPTY(&vd->vd_maps))
		return;
	while ((vm = LIST_FIRST(&vd->vd_maps)) != NULL) {
		LIST_REMOVE(vm, vm_link);
		free(vm, M_VTIOMMU);
	}
	LIST_REMOVE(vd, vd_link);
	free(vd, M_VTIOMMU);
}

static struct vtiommu_endpoint *
vtiommu_endpoint_find(struct vtiommu_softc *sc, uint32_t rid)
{
	struct vtiommu_endpoint *ve;

	VTIOMMU_LOCK_ASSERT(sc);
	LIST_FOREACH(ve, &sc->vtiommu_endpoints, ve_link) {
		if (ve->ve_rid == rid)
			return (ve);
	}
	return (NULL);
}

static struct vtiommu_endpoint *
vtiommu_endpoint_get(struct vtiommu_softc *sc, uint32_t rid)
{
	struct vtiommu_endpoint *ve;

	VTIOMMU_LOCK_ASSERT(sc);
	ve = vtiommu_endpoint_find(sc, rid);
	if (ve != NULL)
		return (ve);
	ve = malloc(sizeof(*ve), M_VTIOMMU, M_NOWAIT | M_ZERO);
	if (ve == NULL)
		return (NULL);
	ve->ve_rid = rid;
	LIST_INSERT_HEAD(&sc->vtiommu_endpoints, ve, ve_link);
	return (ve);
}

static void
vtiommu_domain_add_map(struct vtiommu_domain *vd, uint64_t start, uint64_t end,
    uint64_t phys, uint32_t flags)
{
	struct vtiommu_mapping *vm;

	/* Drop any stale overlap before recording the new translation. */
	vtiommu_domain_del_range(vd, start, end);
	vm = malloc(sizeof(*vm), M_VTIOMMU, M_NOWAIT | M_ZERO);
	if (vm == NULL)
		return;
	vm->vm_start = start;
	vm->vm_end = end;
	vm->vm_phys = phys;
	vm->vm_flags = flags;
	LIST_INSERT_HEAD(&vd->vd_maps, vm, vm_link);
}

static void
vtiommu_domain_del_range(struct vtiommu_domain *vd, uint64_t start,
    uint64_t end)
{
	struct vtiommu_mapping *vm, *tmp;

	LIST_FOREACH_SAFE(vm, &vd->vd_maps, vm_link, tmp) {
		if (vm->vm_start > end || vm->vm_end < start)
			continue;
		LIST_REMOVE(vm, vm_link);
		free(vm, M_VTIOMMU);
	}
}

static void
vtiommu_model_reset(struct vtiommu_softc *sc)
{
	struct vtiommu_domain *vd;
	struct vtiommu_endpoint *ve;
	struct vtiommu_mapping *vm;

	VTIOMMU_LOCK_ASSERT(sc);
	while ((ve = LIST_FIRST(&sc->vtiommu_endpoints)) != NULL) {
		LIST_REMOVE(ve, ve_link);
		free(ve, M_VTIOMMU);
	}
	while ((vd = LIST_FIRST(&sc->vtiommu_domains)) != NULL) {
		while ((vm = LIST_FIRST(&vd->vd_maps)) != NULL) {
			LIST_REMOVE(vm, vm_link);
			free(vm, M_VTIOMMU);
		}
		LIST_REMOVE(vd, vd_link);
		free(vd, M_VTIOMMU);
	}
}

/*
 * busdma/VIOT seam: resolve an endpoint RID to the virtio-iommu instance whose
 * request queue can program it.  A future VIOT-driven busdma_iommu back end
 * calls this to obtain the provider vtable (see the boundary comment above and
 * struct virtio_iommu_provider in virtio_iommu.h).
 */
struct virtio_iommu_provider *
virtio_iommu_provider_lookup(uint32_t endpoint)
{
	struct virtio_iommu_provider *p, *found;
	struct vtiommu_softc *sc;

	found = NULL;
	mtx_lock(&vtiommu_providers_mtx);
	LIST_FOREACH(p, &vtiommu_providers, link) {
		sc = device_get_softc(p->dev);
		VTIOMMU_LOCK(sc);
		if (vtiommu_endpoint_find(sc, endpoint) != NULL)
			found = p;
		VTIOMMU_UNLOCK(sc);
		if (found != NULL)
			break;
	}
	mtx_unlock(&vtiommu_providers_mtx);
	return (found);
}

static void
vtiommu_setup_sysctl(struct vtiommu_softc *sc)
{
	device_t dev;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	dev = sc->vtiommu_dev;
	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "attach_reqs",
	    CTLFLAG_RD, &sc->vtiommu_stat_attach, 0, "ATTACH requests");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "detach_reqs",
	    CTLFLAG_RD, &sc->vtiommu_stat_detach, 0, "DETACH requests");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "map_reqs",
	    CTLFLAG_RD, &sc->vtiommu_stat_map, 0, "MAP requests");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "unmap_reqs",
	    CTLFLAG_RD, &sc->vtiommu_stat_unmap, 0, "UNMAP requests");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "probe_reqs",
	    CTLFLAG_RD, &sc->vtiommu_stat_probe, 0, "PROBE requests");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "faults",
	    CTLFLAG_RD, &sc->vtiommu_stat_faults, 0, "Fault events received");
}
