/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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
 * Driver for the VirtIO memory device (virtio-mem, VirtIO 1.4 section 5.15).
 *
 * A virtio-mem device exposes a contiguous guest-physical region [addr,
 * addr + region_size).  The region is divided into fixed-size blocks of
 * block_size bytes.  The device tells the driver, via the requested_size
 * configuration field, how many bytes within the usable sub-region it wants
 * plugged (made available to the guest).  The driver reconciles the amount it
 * has plugged toward requested_size by issuing PLUG and UNPLUG requests on the
 * single request virtqueue, and it re-evaluates whenever the device raises a
 * configuration-change interrupt.  A per-block bitmap records which blocks are
 * currently plugged.
 *
 * This driver implements the complete guest side of that protocol:
 *   - feature negotiation (no device-specific features are required or
 *     offered by the reference bhyve device; split and packed rings are
 *     negotiated transparently by the shared transport/virtqueue layer),
 *   - configuration-space parsing with a generation-consistent snapshot,
 *   - the PLUG / UNPLUG / UNPLUG_ALL / STATE request/response state machine,
 *   - a block bitmap and plugged-size accounting,
 *   - handling of the ACK / NACK / BUSY / ERROR response codes, and
 *   - configuration-change interrupt handling.
 *
 * ONLINE / MEMORY-HOTPLUG BOUNDARY (read this before extending the driver):
 *
 *   On Linux the driver's next step would be to hand each freshly plugged
 *   block to the memory-hotplug subsystem so the pages join the kernel page
 *   allocator (add_memory()/online_pages()).  FreeBSD has no equivalent
 *   supported runtime path:
 *
 *     - vm_phys_add_seg()/vm_phys_early_add_seg() are boot-time only.  They
 *       are invoked from vm_page_startup()/vm_phys_init() while the VM system
 *       is single-threaded, mutate the fixed-size vm_phys_segs[] array with no
 *       runtime locking, and assume the segment table is finalized once boot
 *       completes.
 *     - vm_page_array (the struct vm_page backing store) is sized once at boot
 *       from phys_avail and cannot be grown at runtime, so physical pages that
 *       appear after boot have no page structures and cannot be freed into the
 *       allocator.
 *
 *   There is therefore genuinely no supported mechanism to online plugged
 *   virtio-mem pages into this kernel's allocator today.  Rather than fake it,
 *   this driver stops at the protocol boundary: it correctly negotiates,
 *   plugs and unplugs blocks per the device contract and accounts for them,
 *   and exposes the plugged size via sysctl, but it does NOT add plugged pages
 *   to the page allocator.  vtmem_online_blocks()/vtmem_offline_blocks() are
 *   the single, clearly-marked seam where a future FreeBSD runtime memory-add
 *   facility would hook in; until such a facility exists they only account.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>

#include <machine/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/mem/virtio_mem.h>

#include "virtio_if.h"

CTASSERT(sizeof(struct virtio_mem_req) == 24);
CTASSERT(sizeof(struct virtio_mem_resp) == 10);
CTASSERT(sizeof(struct virtio_mem_config) == 56);
CTASSERT(offsetof(struct virtio_mem_config, addr) == 16);
CTASSERT(offsetof(struct virtio_mem_config, requested_size) == 48);

/* This driver requires no device-specific features. */
#define VTMEM_FEATURES		0

/*
 * Blocks moved per request.  nb_blocks is a 16-bit wire field, but keeping the
 * per-request span modest bounds the host-side work of a single request and
 * lets a configuration change be observed between chunks.
 */
#define VTMEM_BLOCKS_PER_REQUEST	512

/*
 * Upper bound on the number of blocks (region_size / block_size).  Matches the
 * reference device's cap and bounds the bitmap allocation.
 */
#define VTMEM_MAX_BLOCKS		(1024U * 1024U)

/* Retry delay after a BUSY/NACK response. */
#define VTMEM_RETRY_TIMEOUT		hz

/* Bound a device that consumes a request but never returns its descriptor. */
#define VTMEM_REQUEST_TIMEOUT		(5 * SBT_1S)

#define VTMEM_F_DETACH		0x01
#define VTMEM_F_FAILED		0x02
#define VTMEM_F_TD_EXITED	0x04

struct vtmem_request_io {
	struct virtio_mem_req	 request;
	uint32_t		 pad;
	struct virtio_mem_resp	 response;
};
CTASSERT(offsetof(struct vtmem_request_io, response) >=
    sizeof(struct virtio_mem_req) + 1);

struct vtmem_softc {
	device_t		 vtmem_dev;
	struct mtx		 vtmem_mtx;
	uint64_t		 vtmem_features;
	struct virtqueue	*vtmem_vq;
	struct thread		*vtmem_td;
	uint32_t		 vtmem_flags;

	/* Immutable geometry captured at attach. */
	uint64_t		 vtmem_block_size;
	uint64_t		 vtmem_addr;
	uint64_t		 vtmem_region_size;
	uint32_t		 vtmem_nblocks;

	/* Reconciliation targets refreshed from configuration space. */
	uint64_t		 vtmem_usable_region_size;
	uint64_t		 vtmem_requested_size;
	uint32_t		 vtmem_target_blocks;

	/* Plugged-block accounting; owned by the worker thread. */
	uint8_t			*vtmem_bitmap;
	uint32_t		 vtmem_plugged_blocks;

	int			 vtmem_timeout;

	/* The pad preserves the request/response descriptor direction boundary. */
	struct vtmem_request_io	*vtmem_io;
};

static int	vtmem_probe(device_t);
static int	vtmem_attach(device_t);
static int	vtmem_detach(device_t);
static int	vtmem_attach_completed(device_t);
static int	vtmem_config_change(device_t);

static int	vtmem_negotiate_features(struct vtmem_softc *);
static int	vtmem_alloc_virtqueue(struct vtmem_softc *);
static void	vtmem_read_config(struct vtmem_softc *,
		    struct virtio_mem_config *);
static void	vtmem_vq_intr(void *);

static int	vtmem_send_request(struct vtmem_softc *, uint16_t, uint64_t,
		    uint16_t, uint16_t *);
static bool	vtmem_block_get(const struct vtmem_softc *, uint32_t);
static void	vtmem_block_set(struct vtmem_softc *, uint32_t, uint32_t, bool);

static int	vtmem_unplug_all(struct vtmem_softc *);
static int	vtmem_plug_one(struct vtmem_softc *);
static int	vtmem_unplug_one(struct vtmem_softc *);

static void	vtmem_online_blocks(struct vtmem_softc *, uint32_t, uint32_t);
static void	vtmem_offline_blocks(struct vtmem_softc *, uint32_t, uint32_t);

static void	vtmem_fail(struct vtmem_softc *);
static int	vtmem_sleep(struct vtmem_softc *);
static void	vtmem_thread(void *);
static void	vtmem_setup_sysctl(struct vtmem_softc *);

/*
 * Because plugged blocks cannot be handed to the FreeBSD page allocator (see
 * the file banner), plugging memory the guest cannot use only consumes host
 * backing.  Default to protocol-only operation: negotiate, account, and answer
 * config/STATE, but do not actually PLUG toward requested_size unless an
 * operator opts in with hw.virtio_mem.allow_plug=1 (useful for exercising the
 * full PLUG/UNPLUG contract).  Wire this into onlining if FreeBSD ever gains a
 * runtime memory-add facility.
 */
static int vtmem_allow_plug = 0;
SYSCTL_NODE(_hw, OID_AUTO, virtio_mem, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "VirtIO memory driver");
SYSCTL_INT(_hw_virtio_mem, OID_AUTO, allow_plug,
    CTLFLAG_RDTUN, &vtmem_allow_plug, 0,
    "Issue PLUG requests toward requested_size (plugged memory is not onlined)");

#define vtmem_modern(_sc)	\
    (((_sc)->vtmem_features & VIRTIO_F_VERSION_1) != 0)

#define VTMEM_LOCK(_sc)		mtx_lock(&(_sc)->vtmem_mtx)
#define VTMEM_UNLOCK(_sc)	mtx_unlock(&(_sc)->vtmem_mtx)
#define VTMEM_LOCK_ASSERT(_sc)	mtx_assert(&(_sc)->vtmem_mtx, MA_OWNED)

static struct virtio_feature_desc vtmem_feature_desc[] = {
	{ VIRTIO_MEM_F_ACPI_PXM,		"ACPIProximity"		},
	{ VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE,	"UnpluggedInaccessible"	},
	{ 0, NULL }
};

static device_method_t vtmem_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtmem_probe),
	DEVMETHOD(device_attach,	vtmem_attach),
	DEVMETHOD(device_detach,	vtmem_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_attach_completed, vtmem_attach_completed),
	DEVMETHOD(virtio_config_change,	vtmem_config_change),

	DEVMETHOD_END
};

static driver_t vtmem_driver = {
	"vtmem",
	vtmem_methods,
	sizeof(struct vtmem_softc)
};

VIRTIO_DRIVER_MODULE(virtio_mem, vtmem_driver, 0, 0);
MODULE_VERSION(virtio_mem, 1);
MODULE_DEPEND(virtio_mem, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_mem, VIRTIO_ID_MEM,
    "VirtIO Memory Adapter");

static int
vtmem_probe(device_t dev)
{

	/* virtio-mem is a modern-only (VirtIO 1.0+) device. */
	if (!virtio_bus_is_modern(dev))
		return (ENXIO);
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_mem));
}

static int
vtmem_attach(device_t dev)
{
	struct vtmem_softc *sc;
	struct virtio_mem_config cfg;
	uint64_t blocks;
	int error;

	sc = device_get_softc(dev);
	sc->vtmem_dev = dev;
	mtx_init(&sc->vtmem_mtx, device_get_nameunit(dev), "VirtIO Memory",
	    MTX_DEF);
	virtio_set_feature_desc(dev, vtmem_feature_desc);

	vtmem_setup_sysctl(sc);

	error = vtmem_negotiate_features(sc);
	if (error != 0) {
		device_printf(dev, "cannot negotiate features\n");
		goto fail;
	}

	/*
	 * Capture the immutable geometry.  block_size and addr must be aligned,
	 * region_size must be a whole number of blocks, and the block count must
	 * be representable and bounded so the bitmap allocation is sane.
	 */
	vtmem_read_config(sc, &cfg);
	sc->vtmem_block_size = cfg.block_size;
	sc->vtmem_addr = cfg.addr;
	sc->vtmem_region_size = cfg.region_size;
	sc->vtmem_usable_region_size = cfg.usable_region_size;
	sc->vtmem_requested_size = cfg.requested_size;

	if (sc->vtmem_block_size == 0 ||
	    !powerof2(sc->vtmem_block_size) ||
	    (sc->vtmem_block_size % PAGE_SIZE) != 0 ||
	    sc->vtmem_region_size == 0 ||
	    (sc->vtmem_region_size % sc->vtmem_block_size) != 0 ||
	    (sc->vtmem_addr % sc->vtmem_block_size) != 0 ||
	    sc->vtmem_region_size > UINT64_MAX - sc->vtmem_addr ||
	    sc->vtmem_usable_region_size > sc->vtmem_region_size ||
	    sc->vtmem_requested_size > sc->vtmem_usable_region_size) {
		device_printf(dev, "invalid device configuration\n");
		error = ENXIO;
		goto fail;
	}
	blocks = sc->vtmem_region_size / sc->vtmem_block_size;
	if (blocks == 0 || blocks > VTMEM_MAX_BLOCKS) {
		device_printf(dev, "unsupported block count %ju\n",
		    (uintmax_t)blocks);
		error = ENXIO;
		goto fail;
	}
	sc->vtmem_nblocks = (uint32_t)blocks;

	sc->vtmem_bitmap = malloc(howmany(sc->vtmem_nblocks, 8), M_DEVBUF,
	    M_WAITOK | M_ZERO);
	sc->vtmem_io = malloc(sizeof(*sc->vtmem_io), M_DEVBUF,
	    M_WAITOK | M_ZERO);

	error = vtmem_alloc_virtqueue(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueue\n");
		goto fail;
	}
	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error != 0) {
		device_printf(dev, "cannot setup virtqueue interrupt\n");
		goto fail;
	}

	device_printf(dev,
	    "block_size=%ju region_size=%ju usable=%ju requested=%ju "
	    "blocks=%u\n", (uintmax_t)sc->vtmem_block_size,
	    (uintmax_t)sc->vtmem_region_size,
	    (uintmax_t)sc->vtmem_usable_region_size,
	    (uintmax_t)sc->vtmem_requested_size, sc->vtmem_nblocks);
	return (0);

fail:
	vtmem_detach(dev);
	return (error);
}

static int
vtmem_attach_completed(device_t dev)
{
	struct vtmem_softc *sc;
	int error;

	/*
	 * DRIVER_OK is set only after device_attach() returns, so requests may
	 * not be issued from attach().  Enable the queue interrupt and start the
	 * reconciliation worker here, once the device is fully live.
	 */
	sc = device_get_softc(dev);
	VTMEM_LOCK(sc);
	virtqueue_enable_intr(sc->vtmem_vq);
	VTMEM_UNLOCK(sc);

	error = kthread_add(vtmem_thread, sc, NULL, &sc->vtmem_td, 0, 0,
	    "virtio_mem");
	if (error != 0) {
		device_printf(dev, "cannot create worker thread\n");
		VTMEM_LOCK(sc);
		vtmem_fail(sc);
		VTMEM_UNLOCK(sc);
	}
	return (error);
}

static int
vtmem_detach(device_t dev)
{
	struct vtmem_softc *sc;

	sc = device_get_softc(dev);

	if (sc->vtmem_td != NULL) {
		VTMEM_LOCK(sc);
		sc->vtmem_flags |= VTMEM_F_DETACH;
		wakeup(sc);
		/*
		 * Wait on the sticky exit predicate rather than a single wakeup:
		 * the worker may already have exited (on a device failure) before
		 * detach was ever entered, in which case its wakeup is long gone.
		 * Looping on VTMEM_F_TD_EXITED closes that lost-wakeup race so
		 * detach cannot wedge unkillably.
		 */
		while ((sc->vtmem_flags & VTMEM_F_TD_EXITED) == 0)
			msleep(sc->vtmem_td, &sc->vtmem_mtx, 0, "vtmdth", 0);
		VTMEM_UNLOCK(sc);
		sc->vtmem_td = NULL;
	}

	virtio_stop(dev);
	virtio_teardown_intr(dev);

	if (sc->vtmem_bitmap != NULL) {
		free(sc->vtmem_bitmap, M_DEVBUF);
		sc->vtmem_bitmap = NULL;
	}
	if (sc->vtmem_io != NULL) {
		free(sc->vtmem_io, M_DEVBUF);
		sc->vtmem_io = NULL;
	}
	mtx_destroy(&sc->vtmem_mtx);
	return (0);
}

static int
vtmem_config_change(device_t dev)
{
	struct vtmem_softc *sc;

	/*
	 * requested_size or usable_region_size may have changed.  Wake the
	 * worker; it re-reads a consistent configuration snapshot and
	 * recomputes its target.
	 */
	sc = device_get_softc(dev);
	VTMEM_LOCK(sc);
	sc->vtmem_timeout = 0;
	wakeup(sc);
	VTMEM_UNLOCK(sc);
	return (1);
}

static int
vtmem_negotiate_features(struct vtmem_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtmem_dev;
	features = VTMEM_FEATURES;

	sc->vtmem_features = virtio_negotiate_features(dev, features);
	return (virtio_finalize_features(dev));
}

static int
vtmem_alloc_virtqueue(struct vtmem_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info;

	dev = sc->vtmem_dev;
	VQ_ALLOC_INFO_INIT(&vq_info, 0, vtmem_vq_intr, sc, &sc->vtmem_vq,
	    "%s request", device_get_nameunit(dev));
	return (virtio_alloc_virtqueues(dev, 1, &vq_info));
}

/*
 * Read a generation-consistent snapshot of device configuration space.  The
 * device may update requested_size and usable_region_size asynchronously, so
 * the read is retried until two successive generation counters agree.  Each
 * multi-byte field is read at its natural width; the modern transport converts
 * the little-endian wire value to guest-native byte order.
 */
static void
vtmem_read_config(struct vtmem_softc *sc, struct virtio_mem_config *cfg)
{
	device_t dev;
	int gen;

	dev = sc->vtmem_dev;
	do {
		gen = virtio_config_generation(dev);
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, block_size),
		    &cfg->block_size, sizeof(cfg->block_size));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, addr),
		    &cfg->addr, sizeof(cfg->addr));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, region_size),
		    &cfg->region_size, sizeof(cfg->region_size));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, usable_region_size),
		    &cfg->usable_region_size, sizeof(cfg->usable_region_size));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, plugged_size),
		    &cfg->plugged_size, sizeof(cfg->plugged_size));
		virtio_read_device_config(dev,
		    offsetof(struct virtio_mem_config, requested_size),
		    &cfg->requested_size, sizeof(cfg->requested_size));
	} while (gen != virtio_config_generation(dev));
}

static void
vtmem_vq_intr(void *xsc)
{
	struct vtmem_softc *sc;

	sc = xsc;
	VTMEM_LOCK(sc);
	wakeup(sc);
	VTMEM_UNLOCK(sc);
}

static bool
vtmem_block_get(const struct vtmem_softc *sc, uint32_t block)
{

	return ((sc->vtmem_bitmap[block / 8] & (1U << (block % 8))) != 0);
}

static void
vtmem_block_set(struct vtmem_softc *sc, uint32_t first, uint32_t count,
    bool plugged)
{
	uint32_t i;

	for (i = 0; i < count; i++) {
		if (plugged)
			sc->vtmem_bitmap[(first + i) / 8] |=
			    1U << ((first + i) % 8);
		else
			sc->vtmem_bitmap[(first + i) / 8] &=
			    ~(1U << ((first + i) % 8));
	}
}

/*
 * Issue one request on the request virtqueue and wait for its completion.
 * The worker thread is the only caller, so a single in-flight request pair is
 * sufficient.  Returns a VIRTIO_MEM_RESP_* code (>= 0) on a completed request,
 * or a negative errno on a transport-level failure.  A transport failure marks
 * the device failed; the caller must stop using it.
 */
static int
vtmem_send_request(struct vtmem_softc *sc, uint16_t type, uint64_t addr,
    uint16_t nb_blocks, uint16_t *statep)
{
	struct vtmem_request_io *io;
	struct sglist sg;
	struct sglist_seg segs[4];
	sbintime_t deadline, remaining;
	void *cookie;
	uint32_t len;
	int error, readable;

	io = sc->vtmem_io;
	memset(&io->request, 0, sizeof(io->request));
	io->request.type = htole16(type);
	io->request.addr = htole64(addr);
	io->request.nb_blocks = htole16(nb_blocks);
	memset(&io->response, 0, sizeof(io->response));
	io->response.type = htole16(VIRTIO_MEM_RESP_ERROR);

	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, &io->request, sizeof(io->request));
	if (error != 0)
		return (-error);
	readable = sg.sg_nseg;
	error = sglist_append_boundary(&sg, &io->response,
	    sizeof(io->response));
	if (error != 0)
		return (-error);
	KASSERT(sg.sg_nseg > readable,
	    ("vtmem: request and response collapsed into one descriptor"));
	if (sg.sg_nseg <= readable)
		return (-EFAULT);

	VTMEM_LOCK(sc);
	if ((sc->vtmem_flags & (VTMEM_F_DETACH | VTMEM_F_FAILED)) != 0) {
		VTMEM_UNLOCK(sc);
		return (-ENXIO);
	}
	error = virtqueue_enqueue(sc->vtmem_vq, &io->response, &sg, readable,
	    sg.sg_nseg - readable);
	if (error != 0) {
		VTMEM_UNLOCK(sc);
		return (-error);
	}
	virtqueue_notify(sc->vtmem_vq);

	deadline = sbinuptime() + VTMEM_REQUEST_TIMEOUT;
	while ((cookie = virtqueue_dequeue(sc->vtmem_vq, &len)) == NULL) {
		if ((sc->vtmem_flags & (VTMEM_F_DETACH | VTMEM_F_FAILED)) != 0) {
			VTMEM_UNLOCK(sc);
			return (-ENXIO);
		}
		/*
		 * The MSIX filter (virtqueue_intr_filter) disables this
		 * interrupt each time it schedules the wakeup handler.
		 * Re-arm before sleeping; a nonzero return means a completion
		 * raced the re-enable, so dequeue again instead of sleeping.
		 */
		if (virtqueue_enable_intr(sc->vtmem_vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = EWOULDBLOCK;
			break;
		}
		error = msleep_sbt(sc, &sc->vtmem_mtx, 0, "vtmemq", remaining,
		    0, 0);
		if (error != 0 && error != EWOULDBLOCK)
			break;
		error = 0;
	}
	VTMEM_UNLOCK(sc);

	/*
	 * A missing completion, an unexpected cookie, or a short response means
	 * the request/response storage can no longer be trusted to be idle.
	 * Fail the device so the buffers are not reused under the host.
	 */
	if (cookie == NULL || cookie != &io->response ||
	    len != sizeof(io->response)) {
		device_printf(sc->vtmem_dev,
		    "request type %u did not complete cleanly\n", type);
		VTMEM_LOCK(sc);
		vtmem_fail(sc);
		VTMEM_UNLOCK(sc);
		return (error != 0 ? -error : -EIO);
	}
	if (statep != NULL)
		*statep = le16toh(io->response.state);
	return (le16toh(io->response.type));
}

/*
 * Release every plugged block.  Used at startup to bring the device to a known
 * empty state before reconciliation begins, matching the state a fresh device
 * reports (plugged_size == 0).
 */
static int
vtmem_unplug_all(struct vtmem_softc *sc)
{
	int code;

	for (;;) {
		code = vtmem_send_request(sc, VIRTIO_MEM_REQ_UNPLUG_ALL, 0, 0,
		    NULL);
		if (code < 0)
			return (code);
		if (code != VIRTIO_MEM_RESP_BUSY)
			break;
		/*
		 * The device is temporarily unable to serve requests (the
		 * reference device answers BUSY while a snapshot restore is
		 * incomplete).  Back off and retry rather than failing the
		 * device; a detach or failure wakeup aborts the wait.
		 */
		VTMEM_LOCK(sc);
		if ((sc->vtmem_flags & (VTMEM_F_DETACH | VTMEM_F_FAILED)) !=
		    0) {
			VTMEM_UNLOCK(sc);
			return (-ENXIO);
		}
		msleep(sc, &sc->vtmem_mtx, 0, "vtmemba", VTMEM_RETRY_TIMEOUT);
		VTMEM_UNLOCK(sc);
	}
	if (code != VIRTIO_MEM_RESP_ACK) {
		device_printf(sc->vtmem_dev, "UNPLUG_ALL rejected (resp %d)\n",
		    code);
		return (-EIO);
	}
	if (sc->vtmem_plugged_blocks != 0)
		vtmem_offline_blocks(sc, 0, sc->vtmem_nblocks);
	memset(sc->vtmem_bitmap, 0, howmany(sc->vtmem_nblocks, 8));
	sc->vtmem_plugged_blocks = 0;
	return (0);
}

/*
 * Plug one contiguous run of currently-unplugged blocks, advancing plugged
 * size toward the target.  Returns 1 if progress was made, 0 if there is
 * nothing to do or the device asked us to back off, and a negative errno on a
 * fatal error.
 */
static int
vtmem_plug_one(struct vtmem_softc *sc)
{
	uint64_t addr;
	uint32_t first, run, usable_blocks;
	uint16_t state;
	int code;

	if (sc->vtmem_plugged_blocks >= sc->vtmem_target_blocks)
		return (0);
	usable_blocks =
	    (uint32_t)(sc->vtmem_usable_region_size / sc->vtmem_block_size);
	/*
	 * Defense in depth: never index the bitmap past its allocated block
	 * count even if a misbehaving device reports usable_region_size larger
	 * than region_size.  vtmem_sleep() already clamps the stored value, so
	 * this is a belt-and-suspenders bound on the loops below.
	 */
	if (usable_blocks > sc->vtmem_nblocks)
		usable_blocks = sc->vtmem_nblocks;

	/* Find the lowest unplugged block inside the usable sub-region. */
	for (first = 0; first < usable_blocks; first++) {
		if (!vtmem_block_get(sc, first))
			break;
	}
	if (first >= usable_blocks)
		return (0);

	/* Extend across a contiguous unplugged run, bounded by the target. */
	run = 1;
	while (first + run < usable_blocks &&
	    run < VTMEM_BLOCKS_PER_REQUEST &&
	    sc->vtmem_plugged_blocks + run < sc->vtmem_target_blocks &&
	    !vtmem_block_get(sc, first + run))
		run++;

	addr = sc->vtmem_addr + (uint64_t)first * sc->vtmem_block_size;
	code = vtmem_send_request(sc, VIRTIO_MEM_REQ_PLUG, addr,
	    (uint16_t)run, NULL);
	if (code < 0)
		return (code);

	switch (code) {
	case VIRTIO_MEM_RESP_ACK:
		vtmem_block_set(sc, first, run, true);
		sc->vtmem_plugged_blocks += run;
		vtmem_online_blocks(sc, first, run);
		return (1);
	case VIRTIO_MEM_RESP_NACK:
		/*
		 * The device declined the plug, typically because requested_size
		 * shrank between our snapshot and the request.  Back off and let
		 * the next reconciliation pass re-evaluate against fresh config.
		 */
		sc->vtmem_timeout = VTMEM_RETRY_TIMEOUT;
		return (0);
	case VIRTIO_MEM_RESP_BUSY:
		sc->vtmem_timeout = VTMEM_RETRY_TIMEOUT;
		return (0);
	default:
		/* Verify our bitmap view for diagnostics before failing. */
		if (vtmem_send_request(sc, VIRTIO_MEM_REQ_STATE, addr,
		    (uint16_t)run, &state) == VIRTIO_MEM_RESP_ACK) {
			device_printf(sc->vtmem_dev,
			    "PLUG error at block %u (device state %u)\n",
			    first, state);
		}
		return (-EIO);
	}
}

/*
 * Unplug one contiguous run of currently-plugged blocks, shrinking plugged
 * size toward the target.  Blocks are released from the high end of the
 * plugged region.  Return convention matches vtmem_plug_one().
 */
static int
vtmem_unplug_one(struct vtmem_softc *sc)
{
	uint64_t addr;
	uint32_t first, last, run;
	int code;

	if (sc->vtmem_plugged_blocks <= sc->vtmem_target_blocks)
		return (0);

	/* Find the highest plugged block. */
	if (sc->vtmem_nblocks == 0)
		return (0);
	for (last = sc->vtmem_nblocks; last-- > 0;) {
		if (vtmem_block_get(sc, last))
			break;
	}
	/* last wraps to UINT32_MAX when no plugged block was found. */
	if (last >= sc->vtmem_nblocks)
		return (0);

	/* Extend downward across a contiguous plugged run, bounded by target. */
	first = last;
	run = 1;
	while (first > 0 && run < VTMEM_BLOCKS_PER_REQUEST &&
	    sc->vtmem_plugged_blocks - run > sc->vtmem_target_blocks &&
	    vtmem_block_get(sc, first - 1)) {
		first--;
		run++;
	}

	addr = sc->vtmem_addr + (uint64_t)first * sc->vtmem_block_size;
	code = vtmem_send_request(sc, VIRTIO_MEM_REQ_UNPLUG, addr,
	    (uint16_t)run, NULL);
	if (code < 0)
		return (code);

	switch (code) {
	case VIRTIO_MEM_RESP_ACK:
		vtmem_offline_blocks(sc, first, run);
		vtmem_block_set(sc, first, run, false);
		sc->vtmem_plugged_blocks -= run;
		return (1);
	case VIRTIO_MEM_RESP_BUSY:
	case VIRTIO_MEM_RESP_NACK:
		sc->vtmem_timeout = VTMEM_RETRY_TIMEOUT;
		return (0);
	default:
		device_printf(sc->vtmem_dev, "UNPLUG error at block %u\n",
		    first);
		return (-EIO);
	}
}

/*
 * ONLINE SEAM.  See the file banner: FreeBSD has no supported runtime path to
 * add plugged physical pages to the kernel page allocator, so these routines
 * currently only account for the transition.  They are the single, isolated
 * point where a future runtime memory-add facility would be invoked, one
 * contiguous [first, first + count) block run at a time.
 */
static void
vtmem_online_blocks(struct vtmem_softc *sc __unused, uint32_t first __unused,
    uint32_t count __unused)
{

	/*
	 * A real online step would compute the guest-physical range
	 *   [addr + first * block_size, addr + (first + count) * block_size)
	 * and hand it to a runtime segment-add + page-free facility.  No such
	 * supported facility exists on FreeBSD today; do not fabricate one.
	 */
}

static void
vtmem_offline_blocks(struct vtmem_softc *sc __unused, uint32_t first __unused,
    uint32_t count __unused)
{

	/* Inverse of vtmem_online_blocks(); see that routine. */
}

static void
vtmem_fail(struct vtmem_softc *sc)
{

	VTMEM_LOCK_ASSERT(sc);
	sc->vtmem_flags |= VTMEM_F_FAILED;
	wakeup(sc);
}

/*
 * Block until there is reconciliation work to do, a retry timer expires, or
 * the device is torn down / failed.  On return, vtmem_target_blocks holds the
 * freshly computed target.  Returns non-zero when the worker should exit.
 */
static int
vtmem_sleep(struct vtmem_softc *sc)
{
	struct virtio_mem_config cfg;
	uint64_t usable, reqsz;
	uint32_t target;
	int rc, timeout;

	rc = 0;
	VTMEM_LOCK(sc);
	for (;;) {
		if ((sc->vtmem_flags & (VTMEM_F_DETACH | VTMEM_F_FAILED)) != 0) {
			rc = 1;
			break;
		}

		/*
		 * Recompute the target from a fresh, generation-consistent
		 * snapshot so a configuration change delivered as a spurious
		 * wakeup is always observed.
		 */
		vtmem_read_config(sc, &cfg);
		/*
		 * attach validated the immutable geometry, but the device may
		 * update usable_region_size and requested_size asynchronously
		 * and those fresh values are not otherwise re-validated.  A
		 * device that reports usable_region_size > region_size would
		 * push usable_blocks past the bitmap in vtmem_plug_one() (an
		 * out-of-bounds access), and requested_size > usable would make
		 * the target unreachable and spin the worker.  Clamp both to the
		 * invariants the rest of the driver assumes: usable <= region
		 * and the reconciliation target <= usable.
		 */
		usable = cfg.usable_region_size;
		if (usable > sc->vtmem_region_size)
			usable = sc->vtmem_region_size;
		sc->vtmem_usable_region_size = usable;
		sc->vtmem_requested_size = cfg.requested_size;
		if (vtmem_allow_plug) {
			reqsz = cfg.requested_size;
			if (reqsz > usable)
				reqsz = usable;
			target = (uint32_t)(reqsz / sc->vtmem_block_size);
			if (target > sc->vtmem_nblocks)
				target = sc->vtmem_nblocks;
		} else {
			/* Protocol-only: never plug memory we cannot online. */
			target = 0;
		}
		sc->vtmem_target_blocks = target;

		timeout = sc->vtmem_timeout;
		sc->vtmem_timeout = 0;

		if (sc->vtmem_plugged_blocks != target && timeout == 0)
			break;

		msleep(sc, &sc->vtmem_mtx, 0, "vtmem", timeout);
	}
	VTMEM_UNLOCK(sc);
	return (rc);
}

static void
vtmem_thread(void *xsc)
{
	struct vtmem_softc *sc;
	int result;

	sc = xsc;

	/*
	 * Bring the device to a known empty state before reconciling.  A
	 * transport failure here leaves the worker to exit through the loop
	 * below.
	 */
	if (vtmem_unplug_all(sc) < 0) {
		VTMEM_LOCK(sc);
		vtmem_fail(sc);
		VTMEM_UNLOCK(sc);
	}

	for (;;) {
		if (vtmem_sleep(sc) != 0)
			break;

		if (sc->vtmem_target_blocks > sc->vtmem_plugged_blocks)
			result = vtmem_plug_one(sc);
		else if (sc->vtmem_target_blocks < sc->vtmem_plugged_blocks)
			result = vtmem_unplug_one(sc);
		else
			result = 0;

		if (result < 0) {
			VTMEM_LOCK(sc);
			vtmem_fail(sc);
			VTMEM_UNLOCK(sc);
			break;
		}
	}

	/*
	 * Publish the exit under the lock and record it as a sticky predicate.
	 * The worker can self-terminate on a device/transport failure (via
	 * VTMEM_F_FAILED) long before detach runs; a bare one-shot wakeup would
	 * then be lost and the later join would sleep forever.  VTMEM_F_TD_EXITED
	 * lets the join observe an already-departed worker without sleeping.
	 */
	VTMEM_LOCK(sc);
	sc->vtmem_flags |= VTMEM_F_TD_EXITED;
	wakeup(sc->vtmem_td);
	VTMEM_UNLOCK(sc);
	kthread_exit();
}

static int
vtmem_sysctl_plugged(SYSCTL_HANDLER_ARGS)
{
	struct vtmem_softc *sc;
	uint64_t plugged;

	sc = arg1;
	plugged = (uint64_t)sc->vtmem_plugged_blocks * sc->vtmem_block_size;
	return (sysctl_handle_64(oidp, &plugged, 0, req));
}

static int
vtmem_sysctl_requested(SYSCTL_HANDLER_ARGS)
{
	struct vtmem_softc *sc;
	uint64_t requested;

	sc = arg1;
	requested = sc->vtmem_requested_size;
	return (sysctl_handle_64(oidp, &requested, 0, req));
}

static void
vtmem_setup_sysctl(struct vtmem_softc *sc)
{
	device_t dev;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	dev = sc->vtmem_dev;
	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "block_size", CTLFLAG_RD,
	    &sc->vtmem_block_size, 0, "Plug/unplug block size in bytes");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "region_size", CTLFLAG_RD,
	    &sc->vtmem_region_size, 0, "Device memory region size in bytes");
	SYSCTL_ADD_U64(ctx, child, OID_AUTO, "usable_region_size", CTLFLAG_RD,
	    &sc->vtmem_usable_region_size, 0,
	    "Currently usable sub-region size in bytes");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "requested_size",
	    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
	    vtmem_sysctl_requested, "QU",
	    "Size in bytes the device requests plugged");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "plugged_size",
	    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, sc, 0,
	    vtmem_sysctl_plugged, "QU",
	    "Size in bytes currently plugged (not onlined; see driver notes)");
	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "plugged_blocks", CTLFLAG_RD,
	    &sc->vtmem_plugged_blocks, 0, "Number of currently plugged blocks");
}
