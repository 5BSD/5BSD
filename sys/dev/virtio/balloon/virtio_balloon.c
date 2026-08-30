/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
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

/* Driver for VirtIO memory balloon devices. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/endian.h>
#include <sys/eventhandler.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/balloon/virtio_balloon.h>
#include <dev/virtio/balloon/virtio_balloon_var.h>

#include "virtio_if.h"

struct vtballoon_softc {
	device_t		 vtballoon_dev;
	struct mtx		 vtballoon_mtx;
	uint64_t		 vtballoon_features;
	uint32_t		 vtballoon_flags;
#define VTBALLOON_FLAG_DETACH	 0x01
#define VTBALLOON_FLAG_FAILED	 0x02
#define VTBALLOON_FLAG_LOWMEM	 0x04

	struct virtqueue	*vtballoon_inflate_vq;
	struct virtqueue	*vtballoon_deflate_vq;
	struct virtqueue	*vtballoon_stats_vq;
	struct virtqueue	*vtballoon_free_page_vq;

	uint32_t		 vtballoon_desired_npages;
	uint32_t		 vtballoon_current_npages;
	uint32_t		 vtballoon_poisoned_npages;
	TAILQ_HEAD(,vm_page)	 vtballoon_pages;

	struct thread		*vtballoon_td;
	eventhandler_tag	 vtballoon_lowmem_tag;
	bool			 vtballoon_lowmem_action;
	bool			 vtballoon_hint_pending;
	uint32_t		*vtballoon_page_frames;
	struct virtio_balloon_stat vtballoon_stats[3];
	int			 vtballoon_timeout;

	/*
	 * Free-page-hint state.  vtballoon_cmd_id_active is the command id of
	 * the last round the driver has completed (or is running); the host
	 * requests a new round by publishing a different id >= FIRST in the
	 * config space.  vtballoon_cmd_id_buf is the little-endian command
	 * buffer handed to the host and must outlive an in-flight request.
	 */
	uint32_t		 vtballoon_cmd_id_active;
	uint32_t		 vtballoon_pending_cmd_id;
	uint32_t		 vtballoon_cmd_id_buf;
	uint32_t		 vtballoon_free_page_reported;
};

static struct virtio_feature_desc vtballoon_feature_desc[] = {
	{ VIRTIO_BALLOON_F_MUST_TELL_HOST,	"MustTellHost"	},
	{ VIRTIO_BALLOON_F_STATS_VQ,		"StatsVq"	},
	{ VIRTIO_BALLOON_F_DEFLATE_ON_OOM,	"DeflateOnOOM"	},
	{ VIRTIO_BALLOON_F_FREE_PAGE_HINT,	"FreePageHint"	},
	{ VIRTIO_BALLOON_F_PAGE_POISON,		"PagePoison"	},

	{ 0, NULL }
};

static int	vtballoon_probe(device_t);
static int	vtballoon_attach(device_t);
static int	vtballoon_detach(device_t);
static int	vtballoon_config_change(device_t);

static int	vtballoon_negotiate_features(struct vtballoon_softc *);
static int	vtballoon_setup_features(struct vtballoon_softc *);
static int	vtballoon_alloc_virtqueues(struct vtballoon_softc *);
static int	vtballoon_enqueue_stats(struct vtballoon_softc *);

static void	vtballoon_vq_intr(void *);
static void	vtballoon_stats_vq_intr(void *);
static void	vtballoon_lowmem(void *, int);

static void	vtballoon_inflate(struct vtballoon_softc *, uint32_t);
static void	vtballoon_deflate(struct vtballoon_softc *, uint32_t);

static int	vtballoon_send_page_frames(struct vtballoon_softc *,
		    struct virtqueue *, int);

static uint32_t	vtballoon_read_cmd_id(struct vtballoon_softc *);
static bool	vtballoon_hint_pending(struct vtballoon_softc *, uint32_t *);
static int	vtballoon_free_page_hint_send(struct vtballoon_softc *,
		    struct sglist *, int, int);
static int	vtballoon_free_page_hint(struct vtballoon_softc *, uint32_t);

static void	vtballoon_pop(struct vtballoon_softc *);
static void	vtballoon_free_all_pages(struct vtballoon_softc *);
static void	vtballoon_stop(struct vtballoon_softc *);

static vm_page_t
		vtballoon_alloc_page(struct vtballoon_softc *);
static void	vtballoon_free_page(struct vtballoon_softc *, vm_page_t);

static int	vtballoon_sleep(struct vtballoon_softc *);
static void	vtballoon_thread(void *);
static void	vtballoon_setup_sysctl(struct vtballoon_softc *);

#define vtballoon_modern(_sc) \
    (((_sc)->vtballoon_features & VIRTIO_F_VERSION_1) != 0)

/*
 * Free-page reporting versus free-page hinting: what FreeBSD's VM can and
 * cannot support today.
 *
 * Both VirtIO features need the driver to enumerate the guest's free physical
 * pages and hand their ranges to the host.  Linux implements them on top of
 * buddy-allocator internals it does not export to drivers: FREE_PAGE_HINT walks
 * the free lists in place (walk_free_mem_block()), and PAGE_REPORTING isolates
 * free pages of a target order out of the free lists, reports them, and returns
 * them (mm/page_reporting.c, hooked to a free-page watermark).  FreeBSD's VM
 * exposes neither a free-list walk nor a free-page isolation/return hook to a
 * loadable driver; the only portable primitives are vm_page_alloc_noobj() and
 * vm_page_free(), which the balloon already uses.
 *
 * FREE_PAGE_HINT (implemented here) is host-request-driven and one-shot: the
 * host bumps free_page_hint_cmd_id in config, the guest reports a bounded set
 * of currently-free pages, then acknowledges.  The driver satisfies it safely
 * by allocating genuinely-free pages with vm_page_alloc_noobj() (which never
 * dips below the VM free reservation and returns NULL under pressure rather
 * than blocking), reporting their physical ranges, and freeing every page back
 * to the allocator once the host has drained the request.  This reports real
 * free pages without touching VM internals, at the cost of transiently owning
 * the reported pages; VTBALLOON_FREE_PAGE_HINT_MAX caps that transient
 * footprint.  It therefore reports a bounded sample, not necessarily all free
 * memory the way an in-place free-list walk would.
 *
 * PAGE_REPORTING is deliberately left unnegotiated (fail-closed).  It is a
 * continuous, watermark-driven optimization: to be both correct and useful it
 * needs an in-place free-page isolation/return path and a notification when
 * free memory of the reporting order accumulates.  Emulating that with a
 * polling alloc/report/free loop would churn the allocator continuously and
 * offers no watermark signal, so this driver does not advertise the bit and
 * never allocates the reporting virtqueue (host queue index 4).  Bridging this
 * cleanly requires new FreeBSD VM infrastructure, which is out of scope for the
 * driver.
 */

/* Features desired/implemented by this driver. */
#define VTBALLOON_FEATURES		(VIRTIO_BALLOON_F_MUST_TELL_HOST | \
					 VIRTIO_BALLOON_F_STATS_VQ | \
					 VIRTIO_BALLOON_F_DEFLATE_ON_OOM | \
					 VIRTIO_BALLOON_F_FREE_PAGE_HINT | \
					 VIRTIO_BALLOON_F_PAGE_POISON)

/*
 * Reserved free-page-hint command ids.  The host publishes a real command id
 * (>= 2) in free_page_hint_cmd_id to request a reporting round; the driver
 * answers with a start command carrying that id, a series of free-page ranges,
 * and a trailing stop command (id 0).  The host then advances the config id to
 * DONE (1).
 */
#define VTBALLOON_CMD_ID_STOP		0
#define VTBALLOON_CMD_ID_DONE		1

/* Free pages reported per free-page-hint request chain. */
#define VTBALLOON_HINT_BATCH		32

/*
 * Upper bound on the pages reported in a single free-page-hint round.  The
 * driver transiently owns every reported page until the round completes, so
 * this caps the transient allocation.  Reporting stops earlier when the VM
 * allocator runs dry (vm_page_alloc_noobj() returns NULL above the reserve).
 */
#define VTBALLOON_FREE_PAGE_HINT_MAX	16384

/* Timeout between retries when the balloon needs inflating. */
#define VTBALLOON_LOWMEM_TIMEOUT	hz

/* Bound a device which consumes a request but never returns its descriptor. */
#define VTBALLOON_REQUEST_TIMEOUT	(5 * SBT_1S)

/*
 * Maximum number of pages we'll request to inflate or deflate
 * the balloon in one virtqueue request. Both Linux and NetBSD
 * have settled on 256, doing up to 1MB at a time.
 */
#define VTBALLOON_PFNS_PER_PAGE		(PAGE_SIZE >> VIRTIO_BALLOON_PFN_SHIFT)
#define VTBALLOON_PFNS_PER_REQUEST	256
#define VTBALLOON_PAGES_PER_REQUEST	\
	(VTBALLOON_PFNS_PER_REQUEST / VTBALLOON_PFNS_PER_PAGE)

/* Every guest VM page is represented by one or more 4-KiB balloon PFNs. */
CTASSERT(PAGE_SIZE >= (1U << VIRTIO_BALLOON_PFN_SHIFT));
CTASSERT(PAGE_SIZE % (1U << VIRTIO_BALLOON_PFN_SHIFT) == 0);
CTASSERT(VTBALLOON_PFNS_PER_PAGE <= VTBALLOON_PFNS_PER_REQUEST);
CTASSERT(VTBALLOON_PFNS_PER_REQUEST % VTBALLOON_PFNS_PER_PAGE == 0);
CTASSERT(VTBALLOON_PFNS_PER_REQUEST * sizeof(uint32_t) <= PAGE_SIZE);

#define VTBALLOON_MTX(_sc)		&(_sc)->vtballoon_mtx
#define VTBALLOON_LOCK_INIT(_sc, _name)	mtx_init(VTBALLOON_MTX((_sc)), _name, \
					    "VirtIO Balloon Lock", MTX_DEF)
#define VTBALLOON_LOCK(_sc)		mtx_lock(VTBALLOON_MTX((_sc)))
#define VTBALLOON_UNLOCK(_sc)		mtx_unlock(VTBALLOON_MTX((_sc)))
#define VTBALLOON_LOCK_DESTROY(_sc)	mtx_destroy(VTBALLOON_MTX((_sc)))

static device_method_t vtballoon_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtballoon_probe),
	DEVMETHOD(device_attach,	vtballoon_attach),
	DEVMETHOD(device_detach,	vtballoon_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_config_change, vtballoon_config_change),

	DEVMETHOD_END
};

static driver_t vtballoon_driver = {
	"vtballoon",
	vtballoon_methods,
	sizeof(struct vtballoon_softc)
};

VIRTIO_DRIVER_MODULE(virtio_balloon, vtballoon_driver, 0, 0);
MODULE_VERSION(virtio_balloon, 1);
MODULE_DEPEND(virtio_balloon, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_balloon, VIRTIO_ID_BALLOON,
    "VirtIO Balloon Adapter");

static int
vtballoon_probe(device_t dev)
{
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_balloon));
}

static int
vtballoon_attach(device_t dev)
{
	struct vtballoon_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtballoon_dev = dev;
	virtio_set_feature_desc(dev, vtballoon_feature_desc);

	VTBALLOON_LOCK_INIT(sc, device_get_nameunit(dev));
	TAILQ_INIT(&sc->vtballoon_pages);

	vtballoon_setup_sysctl(sc);

	error = vtballoon_setup_features(sc);
	if (error) {
		device_printf(dev, "cannot setup features\n");
		goto fail;
	}
	if ((sc->vtballoon_features & VIRTIO_BALLOON_F_PAGE_POISON) != 0) {
		/*
		 * Zero is a valid poison value and is portable across guest byte
		 * order.  Publish it before attach returns and the VirtIO bus sets
		 * DRIVER_OK, as required by VirtIO 1.4 section 5.5.6.6.1.
		 */
		virtio_write_dev_config_4(dev,
		    offsetof(struct virtio_balloon_config, poison_val), 0);
	}

	sc->vtballoon_page_frames = malloc(VTBALLOON_PFNS_PER_REQUEST *
	    sizeof(uint32_t), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (sc->vtballoon_page_frames == NULL) {
		error = ENOMEM;
		device_printf(dev,
		    "cannot allocate page frame request array\n");
		goto fail;
	}

	error = vtballoon_alloc_virtqueues(sc);
	if (error) {
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error) {
		device_printf(dev, "cannot setup virtqueue interrupts\n");
		goto fail;
	}

	if (sc->vtballoon_stats_vq != NULL) {
		error = vtballoon_enqueue_stats(sc);
		if (error) {
			device_printf(dev,
			    "cannot initialize statistics virtqueue: %d\n",
			    error);
			goto fail;
		}
	}

	/*
	 * Adopt the host's initial free-page-hint command id as already handled
	 * before starting the balloon thread.  The thread is created here but the
	 * free-page-hint queue interrupt is only enabled below, so a round must
	 * not run for the reset-time standing id: latching it now leaves the
	 * driver idle until a genuine post-attach host request bumps the id via a
	 * configuration-change interrupt, by which point the queue is live.
	 */
	if (sc->vtballoon_free_page_vq != NULL)
		sc->vtballoon_cmd_id_active = vtballoon_read_cmd_id(sc);

	error = kthread_add(vtballoon_thread, sc, NULL, &sc->vtballoon_td,
	    0, 0, "virtio_balloon");
	if (error) {
		device_printf(dev, "cannot create balloon kthread\n");
		goto fail;
	}
	if ((sc->vtballoon_features &
	    VIRTIO_BALLOON_F_DEFLATE_ON_OOM) != 0) {
		sc->vtballoon_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
		    vtballoon_lowmem, sc, LOWMEM_PRI_DEFAULT);
		if (sc->vtballoon_lowmem_tag == NULL) {
			error = ENOMEM;
			device_printf(dev,
			    "cannot register low-memory handler\n");
			goto fail;
		}
	}

	virtqueue_enable_intr(sc->vtballoon_inflate_vq);
	virtqueue_enable_intr(sc->vtballoon_deflate_vq);
	if (sc->vtballoon_stats_vq != NULL)
		virtqueue_enable_intr(sc->vtballoon_stats_vq);
	if (sc->vtballoon_free_page_vq != NULL)
		virtqueue_enable_intr(sc->vtballoon_free_page_vq);

fail:
	if (error)
		vtballoon_detach(dev);

	return (error);
}

static int
vtballoon_detach(device_t dev)
{
	struct vtballoon_softc *sc;

	sc = device_get_softc(dev);

	if (sc->vtballoon_lowmem_tag != NULL) {
		EVENTHANDLER_DEREGISTER(vm_lowmem,
		    sc->vtballoon_lowmem_tag);
		sc->vtballoon_lowmem_tag = NULL;
	}
	if (sc->vtballoon_td != NULL) {
		VTBALLOON_LOCK(sc);
		sc->vtballoon_flags |= VTBALLOON_FLAG_DETACH;
		wakeup_one(sc);
		msleep(sc->vtballoon_td, VTBALLOON_MTX(sc), 0, "vtbdth", 0);
		VTBALLOON_UNLOCK(sc);

		sc->vtballoon_td = NULL;
	}

	/*
	 * Deflate the balloon back to the host only for a fully attached,
	 * non-failed device: vtballoon_pop() submits deflate requests, which
	 * requires a live DRIVER_OK device with allocated queues.
	 */
	if (device_is_attached(dev) &&
	    (sc->vtballoon_flags & VTBALLOON_FLAG_FAILED) == 0)
		vtballoon_pop(sc);

	/*
	 * Reset the device unconditionally before tearing down interrupts and
	 * freeing host-visible memory.  This also runs on the attach-failure
	 * unwind (attach calls vtballoon_detach on error), where
	 * device_is_attached() is still false because newbus sets DF_ATTACHED
	 * only after attach returns 0.  A statistics buffer embedded in the softc
	 * may already be posted to the device (vtballoon_enqueue_stats() runs
	 * during attach); gating the reset on device_is_attached() would free it
	 * under the device -- a DMA-after-free.  virtio_stop() is safe even if no
	 * virtqueue was ever allocated, and vtballoon_free_all_pages() is a no-op
	 * once vtballoon_pop() has already emptied the page list.
	 */
	virtio_stop(dev);
	vtballoon_free_all_pages(sc);

	virtio_teardown_intr(dev);

	if (sc->vtballoon_page_frames != NULL) {
		free(sc->vtballoon_page_frames, M_DEVBUF);
		sc->vtballoon_page_frames = NULL;
	}

	VTBALLOON_LOCK_DESTROY(sc);

	return (0);
}

static int
vtballoon_config_change(device_t dev)
{
	struct vtballoon_softc *sc;

	sc = device_get_softc(dev);

	VTBALLOON_LOCK(sc);
	wakeup_one(sc);
	VTBALLOON_UNLOCK(sc);

	return (1);
}

static void
vtballoon_lowmem(void *arg, int flags)
{
	struct vtballoon_softc *sc;

	if ((flags & VM_LOW_PAGES) == 0)
		return;
	sc = arg;
	VTBALLOON_LOCK(sc);
	if ((sc->vtballoon_flags &
	    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) == 0) {
		/*
		 * Event handlers cannot wait for a virtqueue completion.
		 * Coalesce pressure notifications and let the balloon thread
		 * return one bounded request worth of pages.
		 */
		sc->vtballoon_flags |= VTBALLOON_FLAG_LOWMEM;
		wakeup_one(sc);
	}
	VTBALLOON_UNLOCK(sc);
}

static int
vtballoon_negotiate_features(struct vtballoon_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtballoon_dev;
	features = VTBALLOON_FEATURES;

	sc->vtballoon_features = virtio_negotiate_features(dev, features);
	return (virtio_finalize_features(dev));
}

static int
vtballoon_setup_features(struct vtballoon_softc *sc)
{
	int error;

	error = vtballoon_negotiate_features(sc);
	if (error)
		return (error);

	return (0);
}

static int
vtballoon_alloc_virtqueues(struct vtballoon_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info[4];
	int nvqs;
	bool stats;

	dev = sc->vtballoon_dev;
	nvqs = 2;

	VQ_ALLOC_INFO_INIT(&vq_info[0], 0, vtballoon_vq_intr, sc,
	    &sc->vtballoon_inflate_vq, "%s inflate", device_get_nameunit(dev));

	VQ_ALLOC_INFO_INIT(&vq_info[1], 0, vtballoon_vq_intr, sc,
	    &sc->vtballoon_deflate_vq, "%s deflate", device_get_nameunit(dev));

	stats = (sc->vtballoon_features & VIRTIO_BALLOON_F_STATS_VQ) != 0;
	if (stats) {
		VQ_ALLOC_INFO_INIT(&vq_info[2], 0, vtballoon_stats_vq_intr, sc,
		    &sc->vtballoon_stats_vq, "%s statistics",
		    device_get_nameunit(dev));
		nvqs++;
	}

	/*
	 * The free-page-hint queue is spec index 3, so allocating it requires
	 * the statistics queue (index 2) to exist as well.  FreeBSD's VirtIO
	 * PCI transport allocates queues 0..nvqs-1 contiguously and rejects a
	 * zero-sized intervening queue, so when the host offers the hint
	 * feature without the statistics queue the driver cannot open queue 3
	 * and leaves the negotiated feature idle rather than misallocating.
	 */
	if ((sc->vtballoon_features & VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0) {
		if (stats) {
			VQ_ALLOC_INFO_INIT(&vq_info[3], 0, vtballoon_vq_intr, sc,
			    &sc->vtballoon_free_page_vq, "%s free-page-hint",
			    device_get_nameunit(dev));
			nvqs++;
		} else {
			device_printf(dev, "free-page-hint queue needs the "
			    "statistics queue; leaving the feature idle\n");
		}
	}

	return (virtio_alloc_virtqueues(dev, nvqs, vq_info));
}

static int
vtballoon_enqueue_stats(struct vtballoon_softc *sc)
{
	struct sglist sg;
	struct sglist_seg segs[2];
	uint64_t free_bytes, swap_pages, swap_bytes, total_bytes;
	bool modern;
	int error;

	modern = vtballoon_modern(sc);
	free_bytes = (uint64_t)vm_free_count() * PAGE_SIZE;
	total_bytes = (uint64_t)vm_cnt.v_page_count * PAGE_SIZE;
	swap_pages = VM_CNT_FETCH(v_swappgsin);
	if (swap_pages > UINT64_MAX / PAGE_SIZE)
		swap_bytes = UINT64_MAX;
	else
		swap_bytes = swap_pages * PAGE_SIZE;

	sc->vtballoon_stats[0].tag =
	    virtio_htog16(modern, VIRTIO_BALLOON_S_SWAP_IN);
	sc->vtballoon_stats[0].val = virtio_htog64(modern, swap_bytes);
	sc->vtballoon_stats[1].tag =
	    virtio_htog16(modern, VIRTIO_BALLOON_S_MEMFREE);
	sc->vtballoon_stats[1].val = virtio_htog64(modern, free_bytes);
	sc->vtballoon_stats[2].tag =
	    virtio_htog16(modern, VIRTIO_BALLOON_S_MEMTOT);
	sc->vtballoon_stats[2].val = virtio_htog64(modern, total_bytes);

	/*
	 * The fixed statistics buffer is small, but it is embedded in the
	 * softc and may straddle a physical-page boundary.  Permit both
	 * possible physical segments instead of assuming contiguity.
	 */
	sglist_init(&sg, nitems(segs), segs);
	error = sglist_append(&sg, sc->vtballoon_stats,
	    sizeof(sc->vtballoon_stats));
	if (error != 0)
		return (error);

	error = virtqueue_enqueue(sc->vtballoon_stats_vq, sc, &sg,
	    sg.sg_nseg, 0);
	if (error == 0)
		virtqueue_notify(sc->vtballoon_stats_vq);

	return (error);
}

static void
vtballoon_vq_intr(void *xsc)
{
	struct vtballoon_softc *sc;

	sc = xsc;

	VTBALLOON_LOCK(sc);
	wakeup_one(sc);
	VTBALLOON_UNLOCK(sc);
}

static void
vtballoon_stats_vq_intr(void *xsc)
{
	struct vtballoon_softc *sc;
	void *cookie;
	int error;

	sc = xsc;

	VTBALLOON_LOCK(sc);
again:
	cookie = virtqueue_dequeue(sc->vtballoon_stats_vq, NULL);
	if (cookie == sc &&
	    (sc->vtballoon_flags &
	    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) == 0) {
		error = vtballoon_enqueue_stats(sc);
		if (error != 0) {
			device_printf(sc->vtballoon_dev,
			    "cannot refresh statistics virtqueue: %d\n", error);
			/*
			 * Once the device has returned the sole statistics buffer,
			 * losing the replacement would permanently stop a negotiated
			 * queue.  Let the worker perform a full reset outside this
			 * interrupt callback instead of silently degrading the device.
			 */
			sc->vtballoon_flags |= VTBALLOON_FLAG_FAILED;
			wakeup_one(sc);
		}
	} else if (cookie != NULL && cookie != sc) {
		device_printf(sc->vtballoon_dev,
		    "unexpected statistics virtqueue response\n");
		sc->vtballoon_flags |= VTBALLOON_FLAG_FAILED;
		wakeup_one(sc);
	}
	/*
	 * The MSIX filter disabled this interrupt before scheduling us;
	 * re-arm it so the host's next statistics request is seen, and
	 * drain any completion that raced the re-enable.
	 */
	if ((sc->vtballoon_flags &
	    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) == 0 &&
	    virtqueue_enable_intr(sc->vtballoon_stats_vq) != 0) {
		virtqueue_disable_intr(sc->vtballoon_stats_vq);
		goto again;
	}
	VTBALLOON_UNLOCK(sc);
}

static void
vtballoon_inflate(struct vtballoon_softc *sc, uint32_t npages)
{
	struct virtqueue *vq;
	vm_page_t m;
	uint32_t base;
	int error, i, j;

	vq = sc->vtballoon_inflate_vq;

	npages = MIN(npages / VTBALLOON_PFNS_PER_PAGE,
	    VTBALLOON_PAGES_PER_REQUEST);

	for (i = 0; i < npages; i++) {
		if ((m = vtballoon_alloc_page(sc)) == NULL) {
			sc->vtballoon_timeout = VTBALLOON_LOWMEM_TIMEOUT;
			break;
		}

		error = virtio_balloon_encode_pfn(VM_PAGE_TO_PHYS(m),
		    VTBALLOON_PFNS_PER_PAGE, &base);
		if (error != 0) {
			vtballoon_free_page(sc, m);
			sc->vtballoon_timeout = VTBALLOON_LOWMEM_TIMEOUT;
			break;
		}
		for (j = 0; j < VTBALLOON_PFNS_PER_PAGE; j++) {
			sc->vtballoon_page_frames[i * VTBALLOON_PFNS_PER_PAGE + j] =
			    virtio_htog32(vtballoon_modern(sc), base + j);
		}

		KASSERT(m->a.queue == PQ_NONE,
		    ("%s: allocated page %p on queue", __func__, m));
		TAILQ_INSERT_TAIL(&sc->vtballoon_pages, m, plinks.q);
	}

	if (i > 0) {
		error = vtballoon_send_page_frames(sc, vq,
		    i * VTBALLOON_PFNS_PER_PAGE);
		if (error != 0)
			vtballoon_free_all_pages(sc);
	}
}

static void
vtballoon_deflate(struct vtballoon_softc *sc, uint32_t npages)
{
	TAILQ_HEAD(, vm_page) free_pages;
	struct virtqueue *vq;
	vm_page_t m;
	uint32_t base;
	int error, i, j;

	vq = sc->vtballoon_deflate_vq;
	TAILQ_INIT(&free_pages);

	npages = MIN(npages / VTBALLOON_PFNS_PER_PAGE,
	    VTBALLOON_PAGES_PER_REQUEST);

	for (i = 0; i < npages; i++) {
		m = TAILQ_FIRST(&sc->vtballoon_pages);
		KASSERT(m != NULL, ("%s: no more pages to deflate", __func__));

		error = virtio_balloon_encode_pfn(VM_PAGE_TO_PHYS(m),
		    VTBALLOON_PFNS_PER_PAGE, &base);
		if (__predict_false(error != 0)) {
			/*
			 * Only pages admitted by vtballoon_inflate() can be on this
			 * list.  Fail closed if that invariant is ever violated rather
			 * than narrowing a physical address into a different PFN.
			 */
			TAILQ_CONCAT(&sc->vtballoon_pages, &free_pages, plinks.q);
			VTBALLOON_LOCK(sc);
			sc->vtballoon_flags |= VTBALLOON_FLAG_FAILED;
			wakeup(sc);
			VTBALLOON_UNLOCK(sc);
			vtballoon_stop(sc);
			vtballoon_free_all_pages(sc);
			return;
		}
		for (j = 0; j < VTBALLOON_PFNS_PER_PAGE; j++) {
			sc->vtballoon_page_frames[i * VTBALLOON_PFNS_PER_PAGE + j] =
			    virtio_htog32(vtballoon_modern(sc), base + j);
		}

		TAILQ_REMOVE(&sc->vtballoon_pages, m, plinks.q);
		TAILQ_INSERT_TAIL(&free_pages, m, plinks.q);
	}

	if (i > 0) {
		/* Always tell host first before freeing the pages. */
		if (vtballoon_send_page_frames(sc, vq,
		    i * VTBALLOON_PFNS_PER_PAGE) != 0) {
			/*
			 * A full reset releases all host-side ranges.  Return
			 * both this detached batch and every remaining page.
			 */
			while ((m = TAILQ_FIRST(&free_pages)) != NULL) {
				TAILQ_REMOVE(&free_pages, m, plinks.q);
				vtballoon_free_page(sc, m);
			}
			vtballoon_free_all_pages(sc);
			return;
		}

		while ((m = TAILQ_FIRST(&free_pages)) != NULL) {
			TAILQ_REMOVE(&free_pages, m, plinks.q);
			if ((sc->vtballoon_features &
			    VIRTIO_BALLOON_F_PAGE_POISON) != 0) {
				/*
				 * The deflate descriptor is acknowledged, so the guest may
				 * now reuse this page.  Initialize it to the advertised
				 * poison value before returning it to the VM allocator.
				 * VIRTIO_ACTIVATION_ASSERTION:
				 * acknowledged-deflate-page-initialization
				 */
				pmap_zero_page(m);
				if (sc->vtballoon_poisoned_npages != UINT32_MAX)
					sc->vtballoon_poisoned_npages++;
			}
			vtballoon_free_page(sc, m);
		}
	}

	KASSERT((TAILQ_EMPTY(&sc->vtballoon_pages) &&
	    sc->vtballoon_current_npages == 0) ||
	    (!TAILQ_EMPTY(&sc->vtballoon_pages) &&
	    sc->vtballoon_current_npages != 0),
	    ("%s: bogus page count %d", __func__,
	    sc->vtballoon_current_npages));
}

static int
vtballoon_send_page_frames(struct vtballoon_softc *sc, struct virtqueue *vq,
    int npages)
{
	struct sglist sg;
	struct sglist_seg segs[1];
	sbintime_t deadline, remaining;
	void *c;
	int error;

	sglist_init(&sg, 1, segs);

	error = sglist_append(&sg, sc->vtballoon_page_frames,
	    npages * sizeof(uint32_t));
	if (error != 0)
		goto fail;

	error = virtqueue_enqueue(vq, vq, &sg, 1, 0);
	if (error != 0)
		goto fail;
	virtqueue_notify(vq);

	/*
	 * Inflate and deflate operations are done synchronously. The
	 * interrupt handler will wake us up.
	 */
	VTBALLOON_LOCK(sc);
	deadline = sbinuptime() + VTBALLOON_REQUEST_TIMEOUT;
	while ((c = virtqueue_dequeue(vq, NULL)) == NULL) {
		if ((sc->vtballoon_flags &
		    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) != 0) {
			error = ECANCELED;
			break;
		}
		/*
		 * The MSIX filter (virtqueue_intr_filter) disables this
		 * interrupt each time it schedules the wakeup handler.
		 * Re-arm before sleeping; a nonzero return means a completion
		 * raced the re-enable, so dequeue again instead of sleeping.
		 */
		if (virtqueue_enable_intr(vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = EWOULDBLOCK;
		} else {
			error = msleep_sbt(sc, VTBALLOON_MTX(sc), 0, "vtbspf",
			    remaining, 0, 0);
		}
		if (error != 0)
			break;
	}
	VTBALLOON_UNLOCK(sc);

	error = virtio_balloon_request_result(c != NULL, c == vq, error);
	if (error == 0)
		return (0);

fail:
	device_printf(sc->vtballoon_dev,
	    "balloon request failed: %d; resetting device\n", error);
	VTBALLOON_LOCK(sc);
	sc->vtballoon_flags |= VTBALLOON_FLAG_FAILED;
	wakeup(sc);
	VTBALLOON_UNLOCK(sc);
	/*
	 * The request buffer and PFNs must remain valid until ownership is
	 * revoked.  Full reset is the protocol boundary that releases every
	 * host-side balloon range before callers return pages to the VM.
	 * VIRTIO_ACTIVATION_ASSERTION: bounded-balloon-request-failure
	 */
	vtballoon_stop(sc);
	return (error);
}

static uint32_t
vtballoon_read_cmd_id(struct vtballoon_softc *sc)
{
	uint32_t cmd_id;

	cmd_id = virtio_read_dev_config_4(sc->vtballoon_dev,
	    offsetof(struct virtio_balloon_config, free_page_hint_cmd_id));
	if (!vtballoon_modern(sc))
		cmd_id = le32toh(cmd_id);
	return (cmd_id);
}

/*
 * Determine whether the host is requesting a new free-page-hint round.  The
 * host publishes a command id >= FIRST to ask for a report and advances it to
 * DONE once a round completes, so a round is due only when the config id
 * differs from the last one the driver acted on and is not the reserved DONE
 * sentinel.  This is a pure config read and may run in the balloon thread's
 * sleep path without taking a virtqueue.
 */
static bool
vtballoon_hint_pending(struct vtballoon_softc *sc, uint32_t *cmd_id)
{
	uint32_t received;

	if (sc->vtballoon_free_page_vq == NULL)
		return (false);
	received = vtballoon_read_cmd_id(sc);
	if (received == sc->vtballoon_cmd_id_active ||
	    received == VTBALLOON_CMD_ID_DONE)
		return (false);
	*cmd_id = received;
	return (true);
}

/*
 * Submit one free-page-hint chain and wait for the host to return it.  Command
 * chains are device-readable (readable != 0); free-page range chains are
 * device-writable (writable != 0).  Each chain is completed synchronously, so
 * the queue is empty before the next chain and the whole ring is available.
 */
static int
vtballoon_free_page_hint_send(struct vtballoon_softc *sc, struct sglist *sg,
    int readable, int writable)
{
	struct virtqueue *vq;
	sbintime_t deadline, remaining;
	void *c;
	int error;

	vq = sc->vtballoon_free_page_vq;

	error = virtqueue_enqueue(vq, vq, sg, readable, writable);
	if (error != 0)
		goto fail;
	virtqueue_notify(vq);

	VTBALLOON_LOCK(sc);
	deadline = sbinuptime() + VTBALLOON_REQUEST_TIMEOUT;
	while ((c = virtqueue_dequeue(vq, NULL)) == NULL) {
		if ((sc->vtballoon_flags &
		    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) != 0) {
			error = ECANCELED;
			break;
		}
		/* See vtballoon_send_page_frames: re-arm the filtered intr. */
		if (virtqueue_enable_intr(vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = EWOULDBLOCK;
		} else {
			error = msleep_sbt(sc, VTBALLOON_MTX(sc), 0, "vtbfph",
			    remaining, 0, 0);
		}
		if (error != 0)
			break;
	}
	VTBALLOON_UNLOCK(sc);

	error = virtio_balloon_request_result(c != NULL, c == vq, error);
	if (error == 0)
		return (0);

fail:
	device_printf(sc->vtballoon_dev,
	    "free-page-hint request failed: %d; resetting device\n", error);
	VTBALLOON_LOCK(sc);
	sc->vtballoon_flags |= VTBALLOON_FLAG_FAILED;
	wakeup(sc);
	VTBALLOON_UNLOCK(sc);
	/*
	 * As with inflate/deflate, a full device reset is the protocol boundary
	 * that revokes every outstanding host-side range before the caller
	 * returns the reported pages to the VM allocator.
	 */
	vtballoon_stop(sc);
	return (error);
}

/*
 * Run one host-requested free-page-hint round: report a bounded set of
 * currently-free guest pages and acknowledge completion.  Pages are allocated
 * from the VM free pool (so they are genuinely free at report time), streamed
 * to the host in device-writable range chains, held until the round finishes,
 * then returned to the allocator.  See the design note above VTBALLOON_FEATURES
 * for why this is the tractable half of the two free-page features.
 */
static int
vtballoon_free_page_hint(struct vtballoon_softc *sc, uint32_t cmd_id)
{
	TAILQ_HEAD(, vm_page) hint_pages;
	struct sglist cmd_sg, page_sg;
	struct sglist_seg cmd_seg[1];
	struct sglist_seg page_segs[VTBALLOON_HINT_BATCH];
	vm_page_t m;
	uint32_t reported;
	int error, n;
	bool exhausted;

	TAILQ_INIT(&hint_pages);

	/* Announce the start of the round with the host's command id. */
	sc->vtballoon_cmd_id_buf = virtio_htog32(vtballoon_modern(sc), cmd_id);
	sglist_init(&cmd_sg, nitems(cmd_seg), cmd_seg);
	error = sglist_append(&cmd_sg, &sc->vtballoon_cmd_id_buf,
	    sizeof(sc->vtballoon_cmd_id_buf));
	if (error != 0)
		return (error);
	error = vtballoon_free_page_hint_send(sc, &cmd_sg, 1, 0);
	if (error != 0)
		return (error);

	exhausted = false;
	for (reported = 0; !exhausted && reported < VTBALLOON_FREE_PAGE_HINT_MAX;
	    reported += (uint32_t)n) {
		sglist_init(&page_sg, nitems(page_segs), page_segs);
		for (n = 0; reported + (uint32_t)n < VTBALLOON_FREE_PAGE_HINT_MAX;
		    n++) {
			m = vm_page_alloc_noobj(VM_ALLOC_NODUMP);
			if (m == NULL) {
				/* The free pool is down to its reserve. */
				exhausted = true;
				break;
			}
			KASSERT(m->a.queue == PQ_NONE,
			    ("%s: allocated page %p on queue", __func__, m));
			if (sglist_append_phys(&page_sg, VM_PAGE_TO_PHYS(m),
			    PAGE_SIZE) != 0) {
				/* This chain is full; report m in the next one. */
				vm_page_free(m);
				break;
			}
			TAILQ_INSERT_TAIL(&hint_pages, m, plinks.q);
		}
		if (n == 0)
			break;
		error = vtballoon_free_page_hint_send(sc, &page_sg, 0,
		    page_sg.sg_nseg);
		if (error != 0)
			goto out;
	}

	/* Announce completion so the host advances the config id to DONE. */
	sc->vtballoon_cmd_id_buf = virtio_htog32(vtballoon_modern(sc),
	    VTBALLOON_CMD_ID_STOP);
	sglist_init(&cmd_sg, nitems(cmd_seg), cmd_seg);
	error = sglist_append(&cmd_sg, &sc->vtballoon_cmd_id_buf,
	    sizeof(sc->vtballoon_cmd_id_buf));
	if (error == 0)
		error = vtballoon_free_page_hint_send(sc, &cmd_sg, 1, 0);
	if (error == 0)
		sc->vtballoon_free_page_reported = reported;

out:
	/*
	 * The host has drained (or a reset has revoked) every reported range, so
	 * the reported pages may return to the VM allocator.  These pages were
	 * never balloon-owned, so the inflate/deflate accounting is untouched.
	 */
	while ((m = TAILQ_FIRST(&hint_pages)) != NULL) {
		TAILQ_REMOVE(&hint_pages, m, plinks.q);
		vm_page_free(m);
	}
	return (error);
}

static void
vtballoon_pop(struct vtballoon_softc *sc)
{

	while (!TAILQ_EMPTY(&sc->vtballoon_pages) &&
	    (sc->vtballoon_flags & VTBALLOON_FLAG_FAILED) == 0)
		vtballoon_deflate(sc, sc->vtballoon_current_npages);
}

static void
vtballoon_free_all_pages(struct vtballoon_softc *sc)
{
	vm_page_t m;

	while ((m = TAILQ_FIRST(&sc->vtballoon_pages)) != NULL) {
		TAILQ_REMOVE(&sc->vtballoon_pages, m, plinks.q);
		vtballoon_free_page(sc, m);
	}
}

static void
vtballoon_stop(struct vtballoon_softc *sc)
{

	virtqueue_disable_intr(sc->vtballoon_inflate_vq);
	virtqueue_disable_intr(sc->vtballoon_deflate_vq);
	if (sc->vtballoon_stats_vq != NULL)
		virtqueue_disable_intr(sc->vtballoon_stats_vq);
	if (sc->vtballoon_free_page_vq != NULL)
		virtqueue_disable_intr(sc->vtballoon_free_page_vq);

	virtio_stop(sc->vtballoon_dev);
}

static vm_page_t
vtballoon_alloc_page(struct vtballoon_softc *sc)
{
	vm_page_t m;

	m = vm_page_alloc_noobj(VM_ALLOC_NODUMP);
	if (m != NULL)
		sc->vtballoon_current_npages += VTBALLOON_PFNS_PER_PAGE;

	return (m);
}

static void
vtballoon_free_page(struct vtballoon_softc *sc, vm_page_t m)
{

	vm_page_free(m);
	sc->vtballoon_current_npages -= VTBALLOON_PFNS_PER_PAGE;
}

static uint32_t
vtballoon_desired_size(struct vtballoon_softc *sc)
{
	uint32_t desired;

	desired = virtio_read_dev_config_4(sc->vtballoon_dev,
	    offsetof(struct virtio_balloon_config, num_pages));

	if (!vtballoon_modern(sc))
		desired = le32toh(desired);
	return (virtio_balloon_align_target(desired,
	    VTBALLOON_PFNS_PER_PAGE));
}

static void
vtballoon_update_size(struct vtballoon_softc *sc)
{
	uint32_t npages;

	npages = sc->vtballoon_current_npages;
	if (!vtballoon_modern(sc))
		npages = htole32(npages);

	virtio_write_dev_config_4(sc->vtballoon_dev,
	    offsetof(struct virtio_balloon_config, actual), npages);
}

static int
vtballoon_sleep(struct vtballoon_softc *sc)
{
	int rc, timeout;
	uint32_t current, desired;

	rc = 0;
	current = sc->vtballoon_current_npages;

	VTBALLOON_LOCK(sc);
	for (;;) {
		if ((sc->vtballoon_flags &
		    (VTBALLOON_FLAG_DETACH | VTBALLOON_FLAG_FAILED)) != 0) {
			rc = 1;
			break;
		}
		/*
		 * A pending host request for a free-page-hint round takes
		 * priority over resizing so migration hinting is not delayed by
		 * the resize timeout.  The round itself sleeps on the queue and
		 * must run in thread context, so only latch it here.
		 */
		if (vtballoon_hint_pending(sc, &sc->vtballoon_pending_cmd_id)) {
			sc->vtballoon_hint_pending = true;
			break;
		}
		if ((sc->vtballoon_flags & VTBALLOON_FLAG_LOWMEM) != 0) {
			sc->vtballoon_flags &= ~VTBALLOON_FLAG_LOWMEM;
			if (current != 0) {
				sc->vtballoon_desired_npages =
				    virtio_balloon_lowmem_target(current,
				    VTBALLOON_PFNS_PER_REQUEST);
				sc->vtballoon_lowmem_action = true;
				break;
			}
		}

		desired = vtballoon_desired_size(sc);
		sc->vtballoon_desired_npages = desired;
		sc->vtballoon_lowmem_action = false;

		/*
		 * If given, use non-zero timeout on the first time through
		 * the loop. On subsequent times, timeout will be zero so
		 * we will reevaluate the desired size of the balloon and
		 * break out to retry if needed.
		 */
		timeout = sc->vtballoon_timeout;
		sc->vtballoon_timeout = 0;

		if (current > desired)
			break;
		if (current < desired && timeout == 0)
			break;

		msleep(sc, VTBALLOON_MTX(sc), 0, "vtbslp", timeout);
	}
	VTBALLOON_UNLOCK(sc);

	return (rc);
}

static void
vtballoon_thread(void *xsc)
{
	struct vtballoon_softc *sc;
	uint32_t current, desired;
	bool failed, lowmem_action;

	sc = xsc;

	for (;;) {
		if (vtballoon_sleep(sc) != 0)
			break;

		if (sc->vtballoon_hint_pending) {
			sc->vtballoon_hint_pending = false;
			if (vtballoon_free_page_hint(sc,
			    sc->vtballoon_pending_cmd_id) == 0)
				sc->vtballoon_cmd_id_active =
				    sc->vtballoon_pending_cmd_id;
			continue;
		}

		current = sc->vtballoon_current_npages;
		desired = sc->vtballoon_desired_npages;
		lowmem_action = sc->vtballoon_lowmem_action;

		if (desired != current) {
			if (desired > current)
				vtballoon_inflate(sc, desired - current);
			else
				vtballoon_deflate(sc, current - desired);

			/*
			 * A failed request reset the device and cleared feature
			 * negotiation.  Do not touch device configuration after
			 * that reset; the final zero accounting value is local
			 * teardown state, not a valid post-reset config write.
			 */
			VTBALLOON_LOCK(sc);
			failed = (sc->vtballoon_flags &
			    VTBALLOON_FLAG_FAILED) != 0;
			if (!failed && lowmem_action)
				sc->vtballoon_timeout =
				    VTBALLOON_LOWMEM_TIMEOUT;
			VTBALLOON_UNLOCK(sc);
			if (!failed)
				vtballoon_update_size(sc);
		}
	}

	VTBALLOON_LOCK(sc);
	failed = (sc->vtballoon_flags & VTBALLOON_FLAG_FAILED) != 0;
	VTBALLOON_UNLOCK(sc);
	if (failed) {
		/* A full reset revokes host ownership before pages are reused. */
		vtballoon_stop(sc);
		vtballoon_free_all_pages(sc);
	}

	kthread_exit();
}

static void
vtballoon_setup_sysctl(struct vtballoon_softc *sc)
{
	device_t dev;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	dev = sc->vtballoon_dev;
	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "desired",
	    CTLFLAG_RD, &sc->vtballoon_desired_npages, sizeof(uint32_t),
	    "Desired balloon size in 4096-byte units");

	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "current",
	    CTLFLAG_RD, &sc->vtballoon_current_npages, sizeof(uint32_t),
	    "Current balloon size in 4096-byte units");

	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "poisoned",
	    CTLFLAG_RD, &sc->vtballoon_poisoned_npages, sizeof(uint32_t),
	    "Pages initialized to poison_val after acknowledged deflation");

	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "free_page_hint_reported",
	    CTLFLAG_RD, &sc->vtballoon_free_page_reported, sizeof(uint32_t),
	    "Free pages reported in the last free-page-hint round");
}
