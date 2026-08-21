/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 * Copyright (c) 2023, Arm Ltd
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

/* Driver for VirtIO GPU device. */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/fbio.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/taskqueue.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/resource.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/gpu/virtio_gpu.h>
#include <dev/virtio/gpu/virtio_gpu_geometry.h>

#include <dev/vt/vt.h>
#include <dev/vt/hw/fb/vt_fb.h>
#include <dev/vt/colors/vt_termcolors.h>

#include "fb_if.h"
#include "virtio_if.h"

#define VTGPU_FEATURES	0

/* The guest can allocate resource IDs, we only need one */
#define	VTGPU_RESOURCE_ID	1
#define	VTGPU_REQUEST_TIMEOUT	(10 * SBT_1S)
#define	VTGPU_MAX_FB_SIZE	(256U * 1024U * 1024U)

#define	VTGPU_FLAG_DETACH	0x01
#define	VTGPU_FLAG_FAILED	0x02

struct vtgpu_softc {
	/* Must be first so we can cast from info -> softc */
	struct fb_info 		 vtgpu_fb_info;
	struct virtio_gpu_config vtgpu_gpucfg;

	device_t		 vtgpu_dev;
	uint64_t		 vtgpu_features;
	struct mtx		 vtgpu_mtx;
	struct mtx		 vtgpu_dirty_mtx;
	u_int			 vtgpu_flags;
	u_int			 vtgpu_ops;
	struct taskqueue	*vtgpu_flush_tq;
	struct task		 vtgpu_flush_task;
	uint32_t		 vtgpu_dirty_x1;
	uint32_t		 vtgpu_dirty_y1;
	uint32_t		 vtgpu_dirty_x2;
	uint32_t		 vtgpu_dirty_y2;
	bool			 vtgpu_dirty_valid;

	struct virtqueue	*vtgpu_ctrl_vq;

	uint64_t		 vtgpu_next_fence;

	bool			 vtgpu_have_fb_info;
	bool			 vtgpu_mtx_initialized;
	bool			 vtgpu_dirty_mtx_initialized;
	bool			 vtgpu_request_active;
};

static int	vtgpu_modevent(module_t, int, void *);

static int	vtgpu_probe(device_t);
static int	vtgpu_attach(device_t);
static int	vtgpu_attach_completed(device_t);
static int	vtgpu_detach(device_t);

static int	vtgpu_negotiate_features(struct vtgpu_softc *);
static int	vtgpu_setup_features(struct vtgpu_softc *);
static void	vtgpu_read_config(struct vtgpu_softc *,
		    struct virtio_gpu_config *);
static int	vtgpu_alloc_virtqueue(struct vtgpu_softc *);
static void	vtgpu_ctrl_vq_intr(void *);
static bool	vtgpu_op_enter(struct vtgpu_softc *);
static void	vtgpu_op_leave(struct vtgpu_softc *);
static void	vtgpu_fb_changed(struct vtgpu_softc *, uint32_t, uint32_t,
		    uint32_t, uint32_t);
static void	vtgpu_flush_task(void *, int);
static int	vtgpu_check_response(struct vtgpu_softc *,
		    const struct virtio_gpu_ctrl_hdr *,
		    const struct virtio_gpu_ctrl_hdr *, uint32_t);
static int	vtgpu_get_display_info(struct vtgpu_softc *);
static int	vtgpu_create_2d(struct vtgpu_softc *);
static int	vtgpu_attach_backing(struct vtgpu_softc *);
static int	vtgpu_set_scanout(struct vtgpu_softc *, uint32_t, uint32_t,
		    uint32_t, uint32_t);
static int	vtgpu_transfer_to_host_2d(struct vtgpu_softc *, uint32_t,
		    uint32_t, uint32_t, uint32_t);
static int	vtgpu_resource_flush(struct vtgpu_softc *, uint32_t, uint32_t,
		    uint32_t, uint32_t);

static vd_blank_t		vtgpu_fb_blank;
static vd_bitblt_text_t		vtgpu_fb_bitblt_text;
static vd_bitblt_bmp_t		vtgpu_fb_bitblt_bitmap;
static vd_drawrect_t		vtgpu_fb_drawrect;
static vd_setpixel_t		vtgpu_fb_setpixel;
static vd_bitblt_argb_t		vtgpu_fb_bitblt_argb;

static struct vt_driver vtgpu_fb_driver = {
	.vd_name = "virtio_gpu",
	.vd_init = vt_fb_init,
	.vd_fini = vt_fb_fini,
	.vd_blank = vtgpu_fb_blank,
	.vd_bitblt_text = vtgpu_fb_bitblt_text,
	.vd_invalidate_text = vt_fb_invalidate_text,
	.vd_bitblt_bmp = vtgpu_fb_bitblt_bitmap,
	.vd_bitblt_argb = vtgpu_fb_bitblt_argb,
	.vd_drawrect = vtgpu_fb_drawrect,
	.vd_setpixel = vtgpu_fb_setpixel,
	.vd_postswitch = vt_fb_postswitch,
	.vd_priority = VD_PRIORITY_GENERIC+10,
	.vd_fb_ioctl = vt_fb_ioctl,
	.vd_fb_mmap = NULL,	/* No mmap as we need to signal the host */
	.vd_suspend = vt_fb_suspend,
	.vd_resume = vt_fb_resume,
};

VT_DRIVER_DECLARE(vt_vtgpu, vtgpu_fb_driver);

static void
vtgpu_fb_blank(struct vt_device *vd, term_color_t color)
{
	struct vtgpu_softc *sc;
	struct fb_info *info;

	info = vd->vd_softc;
	sc = (struct vtgpu_softc *)info;
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;

	vt_fb_blank(vd, color);
	vtgpu_fb_changed(sc, 0, 0, sc->vtgpu_fb_info.fb_width,
	    sc->vtgpu_fb_info.fb_height);
}

static void
vtgpu_fb_bitblt_text(struct vt_device *vd, const struct vt_window *vw,
    const term_rect_t *area)
{
	struct vtgpu_softc *sc;
	struct fb_info *info;
	int x, y, width, height;

	info = vd->vd_softc;
	sc = (struct vtgpu_softc *)info;
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;

	vt_fb_bitblt_text(vd, vw, area);

	x = area->tr_begin.tp_col * vw->vw_font->vf_width + vw->vw_draw_area.tr_begin.tp_col;
	y = area->tr_begin.tp_row * vw->vw_font->vf_height + vw->vw_draw_area.tr_begin.tp_row;
	width = area->tr_end.tp_col * vw->vw_font->vf_width + vw->vw_draw_area.tr_begin.tp_col - x;
	height = area->tr_end.tp_row * vw->vw_font->vf_height + vw->vw_draw_area.tr_begin.tp_row - y;

	vtgpu_fb_changed(sc, x, y, width, height);
}

static void
vtgpu_fb_bitblt_bitmap(struct vt_device *vd, const struct vt_window *vw,
    const uint8_t *pattern, const uint8_t *mask,
    unsigned int width, unsigned int height,
    unsigned int x, unsigned int y, term_color_t fg, term_color_t bg)
{
	struct vtgpu_softc *sc;
	struct fb_info *info;

	info = vd->vd_softc;
	sc = (struct vtgpu_softc *)info;
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;

	vt_fb_bitblt_bitmap(vd, vw, pattern, mask, width, height, x, y, fg, bg);

	vtgpu_fb_changed(sc, x, y, width, height);
}

static int
vtgpu_fb_bitblt_argb(struct vt_device *vd, const struct vt_window *vw,
    const uint8_t *argb,
    unsigned int width, unsigned int height,
    unsigned int x, unsigned int y)
{

	return (EOPNOTSUPP);
}

static void
vtgpu_fb_drawrect(struct vt_device *vd, int x1, int y1, int x2, int y2,
    int fill, term_color_t color)
{
	struct vtgpu_softc *sc;
	struct fb_info *info;
	int width, height;

	info = vd->vd_softc;
	sc = (struct vtgpu_softc *)info;
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;

	vt_fb_drawrect(vd, x1, y1, x2, y2, fill, color);

	width = x2 - x1 + 1;
	height = y2 - y1 + 1;
	vtgpu_fb_changed(sc, x1, y1, width, height);
}

static void
vtgpu_fb_setpixel(struct vt_device *vd, int x, int y, term_color_t color)
{
	struct vtgpu_softc *sc;
	struct fb_info *info;

	info = vd->vd_softc;
	sc = (struct vtgpu_softc *)info;
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;

	vt_fb_setpixel(vd, x, y, color);

	vtgpu_fb_changed(sc, x, y, 1, 1);
}

static struct virtio_feature_desc vtgpu_feature_desc[] = {
	{ VIRTIO_GPU_F_VIRGL,		"VirGL"		},
	{ VIRTIO_GPU_F_EDID,		"EDID"		},
	{ VIRTIO_GPU_F_RESOURCE_UUID,	"ResUUID"	},
	{ VIRTIO_GPU_F_RESOURCE_BLOB,	"ResBlob"	},
	{ VIRTIO_GPU_F_CONTEXT_INIT,	"ContextInit"	},
	{ 0, NULL }
};

static device_method_t vtgpu_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtgpu_probe),
	DEVMETHOD(device_attach,	vtgpu_attach),
	DEVMETHOD(device_detach,	vtgpu_detach),

	/* VirtIO methods. */
	DEVMETHOD(virtio_attach_completed, vtgpu_attach_completed),

	DEVMETHOD_END
};

static driver_t vtgpu_driver = {
	"vtgpu",
	vtgpu_methods,
	sizeof(struct vtgpu_softc)
};

VIRTIO_DRIVER_MODULE(virtio_gpu, vtgpu_driver, vtgpu_modevent, NULL);
MODULE_VERSION(virtio_gpu, 1);
MODULE_DEPEND(virtio_gpu, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_gpu, VIRTIO_ID_GPU,
    "VirtIO GPU");

static int
vtgpu_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
	case MOD_QUIESCE:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static int
vtgpu_probe(device_t dev)
{
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_gpu));
}

static int
vtgpu_attach(device_t dev)
{
	struct vtgpu_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtgpu_have_fb_info = false;
	sc->vtgpu_dev = dev;
	sc->vtgpu_next_fence = 1;
	mtx_init(&sc->vtgpu_mtx, device_get_nameunit(dev),
	    "VirtIO GPU request lock", MTX_DEF);
	sc->vtgpu_mtx_initialized = true;
	mtx_init(&sc->vtgpu_dirty_mtx, device_get_nameunit(dev),
	    "VirtIO GPU dirty rectangle", MTX_SPIN);
	sc->vtgpu_dirty_mtx_initialized = true;
	TASK_INIT(&sc->vtgpu_flush_task, 0, vtgpu_flush_task, sc);
	sc->vtgpu_flush_tq = taskqueue_create_fast("vtgpu_flush", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->vtgpu_flush_tq);
	if (sc->vtgpu_flush_tq == NULL) {
		error = ENOMEM;
		goto fail;
	}
	error = taskqueue_start_threads(&sc->vtgpu_flush_tq, 1, PI_TTY,
	    "%s flush", device_get_nameunit(dev));
	if (error != 0) {
		device_printf(dev, "cannot start framebuffer flush thread\n");
		goto fail;
	}
	virtio_set_feature_desc(dev, vtgpu_feature_desc);

	error = vtgpu_setup_features(sc);
	if (error != 0) {
		device_printf(dev, "cannot setup features\n");
		goto fail;
	}

	vtgpu_read_config(sc, &sc->vtgpu_gpucfg);

	error = vtgpu_alloc_virtqueue(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueue\n");
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_TTY);
	if (error != 0) {
		device_printf(dev, "cannot setup virtqueue interrupt\n");
		goto fail;
	}

fail:
	if (error != 0)
		vtgpu_detach(dev);

	return (error);
}

static int
vtgpu_attach_completed(device_t dev)
{
	struct vtgpu_softc *sc;
	void *fb;
	int error;

	sc = device_get_softc(dev);

	/*
	 * Device commands are not legal until the bus has published DRIVER_OK.
	 * Enable completion interrupts before issuing the first synchronous
	 * command; if an entry raced interrupt enable, the request path will
	 * observe it directly in the used ring.
	 */
	(void)virtqueue_enable_intr(sc->vtgpu_ctrl_vq);

	error = vtgpu_get_display_info(sc);
	if (error != 0)
		return (error);

	/*
	 * The current VT backend uses one physically contiguous 2D resource.
	 * Bound device-provided geometry before making a potentially large
	 * M_WAITOK allocation.  Scatter-gather backing remains future work.
	 */
	fb = contigmalloc((size_t)sc->vtgpu_fb_info.fb_size, M_DEVBUF,
	    M_WAITOK | M_ZERO, 0, ~0, 4, 0);
	if (fb == NULL)
		return (ENOMEM);
	sc->vtgpu_fb_info.fb_vbase = (vm_offset_t)fb;
	sc->vtgpu_fb_info.fb_pbase =
	    pmap_kextract(sc->vtgpu_fb_info.fb_vbase);

	error = vtgpu_create_2d(sc);
	if (error != 0)
		return (error);
	error = vtgpu_attach_backing(sc);
	if (error != 0)
		return (error);
	error = vtgpu_set_scanout(sc, 0, 0, sc->vtgpu_fb_info.fb_width,
	    sc->vtgpu_fb_info.fb_height);
	if (error != 0)
		return (error);

	error = vt_allocate(&vtgpu_fb_driver, &sc->vtgpu_fb_info);
	if (error != 0)
		return (error);
	sc->vtgpu_have_fb_info = true;

	error = vtgpu_transfer_to_host_2d(sc, 0, 0,
	    sc->vtgpu_fb_info.fb_width, sc->vtgpu_fb_info.fb_height);
	if (error != 0)
		return (error);
	return (vtgpu_resource_flush(sc, 0, 0,
	    sc->vtgpu_fb_info.fb_width, sc->vtgpu_fb_info.fb_height));
}

static int
vtgpu_detach(device_t dev)
{
	struct vtgpu_softc *sc;

	sc = device_get_softc(dev);
	if (sc->vtgpu_mtx_initialized) {
		/*
		 * Stop VT from publishing new drawing operations before waiting
		 * for requests which already crossed the entry fence.  Set the
		 * flag and wake request waiters under their mutex so neither the
		 * request wait nor the operation-count wait can miss its wakeup.
		 */
		mtx_lock(&sc->vtgpu_mtx);
		atomic_set_rel_int(&sc->vtgpu_flags, VTGPU_FLAG_DETACH);
		wakeup(sc);
		mtx_unlock(&sc->vtgpu_mtx);
	}
	if (sc->vtgpu_have_fb_info)
		vt_deallocate(&vtgpu_fb_driver, &sc->vtgpu_fb_info);
	sc->vtgpu_have_fb_info = false;
	if (sc->vtgpu_flush_tq != NULL) {
		taskqueue_drain(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task);
		taskqueue_free(sc->vtgpu_flush_tq);
		sc->vtgpu_flush_tq = NULL;
	}
	if (sc->vtgpu_mtx_initialized) {
		mtx_lock(&sc->vtgpu_mtx);
		while (sc->vtgpu_ops != 0)
			msleep(&sc->vtgpu_ops, &sc->vtgpu_mtx, 0,
			    "vtgpudt", 0);
		mtx_unlock(&sc->vtgpu_mtx);
	}
	if (sc->vtgpu_ctrl_vq != NULL) {
		virtqueue_disable_intr(sc->vtgpu_ctrl_vq);
		virtio_stop(dev);
		/*
		 * The parent normally tears interrupts down only after child
		 * detach returns.  Drain them here before destroying the mutex
		 * used by vtgpu_ctrl_vq_intr().
		 */
		virtio_teardown_intr(dev);
	}
	if (sc->vtgpu_fb_info.fb_vbase != 0) {
		MPASS(sc->vtgpu_fb_info.fb_size != 0);
		free((void *)sc->vtgpu_fb_info.fb_vbase,
		    M_DEVBUF);
		sc->vtgpu_fb_info.fb_vbase = 0;
	}
	if (sc->vtgpu_mtx_initialized) {
		mtx_destroy(&sc->vtgpu_mtx);
		sc->vtgpu_mtx_initialized = false;
	}
	if (sc->vtgpu_dirty_mtx_initialized) {
		mtx_destroy(&sc->vtgpu_dirty_mtx);
		sc->vtgpu_dirty_mtx_initialized = false;
	}

	return (0);
}

static int
vtgpu_negotiate_features(struct vtgpu_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtgpu_dev;
	features = VTGPU_FEATURES;

	sc->vtgpu_features = virtio_negotiate_features(dev, features);
	return (virtio_finalize_features(dev));
}

static int
vtgpu_setup_features(struct vtgpu_softc *sc)
{
	int error;

	error = vtgpu_negotiate_features(sc);
	if (error != 0)
		return (error);

	return (0);
}

static void
vtgpu_read_config(struct vtgpu_softc *sc,
    struct virtio_gpu_config *gpucfg)
{
	device_t dev;

	dev = sc->vtgpu_dev;

	bzero(gpucfg, sizeof(struct virtio_gpu_config));

#define VTGPU_GET_CONFIG(_dev, _field, _cfg)			\
	virtio_read_device_config(_dev,				\
	    offsetof(struct virtio_gpu_config, _field),	\
	    &(_cfg)->_field, sizeof((_cfg)->_field))		\

	VTGPU_GET_CONFIG(dev, events_read, gpucfg);
	VTGPU_GET_CONFIG(dev, events_clear, gpucfg);
	VTGPU_GET_CONFIG(dev, num_scanouts, gpucfg);
	VTGPU_GET_CONFIG(dev, num_capsets, gpucfg);

#undef VTGPU_GET_CONFIG
}

static int
vtgpu_alloc_virtqueue(struct vtgpu_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info[2];
	int nvqs;

	dev = sc->vtgpu_dev;
	nvqs = 1;

	VQ_ALLOC_INFO_INIT(&vq_info[0], 0, vtgpu_ctrl_vq_intr, sc,
	    &sc->vtgpu_ctrl_vq, "%s control", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, nvqs, vq_info));
}

static void
vtgpu_ctrl_vq_intr(void *xsc)
{
	struct vtgpu_softc *sc;

	sc = xsc;
	mtx_lock(&sc->vtgpu_mtx);
	wakeup(sc);
	mtx_unlock(&sc->vtgpu_mtx);
}

static bool
vtgpu_op_enter(struct vtgpu_softc *sc)
{
	bool entered;

	mtx_lock(&sc->vtgpu_mtx);
	entered = (sc->vtgpu_flags & VTGPU_FLAG_DETACH) == 0;
	if (entered)
		sc->vtgpu_ops++;
	mtx_unlock(&sc->vtgpu_mtx);
	return (entered);
}

static void
vtgpu_op_leave(struct vtgpu_softc *sc)
{

	mtx_lock(&sc->vtgpu_mtx);
	MPASS(sc->vtgpu_ops != 0);
	if (--sc->vtgpu_ops == 0)
		wakeup(&sc->vtgpu_ops);
	mtx_unlock(&sc->vtgpu_mtx);
}

/*
 * VT drawing methods can run from the callout path while a spin lock or
 * critical section is held.  They may update the memory framebuffer there,
 * but must not enter the synchronous VirtIO request path, which sleeps while
 * waiting for a device completion.  Coalesce damage under a spin mutex and
 * hand the transfer to a sleepable taskqueue thread.
 */
static void
vtgpu_fb_changed(struct vtgpu_softc *sc, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height)
{
	uint32_t x2, y2;

	/* A taskqueue cannot make progress while the debugger owns the CPU. */
	if (kdb_active || KERNEL_PANICKED())
		return;
	if (!virtio_gpu_rect_within(sc->vtgpu_fb_info.fb_width,
	    sc->vtgpu_fb_info.fb_height, x, y, width, height))
		return;
	x2 = x + width;
	y2 = y + height;

	mtx_lock_spin(&sc->vtgpu_dirty_mtx);
	/*
	 * Close the interval between the callback's initial flag check and
	 * backend removal.  vt_deallocate() serializes normal VT callbacks,
	 * but this second check also makes the producer/queue lifetime rule
	 * explicit and protects any future producer which calls this helper.
	 */
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0) {
		mtx_unlock_spin(&sc->vtgpu_dirty_mtx);
		return;
	}
	if (!sc->vtgpu_dirty_valid) {
		sc->vtgpu_dirty_x1 = x;
		sc->vtgpu_dirty_y1 = y;
		sc->vtgpu_dirty_x2 = x2;
		sc->vtgpu_dirty_y2 = y2;
		sc->vtgpu_dirty_valid = true;
	} else {
		sc->vtgpu_dirty_x1 = MIN(sc->vtgpu_dirty_x1, x);
		sc->vtgpu_dirty_y1 = MIN(sc->vtgpu_dirty_y1, y);
		sc->vtgpu_dirty_x2 = MAX(sc->vtgpu_dirty_x2, x2);
		sc->vtgpu_dirty_y2 = MAX(sc->vtgpu_dirty_y2, y2);
	}
	mtx_unlock_spin(&sc->vtgpu_dirty_mtx);

	taskqueue_enqueue(sc->vtgpu_flush_tq, &sc->vtgpu_flush_task);
}

static void
vtgpu_flush_task(void *xsc, int pending __unused)
{
	struct vtgpu_softc *sc;
	uint32_t x, y, width, height;
	int error;

	sc = xsc;
	mtx_lock_spin(&sc->vtgpu_dirty_mtx);
	if (!sc->vtgpu_dirty_valid) {
		mtx_unlock_spin(&sc->vtgpu_dirty_mtx);
		return;
	}
	x = sc->vtgpu_dirty_x1;
	y = sc->vtgpu_dirty_y1;
	width = sc->vtgpu_dirty_x2 - x;
	height = sc->vtgpu_dirty_y2 - y;
	sc->vtgpu_dirty_valid = false;
	mtx_unlock_spin(&sc->vtgpu_dirty_mtx);

	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) != 0)
		return;
	error = vtgpu_transfer_to_host_2d(sc, x, y, width, height);
	if (error == 0)
		(void)vtgpu_resource_flush(sc, x, y, width, height);
}

static int
vtgpu_req_resp2(struct vtgpu_softc *sc, void *req1, size_t req1len,
    void *req2, size_t req2len, void *resp, size_t resplen)
{
	struct sglist sg;
	struct sglist_seg segs[6];
	sbintime_t deadline, remaining;
	void *cookie;
	uint32_t used_len;
	int error, last, rcount;

	/*
	 * Detach first removes the VT producer, then waits for this count.
	 * Enter before taking the mutex so a callback already in progress
	 * cannot race mutex destruction.
	 */
	if (!vtgpu_op_enter(sc)) {
		error = ENXIO;
		return (error);
	}

	/*
	 * Each of these protocol objects is smaller than one page, but a stack
	 * object may straddle a page boundary.  Reserve two physical segments
	 * per logical object and tell the virtqueue the physical, rather than
	 * logical, readable count.
	 */
	if (req1len == 0 || req1len > PAGE_SIZE ||
	    (req2 != NULL && (req2len == 0 || req2len > PAGE_SIZE)) ||
	    resplen == 0 || resplen > PAGE_SIZE) {
		error = EINVAL;
		goto leave;
	}
	sglist_init(&sg, nitems(segs), segs);

	error = sglist_append(&sg, req1, req1len);
	if (error != 0) {
		device_printf(sc->vtgpu_dev,
		    "Unable to append the request to the sglist: %d\n",
		    error);
		goto leave;
	}
	if (req2 != NULL) {
		error = sglist_append(&sg, req2, req2len);
		if (error != 0) {
			device_printf(sc->vtgpu_dev,
			    "Unable to append the request to the sglist: %d\n",
			    error);
			goto leave;
		}
	}
	rcount = sg.sg_nseg;
	error = sglist_append_boundary(&sg, resp, resplen);
	if (error != 0) {
		device_printf(sc->vtgpu_dev,
		    "Unable to append the response buffer to the sglist: %d\n",
		    error);
		goto leave;
	}
	KASSERT(sg.sg_nseg > rcount,
	    ("vtgpu: request and response collapsed into one descriptor"));
	if (sg.sg_nseg <= rcount) {
		error = EFAULT;
		goto leave;
	}
	mtx_lock(&sc->vtgpu_mtx);
	while (sc->vtgpu_request_active &&
	    (atomic_load_acq_int(&sc->vtgpu_flags) &
	    (VTGPU_FLAG_DETACH | VTGPU_FLAG_FAILED)) == 0)
		msleep(&sc->vtgpu_request_active, &sc->vtgpu_mtx, 0,
		    "vtgpuq", 0);
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    VTGPU_FLAG_DETACH) != 0) {
		mtx_unlock(&sc->vtgpu_mtx);
		error = ENXIO;
		goto leave;
	}
	if ((atomic_load_acq_int(&sc->vtgpu_flags) &
	    VTGPU_FLAG_FAILED) != 0) {
		mtx_unlock(&sc->vtgpu_mtx);
		error = EIO;
		goto leave;
	}
	sc->vtgpu_request_active = true;

	error = virtqueue_enqueue(sc->vtgpu_ctrl_vq, resp, &sg, rcount,
	    sg.sg_nseg - rcount);
	if (error != 0) {
		device_printf(sc->vtgpu_dev, "Enqueue failed: %d\n", error);
		goto out;
	}

	virtqueue_notify(sc->vtgpu_ctrl_vq);
	deadline = sbinuptime() + VTGPU_REQUEST_TIMEOUT;
	for (;;) {
		cookie = virtqueue_dequeue(sc->vtgpu_ctrl_vq, &used_len);
		if (cookie != NULL)
			break;
		if ((atomic_load_acq_int(&sc->vtgpu_flags) &
		    VTGPU_FLAG_DETACH) != 0) {
			error = ENXIO;
			goto reset;
		}
		if (virtqueue_enable_intr(sc->vtgpu_ctrl_vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = EWOULDBLOCK;
		} else {
			error = msleep_sbt(sc, &sc->vtgpu_mtx, 0, "vtgpurs",
			    remaining, 0, 0);
		}
		if (error == EWOULDBLOCK) {
			device_printf(sc->vtgpu_dev,
			    "control request timed out\n");
			error = ETIMEDOUT;
			goto reset;
		}
		if (error != 0)
			goto reset;
	}
	if (cookie != resp) {
		device_printf(sc->vtgpu_dev,
		    "control request returned an unexpected cookie\n");
		error = EIO;
		goto reset;
	}
	if (used_len != resplen) {
		device_printf(sc->vtgpu_dev,
		    "control request returned %u bytes, expected %zu\n",
		    used_len, resplen);
		error = EIO;
		goto reset;
	}
	error = 0;
	goto out;

reset:
	/*
	 * The descriptor contains pointers into this function's caller stack.
	 * Reset and drain it before returning on every incomplete path.
	 */
	atomic_set_rel_int(&sc->vtgpu_flags, VTGPU_FLAG_FAILED);
	virtio_stop(sc->vtgpu_dev);
	last = 0;
	while (virtqueue_drain(sc->vtgpu_ctrl_vq, &last) != NULL)
		;
out:
	sc->vtgpu_request_active = false;
	wakeup(&sc->vtgpu_request_active);
	mtx_unlock(&sc->vtgpu_mtx);
leave:
	vtgpu_op_leave(sc);
	return (error);
}

static int
vtgpu_req_resp(struct vtgpu_softc *sc, void *req, size_t reqlen,
    void *resp, size_t resplen)
{
	return (vtgpu_req_resp2(sc, req, reqlen, NULL, 0, resp, resplen));
}

static int
vtgpu_check_response(struct vtgpu_softc *sc,
    const struct virtio_gpu_ctrl_hdr *req,
    const struct virtio_gpu_ctrl_hdr *resp, uint32_t expected_type)
{
	uint32_t flags, type;

	type = le32toh(resp->type);
	flags = le32toh(resp->flags);
	if (type != expected_type) {
		device_printf(sc->vtgpu_dev, "Invalid response type %x\n", type);
		return (EIO);
	}
	if ((le32toh(req->flags) & VIRTIO_GPU_FLAG_FENCE) != 0 &&
	    ((flags & VIRTIO_GPU_FLAG_FENCE) == 0 ||
	    resp->fence_id != req->fence_id)) {
		device_printf(sc->vtgpu_dev,
		    "Invalid fenced response flags=%x fence=%ju expected=%ju\n",
		    flags, (uintmax_t)le64toh(resp->fence_id),
		    (uintmax_t)le64toh(req->fence_id));
		return (EIO);
	}
	return (0);
}

static int
vtgpu_get_display_info(struct vtgpu_softc *sc)
{
	struct {
		struct virtio_gpu_ctrl_hdr req;
		char pad;
		struct virtio_gpu_resp_display_info resp;
	} s = { 0 };
	uint32_t height, num_scanouts, stride, width;
	uint64_t size;
	int error, i;

	s.req.type = htole32(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
	s.req.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.fence_id = htole64(atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	error = vtgpu_req_resp(sc, &s.req, sizeof(s.req), &s.resp,
	    sizeof(s.resp));
	if (error != 0)
		return (error);

	error = vtgpu_check_response(sc, &s.req, &s.resp.hdr,
	    VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
	if (error != 0)
		return (error);
	/*
	 * virtio_read_device_config() returns host-endian scalar fields for
	 * both modern and legacy transports.  Do not apply a second guest to
	 * host conversion here: it is a no-op on little-endian machines but
	 * corrupts the scanout count on a big-endian guest.
	 */
	num_scanouts = sc->vtgpu_gpucfg.num_scanouts;
	if (num_scanouts > nitems(s.resp.pmodes)) {
		device_printf(sc->vtgpu_dev,
		    "Invalid scanout count %u\n", num_scanouts);
		return (EINVAL);
	}
	for (i = 0; i < num_scanouts; i++) {
		if (le32toh(s.resp.pmodes[i].enabled) == 0)
			continue;
		if (i != 0) {
			device_printf(sc->vtgpu_dev,
			    "Unsupported enabled scanout %d\n", i);
			return (ENOTSUP);
		}
		width = le32toh(s.resp.pmodes[i].r.width);
		height = le32toh(s.resp.pmodes[i].r.height);
		if (!virtio_gpu_framebuffer_geometry(width, height, 4,
		    INT_MAX, MIN((uint64_t)INT_MAX,
		    (uint64_t)VTGPU_MAX_FB_SIZE), &stride, &size))
			return (EFBIG);

		sc->vtgpu_fb_info.fb_name =
		    device_get_nameunit(sc->vtgpu_dev);
		sc->vtgpu_fb_info.fb_width = width;
		sc->vtgpu_fb_info.fb_height = height;
		/* 32 bits per pixel */
		sc->vtgpu_fb_info.fb_bpp = 32;
		sc->vtgpu_fb_info.fb_depth = 32;
		sc->vtgpu_fb_info.fb_size = size;
		sc->vtgpu_fb_info.fb_stride = stride;
		return (0);
	}

	return (ENXIO);
}

static int
vtgpu_create_2d(struct vtgpu_softc *sc)
{
	struct {
		struct virtio_gpu_resource_create_2d req;
		char pad;
		struct virtio_gpu_ctrl_hdr resp;
	} s = { 0 };
	int error;

	s.req.hdr.type = htole32(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
	s.req.hdr.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.hdr.fence_id = htole64(
	    atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	s.req.resource_id = htole32(VTGPU_RESOURCE_ID);
	s.req.format = htole32(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM);
	s.req.width = htole32(sc->vtgpu_fb_info.fb_width);
	s.req.height = htole32(sc->vtgpu_fb_info.fb_height);

	error = vtgpu_req_resp(sc, &s.req, sizeof(s.req), &s.resp,
	    sizeof(s.resp));
	if (error != 0)
		return (error);

	return (vtgpu_check_response(sc, &s.req.hdr, &s.resp,
	    VIRTIO_GPU_RESP_OK_NODATA));
}

static int
vtgpu_attach_backing(struct vtgpu_softc *sc)
{
	struct {
		/*
		 * Split the backing and mem request arguments as some
		 * hypervisors, e.g. Parallels Desktop, don't work when
		 * they are enqueued together.
		 */
		struct {
			struct virtio_gpu_resource_attach_backing backing;
			char pad;
			struct virtio_gpu_mem_entry mem;
		} req;
		char pad;
		struct virtio_gpu_ctrl_hdr resp;
	} s = { 0 };
	int error;

	s.req.backing.hdr.type =
	    htole32(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
	s.req.backing.hdr.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.backing.hdr.fence_id = htole64(
	    atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	s.req.backing.resource_id = htole32(VTGPU_RESOURCE_ID);
	s.req.backing.nr_entries = htole32(1);

	s.req.mem.addr = htole64(sc->vtgpu_fb_info.fb_pbase);
	s.req.mem.length = htole32(sc->vtgpu_fb_info.fb_size);

	error = vtgpu_req_resp2(sc, &s.req.backing, sizeof(s.req.backing),
	    &s.req.mem, sizeof(s.req.mem), &s.resp, sizeof(s.resp));
	if (error != 0)
		return (error);

	return (vtgpu_check_response(sc, &s.req.backing.hdr, &s.resp,
	    VIRTIO_GPU_RESP_OK_NODATA));
}

static int
vtgpu_set_scanout(struct vtgpu_softc *sc, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height)
{
	struct {
		struct virtio_gpu_set_scanout req;
		char pad;
		struct virtio_gpu_ctrl_hdr resp;
	} s = { 0 };
	int error;

	s.req.hdr.type = htole32(VIRTIO_GPU_CMD_SET_SCANOUT);
	s.req.hdr.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.hdr.fence_id = htole64(
	    atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	s.req.r.x = htole32(x);
	s.req.r.y = htole32(y);
	s.req.r.width = htole32(width);
	s.req.r.height = htole32(height);

	s.req.scanout_id = 0;
	s.req.resource_id = htole32(VTGPU_RESOURCE_ID);

	error = vtgpu_req_resp(sc, &s.req, sizeof(s.req), &s.resp,
	    sizeof(s.resp));
	if (error != 0)
		return (error);

	return (vtgpu_check_response(sc, &s.req.hdr, &s.resp,
	    VIRTIO_GPU_RESP_OK_NODATA));
}

static int
vtgpu_transfer_to_host_2d(struct vtgpu_softc *sc, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height)
{
	struct {
		struct virtio_gpu_transfer_to_host_2d req;
		char pad;
		struct virtio_gpu_ctrl_hdr resp;
	} s = { 0 };
	int error;

	if (!virtio_gpu_rect_within(sc->vtgpu_fb_info.fb_width,
	    sc->vtgpu_fb_info.fb_height, x, y, width, height))
		return (EINVAL);

	s.req.hdr.type = htole32(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
	s.req.hdr.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.hdr.fence_id = htole64(
	    atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	s.req.r.x = htole32(x);
	s.req.r.y = htole32(y);
	s.req.r.width = htole32(width);
	s.req.r.height = htole32(height);

	s.req.offset = htole64((uint64_t)y *
	    sc->vtgpu_fb_info.fb_stride +
	    (uint64_t)x * (sc->vtgpu_fb_info.fb_bpp / 8));
	s.req.resource_id = htole32(VTGPU_RESOURCE_ID);

	error = vtgpu_req_resp(sc, &s.req, sizeof(s.req), &s.resp,
	    sizeof(s.resp));
	if (error != 0)
		return (error);

	return (vtgpu_check_response(sc, &s.req.hdr, &s.resp,
	    VIRTIO_GPU_RESP_OK_NODATA));
}

static int
vtgpu_resource_flush(struct vtgpu_softc *sc, uint32_t x, uint32_t y,
    uint32_t width, uint32_t height)
{
	struct {
		struct virtio_gpu_resource_flush req;
		char pad;
		struct virtio_gpu_ctrl_hdr resp;
	} s = { 0 };
	int error;

	if (!virtio_gpu_rect_within(sc->vtgpu_fb_info.fb_width,
	    sc->vtgpu_fb_info.fb_height, x, y, width, height))
		return (EINVAL);

	s.req.hdr.type = htole32(VIRTIO_GPU_CMD_RESOURCE_FLUSH);
	s.req.hdr.flags = htole32(VIRTIO_GPU_FLAG_FENCE);
	s.req.hdr.fence_id = htole64(
	    atomic_fetchadd_64(&sc->vtgpu_next_fence, 1));

	s.req.r.x = htole32(x);
	s.req.r.y = htole32(y);
	s.req.r.width = htole32(width);
	s.req.r.height = htole32(height);

	s.req.resource_id = htole32(VTGPU_RESOURCE_ID);

	error = vtgpu_req_resp(sc, &s.req, sizeof(s.req), &s.resp,
	    sizeof(s.resp));
	if (error != 0)
		return (error);

	return (vtgpu_check_response(sc, &s.req.hdr, &s.resp,
	    VIRTIO_GPU_RESP_OK_NODATA));
}
