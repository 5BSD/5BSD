/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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
 * VirtIO filesystem (virtio-fs) guest transport.
 *
 * virtio-fs is "FUSE over VirtIO": it speaks the exact same FUSE protocol as
 * the /dev/fuse character device, but carries the request/reply messages over
 * VirtIO request queues instead of read()/write() on a cdev.  Rather than
 * reimplement a filesystem, this driver bridges the in-tree fusefs VFS
 * (sys/fs/fuse) to the VirtIO transport:
 *
 *   - It owns a per-device "fuse" cdev whose open() allocates a struct
 *     fuse_data (a FUSE session).  The stock fusefs mount path
 *     (fuse_vfsop_mount) accepts that device + fd unchanged, so no edits to
 *     sys/fs/fuse are required.
 *
 *   - An in-kernel worker thread plays the role that a userspace FUSE daemon
 *     plays for /dev/fuse: it pops upgoing tickets off the session message
 *     list (data->ms_head), marshals each ticket's FUSE bytes into a VirtIO
 *     descriptor chain (readable = request, writable = reply buffer) and posts
 *     it to the high-priority or a request queue.
 *
 *   - Completion interrupts hand replies to an internal answer adapter that
 *     drives the session answer list (data->aw_head) exactly as
 *     fuse_device_write() would, preserving ticket unique IDs and the FUSE
 *     session error path -- without forging a userspace uio or a daemon.
 *
 * First-slice scope (see docs/waspnest-virtio-fs-5bsd-driver-plan.md): no DAX,
 * no notification queue, no packed-ring/queue-reset/suspend negotiation.
 * Split and packed rings are both supported by the shared virtqueue layer;
 * this driver simply does not advertise the packed-ring feature yet.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>

#include <machine/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/fs/virtio_fs.h>

#include "virtio_if.h"

/* fusefs session/ticket layer we bridge to. */
#include <fs/fuse/fuse.h>
#include <fs/fuse/fuse_ipc.h>

static MALLOC_DEFINE(M_VTFS, "virtio_fs", "VirtIO FS transport");

#define	VTFS_MAX_REQUEST_QUEUES		64U
#define	VTFS_DRAIN_TIMEOUT_SEC		10

struct vtfs_softc;

/*
 * One driver-owned request wrapper per in-flight VirtIO descriptor chain.  It
 * decouples VirtIO buffer lifetime from FUSE ticket lifetime: the ticket's
 * message buffer (tk_ms_fiov) is mapped directly into the readable descriptor,
 * so the ticket must stay alive until the device returns the chain.
 */
struct vtfs_request {
	STAILQ_ENTRY(vtfs_request) vr_link;
	struct fuse_ticket	*vr_tick;	/* owning FUSE ticket */
	void			*vr_reply;	/* writable reply buffer */
	size_t			 vr_reply_cap;	/* size of vr_reply */
	uint32_t		 vr_len;	/* bytes device wrote (on completion) */
	bool			 vr_expects_reply;
};

STAILQ_HEAD(vtfs_reqlist, vtfs_request);

/* Per-virtqueue interrupt context. */
struct vtfs_vq {
	struct vtfs_softc	*vq_sc;
	struct virtqueue	*vq_vq;
	int			 vq_id;
};

struct vtfs_softc {
	device_t		 vtfs_dev;
	struct mtx		 vtfs_mtx;	/* protects vq submit/complete state */
	struct cv		 vtfs_submit_cv; /* wait for descriptor space */
	uint64_t		 vtfs_features;

	/* Device configuration. */
	uint16_t		 vtfs_tag_len;
	char			 vtfs_tag[VIRTIO_FS_TAG_SIZE + 1];
	uint32_t		 vtfs_num_request_queues;

	/* VirtIO queues: index 0 hiprio, 1..N request queues. */
	int			 vtfs_nvqs;
	struct vtfs_vq		*vtfs_vqs;	/* [vtfs_nvqs] */
	struct virtqueue	*vtfs_hiprio_vq;
	struct virtqueue	**vtfs_req_vq;	/* [vtfs_num_request_queues] */
	struct sglist		*vtfs_sg;
	int			 vtfs_max_segs;
	size_t			 vtfs_reply_max;
	u_int			 vtfs_rr;	/* request-queue round robin */
	u_int			 vtfs_inflight;

	/* Completion delivery. */
	struct taskqueue	*vtfs_done_tq;
	struct task		 vtfs_done_task;
	struct vtfs_reqlist	 vtfs_done_list;

	/* FUSE session bridge (one session per device at a time). */
	struct cdev		*vtfs_cdev;
	struct fuse_data	*vtfs_data;	/* current session or NULL */
	struct thread		*vtfs_worker_td;

	bool			 vtfs_busy;	/* a session is open */
	bool			 vtfs_stopping;	/* queues quiescing */
	bool			 vtfs_worker_stop;
	bool			 vtfs_worker_exited;
	bool			 vtfs_need_reinit; /* device was stopped */
	bool			 vtfs_detaching;
	bool			 vtfs_intr_setup;
};

#define	VTFS_LOCK(sc)		mtx_lock(&(sc)->vtfs_mtx)
#define	VTFS_UNLOCK(sc)		mtx_unlock(&(sc)->vtfs_mtx)
#define	VTFS_ASSERT(sc)		mtx_assert(&(sc)->vtfs_mtx, MA_OWNED)

static int	vtfs_probe(device_t);
static int	vtfs_attach(device_t);
static int	vtfs_detach(device_t);

static int	vtfs_read_config(struct vtfs_softc *);
static int	vtfs_alloc_virtqueues(struct vtfs_softc *);
static void	vtfs_vq_intr(void *);
static void	vtfs_done_task(void *, int);

static int	vtfs_device_start(struct vtfs_softc *);
static void	vtfs_device_stop(struct vtfs_softc *);

static d_open_t		vtfs_dev_open;
static void		vtfs_dev_dtor(void *);
static void		vtfs_worker(void *);
static void		vtfs_submit(struct vtfs_softc *, struct fuse_ticket *);
static void		vtfs_deliver(struct vtfs_softc *, struct vtfs_request *);
static void		vtfs_abort_request(struct vtfs_softc *, struct vtfs_request *,
		    bool);
static void		vtfs_session_drain(struct fuse_data *);

static struct cdevsw vtfs_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vtfs_dev_open,
	/*
	 * d_name MUST be "fuse": fuse_vfsop_mount()->fuse_getdevice() only
	 * accepts a mount source whose cdevsw name is "fuse".  The /dev node
	 * itself is named virtiofs<unit>.
	 */
	.d_name =	"fuse",
};

VIRTIO_SIMPLE_PNPINFO(virtio_fs, VIRTIO_ID_FS, "VirtIO Filesystem Adapter");

static struct virtio_feature_desc vtfs_feature_desc[] = {
	{ VIRTIO_FS_F_NOTIFICATION,	"Notification" },
	{ 0, NULL }
};

/*
 * Feature bits this slice is willing to negotiate.  Deliberately empty of any
 * device-specific feature: notification, DAX and the ring extensions are not
 * enabled until each is independently implemented and tested.  Indirect
 * descriptors are negotiated because a maximal request/reply chain
 * (vtfs_max_segs segments) would otherwise consume most or all of a ring on
 * its own; with them each request occupies a single ring slot.  The segment
 * budget itself is clamped to VIRTIO_MAX_INDIRECT and the ring size at
 * attach time either way.
 */
#define	VTFS_FEATURES		VIRTIO_RING_F_INDIRECT_DESC

/* ------------------------------------------------------------------ */
/* FUSE opcode helpers                                                 */
/* ------------------------------------------------------------------ */

static bool
vtfs_op_expects_reply(enum fuse_opcode op)
{

	switch (op) {
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
		return (false);
	default:
		return (true);
	}
}

static bool
vtfs_op_is_hiprio(enum fuse_opcode op)
{

	switch (op) {
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
	case FUSE_INTERRUPT:
		return (true);
	default:
		return (false);
	}
}

/*
 * Compute a bounded reply-buffer size for a ticket.  We never advertise a
 * writable descriptor larger than the reply the operation can produce, and we
 * clamp all user-influenced lengths (READ/READDIR/xattr sizes) to a device
 * maximum so a hostile length in a request cannot force an unbounded guest
 * allocation.
 */
static size_t
vtfs_reply_cap(struct vtfs_softc *sc, struct fuse_ticket *tick)
{
	struct fuse_in_header *ihdr;
	void *body;
	size_t want;

	ihdr = fticket_in_header(tick);
	body = (char *)tick->tk_ms_fiov.base + sizeof(*ihdr);

	/* Default covers every fixed-size reply and READLINK (<= PAGE_SIZE). */
	want = PAGE_SIZE;

	switch (ihdr->opcode) {
	case FUSE_READ:
	case FUSE_READDIR:
	case FUSE_READDIRPLUS:
		if (tick->tk_ms_fiov.len >= sizeof(*ihdr) +
		    sizeof(struct fuse_read_in))
			want = ((struct fuse_read_in *)body)->size;
		break;
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
		if (tick->tk_ms_fiov.len >= sizeof(*ihdr) +
		    sizeof(struct fuse_getxattr_in))
			want = ((struct fuse_getxattr_in *)body)->size;
		break;
	default:
		break;
	}

	if (want < PAGE_SIZE)
		want = PAGE_SIZE;
	if (want > sc->vtfs_reply_max)
		want = sc->vtfs_reply_max;

	return (sizeof(struct fuse_out_header) + want);
}

/* ------------------------------------------------------------------ */
/* VirtIO device plumbing                                             */
/* ------------------------------------------------------------------ */

static int
vtfs_probe(device_t dev)
{

	return (VIRTIO_SIMPLE_PROBE(dev, virtio_fs));
}

static int
vtfs_read_config(struct vtfs_softc *sc)
{
	device_t dev;
	uint32_t nq;
	uint16_t i, taglen;

	dev = sc->vtfs_dev;

	/*
	 * The tag is a fixed 36-byte, NUL-padded field.  It is not required to
	 * be NUL-terminated when it fills the field.  Reject an empty tag and
	 * an embedded NUL in the middle of the name (padding after the name is
	 * fine).
	 */
	virtio_read_device_config_array(dev,
	    offsetof(struct virtio_fs_config, tag),
	    sc->vtfs_tag, 1, VIRTIO_FS_TAG_SIZE);
	sc->vtfs_tag[VIRTIO_FS_TAG_SIZE] = '\0';
	taglen = (uint16_t)strnlen(sc->vtfs_tag, VIRTIO_FS_TAG_SIZE);
	if (taglen == 0) {
		device_printf(dev, "device supplied an empty mount tag\n");
		return (EINVAL);
	}
	for (i = taglen; i < VIRTIO_FS_TAG_SIZE; i++) {
		if (sc->vtfs_tag[i] != '\0') {
			device_printf(dev,
			    "device mount tag has an embedded NUL\n");
			return (EINVAL);
		}
	}
	sc->vtfs_tag_len = taglen;

	nq = virtio_read_dev_config_4(dev,
	    offsetof(struct virtio_fs_config, num_request_queues));
	if (nq == 0) {
		device_printf(dev, "device advertised zero request queues\n");
		return (EINVAL);
	}
	if (nq > VTFS_MAX_REQUEST_QUEUES)
		nq = VTFS_MAX_REQUEST_QUEUES;
	sc->vtfs_num_request_queues = nq;

	device_printf(dev, "mount tag \"%s\", %u request queue%s\n",
	    sc->vtfs_tag, nq, nq == 1 ? "" : "s");
	return (0);
}

static int
vtfs_alloc_virtqueues(struct vtfs_softc *sc)
{
	struct vq_alloc_info *info;
	device_t dev;
	int i, error, nvqs;

	dev = sc->vtfs_dev;
	nvqs = sc->vtfs_nvqs;

	info = malloc(nvqs * sizeof(*info), M_VTFS, M_NOWAIT | M_ZERO);
	if (info == NULL)
		return (ENOMEM);

	/* Queue 0 is the high-priority queue. */
	sc->vtfs_vqs[VIRTIO_FS_VQ_HIPRIO].vq_sc = sc;
	sc->vtfs_vqs[VIRTIO_FS_VQ_HIPRIO].vq_id = VIRTIO_FS_VQ_HIPRIO;
	VQ_ALLOC_INFO_INIT(&info[VIRTIO_FS_VQ_HIPRIO], sc->vtfs_max_segs,
	    vtfs_vq_intr, &sc->vtfs_vqs[VIRTIO_FS_VQ_HIPRIO],
	    &sc->vtfs_hiprio_vq, "%s hiprio", device_get_nameunit(dev));

	/* Queues 1..N are ordinary request queues. */
	for (i = 0; i < (int)sc->vtfs_num_request_queues; i++) {
		int qid = VIRTIO_FS_VQ_REQUEST_BASE + i;

		sc->vtfs_vqs[qid].vq_sc = sc;
		sc->vtfs_vqs[qid].vq_id = qid;
		VQ_ALLOC_INFO_INIT(&info[qid], sc->vtfs_max_segs,
		    vtfs_vq_intr, &sc->vtfs_vqs[qid], &sc->vtfs_req_vq[i],
		    "%s request.%d", device_get_nameunit(dev), i);
	}

	error = virtio_alloc_virtqueues(dev, nvqs, info);
	free(info, M_VTFS);
	if (error != 0)
		return (error);

	/* Cache the resolved virtqueue pointers into the per-vq contexts. */
	sc->vtfs_vqs[VIRTIO_FS_VQ_HIPRIO].vq_vq = sc->vtfs_hiprio_vq;
	for (i = 0; i < (int)sc->vtfs_num_request_queues; i++)
		sc->vtfs_vqs[VIRTIO_FS_VQ_REQUEST_BASE + i].vq_vq =
		    sc->vtfs_req_vq[i];

	return (0);
}

static int
vtfs_attach(device_t dev)
{
	struct vtfs_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtfs_dev = dev;

	mtx_init(&sc->vtfs_mtx, "vtfs", NULL, MTX_DEF);
	cv_init(&sc->vtfs_submit_cv, "vtfssub");
	STAILQ_INIT(&sc->vtfs_done_list);
	TASK_INIT(&sc->vtfs_done_task, 0, vtfs_done_task, sc);

	virtio_set_feature_desc(dev, vtfs_feature_desc);
	sc->vtfs_features = virtio_negotiate_features(dev, VTFS_FEATURES);
	error = virtio_finalize_features(dev);
	if (error != 0) {
		device_printf(dev, "feature negotiation failed: %d\n", error);
		goto fail;
	}

	error = vtfs_read_config(sc);
	if (error != 0)
		goto fail;

	/* Expose the mount tag so mount_virtiofs(8) can resolve it. */
	SYSCTL_ADD_STRING(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)), OID_AUTO, "tag",
	    CTLFLAG_RD, sc->vtfs_tag, 0, "virtio-fs mount tag");

	/*
	 * A single request or reply may be as large as a full physical I/O.
	 * Size the scatter/gather list and the reply clamp accordingly so a
	 * maximal READ/WRITE can be described in one chain.
	 */
	sc->vtfs_reply_max = maxphys;
	sc->vtfs_max_segs = howmany(maxphys, PAGE_SIZE) * 2 + 4;
	/*
	 * The segment budget doubles as the indirect-table size request, which
	 * virtqueue_alloc() rejects outright above VIRTIO_MAX_INDIRECT (one
	 * page of descriptors) whether or not indirect descriptors end up
	 * negotiated.  Clamp before allocating the queues; a large maxphys is
	 * then carried by multiple requests instead of failing attach.
	 */
	if (sc->vtfs_max_segs > VIRTIO_MAX_INDIRECT) {
		sc->vtfs_max_segs = VIRTIO_MAX_INDIRECT;
		sc->vtfs_reply_max = MIN(sc->vtfs_reply_max,
		    (size_t)MAX(VIRTIO_MAX_INDIRECT - 8, 1) * PAGE_SIZE);
	}

	sc->vtfs_nvqs = 1 + sc->vtfs_num_request_queues;
	sc->vtfs_vqs = malloc(sc->vtfs_nvqs * sizeof(*sc->vtfs_vqs), M_VTFS,
	    M_WAITOK | M_ZERO);
	sc->vtfs_req_vq = malloc(sc->vtfs_num_request_queues *
	    sizeof(*sc->vtfs_req_vq), M_VTFS, M_WAITOK | M_ZERO);

	error = vtfs_alloc_virtqueues(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueues: %d\n", error);
		goto fail;
	}

	/*
	 * A descriptor chain may not exceed the (smallest) queue size: without
	 * indirect descriptors every segment consumes one ring descriptor, and
	 * with them the device may still reject an indirect table with more
	 * entries than the ring (as the bhyve transport does).  Clamp the
	 * segment budget and the reply size so a maximal request still fits;
	 * the margin covers the readable request segments.
	 */
	{
		int i, qsize;

		qsize = virtqueue_size(sc->vtfs_hiprio_vq);
		for (i = 0; i < (int)sc->vtfs_num_request_queues; i++)
			qsize = MIN(qsize, virtqueue_size(sc->vtfs_req_vq[i]));
		if (sc->vtfs_max_segs > qsize) {
			sc->vtfs_max_segs = qsize;
			sc->vtfs_reply_max = MIN(sc->vtfs_reply_max,
			    (size_t)MAX(qsize - 8, 1) * PAGE_SIZE);
		}
	}
	sc->vtfs_sg = sglist_alloc(sc->vtfs_max_segs, M_WAITOK);

	error = virtio_setup_intr(dev, INTR_TYPE_MISC | INTR_MPSAFE);
	if (error != 0) {
		device_printf(dev, "cannot setup virtqueue interrupts: %d\n",
		    error);
		goto fail;
	}
	sc->vtfs_intr_setup = true;

	sc->vtfs_done_tq = taskqueue_create("vtfs_done", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->vtfs_done_tq);
	taskqueue_start_threads(&sc->vtfs_done_tq, 1, PWAIT, "%s done",
	    device_get_nameunit(dev));

	/*
	 * Publish a "fuse" cdev named after this device.  Its open() creates a
	 * FUSE session bound to this transport; mount_virtiofs(8) opens it and
	 * hands the fd to the stock fusefs mount path.
	 */
	sc->vtfs_cdev = make_dev(&vtfs_cdevsw, device_get_unit(dev), UID_ROOT,
	    GID_OPERATOR, 0600, "virtiofs%d", device_get_unit(dev));
	if (sc->vtfs_cdev == NULL) {
		device_printf(dev, "cannot create /dev/virtiofs%d\n",
		    device_get_unit(dev));
		error = ENXIO;
		goto fail;
	}
	sc->vtfs_cdev->si_drv1 = sc;

	return (0);

fail:
	vtfs_detach(dev);
	return (error);
}

static int
vtfs_detach(device_t dev)
{
	struct vtfs_softc *sc;
	int i;

	sc = device_get_softc(dev);

	VTFS_LOCK(sc);
	sc->vtfs_detaching = true;
	if (sc->vtfs_busy) {
		/* Detach failed: the device must stay usable. */
		sc->vtfs_detaching = false;
		VTFS_UNLOCK(sc);
		return (EBUSY);
	}
	VTFS_UNLOCK(sc);

	if (sc->vtfs_cdev != NULL) {
		destroy_dev(sc->vtfs_cdev);	/* waits for open fds/dtors */
		sc->vtfs_cdev = NULL;
	}

	if (sc->vtfs_intr_setup) {
		for (i = 0; i < sc->vtfs_nvqs; i++)
			if (sc->vtfs_vqs[i].vq_vq != NULL)
				virtqueue_disable_intr(sc->vtfs_vqs[i].vq_vq);
	}
	virtio_stop(dev);
	if (sc->vtfs_intr_setup) {
		virtio_teardown_intr(dev);
		sc->vtfs_intr_setup = false;
	}

	if (sc->vtfs_done_tq != NULL) {
		taskqueue_drain(sc->vtfs_done_tq, &sc->vtfs_done_task);
		taskqueue_free(sc->vtfs_done_tq);
		sc->vtfs_done_tq = NULL;
	}

	if (sc->vtfs_sg != NULL) {
		sglist_free(sc->vtfs_sg);
		sc->vtfs_sg = NULL;
	}
	free(sc->vtfs_req_vq, M_VTFS);
	sc->vtfs_req_vq = NULL;
	free(sc->vtfs_vqs, M_VTFS);
	sc->vtfs_vqs = NULL;

	cv_destroy(&sc->vtfs_submit_cv);
	mtx_destroy(&sc->vtfs_mtx);
	return (0);
}

/*
 * (Re)start the device before a session opens.  virtio_stop() is used to
 * force a wedged backend to relinquish descriptors during teardown; if that
 * happened, re-initialise the device and its queues here.
 */
static int
vtfs_device_start(struct vtfs_softc *sc)
{
	int i, error;

	if (!sc->vtfs_need_reinit)
		return (0);

	error = virtio_reinit(sc->vtfs_dev, sc->vtfs_features);
	if (error != 0) {
		device_printf(sc->vtfs_dev, "device reinit failed: %d\n", error);
		return (error);
	}
	for (i = 0; i < sc->vtfs_nvqs; i++)
		virtqueue_enable_intr(sc->vtfs_vqs[i].vq_vq);
	virtio_reinit_complete(sc->vtfs_dev);
	sc->vtfs_need_reinit = false;
	return (0);
}

/*
 * Quiesce the queues at session end and reclaim every in-flight request.  In
 * the common case the backend is responsive: outstanding chains complete
 * normally and are delivered, so no device reset is needed.  Only a
 * non-responsive backend forces virtio_stop() + virtqueue_drain() to recover
 * the descriptors, after which the device must be reinitialised before reuse.
 */
static void
vtfs_device_stop(struct vtfs_softc *sc)
{
	struct vtfs_request *req;
	int i, last;
	bool forced;
	sbintime_t deadline;

	VTFS_LOCK(sc);
	sc->vtfs_stopping = true;
	cv_broadcast(&sc->vtfs_submit_cv);
	deadline = sbinuptime() + VTFS_DRAIN_TIMEOUT_SEC * SBT_1S;
	while (sc->vtfs_inflight > 0 && sbinuptime() < deadline)
		msleep_sbt(&sc->vtfs_inflight, &sc->vtfs_mtx, 0, "vtfsdrn",
		    SBT_1S, 0, 0);
	forced = (sc->vtfs_inflight > 0);
	VTFS_UNLOCK(sc);

	/* Flush any completions collected before the queues went idle. */
	taskqueue_drain(sc->vtfs_done_tq, &sc->vtfs_done_task);

	if (!forced)
		return;

	device_printf(sc->vtfs_dev,
	    "backend unresponsive; resetting device to reclaim %u request(s)\n",
	    sc->vtfs_inflight);
	for (i = 0; i < sc->vtfs_nvqs; i++)
		virtqueue_disable_intr(sc->vtfs_vqs[i].vq_vq);
	virtio_stop(sc->vtfs_dev);
	sc->vtfs_need_reinit = true;

	VTFS_LOCK(sc);
	for (i = 0; i < sc->vtfs_nvqs; i++) {
		last = 0;
		while ((req = virtqueue_drain(sc->vtfs_vqs[i].vq_vq,
		    &last)) != NULL) {
			sc->vtfs_inflight--;
			vtfs_abort_request(sc, req, false);
		}
	}
	VTFS_UNLOCK(sc);
}

/* ------------------------------------------------------------------ */
/* Submission path (in-kernel FUSE "daemon")                          */
/* ------------------------------------------------------------------ */

static struct virtqueue *
vtfs_select_vq(struct vtfs_softc *sc, struct fuse_ticket *tick)
{
	u_int idx;

	if (vtfs_op_is_hiprio(fticket_opcode(tick)))
		return (sc->vtfs_hiprio_vq);
	idx = atomic_fetchadd_int(&sc->vtfs_rr, 1) %
	    sc->vtfs_num_request_queues;
	return (sc->vtfs_req_vq[idx]);
}

/*
 * Free a request wrapper and drop the message-list reference the submit path
 * retained on the ticket.  If deliver_dead is true the owning session is being
 * torn down, so any waiter is failed through the standard FUSE session error
 * path (fdata_set_dead) rather than delivered a bogus reply.
 */
static void
vtfs_abort_request(struct vtfs_softc *sc, struct vtfs_request *req,
    bool deliver_dead)
{
	struct fuse_ticket *tick = req->vr_tick;

	if (deliver_dead)
		fdata_set_dead(tick->tk_data);
	free(req->vr_reply, M_VTFS);
	free(req, M_VTFS);
	fuse_ticket_drop(tick);		/* release retained ms reference */
}

static void
vtfs_submit(struct vtfs_softc *sc, struct fuse_ticket *tick)
{
	struct vtfs_request *req;
	struct virtqueue *vq;
	int error, readable, writable;

	req = malloc(sizeof(*req), M_VTFS, M_WAITOK | M_ZERO);
	req->vr_tick = tick;
	req->vr_expects_reply = vtfs_op_expects_reply(fticket_opcode(tick));
	if (req->vr_expects_reply) {
		req->vr_reply_cap = vtfs_reply_cap(sc, tick);
		req->vr_reply = malloc(req->vr_reply_cap, M_VTFS, M_WAITOK);
	}
	vq = vtfs_select_vq(sc, tick);

	VTFS_LOCK(sc);
retry:
	if (sc->vtfs_stopping) {
		VTFS_UNLOCK(sc);
		vtfs_abort_request(sc, req, true);
		return;
	}

	sglist_reset(sc->vtfs_sg);
	error = sglist_append(sc->vtfs_sg, tick->tk_ms_fiov.base,
	    tick->tk_ms_fiov.len);
	readable = sc->vtfs_sg->sg_nseg;
	if (error == 0 && req->vr_expects_reply)
		error = sglist_append_boundary(sc->vtfs_sg, req->vr_reply,
		    req->vr_reply_cap);
	writable = sc->vtfs_sg->sg_nseg - readable;
	if (error != 0) {
		device_printf(sc->vtfs_dev, "sglist build failed: %d\n", error);
		VTFS_UNLOCK(sc);
		vtfs_abort_request(sc, req, true);
		return;
	}
	KASSERT(!req->vr_expects_reply || writable > 0,
	    ("vtfs: request and response share a descriptor"));
	if (req->vr_expects_reply && writable == 0) {
		device_printf(sc->vtfs_dev,
		    "request and response descriptor boundary was lost\n");
		VTFS_UNLOCK(sc);
		vtfs_abort_request(sc, req, true);
		return;
	}

	error = virtqueue_enqueue(vq, req, sc->vtfs_sg, readable, writable);
	if (error == ENOSPC || error == EMSGSIZE) {
		/*
		 * Ring full, or (EMSGSIZE, no indirect descriptors) not
		 * enough contiguous free descriptors for the chain.  The
		 * chain always fits an empty ring -- vtfs_max_segs is
		 * clamped to the queue size when indirect descriptors are
		 * not negotiated -- so wait for a completion to free
		 * descriptors and retry.
		 */
		cv_wait(&sc->vtfs_submit_cv, &sc->vtfs_mtx);
		goto retry;
	}
	if (error != 0) {
		VTFS_UNLOCK(sc);
		vtfs_abort_request(sc, req, true);
		return;
	}
	sc->vtfs_inflight++;
	virtqueue_notify(vq);
	VTFS_UNLOCK(sc);
}

/*
 * The submit worker replaces the userspace FUSE daemon's read() loop: it pops
 * upgoing tickets off the session message list and posts them to the queues.
 * It also owns session teardown, since fusefs unmount simply marks the session
 * dead and relies on the "daemon" to drain it.
 */
static void
vtfs_worker(void *arg)
{
	struct vtfs_softc *sc = arg;
	struct fuse_data *data = sc->vtfs_data;
	struct fuse_ticket *tick;

	for (;;) {
		mtx_lock(&data->ms_mtx);
		for (;;) {
			if (fdata_get_dead(data) || sc->vtfs_worker_stop) {
				tick = NULL;
				break;
			}
			tick = fuse_ms_pop(data);
			if (tick != NULL)
				break;
			msleep(data, &data->ms_mtx, 0, "vtfsms", 0);
		}
		mtx_unlock(&data->ms_mtx);

		if (tick == NULL)
			break;
		vtfs_submit(sc, tick);
	}

	/*
	 * Session teardown.  Quiesce the queues (reclaiming in-flight ms
	 * references), then drain the session's message and answer lists just
	 * as fuse_device.c's fdata_dtor would for a departing daemon.
	 */
	vtfs_device_stop(sc);
	vtfs_session_drain(data);

	VTFS_LOCK(sc);
	sc->vtfs_data = NULL;
	sc->vtfs_busy = false;
	sc->vtfs_worker_exited = true;
	wakeup(&sc->vtfs_worker_exited);
	VTFS_UNLOCK(sc);

	FUSE_LOCK();
	fdata_trydestroy(data);		/* drop the worker's session reference */
	FUSE_UNLOCK();

	kthread_exit();
}

/*
 * Fail every outstanding ticket on the session, mirroring fdata_dtor() in
 * fuse_device.c.  Answer-list tickets are completed with ENOTCONN so their
 * waiters return; message-list tickets that never reached a queue are dropped.
 */
static void
vtfs_session_drain(struct fuse_data *data)
{
	struct fuse_ticket *tick;

	FUSE_LOCK();
	fuse_lck_mtx_lock(data->aw_mtx);
	selwakeuppri(&data->ks_rsel, PZERO);
	while ((tick = fuse_aw_pop(data)) != NULL) {
		fuse_lck_mtx_lock(tick->tk_aw_mtx);
		fticket_set_answered(tick);
		tick->tk_aw_errno = ENOTCONN;
		wakeup(tick);
		fuse_lck_mtx_unlock(tick->tk_aw_mtx);
		fuse_ticket_drop(tick);
	}
	fuse_lck_mtx_unlock(data->aw_mtx);

	fuse_lck_mtx_lock(data->ms_mtx);
	while ((tick = fuse_ms_pop(data)) != NULL)
		fuse_ticket_drop(tick);
	fuse_lck_mtx_unlock(data->ms_mtx);
	FUSE_UNLOCK();
}

/* ------------------------------------------------------------------ */
/* Completion path (internal answer adapter)                          */
/* ------------------------------------------------------------------ */

static void
vtfs_vq_intr(void *xvq)
{
	struct vtfs_vq *q = xvq;
	struct vtfs_softc *sc = q->vq_sc;
	struct virtqueue *vq = q->vq_vq;
	struct vtfs_request *req;
	uint32_t len;
	bool sched = false;

	VTFS_LOCK(sc);
again:
	while ((req = virtqueue_dequeue(vq, &len)) != NULL) {
		req->vr_len = len;
		STAILQ_INSERT_TAIL(&sc->vtfs_done_list, req, vr_link);
		sc->vtfs_inflight--;
		sched = true;
	}
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}
	cv_broadcast(&sc->vtfs_submit_cv);
	if (sc->vtfs_inflight == 0)
		wakeup(&sc->vtfs_inflight);
	VTFS_UNLOCK(sc);

	if (sched)
		taskqueue_enqueue(sc->vtfs_done_tq, &sc->vtfs_done_task);
}

static void
vtfs_done_task(void *arg, int pending __unused)
{
	struct vtfs_softc *sc = arg;
	struct vtfs_request *req;

	for (;;) {
		VTFS_LOCK(sc);
		req = STAILQ_FIRST(&sc->vtfs_done_list);
		if (req != NULL)
			STAILQ_REMOVE_HEAD(&sc->vtfs_done_list, vr_link);
		VTFS_UNLOCK(sc);
		if (req == NULL)
			break;
		vtfs_deliver(sc, req);
	}
}

/*
 * Deliver one completed reply to its FUSE ticket.  This is the internal
 * transport->session adapter: it performs the same queue transition and
 * handler dispatch that fuse_device_write() performs for a userspace daemon,
 * but sources the bytes from the VirtIO reply buffer via a UIO_SYSSPACE uio.
 */
static void
vtfs_deliver(struct vtfs_softc *sc, struct vtfs_request *req)
{
	struct fuse_ticket *tick = req->vr_tick;
	struct fuse_data *data = tick->tk_data;
	struct fuse_out_header ohead;
	struct fuse_ticket *t, *xt, *itick;
	struct iovec iov;
	struct uio uio;
	uint32_t len = req->vr_len;
	bool found = false;

	if (!req->vr_expects_reply) {
		/* FORGET/BATCH_FORGET: nothing to deliver, just reclaim. */
		goto reclaim;
	}

	/*
	 * The device reports how many bytes it wrote into the reply buffer.
	 * The shared virtqueue layer already refuses a used length that
	 * exceeds the chain's writable capacity, but do not rely on that:
	 * fail closed if a completion ever claims more than the buffer we
	 * posted, so the subsequent body copy can never read past vr_reply.
	 */
	if (len > req->vr_reply_cap) {
		device_printf(sc->vtfs_dev,
		    "oversized FUSE reply (%u > %zu bytes)\n",
		    len, req->vr_reply_cap);
		fdata_set_dead(data);
		goto reclaim;
	}

	if (len < sizeof(ohead)) {
		device_printf(sc->vtfs_dev, "runt FUSE reply (%u bytes)\n", len);
		fdata_set_dead(data);
		goto reclaim;
	}
	memcpy(&ohead, req->vr_reply, sizeof(ohead));
	if (ohead.len != len || ohead.unique != tick->tk_unique) {
		device_printf(sc->vtfs_dev, "malformed FUSE reply header\n");
		fdata_set_dead(data);
		goto reclaim;
	}

	/* Detach the ticket from the answer list (mirrors fuse_device_write). */
	fuse_lck_mtx_lock(data->aw_mtx);
	TAILQ_FOREACH_SAFE(t, &data->aw_head, tk_aw_link, xt) {
		if (t == tick) {
			found = true;
			fuse_aw_remove(tick);
			break;
		}
	}
	if (found && tick->irq_unique > 0) {
		/* Discard the FUSE_INTERRUPT companion, if still queued. */
		TAILQ_FOREACH_SAFE(itick, &data->aw_head, tk_aw_link, xt) {
			if (itick->tk_unique == tick->irq_unique) {
				fuse_aw_remove(itick);
				fuse_ticket_drop(itick);
				break;
			}
		}
		tick->irq_unique = 0;
	}
	fuse_lck_mtx_unlock(data->aw_mtx);

	if (!found) {
		/*
		 * The session was already drained (ENOTCONN delivered) or the
		 * op was interrupted.  Drop the answer reference silently.
		 */
		goto reclaim;
	}

	/*
	 * Hand the reply body to the ticket's handler through a kernel-space
	 * uio.  FUSE carries errors as negative errnos; flip the sign and
	 * clamp illegal values exactly as the cdev transport does.
	 */
	ohead.error *= -1;
	if (ohead.error < 0 || ohead.error > ELAST)
		ohead.error = EIO;
	memcpy(&tick->tk_aw_ohead, &ohead, sizeof(ohead));

	iov.iov_base = (char *)req->vr_reply + sizeof(ohead);
	iov.iov_len = len - sizeof(ohead);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = len - sizeof(ohead);
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;		/* copy FROM uio INTO the ticket fiov */
	uio.uio_td = curthread;

	if (tick->tk_aw_handler != NULL)
		(void)tick->tk_aw_handler(tick, &uio);

	fuse_ticket_drop(tick);		/* release the answer-list reference */

reclaim:
	free(req->vr_reply, M_VTFS);
	free(req, M_VTFS);
	fuse_ticket_drop(tick);		/* release the retained ms reference */
}

/* ------------------------------------------------------------------ */
/* cdev: FUSE session lifecycle                                       */
/* ------------------------------------------------------------------ */

static int
vtfs_dev_open(struct cdev *dev, int oflags __unused, int devtype __unused,
    struct thread *td)
{
	struct vtfs_softc *sc = dev->si_drv1;
	struct fuse_data *data;
	int error;

	if (sc == NULL)
		return (ENXIO);

	VTFS_LOCK(sc);
	if (sc->vtfs_detaching) {
		VTFS_UNLOCK(sc);
		return (ENXIO);
	}
	if (sc->vtfs_busy) {
		VTFS_UNLOCK(sc);
		return (EBUSY);
	}
	sc->vtfs_busy = true;
	VTFS_UNLOCK(sc);

	error = vtfs_device_start(sc);
	if (error != 0)
		goto fail;

	data = fdata_alloc(dev, td->td_ucred);

	/* Extra reference held by the worker until the session tears down. */
	FUSE_LOCK();
	data->ref++;
	FUSE_UNLOCK();

	error = devfs_set_cdevpriv(data, vtfs_dev_dtor);
	if (error != 0) {
		FUSE_LOCK();
		data->ref--;
		fdata_trydestroy(data);
		FUSE_UNLOCK();
		goto fail;
	}

	VTFS_LOCK(sc);
	sc->vtfs_data = data;
	sc->vtfs_stopping = false;
	sc->vtfs_worker_stop = false;
	sc->vtfs_worker_exited = false;
	VTFS_UNLOCK(sc);

	error = kthread_add(vtfs_worker, sc, NULL, &sc->vtfs_worker_td, 0, 0,
	    "vtfs%d", device_get_unit(sc->vtfs_dev));
	if (error != 0) {
		device_printf(sc->vtfs_dev, "cannot start worker: %d\n", error);
		/* No worker will run: tear the session down inline. */
		VTFS_LOCK(sc);
		sc->vtfs_data = NULL;
		VTFS_UNLOCK(sc);
		fdata_set_dead(data);
		vtfs_session_drain(data);
		FUSE_LOCK();
		fdata_trydestroy(data);		/* worker ref */
		FUSE_UNLOCK();
		/* The cdevpriv dtor will drop the open reference. */
		goto fail;
	}

	return (0);

fail:
	VTFS_LOCK(sc);
	sc->vtfs_busy = false;
	VTFS_UNLOCK(sc);
	return (error);
}

/*
 * cdev private destructor, run when the mount helper closes its fd.  For a
 * successful mount the session must survive fd close (there is no daemon
 * holding it open); teardown is instead driven by unmount, which marks the
 * session dead and wakes the worker.  Only an unmounted session (a failed or
 * abandoned open) is killed here.
 */
static void
vtfs_dev_dtor(void *arg)
{
	struct fuse_data *data = arg;
	struct cdev *dev = data->fdev;
	struct vtfs_softc *sc = dev != NULL ? dev->si_drv1 : NULL;

	if (data->mp == NULL && sc != NULL) {
		fdata_set_dead(data);
		/* Kick the worker so it observes the dead session and exits. */
		fuse_lck_mtx_lock(data->ms_mtx);
		wakeup(data);
		fuse_lck_mtx_unlock(data->ms_mtx);
	}

	FUSE_LOCK();
	fdata_trydestroy(data);		/* drop the open reference */
	FUSE_UNLOCK();
}

/* ------------------------------------------------------------------ */

static device_method_t vtfs_methods[] = {
	DEVMETHOD(device_probe,		vtfs_probe),
	DEVMETHOD(device_attach,	vtfs_attach),
	DEVMETHOD(device_detach,	vtfs_detach),
	DEVMETHOD_END
};

static driver_t vtfs_driver = {
	"virtio_fs",
	vtfs_methods,
	sizeof(struct vtfs_softc)
};

VIRTIO_DRIVER_MODULE(virtio_fs, vtfs_driver, NULL, NULL);
MODULE_VERSION(virtio_fs, 1);
MODULE_DEPEND(virtio_fs, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_fs, fusefs, 1, 1, 1);
