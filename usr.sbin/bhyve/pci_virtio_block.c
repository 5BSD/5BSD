/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright 2020-2021 Joyent, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/endian.h>

#include <machine/vmm_snapshot.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <md5.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "block_if.h"

#define	VTBLK_BSIZE	512
#define	VTBLK_RINGSZ	128
#define	VTBLK_MAXQ	8
#define	VTBLK_MAXREQ	(VTBLK_RINGSZ * VTBLK_MAXQ)

_Static_assert(VTBLK_MAXREQ <= BLOCKIF_RING_MAX,
    "All ring entries must be able to queue a request");

#define	VTBLK_S_OK	0
#define	VTBLK_S_IOERR	1
#define	VTBLK_S_UNSUPP	2

#define	VTBLK_BLK_ID_LEN	20
#define	VTBLK_BLK_ID_BYTES	(VTBLK_BLK_ID_LEN + 1)

/* Capability bits */
#define	VTBLK_F_BARRIER		(1 << 0)	/* Does host support barriers? */
#define	VTBLK_F_SIZE_MAX	(1 << 1)	/* Indicates maximum segment size */
#define	VTBLK_F_SEG_MAX		(1 << 2)	/* Indicates maximum # of segments */
#define	VTBLK_F_GEOMETRY	(1 << 4)	/* Legacy geometry available  */
#define	VTBLK_F_RO		(1 << 5)	/* Disk is read-only */
#define	VTBLK_F_BLK_SIZE	(1 << 6)	/* Block size of disk is available*/
#define	VTBLK_F_SCSI		(1 << 7)	/* Supports scsi command passthru */
#define	VTBLK_F_FLUSH		(1 << 9)	/* Writeback mode enabled after reset */
#define	VTBLK_F_WCE		(1 << 9)	/* Legacy alias for FLUSH */
#define	VTBLK_F_TOPOLOGY	(1 << 10)	/* Topology information is available */
#define	VTBLK_F_CONFIG_WCE	(1 << 11)	/* Writeback mode available in config */
#define	VTBLK_F_MQ		(1 << 12)	/* Multi-Queue */
#define	VTBLK_F_DISCARD		(1 << 13)	/* Trim blocks */
#define	VTBLK_F_WRITE_ZEROES	(1 << 14)	/* Write zeros */

/*
 * Host capabilities
 */
#define	VTBLK_S_HOSTCAPS      \
  ( VTBLK_F_SEG_MAX  |						    \
    VTBLK_F_BLK_SIZE |						    \
    VTBLK_F_FLUSH    |						    \
    VTBLK_F_TOPOLOGY |						    \
    VIRTIO_RING_F_INDIRECT_DESC )	/* indirect descriptors */

/*
 * The current blockif_delete() interface only allows a single delete
 * request at a time.
 */
#define	VTBLK_MAX_DISCARD_SEG	1

/*
 * An arbitrary limit to prevent excessive latency due to large
 * delete requests.
 */
#define	VTBLK_MAX_DISCARD_SECT	((16 << 20) / VTBLK_BSIZE)	/* 16 MiB */
#define	VTBLK_MAX_WRITE_ZEROES_SECT \
	((16 << 20) / VTBLK_BSIZE)	/* 16 MiB */
#define	VTBLK_MAX_WRITE_ZEROES_SEG	1

/*
 * Config space "registers"
 */
struct vtblk_config {
	uint64_t	vbc_capacity;
	uint32_t	vbc_size_max;
	uint32_t	vbc_seg_max;
	struct {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} vbc_geometry;
	uint32_t	vbc_blk_size;
	struct {
		uint8_t physical_block_exp;
		uint8_t alignment_offset;
		uint16_t min_io_size;
		uint32_t opt_io_size;
	} vbc_topology;
	uint8_t		vbc_writeback;
	uint8_t		unused0[1];
	uint16_t	num_queues;
	uint32_t	max_discard_sectors;
	uint32_t	max_discard_seg;
	uint32_t	discard_sector_alignment;
	uint32_t	max_write_zeroes_sectors;
	uint32_t	max_write_zeroes_seg;
	uint8_t		write_zeroes_may_unmap;
	uint8_t		unused1[3];
} __packed;

/*
 * Fixed-size block header
 */
struct virtio_blk_hdr {
#define	VBH_OP_READ		0
#define	VBH_OP_WRITE		1
#define	VBH_OP_SCSI_CMD		2
#define	VBH_OP_SCSI_CMD_OUT	3
#define	VBH_OP_FLUSH		4
#define	VBH_OP_FLUSH_OUT	5
#define	VBH_OP_IDENT		8
#define	VBH_OP_DISCARD		11
#define	VBH_OP_WRITE_ZEROES	13

#define	VBH_FLAG_BARRIER	0x80000000	/* OR'ed into vbh_type */
	uint32_t	vbh_type;
	uint32_t	vbh_ioprio;
	uint64_t	vbh_sector;
} __packed;

/*
 * Debug printf
 */
static int pci_vtblk_debug;
#define	DPRINTF(params) if (pci_vtblk_debug) PRINTLN params
#define	WPRINTF(params) PRINTLN params

struct pci_vtblk_ioreq {
	struct blockif_req		io_req;
	struct pci_vtblk_softc		*io_sc;
	uint8_t				*io_status;
	uint32_t			io_data_len;
	bool				io_writes_data;
	bool				io_full_transfer;
	bool				io_is_write;
	bool				io_stabilizing;
	bool				io_active;
	uint16_t			io_idx;
	struct vqueue_info		*io_vq;
	uint64_t			io_device_generation;
	uint64_t			io_queue_generation;
};

struct virtio_blk_discard_write_zeroes {
#define	VTBLK_WRITE_ZEROES_FLAG_UNMAP	0x00000001
	uint64_t	sector;
	uint32_t	num_sectors;
	uint32_t	flags;
};

/*
 * Per-device softc
 */
struct pci_vtblk_softc {
	struct virtio_softc vbsc_vs;
	pthread_mutex_t vsc_mtx;
	pthread_cond_t vbsc_reset_cond;
	struct vqueue_info vbsc_vqs[VTBLK_MAXQ];
	struct vtblk_config vbsc_cfg;
	struct virtio_consts vbsc_consts;
	struct blockif_ctxt *bc;
	struct pci_vtblk_ioreq *vbsc_ios;
	uint16_t vbsc_nqueues;
	uint64_t vbsc_generation;
	uint64_t vbsc_qreset_generation;
	struct vqueue_info *vbsc_qreset_vq;
	bool vbsc_qreset_pending;
	bool vbsc_resetting;
	bool vbsc_reset_waiting;
	char vbsc_ident[VTBLK_BLK_ID_BYTES];
};

static void pci_vtblk_reset(void *);
static int pci_vtblk_cancel_request_locked(struct pci_vtblk_softc *,
    struct pci_vtblk_ioreq *);
static void pci_vtblk_reset_enter(struct pci_vtblk_softc *);
static void pci_vtblk_reset_leave(struct pci_vtblk_softc *);
static bool pci_vtblk_requests_drained(const struct pci_vtblk_softc *);
static bool pci_vtblk_queue_requests_drained(
    const struct pci_vtblk_softc *, const struct vqueue_info *);
static bool pci_vtblk_write_needs_stabilization(
    const struct pci_vtblk_softc *);
static void pci_vtblk_configure_range_limits(struct pci_vtblk_softc *,
    int, int);
static int pci_vtblk_qreset(void *, struct vqueue_info *, uint64_t);
static uint64_t pci_vtblk_backend_caps(struct blockif_ctxt *);
static void pci_vtblk_notify(void *, struct vqueue_info *);
static int pci_vtblk_cfgread(void *, int, int, uint32_t *);
static int pci_vtblk_cfgwrite(void *, int, int, uint32_t);
#ifdef BHYVE_SNAPSHOT
static void pci_vtblk_pause(void *);
static void pci_vtblk_resume(void *);
static int pci_vtblk_snapshot(void *, struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtblk_vi_consts = {
	.vc_name =	"vtblk",
	.vc_nvq =	1,
	.vc_cfgsize =	sizeof(struct vtblk_config),
	.vc_reset =	pci_vtblk_reset,
	.vc_qnotify =	pci_vtblk_notify,
	.vc_cfgread =	pci_vtblk_cfgread,
	.vc_cfgwrite =	pci_vtblk_cfgwrite,
	.vc_apply_features = NULL,
	.vc_qreset =	pci_vtblk_qreset,
	.vc_hv_caps =	VTBLK_S_HOSTCAPS | VIRTIO_F_RING_RESET,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vtblk_pause,
	.vc_resume =	pci_vtblk_resume,
	.vc_snapshot =	pci_vtblk_snapshot,
#endif
};

static void
pci_vtblk_reset(void *vsc)
{
	struct pci_vtblk_softc *sc = vsc;
	struct pci_vtblk_ioreq *io;
	int error, i;

	DPRINTF(("vtblk: device reset requested !"));
	pci_vtblk_reset_enter(sc);
	sc->vbsc_qreset_pending = false;
	sc->vbsc_qreset_vq = NULL;
	sc->vbsc_generation++;
	/*
	 * Invalidate the ring before cancellation.  Stale callbacks can then
	 * finish without publishing to guest memory while this reset waits for
	 * the host backend to stop using their data buffers.
	 */
	vi_reset_dev(&sc->vbsc_vs);
	for (i = 0; i < sc->vbsc_nqueues * VTBLK_RINGSZ; i++) {
		io = &sc->vbsc_ios[i];
		if (!io->io_active)
			continue;
		error = pci_vtblk_cancel_request_locked(sc, io);
		if (error != 0 && error != EBUSY)
			vi_set_needs_reset(&sc->vbsc_vs);
	}
	while (!pci_vtblk_requests_drained(sc)) {
		sc->vbsc_reset_waiting = true;
		pthread_cond_wait(&sc->vbsc_reset_cond, &sc->vsc_mtx);
	}
	sc->vbsc_reset_waiting = false;
	pci_vtblk_reset_leave(sc);
}

/*
 * Queue cancellation drops vsc_mtx because blockif_cancel() can wait for a
 * completion callback which takes that mutex.  Serialize reset owners across
 * that unlocked interval so two vCPUs cannot cancel or recycle the same
 * blockif_req concurrently.
 */
static void
pci_vtblk_reset_enter(struct pci_vtblk_softc *sc)
{

	while (sc->vbsc_resetting)
		pthread_cond_wait(&sc->vbsc_reset_cond, &sc->vsc_mtx);
	sc->vbsc_resetting = true;
}

static void
pci_vtblk_reset_leave(struct pci_vtblk_softc *sc)
{

	sc->vbsc_resetting = false;
	pthread_cond_broadcast(&sc->vbsc_reset_cond);
}

/*
 * blockif_cancel() can wait for an in-flight backend operation.  The backend
 * invokes pci_vtblk_done() before that operation leaves its busy queue, and
 * the callback needs vsc_mtx.  Drop the device lock while cancelling or the
 * reset path and completion callback can wait on each other forever.
 *
 * Callers have already invalidated either the device generation or the
 * selected queue generation, so no request can be reused while the lock is
 * dropped.  EINVAL means the backend no longer owns the request; either the
 * callback has completed or is completing it through the stale-generation
 * path.
 */
static int
pci_vtblk_cancel_request_locked(struct pci_vtblk_softc *sc,
    struct pci_vtblk_ioreq *io)
{
	int error;

	pthread_mutex_unlock(&sc->vsc_mtx);
	error = blockif_cancel(sc->bc, &io->io_req);
	pthread_mutex_lock(&sc->vsc_mtx);
	if (error == 0 || error == EINVAL)
		io->io_active = false;
	return (error);
}

static bool
pci_vtblk_write_needs_stabilization(const struct pci_vtblk_softc *sc)
{
	uint64_t negotiated, offered;

	negotiated = sc->vbsc_vs.vs_negotiated_caps;
	offered = sc->vbsc_consts.vc_hv_caps;
	if ((negotiated & VTBLK_F_CONFIG_WCE) != 0)
		return (sc->vbsc_cfg.vbc_writeback == 0);
	return ((offered & VTBLK_F_FLUSH) != 0 &&
	    (negotiated & VTBLK_F_FLUSH) == 0);
}

static bool
pci_vtblk_requests_drained(const struct pci_vtblk_softc *sc)
{
	int i;

	for (i = 0; i < sc->vbsc_nqueues * VTBLK_RINGSZ; i++) {
		if (sc->vbsc_ios[i].io_active)
			return (false);
	}
	return (true);
}

static bool
pci_vtblk_queue_requests_drained(const struct pci_vtblk_softc *sc,
    const struct vqueue_info *vq)
{
	int i;

	for (i = 0; i < sc->vbsc_nqueues * VTBLK_RINGSZ; i++) {
		if (sc->vbsc_ios[i].io_active &&
		    sc->vbsc_ios[i].io_vq == vq)
			return (false);
	}
	return (true);
}

static int
pci_vtblk_qreset(void *vsc, struct vqueue_info *vq, uint64_t generation)
{
	struct pci_vtblk_softc *sc;
	struct pci_vtblk_ioreq *io;
	bool pending;
	int error, i;

	sc = vsc;
	if (vq->vq_num >= sc->vbsc_nqueues ||
	    vq != &sc->vbsc_vqs[vq->vq_num])
		return (EINVAL);
	DPRINTF(("vtblk: queue reset requested q=%u generation=%ju",
	    vq->vq_num, (uintmax_t)generation));
	pci_vtblk_reset_enter(sc);

	/*
	 * The modern transport has already advanced vq_generation, invalidating
	 * every request from this queue's old incarnation.  Pending requests are
	 * removed synchronously without touching other queues.  For a busy
	 * request, EBUSY means its normal callback may still be pending; keep
	 * queue_reset asserted until that callback has stopped using the old
	 * guest buffers.
	 */
	sc->vbsc_qreset_pending = false;
	sc->vbsc_qreset_vq = NULL;
	pending = false;
	for (i = 0; i < sc->vbsc_nqueues * VTBLK_RINGSZ; i++) {
		io = &sc->vbsc_ios[i];
		if (!io->io_active || io->io_vq != vq)
			continue;
		error = pci_vtblk_cancel_request_locked(sc, io);
		switch (error) {
		case 0:
		case EINVAL:
			break;
		case EBUSY:
			pending = true;
			break;
		default:
			pci_vtblk_reset_leave(sc);
			return (error);
		}
	}
	if (!pending || pci_vtblk_queue_requests_drained(sc, vq)) {
		pci_vtblk_reset_leave(sc);
		return (0);
	}
	sc->vbsc_qreset_generation = generation;
	sc->vbsc_qreset_vq = vq;
	sc->vbsc_qreset_pending = true;
	return (EINPROGRESS);
}

static void
pci_vtblk_done_locked(struct pci_vtblk_ioreq *io, int err)
{
	uint32_t used_len;

	io->io_active = false;

	/* convert errno into a virtio block error return */
	if (err == EOPNOTSUPP || err == ENOSYS)
		*io->io_status = VTBLK_S_UNSUPP;
	else if (err != 0)
		*io->io_status = VTBLK_S_IOERR;
	else
		*io->io_status = VTBLK_S_OK;

	/*
	 * Return the descriptor to the driver.  The used length covers the
	 * status byte and any read or identification data actually written.
	 */
	used_len = 1;
	if (io->io_writes_data && io->io_req.br_resid >= 0 &&
	    (uint64_t)io->io_req.br_resid <= io->io_data_len)
		used_len += io->io_data_len - io->io_req.br_resid;
	vq_relchain(io->io_vq, io->io_idx, used_len);
	vq_endchains(io->io_vq, 0);
}

#ifdef BHYVE_SNAPSHOT
static void
pci_vtblk_pause(void *vsc)
{
	struct pci_vtblk_softc *sc = vsc;

	DPRINTF(("vtblk: device pause requested !\n"));
	blockif_pause(sc->bc);
}

static void
pci_vtblk_resume(void *vsc)
{
	struct pci_vtblk_softc *sc = vsc;

	DPRINTF(("vtblk: device resume requested !\n"));
	blockif_resume(sc->bc);
}

static int
pci_vtblk_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	int ret;
	struct pci_vtblk_softc *sc = vsc;

	SNAPSHOT_VAR_OR_LEAVE(sc->vbsc_cfg, meta, ret, done);
	SNAPSHOT_BUF_OR_LEAVE(sc->vbsc_ident, sizeof(sc->vbsc_ident),
			      meta, ret, done);

done:
	return (ret);
}
#endif

static void
pci_vtblk_done(struct blockif_req *br, int err)
{
	struct pci_vtblk_ioreq *io = br->br_param;
	struct pci_vtblk_softc *sc = io->io_sc;
	struct vqueue_info *reset_vq;
	uint64_t generation;
	bool complete, reset_complete;

	complete = true;
	reset_complete = false;
	reset_vq = NULL;
	generation = 0;
	pthread_mutex_lock(&sc->vsc_mtx);
	if (io->io_active &&
	    io->io_device_generation == sc->vbsc_generation &&
	    io->io_queue_generation == io->io_vq->vq_generation) {
		if (err == 0 && io->io_full_transfer &&
		    io->io_req.br_resid != 0)
			err = EIO;
		if (err == 0 && io->io_is_write && !io->io_stabilizing &&
		    pci_vtblk_write_needs_stabilization(sc)) {
			io->io_stabilizing = true;
			err = blockif_flush(sc->bc, &io->io_req);
			if (err == 0)
				complete = false;
		}
		if (complete) {
			io->io_stabilizing = false;
			pci_vtblk_done_locked(io, err);
		}
	} else {
		io->io_active = false;
		io->io_stabilizing = false;
	}
	if (sc->vbsc_reset_waiting)
		pthread_cond_broadcast(&sc->vbsc_reset_cond);
	if (sc->vbsc_qreset_pending &&
	    pci_vtblk_queue_requests_drained(sc, sc->vbsc_qreset_vq)) {
		generation = sc->vbsc_qreset_generation;
		reset_vq = sc->vbsc_qreset_vq;
		sc->vbsc_qreset_pending = false;
		sc->vbsc_qreset_vq = NULL;
		pci_vtblk_reset_leave(sc);
		reset_complete = true;
	}
	pthread_mutex_unlock(&sc->vsc_mtx);
	if (reset_complete)
		vi_pci_modern_queue_reset_complete(reset_vq, generation, 0);
}

static void
pci_vtblk_complete_invalid(struct vqueue_info *vq, const struct vi_req *req,
    struct iovec *iov, int n)
{
	uint8_t *status;
	uint32_t len;
	int i;

	len = 0;
	if (n >= 2 && n <= BLOCKIF_IOV_MAX + 2 && req->ordered &&
	    req->readable > 0 && req->writable > 0 &&
	    req->readable + req->writable == n) {
		for (i = n - 1; i >= req->readable; i--) {
			if (iov[i].iov_len == 0)
				continue;
			status = (uint8_t *)iov[i].iov_base +
			    iov[i].iov_len - 1;
			*status = VTBLK_S_IOERR;
			len = 1;
			break;
		}
	}
	vq_relchain(vq, req->idx, len);
	vq_endchains(vq, 0);
}

/*
 * The block status is the final byte of the device-writable portion of the
 * descriptor chain, not necessarily a byte in the final descriptor.  Split
 * rings permit zero-length descriptors, so walk backwards over them.
 */
static bool
pci_vtblk_status_ptr(const struct vi_req *req, struct iovec *iov, int n,
    uint8_t **status)
{
	int i;

	if (n < 2 || req->readable <= 0 || req->writable <= 0 ||
	    req->readable + req->writable != n)
		return (false);
	for (i = n - 1; i >= req->readable; i--) {
		if (iov[i].iov_len == 0)
			continue;
		*status = (uint8_t *)iov[i].iov_base + iov[i].iov_len - 1;
		return (true);
	}
	return (false);
}

static bool
pci_vtblk_iov_read(const struct iovec *iov, int niov, size_t offset,
    void *dst, size_t length)
{
	size_t copy, skip;
	uint8_t *out;
	int i;

	out = dst;
	skip = offset;
	for (i = 0; i < niov && length != 0; i++) {
		if (skip >= iov[i].iov_len) {
			skip -= iov[i].iov_len;
			continue;
		}
		copy = MIN(length, iov[i].iov_len - skip);
		memcpy(out, (const uint8_t *)iov[i].iov_base + skip, copy);
		out += copy;
		length -= copy;
		skip = 0;
	}
	return (length == 0);
}

/*
 * Copy a byte range from an input iovec into an output iovec without copying
 * the data itself.  This permits the fixed block header and trailing status
 * byte to share descriptors with data, as allowed by the generic split-ring
 * buffer layout.
 */
static int
pci_vtblk_iov_slice(const struct iovec *iov, int niov, size_t offset,
    size_t length, struct iovec *out, int out_max, int *out_count)
{
	size_t copy, skip;
	int i, n;

	n = 0;
	skip = offset;
	for (i = 0; i < niov && length != 0; i++) {
		if (skip >= iov[i].iov_len) {
			skip -= iov[i].iov_len;
			continue;
		}
		if (n == out_max)
			return (E2BIG);
		copy = MIN(length, iov[i].iov_len - skip);
		out[n].iov_base = (uint8_t *)iov[i].iov_base + skip;
		out[n].iov_len = copy;
		n++;
		length -= copy;
		skip = 0;
	}
	if (length != 0)
		return (EINVAL);
	*out_count = n;
	return (0);
}

static int
pci_vtblk_iov_length(const struct iovec *iov, int niov, size_t *length)
{
	size_t total;
	int i;

	total = 0;
	for (i = 0; i < niov; i++) {
		if (iov[i].iov_len > SIZE_MAX - total)
			return (EOVERFLOW);
		total += iov[i].iov_len;
	}
	*length = total;
	return (0);
}

static void
pci_vtblk_proc(struct pci_vtblk_softc *sc, struct vqueue_info *vq)
{
	struct virtio_blk_hdr vbh;
	struct pci_vtblk_ioreq *io;
	int i, n;
	int err;
	ssize_t iolen;
	int writeop, type;
	uint64_t sector, sectors;
	size_t data_len, readable_len, writable_len;
	struct vi_req req;
	struct iovec iov[BLOCKIF_IOV_MAX + 2];
	struct virtio_blk_discard_write_zeroes discard;

	n = vq_getchain(vq, iov, BLOCKIF_IOV_MAX + 2, &req);
	if (n <= 0)
		return;

	/*
	 * Descriptors are direction-ordered, but the protocol header, data, and
	 * status fields need not align to descriptor boundaries.  The readable
	 * section starts with the fixed header and the writable section ends
	 * with the status byte.
	 */
	if (n < 2 || n > BLOCKIF_IOV_MAX + 2 || !req.ordered ||
	    req.readable == 0 || req.writable == 0 ||
	    req.readable + req.writable != n ||
	    pci_vtblk_iov_length(iov, req.readable, &readable_len) != 0 ||
	    pci_vtblk_iov_length(&iov[req.readable], req.writable,
	    &writable_len) != 0 ||
	    readable_len < sizeof(vbh) || writable_len < 1 ||
	    !pci_vtblk_iov_read(iov, req.readable, 0, &vbh, sizeof(vbh))) {
		DPRINTF(("virtio-block: invalid descriptor chain"));
		pci_vtblk_complete_invalid(vq, &req, iov, n);
		return;
	}

	if (vq->vq_num >= sc->vbsc_nqueues || req.idx >= VTBLK_RINGSZ) {
		pci_vtblk_complete_invalid(vq, &req, iov, n);
		return;
	}
	io = &sc->vbsc_ios[vq->vq_num * VTBLK_RINGSZ + req.idx];
	if (io->io_active) {
		pci_vtblk_complete_invalid(vq, &req, iov, n);
		return;
	}
	io->io_vq = vq;
	io->io_data_len = 0;
	io->io_writes_data = false;
	io->io_full_transfer = false;
	io->io_is_write = false;
	io->io_stabilizing = false;
	sector = le64toh(vbh.vbh_sector);
	if (sector > (uint64_t)OFF_MAX / VTBLK_BSIZE) {
		pci_vtblk_complete_invalid(vq, &req, iov, n);
		return;
	}
	io->io_req.br_offset = sector * VTBLK_BSIZE;
	if (!pci_vtblk_status_ptr(&req, iov, n, &io->io_status)) {
		pci_vtblk_complete_invalid(vq, &req, iov, n);
		return;
	}

	/* The legacy BARRIER flag was not advertised. */
	type = le32toh(vbh.vbh_type);
	if ((type & VBH_FLAG_BARRIER) != 0) {
		pci_vtblk_done_locked(io, EOPNOTSUPP);
		return;
	}
	if (type == VBH_OP_WRITE &&
	    (sc->vbsc_consts.vc_hv_caps & VTBLK_F_RO) != 0) {
		pci_vtblk_done_locked(io, EROFS);
		return;
	}
	if (type != VBH_OP_READ && type != VBH_OP_WRITE &&
	    type != VBH_OP_DISCARD && type != VBH_OP_WRITE_ZEROES &&
	    type != VBH_OP_FLUSH && type != VBH_OP_FLUSH_OUT &&
	    type != VBH_OP_IDENT) {
		pci_vtblk_done_locked(io, EOPNOTSUPP);
		return;
	}
	if (type == VBH_OP_DISCARD || type == VBH_OP_WRITE_ZEROES) {
		/*
		 * Section 5.2.6.2 requires UNSUPP when the operation was not
		 * negotiated.  Check negotiation before the read-only media
		 * boundary so a read-only device does not turn an unsupported
		 * operation into IOERR.  The second check is defensive against
		 * stale or corrupted negotiated state.
		 */
		uint64_t feature;

		feature = type == VBH_OP_DISCARD ? VTBLK_F_DISCARD :
		    VTBLK_F_WRITE_ZEROES;
		if ((sc->vbsc_vs.vs_negotiated_caps & feature) == 0) {
			pci_vtblk_done_locked(io, EOPNOTSUPP);
			return;
		}
		if ((sc->vbsc_consts.vc_hv_caps & VTBLK_F_RO) != 0) {
			pci_vtblk_done_locked(io, EROFS);
			return;
		}
	}
	writeop = (type == VBH_OP_WRITE || type == VBH_OP_DISCARD ||
	    type == VBH_OP_WRITE_ZEROES);
	/*
	 * Write/discard data follows the header in the readable section.
	 * Read/ident data precedes status in the writable section.
	 */
	if (writeop) {
		if (writable_len != 1)
			err = EINVAL;
		else {
			data_len = readable_len - sizeof(vbh);
			err = pci_vtblk_iov_slice(iov, req.readable,
			    sizeof(vbh), data_len, io->io_req.br_iov,
			    BLOCKIF_IOV_MAX, &io->io_req.br_iovcnt);
		}
	} else if (type == VBH_OP_READ || type == VBH_OP_IDENT) {
		if (readable_len != sizeof(vbh))
			err = EINVAL;
		else {
			data_len = writable_len - 1;
			err = pci_vtblk_iov_slice(&iov[req.readable],
			    req.writable, 0, data_len, io->io_req.br_iov,
			    BLOCKIF_IOV_MAX, &io->io_req.br_iovcnt);
		}
	} else {
		data_len = 0;
		io->io_req.br_iovcnt = 0;
		err = readable_len == sizeof(vbh) && writable_len == 1 ?
		    0 : EINVAL;
	}
	if (err != 0) {
		pci_vtblk_done_locked(io, err);
		return;
	}
	if ((type == VBH_OP_FLUSH || type == VBH_OP_FLUSH_OUT) &&
	    sector != 0) {
		pci_vtblk_done_locked(io, EINVAL);
		return;
	}

	if (data_len > SSIZE_MAX) {
		pci_vtblk_done_locked(io, EINVAL);
		return;
	}
	iolen = data_len;
	if (type == VBH_OP_READ || type == VBH_OP_WRITE) {
		if (iolen % VTBLK_BSIZE != 0 ||
		    iolen > OFF_MAX - io->io_req.br_offset) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}
		sectors = (uint64_t)iolen / VTBLK_BSIZE;
		if (sector > sc->vbsc_cfg.vbc_capacity ||
		    sectors > sc->vbsc_cfg.vbc_capacity - sector) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}
	}
	if ((type == VBH_OP_READ || type == VBH_OP_IDENT) &&
	    iolen > UINT32_MAX - 1) {
		pci_vtblk_done_locked(io, EINVAL);
		return;
	}
	io->io_req.br_resid = iolen;
	io->io_writes_data = type == VBH_OP_READ || type == VBH_OP_IDENT;
	io->io_full_transfer = type == VBH_OP_READ || type == VBH_OP_WRITE ||
	    type == VBH_OP_WRITE_ZEROES;
	io->io_is_write = type == VBH_OP_WRITE ||
	    type == VBH_OP_WRITE_ZEROES;
	if (io->io_writes_data)
		io->io_data_len = (uint32_t)iolen;

	DPRINTF(("virtio-block: q=%u %s op, %zd bytes, %d segs, "
	    "offset %ld", vq->vq_num,
	    writeop ? "write/discard" : "read/ident", iolen,
	    io->io_req.br_iovcnt, io->io_req.br_offset));

	io->io_active = true;
	io->io_device_generation = sc->vbsc_generation;
	io->io_queue_generation = vq->vq_generation;
	switch (type) {
	case VBH_OP_READ:
		err = blockif_read(sc->bc, &io->io_req);
		break;
	case VBH_OP_WRITE:
		err = blockif_write(sc->bc, &io->io_req);
		break;
	case VBH_OP_DISCARD:
	case VBH_OP_WRITE_ZEROES:
		/*
		 * We currently only support a single request, if the guest
		 * has submitted a request that doesn't conform to the
		 * requirements, we return a error.
		 */
		if (iolen != sizeof(discard) ||
		    !pci_vtblk_iov_read(io->io_req.br_iov,
		    io->io_req.br_iovcnt, 0, &discard, sizeof(discard))) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}

		/*
		 * VirtIO 1.4 section 5.2.6.2:
		 * The device MUST set the status byte to VIRTIO_BLK_S_UNSUPP
		 * for discard and write zeroes commands if any unknown flag is
		 * set. Furthermore, the device MUST set the status byte to
		 * VIRTIO_BLK_S_UNSUPP for discard commands if the unmap flag
		 * is set.
		 *
		 * UNMAP is valid only for WRITE ZEROES.  The backend still
		 * writes actual zeroes, so write_zeroes_may_unmap remains zero.
		 */
		if ((type == VBH_OP_DISCARD && le32toh(discard.flags) != 0) ||
		    (type == VBH_OP_WRITE_ZEROES &&
		    (le32toh(discard.flags) &
		    ~VTBLK_WRITE_ZEROES_FLAG_UNMAP) != 0)) {
			pci_vtblk_done_locked(io, EOPNOTSUPP);
			return;
		}

		/* Make sure the request doesn't exceed our size limit. */
		sectors = le32toh(discard.num_sectors);
		if ((type == VBH_OP_DISCARD &&
		    sectors > VTBLK_MAX_DISCARD_SECT) ||
		    (type == VBH_OP_WRITE_ZEROES &&
		    sectors > VTBLK_MAX_WRITE_ZEROES_SECT) ||
		    le64toh(discard.sector) >
		    (uint64_t)OFF_MAX / VTBLK_BSIZE) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}
		sector = le64toh(discard.sector);
		if (sector > sc->vbsc_cfg.vbc_capacity ||
		    sectors > sc->vbsc_cfg.vbc_capacity - sector) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}

		io->io_req.br_offset = sector * VTBLK_BSIZE;
		io->io_req.br_resid = (ssize_t)sectors * VTBLK_BSIZE;
		if (type == VBH_OP_DISCARD)
			err = blockif_delete(sc->bc, &io->io_req);
		else
			err = blockif_write_zeroes(sc->bc, &io->io_req);
		break;
	case VBH_OP_FLUSH:
	case VBH_OP_FLUSH_OUT:
		err = blockif_flush(sc->bc, &io->io_req);
		break;
	case VBH_OP_IDENT:
		if (iolen != VTBLK_BLK_ID_LEN) {
			pci_vtblk_done_locked(io, EINVAL);
			return;
		}
		/* The serial number is padded with zeroes, not terminated. */
		for (i = 0; i < io->io_req.br_iovcnt; i++)
			memset(io->io_req.br_iov[i].iov_base, 0,
			    io->io_req.br_iov[i].iov_len);
		for (i = 0, err = 0; i < io->io_req.br_iovcnt &&
		    err < VTBLK_BLK_ID_LEN; i++) {
			size_t len;

			len = MIN(io->io_req.br_iov[i].iov_len,
			    (size_t)VTBLK_BLK_ID_LEN - err);
			memcpy(io->io_req.br_iov[i].iov_base,
			    sc->vbsc_ident + err, len);
			err += len;
		}
		io->io_req.br_resid = 0;
		pci_vtblk_done_locked(io, 0);
		return;
	default:
		pci_vtblk_done_locked(io, EOPNOTSUPP);
		return;
	}
	if (err != 0)
		pci_vtblk_done_locked(io, err);
}

static void
pci_vtblk_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtblk_softc *sc = vsc;

	while (vq_has_descs(vq))
		pci_vtblk_proc(sc, vq);
	vq_endchains(vq, 1);
}

static void
pci_vtblk_resized(struct blockif_ctxt *bctxt __unused, void *arg,
    size_t new_size)
{
	struct pci_vtblk_softc *sc;
	struct virtio_softc *vs;

	sc = arg;
	vs = &sc->vbsc_vs;

	VS_LOCK(vs);
	sc->vbsc_cfg.vbc_capacity = new_size / VTBLK_BSIZE; /* 512-byte units */
	vi_pci_config_changed(vs);
	VS_UNLOCK(vs);
}

static uint64_t
pci_vtblk_backend_caps(struct blockif_ctxt *bc)
{
	uint64_t caps;

	caps = VTBLK_S_HOSTCAPS | VIRTIO_F_RING_RESET;
	if (blockif_is_ro(bc))
		caps |= VTBLK_F_RO;
	else {
		caps |= VTBLK_F_WRITE_ZEROES;
		if (blockif_candelete(bc))
			caps |= VTBLK_F_DISCARD;
	}
	return (caps);
}

static void
pci_vtblk_configure_range_limits(struct pci_vtblk_softc *sc, int sectsz,
    int psectsz)
{

	sc->vbsc_cfg.max_discard_sectors = VTBLK_MAX_DISCARD_SECT;
	sc->vbsc_cfg.max_discard_seg = VTBLK_MAX_DISCARD_SEG;
	sc->vbsc_cfg.discard_sector_alignment =
	    MAX(sectsz, psectsz) / VTBLK_BSIZE;
	if ((sc->vbsc_consts.vc_hv_caps & VTBLK_F_WRITE_ZEROES) != 0) {
		sc->vbsc_cfg.max_write_zeroes_sectors =
		    VTBLK_MAX_WRITE_ZEROES_SECT;
		sc->vbsc_cfg.max_write_zeroes_seg =
		    VTBLK_MAX_WRITE_ZEROES_SEG;
		sc->vbsc_cfg.write_zeroes_may_unmap = 0;
	}
}

static int
pci_vtblk_parse_queues(const char *value, uint16_t *nqueues,
    const char **errstr)
{
	long parsed;

	*errstr = NULL;
	if (value == NULL) {
		*nqueues = 1;
		return (0);
	}
	parsed = strtonum(value, 1, VTBLK_MAXQ, errstr);
	if (*errstr != NULL)
		return (EINVAL);
	*nqueues = (uint16_t)parsed;
	return (0);
}

static int
pci_vtblk_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	char bident[sizeof("XXX:XXX")];
	struct blockif_ctxt *bctxt;
	const char *errstr, *path, *queues_value, *serial;
	MD5_CTX mdctx;
	u_char digest[16];
	struct pci_vtblk_softc *sc;
	bool intr_initialized;
	off_t size;
	uint16_t nqueues;
	int i, sectsz, sts, sto;

	/*
	 * The supplied backing file has to exist
	 */
	queues_value = get_config_value_node(nvl, "queues");
	if (pci_vtblk_parse_queues(queues_value, &nqueues, &errstr) != 0) {
		EPRINTLN("virtio-blk queues is %s: %s", errstr, queues_value);
		return (1);
	}
	snprintf(bident, sizeof(bident), "%u:%u", pi->pi_slot, pi->pi_func);
	bctxt = blockif_open(nvl, bident);
	if (bctxt == NULL) {
		perror("Could not open backing file");
		return (1);
	}

	size = blockif_size(bctxt);
	sectsz = blockif_sectsz(bctxt);
	blockif_psectsz(bctxt, &sts, &sto);

	sc = calloc(1, sizeof(struct pci_vtblk_softc));
	if (sc == NULL) {
		blockif_close(bctxt);
		return (1);
	}
	intr_initialized = false;
	sc->bc = bctxt;
	sc->vbsc_nqueues = nqueues;
	sc->vbsc_ios = calloc(sc->vbsc_nqueues * VTBLK_RINGSZ,
	    sizeof(*sc->vbsc_ios));
	if (sc->vbsc_ios == NULL)
		goto failed_early;
	for (i = 0; i < sc->vbsc_nqueues * VTBLK_RINGSZ; i++) {
		struct pci_vtblk_ioreq *io = &sc->vbsc_ios[i];
		io->io_req.br_callback = pci_vtblk_done;
		io->io_req.br_param = io;
		io->io_sc = sc;
		io->io_idx = i % VTBLK_RINGSZ;
	}

	bcopy(&vtblk_vi_consts, &sc->vbsc_consts, sizeof (vtblk_vi_consts));
	sc->vbsc_consts.vc_hv_caps = pci_vtblk_backend_caps(sc->bc);
	sc->vbsc_consts.vc_nvq = sc->vbsc_nqueues;

	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0) {
		blockif_close(sc->bc);
		free(sc->vbsc_ios);
		free(sc);
		return (1);
	}
	if (pthread_cond_init(&sc->vbsc_reset_cond, NULL) != 0) {
		pthread_mutex_destroy(&sc->vsc_mtx);
		blockif_close(sc->bc);
		free(sc->vbsc_ios);
		free(sc);
		return (1);
	}

	/* init virtio softc and virtqueues */
	vi_softc_linkup(&sc->vbsc_vs, &sc->vbsc_consts, sc, pi,
	    sc->vbsc_vqs);
	sc->vbsc_vs.vs_mtx = &sc->vsc_mtx;

	for (i = 0; i < sc->vbsc_nqueues; i++)
		sc->vbsc_vqs[i].vq_qsize = VTBLK_RINGSZ;
	if (vi_pci_select_transport(&sc->vbsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto failed;
	if (sc->vbsc_nqueues > 1 && !vi_pci_is_modern(&sc->vbsc_vs)) {
		EPRINTLN("virtio-blk queues requires transport=modern");
		goto failed;
	}
	if (sc->vbsc_nqueues > 1)
		sc->vbsc_consts.vc_hv_caps |= VTBLK_F_MQ;

	/*
	 * If an explicit identifier is not given, create an
	 * identifier using parts of the md5 sum of the filename.
	 */
	bzero(sc->vbsc_ident, VTBLK_BLK_ID_BYTES);
	if ((serial = get_config_value_node(nvl, "serial")) != NULL ||
	    (serial = get_config_value_node(nvl, "ser")) != NULL) {
		strlcpy(sc->vbsc_ident, serial, VTBLK_BLK_ID_BYTES);
	} else {
		path = get_config_value_node(nvl, "path");
		MD5Init(&mdctx);
		MD5Update(&mdctx, path, strlen(path));
		MD5Final(digest, &mdctx);
		snprintf(sc->vbsc_ident, VTBLK_BLK_ID_BYTES,
		    "BHYVE-%02X%02X-%02X%02X-%02X%02X",
		    digest[0], digest[1], digest[2], digest[3], digest[4],
		    digest[5]);
	}

	/* setup virtio block config space */
	sc->vbsc_cfg.vbc_capacity = size / VTBLK_BSIZE; /* 512-byte units */
	sc->vbsc_cfg.vbc_size_max = 0;	/* not negotiated */

	/*
	 * If Linux is presented with a seg_max greater than the virtio queue
	 * size, it can stumble into situations where it violates its own
	 * invariants and panics.  For safety, we keep seg_max clamped, paying
	 * heed to the two extra descriptors needed for the header and status
	 * of a request.
	 */
	sc->vbsc_cfg.vbc_seg_max = MIN(VTBLK_RINGSZ - 2, BLOCKIF_IOV_MAX);
	sc->vbsc_cfg.vbc_geometry.cylinders = 0;	/* no geometry */
	sc->vbsc_cfg.vbc_geometry.heads = 0;
	sc->vbsc_cfg.vbc_geometry.sectors = 0;
	sc->vbsc_cfg.vbc_blk_size = sectsz;
	sc->vbsc_cfg.vbc_topology.physical_block_exp =
	    (sts > sectsz) ? (ffsll(sts / sectsz) - 1) : 0;
	sc->vbsc_cfg.vbc_topology.alignment_offset =
	    (sto != 0) ? ((sts - sto) / sectsz) : 0;
	sc->vbsc_cfg.vbc_topology.min_io_size = 0;
	sc->vbsc_cfg.vbc_topology.opt_io_size = 0;
	sc->vbsc_cfg.vbc_writeback = 0;
	sc->vbsc_cfg.num_queues = htole16(sc->vbsc_nqueues);
	pci_vtblk_configure_range_limits(sc, sectsz, sts);

	/*
	 * Should we move some of this into virtio.c?  Could
	 * have the device, class, and subdev_0 as fields in
	 * the virtio constants structure.
	 */
	if (vi_pci_is_modern(&sc->vbsc_vs))
		vi_pci_modern_set_identity(&sc->vbsc_vs, VIRTIO_ID_BLOCK);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_TRANSITIONAL_BLOCK);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_BLOCK);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);

	if (vi_intr_init(&sc->vbsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	intr_initialized = true;
	if (vi_pci_is_modern(&sc->vbsc_vs)) {
		if (vi_pci_modern_init(&sc->vbsc_vs, 2) != 0)
			goto failed;
	} else
		vi_set_io_bar(&sc->vbsc_vs, 0);
	if (blockif_add_boot_device(pi, bctxt)) {
		perror("Invalid boot device");
		goto failed;
	}
	blockif_register_resize_callback(sc->bc, pci_vtblk_resized, sc);
	return (0);

failed:
	blockif_close(sc->bc);
	free(sc->vbsc_vs.vs_modern);
	free(sc->vbsc_ios);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vbsc_vs.vs_isr_mtx);
	pthread_cond_destroy(&sc->vbsc_reset_cond);
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc);
	return (1);

failed_early:
	blockif_close(sc->bc);
	free(sc->vbsc_ios);
	free(sc);
	return (1);
}

static int
pci_vtblk_cfgwrite(void *vsc __unused, int offset, int size __unused,
    uint32_t value __unused)
{

	DPRINTF(("vtblk: write to readonly reg %d", offset));
	return (1);
}

static int
pci_vtblk_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtblk_softc *sc = vsc;
	void *ptr;

	*retval = 0;
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(sc->vbsc_cfg) ||
	    (size_t)size > sizeof(sc->vbsc_cfg) - (size_t)offset)
		return (EINVAL);
	ptr = (uint8_t *)&sc->vbsc_cfg + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static const struct pci_devemu pci_de_vblk = {
	.pe_emu =	"virtio-blk",
	.pe_init =	pci_vtblk_init,
	.pe_legacy_config = blockif_legacy_config,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	vi_pci_snapshot,
	.pe_pause =     vi_pci_pause,
	.pe_resume =    vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vblk);
