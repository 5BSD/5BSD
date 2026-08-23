/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * VirtIO sound (virtio-snd) guest driver.
 *
 * Bridges a VIRTIO sound device (as implemented by the in-tree bhyve backend)
 * to the FreeBSD pcm(4) framework.  A single playback (TX) and a single
 * capture (RX) PCM stream are exported at S16_LE, stereo, 44.1/48 kHz -- the
 * format/rate set the device advertises.
 *
 * The implementation speaks the VIRTIO wire protocol directly (see
 * virtio_snd.h); it is not derived from any GPL implementation.
 *
 * Design notes / scope of this first pass:
 *   - Control queue commands are issued synchronously via virtqueue_poll();
 *     the control virtqueue therefore keeps its interrupt disabled.
 *   - The TX/RX data path stages one period at a time through a coherent DMA
 *     bounce buffer per stream and re-arms on completion.  A single transfer
 *     is kept in flight per stream (period-granular latency).
 *   - Both split and packed rings are supported implicitly: the shared
 *     virtqueue(9) layer handles packed rings once VIRTIO_F_RING_PACKED is
 *     negotiated, and this driver only uses the transport-neutral API.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/endian.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

#ifdef HAVE_KERNEL_OPTION_HEADERS
#include "opt_snd.h"
#endif
#include <dev/sound/pcm/sound.h>
#include <mixer_if.h>

#include "virtio_snd.h"

/*
 * Feature bits this driver is willing to accept.  VIRTIO_F_VERSION_1 is added
 * by the modern transport.  There are no virtio-snd device-specific feature
 * bits used here (the bhyve backend advertises controls=0, so VIRTIO_SND_F_CTLS
 * is neither offered nor needed).
 */
#define	VTSND_FEATURES							\
	(VIRTIO_RING_F_INDIRECT_DESC | VIRTIO_RING_F_EVENT_IDX |		\
	 VIRTIO_F_RING_PACKED | VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND)

#define	VTSND_NEVENTBUF		4	/* event-queue receive buffers */
#define	VTSND_MAXBUF		65536	/* max PCM ring / staging buffer */
#define	VTSND_SG_MAX		4	/* max segments in one descriptor chain */

#define	VTSND_STREAM_TX		0	/* stream id 0: playback (output) */
#define	VTSND_STREAM_RX		1	/* stream id 1: capture (input)   */
#define	VTSND_NSTREAM		2

static MALLOC_DEFINE(M_VTSND, "virtio_snd", "VirtIO sound driver");

struct vtsnd_softc;

struct vtsnd_dma {
	bus_dma_tag_t	dma_tag;
	bus_dmamap_t	dma_map;
	void		*dma_vaddr;
	bus_addr_t	dma_paddr;
	bus_size_t	dma_size;
};

struct vtsnd_chan {
	struct vtsnd_softc *sc;
	struct pcm_channel *chan;
	struct snd_dbuf	*buf;
	int		 dir;		/* PCMDIR_PLAY / PCMDIR_REC */
	uint32_t	 stream_id;	/* VTSND_STREAM_TX / _RX */
	int		 vq_idx;	/* VTSND_VQ_TX / VTSND_VQ_RX */
	uint32_t	 ptr;		/* hw pointer into the sndbuf ring */
	uint32_t	 blksz;		/* current period size (bytes) */
	uint32_t	 bufsz;		/* current ring size (bytes) */
	uint32_t	 speed;		/* requested sample rate (Hz) */
	uint8_t		 rate_code;	/* VIRTIO_SND_PCM_RATE_* */
	bool		 running;
	bool		 inflight;	/* a data buffer is outstanding */
	bool		 prepared;	/* stream prepared/params set */
	struct vtsnd_dma data;		/* per-period staging buffer */
	struct vtsnd_dma xhdr;		/* xfer header (stream_id)   */
	struct vtsnd_dma status;	/* pcm_status writeback      */
};

struct vtsnd_softc {
	/*
	 * pcm_init() and the whole pcm(4) framework treat the device softc as a
	 * struct snddev_info; it MUST be the first member.
	 */
	struct snddev_info	vtsnd_info;
	device_t		vtsnd_dev;
	uint64_t		vtsnd_features;
	struct mtx		vtsnd_mtx;
	struct virtqueue	*vtsnd_vqs[VTSND_VQ_MAX];
	struct sglist		*vtsnd_sg;
	struct vtsnd_dma	vtsnd_creq;	/* control request staging  */
	struct vtsnd_dma	vtsnd_cresp;	/* control response staging */
	struct vtsnd_dma	vtsnd_evt[VTSND_NEVENTBUF];
	struct vtsnd_chan	vtsnd_chans[VTSND_NSTREAM];
	int			vtsnd_nchan;
	uint32_t		vtsnd_streams;
	uint32_t		vtsnd_cap_fmts[2];
	struct pcmchan_caps	vtsnd_caps;
	bool			vtsnd_detaching;
	bool			vtsnd_suspended;
	bool			vtsnd_ctrl_busy;	/* control cmd in flight */
	bool			vtsnd_broken;		/* control queue wedged */
};

/*
 * Upper bound on how long a single control command may wait for the device to
 * retire it.  A device that accepts the descriptor but never completes it must
 * not hang the caller (and the softc lock) forever; the wait is bounded and the
 * control queue is then declared broken.
 */
#define	VTSND_CTRL_TIMEOUT	(5 * SBT_1S)

#define	VTSND_LOCK(sc)		mtx_lock(&(sc)->vtsnd_mtx)
#define	VTSND_UNLOCK(sc)	mtx_unlock(&(sc)->vtsnd_mtx)
#define	VTSND_LOCK_ASSERT(sc)	mtx_assert(&(sc)->vtsnd_mtx, MA_OWNED)

static int	vtsnd_probe(device_t);
static int	vtsnd_attach(device_t);
static int	vtsnd_detach(device_t);
static int	vtsnd_suspend(device_t);
static int	vtsnd_resume(device_t);

static int	vtsnd_negotiate_features(struct vtsnd_softc *);
static int	vtsnd_alloc_virtqueues(struct vtsnd_softc *);
static void	vtsnd_control_vq_intr(void *);
static void	vtsnd_event_vq_intr(void *);
static void	vtsnd_tx_vq_intr(void *);
static void	vtsnd_rx_vq_intr(void *);

static int	vtsnd_dma_alloc(struct vtsnd_softc *, bus_size_t,
		    struct vtsnd_dma *);
static void	vtsnd_dma_free(struct vtsnd_dma *);

static int	vtsnd_ctrl_cmd(struct vtsnd_softc *, const void *, size_t,
		    void *, size_t, uint32_t *);
static int	vtsnd_pcm_set_params(struct vtsnd_softc *, struct vtsnd_chan *);
static int	vtsnd_pcm_lifecycle(struct vtsnd_softc *, struct vtsnd_chan *,
		    uint32_t);
static int	vtsnd_pcm_info_query(struct vtsnd_softc *);

static int	vtsnd_event_populate(struct vtsnd_softc *);
static int	vtsnd_tx_submit(struct vtsnd_chan *);
static int	vtsnd_rx_submit(struct vtsnd_chan *);
static void	vtsnd_chan_stop(struct vtsnd_softc *, struct vtsnd_chan *);

static struct virtio_feature_desc vtsnd_feature_desc[] = {
	{ VIRTIO_F_RING_PACKED,		"RingPacked"	},
	{ VIRTIO_F_RING_RESET,		"RingReset"	},
	{ VIRTIO_F_SUSPEND,		"Suspend"	},
	{ 0, NULL }
};

/*
 * DMA helpers.  Each staging buffer gets its own tag; buffers are small and
 * few, and this keeps allocation/teardown trivial and single-segment.
 */
static void
vtsnd_dma_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{

	if (error == 0)
		*(bus_addr_t *)arg = segs[0].ds_addr;
}

static int
vtsnd_dma_alloc(struct vtsnd_softc *sc, bus_size_t size, struct vtsnd_dma *dma)
{
	int error;

	bzero(dma, sizeof(*dma));
	dma->dma_size = size;

	error = bus_dma_tag_create(bus_get_dma_tag(sc->vtsnd_dev),
	    1, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    size,			/* maxsize */
	    1,				/* nsegments */
	    size,			/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &dma->dma_tag);
	if (error != 0) {
		device_printf(sc->vtsnd_dev, "cannot create DMA tag: %d\n",
		    error);
		return (error);
	}

	error = bus_dmamem_alloc(dma->dma_tag, &dma->dma_vaddr,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT | BUS_DMA_ZERO, &dma->dma_map);
	if (error != 0) {
		device_printf(sc->vtsnd_dev, "cannot alloc DMA memory: %d\n",
		    error);
		bus_dma_tag_destroy(dma->dma_tag);
		dma->dma_tag = NULL;
		return (error);
	}

	error = bus_dmamap_load(dma->dma_tag, dma->dma_map, dma->dma_vaddr,
	    size, vtsnd_dma_cb, &dma->dma_paddr, BUS_DMA_NOWAIT);
	if (error != 0 || dma->dma_paddr == 0) {
		device_printf(sc->vtsnd_dev, "cannot load DMA map: %d\n",
		    error);
		bus_dmamem_free(dma->dma_tag, dma->dma_vaddr, dma->dma_map);
		bus_dma_tag_destroy(dma->dma_tag);
		bzero(dma, sizeof(*dma));
		return (error != 0 ? error : ENOMEM);
	}

	return (0);
}

static void
vtsnd_dma_free(struct vtsnd_dma *dma)
{

	if (dma->dma_tag == NULL)
		return;
	if (dma->dma_paddr != 0)
		bus_dmamap_unload(dma->dma_tag, dma->dma_map);
	if (dma->dma_vaddr != NULL)
		bus_dmamem_free(dma->dma_tag, dma->dma_vaddr, dma->dma_map);
	bus_dma_tag_destroy(dma->dma_tag);
	bzero(dma, sizeof(*dma));
}

/*
 * Synchronous control-queue command.  The single control request/response
 * staging pair is shared, so concurrent callers are serialized through
 * vtsnd_ctrl_busy: the softc lock is dropped while sleeping for completion, so
 * a plain lock-held spin no longer provides that exclusion.  Completion is
 * awaited with a bounded deadline (the control-queue interrupt wakes the
 * sleeper); a device that never retires the descriptor times out and wedges the
 * control queue rather than hanging the caller forever.
 */
static int
vtsnd_ctrl_cmd(struct vtsnd_softc *sc, const void *req, size_t reqlen,
    void *resp, size_t resplen, uint32_t *respused)
{
	struct virtqueue *vq;
	struct sglist *sg;
	sbintime_t deadline, remaining;
	void *cookie;
	uint32_t len;
	int error;

	VTSND_LOCK_ASSERT(sc);
	KASSERT(reqlen <= sc->vtsnd_creq.dma_size, ("ctrl req too large"));
	KASSERT(resplen <= sc->vtsnd_cresp.dma_size, ("ctrl resp too large"));

	vq = sc->vtsnd_vqs[VTSND_VQ_CONTROL];
	sg = sc->vtsnd_sg;

	while (sc->vtsnd_ctrl_busy && !sc->vtsnd_broken)
		msleep(&sc->vtsnd_ctrl_busy, &sc->vtsnd_mtx, 0, "vtsndcb", 0);
	if (sc->vtsnd_broken)
		return (EIO);
	sc->vtsnd_ctrl_busy = true;

	memcpy(sc->vtsnd_creq.dma_vaddr, req, reqlen);
	bzero(sc->vtsnd_cresp.dma_vaddr, resplen);
	bus_dmamap_sync(sc->vtsnd_creq.dma_tag, sc->vtsnd_creq.dma_map,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(sc->vtsnd_cresp.dma_tag, sc->vtsnd_cresp.dma_map,
	    BUS_DMASYNC_PREREAD);

	sglist_reset(sg);
	error = sglist_append_phys(sg, sc->vtsnd_creq.dma_paddr, reqlen);
	if (error == 0)
		error = sglist_append_phys_boundary(sg,
		    sc->vtsnd_cresp.dma_paddr,
		    resplen);
	if (error != 0)
		goto release;

	error = virtqueue_enqueue(vq, sc, sg, 1, 1);
	if (error != 0)
		goto release;
	virtqueue_notify(vq);

	/*
	 * Wait for the device to retire the descriptor.  Enable the control
	 * interrupt and re-check before sleeping so a completion racing the
	 * enqueue is never missed; bound the wait so a wedged device cannot hang
	 * the control path (and the shared staging buffers) indefinitely.
	 */
	deadline = sbinuptime() + VTSND_CTRL_TIMEOUT;
	for (;;) {
		cookie = virtqueue_dequeue(vq, &len);
		if (cookie != NULL)
			break;
		if (virtqueue_enable_intr(vq) != 0)
			continue;
		remaining = deadline - sbinuptime();
		if (remaining <= 0) {
			error = ETIMEDOUT;
			break;
		}
		error = msleep_sbt(sc, &sc->vtsnd_mtx, 0, "vtsndc", remaining,
		    0, 0);
		if (error == EWOULDBLOCK) {
			error = ETIMEDOUT;
			break;
		}
		if (error != 0)
			break;
	}
	virtqueue_disable_intr(vq);

	if (cookie == NULL) {
		/*
		 * The descriptor is still outstanding against the shared staging
		 * buffers.  Declare the control queue broken so the buffers are
		 * never reused; the device is reset (reclaiming the descriptor)
		 * at detach before they are freed.
		 */
		device_printf(sc->vtsnd_dev,
		    "control command did not complete (%d)\n", error);
		sc->vtsnd_broken = true;
		if (error == 0)
			error = EIO;
		goto release;
	}

	bus_dmamap_sync(sc->vtsnd_creq.dma_tag, sc->vtsnd_creq.dma_map,
	    BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(sc->vtsnd_cresp.dma_tag, sc->vtsnd_cresp.dma_map,
	    BUS_DMASYNC_POSTREAD);

	if (cookie != sc) {
		error = EIO;
		goto release;
	}
	if (resp != NULL && resplen > 0)
		memcpy(resp, sc->vtsnd_cresp.dma_vaddr, resplen);
	if (respused != NULL)
		*respused = len;
	error = 0;

release:
	sc->vtsnd_ctrl_busy = false;
	wakeup(&sc->vtsnd_ctrl_busy);
	return (error);
}

static int
vtsnd_ctrl_status_ok(struct vtsnd_softc *sc, const void *req, size_t reqlen)
{
	uint8_t resp[VTSND_HDR_SIZE];
	uint32_t status;
	int error;

	error = vtsnd_ctrl_cmd(sc, req, reqlen, resp, sizeof(resp), NULL);
	if (error != 0)
		return (error);
	status = le32dec(resp);
	if (status != VIRTIO_SND_S_OK) {
		device_printf(sc->vtsnd_dev,
		    "control command failed, status 0x%04x\n", status);
		return (EIO);
	}
	return (0);
}

/*
 * VIRTIO_SND_R_PCM_INFO: query the device's stream table.  Used at attach to
 * confirm the device really exposes S16 output+input at a supported rate; a
 * mismatch fails attach closed.
 */
static int
vtsnd_pcm_info_query(struct vtsnd_softc *sc)
{
	uint8_t req[VTSND_QUERY_INFO_SIZE];
	uint8_t resp[VTSND_HDR_SIZE + VTSND_NSTREAM * VTSND_PCM_INFO_SIZE];
	uint32_t status;
	size_t resplen;
	int error;

	KASSERT(sc->vtsnd_streams <= VTSND_NSTREAM, ("too many streams"));
	resplen = VTSND_HDR_SIZE +
	    (size_t)sc->vtsnd_streams * VTSND_PCM_INFO_SIZE;

	le32enc(req + 0, VIRTIO_SND_R_PCM_INFO);
	le32enc(req + 4, 0);			/* start_id */
	le32enc(req + 8, sc->vtsnd_streams);	/* count */
	le32enc(req + 12, VTSND_PCM_INFO_SIZE);	/* size */

	VTSND_LOCK(sc);
	error = vtsnd_ctrl_cmd(sc, req, sizeof(req), resp, resplen, NULL);
	VTSND_UNLOCK(sc);
	if (error != 0)
		return (error);

	status = le32dec(resp);
	if (status != VIRTIO_SND_S_OK) {
		device_printf(sc->vtsnd_dev,
		    "PCM_INFO query failed, status 0x%04x\n", status);
		return (EIO);
	}

	for (uint32_t i = 0; i < sc->vtsnd_streams; i++) {
		const uint8_t *info = resp + VTSND_HDR_SIZE +
		    (size_t)i * VTSND_PCM_INFO_SIZE;
		uint64_t formats, rates;
		uint8_t direction, ch_max;

		formats = le64dec(info + 8);
		rates = le64dec(info + 16);
		direction = info[24];
		ch_max = info[26];

		/*
		 * The channel/virtqueue bindings are fixed: stream 0 is
		 * playback (OUTPUT), stream 1 is capture (INPUT).  The
		 * specification orders streams by direction the same way but a
		 * device is only bound by its per-stream direction field, so
		 * verify it rather than misdirecting PCM data.
		 */
		if (direction != (i == VTSND_STREAM_TX ?
		    VIRTIO_SND_D_OUTPUT : VIRTIO_SND_D_INPUT)) {
			device_printf(sc->vtsnd_dev,
			    "stream %u has unexpected direction %u\n", i,
			    direction);
			return (ENXIO);
		}
		if ((formats & (UINT64_C(1) << VIRTIO_SND_PCM_FMT_S16)) == 0) {
			device_printf(sc->vtsnd_dev,
			    "stream %u lacks S16 support\n", i);
			return (ENXIO);
		}
		if ((rates & ((UINT64_C(1) << VIRTIO_SND_PCM_RATE_44100) |
		    (UINT64_C(1) << VIRTIO_SND_PCM_RATE_48000))) == 0) {
			device_printf(sc->vtsnd_dev,
			    "stream %u lacks 44.1/48 kHz support\n", i);
			return (ENXIO);
		}
		if (bootverbose) {
			device_printf(sc->vtsnd_dev,
			    "stream %u: dir=%u ch_max=%u formats=%#jx "
			    "rates=%#jx\n", i, direction, ch_max,
			    (uintmax_t)formats, (uintmax_t)rates);
		}
	}

	return (0);
}

static int
vtsnd_pcm_set_params(struct vtsnd_softc *sc, struct vtsnd_chan *ch)
{
	uint8_t req[VTSND_PCM_SET_PARAMS_SIZE];

	VTSND_LOCK_ASSERT(sc);

	le32enc(req + 0, VIRTIO_SND_R_PCM_SET_PARAMS);
	le32enc(req + 4, ch->stream_id);
	le32enc(req + 8, ch->bufsz);		/* buffer_bytes */
	le32enc(req + 12, ch->blksz);		/* period_bytes */
	le32enc(req + 16, 0);			/* features */
	req[20] = 2;				/* channels (stereo) */
	req[21] = VIRTIO_SND_PCM_FMT_S16;	/* format */
	req[22] = ch->rate_code;		/* rate */
	req[23] = 0;				/* padding */

	return (vtsnd_ctrl_status_ok(sc, req, sizeof(req)));
}

static int
vtsnd_pcm_lifecycle(struct vtsnd_softc *sc, struct vtsnd_chan *ch,
    uint32_t code)
{
	uint8_t req[VTSND_PCM_HDR_SIZE];

	VTSND_LOCK_ASSERT(sc);

	le32enc(req + 0, code);
	le32enc(req + 4, ch->stream_id);

	return (vtsnd_ctrl_status_ok(sc, req, sizeof(req)));
}

/*
 * Data-path submission.  One period per descriptor chain, one chain in flight.
 */
static int
vtsnd_tx_submit(struct vtsnd_chan *ch)
{
	struct vtsnd_softc *sc = ch->sc;
	struct virtqueue *vq = sc->vtsnd_vqs[ch->vq_idx];
	struct sglist *sg = sc->vtsnd_sg;
	uint8_t *src;
	uint32_t first, blksz;
	int error;

	VTSND_LOCK_ASSERT(sc);

	if (ch->inflight || ch->bufsz == 0 || ch->blksz == 0)
		return (0);

	blksz = ch->blksz;
	src = (uint8_t *)ch->buf->buf;

	/* Copy one period from the pcm ring into the DMA staging buffer. */
	first = ch->ptr;
	if (first + blksz <= ch->bufsz) {
		memcpy(ch->data.dma_vaddr, src + first, blksz);
	} else {
		uint32_t head = ch->bufsz - first;

		memcpy(ch->data.dma_vaddr, src + first, head);
		memcpy((uint8_t *)ch->data.dma_vaddr + head, src, blksz - head);
	}
	bus_dmamap_sync(ch->data.dma_tag, ch->data.dma_map,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(ch->status.dma_tag, ch->status.dma_map,
	    BUS_DMASYNC_PREREAD);

	sglist_reset(sg);
	error = sglist_append_phys(sg, ch->xhdr.dma_paddr, VTSND_PCM_XFER_SIZE);
	if (error == 0)
		error = sglist_append_phys(sg, ch->data.dma_paddr, blksz);
	if (error == 0)
		error = sglist_append_phys_boundary(sg,
		    ch->status.dma_paddr,
		    VTSND_PCM_STATUS_SIZE);
	if (error != 0)
		return (error);

	/* readable: xfer hdr + data; writable: status */
	error = virtqueue_enqueue(vq, ch, sg, 2, 1);
	if (error != 0)
		return (error);
	virtqueue_notify(vq);
	ch->inflight = true;

	return (0);
}

static int
vtsnd_rx_submit(struct vtsnd_chan *ch)
{
	struct vtsnd_softc *sc = ch->sc;
	struct virtqueue *vq = sc->vtsnd_vqs[ch->vq_idx];
	struct sglist *sg = sc->vtsnd_sg;
	uint32_t blksz;
	int error;

	VTSND_LOCK_ASSERT(sc);

	if (ch->inflight || ch->bufsz == 0 || ch->blksz == 0)
		return (0);

	blksz = ch->blksz;
	bus_dmamap_sync(ch->data.dma_tag, ch->data.dma_map,
	    BUS_DMASYNC_PREREAD);
	bus_dmamap_sync(ch->status.dma_tag, ch->status.dma_map,
	    BUS_DMASYNC_PREREAD);

	sglist_reset(sg);
	error = sglist_append_phys(sg, ch->xhdr.dma_paddr, VTSND_PCM_XFER_SIZE);
	if (error == 0)
		error = sglist_append_phys_boundary(sg, ch->data.dma_paddr,
		    blksz);
	if (error == 0)
		error = sglist_append_phys(sg, ch->status.dma_paddr,
		    VTSND_PCM_STATUS_SIZE);
	if (error != 0)
		return (error);

	/* readable: xfer hdr; writable: data + status */
	error = virtqueue_enqueue(vq, ch, sg, 1, 2);
	if (error != 0)
		return (error);
	virtqueue_notify(vq);
	ch->inflight = true;

	return (0);
}

/*
 * Event queue: post receive buffers and (re)consume notifications.  This
 * driver does not act on period-elapsed / jack events (it drives the ring
 * itself), it only recycles the buffers and optionally logs.
 */
static int
vtsnd_event_populate(struct vtsnd_softc *sc)
{
	struct virtqueue *vq = sc->vtsnd_vqs[VTSND_VQ_EVENT];
	struct sglist *sg = sc->vtsnd_sg;
	int error, i;

	VTSND_LOCK_ASSERT(sc);

	for (i = 0; i < VTSND_NEVENTBUF; i++) {
		bus_dmamap_sync(sc->vtsnd_evt[i].dma_tag,
		    sc->vtsnd_evt[i].dma_map, BUS_DMASYNC_PREREAD);
		sglist_reset(sg);
		error = sglist_append_phys(sg, sc->vtsnd_evt[i].dma_paddr,
		    VTSND_EVENT_SIZE);
		if (error != 0)
			return (error);
		error = virtqueue_enqueue(vq, &sc->vtsnd_evt[i], sg, 0, 1);
		if (error != 0)
			return (error);
	}
	virtqueue_notify(vq);

	return (0);
}

static void
vtsnd_event_vq_intr(void *xsc)
{
	struct vtsnd_softc *sc = xsc;
	struct virtqueue *vq = sc->vtsnd_vqs[VTSND_VQ_EVENT];
	struct sglist *sg = sc->vtsnd_sg;
	struct vtsnd_dma *evt;
	uint32_t len;

	VTSND_LOCK(sc);
again:
	while ((evt = virtqueue_dequeue(vq, &len)) != NULL) {
		if (bootverbose && len >= VTSND_EVENT_SIZE) {
			bus_dmamap_sync(evt->dma_tag, evt->dma_map,
			    BUS_DMASYNC_POSTREAD);
			device_printf(sc->vtsnd_dev, "event 0x%08x\n",
			    le32dec(evt->dma_vaddr));
		}
		if (sc->vtsnd_detaching)
			continue;
		/* Recycle the buffer. */
		bus_dmamap_sync(evt->dma_tag, evt->dma_map,
		    BUS_DMASYNC_PREREAD);
		sglist_reset(sg);
		if (sglist_append_phys(sg, evt->dma_paddr,
		    VTSND_EVENT_SIZE) == 0)
			(void)virtqueue_enqueue(vq, evt, sg, 0, 1);
	}
	if (!sc->vtsnd_detaching)
		virtqueue_notify(vq);
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}
	VTSND_UNLOCK(sc);
}

static void
vtsnd_data_complete(struct vtsnd_softc *sc, struct virtqueue *vq, bool play)
{
	struct vtsnd_chan *ch;
	uint32_t len;

	VTSND_LOCK_ASSERT(sc);

again:
	while ((ch = virtqueue_dequeue(vq, &len)) != NULL) {
		ch->inflight = false;

		/*
		 * A completion can retire after detach has drained the queue in
		 * vtsnd_chan_stop() (e.g. a misbehaving device retiring a
		 * descriptor late, after RELEASE failed or timed out).  By then
		 * pcm_unregister() may have freed ch->chan and the sndbuf, so
		 * do not touch any pcm(4) state once detach has begun.
		 */
		if (sc->vtsnd_detaching)
			continue;

		if (!play) {
			uint32_t blksz = ch->blksz;
			uint8_t *dst = (uint8_t *)ch->buf->buf;
			uint32_t first = ch->ptr;

			bus_dmamap_sync(ch->data.dma_tag, ch->data.dma_map,
			    BUS_DMASYNC_POSTREAD);
			if (blksz != 0 && ch->bufsz != 0) {
				if (first + blksz <= ch->bufsz) {
					memcpy(dst + first, ch->data.dma_vaddr,
					    blksz);
				} else {
					uint32_t head = ch->bufsz - first;

					memcpy(dst + first, ch->data.dma_vaddr,
					    head);
					memcpy(dst, (uint8_t *)
					    ch->data.dma_vaddr + head,
					    blksz - head);
				}
			}
		} else {
			bus_dmamap_sync(ch->data.dma_tag, ch->data.dma_map,
			    BUS_DMASYNC_POSTWRITE);
		}
		bus_dmamap_sync(ch->status.dma_tag, ch->status.dma_map,
		    BUS_DMASYNC_POSTREAD);

		if (ch->blksz != 0 && ch->bufsz != 0)
			ch->ptr = (ch->ptr + ch->blksz) % ch->bufsz;

		/* Notify the pcm layer with the driver lock dropped. */
		VTSND_UNLOCK(sc);
		chn_intr(ch->chan);
		VTSND_LOCK(sc);

		if (ch->running && !ch->inflight) {
			if (play)
				(void)vtsnd_tx_submit(ch);
			else
				(void)vtsnd_rx_submit(ch);
		}
	}
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}
}

static void
vtsnd_tx_vq_intr(void *xsc)
{
	struct vtsnd_softc *sc = xsc;

	VTSND_LOCK(sc);
	vtsnd_data_complete(sc, sc->vtsnd_vqs[VTSND_VQ_TX], true);
	VTSND_UNLOCK(sc);
}

static void
vtsnd_rx_vq_intr(void *xsc)
{
	struct vtsnd_softc *sc = xsc;

	VTSND_LOCK(sc);
	vtsnd_data_complete(sc, sc->vtsnd_vqs[VTSND_VQ_RX], false);
	VTSND_UNLOCK(sc);
}

static void
vtsnd_control_vq_intr(void *xsc)
{
	struct vtsnd_softc *sc = xsc;

	/*
	 * The control queue is driven synchronously by vtsnd_ctrl_cmd(), which
	 * enables this interrupt only while waiting for a completion.  Wake the
	 * waiter; it re-checks the used ring under the lock.
	 */
	VTSND_LOCK(sc);
	wakeup(sc);
	VTSND_UNLOCK(sc);
}

/*
 * pcm(4) channel class.
 */
static void *
vtsnd_chan_init(kobj_t obj, void *devinfo, struct snd_dbuf *b,
    struct pcm_channel *c, int dir)
{
	struct vtsnd_softc *sc = devinfo;
	struct vtsnd_chan *ch;
	uint8_t *buf;
	unsigned int bufsz;
	int idx;

	VTSND_LOCK(sc);
	idx = (dir == PCMDIR_PLAY) ? VTSND_STREAM_TX : VTSND_STREAM_RX;
	ch = &sc->vtsnd_chans[idx];
	ch->chan = c;
	ch->buf = b;
	ch->dir = dir;
	sc->vtsnd_nchan++;
	VTSND_UNLOCK(sc);

	bufsz = pcm_getbuffersize(sc->vtsnd_dev, 2048, VTSND_MAXBUF / 4,
	    VTSND_MAXBUF);
	buf = malloc(bufsz, M_VTSND, M_WAITOK | M_ZERO);
	if (sndbuf_setup(b, buf, bufsz) != 0) {
		free(buf, M_VTSND);
		return (NULL);
	}

	return (ch);
}

static int
vtsnd_chan_free(kobj_t obj, void *data)
{
	struct vtsnd_chan *ch = data;
	void *buf;

	buf = ch->buf->buf;
	if (buf != NULL)
		free(buf, M_VTSND);

	return (0);
}

static int
vtsnd_chan_setformat(kobj_t obj, void *data, uint32_t format)
{
	struct vtsnd_chan *ch = data;
	int i;

	for (i = 0; ch->sc->vtsnd_caps.fmtlist[i] != 0; i++) {
		if (format == ch->sc->vtsnd_caps.fmtlist[i])
			return (0);
	}
	return (EINVAL);
}

static uint32_t
vtsnd_chan_setspeed(kobj_t obj, void *data, uint32_t speed)
{
	struct vtsnd_chan *ch = data;

	/* The device offers exactly 44.1 and 48 kHz; snap to the nearest. */
	if (speed >= 46050) {
		ch->speed = 48000;
		ch->rate_code = VIRTIO_SND_PCM_RATE_48000;
	} else {
		ch->speed = 44100;
		ch->rate_code = VIRTIO_SND_PCM_RATE_44100;
	}

	return (ch->speed);
}

static uint32_t
vtsnd_chan_setblocksize(kobj_t obj, void *data, uint32_t blocksize)
{
	struct vtsnd_chan *ch = data;

	return (ch->buf->blksz);
}

static int
vtsnd_chan_trigger(kobj_t obj, void *data, int go)
{
	struct vtsnd_chan *ch = data;
	struct vtsnd_softc *sc = ch->sc;
	int error = 0;

	if (go == PCMTRIG_EMLDMAWR || go == PCMTRIG_EMLDMARD)
		return (0);

	VTSND_LOCK(sc);
	if (sc->vtsnd_detaching || sc->vtsnd_suspended) {
		VTSND_UNLOCK(sc);
		return (0);
	}

	switch (go) {
	case PCMTRIG_START:
		ch->ptr = 0;
		ch->bufsz = ch->buf->bufsize;
		ch->blksz = ch->buf->blksz;
		if (ch->rate_code == 0) {
			ch->rate_code = VIRTIO_SND_PCM_RATE_48000;
			ch->speed = 48000;
		}

		error = vtsnd_pcm_set_params(sc, ch);
		if (error == 0)
			error = vtsnd_pcm_lifecycle(sc, ch,
			    VIRTIO_SND_R_PCM_PREPARE);
		if (error == 0) {
			ch->prepared = true;
			error = vtsnd_pcm_lifecycle(sc, ch,
			    VIRTIO_SND_R_PCM_START);
		}
		if (error == 0) {
			ch->running = true;
			ch->inflight = false;
			if (ch->dir == PCMDIR_PLAY)
				error = vtsnd_tx_submit(ch);
			else
				error = vtsnd_rx_submit(ch);
		}
		break;
	case PCMTRIG_STOP:
	case PCMTRIG_ABORT:
		vtsnd_chan_stop(sc, ch);
		break;
	default:
		break;
	}
	VTSND_UNLOCK(sc);

	return (error);
}

static void
vtsnd_chan_stop(struct vtsnd_softc *sc, struct vtsnd_chan *ch)
{
	struct virtqueue *vq;
	uint32_t len;

	VTSND_LOCK_ASSERT(sc);

	if (!ch->running && !ch->prepared)
		return;

	ch->running = false;
	if (ch->prepared) {
		(void)vtsnd_pcm_lifecycle(sc, ch, VIRTIO_SND_R_PCM_STOP);
		(void)vtsnd_pcm_lifecycle(sc, ch, VIRTIO_SND_R_PCM_RELEASE);
		ch->prepared = false;

		/*
		 * RELEASE retires every outstanding data descriptor for this
		 * stream into the used ring before it completes (virtio-snd
		 * 5.14.6.6.5; see the retire path in the bhyve backend).  Reap
		 * them here, while the softc lock is held and before returning,
		 * so no data-completion interrupt can fire once the channel's
		 * pcm(4) state has been torn down.  Otherwise detach's
		 * pcm_unregister() could free ch->chan and the sndbuf while a
		 * still-pending completion in vtsnd_data_complete() dereferences
		 * them (use-after-free), since the data virtqueue interrupts are
		 * not torn down until after pcm_unregister() returns.
		 */
		vq = sc->vtsnd_vqs[ch->vq_idx];
		if (vq != NULL) {
			while (virtqueue_dequeue(vq, &len) != NULL)
				continue;
		}
	}
	ch->inflight = false;
}

static uint32_t
vtsnd_chan_getptr(kobj_t obj, void *data)
{
	struct vtsnd_chan *ch = data;

	return (ch->running ? ch->ptr : 0);
}

static struct pcmchan_caps *
vtsnd_chan_getcaps(kobj_t obj, void *data)
{
	struct vtsnd_chan *ch = data;

	return (&ch->sc->vtsnd_caps);
}

static kobj_method_t vtsnd_chan_methods[] = {
	KOBJMETHOD(channel_init,	vtsnd_chan_init),
	KOBJMETHOD(channel_free,	vtsnd_chan_free),
	KOBJMETHOD(channel_setformat,	vtsnd_chan_setformat),
	KOBJMETHOD(channel_setspeed,	vtsnd_chan_setspeed),
	KOBJMETHOD(channel_setblocksize, vtsnd_chan_setblocksize),
	KOBJMETHOD(channel_trigger,	vtsnd_chan_trigger),
	KOBJMETHOD(channel_getptr,	vtsnd_chan_getptr),
	KOBJMETHOD(channel_getcaps,	vtsnd_chan_getcaps),
	KOBJMETHOD_END
};
CHANNEL_DECLARE(vtsnd_chan);

/*
 * pcm(4) mixer class.  The device has no hardware mixer; expose a software
 * PCM volume control so applications have a functional slider.
 */
static int
vtsnd_mixer_init(struct snd_mixer *m)
{
	struct vtsnd_softc *sc;

	sc = mix_getdevinfo(m);
	if (sc == NULL)
		return (-1);

	pcm_setflags(sc->vtsnd_dev, pcm_getflags(sc->vtsnd_dev) |
	    SD_F_SOFTPCMVOL);
	mix_setdevs(m, SOUND_MASK_PCM | SOUND_MASK_VOLUME | SOUND_MASK_RECLEV);
	mix_setrecdevs(m, SOUND_MASK_RECLEV);

	return (0);
}

static int
vtsnd_mixer_set(struct snd_mixer *m, unsigned dev, unsigned left,
    unsigned right)
{

	return (0);
}

static uint32_t
vtsnd_mixer_setrecsrc(struct snd_mixer *m, uint32_t src)
{

	return (src == SOUND_MASK_RECLEV ? src : 0);
}

static kobj_method_t vtsnd_mixer_methods[] = {
	KOBJMETHOD(mixer_init,		vtsnd_mixer_init),
	KOBJMETHOD(mixer_set,		vtsnd_mixer_set),
	KOBJMETHOD(mixer_setrecsrc,	vtsnd_mixer_setrecsrc),
	KOBJMETHOD_END
};
MIXER_DECLARE(vtsnd_mixer);

/*
 * VirtIO plumbing.
 */
static int
vtsnd_negotiate_features(struct vtsnd_softc *sc)
{
	device_t dev = sc->vtsnd_dev;
	uint64_t features;

	features = VTSND_FEATURES;
	sc->vtsnd_features = virtio_negotiate_features(dev, features);
	return (virtio_finalize_features(dev));
}

static int
vtsnd_alloc_virtqueues(struct vtsnd_softc *sc)
{
	device_t dev = sc->vtsnd_dev;
	struct vq_alloc_info vq_info[VTSND_VQ_MAX];
	int error;

	VQ_ALLOC_INFO_INIT(&vq_info[VTSND_VQ_CONTROL], 0,
	    vtsnd_control_vq_intr, sc, &sc->vtsnd_vqs[VTSND_VQ_CONTROL],
	    "%s control", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[VTSND_VQ_EVENT], 0,
	    vtsnd_event_vq_intr, sc, &sc->vtsnd_vqs[VTSND_VQ_EVENT],
	    "%s event", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[VTSND_VQ_TX], 0,
	    vtsnd_tx_vq_intr, sc, &sc->vtsnd_vqs[VTSND_VQ_TX],
	    "%s tx", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[VTSND_VQ_RX], 0,
	    vtsnd_rx_vq_intr, sc, &sc->vtsnd_vqs[VTSND_VQ_RX],
	    "%s rx", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, VTSND_VQ_MAX, vq_info);
	return (error);
}

static int
vtsnd_alloc_dma(struct vtsnd_softc *sc)
{
	int error, i;

	error = vtsnd_dma_alloc(sc, VTSND_PCM_SET_PARAMS_SIZE, &sc->vtsnd_creq);
	if (error != 0)
		return (error);
	error = vtsnd_dma_alloc(sc, VTSND_HDR_SIZE +
	    VTSND_NSTREAM * VTSND_PCM_INFO_SIZE, &sc->vtsnd_cresp);
	if (error != 0)
		return (error);
	for (i = 0; i < VTSND_NEVENTBUF; i++) {
		error = vtsnd_dma_alloc(sc, VTSND_EVENT_SIZE,
		    &sc->vtsnd_evt[i]);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < VTSND_NSTREAM; i++) {
		struct vtsnd_chan *ch = &sc->vtsnd_chans[i];

		error = vtsnd_dma_alloc(sc, VTSND_MAXBUF, &ch->data);
		if (error != 0)
			return (error);
		error = vtsnd_dma_alloc(sc, VTSND_PCM_XFER_SIZE, &ch->xhdr);
		if (error != 0)
			return (error);
		error = vtsnd_dma_alloc(sc, VTSND_PCM_STATUS_SIZE, &ch->status);
		if (error != 0)
			return (error);
		/* The xfer header carries just the stream id. */
		le32enc(ch->xhdr.dma_vaddr, ch->stream_id);
		bus_dmamap_sync(ch->xhdr.dma_tag, ch->xhdr.dma_map,
		    BUS_DMASYNC_PREWRITE);
	}

	return (0);
}

static void
vtsnd_free_dma(struct vtsnd_softc *sc)
{
	int i;

	vtsnd_dma_free(&sc->vtsnd_creq);
	vtsnd_dma_free(&sc->vtsnd_cresp);
	for (i = 0; i < VTSND_NEVENTBUF; i++)
		vtsnd_dma_free(&sc->vtsnd_evt[i]);
	for (i = 0; i < VTSND_NSTREAM; i++) {
		vtsnd_dma_free(&sc->vtsnd_chans[i].data);
		vtsnd_dma_free(&sc->vtsnd_chans[i].xhdr);
		vtsnd_dma_free(&sc->vtsnd_chans[i].status);
	}
}

static int
vtsnd_probe(device_t dev)
{

	if (virtio_get_device_type(dev) != VIRTIO_ID_SOUND)
		return (ENXIO);
	device_set_desc(dev, "VirtIO Sound Adapter");
	return (BUS_PROBE_DEFAULT);
}

static int
vtsnd_attach(device_t dev)
{
	struct vtsnd_softc *sc;
	char status[SND_STATUSLEN];
	int error, i;

	sc = device_get_softc(dev);
	sc->vtsnd_dev = dev;

	mtx_init(&sc->vtsnd_mtx, device_get_nameunit(dev), "virtio_snd softc",
	    MTX_DEF);

	virtio_set_feature_desc(dev, vtsnd_feature_desc);

	error = vtsnd_negotiate_features(sc);
	if (error != 0) {
		device_printf(dev, "cannot negotiate features: %d\n", error);
		goto fail;
	}

	sc->vtsnd_streams = virtio_read_dev_config_4(dev, VTSND_CFG_STREAMS);
	if (sc->vtsnd_streams < 1 || sc->vtsnd_streams > VTSND_NSTREAM) {
		device_printf(dev, "unsupported stream count %u\n",
		    sc->vtsnd_streams);
		error = ENXIO;
		goto fail;
	}

	/* Pre-bind the fixed stream identities. */
	sc->vtsnd_chans[VTSND_STREAM_TX].sc = sc;
	sc->vtsnd_chans[VTSND_STREAM_TX].stream_id = VTSND_STREAM_TX;
	sc->vtsnd_chans[VTSND_STREAM_TX].vq_idx = VTSND_VQ_TX;
	sc->vtsnd_chans[VTSND_STREAM_RX].sc = sc;
	sc->vtsnd_chans[VTSND_STREAM_RX].stream_id = VTSND_STREAM_RX;
	sc->vtsnd_chans[VTSND_STREAM_RX].vq_idx = VTSND_VQ_RX;

	sc->vtsnd_sg = sglist_alloc(VTSND_SG_MAX, M_NOWAIT);
	if (sc->vtsnd_sg == NULL) {
		device_printf(dev, "cannot allocate sglist\n");
		error = ENOMEM;
		goto fail;
	}

	error = vtsnd_alloc_dma(sc);
	if (error != 0)
		goto fail;

	error = vtsnd_alloc_virtqueues(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueues: %d\n", error);
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_AV);
	if (error != 0) {
		device_printf(dev, "cannot setup virtqueue interrupt: %d\n",
		    error);
		goto fail;
	}

	/*
	 * Control queue is polled: keep its interrupt masked.  Arm the event,
	 * tx and rx queues.
	 */
	virtqueue_disable_intr(sc->vtsnd_vqs[VTSND_VQ_CONTROL]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_EVENT]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_TX]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_RX]);

	VTSND_LOCK(sc);
	error = vtsnd_event_populate(sc);
	VTSND_UNLOCK(sc);
	if (error != 0) {
		device_printf(dev, "cannot populate event queue: %d\n", error);
		goto fail;
	}

	error = vtsnd_pcm_info_query(sc);
	if (error != 0)
		goto fail;

	/* Capabilities: S16_LE, stereo, 44.1-48 kHz. */
	sc->vtsnd_cap_fmts[0] = SND_FORMAT(AFMT_S16_LE, 2, 0);
	sc->vtsnd_cap_fmts[1] = 0;
	sc->vtsnd_caps = (struct pcmchan_caps){
		44100,			/* minspeed */
		48000,			/* maxspeed */
		sc->vtsnd_cap_fmts,	/* fmtlist */
		0,			/* caps */
	};

	pcm_setflags(dev, pcm_getflags(dev) | SD_F_MPSAFE);
	pcm_init(dev, sc);
	pcm_addchan(dev, PCMDIR_PLAY, &vtsnd_chan_class, sc);
	/* Only expose capture if the device really has the input stream. */
	if (sc->vtsnd_streams > VTSND_STREAM_RX)
		pcm_addchan(dev, PCMDIR_REC, &vtsnd_chan_class, sc);

	snprintf(status, SND_STATUSLEN, "on %s",
	    device_get_nameunit(device_get_parent(dev)));
	if (pcm_register(dev, status)) {
		device_printf(dev, "pcm_register failed\n");
		error = ENXIO;
		goto fail;
	}
	mixer_init(dev, &vtsnd_mixer_class, sc);

	return (0);

fail:
	if (error != 0) {
		/* Undo whatever attach reached; mirror detach ordering. */
		sc->vtsnd_detaching = true;
		/*
		 * Reset the device before freeing any DMA memory.  attach posts
		 * event-queue receive buffers (vtsnd_event_populate) and may leave a
		 * control descriptor outstanding against the shared staging buffers
		 * (vtsnd_ctrl_cmd relies on "the device is reset ... before they are
		 * freed").  Without this reset those descriptors would still be owned
		 * by the device when vtsnd_free_dma() releases their backing memory --
		 * a DMA-after-free.  virtio_stop() is safe even if no virtqueue was
		 * ever allocated.
		 */
		virtio_stop(dev);
		virtio_teardown_intr(dev);
		for (i = 0; i < VTSND_VQ_MAX; i++)
			sc->vtsnd_vqs[i] = NULL;
		vtsnd_free_dma(sc);
		if (sc->vtsnd_sg != NULL) {
			sglist_free(sc->vtsnd_sg);
			sc->vtsnd_sg = NULL;
		}
		mtx_destroy(&sc->vtsnd_mtx);
	}
	return (error);
}

static int
vtsnd_detach(device_t dev)
{
	struct vtsnd_softc *sc;
	int error, i;

	sc = device_get_softc(dev);

	VTSND_LOCK(sc);
	sc->vtsnd_detaching = true;
	for (i = 0; i < VTSND_NSTREAM; i++)
		vtsnd_chan_stop(sc, &sc->vtsnd_chans[i]);
	VTSND_UNLOCK(sc);

	error = pcm_unregister(dev);
	if (error != 0) {
		VTSND_LOCK(sc);
		sc->vtsnd_detaching = false;
		VTSND_UNLOCK(sc);
		return (error);
	}

	virtio_stop(dev);
	virtio_teardown_intr(dev);

	vtsnd_free_dma(sc);
	if (sc->vtsnd_sg != NULL) {
		sglist_free(sc->vtsnd_sg);
		sc->vtsnd_sg = NULL;
	}
	mtx_destroy(&sc->vtsnd_mtx);

	return (0);
}

static int
vtsnd_suspend(device_t dev)
{
	struct vtsnd_softc *sc;
	int i;

	sc = device_get_softc(dev);

	VTSND_LOCK(sc);
	/*
	 * Block new triggers before stopping the streams: vtsnd_chan_stop()
	 * drops the softc lock while its control commands sleep, so setting the
	 * flag afterwards would let a PCMTRIG_START slip in and leave a stream
	 * running (with a data descriptor outstanding) across the suspend.
	 */
	sc->vtsnd_suspended = true;
	for (i = 0; i < VTSND_NSTREAM; i++)
		vtsnd_chan_stop(sc, &sc->vtsnd_chans[i]);
	VTSND_UNLOCK(sc);

	/*
	 * With VIRTIO_F_SUSPEND negotiated the transport quiesces the device;
	 * the common layer drives the actual suspend state transition.
	 */
	return (0);
}

static int
vtsnd_resume(device_t dev)
{
	struct vtsnd_softc *sc;
	int error;

	sc = device_get_softc(dev);

	error = virtio_reinit(dev, sc->vtsnd_features);
	if (error != 0) {
		device_printf(dev, "cannot reinit on resume: %d\n", error);
		return (error);
	}

	virtqueue_disable_intr(sc->vtsnd_vqs[VTSND_VQ_CONTROL]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_EVENT]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_TX]);
	virtqueue_enable_intr(sc->vtsnd_vqs[VTSND_VQ_RX]);

	VTSND_LOCK(sc);
	(void)vtsnd_event_populate(sc);
	sc->vtsnd_suspended = false;
	VTSND_UNLOCK(sc);

	virtio_reinit_complete(dev);

	return (0);
}

static device_method_t vtsnd_methods[] = {
	DEVMETHOD(device_probe,		vtsnd_probe),
	DEVMETHOD(device_attach,	vtsnd_attach),
	DEVMETHOD(device_detach,	vtsnd_detach),
	DEVMETHOD(device_suspend,	vtsnd_suspend),
	DEVMETHOD(device_resume,	vtsnd_resume),
	DEVMETHOD_END
};

/*
 * The driver joins the shared "pcm" devclass so the sound framework discovers
 * it exactly like any other pcm(4) provider (sndstat, dsp cloning, mixer).
 */
static driver_t vtsnd_driver = {
	"pcm",
	vtsnd_methods,
	sizeof(struct vtsnd_softc),
};

VIRTIO_DRIVER_MODULE(virtio_snd, vtsnd_driver, NULL, NULL);
MODULE_VERSION(virtio_snd, 1);
MODULE_DEPEND(virtio_snd, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_snd, sound, SOUND_MINVER, SOUND_PREFVER, SOUND_MAXVER);
