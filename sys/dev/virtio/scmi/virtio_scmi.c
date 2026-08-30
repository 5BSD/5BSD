/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Arm Ltd
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

/* Driver for VirtIO SCMI device. */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/sglist.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/condvar.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/scmi/virtio_scmi.h>

struct vtscmi_pdu {
	enum vtscmi_chan	chan;
	struct sglist		sg;
	struct sglist_seg	segs[4];
	void			*buf;
	int			readable;
	int			writable;
	SLIST_ENTRY(vtscmi_pdu)	next;
};

struct vtscmi_queue {
	device_t				dev;
	int					vq_id;
	unsigned int				vq_sz;
	struct virtqueue			*vq;
	struct mtx				vq_mtx;
	struct vtscmi_pdu			*pdus;
	SLIST_HEAD(pdus_head, vtscmi_pdu)	p_head;
	struct mtx				p_mtx;
	struct mtx				cb_mtx;
	struct cv				cb_cv;
	u_int					cb_inflight;
	virtio_scmi_rx_callback_t		*rx_callback;
	void					*priv;
};

struct vtscmi_softc {
	device_t	vtscmi_dev;
	uint64_t	vtscmi_features;
	uint8_t		vtscmi_vqs_cnt;
	struct vtscmi_queue	vtscmi_queues[VIRTIO_SCMI_CHAN_MAX];
	bool		has_p2a;
	bool		has_shared;
	u_int		quiesced;
};

static device_t vtscmi_dev;
static bool vtscmi_attaching;
static struct mtx vtscmi_global_mtx;

static int vtscmi_modevent(module_t, int, void *);

static int	vtscmi_probe(device_t);
static int	vtscmi_attach(device_t);
static int	vtscmi_detach(device_t);
static int	vtscmi_shutdown(device_t);
static int	vtscmi_negotiate_features(struct vtscmi_softc *);
static int	vtscmi_setup_features(struct vtscmi_softc *);
static void	vtscmi_vq_intr(void *);
static int	vtscmi_alloc_virtqueues(struct vtscmi_softc *);
static int	vtscmi_alloc_queues(struct vtscmi_softc *);
static void	vtscmi_free_queues(struct vtscmi_softc *);
static void	*virtio_scmi_pdu_get(struct vtscmi_queue *, void *,
    unsigned int, unsigned int);
static void	virtio_scmi_pdu_put(device_t, struct vtscmi_pdu *);

static struct virtio_feature_desc vtscmi_feature_desc[] = {
	{ VIRTIO_SCMI_F_P2A_CHANNELS, "P2AChannel" },
	{ VIRTIO_SCMI_F_SHARED_MEMORY, "SharedMem" },
	{ 0, NULL }
};

static device_method_t vtscmi_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtscmi_probe),
	DEVMETHOD(device_attach,	vtscmi_attach),
	DEVMETHOD(device_detach,	vtscmi_detach),
	DEVMETHOD(device_shutdown,	vtscmi_shutdown),

	DEVMETHOD_END
};

static driver_t vtscmi_driver = {
	"vtscmi",
	vtscmi_methods,
	sizeof(struct vtscmi_softc)
};

VIRTIO_DRIVER_MODULE(virtio_scmi, vtscmi_driver, vtscmi_modevent, NULL);
MODULE_VERSION(virtio_scmi, 1);
MODULE_DEPEND(virtio_scmi, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_scmi, VIRTIO_ID_SCMI, "VirtIO SCMI Adapter");

static int
vtscmi_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&vtscmi_global_mtx, "vtscmi global", NULL, MTX_DEF);
		error = 0;
		break;
	case MOD_QUIESCE:
		mtx_lock(&vtscmi_global_mtx);
		error = vtscmi_dev != NULL || vtscmi_attaching ? EBUSY : 0;
		mtx_unlock(&vtscmi_global_mtx);
		break;
	case MOD_UNLOAD:
		mtx_destroy(&vtscmi_global_mtx);
		error = 0;
		break;
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
vtscmi_probe(device_t dev)
{
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_scmi));
}

static int
vtscmi_attach(device_t dev)
{
	struct vtscmi_softc *sc;
	int error;

	/* Reserve the singleton while attach may sleep without the global lock. */
	mtx_lock(&vtscmi_global_mtx);
	if (vtscmi_dev != NULL || vtscmi_attaching) {
		mtx_unlock(&vtscmi_global_mtx);
		return (EEXIST);
	}
	vtscmi_attaching = true;
	mtx_unlock(&vtscmi_global_mtx);

	sc = device_get_softc(dev);
	sc->vtscmi_dev = dev;

	virtio_set_feature_desc(dev, vtscmi_feature_desc);
	error = vtscmi_setup_features(sc);
	if (error) {
		device_printf(dev, "cannot setup features\n");
		goto fail;
	}

	error = vtscmi_alloc_virtqueues(sc);
	if (error) {
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	error = vtscmi_alloc_queues(sc);
	if (error) {
		device_printf(dev, "cannot allocate queues\n");
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error) {
		device_printf(dev, "cannot setup intr\n");
		vtscmi_free_queues(sc);
		goto fail;
	}

fail:
	mtx_lock(&vtscmi_global_mtx);
	if (error == 0)
		vtscmi_dev = sc->vtscmi_dev;
	vtscmi_attaching = false;
	mtx_unlock(&vtscmi_global_mtx);

	return (error);
}

static int
vtscmi_detach(device_t dev)
{
	struct vtscmi_softc *sc;

	sc = device_get_softc(dev);

	mtx_lock(&vtscmi_global_mtx);
	if (vtscmi_dev == dev)
		vtscmi_dev = NULL;
	mtx_unlock(&vtscmi_global_mtx);

	virtio_stop(dev);
	virtio_teardown_intr(dev);

	/* Interrupt drain makes callback unregister non-racing at detach. */
	virtio_scmi_channel_callback_set(dev, VIRTIO_SCMI_CHAN_A2P, NULL, NULL);
	virtio_scmi_channel_callback_set(dev, VIRTIO_SCMI_CHAN_P2A, NULL, NULL);

	vtscmi_free_queues(sc);

	return (0);
}

static int
vtscmi_shutdown(device_t dev)
{

	return (0);
}

static int
vtscmi_negotiate_features(struct vtscmi_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtscmi_dev;
	/* We still don't support shared mem (stats)...so don't advertise it */
	features = VIRTIO_SCMI_F_P2A_CHANNELS;

	sc->vtscmi_features = virtio_negotiate_features(dev, features);
	return (virtio_finalize_features(dev));
}

static int
vtscmi_setup_features(struct vtscmi_softc *sc)
{
	device_t dev;
	int error;

	dev = sc->vtscmi_dev;
	error = vtscmi_negotiate_features(sc);
	if (error)
		return (error);

	if (virtio_with_feature(dev, VIRTIO_SCMI_F_P2A_CHANNELS))
		sc->has_p2a = true;
	if (virtio_with_feature(dev, VIRTIO_SCMI_F_SHARED_MEMORY))
		sc->has_shared = true;

	device_printf(dev, "Platform %s P2A channel.\n",
	    sc->has_p2a ? "supports" : "does NOT support");

	return (0);
}

static int
vtscmi_alloc_queues(struct vtscmi_softc *sc)
{
	int idx;

	for (idx = VIRTIO_SCMI_CHAN_A2P; idx < VIRTIO_SCMI_CHAN_MAX; idx++) {
		int i, vq_sz;
		struct vtscmi_queue *q;
		struct vtscmi_pdu *pdu;

		if (idx == VIRTIO_SCMI_CHAN_P2A && !sc->has_p2a)
			continue;

		q = &sc->vtscmi_queues[idx];
		q->dev = sc->vtscmi_dev;
		q->vq_id = idx;
		vq_sz = virtqueue_size(q->vq);
		q->vq_sz = idx != VIRTIO_SCMI_CHAN_A2P ? vq_sz : vq_sz / 2;

		q->pdus = mallocarray(q->vq_sz, sizeof(*pdu), M_DEVBUF,
		    M_ZERO | M_WAITOK);

		SLIST_INIT(&q->p_head);
		for (i = 0, pdu = q->pdus; i < q->vq_sz; i++, pdu++) {
			pdu->chan = idx;
			/* Each side may straddle a physical-page boundary. */
			sglist_init(&pdu->sg, nitems(pdu->segs), pdu->segs);
			SLIST_INSERT_HEAD(&q->p_head, pdu, next);
		}

		mtx_init(&q->p_mtx, "vtscmi_pdus", "VTSCMI", MTX_SPIN);
		mtx_init(&q->vq_mtx, "vtscmi_vq", "VTSCMI", MTX_SPIN);
		mtx_init(&q->cb_mtx, "vtscmi_cb", "VTSCMI", MTX_DEF);
		cv_init(&q->cb_cv, "vtscmicb");
	}

	return (0);
}

static void
vtscmi_free_queues(struct vtscmi_softc *sc)
{
	int idx;

	for (idx = VIRTIO_SCMI_CHAN_A2P; idx < VIRTIO_SCMI_CHAN_MAX; idx++) {
		struct vtscmi_queue *q;

		if (idx == VIRTIO_SCMI_CHAN_P2A && !sc->has_p2a)
			continue;

		q = &sc->vtscmi_queues[idx];
		if (q->vq_sz == 0)
			continue;

		free(q->pdus, M_DEVBUF);
		cv_destroy(&q->cb_cv);
		mtx_destroy(&q->cb_mtx);
		mtx_destroy(&q->p_mtx);
		mtx_destroy(&q->vq_mtx);
	}
}

static void
vtscmi_vq_intr(void *arg)
{
	struct vtscmi_queue *q = arg;

	/*
	 * TODO
	 * - consider pressure on RX by msg floods
	 *   + Does it need a taskqueue_ like virtio/net to postpone processing
	 *     under pressure ? (SCMI is low_freq compared to network though)
	 */
	for (;;) {
		struct vtscmi_pdu *pdu;
		virtio_scmi_rx_callback_t *callback;
		void *priv;
		uint32_t rx_len;
		bool rearm;

		mtx_lock_spin(&q->vq_mtx);
		pdu = virtqueue_dequeue(q->vq, &rx_len);
		mtx_unlock_spin(&q->vq_mtx);
		if (!pdu) {
			/*
			 * The MSIX filter (virtqueue_intr_filter) disabled this
			 * interrupt before scheduling us.  Re-arm it while a
			 * callback consumer is registered (matching
			 * virtio_scmi_channel_callback_set), and drain any
			 * completion that raced the re-enable.
			 */
			mtx_lock(&q->cb_mtx);
			rearm = q->rx_callback != NULL;
			mtx_unlock(&q->cb_mtx);
			if (rearm && virtqueue_enable_intr(q->vq) != 0)
				continue;
			return;
		}

		mtx_lock(&q->cb_mtx);
		callback = q->rx_callback;
		priv = q->priv;
		if (callback != NULL)
			q->cb_inflight++;
		mtx_unlock(&q->cb_mtx);

		if (callback != NULL)
			callback(pdu->buf, rx_len, priv);

		/* Note that this only frees the PDU, NOT the buffer itself */
		virtio_scmi_pdu_put(q->dev, pdu);
		if (callback != NULL) {
			mtx_lock(&q->cb_mtx);
			if (q->cb_inflight == 0)
				panic("SCMI callback count underflow");
			if (--q->cb_inflight == 0)
				cv_broadcast(&q->cb_cv);
			mtx_unlock(&q->cb_mtx);
		}
	}
}

static int
vtscmi_alloc_virtqueues(struct vtscmi_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info[VIRTIO_SCMI_CHAN_MAX];

	dev = sc->vtscmi_dev;
	sc->vtscmi_vqs_cnt = sc->has_p2a ? 2 : 1;

	VQ_ALLOC_INFO_INIT(&vq_info[VIRTIO_SCMI_CHAN_A2P], 0,
			   vtscmi_vq_intr,
			   &sc->vtscmi_queues[VIRTIO_SCMI_CHAN_A2P],
			   &sc->vtscmi_queues[VIRTIO_SCMI_CHAN_A2P].vq,
			   "%s cmdq", device_get_nameunit(dev));

	if (sc->has_p2a) {
		VQ_ALLOC_INFO_INIT(&vq_info[VIRTIO_SCMI_CHAN_P2A], 0,
				   vtscmi_vq_intr,
				   &sc->vtscmi_queues[VIRTIO_SCMI_CHAN_P2A],
				   &sc->vtscmi_queues[VIRTIO_SCMI_CHAN_P2A].vq,
				   "%s evtq", device_get_nameunit(dev));
	}

	return (virtio_alloc_virtqueues(dev, sc->vtscmi_vqs_cnt, vq_info));
}

static void *
virtio_scmi_pdu_get(struct vtscmi_queue *q, void *buf, unsigned int tx_len,
    unsigned int rx_len)
{
	struct vtscmi_pdu *pdu = NULL;
	int error;

	if (rx_len == 0)
		return (NULL);

	mtx_lock_spin(&q->p_mtx);
	if (!SLIST_EMPTY(&q->p_head)) {
		pdu = SLIST_FIRST(&q->p_head);
		SLIST_REMOVE_HEAD(&q->p_head, next);
	}
	mtx_unlock_spin(&q->p_mtx);

	if (pdu == NULL) {
		device_printf(q->dev, "Cannot allocate PDU.\n");
		return (NULL);
	}

	/*Save msg buffer for easy access */
	pdu->buf = buf;
	if (tx_len != 0) {
		error = sglist_append(&pdu->sg, pdu->buf, tx_len);
		if (error != 0)
			goto fail;
	}
	pdu->readable = pdu->sg.sg_nseg;
	error = sglist_append_boundary(&pdu->sg, pdu->buf, rx_len);
	if (error != 0)
		goto fail;
	pdu->writable = pdu->sg.sg_nseg - pdu->readable;
	KASSERT(pdu->writable > 0,
	    ("vtscmi: request and response share a descriptor"));
	if (pdu->writable == 0)
		goto fail;

	return (pdu);

fail:
	device_printf(q->dev, "Cannot map SCMI message buffers.\n");
	sglist_reset(&pdu->sg);
	mtx_lock_spin(&q->p_mtx);
	SLIST_INSERT_HEAD(&q->p_head, pdu, next);
	mtx_unlock_spin(&q->p_mtx);
	return (NULL);
}

static void
virtio_scmi_pdu_put(device_t dev, struct vtscmi_pdu *pdu)
{
	struct vtscmi_softc *sc;
	struct vtscmi_queue *q;

	if (pdu == NULL)
		return;

	sc = device_get_softc(dev);
	q = &sc->vtscmi_queues[pdu->chan];

	sglist_reset(&pdu->sg);

	mtx_lock_spin(&q->p_mtx);
	SLIST_INSERT_HEAD(&q->p_head, pdu, next);
	mtx_unlock_spin(&q->p_mtx);
}

device_t
virtio_scmi_transport_get(void)
{
	device_t dev;

	mtx_lock(&vtscmi_global_mtx);
	dev = vtscmi_dev;
	if (dev != NULL)
		device_busy(dev);
	mtx_unlock(&vtscmi_global_mtx);
	return (dev);
}

void
virtio_scmi_transport_put(device_t dev)
{

	if (dev != NULL)
		device_unbusy(dev);
}

int
virtio_scmi_transport_start(device_t dev)
{
	struct vtscmi_softc *sc;
	int error;

	sc = device_get_softc(dev);
	if (atomic_load_acq_int(&sc->quiesced) == 0)
		return (0);

	error = virtio_reinit(dev, sc->vtscmi_features);
	if (error != 0)
		return (error);
	virtio_reinit_complete(dev);
	atomic_store_rel_int(&sc->quiesced, 0);
	return (0);
}

void
virtio_scmi_transport_quiesce(device_t dev)
{
	struct vtscmi_softc *sc;
	struct vtscmi_pdu *pdu;
	struct vtscmi_queue *q;
	int last;

	sc = device_get_softc(dev);
	if (atomic_load_acq_int(&sc->quiesced) != 0)
		return;

	/*
	 * Reset first to revoke device ownership of every descriptor.  Merely
	 * disabling callbacks is insufficient: P2A descriptors still contain
	 * consumer-owned buffers which the device may write asynchronously.
	 */
	atomic_store_rel_int(&sc->quiesced, 1);
	virtio_stop(dev);
	for (int chan = 0; chan < sc->vtscmi_vqs_cnt; chan++) {
		q = &sc->vtscmi_queues[chan];
		last = 0;
		mtx_lock_spin(&q->vq_mtx);
		while ((pdu = virtqueue_drain(q->vq, &last)) != NULL)
			virtio_scmi_pdu_put(dev, pdu);
		mtx_unlock_spin(&q->vq_mtx);
	}
}

int
virtio_scmi_channel_size_get(device_t dev, enum vtscmi_chan chan)
{
	struct vtscmi_softc *sc;

	sc = device_get_softc(dev);
	if (chan >= sc->vtscmi_vqs_cnt)
		return (0);

	return (sc->vtscmi_queues[chan].vq_sz);
}

int
virtio_scmi_channel_callback_set(device_t dev, enum vtscmi_chan chan,
    virtio_scmi_rx_callback_t *cb, void *priv)
{
	struct vtscmi_softc *sc;
	struct vtscmi_queue *q;

	sc = device_get_softc(dev);
	if (chan >= sc->vtscmi_vqs_cnt)
		return (1);
	if (atomic_load_acq_int(&sc->quiesced) != 0)
		return (ENXIO);
	q = &sc->vtscmi_queues[chan];

	/* Close admission before waiting for callbacks using the old private. */
	virtqueue_disable_intr(q->vq);

	mtx_lock(&q->cb_mtx);
	while (q->cb_inflight != 0)
		cv_wait(&q->cb_cv, &q->cb_mtx);
	q->rx_callback = cb;
	q->priv = priv;
	mtx_unlock(&q->cb_mtx);

	/* Enable Interrupt on VQ once the callback is set */
	if (cb != NULL && virtqueue_enable_intr(q->vq) != 0)
		vtscmi_vq_intr(q);

	device_printf(dev, "%sabled interrupts on VQ[%d].\n",
	    cb ? "En" : "Dis", chan);

	return (0);
}

int
virtio_scmi_message_enqueue(device_t dev, enum vtscmi_chan chan,
    void *buf, unsigned int tx_len, unsigned int rx_len)
{
	struct vtscmi_softc *sc;
	struct vtscmi_pdu *pdu;
	struct vtscmi_queue *q;
	int ret;

	sc = device_get_softc(dev);
	if (chan >= sc->vtscmi_vqs_cnt)
		return (1);

	q = &sc->vtscmi_queues[chan];
	pdu = virtio_scmi_pdu_get(q, buf, tx_len, rx_len);
	if (pdu == NULL)
		return (ENXIO);

	mtx_lock_spin(&q->vq_mtx);
	if (atomic_load_acq_int(&sc->quiesced) != 0)
		ret = ECANCELED;
	else
		ret = virtqueue_enqueue(q->vq, pdu, &pdu->sg,
		    pdu->readable, pdu->writable);
	if (ret == 0)
		virtqueue_notify(q->vq);
	mtx_unlock_spin(&q->vq_mtx);
	/* virtqueue_enqueue() takes ownership only after a successful enqueue. */
	if (ret != 0)
		virtio_scmi_pdu_put(dev, pdu);

	return (ret);
}

void *
virtio_scmi_message_poll(device_t dev, uint32_t *rx_len)
{
	struct vtscmi_softc *sc;
	struct vtscmi_queue *q;
	struct vtscmi_pdu *pdu;
	void *buf = NULL;

	sc = device_get_softc(dev);

	q = &sc->vtscmi_queues[VIRTIO_SCMI_CHAN_A2P];

	mtx_lock_spin(&q->vq_mtx);
	/* Not using virtqueue_poll since has no configurable timeout */
	pdu = virtqueue_dequeue(q->vq, rx_len);
	mtx_unlock_spin(&q->vq_mtx);
	if (pdu != NULL) {
		buf = pdu->buf;
		virtio_scmi_pdu_put(dev, pdu);
	}

	return (buf);
}
