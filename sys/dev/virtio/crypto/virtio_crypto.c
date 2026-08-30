/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Guest driver for the VirtIO crypto device (VirtIO device ID 20).
 *
 * The device exposes one or more data virtqueues (indices 0..max_dataqueues-1)
 * carrying symmetric crypto requests, and one control virtqueue (the last
 * queue, index max_dataqueues) carrying session lifecycle requests.  This
 * driver binds as a VirtIO bus child, negotiates the modern transport, and
 * registers with the kernel opencrypto(9) framework.
 *
 * opencrypto sessions are direction-agnostic (a single session both encrypts
 * and decrypts), whereas a virtio-crypto CIPHER/AEAD session is created with a
 * fixed direction.  For those modes the driver creates two host sessions at
 * newsession time -- one for each direction -- and selects the matching one
 * per request.  HASH and MAC sessions have no direction and use a single host
 * session.
 *
 * Data requests are submitted asynchronously: process() enqueues onto a data
 * queue and returns, and the queue interrupt handler copies results back and
 * calls crypto_done().  Control requests (session create/destroy) are
 * synchronous: the submitter blocks until the control queue interrupt reports
 * completion.  The wire layouts are defined in virtio_crypto.h and byte-match
 * the bhyve host model.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/crypto/virtio_crypto.h>

#include <opencrypto/cryptodev.h>
#include <cryptodev_if.h>

/* Bounded resource limits. */
#define	VTCRYPTO_MAX_DATA_QUEUES	8
#define	VTCRYPTO_MAX_DATALEN		(64u * 1024u)	/* host max_size */
#define	VTCRYPTO_MAX_AADLEN		1024u
#define	VTCRYPTO_MAX_KEYLEN		64u		/* AES-256 / HMAC key */
#define	VTCRYPTO_GCM_TAGLEN		16u
#define	VTCRYPTO_SHA256_LEN		32u
#define	VTCRYPTO_AES_BLOCK		16u
#define	VTCRYPTO_GCM_IVLEN		12u

MALLOC_DEFINE(M_VTCRYPTO, "vtcrypto", "VirtIO Crypto");

/*
 * Per-session driver state.  For CIPHER and AEAD both directions are created;
 * for HASH and MAC only vss_sid_enc/vss_enc_valid are used.
 */
struct vtcrypto_session {
	uint64_t	vss_sid_enc;
	uint64_t	vss_sid_dec;
	bool		vss_enc_valid;
	bool		vss_dec_valid;
	int		vss_service;	/* VIRTIO_CRYPTO_SERVICE_* */
	int		vss_mode;	/* CSP_MODE_* */
};

/* Per-data-queue state. */
struct vtcrypto_dataq {
	struct vtcrypto_softc	*vdq_sc;
	struct virtqueue	*vdq_vq;
	struct mtx		 vdq_mtx;
	int			 vdq_id;
	bool			 vdq_mtx_init;
};

/*
 * In-flight data request context; the cookie passed to virtqueue_enqueue().
 * The readable and writable wire buffers are each physically contiguous so
 * they occupy a single descriptor.
 */
struct vtcrypto_request {
	struct cryptop	*vcr_crp;
	uint8_t		*vcr_rbuf;	/* header + iv + aad + src */
	size_t		 vcr_rbuf_len;
	uint8_t		*vcr_wbuf;	/* out payload + 1 status byte */
	size_t		 vcr_wbuf_len;
	uint32_t	 vcr_service;
	uint32_t	 vcr_outlen;	/* payload bytes device writes */
	uint32_t	 vcr_taglen;	/* AEAD tag bytes, else 0 */
	uint32_t	 vcr_maclen;	/* digest bytes to return, else 0 */
	bool		 vcr_encrypt;
	bool		 vcr_verify;
};

struct vtcrypto_softc {
	device_t		 vtc_dev;
	uint64_t		 vtc_features;
	int32_t			 vtc_cid;

	struct mtx		 vtc_mtx;	/* control queue serialization */
	bool			 vtc_mtx_init;
	struct virtqueue	*vtc_ctrl_vq;
	bool			 vtc_ctrl_inuse;
	bool			 vtc_ctrl_done;
	bool			 vtc_ctrl_broken;	/* control queue wedged */
	uint8_t			*vtc_ctrl_wbuf;

	int			 vtc_ndataq;
	struct vtcrypto_dataq	*vtc_dataq;
	u_int			 vtc_rr;	/* data queue round-robin */

	/* Parsed device configuration / capabilities. */
	uint32_t		 vtc_services;
	uint32_t		 vtc_cipher_algo_l;
	uint32_t		 vtc_hash_algo;
	uint32_t		 vtc_mac_algo_l;
	uint32_t		 vtc_aead_algo;
	uint32_t		 vtc_max_cipher_key_len;
	uint32_t		 vtc_max_auth_key_len;

	bool			 vtc_have_cipher;
	bool			 vtc_have_hash;
	bool			 vtc_have_mac;
	bool			 vtc_have_aead;
};

/* Only the ring-reset feature is required for the detach quiesce path. */
#define	VTCRYPTO_FEATURES	(VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND)

static struct virtio_feature_desc vtcrypto_feature_desc[] = {
	{ VIRTIO_F_RING_RESET,	"RingReset" },
	{ VIRTIO_F_SUSPEND,	"Suspend" },
	{ 0, NULL }
};

static int	vtcrypto_modevent(module_t, int, void *);
static int	vtcrypto_probe(device_t);
static int	vtcrypto_attach(device_t);
static int	vtcrypto_detach(device_t);

static int	vtcrypto_setup_features(struct vtcrypto_softc *);
static void	vtcrypto_read_config(struct vtcrypto_softc *);
static int	vtcrypto_alloc_virtqueues(struct vtcrypto_softc *);
static void	vtcrypto_ctrl_intr(void *);
static void	vtcrypto_dataq_intr(void *);
static void	vtcrypto_enable_intr(struct vtcrypto_softc *);
static void	vtcrypto_drain(struct vtcrypto_softc *);

static int	vtcrypto_probesession(device_t,
		    const struct crypto_session_params *);
static int	vtcrypto_newsession(device_t, crypto_session_t,
		    const struct crypto_session_params *);
static void	vtcrypto_freesession(device_t, crypto_session_t);
static int	vtcrypto_process(device_t, struct cryptop *, int);

/* Little-endian codecs writing directly into wire byte buffers. */
static void
st32(void *p, uint32_t v)
{
	v = htole32(v);
	memcpy(p, &v, sizeof(v));
}

static void
st64(void *p, uint64_t v)
{
	v = htole64(v);
	memcpy(p, &v, sizeof(v));
}

static uint32_t
ld32(const void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return (le32toh(v));
}

static uint64_t
ld64(const void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));
	return (le64toh(v));
}

static device_method_t vtcrypto_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtcrypto_probe),
	DEVMETHOD(device_attach,	vtcrypto_attach),
	DEVMETHOD(device_detach,	vtcrypto_detach),

	/* Crypto device methods. */
	DEVMETHOD(cryptodev_probesession, vtcrypto_probesession),
	DEVMETHOD(cryptodev_newsession,	vtcrypto_newsession),
	DEVMETHOD(cryptodev_freesession, vtcrypto_freesession),
	DEVMETHOD(cryptodev_process,	vtcrypto_process),

	DEVMETHOD_END
};

static driver_t vtcrypto_driver = {
	"vtcrypto",
	vtcrypto_methods,
	sizeof(struct vtcrypto_softc)
};

VIRTIO_DRIVER_MODULE(virtio_crypto, vtcrypto_driver, vtcrypto_modevent, NULL);
MODULE_VERSION(virtio_crypto, 1);
MODULE_DEPEND(virtio_crypto, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_crypto, crypto, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(virtio_crypto, VIRTIO_ID_CRYPTO, "VirtIO Crypto Adapter");

static int
vtcrypto_modevent(module_t mod, int type, void *unused)
{

	switch (type) {
	case MOD_LOAD:
	case MOD_QUIESCE:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static int
vtcrypto_probe(device_t dev)
{

	return (VIRTIO_SIMPLE_PROBE(dev, virtio_crypto));
}

static int
vtcrypto_attach(device_t dev)
{
	struct vtcrypto_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtc_dev = dev;
	virtio_set_feature_desc(dev, vtcrypto_feature_desc);

	mtx_init(&sc->vtc_mtx, device_get_nameunit(dev), "vtccrl", MTX_DEF);
	sc->vtc_mtx_init = true;

	error = vtcrypto_setup_features(sc);
	if (error != 0) {
		device_printf(dev, "cannot setup features\n");
		goto fail;
	}

	vtcrypto_read_config(sc);
	if (!sc->vtc_have_cipher) {
		device_printf(dev,
		    "device does not offer CIPHER/AES-CBC; not attaching\n");
		error = ENXIO;
		goto fail;
	}

	error = vtcrypto_alloc_virtqueues(sc);
	if (error != 0) {
		device_printf(dev, "cannot allocate virtqueues\n");
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC);
	if (error != 0) {
		device_printf(dev, "cannot setup virtqueue interrupts\n");
		goto fail;
	}
	vtcrypto_enable_intr(sc);

	/*
	 * Register with opencrypto only after interrupts are live, since
	 * newsession() issues a synchronous control request that completes
	 * from the control-queue interrupt handler.
	 */
	sc->vtc_cid = crypto_get_driverid(dev, sizeof(struct vtcrypto_session),
	    CRYPTOCAP_F_HARDWARE);
	if (sc->vtc_cid < 0) {
		device_printf(dev, "cannot get crypto driver id\n");
		error = ENXIO;
		goto fail;
	}

	return (0);

fail:
	vtcrypto_detach(dev);
	return (error);
}

static int
vtcrypto_detach(device_t dev)
{
	struct vtcrypto_softc *sc;
	int i;

	sc = device_get_softc(dev);

	if (sc->vtc_cid >= 0) {
		crypto_unregister_all(sc->vtc_cid);
		sc->vtc_cid = -1;
	}

	/* Stop the device generating interrupts, then reclaim descriptors. */
	virtio_teardown_intr(dev);
	vtcrypto_drain(sc);

	if (sc->vtc_dataq != NULL) {
		for (i = 0; i < sc->vtc_ndataq; i++) {
			if (sc->vtc_dataq[i].vdq_mtx_init)
				mtx_destroy(&sc->vtc_dataq[i].vdq_mtx);
		}
		free(sc->vtc_dataq, M_VTCRYPTO);
		sc->vtc_dataq = NULL;
	}
	if (sc->vtc_mtx_init) {
		mtx_destroy(&sc->vtc_mtx);
		sc->vtc_mtx_init = false;
	}
	return (0);
}

static int
vtcrypto_setup_features(struct vtcrypto_softc *sc)
{
	device_t dev;

	dev = sc->vtc_dev;
	sc->vtc_cid = -1;
	sc->vtc_features = virtio_negotiate_features(dev, VTCRYPTO_FEATURES);
	return (virtio_finalize_features(dev));
}

#define	VTCRYPTO_GET_CONFIG(_dev, _field, _val)				\
	virtio_read_device_config(_dev,					\
	    offsetof(struct virtio_crypto_config, _field),		\
	    (_val), sizeof(((struct virtio_crypto_config *)0)->_field))

static void
vtcrypto_read_config(struct vtcrypto_softc *sc)
{
	device_t dev;
	uint32_t max_dataqueues, ndataq;

	dev = sc->vtc_dev;

	VTCRYPTO_GET_CONFIG(dev, max_dataqueues, &max_dataqueues);
	VTCRYPTO_GET_CONFIG(dev, crypto_services, &sc->vtc_services);
	VTCRYPTO_GET_CONFIG(dev, cipher_algo_l, &sc->vtc_cipher_algo_l);
	VTCRYPTO_GET_CONFIG(dev, hash_algo, &sc->vtc_hash_algo);
	VTCRYPTO_GET_CONFIG(dev, mac_algo_l, &sc->vtc_mac_algo_l);
	VTCRYPTO_GET_CONFIG(dev, aead_algo, &sc->vtc_aead_algo);
	VTCRYPTO_GET_CONFIG(dev, max_cipher_key_len, &sc->vtc_max_cipher_key_len);
	VTCRYPTO_GET_CONFIG(dev, max_auth_key_len, &sc->vtc_max_auth_key_len);

	ndataq = max_dataqueues;
	if (ndataq == 0)
		ndataq = 1;
	if (ndataq > VTCRYPTO_MAX_DATA_QUEUES)
		ndataq = VTCRYPTO_MAX_DATA_QUEUES;
	sc->vtc_ndataq = (int)ndataq;

	sc->vtc_have_cipher =
	    (sc->vtc_services & (1u << VIRTIO_CRYPTO_SERVICE_CIPHER)) != 0 &&
	    (sc->vtc_cipher_algo_l & (1u << VIRTIO_CRYPTO_CIPHER_AES_CBC)) != 0;
	sc->vtc_have_hash =
	    (sc->vtc_services & (1u << VIRTIO_CRYPTO_SERVICE_HASH)) != 0 &&
	    (sc->vtc_hash_algo & (1u << VIRTIO_CRYPTO_HASH_SHA_256)) != 0;
	sc->vtc_have_mac =
	    (sc->vtc_services & (1u << VIRTIO_CRYPTO_SERVICE_MAC)) != 0 &&
	    (sc->vtc_mac_algo_l & (1u << VIRTIO_CRYPTO_MAC_HMAC_SHA_256)) != 0;
	sc->vtc_have_aead =
	    (sc->vtc_services & (1u << VIRTIO_CRYPTO_SERVICE_AEAD)) != 0 &&
	    (sc->vtc_aead_algo & (1u << VIRTIO_CRYPTO_AEAD_GCM)) != 0;

	if (bootverbose) {
		device_printf(dev,
		    "%d data queue(s); cipher=%d hash=%d mac=%d aead=%d\n",
		    sc->vtc_ndataq, sc->vtc_have_cipher, sc->vtc_have_hash,
		    sc->vtc_have_mac, sc->vtc_have_aead);
	}
}

#undef VTCRYPTO_GET_CONFIG

/*
 * Allocate the data virtqueues (indices 0..ndataq-1) and the control
 * virtqueue (index ndataq, the last queue), matching the host layout.
 */
static int
vtcrypto_alloc_virtqueues(struct vtcrypto_softc *sc)
{
	device_t dev;
	struct vq_alloc_info *info;
	int error, i, nvqs;

	dev = sc->vtc_dev;
	nvqs = sc->vtc_ndataq + 1;

	sc->vtc_dataq = mallocarray(sc->vtc_ndataq,
	    sizeof(struct vtcrypto_dataq), M_VTCRYPTO, M_NOWAIT | M_ZERO);
	info = mallocarray(nvqs, sizeof(*info), M_VTCRYPTO,
	    M_NOWAIT | M_ZERO);
	if (sc->vtc_dataq == NULL || info == NULL) {
		free(info, M_VTCRYPTO);
		return (ENOMEM);
	}

	for (i = 0; i < sc->vtc_ndataq; i++) {
		struct vtcrypto_dataq *dq = &sc->vtc_dataq[i];

		dq->vdq_sc = sc;
		dq->vdq_id = i;
		mtx_init(&dq->vdq_mtx, device_get_nameunit(dev), "vtcdq",
		    MTX_DEF);
		dq->vdq_mtx_init = true;
		VQ_ALLOC_INFO_INIT(&info[i], 0, vtcrypto_dataq_intr, dq,
		    &dq->vdq_vq, "%s data.%d", device_get_nameunit(dev), i);
	}
	VQ_ALLOC_INFO_INIT(&info[sc->vtc_ndataq], 0, vtcrypto_ctrl_intr, sc,
	    &sc->vtc_ctrl_vq, "%s control", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, nvqs, info);
	free(info, M_VTCRYPTO);
	return (error);
}

static void
vtcrypto_enable_intr(struct vtcrypto_softc *sc)
{
	int i;

	for (i = 0; i < sc->vtc_ndataq; i++)
		virtqueue_enable_intr(sc->vtc_dataq[i].vdq_vq);
	virtqueue_enable_intr(sc->vtc_ctrl_vq);
}

/*
 * Reset, then drain, every virtqueue so the device relinquishes ownership of
 * guest buffers before they are freed.  Any in-flight cookies are reclaimed
 * and their crypto ops failed.
 */
static void
vtcrypto_drain_vq(struct vtcrypto_softc *sc, struct virtqueue *vq, bool data)
{
	void *cookie;
	int last;

	if (vq == NULL)
		return;
	if (!virtqueue_empty(vq)) {
		if (virtio_reset_virtqueue(sc->vtc_dev, vq) != 0)
			virtio_stop(sc->vtc_dev);
	}
	last = 0;
	while ((cookie = virtqueue_drain(vq, &last)) != NULL) {
		if (data && cookie != NULL) {
			struct vtcrypto_request *vcr = cookie;

			free(vcr->vcr_rbuf, M_VTCRYPTO);
			free(vcr->vcr_wbuf, M_VTCRYPTO);
			if (vcr->vcr_crp != NULL) {
				vcr->vcr_crp->crp_etype = ENXIO;
				crypto_done(vcr->vcr_crp);
			}
			free(vcr, M_VTCRYPTO);
		}
	}
}

static void
vtcrypto_drain(struct vtcrypto_softc *sc)
{
	int i;

	if (sc->vtc_dataq != NULL) {
		for (i = 0; i < sc->vtc_ndataq; i++)
			vtcrypto_drain_vq(sc, sc->vtc_dataq[i].vdq_vq, true);
	}
	vtcrypto_drain_vq(sc, sc->vtc_ctrl_vq, false);
}

/*
 * Map a one-byte device status to an errno.
 */
static int
vtcrypto_status_error(uint8_t status)
{

	switch (status) {
	case VIRTIO_CRYPTO_S_OK:
		return (0);
	case VIRTIO_CRYPTO_S_BADMSG:
		return (EBADMSG);
	case VIRTIO_CRYPTO_S_NOTSUPP:
		return (EOPNOTSUPP);
	case VIRTIO_CRYPTO_S_INVSESS:
		return (EINVAL);
	case VIRTIO_CRYPTO_S_ERR:
	default:
		return (EIO);
	}
}

/*
 * Control-queue interrupt: report completion of the single outstanding
 * synchronous control request to its waiter.
 */
static void
vtcrypto_ctrl_intr(void *xsc)
{
	struct vtcrypto_softc *sc = xsc;
	struct virtqueue *vq = sc->vtc_ctrl_vq;
	void *cookie;

	mtx_lock(&sc->vtc_mtx);
	do {
		virtqueue_disable_intr(vq);
		while ((cookie = virtqueue_dequeue(vq, NULL)) != NULL) {
			sc->vtc_ctrl_done = true;
			wakeup(&sc->vtc_ctrl_done);
		}
	} while (virtqueue_enable_intr(vq) != 0);
	mtx_unlock(&sc->vtc_mtx);
}

/*
 * Issue one control request and block until it completes.  rbuf/wbuf are
 * physically contiguous wire buffers owned by the caller.  On a create,
 * *sidp receives the new session id.
 */
static int
vtcrypto_ctrl_exec(struct vtcrypto_softc *sc, uint8_t *rbuf, size_t rlen,
    uint8_t *wbuf, size_t wlen, bool is_create, uint64_t *sidp,
    bool *retainedp)
{
	struct sglist *sg;
	int error, rd, wr;
	uint8_t status;

	/*
	 * *retainedp reports whether the device still owns rbuf/wbuf on
	 * return: the caller must NOT free them in that case.  Only the
	 * timeout path (below) sets it, because that is the only path that
	 * leaves a descriptor posted to the device.
	 */
	*retainedp = false;

	mtx_lock(&sc->vtc_mtx);
	/*
	 * A prior control request that timed out left its descriptor posted
	 * and the queue in an unknown state; refuse further control traffic
	 * rather than enqueue a second descriptor the device could complete
	 * out of order into a freed buffer.
	 */
	if (sc->vtc_ctrl_broken) {
		mtx_unlock(&sc->vtc_mtx);
		return (EIO);
	}
	while (sc->vtc_ctrl_inuse) {
		error = msleep(&sc->vtc_ctrl_inuse, &sc->vtc_mtx, PZERO,
		    "vtcbsy", 0);
	}
	sc->vtc_ctrl_inuse = true;
	sc->vtc_ctrl_done = false;
	sc->vtc_ctrl_wbuf = wbuf;

	sg = sglist_alloc(4, M_NOWAIT);
	if (sg == NULL) {
		error = ENOMEM;
		goto release;
	}
	error = sglist_append(sg, rbuf, rlen);
	if (error != 0) {
		sglist_free(sg);
		goto release;
	}
	rd = sg->sg_nseg;
	error = sglist_append(sg, wbuf, wlen);
	if (error != 0) {
		sglist_free(sg);
		goto release;
	}
	wr = sg->sg_nseg - rd;

	error = virtqueue_enqueue(sc->vtc_ctrl_vq, sc, sg, rd, wr);
	sglist_free(sg);
	if (error != 0)
		goto release;
	virtqueue_notify(sc->vtc_ctrl_vq);

	while (!sc->vtc_ctrl_done) {
		error = msleep(&sc->vtc_ctrl_done, &sc->vtc_mtx, PZERO,
		    "vtcctl", 10 * hz);
		if (error == EWOULDBLOCK && !sc->vtc_ctrl_done) {
			/*
			 * The device never returned the descriptor; it still
			 * owns rbuf/wbuf.  Retain (leak) them so a late DMA
			 * cannot corrupt freed memory, wedge the control queue
			 * so no future request enqueues behind this one, and
			 * tell the caller not to free.
			 */
			sc->vtc_ctrl_broken = true;
			*retainedp = true;
			error = EIO;
			goto release;
		}
	}

	if (is_create) {
		status = (uint8_t)ld32(wbuf + VTC_SI_OFF_STATUS);
		error = vtcrypto_status_error(status);
		if (error == 0 && sidp != NULL)
			*sidp = ld64(wbuf + VTC_SI_OFF_SESSION_ID);
	} else {
		error = vtcrypto_status_error(wbuf[0]);
	}

release:
	sc->vtc_ctrl_inuse = false;
	wakeup(&sc->vtc_ctrl_inuse);
	mtx_unlock(&sc->vtc_mtx);
	return (error);
}

/*
 * Build and issue a symmetric CREATE_SESSION control request.  For CIPHER and
 * AEAD, op selects the fixed direction; HASH and MAC ignore op.
 */
static int
vtcrypto_create_session(struct vtcrypto_softc *sc, int service,
    const struct crypto_session_params *csp, uint32_t op, uint64_t *sidp)
{
	uint8_t *rbuf, *wbuf;
	const void *key;
	uint32_t opcode, keylen;
	size_t rlen;
	bool retained = false;
	int error;

	key = NULL;
	keylen = 0;

	rbuf = contigmalloc(VTCRYPTO_CTRL_REQ_LEN + VTCRYPTO_MAX_KEYLEN,
	    M_VTCRYPTO, M_NOWAIT | M_ZERO, 0, ~0UL, PAGE_SIZE, 0);
	wbuf = contigmalloc(VTCRYPTO_SESSION_INPUT_LEN, M_VTCRYPTO,
	    M_NOWAIT | M_ZERO, 0, ~0UL, PAGE_SIZE, 0);
	if (rbuf == NULL || wbuf == NULL) {
		error = ENOMEM;
		goto out;
	}

	switch (service) {
	case VIRTIO_CRYPTO_SERVICE_CIPHER:
		opcode = VIRTIO_CRYPTO_CIPHER_CREATE_SESSION;
		keylen = csp->csp_cipher_klen;
		key = csp->csp_cipher_key;
		st32(rbuf + VTC_CTRL_OFF_CIPHER_ALGO,
		    VIRTIO_CRYPTO_CIPHER_AES_CBC);
		st32(rbuf + VTC_CTRL_OFF_CIPHER_KEYLEN, keylen);
		st32(rbuf + VTC_CTRL_OFF_CIPHER_OP, op);
		st32(rbuf + VTC_CTRL_OFF_SYM_OP_TYPE,
		    VIRTIO_CRYPTO_SYM_OP_CIPHER);
		break;
	case VIRTIO_CRYPTO_SERVICE_HASH:
		opcode = VIRTIO_CRYPTO_HASH_CREATE_SESSION;
		st32(rbuf + VTC_CTRL_OFF_HASH_ALGO, VIRTIO_CRYPTO_HASH_SHA_256);
		st32(rbuf + VTC_CTRL_OFF_HASH_RESULT_LEN, VTCRYPTO_SHA256_LEN);
		break;
	case VIRTIO_CRYPTO_SERVICE_MAC:
		opcode = VIRTIO_CRYPTO_MAC_CREATE_SESSION;
		keylen = csp->csp_auth_klen;
		key = csp->csp_auth_key;
		st32(rbuf + VTC_CTRL_OFF_MAC_ALGO,
		    VIRTIO_CRYPTO_MAC_HMAC_SHA_256);
		st32(rbuf + VTC_CTRL_OFF_MAC_RESULT_LEN, VTCRYPTO_SHA256_LEN);
		st32(rbuf + VTC_CTRL_OFF_MAC_AUTH_KEYLEN, keylen);
		break;
	case VIRTIO_CRYPTO_SERVICE_AEAD:
		opcode = VIRTIO_CRYPTO_AEAD_CREATE_SESSION;
		keylen = csp->csp_cipher_klen;
		key = csp->csp_cipher_key;
		st32(rbuf + VTC_CTRL_OFF_AEAD_ALGO, VIRTIO_CRYPTO_AEAD_GCM);
		st32(rbuf + VTC_CTRL_OFF_AEAD_KEYLEN, keylen);
		st32(rbuf + VTC_CTRL_OFF_AEAD_RESULT_LEN, VTCRYPTO_GCM_TAGLEN);
		st32(rbuf + VTC_CTRL_OFF_AEAD_AAD_LEN, 0);
		st32(rbuf + VTC_CTRL_OFF_AEAD_OP, op);
		break;
	default:
		error = EOPNOTSUPP;
		goto out;
	}

	if (keylen > VTCRYPTO_MAX_KEYLEN) {
		error = EINVAL;
		goto out;
	}
	st32(rbuf + VTC_CTRL_OFF_OPCODE, opcode);
	if (keylen > 0 && key != NULL)
		memcpy(rbuf + VTCRYPTO_CTRL_REQ_LEN, key, keylen);
	rlen = VTCRYPTO_CTRL_REQ_LEN + keylen;

	error = vtcrypto_ctrl_exec(sc, rbuf, rlen, wbuf,
	    VTCRYPTO_SESSION_INPUT_LEN, true, sidp, &retained);

out:
	if (!retained) {
		free(rbuf, M_VTCRYPTO);
		free(wbuf, M_VTCRYPTO);
	}
	return (error);
}

static int
vtcrypto_destroy_session(struct vtcrypto_softc *sc, int service, uint64_t sid)
{
	uint8_t *rbuf, *wbuf;
	uint32_t opcode;
	bool retained = false;
	int error;

	switch (service) {
	case VIRTIO_CRYPTO_SERVICE_CIPHER:
		opcode = VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION;
		break;
	case VIRTIO_CRYPTO_SERVICE_HASH:
		opcode = VIRTIO_CRYPTO_HASH_DESTROY_SESSION;
		break;
	case VIRTIO_CRYPTO_SERVICE_MAC:
		opcode = VIRTIO_CRYPTO_MAC_DESTROY_SESSION;
		break;
	case VIRTIO_CRYPTO_SERVICE_AEAD:
		opcode = VIRTIO_CRYPTO_AEAD_DESTROY_SESSION;
		break;
	default:
		return (EOPNOTSUPP);
	}

	rbuf = contigmalloc(VTCRYPTO_CTRL_REQ_LEN, M_VTCRYPTO,
	    M_NOWAIT | M_ZERO, 0, ~0UL, PAGE_SIZE, 0);
	wbuf = contigmalloc(1, M_VTCRYPTO, M_NOWAIT | M_ZERO, 0, ~0UL,
	    PAGE_SIZE, 0);
	if (rbuf == NULL || wbuf == NULL) {
		error = ENOMEM;
		goto out;
	}
	st32(rbuf + VTC_CTRL_OFF_OPCODE, opcode);
	st64(rbuf + VTC_CTRL_OFF_DESTROY_SESSID, sid);
	error = vtcrypto_ctrl_exec(sc, rbuf, VTCRYPTO_CTRL_REQ_LEN, wbuf, 1,
	    false, NULL, &retained);
out:
	if (!retained) {
		free(rbuf, M_VTCRYPTO);
		free(wbuf, M_VTCRYPTO);
	}
	return (error);
}

/*
 * opencrypto probesession: report support for the modes the device offers.
 */
static int
vtcrypto_probesession(device_t dev, const struct crypto_session_params *csp)
{
	struct vtcrypto_softc *sc = device_get_softc(dev);

	if ((csp->csp_flags & ~(CSP_F_SEPARATE_AAD)) != 0)
		return (EINVAL);

	switch (csp->csp_mode) {
	case CSP_MODE_CIPHER:
		if (!sc->vtc_have_cipher)
			return (EINVAL);
		if (csp->csp_cipher_alg != CRYPTO_AES_CBC)
			return (EINVAL);
		switch (csp->csp_cipher_klen) {
		case 16:
		case 24:
		case 32:
			break;
		default:
			return (EINVAL);
		}
		if (csp->csp_ivlen != VTCRYPTO_AES_BLOCK)
			return (EINVAL);
		break;
	case CSP_MODE_DIGEST:
		if (csp->csp_auth_alg == CRYPTO_SHA2_256) {
			if (!sc->vtc_have_hash)
				return (EINVAL);
			if (csp->csp_auth_klen != 0)
				return (EINVAL);
		} else if (csp->csp_auth_alg == CRYPTO_SHA2_256_HMAC) {
			if (!sc->vtc_have_mac)
				return (EINVAL);
			if (csp->csp_auth_klen == 0 ||
			    csp->csp_auth_klen > VTCRYPTO_MAX_KEYLEN)
				return (EINVAL);
		} else
			return (EINVAL);
		if (csp->csp_auth_mlen != 0 &&
		    csp->csp_auth_mlen > VTCRYPTO_SHA256_LEN)
			return (EINVAL);
		break;
	case CSP_MODE_AEAD:
		if (!sc->vtc_have_aead)
			return (EINVAL);
		if (csp->csp_cipher_alg != CRYPTO_AES_NIST_GCM_16)
			return (EINVAL);
		switch (csp->csp_cipher_klen) {
		case 16:
		case 24:
		case 32:
			break;
		default:
			return (EINVAL);
		}
		if (csp->csp_ivlen != VTCRYPTO_GCM_IVLEN)
			return (EINVAL);
		if (csp->csp_auth_mlen != 0 &&
		    csp->csp_auth_mlen != VTCRYPTO_GCM_TAGLEN)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}

	return (CRYPTODEV_PROBE_HARDWARE);
}

static int
vtcrypto_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct vtcrypto_softc *sc = device_get_softc(dev);
	struct vtcrypto_session *s = crypto_get_driver_session(cses);
	int error, service;

	memset(s, 0, sizeof(*s));
	s->vss_mode = csp->csp_mode;

	switch (csp->csp_mode) {
	case CSP_MODE_CIPHER:
		service = VIRTIO_CRYPTO_SERVICE_CIPHER;
		break;
	case CSP_MODE_AEAD:
		service = VIRTIO_CRYPTO_SERVICE_AEAD;
		break;
	case CSP_MODE_DIGEST:
		service = (csp->csp_auth_alg == CRYPTO_SHA2_256_HMAC) ?
		    VIRTIO_CRYPTO_SERVICE_MAC : VIRTIO_CRYPTO_SERVICE_HASH;
		break;
	default:
		return (EINVAL);
	}
	s->vss_service = service;

	if (service == VIRTIO_CRYPTO_SERVICE_CIPHER ||
	    service == VIRTIO_CRYPTO_SERVICE_AEAD) {
		/* Direction-bound modes need one host session per direction. */
		error = vtcrypto_create_session(sc, service, csp,
		    VIRTIO_CRYPTO_OP_ENCRYPT, &s->vss_sid_enc);
		if (error != 0)
			return (error);
		s->vss_enc_valid = true;
		error = vtcrypto_create_session(sc, service, csp,
		    VIRTIO_CRYPTO_OP_DECRYPT, &s->vss_sid_dec);
		if (error != 0) {
			vtcrypto_destroy_session(sc, service, s->vss_sid_enc);
			s->vss_enc_valid = false;
			return (error);
		}
		s->vss_dec_valid = true;
	} else {
		error = vtcrypto_create_session(sc, service, csp, 0,
		    &s->vss_sid_enc);
		if (error != 0)
			return (error);
		s->vss_enc_valid = true;
	}
	return (0);
}

static void
vtcrypto_freesession(device_t dev, crypto_session_t cses)
{
	struct vtcrypto_softc *sc = device_get_softc(dev);
	struct vtcrypto_session *s = crypto_get_driver_session(cses);

	if (s->vss_enc_valid)
		vtcrypto_destroy_session(sc, s->vss_service, s->vss_sid_enc);
	if (s->vss_dec_valid)
		vtcrypto_destroy_session(sc, s->vss_service, s->vss_sid_dec);
	s->vss_enc_valid = s->vss_dec_valid = false;
}

/*
 * Complete one finished data request: check the device status byte, copy the
 * output back into the cryptop, and call crypto_done().
 */
static void
vtcrypto_finish_request(struct vtcrypto_softc *sc, struct vtcrypto_request *vcr)
{
	struct cryptop *crp = vcr->vcr_crp;
	uint8_t status;
	int error;

	status = vcr->vcr_wbuf[vcr->vcr_wbuf_len - 1];
	error = vtcrypto_status_error(status);
	if (error != 0)
		goto done;

	switch (vcr->vcr_service) {
	case VIRTIO_CRYPTO_SERVICE_CIPHER:
		crypto_copyback(crp, crp->crp_payload_start, vcr->vcr_outlen,
		    vcr->vcr_wbuf);
		break;
	case VIRTIO_CRYPTO_SERVICE_AEAD:
		crypto_copyback(crp, crp->crp_payload_start, vcr->vcr_outlen,
		    vcr->vcr_wbuf);
		if (vcr->vcr_encrypt && vcr->vcr_taglen != 0) {
			crypto_copyback(crp, crp->crp_digest_start,
			    vcr->vcr_taglen, vcr->vcr_wbuf + vcr->vcr_outlen);
		}
		break;
	case VIRTIO_CRYPTO_SERVICE_HASH:
	case VIRTIO_CRYPTO_SERVICE_MAC:
		if (vcr->vcr_verify) {
			uint8_t digest[VTCRYPTO_SHA256_LEN];

			crypto_copydata(crp, crp->crp_digest_start,
			    vcr->vcr_maclen, digest);
			if (timingsafe_bcmp(vcr->vcr_wbuf, digest,
			    vcr->vcr_maclen) != 0)
				error = EBADMSG;
		} else {
			crypto_copyback(crp, crp->crp_digest_start,
			    vcr->vcr_maclen, vcr->vcr_wbuf);
		}
		break;
	}

done:
	free(vcr->vcr_rbuf, M_VTCRYPTO);
	free(vcr->vcr_wbuf, M_VTCRYPTO);
	crp->crp_etype = error;
	crypto_done(crp);
	free(vcr, M_VTCRYPTO);
}

static void
vtcrypto_dataq_intr(void *xdq)
{
	struct vtcrypto_dataq *dq = xdq;
	struct vtcrypto_softc *sc = dq->vdq_sc;
	struct virtqueue *vq = dq->vdq_vq;
	struct vtcrypto_request *vcr;

	mtx_lock(&dq->vdq_mtx);
	do {
		virtqueue_disable_intr(vq);
		while ((vcr = virtqueue_dequeue(vq, NULL)) != NULL) {
			mtx_unlock(&dq->vdq_mtx);
			vtcrypto_finish_request(sc, vcr);
			mtx_lock(&dq->vdq_mtx);
		}
	} while (virtqueue_enable_intr(vq) != 0);
	mtx_unlock(&dq->vdq_mtx);
}

/*
 * Build the readable/writable wire buffers for one data request and submit it
 * to a data queue.  Fields are validated so the host cannot be handed an
 * out-of-range length.
 */
static int
vtcrypto_process(device_t dev, struct cryptop *crp, int hint __unused)
{
	struct vtcrypto_softc *sc = device_get_softc(dev);
	const struct crypto_session_params *csp;
	struct vtcrypto_session *s;
	struct vtcrypto_request *vcr;
	struct vtcrypto_dataq *dq;
	struct sglist *sg;
	uint8_t *hdr, *p;
	uint64_t sid;
	uint32_t opcode, ivlen, aadlen, srclen, dstlen, maclen;
	size_t rlen, roff;
	int error, rd, wr;
	bool encrypt;

	csp = crypto_get_params(crp->crp_session);
	s = crypto_get_driver_session(crp->crp_session);
	encrypt = CRYPTO_OP_IS_ENCRYPT(crp->crp_op);

	if (crp->crp_payload_length > (int)VTCRYPTO_MAX_DATALEN) {
		error = E2BIG;
		goto fail;
	}

	vcr = malloc(sizeof(*vcr), M_VTCRYPTO, M_NOWAIT | M_ZERO);
	if (vcr == NULL) {
		error = ENOMEM;
		goto fail;
	}
	vcr->vcr_crp = crp;
	vcr->vcr_service = s->vss_service;

	ivlen = csp->csp_ivlen;
	srclen = crp->crp_payload_length;
	aadlen = 0;

	switch (s->vss_service) {
	case VIRTIO_CRYPTO_SERVICE_CIPHER:
		if ((srclen % VTCRYPTO_AES_BLOCK) != 0 || srclen == 0) {
			error = EINVAL;
			goto fail_vcr;
		}
		sid = encrypt ? s->vss_sid_enc : s->vss_sid_dec;
		opcode = encrypt ? VIRTIO_CRYPTO_CIPHER_ENCRYPT :
		    VIRTIO_CRYPTO_CIPHER_DECRYPT;
		dstlen = srclen;
		vcr->vcr_outlen = srclen;
		vcr->vcr_encrypt = encrypt;
		rlen = VTCRYPTO_DATA_REQ_LEN + ivlen + srclen;
		break;
	case VIRTIO_CRYPTO_SERVICE_AEAD:
		aadlen = crp->crp_aad_length;
		if (aadlen > VTCRYPTO_MAX_AADLEN) {
			error = EINVAL;
			goto fail_vcr;
		}
		sid = encrypt ? s->vss_sid_enc : s->vss_sid_dec;
		opcode = encrypt ? VIRTIO_CRYPTO_AEAD_ENCRYPT :
		    VIRTIO_CRYPTO_AEAD_DECRYPT;
		vcr->vcr_encrypt = encrypt;
		vcr->vcr_taglen = VTCRYPTO_GCM_TAGLEN;
		if (encrypt) {
			/* src=plaintext; dst=ciphertext||tag. */
			dstlen = srclen + VTCRYPTO_GCM_TAGLEN;
			vcr->vcr_outlen = srclen;
			rlen = VTCRYPTO_DATA_REQ_LEN + ivlen + aadlen + srclen;
		} else {
			/* src=ciphertext||tag; dst=plaintext. */
			srclen += VTCRYPTO_GCM_TAGLEN;
			dstlen = crp->crp_payload_length;
			vcr->vcr_outlen = crp->crp_payload_length;
			rlen = VTCRYPTO_DATA_REQ_LEN + ivlen + aadlen + srclen;
		}
		break;
	case VIRTIO_CRYPTO_SERVICE_HASH:
	case VIRTIO_CRYPTO_SERVICE_MAC:
		sid = s->vss_sid_enc;
		opcode = (s->vss_service == VIRTIO_CRYPTO_SERVICE_MAC) ?
		    VIRTIO_CRYPTO_MAC : VIRTIO_CRYPTO_HASH;
		maclen = csp->csp_auth_mlen != 0 ? csp->csp_auth_mlen :
		    VTCRYPTO_SHA256_LEN;
		vcr->vcr_maclen = maclen;
		vcr->vcr_verify =
		    (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) != 0;
		ivlen = 0;
		dstlen = VTCRYPTO_SHA256_LEN;	/* device always writes 32 */
		vcr->vcr_outlen = VTCRYPTO_SHA256_LEN;
		rlen = VTCRYPTO_DATA_REQ_LEN + srclen;
		break;
	default:
		error = EINVAL;
		goto fail_vcr;
	}

	vcr->vcr_rbuf_len = rlen;
	vcr->vcr_wbuf_len = (size_t)dstlen + 1;	/* + 1 status byte */
	vcr->vcr_rbuf = contigmalloc(rlen, M_VTCRYPTO, M_NOWAIT | M_ZERO,
	    0, ~0UL, PAGE_SIZE, 0);
	vcr->vcr_wbuf = contigmalloc(vcr->vcr_wbuf_len, M_VTCRYPTO,
	    M_NOWAIT | M_ZERO, 0, ~0UL, PAGE_SIZE, 0);
	if (vcr->vcr_rbuf == NULL || vcr->vcr_wbuf == NULL) {
		error = ENOMEM;
		goto fail_bufs;
	}

	/* Common op_header. */
	hdr = vcr->vcr_rbuf;
	st32(hdr + VTC_DATA_OFF_OPCODE, opcode);
	st64(hdr + VTC_DATA_OFF_SESSION_ID, sid);

	/* Per-service parameters and gathered input. */
	roff = VTCRYPTO_DATA_REQ_LEN;
	if (s->vss_service == VIRTIO_CRYPTO_SERVICE_CIPHER) {
		st32(hdr + VTC_DATA_OFF_CIPHER_IV_LEN, ivlen);
		st32(hdr + VTC_DATA_OFF_CIPHER_SRC_LEN, crp->crp_payload_length);
		st32(hdr + VTC_DATA_OFF_CIPHER_DST_LEN, dstlen);
		crypto_read_iv(crp, vcr->vcr_rbuf + roff);
		roff += ivlen;
		crypto_copydata(crp, crp->crp_payload_start,
		    crp->crp_payload_length, vcr->vcr_rbuf + roff);
	} else if (s->vss_service == VIRTIO_CRYPTO_SERVICE_AEAD) {
		st32(hdr + VTC_DATA_OFF_AEAD_IV_LEN, ivlen);
		st32(hdr + VTC_DATA_OFF_AEAD_AAD_LEN, aadlen);
		st32(hdr + VTC_DATA_OFF_AEAD_SRC_LEN, srclen);
		st32(hdr + VTC_DATA_OFF_AEAD_DST_LEN, dstlen);
		crypto_read_iv(crp, vcr->vcr_rbuf + roff);
		roff += ivlen;
		if (aadlen > 0) {
			if (crp->crp_aad != NULL)
				memcpy(vcr->vcr_rbuf + roff, crp->crp_aad,
				    aadlen);
			else
				crypto_copydata(crp, crp->crp_aad_start,
				    aadlen, vcr->vcr_rbuf + roff);
			roff += aadlen;
		}
		p = vcr->vcr_rbuf + roff;
		crypto_copydata(crp, crp->crp_payload_start,
		    crp->crp_payload_length, p);
		if (!encrypt) {
			/* Append the tag the host will verify. */
			crypto_copydata(crp, crp->crp_digest_start,
			    VTCRYPTO_GCM_TAGLEN, p + crp->crp_payload_length);
		}
	} else {
		st32(hdr + VTC_DATA_OFF_HASH_SRC_LEN, crp->crp_payload_length);
		st32(hdr + VTC_DATA_OFF_HASH_RESULT_LEN, VTCRYPTO_SHA256_LEN);
		if (crp->crp_payload_length > 0)
			crypto_copydata(crp, crp->crp_payload_start,
			    crp->crp_payload_length, vcr->vcr_rbuf + roff);
	}

	/* Build the descriptor chain: one readable and one writable segment. */
	sg = sglist_alloc(4, M_NOWAIT);
	if (sg == NULL) {
		error = ENOMEM;
		goto fail_bufs;
	}
	error = sglist_append(sg, vcr->vcr_rbuf, rlen);
	if (error != 0) {
		sglist_free(sg);
		goto fail_bufs;
	}
	rd = sg->sg_nseg;
	error = sglist_append(sg, vcr->vcr_wbuf, vcr->vcr_wbuf_len);
	if (error != 0) {
		sglist_free(sg);
		goto fail_bufs;
	}
	wr = sg->sg_nseg - rd;

	dq = &sc->vtc_dataq[atomic_fetchadd_int(&sc->vtc_rr, 1) %
	    sc->vtc_ndataq];
	mtx_lock(&dq->vdq_mtx);
	error = virtqueue_enqueue(dq->vdq_vq, vcr, sg, rd, wr);
	if (error == 0)
		virtqueue_notify(dq->vdq_vq);
	mtx_unlock(&dq->vdq_mtx);
	sglist_free(sg);
	if (error != 0)
		goto fail_bufs;

	return (0);

fail_bufs:
	free(vcr->vcr_rbuf, M_VTCRYPTO);
	free(vcr->vcr_wbuf, M_VTCRYPTO);
fail_vcr:
	free(vcr, M_VTCRYPTO);
fail:
	crp->crp_etype = error;
	crypto_done(crp);
	return (0);
}
