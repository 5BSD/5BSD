/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TU-include ATF harness for the guest virtio_crypto(4) driver.
 *
 * The kernel headers the driver includes are suppressed through their include
 * guards and replaced with minimal mocks: a descriptor-counting virtqueue, a
 * contiguous-buffer cryptop and recorders for crypto_done()/crypto_unblock().
 * Expectations come from crypto(9) (a driver out of resources returns
 * ERESTART and later calls crypto_unblock()) and the VirtIO 1.2 data request
 * layout (virtio_crypto_sym_data_req.op_type at byte 64), never from the
 * driver's own constants.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/time.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <machine/atomic.h>

#include <atf-c.h>

/* ------------------------------------------------- suppressed kernel headers */
#define	_SYS_SYSTM_H_
#define	_SYS_BUS_H_
#define	_SYS_KERNEL_H_
#define	_SYS_LOCK_H_
#define	_SYS_MALLOC_H_
#define	_SYS_MODULE_H_
#define	_SYS_MUTEX_H_
#define	__SGLIST_H__
#define	_MACHINE_BUS_H_
#define	_VIRTIO_H_
#define	_VIRTIO_VIRTQUEUE_H
#define	_CRYPTO_CRYPTO_H_

#ifndef ERESTART
#define	ERESTART	(-1)	/* sys/errno.h, _KERNEL only */
#endif

/* ------------------------------------------------------------- kernel mocks */
struct mock_dev {
	void	*softc;
};
typedef struct mock_dev *device_t;
typedef void *module_t;
enum { MOD_LOAD, MOD_UNLOAD, MOD_SHUTDOWN, MOD_QUIESCE };

typedef struct {
	const char	*name;
	void		*fn;
} device_method_t;
#define	DEVMETHOD(n, f)	{ #n, (void *)(f) }
#define	DEVMETHOD_END	{ NULL, NULL }
typedef struct {
	const char	*name;
	device_method_t	*methods;
	size_t		 size;
} driver_t;

static int bootverbose;
#define	device_get_softc(d)	((d)->softc)
#define	device_get_nameunit(d)	"vtcrypto0"
#define	device_printf(d, ...)	printf(__VA_ARGS__)
#define	DELAY(us)		do { } while (0)
static sbintime_t sbinuptime(void) { return (0); }
#define	INTR_TYPE_MISC		0

struct mtx { int held; };
#define	MTX_DEF			0
#define	mtx_init(m, n, t, o)	((m)->held = 0)
#define	mtx_destroy(m)		do { } while (0)
#define	mtx_lock(m)		((m)->held++)
#define	mtx_unlock(m)		((m)->held--)

#define	M_NOWAIT		0x1
#define	M_ZERO			0x100
#define	MALLOC_DEFINE(t, s, l)	static const int t = 0
static void *
mock_malloc(size_t sz, int fl)
{
	return ((fl & M_ZERO) ? calloc(1, sz) : malloc(sz));
}
#define	malloc(sz, t, fl)	mock_malloc((sz), (fl))
#define	mallocarray(n, sz, t, fl) mock_malloc((n) * (sz), (fl))
#define	contigmalloc(sz, t, fl, lo, hi, al, b) mock_malloc((sz), (fl))
#define	free(p, t)		(free)(p)

#define	MODULE_VERSION(a, b)	_Static_assert(1, "")
#define	MODULE_DEPEND(a, b, c, d, e) _Static_assert(1, "")

struct sglist_seg {
	void	*ss_addr;
	size_t	 ss_len;
};
struct sglist {
	int			sg_nseg;
	int			sg_maxseg;
	struct sglist_seg	sg_segs[8];
};
static struct sglist *
sglist_alloc(int n, int fl)
{
	struct sglist *sg = mock_malloc(sizeof(*sg), M_ZERO);

	(void)fl;
	sg->sg_maxseg = n;
	return (sg);
}
static int
sglist_append(struct sglist *sg, void *buf, size_t len)
{
	if (sg->sg_nseg >= sg->sg_maxseg)
		return (EFBIG);
	sg->sg_segs[sg->sg_nseg].ss_addr = buf;
	sg->sg_segs[sg->sg_nseg].ss_len = len;
	sg->sg_nseg++;
	return (0);
}
#define	sglist_free(sg)		(free)(sg)

/* Virtqueue: a ring of RINGSZ descriptors, one per sglist segment. */
#define	MOCK_RINGSZ		64
#define	MOCK_MAXREQ		4096
typedef void virtqueue_intr_t(void *);
struct virtqueue {
	int		 free_desc;
	void		*cookie[MOCK_MAXREQ];
	int		 ndesc[MOCK_MAXREQ];
	int		 head, tail;		/* posted: [head, tail) */
	int		 used;			/* completed: [head, used) */
	uint8_t		 last_hdr[72];
};
struct vq_alloc_info { int unused; };
struct virtio_feature_desc {
	uint64_t	 vfd_val;
	const char	*vfd_str;
};
#define	VIRTIO_F_RING_RESET	(1ULL << 40)
#define	VIRTIO_F_SUSPEND	(1ULL << 43)
#define	VIRTIO_ID_CRYPTO	20
#define	VQ_ALLOC_INFO_INIT(i, n, f, a, vqp, ...) do { } while (0)
#define	VIRTIO_DRIVER_MODULE(n, d, e, a) _Static_assert(1, "")
#define	VIRTIO_SIMPLE_PNPINFO(d, t, s)	_Static_assert(1, "")
#define	VIRTIO_SIMPLE_PROBE(dev, d)	(0)
#define	virtio_set_feature_desc(d, f)	do { } while (0)
#define	virtio_negotiate_features(d, f)	((uint64_t)(f))
#define	virtio_finalize_features(d)	(0)
#define	virtio_read_device_config(d, o, v, s) memset((v), 0, (s))
#define	virtio_alloc_virtqueues(d, n, i) (0)
#define	virtio_setup_intr(d, t)		(0)
#define	virtio_teardown_intr(d)		do { } while (0)
#define	virtio_reset_virtqueue(d, vq)	(0)
#define	virtio_stop(d)			do { } while (0)

static int
virtqueue_enqueue(struct virtqueue *vq, void *cookie, struct sglist *sg,
    int readable, int writable)
{
	int n = readable + writable;

	/* sys/dev/virtio/virtqueue.c: ENOSPC when the ring lacks descriptors. */
	if (vq->free_desc < n)
		return (ENOSPC);
	ATF_REQUIRE(vq->tail < MOCK_MAXREQ);
	memcpy(vq->last_hdr, sg->sg_segs[0].ss_addr, sizeof(vq->last_hdr));
	vq->free_desc -= n;
	vq->cookie[vq->tail] = cookie;
	vq->ndesc[vq->tail] = n;
	vq->tail++;
	return (0);
}
#define	virtqueue_notify(vq)		do { } while (0)
#define	virtqueue_disable_intr(vq)	do { } while (0)
#define	virtqueue_enable_intr(vq)	(0)
#define	virtqueue_empty(vq)		((vq)->head == (vq)->tail)
static void *
virtqueue_dequeue(struct virtqueue *vq, uint32_t *len)
{
	(void)len;
	if (vq->head == vq->used)
		return (NULL);
	vq->free_desc += vq->ndesc[vq->head];
	return (vq->cookie[vq->head++]);
}
static void *
virtqueue_drain(struct virtqueue *vq, int *last)
{
	(void)last;
	if (vq->head == vq->tail)
		return (NULL);
	vq->free_desc += vq->ndesc[vq->head];
	return (vq->cookie[vq->head++]);
}

/* opencrypto. */
#define	CRYPTO_AES_CBC		11
#define	CRYPTO_SHA2_256_HMAC	18
#define	CRYPTO_AES_NIST_GCM_16	26
#define	CRYPTO_SHA2_256		32
#define	CSP_MODE_CIPHER		2
#define	CSP_MODE_DIGEST		3
#define	CSP_MODE_AEAD		4
#define	CSP_F_SEPARATE_AAD	0x0004
#define	CRYPTO_OP_ENCRYPT	0x1
#define	CRYPTO_OP_VERIFY_DIGEST	0x4
#define	CRYPTO_OP_IS_ENCRYPT(op) ((op) & CRYPTO_OP_ENCRYPT)
#define	CRYPTOCAP_F_HARDWARE	0x01000000
#define	CRYPTODEV_PROBE_HARDWARE (-100)
#define	CRYPTO_SYMQ		0x1

struct crypto_session_params {
	int		 csp_mode;
	int		 csp_flags;
	int		 csp_ivlen;
	int		 csp_cipher_alg;
	int		 csp_cipher_klen;
	const void	*csp_cipher_key;
	int		 csp_auth_alg;
	int		 csp_auth_klen;
	const void	*csp_auth_key;
	int		 csp_auth_mlen;
};
struct mock_session {
	struct crypto_session_params	 csp;
	void				*drv;
};
typedef struct mock_session *crypto_session_t;
struct cryptop {
	crypto_session_t crp_session;
	int		 crp_op;
	int		 crp_flags;
	int		 crp_etype;
	int		 crp_payload_start;
	int		 crp_payload_length;
	void		*crp_aad;
	int		 crp_aad_start;
	int		 crp_aad_length;
	int		 crp_digest_start;
	uint8_t		 iv[16];
	uint8_t		 buf[4096];
	bool		 done;
};
#define	crypto_get_params(s)		(&(s)->csp)
#define	crypto_get_driver_session(s)	((s)->drv)
#define	crypto_read_iv(crp, dst)	memcpy((dst), (crp)->iv, 16)
#define	crypto_copydata(crp, off, len, dst) \
	memcpy((dst), (crp)->buf + (off), (len))
#define	crypto_copyback(crp, off, len, src) \
	memcpy((crp)->buf + (off), (src), (len))
#define	crypto_get_driverid(d, sz, f)	(7)
#define	crypto_unregister_all(id)	do { } while (0)

static int g_done, g_done_err, g_unblock, g_unblock_what;
static void
crypto_done(struct cryptop *crp)
{
	crp->done = true;
	g_done++;
	if (crp->crp_etype != 0)
		g_done_err++;
}
static int
crypto_unblock(uint32_t id, int what)
{
	ATF_REQUIRE_EQ(7, (int)id);
	g_unblock++;
	g_unblock_what = what;
	return (0);
}

/* ------------------------------------------------------------------ DUT */
#include <dev/virtio/crypto/virtio_crypto.c>

#undef free
#undef malloc

/* --------------------------------------------------------------- fixture */
static struct mock_dev g_dev;
static struct vtcrypto_softc g_sc;
static struct vtcrypto_dataq g_dq;
static struct virtqueue g_vq;
static struct vtcrypto_session g_drv;
static struct mock_session g_ses;

static void
fixture(void)
{
	memset(&g_sc, 0, sizeof(g_sc));
	memset(&g_dq, 0, sizeof(g_dq));
	memset(&g_vq, 0, sizeof(g_vq));
	g_vq.free_desc = MOCK_RINGSZ;
	g_dq.vdq_sc = &g_sc;
	g_dq.vdq_vq = &g_vq;
	g_sc.vtc_dev = &g_dev;
	g_sc.vtc_cid = 7;
	g_sc.vtc_ndataq = 1;
	g_sc.vtc_dataq = &g_dq;
	g_sc.vtc_have_cipher = true;
	g_dev.softc = &g_sc;

	memset(&g_drv, 0, sizeof(g_drv));
	g_drv.vss_service = VIRTIO_CRYPTO_SERVICE_CIPHER;
	g_drv.vss_mode = CSP_MODE_CIPHER;
	g_drv.vss_sid_enc = 0x100;
	g_drv.vss_sid_dec = 0x200;
	g_drv.vss_enc_valid = g_drv.vss_dec_valid = true;
	memset(&g_ses, 0, sizeof(g_ses));
	g_ses.csp.csp_mode = CSP_MODE_CIPHER;
	g_ses.csp.csp_cipher_alg = CRYPTO_AES_CBC;
	g_ses.csp.csp_cipher_klen = 16;
	g_ses.csp.csp_ivlen = 16;
	g_ses.drv = &g_drv;
	g_done = g_done_err = g_unblock = g_unblock_what = 0;
}

/* One geli(4) sector: 512-byte AES-CBC. */
static struct cryptop *
sector_crp(bool encrypt)
{
	struct cryptop *crp = calloc(1, sizeof(*crp));

	ATF_REQUIRE(crp != NULL);
	crp->crp_session = &g_ses;
	crp->crp_op = encrypt ? CRYPTO_OP_ENCRYPT : 0;
	crp->crp_payload_length = 512;
	return (crp);
}

/* Device side: complete everything posted with status VIRTIO_CRYPTO_S_OK. */
static void
device_complete_all(void)
{
	for (int i = g_vq.used; i < g_vq.tail; i++) {
		struct vtcrypto_request *vcr = g_vq.cookie[i];

		vcr->vcr_wbuf[vcr->vcr_wbuf_len - 1] = 0;
	}
	g_vq.used = g_vq.tail;
}

/*
 * A full ring is resource exhaustion: crypto(9) requires ERESTART (request
 * kept by the framework, driver blocked) rather than completing the request
 * with ENOSPC, and the completion path must call crypto_unblock().
 */
ATF_TC_WITHOUT_HEAD(ring_full_returns_erestart);
ATF_TC_BODY(ring_full_returns_erestart, tc)
{
	struct cryptop *crp[MOCK_RINGSZ];
	struct cryptop *extra;
	int i, n, rc;

	fixture();
	/* Fill the ring with sector requests until it refuses one. */
	for (n = 0; n < MOCK_RINGSZ; n++) {
		crp[n] = sector_crp(true);
		ATF_REQUIRE_EQ(0, vtcrypto_process(&g_dev, crp[n], 0));
		if (crp[n]->done)
			break;
		ATF_REQUIRE(g_vq.free_desc >= 0);
		if (g_vq.free_desc == 0)
			break;
	}
	ATF_REQUIRE_MSG(g_done == 0, "requests failed before the ring filled");
	ATF_REQUIRE_EQ(0, g_vq.free_desc);
	n++;

	extra = sector_crp(true);
	rc = vtcrypto_process(&g_dev, extra, 0);
	ATF_REQUIRE_MSG(!extra->done,
	    "full ring completed the request with error %d", extra->crp_etype);
	ATF_REQUIRE_MSG(rc == ERESTART, "process returned %d", rc);

	device_complete_all();
	vtcrypto_dataq_intr(&g_dq);
	ATF_REQUIRE_EQ(n, g_done);
	ATF_REQUIRE_EQ(0, g_done_err);
	ATF_REQUIRE_MSG(g_unblock == 1, "crypto_unblock calls: %d", g_unblock);
	ATF_REQUIRE(g_unblock_what & CRYPTO_SYMQ);

	/* The framework resubmits the held request; it now fits. */
	ATF_REQUIRE_EQ(0, vtcrypto_process(&g_dev, extra, 0));
	ATF_REQUIRE(!extra->done);
	device_complete_all();
	vtcrypto_dataq_intr(&g_dq);
	ATF_REQUIRE(extra->done);
	ATF_REQUIRE_EQ(0, extra->crp_etype);
	/* No ERESTART since the last unblock: no spurious second unblock. */
	ATF_REQUIRE_EQ(1, g_unblock);
	for (i = 0; i < n; i++)
		free(crp[i]);
	free(extra);
}

/*
 * A 1 MiB geli(4) WRITE and READ is 2048 sector requests; model opencrypto's
 * dispatch (ERESTART keeps the request and blocks the driver until
 * crypto_unblock()) and require every request to complete without error.
 */
static void
burst(bool encrypt)
{
	enum { NREQ = 2048 };
	struct cryptop **crp;
	bool blocked = false;
	int next = 0, rc, rounds = 0;

	fixture();
	crp = calloc(NREQ, sizeof(*crp));
	ATF_REQUIRE(crp != NULL);
	for (int i = 0; i < NREQ; i++)
		crp[i] = sector_crp(encrypt);
	while (next < NREQ) {
		ATF_REQUIRE(++rounds < 10 * NREQ);
		if (!blocked) {
			rc = vtcrypto_process(&g_dev, crp[next], 0);
			if (rc == ERESTART) {
				blocked = true;
				continue;
			}
			ATF_REQUIRE_EQ(0, rc);
			next++;
			continue;
		}
		/* Blocked: the device drains and the interrupt fires. */
		int before = g_unblock;
		device_complete_all();
		vtcrypto_dataq_intr(&g_dq);
		ATF_REQUIRE_MSG(g_unblock > before,
		    "driver never called crypto_unblock()");
		blocked = false;
	}
	device_complete_all();
	vtcrypto_dataq_intr(&g_dq);
	ATF_REQUIRE_EQ(NREQ, g_done);
	ATF_REQUIRE_MSG(g_done_err == 0, "%d of %d sector requests failed",
	    g_done_err, NREQ);
	for (int i = 0; i < NREQ; i++)
		free(crp[i]);
	free(crp);
}

ATF_TC_WITHOUT_HEAD(geli_1mib_write_burst);
ATF_TC_BODY(geli_1mib_write_burst, tc)
{
	burst(true);
}

ATF_TC_WITHOUT_HEAD(geli_1mib_read_burst);
ATF_TC_BODY(geli_1mib_read_burst, tc)
{
	burst(false);
}

/*
 * VirtIO 1.2 5.9.7.2.1: a CIPHER data request carries
 * virtio_crypto_sym_data_req, whose op_type (le32) follows the 24-byte
 * op_header and the 40-byte cipher/chain union, i.e. byte 64, and must be
 * VIRTIO_CRYPTO_SYM_OP_CIPHER (1) for both directions.
 */
ATF_TC_WITHOUT_HEAD(cipher_data_request_op_type);
ATF_TC_BODY(cipher_data_request_op_type, tc)
{
	for (int enc = 0; enc < 2; enc++) {
		struct cryptop *crp;
		uint32_t op_type;

		fixture();
		crp = sector_crp(enc != 0);
		ATF_REQUIRE_EQ(0, vtcrypto_process(&g_dev, crp, 0));
		ATF_REQUIRE(!crp->done);
		memcpy(&op_type, g_vq.last_hdr + 24 + 40, sizeof(op_type));
		ATF_REQUIRE_MSG(le32toh(op_type) == 1,
		    "%s request op_type %u", enc ? "encrypt" : "decrypt",
		    le32toh(op_type));
		device_complete_all();
		vtcrypto_dataq_intr(&g_dq);
		ATF_REQUIRE(crp->done);
		free(crp);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ring_full_returns_erestart);
	ATF_TP_ADD_TC(tp, geli_1mib_write_burst);
	ATF_TP_ADD_TC(tp, geli_1mib_read_burst);
	ATF_TP_ADD_TC(tp, cipher_data_request_op_type);
	return (atf_no_error());
}
