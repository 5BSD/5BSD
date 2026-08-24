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
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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
 * virtio-crypto host device model.
 *
 * Implemented BSD-clean from the OASIS VirtIO 1.2 specification, section 5.9
 * (virtio-crypto device, device ID 20).  Two virtqueue classes are provided:
 * one or more data queues carrying crypto requests (queues 0..max_dataqueues-1)
 * and a single control queue for session lifecycle (queue index max_dataqueues,
 * the last queue, as the Linux virtio_crypto driver expects).
 *
 * The advertised service subset is CIPHER (AES-CBC), HASH (SHA-256), MAC
 * (HMAC-SHA-256) and AEAD (AES-GCM).  The host crypto backend is OpenSSL's EVP
 * interface.  A session-create request records the algorithm and key in a host
 * session object; each data request re-derives the transform from the stored
 * session state.  Because a session holds no live libcrypto context, its state
 * is fully serializable for snapshot/migration.
 *
 * All guest-supplied lengths, session identifiers and key lengths are validated
 * before use; oversize requests are rejected and no access is made past the
 * mapped descriptor iovecs.
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/endian.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "virtio_pci_modern_probes.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

static int pci_vtcrypto_debug;
#define	DPRINTF(msg, ...)						\
	do {								\
		if (pci_vtcrypto_debug)					\
			PRINTLN("virtio-crypto: " msg, ##__VA_ARGS__);	\
	} while (0)
#define	WPRINTF(msg, ...)	PRINTLN("virtio-crypto: " msg, ##__VA_ARGS__)

#define	VTCRYPTO_RINGSZ			64
#define	VTCRYPTO_MAXSEG			32
#define	VTCRYPTO_MAX_DATAQ		8
#define	VTCRYPTO_MAXQ			(VTCRYPTO_MAX_DATAQ + 1)
#define	VTCRYPTO_DEFAULT_MAXSESSIONS	64u
#define	VTCRYPTO_SESSION_LIMIT		4096u
#define	VTCRYPTO_MAX_KEYLEN		64u	/* AES-256 / HMAC key cap */
#define	VTCRYPTO_MAX_DATALEN		(64u * 1024u)
#define	VTCRYPTO_MAX_IVLEN		16u
#define	VTCRYPTO_MAX_AADLEN		1024u
#define	VTCRYPTO_GCM_TAGLEN		16u

/* Services (section 5.9.4), used as bit positions in crypto_services. */
#define	VIRTIO_CRYPTO_SERVICE_CIPHER	0
#define	VIRTIO_CRYPTO_SERVICE_HASH	1
#define	VIRTIO_CRYPTO_SERVICE_MAC	2
#define	VIRTIO_CRYPTO_SERVICE_AEAD	3

#define	VIRTIO_CRYPTO_OPCODE(service, op)	(((service) << 8) | (op))

/* Control queue opcodes (section 5.9.7.1). */
#define	VIRTIO_CRYPTO_CIPHER_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02)
#define	VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03)
#define	VIRTIO_CRYPTO_HASH_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x02)
#define	VIRTIO_CRYPTO_HASH_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x03)
#define	VIRTIO_CRYPTO_MAC_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x02)
#define	VIRTIO_CRYPTO_MAC_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x03)
#define	VIRTIO_CRYPTO_AEAD_CREATE_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02)
#define	VIRTIO_CRYPTO_AEAD_DESTROY_SESSION	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03)

/* Data queue opcodes (section 5.9.7.2). */
#define	VIRTIO_CRYPTO_CIPHER_ENCRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00)
#define	VIRTIO_CRYPTO_CIPHER_DECRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01)
#define	VIRTIO_CRYPTO_HASH		\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x00)
#define	VIRTIO_CRYPTO_MAC		\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x00)
#define	VIRTIO_CRYPTO_AEAD_ENCRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00)
#define	VIRTIO_CRYPTO_AEAD_DECRYPT	\
	VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01)

/* Cipher/AEAD direction. */
#define	VIRTIO_CRYPTO_OP_ENCRYPT	1
#define	VIRTIO_CRYPTO_OP_DECRYPT	2

/* Symmetric session op_type. */
#define	VIRTIO_CRYPTO_SYM_OP_NONE	0
#define	VIRTIO_CRYPTO_SYM_OP_CIPHER	1
#define	VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING	2

/* Cipher algorithms (cipher_algo_l bit positions). */
#define	VIRTIO_CRYPTO_CIPHER_AES_CBC	3

/* Hash algorithms (hash_algo bit positions). */
#define	VIRTIO_CRYPTO_HASH_SHA_256	4

/* MAC algorithms (mac_algo_l bit positions). */
#define	VIRTIO_CRYPTO_MAC_HMAC_SHA_256	4

/* AEAD algorithms (aead_algo bit positions). */
#define	VIRTIO_CRYPTO_AEAD_GCM		1

/* Request status codes. */
#define	VIRTIO_CRYPTO_OK		0
#define	VIRTIO_CRYPTO_ERR		1
#define	VIRTIO_CRYPTO_BADMSG		2
#define	VIRTIO_CRYPTO_NOTSUPP		3
#define	VIRTIO_CRYPTO_INVSESS		4

/* Device configuration status (section 5.9.4). */
#define	VIRTIO_CRYPTO_S_HW_READY	(1 << 0)

/* Wire header sizes.  Both request headers are 72 bytes in VirtIO 1.2. */
#define	VTCRYPTO_CTRL_HDR_LEN		16u
#define	VTCRYPTO_OP_CTRL_REQ_LEN	72u
#define	VTCRYPTO_OP_HDR_LEN		24u
#define	VTCRYPTO_OP_DATA_REQ_LEN	72u
#define	VTCRYPTO_SESSION_INPUT_LEN	16u

/*
 * Device configuration space (section 5.9.4).  All fields are little-endian on
 * the modern transport, which is the only transport this device supports.
 */
struct virtio_crypto_config {
	uint32_t status;
	uint32_t max_dataqueues;
	uint32_t crypto_services;
	uint32_t cipher_algo_l;
	uint32_t cipher_algo_h;
	uint32_t hash_algo;
	uint32_t mac_algo_l;
	uint32_t mac_algo_h;
	uint32_t aead_algo;
	uint32_t max_cipher_key_len;
	uint32_t max_auth_key_len;
	uint32_t akcipher_algo;
	uint64_t max_size;
} __attribute__((packed));

/*
 * Host session object.  A session records only the algorithm and key material;
 * no live libcrypto context is retained, so a session is trivially serialized.
 */
struct vtcrypto_session {
	bool		used;
	uint32_t	service;
	uint32_t	algo;
	uint32_t	op;		/* cipher/aead direction */
	uint32_t	keylen;
	uint32_t	auth_keylen;
	uint32_t	hash_result_len;
	uint8_t		key[VTCRYPTO_MAX_KEYLEN];
	uint8_t		auth_key[VTCRYPTO_MAX_KEYLEN];
};

struct pci_vtcrypto_softc {
	struct virtio_softc	vcs_vs;
	struct vqueue_info	vcs_vq[VTCRYPTO_MAXQ];
	struct virtio_consts	vcs_consts;
	pthread_mutex_t		vcs_mtx;
	bool			vcs_mtx_initialized;
	uint16_t		vcs_ndataq;
	uint32_t		vcs_maxsessions;
	uint32_t		vcs_nsessions;
	struct vtcrypto_session	*vcs_sessions;
	struct virtio_crypto_config vcs_cfg;
};

static void pci_vtcrypto_reset(void *);
static void pci_vtcrypto_controlq_notify(void *, struct vqueue_info *);
static void pci_vtcrypto_dataq_notify(void *, struct vqueue_info *);
static int pci_vtcrypto_cfgread(void *, int, int, uint32_t *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtcrypto_snapshot(void *, struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtcrypto_vi_consts = {
	.vc_name =		"vtcrypto",
	.vc_nvq =		2,	/* placeholder; set per instance */
	.vc_cfgsize =		sizeof(struct virtio_crypto_config),
	.vc_reset =		pci_vtcrypto_reset,
	.vc_cfgread =		pci_vtcrypto_cfgread,
	.vc_suspend =		vi_pci_lifecycle_noop,
	.vc_resume_device =	vi_pci_lifecycle_noop,
	.vc_pause =		vi_pci_lifecycle_noop,
	.vc_resume =		vi_pci_lifecycle_noop,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot =		pci_vtcrypto_snapshot,
#endif
	.vc_hv_caps =		VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
};

/* Little-endian codecs; the modern-only transport is always version 1. */
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

/*
 * Copy exactly len bytes out of the byte stream formed by concatenating iov[0..
 * niov), starting at absolute offset off, into dst.  Returns false when the
 * region is not fully covered, which the caller reports as VIRTIO_CRYPTO_BADMSG.
 * This is how the device gathers scattered descriptors without ever reading
 * past a mapped iovec.
 */
static bool
iov_pull(const struct iovec *iov, int niov, size_t off, void *dst, size_t len)
{
	uint8_t *out = dst;
	size_t base = 0;

	for (int i = 0; i < niov && len > 0; i++) {
		size_t ilen = iov[i].iov_len;

		if (off >= base + ilen) {
			base += ilen;
			continue;
		}
		size_t start = off - base;
		size_t avail = ilen - start;
		size_t n = len < avail ? len : avail;

		memcpy(out, (const uint8_t *)iov[i].iov_base + start, n);
		out += n;
		off += n;
		len -= n;
		base += ilen;
	}
	return (len == 0);
}

/* As iov_pull, but copies src into the writable iovec stream. */
static bool
iov_push(const struct iovec *iov, int niov, size_t off, const void *src,
    size_t len)
{
	const uint8_t *in = src;
	size_t base = 0;

	for (int i = 0; i < niov && len > 0; i++) {
		size_t ilen = iov[i].iov_len;

		if (off >= base + ilen) {
			base += ilen;
			continue;
		}
		size_t start = off - base;
		size_t avail = ilen - start;
		size_t n = len < avail ? len : avail;

		memcpy((uint8_t *)iov[i].iov_base + start, in, n);
		in += n;
		off += n;
		len -= n;
		base += ilen;
	}
	return (len == 0);
}

static size_t
iov_total(const struct iovec *iov, int niov)
{
	size_t total = 0;

	for (int i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

/*
 * Host crypto backend.  Each helper is stateless and derives the transform
 * from the session record for one request.
 */
static const EVP_CIPHER *
vtcrypto_cbc_for_keylen(uint32_t keylen)
{

	switch (keylen) {
	case 16:
		return (EVP_aes_128_cbc());
	case 24:
		return (EVP_aes_192_cbc());
	case 32:
		return (EVP_aes_256_cbc());
	default:
		return (NULL);
	}
}

static const EVP_CIPHER *
vtcrypto_gcm_for_keylen(uint32_t keylen)
{

	switch (keylen) {
	case 16:
		return (EVP_aes_128_gcm());
	case 24:
		return (EVP_aes_192_gcm());
	case 32:
		return (EVP_aes_256_gcm());
	default:
		return (NULL);
	}
}

static int
vtcrypto_do_cbc(const struct vtcrypto_session *s, const uint8_t *iv,
    const uint8_t *src, size_t srclen, uint8_t *dst)
{
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx;
	int encrypt, outl, finl, ok;

	cipher = vtcrypto_cbc_for_keylen(s->keylen);
	if (cipher == NULL)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (srclen == 0 || (srclen % 16) != 0)
		return (VIRTIO_CRYPTO_BADMSG);
	encrypt = (s->op == VIRTIO_CRYPTO_OP_ENCRYPT) ? 1 : 0;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return (VIRTIO_CRYPTO_ERR);
	ok = 0;
	if (EVP_CipherInit_ex(ctx, cipher, NULL, s->key, iv, encrypt) != 1)
		goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (EVP_CipherUpdate(ctx, dst, &outl, src, (int)srclen) != 1)
		goto out;
	if (EVP_CipherFinal_ex(ctx, dst + outl, &finl) != 1)
		goto out;
	if ((size_t)(outl + finl) != srclen)
		goto out;
	ok = 1;
out:
	EVP_CIPHER_CTX_free(ctx);
	return (ok ? VIRTIO_CRYPTO_OK : VIRTIO_CRYPTO_ERR);
}

static int
vtcrypto_do_sha256(const uint8_t *src, size_t srclen, uint8_t *dst,
    size_t dstlen)
{
	unsigned int mdlen = 0;

	if (dstlen != 32)
		return (VIRTIO_CRYPTO_BADMSG);
	if (EVP_Digest(src, srclen, dst, &mdlen, EVP_sha256(), NULL) != 1)
		return (VIRTIO_CRYPTO_ERR);
	if (mdlen != 32)
		return (VIRTIO_CRYPTO_ERR);
	return (VIRTIO_CRYPTO_OK);
}

static int
vtcrypto_do_hmac_sha256(const struct vtcrypto_session *s, const uint8_t *src,
    size_t srclen, uint8_t *dst, size_t dstlen)
{
	unsigned int maclen = 0;

	if (dstlen != 32)
		return (VIRTIO_CRYPTO_BADMSG);
	if (HMAC(EVP_sha256(), s->auth_key, (int)s->auth_keylen, src, srclen,
	    dst, &maclen) == NULL)
		return (VIRTIO_CRYPTO_ERR);
	if (maclen != 32)
		return (VIRTIO_CRYPTO_ERR);
	return (VIRTIO_CRYPTO_OK);
}

/*
 * AES-GCM.  For encryption, dst receives the ciphertext followed by the
 * VTCRYPTO_GCM_TAGLEN-byte authentication tag; for decryption, src carries the
 * ciphertext followed by the tag and the tag is verified.
 */
static int
vtcrypto_do_gcm(const struct vtcrypto_session *s, const uint8_t *iv,
    size_t ivlen, const uint8_t *aad, size_t aadlen, const uint8_t *src,
    size_t srclen, uint8_t *dst, size_t dstlen)
{
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx;
	uint8_t tag[VTCRYPTO_GCM_TAGLEN];
	int encrypt, outl, finl, ok;

	cipher = vtcrypto_gcm_for_keylen(s->keylen);
	if (cipher == NULL)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (ivlen == 0 || ivlen > VTCRYPTO_MAX_IVLEN)
		return (VIRTIO_CRYPTO_BADMSG);
	encrypt = (s->op == VIRTIO_CRYPTO_OP_ENCRYPT) ? 1 : 0;

	if (encrypt) {
		if (dstlen != srclen + VTCRYPTO_GCM_TAGLEN)
			return (VIRTIO_CRYPTO_BADMSG);
	} else {
		if (srclen < VTCRYPTO_GCM_TAGLEN ||
		    dstlen != srclen - VTCRYPTO_GCM_TAGLEN)
			return (VIRTIO_CRYPTO_BADMSG);
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return (VIRTIO_CRYPTO_ERR);
	ok = -1;	/* -1: generic error; -2: auth failure */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen,
	    NULL) != 1)
		goto out;
	if (EVP_CipherInit_ex(ctx, NULL, NULL, s->key, iv, encrypt) != 1)
		goto out;
	if (aadlen > 0 &&
	    EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)aadlen) != 1)
		goto out;

	if (encrypt) {
		size_t ptlen = srclen;

		if (ptlen > 0 &&
		    EVP_CipherUpdate(ctx, dst, &outl, src, (int)ptlen) != 1)
			goto out;
		if (EVP_CipherFinal_ex(ctx, dst + (ptlen > 0 ? outl : 0),
		    &finl) != 1)
			goto out;
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
		    VTCRYPTO_GCM_TAGLEN, tag) != 1)
			goto out;
		memcpy(dst + ptlen, tag, VTCRYPTO_GCM_TAGLEN);
		ok = 0;
	} else {
		size_t ctlen = srclen - VTCRYPTO_GCM_TAGLEN;

		memcpy(tag, src + ctlen, VTCRYPTO_GCM_TAGLEN);
		if (ctlen > 0 &&
		    EVP_CipherUpdate(ctx, dst, &outl, src, (int)ctlen) != 1)
			goto out;
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
		    VTCRYPTO_GCM_TAGLEN, tag) != 1)
			goto out;
		ok = (EVP_CipherFinal_ex(ctx, dst + (ctlen > 0 ? outl : 0),
		    &finl) == 1) ? 0 : -2;
	}
out:
	EVP_CIPHER_CTX_free(ctx);
	if (ok == 0)
		return (VIRTIO_CRYPTO_OK);
	return (ok == -2 ? VIRTIO_CRYPTO_BADMSG : VIRTIO_CRYPTO_ERR);
}

/* Session table management; the caller holds vcs_mtx. */
static struct vtcrypto_session *
vtcrypto_session_lookup(struct pci_vtcrypto_softc *sc, uint64_t id)
{

	if (id >= sc->vcs_maxsessions)
		return (NULL);
	if (!sc->vcs_sessions[id].used)
		return (NULL);
	return (&sc->vcs_sessions[id]);
}

static int
vtcrypto_session_alloc(struct pci_vtcrypto_softc *sc, uint64_t *idp)
{

	for (uint32_t i = 0; i < sc->vcs_maxsessions; i++) {
		if (!sc->vcs_sessions[i].used) {
			memset(&sc->vcs_sessions[i], 0,
			    sizeof(sc->vcs_sessions[i]));
			sc->vcs_sessions[i].used = true;
			sc->vcs_nsessions++;
			*idp = i;
			return (0);
		}
	}
	return (-1);
}

static void
vtcrypto_session_free_all(struct pci_vtcrypto_softc *sc)
{

	if (sc->vcs_sessions == NULL)
		return;
	memset(sc->vcs_sessions, 0,
	    (size_t)sc->vcs_maxsessions * sizeof(sc->vcs_sessions[0]));
	sc->vcs_nsessions = 0;
}

static void
pci_vtcrypto_reset(void *vsc)
{
	struct pci_vtcrypto_softc *sc = vsc;

	DPRINTF("device reset requested");
	/*
	 * The virtio transport calls vc_reset with vs_mtx (== vcs_mtx) already
	 * held, and vi_reset_dev() asserts it is held.  Free the sessions under
	 * that same held lock -- do NOT re-lock (the mutex is not recursive) or
	 * unlock it here, or vi_reset_dev() runs with the lock dropped.
	 */
	vtcrypto_session_free_all(sc);
	vi_reset_dev(&sc->vcs_vs);
}

/*
 * Control queue: create/destroy a CIPHER, HASH, MAC or AEAD session.  The
 * device-readable portion is the 72-byte op_ctrl_req optionally followed by key
 * material; the device-writable portion is a session_input (create) or a
 * one-byte status (destroy).
 */
static uint8_t
vtcrypto_create_cipher(struct pci_vtcrypto_softc *sc, const uint8_t *req,
    const struct iovec *riov, int rniov, uint64_t *idp)
{
	struct vtcrypto_session *s;
	uint32_t algo, keylen, op, op_type;
	uint64_t id;

	/* cipher_session_para sits immediately after the 16-byte header. */
	algo = ld32(req + 16);
	keylen = ld32(req + 20);
	op = ld32(req + 24);
	/* sym op_type is the last dword of the sym create-session request. */
	op_type = ld32(req + 64);

	if (algo != VIRTIO_CRYPTO_CIPHER_AES_CBC)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (op_type != VIRTIO_CRYPTO_SYM_OP_CIPHER)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (op != VIRTIO_CRYPTO_OP_ENCRYPT && op != VIRTIO_CRYPTO_OP_DECRYPT)
		return (VIRTIO_CRYPTO_BADMSG);
	if (vtcrypto_cbc_for_keylen(keylen) == NULL)
		return (VIRTIO_CRYPTO_BADMSG);

	if (vtcrypto_session_alloc(sc, &id) != 0)
		return (VIRTIO_CRYPTO_ERR);
	s = &sc->vcs_sessions[id];
	/* Key follows the fixed request header as additional readable data. */
	if (!iov_pull(riov, rniov, VTCRYPTO_OP_CTRL_REQ_LEN, s->key, keylen)) {
		s->used = false;
		sc->vcs_nsessions--;
		return (VIRTIO_CRYPTO_BADMSG);
	}
	s->service = VIRTIO_CRYPTO_SERVICE_CIPHER;
	s->algo = algo;
	s->op = op;
	s->keylen = keylen;
	*idp = id;
	return (VIRTIO_CRYPTO_OK);
}

static uint8_t
vtcrypto_create_hash(struct pci_vtcrypto_softc *sc, const uint8_t *req,
    uint64_t *idp)
{
	struct vtcrypto_session *s;
	uint32_t algo, result_len;
	uint64_t id;

	algo = ld32(req + 16);
	result_len = ld32(req + 20);
	if (algo != VIRTIO_CRYPTO_HASH_SHA_256)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (result_len != 32)
		return (VIRTIO_CRYPTO_BADMSG);
	if (vtcrypto_session_alloc(sc, &id) != 0)
		return (VIRTIO_CRYPTO_ERR);
	s = &sc->vcs_sessions[id];
	s->service = VIRTIO_CRYPTO_SERVICE_HASH;
	s->algo = algo;
	s->hash_result_len = result_len;
	*idp = id;
	return (VIRTIO_CRYPTO_OK);
}

static uint8_t
vtcrypto_create_mac(struct pci_vtcrypto_softc *sc, const uint8_t *req,
    const struct iovec *riov, int rniov, uint64_t *idp)
{
	struct vtcrypto_session *s;
	uint32_t algo, result_len, auth_keylen;
	uint64_t id;

	algo = ld32(req + 16);
	result_len = ld32(req + 20);
	auth_keylen = ld32(req + 24);
	if (algo != VIRTIO_CRYPTO_MAC_HMAC_SHA_256)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (result_len != 32)
		return (VIRTIO_CRYPTO_BADMSG);
	if (auth_keylen == 0 || auth_keylen > VTCRYPTO_MAX_KEYLEN)
		return (VIRTIO_CRYPTO_BADMSG);
	if (vtcrypto_session_alloc(sc, &id) != 0)
		return (VIRTIO_CRYPTO_ERR);
	s = &sc->vcs_sessions[id];
	if (!iov_pull(riov, rniov, VTCRYPTO_OP_CTRL_REQ_LEN, s->auth_key,
	    auth_keylen)) {
		s->used = false;
		sc->vcs_nsessions--;
		return (VIRTIO_CRYPTO_BADMSG);
	}
	s->service = VIRTIO_CRYPTO_SERVICE_MAC;
	s->algo = algo;
	s->auth_keylen = auth_keylen;
	s->hash_result_len = result_len;
	*idp = id;
	return (VIRTIO_CRYPTO_OK);
}

static uint8_t
vtcrypto_create_aead(struct pci_vtcrypto_softc *sc, const uint8_t *req,
    const struct iovec *riov, int rniov, uint64_t *idp)
{
	struct vtcrypto_session *s;
	uint32_t algo, keylen, result_len, op;
	uint64_t id;

	algo = ld32(req + 16);
	keylen = ld32(req + 20);
	result_len = ld32(req + 24);
	/* aad_len at +28 is advisory here; op is the fifth dword. */
	op = ld32(req + 32);
	if (algo != VIRTIO_CRYPTO_AEAD_GCM)
		return (VIRTIO_CRYPTO_NOTSUPP);
	if (op != VIRTIO_CRYPTO_OP_ENCRYPT && op != VIRTIO_CRYPTO_OP_DECRYPT)
		return (VIRTIO_CRYPTO_BADMSG);
	if (vtcrypto_gcm_for_keylen(keylen) == NULL)
		return (VIRTIO_CRYPTO_BADMSG);
	if (result_len != VTCRYPTO_GCM_TAGLEN)
		return (VIRTIO_CRYPTO_BADMSG);
	if (vtcrypto_session_alloc(sc, &id) != 0)
		return (VIRTIO_CRYPTO_ERR);
	s = &sc->vcs_sessions[id];
	if (!iov_pull(riov, rniov, VTCRYPTO_OP_CTRL_REQ_LEN, s->key, keylen)) {
		s->used = false;
		sc->vcs_nsessions--;
		return (VIRTIO_CRYPTO_BADMSG);
	}
	s->service = VIRTIO_CRYPTO_SERVICE_AEAD;
	s->algo = algo;
	s->op = op;
	s->keylen = keylen;
	s->hash_result_len = result_len;
	*idp = id;
	return (VIRTIO_CRYPTO_OK);
}

static uint8_t
vtcrypto_destroy(struct pci_vtcrypto_softc *sc, const uint8_t *req,
    uint32_t service)
{
	struct vtcrypto_session *s;
	uint64_t id;

	/* destroy_session_req: session_id is the first field after header. */
	id = ld64(req + 16);
	s = vtcrypto_session_lookup(sc, id);
	if (s == NULL || s->service != service)
		return (VIRTIO_CRYPTO_INVSESS);
	memset(s, 0, sizeof(*s));
	sc->vcs_nsessions--;
	return (VIRTIO_CRYPTO_OK);
}

static void
pci_vtcrypto_control(struct pci_vtcrypto_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTCRYPTO_MAXSEG];
	uint8_t req[VTCRYPTO_OP_CTRL_REQ_LEN];
	uint8_t input[VTCRYPTO_SESSION_INPUT_LEN];
	struct vi_req vireq;
	struct iovec *riov, *wiov;
	uint32_t opcode, service, op;
	uint64_t id;
	uint8_t status;
	uint16_t budget;
	size_t wlen;
	int n, rniov, wniov;
	bool is_create;

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VTCRYPTO_MAXSEG, &vireq);
		if (n <= 0)
			break;
		if (n > VTCRYPTO_MAXSEG || !vireq.ordered ||
		    vireq.readable < 1 || vireq.writable < 1 ||
		    vireq.readable + vireq.writable != n) {
			WPRINTF("invalid control descriptor chain");
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}
		riov = &iov[0];
		rniov = vireq.readable;
		wiov = &iov[vireq.readable];
		wniov = vireq.writable;

		if (!iov_pull(riov, rniov, 0, req, sizeof(req))) {
			WPRINTF("truncated control request");
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}
		opcode = ld32(req + 0);
		service = opcode >> 8;
		op = opcode & 0xff;
		id = 0;
		status = VIRTIO_CRYPTO_NOTSUPP;
		is_create = (op == 0x02);

		pthread_mutex_lock(&sc->vcs_mtx);
		switch (opcode) {
		case VIRTIO_CRYPTO_CIPHER_CREATE_SESSION:
			status = vtcrypto_create_cipher(sc, req, riov, rniov,
			    &id);
			break;
		case VIRTIO_CRYPTO_HASH_CREATE_SESSION:
			status = vtcrypto_create_hash(sc, req, &id);
			break;
		case VIRTIO_CRYPTO_MAC_CREATE_SESSION:
			status = vtcrypto_create_mac(sc, req, riov, rniov, &id);
			break;
		case VIRTIO_CRYPTO_AEAD_CREATE_SESSION:
			status = vtcrypto_create_aead(sc, req, riov, rniov,
			    &id);
			break;
		case VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION:
		case VIRTIO_CRYPTO_HASH_DESTROY_SESSION:
		case VIRTIO_CRYPTO_MAC_DESTROY_SESSION:
		case VIRTIO_CRYPTO_AEAD_DESTROY_SESSION:
			status = vtcrypto_destroy(sc, req, service);
			is_create = false;
			break;
		default:
			status = VIRTIO_CRYPTO_NOTSUPP;
			is_create = false;
			break;
		}
		pthread_mutex_unlock(&sc->vcs_mtx);

		if (is_create) {
			/* session_input: le64 session_id, le32 status, pad. */
			memset(input, 0, sizeof(input));
			st64(input + 0, id);
			st32(input + 8, status);
			if (!iov_push(wiov, wniov, 0, input, sizeof(input))) {
				/*
				 * The guest left no room for the reply.  A
				 * session just created above would otherwise
				 * leak, since the guest never learns its id and
				 * so can never destroy it; roll it back to keep
				 * the session table from being exhausted by
				 * requests with an undersized writable area.
				 */
				if (status == VIRTIO_CRYPTO_OK) {
					pthread_mutex_lock(&sc->vcs_mtx);
					if (id < sc->vcs_maxsessions &&
					    sc->vcs_sessions[id].used) {
						memset(&sc->vcs_sessions[id], 0,
						    sizeof(sc->vcs_sessions[id]));
						sc->vcs_nsessions--;
					}
					pthread_mutex_unlock(&sc->vcs_mtx);
				}
				vq_relchain_req(vq, &vireq, 0);
				continue;
			}
			wlen = sizeof(input);
		} else {
			/* virtio_crypto_inhdr: a single status byte. */
			if (!iov_push(wiov, wniov, 0, &status, 1)) {
				vq_relchain_req(vq, &vireq, 0);
				continue;
			}
			wlen = 1;
		}
		vq_relchain_req(vq, &vireq, (uint32_t)wlen);
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static void
pci_vtcrypto_controlq_notify(void *vsc, struct vqueue_info *vq)
{

	pci_vtcrypto_control(vsc, vq);
}

/*
 * Data queue: run one crypto request against its referenced session.
 */
static uint8_t
vtcrypto_data_cipher(const struct vtcrypto_session *sess, uint32_t opcode, const uint8_t *hdr,
    const struct iovec *riov, int rniov, const struct iovec *wiov, int wniov,
    size_t *wlenp)
{
	uint8_t iv[VTCRYPTO_MAX_IVLEN];
	uint8_t *src = NULL, *dst = NULL;
	uint32_t iv_len, src_len, dst_len;
	uint8_t status;
	size_t roff;

	if (sess->service != VIRTIO_CRYPTO_SERVICE_CIPHER)
		return (VIRTIO_CRYPTO_INVSESS);
	if ((opcode == VIRTIO_CRYPTO_CIPHER_ENCRYPT &&
	    sess->op != VIRTIO_CRYPTO_OP_ENCRYPT) ||
	    (opcode == VIRTIO_CRYPTO_CIPHER_DECRYPT &&
	    sess->op != VIRTIO_CRYPTO_OP_DECRYPT))
		return (VIRTIO_CRYPTO_BADMSG);

	/* cipher_para begins at op_header end (offset 24). */
	iv_len = ld32(hdr + 24);
	src_len = ld32(hdr + 28);
	dst_len = ld32(hdr + 32);
	if (iv_len != VTCRYPTO_MAX_IVLEN)
		return (VIRTIO_CRYPTO_BADMSG);
	if (src_len == 0 || src_len > VTCRYPTO_MAX_DATALEN ||
	    dst_len < src_len)
		return (VIRTIO_CRYPTO_BADMSG);

	roff = VTCRYPTO_OP_DATA_REQ_LEN;
	if (!iov_pull(riov, rniov, roff, iv, iv_len))
		return (VIRTIO_CRYPTO_BADMSG);
	roff += iv_len;
	src = malloc(src_len);
	dst = malloc(src_len);
	if (src == NULL || dst == NULL) {
		status = VIRTIO_CRYPTO_ERR;
		goto out;
	}
	if (!iov_pull(riov, rniov, roff, src, src_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	status = vtcrypto_do_cbc(sess, iv, src, src_len, dst);
	if (status != VIRTIO_CRYPTO_OK)
		goto out;
	if (!iov_push(wiov, wniov, 0, dst, src_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	*wlenp = src_len;
out:
	free(src);
	free(dst);
	return (status);
}

static uint8_t
vtcrypto_data_hash(const struct vtcrypto_session *sess, const uint8_t *hdr,
    const struct iovec *riov, int rniov, const struct iovec *wiov, int wniov,
    size_t *wlenp)
{
	uint8_t md[32];
	uint8_t *src = NULL;
	uint32_t src_len, result_len;
	uint8_t status;

	if (sess->service != VIRTIO_CRYPTO_SERVICE_HASH)
		return (VIRTIO_CRYPTO_INVSESS);
	/* hash_para begins at offset 24. */
	src_len = ld32(hdr + 24);
	result_len = ld32(hdr + 28);
	if (result_len != 32 || src_len > VTCRYPTO_MAX_DATALEN)
		return (VIRTIO_CRYPTO_BADMSG);
	src = malloc(src_len == 0 ? 1 : src_len);
	if (src == NULL)
		return (VIRTIO_CRYPTO_ERR);
	if (!iov_pull(riov, rniov, VTCRYPTO_OP_DATA_REQ_LEN, src, src_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	status = vtcrypto_do_sha256(src, src_len, md, sizeof(md));
	if (status != VIRTIO_CRYPTO_OK)
		goto out;
	if (!iov_push(wiov, wniov, 0, md, sizeof(md))) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	*wlenp = sizeof(md);
out:
	free(src);
	return (status);
}

static uint8_t
vtcrypto_data_mac(const struct vtcrypto_session *sess, const uint8_t *hdr,
    const struct iovec *riov, int rniov, const struct iovec *wiov, int wniov,
    size_t *wlenp)
{
	uint8_t mac[32];
	uint8_t *src = NULL;
	uint32_t src_len, result_len;
	uint8_t status;

	if (sess->service != VIRTIO_CRYPTO_SERVICE_MAC)
		return (VIRTIO_CRYPTO_INVSESS);
	src_len = ld32(hdr + 24);
	result_len = ld32(hdr + 28);
	if (result_len != 32 || src_len > VTCRYPTO_MAX_DATALEN)
		return (VIRTIO_CRYPTO_BADMSG);
	src = malloc(src_len == 0 ? 1 : src_len);
	if (src == NULL)
		return (VIRTIO_CRYPTO_ERR);
	if (!iov_pull(riov, rniov, VTCRYPTO_OP_DATA_REQ_LEN, src, src_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	status = vtcrypto_do_hmac_sha256(sess, src, src_len, mac, sizeof(mac));
	if (status != VIRTIO_CRYPTO_OK)
		goto out;
	if (!iov_push(wiov, wniov, 0, mac, sizeof(mac))) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	*wlenp = sizeof(mac);
out:
	free(src);
	return (status);
}

static uint8_t
vtcrypto_data_aead(const struct vtcrypto_session *sess, uint32_t opcode, const uint8_t *hdr,
    const struct iovec *riov, int rniov, const struct iovec *wiov, int wniov,
    size_t *wlenp)
{
	uint8_t iv[VTCRYPTO_MAX_IVLEN];
	uint8_t *aad = NULL, *src = NULL, *dst = NULL;
	uint32_t iv_len, aad_len, src_len, dst_len;
	uint8_t status;
	size_t roff;

	if (sess->service != VIRTIO_CRYPTO_SERVICE_AEAD)
		return (VIRTIO_CRYPTO_INVSESS);
	if ((opcode == VIRTIO_CRYPTO_AEAD_ENCRYPT &&
	    sess->op != VIRTIO_CRYPTO_OP_ENCRYPT) ||
	    (opcode == VIRTIO_CRYPTO_AEAD_DECRYPT &&
	    sess->op != VIRTIO_CRYPTO_OP_DECRYPT))
		return (VIRTIO_CRYPTO_BADMSG);

	/* aead_para begins at offset 24: iv_len, aad_len, src_len, dst_len. */
	iv_len = ld32(hdr + 24);
	aad_len = ld32(hdr + 28);
	src_len = ld32(hdr + 32);
	dst_len = ld32(hdr + 36);
	if (iv_len == 0 || iv_len > VTCRYPTO_MAX_IVLEN ||
	    aad_len > VTCRYPTO_MAX_AADLEN || src_len > VTCRYPTO_MAX_DATALEN ||
	    dst_len > VTCRYPTO_MAX_DATALEN + VTCRYPTO_GCM_TAGLEN)
		return (VIRTIO_CRYPTO_BADMSG);

	roff = VTCRYPTO_OP_DATA_REQ_LEN;
	if (!iov_pull(riov, rniov, roff, iv, iv_len))
		return (VIRTIO_CRYPTO_BADMSG);
	roff += iv_len;
	aad = malloc(aad_len == 0 ? 1 : aad_len);
	src = malloc(src_len == 0 ? 1 : src_len);
	dst = malloc(dst_len == 0 ? 1 : dst_len);
	if (aad == NULL || src == NULL || dst == NULL) {
		status = VIRTIO_CRYPTO_ERR;
		goto out;
	}
	if (!iov_pull(riov, rniov, roff, aad, aad_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	roff += aad_len;
	if (!iov_pull(riov, rniov, roff, src, src_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	status = vtcrypto_do_gcm(sess, iv, iv_len, aad, aad_len, src, src_len,
	    dst, dst_len);
	if (status != VIRTIO_CRYPTO_OK)
		goto out;
	if (!iov_push(wiov, wniov, 0, dst, dst_len)) {
		status = VIRTIO_CRYPTO_BADMSG;
		goto out;
	}
	*wlenp = dst_len;
out:
	free(aad);
	free(src);
	free(dst);
	return (status);
}

static void
pci_vtcrypto_data(struct pci_vtcrypto_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTCRYPTO_MAXSEG];
	struct vtcrypto_session sess;
	uint8_t hdr[VTCRYPTO_OP_DATA_REQ_LEN];
	struct vi_req vireq;
	struct iovec *riov, *wiov;
	struct vtcrypto_session *live;
	uint32_t opcode, service;
	uint64_t session_id;
	size_t wtotal, wlen;
	uint8_t status;
	uint16_t budget;
	int n, rniov, wniov;

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VTCRYPTO_MAXSEG, &vireq);
		if (n <= 0)
			break;
		if (n > VTCRYPTO_MAXSEG || !vireq.ordered ||
		    vireq.readable < 1 || vireq.writable < 1 ||
		    vireq.readable + vireq.writable != n) {
			WPRINTF("invalid data descriptor chain");
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}
		riov = &iov[0];
		rniov = vireq.readable;
		wiov = &iov[vireq.readable];
		wniov = vireq.writable;
		wtotal = iov_total(wiov, wniov);
		if (wtotal < 1) {
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}

		if (!iov_pull(riov, rniov, 0, hdr, sizeof(hdr))) {
			WPRINTF("truncated data request");
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}
		opcode = ld32(hdr + 0);
		session_id = ld64(hdr + 8);
		service = opcode >> 8;
		wlen = 0;

		/* Copy the session under the lock; run EVP without it held. */
		pthread_mutex_lock(&sc->vcs_mtx);
		live = vtcrypto_session_lookup(sc, session_id);
		if (live != NULL)
			sess = *live;
		pthread_mutex_unlock(&sc->vcs_mtx);
		if (live == NULL) {
			status = VIRTIO_CRYPTO_INVSESS;
			goto respond;
		}

		switch (service) {
		case VIRTIO_CRYPTO_SERVICE_CIPHER:
			status = vtcrypto_data_cipher(&sess, opcode, hdr,
			    riov, rniov, wiov, wniov, &wlen);
			break;
		case VIRTIO_CRYPTO_SERVICE_HASH:
			status = vtcrypto_data_hash(&sess, hdr, riov,
			    rniov, wiov, wniov, &wlen);
			break;
		case VIRTIO_CRYPTO_SERVICE_MAC:
			status = vtcrypto_data_mac(&sess, hdr, riov,
			    rniov, wiov, wniov, &wlen);
			break;
		case VIRTIO_CRYPTO_SERVICE_AEAD:
			status = vtcrypto_data_aead(&sess, opcode, hdr,
			    riov, rniov, wiov, wniov, &wlen);
			break;
		default:
			status = VIRTIO_CRYPTO_NOTSUPP;
			break;
		}

respond:
		/* The one-byte inhdr status is the final writable byte. */
		if (!iov_push(wiov, wniov, wtotal - 1, &status, 1)) {
			vq_relchain_req(vq, &vireq, 0);
			continue;
		}
		vq_relchain_req(vq, &vireq, (uint32_t)(wlen + 1));
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static void
pci_vtcrypto_dataq_notify(void *vsc, struct vqueue_info *vq)
{

	pci_vtcrypto_data(vsc, vq);
}

static void
vtcrypto_config_setup(struct pci_vtcrypto_softc *sc)
{

	memset(&sc->vcs_cfg, 0, sizeof(sc->vcs_cfg));
	sc->vcs_cfg.status = VIRTIO_CRYPTO_S_HW_READY;
	sc->vcs_cfg.max_dataqueues = sc->vcs_ndataq;
	sc->vcs_cfg.crypto_services =
	    (1u << VIRTIO_CRYPTO_SERVICE_CIPHER) |
	    (1u << VIRTIO_CRYPTO_SERVICE_HASH) |
	    (1u << VIRTIO_CRYPTO_SERVICE_MAC) |
	    (1u << VIRTIO_CRYPTO_SERVICE_AEAD);
	sc->vcs_cfg.cipher_algo_l = 1u << VIRTIO_CRYPTO_CIPHER_AES_CBC;
	sc->vcs_cfg.hash_algo = 1u << VIRTIO_CRYPTO_HASH_SHA_256;
	sc->vcs_cfg.mac_algo_l = 1u << VIRTIO_CRYPTO_MAC_HMAC_SHA_256;
	sc->vcs_cfg.aead_algo = 1u << VIRTIO_CRYPTO_AEAD_GCM;
	sc->vcs_cfg.max_cipher_key_len = VTCRYPTO_MAX_KEYLEN;
	sc->vcs_cfg.max_auth_key_len = VTCRYPTO_MAX_KEYLEN;
	sc->vcs_cfg.max_size = VTCRYPTO_MAX_DATALEN;
}

static int
pci_vtcrypto_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtcrypto_softc *sc = vsc;
	struct virtio_crypto_config wire;

	if (retval != NULL)
		*retval = 0;
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(sc->vcs_cfg) ||
	    (size_t)size > sizeof(sc->vcs_cfg) - (size_t)offset)
		return (EINVAL);
	/* The stored config is host byte order; publish it little-endian. */
	wire.status = htole32(sc->vcs_cfg.status);
	wire.max_dataqueues = htole32(sc->vcs_cfg.max_dataqueues);
	wire.crypto_services = htole32(sc->vcs_cfg.crypto_services);
	wire.cipher_algo_l = htole32(sc->vcs_cfg.cipher_algo_l);
	wire.cipher_algo_h = htole32(sc->vcs_cfg.cipher_algo_h);
	wire.hash_algo = htole32(sc->vcs_cfg.hash_algo);
	wire.mac_algo_l = htole32(sc->vcs_cfg.mac_algo_l);
	wire.mac_algo_h = htole32(sc->vcs_cfg.mac_algo_h);
	wire.aead_algo = htole32(sc->vcs_cfg.aead_algo);
	wire.max_cipher_key_len = htole32(sc->vcs_cfg.max_cipher_key_len);
	wire.max_auth_key_len = htole32(sc->vcs_cfg.max_auth_key_len);
	wire.akcipher_algo = htole32(sc->vcs_cfg.akcipher_algo);
	wire.max_size = htole64(sc->vcs_cfg.max_size);
	return (vi_config_read_le(&wire, sizeof(wire), offset, size, retval));
}

#ifdef BHYVE_SNAPSHOT
#define	VTCRYPTO_SNAPSHOT_MAGIC		0x59524331U	/* "1CRY" LE */
#define	VTCRYPTO_SNAPSHOT_VERSION	1U

static int
pci_vtcrypto_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtcrypto_softc *sc = vsc;
	uint32_t magic, version, ndataq, maxsessions, nsessions;
	int ret;

	magic = VTCRYPTO_SNAPSHOT_MAGIC;
	version = VTCRYPTO_SNAPSHOT_VERSION;
	ndataq = sc->vcs_ndataq;
	maxsessions = sc->vcs_maxsessions;
	nsessions = sc->vcs_nsessions;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (magic != VTCRYPTO_SNAPSHOT_MAGIC ||
	    version != VTCRYPTO_SNAPSHOT_VERSION) {
		ret = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(ndataq, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(maxsessions, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(nsessions, meta, ret, done);
	/*
	 * The session table is host-side crypto state.  Its geometry is fixed
	 * at device creation, so a mismatched destination cannot restore it.
	 */
	if (vm_snapshot_is_loading(meta) &&
	    (ndataq != sc->vcs_ndataq || maxsessions != sc->vcs_maxsessions)) {
		ret = EINVAL;
		goto done;
	}

	for (uint32_t i = 0; i < sc->vcs_maxsessions; i++) {
		struct vtcrypto_session *s = &sc->vcs_sessions[i];
		uint8_t used = s->used ? 1 : 0;
		uint32_t service = s->service, algo = s->algo, op = s->op;
		uint32_t keylen = s->keylen, auth_keylen = s->auth_keylen;
		uint32_t hrl = s->hash_result_len;

		SNAPSHOT_U8_OR_LEAVE(used, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(service, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(algo, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(op, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(keylen, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(auth_keylen, meta, ret, done);
		SNAPSHOT_LE32_OR_LEAVE(hrl, meta, ret, done);
		SNAPSHOT_BUF_OR_LEAVE(s->key, sizeof(s->key), meta, ret, done);
		SNAPSHOT_BUF_OR_LEAVE(s->auth_key, sizeof(s->auth_key), meta,
		    ret, done);
		if (vm_snapshot_is_restoring(meta)) {
			if (keylen > VTCRYPTO_MAX_KEYLEN ||
			    auth_keylen > VTCRYPTO_MAX_KEYLEN) {
				ret = EINVAL;
				goto done;
			}
			s->used = used != 0;
			s->service = service;
			s->algo = algo;
			s->op = op;
			s->keylen = keylen;
			s->auth_keylen = auth_keylen;
			s->hash_result_len = hrl;
		}
	}
	if (vm_snapshot_is_restoring(meta)) {
		/*
		 * Do not trust the serialized session count: a corrupt image
		 * could make it disagree with the restored used flags.  Recount
		 * from the slots that were actually marked used.
		 */
		uint32_t used_count = 0;

		for (uint32_t i = 0; i < sc->vcs_maxsessions; i++)
			if (sc->vcs_sessions[i].used)
				used_count++;
		sc->vcs_nsessions = used_count;
	}
	ret = 0;
done:
	return (ret);
}
#endif

static int
pci_vtcrypto_parse_u32(const char *value, uint32_t lo, uint32_t hi,
    uint32_t def, uint32_t *out)
{
	const char *errstr;
	long long parsed;

	if (value == NULL) {
		*out = def;
		return (0);
	}
	parsed = strtonum(value, lo, hi, &errstr);
	if (errstr != NULL)
		return (EINVAL);
	*out = (uint32_t)parsed;
	return (0);
}

static int
pci_vtcrypto_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtcrypto_softc *sc;
	const char *value;
	uint32_t ndataq, maxsessions;
	bool intr_initialized, packed;
	int i;

	value = getenv("BHYVE_VTCRYPTO_DEBUG");
	if (value != NULL && atoi(value) > 0)
		pci_vtcrypto_debug = atoi(value);

	value = get_config_value_node(nvl, "queues");
	if (pci_vtcrypto_parse_u32(value, 1, VTCRYPTO_MAX_DATAQ, 1,
	    &ndataq) != 0) {
		EPRINTLN("virtio-crypto: invalid queues value");
		return (1);
	}
	value = get_config_value_node(nvl, "maxsessions");
	if (pci_vtcrypto_parse_u32(value, 1, VTCRYPTO_SESSION_LIMIT,
	    VTCRYPTO_DEFAULT_MAXSESSIONS, &maxsessions) != 0) {
		EPRINTLN("virtio-crypto: invalid maxsessions value");
		return (1);
	}
	packed = get_config_bool_node_default(nvl, "packed", false);

	sc = calloc(1, sizeof(struct pci_vtcrypto_softc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	sc->vcs_ndataq = (uint16_t)ndataq;
	sc->vcs_maxsessions = maxsessions;
	sc->vcs_sessions = calloc(maxsessions, sizeof(struct vtcrypto_session));
	if (sc->vcs_sessions == NULL)
		goto fail;

	if (pthread_mutex_init(&sc->vcs_mtx, NULL) != 0)
		goto fail;
	sc->vcs_mtx_initialized = true;

	sc->vcs_consts = vtcrypto_vi_consts;
	sc->vcs_consts.vc_nvq = ndataq + 1;	/* data queues + control queue */
	if (packed)
		sc->vcs_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;

	vi_softc_linkup(&sc->vcs_vs, &sc->vcs_consts, sc, pi, sc->vcs_vq);
	sc->vcs_vs.vs_mtx = &sc->vcs_mtx;

	/* Data queues 0..ndataq-1 carry crypto requests. */
	for (i = 0; i < (int)ndataq; i++) {
		sc->vcs_vq[i].vq_qsize = VTCRYPTO_RINGSZ;
		sc->vcs_vq[i].vq_notify = pci_vtcrypto_dataq_notify;
	}
	/* The control queue is the last queue. */
	sc->vcs_vq[ndataq].vq_qsize = VTCRYPTO_RINGSZ;
	sc->vcs_vq[ndataq].vq_notify = pci_vtcrypto_controlq_notify;

	if (vi_pci_select_transport(&sc->vcs_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto fail;
	if (packed && !vi_pci_is_modern(&sc->vcs_vs)) {
		EPRINTLN("virtio-crypto: packed queues require modern transport");
		goto fail;
	}

	vtcrypto_config_setup(sc);

	/* virtio-crypto (device ID 20) has no transitional identity. */
	vi_pci_modern_set_identity(&sc->vcs_vs, VIRTIO_ID_CRYPTO);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_CRYPTO);

	if (vi_intr_init(&sc->vcs_vs, 1, fbsdrun_virtio_msix()))
		goto fail;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vcs_vs, 2) != 0)
		goto fail;

	return (0);

fail:
	free(sc->vcs_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vcs_vs.vs_isr_mtx);
	if (sc->vcs_mtx_initialized)
		pthread_mutex_destroy(&sc->vcs_mtx);
	free(sc->vcs_sessions);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vcrypto = {
	.pe_emu =	"virtio-crypto",
	.pe_init =	pci_vtcrypto_init,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	vi_pci_snapshot,
	.pe_snapshot_validate = vi_pci_snapshot,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause =	vi_pci_pause,
	.pe_resume =	vi_pci_resume,
	.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS,
#endif
};
PCI_EMUL_SET(pci_de_vcrypto);
