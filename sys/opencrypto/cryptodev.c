/*	$OpenBSD: cryptodev.c,v 1.52 2002/06/19 07:22:46 deraadt Exp $	*/

/*-
 * Copyright (c) 2001 Theo de Raadt
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2014-2021 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by John-Mark Gurney
 * under sponsorship of the FreeBSD Foundation and
 * Rubicon Communications, LLC (Netgate).
 *
 * Portions of this software were developed by Ararat River
 * Consulting, LLC under sponsorship of the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
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
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/fcntl.h>
#include <sys/bus.h>
#include <sys/sdt.h>
#include <sys/syscallsubr.h>
#include <sys/user.h>

#include <opencrypto/cryptodev.h>
#include <sys/cryptodesc.h>
#include <opencrypto/xform.h>
#include <crypto/curve25519.h>

#include "cryptodesc_ed25519.h"
#include "cryptodesc_kdf.h"

SDT_PROVIDER_DECLARE(opencrypto);

SDT_PROBE_DEFINE1(opencrypto, dev, ioctl, error, "int"/*line number*/);

#ifdef COMPAT_FREEBSD12
/*
 * Previously, most ioctls were performed against a cloned descriptor
 * of /dev/crypto obtained via CRIOGET.  Now all ioctls are performed
 * against /dev/crypto directly.
 */
#define	CRIOGET		_IOWR('c', 100, uint32_t)
#endif

/* the following are done against the cloned descriptor */

#ifdef COMPAT_FREEBSD32
#include <sys/mount.h>
#include <compat/freebsd32/freebsd32.h>

struct session_op32 {
	uint32_t	cipher;
	uint32_t	mac;
	uint32_t	keylen;
	uint32_t	key;
	int		mackeylen;
	uint32_t	mackey;
	uint32_t	ses;
};

struct session2_op32 {
	uint32_t	cipher;
	uint32_t	mac;
	uint32_t	keylen;
	uint32_t	key;
	int		mackeylen;
	uint32_t	mackey;
	uint32_t	ses;
	int		crid;
	int		ivlen;
	int		maclen;
	int		pad[2];
};

struct crypt_op32 {
	uint32_t	ses;
	uint16_t	op;
	uint16_t	flags;
	u_int		len;
	uint32_t	src, dst;
	uint32_t	mac;
	uint32_t	iv;
};

struct crypt_aead32 {
	uint32_t	ses;
	uint16_t	op;
	uint16_t	flags;
	u_int		len;
	u_int		aadlen;
	u_int		ivlen;
	uint32_t	src;
	uint32_t	dst;
	uint32_t	aad;
	uint32_t	tag;
	uint32_t	iv;
};

#define	CIOCGSESSION32	_IOWR('c', 101, struct session_op32)
#define	CIOCCRYPT32	_IOWR('c', 103, struct crypt_op32)
#define	CIOCGSESSION232	_IOWR('c', 106, struct session2_op32)
#define	CIOCCRYPTAEAD32	_IOWR('c', 109, struct crypt_aead32)

static void
session_op_from_32(const struct session_op32 *from, struct session2_op *to)
{

	memset(to, 0, sizeof(*to));
	CP(*from, *to, cipher);
	CP(*from, *to, mac);
	CP(*from, *to, keylen);
	PTRIN_CP(*from, *to, key);
	CP(*from, *to, mackeylen);
	PTRIN_CP(*from, *to, mackey);
	CP(*from, *to, ses);
	to->crid = CRYPTOCAP_F_HARDWARE;
}

static void
session2_op_from_32(const struct session2_op32 *from, struct session2_op *to)
{

	session_op_from_32((const struct session_op32 *)from, to);
	CP(*from, *to, crid);
	CP(*from, *to, ivlen);
	CP(*from, *to, maclen);
}

static void
session_op_to_32(const struct session2_op *from, struct session_op32 *to)
{

	CP(*from, *to, cipher);
	CP(*from, *to, mac);
	CP(*from, *to, keylen);
	PTROUT_CP(*from, *to, key);
	CP(*from, *to, mackeylen);
	PTROUT_CP(*from, *to, mackey);
	CP(*from, *to, ses);
}

static void
session2_op_to_32(const struct session2_op *from, struct session2_op32 *to)
{

	session_op_to_32(from, (struct session_op32 *)to);
	CP(*from, *to, crid);
}

static void
crypt_op_from_32(const struct crypt_op32 *from, struct crypt_op *to)
{

	CP(*from, *to, ses);
	CP(*from, *to, op);
	CP(*from, *to, flags);
	CP(*from, *to, len);
	PTRIN_CP(*from, *to, src);
	PTRIN_CP(*from, *to, dst);
	PTRIN_CP(*from, *to, mac);
	PTRIN_CP(*from, *to, iv);
}

static void
crypt_op_to_32(const struct crypt_op *from, struct crypt_op32 *to)
{

	CP(*from, *to, ses);
	CP(*from, *to, op);
	CP(*from, *to, flags);
	CP(*from, *to, len);
	PTROUT_CP(*from, *to, src);
	PTROUT_CP(*from, *to, dst);
	PTROUT_CP(*from, *to, mac);
	PTROUT_CP(*from, *to, iv);
}

static void
crypt_aead_from_32(const struct crypt_aead32 *from, struct crypt_aead *to)
{

	CP(*from, *to, ses);
	CP(*from, *to, op);
	CP(*from, *to, flags);
	CP(*from, *to, len);
	CP(*from, *to, aadlen);
	CP(*from, *to, ivlen);
	PTRIN_CP(*from, *to, src);
	PTRIN_CP(*from, *to, dst);
	PTRIN_CP(*from, *to, aad);
	PTRIN_CP(*from, *to, tag);
	PTRIN_CP(*from, *to, iv);
}

static void
crypt_aead_to_32(const struct crypt_aead *from, struct crypt_aead32 *to)
{

	CP(*from, *to, ses);
	CP(*from, *to, op);
	CP(*from, *to, flags);
	CP(*from, *to, len);
	CP(*from, *to, aadlen);
	CP(*from, *to, ivlen);
	PTROUT_CP(*from, *to, src);
	PTROUT_CP(*from, *to, dst);
	PTROUT_CP(*from, *to, aad);
	PTROUT_CP(*from, *to, tag);
	PTROUT_CP(*from, *to, iv);
}
#endif

static void
session2_op_from_op(const struct session_op *from, struct session2_op *to)
{

	memset(to, 0, sizeof(*to));
	memcpy(to, from, sizeof(*from));
	to->crid = CRYPTOCAP_F_HARDWARE;
}

static void
session2_op_to_op(const struct session2_op *from, struct session_op *to)
{

	memcpy(to, from, sizeof(*to));
}

struct csession {
	TAILQ_ENTRY(csession) next;
	crypto_session_t cses;
	volatile u_int	refs;
	uint32_t	ses;
	struct mtx	lock;		/* for op submission */

	u_int		blocksize;
	int		hashsize;
	int		ivsize;

	void		*key;
	void		*mackey;
	size_t		keylen;
	size_t		mackeylen;
};

struct cryptop_data {
	struct csession *cse;

	char		*buf;
	char		*obuf;
	char		*aad;
	bool		done;
};

struct fcrypt {
	TAILQ_HEAD(csessionlist, csession) csessions;
	int		sesn;
	struct mtx	lock;
};

/* A passable, rights-limited OpenCrypto session. */
struct cryptodesc {
	struct csession	*cd_session;
	struct mtx	cd_lock;
	uint32_t	cd_rights;
	uint32_t	cd_type;
	time_t		cd_expires;
	bool		cd_revoked;
	uint8_t		cd_private[CRYPTODESC_ED25519_SECRET_SIZE];
	uint8_t		cd_public[CRYPTODESC_ED25519_PUBLIC_SIZE];
};

#define	CRYPTODESC_MAX_ASYMMETRIC_DATA	(1024 * 1024)

static fo_ioctl_t cryptodesc_ioctl;
static fo_stat_t cryptodesc_stat;
static fo_close_t cryptodesc_close;
static fo_fill_kinfo_t cryptodesc_fill_kinfo;
static int cryptodev_op(struct csession *, const struct crypt_op *);
static int cryptodev_aead(struct csession *, struct crypt_aead *);

static int
cryptodesc_check_rights(struct cryptodesc *cd, uint32_t required)
{
	int error;

	mtx_lock(&cd->cd_lock);
	if (cd->cd_revoked)
		error = EACCES;
	else if (cd->cd_expires != 0 && time_second >= cd->cd_expires)
		error = ESTALE;
	else if ((cd->cd_rights & required) != required)
		error = EPERM;
	else
		error = 0;
	mtx_unlock(&cd->cd_lock);
	return (error);
}

static const struct fileops cryptodesc_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = cryptodesc_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = cryptodesc_stat,
	.fo_close = cryptodesc_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = cryptodesc_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

static bool use_outputbuffers;
SYSCTL_BOOL(_kern_crypto, OID_AUTO, cryptodev_use_output, CTLFLAG_RW,
    &use_outputbuffers, 0,
    "Use separate output buffers for /dev/crypto requests.");

static bool use_separate_aad;
SYSCTL_BOOL(_kern_crypto, OID_AUTO, cryptodev_separate_aad, CTLFLAG_RW,
    &use_separate_aad, 0,
    "Use separate AAD buffer for /dev/crypto requests.");

static MALLOC_DEFINE(M_CRYPTODEV, "cryptodev", "/dev/crypto data buffers");

/*
 * Check a crypto identifier to see if it requested
 * a software device/driver.  This can be done either
 * by device name/class or through search constraints.
 */
static int
checkforsoftware(int *cridp)
{
	int crid;

	crid = *cridp;

	if (!crypto_devallowsoft) {
		if (crid & CRYPTOCAP_F_SOFTWARE) {
			if (crid & CRYPTOCAP_F_HARDWARE) {
				*cridp = CRYPTOCAP_F_HARDWARE;
				return 0;
			}
			return EINVAL;
		}
		if ((crid & CRYPTOCAP_F_HARDWARE) == 0 &&
		    (crypto_getcaps(crid) & CRYPTOCAP_F_HARDWARE) == 0)
			return EINVAL;
	}
	return 0;
}

static int
cse_create_session(struct session2_op *sop, struct csession **csep,
    bool user_keys)
{
	struct crypto_session_params csp;
	struct csession *cse;
	const struct enc_xform *txform;
	const struct auth_hash *thash;
	void *key = NULL;
	void *mackey = NULL;
	crypto_session_t cses;
	int crid, error, mac;

	*csep = NULL;

	mac = sop->mac;
#ifdef COMPAT_FREEBSD12
	switch (sop->mac) {
	case CRYPTO_AES_128_NIST_GMAC:
	case CRYPTO_AES_192_NIST_GMAC:
	case CRYPTO_AES_256_NIST_GMAC:
		/* Should always be paired with GCM. */
		if (sop->cipher != CRYPTO_AES_NIST_GCM_16) {
			CRYPTDEB("GMAC without GCM");
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		if (sop->keylen != sop->mackeylen) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		mac = 0;
		break;
	case CRYPTO_AES_CCM_CBC_MAC:
		/* Should always be paired with CCM. */
		if (sop->cipher != CRYPTO_AES_CCM_16) {
			CRYPTDEB("CBC-MAC without CCM");
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		if (sop->keylen != sop->mackeylen) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		mac = 0;
		break;
	}
#endif

	memset(&csp, 0, sizeof(csp));
	if (use_outputbuffers)
		csp.csp_flags |= CSP_F_SEPARATE_OUTPUT;
	if (mac != 0) {
		csp.csp_auth_alg = mac;
		csp.csp_auth_klen = sop->mackeylen;
	}
	if (sop->cipher != 0) {
		csp.csp_cipher_alg = sop->cipher;
		csp.csp_cipher_klen = sop->keylen;
	}
	thash = crypto_auth_hash(&csp);
	txform = crypto_cipher(&csp);

	if (txform != NULL && txform->macsize != 0) {
		if (mac != 0) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		csp.csp_mode = CSP_MODE_AEAD;
	} else if (txform != NULL && thash != NULL) {
		csp.csp_mode = CSP_MODE_ETA;
	} else if (txform != NULL) {
		csp.csp_mode = CSP_MODE_CIPHER;
	} else if (thash != NULL) {
		csp.csp_mode = CSP_MODE_DIGEST;
	} else {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (EINVAL);
	}

	switch (csp.csp_mode) {
	case CSP_MODE_AEAD:
	case CSP_MODE_ETA:
		if (use_separate_aad)
			csp.csp_flags |= CSP_F_SEPARATE_AAD;
		break;
	}

	if (txform != NULL) {
		if (sop->keylen > txform->maxkey ||
		    sop->keylen < txform->minkey) {
			CRYPTDEB("invalid cipher parameters");
			error = EINVAL;
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}

		key = malloc(csp.csp_cipher_klen, M_CRYPTODEV, M_WAITOK);
		if (user_keys)
			error = copyin(sop->key, key, csp.csp_cipher_klen);
		else if (sop->key != NULL) {
			memcpy(key, sop->key, csp.csp_cipher_klen);
			error = 0;
		} else
			error = EINVAL;
		if (error) {
			CRYPTDEB("invalid key");
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
		csp.csp_cipher_key = key;
		csp.csp_ivlen = txform->ivsize;
	}

	if (thash != NULL) {
		if (sop->mackeylen > thash->keysize || sop->mackeylen < 0) {
			CRYPTDEB("invalid mac key length");
			error = EINVAL;
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}

		if (csp.csp_auth_klen != 0) {
			mackey = malloc(csp.csp_auth_klen, M_CRYPTODEV,
			    M_WAITOK);
			if (user_keys)
				error = copyin(sop->mackey, mackey,
				    csp.csp_auth_klen);
			else if (sop->mackey != NULL) {
				memcpy(mackey, sop->mackey, csp.csp_auth_klen);
				error = 0;
			} else
				error = EINVAL;
			if (error) {
				CRYPTDEB("invalid mac key");
				SDT_PROBE1(opencrypto, dev, ioctl, error,
				    __LINE__);
				goto bail;
			}
			csp.csp_auth_key = mackey;
		}

		if (csp.csp_auth_alg == CRYPTO_AES_NIST_GMAC)
			csp.csp_ivlen = AES_GCM_IV_LEN;
		if (csp.csp_auth_alg == CRYPTO_AES_CCM_CBC_MAC)
			csp.csp_ivlen = AES_CCM_IV_LEN;
	}

	if (sop->ivlen != 0) {
		if (csp.csp_ivlen == 0) {
			CRYPTDEB("does not support an IV");
			error = EINVAL;
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
		csp.csp_ivlen = sop->ivlen;
	}
	if (sop->maclen != 0) {
		if (!(thash != NULL || csp.csp_mode == CSP_MODE_AEAD)) {
			CRYPTDEB("does not support a MAC");
			error = EINVAL;
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
		csp.csp_auth_mlen = sop->maclen;
	}

	crid = sop->crid;
	error = checkforsoftware(&crid);
	if (error) {
		CRYPTDEB("checkforsoftware");
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}
	error = crypto_newsession(&cses, &csp, crid);
	if (error) {
		CRYPTDEB("crypto_newsession");
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}

	cse = malloc(sizeof(struct csession), M_CRYPTODEV, M_WAITOK | M_ZERO);
	mtx_init(&cse->lock, "cryptodev", "crypto session lock", MTX_DEF);
	refcount_init(&cse->refs, 1);
	cse->key = key;
	cse->mackey = mackey;
	cse->keylen = csp.csp_cipher_klen;
	cse->mackeylen = csp.csp_auth_klen;
	cse->cses = cses;
	if (sop->maclen != 0)
		cse->hashsize = sop->maclen;
	else if (thash != NULL)
		cse->hashsize = thash->hashsize;
	else if (csp.csp_mode == CSP_MODE_AEAD)
		cse->hashsize = txform->macsize;
	cse->ivsize = csp.csp_ivlen;

	/*
	 * NB: This isn't necessarily the block size of the underlying
	 * MAC or cipher but is instead a restriction on valid input
	 * sizes.
	 */
	if (txform != NULL)
		cse->blocksize = txform->blocksize;
	else
		cse->blocksize = 1;

	/* return hardware/driver id */
	sop->crid = crypto_ses2hid(cse->cses);
	*csep = cse;
	return (0);
bail:
	if (error) {
		if (key != NULL)
			explicit_bzero(key, csp.csp_cipher_klen);
		if (mackey != NULL)
			explicit_bzero(mackey, csp.csp_auth_klen);
		free(key, M_CRYPTODEV);
		free(mackey, M_CRYPTODEV);
	}
	return (error);
}

static int
cse_create(struct fcrypt *fcr, struct session2_op *sop)
{
	struct csession *cse;
	int error;

	error = cse_create_session(sop, &cse, true);
	if (error != 0)
		return (error);
	mtx_lock(&fcr->lock);
	TAILQ_INSERT_TAIL(&fcr->csessions, cse, next);
	cse->ses = fcr->sesn++;
	mtx_unlock(&fcr->lock);
	sop->ses = cse->ses;
	return (0);
}

static struct csession *
cse_find(struct fcrypt *fcr, u_int ses)
{
	struct csession *cse;

	mtx_lock(&fcr->lock);
	TAILQ_FOREACH(cse, &fcr->csessions, next) {
		if (cse->ses == ses) {
			refcount_acquire(&cse->refs);
			mtx_unlock(&fcr->lock);
			return (cse);
		}
	}
	mtx_unlock(&fcr->lock);
	return (NULL);
}

static void
cse_free(struct csession *cse)
{

	if (!refcount_release(&cse->refs))
		return;
	crypto_freesession(cse->cses);
	mtx_destroy(&cse->lock);
	if (cse->key) {
		explicit_bzero(cse->key, cse->keylen);
		free(cse->key, M_CRYPTODEV);
	}
	if (cse->mackey) {
		explicit_bzero(cse->mackey, cse->mackeylen);
		free(cse->mackey, M_CRYPTODEV);
	}
	free(cse, M_CRYPTODEV);
}

static int
cryptodesc_install(struct thread *td, struct csession *cse, uint32_t type,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *public_key, size_t public_key_len, uint32_t rights,
    uint32_t ttl, int32_t *descriptor_fd)
{
	struct cryptodesc *cd;
	struct file *fp;
	int error, fd;

	if ((rights & ~CRYPTODESC_RIGHT_ALL) != 0 || rights == 0 ||
	    private_key_len > sizeof(cd->cd_private) ||
	    public_key_len > sizeof(cd->cd_public) ||
	    (ttl != 0 && (time_second > INT64_MAX - ttl)))
		return (EINVAL);
	cd = malloc(sizeof(*cd), M_CRYPTODEV, M_WAITOK | M_ZERO);
	cd->cd_session = cse;
	mtx_init(&cd->cd_lock, "cryptodesc", NULL, MTX_DEF);
	cd->cd_rights = rights;
	cd->cd_type = type;
	cd->cd_expires = ttl == 0 ? 0 : time_second + ttl;
	if (private_key_len != 0)
		memcpy(cd->cd_private, private_key, private_key_len);
	if (public_key_len != 0)
		memcpy(cd->cd_public, public_key, public_key_len);
	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		if (cse != NULL)
			cse_free(cse);
		mtx_destroy(&cd->cd_lock);
		explicit_bzero(cd, sizeof(*cd));
		free(cd, M_CRYPTODEV);
		return (error);
	}
	finit(fp, FREAD | FWRITE, DTYPE_CRYPTO, cd, &cryptodesc_ops);
	error = finstall(td, fp, &fd, 0, NULL);
	fdrop(fp, td);
	if (error == 0)
		*descriptor_fd = fd;
	return (error);
}

static int
cryptodesc_mint(struct thread *td, struct cryptodesc_create *create)
{
	struct csession *cse;
	int error;

	if (create->session.ses != 0)
		return (EINVAL);
	create->cd_fd = -1;
	error = cse_create_session(&create->session, &cse, true);
	if (error != 0)
		return (error);
	return (cryptodesc_install(td, cse, 0, NULL, 0, NULL, 0,
	    create->cd_rights, 0, &create->cd_fd));
}

static int
cryptodesc_mint_generated(struct thread *td, struct cryptodesc_generate *create)
{
	struct session2_op session;
	struct csession *cse;
	uint8_t *key, *mackey;
	int error;

	if (create->session.ses != 0 || create->session.key != NULL ||
	    create->session.mackey != NULL || create->session.keylen > 128 ||
	    create->session.mackeylen > 128)
		return (EINVAL);
	create->cd_fd = -1;
	key = create->session.keylen == 0 ? NULL : malloc(create->session.keylen,
	    M_CRYPTODEV, M_WAITOK);
	mackey = create->session.mackeylen == 0 ? NULL :
	    malloc(create->session.mackeylen, M_CRYPTODEV, M_WAITOK);
	if (key != NULL)
		arc4random_buf(key, create->session.keylen);
	if (mackey != NULL)
		arc4random_buf(mackey, create->session.mackeylen);
	session = create->session;
	session.key = key;
	session.mackey = mackey;
	error = cse_create_session(&session, &cse, false);
	if (key != NULL) {
		explicit_bzero(key, create->session.keylen);
		free(key, M_CRYPTODEV);
	}
	if (mackey != NULL) {
		explicit_bzero(mackey, create->session.mackeylen);
		free(mackey, M_CRYPTODEV);
	}
	if (error != 0)
		return (error);
	return (cryptodesc_install(td, cse, 0, NULL, 0, NULL, 0,
	    create->cd_rights, create->cd_ttl, &create->cd_fd));
}

static int
cryptodesc_derive(struct thread *td, struct cryptodesc *cd,
    struct cryptodesc_derive *derive)
{
	struct session2_op session;
	struct csession *cse;
	uint8_t *salt, *info, *output;
	const uint8_t *ikm;
	size_t ikm_len, output_len;
	uint32_t ttl;
	int error;

	if (cd->cd_type != 0 || derive->session.ses != 0 ||
	    derive->session.key != NULL || derive->session.mackey != NULL ||
	    derive->cd_salt_len > CRYPTODESC_MAX_DERIVE_SALT ||
	    derive->cd_info_len > CRYPTODESC_MAX_DERIVE_INFO ||
	    derive->session.keylen > 128 || derive->session.mackeylen > 128 ||
	    derive->session.keylen > SIZE_MAX - derive->session.mackeylen ||
	    derive->cd_rights == 0 ||
	    (derive->cd_rights & ~(CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_DECRYPT | CRYPTODESC_RIGHT_AUTH |
	    CRYPTODESC_RIGHT_VERIFY | CRYPTODESC_RIGHT_DERIVE)) != 0)
		return (EINVAL);
	error = cryptodesc_check_rights(cd, CRYPTODESC_RIGHT_DERIVE);
	if (error != 0)
		return (error);
	if (cd->cd_session->key != NULL) {
		ikm = cd->cd_session->key;
		ikm_len = cd->cd_session->keylen;
	} else {
		ikm = cd->cd_session->mackey;
		ikm_len = cd->cd_session->mackeylen;
	}
	output_len = derive->session.keylen + derive->session.mackeylen;
	if (ikm == NULL || ikm_len == 0 || output_len == 0)
		return (EINVAL);
	salt = info = output = NULL;
	if (derive->cd_salt_len != 0) {
		if (derive->cd_salt == NULL)
			return (EINVAL);
		salt = malloc(derive->cd_salt_len, M_CRYPTODEV, M_WAITOK);
		error = copyin(derive->cd_salt, salt, derive->cd_salt_len);
		if (error != 0)
			goto out;
	}
	if (derive->cd_info_len != 0) {
		if (derive->cd_info == NULL) {
			error = EINVAL;
			goto out;
		}
		info = malloc(derive->cd_info_len, M_CRYPTODEV, M_WAITOK);
		error = copyin(derive->cd_info, info, derive->cd_info_len);
		if (error != 0)
			goto out;
	}
	output = malloc(output_len, M_CRYPTODEV, M_WAITOK);
	error = cryptodesc_hkdf(derive->cd_hash, output, output_len, salt,
	    derive->cd_salt_len, ikm, ikm_len, info, derive->cd_info_len);
	if (error != 0)
		goto out;
	session = derive->session;
	session.key = derive->session.keylen == 0 ? NULL : output;
	session.mackey = derive->session.mackeylen == 0 ? NULL :
	    output + derive->session.keylen;
	error = cse_create_session(&session, &cse, false);
	if (error != 0)
		goto out;
	ttl = derive->cd_ttl;
	if (cd->cd_expires != 0 &&
	    (ttl == 0 || time_second + ttl > cd->cd_expires))
		ttl = cd->cd_expires - time_second;
	error = cryptodesc_install(td, cse, 0, NULL, 0, NULL, 0,
	    derive->cd_rights, ttl, &derive->cd_fd);
out:
	if (salt != NULL) {
		explicit_bzero(salt, derive->cd_salt_len);
		free(salt, M_CRYPTODEV);
	}
	if (info != NULL) {
		explicit_bzero(info, derive->cd_info_len);
		free(info, M_CRYPTODEV);
	}
	if (output != NULL) {
		explicit_bzero(output, output_len);
		free(output, M_CRYPTODEV);
	}
	return (error);
}

static int
cryptodesc_mint_key(struct thread *td, struct cryptodesc_key_create *create)
{
	uint8_t private_key[CRYPTODESC_ED25519_SECRET_SIZE], public_key[32];
	uint32_t allowed;
	int error;

	if (create->cd_flags != 0)
		return (EINVAL);
	create->cd_fd = -1;
	memset(private_key, 0, sizeof(private_key));
	memset(public_key, 0, sizeof(public_key));
	switch (create->cd_type) {
	case CRYPTODESC_KEY_X25519:
		allowed = CRYPTODESC_RIGHT_EXCHANGE;
		curve25519_generate_secret(private_key);
		if (!curve25519_generate_public(public_key, private_key)) {
			error = EIO;
			goto out;
		}
		break;
	case CRYPTODESC_KEY_ED25519:
		allowed = CRYPTODESC_RIGHT_SIGN | CRYPTODESC_RIGHT_VERIFY;
		cryptodesc_ed25519_keypair(public_key, private_key);
		break;
	default:
		return (EINVAL);
	}
	if (create->cd_rights == 0 || (create->cd_rights & ~allowed) != 0) {
		error = EINVAL;
		goto out;
	}
	error = cryptodesc_install(td, NULL, create->cd_type, private_key,
	    create->cd_type == CRYPTODESC_KEY_X25519 ? CRYPTODESC_X25519_SIZE :
	    CRYPTODESC_ED25519_SECRET_SIZE, public_key, sizeof(public_key),
	    create->cd_rights, create->cd_ttl, &create->cd_fd);
	if (error == 0)
		memcpy(create->cd_public, public_key, sizeof(create->cd_public));
out:
	explicit_bzero(private_key, sizeof(private_key));
	explicit_bzero(public_key, sizeof(public_key));
	return (error);
}

static int
cryptodesc_x25519(struct cryptodesc *cd, struct cryptodesc_x25519 *request)
{
	uint8_t peer[CRYPTODESC_X25519_SIZE], shared[CRYPTODESC_X25519_SIZE];
	int error;

	if (cd->cd_type != CRYPTODESC_KEY_X25519 ||
	    request->cd_peer_public == NULL || request->cd_shared_secret == NULL ||
	    request->cd_peer_public_len != sizeof(peer) ||
	    request->cd_shared_secret_len != sizeof(shared))
		return (EINVAL);
	error = cryptodesc_check_rights(cd, CRYPTODESC_RIGHT_EXCHANGE);
	if (error != 0)
		return (error);
	error = copyin(request->cd_peer_public, peer, sizeof(peer));
	if (error == 0 && !curve25519(shared, cd->cd_private, peer))
		error = EINVAL;
	if (error == 0)
		error = copyout(shared, request->cd_shared_secret, sizeof(shared));
	explicit_bzero(peer, sizeof(peer));
	explicit_bzero(shared, sizeof(shared));
	return (error);
}

static int
cryptodesc_sign(struct cryptodesc *cd, struct cryptodesc_sign *request)
{
	uint8_t signature[CRYPTODESC_ED25519_SIGNATURE_SIZE];
	uint8_t *data;
	int error;

	if (cd->cd_type != CRYPTODESC_KEY_ED25519 ||
	    request->cd_data_len > CRYPTODESC_MAX_ASYMMETRIC_DATA ||
	    request->cd_signature == NULL ||
	    request->cd_signature_len != sizeof(signature) ||
	    (request->cd_data_len != 0 && request->cd_data == NULL))
		return (EINVAL);
	error = cryptodesc_check_rights(cd, CRYPTODESC_RIGHT_SIGN);
	if (error != 0)
		return (error);
	data = request->cd_data_len == 0 ? NULL : malloc(request->cd_data_len,
	    M_CRYPTODEV, M_WAITOK);
	if (data != NULL) {
		error = copyin(request->cd_data, data, request->cd_data_len);
		if (error != 0)
			goto out;
	}
	error = cryptodesc_ed25519_sign(signature, data, request->cd_data_len,
	    cd->cd_private);
	if (error == 0)
		error = copyout(signature, request->cd_signature, sizeof(signature));
out:
	if (data != NULL) {
		explicit_bzero(data, request->cd_data_len);
		free(data, M_CRYPTODEV);
	}
	explicit_bzero(signature, sizeof(signature));
	return (error);
}

static int
cryptodesc_verify(struct cryptodesc *cd, struct cryptodesc_verify *request)
{
	uint8_t signature[CRYPTODESC_ED25519_SIGNATURE_SIZE];
	uint8_t *data;
	int error;

	if (cd->cd_type != CRYPTODESC_KEY_ED25519 ||
	    request->cd_data_len > CRYPTODESC_MAX_ASYMMETRIC_DATA ||
	    request->cd_signature == NULL ||
	    request->cd_signature_len != sizeof(signature) ||
	    (request->cd_data_len != 0 && request->cd_data == NULL))
		return (EINVAL);
	error = cryptodesc_check_rights(cd, CRYPTODESC_RIGHT_VERIFY);
	if (error != 0)
		return (error);
	data = request->cd_data_len == 0 ? NULL : malloc(request->cd_data_len,
	    M_CRYPTODEV, M_WAITOK);
	if (data != NULL) {
		error = copyin(request->cd_data, data, request->cd_data_len);
		if (error != 0)
			goto out;
	}
	error = copyin(request->cd_signature, signature, sizeof(signature));
	if (error == 0)
		error = cryptodesc_ed25519_verify(signature, data,
		    request->cd_data_len, cd->cd_public);
out:
	if (data != NULL) {
		explicit_bzero(data, request->cd_data_len);
		free(data, M_CRYPTODEV);
	}
	explicit_bzero(signature, sizeof(signature));
	return (error);
}

static int
cryptodesc_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred __unused, struct thread *td)
{
	struct cryptodesc *cd;
	struct crypt_op *cop;
	struct crypt_aead *caead;
	struct cryptodesc_restrict *attenuation;
	struct cryptodesc_revoke *revoke;
	struct cryptodesc_derive *derive;
	struct cryptodesc_x25519 *x25519;
	struct cryptodesc_sign *sign;
	struct cryptodesc_verify *verify;
	const struct crypto_session_params *csp;
	uint32_t required;
	int error;

	cd = fp->f_data;
	switch (cmd) {
	case CIOCCRYPTODESCREVOKE:
		revoke = data;
		if (revoke->cd_flags != 0)
			return (EINVAL);
		mtx_lock(&cd->cd_lock);
		cd->cd_revoked = true;
		mtx_unlock(&cd->cd_lock);
		return (0);
	case CIOCSCRYPTODESCRIGHTS:
		attenuation = data;
		if ((attenuation->cd_rights & ~CRYPTODESC_RIGHT_ALL) != 0)
			return (EINVAL);
		mtx_lock(&cd->cd_lock);
		if (cd->cd_revoked)
			error = EACCES;
		else if ((attenuation->cd_rights & ~cd->cd_rights) != 0)
			error = EPERM;
		else {
			cd->cd_rights = attenuation->cd_rights;
			error = 0;
		}
		mtx_unlock(&cd->cd_lock);
		return (error);
	case CIOCCRYPTODESCDERIVE:
		derive = data;
		derive->cd_fd = -1;
		return (cryptodesc_derive(td, cd, derive));
	case CIOCCRYPTX25519:
		x25519 = data;
		return (cryptodesc_x25519(cd, x25519));
	case CIOCCRYPTOSIGN:
		sign = data;
		return (cryptodesc_sign(cd, sign));
	case CIOCCRYPTOVERIFY:
		verify = data;
		return (cryptodesc_verify(cd, verify));
	case CIOCCRYPT:
		if (cd->cd_type != 0)
			return (EPROTONOSUPPORT);
		cop = data;
		csp = crypto_get_params(cd->cd_session->cses);
		if (csp->csp_mode == CSP_MODE_DIGEST)
			required = cop->op == COP_ENCRYPT ? CRYPTODESC_RIGHT_AUTH :
			    cop->op == COP_DECRYPT ? CRYPTODESC_RIGHT_VERIFY : 0;
		else if (csp->csp_mode == CSP_MODE_ETA)
			required = cop->op == COP_ENCRYPT ?
			    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH :
			    cop->op == COP_DECRYPT ?
			    CRYPTODESC_RIGHT_DECRYPT | CRYPTODESC_RIGHT_VERIFY : 0;
		else
			required = cop->op == COP_ENCRYPT ?
			    CRYPTODESC_RIGHT_ENCRYPT : cop->op == COP_DECRYPT ?
			    CRYPTODESC_RIGHT_DECRYPT : 0;
		error = required == 0 || cop->ses != 0 ? EPERM :
		    cryptodesc_check_rights(cd, required);
		if (error != 0)
			return (error);
		return (cryptodev_op(cd->cd_session, cop));
	case CIOCCRYPTAEAD:
		if (cd->cd_type != 0)
			return (EPROTONOSUPPORT);
		caead = data;
		required = caead->op == COP_ENCRYPT ?
		    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH :
		    caead->op == COP_DECRYPT ?
		    CRYPTODESC_RIGHT_DECRYPT | CRYPTODESC_RIGHT_VERIFY : 0;
		error = required == 0 || caead->ses != 0 ? EPERM :
		    cryptodesc_check_rights(cd, required);
		if (error != 0)
			return (error);
		return (cryptodev_aead(cd->cd_session, caead));
	default:
		return (ENOTTY);
	}
}

static int
cryptodesc_stat(struct file *fp, struct stat *st,
    struct ucred *active_cred __unused)
{

	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFIFO;
	if ((fp->f_flag & FREAD) != 0)
		st->st_mode |= S_IRUSR;
	if ((fp->f_flag & FWRITE) != 0)
		st->st_mode |= S_IWUSR;
	return (0);
}

static int
cryptodesc_close(struct file *fp, struct thread *td __unused)
{
	struct cryptodesc *cd;

	cd = fp->f_data;
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	if (cd->cd_session != NULL)
		cse_free(cd->cd_session);
	mtx_destroy(&cd->cd_lock);
	explicit_bzero(cd, sizeof(*cd));
	free(cd, M_CRYPTODEV);
	return (0);
}

static int
cryptodesc_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp __unused)
{
	struct cryptodesc *cd;
	const struct crypto_session_params *csp;
	bool revoked;
	uint32_t rights;

	cd = fp->f_data;
	mtx_lock(&cd->cd_lock);
	rights = cd->cd_rights;
	revoked = cd->cd_revoked;
	mtx_unlock(&cd->cd_lock);
	kif->kf_type = KF_TYPE_CRYPTO;
	if (cd->cd_type == 0) {
		csp = crypto_get_params(cd->cd_session->cses);
		snprintf(kif->kf_path, sizeof(kif->kf_path),
		    "crypto:mode=%d:cipher=%d:auth=%d:rights=%#x:revoked=%d",
		    csp->csp_mode, csp->csp_cipher_alg, csp->csp_auth_alg, rights,
		    revoked);
	} else {
		snprintf(kif->kf_path, sizeof(kif->kf_path),
		    "crypto:keytype=%u:rights=%#x:revoked=%d", cd->cd_type,
		    rights, revoked);
	}
	return (0);
}

static bool
cse_delete(struct fcrypt *fcr, u_int ses)
{
	struct csession *cse;

	mtx_lock(&fcr->lock);
	TAILQ_FOREACH(cse, &fcr->csessions, next) {
		if (cse->ses == ses) {
			TAILQ_REMOVE(&fcr->csessions, cse, next);
			mtx_unlock(&fcr->lock);
			cse_free(cse);
			return (true);
		}
	}
	mtx_unlock(&fcr->lock);
	return (false);
}

static struct cryptop_data *
cod_alloc(struct csession *cse, size_t aad_len, size_t len)
{
	struct cryptop_data *cod;

	cod = malloc(sizeof(struct cryptop_data), M_CRYPTODEV, M_WAITOK |
	    M_ZERO);

	cod->cse = cse;
	if (crypto_get_params(cse->cses)->csp_flags & CSP_F_SEPARATE_AAD) {
		if (aad_len != 0)
			cod->aad = malloc(aad_len, M_CRYPTODEV, M_WAITOK);
		cod->buf = malloc(len, M_CRYPTODEV, M_WAITOK);
	} else
		cod->buf = malloc(aad_len + len, M_CRYPTODEV, M_WAITOK);
	if (crypto_get_params(cse->cses)->csp_flags & CSP_F_SEPARATE_OUTPUT)
		cod->obuf = malloc(len, M_CRYPTODEV, M_WAITOK);
	return (cod);
}

static void
cod_free(struct cryptop_data *cod)
{

	free(cod->aad, M_CRYPTODEV);
	free(cod->obuf, M_CRYPTODEV);
	free(cod->buf, M_CRYPTODEV);
	free(cod, M_CRYPTODEV);
}

static int
cryptodev_cb(struct cryptop *crp)
{
	struct cryptop_data *cod = crp->crp_opaque;

	/*
	 * Lock to ensure the wakeup() is not missed by the loops
	 * waiting on cod->done in cryptodev_op() and
	 * cryptodev_aead().
	 */
	mtx_lock(&cod->cse->lock);
	cod->done = true;
	mtx_unlock(&cod->cse->lock);
	wakeup(cod);
	return (0);
}

static int
cryptodev_op(struct csession *cse, const struct crypt_op *cop)
{
	const struct crypto_session_params *csp;
	struct cryptop_data *cod = NULL;
	struct cryptop *crp = NULL;
	char *dst;
	int error;

	if (cop->len > 256*1024-4) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (E2BIG);
	}

	if ((cop->len % cse->blocksize) != 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (EINVAL);
	}

	if (cop->mac && cse->hashsize == 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (EINVAL);
	}

	/*
	 * The COP_F_CIPHER_FIRST flag predates explicit session
	 * modes, but the only way it was used was for EtA so allow it
	 * as long as it is consistent with EtA.
	 */
	if (cop->flags & COP_F_CIPHER_FIRST) {
		if (cop->op != COP_ENCRYPT) {
			SDT_PROBE1(opencrypto, dev, ioctl, error,  __LINE__);
			return (EINVAL);
		}
	}

	cod = cod_alloc(cse, 0, cop->len + cse->hashsize);
	dst = cop->dst;

	crp = crypto_getreq(cse->cses, M_WAITOK);

	error = copyin(cop->src, cod->buf, cop->len);
	if (error) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}
	crp->crp_payload_start = 0;
	crp->crp_payload_length = cop->len;
	if (cse->hashsize)
		crp->crp_digest_start = cop->len;

	csp = crypto_get_params(cse->cses);
	switch (csp->csp_mode) {
	case CSP_MODE_COMPRESS:
		switch (cop->op) {
		case COP_ENCRYPT:
			crp->crp_op = CRYPTO_OP_COMPRESS;
			break;
		case COP_DECRYPT:
			crp->crp_op = CRYPTO_OP_DECOMPRESS;
			break;
		default:
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		break;
	case CSP_MODE_CIPHER:
		if (cop->len == 0 ||
		    (cop->iv == NULL && cop->len == cse->ivsize)) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		switch (cop->op) {
		case COP_ENCRYPT:
			crp->crp_op = CRYPTO_OP_ENCRYPT;
			break;
		case COP_DECRYPT:
			crp->crp_op = CRYPTO_OP_DECRYPT;
			break;
		default:
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		break;
	case CSP_MODE_DIGEST:
		switch (cop->op) {
		case 0:
		case COP_ENCRYPT:
		case COP_DECRYPT:
			crp->crp_op = CRYPTO_OP_COMPUTE_DIGEST;
			if (cod->obuf != NULL)
				crp->crp_digest_start = 0;
			break;
		default:
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		break;
	case CSP_MODE_AEAD:
		if (cse->ivsize != 0 && cop->iv == NULL) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		/* FALLTHROUGH */
	case CSP_MODE_ETA:
		switch (cop->op) {
		case COP_ENCRYPT:
			crp->crp_op = CRYPTO_OP_ENCRYPT |
			    CRYPTO_OP_COMPUTE_DIGEST;
			break;
		case COP_DECRYPT:
			crp->crp_op = CRYPTO_OP_DECRYPT |
			    CRYPTO_OP_VERIFY_DIGEST;
			break;
		default:
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		break;
	default:
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		error = EINVAL;
		goto bail;
	}

	crp->crp_flags = CRYPTO_F_CBIMM | (cop->flags & COP_F_BATCH);
	crypto_use_buf(crp, cod->buf, cop->len + cse->hashsize);
	if (cod->obuf)
		crypto_use_output_buf(crp, cod->obuf, cop->len + cse->hashsize);
	crp->crp_callback = cryptodev_cb;
	crp->crp_opaque = cod;

	if (cop->iv) {
		if (cse->ivsize == 0) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		error = copyin(cop->iv, crp->crp_iv, cse->ivsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
		crp->crp_flags |= CRYPTO_F_IV_SEPARATE;
	} else if (cse->ivsize != 0) {
		if (crp->crp_payload_length < cse->ivsize) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		crp->crp_iv_start = 0;
		crp->crp_payload_length -= cse->ivsize;
		if (crp->crp_payload_length != 0)
			crp->crp_payload_start = cse->ivsize;
		dst += cse->ivsize;
	}

	if (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) {
		error = copyin(cop->mac, cod->buf + crp->crp_digest_start,
		    cse->hashsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}
again:
	/*
	 * Let the dispatch run unlocked, then, interlock against the
	 * callback before checking if the operation completed and going
	 * to sleep.  This insures drivers don't inherit our lock which
	 * results in a lock order reversal between crypto_dispatch forced
	 * entry and the crypto_done callback into us.
	 */
	error = crypto_dispatch(crp);
	if (error != 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}

	mtx_lock(&cse->lock);
	while (!cod->done)
		mtx_sleep(cod, &cse->lock, PWAIT, "crydev", 0);
	mtx_unlock(&cse->lock);

	if (crp->crp_etype == EAGAIN) {
		crp->crp_etype = 0;
		cod->done = false;
		goto again;
	}

	if (crp->crp_etype != 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		error = crp->crp_etype;
		goto bail;
	}

	if (cop->dst != NULL) {
		error = copyout(cod->obuf != NULL ? cod->obuf :
		    cod->buf + crp->crp_payload_start, dst,
		    crp->crp_payload_length);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}

	if (cop->mac != NULL && (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) == 0) {
		error = copyout((cod->obuf != NULL ? cod->obuf : cod->buf) +
		    crp->crp_digest_start, cop->mac, cse->hashsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}

bail:
	crypto_freereq(crp);
	cod_free(cod);

	return (error);
}

static int
cryptodev_aead(struct csession *cse, struct crypt_aead *caead)
{
	const struct crypto_session_params *csp;
	struct cryptop_data *cod = NULL;
	struct cryptop *crp = NULL;
	char *dst;
	int error;

	if (caead->len > 256*1024-4 || caead->aadlen > 256*1024-4) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (E2BIG);
	}

	if ((caead->len % cse->blocksize) != 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (EINVAL);
	}

	if (cse->hashsize == 0 || caead->tag == NULL) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		return (EINVAL);
	}

	/*
	 * The COP_F_CIPHER_FIRST flag predates explicit session
	 * modes, but the only way it was used was for EtA so allow it
	 * as long as it is consistent with EtA.
	 */
	if (caead->flags & COP_F_CIPHER_FIRST) {
		if (caead->op != COP_ENCRYPT) {
			SDT_PROBE1(opencrypto, dev, ioctl, error,  __LINE__);
			return (EINVAL);
		}
	}

	cod = cod_alloc(cse, caead->aadlen, caead->len + cse->hashsize);
	dst = caead->dst;

	crp = crypto_getreq(cse->cses, M_WAITOK);

	if (cod->aad != NULL)
		error = copyin(caead->aad, cod->aad, caead->aadlen);
	else
		error = copyin(caead->aad, cod->buf, caead->aadlen);
	if (error) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}
	crp->crp_aad = cod->aad;
	crp->crp_aad_start = 0;
	crp->crp_aad_length = caead->aadlen;

	if (cod->aad != NULL)
		crp->crp_payload_start = 0;
	else
		crp->crp_payload_start = caead->aadlen;
	error = copyin(caead->src, cod->buf + crp->crp_payload_start,
	    caead->len);
	if (error) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}
	crp->crp_payload_length = caead->len;
	if (caead->op == COP_ENCRYPT && cod->obuf != NULL)
		crp->crp_digest_start = crp->crp_payload_output_start +
		    caead->len;
	else
		crp->crp_digest_start = crp->crp_payload_start + caead->len;

	csp = crypto_get_params(cse->cses);
	switch (csp->csp_mode) {
	case CSP_MODE_AEAD:
	case CSP_MODE_ETA:
		switch (caead->op) {
		case COP_ENCRYPT:
			crp->crp_op = CRYPTO_OP_ENCRYPT |
			    CRYPTO_OP_COMPUTE_DIGEST;
			break;
		case COP_DECRYPT:
			crp->crp_op = CRYPTO_OP_DECRYPT |
			    CRYPTO_OP_VERIFY_DIGEST;
			break;
		default:
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		break;
	default:
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		error = EINVAL;
		goto bail;
	}

	crp->crp_flags = CRYPTO_F_CBIMM | (caead->flags & COP_F_BATCH);
	crypto_use_buf(crp, cod->buf, crp->crp_payload_start + caead->len +
	    cse->hashsize);
	if (cod->obuf != NULL)
		crypto_use_output_buf(crp, cod->obuf, caead->len +
		    cse->hashsize);
	crp->crp_callback = cryptodev_cb;
	crp->crp_opaque = cod;

	if (caead->iv) {
		/*
		 * Permit a 16-byte IV for AES-XTS, but only use the
		 * first 8 bytes as a block number.
		 */
		if (csp->csp_mode == CSP_MODE_ETA &&
		    csp->csp_cipher_alg == CRYPTO_AES_XTS &&
		    caead->ivlen == AES_BLOCK_LEN)
			caead->ivlen = AES_XTS_IV_LEN;

		if (cse->ivsize == 0) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			error = EINVAL;
			goto bail;
		}
		if (caead->ivlen != cse->ivsize) {
			error = EINVAL;
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}

		error = copyin(caead->iv, crp->crp_iv, cse->ivsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
		crp->crp_flags |= CRYPTO_F_IV_SEPARATE;
	} else {
		error = EINVAL;
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}

	if (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) {
		error = copyin(caead->tag, cod->buf + crp->crp_digest_start,
		    cse->hashsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}
again:
	/*
	 * Let the dispatch run unlocked, then, interlock against the
	 * callback before checking if the operation completed and going
	 * to sleep.  This insures drivers don't inherit our lock which
	 * results in a lock order reversal between crypto_dispatch forced
	 * entry and the crypto_done callback into us.
	 */
	error = crypto_dispatch(crp);
	if (error != 0) {
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}

	mtx_lock(&cse->lock);
	while (!cod->done)
		mtx_sleep(cod, &cse->lock, PWAIT, "crydev", 0);
	mtx_unlock(&cse->lock);

	if (crp->crp_etype == EAGAIN) {
		crp->crp_etype = 0;
		cod->done = false;
		goto again;
	}

	if (crp->crp_etype != 0) {
		error = crp->crp_etype;
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		goto bail;
	}

	if (caead->dst != NULL) {
		error = copyout(cod->obuf != NULL ? cod->obuf :
		    cod->buf + crp->crp_payload_start, dst,
		    crp->crp_payload_length);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}

	if ((crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) == 0) {
		error = copyout((cod->obuf != NULL ? cod->obuf : cod->buf) +
		    crp->crp_digest_start, caead->tag, cse->hashsize);
		if (error) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			goto bail;
		}
	}

bail:
	crypto_freereq(crp);
	cod_free(cod);

	return (error);
}

static int
cryptodev_find(struct crypt_find_op *find)
{
	device_t dev;
	size_t fnlen = sizeof find->name;

	if (find->crid != -1) {
		dev = crypto_find_device_byhid(find->crid);
		if (dev == NULL)
			return (ENOENT);
		strncpy(find->name, device_get_nameunit(dev), fnlen);
		find->name[fnlen - 1] = '\x0';
	} else {
		find->name[fnlen - 1] = '\x0';
		find->crid = crypto_find_driver(find->name);
		if (find->crid == -1)
			return (ENOENT);
	}
	return (0);
}

static void
fcrypt_dtor(void *data)
{
	struct fcrypt *fcr = data;
	struct csession *cse;

	while ((cse = TAILQ_FIRST(&fcr->csessions))) {
		TAILQ_REMOVE(&fcr->csessions, cse, next);
		KASSERT(refcount_load(&cse->refs) == 1,
		    ("%s: crypto session %p with %d refs", __func__, cse,
		    refcount_load(&cse->refs)));
		cse_free(cse);
	}
	mtx_destroy(&fcr->lock);
	free(fcr, M_CRYPTODEV);
}

static int
crypto_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct fcrypt *fcr;
	int error;

	fcr = malloc(sizeof(struct fcrypt), M_CRYPTODEV, M_WAITOK | M_ZERO);
	TAILQ_INIT(&fcr->csessions);
	mtx_init(&fcr->lock, "fcrypt", NULL, MTX_DEF);
	error = devfs_set_cdevpriv(fcr, fcrypt_dtor);
	if (error)
		fcrypt_dtor(fcr);
	return (error);
}

static int
crypto_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag,
    struct thread *td)
{
	struct fcrypt *fcr;
	struct csession *cse;
	struct session2_op *sop;
	struct crypt_op *cop;
	struct crypt_aead *caead;
	struct cryptodesc_create *create;
	struct cryptodesc_generate *generate;
	struct cryptodesc_key_create *key_create;
	uint32_t ses;
	int error = 0;
	union {
		struct session2_op sopc;
#ifdef COMPAT_FREEBSD32
		struct crypt_op copc;
		struct crypt_aead aeadc;
#endif
	} thunk;
#ifdef COMPAT_FREEBSD32
	u_long cmd32;
	void *data32;

	cmd32 = 0;
	data32 = NULL;
	switch (cmd) {
	case CIOCGSESSION32:
		cmd32 = cmd;
		data32 = data;
		cmd = CIOCGSESSION;
		data = (void *)&thunk.sopc;
		session_op_from_32((struct session_op32 *)data32, &thunk.sopc);
		break;
	case CIOCGSESSION232:
		cmd32 = cmd;
		data32 = data;
		cmd = CIOCGSESSION2;
		data = (void *)&thunk.sopc;
		session2_op_from_32((struct session2_op32 *)data32,
		    &thunk.sopc);
		break;
	case CIOCCRYPT32:
		cmd32 = cmd;
		data32 = data;
		cmd = CIOCCRYPT;
		data = (void *)&thunk.copc;
		crypt_op_from_32((struct crypt_op32 *)data32, &thunk.copc);
		break;
	case CIOCCRYPTAEAD32:
		cmd32 = cmd;
		data32 = data;
		cmd = CIOCCRYPTAEAD;
		data = (void *)&thunk.aeadc;
		crypt_aead_from_32((struct crypt_aead32 *)data32, &thunk.aeadc);
		break;
	}
#endif

	devfs_get_cdevpriv((void **)&fcr);

	switch (cmd) {
#ifdef COMPAT_FREEBSD12
	case CRIOGET:
		/*
		 * NB: This may fail in cases that the old
		 * implementation did not if the current process has
		 * restricted filesystem access (e.g. running in a
		 * jail that does not expose /dev/crypto or in
		 * capability mode).
		 */
		error = kern_openat(td, AT_FDCWD, "/dev/crypto", UIO_SYSSPACE,
		    O_RDWR, 0);
		if (error == 0)
			*(uint32_t *)data = td->td_retval[0];
		break;
#endif
	case CIOCGSESSION:
	case CIOCGSESSION2:
		if (cmd == CIOCGSESSION) {
			session2_op_from_op((void *)data, &thunk.sopc);
			sop = &thunk.sopc;
		} else
			sop = (struct session2_op *)data;

		error = cse_create(fcr, sop);
		if (cmd == CIOCGSESSION && error == 0)
			session2_op_to_op(sop, (void *)data);
		break;
	case CIOCFSESSION:
		ses = *(uint32_t *)data;
		if (!cse_delete(fcr, ses)) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		break;
	case CIOCCRYPT:
		cop = (struct crypt_op *)data;
		cse = cse_find(fcr, cop->ses);
		if (cse == NULL) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		error = cryptodev_op(cse, cop);
		cse_free(cse);
		break;
	case CIOCFINDDEV:
		error = cryptodev_find((struct crypt_find_op *)data);
		break;
	case CIOCGCRYPTODESC:
		create = (struct cryptodesc_create *)data;
		error = cryptodesc_mint(td, create);
		break;
	case CIOCGCRYPTODESCGENERATE:
		generate = (struct cryptodesc_generate *)data;
		error = cryptodesc_mint_generated(td, generate);
		break;
	case CIOCGCRYPTOKEYDESC:
		key_create = (struct cryptodesc_key_create *)data;
		error = cryptodesc_mint_key(td, key_create);
		break;
	case CIOCCRYPTAEAD:
		caead = (struct crypt_aead *)data;
		cse = cse_find(fcr, caead->ses);
		if (cse == NULL) {
			SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
			return (EINVAL);
		}
		error = cryptodev_aead(cse, caead);
		cse_free(cse);
		break;
	default:
		error = EINVAL;
		SDT_PROBE1(opencrypto, dev, ioctl, error, __LINE__);
		break;
	}

#ifdef COMPAT_FREEBSD32
	switch (cmd32) {
	case CIOCGSESSION32:
		if (error == 0)
			session_op_to_32((void *)data, data32);
		break;
	case CIOCGSESSION232:
		if (error == 0)
			session2_op_to_32((void *)data, data32);
		break;
	case CIOCCRYPT32:
		if (error == 0)
			crypt_op_to_32((void *)data, data32);
		break;
	case CIOCCRYPTAEAD32:
		if (error == 0)
			crypt_aead_to_32((void *)data, data32);
		break;
	}
#endif
	return (error);
}

static struct cdevsw crypto_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	crypto_open,
	.d_ioctl =	crypto_ioctl,
	.d_name =	"crypto",
};
static struct cdev *crypto_dev;

/*
 * Initialization code, both for static and dynamic loading.
 */
static int
cryptodev_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("crypto: <crypto device>\n");
		crypto_dev = make_dev(&crypto_cdevsw, 0, 
				      UID_ROOT, GID_WHEEL, 0666,
				      "crypto");
		return 0;
	case MOD_UNLOAD:
		/*XXX disallow if active sessions */
		destroy_dev(crypto_dev);
		return 0;
	}
	return EINVAL;
}

static moduledata_t cryptodev_mod = {
	"cryptodev",
	cryptodev_modevent,
	0
};
MODULE_VERSION(cryptodev, 1);
DECLARE_MODULE(cryptodev, cryptodev_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(cryptodev, crypto, 1, 1, 1);
MODULE_DEPEND(cryptodev, zlib, 1, 1, 1);
