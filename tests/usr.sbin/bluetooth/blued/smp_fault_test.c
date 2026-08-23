/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection coverage for the allocator / OpenSSL FAILURE arms of the
 * SMP crypto and key-storage code.
 *
 * These error branches -- "if (EVP_... <= 0)", "if (malloc == NULL)",
 * "if (RAND_bytes != 1)", "if (PKCS5_PBKDF2_HMAC != 1)" -- handle real
 * runtime failures and are correctness/security relevant, but are normally
 * unreachable because the underlying primitive never fails in a healthy
 * process.  We reach them with a linker --wrap(3) seam: each wrapped symbol
 * has a __wrap_<sym> that consults a test-settable "fail the Nth call"
 * counter and otherwise tail-calls __real_<sym>.
 *
 * Oracle: each function's documented error contract (smp.h / the function
 * comment in smp_crypto.c / smp_keys.c), cited per test.  Crypto KATs are
 * Core Spec Vol 3 Part H Section 2.2.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lcrypto (OpenSSL EVP/EC) -lpthread (bond_db lock type)
 *
 * Requires the parent Makefile to wrap the symbols (LDFLAGS.smp_fault_test):
 *   -Wl,--wrap=malloc -Wl,--wrap=RAND_bytes -Wl,--wrap=PKCS5_PBKDF2_HMAC
 *   -Wl,--wrap=EVP_CIPHER_CTX_new -Wl,--wrap=EVP_CIPHER_CTX_ctrl
 *   -Wl,--wrap=EVP_EncryptInit_ex -Wl,--wrap=EVP_EncryptUpdate
 *   -Wl,--wrap=EVP_EncryptFinal_ex -Wl,--wrap=EVP_DecryptInit_ex
 *   -Wl,--wrap=EVP_DecryptUpdate -Wl,--wrap=EVP_DecryptFinal_ex
 *   -Wl,--wrap=EVP_MAC_fetch -Wl,--wrap=EVP_MAC_CTX_new
 *   -Wl,--wrap=EVP_MAC_init -Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final
 *   -Wl,--wrap=EC_GROUP_new_by_curve_name -Wl,--wrap=EC_POINT_new
 *   -Wl,--wrap=BN_bin2bn -Wl,--wrap=EC_POINT_set_affine_coordinates
 *   -Wl,--wrap=EC_POINT_is_on_curve
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "hci_util.h"		/* prototypes for the hci_* stubs below */
#include "smp.h"
#include "smp_internal.h"
#include "spec_smp_sc_edge_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/* ================================================================
 * Stubs for external symbols referenced by smp.c (hci_util.c).
 * (identical to smp_negative_test.c)
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{

	return (0);
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{

	return (0);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (0);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{

	return (0);
}

/* ================================================================
 * Fault-injection seam: fail the Nth (1-based) call to a wrapped symbol.
 *
 * Each symbol has an "_at" (the 1-based call ordinal to fail; 0 disables)
 * and an "_n" running counter.  fault_reset() clears all of them so each
 * subtest starts from a clean slate.  Because --wrap only intercepts
 * references emitted from the object files linked here (smp*.c, this test),
 * calls made *inside* libcrypto/libc are NOT counted -- only the SMP code's
 * own direct calls, which is exactly what we want to fault.
 * ================================================================ */

static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

#define FI(sym)		static long fi_##sym##_at, fi_##sym##_n;

FI(malloc)
FI(RAND_bytes)
FI(PKCS5_PBKDF2_HMAC)
FI(EVP_CIPHER_CTX_new)
FI(EVP_CIPHER_CTX_ctrl)
FI(EVP_EncryptInit_ex)
FI(EVP_EncryptUpdate)
FI(EVP_EncryptFinal_ex)
FI(EVP_DecryptInit_ex)
FI(EVP_DecryptUpdate)
FI(EVP_DecryptFinal_ex)
FI(EVP_MAC_fetch)
FI(EVP_MAC_CTX_new)
FI(EVP_MAC_init)
FI(EVP_MAC_update)
FI(EVP_MAC_final)
FI(EC_GROUP_new_by_curve_name)
FI(EC_POINT_new)
FI(BN_bin2bn)
FI(EC_POINT_set_affine_coordinates)
FI(EC_POINT_is_on_curve)
FI(EVP_PKEY_CTX_new_id)
FI(EVP_PKEY_keygen)
FI(EVP_PKEY_get_octet_string_param)
FI(EVP_PKEY_fromdata)
FI(EVP_PKEY_derive)
FI(flock)
FI(fsync)

static int fi_flock_errno;

static void
fault_reset(void)
{

#define Z(sym)	do { fi_##sym##_at = 0; fi_##sym##_n = 0; } while (0)
	Z(malloc);
	Z(RAND_bytes);
	Z(PKCS5_PBKDF2_HMAC);
	Z(EVP_CIPHER_CTX_new);
	Z(EVP_CIPHER_CTX_ctrl);
	Z(EVP_EncryptInit_ex);
	Z(EVP_EncryptUpdate);
	Z(EVP_EncryptFinal_ex);
	Z(EVP_DecryptInit_ex);
	Z(EVP_DecryptUpdate);
	Z(EVP_DecryptFinal_ex);
	Z(EVP_MAC_fetch);
	Z(EVP_MAC_CTX_new);
	Z(EVP_MAC_init);
	Z(EVP_MAC_update);
	Z(EVP_MAC_final);
	Z(EC_GROUP_new_by_curve_name);
	Z(EC_POINT_new);
	Z(BN_bin2bn);
	Z(EC_POINT_set_affine_coordinates);
	Z(EC_POINT_is_on_curve);
	Z(EVP_PKEY_CTX_new_id);
	Z(EVP_PKEY_keygen);
	Z(EVP_PKEY_get_octet_string_param);
	Z(EVP_PKEY_fromdata);
	Z(EVP_PKEY_derive);
	Z(flock);
	Z(fsync);
	fi_flock_errno = EIO;
#undef Z
}

extern int	__real_flock(int, int);
int
__wrap_flock(int fd, int operation)
{

	if (fi_hit(&fi_flock_at, &fi_flock_n)) {
		errno = fi_flock_errno;
		return (-1);
	}
	return (__real_flock(fd, operation));
}

extern int	__real_fsync(int);
int
__wrap_fsync(int fd)
{

	if (fi_hit(&fi_fsync_at, &fi_fsync_n)) {
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

/* ---- allocator ---- */
extern void	*__real_malloc(size_t);
void *
__wrap_malloc(size_t sz)
{

	if (fi_hit(&fi_malloc_at, &fi_malloc_n))
		return (NULL);
	return (__real_malloc(sz));
}

/* ---- RNG / KDF ---- */
extern int	__real_RAND_bytes(unsigned char *, int);
int
__wrap_RAND_bytes(unsigned char *buf, int num)
{

	if (fi_hit(&fi_RAND_bytes_at, &fi_RAND_bytes_n))
		return (0);		/* documented success value is 1 */
	return (__real_RAND_bytes(buf, num));
}

extern int	__real_PKCS5_PBKDF2_HMAC(const char *, int,
		    const unsigned char *, int, int, const EVP_MD *, int,
		    unsigned char *);
int
__wrap_PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest,
    int keylen, unsigned char *out)
{

	if (fi_hit(&fi_PKCS5_PBKDF2_HMAC_at, &fi_PKCS5_PBKDF2_HMAC_n))
		return (0);		/* success value is 1 */
	return (__real_PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter,
	    digest, keylen, out));
}

/* ---- EVP cipher ---- */
extern EVP_CIPHER_CTX	*__real_EVP_CIPHER_CTX_new(void);
EVP_CIPHER_CTX *
__wrap_EVP_CIPHER_CTX_new(void)
{

	if (fi_hit(&fi_EVP_CIPHER_CTX_new_at, &fi_EVP_CIPHER_CTX_new_n))
		return (NULL);
	return (__real_EVP_CIPHER_CTX_new());
}

extern int	__real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *, int, int, void *);
int
__wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{

	if (fi_hit(&fi_EVP_CIPHER_CTX_ctrl_at, &fi_EVP_CIPHER_CTX_ctrl_n))
		return (0);
	return (__real_EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr));
}

extern int	__real_EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *,
		    ENGINE *, const unsigned char *, const unsigned char *);
int
__wrap_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    ENGINE *impl, const unsigned char *key, const unsigned char *iv)
{

	if (fi_hit(&fi_EVP_EncryptInit_ex_at, &fi_EVP_EncryptInit_ex_n))
		return (0);
	return (__real_EVP_EncryptInit_ex(ctx, cipher, impl, key, iv));
}

extern int	__real_EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *,
		    int *, const unsigned char *, int);
int
__wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{

	if (fi_hit(&fi_EVP_EncryptUpdate_at, &fi_EVP_EncryptUpdate_n))
		return (0);
	return (__real_EVP_EncryptUpdate(ctx, out, outl, in, inl));
}

extern int	__real_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *,
		    int *);
int
__wrap_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{

	if (fi_hit(&fi_EVP_EncryptFinal_ex_at, &fi_EVP_EncryptFinal_ex_n))
		return (0);
	return (__real_EVP_EncryptFinal_ex(ctx, out, outl));
}

extern int	__real_EVP_DecryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *,
		    ENGINE *, const unsigned char *, const unsigned char *);
int
__wrap_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    ENGINE *impl, const unsigned char *key, const unsigned char *iv)
{

	if (fi_hit(&fi_EVP_DecryptInit_ex_at, &fi_EVP_DecryptInit_ex_n))
		return (0);
	return (__real_EVP_DecryptInit_ex(ctx, cipher, impl, key, iv));
}

extern int	__real_EVP_DecryptUpdate(EVP_CIPHER_CTX *, unsigned char *,
		    int *, const unsigned char *, int);
int
__wrap_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
    const unsigned char *in, int inl)
{

	if (fi_hit(&fi_EVP_DecryptUpdate_at, &fi_EVP_DecryptUpdate_n))
		return (0);
	return (__real_EVP_DecryptUpdate(ctx, out, outl, in, inl));
}

extern int	__real_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *,
		    int *);
int
__wrap_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
{

	if (fi_hit(&fi_EVP_DecryptFinal_ex_at, &fi_EVP_DecryptFinal_ex_n))
		return (0);		/* mimics a GCM tag mismatch */
	return (__real_EVP_DecryptFinal_ex(ctx, outm, outl));
}

/* ---- EVP_MAC (CMAC) ---- */
extern EVP_MAC	*__real_EVP_MAC_fetch(OSSL_LIB_CTX *, const char *,
		    const char *);
EVP_MAC *
__wrap_EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties)
{

	if (fi_hit(&fi_EVP_MAC_fetch_at, &fi_EVP_MAC_fetch_n))
		return (NULL);
	return (__real_EVP_MAC_fetch(libctx, algorithm, properties));
}

extern EVP_MAC_CTX	*__real_EVP_MAC_CTX_new(EVP_MAC *);
EVP_MAC_CTX *
__wrap_EVP_MAC_CTX_new(EVP_MAC *mac)
{

	if (fi_hit(&fi_EVP_MAC_CTX_new_at, &fi_EVP_MAC_CTX_new_n))
		return (NULL);
	return (__real_EVP_MAC_CTX_new(mac));
}

extern int	__real_EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *,
		    size_t, const OSSL_PARAM *);
int
__wrap_EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{

	if (fi_hit(&fi_EVP_MAC_init_at, &fi_EVP_MAC_init_n))
		return (0);
	return (__real_EVP_MAC_init(ctx, key, keylen, params));
}

extern int	__real_EVP_MAC_update(EVP_MAC_CTX *, const unsigned char *,
		    size_t);
int
__wrap_EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data,
    size_t datalen)
{

	if (fi_hit(&fi_EVP_MAC_update_at, &fi_EVP_MAC_update_n))
		return (0);
	return (__real_EVP_MAC_update(ctx, data, datalen));
}

extern int	__real_EVP_MAC_final(EVP_MAC_CTX *, unsigned char *, size_t *,
		    size_t);
int
__wrap_EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl,
    size_t outsize)
{

	if (fi_hit(&fi_EVP_MAC_final_at, &fi_EVP_MAC_final_n))
		return (0);
	return (__real_EVP_MAC_final(ctx, out, outl, outsize));
}

/* ---- EC / BN (P-256 public key validation) ---- */
extern EC_GROUP	*__real_EC_GROUP_new_by_curve_name(int);
EC_GROUP *
__wrap_EC_GROUP_new_by_curve_name(int nid)
{

	if (fi_hit(&fi_EC_GROUP_new_by_curve_name_at,
	    &fi_EC_GROUP_new_by_curve_name_n))
		return (NULL);
	return (__real_EC_GROUP_new_by_curve_name(nid));
}

extern EC_POINT	*__real_EC_POINT_new(const EC_GROUP *);
EC_POINT *
__wrap_EC_POINT_new(const EC_GROUP *group)
{

	if (fi_hit(&fi_EC_POINT_new_at, &fi_EC_POINT_new_n))
		return (NULL);
	return (__real_EC_POINT_new(group));
}

extern BIGNUM	*__real_BN_bin2bn(const unsigned char *, int, BIGNUM *);
BIGNUM *
__wrap_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{

	if (fi_hit(&fi_BN_bin2bn_at, &fi_BN_bin2bn_n))
		return (NULL);
	return (__real_BN_bin2bn(s, len, ret));
}

extern int	__real_EC_POINT_set_affine_coordinates(const EC_GROUP *,
		    EC_POINT *, const BIGNUM *, const BIGNUM *, BN_CTX *);
int
__wrap_EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p,
    const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
{

	if (fi_hit(&fi_EC_POINT_set_affine_coordinates_at,
	    &fi_EC_POINT_set_affine_coordinates_n))
		return (0);
	return (__real_EC_POINT_set_affine_coordinates(group, p, x, y, ctx));
}

extern int	__real_EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *,
		    BN_CTX *);
int
__wrap_EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
    BN_CTX *ctx)
{

	if (fi_hit(&fi_EC_POINT_is_on_curve_at, &fi_EC_POINT_is_on_curve_n))
		return (0);
	return (__real_EC_POINT_is_on_curve(group, point, ctx));
}

/* ---- EVP P-256 key generation / public-key extraction (smp_sc.c) ---- */
extern EVP_PKEY_CTX *__real_EVP_PKEY_CTX_new_id(int, ENGINE *);
EVP_PKEY_CTX *
__wrap_EVP_PKEY_CTX_new_id(int id, ENGINE *engine)
{

	if (fi_hit(&fi_EVP_PKEY_CTX_new_id_at, &fi_EVP_PKEY_CTX_new_id_n))
		return (NULL);
	return (__real_EVP_PKEY_CTX_new_id(id, engine));
}

extern int __real_EVP_PKEY_keygen(EVP_PKEY_CTX *, EVP_PKEY **);
int
__wrap_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **key)
{

	if (fi_hit(&fi_EVP_PKEY_keygen_at, &fi_EVP_PKEY_keygen_n))
		return (0);
	return (__real_EVP_PKEY_keygen(ctx, key));
}

extern int __real_EVP_PKEY_get_octet_string_param(const EVP_PKEY *,
    const char *, unsigned char *, size_t, size_t *);
int
__wrap_EVP_PKEY_get_octet_string_param(const EVP_PKEY *key,
    const char *name, unsigned char *buf, size_t max_buf_sz, size_t *out_len)
{

	if (fi_hit(&fi_EVP_PKEY_get_octet_string_param_at,
	    &fi_EVP_PKEY_get_octet_string_param_n))
		return (0);
	return (__real_EVP_PKEY_get_octet_string_param(key, name, buf,
	    max_buf_sz, out_len));
}

extern int __real_EVP_PKEY_fromdata(EVP_PKEY_CTX *, EVP_PKEY **, int,
    OSSL_PARAM []);
int
__wrap_EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **key, int selection,
    OSSL_PARAM params[])
{

	if (fi_hit(&fi_EVP_PKEY_fromdata_at, &fi_EVP_PKEY_fromdata_n))
		return (0);
	return (__real_EVP_PKEY_fromdata(ctx, key, selection, params));
}

extern int __real_EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);
int
__wrap_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{

	if (fi_hit(&fi_EVP_PKEY_derive_at, &fi_EVP_PKEY_derive_n))
		return (0);
	return (__real_EVP_PKEY_derive(ctx, key, keylen));
}

/* ================================================================
 * Test fixtures
 * ================================================================ */
static const uint8_t k16[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t r16[16] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/*
 * A valid (on-curve, non-debug) P-256 public key so the healthy path of
 * smp_validate_public_key reaches the EC/BN calls we fault.  This is the
 * SC sample "PKb" from Core Spec Vol 3 Part H Section 2.3.5.6.1 sample data,
 * big-endian coordinates.
 */
static const uint8_t pk_x[32] = {
	0x1e, 0xa1, 0xf0, 0xf0, 0x1f, 0xaf, 0x1d, 0x96,
	0x09, 0x59, 0x22, 0x84, 0xf1, 0x9e, 0x4c, 0x00,
	0x47, 0xb5, 0x8a, 0xfd, 0x86, 0x15, 0xa6, 0x9f,
	0x55, 0x90, 0x77, 0xb2, 0x2f, 0xaa, 0xa1, 0x90
};
static const uint8_t pk_y[32] = {
	0x4c, 0x55, 0xf3, 0x3e, 0x42, 0x9d, 0xad, 0x37,
	0x73, 0x56, 0x70, 0x3a, 0x9a, 0xb8, 0x51, 0x60,
	0x47, 0x2d, 0x11, 0x30, 0xe2, 0x8e, 0x36, 0x76,
	0x5f, 0x89, 0xaf, 0xf9, 0x15, 0xb1, 0x21, 0x4a
};

/* ================================================================
 * smp_aes128 -- Core Spec Vol 3 Part H 2.2.1.
 * Contract (smp.h): returns 0 on success, -1 on failure
 * (warn_unused_result).  Each EVP failure arm zeroes out[] and returns -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(aes128_faults);
ATF_TC_BODY(aes128_faults, tc)
{
	uint8_t out[16];
	int rc;

	/* baseline: healthy call succeeds */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_aes128(k16, r16, out));

	/* EVP_CIPHER_CTX_new == NULL (smp_crypto.c:64) */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	memset(out, 0xaa, sizeof(out));
	rc = smp_aes128(k16, r16, out);
	ATF_CHECK_EQ(-1, rc);

	/* EVP_EncryptInit_ex <= 0 (smp_crypto.c:71) */
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	ATF_CHECK_EQ(-1, smp_aes128(k16, r16, out));

	/* EVP_EncryptUpdate <= 0 (smp_crypto.c:80) */
	fault_reset();
	fi_EVP_EncryptUpdate_at = 1;
	ATF_CHECK_EQ(-1, smp_aes128(k16, r16, out));
}

/* ================================================================
 * smp_aes_cmac -- RFC 4493 / Core Spec Vol 3 Part H 2.2.5.
 * Contract: returns 0 on success, -1 on failure; every failure arm
 * zeroes mac[] first.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(aes_cmac_faults);
ATF_TC_BODY(aes_cmac_faults, tc)
{
	uint8_t mac[16];
	const uint8_t msg[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	fault_reset();
	ATF_REQUIRE_EQ(0, smp_aes_cmac(k16, msg, sizeof(msg), mac));

	/* EVP_MAC_fetch == NULL (smp_crypto.c:285) */
	fault_reset();
	fi_EVP_MAC_fetch_at = 1;
	memset(mac, 0xaa, sizeof(mac));
	ATF_CHECK_EQ(-1, smp_aes_cmac(k16, msg, sizeof(msg), mac));

	/* EVP_MAC_CTX_new == NULL (smp_crypto.c:291) */
	fault_reset();
	fi_EVP_MAC_CTX_new_at = 1;
	ATF_CHECK_EQ(-1, smp_aes_cmac(k16, msg, sizeof(msg), mac));

	/* EVP_MAC_init <= 0 (smp_crypto.c:300) */
	fault_reset();
	fi_EVP_MAC_init_at = 1;
	ATF_CHECK_EQ(-1, smp_aes_cmac(k16, msg, sizeof(msg), mac));

	/* EVP_MAC_update <= 0 (smp_crypto.c:304) */
	fault_reset();
	fi_EVP_MAC_update_at = 1;
	ATF_CHECK_EQ(-1, smp_aes_cmac(k16, msg, sizeof(msg), mac));

	/* EVP_MAC_final <= 0 (smp_crypto.c:309) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ(-1, smp_aes_cmac(k16, msg, sizeof(msg), mac));
}

/* ================================================================
 * smp_c1 / smp_s1 -- Core Spec Vol 3 Part H 2.2.3 / 2.2.4.
 * Contract: return -1 when an underlying E() (smp_aes128) fails.
 * c1 calls smp_aes128 twice (each -> one EVP_CIPHER_CTX_new); we fail the
 * 1st and 2nd invocation to cover both "if (smp_aes128(...) < 0)" arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(c1_s1_faults);
ATF_TC_BODY(c1_s1_faults, tc)
{
	const uint8_t preq[7] = { 1, 2, 3, 4, 5, 6, 7 };
	const uint8_t pres[7] = { 7, 6, 5, 4, 3, 2, 1 };
	const uint8_t ia[6] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6 };
	const uint8_t ra[6] = { 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6 };
	uint8_t confirm[16], stk[16];

	fault_reset();
	ATF_REQUIRE_EQ(0, smp_c1(k16, r16, preq, pres, 0, ia, 1, ra, confirm));

	/* first E() fails (smp_crypto.c:136) */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	ATF_CHECK_EQ(-1, smp_c1(k16, r16, preq, pres, 0, ia, 1, ra, confirm));

	/* second E() fails (smp_crypto.c:144) */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 2;
	ATF_CHECK_EQ(-1, smp_c1(k16, r16, preq, pres, 0, ia, 1, ra, confirm));

	/* s1 propagates the single E() failure (smp_crypto.c:167) */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_s1(k16, r16, r16, stk));
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	ATF_CHECK_EQ(-1, smp_s1(k16, r16, r16, stk));
}

/* ================================================================
 * smp_validate_public_key -- Core Spec Vol 3 Part H 2.3.5.6.1.
 * Contract (smp_crypto.c): returns 0 if the key is a valid on-curve
 * non-infinity point, -1 otherwise.  Every OpenSSL failure "goto out"
 * yields ret == -1 (fail closed -- a key we cannot validate is rejected).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(validate_pubkey_faults);
ATF_TC_BODY(validate_pubkey_faults, tc)
{

	fault_reset();
	ATF_REQUIRE_EQ(0, smp_validate_public_key(pk_x, pk_y, NULL));

	/* EC_GROUP_new_by_curve_name == NULL (smp_crypto.c:236) */
	fault_reset();
	fi_EC_GROUP_new_by_curve_name_at = 1;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));

	/* EC_POINT_new == NULL (smp_crypto.c:240) */
	fault_reset();
	fi_EC_POINT_new_at = 1;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));

	/* BN_bin2bn == NULL, first (x) call (smp_crypto.c:244/246) */
	fault_reset();
	fi_BN_bin2bn_at = 1;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));

	/* BN_bin2bn == NULL, second (y) call (smp_crypto.c:245/246) */
	fault_reset();
	fi_BN_bin2bn_at = 2;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));

	/* EC_POINT_set_affine_coordinates == 0 (smp_crypto.c:249) */
	fault_reset();
	fi_EC_POINT_set_affine_coordinates_at = 1;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));

	/* EC_POINT_is_on_curve == 0 (smp_crypto.c:252) */
	fault_reset();
	fi_EC_POINT_is_on_curve_at = 1;
	ATF_CHECK_EQ(-1, smp_validate_public_key(pk_x, pk_y, NULL));
}

/* ================================================================
 * REGRESSION GUARD: the SC crypto helpers (f4/f5/f6/g2/h6/h7) and
 * smp_generate_sc_oob must propagate a failure of the underlying
 * smp_aes_cmac instead of silently emitting all-zero key material.
 * A transient OpenSSL failure must abort the operation (return -1),
 * never yield a deterministic all-zero confirm / DHKey-check value.
 * We inject a CMAC failure and assert the failure is surfaced.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sc_void_helpers_swallow_cmac_failure);
ATF_TC_BODY(sc_void_helpers_swallow_cmac_failure, tc)
{
	uint8_t u[32], v[32], x[16], out[16];
	uint8_t w32[32], n1[16], n2[16], a1[7], a2[7];
	uint8_t mackey[16], ltk[16], iocap[3], r[16];
	uint8_t keyid[4], salt[16], w16[16];
	uint8_t confirm[16], rnd[16];
	uint32_t g2out;

	memset(u, 0x11, sizeof(u));
	memset(v, 0x22, sizeof(v));
	memset(x, 0x33, sizeof(x));
	memset(w32, 0x44, sizeof(w32));
	memset(w16, 0x44, sizeof(w16));
	memset(n1, 0x55, sizeof(n1));
	memset(n2, 0x66, sizeof(n2));
	memset(a1, 0x77, sizeof(a1));
	memset(a2, 0x88, sizeof(a2));
	memset(iocap, 0x99, sizeof(iocap));
	memset(r, 0xbb, sizeof(r));
	memset(keyid, 0xcc, sizeof(keyid));
	memset(salt, 0xdd, sizeof(salt));

	/* f4 with CMAC forced to fail -> returns -1, not all-zero success */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	memset(out, 0xaa, sizeof(out));
	ATF_CHECK_EQ_MSG(-1, smp_f4(u, v, x, 0, out),
	    "smp_f4 must surface CMAC failure");

	/* f5 with CMAC forced to fail -> returns -1 (guards LTK/MacKey) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_f5(w32, n1, n2, a1, a2, mackey, ltk),
	    "smp_f5 must surface CMAC failure");

	/* f6 with CMAC forced to fail -> returns -1 (guards DHKey check) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_f6(w16, n1, n2, r, iocap, a1, a2, out),
	    "smp_f6 must surface CMAC failure");

	/* g2 with CMAC forced to fail -> returns -1 (guards comparison val) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_g2(u, v, x, n1, &g2out),
	    "smp_g2 must surface CMAC failure");

	/* h6 with CMAC forced to fail -> returns -1 (guards CTKD link key) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_h6(w16, keyid, out),
	    "smp_h6 must surface CMAC failure");

	/* h7 with CMAC forced to fail -> returns -1 (guards CTKD link key) */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_h7(salt, w16, out),
	    "smp_h7 must surface CMAC failure");

	/* smp_generate_sc_oob must report failure (-1), not success */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	memset(confirm, 0xaa, sizeof(confirm));
	ATF_CHECK_EQ_MSG(-1, smp_generate_sc_oob(confirm, rnd, u),
	    "smp_generate_sc_oob must report failure on CMAC failure");
}

ATF_TC_WITHOUT_HEAD(sc_ephemeral_and_oob_faults);
ATF_TC_BODY(sc_ephemeral_and_oob_faults, tc)
{
	struct smp_conn sc;
	uint8_t preq[7] = { BT_SC_SPEC_PAIRING_REQUEST, 0x03, 0, 0x08, 16, 0, 0 };
	uint8_t pres[7] = { BT_SC_SPEC_PAIRING_RESPONSE, 0x03, 0, 0x08, 16, 0, 0 };
	uint8_t confirm[16], random[16], pkx[32];

	/* The pairing-local ephemeral generator has two fail-closed arms. */
	memset(&sc, 0, sizeof(sc));
	fault_reset();
	fi_EVP_PKEY_CTX_new_id_at = 1;
	ATF_CHECK_EQ(-1, smp_pair_sc(&sc, preq, pres, 0));
	fault_reset();
	fi_EVP_PKEY_keygen_at = 1;
	ATF_CHECK_EQ(-1, smp_pair_sc(&sc, preq, pres, 0));

	/* Local SC-OOB generation propagates every key/RNG extraction failure. */
	smp_sc_oob_clear_local();
	fault_reset();
	fi_EVP_PKEY_CTX_new_id_at = 1;
	ATF_CHECK_EQ(-1, smp_sc_oob_generate_local(confirm, random, pkx));
	fault_reset();
	fi_EVP_PKEY_keygen_at = 1;
	ATF_CHECK_EQ(-1, smp_sc_oob_generate_local(confirm, random, pkx));
	fault_reset();
	fi_EVP_PKEY_get_octet_string_param_at = 1;
	ATF_CHECK_EQ(-1, smp_sc_oob_generate_local(confirm, random, pkx));
	fault_reset();
	fi_EVP_MAC_fetch_at = 1;
	ATF_CHECK_EQ(-1, smp_sc_oob_generate_local(confirm, random, pkx));

	/* Replacement frees the previous pending key; clear is idempotent. */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_sc_oob_generate_local(confirm, random, pkx));
	ATF_REQUIRE_EQ(0, smp_sc_oob_generate_local(confirm, random, pkx));
	smp_sc_oob_clear_local();
	smp_sc_oob_clear_local();
}

enum sc_fault_role {
	SC_FAULT_PAIR,
	SC_FAULT_PAIR_PASSKEY,
	SC_FAULT_RESPOND,
	SC_FAULT_RESPOND_PASSKEY
};

static int
sc_fault_passkey(uint32_t *passkey, bool display __unused, void *arg __unused)
{

	*passkey = 123456;
	return (0);
}

enum sc_peer_stage {
	SC_PEER_KEX_ONLY,
	SC_PEER_JW,
	SC_PEER_PASSKEY
};

static void
sc_fault_peer(int fd, bool initiator, enum sc_peer_stage stage,
    const uint8_t public_key[65])
{
	uint8_t pdu[65];
	uint8_t pka[32], pkb[32], nb[16], cb[16];
	ssize_t n;

	if (initiator) {
		pdu[0] = BT_SC_SPEC_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, public_key + 1, 32);
		smp_swap_buf(pdu + 33, public_key + 33, 32);
		memcpy(pka, pdu + 1, sizeof(pka));
		if (send(fd, pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
			_exit(10);
		n = recv(fd, pdu, sizeof(pdu), 0);
		if (n == sizeof(pdu))
			memcpy(pkb, pdu + 1, sizeof(pkb));
	} else {
		n = recv(fd, pdu, sizeof(pdu), 0);
		if (n == sizeof(pdu) && pdu[0] == BT_SC_SPEC_PAIRING_PUBLIC_KEY) {
			memcpy(pka, pdu + 1, sizeof(pka));
			pdu[0] = BT_SC_SPEC_PAIRING_PUBLIC_KEY;
			smp_swap_buf(pdu + 1, public_key + 1, 32);
			smp_swap_buf(pdu + 33, public_key + 33, 32);
			memcpy(pkb, pdu + 1, sizeof(pkb));
			if (send(fd, pdu, sizeof(pdu), MSG_EOR) != sizeof(pdu))
				_exit(11);
		}
	}
	if (n != sizeof(pdu) || pdu[0] != BT_SC_SPEC_PAIRING_PUBLIC_KEY)
		_exit(12);
	if (stage == SC_PEER_KEX_ONLY)
		_exit(0);

	memset(nb, 0x5a, sizeof(nb));
	if (stage == SC_PEER_JW) {
		if (initiator) {
			/* DUT responder: receive Cb, then send Na and receive Nb. */
			n = recv(fd, pdu, 17, 0);
			if (n == 17 && pdu[0] == BT_SC_SPEC_PAIRING_CONFIRM) {
				pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
				memset(pdu + 1, 0xa5, 16);
				(void)send(fd, pdu, 17, MSG_EOR);
				(void)recv(fd, pdu, 17, 0);
			}
		} else {
			/* DUT initiator: send a valid responder confirm and nonce. */
			if (smp_f4(pkb, pka, nb, 0, cb) != 0)
				_exit(13);
			pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
			memcpy(pdu + 1, cb, 16);
			if (send(fd, pdu, 17, MSG_EOR) != 17)
				_exit(14);
			n = recv(fd, pdu, 17, 0);
			if (n == 17 && pdu[0] == BT_SC_SPEC_PAIRING_RANDOM) {
				pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
				memcpy(pdu + 1, nb, 16);
				(void)send(fd, pdu, 17, MSG_EOR);
			}
		}
	} else if (initiator) {
		/* Peer initiator drives responder passkey round zero. */
		pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
		memset(pdu + 1, 0x33, 16);
		(void)send(fd, pdu, 17, MSG_EOR);
		n = recv(fd, pdu, 17, 0);
		if (n == 17 && pdu[0] == BT_SC_SPEC_PAIRING_CONFIRM) {
			pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
			memset(pdu + 1, 0x44, 16);
			(void)send(fd, pdu, 17, MSG_EOR);
			(void)recv(fd, pdu, 17, 0);
		}
	} else {
		/* Peer responder drives initiator passkey round zero. */
		n = recv(fd, pdu, 17, 0);
		if (n == 17 && pdu[0] == BT_SC_SPEC_PAIRING_CONFIRM) {
			pdu[0] = BT_SC_SPEC_PAIRING_CONFIRM;
			memset(pdu + 1, 0x55, 16);
			(void)send(fd, pdu, 17, MSG_EOR);
			n = recv(fd, pdu, 17, 0);
			if (n == 17 && pdu[0] == BT_SC_SPEC_PAIRING_RANDOM) {
				pdu[0] = BT_SC_SPEC_PAIRING_RANDOM;
				memset(pdu + 1, 0x66, 16);
				(void)send(fd, pdu, 17, MSG_EOR);
			}
		}
	}
	_exit(0);
}

static void
run_sc_fault(enum sc_fault_role role, unsigned pre_fault, unsigned mac_at,
    int model)
{
	struct smp_conn sc;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;
	uint8_t public_key[65];
	uint8_t preq[7] = { BT_SC_SPEC_PAIRING_REQUEST, BT_SC_SPEC_IO_KEYBOARD_ONLY, 0,
	    BT_SC_SPEC_AUTH_SECURE_CONNECTIONS | BT_SC_SPEC_AUTH_MITM, 16, 0, 0 };
	uint8_t pres[7] = { BT_SC_SPEC_PAIRING_RESPONSE, BT_SC_SPEC_IO_DISPLAY_ONLY, 0,
	    BT_SC_SPEC_AUTH_SECURE_CONNECTIONS | BT_SC_SPEC_AUTH_MITM, 16, 0, 0 };
	size_t public_len = sizeof(public_key);
	int fds[2], status, result;
	pid_t pid;

	/* Prepare a valid P-256 peer key before arming either fault seam. */
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE(EVP_PKEY_keygen_init(ctx) > 0);
	ATF_REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
	    NID_X9_62_prime256v1) > 0);
	ATF_REQUIRE(EVP_PKEY_keygen(ctx, &key) > 0);
	EVP_PKEY_CTX_free(ctx);
	ATF_REQUIRE(EVP_PKEY_get_octet_string_param(key,
	    OSSL_PKEY_PARAM_PUB_KEY, public_key, sizeof(public_key),
	    &public_len) > 0);
	ATF_REQUIRE_EQ(sizeof(public_key), public_len);
	EVP_PKEY_free(key);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	signal(SIGPIPE, SIG_IGN);
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = fds[0];
	sc.hci_fd = -1;
	sc.con_handle = 0x0042;
	sc.passkey_cb = sc_fault_passkey;
	sc.min_key_size = 16;

	/* Do not leak the preceding iteration's fault ordinal into the peer. */
	fault_reset();
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(fds[0]);
		sc_fault_peer(fds[1], role == SC_FAULT_RESPOND ||
		    role == SC_FAULT_RESPOND_PASSKEY,
		    mac_at == 0 ? SC_PEER_KEX_ONLY :
		    (role == SC_FAULT_PAIR_PASSKEY ||
		    role == SC_FAULT_RESPOND_PASSKEY ? SC_PEER_PASSKEY : SC_PEER_JW),
		    public_key);
	}
	close(fds[1]);
	fault_reset();
	if (mac_at != 0)
		fi_EVP_MAC_final_at = mac_at;
	else if (pre_fault == 1)
		fi_EVP_PKEY_fromdata_at = 1;
	else if (pre_fault == 2)
		fi_EVP_PKEY_derive_at = 1;
	else
		fi_EC_POINT_is_on_curve_at = 1;

	switch (role) {
	case SC_FAULT_PAIR:
		result = smp_pair_sc(&sc, preq, pres, model);
		break;
	case SC_FAULT_PAIR_PASSKEY:
		result = smp_pair_sc_passkey(&sc, preq, pres);
		break;
	case SC_FAULT_RESPOND:
		result = smp_respond_sc(&sc, preq, pres, model);
		break;
	case SC_FAULT_RESPOND_PASSKEY:
		result = smp_respond_sc_passkey(&sc, preq, pres);
		break;
	}
	ATF_CHECK_EQ(-1, result);
	close(fds[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	if (pre_fault == 3 && (role == SC_FAULT_RESPOND ||
	    role == SC_FAULT_RESPOND_PASSKEY))
		ATF_CHECK_EQ(12, WEXITSTATUS(status));
	else
		ATF_CHECK_MSG(WEXITSTATUS(status) == 0,
		    "role=%d mac_at=%u peer_status=%d", role, mac_at,
		    WEXITSTATUS(status));
}

static void
run_sc_early_fault(enum sc_fault_role role, unsigned fault)
{
	struct smp_conn sc;
	uint8_t preq[7] = { BT_SC_SPEC_PAIRING_REQUEST, BT_SC_SPEC_IO_KEYBOARD_ONLY, 0,
	    BT_SC_SPEC_AUTH_SECURE_CONNECTIONS | BT_SC_SPEC_AUTH_MITM, 16, 0, 0 };
	uint8_t pres[7] = { BT_SC_SPEC_PAIRING_RESPONSE, BT_SC_SPEC_IO_DISPLAY_ONLY, 0,
	    BT_SC_SPEC_AUTH_SECURE_CONNECTIONS | BT_SC_SPEC_AUTH_MITM, 16, 0, 0 };
	int fds[2], result;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = fds[0];
	sc.hci_fd = -1;
	sc.passkey_cb = sc_fault_passkey;
	fault_reset();
	if (fault == 0)
		fi_EVP_PKEY_CTX_new_id_at = 1;
	else if (fault == 1)
		fi_EVP_PKEY_keygen_at = 1;
	else
		fi_EVP_PKEY_get_octet_string_param_at = 1;

	switch (role) {
	case SC_FAULT_PAIR:
		result = smp_pair_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS);
		break;
	case SC_FAULT_PAIR_PASSKEY:
		result = smp_pair_sc_passkey(&sc, preq, pres);
		break;
	case SC_FAULT_RESPOND:
		result = smp_respond_sc(&sc, preq, pres, SMP_MODEL_JUST_WORKS);
		break;
	case SC_FAULT_RESPOND_PASSKEY:
		result = smp_respond_sc_passkey(&sc, preq, pres);
		break;
	}
	ATF_CHECK_EQ(-1, result);
	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(sc_peer_key_and_derive_faults);
ATF_TC_BODY(sc_peer_key_and_derive_faults, tc)
{
	enum sc_fault_role role;

	for (role = SC_FAULT_PAIR; role <= SC_FAULT_RESPOND_PASSKEY; role++) {
		run_sc_fault(role, 1, 0, SMP_MODEL_JUST_WORKS);
		run_sc_fault(role, 2, 0, SMP_MODEL_JUST_WORKS);
	}
}

ATF_TC_WITHOUT_HEAD(sc_stage_crypto_faults);
ATF_TC_BODY(sc_stage_crypto_faults, tc)
{
	/* JW/NC: f4, g2/f5, and each f6 invocation in both roles. */
	run_sc_fault(SC_FAULT_PAIR, 0, 1, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_PAIR, 0, 2, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_PAIR, 0, 5, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_PAIR, 0, 6, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_PAIR, 0, 2, SMP_MODEL_NUMERIC_COMPARISON);
	run_sc_fault(SC_FAULT_RESPOND, 0, 1, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_RESPOND, 0, 2, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_RESPOND, 0, 5, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_RESPOND, 0, 6, SMP_MODEL_JUST_WORKS);
	run_sc_fault(SC_FAULT_RESPOND, 0, 2, SMP_MODEL_NUMERIC_COMPARISON);

	/* Passkey: local confirm and peer-confirm verification fail closed. */
	run_sc_fault(SC_FAULT_PAIR_PASSKEY, 0, 1, SMP_MODEL_PASSKEY_ENTRY);
	run_sc_fault(SC_FAULT_PAIR_PASSKEY, 0, 2, SMP_MODEL_PASSKEY_ENTRY);
	run_sc_fault(SC_FAULT_RESPOND_PASSKEY, 0, 1,
	    SMP_MODEL_PASSKEY_ENTRY);
	run_sc_fault(SC_FAULT_RESPOND_PASSKEY, 0, 2,
	    SMP_MODEL_PASSKEY_ENTRY);
}

ATF_TC_WITHOUT_HEAD(sc_all_roles_local_key_faults);
ATF_TC_BODY(sc_all_roles_local_key_faults, tc)
{
	enum sc_fault_role role;
	unsigned fault;

	for (role = SC_FAULT_PAIR; role <= SC_FAULT_RESPOND_PASSKEY; role++)
		for (fault = 0; fault < 3; fault++)
			run_sc_early_fault(role, fault);
}

ATF_TC_WITHOUT_HEAD(sc_all_roles_peer_key_validation_faults);
ATF_TC_BODY(sc_all_roles_peer_key_validation_faults, tc)
{
	enum sc_fault_role role;

	for (role = SC_FAULT_PAIR; role <= SC_FAULT_RESPOND_PASSKEY; role++)
		run_sc_fault(role, 3, 0, SMP_MODEL_JUST_WORKS);
}

/*
 * smp_f5 derives T, then MacKey, then LTK with three successive AES-CMAC
 * calls (Core Spec Vol 3 Part H 2.2.7).  Failing only the 2nd or 3rd CMAC
 * exercises the MacKey- and LTK-guard gotos that a 1st-CMAC failure skips.
 */
ATF_TC_WITHOUT_HEAD(f5_late_cmac_faults);
ATF_TC_BODY(f5_late_cmac_faults, tc)
{
	uint8_t w32[32], n1[16], n2[16], a1[7], a2[7];
	uint8_t mackey[16], ltk[16];

	memset(w32, 0x44, sizeof(w32));
	memset(n1, 0x55, sizeof(n1));
	memset(n2, 0x66, sizeof(n2));
	memset(a1, 0x77, sizeof(a1));
	memset(a2, 0x88, sizeof(a2));

	/* Sanity: no fault -> success. */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_f5(w32, n1, n2, a1, a2, mackey, ltk));

	/* Fail the 2nd CMAC (MacKey) -> MacKey guard goto. */
	fault_reset();
	fi_EVP_MAC_final_at = 2;
	ATF_CHECK_EQ_MSG(-1, smp_f5(w32, n1, n2, a1, a2, mackey, ltk),
	    "smp_f5 must surface a MacKey-CMAC failure");

	/* Fail the 3rd CMAC (LTK) -> LTK guard goto. */
	fault_reset();
	fi_EVP_MAC_final_at = 3;
	ATF_CHECK_EQ_MSG(-1, smp_f5(w32, n1, n2, a1, a2, mackey, ltk),
	    "smp_f5 must surface an LTK-CMAC failure");
}

/*
 * Cross-Transport Key Derivation (Core Spec Vol 3 Part H 2.4.2.4-2.4.2.5).
 * Both directions and both the CT2 (h7) and legacy (h6) derivation
 * branches, plus each h6/h7 CMAC-failure guard, are driven here.  h6 and h7
 * each perform exactly one CMAC, so the LTK-derivation call is the 2nd CMAC.
 * Verbose logging is raised so the LOG_SMP(1,...) arms are also evaluated;
 * this case is a pure function with no socket/fork so it is timing-safe.
 */
ATF_TC_WITHOUT_HEAD(ctkd_derive_faults);
ATF_TC_BODY(ctkd_derive_faults, tc)
{
	struct smp_bond bond, reverse;
	uint8_t untouched_ltk[16];

	blued_verbose = 2;

	memset(&bond, 0, sizeof(bond));
	bond.is_sc = true;
	bond.has_ltk = true;
	bond.is_mitm = true;
	memset(bond.ltk, 0x5A, sizeof(bond.ltk));

	/* CT2 success (h7 then h6) -> link key derived. */
	fault_reset();
	ATF_CHECK_EQ_MSG(0, smp_ctkd_derive_link_key(&bond, true),
	    "CT2 CTKD must succeed with an SC/MITM/LTK bond");
	ATF_CHECK(bond.has_link_key);

	/* Legacy success (h6 then h6). */
	fault_reset();
	bond.has_link_key = false;
	ATF_CHECK_EQ_MSG(0, smp_ctkd_derive_link_key(&bond, false),
	    "legacy CTKD must succeed");
	ATF_CHECK(bond.has_link_key);

	/* CT2 path: h7 (1st CMAC) fails -> -1. */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_ctkd_derive_link_key(&bond, true),
	    "CT2 CTKD must fail when h7 CMAC fails");

	/* Legacy path: first h6 (1st CMAC) fails -> -1. */
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ_MSG(-1, smp_ctkd_derive_link_key(&bond, false),
	    "legacy CTKD must fail when the first h6 CMAC fails");

	/* Final link-key h6 (2nd CMAC) fails -> -1. */
	fault_reset();
	fi_EVP_MAC_final_at = 2;
	ATF_CHECK_EQ_MSG(-1, smp_ctkd_derive_link_key(&bond, true),
	    "CTKD must fail when the LTK-derivation h6 CMAC fails");

	/* Non-MITM bond: CTKD is skipped (returns 0, no key). */
	fault_reset();
	bond.is_mitm = false;
	bond.has_link_key = false;
	ATF_CHECK_EQ_MSG(0, smp_ctkd_derive_link_key(&bond, true),
	    "non-MITM bond must skip CTKD");
	ATF_CHECK(!bond.has_link_key);

	/* Exercise the reverse Link Key -> LTK direction and its guards. */
	memset(&reverse, 0, sizeof(reverse));
	reverse.is_sc = true;
	reverse.has_link_key = true;
	reverse.is_mitm = true;
	memset(reverse.link_key, 0xa5, sizeof(reverse.link_key));

	fault_reset();
	ATF_CHECK_EQ_MSG(0, smp_ctkd_derive_ltk(&reverse, true),
	    "CT2 reverse CTKD must succeed");
	ATF_CHECK(reverse.has_ltk);

	fault_reset();
	reverse.has_ltk = false;
	ATF_CHECK_EQ_MSG(0, smp_ctkd_derive_ltk(&reverse, false),
	    "legacy reverse CTKD must succeed");
	ATF_CHECK(reverse.has_ltk);

	/* A failed derivation must neither mark nor alter the destination LTK. */
	memset(reverse.ltk, 0x3c, sizeof(reverse.ltk));
	memcpy(untouched_ltk, reverse.ltk, sizeof(untouched_ltk));
	reverse.has_ltk = false;
	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ(-1, smp_ctkd_derive_ltk(&reverse, true));
	ATF_CHECK(!reverse.has_ltk);
	ATF_CHECK_EQ(memcmp(reverse.ltk, untouched_ltk,
	    sizeof(untouched_ltk)), 0);

	fault_reset();
	fi_EVP_MAC_final_at = 1;
	ATF_CHECK_EQ(-1, smp_ctkd_derive_ltk(&reverse, false));
	ATF_CHECK(!reverse.has_ltk);

	fault_reset();
	fi_EVP_MAC_final_at = 2;
	ATF_CHECK_EQ(-1, smp_ctkd_derive_ltk(&reverse, true));
	ATF_CHECK(!reverse.has_ltk);

	fault_reset();
	reverse.is_mitm = false;
	ATF_CHECK_EQ(0, smp_ctkd_derive_ltk(&reverse, true));
	ATF_CHECK(!reverse.has_ltk);

	reverse.is_mitm = true;
	reverse.is_sc = false;
	ATF_CHECK_EQ(-1, smp_ctkd_derive_ltk(&reverse, true));
	reverse.is_sc = true;
	reverse.has_link_key = false;
	ATF_CHECK_EQ(-1, smp_ctkd_derive_ltk(&reverse, true));
	ATF_CHECK(!reverse.has_ltk);

	blued_verbose = 0;
}

/* ================================================================
 * smp_rpa_matches / smp_generate_rpa -- Core Spec Vol 3 Part H 2.2.2.
 * smp_rpa_matches contract: returns false on any failure (fail closed).
 * smp_generate_rpa contract: returns 0 on success, -1 on E() failure,
 * and must NOT emit a predictable all-zero RPA -- it leaves the caller's
 * buffer untouched so the caller aborts the rotation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpa_faults);
ATF_TC_BODY(rpa_faults, tc)
{
	uint8_t rpa[6];
	static const uint8_t untouched[6] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
	};
	static const uint8_t zero6[6] = { 0 };
	uint8_t addr[6];

	/* Build a well-formed RPA (top two bits of addr[5] == 01) whose hash
	 * matches irk k16, so the baseline resolves true. */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_generate_rpa(k16, addr));
	ATF_REQUIRE(smp_rpa_matches(k16, addr));

	/* smp_rpa_matches: E() failure -> false (smp_keys.c:334) */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	ATF_CHECK(!smp_rpa_matches(k16, addr));

	/*
	 * smp_generate_rpa: E() failure -> returns -1 and leaves the
	 * output buffer untouched (never a predictable all-zero RPA).
	 */
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	memset(rpa, 0xaa, sizeof(rpa));
	ATF_CHECK_EQ_MSG(-1, smp_generate_rpa(k16, rpa),
	    "smp_generate_rpa must report failure on E() failure");
	ATF_CHECK_EQ_MSG(0, memcmp(rpa, untouched, 6),
	    "smp_generate_rpa must not overwrite the RPA on E() failure");
	ATF_CHECK_MSG(memcmp(rpa, zero6, 6) != 0,
	    "smp_generate_rpa must never emit an all-zero RPA");
}

/* ================================================================
 * smp_verify_signature -- Core Spec Vol 3 Part H 2.4.5.
 * Contract (smp.h): returns bool; false on failure.  The malloc arm
 * (smp_crypto.c:535) and the CMAC-failure arm both return false.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(verify_signature_faults);
ATF_TC_BODY(verify_signature_faults, tc)
{
	const uint8_t msg[4] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t mac8[8] = { 0 };

	/* malloc(msg_len + 4) == NULL -> false (smp_crypto.c:534) */
	fault_reset();
	fi_malloc_at = 1;
	ATF_CHECK(!smp_verify_signature(k16, msg, sizeof(msg), mac8, 0));

	/* CMAC failure inside -> rc != 0 -> false (smp_crypto.c:554) */
	fault_reset();
	fi_EVP_MAC_init_at = 1;
	ATF_CHECK(!smp_verify_signature(k16, msg, sizeof(msg), mac8, 0));
}

/* ================================================================
 * Bond DB save/load helpers
 * ================================================================ */
static struct smp_bond_db	g_db;	/* large; keep off the stack */

struct bond_fixture {
	char	dir[64];
	char	path[96];
	int	dir_fd;
	int	fd;
};

static void
bond_fixture_init(struct bond_fixture *fixture)
{

	memset(fixture, 0, sizeof(*fixture));
	strlcpy(fixture->dir, "/tmp/blued_fault_bond.XXXXXX",
	    sizeof(fixture->dir));
	ATF_REQUIRE(mkdtemp(fixture->dir) != NULL);
	ATF_REQUIRE(snprintf(fixture->path, sizeof(fixture->path),
	    "%s/bonds", fixture->dir) > 0);
	fixture->dir_fd = open(fixture->dir,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fixture->dir_fd >= 0);
	fixture->fd = open(fixture->path,
	    O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ATF_REQUIRE(fixture->fd >= 0);
}

static void
bond_fixture_fini(struct bond_fixture *fixture)
{
	char key_path[sizeof(fixture->path) + sizeof(".key")];

	close(fixture->fd);
	close(fixture->dir_fd);
	unlink(fixture->path);
	ATF_REQUIRE(snprintf(key_path, sizeof(key_path), "%s.key",
	    fixture->path) > 0);
	unlink(key_path);
	rmdir(fixture->dir);
}

static void
db_init(struct smp_bond_db *db, const struct bond_fixture *fixture)
{

	memset(db, 0, sizeof(*db));
	db->fd = fixture->fd;
	db->lock = NULL;
	smp_bond_db_set_atomic(db, fixture->dir_fd, fixture->path);
	db->count = 1;
	db->has_local_irk = true;
	memcpy(db->local_irk, k16, 16);
	memset(db->bonds[0].addr, 0x42, 6);
	db->bonds[0].addr_type = 1;
	db->bonds[0].has_ltk = true;
	memcpy(db->bonds[0].ltk, r16, 16);
}

/* ================================================================
 * smp_bond_db_save -- smp.h: returns 0 on success, -1 on failure.
 * Every failure arm returns -1 AND preserves the prior on-disk file
 * (never writes plaintext).  We fault each allocator / OpenSSL step.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bond_save_faults);
ATF_TC_BODY(bond_save_faults, tc)
{
	struct bond_fixture fixture;

	bond_fixture_init(&fixture);
	db_init(&g_db, &fixture);

	/* Baseline: a healthy save creates and uses its sibling secret. */
	fault_reset();
	ATF_REQUIRE_EQ(0, smp_bond_db_save(&g_db));

	/* EINTR before lock acquisition is retried, never treated as success. */
	fault_reset();
	fi_flock_at = 1;
	fi_flock_errno = EINTR;
	ATF_CHECK_EQ(0, smp_bond_db_save(&g_db));

	/* Any non-retryable lock failure aborts before encryption or writing. */
	fault_reset();
	fi_flock_at = 1;
	fi_flock_errno = EIO;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));
	ATF_CHECK_EQ(0, fi_RAND_bytes_n);

	/* RAND_bytes for the PBKDF2 salt fails (smp_keys.c:1420) */
	fault_reset();
	fi_RAND_bytes_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* RAND_bytes for the GCM IV fails (2nd RAND call, smp_keys.c:1482) */
	fault_reset();
	fi_RAND_bytes_at = 2;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* PKCS5_PBKDF2_HMAC fails in bond_db_derive_key (smp_keys.c:684)
	 * -> refuse to save (BLUED_LOG_SECURITY) -> -1 */
	fault_reset();
	fi_PKCS5_PBKDF2_HMAC_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* malloc of the plaintext payload fails (smp_keys.c:1455) */
	fault_reset();
	fi_malloc_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* 2nd malloc = ciphertext buffer in bond_db_encrypt (smp_keys.c:707) */
	fault_reset();
	fi_malloc_at = 2;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* EVP_EncryptInit_ex in bond_db_encrypt (smp_keys.c:717) */
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* EVP_EncryptUpdate (smp_keys.c:721) */
	fault_reset();
	fi_EVP_EncryptUpdate_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* EVP_EncryptFinal_ex (smp_keys.c:725) */
	fault_reset();
	fi_EVP_EncryptFinal_ex_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* EVP_CIPHER_CTX_ctrl GET_TAG (smp_keys.c:729) */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	/* EVP_CIPHER_CTX_new NULL in bond_db_encrypt (smp_keys.c:712) */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	ATF_CHECK_EQ(-1, smp_bond_db_save(&g_db));

	bond_fixture_fini(&fixture);
}

ATF_TC_WITHOUT_HEAD(bond_postrename_failure_retains_state);
ATF_TC_BODY(bond_postrename_failure_retains_state, tc)
{
	struct bond_fixture fixture;
	struct smp_bond_db loaded;
	struct smp_bond b;
	int fd;

	bond_fixture_init(&fixture);
	db_init(&g_db, &fixture);
	ATF_REQUIRE_EQ(0, smp_bond_db_save(&g_db));
	b = g_db.bonds[0];
	b.addr[0] ^= 0x7f;
	fault_reset();
	fi_fsync_at = 2; /* staged file succeeds; directory fsync fails */
	ATF_CHECK_EQ(-1, smp_bond_db_store(&g_db, &b));
	ATF_CHECK_EQ(2, g_db.count); /* rename committed: do not roll back */

	fd = open(fixture.path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	memset(&loaded, 0, sizeof(loaded));
	smp_bond_db_set_atomic(&loaded, fixture.dir_fd, fixture.path);
	ATF_REQUIRE_EQ(0, smp_bond_db_load(&loaded, fd));
	ATF_CHECK_EQ(2, loaded.count);
	close(fd);
	bond_fixture_fini(&fixture);
}

/*
 * Write a valid v4 (AES-256-GCM + random salt) bond file to fd via a healthy
 * save.  Returns true, or false (and marks skip) if key material is absent.
 */
static bool
seed_valid_bondfile(struct bond_fixture *fixture)
{

	db_init(&g_db, fixture);
	fault_reset();
	if (smp_bond_db_save(&g_db) != 0) {
		atf_tc_skip("environment lacks key material for bond DB");
		return (false);
	}
	return (true);
}

ATF_TC_WITHOUT_HEAD(bond_load_lock_retry);
ATF_TC_BODY(bond_load_lock_retry, tc)
{
	struct bond_fixture fixture;

	bond_fixture_init(&fixture);
	ATF_REQUIRE(seed_valid_bondfile(&fixture));
	db_init(&g_db, &fixture);
	fault_reset();
	fi_flock_at = 1;
	fi_flock_errno = EINTR;
	ATF_CHECK_EQ(0, smp_bond_db_load(&g_db, fixture.fd));
	ATF_CHECK_EQ(1, g_db.count);
	bond_fixture_fini(&fixture);
}

/* ================================================================
 * smp_bond_db_load contracts (smp_keys.c:874):
 *   - malloc(ct) == NULL is a hard error -> returns -1.
 *   - decrypt / key-derivation failure fails closed with -1 and leaves
 *     db->count == 0; callers must not overwrite unverifiable key state.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(bond_load_malloc_fault);
ATF_TC_BODY(bond_load_malloc_fault, tc)
{
	struct bond_fixture fixture;
	int rc;

	bond_fixture_init(&fixture);
	if (!seed_valid_bondfile(&fixture)) {
		bond_fixture_fini(&fixture);
		return;
	}

	/* malloc(ct_len) for the ciphertext buffer fails (smp_keys.c:983).
	 * This is the hard-error arm: returns -1. */
	fault_reset();
	fi_malloc_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;		/* sentinel */
	rc = smp_bond_db_load(&g_db, fixture.fd);
	ATF_CHECK_EQ(-1, rc);

	bond_fixture_fini(&fixture);
}

ATF_TC_WITHOUT_HEAD(bond_load_reject_faults);
ATF_TC_BODY(bond_load_reject_faults, tc)
{
	struct bond_fixture fixture;
	int rc;

	bond_fixture_init(&fixture);
	if (!seed_valid_bondfile(&fixture)) {
		bond_fixture_fini(&fixture);
		return;
	}

	/* GCM tag mismatch simulated via EVP_DecryptFinal_ex == 0
	 * (smp_keys.c:791 -> bond_db_decrypt returns -1 -> load rejects). */
	fault_reset();
	fi_EVP_DecryptFinal_ex_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	rc = smp_bond_db_load(&g_db, fixture.fd);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ_MSG(0, g_db.count, "tag mismatch must reject all bonds");

	/* EVP_DecryptUpdate == 0 (smp_keys.c:781) */
	fault_reset();
	fi_EVP_DecryptUpdate_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	ATF_CHECK_EQ(-1, smp_bond_db_load(&g_db, fixture.fd));
	ATF_CHECK_EQ(0, g_db.count);

	/* EVP_DecryptInit_ex == 0 (smp_keys.c:777) */
	fault_reset();
	fi_EVP_DecryptInit_ex_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	ATF_CHECK_EQ(-1, smp_bond_db_load(&g_db, fixture.fd));
	ATF_CHECK_EQ(0, g_db.count);

	/* EVP_CIPHER_CTX_ctrl SET_TAG == 0 (smp_keys.c:786) */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	ATF_CHECK_EQ(-1, smp_bond_db_load(&g_db, fixture.fd));
	ATF_CHECK_EQ(0, g_db.count);

	/* Key derivation (PKCS5_PBKDF2_HMAC) fails during load
	 * (smp_keys.c:1000) -> bonds inaccessible -> reject, return 0. */
	fault_reset();
	fi_PKCS5_PBKDF2_HMAC_at = 1;
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	rc = smp_bond_db_load(&g_db, fixture.fd);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ(0, g_db.count);

	bond_fixture_fini(&fixture);
}

/*
 * Natural (un-wrapped) GCM authentication failure: flip one ciphertext byte
 * on disk and confirm the real EVP_DecryptFinal_ex tag check rejects it.
 * Proves the wrapped arm above matches genuine tamper behaviour.
 */
ATF_TC_WITHOUT_HEAD(bond_load_real_tamper);
ATF_TC_BODY(bond_load_real_tamper, tc)
{
	struct bond_fixture fixture;
	int rc;
	uint8_t byte;
	off_t ctoff;

	bond_fixture_init(&fixture);
	if (!seed_valid_bondfile(&fixture)) {
		bond_fixture_fini(&fixture);
		return;
	}

	/* v4 layout: 5 magic + 4 ver + 16 salt + 12 iv + 16 tag + 4 len,
	 * then ciphertext.  Flip the first ciphertext byte. */
	ctoff = 5 + 4 + 16 + 12 + 16 + 4;
	ATF_REQUIRE_EQ(1, pread(fixture.fd, &byte, 1, ctoff));
	byte ^= 0xff;
	ATF_REQUIRE_EQ(1, pwrite(fixture.fd, &byte, 1, ctoff));

	fault_reset();
	memset(&g_db, 0, sizeof(g_db));
	g_db.count = 99;
	rc = smp_bond_db_load(&g_db, fixture.fd);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ_MSG(0, g_db.count,
	    "real GCM tag mismatch must reject all bonds");

	bond_fixture_fini(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, aes128_faults);
	ATF_TP_ADD_TC(tp, aes_cmac_faults);
	ATF_TP_ADD_TC(tp, c1_s1_faults);
	ATF_TP_ADD_TC(tp, validate_pubkey_faults);
	ATF_TP_ADD_TC(tp, sc_void_helpers_swallow_cmac_failure);
	ATF_TP_ADD_TC(tp, sc_ephemeral_and_oob_faults);
	ATF_TP_ADD_TC(tp, sc_peer_key_and_derive_faults);
	ATF_TP_ADD_TC(tp, sc_stage_crypto_faults);
	ATF_TP_ADD_TC(tp, sc_all_roles_local_key_faults);
	ATF_TP_ADD_TC(tp, sc_all_roles_peer_key_validation_faults);
	ATF_TP_ADD_TC(tp, f5_late_cmac_faults);
	ATF_TP_ADD_TC(tp, ctkd_derive_faults);
	ATF_TP_ADD_TC(tp, rpa_faults);
	ATF_TP_ADD_TC(tp, verify_signature_faults);
	ATF_TP_ADD_TC(tp, bond_save_faults);
	ATF_TP_ADD_TC(tp, bond_postrename_failure_retains_state);
	ATF_TP_ADD_TC(tp, bond_load_lock_retry);
	ATF_TP_ADD_TC(tp, bond_load_malloc_fault);
	ATF_TP_ADD_TC(tp, bond_load_reject_faults);
	ATF_TP_ADD_TC(tp, bond_load_real_tamper);

	return (atf_no_error());
}
