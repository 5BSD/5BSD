/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the OpenSSL FAILURE arms of the Bluetooth
 * Mesh security toolbox (mesh_crypto.c, MshPRT_v1.1 Section 3.8).
 *
 * Every "if (EVP_... <= 0) { warnx(); ... return (-1); }" arm in
 * mesh_aes128_e / mesh_aes_cmac / s1 / k1 / k2 / k3 / k4 and the AES-CCM
 * encrypt/decrypt paths handles a real EVP primitive failure, but on the
 * valid, bounded inputs these functions receive the underlying OpenSSL call
 * never fails, so those branches are unreachable by ordinary use.  We reach
 * them with a linker --wrap(3) seam: each wrapped EVP symbol has a
 * __wrap_<sym> that consults a test-settable "fail the Nth call" counter and
 * otherwise tail-calls __real_<sym>.  Because --wrap only intercepts
 * references emitted from the objects linked here (mesh_crypto.c and this
 * test), the counters see exactly mesh_crypto.c's own EVP calls.
 *
 * Oracle: mesh_crypto.h's documented contract -- every function returns -1
 * on any primitive failure and leaves its output buffer zeroed.  The spec
 * KAT success values live in mesh_crypto_test.c; here we assert only the
 * documented failure contract (return -1, output zeroed).  This mirrors the
 * smp_fault_test / mesh_sim_fault_test --wrap seams.
 *
 * Requires the parent Makefile to wrap the symbols (LDFLAGS):
 *   -Wl,--wrap=EVP_CIPHER_CTX_new -Wl,--wrap=EVP_CIPHER_CTX_ctrl
 *   -Wl,--wrap=EVP_EncryptInit_ex -Wl,--wrap=EVP_EncryptUpdate
 *   -Wl,--wrap=EVP_EncryptFinal_ex -Wl,--wrap=EVP_DecryptInit_ex
 *   -Wl,--wrap=EVP_DecryptUpdate -Wl,--wrap=EVP_MAC_fetch
 *   -Wl,--wrap=EVP_MAC_CTX_new -Wl,--wrap=EVP_MAC_init
 *   -Wl,--wrap=EVP_MAC_update -Wl,--wrap=EVP_MAC_final
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "mesh_crypto.h"
#include "spec_oracles.h"

/* ================================================================
 * Fault-injection seam: fail the Nth (1-based) call to a wrapped symbol.
 * ================================================================ */
static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

#define FI(sym)		static long fi_##sym##_at, fi_##sym##_n;

FI(EVP_CIPHER_CTX_new)
FI(EVP_CIPHER_CTX_ctrl)
FI(EVP_EncryptInit_ex)
FI(EVP_EncryptUpdate)
FI(EVP_EncryptFinal_ex)
FI(EVP_DecryptInit_ex)
FI(EVP_DecryptUpdate)
FI(EVP_MAC_fetch)
FI(EVP_MAC_CTX_new)
FI(EVP_MAC_init)
FI(EVP_MAC_update)
FI(EVP_MAC_final)

static void
fault_reset(void)
{

#define Z(sym)	do { fi_##sym##_at = 0; fi_##sym##_n = 0; } while (0)
	Z(EVP_CIPHER_CTX_new);
	Z(EVP_CIPHER_CTX_ctrl);
	Z(EVP_EncryptInit_ex);
	Z(EVP_EncryptUpdate);
	Z(EVP_EncryptFinal_ex);
	Z(EVP_DecryptInit_ex);
	Z(EVP_DecryptUpdate);
	Z(EVP_MAC_fetch);
	Z(EVP_MAC_CTX_new);
	Z(EVP_MAC_init);
	Z(EVP_MAC_update);
	Z(EVP_MAC_final);
#undef Z
}

/* ---- EVP cipher (e() ECB and AES-CCM) ---- */
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

/* ---- EVP_MAC (CMAC, used by s1/k1/k2/k3/k4) ---- */
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

/*
 * FIPS 197 Appendix B key/block-shaped inputs.  Their byte values are merely
 * non-normative sentinels in this fault suite; successful cryptographic KATs
 * are independently checked by mesh_crypto_test.c.
 */
static const uint8_t KEY[BT_AES128_KEY_BLOCK_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t BLK[BT_AES128_KEY_BLOCK_SIZE] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static int
all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

/* Non-normative lengths chosen only to exercise non-empty fault paths. */
#define TEST_CCM_PAYLOAD_SIZE	13
#define TEST_CCM_AAD_SIZE	4

static void
expect_ccm_encrypt_failure(const uint8_t nonce[BT_MSHPRT11_NONCE_SIZE],
    const uint8_t *aad, size_t aadlen, const uint8_t *plain, size_t plen)
{
	uint8_t cipher[TEST_CCM_PAYLOAD_SIZE];
	uint8_t mic[BT_MSHPRT11_MIC64_SIZE];

	ATF_REQUIRE(plen <= sizeof(cipher));
	memset(cipher, 0xa5, sizeof(cipher));
	memset(mic, 0xa5, sizeof(mic));
	ATF_CHECK_EQ(-1, mesh_aes_ccm_encrypt(KEY, nonce, aad, aadlen, plain,
	    plen, cipher, mic, BT_MSHPRT11_MIC64_SIZE));
	ATF_CHECK(all_zero(cipher, plen));
	ATF_CHECK(all_zero(mic, BT_MSHPRT11_MIC64_SIZE));
}

static void
expect_ccm_decrypt_failure(const uint8_t nonce[BT_MSHPRT11_NONCE_SIZE],
    const uint8_t *aad, size_t aadlen, const uint8_t *cipher, size_t clen,
    const uint8_t mic[BT_MSHPRT11_MIC64_SIZE])
{
	uint8_t plain[TEST_CCM_PAYLOAD_SIZE];

	ATF_REQUIRE(clen <= sizeof(plain));
	memset(plain, 0xa5, sizeof(plain));
	ATF_CHECK_EQ(-1, mesh_aes_ccm_decrypt(KEY, nonce, aad, aadlen, cipher,
	    clen, plain, mic, BT_MSHPRT11_MIC64_SIZE));
	ATF_CHECK(all_zero(plain, clen));
}

/* ================================================================
 * mesh_aes128_e(): every EVP cipher failure arm returns -1, out zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_aes128_e);
ATF_TC_BODY(fault_aes128_e, tc)
{
	uint8_t out[BT_AES128_KEY_BLOCK_SIZE];

	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	memset(out, 0xa5, sizeof(out));
	ATF_CHECK_EQ(-1, mesh_aes128_e(KEY, BLK, out));
	ATF_CHECK(all_zero(out, BT_AES128_KEY_BLOCK_SIZE));

	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	memset(out, 0xa5, sizeof(out));
	ATF_CHECK_EQ(-1, mesh_aes128_e(KEY, BLK, out));
	ATF_CHECK(all_zero(out, BT_AES128_KEY_BLOCK_SIZE));

	fault_reset();
	fi_EVP_EncryptUpdate_at = 1;
	memset(out, 0xa5, sizeof(out));
	ATF_CHECK_EQ(-1, mesh_aes128_e(KEY, BLK, out));
	ATF_CHECK(all_zero(out, BT_AES128_KEY_BLOCK_SIZE));

	/* Sanity: unarmed, e() succeeds. */
	fault_reset();
	ATF_CHECK_EQ(0, mesh_aes128_e(KEY, BLK, out));
}

/* ================================================================
 * mesh_aes_cmac(): every EVP_MAC failure arm returns -1, mac zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_cmac);
ATF_TC_BODY(fault_cmac, tc)
{
	uint8_t mac[BT_AES_CMAC_SIZE];

	fault_reset();
	fi_EVP_MAC_fetch_at = 1;
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_aes_cmac(KEY, BLK, sizeof(BLK), mac));
	ATF_CHECK(all_zero(mac, BT_AES_CMAC_SIZE));

	fault_reset();
	fi_EVP_MAC_CTX_new_at = 1;
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_aes_cmac(KEY, BLK, sizeof(BLK), mac));
	ATF_CHECK(all_zero(mac, BT_AES_CMAC_SIZE));

	fault_reset();
	fi_EVP_MAC_init_at = 1;
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_aes_cmac(KEY, BLK, sizeof(BLK), mac));
	ATF_CHECK(all_zero(mac, BT_AES_CMAC_SIZE));

	/* MAC_update is only called for len != 0. */
	fault_reset();
	fi_EVP_MAC_update_at = 1;
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_aes_cmac(KEY, BLK, sizeof(BLK), mac));
	ATF_CHECK(all_zero(mac, BT_AES_CMAC_SIZE));

	fault_reset();
	fi_EVP_MAC_final_at = 1;
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_aes_cmac(KEY, BLK, sizeof(BLK), mac));
	ATF_CHECK(all_zero(mac, BT_AES_CMAC_SIZE));
}

/* ================================================================
 * s1/k1/k2/k3/k4: the propagated "AES-CMAC failed" arms.  Each mesh_aes_cmac
 * issues exactly one EVP_MAC_init, so failing EVP_MAC_init at ordinal N fails
 * the Nth CMAC in the derivation, driving that step's error branch.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_kdf);
ATF_TC_BODY(fault_kdf, tc)
{
	uint8_t out[BT_AES_CMAC_SIZE], nid;
	uint8_t enc[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t priv[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t out8[BT_MSHPRT11_K3_NETWORK_ID_SIZE], aid;
	uint8_t salt[BT_AES_CMAC_SIZE];
	uint8_t p[1] = { 0x00 };
	int i;

	/* Fault ordinals and poison bytes are implementation-only sentinels. */

	/* s1: single CMAC. */
	fault_reset();
	fi_EVP_MAC_init_at = 1;
	memset(salt, 0xa5, sizeof(salt));
	ATF_CHECK_EQ(-1, mesh_s1((const uint8_t *)"test", 4, salt));
	ATF_CHECK(all_zero(salt, BT_AES_CMAC_SIZE));

	/* k1: CMAC #1 = AES-CMAC(SALT, N), CMAC #2 = AES-CMAC(T, P). */
	for (i = 1; i <= 2; i++) {
		fault_reset();
		fi_EVP_MAC_init_at = i;
		memset(out, 0xa5, sizeof(out));
		ATF_CHECK_EQ(-1, mesh_k1(KEY, sizeof(KEY), salt, BLK,
		    sizeof(BLK), out));
		ATF_CHECK(all_zero(out, BT_AES_CMAC_SIZE));
	}

	/* k2: CMAC #1 s1, #2 T, #3..#5 T1/T2/T3. */
	for (i = 1; i <= 5; i++) {
		fault_reset();
		fi_EVP_MAC_init_at = i;
		memset(enc, 0xa5, sizeof(enc));
		memset(priv, 0xa5, sizeof(priv));
		nid = 0xff;
		ATF_CHECK_EQ(-1, mesh_k2(KEY, p, 1, &nid, enc, priv));
		ATF_CHECK_EQ(0, nid);
		ATF_CHECK(all_zero(enc, BT_AES128_KEY_BLOCK_SIZE));
		ATF_CHECK(all_zero(priv, BT_AES128_KEY_BLOCK_SIZE));
	}

	/* k3: CMAC #1 s1, #2 T, #3 id64. */
	for (i = 1; i <= 3; i++) {
		fault_reset();
		fi_EVP_MAC_init_at = i;
		memset(out8, 0xa5, sizeof(out8));
		ATF_CHECK_EQ(-1, mesh_k3(KEY, out8));
		ATF_CHECK(all_zero(out8, BT_MSHPRT11_K3_NETWORK_ID_SIZE));
	}

	/* k4: CMAC #1 s1, #2 T, #3 id6. */
	for (i = 1; i <= 3; i++) {
		fault_reset();
		fi_EVP_MAC_init_at = i;
		aid = 0xff;
		ATF_CHECK_EQ(-1, mesh_k4(KEY, &aid));
		ATF_CHECK_EQ(0, aid);
	}
}

/* ================================================================
 * mesh_aes_ccm_encrypt(): every EVP failure arm returns -1 (cipher/mic
 * zeroed), including the AAD-processing arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_ccm_encrypt);
ATF_TC_BODY(fault_ccm_encrypt, tc)
{
	uint8_t nonce[BT_MSHPRT11_NONCE_SIZE] = { 0 };
	uint8_t plain[TEST_CCM_PAYLOAD_SIZE];
	uint8_t aad[TEST_CCM_AAD_SIZE] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t cipher[TEST_CCM_PAYLOAD_SIZE];
	uint8_t mic[BT_MSHPRT11_MIC64_SIZE];

	memset(plain, 0x11, sizeof(plain));

	/* CTX_new. */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* EncryptInit_ex #1 (cipher). */
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* ctrl #1 (SET_IVLEN). */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* ctrl #2 (SET_TAG). */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 2;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* EncryptInit_ex #2 (key/nonce). */
	fault_reset();
	fi_EVP_EncryptInit_ex_at = 2;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* EncryptUpdate (cipher, no AAD). */
	fault_reset();
	fi_EVP_EncryptUpdate_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* EncryptFinal_ex. */
	fault_reset();
	fi_EVP_EncryptFinal_ex_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* ctrl #3 (GET_TAG): IVLEN(1), SET_TAG(2), GET_TAG(3) with no AAD. */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 3;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, sizeof(plain));

	/* AAD path: first EncryptUpdate (total length) fails. */
	fault_reset();
	fi_EVP_EncryptUpdate_at = 1;
	expect_ccm_encrypt_failure(nonce, aad, sizeof(aad), plain,
	    sizeof(plain));

	/* AAD path: second EncryptUpdate (the AAD itself) fails. */
	fault_reset();
	fi_EVP_EncryptUpdate_at = 2;
	expect_ccm_encrypt_failure(nonce, aad, sizeof(aad), plain,
	    sizeof(plain));

	/* Empty plaintext (plen == 0) on the failure path: only the MIC is
	 * zeroed (the "if (plen != 0)" guard's false arm). */
	fault_reset();
	fi_EVP_EncryptFinal_ex_at = 1;
	expect_ccm_encrypt_failure(nonce, NULL, 0, plain, 0);

	/* Sanity: unarmed with AAD succeeds and round-trips. */
	fault_reset();
	ATF_CHECK_EQ(0, mesh_aes_ccm_encrypt(KEY, nonce, aad, sizeof(aad),
	    plain, sizeof(plain), cipher, mic, BT_MSHPRT11_MIC64_SIZE));
	{
		uint8_t back[TEST_CCM_PAYLOAD_SIZE];

		ATF_CHECK_EQ(0, mesh_aes_ccm_decrypt(KEY, nonce, aad,
		    sizeof(aad), cipher, sizeof(cipher), back, mic,
		    BT_MSHPRT11_MIC64_SIZE));
		ATF_CHECK_EQ(0, memcmp(back, plain, sizeof(plain)));
	}
}

/* ================================================================
 * mesh_aes_ccm_decrypt(): every EVP setup failure arm returns -1, plaintext
 * zeroed, including the AAD-processing arms.  (The MIC-verify failure of the
 * final EVP_DecryptUpdate is covered by the tamper KAT in mesh_crypto_test.)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_ccm_decrypt);
ATF_TC_BODY(fault_ccm_decrypt, tc)
{
	uint8_t nonce[BT_MSHPRT11_NONCE_SIZE] = { 0 };
	uint8_t plain[TEST_CCM_PAYLOAD_SIZE];
	uint8_t aad[TEST_CCM_AAD_SIZE] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t cipher[TEST_CCM_PAYLOAD_SIZE];
	uint8_t mic[BT_MSHPRT11_MIC64_SIZE];

	memset(plain, 0x11, sizeof(plain));

	/* Produce a valid (cipher, mic) with no AAD, and one with AAD. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(KEY, nonce, NULL, 0, plain,
	    sizeof(plain), cipher, mic, BT_MSHPRT11_MIC64_SIZE));

	/* CTX_new. */
	fault_reset();
	fi_EVP_CIPHER_CTX_new_at = 1;
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, sizeof(cipher), mic);

	/* DecryptInit_ex #1 (cipher). */
	fault_reset();
	fi_EVP_DecryptInit_ex_at = 1;
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, sizeof(cipher), mic);

	/* ctrl #1 (SET_IVLEN). */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 1;
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, sizeof(cipher), mic);

	/* ctrl #2 (SET_TAG). */
	fault_reset();
	fi_EVP_CIPHER_CTX_ctrl_at = 2;
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, sizeof(cipher), mic);

	/* DecryptInit_ex #2 (key/nonce). */
	fault_reset();
	fi_EVP_DecryptInit_ex_at = 2;
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, sizeof(cipher), mic);

	/* AAD path: a valid AAD-authenticated (cipher, mic). */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(KEY, nonce, aad, sizeof(aad),
	    plain, sizeof(plain), cipher, mic, BT_MSHPRT11_MIC64_SIZE));

	/* AAD path: first DecryptUpdate (total length) fails. */
	fault_reset();
	fi_EVP_DecryptUpdate_at = 1;
	expect_ccm_decrypt_failure(nonce, aad, sizeof(aad), cipher,
	    sizeof(cipher), mic);

	/* AAD path: second DecryptUpdate (the AAD itself) fails. */
	fault_reset();
	fi_EVP_DecryptUpdate_at = 2;
	expect_ccm_decrypt_failure(nonce, aad, sizeof(aad), cipher,
	    sizeof(cipher), mic);

	/* Empty ciphertext (clen == 0): the "if (clen != 0)" guards' false arms
	 * on both the fail: (setup error) and MIC-verify error paths. */
	fault_reset();
	fi_EVP_DecryptInit_ex_at = 1;		/* setup error -> fail: label */
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, 0, mic);

	fault_reset();
	fi_EVP_DecryptUpdate_at = 1;		/* MIC-verify update returns <= 0 */
	expect_ccm_decrypt_failure(nonce, NULL, 0, cipher, 0, mic);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_aes128_e);
	ATF_TP_ADD_TC(tp, fault_cmac);
	ATF_TP_ADD_TC(tp, fault_kdf);
	ATF_TP_ADD_TC(tp, fault_ccm_encrypt);
	ATF_TP_ADD_TC(tp, fault_ccm_decrypt);

	return (atf_no_error());
}
