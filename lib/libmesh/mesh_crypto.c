/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh security toolbox.
 *
 * Implements the cryptographic primitives of the Bluetooth Mesh
 * Protocol specification (MshPRT_v1.1) Section 3.8 "Mesh security":
 *
 *   - e()  : AES-128-ECB single block
 *   - AES-CMAC (RFC 4493) via OpenSSL EVP_MAC
 *   - s1, k1, k2, k3, k4 derivation functions
 *   - AES-128-CCM with a 32-bit or 64-bit MIC
 *   - the network / application / device / proxy nonce builders
 *
 * The Mesh functions operate on values in network (big-endian) byte
 * order, so - unlike the legacy SMP e() function - no byte reversal is
 * performed.  All secrets computed on the stack are cleared with
 * explicit_bzero() before return.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "mesh_crypto.h"

/*
 * AES-128 block cipher e(): out = AES-128-ECB(key, in).
 * MshPRT_v1.1 Section 3.8.2.1.
 */
int
mesh_aes128_e(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	EVP_CIPHER_CTX *ctx;
	int outl;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		warnx("EVP_CIPHER_CTX_new failed");
		memset(out, 0, 16);
		return (-1);
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) <= 0) {
		warnx("EVP_EncryptInit_ex failed");
		EVP_CIPHER_CTX_free(ctx);
		memset(out, 0, 16);
		return (-1);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (EVP_EncryptUpdate(ctx, out, &outl, in, 16) <= 0) {
		warnx("EVP_EncryptUpdate failed");
		EVP_CIPHER_CTX_free(ctx);
		memset(out, 0, 16);
		return (-1);
	}
	EVP_CIPHER_CTX_free(ctx);
	return (0);
}

/*
 * AES-CMAC per RFC 4493.
 * MshPRT_v1.1 Section 3.8.2.2.
 *
 * Key and message are consumed in network byte order (no reversal).
 */
int
mesh_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
    uint8_t mac[16])
{
	EVP_MAC *cmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen;

	static char cipher_name[] = "AES-128-CBC";

	cmac_type = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (cmac_type == NULL) {
		warnx("EVP_MAC_fetch failed");
		memset(mac, 0, 16);
		return (-1);
	}
	ctx = EVP_MAC_CTX_new(cmac_type);
	if (ctx == NULL) {
		warnx("EVP_MAC_CTX_new failed");
		memset(mac, 0, 16);
		EVP_MAC_free(cmac_type);
		return (-1);
	}
	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(ctx, key, 16, params) <= 0) {
		warnx("EVP_MAC_init failed");
		goto cmac_fail;
	}
	if (len != 0 && EVP_MAC_update(ctx, msg, len) <= 0) {
		warnx("EVP_MAC_update failed");
		goto cmac_fail;
	}
	outlen = 16;
	if (EVP_MAC_final(ctx, mac, &outlen, 16) <= 0) {
		warnx("EVP_MAC_final failed");
		goto cmac_fail;
	}
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
	return (0);

cmac_fail:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);
	memset(mac, 0, 16);
	return (-1);
}

/*
 * HMAC-SHA-256 (FIPS 198-1 / RFC 2104).
 * MshPRT_v1.1 Section 3.8.2.3 (the HMAC-SHA-256 primitive introduced for
 * the BTM_ECDH_P256_HMAC_SHA256_AES_CCM provisioning algorithm).
 *
 * Key and message are consumed in network byte order (no reversal); the
 * 32-octet MAC is written to mac.
 */
int
mesh_hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg,
    size_t len, uint8_t mac[32])
{
	EVP_MAC *hmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen;

	static char digest_name[] = "SHA256";

	if (key == NULL || (len != 0 && msg == NULL)) {
		memset(mac, 0, 32);
		return (-1);
	}
	hmac_type = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (hmac_type == NULL) {
		warnx("EVP_MAC_fetch failed");
		memset(mac, 0, 32);
		return (-1);
	}
	ctx = EVP_MAC_CTX_new(hmac_type);
	if (ctx == NULL) {
		warnx("EVP_MAC_CTX_new failed");
		memset(mac, 0, 32);
		EVP_MAC_free(hmac_type);
		return (-1);
	}
	params[0] = OSSL_PARAM_construct_utf8_string("digest", digest_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(ctx, key, keylen, params) <= 0) {
		warnx("EVP_MAC_init failed");
		goto hmac_fail;
	}
	if (len != 0 && EVP_MAC_update(ctx, msg, len) <= 0) {
		warnx("EVP_MAC_update failed");
		goto hmac_fail;
	}
	outlen = 32;
	if (EVP_MAC_final(ctx, mac, &outlen, 32) <= 0 || outlen != 32) {
		warnx("EVP_MAC_final failed");
		goto hmac_fail;
	}
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(hmac_type);
	return (0);

hmac_fail:
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(hmac_type);
	memset(mac, 0, 32);
	return (-1);
}

/*
 * s1 SALT generation: s1(M) = AES-CMAC_ZERO(M).
 * MshPRT_v1.1 Section 3.8.2.4.
 */
int
mesh_s1(const uint8_t *m, size_t len, uint8_t salt[16])
{
	static const uint8_t zero[16] = { 0 };

	return (mesh_aes_cmac(zero, m, len, salt));
}

/*
 * k1 derivation: k1(N, SALT, P) = AES-CMAC_T(P), T = AES-CMAC_SALT(N).
 * MshPRT_v1.1 Section 3.8.2.5.
 */
int
mesh_k1(const uint8_t *n, size_t nlen, const uint8_t salt[16],
    const uint8_t *p, size_t plen, uint8_t out[16])
{
	uint8_t t[16];
	int rc;

	if (mesh_aes_cmac(salt, n, nlen, t) != 0) {
		memset(out, 0, 16);
		return (-1);
	}
	rc = mesh_aes_cmac(t, p, plen, out);
	explicit_bzero(t, sizeof(t));
	return (rc);
}

/*
 * s2 SALT generation: s2(M) = HMAC-SHA-256_ZERO(M), ZERO = 32 octets of
 * 0x00.  MshPRT_v1.1 Section 3.8.2.5.  Used by the HMAC-SHA-256
 * provisioning algorithm's ConfirmationSalt.
 */
int
mesh_s2(const uint8_t *m, size_t len, uint8_t salt[32])
{
	static const uint8_t zero[32] = { 0 };

	return (mesh_hmac_sha256(zero, sizeof(zero), m, len, salt));
}

/*
 * k5 derivation: k5(N, SALT, P) = HMAC-SHA-256_T(P), T = HMAC-SHA-256_SALT(N).
 * MshPRT_v1.1 Section 3.8.2.9.  Produces a 32-octet key; used by the
 * HMAC-SHA-256 provisioning algorithm's ConfirmationKey.
 */
int
mesh_k5(const uint8_t *n, size_t nlen, const uint8_t salt[32],
    const uint8_t *p, size_t plen, uint8_t out[32])
{
	uint8_t t[32];
	int rc;

	if (mesh_hmac_sha256(salt, 32, n, nlen, t) != 0) {
		memset(out, 0, 32);
		return (-1);
	}
	rc = mesh_hmac_sha256(t, sizeof(t), p, plen, out);
	explicit_bzero(t, sizeof(t));
	return (rc);
}

/*
 * k2 network key material derivation.
 * MshPRT_v1.1 Section 3.8.2.6:
 *
 *   SALT = s1("smk2")
 *   T    = AES-CMAC_SALT(N)
 *   T1   = AES-CMAC_T(T0 || P || 0x01),  T0 = empty
 *   T2   = AES-CMAC_T(T1 || P || 0x02)
 *   T3   = AES-CMAC_T(T2 || P || 0x03)
 *   k2   = (T1 || T2 || T3) mod 2^263
 *
 * NID          = least significant 7 bits of T1
 * EncryptionKey = T2
 * PrivacyKey    = T3
 *
 * Note that P is appended in every iteration.
 */
int
mesh_k2(const uint8_t netkey[16], const uint8_t *p, size_t plen,
    uint8_t out_nid[1], uint8_t out_enckey[16], uint8_t out_privkey[16])
{
	static const char smk2[] = "smk2";
	uint8_t salt[16], t[16];
	uint8_t t1[16], t2[16], t3[16];
	uint8_t msg[16 + MESH_K2_MAX_P + 1];
	int rc = -1;

	if (p == NULL || plen > MESH_K2_MAX_P)
		goto out_zero;

	if (mesh_s1((const uint8_t *)smk2, sizeof(smk2) - 1, salt) != 0)
		goto out;
	if (mesh_aes_cmac(salt, netkey, 16, t) != 0)
		goto out;

	/* T1 = AES-CMAC_T(P || 0x01) */
	memcpy(msg, p, plen);
	msg[plen] = 0x01;
	if (mesh_aes_cmac(t, msg, plen + 1, t1) != 0)
		goto out;

	/* T2 = AES-CMAC_T(T1 || P || 0x02) */
	memcpy(msg, t1, 16);
	memcpy(msg + 16, p, plen);
	msg[16 + plen] = 0x02;
	if (mesh_aes_cmac(t, msg, 16 + plen + 1, t2) != 0)
		goto out;

	/* T3 = AES-CMAC_T(T2 || P || 0x03) */
	memcpy(msg, t2, 16);
	memcpy(msg + 16, p, plen);
	msg[16 + plen] = 0x03;
	if (mesh_aes_cmac(t, msg, 16 + plen + 1, t3) != 0)
		goto out;

	out_nid[0] = t1[15] & 0x7f;
	memcpy(out_enckey, t2, 16);
	memcpy(out_privkey, t3, 16);
	rc = 0;

out:
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(t, sizeof(t));
	explicit_bzero(t1, sizeof(t1));
	explicit_bzero(t2, sizeof(t2));
	explicit_bzero(t3, sizeof(t3));
	explicit_bzero(msg, sizeof(msg));
	if (rc == 0)
		return (0);
out_zero:
	out_nid[0] = 0;
	memset(out_enckey, 0, 16);
	memset(out_privkey, 0, 16);
	return (-1);
}

/*
 * k3 derivation: 64-bit network identifier.
 * MshPRT_v1.1 Section 3.8.2.7:
 *
 *   SALT = s1("smk3")
 *   T    = AES-CMAC_SALT(N)
 *   k3   = AES-CMAC_T("id64" || 0x01) mod 2^64
 */
int
mesh_k3(const uint8_t netkey[16], uint8_t out[8])
{
	static const char smk3[] = "smk3";
	static const uint8_t id64[] = { 'i', 'd', '6', '4', 0x01 };
	uint8_t salt[16], t[16], mac[16];
	int rc = -1;

	if (mesh_s1((const uint8_t *)smk3, sizeof(smk3) - 1, salt) != 0)
		goto out;
	if (mesh_aes_cmac(salt, netkey, 16, t) != 0)
		goto out;
	if (mesh_aes_cmac(t, id64, sizeof(id64), mac) != 0)
		goto out;
	memcpy(out, mac + 8, 8);	/* least significant 64 bits */
	rc = 0;
out:
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(t, sizeof(t));
	explicit_bzero(mac, sizeof(mac));
	if (rc != 0)
		memset(out, 0, 8);
	return (rc);
}

/*
 * k4 derivation: 6-bit application key identifier (AID).
 * MshPRT_v1.1 Section 3.8.2.8:
 *
 *   SALT = s1("smk4")
 *   T    = AES-CMAC_SALT(N)
 *   k4   = AES-CMAC_T("id6" || 0x01) mod 2^6
 */
int
mesh_k4(const uint8_t appkey[16], uint8_t out_aid[1])
{
	static const char smk4[] = "smk4";
	static const uint8_t id6[] = { 'i', 'd', '6', 0x01 };
	uint8_t salt[16], t[16], mac[16];
	int rc = -1;

	if (mesh_s1((const uint8_t *)smk4, sizeof(smk4) - 1, salt) != 0)
		goto out;
	if (mesh_aes_cmac(salt, appkey, 16, t) != 0)
		goto out;
	if (mesh_aes_cmac(t, id6, sizeof(id6), mac) != 0)
		goto out;
	out_aid[0] = mac[15] & 0x3f;	/* least significant 6 bits */
	rc = 0;
out:
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(t, sizeof(t));
	explicit_bzero(mac, sizeof(mac));
	if (rc != 0)
		out_aid[0] = 0;
	return (rc);
}

/*
 * AES-128-CCM authenticated encryption.
 * MshPRT_v1.1 Section 3.8.2.3.
 *
 * nonce is 13 octets; miclen is 4 or 8.  cipher receives plen octets
 * and mic receives miclen octets.
 */
int
mesh_aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13],
    const uint8_t *aad, size_t aadlen,
    const uint8_t *plain, size_t plen,
    uint8_t *cipher, uint8_t *mic, size_t miclen)
{
	EVP_CIPHER_CTX *ctx;
	int outl;

	if (miclen != 4 && miclen != 8)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		warnx("EVP_CIPHER_CTX_new failed");
		if (plen != 0)
			memset(cipher, 0, plen);
		memset(mic, 0, miclen);
		return (-1);
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) <= 0)
		goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 13, NULL) <= 0)
		goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)miclen,
	    NULL) <= 0)
		goto fail;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
		goto fail;
	/*
	 * For CCM the total plaintext length must be supplied (output
	 * pointer NULL) before any AAD is passed.
	 */
	if (aadlen != 0) {
		if (EVP_EncryptUpdate(ctx, NULL, &outl, NULL, (int)plen) <= 0)
			goto fail;
		if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) <= 0)
			goto fail;
	}
	if (EVP_EncryptUpdate(ctx, cipher, &outl, plain, (int)plen) <= 0)
		goto fail;
	if (EVP_EncryptFinal_ex(ctx, cipher + outl, &outl) <= 0)
		goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)miclen,
	    mic) <= 0)
		goto fail;
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	warnx("mesh_aes_ccm_encrypt failed");
	EVP_CIPHER_CTX_free(ctx);
	if (plen != 0)
		memset(cipher, 0, plen);
	memset(mic, 0, miclen);
	return (-1);
}

/*
 * AES-128-CCM authenticated decryption.
 * MshPRT_v1.1 Section 3.8.2.3.
 *
 * Verifies the MIC.  Returns 0 only if the MIC is valid; on any error
 * or MIC mismatch returns -1 with the plaintext output zeroed.
 */
int
mesh_aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13],
    const uint8_t *aad, size_t aadlen,
    const uint8_t *cipher, size_t clen,
    uint8_t *plain, const uint8_t *mic, size_t miclen)
{
	EVP_CIPHER_CTX *ctx;
	int outl, ret;

	if (miclen != 4 && miclen != 8)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		warnx("EVP_CIPHER_CTX_new failed");
		if (clen != 0)
			memset(plain, 0, clen);
		return (-1);
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) <= 0)
		goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 13, NULL) <= 0)
		goto fail;
	/* Provide the expected tag before setting key/nonce. */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)miclen,
	    (void *)(uintptr_t)mic) <= 0)
		goto fail;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
		goto fail;
	if (aadlen != 0) {
		if (EVP_DecryptUpdate(ctx, NULL, &outl, NULL, (int)clen) <= 0)
			goto fail;
		if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) <= 0)
			goto fail;
	}
	/*
	 * For CCM the tag is verified as part of this call: a non-positive
	 * return means the MIC did not match.  EVP_DecryptFinal is not used.
	 */
	ret = EVP_DecryptUpdate(ctx, plain, &outl, cipher, (int)clen);
	EVP_CIPHER_CTX_free(ctx);
	if (ret <= 0) {
		if (clen != 0)
			memset(plain, 0, clen);
		return (-1);
	}
	return (0);

fail:
	warnx("mesh_aes_ccm_decrypt failed");
	EVP_CIPHER_CTX_free(ctx);
	if (clen != 0)
		memset(plain, 0, clen);
	return (-1);
}

/* ================================================================
 * Nonce builders.  MshPRT_v1.1 Section 3.8.5.
 *
 * All multi-octet fields are written big-endian (network order):
 *   SEQ is a 24-bit value, SRC/DST are 16-bit, IV Index is 32-bit.
 * ================================================================ */

/*
 * Network nonce (type 0x00).  Section 3.8.5.1.
 *   [0]      nonce type = 0x00
 *   [1]      (CTL << 7) | (TTL & 0x7f)
 *   [2..4]   SEQ
 *   [5..6]   SRC
 *   [7..8]   0x0000 (pad)
 *   [9..12]  IV Index
 */
void
mesh_network_nonce(uint8_t nonce[13], uint8_t ctl, uint8_t ttl,
    uint32_t seq, uint16_t src, uint32_t iv_index)
{

	nonce[0] = 0x00;
	nonce[1] = (uint8_t)((ctl & 0x01) << 7) | (uint8_t)(ttl & 0x7f);
	nonce[2] = (uint8_t)(seq >> 16);
	nonce[3] = (uint8_t)(seq >> 8);
	nonce[4] = (uint8_t)seq;
	nonce[5] = (uint8_t)(src >> 8);
	nonce[6] = (uint8_t)src;
	nonce[7] = 0x00;
	nonce[8] = 0x00;
	nonce[9] = (uint8_t)(iv_index >> 24);
	nonce[10] = (uint8_t)(iv_index >> 16);
	nonce[11] = (uint8_t)(iv_index >> 8);
	nonce[12] = (uint8_t)iv_index;
}

/*
 * Application nonce (type 0x01).  Section 3.8.5.2.
 *   [0]      nonce type = 0x01
 *   [1]      ASZMIC << 7  (remaining bits 0)
 *   [2..4]   SEQ
 *   [5..6]   SRC
 *   [7..8]   DST
 *   [9..12]  IV Index
 */
void
mesh_application_nonce(uint8_t nonce[13], uint8_t aszmic,
    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index)
{

	nonce[0] = 0x01;
	nonce[1] = (uint8_t)((aszmic & 0x01) << 7);
	nonce[2] = (uint8_t)(seq >> 16);
	nonce[3] = (uint8_t)(seq >> 8);
	nonce[4] = (uint8_t)seq;
	nonce[5] = (uint8_t)(src >> 8);
	nonce[6] = (uint8_t)src;
	nonce[7] = (uint8_t)(dst >> 8);
	nonce[8] = (uint8_t)dst;
	nonce[9] = (uint8_t)(iv_index >> 24);
	nonce[10] = (uint8_t)(iv_index >> 16);
	nonce[11] = (uint8_t)(iv_index >> 8);
	nonce[12] = (uint8_t)iv_index;
}

/*
 * Device nonce (type 0x02).  Section 3.8.5.3.
 * Identical layout to the application nonce, distinguished by the
 * nonce type octet.
 */
void
mesh_device_nonce(uint8_t nonce[13], uint8_t aszmic,
    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index)
{

	mesh_application_nonce(nonce, aszmic, seq, src, dst, iv_index);
	nonce[0] = 0x02;
}

/*
 * Proxy nonce (type 0x03).  Section 3.8.5.4.
 *   [0]      nonce type = 0x03
 *   [1]      0x00 (pad)
 *   [2..4]   SEQ
 *   [5..6]   SRC
 *   [7..8]   0x0000 (pad)
 *   [9..12]  IV Index
 */
void
mesh_proxy_nonce(uint8_t nonce[13], uint32_t seq, uint16_t src,
    uint32_t iv_index)
{

	nonce[0] = 0x03;
	nonce[1] = 0x00;
	nonce[2] = (uint8_t)(seq >> 16);
	nonce[3] = (uint8_t)(seq >> 8);
	nonce[4] = (uint8_t)seq;
	nonce[5] = (uint8_t)(src >> 8);
	nonce[6] = (uint8_t)src;
	nonce[7] = 0x00;
	nonce[8] = 0x00;
	nonce[9] = (uint8_t)(iv_index >> 24);
	nonce[10] = (uint8_t)(iv_index >> 16);
	nonce[11] = (uint8_t)(iv_index >> 8);
	nonce[12] = (uint8_t)iv_index;
}
