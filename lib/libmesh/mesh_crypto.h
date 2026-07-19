/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh security toolbox.
 *
 * Pure, hardware-free, side-effect-free cryptographic primitives from
 * the Bluetooth Mesh Protocol specification (MshPRT_v1.1) Section 3.8
 * "Mesh security".  All functions are self-contained, take and return
 * values in network (big-endian) byte order, perform no I/O, keep no
 * global state, and clear intermediate secrets with explicit_bzero().
 *
 * Every function returns 0 on success and -1 on failure (the void
 * nonce builders never fail).  On failure the output buffers are left
 * zeroed.
 */

#ifndef _MESH_CRYPTO_H_
#define _MESH_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Maximum length of the k2 "P" parameter accepted by mesh_k2().  The
 * managed-flooding credential uses a 1-octet P; the friendship
 * credential uses a 9-octet P.  The cap keeps the construction on the
 * stack without dynamic allocation.
 */
#define	MESH_K2_MAX_P	64

/* AES-128 block cipher, e(): out = AES-128-ECB(key, in).  Section 3.8.2.1 */
int	mesh_aes128_e(const uint8_t key[16], const uint8_t in[16],
	    uint8_t out[16]);

/* AES-CMAC (RFC 4493).  Section 3.8.2.2 */
int	mesh_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
	    uint8_t mac[16]);

/* HMAC-SHA-256 (FIPS 198-1 / RFC 2104).  Section 3.8.2.3 */
int	mesh_hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg,
	    size_t len, uint8_t mac[32]);

/* s1 salt generation: s1(M) = AES-CMAC(ZERO, M).  Section 3.8.2.4 */
int	mesh_s1(const uint8_t *m, size_t len, uint8_t salt[16]);

/* s2 salt generation: s2(M) = HMAC-SHA-256(ZERO32, M).  Section 3.8.2.5 */
int	mesh_s2(const uint8_t *m, size_t len, uint8_t salt[32]);

/* k1 derivation: k1(N, SALT, P) = AES-CMAC(AES-CMAC(SALT, N), P). §3.8.2.5 */
int	mesh_k1(const uint8_t *n, size_t nlen, const uint8_t salt[16],
	    const uint8_t *p, size_t plen, uint8_t out[16]);

/*
 * k5 derivation: k5(N, SALT, P) = HMAC-SHA-256(HMAC-SHA-256(SALT, N), P).
 * Section 3.8.2.9.  32-octet output; the HMAC-SHA-256 provisioning
 * algorithm's ConfirmationKey.
 */
int	mesh_k5(const uint8_t *n, size_t nlen, const uint8_t salt[32],
	    const uint8_t *p, size_t plen, uint8_t out[32]);

/*
 * k2 network key material derivation.  Section 3.8.2.6.
 * Produces NID (7 bits), the 128-bit EncryptionKey and the 128-bit
 * PrivacyKey from the NetKey N and the parameter P.
 */
int	mesh_k2(const uint8_t netkey[16], const uint8_t *p, size_t plen,
	    uint8_t out_nid[1], uint8_t out_enckey[16],
	    uint8_t out_privkey[16]);

/* k3 derivation: 64-bit network identifier.  Section 3.8.2.7 */
int	mesh_k3(const uint8_t netkey[16], uint8_t out[8]);

/* k4 derivation: 6-bit application key identifier (AID).  Section 3.8.2.8 */
int	mesh_k4(const uint8_t appkey[16], uint8_t out_aid[1]);

/*
 * AES-128-CCM authenticated encryption / decryption.  Section 3.8.2.3.
 * nonce is 13 octets, miclen is 4 (32-bit MIC) or 8 (64-bit MIC).
 * mesh_aes_ccm_decrypt() verifies the MIC and returns -1 if it does
 * not match (leaving the plaintext output zeroed).
 */
int	mesh_aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13],
	    const uint8_t *aad, size_t aadlen,
	    const uint8_t *plain, size_t plen,
	    uint8_t *cipher, uint8_t *mic, size_t miclen);
int	mesh_aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13],
	    const uint8_t *aad, size_t aadlen,
	    const uint8_t *cipher, size_t clen,
	    uint8_t *plain, const uint8_t *mic, size_t miclen);

/*
 * Nonce builders.  Section 3.8.5.  Each writes exactly 13 octets in
 * the byte layout mandated by the specification.
 */
void	mesh_network_nonce(uint8_t nonce[13], uint8_t ctl, uint8_t ttl,
	    uint32_t seq, uint16_t src, uint32_t iv_index);
void	mesh_application_nonce(uint8_t nonce[13], uint8_t aszmic,
	    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index);
void	mesh_device_nonce(uint8_t nonce[13], uint8_t aszmic,
	    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index);
void	mesh_proxy_nonce(uint8_t nonce[13], uint32_t seq, uint16_t src,
	    uint32_t iv_index);

#endif /* _MESH_CRYPTO_H_ */
