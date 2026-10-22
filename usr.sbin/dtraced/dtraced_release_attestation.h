/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_RELEASE_ATTESTATION_H
#define DTRACED_RELEASE_ATTESTATION_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* HSA1 signs the exact HSL1 source-release witness for one destination.
 * Neither an HSL1 checksum nor the HTX1 checksum is a host credential. */
/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
#define DTRACED_RELEASE_HSL_SIZE 188U
#ifndef DTRACED_RELEASE_ATTESTED_SIZE
#define DTRACED_RELEASE_ATTESTED_SIZE 324U
#endif
#define DTRACED_RELEASE_SIGNED_SIZE 260U

static inline int
dtraced_release_hsl_valid(const uint8_t hsl[DTRACED_RELEASE_HSL_SIZE])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];

	if (hsl == NULL || memcmp(hsl, "HSL1", 4) != 0 ||
	    SHA256(hsl, 156, digest) == NULL ||
	    CRYPTO_memcmp(digest, hsl + 156, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (0);
	}
	return (1);
}

static inline int
dtraced_release_attestation_sign(EVP_PKEY *source_private,
    const uint8_t destination_public[32],
    const uint8_t hsl[DTRACED_RELEASE_HSL_SIZE],
    uint8_t out[DTRACED_RELEASE_ATTESTED_SIZE])
{
	EVP_MD_CTX *ctx = NULL;
	uint8_t candidate[DTRACED_RELEASE_ATTESTED_SIZE] = { 0 };
	const uint8_t zero_public[32] = { 0 };
	size_t public_length = 32, signature_length = 64;
	int ok;

	if (source_private == NULL || destination_public == NULL || out == NULL ||
	    CRYPTO_memcmp(destination_public, zero_public, 32) == 0 ||
	    EVP_PKEY_base_id(source_private) != EVP_PKEY_ED25519 ||
	    !dtraced_release_hsl_valid(hsl)) {
		errno = EINVAL;
		return (0);
	}
	memcpy(candidate, "HSA1", 4);
	candidate[4] = 1;
	memcpy(candidate + 40, destination_public, 32);
	memcpy(candidate + 72, hsl, DTRACED_RELEASE_HSL_SIZE);
	ctx = EVP_MD_CTX_new();
	ok = EVP_PKEY_get_raw_public_key(source_private, candidate + 8,
	    &public_length) == 1 && public_length == 32 && ctx != NULL &&
	    EVP_DigestSignInit(ctx, NULL, NULL, NULL, source_private) == 1 &&
	    EVP_DigestSign(ctx, candidate + DTRACED_RELEASE_SIGNED_SIZE,
	    &signature_length, candidate, DTRACED_RELEASE_SIGNED_SIZE) == 1 &&
	    signature_length == 64;
	EVP_MD_CTX_free(ctx);
	if (!ok) {
		errno = EIO;
		return (0);
	}
	memcpy(out, candidate, sizeof(candidate));
	return (1);
}

static inline int
dtraced_release_attestation_verify(const uint8_t source_public[32],
    const uint8_t destination_public[32],
    const uint8_t expected_hsl[DTRACED_RELEASE_HSL_SIZE],
    const uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE])
{
	EVP_PKEY *key = NULL;
	EVP_MD_CTX *ctx = NULL;
	int ok;

	if (source_public == NULL || destination_public == NULL || wire == NULL ||
	    !dtraced_release_hsl_valid(expected_hsl) ||
	    memcmp(wire, "HSA1", 4) != 0 || wire[4] != 1 ||
	    wire[5] != 0 || wire[6] != 0 || wire[7] != 0 ||
	    CRYPTO_memcmp(wire + 8, source_public, 32) != 0 ||
	    CRYPTO_memcmp(wire + 40, destination_public, 32) != 0 ||
	    CRYPTO_memcmp(wire + 72, expected_hsl,
	    DTRACED_RELEASE_HSL_SIZE) != 0) {
		errno = EPROTO;
		return (0);
	}
	key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	    source_public, 32);
	ctx = EVP_MD_CTX_new();
	ok = key != NULL && ctx != NULL &&
	    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
	    EVP_DigestVerify(ctx, wire + DTRACED_RELEASE_SIGNED_SIZE, 64,
	    wire, DTRACED_RELEASE_SIGNED_SIZE) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	if (!ok) {
		errno = EPROTO;
		return (0);
	}
	return (1);
}

/* HT-C END */
#endif
