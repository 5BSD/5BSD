/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * RFC 5869 HKDF helpers for opaque CRYPTO descriptors.  Derived bytes are
 * only used to create an OpenCrypto session and are wiped before return.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>

#include <sys/cryptodesc.h>
#include "cryptodesc_kdf.h"

#define	CD_SHA256_BLOCK	64
#define	CD_SHA256_LEN	32
#define	CD_SHA512_BLOCK	128
#define	CD_SHA512_LEN	64

static int
cryptodesc_hmac_params(uint32_t hash, size_t *hash_len, size_t *block_len)
{

	switch (hash) {
	case CRYPTODESC_HKDF_SHA256:
		*hash_len = CD_SHA256_LEN;
		*block_len = CD_SHA256_BLOCK;
		return (0);
	case CRYPTODESC_HKDF_SHA512:
		*hash_len = CD_SHA512_LEN;
		*block_len = CD_SHA512_BLOCK;
		return (0);
	default:
		return (EINVAL);
	}
}

static void
cryptodesc_hmac_sha256(uint8_t output[CD_SHA256_LEN], const uint8_t *key,
    size_t key_len, const uint8_t *data, size_t data_len)
{
	SHA256_CTX context;
	uint8_t ipad[CD_SHA256_BLOCK], opad[CD_SHA256_BLOCK], digest[CD_SHA256_LEN];
	size_t i;

	if (key_len > sizeof(ipad)) {
		SHA256_Init(&context);
		SHA256_Update(&context, key, key_len);
		SHA256_Final(digest, &context);
		key = digest;
		key_len = sizeof(digest);
	}
	memset(ipad, 0x36, sizeof(ipad));
	memset(opad, 0x5c, sizeof(opad));
	for (i = 0; i < key_len; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
	SHA256_Init(&context);
	SHA256_Update(&context, ipad, sizeof(ipad));
	SHA256_Update(&context, data, data_len);
	SHA256_Final(output, &context);
	SHA256_Init(&context);
	SHA256_Update(&context, opad, sizeof(opad));
	SHA256_Update(&context, output, CD_SHA256_LEN);
	SHA256_Final(output, &context);
	explicit_bzero(&context, sizeof(context));
	explicit_bzero(ipad, sizeof(ipad));
	explicit_bzero(opad, sizeof(opad));
	explicit_bzero(digest, sizeof(digest));
}

static void
cryptodesc_hmac_sha512(uint8_t output[CD_SHA512_LEN], const uint8_t *key,
    size_t key_len, const uint8_t *data, size_t data_len)
{
	SHA512_CTX context;
	uint8_t ipad[CD_SHA512_BLOCK], opad[CD_SHA512_BLOCK], digest[CD_SHA512_LEN];
	size_t i;

	if (key_len > sizeof(ipad)) {
		SHA512_Init(&context);
		SHA512_Update(&context, key, key_len);
		SHA512_Final(digest, &context);
		key = digest;
		key_len = sizeof(digest);
	}
	memset(ipad, 0x36, sizeof(ipad));
	memset(opad, 0x5c, sizeof(opad));
	for (i = 0; i < key_len; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
	SHA512_Init(&context);
	SHA512_Update(&context, ipad, sizeof(ipad));
	SHA512_Update(&context, data, data_len);
	SHA512_Final(output, &context);
	SHA512_Init(&context);
	SHA512_Update(&context, opad, sizeof(opad));
	SHA512_Update(&context, output, CD_SHA512_LEN);
	SHA512_Final(output, &context);
	explicit_bzero(&context, sizeof(context));
	explicit_bzero(ipad, sizeof(ipad));
	explicit_bzero(opad, sizeof(opad));
	explicit_bzero(digest, sizeof(digest));
}

static void
cryptodesc_hmac(uint32_t hash, uint8_t *output, const uint8_t *key,
    size_t key_len, const uint8_t *data, size_t data_len)
{

	if (hash == CRYPTODESC_HKDF_SHA256)
		cryptodesc_hmac_sha256(output, key, key_len, data, data_len);
	else
		cryptodesc_hmac_sha512(output, key, key_len, data, data_len);
}

int
cryptodesc_hkdf(uint32_t hash, uint8_t *output, size_t output_len,
    const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len)
{
	uint8_t prk[CD_SHA512_LEN], previous[CD_SHA512_LEN], zero[CD_SHA512_LEN];
	uint8_t *input;
	size_t block_len, hash_len, input_len, done, take;
	uint8_t counter;
	int error;

	error = cryptodesc_hmac_params(hash, &hash_len, &block_len);
	if (error != 0 || output_len > 255 * hash_len ||
	    info_len > SIZE_MAX - hash_len - 1)
		return (EINVAL);
	if (ikm == NULL || ikm_len == 0)
		return (EINVAL);
	if (salt == NULL || salt_len == 0) {
		memset(zero, 0, hash_len);
		salt = zero;
		salt_len = hash_len;
	}
	cryptodesc_hmac(hash, prk, salt, salt_len, ikm, ikm_len);
	input = malloc(hash_len + info_len + 1, M_TEMP, M_WAITOK);
	done = 0;
	for (counter = 1; done < output_len; counter++) {
		input_len = 0;
		if (counter != 1) {
			memcpy(input, previous, hash_len);
			input_len = hash_len;
		}
		if (info_len != 0) {
			memcpy(input + input_len, info, info_len);
			input_len += info_len;
		}
		input[input_len++] = counter;
		cryptodesc_hmac(hash, previous, prk, hash_len, input, input_len);
		take = MIN(hash_len, output_len - done);
		memcpy(output + done, previous, take);
		done += take;
	}
	explicit_bzero(input, hash_len + info_len + 1);
	free(input, M_TEMP);
	explicit_bzero(prk, sizeof(prk));
	explicit_bzero(previous, sizeof(previous));
	explicit_bzero(zero, sizeof(zero));
	(void)block_len;
	return (0);
}
