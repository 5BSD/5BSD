/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Ed25519 descriptor operations use the already-loaded crypto.ko ref10
 * primitives.  Private material is held only in the descriptor object.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/libkern.h>

#include <crypto/sha2/sha512.h>

#include "cryptodesc_ed25519.h"

#ifdef HAVE_TI_MODE
typedef uint64_t cd_fe25519[5];
#else
typedef int32_t cd_fe25519[10];
#endif
typedef struct { cd_fe25519 X, Y, Z; } cd_ge25519_p2;
typedef struct { cd_fe25519 X, Y, Z, T; } cd_ge25519_p3;

extern void ge25519_scalarmult_base(cd_ge25519_p3 *, const unsigned char *);
extern void ge25519_p3_tobytes(unsigned char *, const cd_ge25519_p3 *);
extern void ge25519_tobytes(unsigned char *, const cd_ge25519_p2 *);
extern int ge25519_frombytes_negate_vartime(cd_ge25519_p3 *,
    const unsigned char *);
extern void ge25519_double_scalarmult_vartime(cd_ge25519_p2 *,
    const unsigned char *, const cd_ge25519_p3 *, const unsigned char *);
extern int ge25519_has_small_order(const unsigned char[32]);
extern int ge25519_is_canonical(const unsigned char *);
extern void sc25519_reduce(unsigned char *);
extern void sc25519_muladd(unsigned char *, const unsigned char *,
    const unsigned char *, const unsigned char *);
extern int sc25519_is_canonical(const unsigned char *);

static void
cryptodesc_ed25519_clamp(uint8_t scalar[32])
{

	scalar[0] &= 248;
	scalar[31] &= 127;
	scalar[31] |= 64;
}

void
cryptodesc_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64])
{
	SHA512_CTX context;
	uint8_t seed[32], scalar[64];
	cd_ge25519_p3 point;

	arc4random_buf(seed, sizeof(seed));
	SHA512_Init(&context);
	SHA512_Update(&context, seed, sizeof(seed));
	SHA512_Final(scalar, &context);
	cryptodesc_ed25519_clamp(scalar);
	ge25519_scalarmult_base(&point, scalar);
	ge25519_p3_tobytes(public_key, &point);
	memcpy(secret_key, seed, sizeof(seed));
	memcpy(secret_key + sizeof(seed), public_key, 32);
	explicit_bzero(&context, sizeof(context));
	explicit_bzero(seed, sizeof(seed));
	explicit_bzero(scalar, sizeof(scalar));
	explicit_bzero(&point, sizeof(point));
}

int
cryptodesc_ed25519_sign(uint8_t signature[64], const uint8_t *data,
    size_t data_len, const uint8_t secret_key[64])
{
	SHA512_CTX context;
	uint8_t scalar[64], nonce[64], challenge[64];
	cd_ge25519_p3 point;

	SHA512_Init(&context);
	SHA512_Update(&context, secret_key, 32);
	SHA512_Final(scalar, &context);
	SHA512_Init(&context);
	SHA512_Update(&context, scalar + 32, 32);
	SHA512_Update(&context, data, data_len);
	SHA512_Final(nonce, &context);
	memcpy(signature + 32, secret_key + 32, 32);
	sc25519_reduce(nonce);
	ge25519_scalarmult_base(&point, nonce);
	ge25519_p3_tobytes(signature, &point);
	SHA512_Init(&context);
	SHA512_Update(&context, signature, 64);
	SHA512_Update(&context, data, data_len);
	SHA512_Final(challenge, &context);
	sc25519_reduce(challenge);
	cryptodesc_ed25519_clamp(scalar);
	sc25519_muladd(signature + 32, challenge, scalar, nonce);
	explicit_bzero(&context, sizeof(context));
	explicit_bzero(scalar, sizeof(scalar));
	explicit_bzero(nonce, sizeof(nonce));
	explicit_bzero(challenge, sizeof(challenge));
	explicit_bzero(&point, sizeof(point));
	return (0);
}

int
cryptodesc_ed25519_verify(const uint8_t signature[64], const uint8_t *data,
    size_t data_len, const uint8_t public_key[32])
{
	SHA512_CTX context;
	uint8_t challenge[64], expected[32];
	cd_ge25519_p3 public_point;
	cd_ge25519_p2 point;
	int error;

	if (sc25519_is_canonical(signature + 32) == 0 ||
	    ge25519_has_small_order(signature) != 0 ||
	    ge25519_is_canonical(public_key) == 0 ||
	    ge25519_has_small_order(public_key) != 0)
		return (EINVAL);
	if (ge25519_frombytes_negate_vartime(&public_point, public_key) != 0)
		return (EINVAL);
	SHA512_Init(&context);
	SHA512_Update(&context, signature, 32);
	SHA512_Update(&context, public_key, 32);
	SHA512_Update(&context, data, data_len);
	SHA512_Final(challenge, &context);
	sc25519_reduce(challenge);
	ge25519_double_scalarmult_vartime(&point, challenge, &public_point,
	    signature + 32);
	ge25519_tobytes(expected, &point);
	error = timingsafe_bcmp(expected, signature, sizeof(expected)) == 0 ?
	    0 : EBADMSG;
	explicit_bzero(&context, sizeof(context));
	explicit_bzero(challenge, sizeof(challenge));
	explicit_bzero(expected, sizeof(expected));
	explicit_bzero(&public_point, sizeof(public_point));
	explicit_bzero(&point, sizeof(point));
	return (error);
}
