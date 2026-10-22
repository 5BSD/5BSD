/* SPDX-License-Identifier: BSD-2-Clause */
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "dtraced_release_attestation.h"

static EVP_PKEY *
new_key(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	EVP_PKEY *key = nullptr;
	assert(ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

static std::array<uint8_t, 32>
public_bytes(EVP_PKEY *key)
{
	std::array<uint8_t, 32> result{};
	size_t length = result.size();
	assert(EVP_PKEY_get_raw_public_key(key, result.data(), &length) == 1);
	assert(length == result.size());
	return (result);
}

int
main(void)
{
	EVP_PKEY *source = new_key(), *other = new_key(), *destination = new_key();
	const auto source_public = public_bytes(source);
	const auto other_public = public_bytes(other);
	const auto destination_public = public_bytes(destination);
	std::array<uint8_t, DTRACED_RELEASE_HSL_SIZE> hsl{};
	std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> wire{}, changed{};
	memcpy(hsl.data(), "HSL1", 4);
	for (size_t i = 4; i < 156; i++)
		hsl[i] = (uint8_t)i;
	assert(SHA256(hsl.data(), 156, hsl.data() + 156) != nullptr);
	assert(dtraced_release_attestation_sign(source,
	    destination_public.data(), hsl.data(), wire.data()));
	assert(dtraced_release_attestation_verify(source_public.data(),
	    destination_public.data(), hsl.data(), wire.data()));
	assert(!dtraced_release_attestation_verify(other_public.data(),
	    destination_public.data(), hsl.data(), wire.data()));
	assert(errno == EPROTO);
	assert(!dtraced_release_attestation_verify(source_public.data(),
	    other_public.data(), hsl.data(), wire.data()));
	changed = wire;
	changed[72 + 32] ^= 1;
	assert(!dtraced_release_attestation_verify(source_public.data(),
	    destination_public.data(), hsl.data(), changed.data()));
	changed = wire;
	changed[5] = 1;
	assert(!dtraced_release_attestation_verify(source_public.data(),
	    destination_public.data(), hsl.data(), changed.data()));
	changed = wire;
	changed.back() ^= 1;
	assert(!dtraced_release_attestation_verify(source_public.data(),
	    destination_public.data(), hsl.data(), changed.data()));
	hsl[32] ^= 1;
	assert(!dtraced_release_attestation_verify(source_public.data(),
	    destination_public.data(), hsl.data(), wire.data()));
	assert(!dtraced_release_attestation_sign(source,
	    destination_public.data(), hsl.data(), changed.data()));
	EVP_PKEY_free(destination);
	EVP_PKEY_free(other);
	EVP_PKEY_free(source);
	return (0);
}
