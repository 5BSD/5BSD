/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <opencrypto/cryptodev.h>

#include "policy.h"

static bool
aes_key_length(uint32_t length)
{

	return (length == 16 || length == 24 || length == 32);
}

static uint32_t
mac_length(uint32_t mac)
{

	switch (mac) {
	case CRYPTO_SHA2_256_HMAC:
		return (32);
	case CRYPTO_SHA2_384_HMAC:
		return (48);
	case CRYPTO_SHA2_512_HMAC:
		return (64);
	default:
		return (0);
	}
}

static bool
driver_allowed(int32_t crid)
{
	const int flags = CRYPTO_FLAG_HARDWARE | CRYPTO_FLAG_SOFTWARE;

	return (crid == 0 || (crid & ~flags) == 0);
}

static bool
rights_allowed(uint32_t rights, uint32_t allowed)
{

	return (rights != 0 && (rights & ~allowed) == 0);
}

static bool
paired_rights_valid(uint32_t rights)
{
	const uint32_t encrypt = CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_AUTH;
	const uint32_t decrypt = CRYPTODESC_RIGHT_DECRYPT |
	    CRYPTODESC_RIGHT_VERIFY;

	return (rights_allowed(rights, CRYPTODESC_RIGHT_ALL) &&
	    ((rights & encrypt) == 0 || (rights & encrypt) == encrypt) &&
	    ((rights & decrypt) == 0 || (rights & decrypt) == decrypt));
}

static bool
aead_cipher(uint32_t cipher)
{

	return (cipher == CRYPTO_AES_NIST_GCM_16 ||
	    cipher == CRYPTO_CHACHA20_POLY1305 ||
	    cipher == CRYPTO_XCHACHA20_POLY1305);
}

int
cryptocmp_policy_validate(const struct cryptocmp_generate *request)
{
	uint32_t digest_length;

	if (request == NULL || !driver_allowed(request->crid) ||
	    request->keylen > CRYPTOCMP_MAX_CIPHER_KEY_BYTES ||
	    request->mackeylen > CRYPTOCMP_MAX_MAC_KEY_BYTES ||
	    request->ivlen < 0 || request->maclen < 0) {
		errno = EINVAL;
		return (-1);
	}

	digest_length = mac_length(request->mac);
	if (request->mac != 0 && digest_length == 0) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	if (request->mac == 0 &&
	    (request->mackeylen != 0 ||
	    (request->maclen != 0 && !aead_cipher(request->cipher)))) {
		errno = EINVAL;
		return (-1);
	}
	if (request->mac != 0 &&
	    (request->mackeylen < 16 ||
	    (request->maclen != 0 && (uint32_t)request->maclen > digest_length))) {
		errno = EINVAL;
		return (-1);
	}

	switch (request->cipher) {
	case 0:
		if (request->mac == 0 || request->keylen != 0 ||
		    request->ivlen != 0 || !rights_allowed(request->rights,
		    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_VERIFY))
			goto invalid;
		break;
	case CRYPTO_AES_CBC:
		if (!aes_key_length(request->keylen) || request->ivlen != 16)
			goto invalid;
		if (request->mac == 0) {
			if (!rights_allowed(request->rights,
			    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT))
				goto invalid;
		} else if (!paired_rights_valid(request->rights))
			goto invalid;
		break;
	case CRYPTO_AES_NIST_GCM_16:
		if (request->mac != 0 || !aes_key_length(request->keylen) ||
		    request->ivlen != 12 || request->maclen != 16 ||
		    !paired_rights_valid(request->rights))
			goto invalid;
		break;
	case CRYPTO_CHACHA20_POLY1305:
		if (request->mac != 0 || request->keylen != 32 ||
		    request->ivlen != 12 || request->maclen != 16 ||
		    !paired_rights_valid(request->rights))
			goto invalid;
		break;
	case CRYPTO_XCHACHA20_POLY1305:
		if (request->mac != 0 || request->keylen != 32 ||
		    request->ivlen != 24 || request->maclen != 16 ||
		    !paired_rights_valid(request->rights))
			goto invalid;
		break;
	case CRYPTO_AES_XTS:
		if (request->mac != 0 || (request->keylen != 32 &&
		    request->keylen != 64) || request->ivlen != 16 ||
		    !rights_allowed(request->rights,
		    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT))
			goto invalid;
		break;
	case CRYPTO_DEFLATE_COMP:
		if (request->mac != 0 || request->keylen != 0 ||
		    request->ivlen != 0 || !rights_allowed(request->rights,
		    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT))
			goto invalid;
		break;
	default:
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	return (0);

invalid:
	errno = EINVAL;
	return (-1);
}
