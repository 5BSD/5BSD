/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

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

	return (rights_allowed(rights, CRYPTODESC_RIGHT_SESSION) &&
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

static bool
nist_approved_profile(const struct cryptocmp_generate *request)
{

	/* A narrow algorithm selector, not evidence of provider validation. */
	if (request->cipher == 0)
		return (request->mac == CRYPTO_SHA2_256_HMAC ||
		    request->mac == CRYPTO_SHA2_384_HMAC ||
		    request->mac == CRYPTO_SHA2_512_HMAC);
	return (request->cipher == CRYPTO_AES_CBC ||
	    request->cipher == CRYPTO_AES_NIST_GCM_16);
}

static bool
name_valid(const char *name, size_t capacity)
{
	size_t i, length;

	length = strnlen(name, capacity);
	if (length == 0 || length == capacity)
		return (false);
	for (i = 0; i < length; i++) {
		if (!((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
		    name[i] == '_' || name[i] == '-'))
			return (false);
	}
	return (true);
}

int
cryptocmp_policy_validate(const struct cryptocmp_generate *request)
{
	uint32_t digest_length;

	if (request == NULL || !driver_allowed(request->crid) ||
	    request->keylen > CRYPTOCMP_MAX_CIPHER_KEY_BYTES ||
	    request->mackeylen > CRYPTOCMP_MAX_MAC_KEY_BYTES ||
	    request->ttl > 86400 ||
	    (request->flags & ~CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY) != 0 ||
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
		    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_VERIFY |
		    CRYPTODESC_RIGHT_DERIVE))
			goto invalid;
		break;
	case CRYPTO_AES_CBC:
		if (!aes_key_length(request->keylen) || request->ivlen != 16)
			goto invalid;
		if (request->mac == 0) {
			if (!rights_allowed(request->rights,
			    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT |
			    CRYPTODESC_RIGHT_DERIVE))
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
		    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT |
		    CRYPTODESC_RIGHT_DERIVE))
			goto invalid;
		break;
	case CRYPTO_DEFLATE_COMP:
		if (request->mac != 0 || request->keylen != 0 ||
		    request->ivlen != 0 || !rights_allowed(request->rights,
		    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT |
		    CRYPTODESC_RIGHT_DERIVE))
			goto invalid;
		break;
	default:
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	if ((request->flags & CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY) != 0 &&
	    !nist_approved_profile(request))
		goto invalid;
	return (0);

invalid:
	errno = EINVAL;
	return (-1);
}

int
cryptocmp_key_policy_validate(const struct cryptocmp_key_generate *request)
{
	uint32_t allowed;

	if (request == NULL || request->flags != 0 || request->ttl > 86400) {
		errno = EINVAL;
		return (-1);
	}
	switch (request->type) {
	case CRYPTODESC_KEY_X25519:
		allowed = CRYPTODESC_RIGHT_EXCHANGE;
		break;
	case CRYPTODESC_KEY_ED25519:
		allowed = CRYPTODESC_RIGHT_SIGN | CRYPTODESC_RIGHT_VERIFY;
		break;
	default:
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	if (!rights_allowed(request->rights, allowed)) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
cryptocmp_named_create_policy_validate(const struct cryptocmp_named_create *request)
{

	if (request == NULL ||
	    !name_valid(request->name, sizeof(request->name))) {
		errno = EINVAL;
		return (-1);
	}
	return (cryptocmp_policy_validate(&request->generate));
}

int
cryptocmp_named_lease_policy_validate(const struct cryptocmp_named_lease *request)
{

	if (request == NULL || !name_valid(request->name, sizeof(request->name)) ||
	    request->flags != 0 || request->ttl > 86400 ||
	    !rights_allowed(request->rights, CRYPTODESC_RIGHT_SESSION)) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
cryptocmp_named_control_policy_validate(const struct cryptocmp_named_control *request)
{

	if (request == NULL || !name_valid(request->name, sizeof(request->name)) ||
	    request->flags != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Read-only named-key introspection: the name must be a well-formed identifier
 * and the reserved flags field must be zero.  No rights or session parameters
 * are supplied by the caller, so there is nothing further to validate; the
 * kernel resolves the key owner-scoped and fails closed (ENOENT) on a miss.
 */
int
cryptocmp_named_stat_policy_validate(const struct cryptocmp_named_stat *request)
{

	if (request == NULL || !name_valid(request->name, sizeof(request->name)) ||
	    request->flags != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Owner-scoped enumeration: the caller supplies only a resume cursor and a
 * reserved flags field (which must be zero).  No name or owner is on the wire —
 * the daemon scopes the walk to the session's own label — so there is nothing
 * further to validate; any cursor is accepted and the kernel returns an empty
 * page for an out-of-range or exhausted cursor.
 */
int
cryptocmp_named_list_policy_validate(const struct cryptocmp_named_list *request)
{

	if (request == NULL || request->flags != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Unkeyed digest: the algorithm must be one of the allowed plain SHA-2 hashes
 * (the same NIST-profile family the keyed HMAC path admits, minus the key).
 * Unknown/weak algorithms are rejected EPROTONOSUPPORT; malformed parameters
 * (nonzero flags, an over-long ttl) fail EINVAL.  No key material is involved,
 * so there is nothing to owner-scope.
 */
int
cryptocmp_digest_policy_validate(const struct cryptocmp_digest *request)
{

	if (request == NULL || request->flags != 0 || request->ttl > 86400) {
		errno = EINVAL;
		return (-1);
	}
	switch (request->alg) {
	case CRYPTO_SHA2_256:
	case CRYPTO_SHA2_384:
	case CRYPTO_SHA2_512:
		return (0);
	default:
		errno = EPROTONOSUPPORT;
		return (-1);
	}
}

/*
 * CSPRNG: a nonzero request bounded by CRYPTOCMP_MAX_RANDOM_BYTES.  Zero-length
 * and over-cap requests both fail closed with EINVAL.
 */
int
cryptocmp_random_policy_validate(const struct cryptocmp_random *request)
{

	if (request == NULL || request->nbytes == 0 ||
	    request->nbytes > CRYPTOCMP_MAX_RANDOM_BYTES) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}
