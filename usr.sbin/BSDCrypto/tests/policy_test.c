/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include <opencrypto/cryptodev.h>

#include "policy.h"

static struct cryptocmp_generate
request(uint32_t cipher, uint32_t mac, uint32_t keylen, uint32_t mackeylen,
    uint32_t rights, int32_t ivlen, int32_t maclen)
{
	struct cryptocmp_generate generate;

	memset(&generate, 0, sizeof(generate));
	generate.cipher = cipher;
	generate.mac = mac;
	generate.keylen = keylen;
	generate.mackeylen = mackeylen;
	generate.rights = rights;
	generate.crid = CRYPTO_FLAG_SOFTWARE;
	generate.ivlen = ivlen;
	generate.maclen = maclen;
	return (generate);
}

static void
require_valid(const struct cryptocmp_generate *generate)
{
	errno = 0;
	ATF_REQUIRE_MSG(cryptocmp_policy_validate(generate) == 0,
	    "policy rejected valid request: %s", strerror(errno));
}

ATF_TC(valid_profiles);
ATF_TC_HEAD(valid_profiles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] accepts its documented symmetric, hash, and compression profiles");
}
ATF_TC_BODY(valid_profiles, tc)
{
	struct cryptocmp_generate generate;

	generate = request(CRYPTO_AES_CBC, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT, 16, 0);
	require_valid(&generate);
	generate.keylen = 24;
	require_valid(&generate);
	generate.keylen = 32;
	require_valid(&generate);

	generate = request(0, CRYPTO_SHA2_256_HMAC, 0, 16,
	    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_VERIFY, 0, 0);
	require_valid(&generate);
	generate.mac = CRYPTO_SHA2_384_HMAC;
	generate.mackeylen = 32;
	generate.maclen = 48;
	require_valid(&generate);
	generate.mac = CRYPTO_SHA2_512_HMAC;
	generate.mackeylen = 64;
	generate.maclen = 32;
	require_valid(&generate);

	generate = request(CRYPTO_AES_CBC, CRYPTO_SHA2_256_HMAC, 16, 16,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH, 16, 32);
	require_valid(&generate);
	generate.rights = CRYPTODESC_RIGHT_DECRYPT | CRYPTODESC_RIGHT_VERIFY;
	require_valid(&generate);

	generate = request(CRYPTO_AES_NIST_GCM_16, 0, 32, 0,
	    CRYPTODESC_RIGHT_SESSION, 12, 16);
	require_valid(&generate);
	generate = request(CRYPTO_CHACHA20_POLY1305, 0, 32, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH, 12, 16);
	require_valid(&generate);
	generate = request(CRYPTO_XCHACHA20_POLY1305, 0, 32, 0,
	    CRYPTODESC_RIGHT_DECRYPT | CRYPTODESC_RIGHT_VERIFY, 24, 16);
	require_valid(&generate);
	generate = request(CRYPTO_AES_XTS, 0, 64, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	require_valid(&generate);
	generate = request(CRYPTO_DEFLATE_COMP, 0, 0, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT, 0, 0);
	require_valid(&generate);
}

ATF_TC(key_profiles);
ATF_TC_HEAD(key_profiles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] accepts only typed asymmetric capability requests");
}

ATF_TC(approved_only_profiles);
ATF_TC_HEAD(approved_only_profiles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] approved-only policy admits its narrow AES/SHA-2 suite");
}

ATF_TC(named_lifecycle_policy);
ATF_TC_HEAD(named_lifecycle_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] validates named-key lifecycle request boundaries");
}
ATF_TC_BODY(named_lifecycle_policy, tc)
{
	struct cryptocmp_named_create create;
	struct cryptocmp_named_lease lease;
	struct cryptocmp_named_control control;

	memset(&create, 0, sizeof(create));
	strlcpy(create.name, "service-key.1", sizeof(create.name));
	create.generate = request(CRYPTO_AES_CBC, 0, 32, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT, 16, 0);
	ATF_REQUIRE(cryptocmp_named_create_policy_validate(&create) == 0);
	strlcpy(create.name, "bad/name", sizeof(create.name));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_create_policy_validate(&create) == -1);
	strlcpy(create.name, "service-key.1", sizeof(create.name));
	create.generate.keylen = 31;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_create_policy_validate(&create) == -1);

	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.name, "service-key.1", sizeof(lease.name));
	lease.rights = CRYPTODESC_RIGHT_ENCRYPT;
	lease.ttl = 60;
	ATF_REQUIRE(cryptocmp_named_lease_policy_validate(&lease) == 0);
	lease.rights = CRYPTODESC_RIGHT_SIGN;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_lease_policy_validate(&lease) == -1);
	lease.rights = CRYPTODESC_RIGHT_ENCRYPT;
	lease.ttl = 86401;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_lease_policy_validate(&lease) == -1);
	strlcpy(lease.name, "bad/name", sizeof(lease.name));
	lease.ttl = 60;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_lease_policy_validate(&lease) == -1);

	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "service-key.1", sizeof(control.name));
	ATF_REQUIRE(cryptocmp_named_control_policy_validate(&control) == 0);
	control.flags = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_named_control_policy_validate(&control) == -1);
}
ATF_TC_BODY(approved_only_profiles, tc)
{
	struct cryptocmp_generate generate;

	generate = request(CRYPTO_AES_NIST_GCM_16, 0, 32, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH, 12, 16);
	generate.flags = CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY;
	require_valid(&generate);

	generate = request(0, CRYPTO_SHA2_512_HMAC, 0, 64,
	    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_VERIFY, 0, 0);
	generate.flags = CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY;
	require_valid(&generate);

	generate = request(CRYPTO_CHACHA20_POLY1305, 0, 32, 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH, 12, 16);
	generate.flags = CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);

	generate = request(CRYPTO_AES_XTS, 0, 64, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	generate.flags = CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);

	generate = request(CRYPTO_AES_CBC, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	generate.flags = 0x80000000U;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
}
ATF_TC_BODY(key_profiles, tc)
{
	struct cryptocmp_key_generate key;

	memset(&key, 0, sizeof(key));
	key.type = CRYPTODESC_KEY_X25519;
	key.rights = CRYPTODESC_RIGHT_EXCHANGE;
	key.ttl = 60;
	ATF_REQUIRE(cryptocmp_key_policy_validate(&key) == 0);
	key.type = CRYPTODESC_KEY_ED25519;
	key.rights = CRYPTODESC_RIGHT_SIGN | CRYPTODESC_RIGHT_VERIFY;
	ATF_REQUIRE(cryptocmp_key_policy_validate(&key) == 0);
	key.rights = CRYPTODESC_RIGHT_ENCRYPT;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_key_policy_validate(&key) == -1);
	key.type = 99;
	key.rights = CRYPTODESC_RIGHT_SIGN;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT,
	    cryptocmp_key_policy_validate(&key) == -1);
	key.type = CRYPTODESC_KEY_X25519;
	key.rights = CRYPTODESC_RIGHT_EXCHANGE;
	key.ttl = 86401;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_key_policy_validate(&key) == -1);
}

ATF_TC(rejects_invalid_profiles);
ATF_TC_HEAD(rejects_invalid_profiles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] rejects unsupported primitives and malformed parameter sets");
}
ATF_TC_BODY(rejects_invalid_profiles, tc)
{
	struct cryptocmp_generate generate;

	generate = request(CRYPTO_ARC4, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 0, 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT,
	    cryptocmp_policy_validate(&generate) == -1);

	generate = request(CRYPTO_AES_CBC, 0, 15, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_AES_NIST_GCM_16, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 12, 16);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_CHACHA20_POLY1305, 0, 16, 0,
	    CRYPTODESC_RIGHT_ALL, 12, 16);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_XCHACHA20_POLY1305, 0, 32, 0,
	    CRYPTODESC_RIGHT_ALL, 12, 16);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(0, CRYPTO_SHA2_256_HMAC, 1, 16,
	    CRYPTODESC_RIGHT_AUTH, 0, 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_AES_CBC, CRYPTO_SHA2_256_HMAC, 16, 16,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 32);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_AES_CBC, CRYPTO_SHA2_256_HMAC, 16, 16,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH, 16, 33);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
	generate = request(CRYPTO_AES_CBC, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	generate.ttl = 86401;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
}

ATF_TC(driver_selection);
ATF_TC_HEAD(driver_selection, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] permits only OpenCrypto software or hardware driver selectors");
}
ATF_TC_BODY(driver_selection, tc)
{
	struct cryptocmp_generate generate;

	generate = request(CRYPTO_AES_CBC, 0, 16, 0,
	    CRYPTODESC_RIGHT_ENCRYPT, 16, 0);
	generate.crid = 0;
	require_valid(&generate);
	generate.crid = CRYPTO_FLAG_HARDWARE;
	require_valid(&generate);
	generate.crid = CRYPTO_FLAG_SOFTWARE;
	require_valid(&generate);
	generate.crid = CRYPTO_FLAG_HARDWARE | CRYPTO_FLAG_SOFTWARE;
	require_valid(&generate);
	generate.crid = 7;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, cryptocmp_policy_validate(&generate) == -1);
}

ATF_TC(digest_policy);
ATF_TC_HEAD(digest_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] unkeyed-digest policy admits only plain SHA-2 hashes");
}
ATF_TC_BODY(digest_policy, tc)
{
	struct cryptocmp_digest digest;

	/* The three allowed unkeyed hashes. */
	memset(&digest, 0, sizeof(digest));
	digest.alg = CRYPTO_SHA2_256;
	digest.ttl = 60;
	ATF_REQUIRE(cryptocmp_digest_policy_validate(&digest) == 0);
	digest.alg = CRYPTO_SHA2_384;
	ATF_REQUIRE(cryptocmp_digest_policy_validate(&digest) == 0);
	digest.alg = CRYPTO_SHA2_512;
	digest.ttl = 0;
	ATF_REQUIRE(cryptocmp_digest_policy_validate(&digest) == 0);

	/* A keyed HMAC selector is not an unkeyed digest. */
	digest.alg = CRYPTO_SHA2_256_HMAC;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT,
	    cryptocmp_digest_policy_validate(&digest) == -1);

	/* A weak/legacy hash is rejected. */
	digest.alg = CRYPTO_SHA1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT,
	    cryptocmp_digest_policy_validate(&digest) == -1);

	/* An unknown selector is rejected. */
	digest.alg = 999;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPROTONOSUPPORT,
	    cryptocmp_digest_policy_validate(&digest) == -1);

	/* Nonzero flags and an over-long ttl are malformed. */
	digest.alg = CRYPTO_SHA2_256;
	digest.flags = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_digest_policy_validate(&digest) == -1);
	digest.flags = 0;
	digest.ttl = 86401;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_digest_policy_validate(&digest) == -1);
}

ATF_TC(random_policy);
ATF_TC_HEAD(random_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "[CRYPTO] CSPRNG policy bounds the requested byte count");
}
ATF_TC_BODY(random_policy, tc)
{
	struct cryptocmp_random request;

	request.nbytes = 1;
	ATF_REQUIRE(cryptocmp_random_policy_validate(&request) == 0);
	request.nbytes = CRYPTOCMP_MAX_RANDOM_BYTES;
	ATF_REQUIRE(cryptocmp_random_policy_validate(&request) == 0);

	request.nbytes = 0;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_random_policy_validate(&request) == -1);
	request.nbytes = CRYPTOCMP_MAX_RANDOM_BYTES + 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    cryptocmp_random_policy_validate(&request) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_profiles);
	ATF_TP_ADD_TC(tp, key_profiles);
	ATF_TP_ADD_TC(tp, approved_only_profiles);
	ATF_TP_ADD_TC(tp, named_lifecycle_policy);
	ATF_TP_ADD_TC(tp, rejects_invalid_profiles);
	ATF_TP_ADD_TC(tp, driver_selection);
	ATF_TP_ADD_TC(tp, digest_policy);
	ATF_TP_ADD_TC(tp, random_policy);
	return (atf_no_error());
}
