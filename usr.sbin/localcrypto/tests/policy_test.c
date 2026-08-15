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
	    CRYPTODESC_RIGHT_ALL, 12, 16);
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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_profiles);
	ATF_TP_ADD_TC(tp, rejects_invalid_profiles);
	ATF_TP_ADD_TC(tp, driver_selection);
	return (atf_no_error());
}
