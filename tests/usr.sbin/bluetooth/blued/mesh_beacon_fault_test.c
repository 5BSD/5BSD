/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the CMAC/derivation FAILURE arms of the
 * Bluetooth Mesh beacon layer (mesh_beacon.c, MshPRT_v1.1 Section 3.9).
 *
 * mesh_beacon_key(), mesh_beacon_network_id() (k3), mesh_secure_beacon_auth()
 * (AES-CMAC), and the build/parse drivers each guard their crypto-toolbox
 * calls with a "... != 0 -> bail out (output zeroed)" arm.  On the valid
 * NetKey inputs these functions receive, the toolbox never fails, so those
 * arms are unreachable by ordinary use.  We reach them with a linker
 * --wrap(3) seam on the single OpenSSL primitive every AES-CMAC issues
 * exactly once -- EVP_MAC_init.  Failing EVP_MAC_init at ordinal N fails the
 * Nth CMAC in a beacon operation, driving that step's error branch.
 *
 * CMAC ordinals inside a beacon operation:
 *   mesh_beacon_network_id -> k3   : s1, T, id64          = 3 CMACs
 *   mesh_beacon_key        -> s1+k1: s1("nkbk"), T, P     = 3 CMACs
 *   mesh_secure_beacon_auth        : 1 CMAC
 * so in build()/parse() (network_id, then beacon_key, then auth):
 *   #1 = network_id's first CMAC, #4 = beacon_key's first, #7 = auth.
 *
 * Oracle: mesh_beacon.h's documented contract -- each function returns -1 on
 * any derivation failure with its output left zeroed.  The spec KAT success
 * values live in mesh_beacon_test.c.  Mirrors the smp_fault_test /
 * mesh_sim_fault_test --wrap seams.
 *
 * Requires the parent Makefile to wrap the symbol (LDFLAGS):
 *   -Wl,--wrap=EVP_MAC_init
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "mesh_beacon.h"
#include "spec_mesh_beacon_oracles.h"

/* ---- fault seam: fail the Nth (1-based) EVP_MAC_init call. ---- */
static long fi_init_at, fi_init_n;

static void
fault_reset(void)
{

	fi_init_at = 0;
	fi_init_n = 0;
}

extern int	__real_EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *,
		    size_t, const OSSL_PARAM *);
int
__wrap_EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{

	fi_init_n++;
	if (fi_init_at != 0 && fi_init_n == fi_init_at)
		return (0);
	return (__real_EVP_MAC_init(ctx, key, keylen, params));
}

/* ---- Section 8 worked-example NetKey (see mesh_beacon_test.c). ---- */
static const uint8_t NETKEY[BT_MSHPRT11_NETKEY_SIZE] = {
	BT_MSHPRT11_SAMPLE_NETKEY_BYTES
};

static int
all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

/* ================================================================
 * mesh_beacon_key(): s1 failure (CMAC #1) and k1 failure (CMAC #2/#3).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_beacon_key);
ATF_TC_BODY(fault_beacon_key, tc)
{
	uint8_t bkey[BT_MSHPRT11_BEACON_KEY_SIZE];

	/* s1("nkbk") is CMAC #1. */
	fault_reset();
	fi_init_at = 1;
	memset(bkey, 0xa5, sizeof(bkey));
	ATF_CHECK_EQ(-1, mesh_beacon_key(NETKEY, bkey));
	ATF_CHECK(all_zero(bkey, BT_MSHPRT11_BEACON_KEY_SIZE));

	/* k1's first internal CMAC is #2 -> k1 fails -> output zeroed. */
	fault_reset();
	fi_init_at = 2;
	memset(bkey, 0xa5, sizeof(bkey));
	ATF_CHECK_EQ(-1, mesh_beacon_key(NETKEY, bkey));
	ATF_CHECK(all_zero(bkey, BT_MSHPRT11_BEACON_KEY_SIZE));
}

/* ================================================================
 * mesh_secure_beacon_auth(): the single AES-CMAC failure arm.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_beacon_auth);
ATF_TC_BODY(fault_beacon_auth, tc)
{
	uint8_t bkey[BT_MSHPRT11_BEACON_KEY_SIZE] = { 0 };
	uint8_t netid[BT_MSHPRT11_NETWORK_ID_SIZE] = { 0 };
	uint8_t auth[BT_MSHPRT11_BEACON_AUTH_SIZE];

	fault_reset();
	fi_init_at = 1;
	memset(auth, 0xa5, sizeof(auth));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_auth(bkey, 0, 0, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth));
	ATF_CHECK(all_zero(auth, BT_MSHPRT11_BEACON_AUTH_SIZE));
}

/* ================================================================
 * mesh_secure_beacon_build(): network_id (#1), beacon_key (#4) and
 * auth (#7) failures each abort with the output zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_beacon_build);
ATF_TC_BODY(fault_beacon_build, tc)
{
	uint8_t out[BT_MSHPRT11_SECURE_BEACON_SIZE];
	size_t outlen;
	int at;
	const int fail_at[3] = { 1, 4, 7 };

	for (at = 0; at < 3; at++) {
		fault_reset();
		fi_init_at = fail_at[at];
		memset(out, 0xa5, sizeof(out));
		outlen = 99;
		ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_build(NETKEY, 0, 0,
		    BT_MSHPRT11_SAMPLE_IV_INDEX, out, &outlen),
		    "build survived a derivation failure at CMAC #%d",
		    fail_at[at]);
		ATF_CHECK(all_zero(out, BT_MSHPRT11_SECURE_BEACON_SIZE));
		ATF_CHECK_EQ(0, outlen);
	}
}

/* ================================================================
 * mesh_secure_beacon_parse(): network_id (#1), beacon_key (#4) and
 * auth (#7) failures each reject the (otherwise authentic) beacon.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_beacon_parse);
ATF_TC_BODY(fault_beacon_parse, tc)
{
	uint8_t snb[BT_MSHPRT11_SECURE_BEACON_SIZE];
	struct mesh_secure_beacon parsed;
	size_t outlen;
	int at;
	const int fail_at[3] = { 1, 4, 7 };

	/* Build one authentic beacon (unarmed). */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(NETKEY, 0, 0,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, snb, &outlen));
	ATF_REQUIRE_EQ(BT_MSHPRT11_SECURE_BEACON_SIZE, outlen);

	for (at = 0; at < 3; at++) {
		fault_reset();
		fi_init_at = fail_at[at];
		memset(&parsed, 0xa5, sizeof(parsed));
		ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(NETKEY, snb,
		    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed),
		    "parse accepted a beacon despite a derivation failure at "
		    "CMAC #%d", fail_at[at]);
	}

	/* Sanity: unarmed, the same beacon authenticates. */
	fault_reset();
	ATF_CHECK_EQ(0, mesh_secure_beacon_parse(NETKEY, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_beacon_key);
	ATF_TP_ADD_TC(tp, fault_beacon_auth);
	ATF_TP_ADD_TC(tp, fault_beacon_build);
	ATF_TP_ADD_TC(tp, fault_beacon_parse);

	return (atf_no_error());
}
