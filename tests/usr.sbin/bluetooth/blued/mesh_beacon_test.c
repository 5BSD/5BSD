/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh beacon layer
 * (mesh_beacon.[ch], MshPRT_v1.1 Section 3.9).
 *
 * The Secure Network beacon vectors are the canonical worked example of
 * MshPRT_v1.1 Section 8 sample data, derived from the widely published
 * NetKey 7dd7364cd842ad18c17c2b820c84c3d6:
 *
 *   NetworkID (k3)                 = 3ecaff672f673370
 *   BeaconKey  = k1(NetKey, s1("nkbk"), "id128"||0x01)
 *                                  = 5423d967da639a99cb02231a83f7d254
 *   Flags = 0x00, IV Index = 0x12345678
 *   Authentication Value           = 8ea261582f364f6f
 *   Secure Network beacon (Type 0x01 prefixed):
 *     01003ecaff672f673370123456788ea261582f364f6f
 *
 * Every expected value here was reproduced independently with the Python
 * "cryptography" package (AES-CMAC k1/k3 + the AuthValue CMAC) over the
 * Section 8 NetKey before being committed, and the NetworkID/AuthValue
 * match the published Section 8.4.3 Secure Network beacon sample, so a
 * passing test confirms the module against the spec rather than itself.
 *
 * Mesh operates in network (big-endian) byte order; no byte reversal.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_beacon.h"
#include "mesh_crypto.h"
#include "spec_mesh_beacon_oracles.h"

static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

#define	HEX(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

/* ================================================================
 * NetworkID = k3(NetKey) (Section 3.8.2.7).  Byte-exact.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_network_id);
ATF_TC_BODY(mesh_beacon_network_id, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(exp, BT_MSHPRT11_SAMPLE_NETWORK_ID_HEX,
	    BT_MSHPRT11_NETWORK_ID_SIZE);
	uint8_t netid[BT_MSHPRT11_NETWORK_ID_SIZE];

	ATF_REQUIRE_EQ(0, mesh_beacon_network_id(netkey, netid));
	ATF_CHECK_EQ_MSG(0, memcmp(netid, exp, BT_MSHPRT11_NETWORK_ID_SIZE),
	    "NetworkID (k3) does not match Section 8 sample 3ecaff672f673370");
}

/* ================================================================
 * BeaconKey = k1(NetKey, s1("nkbk"), "id128"||0x01) (Section 3.9.6.3.6).
 * Byte-exact against the published worked example.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_beaconkey);
ATF_TC_BODY(mesh_beacon_beaconkey, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(exp, BT_MSHPRT11_SAMPLE_BEACON_KEY_HEX,
	    BT_MSHPRT11_BEACON_KEY_SIZE);
	uint8_t bkey[BT_MSHPRT11_BEACON_KEY_SIZE];

	ATF_REQUIRE_EQ(0, mesh_beacon_key(netkey, bkey));
	ATF_CHECK_EQ_MSG(0, memcmp(bkey, exp, BT_MSHPRT11_BEACON_KEY_SIZE),
	    "BeaconKey does not match the Section 8 worked example");
}

/* ================================================================
 * Authentication Value = AES-CMAC(BeaconKey, Flags||NetworkID||IVIndex)[0..7]
 * for Flags=0x00, IV Index=0x12345678 (Section 3.9.3.1 / 8.4.3).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_authvalue);
ATF_TC_BODY(mesh_beacon_authvalue, tc)
{
	HEX(bkey, BT_MSHPRT11_SAMPLE_BEACON_KEY_HEX,
	    BT_MSHPRT11_BEACON_KEY_SIZE);
	HEX(netid, BT_MSHPRT11_SAMPLE_NETWORK_ID_HEX,
	    BT_MSHPRT11_NETWORK_ID_SIZE);
	HEX(exp, BT_MSHPRT11_SAMPLE_BEACON_AUTH_HEX,
	    BT_MSHPRT11_BEACON_AUTH_SIZE);
	uint8_t auth[BT_MSHPRT11_BEACON_AUTH_SIZE];

	ATF_REQUIRE_EQ(0, mesh_secure_beacon_auth(bkey, 0, 0, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth));
	ATF_CHECK_EQ_MSG(0, memcmp(auth, exp, BT_MSHPRT11_BEACON_AUTH_SIZE),
	    "AuthValue does not match Section 8.4.3 sample 8ea261582f364f6f");
}

/* ================================================================
 * Full Secure Network beacon build: byte-exact 22-octet PDU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_build);
ATF_TC_BODY(mesh_beacon_build, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(exp, BT_MSHPRT11_SAMPLE_SECURE_BEACON_HEX, BT_MSHPRT11_SECURE_BEACON_SIZE);
	uint8_t out[BT_MSHPRT11_SECURE_BEACON_SIZE];
	size_t outlen;

	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(netkey, 0, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, BT_MSHPRT11_SECURE_BEACON_SIZE,
	    "Secure Network beacon length %zu != 22", outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(out, exp, BT_MSHPRT11_SECURE_BEACON_SIZE),
	    "Secure Network beacon does not match Section 8.4.3 sample");
}

/* ================================================================
 * Parse + authenticate the canonical beacon; fields decode correctly.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_parse);
ATF_TC_BODY(mesh_beacon_parse, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(snb, BT_MSHPRT11_SAMPLE_SECURE_BEACON_HEX, BT_MSHPRT11_SECURE_BEACON_SIZE);
	HEX(netid, BT_MSHPRT11_SAMPLE_NETWORK_ID_HEX,
	    BT_MSHPRT11_NETWORK_ID_SIZE);
	HEX(auth, BT_MSHPRT11_SAMPLE_BEACON_AUTH_HEX,
	    BT_MSHPRT11_BEACON_AUTH_SIZE);
	struct mesh_secure_beacon out;

	ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out));
	ATF_CHECK_EQ(out.key_refresh, 0);
	ATF_CHECK_EQ(out.iv_update, 0);
	ATF_CHECK_EQ(out.iv_index, BT_MSHPRT11_SAMPLE_IV_INDEX);
	ATF_CHECK_EQ_MSG(0, memcmp(out.network_id, netid,
	    BT_MSHPRT11_NETWORK_ID_SIZE),
	    "parsed NetworkID mismatch");
	ATF_CHECK_EQ_MSG(0, memcmp(out.auth, auth,
	    BT_MSHPRT11_BEACON_AUTH_SIZE),
	    "parsed AuthValue mismatch");
}

/* ================================================================
 * Authentication tamper rejection: any flipped bit in the AuthValue, the
 * flags, or the IV Index must make parse fail; a wrong NetKey too.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_auth_tamper);
ATF_TC_BODY(mesh_beacon_auth_tamper, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	/* Non-normative wrong key differs from the sample in its last bit. */
	HEX(wrongkey, "7dd7364cd842ad18c17c2b820c84c3d7",
	    BT_MSHPRT11_NETKEY_SIZE);
	HEX(snb, BT_MSHPRT11_SAMPLE_SECURE_BEACON_HEX, BT_MSHPRT11_SECURE_BEACON_SIZE);
	struct mesh_secure_beacon out;

	/* Baseline: authentic beacon verifies. */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out));

	/* Flip a bit in the Authentication Value (last octet). */
	snb[BT_MSHPRT11_SECURE_AUTH_LAST_OFFSET] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out),
	    "parse accepted a corrupted Authentication Value");
	snb[BT_MSHPRT11_SECURE_AUTH_LAST_OFFSET] ^= 0x01;

	/* Flip the IV Index; the auth no longer covers it. */
	snb[BT_MSHPRT11_SECURE_IV_INDEX_OFFSET + 3] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out),
	    "parse accepted a tampered IV Index");
	snb[BT_MSHPRT11_SECURE_IV_INDEX_OFFSET + 3] ^= 0x01;

	/* Flip the Flags octet (bit0 -> key refresh). */
	snb[BT_MSHPRT11_SECURE_FLAGS_OFFSET] ^=
	    BT_MSHPRT11_BEACON_FLAG_KEY_REFRESH;
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out),
	    "parse accepted a tampered Flags octet");
	snb[BT_MSHPRT11_SECURE_FLAGS_OFFSET] ^=
	    BT_MSHPRT11_BEACON_FLAG_KEY_REFRESH;

	/* A different NetKey must not authenticate this beacon (NetworkID
	 * mismatch and/or AuthValue mismatch). */
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(wrongkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &out),
	    "parse accepted a beacon under the wrong NetKey");
}

/* ================================================================
 * Flags decode: Key Refresh (bit0) and IV Update (bit1) round-trip through
 * build/parse for all four combinations, and reserved bits are rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_flags);
ATF_TC_BODY(mesh_beacon_flags, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	uint8_t out[BT_MSHPRT11_SECURE_BEACON_SIZE];
	size_t outlen;
	struct mesh_secure_beacon parsed;
	int kr, ivu;

	for (kr = 0; kr <= 1; kr++) {
		for (ivu = 0; ivu <= 1; ivu++) {
			ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(netkey,
			    (uint8_t)kr, (uint8_t)ivu, BT_MSHPRT11_SAMPLE_IV_INDEX, out,
			    &outlen));
			/* Flags octet encodes kr in bit0, ivu in bit1. */
			ATF_CHECK_EQ_MSG(out[BT_MSHPRT11_SECURE_FLAGS_OFFSET],
			    (uint8_t)(kr * BT_MSHPRT11_BEACON_FLAG_KEY_REFRESH |
			    ivu * BT_MSHPRT11_BEACON_FLAG_IV_UPDATE),
			    "flags octet encoding wrong for kr=%d ivu=%d",
			    kr, ivu);
			ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(netkey,
			    out, BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed));
			ATF_CHECK_EQ(parsed.key_refresh, (uint8_t)kr);
			ATF_CHECK_EQ(parsed.iv_update, (uint8_t)ivu);
		}
	}

	/* A tampered unauthenticated Flags octet is still rejected. */
	ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(netkey, 0, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, &outlen));
	out[BT_MSHPRT11_SECURE_FLAGS_OFFSET] |=
	    BT_MSHPRT11_BEACON_FLAG_RFU_FIRST;
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, out,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed),
	    "parse accepted an unauthenticated Flags change");

	/* An authenticated RFU bit is ignored per Mesh 1.1 Section 1.3.2. */
	{
		uint8_t bkey[BT_MSHPRT11_BEACON_KEY_SIZE];
		uint8_t msg[1 + BT_MSHPRT11_NETWORK_ID_SIZE + 4];
		uint8_t mac[BT_MSHPRT11_BEACON_KEY_SIZE];

		ATF_REQUIRE_EQ(0, mesh_secure_beacon_build(netkey, 0, 0,
		    BT_MSHPRT11_SAMPLE_IV_INDEX, out, &outlen));
		out[BT_MSHPRT11_SECURE_FLAGS_OFFSET] =
		    BT_MSHPRT11_BEACON_FLAG_RFU_MASK;
		msg[0] = out[BT_MSHPRT11_SECURE_FLAGS_OFFSET];
		memcpy(msg + 1, out + 2, 12);
		ATF_REQUIRE_EQ(0, mesh_beacon_key(netkey, bkey));
		ATF_REQUIRE_EQ(0, mesh_aes_cmac(bkey, msg, sizeof(msg), mac));
		memcpy(out + BT_MSHPRT11_SECURE_AUTH_OFFSET, mac,
		    BT_MSHPRT11_BEACON_AUTH_SIZE);
		ATF_REQUIRE_EQ(0, mesh_secure_beacon_parse(netkey, out, outlen,
		    &parsed));
		ATF_CHECK_EQ(0, parsed.key_refresh);
		ATF_CHECK_EQ(0, parsed.iv_update);
	}
}

/* ================================================================
 * Unprovisioned Device beacon (Section 3.9.2) build/parse round trip,
 * with and without the optional URI hash.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_unprovisioned);
ATF_TC_BODY(mesh_beacon_unprovisioned, tc)
{
	/* Non-normative valid Device UUID, URI Hash, and OOB-bit sentinels. */
	HEX(uuid, "70cf7c9732a345b691494810d2e9cbf4",
	    BT_MSHPRT11_DEVICE_UUID_SIZE);
	HEX(urihash, "aabbccdd", BT_MSHPRT11_URI_HASH_SIZE);
	struct mesh_unprov_beacon in, out;
	uint8_t wire[BT_MSHPRT11_UNPROV_BEACON_MAX_SIZE];
	size_t wirelen;

	/* Without URI hash: 19 octets, type 0x00. */
	memset(&in, 0, sizeof(in));
	memcpy(in.uuid, uuid, BT_MSHPRT11_DEVICE_UUID_SIZE);
	in.oob = 0x0004;
	in.has_uri_hash = 0;
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_build(&in, wire, &wirelen));
	ATF_CHECK_EQ_MSG(wirelen, BT_MSHPRT11_UNPROV_BEACON_MIN_SIZE,
	    "unprovisioned beacon length %zu != 19", wirelen);
	ATF_CHECK_EQ(wire[0], BT_MSHPRT11_BEACON_TYPE_UNPROVISIONED);
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_parse(wire, wirelen, &out));
	ATF_CHECK_EQ_MSG(0, memcmp(out.uuid, uuid,
	    BT_MSHPRT11_DEVICE_UUID_SIZE), "UUID mismatch");
	ATF_CHECK_EQ(out.oob, 0x0004);
	ATF_CHECK_EQ(out.has_uri_hash, 0);
	/* RFU OOB Information bits are ignored, but never emitted. */
	wire[BT_MSHPRT11_UNPROV_OOB_OFFSET] |=
	    BT_MSHPRT11_UNPROV_OOB_RFU_MASK >> 8;
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_parse(wire, wirelen, &out));
	ATF_CHECK_EQ(out.oob, 0x0004);
	in.oob = BT_MSHPRT11_UNPROV_OOB_RFU_MASK;
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_build(&in, wire, &wirelen));
	in.oob = 0x0004;

	/* With URI hash: 23 octets. */
	memcpy(in.uri_hash, urihash, BT_MSHPRT11_URI_HASH_SIZE);
	in.has_uri_hash = 1;
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_build(&in, wire, &wirelen));
	ATF_CHECK_EQ_MSG(wirelen, BT_MSHPRT11_UNPROV_BEACON_MAX_SIZE,
	    "unprovisioned beacon length %zu != 23", wirelen);
	ATF_REQUIRE_EQ(0, mesh_unprov_beacon_parse(wire, wirelen, &out));
	ATF_CHECK_EQ(out.has_uri_hash, 1);
	ATF_CHECK_EQ_MSG(0, memcmp(out.uri_hash, urihash,
	    BT_MSHPRT11_URI_HASH_SIZE),
	    "URI hash mismatch");

	/* A truncated length (neither 19 nor 23) is rejected. */
	ATF_CHECK_EQ_MSG(-1, mesh_unprov_beacon_parse(wire, 20, &out),
	    "parse accepted an invalid unprovisioned beacon length");
}

/* ================================================================
 * Input-validation contract (spec-shape negative cases).  Every public
 * entry point rejects NULL pointers; the Secure Network beacon codec also
 * rejects out-of-range flag bits, a wrong Beacon Type octet and a length
 * other than the fixed 22 octets (MshPRT_v1.1 Section 3.9.3), leaving the
 * output zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_beacon_input_validation);
ATF_TC_BODY(mesh_beacon_input_validation, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(netid, BT_MSHPRT11_SAMPLE_NETWORK_ID_HEX,
	    BT_MSHPRT11_NETWORK_ID_SIZE);
	HEX(bkey, BT_MSHPRT11_SAMPLE_BEACON_KEY_HEX,
	    BT_MSHPRT11_BEACON_KEY_SIZE);
	HEX(snb, BT_MSHPRT11_SAMPLE_SECURE_BEACON_HEX, BT_MSHPRT11_SECURE_BEACON_SIZE);
	struct mesh_secure_beacon parsed;
	struct mesh_unprov_beacon ub;
	uint8_t out[BT_MSHPRT11_SECURE_BEACON_SIZE];
	uint8_t netid_out[BT_MSHPRT11_NETWORK_ID_SIZE];
	uint8_t bkey_out[BT_MSHPRT11_BEACON_KEY_SIZE];
	uint8_t auth[BT_MSHPRT11_BEACON_AUTH_SIZE];
	size_t outlen;

	memset(&ub, 0, sizeof(ub));

	/* mesh_beacon_key NULL args. */
	ATF_CHECK_EQ(-1, mesh_beacon_key(NULL, bkey_out));
	ATF_CHECK_EQ(-1, mesh_beacon_key(netkey, NULL));

	/* mesh_beacon_network_id NULL args. */
	ATF_CHECK_EQ(-1, mesh_beacon_network_id(NULL, netid_out));
	ATF_CHECK_EQ(-1, mesh_beacon_network_id(netkey, NULL));

	/* mesh_secure_beacon_auth NULL args + out-of-range flags. */
	ATF_CHECK_EQ(-1, mesh_secure_beacon_auth(NULL, 0, 0, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_auth(bkey, 0, 0, NULL,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_auth(bkey, 0, 0, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, NULL));
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_auth(bkey,
	    BT_MSHPRT11_FLAG_BOOLEAN_INVALID, 0, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth), "auth accepted key_refresh > 1");
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_auth(bkey, 0,
	    BT_MSHPRT11_FLAG_BOOLEAN_INVALID, netid,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, auth), "auth accepted iv_update > 1");

	/* mesh_secure_beacon_build NULL args + out-of-range flags. */
	ATF_CHECK_EQ(-1, mesh_secure_beacon_build(NULL, 0, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, &outlen));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_build(netkey, 0, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_build(netkey, 0, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, NULL));
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_build(netkey,
	    BT_MSHPRT11_FLAG_BOOLEAN_INVALID, 0, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, &outlen), "build accepted key_refresh > 1");
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_build(netkey, 0,
	    BT_MSHPRT11_FLAG_BOOLEAN_INVALID, BT_MSHPRT11_SAMPLE_IV_INDEX,
	    out, &outlen), "build accepted iv_update > 1");

	/* mesh_secure_beacon_parse NULL args, wrong length, wrong type. */
	ATF_CHECK_EQ(-1, mesh_secure_beacon_parse(NULL, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_parse(netkey, NULL,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed));
	ATF_CHECK_EQ(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, NULL));
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE - 1, &parsed),
	    "parse accepted a wrong-length beacon");
	snb[0] = BT_MSHPRT11_BEACON_TYPE_UNPROVISIONED;	/* wrong Beacon Type */
	ATF_CHECK_EQ_MSG(-1, mesh_secure_beacon_parse(netkey, snb,
	    BT_MSHPRT11_SECURE_BEACON_SIZE, &parsed),
	    "parse accepted a wrong Beacon Type octet");
	snb[0] = BT_MSHPRT11_BEACON_TYPE_SECURE_NETWORK;

	/* Unprovisioned beacon codec NULL args + wrong Beacon Type. */
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_build(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_build(&ub, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_build(&ub, out, NULL));
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_parse(NULL, BT_MSHPRT11_UNPROV_BEACON_MIN_SIZE,
	    &ub));
	ATF_CHECK_EQ(-1, mesh_unprov_beacon_parse(out, BT_MSHPRT11_UNPROV_BEACON_MIN_SIZE,
	    NULL));
	memset(out, 0, sizeof(out));
	out[0] = BT_MSHPRT11_BEACON_TYPE_MESH_PRIVATE;
	ATF_CHECK_EQ_MSG(-1, mesh_unprov_beacon_parse(out,
	    BT_MSHPRT11_UNPROV_BEACON_MIN_SIZE, &ub),
	    "unprov parse accepted a wrong Beacon Type octet");
}

/* ================================================================
 * Mesh Private beacon (Section 3.9.4).  No Section 8 sample vector exists in
 * MshPRT_v1.1, so these assert the round-trip (build -> parse+authenticate),
 * a distinct PrivateBeaconKey derivation, and tamper rejection.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_private_beacon_roundtrip);
ATF_TC_BODY(mesh_private_beacon_roundtrip, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(random, BT_MSHPRT11_SAMPLE_PRIVATE_RANDOM_HEX,
	    BT_MSHPRT11_PRIVATE_BEACON_RANDOM_SIZE);
	HEX(expected, BT_MSHPRT11_SAMPLE_PRIVATE_BEACON_HEX,
	    BT_MSHPRT11_PRIVATE_BEACON_SIZE);
	struct mesh_private_beacon pb;
	uint8_t out[BT_MSHPRT11_PRIVATE_BEACON_SIZE];
	size_t outlen;

	/* Build with Key Refresh=1, IV Update=0, IV Index=0x12345678. */
	ATF_REQUIRE_EQ(0, mesh_private_beacon_build(netkey, 1, 0,
	    BT_MSHPRT11_SAMPLE_IV_INDEX, random, out, &outlen));
	ATF_CHECK_EQ(BT_MSHPRT11_PRIVATE_BEACON_SIZE, outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(out, expected,
	    BT_MSHPRT11_PRIVATE_BEACON_SIZE),
	    "Mesh Private beacon differs from independent AES-CMAC/CCM oracle");
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_BEACON_TYPE_MESH_PRIVATE, out[0],
	    "private beacon must carry Beacon Type 0x02");
	/* The Random is carried in clear at octets 1..13. */
	ATF_CHECK_EQ(0, memcmp(out + BT_MSHPRT11_PRIVATE_RANDOM_OFFSET,
	    random, BT_MSHPRT11_PRIVATE_BEACON_RANDOM_SIZE));
	/* The Private Beacon Data (Flags||IV Index) is obfuscated, not clear. */
	ATF_CHECK_MSG(out[BT_MSHPRT11_PRIVATE_DATA_OFFSET] != 0x01 ||
	    out[BT_MSHPRT11_PRIVATE_DATA_OFFSET + 1] != 0x12,
	    "Private Beacon Data must be obfuscated");

	/* Parse+authenticate recovers the Flags and IV Index. */
	ATF_REQUIRE_EQ(0, mesh_private_beacon_parse(netkey, out, outlen, &pb));
	ATF_CHECK_EQ(1, pb.key_refresh);
	ATF_CHECK_EQ(0, pb.iv_update);
	ATF_CHECK_EQ(BT_MSHPRT11_SAMPLE_IV_INDEX, pb.iv_index);
	ATF_CHECK_EQ(0, memcmp(pb.random, random,
	    BT_MSHPRT11_PRIVATE_BEACON_RANDOM_SIZE));

	/* Authenticated RFU Flags are processed as zero. */
	{
		uint8_t pbkey[BT_MSHPRT11_BEACON_KEY_SIZE];
		uint8_t data[BT_MSHPRT11_PRIVATE_BEACON_DATA_SIZE] = {
		    BT_MSHPRT11_BEACON_FLAG_RFU_MASK, 0x12, 0x34, 0x56, 0x78 };

		ATF_REQUIRE_EQ(0, mesh_private_beacon_key(netkey, pbkey));
		ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(pbkey, random, NULL, 0,
		    data, sizeof(data), out + BT_MSHPRT11_PRIVATE_DATA_OFFSET,
		    out + BT_MSHPRT11_PRIVATE_TAG_OFFSET,
		    BT_MSHPRT11_PRIVATE_BEACON_TAG_SIZE));
		ATF_REQUIRE_EQ(0, mesh_private_beacon_parse(netkey, out, outlen,
		    &pb));
		ATF_CHECK_EQ(0, pb.key_refresh);
		ATF_CHECK_EQ(0, pb.iv_update);
	}
}

ATF_TC_WITHOUT_HEAD(mesh_private_beacon_key_distinct);
ATF_TC_BODY(mesh_private_beacon_key_distinct, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	HEX(expected, BT_MSHPRT11_SAMPLE_PRIVATE_BEACON_KEY_HEX,
	    BT_MSHPRT11_BEACON_KEY_SIZE);
	uint8_t pbkey[BT_MSHPRT11_BEACON_KEY_SIZE];
	uint8_t bkey[BT_MSHPRT11_BEACON_KEY_SIZE];

	/* PrivateBeaconKey ("nkpk") differs from the BeaconKey ("nkbk"). */
	ATF_REQUIRE_EQ(0, mesh_private_beacon_key(netkey, pbkey));
	ATF_REQUIRE_EQ(0, mesh_beacon_key(netkey, bkey));
	ATF_CHECK_EQ_MSG(0, memcmp(pbkey, expected,
	    BT_MSHPRT11_BEACON_KEY_SIZE),
	    "PrivateBeaconKey differs from independent k1 oracle");
	ATF_CHECK_MSG(memcmp(pbkey, bkey, BT_MSHPRT11_BEACON_KEY_SIZE) != 0,
	    "PrivateBeaconKey must differ from BeaconKey");
}

ATF_TC_WITHOUT_HEAD(mesh_private_beacon_tamper);
ATF_TC_BODY(mesh_private_beacon_tamper, tc)
{
	HEX(netkey, BT_MSHPRT11_SAMPLE_NETKEY_HEX, BT_MSHPRT11_NETKEY_SIZE);
	/* Non-normative independent wrong-key sentinel. */
	HEX(wrongkey, "00112233445566778899aabbccddeeff",
	    BT_MSHPRT11_NETKEY_SIZE);
	HEX(out, BT_MSHPRT11_SAMPLE_PRIVATE_BEACON_HEX,
	    BT_MSHPRT11_PRIVATE_BEACON_SIZE);
	struct mesh_private_beacon pb;
	size_t outlen = BT_MSHPRT11_PRIVATE_BEACON_SIZE;

	ATF_REQUIRE_EQ(0, mesh_private_beacon_parse(netkey, out, outlen, &pb));

	/* Wrong NetKey -> Authentication Tag fails. */
	ATF_CHECK_EQ_MSG(-1, mesh_private_beacon_parse(wrongkey, out, outlen,
	    &pb), "private beacon accepted under the wrong NetKey");

	/* Flip an obfuscated-data octet -> tag mismatch. */
	out[BT_MSHPRT11_PRIVATE_DATA_OFFSET] ^= 0x01;
	ATF_CHECK_EQ(-1, mesh_private_beacon_parse(netkey, out, outlen, &pb));
	out[BT_MSHPRT11_PRIVATE_DATA_OFFSET] ^= 0x01;

	/* Flip a tag octet -> mismatch. */
	out[BT_MSHPRT11_PRIVATE_TAG_OFFSET] ^= 0x80;
	ATF_CHECK_EQ(-1, mesh_private_beacon_parse(netkey, out, outlen, &pb));
	out[BT_MSHPRT11_PRIVATE_TAG_OFFSET] ^= 0x80;

	/* Wrong length / Beacon Type are rejected. */
	ATF_CHECK_EQ(-1, mesh_private_beacon_parse(netkey, out, outlen - 1,
	    &pb));
	out[0] = BT_MSHPRT11_BEACON_TYPE_SECURE_NETWORK;
	ATF_CHECK_EQ(-1, mesh_private_beacon_parse(netkey, out, outlen, &pb));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_beacon_network_id);
	ATF_TP_ADD_TC(tp, mesh_beacon_beaconkey);
	ATF_TP_ADD_TC(tp, mesh_beacon_authvalue);
	ATF_TP_ADD_TC(tp, mesh_beacon_build);
	ATF_TP_ADD_TC(tp, mesh_beacon_parse);
	ATF_TP_ADD_TC(tp, mesh_beacon_auth_tamper);
	ATF_TP_ADD_TC(tp, mesh_beacon_flags);
	ATF_TP_ADD_TC(tp, mesh_beacon_unprovisioned);
	ATF_TP_ADD_TC(tp, mesh_beacon_input_validation);
	ATF_TP_ADD_TC(tp, mesh_private_beacon_roundtrip);
	ATF_TP_ADD_TC(tp, mesh_private_beacon_key_distinct);
	ATF_TP_ADD_TC(tp, mesh_private_beacon_tamper);

	return (atf_no_error());
}
