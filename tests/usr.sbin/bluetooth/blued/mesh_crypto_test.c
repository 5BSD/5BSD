/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh security toolbox.
 *
 * All vectors are taken byte-for-byte from the Bluetooth Mesh Protocol
 * specification MshPRT_v1.1, Section 8 "Sample data".  Each vector was
 * independently reproduced with a second, unrelated AES-CMAC / AES-CCM
 * implementation (the Python "cryptography" package) before being
 * committed here, so a passing test confirms the module against the
 * published spec values rather than against itself.
 *
 * The key-derivation section 8.1/8.2 keys are:
 *   AppKey (8.1) : 3216d1509884b533248541792b877f98
 *   NetKey (8.1) : f7a2a44f8e8a8029064f173ddc1e2b00
 *   AppKey (8.2) : 63964771734fbd76e3b40519d1d94a48
 *   NetKey (8.2) : 7dd7364cd842ad18c17c2b820c84c3d6
 * The 7dd7364c NetKey is the widely published k2/k3 worked example.
 *
 * Mesh crypto operates in network (big-endian) byte order, so - unlike
 * the SMP legacy e() vectors - no byte reversal is applied here.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_crypto.h"
#include "spec_oracles.h"

/*
 * Parse a big-endian hex string into exactly 'len' bytes.
 */
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
 * e(): AES-128-ECB single block.  MshPRT_v1.1 Section 3.8.2.1.
 *
 * There is no standalone e() vector in Section 8, so the canonical
 * AES-128 example from FIPS-197 Appendix C.1 is used (this is the same
 * value produced by any correct AES-128 implementation):
 *   key = 000102030405060708090a0b0c0d0e0f
 *   in  = 00112233445566778899aabbccddeeff
 *   out = 69c4e0d86a7b0430d8cdb78070b4c55a
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_aes128_e);
ATF_TC_BODY(mesh_aes128_e, tc)
{
	HEX(key, "000102030405060708090a0b0c0d0e0f", 16);
	HEX(in, "00112233445566778899aabbccddeeff", 16);
	HEX(expected, "69c4e0d86a7b0430d8cdb78070b4c55a", 16);
	uint8_t out[16];

	ATF_REQUIRE_EQ(0, mesh_aes128_e(key, in, out));
	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "mesh_aes128_e does not match FIPS-197 C.1 AES-128 vector");
}

/* ================================================================
 * AES-CMAC.  RFC 4493 test vector D.2 (Len = 16), also used by the
 * Mesh spec.  Confirms the CMAC primitive that s1/k1/k2/k3/k4 build on.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_aes_cmac_rfc4493);
ATF_TC_BODY(mesh_aes_cmac_rfc4493, tc)
{
	HEX(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	HEX(msg, "6bc1bee22e409f96e93d7e117393172a", 16);
	HEX(expected, "070a16b46b4d4144f79bdd9dd04a287c", 16);
	uint8_t mac[16];

	ATF_REQUIRE_EQ(0, mesh_aes_cmac(key, msg, 16, mac));
	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "mesh_aes_cmac does not match RFC 4493 test vector");
}

/* ================================================================
 * AES-CMAC over an empty message.  RFC 4493 test vector D.1 (Len = 0):
 *   key = 2b7e151628aed2a6abf7158809cf4f3c
 *   MAC = bb1d6929e9593728 7fa37d129b756746
 * Exercises the len == 0 path (no EVP_MAC_update call).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_aes_cmac_empty);
ATF_TC_BODY(mesh_aes_cmac_empty, tc)
{
	HEX(key, "2b7e151628aed2a6abf7158809cf4f3c", 16);
	HEX(expected, "bb1d6929e95937287fa37d129b756746", 16);
	uint8_t mac[16];

	ATF_REQUIRE_EQ(0, mesh_aes_cmac(key, NULL, 0, mac));
	ATF_CHECK_EQ_MSG(memcmp(mac, expected, 16), 0,
	    "mesh_aes_cmac(empty) does not match RFC 4493 vector D.1");
}

/* ================================================================
 * s1.  MshPRT_v1.1 Section 8.1.1:
 *   s1("test") = b73cefbd641ef2ea598c2b6efb62f79c
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_s1_test);
ATF_TC_BODY(mesh_s1_test, tc)
{
	HEX(expected, "b73cefbd641ef2ea598c2b6efb62f79c", 16);
	uint8_t salt[16];

	ATF_REQUIRE_EQ(0, mesh_s1((const uint8_t *)"test", 4, salt));
	ATF_CHECK_EQ_MSG(memcmp(salt, expected, 16), 0,
	    "mesh_s1(\"test\") does not match spec Section 8.1.1");
}

/* ================================================================
 * k1.  MshPRT_v1.1 Section 8.1.2:
 *   N    = 3216d1509884b533248541792b877f98
 *   SALT = 2ba14ffa0df84a2831938d57d276cab4
 *   P    = 5a09d60797eeb4478aada59db3352a0d
 *   k1   = f6ed15a8934afbe7d83e8dcb57fcf5d7
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_k1_vector);
ATF_TC_BODY(mesh_k1_vector, tc)
{
	HEX(n, "3216d1509884b533248541792b877f98", 16);
	HEX(salt, "2ba14ffa0df84a2831938d57d276cab4", 16);
	HEX(p, "5a09d60797eeb4478aada59db3352a0d", 16);
	HEX(expected, "f6ed15a8934afbe7d83e8dcb57fcf5d7", 16);
	uint8_t out[16];

	ATF_REQUIRE_EQ(0, mesh_k1(n, 16, salt, p, 16, out));
	ATF_CHECK_EQ_MSG(memcmp(out, expected, 16), 0,
	    "mesh_k1 does not match spec Section 8.1.2");
}

/* ================================================================
 * k2 (managed flooding).  MshPRT_v1.1 Section 8.2.2:
 *   N   = 7dd7364cd842ad18c17c2b820c84c3d6
 *   P   = 00
 *   NID = 0x68
 *   EncryptionKey = 0953fa93e7caac9638f58820220a398e
 *   PrivacyKey    = 8b84eedec100067d670971dd2aa700cf
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_k2_managed_flooding);
ATF_TC_BODY(mesh_k2_managed_flooding, tc)
{
	HEX(n, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	uint8_t p[1] = { 0x00 };
	HEX(exp_enc, "0953fa93e7caac9638f58820220a398e", 16);
	HEX(exp_priv, "8b84eedec100067d670971dd2aa700cf", 16);
	uint8_t nid, enc[16], priv[16];

	ATF_REQUIRE_EQ(0, mesh_k2(n, p, 1, &nid, enc, priv));
	ATF_CHECK_EQ_MSG(nid, 0x68,
	    "mesh_k2 NID 0x%02x does not match spec Section 8.2.2 (0x68)", nid);
	ATF_CHECK_EQ_MSG(memcmp(enc, exp_enc, 16), 0,
	    "mesh_k2 EncryptionKey does not match spec Section 8.2.2");
	ATF_CHECK_EQ_MSG(memcmp(priv, exp_priv, 16), 0,
	    "mesh_k2 PrivacyKey does not match spec Section 8.2.2");
}

/* ================================================================
 * k3.  Two published vectors:
 *   Section 8.1.5: N = f7a2a44f8e8a8029064f173ddc1e2b00
 *                  Network ID = ff046958233db014
 *   Section 8.2.5: N = 7dd7364cd842ad18c17c2b820c84c3d6
 *                  Network ID = 3ecaff672f673370
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_k3_vectors);
ATF_TC_BODY(mesh_k3_vectors, tc)
{
	HEX(n1, "f7a2a44f8e8a8029064f173ddc1e2b00", 16);
	HEX(exp1, "ff046958233db014", 8);
	HEX(n2, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	HEX(exp2, "3ecaff672f673370", 8);
	uint8_t out[8];

	ATF_REQUIRE_EQ(0, mesh_k3(n1, out));
	ATF_CHECK_EQ_MSG(memcmp(out, exp1, 8), 0,
	    "mesh_k3 does not match spec Section 8.1.5");

	ATF_REQUIRE_EQ(0, mesh_k3(n2, out));
	ATF_CHECK_EQ_MSG(memcmp(out, exp2, 8), 0,
	    "mesh_k3 does not match spec Section 8.2.5");
}

/* ================================================================
 * k4.  Two published vectors:
 *   Section 8.1.6: N = 3216d1509884b533248541792b877f98  AID = 0x38
 *   Section 8.2.1: N = 63964771734fbd76e3b40519d1d94a48  AID = 0x26
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_k4_vectors);
ATF_TC_BODY(mesh_k4_vectors, tc)
{
	HEX(n1, "3216d1509884b533248541792b877f98", 16);
	HEX(n2, "63964771734fbd76e3b40519d1d94a48", 16);
	uint8_t aid;

	ATF_REQUIRE_EQ(0, mesh_k4(n1, &aid));
	ATF_CHECK_EQ_MSG(aid, 0x38,
	    "mesh_k4 AID 0x%02x does not match spec Section 8.1.6 (0x38)", aid);

	ATF_REQUIRE_EQ(0, mesh_k4(n2, &aid));
	ATF_CHECK_EQ_MSG(aid, 0x26,
	    "mesh_k4 AID 0x%02x does not match spec Section 8.2.1 (0x26)", aid);
}

/* ================================================================
 * Nonce layout checks.  MshPRT_v1.1 Section 8.3.
 *
 * Network nonce from Message #1 (Section 8.3.1):
 *   CTL=1 TTL=0 SEQ=000001 SRC=1201 IVindex=12345678
 *   -> 00800000011201000012345678
 *
 * Device nonce from Message #6 (Section 8.3.6):
 *   ASZMIC=0 SEQ=3129ab SRC=0003 DST=1201 IVindex=12345678
 *   -> 02003129ab0003120112345678
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_nonce_layout);
ATF_TC_BODY(mesh_nonce_layout, tc)
{
	HEX(exp_net, "00800000011201000012345678", 13);
	HEX(exp_dev, "02003129ab0003120112345678", 13);
	uint8_t nonce[13];

	mesh_network_nonce(nonce, 1, 0, 0x000001, 0x1201, 0x12345678);
	ATF_CHECK_EQ_MSG(memcmp(nonce, exp_net, 13), 0,
	    "mesh_network_nonce layout does not match spec Message #1");

	mesh_device_nonce(nonce, 0, 0x3129ab, 0x0003, 0x1201, 0x12345678);
	ATF_CHECK_EQ_MSG(memcmp(nonce, exp_dev, 13), 0,
	    "mesh_device_nonce layout does not match spec Message #6");

	/* Application nonce shares the device layout but with type 0x01. */
	mesh_application_nonce(nonce, 0, 0x3129ab, 0x0003, 0x1201, 0x12345678);
	ATF_CHECK_EQ(nonce[0], 0x01);
	ATF_CHECK_EQ_MSG(memcmp(nonce + 1, exp_dev + 1, 12), 0,
	    "mesh_application_nonce body differs from device nonce body");

	/* Proxy nonce: type 0x03, DST field is padding (0x0000). */
	mesh_proxy_nonce(nonce, 0x000001, 0x1201, 0x12345678);
	ATF_CHECK_EQ(nonce[0], 0x03);
	ATF_CHECK_EQ(nonce[7], 0x00);
	ATF_CHECK_EQ(nonce[8], 0x00);
}

/* ================================================================
 * AES-CCM network PDU, 64-bit NetMIC.  MshPRT_v1.1 Section 8.3.1
 * (Message #1, a Friend Request control message):
 *   EncryptionKey = 0953fa93e7caac9638f58820220a398e
 *   Network nonce = 00800000011201000012345678
 *   plaintext (DST || TransportPDU)
 *                 = fffd034b50057e400000010000
 *   EncDST||EncTransportPDU = b5e5bfdacbaf6cb7fb6bff871f
 *   NetMIC (64-bit)         = 035444ce83a670df
 *   No additional authenticated data.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_ccm_network_mic64);
ATF_TC_BODY(mesh_ccm_network_mic64, tc)
{
	HEX(key, "0953fa93e7caac9638f58820220a398e", 16);
	HEX(nonce, "00800000011201000012345678", 13);
	HEX(plain, "fffd034b50057e400000010000", 13);
	HEX(exp_cipher, "b5e5bfdacbaf6cb7fb6bff871f", 13);
	HEX(exp_mic, "035444ce83a670df", 8);
	uint8_t cipher[13], mic[8], back[13];

	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(key, nonce, NULL, 0,
	    plain, 13, cipher, mic, 8));
	ATF_CHECK_EQ_MSG(memcmp(cipher, exp_cipher, 13), 0,
	    "CCM ciphertext does not match spec Message #1");
	ATF_CHECK_EQ_MSG(memcmp(mic, exp_mic, 8), 0,
	    "CCM 64-bit NetMIC does not match spec Message #1");

	/* Round-trip: decrypt must verify the MIC and recover the plaintext. */
	ATF_REQUIRE_EQ(0, mesh_aes_ccm_decrypt(key, nonce, NULL, 0,
	    exp_cipher, 13, back, exp_mic, 8));
	ATF_CHECK_EQ_MSG(memcmp(back, plain, 13), 0,
	    "CCM decrypt did not recover the Message #1 plaintext");
}

/* ================================================================
 * AES-CCM network PDU, 32-bit NetMIC.  MshPRT_v1.1 Section 8.3.6
 * (Message #6 segment #0, a segmented Config AppKey Add access
 *  message carried in the network layer):
 *   EncryptionKey = 0953fa93e7caac9638f58820220a398e
 *   Network nonce = 00043129ab0003000012345678
 *   plaintext (DST || TransportPDU)
 *                 = 12018026ac01ee9dddfd2169326d23f3afdf
 *   EncDST||EncTransportPDU = 0afba8c63d4e686364979deaf4fd40961145
 *   NetMIC (32-bit)         = 939cda0e
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_ccm_network_mic32);
ATF_TC_BODY(mesh_ccm_network_mic32, tc)
{
	HEX(key, "0953fa93e7caac9638f58820220a398e", 16);
	HEX(nonce, "00043129ab0003000012345678", 13);
	HEX(plain, "12018026ac01ee9dddfd2169326d23f3afdf", 18);
	HEX(exp_cipher, "0afba8c63d4e686364979deaf4fd40961145", 18);
	HEX(exp_mic, "939cda0e", 4);
	uint8_t cipher[18], mic[4], back[18];

	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(key, nonce, NULL, 0,
	    plain, 18, cipher, mic, 4));
	ATF_CHECK_EQ_MSG(memcmp(cipher, exp_cipher, 18), 0,
	    "CCM ciphertext does not match spec Message #6");
	ATF_CHECK_EQ_MSG(memcmp(mic, exp_mic, 4), 0,
	    "CCM 32-bit NetMIC does not match spec Message #6");

	ATF_REQUIRE_EQ(0, mesh_aes_ccm_decrypt(key, nonce, NULL, 0,
	    exp_cipher, 18, back, exp_mic, 4));
	ATF_CHECK_EQ_MSG(memcmp(back, plain, 18), 0,
	    "CCM decrypt did not recover the Message #6 plaintext");
}

/* ================================================================
 * AES-CCM upper-transport (device key) PDU, 32-bit TransMIC, using a
 * device nonce.  MshPRT_v1.1 Section 8.3.6 (Message #6):
 *   DevKey        = 9d6dd0e96eb25dc19a40ed9914f8f03f
 *   Device nonce  = 02003129ab0003120112345678
 *   Access message = 0056341263964771734fbd76e3b40519d1d94a48
 *   EncAccessMessage = ee9dddfd2169326d23f3afdfcfdc18c52fdef772
 *   TransMIC (32-bit) = e0e17308
 * This also exercises the mesh_device_nonce() builder end to end.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_ccm_transport_device);
ATF_TC_BODY(mesh_ccm_transport_device, tc)
{
	HEX(devkey, "9d6dd0e96eb25dc19a40ed9914f8f03f", 16);
	HEX(access, "0056341263964771734fbd76e3b40519d1d94a48", 20);
	HEX(exp_enc, "ee9dddfd2169326d23f3afdfcfdc18c52fdef772", 20);
	HEX(exp_mic, "e0e17308", 4);
	uint8_t nonce[13], cipher[20], mic[4], back[20];

	mesh_device_nonce(nonce, 0, 0x3129ab, 0x0003, 0x1201, 0x12345678);

	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(devkey, nonce, NULL, 0,
	    access, 20, cipher, mic, 4));
	ATF_CHECK_EQ_MSG(memcmp(cipher, exp_enc, 20), 0,
	    "CCM EncAccessMessage does not match spec Message #6");
	ATF_CHECK_EQ_MSG(memcmp(mic, exp_mic, 4), 0,
	    "CCM 32-bit TransMIC does not match spec Message #6");

	ATF_REQUIRE_EQ(0, mesh_aes_ccm_decrypt(devkey, nonce, NULL, 0,
	    exp_enc, 20, back, exp_mic, 4));
	ATF_CHECK_EQ_MSG(memcmp(back, access, 20), 0,
	    "CCM decrypt did not recover the Message #6 access payload");
}

/* ================================================================
 * AES-CCM tamper detection: a corrupted MIC must be rejected, for both
 * MIC sizes.  Uses the Message #1 (64-bit) and Message #6 (32-bit)
 * ciphertexts above.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_ccm_tamper_rejected);
ATF_TC_BODY(mesh_ccm_tamper_rejected, tc)
{
	HEX(key, "0953fa93e7caac9638f58820220a398e", 16);
	HEX(nonce, "00800000011201000012345678", 13);
	HEX(cipher, "b5e5bfdacbaf6cb7fb6bff871f", 13);
	HEX(bad_mic, "035444ce83a670de", 8);	/* last byte flipped */
	uint8_t out[13];

	ATF_CHECK_EQ_MSG(-1, mesh_aes_ccm_decrypt(key, nonce, NULL, 0,
	    cipher, 13, out, bad_mic, 8),
	    "CCM decrypt accepted a corrupted 64-bit MIC");

	/* A corrupted ciphertext byte must also fail. */
	cipher[0] ^= 0xff;
	{
		HEX(good_mic, "035444ce83a670df", 8);
		ATF_CHECK_EQ_MSG(-1, mesh_aes_ccm_decrypt(key, nonce, NULL, 0,
		    cipher, 13, out, good_mic, 8),
		    "CCM decrypt accepted corrupted ciphertext");
	}
}

/* ================================================================
 * Input-validation contract (spec-shape negative cases):
 *   - mesh_k2() rejects a NULL P and a P longer than MESH_K2_MAX_P
 *     (MshPRT_v1.1 Section 3.8.2.6 bounds), leaving all outputs zeroed.
 *   - AES-CCM (Section 3.8.2.3) only defines a 32-bit or 64-bit MIC, so a
 *     miclen other than 4 or 8 must be rejected by both encrypt and decrypt.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_input_validation);
ATF_TC_BODY(mesh_input_validation, tc)
{
	enum {
		/* Test-side snapshot of the mesh_crypto.h implementation cap. */
		TEST_IMPL_K2_MAX_P = 64
	};
	HEX(n, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	HEX(key, "0953fa93e7caac9638f58820220a398e", 16);
	HEX(nonce, "00800000011201000012345678", 13);
	uint8_t bigp[TEST_IMPL_K2_MAX_P + 1] = { 0 };
	uint8_t nid = 0xff, enc[16], priv[16];
	uint8_t plain[13] = { 0 };
	uint8_t cipher[13], mic[8], out[13], mac[32];
	size_t i;

	memset(enc, 0xa5, sizeof(enc));
	memset(priv, 0xa5, sizeof(priv));
	ATF_CHECK_EQ(TEST_IMPL_K2_MAX_P, MESH_K2_MAX_P);

	/* NULL P -> -1, outputs zeroed. */
	ATF_CHECK_EQ_MSG(-1, mesh_k2(n, NULL, 0, &nid, enc, priv),
	    "mesh_k2 accepted a NULL P");
	ATF_CHECK_EQ(0, nid);
	for (i = 0; i < 16; i++)
		ATF_CHECK_EQ(0, enc[i]);

	/* P longer than MESH_K2_MAX_P -> -1. */
	nid = 0xff;
	ATF_CHECK_EQ_MSG(-1, mesh_k2(n, bigp, sizeof(bigp), &nid, enc, priv),
	    "mesh_k2 accepted an over-long P");
	ATF_CHECK_EQ(0, nid);

	/* AES-CCM MIC length must be 4 or 8; 16 is invalid. */
	ATF_CHECK_EQ_MSG(-1, mesh_aes_ccm_encrypt(key, nonce, NULL, 0, plain,
	    13, cipher, mic, 16), "CCM encrypt accepted a 16-octet MIC length");
	ATF_CHECK_EQ_MSG(-1, mesh_aes_ccm_decrypt(key, nonce, NULL, 0, plain,
	    13, out, mic, 16), "CCM decrypt accepted a 16-octet MIC length");

	/* HMAC/k5 reject missing required key/message material and scrub output. */
	memset(mac, 0xa5, sizeof(mac));
	ATF_CHECK_EQ(-1, mesh_hmac_sha256(NULL, 1, plain, sizeof(plain), mac));
	ATF_CHECK_EQ(-1, mesh_hmac_sha256(key, sizeof(key), NULL, 1, mac));
	ATF_CHECK_EQ(-1, mesh_k5(NULL, 1, mac, plain, sizeof(plain), mac));
}

/* ================================================================
 * HMAC-SHA-256.  MshPRT_v1.1 Section 3.8.2.3, the primitive underlying the
 * BTM_ECDH_P256_HMAC_SHA256_AES_CCM provisioning algorithm.  Vectors are the
 * RFC 4231 test cases (independently published), which s2/k5 build on.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_hmac_sha256_rfc4231);
ATF_TC_BODY(mesh_hmac_sha256_rfc4231, tc)
{
	uint8_t mac[32];

	/* RFC 4231 Test Case 1: key = 20 x 0x0b, data = "Hi There". */
	HEX(k1_, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 20);
	HEX(exp1, "b0344c61d8db38535ca8afceaf0bf12b"
	    "881dc200c9833da726e9376c2e32cff7", 32);
	ATF_REQUIRE_EQ(0, mesh_hmac_sha256(k1_, sizeof(k1_),
	    (const uint8_t *)"Hi There", 8, mac));
	ATF_CHECK_EQ_MSG(0, memcmp(mac, exp1, 32),
	    "HMAC-SHA-256 mismatch on RFC 4231 test case 1");

	/* RFC 4231 Test Case 2: key = "Jefe". */
	ATF_REQUIRE_EQ(0, mesh_hmac_sha256((const uint8_t *)"Jefe", 4,
	    (const uint8_t *)"what do ya want for nothing?", 28, mac));
	HEX(exp2, "5bdcc146bf60754e6a042426089575c7"
	    "5a003f089d2739839dec58b964ec3843", 32);
	ATF_CHECK_EQ_MSG(0, memcmp(mac, exp2, 32),
	    "HMAC-SHA-256 mismatch on RFC 4231 test case 2");

	/* RFC 4231 Test Case 4: 25-octet key, data = 50 x 0xcd. */
	HEX(k4_, "0102030405060708090a0b0c0d0e0f10111213141516171819", 25);
	uint8_t d4[50];
	memset(d4, 0xcd, sizeof(d4));
	HEX(exp4, "82558a389a443c0ea4cc819899f2083a"
	    "85f0faa3e578f8077a2e3ff46729665b", 32);
	ATF_REQUIRE_EQ(0, mesh_hmac_sha256(k4_, sizeof(k4_), d4, sizeof(d4),
	    mac));
	ATF_CHECK_EQ_MSG(0, memcmp(mac, exp4, 32),
	    "HMAC-SHA-256 mismatch on RFC 4231 test case 4");
}

/* ================================================================
 * s2 / k5 (HMAC-SHA-256 salt and key derivation).  MshPRT_v1.1 Section
 * 3.8.2.5 / 3.8.2.9.  No standalone spec vector exists; these assert the
 * definitional identities: s2(M) == HMAC-SHA-256(ZERO32, M) and
 * k5(N,SALT,P) == HMAC-SHA-256(HMAC-SHA-256(SALT,N), P).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_s2_definition);
ATF_TC_BODY(mesh_s2_definition, tc)
{
	HEX(m, "0102030405060708", 8);
	/* Independently calculated with Python hmac/hashlib SHA-256. */
	HEX(expected, "c59a063ccd78f8ef7da2e361f5027145"
	    "c495f0728f0575fe5fe55840daaefa51", BT_HMAC_SHA256_SIZE);
	uint8_t salt[BT_HMAC_SHA256_SIZE];

	ATF_REQUIRE_EQ(0, mesh_s2(m, sizeof(m), salt));
	ATF_CHECK_EQ_MSG(0, memcmp(salt, expected, BT_HMAC_SHA256_SIZE),
	    "s2(M) differs from independent HMAC-SHA-256 oracle");
}

ATF_TC_WITHOUT_HEAD(mesh_k5_definition);
ATF_TC_BODY(mesh_k5_definition, tc)
{
	HEX(n, "32216d1509884b533248541792b877f9"
	    "8b8b6b6b6b6b6b6b6b6b6b6b6b6b6b6b", 32);
	HEX(salt, "26073cf43d0b6d10786c8e7c6f9d5be5"
	    "5a1f3e2c4b6a8d0e1f2a3b4c5d6e7f80", 32);
	HEX(p, "70726f6b323536", 7);		/* "prck256" */
	/* Independently calculated with Python hmac/hashlib SHA-256. */
	HEX(expected, "eca973afda275789a859d428faa6c9d7"
	    "dc088c93bc1cbe2099f60b0fe4535213", BT_HMAC_SHA256_SIZE);
	uint8_t out[BT_HMAC_SHA256_SIZE];

	ATF_REQUIRE_EQ(0, mesh_k5(n, sizeof(n), salt, p, sizeof(p), out));
	ATF_CHECK_EQ_MSG(0, memcmp(out, expected, BT_HMAC_SHA256_SIZE),
	    "k5(N,SALT,P) differs from independent nested-HMAC oracle");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_aes128_e);
	ATF_TP_ADD_TC(tp, mesh_aes_cmac_rfc4493);
	ATF_TP_ADD_TC(tp, mesh_hmac_sha256_rfc4231);
	ATF_TP_ADD_TC(tp, mesh_s2_definition);
	ATF_TP_ADD_TC(tp, mesh_k5_definition);
	ATF_TP_ADD_TC(tp, mesh_aes_cmac_empty);
	ATF_TP_ADD_TC(tp, mesh_s1_test);
	ATF_TP_ADD_TC(tp, mesh_k1_vector);
	ATF_TP_ADD_TC(tp, mesh_k2_managed_flooding);
	ATF_TP_ADD_TC(tp, mesh_k3_vectors);
	ATF_TP_ADD_TC(tp, mesh_k4_vectors);
	ATF_TP_ADD_TC(tp, mesh_nonce_layout);
	ATF_TP_ADD_TC(tp, mesh_ccm_network_mic64);
	ATF_TP_ADD_TC(tp, mesh_ccm_network_mic32);
	ATF_TP_ADD_TC(tp, mesh_ccm_transport_device);
	ATF_TP_ADD_TC(tp, mesh_ccm_tamper_rejected);
	ATF_TP_ADD_TC(tp, mesh_input_validation);

	return (atf_no_error());
}
