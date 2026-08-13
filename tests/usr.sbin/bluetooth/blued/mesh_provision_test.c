/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh provisioning layer
 * (mesh_provision.[ch], MshPRT_v1.1 Section 5).
 *
 * The end-to-end vectors are the worked example of MshPRT_v1.1 Section 8.7
 * "PB-ADV provisioning sample data".  Every asserted byte is taken directly
 * from that section's dumps, using the specification's FIXED sample private
 * keys and random numbers so that every derivation is deterministic:
 *
 *   Prov Private Key = 06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663
 *   Device Private Key = 529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba
 *   RandomProvisioner = 8b19ac31d58b124c946209b5db1021b9
 *   RandomDevice      = 55a2a2bca04cd32ff6f346bd0a0c1a3a
 *
 * The whole derivation chain (public-key derivation, ECDHSecret,
 * ConfirmationInputs, ConfirmationSalt, ConfirmationKey, the Confirmation
 * values, ProvisioningSalt, SessionKey, SessionNonce, DevKey and the
 * encrypted provisioning data + MIC) plus the 3GPP TS 27.010 FCS were each
 * independently reproduced with the Python "cryptography" package (ECDH over
 * SECP256R1, AES-CMAC, AES-CCM) over the Section 8.7 inputs before being
 * committed, so a passing test confirms the module against the published
 * spec bytes rather than against itself.
 *
 * Mesh operates in network (big-endian) byte order; no byte reversal is
 * applied (unlike LE SMP).
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_provision.h"
#include "spec_oracles.h"

#define MPROV_ENUM(name, value) MPROV_##name = value,
enum {
	BT_MSHPRT11_PROVISIONING_PDU_ORACLES(MPROV_ENUM)
	BT_MSHPRT11_GPCF_ORACLES(MPROV_ENUM)
	BT_MSHPRT11_BEARER_CONTROL_ORACLES(MPROV_ENUM)
};
#undef MPROV_ENUM

/* Test-only remapping; mesh_provision.c is compiled separately. */
#undef MESH_PROV_INVITE
#define MESH_PROV_INVITE	MPROV_PROV_INVITE
#undef MESH_PROV_CAPABILITIES
#define MESH_PROV_CAPABILITIES	MPROV_PROV_CAPABILITIES
#undef MESH_PROV_START
#define MESH_PROV_START	MPROV_PROV_START
#undef MESH_PROV_PUBLIC_KEY
#define MESH_PROV_PUBLIC_KEY	MPROV_PROV_PUBLIC_KEY
#undef MESH_PROV_INPUT_COMPLETE
#define MESH_PROV_INPUT_COMPLETE MPROV_PROV_INPUT_COMPLETE
#undef MESH_PROV_CONFIRMATION
#define MESH_PROV_CONFIRMATION	MPROV_PROV_CONFIRMATION
#undef MESH_PROV_RANDOM
#define MESH_PROV_RANDOM	MPROV_PROV_RANDOM
#undef MESH_PROV_DATA
#define MESH_PROV_DATA		MPROV_PROV_DATA
#undef MESH_PROV_COMPLETE
#define MESH_PROV_COMPLETE	MPROV_PROV_COMPLETE
#undef MESH_PROV_FAILED
#define MESH_PROV_FAILED	MPROV_PROV_FAILED
#undef MESH_GPCF_START
#define MESH_GPCF_START	MPROV_GPCF_START
#undef MESH_GPCF_ACK
#define MESH_GPCF_ACK		MPROV_GPCF_ACK
#undef MESH_GPCF_CONTINUATION
#define MESH_GPCF_CONTINUATION MPROV_GPCF_CONTINUATION
#undef MESH_GPCF_CONTROL
#define MESH_GPCF_CONTROL	MPROV_GPCF_CONTROL
#undef MESH_BEARER_LINK_OPEN
#define MESH_BEARER_LINK_OPEN	MPROV_BEARER_LINK_OPEN
#undef MESH_BEARER_LINK_ACK
#define MESH_BEARER_LINK_ACK	MPROV_BEARER_LINK_ACK
#undef MESH_BEARER_LINK_CLOSE
#define MESH_BEARER_LINK_CLOSE	MPROV_BEARER_LINK_CLOSE
#undef MESH_PROXY_TYPE_PROVISIONING
#define MESH_PROXY_TYPE_PROVISIONING BT_MSHPRT11_PROXY_PROVISIONING_TYPE
#undef MESH_PROXY_SAR_COMPLETE
#define MESH_PROXY_SAR_COMPLETE BT_MSHPRT11_PROXY_SAR_COMPLETE
#undef MESH_PROXY_SAR_FIRST
#define MESH_PROXY_SAR_FIRST	BT_MSHPRT11_PROXY_SAR_FIRST
#undef MESH_PROXY_SAR_CONTINUATION
#define MESH_PROXY_SAR_CONTINUATION BT_MSHPRT11_PROXY_SAR_CONTINUATION
#undef MESH_PROXY_SAR_LAST
#define MESH_PROXY_SAR_LAST	BT_MSHPRT11_PROXY_SAR_LAST
#undef MESH_PROV_ALGO_P256_CMAC
#define MESH_PROV_ALGO_P256_CMAC BT_MSHPRT11_PROV_ALGORITHM_P256_CMAC
#undef MESH_PROV_ALGO_P256_HMAC
#define MESH_PROV_ALGO_P256_HMAC BT_MSHPRT11_PROV_ALGORITHM_P256_HMAC
#undef MESH_PROV_ALGO_BIT_P256_CMAC
#define MESH_PROV_ALGO_BIT_P256_CMAC BT_MSHPRT11_PROV_ALGORITHM_BIT_P256_CMAC
#undef MESH_PROV_ALGO_BIT_P256_HMAC
#define MESH_PROV_ALGO_BIT_P256_HMAC BT_MSHPRT11_PROV_ALGORITHM_BIT_P256_HMAC

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

/* Shared Section 8.7 material. */
#define	PROV_PRIV	"06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663"
#define	DEV_PRIV	"529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba"
#define	PROV_PUB_X	"2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
#define	PROV_PUB_Y	"919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f"
#define	DEV_PUB_X	"f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"
#define	DEV_PUB_Y	"0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"
#define	ECDH_SECRET	"ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"
#define	RAND_PROV	"8b19ac31d58b124c946209b5db1021b9"
#define	RAND_DEV	"55a2a2bca04cd32ff6f346bd0a0c1a3a"
#define	CONF_INPUTS	"00010001000000000000000000000000002c31a47b5779809ef44cb5eaaf5c3e" \
			"43d5f8faad4a8794cb987e9b03745c78dd919512183898dfbecd52e2408e4387" \
			"1fd021109117bd3ed4eaf8437743715d4ff465e43ff23d3f1b9dc7dfc04da875" \
			"8184dbc966204796eccf0d6cf5e16500cc0201d048bcbbd899eeefc424164e33" \
			"c201c2b010ca6b4d43a8a155cad8ecb279"
#define	CONF_SALT	"5faabe187337c71cc6c973369dcaa79a"
#define	CONF_KEY	"e31fe046c68ec339c425fc6629f0336f"
#define	CONF_PROV	"b38a114dfdca1fe153bd2c1e0dc46ac2"
#define	CONF_DEV	"eeba521c196b52cc2e37aa40329f554e"
#define	PROV_SALT	"a21c7d45f201cf9489a2fb57145015b4"
#define	SESSION_KEY	"c80253af86b33dfa450bbdb2a191fea3"
#define	SESSION_NONCE	"da7ddbe78b5f62b81d6847487e"
#define	DEV_KEY		"0520adad5e0142aa3e325087b4ec16d8"
#define	PROV_DATA	"efb2255e6422d330088e09bb015ed707056700010203040b0c"
#define	ENC_DATA	"d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec29"
#define	DATA_MIC	"73e0ec50783b10c7"

/* Helper: build the provisioner key pair from the fixed sample private key. */
static void
prov_keypair(struct mesh_prov_keypair *kp)
{
	HEX(priv, PROV_PRIV, 32);

	ATF_REQUIRE_EQ(0, mesh_prov_keypair_from_private(priv, kp));
}

static void
dev_keypair(struct mesh_prov_keypair *kp)
{
	HEX(priv, DEV_PRIV, 32);

	ATF_REQUIRE_EQ(0, mesh_prov_keypair_from_private(priv, kp));
}

/* ================================================================
 * ECDH P-256: public-key derivation and shared secret.  Section 8.7.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ecdh_keypair_and_secret);
ATF_TC_BODY(ecdh_keypair_and_secret, tc)
{
	struct mesh_prov_keypair kp_p, kp_d;
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(dpx, DEV_PUB_X, 32);
	HEX(dpy, DEV_PUB_Y, 32);
	HEX(exp_ss, ECDH_SECRET, 32);
	uint8_t ss1[32], ss2[32];

	prov_keypair(&kp_p);
	dev_keypair(&kp_d);

	/* Public keys derived from the fixed private keys match Section 8.7. */
	ATF_CHECK_EQ_MSG(0, memcmp(kp_p.pub_x, ppx, 32), "prov pubkey X (8.7)");
	ATF_CHECK_EQ_MSG(0, memcmp(kp_p.pub_y, ppy, 32), "prov pubkey Y (8.7)");
	ATF_CHECK_EQ_MSG(0, memcmp(kp_d.pub_x, dpx, 32), "dev pubkey X (8.7)");
	ATF_CHECK_EQ_MSG(0, memcmp(kp_d.pub_y, dpy, 32), "dev pubkey Y (8.7)");

	/* ECDHSecret from either side is the same X coordinate. */
	ATF_REQUIRE_EQ(0, mesh_prov_ecdh_secret(&kp_p, dpx, dpy, ss1));
	ATF_REQUIRE_EQ(0, mesh_prov_ecdh_secret(&kp_d, ppx, ppy, ss2));
	ATF_CHECK_EQ_MSG(0, memcmp(ss1, exp_ss, 32), "ECDHSecret prov side (8.7)");
	ATF_CHECK_EQ_MSG(0, memcmp(ss2, exp_ss, 32), "ECDHSecret dev side (8.7)");

	mesh_prov_keypair_free(&kp_p);
	mesh_prov_keypair_free(&kp_d);
}

/* Peer public-key validation rejects an off-curve point. */
ATF_TC_WITHOUT_HEAD(ecdh_reject_off_curve);
ATF_TC_BODY(ecdh_reject_off_curve, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	uint8_t bad_y[32];

	ATF_CHECK_EQ(0, mesh_prov_validate_public_key(ppx, ppy));
	memcpy(bad_y, ppy, 32);
	bad_y[31] ^= 0x01;	/* perturb -> not on curve */
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(ppx, bad_y));
}

/* ================================================================
 * Security functions chain.  Section 8.7.8 / 8.7.12.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(security_derivation_chain);
ATF_TC_BODY(security_derivation_chain, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(dpx, DEV_PUB_X, 32);
	HEX(dpy, DEV_PUB_Y, 32);
	HEX(ecdh, ECDH_SECRET, 32);
	HEX(rp, RAND_PROV, 16);
	HEX(rd, RAND_DEV, 16);
	HEX(exp_ci, CONF_INPUTS, MESH_PROV_CONF_INPUTS_LEN);
	HEX(exp_csalt, CONF_SALT, 16);
	HEX(exp_ckey, CONF_KEY, 16);
	HEX(exp_confp, CONF_PROV, 16);
	HEX(exp_confd, CONF_DEV, 16);
	HEX(exp_psalt, PROV_SALT, 16);
	HEX(exp_skey, SESSION_KEY, 16);
	HEX(exp_snonce, SESSION_NONCE, 13);
	HEX(exp_devkey, DEV_KEY, 16);
	uint8_t invite[1] = { 0x00 };
	HEX(caps, "0100010000000000000000", 11);
	uint8_t start[5] = { 0, 0, 0, 0, 0 };
	uint8_t ppub[64], dpub[64];
	uint8_t auth[16];
	uint8_t ci[MESH_PROV_CONF_INPUTS_LEN];
	uint8_t csalt[16], ckey[16], confp[16], confd[16];
	uint8_t psalt[16], skey[16], snonce[13], devkey[16];

	memcpy(ppub, ppx, 32);
	memcpy(ppub + 32, ppy, 32);
	memcpy(dpub, dpx, 32);
	memcpy(dpub + 32, dpy, 32);
	mesh_prov_auth_no_oob(auth);

	/* ConfirmationInputs (8.7.8). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_inputs(invite, caps, start,
	    ppub, dpub, ci));
	ATF_CHECK_EQ_MSG(0, memcmp(ci, exp_ci, MESH_PROV_CONF_INPUTS_LEN),
	    "ConfirmationInputs (8.7.8)");

	/* ConfirmationSalt = s1(ConfirmationInputs). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_salt(ci,
	    MESH_PROV_CONF_INPUTS_LEN, csalt));
	ATF_CHECK_EQ_MSG(0, memcmp(csalt, exp_csalt, 16),
	    "ConfirmationSalt (8.7.8)");

	/* ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck"). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_key(ecdh, csalt, ckey));
	ATF_CHECK_EQ_MSG(0, memcmp(ckey, exp_ckey, 16),
	    "ConfirmationKey (8.7.8)");

	/* ConfirmationProvisioner and ConfirmationDevice. */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation(ckey, rp, auth, confp));
	ATF_CHECK_EQ_MSG(0, memcmp(confp, exp_confp, 16),
	    "ConfirmationProvisioner (8.7.8)");
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation(ckey, rd, auth, confd));
	ATF_CHECK_EQ_MSG(0, memcmp(confd, exp_confd, 16),
	    "ConfirmationDevice (8.7.9)");

	/* ProvisioningSalt = s1(ConfirmationSalt || RandProv || RandDev). */
	ATF_REQUIRE_EQ(0, mesh_prov_provisioning_salt(csalt, rp, rd, psalt));
	ATF_CHECK_EQ_MSG(0, memcmp(psalt, exp_psalt, 16),
	    "ProvisioningSalt (8.7.12)");

	/* SessionKey, SessionNonce, DevKey. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_key(ecdh, psalt, skey));
	ATF_CHECK_EQ_MSG(0, memcmp(skey, exp_skey, 16), "SessionKey (8.7.12)");
	ATF_REQUIRE_EQ(0, mesh_prov_session_nonce(ecdh, psalt, snonce));
	ATF_CHECK_EQ_MSG(0, memcmp(snonce, exp_snonce, 13),
	    "SessionNonce (8.7.12)");
	ATF_REQUIRE_EQ(0, mesh_prov_device_key(ecdh, psalt, devkey));
	ATF_CHECK_EQ_MSG(0, memcmp(devkey, exp_devkey, 16), "DevKey (8.7.12)");
}

/* ================================================================
 * Provisioning-data encryption + MIC.  Section 8.7.12.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provisioning_data_encrypt);
ATF_TC_BODY(provisioning_data_encrypt, tc)
{
	HEX(skey, SESSION_KEY, 16);
	HEX(snonce, SESSION_NONCE, 13);
	HEX(data, PROV_DATA, 25);
	HEX(exp_enc, ENC_DATA, 25);
	HEX(exp_mic, DATA_MIC, 8);
	uint8_t enc[25], mic[8], back[25];

	ATF_REQUIRE_EQ(0, mesh_prov_data_encrypt(skey, snonce, data, enc, mic));
	ATF_CHECK_EQ_MSG(0, memcmp(enc, exp_enc, 25),
	    "Encrypted provisioning data (8.7.12)");
	ATF_CHECK_EQ_MSG(0, memcmp(mic, exp_mic, 8),
	    "Provisioning data MIC (8.7.12)");

	/* Decrypt/verify round-trips to the plaintext. */
	ATF_REQUIRE_EQ(0, mesh_prov_data_decrypt(skey, snonce, exp_enc, exp_mic,
	    back));
	ATF_CHECK_EQ_MSG(0, memcmp(back, data, 25),
	    "Provisioning data decrypt round-trip (8.7.12)");
}

/* A tampered MIC (or ciphertext) must be rejected. */
ATF_TC_WITHOUT_HEAD(provisioning_data_mic_tamper);
ATF_TC_BODY(provisioning_data_mic_tamper, tc)
{
	HEX(skey, SESSION_KEY, 16);
	HEX(snonce, SESSION_NONCE, 13);
	HEX(enc, ENC_DATA, 25);
	HEX(mic, DATA_MIC, 8);
	uint8_t back[25];
	uint8_t bad_mic[8], bad_enc[25];

	/* Flip one MIC bit. */
	memcpy(bad_mic, mic, 8);
	bad_mic[0] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_prov_data_decrypt(skey, snonce, enc, bad_mic,
	    back), "tampered MIC must fail authentication");

	/* Flip one ciphertext bit. */
	memcpy(bad_enc, enc, 25);
	bad_enc[10] ^= 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_prov_data_decrypt(skey, snonce, bad_enc, mic,
	    back), "tampered ciphertext must fail authentication");
}

/* The unpacked provisioning-data fields match Section 8.7.12. */
ATF_TC_WITHOUT_HEAD(provisioning_data_fields);
ATF_TC_BODY(provisioning_data_fields, tc)
{
	HEX(raw, PROV_DATA, 25);
	HEX(netkey, "efb2255e6422d330088e09bb015ed707", 16);
	struct mesh_prov_data d;
	uint8_t packed[25], wire[25];

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &d));
	ATF_CHECK_EQ_MSG(0, memcmp(d.netkey, netkey, 16), "NetKey (8.7.12)");
	ATF_CHECK_EQ_MSG(0x0567, d.netkey_index, "NetKeyIndex (8.7.12)");
	ATF_CHECK_EQ_MSG(0x00, d.flags, "Flags (8.7.12)");
	ATF_CHECK_EQ_MSG(0x01020304, d.iv_index, "IVIndex (8.7.12)");
	ATF_CHECK_EQ_MSG(0x0b0c, d.unicast_addr, "UnicastAddress (8.7.12)");

	/* Pack is the inverse. */
	ATF_REQUIRE_EQ(0, mesh_prov_data_pack(&d, packed));
	ATF_CHECK_EQ_MSG(0, memcmp(packed, raw, 25),
	    "provisioning-data pack round-trip");

	/* Key-index and Flags RFU bits are processed as zero. */
	memcpy(wire, raw, sizeof(wire));
	wire[16] |= 0xf0;
	wire[18] = 0xff;
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(wire, &d));
	ATF_CHECK_EQ(0x0567, d.netkey_index);
	ATF_CHECK_EQ(0x03, d.flags);

	/* The assigned primary address must be unicast. */
	memcpy(wire, raw, sizeof(wire));
	wire[23] = 0x80; wire[24] = 0x00;
	ATF_CHECK_EQ(-1, mesh_prov_data_unpack(wire, &d));
	ATF_CHECK_EQ(-1, mesh_prov_data_unpack(NULL, &d));
	ATF_CHECK_EQ(-1, mesh_prov_data_unpack(raw, NULL));
	ATF_CHECK_EQ(-1, mesh_prov_data_pack(NULL, packed));
	ATF_CHECK_EQ(-1, mesh_prov_data_pack(&d, NULL));
}

/* ================================================================
 * Confirmation-mismatch rejection: a wrong AuthValue changes the
 * Confirmation, so a device with the correct AuthValue rejects it.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(confirmation_mismatch);
ATF_TC_BODY(confirmation_mismatch, tc)
{
	HEX(ckey, CONF_KEY, 16);
	HEX(rp, RAND_PROV, 16);
	HEX(exp_confp, CONF_PROV, 16);
	uint8_t good_auth[16], wrong_auth[16];
	uint8_t conf_good[16], conf_wrong[16];

	mesh_prov_auth_no_oob(good_auth);
	mesh_prov_auth_static_oob((const uint8_t *)"secret", 6, wrong_auth);

	ATF_REQUIRE_EQ(0, mesh_prov_confirmation(ckey, rp, good_auth, conf_good));
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation(ckey, rp, wrong_auth,
	    conf_wrong));

	/* The No-OOB confirmation matches the spec value. */
	ATF_CHECK_EQ_MSG(0, memcmp(conf_good, exp_confp, 16),
	    "No-OOB confirmation matches spec");
	/* A different AuthValue yields a different confirmation (rejection). */
	ATF_CHECK_MSG(memcmp(conf_wrong, exp_confp, 16) != 0,
	    "wrong AuthValue must change the confirmation");
}

/* ================================================================
 * AuthValue packing.  Section 5.4.2.4.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(authvalue_packing);
ATF_TC_BODY(authvalue_packing, tc)
{
	uint8_t auth[16];
	uint8_t auth256[32], long_value[40];
	HEX(zero, "00000000000000000000000000000000", 16);
	/* Section 5.4.2.4 example: number 019655 -> 0x000000...00004CC7. */
	HEX(num_exp, "00000000000000000000000000004cc7", 16);
	/* Section 5.4.2.4 example: "123ABC" -> 0x31323341424300..00. */
	HEX(alpha_exp, "31323341424300000000000000000000", 16);
	HEX(static_val, "00112233445566778899aabbccddeeff", 16);

	mesh_prov_auth_no_oob(auth);
	ATF_CHECK_EQ_MSG(0, memcmp(auth, zero, 16), "No-OOB AuthValue is zero");

	mesh_prov_auth_numeric(19655, auth);
	ATF_CHECK_EQ_MSG(0, memcmp(auth, num_exp, 16),
	    "numeric AuthValue 019655 (5.4.2.4)");

	mesh_prov_auth_alphanumeric("123ABC", 6, auth);
	ATF_CHECK_EQ_MSG(0, memcmp(auth, alpha_exp, 16),
	    "alphanumeric AuthValue 123ABC (5.4.2.4)");

	mesh_prov_auth_static_oob(static_val, 16, auth);
	ATF_CHECK_EQ_MSG(0, memcmp(auth, static_val, 16),
	    "static-OOB AuthValue copies the 16-octet value");

	/* Algorithm 0x01 uses a 256-bit, rather than 128-bit, AuthValue. */
	memset(long_value, 0xa5, sizeof(long_value));
	mesh_prov_auth256_no_oob(auth256);
	ATF_CHECK_EQ(0, memcmp(auth256, (uint8_t[32]){ 0 }, 32));
	mesh_prov_auth256_static_oob(NULL, 1, auth256);
	ATF_CHECK_EQ(0, memcmp(auth256, (uint8_t[32]){ 0 }, 32));
	mesh_prov_auth256_static_oob(long_value, sizeof(long_value), auth256);
	ATF_CHECK_EQ(0, memcmp(auth256, long_value, 32));
	mesh_prov_auth256_numeric(0x12345678, auth256);
	ATF_CHECK_EQ(0x12, auth256[28]);
	ATF_CHECK_EQ(0x34, auth256[29]);
	ATF_CHECK_EQ(0x56, auth256[30]);
	ATF_CHECK_EQ(0x78, auth256[31]);
}

/* ================================================================
 * Provisioning PDU codec: length / type / reserved-bit validation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pdu_validation);
ATF_TC_BODY(pdu_validation, tc)
{
	struct mesh_prov_pdu p;
	uint8_t buf[65];
	size_t outlen;
	uint8_t att;

	/* Invite build + parse round-trip. */
	ATF_REQUIRE_EQ(0, mesh_prov_invite_build(0x00, buf, &outlen));
	ATF_CHECK_EQ(2, outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, "\x00\x00", 2), "Invite PDU = 0x0000");
	ATF_REQUIRE_EQ(0, mesh_prov_invite_parse(buf, 2, &att));
	ATF_CHECK_EQ(0x00, att);

	/* Reserved padding bits set -> reject. */
	buf[0] = 0x40;	/* type 0, padding bit 6 set */
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 2, &p));
	buf[0] = 0xc0;
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 2, &p));

	/* Unknown (reserved) type -> reject. */
	buf[0] = 0x0a;
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 2, &p));
	buf[0] = 0x3f;
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 2, &p));

	/* Wrong length for the type -> reject (Invite must be 2 octets). */
	buf[0] = MESH_PROV_INVITE;
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 1, &p));
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 3, &p));

	/* Confirmation must be 17 octets. */
	buf[0] = MESH_PROV_CONFIRMATION;
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 16, &p));
	ATF_CHECK_EQ_MSG(0, mesh_prov_pdu_parse(buf, 17, &p),
	    "17-octet Confirmation PDU accepted");
	ATF_CHECK_EQ(MESH_PROV_CONFIRMATION, p.type);
	ATF_CHECK_EQ(16, p.params_len);

	/* Empty / oversize input -> reject. */
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 0, &p));
	ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(buf, 66, &p));
}

/* Public Key / Confirmation / Random / Data structured codecs round-trip. */
ATF_TC_WITHOUT_HEAD(pdu_structured_roundtrip);
ATF_TC_BODY(pdu_structured_roundtrip, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(conf, CONF_PROV, 16);
	HEX(rnd, RAND_PROV, 16);
	HEX(enc, ENC_DATA, 25);
	HEX(mic, DATA_MIC, 8);
	uint8_t buf[65], x[32], y[32], c[16], r[16], e2[25], m2[8];
	size_t outlen;

	ATF_REQUIRE_EQ(0, mesh_prov_public_key_build(ppx, ppy, buf, &outlen));
	ATF_CHECK_EQ(65, outlen);
	ATF_CHECK_EQ(MESH_PROV_PUBLIC_KEY, buf[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_public_key_parse(buf, 65, x, y));
	ATF_CHECK_EQ(0, memcmp(x, ppx, 32));
	ATF_CHECK_EQ(0, memcmp(y, ppy, 32));

	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_build(conf, buf, &outlen));
	ATF_CHECK_EQ(17, outlen);
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_parse(buf, 17, c));
	ATF_CHECK_EQ(0, memcmp(c, conf, 16));

	ATF_REQUIRE_EQ(0, mesh_prov_random_build(rnd, buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_prov_random_parse(buf, 17, r));
	ATF_CHECK_EQ(0, memcmp(r, rnd, 16));

	ATF_REQUIRE_EQ(0, mesh_prov_data_pdu_build(enc, mic, buf, &outlen));
	ATF_CHECK_EQ(34, outlen);
	ATF_CHECK_EQ(MESH_PROV_DATA, buf[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_data_pdu_parse(buf, 34, e2, m2));
	ATF_CHECK_EQ(0, memcmp(e2, enc, 25));
	ATF_CHECK_EQ(0, memcmp(m2, mic, 8));
}

/* ================================================================
 * PB-ADV FCS known-answer tests.  Section 8.7 (3GPP TS 27.010).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbadv_fcs_kat);
ATF_TC_BODY(pbadv_fcs_kat, tc)
{
	struct {
		const char *hex;
		size_t len;
		uint8_t fcs;
	} v[] = {
		{ "0000", 2, 0x14 },				/* Invite */
		{ "010100010000000000000000", 12, 0xd6 },	/* Capabilities */
		{ "020000000000", 6, 0x64 },			/* Start */
		{ "05b38a114dfdca1fe153bd2c1e0dc46ac2", 17, 0xd1 },/* Confirm (prov) */
		{ "05eeba521c196b52cc2e37aa40329f554e", 17, 0xec },/* Confirm (dev) */
		{ "068b19ac31d58b124c946209b5db1021b9", 17, 0xd3 },/* Random (prov) */
		{ "0655a2a2bca04cd32ff6f346bd0a0c1a3a", 17, 0x59 },/* Random (dev) */
		{ "08", 1, 0x3e },				/* Complete */
	};
	uint8_t buf[65];
	size_t i;

	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		hex_to_bytes(buf, v[i].hex, v[i].len);
		ATF_CHECK_EQ_MSG(v[i].fcs, mesh_prov_fcs(buf, v[i].len),
		    "FCS mismatch for vector %zu (8.7)", i);
	}
}

/* ================================================================
 * PB-ADV segmentation + reassembly of the 65-octet Public Key PDU.
 * MshPRT_v1.1 Section 8.7.6 (three segments).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbadv_segment_reassemble);
ATF_TC_BODY(pbadv_segment_reassemble, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(m0, "23af585002080041d1032c31a47b5779809ef44cb5eaaf5c3e43d5f8fa", 29);
	HEX(m1, "23af58500206ad4a8794cb987e9b03745c78dd919512183898dfbecd52", 29);
	HEX(m2, "23af5850020ae2408e43871fd021109117bd3ed4eaf8437743715d4f", 28);
	uint8_t pk[65], pbuf[64];
	struct mesh_gp_pdu segs[MESH_GP_SEG_MAX];
	struct mesh_gp_reasm r;
	uint8_t got[65];
	size_t nseg, outlen, gl, i;
	int rc;
	const struct { const uint8_t *m; size_t len; } exp[3] = {
		{ m0, 29 }, { m1, 29 }, { m2, 28 },
	};

	ATF_REQUIRE_EQ(0, mesh_prov_public_key_build(ppx, ppy, pk, &outlen));
	ATF_REQUIRE_EQ(65, outlen);

	/* Segment: 1 Transaction Start + 2 Continuations = 3 segments. */
	ATF_REQUIRE_EQ(0, mesh_gp_segment(pk, 65, segs, MESH_GP_SEG_MAX, &nseg));
	ATF_CHECK_EQ_MSG(3, nseg, "Public Key PDU splits into 3 PB-ADV segments");

	/* Each PB-ADV message matches Section 8.7.6 byte-for-byte. */
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x02,
		    segs[i].bytes, segs[i].len, pbuf, &outlen));
		ATF_CHECK_EQ_MSG(exp[i].len, outlen,
		    "PB-ADV message %zu length (8.7.6)", i);
		ATF_CHECK_EQ_MSG(0, memcmp(pbuf, exp[i].m, exp[i].len),
		    "PB-ADV message %zu bytes (8.7.6)", i);
	}

	/* Reassemble: first two incomplete (0), final complete + FCS ok (1). */
	mesh_gp_reasm_init(&r);
	rc = mesh_gp_reasm_input(&r, segs[0].bytes, segs[0].len);
	ATF_CHECK_EQ_MSG(0, rc, "Start segment: incomplete");
	rc = mesh_gp_reasm_input(&r, segs[1].bytes, segs[1].len);
	ATF_CHECK_EQ_MSG(0, rc, "Continuation 1: incomplete");
	rc = mesh_gp_reasm_input(&r, segs[2].bytes, segs[2].len);
	ATF_CHECK_EQ_MSG(1, rc, "Continuation 2: complete + FCS verified");

	ATF_REQUIRE_EQ(0, mesh_gp_reasm_get(&r, got, &gl));
	ATF_CHECK_EQ(65, gl);
	ATF_CHECK_EQ_MSG(0, memcmp(got, pk, 65),
	    "reassembled Public Key PDU matches original");

	/* Duplicate final segment is idempotent (still complete). */
	rc = mesh_gp_reasm_input(&r, segs[2].bytes, segs[2].len);
	ATF_CHECK_EQ_MSG(1, rc, "duplicate final segment idempotent");
}

/* A single-segment (short) Provisioning PDU: the Invite. */
ATF_TC_WITHOUT_HEAD(pbadv_single_segment);
ATF_TC_BODY(pbadv_single_segment, tc)
{
	HEX(m0, "23af585000000002140000", 11);	/* Section 8.7.3 */
	uint8_t invite[2], pbuf[64], got[65];
	struct mesh_gp_pdu segs[MESH_GP_SEG_MAX];
	struct mesh_gp_reasm r;
	size_t nseg, outlen, gl;

	ATF_REQUIRE_EQ(0, mesh_prov_invite_build(0x00, invite, &outlen));
	ATF_REQUIRE_EQ(0, mesh_gp_segment(invite, 2, segs, MESH_GP_SEG_MAX,
	    &nseg));
	ATF_CHECK_EQ_MSG(1, nseg, "Invite is a single PB-ADV segment");

	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x00, segs[0].bytes,
	    segs[0].len, pbuf, &outlen));
	ATF_CHECK_EQ_MSG(11, outlen, "Invite PB-ADV message length (8.7.3)");
	ATF_CHECK_EQ_MSG(0, memcmp(pbuf, m0, 11),
	    "Invite PB-ADV message bytes (8.7.3)");

	mesh_gp_reasm_init(&r);
	ATF_CHECK_EQ_MSG(1, mesh_gp_reasm_input(&r, segs[0].bytes, segs[0].len),
	    "single-segment Start completes immediately");
	ATF_REQUIRE_EQ(0, mesh_gp_reasm_get(&r, got, &gl));
	ATF_CHECK_EQ(2, gl);
	ATF_CHECK_EQ(0, memcmp(got, invite, 2));
}

/* Reassembly rejects a corrupted final segment (FCS mismatch). */
ATF_TC_WITHOUT_HEAD(pbadv_reassemble_fcs_reject);
ATF_TC_BODY(pbadv_reassemble_fcs_reject, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	uint8_t pk[65];
	struct mesh_gp_pdu segs[MESH_GP_SEG_MAX];
	struct mesh_gp_reasm r;
	size_t nseg, outlen;

	ATF_REQUIRE_EQ(0, mesh_prov_public_key_build(ppx, ppy, pk, &outlen));
	ATF_REQUIRE_EQ(0, mesh_gp_segment(pk, 65, segs, MESH_GP_SEG_MAX, &nseg));

	/* Corrupt one payload byte in the last continuation segment. */
	segs[2].bytes[3] ^= 0x40;

	mesh_gp_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_gp_reasm_input(&r, segs[0].bytes, segs[0].len));
	ATF_CHECK_EQ(0, mesh_gp_reasm_input(&r, segs[1].bytes, segs[1].len));
	ATF_CHECK_EQ_MSG(-1, mesh_gp_reasm_input(&r, segs[2].bytes, segs[2].len),
	    "corrupted payload must fail the FCS check");
}

/* ================================================================
 * Bearer Control: Link Open / Link ACK / Link Close.  Section 8.7.1/2/14.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbadv_bearer_control);
ATF_TC_BODY(pbadv_bearer_control, tc)
{
	HEX(uuid, "70cf7c9732a345b691494810d2e9cbf4", 16);
	HEX(exp_open, "23af5850000370cf7c9732a345b691494810d2e9cbf4", 22);
	HEX(exp_ack, "23af58500007", 6);
	HEX(exp_close, "23af5850000b00", 7);
	uint8_t gp[32], pbuf[64];
	size_t gplen, outlen;
	struct mesh_gp_parsed p;

	/* Link Open (8.7.1). */
	ATF_REQUIRE_EQ(0, mesh_gp_link_open_build(uuid, gp, &gplen));
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x00, gp, gplen, pbuf,
	    &outlen));
	ATF_CHECK_EQ_MSG(22, outlen, "Link Open length (8.7.1)");
	ATF_CHECK_EQ_MSG(0, memcmp(pbuf, exp_open, 22),
	    "Link Open message (8.7.1)");
	ATF_REQUIRE_EQ(0, mesh_gp_parse(gp, gplen, &p));
	ATF_CHECK_EQ(MESH_GPCF_CONTROL, p.gpcf);
	ATF_CHECK_EQ(MESH_BEARER_LINK_OPEN, p.opcode);
	ATF_CHECK_EQ_MSG(0, memcmp(p.payload, uuid, 16), "Link Open UUID");

	/* Link ACK (8.7.2). */
	ATF_REQUIRE_EQ(0, mesh_gp_link_ack_build(gp, &gplen));
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x00, gp, gplen, pbuf,
	    &outlen));
	ATF_CHECK_EQ_MSG(6, outlen, "Link ACK length (8.7.2)");
	ATF_CHECK_EQ_MSG(0, memcmp(pbuf, exp_ack, 6), "Link ACK message (8.7.2)");
	ATF_REQUIRE_EQ(0, mesh_gp_parse(gp, gplen, &p));
	ATF_CHECK_EQ(MESH_BEARER_LINK_ACK, p.opcode);

	/* Link Close, reason 0x00 (8.7.14). */
	ATF_REQUIRE_EQ(0, mesh_gp_link_close_build(0x00, gp, &gplen));
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x00, gp, gplen, pbuf,
	    &outlen));
	ATF_CHECK_EQ_MSG(7, outlen, "Link Close length (8.7.14)");
	ATF_CHECK_EQ_MSG(0, memcmp(pbuf, exp_close, 7),
	    "Link Close message (8.7.14)");
	ATF_REQUIRE_EQ(0, mesh_gp_parse(gp, gplen, &p));
	ATF_CHECK_EQ(MESH_BEARER_LINK_CLOSE, p.opcode);
	ATF_CHECK_EQ(0x00, p.payload[0]);
}

/* Transaction Acknowledgment PDU (0x01) build + parse. */
ATF_TC_WITHOUT_HEAD(pbadv_transaction_ack);
ATF_TC_BODY(pbadv_transaction_ack, tc)
{
	HEX(exp, "23af58500001", 6);	/* Section 8.7.3.1 */
	uint8_t gp[4], pbuf[64];
	size_t gplen, outlen;
	struct mesh_gp_parsed p;

	ATF_REQUIRE_EQ(0, mesh_gp_ack_build(gp, &gplen));
	ATF_CHECK_EQ(1, gplen);
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x00, gp, gplen, pbuf,
	    &outlen));
	ATF_CHECK_EQ_MSG(0, memcmp(pbuf, exp, 6),
	    "Transaction Ack message (8.7.3.1)");
	ATF_REQUIRE_EQ(0, mesh_gp_parse(gp, gplen, &p));
	ATF_CHECK_EQ(MESH_GPCF_ACK, p.gpcf);
}

/* ================================================================
 * PB-GATT Proxy PDU wrap + SAR.  Section 8.8 (ATT_MTU = 23).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbgatt_sar_public_key);
ATF_TC_BODY(pbgatt_sar_public_key, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	/* Section 8.8 ATT Values (proxy header + payload), MTU 23 => 19/seg. */
	HEX(s0, "43032c31a47b5779809ef44cb5eaaf5c3e43d5f8", 20);
	HEX(s1, "83faad4a8794cb987e9b03745c78dd9195121838", 20);
	HEX(s2, "8398dfbecd52e2408e43871fd021109117bd3ed4", 20);
	HEX(s3, "c3eaf8437743715d4f", 9);
	uint8_t pk[65];
	struct mesh_proxy_pdu segs[8];
	size_t nseg, outlen;
	uint8_t sar, type;
	const uint8_t *payload;
	size_t plen;
	const struct { const uint8_t *m; size_t len; } exp[4] = {
		{ s0, 20 }, { s1, 20 }, { s2, 20 }, { s3, 9 },
	};
	size_t i;

	ATF_REQUIRE_EQ(0, mesh_prov_public_key_build(ppx, ppy, pk, &outlen));

	/* ATT_MTU 23 => Write Command payload 20 => proxy payload 19. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_segment(MESH_PROXY_TYPE_PROVISIONING, pk,
	    65, 19, segs, 8, &nseg));
	ATF_CHECK_EQ_MSG(4, nseg, "65-octet PDU splits into 4 PB-GATT segments");

	for (i = 0; i < 4; i++) {
		ATF_CHECK_EQ_MSG(exp[i].len, segs[i].len,
		    "PB-GATT segment %zu length (8.8)", i);
		ATF_CHECK_EQ_MSG(0, memcmp(segs[i].bytes, exp[i].m, exp[i].len),
		    "PB-GATT segment %zu bytes (8.8)", i);
	}

	/* Parse the first segment header: SAR=first, Type=Provisioning. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_parse(segs[0].bytes, segs[0].len, &sar,
	    &type, &payload, &plen));
	ATF_CHECK_EQ(MESH_PROXY_SAR_FIRST, sar);
	ATF_CHECK_EQ(MESH_PROXY_TYPE_PROVISIONING, type);

	/* Last segment: SAR=last. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_parse(segs[3].bytes, segs[3].len, &sar,
	    &type, &payload, &plen));
	ATF_CHECK_EQ(MESH_PROXY_SAR_LAST, sar);
}

/* A short Provisioning PDU wraps as a single complete Proxy PDU. */
ATF_TC_WITHOUT_HEAD(pbgatt_complete_wrap);
ATF_TC_BODY(pbgatt_complete_wrap, tc)
{
	uint8_t invite[2], out[8];
	size_t outlen;
	uint8_t sar, type;
	const uint8_t *payload;
	size_t plen, ilen;

	ATF_REQUIRE_EQ(0, mesh_prov_invite_build(0x00, invite, &ilen));
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_PROVISIONING, invite, 2, out, &outlen));
	ATF_CHECK_EQ(3, outlen);
	ATF_CHECK_EQ_MSG(0x03, out[0], "Proxy header: SAR=complete|type=prov");

	ATF_REQUIRE_EQ(0, mesh_pbgatt_parse(out, outlen, &sar, &type, &payload,
	    &plen));
	ATF_CHECK_EQ(MESH_PROXY_SAR_COMPLETE, sar);
	ATF_CHECK_EQ(MESH_PROXY_TYPE_PROVISIONING, type);
	ATF_CHECK_EQ(2, plen);
	ATF_CHECK_EQ(0, memcmp(payload, invite, 2));
}

/* ================================================================
 * Remaining structured codecs (Capabilities / Start / Failed / no-param) and
 * generic PDU builder/parser validation.  MshPRT_v1.1 Section 5.4.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(codec_extra);
ATF_TC_BODY(codec_extra, tc)
{
	struct mesh_prov_caps caps_in, caps_out;
	struct mesh_prov_start start_in, start_out;
	uint8_t buf[65];
	size_t outlen;
	uint8_t err, att;
	uint8_t x[32], y[32], c[16], r[16], e2[25], m2[8];

	/* Capabilities build + parse round-trip. */
	memset(&caps_in, 0, sizeof(caps_in));
	caps_in.num_elements = 0x01;
	caps_in.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC |
	    MESH_PROV_ALGO_BIT_P256_HMAC;
	caps_in.public_key_type = 0x01;
	caps_in.static_oob_type = 0x01;
	caps_in.output_oob_size = 0x03;
	caps_in.output_oob_action = 0x0005;
	caps_in.input_oob_size = 0x06;
	caps_in.input_oob_action = 0x0008;
	ATF_REQUIRE_EQ(0, mesh_prov_caps_build(&caps_in, buf, &outlen));
	ATF_CHECK_EQ(12, outlen);
	ATF_CHECK_EQ(MESH_PROV_CAPABILITIES, buf[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_caps_parse(buf, 12, &caps_out));
	ATF_CHECK_EQ(0, memcmp(&caps_in, &caps_out, sizeof(caps_in)));
	/* RFU bits in capability bit fields are ignored by a receiver. */
	buf[2] |= 0x80;
	buf[4] |= 0xfe;
	buf[5] |= 0xfc;
	buf[7] |= 0x80;
	buf[10] |= 0x80;
	ATF_REQUIRE_EQ(0, mesh_prov_caps_parse(buf, 12, &caps_out));
	ATF_CHECK_EQ(0, memcmp(&caps_in, &caps_out, sizeof(caps_in)));
	/* CMAC-only capabilities (HMAC bit clear) are spec-legal (Table 5.21). */
	ATF_REQUIRE_EQ(0, mesh_prov_caps_build(&caps_in, buf, &outlen));
	buf[3] &= (uint8_t)~MESH_PROV_ALGO_BIT_P256_HMAC;
	ATF_REQUIRE_EQ(0, mesh_prov_caps_parse(buf, 12, &caps_out));
	ATF_CHECK_EQ(MESH_PROV_ALGO_BIT_P256_CMAC, caps_out.algorithms);
	ATF_REQUIRE_EQ(0, mesh_prov_caps_build(&caps_in, buf, &outlen));
	/* Wrong-type input is rejected. */
	buf[0] = MESH_PROV_START;
	ATF_CHECK_EQ(-1, mesh_prov_caps_parse(buf, 12, &caps_out));

	/* Start build + parse round-trip. */
	memset(&start_in, 0, sizeof(start_in));
	start_in.algorithm = 0x00;
	start_in.public_key = 0x01;
	start_in.auth_method = 0x02;
	start_in.auth_action = 0x03;
	start_in.auth_size = 0x04;
	ATF_REQUIRE_EQ(0, mesh_prov_start_build(&start_in, buf, &outlen));
	ATF_CHECK_EQ(6, outlen);
	ATF_REQUIRE_EQ(0, mesh_prov_start_parse(buf, 6, &start_out));
	ATF_CHECK_EQ(0, memcmp(&start_in, &start_out, sizeof(start_in)));
	start_in.auth_method = 0;
	start_in.auth_action = 1;
	start_in.auth_size = 0;
	ATF_CHECK_EQ(-1, mesh_prov_start_build(&start_in, buf, &outlen));
	start_in.auth_method = 2;
	start_in.auth_action = 5;
	start_in.auth_size = 1;
	ATF_CHECK_EQ(-1, mesh_prov_start_build(&start_in, buf, &outlen));
	start_in.auth_action = 0;
	start_in.auth_size = 9;
	ATF_CHECK_EQ(-1, mesh_prov_start_build(&start_in, buf, &outlen));
	start_in.auth_method = 2;
	start_in.auth_action = 3;
	start_in.auth_size = 4;
	ATF_REQUIRE_EQ(0, mesh_prov_start_build(&start_in, buf, &outlen));
	buf[0] = MESH_PROV_CAPABILITIES;
	ATF_CHECK_EQ(-1, mesh_prov_start_parse(buf, 6, &start_out));

	/* Failed build + parse round-trip + wrong-type reject. */
	ATF_REQUIRE_EQ(0, mesh_prov_failed_build(0x02, buf, &outlen));
	ATF_CHECK_EQ(2, outlen);
	ATF_CHECK_EQ(MESH_PROV_FAILED, buf[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_failed_parse(buf, 2, &err));
	ATF_CHECK_EQ(0x02, err);
	buf[0] = MESH_PROV_COMPLETE;
	ATF_CHECK_EQ(-1, mesh_prov_failed_parse(buf, 1, &err));

	/* no-param build: Input Complete and Complete are valid; others reject. */
	ATF_REQUIRE_EQ(0, mesh_prov_no_param_build(MESH_PROV_INPUT_COMPLETE, buf,
	    &outlen));
	ATF_CHECK_EQ(1, outlen);
	ATF_CHECK_EQ(MESH_PROV_INPUT_COMPLETE, buf[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_no_param_build(MESH_PROV_COMPLETE, buf,
	    &outlen));
	ATF_CHECK_EQ(MESH_PROV_COMPLETE, buf[0]);
	ATF_CHECK_EQ_MSG(-1, mesh_prov_no_param_build(MESH_PROV_INVITE, buf,
	    &outlen), "no_param_build accepted a parameterised type");

	/* Generic builder rejects a reserved type, a length mismatch and a
	 * NULL params pointer with a non-zero length. */
	ATF_CHECK_EQ(-1, mesh_prov_pdu_build(0x0a, NULL, 0, buf, &outlen));
	{
		uint8_t one = 0x00;

		ATF_CHECK_EQ_MSG(-1, mesh_prov_pdu_build(MESH_PROV_INVITE, &one,
		    5, buf, &outlen), "builder accepted a wrong param length");
	}
	ATF_CHECK_EQ_MSG(-1, mesh_prov_pdu_build(MESH_PROV_CONFIRMATION, NULL,
	    16, buf, &outlen), "builder accepted NULL params with plen > 0");

	/* Structured parsers reject a wrong Type octet. */
	ATF_REQUIRE_EQ(0, mesh_prov_invite_build(0x00, buf, &outlen));
	buf[0] = MESH_PROV_START;
	ATF_CHECK_EQ(-1, mesh_prov_invite_parse(buf, 6, &att));

	memset(buf, 0, sizeof(buf));
	buf[0] = MESH_PROV_CAPABILITIES;		/* not Public Key */
	ATF_CHECK_EQ(-1, mesh_prov_public_key_parse(buf, 12, x, y));
	buf[0] = MESH_PROV_START;			/* not Confirmation */
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_parse(buf, 6, c));
	ATF_CHECK_EQ(-1, mesh_prov_random_parse(buf, 6, r));	/* not Random */
	ATF_CHECK_EQ(-1, mesh_prov_data_pdu_parse(buf, 6, e2, m2));/* not Data */

	/* mesh_prov_pdu_parse rejects a NULL buffer. */
	{
		struct mesh_prov_pdu pp;

		ATF_CHECK_EQ(-1, mesh_prov_pdu_parse(NULL, 2, &pp));
	}

	/*
	 * Every structured parser must also reject a well-formed but
	 * wrong-type PDU (its "p.type != X" arm) *and* a malformed PDU (its
	 * "pdu_parse != 0" arm).  A reserved-type octet (0x0a) always fails
	 * pdu_parse; a valid Invite PDU (0x0000) parses but has the wrong type
	 * for the non-Invite parsers, and a valid Failed PDU (0x0900) is the
	 * wrong type for the Invite parser.
	 */
	{
		uint8_t bad[34];		/* reserved type -> pdu_parse fails */
		uint8_t inv[2] = { MESH_PROV_INVITE, 0x00 };
		uint8_t fail[2] = { MESH_PROV_FAILED, 0x00 };
		struct mesh_prov_caps cc;
		struct mesh_prov_start ss;
		uint8_t xx[32], yy[32], c2[16], r2[16], ee[25], mm[8], ec2;
		uint8_t at2;

		memset(bad, 0, sizeof(bad));
		bad[0] = 0x0a;		/* reserved provisioning type */

		/* Malformed (pdu_parse fails) arm for each parser. */
		ATF_CHECK_EQ(-1, mesh_prov_invite_parse(bad, 2, &at2));
		ATF_CHECK_EQ(-1, mesh_prov_caps_parse(bad, 12, &cc));
		ATF_CHECK_EQ(-1, mesh_prov_start_parse(bad, 6, &ss));
		ATF_CHECK_EQ(-1, mesh_prov_public_key_parse(bad, 65, xx, yy));
		ATF_CHECK_EQ(-1, mesh_prov_confirmation_parse(bad, 17, c2));
		ATF_CHECK_EQ(-1, mesh_prov_random_parse(bad, 17, r2));
		ATF_CHECK_EQ(-1, mesh_prov_data_pdu_parse(bad, 34, ee, mm));
		ATF_CHECK_EQ(-1, mesh_prov_failed_parse(bad, 2, &ec2));

		/*
		 * Well-formed wrong-type arm (p.type != X): feed a valid PDU of
		 * a different type at *its* correct length so pdu_parse succeeds
		 * and only the type check rejects it.  A valid Invite (0x0000,
		 * length 2) is the wrong type for every non-Invite parser; a
		 * valid Failed (0x0900, length 2) is the wrong type for Invite.
		 */
		ATF_CHECK_EQ(-1, mesh_prov_invite_parse(fail, 2, &at2));
		ATF_CHECK_EQ(-1, mesh_prov_caps_parse(inv, 2, &cc));
		ATF_CHECK_EQ(-1, mesh_prov_start_parse(inv, 2, &ss));
		ATF_CHECK_EQ(-1, mesh_prov_public_key_parse(inv, 2, xx, yy));
		ATF_CHECK_EQ(-1, mesh_prov_confirmation_parse(inv, 2, c2));
		ATF_CHECK_EQ(-1, mesh_prov_random_parse(inv, 2, r2));
		ATF_CHECK_EQ(-1, mesh_prov_data_pdu_parse(inv, 2, ee, mm));
		ATF_CHECK_EQ(-1, mesh_prov_failed_parse(inv, 2, &ec2));
	}
}

/* ================================================================
 * ECDH / security-function input-validation arms.  Sections 5.4.2.3/4.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ecdh_input_validation);
ATF_TC_BODY(ecdh_input_validation, tc)
{
	struct mesh_prov_keypair kp;
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(dpx, DEV_PUB_X, 32);
	HEX(dpy, DEV_PUB_Y, 32);
	HEX(pv, PROV_PRIV, 32);
	uint8_t bad_y[32], secret[32];
	uint8_t ci[MESH_PROV_CONF_INPUTS_LEN];
	uint8_t invite[1] = { 0 }, caps[11] = { 0 }, start[5] = { 0 };
	uint8_t ppub[64] = { 0 }, dpub[64] = { 0 };
	uint8_t auth[16];

	/* Freshly generated key pair: exercises the generate + extract path. */
	ATF_REQUIRE_EQ(0, mesh_prov_keypair_generate(&kp));
	/* The generated public key is a valid P-256 point. */
	ATF_CHECK_EQ(0, mesh_prov_validate_public_key(kp.pub_x, kp.pub_y));
	/* ... and ECDH against the fixed device public key round-trips both
	 * directions equally (secret is symmetric). */
	ATF_REQUIRE_EQ(0, mesh_prov_ecdh_secret(&kp, dpx, dpy, secret));
	mesh_prov_keypair_free(&kp);

	/* keypair_free tolerates NULL and a zeroed (pkey == NULL) struct. */
	mesh_prov_keypair_free(NULL);
	{
		struct mesh_prov_keypair zeroed;

		memset(&zeroed, 0, sizeof(zeroed));
		mesh_prov_keypair_free(&zeroed);	/* kp != NULL, pkey == NULL */
	}

	/* validate_public_key: an off-curve point (X kept, Y perturbed by a
	 * large delta so the affine set still succeeds but is-on-curve fails). */
	memcpy(bad_y, ppy, 32);
	bad_y[0] ^= 0x80;
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(ppx, bad_y));

	/* ecdh_secret: NULL local, NULL pkey, and an off-curve peer key. */
	ATF_CHECK_EQ(-1, mesh_prov_ecdh_secret(NULL, dpx, dpy, secret));
	{
		struct mesh_prov_keypair empty;

		memset(&empty, 0, sizeof(empty));	/* pkey == NULL */
		ATF_CHECK_EQ(-1, mesh_prov_ecdh_secret(&empty, dpx, dpy,
		    secret));
	}
	ATF_REQUIRE_EQ(0, mesh_prov_keypair_from_private(pv, &kp));
	ATF_CHECK_EQ_MSG(-1, mesh_prov_ecdh_secret(&kp, ppx, bad_y, secret),
	    "ecdh_secret accepted an off-curve peer key");
	mesh_prov_keypair_free(&kp);

	/* confirmation_inputs rejects any NULL component. */
	memcpy(ppub, ppx, 32);
	memcpy(ppub + 32, ppy, 32);
	memcpy(dpub, dpx, 32);
	memcpy(dpub + 32, dpy, 32);
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_inputs(NULL, caps, start, ppub,
	    dpub, ci));
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_inputs(invite, NULL, start,
	    ppub, dpub, ci));
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_inputs(invite, caps, NULL, ppub,
	    dpub, ci));
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_inputs(invite, caps, start,
	    NULL, dpub, ci));
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_inputs(invite, caps, start,
	    ppub, NULL, ci));

	/* AuthValue packers: NULL / zero-length inputs yield the all-zero value. */
	mesh_prov_auth_static_oob(NULL, 0, auth);
	ATF_CHECK_EQ(0, auth[0]);
	mesh_prov_auth_static_oob((const uint8_t *)"x", 0, auth);
	ATF_CHECK_EQ(0, auth[0]);
	mesh_prov_auth_alphanumeric(NULL, 0, auth);
	ATF_CHECK_EQ(0, auth[0]);
	mesh_prov_auth_alphanumeric("x", 0, auth);
	ATF_CHECK_EQ(0, auth[0]);

	/* Over-long inputs are trimmed to 16 octets (the "len > 16" arm). */
	{
		uint8_t big[20];
		size_t i;

		for (i = 0; i < sizeof(big); i++)
			big[i] = (uint8_t)(0x41 + i);
		mesh_prov_auth_static_oob(big, sizeof(big), auth);
		ATF_CHECK_EQ_MSG(0, memcmp(auth, big, 16),
		    "static-OOB longer than 16 octets must be trimmed");
		mesh_prov_auth_alphanumeric((const char *)big, sizeof(big), auth);
		ATF_CHECK_EQ_MSG(0, memcmp(auth, big, 16),
		    "alphanumeric longer than 16 octets must be trimmed");
	}
}

/* ================================================================
 * Generic Provisioning parse/segment/reassembly negative arms and the
 * PB-ADV / PB-GATT framing validation.  MshPRT_v1.1 Sections 5.3.1 / 6.3.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbadv_pbgatt_negatives);
ATF_TC_BODY(pbadv_pbgatt_negatives, tc)
{
	struct mesh_gp_parsed p;
	struct mesh_gp_reasm r;
	struct mesh_gp_pdu segs[MESH_GP_SEG_MAX];
	struct mesh_proxy_pdu psegs[8];
	uint8_t pdu[70], buf[80], got[65];
	uint32_t link_id;
	uint8_t transaction;
	const uint8_t *gp;
	size_t gl, nseg, outlen, i;
	uint8_t sar, type;
	const uint8_t *payload;
	size_t plen;

	for (i = 0; i < sizeof(pdu); i++)
		pdu[i] = (uint8_t)i;

	/* --- mesh_gp_segment bounds --- */
	ATF_CHECK_EQ(-1, mesh_gp_segment(pdu, 10, segs, MESH_GP_SEG_MAX, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_segment(pdu, 10, NULL, MESH_GP_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_gp_segment(NULL, 10, segs, MESH_GP_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_gp_segment(pdu, 0, segs, MESH_GP_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_gp_segment(pdu, MESH_PROV_PDU_MAX + 1, segs,
	    MESH_GP_SEG_MAX, &nseg));
	/* A 65-octet PDU needs 3 segments; a max of 1 is refused. */
	ATF_CHECK_EQ(-1, mesh_gp_segment(pdu, 65, segs, 1, &nseg));

	/* --- mesh_gp_parse per-GPCF validation --- */
	ATF_CHECK_EQ(-1, mesh_gp_parse(pdu, 4, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_parse(NULL, 4, &p));
	ATF_CHECK_EQ(-1, mesh_gp_parse(pdu, 0, &p));
	{
		uint8_t start_short[3] = { 0x00, 0x00, 0x05 };	/* START, len<4 */
		uint8_t start_big[25];				/* payload 21>20 */
		uint8_t ack2[2] = { 0x01, 0x00 };		/* ACK, len!=1 */
		uint8_t ackpad[1] = { 0x05 };		/* ACK, Padding != 0 */
		uint8_t cont1[1] = { 0x02 };			/* CONT, len<2 */
		uint8_t cont_big[25];				/* CONT payload 24>23 */
		uint8_t lopen[2] = { 0x03, 0x00 };		/* LINK_OPEN len!=17 */
		uint8_t lack[2] = { 0x07, 0x00 };		/* LINK_ACK len!=1 */
		uint8_t lclose[3] = { 0x0b, 0x00, 0x00 };	/* LINK_CLOSE len!=2 */
		uint8_t lbad[2] = { 0x0f, 0x00 };		/* unknown opcode */

		ATF_CHECK_EQ(-1, mesh_gp_parse(start_short, 3, &p));
		memset(start_big, 0, sizeof(start_big));
		start_big[0] = 0x04;		/* segn=1, START */
		ATF_CHECK_EQ(-1, mesh_gp_parse(start_big, sizeof(start_big), &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(ack2, 2, &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(ackpad, 1, &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(cont1, 1, &p));
		memset(cont_big, 0, sizeof(cont_big));
		cont_big[0] = 0x06;		/* seg_index=1, CONT */
		ATF_CHECK_EQ(-1, mesh_gp_parse(cont_big, sizeof(cont_big), &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(lopen, 2, &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(lack, 2, &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(lclose, 3, &p));
		ATF_CHECK_EQ(-1, mesh_gp_parse(lbad, 2, &p));
	}

	/* Public PB-ADV builders reject missing output arguments. */
	ATF_CHECK_EQ(-1, mesh_gp_ack_build(NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_gp_ack_build(buf, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_link_open_build(NULL, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_gp_link_open_build(pdu, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_gp_link_open_build(pdu, buf, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_link_ack_build(NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_gp_link_ack_build(buf, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_link_close_build(0, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_gp_link_close_build(0, buf, NULL));

	/* --- mesh_gp_reasm_input negative arms --- */
	/* gp_parse failure inside reasm. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t bad[3] = { 0x00, 0x00, 0x00 };	/* START len<4 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, bad, 3));
	}
	/* START with SegN past the cap. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t s[5] = { 0x20, 0x00, 0x01, 0x00, 0x00 };  /* segn=8 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, s, 5));
	}
	/* START with total_len == 0 and total_len > max. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t s0[4] = { 0x00, 0x00, 0x00, 0x00 };	/* total 0 */
		uint8_t sbig[5] = { 0x00, 0x00, 0x42, 0x00, 0x00 }; /* total 66 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, s0, 4));
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, sbig, 5));
	}
	/* START segn==0 but payload_len != total_len. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t s[9] = { 0x00, 0x00, 0x0a, 0x00, 1, 2, 3, 4, 5 };
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, s, 9));	/* total 10 != 5 */
	}
	/* START segn!=0 but payload_len != START_MAX. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t s[9] = { 0x04, 0x00, 0x28, 0x00, 1, 2, 3, 4, 5 };
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, s, 9));	/* payload 5 != 20 */
	}
	/* Continuation before any Start (session not active). */
	mesh_gp_reasm_init(&r);
	{
		uint8_t cont[2] = { 0x06, 0x00 };	/* CONT idx=1 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, cont, 2));
	}
	/* Active session, but a Continuation with idx 0 / idx > segn. */
	{
		uint8_t s[24];			/* START segn=1, total=41, payload 20 */
		uint8_t cont0[24];		/* CONT idx=0 */
		uint8_t contbig[24];		/* CONT idx=2 > segn=1 */

		memset(s, 0, sizeof(s));
		s[0] = 0x04; s[1] = 0x00; s[2] = 0x29;	/* segn=1, total=41 */
		mesh_gp_reasm_init(&r);
		ATF_REQUIRE_EQ(0, mesh_gp_reasm_input(&r, s, 24));	/* incomplete */
		memset(cont0, 0, sizeof(cont0));
		cont0[0] = 0x02;			/* CONT idx=0 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, cont0, 24));
		memset(contbig, 0, sizeof(contbig));
		contbig[0] = 0x0a;			/* CONT idx=2 */
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, contbig, 22));
		/* Wrong continuation payload length for the final segment. */
		{
			uint8_t cshort[5] = { 0x06, 1, 2, 3, 4 };  /* idx=1 payload 4 */
			ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, cshort, 5));
		}
	}
	/* Continuation whose (offset + payload) overflows the declared total:
	 * START segn=2 total=21 (payload must be 20), then a full 23-octet
	 * non-final continuation at idx 1 lands past total_len. */
	{
		uint8_t s[24];
		uint8_t cont[24];

		memset(s, 0, sizeof(s));
		s[0] = 0x08; s[1] = 0x00; s[2] = 0x15;	/* segn=2, total=21 */
		mesh_gp_reasm_init(&r);
		ATF_REQUIRE_EQ(0, mesh_gp_reasm_input(&r, s, 24));	/* payload 20 */
		memset(cont, 0, sizeof(cont));
		cont[0] = 0x06;				/* CONT idx=1, payload 23 */
		ATF_CHECK_EQ_MSG(-1, mesh_gp_reasm_input(&r, cont, 24),
		    "continuation past the declared total must be rejected");
	}
	/* An ACK / Bearer Control PDU is not reassembled. */
	mesh_gp_reasm_init(&r);
	{
		uint8_t ack[1] = { 0x01 };
		ATF_CHECK_EQ(-1, mesh_gp_reasm_input(&r, ack, 1));
	}
	/* reasm_complete on a fresh session is 0; reasm_get on it is -1. */
	mesh_gp_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_gp_reasm_complete(&r));
	ATF_CHECK_EQ(0, mesh_gp_reasm_complete(NULL));
	mesh_gp_reasm_init(NULL);
	ATF_CHECK_EQ(-1, mesh_gp_reasm_input(NULL, pdu, 1));
	ATF_CHECK_EQ(-1, mesh_gp_reasm_get(&r, got, NULL));
	ATF_CHECK_EQ(-1, mesh_gp_reasm_get(&r, NULL, &gl));
	ATF_CHECK_EQ_MSG(-1, mesh_gp_reasm_get(&r, got, &gl),
	    "reasm_get on an incomplete session must fail");
	ATF_CHECK_EQ(0, gl);

	/* --- PB-ADV framing --- */
	ATF_CHECK_EQ(-1, mesh_pbadv_build(0x1234, 0x00, NULL, 5, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbadv_build(0x1234, 0x00, pdu, 0, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbadv_build(0x1234, 0x00, pdu, MESH_GP_PDU_MAX + 1,
	    buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbadv_build(0x1234, 0x00, pdu, 1, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbadv_build(0x1234, 0x00, pdu, 1, buf, NULL));
	/* Build then parse a valid PB-ADV packet (success path of parse). */
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(0x23af5850, 0x07, pdu, 6, buf,
	    &outlen));
	ATF_REQUIRE_EQ(0, mesh_pbadv_parse(buf, outlen, &link_id, &transaction,
	    &gp, &gl));
	ATF_CHECK_EQ(0x23af5850, link_id);
	ATF_CHECK_EQ(0x07, transaction);
	ATF_CHECK_EQ(6, gl);
	ATF_CHECK_EQ(0, memcmp(gp, pdu, 6));
	/* PB-ADV parse rejects NULL and a too-short packet. */
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(NULL, 10, &link_id, &transaction, &gp,
	    &gl));
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(buf, MESH_PBADV_HDR_LEN, &link_id,
	    &transaction, &gp, &gl));
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(buf, outlen, NULL, &transaction, &gp,
	    &gl));
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(buf, outlen, &link_id, NULL, &gp, &gl));
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(buf, outlen, &link_id, &transaction,
	    NULL, &gl));
	ATF_CHECK_EQ(-1, mesh_pbadv_parse(buf, outlen, &link_id, &transaction,
	    &gp, NULL));

	/* --- PB-GATT framing --- */
	ATF_CHECK_EQ(-1, mesh_pbgatt_wrap(0x04, 0x00, pdu, 3, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_wrap(0x00, 0x40, pdu, 3, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_wrap(0x00, 0x00, NULL, 3, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_wrap(0, 0, pdu, 1, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_wrap(0, 0, pdu, 1, buf, NULL));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(NULL, 1, &sar, &type, &payload, &plen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(buf, 0, &sar, &type, &payload, &plen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(buf, 1, NULL, &type, &payload, &plen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(buf, 1, &sar, NULL, &payload, &plen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(buf, 1, &sar, &type, NULL, &plen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_parse(buf, 1, &sar, &type, &payload, NULL));
	/* pbgatt_segment bounds: NULL/0/oversize seg_max/too-many-segments. */
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x00, NULL, 10, 19, psegs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x00, pdu, 0, 19, psegs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x00, pdu, 10, 0, psegs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x40, pdu, 10, 19, psegs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x00, pdu, 10,
	    sizeof(psegs[0].bytes), psegs, 8, &nseg));	/* seg_max too big */
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0x00, pdu, 65, 19, psegs, 1, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0, pdu, 1, 19, NULL, 1, &nseg));
	ATF_CHECK_EQ(-1, mesh_pbgatt_segment(0, pdu, 1, 19, psegs, 1, NULL));

	/* pbgatt_wrap with an empty payload (the "plen > 0" false arm): a lone
	 * 1-octet Proxy header. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_PROVISIONING, NULL, 0, buf, &outlen));
	ATF_CHECK_EQ(1, outlen);

	/* pbgatt_segment of a PDU that fits in one segment (the "seg_count == 1"
	 * SAR=complete arm). */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_segment(MESH_PROXY_TYPE_PROVISIONING, pdu,
	    10, 19, psegs, 8, &nseg));
	ATF_CHECK_EQ(1, nseg);
	ATF_CHECK_EQ_MSG((MESH_PROXY_SAR_COMPLETE << 6) |
	    MESH_PROXY_TYPE_PROVISIONING, psegs[0].bytes[0],
	    "single PB-GATT segment must carry SAR=complete");
}

/* ================================================================
 * Provisioning algorithm 0x01: BTM_ECDH_P256_HMAC_SHA256_AES_CCM.
 * MshPRT_v1.1 Section 5.4.1.2 / 5.4.2.4.  No Section 8 vector exists for
 * this algorithm, so these assert the derivation composition (a
 * confirmation/random round-trip that a real provisioner performs) and the
 * 32-octet field selection; the underlying HMAC-SHA-256/s2/k5 primitives are
 * KAT-checked against RFC 4231 in mesh_crypto_test.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(prov_algo01_confirmation_roundtrip);
ATF_TC_BODY(prov_algo01_confirmation_roundtrip, tc)
{
	HEX(ppx, PROV_PUB_X, 32);
	HEX(ppy, PROV_PUB_Y, 32);
	HEX(dpx, DEV_PUB_X, 32);
	HEX(dpy, DEV_PUB_Y, 32);
	HEX(ecdh, ECDH_SECRET, 32);
	/* 32-octet RandomProvisioner / RandomDevice for the HMAC algorithm. */
	HEX(rp, "8b19ac31d58b124c946209b5db1021b9"
	    "b0021b91d21c3e5f8a3d2b1c0f9e8d7c", 32);
	HEX(rd, "55a2a3849dfd733b8f9a2b1c0d4e5f60"
	    "718293a4b5c6d7e8f90a1b2c3d4e5f60", 32);
	uint8_t invite[1] = { 0x00 };
	HEX(caps, "0100020000000000000000", 11);	/* Algorithms bit1 set */
	uint8_t start[5] = { MESH_PROV_ALGO_P256_HMAC, 0, 0, 0, 0 };
	uint8_t ppub[64], dpub[64];
	uint8_t auth[32];
	uint8_t ci[MESH_PROV_CONF_INPUTS_LEN];
	uint8_t csalt[32], ckey[32], confp[32], confd[32], recomp[32];

	memcpy(ppub, ppx, 32);
	memcpy(ppub + 32, ppy, 32);
	memcpy(dpub, dpx, 32);
	memcpy(dpub + 32, dpy, 32);
	mesh_prov_auth256_no_oob(auth);

	/* ConfirmationInputs is algorithm-independent (145 octets). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_inputs(invite, caps, start,
	    ppub, dpub, ci));

	/* ConfirmationSalt = s2(ConfirmationInputs). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_salt_s2(ci,
	    MESH_PROV_CONF_INPUTS_LEN, csalt));
	/* ConfirmationKey = k5(ECDHSecret || AuthValue, salt, "prck256"). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_key_hmac(ecdh, auth, csalt,
	    ckey));

	/* Confirmation = HMAC-SHA-256(ConfirmationKey, Random). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_hmac(ckey, rp, confp));
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_hmac(ckey, rd, confd));

	/*
	 * Round-trip: on receiving RandomDevice, the provisioner recomputes
	 * the device Confirmation and it must match the value the device sent.
	 */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_hmac(ckey, rd, recomp));
	ATF_CHECK_EQ_MSG(0, memcmp(recomp, confd, 32),
	    "algo 0x01 device Confirmation did not round-trip");
	/* Provisioner and device confirmations differ (distinct randoms). */
	ATF_CHECK(memcmp(confp, confd, 32) != 0);

	/* A tampered RandomDevice recomputes to a different Confirmation. */
	rd[0] ^= 0x01;
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_hmac(ckey, rd, recomp));
	ATF_CHECK_MSG(memcmp(recomp, confd, 32) != 0,
	    "tampered RandomDevice must not verify");
}

ATF_TC_WITHOUT_HEAD(prov_algo01_field_selection);
ATF_TC_BODY(prov_algo01_field_selection, tc)
{
	uint8_t conf32[32], rand32[32], conf16[16];
	uint8_t out[64], back[32];
	size_t outlen;

	memset(conf32, 0x5a, sizeof(conf32));
	memset(rand32, 0xa5, sizeof(rand32));
	memset(conf16, 0x33, sizeof(conf16));

	/* Field length is 16 for algo 0x00, 32 for algo 0x01. */
	ATF_CHECK_EQ(16, mesh_prov_auth_field_len(MESH_PROV_ALGO_P256_CMAC));
	ATF_CHECK_EQ(32, mesh_prov_auth_field_len(MESH_PROV_ALGO_P256_HMAC));

	/* Algo 0x01 Confirmation PDU is Type(1) + 32 = 33 octets. */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_build_alg(
	    MESH_PROV_ALGO_P256_HMAC, conf32, out, &outlen));
	ATF_CHECK_EQ(33, outlen);
	ATF_CHECK_EQ(MESH_PROV_CONFIRMATION, out[0]);
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_parse_alg(
	    MESH_PROV_ALGO_P256_HMAC, out, outlen, back));
	ATF_CHECK_EQ_MSG(0, memcmp(back, conf32, 32),
	    "algo 0x01 Confirmation did not round-trip");

	/* The same 33-octet PDU is rejected when parsed as algo 0x00 (17). */
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_parse_alg(
	    MESH_PROV_ALGO_P256_CMAC, out, outlen, back));

	/* Algo 0x01 Random PDU is 33 octets and round-trips. */
	ATF_REQUIRE_EQ(0, mesh_prov_random_build_alg(MESH_PROV_ALGO_P256_HMAC,
	    rand32, out, &outlen));
	ATF_CHECK_EQ(33, outlen);
	ATF_REQUIRE_EQ(0, mesh_prov_random_parse_alg(MESH_PROV_ALGO_P256_HMAC,
	    out, outlen, back));
	ATF_CHECK_EQ_MSG(0, memcmp(back, rand32, 32),
	    "algo 0x01 Random did not round-trip");

	/* Algo 0x00 still selects the 16-octet field (Type + 16 = 17). */
	ATF_REQUIRE_EQ(0, mesh_prov_confirmation_build_alg(
	    MESH_PROV_ALGO_P256_CMAC, conf16, out, &outlen));
	ATF_CHECK_EQ(17, outlen);
	/* ...and a 17-octet algo-0x00 PDU is rejected as algo 0x01. */
	ATF_CHECK_EQ(-1, mesh_prov_confirmation_parse_alg(
	    MESH_PROV_ALGO_P256_HMAC, out, outlen, back));
}

/* ================================================================
 * PB-GATT inbound Proxy PDU SAR reassembly.  MshPRT_v1.1 Section 5.3.3.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pbgatt_reasm_multisegment);
ATF_TC_BODY(pbgatt_reasm_multisegment, tc)
{
	struct mesh_pbgatt_reasm r;
	struct mesh_proxy_pdu segs[8];
	uint8_t pk[64];		/* a 64-octet Public Key Provisioning PDU body */
	uint8_t out[MESH_PROV_PDU_MAX];
	size_t nseg, outlen, i;
	int rc;

	for (i = 0; i < sizeof(pk); i++)
		pk[i] = (uint8_t)(0x40 + i);

	/* Segment a 64-octet PDU at 20 octets/segment: first+cont+cont+last. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_segment(MESH_PROXY_TYPE_PROVISIONING, pk,
	    sizeof(pk), 20, segs, 8, &nseg));
	ATF_REQUIRE(nseg >= 3);

	mesh_pbgatt_reasm_init(&r);
	for (i = 0; i < nseg; i++) {
		rc = mesh_pbgatt_reasm_input(&r, segs[i].bytes, segs[i].len,
		    out, sizeof(out), &outlen);
		if (i < nseg - 1)
			ATF_CHECK_EQ_MSG(0, rc, "mid segment should be incomplete");
		else
			ATF_CHECK_EQ_MSG(1, rc, "last segment should complete");
	}
	ATF_CHECK_EQ(sizeof(pk), outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(out, pk, sizeof(pk)),
	    "PB-GATT reassembly did not recover the original PDU");
}

ATF_TC_WITHOUT_HEAD(pbgatt_reasm_complete_single);
ATF_TC_BODY(pbgatt_reasm_complete_single, tc)
{
	struct mesh_pbgatt_reasm r;
	uint8_t pdu[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	uint8_t wrapped[16], out[MESH_PROV_PDU_MAX];
	size_t wlen, outlen;

	/* A SAR=complete Proxy PDU reassembles in one step. */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_PROVISIONING, pdu, sizeof(pdu), wrapped, &wlen));
	mesh_pbgatt_reasm_init(&r);
	ATF_CHECK_EQ(1, mesh_pbgatt_reasm_input(&r, wrapped, wlen, out,
	    sizeof(out), &outlen));
	ATF_CHECK_EQ(sizeof(pdu), outlen);
	ATF_CHECK_EQ(0, memcmp(out, pdu, sizeof(pdu)));
}

ATF_TC_WITHOUT_HEAD(pbgatt_reasm_bad_sar);
ATF_TC_BODY(pbgatt_reasm_bad_sar, tc)
{
	struct mesh_pbgatt_reasm r;
	struct mesh_proxy_pdu segs[8];
	uint8_t pk[64], out[MESH_PROV_PDU_MAX], seg[32], pay[32];
	size_t nseg, outlen, slen, i;

	for (i = 0; i < sizeof(pk); i++)
		pk[i] = (uint8_t)i;

	/* A continuation with no preceding first segment is rejected. */
	mesh_pbgatt_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_CONTINUATION,
	    MESH_PROXY_TYPE_PROVISIONING, pk, 10, seg, &slen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_reasm_input(&r, seg, slen, out,
	    sizeof(out), &outlen));

	/* A first followed by a complete (illegal mid-reassembly) is rejected. */
	mesh_pbgatt_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_FIRST,
	    MESH_PROXY_TYPE_PROVISIONING, pk, 10, seg, &slen));
	ATF_CHECK_EQ(0, mesh_pbgatt_reasm_input(&r, seg, slen, out,
	    sizeof(out), &outlen));
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_PROVISIONING, pk, 10, seg, &slen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_reasm_input(&r, seg, slen, out,
	    sizeof(out), &outlen));

	/*
	 * Oversize: enough first/continuation segments to exceed the 65-octet
	 * Provisioning PDU maximum must be rejected rather than overflow.
	 */
	ATF_REQUIRE_EQ(0, mesh_pbgatt_segment(MESH_PROXY_TYPE_PROVISIONING, pk,
	    sizeof(pk), 20, segs, 8, &nseg));
	mesh_pbgatt_reasm_init(&r);
	/* Replay first + all continuations, then feed one more oversize LAST. */
	for (i = 0; i + 1 < nseg; i++)
		(void)mesh_pbgatt_reasm_input(&r, segs[i].bytes, segs[i].len,
		    out, sizeof(out), &outlen);
	/* A LAST that would push past MESH_PROV_PDU_MAX is rejected. */
	memset(pay, 0xcc, sizeof(pay));
	ATF_REQUIRE_EQ(0, mesh_pbgatt_wrap(MESH_PROXY_SAR_LAST,
	    MESH_PROXY_TYPE_PROVISIONING, pay, 30, seg, &slen));
	ATF_CHECK_EQ(-1, mesh_pbgatt_reasm_input(&r, seg, slen, out,
	    sizeof(out), &outlen));
}

/* ================================================================
 * A Provisionee that advertises only BTM_ECDH_P256_CMAC (algorithm bit 0)
 * is spec-legal: its Capabilities must validate (MshPRT Table 5.21 /
 * Section 5.4.1.4).  Regression for the check that wrongly required the
 * HMAC bit.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(caps_cmac_only_valid);
ATF_TC_BODY(caps_cmac_only_valid, tc)
{
	struct mesh_prov_caps in, out;
	uint8_t buf[12];
	size_t outlen;

	memset(&in, 0, sizeof(in));
	in.num_elements = 1;
	in.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;	/* bit 0 only, no HMAC */

	/* Build + parse must accept CMAC-only capabilities. */
	ATF_REQUIRE_EQ(0, mesh_prov_caps_build(&in, buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_prov_caps_parse(buf, 12, &out));
	ATF_CHECK_EQ(MESH_PROV_ALGO_BIT_P256_CMAC, out.algorithms);

	/* A Capabilities advertising no supported algorithm is still invalid. */
	in.algorithms = 0;
	ATF_CHECK_EQ(-1, mesh_prov_caps_build(&in, buf, &outlen));
}

/* ================================================================
 * ProvisioningSalt for the HMAC-SHA-256 algorithm (0x01) is s1 over the
 * 32-octet ConfirmationSalt and 32-octet Randoms (a 96-octet input), not the
 * 48-octet CMAC sizing.  Regression for the primitive that hardcoded 16.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provisioning_salt_256);
ATF_TC_BODY(provisioning_salt_256, tc)
{
	uint8_t csalt[32], rp[32], rd[32];
	uint8_t msg[96], expect[16], got[16], got16[16];
	size_t i;

	for (i = 0; i < 32; i++) {
		csalt[i] = (uint8_t)(0x10 + i);
		rp[i] = (uint8_t)(0x40 + i);
		rd[i] = (uint8_t)(0x80 + i);
	}
	/* Reference: s1(ConfirmationSalt(32) || RandProv(32) || RandDev(32)). */
	memcpy(msg, csalt, 32);
	memcpy(msg + 32, rp, 32);
	memcpy(msg + 64, rd, 32);
	ATF_REQUIRE_EQ(0, mesh_s1(msg, sizeof(msg), expect));

	ATF_REQUIRE_EQ(0, mesh_prov_provisioning_salt_256(csalt, rp, rd, got));
	ATF_CHECK_EQ_MSG(0, memcmp(got, expect, 16),
	    "ProvisioningSalt (algorithm 0x01) must be s1 over 96 octets");

	/* The 48-octet (CMAC) sizing yields a different salt: sizes matter. */
	ATF_REQUIRE_EQ(0, mesh_prov_provisioning_salt(csalt, rp, rd, got16));
	ATF_CHECK(memcmp(got, got16, 16) != 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, ecdh_keypair_and_secret);
	ATF_TP_ADD_TC(tp, ecdh_reject_off_curve);
	ATF_TP_ADD_TC(tp, security_derivation_chain);
	ATF_TP_ADD_TC(tp, provisioning_data_encrypt);
	ATF_TP_ADD_TC(tp, provisioning_data_mic_tamper);
	ATF_TP_ADD_TC(tp, provisioning_data_fields);
	ATF_TP_ADD_TC(tp, confirmation_mismatch);
	ATF_TP_ADD_TC(tp, authvalue_packing);
	ATF_TP_ADD_TC(tp, pdu_validation);
	ATF_TP_ADD_TC(tp, pdu_structured_roundtrip);
	ATF_TP_ADD_TC(tp, pbadv_fcs_kat);
	ATF_TP_ADD_TC(tp, pbadv_segment_reassemble);
	ATF_TP_ADD_TC(tp, pbadv_single_segment);
	ATF_TP_ADD_TC(tp, pbadv_reassemble_fcs_reject);
	ATF_TP_ADD_TC(tp, pbadv_bearer_control);
	ATF_TP_ADD_TC(tp, pbadv_transaction_ack);
	ATF_TP_ADD_TC(tp, pbgatt_sar_public_key);
	ATF_TP_ADD_TC(tp, pbgatt_complete_wrap);
	ATF_TP_ADD_TC(tp, codec_extra);
	ATF_TP_ADD_TC(tp, ecdh_input_validation);
	ATF_TP_ADD_TC(tp, pbadv_pbgatt_negatives);
	ATF_TP_ADD_TC(tp, prov_algo01_confirmation_roundtrip);
	ATF_TP_ADD_TC(tp, prov_algo01_field_selection);
	ATF_TP_ADD_TC(tp, pbgatt_reasm_multisegment);
	ATF_TP_ADD_TC(tp, pbgatt_reasm_complete_single);
	ATF_TP_ADD_TC(tp, pbgatt_reasm_bad_sar);
	ATF_TP_ADD_TC(tp, caps_cmac_only_valid);
	ATF_TP_ADD_TC(tp, provisioning_salt_256);

	return (atf_no_error());
}
