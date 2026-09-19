/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh transport layer
 * (mesh_transport.[ch], MshPRT_v1.1 Sections 3.5 and 3.6).
 *
 * The end-to-end vectors are the worked examples of MshPRT_v1.1 Section 8.3
 * "Mesh message sample data".  Every asserted byte is taken directly from
 * the specification's Section 8.3 message dumps:
 *
 *   Section 8.3.6  (Message #6)  - Config AppKey Add, DevKey encrypted,
 *                                  segmented into two 12-octet segments.
 *   Section 8.3.7  (Message #7)  - Segment Acknowledgement, BlockAck 0x02.
 *   Section 8.3.9  (Message #9)  - Segment Acknowledgement, BlockAck 0x03.
 *   Section 8.3.18 (Message #18) - Health Current Status, AppKey encrypted,
 *                                  unsegmented (AKF=1, AID=0x26).
 *   Section 8.3.22 (Message #22) - vendor command to a virtual address,
 *                                  AppKey encrypted with the 16-octet
 *                                  Label UUID as CCM AAD.
 *
 * The upper-transport AES-CCM outputs of Messages #6, #18 and #22 were each
 * independently reproduced with the Python "cryptography" package (AESCCM)
 * over the Section 8 inputs before being committed, so a passing test
 * confirms the module against the published spec bytes rather than against
 * itself.
 *
 * Section 8 provides no segmented message with SZMIC=1 (64-bit TransMIC),
 * so the 64-bit-MIC / three-segment vector (SZMIC64_*) is an independent
 * Python-computed AES-CCM vector, clearly labelled as such; it exercises
 * the 64-bit TransMIC path and the multi-segment SAR that no Section 8
 * sample covers.
 *
 * Mesh operates in network (big-endian) byte order; no byte reversal is
 * applied.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_transport.h"
#include "spec_oracles.h"

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

/* Shared Section 8 material. */
#define	DEVKEY_HEX	"9d6dd0e96eb25dc19a40ed9914f8f03f"
#define	APPKEY_HEX	"63964771734fbd76e3b40519d1d94a48"
#define	APP_AID		BT_MSHPRT11_SAMPLE_APP_AID

/* ================================================================
 * Upper Transport Access PDU, DevKey (AKF=0), 32-bit TransMIC.
 * MshPRT_v1.1 Section 8.3.6 (Message #6, Config AppKey Add):
 *   DevKey            = 9d6dd0e96eb25dc19a40ed9914f8f03f
 *   Application nonce = 02003129ab0003120112345678 (device nonce)
 *   Access message    = 0056341263964771734fbd76e3b40519d1d94a48
 *   EncAccessMessage  = ee9dddfd2169326d23f3afdfcfdc18c52fdef772
 *   TransMIC (32-bit) = e0e17308
 *   UpperTransportPDU = ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_device_msg6);
ATF_TC_BODY(upper_device_msg6, tc)
{
	HEX(devkey, DEVKEY_HEX, 16);
	HEX(access, "0056341263964771734fbd76e3b40519d1d94a48", 20);
	HEX(exp, "ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308", 24);
	uint8_t out[24], back[20];
	size_t outlen, blen;

	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(devkey, 0, 0, 0x3129ab, 0x0003,
	    0x1201, 0x12345678, NULL, access, 20, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 24, "Message #6 upper PDU len %zu != 24",
	    outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 24), 0,
	    "Message #6 Upper Transport Access PDU mismatch (8.3.6)");

	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(devkey, 0, 0, 0x3129ab, 0x0003,
	    0x1201, 0x12345678, NULL, exp, 24, back, &blen));
	ATF_CHECK_EQ_MSG(blen, 20, "Message #6 access len %zu != 20", blen);
	ATF_CHECK_EQ_MSG(memcmp(back, access, 20), 0,
	    "Message #6 decrypt did not recover the access payload (8.3.6)");
}

/* ================================================================
 * Upper Transport Access PDU, AppKey (AKF=1, AID=0x26), 32-bit TransMIC.
 * MshPRT_v1.1 Section 8.3.18 (Message #18, Health Current Status):
 *   AppKey            = 63964771734fbd76e3b40519d1d94a48
 *   Application nonce = 01000000071201ffff12345678
 *   Access message    = 0400000000
 *   EncAccessMessage  = 5a8bde6d91
 *   TransMIC (32-bit) = 06ea078a
 *   UpperTransportPDU = 5a8bde6d9106ea078a
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_app_msg18);
ATF_TC_BODY(upper_app_msg18, tc)
{
	HEX(appkey, APPKEY_HEX, 16);
	HEX(access, "0400000000", 5);
	HEX(exp, "5a8bde6d9106ea078a", 9);
	uint8_t out[9], back[5];
	size_t outlen, blen;

	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(appkey, 1, 0, 0x000007, 0x1201,
	    0xffff, 0x12345678, NULL, access, 5, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 9, "Message #18 upper PDU len %zu != 9",
	    outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 9), 0,
	    "Message #18 Upper Transport Access PDU mismatch (8.3.18)");

	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(appkey, 1, 0, 0x000007, 0x1201,
	    0xffff, 0x12345678, NULL, exp, 9, back, &blen));
	ATF_CHECK_EQ_MSG(blen, 5, "Message #18 access len %zu != 5", blen);
	ATF_CHECK_EQ_MSG(memcmp(back, access, 5), 0,
	    "Message #18 decrypt did not recover the access payload (8.3.18)");
}

/* ================================================================
 * Upper Transport Access PDU to a virtual address: AppKey (AKF=1) with the
 * 16-octet Label UUID as CCM AAD.  MshPRT_v1.1 Section 8.3.22 (Message #22):
 *   AppKey            = 63964771734fbd76e3b40519d1d94a48
 *   Label UUID        = 0073e7e4d8b9440faf8415df4c56c0e1
 *   DST (Virtual)     = b529
 *   Application nonce = 010007080b1234b52912345677
 *   Access message    = d50a0048656c6c6f
 *   EncAccessMessage  = 3871b904d4315263
 *   TransMIC (32-bit) = 16ca48a0
 *   UpperTransportPDU = 3871b904d431526316ca48a0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_virtual_msg22);
ATF_TC_BODY(upper_virtual_msg22, tc)
{
	HEX(appkey, APPKEY_HEX, 16);
	const uint8_t label_ref[BT_MSHPRT11_LABEL_UUID_SIZE] =
	    BT_MSHPRT11_SAMPLE_LABEL_UUID_BYTES;
	uint8_t label[BT_MSHPRT11_LABEL_UUID_SIZE];
	HEX(access, "d50a0048656c6c6f", 8);
	HEX(exp, "3871b904d431526316ca48a0", 12);
	uint8_t out[12], back[8];
	size_t outlen, blen;

	memcpy(label, label_ref, sizeof(label));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(appkey, 1, 0, 0x07080b, 0x1234,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, 0x12345677, label, access, 8,
	    out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 12, "Message #22 upper PDU len %zu != 12",
	    outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 12), 0,
	    "Message #22 virtual-address Upper Transport PDU mismatch (8.3.22)");

	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(appkey, 1, 0, 0x07080b, 0x1234,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, 0x12345677, label, exp, 12,
	    back, &blen));
	ATF_CHECK_EQ_MSG(blen, 8, "Message #22 access len %zu != 8", blen);
	ATF_CHECK_EQ_MSG(memcmp(back, access, 8), 0,
	    "Message #22 decrypt did not recover the access payload (8.3.22)");

	/* Wrong Label UUID (AAD) must fail the TransMIC. */
	label[0] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(appkey, 1, 0, 0x07080b, 0x1234,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, 0x12345677, label, exp, 12,
	    back, &blen),
	    "decrypt accepted a wrong Label UUID AAD (8.3.22)");
	/* Omitting the AAD entirely must also fail. */
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(appkey, 1, 0, 0x07080b, 0x1234,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, 0x12345677, NULL, exp, 12,
	    back, &blen),
	    "decrypt accepted a missing Label UUID AAD (8.3.22)");
}

/* ================================================================
 * 64-bit TransMIC (SZMIC=1) upper transport.  Section 8 has no SZMIC=1
 * segmented sample, so this is an independent Python-computed AES-CCM
 * vector (AESCCM, tag_length=8) over these inputs:
 *   AppKey            = 63964771734fbd76e3b40519d1d94a48 (AID 0x26)
 *   Application nonce = 01800001231201ffff12345678 (ASZMIC=1)
 *   SEQ=000123 SRC=1201 DST=ffff IVindex=12345678
 *   Access payload    = 112233445566778899aabbccddeeff0011223344 (20 octets)
 *   UpperTransportPDU = f866c492c939deb1ecc4e790e8f4470dfaf19f2908f7bb95
 *                       628c7ae6  (28 octets: 20 cipher + 8 TransMIC)
 * ================================================================ */
#define	SZMIC64_ACCESS	"112233445566778899aabbccddeeff0011223344"
#define	SZMIC64_UPPER \
	"f866c492c939deb1ecc4e790e8f4470dfaf19f2908f7bb95628c7ae6"
ATF_TC_WITHOUT_HEAD(upper_szmic64);
ATF_TC_BODY(upper_szmic64, tc)
{
	HEX(appkey, APPKEY_HEX, 16);
	HEX(access, SZMIC64_ACCESS, 20);
	HEX(exp, SZMIC64_UPPER, 28);
	uint8_t out[28], back[20];
	size_t outlen, blen;

	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(appkey, 1, 1, 0x000123, 0x1201,
	    0xffff, 0x12345678, NULL, access, 20, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 28, "SZMIC=1 upper PDU len %zu != 28", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 28), 0,
	    "SZMIC=1 (64-bit TransMIC) Upper Transport PDU mismatch");

	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(appkey, 1, 1, 0x000123, 0x1201,
	    0xffff, 0x12345678, NULL, exp, 28, back, &blen));
	ATF_CHECK_EQ_MSG(blen, 20, "SZMIC=1 access len %zu != 20", blen);
	ATF_CHECK_EQ_MSG(memcmp(back, access, 20), 0,
	    "SZMIC=1 decrypt did not recover the access payload");
}

/* ================================================================
 * TransMIC tamper rejection, both MIC sizes (MshPRT 1.1 §§3.6.5.1 and
 * 3.8.2.3; published 32-bit input from §8.3.18).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_transmic_tamper);
ATF_TC_BODY(upper_transmic_tamper, tc)
{
	HEX(appkey, APPKEY_HEX, 16);
	HEX(u32, "5a8bde6d9106ea078a", 9);		/* 8.3.18, 32-bit MIC */
	HEX(u64, SZMIC64_UPPER, 28);			/* SZMIC=1, 64-bit MIC */
	uint8_t back[20];
	size_t blen;

	/* Flip the last TransMIC octet (32-bit). */
	u32[8] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(appkey, 1, 0, 0x000007, 0x1201,
	    0xffff, 0x12345678, NULL, u32, 9, back, &blen),
	    "decrypt accepted a corrupted 32-bit TransMIC");
	u32[8] ^= 0x01;
	/* Flip a ciphertext octet (32-bit): MIC check must still fail. */
	u32[0] ^= 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(appkey, 1, 0, 0x000007, 0x1201,
	    0xffff, 0x12345678, NULL, u32, 9, back, &blen),
	    "decrypt accepted a corrupted ciphertext (32-bit MIC)");

	/* Flip the last TransMIC octet (64-bit). */
	u64[27] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(appkey, 1, 1, 0x000123, 0x1201,
	    0xffff, 0x12345678, NULL, u64, 28, back, &blen),
	    "decrypt accepted a corrupted 64-bit TransMIC");
}

/* ================================================================
 * Wrong-AID / wrong-AppKey rejection.  A receiver dispatches on the AID in
 * the Lower Transport header; selecting the wrong AppKey (as happens on an
 * AID collision) must fail the TransMIC.  The AID also survives the Lower
 * Transport codec round trip so the dispatcher sees the right value
 * (MshPRT 1.1 §§3.5.2, 3.6.5.1 and 3.8.2.3; §8.3.18 input).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_wrong_aid);
ATF_TC_BODY(upper_wrong_aid, tc)
{
	HEX(appkey, APPKEY_HEX, 16);
	HEX(wrongkey, "00112233445566778899aabbccddeeff", 16);
	HEX(u32, "5a8bde6d9106ea078a", 9);		/* 8.3.18 upper PDU */
	uint8_t back[5];
	size_t blen;

	/* The correct AppKey recovers the payload; a wrong one is rejected. */
	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(appkey, 1, 0, 0x000007, 0x1201,
	    0xffff, 0x12345678, NULL, u32, 9, back, &blen));
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(wrongkey, 1, 0, 0x000007,
	    0x1201, 0xffff, 0x12345678, NULL, u32, 9, back, &blen),
	    "decrypt accepted a wrong AppKey (AID collision)");
}

/* ================================================================
 * Lower Transport unsegmented access codec.  MshPRT_v1.1 Section 8.3.18:
 *   Header (SEG=0,AKF=1,AID=0x26) = 66
 *   LowerTransportPDU = 665a8bde6d9106ea078a
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_unseg_access_msg18);
ATF_TC_BODY(lower_unseg_access_msg18, tc)
{
	HEX(upper, "5a8bde6d9106ea078a", 9);
	HEX(exp, "665a8bde6d9106ea078a", 10);
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 0;
	lo.akf = 1;
	lo.aid = APP_AID;
	memcpy(lo.data, upper, 9);
	lo.data_len = 9;

	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 10, "8.3.18 lower PDU len %zu != 10", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 10), 0,
	    "8.3.18 unsegmented-access Lower Transport PDU mismatch");

	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, exp, 10, &parsed));
	ATF_CHECK_EQ(parsed.seg, 0);
	ATF_CHECK_EQ(parsed.akf, 1);
	ATF_CHECK_EQ_MSG(parsed.aid, APP_AID, "8.3.18 AID %#x != 0x26",
	    parsed.aid);
	ATF_CHECK_EQ(parsed.data_len, 9);
	ATF_CHECK_EQ(0, memcmp(parsed.data, upper, 9));
}

/* ================================================================
 * Lower Transport segmented access codec, both segments of Section 8.3.6:
 *   seg0 Header 8026ac01, PDU 8026ac01ee9dddfd2169326d23f3afdf
 *   seg1 Header 8026ac21, PDU 8026ac21cfdc18c52fdef772e0e17308
 *   (SEG=1 AKF=0 AID=0 SZMIC=0 SeqZero=0x9ab SegN=1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_seg_access_msg6);
ATF_TC_BODY(lower_seg_access_msg6, tc)
{
	HEX(seg0d, "ee9dddfd2169326d23f3afdf", 12);
	HEX(seg1d, "cfdc18c52fdef772e0e17308", 12);
	HEX(exp0, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	HEX(exp1, "8026ac21cfdc18c52fdef772e0e17308", 16);
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	/* Segment 0. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.ctl = 0;
	lo.akf = 0;
	lo.aid = 0;
	lo.szmic = 0;
	lo.seqzero = 0x9ab;
	lo.sego = 0;
	lo.segn = 1;
	memcpy(lo.data, seg0d, 12);
	lo.data_len = 12;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 16, "8.3.6 seg0 len %zu != 16", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp0, 16), 0,
	    "8.3.6 segment #0 Lower Transport PDU mismatch");

	/* Segment 1. */
	lo.sego = 1;
	memcpy(lo.data, seg1d, 12);
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(memcmp(out, exp1, 16), 0,
	    "8.3.6 segment #1 Lower Transport PDU mismatch");

	/* Parse segment 0 back and check every field. */
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, exp0, 16, &parsed));
	ATF_CHECK_EQ(parsed.seg, 1);
	ATF_CHECK_EQ(parsed.akf, 0);
	ATF_CHECK_EQ(parsed.aid, 0);
	ATF_CHECK_EQ(parsed.szmic, 0);
	ATF_CHECK_EQ_MSG(parsed.seqzero, 0x9ab, "8.3.6 SeqZero %#x != 0x9ab",
	    parsed.seqzero);
	ATF_CHECK_EQ(parsed.sego, 0);
	ATF_CHECK_EQ(parsed.segn, 1);
	ATF_CHECK_EQ(parsed.data_len, 12);
	ATF_CHECK_EQ(0, memcmp(parsed.data, seg0d, 12));

	/* Parse segment 1: SegO must advance to 1. */
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, exp1, 16, &parsed));
	ATF_CHECK_EQ(parsed.sego, 1);
	ATF_CHECK_EQ(0, memcmp(parsed.data, seg1d, 12));
}

/* ================================================================
 * Lower Transport unsegmented control codec, using the Segment
 * Acknowledgement of Section 8.3.7 as an opcode-0 control PDU:
 *   LowerTransportPDU = 00a6ac00000002
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_unseg_control);
ATF_TC_BODY(lower_unseg_control, tc)
{
	HEX(pdu, "00a6ac00000002", 7);
	HEX(params, "a6ac00000002", 6);
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 1;
	lo.opcode = 0x00;
	memcpy(lo.data, params, 6);
	lo.data_len = 6;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 7, "8.3.7 control PDU len %zu != 7", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, pdu, 7), 0,
	    "8.3.7 unsegmented-control Lower Transport PDU mismatch");

	ATF_REQUIRE_EQ(0, mesh_lower_parse(1, pdu, 7, &parsed));
	ATF_CHECK_EQ(parsed.seg, 0);
	ATF_CHECK_EQ(parsed.ctl, 1);
	ATF_CHECK_EQ(parsed.opcode, 0x00);
	ATF_CHECK_EQ(parsed.data_len, 6);
	ATF_CHECK_EQ(0, memcmp(parsed.data, params, 6));
}

/* ================================================================
 * Lower Transport codec negatives (MshPRT 1.1 §§3.5.2.1 and 3.5.3.1).
 * ================================================================ */
/*
 * Section 3.5.2.1: an unsegmented ACCESS Lower Transport PDU carries at most
 * 15 octets of Upper Transport Access PDU; anything larger must be segmented.
 * An unsegmented control Lower Transport PDU has a separate 11-parameter
 * limit because its 8-octet NetMIC leaves 12 transport octets total.
 */
ATF_TC_WITHOUT_HEAD(lower_unseg_access_cap);
ATF_TC_BODY(lower_unseg_access_cap, tc)
{
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	uint8_t wire[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	/* 15 octets of unsegmented access is the maximum and builds. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 0;
	lo.akf = 1;
	lo.aid = 0x1a;
	memset(lo.data, 0xa5, BT_MSHPRT11_UNSEG_ACCESS_UPPER_MAX);
	lo.data_len = BT_MSHPRT11_UNSEG_ACCESS_UPPER_MAX;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(1 + BT_MSHPRT11_UNSEG_ACCESS_UPPER_MAX, outlen,
	    "15-octet unsegmented access builds");

	/* 16 octets is rejected (must be segmented). */
	lo.data_len = BT_MSHPRT11_UNSEG_ACCESS_UPPER_MAX + 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "16-octet unsegmented access is rejected");

	/* Eleven control parameters fit; twelve require segmentation. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 1;
	lo.opcode = 0x03;
	memset(lo.data, 0x5a, BT_MSHPRT11_UNSEG_CONTROL_PARAMS_MAX);
	lo.data_len = BT_MSHPRT11_UNSEG_CONTROL_PARAMS_MAX;
	ATF_CHECK_EQ_MSG(0, mesh_lower_build(&lo, out, &outlen),
	    "11-octet unsegmented control is allowed");
	lo.data_len++;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "12-octet unsegmented control is rejected");

	/* Parse: a 17-octet unsegmented access frame is malformed... */
	memset(wire, 0, sizeof(wire));
	wire[0] = 0x40 | 0x1a;			/* SEG=0, AKF=1, AID */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, wire, 1 + 16, &parsed),
	    "16 octets of unsegmented access data is rejected on parse");
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(1, wire,
	    1 + BT_MSHPRT11_UNSEG_CONTROL_PARAMS_MAX + 1, &parsed),
	    "12 octets of unsegmented control data is rejected");
}

ATF_TC_WITHOUT_HEAD(lower_negatives);
ATF_TC_BODY(lower_negatives, tc)
{
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	uint8_t trunc[3] = { 0x80, 0x26, 0xac };	/* SEG=1 but < 4 octets */
	size_t outlen;

	/* SegO > SegN is invalid on build. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.aid = 0;
	lo.seqzero = 0x9ab;
	lo.sego = 2;
	lo.segn = 1;
	lo.data[0] = 0xaa;
	lo.data_len = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted SegO > SegN");

	/* A segment longer than 12 octets is invalid on build. */
	lo.sego = 0;
	lo.data_len = BT_MSHPRT11_SEG_ACCESS_DATA_MAX + 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted a 13-octet segment");

	/* A truncated segmented PDU (< 4 octets) is invalid on parse. */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, trunc, 3, &parsed),
	    "parse accepted a truncated segmented PDU");
}

/* ================================================================
 * SAR segmentation: the full Section 8.3.6 Upper Transport PDU splits into
 * exactly the two published segments with SeqZero/SegO/SegN correct.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_segment_msg6);
ATF_TC_BODY(sar_segment_msg6, tc)
{
	HEX(upper, "ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308", 24);
	HEX(exp0, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	HEX(exp1, "8026ac21cfdc18c52fdef772e0e17308", 16);
	struct mesh_seg segs[MESH_SEG_MAX];
	size_t nseg;

	ATF_REQUIRE_EQ(0, mesh_sar_segment(0, 0, 0, 0x9ab, upper, 24, segs,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ_MSG(nseg, 2, "8.3.6 segment count %zu != 2", nseg);
	ATF_CHECK_EQ(segs[0].len, 16);
	ATF_CHECK_EQ_MSG(memcmp(segs[0].bytes, exp0, 16), 0,
	    "8.3.6 SAR segment #0 mismatch");
	ATF_CHECK_EQ(segs[1].len, 16);
	ATF_CHECK_EQ_MSG(memcmp(segs[1].bytes, exp1, 16), 0,
	    "8.3.6 SAR segment #1 mismatch");
}

/* ================================================================
 * SAR reassembly: in-order, reordered, duplicate, incomplete, using the
 * Section 8.3.6 segments (SRC = 0x0003).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_reassemble_msg6);
ATF_TC_BODY(sar_reassemble_msg6, tc)
{
	HEX(seg0, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	HEX(seg1, "8026ac21cfdc18c52fdef772e0e17308", 16);
	HEX(upper, "ee9dddfd2169326d23f3afdfcfdc18c52fdef772e0e17308", 24);
	struct mesh_reasm r;
	uint8_t out[MESH_UPPER_MAX];
	size_t olen;

	/* In order: seg0 then seg1 completes. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(0, mesh_reasm_input(&r, 0x0003, seg0, 16),
	    "seg0 alone should be incomplete");
	ATF_CHECK_EQ_MSG(1, mesh_reasm_input(&r, 0x0003, seg1, 16),
	    "seg0+seg1 should complete");
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ_MSG(olen, 24, "reassembled len %zu != 24", olen);
	ATF_CHECK_EQ_MSG(memcmp(out, upper, 24), 0,
	    "in-order reassembly did not recover the Upper Transport PDU");

	/* Reordered: seg1 then seg0 completes to the same bytes. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg1, 16));
	ATF_CHECK_EQ(1, mesh_reasm_input(&r, 0x0003, seg0, 16));
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ_MSG(memcmp(out, upper, 24), 0,
	    "reordered reassembly did not recover the Upper Transport PDU");

	/* Duplicate: seg0, seg0 again (idempotent), then seg1 completes. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));
	ATF_CHECK_EQ_MSG(0, mesh_reasm_input(&r, 0x0003, seg0, 16),
	    "duplicate seg0 must not complete the message");
	ATF_CHECK_EQ(1, mesh_reasm_input(&r, 0x0003, seg1, 16));
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ(0, memcmp(out, upper, 24));

	/* Incomplete: only seg0 -> get() must refuse. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));
	ATF_CHECK_EQ_MSG(0, mesh_reasm_complete(&r),
	    "message reported complete with a missing segment");
	ATF_CHECK_EQ_MSG(-1, mesh_reasm_get(&r, out, &olen),
	    "get() returned an incomplete message");
}

/* ================================================================
 * SAR round trip: single-segment (SegO=SegN=0) and the 3-segment / 64-bit
 * SZMIC vector (independent Python vector), covering multi-segment boundary
 * lengths (12,12,4) and reassembly ordering.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_szmic64_3seg);
ATF_TC_BODY(sar_szmic64_3seg, tc)
{
	HEX(upper, SZMIC64_UPPER, 28);
	HEX(h0, "e6848c02", 4);
	HEX(h1, "e6848c22", 4);
	HEX(h2, "e6848c42", 4);
	struct mesh_seg segs[MESH_SEG_MAX];
	struct mesh_reasm r;
	uint8_t out[MESH_UPPER_MAX];
	size_t nseg, olen;

	ATF_REQUIRE_EQ(0, mesh_sar_segment(1, APP_AID, 1, 0x123, upper, 28,
	    segs, MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ_MSG(nseg, 3, "SZMIC64 segment count %zu != 3", nseg);
	ATF_CHECK_EQ(segs[0].len, 16);	/* 4 header + 12 */
	ATF_CHECK_EQ(segs[1].len, 16);
	ATF_CHECK_EQ(segs[2].len, 8);	/* 4 header + 4 (remainder) */
	ATF_CHECK_EQ_MSG(memcmp(segs[0].bytes, h0, 4), 0,
	    "SZMIC64 seg0 header != e6848c02");
	ATF_CHECK_EQ_MSG(memcmp(segs[1].bytes, h1, 4), 0,
	    "SZMIC64 seg1 header != e6848c22");
	ATF_CHECK_EQ_MSG(memcmp(segs[2].bytes, h2, 4), 0,
	    "SZMIC64 seg2 header != e6848c42");

	/* Reassemble out of order: seg2, seg0, seg1. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x1201, segs[2].bytes,
	    segs[2].len));
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x1201, segs[0].bytes,
	    segs[0].len));
	ATF_CHECK_EQ(1, mesh_reasm_input(&r, 0x1201, segs[1].bytes,
	    segs[1].len));
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ_MSG(olen, 28, "SZMIC64 reassembled len %zu != 28", olen);
	ATF_CHECK_EQ_MSG(memcmp(out, upper, 28), 0,
	    "SZMIC64 reassembly did not recover the Upper Transport PDU");
}

/* ================================================================
 * SAR boundaries: a single-segment message and the 32-segment maximum
 * (MshPRT 1.1 §§3.5.3.1-3.5.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_boundaries);
ATF_TC_BODY(sar_boundaries, tc)
{
	uint8_t upper1[9], big[BT_MSHPRT11_UPPER_ACCESS_PDU_MAX];
	uint8_t out[MESH_UPPER_MAX];
	struct mesh_seg segs[MESH_SEG_MAX];
	struct mesh_reasm r;
	size_t nseg, olen, i;

	/* Single short Upper PDU -> one segment, SegO=SegN=0. */
	for (i = 0; i < sizeof(upper1); i++)
		upper1[i] = (uint8_t)(0x10 + i);
	ATF_REQUIRE_EQ(0, mesh_sar_segment(0, 0, 0, 0x000, upper1, 9, segs,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ_MSG(nseg, 1, "single-segment count %zu != 1", nseg);
	ATF_CHECK_EQ(segs[0].len, 4 + 9);
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(1, mesh_reasm_input(&r, 0x0007, segs[0].bytes,
	    segs[0].len), "single segment should complete immediately");
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ(olen, 9);
	ATF_CHECK_EQ(0, memcmp(out, upper1, 9));

	/* Maximum 384-octet Upper PDU -> 32 segments, SegN=31. */
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)i;
	ATF_REQUIRE_EQ(0, mesh_sar_segment(1, APP_AID, 0,
	    BT_MSHPRT11_SEQZERO_MAX, big, sizeof(big), segs, MESH_SEG_MAX,
	    &nseg));
	ATF_CHECK_EQ_MSG(nseg, BT_MSHPRT11_SEGMENT_COUNT_MAX,
	    "max segment count %zu != 32", nseg);

	mesh_reasm_init(&r);
	/* Feed in reverse; only the last-needed segment completes it. */
	for (i = 0; i < BT_MSHPRT11_SEGMENT_COUNT_MAX; i++) {
		size_t idx = BT_MSHPRT11_SEGMENT_OFFSET_MAX - i;
		int rc = mesh_reasm_input(&r, 0x0009, segs[idx].bytes,
		    segs[idx].len);
		if (i < BT_MSHPRT11_SEGMENT_OFFSET_MAX)
			ATF_CHECK_EQ_MSG(0, rc,
			    "32-seg message completed early at i=%zu", i);
		else
			ATF_CHECK_EQ_MSG(1, rc,
			    "32-seg message did not complete on last segment");
	}
	ATF_CHECK_EQ_MSG(mesh_blockack_full(BT_MSHPRT11_SEGMENT_OFFSET_MAX),
	    0xffffffffu,
	    "full BlockAck for SegN=31 must be 0xffffffff");
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ_MSG(olen, BT_MSHPRT11_UPPER_ACCESS_PDU_MAX,
	    "max reassembled len %zu",
	    olen);
	ATF_CHECK_EQ_MSG(memcmp(out, big, sizeof(big)), 0,
	    "32-segment reassembly did not recover the Upper Transport PDU");
}

/* ================================================================
 * SAR error paths (MshPRT 1.1 §3.5.3.2): SEG=0 rejected, a non-final
 * short segment rejected, and a SegN mismatch across a session rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_errors);
ATF_TC_BODY(sar_errors, tc)
{
	HEX(unseg, "665a8bde6d9106ea078a", 10);	/* SEG=0 access PDU */
	HEX(seg0, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	HEX(short0, "8026ac01ee9dddfd2169", 10);	/* SegO 0<SegN 1, 6 data */
	struct mesh_reasm r;

	/* An unsegmented PDU is not a reassembly input. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, unseg, 10),
	    "reassembly accepted an unsegmented PDU");

	/* A non-final segment must be a full 12 octets. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, short0, 10),
	    "reassembly accepted a short non-final segment");

	/* A SegN that changes mid-session is rejected. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));	/* SegN=1 */
	{
		/* Same SRC/SeqZero but SegN=2 (header 8026ac02). */
		HEX(seg0n2, "8026ac02ee9dddfd2169326d23f3afdf", 16);
		ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, seg0n2, 16),
		    "reassembly accepted an inconsistent SegN");
	}
}

/* ================================================================
 * Segment Acknowledgement message.  MshPRT_v1.1 Sections 8.3.7 and 8.3.9:
 *   Message #7: OBO=1 SeqZero=0x09ab BlockAck=00000002 -> 00a6ac00000002
 *   Message #9: OBO=1 SeqZero=0x09ab BlockAck=00000003 -> 00a6ac00000003
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(seg_ack_msg7_msg9);
ATF_TC_BODY(seg_ack_msg7_msg9, tc)
{
	HEX(exp7, "00a6ac00000002", 7);
	HEX(exp9, "00a6ac00000003", 7);
	struct mesh_seg_ack a, parsed;
	uint8_t out[MESH_SEG_ACK_LEN];
	size_t outlen;

	/* Message #7. */
	memset(&a, 0, sizeof(a));
	a.obo = 1;
	a.seqzero = 0x09ab;
	a.blockack = 0x00000002;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&a, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 7, "8.3.7 seg-ack len %zu != 7", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp7, 7), 0,
	    "8.3.7 Segment Acknowledgement PDU mismatch");

	ATF_REQUIRE_EQ(0, mesh_seg_ack_parse(exp7, 7, &parsed));
	ATF_CHECK_EQ(parsed.obo, 1);
	ATF_CHECK_EQ_MSG(parsed.seqzero, 0x09ab, "8.3.7 SeqZero %#x != 0x9ab",
	    parsed.seqzero);
	ATF_CHECK_EQ_MSG(parsed.blockack, 0x00000002u,
	    "8.3.7 BlockAck %#x != 0x2", parsed.blockack);

	/* Message #9. */
	a.blockack = 0x00000003;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&a, out, &outlen));
	ATF_CHECK_EQ_MSG(memcmp(out, exp9, 7), 0,
	    "8.3.9 Segment Acknowledgement PDU mismatch");
	ATF_REQUIRE_EQ(0, mesh_seg_ack_parse(exp9, 7, &parsed));
	ATF_CHECK_EQ(parsed.blockack, 0x00000003u);

	/* A wrong length or wrong opcode is rejected on parse. */
	ATF_CHECK_EQ(-1, mesh_seg_ack_parse(exp7, 6, &parsed));
	{
		HEX(badop, "01a6ac00000002", 7);	/* opcode != 0 */
		ATF_CHECK_EQ_MSG(-1, mesh_seg_ack_parse(badop, 7, &parsed),
		    "seg-ack parse accepted a non-zero opcode");
	}
}

/* ================================================================
 * BlockAck helpers: bitmap from a SegO set, and the full mask (MshPRT 1.1
 * §3.5.3.3; published single-bit value from §8.3.7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(blockack_helpers);
ATF_TC_BODY(blockack_helpers, tc)
{
	uint8_t set[3] = { 0, 1, 4 };

	ATF_CHECK_EQ_MSG(mesh_blockack_from_segs(set, 3), 0x00000013u,
	    "BlockAck for {0,1,4} must be 0x13");
	/* Section 8.3.7 acknowledges segment 1 only. */
	{
		uint8_t one[1] = { 1 };
		ATF_CHECK_EQ(mesh_blockack_from_segs(one, 1), 0x00000002u);
	}
	ATF_CHECK_EQ_MSG(mesh_blockack_full(0), 0x00000001u,
	    "full mask for SegN=0 must be 0x1");
	ATF_CHECK_EQ_MSG(mesh_blockack_full(1), 0x00000003u,
	    "full mask for SegN=1 must be 0x3");
	ATF_CHECK_EQ_MSG(mesh_blockack_full(BT_MSHPRT11_SEGMENT_OFFSET_MAX),
	    0xffffffffu,
	    "full mask for SegN=31 must be 0xffffffff");
}

/* ================================================================
 * Upper transport NULL-argument, length and SEQ guards, plus the device
 * nonce with SZMIC=1 (a 64-bit-TransMIC device-keyed message), which no
 * Section 8 sample exercises.  Section 3.6.5.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_guards);
ATF_TC_BODY(upper_guards, tc)
{
	HEX(devkey, DEVKEY_HEX, 16);
	uint8_t access[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t big[BT_MSHPRT11_ACCESS_PAYLOAD_MAX_MIC32 + 1];
	uint8_t out[MESH_ACCESS_MAX + MESH_TRANS_MIC64];
	uint8_t back[MESH_ACCESS_MAX + 1];
	uint8_t upperbuf[BT_MSHPRT11_UPPER_ACCESS_PDU_MAX + 1];
	size_t outlen, blen;

	memset(big, 0, sizeof(big));
	memset(upperbuf, 0, sizeof(upperbuf));

	/* encrypt: each NULL pointer argument. */
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(NULL, 0, 0, 1, 1, 1, 0, NULL,
	    access, 8, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    NULL, 8, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    access, 8, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    access, 8, out, NULL));
	/* encrypt: empty and oversized access payloads. */
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    access, 0, out, &outlen));
	ATF_CHECK_EQ_MSG(-1, mesh_upper_encrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    big, sizeof(big), out, &outlen),
	    "an access payload over MESH_ACCESS_MAX must be rejected");
	/* encrypt: SEQ out of the 24-bit range. */
	ATF_CHECK_EQ(-1, mesh_upper_encrypt(devkey, 0, 0,
	    BT_MSHPRT11_SEQ_MAX + 1, 1, 1, 0, NULL, access, 8, out, &outlen));

	/* Device nonce with SZMIC=1 (64-bit TransMIC): round trip. */
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(devkey, 0, 1, 0x000123, 0x1201,
	    0xffff, 0x12345678, NULL, access, 8, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 8 + BT_MSHPRT11_TRANS_MIC64_SIZE,
	    "device SZMIC=1 upper PDU len %zu != 16", outlen);
	ATF_REQUIRE_EQ(0, mesh_upper_decrypt(devkey, 0, 1, 0x000123, 0x1201,
	    0xffff, 0x12345678, NULL, out, outlen, back, &blen));
	ATF_CHECK_EQ(blen, 8);
	ATF_CHECK_EQ(0, memcmp(back, access, 8));

	/* decrypt: each NULL pointer argument. */
	ATF_CHECK_EQ(-1, mesh_upper_decrypt(NULL, 0, 0, 1, 1, 1, 0, NULL,
	    out, 8, back, &blen));
	ATF_CHECK_EQ(-1, mesh_upper_decrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    NULL, 8, back, &blen));
	ATF_CHECK_EQ(-1, mesh_upper_decrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    out, 8, NULL, &blen));
	ATF_CHECK_EQ(-1, mesh_upper_decrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    out, 8, back, NULL));
	/* decrypt: SEQ out of range. */
	ATF_CHECK_EQ(-1, mesh_upper_decrypt(devkey, 0, 0,
	    BT_MSHPRT11_SEQ_MAX + 1, 1, 1, 0, NULL, out, 8, back, &blen));
	/* decrypt: upper_len not longer than the TransMIC (nothing to decrypt). */
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    out, BT_MSHPRT11_TRANS_MIC32_SIZE, back, &blen),
	    "an upper PDU that is all TransMIC must be rejected");
	/* decrypt: recovered access payload over MESH_ACCESS_MAX. */
	ATF_CHECK_EQ_MSG(-1, mesh_upper_decrypt(devkey, 0, 0, 1, 1, 1, 0, NULL,
	    upperbuf, sizeof(upperbuf), back, &blen),
	    "an over-length upper PDU must be rejected");
}

/* ================================================================
 * mesh_lower_build validation arms (Section 3.5.2): NULL arguments,
 * over-long data, and every segmented/access/control field-range guard,
 * plus a segmented access build with SZMIC=1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_build_arms);
ATF_TC_BODY(lower_build_arms, tc)
{
	struct mesh_lower lo;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	/* NULL argument guards. */
	memset(&lo, 0, sizeof(lo));
	lo.data[0] = 0xaa;
	lo.data_len = 1;
	ATF_CHECK_EQ(-1, mesh_lower_build(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_lower_build(&lo, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_lower_build(&lo, out, NULL));

	/* Data longer than the Lower Transport maximum (unsegmented). */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 0;
	lo.data_len = MESH_LOWER_DATA_MAX + 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted data over MESH_LOWER_DATA_MAX");

	/* Segmented, empty segment. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.data_len = 0;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted an empty segment");

	/* Segmented field-range guards: SegO, SegN, SeqZero. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.data[0] = 0xaa;
	lo.data_len = 1;
	lo.segn = 1;
	lo.sego = BT_MSHPRT11_SEGMENT_OFFSET_MAX + 1;	/* first invalid */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted SegO > 0x1f");
	lo.sego = 0;
	lo.segn = BT_MSHPRT11_SEGMENT_OFFSET_MAX + 1;	/* first invalid */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted SegN > 0x1f");
	lo.segn = 1;
	lo.seqzero = BT_MSHPRT11_SEQZERO_MAX + 1;	/* first invalid */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted SeqZero > 0x1fff");

	/* Control opcode out of range. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 1;
	lo.opcode = BT_MSHPRT11_CONTROL_OPCODE_MAX + 1;
	lo.data[0] = 0xaa;
	lo.data_len = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted an opcode > 0x7f");

	/* Access AID out of range. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 0;
	lo.ctl = 0;
	lo.aid = BT_MSHPRT11_AID_MAX + 1;
	lo.data[0] = 0xaa;
	lo.data_len = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted an AID > 0x3f");

	/* Valid segmented access with SZMIC=1 (SZMIC bit set in the seg word). */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.ctl = 0;
	lo.szmic = 1;
	lo.seqzero = 0x9ab;
	lo.sego = 0;
	lo.segn = 0;
	memcpy(lo.data, "\x01\x02\x03\x04", 4);
	lo.data_len = 4;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	/* SZMIC=1 sets bit 23 of the seg word => out[1] bit 7. */
	ATF_CHECK_EQ_MSG(out[1] & 0x80, 0x80,
	    "SZMIC=1 must set the high bit of the segmentation word");

	/* Valid segmented CONTROL PDU: the SZMIC bit is RFU (0), not SZMIC. */
	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.ctl = 1;
	lo.opcode = 0x0a;
	lo.szmic = 1;			/* ignored for control: RFU stays 0 */
	lo.seqzero = 0x9ab;
	lo.sego = 0;
	lo.segn = 1;
	memcpy(lo.data, "\x01\x02\x03\x04", 4);
	lo.data_len = 4;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG(out[1] & 0x80, 0x00,
	    "a segmented control PDU must carry RFU=0, not SZMIC");

	/* Segmented control messages carry at most 8 parameter octets. */
	lo.data_len = BT_MSHPRT11_SEG_CONTROL_DATA_MAX + 1;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_build(&lo, out, &outlen),
	    "build accepted a 9-octet segmented control payload");
}

/* ================================================================
 * mesh_lower_parse validation arms (Section 3.5.2): NULL/zero-length
 * guards, a segmented CONTROL PDU (no SZMIC field), SegO>SegN, and the
 * three post-header length checks (over-long unsegmented, over-long
 * segment, empty segment).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_parse_arms);
ATF_TC_BODY(lower_parse_arms, tc)
{
	struct mesh_lower out;
	uint8_t buf[MESH_LOWER_DATA_MAX + 8];

	memset(buf, 0, sizeof(buf));

	/* NULL/zero guards. */
	ATF_CHECK_EQ(-1, mesh_lower_parse(0, NULL, 4, &out));
	ATF_CHECK_EQ(-1, mesh_lower_parse(0, buf, 4, NULL));
	ATF_CHECK_EQ(-1, mesh_lower_parse(0, buf, 0, &out));

	/* A segmented CONTROL PDU (ctl=1): the SZMIC field is not extracted. */
	{
		HEX(segctl, "8000000000aa", 6);		/* SEG=1, Opcode=0 */
		ATF_REQUIRE_EQ(0, mesh_lower_parse(1, segctl, 6, &out));
		ATF_CHECK_EQ(out.seg, 1);
		ATF_CHECK_EQ(out.ctl, 1);
		ATF_CHECK_EQ_MSG(out.szmic, 0,
		    "a segmented control PDU has no SZMIC field");
		segctl[1] |= 0x80;
		ATF_REQUIRE_EQ_MSG(0, mesh_lower_parse(1, segctl, 6, &out),
		    "parse rejected an ignored RFU bit");
		ATF_CHECK_EQ(out.szmic, 0);
	}

	/* SegO > SegN on parse. */
	{
		HEX(bad, "80000020aabbccddeeff00112233", 14); /* SegO=1 SegN=0 */
		ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, bad, 14, &out),
		    "parse accepted SegO > SegN");
	}

	/* Unsegmented data longer than MESH_LOWER_DATA_MAX. */
	buf[0] = 0x00;					/* SEG=0 */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, buf, MESH_LOWER_DATA_MAX + 2,
	    &out), "parse accepted over-long unsegmented data");

	/* Segmented segment longer than 12 octets. */
	buf[0] = 0x80;					/* SEG=1, seqzero/sego/segn 0 */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, buf,
	    4 + BT_MSHPRT11_SEG_ACCESS_DATA_MAX + 1,
	    &out), "parse accepted an over-long segment");

	/* The smaller segmented-control bound is 8 octets, not 12. */
	buf[0] = 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(1, buf,
	    4 + BT_MSHPRT11_SEG_CONTROL_DATA_MAX + 1, &out),
	    "parse accepted a 9-octet segmented control payload");

	/* Segmented PDU with no segment data at all. */
	ATF_CHECK_EQ_MSG(-1, mesh_lower_parse(0, buf, 4, &out),
	    "parse accepted an empty segment");
}

/* ================================================================
 * SAR segmentation validation arms (Section 3.5.3.1): NULL arguments,
 * empty/oversized upper PDU, AID and SeqZero range, and too few output
 * slots.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_segment_arms);
ATF_TC_BODY(sar_segment_arms, tc)
{
	uint8_t upper[24];
	uint8_t big[BT_MSHPRT11_UPPER_ACCESS_PDU_MAX + 1];
	struct mesh_seg segs[MESH_SEG_MAX];
	size_t nseg;

	memset(upper, 0xa5, sizeof(upper));
	memset(big, 0, sizeof(big));

	/* NULL argument guards. */
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, 0, 0, 0, NULL, 24, segs,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, 0, 0, 0, upper, 24, NULL,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, 0, 0, 0, upper, 24, segs,
	    MESH_SEG_MAX, NULL));

	/* Empty and oversized upper PDU. */
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, 0, 0, 0, upper, 0, segs,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ_MSG(-1, mesh_sar_segment(0, 0, 0, 0, big,
	    sizeof(big), segs, MESH_SEG_MAX, &nseg),
	    "an upper PDU over MESH_UPPER_MAX must be rejected");

	/* AID and SeqZero out of range. */
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, BT_MSHPRT11_AID_MAX + 1, 0, 0,
	    upper, 24, segs,
	    MESH_SEG_MAX, &nseg));
	ATF_CHECK_EQ(-1, mesh_sar_segment(0, 0, 0,
	    BT_MSHPRT11_SEQZERO_MAX + 1, upper, 24, segs,
	    MESH_SEG_MAX, &nseg));

	/* Too few output slots for the required segment count (24 -> 2 > 1). */
	ATF_CHECK_EQ_MSG(-1, mesh_sar_segment(0, 0, 0, 0, upper, 24, segs,
	    1, &nseg), "segmentation accepted too few output slots");
}

/* ================================================================
 * Reassembly NULL/inactive guards and session-key restarts (Section
 * 3.5.3.2): a segment from a different SRC or a different SeqZero starts a
 * fresh session; a duplicate of an already-complete message stays
 * complete; malformed inputs are rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(reasm_arms);
ATF_TC_BODY(reasm_arms, tc)
{
	HEX(seg0, "8026ac01ee9dddfd2169326d23f3afdf", 16);	/* seqzero 0x9ab, SegN 1 */
	HEX(segz, "80040001000102030405060708090a0b", 16);	/* seqzero 0x100, SegN 1 */
	HEX(single, "80000000000102030405060708090a0b", 16);	/* SegN 0 (complete) */
	HEX(bad, "8026", 2);					/* SEG=1 but < 4 octets */
	struct mesh_reasm r;
	uint8_t out[MESH_UPPER_MAX];
	size_t olen;

	/* init/complete NULL and inactive guards. */
	mesh_reasm_init(NULL);				/* must not crash */
	ATF_CHECK_EQ(0, mesh_reasm_complete(NULL));
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(0, mesh_reasm_complete(&r),
	    "a freshly initialised (inactive) session is not complete");

	/* input NULL guards. */
	ATF_CHECK_EQ(-1, mesh_reasm_input(NULL, 0x0003, seg0, 16));
	ATF_CHECK_EQ(-1, mesh_reasm_input(&r, 0x0003, NULL, 16));
	/* A malformed (unparsable) segment is rejected. */
	ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, bad, 2),
	    "reassembly accepted an unparsable segment");

	/* A segment from a different SRC restarts the session. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));
	ATF_CHECK_EQ_MSG(0, mesh_reasm_input(&r, 0x0004, seg0, 16),
	    "a different SRC must start a fresh session");
	ATF_CHECK_EQ(r.src, 0x0004);

	/* A segment with a different SeqZero (same SRC) restarts the session. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));
	ATF_CHECK_EQ_MSG(0, mesh_reasm_input(&r, 0x0003, segz, 16),
	    "a different SeqZero must start a fresh session");
	ATF_CHECK_EQ(r.seqzero, 0x100);

	/* AKF, AID and SZMIC are invariant across one segmented message. */
	mesh_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_reasm_input(&r, 0x0003, seg0, 16));
	{
		uint8_t changed[sizeof(seg0)];

		memcpy(changed, seg0, sizeof(changed));
		changed[0] ^= 0x40;		/* AKF */
		ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, changed,
		    sizeof(changed)), "reassembly accepted an AKF change");
		memcpy(changed, seg0, sizeof(changed));
		changed[0] ^= 0x01;		/* AID */
		ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, changed,
		    sizeof(changed)), "reassembly accepted an AID change");
		memcpy(changed, seg0, sizeof(changed));
		changed[1] ^= 0x80;		/* SZMIC */
		ATF_CHECK_EQ_MSG(-1, mesh_reasm_input(&r, 0x0003, changed,
		    sizeof(changed)), "reassembly accepted an SZMIC change");
	}

	/* A duplicate of a completed single-segment message stays complete. */
	mesh_reasm_init(&r);
	ATF_CHECK_EQ_MSG(1, mesh_reasm_input(&r, 0x0007, single, 16),
	    "a single-segment message must complete immediately");
	ATF_CHECK_EQ_MSG(1, mesh_reasm_input(&r, 0x0007, single, 16),
	    "a duplicate of a complete message must remain complete");
	ATF_REQUIRE_EQ(0, mesh_reasm_get(&r, out, &olen));
	ATF_CHECK_EQ(olen, 12);
}

/* ================================================================
 * mesh_reasm_get NULL-argument guards (lib/libmesh/mesh_transport.c local
 * API contract, exercised after a MshPRT 1.1 §3.5.3.2-shaped completion).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(reasm_get_guards);
ATF_TC_BODY(reasm_get_guards, tc)
{
	HEX(single, "80000000000102030405060708090a0b", 16);
	struct mesh_reasm r;
	uint8_t out[MESH_UPPER_MAX];
	size_t olen;

	mesh_reasm_init(&r);
	ATF_REQUIRE_EQ(1, mesh_reasm_input(&r, 0x0007, single, 16));

	ATF_CHECK_EQ(-1, mesh_reasm_get(NULL, out, &olen));
	ATF_CHECK_EQ(-1, mesh_reasm_get(&r, NULL, &olen));
	ATF_CHECK_EQ(-1, mesh_reasm_get(&r, out, NULL));
}

/* ================================================================
 * Segment Acknowledgement and BlockAck helper guards (Section 3.5.3.3):
 * NULL arguments, SeqZero range, OBO=0, a NULL SegO array, and a SegO
 * value at/above the 32-segment maximum (ignored).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(seg_ack_blockack_arms);
ATF_TC_BODY(seg_ack_blockack_arms, tc)
{
	struct mesh_seg_ack a, parsed;
	uint8_t out[MESH_SEG_ACK_LEN];
	size_t outlen;

	memset(&a, 0, sizeof(a));
	a.obo = 1;
	a.seqzero = 0x09ab;

	/* build NULL guards. */
	ATF_CHECK_EQ(-1, mesh_seg_ack_build(NULL, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_seg_ack_build(&a, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_seg_ack_build(&a, out, NULL));

	/* SeqZero out of range. */
	{
		struct mesh_seg_ack bad = a;
		bad.seqzero = BT_MSHPRT11_SEQZERO_MAX + 1;
		ATF_CHECK_EQ_MSG(-1, mesh_seg_ack_build(&bad, out, &outlen),
		    "seg-ack build accepted SeqZero > 0x1fff");
	}

	/* OBO=0 must clear the top bit of octet 1. */
	a.obo = 0;
	a.blockack = 0x00000002;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&a, out, &outlen));
	ATF_CHECK_EQ_MSG(out[1] & 0x80, 0x00,
	    "OBO=0 must leave the OBO bit clear");
	ATF_REQUIRE_EQ(0, mesh_seg_ack_parse(out, outlen, &parsed));
	ATF_CHECK_EQ(parsed.obo, 0);

	out[2] |= 0x01;
	ATF_REQUIRE_EQ_MSG(0, mesh_seg_ack_parse(out, outlen, &parsed),
	    "seg-ack parse rejected ignored RFU bits");
	ATF_CHECK_EQ(parsed.seqzero, a.seqzero);

	/* parse NULL guards. */
	ATF_CHECK_EQ(-1, mesh_seg_ack_parse(NULL, MESH_SEG_ACK_LEN, &parsed));
	ATF_CHECK_EQ(-1, mesh_seg_ack_parse(out, MESH_SEG_ACK_LEN, NULL));

	/* BlockAck helper: NULL SegO array, and an out-of-range SegO ignored. */
	ATF_CHECK_EQ(0u, mesh_blockack_from_segs(NULL, 3));
	{
		uint8_t segos[3] = {
			0, BT_MSHPRT11_SEGMENT_COUNT_MAX, 2
		};	/* 32 is outside the five-bit SegO range and is ignored. */
		ATF_CHECK_EQ_MSG(mesh_blockack_from_segs(segos, 3), 0x00000005u,
		    "a SegO >= MESH_SEG_MAX must be ignored");
	}
}

/*
 * AKF/AID bit isolation (Mesh Protocol 1.1 §3.5.2): in an access Lower
 * Transport header octet 0 is SEG(1)|AKF(1 = bit 6)|AID(6 = bits 0-5).  AKF
 * MUST come from bit 6 alone and AID from bits 0-5 alone.  The published KAT
 * vectors happen to have AID bit 5 equal to AKF, so they cannot catch a
 * decoder that reads AKF from the wrong bit.  These vectors set AID bit 5 and
 * AKF to *different* values, isolating each field.  (Kills an AKF `>>6`->`>>5`
 * shift bug that would conflate AKF with the top AID bit.)
 */
ATF_TC_WITHOUT_HEAD(lower_akf_aid_bit_isolation);
ATF_TC_BODY(lower_akf_aid_bit_isolation, tc)
{
	struct mesh_lower parsed;
	uint8_t pdu[10];

	memset(pdu, 0, sizeof(pdu));

	/* AKF=1, AID=0x06 (bit5 clear): octet0 = 0|1|000110 = 0x46. */
	pdu[0] = 0x46;
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, pdu, sizeof(pdu), &parsed));
	ATF_CHECK_EQ_MSG(parsed.akf, 1,
	    "3.5.2 AKF must read bit 6 (got %d)", parsed.akf);
	ATF_CHECK_EQ_MSG(parsed.aid, 0x06,
	    "3.5.2 AID must be bits 0-5 (got %#x)", parsed.aid);

	/* AKF=0, AID=0x20 (bit5 set): octet0 = 0|0|100000 = 0x20. */
	pdu[0] = 0x20;
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, pdu, sizeof(pdu), &parsed));
	ATF_CHECK_EQ_MSG(parsed.akf, 0,
	    "3.5.2 AKF=0 must not pick up AID bit 5 (got %d)", parsed.akf);
	ATF_CHECK_EQ_MSG(parsed.aid, 0x20,
	    "3.5.2 AID must be bits 0-5 (got %#x)", parsed.aid);
}

/* ================================================================
 * Segmented access SZMIC round-trip (Mesh Protocol 1.1 §3.5.2.1).
 * The SZMIC bit of a segmented Access message (bit 23 of the 4-octet
 * segmentation header, i.e. out[1] bit 7) selects a 64-bit vs 32-bit
 * Upper Transport MIC and MUST be recovered on parse.  A parser that
 * fails to read SZMIC back (e.g. hard-codes it to 0) would silently
 * downgrade a 64-bit-MIC message to 32-bit verification.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lower_seg_szmic_roundtrip);
ATF_TC_BODY(lower_seg_szmic_roundtrip, tc)
{
	struct mesh_lower lo, parsed;
	uint8_t out[MESH_LOWER_DATA_MAX + 4];
	size_t outlen;

	memset(&lo, 0, sizeof(lo));
	lo.seg = 1;
	lo.ctl = 0;
	lo.akf = 1;
	lo.aid = 0x26;
	lo.szmic = 1;			/* 64-bit TransMIC */
	lo.seqzero = 0x9ab;
	lo.sego = 0;
	lo.segn = 1;
	memset(lo.data, 0xAA, BT_MSHPRT11_SEG_ACCESS_DATA_MAX);
	lo.data_len = BT_MSHPRT11_SEG_ACCESS_DATA_MAX;

	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	/* SZMIC is the top bit of the first segmentation-header octet. */
	ATF_CHECK_EQ_MSG((out[1] & 0x80), 0x80,
	    "3.5.2.1 SZMIC=1 must set bit 7 of out[1] (got %#x)", out[1]);

	/* Parse it back: SZMIC MUST survive the round-trip. */
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, out, outlen, &parsed));
	ATF_CHECK_EQ_MSG(parsed.szmic, 1,
	    "3.5.2.1 parsed SZMIC must be 1, got %d", parsed.szmic);
	ATF_CHECK_EQ(parsed.seg, 1);
	ATF_CHECK_EQ(parsed.akf, 1);
	ATF_CHECK_EQ(parsed.aid, 0x26);
	ATF_CHECK_EQ(parsed.seqzero, 0x9ab);

	/* And SZMIC=0 must parse back to 0 (guards an always-1 mutant). */
	lo.szmic = 0;
	ATF_REQUIRE_EQ(0, mesh_lower_build(&lo, out, &outlen));
	ATF_CHECK_EQ_MSG((out[1] & 0x80), 0x00,
	    "3.5.2.1 SZMIC=0 must clear bit 7 of out[1] (got %#x)", out[1]);
	ATF_REQUIRE_EQ(0, mesh_lower_parse(0, out, outlen, &parsed));
	ATF_CHECK_EQ_MSG(parsed.szmic, 0,
	    "3.5.2.1 parsed SZMIC must be 0, got %d", parsed.szmic);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, upper_device_msg6);
	ATF_TP_ADD_TC(tp, upper_app_msg18);
	ATF_TP_ADD_TC(tp, upper_virtual_msg22);
	ATF_TP_ADD_TC(tp, upper_szmic64);
	ATF_TP_ADD_TC(tp, upper_transmic_tamper);
	ATF_TP_ADD_TC(tp, upper_wrong_aid);
	ATF_TP_ADD_TC(tp, lower_unseg_access_msg18);
	ATF_TP_ADD_TC(tp, lower_seg_access_msg6);
	ATF_TP_ADD_TC(tp, lower_akf_aid_bit_isolation);
	ATF_TP_ADD_TC(tp, lower_seg_szmic_roundtrip);
	ATF_TP_ADD_TC(tp, lower_unseg_control);
	ATF_TP_ADD_TC(tp, lower_unseg_access_cap);
	ATF_TP_ADD_TC(tp, lower_negatives);
	ATF_TP_ADD_TC(tp, sar_segment_msg6);
	ATF_TP_ADD_TC(tp, sar_reassemble_msg6);
	ATF_TP_ADD_TC(tp, sar_szmic64_3seg);
	ATF_TP_ADD_TC(tp, sar_boundaries);
	ATF_TP_ADD_TC(tp, sar_errors);
	ATF_TP_ADD_TC(tp, seg_ack_msg7_msg9);
	ATF_TP_ADD_TC(tp, blockack_helpers);
	ATF_TP_ADD_TC(tp, upper_guards);
	ATF_TP_ADD_TC(tp, lower_build_arms);
	ATF_TP_ADD_TC(tp, lower_parse_arms);
	ATF_TP_ADD_TC(tp, sar_segment_arms);
	ATF_TP_ADD_TC(tp, reasm_arms);
	ATF_TP_ADD_TC(tp, reasm_get_guards);
	ATF_TP_ADD_TC(tp, seg_ack_blockack_arms);

	return (atf_no_error());
}
