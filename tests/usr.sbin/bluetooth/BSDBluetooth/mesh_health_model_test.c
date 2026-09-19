/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh Health model
 * (mesh_health_model.[ch], MshMDL_v1.1 Section 7).
 *
 * The Health Current Status vector is the Access payload of MshPRT_v1.1
 * Section 8.3.18 (Message #18):
 *
 *   Access message = 0400000000
 *
 * which is opcode 0x04 (Health Current Status), TestID 0x00, CompanyID
 * 0x0000 (little-endian) and a one-octet FaultArray {0x00} ("No Fault").
 * This exact byte string is asserted for both build and parse.
 *
 * The remaining messages are asserted against byte strings hand-derived from
 * the field-layout and little-endian rules of MshMDL Section 7 (CompanyID is
 * little-endian; a FaultArray is a run of one-octet fault codes); the field
 * VALUES are illustrative but every octet's position and endianness is from
 * the specification, and each is checked for both build and parse.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_health_model.h"
#include "spec_mesh_health_oracles.h"

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
 * Health Current Status: MshPRT Section 8.3.18 access payload.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(current_status_msg18);
ATF_TC_BODY(current_status_msg18, tc)
{
	struct mesh_hlt_fault_status in, out;
	HEX(exp, "0400000000", 5);
	uint8_t buf[8];
	size_t outlen;
	uint32_t op;

	memset(&in, 0, sizeof(in));
	in.test_id = 0x00;
	in.company_id = 0x0000;
	in.faults[0] = 0x00;
	in.n_faults = 1;

	ATF_REQUIRE_EQ(0, mesh_hlt_current_status_build(&in, buf, &outlen));
	ATF_CHECK_EQ_MSG(5, (int)outlen, "Current Status access PDU is 5 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, 5),
	    "Health Current Status must equal the Section 8.3.18 bytes");

	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(exp, 5, &op, &out));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_CURRENT_STATUS, op);
	ATF_CHECK_EQ(0x00, out.test_id);
	ATF_CHECK_EQ(0x0000, out.company_id);
	ATF_CHECK_EQ_MSG(1, (int)out.n_faults, "one fault octet present");
	ATF_CHECK_EQ(0x00, out.faults[0]);
}

/* ================================================================
 * Fault Status with a non-trivial FaultArray (opcode 0x05).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_status_array);
ATF_TC_BODY(fault_status_array, tc)
{
	struct mesh_hlt_fault_status in, out;
	HEX(exp, "0503f1050251", 6);
	uint8_t buf[16];
	size_t outlen;
	uint32_t op;

	/* TestID 0x03, CompanyID 0x05F1 (LE f1 05), faults {0x02, 0x51}. */
	memset(&in, 0, sizeof(in));
	in.test_id = 0x03;
	in.company_id = 0x05f1;
	in.faults[0] = 0x02;
	in.faults[1] = 0x51;
	in.n_faults = 2;

	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_build(&in, buf, &outlen));
	ATF_CHECK_EQ(6, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, 6), "Fault Status access PDU");
	ATF_CHECK_EQ_MSG(0x05, buf[0], "opcode 0x05 (Health Fault Status)");
	ATF_CHECK_EQ_MSG(0xf1, buf[2], "CompanyID low octet (little-endian)");
	ATF_CHECK_EQ_MSG(0x05, buf[3], "CompanyID high octet (little-endian)");

	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(exp, 6, &op, &out));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_FAULT_STATUS, op);
	ATF_CHECK_EQ(0x03, out.test_id);
	ATF_CHECK_EQ(0x05f1, out.company_id);
	ATF_CHECK_EQ(2, (int)out.n_faults);
	ATF_CHECK_EQ(0x02, out.faults[0]);
	ATF_CHECK_EQ(0x51, out.faults[1]);

	/* Empty fault array (no registered faults) is a valid 3-octet status. */
	memset(&in, 0, sizeof(in));
	in.test_id = 0x00;
	in.company_id = 0x05f1;
	in.n_faults = 0;
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_build(&in, buf, &outlen));
	ATF_CHECK_EQ_MSG(4, (int)outlen, "opcode + 3 params, no faults");
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(buf, outlen, &op, &out));
	ATF_CHECK_EQ(0, (int)out.n_faults);
}

/* ================================================================
 * Fault Get / Clear / Test.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_get_clear_test);
ATF_TC_BODY(fault_get_clear_test, tc)
{
	HEX(exp_get, "8031f105", 4);
	HEX(exp_test, "803203f105", 5);
	uint8_t buf[8];
	size_t outlen;
	uint32_t op;
	uint16_t cid;
	uint8_t tid;

	/* Fault Get (0x8031), CompanyID 0x05F1. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(0x05f1, buf, &outlen));
	ATF_CHECK_EQ(4, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_get, 4), "Fault Get access PDU");
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_parse(exp_get, 4, &cid));
	ATF_CHECK_EQ(0x05f1, cid);

	/* Fault Clear (0x802F) round trip. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_clear_build(BT_MESH_HLT_OP_FAULT_CLEAR,
	    0x05f1, buf, &outlen));
	ATF_CHECK_EQ(0x80, buf[0]);
	ATF_CHECK_EQ(0x2f, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_clear_parse(buf, outlen, &op, &cid));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_FAULT_CLEAR, op);
	ATF_CHECK_EQ(0x05f1, cid);

	/* Fault Test (0x8032), TestID 0x03, CompanyID 0x05F1. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_build(BT_MESH_HLT_OP_FAULT_TEST,
	    0x03,
	    0x05f1, buf, &outlen));
	ATF_CHECK_EQ(5, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_test, 5), "Fault Test access PDU");
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_parse(exp_test, 5, &op, &tid, &cid));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_FAULT_TEST, op);
	ATF_CHECK_EQ(0x03, tid);
	ATF_CHECK_EQ(0x05f1, cid);
}

/* ================================================================
 * Period + Attention.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(period_attention);
ATF_TC_BODY(period_attention, tc)
{
	HEX(exp_period, "803704", 3);
	HEX(exp_att, "80050a", 3);
	uint8_t buf[8];
	size_t outlen;
	uint32_t op;
	uint8_t v;

	/* Period Status (0x8037), FastPeriodDivisor 0x04. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_STATUS,
	    0x04,
	    buf, &outlen));
	ATF_CHECK_EQ(3, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_period, 3), "Period Status access PDU");
	ATF_REQUIRE_EQ(0, mesh_hlt_period_parse(exp_period, 3, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_PERIOD_STATUS, op);
	ATF_CHECK_EQ(0x04, v);

	/* FastPeriodDivisor > 15 is invalid. */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_SET,
	    BT_MESH_HLT_FAST_PERIOD_DIVISOR_ABOVE_MAX,
	    buf, &outlen), "FastPeriodDivisor is 4-bit (0..15)");

	/* Period Get (0x8034) carries no parameters. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_GET, 0, buf,
	    &outlen));
	ATF_CHECK_EQ_MSG(2, (int)outlen, "Period Get is opcode-only");

	/* Attention Set (0x8005), 10 seconds. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_SET,
	    0x0a, buf, &outlen));
	ATF_CHECK_EQ(3, (int)outlen);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_att, 3), "Attention Set access PDU");
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_parse(exp_att, 3, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_ATTENTION_SET, op);
	ATF_CHECK_EQ(0x0a, v);

	/* Attention Get (0x8004) carries no parameters. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_GET,
	    0,
	    buf, &outlen));
	ATF_CHECK_EQ(2, (int)outlen);
}

/* ================================================================
 * Server state: register faults, then emit a Fault Status ("test with
 * fault") and verify the FaultArray round-trips.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(server_fault_state);
ATF_TC_BODY(server_fault_state, tc)
{
	struct mesh_hlt_server_state s;
	struct mesh_hlt_fault_status fs, out;
	uint8_t buf[16];
	size_t outlen;
	uint32_t op;

	mesh_hlt_server_init(&s, 0x05f1);
	ATF_CHECK_EQ(0, (int)s.n_registered_faults);	/* P-M14 */

	/* A test registers faults; 0x00 (No Fault) is not stored. */
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&s, 0x02));
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&s, 0x51));
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&s, 0x02));	/* duplicate */
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&s, 0x00));	/* No Fault */
	ATF_CHECK_EQ_MSG(2, (int)s.n_registered_faults,		/* P-M14 */
	    "duplicates and No Fault ignored");

	/* Emit a Fault Status from the registered faults (test-with-fault). */
	memset(&fs, 0, sizeof(fs));
	fs.test_id = 0x03;
	fs.company_id = s.company_id;
	memcpy(fs.faults, s.registered_faults, s.n_registered_faults); /* P-M14 */
	fs.n_faults = s.n_registered_faults;
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_build(&fs, buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(buf, outlen, &op, &out));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_FAULT_STATUS, op);
	ATF_CHECK_EQ(0x05f1, out.company_id);
	ATF_CHECK_EQ(2, (int)out.n_faults);
	ATF_CHECK_EQ(0x02, out.faults[0]);
	ATF_CHECK_EQ(0x51, out.faults[1]);

	/* Health Fault Clear returns the Registered array to empty. */
	mesh_hlt_server_clear_faults(&s);
	ATF_CHECK_EQ(0, (int)s.n_registered_faults);	/* P-M14 */
}

/* Malformed rejection. */
ATF_TC_WITHOUT_HEAD(hlt_negatives);
ATF_TC_BODY(hlt_negatives, tc)
{
	struct mesh_hlt_fault_status fs;
	uint16_t cid;
	uint32_t op;
	HEX(good_get, "8031f105", 4);
	HEX(short_status, "0400", 2);	/* opcode 0x04, only 1 param octet */

	/* Fault Status needs at least TestID + CompanyID (3 params). */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_status_parse(short_status, 2, &op,
	    &fs), "Current Status shorter than TestID+CompanyID is invalid");

	/* Wrong opcode fed to Fault Get. */
	{
		HEX(att, "80050a", 3);
		ATF_CHECK_EQ(-1, mesh_hlt_fault_get_parse(att, 3, &cid));
	}

	/* Fault Get with the wrong parameter length. */
	ATF_CHECK_EQ(-1, mesh_hlt_fault_get_parse(good_get, 3, &cid));
}

/* ================================================================
 * Spec-oracle negatives for the Fault/Current Status codecs.
 *
 * Section 7 Fault/Current Status is TestID(1)|CompanyID(2)|FaultArray(0..N).
 * build() rejects a NULL struct and an over-long FaultArray; parse() rejects
 * a NULL out, a malformed access PDU, a non-status opcode, a body shorter
 * than the 3-octet header, and a FaultArray longer than MESH_HLT_MAX_FAULTS.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_status_negatives);
ATF_TC_BODY(fault_status_negatives, tc)
{
	struct mesh_hlt_fault_status in, out;
	uint8_t buf[8 + MESH_HLT_MAX_FAULTS];
	uint8_t big[3 + MESH_HLT_MAX_FAULTS + 2];
	size_t outlen;

	/* build: NULL struct is rejected. */
	ATF_CHECK_EQ(-1, mesh_hlt_current_status_build(NULL, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_hlt_fault_status_build(NULL, buf, &outlen));

	/* build: a FaultArray longer than the accepted bound is rejected. */
	memset(&in, 0, sizeof(in));
	in.company_id = 0x05f1;
	in.n_faults = MESH_HLT_MAX_FAULTS + 1;
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_status_build(&in, buf, &outlen),
	    "FaultArray beyond MESH_HLT_MAX_FAULTS is rejected");

	/* parse: NULL out. */
	memset(big, 0, sizeof(big));
	big[0] = 0x04;			/* Current Status opcode, 1-octet */
	ATF_CHECK_EQ(-1, mesh_hlt_fault_status_parse(big, 4, NULL, NULL));

	/* parse: malformed access PDU (reserved one-octet opcode 0x7F). */
	{
		uint8_t rfu = BT_MESH_ACCESS_OPCODE_ONE_RFU;
		ATF_CHECK_EQ(-1, mesh_hlt_fault_status_parse(&rfu, 1, NULL,
		    &out));
	}

	/* parse: a valid but non-status opcode (0x8100). */
	{
		uint8_t wrong[2] = { 0x81, 0x00 };
		ATF_CHECK_EQ(-1, mesh_hlt_fault_status_parse(wrong, 2, NULL,
		    &out));
	}

	/* parse: FaultArray longer than MESH_HLT_MAX_FAULTS (opcode + 3 +
	 * 65 fault octets => params_len-3 == 65 > 64). Feed with NULL opcode
	 * to also cover the opcode == NULL arm. */
	big[0] = 0x05;			/* Fault Status opcode */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_status_parse(big,
	    (size_t)(1 + 3 + MESH_HLT_MAX_FAULTS + 1), NULL, &out),
	    "FaultArray beyond MESH_HLT_MAX_FAULTS is rejected on parse");

	/* parse: well-formed with opcode == NULL (cover the NULL-opcode arm). */
	big[0] = 0x04;
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(big, 4, NULL, &out));
	ATF_CHECK_EQ(0, (int)out.n_faults);
}

/* ================================================================
 * Spec-oracle negatives for Fault Get/Clear/Test.  Each parse has an
 * opcode-mismatch, a params-length-mismatch and a malformed-PDU arm; each
 * build with an opcode argument rejects the wrong opcode.  NULL out-params
 * are accepted (the value is simply not reported).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_get_clear_test_negatives);
ATF_TC_BODY(fault_get_clear_test_negatives, tc)
{
	uint8_t buf[8];
	uint8_t rfu = BT_MESH_ACCESS_OPCODE_ONE_RFU;
	uint8_t wrong[2] = { 0x81, 0x00 };	/* valid opcode 0x8100 */
	size_t outlen;

	/* Fault Get: NULL company_id accepted; malformed PDU rejected. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(0x05f1, buf, &outlen));
	ATF_CHECK_EQ(0, mesh_hlt_fault_get_parse(buf, outlen, NULL));
	ATF_CHECK_EQ(-1, mesh_hlt_fault_get_parse(&rfu, 1, NULL));

	/* Fault Clear: build rejects a wrong opcode. */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_clear_build(BT_MESH_HLT_OP_FAULT_GET,
	    0x05f1, buf, &outlen), "Fault Clear build rejects a non-clear opcode");
	/* Clear Unacknowledged (0x8030) is the second accepted opcode. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_clear_build(
	    BT_MESH_HLT_OP_FAULT_CLEAR_UNACK, 0x05f1, buf, &outlen));
	ATF_CHECK_EQ(0x30, buf[1]);
	ATF_CHECK_EQ(0, mesh_hlt_fault_clear_parse(buf, outlen, NULL, NULL));
	/* parse: malformed, wrong opcode, wrong length. */
	ATF_CHECK_EQ(-1, mesh_hlt_fault_clear_parse(&rfu, 1, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_hlt_fault_clear_parse(wrong, 2, NULL, NULL));
	{
		uint8_t bad[5] = { 0x80, 0x2f, 0x01, 0x02, 0x03 }; /* 3 params */
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_clear_parse(bad, 5, NULL,
		    NULL), "Fault Clear with != 2 params is rejected");
	}

	/* Fault Test: build rejects a wrong opcode. */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_test_build(BT_MESH_HLT_OP_FAULT_GET,
	    0x03, 0x05f1, buf, &outlen), "Fault Test build rejects a non-test opcode");
	/* Test Unacknowledged (0x8033) is the second accepted opcode. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_build(
	    BT_MESH_HLT_OP_FAULT_TEST_UNACK,
	    0x03, 0x05f1, buf, &outlen));
	ATF_CHECK_EQ(0x33, buf[1]);
	ATF_CHECK_EQ(0, mesh_hlt_fault_test_parse(buf, outlen, NULL, NULL, NULL));
	/* parse: malformed, wrong opcode, wrong length. */
	ATF_CHECK_EQ(-1, mesh_hlt_fault_test_parse(&rfu, 1, NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_hlt_fault_test_parse(wrong, 2, NULL, NULL, NULL));
	{
		uint8_t bad[4] = { 0x80, 0x32, 0x03 };	/* 1 param, need 3 */
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_fault_test_parse(bad, 3, NULL,
		    NULL, NULL), "Fault Test with != 3 params is rejected");
	}
}

/* ================================================================
 * Spec-oracle coverage for Period and Attention (Sections 7.x): every
 * accepted opcode of the build/parse switch plus the reject arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(period_attention_negatives);
ATF_TC_BODY(period_attention_negatives, tc)
{
	uint8_t buf[8];
	uint8_t rfu = BT_MESH_ACCESS_OPCODE_ONE_RFU;
	uint8_t wrong[2] = { 0x81, 0x00 };
	size_t outlen;
	uint32_t op;
	uint8_t v;

	/* Period build: Set Unack (0x8036) is accepted; a bad opcode is not. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_SET_UNACK,
	    3,
	    buf, &outlen));
	ATF_CHECK_EQ(0x36, buf[1]);
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_period_build(BT_MESH_HLT_OP_FAULT_GET, 0,
	    buf,
	    &outlen), "Period build rejects a non-period opcode");

	/* Period parse: Get with no params (round trip), and NULL out-params. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_GET, 0, buf,
	    &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_period_parse(buf, outlen, NULL, NULL));
	/* Period parse: Set and Set Unack opcodes. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_SET, 5, buf,
	    &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_period_parse(buf, outlen, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_PERIOD_SET, op);
	ATF_CHECK_EQ(5, v);
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_SET_UNACK,
	    6,
	    buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_period_parse(buf, outlen, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_PERIOD_SET_UNACK, op);
	/* Period parse: a Set PDU with a NULL divisor out-param is accepted. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(BT_MESH_HLT_OP_PERIOD_SET, 7, buf,
	    &outlen));
	ATF_CHECK_EQ(0, mesh_hlt_period_parse(buf, outlen, NULL, NULL));
	/* Period parse: malformed, wrong opcode, Get-with-params, Set-wrong-len. */
	ATF_CHECK_EQ(-1, mesh_hlt_period_parse(&rfu, 1, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_hlt_period_parse(wrong, 2, NULL, NULL));
	{
		uint8_t get_bad[3] = { 0x80, 0x34, 0x00 };	/* Get + 1 param */
		uint8_t set_bad[2] = { 0x80, 0x35 };		/* Set + 0 param */
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_period_parse(get_bad, 3, NULL,
		    NULL), "Period Get carries no parameters");
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_period_parse(set_bad, 2, NULL,
		    NULL), "Period Set carries exactly one parameter");
	}

	/* Attention build: Set Unack (0x8006) and Status (0x8007) accepted. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(
	    BT_MESH_HLT_OP_ATTENTION_SET_UNACK, 4, buf, &outlen));
	ATF_CHECK_EQ(0x06, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_STATUS,
	    4, buf, &outlen));
	ATF_CHECK_EQ(0x07, buf[1]);
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_attention_build(BT_MESH_HLT_OP_FAULT_GET, 0,
	    buf, &outlen), "Attention build rejects a non-attention opcode");

	/* Attention parse: Get (no params), Set Unack, Status; NULL out-params. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_GET,
	    0,
	    buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_parse(buf, outlen, NULL, NULL));
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(
	    BT_MESH_HLT_OP_ATTENTION_SET_UNACK, 9, buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_parse(buf, outlen, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_ATTENTION_SET_UNACK, op);
	ATF_CHECK_EQ(9, v);
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_STATUS,
	    2, buf, &outlen));
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_parse(buf, outlen, &op, &v));
	ATF_CHECK_EQ(BT_MESH_HLT_OP_ATTENTION_STATUS, op);
	/* Attention parse: a Set PDU with a NULL attention out-param is accepted. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(BT_MESH_HLT_OP_ATTENTION_SET,
	    3,
	    buf, &outlen));
	ATF_CHECK_EQ(0, mesh_hlt_attention_parse(buf, outlen, NULL, NULL));
	/* Attention parse: malformed, wrong opcode, Get-with-params, Set-wrong-len. */
	ATF_CHECK_EQ(-1, mesh_hlt_attention_parse(&rfu, 1, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_hlt_attention_parse(wrong, 2, NULL, NULL));
	{
		uint8_t get_bad[3] = { 0x80, 0x04, 0x00 };	/* Get + 1 param */
		uint8_t set_bad[2] = { 0x80, 0x05 };		/* Set + 0 param */
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_attention_parse(get_bad, 3, NULL,
		    NULL), "Attention Get carries no parameters");
		ATF_CHECK_EQ_MSG(-1, mesh_hlt_attention_parse(set_bad, 2, NULL,
		    NULL), "Attention Set carries exactly one parameter");
	}
}

/* ================================================================
 * Health Server state guards (Section 7.4.1): NULL handling and the
 * fault-table-full path.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(server_state_guards);
ATF_TC_BODY(server_state_guards, tc)
{
	struct mesh_hlt_server_state s;
	int i;

	/* NULL-safe entry points. */
	mesh_hlt_server_init(NULL, 0x05f1);
	mesh_hlt_server_clear_faults(NULL);
	ATF_CHECK_EQ(-1, mesh_hlt_server_add_fault(NULL, 0x01));

	/* Fill the table with distinct faults (1..MESH_HLT_MAX_FAULTS), then
	 * one more must be rejected (table full). */
	mesh_hlt_server_init(&s, 0x05f1);
	for (i = 1; i <= MESH_HLT_MAX_FAULTS; i++)
		ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&s,
		    (uint8_t)i));
	ATF_CHECK_EQ_MSG((int)MESH_HLT_MAX_FAULTS, (int)s.n_registered_faults,
	    "table holds MESH_HLT_MAX_FAULTS distinct faults");	/* P-M14 */
	ATF_CHECK_EQ_MSG(-1, mesh_hlt_server_add_fault(&s, 0xff),
	    "a full fault table rejects a new fault");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, current_status_msg18);
	ATF_TP_ADD_TC(tp, fault_status_array);
	ATF_TP_ADD_TC(tp, fault_get_clear_test);
	ATF_TP_ADD_TC(tp, period_attention);
	ATF_TP_ADD_TC(tp, server_fault_state);
	ATF_TP_ADD_TC(tp, hlt_negatives);
	ATF_TP_ADD_TC(tp, fault_status_negatives);
	ATF_TP_ADD_TC(tp, fault_get_clear_test_negatives);
	ATF_TP_ADD_TC(tp, period_attention_negatives);
	ATF_TP_ADD_TC(tp, server_state_guards);

	return (atf_no_error());
}
