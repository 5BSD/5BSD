/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh access layer
 * (mesh_access.[ch], MshPRT_v1.1 Section 3.7).
 *
 * The access layer is a cleartext codec; there are no crypto vectors here.
 * The asserted bytes come from the opcode-format rules of Section 3.7.3.1
 * (Table 3.43): one-octet 0x00..0x7E, two-octet 0x80xx..0xBFxx, three-octet
 * vendor 0xC0.. with a little-endian Company Identifier, and the reserved
 * one-octet opcode 0x7F.  Every boundary of the length-detection rule is
 * exercised (0x7F/0x80/0xBF/0xC0/0xFF).
 *
 * Mesh is network (big-endian) byte order for SIG opcodes; the vendor
 * Company Identifier is the documented little-endian exception.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "spec_oracles.h"

/* ================================================================
 * Opcode length detection at every boundary (Section 3.7.3.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(opcode_len_boundaries);
ATF_TC_BODY(opcode_len_boundaries, tc)
{

	/* One-octet range 0x00..0x7E. */
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_ONE_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN),
	    "0x00 is a one-octet opcode");
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_ONE_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_ONE_MAX),
	    "0x7E is the last valid one-octet opcode");
	/* 0x7F is reserved for future use: not a valid opcode. */
	ATF_CHECK_EQ_MSG(-1,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_ONE_RFU),
	    "0x7F is reserved (one-octet RFU)");

	/* Two-octet range 0x8000..0xBFFF. */
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN),
	    "0x8000 is the first two-octet opcode");
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_TWO_MAX),
	    "0xBFFF is the last two-octet opcode");
	/* The gap between one- and two-octet forms is invalid. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_opcode_len(0x0080),
	    "0x0080 is not a valid opcode (gap)");
	ATF_CHECK_EQ_MSG(-1, mesh_access_opcode_len(0x7fff),
	    "0x7FFF is not a valid opcode (gap)");

	/* Three-octet vendor range 0xC00000..0xFFFFFF. */
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MIN),
	    "0xC00000 is the first three-octet opcode");
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN,
	    mesh_access_opcode_len(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MAX),
	    "0xFFFFFF is the last three-octet opcode");
	/* The gap between two- and three-octet forms is invalid. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_opcode_len(0xc000),
	    "0xC000 is not a valid opcode (gap)");
	ATF_CHECK_EQ_MSG(-1, mesh_access_opcode_len(0x01000000),
	    "0x01000000 is out of range");
}

/* ================================================================
 * Build/parse round trip for each opcode form.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(build_parse_one_octet);
ATF_TC_BODY(build_parse_one_octet, tc)
{
	struct mesh_access_pdu ap;
	uint8_t out[8];
	uint8_t params[3] = { 0xaa, 0xbb, 0xcc };
	size_t outlen;

	/* Table 3.43 minimum one-octet opcode plus 3 sentinel parameters. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, params, 3, out, &outlen));
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_ONE_LEN + 3, outlen,
	    "1-octet opcode + 3 params = 4");
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, out[0]);
	ATF_CHECK_EQ_MSG(0, memcmp(out + 1, params, 3), "params follow opcode");

	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(out, outlen, &ap));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_ONE_LEN, ap.opcode_len);
	ATF_CHECK_EQ(0, ap.vendor);
	ATF_CHECK_EQ(3u, ap.params_len);
	ATF_CHECK_EQ(0, memcmp(ap.params, params, 3));
}

ATF_TC_WITHOUT_HEAD(build_parse_two_octet);
ATF_TC_BODY(build_parse_two_octet, tc)
{
	struct mesh_access_pdu ap;
	uint8_t out[8];
	uint8_t param = 0x11;
	size_t outlen;

	/* Non-normative valid two-octet opcode/parameter sentinels. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(0x8003, &param, 1, out, &outlen));
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN + 1, outlen,
	    "2-octet opcode + 1 param = 3");
	ATF_CHECK_EQ_MSG(0x80, out[0], "high opcode octet is big-endian first");
	ATF_CHECK_EQ(0x03, out[1]);
	ATF_CHECK_EQ(0x11, out[2]);

	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(out, outlen, &ap));
	ATF_CHECK_EQ(0x8003u, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN, ap.opcode_len);
	ATF_CHECK_EQ(1u, ap.params_len);
	ATF_CHECK_EQ(0x11, ap.params[0]);
}

ATF_TC_WITHOUT_HEAD(build_parse_vendor_three_octet);
ATF_TC_BODY(build_parse_vendor_three_octet, tc)
{
	struct mesh_access_pdu ap;
	uint8_t out[8];
	uint8_t param = 0x42;
	size_t outlen;
	uint32_t op;

	/*
	 * Vendor opcode: 6-bit opcode 0x0A with Company Identifier 0x1234.
	 * Wire form (Section 3.7.3.1): 0xCA | CID low 0x34 | CID high 0x12,
	 * i.e. the Company Identifier is little-endian.
	 */
	op = mesh_access_vendor_opcode(0x0a, 0x1234);
	ATF_CHECK_EQ_MSG(0xca1234u, op, "canonical vendor opcode 0xCA1234");
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN,
	    mesh_access_opcode_len(op));

	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(op, &param, 1, out, &outlen));
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN + 1, outlen,
	    "3-octet opcode + 1 param = 4");
	ATF_CHECK_EQ_MSG(0xca, out[0], "first octet 11xxxxxx = 0xCA");
	ATF_CHECK_EQ_MSG(0x34, out[1], "Company ID low octet (little-endian)");
	ATF_CHECK_EQ_MSG(0x12, out[2], "Company ID high octet (little-endian)");
	ATF_CHECK_EQ(0x42, out[3]);

	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(out, outlen, &ap));
	ATF_CHECK_EQ(op, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN, ap.opcode_len);
	ATF_CHECK_EQ_MSG(1, ap.vendor, "3-octet opcode is a vendor opcode");
	ATF_CHECK_EQ_MSG(0x1234, ap.company_id, "recovered Company Identifier");
	ATF_CHECK_EQ_MSG(0x1234, mesh_access_opcode_company(op),
	    "opcode_company() extracts the Company Identifier");
	ATF_CHECK_EQ(1u, ap.params_len);
	ATF_CHECK_EQ(0x42, ap.params[0]);
}

/* Wire-prefix boundaries: octet-0 top bits select the length. */
ATF_TC_WITHOUT_HEAD(parse_prefix_boundaries);
ATF_TC_BODY(parse_prefix_boundaries, tc)
{
	struct mesh_access_pdu ap;
	uint8_t b[4];

	/* 0x7F alone: reserved one-octet opcode -> reject. */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_ONE_RFU;
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_parse(b, 1, &ap),
	    "0x7F is reserved and must be rejected on parse");

	/* 0x80: first two-octet opcode; needs a second octet. */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN >> 8;
	b[1] = BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN & 0xff;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(b, 2, &ap));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN, ap.opcode_len);

	/* 0xBF: last two-octet prefix (10xxxxxx). */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_TWO_MAX >> 8;
	b[1] = BT_MSHPRT11_ACCESS_OPCODE_TWO_MAX & 0xff;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(b, 2, &ap));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_TWO_MAX, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_TWO_LEN, ap.opcode_len);

	/* 0xC0: first three-octet prefix (11xxxxxx). */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MIN >> 16;
	b[1] = 0; b[2] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(b, 3, &ap));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MIN, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN, ap.opcode_len);
	ATF_CHECK_EQ(1, ap.vendor);

	/* 0xFF: last three-octet prefix. */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MAX >> 16;
	b[1] = (BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MAX >> 8) & 0xff;
	b[2] = BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MAX & 0xff;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(b, 3, &ap));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MAX, ap.opcode);
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_OPCODE_VENDOR_LEN, ap.opcode_len);
}

/* ================================================================
 * Malformed / truncated PDU rejection.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_truncated_and_malformed);
ATF_TC_BODY(parse_truncated_and_malformed, tc)
{
	struct mesh_access_pdu ap;
	uint8_t b[4];

	/* Empty PDU. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_parse(b, 0, &ap),
	    "empty access PDU is invalid");

	/* Two-octet opcode with only one octet present. */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN >> 8;
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_parse(b, 1, &ap),
	    "truncated two-octet opcode is invalid");

	/* Three-octet opcode with only two octets present. */
	b[0] = BT_MSHPRT11_ACCESS_OPCODE_VENDOR_MIN >> 16;
	b[1] = 0x11; /* Non-normative truncation sentinel. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_parse(b, 2, &ap),
	    "truncated three-octet opcode is invalid");

	/* NULL argument handling. */
	ATF_CHECK_EQ(-1, mesh_access_pdu_parse(NULL, 3, &ap));
	ATF_CHECK_EQ(-1, mesh_access_pdu_parse(b, 3, NULL));
}

/* Build rejects invalid opcodes and oversized parameters. */
ATF_TC_WITHOUT_HEAD(build_rejects_invalid);
ATF_TC_BODY(build_rejects_invalid, tc)
{
	uint8_t out[BT_MSHPRT11_ACCESS_PAYLOAD_MAX + 8];
	uint8_t params[BT_MSHPRT11_ACCESS_PAYLOAD_MAX];
	size_t outlen;

	memset(params, 0, sizeof(params));

	/* Reserved one-octet opcode. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_RFU, NULL, 0, out, &outlen),
	    "cannot build the reserved 0x7F opcode");
	/* Gap value. */
	ATF_CHECK_EQ(-1, mesh_access_pdu_build(0x0080, NULL, 0, out, &outlen));

	/* Params too large for a one-octet opcode (max payload 380). */
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, params,
	    BT_MSHPRT11_ACCESS_PAYLOAD_MAX, out, &outlen),
	    "params + opcode may not exceed the access payload maximum");
	/* Exactly the maximum fits. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, params,
	    BT_MSHPRT11_ACCESS_PARAMS_MAX, out, &outlen));
	ATF_CHECK_EQ(BT_MSHPRT11_ACCESS_PAYLOAD_MAX, (int)outlen);

	/* NULL params with non-zero length. */
	ATF_CHECK_EQ(-1, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, NULL, 1, out, &outlen));
}

/* ================================================================
 * Model dispatch registry (Section 3.7).
 * ================================================================ */
enum {
	/* Non-normative valid opcode/address sentinels for registry behavior. */
	TEST_ACCESS_OPCODE_A = 0x8003,
	TEST_ACCESS_OPCODE_B = 0x00,
	TEST_ACCESS_OPCODE_OTHER = 0x800e,
	TEST_ACCESS_OPCODE_UNKNOWN = 0x1234,
	TEST_ACCESS_ELEMENT_1 = 0x0001,
	TEST_ACCESS_ELEMENT_2 = 0x0002,
	TEST_ACCESS_ELEMENT_MISS = 0x00ff,
	TEST_ACCESS_SOURCE = 0x1201
};

static int
handler_a(const struct mesh_access_rx *rx)
{
	int *hits = rx->ctx;

	hits[0]++;
	/* Report back what we saw so the test can assert addressing. */
	if (rx->elem_addr == TEST_ACCESS_ELEMENT_1 &&
	    rx->src == TEST_ACCESS_SOURCE &&
	    rx->pdu->opcode == TEST_ACCESS_OPCODE_A)
		hits[1] = 1;
	return (0);
}

static int
handler_b(const struct mesh_access_rx *rx)
{
	int *hits = rx->ctx;

	hits[2]++;
	return (7);
}

ATF_TC_WITHOUT_HEAD(dispatch_registry);
ATF_TC_BODY(dispatch_registry, tc)
{
	static const struct mesh_opcode_entry ops0[] = {
		{ TEST_ACCESS_OPCODE_A, handler_a },
		{ TEST_ACCESS_OPCODE_B, handler_b },
	};
	static const struct mesh_opcode_entry ops1[] = {
		{ TEST_ACCESS_OPCODE_OTHER, handler_a },
	};
	struct mesh_model models_e0[] = {
		{ .model_id = 0x0000, .company_id = MESH_COMPANY_SIG,
		  .ops = ops0, .n_ops = 2 },
	};
	struct mesh_model models_e1[] = {
		{ .model_id = 0x1000, .company_id = MESH_COMPANY_SIG,
		  .ops = ops1, .n_ops = 1 },
	};
	struct mesh_element elems[] = {
		{ .addr = TEST_ACCESS_ELEMENT_1, .models = models_e0,
		  .n_models = 1 },
		{ .addr = TEST_ACCESS_ELEMENT_2, .models = models_e1,
		  .n_models = 1 },
	};
	int hits[3];
	uint8_t pdu[4];
	size_t plen;

	/* find_op locates a registered opcode and rejects an unknown one. */
	ATF_CHECK(mesh_model_find_op(&models_e0[0], TEST_ACCESS_OPCODE_A) !=
	    NULL);
	ATF_CHECK(mesh_model_find_op(&models_e0[0],
	    TEST_ACCESS_OPCODE_UNKNOWN) == NULL);

	/* Dispatch opcode 0x8003 to element 0x0001. */
	memset(hits, 0, sizeof(hits));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_A, NULL, 0,
	    pdu, &plen));
	ATF_CHECK_EQ_MSG(0, mesh_access_dispatch(elems, 2, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_1,
	    pdu, plen, hits), "handler_a returns 0");
	ATF_CHECK_EQ_MSG(1, hits[0], "handler_a ran once");
	ATF_CHECK_EQ_MSG(1, hits[1], "handler_a saw correct addressing");

	/* Dispatch opcode 0x800E to element 0x0002 (return value propagates). */
	memset(hits, 0, sizeof(hits));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_OTHER, NULL,
	    0, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch(elems, 2, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_2, pdu,
	    plen, hits));
	ATF_CHECK_EQ(1, hits[0]);

	/* Unhandled opcode on the addressed element -> -1. */
	memset(hits, 0, sizeof(hits));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_OTHER, NULL,
	    0, pdu, &plen));
	ATF_CHECK_EQ_MSG(-1, mesh_access_dispatch(elems, 2,
	    TEST_ACCESS_SOURCE, TEST_ACCESS_ELEMENT_1,
	    pdu, plen, hits), "0x800E is not registered on element 0x0001");

	/* Destination that matches no element -> -1. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_A, NULL, 0,
	    pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(elems, 2, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_MISS, pdu,
	    plen, hits));

	/* handler_b return value (7) propagates from dispatch. */
	memset(hits, 0, sizeof(hits));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_B, NULL, 0,
	    pdu, &plen));
	ATF_CHECK_EQ_MSG(7, mesh_access_dispatch(elems, 2, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_1,
	    pdu, plen, hits), "handler return value propagates");
	ATF_CHECK_EQ(1, hits[2]);
}

/* ================================================================
 * Spec-oracle guard branches: NULL out-params, oversize parameters, and
 * the vendor-only accessor on a non-vendor opcode.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(codec_guards);
ATF_TC_BODY(codec_guards, tc)
{
	struct mesh_access_pdu ap;
	uint8_t out[BT_MSHPRT11_ACCESS_PAYLOAD_MAX + 4];
	uint8_t in[BT_MSHPRT11_ACCESS_PAYLOAD_MAX + 4];
	uint8_t param = 0x11;
	size_t outlen;

	/* opcode_company() returns 0 for a non-3-octet opcode (Section 3.7.3.1). */
	ATF_CHECK_EQ_MSG(0, mesh_access_opcode_company(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN),
	    "a one-octet opcode has no Company Identifier");
	ATF_CHECK_EQ_MSG(0, mesh_access_opcode_company(
	    BT_MSHPRT11_ACCESS_OPCODE_TWO_MIN),
	    "a two-octet opcode has no Company Identifier");

	/* build() rejects NULL out / NULL outlen. */
	ATF_CHECK_EQ(-1, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, &param, 1, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_access_pdu_build(
	    BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN, &param, 1, out, NULL));

	/*
	 * parse() rejects a PDU whose parameter count exceeds
	 * MESH_ACCESS_PARAMS_MAX: a one-octet opcode plus 380 parameter octets
	 * gives params_len 380 > 379.
	 */
	memset(in, 0, sizeof(in));
	in[0] = BT_MSHPRT11_ACCESS_OPCODE_ONE_MIN;
	ATF_CHECK_EQ_MSG(-1, mesh_access_pdu_parse(in,
	    (size_t)(BT_MSHPRT11_ACCESS_OPCODE_ONE_LEN +
	    BT_MSHPRT11_ACCESS_PARAMS_MAX + 1), &ap),
	    "parameters beyond MESH_ACCESS_PARAMS_MAX are rejected");
}

/* ================================================================
 * find_op / dispatch guard branches (Section 3.7): NULL model, NULL ops
 * table, an entry whose handler is NULL, NULL elems/pdu, and a dispatch
 * whose PDU fails to parse.
 * ================================================================ */
static int
guard_handler(const struct mesh_access_rx *rx)
{

	(void)rx;
	return (0);
}

ATF_TC_WITHOUT_HEAD(dispatch_guards);
ATF_TC_BODY(dispatch_guards, tc)
{
	static const struct mesh_opcode_entry ops[] = {
		{ TEST_ACCESS_OPCODE_A, NULL },	/* matching, NULL handler */
		{ TEST_ACCESS_OPCODE_B, guard_handler },
	};
	struct mesh_model model = {
		.model_id = 0x0000, .company_id = MESH_COMPANY_SIG,
		.ops = ops, .n_ops = 2
	};
	struct mesh_model noops = {
		.model_id = 0x0000, .company_id = MESH_COMPANY_SIG
	};
	struct mesh_element elems[] = {
		{ .addr = TEST_ACCESS_ELEMENT_1, .models = &model,
		  .n_models = 1 }
	};
	uint8_t pdu[4];
	uint8_t rfu = BT_MSHPRT11_ACCESS_OPCODE_ONE_RFU;
	size_t plen;

	/* find_op: NULL model, NULL ops table. */
	ATF_CHECK(mesh_model_find_op(NULL, TEST_ACCESS_OPCODE_B) == NULL);
	ATF_CHECK(mesh_model_find_op(&noops, TEST_ACCESS_OPCODE_B) == NULL);
	/* find_op: opcode matches but the handler is NULL -> not a match. */
	ATF_CHECK_MSG(mesh_model_find_op(&model, TEST_ACCESS_OPCODE_A) == NULL,
	    "an entry with a NULL handler is not returned");
	/* find_op: the real handler is still found. */
	ATF_CHECK(mesh_model_find_op(&model, TEST_ACCESS_OPCODE_B) != NULL);

	/* dispatch: NULL elems / NULL pdu. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_ACCESS_OPCODE_B, NULL, 0,
	    pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(NULL, 1, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_1, pdu,
	    plen, NULL));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(elems, 1, TEST_ACCESS_SOURCE,
	    TEST_ACCESS_ELEMENT_1, NULL, 0, NULL));
	/* dispatch: a PDU that fails to parse -> -1. */
	ATF_CHECK_EQ_MSG(-1, mesh_access_dispatch(elems, 1,
	    TEST_ACCESS_SOURCE, TEST_ACCESS_ELEMENT_1,
	    &rfu, 1, NULL), "a malformed access PDU is undispatchable");
}

/* ================================================================
 * P9: address classification, virtual-address derivation, the network
 * message cache, and group/virtual destination resolution in dispatch
 * (MshPRT_v1.1 Sections 3.4.2 / 3.4.6.5 / 3.7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(addr_classification);
ATF_TC_BODY(addr_classification, tc)
{

	/* Unassigned 0x0000 is none of the three types (Section 3.4.2). */
	ATF_CHECK(!mesh_addr_is_unicast(BT_MSHPRT11_ADDR_UNASSIGNED));
	ATF_CHECK(!mesh_addr_is_virtual(BT_MSHPRT11_ADDR_UNASSIGNED));
	ATF_CHECK(!mesh_addr_is_group(BT_MSHPRT11_ADDR_UNASSIGNED));
	/* Unicast 0x0001..0x7FFF. */
	ATF_CHECK(mesh_addr_is_unicast(BT_MSHPRT11_ADDR_UNICAST_MIN));
	ATF_CHECK(mesh_addr_is_unicast(BT_MSHPRT11_ADDR_UNICAST_MAX));
	ATF_CHECK(!mesh_addr_is_unicast(BT_MSHPRT11_ADDR_VIRTUAL_MIN));
	/* Virtual 0x8000..0xBFFF. */
	ATF_CHECK(mesh_addr_is_virtual(BT_MSHPRT11_ADDR_VIRTUAL_MIN));
	ATF_CHECK(mesh_addr_is_virtual(BT_MSHPRT11_ADDR_VIRTUAL_MAX));
	ATF_CHECK(!mesh_addr_is_virtual(BT_MSHPRT11_ADDR_GROUP_MIN));
	/* Group 0xC000..0xFFFF (includes the fixed all-nodes 0xFFFF). */
	ATF_CHECK(mesh_addr_is_group(BT_MSHPRT11_ADDR_GROUP_MIN));
	ATF_CHECK(mesh_addr_is_group(BT_MSHPRT11_ADDR_GROUP_MAX));
	ATF_CHECK(!mesh_addr_is_group(BT_MSHPRT11_ADDR_VIRTUAL_MAX));
	ATF_CHECK_EQ(BT_MSHPRT11_ADDR_ALL_NODES, MESH_ADDR_ALL_NODES);
}

ATF_TC_WITHOUT_HEAD(virtual_addr_derivation);
ATF_TC_BODY(virtual_addr_derivation, tc)
{
	/*
	 * MshPRT §8.3.22 sample data: Label UUID 0073e7e4d8b9440faf8415df4c56c0e1
	 * has virtual address 0xB529 (the DST used in that message's nonce).
	 * va = 0x8000 | (AES-CMAC(s1("vtad"), Label)[14..15] & 0x3FFF).
	 */
	static const uint8_t label[BT_MSHPRT11_LABEL_UUID_SIZE] = {
		0x00, 0x73, 0xe7, 0xe4, 0xd8, 0xb9, 0x44, 0x0f,
		0xaf, 0x84, 0x15, 0xdf, 0x4c, 0x56, 0xc0, 0xe1
	};
	uint16_t va = 0;

	ATF_REQUIRE_EQ(0, mesh_virtual_addr(label, &va));
	ATF_CHECK_EQ_MSG(BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, va,
	    "8.3.22 Label UUID -> virtual address 0xB529");
	ATF_CHECK_MSG(mesh_addr_is_virtual(va), "derived address is virtual");
	/* Guard: NULL arguments. */
	ATF_CHECK_EQ(-1, mesh_virtual_addr(NULL, &va));
	ATF_CHECK_EQ(-1, mesh_virtual_addr(label, NULL));
}

ATF_TC_WITHOUT_HEAD(message_cache);
ATF_TC_BODY(message_cache, tc)
{
	struct mesh_msg_cache c;

	mesh_msg_cache_init(&c);
	/* SRC/SEQ values are non-normative cache-key sentinels. */
	/* First sight of (SRC, SEQ) is new (0); a repeat is a duplicate (1). */
	ATF_CHECK_EQ_MSG(0, mesh_msg_cache_check(&c, 0x0001, 100),
	    "first (src,seq) is not a duplicate");
	ATF_CHECK_EQ_MSG(1, mesh_msg_cache_check(&c, 0x0001, 100),
	    "the same (src,seq) is a duplicate");
	/* A different SEQ from the same SRC is new. */
	ATF_CHECK_EQ(0, mesh_msg_cache_check(&c, 0x0001, 101));
	/* A different SRC with the same SEQ is new. */
	ATF_CHECK_EQ(0, mesh_msg_cache_check(&c, 0x0002, 100));
	ATF_CHECK_EQ(1, mesh_msg_cache_check(&c, 0x0002, 100));
}

static int
p9_handler(const struct mesh_access_rx *rx)
{
	int *seen = rx->ctx;

	if (seen != NULL)
		*seen += 1;
	return (0);
}

ATF_TC_WITHOUT_HEAD(group_virtual_dispatch);
ATF_TC_BODY(group_virtual_dispatch, tc)
{
	static const struct mesh_opcode_entry ops[] = {
		{ 0x8003, p9_handler },
	};
	static const struct mesh_model model = {
		.model_id = 0x1000, .company_id = MESH_COMPANY_SIG,
		.ops = ops, .n_ops = 1
	};
	/* §8.3.22 Label UUID hashes to the virtual address 0xB529. */
	static const uint8_t labels[1][BT_MSHPRT11_LABEL_UUID_SIZE] = {
		{ 0x00, 0x73, 0xe7, 0xe4, 0xd8, 0xb9, 0x44, 0x0f,
		  0xaf, 0x84, 0x15, 0xdf, 0x4c, 0x56, 0xc0, 0xe1 }
	};
	static const uint16_t subs[1] = { 0xc001 };
	struct mesh_element el = {
		.addr = 0x0005,
		.models = &model,
		.n_models = 1,
		.subs = subs,
		.n_subs = 1,
		.labels = labels,
		.n_labels = 1,
	};
	uint8_t pdu[4];
	size_t plen;
	int seen;

	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(0x8003, NULL, 0, pdu, &plen));

	/* Unicast to the element address still resolves. */
	seen = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x1201, 0x0005, pdu, plen,
	    &seen));
	ATF_CHECK_EQ_MSG(1, seen, "unicast dst 0x0005 dispatched");

	/* Group dst on the subscription list resolves (Section 3.4.2). */
	seen = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x1201, 0xc001, pdu, plen,
	    &seen));
	ATF_CHECK_EQ_MSG(1, seen, "subscribed group 0xC001 dispatched");

	/* A group dst NOT subscribed does not resolve. */
	seen = 0;
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x1201, 0xc002, pdu, plen,
	    &seen));
	ATF_CHECK_EQ_MSG(0, seen, "unsubscribed group 0xC002 not dispatched");

	/* Virtual dst whose Label UUID hashes to it resolves (Section 3.4.2.3). */
	seen = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x1201,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS, pdu, plen,
	    &seen));
	ATF_CHECK_EQ_MSG(1, seen, "virtual dst 0xB529 (label hash) dispatched");

	/* A different virtual address (no matching label) does not resolve. */
	seen = 0;
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x1201, 0xb52a, pdu, plen,
	    &seen));
	ATF_CHECK_EQ_MSG(0, seen, "non-matching virtual dst not dispatched");

	/* The fixed all-nodes group 0xFFFF reaches every element. */
	seen = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x1201,
	    BT_MSHPRT11_ADDR_ALL_NODES, pdu, plen, &seen));
	ATF_CHECK_EQ_MSG(1, seen, "all-nodes 0xFFFF dispatched");

	/* mesh_access_elem_addressed() reports the same resolution directly. */
	ATF_CHECK(mesh_access_elem_addressed(&el, 0x0005));
	ATF_CHECK(mesh_access_elem_addressed(&el, 0xc001));
	ATF_CHECK(mesh_access_elem_addressed(&el,
	    BT_MSHPRT11_SAMPLE_VIRTUAL_ADDRESS));
	ATF_CHECK(mesh_access_elem_addressed(&el, BT_MSHPRT11_ADDR_ALL_NODES));
	ATF_CHECK(!mesh_access_elem_addressed(&el, 0x0006));
	ATF_CHECK(!mesh_access_elem_addressed(&el, 0xc002));
	ATF_CHECK(!mesh_access_elem_addressed(&el,
	    BT_MSHPRT11_ADDR_UNASSIGNED));
}

/* ================================================================
 * Multicast fan-out (MshPRT_v1.1 Section 3.4.2): a group destination bound
 * to a subscribed model on TWO elements must be delivered to BOTH, not just
 * the first match.
 * ================================================================ */
static int
fanout_handler(const struct mesh_access_rx *rx)
{
	int *hits = rx->ctx;

	if (hits != NULL)
		hits[0]++;
	return (0);
}

ATF_TC_WITHOUT_HEAD(group_fanout);
ATF_TC_BODY(group_fanout, tc)
{
	static const struct mesh_opcode_entry ops[] = {
		{ 0x8003, fanout_handler },
	};
	static const struct mesh_model model = {
		.model_id = 0x1000, .company_id = MESH_COMPANY_SIG,
		.ops = ops, .n_ops = 1
	};
	/* Both elements subscribe the same model to the group 0xC001. */
	static const uint16_t subs[1] = { 0xc001 };
	struct mesh_element elems[2] = {
		{ .addr = 0x0005, .models = &model, .n_models = 1,
		  .subs = subs, .n_subs = 1 },
		{ .addr = 0x0006, .models = &model, .n_models = 1,
		  .subs = subs, .n_subs = 1 },
	};
	uint8_t pdu[4];
	size_t plen;
	int hits;

	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(0x8003, NULL, 0, pdu, &plen));

	/* Group dst reaches BOTH subscribed elements' models (fan-out). */
	hits = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(elems, 2, 0x1201, 0xc001, pdu,
	    plen, &hits));
	ATF_CHECK_EQ_MSG(2, hits, "group message fanned out to both models");

	/* All-nodes 0xFFFF also reaches every element. */
	hits = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(elems, 2, 0x1201,
	    BT_MSHPRT11_ADDR_ALL_NODES, pdu, plen, &hits));
	ATF_CHECK_EQ_MSG(2, hits, "all-nodes message fanned out to both");

	/* A unicast dst still resolves to exactly one element. */
	hits = 0;
	ATF_CHECK_EQ(0, mesh_access_dispatch(elems, 2, 0x1201, 0x0006, pdu,
	    plen, &hits));
	ATF_CHECK_EQ_MSG(1, hits, "unicast dst delivered once");
}

ATF_TC_WITHOUT_HEAD(circular_u16_transition);
ATF_TC_BODY(circular_u16_transition, tc)
{
	struct mesh_transition_state transition;
	uint16_t halfway;
	enum {
		/* Non-normative states/times chosen around the 16-bit wrap. */
		TEST_WRAP_INITIAL = 65530,
		TEST_WRAP_TARGET = 6,
		TEST_WRAP_MIDPOINT = 0,
		TEST_WRAP_DURATION_MS = 1000,
		TEST_WRAP_START_MS = 100,
		TEST_WRAP_HALF_MS = 600,
		TEST_WRAP_END_MS = 1100
	};

	memset(&transition, 0, sizeof(transition));
	mesh_transition_start_ms(&transition, TEST_WRAP_INITIAL,
	    TEST_WRAP_TARGET, TEST_WRAP_DURATION_MS, 0, TEST_WRAP_START_MS);
	halfway = mesh_transition_sample_u16_circular(&transition,
	    TEST_WRAP_HALF_MS);
	ATF_CHECK_EQ_MSG(TEST_WRAP_MIDPOINT, halfway,
	    "circular Hue midpoint crosses the 0xFFFF->0x0000 boundary");
	ATF_CHECK_EQ(TEST_WRAP_TARGET,
	    mesh_transition_sample_u16_circular(&transition,
	    TEST_WRAP_END_MS));
}

ATF_TC_WITHOUT_HEAD(transition_and_public_guard_completion);
ATF_TC_BODY(transition_and_public_guard_completion, tc)
{
	struct mesh_transition_state state;
	struct mesh_msg_cache cache;
	struct mesh_element el;
	enum {
		/* Non-normative transition state/time and API-guard sentinels. */
		TEST_GUARD_INITIAL = 3,
		TEST_GUARD_TARGET = 9,
		TEST_GUARD_DURATION_MS = 100,
		TEST_GUARD_DELAY_STEPS = 10,
		TEST_GUARD_START_MS = 1000,
		TEST_GUARD_BEFORE_DELAY_MS = 1020
	};

	ATF_CHECK_EQ(0, mesh_msg_cache_check(NULL, 1, 1));
	ATF_CHECK_EQ(0, mesh_access_elem_addressed(NULL, 1));
	ATF_CHECK_EQ(0, mesh_transition_remaining(0));
	ATF_CHECK(mesh_transition_remaining(
	    BT_MMDL111_TRANSITION_MAX_KNOWN_MS) !=
	    BT_MMDL111_REMAINING_TIME_UNKNOWN);
	ATF_CHECK_EQ(0, mesh_transition_time_ms(
	    BT_MMDL111_TRANSITION_STEPS_MASK));
	ATF_CHECK_EQ(BT_MMDL111_REMAINING_TIME_UNKNOWN,
	    mesh_transition_remaining(BT_MMDL111_TRANSITION_MAX_KNOWN_MS + 1));
	mesh_transition_start_ms(NULL, 0, 1, 1, 0, 0);
	ATF_CHECK_EQ(0, mesh_transition_sample(NULL, 0));
	ATF_CHECK_EQ(0, mesh_transition_sample_u16_circular(NULL, 0));
	ATF_CHECK_EQ(0, mesh_transition_sample_binary(NULL, 0));

	memset(&state, 0, sizeof(state));
	state.initial = TEST_GUARD_INITIAL;
	state.target = TEST_GUARD_TARGET;
	ATF_CHECK_EQ(TEST_GUARD_TARGET, mesh_transition_sample(&state, 0));
	ATF_CHECK_EQ(TEST_GUARD_TARGET,
	    mesh_transition_sample_u16_circular(&state, 0));
	ATF_CHECK_EQ(TEST_GUARD_TARGET,
	    mesh_transition_sample_binary(&state, 0));
	mesh_transition_start_ms(&state, TEST_GUARD_INITIAL, TEST_GUARD_TARGET,
	    TEST_GUARD_DURATION_MS, TEST_GUARD_DELAY_STEPS,
	    TEST_GUARD_START_MS);
	ATF_CHECK_EQ(TEST_GUARD_INITIAL,
	    mesh_transition_sample(&state, TEST_GUARD_BEFORE_DELAY_MS));
	mesh_transition_start_ms(&state, TEST_GUARD_INITIAL, TEST_GUARD_TARGET,
	    TEST_GUARD_DURATION_MS, TEST_GUARD_DELAY_STEPS,
	    TEST_GUARD_START_MS);
	ATF_CHECK_EQ(TEST_GUARD_INITIAL, mesh_transition_sample_u16_circular(
	    &state, TEST_GUARD_BEFORE_DELAY_MS));

	memset(&el, 0, sizeof(el));
	el.n_labels = 1;
	ATF_CHECK_EQ(0, mesh_access_elem_addressed(&el, 0x8001));
	mesh_access_tick(NULL, 1, 0);
	mesh_msg_cache_init(&cache);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, opcode_len_boundaries);
	ATF_TP_ADD_TC(tp, build_parse_one_octet);
	ATF_TP_ADD_TC(tp, build_parse_two_octet);
	ATF_TP_ADD_TC(tp, build_parse_vendor_three_octet);
	ATF_TP_ADD_TC(tp, parse_prefix_boundaries);
	ATF_TP_ADD_TC(tp, parse_truncated_and_malformed);
	ATF_TP_ADD_TC(tp, build_rejects_invalid);
	ATF_TP_ADD_TC(tp, dispatch_registry);
	ATF_TP_ADD_TC(tp, codec_guards);
	ATF_TP_ADD_TC(tp, dispatch_guards);
	ATF_TP_ADD_TC(tp, addr_classification);
	ATF_TP_ADD_TC(tp, virtual_addr_derivation);
	ATF_TP_ADD_TC(tp, message_cache);
	ATF_TP_ADD_TC(tp, group_virtual_dispatch);
	ATF_TP_ADD_TC(tp, group_fanout);
	ATF_TP_ADD_TC(tp, circular_u16_transition);
	ATF_TP_ADD_TC(tp, transition_and_public_guard_completion);

	return (atf_no_error());
}
