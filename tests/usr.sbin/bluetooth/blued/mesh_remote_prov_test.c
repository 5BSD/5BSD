/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for Bluetooth Mesh Remote Provisioning (mesh_remote_prov.[ch],
 * MshPRT_v1.1 Section 4.4 and the Remote Provisioning Client / Server models,
 * MshMDL_v1.1 Section 4.4.4 / 4.4.5).
 *
 * The tests assert the documented wire layout of each model message (two-octet
 * big-endian opcode, field order, big-endian OOB Information) against
 * hand-computed spec bytes, round-trip build/parse, reject malformed and
 * truncated PDUs, drive the scan state machine (Start -> Report(s) -> Stop, the
 * single-device filter, the scanned-items limit and the timeout) on a mock
 * clock, and drive the PB-Remote link lifecycle end to end: ScanStart ->
 * ScanReport(device found) -> LinkOpen -> LinkStatus/Report(active) ->
 * (provisioning PDUs tunnelled with the inbound/outbound numbering) ->
 * LinkClose - provisioning a remote device through the existing
 * mesh_provisioner engine.  No test asserts captured runtime output.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_provision.h"
#include "mesh_provisioner.h"
#include "mesh_remote_prov.h"
#include "spec_mesh_remote_prov_oracles.h"

/* Section 8.7 sample data (as used by mesh_provisioner_test). */
static const uint8_t PROV_PRIV[32] = {
	0x06,0xa5,0x16,0x69,0x3c,0x9a,0xa3,0x1a,0x60,0x84,0x54,0x5d,0x0c,0x5d,
	0xb6,0x41,0xb4,0x85,0x72,0xb9,0x72,0x03,0xdd,0xff,0xb7,0xac,0x73,0xf7,
	0xd0,0x45,0x76,0x63 };
static const uint8_t DEV_PRIV[32] = {
	0x52,0x9a,0xa0,0x67,0x0d,0x72,0xcd,0x64,0x97,0x50,0x2e,0xd4,0x73,0x50,
	0x2b,0x03,0x7e,0x88,0x03,0xb5,0xc6,0x08,0x29,0xa5,0xa3,0xca,0xa2,0x19,
	0x50,0x55,0x30,0xba };
static const uint8_t RAND_PROV[32] = {
	0x8b,0x19,0xac,0x31,0xd5,0x8b,0x12,0x4c,0x94,0x62,0x09,0xb5,0xdb,0x10,
	0x21,0xb9,0x36,0xf9,0x68,0xb9,0x4a,0x13,0x00,0x0e,0x64,0xb2,0x23,0x57,
	0x63,0x90,0xdb,0x6b };
static const uint8_t RAND_DEV[32] = {
	0x55,0xa2,0xa2,0xbc,0xa0,0x4c,0xd3,0x2f,0xf6,0xf3,0x46,0xbd,0x0a,0x0c,
	0x1a,0x3a,0x5b,0x9b,0x1f,0xc6,0xa6,0x4b,0x2d,0xe8,0xbe,0xce,0x53,0x18,
	0x7e,0xe9,0x89,0xc6 };
static const uint8_t PROV_DATA[25] = {
	0xef,0xb2,0x25,0x5e,0x64,0x22,0xd3,0x30,0x08,0x8e,0x09,0xbb,0x01,0x5e,
	0xd7,0x07,0x05,0x67,0x00,0x01,0x02,0x03,0x04,0x0b,0x0c };

static const uint8_t UUID_A[16] = {
	0x70,0xcf,0x7c,0x97,0x32,0xa3,0x45,0xb6,0x91,0x49,0x48,0x10,0xd2,0xe9,
	0xcb,0xf4 };
static const uint8_t UUID_B[16] = {
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,
	0xff,0x00 };

/* Mesh two-octet Access opcodes are encoded most-significant octet first. */
static void
spec_check_opcode(const uint8_t *pdu, uint16_t opcode)
{

	ATF_REQUIRE_EQ((uint8_t)(opcode >> 8), pdu[0]);
	ATF_REQUIRE_EQ((uint8_t)opcode, pdu[1]);
}

/* ================================================================
 * Model message codecs: spec bytes + round-trip.
 * ================================================================ */
/* Mesh Model 1.1.1 §4.4.4, Scan Capabilities Status message. */
ATF_TC_WITHOUT_HEAD(scan_caps_status_codec);
ATF_TC_BODY(scan_caps_status_codec, tc)
{
	struct mesh_rp_scan_caps in = { .max_scanned_items = 4, .active_scan = 1 };
	struct mesh_rp_scan_caps back;
	uint8_t buf[8];
	size_t len;

	ATF_REQUIRE_EQ(0, mesh_rp_scan_caps_status_build(&in, buf, &len));
	/* opcode 0x8050 big-endian, then MaxScannedItems, ActiveScan. */
	ATF_REQUIRE_EQ(4, len);
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_CAPS_STATUS);
	ATF_REQUIRE_EQ(4, buf[2]);
	ATF_REQUIRE_EQ(1, buf[3]);

	ATF_REQUIRE_EQ(0, mesh_rp_scan_caps_status_parse(buf, len, &back));
	ATF_REQUIRE_EQ(4, back.max_scanned_items);
	ATF_REQUIRE_EQ(1, back.active_scan);
}

/* Mesh Model 1.1.1 §4.4.4, Scan Start message. */
ATF_TC_WITHOUT_HEAD(scan_start_codec);
ATF_TC_BODY(scan_start_codec, tc)
{
	struct mesh_rp_scan_start in, back;
	uint8_t buf[32];
	size_t len;

	/* General scan: no UUID. */
	memset(&in, 0, sizeof(in));
	in.scanned_items_limit = 3;
	in.timeout = 5;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_build(&in, buf, &len));
	ATF_REQUIRE_EQ(4, len);		/* 2 opcode + 2 params */
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_START);
	ATF_REQUIRE_EQ(3, buf[2]);
	ATF_REQUIRE_EQ(5, buf[3]);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_parse(buf, len, &back));
	ATF_REQUIRE_EQ(0, back.has_uuid);
	ATF_REQUIRE_EQ(3, back.scanned_items_limit);
	ATF_REQUIRE_EQ(5, back.timeout);

	/* Targeted scan: UUID appended. */
	in.has_uuid = 1;
	memcpy(in.uuid, UUID_A, 16);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_build(&in, buf, &len));
	ATF_REQUIRE_EQ(20, len);
	ATF_REQUIRE_EQ(0, memcmp(buf + 4, UUID_A, 16));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_parse(buf, len, &back));
	ATF_REQUIRE_EQ(1, back.has_uuid);
	ATF_REQUIRE_EQ(0, memcmp(back.uuid, UUID_A, 16));

	/* Zero timeout is prohibited. */
	in.timeout = 0;
	ATF_REQUIRE_EQ(-1, mesh_rp_scan_start_build(&in, buf, &len));
}

/* Mesh Model 1.1.1 §4.4.4, Scan Status message. */
ATF_TC_WITHOUT_HEAD(scan_status_codec_and_guards);
ATF_TC_BODY(scan_status_codec_and_guards, tc)
{
	struct mesh_rp_scan_status in = {
	    .status = BT_RP_SPEC_STATUS_SUCCESS,
	    .scanning_state = BT_RP_SPEC_SCAN_ACTIVE,
	    .scanned_items_limit = 7,
	    .timeout = 12
	};
	struct mesh_rp_scan_status out;
	uint8_t buf[16];
	size_t len;

	ATF_REQUIRE_EQ(0, mesh_rp_scan_status_build(&in, buf, &len));
	ATF_CHECK_EQ(6, len);
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_STATUS);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_status_parse(buf, len, &out));
	ATF_CHECK_EQ(in.status, out.status);
	ATF_CHECK_EQ(in.scanning_state, out.scanning_state);
	ATF_CHECK_EQ(in.scanned_items_limit, out.scanned_items_limit);
	ATF_CHECK_EQ(in.timeout, out.timeout);
	ATF_CHECK_EQ(-1, mesh_rp_scan_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_scan_status_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_rp_scan_status_parse(buf, len - 1, &out));
	buf[1] = 0x53;
	ATF_CHECK_EQ(-1, mesh_rp_scan_status_parse(buf, len, &out));
}

/* Mesh Model 1.1.1 §4.4.4, Scan Report message. */
ATF_TC_WITHOUT_HEAD(scan_report_codec);
ATF_TC_BODY(scan_report_codec, tc)
{
	struct mesh_rp_scan_report in, back;
	uint8_t buf[32];
	size_t len;

	memset(&in, 0, sizeof(in));
	in.rssi = -60;			/* 0xC4 */
	memcpy(in.uuid, UUID_A, 16);
	in.oob = 0x1034;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_build(&in, buf, &len));
	ATF_REQUIRE_EQ(21, len);	/* 2 opcode + 1 + 16 + 2 */
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_REPORT);
	ATF_REQUIRE_EQ(0xc4, buf[2]);
	ATF_REQUIRE_EQ(0, memcmp(buf + 3, UUID_A, 16));
	/* OOB Information is big-endian. */
	ATF_REQUIRE_EQ(0x10, buf[19]);
	ATF_REQUIRE_EQ(0x34, buf[20]);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_parse(buf, len, &back));
	ATF_REQUIRE_EQ(-60, back.rssi);
	ATF_REQUIRE_EQ(0x1034, back.oob);
	ATF_REQUIRE_EQ(0, back.has_uri_hash);
	buf[19] |= 0x06;	/* OOB Information RFU bits 9 and 10. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_parse(buf, len, &back));
	ATF_REQUIRE_EQ(0x1034, back.oob);
	in.oob = 0x0600;
	ATF_CHECK_EQ(-1, mesh_rp_scan_report_build(&in, buf, &len));
	in.oob = 0x1034;

	/* With URI Hash. */
	in.has_uri_hash = 1;
	memcpy(in.uri_hash, "\xaa\xbb\xcc\xdd", 4);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_build(&in, buf, &len));
	ATF_REQUIRE_EQ(25, len);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_parse(buf, len, &back));
	ATF_REQUIRE_EQ(1, back.has_uri_hash);
	ATF_REQUIRE_EQ(0, memcmp(back.uri_hash, "\xaa\xbb\xcc\xdd", 4));
}

/* Mesh Model 1.1.1 §4.4.4 and Mesh Protocol 1.1 Table 4.176. */
ATF_TC_WITHOUT_HEAD(ext_scan_codec);
ATF_TC_BODY(ext_scan_codec, tc)
{
	struct mesh_rp_ext_scan_start s, sback;
	struct mesh_rp_ext_scan_report r, rback;
	uint8_t buf[80];
	size_t len;

	/* Extended Scan Start: two AD types, targeted UUID + timeout. */
	memset(&s, 0, sizeof(s));
	s.ad_type_filter_count = 2;
	s.ad_types[0] = BT_RP_SPEC_AD_NAME_COMPLETE;
	s.ad_types[1] = BT_RP_SPEC_AD_URI;
	s.has_uuid = 1;
	memcpy(s.uuid, UUID_A, 16);
	s.timeout = 6;
	ATF_REQUIRE_EQ(0, mesh_rp_ext_scan_start_build(&s, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_EXT_SCAN_START);
	ATF_REQUIRE_EQ(2, buf[2]);
	ATF_REQUIRE_EQ(BT_RP_SPEC_AD_NAME_COMPLETE, buf[3]);
	ATF_REQUIRE_EQ(BT_RP_SPEC_AD_URI, buf[4]);
	ATF_REQUIRE_EQ(0, memcmp(buf + 5, UUID_A, 16));
	ATF_REQUIRE_EQ(6, buf[21]);
	ATF_REQUIRE_EQ(22, len);
	ATF_REQUIRE_EQ(0, mesh_rp_ext_scan_start_parse(buf, len, &sback));
	ATF_REQUIRE_EQ(2, sback.ad_type_filter_count);
	ATF_REQUIRE_EQ(BT_RP_SPEC_AD_URI, sback.ad_types[1]);
	ATF_REQUIRE_EQ(1, sback.has_uuid);
	ATF_REQUIRE_EQ(6, sback.timeout);

	/* Extended Scan Report with OOB + adv structures. */
	memset(&r, 0, sizeof(r));
	r.status = BT_RP_SPEC_STATUS_SUCCESS;
	memcpy(r.uuid, UUID_A, 16);
	r.has_adv = 1;
	r.oob = 0x00a0;
	r.adv[0] = 0x02;
	r.adv[1] = 0x01;
	r.adv[2] = 0x06;
	r.adv_len = 3;
	ATF_REQUIRE_EQ(0, mesh_rp_ext_scan_report_build(&r, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_EXT_SCAN_REPORT);
	ATF_REQUIRE_EQ(BT_RP_SPEC_STATUS_SUCCESS, buf[2]);
	ATF_REQUIRE_EQ(0, memcmp(buf + 3, UUID_A, 16));
	ATF_REQUIRE_EQ(0x00, buf[19]);
	ATF_REQUIRE_EQ(0xa0, buf[20]);
	ATF_REQUIRE_EQ(24, len);	/* 2 + 1 + 16 + 2 + 3 */
	ATF_REQUIRE_EQ(0, mesh_rp_ext_scan_report_parse(buf, len, &rback));
	ATF_REQUIRE_EQ(1, rback.has_adv);
	ATF_REQUIRE_EQ(0x00a0, rback.oob);
	ATF_REQUIRE_EQ(3, rback.adv_len);
	ATF_REQUIRE_EQ(0x06, rback.adv[2]);
}

/* Mesh Model 1.1.1 §§4.4.3-4.4.5, Remote Provisioning link messages. */
ATF_TC_WITHOUT_HEAD(link_msgs_codec);
ATF_TC_BODY(link_msgs_codec, tc)
{
	struct mesh_rp_link_open op, opback;
	struct mesh_rp_link_status st, stback;
	struct mesh_rp_link_report rp, rpback;
	uint8_t buf[32];
	size_t len;
	uint8_t reason;

	/* Link Open: UUID + timeout. */
	memset(&op, 0, sizeof(op));
	memcpy(op.uuid, UUID_B, 16);
	op.has_timeout = 1;
	op.timeout = 10;
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_build(&op, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_LINK_OPEN);
	ATF_REQUIRE_EQ(0, memcmp(buf + 2, UUID_B, 16));
	ATF_REQUIRE_EQ(10, buf[18]);
	ATF_REQUIRE_EQ(19, len);
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_parse(buf, len, &opback));
	ATF_REQUIRE_EQ(1, opback.has_timeout);
	ATF_REQUIRE_EQ(10, opback.timeout);
	ATF_REQUIRE_EQ(0, memcmp(opback.uuid, UUID_B, 16));

	/* Link Open: mutually exclusive NPPI form. */
	memset(&op, 0, sizeof(op));
	op.has_nppi = 1;
	op.nppi_procedure = BT_RP_SPEC_NPPI_NODE_ADDRESS_REFRESH;
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_build(&op, buf, &len));
	ATF_REQUIRE_EQ(3, len);
	ATF_REQUIRE_EQ(BT_RP_SPEC_NPPI_NODE_ADDRESS_REFRESH, buf[2]);
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_parse(buf, len, &opback));
	ATF_REQUIRE_EQ(1, opback.has_nppi);
	ATF_REQUIRE_EQ(BT_RP_SPEC_NPPI_NODE_ADDRESS_REFRESH,
	    opback.nppi_procedure);

	/* Link Close. */
	ATF_REQUIRE_EQ(0, mesh_rp_link_close_build(BT_RP_SPEC_LINK_CLOSE_SUCCESS,
	    buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_LINK_CLOSE);
	ATF_REQUIRE_EQ(3, len);
	ATF_REQUIRE_EQ(0, mesh_rp_link_close_parse(buf, len, &reason));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_CLOSE_SUCCESS, reason);

	/* Link Status. */
	st.status = BT_RP_SPEC_STATUS_SUCCESS;
	st.rp_state = BT_RP_SPEC_LINK_OPENING;
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_build(&st, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_LINK_STATUS);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_OPENING, buf[3]);
	ATF_REQUIRE_EQ(4, len);
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_parse(buf, len, &stback));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_OPENING, stback.rp_state);
	st.rp_state = 0x05;
	ATF_CHECK_EQ(-1, mesh_rp_link_status_build(&st, buf, &len));
	uint8_t bad_link_state[] = { 0x80, 0x5b, 0x00, 0x05 };
	ATF_CHECK_EQ(-1, mesh_rp_link_status_parse(bad_link_state,
	    sizeof(bad_link_state), &stback));

	/* Link Report with reason. */
	memset(&rp, 0, sizeof(rp));
	rp.status = BT_RP_SPEC_STATUS_LINK_CLOSED_BY_DEVICE;
	rp.rp_state = BT_RP_SPEC_LINK_IDLE;
	rp.has_reason = 1;
	rp.reason = BT_RP_SPEC_LINK_CLOSE_SUCCESS;
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_build(&rp, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_LINK_REPORT);
	ATF_REQUIRE_EQ(5, len);
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_parse(buf, len, &rpback));
	ATF_REQUIRE_EQ(1, rpback.has_reason);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_CLOSE_SUCCESS, rpback.reason);
	rp.status = BT_RP_SPEC_STATUS_SUCCESS;
	ATF_CHECK_EQ(-1, mesh_rp_link_report_build(&rp, buf, &len));
}

/* Mesh Model 1.1.1 §§4.4.4-4.4.5, Remote Provisioning PDU messages. */
ATF_TC_WITHOUT_HEAD(pdu_msgs_codec);
ATF_TC_BODY(pdu_msgs_codec, tc)
{
	struct mesh_rp_pdu_send snd, sndback;
	struct mesh_rp_pdu_report rp, rpback;
	uint8_t buf[80];
	size_t len;
	uint8_t num;

	/* PDU Send: OutboundPDUNumber + Provisioning PDU. */
	memset(&snd, 0, sizeof(snd));
	snd.outbound_pdu_number = 0x07;
	snd.prov_pdu[0] = BT_RP_SPEC_PROV_INVITE;
	snd.prov_pdu[1] = 0x00;
	snd.prov_len = 2;
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_send_build(&snd, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_PDU_SEND);
	ATF_REQUIRE_EQ(0x07, buf[2]);
	ATF_REQUIRE_EQ(0x00, buf[3]);
	ATF_REQUIRE_EQ(5, len);
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_send_parse(buf, len, &sndback));
	ATF_REQUIRE_EQ(0x07, sndback.outbound_pdu_number);
	ATF_REQUIRE_EQ(2, sndback.prov_len);

	/* PDU Outbound Report. */
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_outbound_report_build(0x07, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_PDU_OUTBOUND_REPORT);
	ATF_REQUIRE_EQ(3, len);
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_outbound_report_parse(buf, len, &num));
	ATF_REQUIRE_EQ(0x07, num);

	/* PDU Report. */
	memset(&rp, 0, sizeof(rp));
	rp.inbound_pdu_number = 0x03;
	rp.prov_pdu[0] = BT_RP_SPEC_PROV_CAPABILITIES;
	rp.prov_len = 12;
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_report_build(&rp, buf, &len));
	spec_check_opcode(buf, BT_RP_SPEC_OP_PDU_REPORT);
	ATF_REQUIRE_EQ(0x03, buf[2]);
	ATF_REQUIRE_EQ(15, len);
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_report_parse(buf, len, &rpback));
	ATF_REQUIRE_EQ(0x03, rpback.inbound_pdu_number);
	ATF_REQUIRE_EQ(12, rpback.prov_len);
}

/* ================================================================
 * Malformed / truncated PDU rejection (length-gating).
 * ================================================================ */
/* Mesh Model 1.1.1 §§4.4.3-4.4.5 and Mesh Protocol 1.1 Table 4.176. */
ATF_TC_WITHOUT_HEAD(malformed_reject);
ATF_TC_BODY(malformed_reject, tc)
{
	struct mesh_rp_scan_caps caps;
	struct mesh_rp_scan_start ss;
	struct mesh_rp_scan_report sr;
	struct mesh_rp_link_open op;
	struct mesh_rp_pdu_send snd;
	struct mesh_rp_ext_scan_start es;
	uint8_t buf[80];
	size_t len;
	uint8_t reason;

	/* Wrong opcode is rejected. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_stop_build(buf, &len));
	ATF_REQUIRE_EQ(-1, mesh_rp_scan_caps_status_parse(buf, len, &caps));

	/* Scan Capabilities Status must be exactly 2 params. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_status_build(
	    &(struct mesh_rp_scan_status){ 0, 0, 0, 0 }, buf, &len));
	/* re-tag as caps-status opcode length -> parse against caps rejects. */
	buf[0] = (uint8_t)(BT_RP_SPEC_OP_SCAN_CAPS_STATUS >> 8);
	buf[1] = (uint8_t)BT_RP_SPEC_OP_SCAN_CAPS_STATUS;
	ATF_REQUIRE_EQ(-1, mesh_rp_scan_caps_status_parse(buf, len, &caps));
	uint8_t bad_caps_min[] = {
		(uint8_t)(BT_RP_SPEC_OP_SCAN_CAPS_STATUS >> 8),
		(uint8_t)BT_RP_SPEC_OP_SCAN_CAPS_STATUS,
		BT_RP_SPEC_SCAN_CAPS_MIN_ITEMS - 1, 0
	};
	uint8_t bad_caps_active[] = {
		(uint8_t)(BT_RP_SPEC_OP_SCAN_CAPS_STATUS >> 8),
		(uint8_t)BT_RP_SPEC_OP_SCAN_CAPS_STATUS,
		BT_RP_SPEC_SCAN_CAPS_MIN_ITEMS,
		BT_RP_SPEC_ACTIVE_SCAN_SUPPORTED + 1
	};
	ATF_CHECK_EQ(-1, mesh_rp_scan_caps_status_parse(bad_caps_min,
	    sizeof(bad_caps_min), &caps));
	ATF_CHECK_EQ(-1, mesh_rp_scan_caps_status_parse(bad_caps_active,
	    sizeof(bad_caps_active), &caps));

	/* Scan Start with 3 params (not 2 or 18) is rejected. */
	uint8_t s3[] = { 0x80, 0x52, 0x01, 0x05, 0x00 };
	ATF_REQUIRE_EQ(-1, mesh_rp_scan_start_parse(s3, sizeof(s3), &ss));

	/* Scan Report truncated to 18 params (no OOB) is rejected. */
	uint8_t r18[2 + 18];
	memset(r18, 0, sizeof(r18));
	r18[0] = 0x80; r18[1] = 0x55;
	ATF_REQUIRE_EQ(-1, mesh_rp_scan_report_parse(r18, sizeof(r18), &sr));

	/* Link Open with 15-octet UUID is rejected. */
	uint8_t o15[2 + 15];
	memset(o15, 0, sizeof(o15));
	o15[0] = 0x80; o15[1] = 0x59;
	ATF_REQUIRE_EQ(-1, mesh_rp_link_open_parse(o15, sizeof(o15), &op));
	uint8_t bad_nppi[] = {
		(uint8_t)(BT_RP_SPEC_OP_LINK_OPEN >> 8),
		(uint8_t)BT_RP_SPEC_OP_LINK_OPEN,
		BT_RP_SPEC_NPPI_NODE_COMPOSITION_REFRESH + 1
	};
	uint8_t bad_timeout[] = { 0x80, 0x59,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    BT_RP_SPEC_LINK_TIMEOUT_MAX + 1 };
	ATF_CHECK_EQ(-1, mesh_rp_link_open_parse(bad_nppi,
	    sizeof(bad_nppi), &op));
	ATF_CHECK_EQ(-1, mesh_rp_link_open_parse(bad_timeout,
	    sizeof(bad_timeout), &op));
	memset(&op, 0, sizeof(op));
	op.has_nppi = 1;
	op.has_timeout = 1;
	ATF_CHECK_EQ(-1, mesh_rp_link_open_build(&op, buf, &len));
	memset(&op, 0, sizeof(op));
	op.has_timeout = 1;
	op.timeout = BT_RP_SPEC_LINK_TIMEOUT_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_rp_link_open_build(&op, buf, &len));

	/* Link Close with 0 params is rejected. */
	uint8_t lc[] = { 0x80, 0x5a };
	ATF_REQUIRE_EQ(-1, mesh_rp_link_close_parse(lc, sizeof(lc), &reason));
	uint8_t bad_lc1[] = { 0x80, 0x5a,
	    BT_RP_SPEC_LINK_CLOSE_PROHIBITED };
	uint8_t bad_lc3[] = { 0x80, 0x5a,
	    BT_RP_SPEC_LINK_CLOSE_FAIL + 1 };
	ATF_CHECK_EQ(-1, mesh_rp_link_close_parse(bad_lc1,
	    sizeof(bad_lc1), &reason));
	ATF_CHECK_EQ(-1, mesh_rp_link_close_parse(bad_lc3,
	    sizeof(bad_lc3), &reason));
	ATF_CHECK_EQ(-1, mesh_rp_link_close_build(
	    BT_RP_SPEC_LINK_CLOSE_PROHIBITED, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_link_close_build(
	    BT_RP_SPEC_LINK_CLOSE_FAIL + 1, buf, &len));

	/* PDU Send with only the number (no Provisioning PDU) is rejected. */
	uint8_t ps[] = { 0x80, 0x5d, 0x00 };
	ATF_REQUIRE_EQ(-1, mesh_rp_pdu_send_parse(ps, sizeof(ps), &snd));
	/* The payload must be one complete Provisioning PDU, not an arbitrary
	 * nonempty byte string or a valid PDU followed by garbage. */
	uint8_t ps_bad_type[] = { 0x80, 0x5d, 0x00, 0x0a };
	uint8_t ps_bad_len[] = { 0x80, 0x5d, 0x00, 0x00, 0x00, 0x00 };
	ATF_CHECK_EQ(-1, mesh_rp_pdu_send_parse(ps_bad_type,
	    sizeof(ps_bad_type), &snd));
	ATF_CHECK_EQ(-1, mesh_rp_pdu_send_parse(ps_bad_len,
	    sizeof(ps_bad_len), &snd));

	/* Extended Scan Start with count exceeding the params is rejected. */
	uint8_t xs[] = { 0x80, 0x56, 0x05, 0x09 };
	ATF_REQUIRE_EQ(-1, mesh_rp_ext_scan_start_parse(xs, sizeof(xs), &es));
	/* Table 4.176 prohibits zero count, duplicate filters, Shortened Local
	 * Name, and incomplete UUID-list AD types. */
	uint8_t xzero[] = { 0x80, 0x56, 0x00 };
	uint8_t xdup[] = { 0x80, 0x56, 0x02, 0x09, 0x09 };
	uint8_t xshort[] = { 0x80, 0x56, 0x01, BT_RP_SPEC_AD_NAME_SHORT };
	uint8_t xuuid[] = { 0x80, 0x56, 0x03,
	    BT_RP_SPEC_AD_UUID16_INCOMPLETE,
	    BT_RP_SPEC_AD_UUID32_INCOMPLETE,
	    BT_RP_SPEC_AD_UUID128_INCOMPLETE };
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(xzero,
	    sizeof(xzero), &es));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(xdup, sizeof(xdup), &es));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(xshort,
	    sizeof(xshort), &es));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(xuuid,
	    sizeof(xuuid), &es));

	memset(&es, 0, sizeof(es));
	es.ad_type_filter_count = 2;
	es.ad_types[0] = es.ad_types[1] = BT_RP_SPEC_AD_NAME_COMPLETE;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_build(&es, buf, &len));

	/* Extended Scan Report AdvStructures must be a complete concatenation,
	 * not a valid prefix followed by a truncated or zero-length field. */
	uint8_t xr_bad[] = {
		0x80, 0x57, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0x04, 0x09, 0x41
	};
	struct mesh_rp_ext_scan_report er;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_report_parse(xr_bad,
	    sizeof(xr_bad), &er));
	memset(&er, 0, sizeof(er));
	er.has_adv = 1;
	er.adv_len = 1;
	er.adv[0] = 0;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_report_build(&er, buf, &len));
}

/* Mesh Model 1.1.1 §§4.4.4-4.4.5 plus the libmesh defensive API contract. */
ATF_TC_WITHOUT_HEAD(api_guard_and_query_matrix);
ATF_TC_BODY(api_guard_and_query_matrix, tc)
{
	struct mesh_rp_scan_server server;
	struct mesh_rp_scan_client scan_client;
	struct mesh_rp_client_link client_link;
	struct mesh_rp_server_link server_link;
	struct mesh_rp_scan_caps caps;
	struct mesh_rp_scan_start start;
	struct mesh_rp_scan_status scan_status;
	struct mesh_rp_scan_report scan_report;
	struct mesh_rp_ext_scan_start ext_start;
	struct mesh_rp_ext_scan_report ext_report;
	struct mesh_rp_link_open link_open;
	struct mesh_rp_link_status link_status;
	struct mesh_rp_link_report link_report;
	struct mesh_rp_pdu_send send;
	struct mesh_rp_pdu_report report;
	uint8_t buf[96], byte;
	size_t len;
	int emit;

	/* Query messages are real zero-parameter access PDUs. */
	ATF_CHECK_EQ(0, mesh_rp_scan_caps_get_build(buf, &len));
	ATF_CHECK_EQ(2, len);
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_CAPS_GET);
	ATF_CHECK_EQ(0, mesh_rp_scan_get_build(buf, &len));
	ATF_CHECK_EQ(2, len);
	spec_check_opcode(buf, BT_RP_SPEC_OP_SCAN_GET);
	ATF_CHECK_EQ(0, mesh_rp_link_get_build(buf, &len));
	ATF_CHECK_EQ(2, len);
	spec_check_opcode(buf, BT_RP_SPEC_OP_LINK_GET);

	/* Every codec rejects absent input/output and invalid optional lengths. */
	memset(&start, 0, sizeof(start));
	memset(&scan_status, 0, sizeof(scan_status));
	memset(&scan_report, 0, sizeof(scan_report));
	memset(&ext_start, 0, sizeof(ext_start));
	memset(&ext_report, 0, sizeof(ext_report));
	memset(&link_open, 0, sizeof(link_open));
	memset(&link_status, 0, sizeof(link_status));
	memset(&link_report, 0, sizeof(link_report));
	memset(&send, 0, sizeof(send));
	memset(&report, 0, sizeof(report));
	ATF_CHECK_EQ(-1, mesh_rp_scan_caps_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_scan_caps_status_parse(NULL, 0, &caps));
	ATF_CHECK_EQ(-1, mesh_rp_scan_caps_status_parse(buf, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_rp_scan_start_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_scan_start_parse(NULL, 0, &start));
	start.timeout = 1;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_build(&start, buf, &len));
	buf[3] = 0;
	ATF_CHECK_EQ(-1, mesh_rp_scan_start_parse(buf, len, &start));
	ATF_CHECK_EQ(-1, mesh_rp_scan_start_parse(buf, len, NULL));
	ATF_CHECK_EQ(-1, mesh_rp_scan_report_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_scan_report_parse(NULL, 0, &scan_report));
	ATF_CHECK_EQ(-1, mesh_rp_scan_report_parse(buf, len, NULL));
	ext_start.ad_type_filter_count = MESH_RP_AD_FILTER_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_build(&ext_start, buf, &len));
	memset(&ext_start, 0, sizeof(ext_start));
	ext_start.has_uuid = 1;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_build(&ext_start, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(NULL, 0, &ext_start));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_start_parse(buf, 0, NULL));
	ext_report.adv_len = MESH_RP_ADV_DATA_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_report_build(&ext_report, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_report_parse(NULL, 0, &ext_report));
	ATF_CHECK_EQ(-1, mesh_rp_ext_scan_report_parse(buf, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_rp_link_open_build(NULL, buf, &len));
	link_open.has_timeout = 1;
	ATF_CHECK_EQ(-1, mesh_rp_link_open_build(&link_open, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_link_open_parse(NULL, 0, &link_open));
	ATF_CHECK_EQ(-1, mesh_rp_link_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_link_report_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_pdu_send_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_pdu_send_build(&send, buf, &len));
	report.prov_len = MESH_RP_PROV_PDU_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_rp_pdu_report_build(&report, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_pdu_outbound_report_parse(NULL, 0, &byte));
	ATF_CHECK_EQ(-1, mesh_rp_pdu_report_parse(NULL, 0, &report));

	/* State-machine accessors and null contracts, including untouched APIs. */
	mesh_rp_scan_server_init(NULL, 1, 1);
	mesh_rp_scan_server_init(&server, 7, 1);
	memset(&caps, 0, sizeof(caps));
	mesh_rp_scan_server_caps(&server, &caps);
	ATF_CHECK_EQ(7, caps.max_scanned_items);
	ATF_CHECK_EQ(1, caps.active_scan);
	mesh_rp_scan_server_caps(NULL, &caps);
	mesh_rp_scan_server_caps(&server, NULL);
	ATF_CHECK_EQ(-1, mesh_rp_scan_server_start(NULL, &start, 0,
	    &scan_status));
	ATF_CHECK_EQ(-1, mesh_rp_scan_server_stop(NULL, 0, &scan_status));
	mesh_rp_scan_server_status(NULL, 0, &scan_status);
	ATF_CHECK_EQ(-1, mesh_rp_scan_server_device_seen(NULL, UUID_A, 0, 0,
	    0, &scan_report, &emit));
	ATF_CHECK_EQ(0, mesh_rp_scan_server_tick(NULL, 0));
	ATF_CHECK_EQ(0, mesh_rp_scan_server_scanning(NULL));
	mesh_rp_scan_client_init(NULL);
	mesh_rp_scan_client_init(&scan_client);
	ATF_CHECK_EQ(-1, mesh_rp_scan_client_start(NULL, 1, 1, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_scan_client_on_report(NULL, &scan_report));
	ATF_CHECK_EQ(0, mesh_rp_scan_client_found(NULL, UUID_A));
	ATF_CHECK_EQ(-1, mesh_rp_scan_client_stop(NULL, buf, &len));
	mesh_rp_client_link_init(NULL);
	mesh_rp_client_link_init(&client_link);
	ATF_CHECK_EQ(-1, mesh_rp_client_link_open(NULL, UUID_A, 1, 1, 0,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_status(NULL, &link_status));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_report(NULL, &link_report));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_send_pdu(NULL, buf, 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_outbound_report(NULL, 0));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_pdu_report(NULL, &report, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_close(NULL, 0, buf, &len));
	ATF_CHECK_EQ(0, mesh_rp_client_link_tick(NULL, 0));
	ATF_CHECK_EQ(0, mesh_rp_client_link_is_active(NULL));
	ATF_CHECK_EQ(0, mesh_rp_client_link_idle(NULL));
	mesh_rp_server_link_init(NULL);
	mesh_rp_server_link_init(&server_link);
	ATF_CHECK_EQ(-1, mesh_rp_server_link_on_open(NULL, &link_open,
	    &link_status));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_bearer_open(NULL, &link_report));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_on_pdu_send(NULL, &send, buf, &len,
	    &byte));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_report_pdu(NULL, buf, 1, &report));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_on_close(NULL, 0, &link_report));
	mesh_rp_server_link_status(NULL, &link_status);
	ATF_CHECK_EQ(0, mesh_rp_server_link_is_active(NULL));

	/* Negative and idempotence transitions that are distinct from lifecycle. */
	memset(&start, 0, sizeof(start));
	ATF_CHECK_EQ(-1, mesh_rp_scan_server_start(&server, &start, 10,
	    &scan_status));
	ATF_CHECK_EQ(BT_RP_SPEC_STATUS_SCAN_CANNOT_START, scan_status.status);
	start.timeout = 2;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_start(&server, &start, 10,
	    &scan_status));
	ATF_CHECK_EQ(-1, mesh_rp_scan_server_start(&server, &start, 10,
	    &scan_status));
	ATF_CHECK_EQ(BT_RP_SPEC_STATUS_INVALID_STATE, scan_status.status);
	mesh_rp_scan_server_status(&server, 11, &scan_status);
	ATF_CHECK_EQ(0, mesh_rp_scan_server_stop(&server, 12, &scan_status));
	ATF_CHECK_EQ(BT_RP_SPEC_SCAN_IDLE, scan_status.scanning_state);

	ATF_CHECK_EQ(-1, mesh_rp_scan_client_start(&scan_client, 1, 0, NULL,
	    buf, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_start(&scan_client, 1, 2, NULL,
	    buf, &len));
	memset(&scan_report, 0, sizeof(scan_report));
	memcpy(scan_report.uuid, UUID_A, 16);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_on_report(&scan_client,
	    &scan_report));
	ATF_CHECK_EQ(0, mesh_rp_scan_client_on_report(&scan_client,
	    &scan_report));
	scan_client.nfound = MESH_RP_SCAN_FOUND_MAX;
	memcpy(scan_report.uuid, UUID_B, 16);
	ATF_CHECK_EQ(-1, mesh_rp_scan_client_on_report(&scan_client,
	    &scan_report));
	ATF_CHECK_EQ(0, mesh_rp_scan_client_stop(&scan_client, buf, &len));

	client_link.state = BT_RP_SPEC_LINK_ACTIVE;
	ATF_CHECK_EQ(-1, mesh_rp_client_link_open(&client_link, UUID_A, 1, 10,
	    0, buf, &len));
	link_status.status = BT_RP_SPEC_STATUS_INVALID_STATE;
	ATF_CHECK_EQ(0, mesh_rp_client_link_on_status(&client_link,
	    &link_status));
	ATF_CHECK_EQ(BT_RP_SPEC_LINK_IDLE, client_link.state);
	client_link.state = BT_RP_SPEC_LINK_OPENING;
	link_status.status = BT_RP_SPEC_STATUS_SUCCESS;
	link_status.rp_state = BT_RP_SPEC_LINK_ACTIVE;
	ATF_CHECK_EQ(0, mesh_rp_client_link_on_status(&client_link,
	    &link_status));
	ATF_CHECK_EQ(BT_RP_SPEC_LINK_ACTIVE, client_link.state);
	client_link.awaiting_outbound_report = 1;
	ATF_CHECK_EQ(-1, mesh_rp_client_link_send_pdu(&client_link, buf, 1,
	    buf, &len));
	client_link.awaiting_outbound_report = 0;
	ATF_CHECK_EQ(-1, mesh_rp_client_link_send_pdu(&client_link, buf, 0,
	    buf, &len));
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_outbound_report(&client_link, 9));
	client_link.state = BT_RP_SPEC_LINK_IDLE;
	ATF_CHECK_EQ(-1, mesh_rp_client_link_on_pdu_report(&client_link, &report,
	    buf, &len));
	ATF_CHECK_EQ(0, mesh_rp_client_link_tick(&client_link, 99));

	mesh_rp_server_link_init(&server_link);
	ATF_CHECK_EQ(-1, mesh_rp_server_link_bearer_open(&server_link,
	    &link_report));
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_open(&server_link, &link_open,
	    &link_status));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_on_open(&server_link, &link_open,
	    &link_status));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_on_pdu_send(&server_link, &send,
	    buf, &len, &byte));
	ATF_CHECK_EQ(-1, mesh_rp_server_link_report_pdu(&server_link, buf, 1,
	    &report));
	mesh_rp_server_link_status(&server_link, &link_status);
	ATF_CHECK_EQ(BT_RP_SPEC_LINK_OPENING, link_status.rp_state);
}

/* ================================================================
 * Scan state machine: Start -> Report(s) -> Stop, single-device filter,
 * scanned-items limit, and the timeout on a mock clock.
 * ================================================================ */
/* Mesh Protocol 1.1 §4.4.2, Remote Provisioning scanning procedure. */
ATF_TC_WITHOUT_HEAD(scan_fsm_targeted_and_limit);
ATF_TC_BODY(scan_fsm_targeted_and_limit, tc)
{
	struct mesh_rp_scan_server srv;
	struct mesh_rp_scan_client cli;
	struct mesh_rp_scan_start req;
	struct mesh_rp_scan_status st;
	struct mesh_rp_scan_report rep;
	uint8_t msg[32];
	size_t len;
	int emit;
	uint64_t now = 1000;

	mesh_rp_scan_server_init(&srv, 4, 1);
	mesh_rp_scan_client_init(&cli);

	/* Client starts a single-device scan for UUID_A, 5 s timeout. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_start(&cli, 1, 5, UUID_A, msg,
	    &len));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_parse(msg, len, &req));

	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_start(&srv, &req, now, &st));
	ATF_REQUIRE_EQ(BT_RP_SPEC_STATUS_SUCCESS, st.status);
	ATF_REQUIRE_EQ(BT_RP_SPEC_SCAN_LIMITED, st.scanning_state);
	ATF_REQUIRE(mesh_rp_scan_server_scanning(&srv));

	/* A non-matching device is not reported (single-device filter). */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_device_seen(&srv, UUID_B, 0, -40,
	    now, &rep, &emit));
	ATF_REQUIRE_EQ(0, emit);

	/* The targeted device is reported once, then the limit(1) ends scan. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_device_seen(&srv, UUID_A, 0x00a0,
	    -55, now, &rep, &emit));
	ATF_REQUIRE_EQ(1, emit);
	ATF_REQUIRE_EQ(0, memcmp(rep.uuid, UUID_A, 16));
	ATF_REQUIRE(!mesh_rp_scan_server_scanning(&srv));
	mesh_rp_scan_server_status(&srv, now, &st);
	ATF_REQUIRE_EQ(BT_RP_SPEC_SCAN_IDLE, st.scanning_state);
	ATF_REQUIRE_EQ(0, st.scanned_items_limit);
	ATF_REQUIRE_EQ(0, st.timeout);

	/* Deliver the report to the Client. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_build(&rep, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_parse(msg, len, &rep));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_on_report(&cli, &rep));
	ATF_REQUIRE(mesh_rp_scan_client_found(&cli, UUID_A));
	ATF_REQUIRE(!mesh_rp_scan_client_found(&cli, UUID_B));
}

/* Mesh Protocol 1.1 §4.4.2, scan timeout and Scan Status semantics. */
ATF_TC_WITHOUT_HEAD(scan_fsm_timeout);
ATF_TC_BODY(scan_fsm_timeout, tc)
{
	struct mesh_rp_scan_server srv;
	struct mesh_rp_scan_start req;
	struct mesh_rp_scan_status st;
	struct mesh_rp_scan_report rep;
	int emit;
	uint64_t now = 0;

	mesh_rp_scan_server_init(&srv, 4, 0);

	/* General unbounded scan (limit 0) => Active state, 3 s timeout. */
	memset(&req, 0, sizeof(req));
	req.scanned_items_limit = 0;
	req.timeout = 3;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_start(&srv, &req, now, &st));
	ATF_REQUIRE_EQ(BT_RP_SPEC_SCAN_ACTIVE, st.scanning_state);

	/* Just before the deadline a device is still reported. */
	now = 1001;
	mesh_rp_scan_server_status(&srv, now, &st);
	ATF_REQUIRE_EQ(2, st.timeout);
	now = 2999;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_device_seen(&srv, UUID_A, 0, -50,
	    now, &rep, &emit));
	ATF_REQUIRE_EQ(1, emit);

	/* At the 3 s deadline the scan expires. */
	now = 3000;
	ATF_REQUIRE_EQ(1, mesh_rp_scan_server_tick(&srv, now));
	ATF_REQUIRE(!mesh_rp_scan_server_scanning(&srv));
	mesh_rp_scan_server_status(&srv, now, &st);
	ATF_REQUIRE_EQ(0, st.scanned_items_limit);
	ATF_REQUIRE_EQ(0, st.timeout);

	/* A later sighting is not reported. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_device_seen(&srv, UUID_A, 0, -50,
	    now, &rep, &emit));
	ATF_REQUIRE_EQ(0, emit);

	/* Absolute deadline wraps, but elapsed-time expiry remains correct. */
	now = UINT64_MAX - 999;
	req.timeout = 2;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_start(&srv, &req, now, &st));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_tick(&srv, now + 1999));
	ATF_REQUIRE_EQ(1, mesh_rp_scan_server_tick(&srv, now + 2000));
}

/* ================================================================
 * Full remote-provisioning lifecycle over the PB-Remote bearer:
 *   ScanStart -> ScanReport -> LinkOpen -> LinkStatus/Report(active) ->
 *   (provisioning PDUs tunnelled) -> LinkClose.
 *
 * The Client drives a Provisioner mesh_prov_session; the far-side device runs a
 * Device mesh_prov_session reached through the Server, which relays raw
 * Provisioning PDUs.  Every provisioning PDU crosses the wire as a PDU Send /
 * PDU Report with the inbound/outbound numbering.
 * ================================================================ */

/* Move Client -> Server -> device: PDU Send tunnels one provisioner PDU. */
static void
tunnel_c2s(struct mesh_rp_client_link *cl, struct mesh_rp_server_link *sl,
    struct mesh_prov_session *prov, struct mesh_prov_session *dev,
    uint8_t expect_out)
{
	uint8_t pdu[MESH_RP_PROV_PDU_MAX], msg[MESH_RP_MSG_MAX];
	uint8_t relayed[MESH_RP_PROV_PDU_MAX], orep;
	struct mesh_rp_pdu_send snd;
	size_t len, rlen, mlen;

	if (mesh_prov_session_poll(prov, pdu, &len) != 1)
		return;

	/* Client: PDU Send with the current Outbound PDU Number. */
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_send_pdu(cl, pdu, len, msg, &mlen));
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_send_parse(msg, mlen, &snd));
	ATF_REQUIRE_EQ(expect_out, snd.outbound_pdu_number);

	/* Server: relay to the device and emit the PDU Outbound Report. */
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_pdu_send(sl, &snd, relayed,
	    &rlen, &orep));
	ATF_REQUIRE_EQ(expect_out, orep);
	ATF_REQUIRE_EQ(0, mesh_prov_session_recv(dev, relayed, rlen));
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_pdu_delivered(sl, 1, &orep,
	    NULL));

	/* Client: consume the outbound report. */
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_outbound_report_build(orep, msg, &mlen));
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_outbound_report_parse(msg, mlen, &orep));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_outbound_report(cl, orep));
}

/* Move device -> Server -> Client: PDU Report tunnels one device PDU. */
static void
tunnel_s2c(struct mesh_rp_client_link *cl, struct mesh_rp_server_link *sl,
    struct mesh_prov_session *prov, struct mesh_prov_session *dev,
    uint8_t expect_in)
{
	uint8_t pdu[MESH_RP_PROV_PDU_MAX], msg[MESH_RP_MSG_MAX];
	uint8_t delivered[MESH_RP_PROV_PDU_MAX];
	struct mesh_rp_pdu_report rp, rpparse;
	size_t len, dlen, mlen;

	if (mesh_prov_session_poll(dev, pdu, &len) != 1)
		return;

	/* Server: PDU Report with the current Inbound PDU Number. */
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_report_pdu(sl, pdu, len, &rp));
	ATF_REQUIRE_EQ(expect_in, rp.inbound_pdu_number);
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_report_build(&rp, msg, &mlen));

	/* Client: parse the report and feed the provisioner session. */
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_report_parse(msg, mlen, &rpparse));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_pdu_report(cl, &rpparse,
	    delivered, &dlen));
	ATF_REQUIRE_EQ(0, mesh_prov_session_recv(prov, delivered, dlen));
}

/* Mesh Protocol 1.1 §4.4 and §8.7; Mesh Model 1.1.1 §§4.4.4-4.4.5. */
ATF_TC_WITHOUT_HEAD(remote_provisioning_lifecycle);
ATF_TC_BODY(remote_provisioning_lifecycle, tc)
{
	struct mesh_rp_scan_server sscan;
	struct mesh_rp_scan_client cscan;
	struct mesh_rp_client_link clink;
	struct mesh_rp_server_link slink;
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata, got;
	struct mesh_rp_scan_start sreq;
	struct mesh_rp_scan_status sst;
	struct mesh_rp_scan_report srep;
	struct mesh_rp_link_open lop;
	struct mesh_rp_link_status lst;
	struct mesh_rp_link_report lrep;
	uint8_t msg[MESH_RP_MSG_MAX];
	size_t len;
	uint8_t reason;
	int emit, i;
	uint8_t exp_out = 1, exp_in = 1;
	uint64_t now = 1000;

	/* --- Scan: find the remote unprovisioned device. --- */
	mesh_rp_scan_server_init(&sscan, 4, 1);
	mesh_rp_scan_client_init(&cscan);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_start(&cscan, 1, 5, UUID_A, msg,
	    &len));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_parse(msg, len, &sreq));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_start(&sscan, &sreq, now, &sst));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_server_device_seen(&sscan, UUID_A, 0x00a0,
	    -55, now, &srep, &emit));
	ATF_REQUIRE_EQ(1, emit);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_build(&srep, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_parse(msg, len, &srep));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_client_on_report(&cscan, &srep));
	ATF_REQUIRE(mesh_rp_scan_client_found(&cscan, UUID_A));

	/* --- Link Open: PB-Remote link to the discovered UUID. --- */
	mesh_rp_client_link_init(&clink);
	mesh_rp_server_link_init(&slink);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_open(&clink, UUID_A, 10, 30000,
	    now, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_parse(msg, len, &lop));
	ATF_REQUIRE_EQ(0, memcmp(lop.uuid, UUID_A, 16));

	/* Server accepts: Link Status(opening). */
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_open(&slink, &lop, &lst));
	ATF_REQUIRE_EQ(BT_RP_SPEC_STATUS_SUCCESS, lst.status);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_OPENING, lst.rp_state);
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_build(&lst, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_parse(msg, len, &lst));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_status(&clink, &lst));
	ATF_REQUIRE(!mesh_rp_client_link_is_active(&clink));

	/* Device-side bearer up: Link Report(active) => Client ACTIVE. */
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_bearer_open(&slink, &lrep));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_ACTIVE, lrep.rp_state);
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_build(&lrep, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_parse(msg, len, &lrep));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_report(&clink, &lrep));
	ATF_REQUIRE(mesh_rp_client_link_is_active(&clink));
	ATF_REQUIRE(mesh_rp_server_link_is_active(&slink));

	/* --- Provisioning tunnelled over the link. --- */
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(PROV_DATA, &pdata));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = BT_RP_SPEC_ALGO_BIT_P256_CMAC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, PROV_PRIV, RAND_PROV,
	    0x00, &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, DEV_PRIV, RAND_DEV, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));

	/*
	 * Pump: each round drains the provisioner's outbound PDUs to the device
	 * via PDU Send, then the device's outbound PDUs back via PDU Report.
	 * The Outbound/Inbound PDU numbers advance by one per tunnelled PDU.
	 */
	for (i = 0; i < 32; i++) {
		while (mesh_rp_client_link_idle(&clink)) {
			uint8_t peek[MESH_RP_PROV_PDU_MAX];
			size_t plen;
			struct mesh_prov_session tmp;

			/* Stop when the provisioner has nothing queued. */
			tmp = prov;
			if (mesh_prov_session_poll(&tmp, peek, &plen) != 1)
				break;
			tunnel_c2s(&clink, &slink, &prov, &dev, exp_out++);
		}
		while (1) {
			uint8_t peek[MESH_RP_PROV_PDU_MAX];
			size_t plen;
			struct mesh_prov_session tmp;

			tmp = dev;
			if (mesh_prov_session_poll(&tmp, peek, &plen) != 1)
				break;
			tunnel_s2c(&clink, &slink, &prov, &dev, exp_in++);
		}
		if (mesh_prov_session_done(&prov) && mesh_prov_session_done(&dev))
			break;
	}

	ATF_CHECK(mesh_prov_session_done(&prov));
	ATF_CHECK(mesh_prov_session_done(&dev));
	ATF_CHECK(!mesh_prov_session_failed(&prov));
	ATF_CHECK(!mesh_prov_session_failed(&dev));

	/* The remote device was provisioned with the handed-over data. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_get_data(&dev, &got));
	ATF_CHECK_EQ(0x0567, got.netkey_index);
	ATF_CHECK_EQ(0x0b0c, got.unicast_addr);
	/* Both sides derived the same DevKey. */
	ATF_CHECK_EQ(0, memcmp(mesh_prov_session_devkey(&prov),
	    mesh_prov_session_devkey(&dev), 16));
	/* Several PDUs crossed the wire; the numbering advanced. */
	ATF_CHECK(exp_out >= 5);
	ATF_CHECK(exp_in >= 5);

	/* --- Link Close. --- */
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_close(&clink,
	    BT_RP_SPEC_LINK_CLOSE_SUCCESS, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_close_parse(msg, len, &reason));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_CLOSE_SUCCESS, reason);
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_close(&slink, reason, &lrep));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_IDLE, lrep.rp_state);
	ATF_REQUIRE_EQ(0, lrep.has_reason);
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_build(&lrep, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_parse(msg, len, &lrep));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_report(&clink, &lrep));
	ATF_REQUIRE(!mesh_rp_client_link_is_active(&clink));
	ATF_REQUIRE(!mesh_rp_server_link_is_active(&slink));

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/* ================================================================
 * Client link timeout: no Link Status/Report before the open budget elapses.
 * ================================================================ */
/* Mesh Protocol 1.1 §4.4.3 plus the libmesh millisecond timeout contract. */
ATF_TC_WITHOUT_HEAD(client_link_open_timeout);
ATF_TC_BODY(client_link_open_timeout, tc)
{
	struct mesh_rp_client_link cl;
	uint8_t msg[32];
	size_t len;
	uint64_t now = 0;

	mesh_rp_client_link_init(&cl);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_open(&cl, UUID_A, 10, 10000, now,
	    msg, &len));
	/* Before the deadline the link is still opening. */
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_tick(&cl, 9999));
	ATF_REQUIRE(!mesh_rp_client_link_is_active(&cl));
	/* At the deadline the link-open budget expires. */
	ATF_REQUIRE_EQ(1, mesh_rp_client_link_tick(&cl, 10000));
	ATF_REQUIRE(!mesh_rp_client_link_is_active(&cl));

	mesh_rp_client_link_init(&cl);
	now = UINT64_MAX - 499;
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_open(&cl, UUID_A, 10, 1000, now,
	    msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_tick(&cl, now + 999));
	ATF_REQUIRE_EQ(1, mesh_rp_client_link_tick(&cl, now + 1000));
}

/* Mesh Protocol 1.1 §4.4.3 and Mesh Model 1.1.1 Table 4.186. */
ATF_TC_WITHOUT_HEAD(nppi_link_state_and_numbering);
ATF_TC_BODY(nppi_link_state_and_numbering, tc)
{
	struct mesh_rp_client_link cl;
	struct mesh_rp_server_link sl;
	struct mesh_rp_link_open op;
	struct mesh_rp_link_status st;
	struct mesh_rp_link_report lr;
	struct mesh_rp_pdu_send snd, bad;
	struct mesh_rp_pdu_report rp;
	uint8_t msg[MESH_RP_MSG_MAX], pdu[2] = { BT_RP_SPEC_PROV_INVITE, 0 };
	uint8_t delivered[MESH_RP_PROV_PDU_MAX], report_number;
	size_t len, delivered_len;

	mesh_rp_client_link_init(&cl);
	mesh_rp_server_link_init(&sl);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_open_nppi(&cl,
	    BT_RP_SPEC_NPPI_DEVICE_KEY_REFRESH, 10000, 0, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_parse(msg, len, &op));
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_open(&sl, &op, &st));
	/* NPPI opens directly into Link Active; Link Opening is not used. */
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_ACTIVE, st.rp_state);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_ACTIVE, sl.state);
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_bearer_open(&sl, &lr));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_ACTIVE, lr.rp_state);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_status(&cl, &st));
	ATF_REQUIRE(mesh_rp_client_link_is_active(&cl));

	/* Counts start at zero and are incremented before the first PDU. */
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_send_pdu(&cl, pdu, sizeof(pdu),
	    msg, &len));
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_send_parse(msg, len, &snd));
	ATF_REQUIRE_EQ(1, snd.outbound_pdu_number);
	/* A failed encode does not consume the next PDU number. */
	cl.awaiting_outbound_report = 0;
	ATF_REQUIRE_EQ(-1, mesh_rp_client_link_send_pdu(&cl, pdu, sizeof(pdu),
	    NULL, &len));
	ATF_REQUIRE_EQ(1, cl.outbound_pdu_number);
	cl.awaiting_outbound_report = 1;
	bad = snd;
	bad.outbound_pdu_number = 3;
	ATF_REQUIRE_EQ(1, mesh_rp_server_link_on_pdu_send(&sl, &bad, delivered,
	    &delivered_len, &report_number));
	ATF_REQUIRE_EQ(0, delivered_len);
	ATF_REQUIRE_EQ(0, report_number);
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_pdu_send(&sl, &snd, delivered,
	    &delivered_len, &report_number));
	ATF_REQUIRE_EQ(1, report_number);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_OUTBOUND_TRANSFER, sl.state);
	ATF_REQUIRE_EQ(0, sl.outbound_pdu_number);
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_pdu_delivered(&sl, 1,
	    &report_number, NULL));
	ATF_REQUIRE_EQ(1, sl.outbound_pdu_number);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_outbound_report(&cl,
	    report_number));

	ATF_REQUIRE_EQ(0, mesh_rp_server_link_report_pdu(&sl, pdu, sizeof(pdu),
	    &rp));
	ATF_REQUIRE_EQ(1, rp.inbound_pdu_number);
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_pdu_report(&cl, &rp, delivered,
	    &delivered_len));
	ATF_REQUIRE_EQ(-1, mesh_rp_client_link_on_pdu_report(&cl, &rp, delivered,
	    &delivered_len));

	/* Downstream failure does not advance or acknowledge the count. */
	snd.outbound_pdu_number = 2;
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_pdu_send(&sl, &snd, delivered,
	    &delivered_len, &report_number));
	ATF_REQUIRE_EQ(1, mesh_rp_server_link_pdu_delivered(&sl, 0,
	    &report_number, &lr));
	ATF_REQUIRE_EQ(1, report_number);
	ATF_REQUIRE_EQ(1, sl.outbound_pdu_number);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_IDLE, sl.state);
	ATF_REQUIRE_EQ(BT_RP_SPEC_STATUS_LINK_CLOSED_BY_SERVER, lr.status);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_IDLE, lr.rp_state);
	ATF_REQUIRE_EQ(0, lr.has_reason);

	/* PB-Remote failure defers its report until bearer close completion and
	 * preserves the specific Cannot Send PDU status. */
	mesh_rp_server_link_init(&sl);
	memset(&op, 0, sizeof(op));
	memcpy(op.uuid, UUID_A, sizeof(op.uuid));
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_open(&sl, &op, &st));
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_bearer_open(&sl, &lr));
	snd.outbound_pdu_number = 1;
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_on_pdu_send(&sl, &snd, delivered,
	    &delivered_len, &report_number));
	ATF_REQUIRE_EQ(1, mesh_rp_server_link_pdu_delivered(&sl, 0,
	    &report_number, NULL));
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_CLOSING, sl.state);
	ATF_REQUIRE_EQ(0, sl.outbound_pdu_number);
	ATF_REQUIRE_EQ(0, mesh_rp_server_link_bearer_closed(&sl, 2, &lr));
	ATF_REQUIRE_EQ(BT_RP_SPEC_STATUS_CANNOT_TX_PDU, lr.status);
	ATF_REQUIRE_EQ(BT_RP_SPEC_LINK_IDLE, lr.rp_state);
	ATF_REQUIRE_EQ(0, lr.has_reason);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scan_caps_status_codec);
	ATF_TP_ADD_TC(tp, scan_start_codec);
	ATF_TP_ADD_TC(tp, scan_status_codec_and_guards);
	ATF_TP_ADD_TC(tp, scan_report_codec);
	ATF_TP_ADD_TC(tp, ext_scan_codec);
	ATF_TP_ADD_TC(tp, link_msgs_codec);
	ATF_TP_ADD_TC(tp, pdu_msgs_codec);
	ATF_TP_ADD_TC(tp, malformed_reject);
	ATF_TP_ADD_TC(tp, api_guard_and_query_matrix);
	ATF_TP_ADD_TC(tp, scan_fsm_targeted_and_limit);
	ATF_TP_ADD_TC(tp, scan_fsm_timeout);
	ATF_TP_ADD_TC(tp, remote_provisioning_lifecycle);
	ATF_TP_ADD_TC(tp, client_link_open_timeout);
	ATF_TP_ADD_TC(tp, nppi_link_state_and_numbering);

	return (atf_no_error());
}
