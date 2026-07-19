/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Mesh Protocol 1.1 additional Configuration models
 * (mesh_cfg_v11.[ch]; MshMDL_v1.1 Section 4) and their integration into the
 * meshd(8) Configuration Server dispatch runtime (meshd_node.c).
 *
 * Two layers are covered.  The codec tests build each message and assert the
 * exact Access PDU octets - opcode plus parameters - derived from the MshMDL
 * Section 4.3.4 message formats (never from captured output), then parse the
 * bytes back and check the fields round-trip.  The server tests build a
 * Configuration Client message with the codecs, hand it to
 * meshd_foundation_recv(), and check the Get -> Set -> Get behaviour and the
 * auto-Status reply against the same wire layouts.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "spec_mesh_cfg_v11_oracles.h"

/* Deterministic test key material. */
static const uint8_t g_netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t g_appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

#define	ELEM	0x0001

static void
init_node(struct meshd_node *nd)
{
	struct meshd_config cfg;

	meshd_config_defaults(&cfg);
	memcpy(cfg.netkey, g_netkey, 16);
	memcpy(cfg.appkey, g_appkey, 16);
	cfg.have_netkey = 1;
	cfg.have_appkey = 1;
	cfg.unicast_addr = ELEM;
	cfg.iv_index = 0;
	cfg.default_ttl = 7;
	cfg.netkey_index = 0;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
}

/* Deliver one Config message; require a reply was produced, return its length. */
static size_t
deliver(struct meshd_node *nd, const uint8_t *msg, size_t mlen, uint8_t *reply,
    size_t reply_max)
{
	size_t rlen = 0;

	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply, reply_max,
	    &rlen));
	return (rlen);
}

/* Assert the first two octets are the given 2-octet opcode (MshMDL 3.7.3.1). */
static void
check_opcode(const uint8_t *p, uint32_t opcode)
{

	ATF_CHECK_EQ((uint8_t)(opcode >> 8), p[0]);
	ATF_CHECK_EQ((uint8_t)(opcode & 0xff), p[1]);
}

ATF_TC_WITHOUT_HEAD(foundation_opcode_length_matrix);
ATF_TC_BODY(foundation_opcode_length_matrix, tc)
{
	static const uint32_t opcodes[] = {
		MESH_CFG_OP_COMP_DATA_GET, MESH_CFG_OP_DEFAULT_TTL_GET,
		MESH_CFG_OP_DEFAULT_TTL_SET, MESH_CFG_OP_BEACON_GET,
		MESH_CFG_OP_BEACON_SET, MESH_CFG_OP_GATT_PROXY_GET,
		MESH_CFG_OP_GATT_PROXY_SET, MESH_CFG_OP_FRIEND_GET,
		MESH_CFG_OP_FRIEND_SET, MESH_CFG_OP_RELAY_GET,
		MESH_CFG_OP_RELAY_SET, MESH_CFG_OP_NET_TRANSMIT_GET,
		MESH_CFG_OP_NET_TRANSMIT_SET, MESH_CFG_OP_NODE_RESET,
		MESH_CFG_OP_NETKEY_ADD, MESH_CFG_OP_NETKEY_UPDATE,
		MESH_CFG_OP_NETKEY_DELETE, MESH_CFG_OP_NETKEY_GET,
		MESH_CFG_OP_APPKEY_ADD, MESH_CFG_OP_APPKEY_UPDATE,
		MESH_CFG_OP_APPKEY_DELETE, MESH_CFG_OP_APPKEY_GET,
		MESH_CFG_OP_MODEL_APP_BIND, MESH_CFG_OP_MODEL_APP_UNBIND,
		MESH_CFG_OP_SIG_MODEL_APP_GET, MESH_CFG_OP_VND_MODEL_APP_GET,
		MESH_CFG_OP_MODEL_SUB_ADD, MESH_CFG_OP_MODEL_SUB_DELETE,
		MESH_CFG_OP_MODEL_SUB_OVERWRITE, MESH_CFG_OP_MODEL_SUB_DELETE_ALL,
		MESH_CFG_OP_MODEL_SUB_VA_ADD, MESH_CFG_OP_MODEL_SUB_VA_DELETE,
		MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE, MESH_CFG_OP_SIG_MODEL_SUB_GET,
		MESH_CFG_OP_VND_MODEL_SUB_GET, MESH_CFG_OP_MODEL_PUB_GET,
		MESH_CFG_OP_MODEL_PUB_SET, MESH_CFG_OP_MODEL_PUB_VA_SET,
		MESH_CFG_OP_KEY_REFRESH_PHASE_GET,
		MESH_CFG_OP_KEY_REFRESH_PHASE_SET, MESH_CFG_OP_NODE_IDENTITY_GET,
		MESH_CFG_OP_NODE_IDENTITY_SET, MESH_CFG_OP_LPN_POLLTIMEOUT_GET,
		MESH_CFG_OP_HB_PUB_GET, MESH_CFG_OP_HB_PUB_SET,
		MESH_CFG_OP_HB_SUB_GET, MESH_CFG_OP_HB_SUB_SET,
		MESH_HLT_OP_ATTENTION_GET, MESH_HLT_OP_ATTENTION_SET,
		MESH_HLT_OP_PERIOD_GET, MESH_HLT_OP_PERIOD_SET,
		MESH_HLT_OP_FAULT_GET, MESH_HLT_OP_FAULT_CLEAR,
		MESH_HLT_OP_FAULT_CLEAR_UNREL, MESH_HLT_OP_FAULT_TEST,
		MESH_HLT_OP_FAULT_TEST_UNREL, BT_MCFG11_OP_SAR_TRANSMITTER_GET,
		BT_MCFG11_OP_SAR_TRANSMITTER_SET, BT_MCFG11_OP_SAR_RECEIVER_GET,
		BT_MCFG11_OP_SAR_RECEIVER_SET, BT_MCFG11_OP_OD_PRIV_PROXY_GET,
		BT_MCFG11_OP_OD_PRIV_PROXY_SET, BT_MCFG11_OP_PRIV_BEACON_GET,
		BT_MCFG11_OP_PRIV_BEACON_SET, BT_MCFG11_OP_PRIV_GATT_PROXY_GET,
		BT_MCFG11_OP_PRIV_GATT_PROXY_SET,
		BT_MCFG11_OP_PRIV_NODE_IDENTITY_GET,
		BT_MCFG11_OP_PRIV_NODE_IDENTITY_SET,
		BT_MCFG11_OP_SOL_RPL_CLEAR,
		BT_MCFG11_OP_SOL_RPL_CLEAR_UNACK,
		BT_MCFG11_OP_LARGE_COMP_DATA_GET,
		BT_MCFG11_OP_MODELS_METADATA_GET, BT_MCFG11_OP_AGGREGATOR_SEQUENCE
	};
	MESH_HEAP(struct meshd_node, nd);
	uint8_t params[32], msg[40], reply[MESH_ACCESS_PAYLOAD_MAX];
	size_t mlen, rlen;
	int rc;

	/* Every registered foundation opcode is exercised at every short wire
	 * length with two adversarial payload patterns.  This catches parser
	 * boundary regressions and systematically reaches each handler's reject
	 * path without sharing mutations between opcodes. */
	for (size_t oi = 0; oi < sizeof(opcodes) / sizeof(opcodes[0]); oi++) {
		for (unsigned pattern = 0; pattern < 2; pattern++) {
			init_node(nd);
			memset(params, pattern ? 0xff : 0, sizeof(params));
			for (size_t plen = 0; plen <= sizeof(params); plen++) {
				mlen = sizeof(msg);
				ATF_REQUIRE_EQ(0, mesh_access_pdu_build(opcodes[oi],
				    plen == 0 ? NULL : params, plen, msg, &mlen));
				rlen = 0;
				rc = meshd_foundation_recv(nd, msg, mlen, reply,
				    sizeof(reply), &rlen);
				ATF_CHECK(rc == -1 || rc == 0 || rc == 1);
			}
			meshd_node_fini(nd);
		}
	}
}

/* ================================================================
 * SAR Transmitter codec (Section 4.2.29): four packed octets.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_tx_codec);
ATF_TC_BODY(sar_tx_codec, tc)
{
	struct mesh_cfg_sar_transmitter tx, got;
	uint8_t msg[16];
	size_t mlen;
	uint32_t op;

	memset(&tx, 0, sizeof(tx));
	tx.seg_interval_step = 0x3;
	tx.unicast_retrans_count = 0x5;
	tx.unicast_retrans_without_progress_count = 0x2;
	tx.unicast_retrans_interval_step = 0x7;
	tx.unicast_retrans_interval_increment = 0x1;
	tx.multicast_retrans_count = 0x4;
	tx.multicast_retrans_interval_step = 0x6;

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(BT_MCFG11_OP_SAR_TRANSMITTER_SET,
	    &tx, msg, &mlen));
	ATF_CHECK_EQ(BT_MCFG11_ACCESS_OPCODE_LEN + BT_MCFG11_SAR_TX_PARAM_LEN,
	    mlen);
	check_opcode(msg, BT_MCFG11_OP_SAR_TRANSMITTER_SET);
	ATF_CHECK_EQ(BT_MCFG11_SAR_TX_SAMPLE_0, msg[2]);
	ATF_CHECK_EQ(BT_MCFG11_SAR_TX_SAMPLE_1, msg[3]);
	ATF_CHECK_EQ(BT_MCFG11_SAR_TX_SAMPLE_2, msg[4]);
	ATF_CHECK_EQ(BT_MCFG11_SAR_TX_SAMPLE_3, msg[5]);

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(msg, mlen, &op, &got));
	ATF_CHECK_EQ(BT_MCFG11_OP_SAR_TRANSMITTER_SET, op);
	ATF_CHECK_EQ(0, memcmp(&tx, &got, sizeof(tx)));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_build(0, &tx, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_build(BT_MCFG11_OP_SAR_TRANSMITTER_SET,
	    NULL, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(NULL, 0, NULL, &got));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(msg, mlen, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(msg, mlen - 1, NULL, &got));
	tx.multicast_retrans_interval_step = 0x10;
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_build(BT_MCFG11_OP_SAR_TRANSMITTER_SET,
	    &tx, msg, &mlen));

	/* Get has no parameters. */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(msg, &mlen));
	ATF_CHECK_EQ(BT_MCFG11_ACCESS_OPCODE_LEN, mlen);
	check_opcode(msg, BT_MCFG11_OP_SAR_TRANSMITTER_GET);
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(msg, mlen, NULL, &got));
}

/* ================================================================
 * SAR Receiver codec (Section 4.2.30): three packed octets.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sar_rx_codec);
ATF_TC_BODY(sar_rx_codec, tc)
{
	struct mesh_cfg_sar_receiver rx, got;
	uint8_t msg[16];
	size_t mlen;

	memset(&rx, 0, sizeof(rx));
	rx.segments_threshold = 0x12;
	rx.ack_delay_increment = 0x5;
	rx.discard_timeout = 0x9;
	rx.rx_segment_interval_step = 0x4;
	rx.ack_retrans_count = 0x2;

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET, &rx,
	    msg, &mlen));
	ATF_CHECK_EQ(BT_MCFG11_ACCESS_OPCODE_LEN + BT_MCFG11_SAR_RX_PARAM_LEN,
	    mlen);
	check_opcode(msg, BT_MCFG11_OP_SAR_RECEIVER_SET);
	ATF_CHECK_EQ(BT_MCFG11_SAR_RX_SAMPLE_0, msg[2]);
	ATF_CHECK_EQ(BT_MCFG11_SAR_RX_SAMPLE_1, msg[3]);
	ATF_CHECK_EQ(BT_MCFG11_SAR_RX_SAMPLE_2, msg[4]);

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(msg, mlen, NULL, &got));
	ATF_CHECK_EQ(0, memcmp(&rx, &got, sizeof(rx)));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_build(0, &rx, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET,
	    NULL, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(NULL, 0, NULL, &got));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(msg, mlen, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(msg, mlen - 1, NULL, &got));
	rx.ack_retrans_count = 4;
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET, &rx,
	    msg, &mlen));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_get_build(msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(msg, mlen, NULL, &got));
}

/* ================================================================
 * On-Demand Private Proxy codec: single octet.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(od_priv_proxy_codec);
ATF_TC_BODY(od_priv_proxy_codec, tc)
{
	uint8_t msg[8], v;
	size_t mlen;
	uint32_t op;

	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_build(BT_MCFG11_OP_OD_PRIV_PROXY_SET,
	    0x0A, msg, &mlen));
	ATF_CHECK_EQ(3, mlen);
	check_opcode(msg, BT_MCFG11_OP_OD_PRIV_PROXY_SET);
	ATF_CHECK_EQ(0x0A, msg[2]);
	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_parse(msg, mlen, &op, &v));
	ATF_CHECK_EQ(BT_MCFG11_OP_OD_PRIV_PROXY_SET, op);
	ATF_CHECK_EQ(0x0A, v);
	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_build(0, 1, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_parse(NULL, 0, NULL, &v));
	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_parse(msg, mlen - 1, NULL, &v));
	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_get_build(msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_parse(msg, mlen, NULL, &v));
}

/* ================================================================
 * Private Beacon / GATT Proxy / Node Identity codecs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(priv_beacon_codec);
ATF_TC_BODY(priv_beacon_codec, tc)
{
	struct mesh_cfg_priv_beacon pb, got;
	uint8_t msg[8], v;
	size_t mlen;
	uint32_t op;

	/* Set with the optional Random Update Interval Steps octet present. */
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = 1;
	pb.random_update_interval_steps = 0x0A;
	pb.has_random_update = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
	ATF_CHECK_EQ(4, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_BEACON_SET);
	ATF_CHECK_EQ(0x01, msg[2]);
	ATF_CHECK_EQ(0x0A, msg[3]);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_parse(msg, mlen, &got));
	ATF_CHECK_EQ(1, got.private_beacon);
	ATF_CHECK_EQ(0x0A, got.random_update_interval_steps);
	ATF_CHECK_EQ(1, got.has_random_update);

	/* Set with only the Private Beacon octet. */
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
	ATF_CHECK_EQ(3, mlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_parse(msg, mlen, &got));
	ATF_CHECK_EQ(0, got.has_random_update);

	/* Status always carries both octets. */
	pb.private_beacon = 1;
	pb.random_update_interval_steps = 0x03;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_status_build(&pb, msg, &mlen));
	ATF_CHECK_EQ(4, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_BEACON_STATUS);
	ATF_CHECK_EQ(0x01, msg[2]);
	ATF_CHECK_EQ(0x03, msg[3]);

	/* Private GATT Proxy single octet. */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_gatt_proxy_build(
	    BT_MCFG11_OP_PRIV_GATT_PROXY_SET, 0x01, msg, &mlen));
	ATF_CHECK_EQ(3, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_GATT_PROXY_SET);
	ATF_CHECK_EQ(0x01, msg[2]);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_gatt_proxy_parse(msg, mlen, &op, &v));
	ATF_CHECK_EQ(0x01, v);
	ATF_CHECK_EQ(-1, mesh_cfg_priv_gatt_proxy_build(
	    BT_MCFG11_OP_PRIV_GATT_PROXY_SET, 2, msg, &mlen));
	pb.private_beacon = 2;
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
}

ATF_TC_WITHOUT_HEAD(priv_node_identity_codec);
ATF_TC_BODY(priv_node_identity_codec, tc)
{
	struct mesh_cfg_priv_node_identity id, got;
	uint8_t msg[8];
	size_t mlen;
	uint8_t status;
	uint16_t net_idx;

	/* Get: NetKeyIndex (2, 12-bit packed LE). */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_get_build(0x001, msg, &mlen));
	ATF_CHECK_EQ(4, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_NODE_IDENTITY_GET);
	ATF_CHECK_EQ(0x01, msg[2]);
	ATF_CHECK_EQ(0x00, msg[3]);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_get_parse(msg, mlen,
	    &net_idx));
	ATF_CHECK_EQ(0x001, net_idx);

	/* Set: NetKeyIndex (2) + Private Identity (1). */
	memset(&id, 0, sizeof(id));
	id.net_idx = 0x001;
	id.identity = BT_MCFG11_PRIV_ID_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&id, msg, &mlen));
	ATF_CHECK_EQ(5, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_NODE_IDENTITY_SET);
	ATF_CHECK_EQ(0x01, msg[2]);
	ATF_CHECK_EQ(0x00, msg[3]);
	ATF_CHECK_EQ(0x01, msg[4]);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_parse(msg, mlen, &got));
	ATF_CHECK_EQ(0x001, got.net_idx);
	ATF_CHECK_EQ(BT_MCFG11_PRIV_ID_RUNNING, got.identity);

	/* Status: Status (1) + NetKeyIndex (2) + Private Identity (1). */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_build(
	    BT_MCFG11_STATUS_SUCCESS, &id, msg, &mlen));
	ATF_CHECK_EQ(6, mlen);
	check_opcode(msg, BT_MCFG11_OP_PRIV_NODE_IDENTITY_STATUS);
	ATF_CHECK_EQ(0x00, msg[2]);
	ATF_CHECK_EQ(0x01, msg[3]);
	ATF_CHECK_EQ(0x00, msg[4]);
	ATF_CHECK_EQ(0x01, msg[5]);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(msg, mlen,
	    &status, &got));
	ATF_CHECK_EQ(BT_MCFG11_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0x001, got.net_idx);
	id.identity = BT_MCFG11_PRIV_ID_NOT_SUPPORTED;
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_set_build(&id, msg, &mlen));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_get_build(
	    BT_MCFG11_KEY_INDEX_MAX + 1, msg,
	    &mlen));
}

/* ================================================================
 * Solicitation PDU RPL Items Clear codec: address range with an optional
 * Range Length signalled by the top bit of the little-endian word.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sol_pdu_rpl_codec);
ATF_TC_BODY(sol_pdu_rpl_codec, tc)
{
	struct mesh_cfg_addr_range r, got;
	uint8_t msg[8];
	size_t mlen;
	uint32_t op;

	/* Single address: 2 octets, no Range Length, Length-Present bit clear. */
	memset(&r, 0, sizeof(r));
	r.range_start = 0x1234;
	r.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR, &r, msg, &mlen));
	ATF_CHECK_EQ(4, mlen);
	check_opcode(msg, BT_MCFG11_OP_SOL_RPL_CLEAR);
	ATF_CHECK_EQ(0x34, msg[2]);
	ATF_CHECK_EQ(0x12, msg[3]);
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_parse(msg, mlen, &op, &got));
	ATF_CHECK_EQ(0x1234, got.range_start);
	ATF_CHECK_EQ(1, got.range_length);

	/* Ranged: 3 octets, Range Length present, Length-Present bit set. */
	memset(&r, 0, sizeof(r));
	r.range_start = 0x0100;
	r.range_length = 5;
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR_UNACK, &r, msg, &mlen));
	ATF_CHECK_EQ(5, mlen);
	check_opcode(msg, BT_MCFG11_OP_SOL_RPL_CLEAR_UNACK);
	ATF_CHECK_EQ(0x00, msg[2]);
	ATF_CHECK_EQ(0x81, msg[3]);	/* 0x0100 | 0x8000 -> LE high octet 0x81 */
	ATF_CHECK_EQ(0x05, msg[4]);
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_parse(msg, mlen, &op, &got));
	ATF_CHECK_EQ(0x0100, got.range_start);
	ATF_CHECK_EQ(5, got.range_length);

	/* Status echoes the range. */
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_build(&r, msg, &mlen));
	check_opcode(msg, BT_MCFG11_OP_SOL_RPL_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_parse(msg, mlen, &got));
	ATF_CHECK_EQ(0x0100, got.range_start);
	ATF_CHECK_EQ(5, got.range_length);

	/* Mesh Protocol 3.4.2.2.1 prohibits zero and overflowing ranges. */
	r.range_start = 0;
	r.range_length = 1;
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR, &r, msg, &mlen));
	r.range_start = 0x7fff;
	r.range_length = 2;
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_build(&r, msg, &mlen));

	/* Parsers must not accept prohibited RangeLength or wrapped ranges. */
	msg[0] = (uint8_t)(BT_MCFG11_OP_SOL_RPL_STATUS >> 8);
	msg[1] = (uint8_t)BT_MCFG11_OP_SOL_RPL_STATUS;
	msg[2] = 0xff; msg[3] = 0xff; msg[4] = 0x02;
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_parse(msg, 5, &got));
	msg[2] = 0x01; msg[3] = 0x80; msg[4] = 0x01;
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_parse(msg, 5, &got));
}

/* ================================================================
 * Opcodes Aggregator codec: length prefix + item list.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(aggregator_codec);
ATF_TC_BODY(aggregator_codec, tc)
{
	struct mesh_cfg_agg_item items[3], got[MESH_CFG_AGG_MAX_ITEMS];
	uint8_t a[2] = { 0x80, 0x0C };		/* Default TTL Get */
	uint8_t b[2] = { 0x80, 0x6C };		/* SAR Transmitter Get */
	uint8_t msg[64], pre[2];
	size_t mlen, n, plen, l, pfx;
	uint16_t elem;

	/* Length prefix: <=0x7F is 1 octet (len<<1), else 2 octets LE. */
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_encode(3, pre, &plen));
	ATF_CHECK_EQ(1, plen);
	ATF_CHECK_EQ(0x06, pre[0]);
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_encode(0x90, pre, &plen));
	ATF_CHECK_EQ(2, plen);
	ATF_CHECK_EQ(0x21, pre[0]);		/* (0x90<<1)|1 = 0x121 LE */
	ATF_CHECK_EQ(0x01, pre[1]);
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_decode(pre, 2, &l, &pfx));
	ATF_CHECK_EQ(0x90, l);
	ATF_CHECK_EQ(2, pfx);

	items[0].data = a;
	items[0].len = 2;
	items[1].data = b;
	items[1].len = 2;
	items[2].data = NULL;
	items[2].len = 0;			/* empty item */
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_seq_build(ELEM, items, 3, msg, &mlen));
	check_opcode(msg, BT_MCFG11_OP_AGGREGATOR_SEQUENCE);
	ATF_CHECK_EQ(0x01, msg[2]);		/* Element Address LE */
	ATF_CHECK_EQ(0x00, msg[3]);
	ATF_CHECK_EQ(0x04, msg[4]);		/* item0 length prefix (2<<1) */
	ATF_CHECK_EQ(0x80, msg[5]);
	ATF_CHECK_EQ(0x0C, msg[6]);

	ATF_REQUIRE_EQ(0, mesh_cfg_agg_seq_parse(msg, mlen, &elem, got,
	    MESH_CFG_AGG_MAX_ITEMS, &n));
	ATF_CHECK_EQ(ELEM, elem);
	ATF_CHECK_EQ(3, n);
	ATF_CHECK_EQ(2, got[0].len);
	ATF_CHECK_EQ(0, memcmp(got[0].data, a, 2));
	ATF_CHECK_EQ(2, got[1].len);
	ATF_CHECK_EQ(0, memcmp(got[1].data, b, 2));
	ATF_CHECK_EQ(0, got[2].len);
}

/* ================================================================
 * Large Composition Data / Models Metadata codec.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lcd_codec);
ATF_TC_BODY(lcd_codec, tc)
{
	struct mesh_cfg_lcd_get get, gg;
	struct mesh_cfg_lcd_status st, gs;
	uint8_t msg[32];
	size_t mlen;
	uint32_t op;

	memset(&get, 0, sizeof(get));
	get.page = 0;
	get.offset = 0x0010;
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_get_build(BT_MCFG11_OP_LARGE_COMP_DATA_GET,
	    &get, msg, &mlen));
	ATF_CHECK_EQ(5, mlen);
	check_opcode(msg, BT_MCFG11_OP_LARGE_COMP_DATA_GET);
	ATF_CHECK_EQ(0x00, msg[2]);
	ATF_CHECK_EQ(0x10, msg[3]);		/* offset LE */
	ATF_CHECK_EQ(0x00, msg[4]);
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_get_parse(msg, mlen, &op, &gg));
	ATF_CHECK_EQ(BT_MCFG11_OP_LARGE_COMP_DATA_GET, op);
	ATF_CHECK_EQ(0, gg.page);
	ATF_CHECK_EQ(0x0010, gg.offset);

	memset(&st, 0, sizeof(st));
	st.page = 0;
	st.offset = 0x0010;
	st.total_size = 0x0040;
	st.data[0] = 0xAA;
	st.data[1] = 0xBB;
	st.data_len = 2;
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_status_build(
	    BT_MCFG11_OP_LARGE_COMP_DATA_STATUS, &st, msg, &mlen));
	ATF_CHECK_EQ(9, mlen);
	check_opcode(msg, BT_MCFG11_OP_LARGE_COMP_DATA_STATUS);
	ATF_CHECK_EQ(0x00, msg[2]);
	ATF_CHECK_EQ(0x10, msg[3]);
	ATF_CHECK_EQ(0x00, msg[4]);
	ATF_CHECK_EQ(0x40, msg[5]);		/* total size LE */
	ATF_CHECK_EQ(0x00, msg[6]);
	ATF_CHECK_EQ(0xAA, msg[7]);
	ATF_CHECK_EQ(0xBB, msg[8]);
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_status_parse(msg, mlen, &op, &gs));
	ATF_CHECK_EQ(0x0040, gs.total_size);
	ATF_CHECK_EQ(2, gs.data_len);
	ATF_CHECK_EQ(0xAA, gs.data[0]);
}

/* ================================================================
 * Config Server: SAR Transmitter Get -> Set -> Get round-trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_sar_tx_roundtrip);
ATF_TC_BODY(srv_sar_tx_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_sar_transmitter tx, got;
	uint8_t msg[16], reply[32];
	size_t mlen, rlen;

	init_node(nd);

	/* Get: default state is all-zero. */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(6, rlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, NULL, &got));
	ATF_CHECK_EQ(0, got.seg_interval_step);

	/* Set new values. */
	memset(&tx, 0, sizeof(tx));
	tx.seg_interval_step = 0x2;
	tx.unicast_retrans_count = 0x3;
	tx.multicast_retrans_count = 0x7;
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(BT_MCFG11_OP_SAR_TRANSMITTER_SET,
	    &tx, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, NULL, &got));
	ATF_CHECK_EQ(0, memcmp(&tx, &got, sizeof(tx)));

	/* Get again returns the stored values. */
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(reply, rlen, NULL, &got));
	ATF_CHECK_EQ(0x2, got.seg_interval_step);
	ATF_CHECK_EQ(0x3, got.unicast_retrans_count);
	ATF_CHECK_EQ(0x7, got.multicast_retrans_count);
}

/* ================================================================
 * Config Server: SAR Receiver Get -> Set -> Get round-trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_sar_rx_roundtrip);
ATF_TC_BODY(srv_sar_rx_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_sar_receiver rx, got;
	uint8_t msg[16], reply[32];
	size_t mlen, rlen;

	init_node(nd);

	memset(&rx, 0, sizeof(rx));
	rx.segments_threshold = 0x0A;
	rx.ack_delay_increment = 0x3;
	rx.discard_timeout = 0x5;
	rx.rx_segment_interval_step = 0x2;
	rx.ack_retrans_count = 0x1;
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET, &rx,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(5, rlen);
	check_opcode(reply, BT_MCFG11_OP_SAR_RECEIVER_STATUS);

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(reply, rlen, NULL, &got));
	ATF_CHECK_EQ(0, memcmp(&rx, &got, sizeof(rx)));
}

/* ================================================================
 * Config Server: On-Demand Private Proxy + Private Beacon + Private GATT
 * Proxy round-trips (each stateful node-wide octet).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_private_states_roundtrip);
ATF_TC_BODY(srv_private_states_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_priv_beacon pb;
	uint8_t msg[8], reply[16], v;
	size_t mlen, rlen;
	uint32_t op;

	init_node(nd);

	/* On-Demand Private Proxy: Set 0x0A, Get returns 0x0A. */
	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_build(
	    BT_MCFG11_OP_OD_PRIV_PROXY_SET, 0x0A, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	check_opcode(reply, BT_MCFG11_OP_OD_PRIV_PROXY_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_od_priv_proxy_parse(reply, rlen, &op, &v));
	ATF_CHECK_EQ(0x0A, v);

	/* Private Beacon: Set on + random steps, Get returns both. */
	memset(&pb, 0, sizeof(pb));
	pb.private_beacon = 1;
	pb.random_update_interval_steps = 0x14;
	pb.has_random_update = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_set_build(&pb, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	check_opcode(reply, BT_MCFG11_OP_PRIV_BEACON_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_beacon_status_parse(reply, rlen, &pb));
	ATF_CHECK_EQ(1, pb.private_beacon);
	ATF_CHECK_EQ(0x14, pb.random_update_interval_steps);

	/* Private GATT Proxy: Set on, Get returns on. */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_gatt_proxy_build(
	    BT_MCFG11_OP_PRIV_GATT_PROXY_SET, 0x01, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_gatt_proxy_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_gatt_proxy_parse(reply, rlen, &op, &v));
	ATF_CHECK_EQ(0x01, v);
}

/* ================================================================
 * Config Server: Private Node Identity per-subnet Get -> Set -> Get, plus
 * the invalid-NetKey-index Status path.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_priv_node_identity_roundtrip);
ATF_TC_BODY(srv_priv_node_identity_roundtrip, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_priv_node_identity id, got;
	uint8_t msg[8], reply[16], status;
	size_t mlen, rlen;

	init_node(nd);

	/* Get on the primary subnet (index 0): Success, Stopped. */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_get_build(0x000, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ(BT_MCFG11_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(BT_MCFG11_PRIV_ID_STOPPED, got.identity);

	/* Set Running, Get returns Running. */
	memset(&id, 0, sizeof(id));
	id.net_idx = 0x000;
	id.identity = BT_MCFG11_PRIV_ID_RUNNING;
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_set_build(&id, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ(BT_MCFG11_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(BT_MCFG11_PRIV_ID_RUNNING, got.identity);

	/* An unknown NetKey index reports Invalid NetKey Index. */
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_get_build(0x0AB, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_priv_node_identity_status_parse(reply, rlen,
	    &status, &got));
	ATF_CHECK_EQ(BT_MCFG11_STATUS_INVALID_NETKEY_INDEX, status);
}

/* ================================================================
 * Config Server: Solicitation PDU RPL Items Clear echoes the range in a
 * Status; the unacknowledged variant produces no reply.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_sol_pdu_rpl);
ATF_TC_BODY(srv_sol_pdu_rpl, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_addr_range r, got;
	uint8_t msg[8], reply[16];
	size_t mlen, rlen;

	init_node(nd);

	memset(&r, 0, sizeof(r));
	r.range_start = 0x0200;
	r.range_length = 4;
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR, &r, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	check_opcode(reply, BT_MCFG11_OP_SOL_RPL_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_parse(reply, rlen, &got));
	ATF_CHECK_EQ(0x0200, got.range_start);
	ATF_CHECK_EQ(4, got.range_length);

	/* Unacknowledged Clear: handled, no Status reply (rc == 0). */
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR_UNACK, &r, msg, &mlen));
	rlen = 0xdead;
	ATF_CHECK_EQ(0, meshd_foundation_recv(nd, msg, mlen, reply,
	    sizeof(reply), &rlen));
}

/* ================================================================
 * Config Server: Large Composition Data Get returns an offset-addressed
 * page slice with the total size; Models Metadata Get returns an empty page.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_large_comp_data);
ATF_TC_BODY(srv_large_comp_data, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_lcd_get get;
	struct mesh_cfg_lcd_status st;
	uint8_t msg[8], reply[MESH_ACCESS_PAYLOAD_MAX];
	size_t mlen, rlen;

	init_node(nd);

	/* Large Composition Data Get, page 0, offset 0. */
	memset(&get, 0, sizeof(get));
	get.page = 0;
	get.offset = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_get_build(BT_MCFG11_OP_LARGE_COMP_DATA_GET,
	    &get, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	check_opcode(reply, BT_MCFG11_OP_LARGE_COMP_DATA_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_status_parse(reply, rlen, NULL, &st));
	ATF_CHECK_EQ(0, st.page);
	ATF_CHECK_EQ(0, st.offset);
	ATF_CHECK(st.total_size > 0);
	ATF_CHECK(st.data_len > 0);
	ATF_CHECK_EQ((uint16_t)st.total_size, st.total_size);

	/* Get from an offset past the end returns the total size and no data. */
	get.offset = st.total_size;
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_get_build(BT_MCFG11_OP_LARGE_COMP_DATA_GET,
	    &get, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_status_parse(reply, rlen, NULL, &st));
	ATF_CHECK_EQ(0, st.data_len);

	/* Models Metadata Get: an empty metadata page (total size 0). */
	memset(&get, 0, sizeof(get));
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_get_build(BT_MCFG11_OP_MODELS_METADATA_GET,
	    &get, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	check_opcode(reply, BT_MCFG11_OP_MODELS_METADATA_STATUS);
	ATF_REQUIRE_EQ(0, mesh_cfg_lcd_status_parse(reply, rlen, NULL, &st));
	ATF_CHECK_EQ(0, st.total_size);
	ATF_CHECK_EQ(0, st.data_len);
}

/* ================================================================
 * Config Server: an Opcodes Aggregator Sequence batching a SAR Transmitter
 * Get and a Default TTL Get returns an Aggregator Status whose items are the
 * two Status responses.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_aggregator);
ATF_TC_BODY(srv_aggregator, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_agg_item items[2], got[MESH_CFG_AGG_MAX_ITEMS];
	uint8_t sar_get[8], ttl_get[8];
	uint8_t msg[64], reply[128];
	size_t sar_len, ttl_len, mlen, rlen, n;
	uint16_t elem;
	uint8_t status;

	init_node(nd);

	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_get_build(sar_get, &sar_len));
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(MESH_CFG_OP_DEFAULT_TTL_GET, ttl_get,
	    &ttl_len));
	items[0].data = sar_get;
	items[0].len = sar_len;
	items[1].data = ttl_get;
	items[1].len = ttl_len;
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_seq_build(ELEM, items, 2, msg, &mlen));

	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_status_parse(reply, rlen, &status, &elem,
	    got, MESH_CFG_AGG_MAX_ITEMS, &n));
	ATF_CHECK_EQ(BT_MCFG11_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(ELEM, elem);
	ATF_REQUIRE_EQ(2, n);

	/* Item 0 is a SAR Transmitter Status (6 octets: opcode + 4 params). */
	ATF_CHECK_EQ(6, got[0].len);
	check_opcode(got[0].data, BT_MCFG11_OP_SAR_TRANSMITTER_STATUS);
	/* Item 1 is a Default TTL Status (3 octets) reporting the default TTL 7. */
	ATF_CHECK_EQ(3, got[1].len);
	check_opcode(got[1].data, MESH_CFG_OP_DEFAULT_TTL_STATUS);
	ATF_CHECK_EQ(7, got[1].data[2]);
}

ATF_TC_WITHOUT_HEAD(codec_guard_completion);
ATF_TC_BODY(codec_guard_completion, tc)
{
	struct mesh_cfg_sar_transmitter tx;
	struct mesh_cfg_sar_receiver rx;
	struct mesh_cfg_addr_range range;
	struct mesh_cfg_agg_item item, items[MESH_CFG_AGG_MAX_ITEMS];
	struct mesh_cfg_lcd_get get;
	struct mesh_cfg_lcd_status lcd;
	struct mesh_cfg_priv_beacon beacon;
	struct mesh_cfg_priv_node_identity identity;
	uint8_t buf[MESH_ACCESS_PAYLOAD_MAX] = { 0 }, value, status;
	uint16_t elem, net_idx;
	uint32_t opcode;
	size_t len, prefix, n;

	memset(&tx, 0, sizeof(tx));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_build(0, &tx, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_build(BT_MCFG11_OP_SAR_TRANSMITTER_SET,
	    NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(NULL, 0, &opcode, &tx));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_tx_parse(buf, 0, &opcode, NULL));
	memset(&rx, 0, sizeof(rx));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_build(0, &rx, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET,
	    NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(NULL, 0, &opcode, &rx));
	ATF_CHECK_EQ(-1, mesh_cfg_sar_rx_parse(buf, 0, &opcode, NULL));

	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_build(0, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_od_priv_proxy_parse(NULL, 0, &opcode, &value));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_gatt_proxy_build(0, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_gatt_proxy_parse(NULL, 0, &opcode,
	    &value));

	memset(&range, 0, sizeof(range));
	range.range_start = 1;
	range.range_length = 1;
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_clear_build(0, &range, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_clear_build(
	    BT_MCFG11_OP_SOL_RPL_CLEAR, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_clear_parse(NULL, 0, &opcode,
	    &range));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_clear_parse(buf, 0, &opcode,
	    NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_parse(NULL, 0, &range));
	ATF_CHECK_EQ(-1, mesh_cfg_sol_pdu_rpl_status_parse(buf, 0, NULL));

	ATF_CHECK_EQ(-1, mesh_cfg_agg_len_encode(1, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_len_encode(0x8000, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_len_decode(NULL, 0, &len, &prefix));
	buf[0] = 1;
	ATF_CHECK_EQ(-1, mesh_cfg_agg_len_decode(buf, 1, &len, &prefix));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_seq_build(1, NULL, 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_seq_build(1, items,
	    MESH_CFG_AGG_MAX_ITEMS + 1, buf, &len));
	item.data = NULL;
	item.len = 1;
	ATF_CHECK_EQ(-1, mesh_cfg_agg_seq_build(1, &item, 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_seq_parse(NULL, 0, &elem, NULL, 0, &n));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_status_build(0, 1, NULL, 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_status_build(0, 1, items,
	    MESH_CFG_AGG_MAX_ITEMS + 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_agg_status_parse(NULL, 0, &status, &elem,
	    NULL, 0, &n));

	memset(&get, 0, sizeof(get));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_get_build(0, &get, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_get_build(BT_MCFG11_OP_LARGE_COMP_DATA_GET,
	    NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_get_parse(NULL, 0, &opcode, &get));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_get_parse(buf, 0, &opcode, NULL));
	memset(&lcd, 0, sizeof(lcd));
	lcd.data_len = MESH_CFG_LCD_DATA_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_status_build(
	    BT_MCFG11_OP_LARGE_COMP_DATA_STATUS, &lcd, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_status_build(0, &lcd, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_status_parse(NULL, 0, &opcode, &lcd));
	ATF_CHECK_EQ(-1, mesh_cfg_lcd_status_parse(buf, 0, &opcode, NULL));

	memset(&beacon, 0, sizeof(beacon));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_set_parse(NULL, 0, &beacon));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_set_parse(buf, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_status_parse(NULL, 0, &beacon));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_beacon_status_parse(buf, 0, NULL));
	memset(&identity, 0, sizeof(identity));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_get_parse(NULL, 0,
	    &net_idx));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_set_parse(NULL, 0,
	    &identity));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_set_parse(buf, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_status_build(0, NULL, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_status_parse(NULL, 0,
	    &status, &identity));
	ATF_CHECK_EQ(-1, mesh_cfg_priv_node_identity_status_parse(buf, 0,
	    &status, NULL));
}

/* Exact field endpoints and RFU receive behavior from MshPRT 1.1. */
ATF_TC_WITHOUT_HEAD(normative_boundary_matrix);
ATF_TC_BODY(normative_boundary_matrix, tc)
{
	struct mesh_cfg_sar_transmitter tx, tx_got;
	struct mesh_cfg_sar_receiver rx, rx_got;
	struct mesh_cfg_addr_range range, range_got;
	uint8_t params[4], msg[16], prefix[2];
	size_t len, prefix_len;

	/* §§4.2.29-.30: every packed subfield accepts its all-ones value. */
	memset(&tx, 0x0f, sizeof(tx));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_build(
	    BT_MCFG11_OP_SAR_TRANSMITTER_SET, &tx, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(msg, len, NULL, &tx_got));
	ATF_CHECK_EQ(0, memcmp(&tx, &tx_got, sizeof(tx)));
	memset(&rx, 0, sizeof(rx));
	rx.segments_threshold = 0x1f;
	rx.ack_delay_increment = 0x07;
	rx.discard_timeout = 0x0f;
	rx.rx_segment_interval_step = 0x0f;
	rx.ack_retrans_count = 0x03;
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_build(BT_MCFG11_OP_SAR_RECEIVER_SET,
	    &rx, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(msg, len, NULL, &rx_got));
	ATF_CHECK_EQ(0, memcmp(&rx, &rx_got, sizeof(rx)));

	/* §1.3.2: receivers ignore, rather than reject, RFU bits. */
	params[0] = params[1] = params[2] = 0;
	params[3] = 0xf6;
	len = sizeof(msg);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    BT_MCFG11_OP_SAR_TRANSMITTER_STATUS, params, 4, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_tx_parse(msg, len, NULL, &tx_got));
	ATF_CHECK_EQ(6, tx_got.multicast_retrans_interval_step);
	params[0] = params[1] = 0;
	params[2] = 0xff;
	len = sizeof(msg);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(BT_MCFG11_OP_SAR_RECEIVER_STATUS,
	    params, 3, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_sar_rx_parse(msg, len, NULL, &rx_got));
	ATF_CHECK_EQ(3, rx_got.ack_retrans_count);

	/* §4.3.9.1: exact short/long length prefix transition and maximum. */
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_encode(BT_MCFG11_AGG_SHORT_MAX,
	    prefix, &prefix_len));
	ATF_CHECK_EQ(1, prefix_len);
	ATF_CHECK_EQ(0xfe, prefix[0]);
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_encode(
	    BT_MCFG11_AGG_SHORT_MAX + 1, prefix, &prefix_len));
	ATF_CHECK_EQ(2, prefix_len);
	ATF_CHECK_EQ(0x01, prefix[0]);
	ATF_CHECK_EQ(0x01, prefix[1]);
	ATF_REQUIRE_EQ(0, mesh_cfg_agg_len_encode(BT_MCFG11_AGG_LONG_MAX,
	    prefix, &prefix_len));
	ATF_CHECK_EQ(0xff, prefix[0]);
	ATF_CHECK_EQ(0xff, prefix[1]);
	ATF_CHECK_EQ(-1, mesh_cfg_agg_len_encode(
	    BT_MCFG11_AGG_LONG_MAX + 1, prefix, &prefix_len));

	/* §3.4.2.2.1: both unicast Address Range endpoints are valid. */
	range.range_start = BT_MCFG11_UNICAST_MAX;
	range.range_length = BT_MCFG11_RANGE_LENGTH_MIN;
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_build(&range, msg, &len));
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_parse(msg, len,
	    &range_got));
	ATF_CHECK_EQ(BT_MCFG11_UNICAST_MAX, range_got.range_start);
	range.range_start = BT_MCFG11_UNICAST_MIN;
	ATF_REQUIRE_EQ(0, mesh_cfg_sol_pdu_rpl_status_build(&range, msg, &len));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sar_tx_codec);
	ATF_TP_ADD_TC(tp, sar_rx_codec);
	ATF_TP_ADD_TC(tp, od_priv_proxy_codec);
	ATF_TP_ADD_TC(tp, priv_beacon_codec);
	ATF_TP_ADD_TC(tp, priv_node_identity_codec);
	ATF_TP_ADD_TC(tp, sol_pdu_rpl_codec);
	ATF_TP_ADD_TC(tp, aggregator_codec);
	ATF_TP_ADD_TC(tp, lcd_codec);
	ATF_TP_ADD_TC(tp, foundation_opcode_length_matrix);
	ATF_TP_ADD_TC(tp, srv_sar_tx_roundtrip);
	ATF_TP_ADD_TC(tp, srv_sar_rx_roundtrip);
	ATF_TP_ADD_TC(tp, srv_private_states_roundtrip);
	ATF_TP_ADD_TC(tp, srv_priv_node_identity_roundtrip);
	ATF_TP_ADD_TC(tp, srv_sol_pdu_rpl);
	ATF_TP_ADD_TC(tp, srv_large_comp_data);
	ATF_TP_ADD_TC(tp, srv_aggregator);
	ATF_TP_ADD_TC(tp, codec_guard_completion);
	ATF_TP_ADD_TC(tp, normative_boundary_matrix);

	return (atf_no_error());
}
