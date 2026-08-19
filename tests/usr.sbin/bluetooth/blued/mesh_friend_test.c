/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for Bluetooth Mesh Friendship (mesh_friend.[ch], MshPRT_v1.1
 * Section 3.6.6).
 *
 * FRIENDSHIP CREDENTIAL KAT.  The friendship security material is the worked
 * example of MshPRT_v1.1 Section 8.2.3 "EncryptionKey and PrivacyKey
 * (friendship)":
 *
 *   NetKey N     = 7dd7364cd842ad18c17c2b820c84c3d6
 *   LPNAddress   = 1201   FriendAddress = 2345
 *   LPNCounter   = 0000   FriendCounter = 072f
 *   k2 P         = 01 1201 2345 0000 072f
 *   NID          = 5e
 *   EncryptionKey= be635105434859f484fc798e043ce40e
 *   PrivacyKey   = 5d396d4b54d3cbafe943e051fe9a4eb8
 *
 * These NID/EncryptionKey/PrivacyKey bytes are the published Section 8.2.3
 * values; they were reproduced independently with a from-scratch Python
 * AES-CMAC/k2 implementation (every intermediate s1/T/T1/T2/T3 matched the
 * Section 8.2.3 table) before being committed here, so a passing test confirms
 * the module against the spec bytes, not against itself.
 *
 * CONTROL MESSAGE CODECS.  The Friend* message byte vectors are derived octet
 * by octet from the Section 3.6.5 field tables (Tables 3.28-3.46) and the
 * Transport Control opcodes; each vector carries a per-octet derivation in its
 * comment.
 *
 * FRIEND OFFER DELAY.  The expected millisecond values are hand-computed from
 * the Section 3.6.6.3.1 formula (Local Delay = ReceiveWindowFactor*ReceiveWindow
 * - RSSIFactor*RSSI, floored at 100 ms) using the Table 3.34/3.35 factor
 * values, independent of the implementation.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_friend.h"
#include "spec_mesh_friend_oracles.h"

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
 * 1. Friendship credential KAT (Section 8.2.3).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(friend_credentials_kat);
ATF_TC_BODY(friend_credentials_kat, tc)
{
	HEX(netkey, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	HEX(exp_enc, "be635105434859f484fc798e043ce40e", 16);
	HEX(exp_priv, "5d396d4b54d3cbafe943e051fe9a4eb8", 16);
	uint8_t nid, enc[16], priv[16];

	ATF_REQUIRE_EQ(0, mesh_friend_credentials(netkey, 0x1201, 0x2345,
	    0x0000, 0x072f, &nid, enc, priv));
	ATF_CHECK_EQ_MSG(nid, 0x5e, "friendship NID %02x != 5e (8.2.3)", nid);
	ATF_CHECK_EQ_MSG(0, memcmp(enc, exp_enc, 16),
	    "friendship EncryptionKey mismatch (8.2.3)");
	ATF_CHECK_EQ_MSG(0, memcmp(priv, exp_priv, 16),
	    "friendship PrivacyKey mismatch (8.2.3)");
}

ATF_TC_WITHOUT_HEAD(friend_p_input_kat);
ATF_TC_BODY(friend_p_input_kat, tc)
{
	HEX(exp_p, "01120123450000072f", 9);
	uint8_t p[BT_MESH11_FRIEND_K2_P_SIZE];

	/* k2 P = 0x01 || LPNAddress || FriendAddress || LPNCounter || FriendCounter. */
	ATF_REQUIRE_EQ(0, mesh_friend_p_input(0x1201, 0x2345, 0x0000, 0x072f, p));
	ATF_CHECK_EQ(0, memcmp(p, exp_p, 9));
}

ATF_TC_WITHOUT_HEAD(friend_credentials_null);
ATF_TC_BODY(friend_credentials_null, tc)
{
	uint8_t nid, enc[16], priv[16];

	ATF_CHECK_EQ(-1, mesh_friend_credentials(NULL, 0x1201, 0x2345, 0, 0,
	    &nid, enc, priv));
}

/* ================================================================
 * 2. Control message codecs (Section 3.6.5).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(friend_poll_codec);
ATF_TC_BODY(friend_poll_codec, tc)
{
	struct mesh_friend_poll in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;

	/* op 0x01, octet1 = Padding(0b0000000)|FSN.  FSN=1 -> 0101. */
	memset(&in, 0, sizeof(in));
	in.fsn = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&in, buf, &len));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_POLL_PDU_SIZE, len);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_POLL, buf[0]);
	ATF_CHECK_EQ(0x01, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_friend_poll_parse(buf, len, &out));
	ATF_CHECK_EQ(1, out.fsn);

	/* FSN=0 -> 0100. */
	in.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&in, buf, &len));
	ATF_CHECK_EQ(0x00, buf[1]);

	/* A non-zero Padding is rejected on parse. */
	buf[1] = 0x02;
	ATF_CHECK_EQ(-1, mesh_friend_poll_parse(buf, len, &out));
	/* Wrong opcode rejected. */
	buf[0] = 0x02; buf[1] = 0x01;
	ATF_CHECK_EQ(-1, mesh_friend_poll_parse(buf, len, &out));
}

ATF_TC_WITHOUT_HEAD(friend_update_codec);
ATF_TC_BODY(friend_update_codec, tc)
{
	struct mesh_friend_update in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	/*
	 * op 0x02 | Flags(KR=1,IVU=1 -> 0x03) | IV Index 12345678 | MD 01.
	 */
	HEX(exp, "02031234567801", BT_MESH11_FRIEND_UPDATE_PDU_SIZE);

	memset(&in, 0, sizeof(in));
	in.key_refresh = 1;
	in.iv_update = 1;
	in.iv_index = 0x12345678;
	in.md = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_update_build(&in, buf, &len));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_UPDATE_PDU_SIZE, len);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, len), "Friend Update byte layout");

	ATF_REQUIRE_EQ(0, mesh_friend_update_parse(buf, len, &out));
	ATF_CHECK_EQ(1, out.key_refresh);
	ATF_CHECK_EQ(1, out.iv_update);
	ATF_CHECK_EQ(0x12345678, out.iv_index);
	ATF_CHECK_EQ(1, out.md);

	/* Mesh 1.1 Section 1.3.2: set RFU bits are processed as zero. */
	buf[1] = 0xff;
	ATF_REQUIRE_EQ(0, mesh_friend_update_parse(buf, len, &out));
	ATF_CHECK_EQ(1, out.key_refresh);
	ATF_CHECK_EQ(1, out.iv_update);
	/* MD > 1 Prohibited. */
	hex_to_bytes(buf, "02031234567802", len);
	ATF_CHECK_EQ(-1, mesh_friend_update_parse(buf, len, &out));
}

ATF_TC_WITHOUT_HEAD(friend_request_codec);
ATF_TC_BODY(friend_request_codec, tc)
{
	struct mesh_friend_request in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	/*
	 * op 0x03 | Criteria | ReceiveDelay | PollTimeout(3) |
	 * PreviousAddress(2) | NumElements | LPNCounter(2).
	 * Criteria: RSSIFactor=0b01, RxWindowFactor=0b10, MinQSLog=0b011
	 *   -> (01<<5)|(10<<3)|011 = 0x33.
	 * ReceiveDelay 0x0A, PollTimeout 0x000064, PrevAddr 0x0000,
	 * NumElements 0x01, LPNCounter 0x0000.
	 */
	HEX(exp, "03330a0000640000010000", BT_MESH11_FRIEND_REQUEST_PDU_SIZE);

	memset(&in, 0, sizeof(in));
	in.rssi_factor = 0x01;
	in.rx_window_factor = 0x02;
	in.min_queue_size_log = 0x03;
	in.recv_delay = BT_MESH11_FRIEND_RECEIVE_DELAY_MIN_MS;
	in.poll_timeout = 0x000064;
	in.prev_addr = 0x0000;
	in.num_elements = 0x01;
	in.lpn_counter = 0x0000;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&in, buf, &len));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_REQUEST_PDU_SIZE, len);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, len), "Friend Request byte layout");
	ATF_CHECK_EQ(0x33, buf[1]);

	ATF_REQUIRE_EQ(0, mesh_friend_request_parse(buf, len, &out));
	ATF_CHECK_EQ(0x01, out.rssi_factor);
	ATF_CHECK_EQ(0x02, out.rx_window_factor);
	ATF_CHECK_EQ(0x03, out.min_queue_size_log);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_RECEIVE_DELAY_MIN_MS, out.recv_delay);
	ATF_CHECK_EQ(0x000064, out.poll_timeout);
	ATF_CHECK_EQ(0x0000, out.prev_addr);
	ATF_CHECK_EQ(0x01, out.num_elements);
	ATF_CHECK_EQ(0x0000, out.lpn_counter);

	/* NumElements 0x00 Prohibited. */
	buf[8] = 0x00;
	ATF_CHECK_EQ(-1, mesh_friend_request_parse(buf, len, &out));
	/* MinQueueSizeLog 0b000 Prohibited (Criteria low 3 bits). */
	memcpy(buf, exp, len);
	buf[1] = (uint8_t)(exp[1] & 0xf8);
	ATF_CHECK_EQ(-1, mesh_friend_request_parse(buf, len, &out));
	/* Mesh 1.1 Section 1.3.2: the Criteria RFU bit is ignored. */
	memcpy(buf, exp, len);
	buf[1] = (uint8_t)(exp[1] | 0x80);
	ATF_REQUIRE_EQ(0, mesh_friend_request_parse(buf, len, &out));
	ATF_CHECK_EQ(0x01, out.rssi_factor);
	ATF_CHECK_EQ(0x02, out.rx_window_factor);
	ATF_CHECK_EQ(0x03, out.min_queue_size_log);
}

ATF_TC_WITHOUT_HEAD(friend_offer_codec);
ATF_TC_BODY(friend_offer_codec, tc)
{
	struct mesh_friend_offer in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	/*
	 * op 0x04 | ReceiveWindow 0x14 | QueueSize 0x08 | SubListSize 0x05 |
	 * RSSI -60 = 0xC4 | FriendCounter 0x072f.
	 */
	HEX(exp, "04140805c4072f", BT_MESH11_FRIEND_OFFER_PDU_SIZE);

	memset(&in, 0, sizeof(in));
	in.recv_window = 0x14;
	in.queue_size = 0x08;
	in.sub_list_size = 0x05;
	in.rssi = -60;
	in.friend_counter = 0x072f;
	ATF_REQUIRE_EQ(0, mesh_friend_offer_build(&in, buf, &len));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OFFER_PDU_SIZE, len);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, len), "Friend Offer byte layout");

	ATF_REQUIRE_EQ(0, mesh_friend_offer_parse(buf, len, &out));
	ATF_CHECK_EQ(0x14, out.recv_window);
	ATF_CHECK_EQ(0x08, out.queue_size);
	ATF_CHECK_EQ(0x05, out.sub_list_size);
	ATF_CHECK_EQ(-60, out.rssi);		/* signed 8-bit RSSI */
	ATF_CHECK_EQ(0x072f, out.friend_counter);
}

ATF_TC_WITHOUT_HEAD(friend_clear_codec);
ATF_TC_BODY(friend_clear_codec, tc)
{
	struct mesh_friend_clear in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	uint8_t op;
	/* op 0x05 | LPNAddress 0x1201 | LPNCounter 0x0000. */
	HEX(exp_c, "0512010000", BT_MESH11_FRIEND_CLEAR_PDU_SIZE);
	HEX(exp_cc, "0612010000", BT_MESH11_FRIEND_CLEAR_CONFIRM_PDU_SIZE);

	memset(&in, 0, sizeof(in));
	in.lpn_addr = 0x1201;
	in.lpn_counter = 0x0000;
	ATF_REQUIRE_EQ(0, mesh_friend_clear_build(BT_MESH11_FRIEND_OP_CLEAR, &in,
	    buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_c, len), "Friend Clear byte layout");
	ATF_REQUIRE_EQ(0, mesh_friend_clear_parse(buf, len, &out, &op));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_CLEAR, op);
	ATF_CHECK_EQ(0x1201, out.lpn_addr);
	ATF_CHECK_EQ(0x0000, out.lpn_counter);

	/* Clear Confirm shares the layout, opcode 0x06. */
	ATF_REQUIRE_EQ(0, mesh_friend_clear_build(
	    BT_MESH11_FRIEND_OP_CLEAR_CONFIRM,
	    &in, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_cc, len),
	    "Friend Clear Confirm byte layout");
	ATF_REQUIRE_EQ(0, mesh_friend_clear_parse(buf, len, &out, &op));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_CLEAR_CONFIRM, op);

	/* A non-clear opcode is rejected. */
	ATF_CHECK_EQ(-1, mesh_friend_clear_build(0x07, &in, buf, &len));
}

ATF_TC_WITHOUT_HEAD(friend_sublist_codec);
ATF_TC_BODY(friend_sublist_codec, tc)
{
	struct mesh_friend_sublist in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	uint8_t op;
	/* op 0x07 | Transaction 0x00 | AddressList c000 c001. */
	HEX(exp_add, "0700c000c001", 6);
	HEX(exp_rem, "0800c000c001", 6);

	memset(&in, 0, sizeof(in));
	in.transaction = 0x00;
	in.addrs[0] = 0xc000;
	in.addrs[1] = 0xc001;
	in.naddr = 2;
	ATF_REQUIRE_EQ(0, mesh_friend_sublist_build(BT_MESH11_FRIEND_OP_SUBLIST_ADD,
	    &in, buf, &len));
	ATF_CHECK_EQ(6, len);
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_add, len),
	    "Friend Subscription List Add byte layout");
	ATF_REQUIRE_EQ(0, mesh_friend_sublist_parse(buf, len, &out, &op));
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_SUBLIST_ADD, op);
	ATF_CHECK_EQ(2, out.naddr);
	ATF_CHECK_EQ(0xc000, out.addrs[0]);
	ATF_CHECK_EQ(0xc001, out.addrs[1]);

	ATF_REQUIRE_EQ(0, mesh_friend_sublist_build(
	    BT_MESH11_FRIEND_OP_SUBLIST_REMOVE,
	    &in, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp_rem, len),
	    "Friend Subscription List Remove byte layout");

	/* An odd AddressList length is malformed. */
	ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(exp_add, 5, &out, &op));
	/* Empty address list rejected on build. */
	in.naddr = 0;
	ATF_CHECK_EQ(-1, mesh_friend_sublist_build(BT_MESH11_FRIEND_OP_SUBLIST_ADD,
	    &in, buf, &len));
}

ATF_TC_WITHOUT_HEAD(friend_subconfirm_codec);
ATF_TC_BODY(friend_subconfirm_codec, tc)
{
	struct mesh_friend_subconfirm in, out;
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	size_t len;
	/* op 0x09 | Transaction 0x00. */
	HEX(exp, "0900", BT_MESH11_FRIEND_SUBCONFIRM_PDU_SIZE);

	memset(&in, 0, sizeof(in));
	in.transaction = 0x00;
	ATF_REQUIRE_EQ(0, mesh_friend_subconfirm_build(&in, buf, &len));
	ATF_CHECK_EQ_MSG(0, memcmp(buf, exp, len),
	    "Friend Subscription List Confirm byte layout");
	ATF_REQUIRE_EQ(0, mesh_friend_subconfirm_parse(buf, len, &out));
	ATF_CHECK_EQ(0x00, out.transaction);
}

/* ================================================================
 * 3. Criteria helpers (Section 3.6.5.3, Tables 3.33-3.36).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(friend_criteria_pack);
ATF_TC_BODY(friend_criteria_pack, tc)
{
	uint8_t rf, rwf, mqs;

	/* RSSIFactor=0b11, RxWindowFactor=0b10, MinQSLog=0b101
	 *   -> (11<<5)|(10<<3)|101 = 0x60|0x10|0x05 = 0x75. */
	ATF_CHECK_EQ(0x75, mesh_friend_criteria_pack(0x03, 0x02, 0x05));
	mesh_friend_criteria_unpack(0x75, &rf, &rwf, &mqs);
	ATF_CHECK_EQ(0x03, rf);
	ATF_CHECK_EQ(0x02, rwf);
	ATF_CHECK_EQ(0x05, mqs);
}

ATF_TC_WITHOUT_HEAD(friend_min_queue_size);
ATF_TC_BODY(friend_min_queue_size, tc)
{

	/* Table 3.36: N = 2^log; 0b000 Prohibited (return 0). */
	ATF_CHECK_EQ(0, mesh_friend_min_queue_size(0));
	ATF_CHECK_EQ(2, mesh_friend_min_queue_size(1));
	ATF_CHECK_EQ(4, mesh_friend_min_queue_size(2));
	ATF_CHECK_EQ(8, mesh_friend_min_queue_size(3));
	ATF_CHECK_EQ(16, mesh_friend_min_queue_size(4));
	ATF_CHECK_EQ(128, mesh_friend_min_queue_size(7));
}

ATF_TC_WITHOUT_HEAD(friend_factor_x2);
ATF_TC_BODY(friend_factor_x2, tc)
{

	/* Table 3.34/3.35: 0->1.0, 1->1.5, 2->2.0, 3->2.5 (doubled). */
	ATF_CHECK_EQ(2, mesh_friend_factor_x2(0));
	ATF_CHECK_EQ(3, mesh_friend_factor_x2(1));
	ATF_CHECK_EQ(4, mesh_friend_factor_x2(2));
	ATF_CHECK_EQ(5, mesh_friend_factor_x2(3));
}

ATF_TC_WITHOUT_HEAD(friend_offer_delay);
ATF_TC_BODY(friend_offer_delay, tc)
{

	/*
	 * Section 3.6.6.3.1: Local Delay = RWF*RxWin - RSSIF*RSSI, floored 100.
	 * A: RWF=2.0,RSSIF=2.0,RxWin=20,RSSI=-60 -> 40+120=160 (>100) -> 160.
	 * B: RWF=1.5,RSSIF=1.0,RxWin=10,RSSI=-20 -> 15+20=35 (<=100) -> 100.
	 * C: RWF=2.5,RSSIF=1.5,RxWin=100,RSSI=-50 -> 250+75=325 -> 325.
	 * D: RWF=1.0,RSSIF=2.5,RxWin=200,RSSI=50  -> 200-125=75 -> 100.
	 */
	ATF_CHECK_EQ(160, mesh_friend_offer_delay(0x02, 0x02, 20, -60));
	ATF_CHECK_EQ(100, mesh_friend_offer_delay(0x00, 0x01, 10, -20));
	ATF_CHECK_EQ(325, mesh_friend_offer_delay(0x01, 0x03, 100, -50));
	ATF_CHECK_EQ(100, mesh_friend_offer_delay(0x03, 0x00, 200, 50));
}

/* ================================================================
 * 4. Friend Subscription List state (Section 3.6.6.3.3).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(friend_sublist_state);
ATF_TC_BODY(friend_sublist_state, tc)
{
	struct mesh_friend_sublist_state s;

	mesh_friend_sub_init(&s);
	ATF_CHECK_EQ(0, mesh_friend_sub_contains(&s, 0xc000));
	ATF_CHECK_EQ(1, mesh_friend_sub_add(&s, 0xc000));
	ATF_CHECK_EQ(1, mesh_friend_sub_add(&s, 0xc001));
	ATF_CHECK_EQ(0, mesh_friend_sub_add(&s, 0xc000));	/* dup */
	ATF_CHECK_EQ(1, mesh_friend_sub_contains(&s, 0xc000));
	ATF_CHECK_EQ(2, (int)s.n);
	ATF_CHECK_EQ(1, mesh_friend_sub_remove(&s, 0xc000));
	ATF_CHECK_EQ(0, mesh_friend_sub_contains(&s, 0xc000));
	ATF_CHECK_EQ(1, mesh_friend_sub_contains(&s, 0xc001));
	ATF_CHECK_EQ(0, mesh_friend_sub_remove(&s, 0xc000));	/* absent */
	ATF_CHECK_EQ(1, (int)s.n);
}

/* ================================================================
 * 5. Friend Queue (Section 3.5.5 / 3.6.6.4).
 * ================================================================ */

/* Build a plausible queue entry addressed to dst from src at ttl/seq. */
static struct mesh_fq_entry
mkentry(uint16_t src, uint16_t dst, uint8_t ttl, uint32_t seq, uint8_t tag)
{
	struct mesh_fq_entry e;

	memset(&e, 0, sizeof(e));
	e.ctl = 0;
	e.ttl = ttl;
	e.seq = seq;
	e.src = src;
	e.dst = dst;
	e.pdu[0] = tag;
	e.pdu_len = 1;
	return (e);
}

ATF_TC_WITHOUT_HEAD(fq_enqueue_filter);
ATF_TC_BODY(fq_enqueue_filter, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e;

	/* LPN primary 0x0002, 1 element. */
	mesh_fq_init(&q, 0x0002, 1, 8);

	/* Destined to the LPN element, TTL 5 -> stored (TTL decremented). */
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(1, (int)mesh_fq_count(&q));

	/* Not addressed to the LPN and not in the sub list -> dropped. */
	e = mkentry(0x1234, 0x0009, 5, 101, 'b');
	ATF_CHECK_EQ(0, mesh_fq_enqueue(&q, &e));

	/* TTL 1 -> below threshold -> dropped. */
	e = mkentry(0x1234, 0x0002, 1, 102, 'c');
	ATF_CHECK_EQ(0, mesh_fq_enqueue(&q, &e));

	/* SRC is the LPN's own element -> not queued. */
	e = mkentry(0x0002, 0x0002, 5, 103, 'd');
	ATF_CHECK_EQ(0, mesh_fq_enqueue(&q, &e));

	/* A subscription-list group address is accepted after subscribe. */
	ATF_CHECK_EQ(1, mesh_friend_sub_add(&q.sub, 0xc000));
	e = mkentry(0x1234, 0xc000, 5, 104, 'e');
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));
}

ATF_TC_WITHOUT_HEAD(fq_enqueue_ttl_decrement);
ATF_TC_BODY(fq_enqueue_ttl_decrement, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	mesh_fq_init(&q, 0x0002, 1, 8);
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	/* Delivered entry has TTL 5 - 1 = 4 (Section 3.5.5). */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(4, out.ttl);
	ATF_CHECK_EQ(100, out.seq);
}

ATF_TC_WITHOUT_HEAD(fq_enqueue_dedup);
ATF_TC_BODY(fq_enqueue_dedup, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e;

	mesh_fq_init(&q, 0x0002, 1, 8);
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	/* Same (SEQ, SRC) -> not stored again. */
	e = mkentry(0x1234, 0x0002, 4, 100, 'b');
	ATF_CHECK_EQ(0, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(1, (int)mesh_fq_count(&q));
	/* Different SEQ from same SRC -> stored. */
	e = mkentry(0x1234, 0x0002, 5, 101, 'c');
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));
}

ATF_TC_WITHOUT_HEAD(fq_bound_evicts_oldest);
ATF_TC_BODY(fq_bound_evicts_oldest, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	/* Capacity 2. */
	mesh_fq_init(&q, 0x0002, 1, 2);
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	e = mkentry(0x1234, 0x0002, 5, 101, 'b');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	/* Full: a third message evicts the oldest (seq 100). */
	e = mkentry(0x1234, 0x0002, 5, 102, 'c');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));
	/* Oldest surviving entry is now seq 101. */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(101, out.seq);
}

ATF_TC_WITHOUT_HEAD(fq_update_evict_protected);
ATF_TC_BODY(fq_update_evict_protected, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	mesh_fq_init(&q, 0x0002, 1, 2);
	/* A Friend Update is enqueued first (evict-protected). */
	e = mkentry(0x0002, 0x0002, 0, 1, 'U');
	e.is_update = 1;
	ATF_REQUIRE_EQ(0, mesh_fq_enqueue_update(&q, &e));
	/* Then a normal message. */
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	/* Full: a new message evicts the normal one, NOT the Update. */
	e = mkentry(0x1234, 0x0002, 5, 101, 'b');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	/* The Update (oldest, tag 'U') is still delivered first. */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ('U', out.pdu[0]);
	ATF_CHECK_EQ(1, out.is_update);
}

ATF_TC_WITHOUT_HEAD(fq_fsn_delivery_order);
ATF_TC_BODY(fq_fsn_delivery_order, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	mesh_fq_init(&q, 0x0002, 1, 8);
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	e = mkentry(0x1234, 0x0002, 5, 101, 'b');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));

	/* First Poll (FSN 0): head = seq 100, not yet discarded. */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(100, out.seq);
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));

	/* Repeat Poll with SAME FSN (lost response): resend seq 100. */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(100, out.seq);
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));

	/* Poll with TOGGLED FSN (ack): discard seq 100, deliver seq 101. */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 1, NULL, &out));
	ATF_CHECK_EQ(101, out.seq);
	ATF_CHECK_EQ(1, (int)mesh_fq_count(&q));

	/* Toggle again: discard seq 101, queue now empty. */
	ATF_CHECK_EQ(0, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(0, (int)mesh_fq_count(&q));
}

ATF_TC_WITHOUT_HEAD(fq_empty_poll_synthesizes_update);
ATF_TC_BODY(fq_empty_poll_synthesizes_update, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry upd, out;

	mesh_fq_init(&q, 0x0002, 1, 8);
	/* Empty queue + Poll with a supplied Friend Update -> that Update is
	 * enqueued and returned (Section 3.5.5). */
	upd = mkentry(0x0002, 0x0002, 0, 1, 'U');
	upd.is_update = 1;
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, &upd, &out));
	ATF_CHECK_EQ('U', out.pdu[0]);
	ATF_CHECK_EQ(1, out.is_update);

	/* Empty queue + no supplied Update -> nothing to send. */
	mesh_fq_init(&q, 0x0002, 1, 8);
	ATF_CHECK_EQ(0, mesh_fq_poll(&q, 0, NULL, &out));
}

/* ================================================================
 * 6. LPN cadence (Section 3.6.6.4).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(lpn_init_range);
ATF_TC_BODY(lpn_init_range, tc)
{
	struct mesh_lpn_state st;

	/* PollTimeout below the Table 3.38 minimum is Prohibited. */
	ATF_CHECK_EQ(-1, mesh_lpn_init(&st, 0x000009, 0));
	/* Above the maximum is Prohibited. */
	ATF_CHECK_EQ(-1, mesh_lpn_init(&st, 0x34BC00, 0));
	/* A valid PollTimeout (0x0000A0 * 100 ms = 16 s). */
	ATF_REQUIRE_EQ(0, mesh_lpn_init(&st, 0x0000A0, 1000));
	ATF_CHECK_EQ(0, mesh_lpn_poll_fsn(&st));
	ATF_CHECK_EQ((uint64_t)0x0000A0 * 100, mesh_lpn_poll_timeout_ms(&st));
}

ATF_TC_WITHOUT_HEAD(lpn_fsn_toggle);
ATF_TC_BODY(lpn_fsn_toggle, tc)
{
	struct mesh_lpn_state st;

	ATF_REQUIRE_EQ(0, mesh_lpn_init(&st, 0x0000A0, 0));
	ATF_CHECK_EQ(0, mesh_lpn_poll_fsn(&st));
	/* Non-duplicate response toggles the FSN (Section 3.6.6.4.2). */
	ATF_CHECK_EQ(1, mesh_lpn_on_response(&st, 0, 100));
	ATF_CHECK_EQ(1, mesh_lpn_poll_fsn(&st));
	/* Duplicate response does NOT toggle. */
	ATF_CHECK_EQ(1, mesh_lpn_on_response(&st, 1, 200));
	ATF_CHECK_EQ(1, mesh_lpn_poll_fsn(&st));
	/* Another non-duplicate toggles back to 0. */
	ATF_CHECK_EQ(0, mesh_lpn_on_response(&st, 0, 300));
	ATF_CHECK_EQ(0, mesh_lpn_poll_fsn(&st));
}

ATF_TC_WITHOUT_HEAD(lpn_friendship_lost);
ATF_TC_BODY(lpn_friendship_lost, tc)
{
	struct mesh_lpn_state st;
	uint64_t to_ms;

	/* PollTimeout 0x0000A0 * 100 ms = 16000 ms, starting at t=1000. */
	ATF_REQUIRE_EQ(0, mesh_lpn_init(&st, 0x0000A0, 1000));
	to_ms = mesh_lpn_poll_timeout_ms(&st);
	ATF_CHECK_EQ(16000, to_ms);
	/* Before the timeout expires -> not lost. */
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&st, 1000 + to_ms - 1));
	/* At/after the timeout -> lost. */
	ATF_CHECK_EQ(1, mesh_lpn_friendship_lost(&st, 1000 + to_ms));
	/* A successful Poll resets the timer. */
	(void)mesh_lpn_on_response(&st, 0, 1000 + to_ms - 1);
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&st, 1000 + to_ms));
}

/* ================================================================
 * 7. Offer selection (local policy, Section 3.6.6.4.1).
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(lpn_select_offer);
ATF_TC_BODY(lpn_select_offer, tc)
{
	struct mesh_friend_offer offers[3];

	memset(offers, 0, sizeof(offers));
	/* offer0: queue 4. offer1: queue 8 (best). offer2: queue 2. */
	offers[0].queue_size = 4; offers[0].rssi = -40;
	offers[1].queue_size = 8; offers[1].rssi = -70;
	offers[2].queue_size = 2; offers[2].rssi = -30;

	/* Requires min queue size 4: offer1 (largest queue) wins. */
	ATF_CHECK_EQ(1, mesh_lpn_select_offer(offers, 3, 4));

	/* Requires min queue size 16: none qualifies. */
	ATF_CHECK_EQ(-1, mesh_lpn_select_offer(offers, 3, 16));

	/* Tie on queue size -> stronger RSSI wins. */
	offers[0].queue_size = 8; offers[0].sub_list_size = 2; offers[0].rssi = -70;
	offers[1].queue_size = 8; offers[1].sub_list_size = 2; offers[1].rssi = -50;
	offers[2].queue_size = 8; offers[2].sub_list_size = 2; offers[2].rssi = -90;
	ATF_CHECK_EQ(1, mesh_lpn_select_offer(offers, 3, 2));

	ATF_CHECK_EQ(-1, mesh_lpn_select_offer(NULL, 0, 0));
}

/* ================================================================
 * Argument-guard, wrong-length and wrong-opcode arms of every friendship
 * control-message build/parse (Section 3.6.5).  Oracle: the field-length and
 * opcode contract encoded in mesh_friend.h.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_codec_guards);
ATF_TC_BODY(friend_codec_guards, tc)
{
	uint8_t buf[MESH_FRIEND_MSG_MAX];
	uint8_t in[MESH_FRIEND_MSG_MAX];
	size_t len;

	memset(in, 0, sizeof(in));

	/* --- mesh_friend_p_input --- */
	ATF_CHECK_EQ(-1, mesh_friend_p_input(0, 0, 0, 0, NULL));

	/* --- mesh_friend_credentials: each output pointer guarded
	 * individually (netkey valid so the later arms are reached). --- */
	{
		HEX(netkey, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
		uint8_t nid, enc[16], priv[16];

		ATF_CHECK_EQ(-1, mesh_friend_credentials(netkey, 0x1201, 0x2345,
		    0, 0, NULL, enc, priv));
		ATF_CHECK_EQ(-1, mesh_friend_credentials(netkey, 0x1201, 0x2345,
		    0, 0, &nid, NULL, priv));
		ATF_CHECK_EQ(-1, mesh_friend_credentials(netkey, 0x1201, 0x2345,
		    0, 0, &nid, enc, NULL));
	}

	/* --- criteria helpers tolerate NULL out pointers / out-of-range log --- */
	mesh_friend_criteria_unpack(0x75, NULL, NULL, NULL);	/* must not crash */
	ATF_CHECK_EQ_MSG(0, mesh_friend_min_queue_size(8),
	    "MinQueueSizeLog > 7 must return 0 (Table 3.36)");

	/* --- Friend Poll --- */
	{
		struct mesh_friend_poll pin, pout;

		memset(&pin, 0, sizeof(pin));
		ATF_CHECK_EQ(-1, mesh_friend_poll_build(NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_poll_build(&pin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_poll_build(&pin, buf, NULL));
		pin.fsn = 2;			/* FSN is a single bit (0..1) */
		ATF_CHECK_EQ(-1, mesh_friend_poll_build(&pin, buf, &len));

		ATF_CHECK_EQ(-1, mesh_friend_poll_parse(NULL,
		    BT_MESH11_FRIEND_POLL_PDU_SIZE,
		    &pout));
		ATF_CHECK_EQ(-1, mesh_friend_poll_parse(in,
		    BT_MESH11_FRIEND_POLL_PDU_SIZE,
		    NULL));
		in[0] = MESH_FRIEND_OP_POLL;
		ATF_CHECK_EQ(-1, mesh_friend_poll_parse(in, 3, &pout)); /* len */
	}

	/* --- Friend Update --- */
	{
		struct mesh_friend_update uin, uout;

		memset(&uin, 0, sizeof(uin));
		ATF_CHECK_EQ(-1, mesh_friend_update_build(NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_update_build(&uin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_update_build(&uin, buf, NULL));
		uin.key_refresh = 2;
		ATF_CHECK_EQ(-1, mesh_friend_update_build(&uin, buf, &len));
		uin.key_refresh = 0; uin.iv_update = 2;
		ATF_CHECK_EQ(-1, mesh_friend_update_build(&uin, buf, &len));
		uin.iv_update = 0; uin.md = 2;
		ATF_CHECK_EQ(-1, mesh_friend_update_build(&uin, buf, &len));

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_UPDATE;
		ATF_CHECK_EQ(-1, mesh_friend_update_parse(NULL,
		    BT_MESH11_FRIEND_UPDATE_PDU_SIZE, &uout));
		ATF_CHECK_EQ(-1, mesh_friend_update_parse(in,
		    BT_MESH11_FRIEND_UPDATE_PDU_SIZE, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_update_parse(in, 3, &uout)); /* len */
		in[0] = 0x7f;					/* wrong opcode */
		ATF_CHECK_EQ(-1, mesh_friend_update_parse(in,
		    BT_MESH11_FRIEND_UPDATE_PDU_SIZE, &uout));
	}

	/* --- Friend Request --- */
	{
		struct mesh_friend_request rin, rout;

		memset(&rin, 0, sizeof(rin));
		rin.min_queue_size_log = 1;
		rin.recv_delay = 0x0a;
		rin.poll_timeout = BT_MESH11_FRIEND_POLL_TIMEOUT_MIN;
		rin.num_elements = 1;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, NULL));
		rin.rssi_factor = 4;		/* 2-bit field, > 3 invalid */
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.rssi_factor = 0; rin.rx_window_factor = 4;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.rx_window_factor = 0; rin.min_queue_size_log = 8; /* 3-bit */
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.min_queue_size_log = 1;
		rin.poll_timeout = BT_MESH11_FRIEND_POLL_TIMEOUT_MAX + 1;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.poll_timeout = BT_MESH11_FRIEND_POLL_TIMEOUT_MIN;
		rin.recv_delay = 9;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.recv_delay = 0x0a; rin.min_queue_size_log = 0;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));
		rin.min_queue_size_log = 1; rin.num_elements = 0;
		ATF_CHECK_EQ(-1, mesh_friend_request_build(&rin, buf, &len));

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_REQUEST;
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(NULL,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, &rout));
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in, 5, &rout)); /* len */
		in[0] = 0x7f;					/* wrong opcode */
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, &rout));
		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_REQUEST;
		in[1] = 1;				/* MinQueueSizeLog */
		in[2] = 9;				/* ReceiveDelay prohibited */
		in[5] = BT_MESH11_FRIEND_POLL_TIMEOUT_MIN;
		in[8] = 1;
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, &rout));
		in[2] = BT_MESH11_FRIEND_RECEIVE_DELAY_MIN_MS;
		in[5] = BT_MESH11_FRIEND_POLL_TIMEOUT_MIN - 1;
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, &rout));
		in[5] = BT_MESH11_FRIEND_POLL_TIMEOUT_MIN;
		in[6] = 0x80; in[7] = 0x00;	/* PreviousAddress is virtual */
		ATF_CHECK_EQ(-1, mesh_friend_request_parse(in,
		    BT_MESH11_FRIEND_REQUEST_PDU_SIZE, &rout));
	}

	/* --- Friend Offer --- */
	{
		struct mesh_friend_offer oin, oout;

		memset(&oin, 0, sizeof(oin));
		ATF_CHECK_EQ(-1, mesh_friend_offer_build(NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_offer_build(&oin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_offer_build(&oin, buf, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_offer_build(&oin, buf, &len));
		oin.recv_window = 1;
		ATF_CHECK_EQ(0, mesh_friend_offer_build(&oin, buf, &len));

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_OFFER;
		ATF_CHECK_EQ(-1, mesh_friend_offer_parse(NULL,
		    BT_MESH11_FRIEND_OFFER_PDU_SIZE, &oout));
		ATF_CHECK_EQ(-1, mesh_friend_offer_parse(in,
		    BT_MESH11_FRIEND_OFFER_PDU_SIZE, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_offer_parse(in, 3, &oout)); /* len */
		ATF_CHECK_EQ(-1, mesh_friend_offer_parse(in,
		    BT_MESH11_FRIEND_OFFER_PDU_SIZE, &oout)); /* zero ReceiveWindow */
		in[0] = 0x7f;					/* wrong opcode */
		ATF_CHECK_EQ(-1, mesh_friend_offer_parse(in,
		    BT_MESH11_FRIEND_OFFER_PDU_SIZE, &oout));
	}

	/* --- Friend Clear / Clear Confirm --- */
	{
		struct mesh_friend_clear cin, cout;
		uint8_t op;

		memset(&cin, 0, sizeof(cin));
		ATF_CHECK_EQ(-1, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR,
		    NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR,
		    &cin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR,
		    &cin, buf, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR,
		    &cin, buf, &len));		/* unassigned LPNAddress */

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_CLEAR;
		ATF_CHECK_EQ(-1, mesh_friend_clear_parse(NULL,
		    BT_MESH11_FRIEND_CLEAR_PDU_SIZE, &cout, &op));
		ATF_CHECK_EQ(-1, mesh_friend_clear_parse(in,
		    BT_MESH11_FRIEND_CLEAR_PDU_SIZE, NULL, &op));
		ATF_CHECK_EQ(-1, mesh_friend_clear_parse(in, 3, &cout, &op)); /* len */
		in[0] = 0x09;					/* neither 0x05 nor 0x06 */
		ATF_CHECK_EQ(-1, mesh_friend_clear_parse(in,
		    BT_MESH11_FRIEND_CLEAR_PDU_SIZE, &cout, &op));
		/* Unassigned is not a valid LPNAddress. */
		in[0] = MESH_FRIEND_OP_CLEAR;
		ATF_CHECK_EQ(-1, mesh_friend_clear_parse(in,
		    BT_MESH11_FRIEND_CLEAR_PDU_SIZE,
		    &cout, NULL));
	}

	/* --- Friend Subscription List Add/Remove --- */
	{
		struct mesh_friend_sublist sin, sout;
		uint8_t op;

		memset(&sin, 0, sizeof(sin));
		sin.naddr = 1;
		sin.addrs[0] = 0xc000;
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(
		    MESH_FRIEND_OP_SUBLIST_ADD, NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(
		    MESH_FRIEND_OP_SUBLIST_ADD, &sin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(
		    MESH_FRIEND_OP_SUBLIST_ADD, &sin, buf, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(0x09, &sin, buf,
		    &len));				/* invalid opcode */
		sin.naddr = BT_MESH11_FRIEND_SUBLIST_ADDR_MAX + 1;
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(
		    MESH_FRIEND_OP_SUBLIST_ADD, &sin, buf, &len)); /* naddr > max */
		sin.naddr = 1;
		sin.addrs[0] = 0x0001;
		ATF_CHECK_EQ(-1, mesh_friend_sublist_build(
		    MESH_FRIEND_OP_SUBLIST_ADD, &sin, buf, &len));

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_SUBLIST_ADD;
		ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(NULL, 4, &sout, &op));
		ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(in, 4, NULL, &op));
		ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(in, 3, &sout, &op)); /* <4 */
		in[0] = 0x09;					/* wrong opcode */
		ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(in, 4, &sout, &op));
		/* AddressList with N > max (2 + 2*17 = 36 octets). */
		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_SUBLIST_ADD;
		ATF_CHECK_EQ(-1, mesh_friend_sublist_parse(in,
		    2 + 2 * (BT_MESH11_FRIEND_SUBLIST_ADDR_MAX + 1), &sout, &op));
		/* A REMOVE message parses (op == NULL accepted on success). */
		in[0] = MESH_FRIEND_OP_SUBLIST_REMOVE;
		in[1] = 0x00;
		in[2] = 0xc0; in[3] = 0x00;
		ATF_REQUIRE_EQ(0, mesh_friend_sublist_parse(in, 4, &sout, NULL));
		ATF_CHECK_EQ(1, (int)sout.naddr);
		ATF_CHECK_EQ(0xc000, sout.addrs[0]);
	}

	/* --- Friend Subscription List Confirm --- */
	{
		struct mesh_friend_subconfirm scin, scout;

		memset(&scin, 0, sizeof(scin));
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_build(NULL, buf, &len));
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_build(&scin, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_build(&scin, buf, NULL));

		memset(in, 0, sizeof(in));
		in[0] = MESH_FRIEND_OP_SUBLIST_CONFIRM;
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_parse(NULL,
		    BT_MESH11_FRIEND_SUBCONFIRM_PDU_SIZE, &scout));
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_parse(in,
		    BT_MESH11_FRIEND_SUBCONFIRM_PDU_SIZE, NULL));
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_parse(in, 3, &scout)); /* len */
		in[0] = 0x7f;					/* wrong opcode */
		ATF_CHECK_EQ(-1, mesh_friend_subconfirm_parse(in,
		    BT_MESH11_FRIEND_SUBCONFIRM_PDU_SIZE, &scout));
	}
}

/* ================================================================
 * Subscription-list state and Friend Queue argument guards / boundary arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_sublist_state_guards);
ATF_TC_BODY(friend_sublist_state_guards, tc)
{
	struct mesh_friend_sublist_state s;
	size_t i;

	/* NULL-safe entry points. */
	mesh_friend_sub_init(NULL);			/* must not crash */
	ATF_CHECK_EQ(0, mesh_friend_sub_contains(NULL, 0xc000));
	ATF_CHECK_EQ(-1, mesh_friend_sub_add(NULL, 0xc000));
	ATF_CHECK_EQ(0, mesh_friend_sub_remove(NULL, 0xc000));

	/* Fill to the bound, then one more add overflows (-1). */
	mesh_friend_sub_init(&s);
	for (i = 0; i < MESH_FRIEND_SUBLIST_MAX; i++)
		ATF_REQUIRE_EQ(1, mesh_friend_sub_add(&s,
		    (uint16_t)(0xc000 + i)));
	ATF_CHECK_EQ_MSG(-1, mesh_friend_sub_add(&s, 0xdead),
	    "add past the bounded subscription list must fail");
}

ATF_TC_WITHOUT_HEAD(fq_init_and_guards);
ATF_TC_BODY(fq_init_and_guards, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	/* NULL-safe init / count. */
	mesh_fq_init(NULL, 0, 0, 0);			/* must not crash */
	ATF_CHECK_EQ(0, (int)mesh_fq_count(NULL));

	/* num_elements 0 clamps to 1; cap 0 clamps to 1; cap > MAX clamps. */
	mesh_fq_init(&q, 0x0002, 0, 0);
	ATF_CHECK_EQ(1, q.num_elements);
	ATF_CHECK_EQ(1, (int)q.cap);
	mesh_fq_init(&q, 0x0002, 1, MESH_FQ_MAX + 5);
	ATF_CHECK_EQ(MESH_FQ_MAX, (int)q.cap);

	/* enqueue / enqueue_update / poll NULL and oversized-PDU guards. */
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_CHECK_EQ(-1, mesh_fq_enqueue(NULL, &e));
	ATF_CHECK_EQ(-1, mesh_fq_enqueue(&q, NULL));
	ATF_CHECK_EQ(-1, mesh_fq_enqueue_update(NULL, &e));
	ATF_CHECK_EQ(-1, mesh_fq_enqueue_update(&q, NULL));
	e.pdu_len = MESH_FQ_PDU_MAX + 1;		/* oversized Lower PDU */
	ATF_CHECK_EQ(-1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(-1, mesh_fq_enqueue_update(&q, &e));

	ATF_CHECK_EQ(-1, mesh_fq_poll(NULL, 0, NULL, &out));
	ATF_CHECK_EQ(-1, mesh_fq_poll(&q, 0, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_fq_poll(&q, 2, NULL, &out));	/* FSN not 0/1 */
}

/* A queue full of evict-protected Friend Updates rejects further stores. */
ATF_TC_WITHOUT_HEAD(fq_full_of_updates);
ATF_TC_BODY(fq_full_of_updates, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	mesh_fq_init(&q, 0x0002, 1, 2);
	e = mkentry(0x0002, 0x0002, 0, 1, 'U');
	e.is_update = 1;
	ATF_REQUIRE_EQ(0, mesh_fq_enqueue_update(&q, &e));
	e = mkentry(0x0002, 0x0002, 0, 2, 'V');
	e.is_update = 1;
	ATF_REQUIRE_EQ(0, mesh_fq_enqueue_update(&q, &e));

	/* Queue is now full of Update entries; nothing can be evicted. */
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_CHECK_EQ_MSG(-1, mesh_fq_enqueue(&q, &e),
	    "enqueue succeeded with a queue full of protected Updates");
	e = mkentry(0x0002, 0x0002, 0, 3, 'W');
	e.is_update = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_fq_enqueue_update(&q, &e),
	    "enqueue_update succeeded with a queue full of Updates");

	/* An empty-queue Poll whose synthesized Update is oversized fails. */
	mesh_fq_init(&q, 0x0002, 1, 4);
	e = mkentry(0x0002, 0x0002, 0, 1, 'U');
	e.is_update = 1;
	e.pdu_len = MESH_FQ_PDU_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_fq_poll(&q, 0, &e, &out));
}

/* DST below the LPN element range is not for the LPN; two messages with the
 * same SEQ but different SRC are not treated as duplicates. */
ATF_TC_WITHOUT_HEAD(fq_enqueue_addr_edges);
ATF_TC_BODY(fq_enqueue_addr_edges, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e;

	mesh_fq_init(&q, 0x0002, 1, 8);

	/* DST 0x0001 is strictly below lpn_addr 0x0002 -> not for the LPN. */
	e = mkentry(0x1234, 0x0001, 5, 100, 'a');
	ATF_CHECK_EQ(0, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(0, (int)mesh_fq_count(&q));

	/* Same SEQ, different SRC -> not a duplicate, both stored. */
	e = mkentry(0x1111, 0x0002, 5, 200, 'b');
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	e = mkentry(0x2222, 0x0002, 5, 200, 'c');	/* same seq, other src */
	ATF_CHECK_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_CHECK_EQ(2, (int)mesh_fq_count(&q));
}

/* Repeated eviction reuses slots so fq_oldest compares out-of-order insertion
 * counters, and a toggled Poll on an already-empty queue takes the
 * nothing-to-discard arm. */
ATF_TC_WITHOUT_HEAD(fq_eviction_and_empty_ack);
ATF_TC_BODY(fq_eviction_and_empty_ack, tc)
{
	struct mesh_friend_queue q;
	struct mesh_fq_entry e, out;

	mesh_fq_init(&q, 0x0002, 1, 2);
	e = mkentry(0x1234, 0x0002, 5, 100, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));	/* slot0, order0 */
	e = mkentry(0x1234, 0x0002, 5, 101, 'b');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));	/* slot1, order1 */
	e = mkentry(0x1234, 0x0002, 5, 102, 'c');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));	/* evict 100, slot0 order2 */
	/* slot0 order2 (seq102), slot1 order1 (seq101).  The next eviction
	 * must pick slot1 (order1 < order2) -> deliver 102 afterwards. */
	e = mkentry(0x1234, 0x0002, 5, 103, 'd');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));	/* evict 101 */
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));
	ATF_CHECK_EQ(102, out.seq);			/* oldest survivor */

	/* Drain the queue, then a toggled Poll on the empty queue must not
	 * try to discard a non-existent head. */
	mesh_fq_init(&q, 0x0002, 1, 4);
	e = mkentry(0x1234, 0x0002, 5, 200, 'a');
	ATF_REQUIRE_EQ(1, mesh_fq_enqueue(&q, &e));
	ATF_REQUIRE_EQ(1, mesh_fq_poll(&q, 0, NULL, &out));	/* deliver 200 */
	ATF_REQUIRE_EQ(0, mesh_fq_poll(&q, 1, NULL, &out));	/* ack -> empty */
	ATF_CHECK_EQ(0, (int)mesh_fq_count(&q));
	/* Empty queue, FSN toggled again: nothing to discard, nothing to send. */
	ATF_CHECK_EQ(0, mesh_fq_poll(&q, 0, NULL, &out));
}

/* ================================================================
 * LPN cadence argument guards and the friendship-lost pre-timeout arm.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_cadence_guards);
ATF_TC_BODY(lpn_cadence_guards, tc)
{
	struct mesh_lpn_state st;

	/* NULL-safe accessors. */
	ATF_CHECK_EQ(-1, mesh_lpn_init(NULL, 0x0000A0, 0));
	mesh_lpn_established(NULL);			/* must not crash */
	ATF_CHECK_EQ(0, (int)mesh_lpn_poll_timeout_ms(NULL));
	ATF_CHECK_EQ(0, mesh_lpn_poll_fsn(NULL));
	ATF_CHECK_EQ(0, mesh_lpn_on_response(NULL, 0, 0));
	ATF_CHECK_EQ_MSG(1, mesh_lpn_friendship_lost(NULL, 0),
	    "a NULL LPN state is treated as friendship lost");

	ATF_REQUIRE_EQ(0, mesh_lpn_init(&st, 0x0000A0, 1000));
	mesh_lpn_established(&st);			/* the non-NULL arm */
	ATF_CHECK_EQ(1, st.established);
	/* now <= last_poll_ms: no time has elapsed -> not lost. */
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&st, 500));
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&st, 1000));
}

/* ================================================================
 * Offer-selection local-policy tie-break chain (Section 3.6.6.4.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_select_offer_tiebreaks);
ATF_TC_BODY(lpn_select_offer_tiebreaks, tc)
{
	struct mesh_friend_offer o[2];

	/* n == 0 -> no candidate. */
	ATF_CHECK_EQ(-1, mesh_lpn_select_offer(o, 0, 0));

	/* A later, smaller QueueSize does not displace the current best. */
	memset(o, 0, sizeof(o));
	o[0].queue_size = 8; o[1].queue_size = 4;
	ATF_CHECK_EQ(0, mesh_lpn_select_offer(o, 2, 2));

	/* Equal QueueSize: a larger SubscriptionListSize wins. */
	memset(o, 0, sizeof(o));
	o[0].queue_size = 8; o[0].sub_list_size = 2;
	o[1].queue_size = 8; o[1].sub_list_size = 5;
	ATF_CHECK_EQ(1, mesh_lpn_select_offer(o, 2, 2));
	/* ...and a smaller SubscriptionListSize does not. */
	memset(o, 0, sizeof(o));
	o[0].queue_size = 8; o[0].sub_list_size = 5;
	o[1].queue_size = 8; o[1].sub_list_size = 2;
	ATF_CHECK_EQ(0, mesh_lpn_select_offer(o, 2, 2));

	/* Equal QueueSize + SubListSize + RSSI: a smaller ReceiveWindow wins. */
	memset(o, 0, sizeof(o));
	o[0].queue_size = 8; o[0].sub_list_size = 2; o[0].rssi = -50;
	o[0].recv_window = 20;
	o[1].queue_size = 8; o[1].sub_list_size = 2; o[1].rssi = -50;
	o[1].recv_window = 10;
	ATF_CHECK_EQ(1, mesh_lpn_select_offer(o, 2, 2));
	/* ...and a larger ReceiveWindow does not. */
	memset(o, 0, sizeof(o));
	o[0].queue_size = 8; o[0].sub_list_size = 2; o[0].rssi = -50;
	o[0].recv_window = 20;
	o[1].queue_size = 8; o[1].sub_list_size = 2; o[1].rssi = -50;
	o[1].recv_window = 30;
	ATF_CHECK_EQ(0, mesh_lpn_select_offer(o, 2, 2));
}

/* ================================================================
 * Friend role driven FSM (Section 3.6.5): Request -> Offer (after the Offer
 * Delay) -> Poll -> establish -> queued delivery, and the Friend Clear
 * handshake terminating the friendship.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_fsm_flow);
ATF_TC_BODY(friend_fsm_flow, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_clear clr;
	struct mesh_fq_entry msg;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t cpdu[MESH_FRIEND_CLEAR_LEN];
	size_t rlen, clen;
	uint64_t now = 0;

	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);

	/* A Friend Request (PollTimeout 100 units = 10 s). */
	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;	/* min queue size 2 */
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	/* SRC plus NumElements must not extend beyond the unicast range. */
	req.num_elements = 2;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	ATF_CHECK_EQ(-1, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x7fff,
	    -60, now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ST_IDLE, f.state);
	req.num_elements = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));

	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, now,
	    &out));

	/* The Offer waits for the Offer Delay, then is emitted. */
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_NONE, out.action);
	now = 300;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_OP_OFFER, out.pdu[0] & 0x7f);

	/* First Poll establishes the friendship (empty-queue Update reply). */
	{
		struct mesh_friend_poll poll;
		uint8_t ppdu[MESH_FRIEND_POLL_LEN];
		size_t plen;

		memset(&poll, 0, sizeof(poll));
		poll.fsn = 0;
		ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
		ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0,
		    0x1000, now, &out));
		ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, out.action);
		ATF_CHECK_EQ(1, out.msg.is_update);
		ATF_CHECK(mesh_friend_fsm_established(&f));

		/* Enqueue a message and drain it on the next (toggled) Poll. */
		memset(&msg, 0, sizeof(msg));
		msg.ttl = 5;
		msg.seq = 0x20;
		msg.src = 0x0009;
		msg.dst = 0x1201;
		msg.pdu[0] = 0x5a;
		msg.pdu_len = 1;
		ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &msg));

		poll.fsn = 1;
		ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
		ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0,
		    0x1000, now, &out));
		ATF_CHECK_EQ(0, out.msg.is_update);
		ATF_CHECK_EQ(0x5a, out.msg.pdu[0]);
	}

	/* A Friend Clear for this LPN terminates the friendship + confirms. */
	memset(&clr, 0, sizeof(clr));
	clr.lpn_addr = 0x1201;
	clr.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR, &clr,
	    cpdu, &clen));
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_clear(&f, cpdu, clen, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_OP_CLEAR_CONFIRM, out.pdu[0] & 0x7f);
	ATF_CHECK(!mesh_friend_fsm_established(&f));
}

/* ================================================================
 * Friend Clear replay guard (Section 3.6.6.4, Friend Clear procedure): a
 * Friend Clear whose LPNCounter is behind the establishing LPNCounter (a
 * stale/replayed Clear) must not terminate a live friendship; one at/ahead
 * within the 255-step window does.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_fsm_clear_replay_guard);
ATF_TC_BODY(friend_fsm_clear_replay_guard, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	struct mesh_friend_clear clr;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t ppdu[MESH_FRIEND_POLL_LEN];
	uint8_t cpdu[MESH_FRIEND_CLEAR_LEN];
	size_t rlen, plen, clen;
	uint64_t now = 0;

	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);

	/* Establish a friendship at LPNCounter 0x0100. */
	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0100;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, now,
	    &out));
	now = 300;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	ATF_REQUIRE_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	memset(&poll, 0, sizeof(poll));
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_REQUIRE(mesh_friend_fsm_established(&f));

	/* A stale Friend Clear (LPNCounter 0x0000, behind ours) is ignored. */
	memset(&clr, 0, sizeof(clr));
	clr.lpn_addr = 0x1201;
	clr.lpn_counter = 0x0000;
	ATF_REQUIRE_EQ(0, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR, &clr,
	    cpdu, &clen));
	ATF_CHECK_EQ_MSG(0, mesh_friend_fsm_recv_clear(&f, cpdu, clen, &out),
	    "a replayed/stale Friend Clear must not be honoured");
	ATF_CHECK_EQ(MESH_FRIEND_ACT_NONE, out.action);
	ATF_CHECK_MSG(mesh_friend_fsm_established(&f),
	    "friendship must survive a stale Friend Clear");

	/* A Friend Clear at the edge of the window (0x0100 + 255) is honoured. */
	clr.lpn_counter = (uint16_t)(0x0100 + 255);
	ATF_REQUIRE_EQ(0, mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR, &clr,
	    cpdu, &clen));
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_clear(&f, cpdu, clen, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_OP_CLEAR_CONFIRM, out.pdu[0] & 0x7f);
	ATF_CHECK(!mesh_friend_fsm_established(&f));
}

/* ================================================================
 * The Friend Queue accepts messages while the friendship is still forming
 * (OFFERING / ESTABLISHING), so a message that arrives during establishment is
 * preserved rather than dropped (Section 3.6.6.4.1).  The establishing Poll is
 * answered with a Friend Update (Section 3.6.6.3.1) - never a data PDU - and
 * the queued messages are then delivered in order on the following toggled-FSN
 * Polls.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_enqueue_while_establishing);
ATF_TC_BODY(friend_enqueue_while_establishing, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	struct mesh_friend_update up;
	struct mesh_fq_entry a, b;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t ppdu[MESH_FRIEND_POLL_LEN];
	size_t rlen, plen;
	uint64_t now = 0;

	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);

	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, now,
	    &out));

	/* OFFERING: a message addressed to the LPN is queued, not dropped. */
	ATF_CHECK_EQ(MESH_FRIEND_ST_OFFERING, f.state);
	memset(&a, 0, sizeof(a));
	a.ttl = 5;
	a.seq = 0x21;
	a.src = 0x0009;
	a.dst = 0x1201;
	a.pdu[0] = 0xA1;
	a.pdu_len = 1;
	ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &a));

	/* Emit the Offer -> ESTABLISHING. */
	now = 300;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	ATF_REQUIRE_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHING, f.state);

	/* ESTABLISHING: a second message is also queued. */
	memset(&b, 0, sizeof(b));
	b.ttl = 5;
	b.seq = 0x22;
	b.src = 0x0009;
	b.dst = 0x1201;
	b.pdu[0] = 0xB2;
	b.pdu_len = 1;
	ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &b));

	/*
	 * The first Poll (FSN 0) establishes the friendship and MUST be answered
	 * with a Friend Update, not a queued data PDU (Section 3.6.6.3.1): the LPN
	 * considers the friendship established only on receipt of a Friend Update.
	 * The messages queued during establishment are preserved - the Update
	 * carries MD=1 to tell the LPN there is data waiting - and are delivered,
	 * in order, on the subsequent toggled-FSN Polls.
	 */
	memset(&poll, 0, sizeof(poll));
	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, out.action);
	ATF_CHECK_EQ(1, out.msg.is_update);
	ATF_REQUIRE_EQ(0, mesh_friend_update_parse(out.msg.pdu, out.msg.pdu_len,
	    &up));
	ATF_CHECK_EQ_MSG(1, up.md,
	    "the establishing Friend Update must report data pending (MD=1)");

	/* The first toggled-FSN Poll (FSN 1) delivers the oldest queued message. */
	poll.fsn = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, out.action);
	ATF_CHECK_EQ(0, out.msg.is_update);
	ATF_CHECK_EQ(0xA1, out.msg.pdu[0]);

	/*
	 * The next toggled-FSN Poll (FSN 0) acknowledges 0xA1 and delivers the
	 * second queued message, proving establishment-time data is preserved and
	 * delivered in order after the Update rather than dropped.
	 */
	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(0, out.msg.is_update);
	ATF_CHECK_EQ(0xB2, out.msg.pdu[0]);
}

/* ================================================================
 * Finding 16: the empty-queue Friend Update's More Data bit must be computed
 * AFTER the Poll's FSN ack-discard, excluding the entry returned as the
 * response.  After the last queued message is acked the queue is empty, so the
 * synthesized Friend Update must report MD=0 - not a stale MD=1 that livelocks
 * the LPN in an immediate re-poll loop (Section 3.6.6.4.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_fsm_md_after_ack);
ATF_TC_BODY(friend_fsm_md_after_ack, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	struct mesh_friend_update up;
	struct mesh_fq_entry msg;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t ppdu[MESH_FRIEND_POLL_LEN];
	size_t rlen, plen;
	uint64_t now = 0;

	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);

	/* Establish a friendship (PollTimeout 100 units = 10 s). */
	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, now, &out));
	now = 300;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	ATF_REQUIRE_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);

	memset(&poll, 0, sizeof(poll));
	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_REQUIRE(mesh_friend_fsm_established(&f));

	/* Deliver exactly one queued message. */
	memset(&msg, 0, sizeof(msg));
	msg.ttl = 5;
	msg.seq = 0x20;
	msg.src = 0x0009;
	msg.dst = 0x1201;
	msg.pdu[0] = 0x5a;
	msg.pdu_len = 1;
	ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &msg));

	/* Poll (FSN toggled to 1): the message is delivered, not yet acked. */
	poll.fsn = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(0, out.msg.is_update);
	ATF_CHECK_EQ(0x5a, out.msg.pdu[0]);

	/*
	 * Poll (FSN toggled back to 0): acks and discards the delivered message,
	 * leaving the queue empty.  The synthesized Friend Update must carry
	 * MD=0.
	 */
	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, out.action);
	ATF_CHECK_EQ(1, out.msg.is_update);
	ATF_REQUIRE_EQ(0, mesh_friend_update_parse(out.msg.pdu, out.msg.pdu_len,
	    &up));
	ATF_CHECK_EQ_MSG(0, up.md,
	    "empty-queue Friend Update after ack must carry MD=0 (finding)");
}

/* ================================================================
 * Finding 17: while ESTABLISHED with LPN A, a Friend Request from a DIFFERENT
 * LPN must be ignored - it must not overwrite the friendship or discard A's
 * queued messages.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_fsm_request_from_other_lpn_ignored);
ATF_TC_BODY(friend_fsm_request_from_other_lpn_ignored, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	struct mesh_fq_entry msg;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t ppdu[MESH_FRIEND_POLL_LEN];
	size_t rlen, plen;
	uint64_t now = 0;

	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);

	/* Establish a friendship with LPN A = 0x1201. */
	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, now, &out));
	now = 300;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &out));
	memset(&poll, 0, sizeof(poll));
	poll.fsn = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_REQUIRE(mesh_friend_fsm_established(&f));

	/* Queue a message for LPN A. */
	memset(&msg, 0, sizeof(msg));
	msg.ttl = 5;
	msg.seq = 0x30;
	msg.src = 0x0009;
	msg.dst = 0x1201;
	msg.pdu[0] = 0xC3;
	msg.pdu_len = 1;
	ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &msg));

	/* A Friend Request from a DIFFERENT LPN B = 0x1301 must be ignored. */
	ATF_CHECK_EQ_MSG(-1, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1301,
	    -60, now, &out),
	    "a Friend Request from a different LPN must be ignored while "
	    "established");
	ATF_CHECK_MSG(mesh_friend_fsm_established(&f),
	    "the established friendship must survive a foreign Friend Request");
	ATF_CHECK_EQ(0x1201, f.lpn_addr);
	ATF_CHECK_EQ(0x1201, f.queue.lpn_addr);

	/* A's queued message is intact and still delivered. */
	poll.fsn = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    now, &out));
	ATF_CHECK_EQ(0, out.msg.is_update);
	ATF_CHECK_EQ(0xC3, out.msg.pdu[0]);
	ATF_CHECK_EQ(0x1201, out.msg.dst);
}

/* ================================================================
 * Finding 75: the friendship is established only if the first Friend Poll
 * arrives within the establishment window (1 s) of the Friend Offer (Section
 * 3.6.6.3.1).  ESTABLISHING must expire (tick), and a Poll arriving after the
 * window must not establish a friendship the LPN abandoned.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_fsm_establishing_timeout);
ATF_TC_BODY(friend_fsm_establishing_timeout, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_friend_out out;
	struct mesh_friend_request req;
	struct mesh_friend_poll poll;
	uint8_t rpdu[MESH_FRIEND_REQUEST_LEN];
	uint8_t ppdu[MESH_FRIEND_POLL_LEN];
	size_t rlen, plen;

	memset(&req, 0, sizeof(req));
	req.min_queue_size_log = 1;
	req.recv_delay = 100;
	req.poll_timeout = 100;
	req.num_elements = 1;
	req.lpn_counter = 0x0001;
	ATF_REQUIRE_EQ(0, mesh_friend_request_build(&req, rpdu, &rlen));
	memset(&poll, 0, sizeof(poll));
	ATF_REQUIRE_EQ(0, mesh_friend_poll_build(&poll, ppdu, &plen));

	/* 1. tick expires ESTABLISHING once the 1 s window closes with no Poll. */
	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, 0, &out));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, 300, &out));
	ATF_REQUIRE_EQ(MESH_FRIEND_ACT_SEND_CONTROL, out.action);
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHING, f.state);
	/* Just before the window closes: still ESTABLISHING. */
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f,
	    300 + MESH_FRIEND_ESTABLISH_TIMEOUT_MS - 1, &out));
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHING, f.state);
	/* At the window: expire back to IDLE. */
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f,
	    300 + MESH_FRIEND_ESTABLISH_TIMEOUT_MS, &out));
	ATF_CHECK_EQ_MSG(MESH_FRIEND_ST_IDLE, f.state,
	    "ESTABLISHING must expire 1 s after the Offer (finding)");

	/* 2. A Poll inside the window still establishes. */
	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, 0, &out));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, 300, &out));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    300 + MESH_FRIEND_ESTABLISH_TIMEOUT_MS - 1, &out));
	ATF_CHECK(mesh_friend_fsm_established(&f));

	/* 3. A Poll arriving after the window does not establish (finding). */
	mesh_friend_fsm_init(&f, 0x2345, 20, 8, 4, -90, 4);
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, rpdu, rlen, 0x1201,
	    -60, 0, &out));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, 300, &out));
	ATF_CHECK_EQ(-1, mesh_friend_fsm_recv_poll(&f, ppdu, plen, 0, 0, 0x1000,
	    300 + MESH_FRIEND_ESTABLISH_TIMEOUT_MS, &out));
	ATF_CHECK_MSG(!mesh_friend_fsm_established(&f),
	    "a Poll after the 1 s window must not establish the friendship");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, friend_fsm_flow);
	ATF_TP_ADD_TC(tp, friend_fsm_clear_replay_guard);
	ATF_TP_ADD_TC(tp, friend_enqueue_while_establishing);
	ATF_TP_ADD_TC(tp, friend_fsm_md_after_ack);
	ATF_TP_ADD_TC(tp, friend_fsm_request_from_other_lpn_ignored);
	ATF_TP_ADD_TC(tp, friend_fsm_establishing_timeout);

	ATF_TP_ADD_TC(tp, friend_credentials_kat);
	ATF_TP_ADD_TC(tp, friend_p_input_kat);
	ATF_TP_ADD_TC(tp, friend_credentials_null);
	ATF_TP_ADD_TC(tp, friend_poll_codec);
	ATF_TP_ADD_TC(tp, friend_update_codec);
	ATF_TP_ADD_TC(tp, friend_request_codec);
	ATF_TP_ADD_TC(tp, friend_offer_codec);
	ATF_TP_ADD_TC(tp, friend_clear_codec);
	ATF_TP_ADD_TC(tp, friend_sublist_codec);
	ATF_TP_ADD_TC(tp, friend_subconfirm_codec);
	ATF_TP_ADD_TC(tp, friend_criteria_pack);
	ATF_TP_ADD_TC(tp, friend_min_queue_size);
	ATF_TP_ADD_TC(tp, friend_factor_x2);
	ATF_TP_ADD_TC(tp, friend_offer_delay);
	ATF_TP_ADD_TC(tp, friend_sublist_state);
	ATF_TP_ADD_TC(tp, fq_enqueue_filter);
	ATF_TP_ADD_TC(tp, fq_enqueue_ttl_decrement);
	ATF_TP_ADD_TC(tp, fq_enqueue_dedup);
	ATF_TP_ADD_TC(tp, fq_bound_evicts_oldest);
	ATF_TP_ADD_TC(tp, fq_update_evict_protected);
	ATF_TP_ADD_TC(tp, fq_fsn_delivery_order);
	ATF_TP_ADD_TC(tp, fq_empty_poll_synthesizes_update);
	ATF_TP_ADD_TC(tp, lpn_init_range);
	ATF_TP_ADD_TC(tp, lpn_fsn_toggle);
	ATF_TP_ADD_TC(tp, lpn_friendship_lost);
	ATF_TP_ADD_TC(tp, lpn_select_offer);
	ATF_TP_ADD_TC(tp, friend_codec_guards);
	ATF_TP_ADD_TC(tp, friend_sublist_state_guards);
	ATF_TP_ADD_TC(tp, fq_init_and_guards);
	ATF_TP_ADD_TC(tp, fq_full_of_updates);
	ATF_TP_ADD_TC(tp, fq_enqueue_addr_edges);
	ATF_TP_ADD_TC(tp, fq_eviction_and_empty_ack);
	ATF_TP_ADD_TC(tp, lpn_cadence_guards);
	ATF_TP_ADD_TC(tp, lpn_select_offer_tiebreaks);

	return (atf_no_error());
}
