/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the driven Friend and Low Power node state machines
 * (mesh_friend.c Section 6, mesh_lpn.c; MshPRT_v1.1 Section 3.6.5 / 3.6.6.4).
 *
 * The tests drive a Friend engine and an LPN engine against each other over an
 * in-memory relay on an injected millisecond clock (no real sleeps): a full
 * friendship lifecycle - Friend Request, Friend Offer after the Offer Delay,
 * first Friend Poll and establishment, a queued-message delivery through the
 * FSN handshake, PollTimeout expiry and re-establishment - plus the LPN's
 * best-Offer selection policy.  The oracle is the Section 3.6.5 message layout
 * and the Section 3.6.6.4 cadence rules.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_friend.h"
#include "mesh_lpn.h"
#include "spec_mesh_friend_oracles.h"

#define	FRIEND_ADDR	0x2345
#define	LPN_ADDR	0x1201

static void
assert_friend_wire_contract(void)
{
	/* Mesh Protocol 1.1 Section 3.6.5, Tables 3.28-3.46. */
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_POLL, MESH_FRIEND_OP_POLL);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_UPDATE, MESH_FRIEND_OP_UPDATE);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_REQUEST, MESH_FRIEND_OP_REQUEST);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_OFFER, MESH_FRIEND_OP_OFFER);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_SUBLIST_ADD,
	    MESH_FRIEND_OP_SUBLIST_ADD);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_SUBLIST_REMOVE,
	    MESH_FRIEND_OP_SUBLIST_REMOVE);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OP_SUBLIST_CONFIRM,
	    MESH_FRIEND_OP_SUBLIST_CONFIRM);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_POLL_PDU_SIZE, MESH_FRIEND_POLL_LEN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_UPDATE_PDU_SIZE, MESH_FRIEND_UPDATE_LEN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_REQUEST_PDU_SIZE, MESH_FRIEND_REQUEST_LEN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_OFFER_PDU_SIZE, MESH_FRIEND_OFFER_LEN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_SUBCONFIRM_PDU_SIZE,
	    MESH_FRIEND_SUBCONFIRM_LEN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_POLL_TIMEOUT_MIN,
	    MESH_LPN_POLLTIMEOUT_MIN);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_POLL_TIMEOUT_MAX,
	    MESH_LPN_POLLTIMEOUT_MAX);
	ATF_CHECK_EQ(BT_MESH11_FRIEND_SUBLIST_ADDR_MAX,
	    MESH_FRIEND_SUBLIST_ADDR_MAX);
}

/* Build an Offer PDU with the given parameters (Section 3.6.5.4). */
static size_t
build_offer(uint8_t *out, uint8_t recv_window, uint8_t queue_size,
    uint8_t sub_list_size, int8_t rssi, uint16_t friend_counter)
{
	struct mesh_friend_offer o;
	size_t len;

	memset(&o, 0, sizeof(o));
	o.recv_window = recv_window;
	o.queue_size = queue_size;
	o.sub_list_size = sub_list_size;
	o.rssi = rssi;
	o.friend_counter = friend_counter;
	ATF_REQUIRE_EQ(0, mesh_friend_offer_build(&o, out, &len));
	return (len);
}

/* ================================================================
 * Full Friend <-> LPN friendship lifecycle.  Section 3.6.5 / 3.6.6.4.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_lifecycle);
ATF_TC_BODY(friendship_lifecycle, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_lpn_fsm l;
	struct mesh_friend_out fo;
	struct mesh_friend_offer sent_offer;
	struct mesh_lpn_out lo;
	struct mesh_fq_entry msg;
	uint64_t now;

	assert_friend_wire_contract();
	mesh_friend_fsm_init(&f, FRIEND_ADDR, 20, 8, 4, -90, 4);
	/* PollTimeout 100 units = 10 s; poll every 5 s; 1 s Offer window. */
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 100, 100, 1000, 5000);

	/* 1. LPN sends a Friend Request. */
	now = 0;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);

	/* 2. Friend evaluates the Request (strong signal) and accepts. */
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, lo.pdu, lo.pdu_len,
	    LPN_ADDR, -60, now, &fo));

	/* 3. The Offer is emitted only after the Offer Delay. */
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_NONE, fo.action);
	now = 200;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, fo.action);
	ATF_REQUIRE_EQ(0, mesh_friend_offer_parse(fo.pdu, fo.pdu_len,
	    &sent_offer));
	ATF_CHECK_EQ(0, sent_offer.friend_counter);
	ATF_CHECK_EQ(1, f.friend_counter);

	/* 4. LPN collects the Offer. */
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, fo.pdu, fo.pdu_len,
	    FRIEND_ADDR, now));

	/* 5. Offer window closes: LPN selects and sends the first Poll. */
	now = 1000;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, lo.action);
	ATF_CHECK_EQ(FRIEND_ADDR, lo.friend_addr);

	/* 6. Friend receives the Poll: establishes, answers with a Friend
	 * Update (queue empty). */
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, lo.pdu, lo.pdu_len, 0, 0,
	    0x1000, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, fo.action);
	ATF_CHECK(mesh_friend_fsm_established(&f));
	ATF_CHECK_EQ(1, fo.msg.is_update);

	/* 7. LPN processes the Update: friendship established, IV recorded. */
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_update(&l, fo.msg.pdu, fo.msg.pdu_len,
	    now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_ESTABLISHED, lo.action);
	ATF_CHECK(mesh_lpn_fsm_established(&l));
	ATF_CHECK_EQ(FRIEND_ADDR, mesh_lpn_fsm_friend(&l));
	ATF_CHECK_EQ(0x1000u, mesh_lpn_fsm_iv_index(&l));

	/* 8. A message addressed to the LPN is stored in the Friend Queue. */
	memset(&msg, 0, sizeof(msg));
	msg.ctl = 0;
	msg.ttl = 5;
	msg.seq = 0x000010;
	msg.src = 0x0009;
	msg.dst = LPN_ADDR;
	msg.pdu[0] = 0xAA;
	msg.pdu[1] = 0xBB;
	msg.pdu_len = 2;
	ATF_CHECK_EQ(1, mesh_friend_fsm_enqueue(&f, &msg));

	/* 9. Next cadence Poll (FSN toggled to 1) drains the queued message. */
	now = 6000;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, lo.action);
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_poll(&f, lo.pdu, lo.pdu_len, 0, 0,
	    0x1000, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_MSG, fo.action);
	ATF_CHECK_EQ(0, fo.msg.is_update);
	ATF_CHECK_EQ(LPN_ADDR, fo.msg.dst);
	ATF_CHECK_EQ(0xAA, fo.msg.pdu[0]);
	/* The stored TTL is decremented by one on enqueue (Section 3.5.5). */
	ATF_CHECK_EQ(4, fo.msg.ttl);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_on_message(&l, 0, now));

	/* 10. No further Poll before PollTimeout -> both sides drop the
	 * friendship, and the LPN re-establishes. */
	now = 16000;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_TERMINATED, fo.action);
	ATF_CHECK(!mesh_friend_fsm_established(&f));

	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_LOST, lo.action);
	ATF_CHECK(!mesh_lpn_fsm_established(&l));

	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);

	/* The Friend Offer Delay remains ordered when its absolute deadline
	 * wraps the injected millisecond clock. */
	now = UINT64_MAX - 99;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, lo.pdu, lo.pdu_len,
	    LPN_ADDR, -60, now, &fo));
	ATF_REQUIRE(f.offer_delay_ms > 0);
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f,
	    now + f.offer_delay_ms - 1, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_NONE, fo.action);
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f,
	    now + f.offer_delay_ms, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, fo.action);
}

/* ================================================================
 * LPN best-Offer selection: the engine picks the qualifying Offer with the
 * largest queue (local policy, Section 3.6.6.4.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_best_offer);
ATF_TC_BODY(lpn_best_offer, tc)
{
	struct mesh_lpn_fsm l;
	struct mesh_lpn_out lo;
	uint8_t o1[MESH_FRIEND_MSG_MAX], o2[MESH_FRIEND_MSG_MAX];
	uint8_t o3[MESH_FRIEND_MSG_MAX];
	size_t n1, n2, n3;
	uint64_t now = 0;

	assert_friend_wire_contract();
	/* min_queue_size_log 2 -> minimum queue size 4. */
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 2, 100, 100, 1000, 5000);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));

	/* Friend A: too small a queue (rejected); B: queue 8; C: queue 4. */
	n1 = build_offer(o1, 20, 2, 2, -50, 1);
	n2 = build_offer(o2, 20, 8, 2, -70, 2);
	n3 = build_offer(o3, 20, 4, 2, -40, 3);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, o1, n1, 0x0011, now));
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, o2, n2, 0x0022, now));
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, o3, n3, 0x0033, now));

	now = 1000;	/* window closes */
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, lo.action);
	/* Friend B (queue 8) wins despite the weaker RSSI. */
	ATF_CHECK_EQ(0x0022, lo.friend_addr);
	ATF_CHECK_EQ(0x0022, mesh_lpn_fsm_friend(&l));
}

/* ================================================================
 * No qualifying Offer arrives -> the LPN re-Requests when the window closes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_no_offer_rerequest);
ATF_TC_BODY(lpn_no_offer_rerequest, tc)
{
	struct mesh_lpn_fsm l;
	struct mesh_lpn_out lo;
	uint8_t o1[MESH_FRIEND_MSG_MAX];
	size_t n1;
	uint64_t now = 0;

	assert_friend_wire_contract();
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 3, 100, 100, 1000, 5000);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));

	/* Only an Offer whose queue is below the requested minimum (8). */
	n1 = build_offer(o1, 20, 4, 2, -50, 1);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, o1, n1, 0x0011, now));

	now = 1000;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);
	ATF_CHECK(!mesh_lpn_fsm_established(&l));
}

/* ================================================================
 * Friend Subscription List Add/Remove handshake (Section 3.6.6.3.3): the
 * Friend confirms with the matching TransactionNumber and the LPN clears the
 * pending transaction.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_sublist);
ATF_TC_BODY(friendship_sublist, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_lpn_fsm l;
	struct mesh_friend_out fo;
	struct mesh_lpn_out lo;
	uint16_t group[2] = { 0xC000, 0xC001 };
	uint64_t now = 0;

	assert_friend_wire_contract();
	/* Bring a friendship up quickly. */
	mesh_friend_fsm_init(&f, FRIEND_ADDR, 20, 8, 4, -90, 4);
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 100, 100, 1000, 5000);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_recv_request(&f, lo.pdu, lo.pdu_len,
	    LPN_ADDR, -60, now, &fo));
	now = 200;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &fo));
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_recv_offer(&l, fo.pdu, fo.pdu_len,
	    FRIEND_ADDR, now));
	now = 1000;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_REQUIRE_EQ(1, mesh_friend_fsm_recv_poll(&f, lo.pdu, lo.pdu_len, 0, 0,
	    0, now, &fo));
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_recv_update(&l, fo.msg.pdu,
	    fo.msg.pdu_len, now, &lo));

	/* LPN subscribes two group addresses through the Friend. */
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_sub(&l, 1, group, 2, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_SUBLIST, lo.action);

	/* Friend adds them and confirms. */
	ATF_CHECK_EQ(1, mesh_friend_fsm_recv_sublist(&f, lo.pdu, lo.pdu_len,
	    now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_SEND_CONTROL, fo.action);
	ATF_CHECK_EQ(1, mesh_friend_sub_contains(&f.queue.sub, 0xC000));
	ATF_CHECK_EQ(1, mesh_friend_sub_contains(&f.queue.sub, 0xC001));

	/* LPN clears the pending transaction on the Confirm. */
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_subconfirm(&l, fo.pdu, fo.pdu_len));
	ATF_CHECK_EQ(0, l.sub_pending);
}

/* ================================================================
 * A weak Friend Request is rejected by the acceptance policy (Section
 * 3.6.6.3): no Offer is emitted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friend_rejects_weak_request);
ATF_TC_BODY(friend_rejects_weak_request, tc)
{
	struct mesh_friend_fsm f;
	struct mesh_lpn_fsm l;
	struct mesh_friend_out fo;
	struct mesh_lpn_out lo;
	uint64_t now = 0;

	assert_friend_wire_contract();
	mesh_friend_fsm_init(&f, FRIEND_ADDR, 20, 8, 4, -80, 4);
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 100, 100, 1000, 5000);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));

	/* RSSI -95 dBm is below the -80 dBm floor. */
	ATF_CHECK_EQ(-1, mesh_friend_fsm_recv_request(&f, lo.pdu, lo.pdu_len,
	    LPN_ADDR, -95, now, &fo));
	now = 500;
	ATF_REQUIRE_EQ(0, mesh_friend_fsm_tick(&f, now, &fo));
	ATF_CHECK_EQ(MESH_FRIEND_ACT_NONE, fo.action);
}

/* ================================================================
 * LPN establishment supervision (Section 3.6.6.4.1): if the first Friend
 * Update never arrives, the LPN retransmits the Friend Poll each establish
 * window (ReceiveDelay + the chosen Offer's ReceiveWindow) up to its retry
 * budget, then abandons the Friend and sends a fresh Friend Request.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(lpn_establish_retry);
ATF_TC_BODY(lpn_establish_retry, tc)
{
	struct mesh_lpn_fsm l;
	struct mesh_lpn_out lo;
	uint8_t offer[16];
	size_t olen;
	uint64_t now = 0;
	int i;

	assert_friend_wire_contract();
	/* ReceiveDelay 10 ms, poll every 5 s, PollTimeout 10 s, Offer window 1 s. */
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 10, 100, 1000, 5000);
	ATF_CHECK_EQ(MESH_LPN_ESTABLISH_RETRIES, l.establish_max_retries);

	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);

	/* One qualifying Offer with ReceiveWindow 20 ms. */
	olen = build_offer(offer, 20, 8, 4, -60, 1);
	now = 100;
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, offer, olen, FRIEND_ADDR, now));

	/* Offer window closes: first Poll; establish window = 10 + 20 = 30 ms. */
	now = 1000;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, lo.action);
	ATF_CHECK_EQ(30u, l.establish_window_ms);

	/* Before the establish window lapses, nothing is due. */
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now + 10, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_NONE, lo.action);

	/* Each lapse retransmits the Poll, up to the retry budget. */
	for (i = 1; i <= MESH_LPN_ESTABLISH_RETRIES; i++) {
		now += 30;
		ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
		ATF_CHECK_EQ(MESH_LPN_ACT_SEND_POLL, lo.action);
		ATF_CHECK_EQ((unsigned)i, l.establish_retries);
	}

	/* Budget exhausted: abandon the Friend and re-Request. */
	now += 30;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);
	ATF_CHECK_EQ(MESH_LPN_ST_REQUESTING, l.state);

	/* Offer collection and PollTimeout remain correct across clock wrap. */
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 10, 100, 1000, 5000);
	now = UINT64_MAX - 499;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, now, &lo));
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now + 999, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_NONE, lo.action);
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_tick(&l, now + 1000, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_REQUEST, lo.action);
	ATF_REQUIRE_EQ(0, mesh_lpn_init(&l.cadence, 100, now));
	mesh_lpn_established(&l.cadence);
	ATF_CHECK_EQ(0, mesh_lpn_friendship_lost(&l.cadence, now + 9999));
	ATF_CHECK_EQ(1, mesh_lpn_friendship_lost(&l.cadence, now + 10000));
}

/* Public API contracts and ignored-input paths around the driven FSM. */
ATF_TC_WITHOUT_HEAD(lpn_api_guard_matrix);
ATF_TC_BODY(lpn_api_guard_matrix, tc)
{
	struct mesh_friend_subconfirm cf;
	struct mesh_friend_update up;
	struct mesh_lpn_fsm l;
	struct mesh_lpn_out lo;
	uint16_t groups[MESH_FRIEND_SUBLIST_ADDR_MAX + 1];
	uint8_t offer[MESH_FRIEND_MSG_MAX], pdu[MESH_FRIEND_MSG_MAX];
	size_t len;
	unsigned i;

	assert_friend_wire_contract();
	/* Initialisation and every pointer contract are deliberately harmless. */
	mesh_lpn_fsm_init(NULL, LPN_ADDR, 1, 0, 0, 1, 10, 100, 10, 50);
	memset(&l, 0xa5, sizeof(l));
	mesh_lpn_fsm_init(&l, LPN_ADDR, 1, 0, 0, 1, 10, 100, 10, 50);
	ATF_CHECK_EQ(MESH_LPN_ST_IDLE, l.state);
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_start(NULL, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_start(&l, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_tick(NULL, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_tick(&l, 0, NULL));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_tick(&l, 0, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_NONE, lo.action);

	len = build_offer(offer, 1, 8, 4, -60, 1);
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_offer(NULL, offer, len, 1, 0));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_offer(&l, NULL, len, 1, 0));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_offer(&l, offer, len, 1, 0));
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_start(&l, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_offer(&l, offer, 1, 1, 0));
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, offer, len, 1, 0));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_offer(&l, offer, len, 1, 0));
	for (i = 2; i <= MESH_LPN_OFFERS_MAX; i++)
		ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_offer(&l, offer, len, i, 0));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_offer(&l, offer, len, 99, 0));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_offer(&l, offer, len, 99, 11));

	/* Update parsing, state checks, More Data scheduling and accessors. */
	memset(&up, 0, sizeof(up));
	up.key_refresh = 1;
	up.iv_update = 1;
	up.iv_index = 0x12345678;
	up.md = 1;
	ATF_REQUIRE_EQ(0, mesh_friend_update_build(&up, pdu, &len));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_update(NULL, pdu, len, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_update(&l, NULL, len, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_update(&l, pdu, len, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_update(&l, pdu, len, 0, &lo));
	l.state = MESH_LPN_ST_ESTABLISHING;
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_update(&l, pdu, 1, 0, &lo));
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_update(&l, pdu, len, 20, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_ESTABLISHED, lo.action);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_key_refresh(&l));
	ATF_CHECK_EQ(0x12345678u, mesh_lpn_fsm_iv_index(&l));
	ATF_CHECK_EQ(20u, l.next_poll_ms);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_update(&l, pdu, len, 21, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_NONE, lo.action);
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_on_message(NULL, 0, 0));
	l.state = MESH_LPN_ST_IDLE;
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_on_message(&l, 0, 0));
	l.state = MESH_LPN_ST_ESTABLISHED;
	ATF_CHECK_EQ(0, mesh_lpn_fsm_on_message(&l, 1, 30));
	ATF_CHECK_EQ(30u, l.next_poll_ms);

	/* Subscription validation and matching/mismatching confirmations. */
	memset(groups, 0, sizeof(groups));
	groups[0] = 0xc001;
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(NULL, 1, groups, 1, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(&l, 1, NULL, 1, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(&l, 1, groups, 1, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(&l, 1, groups, 0, 0, &lo));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(&l, 1, groups,
	    MESH_FRIEND_SUBLIST_ADDR_MAX + 1, 0, &lo));
	l.state = MESH_LPN_ST_IDLE;
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_sub(&l, 1, groups, 1, 0, &lo));
	l.state = MESH_LPN_ST_ESTABLISHED;
	ATF_REQUIRE_EQ(0, mesh_lpn_fsm_sub(&l, 0, groups, 1, 0, &lo));
	ATF_CHECK_EQ(MESH_LPN_ACT_SEND_SUBLIST, lo.action);
	memset(&cf, 0, sizeof(cf));
	cf.transaction = l.sub_transaction + 1;
	ATF_REQUIRE_EQ(0, mesh_friend_subconfirm_build(&cf, pdu, &len));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_subconfirm(NULL, pdu, len));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_subconfirm(&l, NULL, len));
	ATF_CHECK_EQ(-1, mesh_lpn_fsm_recv_subconfirm(&l, pdu, 1));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_subconfirm(&l, pdu, len));
	cf.transaction = l.sub_transaction;
	ATF_REQUIRE_EQ(0, mesh_friend_subconfirm_build(&cf, pdu, &len));
	ATF_CHECK_EQ(1, mesh_lpn_fsm_recv_subconfirm(&l, pdu, len));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_recv_subconfirm(&l, pdu, len));

	ATF_CHECK_EQ(0, mesh_lpn_fsm_established(NULL));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_friend(NULL));
	ATF_CHECK_EQ(0u, mesh_lpn_fsm_iv_index(NULL));
	ATF_CHECK_EQ(0, mesh_lpn_fsm_key_refresh(NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, friendship_lifecycle);
	ATF_TP_ADD_TC(tp, lpn_best_offer);
	ATF_TP_ADD_TC(tp, lpn_no_offer_rerequest);
	ATF_TP_ADD_TC(tp, friendship_sublist);
	ATF_TP_ADD_TC(tp, friend_rejects_weak_request);
	ATF_TP_ADD_TC(tp, lpn_establish_retry);
	ATF_TP_ADD_TC(tp, lpn_api_guard_matrix);

	return (atf_no_error());
}
