/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh Heartbeat
 * (mesh_heartbeat.[ch], Mesh Protocol 1.1 Sections 3.6.7,
 * 4.2.18-4.2.19, and 4.3.2.61-4.3.2.66).
 *
 * The asserted bytes are derived from the spec wire layouts, not from the
 * code's output:
 *   - the Heartbeat transport control message (Opcode 0x0A) is big-endian;
 *   - the Config Heartbeat Publication/Subscription messages are little-
 *     endian model messages wrapped with the access opcode;
 *   - CountLog uses the log128 transform value = 2^(CountLog-1); PeriodLog
 *     decodes to 2^(PeriodLog-1) seconds.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_model.h"
#include "mesh_heartbeat.h"
#include "spec_mesh_heartbeat_oracles.h"

static void
assert_heartbeat_assigned_contract(void)
{
	ATF_CHECK_EQ(BT_MESH11_HB_CTL_OPCODE, MESH_HB_CTL_OPCODE);
	ATF_CHECK_EQ(BT_MESH11_HB_FEATURE_RELAY, MESH_HB_FEATURE_RELAY);
	ATF_CHECK_EQ(BT_MESH11_HB_FEATURE_PROXY, MESH_HB_FEATURE_PROXY);
	ATF_CHECK_EQ(BT_MESH11_HB_FEATURE_FRIEND, MESH_HB_FEATURE_FRIEND);
	ATF_CHECK_EQ(BT_MESH11_HB_FEATURE_LOW_POWER, MESH_HB_FEATURE_LOW_POWER);
	ATF_CHECK_EQ(BT_MESH11_HB_FEATURE_MASK, MESH_HB_FEATURE_MASK);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_PUB_STATUS, MESH_CFG_OP_HB_PUB_STATUS);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_PUB_GET, MESH_CFG_OP_HB_PUB_GET);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_PUB_SET, MESH_CFG_OP_HB_PUB_SET);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_SUB_GET, MESH_CFG_OP_HB_SUB_GET);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_SUB_SET, MESH_CFG_OP_HB_SUB_SET);
	ATF_CHECK_EQ(BT_MESH11_CFG_OP_HB_SUB_STATUS, MESH_CFG_OP_HB_SUB_STATUS);
}

/* ================================================================
 * CountLog / PeriodLog transforms (Sections 4.2.18.2-.3 and 4.2.19.3-.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(count_period_log);
ATF_TC_BODY(count_period_log, tc)
{
	assert_heartbeat_assigned_contract();

	/* CountLog: value = 2^(log-1); exact powers of two avoid rounding. */
	ATF_CHECK_EQ_MSG(0x00, mesh_hb_count_log(0), "count 0 -> 0x00");
	ATF_CHECK_EQ_MSG(0x01, mesh_hb_count_log(1), "2^0=1 -> 0x01");
	ATF_CHECK_EQ_MSG(0x02, mesh_hb_count_log(2), "2^1=2 -> 0x02");
	ATF_CHECK_EQ_MSG(0x03, mesh_hb_count_log(4), "2^2=4 -> 0x03");
	ATF_CHECK_EQ_MSG(0x04, mesh_hb_count_log(8), "2^3=8 -> 0x04");
	/* Mesh Protocol 1.1 §§4.2.18.2 and 4.2.19.3: saturated sentinel. */
	ATF_CHECK_EQ_MSG(0xff, mesh_hb_count_log(0xffff), "0xFFFF -> 0xFF");
	/* Rounding up: a non-power value takes the next log. */
	ATF_CHECK_EQ_MSG(0x03, mesh_hb_count_log(3), "3 -> 0x03 (2^2>=3)");

	/* PeriodLog validity 0x00..0x11 and 2^(log-1)-second decode. */
	ATF_CHECK(mesh_hb_period_log_valid(0x00));
	ATF_CHECK(mesh_hb_period_log_valid(0x11));
	ATF_CHECK(!mesh_hb_period_log_valid(0x12));
	ATF_CHECK_EQ_MSG(0u, mesh_hb_period_log_decode(0x00), "0 -> 0s");
	ATF_CHECK_EQ_MSG(1u, mesh_hb_period_log_decode(0x01), "1 -> 1s");
	ATF_CHECK_EQ_MSG(2u, mesh_hb_period_log_decode(0x02), "2 -> 2s");
	ATF_CHECK_EQ_MSG(4u, mesh_hb_period_log_decode(0x03), "3 -> 4s");
	ATF_CHECK_EQ_MSG(65536u, mesh_hb_period_log_decode(0x11), "0x11 -> 2^16s");
}

/* ================================================================
 * Heartbeat transport control message (Section 3.6.7.1): big-endian.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_control_message);
ATF_TC_BODY(hb_control_message, tc)
{
	struct mesh_hb_msg m, p;
	uint8_t out[8];
	size_t outlen;
	/* InitTTL 0x7F, Features = Proxy|LowPower = 0x000A (big-endian). */
	assert_heartbeat_assigned_contract();

	memset(&m, 0, sizeof(m));
	m.init_ttl = 0x7f;
	m.features = MESH_HB_FEATURE_PROXY | MESH_HB_FEATURE_LOW_POWER;

	ATF_REQUIRE_EQ(0, mesh_hb_msg_build(&m, out, &outlen));
	ATF_CHECK_EQ_MSG(3, outlen, "HB message body is 3 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_body_proxy_lpn, 3),
	    "InitTTL||Features BE");
	ATF_REQUIRE_EQ(0, mesh_hb_msg_parse(out, outlen, &p));
	ATF_CHECK_EQ(0x7f, p.init_ttl);
	ATF_CHECK_EQ(0x000a, p.features);

	/* Full unsegmented control PDU: SEG=0|Opcode 0x0A, then body. */
	ATF_REQUIRE_EQ(0, mesh_hb_ctl_pdu_build(&m, out, &outlen));
	ATF_CHECK_EQ_MSG(4, outlen, "HB control PDU is 4 octets");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_ctl_proxy_lpn, 4),
	    "0x0A||InitTTL||Features");
	ATF_REQUIRE_EQ(0, mesh_hb_ctl_pdu_parse(out, outlen, &p));
	ATF_CHECK_EQ(0x7f, p.init_ttl);
	ATF_CHECK_EQ(0x000a, p.features);

	/* Set RFU bits are processed as zero (Mesh 1.1 Section 1.3.2). */
	out[1] = 0xff;
	out[2] = 0xff;
	ATF_REQUIRE_EQ(0, mesh_hb_ctl_pdu_parse(out, 4, &p));
	ATF_CHECK_EQ(0x7f, p.init_ttl);
	ATF_CHECK_EQ(0x000a, p.features);
	/* A wrong control opcode is rejected. */
	out[0] = 0x0b;
	ATF_CHECK_EQ(-1, mesh_hb_ctl_pdu_parse(out, 4, &p));
	/* InitTTL out of range on build. */
	m.init_ttl = 0x80;
	ATF_CHECK_EQ(-1, mesh_hb_msg_build(&m, out, &outlen));
	m.init_ttl = 0x7f;
	m.features = 0x0010;
	ATF_CHECK_EQ(-1, mesh_hb_msg_build(&m, out, &outlen));
}

/* ================================================================
 * Config Heartbeat Publication Set/Status (Sections 4.3.2.62-.63):
 * little-endian model messages.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_publication);
ATF_TC_BODY(hb_publication, tc)
{
	struct mesh_hb_pub pub, got;
	uint8_t out[32];
	size_t outlen;
	uint8_t status;
	/*
	 * Destination 0xC001 (LE 01 C0), CountLog 0x01, PeriodLog 0x02,
	 * TTL 0x07, Features 0x0007 (Relay|Proxy|Friend, LE 07 00),
	 * NetKeyIndex 0x123 (pack1 -> 23 01).  Opcode 0x8039 -> 80 39.
	 */
	/* Status opcode 0x06 (1 octet) + Status(0x00) + the same 9 fields. */
	assert_heartbeat_assigned_contract();

	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xc001;
	pub.count_log = 0x01;
	pub.period_log = 0x02;
	pub.ttl = 0x07;
	pub.features = MESH_HB_FEATURE_RELAY | MESH_HB_FEATURE_PROXY |
	    MESH_HB_FEATURE_FRIEND;
	pub.net_idx = 0x123;

	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, out, &outlen));
	ATF_CHECK_EQ_MSG(11, outlen, "HB Pub Set = 2 opcode + 9 params");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_pub_set_sample, 11),
	    "HB Pub Set wire");
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_parse(out, outlen, &got));
	ATF_CHECK_EQ(0xc001, got.dst);
	ATF_CHECK_EQ(0x01, got.count_log);
	ATF_CHECK_EQ(0x02, got.period_log);
	ATF_CHECK_EQ(0x07, got.ttl);
	ATF_CHECK_EQ(0x0007, got.features);
	ATF_CHECK_EQ(0x123, got.net_idx);
	/* RFU feature bits are ignored by a receiver. */
	out[7] |= 0xf0;
	out[8] = 0xff;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_parse(out, outlen, &got));
	ATF_CHECK_EQ(0x0007, got.features);

	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_build(0x00, &pub, out, &outlen));
	ATF_CHECK_EQ_MSG(11, outlen, "HB Pub Status = 1 opcode + 1 status + 9");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_pub_status_sample, 11),
	    "HB Pub Status wire");
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(out, outlen, &status, &got));
	ATF_CHECK_EQ(0x00, status);
	ATF_CHECK_EQ(0xc001, got.dst);
	ATF_CHECK_EQ(0x123, got.net_idx);

	/* Get carries no parameters: opcode 0x8038. */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(out, &outlen));
	ATF_CHECK_EQ(2, outlen);
	ATF_CHECK_EQ(0x80, out[0]);
	ATF_CHECK_EQ(0x38, out[1]);

	/* An invalid PeriodLog is rejected on build. */
	pub.period_log = 0x12;
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(&pub, out, &outlen));
	pub.period_log = 0x02;
	pub.features = 0x0010;
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(&pub, out, &outlen));
	/* Section 4.2.18.1 permits unassigned, unicast, or group, not virtual. */
	pub.features = 0;
	pub.dst = 0x8000;
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(&pub, out, &outlen));
}

/* ================================================================
 * Config Heartbeat Subscription Set/Status (Sections 4.3.2.65-.66).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_subscription_codec);
ATF_TC_BODY(hb_subscription_codec, tc)
{
	struct mesh_hb_sub_set set, gotset;
	struct mesh_hb_sub_status st, gotst;
	uint8_t out[32];
	size_t outlen;
	/*
	 * Source 0x0002 (LE 02 00), Destination 0xC001 (LE 01 C0),
	 * PeriodLog 0x03.  Opcode 0x803B -> 80 3B.
	 */
	/*
	 * Status 0x00, Src 0x0002, Dst 0xC001, PeriodLog 0x03, CountLog 0x02,
	 * MinHops 0x01, MaxHops 0x03.  Opcode 0x803C -> 80 3C.
	 */
	assert_heartbeat_assigned_contract();

	memset(&set, 0, sizeof(set));
	set.src = 0x0002;
	set.dst = 0xc001;
	set.period_log = 0x03;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&set, out, &outlen));
	ATF_CHECK_EQ_MSG(7, outlen, "HB Sub Set = 2 opcode + 5 params");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_sub_set_sample, 7),
	    "HB Sub Set wire");
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_parse(out, outlen, &gotset));
	ATF_CHECK_EQ(0x0002, gotset.src);
	ATF_CHECK_EQ(0xc001, gotset.dst);
	ATF_CHECK_EQ(0x03, gotset.period_log);

	memset(&st, 0, sizeof(st));
	st.status = 0x00;
	st.src = 0x0002;
	st.dst = 0xc001;
	st.period_log = 0x03;
	st.count_log = 0x02;
	st.min_hops = 0x01;
	st.max_hops = 0x03;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_build(&st, out, &outlen));
	ATF_CHECK_EQ_MSG(11, outlen, "HB Sub Status = 2 opcode + 9 params");
	ATF_CHECK_EQ_MSG(0, memcmp(out, bt_mesh11_hb_sub_status_sample, 11),
	    "HB Sub Status wire");
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(out, outlen, &gotst));
	ATF_CHECK_EQ(0x0002, gotst.src);
	ATF_CHECK_EQ(0xc001, gotst.dst);
	ATF_CHECK_EQ(0x02, gotst.count_log);
	ATF_CHECK_EQ(0x01, gotst.min_hops);
	ATF_CHECK_EQ(0x03, gotst.max_hops);

	/* Get: opcode 0x803A, no params. */
	ATF_REQUIRE_EQ(0, mesh_hb_sub_get_build(out, &outlen));
	ATF_CHECK_EQ(2, outlen);
	ATF_CHECK_EQ(0x80, out[0]);
	ATF_CHECK_EQ(0x3a, out[1]);
}

/* ================================================================
 * Subscription receive logic (Sections 3.6.7.3 and 4.3.2.65).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_subscription_receive);
ATF_TC_BODY(hb_subscription_receive, tc)
{
	struct mesh_hb_sub sub;
	struct mesh_hb_sub_set set;
	struct mesh_hb_sub_status snap;

	assert_heartbeat_assigned_contract();

	mesh_hb_sub_init(&sub);
	ATF_CHECK_EQ_MSG(0x7f, sub.min_hops, "MinHops resets to 0x7F");
	ATF_CHECK_EQ_MSG(0x00, sub.max_hops, "MaxHops resets to 0x00");

	/* Arm the subscription: Src 0x0002, Dst 0xC001, PeriodLog 0x05. */
	memset(&set, 0, sizeof(set));
	set.src = 0x0002;
	set.dst = 0xc001;
	set.period_log = 0x05;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_apply(&sub, &set));

	/* A matching, un-relayed heartbeat: InitTTL==RxTTL -> hops = 1. */
	ATF_CHECK_EQ(1, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
	ATF_CHECK_EQ(1, sub.count);
	ATF_CHECK_EQ_MSG(0x01, sub.min_hops, "hops = InitTTL-RxTTL+1 = 1");
	ATF_CHECK_EQ_MSG(0x01, sub.max_hops, "hops = 1");

	/* Relayed twice: InitTTL 5, RxTTL 3 -> hops = 3. */
	ATF_CHECK_EQ(1, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x03));
	ATF_CHECK_EQ(2, sub.count);
	ATF_CHECK_EQ_MSG(0x01, sub.min_hops, "MinHops stays 1");
	ATF_CHECK_EQ_MSG(0x03, sub.max_hops, "MaxHops rises to 3");

	/* A heartbeat from a different source is ignored. */
	ATF_CHECK_EQ(0, mesh_hb_sub_receive(&sub, 0x0009, 0xc001, 0x05, 0x05));
	ATF_CHECK_EQ(2, sub.count);

	/* Snapshot: CountLog(2) = 0x02, Min/Max hops preserved. */
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ(0x02, snap.count_log);
	ATF_CHECK_EQ(0x01, snap.min_hops);
	ATF_CHECK_EQ(0x03, snap.max_hops);
	ATF_CHECK_EQ(0x0002, snap.src);
	ATF_CHECK_EQ(0xc001, snap.dst);

	/* A Set with PeriodLog 0 disables and resets the subscription. */
	set.period_log = 0x00;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_apply(&sub, &set));
	ATF_CHECK_EQ_MSG(0, sub.src, "disabled subscription clears Src");
	ATF_CHECK_EQ(0, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
}

/* ================================================================
 * Publish-on-feature-change (Section 3.6.7.2).
 * ================================================================ */
/* ================================================================
 * Subscription Period countdown (Section 4.2.19.4): the period is a
 * countdown timer; once it expires heartbeats are no longer processed and
 * the Status reports the REMAINING (decreasing) PeriodLog, not the
 * configured one.  (Regression: finding 74 - period was never counted down.)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_subscription_period_countdown);
ATF_TC_BODY(hb_subscription_period_countdown, tc)
{
	struct mesh_hb_sub sub;
	struct mesh_hb_sub_set set;
	struct mesh_hb_sub_status snap;

	assert_heartbeat_assigned_contract();

	/* PeriodLog 0x03 -> 4-second remaining period. */
	mesh_hb_sub_init(&sub);
	memset(&set, 0, sizeof(set));
	set.src = 0x0002;
	set.dst = 0xc001;
	set.period_log = 0x03;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_apply(&sub, &set));

	/* A matching heartbeat is counted while the period runs. */
	ATF_CHECK_EQ(1, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
	ATF_CHECK_EQ(1, sub.count);

	/* Snapshot before any countdown reports the full remaining PeriodLog. */
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ_MSG(0x03, snap.period_log, "remaining PeriodLog starts at 0x03");

	/*
	 * Advance time and watch the reported PeriodLog decrease as the
	 * remaining period shrinks (4s -> 2s -> 1s).  Heartbeats keep counting
	 * while the period is non-zero.
	 */
	mesh_hb_sub_tick(&sub, 2);		/* 4s -> 2s remaining */
	ATF_CHECK_EQ(1, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
	ATF_CHECK_EQ(2, sub.count);
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ_MSG(0x02, snap.period_log, "2s remaining -> PeriodLog 0x02");

	mesh_hb_sub_tick(&sub, 1);		/* 2s -> 1s remaining */
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ_MSG(0x01, snap.period_log, "1s remaining -> PeriodLog 0x01");

	/*
	 * Advance past the end of the period: it expires, heartbeats are no
	 * longer processed, and the reported PeriodLog reaches 0x00.
	 */
	mesh_hb_sub_tick(&sub, 5);		/* well past 1s remaining */
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ_MSG(0x00, snap.period_log, "expired period -> PeriodLog 0x00");
	ATF_CHECK_EQ_MSG(0, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05),
	    "an expired subscription no longer counts heartbeats");
	ATF_CHECK_EQ_MSG(2, sub.count, "Count frozen after the period expired");
	/* Source/Destination remain configured; only the period is exhausted. */
	ATF_CHECK_EQ(0x0002, snap.src);
	ATF_CHECK_EQ(0xc001, snap.dst);

	/* PeriodLog 0x01 (1s): a single tick expires it. */
	set.period_log = 0x01;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_apply(&sub, &set));
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ(0x01, snap.period_log);
	ATF_CHECK_EQ(1, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
	mesh_hb_sub_tick(&sub, 1);
	ATF_CHECK_EQ(0, mesh_hb_sub_receive(&sub, 0x0002, 0xc001, 0x05, 0x05));
	mesh_hb_sub_snapshot(&sub, MESH_CFG_SUCCESS, &snap);
	ATF_CHECK_EQ(0x00, snap.period_log);

	/* tick() is a no-op on an unsubscribed state. */
	mesh_hb_sub_init(&sub);
	mesh_hb_sub_tick(&sub, 10);
	mesh_hb_sub_tick(NULL, 10);
}

ATF_TC_WITHOUT_HEAD(hb_publish_on_feature_change);
ATF_TC_BODY(hb_publish_on_feature_change, tc)
{
	struct mesh_hb_pub pub;
	struct mesh_hb_msg msg;

	assert_heartbeat_assigned_contract();

	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xc001;
	pub.ttl = 0x04;
	pub.features = MESH_HB_FEATURE_RELAY;	/* only Relay triggers */

	/* Relay turned on (0x0000 -> 0x0001): a Heartbeat is published. */
	ATF_CHECK_EQ(1, mesh_hb_pub_feature_change(&pub, 0x0000,
	    MESH_HB_FEATURE_RELAY, &msg));
	ATF_CHECK_EQ_MSG(0x04, msg.init_ttl, "published InitTTL = pub TTL");
	ATF_CHECK_EQ_MSG(MESH_HB_FEATURE_RELAY, msg.features,
	    "published Features = current features");

	/* Proxy toggled, but Proxy is not in the trigger mask: no publish. */
	ATF_CHECK_EQ(0, mesh_hb_pub_feature_change(&pub, 0x0000,
	    MESH_HB_FEATURE_PROXY, &msg));

	/* Current features reflect all active bits, not just the trigger. */
	ATF_CHECK_EQ(1, mesh_hb_pub_feature_change(&pub,
	    MESH_HB_FEATURE_PROXY,
	    MESH_HB_FEATURE_PROXY | MESH_HB_FEATURE_RELAY, &msg));
	ATF_CHECK_EQ(MESH_HB_FEATURE_PROXY | MESH_HB_FEATURE_RELAY, msg.features);

	/* Publication disabled (dst unassigned): never publishes. */
	pub.dst = MESH_ADDR_UNASSIGNED;
	ATF_CHECK_EQ(0, mesh_hb_pub_feature_change(&pub, 0x0000,
	    MESH_HB_FEATURE_RELAY, &msg));
}

/* ================================================================
 * Periodic Heartbeat publication (Mesh Protocol 1.1 §3.6.7.2): the emitter
 * publishes one Heartbeat per configured Period, decrementing the Count,
 * and stops once the Count is exhausted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hb_periodic_publish);
ATF_TC_BODY(hb_periodic_publish, tc)
{
	struct mesh_hb_pub pub;
	struct mesh_hb_pub_timer t;
	struct mesh_hb_msg msg;
	int i, published;

	assert_heartbeat_assigned_contract();

	/*
	 * CountLog 0x03 -> 4 publications; PeriodLog 0x02 -> 2 seconds.  The
	 * emitter publishes immediately, then every 2 seconds, for 4 messages.
	 */
	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xc005;
	pub.count_log = 0x03;			/* 2^(3-1) = 4 messages */
	pub.period_log = 0x02;			/* 2^(2-1) = 2 seconds */
	pub.ttl = 4;
	pub.features = MESH_HB_FEATURE_RELAY;
	pub.net_idx = 0x000;

	mesh_hb_pub_timer_init(&t, &pub);
	ATF_REQUIRE_EQ_MSG(1, mesh_hb_pub_timer_active(&t),
	    "a configured publication is active");
	ATF_CHECK_EQ(0x03, mesh_hb_pub_timer_count_log(&t));

	/*
	 * Section 3.6.7.2 requires the first message as soon as possible after
	 * configuration.  The remaining messages follow at two-second periods.
	 */
	published = mesh_hb_pub_timer_tick(&t, 0, MESH_HB_FEATURE_RELAY, &msg);
	ATF_REQUIRE_EQ(1, published);
	ATF_CHECK_EQ(4, msg.init_ttl);
	ATF_CHECK_EQ(MESH_HB_FEATURE_RELAY, msg.features);
	for (i = 0; i < 10; i++) {
		if (mesh_hb_pub_timer_tick(&t, 2, MESH_HB_FEATURE_RELAY, &msg)) {
			published++;
			ATF_CHECK_EQ(4, msg.init_ttl);
			ATF_CHECK_EQ(MESH_HB_FEATURE_RELAY, msg.features);
		}
	}
	ATF_CHECK_EQ_MSG(4, published, "exactly Count (4) periodic publishes");
	ATF_CHECK_EQ_MSG(0, mesh_hb_pub_timer_active(&t),
	    "the timer stops once the Count is exhausted");
	ATF_CHECK_EQ(0x00, mesh_hb_pub_timer_count_log(&t));

	/* After the immediate publication, two one-second ticks cross a period. */
	mesh_hb_pub_timer_init(&t, &pub);
	ATF_CHECK_EQ(1, mesh_hb_pub_timer_tick(&t, 0, 0, &msg));
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_tick(&t, 1, 0, &msg));
	ATF_CHECK_EQ(1, mesh_hb_pub_timer_tick(&t, 1, 0, &msg));

	/* A disabled publication (dst unassigned) never fires. */
	pub.dst = MESH_ADDR_UNASSIGNED;
	mesh_hb_pub_timer_init(&t, &pub);
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_active(&t));
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_tick(&t, 100, 0, &msg));

	/* PeriodLog 0 also disables periodic publication. */
	pub.dst = 0xc005;
	pub.period_log = 0x00;
	mesh_hb_pub_timer_init(&t, &pub);
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_active(&t));

	/* CountLog 0xFF publishes indefinitely (never exhausts). */
	pub.period_log = 0x01;			/* 1 second */
	pub.count_log = 0xff;
	mesh_hb_pub_timer_init(&t, &pub);
	ATF_CHECK_EQ(0xff, mesh_hb_pub_timer_count_log(&t));
	for (i = 0; i < 50; i++)
		(void)mesh_hb_pub_timer_tick(&t, 1, 0, &msg);
	ATF_CHECK_EQ_MSG(1, mesh_hb_pub_timer_active(&t),
	    "indefinite publication never exhausts");
}

ATF_TC_WITHOUT_HEAD(guard_and_boundary_completion);
ATF_TC_BODY(guard_and_boundary_completion, tc)
{
	struct mesh_hb_msg msg;
	struct mesh_hb_pub pub;
	struct mesh_hb_pub_timer timer;
	struct mesh_hb_sub_set set;
	struct mesh_hb_sub_status status;
	struct mesh_hb_sub sub;
	uint8_t buf[32] = { 0 }, st;
	size_t len;

	assert_heartbeat_assigned_contract();

	ATF_CHECK_EQ(0xff, mesh_hb_count_log(0xffff));
	ATF_CHECK_EQ(0u, mesh_hb_period_log_decode(0));
	ATF_CHECK_EQ(0u, mesh_hb_period_log_decode(0x12));

	memset(&msg, 0, sizeof(msg));
	msg.init_ttl = 0x80;
	ATF_CHECK_EQ(-1, mesh_hb_msg_build(&msg, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_msg_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_msg_parse(buf, 3, NULL));
	buf[0] = 0x80;
	ATF_CHECK_EQ(0, mesh_hb_msg_parse(buf, 3, &msg));
	ATF_CHECK_EQ(0, msg.init_ttl);
	msg.init_ttl = 0x80;
	ATF_CHECK_EQ(-1, mesh_hb_ctl_pdu_build(&msg, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_ctl_pdu_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_ctl_pdu_parse(buf, 4, NULL));
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ(-1, mesh_hb_ctl_pdu_parse(buf, 4, &msg));

	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xc001;
	pub.count_log = 1;
	pub.period_log = 1;
	pub.ttl = 1;
	pub.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(&pub, buf, &len));
	pub.net_idx = 0;
	pub.period_log = 0x12;
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(&pub, buf, &len));
	pub.period_log = 1;
	pub.count_log = 0x12;
	ATF_CHECK_EQ(-1, mesh_hb_pub_status_build(0, &pub, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_parse(NULL, 0, &pub));
	ATF_CHECK_EQ(-1, mesh_hb_pub_set_parse(buf, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_hb_pub_status_build(0, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_pub_status_parse(NULL, 0, &st, &pub));
	ATF_CHECK_EQ(-1, mesh_hb_pub_status_parse(buf, 1, &st, NULL));
	ATF_CHECK_EQ(-1, mesh_hb_pub_feature_change(NULL, 0, 0, &msg));
	ATF_CHECK_EQ(-1, mesh_hb_pub_feature_change(&pub, 0, 0, NULL));

	mesh_hb_pub_timer_init(NULL, &pub);
	mesh_hb_pub_timer_init(&timer, NULL);
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_active(NULL));
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_tick(&timer, 1, 0, NULL));
	ATF_CHECK_EQ(0, mesh_hb_pub_timer_count_log(NULL));

	memset(&set, 0, sizeof(set));
	set.period_log = 0x12;
	ATF_CHECK_EQ(-1, mesh_hb_sub_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_sub_set_build(&set, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_sub_set_parse(NULL, 0, &set));
	ATF_CHECK_EQ(-1, mesh_hb_sub_set_parse(buf, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_hb_sub_status_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_sub_status_parse(NULL, 0, &status));
	ATF_CHECK_EQ(-1, mesh_hb_sub_status_parse(buf, 1, NULL));
	mesh_hb_sub_init(NULL);
	ATF_CHECK_EQ(-1, mesh_hb_sub_apply(NULL, &set));
	mesh_hb_sub_init(&sub);
	ATF_CHECK_EQ(-1, mesh_hb_sub_apply(&sub, NULL));
	set.period_log = 0x12;
	ATF_CHECK_EQ(-1, mesh_hb_sub_apply(&sub, &set));
	set.src = 0xc001;
	set.dst = 0xc002;
	set.period_log = 1;
	ATF_CHECK_EQ(-1, mesh_hb_sub_apply(&sub, &set));
	/* Section 4.2.19.2 prohibits virtual subscription destinations. */
	set.src = 1;
	set.dst = 0x8000;
	ATF_CHECK_EQ(-1, mesh_hb_sub_set_build(&set, buf, &len));
	ATF_CHECK_EQ(-1, mesh_hb_sub_apply(&sub, &set));
	/* A saturated Subscription Count snapshots as CountLog 0xFF. */
	sub.src = 1;
	sub.dst = 0xc001;
	sub.count = 0xffff;
	mesh_hb_sub_snapshot(&sub, 0, &status);
	ATF_CHECK_EQ(0xff, status.count_log);
	ATF_CHECK_EQ(0, mesh_hb_sub_receive(NULL, 1, 2, 1, 1));
	sub.src = 1;
	sub.dst = 0xc001;
	ATF_CHECK_EQ(0, mesh_hb_sub_receive(&sub, 1, 0xc001, 1, 2));
	mesh_hb_sub_snapshot(&sub, 0, NULL);
	mesh_hb_sub_snapshot(NULL, 0, &status);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, count_period_log);
	ATF_TP_ADD_TC(tp, hb_control_message);
	ATF_TP_ADD_TC(tp, hb_publication);
	ATF_TP_ADD_TC(tp, hb_subscription_codec);
	ATF_TP_ADD_TC(tp, hb_subscription_receive);
	ATF_TP_ADD_TC(tp, hb_subscription_period_countdown);
	ATF_TP_ADD_TC(tp, hb_publish_on_feature_change);
	ATF_TP_ADD_TC(tp, hb_periodic_publish);
	ATF_TP_ADD_TC(tp, guard_and_boundary_completion);

	return (atf_no_error());
}
