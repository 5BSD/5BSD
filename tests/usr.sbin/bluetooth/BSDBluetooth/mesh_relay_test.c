/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh Relay feature + retransmit configuration
 * (mesh_relay.[ch], MshPRT_v1.1 Section 3.4.6 / 3.6.4, Section 4.2.20 /
 * 4.2.21).
 *
 * The relay decision matrix asserts the Section 3.4.6.3 gate directly: a PDU
 * is relayed only when the feature is enabled AND the TTL is >= 2 AND the PDU
 * is not already in the Network Message Cache AND the destination is not one
 * of this node's own addresses; the retransmit TTL is TTL - 1.  The count /
 * interval accessors assert the Section 4.2.20.1 / 4.2.20.2 formulas
 * (transmissions = Count + 1; interval = (Interval Steps + 1) * 10 ms) and the
 * composite Count/Interval-Steps octet packing used by Config Relay Set
 * (Section 4.3.2.13).
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_relay.h"
#include "spec_mesh_relay_oracles.h"

static struct mesh_relay_config
cfg_enabled(void)
{
	struct mesh_relay_config c;

	memset(&c, 0, sizeof(c));
	c.enabled = 1;
	return (c);
}

/* --- Relay decision matrix (Section 3.4.6.3) --- */

ATF_TC_WITHOUT_HEAD(relay_enabled_ttl2_onward);
ATF_TC_BODY(relay_enabled_ttl2_onward, tc)
{
	struct mesh_relay_config c = cfg_enabled();
	uint8_t nt = 0xff;

	/* enabled, TTL 2, not cached, destined onward -> relay with TTL 1. */
	ATF_CHECK_EQ(1, mesh_relay_decide(&c, BT_MESH_SPEC_TTL_RELAY_MIN,
	    0, 0, &nt));
	ATF_CHECK_EQ(BT_MESH_SPEC_TTL_RELAY_MIN - 1, nt);
}

ATF_TC_WITHOUT_HEAD(relay_enabled_ttl127_onward);
ATF_TC_BODY(relay_enabled_ttl127_onward, tc)
{
	struct mesh_relay_config c = cfg_enabled();
	uint8_t nt = 0;

	ATF_CHECK_EQ(1, mesh_relay_decide(&c, BT_MESH_SPEC_TTL_MAX,
	    0, 0, &nt));
	ATF_CHECK_EQ(BT_MESH_SPEC_TTL_MAX - 1, nt);
}

ATF_TC_WITHOUT_HEAD(relay_enabled_ttl1_no_relay);
ATF_TC_BODY(relay_enabled_ttl1_no_relay, tc)
{
	struct mesh_relay_config c = cfg_enabled();
	uint8_t nt = 0x55;

	/* TTL 1 is below the relay threshold (Section 3.4.6.3). */
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, BT_MESH_SPEC_TTL_NO_RELAY_MAX,
	    0, 0, &nt));
	ATF_CHECK_EQ(0x55, nt);		/* untouched */
}

ATF_TC_WITHOUT_HEAD(relay_enabled_ttl0_no_relay);
ATF_TC_BODY(relay_enabled_ttl0_no_relay, tc)
{
	struct mesh_relay_config c = cfg_enabled();

	ATF_CHECK_EQ(0, mesh_relay_decide(&c, 0, 0, 0, NULL));
}

/* Mesh Protocol 1.1.1 Network PDU TTL is 7 bits; 0x80..0xff are reserved. */
ATF_TC_WITHOUT_HEAD(relay_reserved_ttl_no_relay);
ATF_TC_BODY(relay_reserved_ttl_no_relay, tc)
{
	struct mesh_relay_config c = cfg_enabled();
	uint8_t nt = 0x55;

	ATF_CHECK_EQ(0, mesh_relay_decide(&c,
	    BT_MESH_SPEC_TTL_FIRST_RESERVED, 0, 0, &nt));
	ATF_CHECK_EQ(0x55, nt);
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, UINT8_MAX, 0, 0, &nt));
	ATF_CHECK_EQ(0x55, nt);
}

ATF_TC_WITHOUT_HEAD(relay_disabled_never);
ATF_TC_BODY(relay_disabled_never, tc)
{
	struct mesh_relay_config c;

	memset(&c, 0, sizeof(c));
	c.enabled = 0;
	/* Disabled: no relay even with a relayable TTL. */
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, BT_MESH_SPEC_TTL_MAX,
	    0, 0, NULL));
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, BT_MESH_SPEC_TTL_RELAY_MIN,
	    0, 0, NULL));
}

ATF_TC_WITHOUT_HEAD(relay_in_cache_suppressed);
ATF_TC_BODY(relay_in_cache_suppressed, tc)
{
	struct mesh_relay_config c = cfg_enabled();

	/* Already in the Network Message Cache -> do not relay. */
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, 5, 1, 0, NULL));
}

ATF_TC_WITHOUT_HEAD(relay_dst_local_suppressed);
ATF_TC_BODY(relay_dst_local_suppressed, tc)
{
	struct mesh_relay_config c = cfg_enabled();

	/* Destination is one of our own addresses -> do not relay onward. */
	ATF_CHECK_EQ(0, mesh_relay_decide(&c, 5, 0, 1, NULL));
}

ATF_TC_WITHOUT_HEAD(relay_null_cfg);
ATF_TC_BODY(relay_null_cfg, tc)
{

	ATF_CHECK_EQ(0, mesh_relay_decide(NULL, 5, 0, 0, NULL));
}

/* --- Retransmit policy (Section 4.2.20 / 4.2.21) --- */

ATF_TC_WITHOUT_HEAD(relay_tx_count);
ATF_TC_BODY(relay_tx_count, tc)
{

	/* Number of transmissions = Count + 1 (0b000 -> 1, 0b111 -> 8). */
	ATF_CHECK_EQ(1, mesh_relay_tx_count(0));
	ATF_CHECK_EQ(3, mesh_relay_tx_count(2));
	ATF_CHECK_EQ(BT_MESH_SPEC_RETRANS_COUNT_MAX + 1,
	    mesh_relay_tx_count(BT_MESH_SPEC_RETRANS_COUNT_MAX));
	/* Field is masked to 3 bits. */
	ATF_CHECK_EQ(1, mesh_relay_tx_count(
	    1u << BT_MESH_SPEC_RETRANS_COUNT_BITS));
}

ATF_TC_WITHOUT_HEAD(relay_interval_ms);
ATF_TC_BODY(relay_interval_ms, tc)
{

	/* Interval = (Interval Steps + 1) * 10 ms. */
	ATF_CHECK_EQ(BT_MESH_SPEC_RETRANS_STEP_MS,
	    mesh_relay_interval_ms(0));
	/* 0b10000 = 16 -> 170 ms (Section 4.2.20.2 example). */
	ATF_CHECK_EQ(17 * BT_MESH_SPEC_RETRANS_STEP_MS,
	    mesh_relay_interval_ms(0x10));
	ATF_CHECK_EQ((BT_MESH_SPEC_RETRANS_STEPS_MAX + 1) *
	    BT_MESH_SPEC_RETRANS_STEP_MS,
	    mesh_relay_interval_ms(BT_MESH_SPEC_RETRANS_STEPS_MAX));
	/* Field is masked to 5 bits. */
	ATF_CHECK_EQ(BT_MESH_SPEC_RETRANS_STEP_MS,
	    mesh_relay_interval_ms(1u << BT_MESH_SPEC_RETRANS_STEPS_BITS));
}

ATF_TC_WITHOUT_HEAD(relay_pack_unpack);
ATF_TC_BODY(relay_pack_unpack, tc)
{
	uint8_t count, steps;

	/* Count in bits 2..0, Interval Steps in bits 7..3. */
	ATF_CHECK_EQ(0x00, mesh_relay_pack(0, 0));
	/* count=5 (0b101), steps=0b10000 -> 0b10000101 = 0x85. */
	ATF_CHECK_EQ(BT_MESH_SPEC_RETRANS_PACK(5, 0x10),
	    mesh_relay_pack(5, 0x10));
	ATF_CHECK_EQ(BT_MESH_SPEC_RETRANS_PACK(
	    BT_MESH_SPEC_RETRANS_COUNT_MAX, BT_MESH_SPEC_RETRANS_STEPS_MAX),
	    mesh_relay_pack(BT_MESH_SPEC_RETRANS_COUNT_MAX,
	    BT_MESH_SPEC_RETRANS_STEPS_MAX));

	mesh_relay_unpack(BT_MESH_SPEC_RETRANS_PACK(5, 0x10), &count, &steps);
	ATF_CHECK_EQ(5, count);
	ATF_CHECK_EQ(0x10, steps);

	/* NULL outputs are tolerated. */
	mesh_relay_unpack(BT_MESH_SPEC_RETRANS_PACK(5, 0x10), NULL, &steps);
	ATF_CHECK_EQ(0x10, steps);
	mesh_relay_unpack(BT_MESH_SPEC_RETRANS_PACK(5, 0x10), &count, NULL);
	ATF_CHECK_EQ(5, count);
}

ATF_TC_WITHOUT_HEAD(relay_pack_roundtrip_all);
ATF_TC_BODY(relay_pack_roundtrip_all, tc)
{
	unsigned cc, ss;

	/* Every (count, steps) pair round-trips through pack/unpack. */
	for (cc = 0; cc <= BT_MESH_SPEC_RETRANS_COUNT_MAX; cc++) {
		for (ss = 0; ss <= BT_MESH_SPEC_RETRANS_STEPS_MAX; ss++) {
			uint8_t o = mesh_relay_pack((uint8_t)cc, (uint8_t)ss);
			uint8_t rc, rs;

			mesh_relay_unpack(o, &rc, &rs);
			ATF_CHECK_EQ(cc, rc);
			ATF_CHECK_EQ(ss, rs);
		}
	}
}

/* --- Relay Retransmit scheduler (Section 3.4.6.3 / 4.2.21) --- */

ATF_TC_WITHOUT_HEAD(relay_tx_schedule_count3);
ATF_TC_BODY(relay_tx_schedule_count3, tc)
{
	struct mesh_relay_tx j;
	int fired;
	uint64_t t;

	/* Count 3, Interval Steps 0 => 10 ms spacing.  now = 0. */
	mesh_relay_tx_schedule(&j, 3, 0, 0);
	ATF_CHECK_EQ(1, mesh_relay_tx_active(&j));

	/* Nothing before the first interval elapses. */
	ATF_CHECK_EQ(0, mesh_relay_tx_due(&j, 5));
	ATF_CHECK_EQ(0, mesh_relay_tx_fire(&j, 5));

	/* Exactly 3 retransmissions, one per 10 ms step. */
	fired = 0;
	for (t = 0; t <= 100; t += 5)
		fired += mesh_relay_tx_fire(&j, t);
	ATF_CHECK_EQ_MSG(3, fired, "Count 3 must produce exactly 3 retransmits");
	ATF_CHECK_EQ_MSG(0, mesh_relay_tx_active(&j),
	    "schedule must be inactive after the last retransmit");
	/* No further retransmissions once exhausted. */
	ATF_CHECK_EQ(0, mesh_relay_tx_fire(&j, 1000));
}

ATF_TC_WITHOUT_HEAD(relay_tx_interval_spacing);
ATF_TC_BODY(relay_tx_interval_spacing, tc)
{
	struct mesh_relay_tx j;

	/* Interval Steps 1 => 20 ms; first retransmit is due at now + 20. */
	mesh_relay_tx_schedule(&j, 2, 1, 100);
	ATF_CHECK_EQ(0, mesh_relay_tx_due(&j, 119));
	ATF_CHECK_EQ(1, mesh_relay_tx_due(&j, 120));
	ATF_CHECK_EQ(1, mesh_relay_tx_fire(&j, 120));
	/* Second retransmit one interval later, at 140. */
	ATF_CHECK_EQ(0, mesh_relay_tx_due(&j, 139));
	ATF_CHECK_EQ(1, mesh_relay_tx_fire(&j, 140));
	ATF_CHECK_EQ(0, mesh_relay_tx_active(&j));
}

ATF_TC_WITHOUT_HEAD(relay_tx_count_zero);
ATF_TC_BODY(relay_tx_count_zero, tc)
{
	struct mesh_relay_tx j;

	/* Count 0 => no retransmissions scheduled at all. */
	mesh_relay_tx_schedule(&j, 0, 5, 0);
	ATF_CHECK_EQ(0, mesh_relay_tx_active(&j));
	ATF_CHECK_EQ(0, mesh_relay_tx_due(&j, 1000));
	ATF_CHECK_EQ(0, mesh_relay_tx_fire(&j, 1000));
}

ATF_TC_WITHOUT_HEAD(relay_tx_null);
ATF_TC_BODY(relay_tx_null, tc)
{

	/* NULL job is tolerated everywhere. */
	mesh_relay_tx_schedule(NULL, 3, 0, 0);
	ATF_CHECK_EQ(0, mesh_relay_tx_active(NULL));
	ATF_CHECK_EQ(0, mesh_relay_tx_due(NULL, 10));
	ATF_CHECK_EQ(0, mesh_relay_tx_fire(NULL, 10));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, relay_enabled_ttl2_onward);
	ATF_TP_ADD_TC(tp, relay_enabled_ttl127_onward);
	ATF_TP_ADD_TC(tp, relay_enabled_ttl1_no_relay);
	ATF_TP_ADD_TC(tp, relay_enabled_ttl0_no_relay);
	ATF_TP_ADD_TC(tp, relay_reserved_ttl_no_relay);
	ATF_TP_ADD_TC(tp, relay_disabled_never);
	ATF_TP_ADD_TC(tp, relay_in_cache_suppressed);
	ATF_TP_ADD_TC(tp, relay_dst_local_suppressed);
	ATF_TP_ADD_TC(tp, relay_null_cfg);
	ATF_TP_ADD_TC(tp, relay_tx_count);
	ATF_TP_ADD_TC(tp, relay_interval_ms);
	ATF_TP_ADD_TC(tp, relay_pack_unpack);
	ATF_TP_ADD_TC(tp, relay_pack_roundtrip_all);
	ATF_TP_ADD_TC(tp, relay_tx_schedule_count3);
	ATF_TP_ADD_TC(tp, relay_tx_interval_spacing);
	ATF_TP_ADD_TC(tp, relay_tx_count_zero);
	ATF_TP_ADD_TC(tp, relay_tx_null);

	return (atf_no_error());
}
