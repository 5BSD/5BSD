/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh Directed Forwarding engine
 * (mesh_df.[ch], MshPRT_v1.1 Section 3.6.6 and MshMDL_v1.1 Section 4.4.2).
 *
 * The tests assert the documented wire layout of each PDU/model message (field
 * order, bit packing and endianness) against hand-computed spec bytes, exercise
 * the Forwarding Table (add/lookup/expire) and Forwarding Number wrap rules,
 * and drive the path discovery lifecycle (Request -> Reply -> Confirm ->
 * forward-along-path -> expire) with a mock millisecond clock.  No test asserts
 * captured runtime output; every expected value is derived from the spec field
 * layout.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_df.h"
#include "spec_mesh_df_oracles.h"

/* ================================================================
 * Unicast address range sub-codec (Section 3.6.6.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(addr_range_single);
ATF_TC_BODY(addr_range_single, tc)
{
	struct mesh_df_addr_range r = { .range_start = 0x0123, .range_length = 1 };
	struct mesh_df_addr_range back;
	uint8_t buf[3];
	size_t len, used;

	ATF_REQUIRE_EQ(0, mesh_df_addr_range_build(&r, buf, &len));
	/* Length_Present=0: word = range_start << 1 = 0x0246, big-endian. */
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_RANGE_SINGLE_SIZE, len);
	ATF_REQUIRE_EQ(0x02, buf[0]);
	ATF_REQUIRE_EQ(0x46, buf[1]);

	ATF_REQUIRE_EQ(0, mesh_df_addr_range_parse(buf, len, &back, &used));
	ATF_REQUIRE_EQ(2, used);
	ATF_REQUIRE_EQ(0x0123, back.range_start);
	ATF_REQUIRE_EQ(1, back.range_length);
}

ATF_TC_WITHOUT_HEAD(addr_range_multi);
ATF_TC_BODY(addr_range_multi, tc)
{
	struct mesh_df_addr_range r = { .range_start = 0x0100, .range_length = 5 };
	struct mesh_df_addr_range back;
	uint8_t buf[3];
	size_t len, used;

	ATF_REQUIRE_EQ(0, mesh_df_addr_range_build(&r, buf, &len));
	/* Length_Present=1: word = (0x0100 << 1) | 1 = 0x0201; length octet 5. */
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_RANGE_MULTI_SIZE, len);
	ATF_REQUIRE_EQ(0x02, buf[0]);
	ATF_REQUIRE_EQ(0x01, buf[1]);
	ATF_REQUIRE_EQ(0x05, buf[2]);

	ATF_REQUIRE_EQ(0, mesh_df_addr_range_parse(buf, len, &back, &used));
	ATF_REQUIRE_EQ(3, used);
	ATF_REQUIRE_EQ(0x0100, back.range_start);
	ATF_REQUIRE_EQ(5, back.range_length);
}

ATF_TC_WITHOUT_HEAD(addr_range_rejects);
ATF_TC_BODY(addr_range_rejects, tc)
{
	struct mesh_df_addr_range r = { .range_start = 0xC000, .range_length = 1 };
	uint8_t buf[3];
	size_t len;

	/* Non-unicast range start is rejected. */
	ATF_REQUIRE_EQ(-1, mesh_df_addr_range_build(&r, buf, &len));

	/* The half-open range end may not exceed 0x8000. */
	r.range_start = 0x7fff;
	r.range_length = 2;
	ATF_REQUIRE_EQ(-1, mesh_df_addr_range_build(&r, buf, &len));
	buf[0] = 0xff; buf[1] = 0xff; buf[2] = 2;
	ATF_REQUIRE_EQ(-1, mesh_df_addr_range_parse(buf, sizeof(buf), &r,
	    &len));
}

/* ================================================================
 * Path Request (0x0B).  Section 3.6.6.5.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(path_request_codec);
ATF_TC_BODY(path_request_codec, tc)
{
	struct mesh_df_path_request in, out;
	uint8_t buf[16];
	size_t len;

	memset(&in, 0, sizeof(in));
	in.metric_type = MESH_DF_METRIC_NODE_COUNT;	/* 0 */
	in.lifetime = MESH_DF_LIFETIME_2_HOUR;		/* 1 */
	in.path_discovery_interval = 1;
	in.forwarding_number = 0x2A;
	in.path_metric = 0;
	in.destination = 0x0005;			/* Path Target */
	in.origin.range_start = 0x0001;
	in.origin.range_length = 1;

	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&in, buf, &len));
	/*
	 * o0: OBO=0, metric_type=0 (<<4), lifetime=1 (<<2 => 0x04),
	 *     path_discovery_interval=1 (<<1 => 0x02) => 0x06.
	 * o1: forwarding_number 0x2A.
	 * o2: path_metric 0 << 1 => 0x00.
	 * o3-o4: destination 0x0005 big-endian.
	 * o5-o6: origin range 0x0001 single => 0x0002.
	 */
	ATF_REQUIRE_EQ(7, len);
	ATF_REQUIRE_EQ(0x06, buf[0]);
	ATF_REQUIRE_EQ(0x2A, buf[1]);
	ATF_REQUIRE_EQ(0x00, buf[2]);
	ATF_REQUIRE_EQ(0x00, buf[3]);
	ATF_REQUIRE_EQ(0x05, buf[4]);
	ATF_REQUIRE_EQ(0x00, buf[5]);
	ATF_REQUIRE_EQ(0x02, buf[6]);

	ATF_REQUIRE_EQ(0, mesh_df_path_request_parse(buf, len, &out));
	ATF_REQUIRE_EQ(0, out.on_behalf_of_dependent_origin);
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_LIFETIME_2_HOUR, out.lifetime);
	ATF_REQUIRE_EQ(1, out.path_discovery_interval);
	ATF_REQUIRE_EQ(0x2A, out.forwarding_number);
	ATF_REQUIRE_EQ(0x0005, out.destination);
	ATF_REQUIRE_EQ(0x0001, out.origin.range_start);
}

ATF_TC_WITHOUT_HEAD(path_request_dependent_origin);
ATF_TC_BODY(path_request_dependent_origin, tc)
{
	struct mesh_df_path_request in, out;
	uint8_t buf[16];
	size_t len;

	memset(&in, 0, sizeof(in));
	in.on_behalf_of_dependent_origin = 1;
	in.forwarding_number = 1;
	in.destination = 0x0007;
	in.origin.range_start = 0x0002;
	in.origin.range_length = 1;
	in.dependent_origin.range_start = 0x0003;
	in.dependent_origin.range_length = 2;

	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&in, buf, &len));
	/* OBO bit set => dependent origin range appended (3 octets, length 2). */
	ATF_REQUIRE_EQ(0x80, (uint8_t)(buf[0] & 0x80));
	ATF_REQUIRE_EQ(7 + 3, len);

	ATF_REQUIRE_EQ(0, mesh_df_path_request_parse(buf, len, &out));
	ATF_REQUIRE_EQ(1, out.on_behalf_of_dependent_origin);
	ATF_REQUIRE_EQ(0x0003, out.dependent_origin.range_start);
	ATF_REQUIRE_EQ(2, out.dependent_origin.range_length);
}

/* ================================================================
 * Path Reply (0x0C).  Section 3.6.6.5.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(path_reply_codec);
ATF_TC_BODY(path_reply_codec, tc)
{
	struct mesh_df_path_reply in, out;
	uint8_t buf[16];
	size_t len;

	memset(&in, 0, sizeof(in));
	in.confirmation_request = 1;
	in.forwarding_number = 0x2A;
	in.path_origin = 0x0001;
	in.target.range_start = 0x0005;
	in.target.range_length = 1;

	ATF_REQUIRE_EQ(0, mesh_df_path_reply_build(&in, buf, &len));
	/*
	 * o0: OBO=0, confirmation_request=1 (bit6) => 0x40.
	 * o1: forwarding_number 0x2A.
	 * o2-o3: path_origin 0x0001 big-endian.
	 * o4-o5: target range single 0x0005 => 0x000A.
	 */
	ATF_REQUIRE_EQ(6, len);
	ATF_REQUIRE_EQ(0x40, buf[0]);
	ATF_REQUIRE_EQ(0x2A, buf[1]);
	ATF_REQUIRE_EQ(0x00, buf[2]);
	ATF_REQUIRE_EQ(0x01, buf[3]);
	ATF_REQUIRE_EQ(0x00, buf[4]);
	ATF_REQUIRE_EQ(0x0A, buf[5]);

	ATF_REQUIRE_EQ(0, mesh_df_path_reply_parse(buf, len, &out));
	ATF_REQUIRE_EQ(1, out.confirmation_request);
	ATF_REQUIRE_EQ(0x2A, out.forwarding_number);
	ATF_REQUIRE_EQ(0x0001, out.path_origin);
	ATF_REQUIRE_EQ(0x0005, out.target.range_start);
}

/* ================================================================
 * Path Confirmation / Echo / Dependent Update / Solicitation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(path_confirmation_codec);
ATF_TC_BODY(path_confirmation_codec, tc)
{
	struct mesh_df_path_confirmation in = { .path_origin = 0x0001,
	    .path_target = 0x0005 };
	struct mesh_df_path_confirmation out;
	uint8_t buf[4];
	size_t len;

	ATF_REQUIRE_EQ(0, mesh_df_path_confirmation_build(&in, buf, &len));
	ATF_REQUIRE_EQ(4, len);
	ATF_REQUIRE_EQ(0x00, buf[0]);
	ATF_REQUIRE_EQ(0x01, buf[1]);
	ATF_REQUIRE_EQ(0x00, buf[2]);
	ATF_REQUIRE_EQ(0x05, buf[3]);
	ATF_REQUIRE_EQ(0, mesh_df_path_confirmation_parse(buf, len, &out));
	ATF_REQUIRE_EQ(0x0001, out.path_origin);
	ATF_REQUIRE_EQ(0x0005, out.path_target);
}

ATF_TC_WITHOUT_HEAD(path_echo_codec);
ATF_TC_BODY(path_echo_codec, tc)
{
	uint8_t buf[4];
	size_t len;
	uint16_t dst;

	ATF_REQUIRE_EQ(0, mesh_df_path_echo_request_build(buf, &len));
	ATF_REQUIRE_EQ(0, len);			/* echo request has no parameters */

	ATF_REQUIRE_EQ(0, mesh_df_path_echo_reply_build(0x0005, buf, &len));
	ATF_REQUIRE_EQ(2, len);
	ATF_REQUIRE_EQ(0x00, buf[0]);
	ATF_REQUIRE_EQ(0x05, buf[1]);
	ATF_REQUIRE_EQ(0, mesh_df_path_echo_reply_parse(buf, len, &dst));
	ATF_REQUIRE_EQ(0x0005, dst);
}

ATF_TC_WITHOUT_HEAD(dependent_update_codec);
ATF_TC_BODY(dependent_update_codec, tc)
{
	struct mesh_df_dependent_update in, out;
	uint8_t buf[8];
	size_t len;

	memset(&in, 0, sizeof(in));
	in.type = MESH_DF_DEP_ADD;
	in.path_endpoint = 0x0001;
	in.dependent.range_start = 0x0009;
	in.dependent.range_length = 1;

	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_build(&in, buf, &len));
	ATF_REQUIRE_EQ(5, len);
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_DEP_ADD, buf[0]);
	ATF_REQUIRE_EQ(0x00, buf[1]);
	ATF_REQUIRE_EQ(0x01, buf[2]);
	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_parse(buf, len, &out));
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_DEP_ADD, out.type);
	ATF_REQUIRE_EQ(0x0001, out.path_endpoint);
	ATF_REQUIRE_EQ(0x0009, out.dependent.range_start);
}

ATF_TC_WITHOUT_HEAD(solicitation_codec);
ATF_TC_BODY(solicitation_codec, tc)
{
	uint16_t in[3] = { 0x0005, 0x0006, 0x0007 };
	uint16_t out[3];
	uint8_t buf[8];
	size_t len, n;

	ATF_REQUIRE_EQ(0, mesh_df_path_solicitation_build(in, 3, buf, &len));
	ATF_REQUIRE_EQ(6, len);
	ATF_REQUIRE_EQ(0x00, buf[0]);
	ATF_REQUIRE_EQ(0x05, buf[1]);
	ATF_REQUIRE_EQ(0x07, buf[5]);
	ATF_REQUIRE_EQ(0, mesh_df_path_solicitation_parse(buf, len, out, 3, &n));
	ATF_REQUIRE_EQ(3, n);
	ATF_REQUIRE_EQ(0x0006, out[1]);
}

/* ================================================================
 * Forwarding Number wrap rules (Section 3.6.6.5).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(forwarding_number_wrap);
ATF_TC_BODY(forwarding_number_wrap, tc)
{

	ATF_REQUIRE_EQ(1, mesh_df_fn_next(0));
	ATF_REQUIRE_EQ(0, mesh_df_fn_next(BT_MSHPRT11_DF_FN_MAX));

	/* Serial-number freshness: b newer than a when (b-a) in 1..127. */
	ATF_REQUIRE_EQ(1, mesh_df_fn_newer(0, 1));
	ATF_REQUIRE_EQ(1, mesh_df_fn_newer(255, 0));	/* across the wrap */
	ATF_REQUIRE_EQ(0, mesh_df_fn_newer(1, 0));
	ATF_REQUIRE_EQ(0, mesh_df_fn_newer(5, 5));	/* equal is not newer */
	ATF_REQUIRE_EQ(0, mesh_df_fn_newer(0, 200));	/* 200 is "older" (>127) */
}

/* ================================================================
 * Forwarding Table add / lookup / expire (Section 3.6.6.5), mock clock.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fwd_table_add_lookup);
ATF_TC_BODY(fwd_table_add_lookup, tc)
{
	struct mesh_df_fwd_table t;
	struct mesh_df_fwd_entry *e;
	uint64_t now = 1000;

	mesh_df_table_init(&t);
	e = mesh_df_table_add(&t, 0x0001, 0x0005, 0x2A, 1, 2,
	    mesh_df_lifetime_ms[MESH_DF_LIFETIME_12_MIN], now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(1, t.count);
	ATF_REQUIRE_EQ(0, e->fixed_path);

	/* dst == target selects the entry; dst == origin selects it too. */
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0005, now) == e);
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0005, 0x0001, now) == e);
	/* Unknown dst has no path. */
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0099, now) == NULL);

	/* Dependent of the target is reachable through the same entry. */
	ATF_REQUIRE_EQ(0, mesh_df_entry_add_dependent(e, 1, 0x0006));
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0006, now) == e);
	ATF_CHECK_EQ(0, mesh_df_entry_add_dependent(e, 1, 0x0006));
	ATF_CHECK_EQ(-1, mesh_df_entry_add_dependent(NULL, 1, 0x0007));
	ATF_CHECK_EQ(-1, mesh_df_entry_add_dependent(e, 1, 0));
	ATF_CHECK_EQ(0, mesh_df_entry_add_dependent(e, 0, 0x0007));
	ATF_CHECK_EQ(0, mesh_df_entry_add_dependent(e, 0, 0x0007));
	ATF_CHECK_EQ(-1, mesh_df_entry_del_dependent(NULL, 1, 0x0006));
	ATF_CHECK_EQ(0, mesh_df_entry_del_dependent(e, 1, 0x0006));
	ATF_CHECK_EQ(0, mesh_df_entry_del_dependent(e, 1, 0x0006));
	ATF_CHECK_EQ(0, mesh_df_entry_del_dependent(e, 0, 0x0007));
	ATF_CHECK_EQ(-1, mesh_df_table_delete(NULL, 1, 5));
	ATF_CHECK_EQ(-1, mesh_df_table_delete(&t, 9, 10));
	ATF_CHECK_EQ(0, mesh_df_table_delete(&t, 1, 5));
	ATF_CHECK_EQ(0, t.count);
	ATF_CHECK_EQ(-1, mesh_df_table_delete(&t, 1, 5));
}

ATF_TC_WITHOUT_HEAD(fwd_table_expire);
ATF_TC_BODY(fwd_table_expire, tc)
{
	struct mesh_df_fwd_table t;
	struct mesh_df_fwd_entry *e;
	uint64_t now = 0;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_12_MIN];

	mesh_df_table_init(&t);
	e = mesh_df_table_add(&t, 0x0001, 0x0005, 1, 1, 2, life, now);
	ATF_REQUIRE(e != NULL);

	/* Still valid one ms before the lifetime elapses. */
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0005, life - 1) != NULL);
	ATF_REQUIRE_EQ(0, mesh_df_table_expire(&t, life - 1));

	/* Expired at the lifetime boundary. */
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0005, life) == NULL);
	ATF_REQUIRE_EQ(1, mesh_df_table_expire(&t, life));
	ATF_REQUIRE_EQ(0, t.count);
}

ATF_TC_WITHOUT_HEAD(fwd_table_fixed_path);
ATF_TC_BODY(fwd_table_fixed_path, tc)
{
	struct mesh_df_fwd_table t;
	struct mesh_df_fwd_entry *e;

	mesh_df_table_init(&t);
	/* lifetime 0 => a fixed path that never expires. */
	e = mesh_df_table_add(&t, 0x0001, 0x0005, 1, 1, 2, 0, 0);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(1, e->fixed_path);
	ATF_REQUIRE_EQ(0, mesh_df_table_expire(&t, (uint64_t)1 << 40));
	ATF_REQUIRE(mesh_df_table_lookup(&t, 0x0001, 0x0005,
	    (uint64_t)1 << 40) == e);
}

/* ================================================================
 * Directed forwarding decision (Section 3.6.6.5).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(forward_decide);
ATF_TC_BODY(forward_decide, tc)
{
	struct mesh_df_fwd_table t;
	struct mesh_df_features feat;
	struct mesh_df_fwd_entry *matched;
	uint8_t new_ttl;
	uint64_t now = 100;

	mesh_df_table_init(&t);
	memset(&feat, 0, sizeof(feat));

	/* No features, no table entry: drop even a high-TTL PDU. */
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DROP,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl, now,
	    &matched));

	/* Managed-flood relay on, no path: flood with decremented TTL. */
	feat.managed_flood_relay = 1;
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_FLOOD,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl, now,
	    &matched));
	ATF_REQUIRE_EQ(4, new_ttl);
	ATF_REQUIRE(matched == NULL);

	/* TTL 1 is never forwarded (managed flooding or directed). */
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DROP,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 1, &new_ttl, now,
	    &matched));

	/* Directed relay on with a matching path: forward along the path. */
	mesh_df_table_add(&t, 0x0001, 0x0005, 1, 1, 2,
	    mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR], now);
	feat.directed_relay = 1;
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DIRECTED,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl, now,
	    &matched));
	ATF_REQUIRE_EQ(4, new_ttl);
	ATF_REQUIRE(matched != NULL);
	ATF_REQUIRE_EQ(now, matched->last_used_ms);

	/* Directed feature on but dst has no path: fall back to flooding. */
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_FLOOD,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x00AA, 5, &new_ttl, now,
	    &matched));
}

/* ================================================================
 * Path discovery lifecycle with a mock clock:
 *   Request -> Reply -> Confirm -> forward-along-path -> expire.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(discovery_lifecycle);
ATF_TC_BODY(discovery_lifecycle, tc)
{
	struct mesh_df_discovery d;
	struct mesh_df_path_request req;
	struct mesh_df_path_reply rep;
	struct mesh_df_path_confirmation conf;
	struct mesh_df_fwd_table t;
	struct mesh_df_features feat;
	struct mesh_df_fwd_entry *e;
	uint8_t fn, new_ttl;
	int need_confirm = 0;
	uint64_t now = 0;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR];

	mesh_df_table_init(&t);
	memset(&feat, 0, sizeof(feat));
	feat.directed_relay = 1;

	/* Origin 0x0001 advances its Forwarding Number and starts discovery. */
	fn = mesh_df_fn_next(0);
	ATF_REQUIRE_EQ(0, mesh_df_discovery_start(&d, 0x0001, 0x0005, fn,
	    MESH_DF_METRIC_NODE_COUNT, MESH_DF_LIFETIME_2_HOUR, 1, 1,
	    /*timeout*/ 2000, now, &req));
	ATF_REQUIRE_EQ(MESH_DF_DISC_REQUEST_SENT, d.state);
	ATF_REQUIRE_EQ(fn, req.forwarding_number);
	ATF_REQUIRE_EQ(0x0005, req.destination);
	ATF_REQUIRE_EQ(0x0001, req.origin.range_start);

	/* A non-matching reply (wrong forwarding number) is ignored. */
	memset(&rep, 0, sizeof(rep));
	rep.path_origin = 0x0001;
	rep.forwarding_number = (uint8_t)(fn + 7);
	rep.target.range_start = 0x0005;
	rep.target.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_discovery_on_reply(&d, &rep, &need_confirm));
	ATF_REQUIRE_EQ(MESH_DF_DISC_REQUEST_SENT, d.state);

	/* The Path Target replies; the origin accepts and a confirm is due. */
	rep.forwarding_number = fn;
	rep.confirmation_request = 1;
	now = 500;
	ATF_REQUIRE_EQ(1, mesh_df_discovery_on_reply(&d, &rep, &need_confirm));
	ATF_REQUIRE_EQ(MESH_DF_DISC_REPLY_RECEIVED, d.state);
	ATF_REQUIRE_EQ(1, need_confirm);
	ATF_REQUIRE_EQ(1, d.lane_counter);

	/* Origin sends the Path Confirmation and the path is established. */
	ATF_REQUIRE_EQ(0, mesh_df_discovery_confirm(&d, &conf));
	ATF_REQUIRE_EQ(MESH_DF_DISC_ESTABLISHED, d.state);
	ATF_REQUIRE_EQ(0x0001, conf.path_origin);
	ATF_REQUIRE_EQ(0x0005, conf.path_target);

	/* Install the resulting Forwarding Table entry and forward along it. */
	e = mesh_df_table_add(&t, d.origin, d.target, d.forwarding_number,
	    1, 2, life, now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DIRECTED,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl,
	    now, NULL));

	/* The path expires once its lifetime elapses; discovery must restart. */
	now += life;
	ATF_REQUIRE_EQ(1, mesh_df_table_expire(&t, now));
	feat.managed_flood_relay = 0;
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DROP,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl,
	    now, NULL));
}

ATF_TC_WITHOUT_HEAD(discovery_timeout);
ATF_TC_BODY(discovery_timeout, tc)
{
	struct mesh_df_discovery d;
	struct mesh_df_path_request req;
	uint64_t now = 1000;

	ATF_REQUIRE_EQ(0, mesh_df_discovery_start(&d, 0x0001, 0x0005, 1,
	    MESH_DF_METRIC_NODE_COUNT, MESH_DF_LIFETIME_12_MIN, 1, 0,
	    /*timeout*/ 3000, now, &req));

	/* Not yet timed out. */
	ATF_REQUIRE_EQ(0, mesh_df_discovery_timed_out(&d, now + 2999));
	ATF_REQUIRE_EQ(MESH_DF_DISC_REQUEST_SENT, d.state);

	/* Times out at the boundary and moves to FAILED. */
	ATF_REQUIRE_EQ(1, mesh_df_discovery_timed_out(&d, now + 3000));
	ATF_REQUIRE_EQ(MESH_DF_DISC_FAILED, d.state);
}

/* ================================================================
 * Directed Forwarding Configuration model codecs (MshMDL Section 4.4.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cfg_directed_control);
ATF_TC_BODY(cfg_directed_control, tc)
{
	struct mesh_cfg_directed_control in, out;
	struct mesh_access_pdu ap;
	uint8_t buf[16];
	size_t len;
	uint8_t status;
	uint16_t idx;
	static const uint8_t get_ref[] = { 0x80, 0x7b, 0x23, 0x01 };
	static const uint8_t set_ref[] = {
		0x80, 0x7c, 0x10, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01
	};
	static const uint8_t status_ref[] = {
		0x80, 0x7d, 0x00, 0x10, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01
	};

	/* Get: opcode 0x807C? No, GET is 0x807B; NetKeyIndex little-endian. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_build(0x0123, buf, &len));
	ATF_REQUIRE_EQ(sizeof(get_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, get_ref, sizeof(get_ref)));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(buf, len, &ap));
	ATF_REQUIRE_EQ(BT_MSHMDL111_DF_OP_CONTROL_GET, ap.opcode);
	ATF_REQUIRE_EQ(0x23, ap.params[0]);	/* LE low octet */
	ATF_REQUIRE_EQ(0x01, ap.params[1]);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_parse(buf, len, &idx));
	ATF_REQUIRE_EQ(0x0123, idx);
	/* RFU bits in the packed 12-bit NetKeyIndex are ignored on receive. */
	buf[3] |= 0xf0;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_parse(buf, len, &idx));
	ATF_REQUIRE_EQ(0x0123, idx);

	memset(&in, 0, sizeof(in));
	in.net_idx = 0x0010;
	in.directed_forwarding = 1;
	in.directed_relay = 1;
	in.directed_proxy = 1;
	in.directed_proxy_use_directed_default = 2;
	in.directed_friend = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, set_ref, sizeof(set_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_parse(buf, len, &out));
	ATF_REQUIRE_EQ(0x0010, out.net_idx);
	ATF_REQUIRE_EQ(1, out.directed_forwarding);
	ATF_REQUIRE_EQ(2, out.directed_proxy_use_directed_default);
	ATF_REQUIRE_EQ(1, out.directed_friend);

	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_build(
	    MESH_CFG_STATUS_SUCCESS, &in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(status_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, status_ref, sizeof(status_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(buf, len,
	    &status, &out));
	ATF_REQUIRE_EQ(BT_MSHMDL111_CFG_STATUS_SUCCESS, status);
	ATF_REQUIRE_EQ(1, out.directed_relay);
}

ATF_TC_WITHOUT_HEAD(cfg_path_metric);
ATF_TC_BODY(cfg_path_metric, tc)
{
	struct mesh_cfg_path_metric in, out;
	struct mesh_access_pdu ap;
	uint8_t buf[8];
	size_t len;
	uint8_t status;
	static const uint8_t set_ref[] = {
		0x80, 0x7f, 0x01, 0x00, 0x10
	};
	static const uint8_t status_ref[] = {
		0x80, 0x80, 0x00, 0x01, 0x00, 0x10
	};

	memset(&in, 0, sizeof(in));
	in.net_idx = 0x0001;
	in.metric_type = MESH_DF_METRIC_NODE_COUNT;	/* 0 */
	in.lifetime = MESH_DF_LIFETIME_24_HOUR;		/* 2 */

	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_set_build(&in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, set_ref, sizeof(set_ref)));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(buf, len, &ap));
	/* packed octet = metric_type | (lifetime << 3) = 0 | (2<<3) = 0x10. */
	ATF_REQUIRE_EQ(0x10, ap.params[2]);
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_set_parse(buf, len, &out));
	ATF_REQUIRE_EQ(BT_MSHPRT11_DF_LIFETIME_24_HOUR, out.lifetime);

	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_status_build(
	    MESH_CFG_STATUS_SUCCESS, &in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(status_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, status_ref, sizeof(status_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_status_parse(buf, len, &status,
	    &out));
	ATF_REQUIRE_EQ(BT_MSHMDL111_CFG_STATUS_SUCCESS, status);
	ATF_REQUIRE_EQ(0x0001, out.net_idx);
}

ATF_TC_WITHOUT_HEAD(cfg_lanes_two_way_echo);
ATF_TC_BODY(cfg_lanes_two_way_echo, tc)
{
	struct mesh_cfg_wanted_lanes wl = { .net_idx = 0x0002, .wanted_lanes = 3 };
	struct mesh_cfg_wanted_lanes wl_out;
	struct mesh_cfg_two_way_path tw = { .net_idx = 0x0002, .two_way_path = 1 };
	struct mesh_cfg_two_way_path tw_out;
	struct mesh_cfg_path_echo_interval pe = { .net_idx = 0x0002,
	    .unicast_echo_interval = 20, .multicast_echo_interval = 40 };
	struct mesh_cfg_path_echo_interval pe_out;
	uint8_t buf[8];
	size_t len;
	uint8_t status;
	static const uint8_t lanes_set_ref[] = {
		0x80, 0x91, 0x02, 0x00, 0x03
	};
	static const uint8_t lanes_status_ref[] = {
		0x80, 0x92, 0x00, 0x02, 0x00, 0x03
	};
	static const uint8_t two_way_set_ref[] = {
		0x80, 0x94, 0x02, 0x00, 0x01
	};
	static const uint8_t echo_set_ref[] = {
		0x80, 0x97, 0x02, 0x00, 0x14, 0x28
	};

	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_set_build(&wl, buf, &len));
	ATF_REQUIRE_EQ(sizeof(lanes_set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, lanes_set_ref, sizeof(lanes_set_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_set_parse(buf, len, &wl_out));
	ATF_REQUIRE_EQ(3, wl_out.wanted_lanes);
	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_status_build(
	    MESH_CFG_STATUS_SUCCESS, &wl, buf, &len));
	ATF_REQUIRE_EQ(sizeof(lanes_status_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, lanes_status_ref,
	    sizeof(lanes_status_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_status_parse(buf, len, &status,
	    &wl_out));
	ATF_REQUIRE_EQ(3, wl_out.wanted_lanes);

	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_set_build(&tw, buf, &len));
	ATF_REQUIRE_EQ(sizeof(two_way_set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, two_way_set_ref,
	    sizeof(two_way_set_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_set_parse(buf, len, &tw_out));
	ATF_REQUIRE_EQ(1, tw_out.two_way_path);

	ATF_REQUIRE_EQ(0, mesh_cfg_path_echo_interval_set_build(&pe, buf, &len));
	ATF_REQUIRE_EQ(sizeof(echo_set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, echo_set_ref, sizeof(echo_set_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_path_echo_interval_set_parse(buf, len, &pe_out));
	ATF_REQUIRE_EQ(20, pe_out.unicast_echo_interval);
	ATF_REQUIRE_EQ(40, pe_out.multicast_echo_interval);
}

ATF_TC_WITHOUT_HEAD(cfg_directed_transmit);
ATF_TC_BODY(cfg_directed_transmit, tc)
{
	struct mesh_cfg_transmit in = { .count = 2, .interval_steps = 5 };
	struct mesh_cfg_transmit out;
	struct mesh_access_pdu ap;
	uint8_t buf[8];
	size_t len;
	uint32_t opcode;
	static const uint8_t net_set_ref[] = { 0x80, 0x9a, 0x2a };
	static const uint8_t relay_status_ref[] = { 0x80, 0x9e, 0x2a };

	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_build(
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET, &in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(net_set_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, net_set_ref, sizeof(net_set_ref)));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(buf, len, &ap));
	/* octet = count | (interval_steps << 3) = 2 | (5<<3) = 0x2A. */
	ATF_REQUIRE_EQ(0x2A, ap.params[0]);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_parse(buf, len, &opcode,
	    &out));
	ATF_REQUIRE_EQ(BT_MSHMDL111_DF_OP_NET_TX_SET, opcode);
	ATF_REQUIRE_EQ(2, out.count);
	ATF_REQUIRE_EQ(5, out.interval_steps);

	/* The Relay Retransmit variant shares the format. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_build(
	    MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS, &in, buf, &len));
	ATF_REQUIRE_EQ(sizeof(relay_status_ref), len);
	ATF_REQUIRE_EQ(0, memcmp(buf, relay_status_ref,
	    sizeof(relay_status_ref)));
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_parse(buf, len, &opcode,
	    &out));
	ATF_REQUIRE_EQ(BT_MSHMDL111_DF_OP_RELAY_TX_STATUS, opcode);
}

/* ================================================================
 * Non-origin path discovery roles (MshPRT_v1.1 Section 3.6.6.5).
 *
 * A three-node line: Path Origin 0x0001 - relay 0x0002 - Path Target 0x0005.
 * The relay and target run mesh_df_recv_control(); the origin drives its own
 * role through the discovery state machine.  Bearer ids model the links from
 * each node's own point of view: at the relay, bearer 1 faces the origin and
 * bearer 2 faces the target; at the target, bearer 9 faces the relay.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(nonorigin_multihop_lifecycle);
ATF_TC_BODY(nonorigin_multihop_lifecycle, tc)
{
	struct mesh_df_node relay, target;
	struct mesh_df_discovery d;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	struct mesh_df_path_reply rep;
	struct mesh_df_path_confirmation conf;
	struct mesh_df_fwd_entry *re, *te;
	uint8_t reqbuf[16], repbuf[16], confbuf[8];
	size_t reqlen, replen, conflen;
	uint8_t fn, new_ttl;
	int need_confirm = 0;
	uint64_t now = 1000;

	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	mesh_df_node_init(&target, 0x0005, 0x0005, MESH_DF_LIFETIME_2_HOUR, 1);

	/* Origin 0x0001 starts a discovery toward 0x0005 and sends the Request. */
	fn = mesh_df_fn_next(0x41);
	ATF_REQUIRE_EQ(0, mesh_df_discovery_start(&d, 0x0001, 0x0005, fn,
	    MESH_DF_METRIC_NODE_COUNT, MESH_DF_LIFETIME_2_HOUR, 1, 1,
	    /*timeout*/ 4000, now, &req));
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));

	/* Relay receives the Request from the origin on bearer 1, TTL 5. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));

	/* Reverse entry installed toward the origin; forward half not yet known. */
	re = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE(re != NULL);
	ATF_REQUIRE(mesh_df_entry_reverse_valid(re));
	ATF_REQUIRE(!mesh_df_entry_forward_valid(re));
	ATF_REQUIRE_EQ(1, re->bearer_toward_origin);
	ATF_REQUIRE_EQ(fn, re->forwarding_number);
	ATF_REQUIRE_EQ(1, relay.table.count);

	/* Re-forwarded as a managed flood, TTL decremented, node-count metric+1. */
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_REQUEST, out.opcode);
	ATF_REQUIRE_EQ(MESH_DF_BEARER_FLOOD, out.bearer);
	ATF_REQUIRE_EQ(4, out.ttl);
	ATF_REQUIRE_EQ(0x02, out.pdu[2]);	/* path_metric 1, <<1 => 0x02 */

	/* Capture the forwarded Request before the next call rewrites *out. */
	{
		uint8_t fwd[16];
		size_t fwdlen = out.pdulen;
		uint8_t fwdttl = out.ttl;

		memcpy(fwd, out.pdu, fwdlen);

		/* A duplicate Request (same origin + forwarding number) is deduped. */
		ATF_REQUIRE_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&relay,
		    &ctx, MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));
		ATF_REQUIRE_EQ(1, relay.table.count);	/* no second entry */

		/* Target receives the forwarded Request on bearer 9 and replies. */
		memset(&ctx, 0, sizeof(ctx));
		ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = fwdttl; ctx.bearer = 9;
		ctx.now = now;
		ATF_REQUIRE_EQ(MESH_DF_RECV_FOR_TARGET, mesh_df_recv_control(&target,
		    &ctx, MESH_DF_OP_PATH_REQUEST, fwd, fwdlen, &out));
	}
	te = mesh_df_table_lookup(&target.table, 0x0001, 0x0005, now);
	ATF_REQUIRE(te != NULL);
	ATF_REQUIRE(mesh_df_entry_reverse_valid(te));
	ATF_REQUIRE_EQ(9, te->bearer_toward_origin);

	/* Reply: OBO=0, Confirmation_Request=1 (target two_way_path), fn, origin. */
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_REPLY, out.opcode);
	ATF_REQUIRE_EQ(9, out.bearer);		/* back along the reverse path */
	ATF_REQUIRE_EQ(0x0001, out.dst);
	ATF_REQUIRE_EQ(0x40, out.pdu[0]);	/* Confirmation_Request bit6 */
	ATF_REQUIRE_EQ(fn, out.pdu[1]);
	memcpy(repbuf, out.pdu, out.pdulen);
	replen = out.pdulen;

	/* Relay receives the Reply from the target on bearer 2, installs forward. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0005; ctx.dst = 0x0001; ctx.ttl = 5; ctx.bearer = 2;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REPLY, repbuf, replen, &out));
	re = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE(re != NULL);
	ATF_REQUIRE(mesh_df_entry_forward_valid(re));
	ATF_REQUIRE_EQ(2, re->bearer_toward_target);
	/* Reply forwarded back toward the origin on the reverse bearer. */
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_REPLY, out.opcode);
	ATF_REQUIRE_EQ(1, out.bearer);
	ATF_REQUIRE_EQ(0x0001, out.dst);
	ATF_REQUIRE_EQ(4, out.ttl);

	/* Origin accepts the forwarded Reply and completes with a Confirmation. */
	ATF_REQUIRE_EQ(0, mesh_df_path_reply_parse(out.pdu, out.pdulen, &rep));
	ATF_REQUIRE_EQ(1, mesh_df_discovery_on_reply(&d, &rep, &need_confirm));
	ATF_REQUIRE_EQ(1, need_confirm);
	ATF_REQUIRE_EQ(0, mesh_df_discovery_confirm(&d, &conf));
	ATF_REQUIRE_EQ(MESH_DF_DISC_ESTABLISHED, d.state);
	ATF_REQUIRE_EQ(0, mesh_df_path_confirmation_build(&conf, confbuf, &conflen));

	/* Confirmation transits the relay: lane locked, forwarded to the target. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_CONFIRMATION, confbuf, conflen, &out));
	re = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(1, re->backward_validated);	/* lane locked */
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_CONFIRMATION, out.opcode);
	ATF_REQUIRE_EQ(2, out.bearer);			/* toward the target */

	/* Target consumes the Confirmation and locks its lane. */
	memcpy(confbuf, out.pdu, out.pdulen);
	conflen = out.pdulen;
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = out.ttl; ctx.bearer = 9;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&target, &ctx,
	    MESH_DF_OP_PATH_CONFIRMATION, confbuf, conflen, &out));
	te = mesh_df_table_lookup(&target.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(1, te->backward_validated);

	/* The relay now carries a full path: directed forwarding both ways. */
	{
		struct mesh_df_features feat;

		memset(&feat, 0, sizeof(feat));
		feat.directed_relay = 1;
		ATF_REQUIRE_EQ(MESH_DF_FORWARD_DIRECTED,
		    mesh_df_forward_decide(&relay.table, &feat, 0x0001, 0x0005,
		    5, &new_ttl, now, NULL));
	}
}

/*
 * A Request whose forwarding number is newer (serial arithmetic) re-processes
 * the same path and resets the forward half; a Reply reaching the Path Origin
 * node terminates with FOR_ORIGIN rather than being forwarded.
 */
ATF_TC_WITHOUT_HEAD(nonorigin_fn_refresh_and_origin);
ATF_TC_BODY(nonorigin_fn_refresh_and_origin, tc)
{
	struct mesh_df_node relay, origin;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	struct mesh_df_path_reply rep;
	struct mesh_df_fwd_entry *e;
	uint8_t reqbuf[16], repbuf[16];
	size_t reqlen, replen;
	uint64_t now = 0;

	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);

	/* First Request with fn=0x10 installs the reverse entry. */
	memset(&req, 0, sizeof(req));
	req.forwarding_number = 0x10;
	req.destination = 0x0005;
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(0x10, e->forwarding_number);

	/* Mark the forward half as if a reply had arrived (non-zero bearer). */
	e->bearer_toward_target = 2;
	ATF_REQUIRE(mesh_df_entry_forward_valid(e));

	/* A newer forwarding number (0x11) re-processes and resets the forward. */
	req.forwarding_number = 0x11;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	ctx.bearer = 3;			/* origin now reachable via a new bearer */
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(0x11, e->forwarding_number);
	ATF_REQUIRE_EQ(3, e->bearer_toward_origin);
	ATF_REQUIRE(!mesh_df_entry_forward_valid(e));	/* forward half reset */
	ATF_REQUIRE_EQ(1, relay.table.count);

	/* An older forwarding number (0x0F) is deduped (serial arithmetic). */
	req.forwarding_number = 0x0F;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	ATF_REQUIRE_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));

	/* At the Path Origin node a matching Reply terminates the path. */
	mesh_df_node_init(&origin, 0x0001, 0x0001, MESH_DF_LIFETIME_2_HOUR, 0);
	e = mesh_df_table_add(&origin.table, 0x0001, 0x0005, 0x20, 4,
	    MESH_DF_BEARER_NONE, mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR],
	    now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE(mesh_df_entry_reverse_valid(e));	/* bearer 4 toward origin */
	memset(&rep, 0, sizeof(rep));
	rep.forwarding_number = 0x20;
	rep.path_origin = 0x0001;
	rep.target.range_start = 0x0005;
	rep.target.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_reply_build(&rep, repbuf, &replen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0005; ctx.dst = 0x0001; ctx.ttl = 5; ctx.bearer = 4;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FOR_ORIGIN, mesh_df_recv_control(&origin,
	    &ctx, MESH_DF_OP_PATH_REPLY, repbuf, replen, &out));
	e = mesh_df_table_lookup(&origin.table, 0x0001, 0x0005, now);
	ATF_REQUIRE(mesh_df_entry_forward_valid(e));
}

/*
 * Path Echo keep-alive (Section 3.6.6.5.4): an Echo Request/Reply refreshes the
 * path; an unanswered Echo Request invalidates the path at its deadline.  Also
 * covers the endpoint answering an Echo Request addressed to it.
 */
ATF_TC_WITHOUT_HEAD(nonorigin_path_echo);
ATF_TC_BODY(nonorigin_path_echo, tc)
{
	struct mesh_df_node node, target;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_fwd_entry *e;
	uint8_t rbuf[4];
	size_t rlen;
	uint64_t now = 1000;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR];

	/* A node with an established path toward 0x0005 (forward bearer 2). */
	mesh_df_node_init(&node, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	e = mesh_df_table_add(&node.table, 0x0002, 0x0005, 0x30, 0, 2, life, now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE(mesh_df_entry_forward_valid(e));	/* bearer 2 toward target */

	/* Send an Echo Request toward the target; it becomes echo-pending. */
	ATF_REQUIRE_EQ(0, mesh_df_echo_start(&node, 0x0005, 5, /*timeout*/ 2000,
	    now, &out));
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_ECHO_REQUEST, out.opcode);
	ATF_REQUIRE_EQ(2, out.bearer);
	ATF_REQUIRE_EQ(0, out.pdulen);		/* Echo Request has no parameters */
	ATF_REQUIRE_EQ(1, mesh_df_echo_is_pending(&node, 0x0005));

	/* An Echo Reply from the target clears the pending state and keeps alive. */
	ATF_REQUIRE_EQ(0, mesh_df_path_echo_reply_build(0x0005, rbuf, &rlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0005; ctx.dst = 0x0002; ctx.ttl = 5; ctx.bearer = 2;
	ctx.now = now + 500;
	ATF_REQUIRE_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_ECHO_REPLY, rbuf, rlen, &out));
	ATF_REQUIRE_EQ(0, mesh_df_echo_is_pending(&node, 0x0005));
	e = mesh_df_table_lookup(&node.table, 0x0002, 0x0005, now + 500);
	ATF_REQUIRE_EQ(now + 500, e->install_ms);	/* lifetime refreshed */

	/* No expiry while nothing is pending. */
	ATF_REQUIRE_EQ(0, mesh_df_echo_expire(&node, now + 100000));

	/* A second Echo Request that goes unanswered invalidates the path. */
	ATF_REQUIRE_EQ(0, mesh_df_echo_start(&node, 0x0005, 5, /*timeout*/ 2000,
	    now + 1000, &out));
	ATF_REQUIRE_EQ(0, mesh_df_echo_expire(&node, now + 1000 + 1999));
	ATF_REQUIRE_EQ(1, mesh_df_echo_expire(&node, now + 1000 + 2000));
	ATF_REQUIRE(mesh_df_table_lookup(&node.table, 0x0002, 0x0005,
	    now + 3000) == NULL);
	ATF_REQUIRE_EQ(0, node.table.count);

	/* The addressed endpoint answers an Echo Request with its own address. */
	mesh_df_node_init(&target, 0x0005, 0x0005, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 4; ctx.bearer = 9;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FOR_TARGET, mesh_df_recv_control(&target,
	    &ctx, MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_ECHO_REPLY, out.opcode);
	ATF_REQUIRE_EQ(2, out.pdulen);
	ATF_REQUIRE_EQ(0x00, out.pdu[0]);	/* Destination 0x0005 big-endian */
	ATF_REQUIRE_EQ(0x05, out.pdu[1]);
	ATF_REQUIRE_EQ(9, out.bearer);
	ATF_REQUIRE_EQ(0x0001, out.dst);
}

/*
 * Dependent Node Update (Section 3.6.6.5.6): a relay tracks a dependent address
 * behind the Path Target, then untracks it on a remove.
 */
ATF_TC_WITHOUT_HEAD(nonorigin_dependent_update);
ATF_TC_BODY(nonorigin_dependent_update, tc)
{
	struct mesh_df_node relay;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_dependent_update du;
	struct mesh_df_fwd_entry *e;
	uint8_t buf[8];
	size_t len;
	uint64_t now = 1000;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR];

	/* Relay with a full path 0x0001 <-> 0x0005 (origin bearer 1, target 2). */
	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	e = mesh_df_table_add(&relay.table, 0x0001, 0x0005, 0x40, 1, 2, life, now);
	ATF_REQUIRE(e != NULL);		/* bearers 1/2 => reverse+forward valid */

	/* Add dependent 0x0006 behind the Path Target 0x0005. */
	memset(&du, 0, sizeof(du));
	du.type = MESH_DF_DEP_ADD;
	du.path_endpoint = 0x0005;
	du.dependent.range_start = 0x0006;
	du.dependent.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_build(&du, buf, &len));

	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	/* Update travels toward the endpoint 0x0005 on the forward bearer. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_DEPENDENT_NODE_UPDATE, buf, len, &out));
	ATF_REQUIRE_EQ(2, out.bearer);
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(1, e->dep_target_n);
	ATF_REQUIRE_EQ(0x0006, e->dep_target[0]);
	/* The dependent is now reachable via this entry. */
	ATF_REQUIRE(mesh_df_table_lookup(&relay.table, 0x0001, 0x0006, now) == e);

	/* A remove untracks it. */
	du.type = MESH_DF_DEP_REMOVE;
	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_build(&du, buf, &len));
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_DEPENDENT_NODE_UPDATE, buf, len, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE_EQ(0, e->dep_target_n);
}

ATF_TC_WITHOUT_HEAD(remaining_forwarding_paths);
ATF_TC_BODY(remaining_forwarding_paths, tc)
{
	struct mesh_df_node relay, full;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_fwd_entry *e;
	struct mesh_df_path_request req;
	struct mesh_df_dependent_update du;
	uint8_t buf[16];
	size_t len, i;
	uint64_t now = 1000;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR];

	mesh_df_node_init(&relay, 0x0002, 0x0002,
	    MESH_DF_LIFETIME_2_HOUR, 0);
	e = mesh_df_table_add(&relay.table, 0x0001, 0x0005, 1, 3, 7,
	    life, now);
	ATF_REQUIRE(e != NULL);

	/* An Echo Request follows the target-facing half of a matched path. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001;
	ctx.dst = 0x0005;
	ctx.ttl = 4;
	ctx.bearer = 3;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));
	ATF_CHECK_EQ(MESH_DF_OP_PATH_ECHO_REQUEST, out.opcode);
	ATF_CHECK_EQ(7, out.bearer);
	ATF_CHECK_EQ(3, out.ttl);

	/* A Reply follows the origin-facing half and preserves its two bytes. */
	ATF_REQUIRE_EQ(0, mesh_df_path_echo_reply_build(0x0005, buf, &len));
	ctx.src = 0x0005;
	ctx.dst = 0x0001;
	ctx.bearer = 7;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_PATH_ECHO_REPLY, buf, len, &out));
	ATF_CHECK_EQ(MESH_DF_OP_PATH_ECHO_REPLY, out.opcode);
	ATF_CHECK_EQ(3, out.bearer);
	ATF_CHECK_EQ(0, memcmp(buf, out.pdu, len));

	/* Missing path, absent bearer and exhausted TTL fail closed. */
	ctx.src = 0x0010;
	ctx.dst = 0x0011;
	ATF_CHECK_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));
	ctx.src = 0x0001;
	ctx.dst = 0x0005;
	e->bearer_toward_target = MESH_DF_BEARER_NONE;
	ATF_CHECK_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));
	e->bearer_toward_target = 7;
	ctx.ttl = 1;
	ATF_CHECK_EQ(MESH_DF_RECV_CONSUMED, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));

	/* Origin-side dependent updates take the opposite lookup/forward arm. */
	memset(&du, 0, sizeof(du));
	du.type = MESH_DF_DEP_ADD;
	du.path_endpoint = 0x0001;
	du.dependent.range_start = 0x0008;
	du.dependent.range_length = 2;
	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_build(&du, buf, &len));
	ctx.src = 0x0005;
	ctx.dst = 0x0001;
	ctx.ttl = 4;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_DEPENDENT_NODE_UPDATE, buf, len, &out));
	ATF_CHECK_EQ(3, out.bearer);
	ATF_CHECK_EQ(2, e->dep_origin_n);
	du.type = MESH_DF_DEP_REMOVE;
	ATF_REQUIRE_EQ(0, mesh_df_dependent_update_build(&du, buf, &len));
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_DEPENDENT_NODE_UPDATE, buf, len, &out));
	ATF_CHECK_EQ(0, e->dep_origin_n);

	/* A request made for a dependent origin records the complete range. */
	memset(&req, 0, sizeof(req));
	req.on_behalf_of_dependent_origin = 1;
	req.forwarding_number = 2;
	req.destination = 0x0006;
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	req.dependent_origin.range_start = 0x0008;
	req.dependent_origin.range_length = 2;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, buf, &len));
	ctx.src = 0x0001;
	ctx.dst = 0x0006;
	ctx.ttl = 4;
	ctx.bearer = 5;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay,
	    &ctx, MESH_DF_OP_PATH_REQUEST, buf, len, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0006, now);
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(2, e->dep_origin_n);

	/* A saturated forwarding table rejects a new discovery deterministically. */
	mesh_df_node_init(&full, 0x0002, 0x0002,
	    MESH_DF_LIFETIME_2_HOUR, 0);
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		full.table.entries[i].valid = 1;
		full.table.entries[i].path_origin = (uint16_t)(0x0100 + i);
		full.table.entries[i].path_target = (uint16_t)(0x0200 + i);
	}
	full.table.count = MESH_DF_MAX_ENTRIES;
	ATF_CHECK_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&full, &ctx,
	    MESH_DF_OP_PATH_REQUEST, buf, len, &out));
}

/*
 * Length-gating: every non-origin handler rejects a truncated control PDU
 * without over-reading, and an unknown opcode drops.
 */
ATF_TC_WITHOUT_HEAD(nonorigin_truncated_pdus);
ATF_TC_BODY(nonorigin_truncated_pdus, tc)
{
	struct mesh_df_node node;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	uint8_t buf[8] = { 0 };

	mesh_df_node_init(&node, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;

	/* Path Request needs >= 7 octets. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_REQUEST, buf, 3, &out));
	/* Path Reply needs >= 6 octets. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_REPLY, buf, 2, &out));
	/* Path Confirmation is exactly 4 octets. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_CONFIRMATION, buf, 3, &out));
	/* Echo Request carries no parameters; any parameter is invalid. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_ECHO_REQUEST, buf, 1, &out));
	/* Echo Reply is exactly 2 octets. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_ECHO_REPLY, buf, 1, &out));
	/* Dependent Node Update needs >= 5 octets. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_DEPENDENT_NODE_UPDATE, buf, 2, &out));
	/* A NULL body with a non-zero length is rejected. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_REQUEST, NULL, 7, &out));
	/* An unknown transport-control opcode drops. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_DROP, mesh_df_recv_control(&node, &ctx,
	    0x7F, buf, 4, &out));
}

ATF_TC_WITHOUT_HEAD(codec_guard_matrix);
ATF_TC_BODY(codec_guard_matrix, tc)
{
	struct mesh_df_addr_range range = { .range_start = 1, .range_length = 1 };
	struct mesh_df_path_request request;
	struct mesh_df_path_reply reply;
	struct mesh_df_path_confirmation confirmation;
	struct mesh_df_dependent_update update;
	struct mesh_cfg_directed_control dc;
	struct mesh_cfg_path_metric metric;
	struct mesh_cfg_wanted_lanes lanes;
	struct mesh_cfg_two_way_path two_way;
	struct mesh_cfg_path_echo_interval echo;
	struct mesh_cfg_transmit tx;
	struct mesh_df_fwd_table table;
	struct mesh_df_fwd_entry *entry, *matched;
	struct mesh_df_discovery discovery;
	struct mesh_df_node node;
	struct mesh_df_output output;
	struct mesh_df_features features;
	uint8_t buf[32] = { 0 }, status;
	uint16_t u16, dests[2] = { 1, 2 };
	uint32_t opcode;
	size_t len, used, n;

	/* Transport-control codecs reject missing outputs and malformed ranges. */
	ATF_CHECK_EQ(-1, mesh_df_addr_range_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_addr_range_build(&range, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_df_addr_range_build(&range, buf, NULL));
	range.range_length = 0;
	ATF_CHECK_EQ(-1, mesh_df_addr_range_build(&range, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_addr_range_parse(NULL, 0, &range, &used));
	ATF_CHECK_EQ(-1, mesh_df_addr_range_parse(buf, 1, &range, &used));
	buf[0] = buf[1] = 0;
	ATF_CHECK_EQ(-1, mesh_df_addr_range_parse(buf, 2, &range, &used));
	buf[1] = 3; /* start=1, Length_Present=1, but no length octet. */
	ATF_CHECK_EQ(-1, mesh_df_addr_range_parse(buf, 2, &range, &used));
	buf[2] = 1;
	ATF_CHECK_EQ(-1, mesh_df_addr_range_parse(buf, 3, &range, &used));

	memset(&request, 0, sizeof(request));
	request.origin.range_start = 1;
	request.origin.range_length = 1;
	request.destination = 2;
	ATF_CHECK_EQ(-1, mesh_df_path_request_build(NULL, buf, &len));
	request.metric_type = 8;
	ATF_CHECK_EQ(-1, mesh_df_path_request_build(&request, buf, &len));
	request.metric_type = 0;
	request.destination = 0x8000;
	ATF_CHECK_EQ(-1, mesh_df_path_request_build(&request, buf, &len));
	request.destination = 2;
	request.origin.range_length = 0;
	ATF_CHECK_EQ(-1, mesh_df_path_request_build(&request, buf, &len));
	request.origin.range_length = 1;
	request.on_behalf_of_dependent_origin = 1;
	ATF_CHECK_EQ(-1, mesh_df_path_request_build(&request, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_request_parse(NULL, 0, &request));
	ATF_CHECK_EQ(-1, mesh_df_path_request_parse(buf, 6, &request));
	memset(buf, 0, sizeof(buf));
	buf[3] = 0; buf[4] = 2; /* valid target, invalid zero Origin range */
	ATF_CHECK_EQ(-1, mesh_df_path_request_parse(buf, 7, &request));
	buf[0] = 0x80; buf[5] = 1; buf[6] = 0;
	ATF_CHECK_EQ(-1, mesh_df_path_request_parse(buf, 7, &request));

	memset(&reply, 0, sizeof(reply));
	reply.path_origin = 1;
	reply.target.range_start = 2;
	reply.target.range_length = 1;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_build(NULL, buf, &len));
	reply.path_origin = 0;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_build(&reply, buf, &len));
	reply.path_origin = 1; reply.target.range_length = 0;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_build(&reply, buf, &len));
	reply.target.range_length = 1; reply.on_behalf_of_dependent_target = 1;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_build(&reply, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_reply_parse(NULL, 0, &reply));
	ATF_CHECK_EQ(-1, mesh_df_path_reply_parse(buf, 5, &reply));
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ(-1, mesh_df_path_reply_parse(buf, 6, &reply));
	buf[2] = 0; buf[3] = 1;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_parse(buf, 6, &reply));
	buf[0] = 0x80; buf[4] = 2; buf[5] = 0;
	ATF_CHECK_EQ(-1, mesh_df_path_reply_parse(buf, 6, &reply));

	memset(&confirmation, 0, sizeof(confirmation));
	ATF_CHECK_EQ(-1, mesh_df_path_confirmation_build(NULL, buf, &len));
	ATF_CHECK_EQ(0, mesh_df_path_confirmation_build(&confirmation, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_df_path_confirmation_parse(NULL, 0,
	    &confirmation));
	ATF_CHECK_EQ(0, mesh_df_path_echo_request_build(NULL, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_echo_reply_build(0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_echo_reply_parse(NULL, 0, &u16));

	memset(&update, 0, sizeof(update));
	ATF_CHECK_EQ(-1, mesh_df_dependent_update_build(NULL, buf, &len));
	update.type = 2;
	ATF_CHECK_EQ(-1, mesh_df_dependent_update_build(&update, buf, &len));
	update.type = 0; update.path_endpoint = 1;
	ATF_CHECK_EQ(-1, mesh_df_dependent_update_build(&update, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_dependent_update_parse(NULL, 0, &update));
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ(-1, mesh_df_dependent_update_parse(buf, 5, &update));
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_build(NULL, 1, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_build(dests, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_build(dests,
	    MESH_DF_SOLICITATION_MAX + 1, buf, &len));
	dests[0] = 0x8000;
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_build(dests, 2, buf, &len));
	dests[0] = 1;
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_parse(NULL, 0, dests, 2, &n));
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_parse(buf, 1, dests, 2, &n));
	memset(buf, 0, sizeof(buf)); buf[1] = 1; buf[3] = 2;
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_parse(buf, 4, dests, 1, &n));
	buf[0] = 0x80;
	ATF_CHECK_EQ(-1, mesh_df_path_solicitation_parse(buf, 4, dests, 2, &n));

	/* Every Directed Forwarding Configuration codec's negative contract. */
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_get_build(0x1000, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_get_parse(NULL, 0, &u16));
	memset(&dc, 0, sizeof(dc)); dc.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_set_build(&dc, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_set_parse(NULL, 0, &dc));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_status_build(0, NULL, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_control_status_parse(NULL, 0, &status,
	    &dc));

	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_get_build(0x1000, buf, &len));
	memset(&metric, 0, sizeof(metric)); metric.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_set_build(&metric, buf, &len));
	metric.net_idx = 0; metric.metric_type = 8;
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_set_build(&metric, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_set_parse(NULL, 0, &metric));
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_status_build(0, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_metric_status_parse(NULL, 0, &status,
	    &metric));

	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_get_build(0x1000, buf, &len));
	memset(&lanes, 0, sizeof(lanes)); lanes.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_set_build(&lanes, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_set_parse(NULL, 0, &lanes));
	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_status_build(0, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_wanted_lanes_status_parse(NULL, 0, &status,
	    &lanes));

	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_get_build(0x1000, buf, &len));
	memset(&two_way, 0, sizeof(two_way)); two_way.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_set_build(&two_way, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_set_parse(NULL, 0, &two_way));
	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_status_build(0, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_two_way_path_status_parse(NULL, 0, &status,
	    &two_way));

	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_get_build(0x1000, buf,
	    &len));
	memset(&echo, 0, sizeof(echo)); echo.net_idx = 0x1000;
	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_set_build(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_set_build(&echo, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_set_parse(NULL, 0, &echo));
	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_status_build(0, NULL, buf,
	    &len));
	ATF_CHECK_EQ(-1, mesh_cfg_path_echo_interval_status_parse(NULL, 0,
	    &status, &echo));

	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_get_build(0, buf, &len));
	memset(&tx, 0, sizeof(tx)); tx.count = 8;
	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_build(
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET, NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_build(
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET, &tx, buf, &len));
	tx.count = 0;
	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_build(0, &tx, buf, &len));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_parse(NULL, 0, &opcode, &tx));
	ATF_CHECK_EQ(-1, mesh_cfg_directed_transmit_parse(buf, 1, NULL, &tx));

	/* Table capacity and discovery-state guards are separate from the wire
	 * codecs: drive every fail-closed state without requiring a network. */
	memset(&table, 0, sizeof(table));
	ATF_CHECK(mesh_df_table_add(NULL, 1, 2, 0, 1, 2, 1, 0) == NULL);
	ATF_CHECK(mesh_df_table_add(&table, 0, 2, 0, 1, 2, 1, 0) == NULL);
	for (n = 0; n < MESH_DF_MAX_ENTRIES; n++) {
		table.entries[n].valid = 1;
		table.entries[n].path_origin = (uint16_t)(n + 1);
		table.entries[n].path_target = (uint16_t)(n + 0x100);
	}
	table.count = MESH_DF_MAX_ENTRIES;
	ATF_CHECK(mesh_df_table_add(&table, 0x7000, 0x7001, 0, 1, 2, 1,
	    0) == NULL);
	ATF_CHECK(mesh_df_table_lookup(NULL, 1, 2, 0) == NULL);
	entry = &table.entries[0];
	entry->dep_target_n = MESH_DF_MAX_DEPENDENTS;
	entry->dep_origin_n = MESH_DF_MAX_DEPENDENTS;
	ATF_CHECK_EQ(-1, mesh_df_entry_add_dependent(entry, 1, 0x200));
	ATF_CHECK_EQ(-1, mesh_df_entry_add_dependent(entry, 0, 0x200));
	ATF_CHECK_EQ(0u, mesh_df_table_expire(NULL, 0));

	memset(&discovery, 0, sizeof(discovery));
	ATF_CHECK_EQ(-1, mesh_df_discovery_start(NULL, 1, 2, 0, 0, 0, 1,
	    0, 1, 0, &request));
	ATF_CHECK_EQ(-1, mesh_df_discovery_start(&discovery, 0, 2, 0, 0, 0,
	    1, 0, 1, 0, &request));
	ATF_CHECK_EQ(-1, mesh_df_discovery_start(&discovery, 1, 0x8000, 0, 0,
	    0, 1, 0, 1, 0, &request));
	ATF_CHECK_EQ(-1, mesh_df_discovery_on_reply(NULL, &reply, NULL));
	ATF_CHECK_EQ(0, mesh_df_discovery_on_reply(&discovery, &reply, NULL));
	ATF_CHECK_EQ(-1, mesh_df_discovery_confirm(NULL, &confirmation));
	ATF_CHECK_EQ(-1, mesh_df_discovery_confirm(&discovery, &confirmation));
	ATF_CHECK_EQ(0, mesh_df_discovery_timed_out(NULL, 0));
	discovery.state = MESH_DF_DISC_ESTABLISHED;
	ATF_CHECK_EQ(0, mesh_df_discovery_timed_out(&discovery, UINT64_MAX));
	ATF_CHECK_EQ(MESH_DF_FORWARD_DROP, mesh_df_forward_decide(NULL, NULL, 1,
	    2, 5, NULL, 0, &matched));
	mesh_df_node_init(NULL, 1, 1, 0, 0);
	memset(&node, 0, sizeof(node));
	memset(&output, 0, sizeof(output));
	memset(&features, 0, sizeof(features));
	ATF_CHECK_EQ(-1, mesh_df_echo_start(NULL, 2, 5, 1, 0, &output));
	ATF_CHECK_EQ(-1, mesh_df_echo_start(&node, 2, 5, 1, 0, &output));
	ATF_CHECK_EQ(0, mesh_df_echo_is_pending(NULL, 2));
	ATF_CHECK_EQ(0u, mesh_df_echo_expire(NULL, 0));

	/* Valid GET/STATUS encodings complement the malformed-codec matrix. */
	ATF_CHECK_EQ(0, mesh_cfg_path_metric_get_build(0, buf, &len));
	memset(&metric, 0, sizeof(metric));
	ATF_CHECK_EQ(0, mesh_cfg_path_metric_status_build(0, &metric, buf,
	    &len));
	ATF_CHECK_EQ(0, mesh_cfg_path_metric_status_parse(buf, len, &status,
	    &metric));
	ATF_CHECK_EQ(0, mesh_cfg_wanted_lanes_get_build(0, buf, &len));
	memset(&lanes, 0, sizeof(lanes));
	ATF_CHECK_EQ(0, mesh_cfg_wanted_lanes_status_build(0, &lanes, buf,
	    &len));
	ATF_CHECK_EQ(0, mesh_cfg_wanted_lanes_status_parse(buf, len, &status,
	    &lanes));
	ATF_CHECK_EQ(0, mesh_cfg_two_way_path_get_build(0, buf, &len));
	memset(&two_way, 0, sizeof(two_way));
	two_way.two_way_path = 1;
	ATF_CHECK_EQ(0, mesh_cfg_two_way_path_status_build(0, &two_way, buf,
	    &len));
	ATF_CHECK_EQ(0, mesh_cfg_two_way_path_status_parse(buf, len, &status,
	    &two_way));
	ATF_CHECK_EQ(0, mesh_cfg_path_echo_interval_get_build(0, buf, &len));
	memset(&echo, 0, sizeof(echo));
	echo.unicast_echo_interval = 1;
	echo.multicast_echo_interval = 2;
	ATF_CHECK_EQ(0, mesh_cfg_path_echo_interval_status_build(0, &echo, buf,
	    &len));
	ATF_CHECK_EQ(0, mesh_cfg_path_echo_interval_status_parse(buf, len,
	    &status, &echo));
	ATF_CHECK_EQ(0, mesh_cfg_directed_transmit_get_build(
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET, buf, &len));
	ATF_CHECK_EQ(0, mesh_cfg_directed_transmit_get_build(
	    MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_GET, buf, &len));
}

/* ================================================================
 * Regression tests for verified correctness findings (MshPRT_v1.1
 * Section 3.6.6).  Each fails against the pre-fix behavior.
 * ================================================================ */

/*
 * Finding 76: a half-installed (reverse-only) forwarding entry, whose bearer
 * toward the target is MESH_DF_BEARER_NONE, must not yield a DIRECTED decision.
 * mesh_df_forward_decide() has to fall through to managed flooding so the PDU
 * is not misdelivered to "bearer 0".
 */
ATF_TC_WITHOUT_HEAD(forward_decide_half_installed_floods);
ATF_TC_BODY(forward_decide_half_installed_floods, tc)
{
	struct mesh_df_fwd_table t;
	struct mesh_df_features feat;
	struct mesh_df_fwd_entry *matched;
	uint8_t new_ttl;
	uint64_t now = 100;

	mesh_df_table_init(&t);
	memset(&feat, 0, sizeof(feat));
	feat.directed_relay = 1;
	feat.managed_flood_relay = 1;

	/* Reverse-only entry: bearer toward origin known (1), toward target NONE. */
	ATF_REQUIRE(mesh_df_table_add(&t, 0x0001, 0x0005, 0x2A, 1,
	    MESH_DF_BEARER_NONE, mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR],
	    now) != NULL);

	/*
	 * A PDU toward the target 0x0005 has no installed target-facing bearer,
	 * so the decision must be FLOOD (not DIRECTED with bearer 0).
	 */
	matched = NULL;
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_FLOOD,
	    mesh_df_forward_decide(&t, &feat, 0x0001, 0x0005, 5, &new_ttl, now,
	    &matched));
	ATF_REQUIRE(matched == NULL);

	/* Toward the origin 0x0001 the bearer IS installed: still directed. */
	ATF_REQUIRE_EQ(MESH_DF_FORWARD_DIRECTED,
	    mesh_df_forward_decide(&t, &feat, 0x0005, 0x0001, 5, &new_ttl, now,
	    &matched));
	ATF_REQUIRE(matched != NULL);
}

/*
 * Finding 79: a relay must install the reverse Forwarding Table entry with the
 * Path_Lifetime carried in the received Path Request, not the relay's local
 * lifetime.
 */
ATF_TC_WITHOUT_HEAD(request_uses_received_lifetime);
ATF_TC_BODY(request_uses_received_lifetime, tc)
{
	struct mesh_df_node relay;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	struct mesh_df_fwd_entry *e;
	uint8_t reqbuf[16];
	size_t reqlen;
	uint64_t now = 0;
	uint64_t local = mesh_df_lifetime_ms[MESH_DF_LIFETIME_12_MIN];
	uint64_t rxlife = mesh_df_lifetime_ms[MESH_DF_LIFETIME_24_HOUR];

	/* Relay configured for a 12-minute local lifetime. */
	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_12_MIN, 0);

	/* The request asks for a 24-hour Path_Lifetime. */
	memset(&req, 0, sizeof(req));
	req.lifetime = MESH_DF_LIFETIME_24_HOUR;
	req.forwarding_number = 0x60;
	req.destination = 0x0005;
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));

	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0005, now);
	ATF_REQUIRE(e != NULL);
	/* The entry must carry the received 24h lifetime, not the local 12min. */
	ATF_REQUIRE(rxlife > local);
	ATF_REQUIRE_EQ(rxlife, e->lifetime_ms);
	/* Still valid long after the local default would have expired. */
	ATF_REQUIRE(mesh_df_table_lookup(&relay.table, 0x0001, 0x0005,
	    local + 1) != NULL);
}

/*
 * Finding 21: a discovery whose Destination is a secondary element or a group
 * keys the reverse entry on that address, but the Path Reply carries the Path
 * Target's element range / primary address.  The reply must be matched to the
 * reverse entry by range coverage, not primary-address equality.
 */
ATF_TC_WITHOUT_HEAD(reply_matches_secondary_or_group);
ATF_TC_BODY(reply_matches_secondary_or_group, tc)
{
	struct mesh_df_node relay;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	struct mesh_df_path_reply rep;
	struct mesh_df_fwd_entry *e;
	uint8_t reqbuf[16], repbuf[16];
	size_t reqlen, replen;
	uint64_t now = 1000;

	/* --- secondary-element destination 0x0006 (target primary 0x0005) --- */
	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&req, 0, sizeof(req));
	req.forwarding_number = 0x50;
	req.destination = 0x0006;		/* a secondary element */
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0006; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));

	/* The target replies with element range 0x0005..0x0006 (primary 0x0005). */
	memset(&rep, 0, sizeof(rep));
	rep.forwarding_number = 0x50;
	rep.path_origin = 0x0001;
	rep.target.range_start = 0x0005;
	rep.target.range_length = 2;		/* covers 0x0005 and 0x0006 */
	ATF_REQUIRE_EQ(0, mesh_df_path_reply_build(&rep, repbuf, &replen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0005; ctx.dst = 0x0001; ctx.ttl = 5; ctx.bearer = 2;
	ctx.now = now;
	/* Old behavior looked up (0x0001, 0x0005) and dropped; must FORWARD now. */
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REPLY, repbuf, replen, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0x0006, now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE(mesh_df_entry_forward_valid(e));
	ATF_REQUIRE_EQ(2, e->bearer_toward_target);

	/* --- group destination 0xC000 --- */
	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&req, 0, sizeof(req));
	req.forwarding_number = 0x51;
	req.destination = 0xC000;		/* group target */
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0xC000; ctx.ttl = 5; ctx.bearer = 1;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));

	/* A group member replies with its own unicast address. */
	memset(&rep, 0, sizeof(rep));
	rep.forwarding_number = 0x51;
	rep.path_origin = 0x0001;
	rep.target.range_start = 0x0009;
	rep.target.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_reply_build(&rep, repbuf, &replen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0009; ctx.dst = 0x0001; ctx.ttl = 5; ctx.bearer = 2;
	ctx.now = now;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REPLY, repbuf, replen, &out));
	e = mesh_df_table_lookup(&relay.table, 0x0001, 0xC000, now);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE(mesh_df_entry_forward_valid(e));
}

/*
 * Finding 25: a Path/Echo Reply must be originated with a fresh TTL, not the
 * received request's residual TTL, or a request that arrives with a small TTL
 * yields a reply that dies before completing the return trip.
 */
ATF_TC_WITHOUT_HEAD(reply_uses_fresh_ttl);
ATF_TC_BODY(reply_uses_fresh_ttl, tc)
{
	struct mesh_df_node target;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	uint8_t reqbuf[16];
	size_t reqlen;

	mesh_df_node_init(&target, 0x0005, 0x0005, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&req, 0, sizeof(req));
	req.forwarding_number = 0x70;
	req.destination = 0x0005;
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));

	/* Request arrives with a low residual TTL (2). */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 2; ctx.bearer = 9;
	ctx.now = 0;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FOR_TARGET, mesh_df_recv_control(&target,
	    &ctx, MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_REPLY, out.opcode);
	/* Reply originates with a fresh TTL, not the request residual (2). */
	ATF_REQUIRE_EQ(MESH_DF_DEFAULT_TTL, out.ttl);

	/* The echo endpoint reply is likewise originated with a fresh TTL. */
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = 0x0005; ctx.ttl = 2; ctx.bearer = 9;
	ctx.now = 0;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FOR_TARGET, mesh_df_recv_control(&target,
	    &ctx, MESH_DF_OP_PATH_ECHO_REQUEST, NULL, 0, &out));
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_ECHO_REPLY, out.opcode);
	ATF_REQUIRE_EQ(MESH_DF_DEFAULT_TTL, out.ttl);
}

/*
 * Finding 83: when a node both originates a path to T and relays another path
 * (O2, T) to the same target, a Path Echo Reply must refresh/forward the entry
 * for the path it actually traverses, disambiguated by both endpoints.
 */
ATF_TC_WITHOUT_HEAD(echo_reply_disambiguates_shared_target);
ATF_TC_BODY(echo_reply_disambiguates_shared_target, tc)
{
	struct mesh_df_node node;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_fwd_entry *a, *b;
	uint8_t rbuf[4];
	size_t rlen;
	uint64_t now = 1000;
	uint64_t life = mesh_df_lifetime_ms[MESH_DF_LIFETIME_2_HOUR];

	mesh_df_node_init(&node, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);

	/* Entry A: a path this node ORIGINATES to target 0x0005 (slot 0). */
	a = mesh_df_table_add(&node.table, 0x0002, 0x0005, 0x10,
	    MESH_DF_BEARER_NONE, 2, life, now);
	ATF_REQUIRE(a != NULL);
	/* Entry B: a path (O2=0x0001, T=0x0005) this node RELAYS (slot 1). */
	b = mesh_df_table_add(&node.table, 0x0001, 0x0005, 0x11, 1, 2, life,
	    now);
	ATF_REQUIRE(b != NULL);
	ATF_REQUIRE(a != b);

	/* An Echo Reply travelling O2's path back toward 0x0001 (dest = T). */
	ATF_REQUIRE_EQ(0, mesh_df_path_echo_reply_build(0x0005, rbuf, &rlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0005; ctx.dst = 0x0001; ctx.ttl = 5; ctx.bearer = 2;
	ctx.now = now + 400;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&node, &ctx,
	    MESH_DF_OP_PATH_ECHO_REPLY, rbuf, rlen, &out));
	/* Forwarded toward O2 (0x0001) on entry B's origin-facing bearer. */
	ATF_REQUIRE_EQ(1, out.bearer);
	ATF_REQUIRE_EQ(0x0001, out.dst);
	/* Only entry B (the traversed path) is refreshed; entry A is untouched. */
	ATF_REQUIRE_EQ(now + 400, b->install_ms);
	ATF_REQUIRE_EQ(now, a->install_ms);
}

/*
 * Finding 84: a re-flooded Path Request must be addressed to the
 * all-directed-forwarding-nodes group (0xFFFB) with the network SRC
 * re-originated by the relay, not carried through as the unicast destination.
 */
ATF_TC_WITHOUT_HEAD(reflood_request_addressing);
ATF_TC_BODY(reflood_request_addressing, tc)
{
	struct mesh_df_node relay;
	struct mesh_df_recv_ctx ctx;
	struct mesh_df_output out;
	struct mesh_df_path_request req;
	uint8_t reqbuf[16];
	size_t reqlen;

	mesh_df_node_init(&relay, 0x0002, 0x0002, MESH_DF_LIFETIME_2_HOUR, 0);
	memset(&req, 0, sizeof(req));
	req.forwarding_number = 0x80;
	req.destination = 0x0005;
	req.origin.range_start = 0x0001;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));
	memset(&ctx, 0, sizeof(ctx));
	ctx.src = 0x0001; ctx.dst = MESH_DF_ADDR_ALL_DIRECTED; ctx.ttl = 5;
	ctx.bearer = 1;
	ctx.now = 0;
	ATF_REQUIRE_EQ(MESH_DF_RECV_FORWARD, mesh_df_recv_control(&relay, &ctx,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, &out));
	ATF_REQUIRE_EQ(MESH_DF_OP_PATH_REQUEST, out.opcode);
	ATF_REQUIRE_EQ(MESH_DF_BEARER_FLOOD, out.bearer);
	/* Re-flood to the all-directed group, SRC re-originated as this relay. */
	ATF_REQUIRE_EQ(MESH_DF_ADDR_ALL_DIRECTED, out.dst);
	ATF_REQUIRE_EQ(0x0002, out.src);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, addr_range_single);
	ATF_TP_ADD_TC(tp, addr_range_multi);
	ATF_TP_ADD_TC(tp, addr_range_rejects);
	ATF_TP_ADD_TC(tp, path_request_codec);
	ATF_TP_ADD_TC(tp, path_request_dependent_origin);
	ATF_TP_ADD_TC(tp, path_reply_codec);
	ATF_TP_ADD_TC(tp, path_confirmation_codec);
	ATF_TP_ADD_TC(tp, path_echo_codec);
	ATF_TP_ADD_TC(tp, dependent_update_codec);
	ATF_TP_ADD_TC(tp, solicitation_codec);
	ATF_TP_ADD_TC(tp, forwarding_number_wrap);
	ATF_TP_ADD_TC(tp, fwd_table_add_lookup);
	ATF_TP_ADD_TC(tp, fwd_table_expire);
	ATF_TP_ADD_TC(tp, fwd_table_fixed_path);
	ATF_TP_ADD_TC(tp, forward_decide);
	ATF_TP_ADD_TC(tp, discovery_lifecycle);
	ATF_TP_ADD_TC(tp, discovery_timeout);
	ATF_TP_ADD_TC(tp, cfg_directed_control);
	ATF_TP_ADD_TC(tp, cfg_path_metric);
	ATF_TP_ADD_TC(tp, cfg_lanes_two_way_echo);
	ATF_TP_ADD_TC(tp, cfg_directed_transmit);
	ATF_TP_ADD_TC(tp, nonorigin_multihop_lifecycle);
	ATF_TP_ADD_TC(tp, nonorigin_fn_refresh_and_origin);
	ATF_TP_ADD_TC(tp, nonorigin_path_echo);
	ATF_TP_ADD_TC(tp, nonorigin_dependent_update);
	ATF_TP_ADD_TC(tp, remaining_forwarding_paths);
	ATF_TP_ADD_TC(tp, nonorigin_truncated_pdus);
	ATF_TP_ADD_TC(tp, codec_guard_matrix);
	ATF_TP_ADD_TC(tp, forward_decide_half_installed_floods);
	ATF_TP_ADD_TC(tp, request_uses_received_lifetime);
	ATF_TP_ADD_TC(tp, reply_matches_secondary_or_group);
	ATF_TP_ADD_TC(tp, reply_uses_fresh_ttl);
	ATF_TP_ADD_TC(tp, echo_reply_disambiguates_shared_target);
	ATF_TP_ADD_TC(tp, reflood_request_addressing);

	return (atf_no_error());
}
