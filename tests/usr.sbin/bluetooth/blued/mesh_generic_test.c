/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh Generic models (mesh_generic.[ch],
 * Mesh Model 1.1.1 Chapter 3): Generic model message codecs, server state
 * transitions, bindings, and client helpers.
 *
 * The Mesh Model 1.1 specification provides no worked byte dumps for these
 * messages, so the asserted bytes come from the Section 7.1 opcode map and
 * the Section 3.2 field layout (little-endian access-layer fields).  Every
 * asserted parameter block follows the cited field order directly; symbolic
 * protocol values come from spec_mesh_generic_oracles.h, which deliberately
 * does not include the production header:
 *
 *   OnOff Set 0x8202  onoff=1 tid=0x22            -> 01 22
 *   OnOff Set         + tt=0x0A delay=0x05        -> 01 22 0a 05
 *   OnOff Status      present=0 target=1 rem=0x0A -> 00 01 0a
 *   Level Set 0x8206  level=4660 tid=0x10         -> 34 12 10  (LE 0x1234)
 *   Delta Set 0x8209  delta=-100 tid=1            -> 9c ff ff ff 01
 *   Move  Set 0x820B  delta=-2000 tid=2           -> 30 f8 02
 *   Level Status      present=100 target=200 r=0a -> 64 00 c8 00 0a
 */

#include <sys/param.h>
#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_generic.h"
#include "spec_mesh_generic_oracles.h"

static int
dispatch_model(struct mesh_model *model, uint32_t opcode,
    const uint8_t *params, size_t params_len, struct mesh_model_reply *reply)
{
	const struct mesh_opcode_entry *entry;
	struct mesh_access_pdu pdu;
	struct mesh_access_rx rx;

	entry = mesh_model_find_op(model, opcode);
	if (entry == NULL)
		return (-1);
	memset(&pdu, 0, sizeof(pdu));
	pdu.opcode = opcode;
	pdu.params_len = params_len;
	if (params_len != 0)
		memcpy(pdu.params, params, params_len);
	memset(&rx, 0, sizeof(rx));
	rx.src = 0x1201;
	rx.elem_addr = 0x0003;
	rx.pdu = &pdu;
	rx.model_user = model->user;
	rx.ctx = reply;
	rx.now_ms = 1000;
	return (entry->handler(&rx));
}

/*
 * Assigned Numbers is an oracle distinct from mesh_generic.h.  Pin every
 * SIG model identifier and message opcode used by this implementation so a
 * self-consistent but wrongly numbered encoder cannot pass scenario tests.
 */
ATF_TC_WITHOUT_HEAD(assigned_numbers_contract);
ATF_TC_BODY(assigned_numbers_contract, tc)
{
	static const struct {
		uint32_t production;
		uint32_t specification;
	} values[] = {
		{ MESH_MODEL_GEN_ONOFF_SRV, BTMG_MODEL_ONOFF_SRV },
		{ MESH_MODEL_GEN_ONOFF_CLI, BTMG_MODEL_ONOFF_CLI },
		{ MESH_MODEL_GEN_LEVEL_SRV, BTMG_MODEL_LEVEL_SRV },
		{ MESH_MODEL_GEN_LEVEL_CLI, BTMG_MODEL_LEVEL_CLI },
		{ MESH_MODEL_GEN_DTT_SRV, BTMG_MODEL_DTT_SRV },
		{ MESH_MODEL_GEN_DTT_CLI, BTMG_MODEL_DTT_CLI },
		{ MESH_MODEL_GEN_POWER_ONOFF_SRV, BTMG_MODEL_POWER_ONOFF_SRV },
		{ MESH_MODEL_GEN_POWER_ONOFF_SETUP_SRV,
		    BTMG_MODEL_POWER_ONOFF_SETUP_SRV },
		{ MESH_MODEL_GEN_POWER_ONOFF_CLI, BTMG_MODEL_POWER_ONOFF_CLI },
		{ MESH_MODEL_GEN_POWER_LEVEL_SRV, BTMG_MODEL_POWER_LEVEL_SRV },
		{ MESH_MODEL_GEN_POWER_LEVEL_SETUP_SRV,
		    BTMG_MODEL_POWER_LEVEL_SETUP_SRV },
		{ MESH_MODEL_GEN_POWER_LEVEL_CLI, BTMG_MODEL_POWER_LEVEL_CLI },
		{ MESH_MODEL_GEN_BATTERY_SRV, BTMG_MODEL_BATTERY_SRV },
		{ MESH_MODEL_GEN_BATTERY_CLI, BTMG_MODEL_BATTERY_CLI },
		{ MESH_MODEL_GEN_LOCATION_SRV, BTMG_MODEL_LOCATION_SRV },
		{ MESH_MODEL_GEN_LOCATION_SETUP_SRV,
		    BTMG_MODEL_LOCATION_SETUP_SRV },
		{ MESH_MODEL_GEN_LOCATION_CLI, BTMG_MODEL_LOCATION_CLI },
		{ MESH_OP_GEN_ONOFF_GET, BTMG_OP_ONOFF_GET },
		{ MESH_OP_GEN_ONOFF_SET, BTMG_OP_ONOFF_SET },
		{ MESH_OP_GEN_ONOFF_SET_UNACK, BTMG_OP_ONOFF_SET_UNACK },
		{ MESH_OP_GEN_ONOFF_STATUS, BTMG_OP_ONOFF_STATUS },
		{ MESH_OP_GEN_LEVEL_GET, BTMG_OP_LEVEL_GET },
		{ MESH_OP_GEN_LEVEL_SET, BTMG_OP_LEVEL_SET },
		{ MESH_OP_GEN_LEVEL_SET_UNACK, BTMG_OP_LEVEL_SET_UNACK },
		{ MESH_OP_GEN_LEVEL_STATUS, BTMG_OP_LEVEL_STATUS },
		{ MESH_OP_GEN_DELTA_SET, BTMG_OP_DELTA_SET },
		{ MESH_OP_GEN_DELTA_SET_UNACK, BTMG_OP_DELTA_SET_UNACK },
		{ MESH_OP_GEN_MOVE_SET, BTMG_OP_MOVE_SET },
		{ MESH_OP_GEN_MOVE_SET_UNACK, BTMG_OP_MOVE_SET_UNACK },
		{ MESH_OP_GEN_DTT_GET, BTMG_OP_DTT_GET },
		{ MESH_OP_GEN_DTT_SET, BTMG_OP_DTT_SET },
		{ MESH_OP_GEN_DTT_SET_UNACK, BTMG_OP_DTT_SET_UNACK },
		{ MESH_OP_GEN_DTT_STATUS, BTMG_OP_DTT_STATUS },
		{ MESH_OP_GEN_ONPOWERUP_GET, BTMG_OP_ONPOWERUP_GET },
		{ MESH_OP_GEN_ONPOWERUP_STATUS, BTMG_OP_ONPOWERUP_STATUS },
		{ MESH_OP_GEN_ONPOWERUP_SET, BTMG_OP_ONPOWERUP_SET },
		{ MESH_OP_GEN_ONPOWERUP_SET_UNACK, BTMG_OP_ONPOWERUP_SET_UNACK },
		{ MESH_OP_GEN_POWER_LEVEL_GET, BTMG_OP_POWER_LEVEL_GET },
		{ MESH_OP_GEN_POWER_LEVEL_SET, BTMG_OP_POWER_LEVEL_SET },
		{ MESH_OP_GEN_POWER_LEVEL_SET_UNACK,
		    BTMG_OP_POWER_LEVEL_SET_UNACK },
		{ MESH_OP_GEN_POWER_LEVEL_STATUS, BTMG_OP_POWER_LEVEL_STATUS },
		{ MESH_OP_GEN_POWER_LAST_GET, BTMG_OP_POWER_LAST_GET },
		{ MESH_OP_GEN_POWER_LAST_STATUS, BTMG_OP_POWER_LAST_STATUS },
		{ MESH_OP_GEN_POWER_DEFAULT_GET, BTMG_OP_POWER_DEFAULT_GET },
		{ MESH_OP_GEN_POWER_DEFAULT_STATUS,
		    BTMG_OP_POWER_DEFAULT_STATUS },
		{ MESH_OP_GEN_POWER_RANGE_GET, BTMG_OP_POWER_RANGE_GET },
		{ MESH_OP_GEN_POWER_RANGE_STATUS, BTMG_OP_POWER_RANGE_STATUS },
		{ MESH_OP_GEN_POWER_DEFAULT_SET, BTMG_OP_POWER_DEFAULT_SET },
		{ MESH_OP_GEN_POWER_DEFAULT_SET_UNACK,
		    BTMG_OP_POWER_DEFAULT_SET_UNACK },
		{ MESH_OP_GEN_POWER_RANGE_SET, BTMG_OP_POWER_RANGE_SET },
		{ MESH_OP_GEN_POWER_RANGE_SET_UNACK,
		    BTMG_OP_POWER_RANGE_SET_UNACK },
		{ MESH_OP_GEN_BATTERY_GET, BTMG_OP_BATTERY_GET },
		{ MESH_OP_GEN_BATTERY_STATUS, BTMG_OP_BATTERY_STATUS },
		{ MESH_OP_GEN_LOCATION_GLOBAL_GET, BTMG_OP_LOCATION_GLOBAL_GET },
		{ MESH_OP_GEN_LOCATION_LOCAL_GET, BTMG_OP_LOCATION_LOCAL_GET },
		{ MESH_OP_GEN_LOCATION_LOCAL_STATUS,
		    BTMG_OP_LOCATION_LOCAL_STATUS },
		{ MESH_OP_GEN_LOCATION_LOCAL_SET, BTMG_OP_LOCATION_LOCAL_SET },
		{ MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK,
		    BTMG_OP_LOCATION_LOCAL_SET_UNACK },
		{ MESH_OP_GEN_LOCATION_GLOBAL_STATUS,
		    BTMG_OP_LOCATION_GLOBAL_STATUS },
		{ MESH_OP_GEN_LOCATION_GLOBAL_SET, BTMG_OP_LOCATION_GLOBAL_SET },
		{ MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK,
		    BTMG_OP_LOCATION_GLOBAL_SET_UNACK },
	};

	for (size_t i = 0; i < nitems(values); i++)
		ATF_CHECK_EQ(values[i].specification, values[i].production);
	ATF_CHECK_EQ(BTMG_OFF, MESH_GEN_OFF);
	ATF_CHECK_EQ(BTMG_ON, MESH_GEN_ON);
	ATF_CHECK_EQ(BTMG_ONPOWERUP_OFF, MESH_GEN_ONPOWERUP_OFF);
	ATF_CHECK_EQ(BTMG_ONPOWERUP_DEFAULT, MESH_GEN_ONPOWERUP_DEFAULT);
	ATF_CHECK_EQ(BTMG_ONPOWERUP_RESTORE, MESH_GEN_ONPOWERUP_RESTORE);
}

/* ================================================================
 * OnOff codecs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(onoff_set_codec);
ATF_TC_BODY(onoff_set_codec, tc)
{
	struct mesh_gen_onoff_set s, d;
	uint8_t out[8];
	size_t len;
	static const uint8_t exp2[] = { 0x01, 0x22 };
	static const uint8_t exp4[] = { 0x01, 0x22, 0x0a, 0x05 };

	memset(&s, 0, sizeof(s));
	s.onoff = 1;
	s.tid = 0x22;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, out, &len));
	ATF_CHECK_EQ(2u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp2, 2));

	s.has_transition = 1;
	s.transition_time = 0x0a;
	s.delay = 0x05;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, out, &len));
	ATF_CHECK_EQ(4u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp4, 4));

	/* Decode both forms. */
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_decode(exp2, 2, &d));
	ATF_CHECK_EQ(1, d.onoff);
	ATF_CHECK_EQ(0x22, d.tid);
	ATF_CHECK_EQ(0, d.has_transition);
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_decode(exp4, 4, &d));
	ATF_CHECK_EQ(1, d.has_transition);
	ATF_CHECK_EQ(0x0a, d.transition_time);
	ATF_CHECK_EQ(0x05, d.delay);
}

ATF_TC_WITHOUT_HEAD(onoff_set_negative);
ATF_TC_BODY(onoff_set_negative, tc)
{
	struct mesh_gen_onoff_set s, d;
	uint8_t out[8];
	size_t len;
	static const uint8_t bad_onoff[] = { 0x02, 0x00 };
	static const uint8_t len3[] = { 0x01, 0x00, 0x00 };

	/* onoff > 1 is prohibited. */
	memset(&s, 0, sizeof(s));
	s.onoff = 2;
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&s, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(bad_onoff, 2, &d));

	/* Odd length (3) is invalid; empty is invalid. */
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(len3, 3, &d));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(len3, 0, &d));

	/* NULL guards. */
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&s, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&s, out, NULL));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(NULL, 2, &d));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(bad_onoff, 2, NULL));
}

ATF_TC_WITHOUT_HEAD(onoff_status_codec);
ATF_TC_BODY(onoff_status_codec, tc)
{
	struct mesh_gen_onoff_status s, d;
	uint8_t out[8];
	size_t len;
	static const uint8_t exp3[] = { 0x00, 0x01, 0x0a };

	memset(&s, 0, sizeof(s));
	s.present = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_status_encode(&s, out, &len));
	ATF_CHECK_EQ(1u, len);
	ATF_CHECK_EQ(0x01, out[0]);

	memset(&s, 0, sizeof(s));
	s.present = 0;
	s.has_target = 1;
	s.target = 1;
	s.remaining = 0x0a;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_status_encode(&s, out, &len));
	ATF_CHECK_EQ(3u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp3, 3));

	ATF_REQUIRE_EQ(0, mesh_gen_onoff_status_decode(exp3, 3, &d));
	ATF_CHECK_EQ(0, d.present);
	ATF_CHECK_EQ(1, d.has_target);
	ATF_CHECK_EQ(1, d.target);
	ATF_CHECK_EQ(0x0a, d.remaining);

	/* Negatives: prohibited values, bad lengths, NULLs. */
	s.present = 2;
	s.has_target = 0;
	ATF_CHECK_EQ(-1, mesh_gen_onoff_status_encode(&s, out, &len));
	s.present = 0;
	s.has_target = 1;
	s.target = 2;
	ATF_CHECK_EQ(-1, mesh_gen_onoff_status_encode(&s, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(exp3, 2, &d));
	{
		static const uint8_t badp[] = { 0x02 };
		static const uint8_t badt[] = { 0x00, 0x02, 0x00 };
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(badp, 1, &d));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(badt, 3, &d));
	}
	ATF_CHECK_EQ(-1, mesh_gen_onoff_status_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(NULL, 1, &d));
}

/* ================================================================
 * Level codecs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(level_set_codec);
ATF_TC_BODY(level_set_codec, tc)
{
	struct mesh_gen_level_set s, d;
	uint8_t out[8];
	size_t len;
	static const uint8_t exp[] = { 0x34, 0x12, 0x10 };	/* 0x1234 LE */

	memset(&s, 0, sizeof(s));
	s.level = 4660;			/* 0x1234 */
	s.tid = 0x10;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, out, &len));
	ATF_CHECK_EQ(3u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp, 3));

	s.has_transition = 1;
	s.transition_time = 0x0a;
	s.delay = 0x05;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, out, &len));
	ATF_CHECK_EQ(5u, len);

	ATF_REQUIRE_EQ(0, mesh_gen_level_set_decode(exp, 3, &d));
	ATF_CHECK_EQ(4660, d.level);
	ATF_CHECK_EQ(0x10, d.tid);
	ATF_CHECK_EQ(0, d.has_transition);
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_decode(out, 5, &d));
	ATF_CHECK_EQ(1, d.has_transition);

	/* Negative level round-trips (little-endian two's complement). */
	memset(&s, 0, sizeof(s));
	s.level = -1;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, out, &len));
	ATF_CHECK_EQ(0xff, out[0]);
	ATF_CHECK_EQ(0xff, out[1]);
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_decode(out, 3, &d));
	ATF_CHECK_EQ(-1, d.level);

	ATF_CHECK_EQ(-1, mesh_gen_level_set_decode(exp, 4, &d));
	ATF_CHECK_EQ(-1, mesh_gen_level_set_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_level_set_decode(NULL, 3, &d));
}

ATF_TC_WITHOUT_HEAD(delta_move_codec);
ATF_TC_BODY(delta_move_codec, tc)
{
	struct mesh_gen_delta_set dl, dd;
	struct mesh_gen_move_set mv, md;
	uint8_t out[8];
	size_t len;
	static const uint8_t dexp[] = { 0x9c, 0xff, 0xff, 0xff, 0x01 };	/* -100 */
	static const uint8_t mexp[] = { 0x30, 0xf8, 0x02 };		/* -2000 */

	memset(&dl, 0, sizeof(dl));
	dl.delta = -100;
	dl.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_encode(&dl, out, &len));
	ATF_CHECK_EQ(5u, len);
	ATF_CHECK_EQ(0, memcmp(out, dexp, 5));
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_decode(dexp, 5, &dd));
	ATF_CHECK_EQ(-100, dd.delta);
	ATF_CHECK_EQ(1, dd.tid);
	dl.has_transition = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_encode(&dl, out, &len));
	ATF_CHECK_EQ(7u, len);
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_decode(out, 7, &dd));
	ATF_CHECK_EQ(1, dd.has_transition);
	ATF_CHECK_EQ(-1, mesh_gen_delta_set_decode(dexp, 6, &dd));
	ATF_CHECK_EQ(-1, mesh_gen_delta_set_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_delta_set_decode(NULL, 5, &dd));

	memset(&mv, 0, sizeof(mv));
	mv.delta = -2000;
	mv.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&mv, out, &len));
	ATF_CHECK_EQ(3u, len);
	ATF_CHECK_EQ(0, memcmp(out, mexp, 3));
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_decode(mexp, 3, &md));
	ATF_CHECK_EQ(-2000, md.delta);
	mv.has_transition = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&mv, out, &len));
	ATF_CHECK_EQ(5u, len);
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_decode(out, 5, &md));
	ATF_CHECK_EQ(1, md.has_transition);
	ATF_CHECK_EQ(-1, mesh_gen_move_set_decode(mexp, 4, &md));
	ATF_CHECK_EQ(-1, mesh_gen_move_set_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_move_set_decode(NULL, 3, &md));
}

ATF_TC_WITHOUT_HEAD(level_status_codec);
ATF_TC_BODY(level_status_codec, tc)
{
	struct mesh_gen_level_status s, d;
	uint8_t out[8];
	size_t len;
	static const uint8_t exp5[] = { 0x64, 0x00, 0xc8, 0x00, 0x0a };

	memset(&s, 0, sizeof(s));
	s.present = 100;
	ATF_REQUIRE_EQ(0, mesh_gen_level_status_encode(&s, out, &len));
	ATF_CHECK_EQ(2u, len);

	s.has_target = 1;
	s.target = 200;
	s.remaining = 0x0a;
	ATF_REQUIRE_EQ(0, mesh_gen_level_status_encode(&s, out, &len));
	ATF_CHECK_EQ(5u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp5, 5));

	ATF_REQUIRE_EQ(0, mesh_gen_level_status_decode(exp5, 5, &d));
	ATF_CHECK_EQ(100, d.present);
	ATF_CHECK_EQ(1, d.has_target);
	ATF_CHECK_EQ(200, d.target);
	ATF_CHECK_EQ(0x0a, d.remaining);
	ATF_REQUIRE_EQ(0, mesh_gen_level_status_decode(exp5, 2, &d));
	ATF_CHECK_EQ(0, d.has_target);
	ATF_CHECK_EQ(-1, mesh_gen_level_status_decode(exp5, 3, &d));
	ATF_CHECK_EQ(-1, mesh_gen_level_status_encode(NULL, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_level_status_decode(NULL, 2, &d));
}

/* ================================================================
 * Saturating add (Delta Set arithmetic).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sat_add);
ATF_TC_BODY(sat_add, tc)
{

	ATF_CHECK_EQ(5, mesh_gen_level_sat_add(0, 5));
	ATF_CHECK_EQ(32767, mesh_gen_level_sat_add(32000, 1000));
	ATF_CHECK_EQ(-32768, mesh_gen_level_sat_add(-32000, -1000));
	ATF_CHECK_EQ(32767, mesh_gen_level_sat_add(32767, 0));
	ATF_CHECK_EQ(-32768, mesh_gen_level_sat_add(-32768, 0));
}

/* ================================================================
 * OnOff server state machine.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(onoff_server);
ATF_TC_BODY(onoff_server, tc)
{
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_status st;
	uint8_t p[4];
	size_t plen;
	int want;

	mesh_gen_onoff_srv_init(&srv, 0);
	ATF_CHECK_EQ(0, srv.present);

	/* Acknowledged Set turns it on and asks for a Status. */
	{
		struct mesh_gen_onoff_set s = { 1, 1, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, p, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(1, srv.present);
	ATF_CHECK_EQ(1, want);
	ATF_CHECK_EQ(1, st.present);

	/* GET returns present without changing it. */
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_GET, NULL, 0, &st, &want));
	ATF_CHECK_EQ(1, want);
	ATF_CHECK_EQ(1, st.present);

	/* Set Unacknowledged turns it off, no Status. */
	{
		struct mesh_gen_onoff_set s = { 0, 2, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, p, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_SET_UNACK, p, plen, &st, &want));
	ATF_CHECK_EQ(0, srv.present);
	ATF_CHECK_EQ(0, want);

	/* Retransmission (same src+tid) is ignored: state stays. */
	{
		struct mesh_gen_onoff_set s = { 1, 9, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, p, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(1, srv.present);
	{
		struct mesh_gen_onoff_set s = { 0, 9, 0, 0, 0 };	/* same tid */
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, p, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_SET, p, plen, &st, &want));
	ATF_CHECK_EQ_MSG(1, srv.present, "same-tid retransmission ignored");

	/* A different source with the same tid is a new transaction. */
	{
		struct mesh_gen_onoff_set s = { 0, 9, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_set_encode(&s, p, &plen));
	}
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv(&srv, 0x1301,
	    MESH_OP_GEN_ONOFF_SET, p, plen, &st, &want));
	ATF_CHECK_EQ_MSG(0, srv.present, "different source is a new transaction");

	/* Malformed params and unknown opcode. */
	ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_SET, p, 3, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_ONOFF_GET, p, 1, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(&srv, 0x1201, 0x8299,
	    NULL, 0, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(NULL, 0x1201,
	    MESH_OP_GEN_ONOFF_GET, NULL, 0, &st, &want));
}

/* ================================================================
 * Level server: Set, Delta transaction base, Move saturation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(level_server_set_get);
ATF_TC_BODY(level_server_set_get, tc)
{
	struct mesh_gen_level_srv srv;
	struct mesh_gen_level_status st;
	uint8_t p[8];
	size_t plen;
	int want;
	struct mesh_gen_level_set s;

	mesh_gen_level_srv_init(&srv, 0);
	memset(&s, 0, sizeof(s));
	s.level = 5000;
	s.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_LEVEL_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(5000, srv.present);
	ATF_CHECK_EQ(1, want);
	ATF_CHECK_EQ(5000, st.present);

	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, &st, &want));
	ATF_CHECK_EQ(1, want);
	ATF_CHECK_EQ(5000, st.present);

	/* Unacknowledged Set: no Status. */
	s.level = -100;
	s.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_LEVEL_SET_UNACK, p, plen, &st, &want));
	ATF_CHECK_EQ(-100, srv.present);
	ATF_CHECK_EQ(0, want);

	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_LEVEL_GET, p, 1, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_LEVEL_SET, p, 4, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&srv, 0x1201, 0x8299,
	    NULL, 0, &st, &want));
	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(NULL, 0x1201,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, &st, &want));
}

ATF_TC_WITHOUT_HEAD(level_server_delta);
ATF_TC_BODY(level_server_delta, tc)
{
	struct mesh_gen_level_srv srv;
	struct mesh_gen_level_status st;
	struct mesh_gen_delta_set d;
	uint8_t p[8];
	size_t plen;
	int want;

	mesh_gen_level_srv_init(&srv, 100);

	/* New transaction: base = 100, +50 -> 150. */
	memset(&d, 0, sizeof(d));
	d.delta = 50;
	d.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_encode(&d, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_DELTA_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(150, srv.present);
	ATF_CHECK_EQ(1, want);

	/* Same tid = same transaction: re-apply from base 100 -> 150 (not 200). */
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_DELTA_SET, p, plen, &st, &want));
	ATF_CHECK_EQ_MSG(150, srv.present, "same-tid Delta re-applies from base");

	/* New tid = new transaction: base becomes 150, +50 -> 200. */
	d.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_encode(&d, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_DELTA_SET_UNACK, p, plen, &st, &want));
	ATF_CHECK_EQ(200, srv.present);
	ATF_CHECK_EQ(0, want);

	/* Delta saturates. */
	mesh_gen_level_srv_init(&srv, 32000);
	d.delta = 1000;
	d.tid = 3;
	ATF_REQUIRE_EQ(0, mesh_gen_delta_set_encode(&d, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_DELTA_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(32767, srv.present);

	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_DELTA_SET, p, 6, &st, &want));
}

ATF_TC_WITHOUT_HEAD(level_server_move);
ATF_TC_BODY(level_server_move, tc)
{
	struct mesh_gen_level_srv srv;
	struct mesh_gen_level_status st;
	struct mesh_gen_move_set m;
	uint8_t p[8];
	size_t plen;
	int want;

	/* Positive move -> upper bound. */
	mesh_gen_level_srv_init(&srv, 0);
	memset(&m, 0, sizeof(m));
	m.delta = 5;
	m.tid = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&m, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_MOVE_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(32767, srv.present);
	ATF_CHECK_EQ(1, want);

	/* Negative move -> lower bound. */
	mesh_gen_level_srv_init(&srv, 0);
	m.delta = -5;
	m.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&m, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_MOVE_SET_UNACK, p, plen, &st, &want));
	ATF_CHECK_EQ(-32768, srv.present);
	ATF_CHECK_EQ(0, want);

	/* Zero move -> unchanged (movement stops). */
	mesh_gen_level_srv_init(&srv, 123);
	m.delta = 0;
	m.tid = 3;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&m, p, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_MOVE_SET, p, plen, &st, &want));
	ATF_CHECK_EQ(123, srv.present);

	ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&srv, 0x1201,
	    MESH_OP_GEN_MOVE_SET, p, 4, &st, &want));
}

/* ================================================================
 * Clients: build helpers + Status parse.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(clients);
ATF_TC_BODY(clients, tc)
{
	struct mesh_gen_onoff_cli oc;
	struct mesh_gen_level_cli lc;
	uint8_t out[16];
	size_t len;
	static const uint8_t exp_get[] = { BTMG_OP_ONOFF_GET >> 8,
	    BTMG_OP_ONOFF_GET & 0xff };
	static const uint8_t exp_set[] = { BTMG_OP_ONOFF_SET >> 8,
	    BTMG_OP_ONOFF_SET & 0xff, BTMG_ON, 0x01 };
	static const uint8_t exp_setu[] = { BTMG_OP_ONOFF_SET_UNACK >> 8,
	    BTMG_OP_ONOFF_SET_UNACK & 0xff, BTMG_ON, 0x01 };

	/* OnOff Get / Set / Set Unacknowledged access PDUs. */
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_get(out, &len));
	ATF_CHECK_EQ(2u, len);
	ATF_CHECK_EQ(0, memcmp(out, exp_get, 2));
	{
		struct mesh_gen_onoff_set s = { 1, 1, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&s, 1, out, &len));
		ATF_CHECK_EQ(4u, len);
		ATF_CHECK_EQ(0, memcmp(out, exp_set, 4));
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&s, 0, out, &len));
		ATF_CHECK_EQ(0, memcmp(out, exp_setu, 4));
		s.onoff = 2;
		ATF_CHECK_EQ(-1, mesh_gen_onoff_cli_set(&s, 1, out, &len));
	}

	/* Level / Delta / Move client builders. */
	ATF_REQUIRE_EQ(0, mesh_gen_level_cli_get(out, &len));
	ATF_CHECK_EQ(BTMG_OP_LEVEL_GET >> 8, out[0]);
	ATF_CHECK_EQ(BTMG_OP_LEVEL_GET & 0xff, out[1]);
	{
		struct mesh_gen_level_set s = { 0x1234, 0x10, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_set(&s, 1, out, &len));
		ATF_CHECK_EQ(BTMG_OP_LEVEL_SET & 0xff, out[1]);
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_set(&s, 0, out, &len));
		ATF_CHECK_EQ(BTMG_OP_LEVEL_SET_UNACK & 0xff, out[1]);
	}
	{
		struct mesh_gen_delta_set s = { -100, 1, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_delta_cli_set(&s, 1, out, &len));
		ATF_CHECK_EQ(BTMG_OP_DELTA_SET & 0xff, out[1]);
		ATF_REQUIRE_EQ(0, mesh_gen_delta_cli_set(&s, 0, out, &len));
		ATF_CHECK_EQ(BTMG_OP_DELTA_SET_UNACK & 0xff, out[1]);
	}
	{
		struct mesh_gen_move_set s = { -2000, 2, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_move_cli_set(&s, 1, out, &len));
		ATF_CHECK_EQ(BTMG_OP_MOVE_SET & 0xff, out[1]);
		ATF_REQUIRE_EQ(0, mesh_gen_move_cli_set(&s, 0, out, &len));
		ATF_CHECK_EQ(BTMG_OP_MOVE_SET_UNACK & 0xff, out[1]);
	}

	/* Client Status parse into last-status cache. */
	mesh_gen_onoff_cli_init(&oc);
	ATF_CHECK_EQ(0, oc.have_status);
	{
		static const uint8_t st1[] = { 0x01 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_recv(&oc,
		    MESH_OP_GEN_ONOFF_STATUS, st1, 1));
		ATF_CHECK_EQ(1, oc.have_status);
		ATF_CHECK_EQ(1, oc.last.present);
	}
	/* Wrong opcode and malformed params rejected. */
	ATF_CHECK_EQ(-1, mesh_gen_onoff_cli_recv(&oc, MESH_OP_GEN_ONOFF_GET,
	    out, 1));
	{
		static const uint8_t bad[] = { 0x02 };
		ATF_CHECK_EQ(-1, mesh_gen_onoff_cli_recv(&oc,
		    MESH_OP_GEN_ONOFF_STATUS, bad, 1));
	}
	ATF_CHECK_EQ(-1, mesh_gen_onoff_cli_recv(NULL,
	    MESH_OP_GEN_ONOFF_STATUS, out, 1));

	mesh_gen_level_cli_init(&lc);
	{
		static const uint8_t st[] = { 0x64, 0x00 };	/* 100 */
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_recv(&lc,
		    MESH_OP_GEN_LEVEL_STATUS, st, 2));
		ATF_CHECK_EQ(1, lc.have_status);
		ATF_CHECK_EQ(100, lc.last.present);
	}
	ATF_CHECK_EQ(-1, mesh_gen_level_cli_recv(&lc, MESH_OP_GEN_LEVEL_GET,
	    out, 2));
	ATF_CHECK_EQ(-1, mesh_gen_level_cli_recv(NULL,
	    MESH_OP_GEN_LEVEL_STATUS, out, 2));
}

/* ================================================================
 * Model-registry dispatch: a Set routed through mesh_access_dispatch
 * updates the server and produces a Status reply in the ctx.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(dispatch_integration);
ATF_TC_BODY(dispatch_integration, tc)
{
	struct mesh_gen_onoff_srv srv;
	struct mesh_gen_onoff_cli cli;
	struct mesh_model_reply gd;
	struct mesh_model models[1];
	struct mesh_element el;
	uint16_t app_idx = 1;
	uint16_t group = 0xc001;
	uint8_t pdu[8];
	size_t plen;

	mesh_gen_onoff_srv_init(&srv, 0);
	models[0] = mesh_gen_onoff_srv_model(&srv);
	models[0].subs = &group;
	models[0].n_subs = 1;
	models[0].subscriptions_configured = 1;
	models[0].app_idx = &app_idx;
	models[0].n_app = 1;
	models[0].bindings_configured = 1;
	ATF_CHECK_EQ(BTMG_MODEL_ONOFF_SRV, models[0].model_id);
	memset(&el, 0, sizeof(el));
	el.addr = 0x0002;
	el.models = models;
	el.n_models = 1;
	el.subs = &group;
	el.n_subs = 1;

	{
		struct mesh_gen_onoff_set s = { 1, 3, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&s, 1, pdu, &plen));
	}
	memset(&gd, 0, sizeof(gd));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 0x0005, 0x0002, pdu,
	    plen, &gd));
	ATF_CHECK_EQ(1, srv.present);
	ATF_CHECK_EQ(1, gd.have_reply);
	ATF_CHECK_EQ(BTMG_OP_ONOFF_STATUS, gd.opcode);
	ATF_CHECK_EQ(0x0002, gd.src);
	ATF_CHECK_EQ(0x0005, gd.dst);

	/* MMDL 1.1 Section 3.1 keys a transaction by SRC, DST, and TID.  The
	 * same source/TID sent to a subscribed group is a new transaction. */
	{
		struct mesh_gen_onoff_set s = { 0, 3, 0, 0, 0 };

		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&s, 0, pdu, &plen));
		ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 0x0005, group,
		    pdu, plen, NULL));
		ATF_CHECK_EQ(0, srv.present);
	}

	/* Feed that reply into a client model registry. */
	mesh_gen_onoff_cli_init(&cli);
	{
		struct mesh_model cm[1];
		struct mesh_element ce;
		uint8_t rpdu[8];
		size_t rlen;

		cm[0] = mesh_gen_onoff_cli_model(&cli);
		ce.addr = 0x0005;
		ce.models = cm;
		ce.n_models = 1;
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(gd.opcode, gd.params,
		    gd.params_len, rpdu, &rlen));
		ATF_REQUIRE_EQ(0, mesh_access_dispatch(&ce, 1, 0x0002, 0x0005,
		    rpdu, rlen, NULL));
		ATF_CHECK_EQ(1, cli.have_status);
		ATF_CHECK_EQ(1, cli.last.present);

		/* Level client model id sanity. */
		cm[0] = mesh_gen_level_cli_model(NULL);
		ATF_CHECK_EQ(BTMG_MODEL_LEVEL_CLI, cm[0].model_id);
		cm[0] = mesh_gen_level_srv_model(NULL);
		ATF_CHECK_EQ(BTMG_MODEL_LEVEL_SRV, cm[0].model_id);
	}
}

/* ================================================================
 * Exhaustive NULL-argument, boundary and defensive-arm coverage.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(null_and_boundary);
ATF_TC_BODY(null_and_boundary, tc)
{
	uint8_t out[8];
	size_t len;
	int want;

	/* Every encoder: out==NULL and outlen==NULL sub-conditions. */
	{
		struct mesh_gen_onoff_set s = { 1, 1, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&s, out, NULL));
	}
	{
		struct mesh_gen_onoff_status s = { 0, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_encode(&s, out, NULL));
	}
	{
		struct mesh_gen_level_set s = { 0, 0, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_level_set_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_level_set_encode(&s, out, NULL));
	}
	{
		struct mesh_gen_delta_set s = { 0, 0, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_encode(&s, out, NULL));
	}
	{
		struct mesh_gen_move_set s = { 0, 0, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_move_set_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_move_set_encode(&s, out, NULL));
	}
	{
		struct mesh_gen_level_status s = { 0, 0, 0, 0 };
		ATF_CHECK_EQ(-1, mesh_gen_level_status_encode(&s, NULL, &len));
		ATF_CHECK_EQ(-1, mesh_gen_level_status_encode(&s, out, NULL));
	}

	/* Every decoder: in==NULL and out==NULL sub-conditions. */
	{
		struct mesh_gen_onoff_set d;
		struct mesh_gen_onoff_status ds;
		struct mesh_gen_level_set dl;
		struct mesh_gen_delta_set dd;
		struct mesh_gen_move_set dm;
		struct mesh_gen_level_status dls;
		static const uint8_t v[8] = { 0 };

		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(NULL, 2, &d));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(v, 2, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(NULL, 1, &ds));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_status_decode(v, 1, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_level_set_decode(NULL, 3, &dl));
		ATF_CHECK_EQ(-1, mesh_gen_level_set_decode(v, 3, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_decode(NULL, 5, &dd));
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_decode(v, 5, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_move_set_decode(NULL, 3, &dm));
		ATF_CHECK_EQ(-1, mesh_gen_move_set_decode(v, 3, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_level_status_decode(NULL, 2, &dls));
		ATF_CHECK_EQ(-1, mesh_gen_level_status_decode(v, 2, NULL));
	}

	/* Client builders with a NULL message hit the encoder-error arm. */
	ATF_CHECK_EQ(-1, mesh_gen_onoff_cli_set(NULL, 1, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_level_cli_set(NULL, 1, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_delta_cli_set(NULL, 1, out, &len));
	ATF_CHECK_EQ(-1, mesh_gen_move_cli_set(NULL, 1, out, &len));

	/* Client init NULL guard and Level Status parse-error arm. */
	mesh_gen_onoff_cli_init(NULL);
	mesh_gen_level_cli_init(NULL);
	{
		struct mesh_gen_level_cli lc;

		mesh_gen_level_cli_init(&lc);
		ATF_CHECK_EQ(-1, mesh_gen_level_cli_recv(&lc,
		    MESH_OP_GEN_LEVEL_STATUS, out, 3));	/* bad length */
	}

	/* Server init: NULL guard and the present>ON clamp ternary. */
	mesh_gen_onoff_srv_init(NULL, 0);
	mesh_gen_level_srv_init(NULL, 0);
	{
		struct mesh_gen_onoff_srv s;

		mesh_gen_onoff_srv_init(&s, 5);		/* clamped to ON */
		ATF_CHECK_EQ(BTMG_ON, s.present);
	}

	/* Server recv NULL status / want_status guards. */
	{
		struct mesh_gen_onoff_srv os;
		struct mesh_gen_level_srv ls;
		struct mesh_gen_onoff_status ost;
		struct mesh_gen_level_status lst;
		int w;

		mesh_gen_onoff_srv_init(&os, 0);
		mesh_gen_level_srv_init(&ls, 0);
		ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(&os, 1,
		    MESH_OP_GEN_ONOFF_GET, NULL, 0, NULL, &w));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_srv_recv(&os, 1,
		    MESH_OP_GEN_ONOFF_GET, NULL, 0, &ost, NULL));
		ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&ls, 1,
		    MESH_OP_GEN_LEVEL_GET, NULL, 0, NULL, &w));
		ATF_CHECK_EQ(-1, mesh_gen_level_srv_recv(&ls, 1,
		    MESH_OP_GEN_LEVEL_GET, NULL, 0, &lst, NULL));

		/* Level Set and Move retransmission (same src+tid) paths. */
		{
			struct mesh_gen_level_set s = { 500, 4, 0, 0, 0 };
			uint8_t p[8];
			size_t pl;

			ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, p, &pl));
			ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&ls, 1,
			    MESH_OP_GEN_LEVEL_SET, p, pl, &lst, &w));
			s.level = 999;			/* same tid: ignored */
			ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&s, p, &pl));
			ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&ls, 1,
			    MESH_OP_GEN_LEVEL_SET, p, pl, &lst, &w));
			ATF_CHECK_EQ(500, ls.present);
		}
		{
			struct mesh_gen_move_set m = { 5, 8, 0, 0, 0 };
			uint8_t p[8];
			size_t pl;

			mesh_gen_level_srv_init(&ls, 0);
			ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&m, p, &pl));
			ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&ls, 1,
			    MESH_OP_GEN_MOVE_SET, p, pl, &lst, &w));
			ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv(&ls, 1,
			    MESH_OP_GEN_MOVE_SET, p, pl, &lst, &w));
			ATF_CHECK_EQ(32767, ls.present);
		}
	}

	/* Reserved transition-time encodings are rejected symmetrically by
	 * every Set encoder and decoder. */
	{
		struct mesh_gen_onoff_set os = { .onoff = 1, .has_transition = 1,
		    .transition_time = BTMG_TRANSITION_RESERVED_STEPS };
		struct mesh_gen_level_set ls = { .has_transition = 1,
		    .transition_time = BTMG_TRANSITION_RESERVED_STEPS };
		struct mesh_gen_delta_set ds = { .has_transition = 1,
		    .transition_time = BTMG_TRANSITION_RESERVED_STEPS };
		struct mesh_gen_move_set ms = { .has_transition = 1,
		    .transition_time = BTMG_TRANSITION_RESERVED_STEPS };
		uint8_t ow[4] = { 1, 1, 0x3f, 0 };
		uint8_t lw[7] = { 0, 0, 1, 0x3f, 0, 0x3f, 0 };

		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_encode(&os, out, &len));
		ATF_CHECK_EQ(-1, mesh_gen_level_set_encode(&ls, out, &len));
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_encode(&ds, out, &len));
		ATF_CHECK_EQ(-1, mesh_gen_move_set_encode(&ms, out, &len));
		ATF_CHECK_EQ(-1, mesh_gen_onoff_set_decode(ow, sizeof(ow), &os));
		ATF_CHECK_EQ(-1, mesh_gen_level_set_decode(lw, 5, &ls));
		ATF_CHECK_EQ(-1, mesh_gen_delta_set_decode(lw, 7, &ds));
		ATF_CHECK_EQ(-1, mesh_gen_move_set_decode(lw, 5, &ms));
	}

	mesh_gen_onoff_srv_bind(NULL, NULL, NULL);
	mesh_gen_onoff_srv_set_present(NULL, 1);
	mesh_gen_level_srv_bind(NULL, NULL, NULL);
	mesh_gen_battery_srv_init(NULL);
	mesh_gen_location_srv_init(NULL);
	mesh_gen_dtt_srv_init(NULL, 0);
	ATF_CHECK_EQ(-1, mesh_gen_power_onoff_srv_recv(NULL, 0, NULL, 0,
	    out, &want));
	ATF_CHECK_EQ(-1, mesh_gen_dtt_srv_recv(NULL, 0, NULL, 0, out,
	    &want));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_srv_recv(NULL, 0, 0, NULL, 0,
	    NULL));
}

/* Dispatch handlers with a NULL model user and a NULL reply ctx. */
ATF_TC_WITHOUT_HEAD(dispatch_defensive);
ATF_TC_BODY(dispatch_defensive, tc)
{
	struct mesh_gen_onoff_srv srv;
	struct mesh_model m[1];
	struct mesh_element el;
	uint8_t pdu[8];
	size_t plen;

	{
		struct mesh_gen_onoff_set s = { 1, 1, 0, 0, 0 };
		ATF_REQUIRE_EQ(0, mesh_gen_onoff_cli_set(&s, 1, pdu, &plen));
	}
	el.addr = 0x0002;
	el.models = m;
	el.n_models = 1;

	/* OnOff handler with a NULL user pointer returns -1. */
	m[0] = mesh_gen_onoff_srv_model(NULL);
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002, pdu,
	    plen, NULL));

	/* OnOff handler where srv_recv rejects a malformed message. */
	{
		struct mesh_gen_onoff_srv s;
		uint8_t bad[4];
		size_t bl;

		mesh_gen_onoff_srv_init(&s, 0);
		m[0] = mesh_gen_onoff_srv_model(&s);
		bad[0] = 0x82;
		bad[1] = 0x02;
		bad[2] = 0x02;		/* onoff = 2, prohibited */
		bad[3] = 0x01;
		bl = 4;
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    bad, bl, NULL));
	}

	/* Level handler: NULL user, and a malformed Level Set (both via a
	 * Level opcode so the level model actually matches). */
	{
		struct mesh_gen_level_srv ls;
		uint8_t lpdu[16];
		size_t ll;
		struct mesh_gen_level_set s = { 42, 1, 0, 0, 0 };

		m[0] = mesh_gen_level_srv_model(NULL);
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_set(&s, 1, lpdu, &ll));
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    lpdu, ll, NULL));

		mesh_gen_level_srv_init(&ls, 0);
		m[0] = mesh_gen_level_srv_model(&ls);
		/* Level Set opcode 0x8206 with a truncated 2-octet param. */
		lpdu[0] = 0x82;
		lpdu[1] = 0x06;
		lpdu[2] = 0x00;
		lpdu[3] = 0x00;		/* only 2 param octets: invalid */
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    lpdu, 4, NULL));
	}

	/* Client handlers with a NULL user pointer over a Status PDU. */
	{
		uint8_t st[4];
		size_t stl;
		struct mesh_gen_onoff_status oss = { 1, 0, 0, 0 };

		ATF_REQUIRE_EQ(0, mesh_gen_onoff_status_encode(&oss, st + 2,
		    &stl));
		st[0] = 0x82;
		st[1] = 0x04;
		m[0] = mesh_gen_onoff_cli_model(NULL);
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    st, stl + 2, NULL));
		st[1] = 0x08;
		m[0] = mesh_gen_level_cli_model(NULL);
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    st, stl + 2, NULL));
	}

	/* Acknowledged Set with a NULL ctx: want_status true but no reply
	 * sink (the d != NULL guard False arm). */
	mesh_gen_onoff_srv_init(&srv, 0);
	m[0] = mesh_gen_onoff_srv_model(&srv);
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x0005, 0x0002, pdu,
	    plen, NULL));
	ATF_CHECK_EQ(1, srv.present);
	/* Same for the Level server. */
	{
		struct mesh_gen_level_srv ls;
		struct mesh_gen_level_set s = { 7, 1, 0, 0, 0 };

		mesh_gen_level_srv_init(&ls, 0);
		m[0] = mesh_gen_level_srv_model(&ls);
		ATF_REQUIRE_EQ(0, mesh_gen_level_cli_set(&s, 1, pdu, &plen));
		ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 0x0005, 0x0002,
		    pdu, plen, NULL));
		ATF_CHECK_EQ(7, ls.present);
	}
}

ATF_TC_WITHOUT_HEAD(power_onoff_vertical);
ATF_TC_BODY(power_onoff_vertical, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_power_onoff_srv srv;
	struct mesh_gen_power_onoff_cli cli;
	uint8_t pdu[8], status;
	size_t plen;
	int want;
	static const uint8_t restore[] = { BTMG_ONPOWERUP_RESTORE };

	mesh_gen_onoff_srv_init(&onoff, BTMG_ON);
	mesh_gen_power_onoff_srv_init(&srv, &onoff, BTMG_ONPOWERUP_OFF);
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_srv_recv(&srv,
	    MESH_OP_GEN_ONPOWERUP_GET, NULL, 0, &status, &want));
	ATF_CHECK_EQ(BTMG_ONPOWERUP_OFF, status);
	ATF_CHECK_EQ(1, want);
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_srv_recv(&srv,
	    MESH_OP_GEN_ONPOWERUP_SET, restore, sizeof(restore), &status, &want));
	ATF_CHECK_EQ(BTMG_ONPOWERUP_RESTORE, srv.on_power_up);
	ATF_CHECK_EQ(1, want);
	ATF_CHECK_EQ(-1, mesh_gen_power_onoff_srv_recv(&srv,
	    MESH_OP_GEN_ONPOWERUP_SET, (const uint8_t[]){ 3 }, 1,
	    &status, &want));

	/* Bound state follows the configured behavior across a power cycle. */
	srv.on_power_up = BTMG_ONPOWERUP_OFF;
	mesh_gen_power_onoff_srv_power_cycle(&srv);
	ATF_CHECK_EQ(BTMG_OFF, onoff.present);
	srv.on_power_up = BTMG_ONPOWERUP_DEFAULT;
	mesh_gen_power_onoff_srv_power_cycle(&srv);
	ATF_CHECK_EQ(BTMG_ON, onoff.present);

	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_get(pdu, &plen));
	ATF_CHECK_EQ(2u, plen);
	ATF_CHECK_EQ(BTMG_OP_ONPOWERUP_GET >> 8, pdu[0]);
	ATF_CHECK_EQ(BTMG_OP_ONPOWERUP_GET & 0xff, pdu[1]);
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_set(
	    BTMG_ONPOWERUP_RESTORE, 1, pdu, &plen));
	ATF_CHECK_EQ(3u, plen);
	ATF_CHECK_EQ(BTMG_OP_ONPOWERUP_SET & 0xff, pdu[1]);
	ATF_CHECK_EQ(-1, mesh_gen_power_onoff_cli_set(3, 1, pdu, &plen));
	mesh_gen_power_onoff_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_recv(&cli,
	    MESH_OP_GEN_ONPOWERUP_STATUS, restore, sizeof(restore)));
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(BTMG_ONPOWERUP_RESTORE, cli.on_power_up);
	ATF_CHECK_EQ(BTMG_MODEL_POWER_ONOFF_SRV,
	    mesh_gen_power_onoff_srv_model(&srv).model_id);
	ATF_CHECK_EQ(BTMG_MODEL_POWER_ONOFF_SETUP_SRV,
	    mesh_gen_power_onoff_setup_srv_model(&srv).model_id);
}

ATF_TC_WITHOUT_HEAD(default_transition_time_vertical);
ATF_TC_BODY(default_transition_time_vertical, tc)
{
	struct mesh_gen_dtt_srv srv;
	struct mesh_gen_dtt_cli cli;
	uint8_t pdu[4], status;
	size_t plen;
	int want;
	static const uint8_t one_second[] = { 0x0a };

	ATF_CHECK(mesh_gen_transition_time_valid(BTMG_TRANSITION_ONE_SECOND));
	ATF_CHECK(!mesh_gen_transition_time_valid(
	    BTMG_TRANSITION_RESERVED_STEPS));
	ATF_CHECK(!mesh_gen_transition_time_valid(0xff));
	mesh_gen_dtt_srv_init(&srv, BTMG_TRANSITION_ONE_SECOND);
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_srv_recv(&srv, MESH_OP_GEN_DTT_GET,
	    NULL, 0, &status, &want));
	ATF_CHECK_EQ(BTMG_TRANSITION_ONE_SECOND, status);
	ATF_CHECK_EQ(1, want);
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_srv_recv(&srv, MESH_OP_GEN_DTT_SET_UNACK,
	    (const uint8_t[]){ BTMG_TRANSITION_ONE_STEP_1S }, 1, &status, &want));
	ATF_CHECK_EQ(BTMG_TRANSITION_ONE_STEP_1S, srv.transition_time);
	ATF_CHECK_EQ(0, want);
	ATF_CHECK_EQ(-1, mesh_gen_dtt_srv_recv(&srv, MESH_OP_GEN_DTT_SET,
	    (const uint8_t[]){ BTMG_TRANSITION_RESERVED_STEPS }, 1, &status,
	    &want));
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_get(pdu, &plen));
	ATF_CHECK_EQ(BTMG_OP_DTT_GET & 0xff, pdu[1]);
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_set(BTMG_TRANSITION_ONE_SECOND, 1,
	    pdu, &plen));
	ATF_CHECK_EQ(BTMG_OP_DTT_SET & 0xff, pdu[1]);
	ATF_CHECK_EQ(-1, mesh_gen_dtt_cli_set(BTMG_TRANSITION_RESERVED_STEPS,
	    1, pdu, &plen));
	mesh_gen_dtt_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_recv(&cli, MESH_OP_GEN_DTT_STATUS,
	    one_second, sizeof(one_second)));
	ATF_CHECK_EQ(1, cli.have_status);
	ATF_CHECK_EQ(BTMG_TRANSITION_ONE_SECOND, cli.transition_time);
	ATF_CHECK_EQ(BTMG_MODEL_DTT_SRV,
	    mesh_gen_dtt_srv_model(&srv).model_id);
}

ATF_TC_WITHOUT_HEAD(power_level_bindings);
ATF_TC_BODY(power_level_bindings, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_gen_power_onoff_srv power_onoff;
	struct mesh_gen_power_level_srv power;
	struct mesh_model_reply reply;
	struct mesh_gen_power_level_cli cli;
	uint8_t pdu[8];
	size_t plen;
	static const uint8_t set500[] = { 0xf4, 0x01, 0x22 };
	static const uint8_t range_bad[] = { 0x00, 0x00, 0xe8, 0x03 };
	static const uint8_t range_ok[] = { 0x64, 0x00, 0xe8, 0x03 };
	static const uint8_t range_inverted[] = { 0xe8, 0x03, 0x64, 0x00 };

	mesh_gen_onoff_srv_init(&onoff, BTMG_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_gen_power_onoff_srv_init(&power_onoff, &onoff,
	    BTMG_ONPOWERUP_RESTORE);
	mesh_gen_power_level_srv_init(&power, &onoff, &level, &power_onoff);
	power.range_min = 100;
	power.range_max = 1000;
	mesh_gen_power_level_set_actual(&power, 50);
	ATF_CHECK_EQ(100, power.actual);
	ATF_CHECK_EQ(100, power.last);
	ATF_CHECK_EQ(BTMG_ON, onoff.present);
	ATF_CHECK_EQ((int16_t)(100 - 32768), level.present);
	mesh_gen_power_level_set_actual(&power, 0);
	ATF_CHECK_EQ(0, power.actual);
	ATF_CHECK_EQ(100, power.last);
	ATF_CHECK_EQ(BTMG_OFF, onoff.present);
	power.default_power = 500;
	power_onoff.on_power_up = BTMG_ONPOWERUP_DEFAULT;
	mesh_gen_power_level_power_cycle(&power);
	ATF_CHECK_EQ(500, power.actual);
	power.default_power = 0;
	mesh_gen_power_level_power_cycle(&power);
	ATF_CHECK_EQ(500, power.actual);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_LEVEL_SET, set500, sizeof(set500), &reply));
	ATF_CHECK_EQ(1, reply.have_reply);
	ATF_CHECK_EQ(BTMG_OP_POWER_LEVEL_STATUS, reply.opcode);
	ATF_CHECK_EQ(2u, reply.params_len);
	ATF_CHECK_EQ(500, power.actual);
	/* Same TID/source is a retransmission and cannot apply a new value. */
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_LEVEL_SET_UNACK,
	    (const uint8_t[]){ 0x58, 0x02, 0x22 }, 3, NULL));
	ATF_CHECK_EQ(500, power.actual);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_RANGE_SET, range_bad, sizeof(range_bad), &reply));
	ATF_CHECK_EQ(BTMG_POWER_RANGE_STATUS_MIN, reply.params[0]);
	ATF_CHECK_EQ(100, power.range_min);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_RANGE_SET, range_ok, sizeof(range_ok), &reply));
	ATF_CHECK_EQ(BTMG_POWER_RANGE_STATUS_SUCCESS, reply.params[0]);
	ATF_CHECK_EQ(1000, power.range_max);
	/*
	 * Mesh Model 1.1.1 §3.3.6: Range Min greater than Range Max
	 * makes the message invalid and ignored.  It must not be converted
	 * into status 0x02 (Cannot Set Range Max), mutate state, or reply.
	 */
	power.range_status = BTMG_POWER_RANGE_STATUS_MIN;
	ATF_CHECK_EQ(-1, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_RANGE_SET, range_inverted,
	    sizeof(range_inverted), &reply));
	ATF_CHECK_EQ(0, reply.have_reply);
	ATF_CHECK_EQ(BTMG_POWER_RANGE_STATUS_MIN, power.range_status);
	ATF_CHECK_EQ(100, power.range_min);
	ATF_CHECK_EQ(1000, power.range_max);
	ATF_CHECK_EQ(-1, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_LEVEL_SET, set500, 4, &reply));
	ATF_CHECK_EQ(BTMG_MODEL_POWER_LEVEL_SRV,
	    mesh_gen_power_level_srv_model(&power).model_id);
	ATF_CHECK_EQ(BTMG_MODEL_POWER_LEVEL_SETUP_SRV,
	    mesh_gen_power_level_setup_srv_model(&power).model_id);
	mesh_gen_power_level_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_set(500, 9, 1, pdu, &plen));
	ATF_CHECK_EQ(5u, plen);
	ATF_CHECK_EQ(BTMG_OP_POWER_LEVEL_SET & 0xff, pdu[1]);
	ATF_REQUIRE_EQ(0, mesh_gen_power_range_cli_set(100, 1000, 1, pdu,
	    &plen));
	ATF_CHECK_EQ(6u, plen);
	ATF_CHECK_EQ(-1, mesh_gen_power_range_cli_set(0, 1000, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_recv(&cli,
	    MESH_OP_GEN_POWER_RANGE_STATUS,
	    (const uint8_t[]){ 0, 100, 0, 0xe8, 0x03 }, 5));
	ATF_CHECK_EQ(1, cli.have_range);
	ATF_CHECK_EQ(1000, cli.range_max);
}

ATF_TC_WITHOUT_HEAD(battery_vertical);
ATF_TC_BODY(battery_vertical, tc)
{
	struct mesh_gen_battery_status in, out;
	struct mesh_gen_battery_cli cli;
	uint8_t wire[8], pdu[4];
	size_t plen;

	memset(&in, 0, sizeof(in));
	in.level = 85;
	in.discharge_minutes = 0x010203;
	in.charge_minutes = 0x040506;
	/* Serviceability=01; Charging/Indicator/Presence=10. */
	in.flags = BTMG_BATTERY_FLAGS_VALID_SAMPLE;
	ATF_REQUIRE_EQ(0, mesh_gen_battery_status_encode(&in, wire));
	ATF_CHECK_EQ(0x03, wire[1]);
	ATF_CHECK_EQ(0x02, wire[2]);
	ATF_CHECK_EQ(0x01, wire[3]);
	ATF_REQUIRE_EQ(0, mesh_gen_battery_status_decode(wire, sizeof(wire),
	    &out));
	ATF_CHECK_EQ(85, out.level);
	ATF_CHECK_EQ(0x040506u, out.charge_minutes);
	in.level = BTMG_BATTERY_LEVEL_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_gen_battery_status_encode(&in, wire));
	/* All four 0b11 fields mean unknown and are valid. */
	in.level = 85; in.flags = BTMG_BATTERY_FLAGS_ALL_UNKNOWN;
	ATF_CHECK_EQ(0, mesh_gen_battery_status_encode(&in, wire));
	/* Serviceability=0b00 is Reserved for Future Use. */
	in.flags = BTMG_BATTERY_FLAGS_RESERVED_SAMPLE;
	ATF_CHECK_EQ(-1, mesh_gen_battery_status_encode(&in, wire));
	/*
	 * Mesh Model 1.1.1 Tables 3.12-3.15 define all 2-bit flag values;
	 * only Serviceability=0b00 (bits 7:6) is reserved.  Exhaust the
	 * complete octet so no valid "unknown" field is rejected again.
	 */
	for (unsigned int flags = 0; flags <= UINT8_MAX; flags++) {
		in.flags = (uint8_t)flags;
		if (((flags >> 6) & 0x03) == 0)
			ATF_CHECK_EQ(-1, mesh_gen_battery_status_encode(&in, wire));
		else
			ATF_CHECK_EQ(0, mesh_gen_battery_status_encode(&in, wire));
	}
	in.flags = BTMG_BATTERY_FLAGS_ALL_UNKNOWN;
	ATF_REQUIRE_EQ(0, mesh_gen_battery_status_encode(&in, wire));
	mesh_gen_battery_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_gen_battery_cli_get(pdu, &plen));
	ATF_CHECK_EQ(2u, plen);
	ATF_CHECK_EQ(BTMG_OP_BATTERY_GET & 0xff, pdu[1]);
	ATF_REQUIRE_EQ(0, mesh_gen_battery_cli_recv(&cli,
	    MESH_OP_GEN_BATTERY_STATUS, wire, sizeof(wire)));
	ATF_CHECK_EQ(1, cli.have_status);
}

ATF_TC_WITHOUT_HEAD(location_vertical);
ATF_TC_BODY(location_vertical, tc)
{
	struct mesh_gen_location_global g = { -123456, 654321, 42 }, gd;
	struct mesh_gen_location_local l = { -10, 20, 3, 7, 0x1234 }, ld;
	struct mesh_gen_location_cli cli;
	uint8_t gw[10], lw[9], pdu[16];
	size_t plen;

	ATF_REQUIRE_EQ(0, mesh_gen_location_global_encode(&g, gw));
	ATF_REQUIRE_EQ(0, mesh_gen_location_global_decode(gw, sizeof(gw), &gd));
	ATF_CHECK_EQ(g.latitude, gd.latitude);
	ATF_CHECK_EQ(g.longitude, gd.longitude);
	ATF_REQUIRE_EQ(0, mesh_gen_location_local_encode(&l, lw));
	ATF_REQUIRE_EQ(0, mesh_gen_location_local_decode(lw, sizeof(lw), &ld));
	ATF_CHECK_EQ(l.north, ld.north);
	ATF_CHECK_EQ(l.uncertainty, ld.uncertainty);
	ATF_CHECK_EQ(-1, mesh_gen_location_local_decode(lw, 8, &ld));
	mesh_gen_location_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_set_global(&g, 1, pdu, &plen));
	ATF_CHECK_EQ(11u, plen); /* one-octet opcode + ten parameters */
	ATF_CHECK_EQ(BTMG_OP_LOCATION_GLOBAL_SET, pdu[0]);
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_set_local(&l, 1, pdu, &plen));
	ATF_CHECK_EQ(11u, plen); /* two-octet opcode + nine parameters */
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_recv(&cli,
	    MESH_OP_GEN_LOCATION_GLOBAL_STATUS, gw, sizeof(gw)));
	ATF_CHECK_EQ(1, cli.have_global);
}

ATF_TC_WITHOUT_HEAD(extended_client_matrix);
ATF_TC_BODY(extended_client_matrix, tc)
{
	struct mesh_gen_dtt_cli dtt;
	struct mesh_gen_power_onoff_cli ponoff;
	struct mesh_gen_power_level_cli power;
	struct mesh_gen_battery_cli battery;
	struct mesh_gen_location_cli location;
	struct mesh_gen_battery_status bst = { 50, 10, 20,
	    BTMG_BATTERY_FLAGS_ALL_UNKNOWN };
	struct mesh_gen_location_global global = { 1, -2, 3 };
	struct mesh_gen_location_local local = { 1, 2, 3, 4, 5 };
	uint8_t pdu[32], bwire[8], gwire[10], lwire[9];
	size_t plen;

	mesh_gen_dtt_cli_init(&dtt);
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_set(0x21, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_gen_dtt_cli_set(0x3f, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_dtt_cli_recv(&dtt, MESH_OP_GEN_DTT_STATUS,
	    (const uint8_t[]){ 0x21 }, 1));
	ATF_CHECK_EQ(-1, mesh_gen_dtt_cli_recv(&dtt, 0,
	    (const uint8_t[]){ 0x21 }, 1));
	ATF_CHECK_EQ(-1, mesh_gen_dtt_cli_recv(&dtt, MESH_OP_GEN_DTT_STATUS,
	    (const uint8_t[]){ 0x3f }, 1));

	mesh_gen_power_onoff_cli_init(&ponoff);
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_set(
	    BTMG_ONPOWERUP_RESTORE, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_gen_power_onoff_cli_set(3, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_onoff_cli_recv(&ponoff,
	    MESH_OP_GEN_ONPOWERUP_STATUS,
	    (const uint8_t[]){ BTMG_ONPOWERUP_DEFAULT }, 1));
	ATF_CHECK_EQ(-1, mesh_gen_power_onoff_cli_recv(&ponoff, 0,
	    (const uint8_t[]){ 1 }, 1));

	mesh_gen_power_level_cli_init(&power);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_last_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_default_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_range_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_set(0x1234, 1, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_default_cli_set(0x2345, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_range_cli_set(1, 0xffff, 0, pdu,
	    &plen));
	ATF_CHECK_EQ(-1, mesh_gen_power_range_cli_set(2, 1, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_LEVEL_STATUS,
	    (const uint8_t[]){ 0x34, 0x12 }, 2));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_LEVEL_STATUS,
	    (const uint8_t[]){ 0x34, 0x12, 0x45, 0x23, 0x21 }, 5));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_LAST_STATUS,
	    (const uint8_t[]){ 1, 0 }, 2));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_LAST_STATUS,
	    (const uint8_t[]){ 0, 0 }, 2));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_DEFAULT_STATUS,
	    (const uint8_t[]){ 2, 0 }, 2));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_cli_recv(&power, 0,
	    (const uint8_t[]){ 2, 0 }, 2));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_cli_recv(&power,
	    MESH_OP_GEN_POWER_RANGE_STATUS,
	    (const uint8_t[]){ 3, 1, 0, 2, 0 }, 5));

	mesh_gen_battery_cli_init(&battery);
	ATF_REQUIRE_EQ(0, mesh_gen_battery_status_encode(&bst, bwire));
	ATF_REQUIRE_EQ(0, mesh_gen_battery_cli_recv(&battery,
	    MESH_OP_GEN_BATTERY_STATUS, bwire, sizeof(bwire)));
	ATF_CHECK_EQ(-1, mesh_gen_battery_cli_recv(&battery, 0, bwire,
	    sizeof(bwire)));

	mesh_gen_location_cli_init(&location);
	ATF_REQUIRE_EQ(0, mesh_gen_location_global_encode(&global, gwire));
	ATF_REQUIRE_EQ(0, mesh_gen_location_local_encode(&local, lwire));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_get(1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_get(0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_set_global(&global, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_set_local(&local, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_recv(&location,
	    MESH_OP_GEN_LOCATION_GLOBAL_STATUS, gwire, sizeof(gwire)));
	ATF_REQUIRE_EQ(0, mesh_gen_location_cli_recv(&location,
	    MESH_OP_GEN_LOCATION_LOCAL_STATUS, lwire, sizeof(lwire)));
	ATF_CHECK_EQ(-1, mesh_gen_location_cli_recv(&location, 0, lwire,
	    sizeof(lwire)));
}

ATF_TC_WITHOUT_HEAD(timed_transition_and_tid_window);
ATF_TC_BODY(timed_transition_and_tid_window, tc)
{
	struct mesh_gen_level_srv srv;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_dtt_srv dtt;
	struct mesh_gen_power_level_srv power;
	struct mesh_gen_level_set set;
	struct mesh_gen_move_set move;
	struct mesh_gen_level_status status;
	struct mesh_gen_onoff_status onoff_status;
	struct mesh_model model;
	struct mesh_element element;
	struct mesh_model_reply reply;
	uint8_t params[5];
	size_t plen;
	int want;

	mesh_gen_level_srv_init(&srv, 0);
	memset(&set, 0, sizeof(set));
	set.level = 1000;
	set.tid = 9;
	set.has_transition = 1;
	set.transition_time = 0x0a;	/* 10 * 100 ms */
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&set, params, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_SET, params, plen, &status, &want, 1000));
	ATF_CHECK_EQ(0, status.present);
	ATF_CHECK_EQ(1, status.has_target);
	ATF_CHECK_EQ(1000, status.target);
	model = mesh_gen_level_srv_model(&srv);
	memset(&element, 0, sizeof(element));
	element.addr = 1; element.models = &model; element.n_models = 1;
	mesh_access_tick(&element, 1, 1500);
	ATF_CHECK_EQ(500, srv.present);
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, &status, &want, 1500));
	ATF_CHECK_EQ(500, status.present);
	ATF_CHECK_EQ(0x05, status.remaining);
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, &status, &want, 2000));
	ATF_CHECK_EQ(1000, status.present);
	ATF_CHECK_EQ(0, status.has_target);

	set.level = 2000;
	set.has_transition = 0;
	ATF_REQUIRE_EQ(0, mesh_gen_level_set_encode(&set, params, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_SET, params, plen, &status, &want, 6000));
	ATF_CHECK_EQ(1000, status.present);	/* same transaction */
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_SET, params, plen, &status, &want, 7001));
	ATF_CHECK_EQ(2000, status.present);	/* six-second window expired */

	/* Move delta is a rate per transition period, not total duration. */
	mesh_gen_level_srv_init(&srv, 0);
	memset(&move, 0, sizeof(move));
	move.delta = 1000; move.tid = 1; move.has_transition = 1;
	move.transition_time = 0x0a;
	ATF_REQUIRE_EQ(0, mesh_gen_move_set_encode(&move, params, &plen));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_MOVE_SET, params, plen, &status, &want, 0));
	ATF_REQUIRE_EQ(0, mesh_gen_level_srv_recv_at(&srv, 1,
	    MESH_OP_GEN_LEVEL_GET, NULL, 0, &status, &want, 1000));
	ATF_CHECK_EQ(1000, status.present);
	ATF_CHECK_EQ(INT16_MAX, status.target);

	/* Power Level uses the injected clock and emits target/remaining status. */
	mesh_gen_power_level_srv_init(&power, NULL, NULL, NULL);
	params[0] = 0xe8; params[1] = 0x03; params[2] = 4;
	params[3] = 0x0a; params[4] = 0;
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv_at(&power, 1,
	    MESH_OP_GEN_POWER_LEVEL_SET, params, 5, &reply, 1000));
	ATF_CHECK_EQ(5u, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv_at(&power, 1,
	    MESH_OP_GEN_POWER_LEVEL_GET, NULL, 0, &reply, 1500));
	ATF_CHECK_EQ(500, power.actual);
	ATF_CHECK_EQ(BTMG_TRANSITION_HALF_SECOND, reply.params[4]);

	mesh_gen_onoff_srv_init(&onoff, BTMG_OFF);
	mesh_gen_dtt_srv_init(&dtt, 0x0a);
	onoff.dtt = &dtt;
	params[0] = BTMG_ON; params[1] = 1;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv_at(&onoff, 1,
	    MESH_OP_GEN_ONOFF_SET, params, 2,
	    &onoff_status, &want, 1000));
	ATF_CHECK_EQ(BTMG_ON, onoff.present);
	ATF_CHECK_EQ(1, onoff_status.has_target);

	/*
	 * Mesh Model 1.1.1 §3.1.1, Figures 3.1-3.2: On -> Off retains
	 * Present OnOff=On until the transition finishes.
	 */
	mesh_gen_onoff_srv_init(&onoff, BTMG_ON);
	params[0] = BTMG_OFF;
	params[1] = 2;
	params[2] = 0x0a;	/* 10 steps at 100 ms = one second. */
	params[3] = 0;
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv_at(&onoff, 1,
	    MESH_OP_GEN_ONOFF_SET, params, 4, &onoff_status, &want, 3000));
	ATF_CHECK_EQ(BTMG_ON, onoff.present);
	ATF_CHECK_EQ(BTMG_OFF, onoff_status.target);
	model = mesh_gen_onoff_srv_model(&onoff);
	element.models = &model;
	mesh_access_tick(&element, 1, 3500);
	ATF_CHECK_EQ(BTMG_ON, onoff.present);
	mesh_access_tick(&element, 1, 4000);
	ATF_CHECK_EQ(BTMG_OFF, onoff.present);

	/* Delay is encoded in five-millisecond steps (§3.2.1.2). */
	mesh_gen_onoff_srv_init(&onoff, BTMG_OFF);
	params[0] = BTMG_ON;
	params[1] = 3;
	params[2] = 0;
	params[3] = 10;	/* 50 ms delay, zero transition duration. */
	ATF_REQUIRE_EQ(0, mesh_gen_onoff_srv_recv_at(&onoff, 1,
	    MESH_OP_GEN_ONOFF_SET, params, 4, &onoff_status, &want, 5000));
	ATF_CHECK_EQ(BTMG_OFF, onoff.present);
	model = mesh_gen_onoff_srv_model(&onoff);
	element.models = &model;
	mesh_access_tick(&element, 1, 5049);
	ATF_CHECK_EQ(BTMG_OFF, onoff.present);
	mesh_access_tick(&element, 1, 5050);
	ATF_CHECK_EQ(BTMG_ON, onoff.present);
}

ATF_TC_WITHOUT_HEAD(server_model_handler_matrix);
ATF_TC_BODY(server_model_handler_matrix, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_gen_power_onoff_srv power_onoff;
	struct mesh_gen_dtt_srv dtt;
	struct mesh_gen_power_level_srv power;
	struct mesh_gen_battery_srv battery;
	struct mesh_gen_location_srv location;
	struct mesh_model model;
	struct mesh_model_reply reply;
	uint8_t params[16];

	mesh_gen_onoff_srv_init(&onoff, BTMG_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_gen_power_onoff_srv_init(&power_onoff, &onoff,
	    BTMG_ONPOWERUP_OFF);
	mesh_gen_power_onoff_srv_init(NULL, &onoff, BTMG_ONPOWERUP_OFF);
	mesh_gen_power_onoff_srv_power_cycle(NULL);
	{
		struct mesh_gen_power_onoff_srv unbound;
		mesh_gen_power_onoff_srv_init(&unbound, NULL,
		    BTMG_ONPOWERUP_OFF);
		mesh_gen_power_onoff_srv_power_cycle(&unbound);
	}
	model = mesh_gen_power_onoff_srv_model(&power_onoff);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_ONPOWERUP_GET,
	    NULL, 0, &reply));
	ATF_CHECK(reply.have_reply);
	model = mesh_gen_power_onoff_setup_srv_model(&power_onoff);
	params[0] = BTMG_ONPOWERUP_RESTORE;
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_ONPOWERUP_SET,
	    params, 1, &reply));
	ATF_CHECK(reply.have_reply);
	ATF_CHECK_EQ(-1, dispatch_model(&model, MESH_OP_GEN_ONPOWERUP_SET,
	    params, 0, &reply));
	onoff.present = BTMG_OFF;
	power_onoff.last_onoff = BTMG_ON;
	power_onoff.on_power_up = BTMG_ONPOWERUP_RESTORE;
	mesh_gen_power_onoff_srv_power_cycle(&power_onoff);
	ATF_CHECK_EQ(BTMG_ON, onoff.present);

	mesh_gen_dtt_srv_init(&dtt, 0x0a);
	model = mesh_gen_dtt_srv_model(&dtt);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_DTT_GET, NULL, 0,
	    &reply));
	ATF_CHECK(reply.have_reply);
	params[0] = 0x14;
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_DTT_SET, params, 1,
	    &reply));

	mesh_gen_power_level_srv_init(&power, &onoff, &level, &power_onoff);
	mesh_gen_power_level_srv_init(NULL, &onoff, &level, &power_onoff);
	mesh_gen_power_level_set_actual(NULL, 1);
	mesh_gen_power_level_power_cycle(NULL);
	model = mesh_gen_power_level_srv_model(&power);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_POWER_LEVEL_GET,
	    NULL, 0, &reply));
	ATF_CHECK(reply.have_reply);
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_LAST_GET, NULL, 0, &reply));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_DEFAULT_GET, NULL, 0, &reply));
	ATF_REQUIRE_EQ(0, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_RANGE_GET, NULL, 0, &reply));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_srv_recv(&power, 1,
	    MESH_OP_GEN_POWER_LAST_GET, params, 1, &reply));
	ATF_CHECK_EQ(-1, mesh_gen_power_level_srv_recv(&power, 1, 0xffffffff,
	    NULL, 0, &reply));
	model = mesh_gen_power_level_setup_srv_model(&power);
	params[0] = 0x34; params[1] = 0x12;
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_POWER_DEFAULT_SET,
	    params, 2, &reply));
	ATF_CHECK(reply.have_reply);

	mesh_gen_battery_srv_init(&battery);
	model = mesh_gen_battery_srv_model(&battery);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model, MESH_OP_GEN_BATTERY_GET, NULL,
	    0, &reply));
	ATF_CHECK_EQ(8u, reply.params_len);
	ATF_CHECK_EQ(-1, dispatch_model(&model, MESH_OP_GEN_BATTERY_GET, params,
	    1, &reply));

	mesh_gen_location_srv_init(&location);
	model = mesh_gen_location_srv_model(&location);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model,
	    MESH_OP_GEN_LOCATION_GLOBAL_GET, NULL, 0, &reply));
	ATF_CHECK_EQ(10u, reply.params_len);
	ATF_REQUIRE_EQ(0, dispatch_model(&model,
	    MESH_OP_GEN_LOCATION_LOCAL_GET, NULL, 0, &reply));
	model = mesh_gen_location_setup_srv_model(&location);
	ATF_REQUIRE_EQ(0, mesh_gen_location_global_encode(&location.global,
	    params));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, dispatch_model(&model,
	    MESH_OP_GEN_LOCATION_GLOBAL_SET, params, 10, &reply));
	ATF_CHECK(reply.have_reply);
	ATF_REQUIRE_EQ(0, mesh_gen_location_local_encode(&location.local,
	    params));
	ATF_REQUIRE_EQ(0, dispatch_model(&model,
	    MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK, params, 9, &reply));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, assigned_numbers_contract);
	ATF_TP_ADD_TC(tp, onoff_set_codec);
	ATF_TP_ADD_TC(tp, onoff_set_negative);
	ATF_TP_ADD_TC(tp, onoff_status_codec);
	ATF_TP_ADD_TC(tp, level_set_codec);
	ATF_TP_ADD_TC(tp, delta_move_codec);
	ATF_TP_ADD_TC(tp, level_status_codec);
	ATF_TP_ADD_TC(tp, sat_add);
	ATF_TP_ADD_TC(tp, onoff_server);
	ATF_TP_ADD_TC(tp, level_server_set_get);
	ATF_TP_ADD_TC(tp, level_server_delta);
	ATF_TP_ADD_TC(tp, level_server_move);
	ATF_TP_ADD_TC(tp, clients);
	ATF_TP_ADD_TC(tp, dispatch_integration);
	ATF_TP_ADD_TC(tp, null_and_boundary);
	ATF_TP_ADD_TC(tp, dispatch_defensive);
	ATF_TP_ADD_TC(tp, power_onoff_vertical);
	ATF_TP_ADD_TC(tp, default_transition_time_vertical);
	ATF_TP_ADD_TC(tp, power_level_bindings);
	ATF_TP_ADD_TC(tp, battery_vertical);
	ATF_TP_ADD_TC(tp, location_vertical);
	ATF_TP_ADD_TC(tp, extended_client_matrix);
	ATF_TP_ADD_TC(tp, timed_transition_and_tid_window);
	ATF_TP_ADD_TC(tp, server_model_handler_matrix);

	return (atf_no_error());
}
