/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh Key Refresh procedure state machine
 * (mesh_key_refresh.[ch], MshPRT_v1.1 Section 3.11.4).
 *
 * Behavioural tests over the phase transitions (0->1->2->3->0), the
 * per-phase TX/RX key selection table, and the beacon Key-Refresh-Flag that
 * drives the phase advance.
 */

#include <sys/types.h>

#include <atf-c.h>

#include "mesh_key_refresh.h"
#include "spec_oracles.h"

/* ================================================================
 * Full phase walk: 0 -> 1 (begin) -> 2 (new-key KR=1 beacon) -> 3
 * (new-key KR=0 beacon); the owner then promotes the key and resets to 0.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_kr_phase_walk);
ATF_TC_BODY(mesh_kr_phase_walk, tc)
{
	struct mesh_key_refresh st;

	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_NORMAL, MESH_KR_PHASE_NORMAL);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_1, MESH_KR_PHASE_1);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_2, MESH_KR_PHASE_2);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3, MESH_KR_PHASE_3);

	mesh_kr_init(&st);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_NORMAL, mesh_kr_phase(&st));

	/* 0 -> 1: local begin (new key distributed). */
	ATF_CHECK_EQ(0, mesh_kr_begin(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_1, mesh_kr_phase(&st));
	/* Begin again is refused (already refreshing). */
	ATF_CHECK_EQ_MSG(-1, mesh_kr_begin(&st),
	    "begin must be refused when not in Phase 0");

	/* 1 -> 2: beacon with Key Refresh Flag SET. */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_2,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));

	/* 2 -> 3: beacon with Key Refresh Flag CLEAR (revocation begins). */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));

	/* Phase 3 stays latched until the owner has actually promoted the key. */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));
	mesh_kr_init(&st);	/* owner completed revocation/key promotion */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_NORMAL, mesh_kr_phase(&st));
}

/* ================================================================
 * Beacon flag behavior includes the §3.11.4.1 robustness rule: in Phase 1,
 * a beacon authenticated with the new NetKey and KR=0 skips Phase 2 and
 * immediately selects Phase 3.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_kr_flag_stability);
ATF_TC_BODY(mesh_kr_flag_stability, tc)
{
	struct mesh_key_refresh st;

	mesh_kr_init(&st);
	ATF_REQUIRE_EQ(0, mesh_kr_begin(&st));	/* Phase 1 */

	/* Advance to Phase 2 and prove repeated KR=1 is idempotent. */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_2,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));
	/* Phase 2 with flag SET: stays in Phase 2 (idempotent). */
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_PHASE_2,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));

	/* Restart; Phase 1 + a new-key KR=0 beacon skips Phase 2. */
	mesh_kr_init(&st);
	ATF_REQUIRE_EQ(0, mesh_kr_begin(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));

	/* Phase 0 ignores beacons (no active refresh). */
	mesh_kr_init(&st);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_NORMAL,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_STATE_NORMAL,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));
}

/* ================================================================
 * Per-phase key-selection table (Sections 3.11.4.1-3.11.4.3):
 *   Phase | TX  | RX old | RX new | own beacon flag
 *   ------+-----+--------+--------+----------------
 *     0   | old |  yes   |  no    |  0
 *     1   | old |  yes   |  yes   |  0
 *     2   | new |  yes   |  yes   |  1
 *     3   | new |  no    |  yes   |  0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_kr_key_selection);
ATF_TC_BODY(mesh_kr_key_selection, tc)
{
	struct mesh_key_refresh st;

	/* Phase 0. */
	mesh_kr_init(&st);
	ATF_CHECK_EQ(MESH_KR_KEY_OLD, mesh_kr_tx_key(&st));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_old(&st));
	ATF_CHECK_EQ(0, mesh_kr_rx_accept_new(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));

	/* Phase 1. */
	ATF_REQUIRE_EQ(0, mesh_kr_begin(&st));
	ATF_CHECK_EQ(MESH_KR_KEY_OLD, mesh_kr_tx_key(&st));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_old(&st));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_new(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));

	/* Phase 2. */
	ATF_REQUIRE_EQ(BT_MSHPRT11_KR_STATE_PHASE_2,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));
	ATF_CHECK_EQ(MESH_KR_KEY_NEW, mesh_kr_tx_key(&st));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_old(&st));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_new(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_SET, mesh_kr_beacon_flag(&st));

	/* Phase 3 (revoking). */
	ATF_REQUIRE_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));
	ATF_CHECK_EQ(MESH_KR_KEY_NEW, mesh_kr_tx_key(&st));
	ATF_CHECK_EQ_MSG(0, mesh_kr_rx_accept_old(&st),
	    "Phase 3 must revoke (reject) the old key");
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_new(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));
}

/* ================================================================
 * NULL-argument guards: every accessor must fail safe, returning the
 * documented default for a NULL state.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_kr_null_guards);
ATF_TC_BODY(mesh_kr_null_guards, tc)
{

	mesh_kr_init(NULL);				/* must not crash */
	ATF_CHECK_EQ(-1, mesh_kr_phase(NULL));
	ATF_CHECK_EQ(-1, mesh_kr_begin(NULL));
	ATF_CHECK_EQ(-1, mesh_kr_beacon(NULL, 1));
	ATF_CHECK_EQ(0, mesh_kr_beacon_flag(NULL));
	ATF_CHECK_EQ(MESH_KR_KEY_OLD, mesh_kr_tx_key(NULL));
	ATF_CHECK_EQ(1, mesh_kr_rx_accept_old(NULL));
	ATF_CHECK_EQ(0, mesh_kr_rx_accept_new(NULL));
}

/* ================================================================
 * A beacon received in an out-of-range (corrupt) phase leaves the phase
 * untouched: the switch default arm must be a no-op, not a transition.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_kr_beacon_invalid_phase);
ATF_TC_BODY(mesh_kr_beacon_invalid_phase, tc)
{
	struct mesh_key_refresh st;

	mesh_kr_init(&st);
	st.phase = 7;	/* non-normative corrupt-state sentinel, not a phase value */
	ATF_CHECK_EQ_MSG(7, mesh_kr_beacon(&st, 1),
	    "an unknown phase must be left unchanged by a beacon");
	ATF_CHECK_EQ_MSG(7, mesh_kr_beacon(&st, 0),
	    "an unknown phase must be left unchanged by a beacon");
}

/*
 * Finding 5 regression: the beacon Key Refresh flag a node advertises is SET
 * only in Phase 2 and CLEAR in every other phase (0, 1, and 3), matching
 * MshPRT Sections 3.11.4.2-3.11.4.3.  Locks the corrected header contract,
 * which previously claimed the flag was set in Phase 3 as well.
 */
ATF_TC_WITHOUT_HEAD(mesh_kr_beacon_flag_by_phase);
ATF_TC_BODY(mesh_kr_beacon_flag_by_phase, tc)
{
	struct mesh_key_refresh st;

	/* Phase 0 (Normal): CLEAR. */
	mesh_kr_init(&st);
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));

	/* Phase 1 (distributing): CLEAR. */
	ATF_REQUIRE_EQ(0, mesh_kr_begin(&st));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));

	/* Phase 2 (using new keys): SET. */
	ATF_REQUIRE_EQ(BT_MSHPRT11_KR_STATE_PHASE_2,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_SET));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_SET, mesh_kr_beacon_flag(&st));

	/* Phase 3 (revoking): CLEAR, not SET. */
	ATF_REQUIRE_EQ(BT_MSHPRT11_KR_TRANSITION_PHASE_3,
	    mesh_kr_beacon(&st, BT_MSHPRT11_KR_FLAG_CLEAR));
	ATF_CHECK_EQ(BT_MSHPRT11_KR_FLAG_CLEAR, mesh_kr_beacon_flag(&st));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_kr_beacon_flag_by_phase);
	ATF_TP_ADD_TC(tp, mesh_kr_phase_walk);
	ATF_TP_ADD_TC(tp, mesh_kr_flag_stability);
	ATF_TP_ADD_TC(tp, mesh_kr_key_selection);
	ATF_TP_ADD_TC(tp, mesh_kr_null_guards);
	ATF_TP_ADD_TC(tp, mesh_kr_beacon_invalid_phase);

	return (atf_no_error());
}
