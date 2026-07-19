/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh IV Update procedure state machine
 * (mesh_iv.[ch], Mesh Protocol 1.1.1 Sections 3.11.5-3.11.6).
 *
 * These are behavioural / spec-rule tests rather than crypto KATs: the IV
 * Update procedure defines state transitions and accept rules, not fixed
 * byte vectors.  The 96-hour minimum-dwell policy is exercised against an
 * INJECTED clock (a plain uint64_t of seconds), so no real time is read.
 *
 * Reference: Mesh Protocol 1.1.1 Sections 3.11.5-3.11.6 and Tables
 * 3.83-3.85; MESH.TS p15 Section 4.11.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>

#include "mesh_iv.h"
#include "spec_mesh_iv_oracles.h"

#define	DWELL	BT_MESH_SPEC_IV_DWELL_SECONDS

/* ================================================================
 * Mesh Protocol 1.1.1 §§3.11.5-3.11.6; MESH.TS p15 §§4.11.3 and
 * 4.11.7, Tables 4.16 and 4.20: received-IV-Index boundary matrix.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_accept_matrix);
ATF_TC_BODY(mesh_iv_accept_matrix, tc)
{
	struct mesh_iv_state st;

	/* Lower IV Index is always rejected. */
	mesh_iv_init(&st, 100, 0);
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT,
	    mesh_iv_recv_beacon(&st, 99, 0, DWELL),
	    "a lower IV Index must be rejected");
	ATF_CHECK_EQ(st.iv_index, 100u);	/* unchanged */

	/* MESH.TS p15 §4.11.7: current + 43 is outside the recovery window. */
	mesh_iv_init(&st, 100, 0);
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT,
	    mesh_iv_recv_beacon(&st,
	    100 + BT_MESH_SPEC_IV_RECOVERY_MAX_INCREMENT + 1, 0, DWELL),
	    "an IV Index > current+42 must be rejected");
	ATF_CHECK_EQ(st.iv_index, 100u);

	/* MESH.TS p15 §4.11.3/Table 4.16: +42 is the recovery boundary. */
	mesh_iv_init(&st, 100, 0);
	ATF_REQUIRE_EQ(0, mesh_iv_recovery_begin(&st));
	ATF_CHECK_EQ_MSG(MESH_IV_JUMPED,
	    mesh_iv_recv_beacon(&st,
	    100 + BT_MESH_SPEC_IV_RECOVERY_MAX_INCREMENT, 0, DWELL),
	    "an IV Index == current+42 must be accepted");
	ATF_CHECK_EQ(st.iv_index,
	    100u + BT_MESH_SPEC_IV_RECOVERY_MAX_INCREMENT);

	/* Same IV Index, no flag, Normal state: no change (accepted). */
	mesh_iv_init(&st, 100, 0);
	ATF_CHECK_EQ(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 100, 0, DWELL));
	ATF_CHECK_EQ(st.iv_index, 100u);
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5 Table 3.84; MESH.TS p15 §4.11.1
 * Table 4.14: Normal <-> Update transitions driven by beacons.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_transitions);
ATF_TC_BODY(mesh_iv_transitions, tc)
{
	struct mesh_iv_state st;

	/* Normal at n=100; a beacon carrying n+1 with the IV Update flag set
	 * starts the update (adopt 101, Update In Progress). */
	mesh_iv_init(&st, 100, 0);
	ATF_CHECK_EQ_MSG(MESH_IV_STARTED,
	    mesh_iv_recv_beacon(&st, 101, 1, DWELL),
	    "beacon n+1 with IV Update flag must start the update");
	ATF_CHECK_EQ(st.iv_index, 101u);
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);

	/* While updating, TX uses the OLD index (100), RX accepts 100 & 101. */
	ATF_CHECK_EQ(mesh_iv_tx_index(&st), 100u);
	ATF_CHECK(mesh_iv_rx_accept(&st, 100));
	ATF_CHECK(mesh_iv_rx_accept(&st, 101));
	ATF_CHECK(!mesh_iv_rx_accept(&st, 102));

	/* A later beacon at the same index with the flag CLEAR completes the
	 * update (back to Normal on 101) once the dwell has elapsed. */
	ATF_CHECK_EQ_MSG(MESH_IV_COMPLETED,
	    mesh_iv_recv_beacon(&st, 101, 0, DWELL + DWELL),
	    "beacon with flag clear must complete the update after dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
	ATF_CHECK_EQ(st.iv_index, 101u);
	/* Back in Normal, TX uses 101 and RX keeps the required n/n-1 overlap. */
	ATF_CHECK_EQ(mesh_iv_tx_index(&st), 101u);
	ATF_CHECK(mesh_iv_rx_accept(&st, 101));
	ATF_CHECK(mesh_iv_rx_accept(&st, 100));
	ATF_CHECK(!mesh_iv_rx_accept(&st, 99));
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.6 Table 3.85: explicitly armed missed-start
 * recovery accepts n+1 with the flag clear and consumes the recovery arm.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_jump_recovery);
ATF_TC_BODY(mesh_iv_jump_recovery, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 7, 0);
	ATF_REQUIRE_EQ(0, mesh_iv_recovery_begin(&st));
	ATF_CHECK_EQ_MSG(MESH_IV_JUMPED,
	    mesh_iv_recv_beacon(&st, 8, 0, 0),
	    "beacon n+1 flag-clear must jump to Normal on the new index");
	ATF_CHECK_EQ(st.iv_index, 8u);
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.9.3 defines the 24-bit SEQ maximum; 0x00800000 is
 * the explicitly local mesh_iv.h early-update policy.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_seq_exhaustion);
ATF_TC_BODY(mesh_iv_seq_exhaustion, tc)
{

	ATF_CHECK(!mesh_iv_seq_exhausted(0));
	ATF_CHECK(!mesh_iv_seq_exhausted(BT_MESH_IMPL_SEQ_TRIGGER - 1));
	ATF_CHECK(mesh_iv_seq_exhausted(BT_MESH_IMPL_SEQ_TRIGGER));
	ATF_CHECK(mesh_iv_seq_exhausted(BT_MESH_SPEC_SEQ_MAX));
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5: 96-hour minimum-dwell enforcement:
 * a locally initiated begin/complete is refused before the dwell elapses
 * and permitted after.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_dwell);
ATF_TC_BODY(mesh_iv_dwell, tc)
{
	struct mesh_iv_state st;

	/* Enter Normal at t=1000. */
	mesh_iv_init(&st, 5, 1000);

	/* One second short of the dwell: begin is refused. */
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT,
	    mesh_iv_begin_update(&st, 1000 + DWELL - 1),
	    "IV Update must not start before the 96h dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
	ATF_CHECK_EQ(st.iv_index, 5u);

	/* Exactly at the dwell boundary: begin is permitted (5 -> 6). */
	ATF_CHECK_EQ_MSG(MESH_IV_STARTED,
	    mesh_iv_begin_update(&st, 1000 + DWELL),
	    "IV Update must start once the 96h dwell has elapsed");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
	ATF_CHECK_EQ(st.iv_index, 6u);

	/* Completion is likewise dwell-gated from the state-entry time. */
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT,
	    mesh_iv_complete_update(&st, 1000 + DWELL + DWELL - 1),
	    "IV Update must not complete before a further 96h dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);

	ATF_CHECK_EQ_MSG(MESH_IV_COMPLETED,
	    mesh_iv_complete_update(&st, 1000 + DWELL + DWELL),
	    "IV Update must complete after the second 96h dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
	ATF_CHECK_EQ(st.iv_index, 6u);
}

/* ================================================================
 * MESH.TS p15 §4.11.6 Table 4.19: the dwell gates a received beacon
 * that would start the update is deferred (NO_CHANGE) until the dwell.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_dwell);
ATF_TC_BODY(mesh_iv_beacon_dwell, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 20, 500);

	/* n+1 with flag before dwell: deferred, no state change. */
	ATF_CHECK_EQ_MSG(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 21, 1, 500 + DWELL - 1),
	    "beacon-driven start must be deferred before the dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
	ATF_CHECK_EQ(st.iv_index, 20u);

	/* Same beacon after the dwell: the update starts. */
	ATF_CHECK_EQ_MSG(MESH_IV_STARTED,
	    mesh_iv_recv_beacon(&st, 21, 1, 500 + DWELL),
	    "beacon-driven start must proceed after the dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
	ATF_CHECK_EQ(st.iv_index, 21u);
}

/* ================================================================
 * lib/libmesh/mesh_iv.h defensive API contract: every entry point fails
 * safe on NULL.  This is not a Mesh Protocol requirement.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_null_guards);
ATF_TC_BODY(mesh_iv_null_guards, tc)
{

	mesh_iv_init(NULL, 1, 0);			/* must not crash */
	ATF_CHECK_EQ(0u, mesh_iv_tx_index(NULL));
	ATF_CHECK_EQ(0, mesh_iv_rx_accept(NULL, 5));
	ATF_CHECK_EQ(MESH_IV_REJECT, mesh_iv_begin_update(NULL, DWELL));
	ATF_CHECK_EQ(MESH_IV_REJECT, mesh_iv_complete_update(NULL, DWELL));
	ATF_CHECK_EQ(-1, mesh_iv_recovery_begin(NULL));
	ATF_CHECK_EQ(MESH_IV_REJECT, mesh_iv_recv_beacon(NULL, 1, 0, 0));
}

/*
 * Mesh Protocol 1.1.1 §3.11.6/Table 3.85 and MESH.TS p15 §4.11.3:
 * recovery jumps require an explicitly active IV Index Recovery procedure,
 * and one accepted beacon completes that observation.
 */
ATF_TC_WITHOUT_HEAD(mesh_iv_recovery_requires_mode);
ATF_TC_BODY(mesh_iv_recovery_requires_mode, tc)
{
	struct mesh_iv_state st;
	uint32_t recovered;

	recovered = 10 + BT_MESH_SPEC_IV_RECOVERY_MAX_INCREMENT;
	mesh_iv_init(&st, 10, 0);
	ATF_CHECK_EQ(MESH_IV_REJECT,
	    mesh_iv_recv_beacon(&st, recovered, 0, 0));
	ATF_CHECK_EQ(10u, st.iv_index);

	ATF_REQUIRE_EQ(0, mesh_iv_recovery_begin(&st));
	ATF_CHECK_EQ(MESH_IV_JUMPED,
	    mesh_iv_recv_beacon(&st, recovered, 0, 0));
	ATF_CHECK_EQ(recovered, st.iv_index);

	/* The successful recovery consumed the arm. */
	ATF_CHECK_EQ(MESH_IV_REJECT,
	    mesh_iv_recv_beacon(&st, recovered + 1, 0, 0));
	ATF_CHECK_EQ(recovered, st.iv_index);
}

/* ================================================================
 * lib/libmesh/mesh_iv.h defensive state contract for a contrived Update In
 * Progress value at IV Index zero (not a reachable normative state):
 * TX must NOT wrap to UINT32_MAX and RX must not accept a spurious
 * iv_index-1.  This exercises the `iv_index != 0` guards.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_index_zero_in_progress);
ATF_TC_BODY(mesh_iv_index_zero_in_progress, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 0, 0);
	st.state = BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS;	/* contrived: index 0 */

	/* No old index exists, so TX must use the current index (0). */
	ATF_CHECK_EQ(0u, mesh_iv_tx_index(&st));
	/* The current index is still accepted... */
	ATF_CHECK(mesh_iv_rx_accept(&st, 0));
	/* ...but there is no valid iv_index-1, so a nonzero index is rejected. */
	ATF_CHECK(!mesh_iv_rx_accept(&st, 5));
}

/* ================================================================
 * Mesh Protocol 1.1.1 §§3.9.4 and 3.11.5 plus the local monotonic-clock
 * contract: locally initiated begin reject arms besides dwell.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_begin_reject_arms);
ATF_TC_BODY(mesh_iv_begin_reject_arms, tc)
{
	struct mesh_iv_state st;

	/* A clock that appears to move backwards (now < entered) never elapses. */
	mesh_iv_init(&st, 5, 1000);
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT, mesh_iv_begin_update(&st, 500),
	    "a backwards clock must be treated as dwell-not-elapsed");
	ATF_CHECK_EQ(st.iv_index, 5u);

	/* begin is refused when not in Normal (already Update In Progress). */
	mesh_iv_init(&st, 5, 0);
	st.state = BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS;
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT, mesh_iv_begin_update(&st, DWELL),
	    "begin must be refused outside Normal Operation");

	/* iv_index at its maximum cannot advance. */
	mesh_iv_init(&st, UINT32_MAX, 0);
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT, mesh_iv_begin_update(&st, DWELL),
	    "begin must be refused at the maximum IV Index");
	ATF_CHECK_EQ(st.iv_index, UINT32_MAX);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5 Table 3.84: completion is valid only from
 * Update In Progress.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_complete_wrong_state);
ATF_TC_BODY(mesh_iv_complete_wrong_state, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 5, 0);			/* Normal */
	ATF_CHECK_EQ_MSG(MESH_IV_REJECT, mesh_iv_complete_update(&st, DWELL),
	    "complete must be refused outside Update In Progress");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5 and MESH.TS p15 §4.11.9: a same-index beacon
 * node's own index already matches the update target, so it starts a
 * same-index update, dwell-gated.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_same_index_start);
ATF_TC_BODY(mesh_iv_beacon_same_index_start, tc)
{
	struct mesh_iv_state st;

	/* Before the dwell: deferred, no change. */
	mesh_iv_init(&st, 100, 1000);
	ATF_CHECK_EQ_MSG(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 100, 1, 1000),
	    "same-index start must be deferred before the dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_NORMAL);
	ATF_CHECK_EQ(st.iv_index, 100u);

	/* After the dwell: the same-index update starts (index unchanged). */
	mesh_iv_init(&st, 100, 1000);
	ATF_CHECK_EQ_MSG(MESH_IV_STARTED,
	    mesh_iv_recv_beacon(&st, 100, 1, 1000 + DWELL),
	    "same-index start must proceed after the dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
	ATF_CHECK_EQ(st.iv_index, 100u);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5 Table 3.84: same-index flag-set beacon while
 * (an idempotent re-advertisement): no change.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_same_index_flagset_inprogress);
ATF_TC_BODY(mesh_iv_beacon_same_index_flagset_inprogress, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 100, 0);
	st.state = BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS;
	ATF_CHECK_EQ(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 100, 1, DWELL));
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
	ATF_CHECK_EQ(st.iv_index, 100u);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5: same-index flag-clear beacon while Update In
 * before the dwell: completion is deferred (NO_CHANGE).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_complete_before_dwell);
ATF_TC_BODY(mesh_iv_beacon_complete_before_dwell, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 100, 1000);
	st.state = BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS;
	ATF_CHECK_EQ_MSG(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 100, 0, 1000),
	    "beacon-driven completion must be deferred before the dwell");
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.5 Table 3.84: a +1 flag-set beacon while already
 * Progress is ignored (the update to that index is already tracked).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_plus1_flag_inprogress);
ATF_TC_BODY(mesh_iv_beacon_plus1_flag_inprogress, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 100, 0);
	st.state = BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS;
	ATF_CHECK_EQ(MESH_IV_NO_CHANGE,
	    mesh_iv_recv_beacon(&st, 101, 1, DWELL));
	ATF_CHECK_EQ(st.iv_index, 100u);
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
}

/* ================================================================
 * Mesh Protocol 1.1.1 §3.11.6 Table 3.85: explicitly armed multi-index
 * recovery with the flag set adopts Update In Progress.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_iv_beacon_recovery_jump_flag);
ATF_TC_BODY(mesh_iv_beacon_recovery_jump_flag, tc)
{
	struct mesh_iv_state st;

	mesh_iv_init(&st, 100, 0);
	ATF_REQUIRE_EQ(0, mesh_iv_recovery_begin(&st));
	ATF_CHECK_EQ_MSG(MESH_IV_JUMPED,
	    mesh_iv_recv_beacon(&st, 110, 1, 0),
	    "an in-window multi-index jump with the flag must adopt Update state");
	ATF_CHECK_EQ(st.iv_index, 110u);
	ATF_CHECK_EQ(st.state, BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_iv_accept_matrix);
	ATF_TP_ADD_TC(tp, mesh_iv_transitions);
	ATF_TP_ADD_TC(tp, mesh_iv_jump_recovery);
	ATF_TP_ADD_TC(tp, mesh_iv_seq_exhaustion);
	ATF_TP_ADD_TC(tp, mesh_iv_dwell);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_dwell);
	ATF_TP_ADD_TC(tp, mesh_iv_null_guards);
	ATF_TP_ADD_TC(tp, mesh_iv_recovery_requires_mode);
	ATF_TP_ADD_TC(tp, mesh_iv_index_zero_in_progress);
	ATF_TP_ADD_TC(tp, mesh_iv_begin_reject_arms);
	ATF_TP_ADD_TC(tp, mesh_iv_complete_wrong_state);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_same_index_start);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_same_index_flagset_inprogress);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_complete_before_dwell);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_plus1_flag_inprogress);
	ATF_TP_ADD_TC(tp, mesh_iv_beacon_recovery_jump_flag);

	return (atf_no_error());
}
