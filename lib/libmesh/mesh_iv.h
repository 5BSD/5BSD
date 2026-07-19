/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh IV Update procedure (Mesh Protocol 1.1.1 Section 3.11.5).
 *
 * The IV Index is a 32-bit value shared by every node in a subnet; it feeds
 * the network/application/device nonces and, together with the 24-bit SEQ,
 * guarantees nonce uniqueness.  Because SEQ is only 24 bits, a busy node
 * eventually exhausts it and the whole network must move to a fresh IV Index
 * via the IV Update procedure.
 *
 * The procedure has two states (Section 3.11.5):
 *
 *   MESH_IV_NORMAL              Normal Operation.  Beacons carry the current
 *                              IV Index n with the IV Update flag clear; both
 *                              TX and RX use n.
 *   MESH_IV_UPDATE_IN_PROGRESS Update In Progress.  Beacons carry IV Index
 *                              n+1 with the IV Update flag set; the node
 *                              TRANSMITS with the old index n but ACCEPTS
 *                              received PDUs on either n or n+1.  When the
 *                              update completes the node returns to Normal
 *                              Operation using n+1.
 *
 * TIMING POLICY (Section 3.11.5).  This module is hardware-free: it never
 * reads a real clock.  Every entry point that cares about time takes a
 * caller-supplied monotonic timestamp `now` (documented as seconds, e.g. a
 * time_t or the hci_emulator virtual clock), and the state struct records
 * when the current state was entered.  Two policies are enforced:
 *
 *   - A node stays in each state for at least 96 hours before it may make
 *     the paired transition (MESH_IV_MIN_DWELL_SECS).  This bounds how fast
 *     the IV Index can advance and defeats a replay/SEQ-rollback attacker.
 *   - Network PDUs from the current and previous IV Index are accepted in
 *     both Normal Operation and IV Update in Progress.  Beacon-driven
 *     recovery accepts a newer IV Index only within the 42-index window.
 *
 * A node should start an IV Update when its SEQ approaches exhaustion;
 * MESH_IV_SEQ_TRIGGER is the recommended threshold and mesh_iv_seq_exhausted()
 * is the predicate.
 *
 * The module is pure: no I/O, no globals.  Predicates return their result
 * directly; the transition helpers return an action code (below).
 */

#ifndef _MESH_IV_H_
#define _MESH_IV_H_

#include <stdint.h>

/* IV Update states.  Mesh Protocol 1.1.1 Section 3.11.5. */
#define	MESH_IV_NORMAL			0
#define	MESH_IV_UPDATE_IN_PROGRESS	1

/*
 * Minimum time (seconds) a node must remain in a state before the paired
 * transition is permitted: 96 hours.  Mesh Protocol 1.1.1 Section 3.11.5.
 */
#define	MESH_IV_DWELL_HOURS		96
#define	MESH_IV_MIN_DWELL_SECS		((uint64_t)MESH_IV_DWELL_HOURS * 3600)

/*
 * Maximum amount a received IV Index may exceed the known IV Index and
 * still be accepted (IV Index recovery bound).  Section 3.11.6.
 */
#define	MESH_IV_MAX_LOOKAHEAD		42

/*
 * Recommended SEQ value at which a node starts an IV Update to avoid
 * exhausting the 24-bit sequence space (0xFFFFFF).  Half the space leaves
 * ample headroom for the 96-hour update to complete.
 */
#define	MESH_IV_SEQ_MAX			0x00FFFFFFu
#define	MESH_IV_SEQ_TRIGGER		0x00800000u

/*
 * IV Update state.  `iv_index` is the value a beacon would carry: in Normal
 * Operation it is the operating index n; in Update In Progress it is n+1
 * (the target), and the node transmits with iv_index-1.  `entered_time` is
 * the `now` value at which the current state was entered.
 */
struct mesh_iv_state {
	uint32_t	iv_index;
	int		state;
	uint64_t	entered_time;
	int		recovery_active;
};

/* Action results from the transition helpers. */
#define	MESH_IV_REJECT			-1	/* input rejected, no change */
#define	MESH_IV_NO_CHANGE		0	/* accepted, state unchanged */
#define	MESH_IV_STARTED			1	/* Normal -> Update In Progress */
#define	MESH_IV_COMPLETED		2	/* Update In Progress -> Normal */
#define	MESH_IV_JUMPED			3	/* recovered to a higher index */

/* Initialise a state to Normal Operation at IV Index iv_index. */
void	mesh_iv_init(struct mesh_iv_state *st, uint32_t iv_index, uint64_t now);

/*
 * IV Index used for TRANSMITTED PDUs, and predicate for whether a RECEIVED
 * PDU carrying `pdu_iv` is on an acceptable index.  Section 3.11.5: while
 * updating, TX uses the old index and RX accepts old or new.
 */
uint32_t mesh_iv_tx_index(const struct mesh_iv_state *st);
int	 mesh_iv_rx_accept(const struct mesh_iv_state *st, uint32_t pdu_iv);

/* SEQ-exhaustion predicate: 1 when seq has reached the update trigger. */
int	mesh_iv_seq_exhausted(uint32_t seq);

/*
 * Locally initiate / complete an IV Update (e.g. driven by SEQ exhaustion).
 * Both are gated by the 96-hour minimum dwell: they return MESH_IV_STARTED /
 * MESH_IV_COMPLETED on success (updating the state and entered_time) or
 * MESH_IV_REJECT if the wrong state or the dwell has not elapsed.
 */
int	mesh_iv_begin_update(struct mesh_iv_state *st, uint64_t now);
int	mesh_iv_complete_update(struct mesh_iv_state *st, uint64_t now);

/*
 * Arm one IV Index Recovery observation.  Mesh Protocol 1.1.1 Section
 * 3.11.6 requires the surrounding node to enforce the 192-hour eligibility
 * rule before calling this function.  One accepted newer index consumes the
 * arm; ordinary beacon processing cannot perform a recovery jump.
 */
int	mesh_iv_recovery_begin(struct mesh_iv_state *st);

/*
 * Process a received Secure Network beacon's (IV Index, IV Update flag).
 * Applies the Sections 3.11.5-3.11.6 accept rules and drives the state machine:
 *
 *   recv_iv <  current            -> MESH_IV_REJECT (never go backwards)
 *   recv_iv >  current + 42       -> MESH_IV_REJECT (outside recovery bound)
 *   recv_iv == current, flag set, state Normal   -> MESH_IV_STARTED*
 *   recv_iv == current, flag clear, state Update -> MESH_IV_COMPLETED*
 *   recv_iv == current+1, flag set               -> MESH_IV_STARTED* (adopt)
 *   recv_iv == current+1, flag clear, recovery   -> MESH_IV_JUMPED  (adopt)
 *   current+1 < recv_iv <= current+42, recovery  -> MESH_IV_JUMPED
 *   otherwise                                    -> MESH_IV_NO_CHANGE
 *
 * (*) The two paired transitions at the same/adjacent index are gated by the
 * 96-hour dwell; if the dwell has not elapsed the call returns
 * MESH_IV_NO_CHANGE and the state is left unchanged.  Recovery jumps of more
 * than one index are not dwell-gated, but require mesh_iv_recovery_begin().
 */
int	mesh_iv_recv_beacon(struct mesh_iv_state *st, uint32_t recv_iv,
	    int recv_iv_update, uint64_t now);

#endif /* _MESH_IV_H_ */
