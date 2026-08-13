/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Key Refresh procedure (MshPRT_v1.1 Section 3.11.4).
 *
 * Key Refresh replaces a subnet's NetKey (and any bound AppKeys) across all
 * member nodes without dropping traffic, and lets an administrator exclude a
 * compromised node by not giving it the new key.  It runs as a phase state
 * machine per subnet:
 *
 *   Phase 0  Normal Operation.  Only the current key exists.
 *   Phase 1  Key Distribution.  The new key has been distributed but is not
 *            yet used for transmitting.  A node TRANSMITS with the OLD key
 *            and ACCEPTS receptions secured with EITHER key.
 *   Phase 2  Using New Keys.  A node TRANSMITS with the NEW key and still
 *            ACCEPTS receptions on EITHER key.
 *   Phase 3  Revoking Old Keys.  The old key is revoked; the node transmits
 *            with the new key and accepts ONLY the new key.  Phase 3 is
 *            transient and immediately settles back to Phase 0 with the new
 *            key as the (sole) current key.
 *
 * Key selection per phase (used by TX, accepted by RX):
 *
 *   Phase | TX key | RX old | RX new
 *   ------+--------+--------+-------
 *     0   |  old   |  yes   |  no
 *     1   |  old   |  yes   |  yes
 *     2   |  new   |  yes   |  yes
 *     3   |  new   |  no    |  yes
 *
 * A beacon authenticated with the new NetKey drives the phase advance:
 * KR=1 selects Phase 2; KR=0 in Phase 1 skips Phase 2 and selects Phase 3,
 * while KR=0 in Phase 2 also selects Phase 3 (Sections 3.11.4.1-3.11.4.3).
 * The owner then revokes/promotes the actual keys and reinitializes this
 * decision state to Normal Operation.
 *
 * Pure state machine: no I/O, no globals, no crypto here (the actual key
 * material lives in the caller; this module only decides which key applies).
 */

#ifndef _MESH_KEY_REFRESH_H_
#define _MESH_KEY_REFRESH_H_

/* Key Refresh phases.  MshPRT_v1.1 Section 3.11.4. */
#define	MESH_KR_PHASE_NORMAL	0
#define	MESH_KR_PHASE_1		1	/* distributing new keys */
#define	MESH_KR_PHASE_2		2	/* using new keys */
#define	MESH_KR_PHASE_3		3	/* revoking old keys (transient) */

/* Which key applies.  Returned by the TX/RX selectors. */
#define	MESH_KR_KEY_OLD		0
#define	MESH_KR_KEY_NEW		1

/* Per-subnet Key Refresh state. */
struct mesh_key_refresh {
	int	phase;
};

/* Initialise to Phase 0 (Normal Operation). */
void	mesh_kr_init(struct mesh_key_refresh *st);

/* Current phase (MESH_KR_PHASE_*). */
int	mesh_kr_phase(const struct mesh_key_refresh *st);

/*
 * Locally begin a Key Refresh: Phase 0 -> Phase 1 (new key distributed).
 * Returns 0 on success, -1 if not in Phase 0.
 */
int	mesh_kr_begin(struct mesh_key_refresh *st);

/*
 * Advance the phase on receipt of a Secure Network beacon carrying
 * key_refresh_flag (0 or 1), secured with the new key.  Section 3.11.4:
 *
 *   Phase 1 + flag=1 -> Phase 2
 *   Phase 1 + flag=0 -> Phase 3  (Phase 2 is skipped)
 *   Phase 2 + flag=0 -> Phase 3  (revocation begins)
 *   Phase 3 (any)    -> unchanged until the owner completes key promotion
 *   otherwise        -> unchanged
 *
 * Returns the new phase, or -1 on a NULL argument.
 */
int	mesh_kr_beacon(struct mesh_key_refresh *st, int key_refresh_flag);

/*
 * Key Refresh Flag a node should advertise in its own Secure Network beacon
 * for the current phase: SET only in Phase 2, CLEAR otherwise (including
 * Phase 1 and Phase 3).  Sections 3.11.4.2-3.11.4.3.
 */
int	mesh_kr_beacon_flag(const struct mesh_key_refresh *st);

/*
 * Key selection.  mesh_kr_tx_key() returns the key used to secure outgoing
 * PDUs; mesh_kr_rx_accept_old()/_new() report whether a reception secured
 * with the old/new key is accepted in the current phase.
 */
int	mesh_kr_tx_key(const struct mesh_key_refresh *st);
int	mesh_kr_rx_accept_old(const struct mesh_key_refresh *st);
int	mesh_kr_rx_accept_new(const struct mesh_key_refresh *st);

#endif /* _MESH_KEY_REFRESH_H_ */
