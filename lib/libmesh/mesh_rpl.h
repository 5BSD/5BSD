/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Replay Protection List (MshPRT_v1.1 Section 3.9.8).
 *
 * The RPL defends against replay of network PDUs.  It is keyed by the
 * source unicast address (SRC) and, for each SRC, stores the (IV Index, SEQ)
 * of the most recently ACCEPTED PDU.  A received PDU is a replay - and must
 * be discarded - unless its (IV Index, SEQ) is strictly newer than the
 * stored value:
 *
 *   - a higher IV Index is always newer (and resets acceptance: SEQ starts
 *     over in the new IV Index epoch);
 *   - within the same IV Index, only a strictly greater SEQ is newer;
 *   - a lower IV Index, or an equal-or-lower SEQ in the same IV Index, is a
 *     replay and is rejected.
 *
 * This promotes the minimal mesh_net_rpl_check() primitive (which tracked
 * SEQ only) to the full, IV-Index-aware list required by Section 3.9.8.
 *
 * The list is bounded: the caller provides fixed backing storage.  When the
 * list is full and a PDU arrives from an unknown SRC there is no slot to
 * record it, so the PDU is rejected (a node must not accept traffic it
 * cannot replay-protect).
 *
 * Pure and hardware-free: no I/O, no globals, no dynamic allocation.
 */

#ifndef _MESH_RPL_H_
#define _MESH_RPL_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_net.h"

/* One RPL entry: the last accepted (IV Index, SEQ) from a SRC. */
struct mesh_rpl_entry {
	uint16_t	src;
	uint32_t	iv_index;
	uint32_t	seq;
	int		valid;
};

/* Bounded RPL over caller-provided entry storage. */
struct mesh_rpl {
	struct mesh_rpl_entry	*entries;
	size_t			 size;
};

/* Bind an RPL to backing storage (all slots start empty). */
void	mesh_rpl_init(struct mesh_rpl *rpl, struct mesh_rpl_entry *storage,
	    size_t n);

/* Clear every entry (empties the list; storage is retained). */
void	mesh_rpl_reset(struct mesh_rpl *rpl);

/*
 * Replay-check a received PDU identified by (src, iv_index, seq).
 * Section 3.9.8.  SRC must be a unicast element address and SEQ must fit its
 * 24-bit Network PDU field; invalid field values fail closed with -1. Returns:
 *
 *    1  accepted - the (iv_index, seq) is newer than the stored entry (or
 *       the SRC was unseen); the entry is created/updated in place.
 *    0  rejected - a replay: lower IV Index, or equal-or-lower SEQ within
 *       the same IV Index.  The list is not modified.
 *   -1  rejected - the list is full and the SRC is unknown, so the PDU
 *       cannot be recorded.  The list is not modified.
 *
 * A caller that only wants the decision without recording (a "peek") can
 * copy the entry first; the normal receive path records on acceptance.
 */
int	mesh_rpl_check(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
	    uint32_t seq);

/*
 * Integrated secured-receive seam: decrypt a Network PDU (mesh_net_decrypt)
 * and, only if it authenticates, enforce the RPL on its (SRC, IV Index,
 * SEQ).  This wires the RPL into the network receive path without disturbing
 * mesh_net.c.  Returns:
 *
 *    1  accepted - authenticated AND not a replay; *out holds the PDU.
 *    0  replay   - authenticated but rejected by the RPL.
 *   -1  error    - NID mismatch, malformed PDU, or NetMIC failure (never
 *       reached the RPL); *out is zeroed.
 *
 * Note: a PDU is entered into the RPL only after its NetMIC verifies, so a
 * forged/corrupt PDU can never poison the list.
 */
int	mesh_rpl_net_receive(struct mesh_rpl *rpl, const uint8_t enckey[16],
	    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index,
	    const uint8_t *in, size_t inlen, struct mesh_net_pdu *out);

#endif /* _MESH_RPL_H_ */
