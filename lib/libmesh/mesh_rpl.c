/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Replay Protection List (MshPRT_v1.1 Section 3.9.8).
 * See mesh_rpl.h for the semantics.
 */

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mesh_net.h"
#include "mesh_probes.h"
#include "mesh_rpl.h"

void
mesh_rpl_init(struct mesh_rpl *rpl, struct mesh_rpl_entry *storage, size_t n)
{

	if (rpl == NULL)
		return;
	rpl->entries = storage;
	rpl->size = (storage != NULL) ? n : 0;
	if (rpl->entries != NULL && rpl->size != 0)
		memset(rpl->entries, 0, n * sizeof(*rpl->entries));
}

void
mesh_rpl_reset(struct mesh_rpl *rpl)
{

	if (rpl == NULL || rpl->entries == NULL)
		return;
	memset(rpl->entries, 0, rpl->size * sizeof(*rpl->entries));
}

/*
 * Is (iv_index, seq) strictly newer than the stored (e_iv, e_seq)?
 * A higher IV Index is always newer; within an IV Index only a strictly
 * greater SEQ is newer.  MshPRT_v1.1 Section 3.8.8.
 */
static int
mesh_rpl_is_newer(uint32_t iv_index, uint32_t seq, uint32_t e_iv,
    uint32_t e_seq)
{

	if (iv_index != e_iv)
		return (iv_index > e_iv);
	return (seq > e_seq);
}

int
mesh_rpl_check(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
    uint32_t seq)
{
	size_t i, free_slot;

	if (rpl == NULL || rpl->entries == NULL || rpl->size == 0)
		return (-1);
	/* SRC is a unicast element address and SEQ is a 24-bit wire field. */
	if (src < 0x0001 || src > 0x7fff || seq > 0xffffff)
		return (-1);

	free_slot = rpl->size;
	for (i = 0; i < rpl->size; i++) {
		if (!rpl->entries[i].valid) {
			if (free_slot == rpl->size)
				free_slot = i;
			continue;
		}
		if (rpl->entries[i].src == src) {
			if (!mesh_rpl_is_newer(iv_index, seq,
			    rpl->entries[i].iv_index, rpl->entries[i].seq)) {
				/* Replay-protection hit: SRC seen with a <= seq. */
				MESH_PROBE_RPL_CHECK(src, seq, 0);
				return (0);		/* replay */
			}
			rpl->entries[i].iv_index = iv_index;
			rpl->entries[i].seq = seq;
			MESH_PROBE_RPL_CHECK(src, seq, 1);
			return (1);			/* newer, updated */
		}
	}

	if (free_slot == rpl->size) {
		MESH_PROBE_RPL_CHECK(src, seq, -1);
		return (-1);				/* full, SRC unknown */
	}
	rpl->entries[free_slot].src = src;
	rpl->entries[free_slot].iv_index = iv_index;
	rpl->entries[free_slot].seq = seq;
	rpl->entries[free_slot].valid = 1;
	MESH_PROBE_RPL_CHECK(src, seq, 1);
	return (1);
}

int
mesh_rpl_net_receive(struct mesh_rpl *rpl, const uint8_t enckey[16],
    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index,
    const uint8_t *in, size_t inlen, struct mesh_net_pdu *out)
{

	if (out == NULL)
		return (-1);
	/*
	 * Authenticate first: only a PDU whose NetMIC verifies is allowed to
	 * touch the RPL, so attacker bytes cannot poison the list.
	 */
	if (mesh_net_decrypt(enckey, privkey, nid, iv_index, in, inlen,
	    out) != 0)
		return (-1);

	if (mesh_rpl_check(rpl, out->src, iv_index, out->seq) != 1) {
		MESH_PROBE_RPL_NET_RECV(out->src, 0);
		memset(out, 0, sizeof(*out));
		return (0);				/* replay */
	}
	MESH_PROBE_RPL_NET_RECV(out->src, 1);
	return (1);
}

/*
 * C4-M1: two-candidate secured-receive wrapper for the IV Update procedure.
 *
 * mesh_rpl_net_receive() authenticates under a single IV Index.  Per MshPRT
 * 3.10.5/3.11.5 the IVI bit of a received Network PDU selects between the
 * current IV Index and IV Index - 1 in Normal Operation as well as during an
 * active IV Update: a node must accept traffic secured with the previous IV
 * Index whenever iv_index > 0, independent of the iv_update flag (a peer may
 * remain In-Progress for >=96h and keep securing at iv_index - 1 while this
 * node has already passed iv_update=0).  A consumer calling the single-IV
 * seam directly would silently drop that traffic.  This wrapper tries
 * iv_index first and, only when the PDU fails to authenticate under it,
 * retries under iv_index - 1.
 *
 * The IVI bit ensures at most one of the two IV Indices can authenticate the
 * PDU, so exactly one candidate is ever recorded.  The RPL is enforced with
 * the IV Index that actually authenticated the PDU, preserving the Section
 * 3.9.8 ordering across the epoch boundary.  A replay verdict (rc == 0) is
 * authoritative and must NOT be retried under the other IV Index.  The
 * iv_update argument is retained for source/ABI compatibility but no longer
 * gates the retry.  Returns the same 1/0/-1 values as
 * mesh_rpl_net_receive().
 */
int
mesh_rpl_net_receive_ivupd(struct mesh_rpl *rpl, const uint8_t enckey[16],
    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index, int iv_update,
    const uint8_t *in, size_t inlen, struct mesh_net_pdu *out)
{
	int rc;

	(void)iv_update;
	rc = mesh_rpl_net_receive(rpl, enckey, privkey, nid, iv_index, in,
	    inlen, out);
	if (rc >= 0 || iv_index == 0)
		return (rc);
	/* Authentication failed under the current IV Index; try IV-1. */
	return (mesh_rpl_net_receive(rpl, enckey, privkey, nid, iv_index - 1,
	    in, inlen, out));
}
