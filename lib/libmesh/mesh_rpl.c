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
	rpl->full_drops = 0;
	if (rpl->entries != NULL && rpl->size != 0)
		memset(rpl->entries, 0, n * sizeof(*rpl->entries));
}

void
mesh_rpl_reset(struct mesh_rpl *rpl)
{

	if (rpl == NULL || rpl->entries == NULL)
		return;
	memset(rpl->entries, 0, rpl->size * sizeof(*rpl->entries));
	rpl->full_drops = 0;
}

uint32_t
mesh_rpl_full_drops(const struct mesh_rpl *rpl)
{

	return (rpl != NULL ? rpl->full_drops : 0);
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

/*
 * Shared list scan.  Returns the 1 / 0 / -1 verdict and, for verdict 1, the
 * index of the slot that would carry the entry (an existing slot for a known
 * SRC, otherwise the first free one).  Never mutates the list.
 */
static int
mesh_rpl_scan(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
    uint32_t seq, size_t *slot)
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
		if (rpl->entries[i].src != src)
			continue;
		if (!mesh_rpl_is_newer(iv_index, seq, rpl->entries[i].iv_index,
		    rpl->entries[i].seq))
			return (0);			/* replay */
		*slot = i;
		return (1);
	}

	if (free_slot == rpl->size) {
		/*
		 * Reclaim an entry that can no longer adjudicate anything: a
		 * receiver authenticates a Network PDU only under the current
		 * IV Index or IV Index - 1 (MshPRT_v1.1.1 Sections 3.10.5 and
		 * 3.11.5), so an entry more than one epoch behind the IV Index
		 * that just authenticated this PDU cannot be reached by any
		 * PDU that would still authenticate.  Every message that
		 * source can still send carries an IVISeq strictly greater
		 * than the reclaimed value, which an empty slot accepts too -
		 * so this reclaim opens no replay window.  Nothing else is
		 * evicted: discarding a live entry to make room would.
		 */
		for (i = 0; i < rpl->size; i++)
			if (rpl->entries[i].valid &&
			    rpl->entries[i].iv_index + 1 < iv_index) {
				free_slot = i;
				break;
			}
	}
	if (free_slot == rpl->size) {
		/*
		 * "If a node does not have enough resources to perform replay
		 * protection for a given source address, then the node shall
		 * discard the message immediately upon reception."  Fail
		 * closed, and count it so the condition is reportable rather
		 * than a silent black hole.
		 */
		rpl->full_drops++;
		return (-1);				/* full, SRC unknown */
	}
	*slot = free_slot;
	return (1);
}

int
mesh_rpl_peek(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
    uint32_t seq)
{
	size_t slot = 0;
	int rc;

	rc = mesh_rpl_scan(rpl, src, iv_index, seq, &slot);
	MESH_PROBE_RPL_CHECK(src, seq, rc);
	return (rc);
}

int
mesh_rpl_commit(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
    uint32_t seq)
{
	size_t slot = 0;
	int rc;

	rc = mesh_rpl_scan(rpl, src, iv_index, seq, &slot);
	if (rc != 1)
		return (rc);
	rpl->entries[slot].src = src;
	rpl->entries[slot].iv_index = iv_index;
	rpl->entries[slot].seq = seq;
	rpl->entries[slot].valid = 1;
	return (1);
}

int
mesh_rpl_check(struct mesh_rpl *rpl, uint16_t src, uint32_t iv_index,
    uint32_t seq)
{
	int rc;

	rc = mesh_rpl_peek(rpl, src, iv_index, seq);
	if (rc == 1)
		(void)mesh_rpl_commit(rpl, src, iv_index, seq);
	return (rc);
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
 * authoritative and must NOT be retried under the other IV Index.  Returns the
 * same 1/0/-1 values as mesh_rpl_net_receive().
 */
int
mesh_rpl_net_receive_ivupd(struct mesh_rpl *rpl, const uint8_t enckey[16],
    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index,
    const uint8_t *in, size_t inlen, struct mesh_net_pdu *out)
{
	int rc;

	rc = mesh_rpl_net_receive(rpl, enckey, privkey, nid, iv_index, in,
	    inlen, out);
	if (rc >= 0 || iv_index == 0)
		return (rc);
	/* Authentication failed under the current IV Index; try IV-1. */
	return (mesh_rpl_net_receive(rpl, enckey, privkey, nid, iv_index - 1,
	    in, inlen, out));
}
