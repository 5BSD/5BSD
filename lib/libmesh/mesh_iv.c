/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh IV Update procedure state machine (MshPRT_v1.1
 * Section 3.11.5).  See mesh_iv.h for the state model and timing policy.
 *
 * Pure and hardware-free: time is supplied by the caller as a monotonic
 * `now` value (seconds); the module reads no real clock and keeps no
 * global state.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_iv.h"
#include "mesh_probes.h"

void
mesh_iv_init(struct mesh_iv_state *st, uint32_t iv_index, uint64_t now)
{

	if (st == NULL)
		return;
	st->iv_index = iv_index;
	st->state = MESH_IV_NORMAL;
	st->entered_time = now;
	st->recovery_active = 0;
}

uint32_t
mesh_iv_tx_index(const struct mesh_iv_state *st)
{

	if (st == NULL)
		return (0);
	if (st->state == MESH_IV_UPDATE_IN_PROGRESS && st->iv_index != 0)
		return (st->iv_index - 1);	/* transmit on the old index */
	return (st->iv_index);
}

int
mesh_iv_rx_accept(const struct mesh_iv_state *st, uint32_t pdu_iv)
{

	if (st == NULL)
		return (0);
	if (pdu_iv == st->iv_index)
		return (1);
	/* Both states accept the previous index during the network transition. */
	if (st->iv_index != 0 && pdu_iv == st->iv_index - 1)
		return (1);
	return (0);
}

int
mesh_iv_seq_exhausted(uint32_t seq)
{

	return (seq >= MESH_IV_SEQ_TRIGGER);
}

/*
 * Has the node dwelled in its current state for the 96-hour minimum?  A
 * clock that appears to move backwards (now < entered_time) is treated
 * conservatively as "not yet elapsed".
 */
static int
mesh_iv_dwell_elapsed(const struct mesh_iv_state *st, uint64_t now)
{

	if (now < st->entered_time)
		return (0);
	return (now - st->entered_time >= MESH_IV_MIN_DWELL_SECS);
}

int
mesh_iv_begin_update(struct mesh_iv_state *st, uint64_t now)
{

	if (st == NULL || st->state != MESH_IV_NORMAL)
		return (MESH_IV_REJECT);
	if (!mesh_iv_dwell_elapsed(st, now))
		return (MESH_IV_REJECT);
	if (st->iv_index == UINT32_MAX)
		return (MESH_IV_REJECT);	/* cannot advance past the max */
	MESH_PROBE_IV_UPDATE_BEGIN(st->iv_index, st->iv_index + 1);
	st->iv_index += 1;
	st->state = MESH_IV_UPDATE_IN_PROGRESS;
	st->entered_time = now;
	return (MESH_IV_STARTED);
}

int
mesh_iv_complete_update(struct mesh_iv_state *st, uint64_t now)
{

	if (st == NULL || st->state != MESH_IV_UPDATE_IN_PROGRESS)
		return (MESH_IV_REJECT);
	if (!mesh_iv_dwell_elapsed(st, now))
		return (MESH_IV_REJECT);
	st->state = MESH_IV_NORMAL;
	st->entered_time = now;
	MESH_PROBE_IV_UPDATE_DONE(st->iv_index);
	return (MESH_IV_COMPLETED);
}

int
mesh_iv_recovery_begin(struct mesh_iv_state *st)
{

	if (st == NULL)
		return (-1);
	st->recovery_active = 1;
	return (0);
}

int
mesh_iv_recv_beacon(struct mesh_iv_state *st, uint32_t recv_iv,
    int recv_iv_update, uint64_t now)
{
	uint32_t cur;
	int flag;

	if (st == NULL)
		return (MESH_IV_REJECT);
	cur = st->iv_index;
	flag = recv_iv_update ? 1 : 0;

	/* Never accept a lower IV Index. */
	if (recv_iv < cur) {
		MESH_PROBE_IV_BEACON(recv_iv, 0);
		return (MESH_IV_REJECT);
	}

	/* Outside the recovery window. */
	if (recv_iv - cur > MESH_IV_MAX_LOOKAHEAD) {
		MESH_PROBE_IV_BEACON(recv_iv, 0);
		return (MESH_IV_REJECT);
	}

	/* Beacon IV Index is within the acceptance window. */
	MESH_PROBE_IV_BEACON(recv_iv, 1);

	if (recv_iv == cur) {
		if (!flag && st->state == MESH_IV_UPDATE_IN_PROGRESS) {
			if (!mesh_iv_dwell_elapsed(st, now))
				return (MESH_IV_NO_CHANGE);
			st->state = MESH_IV_NORMAL;
			st->entered_time = now;
			return (MESH_IV_COMPLETED);
		}
		/*
		 * A same-index beacon with the IV Update flag set carries no
		 * legal transition: MshPRT Section 3.11.5 requires Normal ->
		 * In Progress to increment the IV Index, and Tables 3.84/3.85
		 * define no same-index start.  Ignore the flag rather than
		 * regressing the TX index (which would reuse (IV, SEQ) nonces).
		 */
		return (MESH_IV_NO_CHANGE);
	}

	if (recv_iv == cur + 1) {
		/*
		 * Table 3.85: an armed IV Index Recovery observing a newer
		 * index adopts the IV Index and flag without the 96-hour dwell
		 * gate (Section 3.11.6 exempts recovery), resetting SEQ if the
		 * update is In Progress.  This must be checked before the
		 * ordinary same-step rules below, which would otherwise strand
		 * an armed node until a flag=0 beacon arrives.
		 */
		if (st->recovery_active) {
			st->iv_index = recv_iv;
			st->state = flag ? MESH_IV_UPDATE_IN_PROGRESS :
			    MESH_IV_NORMAL;
			st->entered_time = now;
			st->recovery_active = 0;
			return (MESH_IV_JUMPED);
		}
		if (flag) {
			/* Network started an update to n+1; adopt and update. */
			if (st->state == MESH_IV_UPDATE_IN_PROGRESS)
				return (MESH_IV_NO_CHANGE);
			if (!mesh_iv_dwell_elapsed(st, now))
				return (MESH_IV_NO_CHANGE);
			st->iv_index = recv_iv;
			st->state = MESH_IV_UPDATE_IN_PROGRESS;
			st->entered_time = now;
			return (MESH_IV_STARTED);
		}
		/* Table 3.85 permits this jump only during IV Index Recovery. */
		return (MESH_IV_REJECT);
	}

	/*
	 * recv_iv is more than one index ahead but within the recovery
	 * window.  Table 3.85 allows adoption only while the explicit IV Index
	 * Recovery procedure is armed; an accepted beacon completes it.
	 */
	if (!st->recovery_active)
		return (MESH_IV_REJECT);
	st->iv_index = recv_iv;
	st->state = flag ? MESH_IV_UPDATE_IN_PROGRESS : MESH_IV_NORMAL;
	st->entered_time = now;
	st->recovery_active = 0;
	return (MESH_IV_JUMPED);
}
