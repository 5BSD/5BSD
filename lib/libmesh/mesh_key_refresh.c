/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Key Refresh procedure state machine (MshPRT_v1.1
 * Section 3.11.4).  See mesh_key_refresh.h for the phase model and the
 * per-phase key-selection table.
 *
 * Pure: no I/O, no globals, no crypto.
 */

#include <stddef.h>

#include "mesh_key_refresh.h"

void
mesh_kr_init(struct mesh_key_refresh *st)
{

	if (st == NULL)
		return;
	st->phase = MESH_KR_PHASE_NORMAL;
}

int
mesh_kr_phase(const struct mesh_key_refresh *st)
{

	if (st == NULL)
		return (-1);
	return (st->phase);
}

int
mesh_kr_begin(struct mesh_key_refresh *st)
{

	if (st == NULL || st->phase != MESH_KR_PHASE_NORMAL)
		return (-1);
	st->phase = MESH_KR_PHASE_1;
	return (0);
}

int
mesh_kr_beacon(struct mesh_key_refresh *st, int key_refresh_flag)
{
	int flag;

	if (st == NULL)
		return (-1);
	flag = key_refresh_flag ? 1 : 0;

	switch (st->phase) {
	case MESH_KR_PHASE_1:
		/* A new-key KR=0 beacon skips Phase 2 and revokes old keys. */
		st->phase = flag ? MESH_KR_PHASE_2 : MESH_KR_PHASE_3;
		break;
	case MESH_KR_PHASE_2:
		if (!flag)
			st->phase = MESH_KR_PHASE_3;
		break;
	case MESH_KR_PHASE_3:
		/* The owner promotes the new key, then calls mesh_kr_init(). */
		break;
	case MESH_KR_PHASE_NORMAL:
	default:
		break;
	}
	return (st->phase);
}

int
mesh_kr_beacon_flag(const struct mesh_key_refresh *st)
{

	if (st == NULL)
		return (0);
	return (st->phase == MESH_KR_PHASE_2 ? 1 : 0);
}

int
mesh_kr_tx_key(const struct mesh_key_refresh *st)
{

	if (st == NULL)
		return (MESH_KR_KEY_OLD);
	/* New key used for TX from Phase 2 onward. */
	return ((st->phase == MESH_KR_PHASE_2 ||
	    st->phase == MESH_KR_PHASE_3) ? MESH_KR_KEY_NEW : MESH_KR_KEY_OLD);
}

int
mesh_kr_rx_accept_old(const struct mesh_key_refresh *st)
{

	if (st == NULL)
		return (1);
	/*
	 * The old key is accepted in Phase 0 (where it is the sole current
	 * key) and in Phases 1 and 2; it is revoked only in Phase 3.
	 */
	return (st->phase != MESH_KR_PHASE_3 ? 1 : 0);
}

int
mesh_kr_rx_accept_new(const struct mesh_key_refresh *st)
{

	if (st == NULL)
		return (0);
	/* New key accepted once distributed (Phases 1, 2, 3). */
	return (st->phase != MESH_KR_PHASE_NORMAL ? 1 : 0);
}
