/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Relay feature + retransmit configuration (MshPRT_v1.1
 * Section 3.4.6 / 3.6.4, Section 4.2.20 / 4.2.21).  See mesh_relay.h.
 *
 * The core TTL predicate is reused from mesh_net.c (mesh_net_relay); this file
 * only adds the feature gate and the pure config arithmetic, so nothing here
 * touches crypto or I/O.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_net.h"
#include "mesh_relay.h"

/*
 * Relay decision.  MshPRT_v1.1 Section 3.4.6.3.
 */
int
mesh_relay_decide(const struct mesh_relay_config *cfg, uint8_t ttl,
    int in_cache, int dst_is_local, uint8_t *new_ttl)
{

	if (cfg == NULL)
		return (0);
	if (!cfg->enabled)		/* feature disabled */
		return (0);
	if (in_cache)			/* already seen (Network Message Cache) */
		return (0);
	if (dst_is_local)		/* addressed to us, not onward */
		return (0);
	/* TTL >= 2 gate + TTL-1 decrement (Section 3.4.6.3). */
	return (mesh_net_relay(ttl, new_ttl));
}

/*
 * Retransmit policy accessors.  MshPRT_v1.1 Section 4.2.20 / 4.2.21.
 */
uint8_t
mesh_relay_tx_count(uint8_t count_field)
{

	/* Number of transmissions = Count + 1. */
	return ((uint8_t)((count_field & MESH_RELAY_COUNT_MASK) + 1));
}

uint16_t
mesh_relay_interval_ms(uint8_t steps_field)
{

	/* Interval = (Interval Steps + 1) * 10 ms. */
	return ((uint16_t)(((steps_field & MESH_RELAY_STEPS_MASK) + 1) * 10));
}

/*
 * Composite Count/Interval-Steps octet codec: Count in bits 2..0, Interval
 * Steps in bits 7..3.  MshPRT_v1.1 Section 4.3.2.13 / 4.3.2.70.
 */
uint8_t
mesh_relay_pack(uint8_t count, uint8_t steps)
{

	return ((uint8_t)((count & MESH_RELAY_COUNT_MASK) |
	    ((steps & MESH_RELAY_STEPS_MASK) << 3)));
}

void
mesh_relay_unpack(uint8_t octet, uint8_t *count, uint8_t *steps)
{

	if (count != NULL)
		*count = (uint8_t)(octet & MESH_RELAY_COUNT_MASK);
	if (steps != NULL)
		*steps = (uint8_t)((octet >> 3) & MESH_RELAY_STEPS_MASK);
}

/*
 * Relay Retransmit timed scheduler.  MshPRT_v1.1 Section 3.4.6.3 / 4.2.21.
 *
 * Pure and hardware-free: `now` is a caller-supplied monotonic millisecond
 * value (like mesh_iv.c's clock); the engine reads no real clock and does no
 * sleeping.  The initial relay transmission is the caller's responsibility;
 * this schedules the Relay Retransmit Count additional transmissions at the
 * Relay Retransmit Interval Steps spacing.
 */
void
mesh_relay_tx_schedule(struct mesh_relay_tx *j, uint8_t count, uint8_t steps,
    uint64_t now_ms)
{

	if (j == NULL)
		return;
	memset(j, 0, sizeof(*j));
	j->remaining = (uint8_t)(count & MESH_RELAY_COUNT_MASK);
	if (j->remaining == 0)		/* count 0 => no retransmission */
		return;
	j->interval_ms = mesh_relay_interval_ms(steps);
	j->next_ms = now_ms + j->interval_ms;
	j->active = 1;
}

int
mesh_relay_tx_active(const struct mesh_relay_tx *j)
{

	return (j != NULL && j->active);
}

int
mesh_relay_tx_due(const struct mesh_relay_tx *j, uint64_t now_ms)
{

	if (j == NULL || !j->active)
		return (0);
	return (now_ms >= j->next_ms);
}

int
mesh_relay_tx_fire(struct mesh_relay_tx *j, uint64_t now_ms)
{

	if (!mesh_relay_tx_due(j, now_ms))
		return (0);
	j->remaining--;
	if (j->remaining == 0)
		j->active = 0;			/* last retransmission consumed */
	else
		j->next_ms += j->interval_ms;
	return (1);
}
