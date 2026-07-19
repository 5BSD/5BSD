/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Relay feature (MshPRT_v1.1 Section 3.4.6 / 3.6.4), with the
 * Network Transmit and Relay Retransmit configuration states (Section 4.2.20
 * and 4.2.21).
 *
 * The Relay feature retransmits Network PDUs received over the advertising
 * bearer so a message can travel more than one hop (managed flooding).  The
 * core "may this PDU be relayed and with what TTL" arithmetic already lives in
 * mesh_net_relay() (Section 3.4.6.3: relay only when TTL >= 2, retransmit with
 * TTL - 1); this module adds the FEATURE GATE around it - the relay-enabled
 * flag, the Network Message Cache ("already seen") check, and the
 * destined-onward (destination is not one of this node's own unicast
 * addresses) check - and models the retransmit interval/count states as pure
 * configuration.
 *
 * Pure and hardware-free: no I/O, no globals, no dynamic allocation.  The
 * predicates return their decision directly.
 */

#ifndef _MESH_RELAY_H_
#define _MESH_RELAY_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Network Transmit / Relay Retransmit state.  MshPRT_v1.1 Section 4.2.20 and
 * 4.2.21.  Both composite states hold a 3-bit Count and a 5-bit Interval
 * Steps.  On the wire (e.g. the Config Relay Set / Config Network Transmit Set
 * messages, Section 4.3.2.13 / 4.3.2.70) the two subfields are packed into a
 * single octet: Count in bits 2..0, Interval Steps in bits 7..3.
 */
#define	MESH_RELAY_COUNT_MASK		0x07	/* 3-bit Count field */
#define	MESH_RELAY_STEPS_MASK		0x1f	/* 5-bit Interval Steps field */

/*
 * Relay feature configuration.  `enabled` gates the whole feature; the
 * transmit/retransmit substates are the Section 4.2.20 / 4.2.21 values.
 */
struct mesh_relay_config {
	int		enabled;		/* Relay feature enabled */
	uint8_t		net_tx_count;		/* Network Transmit Count (3-bit) */
	uint8_t		net_tx_steps;		/* Network Transmit Interval Steps (5-bit) */
	uint8_t		relay_rx_count;		/* Relay Retransmit Count (3-bit) */
	uint8_t		relay_rx_steps;		/* Relay Retransmit Interval Steps (5-bit) */
};

/*
 * Relay decision.  MshPRT_v1.1 Section 3.4.6.3.  A received (authenticated)
 * Network PDU is relayed only when ALL of the following hold:
 *
 *   - the Relay feature is enabled (cfg->enabled != 0);
 *   - the PDU is not already in the Network Message Cache (in_cache == 0),
 *     i.e. it has not been seen/processed before (Section 3.4.6.5);
 *   - the destination is not one of this node's own unicast addresses
 *     (dst_is_local == 0), i.e. the PDU is destined onward;
 *   - the TTL is 2 or greater (mesh_net_relay()).
 *
 * Returns 1 and, when new_ttl != NULL, writes the retransmit TTL (TTL - 1)
 * when the PDU is to be relayed; returns 0 otherwise (new_ttl untouched).
 * cfg must be non-NULL.
 */
int	mesh_relay_decide(const struct mesh_relay_config *cfg, uint8_t ttl,
	    int in_cache, int dst_is_local, uint8_t *new_ttl);

/*
 * Retransmit policy accessors.  MshPRT_v1.1 Section 4.2.20 / 4.2.21.
 *
 * mesh_relay_tx_count(): number of transmissions = Count + 1 (0b000 => 1
 *   transmission, 0b111 => 8).  The Count field is masked to 3 bits.
 * mesh_relay_interval_ms(): transmission interval = (Interval Steps + 1) * 10
 *   milliseconds.  The Interval Steps field is masked to 5 bits (so the result
 *   ranges over 10..320 ms).
 */
uint8_t		mesh_relay_tx_count(uint8_t count_field);
uint16_t	mesh_relay_interval_ms(uint8_t steps_field);

/*
 * Composite Count/Interval-Steps octet codec (the on-wire packing shared by
 * Config Relay Set and Config Network Transmit Set, Section 4.3.2.13 /
 * 4.3.2.70): Count occupies bits 2..0 and Interval Steps bits 7..3.
 *
 * mesh_relay_pack() returns the packed octet (inputs masked to their fields).
 * mesh_relay_unpack() splits an octet back into count/steps (either output
 * pointer may be NULL).
 */
uint8_t	mesh_relay_pack(uint8_t count, uint8_t steps);
void	mesh_relay_unpack(uint8_t octet, uint8_t *count, uint8_t *steps);

/*
 * Relay Retransmit timed scheduler.  MshPRT_v1.1 Section 3.4.6.3 / 4.2.21.
 *
 * When a Network PDU is relayed, the node retransmits it Relay Retransmit
 * Count additional times, spaced by the Relay Retransmit Interval Steps.  A
 * struct mesh_relay_tx models one such in-flight schedule; time is a
 * caller-supplied monotonic millisecond value (no real clock, no sleeping),
 * matching the rest of libblemesh's injected-clock timing.
 */
struct mesh_relay_tx {
	int		active;		/* retransmissions still pending */
	uint8_t		remaining;	/* retransmissions left to send */
	uint16_t	interval_ms;	/* spacing between retransmissions */
	uint64_t	next_ms;	/* absolute time of the next one */
};

/*
 * Schedule the Relay Retransmit Count retransmissions of a just-relayed PDU,
 * each Interval-Steps apart, starting one interval after now_ms.  count is
 * the raw 3-bit Relay Retransmit Count (the number of RETRANSMISSIONS): a
 * count of 0 schedules none (the job is left inactive).  The initial relay
 * transmission is the caller's; this covers only the retransmissions.
 */
void	mesh_relay_tx_schedule(struct mesh_relay_tx *j, uint8_t count,
	    uint8_t steps, uint64_t now_ms);

/* 1 while retransmissions remain, 0 once the schedule is exhausted. */
int	mesh_relay_tx_active(const struct mesh_relay_tx *j);

/* 1 iff a retransmission is due at now_ms (active and now_ms >= next). */
int	mesh_relay_tx_due(const struct mesh_relay_tx *j, uint64_t now_ms);

/*
 * If a retransmission is due at now_ms, consume it (advance the schedule to
 * the next interval, or deactivate after the last) and return 1; otherwise
 * return 0 with the schedule unchanged.
 */
int	mesh_relay_tx_fire(struct mesh_relay_tx *j, uint64_t now_ms);

#endif /* _MESH_RELAY_H_ */
