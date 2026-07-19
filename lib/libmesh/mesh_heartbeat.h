/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Heartbeat (Mesh Protocol 1.1 Sections 3.6.7,
 * 4.2.18-4.2.19, and 4.3.2.61-4.3.2.66).
 *
 * Two distinct on-wire objects live here:
 *
 *   1. The Heartbeat transport control message (Section 3.6.7.1): an
 *      UNSEGMENTED control message with Opcode 0x0A carrying InitTTL (7 bits)
 *      and Features (16 bits, big-endian on the wire like every transport
 *      field).  It is published on a feature change (Relay/Proxy/Friend/Low
 *      Power bit change) and periodically.
 *
 *   2. The Configuration model Heartbeat Publication and Subscription
 *      messages (Sections 4.3.2.61-.66): access-layer messages whose multi-
 *      octet fields are LITTLE-endian per the model convention, built and
 *      parsed with the mesh_access.[ch] opcode wrapper.
 *
 * CountLog / PeriodLog use the transforms in Sections 4.2.18.2-.3 and
 * 4.2.19.3-.4: value 0 -> 0x00, and value v (1..0xFFFF) -> the smallest n in
 * 1..0x11 with 2^(n-1) >= v (so the transform is exactly value = 2^(n-1) at
 * the encoded points).  For the Heartbeat Publication Count the sentinel 0xFF
 * additionally means "publish indefinitely".
 *
 * Pure and hardware-free: no I/O, no globals.  Every codec returns 0 on
 * success and -1 on failure, output zeroed on failure.
 */

#ifndef _MESH_HEARTBEAT_H_
#define _MESH_HEARTBEAT_H_

#include <stddef.h>
#include <stdint.h>

/* ----------------------------------------------------------------
 * Feature bits (MshPRT_v1.1 Section 3.6.7.1, Features field).  These match
 * the Composition Data Features bit order (Section 4.2.1.5).
 * ---------------------------------------------------------------- */
#define	MESH_HB_FEATURE_RELAY		0x0001u
#define	MESH_HB_FEATURE_PROXY		0x0002u
#define	MESH_HB_FEATURE_FRIEND		0x0004u
#define	MESH_HB_FEATURE_LOW_POWER	0x0008u
#define	MESH_HB_FEATURE_MASK		0x000fu

/* ----------------------------------------------------------------
 * Configuration Heartbeat opcodes (Bluetooth Assigned Numbers).
 * ---------------------------------------------------------------- */
#define	MESH_CFG_OP_HB_PUB_STATUS	0x06	/* one-octet opcode */
#define	MESH_CFG_OP_HB_PUB_GET		0x8038
#define	MESH_CFG_OP_HB_PUB_SET		0x8039
#define	MESH_CFG_OP_HB_SUB_GET		0x803A
#define	MESH_CFG_OP_HB_SUB_SET		0x803B
#define	MESH_CFG_OP_HB_SUB_STATUS	0x803C

/* Transport control Opcode for the Heartbeat message (Section 3.5.2.3). */
#define	MESH_HB_CTL_OPCODE		0x0A

/* ----------------------------------------------------------------
 * CountLog / PeriodLog helpers (Sections 4.2.18.2-.3 and 4.2.19.3-.4).
 * ---------------------------------------------------------------- */

/* Encode an actual count (0..0xFFFF) to a CountLog (0x00, 0x01..0x11). */
uint8_t	mesh_hb_count_log(uint16_t count);

/* Validity of a PeriodLog octet: 0x00..0x11. */
int	mesh_hb_period_log_valid(uint8_t plog);

/* Decode a PeriodLog to its period in seconds (0x00 -> 0). */
uint32_t mesh_hb_period_log_decode(uint8_t plog);

/* ================================================================
 * Heartbeat transport control message (Section 3.6.7.1).
 * ================================================================ */
struct mesh_hb_msg {
	uint8_t		init_ttl;	/* 7-bit Initial TTL */
	uint16_t	features;	/* MESH_HB_FEATURE_* bitmap */
};

/* The 3-octet message body: InitTTL (1) || Features (2, big-endian). */
int	mesh_hb_msg_build(const struct mesh_hb_msg *in, uint8_t *out,
	    size_t *outlen);
int	mesh_hb_msg_parse(const uint8_t *in, size_t inlen,
	    struct mesh_hb_msg *out);

/*
 * The full unsegmented Transport Control PDU (Section 3.5.2.3):
 *   octet0 = SEG(0)|Opcode(0x0A), then InitTTL || Features (big-endian).
 */
int	mesh_hb_ctl_pdu_build(const struct mesh_hb_msg *in, uint8_t *out,
	    size_t *outlen);
int	mesh_hb_ctl_pdu_parse(const uint8_t *in, size_t inlen,
	    struct mesh_hb_msg *out);

/* ================================================================
 * Heartbeat Publication (Sections 4.2.18 and 4.3.2.61-.63).
 * ================================================================ */
struct mesh_hb_pub {
	uint16_t	dst;		/* publication destination (0 => off) */
	uint8_t		count_log;	/* CountLog (0x00..0x11, or 0xFF) */
	uint8_t		period_log;	/* PeriodLog (0x00..0x11) */
	uint8_t		ttl;		/* publication TTL (0..0x7F) */
	uint16_t	features;	/* trigger feature mask */
	uint16_t	net_idx;	/* NetKey index */
};

/*
 * Config Heartbeat Publication Get (0x8038): no parameters.
 * Config Heartbeat Publication Set (0x8039):
 *   Destination(2) CountLog(1) PeriodLog(1) TTL(1) Features(2) NetKeyIndex(2).
 * Config Heartbeat Publication Status (0x06):
 *   Status(1) then the same seven fields.
 * All multi-octet fields little-endian; NetKeyIndex is the 12-bit packing.
 */
int	mesh_hb_pub_get_build(uint8_t *out, size_t *outlen);
int	mesh_hb_pub_set_build(const struct mesh_hb_pub *in, uint8_t *out,
	    size_t *outlen);
int	mesh_hb_pub_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_hb_pub *out);
int	mesh_hb_pub_status_build(uint8_t status, const struct mesh_hb_pub *in,
	    uint8_t *out, size_t *outlen);
int	mesh_hb_pub_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_hb_pub *out);

/*
 * Publish-on-feature-change (Section 3.6.7.2).  Given the node's feature set
 * before and after a change, decide whether a triggered Heartbeat must be
 * published: a message is sent when a bit that is in the publication trigger
 * mask (pub->features) changed.  The emitted message carries the node's
 * CURRENT features and InitTTL = pub->ttl.  Returns 1 and fills *msg when a
 * Heartbeat should be published, 0 when it must not, -1 on a bad argument.
 */
int	mesh_hb_pub_feature_change(const struct mesh_hb_pub *pub,
	    uint16_t old_features, uint16_t new_features,
	    struct mesh_hb_msg *msg);

/*
 * Periodic Heartbeat publication emitter (Mesh Protocol 1.1 §3.6.7.2).  While
 * the Publication Count is non-zero and the Publication Period (PeriodLog) is
 * non-zero, the node publishes a Heartbeat transport control message every
 * Period seconds, decrementing the Count on each publication until it reaches
 * zero (a CountLog of 0xFF publishes indefinitely).  This is the count-down /
 * period state a scheduler ticks; the trigger-on-feature-change path is
 * mesh_hb_pub_feature_change().
 *
 * mesh_hb_pub_timer_init() loads the configured publication into the timer,
 * decoding the CountLog to a remaining count and the PeriodLog to seconds; a
 * disabled publication (Destination 0, PeriodLog 0 or CountLog 0) leaves the
 * timer inactive.  mesh_hb_pub_timer_tick() advances the timer by secs seconds
 * and, when a Period boundary is crossed and publications remain, fills *out
 * with the message to publish (InitTTL from the publication TTL, Features the
 * node's current feature set) and returns 1; otherwise it returns 0.  The
 * Count reflected by mesh_hb_pub_timer_count_log() is the CountLog of the
 * publications still owed.
 */
struct mesh_hb_pub_timer {
	uint16_t	dst;		/* publication destination (0 => disabled) */
	uint8_t		ttl;		/* InitTTL carried in each message */
	uint16_t	net_idx;	/* NetKey index the message is secured with */
	uint32_t	period;		/* seconds between publications (0 => off) */
	uint32_t	elapsed;	/* seconds accumulated toward the next send */
	uint32_t	remaining;	/* publications still owed */
	int		indefinite;	/* CountLog 0xFF: publish without a limit */
};
void	mesh_hb_pub_timer_init(struct mesh_hb_pub_timer *t,
	    const struct mesh_hb_pub *pub);
int	mesh_hb_pub_timer_active(const struct mesh_hb_pub_timer *t);
int	mesh_hb_pub_timer_tick(struct mesh_hb_pub_timer *t, uint32_t secs,
	    uint16_t features, struct mesh_hb_msg *out);
uint8_t	mesh_hb_pub_timer_count_log(const struct mesh_hb_pub_timer *t);

/* ================================================================
 * Heartbeat Subscription (Sections 4.2.19 and 4.3.2.64-.66).
 * ================================================================ */
struct mesh_hb_sub {
	uint16_t	src;		/* subscription source (0 => off) */
	uint16_t	dst;		/* subscription destination (0 => off) */
	uint8_t		period_log;	/* configured PeriodLog */
	uint16_t	count;		/* received count (saturates at 0xFFFF) */
	uint8_t		min_hops;	/* smallest observed hop count */
	uint8_t		max_hops;	/* largest observed hop count */
};

/*
 * Config Heartbeat Subscription Get (0x803A): no parameters.
 * Config Heartbeat Subscription Set (0x803B): Source(2) Destination(2)
 *   PeriodLog(1).
 * Config Heartbeat Subscription Status (0x803C): Status(1) Source(2)
 *   Destination(2) PeriodLog(1) CountLog(1) MinHops(1) MaxHops(1).
 */
struct mesh_hb_sub_set {
	uint16_t	src;
	uint16_t	dst;
	uint8_t		period_log;
};
struct mesh_hb_sub_status {
	uint8_t		status;
	uint16_t	src;
	uint16_t	dst;
	uint8_t		period_log;
	uint8_t		count_log;
	uint8_t		min_hops;
	uint8_t		max_hops;
};
int	mesh_hb_sub_get_build(uint8_t *out, size_t *outlen);
int	mesh_hb_sub_set_build(const struct mesh_hb_sub_set *in, uint8_t *out,
	    size_t *outlen);
int	mesh_hb_sub_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_hb_sub_set *out);
int	mesh_hb_sub_status_build(const struct mesh_hb_sub_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_hb_sub_status_parse(const uint8_t *in, size_t inlen,
	    struct mesh_hb_sub_status *out);

/*
 * Subscription receive state machine (Sections 3.6.7.3 and 4.3.2.65).
 * mesh_hb_sub_init() clears it.  mesh_hb_sub_apply() applies a Subscription
 * Set: a zero Source, zero Destination or zero PeriodLog disables the
 * subscription; otherwise it (re)arms it and resets Count/MinHops/MaxHops
 * (Count=0, MinHops=0x7F, MaxHops=0x00).  mesh_hb_sub_receive() ingests one
 * received Heartbeat: when (src,dst) match the active subscription it counts
 * it (saturating at 0xFFFF) and folds hops = InitTTL - RxTTL + 1 into
 * Min/Max Hops.  Returns 1 if counted, 0 if ignored.
 */
void	mesh_hb_sub_init(struct mesh_hb_sub *s);
int	mesh_hb_sub_apply(struct mesh_hb_sub *s, const struct mesh_hb_sub_set *in);
int	mesh_hb_sub_receive(struct mesh_hb_sub *s, uint16_t src, uint16_t dst,
	    uint8_t init_ttl, uint8_t rx_ttl);
/* Snapshot the subscription as a Status structure. */
void	mesh_hb_sub_snapshot(const struct mesh_hb_sub *s, uint8_t status,
	    struct mesh_hb_sub_status *out);

#endif /* _MESH_HEARTBEAT_H_ */
