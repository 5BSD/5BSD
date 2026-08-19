/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Friendship (MshPRT_v1.1 Section 3.6.6), built on the
 * mesh_crypto.[ch] toolbox (Section 3.8) and the lower-transport control
 * framing of mesh_transport.[ch] (Section 3.5).
 *
 * Friendship lets a battery-powered Low Power node (LPN) sleep: it hands off
 * to a neighbouring Friend node, which stores messages addressed to the LPN in
 * a Friend Queue and delivers them when the LPN wakes and polls.  This module
 * provides four things:
 *
 *   1. Friendship security material (Section 3.6.6.2 / 3.9.6.3.1): the k2
 *      derivation with the friendship P-input
 *      0x01 || LPNAddress || FriendAddress || LPNCounter || FriendCounter
 *      producing the friendship NID / EncryptionKey / PrivacyKey.
 *   2. The Lower Transport Control friendship messages (Section 3.6.5):
 *      Friend Poll/Update/Request/Offer/Clear/Clear Confirm and the
 *      Subscription List Add/Remove/Confirm - build and parse, each with the
 *      exact Section 3.6.5 field layout.
 *   3. The Friend Queue model (Section 3.5.5 / 3.6.6.4): a bounded per-LPN
 *      store with the subscription-list + TTL enqueue filter, oldest-first
 *      eviction protecting Friend Update entries, and the single-bit Friend
 *      Sequence Number (FSN) poll/ack delivery protocol.
 *   4. The LPN side: Friend Request criteria encode/decode, the Friend Offer
 *      Delay formula, offer selection, and the poll/PollTimeout cadence driven
 *      by a caller-supplied clock.
 *
 * Pure and hardware-free: values are held in host order and packed big-endian
 * on the wire; no I/O, no globals, no dynamic allocation; secrets cleared with
 * explicit_bzero().  Codec/derivation functions return 0 on success and -1 on
 * failure with outputs zeroed; predicates return their result directly.
 *
 * NOTE ON NONCE: friendship-secured Network PDUs use the STANDARD network
 * nonce (mesh_network_nonce, Section 3.8.5.1) with the friendship security
 * material - there is no separate "Friend nonce".  A caller secures a
 * friendship PDU by feeding the friendship NID/EncryptionKey/PrivacyKey from
 * mesh_friend_credentials() to mesh_net_encrypt()/mesh_net_decrypt().
 */

#ifndef _MESH_FRIEND_H_
#define _MESH_FRIEND_H_

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * 1. Friendship security material.  MshPRT_v1.1 Section 3.6.6.2.
 * ================================================================ */

/*
 * Length of the friendship k2 P-input:
 *   0x01 (1) || LPNAddress (2) || FriendAddress (2) || LPNCounter (2) ||
 *   FriendCounter (2) = 9 octets.  Section 3.9.6.3.1.
 */
#define	MESH_FRIEND_P_LEN	9

/*
 * Build the 9-octet friendship k2 P-input into out (big-endian addresses and
 * counters).  Exposed for callers/tests that want the raw P value; returns 0
 * on success, -1 if out is NULL.
 */
int	mesh_friend_p_input(uint16_t lpn_addr, uint16_t friend_addr,
	    uint16_t lpn_counter, uint16_t friend_counter,
	    uint8_t out[MESH_FRIEND_P_LEN]);

/*
 * Derive the friendship security material.  MshPRT_v1.1 Section 3.6.6.2 /
 * 3.9.6.3.1:
 *
 *   NID || EncryptionKey || PrivacyKey =
 *       k2(NetKey, 0x01 || LPNAddress || FriendAddress ||
 *                  LPNCounter || FriendCounter)
 *
 * Returns 0 on success (out_nid holds the 7-bit NID, out_enckey/out_privkey
 * the 128-bit keys); -1 on failure with all outputs zeroed.
 */
int	mesh_friend_credentials(const uint8_t netkey[16], uint16_t lpn_addr,
	    uint16_t friend_addr, uint16_t lpn_counter, uint16_t friend_counter,
	    uint8_t out_nid[1], uint8_t out_enckey[16], uint8_t out_privkey[16]);

/* ================================================================
 * 2. Lower Transport Control friendship messages.  Section 3.6.5.
 *
 * Each on-wire message is an Unsegmented Transport Control PDU: octet 0 is
 * SEG(0)|Opcode(7) and the remaining octets are the message parameters.  The
 * build functions below emit that complete PDU (opcode octet + parameters);
 * the parse functions consume it (validating in[0]'s opcode).
 * ================================================================ */

/* Transport Control opcodes for the friendship messages (Section 3.6.5). */
#define	MESH_FRIEND_OP_POLL		0x01
#define	MESH_FRIEND_OP_UPDATE		0x02
#define	MESH_FRIEND_OP_REQUEST		0x03
#define	MESH_FRIEND_OP_OFFER		0x04
#define	MESH_FRIEND_OP_CLEAR		0x05
#define	MESH_FRIEND_OP_CLEAR_CONFIRM	0x06
#define	MESH_FRIEND_OP_SUBLIST_ADD	0x07
#define	MESH_FRIEND_OP_SUBLIST_REMOVE	0x08
#define	MESH_FRIEND_OP_SUBLIST_CONFIRM	0x09

/* Fixed on-wire message lengths (opcode octet + parameters). */
#define	MESH_FRIEND_POLL_LEN		2	/* op + 1 (Padding|FSN) */
#define	MESH_FRIEND_UPDATE_LEN		7	/* op + Flags,IVIndex,MD */
#define	MESH_FRIEND_REQUEST_LEN		11	/* op + 10 param octets */
#define	MESH_FRIEND_OFFER_LEN		7	/* op + 6 param octets */
#define	MESH_FRIEND_CLEAR_LEN		5	/* op + LPNAddr,LPNCounter */
#define	MESH_FRIEND_CLEAR_CONFIRM_LEN	5	/* op + LPNAddr,LPNCounter */
#define	MESH_FRIEND_SUBCONFIRM_LEN	2	/* op + TransactionNumber */

/* Bound on the number of addresses in a Subscription List Add/Remove. */
#define	MESH_FRIEND_SUBLIST_ADDR_MAX	16

/* Friend Poll (0x01): FSN is a single bit; the 7-bit Padding is 0. */
struct mesh_friend_poll {
	uint8_t		fsn;		/* Friend Sequence Number, 0 or 1 */
};

/* Friend Update (0x02): Flags (Key Refresh | IV Update), IV Index, MD. */
struct mesh_friend_update {
	uint8_t		key_refresh;	/* Flags bit 0: In-Phase2 */
	uint8_t		iv_update;	/* Flags bit 1: IV Update in Progress */
	uint32_t	iv_index;	/* current IV Index */
	uint8_t		md;		/* More Data: 1 => queue not empty */
};

/*
 * Friend Request (0x03).  Criteria decomposed into its subfields (Section
 * 3.6.5.3): RSSIFactor/ReceiveWindowFactor are 2-bit encodings, MinQueueSizeLog
 * a 3-bit log2.  See the criteria helpers below for the value meanings.
 */
struct mesh_friend_request {
	uint8_t		rssi_factor;	/* Criteria: 2-bit RSSIFactor */
	uint8_t		rx_window_factor; /* Criteria: 2-bit ReceiveWindowFactor */
	uint8_t		min_queue_size_log; /* Criteria: 3-bit MinQueueSizeLog */
	uint8_t		recv_delay;	/* ReceiveDelay, ms (0x0A..0xFF valid) */
	uint32_t	poll_timeout;	/* PollTimeout, units of 100 ms (24-bit) */
	uint16_t	prev_addr;	/* PreviousAddress */
	uint8_t		num_elements;	/* NumElements (>= 1) */
	uint16_t	lpn_counter;	/* LPNCounter */
};

/* Friend Offer (0x04). */
struct mesh_friend_offer {
	uint8_t		recv_window;	/* ReceiveWindow, ms (>= 1) */
	uint8_t		queue_size;	/* QueueSize */
	uint8_t		sub_list_size;	/* SubscriptionListSize */
	int8_t		rssi;		/* RSSI, signed dBm (0x7F = n/a) */
	uint16_t	friend_counter;	/* FriendCounter */
};

/* Friend Clear (0x05) and Friend Clear Confirm (0x06) share this layout. */
struct mesh_friend_clear {
	uint16_t	lpn_addr;	/* LPNAddress */
	uint16_t	lpn_counter;	/* LPNCounter */
};

/* Friend Subscription List Add (0x07) / Remove (0x08). */
struct mesh_friend_sublist {
	uint8_t		transaction;	/* TransactionNumber */
	uint16_t	addrs[MESH_FRIEND_SUBLIST_ADDR_MAX];
	size_t		naddr;		/* number of addresses (>= 1) */
};

/* Friend Subscription List Confirm (0x09). */
struct mesh_friend_subconfirm {
	uint8_t		transaction;	/* TransactionNumber */
};

/* Build (opcode + parameters) / parse each friendship control message. */
int	mesh_friend_poll_build(const struct mesh_friend_poll *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_poll_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_poll *out);

int	mesh_friend_update_build(const struct mesh_friend_update *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_update_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_update *out);

int	mesh_friend_request_build(const struct mesh_friend_request *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_request_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_request *out);

int	mesh_friend_offer_build(const struct mesh_friend_offer *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_offer_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_offer *out);

/* op selects CLEAR (0x05) vs CLEAR_CONFIRM (0x06). */
int	mesh_friend_clear_build(uint8_t op, const struct mesh_friend_clear *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_clear_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_clear *out, uint8_t *op);

/* op selects SUBLIST_ADD (0x07) vs SUBLIST_REMOVE (0x08). */
int	mesh_friend_sublist_build(uint8_t op, const struct mesh_friend_sublist *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_sublist_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_sublist *out, uint8_t *op);

int	mesh_friend_subconfirm_build(const struct mesh_friend_subconfirm *in,
	    uint8_t *out, size_t *outlen);
int	mesh_friend_subconfirm_parse(const uint8_t *in, size_t inlen,
	    struct mesh_friend_subconfirm *out);

/*
 * Length of the on-wire buffer needed for the largest friendship message.  A
 * Subscription List Add/Remove is op(1) + Transaction(1) + 2*N; bound N.
 */
#define	MESH_FRIEND_MSG_MAX	(2 + 2 * MESH_FRIEND_SUBLIST_ADDR_MAX)

/* ----------------------------------------------------------------
 * Criteria field helpers (Section 3.6.5.3, Tables 3.33-3.36).
 * ---------------------------------------------------------------- */

/*
 * Pack/unpack the 1-octet Criteria field: bit 7 RFU (0), bits 6..5 RSSIFactor,
 * bits 4..3 ReceiveWindowFactor, bits 2..0 MinQueueSizeLog.
 */
uint8_t	mesh_friend_criteria_pack(uint8_t rssi_factor, uint8_t rx_window_factor,
	    uint8_t min_queue_size_log);
void	mesh_friend_criteria_unpack(uint8_t octet, uint8_t *rssi_factor,
	    uint8_t *rx_window_factor, uint8_t *min_queue_size_log);

/*
 * MinQueueSizeLog -> N (minimum queue size) = 2^log (Table 3.36).  log 0 is
 * Prohibited; this returns 0 for a log of 0 and 1u<<log otherwise.
 */
uint16_t	mesh_friend_min_queue_size(uint8_t min_queue_size_log);

/*
 * RSSIFactor / ReceiveWindowFactor 2-bit encoding -> factor * 2 (Table 3.34 /
 * 3.35): 0b00->2 (1.0), 0b01->3 (1.5), 0b10->4 (2.0), 0b11->5 (2.5).  The
 * doubled value keeps the Friend Offer Delay arithmetic in integers.
 */
uint8_t	mesh_friend_factor_x2(uint8_t enc);

/*
 * Friend Offer Delay.  MshPRT_v1.1 Section 3.6.6.3.1:
 *   Local Delay = ReceiveWindowFactor*ReceiveWindow - RSSIFactor*RSSI
 *   Friend Offer Delay = (Local Delay > 100) ? Local Delay : 100  [ms]
 * rssi is the signed dBm measured for the Friend Request.  Returns the delay
 * in milliseconds.  rssi_factor / rx_window_factor are the 2-bit encodings.
 */
int	mesh_friend_offer_delay(uint8_t rssi_factor, uint8_t rx_window_factor,
	    uint8_t recv_window, int8_t rssi);

/* ================================================================
 * 3. Friend Subscription List state (the Friend node's per-LPN list).
 *    Section 3.6.6 / 3.6.6.3.3.
 * ================================================================ */

#define	MESH_FRIEND_SUBLIST_MAX	16

struct mesh_friend_sublist_state {
	uint16_t	addrs[MESH_FRIEND_SUBLIST_MAX];
	size_t		n;
};

void	mesh_friend_sub_init(struct mesh_friend_sublist_state *s);
/* Add: returns 1 added, 0 already present, -1 full. */
int	mesh_friend_sub_add(struct mesh_friend_sublist_state *s, uint16_t addr);
/* Remove: returns 1 removed, 0 not present. */
int	mesh_friend_sub_remove(struct mesh_friend_sublist_state *s, uint16_t addr);
/* Contains: returns 1 present, 0 absent. */
int	mesh_friend_sub_contains(const struct mesh_friend_sublist_state *s,
	    uint16_t addr);

/* ================================================================
 * 4. Friend Queue.  MshPRT_v1.1 Section 3.5.5 / 3.6.6.4.
 * ================================================================ */

/* Maximum stored Lower Transport PDU length (matches mesh_transport). */
#define	MESH_FQ_PDU_MAX		88
/* Hard cap on queue slots; the runtime bound (cap) may be smaller. */
#define	MESH_FQ_MAX		16

/*
 * One Friend Queue entry: the stored Lower Transport PDU plus the associated
 * network-layer fields (CTL/TTL/SEQ/SRC/DST), per Section 3.5.5.  is_update
 * marks a Friend Update entry, which is protected from full-queue eviction.
 */
struct mesh_fq_entry {
	uint8_t		ctl;
	uint8_t		ttl;
	uint32_t	seq;
	uint16_t	src;
	uint16_t	dst;
	uint8_t		pdu[MESH_FQ_PDU_MAX];	/* Lower Transport PDU */
	size_t		pdu_len;
	int		is_update;		/* Friend Update (evict-protected) */
	uint8_t		segmented;		/* an as-yet-unreassembled segment */
	int		valid;
	uint32_t	order;			/* insertion order (oldest = smallest) */
};

/*
 * Friend Queue: bounded ring of entries plus the LPN identity used by the
 * enqueue filter and the FSN delivery state.  cap is the runtime bound
 * (1..MESH_FQ_MAX).
 */
struct mesh_friend_queue {
	struct mesh_fq_entry		entries[MESH_FQ_MAX];
	size_t				cap;
	uint32_t			order_ctr;	/* monotonic insertion counter */
	uint16_t			lpn_addr;	/* LPN primary element unicast */
	uint8_t				num_elements;	/* LPN element count (range) */
	struct mesh_friend_sublist_state sub;		/* Friend Subscription List */
	int				last_fsn;	/* FSN of last poll answered; -1 none */
};

/*
 * Bind a Friend Queue to an LPN.  cap is clamped to [1, MESH_FQ_MAX]; the
 * subscription list starts empty and the FSN state is reset.
 */
void	mesh_fq_init(struct mesh_friend_queue *q, uint16_t lpn_addr,
	    uint8_t num_elements, size_t cap);

/*
 * Enqueue a received message destined for the LPN.  MshPRT_v1.1 Section 3.5.5.
 * The caller supplies the message in *in (CTL/TTL/SEQ/SRC/DST + Lower Transport
 * PDU) exactly as received.  The policy is:
 *
 *   - a message flagged as an as-yet-unreassembled segment (in->segmented) is
 *     not stored: a Segmented Access/Control message is queued only after the
 *     complete Upper Transport PDU has been reassembled (Section 3.5.5);
 *   - the DST must be a unicast address of an LPN element (in the range
 *     [lpn_addr, lpn_addr+num_elements-1]) or an address in the Friend
 *     Subscription List; otherwise the message is not for the LPN;
 *   - the TTL must be 2 or greater;
 *   - if an entry with the same (SEQ, SRC) is already queued, or the SRC is
 *     one of the LPN's own element addresses, the message is not stored;
 *   - otherwise the stored copy's TTL is decremented by 1 and the entry is
 *     appended; if the queue is full, the oldest non-Update entry is evicted
 *     first (repeating if necessary).
 *
 * Returns 1 stored, 0 filtered/not stored, -1 error (NULL / oversized PDU /
 * full of Update entries with no room).
 */
int	mesh_fq_enqueue(struct mesh_friend_queue *q,
	    const struct mesh_fq_entry *in);

/*
 * Add a Friend Update entry to the queue.  Section 3.5.5: a security update
 * (or the empty-queue Poll response) is stored as a Friend Update, which is
 * exempt from the DST filter and from full-queue eviction.  pdu/pdu_len is the
 * built Friend Update Lower Transport PDU.  Returns 0 on success, -1 on error.
 */
int	mesh_fq_enqueue_update(struct mesh_friend_queue *q,
	    const struct mesh_fq_entry *in);

/* Number of valid entries currently queued. */
size_t	mesh_fq_count(const struct mesh_friend_queue *q);

/*
 * Discard every entry in the Friend Queue (Section 3.6.6.3.2: when a
 * friendship is terminated the Friend node shall discard all entries in the
 * Friend Queue).  The LPN binding and subscription list are retained; the FSN
 * delivery state is reset.
 */
void	mesh_fq_flush(struct mesh_friend_queue *q);

/*
 * Respond to a Friend Poll.  MshPRT_v1.1 Section 3.6.6.4.2.  fsn is the FSN
 * carried in the Poll.  The single-bit FSN handshake:
 *
 *   - if this Poll's FSN differs from the FSN of the previously answered Poll
 *     (or this is the first Poll), the previously delivered head entry - if
 *     any - was acknowledged and is discarded;
 *   - if the FSN is unchanged, the last response was lost and the same head is
 *     resent (nothing discarded);
 *   - the (new) oldest entry is then returned in *out as the message to send.
 *
 * If the queue is empty and empty_update != NULL, that Friend Update entry is
 * enqueued first and returned (Section 3.5.5: an empty-queue Poll must be
 * answered with a freshly generated Friend Update).
 *
 * Returns 1 with *out filled when there is a message to send; 0 when the queue
 * is empty and no empty_update was supplied (nothing to send); -1 on error.
 */
int	mesh_fq_poll(struct mesh_friend_queue *q, int fsn,
	    const struct mesh_fq_entry *empty_update, struct mesh_fq_entry *out);

/* ================================================================
 * 5. Low Power node cadence.  MshPRT_v1.1 Section 3.6.6.4.
 * ================================================================ */

/*
 * PollTimeout wire-value bounds (units of 100 ms).  Section 3.6.5.3 Table 3.38:
 * 0x00000A..0x34BBFF valid, everything else Prohibited.
 */
#define	MESH_LPN_POLLTIMEOUT_MIN	0x00000Au
#define	MESH_LPN_POLLTIMEOUT_MAX	0x34BBFFu

/*
 * LPN friendship cadence state.  The clock (now) is caller-supplied and in
 * milliseconds, matching the ms units of ReceiveDelay/ReceiveWindow; this
 * module never reads a real clock (like mesh_iv).
 */
struct mesh_lpn_state {
	uint32_t	poll_timeout;	/* configured PollTimeout, units 100 ms */
	uint64_t	last_poll_ms;	/* clock at the last successful Poll */
	int		fsn;		/* LPN Friend Sequence Number, 0 or 1 */
	int		established;	/* friendship established */
};

/*
 * Start a friendship establishment attempt: FSN is reset to 0 (Section
 * 3.6.6.4.1) and the PollTimeout recorded; poll_timeout must be in range or
 * the call fails (-1) and the state is left zeroed.  now seeds last_poll_ms.
 */
int	mesh_lpn_init(struct mesh_lpn_state *st, uint32_t poll_timeout,
	    uint64_t now);

/* Mark the friendship established (a Friend Update was received). */
void	mesh_lpn_established(struct mesh_lpn_state *st);

/* PollTimeout expressed in milliseconds (poll_timeout * 100). */
uint64_t	mesh_lpn_poll_timeout_ms(const struct mesh_lpn_state *st);

/*
 * The FSN value to place in the next Friend Poll (Section 3.6.6.4.2: FSN =
 * current Friend Sequence Number).
 */
int	mesh_lpn_poll_fsn(const struct mesh_lpn_state *st);

/*
 * Record the outcome of a Poll response (Section 3.6.6.4.2).  If a
 * non-duplicate response was received (is_duplicate == 0), the FSN is toggled
 * and last_poll_ms is advanced to now (the Poll succeeded).  A duplicate
 * response leaves the FSN unchanged but still counts as contact, advancing
 * last_poll_ms.  Returns the (possibly toggled) FSN.
 */
int	mesh_lpn_on_response(struct mesh_lpn_state *st, int is_duplicate,
	    uint64_t now);

/*
 * Friendship-lost predicate (Section 3.6.6.4.2): the friendship is considered
 * terminated once the PollTimeout has elapsed since the last successful Poll.
 * Returns 1 if (now - last_poll_ms) >= PollTimeout ms, else 0.
 */
int	mesh_lpn_friendship_lost(const struct mesh_lpn_state *st, uint64_t now);

/*
 * Offer selection (LPN side).  MshPRT_v1.1 leaves the exact choice to the
 * implementation (Section 3.6.6.4.1: "may select one of the Friend nodes");
 * this is a deterministic LOCAL POLICY, not a spec-mandated algorithm.  Among
 * the offers[0..n) that meet the requested minimum queue size (QueueSize >=
 * min_queue_size), the selected offer is the one with, in order: the largest
 * QueueSize, then the largest SubscriptionListSize, then the strongest RSSI,
 * then the smallest ReceiveWindow, then the lowest index.  Returns the index
 * of the selected offer, or -1 if none qualifies (or on bad arguments).
 */
int	mesh_lpn_select_offer(const struct mesh_friend_offer *offers, size_t n,
	    uint16_t min_queue_size);

/* ================================================================
 * 6. Friend role driven state machine.  MshPRT_v1.1 Section 3.6.5.
 *
 * The engine drives the Friend side of a single friendship end to end from a
 * caller-supplied millisecond clock: it evaluates an incoming Friend Request
 * against local criteria, emits a Friend Offer after the Friend Offer Delay,
 * establishes the friendship on the first Friend Poll, answers each Poll from
 * the Friend Queue, services the Subscription List Add/Remove handshake, and
 * supervises the PollTimeout - terminating the friendship if no Poll arrives
 * in time.  It owns one struct mesh_friend_queue (Section 3.6.6.4).
 * ================================================================ */

/*
 * Establishment window (MshPRT_v1.1 Section 3.6.6.3.1): the friendship is
 * established only if the first Friend Poll arrives within 1 s of the Friend
 * Offer.  ESTABLISHING expires after this with no established friendship.
 */
#define	MESH_FRIEND_ESTABLISH_TIMEOUT_MS	1000u

/*
 * Friend Clear procedure timers (Section 3.6.6.3.1).  The first Friend Clear
 * is sent as soon as the friendship is established; the Friend Clear Repeat
 * timer starts at 1 s and doubles on each expiry, and the Friend Clear
 * Procedure timer runs for twice the PollTimeout, after which the procedure is
 * abandoned.
 */
#define	MESH_FRIEND_CLEAR_REPEAT_MS	1000u

/* Friendship phase (Section 3.6.5 / 3.6.6.4.1). */
enum mesh_friend_fsm_state {
	MESH_FRIEND_ST_IDLE = 0,	/* no friendship, no pending offer */
	MESH_FRIEND_ST_OFFERING,	/* Request accepted, Offer pending (delay) */
	MESH_FRIEND_ST_ESTABLISHING,	/* Offer sent, awaiting the first Poll */
	MESH_FRIEND_ST_ESTABLISHED,	/* friendship active */
};

/* The action a Friend FSM step asks the caller to perform. */
enum mesh_friend_action {
	MESH_FRIEND_ACT_NONE = 0,	/* nothing to send */
	MESH_FRIEND_ACT_SEND_CONTROL,	/* out->pdu is a control message to send */
	MESH_FRIEND_ACT_SEND_MSG,	/* out->msg is a queued PDU to deliver */
	MESH_FRIEND_ACT_TERMINATED,	/* friendship dropped (PollTimeout) */
	MESH_FRIEND_ACT_SEND_CLEAR,	/* out->pdu is a Friend Clear for out->addr */
};

/*
 * Output of a Friend FSM step.  For MESH_FRIEND_ACT_SEND_CLEAR the control PDU
 * is a Friend Clear that must be sent (with managed-flooding credentials, TTL
 * 0x7F) to the previous Friend at out->addr, not to the LPN.
 */
struct mesh_friend_out {
	enum mesh_friend_action	action;
	uint8_t			pdu[MESH_FRIEND_MSG_MAX];	/* control PDU */
	size_t			pdu_len;
	uint16_t		addr;		/* control-PDU destination (SEND_CLEAR) */
	struct mesh_fq_entry	msg;		/* dequeued queue entry (ACT_SEND_MSG) */
};

/*
 * Friend role engine.  The local Offer parameters (ReceiveWindow, QueueSize,
 * SubscriptionListSize) and the acceptance policy (a floor RSSI and the largest
 * MinQueueSizeLog we can serve) are fixed at init; the per-friendship
 * negotiated values arrive in the Friend Request.
 */
struct mesh_friend_fsm {
	enum mesh_friend_fsm_state	state;
	uint16_t			friend_addr;	/* our primary element */

	/* Local Offer parameters / acceptance policy. */
	uint8_t				recv_window;	/* our ReceiveWindow, ms */
	uint8_t				queue_size;	/* our QueueSize capacity */
	uint8_t				sub_list_size;	/* our SubscriptionListSize */
	int8_t				min_rssi;	/* reject weaker Requests */
	uint8_t				max_queue_size_log; /* largest we can serve */

	/* Negotiated per-friendship state from the Friend Request. */
	uint16_t			lpn_addr;
	uint16_t			lpn_counter;
	uint16_t			friend_counter;	/* our FriendCounter */
	uint16_t			prev_addr;	/* PreviousAddress from the Request */
	uint8_t				num_elements;
	uint8_t				recv_delay;	/* LPN ReceiveDelay, ms */
	uint32_t			poll_timeout;	/* units of 100 ms */

	/* Timers (injected clock, ms). */
	uint64_t			offer_start_ms;
	uint32_t			offer_delay_ms;
	uint64_t			offer_at_ms;	/* when to emit the Offer */
	uint64_t			offer_sent_ms;	/* Offer emitted; ESTABLISHING start */
	uint64_t			last_poll_ms;	/* last Poll received */

	/*
	 * Establishment handshake (Section 3.6.6.3.1): the first Friend Poll is
	 * answered with a Friend Update, not a queued data PDU.  establish_update
	 * is set from that first Poll until the LPN acknowledges the Update with a
	 * Poll carrying a toggled FSN, at which point queued data delivery begins.
	 */
	uint8_t				establish_update;
	uint8_t				establish_fsn;	/* FSN of the establishing Poll */

	/*
	 * Friend Clear procedure (Section 3.6.6.3.1): when an accepted LPN carried
	 * a valid PreviousAddress, Friend Clear messages are sent to the previous
	 * Friend until a Friend Clear Confirm is received or the procedure timer
	 * (2 x PollTimeout) expires.  The repeat period starts at 1 s and doubles.
	 */
	uint8_t				clear_active;
	uint16_t			clear_addr;	/* previous Friend to clear */
	uint16_t			clear_lpn_counter;
	uint64_t			clear_repeat_at_ms;
	uint32_t			clear_repeat_ms;	/* current repeat period */
	uint64_t			clear_deadline_ms;	/* procedure timer */

	struct mesh_friend_offer	offer;		/* the pending Offer contents */
	struct mesh_friend_queue	queue;		/* the Friend Queue */
};

/*
 * Initialise a Friend engine at address friend_addr with the local Offer
 * parameters and acceptance policy.  The engine starts IDLE with an empty
 * FriendCounter; the queue is bound on the first accepted Request.
 */
void	mesh_friend_fsm_init(struct mesh_friend_fsm *f, uint16_t friend_addr,
	    uint8_t recv_window, uint8_t queue_size, uint8_t sub_list_size,
	    int8_t min_rssi, uint8_t max_queue_size_log);

/*
 * Evaluate a received Friend Request (Section 3.6.5.3 / 3.6.6.3).  lpn_addr is
 * the Network PDU SRC and rssi is the measured signal for the Request.
 * Acceptance policy: the LPN element range is valid, rssi >= min_rssi and the
 * requested MinQueueSizeLog is one we can serve (<= max_queue_size_log and the
 * resulting minimum queue size <= our QueueSize).  On acceptance the engine
 * moves to OFFERING, binds the Friend Queue to the LPN, computes the Friend
 * Offer Delay (Section 3.6.6.3.1) and schedules the Offer at now + delay;
 * out->action is NONE (the Offer is emitted later by mesh_friend_fsm_tick).
 * A Request for the already-established LPN re-arms a fresh Offer (Section
 * 3.6.5).  Returns 0 accepted, -1 rejected/ignored (bad argument, failed
 * criteria, unparsable) with the state unchanged on a bad argument.
 */
int	mesh_friend_fsm_recv_request(struct mesh_friend_fsm *f,
	    const uint8_t *pdu, size_t len, uint16_t lpn_addr, int8_t rssi,
	    uint64_t now,
	    struct mesh_friend_out *out);

/*
 * Rebind an existing FSM to an LPN primary-element unicast address.  This is
 * retained for simulations; normal Request processing binds atomically.
 * Returns 0 on success and -1 if the address or element range is invalid.
 */
int	mesh_friend_fsm_bind_lpn(struct mesh_friend_fsm *f, uint16_t lpn_addr);

/*
 * Advance the engine's timers.  Emits the pending Friend Offer once the Offer
 * Delay has elapsed (OFFERING -> ESTABLISHING, out->action SEND_CONTROL), and
 * supervises the PollTimeout while ESTABLISHED (terminates the friendship, out
 * ->action TERMINATED, if now - last_poll >= PollTimeout).  Returns 0.
 */
int	mesh_friend_fsm_tick(struct mesh_friend_fsm *f, uint64_t now,
	    struct mesh_friend_out *out);

/*
 * Process a received Friend Poll (Section 3.6.6.4.2).  The first Poll while
 * ESTABLISHING establishes the friendship.  Records the Poll time (resetting
 * the PollTimeout supervision) and runs the Friend Queue's FSN handshake: emits
 * the next queued PDU (out->action SEND_MSG) or, on an empty queue, a freshly
 * built Friend Update carrying the supplied security flags (out->action
 * SEND_MSG with a Friend Update entry).  Returns 1 with out filled, 0 if there
 * was nothing to send, -1 on error or a Poll in the wrong state.
 */
int	mesh_friend_fsm_recv_poll(struct mesh_friend_fsm *f, const uint8_t *pdu,
	    size_t len, uint8_t key_refresh, uint8_t iv_update, uint32_t iv_index,
	    uint64_t now, struct mesh_friend_out *out);

/*
 * Process a Friend Subscription List Add (0x07) / Remove (0x08) (Section
 * 3.6.6.3.3): mutate the queue's subscription list and emit the matching
 * Subscription List Confirm (out->action SEND_CONTROL).  Returns 1 with a
 * confirm to send, -1 on error or the wrong state.
 */
int	mesh_friend_fsm_recv_sublist(struct mesh_friend_fsm *f,
	    const uint8_t *pdu, size_t len, uint64_t now,
	    struct mesh_friend_out *out);

/*
 * Process a Friend Clear (0x05) or Friend Clear Confirm (0x06) (Section
 * 3.6.5.5 / 3.6.5.6).  A Friend Clear that targets our LPN with an in-range
 * LPNCounter terminates the friendship, discards the Friend Queue and emits a
 * Friend Clear Confirm (out->action SEND_CONTROL, returns 1).  A Friend Clear
 * Confirm that matches an in-flight Friend Clear procedure (this Friend cleared
 * a previous Friend of the LPN) stops that procedure (returns 0, no output).
 * Returns 0 when the message does not match, -1 on error.
 */
int	mesh_friend_fsm_recv_clear(struct mesh_friend_fsm *f, const uint8_t *pdu,
	    size_t len, struct mesh_friend_out *out);

/*
 * Offer a message received off the network to the Friend Queue for the LPN
 * (Section 3.5.5).  Thin wrapper over mesh_fq_enqueue that queues while the
 * friendship is forming or established (OFFERING / ESTABLISHING / ESTABLISHED)
 * and no-ops only while IDLE.  Returns mesh_fq_enqueue's result (1 stored, 0
 * filtered, -1 error), or 0 if IDLE.
 */
int	mesh_friend_fsm_enqueue(struct mesh_friend_fsm *f,
	    const struct mesh_fq_entry *in);

/* True while the friendship is established. */
int	mesh_friend_fsm_established(const struct mesh_friend_fsm *f);

#endif /* _MESH_FRIEND_H_ */
