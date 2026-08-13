/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Low Power node (LPN) driven state machine.  MshPRT_v1.1
 * Section 3.6.5 (friendship messages) and Section 3.6.6.4 (the LPN cadence).
 *
 * The engine drives the LPN side of a single friendship from a caller-supplied
 * millisecond clock, built on the mesh_friend.[ch] control-message codecs and
 * the mesh_lpn_state cadence helpers:
 *
 *   - establishment: send a Friend Request, collect the Friend Offers arriving
 *     inside a caller-set window, select the best (mesh_lpn_select_offer), and
 *     send the first Friend Poll to the chosen Friend;
 *   - operation: poll on the configured cadence, process each Friend Update
 *     (recording the IV Index / Key Refresh flags and the More Data bit) and
 *     toggle the Friend Sequence Number for the next Poll;
 *   - subscription: add/remove group addresses through the Friend with the
 *     Subscription List Add/Remove + Confirm transaction handshake;
 *   - recovery: re-establish (a fresh Friend Request) once the PollTimeout
 *     lapses with no successful Poll (Section 3.6.6.4.2).
 *
 * Pure and hardware-free: no I/O, no globals, no real clock.  Each entry point
 * fills a struct mesh_lpn_out describing the single action the caller must take
 * (send a control PDU to a Friend, or an informational transition).
 */

#ifndef _MESH_LPN_H_
#define _MESH_LPN_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_friend.h"

/* Maximum Friend Offers collected in one establishment window. */
#define	MESH_LPN_OFFERS_MAX	8

/*
 * Default budget of Friend Poll retransmissions while establishing (awaiting
 * the first Friend Update) before the chosen Friend is abandoned and a fresh
 * Friend Request is sent (Section 3.6.6.4.1).
 */
#define	MESH_LPN_ESTABLISH_RETRIES	3

/* LPN friendship phase (Section 3.6.6.4.1). */
enum mesh_lpn_fsm_state {
	MESH_LPN_ST_IDLE = 0,		/* no friendship, idle */
	MESH_LPN_ST_REQUESTING,		/* Request sent, collecting Offers */
	MESH_LPN_ST_ESTABLISHING,	/* Offer chosen, first Poll sent */
	MESH_LPN_ST_ESTABLISHED,	/* friendship active, polling */
};

/* The action an LPN FSM step asks the caller to perform. */
enum mesh_lpn_action {
	MESH_LPN_ACT_NONE = 0,
	MESH_LPN_ACT_SEND_REQUEST,	/* broadcast Friend Request (out->pdu) */
	MESH_LPN_ACT_SEND_POLL,		/* Friend Poll to out->friend_addr */
	MESH_LPN_ACT_SEND_SUBLIST,	/* Subscription List Add/Remove */
	MESH_LPN_ACT_ESTABLISHED,	/* friendship just came up (informational) */
	MESH_LPN_ACT_LOST,		/* friendship lost; a re-Request follows */
};

/* Output of an LPN FSM step. */
struct mesh_lpn_out {
	enum mesh_lpn_action	action;
	uint8_t			pdu[MESH_FRIEND_MSG_MAX];
	size_t			pdu_len;
	uint16_t		friend_addr;	/* PDU destination when established */
};

struct mesh_lpn_fsm {
	enum mesh_lpn_fsm_state	state;
	uint16_t		lpn_addr;
	uint8_t			num_elements;

	/* Friend Request criteria + parameters (Section 3.6.5.3). */
	uint8_t			rssi_factor;
	uint8_t			rx_window_factor;
	uint8_t			min_queue_size_log;
	uint8_t			recv_delay;	/* ms */
	uint32_t		poll_timeout;	/* units of 100 ms */
	uint16_t		prev_addr;
	uint16_t		lpn_counter;	/* increments per Request */

	/* Timers (injected clock, ms). */
	uint32_t		offer_window_ms;  /* Offer collection window */
	uint64_t		offer_start_ms;
	uint64_t		offer_deadline_ms;
	uint32_t		poll_interval_ms; /* Poll cadence (< PollTimeout) */
	uint64_t		next_poll_start_ms;
	uint64_t		next_poll_ms;

	/* Collected Offers. */
	struct mesh_friend_offer offers[MESH_LPN_OFFERS_MAX];
	uint16_t		offer_addr[MESH_LPN_OFFERS_MAX];
	size_t			n_offers;

	uint16_t		friend_addr;	/* selected Friend */
	struct mesh_lpn_state	cadence;	/* FSN + PollTimeout supervision */

	/*
	 * Set when a Friend Poll has been emitted and its response is still
	 * outstanding.  The first response for a Poll toggles the FSN; a second
	 * copy of that response (arriving before the next Poll) is a duplicate
	 * and must not toggle the FSN again (Section 3.6.6.4.2).
	 */
	int			poll_outstanding;

	/*
	 * Establishment supervision: the first Friend Poll may be lost or its
	 * Friend Update never arrive, so the Poll is retransmitted each
	 * establish window (ReceiveDelay + the chosen Offer's ReceiveWindow) up
	 * to establish_max_retries before the Friend is abandoned (re-Request).
	 */
	uint32_t		establish_window_ms;
	uint64_t		establish_start_ms;
	uint64_t		establish_deadline_ms;
	unsigned		establish_retries;
	unsigned		establish_max_retries;

	/* Last Friend Update security state. */
	uint8_t			key_refresh;
	uint8_t			iv_update;
	uint32_t		iv_index;
	int			more_data;

	/* Subscription List transaction handshake. */
	uint8_t			sub_transaction;
	int			sub_pending;	/* awaiting a Confirm */
};

/*
 * Initialise the LPN engine.  rssi_factor / rx_window_factor / min_queue_size_log
 * are the 2/2/3-bit Criteria encodings (Section 3.6.5.3); recv_delay is the LPN
 * ReceiveDelay in ms; poll_timeout is the PollTimeout in units of 100 ms;
 * offer_window_ms is how long to gather Offers before selecting; poll_interval_ms
 * is the Poll cadence and must be shorter than PollTimeout (poll_timeout*100 ms)
 * so a Poll always precedes the supervision deadline.  Starts IDLE.
 */
void	mesh_lpn_fsm_init(struct mesh_lpn_fsm *l, uint16_t lpn_addr,
	    uint8_t num_elements, uint8_t rssi_factor, uint8_t rx_window_factor,
	    uint8_t min_queue_size_log, uint8_t recv_delay, uint32_t poll_timeout,
	    uint32_t offer_window_ms, uint32_t poll_interval_ms);

/*
 * Begin (or restart) friendship establishment: build a Friend Request
 * (out->action SEND_REQUEST, out->pdu), advance the LPNCounter, and open the
 * Offer collection window.  Returns 0, -1 on error.
 */
int	mesh_lpn_fsm_start(struct mesh_lpn_fsm *l, uint64_t now,
	    struct mesh_lpn_out *out);

/*
 * Record a received Friend Offer from friend_addr while collecting (state
 * REQUESTING and still inside the window).  Returns 1 stored, 0 ignored (wrong
 * state / window closed / table full), -1 on error.
 */
int	mesh_lpn_fsm_recv_offer(struct mesh_lpn_fsm *l, const uint8_t *pdu,
	    size_t len, uint16_t friend_addr, uint64_t now);

/*
 * Advance the engine's timers.  Closes the Offer window and selects the best
 * Offer (sending the first Poll, or re-Requesting if none arrived);
 * retransmits the first Poll each establish window while ESTABLISHING until
 * the first Friend Update arrives or the retry budget is spent (then
 * re-Requests); issues the next cadence Poll while ESTABLISHED; and
 * re-establishes once the PollTimeout lapses.  Fills out with the resulting
 * action.  Returns 0.
 */
int	mesh_lpn_fsm_tick(struct mesh_lpn_fsm *l, uint64_t now,
	    struct mesh_lpn_out *out);

/*
 * Process a received Friend Update (Section 3.6.6.4.2): establish the
 * friendship on the first Update, record the IV Index / Key Refresh flags and
 * the More Data bit, toggle the Friend Sequence Number, and schedule the next
 * Poll (immediately when More Data is set).  out->action is ESTABLISHED on the
 * first Update, else NONE.  Returns 1 on a processed Update, -1 on error or the
 * wrong state.
 */
int	mesh_lpn_fsm_recv_update(struct mesh_lpn_fsm *l, const uint8_t *pdu,
	    size_t len, uint64_t now, struct mesh_lpn_out *out);

/*
 * Note that a queued data message was delivered as this Poll's response.
 * Toggles the Friend Sequence Number and schedules the next Poll (immediately
 * if more_data indicates the Friend Queue still holds entries).  Returns 0, -1
 * on error or the wrong state.
 */
int	mesh_lpn_fsm_on_message(struct mesh_lpn_fsm *l, int more_data,
	    uint64_t now);

/*
 * Queue a Subscription List Add (add != 0) / Remove of up to naddr group
 * addresses through the Friend (Section 3.6.6.3.3): build the message with a
 * fresh TransactionNumber (out->action SEND_SUBLIST) and await its Confirm.
 * Returns 0, -1 on error, the wrong state, or a bad address count.
 */
int	mesh_lpn_fsm_sub(struct mesh_lpn_fsm *l, int add, const uint16_t *addrs,
	    size_t naddr, uint64_t now, struct mesh_lpn_out *out);

/*
 * Process a Subscription List Confirm: clears the pending subscription
 * transaction when the TransactionNumber matches.  Returns 1 matched, 0 not
 * matched, -1 on error.
 */
int	mesh_lpn_fsm_recv_subconfirm(struct mesh_lpn_fsm *l, const uint8_t *pdu,
	    size_t len);

/* Inspection accessors. */
int		mesh_lpn_fsm_established(const struct mesh_lpn_fsm *l);
uint16_t	mesh_lpn_fsm_friend(const struct mesh_lpn_fsm *l);
uint32_t	mesh_lpn_fsm_iv_index(const struct mesh_lpn_fsm *l);
uint8_t		mesh_lpn_fsm_key_refresh(const struct mesh_lpn_fsm *l);

#endif /* _MESH_LPN_H_ */
