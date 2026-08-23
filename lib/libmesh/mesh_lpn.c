/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Low Power node driven state machine.  MshPRT_v1.1 Section
 * 3.6.5 / 3.6.6.4.  See mesh_lpn.h.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_friend.h"
#include "mesh_lpn.h"

/* Build a Friend Request into out and open a fresh Offer window. */
static int
lpn_build_request(struct mesh_lpn_fsm *l, uint64_t now, struct mesh_lpn_out *out)
{
	struct mesh_friend_request req;
	size_t olen;

	/*
	 * PreviousAddress carries the unicast address of the Friend of the prior
	 * friendship (0 = none), so a new Friend can send Friend Clear to release
	 * it (Section 3.6.6.4.1).  friend_addr holds the last selected Friend and
	 * is 0 on the first-ever Request.
	 */
	l->prev_addr = l->friend_addr;

	memset(&req, 0, sizeof(req));
	req.rssi_factor = l->rssi_factor;
	req.rx_window_factor = l->rx_window_factor;
	req.min_queue_size_log = l->min_queue_size_log;
	req.recv_delay = l->recv_delay;
	req.poll_timeout = l->poll_timeout;
	req.prev_addr = l->prev_addr;
	req.num_elements = l->num_elements;
	req.lpn_counter = l->lpn_counter;
	/*
	 * The friendship security credential (MshPRT 3.6.6.2) uses the LPNCounter
	 * carried in THIS Request, but l->lpn_counter is incremented for the next
	 * one below; remember the wire value so the credential matches the peer.
	 */
	l->est_lpn_counter = l->lpn_counter;

	olen = 0;
	if (mesh_friend_request_build(&req, out->pdu, &olen) != 0)
		return (-1);
	out->pdu_len = olen;
	out->action = MESH_LPN_ACT_SEND_REQUEST;

	l->lpn_counter++;
	l->n_offers = 0;
	l->poll_outstanding = 0;
	l->offer_start_ms = now;
	l->offer_deadline_ms = now + l->offer_window_ms;
	l->state = MESH_LPN_ST_REQUESTING;
	return (0);
}

/* Build the next Friend Poll into out, addressed to the selected Friend. */
static int
lpn_build_poll(struct mesh_lpn_fsm *l, struct mesh_lpn_out *out)
{
	struct mesh_friend_poll poll;
	size_t olen;

	memset(&poll, 0, sizeof(poll));
	poll.fsn = (uint8_t)mesh_lpn_poll_fsn(&l->cadence);
	olen = 0;
	if (mesh_friend_poll_build(&poll, out->pdu, &olen) != 0)
		return (-1);
	out->pdu_len = olen;
	out->friend_addr = l->friend_addr;
	out->action = MESH_LPN_ACT_SEND_POLL;
	l->poll_outstanding = 1;		/* awaiting this Poll's response */
	return (0);
}

void
mesh_lpn_fsm_init(struct mesh_lpn_fsm *l, uint16_t lpn_addr,
    uint8_t num_elements, uint8_t rssi_factor, uint8_t rx_window_factor,
    uint8_t min_queue_size_log, uint8_t recv_delay, uint32_t poll_timeout,
    uint32_t offer_window_ms, uint32_t poll_interval_ms)
{

	if (l == NULL)
		return;
	memset(l, 0, sizeof(*l));
	l->state = MESH_LPN_ST_IDLE;
	l->lpn_addr = lpn_addr;
	l->num_elements = num_elements;
	l->rssi_factor = rssi_factor;
	l->rx_window_factor = rx_window_factor;
	l->min_queue_size_log = min_queue_size_log;
	l->recv_delay = recv_delay;
	l->poll_timeout = poll_timeout;
	l->offer_window_ms = offer_window_ms;
	l->poll_interval_ms = poll_interval_ms;
	l->establish_max_retries = MESH_LPN_ESTABLISH_RETRIES;
}

int
mesh_lpn_fsm_start(struct mesh_lpn_fsm *l, uint64_t now, struct mesh_lpn_out *out)
{

	if (l == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	return (lpn_build_request(l, now, out));
}

int
mesh_lpn_fsm_recv_offer(struct mesh_lpn_fsm *l, const uint8_t *pdu, size_t len,
    uint16_t friend_addr, uint64_t now)
{
	struct mesh_friend_offer offer;
	size_t i;

	if (l == NULL || pdu == NULL)
		return (-1);
	if (l->state != MESH_LPN_ST_REQUESTING ||
	    now - l->offer_start_ms > l->offer_window_ms)
		return (0);
	if (mesh_friend_offer_parse(pdu, len, &offer) != 0)
		return (-1);
	if (l->n_offers >= MESH_LPN_OFFERS_MAX)
		return (0);
	/* Ignore a duplicate Offer from a Friend already recorded. */
	for (i = 0; i < l->n_offers; i++) {
		if (l->offer_addr[i] == friend_addr)
			return (0);
	}
	l->offers[l->n_offers] = offer;
	l->offer_addr[l->n_offers] = friend_addr;
	l->n_offers++;
	return (1);
}

int
mesh_lpn_fsm_tick(struct mesh_lpn_fsm *l, uint64_t now, struct mesh_lpn_out *out)
{
	uint16_t min_qsz;
	int best;

	if (l == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_LPN_ACT_NONE;

	switch (l->state) {
	case MESH_LPN_ST_REQUESTING:
		if (now - l->offer_start_ms < l->offer_window_ms)
			return (0);
		min_qsz = mesh_friend_min_queue_size(l->min_queue_size_log);
		best = mesh_lpn_select_offer(l->offers, l->n_offers, min_qsz);
		if (best < 0)
			/* No qualifying Offer: re-Request. */
			return (lpn_build_request(l, now, out));
		l->friend_addr = l->offer_addr[best];
		l->friend_counter = l->offers[best].friend_counter;
		if (mesh_lpn_init(&l->cadence, l->poll_timeout, now) != 0)
			return (-1);
		l->state = MESH_LPN_ST_ESTABLISHING;
		/* Open the establish window: ReceiveDelay + Offer ReceiveWindow. */
		l->establish_window_ms = (uint32_t)l->recv_delay +
		    l->offers[best].recv_window;
		if (l->establish_window_ms == 0)
			l->establish_window_ms = 1;
		l->establish_retries = 0;
		l->establish_start_ms = now;
		l->establish_deadline_ms = now + l->establish_window_ms;
		return (lpn_build_poll(l, out));

	case MESH_LPN_ST_ESTABLISHING:
		/*
		 * Awaiting the first Friend Update.  Retransmit the Friend Poll
		 * once the establish window lapses; once the retry budget is
		 * spent, abandon this Friend and send a fresh Friend Request.
		 */
		if (now - l->establish_start_ms < l->establish_window_ms)
			return (0);
		if (l->establish_retries >= l->establish_max_retries)
			return (lpn_build_request(l, now, out));
		l->establish_retries++;
		l->establish_start_ms = now;
		l->establish_deadline_ms = now + l->establish_window_ms;
		return (lpn_build_poll(l, out));

	case MESH_LPN_ST_ESTABLISHED:
		if (mesh_lpn_friendship_lost(&l->cadence, now)) {
			out->action = MESH_LPN_ACT_LOST;
			l->state = MESH_LPN_ST_IDLE;
			return (0);
		}
		if (now - l->next_poll_start_ms >=
		    l->next_poll_ms - l->next_poll_start_ms) {
			/*
			 * Emit the due Poll and pace the next (re)transmission by
			 * ReceiveDelay + ReceiveWindow so a due Poll is not
			 * re-emitted every tick (poll storm; finding).  A
			 * received Friend Update reschedules next_poll_ms to the
			 * normal cadence; if no response arrives within the
			 * window the Poll is retransmitted.
			 */
			uint32_t window = l->establish_window_ms != 0 ?
			    l->establish_window_ms : 1;

			l->next_poll_start_ms = now;
			l->next_poll_ms = now + window;
			return (lpn_build_poll(l, out));
		}
		return (0);

	case MESH_LPN_ST_IDLE:
	default:
		return (0);
	}
}

int
mesh_lpn_fsm_recv_update(struct mesh_lpn_fsm *l, const uint8_t *pdu, size_t len,
    uint64_t now, struct mesh_lpn_out *out)
{
	struct mesh_friend_update up;
	int first, is_duplicate;

	if (l == NULL || pdu == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_LPN_ACT_NONE;

	if (l->state != MESH_LPN_ST_ESTABLISHING &&
	    l->state != MESH_LPN_ST_ESTABLISHED)
		return (-1);
	if (mesh_friend_update_parse(pdu, len, &up) != 0)
		return (-1);

	first = (l->state == MESH_LPN_ST_ESTABLISHING);
	l->state = MESH_LPN_ST_ESTABLISHED;
	mesh_lpn_established(&l->cadence);

	l->key_refresh = up.key_refresh;
	l->iv_update = up.iv_update;
	l->iv_index = up.iv_index;
	l->more_data = up.md ? 1 : 0;

	/*
	 * The Update acknowledges the outstanding Poll: toggle FSN and advance
	 * supervision.  Duplicate detection is keyed on PDU identity - a response
	 * byte-identical to the last received Friend Update is a duplicate and
	 * must not toggle the FSN (Section 3.6.6.4.2).  Keying on PDU identity
	 * rather than the poll-outstanding flag prevents a stale retransmission of
	 * a prior response (arriving while a fresh Poll is outstanding) from
	 * erroneously toggling the FSN.
	 */
	is_duplicate = (l->have_last_update && len == l->last_update_len &&
	    memcmp(l->last_update, pdu, len) == 0);
	l->poll_outstanding = 0;
	if (len <= sizeof(l->last_update)) {
		memcpy(l->last_update, pdu, len);
		l->last_update_len = len;
		l->have_last_update = 1;
	}
	(void)mesh_lpn_on_response(&l->cadence, is_duplicate, now);
	l->next_poll_start_ms = now;
	l->next_poll_ms = up.md ? now : now + l->poll_interval_ms;

	if (first)
		out->action = MESH_LPN_ACT_ESTABLISHED;
	return (1);
}

int
mesh_lpn_fsm_on_message(struct mesh_lpn_fsm *l, int more_data, uint64_t now)
{

	if (l == NULL)
		return (-1);
	if (l->state != MESH_LPN_ST_ESTABLISHED)
		return (-1);
	l->more_data = more_data ? 1 : 0;
	/*
	 * A delivered message acknowledges the outstanding Poll (toggle FSN); a
	 * duplicate copy arriving with no Poll outstanding does not (finding).
	 */
	{
		int is_duplicate = !l->poll_outstanding;

		l->poll_outstanding = 0;
		(void)mesh_lpn_on_response(&l->cadence, is_duplicate, now);
	}
	l->next_poll_start_ms = now;
	l->next_poll_ms = more_data ? now : now + l->poll_interval_ms;
	return (0);
}

int
mesh_lpn_fsm_sub(struct mesh_lpn_fsm *l, int add, const uint16_t *addrs,
    size_t naddr, uint64_t now, struct mesh_lpn_out *out)
{
	struct mesh_friend_sublist sl;
	size_t olen;
	uint8_t op;

	if (l == NULL || addrs == NULL || out == NULL)
		return (-1);
	if (naddr == 0 || naddr > MESH_FRIEND_SUBLIST_ADDR_MAX)
		return (-1);
	if (l->state != MESH_LPN_ST_ESTABLISHED)
		return (-1);
	(void)now;

	memset(&sl, 0, sizeof(sl));
	/*
	 * The first Subscription List TransactionNumber is 0x00 and increments per
	 * completed transaction (Section 3.6.6.4.3).  sub_transaction holds the
	 * number in flight; it advances on the matching Confirm (recv_subconfirm).
	 */
	sl.transaction = l->sub_transaction;
	sl.naddr = naddr;
	memcpy(sl.addrs, addrs, naddr * sizeof(addrs[0]));
	op = add ? MESH_FRIEND_OP_SUBLIST_ADD : MESH_FRIEND_OP_SUBLIST_REMOVE;

	memset(out, 0, sizeof(*out));
	olen = 0;
	if (mesh_friend_sublist_build(op, &sl, out->pdu, &olen) != 0)
		return (-1);
	out->pdu_len = olen;
	out->friend_addr = l->friend_addr;
	out->action = MESH_LPN_ACT_SEND_SUBLIST;
	l->sub_pending = 1;
	return (0);
}

int
mesh_lpn_fsm_recv_subconfirm(struct mesh_lpn_fsm *l, const uint8_t *pdu,
    size_t len)
{
	struct mesh_friend_subconfirm cf;

	if (l == NULL || pdu == NULL)
		return (-1);
	if (mesh_friend_subconfirm_parse(pdu, len, &cf) != 0)
		return (-1);
	if (!l->sub_pending || cf.transaction != l->sub_transaction)
		return (0);
	l->sub_pending = 0;
	l->sub_transaction++;		/* advance TransactionNumber for the next */
	return (1);
}

int
mesh_lpn_fsm_established(const struct mesh_lpn_fsm *l)
{

	return (l != NULL && l->state == MESH_LPN_ST_ESTABLISHED);
}

uint16_t
mesh_lpn_fsm_friend(const struct mesh_lpn_fsm *l)
{

	return (l != NULL ? l->friend_addr : 0);
}

uint16_t
mesh_lpn_fsm_friend_counter(const struct mesh_lpn_fsm *l)
{

	return (l != NULL ? l->friend_counter : 0);
}

uint16_t
mesh_lpn_fsm_lpn_counter(const struct mesh_lpn_fsm *l)
{

	/* The friendship credential's LPNCounter is the establishing Request's
	 * value, not the (already-incremented) next counter. */
	return (l != NULL ? l->est_lpn_counter : 0);
}

uint32_t
mesh_lpn_fsm_iv_index(const struct mesh_lpn_fsm *l)
{

	return (l != NULL ? l->iv_index : 0);
}

uint8_t
mesh_lpn_fsm_key_refresh(const struct mesh_lpn_fsm *l)
{

	return (l != NULL ? l->key_refresh : 0);
}
