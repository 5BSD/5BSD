/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Friendship (MshPRT_v1.1 Section 3.6.6).  See mesh_friend.h.
 *
 * All multi-octet fields are packed big-endian on the wire (Section 3.1.1).
 * The friendship control messages are Unsegmented Transport Control PDUs whose
 * octet 0 is SEG(0)|Opcode(7); this file builds/parses the whole PDU (opcode
 * octet + parameters) so the codec is self-contained.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_friend.h"

/* Big-endian 16-bit read/write helpers. */
static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
get16(const uint8_t *p)
{

	return ((uint16_t)((p[0] << 8) | p[1]));
}

/* ================================================================
 * 1. Friendship security material.  Section 3.6.6.2 / 3.9.6.3.1.
 * ================================================================ */

int
mesh_friend_p_input(uint16_t lpn_addr, uint16_t friend_addr,
    uint16_t lpn_counter, uint16_t friend_counter, uint8_t out[MESH_FRIEND_P_LEN])
{

	if (out == NULL)
		return (-1);
	out[0] = 0x01;
	put16(out + 1, lpn_addr);
	put16(out + 3, friend_addr);
	put16(out + 5, lpn_counter);
	put16(out + 7, friend_counter);
	return (0);
}

int
mesh_friend_credentials(const uint8_t netkey[16], uint16_t lpn_addr,
    uint16_t friend_addr, uint16_t lpn_counter, uint16_t friend_counter,
    uint8_t out_nid[1], uint8_t out_enckey[16], uint8_t out_privkey[16])
{
	uint8_t p[MESH_FRIEND_P_LEN];
	int rc;

	if (netkey == NULL || out_nid == NULL || out_enckey == NULL ||
	    out_privkey == NULL) {
		if (out_nid != NULL)
			out_nid[0] = 0;
		if (out_enckey != NULL)
			memset(out_enckey, 0, 16);
		if (out_privkey != NULL)
			memset(out_privkey, 0, 16);
		return (-1);
	}

	(void)mesh_friend_p_input(lpn_addr, friend_addr, lpn_counter,
	    friend_counter, p);
	rc = mesh_k2(netkey, p, sizeof(p), out_nid, out_enckey, out_privkey);
	explicit_bzero(p, sizeof(p));
	return (rc);
}

/* ================================================================
 * 2. Lower Transport Control friendship messages.  Section 3.6.5.
 * ================================================================ */

/* --- Friend Poll (0x01) --- */
int
mesh_friend_poll_build(const struct mesh_friend_poll *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->fsn > 1)
		return (-1);
	out[0] = MESH_FRIEND_OP_POLL;
	out[1] = (uint8_t)(in->fsn & 0x01);	/* Padding (7b, 0) | FSN (1b) */
	*outlen = MESH_FRIEND_POLL_LEN;
	return (0);
}

int
mesh_friend_poll_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_poll *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_FRIEND_POLL_LEN || in[0] != MESH_FRIEND_OP_POLL)
		return (-1);
	if ((in[1] & 0xfe) != 0)		/* Padding must be 0b0000000 */
		return (-1);
	out->fsn = (uint8_t)(in[1] & 0x01);
	return (0);
}

/* --- Friend Update (0x02) --- */
int
mesh_friend_update_build(const struct mesh_friend_update *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->key_refresh > 1 || in->iv_update > 1 || in->md > 1)
		return (-1);
	out[0] = MESH_FRIEND_OP_UPDATE;
	out[1] = (uint8_t)((in->key_refresh & 0x01) |
	    ((in->iv_update & 0x01) << 1));	/* Flags (Section 3.6.5.2) */
	out[2] = (uint8_t)(in->iv_index >> 24);
	out[3] = (uint8_t)(in->iv_index >> 16);
	out[4] = (uint8_t)(in->iv_index >> 8);
	out[5] = (uint8_t)in->iv_index;
	out[6] = (uint8_t)(in->md & 0x01);
	*outlen = MESH_FRIEND_UPDATE_LEN;
	return (0);
}

int
mesh_friend_update_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_update *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_FRIEND_UPDATE_LEN || in[0] != MESH_FRIEND_OP_UPDATE)
		return (-1);
	if (in[6] > 1)				/* MD 2..255 Prohibited */
		return (-1);
	out->key_refresh = (uint8_t)(in[1] & 0x01);
	out->iv_update = (uint8_t)((in[1] >> 1) & 0x01);
	out->iv_index = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16) |
	    ((uint32_t)in[4] << 8) | (uint32_t)in[5];
	out->md = in[6];
	return (0);
}

/* --- Criteria field helpers (Section 3.6.5.3) --- */
uint8_t
mesh_friend_criteria_pack(uint8_t rssi_factor, uint8_t rx_window_factor,
    uint8_t min_queue_size_log)
{

	/* bit7 RFU=0 | RSSIFactor[6:5] | ReceiveWindowFactor[4:3] | MinQSLog[2:0] */
	return ((uint8_t)(((rssi_factor & 0x03) << 5) |
	    ((rx_window_factor & 0x03) << 3) | (min_queue_size_log & 0x07)));
}

void
mesh_friend_criteria_unpack(uint8_t octet, uint8_t *rssi_factor,
    uint8_t *rx_window_factor, uint8_t *min_queue_size_log)
{

	if (rssi_factor != NULL)
		*rssi_factor = (uint8_t)((octet >> 5) & 0x03);
	if (rx_window_factor != NULL)
		*rx_window_factor = (uint8_t)((octet >> 3) & 0x03);
	if (min_queue_size_log != NULL)
		*min_queue_size_log = (uint8_t)(octet & 0x07);
}

uint16_t
mesh_friend_min_queue_size(uint8_t min_queue_size_log)
{

	if (min_queue_size_log == 0 || min_queue_size_log > 7)
		return (0);			/* 0b000 Prohibited (Table 3.36) */
	return ((uint16_t)(1u << min_queue_size_log));
}

uint8_t
mesh_friend_factor_x2(uint8_t enc)
{

	/* 0b00->2 (1.0), 0b01->3 (1.5), 0b10->4 (2.0), 0b11->5 (2.5). */
	return ((uint8_t)((enc & 0x03) + 2));
}

int
mesh_friend_offer_delay(uint8_t rssi_factor, uint8_t rx_window_factor,
    uint8_t recv_window, int8_t rssi)
{
	int rwf2, rssif2, local2, local;

	rwf2 = mesh_friend_factor_x2(rx_window_factor);
	rssif2 = mesh_friend_factor_x2(rssi_factor);
	/* 2 * Local Delay = rwf2*ReceiveWindow - rssif2*RSSI. */
	local2 = rwf2 * (int)recv_window - rssif2 * (int)rssi;
	local = local2 / 2;			/* Local Delay (ms) */
	return (local > 100 ? local : 100);
}

/* --- Friend Request (0x03) --- */
int
mesh_friend_request_build(const struct mesh_friend_request *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->rssi_factor > 3 || in->rx_window_factor > 3 ||
	    in->min_queue_size_log == 0 || in->min_queue_size_log > 7)
		return (-1);
	if (in->recv_delay < 0x0a ||
	    in->poll_timeout < MESH_LPN_POLLTIMEOUT_MIN ||
	    in->poll_timeout > MESH_LPN_POLLTIMEOUT_MAX ||
	    in->num_elements == 0 || in->prev_addr > 0x7fff)
		return (-1);
	out[0] = MESH_FRIEND_OP_REQUEST;
	out[1] = mesh_friend_criteria_pack(in->rssi_factor,
	    in->rx_window_factor, in->min_queue_size_log);
	out[2] = in->recv_delay;
	out[3] = (uint8_t)(in->poll_timeout >> 16);
	out[4] = (uint8_t)(in->poll_timeout >> 8);
	out[5] = (uint8_t)in->poll_timeout;
	put16(out + 6, in->prev_addr);
	out[8] = in->num_elements;
	put16(out + 9, in->lpn_counter);
	*outlen = MESH_FRIEND_REQUEST_LEN;
	return (0);
}

int
mesh_friend_request_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_request *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_FRIEND_REQUEST_LEN || in[0] != MESH_FRIEND_OP_REQUEST)
		return (-1);
	mesh_friend_criteria_unpack(in[1], &out->rssi_factor,
	    &out->rx_window_factor, &out->min_queue_size_log);
	if (out->min_queue_size_log == 0)	/* MinQueueSizeLog 0b000 Prohibited */
		return (-1);
	out->recv_delay = in[2];
	out->poll_timeout = ((uint32_t)in[3] << 16) | ((uint32_t)in[4] << 8) |
	    (uint32_t)in[5];
	if (out->recv_delay < 0x0a ||
	    out->poll_timeout < MESH_LPN_POLLTIMEOUT_MIN ||
	    out->poll_timeout > MESH_LPN_POLLTIMEOUT_MAX)
		return (-1);
	out->prev_addr = get16(in + 6);
	if (out->prev_addr > 0x7fff)
		return (-1);
	out->num_elements = in[8];
	if (out->num_elements == 0)		/* NumElements 0x00 Prohibited */
		return (-1);
	out->lpn_counter = get16(in + 9);
	return (0);
}

/* --- Friend Offer (0x04) --- */
int
mesh_friend_offer_build(const struct mesh_friend_offer *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->recv_window == 0)
		return (-1);
	out[0] = MESH_FRIEND_OP_OFFER;
	out[1] = in->recv_window;
	out[2] = in->queue_size;
	out[3] = in->sub_list_size;
	out[4] = (uint8_t)in->rssi;
	put16(out + 5, in->friend_counter);
	*outlen = MESH_FRIEND_OFFER_LEN;
	return (0);
}

int
mesh_friend_offer_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_offer *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_FRIEND_OFFER_LEN || in[0] != MESH_FRIEND_OP_OFFER)
		return (-1);
	if (in[1] == 0)
		return (-1);
	out->recv_window = in[1];
	out->queue_size = in[2];
	out->sub_list_size = in[3];
	out->rssi = (int8_t)in[4];
	out->friend_counter = get16(in + 5);
	return (0);
}

/* --- Friend Clear (0x05) / Friend Clear Confirm (0x06) --- */
int
mesh_friend_clear_build(uint8_t op, const struct mesh_friend_clear *in,
    uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (op != MESH_FRIEND_OP_CLEAR && op != MESH_FRIEND_OP_CLEAR_CONFIRM)
		return (-1);
	if (in->lpn_addr < 0x0001 || in->lpn_addr > 0x7fff)
		return (-1);
	out[0] = op;
	put16(out + 1, in->lpn_addr);
	put16(out + 3, in->lpn_counter);
	*outlen = MESH_FRIEND_CLEAR_LEN;
	return (0);
}

int
mesh_friend_clear_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_clear *out, uint8_t *op)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (op != NULL)
		*op = 0;
	if (inlen != MESH_FRIEND_CLEAR_LEN)
		return (-1);
	if (in[0] != MESH_FRIEND_OP_CLEAR && in[0] != MESH_FRIEND_OP_CLEAR_CONFIRM)
		return (-1);
	out->lpn_addr = get16(in + 1);
	if (out->lpn_addr < 0x0001 || out->lpn_addr > 0x7fff)
		return (-1);
	out->lpn_counter = get16(in + 3);
	if (op != NULL)
		*op = in[0];
	return (0);
}

/* --- Friend Subscription List Add (0x07) / Remove (0x08) --- */
int
mesh_friend_sublist_build(uint8_t op, const struct mesh_friend_sublist *in,
    uint8_t *out, size_t *outlen)
{
	size_t i;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (op != MESH_FRIEND_OP_SUBLIST_ADD && op != MESH_FRIEND_OP_SUBLIST_REMOVE)
		return (-1);
	if (in->naddr == 0 || in->naddr > MESH_FRIEND_SUBLIST_ADDR_MAX)
		return (-1);
	for (i = 0; i < in->naddr; i++)
		if (in->addrs[i] < 0x8000)
			return (-1);
	out[0] = op;
	out[1] = in->transaction;
	for (i = 0; i < in->naddr; i++)
		put16(out + 2 + 2 * i, in->addrs[i]);
	*outlen = 2 + 2 * in->naddr;
	return (0);
}

int
mesh_friend_sublist_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_sublist *out, uint8_t *op)
{
	size_t n, i;

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (op != NULL)
		*op = 0;
	if (inlen < 4)				/* op + transaction + >=1 address */
		return (-1);
	if (in[0] != MESH_FRIEND_OP_SUBLIST_ADD &&
	    in[0] != MESH_FRIEND_OP_SUBLIST_REMOVE)
		return (-1);
	if (((inlen - 2) % 2) != 0)		/* AddressList is 2*N octets */
		return (-1);
	n = (inlen - 2) / 2;
	if (n > MESH_FRIEND_SUBLIST_ADDR_MAX)
		return (-1);
	out->transaction = in[1];
	for (i = 0; i < n; i++) {
		out->addrs[i] = get16(in + 2 + 2 * i);
		if (out->addrs[i] < 0x8000) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
	}
	out->naddr = n;
	if (op != NULL)
		*op = in[0];
	return (0);
}

/* --- Friend Subscription List Confirm (0x09) --- */
int
mesh_friend_subconfirm_build(const struct mesh_friend_subconfirm *in,
    uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	out[0] = MESH_FRIEND_OP_SUBLIST_CONFIRM;
	out[1] = in->transaction;
	*outlen = MESH_FRIEND_SUBCONFIRM_LEN;
	return (0);
}

int
mesh_friend_subconfirm_parse(const uint8_t *in, size_t inlen,
    struct mesh_friend_subconfirm *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_FRIEND_SUBCONFIRM_LEN ||
	    in[0] != MESH_FRIEND_OP_SUBLIST_CONFIRM)
		return (-1);
	out->transaction = in[1];
	return (0);
}

/* ================================================================
 * 3. Friend Subscription List state.  Section 3.6.6.3.3.
 * ================================================================ */

void
mesh_friend_sub_init(struct mesh_friend_sublist_state *s)
{

	if (s != NULL)
		memset(s, 0, sizeof(*s));
}

int
mesh_friend_sub_contains(const struct mesh_friend_sublist_state *s,
    uint16_t addr)
{
	size_t i;

	if (s == NULL)
		return (0);
	for (i = 0; i < s->n; i++)
		if (s->addrs[i] == addr)
			return (1);
	return (0);
}

int
mesh_friend_sub_add(struct mesh_friend_sublist_state *s, uint16_t addr)
{

	if (s == NULL)
		return (-1);
	if (mesh_friend_sub_contains(s, addr))
		return (0);			/* already present */
	if (s->n >= MESH_FRIEND_SUBLIST_MAX)
		return (-1);			/* full */
	s->addrs[s->n++] = addr;
	return (1);
}

int
mesh_friend_sub_remove(struct mesh_friend_sublist_state *s, uint16_t addr)
{
	size_t i;

	if (s == NULL)
		return (0);
	for (i = 0; i < s->n; i++) {
		if (s->addrs[i] == addr) {
			/* Compact the tail down over the removed slot. */
			memmove(&s->addrs[i], &s->addrs[i + 1],
			    (s->n - i - 1) * sizeof(s->addrs[0]));
			s->n--;
			s->addrs[s->n] = 0;
			return (1);
		}
	}
	return (0);
}

/* ================================================================
 * 4. Friend Queue.  Section 3.5.5 / 3.6.6.4.
 * ================================================================ */

void
mesh_fq_init(struct mesh_friend_queue *q, uint16_t lpn_addr,
    uint8_t num_elements, size_t cap)
{

	if (q == NULL)
		return;
	memset(q, 0, sizeof(*q));
	q->lpn_addr = lpn_addr;
	q->num_elements = num_elements == 0 ? 1 : num_elements;
	if (cap == 0)
		cap = 1;
	if (cap > MESH_FQ_MAX)
		cap = MESH_FQ_MAX;
	q->cap = cap;
	q->last_fsn = -1;			/* no Poll answered yet */
}

size_t
mesh_fq_count(const struct mesh_friend_queue *q)
{
	size_t i, n = 0;

	if (q == NULL)
		return (0);
	for (i = 0; i < q->cap; i++)
		if (q->entries[i].valid)
			n++;
	return (n);
}

/* Is addr one of the LPN's own element unicast addresses? */
static int
fq_is_lpn_addr(const struct mesh_friend_queue *q, uint16_t addr)
{

	return (addr >= q->lpn_addr &&
	    (uint32_t)addr < (uint32_t)q->lpn_addr + q->num_elements);
}

/* Find a free slot index, or q->cap if none. */
static size_t
fq_free_slot(struct mesh_friend_queue *q)
{
	size_t i;

	for (i = 0; i < q->cap; i++)
		if (!q->entries[i].valid)
			return (i);
	return (q->cap);
}

/* Index of the oldest entry matching is_update==want_update, or q->cap. */
static size_t
fq_oldest(struct mesh_friend_queue *q, int want_update)
{
	size_t i, best = q->cap;

	for (i = 0; i < q->cap; i++) {
		if (!q->entries[i].valid)
			continue;
		if ((q->entries[i].is_update != 0) != (want_update != 0))
			continue;
		if (best == q->cap || q->entries[i].order < q->entries[best].order)
			best = i;
	}
	return (best);
}

/* Index of the oldest valid entry regardless of type, or q->cap. */
static size_t
fq_oldest_any(struct mesh_friend_queue *q)
{
	size_t i, best = q->cap;

	for (i = 0; i < q->cap; i++) {
		if (!q->entries[i].valid)
			continue;
		if (best == q->cap || q->entries[i].order < q->entries[best].order)
			best = i;
	}
	return (best);
}

/* Store *in into a free (possibly evicted) slot.  Returns 0 ok, -1 no room. */
static int
fq_store(struct mesh_friend_queue *q, const struct mesh_fq_entry *in,
    int is_update)
{
	size_t slot;
	struct mesh_fq_entry *e;

	slot = fq_free_slot(q);
	while (slot == q->cap) {
		/* Full: evict the oldest NON-Update entry (Section 3.5.5). */
		size_t victim = fq_oldest(q, 0);
		if (victim == q->cap)
			return (-1);		/* only Update entries; no room */
		q->entries[victim].valid = 0;
		slot = victim;
	}

	e = &q->entries[slot];
	memset(e, 0, sizeof(*e));
	e->ctl = in->ctl;
	e->ttl = in->ttl;
	e->seq = in->seq;
	e->src = in->src;
	e->dst = in->dst;
	if (in->pdu_len > MESH_FQ_PDU_MAX)
		return (-1);
	memcpy(e->pdu, in->pdu, in->pdu_len);
	e->pdu_len = in->pdu_len;
	e->is_update = is_update;
	e->valid = 1;
	e->order = q->order_ctr++;
	return (0);
}

int
mesh_fq_enqueue(struct mesh_friend_queue *q, const struct mesh_fq_entry *in)
{
	size_t i;

	if (q == NULL || in == NULL || in->pdu_len > MESH_FQ_PDU_MAX)
		return (-1);

	/* Destined for the LPN? unicast element OR in the subscription list. */
	if (!fq_is_lpn_addr(q, in->dst) &&
	    !mesh_friend_sub_contains(&q->sub, in->dst))
		return (0);			/* not for this LPN */

	/* TTL must be 2 or greater (Section 3.5.5). */
	if (in->ttl < 2)
		return (0);

	/* Do not queue the LPN's own outbound messages. */
	if (fq_is_lpn_addr(q, in->src))
		return (0);

	/* Dedup on (SEQ, SRC). */
	for (i = 0; i < q->cap; i++) {
		if (q->entries[i].valid && q->entries[i].seq == in->seq &&
		    q->entries[i].src == in->src)
			return (0);		/* already queued */
	}

	/* Store with TTL decremented by 1. */
	{
		struct mesh_fq_entry tmp = *in;
		tmp.ttl = (uint8_t)(in->ttl - 1);
		if (fq_store(q, &tmp, 0) != 0)
			return (-1);
	}
	return (1);
}

int
mesh_fq_enqueue_update(struct mesh_friend_queue *q,
    const struct mesh_fq_entry *in)
{

	if (q == NULL || in == NULL || in->pdu_len > MESH_FQ_PDU_MAX)
		return (-1);
	/* Friend Update bypasses the DST filter and is evict-protected. */
	if (fq_store(q, in, 1) != 0)
		return (-1);
	return (0);
}

int
mesh_fq_poll(struct mesh_friend_queue *q, int fsn,
    const struct mesh_fq_entry *empty_update, struct mesh_fq_entry *out)
{
	size_t head;

	if (q == NULL || out == NULL || (fsn != 0 && fsn != 1))
		return (-1);
	memset(out, 0, sizeof(*out));

	/*
	 * FSN handshake (Section 3.6.6.4.2).  A changed FSN acknowledges the
	 * previously delivered head, which is then discarded.  An unchanged
	 * FSN means the last response was lost -> resend the same head.
	 */
	if (q->last_fsn != -1 && fsn != q->last_fsn) {
		head = fq_oldest_any(q);
		if (head != q->cap)
			q->entries[head].valid = 0;	/* acked -> discard */
	}
	q->last_fsn = fsn;

	/* Empty queue: synthesize a Friend Update to answer the Poll. */
	if (mesh_fq_count(q) == 0) {
		if (empty_update == NULL)
			return (0);		/* nothing to send */
		if (mesh_fq_enqueue_update(q, empty_update) != 0)
			return (-1);
	}

	/* Deliver the oldest entry (Section 3.5.5: oldest, regardless of type). */
	head = fq_oldest_any(q);
	if (head == q->cap)
		return (0);
	*out = q->entries[head];
	return (1);
}

/* ================================================================
 * 5. Low Power node cadence.  Section 3.6.6.4.
 * ================================================================ */

int
mesh_lpn_init(struct mesh_lpn_state *st, uint32_t poll_timeout, uint64_t now)
{

	if (st == NULL)
		return (-1);
	memset(st, 0, sizeof(*st));
	if (poll_timeout < MESH_LPN_POLLTIMEOUT_MIN ||
	    poll_timeout > MESH_LPN_POLLTIMEOUT_MAX)
		return (-1);			/* Prohibited PollTimeout */
	st->poll_timeout = poll_timeout;
	st->last_poll_ms = now;
	st->fsn = 0;				/* FSN reset to 0 (Section 3.6.6.4.1) */
	st->established = 0;
	return (0);
}

void
mesh_lpn_established(struct mesh_lpn_state *st)
{

	if (st != NULL)
		st->established = 1;
}

uint64_t
mesh_lpn_poll_timeout_ms(const struct mesh_lpn_state *st)
{

	if (st == NULL)
		return (0);
	return ((uint64_t)st->poll_timeout * 100);
}

int
mesh_lpn_poll_fsn(const struct mesh_lpn_state *st)
{

	if (st == NULL)
		return (0);
	return (st->fsn & 0x01);
}

int
mesh_lpn_on_response(struct mesh_lpn_state *st, int is_duplicate, uint64_t now)
{

	if (st == NULL)
		return (0);
	if (!is_duplicate)
		st->fsn ^= 1;			/* toggle FSN (Section 3.6.6.4.2) */
	st->last_poll_ms = now;			/* contact -> reset PollTimeout */
	return (st->fsn & 0x01);
}

int
mesh_lpn_friendship_lost(const struct mesh_lpn_state *st, uint64_t now)
{
	uint64_t elapsed, timeout_ms;

	if (st == NULL)
		return (1);
	elapsed = now - st->last_poll_ms;
	/*
	 * Unsigned subtraction handles clock wrap.  An elapsed value in the
	 * upper half of the serial-number space instead represents a small
	 * backward clock adjustment and must not expire the friendship.
	 */
	if (elapsed > INT64_MAX)
		return (0);
	timeout_ms = (uint64_t)st->poll_timeout * 100;
	return (elapsed >= timeout_ms ? 1 : 0);
}

int
mesh_lpn_select_offer(const struct mesh_friend_offer *offers, size_t n,
    uint16_t min_queue_size)
{
	size_t i;
	int best = -1;

	if (offers == NULL || n == 0)
		return (-1);
	for (i = 0; i < n; i++) {
		const struct mesh_friend_offer *o = &offers[i];

		/* Must meet the requested minimum queue size. */
		if (o->queue_size < min_queue_size)
			continue;
		if (best < 0) {
			best = (int)i;
			continue;
		}
		{
			const struct mesh_friend_offer *b = &offers[best];

			/* Local policy tie-break chain (not spec-mandated). */
			if (o->queue_size != b->queue_size) {
				if (o->queue_size > b->queue_size)
					best = (int)i;
			} else if (o->sub_list_size != b->sub_list_size) {
				if (o->sub_list_size > b->sub_list_size)
					best = (int)i;
			} else if (o->rssi != b->rssi) {
				if (o->rssi > b->rssi)
					best = (int)i;
			} else if (o->recv_window < b->recv_window) {
				best = (int)i;
			}
		}
	}
	return (best);
}

/* ================================================================
 * 6. Friend role driven state machine.  MshPRT_v1.1 Section 3.6.5.
 * ================================================================ */

/* PollTimeout expressed in milliseconds (units of 100 ms). */
static uint64_t
friend_poll_timeout_ms(const struct mesh_friend_fsm *f)
{

	return ((uint64_t)f->poll_timeout * 100u);
}

/*
 * Fill an fq_entry with a freshly built Friend Update carrying the current
 * security flags, used as the empty-queue Poll response (Section 3.5.5).
 */
static int
friend_build_update_entry(const struct mesh_friend_fsm *f, uint8_t key_refresh,
    uint8_t iv_update, uint32_t iv_index, int more_data, struct mesh_fq_entry *e)
{
	struct mesh_friend_update up;
	uint8_t pdu[MESH_FRIEND_UPDATE_LEN];
	size_t plen;

	memset(&up, 0, sizeof(up));
	up.key_refresh = key_refresh ? 1 : 0;
	up.iv_update = iv_update ? 1 : 0;
	up.iv_index = iv_index;
	/*
	 * More Data reflects the queue state AFTER this Poll's FSN ack-discard
	 * and excludes the entry being returned; the caller computes it (see
	 * mesh_friend_fsm_recv_poll).  Computing it from the pre-discard queue
	 * count leaves the already-delivered head counted, so every empty-queue
	 * Update would carry MD=1 forever and livelock the LPN in an immediate
	 * re-poll loop (Section 3.6.6.4.2).
	 */
	up.md = more_data ? 1 : 0;
	if (mesh_friend_update_build(&up, pdu, &plen) != 0)
		return (-1);

	memset(e, 0, sizeof(*e));
	e->ctl = 1;
	e->ttl = 0;
	e->src = f->friend_addr;
	e->dst = f->lpn_addr;
	memcpy(e->pdu, pdu, plen);
	e->pdu_len = plen;
	e->is_update = 1;
	return (0);
}

void
mesh_friend_fsm_init(struct mesh_friend_fsm *f, uint16_t friend_addr,
    uint8_t recv_window, uint8_t queue_size, uint8_t sub_list_size,
    int8_t min_rssi, uint8_t max_queue_size_log)
{

	if (f == NULL)
		return;
	memset(f, 0, sizeof(*f));
	f->state = MESH_FRIEND_ST_IDLE;
	f->friend_addr = friend_addr;
	f->recv_window = recv_window;
	f->queue_size = queue_size;
	f->sub_list_size = sub_list_size;
	f->min_rssi = min_rssi;
	f->max_queue_size_log = max_queue_size_log;
}

int
mesh_friend_fsm_recv_request(struct mesh_friend_fsm *f, const uint8_t *pdu,
    size_t len, uint16_t lpn_addr, int8_t rssi, uint64_t now,
    struct mesh_friend_out *out)
{
	struct mesh_friend_request req;
	uint16_t min_qsz;
	int delay;

	if (f == NULL || pdu == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_FRIEND_ACT_NONE;

	if (mesh_friend_request_parse(pdu, len, &req) != 0)
		return (-1);
	/* SRC is the LPN primary unicast address; its element range must fit. */
	if (lpn_addr == 0 || lpn_addr > 0x7fff ||
	    (uint32_t)lpn_addr + req.num_elements > 0x8000)
		return (-1);

	/*
	 * While a friendship is established, ignore a Friend Request from a
	 * different LPN: it must not overwrite the live friendship and silently
	 * discard the queued messages (finding).  A Request from the same LPN
	 * re-arms a fresh Offer (Section 3.6.5).
	 */
	if (f->state == MESH_FRIEND_ST_ESTABLISHED && lpn_addr != f->lpn_addr)
		return (-1);

	/* Acceptance policy (Section 3.6.6.3): signal floor + serveable queue. */
	if (rssi < f->min_rssi)
		return (-1);
	if (req.min_queue_size_log > f->max_queue_size_log)
		return (-1);
	min_qsz = mesh_friend_min_queue_size(req.min_queue_size_log);
	if (min_qsz == 0 || min_qsz > f->queue_size)
		return (-1);

	/*
	 * Record the negotiated per-friendship parameters.  The LPN primary
	 * element unicast address is carried by the network layer (the message
	 * SRC), not the Friend Request control message, and was validated above.
	 */
	f->lpn_counter = req.lpn_counter;
	f->lpn_addr = lpn_addr;
	f->num_elements = req.num_elements;
	f->recv_delay = req.recv_delay;
	f->poll_timeout = req.poll_timeout;
	mesh_fq_init(&f->queue, lpn_addr, f->num_elements, f->queue_size);

	/* Compose the Offer we will emit after the delay. */
	memset(&f->offer, 0, sizeof(f->offer));
	f->offer.recv_window = f->recv_window;
	f->offer.queue_size = f->queue_size;
	f->offer.sub_list_size = f->sub_list_size;
	f->offer.rssi = rssi;
	f->offer.friend_counter = f->friend_counter;

	delay = mesh_friend_offer_delay(req.rssi_factor, req.rx_window_factor,
	    f->recv_window, rssi);
	if (delay < 0)
		return (-1);
	f->offer_start_ms = now;
	f->offer_delay_ms = (uint32_t)delay;
	f->offer_at_ms = now + (uint64_t)delay;
	f->state = MESH_FRIEND_ST_OFFERING;
	return (0);
}

/*
 * Bind the LPN primary-element unicast address (carried by the network layer,
 * not the Friend Request control message).  Must be called after an accepted
 * Request and before Polls arrive; re-inits the queue for that LPN.
 */
int
mesh_friend_fsm_bind_lpn(struct mesh_friend_fsm *f, uint16_t lpn_addr)
{

	if (f == NULL)
		return (-1);
	if (lpn_addr == 0 || lpn_addr > 0x7fff || f->num_elements == 0 ||
	    (uint32_t)lpn_addr + f->num_elements > 0x8000)
		return (-1);
	f->lpn_addr = lpn_addr;
	mesh_fq_init(&f->queue, lpn_addr, f->num_elements, f->queue_size);
	return (0);
}

int
mesh_friend_fsm_tick(struct mesh_friend_fsm *f, uint64_t now,
    struct mesh_friend_out *out)
{
	size_t olen;

	if (f == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_FRIEND_ACT_NONE;

	if (f->state == MESH_FRIEND_ST_OFFERING &&
	    now - f->offer_start_ms >= f->offer_delay_ms) {
		olen = 0;
		if (mesh_friend_offer_build(&f->offer, out->pdu, &olen) != 0)
			return (-1);
		out->pdu_len = olen;
		out->action = MESH_FRIEND_ACT_SEND_CONTROL;
		/* The value in this Offer is the current counter; increment only
		 * after the Offer has actually been emitted (Section 3.6.6.3.1). */
		f->friend_counter++;
		f->offer_sent_ms = now;
		f->state = MESH_FRIEND_ST_ESTABLISHING;
		return (0);
	}

	/*
	 * The friendship is established only if the first Friend Poll arrives
	 * within the establishment window of the Offer (Section 3.6.6.3.1).
	 * Expire ESTABLISHING back to IDLE so a Poll replayed far later cannot
	 * "establish" a friendship the LPN abandoned (finding).
	 */
	if (f->state == MESH_FRIEND_ST_ESTABLISHING &&
	    now - f->offer_sent_ms >= MESH_FRIEND_ESTABLISH_TIMEOUT_MS) {
		f->state = MESH_FRIEND_ST_IDLE;
		return (0);
	}

	if (f->state == MESH_FRIEND_ST_ESTABLISHED &&
	    now - f->last_poll_ms >= friend_poll_timeout_ms(f)) {
		out->action = MESH_FRIEND_ACT_TERMINATED;
		f->state = MESH_FRIEND_ST_IDLE;
		return (0);
	}
	return (0);
}

int
mesh_friend_fsm_recv_poll(struct mesh_friend_fsm *f, const uint8_t *pdu,
    size_t len, uint8_t key_refresh, uint8_t iv_update, uint32_t iv_index,
    uint64_t now, struct mesh_friend_out *out)
{
	struct mesh_friend_poll poll;
	struct mesh_fq_entry empty_update;
	size_t qcount, remaining;
	int rc, will_discard;

	if (f == NULL || pdu == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_FRIEND_ACT_NONE;

	if (f->state != MESH_FRIEND_ST_ESTABLISHING &&
	    f->state != MESH_FRIEND_ST_ESTABLISHED)
		return (-1);
	if (mesh_friend_poll_parse(pdu, len, &poll) != 0)
		return (-1);

	/*
	 * A first Poll that arrives more than the establishment window after the
	 * Offer does not establish the friendship (Section 3.6.6.3.1): the LPN
	 * has abandoned it.  Drop to IDLE and reject.
	 */
	if (f->state == MESH_FRIEND_ST_ESTABLISHING &&
	    now - f->offer_sent_ms >= MESH_FRIEND_ESTABLISH_TIMEOUT_MS) {
		f->state = MESH_FRIEND_ST_IDLE;
		return (-1);
	}

	/* The first Poll establishes the friendship (Section 3.6.6.4.1). */
	f->state = MESH_FRIEND_ST_ESTABLISHED;
	f->last_poll_ms = now;

	/*
	 * Compute More Data as the queue will look after this Poll's FSN
	 * ack-discard, excluding the entry returned as the response.  A changed
	 * FSN discards the previously delivered head (mirrors mesh_fq_poll), so
	 * the empty-queue Friend Update carries MD=0 once the last message has
	 * been acked instead of a stale MD=1 (Section 3.6.6.4.2, finding).
	 */
	qcount = mesh_fq_count(&f->queue);
	will_discard = (f->queue.last_fsn != -1 && poll.fsn != f->queue.last_fsn);
	remaining = (will_discard && qcount > 0) ? qcount - 1 : qcount;
	if (friend_build_update_entry(f, key_refresh, iv_update, iv_index,
	    remaining > 0 ? 1 : 0, &empty_update) != 0)
		return (-1);
	rc = mesh_fq_poll(&f->queue, poll.fsn, &empty_update, &out->msg);
	if (rc <= 0)
		return (rc);
	out->action = MESH_FRIEND_ACT_SEND_MSG;
	return (1);
}

int
mesh_friend_fsm_recv_sublist(struct mesh_friend_fsm *f, const uint8_t *pdu,
    size_t len, uint64_t now, struct mesh_friend_out *out)
{
	struct mesh_friend_sublist sl;
	struct mesh_friend_subconfirm cf;
	uint8_t op;
	size_t i, olen;

	if (f == NULL || pdu == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_FRIEND_ACT_NONE;

	if (f->state != MESH_FRIEND_ST_ESTABLISHED)
		return (-1);
	if (mesh_friend_sublist_parse(pdu, len, &sl, &op) != 0)
		return (-1);

	/* A Subscription List message is contact: reset PollTimeout supervision. */
	f->last_poll_ms = now;

	for (i = 0; i < sl.naddr; i++) {
		if (op == MESH_FRIEND_OP_SUBLIST_ADD)
			(void)mesh_friend_sub_add(&f->queue.sub, sl.addrs[i]);
		else
			(void)mesh_friend_sub_remove(&f->queue.sub, sl.addrs[i]);
	}

	memset(&cf, 0, sizeof(cf));
	cf.transaction = sl.transaction;
	olen = 0;
	if (mesh_friend_subconfirm_build(&cf, out->pdu, &olen) != 0)
		return (-1);
	out->pdu_len = olen;
	out->action = MESH_FRIEND_ACT_SEND_CONTROL;
	return (1);
}

int
mesh_friend_fsm_recv_clear(struct mesh_friend_fsm *f, const uint8_t *pdu,
    size_t len, struct mesh_friend_out *out)
{
	struct mesh_friend_clear clr;
	uint8_t op;
	size_t olen;

	if (f == NULL || pdu == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	out->action = MESH_FRIEND_ACT_NONE;

	if (mesh_friend_clear_parse(pdu, len, &clr, &op) != 0)
		return (-1);
	if (op != MESH_FRIEND_OP_CLEAR)
		return (-1);
	if (clr.lpn_addr != f->lpn_addr)
		return (0);

	/*
	 * Replay guard (Section 3.6.6.4, Friend Clear procedure).  Honour the
	 * Friend Clear only when its LPNCounter is at or ahead of the LPNCounter
	 * that established this friendship, within the 255-step acceptance window
	 * (a fresh Friend Request from the LPN advances the LPNCounter, so the
	 * new Friend's Clear carries a slightly higher value).  A stale or
	 * replayed Friend Clear (counter behind ours) must not tear down a live
	 * friendship.
	 */
	if ((uint16_t)(clr.lpn_counter - f->lpn_counter) > 255)
		return (0);

	/* Terminate and confirm (Section 3.6.5.5). */
	f->state = MESH_FRIEND_ST_IDLE;
	olen = 0;
	if (mesh_friend_clear_build(MESH_FRIEND_OP_CLEAR_CONFIRM, &clr, out->pdu,
	    &olen) != 0)
		return (-1);
	out->pdu_len = olen;
	out->action = MESH_FRIEND_ACT_SEND_CONTROL;
	return (1);
}

int
mesh_friend_fsm_enqueue(struct mesh_friend_fsm *f, const struct mesh_fq_entry *in)
{

	if (f == NULL || in == NULL)
		return (-1);
	/*
	 * Queue LPN-addressed messages as soon as the friendship is forming
	 * (OFFERING / ESTABLISHING), not only once ESTABLISHED, so a message
	 * that arrives during establishment is delivered on the first Poll
	 * rather than dropped (Section 3.6.6.4.1).  The Friend Queue is
	 * initialised when the Friend Request is accepted (OFFERING).
	 */
	if (f->state == MESH_FRIEND_ST_IDLE)
		return (0);
	return (mesh_fq_enqueue(&f->queue, in));
}

int
mesh_friend_fsm_established(const struct mesh_friend_fsm *f)
{

	return (f != NULL && f->state == MESH_FRIEND_ST_ESTABLISHED);
}
