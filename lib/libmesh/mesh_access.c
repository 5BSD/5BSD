/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh access layer (MshPRT_v1.1 Section 3.7): the cleartext
 * Access PDU codec (opcode + parameters) and a small model-dispatch
 * registry.  See mesh_access.h for the opcode-length rules and the
 * canonical numeric opcode representation.
 *
 * No crypto here: the Access PDU produced by mesh_access_pdu_build() is the
 * plaintext "Access Payload" that mesh_upper_encrypt() (Section 3.6) then
 * AES-CCM encrypts.  All multi-octet SIG opcodes are big-endian on the wire;
 * a 3-octet vendor opcode carries its Company Identifier little-endian.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "mesh_access.h"
#include "mesh_crypto.h"
#include "mesh_probes.h"

/* ================================================================
 * Address classification + virtual-address derivation (Section 3.4.2).
 * ================================================================ */

int
mesh_addr_is_unicast(uint16_t a)
{

	return (a >= 0x0001 && a <= 0x7fff);
}

int
mesh_addr_is_virtual(uint16_t a)
{

	return (a >= 0x8000 && a <= 0xbfff);
}

int
mesh_addr_is_group(uint16_t a)
{

	return (a >= 0xc000 && a <= 0xffff);
}

int
mesh_virtual_addr(const uint8_t label[MESH_LABEL_UUID_LEN], uint16_t *va)
{
	static const uint8_t vtad[4] = { 'v', 't', 'a', 'd' };
	uint8_t salt[16], hash[16];
	uint16_t h;

	if (va != NULL)
		*va = 0;
	if (label == NULL || va == NULL)
		return (-1);
	/* salt = s1("vtad"); hash = AES-CMAC(salt, Label UUID). */
	if (mesh_s1(vtad, sizeof(vtad), salt) != 0)
		return (-1);
	if (mesh_aes_cmac(salt, label, MESH_LABEL_UUID_LEN, hash) != 0)
		return (-1);
	/* Low 14 bits of the last two hash octets, tagged 10 => 0x8000. */
	h = (uint16_t)(((uint16_t)hash[14] << 8) | hash[15]);
	*va = (uint16_t)(0x8000u | (h & 0x3fffu));
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(hash, sizeof(hash));
	return (0);
}

/* ================================================================
 * Network message cache (Section 3.4.6.5): relay-loop dedup by (SRC, SEQ).
 * ================================================================ */

void
mesh_msg_cache_init(struct mesh_msg_cache *c)
{

	if (c != NULL)
		memset(c, 0, sizeof(*c));
}

int
mesh_msg_cache_check(struct mesh_msg_cache *c, uint16_t src, uint32_t seq)
{
	size_t i;

	if (c == NULL)
		return (0);
	for (i = 0; i < MESH_MSG_CACHE_SIZE; i++) {
		if (c->slots[i].valid && c->slots[i].src == src &&
		    c->slots[i].seq == seq)
			return (1);		/* already seen: a duplicate */
	}
	c->slots[c->next].valid = 1;
	c->slots[c->next].src = src;
	c->slots[c->next].seq = seq;
	c->next = (c->next + 1) % MESH_MSG_CACHE_SIZE;
	return (0);
}

/* ================================================================
 * Opcode length + vendor helpers (Section 3.7.3.1).
 * ================================================================ */

int
mesh_access_opcode_len(uint32_t opcode)
{

	if (opcode <= 0x7e)			/* 0x00..0x7E one-octet */
		return (1);
	if (opcode == 0x7f)			/* reserved for future use */
		return (-1);
	if (opcode >= 0x8000 && opcode <= 0xbfff)
		return (2);			/* 10xxxxxx xxxxxxxx */
	if (opcode >= 0xc00000 && opcode <= 0xffffff)
		return (3);			/* 11xxxxxx + 16-bit CID */
	return (-1);				/* gap / out of range */
}

uint32_t
mesh_access_vendor_opcode(uint8_t op6, uint16_t company_id)
{

	/* 11xxxxxx first octet; low 16 bits carry the Company Identifier. */
	return (((uint32_t)(0xc0 | (op6 & 0x3f)) << 16) | company_id);
}

uint16_t
mesh_access_opcode_company(uint32_t opcode)
{

	if (mesh_access_opcode_len(opcode) != 3)
		return (0);
	return ((uint16_t)(opcode & 0xffff));
}

/* ================================================================
 * Access PDU codec (Section 3.7.3).
 * ================================================================ */

int
mesh_access_pdu_build(uint32_t opcode, const uint8_t *params, size_t params_len,
    uint8_t *out, size_t *outlen)
{
	int oplen;

	if (out == NULL || outlen == NULL)
		return (-1);
	if (params == NULL && params_len != 0)
		return (-1);
	oplen = mesh_access_opcode_len(opcode);
	if (oplen < 0)
		return (-1);
	if (params_len > MESH_ACCESS_PAYLOAD_MAX - (size_t)oplen)
		return (-1);

	switch (oplen) {
	case 1:
		out[0] = (uint8_t)opcode;
		break;
	case 2:
		out[0] = (uint8_t)(opcode >> 8);
		out[1] = (uint8_t)opcode;
		break;
	case 3:
	default:
		out[0] = (uint8_t)(opcode >> 16);	/* 11xxxxxx */
		out[1] = (uint8_t)(opcode);		/* CID low  (LE) */
		out[2] = (uint8_t)(opcode >> 8);	/* CID high (LE) */
		break;
	}
	if (params_len != 0)
		memcpy(out + oplen, params, params_len);
	*outlen = (size_t)oplen + params_len;
	return (0);
}

int
mesh_access_pdu_parse(const uint8_t *in, size_t inlen, struct mesh_access_pdu *out)
{
	uint8_t b0;
	size_t oplen;

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen == 0)
		return (-1);

	b0 = in[0];
	if ((b0 & 0x80) == 0x00) {
		/* 0xxxxxxx one-octet; 0x7F is reserved for future use. */
		if (b0 == 0x7f)
			goto fail;
		out->opcode = b0;
		oplen = 1;
	} else if ((b0 & 0xc0) == 0x80) {
		/* 10xxxxxx two-octet. */
		if (inlen < 2)
			goto fail;
		out->opcode = ((uint32_t)b0 << 8) | in[1];
		oplen = 2;
	} else {
		/* 11xxxxxx three-octet vendor; Company ID little-endian. */
		if (inlen < 3)
			goto fail;
		out->company_id = (uint16_t)(in[1] | ((uint16_t)in[2] << 8));
		out->opcode = ((uint32_t)b0 << 16) | out->company_id;
		out->vendor = 1;
		oplen = 3;
	}

	out->opcode_len = (uint8_t)oplen;
	out->params_len = inlen - oplen;
	if (out->params_len > MESH_ACCESS_PARAMS_MAX)
		goto fail;
	if (out->params_len != 0)
		memcpy(out->params, in + oplen, out->params_len);
	MESH_PROBE_ACCESS_PARSE(out->opcode, (int)out->params_len);
	return (0);

fail:
	memset(out, 0, sizeof(*out));
	return (-1);
}

/* ================================================================
 * Model message dispatch (Section 3.7).
 * ================================================================ */

const struct mesh_opcode_entry *
mesh_model_find_op(const struct mesh_model *m, uint32_t opcode)
{
	size_t i;

	if (m == NULL || m->ops == NULL)
		return (NULL);
	for (i = 0; i < m->n_ops; i++) {
		if (m->ops[i].opcode == opcode && m->ops[i].handler != NULL)
			return (&m->ops[i]);
	}
	return (NULL);
}

static int
mesh_model_accepts_app_opcode(const struct mesh_model *m, uint32_t opcode)
{
	size_t i;

	if (m == NULL)
		return (0);
	for (i = 0; i < m->n_app_opcodes; i++)
		if (m->app_opcodes[i] == opcode)
			return (1);
	return (0);
}

static int
mesh_model_multicast_addressed(const struct mesh_model *m, uint16_t dst)
{
	size_t i;
	int is_va;

	if (!m->subscriptions_configured || dst == MESH_ADDR_ALL_NODES)
		return (1);
	for (i = 0; i < m->n_subs; i++) {
		is_va = m->sub_is_va != NULL && m->sub_is_va[i];
		if (mesh_addr_is_group(dst) && !is_va && m->subs != NULL &&
		    m->subs[i] == dst)
			return (1);
		if (mesh_addr_is_virtual(dst) && is_va && m->labels != NULL) {
			uint16_t va;

			if (mesh_virtual_addr(m->labels[i], &va) == 0 && va == dst)
				return (1);
		}
	}
	return (0);
}

int
mesh_access_elem_addressed(const struct mesh_element *el, uint16_t dst)
{
	size_t i;

	if (el == NULL)
		return (0);
	if (mesh_addr_is_unicast(dst))
		return (el->addr == dst);
	if (dst == MESH_ADDR_ALL_NODES)
		return (1);		/* fixed all-nodes group */
	if (mesh_addr_is_group(dst)) {
		for (i = 0; i < el->n_subs; i++) {
			if (el->subs != NULL && el->subs[i] == dst)
				return (1);
		}
		return (0);
	}
	if (mesh_addr_is_virtual(dst)) {
		for (i = 0; i < el->n_labels; i++) {
			uint16_t va;

			if (el->labels == NULL)
				break;
			if (mesh_virtual_addr(el->labels[i], &va) == 0 &&
			    va == dst)
				return (1);
		}
		return (0);
	}
	return (0);			/* unassigned or otherwise unresolved */
}

int
mesh_access_dispatch_key_at(const struct mesh_element *elems, size_t n_elems,
    uint16_t src, uint16_t dst, uint16_t app_idx, const uint8_t *pdu,
    size_t pdu_len, void *ctx, uint64_t now_ms)
{
	struct mesh_access_pdu ap;
	struct mesh_access_rx rx;
	size_t ei, mi;
	int ran = 0, rc = -1;

	if (elems == NULL || pdu == NULL)
		return (-1);
	if (mesh_access_pdu_parse(pdu, pdu_len, &ap) != 0)
		return (-1);

	/* Model dispatch: opcode routed for src -> dst. */
	MESH_PROBE_ACCESS_DISPATCH(ap.opcode, src, dst);

	/*
	 * Multicast fan-out (MshPRT_v1.1 Section 3.4.2): a unicast destination
	 * resolves to a single element, but a group, virtual or all-nodes
	 * destination is delivered to EVERY subscribed model on EVERY addressed
	 * element, not just the first match.  The loop therefore invokes each
	 * matching handler and never returns early; the reported result is the
	 * last handler's return value, or -1 when no model handled the opcode.
	 */
	for (ei = 0; ei < n_elems; ei++) {
		const struct mesh_element *el = &elems[ei];

		/*
		 * Destination resolution (Sections 3.4.2 / 3.7): unicast to the
		 * element address, group via the subscription list, virtual via
		 * a Label UUID that hashes to dst, or the all-nodes group.
		 */
		if (!mesh_access_elem_addressed(el, dst))
			continue;
		for (mi = 0; mi < el->n_models; mi++) {
			const struct mesh_model *m = &el->models[mi];
			const struct mesh_opcode_entry *op;

			op = mesh_model_find_op(m, ap.opcode);
			if (op == NULL && !mesh_model_accepts_app_opcode(m,
			    ap.opcode))
				continue;
			if (!mesh_addr_is_unicast(dst) &&
			    !mesh_model_multicast_addressed(m, dst))
				continue;
			if (app_idx != UINT16_MAX && m->bindings_configured) {
				size_t ai;

				for (ai = 0; ai < m->n_app; ai++)
					if (m->app_idx[ai] == app_idx)
						break;
				if (ai == m->n_app)
					continue;
			}
			memset(&rx, 0, sizeof(rx));
			rx.src = src;
			rx.dst = dst;
			rx.elem_addr = el->addr;
			rx.pdu = &ap;
			rx.model_user = m->user;
				rx.ctx = ctx;
				rx.now_ms = now_ms;
			if (op != NULL)
				rc = op->handler(&rx);
			else
				rc = 0;
			ran = 1;
		}
	}
	return (ran ? rc : -1);	/* -1: no model on any addressed element handled it */
}

int
mesh_access_dispatch_at(const struct mesh_element *elems, size_t n_elems,
    uint16_t src, uint16_t dst, const uint8_t *pdu, size_t pdu_len, void *ctx,
    uint64_t now_ms)
{

	return (mesh_access_dispatch_key_at(elems, n_elems, src, dst, UINT16_MAX,
	    pdu, pdu_len, ctx, now_ms));
}

uint64_t
mesh_access_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int
mesh_transition_time_valid(uint8_t transition_time)
{
	return ((transition_time & 0x3f) != 0x3f);
}

uint64_t
mesh_transition_time_ms(uint8_t transition_time)
{
	static const uint32_t unit_ms[] = { 100, 1000, 10000, 600000 };

	if (!mesh_transition_time_valid(transition_time))
		return (0);
	return ((uint64_t)(transition_time & 0x3f) *
	    unit_ms[transition_time >> 6]);
}

uint8_t
mesh_transition_remaining(uint64_t remaining_ms)
{
	static const uint32_t unit_ms[] = { 100, 1000, 10000, 600000 };
	unsigned resolution;
	uint64_t steps;

	if (remaining_ms == 0)
		return (0);
	for (resolution = 0; resolution < 4; resolution++) {
		steps = (remaining_ms + unit_ms[resolution] - 1) /
		    unit_ms[resolution];
		if (steps <= 62)
			return ((uint8_t)(resolution << 6) | (uint8_t)steps);
	}
	return (0x3f);
}

void
mesh_transition_start(struct mesh_transition_state *state, int32_t initial,
    int32_t target, uint8_t transition_time, uint8_t delay, uint64_t now_ms)
{
	mesh_transition_start_ms(state, initial, target,
	    mesh_transition_time_ms(transition_time), delay, now_ms);
}

void
mesh_transition_start_ms(struct mesh_transition_state *state, int32_t initial,
    int32_t target, uint64_t duration_ms, uint8_t delay, uint64_t now_ms)
{
	if (state == NULL)
		return;
	state->initial = initial;
	state->target = target;
	state->start_ms = now_ms + (uint64_t)delay * 5;
	state->end_ms = state->start_ms + duration_ms;
	state->active = state->start_ms > now_ms || duration_ms != 0;
}

int32_t
mesh_transition_sample(struct mesh_transition_state *state, uint64_t now_ms)
{
	int64_t delta, elapsed, duration;

	if (state == NULL || !state->active)
		return (state == NULL ? 0 : state->target);
	if (now_ms < state->start_ms)
		return (state->initial);
	if (now_ms >= state->end_ms) {
		state->active = 0;
		return (state->target);
	}
	duration = (int64_t)(state->end_ms - state->start_ms);
	elapsed = (int64_t)(now_ms - state->start_ms);
	delta = (int64_t)state->target - state->initial;
	return ((int32_t)(state->initial + delta * elapsed / duration));
}

uint16_t
mesh_transition_sample_u16_circular(struct mesh_transition_state *state,
    uint64_t now_ms)
{
	int64_t delta, elapsed, duration, value;

	if (state == NULL || !state->active)
		return ((uint16_t)(state == NULL ? 0 : state->target));
	if (now_ms < state->start_ms)
		return ((uint16_t)state->initial);
	if (now_ms >= state->end_ms) {
		state->active = 0;
		return ((uint16_t)state->target);
	}
	delta = (int64_t)(uint16_t)state->target -
	    (int64_t)(uint16_t)state->initial;
	if (delta > 32768)
		delta -= 65536;
	else if (delta < -32768)
		delta += 65536;
	duration = (int64_t)(state->end_ms - state->start_ms);
	elapsed = (int64_t)(now_ms - state->start_ms);
	value = (int64_t)(uint16_t)state->initial + delta * elapsed / duration;
	return ((uint16_t)value);
}

uint8_t
mesh_transition_sample_binary(struct mesh_transition_state *state,
    uint64_t now_ms)
{
	if (state == NULL)
		return (0);
	if (!state->active)
		return ((uint8_t)state->target);
	if (now_ms < state->start_ms)
		return ((uint8_t)state->initial);
	if (now_ms >= state->end_ms) {
		state->active = 0;
		return ((uint8_t)state->target);
	}
	return (state->target != 0 ? 1 : (uint8_t)state->initial);
}

int
mesh_access_dispatch(const struct mesh_element *elems, size_t n_elems,
    uint16_t src, uint16_t dst, const uint8_t *pdu, size_t pdu_len, void *ctx)
{
	uint64_t now_ms = mesh_access_now_ms();

	return (mesh_access_dispatch_at(elems, n_elems, src, dst, pdu, pdu_len,
	    ctx, now_ms));
}

void
mesh_access_tick(const struct mesh_element *elems, size_t n_elems,
    uint64_t now_ms)
{
	size_t ei, mi;

	if (elems == NULL)
		return;
	for (ei = 0; ei < n_elems; ei++)
		for (mi = 0; mi < elems[ei].n_models; mi++)
			if (elems[ei].models[mi].tick != NULL)
				elems[ei].models[mi].tick(
				    elems[ei].models[mi].user, now_ms);
}
