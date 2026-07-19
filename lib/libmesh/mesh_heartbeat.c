/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Heartbeat (Mesh Protocol 1.1 Sections 3.6.7,
 * 4.2.18-4.2.19, and 4.3.2.61-4.3.2.66).  See mesh_heartbeat.h for the wire
 * layouts and the CountLog/PeriodLog log128 transform.
 *
 * The transport control message (Opcode 0x0A) is big-endian; the
 * Configuration model Heartbeat Publication/Subscription messages are
 * little-endian per the model convention and are wrapped with the access
 * opcode via mesh_access_pdu_build()/mesh_access_pdu_parse().
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_model.h"
#include "mesh_heartbeat.h"

/* Little-endian 16-bit helpers (model-message convention). */
static void
put16le(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
get16le(const uint8_t *p)
{

	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

/* ================================================================
 * CountLog / PeriodLog (Sections 4.2.18.2-.3 and 4.2.19.3-.4).
 * ================================================================ */

uint8_t
mesh_hb_count_log(uint16_t count)
{
	uint8_t n;

	if (count == 0)
		return (0x00);
	if (count == 0xffff)
		return (0xff);
	/* Smallest n in 1..0x10 with 2^(n-1) >= count. */
	for (n = 1; n <= 0x10; n++) {
		if (((uint32_t)1 << (n - 1)) >= count)
			return (n);
	}
	return (0x11);
}

int
mesh_hb_period_log_valid(uint8_t plog)
{

	return (plog <= 0x11);
}

uint32_t
mesh_hb_period_log_decode(uint8_t plog)
{

	if (plog == 0x00)
		return (0);
	if (plog > 0x11)
		return (0);
	return ((uint32_t)1 << (plog - 1));	/* 2^(PeriodLog-1) seconds */
}

/* ================================================================
 * Transport control message (Section 3.6.7.1).
 * ================================================================ */

int
mesh_hb_msg_build(const struct mesh_hb_msg *in, uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->init_ttl > 0x7f ||
	    (in->features & ~MESH_HB_FEATURE_MASK) != 0)
		return (-1);
	out[0] = (uint8_t)(in->init_ttl & 0x7f);
	out[1] = (uint8_t)(in->features >> 8);	/* Features big-endian */
	out[2] = (uint8_t)(in->features & 0xff);
	*outlen = 3;
	return (0);
}

int
mesh_hb_msg_parse(const uint8_t *in, size_t inlen, struct mesh_hb_msg *out)
{

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || inlen != 3)
		return (-1);
	out->init_ttl = (uint8_t)(in[0] & 0x7f);
	out->features = (uint16_t)((((uint16_t)in[1] << 8) | in[2]) &
	    MESH_HB_FEATURE_MASK);
	return (0);
}

int
mesh_hb_ctl_pdu_build(const struct mesh_hb_msg *in, uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->init_ttl > 0x7f ||
	    (in->features & ~MESH_HB_FEATURE_MASK) != 0)
		return (-1);
	/* SEG=0, CTL Opcode 0x0A. */
	out[0] = (uint8_t)(MESH_HB_CTL_OPCODE & 0x7f);
	out[1] = (uint8_t)(in->init_ttl & 0x7f);
	out[2] = (uint8_t)(in->features >> 8);
	out[3] = (uint8_t)(in->features & 0xff);
	*outlen = 4;
	return (0);
}

int
mesh_hb_ctl_pdu_parse(const uint8_t *in, size_t inlen, struct mesh_hb_msg *out)
{

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || inlen != 4)
		return (-1);
	if (in[0] != (uint8_t)(MESH_HB_CTL_OPCODE & 0x7f))	/* SEG=0, 0x0A */
		return (-1);
	return (mesh_hb_msg_parse(in + 1, inlen - 1, out));
}

/* ================================================================
 * Heartbeat Publication messages (Sections 4.3.2.61-.63).
 * ================================================================ */

int
mesh_hb_pub_get_build(uint8_t *out, size_t *outlen)
{

	return (mesh_access_pdu_build(MESH_CFG_OP_HB_PUB_GET, NULL, 0, out,
	    outlen));
}

/* Pack the 9-octet publication body (no Status). */
static int
hb_pub_pack(const struct mesh_hb_pub *in, uint8_t *p)
{

	if (in->net_idx > 0x0fff || in->ttl > 0x7f ||
	    (in->features & ~MESH_HB_FEATURE_MASK) != 0)
		return (-1);
	if (!mesh_hb_period_log_valid(in->period_log))
		return (-1);
	if (in->count_log > 0x11 && in->count_log != 0xff)
		return (-1);
	put16le(p + 0, in->dst);
	p[2] = in->count_log;
	p[3] = in->period_log;
	p[4] = in->ttl;
	put16le(p + 5, in->features);
	mesh_cfg_keyidx_pack1(p + 7, in->net_idx);
	return (0);
}

static void
hb_pub_unpack(const uint8_t *p, struct mesh_hb_pub *out)
{

	out->dst = get16le(p + 0);
	out->count_log = p[2];
	out->period_log = p[3];
	out->ttl = p[4];
	out->features = (uint16_t)(get16le(p + 5) & MESH_HB_FEATURE_MASK);
	out->net_idx = mesh_cfg_keyidx_unpack1(p + 7);
}

int
mesh_hb_pub_set_build(const struct mesh_hb_pub *in, uint8_t *out, size_t *outlen)
{
	uint8_t params[9];

	if (in == NULL)
		return (-1);
	/* Mesh Protocol 1.1 Section 4.2.18.1: virtual is prohibited. */
	if (in->dst != MESH_ADDR_UNASSIGNED &&
	    !mesh_addr_is_unicast(in->dst) && !mesh_addr_is_group(in->dst))
		return (-1);
	if (hb_pub_pack(in, params) != 0)
		return (-1);
	return (mesh_access_pdu_build(MESH_CFG_OP_HB_PUB_SET, params,
	    sizeof(params), out, outlen));
}

int
mesh_hb_pub_set_parse(const uint8_t *in, size_t inlen, struct mesh_hb_pub *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_HB_PUB_SET || ap.params_len != 9)
		return (-1);
	hb_pub_unpack(ap.params, out);
	return (0);
}

int
mesh_hb_pub_status_build(uint8_t status, const struct mesh_hb_pub *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 9];

	if (in == NULL)
		return (-1);
	params[0] = status;
	if (hb_pub_pack(in, params + 1) != 0)
		return (-1);
	return (mesh_access_pdu_build(MESH_CFG_OP_HB_PUB_STATUS, params,
	    sizeof(params), out, outlen));
}

int
mesh_hb_pub_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    struct mesh_hb_pub *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_HB_PUB_STATUS || ap.params_len != 10)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	hb_pub_unpack(ap.params + 1, out);
	return (0);
}

int
mesh_hb_pub_feature_change(const struct mesh_hb_pub *pub, uint16_t old_features,
    uint16_t new_features, struct mesh_hb_msg *msg)
{
	uint16_t changed;

	if (pub == NULL || msg == NULL)
		return (-1);
	memset(msg, 0, sizeof(*msg));
	if (pub->dst == MESH_ADDR_UNASSIGNED)
		return (0);			/* publication disabled */
	changed = (uint16_t)((old_features ^ new_features) &
	    MESH_HB_FEATURE_MASK);
	if ((changed & pub->features) == 0)
		return (0);			/* no triggering feature changed */
	msg->init_ttl = (uint8_t)(pub->ttl & 0x7f);
	msg->features = (uint16_t)(new_features & MESH_HB_FEATURE_MASK);
	return (1);
}

/* ================================================================
 * Periodic Heartbeat publication emitter (Section 4.2.18).
 * ================================================================ */

/* Decode a CountLog to the number of publications it represents. */
static uint32_t
hb_count_log_decode(uint8_t clog)
{

	if (clog == 0x00)
		return (0);
	if (clog >= 0x11)			/* 0x11 caps at 0xFFFF */
		return (0xffff);
	return ((uint32_t)1 << (clog - 1));	/* 2^(CountLog-1) */
}

void
mesh_hb_pub_timer_init(struct mesh_hb_pub_timer *t, const struct mesh_hb_pub *pub)
{

	if (t == NULL)
		return;
	memset(t, 0, sizeof(*t));
	if (pub == NULL)
		return;
	t->dst = pub->dst;
	t->ttl = (uint8_t)(pub->ttl & 0x7f);
	t->net_idx = pub->net_idx;
	t->period = mesh_hb_period_log_decode(pub->period_log);
	t->indefinite = (pub->count_log == 0xff) ? 1 : 0;
	t->remaining = t->indefinite ? 0 : hb_count_log_decode(pub->count_log);
	/* Section 3.6.7.2: the first periodic Heartbeat is due immediately. */
	t->elapsed = t->period;
}

int
mesh_hb_pub_timer_active(const struct mesh_hb_pub_timer *t)
{

	if (t == NULL)
		return (0);
	if (t->dst == MESH_ADDR_UNASSIGNED || t->period == 0)
		return (0);
	return (t->indefinite || t->remaining > 0);
}

int
mesh_hb_pub_timer_tick(struct mesh_hb_pub_timer *t, uint32_t secs,
    uint16_t features, struct mesh_hb_msg *out)
{

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (!mesh_hb_pub_timer_active(t) || out == NULL)
		return (0);
	t->elapsed += secs;
	if (t->elapsed < t->period)
		return (0);			/* period not yet elapsed */
	t->elapsed -= t->period;
	out->init_ttl = t->ttl;
	out->features = (uint16_t)(features & MESH_HB_FEATURE_MASK);
	if (!t->indefinite && t->remaining > 0)
		t->remaining--;			/* one publication consumed */
	return (1);
}

uint8_t
mesh_hb_pub_timer_count_log(const struct mesh_hb_pub_timer *t)
{

	if (t == NULL)
		return (0x00);
	if (t->indefinite)
		return (0xff);
	return (mesh_hb_count_log((uint16_t)t->remaining));
}

/* ================================================================
 * Heartbeat Subscription messages (Sections 4.3.2.64-.66).
 * ================================================================ */

int
mesh_hb_sub_get_build(uint8_t *out, size_t *outlen)
{

	return (mesh_access_pdu_build(MESH_CFG_OP_HB_SUB_GET, NULL, 0, out,
	    outlen));
}

int
mesh_hb_sub_set_build(const struct mesh_hb_sub_set *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[5];

	if (in == NULL)
		return (-1);
	if (!mesh_hb_period_log_valid(in->period_log))
		return (-1);
	/* Sections 4.2.19.1-.2: Source is unicast; Destination unicast/group. */
	if (in->src != MESH_ADDR_UNASSIGNED && !mesh_addr_is_unicast(in->src))
		return (-1);
	if (in->dst != MESH_ADDR_UNASSIGNED &&
	    !mesh_addr_is_unicast(in->dst) && !mesh_addr_is_group(in->dst))
		return (-1);
	put16le(params + 0, in->src);
	put16le(params + 2, in->dst);
	params[4] = in->period_log;
	return (mesh_access_pdu_build(MESH_CFG_OP_HB_SUB_SET, params,
	    sizeof(params), out, outlen));
}

int
mesh_hb_sub_set_parse(const uint8_t *in, size_t inlen, struct mesh_hb_sub_set *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_HB_SUB_SET || ap.params_len != 5)
		return (-1);
	out->src = get16le(ap.params + 0);
	out->dst = get16le(ap.params + 2);
	out->period_log = ap.params[4];
	return (0);
}

int
mesh_hb_sub_status_build(const struct mesh_hb_sub_status *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[9];

	if (in == NULL)
		return (-1);
	params[0] = in->status;
	put16le(params + 1, in->src);
	put16le(params + 3, in->dst);
	params[5] = in->period_log;
	params[6] = in->count_log;
	params[7] = in->min_hops;
	params[8] = in->max_hops;
	return (mesh_access_pdu_build(MESH_CFG_OP_HB_SUB_STATUS, params,
	    sizeof(params), out, outlen));
}

int
mesh_hb_sub_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_hb_sub_status *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_HB_SUB_STATUS || ap.params_len != 9)
		return (-1);
	out->status = ap.params[0];
	out->src = get16le(ap.params + 1);
	out->dst = get16le(ap.params + 3);
	out->period_log = ap.params[5];
	out->count_log = ap.params[6];
	out->min_hops = ap.params[7];
	out->max_hops = ap.params[8];
	return (0);
}

/* ================================================================
 * Subscription receive state machine.
 * ================================================================ */

void
mesh_hb_sub_init(struct mesh_hb_sub *s)
{

	if (s == NULL)
		return;
	memset(s, 0, sizeof(*s));
	s->min_hops = 0x7f;
	s->max_hops = 0x00;
}

int
mesh_hb_sub_apply(struct mesh_hb_sub *s, const struct mesh_hb_sub_set *in)
{

	if (s == NULL || in == NULL)
		return (-1);
	if (!mesh_hb_period_log_valid(in->period_log))
		return (-1);
	/*
	 * A zero Source, zero Destination, or PeriodLog 0 disables the
	 * subscription (Section 4.3.2.65); Count/MinHops/MaxHops reset.
	 */
	memset(s, 0, sizeof(*s));
	s->min_hops = 0x7f;
	s->max_hops = 0x00;
	if (in->src == MESH_ADDR_UNASSIGNED || in->dst == MESH_ADDR_UNASSIGNED ||
	    in->period_log == 0x00) {
		return (0);
	}
	/* Source must be a unicast address; Destination unicast or group. */
	if (!mesh_addr_is_unicast(in->src))
		return (-1);
	if (!mesh_addr_is_unicast(in->dst) && !mesh_addr_is_group(in->dst))
		return (-1);
	s->src = in->src;
	s->dst = in->dst;
	s->period_log = in->period_log;
	return (0);
}

int
mesh_hb_sub_receive(struct mesh_hb_sub *s, uint16_t src, uint16_t dst,
    uint8_t init_ttl, uint8_t rx_ttl)
{
	uint8_t hops;

	if (s == NULL)
		return (0);
	if (s->src == MESH_ADDR_UNASSIGNED || s->dst == MESH_ADDR_UNASSIGNED)
		return (0);			/* not subscribed */
	if (src != s->src || dst != s->dst)
		return (0);			/* not our (src,dst) pair */
	if (rx_ttl > init_ttl)
		return (0);			/* malformed: TTL only decreases */

	if (s->count < 0xffff)
		s->count++;			/* saturating count */
	/* hops = InitTTL - RxTTL + 1 (Section 3.6.7.3). */
	hops = (uint8_t)(init_ttl - rx_ttl + 1);
	if (hops < s->min_hops)
		s->min_hops = hops;
	if (hops > s->max_hops)
		s->max_hops = hops;
	return (1);
}

void
mesh_hb_sub_snapshot(const struct mesh_hb_sub *s, uint8_t status,
    struct mesh_hb_sub_status *out)
{

	if (out == NULL)
		return;
	memset(out, 0, sizeof(*out));
	if (s == NULL)
		return;
	out->status = status;
	out->src = s->src;
	out->dst = s->dst;
	out->period_log = s->period_log;
	out->count_log = mesh_hb_count_log(s->count);
	out->min_hops = s->min_hops;
	out->max_hops = s->max_hops;
}
