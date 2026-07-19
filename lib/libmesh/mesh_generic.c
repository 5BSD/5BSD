/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Generic models (MshMDL_v1.1 Section 3.2): the Generic OnOff
 * and Generic Level Server/Client message codecs, server state machines and
 * client helpers.  See mesh_generic.h for the opcode map, the little-endian
 * field order and the injected-clock transition model.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_generic.h"

/* ================================================================
 * Little-endian field helpers.
 * ================================================================ */

static void
put_le16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static uint16_t
get_le16(const uint8_t *p)
{

	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

static void
put_le32(uint8_t *p, uint32_t v)
{

	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t
get_le32(const uint8_t *p)
{

	return ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

int16_t
mesh_gen_level_sat_add(int32_t base, int32_t delta)
{
	int32_t r = base + delta;

	if (r > 32767)
		r = 32767;
	else if (r < -32768)
		r = -32768;
	return ((int16_t)r);
}

/* ================================================================
 * Generic OnOff codecs (Section 3.2.1.2 / 3.2.1.4).
 * ================================================================ */

int
mesh_gen_onoff_set_encode(const struct mesh_gen_onoff_set *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (in->onoff > MESH_GEN_ON)		/* OnOff is 0 or 1 */
		return (-1);
	out[0] = in->onoff;
	out[1] = in->tid;
	if (in->has_transition) {
		if (!mesh_transition_time_valid(in->transition_time))
			return (-1);
		out[2] = in->transition_time;
		out[3] = in->delay;
		*outlen = 4;
	} else
		*outlen = 2;
	return (0);
}

int
mesh_gen_onoff_set_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_onoff_set *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 2 && inlen != 4)
		return (-1);
	if (in[0] > MESH_GEN_ON)
		return (-1);
	out->onoff = in[0];
	out->tid = in[1];
	if (inlen == 4) {
		if (!mesh_transition_time_valid(in[2]))
			return (-1);
		out->has_transition = 1;
		out->transition_time = in[2];
		out->delay = in[3];
	}
	return (0);
}

int
mesh_gen_onoff_status_encode(const struct mesh_gen_onoff_status *in,
    uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (in->present > MESH_GEN_ON)
		return (-1);
	out[0] = in->present;
	if (in->has_target) {
		if (in->target > MESH_GEN_ON)
			return (-1);
		out[1] = in->target;
		out[2] = in->remaining;
		*outlen = 3;
	} else
		*outlen = 1;
	return (0);
}

int
mesh_gen_onoff_status_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_onoff_status *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 1 && inlen != 3)
		return (-1);
	if (in[0] > MESH_GEN_ON)
		return (-1);
	out->present = in[0];
	if (inlen == 3) {
		if (in[1] > MESH_GEN_ON)
			return (-1);
		out->has_target = 1;
		out->target = in[1];
		out->remaining = in[2];
	}
	return (0);
}

/* ================================================================
 * Generic Level codecs (Section 3.2.2.2/.3/.5/.8).
 * ================================================================ */

int
mesh_gen_level_set_encode(const struct mesh_gen_level_set *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	put_le16(out, (uint16_t)in->level);
	out[2] = in->tid;
	if (in->has_transition) {
		if (!mesh_transition_time_valid(in->transition_time))
			return (-1);
		out[3] = in->transition_time;
		out[4] = in->delay;
		*outlen = 5;
	} else
		*outlen = 3;
	return (0);
}

int
mesh_gen_level_set_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_level_set *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 3 && inlen != 5)
		return (-1);
	out->level = (int16_t)get_le16(in);
	out->tid = in[2];
	if (inlen == 5) {
		if (!mesh_transition_time_valid(in[3]))
			return (-1);
		out->has_transition = 1;
		out->transition_time = in[3];
		out->delay = in[4];
	}
	return (0);
}

int
mesh_gen_delta_set_encode(const struct mesh_gen_delta_set *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	put_le32(out, (uint32_t)in->delta);
	out[4] = in->tid;
	if (in->has_transition) {
		if (!mesh_transition_time_valid(in->transition_time))
			return (-1);
		out[5] = in->transition_time;
		out[6] = in->delay;
		*outlen = 7;
	} else
		*outlen = 5;
	return (0);
}

int
mesh_gen_delta_set_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_delta_set *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 5 && inlen != 7)
		return (-1);
	out->delta = (int32_t)get_le32(in);
	out->tid = in[4];
	if (inlen == 7) {
		if (!mesh_transition_time_valid(in[5]))
			return (-1);
		out->has_transition = 1;
		out->transition_time = in[5];
		out->delay = in[6];
	}
	return (0);
}

int
mesh_gen_move_set_encode(const struct mesh_gen_move_set *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	put_le16(out, (uint16_t)in->delta);
	out[2] = in->tid;
	if (in->has_transition) {
		if (!mesh_transition_time_valid(in->transition_time))
			return (-1);
		out[3] = in->transition_time;
		out[4] = in->delay;
		*outlen = 5;
	} else
		*outlen = 3;
	return (0);
}

int
mesh_gen_move_set_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_move_set *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 3 && inlen != 5)
		return (-1);
	out->delta = (int16_t)get_le16(in);
	out->tid = in[2];
	if (inlen == 5) {
		if (!mesh_transition_time_valid(in[3]))
			return (-1);
		out->has_transition = 1;
		out->transition_time = in[3];
		out->delay = in[4];
	}
	return (0);
}

int
mesh_gen_level_status_encode(const struct mesh_gen_level_status *in,
    uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	put_le16(out, (uint16_t)in->present);
	if (in->has_target) {
		put_le16(out + 2, (uint16_t)in->target);
		out[4] = in->remaining;
		*outlen = 5;
	} else
		*outlen = 2;
	return (0);
}

int
mesh_gen_level_status_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_level_status *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != 2 && inlen != 5)
		return (-1);
	out->present = (int16_t)get_le16(in);
	if (inlen == 5) {
		out->has_target = 1;
		out->target = (int16_t)get_le16(in + 2);
		out->remaining = in[4];
	}
	return (0);
}

/* ================================================================
 * Transaction tracking (Section 3.1).
 * ================================================================ */

/*
 * Returns 1 when (src, tid) begins a NEW transaction (recording it), or 0
 * when it is a retransmission of the transaction last seen by this server.
 */
static int
gen_tid_is_new(struct mesh_gen_tid *t, uint16_t src, uint16_t dst, uint8_t tid,
    uint64_t now_ms)
{

	if (t->valid && t->src == src && t->dst == dst && t->tid == tid &&
	    now_ms <= t->expires_ms)
		return (0);
	t->valid = 1;
	t->src = src;
	t->dst = dst;
	t->tid = tid;
	t->expires_ms = now_ms + 6000;
	return (1);
}

static uint8_t
gen_effective_transition(const struct mesh_gen_dtt_srv *dtt, int has,
    uint8_t explicit_time)
{
	return (has ? explicit_time : (dtt != NULL ? dtt->transition_time : 0));
}

/* ================================================================
 * Generic OnOff Server (Section 3.2.1).
 * ================================================================ */

void
mesh_gen_onoff_srv_init(struct mesh_gen_onoff_srv *srv, uint8_t present)
{

	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->present = (present > MESH_GEN_ON) ? MESH_GEN_ON : present;
}

void
mesh_gen_onoff_srv_bind(struct mesh_gen_onoff_srv *srv,
    void (*changed)(void *, uint8_t), void *arg)
{

	if (srv == NULL)
		return;
	srv->changed = changed;
	srv->changed_arg = arg;
}

void
mesh_gen_onoff_srv_set_present(struct mesh_gen_onoff_srv *srv, uint8_t present)
{

	if (srv == NULL)
		return;
	present = present ? MESH_GEN_ON : MESH_GEN_OFF;
	if (srv->present == present)
		return;
	srv->present = present;
	if (srv->changed != NULL)
		srv->changed(srv->changed_arg, present);
}

int
mesh_gen_onoff_srv_recv_at_dst(struct mesh_gen_onoff_srv *srv, uint16_t src,
    uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_onoff_status *status, int *want_status, uint64_t now_ms)
{
	struct mesh_gen_onoff_set set;
	uint64_t remaining;
	uint8_t transition_time;

	if (srv == NULL || status == NULL || want_status == NULL)
		return (-1);
	memset(status, 0, sizeof(*status));
	*want_status = 0;
	if (srv->transition.active)
		mesh_gen_onoff_srv_set_present(srv,
		    mesh_transition_sample_binary(&srv->transition, now_ms));

	switch (opcode) {
	case MESH_OP_GEN_ONOFF_GET:
		if (plen != 0)
			return (-1);
		*want_status = 1;
		break;
	case MESH_OP_GEN_ONOFF_SET:
	case MESH_OP_GEN_ONOFF_SET_UNACK:
		if (mesh_gen_onoff_set_decode(params, plen, &set) != 0)
			return (-1);
		if (gen_tid_is_new(&srv->txn, src, dst, set.tid, now_ms)) {
			transition_time = gen_effective_transition(srv->dtt,
			    set.has_transition, set.transition_time);
			if ((set.has_transition && set.delay != 0) ||
			    mesh_transition_time_ms(transition_time) != 0) {
				mesh_transition_start(&srv->transition, srv->present,
				    set.onoff, transition_time,
				    set.has_transition ? set.delay : 0, now_ms);
				mesh_gen_onoff_srv_set_present(srv,
				    mesh_transition_sample_binary(&srv->transition,
				    now_ms));
			} else {
				srv->transition.active = 0;
				mesh_gen_onoff_srv_set_present(srv, set.onoff);
			}
		}
		if (opcode == MESH_OP_GEN_ONOFF_SET)
			*want_status = 1;
		break;
	default:
		return (-1);
	}
	status->present = srv->present;
	status->has_target = srv->transition.active;
	if (status->has_target) {
		status->target = (uint8_t)srv->transition.target;
		remaining = srv->transition.end_ms > now_ms ?
		    srv->transition.end_ms - now_ms : 0;
		status->remaining = mesh_transition_remaining(remaining);
	}
	return (0);
}

int
mesh_gen_onoff_srv_recv_at(struct mesh_gen_onoff_srv *srv, uint16_t src,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_onoff_status *status, int *want_status, uint64_t now_ms)
{
	return (mesh_gen_onoff_srv_recv_at_dst(srv, src, 0, opcode, params,
	    plen, status, want_status, now_ms));
}

int
mesh_gen_onoff_srv_recv(struct mesh_gen_onoff_srv *srv, uint16_t src,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_onoff_status *status, int *want_status)
{
	return (mesh_gen_onoff_srv_recv_at(srv, src, opcode, params, plen, status,
	    want_status, mesh_access_now_ms()));
}

/* ================================================================
 * Generic Level Server (Section 3.2.2).
 * ================================================================ */

void
mesh_gen_level_srv_init(struct mesh_gen_level_srv *srv, int16_t present)
{

	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->present = present;
	srv->txn_base = present;
}

void
mesh_gen_level_srv_bind(struct mesh_gen_level_srv *srv,
    void (*changed)(void *, int16_t), void *arg)
{

	if (srv == NULL)
		return;
	srv->changed = changed;
	srv->changed_arg = arg;
}

void
mesh_gen_level_srv_set_present(struct mesh_gen_level_srv *srv, int16_t present)
{

	if (srv == NULL || srv->present == present)
		return;
	srv->present = present;
	if (srv->changed != NULL)
		srv->changed(srv->changed_arg, present);
}

int
mesh_gen_level_srv_recv_at_dst(struct mesh_gen_level_srv *srv, uint16_t src,
    uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_level_status *status, int *want_status, uint64_t now_ms)
{
	struct mesh_gen_level_set lset;
	struct mesh_gen_delta_set dset;
	struct mesh_gen_move_set mset;
	uint64_t remaining;
	uint8_t transition_time;

	if (srv == NULL || status == NULL || want_status == NULL)
		return (-1);
	memset(status, 0, sizeof(*status));
	*want_status = 0;
	if (srv->transition.active)
		mesh_gen_level_srv_set_present(srv,
		    (int16_t)mesh_transition_sample(&srv->transition, now_ms));

	switch (opcode) {
	case MESH_OP_GEN_LEVEL_GET:
		if (plen != 0)
			return (-1);
		*want_status = 1;
		break;
	case MESH_OP_GEN_LEVEL_SET:
	case MESH_OP_GEN_LEVEL_SET_UNACK:
		if (mesh_gen_level_set_decode(params, plen, &lset) != 0)
			return (-1);
		if (gen_tid_is_new(&srv->txn, src, dst, lset.tid, now_ms)) {
			transition_time = gen_effective_transition(srv->dtt,
			    lset.has_transition, lset.transition_time);
			if ((lset.has_transition && lset.delay != 0) ||
			    mesh_transition_time_ms(transition_time) != 0)
				mesh_transition_start(&srv->transition, srv->present,
				    lset.level, transition_time,
				    lset.has_transition ? lset.delay : 0, now_ms);
			else {
				srv->transition.active = 0;
				mesh_gen_level_srv_set_present(srv, lset.level);
			}
			srv->txn_base = srv->present;
		}
		if (opcode == MESH_OP_GEN_LEVEL_SET)
			*want_status = 1;
		break;
	case MESH_OP_GEN_DELTA_SET:
	case MESH_OP_GEN_DELTA_SET_UNACK:
	{
		int new_transaction, changed_delta;

		if (mesh_gen_delta_set_decode(params, plen, &dset) != 0)
			return (-1);
		/*
		 * Delta is applied relative to the Level at the START of the
		 * transaction (Section 3.2.2.3): a new transaction captures the
		 * base; a retransmission re-applies from the same base.
		 */
		new_transaction = gen_tid_is_new(&srv->txn, src, dst, dset.tid,
		    now_ms);
		if (new_transaction)
			srv->txn_base = srv->present;
		changed_delta = new_transaction || !srv->delta_valid ||
		    srv->last_delta != dset.delta;
		if (changed_delta) {
			transition_time = gen_effective_transition(srv->dtt,
			    dset.has_transition, dset.transition_time);
			srv->last_delta = dset.delta;
			srv->delta_valid = 1;
			if ((dset.has_transition && dset.delay != 0) ||
			    mesh_transition_time_ms(transition_time) != 0)
				mesh_transition_start(&srv->transition, srv->present,
				    mesh_gen_level_sat_add(srv->txn_base, dset.delta),
				    transition_time,
				    dset.has_transition ? dset.delay : 0, now_ms);
			else {
				srv->transition.active = 0;
				mesh_gen_level_srv_set_present(srv,
				    mesh_gen_level_sat_add(srv->txn_base, dset.delta));
			}
		}
		if (opcode == MESH_OP_GEN_DELTA_SET)
			*want_status = 1;
		break;
	}
	case MESH_OP_GEN_MOVE_SET:
	case MESH_OP_GEN_MOVE_SET_UNACK:
		if (mesh_gen_move_set_decode(params, plen, &mset) != 0)
			return (-1);
		if (gen_tid_is_new(&srv->txn, src, dst, mset.tid, now_ms)) {
			transition_time = gen_effective_transition(srv->dtt,
			    mset.has_transition, mset.transition_time);
			if (mset.delta != 0 && ((mset.has_transition &&
			    mset.delay != 0) ||
			    mesh_transition_time_ms(transition_time) != 0)) {
				uint64_t distance, duration, period;
				int32_t target;

				target = mset.delta > 0 ? INT16_MAX : INT16_MIN;
				distance = mset.delta > 0 ?
				    (uint64_t)(target - srv->present) :
				    (uint64_t)(srv->present - target);
				period = mesh_transition_time_ms(transition_time);
				duration = (distance * period +
				    (uint64_t)abs(mset.delta) - 1) /
				    (uint64_t)abs(mset.delta);
				mesh_transition_start_ms(&srv->transition, srv->present,
				    target, duration,
				    mset.has_transition ? mset.delay : 0, now_ms);
			}
			else if (mset.delta > 0)
				mesh_gen_level_srv_set_present(srv, INT16_MAX);
			else if (mset.delta < 0)
				mesh_gen_level_srv_set_present(srv, INT16_MIN);
			else
				srv->transition.active = 0;
			/* delta == 0: movement stops, Level unchanged. */
			srv->txn_base = srv->present;
		}
		if (opcode == MESH_OP_GEN_MOVE_SET)
			*want_status = 1;
		break;
	default:
		return (-1);
	}
	status->present = srv->present;
	status->has_target = srv->transition.active;
	if (status->has_target) {
		status->target = (int16_t)srv->transition.target;
		remaining = srv->transition.end_ms > now_ms ?
		    srv->transition.end_ms - now_ms : 0;
		status->remaining = mesh_transition_remaining(remaining);
	}
	return (0);
}

int
mesh_gen_level_srv_recv_at(struct mesh_gen_level_srv *srv, uint16_t src,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_level_status *status, int *want_status, uint64_t now_ms)
{
	return (mesh_gen_level_srv_recv_at_dst(srv, src, 0, opcode, params,
	    plen, status, want_status, now_ms));
}

int
mesh_gen_level_srv_recv(struct mesh_gen_level_srv *srv, uint16_t src,
    uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_gen_level_status *status, int *want_status)
{
	return (mesh_gen_level_srv_recv_at(srv, src, opcode, params, plen, status,
	    want_status, mesh_access_now_ms()));
}

void
mesh_gen_power_onoff_srv_init(struct mesh_gen_power_onoff_srv *srv,
    struct mesh_gen_onoff_srv *bound, uint8_t on_power_up)
{
	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->bound_onoff = bound;
	srv->on_power_up = on_power_up <= MESH_GEN_ONPOWERUP_RESTORE ?
	    on_power_up : MESH_GEN_ONPOWERUP_OFF;
	if (bound != NULL)
		srv->last_onoff = bound->present;
}

void
mesh_gen_power_onoff_srv_power_cycle(struct mesh_gen_power_onoff_srv *srv)
{
	uint8_t previous;

	if (srv == NULL || srv->bound_onoff == NULL)
		return;
	previous = srv->bound_onoff->present;
	switch (srv->on_power_up) {
	case MESH_GEN_ONPOWERUP_OFF:
		mesh_gen_onoff_srv_set_present(srv->bound_onoff, MESH_GEN_OFF);
		break;
	case MESH_GEN_ONPOWERUP_DEFAULT:
		mesh_gen_onoff_srv_set_present(srv->bound_onoff, MESH_GEN_ON);
		break;
	case MESH_GEN_ONPOWERUP_RESTORE:
		mesh_gen_onoff_srv_set_present(srv->bound_onoff, srv->last_onoff);
		break;
	}
	srv->last_onoff = previous;
}

int
mesh_gen_power_onoff_srv_recv(struct mesh_gen_power_onoff_srv *srv,
    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *status,
    int *want_status)
{
	if (srv == NULL || status == NULL || want_status == NULL)
		return (-1);
	*want_status = 0;
	if (opcode == MESH_OP_GEN_ONPOWERUP_GET) {
		if (plen != 0)
			return (-1);
		*want_status = 1;
	} else if (opcode == MESH_OP_GEN_ONPOWERUP_SET ||
	    opcode == MESH_OP_GEN_ONPOWERUP_SET_UNACK) {
		if (params == NULL || plen != 1 ||
		    params[0] > MESH_GEN_ONPOWERUP_RESTORE)
			return (-1);
		srv->on_power_up = params[0];
		*want_status = opcode == MESH_OP_GEN_ONPOWERUP_SET;
	} else
		return (-1);
	*status = srv->on_power_up;
	return (0);
}

int
mesh_gen_transition_time_valid(uint8_t transition_time)
{
	return (mesh_transition_time_valid(transition_time));
}

void
mesh_gen_dtt_srv_init(struct mesh_gen_dtt_srv *srv, uint8_t transition_time)
{
	if (srv == NULL)
		return;
	srv->transition_time = mesh_gen_transition_time_valid(transition_time) ?
	    transition_time : 0;
}

int
mesh_gen_dtt_srv_recv(struct mesh_gen_dtt_srv *srv, uint32_t opcode,
    const uint8_t *params, size_t plen, uint8_t *status, int *want_status)
{
	if (srv == NULL || status == NULL || want_status == NULL)
		return (-1);
	*want_status = 0;
	if (opcode == MESH_OP_GEN_DTT_GET) {
		if (plen != 0)
			return (-1);
		*want_status = 1;
	} else if (opcode == MESH_OP_GEN_DTT_SET ||
	    opcode == MESH_OP_GEN_DTT_SET_UNACK) {
		if (params == NULL || plen != 1 ||
		    !mesh_gen_transition_time_valid(params[0]))
			return (-1);
		srv->transition_time = params[0];
		*want_status = opcode == MESH_OP_GEN_DTT_SET;
	} else
		return (-1);
	*status = srv->transition_time;
	return (0);
}

void
mesh_gen_power_level_srv_init(struct mesh_gen_power_level_srv *srv,
    struct mesh_gen_onoff_srv *onoff, struct mesh_gen_level_srv *level,
    struct mesh_gen_power_onoff_srv *power_onoff)
{
	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->last = UINT16_MAX;
	srv->range_min = 1;
	srv->range_max = UINT16_MAX;
	srv->bound_onoff = onoff;
	srv->bound_level = level;
	srv->bound_power_onoff = power_onoff;
}

void
mesh_gen_power_level_set_actual(struct mesh_gen_power_level_srv *srv,
    uint16_t actual)
{
	if (srv == NULL)
		return;
	if (actual != 0 && actual < srv->range_min)
		actual = srv->range_min;
	if (actual > srv->range_max)
		actual = srv->range_max;
	srv->actual = actual;
	if (actual != 0)
		srv->last = actual;
	if (srv->bound_onoff != NULL)
		mesh_gen_onoff_srv_set_present(srv->bound_onoff,
		    actual != 0 ? MESH_GEN_ON : MESH_GEN_OFF);
	if (srv->bound_level != NULL)
		mesh_gen_level_srv_set_present(srv->bound_level,
		    (int16_t)((int32_t)actual - 32768));
}

void
mesh_gen_power_level_power_cycle(struct mesh_gen_power_level_srv *srv)
{
	uint16_t actual;

	if (srv == NULL || srv->bound_power_onoff == NULL)
		return;
	switch (srv->bound_power_onoff->on_power_up) {
	case MESH_GEN_ONPOWERUP_OFF:
		actual = 0;
		break;
	case MESH_GEN_ONPOWERUP_DEFAULT:
		actual = srv->default_power != 0 ? srv->default_power : srv->last;
		break;
	default:
		actual = srv->actual;
		break;
	}
	mesh_gen_power_level_set_actual(srv, actual);
}

static void
power_reply_u16(struct mesh_model_reply *r, uint32_t opcode, uint16_t value)
{
	if (r == NULL)
		return;
	r->have_reply = 1;
	r->opcode = opcode;
	r->params[0] = (uint8_t)value;
	r->params[1] = (uint8_t)(value >> 8);
	r->params_len = 2;
}

static void
power_level_update(struct mesh_gen_power_level_srv *srv, uint64_t now_ms)
{
	if (srv->transition.active)
		mesh_gen_power_level_set_actual(srv,
		    (uint16_t)mesh_transition_sample(&srv->transition, now_ms));
}

static void
power_level_status(struct mesh_gen_power_level_srv *srv,
    struct mesh_model_reply *reply, uint64_t now_ms)
{
	uint64_t remaining;

	power_reply_u16(reply, MESH_OP_GEN_POWER_LEVEL_STATUS, srv->actual);
	if (reply == NULL || !srv->transition.active)
		return;
	reply->params[2] = (uint8_t)srv->transition.target;
	reply->params[3] = (uint8_t)(srv->transition.target >> 8);
	remaining = srv->transition.end_ms > now_ms ?
	    srv->transition.end_ms - now_ms : 0;
	reply->params[4] = mesh_transition_remaining(remaining);
	reply->params_len = 5;
}

int
mesh_gen_power_level_srv_recv_at_dst(struct mesh_gen_power_level_srv *srv,
    uint16_t src, uint16_t dst, uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_model_reply *reply, uint64_t now_ms)
{
	uint16_t value, min, max;
	uint8_t transition_time;
	int ack;

	if (srv == NULL)
		return (-1);
	if (reply != NULL)
		memset(reply, 0, sizeof(*reply));
	power_level_update(srv, now_ms);
	switch (opcode) {
	case MESH_OP_GEN_POWER_LEVEL_GET:
		if (plen != 0) return (-1);
		power_level_status(srv, reply, now_ms);
		break;
	case MESH_OP_GEN_POWER_LAST_GET:
		if (plen != 0) return (-1);
		power_reply_u16(reply, MESH_OP_GEN_POWER_LAST_STATUS, srv->last);
		break;
	case MESH_OP_GEN_POWER_DEFAULT_GET:
		if (plen != 0) return (-1);
		power_reply_u16(reply, MESH_OP_GEN_POWER_DEFAULT_STATUS,
		    srv->default_power);
		break;
	case MESH_OP_GEN_POWER_RANGE_GET:
		if (plen != 0) return (-1);
		if (reply != NULL) {
			reply->have_reply = 1;
			reply->opcode = MESH_OP_GEN_POWER_RANGE_STATUS;
			reply->params[0] = srv->range_status;
			reply->params[1] = (uint8_t)srv->range_min;
			reply->params[2] = (uint8_t)(srv->range_min >> 8);
			reply->params[3] = (uint8_t)srv->range_max;
			reply->params[4] = (uint8_t)(srv->range_max >> 8);
			reply->params_len = 5;
		}
		break;
	case MESH_OP_GEN_POWER_LEVEL_SET:
	case MESH_OP_GEN_POWER_LEVEL_SET_UNACK:
		if (params == NULL || (plen != 3 && plen != 5) ||
		    (plen == 5 && !mesh_gen_transition_time_valid(params[3])))
			return (-1);
		value = (uint16_t)params[0] | ((uint16_t)params[1] << 8);
		if (gen_tid_is_new(&srv->txn, src, dst, params[2], now_ms)) {
			transition_time = gen_effective_transition(srv->dtt,
			    plen == 5, plen == 5 ? params[3] : 0);
			if ((plen == 5 && params[4] != 0) ||
			    mesh_transition_time_ms(transition_time) != 0)
				mesh_transition_start(&srv->transition, srv->actual,
				    value, transition_time,
				    plen == 5 ? params[4] : 0, now_ms);
			else {
				srv->transition.active = 0;
				mesh_gen_power_level_set_actual(srv, value);
			}
		}
		if (opcode == MESH_OP_GEN_POWER_LEVEL_SET)
			power_level_status(srv, reply, now_ms);
		break;
	case MESH_OP_GEN_POWER_DEFAULT_SET:
	case MESH_OP_GEN_POWER_DEFAULT_SET_UNACK:
		if (params == NULL || plen != 2) return (-1);
		srv->default_power = (uint16_t)params[0] |
		    ((uint16_t)params[1] << 8);
		if (opcode == MESH_OP_GEN_POWER_DEFAULT_SET)
			power_reply_u16(reply, MESH_OP_GEN_POWER_DEFAULT_STATUS,
			    srv->default_power);
		break;
	case MESH_OP_GEN_POWER_RANGE_SET:
	case MESH_OP_GEN_POWER_RANGE_SET_UNACK:
		if (params == NULL || plen != 4) return (-1);
		min = (uint16_t)params[0] | ((uint16_t)params[1] << 8);
		max = (uint16_t)params[2] | ((uint16_t)params[3] << 8);
		/*
		 * Mesh Model 1.1.1, Generic Power Range Set: a Range Min
		 * greater than Range Max makes the message invalid and ignored.
		 * It is not a "Cannot Set Range Max" status condition.
		 */
		if (min > max)
			return (-1);
		ack = opcode == MESH_OP_GEN_POWER_RANGE_SET;
		srv->range_status = min == 0 ? 1 : (max == 0 ? 2 : 0);
		if (srv->range_status == 0) {
			srv->range_min = min;
			srv->range_max = max;
			mesh_gen_power_level_set_actual(srv, srv->actual);
		}
		if (ack && reply != NULL) {
			reply->have_reply = 1;
			reply->opcode = MESH_OP_GEN_POWER_RANGE_STATUS;
			reply->params[0] = srv->range_status;
			reply->params[1] = (uint8_t)srv->range_min;
			reply->params[2] = (uint8_t)(srv->range_min >> 8);
			reply->params[3] = (uint8_t)srv->range_max;
			reply->params[4] = (uint8_t)(srv->range_max >> 8);
			reply->params_len = 5;
		}
		break;
	default:
		return (-1);
	}
	return (0);
}

int
mesh_gen_power_level_srv_recv_at(struct mesh_gen_power_level_srv *srv,
    uint16_t src, uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_model_reply *reply, uint64_t now_ms)
{
	return (mesh_gen_power_level_srv_recv_at_dst(srv, src, 0, opcode,
	    params, plen, reply, now_ms));
}

int
mesh_gen_power_level_srv_recv(struct mesh_gen_power_level_srv *srv,
    uint16_t src, uint32_t opcode, const uint8_t *params, size_t plen,
    struct mesh_model_reply *reply)
{
	return (mesh_gen_power_level_srv_recv_at(srv, src, opcode, params, plen,
	    reply, mesh_access_now_ms()));
}

static int
battery_flags_valid(uint8_t flags)
{
	/*
	 * Mesh Model 1.1.1 §3.1.6.4, Tables 3.12-3.15: 0b11 is
	 * the valid "unknown" value for every two-bit field.  Only
	 * Serviceability 0b00 (bits 6-7) is reserved for future use.
	 */
	return (((flags >> 6) & 3) != 0);
}

int
mesh_gen_battery_status_encode(const struct mesh_gen_battery_status *in,
    uint8_t out[8])
{
	if (in == NULL || out == NULL ||
	    (in->level > 100 && in->level != 0xff) ||
	    in->discharge_minutes > 0xffffff || in->charge_minutes > 0xffffff ||
	    !battery_flags_valid(in->flags))
		return (-1);
	out[0] = in->level;
	out[1] = (uint8_t)in->discharge_minutes;
	out[2] = (uint8_t)(in->discharge_minutes >> 8);
	out[3] = (uint8_t)(in->discharge_minutes >> 16);
	out[4] = (uint8_t)in->charge_minutes;
	out[5] = (uint8_t)(in->charge_minutes >> 8);
	out[6] = (uint8_t)(in->charge_minutes >> 16);
	out[7] = in->flags;
	return (0);
}

int
mesh_gen_battery_status_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_battery_status *out)
{
	struct mesh_gen_battery_status st;

	if (in == NULL || out == NULL || inlen != 8)
		return (-1);
	st.level = in[0];
	st.discharge_minutes = (uint32_t)in[1] | ((uint32_t)in[2] << 8) |
	    ((uint32_t)in[3] << 16);
	st.charge_minutes = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
	    ((uint32_t)in[6] << 16);
	st.flags = in[7];
	if ((st.level > 100 && st.level != 0xff) || !battery_flags_valid(st.flags))
		return (-1);
	*out = st;
	return (0);
}

void
mesh_gen_battery_srv_init(struct mesh_gen_battery_srv *srv)
{
	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->state.level = 0xff;
	srv->state.discharge_minutes = 0xffffff;
	srv->state.charge_minutes = 0xffffff;
	/* All four fields unknown; valid per Tables 3.12-3.15. */
	srv->state.flags = 0xff;
}

int
mesh_gen_location_global_encode(const struct mesh_gen_location_global *in,
    uint8_t out[10])
{
	uint32_t lat, lon;

	if (in == NULL || out == NULL)
		return (-1);
	lat = (uint32_t)in->latitude; lon = (uint32_t)in->longitude;
	out[0] = lat; out[1] = lat >> 8; out[2] = lat >> 16; out[3] = lat >> 24;
	out[4] = lon; out[5] = lon >> 8; out[6] = lon >> 16; out[7] = lon >> 24;
	out[8] = (uint8_t)in->altitude; out[9] = (uint8_t)((uint16_t)in->altitude >> 8);
	return (0);
}

int
mesh_gen_location_global_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_location_global *out)
{
	if (in == NULL || out == NULL || inlen != 10)
		return (-1);
	out->latitude = (int32_t)((uint32_t)in[0] | ((uint32_t)in[1] << 8) |
	    ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24));
	out->longitude = (int32_t)((uint32_t)in[4] | ((uint32_t)in[5] << 8) |
	    ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24));
	out->altitude = (int16_t)((uint16_t)in[8] | ((uint16_t)in[9] << 8));
	return (0);
}

int
mesh_gen_location_local_encode(const struct mesh_gen_location_local *in,
    uint8_t out[9])
{
	if (in == NULL || out == NULL)
		return (-1);
	out[0] = (uint8_t)in->north; out[1] = (uint8_t)((uint16_t)in->north >> 8);
	out[2] = (uint8_t)in->east; out[3] = (uint8_t)((uint16_t)in->east >> 8);
	out[4] = (uint8_t)in->altitude; out[5] = (uint8_t)((uint16_t)in->altitude >> 8);
	out[6] = in->floor;
	out[7] = (uint8_t)in->uncertainty; out[8] = (uint8_t)(in->uncertainty >> 8);
	return (0);
}

int
mesh_gen_location_local_decode(const uint8_t *in, size_t inlen,
    struct mesh_gen_location_local *out)
{
	if (in == NULL || out == NULL || inlen != 9)
		return (-1);
	out->north = (int16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
	out->east = (int16_t)((uint16_t)in[2] | ((uint16_t)in[3] << 8));
	out->altitude = (int16_t)((uint16_t)in[4] | ((uint16_t)in[5] << 8));
	out->floor = in[6];
	out->uncertainty = (uint16_t)in[7] | ((uint16_t)in[8] << 8);
	return (0);
}

void
mesh_gen_location_srv_init(struct mesh_gen_location_srv *srv)
{
	if (srv == NULL)
		return;
	memset(srv, 0, sizeof(*srv));
	srv->global.latitude = INT32_MIN;
	srv->global.longitude = INT32_MIN;
	srv->global.altitude = INT16_MAX;
	srv->local.north = INT16_MIN;
	srv->local.east = INT16_MIN;
	srv->local.altitude = INT16_MAX;
	srv->local.floor = 0xff;
}

/* ================================================================
 * Access-layer dispatch handlers + model tables.
 * ================================================================ */

static int
onoff_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_onoff_srv *srv;
	struct mesh_model_reply *d;
	struct mesh_gen_onoff_status st;
	int want;

	srv = rx->model_user;
	if (srv == NULL)
		return (-1);
	if (mesh_gen_onoff_srv_recv_at_dst(srv, rx->src, rx->dst,
	    rx->pdu->opcode,
	    rx->pdu->params, rx->pdu->params_len, &st, &want, rx->now_ms) != 0)
		return (-1);
	d = rx->ctx;
	if (want && d != NULL) {
		d->have_reply = 1;
		d->opcode = MESH_OP_GEN_ONOFF_STATUS;
		(void)mesh_gen_onoff_status_encode(&st, d->params,
		    &d->params_len);
		d->src = rx->elem_addr;
		d->dst = rx->src;
	}
	return (0);
}

static int
level_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_level_srv *srv;
	struct mesh_model_reply *d;
	struct mesh_gen_level_status st;
	int want;

	srv = rx->model_user;
	if (srv == NULL)
		return (-1);
	if (mesh_gen_level_srv_recv_at_dst(srv, rx->src, rx->dst,
	    rx->pdu->opcode,
	    rx->pdu->params, rx->pdu->params_len, &st, &want, rx->now_ms) != 0)
		return (-1);
	d = rx->ctx;
	if (want && d != NULL) {
		d->have_reply = 1;
		d->opcode = MESH_OP_GEN_LEVEL_STATUS;
		(void)mesh_gen_level_status_encode(&st, d->params,
		    &d->params_len);
		d->src = rx->elem_addr;
		d->dst = rx->src;
	}
	return (0);
}

static int
onoff_cli_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_onoff_cli *cli;

	cli = rx->model_user;
	if (cli == NULL)
		return (-1);
	return (mesh_gen_onoff_cli_recv(cli, rx->pdu->opcode, rx->pdu->params,
	    rx->pdu->params_len));
}

static int
level_cli_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_level_cli *cli;

	cli = rx->model_user;
	if (cli == NULL)
		return (-1);
	return (mesh_gen_level_cli_recv(cli, rx->pdu->opcode, rx->pdu->params,
	    rx->pdu->params_len));
}

static int
power_onoff_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_power_onoff_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint8_t status;
	int want;

	if (mesh_gen_power_onoff_srv_recv(srv, rx->pdu->opcode, rx->pdu->params,
	    rx->pdu->params_len, &status, &want) != 0)
		return (-1);
	if (want && reply != NULL) {
		reply->have_reply = 1;
		reply->opcode = MESH_OP_GEN_ONPOWERUP_STATUS;
		reply->params[0] = status;
		reply->params_len = 1;
		reply->src = rx->elem_addr;
		reply->dst = rx->src;
	}
	return (0);
}

static int
dtt_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_dtt_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint8_t status;
	int want;

	if (mesh_gen_dtt_srv_recv(srv, rx->pdu->opcode, rx->pdu->params,
	    rx->pdu->params_len, &status, &want) != 0)
		return (-1);
	if (want && reply != NULL) {
		reply->have_reply = 1;
		reply->opcode = MESH_OP_GEN_DTT_STATUS;
		reply->params[0] = status;
		reply->params_len = 1;
		reply->src = rx->elem_addr;
		reply->dst = rx->src;
	}
	return (0);
}

static int
power_level_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_model_reply *reply = rx->ctx;
	int error;

	error = mesh_gen_power_level_srv_recv_at_dst(rx->model_user, rx->src,
	    rx->dst,
	    rx->pdu->opcode, rx->pdu->params, rx->pdu->params_len, reply,
	    rx->now_ms);
	if (error == 0 && reply != NULL && reply->have_reply) {
		reply->src = rx->elem_addr;
		reply->dst = rx->src;
	}
	return (error);
}

static int
battery_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_battery_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;

	if (srv == NULL || rx->pdu->opcode != MESH_OP_GEN_BATTERY_GET ||
	    rx->pdu->params_len != 0)
		return (-1);
	if (reply != NULL) {
		reply->have_reply = 1;
		reply->opcode = MESH_OP_GEN_BATTERY_STATUS;
		if (mesh_gen_battery_status_encode(&srv->state, reply->params) != 0)
			return (-1);
		reply->params_len = 8;
		reply->src = rx->elem_addr;
		reply->dst = rx->src;
	}
	return (0);
}

static int
location_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_gen_location_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint32_t opcode = rx->pdu->opcode;
	int global, ack;

	if (srv == NULL)
		return (-1);
	global = opcode == MESH_OP_GEN_LOCATION_GLOBAL_GET ||
	    opcode == MESH_OP_GEN_LOCATION_GLOBAL_SET ||
	    opcode == MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK;
	ack = opcode != MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK &&
	    opcode != MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK;
	if (opcode == MESH_OP_GEN_LOCATION_GLOBAL_GET ||
	    opcode == MESH_OP_GEN_LOCATION_LOCAL_GET) {
		if (rx->pdu->params_len != 0)
			return (-1);
	} else if (global) {
		if (mesh_gen_location_global_decode(rx->pdu->params,
		    rx->pdu->params_len, &srv->global) != 0)
			return (-1);
	} else if (opcode == MESH_OP_GEN_LOCATION_LOCAL_SET ||
	    opcode == MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK) {
		if (mesh_gen_location_local_decode(rx->pdu->params,
		    rx->pdu->params_len, &srv->local) != 0)
			return (-1);
	} else
		return (-1);
	if (ack && reply != NULL) {
		reply->have_reply = 1;
		reply->opcode = global ? MESH_OP_GEN_LOCATION_GLOBAL_STATUS :
		    MESH_OP_GEN_LOCATION_LOCAL_STATUS;
		if (global) {
			(void)mesh_gen_location_global_encode(&srv->global, reply->params);
			reply->params_len = 10;
		} else {
			(void)mesh_gen_location_local_encode(&srv->local, reply->params);
			reply->params_len = 9;
		}
		reply->src = rx->elem_addr; reply->dst = rx->src;
	}
	return (0);
}

static const struct mesh_opcode_entry onoff_srv_ops[] = {
	{ MESH_OP_GEN_ONOFF_GET, onoff_srv_handler },
	{ MESH_OP_GEN_ONOFF_SET, onoff_srv_handler },
	{ MESH_OP_GEN_ONOFF_SET_UNACK, onoff_srv_handler },
};

static const struct mesh_opcode_entry level_srv_ops[] = {
	{ MESH_OP_GEN_LEVEL_GET, level_srv_handler },
	{ MESH_OP_GEN_LEVEL_SET, level_srv_handler },
	{ MESH_OP_GEN_LEVEL_SET_UNACK, level_srv_handler },
	{ MESH_OP_GEN_DELTA_SET, level_srv_handler },
	{ MESH_OP_GEN_DELTA_SET_UNACK, level_srv_handler },
	{ MESH_OP_GEN_MOVE_SET, level_srv_handler },
	{ MESH_OP_GEN_MOVE_SET_UNACK, level_srv_handler },
};

static const struct mesh_opcode_entry onoff_cli_ops[] = {
	{ MESH_OP_GEN_ONOFF_STATUS, onoff_cli_handler },
};

static const struct mesh_opcode_entry level_cli_ops[] = {
	{ MESH_OP_GEN_LEVEL_STATUS, level_cli_handler },
};

static const struct mesh_opcode_entry power_onoff_srv_ops[] = {
	{ MESH_OP_GEN_ONPOWERUP_GET, power_onoff_srv_handler },
};

static const struct mesh_opcode_entry dtt_srv_ops[] = {
	{ MESH_OP_GEN_DTT_GET, dtt_srv_handler },
	{ MESH_OP_GEN_DTT_SET, dtt_srv_handler },
	{ MESH_OP_GEN_DTT_SET_UNACK, dtt_srv_handler },
};

static const struct mesh_opcode_entry power_level_srv_ops[] = {
	{ MESH_OP_GEN_POWER_LEVEL_GET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_LEVEL_SET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_LEVEL_SET_UNACK, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_LAST_GET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_DEFAULT_GET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_RANGE_GET, power_level_srv_handler },
};

static const struct mesh_opcode_entry power_level_setup_srv_ops[] = {
	{ MESH_OP_GEN_POWER_DEFAULT_SET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_DEFAULT_SET_UNACK, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_RANGE_SET, power_level_srv_handler },
	{ MESH_OP_GEN_POWER_RANGE_SET_UNACK, power_level_srv_handler },
};

static const struct mesh_opcode_entry battery_srv_ops[] = {
	{ MESH_OP_GEN_BATTERY_GET, battery_srv_handler },
};

static const struct mesh_opcode_entry location_srv_ops[] = {
	{ MESH_OP_GEN_LOCATION_GLOBAL_GET, location_srv_handler },
	{ MESH_OP_GEN_LOCATION_LOCAL_GET, location_srv_handler },
};

static const struct mesh_opcode_entry location_setup_srv_ops[] = {
	{ MESH_OP_GEN_LOCATION_GLOBAL_SET, location_srv_handler },
	{ MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK, location_srv_handler },
	{ MESH_OP_GEN_LOCATION_LOCAL_SET, location_srv_handler },
	{ MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK, location_srv_handler },
};

static void
onoff_srv_tick(void *arg, uint64_t now_ms)
{
	struct mesh_gen_onoff_srv *srv = arg;

	if (srv != NULL && srv->transition.active)
		mesh_gen_onoff_srv_set_present(srv,
		    mesh_transition_sample_binary(&srv->transition, now_ms));
}

static void
level_srv_tick(void *arg, uint64_t now_ms)
{
	struct mesh_gen_level_srv *srv = arg;

	if (srv != NULL && srv->transition.active)
		mesh_gen_level_srv_set_present(srv,
		    (int16_t)mesh_transition_sample(&srv->transition, now_ms));
}

static void
power_level_srv_tick(void *arg, uint64_t now_ms)
{
	struct mesh_gen_power_level_srv *srv = arg;

	if (srv != NULL)
		power_level_update(srv, now_ms);
}

static const struct mesh_opcode_entry power_onoff_setup_srv_ops[] = {
	{ MESH_OP_GEN_ONPOWERUP_SET, power_onoff_srv_handler },
	{ MESH_OP_GEN_ONPOWERUP_SET_UNACK, power_onoff_srv_handler },
};

struct mesh_model
mesh_gen_onoff_srv_model(struct mesh_gen_onoff_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_ONOFF_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = onoff_srv_ops;
	m.n_ops = sizeof(onoff_srv_ops) / sizeof(onoff_srv_ops[0]);
	m.user = srv;
	m.tick = onoff_srv_tick;
	return (m);
}

struct mesh_model
mesh_gen_level_srv_model(struct mesh_gen_level_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_LEVEL_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = level_srv_ops;
	m.n_ops = sizeof(level_srv_ops) / sizeof(level_srv_ops[0]);
	m.user = srv;
	m.tick = level_srv_tick;
	return (m);
}

struct mesh_model
mesh_gen_power_onoff_srv_model(struct mesh_gen_power_onoff_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_POWER_ONOFF_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = power_onoff_srv_ops;
	m.n_ops = sizeof(power_onoff_srv_ops) / sizeof(power_onoff_srv_ops[0]);
	m.user = srv;
	return (m);
}

struct mesh_model
mesh_gen_dtt_srv_model(struct mesh_gen_dtt_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_DTT_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = dtt_srv_ops;
	m.n_ops = sizeof(dtt_srv_ops) / sizeof(dtt_srv_ops[0]);
	m.user = srv;
	return (m);
}

struct mesh_model
mesh_gen_power_level_srv_model(struct mesh_gen_power_level_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_POWER_LEVEL_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = power_level_srv_ops;
	m.n_ops = sizeof(power_level_srv_ops) / sizeof(power_level_srv_ops[0]);
	m.user = srv;
	m.tick = power_level_srv_tick;
	return (m);
}

struct mesh_model
mesh_gen_power_level_setup_srv_model(struct mesh_gen_power_level_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_POWER_LEVEL_SETUP_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = power_level_setup_srv_ops;
	m.n_ops = sizeof(power_level_setup_srv_ops) /
	    sizeof(power_level_setup_srv_ops[0]);
	m.user = srv;
	return (m);
}

struct mesh_model
mesh_gen_battery_srv_model(struct mesh_gen_battery_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_BATTERY_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = battery_srv_ops;
	m.n_ops = sizeof(battery_srv_ops) / sizeof(battery_srv_ops[0]);
	m.user = srv;
	return (m);
}

static struct mesh_model
location_model(uint16_t id, const struct mesh_opcode_entry *ops, size_t nops,
    struct mesh_gen_location_srv *srv)
{
	struct mesh_model m;
	memset(&m, 0, sizeof(m));
	m.model_id = id; m.company_id = MESH_COMPANY_SIG;
	m.ops = ops; m.n_ops = nops; m.user = srv;
	return (m);
}

struct mesh_model
mesh_gen_location_srv_model(struct mesh_gen_location_srv *srv)
{
	return (location_model(MESH_MODEL_GEN_LOCATION_SRV, location_srv_ops,
	    sizeof(location_srv_ops) / sizeof(location_srv_ops[0]), srv));
}

struct mesh_model
mesh_gen_location_setup_srv_model(struct mesh_gen_location_srv *srv)
{
	return (location_model(MESH_MODEL_GEN_LOCATION_SETUP_SRV,
	    location_setup_srv_ops, sizeof(location_setup_srv_ops) /
	    sizeof(location_setup_srv_ops[0]), srv));
}

struct mesh_model
mesh_gen_power_onoff_setup_srv_model(struct mesh_gen_power_onoff_srv *srv)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_POWER_ONOFF_SETUP_SRV;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = power_onoff_setup_srv_ops;
	m.n_ops = sizeof(power_onoff_setup_srv_ops) /
	    sizeof(power_onoff_setup_srv_ops[0]);
	m.user = srv;
	return (m);
}

struct mesh_model
mesh_gen_onoff_cli_model(struct mesh_gen_onoff_cli *cli)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_ONOFF_CLI;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = onoff_cli_ops;
	m.n_ops = sizeof(onoff_cli_ops) / sizeof(onoff_cli_ops[0]);
	m.user = cli;
	return (m);
}

struct mesh_model
mesh_gen_level_cli_model(struct mesh_gen_level_cli *cli)
{
	struct mesh_model m;

	memset(&m, 0, sizeof(m));
	m.model_id = MESH_MODEL_GEN_LEVEL_CLI;
	m.company_id = MESH_COMPANY_SIG;
	m.ops = level_cli_ops;
	m.n_ops = sizeof(level_cli_ops) / sizeof(level_cli_ops[0]);
	m.user = cli;
	return (m);
}

/* ================================================================
 * Clients (Section 3.2.1 / 3.2.2).
 * ================================================================ */

void
mesh_gen_onoff_cli_init(struct mesh_gen_onoff_cli *cli)
{

	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

void
mesh_gen_level_cli_init(struct mesh_gen_level_cli *cli)
{

	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

void
mesh_gen_power_onoff_cli_init(struct mesh_gen_power_onoff_cli *cli)
{
	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

void
mesh_gen_dtt_cli_init(struct mesh_gen_dtt_cli *cli)
{
	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

int
mesh_gen_onoff_cli_get(uint8_t *out, size_t *outlen)
{

	return (mesh_access_pdu_build(MESH_OP_GEN_ONOFF_GET, NULL, 0, out,
	    outlen));
}

int
mesh_gen_onoff_cli_set(const struct mesh_gen_onoff_set *in, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[4];
	size_t plen;
	uint32_t opcode;

	if (mesh_gen_onoff_set_encode(in, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_ONOFF_SET : MESH_OP_GEN_ONOFF_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

int
mesh_gen_level_cli_get(uint8_t *out, size_t *outlen)
{

	return (mesh_access_pdu_build(MESH_OP_GEN_LEVEL_GET, NULL, 0, out,
	    outlen));
}

int
mesh_gen_level_cli_set(const struct mesh_gen_level_set *in, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[5];
	size_t plen;
	uint32_t opcode;

	if (mesh_gen_level_set_encode(in, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_LEVEL_SET : MESH_OP_GEN_LEVEL_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

int
mesh_gen_delta_cli_set(const struct mesh_gen_delta_set *in, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[7];
	size_t plen;
	uint32_t opcode;

	if (mesh_gen_delta_set_encode(in, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_DELTA_SET : MESH_OP_GEN_DELTA_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

int
mesh_gen_move_cli_set(const struct mesh_gen_move_set *in, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[5];
	size_t plen;
	uint32_t opcode;

	if (mesh_gen_move_set_encode(in, params, &plen) != 0)
		return (-1);
	opcode = ack ? MESH_OP_GEN_MOVE_SET : MESH_OP_GEN_MOVE_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

int
mesh_gen_power_onoff_cli_get(uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(MESH_OP_GEN_ONPOWERUP_GET, NULL, 0, out,
	    outlen));
}

int
mesh_gen_dtt_cli_get(uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(MESH_OP_GEN_DTT_GET, NULL, 0, out,
	    outlen));
}

int
mesh_gen_dtt_cli_set(uint8_t transition_time, int ack, uint8_t *out,
    size_t *outlen)
{
	uint32_t opcode;

	if (!mesh_gen_transition_time_valid(transition_time))
		return (-1);
	opcode = ack ? MESH_OP_GEN_DTT_SET : MESH_OP_GEN_DTT_SET_UNACK;
	return (mesh_access_pdu_build(opcode, &transition_time, 1, out, outlen));
}

int
mesh_gen_dtt_cli_recv(struct mesh_gen_dtt_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	if (cli == NULL || opcode != MESH_OP_GEN_DTT_STATUS || params == NULL ||
	    plen != 1 || !mesh_gen_transition_time_valid(params[0]))
		return (-1);
	cli->transition_time = params[0];
	cli->have_status = 1;
	return (0);
}

int
mesh_gen_power_onoff_cli_set(uint8_t on_power_up, int ack, uint8_t *out,
    size_t *outlen)
{
	uint32_t opcode;

	if (on_power_up > MESH_GEN_ONPOWERUP_RESTORE)
		return (-1);
	opcode = ack ? MESH_OP_GEN_ONPOWERUP_SET :
	    MESH_OP_GEN_ONPOWERUP_SET_UNACK;
	return (mesh_access_pdu_build(opcode, &on_power_up, 1, out, outlen));
}

int
mesh_gen_power_onoff_cli_recv(struct mesh_gen_power_onoff_cli *cli,
    uint32_t opcode, const uint8_t *params, size_t plen)
{
	if (cli == NULL || opcode != MESH_OP_GEN_ONPOWERUP_STATUS ||
	    params == NULL || plen != 1 || params[0] > MESH_GEN_ONPOWERUP_RESTORE)
		return (-1);
	cli->on_power_up = params[0];
	cli->have_status = 1;
	return (0);
}

void
mesh_gen_power_level_cli_init(struct mesh_gen_power_level_cli *cli)
{
	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

static int
power_cli_empty(uint32_t opcode, uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(opcode, NULL, 0, out, outlen));
}

int
mesh_gen_power_level_cli_get(uint8_t *out, size_t *outlen)
{
	return (power_cli_empty(MESH_OP_GEN_POWER_LEVEL_GET, out, outlen));
}

int
mesh_gen_power_last_cli_get(uint8_t *out, size_t *outlen)
{
	return (power_cli_empty(MESH_OP_GEN_POWER_LAST_GET, out, outlen));
}

int
mesh_gen_power_default_cli_get(uint8_t *out, size_t *outlen)
{
	return (power_cli_empty(MESH_OP_GEN_POWER_DEFAULT_GET, out, outlen));
}

int
mesh_gen_power_range_cli_get(uint8_t *out, size_t *outlen)
{
	return (power_cli_empty(MESH_OP_GEN_POWER_RANGE_GET, out, outlen));
}

int
mesh_gen_power_level_cli_set(uint16_t power, uint8_t tid, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3] = { (uint8_t)power, (uint8_t)(power >> 8), tid };

	return (mesh_access_pdu_build(ack ? MESH_OP_GEN_POWER_LEVEL_SET :
	    MESH_OP_GEN_POWER_LEVEL_SET_UNACK, p, sizeof(p), out, outlen));
}

int
mesh_gen_power_default_cli_set(uint16_t power, int ack, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2] = { (uint8_t)power, (uint8_t)(power >> 8) };

	return (mesh_access_pdu_build(ack ? MESH_OP_GEN_POWER_DEFAULT_SET :
	    MESH_OP_GEN_POWER_DEFAULT_SET_UNACK, p, sizeof(p), out, outlen));
}

int
mesh_gen_power_range_cli_set(uint16_t min, uint16_t max, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (min == 0 || max == 0 || max < min)
		return (-1);
	p[0] = (uint8_t)min;
	p[1] = (uint8_t)(min >> 8);
	p[2] = (uint8_t)max;
	p[3] = (uint8_t)(max >> 8);
	return (mesh_access_pdu_build(ack ? MESH_OP_GEN_POWER_RANGE_SET :
	    MESH_OP_GEN_POWER_RANGE_SET_UNACK, p, sizeof(p), out, outlen));
}

int
mesh_gen_power_level_cli_recv(struct mesh_gen_power_level_cli *cli,
    uint32_t opcode, const uint8_t *params, size_t plen)
{
	uint16_t value;

	if (cli == NULL || params == NULL)
		return (-1);
	if (opcode == MESH_OP_GEN_POWER_RANGE_STATUS) {
		if (plen != 5 || params[0] > 2)
			return (-1);
		cli->range_status = params[0];
		cli->range_min = (uint16_t)params[1] | ((uint16_t)params[2] << 8);
		cli->range_max = (uint16_t)params[3] | ((uint16_t)params[4] << 8);
		cli->have_range = 1;
		return (0);
	}
	if (plen != 2 && !(opcode == MESH_OP_GEN_POWER_LEVEL_STATUS && plen == 5))
		return (-1);
	value = (uint16_t)params[0] | ((uint16_t)params[1] << 8);
	switch (opcode) {
	case MESH_OP_GEN_POWER_LEVEL_STATUS:
		if (plen == 5 && !mesh_gen_transition_time_valid(params[4]))
			return (-1);
		cli->actual = value;
		cli->have_actual = 1;
		break;
	case MESH_OP_GEN_POWER_LAST_STATUS:
		if (value == 0) return (-1);
		cli->last = value;
		cli->have_last = 1;
		break;
	case MESH_OP_GEN_POWER_DEFAULT_STATUS:
		cli->default_power = value;
		cli->have_default = 1;
		break;
	default:
		return (-1);
	}
	return (0);
}

void
mesh_gen_battery_cli_init(struct mesh_gen_battery_cli *cli)
{
	if (cli != NULL)
		memset(cli, 0, sizeof(*cli));
}

int
mesh_gen_battery_cli_get(uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(MESH_OP_GEN_BATTERY_GET, NULL, 0, out,
	    outlen));
}

int
mesh_gen_battery_cli_recv(struct mesh_gen_battery_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	if (cli == NULL || opcode != MESH_OP_GEN_BATTERY_STATUS ||
	    mesh_gen_battery_status_decode(params, plen, &cli->last) != 0)
		return (-1);
	cli->have_status = 1;
	return (0);
}

void
mesh_gen_location_cli_init(struct mesh_gen_location_cli *cli)
{
	if (cli != NULL) memset(cli, 0, sizeof(*cli));
}

int
mesh_gen_location_cli_get(int global, uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(global ? MESH_OP_GEN_LOCATION_GLOBAL_GET :
	    MESH_OP_GEN_LOCATION_LOCAL_GET, NULL, 0, out, outlen));
}

int
mesh_gen_location_cli_set_global(const struct mesh_gen_location_global *in,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t p[10];
	if (mesh_gen_location_global_encode(in, p) != 0) return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_GEN_LOCATION_GLOBAL_SET :
	    MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK, p, sizeof(p), out, outlen));
}

int
mesh_gen_location_cli_set_local(const struct mesh_gen_location_local *in,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t p[9];
	if (mesh_gen_location_local_encode(in, p) != 0) return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_GEN_LOCATION_LOCAL_SET :
	    MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK, p, sizeof(p), out, outlen));
}

int
mesh_gen_location_cli_recv(struct mesh_gen_location_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	if (cli == NULL) return (-1);
	if (opcode == MESH_OP_GEN_LOCATION_GLOBAL_STATUS) {
		if (mesh_gen_location_global_decode(params, plen, &cli->global) != 0)
			return (-1);
		cli->have_global = 1;
	} else if (opcode == MESH_OP_GEN_LOCATION_LOCAL_STATUS) {
		if (mesh_gen_location_local_decode(params, plen, &cli->local) != 0)
			return (-1);
		cli->have_local = 1;
	} else return (-1);
	return (0);
}

int
mesh_gen_onoff_cli_recv(struct mesh_gen_onoff_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	struct mesh_gen_onoff_status st;

	if (cli == NULL || opcode != MESH_OP_GEN_ONOFF_STATUS)
		return (-1);
	if (mesh_gen_onoff_status_decode(params, plen, &st) != 0)
		return (-1);
	cli->last = st;
	cli->have_status = 1;
	return (0);
}

int
mesh_gen_level_cli_recv(struct mesh_gen_level_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	struct mesh_gen_level_status st;

	if (cli == NULL || opcode != MESH_OP_GEN_LEVEL_STATUS)
		return (-1);
	if (mesh_gen_level_status_decode(params, plen, &st) != 0)
		return (-1);
	cli->last = st;
	cli->have_status = 1;
	return (0);
}
