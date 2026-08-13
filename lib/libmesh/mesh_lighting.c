/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <string.h>

#include "mesh_lighting.h"

static uint16_t
get_u16(const uint8_t * p){
        return ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}

static void
put_u16(uint8_t * p, uint16_t value)
{
        p[0] = value;
        p[1] = value >> 8;
}

static int
put_transition(uint8_t *params, size_t mandatory_len,
    const struct mesh_light_transition *transition, size_t *params_len)
{
	if (transition == NULL || params_len == NULL)
		return (-1);
	*params_len = mandatory_len;
	if (!transition->has_transition)
		return (0);
	params[mandatory_len] = transition->transition_time;
	params[mandatory_len + 1] = transition->delay;
	*params_len += 2;
	return (0);
}

static int
lighting_tid_is_new(uint16_t *last_src, uint16_t *last_dst,
    uint8_t *last_tid, int *valid, uint64_t *expires_ms, uint16_t src,
    uint16_t dst, uint8_t tid, uint64_t now_ms)
{
	if (*valid && *last_src == src && *last_dst == dst && *last_tid == tid &&
	    now_ms <= *expires_ms) {
		/*
		 * MMDL Section 3.1: the 6 s transaction window runs from the
		 * PREVIOUS same-TID message, so a retransmission refreshes it.
		 */
		*expires_ms = now_ms + 6000;
		return (0);
	}
	*last_src = src;
	*last_dst = dst;
	*last_tid = tid;
	*valid = 1;
	*expires_ms = now_ms + 6000;
	return (1);
}

static uint8_t
lighting_remaining(uint64_t now_ms, const struct mesh_transition_state *a,
    const struct mesh_transition_state *b,
    const struct mesh_transition_state *c)
{
	const struct mesh_transition_state *states[] = { a, b, c };
	uint64_t end_ms = now_ms;
	size_t i;

	for (i = 0; i < sizeof(states) / sizeof(states[0]); i++)
		if (states[i] != NULL && states[i]->active &&
		    states[i]->end_ms > end_ms)
			end_ms = states[i]->end_ms;
	return (mesh_transition_remaining(end_ms - now_ms));
}

static uint8_t
lighting_effective_transition(const struct mesh_light_lightness_srv *lightness,
    int has, uint8_t explicit_time)
{
	if (has && (explicit_time & 0x3f) != 0x3f)
		return (explicit_time);
	return (lightness != NULL && lightness->dtt != NULL ?
	    lightness->dtt->transition_time : 0);
}

static uint16_t
isqrt32(uint32_t value) {
        uint32_t result = 0, bit = UINT32_C(1) << 30;

        while (bit > value)
                bit >>= 2;
        while (bit != 0) {
                if (value >= result + bit) {
                        value -= result + bit;
                        result = (result >> 1) + bit;
                } else
                        result >>= 1;
                bit >>= 2;
        }
        return (result > UINT16_MAX ? UINT16_MAX : (uint16_t) result);
}

uint16_t
mesh_light_lightness_linear(uint16_t actual) {
        /*
         * MMDL Section 6.1.2.2.1: Linear = Ceil(65535 * (Actual/65535)^2)
         * = Ceil(Actual^2 / 65535).  Round up so a non-zero Actual never
         * maps to Linear 0.
         */
        return (((uint32_t) actual * actual + (UINT16_MAX - 1)) / UINT16_MAX);
}

static void
lightness_bind(struct mesh_light_lightness_srv *srv)
{
	if (srv->onoff != NULL)
		mesh_gen_onoff_srv_set_present(srv->onoff, srv->actual != 0);
	if (srv->level != NULL)
		mesh_gen_level_srv_set_present(srv->level,
		    (int16_t)((int32_t)srv->actual - 32768));
}

static int
lightness_value_valid(const struct mesh_light_lightness_srv *srv,
    uint16_t lightness)
{
	return (srv != NULL && (lightness == 0 ||
	    (lightness >= srv->range_min && lightness <= srv->range_max)));
}

/*
 * MMDL Section 6.1.2.2.5: a non-zero Lightness outside [Range Min, Range Max]
 * is clamped to the nearer limit (0 stays 0 = off), never rejected.
 */
static uint16_t
lightness_clamp(const struct mesh_light_lightness_srv *srv, uint16_t lightness)
{
	if (lightness == 0)
		return (0);
	if (lightness < srv->range_min)
		return (srv->range_min);
	if (lightness > srv->range_max)
		return (srv->range_max);
	return (lightness);
}

void
mesh_light_lightness_srv_init(struct mesh_light_lightness_srv *srv,
         struct mesh_gen_onoff_srv *onoff, struct mesh_gen_level_srv *level)
{
        if (srv == NULL)
                return;
        memset(srv, 0, sizeof(*srv));
        srv->last = UINT16_MAX;
        srv->range_min = 1;
        srv->range_max = UINT16_MAX;
        srv->onoff = onoff;
        srv->level = level;
}

int
mesh_light_lightness_set_actual(struct mesh_light_lightness_srv *srv,
                                uint16_t actual)
{
	if (!lightness_value_valid(srv, actual))
                return (-1);
        srv->actual = actual;
        if (actual != 0)
                srv->last = actual;
        lightness_bind(srv);
        return (0);
}

int
mesh_light_lightness_set_linear(struct mesh_light_lightness_srv *srv,
                                uint16_t linear)
{
        uint16_t actual = isqrt32((uint32_t) linear * UINT16_MAX);
        return (mesh_light_lightness_set_actual(srv, actual));
}

static void
lightness_update(struct mesh_light_lightness_srv *srv, uint64_t now_ms)
{
	uint16_t actual;

	if (srv == NULL || !srv->transition.active)
		return;
	actual = (uint16_t)mesh_transition_sample(&srv->transition, now_ms);
	(void)mesh_light_lightness_set_actual(srv, actual);
}

static void
lightness_tick(void *arg, uint64_t now_ms)
{
	lightness_update(arg, now_ms);
}

static void
lightness_status(struct mesh_model_reply *reply,
    struct mesh_light_lightness_srv *srv, int linear, uint64_t now_ms)
{
	uint16_t present, target;
	uint64_t remaining;

	present = linear ? mesh_light_lightness_linear(srv->actual) : srv->actual;
	put_u16(reply->params, present);
	if (!srv->transition.active) {
		reply->params_len = 2;
		return;
	}
	target = (uint16_t)srv->transition.target;
	if (linear)
		target = mesh_light_lightness_linear(target);
	put_u16(reply->params + 2, target);
	remaining = srv->transition.end_ms > now_ms ?
	    srv->transition.end_ms - now_ms : 0;
	reply->params[4] = mesh_transition_remaining(remaining);
	reply->params_len = 5;
}

static void
reply_init(const struct mesh_access_rx *rx, struct mesh_model_reply *reply,
           uint32_t opcode)
{
        memset(reply, 0, sizeof(*reply));
        reply->have_reply = 1;
        reply->src = rx->elem_addr;
        reply->dst = rx->src;
        reply->opcode = opcode;
}

static int
lightness_srv_handler(const struct mesh_access_rx *rx)
{
        struct mesh_light_lightness_srv *srv = rx->model_user;
        struct mesh_model_reply *reply = rx->ctx;
        uint16_t value;
	uint8_t transition_time;
        int     linear, ack;

	if (srv == NULL || reply == NULL)
		return (-1);
	lightness_update(srv, rx->now_ms);
        linear = rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET ||
                rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET ||
                rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK;
        switch (rx->pdu->opcode) {
        case MESH_OP_LIGHT_LIGHTNESS_GET:
        case MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET:
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, linear ? MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS :
                           MESH_OP_LIGHT_LIGHTNESS_STATUS);
		lightness_status(reply, srv, linear, rx->now_ms);
                return (0);
        case MESH_OP_LIGHT_LIGHTNESS_LAST_GET:
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS);
                put_u16(reply->params, srv->last);
                reply->params_len = 2;
                return (0);
        case MESH_OP_LIGHT_LIGHTNESS_DEFAULT_GET:
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS);
                put_u16(reply->params, srv->default_lightness);
                reply->params_len = 2;
                return (0);
        case MESH_OP_LIGHT_LIGHTNESS_RANGE_GET:
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS);
                reply->params[0] = srv->range_status;
                put_u16(reply->params + 1, srv->range_min);
                put_u16(reply->params + 3, srv->range_max);
                reply->params_len = 5;
                return (0);
        case MESH_OP_LIGHT_LIGHTNESS_SET:
        case MESH_OP_LIGHT_LIGHTNESS_SET_UNACK:
	case MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET:
	case MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK:
			if (rx->pdu->params_len != 3 &&
			    rx->pdu->params_len != 5)
                        return (-1);
                value = get_u16(rx->pdu->params);
                ack = rx->pdu->opcode ==
                        MESH_OP_LIGHT_LIGHTNESS_SET || rx->pdu->opcode ==
                        MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET;
		if (lighting_tid_is_new(&srv->last_src, &srv->last_dst,
		    &srv->last_tid,
		    &srv->tid_valid, &srv->tid_expires_ms, rx->src,
		    rx->dst, rx->pdu->params[2], rx->now_ms)) {
			uint16_t target;

			transition_time = lighting_effective_transition(srv,
			    rx->pdu->params_len == 5,
			    rx->pdu->params_len == 5 ? rx->pdu->params[3] : 0);
			/*
			 * Resolve the target in Actual space (Linear Set
			 * converts first) and clamp an out-of-range value to
			 * the Range rather than dropping the message
			 * (MMDL Section 6.1.2.2.5).
			 */
			target = linear ?
			    isqrt32((uint32_t)value * UINT16_MAX) : value;
			target = lightness_clamp(srv, target);
			if ((rx->pdu->params_len == 5 &&
			    rx->pdu->params[4] != 0) ||
			    mesh_transition_time_ms(transition_time) != 0) {
				mesh_transition_start(&srv->transition, srv->actual,
				    target, transition_time,
				    rx->pdu->params_len == 5 ? rx->pdu->params[4] : 0,
				    rx->now_ms);
			} else {
				srv->transition.active = 0;
				(void)mesh_light_lightness_set_actual(srv, target);
			}
                }
                if (!ack) {
                        memset(reply, 0, sizeof(*reply));
                        return (0);
                }
                reply_init(rx, reply, linear ? MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS :
                           MESH_OP_LIGHT_LIGHTNESS_STATUS);
		lightness_status(reply, srv, linear, rx->now_ms);
                return (0);
        default:
                return (-1);
        }
}

static int
lightness_setup_handler(const struct mesh_access_rx *rx)
{
        struct mesh_light_lightness_srv *srv = rx->model_user;
        struct mesh_model_reply *reply = rx->ctx;
        uint16_t min, max;
        int     ack;

        if (srv == NULL || reply == NULL)
                return (-1);
        ack = rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET ||
                rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_RANGE_SET;
        if (rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET ||
            rx->pdu->opcode == MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK) {
		if (rx->pdu->params_len != 2)
			return (-1);
		/*
		 * MMDL Section 6.1.2.4: the Light Lightness Default is a plain
		 * 0x0000-0xFFFF value (0 = use Last) with no Range binding, so
		 * it is not validated against Range Min/Max.
		 */
		srv->default_lightness = get_u16(rx->pdu->params);
                if (!ack) {
                        memset(reply, 0, sizeof(*reply));
                        return (0);
                }
                reply_init(rx, reply, MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS);
                put_u16(reply->params, srv->default_lightness);
                reply->params_len = 2;
                return (0);
        }
        if ((rx->pdu->opcode != MESH_OP_LIGHT_LIGHTNESS_RANGE_SET &&
             rx->pdu->opcode != MESH_OP_LIGHT_LIGHTNESS_RANGE_SET_UNACK) ||
            rx->pdu->params_len != 4)
                return (-1);
        min = get_u16(rx->pdu->params);
        max = get_u16(rx->pdu->params + 2);
        if (min == 0 || max == 0 || min > max)
                return (-1);
        srv->range_min = min;
        srv->range_max = max;
        srv->range_status = 0;
        if (!ack) {
                memset(reply, 0, sizeof(*reply));
                return (0);
        }
        reply_init(rx, reply, MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS);
        reply->params[0] = 0;
        put_u16(reply->params + 1, min);
        put_u16(reply->params + 3, max);
        reply->params_len = 5;
        return (0);
}

static const struct mesh_opcode_entry lightness_srv_ops[] = {
        {MESH_OP_LIGHT_LIGHTNESS_GET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_SET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_SET_UNACK, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_LAST_GET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_DEFAULT_GET, lightness_srv_handler},
        {MESH_OP_LIGHT_LIGHTNESS_RANGE_GET, lightness_srv_handler},
};
static const struct mesh_opcode_entry lightness_setup_ops[] = {
        {MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET, lightness_setup_handler},
        {MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK, lightness_setup_handler},
        {MESH_OP_LIGHT_LIGHTNESS_RANGE_SET, lightness_setup_handler},
        {MESH_OP_LIGHT_LIGHTNESS_RANGE_SET_UNACK, lightness_setup_handler},
};

static struct mesh_model
lighting_model(void *user, uint16_t id, const struct mesh_opcode_entry *ops,
    size_t nops)
{
        struct mesh_model model;
        memset(&model, 0, sizeof(model));
        model.model_id = id;
        model.company_id = MESH_COMPANY_SIG;
        model.ops = ops;
        model.n_ops = nops;
	model.user = user;
        return (model);
}

struct mesh_model
mesh_light_lightness_srv_model(struct mesh_light_lightness_srv *srv)
{
	struct mesh_model model;

	model = lighting_model(srv, MESH_MODEL_LIGHT_LIGHTNESS_SRV,
	    lightness_srv_ops, sizeof(lightness_srv_ops) /
	    sizeof(lightness_srv_ops[0]));
	model.tick = lightness_tick;
	return (model);
}

struct mesh_model
mesh_light_lightness_setup_srv_model(struct mesh_light_lightness_srv *srv)
{
	return (lighting_model(srv, MESH_MODEL_LIGHT_LIGHTNESS_SETUP_SRV,
                                lightness_setup_ops, sizeof(lightness_setup_ops) / sizeof(lightness_setup_ops[0])));
}

void
mesh_light_lightness_cli_init(struct mesh_light_lightness_cli *cli)
{
        if (cli != NULL)
                memset(cli, 0, sizeof(*cli));
}

int
mesh_light_lightness_cli_get(uint32_t opcode, uint8_t * out, size_t * outlen)
{
        if (opcode != MESH_OP_LIGHT_LIGHTNESS_GET &&
            opcode != MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET &&
            opcode != MESH_OP_LIGHT_LIGHTNESS_LAST_GET &&
            opcode != MESH_OP_LIGHT_LIGHTNESS_DEFAULT_GET &&
            opcode != MESH_OP_LIGHT_LIGHTNESS_RANGE_GET)
                return (-1);
        return (mesh_access_pdu_build(opcode, NULL, 0, out, outlen));
}

static int
lightness_cli_set(uint32_t opcode, const struct mesh_light_lightness_set *set,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[5];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	params[2] = set->tid;
	if (put_transition(params, 3, &set->transition, &params_len) != 0)
		return (-1);
	if (!ack)
		opcode = opcode == MESH_OP_LIGHT_LIGHTNESS_SET ?
			MESH_OP_LIGHT_LIGHTNESS_SET_UNACK : MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, params_len, out, outlen));
}

int
mesh_light_lightness_cli_actual_set(const struct mesh_light_lightness_set *set,
    int ack, uint8_t *out, size_t *outlen)
{
	return (lightness_cli_set(MESH_OP_LIGHT_LIGHTNESS_SET, set, ack, out,
	    outlen));
}

int
mesh_light_lightness_cli_linear_set(const struct mesh_light_lightness_set *set,
    int ack, uint8_t *out, size_t *outlen)
{
	return (lightness_cli_set(MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET, set, ack,
	    out, outlen));
}

int
mesh_light_lightness_cli_default_set(uint16_t lightness, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	put_u16(params, lightness);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET :
	    MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK, params, sizeof(params), out,
	    outlen));
}

int
mesh_light_lightness_cli_range_set(uint16_t min, uint16_t max, int ack,
                                   uint8_t * out, size_t * outlen)
{
        uint8_t params[4];
        if (min == 0 || max == 0 || min > max)
                return (-1);
        put_u16(params, min);
        put_u16(params + 2, max);
        return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_LIGHTNESS_RANGE_SET :
        MESH_OP_LIGHT_LIGHTNESS_RANGE_SET_UNACK, params, sizeof(params), out,
                                      outlen));
}

int
mesh_light_lightness_cli_recv(struct mesh_light_lightness_cli *cli,
                        uint32_t opcode, const uint8_t * params, size_t len)
{
        if (cli == NULL || params == NULL)
                return (-1);
        switch (opcode) {
	case MESH_OP_LIGHT_LIGHTNESS_STATUS:
		if (len != 2 && len != 5)
			return (-1);
		cli->actual = get_u16(params);
		cli->has_target = len == 5;
		if (len == 5) {
			cli->target = get_u16(params + 2);
			cli->remaining_time = params[4];
		}
		break;
	case MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS:
		if (len != 2 && len != 5)
			return (-1);
		cli->linear = get_u16(params);
		cli->has_target = len == 5;
		if (len == 5) {
			cli->target = get_u16(params + 2);
			cli->remaining_time = params[4];
		}
                break;
        case MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS:
                if (len != 2)
                        return (-1);
                cli->last = get_u16(params);
                break;
        case MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS:
                if (len != 2)
                        return (-1);
                cli->default_lightness = get_u16(params);
                break;
        case MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS:
                if (len != 5 || params[0] > 2)
                        return (-1);
                cli->range_status = params[0];
                cli->range_min = get_u16(params + 1);
                cli->range_max = get_u16(params + 3);
                break;
        default:
                return (-1);
        }
        return (0);
}

void
mesh_light_ctl_srv_init(struct mesh_light_ctl_srv *srv,
                        struct mesh_light_lightness_srv *lightness)
{
        if (srv == NULL)
                return;
        memset(srv, 0, sizeof(*srv));
        srv->temperature = 0x0320;
        srv->default_temperature = srv->temperature;
        srv->range_min = 0x0320;
        srv->range_max = 0x4e20;
        srv->lightness = lightness;
}

/*
 * MMDL Section 6.1.3.1.3: a CTL Temperature outside [Range Min, Range Max] is
 * clamped to the nearer limit, not rejected (same binding as CTL Set).
 */
static uint16_t
ctl_temp_clamp(const struct mesh_light_ctl_srv *srv, uint16_t temperature)
{
	if (temperature < srv->range_min)
		return (srv->range_min);
	if (temperature > srv->range_max)
		return (srv->range_max);
	return (temperature);
}

static int16_t
ctl_level_from_temperature(const struct mesh_light_ctl_srv *srv)
{
	uint32_t span, offset;

	span = (uint32_t)srv->range_max - srv->range_min;
	if (span == 0)
		return (INT16_MIN);
	if (srv->temperature <= srv->range_min)
		return (INT16_MIN);
	if (srv->temperature >= srv->range_max)
		return (INT16_MAX);
	offset = (uint32_t)srv->temperature - srv->range_min;
	return ((int16_t)((offset * UINT32_C(65535) + span / 2) / span -
	    UINT32_C(32768)));
}

static void
ctl_sync_level(struct mesh_light_ctl_srv *srv)
{

	if (srv->temperature_level != NULL)
		mesh_gen_level_srv_set_present(srv->temperature_level,
		    ctl_level_from_temperature(srv));
}

int
mesh_light_ctl_set(struct mesh_light_ctl_srv *srv, uint16_t lightness,
                   uint16_t temperature, int16_t delta_uv)
{
        if (srv == NULL || temperature < srv->range_min ||
            temperature > srv->range_max || srv->lightness == NULL ||
            mesh_light_lightness_set_actual(srv->lightness, lightness) != 0)
                return (-1);
        srv->temperature = temperature;
        srv->delta_uv = delta_uv;
	ctl_sync_level(srv);
        return (0);
}

static void
ctl_update(struct mesh_light_ctl_srv *srv, uint64_t now_ms)
{
	lightness_update(srv->lightness, now_ms);
	if (srv->temperature_transition.active)
		srv->temperature = (uint16_t)mesh_transition_sample(
		    &srv->temperature_transition, now_ms);
	if (srv->delta_uv_transition.active)
		srv->delta_uv = (int16_t)mesh_transition_sample(
		    &srv->delta_uv_transition, now_ms);
	ctl_sync_level(srv);
}

static void
ctl_tick(void *arg, uint64_t now_ms)
{
	ctl_update(arg, now_ms);
}

static int
ctl_transition_active(const struct mesh_light_ctl_srv *srv, int temp_only)
{
	return (srv->temperature_transition.active ||
	    srv->delta_uv_transition.active ||
	    (!temp_only && srv->lightness->transition.active));
}

static int
ctl_handler(const struct mesh_access_rx *rx)
{
        struct mesh_light_ctl_srv *srv = rx->model_user;
        struct mesh_model_reply *reply = rx->ctx;
        uint16_t lightness, temperature;
        int16_t delta;
	uint8_t transition_time, delay;
        int     temp_only, ack;

	if (srv == NULL || reply == NULL)
		return (-1);
	ctl_update(srv, rx->now_ms);
        temp_only = rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_GET ||
                rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_SET ||
                rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK;
        if (rx->pdu->opcode == MESH_OP_LIGHT_CTL_GET ||
            rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_GET) {
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, temp_only ? MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS :
                           MESH_OP_LIGHT_CTL_STATUS);
                if (temp_only) {
			put_u16(reply->params, srv->temperature);
			put_u16(reply->params + 2, (uint16_t) srv->delta_uv);
			if (ctl_transition_active(srv, 1)) {
				put_u16(reply->params + 4,
				    (uint16_t)srv->temperature_transition.target);
				put_u16(reply->params + 6,
				    (uint16_t)srv->delta_uv_transition.target);
				reply->params[8] = lighting_remaining(rx->now_ms,
				    &srv->temperature_transition,
				    &srv->delta_uv_transition, NULL);
				reply->params_len = 9;
			} else
				reply->params_len = 4;
		} else {
			put_u16(reply->params, srv->lightness->actual);
			put_u16(reply->params + 2, srv->temperature);
			if (ctl_transition_active(srv, 0)) {
				put_u16(reply->params + 4,
				    srv->lightness->transition.active ?
				    (uint16_t)srv->lightness->transition.target :
				    srv->lightness->actual);
				put_u16(reply->params + 6,
				    srv->temperature_transition.active ?
				    (uint16_t)srv->temperature_transition.target :
				    srv->temperature);
				reply->params[8] = lighting_remaining(rx->now_ms,
				    &srv->lightness->transition,
				    &srv->temperature_transition,
				    &srv->delta_uv_transition);
				reply->params_len = 9;
			} else
				reply->params_len = 4;
                }
                return (0);
        }
        if ((rx->pdu->opcode != MESH_OP_LIGHT_CTL_SET &&
             rx->pdu->opcode != MESH_OP_LIGHT_CTL_SET_UNACK &&
             rx->pdu->opcode != MESH_OP_LIGHT_CTL_TEMPERATURE_SET &&
             rx->pdu->opcode != MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK) ||
	    (rx->pdu->params_len != (temp_only ? 5 : 7) &&
	    rx->pdu->params_len != (temp_only ? 7 : 9)))
		return (-1);
        if (temp_only) {
                lightness = srv->lightness->actual;
                temperature = get_u16(rx->pdu->params);
                delta = (int16_t) get_u16(rx->pdu->params + 2);
        } else {
                lightness = get_u16(rx->pdu->params);
                temperature = get_u16(rx->pdu->params + 2);
                delta = (int16_t) get_u16(rx->pdu->params + 4);
        }
        ack = rx->pdu->opcode == MESH_OP_LIGHT_CTL_SET ||
                rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_SET;
	/*
	 * Clamp out-of-range components to their Range rather than dropping the
	 * whole message (MMDL Section 6.1.3.1.3 for Temperature, 6.1.2.2.5 for
	 * Lightness); this also keeps in-range composite components applied.
	 */
	temperature = ctl_temp_clamp(srv, temperature);
	if (!temp_only)
		lightness = lightness_clamp(srv->lightness, lightness);
	if (lighting_tid_is_new(&srv->last_src, &srv->last_dst, &srv->last_tid,
	    &srv->tid_valid, &srv->tid_expires_ms, rx->src,
	    rx->dst, rx->pdu->params[temp_only ? 4 : 6], rx->now_ms)) {
		transition_time = lighting_effective_transition(srv->lightness,
		    rx->pdu->params_len == (temp_only ? 7 : 9),
		    rx->pdu->params_len == (temp_only ? 7 : 9) ?
		    rx->pdu->params[temp_only ? 5 : 7] : 0);
		delay = rx->pdu->params_len == (temp_only ? 7 : 9) ?
		    rx->pdu->params[temp_only ? 6 : 8] : 0;
		if (delay != 0 || mesh_transition_time_ms(transition_time) != 0) {
			if (!temp_only)
				mesh_transition_start(&srv->lightness->transition,
				    srv->lightness->actual, lightness,
				    transition_time, delay,
				    rx->now_ms);
			mesh_transition_start(&srv->temperature_transition,
			    srv->temperature, temperature,
			    transition_time, delay, rx->now_ms);
			mesh_transition_start(&srv->delta_uv_transition,
			    srv->delta_uv, delta,
			    transition_time, delay, rx->now_ms);
		} else {
			srv->temperature_transition.active = 0;
			srv->delta_uv_transition.active = 0;
			if (!temp_only)
				srv->lightness->transition.active = 0;
			if (mesh_light_ctl_set(srv, lightness, temperature,
			    delta) != 0)
				return (-1);
		}
        }
        if (!ack) {
                memset(reply, 0, sizeof(*reply));
                return (0);
        }
        reply_init(rx, reply, temp_only ? MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS :
                   MESH_OP_LIGHT_CTL_STATUS);
	if (temp_only) {
		put_u16(reply->params, srv->temperature);
		put_u16(reply->params + 2, (uint16_t) srv->delta_uv);
		if (ctl_transition_active(srv, 1)) {
			put_u16(reply->params + 4,
			    srv->temperature_transition.active ?
			    (uint16_t)srv->temperature_transition.target :
			    srv->temperature);
			put_u16(reply->params + 6,
			    srv->delta_uv_transition.active ?
			    (uint16_t)srv->delta_uv_transition.target :
			    (uint16_t)srv->delta_uv);
			reply->params[8] = lighting_remaining(rx->now_ms,
			    &srv->temperature_transition, &srv->delta_uv_transition,
			    NULL);
			reply->params_len = 9;
		} else
			reply->params_len = 4;
	} else {
		put_u16(reply->params, srv->lightness->actual);
		put_u16(reply->params + 2, srv->temperature);
		if (ctl_transition_active(srv, 0)) {
			put_u16(reply->params + 4,
			    (uint16_t)srv->lightness->transition.target);
			put_u16(reply->params + 6,
			    (uint16_t)srv->temperature_transition.target);
			reply->params[8] = lighting_remaining(rx->now_ms,
			    &srv->lightness->transition, &srv->temperature_transition,
			    &srv->delta_uv_transition);
			reply->params_len = 9;
		} else
			reply->params_len = 4;
        }
        return (0);
}

static int
ctl_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_light_ctl_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint16_t default_lightness, default_temperature, min, max;
	int16_t default_delta_uv;
	int     ack;

        if (srv == NULL || reply == NULL)
                return (-1);
        ack = rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_SET ||
                rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET;
        if (rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_GET ||
            rx->pdu->opcode == MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_GET) {
                if (rx->pdu->params_len != 0)
                        return (-1);
                reply_init(rx, reply, rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_GET ?
                           MESH_OP_LIGHT_CTL_DEFAULT_STATUS : MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS);
                if (rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_GET) {
                        put_u16(reply->params, srv->default_lightness);
                        put_u16(reply->params + 2, srv->default_temperature);
                        put_u16(reply->params + 4, (uint16_t) srv->default_delta_uv);
                        reply->params_len = 6;
                } else {
                        reply->params[0] = srv->range_status;
                        put_u16(reply->params + 1, srv->range_min);
                        put_u16(reply->params + 3, srv->range_max);
                        reply->params_len = 5;
                }
                return (0);
        }
        if (rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_SET ||
            rx->pdu->opcode == MESH_OP_LIGHT_CTL_DEFAULT_SET_UNACK) {
                if (rx->pdu->params_len != 6)
                        return (-1);
                default_lightness = get_u16(rx->pdu->params);
                default_temperature = get_u16(rx->pdu->params + 2);
                default_delta_uv = (int16_t) get_u16(rx->pdu->params + 4);
		if (!lightness_value_valid(srv->lightness, default_lightness) ||
		    default_temperature < srv->range_min ||
		    default_temperature > srv->range_max)
                        return (-1);
                srv->default_lightness = default_lightness;
                srv->default_temperature = default_temperature;
                srv->default_delta_uv = default_delta_uv;
                if (!ack) {
                        memset(reply, 0, sizeof(*reply));
                        return (0);
                }
                reply_init(rx, reply, MESH_OP_LIGHT_CTL_DEFAULT_STATUS);
                memcpy(reply->params, rx->pdu->params, 6);
                reply->params_len = 6;
                return (0);
        }
        if ((rx->pdu->opcode != MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET &&
        rx->pdu->opcode != MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACK) ||
            rx->pdu->params_len != 4)
                return (-1);
        min = get_u16(rx->pdu->params);
        max = get_u16(rx->pdu->params + 2);
        if (min < 0x0320 || max > 0x4e20 || min > max)
                return (-1);
        srv->range_min = min;
        srv->range_max = max;
        srv->range_status = 0;
	ctl_sync_level(srv);
        if (!ack) {
                memset(reply, 0, sizeof(*reply));
                return (0);
        }
        reply_init(rx, reply, MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS);
        reply->params[0] = 0;
        put_u16(reply->params + 1, min);
        put_u16(reply->params + 3, max);
        reply->params_len = 5;
        return (0);
}

static const struct mesh_opcode_entry ctl_ops[] = {
        {MESH_OP_LIGHT_CTL_GET, ctl_handler}, {MESH_OP_LIGHT_CTL_SET, ctl_handler},
        {MESH_OP_LIGHT_CTL_SET_UNACK, ctl_handler},
};
static const struct mesh_opcode_entry ctl_temp_ops[] = {
        {MESH_OP_LIGHT_CTL_TEMPERATURE_GET, ctl_handler},
        {MESH_OP_LIGHT_CTL_TEMPERATURE_SET, ctl_handler}, {MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK, ctl_handler},
};
static const struct mesh_opcode_entry ctl_setup_ops[] = {
        {MESH_OP_LIGHT_CTL_DEFAULT_GET, ctl_setup_handler}, {MESH_OP_LIGHT_CTL_DEFAULT_SET, ctl_setup_handler},
        {MESH_OP_LIGHT_CTL_DEFAULT_SET_UNACK, ctl_setup_handler}, {MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_GET, ctl_setup_handler},
        {MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET, ctl_setup_handler}, {MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACK, ctl_setup_handler},
};
struct mesh_model mesh_light_ctl_srv_model(struct mesh_light_ctl_srv *s){
	struct mesh_model model = lighting_model(s, MESH_MODEL_LIGHT_CTL_SRV,
	    ctl_ops, sizeof(ctl_ops) / sizeof(ctl_ops[0]));
	model.tick = ctl_tick;
	return (model);
}
struct mesh_model mesh_light_ctl_setup_srv_model(struct mesh_light_ctl_srv *s){
	return (lighting_model(s, MESH_MODEL_LIGHT_CTL_SETUP_SRV, ctl_setup_ops, sizeof(ctl_setup_ops) / sizeof(ctl_setup_ops[0])));
}
struct mesh_model mesh_light_ctl_temp_srv_model(struct mesh_light_ctl_srv *s){
	struct mesh_model model = lighting_model(s, MESH_MODEL_LIGHT_CTL_TEMP_SRV,
	    ctl_temp_ops, sizeof(ctl_temp_ops) / sizeof(ctl_temp_ops[0]));
	model.tick = ctl_tick;
	return (model);
}
void    mesh_light_ctl_cli_init(struct mesh_light_ctl_cli *c){
        if (c != NULL)
                memset(c, 0, sizeof(*c));
}
int     mesh_light_ctl_cli_get(uint32_t op, uint8_t * o, size_t * n) {
        if (op != MESH_OP_LIGHT_CTL_GET && op != MESH_OP_LIGHT_CTL_TEMPERATURE_GET && op != MESH_OP_LIGHT_CTL_DEFAULT_GET && op != MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_GET)
                return (-1);
        return (mesh_access_pdu_build(op, NULL, 0, o, n));
}
int
mesh_light_ctl_cli_set(const struct mesh_light_ctl_set *set, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[9];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->temperature);
	put_u16(params + 4, (uint16_t)set->delta_uv);
	params[6] = set->tid;
	if (put_transition(params, 7, &set->transition, &params_len) != 0)
		return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_CTL_SET :
	    MESH_OP_LIGHT_CTL_SET_UNACK, params, params_len, out, outlen));
}

int
mesh_light_ctl_cli_temperature_set(
    const struct mesh_light_ctl_temperature_set *set, int ack, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[7];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->temperature);
	put_u16(params + 2, (uint16_t)set->delta_uv);
	params[4] = set->tid;
	if (put_transition(params, 5, &set->transition, &params_len) != 0)
		return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_CTL_TEMPERATURE_SET :
	    MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK, params, params_len, out,
	    outlen));
}

int
mesh_light_ctl_cli_default_set(const struct mesh_light_ctl_default *set,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[6];

	if (set == NULL || set->temperature < 0x0320 ||
	    set->temperature > 0x4e20)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->temperature);
	put_u16(params + 4, (uint16_t)set->delta_uv);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_CTL_DEFAULT_SET :
	    MESH_OP_LIGHT_CTL_DEFAULT_SET_UNACK, params, sizeof(params), out,
	    outlen));
}

int
mesh_light_ctl_cli_temperature_range_set(uint16_t min, uint16_t max, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[4];

	if (min < 0x0320 || max > 0x4e20 || min > max)
		return (-1);
	put_u16(params, min);
	put_u16(params + 2, max);
	return (mesh_access_pdu_build(ack ?
	    MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET :
	    MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACK, params, sizeof(params),
	    out, outlen));
}
int     mesh_light_ctl_cli_recv(struct mesh_light_ctl_cli *c, uint32_t op, const uint8_t * p, size_t n){
        if (c == NULL || p == NULL)
                return (-1);
	if (op == MESH_OP_LIGHT_CTL_STATUS && (n == 4 || n == 9)) {
		c->lightness = get_u16(p);
		c->temperature = get_u16(p + 2);
		c->has_target = n == 9;
		if (n == 9) {
			c->target_lightness = get_u16(p + 4);
			c->target_temperature = get_u16(p + 6);
			c->remaining_time = p[8];
		}
		return 0;
	} if (op == MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS && (n == 4 || n == 9)) {
		c->temperature = get_u16(p);
		c->delta_uv = (int16_t) get_u16(p + 2);
		c->has_target = n == 9;
		if (n == 9) {
			c->target_temperature = get_u16(p + 4);
			c->target_delta_uv = (int16_t)get_u16(p + 6);
			c->remaining_time = p[8];
		}
		return 0;
	} if (op == MESH_OP_LIGHT_CTL_DEFAULT_STATUS && n == 6) {
		c->lightness = get_u16(p);
		c->temperature = get_u16(p + 2);
		c->delta_uv = (int16_t)get_u16(p + 4);
		return 0;
	} if (op == MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS && n == 5) {
                if (p[0] > 2)
                        return -1;
                c->range_status = p[0];
                c->range_min = get_u16(p + 1);
                c->range_max = get_u16(p + 3);
                return 0;
        } return -1;
}

void
mesh_light_hsl_srv_init(struct mesh_light_hsl_srv *srv,
                        struct mesh_light_lightness_srv *lightness)
{
        if (srv == NULL)
                return;
        memset(srv, 0, sizeof(*srv));
        srv->hue_max = UINT16_MAX;
        srv->saturation_max = UINT16_MAX;
        srv->lightness = lightness;
}

static int
hsl_hue_in_range(const struct mesh_light_hsl_srv *srv, uint16_t hue)
{

	if (srv->hue_min <= srv->hue_max)
		return (hue >= srv->hue_min && hue <= srv->hue_max);
	return (hue >= srv->hue_min || hue <= srv->hue_max);
}

/*
 * MMDL Section 6.1.4.6.2: an out-of-range Hue is clamped to the nearer
 * configured boundary, not rejected.  A wrapping range (Min > Max) clamps to
 * whichever boundary is nearer within the excluded (Max, Min) gap.
 */
static uint16_t
hsl_hue_clamp(const struct mesh_light_hsl_srv *srv, uint16_t hue)
{
	if (hsl_hue_in_range(srv, hue))
		return (hue);
	if (srv->hue_min <= srv->hue_max)
		return (hue < srv->hue_min ? srv->hue_min : srv->hue_max);
	return ((uint16_t)(srv->hue_min - hue) <= (uint16_t)(hue - srv->hue_max) ?
	    srv->hue_min : srv->hue_max);
}

/* MMDL Section 6.1.4.7.2: an out-of-range Saturation is clamped to Range. */
static uint16_t
hsl_saturation_clamp(const struct mesh_light_hsl_srv *srv, uint16_t saturation)
{
	if (saturation < srv->saturation_min)
		return (srv->saturation_min);
	if (saturation > srv->saturation_max)
		return (srv->saturation_max);
	return (saturation);
}

static uint16_t
hsl_hue_transition_sample(struct mesh_light_hsl_srv *srv, uint64_t now_ms)
{
	struct mesh_transition_state *state = &srv->hue_transition;
	uint32_t initial, target, span;
	int64_t elapsed, duration, position;

	if (srv->hue_min == 0 && srv->hue_max == UINT16_MAX)
		return (mesh_transition_sample_u16_circular(state, now_ms));
	if (srv->hue_min <= srv->hue_max)
		return ((uint16_t)mesh_transition_sample(state, now_ms));
	if (!state->active || now_ms < state->start_ms || now_ms >= state->end_ms)
		return ((uint16_t)mesh_transition_sample(state, now_ms));
	span = (uint16_t)(srv->hue_max - srv->hue_min);
	initial = (uint16_t)((uint16_t)state->initial - srv->hue_min);
	target = (uint16_t)((uint16_t)state->target - srv->hue_min);
	if (initial > span || target > span)
		return ((uint16_t)mesh_transition_sample(state, now_ms));
	duration = (int64_t)(state->end_ms - state->start_ms);
	elapsed = (int64_t)(now_ms - state->start_ms);
	position = (int64_t)initial +
	    ((int64_t)target - initial) * elapsed / duration;
	return ((uint16_t)(srv->hue_min + position));
}

static void
hsl_sync_levels(struct mesh_light_hsl_srv *srv)
{

	if (srv->hue_level != NULL)
		mesh_gen_level_srv_set_present(srv->hue_level,
		    (int16_t)((int32_t)srv->hue - 32768));
	if (srv->saturation_level != NULL)
		mesh_gen_level_srv_set_present(srv->saturation_level,
		    (int16_t)((int32_t)srv->saturation - 32768));
}

int
mesh_light_hsl_set(struct mesh_light_hsl_srv *srv, uint16_t lightness,
                   uint16_t hue, uint16_t saturation)
{
	if (srv == NULL || srv->lightness == NULL ||
	    !hsl_hue_in_range(srv, hue) || saturation < srv->saturation_min ||
            saturation > srv->saturation_max ||
            mesh_light_lightness_set_actual(srv->lightness, lightness) != 0)
                return (-1);
        srv->hue = hue;
        srv->saturation = saturation;
	hsl_sync_levels(srv);
        return (0);
}

static void
hsl_update(struct mesh_light_hsl_srv *srv, uint64_t now_ms)
{
	lightness_update(srv->lightness, now_ms);
	if (srv->hue_transition.active)
		srv->hue = hsl_hue_transition_sample(srv, now_ms);
	if (srv->saturation_transition.active)
		srv->saturation = (uint16_t)mesh_transition_sample(
		    &srv->saturation_transition, now_ms);
	hsl_sync_levels(srv);
}

static void
hsl_tick(void *arg, uint64_t now_ms)
{
	hsl_update(arg, now_ms);
}

static int
hsl_handler(const struct mesh_access_rx *rx)
{
        struct mesh_light_hsl_srv *srv = rx->model_user;
        struct mesh_model_reply *r = rx->ctx;
        uint16_t lightness, hue, saturation;
        uint32_t op = rx->pdu->opcode;
	uint8_t transition_time, delay;
        int     component, ack;

	if (srv == NULL || r == NULL)
		return (-1);
	hsl_update(srv, rx->now_ms);
        component = op == MESH_OP_LIGHT_HSL_HUE_GET || op == MESH_OP_LIGHT_HSL_HUE_SET ||
                op == MESH_OP_LIGHT_HSL_HUE_SET_UNACK || op == MESH_OP_LIGHT_HSL_SATURATION_GET ||
                op == MESH_OP_LIGHT_HSL_SATURATION_SET || op == MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK;
	if (op == MESH_OP_LIGHT_HSL_GET || op == MESH_OP_LIGHT_HSL_TARGET_GET ||
	    op == MESH_OP_LIGHT_HSL_HUE_GET ||
	    op == MESH_OP_LIGHT_HSL_SATURATION_GET) {
                if (rx->pdu->params_len != 0)
                        return (-1);
		reply_init(rx, r, op == MESH_OP_LIGHT_HSL_GET ? MESH_OP_LIGHT_HSL_STATUS :
		    op == MESH_OP_LIGHT_HSL_TARGET_GET ? MESH_OP_LIGHT_HSL_TARGET_STATUS :
			   (op == MESH_OP_LIGHT_HSL_HUE_GET ? MESH_OP_LIGHT_HSL_HUE_STATUS : MESH_OP_LIGHT_HSL_SATURATION_STATUS));
		if (op == MESH_OP_LIGHT_HSL_GET || op == MESH_OP_LIGHT_HSL_TARGET_GET) {
			int target = op == MESH_OP_LIGHT_HSL_TARGET_GET;

			put_u16(r->params, target &&
			    srv->lightness->transition.active ?
			    (uint16_t)srv->lightness->transition.target :
			    srv->lightness->actual);
			put_u16(r->params + 2, target && srv->hue_transition.active ?
			    (uint16_t)srv->hue_transition.target : srv->hue);
			put_u16(r->params + 4, target &&
			    srv->saturation_transition.active ?
			    (uint16_t)srv->saturation_transition.target :
			    srv->saturation);
			if (srv->lightness->transition.active ||
			    srv->hue_transition.active ||
			    srv->saturation_transition.active) {
				r->params[6] = lighting_remaining(rx->now_ms,
				    &srv->lightness->transition, &srv->hue_transition,
				    &srv->saturation_transition);
				r->params_len = 7;
			} else
				r->params_len = 6;
		} else {
			put_u16(r->params, op == MESH_OP_LIGHT_HSL_HUE_GET ? srv->hue : srv->saturation);
			if ((op == MESH_OP_LIGHT_HSL_HUE_GET ?
			    srv->hue_transition.active :
			    srv->saturation_transition.active)) {
				struct mesh_transition_state *transition =
				    op == MESH_OP_LIGHT_HSL_HUE_GET ?
				    &srv->hue_transition : &srv->saturation_transition;
				put_u16(r->params + 2,
				    (uint16_t)transition->target);
				r->params[4] = mesh_transition_remaining(
				    transition->end_ms - rx->now_ms);
				r->params_len = 5;
			} else
				r->params_len = 2;
                }
                return (0);
        }
        if ((op != MESH_OP_LIGHT_HSL_SET && op != MESH_OP_LIGHT_HSL_SET_UNACK &&
             op != MESH_OP_LIGHT_HSL_HUE_SET && op != MESH_OP_LIGHT_HSL_HUE_SET_UNACK &&
             op != MESH_OP_LIGHT_HSL_SATURATION_SET && op != MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK) ||
	    (rx->pdu->params_len != (component ? 3 : 7) &&
	    rx->pdu->params_len != (component ? 5 : 9)))
		return (-1);
        lightness = component ? srv->lightness->actual : get_u16(rx->pdu->params);
        hue = component ? srv->hue : get_u16(rx->pdu->params + 2);
        saturation = component ? srv->saturation : get_u16(rx->pdu->params + 4);
        if (op == MESH_OP_LIGHT_HSL_HUE_SET || op == MESH_OP_LIGHT_HSL_HUE_SET_UNACK)
                hue = get_u16(rx->pdu->params);
        if (op == MESH_OP_LIGHT_HSL_SATURATION_SET || op == MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK)
                saturation = get_u16(rx->pdu->params);
	/*
	 * Clamp out-of-range components to their Range rather than dropping the
	 * whole message (MMDL Section 6.1.4); this keeps in-range composite
	 * components applied.
	 */
	lightness = lightness_clamp(srv->lightness, lightness);
	hue = hsl_hue_clamp(srv, hue);
	saturation = hsl_saturation_clamp(srv, saturation);
        ack = op == MESH_OP_LIGHT_HSL_SET || op == MESH_OP_LIGHT_HSL_HUE_SET || op == MESH_OP_LIGHT_HSL_SATURATION_SET;
	if (lighting_tid_is_new(&srv->last_src, &srv->last_dst, &srv->last_tid,
	    &srv->tid_valid, &srv->tid_expires_ms, rx->src,
	    rx->dst, rx->pdu->params[component ? 2 : 6], rx->now_ms)) {
		transition_time = lighting_effective_transition(srv->lightness,
		    rx->pdu->params_len == (component ? 5 : 9),
		    rx->pdu->params_len == (component ? 5 : 9) ?
		    rx->pdu->params[component ? 3 : 7] : 0);
		delay = rx->pdu->params_len == (component ? 5 : 9) ?
		    rx->pdu->params[component ? 4 : 8] : 0;
		if (delay != 0 || mesh_transition_time_ms(transition_time) != 0) {
			if (!component)
				mesh_transition_start(&srv->lightness->transition,
				    srv->lightness->actual, lightness,
				    transition_time, delay,
				    rx->now_ms);
			if (op == MESH_OP_LIGHT_HSL_SET ||
			    op == MESH_OP_LIGHT_HSL_SET_UNACK ||
			    op == MESH_OP_LIGHT_HSL_HUE_SET ||
			    op == MESH_OP_LIGHT_HSL_HUE_SET_UNACK)
				mesh_transition_start(&srv->hue_transition, srv->hue,
				    hue, transition_time, delay, rx->now_ms);
			if (op == MESH_OP_LIGHT_HSL_SET ||
			    op == MESH_OP_LIGHT_HSL_SET_UNACK ||
			    op == MESH_OP_LIGHT_HSL_SATURATION_SET ||
			    op == MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK)
				mesh_transition_start(&srv->saturation_transition,
				    srv->saturation, saturation, transition_time, delay,
				    rx->now_ms);
		} else {
			if (!component)
				srv->lightness->transition.active = 0;
			if (!component || op == MESH_OP_LIGHT_HSL_HUE_SET ||
			    op == MESH_OP_LIGHT_HSL_HUE_SET_UNACK)
				srv->hue_transition.active = 0;
			if (!component || op == MESH_OP_LIGHT_HSL_SATURATION_SET ||
			    op == MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK)
				srv->saturation_transition.active = 0;
			if (mesh_light_hsl_set(srv, lightness, hue, saturation) != 0)
				return (-1);
		}
        }
        if (!ack) {
                memset(r, 0, sizeof(*r));
                return 0;
        }
        reply_init(rx, r, component ? (op == MESH_OP_LIGHT_HSL_HUE_SET ? MESH_OP_LIGHT_HSL_HUE_STATUS : MESH_OP_LIGHT_HSL_SATURATION_STATUS) : MESH_OP_LIGHT_HSL_STATUS);
        if (!component) {
                put_u16(r->params, srv->lightness->actual);
		put_u16(r->params + 2, srv->hue);
		put_u16(r->params + 4, srv->saturation);
		if (srv->lightness->transition.active ||
		    srv->hue_transition.active ||
		    srv->saturation_transition.active) {
			r->params[6] = lighting_remaining(rx->now_ms,
			    &srv->lightness->transition, &srv->hue_transition,
			    &srv->saturation_transition);
			r->params_len = 7;
		} else
			r->params_len = 6;
	} else {
		put_u16(r->params, op == MESH_OP_LIGHT_HSL_HUE_SET ? srv->hue : srv->saturation);
		if ((op == MESH_OP_LIGHT_HSL_HUE_SET ?
		    srv->hue_transition.active :
		    srv->saturation_transition.active)) {
			struct mesh_transition_state *transition =
			    op == MESH_OP_LIGHT_HSL_HUE_SET ?
			    &srv->hue_transition : &srv->saturation_transition;
			put_u16(r->params + 2, (uint16_t)transition->target);
			r->params[4] = mesh_transition_remaining(
			    transition->end_ms - rx->now_ms);
			r->params_len = 5;
		} else
			r->params_len = 2;
        }
        return 0;
}

static const struct mesh_opcode_entry hsl_ops[] = {
        {MESH_OP_LIGHT_HSL_GET, hsl_handler}, {MESH_OP_LIGHT_HSL_SET, hsl_handler}, {MESH_OP_LIGHT_HSL_SET_UNACK, hsl_handler},
        {MESH_OP_LIGHT_HSL_HUE_GET, hsl_handler}, {MESH_OP_LIGHT_HSL_HUE_SET, hsl_handler}, {MESH_OP_LIGHT_HSL_HUE_SET_UNACK, hsl_handler},
	{MESH_OP_LIGHT_HSL_SATURATION_GET, hsl_handler}, {MESH_OP_LIGHT_HSL_SATURATION_SET, hsl_handler}, {MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK, hsl_handler},
	{MESH_OP_LIGHT_HSL_TARGET_GET, hsl_handler},
};
static int
hsl_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_light_hsl_srv *srv = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	uint32_t op = rx->pdu->opcode;
	uint16_t hue_min, hue_max, saturation_min, saturation_max;
	int     ack;

        if (srv == NULL || r == NULL)
                return -1;
        if (op == MESH_OP_LIGHT_HSL_DEFAULT_GET || op == MESH_OP_LIGHT_HSL_RANGE_GET) {
                if (rx->pdu->params_len != 0)
                        return -1;
                reply_init(rx, r, op == MESH_OP_LIGHT_HSL_DEFAULT_GET ? MESH_OP_LIGHT_HSL_DEFAULT_STATUS : MESH_OP_LIGHT_HSL_RANGE_STATUS);
                if (op == MESH_OP_LIGHT_HSL_DEFAULT_GET) {
                        put_u16(r->params, srv->default_lightness);
                        put_u16(r->params + 2, srv->default_hue);
                        put_u16(r->params + 4, srv->default_saturation);
                        r->params_len = 6;
                } else {
                        r->params[0] = srv->range_status;
                        put_u16(r->params + 1, srv->hue_min);
                        put_u16(r->params + 3, srv->hue_max);
                        put_u16(r->params + 5, srv->saturation_min);
                        put_u16(r->params + 7, srv->saturation_max);
                        r->params_len = 9;
                }
                return 0;
        }
        ack = op == MESH_OP_LIGHT_HSL_DEFAULT_SET || op == MESH_OP_LIGHT_HSL_RANGE_SET;
	if (op == MESH_OP_LIGHT_HSL_DEFAULT_SET || op == MESH_OP_LIGHT_HSL_DEFAULT_SET_UNACK) {
		if (rx->pdu->params_len != 6)
			return -1;
		if (!lightness_value_valid(srv->lightness,
		    get_u16(rx->pdu->params)) ||
		    !hsl_hue_in_range(srv, get_u16(rx->pdu->params + 2)) ||
		    get_u16(rx->pdu->params + 4) < srv->saturation_min ||
		    get_u16(rx->pdu->params + 4) > srv->saturation_max)
			return (-1);
		srv->default_lightness = get_u16(rx->pdu->params);
		srv->default_hue = get_u16(rx->pdu->params + 2);
		srv->default_saturation = get_u16(rx->pdu->params + 4);
                if (!ack) {
                        memset(r, 0, sizeof(*r));
                        return 0;
                }
                reply_init(rx, r, MESH_OP_LIGHT_HSL_DEFAULT_STATUS);
                memcpy(r->params, rx->pdu->params, 6);
                r->params_len = 6;
                return 0;
        }
        if ((op != MESH_OP_LIGHT_HSL_RANGE_SET && op != MESH_OP_LIGHT_HSL_RANGE_SET_UNACK) || rx->pdu->params_len != 8)
                return -1;
        hue_min = get_u16(rx->pdu->params);
        hue_max = get_u16(rx->pdu->params + 2);
        saturation_min = get_u16(rx->pdu->params + 4);
        saturation_max = get_u16(rx->pdu->params + 6);
	if (saturation_min > saturation_max)
                return -1;
        srv->hue_min = hue_min;
        srv->hue_max = hue_max;
        srv->saturation_min = saturation_min;
        srv->saturation_max = saturation_max;
        srv->range_status = 0;
        if (!ack) {
                memset(r, 0, sizeof(*r));
                return 0;
        }
        reply_init(rx, r, MESH_OP_LIGHT_HSL_RANGE_STATUS);
        r->params[0] = 0;
        memcpy(r->params + 1, rx->pdu->params, 8);
        r->params_len = 9;
        return 0;
}
static const struct mesh_opcode_entry hsl_setup_ops[] = {
        {MESH_OP_LIGHT_HSL_DEFAULT_GET, hsl_setup_handler}, {MESH_OP_LIGHT_HSL_DEFAULT_SET, hsl_setup_handler}, {MESH_OP_LIGHT_HSL_DEFAULT_SET_UNACK, hsl_setup_handler},
        {MESH_OP_LIGHT_HSL_RANGE_GET, hsl_setup_handler}, {MESH_OP_LIGHT_HSL_RANGE_SET, hsl_setup_handler}, {MESH_OP_LIGHT_HSL_RANGE_SET_UNACK, hsl_setup_handler},
};
struct mesh_model mesh_light_hsl_srv_model(struct mesh_light_hsl_srv *s){
	struct mesh_model model = lighting_model(s, MESH_MODEL_LIGHT_HSL_SRV,
	    hsl_ops, sizeof(hsl_ops) / sizeof(hsl_ops[0]));
	model.tick = hsl_tick;
	return model;
}
struct mesh_model mesh_light_hsl_hue_srv_model(struct mesh_light_hsl_srv *s){
	return lighting_model(s, MESH_MODEL_LIGHT_HSL_HUE_SRV, hsl_ops + 3, 3);
}
struct mesh_model mesh_light_hsl_sat_srv_model(struct mesh_light_hsl_srv *s){
	return lighting_model(s, MESH_MODEL_LIGHT_HSL_SAT_SRV, hsl_ops + 6, 3);
}
struct mesh_model mesh_light_hsl_setup_srv_model(struct mesh_light_hsl_srv *s){
	return lighting_model(s, MESH_MODEL_LIGHT_HSL_SETUP_SRV, hsl_setup_ops, sizeof(hsl_setup_ops) / sizeof(hsl_setup_ops[0]));
}
void    mesh_light_hsl_cli_init(struct mesh_light_hsl_cli *c){
        if (c != NULL)
                memset(c, 0, sizeof(*c));
}
int     mesh_light_hsl_cli_get(uint32_t op, uint8_t * o, size_t * n) {
	if (op != MESH_OP_LIGHT_HSL_GET && op != MESH_OP_LIGHT_HSL_TARGET_GET &&
	    op != MESH_OP_LIGHT_HSL_HUE_GET &&
	    op != MESH_OP_LIGHT_HSL_SATURATION_GET)
		return -1;
	return mesh_access_pdu_build(op, NULL, 0, o, n);
}
int
mesh_light_hsl_cli_set(const struct mesh_light_hsl_set *set, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[9];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->hue);
	put_u16(params + 4, set->saturation);
	params[6] = set->tid;
	if (put_transition(params, 7, &set->transition, &params_len) != 0)
		return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_HSL_SET :
	    MESH_OP_LIGHT_HSL_SET_UNACK, params, params_len, out, outlen));
}

static int
hsl_component_cli_set(uint32_t opcode,
    const struct mesh_light_hsl_component_set *set, int ack, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[5];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->value);
	params[2] = set->tid;
	if (put_transition(params, 3, &set->transition, &params_len) != 0)
		return (-1);
	if (!ack)
		opcode = opcode == MESH_OP_LIGHT_HSL_HUE_SET ?
		    MESH_OP_LIGHT_HSL_HUE_SET_UNACK :
		    MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK;
	return (mesh_access_pdu_build(opcode, params, params_len, out, outlen));
}

int
mesh_light_hsl_cli_hue_set(const struct mesh_light_hsl_component_set *set,
    int ack, uint8_t *out, size_t *outlen)
{
	return (hsl_component_cli_set(MESH_OP_LIGHT_HSL_HUE_SET, set, ack, out,
	    outlen));
}

int
mesh_light_hsl_cli_saturation_set(
    const struct mesh_light_hsl_component_set *set, int ack, uint8_t *out,
    size_t *outlen)
{
	return (hsl_component_cli_set(MESH_OP_LIGHT_HSL_SATURATION_SET, set, ack,
	    out, outlen));
}

int
mesh_light_hsl_cli_default_set(const struct mesh_light_hsl_triplet *set,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[6];

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->hue);
	put_u16(params + 4, set->saturation);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_HSL_DEFAULT_SET :
	    MESH_OP_LIGHT_HSL_DEFAULT_SET_UNACK, params, sizeof(params), out,
	    outlen));
}

int
mesh_light_hsl_cli_range_set(const struct mesh_light_hsl_range *range,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[8];

	if (range == NULL || range->saturation_min > range->saturation_max)
		return (-1);
	put_u16(params, range->hue_min);
	put_u16(params + 2, range->hue_max);
	put_u16(params + 4, range->saturation_min);
	put_u16(params + 6, range->saturation_max);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_HSL_RANGE_SET :
	    MESH_OP_LIGHT_HSL_RANGE_SET_UNACK, params, sizeof(params), out,
	    outlen));
}
int     mesh_light_hsl_cli_recv(struct mesh_light_hsl_cli *c, uint32_t op, const uint8_t * p, size_t n){
        if (c == NULL || p == NULL)
                return -1;
	if ((op == MESH_OP_LIGHT_HSL_STATUS ||
	    op == MESH_OP_LIGHT_HSL_TARGET_STATUS) && (n == 6 || n == 7)) {
		if (op == MESH_OP_LIGHT_HSL_TARGET_STATUS) {
			c->target_lightness = get_u16(p);
			c->target_hue = get_u16(p + 2);
			c->target_saturation = get_u16(p + 4);
			c->has_target = 1;
		} else {
			c->lightness = get_u16(p);
			c->hue = get_u16(p + 2);
			c->saturation = get_u16(p + 4);
			c->has_target = n == 7;
		}
		c->remaining_time = n == 7 ? p[6] : 0;
		return 0;
	} if (op == MESH_OP_LIGHT_HSL_HUE_STATUS && (n == 2 || n == 5)) {
		c->hue = get_u16(p);
		c->has_target = n == 5;
		if (n == 5) {
			c->target_hue = get_u16(p + 2);
			c->remaining_time = p[4];
		}
		return 0;
	} if (op == MESH_OP_LIGHT_HSL_SATURATION_STATUS && (n == 2 || n == 5)) {
		c->saturation = get_u16(p);
		c->has_target = n == 5;
		if (n == 5) {
			c->target_saturation = get_u16(p + 2);
			c->remaining_time = p[4];
		}
                return 0;
        } if (op == MESH_OP_LIGHT_HSL_DEFAULT_STATUS && n == 6) {
                c->default_lightness = get_u16(p);
                c->default_hue = get_u16(p + 2);
                c->default_saturation = get_u16(p + 4);
                return 0;
        } if (op == MESH_OP_LIGHT_HSL_RANGE_STATUS && n == 9 && p[0] <= 2) {
                c->range_status = p[0];
                c->hue_min = get_u16(p + 1);
                c->hue_max = get_u16(p + 3);
                c->saturation_min = get_u16(p + 5);
                c->saturation_max = get_u16(p + 7);
                return 0;
        } return -1;
}

void    mesh_light_xyl_srv_init(struct mesh_light_xyl_srv *s, struct mesh_light_lightness_srv *l){
        if (s == NULL)
                return;
        memset(s, 0, sizeof(*s));
        s->x_max = UINT16_MAX;
        s->y_max = UINT16_MAX;
        s->lightness = l;
}
/* MMDL Section 6.1.5: an out-of-range xyL x/y is clamped to Range, not dropped. */
static uint16_t
xyl_clamp(uint16_t value, uint16_t min, uint16_t max)
{
	if (value < min)
		return (min);
	if (value > max)
		return (max);
	return (value);
}

int
mesh_light_xyl_set(struct mesh_light_xyl_srv *s, uint16_t l, uint16_t x, uint16_t y)
{
        if (s == NULL || s->lightness == NULL || x < s->x_min || x > s->x_max || y < s->y_min || y > s->y_max || mesh_light_lightness_set_actual(s->lightness, l) != 0)
                return -1;
        s->x = x;
        s->y = y;
        return 0;
}
static void
xyl_update(struct mesh_light_xyl_srv *s, uint64_t now_ms)
{
	lightness_update(s->lightness, now_ms);
	if (s->x_transition.active)
		s->x = (uint16_t)mesh_transition_sample(&s->x_transition, now_ms);
	if (s->y_transition.active)
		s->y = (uint16_t)mesh_transition_sample(&s->y_transition, now_ms);
}
static void
xyl_tick(void *arg, uint64_t now_ms)
{
	xyl_update(arg, now_ms);
}
static int xyl_handler(const struct mesh_access_rx *rx){
        struct mesh_light_xyl_srv *s = rx->model_user;
        struct mesh_model_reply *r = rx->ctx;
        uint32_t op = rx->pdu->opcode;
        uint16_t l, x, y;
	uint8_t transition_time, delay;
        int     ack;
	if (s == NULL || r == NULL)
		return -1;
	xyl_update(s, rx->now_ms);
        if (op == MESH_OP_LIGHT_XYL_GET || op == MESH_OP_LIGHT_XYL_TARGET_GET) {
                if (rx->pdu->params_len != 0)
                        return -1;
                reply_init(rx, r, op == MESH_OP_LIGHT_XYL_GET ? MESH_OP_LIGHT_XYL_STATUS : MESH_OP_LIGHT_XYL_TARGET_STATUS);
		put_u16(r->params, op == MESH_OP_LIGHT_XYL_TARGET_GET &&
		    s->lightness->transition.active ?
		    (uint16_t)s->lightness->transition.target :
		    s->lightness->actual);
		put_u16(r->params + 2, op == MESH_OP_LIGHT_XYL_TARGET_GET &&
		    s->x_transition.active ? (uint16_t)s->x_transition.target : s->x);
		put_u16(r->params + 4, op == MESH_OP_LIGHT_XYL_TARGET_GET &&
		    s->y_transition.active ? (uint16_t)s->y_transition.target : s->y);
		if (s->lightness->transition.active || s->x_transition.active ||
		    s->y_transition.active) {
			r->params[6] = lighting_remaining(rx->now_ms,
			    &s->lightness->transition, &s->x_transition,
			    &s->y_transition);
			r->params_len = 7;
		} else
			r->params_len = 6;
                return 0;
	} if ((op != MESH_OP_LIGHT_XYL_SET &&
	    op != MESH_OP_LIGHT_XYL_SET_UNACK) ||
	    (rx->pdu->params_len != 7 && rx->pdu->params_len != 9))
		return -1;
        l = get_u16(rx->pdu->params);
        x = get_u16(rx->pdu->params + 2);
        y = get_u16(rx->pdu->params + 4);
	/*
	 * Clamp out-of-range components to their Range rather than dropping the
	 * whole message (MMDL Section 6.1.5), keeping in-range components.
	 */
	l = lightness_clamp(s->lightness, l);
	x = xyl_clamp(x, s->x_min, s->x_max);
	y = xyl_clamp(y, s->y_min, s->y_max);
        ack = op == MESH_OP_LIGHT_XYL_SET;
	if (lighting_tid_is_new(&s->last_src, &s->last_dst, &s->last_tid,
	    &s->tid_valid, &s->tid_expires_ms, rx->src, rx->dst,
	    rx->pdu->params[6], rx->now_ms)) {
		transition_time = lighting_effective_transition(s->lightness,
		    rx->pdu->params_len == 9,
		    rx->pdu->params_len == 9 ? rx->pdu->params[7] : 0);
		delay = rx->pdu->params_len == 9 ? rx->pdu->params[8] : 0;
		if (delay != 0 || mesh_transition_time_ms(transition_time) != 0) {
			mesh_transition_start(&s->lightness->transition,
			    s->lightness->actual, l, transition_time, delay,
			    rx->now_ms);
			mesh_transition_start(&s->x_transition, s->x, x,
			    transition_time, delay, rx->now_ms);
			mesh_transition_start(&s->y_transition, s->y, y,
			    transition_time, delay, rx->now_ms);
		} else {
			s->lightness->transition.active = 0;
			s->x_transition.active = 0;
			s->y_transition.active = 0;
			if (mesh_light_xyl_set(s, l, x, y) != 0)
				return -1;
		}
        } if (!ack) {
                memset(r, 0, sizeof(*r));
                return 0;
        } reply_init(rx, r, MESH_OP_LIGHT_XYL_STATUS);
        put_u16(r->params, s->lightness->actual);
	put_u16(r->params + 2, s->x);
	put_u16(r->params + 4, s->y);
	if (s->lightness->transition.active || s->x_transition.active ||
	    s->y_transition.active) {
		r->params[6] = lighting_remaining(rx->now_ms,
		    &s->lightness->transition, &s->x_transition, &s->y_transition);
		r->params_len = 7;
	} else
		r->params_len = 6;
        return 0;
}
static int xyl_setup_handler(const struct mesh_access_rx *rx){
        struct mesh_light_xyl_srv *s = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	uint32_t op = rx->pdu->opcode;
	uint16_t x_min, x_max, y_min, y_max;
	int     ack;
        if (s == NULL || r == NULL)
                return -1;
        if (op == MESH_OP_LIGHT_XYL_DEFAULT_GET || op == MESH_OP_LIGHT_XYL_RANGE_GET) {
                if (rx->pdu->params_len != 0)
                        return -1;
                reply_init(rx, r, op == MESH_OP_LIGHT_XYL_DEFAULT_GET ? MESH_OP_LIGHT_XYL_DEFAULT_STATUS : MESH_OP_LIGHT_XYL_RANGE_STATUS);
                if (op == MESH_OP_LIGHT_XYL_DEFAULT_GET) {
                        put_u16(r->params, s->default_lightness);
                        put_u16(r->params + 2, s->default_x);
                        put_u16(r->params + 4, s->default_y);
                        r->params_len = 6;
                } else {
                        r->params[0] = s->range_status;
                        put_u16(r->params + 1, s->x_min);
                        put_u16(r->params + 3, s->x_max);
                        put_u16(r->params + 5, s->y_min);
                        put_u16(r->params + 7, s->y_max);
                        r->params_len = 9;
                } return 0;
	} ack = op == MESH_OP_LIGHT_XYL_DEFAULT_SET || op == MESH_OP_LIGHT_XYL_RANGE_SET;
	if (op == MESH_OP_LIGHT_XYL_DEFAULT_SET || op == MESH_OP_LIGHT_XYL_DEFAULT_SET_UNACK) {
		if (rx->pdu->params_len != 6)
			return -1;
		if (!lightness_value_valid(s->lightness,
		    get_u16(rx->pdu->params)) ||
		    get_u16(rx->pdu->params + 2) < s->x_min ||
		    get_u16(rx->pdu->params + 2) > s->x_max ||
		    get_u16(rx->pdu->params + 4) < s->y_min ||
		    get_u16(rx->pdu->params + 4) > s->y_max)
			return (-1);
		s->default_lightness = get_u16(rx->pdu->params);
                s->default_x = get_u16(rx->pdu->params + 2);
                s->default_y = get_u16(rx->pdu->params + 4);
                if (!ack) {
                        memset(r, 0, sizeof(*r));
                        return 0;
                } reply_init(rx, r, MESH_OP_LIGHT_XYL_DEFAULT_STATUS);
                memcpy(r->params, rx->pdu->params, 6);
                r->params_len = 6;
                return 0;
        } if ((op != MESH_OP_LIGHT_XYL_RANGE_SET && op != MESH_OP_LIGHT_XYL_RANGE_SET_UNACK) || rx->pdu->params_len != 8)
                return -1;
        x_min = get_u16(rx->pdu->params);
        x_max = get_u16(rx->pdu->params + 2);
        y_min = get_u16(rx->pdu->params + 4);
        y_max = get_u16(rx->pdu->params + 6);
        if (x_min > x_max || y_min > y_max)
                return -1;
        s->x_min = x_min;
        s->x_max = x_max;
        s->y_min = y_min;
        s->y_max = y_max;
        s->range_status = 0;
        if (!ack) {
                memset(r, 0, sizeof(*r));
                return 0;
        } reply_init(rx, r, MESH_OP_LIGHT_XYL_RANGE_STATUS);
        r->params[0] = 0;
        memcpy(r->params + 1, rx->pdu->params, 8);
        r->params_len = 9;
        return 0;
}
static const struct mesh_opcode_entry xyl_ops[] = {{MESH_OP_LIGHT_XYL_GET, xyl_handler}, {MESH_OP_LIGHT_XYL_SET, xyl_handler}, {MESH_OP_LIGHT_XYL_SET_UNACK, xyl_handler}, {MESH_OP_LIGHT_XYL_TARGET_GET, xyl_handler}};
static const struct mesh_opcode_entry xyl_setup_ops[] = {{MESH_OP_LIGHT_XYL_DEFAULT_GET, xyl_setup_handler}, {MESH_OP_LIGHT_XYL_DEFAULT_SET, xyl_setup_handler}, {MESH_OP_LIGHT_XYL_DEFAULT_SET_UNACK, xyl_setup_handler}, {MESH_OP_LIGHT_XYL_RANGE_GET, xyl_setup_handler}, {MESH_OP_LIGHT_XYL_RANGE_SET, xyl_setup_handler}, {MESH_OP_LIGHT_XYL_RANGE_SET_UNACK, xyl_setup_handler}};
struct mesh_model mesh_light_xyl_srv_model(struct mesh_light_xyl_srv *s){
	struct mesh_model model = lighting_model(s, MESH_MODEL_LIGHT_XYL_SRV,
	    xyl_ops, sizeof(xyl_ops) / sizeof(xyl_ops[0]));
	model.tick = xyl_tick;
	return model;
} struct mesh_model mesh_light_xyl_setup_srv_model(struct mesh_light_xyl_srv *s){
	return lighting_model(s, MESH_MODEL_LIGHT_XYL_SETUP_SRV, xyl_setup_ops, sizeof(xyl_setup_ops) / sizeof(xyl_setup_ops[0]));
}
void    mesh_light_xyl_cli_init(struct mesh_light_xyl_cli *c){
        if (c != NULL)
                memset(c, 0, sizeof(*c));
} int   mesh_light_xyl_cli_get(uint32_t op, uint8_t * o, size_t * n) {
        if (op != MESH_OP_LIGHT_XYL_GET && op != MESH_OP_LIGHT_XYL_TARGET_GET && op != MESH_OP_LIGHT_XYL_DEFAULT_GET && op != MESH_OP_LIGHT_XYL_RANGE_GET)
                return -1;
        return mesh_access_pdu_build(op, NULL, 0, o, n);
} int
mesh_light_xyl_cli_set(const struct mesh_light_xyl_set *set, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[9];
	size_t params_len;

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->x);
	put_u16(params + 4, set->y);
	params[6] = set->tid;
	if (put_transition(params, 7, &set->transition, &params_len) != 0)
		return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_XYL_SET :
	    MESH_OP_LIGHT_XYL_SET_UNACK, params, params_len, out, outlen));
} int   mesh_light_xyl_cli_recv(struct mesh_light_xyl_cli *c, uint32_t op, const uint8_t * p, size_t n){
        if (c == NULL || p == NULL)
                return -1;
	if ((op == MESH_OP_LIGHT_XYL_STATUS ||
	    op == MESH_OP_LIGHT_XYL_TARGET_STATUS) && (n == 6 || n == 7)) {
		if (op == MESH_OP_LIGHT_XYL_TARGET_STATUS) {
			c->target_lightness = get_u16(p);
			c->target_x = get_u16(p + 2);
			c->target_y = get_u16(p + 4);
			c->has_target = 1;
		} else {
			c->lightness = get_u16(p);
			c->x = get_u16(p + 2);
			c->y = get_u16(p + 4);
			c->has_target = n == 7;
		}
		c->remaining_time = n == 7 ? p[6] : 0;
		return 0;
        } if (op == MESH_OP_LIGHT_XYL_DEFAULT_STATUS && n == 6) {
                c->default_lightness = get_u16(p);
                c->default_x = get_u16(p + 2);
                c->default_y = get_u16(p + 4);
                return 0;
        } if (op == MESH_OP_LIGHT_XYL_RANGE_STATUS && n == 9 && p[0] <= 2) {
                c->range_status = p[0];
                c->x_min = get_u16(p + 1);
                c->x_max = get_u16(p + 3);
                c->y_min = get_u16(p + 5);
                c->y_max = get_u16(p + 7);
                return 0;
        } return -1;
}

int
mesh_light_xyl_cli_default_set(const struct mesh_light_xyl_triplet *set,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[6];

	if (set == NULL)
		return (-1);
	put_u16(params, set->lightness);
	put_u16(params + 2, set->x);
	put_u16(params + 4, set->y);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_XYL_DEFAULT_SET :
	    MESH_OP_LIGHT_XYL_DEFAULT_SET_UNACK, params, sizeof(params), out,
	    outlen));
}

int
mesh_light_xyl_cli_range_set(const struct mesh_light_xyl_range *range,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t params[8];

	if (range == NULL || range->x_min > range->x_max ||
	    range->y_min > range->y_max)
		return (-1);
	put_u16(params, range->x_min);
	put_u16(params + 2, range->x_max);
	put_u16(params + 4, range->y_min);
	put_u16(params + 6, range->y_max);
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_XYL_RANGE_SET :
	    MESH_OP_LIGHT_XYL_RANGE_SET_UNACK, params, sizeof(params), out,
	    outlen));
}

void    mesh_light_lc_srv_init(struct mesh_light_lc_srv *s, struct mesh_light_lightness_srv *l){
        if (s == NULL)
                return;
        memset(s, 0, sizeof(*s));
        s->lightness = l;
}
int     mesh_light_lc_set(struct mesh_light_lc_srv *s, uint8_t mode, uint8_t onoff){
        if (s == NULL || mode > 1 || onoff > 1)
                return -1;
        if (mode && s->lightness != NULL &&
            mesh_light_lightness_set_actual(s->lightness,
            onoff ? s->lightness->last : 0) != 0)
                return -1;
        s->mode = mode;
        s->light_onoff = onoff;
        return 0;
}
static void
lc_update(struct mesh_light_lc_srv *s, uint64_t now_ms)
{
	uint8_t onoff;

	if (!s->transition.active)
		return;
	onoff = mesh_transition_sample_binary(&s->transition, now_ms);
	if (onoff != s->light_onoff)
		(void)mesh_light_lc_set(s, s->mode, onoff);
}
static void
lc_tick(void *arg, uint64_t now_ms)
{
	lc_update(arg, now_ms);
}

static int
lc_property_value_len(uint16_t id, size_t *len)
{

	if (len == NULL)
		return (-1);
	if (id >= 0x002b && id <= 0x002d)
		*len = 3;	/* Illuminance */
	else if (id >= 0x002e && id <= 0x0030)
		*len = 2;	/* Perceived Lightness */
	else if (id == 0x0031)
		*len = 1;	/* Percentage 8 */
	else if (id >= 0x0032 && id <= 0x0035)
		*len = 4;	/* Coefficient */
	else if (id >= 0x0036 && id <= 0x003c)
		*len = 3;	/* Time Millisecond 24 */
	else
		return (-1);
	return (0);
}

static int lc_prop(struct mesh_light_lc_srv *s, uint16_t id, const uint8_t * v, size_t n, int set, struct mesh_model_reply *r, const struct mesh_access_rx *rx){
        size_t  expected_len, i;
        if (s == NULL || id == 0 || r == NULL || rx == NULL)
                return -1;
	if (lc_property_value_len(id, &expected_len) != 0 ||
	    (set && n != expected_len))
                return -1;
        if (set) {
                if (mesh_light_lc_property_set(s, id, v, n) != 0)
                        return -1;
        }
        for (i = 0; i < s->n_properties && s->properties[i].id != id; i++);
        if (i == s->n_properties)
                return -1;
        reply_init(rx, r, MESH_OP_LIGHT_LC_PROPERTY_STATUS);
        put_u16(r->params, id);
        memcpy(r->params + 2, s->properties[i].value, s->properties[i].len);
        r->params_len = 2 + s->properties[i].len;
        return 0;
}
static int
lc_handler(const struct mesh_access_rx *rx)
{
	struct mesh_light_lc_srv *s = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	const uint8_t *p = rx->pdu->params;
	uint32_t op = rx->pdu->opcode;
	size_t plen = rx->pdu->params_len;
	uint32_t status_op;
	uint8_t transition_time, delay;
	int ack;

	if (s == NULL || r == NULL)
		return (-1);
	lc_update(s, rx->now_ms);
	if (op == MESH_OP_LIGHT_LC_MODE_GET || op == MESH_OP_LIGHT_LC_OM_GET ||
	    op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET) {
		if (plen != 0)
			return (-1);
		status_op = op == MESH_OP_LIGHT_LC_MODE_GET ?
		    MESH_OP_LIGHT_LC_MODE_STATUS :
		    op == MESH_OP_LIGHT_LC_OM_GET ? MESH_OP_LIGHT_LC_OM_STATUS :
		    MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS;
		reply_init(rx, r, status_op);
		r->params[0] = op == MESH_OP_LIGHT_LC_MODE_GET ? s->mode :
		    op == MESH_OP_LIGHT_LC_OM_GET ? s->occupancy_mode :
		    s->light_onoff;
		if (op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET &&
		    s->transition.active) {
			r->params[1] = (uint8_t)s->transition.target;
			r->params[2] = mesh_transition_remaining(
			    s->transition.end_ms - rx->now_ms);
			r->params_len = 3;
		} else
			r->params_len = 1;
		return (0);
	}

	ack = op == MESH_OP_LIGHT_LC_MODE_SET ||
	    op == MESH_OP_LIGHT_LC_OM_SET ||
	    op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET;
	if (!ack && op != MESH_OP_LIGHT_LC_MODE_SET_UNACK &&
	    op != MESH_OP_LIGHT_LC_OM_SET_UNACK &&
	    op != MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK)
		return (-1);

	if (op == MESH_OP_LIGHT_LC_MODE_SET ||
	    op == MESH_OP_LIGHT_LC_MODE_SET_UNACK) {
		if (plen != 1 || p[0] > 1 ||
		    mesh_light_lc_set(s, p[0], s->light_onoff) != 0)
			return (-1);
		status_op = MESH_OP_LIGHT_LC_MODE_STATUS;
	} else if (op == MESH_OP_LIGHT_LC_OM_SET ||
	    op == MESH_OP_LIGHT_LC_OM_SET_UNACK) {
		if (plen != 1 || p[0] > 1)
			return (-1);
		s->occupancy_mode = p[0];
		status_op = MESH_OP_LIGHT_LC_OM_STATUS;
	} else {
		if ((plen != 2 && plen != 4) || p[0] > 1)
			return (-1);
		if (lighting_tid_is_new(&s->last_src, &s->last_dst, &s->last_tid,
		    &s->tid_valid, &s->tid_expires_ms, rx->src, rx->dst, p[1],
		    rx->now_ms)) {
			transition_time = lighting_effective_transition(s->lightness,
			    plen == 4, plen == 4 ? p[2] : 0);
			delay = plen == 4 ? p[3] : 0;
			if (delay != 0 ||
			    mesh_transition_time_ms(transition_time) != 0) {
				mesh_transition_start(&s->transition,
				    s->light_onoff, p[0], transition_time, delay,
				    rx->now_ms);
				lc_update(s, rx->now_ms);
			} else {
				s->transition.active = 0;
				if (mesh_light_lc_set(s, s->mode, p[0]) != 0)
					return (-1);
			}
		}
		status_op = MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS;
	}

	if (!ack) {
		memset(r, 0, sizeof(*r));
		return (0);
	}
	reply_init(rx, r, status_op);
	r->params[0] = s->light_onoff;
	if (status_op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS &&
	    s->transition.active) {
		r->params[1] = (uint8_t)s->transition.target;
		r->params[2] = mesh_transition_remaining(
		    s->transition.end_ms - rx->now_ms);
		r->params_len = 3;
	} else
		r->params_len = 1;
	return (0);
}
static int lc_setup_handler(const struct mesh_access_rx *rx){
        struct mesh_light_lc_srv *s = rx->model_user;
        struct mesh_model_reply *r = rx->ctx;
        uint32_t op = rx->pdu->opcode;
        int     ack;
        if (s == NULL || r == NULL)
                return -1;
        if (op == MESH_OP_LIGHT_LC_PROPERTY_GET) {
                if (rx->pdu->params_len != 2)
                        return -1;
                return lc_prop(s, get_u16(rx->pdu->params), NULL, 0, 0, r, rx);
        } ack = op == MESH_OP_LIGHT_LC_PROPERTY_SET;
        if (!ack && op != MESH_OP_LIGHT_LC_PROPERTY_SET_UNACK)
                return -1;
        if (rx->pdu->params_len < 2)
                return -1;
        if (lc_prop(s, get_u16(rx->pdu->params), rx->pdu->params + 2, rx->pdu->params_len - 2, 1, r, rx))
                return -1;
        if (!ack)
                memset(r, 0, sizeof(*r));
        return 0;
}
static const struct mesh_opcode_entry lc_ops[] = {{MESH_OP_LIGHT_LC_MODE_GET, lc_handler}, {MESH_OP_LIGHT_LC_MODE_SET, lc_handler}, {MESH_OP_LIGHT_LC_MODE_SET_UNACK, lc_handler}, {MESH_OP_LIGHT_LC_OM_GET, lc_handler}, {MESH_OP_LIGHT_LC_OM_SET, lc_handler}, {MESH_OP_LIGHT_LC_OM_SET_UNACK, lc_handler}, {MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET, lc_handler}, {MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET, lc_handler}, {MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK, lc_handler}};
static const struct mesh_opcode_entry lc_setup_ops[] = {{MESH_OP_LIGHT_LC_PROPERTY_GET, lc_setup_handler}, {MESH_OP_LIGHT_LC_PROPERTY_SET, lc_setup_handler}, {MESH_OP_LIGHT_LC_PROPERTY_SET_UNACK, lc_setup_handler}};
struct mesh_model mesh_light_lc_srv_model(struct mesh_light_lc_srv *s){
	struct mesh_model model = lighting_model(s, MESH_MODEL_LIGHT_LC_SRV,
	    lc_ops, sizeof(lc_ops) / sizeof(lc_ops[0]));
	model.tick = lc_tick;
	return model;
} struct mesh_model mesh_light_lc_setup_srv_model(struct mesh_light_lc_srv *s){
	return lighting_model(s, MESH_MODEL_LIGHT_LC_SETUP_SRV, lc_setup_ops, sizeof(lc_setup_ops) / sizeof(lc_setup_ops[0]));
}
void    mesh_light_lc_cli_init(struct mesh_light_lc_cli *c){
        if (c)
                memset(c, 0, sizeof(*c));
} int   mesh_light_lc_cli_get(uint32_t op, uint16_t id, uint8_t * o, size_t * n) {
        uint8_t p[2];
        if (op == MESH_OP_LIGHT_LC_PROPERTY_GET) {
                if (id == 0)
                        return -1;
                put_u16(p, id);
                return mesh_access_pdu_build(op, p, 2, o, n);
        } if (op != MESH_OP_LIGHT_LC_MODE_GET && op != MESH_OP_LIGHT_LC_OM_GET && op != MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET)
                return -1;
        return mesh_access_pdu_build(op, NULL, 0, o, n);
}

static int
lc_cli_mode_set(uint32_t opcode, uint8_t mode, int ack, uint8_t *out,
    size_t *outlen)
{
	if (mode > 1)
		return (-1);
	return (mesh_access_pdu_build(ack ? opcode : opcode + 1, &mode, 1,
	    out, outlen));
}

int
mesh_light_lc_cli_mode_set(uint8_t mode, int ack, uint8_t *out,
    size_t *outlen)
{
	return (lc_cli_mode_set(MESH_OP_LIGHT_LC_MODE_SET, mode, ack, out,
	    outlen));
}

int
mesh_light_lc_cli_occupancy_set(uint8_t mode, int ack, uint8_t *out,
    size_t *outlen)
{
	return (lc_cli_mode_set(MESH_OP_LIGHT_LC_OM_SET, mode, ack, out,
	    outlen));
}

int
mesh_light_lc_cli_light_onoff_set(const struct mesh_light_lc_onoff_set *set,
    int ack, uint8_t *out, size_t *outlen)
{
	uint8_t p[4];
	size_t plen;

	if (set == NULL || set->light_onoff > 1)
		return (-1);
	p[0] = set->light_onoff;
	p[1] = set->tid;
	plen = 2;
	if (set->transition.has_transition) {
		p[2] = set->transition.transition_time;
		p[3] = set->transition.delay;
		plen = 4;
	}
	return (mesh_access_pdu_build(ack ? MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET :
	    MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK, p, plen, out, outlen));
}

int   mesh_light_lc_cli_property_set(uint16_t id, const uint8_t * v, size_t l, int ack, uint8_t * o, size_t * n){
        uint8_t p[6];
        if (id == 0 || (v == NULL && l != 0) ||
            l > MESH_LIGHT_LC_PROPERTY_VALUE_MAX)
                return -1;
        put_u16(p, id);
        if (l != 0)
                memcpy(p + 2, v, l);
        return mesh_access_pdu_build(ack ? MESH_OP_LIGHT_LC_PROPERTY_SET : MESH_OP_LIGHT_LC_PROPERTY_SET_UNACK, p, l + 2, o, n);
} int   mesh_light_lc_cli_recv(struct mesh_light_lc_cli *c, uint32_t op, const uint8_t * p, size_t n){
        uint16_t id;

        if (c == NULL || p == NULL)
                return -1;
        if (n == 1) {
                if (p[0] > 1)
                        return -1;
                if (op == MESH_OP_LIGHT_LC_MODE_STATUS)
                        c->mode = p[0];
                else if (op == MESH_OP_LIGHT_LC_OM_STATUS)
                        c->occupancy_mode = p[0];
                else if (op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS)
                        c->light_onoff = p[0];
                else
                        return -1;
                if (op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS)
			c->has_target = 0;
                return 0;
	} if (op == MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS && n == 3) {
		if (p[0] > 1 || p[1] > 1)
			return (-1);
		c->light_onoff = p[0];
		c->target_light_onoff = p[1];
		c->remaining_time = p[2];
		c->has_target = 1;
		return (0);
        } if (op == MESH_OP_LIGHT_LC_PROPERTY_STATUS && n >= 2 && n <= 6) {
                id = get_u16(p);
                if (id == 0)
                        return -1;
                c->property_id = id;
                c->property_len = n - 2;
                memcpy(c->property, p + 2, n - 2);
                return 0;
        } return -1;
}
