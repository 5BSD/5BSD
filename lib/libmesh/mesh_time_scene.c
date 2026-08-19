/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include "mesh_time_scene.h"
#include "mesh_generic.h"

int
mesh_time_state_encode(const struct mesh_time_state *state, uint8_t out[10])
{
	uint16_t packed;

	if (state == NULL || out == NULL || state->tai_seconds > MESH_TIME_TAI_MAX ||
	    state->tai_utc_delta > 0x7fff || state->time_authority > 1)
		return (-1);
	out[0] = state->tai_seconds;
	out[1] = state->tai_seconds >> 8;
	out[2] = state->tai_seconds >> 16;
	out[3] = state->tai_seconds >> 24;
	out[4] = state->tai_seconds >> 32;
	out[5] = state->subsecond;
	out[6] = state->uncertainty;
	/*
	 * MMDL Section 1.5: Time Authority is bit 0 and TAI-UTC Delta occupies
	 * bits 1..15 of the little-endian 16-bit word.
	 */
	packed = (uint16_t)(state->time_authority & 0x01) |
	    (uint16_t)(state->tai_utc_delta << 1);
	out[7] = packed;
	out[8] = packed >> 8;
	out[9] = state->time_zone_offset;
	return (0);
}

int
mesh_time_state_decode(const uint8_t *in, size_t inlen,
    struct mesh_time_state *state)
{
	uint16_t packed;

	if (in == NULL || state == NULL || inlen != 10)
		return (-1);
	memset(state, 0, sizeof(*state));
	state->tai_seconds = (uint64_t)in[0] | ((uint64_t)in[1] << 8) |
	    ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24) |
	    ((uint64_t)in[4] << 32);
	state->subsecond = in[5];
	state->uncertainty = in[6];
	packed = (uint16_t)in[7] | ((uint16_t)in[8] << 8);
	state->time_authority = packed & 0x01;
	state->tai_utc_delta = (packed >> 1) & 0x7fff;
	state->time_zone_offset = in[9];
	return (0);
}

static void
put_tai40(uint8_t out[5], uint64_t tai)
{
	unsigned int i;
	for (i = 0; i < 5; i++) out[i] = tai >> (8 * i);
}

static uint64_t
get_tai40(const uint8_t in[5])
{
	uint64_t tai = 0;
	unsigned int i;
	for (i = 0; i < 5; i++) tai |= (uint64_t)in[i] << (8 * i);
	return (tai);
}

void
mesh_time_srv_init(struct mesh_time_srv *srv)
{
	if (srv == NULL) return;
	memset(srv, 0, sizeof(*srv));
	srv->time.time_zone_offset = 0x40;
	srv->new_zone_offset = 0x40;
}

void
mesh_time_srv_tick(struct mesh_time_srv *srv, uint64_t tai)
{
	if (srv == NULL || tai > MESH_TIME_TAI_MAX) return;
	srv->time.tai_seconds = tai;
	if (srv->zone_change != 0 && tai >= srv->zone_change) {
		srv->time.time_zone_offset = srv->new_zone_offset;
		srv->zone_change = 0;
	}
	if (srv->delta_change != 0 && tai >= srv->delta_change) {
		srv->time.tai_utc_delta = srv->new_tai_utc_delta;
		srv->delta_change = 0;
	}
}

static void
time_reply_init(const struct mesh_access_rx *rx, struct mesh_model_reply *reply,
    uint32_t opcode)
{
	memset(reply, 0, sizeof(*reply));
	reply->have_reply = 1; reply->src = rx->elem_addr; reply->dst = rx->src;
	reply->opcode = opcode;
}

static int
time_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_time_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint16_t packed;

	if (srv == NULL || reply == NULL) return (-1);
	switch (rx->pdu->opcode) {
	case MESH_OP_TIME_GET:
		if (rx->pdu->params_len != 0) return (-1);
		time_reply_init(rx, reply, MESH_OP_TIME_STATUS);
		if (srv->time.tai_seconds == 0) {
			memset(reply->params, 0, 5); reply->params_len = 5;
		} else if (mesh_time_state_encode(&srv->time, reply->params) == 0)
			reply->params_len = 10;
		else return (-1);
		break;
	case MESH_OP_TIME_ROLE_GET:
		if (rx->pdu->params_len != 0) return (-1);
		time_reply_init(rx, reply, MESH_OP_TIME_ROLE_STATUS);
		reply->params[0] = srv->role; reply->params_len = 1;
		break;
	case MESH_OP_TIME_ZONE_GET:
		if (rx->pdu->params_len != 0) return (-1);
		time_reply_init(rx, reply, MESH_OP_TIME_ZONE_STATUS);
		reply->params[0] = srv->time.time_zone_offset;
		reply->params[1] = srv->new_zone_offset;
		put_tai40(reply->params + 2, srv->zone_change); reply->params_len = 7;
		break;
	case MESH_OP_TAI_UTC_DELTA_GET:
		if (rx->pdu->params_len != 0) return (-1);
		time_reply_init(rx, reply, MESH_OP_TAI_UTC_DELTA_STATUS);
		packed = srv->time.tai_utc_delta;
		reply->params[0] = packed; reply->params[1] = packed >> 8;
		packed = srv->new_tai_utc_delta;
		reply->params[2] = packed; reply->params[3] = packed >> 8;
		put_tai40(reply->params + 4, srv->delta_change); reply->params_len = 9;
		break;
	default: return (-1);
	}
	return (0);
}

static int
time_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_time_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	uint16_t delta;

	if (srv == NULL || reply == NULL) return (-1);
	switch (rx->pdu->opcode) {
	case MESH_OP_TIME_SET:
		if (mesh_time_state_decode(rx->pdu->params, rx->pdu->params_len,
		    &srv->time) != 0) return (-1);
		time_reply_init(rx, reply, MESH_OP_TIME_STATUS);
		/*
		 * LOW / MMDL 5.2.1.5: the echoed Time Status honors the omission
		 * rule -- when TAI Seconds is 0 the message carries only the
		 * 5-octet zero TAI Seconds field, not the full 10-octet body.
		 */
		if (srv->time.tai_seconds == 0) {
			memset(reply->params, 0, 5); reply->params_len = 5;
		} else if (mesh_time_state_encode(&srv->time, reply->params) == 0)
			reply->params_len = 10;
		else return (-1);
		break;
	case MESH_OP_TIME_ROLE_SET:
		if (rx->pdu->params_len != 1 || rx->pdu->params[0] > 3) return (-1);
		srv->role = rx->pdu->params[0];
		time_reply_init(rx, reply, MESH_OP_TIME_ROLE_STATUS);
		reply->params[0] = srv->role; reply->params_len = 1;
		break;
	case MESH_OP_TIME_ZONE_SET:
		if (rx->pdu->params_len != 6) return (-1);
		srv->new_zone_offset = rx->pdu->params[0];
		srv->zone_change = get_tai40(rx->pdu->params + 1);
		time_reply_init(rx, reply, MESH_OP_TIME_ZONE_STATUS);
		reply->params[0] = srv->time.time_zone_offset;
		reply->params[1] = srv->new_zone_offset;
		put_tai40(reply->params + 2, srv->zone_change); reply->params_len = 7;
		break;
	case MESH_OP_TAI_UTC_DELTA_SET:
		if (rx->pdu->params_len != 7 || (rx->pdu->params[1] & 0x80) != 0)
			return (-1);
		delta = (uint16_t)rx->pdu->params[0] |
		    ((uint16_t)rx->pdu->params[1] << 8);
		srv->new_tai_utc_delta = delta;
		srv->delta_change = get_tai40(rx->pdu->params + 2);
		time_reply_init(rx, reply, MESH_OP_TAI_UTC_DELTA_STATUS);
		delta = srv->time.tai_utc_delta;
		reply->params[0] = delta; reply->params[1] = delta >> 8;
		delta = srv->new_tai_utc_delta;
		reply->params[2] = delta; reply->params[3] = delta >> 8;
		put_tai40(reply->params + 4, srv->delta_change); reply->params_len = 9;
		break;
	default: return (-1);
	}
	return (0);
}

static const struct mesh_opcode_entry time_srv_ops[] = {
	{ MESH_OP_TIME_GET, time_srv_handler },
	{ MESH_OP_TIME_ROLE_GET, time_srv_handler },
	{ MESH_OP_TIME_ZONE_GET, time_srv_handler },
	{ MESH_OP_TAI_UTC_DELTA_GET, time_srv_handler },
};
static const struct mesh_opcode_entry time_setup_ops[] = {
	{ MESH_OP_TIME_SET, time_setup_handler },
	{ MESH_OP_TIME_ROLE_SET, time_setup_handler },
	{ MESH_OP_TIME_ZONE_SET, time_setup_handler },
	{ MESH_OP_TAI_UTC_DELTA_SET, time_setup_handler },
};

static struct mesh_model
time_model(struct mesh_time_srv *srv, uint16_t id,
    const struct mesh_opcode_entry *ops, size_t nops)
{
	struct mesh_model m;
	memset(&m, 0, sizeof(m)); m.model_id = id; m.company_id = MESH_COMPANY_SIG;
	m.ops = ops; m.n_ops = nops; m.user = srv; return (m);
}

struct mesh_model
mesh_time_srv_model(struct mesh_time_srv *srv)
{
	return (time_model(srv, MESH_MODEL_TIME_SRV, time_srv_ops,
	    sizeof(time_srv_ops) / sizeof(time_srv_ops[0])));
}

struct mesh_model
mesh_time_setup_srv_model(struct mesh_time_srv *srv)
{
	return (time_model(srv, MESH_MODEL_TIME_SETUP_SRV, time_setup_ops,
	    sizeof(time_setup_ops) / sizeof(time_setup_ops[0])));
}

void
mesh_time_cli_init(struct mesh_time_cli *cli)
{
	if (cli != NULL) memset(cli, 0, sizeof(*cli));
}

static int
time_cli_empty(uint32_t op, uint8_t *out, size_t *outlen)
{
	return (mesh_access_pdu_build(op, NULL, 0, out, outlen));
}
int mesh_time_cli_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_TIME_GET, o, n)); }
int mesh_time_cli_role_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_TIME_ROLE_GET, o, n)); }
int mesh_time_cli_zone_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_TIME_ZONE_GET, o, n)); }
int mesh_time_cli_delta_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_TAI_UTC_DELTA_GET, o, n)); }

int
mesh_time_cli_set(const struct mesh_time_state *state, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[10];
	if (mesh_time_state_encode(state, p) != 0) return (-1);
	return (mesh_access_pdu_build(MESH_OP_TIME_SET, p, 10, out, outlen));
}

int
mesh_time_cli_role_set(uint8_t role, uint8_t *out, size_t *outlen)
{
	if (role > 3) return (-1);
	return (mesh_access_pdu_build(MESH_OP_TIME_ROLE_SET, &role, 1, out, outlen));
}

int
mesh_time_cli_zone_set(uint8_t zone, uint64_t change, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[6];
	if (change > MESH_TIME_TAI_MAX) return (-1);
	p[0] = zone; put_tai40(p + 1, change);
	return (mesh_access_pdu_build(MESH_OP_TIME_ZONE_SET, p, 6, out, outlen));
}

int
mesh_time_cli_delta_set(uint16_t delta, uint64_t change, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[7];
	if (delta > 0x7fff || change > MESH_TIME_TAI_MAX) return (-1);
	p[0] = delta; p[1] = delta >> 8; put_tai40(p + 2, change);
	return (mesh_access_pdu_build(MESH_OP_TAI_UTC_DELTA_SET, p, 7, out, outlen));
}

int
mesh_time_cli_recv(struct mesh_time_cli *cli, uint32_t opcode,
    const uint8_t *p, size_t n)
{
	if (cli == NULL || p == NULL) return (-1);
	switch (opcode) {
	case MESH_OP_TIME_STATUS:
		if (n == 5 && get_tai40(p) == 0) memset(&cli->time, 0, sizeof(cli->time));
		else if (mesh_time_state_decode(p, n, &cli->time) != 0) return (-1);
		break;
	case MESH_OP_TIME_ROLE_STATUS:
		if (n != 1 || p[0] > 3) return (-1); cli->role = p[0]; break;
	case MESH_OP_TIME_ZONE_STATUS:
		if (n != 7) return (-1); cli->current_zone_offset = p[0];
		cli->new_zone_offset = p[1]; cli->zone_change = get_tai40(p + 2); break;
	case MESH_OP_TAI_UTC_DELTA_STATUS:
		if (n != 9 || (p[1] & 0x80) != 0 || (p[3] & 0x80) != 0) return (-1);
		cli->current_tai_utc_delta = p[0] | ((uint16_t)p[1] << 8);
		cli->new_tai_utc_delta = p[2] | ((uint16_t)p[3] << 8);
		cli->delta_change = get_tai40(p + 4); break;
	default: return (-1);
	}
	cli->last_opcode = opcode; return (0);
}

void
mesh_scene_srv_init(struct mesh_scene_srv *srv, mesh_scene_capture_fn capture,
    mesh_scene_recall_fn recall, void *arg)
{
	if (srv == NULL) return;
	memset(srv, 0, sizeof(*srv)); srv->capture = capture;
	srv->recall = recall; srv->cb_arg = arg;
}

static struct mesh_scene_entry *
scene_find(struct mesh_scene_srv *srv, uint16_t number)
{
	size_t i;
	if (srv == NULL || number == 0) return (NULL);
	for (i = 0; i < srv->n_scenes; i++)
		if (srv->scenes[i].number == number) return (&srv->scenes[i]);
	return (NULL);
}

int
mesh_scene_srv_store(struct mesh_scene_srv *srv, uint16_t number)
{
	struct mesh_scene_entry *entry;
	uint8_t data[MESH_SCENE_DATA_MAX];
	size_t pos, len = 0;

	if (srv == NULL || number == 0 || srv->capture == NULL) return (-1);
	/* Capture into scratch storage so a failed callback cannot mutate state. */
	if (srv->capture(srv->cb_arg, data, sizeof(data), &len) != 0 ||
	    len > sizeof(data))
		return (-1);
	entry = scene_find(srv, number);
	if (entry == NULL) {
		if (srv->n_scenes >= MESH_SCENE_MAX) return (-1);
		for (pos = 0; pos < srv->n_scenes && srv->scenes[pos].number < number;
		    pos++) /* sorted insertion */;
		memmove(&srv->scenes[pos + 1], &srv->scenes[pos],
		    (srv->n_scenes - pos) * sizeof(srv->scenes[0]));
		entry = &srv->scenes[pos]; memset(entry, 0, sizeof(*entry));
		entry->number = number; srv->n_scenes++;
	}
	if (len != 0)
		memcpy(entry->data, data, len);
	entry->data_len = len; srv->current_scene = number;
	srv->target_scene = 0; return (0);
}

int
mesh_scene_srv_delete(struct mesh_scene_srv *srv, uint16_t number)
{
	size_t i;
	if (srv == NULL || number == 0) return (-1);
	for (i = 0; i < srv->n_scenes; i++) if (srv->scenes[i].number == number) {
		memmove(&srv->scenes[i], &srv->scenes[i + 1],
		    (srv->n_scenes - i - 1) * sizeof(srv->scenes[0]));
		srv->n_scenes--;
		if (srv->current_scene == number) srv->current_scene = 0;
		if (srv->target_scene == number) srv->target_scene = 0;
		break;
	}
	return (0); /* deleting an absent scene is Success */
}

int
mesh_scene_srv_recall(struct mesh_scene_srv *srv, uint16_t number)
{
	struct mesh_scene_entry *entry = scene_find(srv, number);
	if (entry == NULL || srv->recall == NULL ||
	    srv->recall(srv->cb_arg, entry->data, entry->data_len) != 0) return (-1);
	srv->current_scene = number; srv->target_scene = 0; return (0);
}

static void
scene_status_reply(const struct mesh_access_rx *rx, struct mesh_model_reply *r,
    uint8_t status, struct mesh_scene_srv *srv)
{
	time_reply_init(rx, r, MESH_OP_SCENE_STATUS); r->params[0] = status;
	r->params[1] = srv->current_scene;
	r->params[2] = srv->current_scene >> 8;
	if (srv->transition.active) {
		r->params[3] = srv->target_scene;
		r->params[4] = srv->target_scene >> 8;
		r->params[5] = mesh_transition_remaining(
		    srv->transition.end_ms - rx->now_ms);
		r->params_len = 6;
	} else
		r->params_len = 3;
}

static int
scene_tid_is_new(struct mesh_scene_srv *srv, uint16_t src, uint16_t dst,
    uint8_t tid, uint64_t now_ms)
{
	if (srv->tid_valid && srv->last_src == src && srv->last_dst == dst &&
	    srv->last_tid == tid && now_ms <= srv->tid_expires_ms) {
		/*
		 * MMDL Section 3.1: the 6 s transaction window runs from the
		 * PREVIOUS same-TID message, so a retransmission refreshes it.
		 */
		srv->tid_expires_ms = now_ms + 6000;
		return (0);
	}
	srv->last_src = src;
	srv->last_dst = dst;
	srv->last_tid = tid;
	srv->tid_valid = 1;
	srv->tid_expires_ms = now_ms + 6000;
	return (1);
}

static void
scene_register_reply(const struct mesh_access_rx *rx,
    struct mesh_model_reply *r, struct mesh_scene_srv *srv, uint8_t status)
{
	size_t i;
	time_reply_init(rx, r, MESH_OP_SCENE_REGISTER_STATUS); r->params[0] = status;
	r->params[1] = srv->current_scene; r->params[2] = srv->current_scene >> 8;
	for (i = 0; i < srv->n_scenes; i++) {
		r->params[3 + 2*i] = srv->scenes[i].number;
		r->params[4 + 2*i] = srv->scenes[i].number >> 8;
	}
	r->params_len = 3 + 2 * srv->n_scenes;
}

static int
scene_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_scene_srv *srv = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	uint16_t number;
	uint8_t status, transition_time, delay;

	if (srv == NULL || r == NULL) return (-1);
	mesh_scene_srv_tick(srv, rx->now_ms);
	if (rx->pdu->opcode == MESH_OP_SCENE_GET) {
		if (rx->pdu->params_len != 0) return (-1);
		scene_status_reply(rx, r, 0, srv); return (0);
	}
	if (rx->pdu->opcode == MESH_OP_SCENE_REGISTER_GET) {
		if (rx->pdu->params_len != 0) return (-1);
		scene_register_reply(rx, r, srv, 0); return (0);
	}
	if ((rx->pdu->opcode != MESH_OP_SCENE_RECALL &&
	    rx->pdu->opcode != MESH_OP_SCENE_RECALL_UNACK) ||
	    (rx->pdu->params_len != 3 && rx->pdu->params_len != 5)) return (-1);
	if (rx->pdu->params_len == 5 &&
	    !mesh_transition_time_valid(rx->pdu->params[3])) return (-1);
	number = rx->pdu->params[0] | ((uint16_t)rx->pdu->params[1] << 8);
	if (number == 0) return (-1);
	if (scene_tid_is_new(srv, rx->src, rx->dst, rx->pdu->params[2],
	    rx->now_ms)) {
		transition_time = rx->pdu->params_len == 5 ?
		    rx->pdu->params[3] :
		    (srv->dtt != NULL ? srv->dtt->transition_time : 0);
		delay = rx->pdu->params_len == 5 ? rx->pdu->params[4] : 0;
		if (scene_find(srv, number) == NULL)
			status = 2;
		else if (delay != 0 ||
		    mesh_transition_time_ms(transition_time) != 0) {
			srv->target_scene = number;
			mesh_transition_start(&srv->transition, srv->current_scene,
			    number, transition_time, delay,
			    rx->now_ms);
			/*
			 * P-M9 / MMDL 5.1.3.2.1: while a scene transition is in
			 * progress the Current Scene shall be 0x0000; it is
			 * restored to the target on completion (mesh_scene_srv_tick
			 * -> mesh_scene_srv_recall).
			 */
			srv->current_scene = 0;
			status = 0;
		} else {
			srv->transition.active = 0;
			status = mesh_scene_srv_recall(srv, number) == 0 ? 0 : 2;
		}
	} else status = scene_find(srv, number) != NULL ? 0 : 2;
	if (rx->pdu->opcode == MESH_OP_SCENE_RECALL_UNACK) {
		memset(r, 0, sizeof(*r)); return (0);
	}
	scene_status_reply(rx, r, status, srv); return (0);
}

static int
scene_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_scene_srv *srv = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	uint16_t number;
	uint8_t status = 0;
	int ack;

	if (srv == NULL || r == NULL || rx->pdu->params_len != 2) return (-1);
	number = rx->pdu->params[0] | ((uint16_t)rx->pdu->params[1] << 8);
	if (number == 0) return (-1);
	ack = rx->pdu->opcode == MESH_OP_SCENE_STORE ||
	    rx->pdu->opcode == MESH_OP_SCENE_DELETE;
	if (rx->pdu->opcode == MESH_OP_SCENE_STORE ||
	    rx->pdu->opcode == MESH_OP_SCENE_STORE_UNACK) {
		/*
		 * LOW / MMDL 5.2.2.11: "Scene Register Full" (0x01) is reported
		 * ONLY when a new scene cannot be added because the register is
		 * full.  A capture-callback failure is an internal error, not a
		 * full register, so it must not be reported as Register Full;
		 * with no status code defined for it the store is reported as
		 * Success (the spec assumes capture cannot fail).
		 */
		if (scene_find(srv, number) == NULL &&
		    srv->n_scenes >= MESH_SCENE_MAX)
			status = 1;
		else
			(void)mesh_scene_srv_store(srv, number);
	} else if (rx->pdu->opcode == MESH_OP_SCENE_DELETE ||
	    rx->pdu->opcode == MESH_OP_SCENE_DELETE_UNACK) {
		(void)mesh_scene_srv_delete(srv, number);
	} else return (-1);
	if (ack) scene_register_reply(rx, r, srv, status);
	else memset(r, 0, sizeof(*r));
	return (0);
}

static const struct mesh_opcode_entry scene_srv_ops[] = {
	{ MESH_OP_SCENE_GET, scene_srv_handler },
	{ MESH_OP_SCENE_RECALL, scene_srv_handler },
	{ MESH_OP_SCENE_RECALL_UNACK, scene_srv_handler },
	{ MESH_OP_SCENE_REGISTER_GET, scene_srv_handler },
};
static const struct mesh_opcode_entry scene_setup_ops[] = {
	{ MESH_OP_SCENE_STORE, scene_setup_handler },
	{ MESH_OP_SCENE_STORE_UNACK, scene_setup_handler },
	{ MESH_OP_SCENE_DELETE, scene_setup_handler },
	{ MESH_OP_SCENE_DELETE_UNACK, scene_setup_handler },
};

void
mesh_scene_srv_tick(struct mesh_scene_srv *srv, uint64_t now_ms)
{
	if (srv == NULL || !srv->transition.active ||
	    now_ms < srv->transition.end_ms)
		return;
	srv->transition.active = 0;
	(void)mesh_scene_srv_recall(srv, srv->target_scene);
}

static void
scene_model_tick(void *arg, uint64_t now_ms)
{
	mesh_scene_srv_tick(arg, now_ms);
}

struct mesh_model mesh_scene_srv_model(struct mesh_scene_srv *s) {
	struct mesh_model model;

	model = time_model((struct mesh_time_srv *)(void *)s,
	    MESH_MODEL_SCENE_SRV, scene_srv_ops,
	    sizeof(scene_srv_ops) / sizeof(scene_srv_ops[0]));
	model.tick = scene_model_tick;
	return (model); }
struct mesh_model mesh_scene_setup_srv_model(struct mesh_scene_srv *s) {
	return (time_model((struct mesh_time_srv *)(void *)s, MESH_MODEL_SCENE_SETUP_SRV,
	    scene_setup_ops, sizeof(scene_setup_ops) / sizeof(scene_setup_ops[0]))); }

void mesh_scene_cli_init(struct mesh_scene_cli *c) { if (c != NULL) memset(c, 0, sizeof(*c)); }
int mesh_scene_cli_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_SCENE_GET, o, n)); }
int mesh_scene_cli_register_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_SCENE_REGISTER_GET, o, n)); }

static int
scene_cli_number(uint32_t op, uint16_t number, uint8_t *out, size_t *outlen)
{
	uint8_t p[2]; if (number == 0) return (-1);
	p[0] = number; p[1] = number >> 8;
	return (mesh_access_pdu_build(op, p, 2, out, outlen));
}
int mesh_scene_cli_store(uint16_t s, int a, uint8_t *o, size_t *n) { return (scene_cli_number(a ? MESH_OP_SCENE_STORE : MESH_OP_SCENE_STORE_UNACK, s, o, n)); }
int mesh_scene_cli_delete(uint16_t s, int a, uint8_t *o, size_t *n) { return (scene_cli_number(a ? MESH_OP_SCENE_DELETE : MESH_OP_SCENE_DELETE_UNACK, s, o, n)); }

int
mesh_scene_cli_recall(uint16_t scene, uint8_t tid, int ack, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[3]; if (scene == 0) return (-1);
	p[0] = scene; p[1] = scene >> 8; p[2] = tid;
	return (mesh_access_pdu_build(ack ? MESH_OP_SCENE_RECALL :
	    MESH_OP_SCENE_RECALL_UNACK, p, 3, out, outlen));
}

int
mesh_scene_cli_recv(struct mesh_scene_cli *c, uint32_t op, const uint8_t *p,
    size_t n)
{
	size_t i;
	if (c == NULL || p == NULL) return (-1);
	if (op == MESH_OP_SCENE_STATUS) {
		if (n != 3 && n != 6) return (-1); c->status = p[0];
		c->current_scene = p[1] | ((uint16_t)p[2] << 8);
		c->target_scene = n == 6 ? p[3] | ((uint16_t)p[4] << 8) : 0;
		c->remaining_time = n == 6 ? p[5] : 0;
	} else if (op == MESH_OP_SCENE_REGISTER_STATUS) {
		if (n < 3 || ((n - 3) & 1) != 0 || (n - 3) / 2 > MESH_SCENE_MAX)
			return (-1);
		c->status = p[0]; c->current_scene = p[1] | ((uint16_t)p[2] << 8);
		c->n_scenes = (n - 3) / 2;
		for (i = 0; i < c->n_scenes; i++)
			c->scenes[i] = p[3 + 2*i] | ((uint16_t)p[4 + 2*i] << 8);
	} else return (-1);
	return (0);
}

static void
bits_put(uint8_t out[10], unsigned int off, unsigned int width, uint32_t value)
{
	unsigned int i;
	for (i = 0; i < width; i++) if ((value & (UINT32_C(1) << i)) != 0)
		out[(off + i) / 8] |= UINT8_C(1) << ((off + i) % 8);
}

static uint32_t
bits_get(const uint8_t in[10], unsigned int off, unsigned int width)
{
	uint32_t value = 0;
	unsigned int i;
	for (i = 0; i < width; i++) if ((in[(off + i) / 8] &
	    (UINT8_C(1) << ((off + i) % 8))) != 0) value |= UINT32_C(1) << i;
	return (value);
}

static int
scheduler_action_valid(const struct mesh_scheduler_action *a)
{
	if (a == NULL || a->index >= MESH_SCHEDULER_MAX || a->year > 0x64 ||
	    a->months > 0xfff || a->day > 0x1f ||
	    a->hour > 0x19 || a->minute > 0x3f || a->second > 0x3f ||
	    a->days_of_week > 0x7f ||
	    (a->action != 0 && a->action != 1 && a->action != 2 && a->action != 0xf) ||
	    (a->transition_time & 0x3f) == 0x3f ||
	    (a->action == 2 && a->scene_number == 0)) return (0);
	return (1);
}

int
mesh_scheduler_action_encode(const struct mesh_scheduler_action *a,
    uint8_t out[10])
{
	if (!scheduler_action_valid(a) || out == NULL) return (-1);
	memset(out, 0, 10);
	bits_put(out, 0, 4, a->index); bits_put(out, 4, 7, a->year);
	bits_put(out, 11, 12, a->months); bits_put(out, 23, 5, a->day);
	bits_put(out, 28, 5, a->hour); bits_put(out, 33, 6, a->minute);
	bits_put(out, 39, 6, a->second); bits_put(out, 45, 7, a->days_of_week);
	bits_put(out, 52, 4, a->action); bits_put(out, 56, 8, a->transition_time);
	bits_put(out, 64, 16, a->scene_number);
	return (0);
}

int
mesh_scheduler_action_decode(const uint8_t *in, size_t n,
    struct mesh_scheduler_action *a)
{
	if (in == NULL || n != 10 || a == NULL) return (-1);
	memset(a, 0, sizeof(*a)); a->index = bits_get(in, 0, 4);
	a->year = bits_get(in, 4, 7); a->months = bits_get(in, 11, 12);
	a->day = bits_get(in, 23, 5); a->hour = bits_get(in, 28, 5);
	a->minute = bits_get(in, 33, 6); a->second = bits_get(in, 39, 6);
	a->days_of_week = bits_get(in, 45, 7); a->action = bits_get(in, 52, 4);
	a->transition_time = bits_get(in, 56, 8); a->scene_number = bits_get(in, 64, 16);
	return (scheduler_action_valid(a) ? 0 : -1);
}

void
mesh_scheduler_srv_init(struct mesh_scheduler_srv *srv)
{
	if (srv != NULL) memset(srv, 0, sizeof(*srv));
}

static int
scheduler_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_scheduler_srv *srv = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	uint8_t index;

	if (srv == NULL || r == NULL) return (-1);
	if (rx->pdu->opcode == MESH_OP_SCHEDULER_GET) {
		if (rx->pdu->params_len != 0) return (-1);
		time_reply_init(rx, r, MESH_OP_SCHEDULER_STATUS);
		r->params[0] = srv->defined; r->params[1] = srv->defined >> 8;
		r->params_len = 2; return (0);
	}
	if (rx->pdu->opcode != MESH_OP_SCHEDULER_ACTION_GET ||
	    rx->pdu->params_len != 1 || rx->pdu->params[0] > 0x0f) return (-1);
	index = rx->pdu->params[0]; time_reply_init(rx, r, MESH_OP_SCHEDULER_ACTION_STATUS);
	if ((srv->defined & (1u << index)) != 0) {
		if (mesh_scheduler_action_encode(&srv->entries[index], r->params) != 0)
			return (-1);
		r->params_len = 10;
	} else { r->params[0] = index; r->params_len = 1; }
	return (0);
}

static int
scheduler_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_scheduler_srv *srv = rx->model_user;
	struct mesh_model_reply *r = rx->ctx;
	struct mesh_scheduler_action action;
	int ack;

	if (srv == NULL || r == NULL ||
	    mesh_scheduler_action_decode(rx->pdu->params, rx->pdu->params_len,
	    &action) != 0) return (-1);
	ack = rx->pdu->opcode == MESH_OP_SCHEDULER_ACTION_SET;
	if (!ack && rx->pdu->opcode != MESH_OP_SCHEDULER_ACTION_SET_UNACK) return (-1);
	if (action.action == 0xf) {
		memset(&srv->entries[action.index], 0, sizeof(srv->entries[0]));
		srv->defined &= ~(1u << action.index);
	} else {
		srv->entries[action.index] = action; srv->defined |= 1u << action.index;
	}
	if (ack) {
		time_reply_init(rx, r, MESH_OP_SCHEDULER_ACTION_STATUS);
		memcpy(r->params, rx->pdu->params, 10); r->params_len = 10;
	} else memset(r, 0, sizeof(*r));
	return (0);
}

static const struct mesh_opcode_entry scheduler_srv_ops[] = {
	{ MESH_OP_SCHEDULER_GET, scheduler_srv_handler },
	{ MESH_OP_SCHEDULER_ACTION_GET, scheduler_srv_handler },
};
static const struct mesh_opcode_entry scheduler_setup_ops[] = {
	{ MESH_OP_SCHEDULER_ACTION_SET, scheduler_setup_handler },
	{ MESH_OP_SCHEDULER_ACTION_SET_UNACK, scheduler_setup_handler },
};
struct mesh_model mesh_scheduler_srv_model(struct mesh_scheduler_srv *s) {
	return (time_model((struct mesh_time_srv *)(void *)s, MESH_MODEL_SCHEDULER_SRV,
	    scheduler_srv_ops, sizeof(scheduler_srv_ops) / sizeof(scheduler_srv_ops[0]))); }
struct mesh_model mesh_scheduler_setup_srv_model(struct mesh_scheduler_srv *s) {
	return (time_model((struct mesh_time_srv *)(void *)s, MESH_MODEL_SCHEDULER_SETUP_SRV,
	    scheduler_setup_ops, sizeof(scheduler_setup_ops) / sizeof(scheduler_setup_ops[0]))); }
void mesh_scheduler_cli_init(struct mesh_scheduler_cli *c) { if (c != NULL) memset(c, 0, sizeof(*c)); }
int mesh_scheduler_cli_get(uint8_t *o, size_t *n) { return (time_cli_empty(MESH_OP_SCHEDULER_GET, o, n)); }

int
mesh_scheduler_cli_action_get(uint8_t index, uint8_t *out, size_t *outlen)
{
	if (index > 0x0f) return (-1);
	return (mesh_access_pdu_build(MESH_OP_SCHEDULER_ACTION_GET, &index, 1,
	    out, outlen));
}

int
mesh_scheduler_cli_action_set(const struct mesh_scheduler_action *a, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[10];
	if (mesh_scheduler_action_encode(a, p) != 0) return (-1);
	return (mesh_access_pdu_build(ack ? MESH_OP_SCHEDULER_ACTION_SET :
	    MESH_OP_SCHEDULER_ACTION_SET_UNACK, p, 10, out, outlen));
}

int
mesh_scheduler_cli_recv(struct mesh_scheduler_cli *c, uint32_t op,
    const uint8_t *p, size_t n)
{
	if (c == NULL || p == NULL) return (-1);
	if (op == MESH_OP_SCHEDULER_STATUS) {
		if (n != 2) return (-1); c->defined = p[0] | ((uint16_t)p[1] << 8);
		return (0);
	}
	if (op != MESH_OP_SCHEDULER_ACTION_STATUS || (n != 1 && n != 10) ||
	    (n == 1 && p[0] > 0x0f)) return (-1);
	c->action_present = n == 10;
	if (n == 1) { memset(&c->action, 0, sizeof(c->action)); c->action.index = p[0];
		return (0); }
	return (mesh_scheduler_action_decode(p, n, &c->action));
}
