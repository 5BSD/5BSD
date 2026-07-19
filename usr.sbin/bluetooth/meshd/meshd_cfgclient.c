/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd Config Client (MshMDL_v1.1 Section 4.3.4).
 *
 * This is the mesh operability layer's manager-to-node control path: it drives a
 * provisioned node's Configuration Server by sending acknowledged Configuration
 * messages sealed under that node's DevKey and correlating the returned Config
 * *Status*.  It bridges three existing pieces:
 *
 *   - the libmesh Config Client PDU builders (mesh_mgr_cfg_*_pdu), which format a
 *     plaintext Configuration Access PDU for the manager's key set;
 *   - the DevKey transaction engine (mesh_mgr_txn_*), which seals the request to
 *     a roster node, retransmits over a lossy bearer and matches the Status;
 *   - the daemon transmit seam (mesh_sim_send_upper + meshd_drain_tx), which
 *     wraps the sealed Upper Transport PDU in Lower Transport / Network layers,
 *     secures it with the node's subnet credential and hands it to the bearer.
 *
 * The engine (send / rx / tick / status) performs no argument parsing; the verb
 * dispatcher (meshd_cfg_client_verb) turns an operator "cfg <sub-verb> ..." line
 * into a builder call and surfaces the Status.  All logic is pure and testable.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "meshd.h"

/* Upper Transport PDU scratch (bounds a sealed Configuration message). */
#define	CFG_UPPER_MAX	MESH_UPPER_MAX

/* ================================================================
 * Transaction engine.
 * ================================================================ */

int
meshd_cfg_client_send(struct meshd_node *nd, uint16_t dst, const uint8_t *req,
    size_t req_len, uint32_t expect_status_opcode, uint64_t now,
    uint8_t *out_upper, size_t *out_upper_len, uint32_t *out_seq)
{
	struct mesh_mgr_node *node;
	uint8_t upper[CFG_UPPER_MAX];
	size_t upper_len;
	uint32_t seq0;
	int n;

	if (nd == NULL || req == NULL || req_len == 0)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL || nd->self == NULL)
		return (-1);
	node = mesh_mgr_find_by_addr(nd->mgr, dst);
	if (node == NULL)
		return (-1);

	/*
	 * Unify the manager's Config Client sequence space with the node's live
	 * SEQ: the manager and this node are the same device (mgr->self_addr ==
	 * nd->addr), so both must draw from one monotonic SEQ per IV Index
	 * (MshPRT_v1.1 Section 3.8.4).  Seal under the live SEQ, then advance it
	 * past every Network PDU the transmit produced.
	 */
	seq0 = mesh_sim_node_seq(nd->self);
	nd->mgr->seq = seq0;
	if (mesh_mgr_txn_begin(nd->mgr, &nd->cfg_txn, node, req, req_len,
	    expect_status_opcode, now, MESHD_CFG_RETRY_TICKS,
	    MESHD_CFG_MAX_ATTEMPTS, upper, &upper_len, &seq0) != 0)
		return (-1);
	n = mesh_sim_send_upper(&nd->sim, nd->self, dst, seq0, upper, upper_len,
	    0, 0, nd->cfg.default_ttl);
	if (n < 0)
		return (-1);
	nd->self->seq = seq0 + (uint32_t)n;
	nd->mgr->seq = nd->self->seq;
	meshd_drain_tx(nd);

	if (out_upper != NULL && out_upper_len != NULL) {
		memcpy(out_upper, upper, upper_len);
		*out_upper_len = upper_len;
	}
	if (out_seq != NULL)
		*out_seq = seq0;
	return (0);
}

int
meshd_cfg_client_rx(struct meshd_node *nd, uint32_t seq, uint16_t src,
    uint16_t dst, const uint8_t *upper, size_t upper_len)
{
	struct mesh_mgr_node *node;

	if (nd == NULL || upper == NULL)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL)
		return (0);
	if (nd->cfg_txn.state != MESH_MGR_TXN_WAITING)
		return (0);
	node = mesh_mgr_find_by_addr(nd->mgr, nd->cfg_txn.node_addr);
	if (node == NULL)
		return (0);
	return (mesh_mgr_txn_rx(&nd->cfg_txn, nd->mgr, node, seq, src, dst,
	    upper, upper_len));
}

int
meshd_cfg_client_tick(struct meshd_node *nd, uint64_t now)
{
	struct mesh_mgr_node *node;
	uint8_t upper[CFG_UPPER_MAX];
	size_t upper_len;
	uint32_t seq0;
	int r, n;

	if (nd == NULL)
		return (-1);
	if (!nd->mgr_active || nd->mgr == NULL || nd->self == NULL)
		return (0);
	if (nd->cfg_txn.state != MESH_MGR_TXN_WAITING)
		return (0);
	node = mesh_mgr_find_by_addr(nd->mgr, nd->cfg_txn.node_addr);
	if (node == NULL)
		return (0);
	seq0 = mesh_sim_node_seq(nd->self);
	nd->mgr->seq = seq0;
	r = mesh_mgr_txn_tick(nd->mgr, &nd->cfg_txn, node, now, upper,
	    &upper_len, &seq0);
	if (r != 1)
		return (r < 0 ? -1 : 0);
	n = mesh_sim_send_upper(&nd->sim, nd->self, nd->cfg_txn.node_addr, seq0,
	    upper, upper_len, 0, 0, nd->cfg.default_ttl);
	if (n < 0)
		return (-1);
	nd->self->seq = seq0 + (uint32_t)n;
	nd->mgr->seq = nd->self->seq;
	meshd_drain_tx(nd);
	return (1);
}

int
meshd_cfg_client_status(const struct meshd_node *nd, const uint8_t **status,
    size_t *status_len)
{

	if (status != NULL)
		*status = NULL;
	if (status_len != NULL)
		*status_len = 0;
	if (nd == NULL)
		return (MESH_MGR_TXN_IDLE);
	if (nd->cfg_txn.state == MESH_MGR_TXN_COMPLETE) {
		if (status != NULL)
			*status = nd->cfg_txn.status;
		if (status_len != NULL)
			*status_len = nd->cfg_txn.status_len;
	}
	return ((int)nd->cfg_txn.state);
}

/* ================================================================
 * Verb dispatcher.
 * ================================================================ */

/* Parse a strtoul-style unsigned argument with an inclusive upper bound. */
static int
cfg_u32(const char *s, uint32_t max, uint32_t *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (*end != '\0' || errno != 0 || v > max)
		return (-1);
	*out = (uint32_t)v;
	return (0);
}

/*
 * Parse a model identifier from argv[first..argc-1]: exactly one trailing token
 * is a 16-bit SIG model, exactly two are a vendor model (company then model).
 */
static int
cfg_model_tail(int argc, char **argv, int first, struct mesh_cfg_model_id *m)
{
	uint32_t a, b;

	memset(m, 0, sizeof(*m));
	if (argc - first == 1) {
		if (cfg_u32(argv[first], 0xFFFF, &a) != 0)
			return (-1);
		m->vendor = 0;
		m->model_id = (uint16_t)a;
		return (0);
	}
	if (argc - first == 2) {
		if (cfg_u32(argv[first], 0xFFFF, &a) != 0 ||
		    cfg_u32(argv[first + 1], 0xFFFF, &b) != 0)
			return (-1);
		m->vendor = 1;
		m->company_id = (uint16_t)a;
		m->model_id = (uint16_t)b;
		return (0);
	}
	return (-1);
}

/*
 * Surface the outcome of a just-issued transaction.  Over a real bearer the
 * Status arrives asynchronously, so a WAITING transaction reports the send; a
 * COMPLETE one (loopback / test) parses the Status code where a codec exists.
 */
static int
cfg_result(struct meshd_node *nd, const char *verb, uint16_t dst,
    char *reply, size_t reply_max)
{
	const uint8_t *st;
	size_t stlen;
	int state;
	uint8_t status;
	uint16_t a16, b16;
	struct mesh_cfg_model_app app;
	struct mesh_cfg_model_sub sub;

	state = meshd_cfg_client_status(nd, &st, &stlen);
	if (state != MESH_MGR_TXN_COMPLETE || st == NULL) {
		snprintf(reply, reply_max, "OK cfg %s dst=0x%04x sent state=%d",
		    verb, dst, state);
		return (0);
	}

	/* Decode the common Status codes; fall back to a raw report. */
	if (mesh_mgr_cfg_appkey_status_parse(st, stlen, &status, &a16,
	    &b16) == 0) {
		snprintf(reply, reply_max,
		    "OK cfg %s dst=0x%04x status=0x%02x netidx=%u appidx=%u",
		    verb, dst, status, a16, b16);
		return (0);
	}
	if (mesh_mgr_cfg_model_app_status_parse(st, stlen, &status, &app) == 0) {
		snprintf(reply, reply_max,
		    "OK cfg %s dst=0x%04x status=0x%02x elem=0x%04x appidx=%u",
		    verb, dst, status, app.elem_addr, app.app_idx);
		return (0);
	}
	if (mesh_mgr_cfg_model_sub_status_parse(st, stlen, &status, &sub) == 0) {
		snprintf(reply, reply_max,
		    "OK cfg %s dst=0x%04x status=0x%02x elem=0x%04x sub=0x%04x",
		    verb, dst, status, sub.elem_addr, sub.address);
		return (0);
	}
	if (mesh_mgr_cfg_netkey_status_parse(st, stlen, &status, &a16) == 0) {
		snprintf(reply, reply_max,
		    "OK cfg %s dst=0x%04x status=0x%02x netidx=%u", verb, dst,
		    status, a16);
		return (0);
	}
	if (mesh_mgr_cfg_node_reset_status_parse(st, stlen) == 0) {
		snprintf(reply, reply_max, "OK cfg %s dst=0x%04x reset", verb,
		    dst);
		return (0);
	}
	snprintf(reply, reply_max,
	    "OK cfg %s dst=0x%04x status received (%zu octets)", verb, dst,
	    stlen);
	return (0);
}

/*
 * The u8-state node-wide verbs (beacon / gatt-proxy / friend / ttl) share a
 * shape: one optional state octet selects Set vs Get.
 */
static int
cfg_u8_state(struct meshd_node *nd, const char *verb, uint16_t dst, int argc,
    char **argv, int argi, uint32_t get_op, uint32_t set_op, uint64_t now,
    char *reply, size_t reply_max)
{
	uint8_t pdu[MESH_ACCESS_MAX];
	size_t plen;
	uint32_t val;
	int r;

	if (argc == argi) {			/* Get */
		r = mesh_mgr_cfg_u8_state_get_pdu(nd->mgr, get_op, pdu, &plen);
	} else if (argc == argi + 1 && cfg_u32(argv[argi], 0xFF, &val) == 0) {
		r = mesh_mgr_cfg_u8_state_set_pdu(nd->mgr, set_op, (uint8_t)val,
		    pdu, &plen);
	} else {
		snprintf(reply, reply_max, "ERR usage: cfg %s <dst> [state]",
		    verb);
		return (-1);
	}
	if (r != 0) {
		snprintf(reply, reply_max, "ERR cfg %s build failed", verb);
		return (-1);
	}
	/* All four u8-state Status opcodes differ; use the matching Get+2. */
	if (meshd_cfg_client_send(nd, dst, pdu, plen, set_op + 1, now, NULL,
	    NULL, NULL) != 0) {
		snprintf(reply, reply_max, "ERR cfg %s send failed", verb);
		return (-1);
	}
	return (cfg_result(nd, verb, dst, reply, reply_max));
}

int
meshd_cfg_client_verb(struct meshd_node *nd, int argc, char **argv,
    uint64_t now, char *reply, size_t reply_max)
{
	uint8_t pdu[MESH_ACCESS_MAX];
	uint8_t key[16], label[16];
	size_t plen;
	struct mesh_cfg_model_id m;
	uint32_t dst, a, b, c, d, e;
	const char *v;
	int r;

	if (nd == NULL || argv == NULL || reply == NULL || reply_max == 0)
		return (-1);
	if (argc < 1) {
		snprintf(reply, reply_max, "ERR usage: cfg <verb> <dst> [args]");
		return (-1);
	}
	v = argv[0];
	if (!nd->mgr_active || nd->mgr == NULL) {
		snprintf(reply, reply_max, "ERR no network (create-network first)");
		return (-1);
	}
	/* Every config verb targets a destination node address in argv[1]. */
	if (argc < 2 || cfg_u32(argv[1], 0xFFFF, &dst) != 0) {
		snprintf(reply, reply_max, "ERR usage: cfg %s <dst> [args]", v);
		return (-1);
	}
	if (mesh_mgr_find_by_addr(nd->mgr, (uint16_t)dst) == NULL) {
		snprintf(reply, reply_max, "ERR no such node 0x%04x",
		    (uint16_t)dst);
		return (-1);
	}

	/* ---- Composition Data ---- */
	if (strcmp(v, "comp-get") == 0) {
		a = 0;
		if (argc == 3 && cfg_u32(argv[2], 0xFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_comp_get_pdu(nd->mgr, (uint8_t)a, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_COMP_DATA_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- AppKey management ---- */
	if (strcmp(v, "appkey-add") == 0 || strcmp(v, "appkey-update") == 0 ||
	    strcmp(v, "appkey-delete") == 0) {
		if (argc != 2)
			goto usage;
		if (v[7] == 'a')
			r = mesh_mgr_cfg_appkey_add_pdu(nd->mgr, pdu, &plen);
		else if (v[7] == 'u')
			r = mesh_mgr_cfg_appkey_update_pdu(nd->mgr, pdu, &plen);
		else
			r = mesh_mgr_cfg_appkey_delete_pdu(nd->mgr, pdu, &plen);
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_APPKEY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "appkey-get") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0x0FFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_appkey_get_pdu(nd->mgr, (uint16_t)a, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_APPKEY_LIST, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Model AppKey binding ---- */
	if (strcmp(v, "model-bind") == 0 || strcmp(v, "model-unbind") == 0) {
		if (argc < 4 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_model_tail(argc, argv, 3, &m) != 0)
			goto usage;
		if (v[6] == 'b')
			r = mesh_mgr_cfg_model_app_bind_pdu(nd->mgr, (uint16_t)a,
			    &m, pdu, &plen);
		else
			r = mesh_mgr_cfg_model_app_unbind_pdu(nd->mgr, (uint16_t)a,
			    &m, pdu, &plen);
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_APP_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "model-app-get") == 0) {
		if (argc < 4 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_model_tail(argc, argv, 3, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_app_get_pdu(nd->mgr, (uint16_t)a, &m, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    m.vendor ? 0x804Eu : 0x804Cu, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Model subscription ---- */
	if (strcmp(v, "sub-add") == 0 || strcmp(v, "sub-delete") == 0 ||
	    strcmp(v, "sub-overwrite") == 0) {
		if (argc < 5 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFFFF, &b) != 0 ||
		    cfg_model_tail(argc, argv, 4, &m) != 0)
			goto usage;
		if (strcmp(v, "sub-add") == 0)
			r = mesh_mgr_cfg_model_sub_add_pdu(nd->mgr, (uint16_t)a,
			    (uint16_t)b, &m, pdu, &plen);
		else if (strcmp(v, "sub-delete") == 0)
			r = mesh_mgr_cfg_model_sub_delete_pdu(nd->mgr, (uint16_t)a,
			    (uint16_t)b, &m, pdu, &plen);
		else
			r = mesh_mgr_cfg_model_sub_overwrite_pdu(nd->mgr,
			    (uint16_t)a, (uint16_t)b, &m, pdu, &plen);
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_SUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sub-delete-all") == 0) {
		if (argc < 4 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_model_tail(argc, argv, 3, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_sub_delete_all_pdu(nd->mgr, (uint16_t)a,
		    &m, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_SUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sub-va-add") == 0 || strcmp(v, "sub-va-delete") == 0 ||
	    strcmp(v, "sub-va-overwrite") == 0) {
		if (argc < 5 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    meshd_hexdecode(argv[3], label, sizeof(label)) != 0 ||
		    cfg_model_tail(argc, argv, 4, &m) != 0)
			goto usage;
		if (strcmp(v, "sub-va-add") == 0)
			r = mesh_mgr_cfg_model_sub_va_add_pdu(nd->mgr, (uint16_t)a,
			    label, &m, pdu, &plen);
		else if (strcmp(v, "sub-va-delete") == 0)
			r = mesh_mgr_cfg_model_sub_va_delete_pdu(nd->mgr,
			    (uint16_t)a, label, &m, pdu, &plen);
		else
			r = mesh_mgr_cfg_model_sub_va_overwrite_pdu(nd->mgr,
			    (uint16_t)a, label, &m, pdu, &plen);
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_SUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sub-get") == 0) {
		if (argc < 4 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_model_tail(argc, argv, 3, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_sub_get_pdu(nd->mgr, (uint16_t)a, &m, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    m.vendor ? 0x802Cu : 0x802Au, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Model publication ---- */
	if (strcmp(v, "pub-set") == 0) {
		if (argc < 8 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFFFF, &b) != 0 ||
		    cfg_u32(argv[4], 0x7F, &c) != 0 ||
		    cfg_u32(argv[5], 0xFF, &d) != 0 ||
		    cfg_u32(argv[6], 0xFF, &e) != 0 ||
		    cfg_model_tail(argc, argv, 7, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_pub_set_pdu(nd->mgr, (uint16_t)a,
		    (uint16_t)b, (uint8_t)c, (uint8_t)d, (uint8_t)e, &m, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_PUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "pub-va-set") == 0) {
		if (argc < 8 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    meshd_hexdecode(argv[3], label, sizeof(label)) != 0 ||
		    cfg_u32(argv[4], 0x7F, &c) != 0 ||
		    cfg_u32(argv[5], 0xFF, &d) != 0 ||
		    cfg_u32(argv[6], 0xFF, &e) != 0 ||
		    cfg_model_tail(argc, argv, 7, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_pub_va_set_pdu(nd->mgr, (uint16_t)a, label,
		    (uint8_t)c, (uint8_t)d, (uint8_t)e, &m, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_PUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "pub-get") == 0) {
		if (argc < 4 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_model_tail(argc, argv, 3, &m) != 0)
			goto usage;
		if (mesh_mgr_cfg_model_pub_get_pdu(nd->mgr, (uint16_t)a, &m, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_MODEL_PUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- NetKey management ---- */
	if (strcmp(v, "netkey-add") == 0 || strcmp(v, "netkey-update") == 0) {
		if (argc != 4 || cfg_u32(argv[2], 0x0FFF, &a) != 0 ||
		    meshd_hexdecode(argv[3], key, sizeof(key)) != 0)
			goto usage;
		if (v[7] == 'a')
			r = mesh_mgr_cfg_netkey_add_pdu(nd->mgr, (uint16_t)a, key,
			    pdu, &plen);
		else
			r = mesh_mgr_cfg_netkey_update_pdu(nd->mgr, (uint16_t)a,
			    key, pdu, &plen);
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NETKEY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "netkey-delete") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0x0FFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_netkey_delete_pdu(nd->mgr, (uint16_t)a, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NETKEY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Key Refresh phase ---- */
	if (strcmp(v, "kr-phase-get") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0x0FFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_kr_phase_get_pdu(nd->mgr, (uint16_t)a, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_KEY_REFRESH_PHASE_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "kr-phase-set") == 0) {
		if (argc != 4 || cfg_u32(argv[2], 0x0FFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFF, &b) != 0)
			goto usage;
		if (mesh_mgr_cfg_kr_phase_set_pdu(nd->mgr, (uint16_t)a,
		    (uint8_t)b, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_KEY_REFRESH_PHASE_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Node-wide u8 states: beacon / gatt-proxy / friend / ttl ---- */
	if (strcmp(v, "beacon") == 0)
		return (cfg_u8_state(nd, v, (uint16_t)dst, argc, argv, 2,
		    MESH_CFG_OP_BEACON_GET, MESH_CFG_OP_BEACON_SET, now, reply,
		    reply_max));
	if (strcmp(v, "gatt-proxy") == 0)
		return (cfg_u8_state(nd, v, (uint16_t)dst, argc, argv, 2,
		    MESH_CFG_OP_GATT_PROXY_GET, MESH_CFG_OP_GATT_PROXY_SET, now,
		    reply, reply_max));
	if (strcmp(v, "friend") == 0)
		return (cfg_u8_state(nd, v, (uint16_t)dst, argc, argv, 2,
		    MESH_CFG_OP_FRIEND_GET, MESH_CFG_OP_FRIEND_SET, now, reply,
		    reply_max));
	if (strcmp(v, "ttl") == 0)
		return (cfg_u8_state(nd, v, (uint16_t)dst, argc, argv, 2,
		    MESH_CFG_OP_DEFAULT_TTL_GET, MESH_CFG_OP_DEFAULT_TTL_SET, now,
		    reply, reply_max));

	/* ---- Relay ---- */
	if (strcmp(v, "relay") == 0) {
		if (argc == 2)
			r = mesh_mgr_cfg_relay_get_pdu(nd->mgr, pdu, &plen);
		else if (argc == 4 && cfg_u32(argv[2], 0xFF, &a) == 0 &&
		    cfg_u32(argv[3], 0xFF, &b) == 0)
			r = mesh_mgr_cfg_relay_set_pdu(nd->mgr, (uint8_t)a,
			    (uint8_t)b, pdu, &plen);
		else
			goto usage;
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_RELAY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Network Transmit ---- */
	if (strcmp(v, "nettransmit") == 0) {
		if (argc == 2)
			r = mesh_mgr_cfg_net_transmit_get_pdu(nd->mgr, pdu, &plen);
		else if (argc == 4 && cfg_u32(argv[2], 0x07, &a) == 0 &&
		    cfg_u32(argv[3], 0x1F, &b) == 0)
			r = mesh_mgr_cfg_net_transmit_set_pdu(nd->mgr, (uint8_t)a,
			    (uint8_t)b, pdu, &plen);
		else
			goto usage;
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NET_TRANSMIT_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Node Identity ---- */
	if (strcmp(v, "node-identity-get") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0x0FFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_node_identity_get_pdu(nd->mgr, (uint16_t)a, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NODE_IDENTITY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "node-identity-set") == 0) {
		if (argc != 4 || cfg_u32(argv[2], 0x0FFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFF, &b) != 0)
			goto usage;
		if (mesh_mgr_cfg_node_identity_set_pdu(nd->mgr, (uint16_t)a,
		    (uint8_t)b, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NODE_IDENTITY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- LPN PollTimeout ---- */
	if (strcmp(v, "lpn-polltimeout-get") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0xFFFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_lpn_polltimeout_get_pdu(nd->mgr, (uint16_t)a,
		    pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_LPN_POLLTIMEOUT_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Heartbeat publication / subscription ---- */
	if (strcmp(v, "hb-pub-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_hb_pub_get_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_HB_PUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "hb-pub-set") == 0) {
		struct mesh_hb_pub hp;

		if (argc != 7 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFF, &b) != 0 ||
		    cfg_u32(argv[4], 0xFF, &c) != 0 ||
		    cfg_u32(argv[5], 0x7F, &d) != 0 ||
		    cfg_u32(argv[6], 0x0FFF, &e) != 0)
			goto usage;
		memset(&hp, 0, sizeof(hp));
		hp.dst = (uint16_t)a;
		hp.count_log = (uint8_t)b;
		hp.period_log = (uint8_t)c;
		hp.ttl = (uint8_t)d;
		hp.net_idx = (uint16_t)e;
		if (mesh_mgr_cfg_hb_pub_set_pdu(nd->mgr, &hp, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_HB_PUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "hb-sub-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_hb_sub_get_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_HB_SUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "hb-sub-set") == 0) {
		if (argc != 5 || cfg_u32(argv[2], 0xFFFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFFFF, &b) != 0 ||
		    cfg_u32(argv[4], 0xFF, &c) != 0)
			goto usage;
		if (mesh_mgr_cfg_hb_sub_set_pdu(nd->mgr, (uint16_t)a, (uint16_t)b,
		    (uint8_t)c, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_HB_SUB_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	/* ---- Node Reset ---- */
	if (strcmp(v, "node-reset") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_node_reset_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_NODE_RESET_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	snprintf(reply, reply_max, "ERR unknown cfg verb: %s", v);
	return (-1);

usage:
	snprintf(reply, reply_max, "ERR bad usage/argument: cfg %s", v);
	return (-1);
build_err:
	snprintf(reply, reply_max, "ERR cfg %s build failed", v);
	return (-1);
send_err:
	snprintf(reply, reply_max, "ERR cfg %s send failed", v);
	return (-1);
}
