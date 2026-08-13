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
	    expect_status_opcode, now, MESHD_CFG_RETRY_MS,
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

	/* ---- Mesh 1.1 node states: SAR / Private beacons & proxy / LCD ---- */
	if (strcmp(v, "sar-tx-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_sar_tx_get_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_SAR_TRANSMITTER_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sar-tx-set") == 0) {
		struct mesh_cfg_sar_transmitter tx;
		uint32_t f[7];
		int i;

		if (argc != 9)
			goto usage;
		for (i = 0; i < 7; i++)
			if (cfg_u32(argv[2 + i], 0x0F, &f[i]) != 0)
				goto usage;
		memset(&tx, 0, sizeof(tx));
		tx.seg_interval_step = (uint8_t)f[0];
		tx.unicast_retrans_count = (uint8_t)f[1];
		tx.unicast_retrans_without_progress_count = (uint8_t)f[2];
		tx.unicast_retrans_interval_step = (uint8_t)f[3];
		tx.unicast_retrans_interval_increment = (uint8_t)f[4];
		tx.multicast_retrans_count = (uint8_t)f[5];
		tx.multicast_retrans_interval_step = (uint8_t)f[6];
		if (mesh_mgr_cfg_sar_tx_set_pdu(nd->mgr, &tx, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_SAR_TRANSMITTER_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sar-rx-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_sar_rx_get_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_SAR_RECEIVER_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "sar-rx-set") == 0) {
		struct mesh_cfg_sar_receiver rx;

		if (argc != 7 || cfg_u32(argv[2], 0x1F, &a) != 0 ||
		    cfg_u32(argv[3], 0x07, &b) != 0 ||
		    cfg_u32(argv[4], 0x0F, &c) != 0 ||
		    cfg_u32(argv[5], 0x0F, &d) != 0 ||
		    cfg_u32(argv[6], 0x03, &e) != 0)
			goto usage;
		memset(&rx, 0, sizeof(rx));
		rx.segments_threshold = (uint8_t)a;
		rx.ack_delay_increment = (uint8_t)b;
		rx.discard_timeout = (uint8_t)c;
		rx.rx_segment_interval_step = (uint8_t)d;
		rx.ack_retrans_count = (uint8_t)e;
		if (mesh_mgr_cfg_sar_rx_set_pdu(nd->mgr, &rx, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_SAR_RECEIVER_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "priv-beacon-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_mgr_cfg_priv_beacon_get_pdu(nd->mgr, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PRIV_BEACON_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "priv-beacon-set") == 0) {
		struct mesh_cfg_priv_beacon pb;

		if (argc < 3 || argc > 4 || cfg_u32(argv[2], 0x01, &a) != 0)
			goto usage;
		memset(&pb, 0, sizeof(pb));
		pb.private_beacon = (uint8_t)a;
		if (argc == 4) {
			if (cfg_u32(argv[3], 0xFF, &b) != 0)
				goto usage;
			pb.random_update_interval_steps = (uint8_t)b;
			pb.has_random_update = 1;
		}
		if (mesh_mgr_cfg_priv_beacon_set_pdu(nd->mgr, &pb, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PRIV_BEACON_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "priv-gatt-proxy") == 0) {
		if (argc == 2)
			r = mesh_mgr_cfg_priv_gatt_proxy_get_pdu(nd->mgr, pdu, &plen);
		else if (argc == 3 && cfg_u32(argv[2], 0xFF, &a) == 0)
			r = mesh_mgr_cfg_priv_gatt_proxy_set_pdu(nd->mgr,
			    (uint8_t)a, pdu, &plen);
		else
			goto usage;
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PRIV_GATT_PROXY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "od-priv-proxy") == 0) {
		if (argc == 2)
			r = mesh_mgr_cfg_od_priv_proxy_get_pdu(nd->mgr, pdu, &plen);
		else if (argc == 3 && cfg_u32(argv[2], 0xFF, &a) == 0)
			r = mesh_mgr_cfg_od_priv_proxy_set_pdu(nd->mgr,
			    (uint8_t)a, pdu, &plen);
		else
			goto usage;
		if (r != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_OD_PRIV_PROXY_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "priv-node-identity-get") == 0) {
		if (argc != 3 || cfg_u32(argv[2], 0x0FFF, &a) != 0)
			goto usage;
		if (mesh_mgr_cfg_priv_node_identity_get_pdu(nd->mgr, (uint16_t)a,
		    pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PRIV_NODE_IDENTITY_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "priv-node-identity-set") == 0) {
		if (argc != 4 || cfg_u32(argv[2], 0x0FFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFF, &b) != 0)
			goto usage;
		if (mesh_mgr_cfg_priv_node_identity_set_pdu(nd->mgr, (uint16_t)a,
		    (uint8_t)b, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PRIV_NODE_IDENTITY_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (cfg_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "lcd-get") == 0) {
		if (argc != 4 || cfg_u32(argv[2], 0xFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFFFF, &b) != 0)
			goto usage;
		if (mesh_mgr_cfg_lcd_get_pdu(nd->mgr, (uint8_t)a, (uint16_t)b,
		    pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_LARGE_COMP_DATA_STATUS, now, NULL, NULL, NULL) != 0)
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

/* ================================================================
 * Directed Forwarding Configuration Client (finding 129).
 *
 * The Set/Get verbs build a Directed-Forwarding Configuration message and drive
 * it over the same DevKey transaction engine as "cfg"; "discover" arms the local
 * Path Origin discovery FSM (no roster node required).
 * ================================================================ */

/* Surface a DF Config Status; decode the codec that matches the reply opcode. */
static int
df_result(struct meshd_node *nd, const char *verb, uint16_t dst, char *reply,
    size_t reply_max)
{
	const uint8_t *st;
	size_t stlen;
	int state;
	uint8_t status;
	struct mesh_cfg_directed_control dc;
	struct mesh_cfg_path_metric pm;
	struct mesh_cfg_wanted_lanes wl;
	struct mesh_cfg_two_way_path tw;
	struct mesh_cfg_path_echo_interval pe;
	struct mesh_cfg_transmit tx;
	uint32_t txop;

	state = meshd_cfg_client_status(nd, &st, &stlen);
	if (state != MESH_MGR_TXN_COMPLETE || st == NULL) {
		snprintf(reply, reply_max, "OK df %s dst=0x%04x sent state=%d",
		    verb, dst, state);
		return (0);
	}
	if (mesh_cfg_directed_control_status_parse(st, stlen, &status, &dc) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x status=0x%02x netidx=%u fwd=%u relay=%u "
		    "proxy=%u friend=%u", verb, dst, status, dc.net_idx,
		    dc.directed_forwarding, dc.directed_relay, dc.directed_proxy,
		    dc.directed_friend);
		return (0);
	}
	if (mesh_cfg_path_metric_status_parse(st, stlen, &status, &pm) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x status=0x%02x netidx=%u type=%u life=%u",
		    verb, dst, status, pm.net_idx, pm.metric_type, pm.lifetime);
		return (0);
	}
	if (mesh_cfg_wanted_lanes_status_parse(st, stlen, &status, &wl) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x status=0x%02x netidx=%u lanes=%u", verb,
		    dst, status, wl.net_idx, wl.wanted_lanes);
		return (0);
	}
	if (mesh_cfg_two_way_path_status_parse(st, stlen, &status, &tw) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x status=0x%02x netidx=%u two-way=%u",
		    verb, dst, status, tw.net_idx, tw.two_way_path);
		return (0);
	}
	if (mesh_cfg_path_echo_interval_status_parse(st, stlen, &status,
	    &pe) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x status=0x%02x netidx=%u uni=%u multi=%u",
		    verb, dst, status, pe.net_idx, pe.unicast_echo_interval,
		    pe.multicast_echo_interval);
		return (0);
	}
	if (mesh_cfg_directed_transmit_parse(st, stlen, &txop, &tx) == 0) {
		snprintf(reply, reply_max,
		    "OK df %s dst=0x%04x count=%u steps=%u", verb, dst, tx.count,
		    tx.interval_steps);
		return (0);
	}
	snprintf(reply, reply_max,
	    "OK df %s dst=0x%04x status received (%zu octets)", verb, dst, stlen);
	return (0);
}

int
meshd_df_client_verb(struct meshd_node *nd, int argc, char **argv, uint64_t now,
    char *reply, size_t reply_max)
{
	uint8_t pdu[MESH_ACCESS_MAX];
	size_t plen;
	uint32_t dst, netidx, a, b, c, d, e;
	const char *v;

	if (nd == NULL || argv == NULL || reply == NULL || reply_max == 0)
		return (-1);
	if (argc < 1) {
		snprintf(reply, reply_max, "ERR usage: df <verb> <dst> [args]");
		return (-1);
	}
	v = argv[0];

	/* Local Path Origin discovery: no roster node required. */
	if (strcmp(v, "discover") == 0) {
		if (argc != 2 || cfg_u32(argv[1], 0xFFFF, &a) != 0)
			goto usage;
		if (meshd_df_discover_begin(nd, (uint16_t)a, now) != 0) {
			snprintf(reply, reply_max, "ERR df discover failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK df discover target=0x%04x state=%d", (uint16_t)a,
		    nd->self->df_disc.state);
		return (0);
	}
	if (strcmp(v, "discover-status") == 0) {
		snprintf(reply, reply_max,
		    "OK df discover-status enabled=%d state=%d origin=0x%04x "
		    "target=0x%04x", nd->self != NULL && nd->self->df_enabled,
		    nd->self != NULL ? nd->self->df_disc.state : 0,
		    nd->self != NULL ? nd->self->df_disc.origin : 0,
		    nd->self != NULL ? nd->self->df_disc.target : 0);
		return (0);
	}

	if (!nd->mgr_active || nd->mgr == NULL) {
		snprintf(reply, reply_max, "ERR no network (create-network first)");
		return (-1);
	}
	if (argc < 2 || cfg_u32(argv[1], 0xFFFF, &dst) != 0)
		goto usage;
	if (mesh_mgr_find_by_addr(nd->mgr, (uint16_t)dst) == NULL) {
		snprintf(reply, reply_max, "ERR no such node 0x%04x",
		    (uint16_t)dst);
		return (-1);
	}
	netidx = nd->netkey_index;

	if (strcmp(v, "get") == 0) {
		if (argc == 3 && cfg_u32(argv[2], 0x0FFF, &netidx) != 0)
			goto usage;
		else if (argc != 2 && argc != 3)
			goto usage;
		if (mesh_cfg_directed_control_get_build((uint16_t)netidx, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "set") == 0) {
		struct mesh_cfg_directed_control ctl;
		int on;

		if (argc < 3 || argc > 4)
			goto usage;
		if (strcmp(argv[2], "on") == 0)
			on = 1;
		else if (strcmp(argv[2], "off") == 0)
			on = 0;
		else
			goto usage;
		if (argc == 4 && cfg_u32(argv[3], 0x0FFF, &netidx) != 0)
			goto usage;
		memset(&ctl, 0, sizeof(ctl));
		ctl.net_idx = (uint16_t)netidx;
		ctl.directed_forwarding = (uint8_t)on;
		ctl.directed_relay = (uint8_t)on;
		if (mesh_cfg_directed_control_set_build(&ctl, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "control-set") == 0) {
		struct mesh_cfg_directed_control ctl;

		if (argc != 8 || cfg_u32(argv[2], 0x0FFF, &netidx) != 0 ||
		    cfg_u32(argv[3], 1, &a) != 0 || cfg_u32(argv[4], 1, &b) != 0 ||
		    cfg_u32(argv[5], 1, &c) != 0 || cfg_u32(argv[6], 1, &d) != 0 ||
		    cfg_u32(argv[7], 1, &e) != 0)
			goto usage;
		memset(&ctl, 0, sizeof(ctl));
		ctl.net_idx = (uint16_t)netidx;
		ctl.directed_forwarding = (uint8_t)a;
		ctl.directed_relay = (uint8_t)b;
		ctl.directed_proxy = (uint8_t)c;
		ctl.directed_proxy_use_directed_default = (uint8_t)d;
		ctl.directed_friend = (uint8_t)e;
		if (mesh_cfg_directed_control_set_build(&ctl, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "metric-get") == 0) {
		if (argc == 3 && cfg_u32(argv[2], 0x0FFF, &netidx) != 0)
			goto usage;
		else if (argc != 2 && argc != 3)
			goto usage;
		if (mesh_cfg_path_metric_get_build((uint16_t)netidx, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PATH_METRIC_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "metric-set") == 0) {
		struct mesh_cfg_path_metric pm;

		if (argc < 4 || argc > 5 || cfg_u32(argv[2], 0x07, &a) != 0 ||
		    cfg_u32(argv[3], 0x03, &b) != 0 ||
		    (argc == 5 && cfg_u32(argv[4], 0x0FFF, &netidx) != 0))
			goto usage;
		memset(&pm, 0, sizeof(pm));
		pm.net_idx = (uint16_t)netidx;
		pm.metric_type = (uint8_t)a;
		pm.lifetime = (uint8_t)b;
		if (mesh_cfg_path_metric_set_build(&pm, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PATH_METRIC_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "lanes-get") == 0) {
		if (argc == 3 && cfg_u32(argv[2], 0x0FFF, &netidx) != 0)
			goto usage;
		else if (argc != 2 && argc != 3)
			goto usage;
		if (mesh_cfg_wanted_lanes_get_build((uint16_t)netidx, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_WANTED_LANES_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "lanes-set") == 0) {
		struct mesh_cfg_wanted_lanes wl;

		if (argc < 3 || argc > 4 || cfg_u32(argv[2], 0xFF, &a) != 0 ||
		    (argc == 4 && cfg_u32(argv[3], 0x0FFF, &netidx) != 0))
			goto usage;
		memset(&wl, 0, sizeof(wl));
		wl.net_idx = (uint16_t)netidx;
		wl.wanted_lanes = (uint8_t)a;
		if (mesh_cfg_wanted_lanes_set_build(&wl, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_WANTED_LANES_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "two-way-get") == 0) {
		if (argc == 3 && cfg_u32(argv[2], 0x0FFF, &netidx) != 0)
			goto usage;
		else if (argc != 2 && argc != 3)
			goto usage;
		if (mesh_cfg_two_way_path_get_build((uint16_t)netidx, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_TWO_WAY_PATH_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "two-way-set") == 0) {
		struct mesh_cfg_two_way_path tw;

		if (argc < 3 || argc > 4 || cfg_u32(argv[2], 1, &a) != 0 ||
		    (argc == 4 && cfg_u32(argv[3], 0x0FFF, &netidx) != 0))
			goto usage;
		memset(&tw, 0, sizeof(tw));
		tw.net_idx = (uint16_t)netidx;
		tw.two_way_path = (uint8_t)a;
		if (mesh_cfg_two_way_path_set_build(&tw, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_TWO_WAY_PATH_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "echo-get") == 0) {
		if (argc == 3 && cfg_u32(argv[2], 0x0FFF, &netidx) != 0)
			goto usage;
		else if (argc != 2 && argc != 3)
			goto usage;
		if (mesh_cfg_path_echo_interval_get_build((uint16_t)netidx, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "echo-set") == 0) {
		struct mesh_cfg_path_echo_interval pe;

		if (argc < 4 || argc > 5 || cfg_u32(argv[2], 0xFF, &a) != 0 ||
		    cfg_u32(argv[3], 0xFF, &b) != 0 ||
		    (argc == 5 && cfg_u32(argv[4], 0x0FFF, &netidx) != 0))
			goto usage;
		memset(&pe, 0, sizeof(pe));
		pe.net_idx = (uint16_t)netidx;
		pe.unicast_echo_interval = (uint8_t)a;
		pe.multicast_echo_interval = (uint8_t)b;
		if (mesh_cfg_path_echo_interval_set_build(&pe, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "net-transmit-get") == 0 ||
	    strcmp(v, "relay-retransmit-get") == 0) {
		uint32_t getop, statop;

		if (argc != 2)
			goto usage;
		if (v[0] == 'n') {
			getop = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET;
			statop = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS;
		} else {
			getop = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_GET;
			statop = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS;
		}
		if (mesh_cfg_directed_transmit_get_build(getop, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen, statop,
		    now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "net-transmit-set") == 0 ||
	    strcmp(v, "relay-retransmit-set") == 0) {
		struct mesh_cfg_transmit tx;
		uint32_t setop, statop;

		if (argc != 4 || cfg_u32(argv[2], 0x07, &a) != 0 ||
		    cfg_u32(argv[3], 0x1F, &b) != 0)
			goto usage;
		if (v[0] == 'n') {
			setop = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET;
			statop = MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS;
		} else {
			setop = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET;
			statop = MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS;
		}
		memset(&tx, 0, sizeof(tx));
		tx.count = (uint8_t)a;
		tx.interval_steps = (uint8_t)b;
		if (mesh_cfg_directed_transmit_build(setop, &tx, pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen, statop,
		    now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (df_result(nd, v, (uint16_t)dst, reply, reply_max));
	}

	snprintf(reply, reply_max, "ERR unknown df verb: %s", v);
	return (-1);
usage:
	snprintf(reply, reply_max, "ERR bad usage/argument: df %s", v);
	return (-1);
build_err:
	snprintf(reply, reply_max, "ERR df %s build failed", v);
	return (-1);
send_err:
	snprintf(reply, reply_max, "ERR df %s send failed", v);
	return (-1);
}

/* ================================================================
 * Remote Provisioning Client (finding 128).
 *
 * The RPR models operate under the target node's DevKey, so the client verbs
 * drive the same transaction engine as "cfg"; the scan/link client FSMs record
 * the correlated Status/Report.
 * ================================================================ */

/* Surface an RPR Status/Report; drive the matching client FSM where useful. */
static int
rpr_result(struct meshd_node *nd, const char *verb, uint16_t dst, char *reply,
    size_t reply_max)
{
	const uint8_t *st;
	size_t stlen;
	int state;
	struct mesh_rp_scan_status ss;
	struct mesh_rp_scan_caps sc;
	struct mesh_rp_link_status ls;
	struct mesh_rp_link_report lr;

	state = meshd_cfg_client_status(nd, &st, &stlen);
	if (state != MESH_MGR_TXN_COMPLETE || st == NULL) {
		snprintf(reply, reply_max,
		    "OK remote-prov %s dst=0x%04x sent state=%d", verb, dst,
		    state);
		return (0);
	}
	if (mesh_rp_scan_status_parse(st, stlen, &ss) == 0) {
		snprintf(reply, reply_max,
		    "OK remote-prov %s dst=0x%04x status=0x%02x scan-state=%u "
		    "limit=%u timeout=%u", verb, dst, ss.status,
		    ss.scanning_state, ss.scanned_items_limit, ss.timeout);
		return (0);
	}
	if (mesh_rp_scan_caps_status_parse(st, stlen, &sc) == 0) {
		snprintf(reply, reply_max,
		    "OK remote-prov %s dst=0x%04x max-items=%u active=%u", verb,
		    dst, sc.max_scanned_items, sc.active_scan);
		return (0);
	}
	if (mesh_rp_link_status_parse(st, stlen, &ls) == 0) {
		(void)mesh_rp_client_link_on_status(&nd->rpr.client_link, &ls);
		snprintf(reply, reply_max,
		    "OK remote-prov %s dst=0x%04x status=0x%02x link-state=%u",
		    verb, dst, ls.status, ls.rp_state);
		return (0);
	}
	if (mesh_rp_link_report_parse(st, stlen, &lr) == 0) {
		(void)mesh_rp_client_link_on_report(&nd->rpr.client_link, &lr);
		nd->rpr.client_active =
		    mesh_rp_client_link_is_active(&nd->rpr.client_link);
		snprintf(reply, reply_max,
		    "OK remote-prov %s dst=0x%04x status=0x%02x link-state=%u",
		    verb, dst, lr.status, lr.rp_state);
		return (0);
	}
	snprintf(reply, reply_max,
	    "OK remote-prov %s dst=0x%04x status received (%zu octets)", verb,
	    dst, stlen);
	return (0);
}

int
meshd_rpr_client_verb(struct meshd_node *nd, int argc, char **argv,
    uint64_t now, char *reply, size_t reply_max)
{
	uint8_t pdu[MESH_RP_MSG_MAX];
	uint8_t uuid[16];
	size_t plen;
	uint32_t dst, a, b;
	const char *v;

	if (nd == NULL || argv == NULL || reply == NULL || reply_max == 0)
		return (-1);
	if (argc < 1) {
		snprintf(reply, reply_max,
		    "ERR usage: remote-prov <verb> <dst> [args]");
		return (-1);
	}
	v = argv[0];

	/* Local client-FSM status: no roster node required. */
	if (strcmp(v, "status") == 0) {
		snprintf(reply, reply_max,
		    "OK remote-prov status server=0x%04x active=%d "
		    "link-active=%d scanning=%d found=%zu reports=%zu",
		    nd->rpr.server_addr, nd->rpr.client_active,
		    mesh_rp_client_link_is_active(&nd->rpr.client_link),
		    nd->rpr.scan_client.scanning, nd->rpr.scan_client.nfound,
		    nd->rpr.n_reports);
		return (0);
	}
	/* List the buffered unsolicited Reports received from a Server. */
	if (strcmp(v, "reports") == 0) {
		size_t i, shown, off, first;

		shown = nd->rpr.n_reports < MESHD_RPR_MAX_REPORTS ?
		    nd->rpr.n_reports : MESHD_RPR_MAX_REPORTS;
		first = (nd->rpr.report_head + MESHD_RPR_MAX_REPORTS - shown) %
		    MESHD_RPR_MAX_REPORTS;
		off = (size_t)snprintf(reply, reply_max,
		    "OK remote-prov reports total=%zu shown=%zu",
		    nd->rpr.n_reports, shown);
		for (i = 0; i < shown && off < reply_max; i++) {
			const struct meshd_rpr_report *r =
			    &nd->rpr.reports[(first + i) % MESHD_RPR_MAX_REPORTS];
			int w;
			size_t k;

			w = snprintf(reply + off, reply_max - off,
			    " [op=0x%04x src=0x%04x ", r->opcode, r->src);
			if (w < 0 || (size_t)w >= reply_max - off)
				break;
			off += (size_t)w;
			for (k = 0; k < r->len && off + 2 < reply_max; k++) {
				w = snprintf(reply + off, reply_max - off,
				    "%02x", r->data[k]);
				if (w < 0 || (size_t)w >= reply_max - off)
					break;
				off += (size_t)w;
			}
			if (off < reply_max)
				reply[off++] = ']';
		}
		if (off < reply_max)
			reply[off] = '\0';
		else if (reply_max > 0)
			reply[reply_max - 1] = '\0';
		return (0);
	}

	if (!nd->mgr_active || nd->mgr == NULL) {
		snprintf(reply, reply_max, "ERR no network (create-network first)");
		return (-1);
	}
	if (argc < 2 || cfg_u32(argv[1], 0xFFFF, &dst) != 0)
		goto usage;
	if (mesh_mgr_find_by_addr(nd->mgr, (uint16_t)dst) == NULL) {
		snprintf(reply, reply_max, "ERR no such node 0x%04x",
		    (uint16_t)dst);
		return (-1);
	}

	if (strcmp(v, "caps") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_rp_scan_caps_get_build(pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_SCAN_CAPABILITIES_STATUS, now, NULL, NULL,
		    NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "scan-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_rp_scan_get_build(pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_SCAN_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "scan") == 0) {
		const uint8_t *up = NULL;
		uint32_t limit = 0, timeout = 5;
		int ai = 2;

		/* Optional device UUID (32 hex) targets a single device. */
		if (argc > ai && strlen(argv[ai]) == 32) {
			if (meshd_hexdecode(argv[ai], uuid, sizeof(uuid)) != 0)
				goto usage;
			up = uuid;
			ai++;
		}
		if (argc > ai && cfg_u32(argv[ai], 0xFF, &limit) != 0)
			goto usage;
		else if (argc > ai)
			ai++;
		if (argc > ai && cfg_u32(argv[ai], 0xFF, &timeout) != 0)
			goto usage;
		else if (argc > ai)
			ai++;
		if (argc != ai)
			goto usage;
		if (timeout == 0)
			timeout = 5;
		if (mesh_rp_scan_client_start(&nd->rpr.scan_client,
		    (uint8_t)limit, (uint8_t)timeout, up, pdu, &plen) != 0)
			goto build_err;
		nd->rpr.server_addr = (uint16_t)dst;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_SCAN_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "scan-stop") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_rp_scan_client_stop(&nd->rpr.scan_client, pdu,
		    &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_SCAN_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "link-get") == 0) {
		if (argc != 2)
			goto usage;
		if (mesh_rp_link_get_build(pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_LINK_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "link-open") == 0 || strcmp(v, "provision") == 0) {
		uint32_t timeout = 10;

		if (argc < 3 || argc > 4 ||
		    meshd_hexdecode(argv[2], uuid, sizeof(uuid)) != 0 ||
		    (argc == 4 && cfg_u32(argv[3], 0xFF, &timeout) != 0))
			goto usage;
		if (timeout == 0)
			timeout = 10;
		if (mesh_rp_client_link_open(&nd->rpr.client_link, uuid,
		    (uint8_t)timeout, 30000, now, pdu, &plen) != 0)
			goto build_err;
		nd->rpr.server_addr = (uint16_t)dst;
		nd->rpr.client_active = 1;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_LINK_STATUS, now, NULL, NULL, NULL) != 0)
			goto send_err;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	if (strcmp(v, "link-close") == 0) {
		if (argc < 2 || argc > 3 ||
		    (argc == 3 && cfg_u32(argv[2], 0x02, &a) != 0))
			goto usage;
		if (argc != 3)
			a = MESH_RP_LINK_CLOSE_SUCCESS;
		if (mesh_rp_client_link_close(&nd->rpr.client_link, (uint8_t)a,
		    pdu, &plen) != 0)
			goto build_err;
		if (meshd_cfg_client_send(nd, (uint16_t)dst, pdu, plen,
		    MESH_RP_OP_LINK_REPORT, now, NULL, NULL, NULL) != 0)
			goto send_err;
		nd->rpr.client_active = 0;
		return (rpr_result(nd, v, (uint16_t)dst, reply, reply_max));
	}
	(void)a; (void)b;

	snprintf(reply, reply_max, "ERR unknown remote-prov verb: %s", v);
	return (-1);
usage:
	snprintf(reply, reply_max, "ERR bad usage/argument: remote-prov %s", v);
	return (-1);
build_err:
	snprintf(reply, reply_max, "ERR remote-prov %s build failed", v);
	return (-1);
send_err:
	snprintf(reply, reply_max, "ERR remote-prov %s send failed", v);
	return (-1);
}
