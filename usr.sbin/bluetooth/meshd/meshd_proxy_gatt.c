/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/* Mesh Proxy Service client receive path (Mesh Protocol v1.1, Section 6). */

#include <sys/types.h>

#include <string.h>

#include "meshd.h"

struct proxy_key_candidate {
	uint8_t nid;
	const uint8_t *enc;
	const uint8_t *priv;
};

static int
proxy_config_recv(struct meshd_node *nd, struct meshd_proxy_gatt *session,
    const uint8_t *pdu, size_t len)
{
	struct proxy_key_candidate keys[MESH_SIM_MAX_SUBNETS * 2 + 2];
	struct mesh_proxy_cfg cfg;
	uint8_t msg[16];
	uint32_t ivs[2], seq;
	uint16_t src;
	size_t i, k, msglen, nkeys, niv;

	nkeys = 0;
	if (mesh_kr_rx_accept_old(&nd->self->kr))
		keys[nkeys++] = (struct proxy_key_candidate){ nd->self->nid,
		    nd->self->enckey, nd->self->privkey };
	if (nd->self->have_new_key && mesh_kr_rx_accept_new(&nd->self->kr))
		keys[nkeys++] = (struct proxy_key_candidate){ nd->self->new_nid,
		    nd->self->new_enckey, nd->self->new_privkey };
	for (i = 0; i < nd->self->n_subnets; i++) {
		struct mesh_sim_subnet_key *subnet = &nd->self->subnets[i];

		if (!subnet->valid)
			continue;
		if (mesh_kr_rx_accept_old(&subnet->kr))
			keys[nkeys++] = (struct proxy_key_candidate){ subnet->nid,
			    subnet->enckey, subnet->privkey };
		if (subnet->have_new_key && mesh_kr_rx_accept_new(&subnet->kr))
			keys[nkeys++] = (struct proxy_key_candidate){ subnet->new_nid,
			    subnet->new_enckey, subnet->new_privkey };
	}
	ivs[0] = nd->self->iv.iv_index;
	niv = 1;
	if (ivs[0] > 0) {
		ivs[1] = ivs[0] - 1;
		niv = 2;
	}
	for (k = 0; k < nkeys; k++) {
		for (i = 0; i < niv; i++) {
			if (mesh_proxy_cfg_decrypt(keys[k].enc, keys[k].priv,
			    keys[k].nid, ivs[i], pdu, len, &seq, &src, msg,
			    sizeof(msg), &msglen) != 0)
				continue;
			if (mesh_proxy_cfg_parse(msg, msglen, &cfg) != 0 ||
			    cfg.opcode != MESH_PROXY_OP_FILTER_STATUS)
				return (-1);
			if (mesh_rpl_check(&nd->self->rpl, src, ivs[i], seq) != 1)
				return (-1);
			session->filter_type = cfg.filter_type;
			session->filter_size = cfg.list_size;
			session->have_filter_status = 1;
			return (1);
		}
	}
	return (-1);
}

static struct meshd_proxy_gatt *
proxy_session(struct meshd_node *nd, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{
	struct meshd_proxy_gatt *match;
	size_t i;

	if (nd == NULL || addr == NULL)
		return (NULL);
	/* A still-provisional default session is the caller's exact selection. */
	if (adapter_index == MESHD_ADAPTER_DEFAULT) {
		for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
			if (nd->proxy_gatt[i].active &&
			    nd->proxy_gatt[i].addr_type == addr_type &&
			    nd->proxy_gatt[i].adapter_index == MESHD_ADAPTER_DEFAULT &&
			    strcmp(nd->proxy_gatt[i].addr, addr) == 0)
				return (&nd->proxy_gatt[i]);
	}
	match = NULL;
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++) {
		if (!nd->proxy_gatt[i].active ||
		    nd->proxy_gatt[i].addr_type != addr_type ||
		    strcmp(nd->proxy_gatt[i].addr, addr) != 0 ||
		    (adapter_index != MESHD_ADAPTER_DEFAULT &&
		    nd->proxy_gatt[i].adapter_index != adapter_index))
			continue;
		/* The default selector names a link only when the tuple is unique. */
		if (match != NULL)
			return (NULL);
		match = &nd->proxy_gatt[i];
	}
	return (match);
}

int
meshd_proxy_gatt_begin(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu)
{
	struct meshd_proxy_gatt *session;
	size_t i;

	if (nd == NULL || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM || !nd->provisioned ||
	    mtu < MESHD_PBGATT_MIN_MTU || mtu > MESHD_GATT_MAX_MTU ||
	    proxy_session(nd, addr, addr_type, adapter_index) != NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (!nd->proxy_gatt[i].active)
			break;
	if (i == MESHD_MAX_PROXY_GATT)
		return (-1);
	session = &nd->proxy_gatt[i];
	memset(session, 0, sizeof(*session));
	mesh_proxy_reasm_init(&session->rx);
	strlcpy(session->addr, addr, sizeof(session->addr));
	session->addr_type = addr_type;
	session->adapter_index = adapter_index;
	session->mtu = mtu;
	session->active = 1;
	return (0);
}

int
meshd_proxy_gatt_recv_mtu(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu, size_t len,
    uint16_t bearer_mtu, uint64_t now_ms)
{
	struct meshd_proxy_gatt *session;
	uint8_t type, msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	int complete, rc;

	session = proxy_session(nd, addr, addr_type, adapter_index);
	if (session == NULL || pdu == NULL || len == 0 ||
	    bearer_mtu < MESHD_PBGATT_MIN_MTU ||
	    len > (size_t)bearer_mtu - 3)
		return (-1);
	rc = mesh_proxy_reasm_feed(&session->rx, pdu, len, &complete,
	    &type, msg, sizeof(msg), &msglen);
	if (rc == MESH_PROXY_REASM_ERROR) {
		session->rx_started = 0;
		return (-1);
	}
	if (rc == MESH_PROXY_REASM_IGNORED)
		return (0);
	if (!complete) {
		/*
		 * The 20s SAR reassembly timeout is measured per-segment
		 * (Section 6.3.2.2): refresh the start stamp on EVERY accepted
		 * segment, not only the first, so a slow-but-steady multi-segment
		 * transfer with sub-20s inter-segment gaps is not torn down at 20s
		 * from the first segment (C6-M10).
		 */
		session->rx_started_ms = now_ms;
		session->rx_started = 1;
		return (0);
	}
	session->rx_started = 0;
	switch (type) {
	case MESH_PROXY_TYPE_NETWORK:
		return (meshd_bearer_rx(nd, msg, msglen) < 0 ? 0 : 1);
	case MESH_PROXY_TYPE_BEACON:
		return (meshd_beacon_rx(nd, msg, msglen) < 0 ? 0 : 1);
	case MESH_PROXY_TYPE_CONFIG:
		return (proxy_config_recv(nd, session, msg, msglen) < 0 ? 0 : 1);
	default:
		return (0);
	}
}

int
meshd_proxy_gatt_recv(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu, size_t len,
    uint64_t now_ms)
{
	struct meshd_proxy_gatt *session;

	session = proxy_session(nd, addr, addr_type, adapter_index);
	if (session == NULL)
		return (-1);
	return (meshd_proxy_gatt_recv_mtu(nd, addr, addr_type, adapter_index,
	    pdu, len, session->mtu, now_ms));
}

int
meshd_proxy_gatt_set_mtu(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu)
{
	struct meshd_proxy_gatt *session;

	session = proxy_session(nd, addr, addr_type, adapter_index);
	if (session == NULL || mtu < MESHD_PBGATT_MIN_MTU ||
	    mtu > MESHD_GATT_MAX_MTU)
		return (-1);
	if (session->rx.in_progress)
		return (-1);
	session->mtu = mtu;
	return (0);
}

/*
 * Replace a provisional (normally MESHD_ADAPTER_DEFAULT) selector with the
 * controller that discovery actually selected.  Do all validation before the
 * assignment so callers can treat failure as leaving the session untouched.
 */
int
meshd_proxy_gatt_resolve_adapter(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t requested_adapter, uint8_t resolved_adapter)
{
	struct meshd_proxy_gatt *session, *conflict;

	if (resolved_adapter >= MESHD_ADAPTER_DEFAULT)
		return (-1);
	session = proxy_session(nd, addr, addr_type, requested_adapter);
	if (session == NULL)
		return (-1);
	if (requested_adapter == resolved_adapter)
		return (0);
	conflict = proxy_session(nd, addr, addr_type, resolved_adapter);
	if (conflict != NULL && conflict != session)
		return (-1);
	session->adapter_index = resolved_adapter;
	return (0);
}

void
meshd_proxy_gatt_cancel(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	size_t i;

	if (nd == NULL)
		return;
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++)
		if (nd->proxy_gatt[i].active && (addr == NULL ||
		    (nd->proxy_gatt[i].addr_type == addr_type &&
		    nd->proxy_gatt[i].adapter_index == adapter_index &&
		    strcmp(nd->proxy_gatt[i].addr, addr) == 0)))
			memset(&nd->proxy_gatt[i], 0,
			    sizeof(nd->proxy_gatt[i]));
}

void
meshd_proxy_gatt_close(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	struct meshd_proxy_gatt *session;

	session = proxy_session(nd, addr, addr_type, adapter_index);
	if (session == NULL)
		return;
	if (nd->bearer != NULL && nd->bearer->proxy_close != NULL)
		(void)nd->bearer->proxy_close(nd->bearer->arg, session->addr,
		    session->addr_type, session->adapter_index);
	memset(session, 0, sizeof(*session));
}

int
meshd_proxy_gatt_connect(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{

	if (nd == NULL || addr == NULL || nd->bearer == NULL ||
	    addr_type > MESHD_ADDR_RANDOM || nd->bearer->proxy_open == NULL ||
	    meshd_proxy_gatt_begin(nd, addr, addr_type, adapter_index,
	    MESHD_PBGATT_MIN_MTU) != 0)
		return (-1);
	if (nd->bearer->proxy_open(nd->bearer->arg, addr, addr_type,
	    adapter_index) != 0) {
		meshd_proxy_gatt_cancel(nd, addr, addr_type, adapter_index);
		return (-1);
	}
	return (0);
}

static int
proxy_config_tx(struct meshd_node *nd, const char *addr, uint8_t addr_type,
    uint8_t adapter_index, uint16_t net_idx, const uint8_t *msg, size_t msglen)
{
	struct mesh_sim_subnet_key *subnet = NULL;
	struct meshd_proxy_gatt *session;
	const uint8_t *enc, *priv;
	uint8_t nid, secured[MESH_PROXY_MAX_NETWORK_PDU];
	size_t i, secured_len;

	session = proxy_session(nd, addr, addr_type, adapter_index);
	if (session == NULL ||
	    nd->bearer == NULL ||
	    nd->bearer->proxy_tx == NULL)
		return (-1);
	if (net_idx == nd->self->primary_net_idx) {
		if (nd->self->have_new_key &&
		    mesh_kr_tx_key(&nd->self->kr) == MESH_KR_KEY_NEW) {
			nid = nd->self->new_nid;
			enc = nd->self->new_enckey;
			priv = nd->self->new_privkey;
		} else {
			nid = nd->self->nid;
			enc = nd->self->enckey;
			priv = nd->self->privkey;
		}
	} else {
		for (i = 0; i < nd->self->n_subnets; i++)
			if (nd->self->subnets[i].valid &&
			    nd->self->subnets[i].net_idx == net_idx)
				subnet = &nd->self->subnets[i];
		if (subnet == NULL)
			return (-1);
		if (subnet->have_new_key &&
		    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW) {
			nid = subnet->new_nid;
			enc = subnet->new_enckey;
			priv = subnet->new_privkey;
		} else {
			nid = subnet->nid;
			enc = subnet->enckey;
			priv = subnet->privkey;
		}
	}
	if (nd->self->seq > MESH_IV_SEQ_MAX)
		return (-1);
	if (mesh_proxy_cfg_encrypt(enc, priv, nid,
	    mesh_iv_tx_index(&nd->self->iv), nd->self->seq, nd->self->addr,
	    msg, msglen, secured, &secured_len) != 0)
		return (-1);
	nd->self->seq++;
	return (nd->bearer->proxy_tx(nd->bearer->arg, addr, addr_type,
	    session->adapter_index,
	    MESH_PROXY_TYPE_CONFIG, secured, secured_len));
}

int
meshd_proxy_gatt_set_filter(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t net_idx,
    uint8_t filter_type)
{
	uint8_t msg[2];
	size_t len;

	if (mesh_proxy_cfg_set_filter_build(filter_type, msg, sizeof(msg),
	    &len) != 0)
		return (-1);
	return (proxy_config_tx(nd, addr, addr_type, adapter_index, net_idx, msg,
	    len));
}

int
meshd_proxy_gatt_update_filter(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t net_idx, uint8_t opcode,
    const uint16_t *addrs, size_t n)
{
	uint8_t msg[1 + MESH_PROXY_MAX_ADDR_PER_MSG * 2];
	size_t len;

	if (mesh_proxy_cfg_addr_build(opcode, addrs, n, msg, sizeof(msg),
	    &len) != 0)
		return (-1);
	return (proxy_config_tx(nd, addr, addr_type, adapter_index, net_idx, msg,
	    len));
}

void
meshd_gatt_tick(struct meshd_node *nd, uint64_t now_ms)
{
	struct meshd_proxy_gatt *session;
	size_t i;

	if (nd == NULL)
		return;
	if (nd->pbgatt.active && nd->pbgatt.timeout_closing) {
		if (now_ms >= nd->pbgatt.timeout_started_ms &&
		    now_ms - nd->pbgatt.timeout_started_ms >=
		    MESHD_PBGATT_FAILED_CLOSE_TIMEOUT_MS)
			meshd_pbgatt_close(nd);
	} else if (nd->pbgatt.active && nd->pbgatt.rx_started &&
	    now_ms >= nd->pbgatt.rx_started_ms &&
	    now_ms - nd->pbgatt.rx_started_ms >= MESHD_PROXY_SAR_TIMEOUT_MS)
		meshd_pbgatt_close(nd);
	else if (nd->pbgatt.active && nd->pbgatt.protocol_timer &&
	    now_ms >= nd->pbgatt.protocol_started_ms &&
	    now_ms - nd->pbgatt.protocol_started_ms >=
	    MESHD_PBGATT_PROTOCOL_TIMEOUT_MS)
		if (meshd_pbgatt_timeout(nd, now_ms) != 0)
			meshd_pbgatt_close(nd);
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++) {
		session = &nd->proxy_gatt[i];
		if (!session->active || !session->rx_started ||
		    now_ms < session->rx_started_ms ||
		    now_ms - session->rx_started_ms < MESHD_PROXY_SAR_TIMEOUT_MS)
			continue;
		meshd_proxy_gatt_close(nd, session->addr, session->addr_type,
		    session->adapter_index);
	}
}
