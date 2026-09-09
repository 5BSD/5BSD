/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Mesh Proxy Service (MshPRT_v1.1.1 Sections 6 and 7.2): both roles.
 *
 * The first half is the Proxy CLIENT -- this node discovering, subscribing to
 * and driving a peer's Mesh Proxy Service.  The second half is the Proxy
 * SERVER -- a Proxy Client connecting to this node: the per-connection proxy
 * filter and reassembly context, the proxy configuration messages answered with
 * a Filter Status, the filtered network-interface output, and the connectable
 * proxy advertising a peer finds this node with.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <openssl/rand.h>
#include <string.h>

#include "meshd.h"

/*
 * Enumerate this node's inbound network security credentials: the primary
 * subnet and every additional subnet, each with whichever of its current and
 * new keys the Key Refresh phase says may be received on (Section 3.11.4).
 * Shared by the Proxy Client's Filter Status path, the server's proxy
 * configuration path and the server's network-interface output, all of which
 * must try exactly the same candidate set.
 */
struct proxy_key_candidate {
	uint8_t		nid;
	const uint8_t	*enc;
	const uint8_t	*priv;
};

#define	PROXY_MAX_KEYS	(MESH_SIM_MAX_SUBNETS * 2 + 2)

static size_t
proxy_rx_keys(struct meshd_node *nd, struct proxy_key_candidate *keys)
{
	size_t i, nkeys;

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
	return (nkeys);
}

/*
 * The IV Index values a received PDU may have been secured under (Section
 * 3.10.5): the current one, and the previous one while it is still accepted.
 */
static size_t
proxy_rx_ivs(const struct meshd_node *nd, uint32_t *ivs)
{

	ivs[0] = nd->self->iv.iv_index;
	if (ivs[0] == 0)
		return (1);
	ivs[1] = ivs[0] - 1;
	return (2);
}


static int
proxy_config_recv(struct meshd_node *nd, struct meshd_proxy_gatt *session,
    const uint8_t *pdu, size_t len)
{
	struct proxy_key_candidate keys[PROXY_MAX_KEYS];
	struct mesh_proxy_cfg cfg;
	uint8_t msg[16];
	uint32_t ivs[2], seq;
	uint16_t src;
	size_t i, k, msglen, nkeys, niv;

	nkeys = proxy_rx_keys(nd, keys);
	niv = proxy_rx_ivs(nd, ivs);
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
	if (session == NULL || pdu == NULL ||
	    bearer_mtu < MESHD_PBGATT_MIN_MTU ||
	    len > (size_t)bearer_mtu - 3)
		return (-1);
	/*
	 * A zero-length ATT Handle Value Notification is legal on the wire;
	 * ignore it rather than treating it as a fatal error, which would tear
	 * the whole proxy link down on a single empty notify (NB-32).
	 */
	if (len == 0)
		return (0);
	rc = mesh_proxy_reasm_feed(&session->rx, pdu, len, &complete,
	    &type, msg, sizeof(msg), &msglen);
	if (rc == MESH_PROXY_REASM_ERROR)
		return (-1);
	if (rc == MESH_PROXY_REASM_IGNORED)
		return (0);
	if (!complete) {
		/*
		 * The 20 s SAR reassembly timeout (Section 6.3.2.2) is owned by
		 * mesh_proxy_reasm_tick(), which arms its clock on the first tick
		 * after a segment.  Arm it here instead, from this segment's own
		 * timestamp, so the deadline is measured from the segment rather
		 * than from the next tick.  mesh_proxy_reasm_feed() disarms the
		 * clock on EVERY accepted segment, so a slow-but-steady
		 * multi-segment transfer with sub-20 s inter-segment gaps is not
		 * torn down at 20 s from the first segment (C6-M10).
		 */
		(void)mesh_proxy_reasm_tick(&session->rx, now_ms);
		return (0);
	}
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
	/*
	 * Proxy Server role, driven on the same clock as the client role: the
	 * per-connection SAR timeout and connect-time beacon retry, the
	 * presence rule for the «Mesh Proxy Service» in the GATT database
	 * (Section 7.2.2.2), and the proxy advertising cadence.
	 */
	meshd_proxy_server_tick(nd, now_ms);
	(void)meshd_proxy_service_sync(nd);
	/*
	 * Proxy advertising shares the beacon cadence: one advertisement per
	 * interval, rotating through the subnets (Section 7.2.2.2.2's
	 * "it shall interleave the advertising of each subnet").
	 */
	if (nd->proxy_adv_last == 0 || now_ms >= nd->proxy_adv_last +
	    MESHD_BEACON_INTERVAL * 1000ULL)
		(void)meshd_proxy_adv_emit(nd, now_ms);
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
	/*
	 * Proxy SAR reassembly timeout (Section 6.3.2.2).  The deadline is
	 * evaluated by mesh_proxy_reasm_tick(), the library's own timeout clock,
	 * rather than by a second copy of the rule here; it discards the stalled
	 * partial message and returns 1, and the specification has the receiver
	 * disconnect, which is what closing the link does.
	 */
	for (i = 0; i < MESHD_MAX_PROXY_GATT; i++) {
		session = &nd->proxy_gatt[i];
		if (!session->active ||
		    mesh_proxy_reasm_tick(&session->rx, now_ms) != 1)
			continue;
		meshd_proxy_gatt_close(nd, session->addr, session->addr_type,
		    session->adapter_index);
	}
}

/* ================================================================
 * Mesh Proxy SERVER role (MshPRT_v1.1.1 Sections 6.7 and 7.2).
 *
 * Everything above this line is the Proxy CLIENT: this node discovering,
 * subscribing to and writing a PEER's Mesh Proxy Service.  Below is the server
 * side, where a Proxy Client (typically a phone) connects to THIS node: the
 * per-connection proxy filter and reassembly context, the proxy configuration
 * messages answered with a Filter Status, the network-interface output that
 * the filter gates, and the connectable proxy advertising that lets the peer
 * find us in the first place.
 * ================================================================ */

/* Locate the per-connection Proxy Server state for one inbound GATT link. */
static struct meshd_proxy_server *
proxy_srv_session(struct meshd_node *nd, const char *addr, uint8_t addr_type,
    uint8_t adapter_index)
{
	struct meshd_proxy_server *match;
	size_t i;

	if (nd == NULL || addr == NULL)
		return (NULL);
	match = NULL;
	for (i = 0; i < MESHD_MAX_PROXY_SERVER; i++) {
		if (!nd->proxy_srv[i].active ||
		    nd->proxy_srv[i].addr_type != addr_type ||
		    strcmp(nd->proxy_srv[i].addr, addr) != 0 ||
		    (adapter_index != MESHD_ADAPTER_DEFAULT &&
		    nd->proxy_srv[i].adapter_index != adapter_index))
			continue;
		/* The default selector names a link only when it is unique. */
		if (match != NULL)
			return (NULL);
		match = &nd->proxy_srv[i];
	}
	return (match);
}

int
meshd_proxy_server_active(const struct meshd_node *nd)
{
	size_t i;

	if (nd == NULL)
		return (0);
	for (i = 0; i < MESHD_MAX_PROXY_SERVER; i++)
		if (nd->proxy_srv[i].active)
			return (1);
	return (0);
}

/*
 * Send one Proxy protocol message to a connected Proxy Client, segmented into
 * Proxy PDUs that fit the connection's ATT_MTU (Sections 6.3.2.1 and 7.2.2.2.7:
 * a Proxy PDU is carried in one ATT notification, so its length is ATT_MTU-3).
 */
static int
proxy_srv_send(struct meshd_node *nd, struct meshd_proxy_server *srv,
    uint8_t type, const uint8_t *msg, size_t msglen)
{
	struct mesh_proxy_seg segs[8];
	size_t i, nseg, pdu_max;

	if (nd->bearer == NULL || nd->bearer->proxy_srv_tx == NULL)
		return (-1);
	if (srv->mtu < MESHD_PBGATT_MIN_MTU)
		return (-1);
	pdu_max = (size_t)srv->mtu - 3;
	if (pdu_max > MESH_PROXY_MAX_PDU)
		pdu_max = MESH_PROXY_MAX_PDU;
	if (mesh_proxy_segment(type, msg, msglen, pdu_max, segs,
	    nitems(segs), &nseg) != 0)
		return (-1);
	for (i = 0; i < nseg; i++)
		if (nd->bearer->proxy_srv_tx(nd->bearer->arg, srv->addr,
		    srv->addr_type, srv->adapter_index, segs[i].bytes,
		    segs[i].len) != 0)
			return (-1);
	return (0);
}

/*
 * Answer a proxy configuration message with a Filter Status (Section 6.6.4).
 *
 * Section 6.7: "the Filter Status message shall be secured with the same
 * network security credentials as were used for the received message", and
 * "a Proxy Server shall set the SRC field to the unicast address of its primary
 * element and the SEQ field shall use the sequence number of its primary
 * element".  The IV Index is the node's transmit index, as for every other
 * outbound PDU (Section 3.10.5).
 */
static int
proxy_srv_filter_status(struct meshd_node *nd, struct meshd_proxy_server *srv,
    const struct proxy_key_candidate *key)
{
	/* Opcode (1) || FilterType (1) || ListSize (2): Sections 6.6, 6.6.4. */
	uint8_t msg[4], secured[MESH_PROXY_MAX_NETWORK_PDU];
	size_t msglen, secured_len;

	if (mesh_proxy_cfg_filter_status_build(srv->filter.type,
	    (uint16_t)srv->filter.count, msg, sizeof(msg), &msglen) != 0)
		return (-1);
	if (nd->self->seq > MESH_IV_SEQ_MAX)
		return (-1);
	if (mesh_proxy_cfg_encrypt(key->enc, key->priv, key->nid,
	    mesh_iv_tx_index(&nd->self->iv), nd->self->seq, nd->self->addr,
	    msg, msglen, secured, &secured_len) != 0)
		return (-1);
	nd->self->seq++;
	return (proxy_srv_send(nd, srv, MESH_PROXY_TYPE_CONFIG, secured,
	    secured_len));
}

/*
 * Apply one Add / Remove Addresses message to the connection's proxy filter
 * (Sections 6.6.2, 6.6.3 and 6.7).  "If the AddressArray field contains the
 * unassigned address, the Proxy Server shall ignore that address"; an address
 * already present is not added twice, and "if the Proxy Server runs out of
 * space in the proxy filter list, the Proxy Server shall not add these
 * addresses" -- neither condition is an error, and both are simply reflected
 * in the ListSize the Filter Status reports back.
 */
static void
proxy_srv_filter_addrs(struct meshd_proxy_server *srv, uint8_t opcode,
    const uint16_t *addrs, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (addrs[i] == MESH_ADDR_UNASSIGNED)
			continue;
		if (opcode == MESH_PROXY_OP_ADD_ADDR)
			(void)mesh_proxy_filter_add(&srv->filter, &addrs[i], 1);
		else
			(void)mesh_proxy_filter_remove(&srv->filter, &addrs[i],
			    1);
	}
}

/*
 * A proxy configuration message arrived from the Proxy Client (Section 6.6).
 * Returns 1 when it was accepted and answered, 0 when it was ignored, -1 when
 * it could not be authenticated.
 */
static int
proxy_srv_config_recv(struct meshd_node *nd, struct meshd_proxy_server *srv,
    const uint8_t *pdu, size_t len)
{
	struct proxy_key_candidate keys[PROXY_MAX_KEYS];
	struct mesh_proxy_cfg cfg;
	uint8_t msg[16];
	uint32_t ivs[2], seq;
	uint16_t src;
	size_t i, k, msglen, nkeys, niv;

	nkeys = proxy_rx_keys(nd, keys);
	niv = proxy_rx_ivs(nd, ivs);
	for (k = 0; k < nkeys; k++) {
		for (i = 0; i < niv; i++) {
			if (mesh_proxy_cfg_decrypt(keys[k].enc, keys[k].priv,
			    keys[k].nid, ivs[i], pdu, len, &seq, &src, msg,
			    sizeof(msg), &msglen) != 0)
				continue;
			/*
			 * An RFU opcode is rejected by the codec, which is
			 * exactly Section 6.7's "upon receiving a proxy
			 * configuration message with the Opcode field set to a
			 * value that is Reserved for Future Use, the Proxy
			 * Server shall ignore this message".
			 */
			if (mesh_proxy_cfg_parse(msg, msglen, &cfg) != 0)
				return (0);
			if (mesh_rpl_check(&nd->self->rpl, src, ivs[i], seq) != 1)
				return (0);
			switch (cfg.opcode) {
			case MESH_PROXY_OP_SET_FILTER_TYPE:
				/*
				 * "it shall set the proxy filter type as
				 * requested in the message parameter, and it
				 * shall clear the proxy filter list"
				 * (Section 6.7); the library's set_type does
				 * both.
				 */
				if (mesh_proxy_filter_set_type(&srv->filter,
				    cfg.filter_type) != 0)
					return (0);
				break;
			case MESH_PROXY_OP_ADD_ADDR:
			case MESH_PROXY_OP_REMOVE_ADDR:
				proxy_srv_filter_addrs(srv, cfg.opcode,
				    cfg.addrs, cfg.naddr);
				break;
			default:
				/*
				 * Filter Status and the two Directed Proxy
				 * messages are not sent by a Proxy Client to a
				 * Proxy Server in this role; nothing to do and
				 * nothing to answer.
				 */
				return (0);
			}
			return (proxy_srv_filter_status(nd, srv, &keys[k]) == 0 ?
			    1 : 0);
		}
	}
	return (-1);
}

/*
 * Proxy filter maintenance driven by inbound Network PDUs (Section 6.7):
 * "If the proxy filter is an accept list filter, upon receiving a Proxy PDU
 * containing a valid Network PDU from the Proxy Client, the Proxy Server shall
 * add the unicast address contained in the SRC field ... to the accept list.
 * If the proxy filter is a reject list filter, [it] shall remove [it] from the
 * reject list."  A PDU that authenticates under none of our credentials is not
 * a valid Network PDU and changes nothing.
 */
static void
proxy_srv_learn_src(struct meshd_node *nd, struct meshd_proxy_server *srv,
    const uint8_t *pdu, size_t len)
{
	struct proxy_key_candidate keys[PROXY_MAX_KEYS];
	struct mesh_net_pdu net;
	uint32_t ivs[2];
	size_t i, k, nkeys, niv;

	nkeys = proxy_rx_keys(nd, keys);
	niv = proxy_rx_ivs(nd, ivs);
	for (k = 0; k < nkeys; k++)
		for (i = 0; i < niv; i++) {
			if (mesh_net_decrypt(keys[k].enc, keys[k].priv,
			    keys[k].nid, ivs[i], pdu, len, &net) != 0)
				continue;
			if (net.src < MESHD_UNICAST_MIN ||
			    net.src > MESHD_UNICAST_MAX)
				return;
			if (srv->filter.type == MESH_PROXY_FILTER_ACCEPT)
				(void)mesh_proxy_filter_add(&srv->filter,
				    &net.src, 1);
			else
				(void)mesh_proxy_filter_remove(&srv->filter,
				    &net.src, 1);
			return;
		}
}

/*
 * Send one mesh beacon for a subnet to a Proxy Client (Section 6.7 with Table
 * 6.15): a Secure Network beacon while the connection's Proxy Privacy parameter
 * is Disabled, a Mesh Private beacon while it is Enabled.  The beacon is
 * secured with the key the subnet currently beacons under, which from Key
 * Refresh Phase 2 is the new key (Sections 3.11.4.1-3.11.4.3).
 */
static int
proxy_srv_subnet_beacon(struct meshd_node *nd, struct meshd_proxy_server *srv,
    uint16_t net_idx)
{
	uint8_t beacon[MESH_PRIVATE_BEACON_LEN];
	uint8_t random[MESH_PRIVATE_BEACON_RANDOM_LEN];
	const struct mesh_node *self = nd->self;
	const uint8_t *bkey;
	struct mesh_sim_subnet_key *subnet;
	size_t blen, i;
	uint8_t kr_flag, iv_update;
	int rc;

	if (net_idx == self->primary_net_idx) {
		if (self->have_new_key &&
		    mesh_kr_phase(&self->kr) >= MESH_KR_PHASE_2) {
			bkey = self->new_netkey;
			kr_flag = (uint8_t)mesh_kr_beacon_flag(&self->kr);
		} else {
			bkey = self->netkey;
			kr_flag = 0;
		}
	} else {
		subnet = NULL;
		for (i = 0; i < self->n_subnets; i++)
			if (self->subnets[i].valid &&
			    self->subnets[i].net_idx == net_idx)
				subnet = &nd->self->subnets[i];
		if (subnet == NULL)
			return (-1);
		if (subnet->have_new_key &&
		    mesh_kr_phase(&subnet->kr) >= MESH_KR_PHASE_2) {
			bkey = subnet->new_netkey;
			kr_flag = (uint8_t)mesh_kr_beacon_flag(&subnet->kr);
		} else {
			bkey = subnet->netkey;
			kr_flag = 0;
		}
	}
	iv_update = (self->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ? 1 : 0;
	if (srv->privacy != 0) {
		if (RAND_bytes(random, sizeof(random)) != 1)
			return (-1);
		rc = mesh_private_beacon_build(bkey, kr_flag, iv_update,
		    self->iv.iv_index, random, beacon, &blen);
		explicit_bzero(random, sizeof(random));
	} else
		rc = mesh_secure_beacon_build(bkey, kr_flag, iv_update,
		    self->iv.iv_index, beacon, &blen);
	if (rc != 0)
		return (-1);
	return (proxy_srv_send(nd, srv, MESH_PROXY_TYPE_BEACON, beacon, blen));
}

/*
 * "The Proxy Server shall send a mesh beacon for each known subnet to the Proxy
 * Client" (Section 6.7).  At the instant the link comes up the client has
 * usually not yet enabled notifications on Mesh Proxy Data Out, so a send can
 * legitimately fail; the attempt is repeated from the tick until every subnet's
 * beacon has been handed to the bearer, rather than dropping them.
 */
static void
proxy_srv_connect_beacons(struct meshd_node *nd, struct meshd_proxy_server *srv)
{
	size_t i;
	int failed;

	if (!srv->beacons_pending)
		return;
	failed = 0;
	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (!nd->db.netkeys[i].valid)
			continue;
		if (proxy_srv_subnet_beacon(nd, srv,
		    nd->db.netkeys[i].net_idx) != 0)
			failed = 1;
	}
	srv->beacons_pending = failed;
}

int
meshd_proxy_server_open(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, uint16_t mtu)
{
	struct meshd_proxy_server *srv;
	size_t i;

	if (nd == NULL || addr == NULL || strlen(addr) != 17 ||
	    addr_type > MESHD_ADDR_RANDOM ||
	    adapter_index == MESHD_ADAPTER_DEFAULT || !nd->provisioned ||
	    mtu < MESHD_PBGATT_MIN_MTU || mtu > MESHD_GATT_MAX_MTU ||
	    proxy_srv_session(nd, addr, addr_type, adapter_index) != NULL)
		return (-1);
	for (i = 0; i < MESHD_MAX_PROXY_SERVER; i++)
		if (!nd->proxy_srv[i].active)
			break;
	if (i == MESHD_MAX_PROXY_SERVER)
		return (-1);
	srv = &nd->proxy_srv[i];
	memset(srv, 0, sizeof(*srv));
	/*
	 * "Upon connection, the Proxy Server shall initialize the proxy filter
	 * as an accept list filter and the accept list shall be empty."
	 * (Section 6.7 / 6.4.1.)
	 */
	mesh_proxy_filter_init(&srv->filter);
	mesh_proxy_reasm_init(&srv->rx);
	strlcpy(srv->addr, addr, sizeof(srv->addr));
	srv->addr_type = addr_type;
	srv->adapter_index = adapter_index;
	srv->mtu = mtu;
	/*
	 * Proxy Privacy parameter (Sections 6.5 and 7.2.2.2.6), evaluated once
	 * and retained for the lifetime of the connection: Disabled while the
	 * GATT Proxy state or any subnet's Node Identity state is enabled;
	 * Enabled when both are disabled and the Private GATT Proxy state or
	 * any subnet's Private Node Identity state is enabled.
	 */
	srv->privacy = 0;
	if (nd->cfg.gatt_proxy != 1) {
		int node_identity = 0, priv_identity = 0;

		for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
			if (!nd->db.netkeys[i].valid)
				continue;
			if (nd->db.netkeys[i].node_identity ==
			    MESH_CFG_NODE_IDENTITY_RUNNING)
				node_identity = 1;
			if (nd->db.netkeys[i].priv_node_identity ==
			    MESH_CFG_NODE_IDENTITY_RUNNING)
				priv_identity = 1;
		}
		if (!node_identity &&
		    (nd->db.priv_gatt_proxy == 1 || priv_identity))
			srv->privacy = 1;
	}
	srv->active = 1;
	/*
	 * "The Proxy Server shall send a mesh beacon for each known subnet to
	 * the Proxy Client" (Section 6.7).  A beacon that cannot be built or
	 * sent does not fail the connection: the link is up and usable, and the
	 * client can still drive it.
	 */
	srv->beacons_pending = 1;
	proxy_srv_connect_beacons(nd, srv);
	return (0);
}

void
meshd_proxy_server_close(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index)
{
	size_t i;

	if (nd == NULL)
		return;
	for (i = 0; i < MESHD_MAX_PROXY_SERVER; i++)
		if (nd->proxy_srv[i].active && (addr == NULL ||
		    (nd->proxy_srv[i].addr_type == addr_type &&
		    nd->proxy_srv[i].adapter_index == adapter_index &&
		    strcmp(nd->proxy_srv[i].addr, addr) == 0)))
			memset(&nd->proxy_srv[i], 0, sizeof(nd->proxy_srv[i]));
}

int
meshd_proxy_server_recv(struct meshd_node *nd, const char *addr,
    uint8_t addr_type, uint8_t adapter_index, const uint8_t *pdu, size_t len,
    uint16_t bearer_mtu, uint64_t now_ms)
{
	struct meshd_proxy_server *srv;
	uint8_t type, msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	int complete, rc;

	srv = proxy_srv_session(nd, addr, addr_type, adapter_index);
	if (srv == NULL || pdu == NULL || bearer_mtu < MESHD_PBGATT_MIN_MTU ||
	    len > (size_t)bearer_mtu - 3)
		return (-1);
	/* An empty write is legal on the wire and carries no Proxy PDU. */
	if (len == 0)
		return (0);
	/*
	 * Track the connection's live ATT_MTU: a Proxy Client may exchange MTU
	 * after connecting, and the segmentation of everything we send back is
	 * sized from it (Section 7.2.2.2.7).  Never shrink it mid-reassembly.
	 */
	if (bearer_mtu <= MESHD_GATT_MAX_MTU && !srv->rx.in_progress)
		srv->mtu = bearer_mtu;
	rc = mesh_proxy_reasm_feed(&srv->rx, pdu, len, &complete, &type, msg,
	    sizeof(msg), &msglen);
	if (rc == MESH_PROXY_REASM_ERROR)
		return (-1);
	if (rc == MESH_PROXY_REASM_IGNORED)
		return (0);
	if (!complete) {
		(void)mesh_proxy_reasm_tick(&srv->rx, now_ms);
		return (0);
	}
	switch (type) {
	case MESH_PROXY_TYPE_NETWORK:
		proxy_srv_learn_src(nd, srv, msg, msglen);
		return (meshd_bearer_rx(nd, msg, msglen) < 0 ? 0 : 1);
	case MESH_PROXY_TYPE_BEACON:
		return (meshd_beacon_rx(nd, msg, msglen) < 0 ? 0 : 1);
	case MESH_PROXY_TYPE_CONFIG:
		return (proxy_srv_config_recv(nd, srv, msg, msglen) > 0 ? 1 : 0);
	default:
		/*
		 * A Provisioning PDU belongs to the Mesh Provisioning Service,
		 * not to the Mesh Proxy Service (Section 6.2.2); ignore it.
		 */
		return (0);
	}
}

int
meshd_proxy_server_forward(struct meshd_node *nd, const uint8_t *pdu,
    size_t len)
{
	struct proxy_key_candidate keys[PROXY_MAX_KEYS];
	struct mesh_net_pdu net;
	uint32_t ivs[2];
	size_t i, k, n, nkeys, niv;
	int found, sent;

	if (nd == NULL || nd->self == NULL || pdu == NULL || len == 0)
		return (0);
	if (nd->bearer == NULL || nd->bearer->proxy_srv_tx == NULL)
		return (0);
	if (!meshd_proxy_server_active(nd))
		return (0);
	/*
	 * The proxy filter is keyed on the Network PDU's destination address
	 * (Sections 6.4 and 6.4.1), which is inside the encrypted payload, so
	 * the PDU has to authenticate under one of this node's credentials
	 * before it can be filtered.  One that does not is not ours to forward.
	 */
	nkeys = proxy_rx_keys(nd, keys);
	niv = proxy_rx_ivs(nd, ivs);
	found = 0;
	for (k = 0; k < nkeys && !found; k++)
		for (i = 0; i < niv; i++)
			if (mesh_net_decrypt(keys[k].enc, keys[k].priv,
			    keys[k].nid, ivs[i], pdu, len, &net) == 0) {
				found = 1;
				break;
			}
	if (!found)
		return (0);
	sent = 0;
	for (n = 0; n < MESHD_MAX_PROXY_SERVER; n++) {
		struct meshd_proxy_server *srv = &nd->proxy_srv[n];

		if (!srv->active ||
		    !mesh_proxy_filter_accepts(&srv->filter, net.dst))
			continue;
		if (proxy_srv_send(nd, srv, MESH_PROXY_TYPE_NETWORK, pdu,
		    len) == 0)
			sent++;
	}
	return (sent);
}

void
meshd_proxy_server_tick(struct meshd_node *nd, uint64_t now_ms)
{
	struct meshd_proxy_server *srv;
	size_t i;

	if (nd == NULL)
		return;
	/*
	 * SAR reassembly timeout (Section 6.3.2.2): a partial message that goes
	 * 20 s without a further segment is discarded and the receiver
	 * disconnects, which for the server is closing this connection's state.
	 */
	for (i = 0; i < MESHD_MAX_PROXY_SERVER; i++) {
		srv = &nd->proxy_srv[i];
		if (!srv->active)
			continue;
		proxy_srv_connect_beacons(nd, srv);
		if (mesh_proxy_reasm_tick(&srv->rx, now_ms) != 1)
			continue;
		meshd_proxy_server_close(nd, srv->addr, srv->addr_type,
		    srv->adapter_index);
	}
}

/*
 * Section 7.2.2.2: the Mesh Proxy Service "shall be present in the GATT
 * database of a provisioned device" while any subnet's Node Identity or
 * Private Node Identity state is 0x00 or 0x01 -- that is, while the identity
 * functionality exists at all rather than reading Not Supported (0x02) -- and
 * "shall not be present" otherwise.  A node that has the Proxy feature enabled
 * needs it too (Section 3.4.6.4).
 */
int
meshd_proxy_service_sync(struct meshd_node *nd)
{
	size_t i;
	int want;

	if (nd == NULL || nd->bearer == NULL ||
	    nd->bearer->proxy_service == NULL)
		return (0);
	want = 0;
	if (nd->provisioned) {
		if (nd->cfg.gatt_proxy == 1 || nd->db.priv_gatt_proxy == 1)
			want = 1;
		for (i = 0; i < MESHD_MAX_NETKEYS && !want; i++) {
			if (!nd->db.netkeys[i].valid)
				continue;
			if (nd->db.netkeys[i].node_identity !=
			    MESH_CFG_NODE_IDENTITY_NOT_SUPPORTED ||
			    nd->db.netkeys[i].priv_node_identity !=
			    MESH_CFG_NODE_IDENTITY_NOT_SUPPORTED)
				want = 1;
		}
	}
	if (want == nd->proxy_service_registered)
		return (0);
	if (nd->bearer->proxy_service(nd->bearer->arg, want) != 0)
		return (-1);
	nd->proxy_service_registered = want;
	return (1);
}

/*
 * Select the subnet key a proxy advertisement is built from.  The Mesh Proxy
 * Service advertising "depends on the NetKey value and will be updated upon
 * transition from Phase 1" (Section 7.2.2.2.1 note), so it follows the same
 * rule as the beacon: the new key from Key Refresh Phase 2 onwards.
 */
static const uint8_t *
proxy_adv_netkey(const struct meshd_node *nd,
    const struct meshd_netkey_entry *e)
{
	const struct mesh_node *self = nd->self;
	size_t i;

	if (e->net_idx == self->primary_net_idx)
		return (self->have_new_key &&
		    mesh_kr_phase(&self->kr) >= MESH_KR_PHASE_2 ?
		    self->new_netkey : self->netkey);
	for (i = 0; i < self->n_subnets; i++) {
		const struct mesh_sim_subnet_key *s = &self->subnets[i];

		if (!s->valid || s->net_idx != e->net_idx)
			continue;
		return (s->have_new_key &&
		    mesh_kr_phase(&s->kr) >= MESH_KR_PHASE_2 ?
		    s->new_netkey : s->netkey);
	}
	/*
	 * The Configuration database holds a NetKey the sim node does not: use
	 * the configured key, which is what the subnet was added with.
	 */
	return (e->has_new_key && e->kr_phase >= MESH_CFG_KR_PHASE_2 ?
	    e->new_key : e->key);
}

/*
 * Build the proxy advertising Service Data AD structure for one subnet, per the
 * Section 7.2.2.2 tables:
 *
 *   Table 7.10  Private Node Identity state Enable      -> type 0x03
 *               Node Identity state Enable              -> type 0x01
 *   Table 7.9   GATT Proxy state Enable                 -> type 0x00 (Network ID)
 *               GATT Proxy Disable + Private GATT Proxy Enable -> type 0x02
 *
 * The identity forms take precedence: they name THIS node and are what a client
 * that wants this specific node is scanning for.  A fresh 64-bit random value
 * is drawn for every identity advertisement, which is also the point at which
 * the private forms require the advertising address to be regenerated
 * (Sections 7.2.2.2.4, 7.2.2.2.5) -- hence the address policy returned with it.
 */
static int
proxy_adv_build(struct meshd_node *nd, const struct meshd_netkey_entry *e,
    uint8_t *ad, size_t *adlen, uint8_t *policy)
{
	uint8_t identity_key[16], random[MESH_PROXY_ID_RANDOM_LEN];
	const uint8_t *netkey;
	int rc;

	netkey = proxy_adv_netkey(nd, e);
	if (e->priv_node_identity == MESH_CFG_NODE_IDENTITY_RUNNING ||
	    e->node_identity == MESH_CFG_NODE_IDENTITY_RUNNING) {
		if (mesh_proxy_identity_key(netkey, identity_key) != 0)
			return (-1);
		if (RAND_bytes(random, sizeof(random)) != 1) {
			explicit_bzero(identity_key, sizeof(identity_key));
			return (-1);
		}
		if (e->priv_node_identity == MESH_CFG_NODE_IDENTITY_RUNNING) {
			rc = mesh_proxy_adv_private_node_identity_build(
			    identity_key, nd->self->addr, random, ad, adlen);
			*policy = MESHD_ADV_ADDR_NRPA;
		} else {
			rc = mesh_proxy_adv_node_identity_build(identity_key,
			    nd->self->addr, random, ad, adlen);
			*policy = MESHD_ADV_ADDR_DEFAULT;
		}
		explicit_bzero(identity_key, sizeof(identity_key));
		explicit_bzero(random, sizeof(random));
		return (rc);
	}
	if (nd->cfg.gatt_proxy == 1) {
		*policy = MESHD_ADV_ADDR_DEFAULT;
		return (mesh_proxy_adv_network_id_build(netkey, ad, adlen));
	}
	if (nd->db.priv_gatt_proxy == 1) {
		if (RAND_bytes(random, sizeof(random)) != 1)
			return (-1);
		rc = mesh_proxy_adv_private_network_id_build(netkey, random, ad,
		    adlen);
		explicit_bzero(random, sizeof(random));
		*policy = MESHD_ADV_ADDR_NRPA;
		return (rc);
	}
	return (1);	/* nothing to advertise for this subnet */
}

int
meshd_proxy_adv_emit(struct meshd_node *nd, uint64_t now_ms)
{
	uint8_t ad[MESH_PROXY_ADV_NODE_IDENTITY_LEN];
	size_t adlen, i, slot;
	uint8_t policy;
	int rc;

	if (nd == NULL || nd->self == NULL)
		return (-1);
	if (!nd->provisioned || nd->bearer == NULL ||
	    nd->bearer->proxy_adv == NULL)
		return (0);
	/*
	 * "When a server is a member of multiple subnets, it shall interleave
	 * the advertising of each subnet" (Sections 7.2.2.2.2, 7.2.2.2.3,
	 * 7.2.2.2.4, 7.2.2.2.5).  One advertisement is emitted per beacon
	 * cadence and the cursor advances, so consecutive cadences rotate
	 * through the subnets that have something to advertise.
	 */
	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		slot = (nd->proxy_adv_next + i) % MESHD_MAX_NETKEYS;
		if (!nd->db.netkeys[slot].valid)
			continue;
		policy = MESHD_ADV_ADDR_DEFAULT;
		adlen = 0;
		rc = proxy_adv_build(nd, &nd->db.netkeys[slot], ad, &adlen,
		    &policy);
		if (rc > 0)
			continue;	/* this subnet advertises nothing */
		if (rc < 0)
			return (0);
		nd->proxy_adv_next = (slot + 1) % MESHD_MAX_NETKEYS;
		nd->proxy_adv_last = now_ms;
		if (nd->bearer->proxy_adv(nd->bearer->arg, 1, policy, ad,
		    adlen) != 0)
			return (0);
		nd->proxy_adv_on = 1;
		return (1);
	}
	nd->proxy_adv_last = now_ms;
	/*
	 * Nothing to advertise on any subnet: Table 7.9/7.10's "No Proxy
	 * Advertising" / "No Identity Advertising".  Stop any advertisement
	 * still on air from an earlier cadence.
	 */
	if (nd->proxy_adv_on) {
		(void)nd->bearer->proxy_adv(nd->bearer->arg, 0,
		    MESHD_ADV_ADDR_DEFAULT, NULL, 0);
		nd->proxy_adv_on = 0;
	}
	return (0);
}
