/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh multi-node network simulator.  Composes the Phase 1-8
 * libmesh modules into a running network over a shared virtual advertising
 * medium.  See mesh_sim.h for the architecture and the modelled scope.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "mesh_sim.h"
#include "mesh_crypto.h"
#include "mesh_generic.h"
#include "mesh_beacon.h"
#include "mesh_provision.h"

/* Managed-flooding k2 P-input is the single octet 0x00 (MshPRT_v1.1 3.8.2.6). */
static const uint8_t k2_p_managed[1] = { 0x00 };

/* Largest Upper Transport Access PDU we buffer. */
#define	SIM_UPPER_MAX	MESH_UPPER_MAX
#define	SIM_SAR_RETRANS_MS	200
#define	SIM_SAR_DISCARD_MS	10000
#define	SIM_SAR_RETRIES		4
/* Default TTL used for locally originated Segment Acks (MshPRT_v1.1 3.5.3.4). */
#define	SIM_DEFAULT_TTL		5

static struct mesh_sim_subnet_key *find_subnet(struct mesh_node *, uint16_t);
static void node_recv_net(struct mesh_sim *, struct mesh_node *,
    const uint8_t *, size_t, int);

/* ================================================================
 * Small helpers.
 * ================================================================ */

static int
local_unicast(const struct mesh_node *node, uint16_t addr)
{
	uint8_t i;

	for (i = 0; i < node->n_elements; i++) {
		if (node->elems[i].addr == addr)
			return (1);
	}
	return (0);
}

static int
node_subscribed(const struct mesh_node *node, uint16_t addr)
{
	uint8_t ei;
	size_t i;

	for (ei = 0; ei < node->n_elements; ei++) {
		for (i = 0; i < node->elem_n_subs[ei]; i++) {
			if (node->elem_subs[ei][i] == addr)
				return (1);
		}
		if (mesh_addr_is_virtual(addr)) {
			for (i = 0; i < node->elem_n_labels[ei]; i++) {
				uint16_t va;

				if (mesh_virtual_addr(node->elem_labels[ei][i], &va) == 0 &&
				    va == addr)
					return (1);
			}
		}
	}
	return (0);
}

static int
addressed_here(const struct mesh_node *node, uint16_t dst)
{

	if (dst == MESH_ADDR_ALL_NODES)
		return (1);
	if (local_unicast(node, dst))
		return (1);
	if (node_subscribed(node, dst))
		return (1);
	return (0);
}

/*
 * Network message cache: 1 if (src, seq, iv_index) already recorded, else
 * records it and returns 0.  M-N1: the IV Index is part of the key so the same
 * (src, seq) recurring after an IV Index change is not treated as a duplicate.
 */
static int
nmc_seen_record(struct mesh_node *node, uint16_t src, uint32_t seq,
    uint32_t iv_index)
{
	size_t i;

	for (i = 0; i < MESH_SIM_NMC_SIZE; i++) {
		if (node->nmc[i].valid && node->nmc[i].src == src &&
		    node->nmc[i].seq == seq && node->nmc[i].iv_index == iv_index)
			return (1);
	}
	node->nmc[node->nmc_next].valid = 1;
	node->nmc[node->nmc_next].src = src;
	node->nmc[node->nmc_next].seq = seq;
	node->nmc[node->nmc_next].iv_index = iv_index;
	node->nmc_next = (node->nmc_next + 1) % MESH_SIM_NMC_SIZE;
	return (0);
}

/* Select the network security material a node uses to TRANSMIT (Key Refresh). */
static void
node_tx_netsec(const struct mesh_node *node, uint8_t *nid,
    const uint8_t **enc, const uint8_t **priv)
{

	if (node->have_new_key && mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
		*nid = node->new_nid;
		*enc = node->new_enckey;
		*priv = node->new_privkey;
	} else {
		*nid = node->nid;
		*enc = node->enckey;
		*priv = node->privkey;
	}
}

/* ================================================================
 * Medium.
 * ================================================================ */

static int
enqueue_net_to(struct mesh_sim *sim, int tx_node, int to_node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{
	struct mesh_sim_tx *slot;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;

	if (sim->n_tx >= MESH_SIM_MAX_TX)
		return (-1);
	if (mesh_net_encrypt(enc, priv, nid, iv, pdu, out, &outlen) != 0)
		return (-1);
	slot = &sim->tx[sim->n_tx++];
	memcpy(slot->bytes, out, outlen);
	slot->len = outlen;
	slot->tx_node = tx_node;
	slot->to_node = to_node;
	slot->valid = 1;
	return (0);
}

static int
enqueue_net(struct mesh_sim *sim, int tx_node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{

	int error;
	struct mesh_sim_relay_tx *job;
	size_t i;

	error = enqueue_net_to(sim, tx_node, -1, nid, enc, priv, iv, pdu);
	if (error != 0 || tx_node < 0 || tx_node >= sim->n_nodes ||
	    sim->nodes[tx_node].relay.net_tx_count == 0)
		return (error);
	job = NULL;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++)
		if (!mesh_relay_tx_active(&sim->retransmit[i].timer)) {
			job = &sim->retransmit[i];
			break;
		}
	if (job == NULL)
		return (0);
	job->pdu = sim->tx[sim->n_tx - 1];
	mesh_relay_tx_schedule(&job->timer,
	    sim->nodes[tx_node].relay.net_tx_count,
	    sim->nodes[tx_node].relay.net_tx_steps, sim->now_ms);
	return (0);
}

static int
enqueue_relay(struct mesh_sim *sim, struct mesh_node *node, uint8_t nid,
    const uint8_t *enc, const uint8_t *priv, uint32_t iv,
    const struct mesh_net_pdu *pdu)
{
	struct mesh_sim_relay_tx *job;
	int error;
	size_t i;

	error = enqueue_net_to(sim, node->index, -1, nid, enc, priv, iv, pdu);
	if (error != 0 || node->relay.relay_rx_count == 0)
		return (error);
	job = NULL;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++)
		if (!mesh_relay_tx_active(&sim->retransmit[i].timer)) {
			job = &sim->retransmit[i];
			break;
		}
	if (job == NULL)
		return (0);
	job->pdu = sim->tx[sim->n_tx - 1];
	mesh_relay_tx_schedule(&job->timer, node->relay.relay_rx_count,
	    node->relay.relay_rx_steps, sim->now_ms);
	return (0);
}

static void
sar_tx_record(struct mesh_sim *sim, struct mesh_node *node, size_t first,
    size_t nseg, uint16_t dst, uint16_t seqzero)
{
	struct mesh_sim_sar_tx *s = NULL;
	size_t i;

	if (!mesh_addr_is_unicast(dst) || nseg == 0 || nseg > MESH_SEG_MAX ||
	    first + nseg > sim->n_tx)
		return;
	for (i = 0; i < MESH_SIM_SAR_TX; i++) {
		if (!node->sar_tx[i].used) {
			s = &node->sar_tx[i];
			break;
		}
		if (s == NULL || node->sar_tx[i].deadline_ms < s->deadline_ms)
			s = &node->sar_tx[i];
	}
	memset(s, 0, sizeof(*s));
	for (i = 0; i < nseg; i++)
		s->seg[i] = sim->tx[first + i];
	s->dst = dst;
	s->seqzero = seqzero;
	s->segn = (uint8_t)(nseg - 1);
	s->deadline_ms = sim->now_ms + SIM_SAR_RETRANS_MS;
	s->used = 1;
}

static void
sar_tx_requeue_missing(struct mesh_sim *sim, struct mesh_sim_sar_tx *s)
{
	uint32_t full;
	size_t i;

	full = mesh_blockack_full(s->segn);
	if ((s->blockack & full) == full) {
		s->used = 0;
		return;
	}
	for (i = 0; i <= s->segn && sim->n_tx < MESH_SIM_MAX_TX; i++)
		if ((s->blockack & ((uint32_t)1 << i)) == 0)
			sim->tx[sim->n_tx++] = s->seg[i];
	s->retries++;
	s->deadline_ms = sim->now_ms + SIM_SAR_RETRANS_MS;
	if (s->retries >= SIM_SAR_RETRIES)
		s->used = 0;
}

/* The current virtual clock expressed in milliseconds (DF / provisioning). */
static uint64_t
sim_now_ms(const struct mesh_sim *sim)
{

	return (sim->now_ms);
}

/* ================================================================
 * Setup.
 * ================================================================ */

int
mesh_sim_init(struct mesh_sim *sim, const uint8_t netkey[16],
    const uint8_t appkey[16], uint32_t iv_index)
{

	if (sim == NULL || netkey == NULL || appkey == NULL)
		return (-1);
	memset(sim, 0, sizeof(*sim));
	memcpy(sim->netkey, netkey, 16);
	memcpy(sim->appkey, appkey, 16);
	sim->iv_index = iv_index;
	sim->now = 0;
	sim->now_ms = 0;
	return (0);
}

struct mesh_node *
mesh_sim_add_node(struct mesh_sim *sim, uint16_t addr, uint8_t n_elements)
{
	struct mesh_node *node;
	size_t i;

	if (sim == NULL || n_elements == 0 || n_elements > MESH_SIM_MAX_ELEMS)
		return (NULL);
	if (sim->n_nodes >= MESH_SIM_MAX_NODES)
		return (NULL);
	node = &sim->nodes[sim->n_nodes];
	memset(node, 0, sizeof(*node));
	node->addr = addr;
	node->n_elements = n_elements;
	for (i = 0; i < n_elements; i++) {
		node->elems[i].addr = (uint16_t)(addr + i);
		node->elems[i].models = node->models[i];
		node->elems[i].n_models = 0;
	}
	memcpy(node->netkey, sim->netkey, 16);
	if (mesh_k2(node->netkey, k2_p_managed, sizeof(k2_p_managed),
	    &node->nid, node->enckey, node->privkey) != 0)
		return (NULL);
	node->primary_net_idx = 0;
	if (mesh_sim_add_appkey(node, 0, 0, sim->appkey) != 0)
		return (NULL);
	mesh_iv_init(&node->iv, sim->iv_index, sim->now);
	node->seq = 0;
	mesh_rpl_init(&node->rpl, node->rpl_store, MESH_SIM_RPL_SIZE);
	mesh_kr_init(&node->kr);
	node->sim = sim;
	node->index = sim->n_nodes;
	sim->n_nodes++;
	return (node);
}

int
mesh_sim_add_model(struct mesh_node *node, uint8_t elem_index,
    struct mesh_model model)
{
	struct mesh_element *el;

	if (node == NULL || elem_index >= node->n_elements)
		return (-1);
	el = &node->elems[elem_index];
	/* Sized for complete SIG application-model compositions. */
	if (el->n_models >= MESH_SIM_MAX_MODELS)
		return (-1);
	node->models[elem_index][el->n_models] = model;
	el->n_models++;
	return (0);
}

int
mesh_sim_set_devkey(struct mesh_node *node, const uint8_t devkey[16],
    mesh_sim_devkey_rx_fn rx, void *arg)
{

	if (node == NULL || devkey == NULL)
		return (-1);
	memcpy(node->devkey, devkey, sizeof(node->devkey));
	node->have_devkey = 1;
	node->devkey_rx = rx;
	node->devkey_rx_arg = arg;
	return (0);
}

int
mesh_sim_set_devkey_client(struct mesh_node *node,
    mesh_sim_devkey_lookup_fn lookup, mesh_sim_devkey_upper_rx_fn rx, void *arg)
{

	if (node == NULL || lookup == NULL || rx == NULL)
		return (-1);
	node->devkey_lookup = lookup;
	node->devkey_upper_rx = rx;
	node->devkey_client_arg = arg;
	return (0);
}

int
mesh_sim_subscribe(struct mesh_node *node, uint16_t group)
{
	uint8_t i;

	if (node == NULL)
		return (-1);
	for (i = 0; i < node->n_elements; i++)
		if (node->elem_n_subs[i] >= MESH_SIM_MAX_SUBS)
			return (-1);
	for (i = 0; i < node->n_elements; i++)
		(void)mesh_sim_subscribe_element(node, i, group);
	return (0);
}

int
mesh_sim_subscribe_element(struct mesh_node *node, uint8_t elem_index,
    uint16_t group)
{
	size_t i;

	if (node == NULL || elem_index >= node->n_elements)
		return (-1);
	for (i = 0; i < node->elem_n_subs[elem_index]; i++)
		if (node->elem_subs[elem_index][i] == group)
			return (0);
	if (node->elem_n_subs[elem_index] >= MESH_SIM_MAX_SUBS)
		return (-1);
	node->elem_subs[elem_index][node->elem_n_subs[elem_index]++] = group;
	node->elems[elem_index].subs = node->elem_subs[elem_index];
	node->elems[elem_index].n_subs = node->elem_n_subs[elem_index];
	return (0);
}

int
mesh_sim_subscribe_virtual_element(struct mesh_node *node, uint8_t elem_index,
    const uint8_t label[MESH_LABEL_UUID_LEN])
{
	size_t i;

	if (node == NULL || label == NULL || elem_index >= node->n_elements)
		return (-1);
	for (i = 0; i < node->elem_n_labels[elem_index]; i++)
		if (memcmp(node->elem_labels[elem_index][i], label,
		    MESH_LABEL_UUID_LEN) == 0)
			return (0);
	if (node->elem_n_labels[elem_index] >= MESH_SIM_MAX_SUBS)
		return (-1);
	memcpy(node->elem_labels[elem_index][node->elem_n_labels[elem_index]++],
	    label, MESH_LABEL_UUID_LEN);
	node->elems[elem_index].labels = node->elem_labels[elem_index];
	node->elems[elem_index].n_labels = node->elem_n_labels[elem_index];
	return (0);
}

void
mesh_sim_clear_subscriptions(struct mesh_node *node, uint8_t elem_index)
{

	if (node == NULL || elem_index >= node->n_elements)
		return;
	node->elem_n_subs[elem_index] = 0;
	node->elem_n_labels[elem_index] = 0;
	node->elems[elem_index].subs = node->elem_subs[elem_index];
	node->elems[elem_index].n_subs = 0;
	node->elems[elem_index].labels = node->elem_labels[elem_index];
	node->elems[elem_index].n_labels = 0;
}

int
mesh_sim_link(struct mesh_sim *sim, struct mesh_node *a, struct mesh_node *b)
{

	if (sim == NULL || a == NULL || b == NULL || a == b)
		return (-1);
	sim->use_topology = 1;
	sim->linked[a->index][b->index] = 1;
	sim->linked[b->index][a->index] = 1;
	return (0);
}

void
mesh_sim_set_relay(struct mesh_node *node, int enabled)
{

	if (node == NULL)
		return;
	node->is_relay = enabled ? 1 : 0;
	node->relay.enabled = enabled ? 1 : 0;
}

int
mesh_sim_set_friend(struct mesh_node *node, uint16_t lpn_addr,
    uint8_t lpn_elements, size_t qcap)
{

	if (node == NULL || lpn_elements == 0)
		return (-1);
	node->is_friend = 1;
	node->friend_lpn = lpn_addr;
	mesh_fq_init(&node->fq, lpn_addr, lpn_elements, qcap);
	return (0);
}

int
mesh_sim_set_lpn(struct mesh_node *node, uint16_t friend_addr,
    uint32_t poll_timeout)
{

	if (node == NULL)
		return (-1);
	if (mesh_lpn_init(&node->lpn, poll_timeout, 0) != 0)
		return (-1);
	node->is_lpn = 1;
	node->awake = 0;
	node->lpn_friend = friend_addr;
	return (0);
}

int
mesh_sim_establish_friendship(struct mesh_sim *sim, struct mesh_node *friend,
    struct mesh_node *lpn, uint16_t net_idx, uint16_t lpn_counter,
    uint16_t friend_counter)
{
	struct mesh_sim_subnet_key *friend_subnet, *lpn_subnet;
	const uint8_t *friend_key, *lpn_key;
	uint8_t nid[1];

	if (sim == NULL || friend == NULL || lpn == NULL)
		return (-1);
	if (!friend->is_friend || !lpn->is_lpn)
		return (-1);
	if (net_idx == friend->primary_net_idx)
		friend_key = friend->netkey;
	else {
		friend_subnet = find_subnet(friend, net_idx);
		if (friend_subnet == NULL)
			return (-1);
		friend_key = friend_subnet->netkey;
	}
	if (net_idx == lpn->primary_net_idx)
		lpn_key = lpn->netkey;
	else {
		lpn_subnet = find_subnet(lpn, net_idx);
		if (lpn_subnet == NULL)
			return (-1);
		lpn_key = lpn_subnet->netkey;
	}
	if (timingsafe_bcmp(friend_key, lpn_key, 16) != 0)
		return (-1);
	/*
	 * Both endpoints derive the SAME friendship credential from the subnet
	 * NetKey and the exchanged addresses/counters (Section 3.6.6.2).
	 */
	if (mesh_friend_credentials(friend_key, lpn->addr, friend->addr,
	    lpn_counter, friend_counter, nid, friend->friend_enckey,
	    friend->friend_privkey) != 0)
		return (-1);
	friend->friend_nid = nid[0];
	friend->have_friend_cred = 1;
	friend->friend_net_idx = net_idx;
	friend->fc_lpn_addr = lpn->addr;
	friend->fc_friend_addr = friend->addr;
	friend->fc_lpn_counter = lpn_counter;
	friend->fc_friend_counter = friend_counter;
	if (mesh_friend_credentials(lpn_key, lpn->addr, friend->addr,
	    lpn_counter, friend_counter, nid, lpn->friend_enckey,
	    lpn->friend_privkey) != 0)
		return (-1);
	lpn->friend_nid = nid[0];
	lpn->have_friend_cred = 1;
	lpn->friend_net_idx = net_idx;
	lpn->fc_lpn_addr = lpn->addr;
	lpn->fc_friend_addr = friend->addr;
	lpn->fc_lpn_counter = lpn_counter;
	lpn->fc_friend_counter = friend_counter;
	mesh_lpn_established(&lpn->lpn);
	return (0);
}

int
mesh_sim_add_subnet(struct mesh_node *node, uint16_t net_idx,
    const uint8_t netkey[16])
{
	struct mesh_sim_subnet_key *subnet;
	size_t i;

	if (node == NULL || netkey == NULL || net_idx > 0x0fff)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (timingsafe_bcmp(node->netkey, netkey, 16) == 0 ? 0 : -1);
	for (i = 0; i < node->n_subnets; i++) {
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (timingsafe_bcmp(node->subnets[i].netkey, netkey, 16) == 0 ?
			    0 : -1);
	}
	if (node->n_subnets >= MESH_SIM_MAX_SUBNETS - 1)
		return (-1);
	subnet = &node->subnets[node->n_subnets];
	memset(subnet, 0, sizeof(*subnet));
	subnet->valid = 1;
	subnet->net_idx = net_idx;
	mesh_kr_init(&subnet->kr);
	memcpy(subnet->netkey, netkey, 16);
	if (mesh_k2(subnet->netkey, k2_p_managed, sizeof(k2_p_managed),
	    &subnet->nid, subnet->enckey, subnet->privkey) != 0) {
		memset(subnet, 0, sizeof(*subnet));
		return (-1);
	}
	node->n_subnets++;
	return (0);
}

int
mesh_sim_add_appkey(struct mesh_node *node, uint16_t net_idx,
    uint16_t app_idx, const uint8_t appkey[16])
{
	struct mesh_sim_app_key *entry;
	size_t i;
	int have_subnet;

	if (node == NULL || appkey == NULL || net_idx > 0x0fff ||
	    app_idx > 0x0fff)
		return (-1);
	have_subnet = net_idx == node->primary_net_idx;
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			have_subnet = 1;
	if (!have_subnet)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++) {
		entry = &node->appkeys[i];
		if (entry->valid && entry->app_idx == app_idx) {
			if (entry->net_idx != net_idx)
				return (-1);
			memcpy(entry->key, appkey, 16);
			return (mesh_k4(entry->key, &entry->aid));
		}
	}
	if (node->n_appkeys >= MESH_SIM_MAX_APPKEYS)
		return (-1);
	entry = &node->appkeys[node->n_appkeys];
	memset(entry, 0, sizeof(*entry));
	entry->valid = 1;
	entry->net_idx = net_idx;
	entry->app_idx = app_idx;
	memcpy(entry->key, appkey, 16);
	if (mesh_k4(entry->key, &entry->aid) != 0) {
		memset(entry, 0, sizeof(*entry));
		return (-1);
	}
	node->n_appkeys++;
	return (0);
}

int
mesh_sim_remove_appkey(struct mesh_node *node, uint16_t app_idx)
{
	size_t i;

	if (node == NULL)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++) {
		if (!node->appkeys[i].valid || node->appkeys[i].app_idx != app_idx)
			continue;
		memmove(&node->appkeys[i], &node->appkeys[i + 1],
		    (node->n_appkeys - i - 1) * sizeof(node->appkeys[0]));
		node->n_appkeys--;
		memset(&node->appkeys[node->n_appkeys], 0,
		    sizeof(node->appkeys[0]));
		return (0);
	}
	return (-1);
}

int
mesh_sim_remove_subnet(struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL || net_idx == node->primary_net_idx)
		return (-1);
	for (i = node->n_appkeys; i > 0; i--)
		if (node->appkeys[i - 1].valid &&
		    node->appkeys[i - 1].net_idx == net_idx)
			(void)mesh_sim_remove_appkey(node,
			    node->appkeys[i - 1].app_idx);
	for (i = 0; i < node->n_subnets; i++) {
		if (!node->subnets[i].valid || node->subnets[i].net_idx != net_idx)
			continue;
		memmove(&node->subnets[i], &node->subnets[i + 1],
		    (node->n_subnets - i - 1) * sizeof(node->subnets[0]));
		node->n_subnets--;
		memset(&node->subnets[node->n_subnets], 0,
		    sizeof(node->subnets[0]));
		return (0);
	}
	return (-1);
}

void
mesh_sim_set_proxy(struct mesh_node *node)
{

	if (node == NULL)
		return;
	node->is_proxy = 1;
	mesh_proxy_filter_init(&node->pfilter);
}

int
mesh_sim_proxy_apply_config(struct mesh_node *node, const uint8_t *secured_pdu,
    size_t len)
{
	struct mesh_proxy_cfg cfg;
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	uint32_t iv;

	if (node == NULL || secured_pdu == NULL || !node->is_proxy)
		return (-1);
	iv = mesh_iv_tx_index(&node->iv);
	if (mesh_proxy_cfg_decrypt(node->enckey, node->privkey, node->nid, iv,
	    secured_pdu, len, NULL, NULL, msg, sizeof(msg), &msglen) != 0)
		return (-1);
	if (mesh_proxy_cfg_parse(msg, msglen, &cfg) != 0)
		return (-1);
	switch (cfg.opcode) {
	case MESH_PROXY_OP_SET_FILTER_TYPE:
		return (mesh_proxy_filter_set_type(&node->pfilter,
		    cfg.filter_type));
	case MESH_PROXY_OP_ADD_ADDR:
		return (mesh_proxy_filter_add(&node->pfilter, cfg.addrs,
		    cfg.naddr));
	case MESH_PROXY_OP_REMOVE_ADDR:
		return (mesh_proxy_filter_remove(&node->pfilter, cfg.addrs,
		    cfg.naddr));
	default:
		return (-1);
	}
}

int
mesh_sim_proxy_gatt_in(struct mesh_sim *sim, struct mesh_node *proxy,
    const uint8_t *net_pdu, size_t len)
{

	if (sim == NULL || proxy == NULL || net_pdu == NULL || !proxy->is_proxy ||
	    len == 0 || len > MESH_NET_MAX_PDU)
		return (-1);
	/*
	 * MshPRT_v1.1 Section 6.7: the Proxy Server both relays the PDU onto the
	 * advertising bearer (reinject) and hands it to its own network layer.
	 * mesh_sim_step() skips delivery back to the transmitting node, so a PDU
	 * addressed to the proxy (or a group it subscribes to) would never be
	 * delivered locally; deliver it here.
	 */
	node_recv_net(sim, proxy, net_pdu, len, -1);
	return (mesh_sim_reinject(sim, proxy->index, net_pdu, len));
}

/* ================================================================
 * Transmit path.
 * ================================================================ */

/*
 * Originate an access message secured with explicit network (nid/enc/priv) and
 * application (appkey/aid) material.  node_originate() below wraps this with the
 * node's primary-subnet (Key-Refresh-aware) credential; the secondary-subnet
 * originator supplies the netkey2/appkey2 credential instead.
 */
static int
node_originate_ex(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t src_addr, uint16_t dst, uint32_t opcode, const uint8_t *params,
    size_t plen, uint8_t ttl, uint8_t nid, const uint8_t *enc,
    const uint8_t *priv, const uint8_t *appkey, uint8_t aid,
    const uint8_t *label)
{
	uint8_t apdu[MESH_ACCESS_PAYLOAD_MAX];
	uint8_t upper[SIM_UPPER_MAX];
	struct mesh_net_pdu np;
	uint32_t iv, seq0;
	size_t apdu_len, upper_len;
	uint16_t va;

	if (mesh_addr_is_virtual(dst)) {
		if (label == NULL || mesh_virtual_addr(label, &va) != 0 || va != dst)
			return (-1);
	} else if (label != NULL)
		return (-1);
	if (mesh_access_pdu_build(opcode, params, plen, apdu, &apdu_len) != 0)
		return (-1);
	seq0 = node->seq;
	iv = mesh_iv_tx_index(&node->iv);
	if (seq0 > MESH_IV_SEQ_MAX)
		return (-1);
	if (mesh_upper_encrypt(appkey, 1, 0, seq0, src_addr, dst, iv,
	    label, apdu, apdu_len, upper, &upper_len) != 0)
		return (-1);

	if (upper_len <= MESH_NET_MAX_TRANSPORT_PDU - 1) {
		/* Unsegmented access Lower Transport PDU. */
		struct mesh_lower lt;
		uint8_t lt_bytes[MESH_LOWER_DATA_MAX];
		size_t lt_len;

		memset(&lt, 0, sizeof(lt));
		lt.seg = 0;
		lt.ctl = 0;
		lt.akf = 1;
		lt.aid = aid;
		memcpy(lt.data, upper, upper_len);
		lt.data_len = upper_len;
		if (mesh_lower_build(&lt, lt_bytes, &lt_len) != 0)
			return (-1);
		memset(&np, 0, sizeof(np));
		np.nid = nid;
		np.ctl = 0;
		np.ttl = ttl;
		np.seq = seq0;
		np.src = src_addr;
		np.dst = dst;
		memcpy(np.transport, lt_bytes, lt_len);
		np.transport_len = lt_len;
		if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
			return (-1);
		node->seq++;
		return (0);
	} else {
		/* Segmented access. */
		struct mesh_seg segs[MESH_SEG_MAX];
		size_t nseg, i, first;
		uint16_t seqzero = (uint16_t)(seq0 & 0x1fff);

		if (mesh_sar_segment(1, aid, 0, seqzero, upper, upper_len,
		    segs, MESH_SEG_MAX, &nseg) != 0)
			return (-1);
		if (nseg - 1 > MESH_IV_SEQ_MAX - seq0 ||
		    nseg > MESH_SIM_MAX_TX - sim->n_tx)
			return (-1);
		first = sim->n_tx;
		for (i = 0; i < nseg; i++) {
			memset(&np, 0, sizeof(np));
			np.nid = nid;
			np.ctl = 0;
			np.ttl = ttl;
			np.seq = seq0 + (uint32_t)i;
			np.src = src_addr;
			np.dst = dst;
			memcpy(np.transport, segs[i].bytes, segs[i].len);
			np.transport_len = segs[i].len;
			if (enqueue_net(sim, node->index, nid, enc, priv, iv,
			    &np) != 0)
				return (-1);
		}
		sar_tx_record(sim, node, first, nseg, dst, seqzero);
		node->seq += (uint32_t)nseg;
		return (0);
	}
}

static int
node_originate(struct mesh_sim *sim, struct mesh_node *node, uint16_t src_addr,
    uint16_t dst, uint32_t opcode, const uint8_t *params, size_t plen,
    uint8_t ttl)
{
	uint8_t nid;
	const uint8_t *enc, *priv;

	node_tx_netsec(node, &nid, &enc, &priv);
	if (node->n_appkeys == 0)
		return (-1);
	return (node_originate_ex(sim, node, src_addr, dst, opcode, params, plen,
	    ttl, nid, enc, priv, node->appkeys[0].key, node->appkeys[0].aid,
	    NULL));
}

static int
node_tx_control(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    const uint8_t *lt, size_t lt_len, uint8_t ttl, int friend_cred)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	/*
	 * The friendship credential is reserved for actual Friend<->LPN traffic
	 * (e.g. the LPN's Friend Poll): only such PDUs (friend_cred) may use it
	 * (Section 3.6.6.2).  Every other control PDU (e.g. a Segment Ack to a
	 * third party) uses the managed-flooding subnet credential.
	 */
	if (friend_cred && node->have_friend_cred) {
		nid = node->friend_nid;
		enc = node->friend_enckey;
		priv = node->friend_privkey;
	} else
		node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	if (node->seq > MESH_IV_SEQ_MAX)
		return (-1);
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = 1;
	np.ttl = ttl;
	np.seq = node->seq;
	np.src = node->addr;
	np.dst = dst;
	memcpy(np.transport, lt, lt_len);
	np.transport_len = lt_len;
	if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
		return (-1);
	node->seq++;
	return (0);
}

static struct mesh_sim_reasm *
reasm_session(struct mesh_sim *sim, struct mesh_node *node, uint16_t src,
    uint32_t seqauth, uint32_t iv, int ctl)
{
	struct mesh_sim_reasm *free_slot = NULL;
	size_t i;

	for (i = 0; i < MESH_SIM_REASM; i++) {
		struct mesh_sim_reasm *s = &node->reasm[i];

		if (s->used && sim->now_ms >= s->deadline_ms)
			s->used = 0;
		if (s->used && s->r.src == src && s->seqauth == seqauth &&
		    s->iv_index == iv && s->ctl == ctl)
			return (s);
		if (!s->used && free_slot == NULL)
			free_slot = s;
	}
	return (free_slot);
}

static void
send_seg_ack(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint16_t seqzero, uint32_t blockack, uint8_t ttl)
{
	struct mesh_seg_ack ack;
	uint8_t lt[MESH_SEG_ACK_LEN];
	size_t len;

	if (!mesh_addr_is_unicast(dst))
		return;
	memset(&ack, 0, sizeof(ack));
	ack.seqzero = seqzero;
	ack.blockack = blockack;
	if (mesh_seg_ack_build(&ack, lt, &len) == 0)
		(void)node_tx_control(sim, node, dst, lt, len, ttl, 0);
}

int
mesh_sim_send_access(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t ttl)
{

	if (sim == NULL || node == NULL)
		return (-1);
	return (node_originate(sim, node, node->addr, dst, opcode, params,
	    plen, ttl));
}

int
mesh_sim_send_upper(struct mesh_sim *sim, struct mesh_node *node, uint16_t dst,
    uint32_t seq0, const uint8_t *upper, size_t upper_len, int akf, uint8_t aid,
    uint8_t ttl)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	if (sim == NULL || node == NULL || upper == NULL || upper_len == 0 ||
	    upper_len > SIM_UPPER_MAX)
		return (-1);
	node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	if (seq0 > MESH_IV_SEQ_MAX)
		return (-1);

	if (upper_len <= MESH_NET_MAX_TRANSPORT_PDU - 1) {
		/* Unsegmented Lower Transport PDU. */
		struct mesh_lower lt;
		uint8_t lt_bytes[MESH_LOWER_DATA_MAX];
		size_t lt_len;

		memset(&lt, 0, sizeof(lt));
		lt.seg = 0;
		lt.ctl = 0;
		lt.akf = akf ? 1 : 0;
		lt.aid = aid;
		memcpy(lt.data, upper, upper_len);
		lt.data_len = upper_len;
		if (mesh_lower_build(&lt, lt_bytes, &lt_len) != 0)
			return (-1);
		memset(&np, 0, sizeof(np));
		np.nid = nid;
		np.ctl = 0;
		np.ttl = ttl;
		np.seq = seq0;
		np.src = node->addr;
		np.dst = dst;
		memcpy(np.transport, lt_bytes, lt_len);
		np.transport_len = lt_len;
		if (enqueue_net(sim, node->index, nid, enc, priv, iv, &np) != 0)
			return (-1);
		return (1);
	} else {
		/* Segmented access. */
		struct mesh_seg segs[MESH_SEG_MAX];
		size_t nseg, i, first;
		uint16_t seqzero = (uint16_t)(seq0 & 0x1fff);

		if (mesh_sar_segment(akf ? 1 : 0, aid, 0, seqzero, upper,
		    upper_len, segs, MESH_SEG_MAX, &nseg) != 0)
			return (-1);
		if (nseg - 1 > MESH_IV_SEQ_MAX - seq0 ||
		    nseg > MESH_SIM_MAX_TX - sim->n_tx)
			return (-1);
		first = sim->n_tx;
		for (i = 0; i < nseg; i++) {
			memset(&np, 0, sizeof(np));
			np.nid = nid;
			np.ctl = 0;
			np.ttl = ttl;
			np.seq = seq0 + (uint32_t)i;
			np.src = node->addr;
			np.dst = dst;
			memcpy(np.transport, segs[i].bytes, segs[i].len);
			np.transport_len = segs[i].len;
			if (enqueue_net(sim, node->index, nid, enc, priv, iv,
			    &np) != 0)
				return (-1);
		}
		sar_tx_record(sim, node, first, nseg, dst, seqzero);
		return ((int)nseg);
	}
}

int
mesh_sim_send_access_key(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t net_idx, uint16_t app_idx, uint16_t dst, uint32_t opcode,
    const uint8_t *params, size_t plen, uint8_t ttl)
{

	if (node == NULL)
		return (-1);
	return (mesh_sim_send_access_key_from(sim, node, node->addr, net_idx,
	    app_idx, dst, opcode, params, plen, ttl));
}

int
mesh_sim_send_access_key_from(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t src, uint16_t net_idx, uint16_t app_idx, uint16_t dst,
    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t ttl)
{
	const struct mesh_sim_subnet_key *subnet = NULL;
	const struct mesh_sim_app_key *appkey = NULL;
	size_t i;

	if (sim == NULL || node == NULL || src < node->addr ||
	    (uint32_t)src >= (uint32_t)node->addr + node->n_elements)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++)
		if (node->appkeys[i].valid && node->appkeys[i].app_idx == app_idx &&
		    node->appkeys[i].net_idx == net_idx)
			appkey = &node->appkeys[i];
	if (appkey == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx && node->have_new_key &&
	    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, node->new_nid, node->new_enckey,
		    node->new_privkey, appkey->key, appkey->aid, NULL));
	if (net_idx == node->primary_net_idx)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, node->nid, node->enckey, node->privkey,
		    appkey->key, appkey->aid, NULL));
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			subnet = &node->subnets[i];
	if (subnet == NULL)
		return (-1);
	if (subnet->have_new_key &&
	    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW)
		return (node_originate_ex(sim, node, src, dst, opcode,
		    params, plen, ttl, subnet->new_nid, subnet->new_enckey,
		    subnet->new_privkey, appkey->key, appkey->aid, NULL));
	return (node_originate_ex(sim, node, src, dst, opcode, params,
	    plen, ttl, subnet->nid, subnet->enckey, subnet->privkey,
	    appkey->key, appkey->aid, NULL));
}

int
mesh_sim_send_access_key_from_virtual(struct mesh_sim *sim,
    struct mesh_node *node, uint16_t src, uint16_t net_idx, uint16_t app_idx,
    const uint8_t label[MESH_LABEL_UUID_LEN], uint32_t opcode,
    const uint8_t *params, size_t plen, uint8_t ttl)
{
	const struct mesh_sim_subnet_key *subnet = NULL;
	const struct mesh_sim_app_key *appkey = NULL;
	const uint8_t *nidp, *enc, *priv;
	uint16_t dst;
	size_t i;
	uint8_t nid;

	if (sim == NULL || node == NULL || label == NULL ||
	    src < node->addr ||
	    (uint32_t)src >= (uint32_t)node->addr + node->n_elements ||
	    mesh_virtual_addr(label, &dst) != 0)
		return (-1);
	for (i = 0; i < node->n_appkeys; i++)
		if (node->appkeys[i].valid && node->appkeys[i].app_idx == app_idx &&
		    node->appkeys[i].net_idx == net_idx)
			appkey = &node->appkeys[i];
	if (appkey == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx) {
		if (node->have_new_key &&
		    mesh_kr_tx_key(&node->kr) == MESH_KR_KEY_NEW) {
			nid = node->new_nid; enc = node->new_enckey;
			priv = node->new_privkey;
		} else {
			nid = node->nid; enc = node->enckey; priv = node->privkey;
		}
	} else {
		for (i = 0; i < node->n_subnets; i++)
			if (node->subnets[i].valid &&
			    node->subnets[i].net_idx == net_idx)
				subnet = &node->subnets[i];
		if (subnet == NULL)
			return (-1);
		if (subnet->have_new_key &&
		    mesh_kr_tx_key(&subnet->kr) == MESH_KR_KEY_NEW) {
			nid = subnet->new_nid; enc = subnet->new_enckey;
			priv = subnet->new_privkey;
		} else {
			nid = subnet->nid; enc = subnet->enckey;
			priv = subnet->privkey;
		}
	}
	nidp = &nid;
	return (node_originate_ex(sim, node, src, dst, opcode, params, plen,
	    ttl, *nidp, enc, priv, appkey->key, appkey->aid, label));
}

/* ================================================================
 * Receive path.
 * ================================================================ */

/*
 * Attempt to decrypt a received PDU under the node's key/IV candidates.
 * On success fills *out, records the IV used and, via the enc/priv/nid out-
 * pointers, the
 * key material that verified (so a relay can re-secure with the same subnet
 * credential).  Returns 0 on success, -1 if no candidate authenticated.
 */
static int
try_decrypt(struct mesh_node *node, const uint8_t *bytes, size_t len,
    struct mesh_net_pdu *out, uint32_t *iv_used, uint8_t *nid_used,
    const uint8_t **enc_used, const uint8_t **priv_used,
    uint16_t *net_idx_used)
{
	struct {
		uint8_t		nid;
		const uint8_t	*enc;
		const uint8_t	*priv;
		uint16_t	net_idx;
	} cand[MESH_SIM_MAX_SUBNETS * 2 + 1];
	uint32_t ivs[2];
	int n_iv, i, c, ncand;
	size_t si;

	ivs[0] = node->iv.iv_index;
	n_iv = 1;
	if (node->iv.iv_index > 0) {
		ivs[1] = node->iv.iv_index - 1;
		n_iv = 2;
	}

	/*
	 * Assemble the network-credential candidates this node will try, in the
	 * MshPRT_v1.1 Section 3.4.6.3 NID-candidate sense: the primary subnet
	 * (Key-Refresh old/new), the friendship credential, and any secondary
	 * subnet.  AppKey/AID selection is intentionally deferred until after
	 * network authentication because a subnet can bind multiple AppKeys.
	 */
	ncand = 0;
	if (mesh_kr_rx_accept_old(&node->kr)) {
		cand[ncand].nid = node->nid;
		cand[ncand].enc = node->enckey;
		cand[ncand].priv = node->privkey;
		cand[ncand].net_idx = node->primary_net_idx;
		ncand++;
	}
	if (node->have_new_key && mesh_kr_rx_accept_new(&node->kr)) {
		cand[ncand].nid = node->new_nid;
		cand[ncand].enc = node->new_enckey;
		cand[ncand].priv = node->new_privkey;
		cand[ncand].net_idx = node->primary_net_idx;
		ncand++;
	}
	if (node->have_friend_cred) {
		cand[ncand].nid = node->friend_nid;
		cand[ncand].enc = node->friend_enckey;
		cand[ncand].priv = node->friend_privkey;
		cand[ncand].net_idx = node->friend_net_idx;
		ncand++;
	}
	for (si = 0; si < node->n_subnets; si++) {
		if (!node->subnets[si].valid)
			continue;
		if (mesh_kr_rx_accept_old(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].nid;
			cand[ncand].enc = node->subnets[si].enckey;
			cand[ncand].priv = node->subnets[si].privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			ncand++;
		}
		if (node->subnets[si].have_new_key &&
		    mesh_kr_rx_accept_new(&node->subnets[si].kr)) {
			cand[ncand].nid = node->subnets[si].new_nid;
			cand[ncand].enc = node->subnets[si].new_enckey;
			cand[ncand].priv = node->subnets[si].new_privkey;
			cand[ncand].net_idx = node->subnets[si].net_idx;
			ncand++;
		}
	}

	for (c = 0; c < ncand; c++) {
		if (!mesh_net_nid_match(cand[c].nid, bytes[0]))
			continue;
		for (i = 0; i < n_iv; i++) {
			if (mesh_net_decrypt(cand[c].enc, cand[c].priv,
			    cand[c].nid, ivs[i], bytes, len, out) == 0) {
				*iv_used = ivs[i];
				*nid_used = cand[c].nid;
				*enc_used = cand[c].enc;
				*priv_used = cand[c].priv;
				*net_idx_used = cand[c].net_idx;
				return (0);
			}
		}
	}
	return (-1);
}

static void
node_deliver_access(struct mesh_sim *sim, struct mesh_node *node, uint16_t src,
    uint16_t dst, uint32_t seqauth, int szmic, int akf, uint8_t aid,
    const uint8_t *upper, size_t upper_len, uint32_t iv, uint16_t net_idx)
{
	uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
	struct mesh_access_pdu ap;
	struct mesh_model_reply reply;
	size_t access_len, ei, i, li;
	uint16_t rx_app_idx = UINT16_MAX;
	int opened = 0;

	if (akf == 0) {
		uint8_t reply_access[MESH_ACCESS_PAYLOAD_MAX];
		uint8_t reply_upper[SIM_UPPER_MAX];
		uint8_t remote_key[16];
		size_t reply_len = 0, reply_upper_len;
		uint32_t reply_seq;
		int local_open, n, rc;

		if (dst != node->addr)
			return;
		local_open = node->have_devkey && node->devkey_rx != NULL &&
		    mesh_upper_decrypt(node->devkey, 0, szmic, seqauth, src, dst, iv,
		    NULL, upper, upper_len, access, &access_len) == 0;
		if (!local_open) {
			if (node->devkey_lookup == NULL || node->devkey_upper_rx == NULL ||
			    node->devkey_lookup(node->devkey_client_arg, src,
			    remote_key) != 0 ||
			    mesh_upper_decrypt(remote_key, 0, szmic, seqauth, src, dst,
			    iv, NULL, upper, upper_len, access, &access_len) != 0)
				return;
		}
		if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
			return;
		node->rx.valid = 1;
		node->rx.src = src;
		node->rx.dst = dst;
		node->rx.app_idx = UINT16_MAX;
		node->rx.opcode = ap.opcode;
		node->rx.params_len = ap.params_len;
		memcpy(node->rx.params, ap.params, ap.params_len);
		node->rx.count++;
		if (!local_open) {
			(void)node->devkey_upper_rx(node->devkey_client_arg, seqauth,
			    src, dst, upper, upper_len);
			explicit_bzero(remote_key, sizeof(remote_key));
			return;
		}
		rc = node->devkey_rx(node->devkey_rx_arg, src, dst, access,
		    access_len, reply_access, &reply_len);
		if (rc <= 0 || reply_len == 0 || reply_len > sizeof(reply_access))
			return;
		reply_seq = node->seq;
		if (mesh_upper_encrypt(node->devkey, 0, 0, reply_seq, node->addr,
		    src, iv, NULL, reply_access, reply_len, reply_upper,
		    &reply_upper_len) != 0)
			return;
		n = mesh_sim_send_upper(sim, node, src, reply_seq, reply_upper,
		    reply_upper_len, 0, 0, 5);
		if (n > 0)
			node->seq += (uint32_t)n;
		return;
	}
	if (akf != 1)
		return;
	for (i = 0; i < node->n_appkeys && !opened; i++) {
		if (!node->appkeys[i].valid || node->appkeys[i].net_idx != net_idx ||
		    node->appkeys[i].aid != aid)
			continue;
		if (!mesh_addr_is_virtual(dst)) {
			opened = mesh_upper_decrypt(node->appkeys[i].key, 1, szmic,
			    seqauth, src, dst, iv, NULL, upper, upper_len, access,
			    &access_len) == 0;
			if (opened)
				rx_app_idx = node->appkeys[i].app_idx;
			continue;
		}
		/*
		 * A virtual DST alone is insufficient: hash collisions are resolved
		 * by authenticating with each subscribed Label UUID as CCM AAD.
		 */
		for (ei = 0; ei < node->n_elements && !opened; ei++) {
			for (li = 0; li < node->elem_n_labels[ei]; li++) {
				uint16_t va;

				if (mesh_virtual_addr(node->elem_labels[ei][li], &va) != 0 ||
				    va != dst)
					continue;
				if (mesh_upper_decrypt(node->appkeys[i].key, 1, szmic,
				    seqauth, src, dst, iv, node->elem_labels[ei][li],
				    upper, upper_len, access, &access_len) == 0) {
					opened = 1;
					rx_app_idx = node->appkeys[i].app_idx;
					break;
				}
			}
		}
	}
	if (!opened)
		return;
	if (mesh_access_pdu_parse(access, access_len, &ap) != 0)
		return;

	/* Capture the delivered access message (test hook). */
	node->rx.valid = 1;
	node->rx.src = src;
	node->rx.dst = dst;
	node->rx.app_idx = rx_app_idx;
	node->rx.opcode = ap.opcode;
	node->rx.params_len = ap.params_len;
	memcpy(node->rx.params, ap.params, ap.params_len);
	node->rx.count++;

	memset(&reply, 0, sizeof(reply));
	(void)mesh_access_dispatch_key_at(node->elems, node->n_elements, src, dst,
	    rx_app_idx, access, access_len, &reply, sim_now_ms(sim));
	if (reply.have_reply)
		(void)node_originate(sim, node, reply.src, reply.dst, reply.opcode,
		    reply.params, reply.params_len, 5);
}

/* ================================================================
 * Directed Forwarding and Heartbeat receive-side helpers.
 * ================================================================ */

/* Send a locally originated Transport Control PDU (opcode || params). */
static int
node_tx_df(struct mesh_sim *sim, struct mesh_node *node, int to_node,
    uint16_t dst, uint8_t opcode, const uint8_t *params, size_t plen,
    uint8_t ttl)
{
	struct mesh_net_pdu np;
	uint8_t nid;
	const uint8_t *enc, *priv;
	uint32_t iv;

	if (plen + 1 > sizeof(np.transport))
		return (-1);
	if (node->seq > MESH_IV_SEQ_MAX)
		return (-1);
	node_tx_netsec(node, &nid, &enc, &priv);
	iv = mesh_iv_tx_index(&node->iv);
	memset(&np, 0, sizeof(np));
	np.nid = nid;
	np.ctl = 1;
	np.ttl = ttl;
	np.seq = node->seq;
	np.src = node->addr;
	np.dst = dst;
	np.transport[0] = (uint8_t)(opcode & 0x7f);
	memcpy(np.transport + 1, params, plen);
	np.transport_len = plen + 1;
	if (enqueue_net_to(sim, node->index, to_node, nid, enc, priv, iv,
	    &np) != 0)
		return (-1);
	node->seq++;
	return (0);
}

/* Find a forwarding-table entry by its (Path Origin, Path Target) key. */
static struct mesh_df_fwd_entry *
df_find(struct mesh_df_fwd_table *t, uint16_t origin, uint16_t target)
{
	size_t i;

	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		if (t->entries[i].valid &&
		    t->entries[i].path_origin == origin &&
		    t->entries[i].path_target == target)
			return (&t->entries[i]);
	}
	return (NULL);
}

static int
df_dep_has(const uint16_t *deps, size_t n, uint16_t addr)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (deps[i] == addr)
			return (1);
	}
	return (0);
}

/*
 * Handle a Directed Forwarding path-discovery control PDU (Path Request /
 * Reply / Confirmation, MshPRT_v1.1 Section 3.6.6.5).  Returns 1 if the PDU was
 * a path-discovery opcode consumed here, 0 if it is some other control PDU that
 * the caller should keep processing.  prev_hop is the adjacent node the PDU was
 * heard from - the bearer recorded in the Forwarding Table.
 */
static int
df_handle_control(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_net_pdu *pdu, int prev_hop, int seen, uint32_t iv,
    uint8_t nid, const uint8_t *enc, const uint8_t *priv)
{
	uint8_t op = (uint8_t)(pdu->transport[0] & 0x7f);
	const uint8_t *params = pdu->transport + 1;
	size_t plen = (pdu->transport_len > 0) ? pdu->transport_len - 1 : 0;
	uint64_t now = sim_now_ms(sim);

	switch (op) {
	case MESH_DF_OP_PATH_REQUEST: {
		struct mesh_df_path_request req;
		uint64_t lifetime;

		if (seen)
			return (1);	/* already processed and re-flooded */
		if (mesh_df_path_request_parse(params, plen, &req) != 0)
			return (1);
		lifetime = mesh_df_lifetime_ms[req.lifetime & 0x03];
		if (local_unicast(node, req.destination)) {
			/* Path Target: install the reverse entry and reply. */
			struct mesh_df_path_reply rep;
			uint8_t rp[MESH_ACCESS_PAYLOAD_MAX];
			size_t rl;

			(void)mesh_df_table_add(&node->df_table,
			    req.origin.range_start, req.destination,
			    req.forwarding_number, (uint8_t)prev_hop, 0, lifetime,
			    now);
			memset(&rep, 0, sizeof(rep));
			rep.confirmation_request = 1;
			rep.forwarding_number = req.forwarding_number;
			rep.path_origin = req.origin.range_start;
			rep.target.range_start = node->addr;
			rep.target.range_length = node->n_elements;
			if (mesh_df_path_reply_build(&rep, rp, &rl) == 0)
				(void)node_tx_df(sim, node, prev_hop,
				    req.origin.range_start, MESH_DF_OP_PATH_REPLY,
				    rp, rl, pdu->ttl);
			return (1);
		}
		/* Intermediate: install the reverse entry and re-flood. */
		(void)mesh_df_table_add(&node->df_table, req.origin.range_start,
		    req.destination, req.forwarding_number, (uint8_t)prev_hop, 0,
		    lifetime, now);
		if (pdu->ttl >= 2) {
			struct mesh_net_pdu rp = *pdu;

			rp.ttl = (uint8_t)(pdu->ttl - 1);
			if (enqueue_net_to(sim, node->index, -1, nid, enc, priv,
			    iv, &rp) == 0)
				node->relay_count++;
		}
		return (1);
	}
	case MESH_DF_OP_PATH_REPLY: {
		struct mesh_df_path_reply rep;
		struct mesh_df_fwd_entry *e;

		if (mesh_df_path_reply_parse(params, plen, &rep) != 0)
			return (1);
		if (local_unicast(node, rep.path_origin)) {
			/* Path Origin: accept the reply, confirm the path. */
			int need_confirm = 0;

			if (mesh_df_discovery_on_reply(&node->df_disc, &rep,
			    &need_confirm) != 1)
				return (1);
			(void)mesh_df_table_add(&node->df_table, node->addr,
			    rep.target.range_start, rep.forwarding_number, 0,
			    (uint8_t)prev_hop,
			    mesh_df_lifetime_ms[node->df_disc.lifetime & 0x03],
			    now);
			if (need_confirm) {
				struct mesh_df_path_confirmation cf;
				uint8_t cb[8];
				size_t cl;

				if (mesh_df_discovery_confirm(&node->df_disc,
				    &cf) == 0 &&
				    mesh_df_path_confirmation_build(&cf, cb,
				    &cl) == 0)
					(void)node_tx_df(sim, node, prev_hop,
					    rep.target.range_start,
					    MESH_DF_OP_PATH_CONFIRMATION, cb, cl,
					    pdu->ttl);
			}
			return (1);
		}
		if (seen)
			return (1);
		/* Intermediate: complete the entry and forward toward origin. */
		e = df_find(&node->df_table, rep.path_origin,
		    rep.target.range_start);
		if (e != NULL) {
			e->bearer_toward_target = (uint8_t)prev_hop;
			if (pdu->ttl >= 2) {
				struct mesh_net_pdu fp = *pdu;

				fp.ttl = (uint8_t)(pdu->ttl - 1);
				(void)enqueue_net_to(sim, node->index,
				    e->bearer_toward_origin, nid, enc, priv, iv,
				    &fp);
			}
		}
		return (1);
	}
	case MESH_DF_OP_PATH_CONFIRMATION: {
		struct mesh_df_path_confirmation cf;
		struct mesh_df_fwd_entry *e;

		if (mesh_df_path_confirmation_parse(params, plen, &cf) != 0)
			return (1);
		e = df_find(&node->df_table, cf.path_origin, cf.path_target);
		if (e != NULL)
			e->backward_validated = 1;
		if (local_unicast(node, cf.path_target))
			return (1);	/* reached the Path Target */
		if (seen)
			return (1);
		if (e != NULL && pdu->ttl >= 2) {
			struct mesh_net_pdu fp = *pdu;

			fp.ttl = (uint8_t)(pdu->ttl - 1);
			(void)enqueue_net_to(sim, node->index,
			    e->bearer_toward_target, nid, enc, priv, iv, &fp);
		}
		return (1);
	}
	default:
		return (0);
	}
}

static void
node_recv_net(struct mesh_sim *sim, struct mesh_node *node,
    const uint8_t *bytes, size_t len, int prev_hop)
{
	struct mesh_net_pdu pdu;
	uint32_t iv;
	uint16_t net_idx;
	uint8_t nid;
	const uint8_t *enc, *priv;
	int seen;

	sim->delivered++;
	if (try_decrypt(node, bytes, len, &pdu, &iv, &nid, &enc, &priv,
	    &net_idx) != 0)
		return;
	if (local_unicast(node, pdu.src))	/* our own message looped back */
		return;

	seen = nmc_seen_record(node, pdu.src, pdu.seq, iv);	/* M-N1 */

	/*
	 * Proxy (GATT bearer) forward, MshPRT_v1.1 Section 6.4/6.7: a proxy
	 * forwards a Network PDU to its GATT client only when the destination
	 * passes the proxy filter.  Count it once per distinct PDU (not per
	 * relay copy).
	 */
	if (node->is_proxy && !seen &&
	    mesh_proxy_filter_accepts(&node->pfilter, pdu.dst)) {
		node->proxy_fwd_count++;
		node->proxy_last_fwd_dst = pdu.dst;
	}

	/*
	 * Directed Forwarding path-discovery control PDUs (Path Request / Reply
	 * / Confirmation) are consumed by the DF machinery; they establish the
	 * Forwarding Table and are not delivered to models (Section 3.6.6.5).
	 */
	if (node->df_enabled && pdu.ctl == 1 &&
	    df_handle_control(sim, node, &pdu, prev_hop, seen, iv, nid, enc,
	    priv))
		return;

	/*
	 * Forwarding.  A DF node routes along an established path when one
	 * matches (delivered only to the next-hop bearer), otherwise falls back
	 * to managed flooding (Section 3.6.6).  A plain node uses the Relay
	 * feature.  Duplicates (seen) are never re-forwarded.
	 */
	if (node->df_enabled && !seen && !local_unicast(node, pdu.dst)) {
		enum mesh_df_forward v;
		struct mesh_df_fwd_entry *m = NULL;
		uint8_t new_ttl;

		v = mesh_df_forward_decide(&node->df_table, &node->df_feat,
		    pdu.src, pdu.dst, pdu.ttl, &new_ttl, sim_now_ms(sim), &m);
		if (v == MESH_DF_FORWARD_DIRECTED && m != NULL) {
			struct mesh_net_pdu rp = pdu;
			int bearer;

			rp.ttl = new_ttl;
			if (pdu.dst == m->path_target ||
			    df_dep_has(m->dep_target, m->dep_target_n, pdu.dst))
				bearer = m->bearer_toward_target;
			else
				bearer = m->bearer_toward_origin;
			/*
			 * A half-installed entry may carry MESH_DF_BEARER_NONE
			 * (0) for the selected direction.  Bearer 0 also aliases
			 * node index 0, so unicasting there would blackhole the
			 * PDU; fall back to managed flooding instead (consistent
			 * with mesh_df_forward_decide()).
			 */
			if (bearer == MESH_DF_BEARER_NONE) {
				if (enqueue_relay(sim, node, nid, enc, priv, iv,
				    &rp) == 0)
					node->relay_count++;
			} else if (enqueue_net_to(sim, node->index, bearer, nid,
			    enc, priv, iv, &rp) == 0) {
				node->relay_count++;
				node->df_directed_fwd++;
			}
		} else if (v == MESH_DF_FORWARD_FLOOD) {
			struct mesh_net_pdu rp = pdu;

			rp.ttl = new_ttl;
			if (enqueue_relay(sim, node, nid, enc, priv, iv,
			    &rp) == 0)
				node->relay_count++;
		}
	} else if (!node->df_enabled && node->is_relay) {
		uint8_t new_ttl;
		int dst_local = local_unicast(node, pdu.dst);

		if (mesh_relay_decide(&node->relay, pdu.ttl, seen, dst_local,
		    &new_ttl)) {
			struct mesh_net_pdu rp = pdu;

			rp.ttl = new_ttl;
			if (enqueue_relay(sim, node, nid, enc, priv, iv,
			    &rp) == 0)
				node->relay_count++;
		}
	}

	/* Friend feature: store an access message destined for our LPN. */
	if (node->is_friend && pdu.ctl == 0) {
		uint16_t base = node->fq.lpn_addr;
		uint16_t top = (uint16_t)(base + node->fq.num_elements - 1);
		int for_lpn = (pdu.dst >= base && pdu.dst <= top) ||
		    mesh_friend_sub_contains(&node->fq.sub, pdu.dst);

		if (for_lpn) {
			struct mesh_fq_entry e;

			memset(&e, 0, sizeof(e));
			e.ctl = pdu.ctl;
			e.ttl = pdu.ttl;
			e.seq = pdu.seq;
			e.src = pdu.src;
			e.dst = pdu.dst;
			if (pdu.transport_len <= MESH_FQ_PDU_MAX) {
				memcpy(e.pdu, pdu.transport, pdu.transport_len);
				e.pdu_len = pdu.transport_len;
				(void)mesh_fq_enqueue(&node->fq, &e);
			}
		}
	}

	/* A sleeping Low Power node's radio is off. */
	if (node->is_lpn && !node->awake)
		return;
	if (!addressed_here(node, pdu.dst))
		return;

	/* Capture the TTL of the PDU as delivered (per-hop decrement proof). */
	node->rx.ttl = pdu.ttl;

	if (pdu.ctl == 0) {
		struct mesh_lower lower;

		if (mesh_lower_parse(0, pdu.transport, pdu.transport_len,
		    &lower) != 0)
			return;
		if (lower.seg == 0) {
			/* Unsegmented messages use their Network SEQ directly. */
			if (mesh_rpl_check(&node->rpl, pdu.src, iv,
			    pdu.seq) != 1)
				return;
			node_deliver_access(sim, node, pdu.src, pdu.dst,
			    pdu.seq, 0, lower.akf, lower.aid, lower.data,
			    lower.data_len, iv, net_idx);
		} else {
			struct mesh_sim_reasm *sess;
			uint8_t up[SIM_UPPER_MAX];
			size_t up_len;
			uint32_t seqauth, maxseq;
			int r;

			/*
			 * SeqAuth is the sequence number of segment zero.  Every
			 * segment in a transaction must encode the same SeqAuth via
			 * (Network SEQ - SegO) and SeqZero.  Check underflow as well as
			 * the 13-bit relationship before touching SAR/RPL state.
			 */
			/*
			 * MshPRT_v1.1 Section 3.5.3.1: SeqAuth is derived from
			 * SeqZero, not from (SEQ - SegO).  A compliant peer may
			 * (re)transmit any segment with any SEQ in the window
			 * [SeqAuth, SeqAuth + 8191], so reconstruct the upper
			 * SEQ bits and borrow one 0x2000 block if SeqZero maps
			 * above this segment's SEQ.
			 */
			seqauth = (pdu.seq & ~(uint32_t)0x1fff) | lower.seqzero;
			if (seqauth > pdu.seq)
				seqauth -= 0x2000;
			if (seqauth > 0xffffff - lower.segn)
				return;

			sess = reasm_session(sim, node, pdu.src, seqauth, iv, 0);
			if (sess == NULL)
				return;
			if (!sess->used) {
				/*
				 * Replay protection is evaluated once for the segmented
				 * transaction, at its SeqAuth.  Subsequent unseen segments
				 * in the active transaction may arrive in any order and must
				 * not be rejected merely because their individual Network
				 * SEQ is below a segment already received.
				 */
				if (mesh_rpl_check(&node->rpl, pdu.src, iv,
				    seqauth) != 1)
					return;
				mesh_reasm_init(&sess->r);
				sess->seqauth = seqauth;
				sess->iv_index = iv;
				sess->dst = pdu.dst;
				sess->szmic = lower.szmic;
				sess->ctl = 0;
				sess->complete = 0;
				sess->deadline_ms = sim->now_ms +
				    SIM_SAR_DISCARD_MS;
				sess->used = 1;
			} else if (sess->complete) {
				/*
				 * C4-L4: a retransmitted segment for an
				 * already-completed SeqAuth.  MshPRT 3.5.3.4
				 * requires re-sending the (complete) block ack
				 * rather than silently dropping it; do not
				 * re-run RPL/reassembly or re-deliver.
				 */
				sess->deadline_ms = sim->now_ms +
				    SIM_SAR_DISCARD_MS;
				if (local_unicast(node, pdu.dst))
					send_seg_ack(sim, node, pdu.src,
					    lower.seqzero, sess->r.blockack,
					    SIM_DEFAULT_TTL);
				return;
			} else if (sess->dst != pdu.dst ||
			    sess->szmic != lower.szmic ||
			    sess->r.akf != lower.akf || sess->r.aid != lower.aid) {
				/* Header fields are invariant across one segmented PDU. */
				return;
			}
			r = mesh_reasm_input(&sess->r, pdu.src, pdu.transport,
			    pdu.transport_len);
			if (r < 0)
				return;
			sess->deadline_ms = sim->now_ms + SIM_SAR_DISCARD_MS;
			/*
			 * MshPRT_v1.1 Section 3.5.3.4: acknowledge only a
			 * segmented message addressed to a unicast address of
			 * this node - never a group/virtual DST - and send the
			 * ack with a fresh default TTL rather than the residual
			 * (already decremented) received TTL.
			 */
			if (local_unicast(node, pdu.dst))
				send_seg_ack(sim, node, pdu.src, lower.seqzero,
				    sess->r.blockack, SIM_DEFAULT_TTL);
			if (r == 1) {
				/* Advance the persistent RPL past every SEQ consumed by
				 * this transaction.  If a newer message already advanced
				 * it, leave that newer value intact. */
				maxseq = sess->seqauth + sess->r.segn;
				(void)mesh_rpl_check(&node->rpl, pdu.src, iv, maxseq);
				if (mesh_reasm_get(&sess->r, up, &up_len) == 0)
					node_deliver_access(sim, node, pdu.src,
					    pdu.dst, sess->seqauth, sess->szmic,
					    lower.akf, lower.aid, up, up_len, iv,
					    net_idx);
				/*
				 * C4-L4: keep the session so a retransmitted
				 * segment is re-acked (handled above) until the
				 * SAR discard deadline reaps it.
				 */
				sess->complete = 1;
			}
		}
	} else {
		struct mesh_lower lower;
		const uint8_t *ctlp = pdu.transport;
		size_t ctl_len = pdu.transport_len;
		uint8_t ctlbuf[SIM_UPPER_MAX + 1];
		uint8_t op;

		if (mesh_lower_parse(1, pdu.transport, pdu.transport_len,
		    &lower) != 0)
			return;
		if (lower.seg) {
			struct mesh_sim_reasm *sess;
			uint32_t seqauth, maxseq;
			size_t data_len;
			int r;

			/*
			 * MshPRT_v1.1 Section 3.5.3.1: SeqAuth is derived from
			 * SeqZero, not from (SEQ - SegO).  A compliant peer may
			 * (re)transmit any segment with any SEQ in the window
			 * [SeqAuth, SeqAuth + 8191], so reconstruct the upper
			 * SEQ bits and borrow one 0x2000 block if SeqZero maps
			 * above this segment's SEQ.
			 */
			seqauth = (pdu.seq & ~(uint32_t)0x1fff) | lower.seqzero;
			if (seqauth > pdu.seq)
				seqauth -= 0x2000;
			if (seqauth > 0xffffff - lower.segn)
				return;
			sess = reasm_session(sim, node, pdu.src, seqauth, iv, 1);
			if (sess == NULL)
				return;
			if (!sess->used) {
				if (mesh_rpl_check(&node->rpl, pdu.src, iv,
				    seqauth) != 1)
					return;
				mesh_reasm_init(&sess->r);
				sess->seqauth = seqauth;
				sess->iv_index = iv;
				sess->dst = pdu.dst;
				sess->ctl = 1;
				sess->complete = 0;
				sess->deadline_ms = sim->now_ms +
				    SIM_SAR_DISCARD_MS;
				sess->used = 1;
			} else if (sess->complete) {
				/* C4-L4: re-ack a retransmit of a completed
				 * SeqAuth (MshPRT 3.5.3.4); no re-delivery. */
				sess->deadline_ms = sim->now_ms +
				    SIM_SAR_DISCARD_MS;
				if (local_unicast(node, pdu.dst))
					send_seg_ack(sim, node, pdu.src,
					    lower.seqzero, sess->r.blockack,
					    SIM_DEFAULT_TTL);
				return;
			} else if (sess->dst != pdu.dst ||
			    sess->r.opcode != lower.opcode)
				return;
			r = mesh_reasm_input_ctl(&sess->r, pdu.src, 1,
			    pdu.transport, pdu.transport_len);
			if (r < 0)
				return;
			sess->deadline_ms = sim->now_ms + SIM_SAR_DISCARD_MS;
			/*
			 * MshPRT_v1.1 Section 3.5.3.4: acknowledge only a
			 * segmented message addressed to a unicast address of
			 * this node - never a group/virtual DST - and send the
			 * ack with a fresh default TTL rather than the residual
			 * (already decremented) received TTL.
			 */
			if (local_unicast(node, pdu.dst))
				send_seg_ack(sim, node, pdu.src, lower.seqzero,
				    sess->r.blockack, SIM_DEFAULT_TTL);
			if (r == 0)
				return;
			maxseq = sess->seqauth + sess->r.segn;
			(void)mesh_rpl_check(&node->rpl, pdu.src, iv, maxseq);
			ctlbuf[0] = sess->r.opcode;
			if (mesh_reasm_get(&sess->r, ctlbuf + 1, &data_len) != 0) {
				sess->used = 0;
				return;
			}
			ctlp = ctlbuf;
			ctl_len = data_len + 1;
			/* C4-L4: retain for retransmit re-ack (as above). */
			sess->complete = 1;
		} else if (mesh_rpl_check(&node->rpl, pdu.src, iv,
		    pdu.seq) != 1)
			return;

		op = (uint8_t)(ctlp[0] & 0x7f);
		if (op == 0x00) {
			struct mesh_seg_ack ack;
			size_t i;

			if (mesh_seg_ack_parse(ctlp, ctl_len, &ack) != 0)
				return;
			for (i = 0; i < MESH_SIM_SAR_TX; i++) {
				struct mesh_sim_sar_tx *s = &node->sar_tx[i];

				if (!s->used || s->dst != pdu.src ||
				    s->seqzero != ack.seqzero)
					continue;
				s->blockack |= ack.blockack &
				    mesh_blockack_full(s->segn);
				sar_tx_requeue_missing(sim, s);
				break;
			}
			return;
		}

		/*
		 * Heartbeat subscription (MshMDL_v1.1 Section 4.4.1.2.19): count a
		 * received Heartbeat and fold in its hop count.  The received
		 * network TTL is RxTTL; hops = InitTTL - RxTTL + 1.  RPL has
		 * already collapsed the relayed copies to the first (shortest-path)
		 * arrival, so the count advances once per publication.
		 */
		if (op == MESH_HB_CTL_OPCODE && node->hb_sub_active) {
			struct mesh_hb_msg hm;

			if (mesh_hb_ctl_pdu_parse(ctlp, ctl_len, &hm) == 0)
				(void)mesh_hb_sub_receive(&node->hb_sub, pdu.src,
				    pdu.dst, hm.init_ttl, pdu.ttl);
		}

		if (op == MESH_FRIEND_OP_POLL && node->is_friend &&
		    node->have_friend_cred && pdu.src == node->friend_lpn) {
			struct mesh_friend_poll poll;
			struct mesh_fq_entry out;

			if (mesh_friend_poll_parse(ctlp, ctl_len, &poll) != 0)
				return;
			if (mesh_fq_poll(&node->fq, poll.fsn, NULL, &out) == 1) {
				struct mesh_net_pdu dp;
				uint8_t tnid;
				const uint8_t *tenc, *tpriv;

				/* MshPRT §3.6.6.2: established friendship
				 * security material is mandatory for delivery. */
				tnid = node->friend_nid;
				tenc = node->friend_enckey;
				tpriv = node->friend_privkey;
				memset(&dp, 0, sizeof(dp));
				dp.nid = tnid;
				dp.ctl = out.ctl;
				dp.ttl = out.ttl;
				dp.seq = out.seq;
				dp.src = out.src;
				dp.dst = out.dst;
				memcpy(dp.transport, out.pdu, out.pdu_len);
				dp.transport_len = out.pdu_len;
				(void)enqueue_net(sim, node->index, tnid, tenc,
				    tpriv, mesh_iv_tx_index(&node->iv), &dp);
			}
		}
	}
}

/* ================================================================
 * Stepping the medium.
 * ================================================================ */

int
mesh_sim_step(struct mesh_sim *sim)
{
	struct mesh_sim_tx snap[MESH_SIM_MAX_TX];
	size_t cnt, i;
	int j;

	if (sim == NULL || sim->n_tx == 0)
		return (0);
	cnt = sim->n_tx;
	memcpy(snap, sim->tx, cnt * sizeof(snap[0]));
	sim->n_tx = 0;

	for (i = 0; i < cnt; i++) {
		if (!snap[i].valid)
			continue;
		for (j = 0; j < sim->n_nodes; j++) {
			if (j == snap[i].tx_node)
				continue;
			if (snap[i].to_node >= 0 && snap[i].to_node != j)
				continue;	/* directed forward: one hop only */
			if (sim->use_topology &&
			    !sim->linked[snap[i].tx_node][j])
				continue;
			node_recv_net(sim, &sim->nodes[j], snap[i].bytes,
			    snap[i].len, snap[i].tx_node);
		}
	}
	return ((int)cnt);
}

int
mesh_sim_run(struct mesh_sim *sim, int max_steps)
{
	int steps = 0;

	if (sim == NULL)
		return (0);
	while (sim->n_tx != 0 && steps < max_steps) {
		(void)mesh_sim_step(sim);
		steps++;
	}
	return (steps);
}

int
mesh_sim_reinject(struct mesh_sim *sim, int tx_node, const uint8_t *bytes,
    size_t len)
{
	struct mesh_sim_tx *slot;

	if (sim == NULL || bytes == NULL || len == 0 || len > MESH_NET_MAX_PDU)
		return (-1);
	if (sim->n_tx >= MESH_SIM_MAX_TX)
		return (-1);
	slot = &sim->tx[sim->n_tx++];
	memcpy(slot->bytes, bytes, len);
	slot->len = len;
	slot->tx_node = tx_node;
	slot->to_node = -1;
	slot->valid = 1;
	return (0);
}

int
mesh_sim_lpn_poll(struct mesh_sim *sim, struct mesh_node *lpn)
{
	struct mesh_friend_poll poll;
	uint8_t lt[MESH_FRIEND_POLL_LEN];
	size_t lt_len;
	uint32_t before;

	if (sim == NULL || lpn == NULL || !lpn->is_lpn ||
	    !lpn->have_friend_cred)
		return (-1);
	before = lpn->rx.count;
	lpn->awake = 1;
	poll.fsn = (uint8_t)mesh_lpn_poll_fsn(&lpn->lpn);
	if (mesh_friend_poll_build(&poll, lt, &lt_len) != 0) {
		lpn->awake = 0;
		return (-1);
	}
	if (node_tx_control(sim, lpn, lpn->lpn_friend, lt, lt_len, 0, 1) != 0) {
		lpn->awake = 0;
		return (-1);
	}
	(void)mesh_sim_run(sim, 8);
	/*
	 * Only toggle the Friend Sequence Number when the Friend actually
	 * responded (a queued message was delivered).  Advancing the FSN after a
	 * lost/empty response would make the next Poll's changed FSN look like an
	 * ack to mesh_fq_poll() and drop the still-undelivered head.
	 */
	if (lpn->rx.count > before)
		(void)mesh_lpn_on_response(&lpn->lpn, 0, sim->now * 1000);
	lpn->awake = 0;
	return (lpn->rx.count > before ? 1 : 0);
}

/* ================================================================
 * Beacons, IV Update and Key Refresh.
 * ================================================================ */

void
mesh_sim_advance(struct mesh_sim *sim, uint64_t dt_secs)
{

	mesh_sim_advance_ms(sim, dt_secs * 1000);
}

void
mesh_sim_advance_ms(struct mesh_sim *sim, uint64_t dt_ms)
{
	int i, j;

	if (sim == NULL)
		return;
	sim->now_ms += dt_ms;
	sim->now = sim->now_ms / 1000;
	for (i = 0; i < MESH_SIM_RELAY_TX; i++) {
		while (mesh_relay_tx_due(&sim->retransmit[i].timer,
		    sim->now_ms)) {
			if (sim->n_tx >= MESH_SIM_MAX_TX)
				break;
			sim->tx[sim->n_tx++] = sim->retransmit[i].pdu;
			(void)mesh_relay_tx_fire(&sim->retransmit[i].timer,
			    sim->now_ms);
		}
	}
	for (i = 0; i < sim->n_nodes; i++) {
		mesh_access_tick(sim->nodes[i].elems,
		    sim->nodes[i].n_elements, sim_now_ms(sim));
		for (j = 0; j < MESH_SIM_REASM; j++)
			if (sim->nodes[i].reasm[j].used && sim->now_ms >=
			    sim->nodes[i].reasm[j].deadline_ms)
				sim->nodes[i].reasm[j].used = 0;
		for (j = 0; j < MESH_SIM_SAR_TX; j++)
			if (sim->nodes[i].sar_tx[j].used && sim->now_ms >=
			    sim->nodes[i].sar_tx[j].deadline_ms)
				sar_tx_requeue_missing(sim,
				    &sim->nodes[i].sar_tx[j]);
	}
}

int
mesh_sim_send_beacon(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t net_idx)
{
	uint8_t beacon[MESH_SECURE_BEACON_LEN];
	const uint8_t *bkey;
	struct mesh_sim_subnet_key *subnet;
	size_t blen;
	int kr_flag, iv_update, j, phase, have_new;
	uint32_t iv_index;

	if (sim == NULL || node == NULL)
		return (-1);
	iv_update = (node->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ? 1 : 0;
	iv_index = node->iv.iv_index;
	subnet = NULL;
	if (net_idx == node->primary_net_idx) {
		phase = mesh_kr_phase(&node->kr);
		have_new = node->have_new_key;
		/*
		 * C4-M2: Phase-1 nodes must still beacon with the OLD key
		 * (MshPRT 3.11.4); new-key beacons begin at Phase 2.  Beaconing
		 * the new key in Phase 1 (with the Phase-1 KR=0 flag) is the
		 * Phase-3 signal and would collapse receivers straight to
		 * Phase 3, revoking the old key mid-distribution.
		 */
		bkey = have_new && phase >= MESH_KR_PHASE_2 ?
		    node->new_netkey : node->netkey;
		kr_flag = have_new ? mesh_kr_beacon_flag(&node->kr) : 0;
	} else {
		subnet = find_subnet(node, net_idx);
		if (subnet == NULL)
			return (-1);
		phase = mesh_kr_phase(&subnet->kr);
		have_new = subnet->have_new_key;
		/* C4-M2: subnet mirror of the primary fix above. */
		bkey = have_new && phase >= MESH_KR_PHASE_2 ?
		    subnet->new_netkey : subnet->netkey;
		kr_flag = have_new ? mesh_kr_beacon_flag(&subnet->kr) : 0;
	}
	if (mesh_secure_beacon_build(bkey, (uint8_t)kr_flag,
	    (uint8_t)iv_update, iv_index, beacon, &blen) != 0)
		return (-1);

	for (j = 0; j < sim->n_nodes; j++) {
		struct mesh_node *m = &sim->nodes[j];

		if (m == node)
			continue;
		(void)mesh_sim_node_recv_beacon(m, beacon, blen, sim->now, NULL);
	}
	return (0);
}

int
mesh_sim_node_recv_beacon(struct mesh_node *node, const uint8_t *beacon,
    size_t len, uint64_t now, uint16_t *net_idx)
{
	struct mesh_secure_beacon sb;
	struct mesh_sim_subnet_key *subnet;
	int before;
	size_t i;

	if (node == NULL || beacon == NULL)
		return (-1);
	/*
	 * A beacon secured with the node's current key carries the IV state
		 * only; the Key Refresh phase advance (Section 3.11.4) is driven by
	 * the beacon secured with the NEW key.
	 */
	if (mesh_secure_beacon_parse(node->netkey, beacon, len, &sb) == 0) {
		(void)mesh_iv_recv_beacon(&node->iv, sb.iv_index, sb.iv_update,
		    now);
		if (net_idx != NULL)
			*net_idx = node->primary_net_idx;
		return (0);
	}
	if (node->have_new_key &&
	    mesh_secure_beacon_parse(node->new_netkey, beacon, len, &sb) == 0) {
		(void)mesh_iv_recv_beacon(&node->iv, sb.iv_index, sb.iv_update,
		    now);
		before = mesh_kr_phase(&node->kr);
		(void)mesh_kr_beacon(&node->kr, sb.key_refresh);
		/*
		 * Entering Phase 3 revokes the old key immediately: promote the new
		 * key so the node returns to Normal Operation with only that key.
		 */
		if (before != MESH_KR_PHASE_3 &&
		    mesh_kr_phase(&node->kr) == MESH_KR_PHASE_3)
			(void)mesh_sim_key_refresh_finalize(node);
		if (net_idx != NULL)
			*net_idx = node->primary_net_idx;
		return (0);
	}
	for (i = 0; i < node->n_subnets; i++) {
		subnet = &node->subnets[i];
		if (!subnet->valid)
			continue;
		if (mesh_secure_beacon_parse(subnet->netkey, beacon, len,
		    &sb) == 0) {
			(void)mesh_iv_recv_beacon(&node->iv, sb.iv_index,
			    sb.iv_update, now);
			if (net_idx != NULL)
				*net_idx = subnet->net_idx;
			return (0);
		}
		if (!subnet->have_new_key ||
		    mesh_secure_beacon_parse(subnet->new_netkey, beacon, len,
		    &sb) != 0)
			continue;
		(void)mesh_iv_recv_beacon(&node->iv, sb.iv_index, sb.iv_update,
		    now);
		before = mesh_kr_phase(&subnet->kr);
		(void)mesh_kr_beacon(&subnet->kr, sb.key_refresh);
		if (before != MESH_KR_PHASE_3 &&
		    mesh_kr_phase(&subnet->kr) == MESH_KR_PHASE_3)
			(void)mesh_sim_subnet_key_refresh_finalize(node,
			    subnet->net_idx);
		if (net_idx != NULL)
			*net_idx = subnet->net_idx;
		return (0);
	}
	return (-1);
}

int
mesh_sim_begin_iv_update(struct mesh_node *node)
{

	if (node == NULL)
		return (-1);
	return (mesh_iv_begin_update(&node->iv, node->sim->now) ==
	    MESH_IV_STARTED ? 0 : -1);
}

int
mesh_sim_complete_iv_update(struct mesh_node *node)
{

	if (node == NULL)
		return (-1);
	return (mesh_iv_complete_update(&node->iv, node->sim->now) ==
	    MESH_IV_COMPLETED ? 0 : -1);
}

int
mesh_sim_begin_key_refresh(struct mesh_node *node, const uint8_t new_netkey[16])
{

	if (node == NULL || new_netkey == NULL)
		return (-1);
	memcpy(node->new_netkey, new_netkey, 16);
	if (mesh_k2(node->new_netkey, k2_p_managed, sizeof(k2_p_managed),
	    &node->new_nid, node->new_enckey, node->new_privkey) != 0)
		return (-1);
	node->have_new_key = 1;
	if (mesh_kr_begin(&node->kr) != 0)
		return (-1);
	return (0);
}

int
mesh_sim_key_refresh_advance(struct mesh_node *node)
{

	if (node == NULL || !node->have_new_key)
		return (-1);
	/* Phase 1 -> Phase 2: the node starts transmitting with the new key. */
	if (mesh_kr_beacon(&node->kr, 1) < 0)
		return (-1);
	return (0);
}

int
mesh_sim_key_refresh_finalize(struct mesh_node *node)
{
	uint8_t nid[1];

	if (node == NULL || !node->have_new_key)
		return (-1);
	/* Promote the new managed-flooding credential to the sole current key. */
	memcpy(node->netkey, node->new_netkey, 16);
	node->nid = node->new_nid;
	memcpy(node->enckey, node->new_enckey, 16);
	memcpy(node->privkey, node->new_privkey, 16);
	/*
	 * Re-derive any friendship credential from the promoted NetKey
	 * (Section 3.6.4.2): friendship security is bound to the subnet key, so
	 * a refresh that did not re-derive it would silently break the LPN link.
	 */
	if (node->have_friend_cred &&
	    node->friend_net_idx == node->primary_net_idx) {
		if (mesh_friend_credentials(node->netkey, node->fc_lpn_addr,
		    node->fc_friend_addr, node->fc_lpn_counter,
		    node->fc_friend_counter, nid, node->friend_enckey,
		    node->friend_privkey) != 0)
			return (-1);
		node->friend_nid = nid[0];
	}
	/* Reset the phase machine and scrub the (now promoted) new-key slot. */
	mesh_kr_init(&node->kr);
	node->have_new_key = 0;
	explicit_bzero(node->new_netkey, sizeof(node->new_netkey));
	node->new_nid = 0;
	explicit_bzero(node->new_enckey, sizeof(node->new_enckey));
	explicit_bzero(node->new_privkey, sizeof(node->new_privkey));
	return (0);
}

static struct mesh_sim_subnet_key *
find_subnet(struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL)
		return (NULL);
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (&node->subnets[i]);
	return (NULL);
}

int
mesh_sim_subnet_key_refresh_begin(struct mesh_node *node, uint16_t net_idx,
    const uint8_t new_netkey[16])
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL || new_netkey == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_begin_key_refresh(node, new_netkey));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || subnet->have_new_key)
		return (-1);
	memcpy(subnet->new_netkey, new_netkey, 16);
	if (mesh_k2(subnet->new_netkey, k2_p_managed, sizeof(k2_p_managed),
	    &subnet->new_nid, subnet->new_enckey, subnet->new_privkey) != 0)
		return (-1);
	if (mesh_kr_begin(&subnet->kr) != 0)
		return (-1);
	subnet->have_new_key = 1;
	return (0);
}

int
mesh_sim_subnet_key_refresh_advance(struct mesh_node *node, uint16_t net_idx)
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_key_refresh_advance(node));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || !subnet->have_new_key)
		return (-1);
	return (mesh_kr_beacon(&subnet->kr, 1) < 0 ? -1 : 0);
}

int
mesh_sim_subnet_key_refresh_finalize(struct mesh_node *node, uint16_t net_idx)
{
	struct mesh_sim_subnet_key *subnet;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_sim_key_refresh_finalize(node));
	subnet = find_subnet(node, net_idx);
	if (subnet == NULL || !subnet->have_new_key)
		return (-1);
	memcpy(subnet->netkey, subnet->new_netkey, 16);
	subnet->nid = subnet->new_nid;
	memcpy(subnet->enckey, subnet->new_enckey, 16);
	memcpy(subnet->privkey, subnet->new_privkey, 16);
	if (node->have_friend_cred && node->friend_net_idx == net_idx) {
		uint8_t nid[1];

		if (mesh_friend_credentials(subnet->netkey, node->fc_lpn_addr,
		    node->fc_friend_addr, node->fc_lpn_counter,
		    node->fc_friend_counter, nid, node->friend_enckey,
		    node->friend_privkey) != 0)
			return (-1);
		node->friend_nid = nid[0];
	}
	mesh_kr_init(&subnet->kr);
	subnet->have_new_key = 0;
	explicit_bzero(subnet->new_netkey, sizeof(subnet->new_netkey));
	subnet->new_nid = 0;
	explicit_bzero(subnet->new_enckey, sizeof(subnet->new_enckey));
	explicit_bzero(subnet->new_privkey, sizeof(subnet->new_privkey));
	return (0);
}

int
mesh_sim_subnet_kr_phase(const struct mesh_node *node, uint16_t net_idx)
{
	size_t i;

	if (node == NULL)
		return (-1);
	if (net_idx == node->primary_net_idx)
		return (mesh_kr_phase(&node->kr));
	for (i = 0; i < node->n_subnets; i++)
		if (node->subnets[i].valid && node->subnets[i].net_idx == net_idx)
			return (mesh_kr_phase(&node->subnets[i].kr));
	return (-1);
}

/* ================================================================
 * Directed Forwarding.
 * ================================================================ */

void
mesh_sim_set_df(struct mesh_node *node, int managed_flood)
{

	if (node == NULL)
		return;
	node->df_enabled = 1;
	mesh_df_table_init(&node->df_table);
	node->df_feat.directed_relay = 1;
	node->df_feat.directed_proxy = 1;
	node->df_feat.directed_friend = 1;
	node->df_feat.managed_flood_relay = managed_flood ? 1 : 0;
	node->df_fn = 0;
}

int
mesh_sim_df_discover(struct mesh_sim *sim, struct mesh_node *origin,
    uint16_t target, uint8_t lifetime_sel)
{
	struct mesh_df_path_request req;
	uint8_t params[MESH_ACCESS_PAYLOAD_MAX];
	size_t plen;
	uint64_t now;

	if (sim == NULL || origin == NULL || !origin->df_enabled)
		return (-1);
	now = sim_now_ms(sim);
	/*
	 * Begin the Path Origin discovery (Section 3.6.6.5): a fresh Forwarding
	 * Number, one wanted lane, two-way path so the target confirms.  The
	 * built Path Request is flooded as a Transport Control PDU; DF relays
	 * install reverse entries and re-flood, the target replies along the
	 * reverse path, and the origin confirms - all pumped by mesh_sim_run.
	 */
	if (mesh_df_discovery_start(&origin->df_disc, origin->addr, target,
	    origin->df_fn, MESH_DF_METRIC_NODE_COUNT, lifetime_sel & 0x03, 1, 1,
	    30000, now, &req) != 0)
		return (-1);
	origin->df_fn = mesh_df_fn_next(origin->df_fn);
	if (mesh_df_path_request_build(&req, params, &plen) != 0)
		return (-1);
	if (node_tx_df(sim, origin, -1, MESH_ADDR_ALL_DF,
	    MESH_DF_OP_PATH_REQUEST, params, plen, 5) != 0)
		return (-1);
	(void)mesh_sim_run(sim, 32);
	return (origin->df_disc.state == MESH_DF_DISC_ESTABLISHED ? 0 : -1);
}

void
mesh_sim_df_expire(struct mesh_sim *sim)
{
	int j;

	if (sim == NULL)
		return;
	for (j = 0; j < sim->n_nodes; j++) {
		if (sim->nodes[j].df_enabled)
			(void)mesh_df_table_expire(&sim->nodes[j].df_table,
			    sim_now_ms(sim));
	}
}

/* ================================================================
 * Heartbeat.
 * ================================================================ */

void
mesh_sim_hb_set_pub(struct mesh_node *node, uint16_t dst, uint8_t count_log,
    uint8_t period_log, uint8_t ttl, uint16_t trigger_features,
    uint16_t cur_features)
{

	if (node == NULL)
		return;
	memset(&node->hb_pub, 0, sizeof(node->hb_pub));
	node->hb_pub.dst = dst;
	node->hb_pub.count_log = count_log;
	node->hb_pub.period_log = period_log;
	node->hb_pub.ttl = ttl;
	node->hb_pub.features = trigger_features;
	node->hb_features = cur_features;
	mesh_hb_pub_timer_init(&node->hb_timer, &node->hb_pub);
}

void
mesh_sim_hb_set_sub(struct mesh_node *node, uint16_t src, uint16_t dst,
    uint8_t period_log)
{
	struct mesh_hb_sub_set set;

	if (node == NULL)
		return;
	mesh_hb_sub_init(&node->hb_sub);
	set.src = src;
	set.dst = dst;
	set.period_log = period_log;
	/* apply returns 0 on success; the subscription is armed when it kept a
	 * source (a zero Source/Destination/PeriodLog leaves it disabled). */
	node->hb_sub_active = (mesh_hb_sub_apply(&node->hb_sub, &set) == 0 &&
	    node->hb_sub.src != 0 && node->hb_sub.dst != 0);
}

/* Originate a Heartbeat transport control message onto the medium (flooded). */
static int
node_hb_publish(struct mesh_sim *sim, struct mesh_node *node,
    const struct mesh_hb_msg *m)
{
	uint8_t body[3];
	size_t blen;

	if (node->hb_pub.dst == 0)
		return (-1);
	if (mesh_hb_msg_build(m, body, &blen) != 0)
		return (-1);
	return (node_tx_df(sim, node, -1, node->hb_pub.dst, MESH_HB_CTL_OPCODE,
	    body, blen, m->init_ttl));
}

int
mesh_sim_hb_feature_change(struct mesh_sim *sim, struct mesh_node *node,
    uint16_t new_features)
{
	struct mesh_hb_msg m;
	uint16_t old;
	int r;

	if (sim == NULL || node == NULL)
		return (-1);
	old = node->hb_features;
	node->hb_features = new_features;
	r = mesh_hb_pub_feature_change(&node->hb_pub, old, new_features, &m);
	if (r != 1)
		return (r == 0 ? 0 : -1);
	return (node_hb_publish(sim, node, &m) == 0 ? 1 : -1);
}

int
mesh_sim_hb_publish_periodic(struct mesh_sim *sim, struct mesh_node *node,
    uint32_t dt_secs)
{
	struct mesh_hb_msg m;
	int published = 0;

	if (sim == NULL || node == NULL)
		return (-1);
	/*
	 * Tick the publication timer one Period at a time so each crossed
	 * boundary emits a Heartbeat (MshMDL_v1.1 Section 4.2.18).
	 */
	while (mesh_hb_pub_timer_tick(&node->hb_timer, dt_secs,
	    node->hb_features, &m) == 1) {
		if (node_hb_publish(sim, node, &m) == 0)
			published++;
		dt_secs = 0;	/* drain any further boundaries at this instant */
		if (!mesh_hb_pub_timer_active(&node->hb_timer))
			break;
	}
	return (published);
}

/* ================================================================
 * Provisioning (PB-ADV) over the virtual bearer.
 * ================================================================ */

/* Drain a session's outbound Provisioning PDUs into that side's pending FIFO. */
static void
prov_drain_session(struct mesh_sim_prov *pv, int side)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len, slot;

	while (mesh_prov_session_poll(&pv->sess[side], pdu, &len) == 1) {
		slot = pv->fifo_tail[side] % MESH_SIM_PROV_FIFO;
		if ((pv->fifo_tail[side] - pv->fifo_head[side]) >=
		    MESH_SIM_PROV_FIFO)
			break;			/* FIFO full (never in practice) */
		memcpy(pv->fifo[side][slot], pdu, len);
		pv->fifo_len[side][slot] = len;
		pv->fifo_tail[side]++;
	}
}

int
mesh_sim_provision_begin(struct mesh_sim *sim, struct mesh_sim_prov *pv,
    const uint8_t dev_uuid[16], uint16_t assign_addr, uint8_t dev_elements)
{
	struct mesh_prov_data data;
	struct mesh_prov_caps caps;
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	size_t pktlen, acklen;
	int have_ack = 0;

	if (sim == NULL || pv == NULL || dev_uuid == NULL || dev_elements == 0)
		return (-1);
	memset(pv, 0, sizeof(*pv));
	pv->assigned_addr = assign_addr;
	pv->dev_elements = dev_elements;

	/* The Provisioner hands over the sim's subnet material. */
	memset(&data, 0, sizeof(data));
	memcpy(data.netkey, sim->netkey, 16);
	data.netkey_index = 0;
	data.flags = 0;
	data.iv_index = sim->iv_index;
	data.unicast_addr = assign_addr;

	memset(&caps, 0, sizeof(caps));
	caps.num_elements = dev_elements;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;

	if (mesh_prov_provisioner_init(&pv->sess[0], NULL, NULL, 0x00,
	    &data) != 0)
		return (-1);
	if (mesh_prov_device_init(&pv->sess[1], NULL, NULL, &caps) != 0) {
		mesh_prov_session_free(&pv->sess[0]);
		return (-1);
	}
	mesh_prov_link_init_provisioner(&pv->link[0], 0x0acce55e, dev_uuid,
	    1000, 8);
	mesh_prov_link_init_device(&pv->link[1], dev_uuid, 1000, 8);

	/* PB-ADV Link Open / Link Ack handshake (Section 5.3.1). */
	if (mesh_prov_link_open(&pv->link[0], pv->now_ms, pkt, &pktlen) != 0)
		return (-1);
	if (mesh_prov_link_recv(&pv->link[1], pkt, pktlen, pv->now_ms, NULL,
	    NULL, NULL, ack, &acklen, &have_ack) != 0 || !have_ack)
		return (-1);
	if (mesh_prov_link_recv(&pv->link[0], ack, acklen, pv->now_ms, NULL,
	    NULL, NULL, NULL, NULL, NULL) != 0)
		return (-1);
	if (!mesh_prov_link_is_open(&pv->link[0]) ||
	    !mesh_prov_link_is_open(&pv->link[1]))
		return (-1);

	/* Kick off the Provisioning PDU exchange with the Invite. */
	if (mesh_prov_session_start(&pv->sess[0]) != 0)
		return (-1);
	prov_drain_session(pv, 0);
	return (0);
}

int
mesh_sim_provision_run(struct mesh_sim *sim, struct mesh_sim_prov *pv,
    int max_iters)
{
	int iter, side;

	if (sim == NULL || pv == NULL)
		return (-1);
	for (iter = 0; iter < max_iters; iter++) {
		int progressed = 0;

		for (side = 0; side < 2; side++) {
			int other = side ^ 1;
			uint8_t pkt[MESH_PBADV_PKT_MAX];
			size_t pktlen;
			int rc;

			prov_drain_session(pv, side);
			/* Feed the next queued PDU when the link is idle. */
			if (mesh_prov_link_idle(&pv->link[side]) &&
			    pv->fifo_head[side] != pv->fifo_tail[side]) {
				size_t slot = pv->fifo_head[side] %
				    MESH_SIM_PROV_FIFO;

				if (mesh_prov_link_send(&pv->link[side],
				    pv->fifo[side][slot],
				    pv->fifo_len[side][slot], pv->now_ms) == 0) {
					pv->fifo_head[side]++;
					progressed = 1;
				}
			}
			/* Emit bearer packets and deliver them to the peer. */
			while ((rc = mesh_prov_link_poll(&pv->link[side],
			    pv->now_ms, pkt, &pktlen)) == 1) {
				uint8_t pdu[MESH_PROV_PDU_MAX];
				uint8_t ack[MESH_PBADV_PKT_MAX];
				size_t pl = 0, al = 0;
				int have_pdu = 0, have_ack = 0;

				(void)mesh_prov_link_recv(&pv->link[other], pkt,
				    pktlen, pv->now_ms, pdu, &pl, &have_pdu, ack,
				    &al, &have_ack);
				if (have_ack)
					(void)mesh_prov_link_recv(&pv->link[side],
					    ack, al, pv->now_ms, NULL, NULL, NULL,
					    NULL, NULL, NULL);
				if (have_pdu) {
					(void)mesh_prov_session_recv(
					    &pv->sess[other], pdu, pl);
					prov_drain_session(pv, other);
				}
				progressed = 1;
			}
			if (rc < 0)
				return (-1);
		}
		if ((mesh_prov_session_done(&pv->sess[0]) ||
		    mesh_prov_session_failed(&pv->sess[0])) &&
		    (mesh_prov_session_done(&pv->sess[1]) ||
		    mesh_prov_session_failed(&pv->sess[1])))
			break;
		if (!progressed)
			pv->now_ms += 1000;	/* trip the retransmission timers */
	}

	pv->failed = mesh_prov_session_failed(&pv->sess[0]) ||
	    mesh_prov_session_failed(&pv->sess[1]);
	pv->done = mesh_prov_session_done(&pv->sess[0]) &&
	    mesh_prov_session_done(&pv->sess[1]);
	if (!pv->done || pv->failed)
		return (-1);
	/* Both sides must have derived the same DevKey (Section 5.4.2.5). */
	if (timingsafe_bcmp(mesh_prov_session_devkey(&pv->sess[0]),
	    mesh_prov_session_devkey(&pv->sess[1]), 16) != 0)
		return (-1);
	return (0);
}

struct mesh_node *
mesh_sim_provision_commit(struct mesh_sim *sim, struct mesh_sim_prov *pv)
{

	if (sim == NULL || pv == NULL || !pv->done || pv->failed)
		return (NULL);
	/*
	 * The device installed the sim's NetKey and its assigned unicast; admit
	 * it as a node deriving the same subnet/app credentials every other node
	 * holds, so it participates in network traffic immediately.
	 */
	return (mesh_sim_add_node(sim, pv->assigned_addr, pv->dev_elements));
}

const uint8_t *
mesh_sim_prov_devkey(const struct mesh_sim_prov *pv, int side)
{

	if (pv == NULL || side < 0 || side > 1)
		return (NULL);
	return (mesh_prov_session_devkey(&pv->sess[side]));
}

/* ================================================================
 * Inspection.
 * ================================================================ */

struct mesh_node *
mesh_sim_node_at(struct mesh_sim *sim, uint16_t addr)
{
	int j;

	if (sim == NULL)
		return (NULL);
	for (j = 0; j < sim->n_nodes; j++) {
		if (local_unicast(&sim->nodes[j], addr))
			return (&sim->nodes[j]);
	}
	return (NULL);
}

uint32_t
mesh_sim_node_seq(const struct mesh_node *node)
{

	return (node != NULL ? node->seq : 0);
}

uint32_t
mesh_sim_node_iv(const struct mesh_node *node)
{

	return (node != NULL ? node->iv.iv_index : 0);
}

int
mesh_sim_node_kr_phase(const struct mesh_node *node)
{

	return (node != NULL ? mesh_kr_phase(&node->kr) : -1);
}

size_t
mesh_sim_pending(const struct mesh_sim *sim)
{

	return (sim != NULL ? sim->n_tx : 0);
}
