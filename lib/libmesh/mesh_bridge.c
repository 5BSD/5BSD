/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Subnet Bridge state and message codec.  See mesh_bridge.h for
 * the state model, the forwarding rule and the specification citations.
 */

#include <string.h>

#include "mesh_access.h"
#include "mesh_bridge.h"
#include "mesh_cfg_model.h"

#define	BRIDGE_KEYIDX_MAX	0x0fffu

/* ================================================================
 * State operations (MshPRT_v1.1.1 Sections 4.2.42, 4.4.9.2.2).
 * ================================================================ */

int
mesh_bridge_entry_valid(const struct mesh_bridge_entry *e)
{

	if (e == NULL)
		return (0);
	if (e->net_idx1 > BRIDGE_KEYIDX_MAX || e->net_idx2 > BRIDGE_KEYIDX_MAX)
		return (0);
	/*
	 * "The NetKeyIndex1 and NetKeyIndex2 fields shall have different
	 * values" and "The Address1 and Address2 fields shall have different
	 * values" (Section 4.3.11.4).
	 */
	if (e->net_idx1 == e->net_idx2 || e->addr1 == e->addr2)
		return (0);
	/* "The Address1 field value shall be a unicast address." */
	if (!mesh_addr_is_unicast(e->addr1))
		return (0);
	switch (e->directions) {
	case MESH_BRIDGE_DIR_ONE_WAY:
		/*
		 * "If the Directions field value is 0x01, the unassigned
		 * address and the all-nodes fixed group address are prohibited
		 * values for the Address2 field."
		 */
		if (e->addr2 == MESH_ADDR_UNASSIGNED ||
		    e->addr2 == MESH_ADDR_ALL_NODES)
			return (0);
		return (1);
	case MESH_BRIDGE_DIR_TWO_WAY:
		/*
		 * "If the Directions field value is 0x02, then the Address2
		 * field value shall be a unicast address."
		 */
		return (mesh_addr_is_unicast(e->addr2));
	default:
		/* 0x00 and 0x03-0xFF are prohibited (Table 4.71). */
		return (0);
	}
}

static int
bridge_entry_keys_match(const struct mesh_bridge_entry *a,
    const struct mesh_bridge_entry *b)
{

	return (a->net_idx1 == b->net_idx1 && a->net_idx2 == b->net_idx2 &&
	    a->addr1 == b->addr1 && a->addr2 == b->addr2);
}

int
mesh_bridge_table_add(struct mesh_bridging_table *t,
    const struct mesh_bridge_entry *e)
{
	size_t i;

	if (t == NULL || e == NULL)
		return (-1);
	for (i = 0; i < t->n; i++) {
		if (bridge_entry_keys_match(&t->entries[i], e)) {
			/*
			 * "If a Bridging Table state entry corresponding to the
			 * received message exists, the element shall set the
			 * Directions field in the entry to the value of the
			 * Directions field in the received message."
			 */
			t->entries[i].directions = e->directions;
			return (0);
		}
	}
	if (t->n >= MESH_BRIDGE_TABLE_SIZE)
		return (-1);		/* Insufficient Resources */
	t->entries[t->n++] = *e;
	return (0);
}

size_t
mesh_bridge_table_remove(struct mesh_bridging_table *t, uint16_t net_idx1,
    uint16_t net_idx2, uint16_t addr1, uint16_t addr2)
{
	size_t i, kept = 0, removed = 0;

	if (t == NULL)
		return (0);
	for (i = 0; i < t->n; i++) {
		const struct mesh_bridge_entry *e = &t->entries[i];
		int match;

		match = e->net_idx1 == net_idx1 && e->net_idx2 == net_idx2 &&
		    (addr1 == MESH_ADDR_UNASSIGNED || e->addr1 == addr1) &&
		    (addr2 == MESH_ADDR_UNASSIGNED || e->addr2 == addr2);
		if (match) {
			removed++;
			continue;
		}
		t->entries[kept++] = *e;
	}
	if (removed != 0)
		memset(&t->entries[kept], 0,
		    (t->n - kept) * sizeof(t->entries[0]));
	t->n = kept;
	return (removed);
}

size_t
mesh_bridge_table_remove_netkey(struct mesh_bridging_table *t, uint16_t net_idx)
{
	size_t i, kept = 0, removed = 0;

	if (t == NULL)
		return (0);
	for (i = 0; i < t->n; i++) {
		const struct mesh_bridge_entry *e = &t->entries[i];

		if (e->net_idx1 == net_idx || e->net_idx2 == net_idx) {
			removed++;
			continue;
		}
		t->entries[kept++] = *e;
	}
	if (removed != 0)
		memset(&t->entries[kept], 0,
		    (t->n - kept) * sizeof(t->entries[0]));
	t->n = kept;
	return (removed);
}

int
mesh_bridge_forward_net_idx(const struct mesh_bridging_table *t, uint16_t src,
    uint16_t dst, uint16_t rx_net_idx, uint16_t *out_net_idx)
{
	size_t i;

	if (out_net_idx != NULL)
		*out_net_idx = 0;
	if (t == NULL || out_net_idx == NULL)
		return (0);
	for (i = 0; i < t->n; i++) {
		const struct mesh_bridge_entry *e = &t->entries[i];

		if (e->directions != MESH_BRIDGE_DIR_ONE_WAY &&
		    e->directions != MESH_BRIDGE_DIR_TWO_WAY)
			continue;
		/*
		 * Address1 -> Address2, inbound on NetKeyIndex1: retransmit
		 * under NetKeyIndex2 (Section 3.4.6.3).  Allowed for both
		 * Directions values.
		 */
		if (src == e->addr1 && dst == e->addr2 &&
		    rx_net_idx == e->net_idx1) {
			*out_net_idx = e->net_idx2;
			return (1);
		}
		/*
		 * Address2 -> Address1, inbound on NetKeyIndex2: retransmit
		 * under NetKeyIndex1, and only when Directions is 0x02.
		 */
		if (e->directions == MESH_BRIDGE_DIR_TWO_WAY &&
		    src == e->addr2 && dst == e->addr1 &&
		    rx_net_idx == e->net_idx2) {
			*out_net_idx = e->net_idx1;
			return (1);
		}
	}
	return (0);
}

size_t
mesh_bridge_subnets_filter(const struct mesh_bridging_table *t, uint8_t filter,
    uint16_t net_idx, uint8_t start_index,
    struct mesh_bridge_subnets_pair *pairs, size_t max_pairs)
{
	struct mesh_bridge_subnets_pair seen[MESH_BRIDGE_TABLE_SIZE];
	size_t i, j, n_seen = 0, n_out = 0, index = 0;

	if (t == NULL || pairs == NULL)
		return (0);
	for (i = 0; i < t->n; i++) {
		const struct mesh_bridge_entry *e = &t->entries[i];
		int keep;

		switch (filter) {
		case MESH_BRIDGE_FILTER_ALL:
			keep = 1;
			break;
		case MESH_BRIDGE_FILTER_NETKEY1:
			keep = (e->net_idx1 == net_idx);
			break;
		case MESH_BRIDGE_FILTER_NETKEY2:
			keep = (e->net_idx2 == net_idx);
			break;
		case MESH_BRIDGE_FILTER_EITHER:
			keep = (e->net_idx1 == net_idx ||
			    e->net_idx2 == net_idx);
			break;
		default:
			return (0);
		}
		if (!keep)
			continue;
		/* "a filtered set of not repeated (i.e., unique) entries" */
		for (j = 0; j < n_seen; j++)
			if (seen[j].net_idx1 == e->net_idx1 &&
			    seen[j].net_idx2 == e->net_idx2)
				break;
		if (j < n_seen)
			continue;
		seen[n_seen].net_idx1 = e->net_idx1;
		seen[n_seen].net_idx2 = e->net_idx2;
		n_seen++;
		if (index++ < start_index)
			continue;
		if (n_out >= max_pairs)
			break;
		pairs[n_out].net_idx1 = e->net_idx1;
		pairs[n_out].net_idx2 = e->net_idx2;
		n_out++;
	}
	return (n_out);
}

size_t
mesh_bridging_table_filter(const struct mesh_bridging_table *t,
    uint16_t net_idx1, uint16_t net_idx2, uint16_t start_index,
    struct mesh_bridge_addr_entry *addrs, size_t max_addrs)
{
	size_t i, n_out = 0, index = 0;

	if (t == NULL || addrs == NULL)
		return (0);
	for (i = 0; i < t->n; i++) {
		const struct mesh_bridge_entry *e = &t->entries[i];

		if (e->net_idx1 != net_idx1 || e->net_idx2 != net_idx2)
			continue;
		if (index++ < start_index)
			continue;
		if (n_out >= max_addrs)
			break;
		addrs[n_out].addr1 = e->addr1;
		addrs[n_out].addr2 = e->addr2;
		addrs[n_out].directions = e->directions;
		n_out++;
	}
	return (n_out);
}

/* ================================================================
 * Message codec (MshPRT_v1.1.1 Section 4.3.11).
 * ================================================================ */

static void
put_le16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
get_le16(const uint8_t *p)
{

	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

/*
 * Split a received Access PDU and check its opcode.  Returns the parameter
 * pointer and length, or NULL when the PDU is malformed or carries a
 * different opcode.
 */
static const uint8_t *
bridge_params(const uint8_t *in, size_t inlen, uint32_t opcode,
    struct mesh_access_pdu *ap, size_t *plen)
{

	if (in == NULL || ap == NULL || plen == NULL)
		return (NULL);
	if (mesh_access_pdu_parse(in, inlen, ap) != 0)
		return (NULL);
	if (ap->opcode != opcode)
		return (NULL);
	*plen = ap->params_len;
	return (ap->params);
}

int
mesh_bridge_subnet_build(uint32_t opcode, uint8_t state, uint8_t *out,
    size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (opcode != MESH_BRIDGE_OP_SUBNET_BRIDGE_SET &&
	    opcode != MESH_BRIDGE_OP_SUBNET_BRIDGE_STATUS)
		return (-1);
	if (state != MESH_BRIDGE_DISABLED && state != MESH_BRIDGE_ENABLED)
		return (-1);		/* 0x02-0xFF prohibited (Table 4.69) */
	return (mesh_access_pdu_build(opcode, &state, 1, out, outlen));
}

int
mesh_bridge_subnet_parse(const uint8_t *in, size_t inlen, uint8_t *state)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (state == NULL)
		return (-1);
	*state = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_BRIDGE_OP_SUBNET_BRIDGE_SET &&
	    ap.opcode != MESH_BRIDGE_OP_SUBNET_BRIDGE_STATUS)
		return (-1);
	p = ap.params;
	plen = ap.params_len;
	if (plen != 1)
		return (-1);
	if (p[0] != MESH_BRIDGE_DISABLED && p[0] != MESH_BRIDGE_ENABLED)
		return (-1);
	*state = p[0];
	return (0);
}

int
mesh_bridge_table_add_build(const struct mesh_bridge_entry *e, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[8];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (e == NULL || e->net_idx1 > BRIDGE_KEYIDX_MAX ||
	    e->net_idx2 > BRIDGE_KEYIDX_MAX)
		return (-1);
	params[0] = e->directions;
	mesh_cfg_keyidx_pack2(&params[1], e->net_idx1, e->net_idx2);
	put_le16(&params[4], e->addr1);
	put_le16(&params[6], e->addr2);
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_ADD, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridge_table_add_parse(const uint8_t *in, size_t inlen,
    struct mesh_bridge_entry *e)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (e == NULL)
		return (-1);
	memset(e, 0, sizeof(*e));
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_ADD, &ap, &plen);
	if (p == NULL || plen != 8)
		return (-1);
	e->directions = p[0];
	mesh_cfg_keyidx_unpack2(&p[1], &e->net_idx1, &e->net_idx2);
	e->addr1 = get_le16(&p[4]);
	e->addr2 = get_le16(&p[6]);
	return (0);
}

int
mesh_bridge_table_remove_build(uint16_t net_idx1, uint16_t net_idx2,
    uint16_t addr1, uint16_t addr2, uint8_t *out, size_t *outlen)
{
	uint8_t params[7];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (net_idx1 > BRIDGE_KEYIDX_MAX || net_idx2 > BRIDGE_KEYIDX_MAX)
		return (-1);
	mesh_cfg_keyidx_pack2(&params[0], net_idx1, net_idx2);
	put_le16(&params[3], addr1);
	put_le16(&params[5], addr2);
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_REMOVE, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridge_table_remove_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx1, uint16_t *net_idx2, uint16_t *addr1, uint16_t *addr2)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (net_idx1 == NULL || net_idx2 == NULL || addr1 == NULL ||
	    addr2 == NULL)
		return (-1);
	*net_idx1 = *net_idx2 = *addr1 = *addr2 = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_REMOVE, &ap, &plen);
	if (p == NULL || plen != 7)
		return (-1);
	mesh_cfg_keyidx_unpack2(&p[0], net_idx1, net_idx2);
	*addr1 = get_le16(&p[3]);
	*addr2 = get_le16(&p[5]);
	return (0);
}

int
mesh_bridge_table_status_build(const struct mesh_bridge_table_status *s,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[9];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (s == NULL || s->net_idx1 > BRIDGE_KEYIDX_MAX ||
	    s->net_idx2 > BRIDGE_KEYIDX_MAX)
		return (-1);
	params[0] = s->status;
	params[1] = s->current_directions;
	mesh_cfg_keyidx_pack2(&params[2], s->net_idx1, s->net_idx2);
	put_le16(&params[5], s->addr1);
	put_le16(&params[7], s->addr2);
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_STATUS, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridge_table_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_bridge_table_status *s)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (s == NULL)
		return (-1);
	memset(s, 0, sizeof(*s));
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_STATUS, &ap, &plen);
	if (p == NULL || plen != 9)
		return (-1);
	s->status = p[0];
	s->current_directions = p[1];
	mesh_cfg_keyidx_unpack2(&p[2], &s->net_idx1, &s->net_idx2);
	s->addr1 = get_le16(&p[5]);
	s->addr2 = get_le16(&p[7]);
	return (0);
}

/*
 * Filter / NetKeyIndex octet pair shared by BRIDGED_SUBNETS_GET and
 * BRIDGED_SUBNETS_LIST (Tables 4.290 / 4.292):
 *   o0 = Filter (bits 1:0) | Prohibited (bits 3:2) | NetKeyIndex[3:0] << 4
 *   o1 = NetKeyIndex[11:4]
 */
static void
bridge_filter_pack(uint8_t *o, uint8_t filter, uint16_t net_idx)
{

	o[0] = (uint8_t)((filter & 0x03) | ((net_idx & 0x0f) << 4));
	o[1] = (uint8_t)((net_idx >> 4) & 0xff);
}

static int
bridge_filter_unpack(const uint8_t *o, uint8_t *filter, uint16_t *net_idx)
{

	if ((o[0] & 0x0c) != 0)
		return (-1);		/* Prohibited bits must be zero */
	*filter = (uint8_t)(o[0] & 0x03);
	*net_idx = (uint16_t)(((o[0] >> 4) & 0x0f) | ((uint16_t)o[1] << 4));
	return (0);
}

int
mesh_bridged_subnets_get_build(uint8_t filter, uint16_t net_idx,
    uint8_t start_index, uint8_t *out, size_t *outlen)
{
	uint8_t params[3];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (filter > MESH_BRIDGE_FILTER_EITHER || net_idx > BRIDGE_KEYIDX_MAX)
		return (-1);
	bridge_filter_pack(params, filter, net_idx);
	params[2] = start_index;
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_SUBNETS_GET, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridged_subnets_get_parse(const uint8_t *in, size_t inlen, uint8_t *filter,
    uint16_t *net_idx, uint8_t *start_index)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (filter == NULL || net_idx == NULL || start_index == NULL)
		return (-1);
	*filter = 0;
	*net_idx = 0;
	*start_index = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_SUBNETS_GET, &ap, &plen);
	if (p == NULL || plen != 3 ||
	    bridge_filter_unpack(p, filter, net_idx) != 0)
		return (-1);
	*start_index = p[2];
	return (0);
}

int
mesh_bridged_subnets_list_build(uint8_t filter, uint16_t net_idx,
    uint8_t start_index, const struct mesh_bridge_subnets_pair *pairs,
    size_t n_pairs, uint8_t *out, size_t *outlen)
{
	uint8_t params[3 + 3 * MESH_BRIDGE_TABLE_SIZE];
	size_t i, off;

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (filter > MESH_BRIDGE_FILTER_EITHER || net_idx > BRIDGE_KEYIDX_MAX)
		return (-1);
	if (n_pairs > MESH_BRIDGE_TABLE_SIZE || (n_pairs != 0 && pairs == NULL))
		return (-1);
	bridge_filter_pack(params, filter, net_idx);
	params[2] = start_index;
	off = 3;
	for (i = 0; i < n_pairs; i++) {
		if (pairs[i].net_idx1 > BRIDGE_KEYIDX_MAX ||
		    pairs[i].net_idx2 > BRIDGE_KEYIDX_MAX)
			return (-1);
		mesh_cfg_keyidx_pack2(&params[off], pairs[i].net_idx1,
		    pairs[i].net_idx2);
		off += 3;
	}
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_SUBNETS_LIST, params, off,
	    out, outlen));
}

int
mesh_bridged_subnets_list_parse(const uint8_t *in, size_t inlen,
    uint8_t *filter, uint16_t *net_idx, uint8_t *start_index,
    struct mesh_bridge_subnets_pair *pairs, size_t max_pairs, size_t *n_pairs)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen, i, n;

	if (filter == NULL || net_idx == NULL || start_index == NULL ||
	    n_pairs == NULL)
		return (-1);
	*filter = 0;
	*net_idx = 0;
	*start_index = 0;
	*n_pairs = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_SUBNETS_LIST, &ap, &plen);
	if (p == NULL || plen < 3 || (plen - 3) % 3 != 0 ||
	    bridge_filter_unpack(p, filter, net_idx) != 0)
		return (-1);
	*start_index = p[2];
	n = (plen - 3) / 3;
	if (n > max_pairs)
		return (-1);
	for (i = 0; i < n; i++)
		mesh_cfg_keyidx_unpack2(&p[3 + 3 * i], &pairs[i].net_idx1,
		    &pairs[i].net_idx2);
	*n_pairs = n;
	return (0);
}

int
mesh_bridging_table_get_build(uint16_t net_idx1, uint16_t net_idx2,
    uint16_t start_index, uint8_t *out, size_t *outlen)
{
	uint8_t params[5];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (net_idx1 > BRIDGE_KEYIDX_MAX || net_idx2 > BRIDGE_KEYIDX_MAX)
		return (-1);
	mesh_cfg_keyidx_pack2(&params[0], net_idx1, net_idx2);
	put_le16(&params[3], start_index);
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_GET, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridging_table_get_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx1, uint16_t *net_idx2, uint16_t *start_index)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (net_idx1 == NULL || net_idx2 == NULL || start_index == NULL)
		return (-1);
	*net_idx1 = *net_idx2 = *start_index = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_GET, &ap, &plen);
	if (p == NULL || plen != 5)
		return (-1);
	mesh_cfg_keyidx_unpack2(&p[0], net_idx1, net_idx2);
	*start_index = get_le16(&p[3]);
	return (0);
}

int
mesh_bridging_table_list_build(uint8_t status, uint16_t net_idx1,
    uint16_t net_idx2, uint16_t start_index,
    const struct mesh_bridge_addr_entry *addrs, size_t n_addrs, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[6 + 5 * MESH_BRIDGE_TABLE_SIZE];
	size_t i, off;

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	if (net_idx1 > BRIDGE_KEYIDX_MAX || net_idx2 > BRIDGE_KEYIDX_MAX)
		return (-1);
	if (n_addrs > MESH_BRIDGE_TABLE_SIZE || (n_addrs != 0 && addrs == NULL))
		return (-1);
	/*
	 * "If the value of the Status field is Success, the
	 * Bridged_Addresses_List field shall be optional; otherwise, the
	 * Bridged_Addresses_List field shall not be present" (C.1, Table 4.295).
	 */
	if (status != MESH_CFG_SUCCESS && n_addrs != 0)
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack2(&params[1], net_idx1, net_idx2);
	put_le16(&params[4], start_index);
	off = 6;
	for (i = 0; i < n_addrs; i++) {
		put_le16(&params[off], addrs[i].addr1);
		put_le16(&params[off + 2], addrs[i].addr2);
		params[off + 4] = addrs[i].directions;
		off += 5;
	}
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_LIST, params, off,
	    out, outlen));
}

int
mesh_bridging_table_list_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *net_idx1, uint16_t *net_idx2, uint16_t *start_index,
    struct mesh_bridge_addr_entry *addrs, size_t max_addrs, size_t *n_addrs)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen, i, n;

	if (status == NULL || net_idx1 == NULL || net_idx2 == NULL ||
	    start_index == NULL || n_addrs == NULL)
		return (-1);
	*status = 0;
	*net_idx1 = *net_idx2 = *start_index = 0;
	*n_addrs = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_LIST, &ap, &plen);
	if (p == NULL || plen < 6 || (plen - 6) % 5 != 0)
		return (-1);
	*status = p[0];
	mesh_cfg_keyidx_unpack2(&p[1], net_idx1, net_idx2);
	*start_index = get_le16(&p[4]);
	n = (plen - 6) / 5;
	if (n > max_addrs)
		return (-1);
	if (*status != MESH_CFG_SUCCESS && n != 0)
		return (-1);
	for (i = 0; i < n; i++) {
		addrs[i].addr1 = get_le16(&p[6 + 5 * i]);
		addrs[i].addr2 = get_le16(&p[8 + 5 * i]);
		addrs[i].directions = p[10 + 5 * i];
	}
	*n_addrs = n;
	return (0);
}

int
mesh_bridge_table_size_status_build(uint16_t size, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (out == NULL || outlen == NULL)
		return (-1);
	*outlen = 0;
	put_le16(params, size);
	return (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_SIZE_STATUS, params,
	    sizeof(params), out, outlen));
}

int
mesh_bridge_table_size_status_parse(const uint8_t *in, size_t inlen,
    uint16_t *size)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;
	size_t plen;

	if (size == NULL)
		return (-1);
	*size = 0;
	p = bridge_params(in, inlen, MESH_BRIDGE_OP_TABLE_SIZE_STATUS, &ap,
	    &plen);
	if (p == NULL || plen != 2)
		return (-1);
	*size = get_le16(p);
	return (0);
}
