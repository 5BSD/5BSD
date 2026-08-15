/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Configuration model codecs (MshMDL_v1.1 Section 4.4.1).
 *
 * Each _build() assembles the message parameters then wraps them with the
 * access-layer opcode via mesh_access_pdu_build(), so the output is the full
 * Access PDU (the plaintext carried by the upper transport).  Each _parse()
 * runs mesh_access_pdu_parse() first, checks the opcode, then decodes the
 * parameters.  All addresses, key indexes and model identifiers are
 * little-endian on the wire (Section 4.3.1 / 4.3.2); the two-index key
 * packing follows Section 4.3.1.1.  Outputs are zeroed on failure.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_model.h"

/* Little-endian 16-bit field helpers. */
static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
get16(const uint8_t *p)
{

	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

/* MshPRT 1.1 §4.3.2: Configuration ElementAddress fields are unicast. */
static int
valid_element_address(uint16_t addr)
{

	return (mesh_addr_is_unicast(addr));
}

/*
 * MshPRT 1.1 §4.3.2.18/.20/.22: non-virtual subscription messages
 * accept group addresses except the all-nodes address.
 */
static int
valid_subscription_address(uint16_t addr)
{

	return (mesh_addr_is_group(addr) && addr != MESH_ADDR_ALL_NODES);
}

/* Finish a build: wrap assembled params with the opcode. */
static int
wrap(uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *out,
    size_t *outlen)
{

	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

/* ================================================================
 * Key-index packing (Section 4.3.1.1).
 * ================================================================ */

void
mesh_cfg_keyidx_pack1(uint8_t out[2], uint16_t idx)
{

	out[0] = (uint8_t)(idx & 0xff);
	out[1] = (uint8_t)((idx >> 8) & 0x0f);	/* 4 RFU bits = 0 */
}

uint16_t
mesh_cfg_keyidx_unpack1(const uint8_t in[2])
{

	return ((uint16_t)(in[0] | ((uint16_t)(in[1] & 0x0f) << 8)));
}

void
mesh_cfg_keyidx_pack2(uint8_t out[3], uint16_t idx0, uint16_t idx1)
{

	/* idx0 in the low 12 bits, idx1 in the high 12 bits. */
	out[0] = (uint8_t)(idx0 & 0xff);
	out[1] = (uint8_t)(((idx1 & 0x0f) << 4) | ((idx0 >> 8) & 0x0f));
	out[2] = (uint8_t)((idx1 >> 4) & 0xff);
}

void
mesh_cfg_keyidx_unpack2(const uint8_t in[3], uint16_t *idx0, uint16_t *idx1)
{

	if (idx0 != NULL)
		*idx0 = (uint16_t)(in[0] | ((uint16_t)(in[1] & 0x0f) << 8));
	if (idx1 != NULL)
		*idx1 = (uint16_t)(((in[1] >> 4) & 0x0f) | ((uint16_t)in[2] << 4));
}

/* ================================================================
 * Model identifier (Section 4.3.2).
 * ================================================================ */

int
mesh_cfg_model_id_encode(const struct mesh_cfg_model_id *m, uint8_t *out,
    size_t *outlen)
{

	if (m == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (m->vendor) {
		put16(out, m->company_id);
		put16(out + 2, m->model_id);
		*outlen = 4;
	} else {
		put16(out, m->model_id);
		*outlen = 2;
	}
	return (0);
}

int
mesh_cfg_model_id_decode(const uint8_t *in, size_t inlen,
    struct mesh_cfg_model_id *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen == 2) {
		out->vendor = 0;
		out->model_id = get16(in);
	} else if (inlen == 4) {
		out->vendor = 1;
		out->company_id = get16(in);
		out->model_id = get16(in + 2);
	} else
		return (-1);
	return (0);
}

/* ================================================================
 * Composition Data Page 0 (Section 4.4.1.2.1).
 * ================================================================ */

int
mesh_cfg_comp_page0_encode(const struct mesh_cfg_comp_page0 *in, uint8_t *out,
    size_t *outlen)
{
	size_t off, e, i;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->n_elements > MESH_CFG_COMP_MAX_ELEMENTS)
		return (-1);

	put16(out + 0, in->cid);
	put16(out + 2, in->pid);
	put16(out + 4, in->vid);
	put16(out + 6, in->crpl);
	put16(out + 8, in->features);
	off = 10;

	for (e = 0; e < in->n_elements; e++) {
		const struct mesh_cfg_comp_element *el = &in->elements[e];

		if (el->n_sig > MESH_CFG_COMP_MAX_MODELS ||
		    el->n_vnd > MESH_CFG_COMP_MAX_MODELS)
			return (-1);
		if (off + 4 + el->n_sig * 2 + el->n_vnd * 4 >
		    MESH_ACCESS_PARAMS_MAX)
			return (-1);
		put16(out + off, el->loc);
		off += 2;
		out[off++] = (uint8_t)el->n_sig;
		out[off++] = (uint8_t)el->n_vnd;
		for (i = 0; i < el->n_sig; i++) {
			put16(out + off, el->sig_models[i]);
			off += 2;
		}
		for (i = 0; i < el->n_vnd; i++) {
			put16(out + off, el->vnd_models[i].company_id);
			put16(out + off + 2, el->vnd_models[i].model_id);
			off += 4;
		}
	}
	*outlen = off;
	return (0);
}

int
mesh_cfg_comp_page0_decode(const uint8_t *in, size_t inlen,
    struct mesh_cfg_comp_page0 *out)
{
	size_t off, i;

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen < 10)
		goto fail;

	out->cid = get16(in + 0);
	out->pid = get16(in + 2);
	out->vid = get16(in + 4);
	out->crpl = get16(in + 6);
	out->features = get16(in + 8);
	off = 10;

	while (off < inlen) {
		struct mesh_cfg_comp_element *el;
		uint8_t ns, nv;

		if (out->n_elements >= MESH_CFG_COMP_MAX_ELEMENTS)
			goto fail;
		if (off + 4 > inlen)
			goto fail;
		el = &out->elements[out->n_elements];
		el->loc = get16(in + off);
		off += 2;
		ns = in[off++];
		nv = in[off++];
		if (ns > MESH_CFG_COMP_MAX_MODELS ||
		    nv > MESH_CFG_COMP_MAX_MODELS)
			goto fail;
		if (off + (size_t)ns * 2 + (size_t)nv * 4 > inlen)
			goto fail;
		for (i = 0; i < ns; i++) {
			el->sig_models[i] = get16(in + off);
			off += 2;
		}
		for (i = 0; i < nv; i++) {
			el->vnd_models[i].company_id = get16(in + off);
			el->vnd_models[i].model_id = get16(in + off + 2);
			off += 4;
		}
		el->n_sig = ns;
		el->n_vnd = nv;
		out->n_elements++;
	}
	return (0);
fail:
	memset(out, 0, sizeof(*out));
	return (-1);
}

int
mesh_cfg_comp_get_build(uint8_t page, uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_COMP_DATA_GET, &page, 1, out, outlen));
}

int
mesh_cfg_comp_get_parse(const uint8_t *in, size_t inlen, uint8_t *page)
{
	struct mesh_access_pdu ap;

	if (page != NULL)
		*page = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_COMP_DATA_GET || ap.params_len != 1)
		return (-1);
	if (page != NULL)
		*page = ap.params[0];
	return (0);
}

int
mesh_cfg_comp_status_build(const struct mesh_cfg_comp_status *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[1 + MESH_CFG_COMP_DATA_MAX];

	if (in == NULL || in->data_len > MESH_CFG_COMP_DATA_MAX)
		return (-1);
	params[0] = in->page;
	if (in->data_len != 0)
		memcpy(params + 1, in->data, in->data_len);
	return (wrap(MESH_CFG_OP_COMP_DATA_STATUS, params, 1 + in->data_len,
	    out, outlen));
}

int
mesh_cfg_comp_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_comp_status *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_COMP_DATA_STATUS || ap.params_len < 1)
		return (-1);
	if (ap.params_len - 1 > MESH_CFG_COMP_DATA_MAX)
		return (-1);
	out->page = ap.params[0];
	out->data_len = ap.params_len - 1;
	if (out->data_len != 0)
		memcpy(out->data, ap.params + 1, out->data_len);
	return (0);
}

/* ================================================================
 * AppKey management.
 * ================================================================ */

int
mesh_cfg_appkey_add_build(uint32_t opcode, const struct mesh_cfg_appkey *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[3 + 16];

	if (in == NULL)
		return (-1);
	if (opcode != MESH_CFG_OP_APPKEY_ADD && opcode != MESH_CFG_OP_APPKEY_UPDATE)
		return (-1);
	if (in->net_idx > 0x0fff || in->app_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack2(params, in->net_idx, in->app_idx);
	memcpy(params + 3, in->key, 16);
	return (wrap(opcode, params, sizeof(params), out, outlen));
}

int
mesh_cfg_appkey_add_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_appkey *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_APPKEY_ADD &&
	    ap.opcode != MESH_CFG_OP_APPKEY_UPDATE)
		return (-1);
	if (ap.params_len != 3 + 16)
		return (-1);
	mesh_cfg_keyidx_unpack2(ap.params, &out->net_idx, &out->app_idx);
	memcpy(out->key, ap.params + 3, 16);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_appkey_delete_build(uint16_t net_idx, uint16_t app_idx, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[3];

	if (net_idx > 0x0fff || app_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack2(params, net_idx, app_idx);
	return (wrap(MESH_CFG_OP_APPKEY_DELETE, params, sizeof(params), out,
	    outlen));
}

int
mesh_cfg_appkey_delete_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx,
    uint16_t *app_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (app_idx != NULL)
		*app_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_APPKEY_DELETE || ap.params_len != 3)
		return (-1);
	mesh_cfg_keyidx_unpack2(ap.params, net_idx, app_idx);
	return (0);
}

int
mesh_cfg_appkey_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (net_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	return (wrap(MESH_CFG_OP_APPKEY_GET, params, sizeof(params), out, outlen));
}

int
mesh_cfg_appkey_get_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_APPKEY_GET || ap.params_len != 2)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	return (0);
}

int
mesh_cfg_appkey_status_build(uint8_t status, uint16_t net_idx, uint16_t app_idx,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 3];

	if (net_idx > 0x0fff || app_idx > 0x0fff)
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack2(params + 1, net_idx, app_idx);
	return (wrap(MESH_CFG_OP_APPKEY_STATUS, params, sizeof(params), out,
	    outlen));
}

int
mesh_cfg_appkey_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *net_idx, uint16_t *app_idx)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (net_idx != NULL)
		*net_idx = 0;
	if (app_idx != NULL)
		*app_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_APPKEY_STATUS || ap.params_len != 4)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	mesh_cfg_keyidx_unpack2(ap.params + 1, net_idx, app_idx);
	return (0);
}

/*
 * Pack a list of key indexes two-per-3-octets, a trailing odd index in 2.
 * Returns the packed length or (size_t)-1 on overflow.
 */
static size_t
keyidx_list_pack(const uint16_t *idx, size_t n, uint8_t *out, size_t max)
{
	size_t i, off;

	off = 0;
	for (i = 0; i < n; i += 2) {
		if (idx[i] > 0x0fff)
			return ((size_t)-1);
		if (i + 1 < n) {
			if (idx[i + 1] > 0x0fff || off + 3 > max)
				return ((size_t)-1);
			mesh_cfg_keyidx_pack2(out + off, idx[i], idx[i + 1]);
			off += 3;
		} else {
			if (off + 2 > max)
				return ((size_t)-1);
			mesh_cfg_keyidx_pack1(out + off, idx[i]);
			off += 2;
		}
	}
	return (off);
}

/*
 * Unpack a two-per-3-octets key-index list.  Returns 0 and *n on success,
 * -1 on a malformed length (a remainder of 1 octet is invalid).
 */
static int
keyidx_list_unpack(const uint8_t *in, size_t len, uint16_t *idx, size_t max,
    size_t *n)
{
	size_t off, cnt;

	off = 0;
	cnt = 0;
	while (off < len) {
		if (len - off == 2) {
			if (cnt >= max)
				return (-1);
			idx[cnt++] = mesh_cfg_keyidx_unpack1(in + off);
			off += 2;
		} else if (len - off >= 3) {
			uint16_t a, b;

			if (cnt + 2 > max)
				return (-1);
			mesh_cfg_keyidx_unpack2(in + off, &a, &b);
			idx[cnt++] = a;
			idx[cnt++] = b;
			off += 3;
		} else
			return (-1);	/* 1 octet remaining: malformed */
	}
	if (n != NULL)
		*n = cnt;
	return (0);
}

int
mesh_cfg_appkey_list_build(uint8_t status, uint16_t net_idx,
    const uint16_t *app_idx, size_t n, uint8_t *out, size_t *outlen)
{
	uint8_t params[3 + MESH_CFG_MAX_KEY_INDEXES * 3];
	size_t plen;

	if (net_idx > 0x0fff)
		return (-1);
	if (n > MESH_CFG_MAX_KEY_INDEXES || (n != 0 && app_idx == NULL))
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack1(params + 1, net_idx);
	plen = keyidx_list_pack(app_idx, n, params + 3, sizeof(params) - 3);
	if (plen == (size_t)-1)
		return (-1);
	return (wrap(MESH_CFG_OP_APPKEY_LIST, params, 3 + plen, out, outlen));
}

int
mesh_cfg_appkey_list_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *net_idx, uint16_t *app_idx, size_t max, size_t *n)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (net_idx != NULL)
		*net_idx = 0;
	if (n != NULL)
		*n = 0;
	if (app_idx == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_APPKEY_LIST || ap.params_len < 3)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params + 1);
	return (keyidx_list_unpack(ap.params + 3, ap.params_len - 3, app_idx,
	    max, n));
}

/* ================================================================
 * NetKey management.
 * ================================================================ */

int
mesh_cfg_netkey_add_build(uint32_t opcode, const struct mesh_cfg_netkey *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 16];

	if (in == NULL)
		return (-1);
	if (opcode != MESH_CFG_OP_NETKEY_ADD && opcode != MESH_CFG_OP_NETKEY_UPDATE)
		return (-1);
	if (in->net_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack1(params, in->net_idx);
	memcpy(params + 2, in->key, 16);
	return (wrap(opcode, params, sizeof(params), out, outlen));
}

int
mesh_cfg_netkey_add_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_netkey *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NETKEY_ADD &&
	    ap.opcode != MESH_CFG_OP_NETKEY_UPDATE)
		return (-1);
	if (ap.params_len != 2 + 16)
		return (-1);
	out->net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	memcpy(out->key, ap.params + 2, 16);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_netkey_delete_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (net_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	return (wrap(MESH_CFG_OP_NETKEY_DELETE, params, sizeof(params), out,
	    outlen));
}

int
mesh_cfg_netkey_delete_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NETKEY_DELETE || ap.params_len != 2)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	return (0);
}

int
mesh_cfg_netkey_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_NETKEY_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_netkey_status_build(uint8_t status, uint16_t net_idx, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[1 + 2];

	if (net_idx > 0x0fff)
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack1(params + 1, net_idx);
	return (wrap(MESH_CFG_OP_NETKEY_STATUS, params, sizeof(params), out,
	    outlen));
}

int
mesh_cfg_netkey_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (net_idx != NULL)
		*net_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NETKEY_STATUS || ap.params_len != 3)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params + 1);
	return (0);
}

int
mesh_cfg_netkey_list_build(const uint16_t *net_idx, size_t n, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[MESH_CFG_MAX_KEY_INDEXES * 3];
	size_t plen;

	if (n > MESH_CFG_MAX_KEY_INDEXES || (n != 0 && net_idx == NULL))
		return (-1);
	plen = keyidx_list_pack(net_idx, n, params, sizeof(params));
	if (plen == (size_t)-1)
		return (-1);
	return (wrap(MESH_CFG_OP_NETKEY_LIST, params, plen, out, outlen));
}

int
mesh_cfg_netkey_list_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx,
    size_t max, size_t *n)
{
	struct mesh_access_pdu ap;

	if (n != NULL)
		*n = 0;
	if (net_idx == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NETKEY_LIST)
		return (-1);
	return (keyidx_list_unpack(ap.params, ap.params_len, net_idx, max, n));
}

/* ================================================================
 * Model App bind / unbind / status.
 * ================================================================ */

int
mesh_cfg_model_app_build(uint32_t opcode, const struct mesh_cfg_model_app *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[4 + 4];
	size_t midlen;

	if (in == NULL || !valid_element_address(in->elem_addr))
		return (-1);
	if (opcode != MESH_CFG_OP_MODEL_APP_BIND &&
	    opcode != MESH_CFG_OP_MODEL_APP_UNBIND)
		return (-1);
	if (in->app_idx > 0x0fff)
		return (-1);
	put16(params, in->elem_addr);
	mesh_cfg_keyidx_pack1(params + 2, in->app_idx);
	if (mesh_cfg_model_id_encode(&in->model, params + 4, &midlen) != 0)
		return (-1);
	return (wrap(opcode, params, 4 + midlen, out, outlen));
}

int
mesh_cfg_model_app_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_model_app *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_APP_BIND &&
	    ap.opcode != MESH_CFG_OP_MODEL_APP_UNBIND)
		return (-1);
	if (ap.params_len != 6 && ap.params_len != 8)
		return (-1);
	out->elem_addr = get16(ap.params);
	out->app_idx = mesh_cfg_keyidx_unpack1(ap.params + 2);
	if (mesh_cfg_model_id_decode(ap.params + 4, ap.params_len - 4,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_model_app_status_build(uint8_t status,
    const struct mesh_cfg_model_app *in, uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 4 + 4];
	size_t midlen;

	if (in == NULL || in->app_idx > 0x0fff)
		return (-1);
	params[0] = status;
	put16(params + 1, in->elem_addr);
	mesh_cfg_keyidx_pack1(params + 3, in->app_idx);
	if (mesh_cfg_model_id_encode(&in->model, params + 5, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_APP_STATUS, params, 5 + midlen, out,
	    outlen));
}

int
mesh_cfg_model_app_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    struct mesh_cfg_model_app *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (status != NULL)
		*status = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_APP_STATUS)
		return (-1);
	if (ap.params_len != 7 && ap.params_len != 9)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	out->elem_addr = get16(ap.params + 1);
	out->app_idx = mesh_cfg_keyidx_unpack1(ap.params + 3);
	if (mesh_cfg_model_id_decode(ap.params + 5, ap.params_len - 5,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/* ================================================================
 * Model publication.
 * ================================================================ */

static void
pub_pack_common(uint8_t *p, const struct mesh_cfg_model_pub *in)
{
	uint16_t word;

	put16(p + 0, in->pub_addr);
	word = (uint16_t)((in->app_idx & 0x0fff) |
	    ((in->cred_flag ? 1u : 0u) << 12));
	put16(p + 2, word);
	p[4] = in->ttl;
	p[5] = in->period;
	p[6] = in->retransmit;
}

static void
pub_unpack_common(const uint8_t *p, struct mesh_cfg_model_pub *out)
{
	uint16_t word;

	out->pub_addr = get16(p + 0);
	word = get16(p + 2);
	out->app_idx = (uint16_t)(word & 0x0fff);
	out->cred_flag = (uint8_t)((word >> 12) & 0x01);
	out->ttl = p[4];
	out->period = p[5];
	out->retransmit = p[6];
}

int
mesh_cfg_model_pub_set_build(const struct mesh_cfg_model_pub *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[2 + 7 + 4];
	size_t midlen;

	if (in == NULL || !valid_element_address(in->elem_addr) ||
	    in->app_idx > 0x0fff || mesh_addr_is_virtual(in->pub_addr))
		return (-1);
	put16(params, in->elem_addr);
	pub_pack_common(params + 2, in);
	if (mesh_cfg_model_id_encode(&in->model, params + 9, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_PUB_SET, params, 9 + midlen, out, outlen));
}

int
mesh_cfg_model_pub_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_model_pub *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_PUB_SET)
		return (-1);
	if (ap.params_len != 11 && ap.params_len != 13)
		return (-1);
	out->elem_addr = get16(ap.params);
	pub_unpack_common(ap.params + 2, out);
	if (mesh_cfg_model_id_decode(ap.params + 9, ap.params_len - 9,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_cfg_model_pub_status_build(uint8_t status,
    const struct mesh_cfg_model_pub *in, uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 2 + 7 + 4];
	size_t midlen;

	if (in == NULL || in->app_idx > 0x0fff)
		return (-1);
	params[0] = status;
	put16(params + 1, in->elem_addr);
	pub_pack_common(params + 3, in);
	if (mesh_cfg_model_id_encode(&in->model, params + 10, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_PUB_STATUS, params, 10 + midlen, out,
	    outlen));
}

int
mesh_cfg_model_pub_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    struct mesh_cfg_model_pub *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (status != NULL)
		*status = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_PUB_STATUS)
		return (-1);
	if (ap.params_len != 12 && ap.params_len != 14)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	out->elem_addr = get16(ap.params + 1);
	pub_unpack_common(ap.params + 3, out);
	if (mesh_cfg_model_id_decode(ap.params + 10, ap.params_len - 10,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_cfg_model_pub_get_build(uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 4];
	size_t midlen;

	if (model == NULL || !valid_element_address(elem_addr))
		return (-1);
	put16(params, elem_addr);
	if (mesh_cfg_model_id_encode(model, params + 2, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_PUB_GET, params, 2 + midlen, out, outlen));
}

int
mesh_cfg_model_pub_get_parse(const uint8_t *in, size_t inlen, uint16_t *elem_addr,
    struct mesh_cfg_model_id *model)
{
	struct mesh_access_pdu ap;

	if (elem_addr != NULL)
		*elem_addr = 0;
	if (model != NULL)
		memset(model, 0, sizeof(*model));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_PUB_GET)
		return (-1);
	if (ap.params_len != 4 && ap.params_len != 6)
		return (-1);
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params);
	return (mesh_cfg_model_id_decode(ap.params + 2, ap.params_len - 2, model));
}

/* ================================================================
 * Model subscription.
 * ================================================================ */

int
mesh_cfg_model_sub_build(uint32_t opcode, const struct mesh_cfg_model_sub *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 2 + 4];
	size_t midlen;

	if (in == NULL || !valid_element_address(in->elem_addr) ||
	    !valid_subscription_address(in->address))
		return (-1);
	if (opcode != MESH_CFG_OP_MODEL_SUB_ADD &&
	    opcode != MESH_CFG_OP_MODEL_SUB_DELETE &&
	    opcode != MESH_CFG_OP_MODEL_SUB_OVERWRITE)
		return (-1);
	put16(params, in->elem_addr);
	put16(params + 2, in->address);
	if (mesh_cfg_model_id_encode(&in->model, params + 4, &midlen) != 0)
		return (-1);
	return (wrap(opcode, params, 4 + midlen, out, outlen));
}

int
mesh_cfg_model_sub_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_model_sub *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_SUB_ADD &&
	    ap.opcode != MESH_CFG_OP_MODEL_SUB_DELETE &&
	    ap.opcode != MESH_CFG_OP_MODEL_SUB_OVERWRITE)
		return (-1);
	if (ap.params_len != 6 && ap.params_len != 8)
		return (-1);
	out->elem_addr = get16(ap.params);
	out->address = get16(ap.params + 2);
	if (mesh_cfg_model_id_decode(ap.params + 4, ap.params_len - 4,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_model_sub_del_all_build(uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 4];
	size_t midlen;

	if (model == NULL || !valid_element_address(elem_addr))
		return (-1);
	put16(params, elem_addr);
	if (mesh_cfg_model_id_encode(model, params + 2, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_SUB_DELETE_ALL, params, 2 + midlen, out,
	    outlen));
}

int
mesh_cfg_model_sub_del_all_parse(const uint8_t *in, size_t inlen,
    uint16_t *elem_addr, struct mesh_cfg_model_id *model)
{
	struct mesh_access_pdu ap;

	if (elem_addr != NULL)
		*elem_addr = 0;
	if (model != NULL)
		memset(model, 0, sizeof(*model));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_SUB_DELETE_ALL)
		return (-1);
	if (ap.params_len != 4 && ap.params_len != 6)
		return (-1);
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params);
	return (mesh_cfg_model_id_decode(ap.params + 2, ap.params_len - 2, model));
}

int
mesh_cfg_model_sub_status_build(uint8_t status,
    const struct mesh_cfg_model_sub *in, uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 2 + 2 + 4];
	size_t midlen;

	if (in == NULL)
		return (-1);
	params[0] = status;
	put16(params + 1, in->elem_addr);
	put16(params + 3, in->address);
	if (mesh_cfg_model_id_encode(&in->model, params + 5, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_SUB_STATUS, params, 5 + midlen, out,
	    outlen));
}

int
mesh_cfg_model_sub_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    struct mesh_cfg_model_sub *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (status != NULL)
		*status = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_SUB_STATUS)
		return (-1);
	if (ap.params_len != 7 && ap.params_len != 9)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	out->elem_addr = get16(ap.params + 1);
	out->address = get16(ap.params + 3);
	if (mesh_cfg_model_id_decode(ap.params + 5, ap.params_len - 5,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/* ================================================================
 * Virtual-address Model Publication / Subscription (Section 4.4.1.2.7/9/10/11).
 * ================================================================ */

int
mesh_cfg_model_pub_va_set_build(const struct mesh_cfg_model_pub_va *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 16 + 2 + 3 + 4];
	uint16_t word;
	size_t midlen;

	if (in == NULL || !valid_element_address(in->elem_addr) ||
	    in->app_idx > 0x0fff)
		return (-1);
	put16(params, in->elem_addr);
	memcpy(params + 2, in->label, 16);
	word = (uint16_t)((in->app_idx & 0x0fff) |
	    ((in->cred_flag ? 1u : 0u) << 12));
	put16(params + 18, word);
	params[20] = in->ttl;
	params[21] = in->period;
	params[22] = in->retransmit;
	if (mesh_cfg_model_id_encode(&in->model, params + 23, &midlen) != 0)
		return (-1);
	return (wrap(MESH_CFG_OP_MODEL_PUB_VA_SET, params, 23 + midlen, out,
	    outlen));
}

int
mesh_cfg_model_pub_va_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_model_pub_va *out)
{
	struct mesh_access_pdu ap;
	uint16_t word;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_PUB_VA_SET)
		return (-1);
	if (ap.params_len != 25 && ap.params_len != 27)
		return (-1);
	out->elem_addr = get16(ap.params);
	memcpy(out->label, ap.params + 2, 16);
	word = get16(ap.params + 18);
	out->app_idx = (uint16_t)(word & 0x0fff);
	out->cred_flag = (uint8_t)((word >> 12) & 0x01);
	out->ttl = ap.params[20];
	out->period = ap.params[21];
	out->retransmit = ap.params[22];
	if (mesh_cfg_model_id_decode(ap.params + 23, ap.params_len - 23,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_cfg_model_sub_va_build(uint32_t opcode,
    const struct mesh_cfg_model_sub_va *in, uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 16 + 4];
	size_t midlen;

	if (in == NULL || !valid_element_address(in->elem_addr))
		return (-1);
	if (opcode != MESH_CFG_OP_MODEL_SUB_VA_ADD &&
	    opcode != MESH_CFG_OP_MODEL_SUB_VA_DELETE &&
	    opcode != MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE)
		return (-1);
	put16(params, in->elem_addr);
	memcpy(params + 2, in->label, 16);
	if (mesh_cfg_model_id_encode(&in->model, params + 18, &midlen) != 0)
		return (-1);
	return (wrap(opcode, params, 18 + midlen, out, outlen));
}

int
mesh_cfg_model_sub_va_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_model_sub_va *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_MODEL_SUB_VA_ADD &&
	    ap.opcode != MESH_CFG_OP_MODEL_SUB_VA_DELETE &&
	    ap.opcode != MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE)
		return (-1);
	if (ap.params_len != 20 && ap.params_len != 22)
		return (-1);
	out->elem_addr = get16(ap.params);
	memcpy(out->label, ap.params + 2, 16);
	if (mesh_cfg_model_id_decode(ap.params + 18, ap.params_len - 18,
	    &out->model) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Model Subscription Get / List and Model App Get / List
 * (Section 4.4.1.2.4/5/12/13).
 * ================================================================ */

/* Model-identifier octet count implied by a SIG-vs-vendor opcode pair. */
static size_t
opcode_midlen(uint32_t opcode, int vendor)
{

	(void)opcode;
	return (vendor ? 4 : 2);
}

/* ElementAddress + ModelId "Get" shared by Subscription/App Get. */
static int
model_get_build(uint32_t opcode, int vendor, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	uint8_t params[2 + 4];
	size_t midlen;

	if (model == NULL || model->vendor != vendor ||
	    !valid_element_address(elem_addr))
		return (-1);
	put16(params, elem_addr);
	if (mesh_cfg_model_id_encode(model, params + 2, &midlen) != 0)
		return (-1);
	return (wrap(opcode, params, 2 + midlen, out, outlen));
}

static int
model_get_parse(uint32_t want_opcode, int vendor, const uint8_t *in,
    size_t inlen, uint32_t *opcode, uint16_t *elem_addr,
    struct mesh_cfg_model_id *model)
{
	struct mesh_access_pdu ap;
	size_t midlen;

	if (elem_addr != NULL)
		*elem_addr = 0;
	if (model != NULL)
		memset(model, 0, sizeof(*model));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != want_opcode)
		return (-1);
	midlen = opcode_midlen(want_opcode, vendor);
	if (ap.params_len != 2 + midlen)
		return (-1);
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (mesh_cfg_model_id_decode(ap.params + 2, midlen, model));
}

int
mesh_cfg_model_sub_get_build(uint32_t opcode, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	int vendor;

	if (opcode == MESH_CFG_OP_SIG_MODEL_SUB_GET)
		vendor = 0;
	else if (opcode == MESH_CFG_OP_VND_MODEL_SUB_GET)
		vendor = 1;
	else
		return (-1);
	return (model_get_build(opcode, vendor, elem_addr, model, out, outlen));
}

int
mesh_cfg_model_sub_get_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint16_t *elem_addr, struct mesh_cfg_model_id *model)
{

	if (opcode != NULL)
		*opcode = 0;
	if (model_get_parse(MESH_CFG_OP_SIG_MODEL_SUB_GET, 0, in, inlen, opcode,
	    elem_addr, model) == 0)
		return (0);
	return (model_get_parse(MESH_CFG_OP_VND_MODEL_SUB_GET, 1, in, inlen,
	    opcode, elem_addr, model));
}

int
mesh_cfg_model_app_get_build(uint32_t opcode, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	int vendor;

	if (opcode == MESH_CFG_OP_SIG_MODEL_APP_GET)
		vendor = 0;
	else if (opcode == MESH_CFG_OP_VND_MODEL_APP_GET)
		vendor = 1;
	else
		return (-1);
	return (model_get_build(opcode, vendor, elem_addr, model, out, outlen));
}

int
mesh_cfg_model_app_get_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint16_t *elem_addr, struct mesh_cfg_model_id *model)
{

	if (opcode != NULL)
		*opcode = 0;
	if (model_get_parse(MESH_CFG_OP_SIG_MODEL_APP_GET, 0, in, inlen, opcode,
	    elem_addr, model) == 0)
		return (0);
	return (model_get_parse(MESH_CFG_OP_VND_MODEL_APP_GET, 1, in, inlen,
	    opcode, elem_addr, model));
}

/* Subscription List: the trailing addresses are 2-octet little-endian. */
int
mesh_cfg_model_sub_list_build(uint32_t opcode, uint8_t status,
    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
    const uint16_t *addrs, size_t n, uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 2 + 4 + MESH_CFG_MAX_ADDRESSES * 2];
	size_t midlen, off, i;
	int vendor;

	if (opcode == MESH_CFG_OP_SIG_MODEL_SUB_LIST)
		vendor = 0;
	else if (opcode == MESH_CFG_OP_VND_MODEL_SUB_LIST)
		vendor = 1;
	else
		return (-1);
	if (model == NULL || model->vendor != vendor)
		return (-1);
	if (n > MESH_CFG_MAX_ADDRESSES || (n != 0 && addrs == NULL))
		return (-1);
	params[0] = status;
	put16(params + 1, elem_addr);
	if (mesh_cfg_model_id_encode(model, params + 3, &midlen) != 0)
		return (-1);
	off = 3 + midlen;
	for (i = 0; i < n; i++) {
		put16(params + off, addrs[i]);
		off += 2;
	}
	return (wrap(opcode, params, off, out, outlen));
}

int
mesh_cfg_model_sub_list_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
    uint16_t *addrs, size_t max, size_t *n)
{
	struct mesh_access_pdu ap;
	size_t midlen, off, cnt;
	int vendor;

	if (status != NULL)
		*status = 0;
	if (elem_addr != NULL)
		*elem_addr = 0;
	if (opcode != NULL)
		*opcode = 0;
	if (n != NULL)
		*n = 0;
	if (model != NULL)
		memset(model, 0, sizeof(*model));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode == MESH_CFG_OP_SIG_MODEL_SUB_LIST)
		vendor = 0;
	else if (ap.opcode == MESH_CFG_OP_VND_MODEL_SUB_LIST)
		vendor = 1;
	else
		return (-1);
	midlen = opcode_midlen(ap.opcode, vendor);
	if (ap.params_len < 3 + midlen)
		return (-1);
	if (((ap.params_len - 3 - midlen) % 2) != 0)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params + 1);
	if (mesh_cfg_model_id_decode(ap.params + 3, midlen, model) != 0)
		return (-1);
	off = 3 + midlen;
	cnt = 0;
	while (off < ap.params_len) {
		if (addrs == NULL || cnt >= max)
			return (-1);
		addrs[cnt++] = get16(ap.params + off);
		off += 2;
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	if (n != NULL)
		*n = cnt;
	return (0);
}

/* App List: the trailing AppKeyIndexes use the two-per-3-octet packing. */
int
mesh_cfg_model_app_list_build(uint32_t opcode, uint8_t status,
    uint16_t elem_addr, const struct mesh_cfg_model_id *model,
    const uint16_t *app_idx, size_t n, uint8_t *out, size_t *outlen)
{
	uint8_t params[1 + 2 + 4 + MESH_CFG_MAX_KEY_INDEXES * 3];
	size_t midlen, plen;
	int vendor;

	if (opcode == MESH_CFG_OP_SIG_MODEL_APP_LIST)
		vendor = 0;
	else if (opcode == MESH_CFG_OP_VND_MODEL_APP_LIST)
		vendor = 1;
	else
		return (-1);
	if (model == NULL || model->vendor != vendor)
		return (-1);
	if (n > MESH_CFG_MAX_KEY_INDEXES || (n != 0 && app_idx == NULL))
		return (-1);
	params[0] = status;
	put16(params + 1, elem_addr);
	if (mesh_cfg_model_id_encode(model, params + 3, &midlen) != 0)
		return (-1);
	plen = keyidx_list_pack(app_idx, n, params + 3 + midlen,
	    sizeof(params) - 3 - midlen);
	if (plen == (size_t)-1)
		return (-1);
	return (wrap(opcode, params, 3 + midlen + plen, out, outlen));
}

int
mesh_cfg_model_app_list_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
    uint16_t *app_idx, size_t max, size_t *n)
{
	struct mesh_access_pdu ap;
	size_t midlen;
	int vendor;

	if (status != NULL)
		*status = 0;
	if (elem_addr != NULL)
		*elem_addr = 0;
	if (opcode != NULL)
		*opcode = 0;
	if (n != NULL)
		*n = 0;
	if (model != NULL)
		memset(model, 0, sizeof(*model));
	if (app_idx == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode == MESH_CFG_OP_SIG_MODEL_APP_LIST)
		vendor = 0;
	else if (ap.opcode == MESH_CFG_OP_VND_MODEL_APP_LIST)
		vendor = 1;
	else
		return (-1);
	midlen = opcode_midlen(ap.opcode, vendor);
	if (ap.params_len < 3 + midlen)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params + 1);
	if (mesh_cfg_model_id_decode(ap.params + 3, midlen, model) != 0)
		return (-1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (keyidx_list_unpack(ap.params + 3 + midlen,
	    ap.params_len - 3 - midlen, app_idx, max, n));
}

/* ================================================================
 * Config Network Transmit (Section 4.4.1.2.x).
 * ================================================================ */

int
mesh_cfg_net_transmit_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_NET_TRANSMIT_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_net_transmit_set_build(uint32_t opcode,
    const struct mesh_cfg_net_transmit *in, uint8_t *out, size_t *outlen)
{
	uint8_t v;

	if (in == NULL)
		return (-1);
	if (opcode != MESH_CFG_OP_NET_TRANSMIT_SET &&
	    opcode != MESH_CFG_OP_NET_TRANSMIT_STATUS)
		return (-1);
	if (in->count > 0x07 || in->interval_steps > 0x1f)
		return (-1);
	v = (uint8_t)((in->count & 0x07) | ((in->interval_steps & 0x1f) << 3));
	return (wrap(opcode, &v, 1, out, outlen));
}

int
mesh_cfg_net_transmit_set_parse(const uint8_t *in, size_t inlen,
    uint32_t *opcode, struct mesh_cfg_net_transmit *out)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NET_TRANSMIT_SET &&
	    ap.opcode != MESH_CFG_OP_NET_TRANSMIT_STATUS)
		return (-1);
	if (ap.params_len != 1)
		return (-1);
	out->count = (uint8_t)(ap.params[0] & 0x07);
	out->interval_steps = (uint8_t)((ap.params[0] >> 3) & 0x1f);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Config Key Refresh Phase (Section 4.4.1.2.x).
 * ================================================================ */

int
mesh_cfg_kr_phase_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (net_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	return (wrap(MESH_CFG_OP_KEY_REFRESH_PHASE_GET, params, 2, out, outlen));
}

int
mesh_cfg_kr_phase_get_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_KEY_REFRESH_PHASE_GET || ap.params_len != 2)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	return (0);
}

int
mesh_cfg_kr_phase_set_build(uint16_t net_idx, uint8_t transition, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[3];

	if (net_idx > 0x0fff)
		return (-1);
	if (transition != MESH_CFG_KR_TRANSITION_2 &&
	    transition != MESH_CFG_KR_TRANSITION_3)
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	params[2] = transition;
	return (wrap(MESH_CFG_OP_KEY_REFRESH_PHASE_SET, params, 3, out, outlen));
}

int
mesh_cfg_kr_phase_set_parse(const uint8_t *in, size_t inlen, uint16_t *net_idx,
    uint8_t *transition)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (transition != NULL)
		*transition = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_KEY_REFRESH_PHASE_SET || ap.params_len != 3)
		return (-1);
	if (ap.params[2] != MESH_CFG_KR_TRANSITION_2 &&
	    ap.params[2] != MESH_CFG_KR_TRANSITION_3)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	if (transition != NULL)
		*transition = ap.params[2];
	return (0);
}

int
mesh_cfg_kr_phase_status_build(uint8_t status, uint16_t net_idx, uint8_t phase,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[4];

	if (net_idx > 0x0fff)
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack1(params + 1, net_idx);
	params[3] = phase;
	return (wrap(MESH_CFG_OP_KEY_REFRESH_PHASE_STATUS, params, 4, out,
	    outlen));
}

int
mesh_cfg_kr_phase_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *net_idx, uint8_t *phase)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (net_idx != NULL)
		*net_idx = 0;
	if (phase != NULL)
		*phase = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_KEY_REFRESH_PHASE_STATUS ||
	    ap.params_len != 4)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params + 1);
	if (phase != NULL)
		*phase = ap.params[3];
	return (0);
}

/* ================================================================
 * Config Node Identity (Section 4.4.1.2.x).
 * ================================================================ */

int
mesh_cfg_node_identity_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (net_idx > 0x0fff)
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	return (wrap(MESH_CFG_OP_NODE_IDENTITY_GET, params, 2, out, outlen));
}

int
mesh_cfg_node_identity_get_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NODE_IDENTITY_GET || ap.params_len != 2)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	return (0);
}

int
mesh_cfg_node_identity_set_build(uint16_t net_idx, uint8_t identity,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[3];

	if (net_idx > 0x0fff || (identity != MESH_CFG_NODE_IDENTITY_STOPPED &&
	    identity != MESH_CFG_NODE_IDENTITY_RUNNING))
		return (-1);
	mesh_cfg_keyidx_pack1(params, net_idx);
	params[2] = identity;
	return (wrap(MESH_CFG_OP_NODE_IDENTITY_SET, params, 3, out, outlen));
}

int
mesh_cfg_node_identity_set_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx, uint8_t *identity)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (identity != NULL)
		*identity = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NODE_IDENTITY_SET || ap.params_len != 3)
		return (-1);
	if (ap.params[2] != MESH_CFG_NODE_IDENTITY_STOPPED &&
	    ap.params[2] != MESH_CFG_NODE_IDENTITY_RUNNING)
		return (-1);
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params);
	if (identity != NULL)
		*identity = ap.params[2];
	return (0);
}

int
mesh_cfg_node_identity_status_build(uint8_t status, uint16_t net_idx,
    uint8_t identity, uint8_t *out, size_t *outlen)
{
	uint8_t params[4];

	if (net_idx > 0x0fff)
		return (-1);
	params[0] = status;
	mesh_cfg_keyidx_pack1(params + 1, net_idx);
	params[3] = identity;
	return (wrap(MESH_CFG_OP_NODE_IDENTITY_STATUS, params, 4, out, outlen));
}

int
mesh_cfg_node_identity_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, uint16_t *net_idx, uint8_t *identity)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (net_idx != NULL)
		*net_idx = 0;
	if (identity != NULL)
		*identity = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_NODE_IDENTITY_STATUS || ap.params_len != 4)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (net_idx != NULL)
		*net_idx = mesh_cfg_keyidx_unpack1(ap.params + 1);
	if (identity != NULL)
		*identity = ap.params[3];
	return (0);
}

/* ================================================================
 * Config Low Power Node PollTimeout (Section 4.4.1.2.x).
 * ================================================================ */

int
mesh_cfg_lpn_polltimeout_get_build(uint16_t lpn_addr, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[2];

	if (!mesh_addr_is_unicast(lpn_addr))
		return (-1);
	put16(params, lpn_addr);
	return (wrap(MESH_CFG_OP_LPN_POLLTIMEOUT_GET, params, 2, out, outlen));
}

int
mesh_cfg_lpn_polltimeout_get_parse(const uint8_t *in, size_t inlen,
    uint16_t *lpn_addr)
{
	struct mesh_access_pdu ap;

	if (lpn_addr != NULL)
		*lpn_addr = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_LPN_POLLTIMEOUT_GET || ap.params_len != 2)
		return (-1);
	if (lpn_addr != NULL)
		*lpn_addr = get16(ap.params);
	return (0);
}

int
mesh_cfg_lpn_polltimeout_status_build(uint16_t lpn_addr, uint32_t poll_timeout,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[5];

	if (poll_timeout > 0xffffff)
		return (-1);
	put16(params, lpn_addr);
	/* PollTimeout: 3 octets, little-endian, units of 100 ms. */
	params[2] = (uint8_t)(poll_timeout & 0xff);
	params[3] = (uint8_t)((poll_timeout >> 8) & 0xff);
	params[4] = (uint8_t)((poll_timeout >> 16) & 0xff);
	return (wrap(MESH_CFG_OP_LPN_POLLTIMEOUT_STATUS, params, 5, out, outlen));
}

int
mesh_cfg_lpn_polltimeout_status_parse(const uint8_t *in, size_t inlen,
    uint16_t *lpn_addr, uint32_t *poll_timeout)
{
	struct mesh_access_pdu ap;

	if (lpn_addr != NULL)
		*lpn_addr = 0;
	if (poll_timeout != NULL)
		*poll_timeout = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_LPN_POLLTIMEOUT_STATUS ||
	    ap.params_len != 5)
		return (-1);
	if (lpn_addr != NULL)
		*lpn_addr = get16(ap.params);
	if (poll_timeout != NULL)
		*poll_timeout = (uint32_t)ap.params[2] |
		    ((uint32_t)ap.params[3] << 8) |
		    ((uint32_t)ap.params[4] << 16);
	return (0);
}

/* ================================================================
 * Node-wide single-octet state and empty messages.
 * ================================================================ */

int
mesh_cfg_u8_state_build(uint32_t opcode, uint8_t value, uint8_t *out,
    size_t *outlen)
{

	switch (opcode) {
	case MESH_CFG_OP_BEACON_SET:
	case MESH_CFG_OP_BEACON_STATUS:
	case MESH_CFG_OP_DEFAULT_TTL_SET:
	case MESH_CFG_OP_DEFAULT_TTL_STATUS:
	case MESH_CFG_OP_GATT_PROXY_SET:
	case MESH_CFG_OP_GATT_PROXY_STATUS:
	case MESH_CFG_OP_FRIEND_SET:
	case MESH_CFG_OP_FRIEND_STATUS:
		return (wrap(opcode, &value, 1, out, outlen));
	default:
		return (-1);
	}
}

int
mesh_cfg_u8_state_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *value)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (value != NULL)
		*value = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	switch (ap.opcode) {
	case MESH_CFG_OP_BEACON_SET:
	case MESH_CFG_OP_BEACON_STATUS:
	case MESH_CFG_OP_DEFAULT_TTL_SET:
	case MESH_CFG_OP_DEFAULT_TTL_STATUS:
	case MESH_CFG_OP_GATT_PROXY_SET:
	case MESH_CFG_OP_GATT_PROXY_STATUS:
	case MESH_CFG_OP_FRIEND_SET:
	case MESH_CFG_OP_FRIEND_STATUS:
		break;
	default:
		return (-1);
	}
	if (ap.params_len != 1)
		return (-1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	if (value != NULL)
		*value = ap.params[0];
	return (0);
}

int
mesh_cfg_empty_build(uint32_t opcode, uint8_t *out, size_t *outlen)
{

	return (wrap(opcode, NULL, 0, out, outlen));
}

int
mesh_cfg_relay_set_build(uint32_t opcode, const struct mesh_cfg_relay *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	if (in == NULL)
		return (-1);
	if (opcode != MESH_CFG_OP_RELAY_SET && opcode != MESH_CFG_OP_RELAY_STATUS)
		return (-1);
	params[0] = in->relay;
	params[1] = in->retransmit;
	return (wrap(opcode, params, sizeof(params), out, outlen));
}

int
mesh_cfg_relay_set_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_relay *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (opcode != NULL)
		*opcode = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_RELAY_SET &&
	    ap.opcode != MESH_CFG_OP_RELAY_STATUS)
		return (-1);
	if (ap.params_len != 2)
		return (-1);
	if (ap.opcode == MESH_CFG_OP_RELAY_SET && ap.params[0] > 1)
		return (-1);
	out->relay = ap.params[0];
	out->retransmit = ap.params[1];
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_node_reset_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_NODE_RESET, NULL, 0, out, outlen));
}

int
mesh_cfg_node_reset_status_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_NODE_RESET_STATUS, NULL, 0, out, outlen));
}

/* ================================================================
 * Minimal Configuration Server state (Section 4.4.1.1).
 * ================================================================ */

void
mesh_cfg_server_init(struct mesh_cfg_server_state *s)
{

	if (s == NULL)
		return;
	memset(s, 0, sizeof(*s));
	s->default_ttl = 0;	/* device default; caller may raise it */
	s->beacon = 0;
	s->gatt_proxy = 0;
	s->friend = 0;
	s->relay = 0;
	s->relay_retransmit = 0;
}

int
mesh_cfg_default_ttl_valid(uint8_t ttl)
{

	/* Default TTL is 0 or 2..127; the value 1 and >127 are prohibited. */
	if (ttl == 1 || ttl > 127)
		return (0);
	return (1);
}
