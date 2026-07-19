/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Protocol 1.1 additional Configuration model codecs
 * (MshPRT_v1.1 Sections 4.2-4.4). See mesh_cfg_v11.h for model wire
 * layouts.  Each _build() wraps the assembled parameters with the access-layer
 * opcode via mesh_access_pdu_build(); each _parse() runs mesh_access_pdu_parse()
 * first, checks the opcode, then decodes the parameters.  Outputs are zeroed on
 * failure.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_cfg_v11.h"

/* Little-endian 16-bit helpers. */
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

/* Finish a build: wrap assembled params with the opcode. */
static int
wrap(uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *out,
    size_t *outlen)
{

	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

/* Parse an Access PDU and require a specific opcode; report the parameters. */
static int
unwrap(const uint8_t *in, size_t inlen, uint32_t opcode,
    struct mesh_access_pdu *ap)
{

	if (in == NULL || ap == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, ap) != 0)
		return (-1);
	if (ap->opcode != opcode)
		return (-1);
	return (0);
}

/* ================================================================
 * SAR Transmitter (Section 4.2.29).
 * ================================================================ */

int
mesh_cfg_sar_tx_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_SAR_TRANSMITTER_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_sar_tx_build(uint32_t opcode, const struct mesh_cfg_sar_transmitter *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || in->seg_interval_step > 0x0f ||
	    in->unicast_retrans_count > 0x0f ||
	    in->unicast_retrans_without_progress_count > 0x0f ||
	    in->unicast_retrans_interval_step > 0x0f ||
	    in->unicast_retrans_interval_increment > 0x0f ||
	    in->multicast_retrans_count > 0x0f ||
	    in->multicast_retrans_interval_step > 0x0f)
		return (-1);
	if (opcode != MESH_CFG_OP_SAR_TRANSMITTER_SET &&
	    opcode != MESH_CFG_OP_SAR_TRANSMITTER_STATUS)
		return (-1);
	p[0] = (uint8_t)((in->seg_interval_step & 0x0f) |
	    ((in->unicast_retrans_count & 0x0f) << 4));
	p[1] = (uint8_t)((in->unicast_retrans_without_progress_count & 0x0f) |
	    ((in->unicast_retrans_interval_step & 0x0f) << 4));
	p[2] = (uint8_t)((in->unicast_retrans_interval_increment & 0x0f) |
	    ((in->multicast_retrans_count & 0x0f) << 4));
	p[3] = (uint8_t)(in->multicast_retrans_interval_step & 0x0f);
	return (wrap(opcode, p, sizeof(p), out, outlen));
}

int
mesh_cfg_sar_tx_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_sar_transmitter *out)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_SAR_TRANSMITTER_SET &&
	    ap.opcode != MESH_CFG_OP_SAR_TRANSMITTER_STATUS)
		return (-1);
	if (ap.params_len != 4)
		return (-1);
	p = ap.params;
	out->seg_interval_step = p[0] & 0x0f;
	out->unicast_retrans_count = (p[0] >> 4) & 0x0f;
	out->unicast_retrans_without_progress_count = p[1] & 0x0f;
	out->unicast_retrans_interval_step = (p[1] >> 4) & 0x0f;
	out->unicast_retrans_interval_increment = p[2] & 0x0f;
	out->multicast_retrans_count = (p[2] >> 4) & 0x0f;
	out->multicast_retrans_interval_step = p[3] & 0x0f;
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * SAR Receiver (Section 4.2.30).
 * ================================================================ */

int
mesh_cfg_sar_rx_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_SAR_RECEIVER_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_sar_rx_build(uint32_t opcode, const struct mesh_cfg_sar_receiver *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL || in->segments_threshold > 0x1f ||
	    in->ack_delay_increment > 0x07 || in->discard_timeout > 0x0f ||
	    in->rx_segment_interval_step > 0x0f ||
	    in->ack_retrans_count > 0x03)
		return (-1);
	if (opcode != MESH_CFG_OP_SAR_RECEIVER_SET &&
	    opcode != MESH_CFG_OP_SAR_RECEIVER_STATUS)
		return (-1);
	p[0] = (uint8_t)((in->segments_threshold & 0x1f) |
	    ((in->ack_delay_increment & 0x07) << 5));
	p[1] = (uint8_t)((in->discard_timeout & 0x0f) |
	    ((in->rx_segment_interval_step & 0x0f) << 4));
	p[2] = (uint8_t)(in->ack_retrans_count & 0x03);
	return (wrap(opcode, p, sizeof(p), out, outlen));
}

int
mesh_cfg_sar_rx_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_sar_receiver *out)
{
	struct mesh_access_pdu ap;
	const uint8_t *p;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_SAR_RECEIVER_SET &&
	    ap.opcode != MESH_CFG_OP_SAR_RECEIVER_STATUS)
		return (-1);
	if (ap.params_len != 3)
		return (-1);
	p = ap.params;
	out->segments_threshold = p[0] & 0x1f;
	out->ack_delay_increment = (p[0] >> 5) & 0x07;
	out->discard_timeout = p[1] & 0x0f;
	out->rx_segment_interval_step = (p[1] >> 4) & 0x0f;
	out->ack_retrans_count = p[2] & 0x03;
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * On-Demand Private Proxy Server.
 * ================================================================ */

int
mesh_cfg_od_priv_proxy_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_OD_PRIV_PROXY_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_od_priv_proxy_build(uint32_t opcode, uint8_t value, uint8_t *out,
    size_t *outlen)
{

	if (opcode != MESH_CFG_OP_OD_PRIV_PROXY_SET &&
	    opcode != MESH_CFG_OP_OD_PRIV_PROXY_STATUS)
		return (-1);
	return (wrap(opcode, &value, 1, out, outlen));
}

int
mesh_cfg_od_priv_proxy_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *value)
{
	struct mesh_access_pdu ap;

	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_OD_PRIV_PROXY_SET &&
	    ap.opcode != MESH_CFG_OP_OD_PRIV_PROXY_STATUS)
		return (-1);
	if (ap.params_len != 1)
		return (-1);
	if (value != NULL)
		*value = ap.params[0];
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Solicitation PDU RPL Configuration Server.
 * ================================================================ */

/* Encode an Address Range: le16(start | length-present<<15) + optional len. */
static int
addr_range_valid(const struct mesh_cfg_addr_range *r)
{

	return (r != NULL && r->range_start != 0 &&
	    r->range_start <= 0x7fff && r->range_length != 0 &&
	    (uint32_t)r->range_start + r->range_length <= 0x8000);
}

static size_t
addr_range_encode(const struct mesh_cfg_addr_range *r, uint8_t *p)
{
	uint16_t word = (uint16_t)(r->range_start & 0x7fff);

	if (r->range_length > 1) {
		put16(p, (uint16_t)(word | 0x8000));
		p[2] = r->range_length;
		return (3);
	}
	put16(p, word);
	return (2);
}

/* Decode an Address Range; returns the octets consumed, or 0 on error. */
static size_t
addr_range_decode(const uint8_t *p, size_t len, struct mesh_cfg_addr_range *r)
{
	uint16_t word;

	if (len < 2)
		return (0);
	word = get16(p);
	r->range_start = word & 0x7fff;
	if (word & 0x8000) {
		if (len < 3)
			return (0);
		r->range_length = p[2];
		return (addr_range_valid(r) && r->range_length >= 2 ? 3 : 0);
	}
	r->range_length = 1;
	return (addr_range_valid(r) ? 2 : 0);
}

int
mesh_cfg_sol_pdu_rpl_clear_build(uint32_t opcode,
    const struct mesh_cfg_addr_range *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[3];
	size_t n;

	if (!addr_range_valid(in))
		return (-1);
	if (opcode != MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR &&
	    opcode != MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR_UNACK)
		return (-1);
	n = addr_range_encode(in, p);
	return (wrap(opcode, p, n, out, outlen));
}

int
mesh_cfg_sol_pdu_rpl_clear_parse(const uint8_t *in, size_t inlen,
    uint32_t *opcode, struct mesh_cfg_addr_range *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR &&
	    ap.opcode != MESH_CFG_OP_SOL_PDU_RPL_ITEMS_CLEAR_UNACK)
		return (-1);
	if (addr_range_decode(ap.params, ap.params_len, out) != ap.params_len)
		return (-1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_sol_pdu_rpl_status_build(const struct mesh_cfg_addr_range *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];
	size_t n;

	if (!addr_range_valid(in))
		return (-1);
	n = addr_range_encode(in, p);
	return (wrap(MESH_CFG_OP_SOL_PDU_RPL_ITEMS_STATUS, p, n, out, outlen));
}

int
mesh_cfg_sol_pdu_rpl_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_addr_range *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_SOL_PDU_RPL_ITEMS_STATUS, &ap) != 0)
		return (-1);
	if (addr_range_decode(ap.params, ap.params_len, out) != ap.params_len)
		return (-1);
	return (0);
}

/* ================================================================
 * Opcodes Aggregator Server.
 * ================================================================ */

int
mesh_cfg_agg_len_encode(size_t len, uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	if (len <= 0x7f) {
		out[0] = (uint8_t)(len << 1);		/* Length_Format bit 0 = 0 */
		*outlen = 1;
		return (0);
	}
	if (len > 0x7fff)
		return (-1);
	put16(out, (uint16_t)((len << 1) | 0x0001));	/* Length_Format bit 0 = 1 */
	*outlen = 2;
	return (0);
}

int
mesh_cfg_agg_len_decode(const uint8_t *in, size_t inlen, size_t *len,
    size_t *prefix)
{

	if (in == NULL || len == NULL || prefix == NULL || inlen < 1)
		return (-1);
	if ((in[0] & 0x01) == 0) {
		*len = (size_t)(in[0] >> 1);
		*prefix = 1;
		return (0);
	}
	if (inlen < 2)
		return (-1);
	*len = (size_t)(get16(in) >> 1);
	*prefix = 2;
	return (0);
}

/* Serialise the length-prefixed item list into p; returns bytes written or 0. */
static size_t
agg_items_encode(const struct mesh_cfg_agg_item *items, size_t n, uint8_t *p,
    size_t cap)
{
	size_t i, off = 0;

	for (i = 0; i < n; i++) {
		uint8_t pre[2];
		size_t prelen;

		if (mesh_cfg_agg_len_encode(items[i].len, pre, &prelen) != 0)
			return (0);
		if (off + prelen + items[i].len > cap)
			return (0);
		memcpy(p + off, pre, prelen);
		off += prelen;
		if (items[i].len != 0 && items[i].data == NULL)
			return (0);
		if (items[i].len != 0)
			memcpy(p + off, items[i].data, items[i].len);
		off += items[i].len;
	}
	return (off);
}

/* Parse a length-prefixed item list; views point into in. */
static int
agg_items_decode(const uint8_t *in, size_t inlen, struct mesh_cfg_agg_item *items,
    size_t max, size_t *n)
{
	size_t off = 0, cnt = 0;

	while (off < inlen) {
		size_t len, prefix;

		if (mesh_cfg_agg_len_decode(in + off, inlen - off, &len,
		    &prefix) != 0)
			return (-1);
		off += prefix;
		if (off + len > inlen)
			return (-1);
		if (cnt >= max)
			return (-1);
		items[cnt].data = (len != 0) ? in + off : NULL;
		items[cnt].len = len;
		cnt++;
		off += len;
	}
	if (n != NULL)
		*n = cnt;
	return (0);
}

int
mesh_cfg_agg_seq_build(uint16_t elem_addr, const struct mesh_cfg_agg_item *items,
    size_t n, uint8_t *out, size_t *outlen)
{
	uint8_t p[MESH_ACCESS_PARAMS_MAX];
	size_t off;

	if ((items == NULL && n != 0) || n > MESH_CFG_AGG_MAX_ITEMS)
		return (-1);
	put16(p, elem_addr);
	off = 2;
	if (n != 0) {
		size_t w = agg_items_encode(items, n, p + off, sizeof(p) - off);

		if (w == 0)
			return (-1);
		off += w;
	}
	return (wrap(MESH_CFG_OP_AGGREGATOR_SEQUENCE, p, off, out, outlen));
}

int
mesh_cfg_agg_seq_parse(const uint8_t *in, size_t inlen, uint16_t *elem_addr,
    struct mesh_cfg_agg_item *items, size_t max, size_t *n)
{
	struct mesh_access_pdu ap;

	if (items == NULL)
		return (-1);
	if (unwrap(in, inlen, MESH_CFG_OP_AGGREGATOR_SEQUENCE, &ap) != 0)
		return (-1);
	if (ap.params_len < 2)
		return (-1);
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params);
	/*
	 * Item views must point into the caller's input buffer (not the parsed
	 * PDU's local params copy), so they stay valid after this returns.  The
	 * parameters begin at in + opcode_len.
	 */
	return (agg_items_decode(in + ap.opcode_len + 2, ap.params_len - 2, items,
	    max, n));
}

int
mesh_cfg_agg_status_build(uint8_t status, uint16_t elem_addr,
    const struct mesh_cfg_agg_item *items, size_t n, uint8_t *out, size_t *outlen)
{
	uint8_t p[MESH_ACCESS_PARAMS_MAX];
	size_t off;

	if ((items == NULL && n != 0) || n > MESH_CFG_AGG_MAX_ITEMS)
		return (-1);
	p[0] = status;
	put16(p + 1, elem_addr);
	off = 3;
	if (n != 0) {
		size_t w = agg_items_encode(items, n, p + off, sizeof(p) - off);

		if (w == 0)
			return (-1);
		off += w;
	}
	return (wrap(MESH_CFG_OP_AGGREGATOR_STATUS, p, off, out, outlen));
}

int
mesh_cfg_agg_status_parse(const uint8_t *in, size_t inlen, uint8_t *status,
    uint16_t *elem_addr, struct mesh_cfg_agg_item *items, size_t max, size_t *n)
{
	struct mesh_access_pdu ap;

	if (items == NULL)
		return (-1);
	if (unwrap(in, inlen, MESH_CFG_OP_AGGREGATOR_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len < 3)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	if (elem_addr != NULL)
		*elem_addr = get16(ap.params + 1);
	/* Item views point into the caller's buffer (see mesh_cfg_agg_seq_parse). */
	return (agg_items_decode(in + ap.opcode_len + 3, ap.params_len - 3, items,
	    max, n));
}

/* ================================================================
 * Large Composition Data Server (Large Composition Data / Models Metadata).
 * ================================================================ */

int
mesh_cfg_lcd_get_build(uint32_t opcode, const struct mesh_cfg_lcd_get *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL)
		return (-1);
	if (opcode != MESH_CFG_OP_LARGE_COMP_DATA_GET &&
	    opcode != MESH_CFG_OP_MODELS_METADATA_GET)
		return (-1);
	p[0] = in->page;
	put16(p + 1, in->offset);
	return (wrap(opcode, p, sizeof(p), out, outlen));
}

int
mesh_cfg_lcd_get_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_lcd_get *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_LARGE_COMP_DATA_GET &&
	    ap.opcode != MESH_CFG_OP_MODELS_METADATA_GET)
		return (-1);
	if (ap.params_len != 3)
		return (-1);
	out->page = ap.params[0];
	out->offset = get16(ap.params + 1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_lcd_status_build(uint32_t opcode, const struct mesh_cfg_lcd_status *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[5 + MESH_CFG_LCD_DATA_MAX];

	if (in == NULL || in->data_len > MESH_CFG_LCD_DATA_MAX)
		return (-1);
	if (opcode != MESH_CFG_OP_LARGE_COMP_DATA_STATUS &&
	    opcode != MESH_CFG_OP_MODELS_METADATA_STATUS)
		return (-1);
	p[0] = in->page;
	put16(p + 1, in->offset);
	put16(p + 3, in->total_size);
	if (in->data_len != 0)
		memcpy(p + 5, in->data, in->data_len);
	return (wrap(opcode, p, 5 + in->data_len, out, outlen));
}

int
mesh_cfg_lcd_status_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_cfg_lcd_status *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_LARGE_COMP_DATA_STATUS &&
	    ap.opcode != MESH_CFG_OP_MODELS_METADATA_STATUS)
		return (-1);
	if (ap.params_len < 5 || ap.params_len - 5 > MESH_CFG_LCD_DATA_MAX)
		return (-1);
	out->page = ap.params[0];
	out->offset = get16(ap.params + 1);
	out->total_size = get16(ap.params + 3);
	out->data_len = ap.params_len - 5;
	if (out->data_len != 0)
		memcpy(out->data, ap.params + 5, out->data_len);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Private Beacon Server.
 * ================================================================ */

int
mesh_cfg_priv_beacon_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_PRIV_BEACON_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_priv_beacon_set_build(const struct mesh_cfg_priv_beacon *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[2];
	size_t n;

	if (in == NULL || in->private_beacon > 1)
		return (-1);
	p[0] = in->private_beacon;
	n = 1;
	if (in->has_random_update) {
		p[1] = in->random_update_interval_steps;
		n = 2;
	}
	return (wrap(MESH_CFG_OP_PRIV_BEACON_SET, p, n, out, outlen));
}

int
mesh_cfg_priv_beacon_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_priv_beacon *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PRIV_BEACON_SET, &ap) != 0)
		return (-1);
	if (ap.params_len != 1 && ap.params_len != 2)
		return (-1);
	out->private_beacon = ap.params[0];
	if (out->private_beacon > 1)
		return (-1);
	if (ap.params_len == 2) {
		out->random_update_interval_steps = ap.params[1];
		out->has_random_update = 1;
	}
	return (0);
}

int
mesh_cfg_priv_beacon_status_build(const struct mesh_cfg_priv_beacon *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[2];

	if (in == NULL || in->private_beacon > 1)
		return (-1);
	p[0] = in->private_beacon;
	p[1] = in->random_update_interval_steps;
	return (wrap(MESH_CFG_OP_PRIV_BEACON_STATUS, p, sizeof(p), out, outlen));
}

int
mesh_cfg_priv_beacon_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_priv_beacon *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PRIV_BEACON_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len != 2)
		return (-1);
	out->private_beacon = ap.params[0];
	if (out->private_beacon > 1)
		return (-1);
	out->random_update_interval_steps = ap.params[1];
	out->has_random_update = 1;
	return (0);
}

int
mesh_cfg_priv_gatt_proxy_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_CFG_OP_PRIV_GATT_PROXY_GET, NULL, 0, out, outlen));
}

int
mesh_cfg_priv_gatt_proxy_build(uint32_t opcode, uint8_t value, uint8_t *out,
    size_t *outlen)
{

	if (opcode != MESH_CFG_OP_PRIV_GATT_PROXY_SET &&
	    opcode != MESH_CFG_OP_PRIV_GATT_PROXY_STATUS)
		return (-1);
	if ((opcode == MESH_CFG_OP_PRIV_GATT_PROXY_SET && value > 1) ||
	    value > MESH_CFG_PRIV_IDENTITY_NOT_SUPPORTED)
		return (-1);
	return (wrap(opcode, &value, 1, out, outlen));
}

int
mesh_cfg_priv_gatt_proxy_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *value)
{
	struct mesh_access_pdu ap;

	if (in == NULL || mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_PRIV_GATT_PROXY_SET &&
	    ap.opcode != MESH_CFG_OP_PRIV_GATT_PROXY_STATUS)
		return (-1);
	if (ap.params_len != 1)
		return (-1);
	if ((ap.opcode == MESH_CFG_OP_PRIV_GATT_PROXY_SET && ap.params[0] > 1) ||
	    ap.params[0] > MESH_CFG_PRIV_IDENTITY_NOT_SUPPORTED)
		return (-1);
	if (value != NULL)
		*value = ap.params[0];
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

int
mesh_cfg_priv_node_identity_get_build(uint16_t net_idx, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];

	if (net_idx > 0x0fff)
		return (-1);
	put16(p, net_idx);
	return (wrap(MESH_CFG_OP_PRIV_NODE_IDENTITY_GET, p, sizeof(p), out,
	    outlen));
}

int
mesh_cfg_priv_node_identity_get_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (unwrap(in, inlen, MESH_CFG_OP_PRIV_NODE_IDENTITY_GET, &ap) != 0)
		return (-1);
	if (ap.params_len != 2)
		return (-1);
	if (net_idx != NULL)
		*net_idx = get16(ap.params) & 0x0fff;
	return (0);
}

int
mesh_cfg_priv_node_identity_set_build(
    const struct mesh_cfg_priv_node_identity *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL || in->net_idx > 0x0fff ||
	    in->identity > MESH_CFG_PRIV_IDENTITY_RUNNING)
		return (-1);
	put16(p, (uint16_t)(in->net_idx & 0x0fff));
	p[2] = in->identity;
	return (wrap(MESH_CFG_OP_PRIV_NODE_IDENTITY_SET, p, sizeof(p), out,
	    outlen));
}

int
mesh_cfg_priv_node_identity_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_priv_node_identity *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PRIV_NODE_IDENTITY_SET, &ap) != 0)
		return (-1);
	if (ap.params_len != 3)
		return (-1);
	out->net_idx = get16(ap.params) & 0x0fff;
	out->identity = ap.params[2];
	if (out->identity > MESH_CFG_PRIV_IDENTITY_RUNNING)
		return (-1);
	return (0);
}

int
mesh_cfg_priv_node_identity_status_build(uint8_t status,
    const struct mesh_cfg_priv_node_identity *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || in->net_idx > 0x0fff ||
	    in->identity > MESH_CFG_PRIV_IDENTITY_NOT_SUPPORTED)
		return (-1);
	p[0] = status;
	put16(p + 1, (uint16_t)(in->net_idx & 0x0fff));
	p[3] = in->identity;
	return (wrap(MESH_CFG_OP_PRIV_NODE_IDENTITY_STATUS, p, sizeof(p), out,
	    outlen));
}

int
mesh_cfg_priv_node_identity_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_priv_node_identity *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PRIV_NODE_IDENTITY_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len != 4)
		return (-1);
	if (status != NULL)
		*status = ap.params[0];
	out->net_idx = get16(ap.params + 1) & 0x0fff;
	out->identity = ap.params[3];
	if (out->identity > MESH_CFG_PRIV_IDENTITY_NOT_SUPPORTED)
		return (-1);
	return (0);
}
