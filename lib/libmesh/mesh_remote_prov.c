/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Remote Provisioning (MshPRT_v1.1 Section 4.4) and the Remote
 * Provisioning Client / Server models (MshMDL_v1.1 Section 4.4.4 / 4.4.5).  See
 * mesh_remote_prov.h for the wire layouts and the module contract.
 *
 * The model messages are wrapped with the two-octet access-layer opcode via
 * mesh_access_pdu_build() (big-endian opcode octets), exactly like
 * mesh_cfg_v11 / mesh_df; the OOB Information field is big-endian to match the
 * unprovisioned device beacon (mesh_beacon).  Every parse length-gates each
 * field before reading it.  Timers use a caller-supplied millisecond clock.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_beacon.h"
#include "mesh_remote_prov.h"

/*
 * Advertising Data Type values prohibited in an Extended Scan AD Type Filter
 * by Mesh Protocol 1.1, Table 4.176.  The numeric assignments are from the
 * Bluetooth Assigned Numbers, Generic Access Profile data types table.
 */
#define RP_AD_TYPE_UUID16_INCOMPLETE	0x02
#define RP_AD_TYPE_UUID32_INCOMPLETE	0x04
#define RP_AD_TYPE_UUID128_INCOMPLETE	0x06
#define RP_AD_TYPE_SHORT_LOCAL_NAME	0x08

/* Big-endian 16-bit helpers (OOB Information). */
static void
be16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
rd_be16(const uint8_t *p)
{

	return ((uint16_t)(((uint16_t)p[0] << 8) | p[1]));
}

static int
wrap(uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *out,
    size_t *outlen)
{

	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

/* Unwrap a received message, checking the opcode and copying out the params. */
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

static int
rp_ad_filter_valid(const uint8_t *types, size_t count)
{
	size_t i, j;

	if (types == NULL || count == 0 || count > MESH_RP_AD_FILTER_MAX)
		return (0);
	for (i = 0; i < count; i++) {
		/* MshPRT 1.1 Table 4.176: shortened name and incomplete UUID
		 * lists cannot be requested by Extended Scan. */
		if (types[i] == RP_AD_TYPE_SHORT_LOCAL_NAME ||
		    types[i] == RP_AD_TYPE_UUID16_INCOMPLETE ||
		    types[i] == RP_AD_TYPE_UUID32_INCOMPLETE ||
		    types[i] == RP_AD_TYPE_UUID128_INCOMPLETE)
			return (0);
		for (j = 0; j < i; j++)
			if (types[j] == types[i])
				return (0);
	}
	return (1);
}

static int
rp_adv_structures_valid(const uint8_t *adv, size_t len)
{
	size_t field_len, off = 0;

	if (len != 0 && adv == NULL)
		return (0);
	while (off < len) {
		field_len = adv[off];
		/* Length includes the AD Type, so zero cannot encode an AD
		 * Structure.  The following field must fit completely. */
		if (field_len == 0 || field_len > len - off - 1)
			return (0);
		off += 1 + field_len;
	}
	return (1);
}

/* A PB-Remote payload is exactly one Provisioning PDU.  Confirmation and
 * Random have either the 16-octet CMAC or 32-octet HMAC form. */
static int
rp_prov_pdu_valid(const uint8_t *pdu, size_t len)
{
	struct mesh_prov_pdu parsed;

	return (mesh_prov_pdu_parse(pdu, len, &parsed) == 0 ||
	    mesh_prov_pdu_parse_alg(MESH_PROV_ALGO_P256_HMAC, pdu, len,
	    &parsed) == 0);
}

/* ================================================================
 * Scan Capabilities.
 * ================================================================ */
int
mesh_rp_scan_caps_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_RP_OP_SCAN_CAPABILITIES_GET, NULL, 0, out, outlen));
}

int
mesh_rp_scan_caps_status_build(const struct mesh_rp_scan_caps *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];

	if (in == NULL || in->max_scanned_items < 4 || in->active_scan > 1)
		return (-1);
	p[0] = in->max_scanned_items;
	p[1] = in->active_scan;
	return (wrap(MESH_RP_OP_SCAN_CAPABILITIES_STATUS, p, 2, out, outlen));
}

int
mesh_rp_scan_caps_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_scan_caps *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_SCAN_CAPABILITIES_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len != 2 || out == NULL || ap.params[0] < 4 ||
	    ap.params[1] > 1)
		return (-1);
	out->max_scanned_items = ap.params[0];
	out->active_scan = ap.params[1];
	return (0);
}

/* ================================================================
 * Scan Get / Start / Stop / Status / Report.
 * ================================================================ */
int
mesh_rp_scan_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_RP_OP_SCAN_GET, NULL, 0, out, outlen));
}

int
mesh_rp_scan_start_build(const struct mesh_rp_scan_start *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[18];
	size_t n;

	if (in == NULL)
		return (-1);
	/* Timeout is 0x01..0xFF (Section 4.4.2). */
	if (in->timeout == 0)
		return (-1);
	p[0] = in->scanned_items_limit;
	p[1] = in->timeout;
	n = 2;
	if (in->has_uuid) {
		memcpy(p + 2, in->uuid, 16);
		n = 18;
	}
	return (wrap(MESH_RP_OP_SCAN_START, p, n, out, outlen));
}

int
mesh_rp_scan_start_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_scan_start *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_SCAN_START, &ap) != 0)
		return (-1);
	if (out == NULL)
		return (-1);
	if (ap.params_len != 2 && ap.params_len != 18)
		return (-1);
	if (ap.params[1] == 0)
		return (-1);
	out->scanned_items_limit = ap.params[0];
	out->timeout = ap.params[1];
	if (ap.params_len == 18) {
		out->has_uuid = 1;
		memcpy(out->uuid, ap.params + 2, 16);
	}
	return (0);
}

int
mesh_rp_scan_stop_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_RP_OP_SCAN_STOP, NULL, 0, out, outlen));
}

int
mesh_rp_scan_status_build(const struct mesh_rp_scan_status *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || in->status > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    in->scanning_state > MESH_RP_SCAN_LIMITED)
		return (-1);
	p[0] = in->status;
	p[1] = in->scanning_state;
	p[2] = in->scanned_items_limit;
	p[3] = in->timeout;
	return (wrap(MESH_RP_OP_SCAN_STATUS, p, 4, out, outlen));
}

int
mesh_rp_scan_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_scan_status *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_SCAN_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len != 4 || out == NULL ||
	    ap.params[0] > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    ap.params[1] > MESH_RP_SCAN_LIMITED)
		return (-1);
	out->status = ap.params[0];
	out->scanning_state = ap.params[1];
	out->scanned_items_limit = ap.params[2];
	out->timeout = ap.params[3];
	return (0);
}

int
mesh_rp_scan_report_build(const struct mesh_rp_scan_report *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[23];
	size_t n;

	if (in == NULL || (in->oob & ~MESH_OOB_INFO_MASK) != 0)
		return (-1);
	p[0] = (uint8_t)in->rssi;
	memcpy(p + 1, in->uuid, 16);
	be16(p + 17, in->oob);
	n = 19;
	if (in->has_uri_hash) {
		memcpy(p + 19, in->uri_hash, 4);
		n = 23;
	}
	return (wrap(MESH_RP_OP_SCAN_REPORT, p, n, out, outlen));
}

int
mesh_rp_scan_report_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_scan_report *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_SCAN_REPORT, &ap) != 0)
		return (-1);
	if (out == NULL)
		return (-1);
	if (ap.params_len != 19 && ap.params_len != 23)
		return (-1);
	out->rssi = (int8_t)ap.params[0];
	memcpy(out->uuid, ap.params + 1, 16);
	out->oob = rd_be16(ap.params + 17) & MESH_OOB_INFO_MASK;
	if (ap.params_len == 23) {
		out->has_uri_hash = 1;
		memcpy(out->uri_hash, ap.params + 19, 4);
	}
	return (0);
}

/* ================================================================
 * Extended Scan Start / Report.
 * ================================================================ */
int
mesh_rp_ext_scan_start_build(const struct mesh_rp_ext_scan_start *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[1 + MESH_RP_AD_FILTER_MAX + 17];
	size_t n;

	if (in == NULL || !rp_ad_filter_valid(in->ad_types,
	    in->ad_type_filter_count))
		return (-1);
	p[0] = in->ad_type_filter_count;
	memcpy(p + 1, in->ad_types, in->ad_type_filter_count);
	n = (size_t)1 + in->ad_type_filter_count;
	if (in->has_uuid) {
		if (in->timeout == 0)
			return (-1);
		memcpy(p + n, in->uuid, 16);
		n += 16;
		p[n] = in->timeout;
		n += 1;
	}
	return (wrap(MESH_RP_OP_EXTENDED_SCAN_START, p, n, out, outlen));
}

int
mesh_rp_ext_scan_start_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_ext_scan_start *out)
{
	struct mesh_access_pdu ap;
	size_t count, rem;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_EXTENDED_SCAN_START, &ap) != 0)
		return (-1);
	if (out == NULL || ap.params_len < 1)
		return (-1);
	count = ap.params[0];
	if (count > MESH_RP_AD_FILTER_MAX || ap.params_len < 1 + count ||
	    !rp_ad_filter_valid(ap.params + 1, count))
		return (-1);
	rem = ap.params_len - 1 - count;
	/* The trailing UUID(16) + Timeout(1) is present as a unit, or absent. */
	if (rem != 0 && rem != 17)
		return (-1);
	out->ad_type_filter_count = (uint8_t)count;
	memcpy(out->ad_types, ap.params + 1, count);
	if (rem == 17) {
		out->has_uuid = 1;
		memcpy(out->uuid, ap.params + 1 + count, 16);
		out->timeout = ap.params[1 + count + 16];
		if (out->timeout == 0)
			return (-1);
	}
	return (0);
}

int
mesh_rp_ext_scan_report_build(const struct mesh_rp_ext_scan_report *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[1 + 16 + 2 + MESH_RP_ADV_DATA_MAX];
	size_t n;

	if (in == NULL || in->status > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    in->adv_len > MESH_RP_ADV_DATA_MAX ||
	    (in->has_adv && !rp_adv_structures_valid(in->adv, in->adv_len)))
		return (-1);
	p[0] = in->status;
	memcpy(p + 1, in->uuid, 16);
	n = 17;
	if (in->has_adv) {
		if ((in->oob & ~MESH_OOB_INFO_MASK) != 0)
			return (-1);
		be16(p + 17, in->oob);
		memcpy(p + 19, in->adv, in->adv_len);
		n = 19 + in->adv_len;
	}
	return (wrap(MESH_RP_OP_EXTENDED_SCAN_REPORT, p, n, out, outlen));
}

int
mesh_rp_ext_scan_report_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_ext_scan_report *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_EXTENDED_SCAN_REPORT, &ap) != 0)
		return (-1);
	if (out == NULL || ap.params_len < 17 ||
	    ap.params[0] > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER)
		return (-1);
	/* Either just Status+UUID, or +OOB(2)+AdvStructures(>=0). */
	if (ap.params_len == 18)
		return (-1);
	out->status = ap.params[0];
	memcpy(out->uuid, ap.params + 1, 16);
	if (ap.params_len >= 19) {
		out->has_adv = 1;
		out->oob = rd_be16(ap.params + 17) & MESH_OOB_INFO_MASK;
		out->adv_len = ap.params_len - 19;
		if (out->adv_len > MESH_RP_ADV_DATA_MAX ||
		    !rp_adv_structures_valid(ap.params + 19, out->adv_len))
			return (-1);
		memcpy(out->adv, ap.params + 19, out->adv_len);
	}
	return (0);
}

/* ================================================================
 * Link Get / Open / Close / Status / Report.
 * ================================================================ */
int
mesh_rp_link_get_build(uint8_t *out, size_t *outlen)
{

	return (wrap(MESH_RP_OP_LINK_GET, NULL, 0, out, outlen));
}

int
mesh_rp_link_open_build(const struct mesh_rp_link_open *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[17];
	size_t n;

	if (in == NULL)
		return (-1);
	if (in->has_nppi) {
		if (in->has_timeout || in->nppi_procedure >
		    MESH_RP_NPPI_NODE_COMPOSITION_REFRESH)
			return (-1);
		p[0] = in->nppi_procedure;
		return (wrap(MESH_RP_OP_LINK_OPEN, p, 1, out, outlen));
	}
	memcpy(p, in->uuid, 16);
	n = 16;
	if (in->has_timeout) {
		if (in->timeout == 0 || in->timeout > 0x3c)
			return (-1);
		p[16] = in->timeout;
		n = 17;
	}
	return (wrap(MESH_RP_OP_LINK_OPEN, p, n, out, outlen));
}

int
mesh_rp_link_open_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_link_open *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_LINK_OPEN, &ap) != 0)
		return (-1);
	if (out == NULL)
		return (-1);
	if (ap.params_len == 1) {
		if (ap.params[0] > MESH_RP_NPPI_NODE_COMPOSITION_REFRESH)
			return (-1);
		out->has_nppi = 1;
		out->nppi_procedure = ap.params[0];
		return (0);
	}
	if (ap.params_len != 16 && ap.params_len != 17)
		return (-1);
	memcpy(out->uuid, ap.params, 16);
	if (ap.params_len == 17) {
		out->has_timeout = 1;
		out->timeout = ap.params[16];
		if (out->timeout == 0 || out->timeout > 0x3c)
			return (-1);
	}
	return (0);
}

int
mesh_rp_link_close_build(uint8_t reason, uint8_t *out, size_t *outlen)
{

	if (reason == MESH_RP_LINK_CLOSE_PROHIBITED ||
	    reason > MESH_RP_LINK_CLOSE_FAIL)
		return (-1);
	return (wrap(MESH_RP_OP_LINK_CLOSE, &reason, 1, out, outlen));
}

int
mesh_rp_link_close_parse(const uint8_t *in, size_t inlen, uint8_t *reason)
{
	struct mesh_access_pdu ap;

	if (reason != NULL)
		*reason = 0;
	if (unwrap(in, inlen, MESH_RP_OP_LINK_CLOSE, &ap) != 0)
		return (-1);
	if (ap.params_len != 1 || reason == NULL)
		return (-1);
	if (ap.params[0] == MESH_RP_LINK_CLOSE_PROHIBITED ||
	    ap.params[0] > MESH_RP_LINK_CLOSE_FAIL)
		return (-1);
	*reason = ap.params[0];
	return (0);
}

int
mesh_rp_link_status_build(const struct mesh_rp_link_status *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];

	if (in == NULL || in->status > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    in->rp_state > MESH_RP_LINK_CLOSING)
		return (-1);
	p[0] = in->status;
	p[1] = in->rp_state;
	return (wrap(MESH_RP_OP_LINK_STATUS, p, 2, out, outlen));
}

int
mesh_rp_link_status_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_link_status *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_LINK_STATUS, &ap) != 0)
		return (-1);
	if (ap.params_len != 2 || out == NULL ||
	    ap.params[0] > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    ap.params[1] > MESH_RP_LINK_CLOSING)
		return (-1);
	out->status = ap.params[0];
	out->rp_state = ap.params[1];
	return (0);
}

int
mesh_rp_link_report_build(const struct mesh_rp_link_report *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[3];
	size_t n;

	if (in == NULL || in->status > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    in->rp_state > MESH_RP_LINK_CLOSING)
		return (-1);
	/* Reason is permitted only for a device/server close that actually
	 * supplies a bearer reason. */
	if (in->has_reason &&
	    in->status != MESH_RP_STATUS_LINK_CLOSED_BY_DEVICE &&
	    in->status != MESH_RP_STATUS_LINK_CLOSED_BY_SERVER)
		return (-1);
	p[0] = in->status;
	p[1] = in->rp_state;
	n = 2;
	if (in->has_reason) {
		p[2] = in->reason;
		n = 3;
	}
	return (wrap(MESH_RP_OP_LINK_REPORT, p, n, out, outlen));
}

int
mesh_rp_link_report_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_link_report *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_LINK_REPORT, &ap) != 0)
		return (-1);
	if (out == NULL)
		return (-1);
	if (ap.params_len != 2 && ap.params_len != 3)
		return (-1);
	if (ap.params[0] > MESH_RP_STATUS_LINK_CLOSED_CANNOT_DELIVER ||
	    ap.params[1] > MESH_RP_LINK_CLOSING)
		return (-1);
	out->status = ap.params[0];
	out->rp_state = ap.params[1];
	if (ap.params_len == 3) {
		if (ap.params[0] != MESH_RP_STATUS_LINK_CLOSED_BY_DEVICE &&
		    ap.params[0] != MESH_RP_STATUS_LINK_CLOSED_BY_SERVER)
			return (-1);
		out->has_reason = 1;
		out->reason = ap.params[2];
	}
	return (0);
}

/* ================================================================
 * PDU Send / Outbound Report / Report.
 * ================================================================ */
int
mesh_rp_pdu_send_build(const struct mesh_rp_pdu_send *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[1 + MESH_RP_PROV_PDU_MAX];

	if (in == NULL || !rp_prov_pdu_valid(in->prov_pdu, in->prov_len))
		return (-1);
	p[0] = in->outbound_pdu_number;
	memcpy(p + 1, in->prov_pdu, in->prov_len);
	return (wrap(MESH_RP_OP_PDU_SEND, p, 1 + in->prov_len, out, outlen));
}

int
mesh_rp_pdu_send_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_pdu_send *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_PDU_SEND, &ap) != 0)
		return (-1);
	if (out == NULL || ap.params_len < 2)
		return (-1);
	out->prov_len = ap.params_len - 1;
	if (out->prov_len > MESH_RP_PROV_PDU_MAX ||
	    !rp_prov_pdu_valid(ap.params + 1, out->prov_len))
		return (-1);
	out->outbound_pdu_number = ap.params[0];
	memcpy(out->prov_pdu, ap.params + 1, out->prov_len);
	return (0);
}

int
mesh_rp_pdu_outbound_report_build(uint8_t outbound_pdu_number, uint8_t *out,
    size_t *outlen)
{

	return (wrap(MESH_RP_OP_PDU_OUTBOUND_REPORT, &outbound_pdu_number, 1,
	    out, outlen));
}

int
mesh_rp_pdu_outbound_report_parse(const uint8_t *in, size_t inlen,
    uint8_t *outbound_pdu_number)
{
	struct mesh_access_pdu ap;

	if (outbound_pdu_number != NULL)
		*outbound_pdu_number = 0;
	if (unwrap(in, inlen, MESH_RP_OP_PDU_OUTBOUND_REPORT, &ap) != 0)
		return (-1);
	if (ap.params_len != 1 || outbound_pdu_number == NULL)
		return (-1);
	*outbound_pdu_number = ap.params[0];
	return (0);
}

int
mesh_rp_pdu_report_build(const struct mesh_rp_pdu_report *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[1 + MESH_RP_PROV_PDU_MAX];

	if (in == NULL || !rp_prov_pdu_valid(in->prov_pdu, in->prov_len))
		return (-1);
	p[0] = in->inbound_pdu_number;
	memcpy(p + 1, in->prov_pdu, in->prov_len);
	return (wrap(MESH_RP_OP_PDU_REPORT, p, 1 + in->prov_len, out, outlen));
}

int
mesh_rp_pdu_report_parse(const uint8_t *in, size_t inlen,
    struct mesh_rp_pdu_report *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_RP_OP_PDU_REPORT, &ap) != 0)
		return (-1);
	if (out == NULL || ap.params_len < 2)
		return (-1);
	out->prov_len = ap.params_len - 1;
	if (out->prov_len > MESH_RP_PROV_PDU_MAX ||
	    !rp_prov_pdu_valid(ap.params + 1, out->prov_len))
		return (-1);
	out->inbound_pdu_number = ap.params[0];
	memcpy(out->prov_pdu, ap.params + 1, out->prov_len);
	return (0);
}

/* ================================================================
 * Scan state machine - Server responder (Section 4.4.2).
 * ================================================================ */
void
mesh_rp_scan_server_init(struct mesh_rp_scan_server *s,
    uint8_t max_scanned_items, int active_scan_supported)
{

	if (s == NULL)
		return;
	memset(s, 0, sizeof(*s));
	s->state = MESH_RP_SCAN_IDLE;
	/* Table 4.46 prohibits advertising fewer than four reportable UUIDs. */
	s->max_scanned_items = max_scanned_items < 4 ? 4 : max_scanned_items;
	s->active_scan_supported = active_scan_supported ? 1 : 0;
}

void
mesh_rp_scan_server_caps(const struct mesh_rp_scan_server *s,
    struct mesh_rp_scan_caps *out)
{

	if (s == NULL || out == NULL)
		return;
	out->max_scanned_items = s->max_scanned_items;
	out->active_scan = (uint8_t)s->active_scan_supported;
}

static void
scan_server_fill_status(const struct mesh_rp_scan_server *s, uint8_t status,
    struct mesh_rp_scan_status *st)
{

	st->status = status;
	st->scanning_state = s->state;
	st->scanned_items_limit = s->items_limit;
	st->timeout = s->timeout;
}

static void
scan_server_set_idle(struct mesh_rp_scan_server *s)
{

	s->state = MESH_RP_SCAN_IDLE;
	s->items_limit = 0;
	s->timeout = 0;
	s->has_target = 0;
}

int
mesh_rp_scan_server_start(struct mesh_rp_scan_server *s,
    const struct mesh_rp_scan_start *req, uint64_t now,
    struct mesh_rp_scan_status *st)
{

	if (s == NULL || req == NULL || st == NULL)
		return (-1);
	if (req->timeout == 0) {
		scan_server_fill_status(s, MESH_RP_STATUS_SCANNING_CANNOT_START,
		    st);
		return (-1);
	}
	if (s->state != MESH_RP_SCAN_IDLE) {
		scan_server_fill_status(s, MESH_RP_STATUS_INVALID_STATE, st);
		return (-1);
	}
	s->items_limit = req->scanned_items_limit;
	s->timeout = req->timeout;
	s->reported = 0;
	s->has_target = req->has_uuid;
	if (req->has_uuid)
		memcpy(s->target, req->uuid, 16);
	/*
	 * A scan targeting a single device UUID uses the Limited state; a
	 * general scan for any unprovisioned device (bounded only by the
	 * scanned-items limit) uses the Active state (Section 4.4.2).
	 */
	s->state = req->has_uuid ? MESH_RP_SCAN_LIMITED : MESH_RP_SCAN_ACTIVE;
	s->start_ms = now;
	s->deadline_ms = now + (uint64_t)req->timeout * 1000ULL;
	scan_server_fill_status(s, MESH_RP_STATUS_SUCCESS, st);
	return (0);
}

int
mesh_rp_scan_server_stop(struct mesh_rp_scan_server *s, uint64_t now,
    struct mesh_rp_scan_status *st)
{

	if (s == NULL || st == NULL)
		return (-1);
	(void)now;
	scan_server_set_idle(s);
	scan_server_fill_status(s, MESH_RP_STATUS_SUCCESS, st);
	return (0);
}

void
mesh_rp_scan_server_status(struct mesh_rp_scan_server *s, uint64_t now,
    struct mesh_rp_scan_status *st)
{

	if (s == NULL || st == NULL)
		return;
	(void)mesh_rp_scan_server_tick(s, now);
	scan_server_fill_status(s, MESH_RP_STATUS_SUCCESS, st);
}

int
mesh_rp_scan_server_device_seen(struct mesh_rp_scan_server *s,
    const uint8_t uuid[16], uint16_t oob, int8_t rssi, uint64_t now,
    struct mesh_rp_scan_report *rep, int *emit)
{

	if (s == NULL || uuid == NULL || rep == NULL || emit == NULL)
		return (-1);
	*emit = 0;
	/* Drop expired scans first so a late sighting is not reported. */
	(void)mesh_rp_scan_server_tick(s, now);
	if (s->state != MESH_RP_SCAN_ACTIVE && s->state != MESH_RP_SCAN_LIMITED)
		return (0);
	if (s->has_target && memcmp(s->target, uuid, 16) != 0)
		return (0);
	if (s->items_limit != 0 && s->reported >= s->items_limit)
		return (0);
	memset(rep, 0, sizeof(*rep));
	rep->rssi = rssi;
	memcpy(rep->uuid, uuid, 16);
	rep->oob = oob;
	*emit = 1;
	if (s->reported < 0xff)
		s->reported++;
	if (s->items_limit != 0 && s->reported >= s->items_limit)
		scan_server_set_idle(s);
	return (0);
}

int
mesh_rp_scan_server_tick(struct mesh_rp_scan_server *s, uint64_t now)
{
	uint64_t duration, elapsed, remaining;

	if (s == NULL)
		return (0);
	if (s->state != MESH_RP_SCAN_ACTIVE && s->state != MESH_RP_SCAN_LIMITED)
		return (0);
	duration = s->deadline_ms - s->start_ms;
	elapsed = now - s->start_ms;
	if (elapsed >= duration) {
		scan_server_set_idle(s);
		return (1);
	}
	remaining = duration - elapsed;
	/* Timeout is the maximum whole number of seconds remaining; round up
	 * while a fractional final second is still active. */
	s->timeout = (uint8_t)((remaining + 999) / 1000);
	return (0);
}

int
mesh_rp_scan_server_scanning(const struct mesh_rp_scan_server *s)
{

	return (s != NULL && (s->state == MESH_RP_SCAN_ACTIVE ||
	    s->state == MESH_RP_SCAN_LIMITED));
}

/* ================================================================
 * Scan state machine - Client controller (Section 4.4.2).
 * ================================================================ */
void
mesh_rp_scan_client_init(struct mesh_rp_scan_client *c)
{

	if (c == NULL)
		return;
	memset(c, 0, sizeof(*c));
}

int
mesh_rp_scan_client_start(struct mesh_rp_scan_client *c,
    uint8_t scanned_items_limit, uint8_t timeout, const uint8_t uuid[16],
    uint8_t *out, size_t *outlen)
{
	struct mesh_rp_scan_start req;

	if (c == NULL)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.scanned_items_limit = scanned_items_limit;
	req.timeout = timeout;
	if (uuid != NULL) {
		req.has_uuid = 1;
		memcpy(req.uuid, uuid, 16);
	}
	if (mesh_rp_scan_start_build(&req, out, outlen) != 0)
		return (-1);
	c->scanning = 1;
	c->nfound = 0;
	return (0);
}

int
mesh_rp_scan_client_on_report(struct mesh_rp_scan_client *c,
    const struct mesh_rp_scan_report *rep)
{
	size_t i;

	if (c == NULL || rep == NULL)
		return (-1);
	for (i = 0; i < c->nfound; i++) {
		if (memcmp(c->found[i], rep->uuid, 16) == 0)
			return (0);	/* already recorded */
	}
	if (c->nfound >= MESH_RP_SCAN_FOUND_MAX)
		return (-1);
	memcpy(c->found[c->nfound], rep->uuid, 16);
	c->nfound++;
	return (0);
}

int
mesh_rp_scan_client_found(const struct mesh_rp_scan_client *c,
    const uint8_t uuid[16])
{
	size_t i;

	if (c == NULL || uuid == NULL)
		return (0);
	for (i = 0; i < c->nfound; i++) {
		if (memcmp(c->found[i], uuid, 16) == 0)
			return (1);
	}
	return (0);
}

int
mesh_rp_scan_client_stop(struct mesh_rp_scan_client *c, uint8_t *out,
    size_t *outlen)
{

	if (c == NULL)
		return (-1);
	if (mesh_rp_scan_stop_build(out, outlen) != 0)
		return (-1);
	c->scanning = 0;
	return (0);
}

/* ================================================================
 * PB-Remote bearer - Client link (Section 4.4.3).
 * ================================================================ */
void
mesh_rp_client_link_init(struct mesh_rp_client_link *l)
{

	if (l == NULL)
		return;
	memset(l, 0, sizeof(*l));
	l->state = MESH_RP_LINK_IDLE;
}

int
mesh_rp_client_link_open(struct mesh_rp_client_link *l,
    const uint8_t device_uuid[16], uint8_t timeout, uint64_t open_timeout_ms,
    uint64_t now, uint8_t *out, size_t *outlen)
{
	struct mesh_rp_link_open op;

	if (l == NULL || device_uuid == NULL)
		return (-1);
	if (l->state != MESH_RP_LINK_IDLE)
		return (-1);
	memset(&op, 0, sizeof(op));
	memcpy(op.uuid, device_uuid, 16);
	if (timeout != 0) {
		op.has_timeout = 1;
		op.timeout = timeout;
	}
	if (mesh_rp_link_open_build(&op, out, outlen) != 0)
		return (-1);
	memcpy(l->device_uuid, device_uuid, 16);
	l->has_nppi = 0;
	l->state = MESH_RP_LINK_OPENING;
	l->outbound_pdu_number = 0;
	l->inbound_pdu_number = 0;
	l->have_inbound = 0;
	l->awaiting_outbound_report = 0;
	l->open_ms = now;
	l->open_deadline_ms = now + open_timeout_ms;
	return (0);
}

int
mesh_rp_client_link_open_nppi(struct mesh_rp_client_link *l,
    uint8_t procedure, uint64_t open_timeout_ms, uint64_t now, uint8_t *out,
    size_t *outlen)
{
	struct mesh_rp_link_open op;

	if (l == NULL || l->state != MESH_RP_LINK_IDLE ||
	    procedure > MESH_RP_NPPI_NODE_COMPOSITION_REFRESH)
		return (-1);
	memset(&op, 0, sizeof(op));
	op.has_nppi = 1;
	op.nppi_procedure = procedure;
	if (mesh_rp_link_open_build(&op, out, outlen) != 0)
		return (-1);
	memset(l->device_uuid, 0, sizeof(l->device_uuid));
	l->has_nppi = 1;
	l->nppi_procedure = procedure;
	l->state = MESH_RP_LINK_OPENING;
	l->outbound_pdu_number = 0;
	l->inbound_pdu_number = 0;
	l->have_inbound = 0;
	l->awaiting_outbound_report = 0;
	l->open_ms = now;
	l->open_deadline_ms = now + open_timeout_ms;
	return (0);
}

/* A link is usable once the Server reports ACTIVE or a busier state. */
static int
rp_state_usable(uint8_t st)
{

	return (st == MESH_RP_LINK_ACTIVE ||
	    st == MESH_RP_LINK_OUTBOUND_TRANSFER);
}

int
mesh_rp_client_link_on_status(struct mesh_rp_client_link *l,
    const struct mesh_rp_link_status *st)
{

	if (l == NULL || st == NULL)
		return (-1);
	if (st->status != MESH_RP_STATUS_SUCCESS) {
		l->state = MESH_RP_LINK_IDLE;
		return (0);
	}
	if (l->state == MESH_RP_LINK_OPENING && rp_state_usable(st->rp_state))
		l->state = MESH_RP_LINK_ACTIVE;
	else if (st->rp_state == MESH_RP_LINK_IDLE)
		l->state = MESH_RP_LINK_IDLE;
	return (0);
}

int
mesh_rp_client_link_on_report(struct mesh_rp_client_link *l,
    const struct mesh_rp_link_report *rp)
{

	if (l == NULL || rp == NULL)
		return (-1);
	if (rp->rp_state == MESH_RP_LINK_IDLE) {
		l->state = MESH_RP_LINK_IDLE;
		if (rp->has_reason)
			l->last_reason = rp->reason;
		return (0);
	}
	if (l->state == MESH_RP_LINK_OPENING && rp_state_usable(rp->rp_state))
		l->state = MESH_RP_LINK_ACTIVE;
	return (0);
}

int
mesh_rp_client_link_send_pdu(struct mesh_rp_client_link *l,
    const uint8_t *prov_pdu, size_t len, uint8_t *out, size_t *outlen)
{
	struct mesh_rp_pdu_send snd;
	uint8_t next_number;

	if (l == NULL || prov_pdu == NULL)
		return (-1);
	if (l->state != MESH_RP_LINK_ACTIVE || l->awaiting_outbound_report)
		return (-1);
	if (len == 0 || len > MESH_RP_PROV_PDU_MAX)
		return (-1);
	memset(&snd, 0, sizeof(snd));
	next_number = (uint8_t)(l->outbound_pdu_number + 1);
	snd.outbound_pdu_number = next_number;
	snd.prov_len = len;
	memcpy(snd.prov_pdu, prov_pdu, len);
	if (mesh_rp_pdu_send_build(&snd, out, outlen) != 0)
		return (-1);
	l->outbound_pdu_number = next_number;
	l->awaiting_outbound_report = 1;
	return (0);
}

int
mesh_rp_client_link_on_outbound_report(struct mesh_rp_client_link *l,
    uint8_t outbound_pdu_number)
{

	if (l == NULL)
		return (-1);
	if (!l->awaiting_outbound_report ||
	    outbound_pdu_number != l->outbound_pdu_number)
		return (-1);
	l->awaiting_outbound_report = 0;
	return (0);
}

int
mesh_rp_client_link_on_pdu_report(struct mesh_rp_client_link *l,
    const struct mesh_rp_pdu_report *rp, uint8_t *prov_pdu, size_t *len)
{

	if (l == NULL || rp == NULL || prov_pdu == NULL || len == NULL)
		return (-1);
	if (l->state != MESH_RP_LINK_ACTIVE)
		return (-1);
	if (rp->prov_len == 0 || rp->prov_len > MESH_RP_PROV_PDU_MAX)
		return (-1);
	if (rp->inbound_pdu_number != (uint8_t)(l->inbound_pdu_number + 1))
		return (-1);
	memcpy(prov_pdu, rp->prov_pdu, rp->prov_len);
	*len = rp->prov_len;
	l->inbound_pdu_number = rp->inbound_pdu_number;
	l->have_inbound = 1;
	return (0);
}

int
mesh_rp_client_link_close(struct mesh_rp_client_link *l, uint8_t reason,
    uint8_t *out, size_t *outlen)
{

	if (l == NULL)
		return (-1);
	if (mesh_rp_link_close_build(reason, out, outlen) != 0)
		return (-1);
	l->last_reason = reason;
	l->state = MESH_RP_LINK_CLOSING;
	return (0);
}

int
mesh_rp_client_link_tick(struct mesh_rp_client_link *l, uint64_t now)
{

	if (l == NULL)
		return (0);
	if (l->state != MESH_RP_LINK_OPENING)
		return (0);
	if (now - l->open_ms >= l->open_deadline_ms - l->open_ms) {
		l->state = MESH_RP_LINK_IDLE;
		return (1);
	}
	return (0);
}

int
mesh_rp_client_link_is_active(const struct mesh_rp_client_link *l)
{

	return (l != NULL && l->state == MESH_RP_LINK_ACTIVE);
}

int
mesh_rp_client_link_idle(const struct mesh_rp_client_link *l)
{

	return (l != NULL && l->state == MESH_RP_LINK_ACTIVE &&
	    !l->awaiting_outbound_report);
}

/* ================================================================
 * PB-Remote bearer - Server link (Section 4.4.3).
 * ================================================================ */
void
mesh_rp_server_link_init(struct mesh_rp_server_link *s)
{

	if (s == NULL)
		return;
	memset(s, 0, sizeof(*s));
	s->state = MESH_RP_LINK_IDLE;
}

int
mesh_rp_server_link_on_open(struct mesh_rp_server_link *s,
    const struct mesh_rp_link_open *op, struct mesh_rp_link_status *st)
{

	if (s == NULL || op == NULL || st == NULL)
		return (-1);
	if (s->state != MESH_RP_LINK_IDLE) {
		st->status = MESH_RP_STATUS_INVALID_STATE;
		st->rp_state = s->state;
		return (-1);
	}
	if (op->has_nppi) {
		if (op->has_timeout || op->nppi_procedure >
		    MESH_RP_NPPI_NODE_COMPOSITION_REFRESH) {
			st->status = MESH_RP_STATUS_INVALID_STATE;
			st->rp_state = s->state;
			return (-1);
		}
		memset(s->device_uuid, 0, sizeof(s->device_uuid));
		s->has_nppi = 1;
		s->nppi_procedure = op->nppi_procedure;
	} else {
		if (op->has_timeout && (op->timeout == 0 || op->timeout > 0x3c)) {
			st->status = MESH_RP_STATUS_INVALID_STATE;
			st->rp_state = s->state;
			return (-1);
		}
		memcpy(s->device_uuid, op->uuid, 16);
		s->has_nppi = 0;
		s->nppi_procedure = 0;
	}
	s->inbound_pdu_number = 0;
	s->outbound_pdu_number = 0;
	s->have_outbound = 0;
	s->outbound_pending = 0;
	s->state = op->has_nppi ? MESH_RP_LINK_ACTIVE : MESH_RP_LINK_OPENING;
	st->status = MESH_RP_STATUS_SUCCESS;
	st->rp_state = s->state;
	return (0);
}

int
mesh_rp_server_link_bearer_open(struct mesh_rp_server_link *s,
    struct mesh_rp_link_report *rp)
{

	if (s == NULL || rp == NULL)
		return (-1);
	if (s->has_nppi) {
		if (s->state != MESH_RP_LINK_ACTIVE)
			return (-1);
	} else if (s->state != MESH_RP_LINK_OPENING) {
		return (-1);
	}
	s->state = MESH_RP_LINK_ACTIVE;
	memset(rp, 0, sizeof(*rp));
	rp->status = MESH_RP_STATUS_SUCCESS;
	rp->rp_state = MESH_RP_LINK_ACTIVE;
	return (0);
}

int
mesh_rp_server_link_on_pdu_send(struct mesh_rp_server_link *s,
    const struct mesh_rp_pdu_send *snd, uint8_t *prov_pdu, size_t *len,
    uint8_t *outrep)
{

	if (s == NULL || snd == NULL || prov_pdu == NULL || len == NULL ||
	    outrep == NULL)
		return (-1);
	if (s->state != MESH_RP_LINK_ACTIVE)
		return (-1);
	if (!rp_prov_pdu_valid(snd->prov_pdu, snd->prov_len))
		return (-1);
	*outrep = s->outbound_pdu_number;
	*len = 0;
	if (s->outbound_pending)
		return (1);
	if (snd->outbound_pdu_number !=
	    (uint8_t)(s->outbound_pdu_number + 1))
		return (1);
	memcpy(prov_pdu, snd->prov_pdu, snd->prov_len);
	*len = snd->prov_len;
	s->pending_outbound_pdu_number = snd->outbound_pdu_number;
	s->outbound_pending = 1;
	s->state = MESH_RP_LINK_OUTBOUND_TRANSFER;
	*outrep = snd->outbound_pdu_number;
	return (0);
}

int
mesh_rp_server_link_pdu_delivered(struct mesh_rp_server_link *s, int success,
    uint8_t *outrep, struct mesh_rp_link_report *failure_report)
{

	if (s == NULL || outrep == NULL || !s->outbound_pending)
		return (-1);
	if (!success && s->has_nppi && failure_report == NULL)
		return (-1);
	*outrep = s->outbound_pdu_number;
	if (!success) {
		s->outbound_pending = 0;
		if (s->has_nppi) {
			s->state = MESH_RP_LINK_IDLE;
			memset(failure_report, 0, sizeof(*failure_report));
			failure_report->status =
			    MESH_RP_STATUS_LINK_CLOSED_BY_SERVER;
			failure_report->rp_state = MESH_RP_LINK_IDLE;
		} else {
			s->state = MESH_RP_LINK_CLOSING;
			s->link_close_status =
			    MESH_RP_STATUS_LINK_CLOSED_CANNOT_TX_PDU;
			s->has_link_close_reason = 0;
		}
		return (1);
	}
	s->outbound_pdu_number = s->pending_outbound_pdu_number;
	s->have_outbound = 1;
	s->outbound_pending = 0;
	s->state = MESH_RP_LINK_ACTIVE;
	*outrep = s->outbound_pdu_number;
	return (0);
}

int
mesh_rp_server_link_bearer_closed(struct mesh_rp_server_link *s, int reason,
    struct mesh_rp_link_report *rp)
{

	if (s == NULL || rp == NULL || s->state != MESH_RP_LINK_CLOSING)
		return (-1);
	if (reason >= 0 && reason <= 0xff) {
		s->has_link_close_reason = 1;
		s->link_close_reason = (uint8_t)reason;
	}
	s->state = MESH_RP_LINK_IDLE;
	memset(rp, 0, sizeof(*rp));
	rp->status = s->link_close_status;
	rp->rp_state = MESH_RP_LINK_IDLE;
	/* A Reason is permitted only with Closed by Device/Server, not with the
	 * more specific Cannot Send PDU status (Table 4.186). */
	if ((rp->status == MESH_RP_STATUS_LINK_CLOSED_BY_DEVICE ||
	    rp->status == MESH_RP_STATUS_LINK_CLOSED_BY_SERVER) &&
	    s->has_link_close_reason) {
		rp->has_reason = 1;
		rp->reason = s->link_close_reason;
	}
	return (0);
}

int
mesh_rp_server_link_report_pdu(struct mesh_rp_server_link *s,
    const uint8_t *prov_pdu, size_t len, struct mesh_rp_pdu_report *out)
{

	if (s == NULL || prov_pdu == NULL || out == NULL)
		return (-1);
	if (s->state != MESH_RP_LINK_ACTIVE)
		return (-1);
	if (!rp_prov_pdu_valid(prov_pdu, len))
		return (-1);
	memset(out, 0, sizeof(*out));
	s->inbound_pdu_number++;
	out->inbound_pdu_number = s->inbound_pdu_number;
	out->prov_len = len;
	memcpy(out->prov_pdu, prov_pdu, len);
	return (0);
}

int
mesh_rp_server_link_on_close(struct mesh_rp_server_link *s, uint8_t reason,
    struct mesh_rp_link_report *rp)
{

	if (s == NULL || rp == NULL)
		return (-1);
	s->state = MESH_RP_LINK_IDLE;
	memset(rp, 0, sizeof(*rp));
	rp->status = MESH_RP_STATUS_LINK_CLOSED_BY_CLIENT;
	rp->rp_state = MESH_RP_LINK_IDLE;
	/* Table 4.186 permits Reason only when the device or server closed the
	 * bearer.  A client-requested close is represented by Status alone. */
	(void)reason;
	return (0);
}

void
mesh_rp_server_link_status(const struct mesh_rp_server_link *s,
    struct mesh_rp_link_status *st)
{

	if (s == NULL || st == NULL)
		return;
	st->status = MESH_RP_STATUS_SUCCESS;
	st->rp_state = s->state;
}

int
mesh_rp_server_link_is_active(const struct mesh_rp_server_link *s)
{

	return (s != NULL && s->state == MESH_RP_LINK_ACTIVE);
}
