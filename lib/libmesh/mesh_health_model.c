/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Health model codecs (MshMDL_v1.1 Section 7).
 *
 * Each _build() assembles the parameters and wraps them with the opcode via
 * mesh_access_pdu_build(); each _parse() runs mesh_access_pdu_parse() then
 * decodes.  The Company Identifier is little-endian; a Fault Array is a run
 * of 1-octet fault codes.  Output is zeroed on failure.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_health_model.h"

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

/* ================================================================
 * Fault / Current Status (Section 7.x).
 * ================================================================ */

static int
fault_status_build(uint32_t opcode, const struct mesh_hlt_fault_status *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[3 + MESH_HLT_MAX_FAULTS];

	if (in == NULL || in->n_faults > MESH_HLT_MAX_FAULTS)
		return (-1);
	params[0] = in->test_id;
	put16(params + 1, in->company_id);
	if (in->n_faults != 0)
		memcpy(params + 3, in->faults, in->n_faults);
	return (mesh_access_pdu_build(opcode, params, 3 + in->n_faults, out,
	    outlen));
}

int
mesh_hlt_current_status_build(const struct mesh_hlt_fault_status *in,
    uint8_t *out, size_t *outlen)
{

	return (fault_status_build(MESH_HLT_OP_CURRENT_STATUS, in, out, outlen));
}

int
mesh_hlt_fault_status_build(const struct mesh_hlt_fault_status *in, uint8_t *out,
    size_t *outlen)
{

	return (fault_status_build(MESH_HLT_OP_FAULT_STATUS, in, out, outlen));
}

int
mesh_hlt_fault_status_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    struct mesh_hlt_fault_status *out)
{
	struct mesh_access_pdu ap;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (opcode != NULL)
		*opcode = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_HLT_OP_CURRENT_STATUS &&
	    ap.opcode != MESH_HLT_OP_FAULT_STATUS)
		return (-1);
	if (ap.params_len < 3)
		return (-1);
	if (ap.params_len - 3 > MESH_HLT_MAX_FAULTS)
		return (-1);
	out->test_id = ap.params[0];
	out->company_id = get16(ap.params + 1);
	out->n_faults = ap.params_len - 3;
	if (out->n_faults != 0)
		memcpy(out->faults, ap.params + 3, out->n_faults);
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Fault Get / Clear / Test.
 * ================================================================ */

int
mesh_hlt_fault_get_build(uint16_t company_id, uint8_t *out, size_t *outlen)
{
	uint8_t params[2];

	put16(params, company_id);
	return (mesh_access_pdu_build(MESH_HLT_OP_FAULT_GET, params,
	    sizeof(params), out, outlen));
}

int
mesh_hlt_fault_get_parse(const uint8_t *in, size_t inlen, uint16_t *company_id)
{
	struct mesh_access_pdu ap;

	if (company_id != NULL)
		*company_id = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_HLT_OP_FAULT_GET || ap.params_len != 2)
		return (-1);
	if (company_id != NULL)
		*company_id = get16(ap.params);
	return (0);
}

int
mesh_hlt_fault_clear_build(uint32_t opcode, uint16_t company_id, uint8_t *out,
    size_t *outlen)
{
	uint8_t params[2];

	if (opcode != MESH_HLT_OP_FAULT_CLEAR &&
	    opcode != MESH_HLT_OP_FAULT_CLEAR_UNREL)
		return (-1);
	put16(params, company_id);
	return (mesh_access_pdu_build(opcode, params, sizeof(params), out,
	    outlen));
}

int
mesh_hlt_fault_clear_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint16_t *company_id)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (company_id != NULL)
		*company_id = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_HLT_OP_FAULT_CLEAR &&
	    ap.opcode != MESH_HLT_OP_FAULT_CLEAR_UNREL)
		return (-1);
	if (ap.params_len != 2)
		return (-1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	if (company_id != NULL)
		*company_id = get16(ap.params);
	return (0);
}

int
mesh_hlt_fault_test_build(uint32_t opcode, uint8_t test_id, uint16_t company_id,
    uint8_t *out, size_t *outlen)
{
	uint8_t params[3];

	if (opcode != MESH_HLT_OP_FAULT_TEST &&
	    opcode != MESH_HLT_OP_FAULT_TEST_UNREL)
		return (-1);
	params[0] = test_id;
	put16(params + 1, company_id);
	return (mesh_access_pdu_build(opcode, params, sizeof(params), out,
	    outlen));
}

int
mesh_hlt_fault_test_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *test_id, uint16_t *company_id)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (test_id != NULL)
		*test_id = 0;
	if (company_id != NULL)
		*company_id = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_HLT_OP_FAULT_TEST &&
	    ap.opcode != MESH_HLT_OP_FAULT_TEST_UNREL)
		return (-1);
	if (ap.params_len != 3)
		return (-1);
	if (opcode != NULL)
		*opcode = ap.opcode;
	if (test_id != NULL)
		*test_id = ap.params[0];
	if (company_id != NULL)
		*company_id = get16(ap.params + 1);
	return (0);
}

/* ================================================================
 * Period.
 * ================================================================ */

int
mesh_hlt_period_build(uint32_t opcode, uint8_t fast_period_divisor, uint8_t *out,
    size_t *outlen)
{

	switch (opcode) {
	case MESH_HLT_OP_PERIOD_SET:
	case MESH_HLT_OP_PERIOD_SET_UNREL:
	case MESH_HLT_OP_PERIOD_STATUS:
		if (fast_period_divisor > 15)
			return (-1);
		return (mesh_access_pdu_build(opcode, &fast_period_divisor, 1,
		    out, outlen));
	case MESH_HLT_OP_PERIOD_GET:
		return (mesh_access_pdu_build(opcode, NULL, 0, out, outlen));
	default:
		return (-1);
	}
}

int
mesh_hlt_period_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *fast_period_divisor)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (fast_period_divisor != NULL)
		*fast_period_divisor = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	switch (ap.opcode) {
	case MESH_HLT_OP_PERIOD_GET:
		if (ap.params_len != 0)
			return (-1);
		break;
	case MESH_HLT_OP_PERIOD_SET:
	case MESH_HLT_OP_PERIOD_SET_UNREL:
	case MESH_HLT_OP_PERIOD_STATUS:
		if (ap.params_len != 1)
			return (-1);
		/*
		 * P-M13 / MMDL 1.3.3: Fast Period Divisor 16-255 is Prohibited;
		 * such a message is silently ignored (parse fails so the caller
		 * emits no Status and persists nothing).
		 */
		if (ap.params[0] > 15)
			return (-1);
		if (fast_period_divisor != NULL)
			*fast_period_divisor = ap.params[0];
		break;
	default:
		return (-1);
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Attention.
 * ================================================================ */

int
mesh_hlt_attention_build(uint32_t opcode, uint8_t attention, uint8_t *out,
    size_t *outlen)
{

	switch (opcode) {
	case MESH_HLT_OP_ATTENTION_SET:
	case MESH_HLT_OP_ATTENTION_SET_UNREL:
	case MESH_HLT_OP_ATTENTION_STATUS:
		return (mesh_access_pdu_build(opcode, &attention, 1, out, outlen));
	case MESH_HLT_OP_ATTENTION_GET:
		return (mesh_access_pdu_build(opcode, NULL, 0, out, outlen));
	default:
		return (-1);
	}
}

int
mesh_hlt_attention_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
    uint8_t *attention)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (attention != NULL)
		*attention = 0;
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	switch (ap.opcode) {
	case MESH_HLT_OP_ATTENTION_GET:
		if (ap.params_len != 0)
			return (-1);
		break;
	case MESH_HLT_OP_ATTENTION_SET:
	case MESH_HLT_OP_ATTENTION_SET_UNREL:
	case MESH_HLT_OP_ATTENTION_STATUS:
		if (ap.params_len != 1)
			return (-1);
		if (attention != NULL)
			*attention = ap.params[0];
		break;
	default:
		return (-1);
	}
	if (opcode != NULL)
		*opcode = ap.opcode;
	return (0);
}

/* ================================================================
 * Minimal Health Server state (Section 7.4.1).
 * ================================================================ */

void
mesh_hlt_server_init(struct mesh_hlt_server_state *s, uint16_t company_id)
{

	if (s == NULL)
		return;
	memset(s, 0, sizeof(*s));
	s->company_id = company_id;
}

static int
fault_array_add(uint8_t *faults, size_t *n, uint8_t fault)
{
	size_t i;

	for (i = 0; i < *n; i++)
		if (faults[i] == fault)
			return (0);		/* already recorded */
	if (*n >= MESH_HLT_MAX_FAULTS)
		return (-1);
	faults[(*n)++] = fault;
	return (0);
}

/*
 * P-M14 / MshPRT 4.2.16: a present fault is recorded in the Current Fault array
 * and, because it has been present, also shadowed into the Registered Fault
 * array (which is cleared only by mesh_hlt_server_clear_faults()).
 */
int
mesh_hlt_server_add_fault(struct mesh_hlt_server_state *s, uint8_t fault)
{

	if (s == NULL)
		return (-1);
	if (fault == 0x00)		/* 0x00 is "No Fault"; nothing to add */
		return (0);
	if (fault_array_add(s->current_faults, &s->n_current_faults, fault) != 0)
		return (-1);
	return (fault_array_add(s->registered_faults, &s->n_registered_faults,
	    fault));
}

/*
 * P-M14: a resolved condition is removed from the real-time Current Fault array
 * only; the Registered Fault shadow persists until a Health Fault Clear.
 */
void
mesh_hlt_server_clear_current(struct mesh_hlt_server_state *s)
{

	if (s == NULL)
		return;
	memset(s->current_faults, 0, sizeof(s->current_faults));
	s->n_current_faults = 0;
}

/*
 * P-M14 / MshPRT 4.2.16.2: a Health Fault Clear message clears the Registered
 * Fault array only.  The Current Fault array reflects present conditions and is
 * untouched.
 */
void
mesh_hlt_server_clear_faults(struct mesh_hlt_server_state *s)
{

	if (s == NULL)
		return;
	memset(s->registered_faults, 0, sizeof(s->registered_faults));
	s->n_registered_faults = 0;
}
