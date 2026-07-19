/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Health model (MshMDL_v1.1 Section 7), a foundation model
 * for fault reporting and node attention.  This module provides the message
 * codecs (build + parse of the access-PDU parameters) and a small server
 * state block.
 *
 * As with the Configuration model, each _build() emits the full Access PDU
 * (opcode + parameters) via mesh_access.[ch]; each _parse() consumes it.
 * The Company Identifier is little-endian (Section 7.x); a Fault Array is a
 * sequence of 1-octet fault codes.  Opcodes are cited from the MshMDL
 * Section 7.2 message summary.  Pure, hardware-free, no globals; output
 * zeroed on failure.
 */

#ifndef _MESH_HEALTH_MODEL_H_
#define _MESH_HEALTH_MODEL_H_

#include <stddef.h>
#include <stdint.h>

/* Health model opcodes (MshMDL Section 7.2). */
#define	MESH_HLT_OP_CURRENT_STATUS	0x0004
#define	MESH_HLT_OP_FAULT_STATUS	0x0005
#define	MESH_HLT_OP_ATTENTION_GET	0x8004
#define	MESH_HLT_OP_ATTENTION_SET	0x8005
#define	MESH_HLT_OP_ATTENTION_SET_UNREL	0x8006
#define	MESH_HLT_OP_ATTENTION_STATUS	0x8007
#define	MESH_HLT_OP_FAULT_CLEAR		0x802F
#define	MESH_HLT_OP_FAULT_CLEAR_UNREL	0x8030
#define	MESH_HLT_OP_FAULT_GET		0x8031
#define	MESH_HLT_OP_FAULT_TEST		0x8032
#define	MESH_HLT_OP_FAULT_TEST_UNREL	0x8033
#define	MESH_HLT_OP_PERIOD_GET		0x8034
#define	MESH_HLT_OP_PERIOD_SET		0x8035
#define	MESH_HLT_OP_PERIOD_SET_UNREL	0x8036
#define	MESH_HLT_OP_PERIOD_STATUS	0x8037

/* Longest fault array we accept in a parsed status (bounded for the stack). */
#define	MESH_HLT_MAX_FAULTS		64

/*
 * Health Current Status (0x04) / Fault Status (0x05):
 *   TestID (1) | CompanyID (2, LE) | FaultArray (0..N, one octet per fault).
 * A fault code of 0x00 means "No Fault"; an empty FaultArray also means no
 * registered faults.
 */
struct mesh_hlt_fault_status {
	uint8_t		test_id;
	uint16_t	company_id;
	uint8_t		faults[MESH_HLT_MAX_FAULTS];
	size_t		n_faults;
};
int	mesh_hlt_current_status_build(const struct mesh_hlt_fault_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_hlt_fault_status_build(const struct mesh_hlt_fault_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_hlt_fault_status_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_hlt_fault_status *out);

/* Health Fault Get (0x8031): CompanyID (2, LE). */
int	mesh_hlt_fault_get_build(uint16_t company_id, uint8_t *out,
	    size_t *outlen);
int	mesh_hlt_fault_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *company_id);

/*
 * Health Fault Clear (0x802F) / Clear Unacknowledged (0x8030):
 * CompanyID (2, LE).  build() takes the opcode.
 */
int	mesh_hlt_fault_clear_build(uint32_t opcode, uint16_t company_id,
	    uint8_t *out, size_t *outlen);
int	mesh_hlt_fault_clear_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint16_t *company_id);

/*
 * Health Fault Test (0x8032) / Test Unacknowledged (0x8033):
 * TestID (1) | CompanyID (2, LE).  build() takes the opcode.
 */
int	mesh_hlt_fault_test_build(uint32_t opcode, uint8_t test_id,
	    uint16_t company_id, uint8_t *out, size_t *outlen);
int	mesh_hlt_fault_test_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, uint8_t *test_id, uint16_t *company_id);

/*
 * Health Period Get (0x8034) / Set (0x8035) / Set Unack (0x8036) / Status
 * (0x8037): the Set/Status carry FastPeriodDivisor (1 octet, 0..15).  Get is
 * empty.  build() takes the opcode.
 */
int	mesh_hlt_period_build(uint32_t opcode, uint8_t fast_period_divisor,
	    uint8_t *out, size_t *outlen);
int	mesh_hlt_period_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    uint8_t *fast_period_divisor);

/*
 * Health Attention Get (0x8004) / Set (0x8005) / Set Unack (0x8006) / Status
 * (0x8007): the Set/Status carry Attention (1 octet, seconds).  Get is empty.
 * build() takes the opcode.
 */
int	mesh_hlt_attention_build(uint32_t opcode, uint8_t attention, uint8_t *out,
	    size_t *outlen);
int	mesh_hlt_attention_parse(const uint8_t *in, size_t inlen, uint32_t *opcode,
	    uint8_t *attention);

/*
 * Minimal Health Server state (Section 7.4.1): the registered fault array,
 * the current test id, the fast period divisor and the attention timer.
 */
struct mesh_hlt_server_state {
	uint16_t	company_id;
	uint8_t		test_id;
	uint8_t		fast_period_divisor;	/* 0..15 */
	uint8_t		attention;		/* seconds remaining */
	uint8_t		faults[MESH_HLT_MAX_FAULTS];
	size_t		n_faults;
};
void	mesh_hlt_server_init(struct mesh_hlt_server_state *s, uint16_t company_id);
int	mesh_hlt_server_add_fault(struct mesh_hlt_server_state *s, uint8_t fault);
void	mesh_hlt_server_clear_faults(struct mesh_hlt_server_state *s);

#endif /* _MESH_HEALTH_MODEL_H_ */
