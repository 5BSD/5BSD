/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh provisioning bearer + PDU parsers
 * (lib/libmesh/mesh_provision.c).
 *
 * Provisioning is a PRE-AUTHENTICATION protocol: before any key agreement
 * completes, an unprovisioned device (or a Provisioner) accepts and parses
 * attacker-controlled bearer bytes off the air - PB-ADV Generic Provisioning
 * PDUs (Transaction Start / Continuation / Ack / Bearer Control) that are
 * reassembled into a Provisioning PDU, or PB-GATT Proxy PDUs.  A malformed
 * SegN, an out-of-range segment index, an inconsistent TotalLength, a
 * truncated field, or a reserved PDU type must all be handled without an
 * out-of-bounds access.  This is therefore a prime attack surface, and a
 * crash here is a real bug in our code.
 *
 * The harness treats the fuzz input as attacker-controlled bearer bytes and
 * drives:
 *
 *   mesh_prov_pdu_parse()      -- the Provisioning PDU Type/length/reserved
 *                                 codec, plus every structured per-type parser.
 *   mesh_gp_parse()            -- the Generic Provisioning GPCF decode.
 *   mesh_pbadv_parse()         -- the PB-ADV LinkID/Transaction framing, then
 *                                 the inner Generic Provisioning PDU.
 *   mesh_gp_reasm_input()      -- the transaction reassembly state machine,
 *                                 fed a stream of length-prefixed GP PDUs
 *                                 (segmentation is the core memcpy surface).
 *   mesh_pbgatt_parse()        -- the PB-GATT Proxy PDU SAR/type header.
 *
 * Every parser copies out of the input into fixed-size structures, so
 * AddressSanitizer / UndefinedBehaviorSanitizer catch any read past the exact
 * input length or any integer UB in the length arithmetic.
 *
 * Reference: MshPRT_v1.1 Section 5.3 (provisioning bearers) and Section 5.4.1
 * (Provisioning PDUs).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_provision.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_prov_pdu pp;
	struct mesh_prov_caps caps;
	struct mesh_prov_start start;
	struct mesh_prov_data pd;
	struct mesh_gp_parsed gp;
	struct mesh_gp_reasm reasm;
	uint8_t *copy;
	uint8_t x[32], y[32], c[16], r[16], enc[25], mic[8], att, ec;
	uint32_t link_id;
	uint8_t txn, sar, ptype;
	const uint8_t *inner, *payload;
	size_t inner_len, plen, off, pdu_len;
	uint8_t out_pdu[MESH_PROV_PDU_MAX];

	/* A PB-ADV packet is small; keep slack for oversize paths. */
	if (size > 512)
		size = 512;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/* Provisioning PDU codec + every structured per-type parser. */
	(void)mesh_prov_pdu_parse(copy, size, &pp);
	(void)mesh_prov_invite_parse(copy, size, &att);
	(void)mesh_prov_caps_parse(copy, size, &caps);
	(void)mesh_prov_start_parse(copy, size, &start);
	(void)mesh_prov_public_key_parse(copy, size, x, y);
	(void)mesh_prov_confirmation_parse(copy, size, c);
	(void)mesh_prov_random_parse(copy, size, r);
	(void)mesh_prov_data_pdu_parse(copy, size, enc, mic);
	(void)mesh_prov_failed_parse(copy, size, &ec);

	/* Provisioning data unpack requires exactly 25 octets. */
	if (size >= MESH_PROV_DATA_LEN)
		(void)mesh_prov_data_unpack(copy, &pd);

	/* Generic Provisioning PDU decode. */
	(void)mesh_gp_parse(copy, size, &gp);

	/* PB-ADV framing: strip LinkID/Transaction, then parse the inner GP PDU. */
	if (mesh_pbadv_parse(copy, size, &link_id, &txn, &inner, &inner_len) == 0)
		(void)mesh_gp_parse(inner, inner_len, &gp);

	/* PB-GATT Proxy PDU header. */
	(void)mesh_pbgatt_parse(copy, size, &sar, &ptype, &payload, &plen);

	/*
	 * Transaction reassembly: treat the input as a stream of length-prefixed
	 * Generic Provisioning PDUs (1-octet length, then that many GP-PDU
	 * octets) and feed each one to the reassembly state machine.  This
	 * drives the segment memcpy / offset arithmetic with arbitrary SegN,
	 * segment index, TotalLength and payload lengths.
	 */
	mesh_gp_reasm_init(&reasm);
	off = 0;
	while (off < size) {
		size_t chunk = copy[off++];

		if (chunk > size - off)
			chunk = size - off;
		if (mesh_gp_reasm_input(&reasm, copy + off, chunk) == 1)
			(void)mesh_gp_reasm_get(&reasm, out_pdu, &pdu_len);
		off += chunk;
		if (chunk == 0)
			break;	/* avoid spinning on a zero-length chunk */
	}

	free(copy);
	return (0);
}
