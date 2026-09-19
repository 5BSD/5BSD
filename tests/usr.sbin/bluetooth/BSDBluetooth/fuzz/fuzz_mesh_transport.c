/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh transport layer
 * (lib/libmesh/mesh_transport.c on top of mesh_crypto.c).
 *
 * The transport layer sits directly above the network layer: once a Network
 * PDU has been deobfuscated and NetMIC-verified, its Lower Transport PDU is
 * attacker-controlled and must be parsed, reassembled (SAR) and upper-
 * transport-decrypted before any of it can be trusted.  The Segment
 * Acknowledgement reflected back is likewise built from attacker-influenced
 * SeqZero/BlockAck values.  This harness treats the fuzz input as one (or a
 * stream of) received Lower Transport PDU(s) and drives the whole surface:
 *
 *   mesh_lower_parse()   -- the Lower Transport PDU field-layout codec, run
 *                           for both CTL=0 (access) and CTL=1 (control) since
 *                           the enclosing network CTL bit is itself attacker
 *                           supplied.
 *   mesh_reasm_input()   -- the SAR reassembly state machine (Section 3.5.3.2),
 *                           the core memcpy-into-fixed-buffer surface.  The
 *                           input is sliced into length-prefixed segments and
 *                           fed one at a time into a single session so multi-
 *                           segment (SegO/SegN, SeqZero, block-ack) paths are
 *                           explored, then mesh_reasm_get() extracts the
 *                           reassembled Upper Transport PDU when complete.
 *   mesh_upper_decrypt() -- the AES-CCM upper-transport decrypt + TransMIC
 *                           verify (Section 3.6.5.1), keyed with a FIXED
 *                           AppKey so the CCM math runs over arbitrary bytes.
 *                           akf/szmic/label-UUID are taken from a fuzzed
 *                           selector byte so both nonce forms and the virtual-
 *                           address AAD path are reached.  Attacker bytes will
 *                           (almost always) fail the MIC, but only after the
 *                           CCM code has chewed on them.
 *   mesh_seg_ack_parse() -- the Segment Acknowledgement (Opcode 0x00) codec.
 *   mesh_blockack_from_segs() -- the SegO-array -> block-ack bitmap helper.
 *
 * ASan/UBSan catch any out-of-bounds access, oversized memcpy or integer UB
 * on the parse / reassembly / decrypt path.
 *
 * Reference: MshPRT_v1.1 Section 3.5 (lower transport / SAR), Section 3.6
 * (upper transport), Section 3.8 (security).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_transport.h"

/* Fixed 128-bit AppKey (arbitrary but constant) so the CCM path is stable. */
static const uint8_t mesh_appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};
/* Fixed Label UUID for the virtual-address AAD path. */
static const uint8_t mesh_label[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
#define	MESH_IVINDEX	0x12345678u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_lower lo;
	struct mesh_seg_ack ack;
	struct mesh_reasm r;
	uint8_t *copy;
	uint8_t sel;
	size_t i;

	/* An advertising-bearer Lower Transport PDU is small; allow slack so
	 * oversized-length branches are still reached, but bound reassembly. */
	if (size > 512)
		size = 512;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	sel = size >= 1 ? copy[0] : 0;

	/* Lower Transport PDU codec, both network CTL interpretations. */
	(void)mesh_lower_parse(0, copy, size, &lo);
	(void)mesh_lower_parse(1, copy, size, &lo);

	/* Segment Acknowledgement codec (fixed 7-octet form). */
	(void)mesh_seg_ack_parse(copy, size, &ack);

	/*
	 * SAR reassembly state machine.  Slice the input into a stream of
	 * length-prefixed segmented-access Lower Transport PDUs and feed them
	 * into ONE session (constant SRC) so multi-segment accumulation, the
	 * SegN-consistency and block-ack/duplicate paths, and the completion
	 * extraction are all exercised.  A src that flips on the high selector
	 * bit also drives the "new (SRC,SeqZero) restarts session" branch.
	 */
	mesh_reasm_init(&r);
	i = (size >= 1) ? 1 : 0;	/* octet 0 is the selector */
	while (i < size) {
		size_t seglen = copy[i++];
		const uint8_t *seg = copy + i;
		uint16_t src;
		int rc;

		if (seglen > size - i)
			seglen = size - i;	/* clamp to remaining input */
		src = (uint16_t)((sel & 0x80) ? 0x0002 : 0x0001);
		rc = mesh_reasm_input(&r, src, seg, seglen);
		if (rc == 1) {
			uint8_t upper[MESH_UPPER_MAX];
			size_t ulen = 0;

			if (mesh_reasm_get(&r, upper, &ulen) == 0 && ulen > 0) {
				uint8_t acc[MESH_UPPER_MAX];
				size_t alen = 0;

				/* Feed the reassembled Upper Transport PDU into
				 * the AES-CCM decrypt, honouring the session's
				 * AKF/SZMIC as reassembly recorded them. */
				(void)mesh_upper_decrypt(mesh_appkey, r.akf,
				    r.szmic, 0x000001, src, 0x0003,
				    MESH_IVINDEX, NULL, upper, ulen, acc, &alen);
			}
		}
		i += seglen;
	}

	/*
	 * Direct upper-transport decrypt over the raw input, with the nonce
	 * form / MIC size / virtual-address AAD selected from the fuzzed byte.
	 */
	if (size >= 2) {
		uint8_t acc[MESH_UPPER_MAX];
		size_t alen = 0;
		int akf = (sel & 0x01);
		int szmic = (sel >> 1) & 0x01;
		const uint8_t *label = (sel & 0x04) ? mesh_label : NULL;
		uint16_t src = (uint16_t)((copy[1] << 8) | sel);
		uint16_t dst = (uint16_t)(sel << 8 | 0x03);

		(void)mesh_upper_decrypt(mesh_appkey, akf, szmic, sel,
		    src, dst, MESH_IVINDEX, label, copy, size, acc, &alen);
	}

	/* Block-ack bitmap helper over the raw bytes as a SegO array. */
	(void)mesh_blockack_from_segs(copy, size);

	free(copy);
	return (0);
}
