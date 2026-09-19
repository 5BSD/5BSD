/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh Proxy protocol receive path
 * (lib/libmesh/mesh_proxy.c on top of mesh_crypto.c).
 *
 * A Proxy PDU is fully attacker-controlled GATT input: it arrives on the
 * Mesh Proxy Data In / Data Out characteristic (a plain Write Without
 * Response or Notification, no bonding required) and the receiver must
 * parse the SAR|MessageType header, reassemble segments across PDUs, and --
 * for a Proxy Configuration message -- deobfuscate, run AES-CCM and verify
 * the NetMIC purely on those untrusted bytes.  This harness treats the fuzz
 * input as a stream of received Proxy PDUs and drives the whole receive
 * surface against it:
 *
 *   mesh_proxy_pdu_parse()   -- the SAR/MessageType header codec.
 *   mesh_proxy_reasm_feed()  -- the bounded SAR reassembler, fed one PDU at
 *                               a time (length-prefixed slices of the input)
 *                               so segment ordering / type-change / overflow
 *                               paths are explored.
 *   mesh_proxy_cfg_parse()   -- the plaintext proxy-config opcode/parameter
 *                               codec.
 *   mesh_proxy_cfg_decrypt() -- the real deobfuscate + AES-CCM + NetMIC path,
 *                               keyed with the FIXED MshPRT_v1.1 Section 8.9.1
 *                               material so the PECB/CCM math actually runs on
 *                               arbitrary input.  Attacker bytes will (almost
 *                               always) fail the MIC, but only after the
 *                               deobfuscate + CCM code has chewed on them.
 *
 * The fixed key material is the Section 8.9.1 managed-flooding security:
 *   NID           = 0x10
 *   EncryptionKey = 3a4fe84a6cc2c6a766ea93f1084d4039
 *   PrivacyKey    = f695fcce709ccface4d8b7a1e6e39d25
 *   IV Index      = 0x12345678
 *
 * ASan/UBSan catch any out-of-bounds access or undefined behaviour on the
 * parse / reassemble / decrypt path.
 *
 * Reference: MshPRT_v1.1 Section 6 (Proxy protocol), Section 3.8 (security),
 * Section 8.9 (proxy configuration message sample data).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_proxy.h"

/* Section 8.9.1 fixed managed-flooding security material (host-order). */
static const uint8_t mesh_enckey[16] = {
	0x3a, 0x4f, 0xe8, 0x4a, 0x6c, 0xc2, 0xc6, 0xa7,
	0x66, 0xea, 0x93, 0xf1, 0x08, 0x4d, 0x40, 0x39
};
static const uint8_t mesh_privkey[16] = {
	0xf6, 0x95, 0xfc, 0xce, 0x70, 0x9c, 0xcf, 0xac,
	0xe4, 0xd8, 0xb7, 0xa1, 0xe6, 0xe3, 0x9d, 0x25
};
#define	MESH_NID	0x10
#define	MESH_IVINDEX	0x12345678u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_proxy_reasm r;
	struct mesh_proxy_cfg cfg;
	uint8_t *copy;
	uint8_t sar, type, mtype, msg[MESH_PROXY_MAX_MSG];
	const uint8_t *pdata;
	size_t pdatalen, msglen, off;
	uint32_t seq;
	uint16_t src;
	int complete;

	/* Keep inputs bounded but leave slack for oversized-length paths. */
	if (size > 256)
		size = 256;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/* Single Proxy PDU parse on the raw bytes. */
	(void)mesh_proxy_pdu_parse(copy, size, &sar, &type, &pdata, &pdatalen);

	/* Plaintext proxy-config codec on the raw bytes. */
	memset(&cfg, 0, sizeof(cfg));
	(void)mesh_proxy_cfg_parse(copy, size, &cfg);

	/*
	 * Secured proxy-config receive path: NID check, header deobfuscation
	 * with the Privacy Key, AES-CCM decrypt and NetMIC verification, keyed
	 * with the fixed Section 8.9.1 material.
	 */
	msglen = 0;
	(void)mesh_proxy_cfg_decrypt(mesh_enckey, mesh_privkey, MESH_NID,
	    MESH_IVINDEX, copy, size, &seq, &src, msg, sizeof(msg), &msglen);

	/*
	 * SAR reassembly: carve the input into a stream of Proxy PDUs.  Each
	 * PDU is length-prefixed by one input octet (bounded to what remains),
	 * so segment ordering, MessageType changes and overflow are exercised
	 * across a fresh reassembler.
	 */
	mesh_proxy_reasm_init(&r);
	off = 0;
	while (off < size) {
		size_t seglen = copy[off++];

		if (seglen > size - off)
			seglen = size - off;
		if (seglen == 0)
			break;
		if (mesh_proxy_reasm_feed(&r, copy + off, seglen, &complete,
		    &mtype, msg, sizeof(msg), &msglen) != 0)
			mesh_proxy_reasm_init(&r);
		off += seglen;
	}

	free(copy);
	return (0);
}
