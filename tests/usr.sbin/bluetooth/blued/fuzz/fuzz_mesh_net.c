/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh network-layer receive path
 * (lib/libmesh/mesh_net.c on top of mesh_crypto.c).
 *
 * A secured Network PDU is fully attacker-controlled radio input: it
 * arrives on the advertising / GATT bearer before any authentication, and
 * the receiver must deobfuscate the header, check the NID, run AES-CCM and
 * verify the NetMIC purely on those untrusted bytes.  This harness treats
 * the fuzz input AS one received secured Network PDU and drives the whole
 * receive path against it:
 *
 *   mesh_net_pdu_parse()  -- the cleartext field-layout codec, fed the raw
 *                            bytes so short/oversized length fields are
 *                            explored directly.
 *   mesh_net_decrypt()    -- the real deobfuscate + AES-CCM + NetMIC path,
 *                            keyed with FIXED MshPRT_v1.1 Section 8.2.2 test
 *                            material so the PECB/CCM math actually runs on
 *                            arbitrary input.  The point is to find OOB/UB in
 *                            parse + deobfuscate + decrypt, NOT to forge a
 *                            valid MIC (which is cryptographically infeasible
 *                            for the fuzzer to hit).
 *   mesh_net_nid_match()  -- the NID predicate, driven with the input's
 *                            octet 0.
 *   mesh_net_relay()      -- the relay/TTL-decrement predicate, driven with
 *                            a fuzzed header octet.
 *
 * The fixed key material is the Section 8.2.2 network security produced by
 * mesh_k2() from NetKey 7dd7364cd842ad18c17c2b820c84c3d6 with IV Index
 * 0x12345678:
 *   NID           = 0x68
 *   EncryptionKey = 0953fa93e7caac9638f58820220a398e
 *   PrivacyKey    = 8b84eedec100067d670971dd2aa700cf
 *
 * ASan/UBSan catch any out-of-bounds access or undefined behaviour on the
 * parse/deobfuscate/decrypt path.
 *
 * Reference: MshPRT_v1.1 Section 3.4 (Network layer), Section 3.8 (Mesh
 * security), Section 8.2.2 / 8.3 (sample data).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_net.h"

/* Section 8.2.2 fixed network security material (host-order key bytes). */
static const uint8_t mesh_enckey[16] = {
	0x09, 0x53, 0xfa, 0x93, 0xe7, 0xca, 0xac, 0x96,
	0x38, 0xf5, 0x88, 0x20, 0x22, 0x0a, 0x39, 0x8e
};
static const uint8_t mesh_privkey[16] = {
	0x8b, 0x84, 0xee, 0xde, 0xc1, 0x00, 0x06, 0x7d,
	0x67, 0x09, 0x71, 0xdd, 0x2a, 0xa7, 0x00, 0xcf
};
#define	MESH_NID	0x68
#define	MESH_IVINDEX	0x12345678u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_net_pdu out;
	uint8_t *copy;

	/* A secured Network PDU on the advertising bearer is <= 29 octets;
	 * accept a little slack so oversized-length paths are still reached. */
	if (size > 64)
		size = 64;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/* Cleartext field-layout codec on the raw bytes. */
	memset(&out, 0, sizeof(out));
	(void)mesh_net_pdu_parse(copy, size, &out);

	/*
	 * Full secured receive path: NID check, header deobfuscation with the
	 * Privacy Key, AES-CCM decrypt and NetMIC verification, all keyed with
	 * the fixed Section 8.2.2 material.  Attacker bytes will (almost
	 * always) fail the MIC, but only after the deobfuscate + CCM code has
	 * chewed on them.
	 */
	memset(&out, 0, sizeof(out));
	(void)mesh_net_decrypt(mesh_enckey, mesh_privkey, MESH_NID,
	    MESH_IVINDEX, copy, size, &out);

	/* Deobfuscation via the NID that matches the fixed key, so decrypt is
	 * driven past the up-front NID gate at least sometimes. */
	if (size >= 1) {
		uint8_t forced[64];

		memcpy(forced, copy, size);
		forced[0] = (uint8_t)((forced[0] & 0x80) | MESH_NID);
		memset(&out, 0, sizeof(out));
		(void)mesh_net_decrypt(mesh_enckey, mesh_privkey, MESH_NID,
		    MESH_IVINDEX, forced, size, &out);

		/* NID predicate on the received octet 0. */
		(void)mesh_net_nid_match(MESH_NID, copy[0]);

		/* Relay/TTL predicate on a fuzzed header octet: the low 7 bits
		 * are the TTL that gates the relay decision. */
		{
			uint8_t new_ttl;

			(void)mesh_net_relay((uint8_t)(copy[0] & 0x7f),
			    &new_ttl);
			(void)mesh_net_relay((uint8_t)(copy[0] & 0x7f), NULL);
		}
	}

	free(copy);
	return (0);
}
