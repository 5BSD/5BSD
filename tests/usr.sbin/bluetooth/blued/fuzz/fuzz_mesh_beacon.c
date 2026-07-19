/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for the Bluetooth Mesh Secure Network beacon parser
 * (lib/libmesh/mesh_beacon.c on top of mesh_crypto.c).
 *
 * A Secure Network beacon is fully attacker-controlled radio input: it
 * arrives on the advertising / GATT-Provisioning bearer before any
 * authentication, and the receiver must parse the fixed-layout beacon,
 * recompute the NetworkID (k3) and BeaconKey (k1), and verify the
 * Authentication Value purely on those untrusted bytes.  This harness treats
 * the fuzz input AS one received beacon and drives the parse/authenticate
 * path against it, keyed with the FIXED MshPRT_v1.1 Section 8 NetKey
 * (7dd7364cd842ad18c17c2b820c84c3d6) so the k1/k3/CMAC math actually runs on
 * arbitrary input.
 *
 * The point is to find OOB/UB in the parser + auth path, NOT to forge a valid
 * Authentication Value (cryptographically infeasible for the fuzzer).  The
 * Unprovisioned Device beacon codec is exercised too, since it shares the
 * beacon dispatch surface.
 *
 * ASan/UBSan catch any out-of-bounds access or undefined behaviour.
 *
 * Reference: MshPRT_v1.1 Section 3.9 (beacons), Section 3.8 (security),
 * Section 8.4.3 (Secure Network beacon sample data).
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_beacon.h"

/* Section 8 fixed NetKey (host-order bytes). */
static const uint8_t mesh_netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mesh_secure_beacon sb;
	struct mesh_unprov_beacon ub;
	uint8_t *copy;

	/* A beacon PDU is small; keep slack so oversized-length paths run. */
	if (size > 64)
		size = 64;

	/* Own copy so ASan flags any read past the exact input length. */
	copy = malloc(size == 0 ? 1 : size);
	if (copy == NULL)
		return (0);
	if (size != 0)
		memcpy(copy, data, size);

	/*
	 * Secure Network beacon parse + authenticate on the raw bytes.  The
	 * carried NetworkID and Authentication Value are checked against the
	 * fixed NetKey; attacker bytes will (almost always) fail, but only
	 * after k3/k1/CMAC have chewed on them.
	 */
	memset(&sb, 0, sizeof(sb));
	(void)mesh_secure_beacon_parse(mesh_netkey, copy, size, &sb);

	/*
	 * Force the Beacon Type octet to Secure Network so the length/flags/
	 * NetworkID branches past the type gate are exercised on fuzz bytes.
	 */
	if (size >= 1) {
		uint8_t forced[64];

		memcpy(forced, copy, size);
		forced[0] = MESH_BEACON_TYPE_SECURE_NETWORK;
		memset(&sb, 0, sizeof(sb));
		(void)mesh_secure_beacon_parse(mesh_netkey, forced, size, &sb);
	}

	/* Unprovisioned Device beacon codec on the raw bytes. */
	memset(&ub, 0, sizeof(ub));
	(void)mesh_unprov_beacon_parse(copy, size, &ub);

	free(copy);
	return (0);
}
