/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh beacons.
 *
 * Implements the beacon PDUs of the Bluetooth Mesh Protocol specification
 * (MshPRT_v1.1) Section 3.9 "Bluetooth Mesh beacons", built on the
 * cryptographic toolbox in mesh_crypto.[ch] (Section 3.8):
 *
 *   - Unprovisioned Device beacon (Section 3.9.2, Beacon Type 0x00)
 *   - Secure Network beacon        (Section 3.9.3, Beacon Type 0x01)
 *
 * The module is pure and hardware-free: every function operates on values
 * in network (big-endian) byte order, performs no I/O, keeps no global
 * state, and clears intermediate secrets with explicit_bzero().  Each
 * function returns 0 on success and -1 on failure; on failure the output
 * buffers/structures are left zeroed.
 *
 * The Secure Network beacon is authenticated with a BeaconKey derived from
 * the NetKey (Section 3.9.6.3.6):
 *
 *   BeaconKey = k1(NetKey, s1("nkbk"), "id128" || 0x01)
 *
 * and the NetworkID carried in the beacon is k3(NetKey) (Section 3.8.2.7).
 * The Authentication Value is
 *
 *   AuthValue = AES-CMAC(BeaconKey, Flags || NetworkID || IVIndex)[0..7]
 *
 * (Section 3.9.3.1); a receiver recomputes it from the NetKey and rejects
 * the beacon on a mismatch.
 */

#ifndef _MESH_BEACON_H_
#define _MESH_BEACON_H_

#include <stddef.h>
#include <stdint.h>

/* Beacon Type octet.  MshPRT_v1.1 Section 3.9. */
#define	MESH_BEACON_TYPE_UNPROVISIONED	0x00
#define	MESH_BEACON_TYPE_SECURE_NETWORK	0x01
#define	MESH_BEACON_TYPE_MESH_PRIVATE	0x02	/* Section 3.9.4 */

/*
 * Secure Network beacon wire layout (Section 3.9.3):
 *   octet 0     Beacon Type = 0x01
 *   octet 1     Flags: bit0 Key Refresh, bit1 IV Update
 *   octets 2-9  Network ID (k3 of the NetKey)
 *   octets 10-13 IV Index (32-bit, big-endian)
 *   octets 14-21 Authentication Value (64-bit)
 */
#define	MESH_NETWORK_ID_LEN		8
#define	MESH_BEACON_AUTH_LEN		8
#define	MESH_SECURE_BEACON_LEN		22

/* Secure Network beacon Flags octet bits (Section 3.9.3). */
#define	MESH_BEACON_FLAG_KEY_REFRESH	0x01
#define	MESH_BEACON_FLAG_IV_UPDATE	0x02

/* OOB Information bits 9 and 10 are RFU in Mesh Protocol 1.1. */
#define	MESH_OOB_INFO_MASK		0xf9ffu

/*
 * Unprovisioned Device beacon wire layout (Section 3.9.2):
 *   octet 0      Beacon Type = 0x00
 *   octets 1-16  Device UUID (16 octets)
 *   octets 17-18 OOB Information (16-bit, big-endian)
 *   octets 19-22 URI Hash (4 octets, OPTIONAL)
 */
#define	MESH_UUID_LEN			16
#define	MESH_UNPROV_BEACON_MIN_LEN	19	/* type + UUID + OOB */
#define	MESH_UNPROV_BEACON_MAX_LEN	23	/* + URI hash */

/*
 * Mesh Private beacon wire layout (Section 3.9.4):
 *   octet 0      Beacon Type = 0x02
 *   octets 1-13  Random (13 octets)
 *   octets 14-18 Obfuscated Private Beacon Data (Flags(1) || IV Index(4))
 *   octets 19-26 Authentication Tag (64-bit)
 * The Private Beacon Data is obfuscated+authenticated with AES-CCM under the
 * PrivateBeaconKey using the Random as the nonce and an 8-octet tag.
 */
#define	MESH_PRIVATE_BEACON_RANDOM_LEN	13
#define	MESH_PRIVATE_BEACON_DATA_LEN	5	/* Flags(1) + IV Index(4) */
#define	MESH_PRIVATE_BEACON_TAG_LEN	8
#define	MESH_PRIVATE_BEACON_LEN		27

/* Parsed Secure Network beacon (Section 3.9.3). */
struct mesh_secure_beacon {
	uint8_t		key_refresh;			/* 0 or 1 */
	uint8_t		iv_update;			/* 0 or 1 */
	uint8_t		network_id[MESH_NETWORK_ID_LEN];
	uint32_t	iv_index;
	uint8_t		auth[MESH_BEACON_AUTH_LEN];	/* as received/built */
};

/* Parsed Mesh Private beacon (Section 3.9.4). */
struct mesh_private_beacon {
	uint8_t		key_refresh;			/* 0 or 1 */
	uint8_t		iv_update;			/* 0 or 1 */
	uint32_t	iv_index;
	uint8_t		random[MESH_PRIVATE_BEACON_RANDOM_LEN];
};

/* Parsed Unprovisioned Device beacon (Section 3.9.2). */
struct mesh_unprov_beacon {
	uint8_t		uuid[MESH_UUID_LEN];
	uint16_t	oob;
	int		has_uri_hash;
	uint8_t		uri_hash[4];
};

/*
 * BeaconKey derivation (Section 3.9.6.3.6):
 *   BeaconKey = k1(NetKey, s1("nkbk"), "id128" || 0x01)
 */
int	mesh_beacon_key(const uint8_t netkey[16], uint8_t out[16]);

/*
 * NetworkID carried in the Secure Network beacon: k3(NetKey).  Section
 * 3.8.2.7.  Convenience wrapper so callers/tests can obtain the exact 8
 * octets without pulling in mesh_crypto.h directly.
 */
int	mesh_beacon_network_id(const uint8_t netkey[16],
	    uint8_t out[MESH_NETWORK_ID_LEN]);

/*
 * Authentication Value construction (Section 3.9.3.1):
 *   AuthValue = AES-CMAC(BeaconKey, Flags || NetworkID || IVIndex)[0..7]
 * The Flags octet is (key_refresh) | (iv_update << 1).
 */
int	mesh_secure_beacon_auth(const uint8_t beaconkey[16],
	    uint8_t key_refresh, uint8_t iv_update,
	    const uint8_t network_id[MESH_NETWORK_ID_LEN], uint32_t iv_index,
	    uint8_t auth[MESH_BEACON_AUTH_LEN]);

/*
 * Build a complete Secure Network beacon (22 octets, including the Beacon
 * Type octet) from the NetKey and the flag/IV-index state.  The NetworkID
 * (k3) and BeaconKey (k1) are derived internally and the Authentication
 * Value is computed and appended.
 */
int	mesh_secure_beacon_build(const uint8_t netkey[16], uint8_t key_refresh,
	    uint8_t iv_update, uint32_t iv_index, uint8_t *out, size_t *outlen);

/*
 * Parse and authenticate a Secure Network beacon.  Verifies the Beacon
 * Type, that the carried NetworkID equals k3(NetKey), and that the
 * Authentication Value matches AES-CMAC(BeaconKey, ...).  Returns -1 (with
 * *out zeroed) on any mismatch or malformed input.
 */
int	mesh_secure_beacon_parse(const uint8_t netkey[16], const uint8_t *in,
	    size_t inlen, struct mesh_secure_beacon *out);

/*
 * PrivateBeaconKey derivation (Section 3.9.6.3.7):
 *   PrivateBeaconKey = k1(NetKey, s1("nkpk"), "id128" || 0x01)
 */
int	mesh_private_beacon_key(const uint8_t netkey[16], uint8_t out[16]);

/*
 * Build / parse+authenticate a Mesh Private beacon (27 octets, Section
 * 3.9.4).  build obfuscates+authenticates the Flags/IV-index under the
 * PrivateBeaconKey with the supplied 13-octet Random; parse recovers them and
 * returns -1 (with *out zeroed) on a bad Authentication Tag, a reserved Flags
 * bit, or malformed input.
 */
int	mesh_private_beacon_build(const uint8_t netkey[16], uint8_t key_refresh,
	    uint8_t iv_update, uint32_t iv_index,
	    const uint8_t random[MESH_PRIVATE_BEACON_RANDOM_LEN], uint8_t *out,
	    size_t *outlen);
int	mesh_private_beacon_parse(const uint8_t netkey[16], const uint8_t *in,
	    size_t inlen, struct mesh_private_beacon *out);

/*
 * Unprovisioned Device beacon codec (Section 3.9.2).  build packs
 * type||UUID||OOB[||URIHash]; parse is its inverse.  No crypto: the URI
 * Hash, when present, is carried verbatim (its s1() derivation is a
 * provisioning-bearer concern outside this module).
 */
int	mesh_unprov_beacon_build(const struct mesh_unprov_beacon *in,
	    uint8_t *out, size_t *outlen);
int	mesh_unprov_beacon_parse(const uint8_t *in, size_t inlen,
	    struct mesh_unprov_beacon *out);

#endif /* _MESH_BEACON_H_ */
