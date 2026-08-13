/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh beacons (MshPRT_v1.1 Section 3.9), built on the
 * mesh_crypto.[ch] security toolbox (Section 3.8).
 *
 * See mesh_beacon.h for the wire layouts and the BeaconKey / NetworkID /
 * Authentication Value constructions.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_beacon.h"
#include "mesh_probes.h"

/*
 * BeaconKey = k1(NetKey, s1("nkbk"), "id128" || 0x01).
 * MshPRT_v1.1 Section 3.9.6.3.6.
 */
int
mesh_beacon_key(const uint8_t netkey[16], uint8_t out[16])
{
	static const char nkbk[] = "nkbk";
	static const uint8_t id128[] = { 'i', 'd', '1', '2', '8', 0x01 };
	uint8_t salt[16];
	int rc;

	if (netkey == NULL || out == NULL)
		return (-1);
	if (mesh_s1((const uint8_t *)nkbk, sizeof(nkbk) - 1, salt) != 0) {
		memset(out, 0, 16);
		return (-1);
	}
	rc = mesh_k1(netkey, 16, salt, id128, sizeof(id128), out);
	explicit_bzero(salt, sizeof(salt));
	if (rc != 0)
		memset(out, 0, 16);
	return (rc);
}

/*
 * PrivateBeaconKey = k1(NetKey, s1("nkpk"), "id128" || 0x01).
 * MshPRT_v1.1 Section 3.9.6.3.7.
 */
int
mesh_private_beacon_key(const uint8_t netkey[16], uint8_t out[16])
{
	static const char nkpk[] = "nkpk";
	static const uint8_t id128[] = { 'i', 'd', '1', '2', '8', 0x01 };
	uint8_t salt[16];
	int rc;

	if (netkey == NULL || out == NULL)
		return (-1);
	if (mesh_s1((const uint8_t *)nkpk, sizeof(nkpk) - 1, salt) != 0) {
		memset(out, 0, 16);
		return (-1);
	}
	rc = mesh_k1(netkey, 16, salt, id128, sizeof(id128), out);
	explicit_bzero(salt, sizeof(salt));
	if (rc != 0)
		memset(out, 0, 16);
	return (rc);
}

/*
 * NetworkID = k3(NetKey).  MshPRT_v1.1 Section 3.8.2.7.
 */
int
mesh_beacon_network_id(const uint8_t netkey[16],
    uint8_t out[MESH_NETWORK_ID_LEN])
{

	if (netkey == NULL || out == NULL)
		return (-1);
	return (mesh_k3(netkey, out));
}

/*
 * AuthValue = AES-CMAC(BeaconKey, Flags || NetworkID || IVIndex)[0..7].
 * MshPRT_v1.1 Section 3.9.3.1.
 */
int
mesh_secure_beacon_auth(const uint8_t beaconkey[16], uint8_t key_refresh,
    uint8_t iv_update, const uint8_t network_id[MESH_NETWORK_ID_LEN],
    uint32_t iv_index, uint8_t auth[MESH_BEACON_AUTH_LEN])
{
	uint8_t msg[1 + MESH_NETWORK_ID_LEN + 4];
	uint8_t mac[16];
	int rc;

	if (beaconkey == NULL || network_id == NULL || auth == NULL)
		return (-1);
	if (key_refresh > 1 || iv_update > 1) {
		memset(auth, 0, MESH_BEACON_AUTH_LEN);
		return (-1);
	}

	msg[0] = (uint8_t)((key_refresh & 0x01) |
	    ((iv_update & 0x01) << 1));
	memcpy(msg + 1, network_id, MESH_NETWORK_ID_LEN);
	msg[9] = (uint8_t)(iv_index >> 24);
	msg[10] = (uint8_t)(iv_index >> 16);
	msg[11] = (uint8_t)(iv_index >> 8);
	msg[12] = (uint8_t)iv_index;

	rc = mesh_aes_cmac(beaconkey, msg, sizeof(msg), mac);
	if (rc == 0)
		memcpy(auth, mac, MESH_BEACON_AUTH_LEN);
	else
		memset(auth, 0, MESH_BEACON_AUTH_LEN);
	explicit_bzero(mac, sizeof(mac));
	explicit_bzero(msg, sizeof(msg));
	/* Secure Network Beacon auth: key_refresh flag + result (0 ok). */
	MESH_PROBE_BEACON_AUTH(key_refresh, rc);
	return (rc);
}

static int
secure_beacon_auth_raw(const uint8_t beaconkey[16], uint8_t flags,
    const uint8_t network_id[MESH_NETWORK_ID_LEN], uint32_t iv_index,
    uint8_t auth[MESH_BEACON_AUTH_LEN])
{
	uint8_t msg[1 + MESH_NETWORK_ID_LEN + 4], mac[16];
	int rc;

	msg[0] = flags;
	memcpy(msg + 1, network_id, MESH_NETWORK_ID_LEN);
	msg[9] = (uint8_t)(iv_index >> 24);
	msg[10] = (uint8_t)(iv_index >> 16);
	msg[11] = (uint8_t)(iv_index >> 8);
	msg[12] = (uint8_t)iv_index;
	rc = mesh_aes_cmac(beaconkey, msg, sizeof(msg), mac);
	if (rc == 0)
		memcpy(auth, mac, MESH_BEACON_AUTH_LEN);
	explicit_bzero(mac, sizeof(mac));
	explicit_bzero(msg, sizeof(msg));
	return (rc);
}

/*
 * Build a complete Secure Network beacon.  MshPRT_v1.1 Section 3.9.3.
 */
int
mesh_secure_beacon_build(const uint8_t netkey[16], uint8_t key_refresh,
    uint8_t iv_update, uint32_t iv_index, uint8_t *out, size_t *outlen)
{
	uint8_t netid[MESH_NETWORK_ID_LEN];
	uint8_t bkey[16];
	uint8_t auth[MESH_BEACON_AUTH_LEN];
	int rc = -1;

	if (netkey == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (key_refresh > 1 || iv_update > 1)
		return (-1);

	if (mesh_beacon_network_id(netkey, netid) != 0)
		goto out;
	if (mesh_beacon_key(netkey, bkey) != 0)
		goto out;
	if (mesh_secure_beacon_auth(bkey, key_refresh, iv_update, netid,
	    iv_index, auth) != 0)
		goto out;

	out[0] = MESH_BEACON_TYPE_SECURE_NETWORK;
	out[1] = (uint8_t)((key_refresh & 0x01) | ((iv_update & 0x01) << 1));
	memcpy(out + 2, netid, MESH_NETWORK_ID_LEN);
	out[10] = (uint8_t)(iv_index >> 24);
	out[11] = (uint8_t)(iv_index >> 16);
	out[12] = (uint8_t)(iv_index >> 8);
	out[13] = (uint8_t)iv_index;
	memcpy(out + 14, auth, MESH_BEACON_AUTH_LEN);
	*outlen = MESH_SECURE_BEACON_LEN;
	rc = 0;
out:
	explicit_bzero(bkey, sizeof(bkey));
	explicit_bzero(auth, sizeof(auth));
	if (rc != 0) {
		memset(out, 0, MESH_SECURE_BEACON_LEN);
		*outlen = 0;
	}
	return (rc);
}

/*
 * Parse and authenticate a Secure Network beacon.  MshPRT_v1.1
 * Section 3.9.3.
 */
int
mesh_secure_beacon_parse(const uint8_t netkey[16], const uint8_t *in,
    size_t inlen, struct mesh_secure_beacon *out)
{
	uint8_t netid[MESH_NETWORK_ID_LEN];
	uint8_t bkey[16];
	uint8_t auth[MESH_BEACON_AUTH_LEN];
	uint8_t key_refresh, iv_update;
	uint32_t iv_index;
	int rc = -1;

	if (netkey == NULL || in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));

	if (inlen != MESH_SECURE_BEACON_LEN)
		return (-1);
	if (in[0] != MESH_BEACON_TYPE_SECURE_NETWORK)
		return (-1);
	key_refresh = (uint8_t)(in[1] & MESH_BEACON_FLAG_KEY_REFRESH);
	iv_update = (uint8_t)((in[1] & MESH_BEACON_FLAG_IV_UPDATE) >> 1);
	iv_index = ((uint32_t)in[10] << 24) | ((uint32_t)in[11] << 16) |
	    ((uint32_t)in[12] << 8) | (uint32_t)in[13];

	/* The carried NetworkID must equal k3(NetKey) for this key. */
	if (mesh_beacon_network_id(netkey, netid) != 0)
		goto out;
	if (memcmp(netid, in + 2, MESH_NETWORK_ID_LEN) != 0)
		goto out;

	/* Recompute and verify the Authentication Value. */
	if (mesh_beacon_key(netkey, bkey) != 0)
		goto out;
	/* Authenticate the wire Flags, then ignore their RFU bits semantically. */
	if (secure_beacon_auth_raw(bkey, in[1], netid,
	    iv_index, auth) != 0)
		goto out;
	if (timingsafe_bcmp(auth, in + 14, MESH_BEACON_AUTH_LEN) != 0)
		goto out;

	out->key_refresh = key_refresh;
	out->iv_update = iv_update;
	memcpy(out->network_id, netid, MESH_NETWORK_ID_LEN);
	out->iv_index = iv_index;
	memcpy(out->auth, in + 14, MESH_BEACON_AUTH_LEN);
	rc = 0;
out:
	explicit_bzero(bkey, sizeof(bkey));
	explicit_bzero(auth, sizeof(auth));
	if (rc != 0)
		memset(out, 0, sizeof(*out));
	return (rc);
}

/*
 * Build a Mesh Private beacon.  MshPRT_v1.1 Section 3.9.4.
 *
 * The 5-octet Private Beacon Data (Flags || IV Index) is obfuscated and
 * authenticated with AES-CCM under the PrivateBeaconKey, using the 13-octet
 * Random as the nonce and an 8-octet Authentication Tag; no additional
 * authenticated data.  Wire layout (27 octets):
 *   octet 0      Beacon Type = 0x02
 *   octets 1-13  Random (13)
 *   octets 14-18 Obfuscated Private Beacon Data (5)
 *   octets 19-26 Authentication Tag (8)
 */
int
mesh_private_beacon_build(const uint8_t netkey[16], uint8_t key_refresh,
    uint8_t iv_update, uint32_t iv_index,
    const uint8_t random[MESH_PRIVATE_BEACON_RANDOM_LEN], uint8_t *out,
    size_t *outlen)
{
	uint8_t pbkey[16];
	uint8_t data[MESH_PRIVATE_BEACON_DATA_LEN];
	uint8_t obf[MESH_PRIVATE_BEACON_DATA_LEN];
	uint8_t tag[MESH_PRIVATE_BEACON_TAG_LEN];
	int rc = -1;

	if (netkey == NULL || random == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (key_refresh > 1 || iv_update > 1)
		return (-1);

	data[0] = (uint8_t)((key_refresh & 0x01) | ((iv_update & 0x01) << 1));
	data[1] = (uint8_t)(iv_index >> 24);
	data[2] = (uint8_t)(iv_index >> 16);
	data[3] = (uint8_t)(iv_index >> 8);
	data[4] = (uint8_t)iv_index;

	if (mesh_private_beacon_key(netkey, pbkey) != 0)
		goto out;
	if (mesh_aes_ccm_encrypt(pbkey, random, NULL, 0, data,
	    MESH_PRIVATE_BEACON_DATA_LEN, obf, tag,
	    MESH_PRIVATE_BEACON_TAG_LEN) != 0)
		goto out;

	out[0] = MESH_BEACON_TYPE_MESH_PRIVATE;
	memcpy(out + 1, random, MESH_PRIVATE_BEACON_RANDOM_LEN);
	memcpy(out + 14, obf, MESH_PRIVATE_BEACON_DATA_LEN);
	memcpy(out + 19, tag, MESH_PRIVATE_BEACON_TAG_LEN);
	*outlen = MESH_PRIVATE_BEACON_LEN;
	rc = 0;
out:
	explicit_bzero(pbkey, sizeof(pbkey));
	explicit_bzero(data, sizeof(data));
	if (rc != 0) {
		memset(out, 0, MESH_PRIVATE_BEACON_LEN);
		*outlen = 0;
	}
	return (rc);
}

/*
 * Parse and authenticate a Mesh Private beacon.  MshPRT_v1.1 Section 3.9.4.
 * Recovers the Flags and IV Index by AES-CCM-decrypting the obfuscated
 * Private Beacon Data under the PrivateBeaconKey with the carried Random as
 * the nonce; a bad Authentication Tag fails.  Reserved Flags bits (2-7) are
 * ignored (processed as 0) per MshPRT Section 1.3.2, not rejected.
 */
int
mesh_private_beacon_parse(const uint8_t netkey[16], const uint8_t *in,
    size_t inlen, struct mesh_private_beacon *out)
{
	uint8_t pbkey[16];
	uint8_t data[MESH_PRIVATE_BEACON_DATA_LEN];
	uint8_t flags;
	int rc = -1;

	if (netkey == NULL || in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));

	if (inlen != MESH_PRIVATE_BEACON_LEN)
		return (-1);
	if (in[0] != MESH_BEACON_TYPE_MESH_PRIVATE)
		return (-1);

	if (mesh_private_beacon_key(netkey, pbkey) != 0)
		goto out;
	if (mesh_aes_ccm_decrypt(pbkey, in + 1, NULL, 0, in + 14,
	    MESH_PRIVATE_BEACON_DATA_LEN, data, in + 19,
	    MESH_PRIVATE_BEACON_TAG_LEN) != 0)
		goto out;

	flags = data[0];
	/*
	 * Only bits 0 (Key Refresh) and 1 (IV Update) are defined.  Bits 2-7 are
	 * Reserved for Future Use: MshPRT Section 1.3.2 requires a received RFU
	 * bit set to 1 to be processed as if it were 0, so the reserved bits are
	 * ignored (masked off) rather than causing the beacon to be rejected.
	 */
	out->key_refresh = (uint8_t)(flags & MESH_BEACON_FLAG_KEY_REFRESH);
	out->iv_update = (uint8_t)((flags & MESH_BEACON_FLAG_IV_UPDATE) >> 1);
	out->iv_index = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
	    ((uint32_t)data[3] << 8) | (uint32_t)data[4];
	memcpy(out->random, in + 1, MESH_PRIVATE_BEACON_RANDOM_LEN);
	rc = 0;
out:
	explicit_bzero(pbkey, sizeof(pbkey));
	explicit_bzero(data, sizeof(data));
	if (rc != 0)
		memset(out, 0, sizeof(*out));
	return (rc);
}

/*
 * Unprovisioned Device beacon codec.  MshPRT_v1.1 Section 3.9.2.
 */
int
mesh_unprov_beacon_build(const struct mesh_unprov_beacon *in, uint8_t *out,
    size_t *outlen)
{
	size_t len;

	if (in == NULL || out == NULL || outlen == NULL ||
	    (in->oob & ~MESH_OOB_INFO_MASK) != 0)
		return (-1);

	out[0] = MESH_BEACON_TYPE_UNPROVISIONED;
	memcpy(out + 1, in->uuid, MESH_UUID_LEN);
	out[17] = (uint8_t)(in->oob >> 8);
	out[18] = (uint8_t)in->oob;
	len = MESH_UNPROV_BEACON_MIN_LEN;
	if (in->has_uri_hash) {
		memcpy(out + 19, in->uri_hash, 4);
		len += 4;
	}
	*outlen = len;
	return (0);
}

int
mesh_unprov_beacon_parse(const uint8_t *in, size_t inlen,
    struct mesh_unprov_beacon *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));

	if (inlen != MESH_UNPROV_BEACON_MIN_LEN &&
	    inlen != MESH_UNPROV_BEACON_MAX_LEN)
		return (-1);
	if (in[0] != MESH_BEACON_TYPE_UNPROVISIONED)
		return (-1);

	memcpy(out->uuid, in + 1, MESH_UUID_LEN);
	out->oob = (uint16_t)(((in[17] << 8) | in[18]) & MESH_OOB_INFO_MASK);
	if (inlen == MESH_UNPROV_BEACON_MAX_LEN) {
		memcpy(out->uri_hash, in + 19, 4);
		out->has_uri_hash = 1;
	}
	return (0);
}
