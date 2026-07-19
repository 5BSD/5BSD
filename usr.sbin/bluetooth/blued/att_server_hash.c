/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server database hash computation — GATT Robust Caching support.
 * Core Spec Vol 3 Part G Section 7.3.1.
 *
 * Split from att_server.c for readability.
 */

#include <sys/types.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"

/*
 * Compute the GATT Database Hash.
 * Core Spec Vol 3 Part G Section 7.3.1
 *
 * The hash covers exactly 10 attribute types:
 *   0x2800, 0x2801, 0x2802, 0x2803, 0x2900 (with value)
 *   0x2901, 0x2902, 0x2903, 0x2904, 0x2905 (handle+type only)
 *
 * The hash is AES-CMAC with an all-zero 128-bit key.
 */
void
attdb_compute_db_hash(struct att_db *db, uint8_t hash[16])
{
	EVP_MAC *cmac_type;
	EVP_MAC_CTX *ctx;
	OSSL_PARAM params[2];
	size_t outlen;
	uint8_t zero_key[16];
	static char cipher_name[] = "AES-128-CBC";

	memset(zero_key, 0, sizeof(zero_key));

	cmac_type = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (cmac_type == NULL) {
		warnx("attdb_compute_db_hash: EVP_MAC_fetch failed");
		memset(hash, 0, 16);
		return;
	}
	ctx = EVP_MAC_CTX_new(cmac_type);
	if (ctx == NULL) {
		warnx("attdb_compute_db_hash: EVP_MAC_CTX_new failed");
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}
	params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	if (!EVP_MAC_init(ctx, zero_key, 16, params)) {
		warnx("attdb_compute_db_hash: EVP_MAC_init failed");
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}

	for (int i = 0; i < db->count; i++) {
		struct att_attr *a = &db->attrs[i];
		uint8_t handle_le[2];
		uint8_t uuid16_le[2];
		int include_value;
		const uint8_t *uuid_bytes;
		size_t uuid_len;

		/* Skip characteristic values (not included in hash) */
		if (a->is_char_value)
			continue;

		if (a->uuid16 != 0) {
			switch (a->uuid16) {
			case 0x2800: /* Primary Service */
			case 0x2801: /* Secondary Service */
			case 0x2802: /* Include */
			case 0x2803: /* Characteristic Declaration */
			case 0x2900: /* Char Extended Properties */
				include_value = 1;
				break;
			case 0x2901: /* Char User Description */
			case 0x2902: /* CCCD */
			case 0x2903: /* SCCD */
			case 0x2904: /* Char Presentation Format */
			case 0x2905: /* Char Aggregate Format */
				include_value = 0;
				break;
			default:
				continue;
			}
			uuid16_le[0] = a->uuid16 & 0xFF;
			uuid16_le[1] = (a->uuid16 >> 8) & 0xFF;
			uuid_bytes = uuid16_le;
			uuid_len = 2;
		} else {
			/*
			 * 128-bit UUID: check if it's a Bluetooth Base UUID
			 * encoding of one of the 10 hashable types.
			 * The 16-bit short form occupies bytes [12..13]
			 * in little-endian wire order; bytes [0..11] and
			 * [14..15] must match the Bluetooth Base UUID.
			 */
			uint16_t u16;

			if (memcmp(a->uuid128, bt_base_uuid_le, 12) != 0 ||
			    a->uuid128[14] != 0x00 || a->uuid128[15] != 0x00)
				continue;
			u16 = get_le16(a->uuid128 + 12);
			switch (u16) {
			case 0x2800: case 0x2801: case 0x2802:
			case 0x2803: case 0x2900:
				include_value = 1;
				break;
			case 0x2901: case 0x2902: case 0x2903:
			case 0x2904: case 0x2905:
				include_value = 0;
				break;
			default:
				continue;
			}
			uuid_bytes = a->uuid128;
			uuid_len = 16;
		}

		handle_le[0] = a->handle & 0xFF;
		handle_le[1] = (a->handle >> 8) & 0xFF;

		if (!EVP_MAC_update(ctx, handle_le, 2) ||
		    !EVP_MAC_update(ctx, uuid_bytes, uuid_len) ||
		    (include_value && a->value != NULL &&
		    !EVP_MAC_update(ctx, a->value, a->value_len))) {
			warnx("attdb_compute_db_hash: EVP_MAC_update failed");
			EVP_MAC_CTX_free(ctx);
			EVP_MAC_free(cmac_type);
			memset(hash, 0, 16);
			return;
		}
	}

	outlen = 16;
	if (!EVP_MAC_final(ctx, hash, &outlen, 16)) {
		warnx("attdb_compute_db_hash: EVP_MAC_final failed");
		EVP_MAC_CTX_free(ctx);
		EVP_MAC_free(cmac_type);
		memset(hash, 0, 16);
		return;
	}
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(cmac_type);

	/* Robust Caching: DB Hash recomputed (emit length only, never the hash). */
	BLUED_PROBE_ATT_CACHE_HASH((int)outlen);

	LOG_ATT(2, "database hash: %02x%02x%02x%02x%02x%02x%02x%02x"
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
	    hash[0], hash[1], hash[2], hash[3],
	    hash[4], hash[5], hash[6], hash[7],
	    hash[8], hash[9], hash[10], hash[11],
	    hash[12], hash[13], hash[14], hash[15]);
}
