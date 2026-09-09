/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * GATT (Generic Attribute Profile) client.
 *
 * Service, characteristic, and descriptor discovery per
 * Core Spec Vol 3 Part G.  Built on top of the ATT layer.
 */

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "gatt.h"

/*
 * gatt:disc:step probe procedure codes.  Each GATT client discovery
 * procedure fires BLUED_PROBE_GATT_DISC_STEP once per ATT round-trip
 * (outer loop iteration) with its proc code, the handle range being
 * scanned, and the cumulative number of results found so far.
 */
#define	GATT_DISC_PROC_PRIMARY		1	/* discover all primaries */
#define	GATT_DISC_PROC_PRIMARY_UUID16	2	/* primary by 16-bit UUID */
#define	GATT_DISC_PROC_PRIMARY_UUID128	3	/* primary by 128-bit UUID */
#define	GATT_DISC_PROC_SECONDARY	4	/* discover secondaries */
#define	GATT_DISC_PROC_INCLUDES		5	/* discover includes */
#define	GATT_DISC_PROC_CHARS		6	/* discover characteristics */
#define	GATT_DISC_PROC_DESCS		7	/* discover descriptors */

/*
 * Configured Database Hash wire byte order (GATT_DB_HASH_ORDER_*).
 *
 * Written once at startup and again on each SIGHUP config reload by
 * gatt_set_db_hash_byte_order(); read from every thread that publishes or
 * parses a Database Hash characteristic value.  Atomic for the same reason
 * hci_conn.c's l2cap_own_address_type is: a plain scalar written by the
 * reload path and read by the connection threads would be a data race.
 * Defaults to the BlueZ order so a daemon whose operator never sets the knob
 * keeps the historical on-the-wire behaviour, and so unit tests that link
 * gatt.c without config.c see that behaviour too.
 */
static _Atomic uint8_t gatt_db_hash_order = GATT_DB_HASH_ORDER_BLUEZ;

void
gatt_set_db_hash_byte_order(uint8_t order)
{

	atomic_store(&gatt_db_hash_order,
	    order == GATT_DB_HASH_ORDER_REVERSED ?
	    GATT_DB_HASH_ORDER_REVERSED : GATT_DB_HASH_ORDER_BLUEZ);
}

uint8_t
gatt_get_db_hash_byte_order(void)
{

	return (atomic_load(&gatt_db_hash_order));
}

/*
 * Convert a Database Hash between computation order (raw AES-CMAC output,
 * most significant octet first) and the configured wire order.  The mapping
 * is an involution -- identity for the BlueZ order, a full 16-octet reversal
 * for the Zephyr/PTS order -- so the two directions share one implementation
 * and differ only in the name that documents the call site.  in and out may
 * be the same buffer.
 */
static void
gatt_db_hash_reorder(const uint8_t in[GATT_DB_HASH_LEN],
    uint8_t out[GATT_DB_HASH_LEN])
{
	uint8_t tmp[GATT_DB_HASH_LEN];
	int i;

	if (atomic_load(&gatt_db_hash_order) != GATT_DB_HASH_ORDER_REVERSED) {
		memmove(out, in, GATT_DB_HASH_LEN);
		return;
	}
	for (i = 0; i < GATT_DB_HASH_LEN; i++)
		tmp[i] = in[GATT_DB_HASH_LEN - 1 - i];
	memcpy(out, tmp, GATT_DB_HASH_LEN);
}

/* Computation order (raw CMAC, MSB first) -> characteristic value octets. */
void
gatt_db_hash_to_wire(const uint8_t hash[GATT_DB_HASH_LEN],
    uint8_t wire[GATT_DB_HASH_LEN])
{

	gatt_db_hash_reorder(hash, wire);
}

/* Characteristic value octets -> computation order (raw CMAC, MSB first). */
void
gatt_db_hash_from_wire(const uint8_t wire[GATT_DB_HASH_LEN],
    uint8_t hash[GATT_DB_HASH_LEN])
{

	gatt_db_hash_reorder(wire, hash);
}

/*
 * Publish the Database Hash: recompute it over db and write it into the
 * 0x2B2A characteristic value in the configured WIRE byte order.
 *
 * attdb_compute_db_hash() yields the raw AES-CMAC output (computation order,
 * most significant octet first).  Only the characteristic value -- the octets
 * a peer actually reads -- is reordered; nothing else in the daemon stores the
 * reordered form.  Wire sites 1-3 of 4 all funnel through here so that no
 * publish path can be left with a hardcoded order.
 */
void
gatt_db_publish_hash(struct att_db *db)
{
	uint8_t db_hash[GATT_DB_HASH_LEN], wire[GATT_DB_HASH_LEN];
	int i;

	if (db == NULL)
		return;

	attdb_compute_db_hash(db, db_hash);
	gatt_db_hash_to_wire(db_hash, wire);
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == GATT_UUID_DATABASE_HASH &&
		    db->attrs[i].value_len == GATT_DB_HASH_LEN) {
			memcpy(db->attrs[i].value, wire, GATT_DB_HASH_LEN);
			break;
		}
	}
}

static int
gatt_bad_response(void)
{

	errno = EPROTO;
	return (-1);
}

/* Attribute Not Found is the specified successful terminator for discovery. */
static bool
gatt_discovery_complete(int att_status)
{

	return (att_status == ATT_ERR_ATTR_NOT_FOUND);
}

/*
 * Read the Database Hash characteristic (UUID 0x2B2A) from the GATT
 * Service (UUID 0x1801) on the remote device.
 * Core Spec Vol 3 Part G Section 7.3.1
 *
 * Uses Read By Type over the full handle range.  The response contains
 * [attr_data_len, [handle(2) + hash(16)]*].  We extract the first
 * 16-byte hash value.
 *
 * The returned hash is in computation order (raw AES-CMAC, most significant
 * octet first) regardless of the configured wire order, so it can be compared
 * byte-for-byte with a stored bond hash; see gatt.h.
 *
 * Returns 0 on success with hash filled in, -1 on failure.
 */
int
gatt_read_database_hash(struct att_conn *ac, uint8_t hash[16])
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	int ret;

	if (ac == NULL || hash == NULL) {
		errno = EINVAL;
		return (-1);
	}

	ret = att_read_by_type(ac, 0x0001, 0xFFFF,
	    GATT_UUID_DATABASE_HASH, buf, sizeof(buf), &len);
	if (ret != 0)
		return (-1);

	/*
	 * Response format: [attr_data_len(1), [handle(2) + value]*]
	 * For Database Hash, attr_data_len should be 18 (2 + 16).
	 * We need at least 1 + 18 = 19 bytes.
	 */
	if (len != 19)
		return (-1);

	uint8_t entry_len = buf[0];
	if (entry_len != 18 || get_le16(buf + 1) == 0)
		return (-1);

	/*
	 * Extract the 16-byte hash value (skip handle bytes), converting the
	 * peer's characteristic value from the configured wire order into the
	 * computation order every internal consumer (bond records, cache
	 * comparisons) uses.  Wire site 4 of 4; see gatt.h.
	 */
	gatt_db_hash_from_wire(buf + 3, hash);

	LOG_GATT(1, "read database hash from remote");

	return (0);
}

/*
 * Opt into Robust Caching (and any other Client Supported Features bits the
 * caller names) on the peer.
 *
 * Core Spec Vol 3 Part G §2.5.2.1 line 72351 conditions the whole
 * change-awareness mechanism on this characteristic: only a client that has
 * set the Robust Caching bit is ever sent an ATT_ERROR_RSP with Database Out
 * Of Sync (0x12), and only such a client gets the server-side guarantee that
 * notifications are withheld while it is change-unaware.  A client that caches
 * handles across connections without writing this bit — which is what blued
 * did — is caching on the strength of a hash it only sometimes reads.
 *
 * The characteristic is located with Read Using Characteristic UUID over
 * 0x0001-0xFFFF, so this works with no discovery state and on a cache-hit
 * reconnect.  §7.2 line 75100 forbids clearing a bit that is already set, so
 * the current value is read first and written back only if the OR changes it;
 * a bonded client's value is persistent across connections (§7.2 lines
 * 75093-75094), which is exactly the case that would otherwise get a Value Not
 * Allowed (0x13) from a zero-seeded rewrite.
 *
 * Returns 0 if the peer now has the requested bits set (including "already
 * set"), ENOENT if it exposes no Client Supported Features characteristic, and
 * otherwise a positive ATT error code or -1.
 */
int
gatt_set_client_supported_features(struct att_conn *ac, uint8_t bits)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	uint16_t handle;
	uint8_t entry_len, current, desired;
	size_t len = 0;
	int ret;

	if (ac == NULL) {
		errno = EINVAL;
		return (-1);
	}

	ret = att_read_by_type(ac, 0x0001, 0xFFFF, GATT_UUID_CLIENT_SUPP_FEAT,
	    buf, sizeof(buf), &len);
	if (ret != 0)
		return (ret);

	/*
	 * [attr_data_len(1), handle(2), value...] -- §3.4.4.1.  att_read_by_type
	 * maps Attribute Not Found to success with a zero length, so a short
	 * response is the "peer has no such characteristic" case.
	 */
	if (len < 4)
		return (ENOENT);
	entry_len = buf[0];
	if (entry_len < 3 || (size_t)entry_len > len - 1)
		return (ENOENT);
	handle = get_le16(buf + 1);
	if (handle == 0)
		return (ENOENT);
	current = buf[3];

	desired = (uint8_t)(current | bits);
	if (desired == current) {
		LOG_GATT(1, "client supported features already %#02x", current);
		return (0);
	}

	/*
	 * The characteristic value is exactly one octet in this profile's use
	 * (Core §3.3.3.3 sizing is enforced server-side); write the single
	 * octet back with a Write Request so a rejection is visible.
	 */
	ret = att_write_req(ac, handle, &desired, sizeof(desired));
	if (ret != 0) {
		LOG_GATT(1, "client supported features write failed (%d)", ret);
		return (ret);
	}
	LOG_GATT(1, "client supported features %#02x -> %#02x at handle %04x",
	    current, desired, handle);
	return (0);
}

/*
 * Find the Client Characteristic Configuration descriptor belonging to the
 * characteristic whose value handle is `value_handle'.
 *
 * The search runs from value_handle + 1 and stops at the next characteristic
 * declaration (0x2803), which by Core Vol 3 Part G §3.3 ends the current
 * characteristic definition -- so a CCCD belonging to a LATER characteristic
 * can never be returned.
 *
 * Returns 0 with *cccd_handle set, ENOENT if there is none, or an error.
 */
int
gatt_find_cccd(struct att_conn *ac, uint16_t value_handle,
    uint16_t search_end, uint16_t *cccd_handle)
{
	struct gatt_desc descs[8];
	int ndescs = 0, i, ret;

	if (ac == NULL || cccd_handle == NULL || value_handle == 0 ||
	    value_handle == 0xFFFF) {
		errno = EINVAL;
		return (-1);
	}
	*cccd_handle = 0;
	if (search_end <= value_handle)
		return (ENOENT);

	ret = gatt_discover_descriptors(ac, (uint16_t)(value_handle + 1),
	    search_end, descs, (int)(sizeof(descs) / sizeof(descs[0])),
	    &ndescs);
	if (ret != 0)
		return (ret);

	for (i = 0; i < ndescs; i++) {
		if (descs[i].uuid16 == GATT_UUID_CHAR_DECL)
			break;
		if (descs[i].uuid16 == GATT_UUID_CCCD_DESC) {
			*cccd_handle = descs[i].handle;
			return (0);
		}
	}
	return (ENOENT);
}

/*
 * Write a Client Characteristic Configuration descriptor.
 * Core Spec Vol 3 Part G §3.3.3.3: two octets, little-endian.
 */
int
gatt_write_cccd(struct att_conn *ac, uint16_t cccd_handle, uint16_t value)
{
	uint8_t val[2];

	if (ac == NULL || cccd_handle == 0) {
		errno = EINVAL;
		return (-1);
	}
	val[0] = (uint8_t)value;
	val[1] = (uint8_t)(value >> 8);
	return (att_write_req(ac, cccd_handle, val, sizeof(val)));
}

/*
 * Discover all primary services using Read By Group Type.
 * Core Spec Vol 3 Part G Section 4.4.1
 *
 * Iterates from handle 0x0001 to 0xFFFF until Attribute Not Found.
 */
int
gatt_discover_primary_services_range(struct att_conn *ac,
    uint16_t start_handle, uint16_t end_handle,
    struct gatt_service *svcs, int maxsvcs, int *nsvcs)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	uint16_t start = start_handle;
	int count = 0;
	int ret;

	if (nsvcs == NULL || ac == NULL || start_handle == 0 ||
	    start_handle > end_handle || maxsvcs < 0 ||
	    (maxsvcs > 0 && svcs == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*nsvcs = 0;

	while (start <= end_handle && count < maxsvcs) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_PRIMARY, start,
		    end_handle, count);
		ret = att_read_by_group_type(ac, start, end_handle,
		    GATT_UUID_PRIMARY_SERVICE, buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		/*
		 * Response format: [attr_data_len, [data]*]
		 * Each entry: [start_handle(2), end_handle(2), uuid(2 or 16)]
		 */
		uint8_t entry_len = buf[0];
		const uint8_t *p = buf + 1;
		len -= 1;

		if (entry_len != 6 && entry_len != 8 && entry_len != 20)
			return (gatt_bad_response());
		if (len % entry_len != 0)
			return (gatt_bad_response());

		while (len >= entry_len && count < maxsvcs) {
			struct gatt_service *s = &svcs[count];
			uint16_t service_start, service_end;

			service_start = get_le16(p);
			service_end = get_le16(p + 2);
			if (service_start < start || service_start == 0 ||
			    service_end < service_start ||
			    (count > 0 &&
			    service_start <= svcs[count - 1].end_handle))
				return (gatt_bad_response());
			s->start_handle = service_start;
			s->end_handle = service_end;

			if (entry_len == 6) {
				/* 16-bit UUID */
				s->uuid16 = get_le16(p + 4);
				memset(s->uuid128, 0, 16);
			} else if (entry_len == 8) {
				/* 32-bit UUID — collapse to 16-bit if possible */
				uint32_t u32 = (uint32_t)p[4] |
				    ((uint32_t)p[5] << 8) |
				    ((uint32_t)p[6] << 16) |
				    ((uint32_t)p[7] << 24);
				if ((u32 & 0xFFFF0000) == 0) {
					s->uuid16 = (uint16_t)u32;
					memset(s->uuid128, 0, 16);
				} else {
					s->uuid16 = 0;
					memcpy(s->uuid128,
					    bt_base_uuid_le, 12);
					memcpy(s->uuid128 + 12, p + 4, 4);
				}
			} else if (entry_len == 20) {
				/* 128-bit UUID */
				s->uuid16 = 0;
				memcpy(s->uuid128, p + 4, 16);
			}

			count++;
			p += entry_len;
			len -= entry_len;
		}

		/* Next iteration starts after the last service's end handle */
		if (count == 0)
			break;
		{
			uint16_t new_start = svcs[count - 1].end_handle + 1;
			if (new_start <= start || new_start == 0)
				break; /* non-advancing or wrapped */
			start = new_start;
		}
	}

	*nsvcs = count;
	LOG_GATT(1, "discovered %d primary services", count);
	return (0);
}

int
gatt_discover_primary_services(struct att_conn *ac,
    struct gatt_service *svcs, int maxsvcs, int *nsvcs)
{

	return (gatt_discover_primary_services_range(ac, 0x0001, 0xffff,
	    svcs, maxsvcs, nsvcs));
}

/*
 * Discover a primary service by 16-bit UUID using Find By Type Value.
 * Core Spec Vol 3 Part G Section 4.4.2
 *
 * The response contains handle-range pairs for each matching service.
 */
int
gatt_discover_primary_service_by_uuid(struct att_conn *ac, uint16_t uuid16,
    struct gatt_service *services, int max_services, int *count)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	uint8_t val[2];
	size_t len;
	uint16_t start = 0x0001;
	int n = 0;
	int ret;

	if (count == NULL || ac == NULL || max_services < 0 ||
	    (max_services > 0 && services == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;

	put_le16(val, uuid16);

	while (start <= 0xFFFF && n < max_services) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_PRIMARY_UUID16, start,
		    0xFFFF, n);
		ret = att_find_by_type_value(ac, start, 0xFFFF,
		    GATT_UUID_PRIMARY_SERVICE, val, sizeof(val),
		    buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		/*
		 * Response format: [found_handle(2), group_end_handle(2)]*
		 * Each entry is 4 bytes: start handle + end handle.
		 */
		const uint8_t *p = buf;

		if (len % 4 != 0)
			return (gatt_bad_response());
		while (len >= 4 && n < max_services) {
			struct gatt_service *s = &services[n];
			uint16_t service_start, service_end;

			service_start = get_le16(p);
			service_end = get_le16(p + 2);
			if (service_start < start || service_start == 0 ||
			    service_end < service_start ||
			    (n > 0 && service_start <= services[n - 1].end_handle))
				return (gatt_bad_response());
			s->start_handle = service_start;
			s->end_handle = service_end;
			s->uuid16 = uuid16;
			memset(s->uuid128, 0, 16);

			n++;
			p += 4;
			len -= 4;
		}

		if (n == 0)
			break;
		{
			uint16_t new_start = services[n - 1].end_handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*count = n;
	LOG_GATT(1, "discovered %d primary services with uuid 0x%04x", n,
	    uuid16);
	return (0);
}

/*
 * Discover a primary service by 128-bit UUID using Find By Type Value.
 * Core Spec Vol 3 Part G Section 4.4.2
 */
int
gatt_discover_primary_service_by_uuid128(struct att_conn *ac,
    const uint8_t uuid128[16],
    struct gatt_service *services, int max_services, int *count)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	uint16_t start = 0x0001;
	int n = 0;
	int ret;

	if (count == NULL || ac == NULL || uuid128 == NULL ||
	    max_services < 0 || (max_services > 0 && services == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;

	/* UUID value is already in LE wire format (128-bit, 16 bytes) */
	while (start <= 0xFFFF && n < max_services) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_PRIMARY_UUID128, start,
		    0xFFFF, n);
		ret = att_find_by_type_value(ac, start, 0xFFFF,
		    GATT_UUID_PRIMARY_SERVICE, uuid128, 16,
		    buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		const uint8_t *p = buf;

		if (len % 4 != 0)
			return (gatt_bad_response());
		while (len >= 4 && n < max_services) {
			struct gatt_service *s = &services[n];
			uint16_t service_start, service_end;

			service_start = get_le16(p);
			service_end = get_le16(p + 2);
			if (service_start < start || service_start == 0 ||
			    service_end < service_start ||
			    (n > 0 && service_start <= services[n - 1].end_handle))
				return (gatt_bad_response());
			s->start_handle = service_start;
			s->end_handle = service_end;
			s->uuid16 = 0;
			memcpy(s->uuid128, uuid128, 16);

			n++;
			p += 4;
			len -= 4;
		}

		if (n == 0)
			break;
		{
			uint16_t new_start = services[n - 1].end_handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*count = n;
	LOG_GATT(1, "discovered %d primary services by uuid128", n);
	return (0);
}

/*
 * Discover all secondary services using Read By Group Type.
 *
 * NOTE: This is a non-standard extension.  Core Spec Vol 3 Part G
 * Section 2.6.2 states "There is no procedure for discovering
 * secondary services."  Per the spec, secondary services are only
 * found through Include declarations (0x2802).  This function is
 * provided for diagnostic use only.
 */
int
gatt_discover_secondary_services(struct att_conn *ac,
    struct gatt_service *services, int max_services, int *count)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	uint16_t start = 0x0001;
	int n = 0;
	int ret;

	if (count == NULL || ac == NULL || max_services < 0 ||
	    (max_services > 0 && services == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;

	while (start <= 0xFFFF && n < max_services) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_SECONDARY, start,
		    0xFFFF, n);
		ret = att_read_by_group_type(ac, start, 0xFFFF,
		    GATT_UUID_SECONDARY_SERVICE, buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		uint8_t entry_len = buf[0];
		const uint8_t *p = buf + 1;
		len -= 1;

		if (entry_len != 6 && entry_len != 8 && entry_len != 20)
			return (gatt_bad_response());
		if (len % entry_len != 0)
			return (gatt_bad_response());

		while (len >= entry_len && n < max_services) {
			struct gatt_service *s = &services[n];
			uint16_t service_start, service_end;

			service_start = get_le16(p);
			service_end = get_le16(p + 2);
			if (service_start < start || service_start == 0 ||
			    service_end < service_start ||
			    (n > 0 && service_start <= services[n - 1].end_handle))
				return (gatt_bad_response());
			s->start_handle = service_start;
			s->end_handle = service_end;

			if (entry_len == 6) {
				s->uuid16 = get_le16(p + 4);
				memset(s->uuid128, 0, 16);
			} else if (entry_len == 8) {
				uint32_t u32 = (uint32_t)p[4] |
				    ((uint32_t)p[5] << 8) |
				    ((uint32_t)p[6] << 16) |
				    ((uint32_t)p[7] << 24);
				if ((u32 & 0xFFFF0000) == 0) {
					s->uuid16 = (uint16_t)u32;
					memset(s->uuid128, 0, 16);
				} else {
					s->uuid16 = 0;
					memcpy(s->uuid128,
					    bt_base_uuid_le, 12);
					memcpy(s->uuid128 + 12, p + 4, 4);
				}
			} else if (entry_len == 20) {
				s->uuid16 = 0;
				memcpy(s->uuid128, p + 4, 16);
			}

			n++;
			p += entry_len;
			len -= entry_len;
		}

		if (n == 0)
			break;
		{
			uint16_t new_start = services[n - 1].end_handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*count = n;
	LOG_GATT(1, "discovered %d secondary services", n);
	return (0);
}

/*
 * Discover included services within a handle range using Read By Type.
 * Core Spec Vol 3 Part G Section 4.5.1
 *
 * Each include declaration (UUID 0x2802) contains:
 *   - Include Attribute Handle (from the response framing)
 *   - Included Service Attribute Handle (start handle)
 *   - End Group Handle
 *   - Service UUID (only present for 16-bit UUIDs)
 *
 * When the included service uses a 128-bit UUID, the UUID is not
 * present in the include declaration.  A separate ATT Read Request
 * on the included service's start handle is needed to retrieve it.
 */
int
gatt_discover_includes(struct att_conn *ac,
    uint16_t start_handle, uint16_t end_handle,
    struct gatt_include *includes, int max_includes, int *count)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	uint16_t start = start_handle;
	int n = 0;
	int ret;

	if (count == NULL || ac == NULL || start_handle == 0 ||
	    start_handle > end_handle || max_includes < 0 ||
	    (max_includes > 0 && includes == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*count = 0;

	while (start <= end_handle && n < max_includes) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_INCLUDES, start,
		    end_handle, n);
		ret = att_read_by_type(ac, start, end_handle,
		    GATT_UUID_INCLUDE, buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		/*
		 * Response format: [attr_data_len, [data]*]
		 * entry_len == 8: handle(2) + start(2) + end(2) + uuid16(2)
		 * entry_len == 6: handle(2) + start(2) + end(2), no UUID
		 */
		uint8_t entry_len = buf[0];
		const uint8_t *p = buf + 1;
		len -= 1;

		if (entry_len != 6 && entry_len != 8)
			return (gatt_bad_response());
		if (len % entry_len != 0)
			return (gatt_bad_response());

		while (len >= entry_len && n < max_includes) {
			struct gatt_include *inc = &includes[n];
			uint16_t handle, included_start, included_end;

			handle = get_le16(p);
			included_start = get_le16(p + 2);
			included_end = get_le16(p + 4);
			if (handle < start || handle > end_handle ||
			    included_start == 0 || included_end < included_start ||
			    (n > 0 && handle <= includes[n - 1].handle))
				return (gatt_bad_response());
			inc->handle = handle;
			inc->start_handle = included_start;
			inc->end_handle = included_end;

			if (entry_len == 8) {
				/* 16-bit UUID is present */
				inc->uuid16 = get_le16(p + 6);
				memset(inc->uuid128, 0, 16);
				inc->has_uuid = true;
			} else if (entry_len == 6) {
				/*
				 * 128-bit UUID: not in the response.
				 * Read the included service's start handle
				 * to obtain the 128-bit service UUID.
				 */
				uint8_t rdbuf[ATT_PDU_BUF_SIZE];
				size_t rdlen;

				inc->uuid16 = 0;
				memset(inc->uuid128, 0, 16);
				inc->has_uuid = false;

				ret = att_read(ac, inc->start_handle,
				    rdbuf, sizeof(rdbuf), &rdlen);
				if (ret == 0 && rdlen == 16) {
					memcpy(inc->uuid128, rdbuf, 16);
					inc->has_uuid = true;
				}
			}

			n++;
			p += entry_len;
			len -= entry_len;
		}

		if (n == 0)
			break;
		{
			uint16_t new_start = includes[n - 1].handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*count = n;
	LOG_GATT(1, "discovered %d includes in %04x-%04x", n,
	    start_handle, end_handle);
	return (0);
}

/*
 * Discover characteristics within a handle range using Read By Type.
 * Core Spec Vol 3 Part G Section 4.6.1
 */
int
gatt_discover_characteristics(struct att_conn *ac,
    uint16_t start, uint16_t end,
    struct gatt_char *chars, int maxchars, int *nchars)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	int count = 0;
	int ret;
	uint16_t orig_start = start;

	if (nchars == NULL || ac == NULL || start == 0 || start > end ||
	    maxchars < 0 || (maxchars > 0 && chars == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*nchars = 0;

	while (start <= end && count < maxchars) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_CHARS, start, end,
		    count);
		ret = att_read_by_type(ac, start, end,
		    GATT_UUID_CHARACTERISTIC, buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		/*
		 * Response format: [attr_data_len, [data]*]
		 * Each entry: [decl_handle(2), properties(1),
		 *              value_handle(2), uuid(2 or 16)]
		 */
		uint8_t entry_len = buf[0];
		const uint8_t *p = buf + 1;
		len -= 1;

		if (entry_len != 7 && entry_len != 9 && entry_len != 21)
			return (gatt_bad_response());
		if (len % entry_len != 0)
			return (gatt_bad_response());

		while (len >= entry_len && count < maxchars) {
			struct gatt_char *c = &chars[count];
			uint16_t decl_handle, value_handle;

			decl_handle = get_le16(p);
			value_handle = get_le16(p + 3);
			if (decl_handle < start || decl_handle > end ||
			    value_handle <= decl_handle || value_handle > end ||
			    (count > 0 &&
			    decl_handle <= chars[count - 1].decl_handle))
				return (gatt_bad_response());
			c->decl_handle = decl_handle;
			c->properties = p[2];
			c->value_handle = value_handle;

			if (entry_len == 7) {
				/* 16-bit UUID */
				c->uuid16 = get_le16(p + 5);
				memset(c->uuid128, 0, 16);
			} else if (entry_len == 9) {
				/* 32-bit UUID — collapse to 16-bit if possible */
				uint32_t u32 = (uint32_t)p[5] |
				    ((uint32_t)p[6] << 8) |
				    ((uint32_t)p[7] << 16) |
				    ((uint32_t)p[8] << 24);
				if ((u32 & 0xFFFF0000) == 0) {
					c->uuid16 = (uint16_t)u32;
					memset(c->uuid128, 0, 16);
				} else {
					c->uuid16 = 0;
					memcpy(c->uuid128,
					    bt_base_uuid_le, 12);
					memcpy(c->uuid128 + 12, p + 5, 4);
				}
			} else if (entry_len == 21) {
				/* 128-bit UUID */
				c->uuid16 = 0;
				memcpy(c->uuid128, p + 5, 16);
			}

			count++;
			p += entry_len;
			len -= entry_len;
		}

		if (count == 0)
			break;
		{
			uint16_t new_start = chars[count - 1].decl_handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*nchars = count;
	LOG_GATT(1, "discovered %d characteristics in %04x-%04x", count,
	    orig_start, end);
	return (0);
}

/*
 * Discover descriptors within a handle range using Find Information.
 * Core Spec Vol 3 Part G Section 4.7.1
 */
int
gatt_discover_descriptors(struct att_conn *ac,
    uint16_t start, uint16_t end,
    struct gatt_desc *descs, int maxdescs, int *ndescs)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t len;
	int count = 0;
	int ret;
	uint16_t orig_start = start;

	if (ndescs == NULL || ac == NULL || start == 0 || start > end ||
	    maxdescs < 0 || (maxdescs > 0 && descs == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	*ndescs = 0;

	while (start <= end && count < maxdescs) {
		BLUED_PROBE_GATT_DISC_STEP(GATT_DISC_PROC_DESCS, start, end,
		    count);
		ret = att_find_info(ac, start, end, buf, sizeof(buf), &len);
		if (gatt_discovery_complete(ret))
			break;
		if (ret != 0)
			return (ret);
		if (len == 0)
			break;

		/*
		 * Response format: [format, [data]*]
		 * format 1: handle(2) + uuid16(2) = 4 bytes per entry
		 * format 2: handle(2) + uuid128(16) = 18 bytes per entry
		 */
		uint8_t format = buf[0];
		const uint8_t *p = buf + 1;
		len -= 1;
		uint8_t entry_len;

		if (format == 1)
			entry_len = 4;
		else if (format == 2)
			entry_len = 18;
		else
			return (gatt_bad_response());
		if (len % entry_len != 0)
			return (gatt_bad_response());

		while (len >= entry_len && count < maxdescs) {
			struct gatt_desc *d = &descs[count];
			uint16_t handle;

			handle = get_le16(p);
			if (handle < start || handle > end ||
			    (count > 0 && handle <= descs[count - 1].handle))
				return (gatt_bad_response());
			d->handle = handle;

			if (format == 1) {
				d->uuid16 = get_le16(p + 2);
				memset(d->uuid128, 0, 16);
			} else {
				d->uuid16 = 0;
				memcpy(d->uuid128, p + 2, 16);
			}

			count++;
			p += entry_len;
			len -= entry_len;
		}

		if (count == 0)
			break;
		{
			uint16_t new_start = descs[count - 1].handle + 1;
			if (new_start <= start || new_start == 0)
				break;
			start = new_start;
		}
	}

	*ndescs = count;
	LOG_GATT(1, "discovered %d descriptors in %04x-%04x", count,
	    orig_start, end);
	return (0);
}
