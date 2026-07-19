/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Structured advertising-data builder.  See adv_builder.h.  Assembles typed
 * fields into the [len][type][data] AD structures of an advertising or
 * scan-response payload (Core Spec Vol 3 Part C §11, CSS Part A §1), enforcing
 * per-field size limits and the payload budget.
 */

#include <errno.h>
#include <string.h>

#include "adv_builder.h"
#include "ble_util.h"

void
adv_ad_init(struct adv_ad *b, uint16_t cap)
{

	memset(b, 0, sizeof(*b));
	b->cap = (cap > ADV_EXT_BUDGET) ? ADV_EXT_BUDGET : cap;
}

int
adv_ad_append(struct adv_ad *b, uint8_t type, const uint8_t *val, uint8_t vlen)
{
	size_t need;

	/*
	 * One AD structure's length octet counts the type octet plus the
	 * value, so the value may be at most 254 octets (CSS Part A §1.1).
	 */
	if (vlen > 254) {
		errno = EINVAL;
		return (-1);
	}
	need = (size_t)vlen + 2;		/* len octet + type octet + value */
	if ((size_t)b->len + need > b->cap) {
		errno = ENOSPC;
		return (-1);
	}
	b->data[b->len++] = (uint8_t)(vlen + 1);
	b->data[b->len++] = type;
	if (vlen > 0)
		memcpy(&b->data[b->len], val, vlen);
	b->len += vlen;
	return (0);
}

int
adv_ad_add_flags(struct adv_ad *b, uint8_t flags)
{

	return (adv_ad_append(b, AD_TYPE_FLAGS, &flags, 1));
}

int
adv_ad_add_uuid16(struct adv_ad *b, bool complete, const uint16_t *uuids,
    size_t n)
{
	uint8_t val[254];
	size_t i;

	if (n == 0 || n > sizeof(val) / 2) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < n; i++)
		put_le16(&val[i * 2], uuids[i]);
	return (adv_ad_append(b, complete ? AD_TYPE_UUID16_COMPLETE :
	    AD_TYPE_UUID16_INCOMPLETE, val, (uint8_t)(n * 2)));
}

int
adv_ad_add_uuid128(struct adv_ad *b, bool complete, const uint8_t *uuids_le,
    size_t n)
{

	/* Each 128-bit UUID is 16 octets, little-endian (CSS Part A §1.1). */
	if (n == 0 || n * 16 > 254) {
		errno = EINVAL;
		return (-1);
	}
	return (adv_ad_append(b, complete ? AD_TYPE_UUID128_COMPLETE :
	    AD_TYPE_UUID128_INCOMPLETE, uuids_le, (uint8_t)(n * 16)));
}

int
adv_ad_add_name(struct adv_ad *b, bool complete, const char *name)
{
	size_t len;

	len = strlen(name);
	if (len == 0 || len > 254) {
		errno = EINVAL;
		return (-1);
	}
	return (adv_ad_append(b, complete ? AD_TYPE_NAME_COMPLETE :
	    AD_TYPE_NAME_SHORT, (const uint8_t *)name, (uint8_t)len));
}

int
adv_ad_add_tx_power(struct adv_ad *b, int8_t dbm)
{
	uint8_t v = (uint8_t)dbm;

	return (adv_ad_append(b, AD_TYPE_TX_POWER, &v, 1));
}

int
adv_ad_add_appearance(struct adv_ad *b, uint16_t appearance)
{
	uint8_t val[2];

	put_le16(val, appearance);
	return (adv_ad_append(b, AD_TYPE_APPEARANCE, val, 2));
}

int
adv_ad_add_manuf(struct adv_ad *b, uint16_t company, const uint8_t *data,
    size_t n)
{
	uint8_t val[254];

	/* Company Identifier Code (2 octets LE) then payload (CSS Part A §1.4). */
	if (n + 2 > sizeof(val)) {
		errno = EINVAL;
		return (-1);
	}
	put_le16(val, company);
	if (n > 0)
		memcpy(&val[2], data, n);
	return (adv_ad_append(b, AD_TYPE_MANUF_DATA, val, (uint8_t)(n + 2)));
}

int
adv_ad_add_service_data16(struct adv_ad *b, uint16_t uuid, const uint8_t *data,
    size_t n)
{
	uint8_t val[254];

	/* 16-bit Service UUID (2 octets LE) then service data (CSS Part A §1.11). */
	if (n + 2 > sizeof(val)) {
		errno = EINVAL;
		return (-1);
	}
	put_le16(val, uuid);
	if (n > 0)
		memcpy(&val[2], data, n);
	return (adv_ad_append(b, AD_TYPE_SERVICE_DATA16, val, (uint8_t)(n + 2)));
}
