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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "att.h"
#include "ble_util.h"
#include "gatt.h"

/*
 * Discover all primary services using Read By Group Type.
 * Core Spec Vol 3 Part G Section 4.4.1
 *
 * Iterates from handle 0x0001 to 0xFFFF until Attribute Not Found.
 */
int
gatt_discover_primary_services(struct att_conn *ac,
    struct gatt_service *svcs, int maxsvcs, int *nsvcs)
{
	uint8_t buf[ATT_MAX_MTU];
	size_t len;
	uint16_t start = 0x0001;
	int count = 0;
	int ret;

	while (start <= 0xFFFF && count < maxsvcs) {
		ret = att_read_by_group_type(ac, start, 0xFFFF,
		    GATT_UUID_PRIMARY_SERVICE, buf, sizeof(buf), &len);
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

		if (entry_len < 6)	/* minimum: 2+2+2 for 16-bit UUID */
			break;

		while (len >= entry_len && count < maxsvcs) {
			struct gatt_service *s = &svcs[count];

			s->start_handle = get_le16(p);
			s->end_handle = get_le16(p + 2);

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
			} else {
				break;
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

/*
 * Discover characteristics within a handle range using Read By Type.
 * Core Spec Vol 3 Part G Section 4.6.1
 */
int
gatt_discover_characteristics(struct att_conn *ac,
    uint16_t start, uint16_t end,
    struct gatt_char *chars, int maxchars, int *nchars)
{
	uint8_t buf[ATT_MAX_MTU];
	size_t len;
	int count = 0;
	int ret;
	uint16_t orig_start = start;

	while (start <= end && count < maxchars) {
		ret = att_read_by_type(ac, start, end,
		    GATT_UUID_CHARACTERISTIC, buf, sizeof(buf), &len);
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

		if (entry_len < 7)	/* minimum: 2+1+2+2 */
			break;

		while (len >= entry_len && count < maxchars) {
			struct gatt_char *c = &chars[count];

			c->decl_handle = get_le16(p);
			c->properties = p[2];
			c->value_handle = get_le16(p + 3);

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
			} else {
				break;
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
	uint8_t buf[ATT_MAX_MTU];
	size_t len;
	int count = 0;
	int ret;
	uint16_t orig_start = start;

	while (start <= end && count < maxdescs) {
		ret = att_find_info(ac, start, end, buf, sizeof(buf), &len);
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
			break;

		while (len >= entry_len && count < maxdescs) {
			struct gatt_desc *d = &descs[count];

			d->handle = get_le16(p);

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
