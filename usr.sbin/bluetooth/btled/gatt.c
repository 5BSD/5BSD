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
				s->uuid16 = get_le16(p + 4);
				memset(s->uuid128, 0, 16);
			} else if (entry_len == 20) {
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
		start = svcs[count - 1].end_handle + 1;
		if (start == 0)	/* wrapped */
			break;
	}

	*nsvcs = count;
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
				c->uuid16 = get_le16(p + 5);
				memset(c->uuid128, 0, 16);
			} else if (entry_len == 21) {
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
		start = chars[count - 1].decl_handle + 1;
		if (start == 0)
			break;
	}

	*nchars = count;
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
		start = descs[count - 1].handle + 1;
		if (start == 0)
			break;
	}

	*ndescs = count;
	return (0);
}

/*
 * High-level: discover a service by UUID16, including all its
 * characteristics and their descriptors.
 */
int
gatt_discover_service(struct att_conn *ac, uint16_t uuid16,
    struct gatt_discovery *disc)
{
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int nsvcs, i, ret;

	memset(disc, 0, sizeof(*disc));

	/* Find the service */
	ret = gatt_discover_primary_services(ac, svcs, GATT_MAX_SERVICES,
	    &nsvcs);
	if (ret != 0)
		return (ret);

	for (i = 0; i < nsvcs; i++) {
		if (svcs[i].uuid16 == uuid16)
			break;
	}
	if (i == nsvcs)
		return (ENOENT);

	disc->service = svcs[i];

	/* Discover characteristics */
	ret = gatt_discover_characteristics(ac, disc->service.start_handle,
	    disc->service.end_handle, disc->chars, GATT_MAX_CHARS,
	    &disc->nchars);
	if (ret != 0)
		return (ret);

	/* Discover descriptors for each characteristic */
	disc->ndescs = 0;
	for (i = 0; i < disc->nchars; i++) {
		uint16_t desc_start = disc->chars[i].value_handle + 1;
		uint16_t desc_end;

		if (i + 1 < disc->nchars)
			desc_end = disc->chars[i + 1].decl_handle - 1;
		else
			desc_end = disc->service.end_handle;

		if (desc_start > desc_end)
			continue;

		int ndesc;
		ret = gatt_discover_descriptors(ac, desc_start, desc_end,
		    disc->descs + disc->ndescs,
		    GATT_MAX_DESCS - disc->ndescs, &ndesc);
		if (ret != 0)
			return (ret);

		disc->ndescs += ndesc;
	}

	return (0);
}

/*
 * Enable notifications on a characteristic by writing 0x0001 to its CCCD.
 * Searches the descriptor list for CCCD (UUID 0x2902) that falls within
 * the characteristic's handle range.
 */
int
gatt_enable_notifications(struct att_conn *ac,
    const struct gatt_char *ch, uint16_t end_handle,
    const struct gatt_desc *descs, int ndescs)
{
	uint8_t val[2];

	if (!(ch->properties & GATT_PROP_NOTIFY))
		return (ENOTSUP);

	/* Find CCCD descriptor for this characteristic */
	for (int i = 0; i < ndescs; i++) {
		if (descs[i].uuid16 == GATT_UUID_CCCD &&
		    descs[i].handle > ch->value_handle &&
		    descs[i].handle <= end_handle) {
			put_le16(val, GATT_CCCD_NOTIFY);
			return (att_write_req(ac, descs[i].handle,
			    val, sizeof(val)));
		}
	}

	return (ENOENT);
}
