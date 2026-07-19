/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_ADV_BUILDER_H_
#define _BLUED_ADV_BUILDER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Structured advertising-data (AD) builder.  Assembles the [len][type][data]
 * AD structures of an advertising or scan-response payload from typed fields
 * (the common LE-advertisement model properties / NimBLE adv-data helpers), so a client
 * need not hand-assemble hex.  Core Spec Vol 3 Part C §11 (AD format) and Core
 * Specification Supplement Part A §1 (AD type definitions / Assigned Numbers).
 */

/* AD type values (CSS Part A §1, Assigned Numbers §2.3). */
#define AD_TYPE_FLAGS			0x01
#define AD_TYPE_UUID16_INCOMPLETE	0x02
#define AD_TYPE_UUID16_COMPLETE		0x03
#define AD_TYPE_UUID128_INCOMPLETE	0x06
#define AD_TYPE_UUID128_COMPLETE	0x07
#define AD_TYPE_NAME_SHORT		0x08
#define AD_TYPE_NAME_COMPLETE		0x09
#define AD_TYPE_TX_POWER		0x0A
#define AD_TYPE_SERVICE_DATA16		0x16
#define AD_TYPE_APPEARANCE		0x19
#define AD_TYPE_MANUF_DATA		0xFF

/* GAP flags bits (Core Spec Vol 3 Part C §11, CSS Part A §1.3). */
#define AD_FLAG_LE_LIMITED_DISC		0x01
#define AD_FLAG_LE_GENERAL_DISC		0x02
#define AD_FLAG_BREDR_NOT_SUPPORTED	0x04

/*
 * Payload budgets: the 31-octet legacy AD limit (Core Spec Vol 4 Part E §7.8.7)
 * and the larger buffer used when extended advertising is active (single,
 * non-fragmented Set Extended Advertising Data, §7.8.54).
 */
#define ADV_LEGACY_BUDGET		31
#define ADV_EXT_BUDGET			251

struct adv_ad {
	uint8_t		data[ADV_EXT_BUDGET];
	uint16_t	len;	/* bytes assembled so far */
	uint16_t	cap;	/* budget: ADV_LEGACY_BUDGET or ADV_EXT_BUDGET */
};

/* Initialize an empty builder with the given budget (clamped to ADV_EXT_BUDGET). */
void	adv_ad_init(struct adv_ad *b, uint16_t cap);

/*
 * Append one AD structure [len][type][value...].  Returns 0 on success, or -1
 * with errno set: EINVAL if the value cannot fit a single AD structure
 * (vlen > 254), ENOSPC if appending would exceed the budget.
 */
int	adv_ad_append(struct adv_ad *b, uint8_t type, const uint8_t *val,
	    uint8_t vlen);

/* Typed field helpers.  Each emits exactly one AD structure. */
int	adv_ad_add_flags(struct adv_ad *b, uint8_t flags);
int	adv_ad_add_uuid16(struct adv_ad *b, bool complete,
	    const uint16_t *uuids, size_t n);
int	adv_ad_add_uuid128(struct adv_ad *b, bool complete,
	    const uint8_t *uuids_le, size_t n);	/* n * 16 LE bytes */
int	adv_ad_add_name(struct adv_ad *b, bool complete, const char *name);
int	adv_ad_add_tx_power(struct adv_ad *b, int8_t dbm);
int	adv_ad_add_appearance(struct adv_ad *b, uint16_t appearance);
int	adv_ad_add_manuf(struct adv_ad *b, uint16_t company,
	    const uint8_t *data, size_t n);
int	adv_ad_add_service_data16(struct adv_ad *b, uint16_t uuid,
	    const uint8_t *data, size_t n);

#endif /* _BLUED_ADV_BUILDER_H_ */
