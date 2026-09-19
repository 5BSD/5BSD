/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Unit tests for the structured advertising-data builder (adv_builder.c).
 * Assert the exact [len][type][data] AD-structure bytes emitted for each typed
 * field (Core Spec Vol 3 Part C §11, CSS Part A §1), correct field framing, and
 * budget enforcement (31-byte legacy overflow -> ENOSPC).
 */

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "adv_builder.h"
#include "spec_adv_builder_oracles.h"

/* ================================================================
 * Per-field framing
 * ================================================================ */

/* Flags (0x01): auto-general-discoverable value 0x06. */
ATF_TC_WITHOUT_HEAD(flags_framing);
ATF_TC_BODY(flags_framing, tc)
{
	struct adv_ad b;
	static const uint8_t want[] = { 0x02, 0x01, 0x06 };

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_flags(&b,
	    BT_ADV_SPEC_FLAG_GENERAL_DISCOVERABLE |
	    BT_ADV_SPEC_FLAG_BREDR_NOT_SUPPORTED));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* Complete Local Name (0x09). */
ATF_TC_WITHOUT_HEAD(name_framing);
ATF_TC_BODY(name_framing, tc)
{
	struct adv_ad b;
	static const uint8_t want[] = { 0x08, 0x09, 'T','e','s','t','D','e','v' };

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_name(&b, true, "TestDev"));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));

	/* Shortened name uses type 0x08. */
	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_name(&b, false, "Tst"));
	ATF_CHECK_EQ(BT_ADV_SPEC_TYPE_NAME_SHORT, b.data[1]);

	/* Empty name is rejected. */
	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_CHECK_EQ(-1, adv_ad_add_name(&b, true, ""));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, b.len);
}

/* TX Power Level (0x0A) — signed, negative value. */
ATF_TC_WITHOUT_HEAD(tx_power_framing);
ATF_TC_BODY(tx_power_framing, tc)
{
	struct adv_ad b;
	static const uint8_t want[] = { 0x02, 0x0A, 0xFC };	/* -4 dBm */

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_tx_power(&b, -4));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* Appearance (0x19) — 16-bit little-endian. */
ATF_TC_WITHOUT_HEAD(appearance_framing);
ATF_TC_BODY(appearance_framing, tc)
{
	struct adv_ad b;
	static const uint8_t want[] = { 0x03, 0x19, 0xC1, 0x03 };  /* 0x03C1 */

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_appearance(&b, 0x03C1));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* Complete/Incomplete 16-bit Service UUID list (0x03 / 0x02), LE order. */
ATF_TC_WITHOUT_HEAD(uuid16_framing);
ATF_TC_BODY(uuid16_framing, tc)
{
	struct adv_ad b;
	static const uint16_t uu[] = { 0x180F, 0x180A };
	static const uint8_t want[] = {
		0x05, 0x03, 0x0F, 0x18, 0x0A, 0x18
	};

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_uuid16(&b, true, uu, 2));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_uuid16(&b, false, uu, 2));
	ATF_CHECK_EQ(BT_ADV_SPEC_TYPE_UUID16_INCOMPLETE, b.data[1]);

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_CHECK_EQ(-1, adv_ad_add_uuid16(&b, true, uu, 0));
	ATF_CHECK_EQ(EINVAL, errno);
}

/* Complete 128-bit Service UUID list (0x07): 16 LE octets verbatim. */
ATF_TC_WITHOUT_HEAD(uuid128_framing);
ATF_TC_BODY(uuid128_framing, tc)
{
	struct adv_ad b;
	uint8_t uu[16];
	int i;

	for (i = 0; i < 16; i++)
		uu[i] = (uint8_t)(i * 0x11);

	adv_ad_init(&b, BT_ADV_SPEC_EXT_COMMAND_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_uuid128(&b, true, uu, 1));
	ATF_CHECK_EQ(18, b.len);		/* len + type + 16 */
	ATF_CHECK_EQ(17, b.data[0]);
	ATF_CHECK_EQ(BT_ADV_SPEC_TYPE_UUID128_COMPLETE, b.data[1]);
	ATF_CHECK_EQ(0, memcmp(&b.data[2], uu, 16));
}

/*
 * Manufacturer Specific Data (0xFF): 2-octet company id (LE) then payload
 * (CSS Part A §1.4).
 */
ATF_TC_WITHOUT_HEAD(manuf_framing);
ATF_TC_BODY(manuf_framing, tc)
{
	struct adv_ad b;
	static const uint8_t data[] = { 0xDE, 0xAD };
	static const uint8_t want[] = { 0x05, 0xFF, 0x4C, 0x00, 0xDE, 0xAD };

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_manuf(&b, 0x004C, data, sizeof(data)));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* Service Data - 16-bit UUID (0x16): UUID (LE) then service data. */
ATF_TC_WITHOUT_HEAD(service_data_framing);
ATF_TC_BODY(service_data_framing, tc)
{
	struct adv_ad b;
	static const uint8_t data[] = { 0x64 };			/* battery 100% */
	static const uint8_t want[] = { 0x04, 0x16, 0x0F, 0x18, 0x64 };

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_service_data16(&b, 0x180F, data,
	    sizeof(data)));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* Multiple fields concatenate in order with correct running length. */
ATF_TC_WITHOUT_HEAD(multi_field);
ATF_TC_BODY(multi_field, tc)
{
	struct adv_ad b;
	static const uint8_t want[] = {
		0x02, 0x01, 0x06,			/* Flags */
		0x05, 0x09, 'T','e','s','t'		/* Complete Name */
	};

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_flags(&b,
	    BT_ADV_SPEC_FLAG_GENERAL_DISCOVERABLE |
	    BT_ADV_SPEC_FLAG_BREDR_NOT_SUPPORTED));
	ATF_REQUIRE_EQ(0, adv_ad_add_name(&b, true, "Test"));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK_EQ(0, memcmp(b.data, want, sizeof(want)));
}

/* ================================================================
 * Budget enforcement
 * ================================================================ */

/* The 31-byte legacy budget rejects an overflowing field with ENOSPC and
 * leaves the buffer unchanged. */
ATF_TC_WITHOUT_HEAD(legacy_overflow);
ATF_TC_BODY(legacy_overflow, tc)
{
	struct adv_ad b;
	char name[28];
	uint16_t before;

	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_flags(&b,
	    BT_ADV_SPEC_FLAG_GENERAL_DISCOVERABLE |
	    BT_ADV_SPEC_FLAG_BREDR_NOT_SUPPORTED));

	/* A 27-char name needs 29 bytes; 3 + 29 = 32 > 31 -> ENOSPC. */
	memset(name, 'A', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	before = b.len;
	errno = 0;
	ATF_CHECK_EQ(-1, adv_ad_add_name(&b, true, name));
	ATF_CHECK_EQ(ENOSPC, errno);
	ATF_CHECK_EQ(before, b.len);

	/* A 26-char name (28 bytes) fits exactly to the 31-byte edge. */
	name[26] = '\0';
	ATF_REQUIRE_EQ(0, adv_ad_add_name(&b, true, name));
	ATF_CHECK_EQ(BT_ADV_SPEC_LEGACY_DATA_MAX, b.len);
}

/* The extended budget (251) accepts a payload that overflows legacy. */
ATF_TC_WITHOUT_HEAD(extended_budget);
ATF_TC_BODY(extended_budget, tc)
{
	struct adv_ad b;
	uint8_t data[200];

	memset(data, 0x5A, sizeof(data));
	adv_ad_init(&b, BT_ADV_SPEC_EXT_COMMAND_DATA_MAX);
	ATF_REQUIRE_EQ(0, adv_ad_add_manuf(&b, 0x004C, data, sizeof(data)));
	ATF_CHECK_EQ(2 + 2 + sizeof(data), b.len);

	/* The same payload does not fit the legacy budget. */
	adv_ad_init(&b, BT_ADV_SPEC_LEGACY_DATA_MAX);
	errno = 0;
	ATF_CHECK_EQ(-1, adv_ad_add_manuf(&b, 0x004C, data, sizeof(data)));
	ATF_CHECK_EQ(ENOSPC, errno);
}

/* adv_ad_init clamps an over-large budget to the extended maximum. */
ATF_TC_WITHOUT_HEAD(init_clamp);
ATF_TC_BODY(init_clamp, tc)
{
	struct adv_ad b;

	adv_ad_init(&b, 1000);
	ATF_CHECK_EQ(BT_ADV_SPEC_EXT_COMMAND_DATA_MAX, b.cap);
	ATF_CHECK_EQ(0, b.len);
}

ATF_TC_WITHOUT_HEAD(field_size_rejections);
ATF_TC_BODY(field_size_rejections, tc)
{
	struct adv_ad b;
	uint8_t bytes[255] = { 0 };
	uint16_t uuids[128] = { 0 };

	adv_ad_init(&b, BT_ADV_SPEC_EXT_COMMAND_DATA_MAX);
	ATF_CHECK_EQ(-1, adv_ad_append(&b, BT_ADV_SPEC_TYPE_FLAGS, bytes,
	    BT_ADV_SPEC_AD_DATA_MAX + 1));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, adv_ad_add_uuid16(&b, true, uuids, 128));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, adv_ad_add_uuid128(&b, true, bytes, 16));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, adv_ad_add_manuf(&b, 1, bytes, 253));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, adv_ad_add_service_data16(&b, 1, bytes, 253));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, flags_framing);
	ATF_TP_ADD_TC(tp, name_framing);
	ATF_TP_ADD_TC(tp, tx_power_framing);
	ATF_TP_ADD_TC(tp, appearance_framing);
	ATF_TP_ADD_TC(tp, uuid16_framing);
	ATF_TP_ADD_TC(tp, uuid128_framing);
	ATF_TP_ADD_TC(tp, manuf_framing);
	ATF_TP_ADD_TC(tp, service_data_framing);
	ATF_TP_ADD_TC(tp, multi_field);
	ATF_TP_ADD_TC(tp, legacy_overflow);
	ATF_TP_ADD_TC(tp, extended_budget);
	ATF_TP_ADD_TC(tp, init_clamp);
	ATF_TP_ADD_TC(tp, field_size_rejections);

	return (atf_no_error());
}
