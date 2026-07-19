/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Advertising-report / AD-structure PARSER edge cases (hci_scan.c).
 *
 * These extend the parser coverage in hci_offline_test.c to the AD-type
 * branches and extended-advertising-report field boundaries that the
 * offline suite leaves untouched.  The parsers consume attacker-controlled
 * over-the-air bytes, so every branch is a potential malformed-input target.
 *
 * Oracle: AD structure layout and the specific AD types are defined in
 * Core Spec Vol 3 Part C Section 11 and the assigned-numbers Core Specification
 * Supplement (CSS) Part A Section 1; the LE Extended Advertising Report event
 * layout is Core Spec Vol 4 Part E Section 7.7.65.13.
 *
 * Link set: hci_scan_parse_edge_test.c hci_util.c hci_adv.c hci_scan.c
 * hci_conn.c hci_privacy.c hci_misc.c hci_log.c   (+ libbluetooth, libcrypto).
 */

#include <sys/types.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <netgraph/bluetooth/include/ng_bluetooth.h>	/* BDADDR_LE_* */

#include <atf-c.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_hci_scan_parse_oracles.h"

/* Stub globals required by the hci_*.c logging macros (_BLUED_LOG). */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define AD_FLAGS BT_SP_SPEC_AD_FLAGS
#define AD_UUID16_INCOMPLETE BT_SP_SPEC_AD_UUID16_INCOMPLETE
#define AD_UUID16_COMPLETE BT_SP_SPEC_AD_UUID16_COMPLETE
#define AD_SHORT_NAME BT_SP_SPEC_AD_SHORT_NAME
#define AD_COMPLETE_NAME BT_SP_SPEC_AD_COMPLETE_NAME
#define AD_MANUFACTURER BT_SP_SPEC_AD_MANUFACTURER

/* ================================================================
 * hci_parse_ad: exact-fit boundary — an AD whose declared length
 * consumes the whole buffer must be accepted and point at the end.
 * Core Spec Vol 3 Part C 11.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_ad_exact_fit);
ATF_TC_BODY(parse_ad_exact_fit, tc)
{
	/* adlen = 3 covers type + 2 value bytes; buffer is exactly 4. */
	const uint8_t ad[] = { 0x03, AD_UUID16_COMPLETE, 0x12, 0x18 };
	uint8_t type, vlen;
	const uint8_t *val, *next;

	next = hci_parse_ad(ad, sizeof(ad), &type, &val, &vlen);
	ATF_REQUIRE(next != NULL);
	ATF_CHECK_EQ(type, AD_UUID16_COMPLETE);
	ATF_CHECK_EQ(vlen, 2);
	ATF_CHECK(next == ad + sizeof(ad));	/* points exactly at the end */
}

/* ================================================================
 * hci_parse_ad_fields: Manufacturer Specific Data (0xFF).
 * First two value octets are the little-endian company identifier
 * (CSS Part A 1.4).  vlen>=2 required.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_fields_manufacturer);
ATF_TC_BODY(parse_fields_manufacturer, tc)
{
	/* company id BT_SP_SPEC_COMPANY_APPLE (LE bytes 0x4C,0x00) + one payload byte. */
	const uint8_t ad[] = { 0x04, AD_MANUFACTURER, 0x4C, 0x00, 0xAB };
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK_EQ(sr.mfr_id, BT_SP_SPEC_COMPANY_APPLE);
}

/*
 * Manufacturer data shorter than the 2-octet company id must be ignored
 * (vlen < 2 branch): mfr_id stays at the BT_SP_SPEC_MFR_NONE "none" sentinel.
 */
ATF_TC_WITHOUT_HEAD(parse_fields_manufacturer_too_short);
ATF_TC_BODY(parse_fields_manufacturer_too_short, tc)
{
	const uint8_t ad[] = { 0x02, AD_MANUFACTURER, 0x4C };	/* vlen == 1 */
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK_EQ(sr.mfr_id, BT_SP_SPEC_MFR_NONE);
}

/*
 * A second Manufacturer Specific Data structure must NOT overwrite an
 * already-captured company id (the "mfr_id == BT_SP_SPEC_MFR_NONE" guard is false).
 */
ATF_TC_WITHOUT_HEAD(parse_fields_manufacturer_no_overwrite);
ATF_TC_BODY(parse_fields_manufacturer_no_overwrite, tc)
{
	const uint8_t ad[] = {
		0x03, AD_MANUFACTURER, 0x4C, 0x00,	/* BT_SP_SPEC_COMPANY_APPLE */
		0x03, AD_MANUFACTURER, 0xFF, 0xFE,	/* would be 0xFEFF */
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK_EQ(sr.mfr_id, BT_SP_SPEC_COMPANY_APPLE);	/* first one kept */
}

/* ================================================================
 * hci_parse_ad_fields: Shortened Local Name (0x08) is captured just
 * like the Complete Local Name.  CSS Part A 1.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_fields_short_name);
ATF_TC_BODY(parse_fields_short_name, tc)
{
	const uint8_t ad[] = { 0x04, AD_SHORT_NAME, 'A', 'B', 'C' };
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "ABC");
}

/*
 * A Complete Local Name supersedes a Shortened Local Name.  This is also the
 * merge behavior needed when the shortened name is in ADV_IND and the complete
 * name follows in SCAN_RSP.
 */
ATF_TC_WITHOUT_HEAD(parse_fields_name_first_wins);
ATF_TC_BODY(parse_fields_name_first_wins, tc)
{
	const uint8_t ad[] = {
		0x03, AD_SHORT_NAME, 'H', 'i',		/* "Hi" */
		0x05, AD_COMPLETE_NAME, 'L', 'o', 'n', 'g',
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "Long");
	ATF_CHECK(sr.name_complete);
}

/*
 * A zero-length name value (adlen == 1, so vlen == 0) does not set a
 * name — the "vlen > 0" guard is false — but parsing continues past it.
 */
ATF_TC_WITHOUT_HEAD(parse_fields_empty_name_then_uuid);
ATF_TC_BODY(parse_fields_empty_name_then_uuid, tc)
{
	const uint8_t ad[] = {
		0x01, AD_COMPLETE_NAME,			/* empty name, vlen 0 */
		0x03, AD_UUID16_COMPLETE, 0x0F, 0x18,	/* Battery Service */
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(!sr.has_name);
	ATF_REQUIRE_EQ(sr.num_svc_uuids, 1);
	ATF_CHECK_EQ(sr.svc_uuids[0], BT_SP_SPEC_UUID_BATTERY_SERVICE);
}

/* ================================================================
 * hci_parse_ad_fields: Incomplete 16-bit UUID list (0x02) is parsed
 * the same as the complete list.  Its value is a sequence of 16-bit UUIDs, so
 * an odd value length invalidates the whole typed field.  CSS Part A 1.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_fields_uuid_incomplete_odd);
ATF_TC_BODY(parse_fields_uuid_incomplete_odd, tc)
{
	/* Two whole UUID16s plus one stray octet (vlen == 5, odd). */
	const uint8_t ad[] = {
		0x06, AD_UUID16_INCOMPLETE,
		0x0F, 0x18,	/* BT_SP_SPEC_UUID_BATTERY_SERVICE */
		0x12, 0x18,	/* BT_SP_SPEC_UUID_HID_SERVICE */
		0xAA,		/* dangling half-UUID -> ignored */
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK_EQ(sr.num_svc_uuids, 0);
}

/*
 * UUIDs accumulate across two separate list ADs, and the too-short
 * (vlen < 2) UUID list is skipped entirely.
 */
ATF_TC_WITHOUT_HEAD(parse_fields_uuid_accumulate_and_short);
ATF_TC_BODY(parse_fields_uuid_accumulate_and_short, tc)
{
	const uint8_t ad[] = {
		0x02, AD_UUID16_COMPLETE, 0x01,		/* vlen 1 -> skipped */
		0x03, AD_UUID16_COMPLETE, 0x0F, 0x18,	/* BT_SP_SPEC_UUID_BATTERY_SERVICE */
		0x03, AD_UUID16_INCOMPLETE, 0x12, 0x18,	/* BT_SP_SPEC_UUID_HID_SERVICE */
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_REQUIRE_EQ(sr.num_svc_uuids, 2);
	ATF_CHECK_EQ(sr.svc_uuids[0], BT_SP_SPEC_UUID_BATTERY_SERVICE);
	ATF_CHECK_EQ(sr.svc_uuids[1], BT_SP_SPEC_UUID_HID_SERVICE);
}

/*
 * An unrecognised AD type falls through every branch and is skipped,
 * yet the following well-known AD is still parsed — proving the walk
 * advances by the declared length even for unknown types.
 */
ATF_TC_WITHOUT_HEAD(parse_fields_unknown_type_skipped);
ATF_TC_BODY(parse_fields_unknown_type_skipped, tc)
{
	const uint8_t ad[] = {
		0x03, 0x0A, 0x11, 0x22,			/* TX Power / unhandled */
		0x05, AD_COMPLETE_NAME, 'n', 'a', 'm', 'e',
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "name");
}

/* ================================================================
 * hci_parse_ext_adv_report: address-type classification.
 * addr_type 0x01/0x03 -> random; 0x00/0x02 -> public.
 * Core Spec Vol 4 Part E 7.7.65.13.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(parse_ext_report_addr_random);
ATF_TC_BODY(parse_ext_report_addr_random, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN];
	struct ble_scan_result sr;

	/* addr_type == 0x01 (random), data_len 0. */
	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = BT_SP_SPEC_ADDR_RANDOM;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 0;
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN);
	ATF_CHECK_EQ(sr.addr_type, BDADDR_LE_RANDOM);

	/* addr_type == 0x03 (resolvable-from-random) is also random. */
	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = BT_SP_SPEC_ADDR_RANDOM_IDENTITY;
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN);
	ATF_CHECK_EQ(sr.addr_type, BDADDR_LE_RANDOM);
}

ATF_TC_WITHOUT_HEAD(parse_ext_report_addr_public);
ATF_TC_BODY(parse_ext_report_addr_public, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN];
	struct ble_scan_result sr;

	/* addr_type == 0x02 (resolvable-from-public) classifies as public. */
	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = BT_SP_SPEC_ADDR_PUBLIC_IDENTITY;
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN);
	ATF_CHECK_EQ(sr.addr_type, BDADDR_LE_PUBLIC);
}

/*
 * RSSI (octet 13) and the address bytes (3..8) are copied out.  Feed a
 * negative RSSI and a recognisable address, with a full AD payload so
 * the header+data length accounting is exercised on a non-zero data_len.
 */
ATF_TC_WITHOUT_HEAD(parse_ext_report_fields_extracted);
ATF_TC_BODY(parse_ext_report_fields_extracted, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 6];
	struct ble_scan_result sr;
	size_t consumed;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[3] = 0xDE; buf[4] = 0xAD; buf[5] = 0xBE;
	buf[6] = 0xEF; buf[7] = 0x00; buf[8] = 0x11;
	buf[BT_SP_SPEC_RSSI_OFFSET] = (uint8_t)(int8_t)-71;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 6;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN] = 0x05;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 1] = AD_COMPLETE_NAME;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 2] = 'x';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 3] = 'y';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 4] = 'z';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 5] = 'w';

	memset(&sr, 0, sizeof(sr));
	consumed = hci_parse_ext_adv_report(buf, sizeof(buf), &sr);
	ATF_CHECK_EQ(consumed, BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 6);
	ATF_CHECK_EQ(sr.rssi, -71);
	ATF_CHECK_EQ(sr.addr[0], 0xDE);
	ATF_CHECK_EQ(sr.addr[5], 0x11);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "xyzw");
}

/*
 * Exact boundary: remain == header + data_len is accepted (returns the
 * full consumed length); one byte short of that must return 0.
 */
ATF_TC_WITHOUT_HEAD(parse_ext_report_datalen_exact_and_short);
ATF_TC_BODY(parse_ext_report_datalen_exact_and_short, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 4];
	struct ble_scan_result sr;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 4;

	/* Exactly header + 4 present -> accepted. */
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf,
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 4, &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 4);

	/* One byte short -> rejected (returns 0). */
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf,
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 3, &sr), 0);
}

/*
 * The parser clears the caller's per-report fields before merging: a
 * stale has_name / mfr_id from a reused struct must not survive a report
 * that carries no such AD.
 */
ATF_TC_WITHOUT_HEAD(parse_ext_report_resets_fields);
ATF_TC_BODY(parse_ext_report_resets_fields, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN];
	struct ble_scan_result sr;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 0;

	memset(&sr, 0, sizeof(sr));
	sr.has_name = true;
	strcpy(sr.name, "stale");
	sr.mfr_id = 0x1234;
	sr.num_svc_uuids = 3;

	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN);
	ATF_CHECK(!sr.has_name);
	ATF_CHECK_EQ(sr.mfr_id, BT_SP_SPEC_MFR_NONE);
	ATF_CHECK_EQ(sr.num_svc_uuids, 0);
}

/* Reserved Core 5.2 enum/bit values are rejected before output mutation. */
ATF_TC_WITHOUT_HEAD(parse_ext_report_reserved_fields);
ATF_TC_BODY(parse_ext_report_reserved_fields, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN];
	struct ble_scan_result before, sr;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	memset(&before, 0x5a, sizeof(before));

	sr = before;
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = 0x04; /* first reserved */
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
	ATF_CHECK_EQ(memcmp(&sr, &before, sizeof(sr)), 0);

	sr = before;
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = BT_SP_SPEC_ADDR_PUBLIC;
	buf[0] = BT_SP_SPEC_DATA_STATUS_RESERVED;
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
	ATF_CHECK_EQ(memcmp(&sr, &before, sizeof(sr)), 0);

	sr = before;
	buf[0] = 0x00;
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = 0x02; /* first reserved PHY */
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
	ATF_CHECK_EQ(memcmp(&sr, &before, sizeof(sr)), 0);

	sr = before;
	buf[0] = BT_SP_SPEC_LEGACY_UNDEFINED;
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
	ATF_CHECK_EQ(memcmp(&sr, &before, sizeof(sr)), 0);
}

/* Core 6.3 Vol 4 Part E §7.7.65.13: anonymous 0xff and 229-byte max. */
ATF_TC_WITHOUT_HEAD(parse_ext_report_anonymous_data_max);
ATF_TC_BODY(parse_ext_report_anonymous_data_max, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN +
	    BT_SP_SPEC_EXT_REPORT_DATA_MAX + 1];
	struct ble_scan_result before, sr;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_ADDR_TYPE_OFFSET] = BT_SP_SPEC_ADDR_ANONYMOUS;
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = BT_SP_SPEC_EXT_REPORT_DATA_MAX;
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf) - 1, &sr),
	    BT_SP_SPEC_EXT_REPORT_FIXED_LEN + BT_SP_SPEC_EXT_REPORT_DATA_MAX);
	for (size_t i = 0; i < sizeof(sr.addr); i++)
		ATF_CHECK_EQ(sr.addr[i], 0);

	before = sr;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = BT_SP_SPEC_EXT_REPORT_DATA_MAX + 1;
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
	ATF_CHECK_EQ(memcmp(&sr, &before, sizeof(sr)), 0);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, parse_ad_exact_fit);
	ATF_TP_ADD_TC(tp, parse_fields_manufacturer);
	ATF_TP_ADD_TC(tp, parse_fields_manufacturer_too_short);
	ATF_TP_ADD_TC(tp, parse_fields_manufacturer_no_overwrite);
	ATF_TP_ADD_TC(tp, parse_fields_short_name);
	ATF_TP_ADD_TC(tp, parse_fields_name_first_wins);
	ATF_TP_ADD_TC(tp, parse_fields_empty_name_then_uuid);
	ATF_TP_ADD_TC(tp, parse_fields_uuid_incomplete_odd);
	ATF_TP_ADD_TC(tp, parse_fields_uuid_accumulate_and_short);
	ATF_TP_ADD_TC(tp, parse_fields_unknown_type_skipped);
	ATF_TP_ADD_TC(tp, parse_ext_report_addr_random);
	ATF_TP_ADD_TC(tp, parse_ext_report_addr_public);
	ATF_TP_ADD_TC(tp, parse_ext_report_fields_extracted);
	ATF_TP_ADD_TC(tp, parse_ext_report_datalen_exact_and_short);
	ATF_TP_ADD_TC(tp, parse_ext_report_resets_fields);
	ATF_TP_ADD_TC(tp, parse_ext_report_reserved_fields);
	ATF_TP_ADD_TC(tp, parse_ext_report_anonymous_data_max);

	return (atf_no_error());
}
