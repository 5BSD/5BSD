/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Offline HCI utility tests — verify pure-logic functions
 * without requiring Bluetooth hardware.
 *
 * Tests ble_build_adv_data() and hci_le_default_event_mask()
 * which are pure computation with no socket I/O.
 */

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_adv_builder_oracles.h"
#include "spec_hci_offline_oracles.h"
#include "spec_hci_scan_parse_oracles.h"

/* Stub globals required by hci_util.c logging */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* ================================================================
 * ble_build_adv_data: basic flags + name
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_flags_and_name);
ATF_TC_BODY(test_adv_data_flags_and_name, tc)
{
	uint8_t buf[BT_ADV_SPEC_LEGACY_DATA_MAX];
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "Test", NULL, 0);

	ATF_REQUIRE(len > 0);

	/* Flags: len=2, type=0x01, value=0x06 */
	ATF_CHECK_EQ(buf[0], 2);
	ATF_CHECK_EQ(buf[1], BT_ADV_SPEC_TYPE_FLAGS);
	ATF_CHECK_EQ(buf[2], BT_ADV_SPEC_FLAG_GENERAL_DISCOVERABLE |
	    BT_ADV_SPEC_FLAG_BREDR_NOT_SUPPORTED);

	/* Name: len=5, type=0x09 (Complete Local Name), "Test" */
	ATF_CHECK_EQ(buf[3], 5);     /* 1 (type) + 4 (name) */
	ATF_CHECK_EQ(buf[4], BT_ADV_SPEC_TYPE_NAME_COMPLETE);
	ATF_CHECK_EQ(buf[5], 'T');
	ATF_CHECK_EQ(buf[6], 'e');
	ATF_CHECK_EQ(buf[7], 's');
	ATF_CHECK_EQ(buf[8], 't');
}

/* ================================================================
 * ble_build_adv_data: with service UUIDs
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_with_uuids);
ATF_TC_BODY(test_adv_data_with_uuids, tc)
{
	uint8_t buf[BT_ADV_SPEC_LEGACY_DATA_MAX];
	uint16_t uuids[] = { BT_SP_SPEC_UUID_HID_SERVICE, BT_SP_SPEC_UUID_BATTERY_SERVICE };
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "BLE", uuids, 2);

	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= BT_ADV_SPEC_LEGACY_DATA_MAX);

	/* Should contain flags (3 bytes) + name + UUID list */
	/* UUID list: len, type=0x03, uuid1_lo, uuid1_hi, uuid2_lo, uuid2_hi */
	{
		bool found_uuid = false;
		int i = 0;
		while (i < len) {
			uint8_t adlen = buf[i];
			uint8_t adtype = buf[i + 1];
			if (adtype == BT_ADV_SPEC_TYPE_UUID16_COMPLETE ||
			    adtype == BT_ADV_SPEC_TYPE_UUID16_INCOMPLETE) {
				/* UUID16 list */
				found_uuid = true;
				/* First UUID: 0x1812 in LE = 0x12, 0x18 */
				ATF_CHECK_EQ(buf[i + 2], 0x12);
				ATF_CHECK_EQ(buf[i + 3], 0x18);
			}
			i += adlen + 1;
		}
		ATF_CHECK(found_uuid);
	}
}

/* ================================================================
 * ble_build_adv_data: buffer too small
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_buffer_too_small);
ATF_TC_BODY(test_adv_data_buffer_too_small, tc)
{
	uint8_t buf[2];  /* too small for even flags */
	int len;

	len = ble_build_adv_data(buf, sizeof(buf), "Test", NULL, 0);
	ATF_CHECK_EQ(len, -1);
}

/* ================================================================
 * ble_build_adv_data: NULL name
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_null_name);
ATF_TC_BODY(test_adv_data_null_name, tc)
{
	uint8_t buf[BT_ADV_SPEC_LEGACY_DATA_MAX];
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), NULL, NULL, 0);

	ATF_REQUIRE(len > 0);
	/* Should contain only flags (3 bytes) */
	ATF_CHECK_EQ(len, 3);
}

/* ================================================================
 * ble_build_adv_data: name truncation when buffer is tight
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_name_truncation);
ATF_TC_BODY(test_adv_data_name_truncation, tc)
{
	uint8_t buf[10];  /* 3 flags + 7 for name = room for 5 chars */
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf),
	    "VeryLongDeviceName", NULL, 0);

	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= 10);

	/* Name should be truncated, type should be 0x08 (Shortened) */
	ATF_CHECK_EQ(buf[4], BT_ADV_SPEC_TYPE_NAME_SHORT);
}

/* ================================================================
 * hci_le_default_event_mask: base features (no extensions)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_base);
ATF_TC_BODY(test_event_mask_base, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(0);

	/* Must always include connection complete */
	ATF_CHECK((mask & BT_OFF_MASK_CONN_COMPLETE) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_ADV_REPORT) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_LTK_REQUEST) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_CONN_UPDATE) != 0);

	/* Extended advertising bits should NOT be set without features */
	ATF_CHECK((mask & BT_OFF_MASK_EXT_ADV_REPORT) == 0);
}

/* ================================================================
 * hci_le_default_event_mask: with extended advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_ext_adv);
ATF_TC_BODY(test_event_mask_ext_adv, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(BT_OFF_FEAT_EXT_ADVERTISING);

	ATF_CHECK((mask & BT_OFF_MASK_EXT_ADV_REPORT) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_ADV_SET_TERMINATED) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_SCAN_REQUEST) != 0);
}

/* ================================================================
 * hci_le_default_event_mask: with periodic advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_periodic_adv);
ATF_TC_BODY(test_event_mask_periodic_adv, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(BT_OFF_FEAT_PERIODIC_ADVERTISING);

	ATF_CHECK((mask & BT_OFF_MASK_PERIODIC_SYNC_EST) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_PERIODIC_REPORT) != 0);
	ATF_CHECK((mask & BT_OFF_MASK_PERIODIC_SYNC_LOST) != 0);
}

/* ================================================================
 * hci_le_default_event_mask: with CIS features
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_cis);
ATF_TC_BODY(test_event_mask_cis, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(BT_OFF_FEAT_CIS_CENTRAL);
	ATF_CHECK((mask & BT_OFF_MASK_CIS_ESTABLISHED) != 0);

	mask = hci_le_default_event_mask(BT_OFF_FEAT_CIS_PERIPHERAL);
	ATF_CHECK((mask & BT_OFF_MASK_CIS_REQUEST) != 0);
}

/* ================================================================
 * Advertising-report parser robustness (hci_scan.c)
 *
 * These parsers consume attacker-controlled advertising bytes off the
 * air.  The cases below lock in bounds handling, control-character
 * sanitization, and buffer clamping -- the class of defect the fuzz
 * harnesses hunt for.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_ad_basic);
ATF_TC_BODY(test_parse_ad_basic, tc)
{
	const uint8_t ad[] = {
	    0x05, BT_SP_SPEC_AD_COMPLETE_NAME, 'a', 'b', 'c', 'd'
	};
	uint8_t type, vlen;
	const uint8_t *val, *next;

	next = hci_parse_ad(ad, sizeof(ad), &type, &val, &vlen);
	ATF_REQUIRE(next != NULL);
	ATF_CHECK_EQ(type, BT_SP_SPEC_AD_COMPLETE_NAME);
	ATF_CHECK_EQ(vlen, 4);
	ATF_CHECK(val == ad + 2);
	ATF_CHECK(next == ad + 6);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_zero_len);
ATF_TC_BODY(test_parse_ad_zero_len, tc)
{
	const uint8_t ad[] = {
	    0x00, BT_SP_SPEC_AD_COMPLETE_NAME
	};	/* adlen == 0 */
	uint8_t type, vlen;
	const uint8_t *val;

	ATF_CHECK(hci_parse_ad(ad, sizeof(ad), &type, &val, &vlen) == NULL);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_overflow_len);
ATF_TC_BODY(test_parse_ad_overflow_len, tc)
{
	const uint8_t ad[] = {
	    0x20, BT_SP_SPEC_AD_COMPLETE_NAME, 'x'
	};	/* adlen 32 > present */
	uint8_t type, vlen;
	const uint8_t *val;

	ATF_CHECK(hci_parse_ad(ad, sizeof(ad), &type, &val, &vlen) == NULL);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_too_short);
ATF_TC_BODY(test_parse_ad_too_short, tc)
{
	const uint8_t ad[] = { 0x01 };
	uint8_t type, vlen;
	const uint8_t *val;

	ATF_CHECK(hci_parse_ad(ad, 1, &type, &val, &vlen) == NULL);
	ATF_CHECK(hci_parse_ad(ad, 0, &type, &val, &vlen) == NULL);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_fields_name);
ATF_TC_BODY(test_parse_ad_fields_name, tc)
{
	const uint8_t ad[] = {
	    0x05, BT_SP_SPEC_AD_COMPLETE_NAME, 'N', 'A', 'M', 'E'
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "NAME");
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_fields_name_injection);
ATF_TC_BODY(test_parse_ad_fields_name_injection, tc)
{
	/* Control characters in the name must be sanitized to '?'. */
	const uint8_t ad[] = {
	    0x05, BT_SP_SPEC_AD_COMPLETE_NAME, 'A', '\n', '\r', 'B'
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "A??B");
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_fields_name_clamp);
ATF_TC_BODY(test_parse_ad_fields_name_clamp, tc)
{
	/* A 40-byte name must clamp to sizeof(name)-1 and stay NUL-terminated. */
	uint8_t ad[42];
	struct ble_scan_result sr;
	size_t i;

	ad[0] = 41;		/* type + 40 name bytes */
	ad[1] = BT_SP_SPEC_AD_COMPLETE_NAME;
	for (i = 0; i < 40; i++)
		ad[2 + i] = 'x';
	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_EQ(strlen(sr.name), sizeof(sr.name) - 1);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_fields_uuid_overflow);
ATF_TC_BODY(test_parse_ad_fields_uuid_overflow, tc)
{
	/* 10 UUID16s but svc_uuids holds only 8 -> capped, no overflow. */
	uint8_t ad[2 + 20];
	struct ble_scan_result sr;
	int i;

	ad[0] = 1 + 20;
	ad[1] = BT_SP_SPEC_AD_UUID16_COMPLETE;
	for (i = 0; i < 20; i++)
		ad[2 + i] = (uint8_t)i;
	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK_EQ(sr.num_svc_uuids, 8);
}

ATF_TC_WITHOUT_HEAD(test_parse_ad_fields_truncated);
ATF_TC_BODY(test_parse_ad_fields_truncated, tc)
{
	/* Declared adlen (10) exceeds the bytes present -> reject, no read-over. */
	const uint8_t ad[] = {
	    0x0A, BT_SP_SPEC_AD_COMPLETE_NAME, 'h', 'i'
	};
	struct ble_scan_result sr;

	memset(&sr, 0, sizeof(sr));
	sr.mfr_id = BT_SP_SPEC_MFR_NONE;
	hci_parse_ad_fields(ad, sizeof(ad), &sr);
	ATF_CHECK(!sr.has_name);
}

ATF_TC_WITHOUT_HEAD(test_parse_ext_report_short_header);
ATF_TC_BODY(test_parse_ext_report_short_header, tc)
{
	uint8_t buf[10];	/* < BT_SP_SPEC_EXT_REPORT_FIXED_LEN */
	struct ble_scan_result sr;

	memset(buf, 0, sizeof(buf));
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
}

ATF_TC_WITHOUT_HEAD(test_parse_ext_report_datalen_overflow);
ATF_TC_BODY(test_parse_ext_report_datalen_overflow, tc)
{
	/* Header claims 50 data bytes that are not present -> returns 0. */
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN];
	struct ble_scan_result sr;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 50;
	memset(&sr, 0, sizeof(sr));
	ATF_CHECK_EQ(hci_parse_ext_adv_report(buf, sizeof(buf), &sr), 0);
}

ATF_TC_WITHOUT_HEAD(test_parse_ext_report_valid);
ATF_TC_BODY(test_parse_ext_report_valid, tc)
{
	uint8_t buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 6];
	struct ble_scan_result sr;
	size_t consumed;

	memset(buf, 0, sizeof(buf));
	buf[BT_SP_SPEC_PRIMARY_PHY_OFFSET] = BT_SP_SPEC_PRIMARY_PHY_1M;
	buf[BT_SP_SPEC_DATA_LEN_OFFSET] = 6;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN] = 0x05;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 1] =
	    BT_SP_SPEC_AD_COMPLETE_NAME;
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 2] = 't';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 3] = 'e';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 4] = 's';
	buf[BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 5] = 't';
	memset(&sr, 0, sizeof(sr));
	consumed = hci_parse_ext_adv_report(buf, sizeof(buf), &sr);
	ATF_CHECK_EQ(consumed, BT_SP_SPEC_EXT_REPORT_FIXED_LEN + 6);
	ATF_CHECK(sr.has_name);
	ATF_CHECK_STREQ(sr.name, "test");
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Advertising data building */
	ATF_TP_ADD_TC(tp, test_adv_data_flags_and_name);
	ATF_TP_ADD_TC(tp, test_adv_data_with_uuids);
	ATF_TP_ADD_TC(tp, test_adv_data_buffer_too_small);
	ATF_TP_ADD_TC(tp, test_adv_data_null_name);
	ATF_TP_ADD_TC(tp, test_adv_data_name_truncation);

	/* Event mask computation */
	ATF_TP_ADD_TC(tp, test_event_mask_base);
	ATF_TP_ADD_TC(tp, test_event_mask_ext_adv);
	ATF_TP_ADD_TC(tp, test_event_mask_periodic_adv);
	ATF_TP_ADD_TC(tp, test_event_mask_cis);

	/* Advertising-report parser robustness */
	ATF_TP_ADD_TC(tp, test_parse_ad_basic);
	ATF_TP_ADD_TC(tp, test_parse_ad_zero_len);
	ATF_TP_ADD_TC(tp, test_parse_ad_overflow_len);
	ATF_TP_ADD_TC(tp, test_parse_ad_too_short);
	ATF_TP_ADD_TC(tp, test_parse_ad_fields_name);
	ATF_TP_ADD_TC(tp, test_parse_ad_fields_name_injection);
	ATF_TP_ADD_TC(tp, test_parse_ad_fields_name_clamp);
	ATF_TP_ADD_TC(tp, test_parse_ad_fields_uuid_overflow);
	ATF_TP_ADD_TC(tp, test_parse_ad_fields_truncated);
	ATF_TP_ADD_TC(tp, test_parse_ext_report_short_header);
	ATF_TP_ADD_TC(tp, test_parse_ext_report_datalen_overflow);
	ATF_TP_ADD_TC(tp, test_parse_ext_report_valid);

	return (atf_no_error());
}
