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
#include "ble_util.h"

/* Stub globals required by hci_util.c logging */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* ================================================================
 * ble_build_adv_data: basic flags + name
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_data_flags_and_name);
ATF_TC_BODY(test_adv_data_flags_and_name, tc)
{
	uint8_t buf[31];
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "Test", NULL, 0);

	ATF_REQUIRE(len > 0);

	/* Flags: len=2, type=0x01, value=0x06 */
	ATF_CHECK_EQ(buf[0], 2);
	ATF_CHECK_EQ(buf[1], 0x01);  /* AD_TYPE_FLAGS */
	ATF_CHECK_EQ(buf[2], 0x06);  /* LE General + BR/EDR Not Supported */

	/* Name: len=5, type=0x09 (Complete Local Name), "Test" */
	ATF_CHECK_EQ(buf[3], 5);     /* 1 (type) + 4 (name) */
	ATF_CHECK_EQ(buf[4], 0x09);  /* AD_TYPE_COMPLETE_LOCAL_NAME */
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
	uint8_t buf[31];
	uint16_t uuids[] = { 0x1812, 0x180F };
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "BLE", uuids, 2);

	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= 31);

	/* Should contain flags (3 bytes) + name + UUID list */
	/* UUID list: len, type=0x03, uuid1_lo, uuid1_hi, uuid2_lo, uuid2_hi */
	{
		bool found_uuid = false;
		int i = 0;
		while (i < len) {
			uint8_t adlen = buf[i];
			uint8_t adtype = buf[i + 1];
			if (adtype == 0x03 || adtype == 0x02) {
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
	uint8_t buf[31];
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
	ATF_CHECK_EQ(buf[4], 0x08);  /* AD_TYPE_SHORT_LOCAL_NAME */
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
	ATF_CHECK((mask & LE_EVTMASK_CONN_COMPLETE) != 0);
	ATF_CHECK((mask & LE_EVTMASK_ADV_REPORT) != 0);
	ATF_CHECK((mask & LE_EVTMASK_LTK_REQUEST) != 0);
	ATF_CHECK((mask & LE_EVTMASK_CONN_UPDATE) != 0);

	/* Extended advertising bits should NOT be set without features */
	ATF_CHECK((mask & LE_EVTMASK_EXT_ADV_REPORT) == 0);
}

/* ================================================================
 * hci_le_default_event_mask: with extended advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_ext_adv);
ATF_TC_BODY(test_event_mask_ext_adv, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(LE_FEAT_EXT_ADVERTISING);

	ATF_CHECK((mask & LE_EVTMASK_EXT_ADV_REPORT) != 0);
	ATF_CHECK((mask & LE_EVTMASK_ADV_SET_TERM) != 0);
	ATF_CHECK((mask & LE_EVTMASK_SCAN_REQ_RCVD) != 0);
}

/* ================================================================
 * hci_le_default_event_mask: with periodic advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_periodic_adv);
ATF_TC_BODY(test_event_mask_periodic_adv, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(LE_FEAT_PERIODIC_ADV);

	ATF_CHECK((mask & LE_EVTMASK_PER_ADV_SYNC_EST) != 0);
	ATF_CHECK((mask & LE_EVTMASK_PER_ADV_REPORT) != 0);
	ATF_CHECK((mask & LE_EVTMASK_PER_ADV_SYNC_LOST) != 0);
}

/* ================================================================
 * hci_le_default_event_mask: with CIS features
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_event_mask_cis);
ATF_TC_BODY(test_event_mask_cis, tc)
{
	uint64_t mask;

	mask = hci_le_default_event_mask(LE_FEAT_CIS_CENTRAL);
	ATF_CHECK((mask & LE_EVTMASK_CIS_ESTABLISHED) != 0);

	mask = hci_le_default_event_mask(LE_FEAT_CIS_PERIPH);
	ATF_CHECK((mask & LE_EVTMASK_CIS_REQUEST) != 0);
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

	return (atf_no_error());
}
