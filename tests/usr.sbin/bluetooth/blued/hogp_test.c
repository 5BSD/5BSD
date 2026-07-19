/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for HOGP (HID over GATT Profile) logic.
 *
 * Tests hogp_find_feature_handle() and report mapping without
 * requiring Bluetooth hardware or a running daemon.
 */

#include <atf-c.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "hogp_report.h"
#include "spec_hogp_oracles.h"

/* Provide globals needed by headers */
extern atomic_int blued_verbose;
extern int blued_daemonized;
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

struct hogp_device {
	struct hogp_report	reports[HOGP_MAX_REPORTS];
	int			nreports;
};

static void
assert_hogp_report_contract(void)
{

	ATF_CHECK_EQ(HID_REPORT_TYPE_INPUT, BT_HOGP111_REPORT_TYPE_INPUT);
	ATF_CHECK_EQ(HID_REPORT_TYPE_OUTPUT, BT_HOGP111_REPORT_TYPE_OUTPUT);
	ATF_CHECK_EQ(HID_REPORT_TYPE_FEATURE, BT_HOGP111_REPORT_TYPE_FEATURE);
}

/* Non-normative distinct report IDs and valid ATT handle sentinels. */
#define TEST_REPORT_ID_ONE	1
#define TEST_REPORT_ID_TWO	2
#define TEST_HANDLE_ONE		0x0020
#define TEST_HANDLE_TWO		0x0025

/* ================================================================
 * hogp_find_feature_handle: single Feature report
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_single);
ATF_TC_BODY(test_hogp_find_feature_single, tc)
{
	struct hogp_device dev;
	uint16_t handle;

	assert_hogp_report_contract();
	memset(&dev, 0, sizeof(dev));

	/* Set up one Feature report with id=1, handle=0x0020 */
	dev.reports[0].value_handle = TEST_HANDLE_ONE;
	dev.reports[0].report_id = TEST_REPORT_ID_ONE;
	dev.reports[0].report_type = BT_HOGP111_REPORT_TYPE_FEATURE;
	dev.nreports = 1;

	handle = hogp_find_report_handle(dev.reports, dev.nreports,
	    TEST_REPORT_ID_ONE, BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, TEST_HANDLE_ONE);
}

/* ================================================================
 * hogp_find_feature_handle: wrong report ID returns 0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_wrong_id);
ATF_TC_BODY(test_hogp_find_feature_wrong_id, tc)
{
	struct hogp_device dev;
	uint16_t handle;

	assert_hogp_report_contract();
	memset(&dev, 0, sizeof(dev));

	dev.reports[0].value_handle = TEST_HANDLE_ONE;
	dev.reports[0].report_id = TEST_REPORT_ID_ONE;
	dev.reports[0].report_type = BT_HOGP111_REPORT_TYPE_FEATURE;
	dev.nreports = 1;

	/* Report ID 2 doesn't exist */
	handle = hogp_find_report_handle(dev.reports, dev.nreports,
	    TEST_REPORT_ID_TWO, BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: Input report not returned (wrong type)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_wrong_type);
ATF_TC_BODY(test_hogp_find_feature_wrong_type, tc)
{
	struct hogp_device dev;
	uint16_t handle;

	assert_hogp_report_contract();
	memset(&dev, 0, sizeof(dev));

	/* Input report with id=1 — should NOT be found by Feature lookup */
	dev.reports[0].value_handle = TEST_HANDLE_ONE;
	dev.reports[0].report_id = TEST_REPORT_ID_ONE;
	dev.reports[0].report_type = BT_HOGP111_REPORT_TYPE_INPUT;
	dev.nreports = 1;

	handle = hogp_find_report_handle(dev.reports, dev.nreports,
	    TEST_REPORT_ID_ONE, BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: multiple reports, find specific one
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_multiple);
ATF_TC_BODY(test_hogp_find_feature_multiple, tc)
{
	struct hogp_device dev;
	uint16_t handle;

	assert_hogp_report_contract();
	memset(&dev, 0, sizeof(dev));

	/* Input report id=0 */
	dev.reports[0].value_handle = 0x0010;
	dev.reports[0].report_id = 0;
	dev.reports[0].report_type = BT_HOGP111_REPORT_TYPE_INPUT;

	/* Output report id=0 */
	dev.reports[1].value_handle = 0x0015;
	dev.reports[1].report_id = 0;
	dev.reports[1].report_type = BT_HOGP111_REPORT_TYPE_OUTPUT;

	/* Feature report id=1 */
	dev.reports[2].value_handle = TEST_HANDLE_ONE;
	dev.reports[2].report_id = TEST_REPORT_ID_ONE;
	dev.reports[2].report_type = BT_HOGP111_REPORT_TYPE_FEATURE;

	/* Feature report id=2 */
	dev.reports[3].value_handle = TEST_HANDLE_TWO;
	dev.reports[3].report_id = TEST_REPORT_ID_TWO;
	dev.reports[3].report_type = BT_HOGP111_REPORT_TYPE_FEATURE;

	dev.nreports = 4;
	/* Find feature id=2 */
	handle = hogp_find_report_handle(dev.reports, dev.nreports,
	    TEST_REPORT_ID_TWO, BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, TEST_HANDLE_TWO);

	/* Find feature id=1 */
	handle = hogp_find_report_handle(dev.reports, dev.nreports,
	    TEST_REPORT_ID_ONE, BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, TEST_HANDLE_ONE);

	/* Input id=0 should NOT be found */
	handle = hogp_find_report_handle(dev.reports, dev.nreports, 0,
	    BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: NULL hogp returns 0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_null_hogp);
ATF_TC_BODY(test_hogp_find_feature_null_hogp, tc)
{
	uint16_t handle;

	assert_hogp_report_contract();
	handle = hogp_find_report_handle(NULL, 1, TEST_REPORT_ID_ONE,
	    BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: empty reports array
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_empty);
ATF_TC_BODY(test_hogp_find_feature_empty, tc)
{
	struct hogp_device dev;
	uint16_t handle;

	assert_hogp_report_contract();
	memset(&dev, 0, sizeof(dev));
	dev.nreports = 0;
	handle = hogp_find_report_handle(dev.reports, dev.nreports, 0,
	    BT_HOGP111_REPORT_TYPE_FEATURE);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_hogp_find_feature_single);
	ATF_TP_ADD_TC(tp, test_hogp_find_feature_wrong_id);
	ATF_TP_ADD_TC(tp, test_hogp_find_feature_wrong_type);
	ATF_TP_ADD_TC(tp, test_hogp_find_feature_multiple);
	ATF_TP_ADD_TC(tp, test_hogp_find_feature_null_hogp);
	ATF_TP_ADD_TC(tp, test_hogp_find_feature_empty);

	return (atf_no_error());
}
