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
#include "spec_extref_hogp_characteristics.h"

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
 * H6 -- Report Type disposal.
 *
 * HIDS v1.1 Table 2.7 assigns 0x01/0x02/0x03 and marks 0x00 Prohibited,
 * 0x04-0xFF reserved.  A Report characteristic whose Report Reference
 * descriptor could not be read used to be retained with Report Type 0x00: a
 * value that matches no branch, so the report was neither subscribed nor
 * routed and the keyboard was silently mute.
 *
 * GATES the fix: reverting hogp_report_type_is_valid() to accept 0x00 fails
 * here.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(report_type_prohibited_and_reserved_rejected);
ATF_TC_BODY(report_type_prohibited_and_reserved_rejected, tc)
{
	unsigned int v;

	assert_hogp_report_contract();

	ATF_CHECK_MSG(hogp_report_type_is_valid(BT_EXTREF_REPORT_TYPE_INPUT),
	    "Input Report (HIDS Table 2.7) must be accepted");
	ATF_CHECK_MSG(hogp_report_type_is_valid(BT_EXTREF_REPORT_TYPE_OUTPUT),
	    "Output Report (HIDS Table 2.7) must be accepted");
	ATF_CHECK_MSG(hogp_report_type_is_valid(BT_EXTREF_REPORT_TYPE_FEATURE),
	    "Feature Report (HIDS Table 2.7) must be accepted");

	ATF_CHECK_MSG(!hogp_report_type_is_valid(0x00),
	    "HIDS Table 2.7 marks Report Type 0x00 Prohibited");
	for (v = 0x04; v <= 0xFF; v++)
		ATF_CHECK_MSG(!hogp_report_type_is_valid((uint8_t)v),
		    "HIDS Table 2.7 reserves Report Type %#02x", v);
}

/* ================================================================
 * H6 -- an Input Report is only usable if it has a CCCD.
 *
 * HIDS Table 2.4 makes Notify mandatory for an Input Report and HOGP 4.8 has
 * the Report Host enable it through the Client Characteristic Configuration
 * descriptor, so an Input Report with no CCCD can never deliver anything.
 * hogp_subscribe() uses this count to decide whether to fail; a device where
 * every Report Reference read failed reaches zero and must not report success.
 *
 * GATES the fix.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(usable_input_report_count);
ATF_TC_BODY(usable_input_report_count, tc)
{
	struct hogp_report r[4];

	assert_hogp_report_contract();
	memset(r, 0, sizeof(r));

	/* Every Report Reference read failed: nothing classified at all. */
	ATF_CHECK_EQ_MSG(0, hogp_count_usable_input_reports(r, 4),
	    "unclassified reports must not count as usable input");

	/* Input Report with no CCCD: discovered, but unreachable. */
	r[0].report_type = BT_EXTREF_REPORT_TYPE_INPUT;
	r[0].value_handle = TEST_HANDLE_ONE;
	r[0].cccd_handle = 0;
	ATF_CHECK_EQ_MSG(0, hogp_count_usable_input_reports(r, 4),
	    "an Input Report without a CCCD cannot be subscribed");

	/* Output and Feature Reports are never input, CCCD or not. */
	r[1].report_type = BT_EXTREF_REPORT_TYPE_OUTPUT;
	r[1].cccd_handle = TEST_HANDLE_TWO;
	r[2].report_type = BT_EXTREF_REPORT_TYPE_FEATURE;
	r[2].cccd_handle = TEST_HANDLE_TWO;
	ATF_CHECK_EQ(0, hogp_count_usable_input_reports(r, 4));

	r[3].report_type = BT_EXTREF_REPORT_TYPE_INPUT;
	r[3].report_id = TEST_REPORT_ID_ONE;
	r[3].value_handle = TEST_HANDLE_TWO;
	r[3].cccd_handle = TEST_HANDLE_TWO;
	ATF_CHECK_EQ_MSG(1, hogp_count_usable_input_reports(r, 4),
	    "an Input Report with a CCCD is usable");

	ATF_CHECK_EQ(0, hogp_count_usable_input_reports(NULL, 4));
	ATF_CHECK_EQ(0, hogp_count_usable_input_reports(r, 0));
}

/* ================================================================
 * H1 -- two HID Service instances may legally collide.
 *
 * HIDS 2.5.3.2 scopes Report ID uniqueness to a service; HOGP 3.1.6 requires
 * device-wide uniqueness only of HID ISO devices, and HOGP 2.5 explicitly
 * sanctions multi-instance composite devices.  So a keyboard instance and a
 * mouse instance may both use Report ID 1 for an Output Report, and merging
 * them into one flat table routes the keyboard's LED write to the mouse.
 *
 * GATES the fix: with hogp_instance_conflicts() removed (always false), the
 * colliding and the mixed-numbering cases fail.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(instance_conflict_detection);
ATF_TC_BODY(instance_conflict_detection, tc)
{
	struct hogp_report inst_a[2], inst_b[2];

	assert_hogp_report_contract();

	/* Instance A: Input id 1, Output id 1. */
	memset(inst_a, 0, sizeof(inst_a));
	inst_a[0].report_type = BT_EXTREF_REPORT_TYPE_INPUT;
	inst_a[0].report_id = 1;
	inst_a[0].value_handle = 0x0020;
	inst_a[1].report_type = BT_EXTREF_REPORT_TYPE_OUTPUT;
	inst_a[1].report_id = 1;
	inst_a[1].value_handle = 0x0024;

	/* Instance B reuses Output id 1 -- outbound routing is ambiguous. */
	memset(inst_b, 0, sizeof(inst_b));
	inst_b[0].report_type = BT_EXTREF_REPORT_TYPE_OUTPUT;
	inst_b[0].report_id = 1;
	inst_b[0].value_handle = 0x0044;
	inst_b[0].instance = 1;
	ATF_CHECK_MSG(hogp_instance_conflicts(inst_a, 2, inst_b, 1),
	    "a reused (Report Type, Report ID) pair must be refused");

	/* Instance B uses distinct IDs -- safe to share one report table. */
	inst_b[0].report_id = 2;
	inst_b[1].report_type = BT_EXTREF_REPORT_TYPE_INPUT;
	inst_b[1].report_id = 3;
	inst_b[1].value_handle = 0x0048;
	inst_b[1].instance = 1;
	ATF_CHECK_MSG(!hogp_instance_conflicts(inst_a, 2, inst_b, 2),
	    "distinct report identities must be admitted");

	/*
	 * Instance B is unnumbered while A is numbered.  The report-ID
	 * prepend/strip of HOGP 4.8.1 is a whole-HID-device property, so
	 * sharing one vhid would mis-frame one of the two.
	 */
	memset(inst_b, 0, sizeof(inst_b));
	inst_b[0].report_type = BT_EXTREF_REPORT_TYPE_INPUT;
	inst_b[0].report_id = 0;
	inst_b[0].value_handle = 0x0048;
	inst_b[0].instance = 1;
	ATF_CHECK_MSG(hogp_instance_conflicts(inst_a, 2, inst_b, 1),
	    "mixing numbered and unnumbered instances must be refused");

	/* Nothing admitted yet: the first instance is always accepted. */
	ATF_CHECK(!hogp_instance_conflicts(NULL, 0, inst_b, 1));
	ATF_CHECK(!hogp_instance_conflicts(inst_a, 0, inst_b, 1));
}

/* ================================================================
 * H1 -- instance-scoped lookup.
 *
 * PINS the routing primitive: the same (Report Type, Report ID) in two
 * instances resolves to two different value handles.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(find_report_handle_is_instance_scoped);
ATF_TC_BODY(find_report_handle_is_instance_scoped, tc)
{
	struct hogp_report r[2];

	assert_hogp_report_contract();
	memset(r, 0, sizeof(r));
	r[0].report_type = BT_EXTREF_REPORT_TYPE_OUTPUT;
	r[0].report_id = 1;
	r[0].value_handle = TEST_HANDLE_ONE;
	r[0].instance = 0;
	r[1].report_type = BT_EXTREF_REPORT_TYPE_OUTPUT;
	r[1].report_id = 1;
	r[1].value_handle = TEST_HANDLE_TWO;
	r[1].instance = 1;

	ATF_CHECK_EQ(TEST_HANDLE_ONE, hogp_find_report_handle_instance(r, 2, 1,
	    BT_EXTREF_REPORT_TYPE_OUTPUT, 0));
	ATF_CHECK_EQ(TEST_HANDLE_TWO, hogp_find_report_handle_instance(r, 2, 1,
	    BT_EXTREF_REPORT_TYPE_OUTPUT, 1));
	ATF_CHECK_EQ(0, hogp_find_report_handle_instance(r, 2, 1,
	    BT_EXTREF_REPORT_TYPE_OUTPUT, 2));

	/*
	 * The unscoped form takes the first match; this is exactly why
	 * hogp_instance_conflicts() must keep such a table from ever forming.
	 */
	ATF_CHECK_EQ(TEST_HANDLE_ONE, hogp_find_report_handle(r, 2, 1,
	    BT_EXTREF_REPORT_TYPE_OUTPUT));
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
	ATF_TP_ADD_TC(tp, report_type_prohibited_and_reserved_rejected);
	ATF_TP_ADD_TC(tp, usable_input_report_count);
	ATF_TP_ADD_TC(tp, instance_conflict_detection);
	ATF_TP_ADD_TC(tp, find_report_handle_is_instance_scoped);

	return (atf_no_error());
}
