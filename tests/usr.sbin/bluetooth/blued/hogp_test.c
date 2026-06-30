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

/* Provide globals needed by headers */
extern atomic_int blued_verbose;
extern int blued_daemonized;
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/*
 * Report type constants and HOGP structures from blued.c.
 * Defined here so the test doesn't need to link blued.o.
 */
#define HID_REPORT_TYPE_INPUT	0x01
#define HID_REPORT_TYPE_OUTPUT	0x02
#define HID_REPORT_TYPE_FEATURE	0x03

struct hogp_report {
	uint16_t	value_handle;
	uint16_t	cccd_handle;
	uint8_t		report_id;
	uint8_t		report_type;
};

#define HOGP_MAX_REPORTS	16

struct hogp_device {
	char			_pad[256]; /* placeholder for att_conn etc. */
	struct hogp_report	reports[HOGP_MAX_REPORTS];
	int			nreports;
};

/*
 * Minimal blued_conn for testing — only hogp pointer matters.
 */
struct blued_conn {
	struct hogp_device	*hogp;
};

/*
 * hogp_find_feature_handle — copied from blued.c for testing
 * without linking the entire daemon.
 */
static uint16_t
hogp_find_feature_handle(struct blued_conn *conn, uint8_t report_id)
{
	struct hogp_device *dev;
	int i;

	if (conn == NULL || conn->hogp == NULL)
		return (0);
	dev = conn->hogp;

	for (i = 0; i < dev->nreports; i++) {
		if (dev->reports[i].report_type == HID_REPORT_TYPE_FEATURE &&
		    dev->reports[i].report_id == report_id)
			return (dev->reports[i].value_handle);
	}
	return (0);
}

/* ================================================================
 * hogp_find_feature_handle: single Feature report
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_single);
ATF_TC_BODY(test_hogp_find_feature_single, tc)
{
	struct blued_conn conn;
	struct hogp_device dev;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));

	/* Set up one Feature report with id=1, handle=0x0020 */
	dev.reports[0].value_handle = 0x0020;
	dev.reports[0].report_id = 1;
	dev.reports[0].report_type = 0x03;  /* HID_REPORT_TYPE_FEATURE */
	dev.nreports = 1;

	conn.hogp = &dev;

	handle = hogp_find_feature_handle(&conn, 1);
	ATF_CHECK_EQ(handle, 0x0020);
}

/* ================================================================
 * hogp_find_feature_handle: wrong report ID returns 0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_wrong_id);
ATF_TC_BODY(test_hogp_find_feature_wrong_id, tc)
{
	struct blued_conn conn;
	struct hogp_device dev;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));

	dev.reports[0].value_handle = 0x0020;
	dev.reports[0].report_id = 1;
	dev.reports[0].report_type = 0x03;
	dev.nreports = 1;

	conn.hogp = &dev;

	/* Report ID 2 doesn't exist */
	handle = hogp_find_feature_handle(&conn, 2);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: Input report not returned (wrong type)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_wrong_type);
ATF_TC_BODY(test_hogp_find_feature_wrong_type, tc)
{
	struct blued_conn conn;
	struct hogp_device dev;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));

	/* Input report with id=1 — should NOT be found by Feature lookup */
	dev.reports[0].value_handle = 0x0020;
	dev.reports[0].report_id = 1;
	dev.reports[0].report_type = 0x01;  /* HID_REPORT_TYPE_INPUT */
	dev.nreports = 1;

	conn.hogp = &dev;

	handle = hogp_find_feature_handle(&conn, 1);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: multiple reports, find specific one
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_multiple);
ATF_TC_BODY(test_hogp_find_feature_multiple, tc)
{
	struct blued_conn conn;
	struct hogp_device dev;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));

	/* Input report id=0 */
	dev.reports[0].value_handle = 0x0010;
	dev.reports[0].report_id = 0;
	dev.reports[0].report_type = 0x01;

	/* Output report id=0 */
	dev.reports[1].value_handle = 0x0015;
	dev.reports[1].report_id = 0;
	dev.reports[1].report_type = 0x02;

	/* Feature report id=1 */
	dev.reports[2].value_handle = 0x0020;
	dev.reports[2].report_id = 1;
	dev.reports[2].report_type = 0x03;

	/* Feature report id=2 */
	dev.reports[3].value_handle = 0x0025;
	dev.reports[3].report_id = 2;
	dev.reports[3].report_type = 0x03;

	dev.nreports = 4;
	conn.hogp = &dev;

	/* Find feature id=2 */
	handle = hogp_find_feature_handle(&conn, 2);
	ATF_CHECK_EQ(handle, 0x0025);

	/* Find feature id=1 */
	handle = hogp_find_feature_handle(&conn, 1);
	ATF_CHECK_EQ(handle, 0x0020);

	/* Input id=0 should NOT be found */
	handle = hogp_find_feature_handle(&conn, 0);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: NULL hogp returns 0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_null_hogp);
ATF_TC_BODY(test_hogp_find_feature_null_hogp, tc)
{
	struct blued_conn conn;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	conn.hogp = NULL;

	handle = hogp_find_feature_handle(&conn, 1);
	ATF_CHECK_EQ(handle, 0);
}

/* ================================================================
 * hogp_find_feature_handle: empty reports array
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hogp_find_feature_empty);
ATF_TC_BODY(test_hogp_find_feature_empty, tc)
{
	struct blued_conn conn;
	struct hogp_device dev;
	uint16_t handle;

	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));
	dev.nreports = 0;
	conn.hogp = &dev;

	handle = hogp_find_feature_handle(&conn, 0);
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
