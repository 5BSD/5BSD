/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * P13 — HOGP boot-protocol fallback must enter Boot Protocol Mode.
 *
 * A boot-only HID device (no Report Map) notifies its Boot Input Report
 * characteristic only while in Boot Protocol Mode; the Protocol Mode
 * characteristic defaults to Report Protocol (0x01) at connection.  So
 * the boot fallback in blued_central.c:hogp_setup_boot_protocol() must
 * write Protocol Mode = Boot (0x00) to the Protocol Mode value handle
 * before subscribing to the boot report, otherwise the device stays in
 * Report mode and delivers no input (HOGP spec, Protocol Mode / Boot
 * Host requirements).
 *
 * The daemon and this test share hogp_enter_boot_protocol(); the test stubs
 * only att_write_cmd().  UUID inputs come from generated Assigned Numbers
 * oracles and mode expectations come from the separate HIDS 1.1 oracle, so
 * it detects both wrong production literals and missing/failed writes.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "att.h"
#include "gatt.h"
#include "hogp_boot.h"
#include "spec_oracles.h"

/* Capture the actual production helper's ATT Write Command. */
static struct {
	int		called;
	int		result;
	uint16_t	handle;
	uint8_t		value;
	size_t		len;
} pm_write;

int
att_write_cmd(struct att_conn *att, uint16_t handle, const void *data,
    size_t len)
{

	ATF_CHECK(att != NULL);
	pm_write.called++;
	pm_write.handle = handle;
	pm_write.len = len;
	if (data != NULL && len > 0)
		pm_write.value = *(const uint8_t *)data;
	return (pm_write.result);
}

/* ================================================================
 * Boot-only keyboard: a Boot Protocol Mode (0x00) write must be sent
 * to the Protocol Mode value handle.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(boot_keyboard_enters_boot_mode);
ATF_TC_BODY(boot_keyboard_enters_boot_mode, tc)
{
	struct att_conn att;
	static const struct gatt_char chars[] = {
		{ .value_handle = 0x0010,
		  .uuid16 = BT_ASSIGNED_UUID_PROTOCOL_MODE },
		{ .value_handle = 0x0013,
		  .uuid16 = BT_ASSIGNED_UUID_BOOT_KEYBOARD_INPUT_REPORT },
	};

	/* Handles 0x0010/0x0013 are non-normative distinguishable fixtures. */
	memset(&att, 0, sizeof(att));
	memset(&pm_write, 0, sizeof(pm_write));
	ATF_REQUIRE_EQ(0, hogp_enter_boot_protocol(&att, chars,
	    sizeof(chars) / sizeof(chars[0])));

	ATF_CHECK_EQ_MSG(1, pm_write.called,
	    "boot fallback must write the Protocol Mode characteristic");
	ATF_CHECK_EQ_MSG(0x0010, pm_write.handle,
	    "write must target the Protocol Mode value handle");
	ATF_CHECK_EQ_MSG(1, pm_write.len, "Protocol Mode is one octet");
	ATF_CHECK_EQ_MSG(BT_HIDS11_PROTOCOL_MODE_BOOT, pm_write.value,
	    "Protocol Mode must be set to Boot (0x00), not Report");
	ATF_CHECK_MSG(pm_write.value != BT_HIDS11_PROTOCOL_MODE_REPORT,
	    "must not leave the device in Report Protocol Mode");

	/* A failed ATT write must fail closed, not proceed to subscription. */
	memset(&pm_write, 0, sizeof(pm_write));
	pm_write.result = -1;
	ATF_CHECK_EQ(EIO, hogp_enter_boot_protocol(&att, chars,
	    sizeof(chars) / sizeof(chars[0])));
	ATF_CHECK_EQ(1, pm_write.called);
}

/* ================================================================
 * Boot-only mouse also enters Boot Protocol Mode.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(boot_mouse_enters_boot_mode);
ATF_TC_BODY(boot_mouse_enters_boot_mode, tc)
{
	struct att_conn att;
	static const struct gatt_char chars[] = {
		{ .value_handle = 0x0023,
		  .uuid16 = BT_ASSIGNED_UUID_BOOT_MOUSE_INPUT_REPORT },
		{ .value_handle = 0x0020,
		  .uuid16 = BT_ASSIGNED_UUID_PROTOCOL_MODE },
	};
	static const struct gatt_char missing_mode[] = {
		{ .value_handle = 0x0023,
		  .uuid16 = BT_ASSIGNED_UUID_BOOT_MOUSE_INPUT_REPORT },
	};

	/* Handles 0x0020/0x0023 are non-normative distinguishable fixtures. */
	memset(&att, 0, sizeof(att));
	memset(&pm_write, 0, sizeof(pm_write));
	ATF_REQUIRE_EQ(0, hogp_enter_boot_protocol(&att, chars,
	    sizeof(chars) / sizeof(chars[0])));
	ATF_CHECK_EQ(1, pm_write.called);
	ATF_CHECK_EQ(0x0020, pm_write.handle);
	ATF_CHECK_EQ(BT_HIDS11_PROTOCOL_MODE_BOOT, pm_write.value);

	memset(&pm_write, 0, sizeof(pm_write));
	ATF_CHECK_EQ(ENOENT, hogp_enter_boot_protocol(&att, missing_mode,
	    sizeof(missing_mode) / sizeof(missing_mode[0])));
	ATF_CHECK_EQ_MSG(0, pm_write.called,
	    "missing mandatory Protocol Mode must fail before ATT I/O");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, boot_keyboard_enters_boot_mode);
	ATF_TP_ADD_TC(tp, boot_mouse_enters_boot_mode);

	return (atf_no_error());
}
