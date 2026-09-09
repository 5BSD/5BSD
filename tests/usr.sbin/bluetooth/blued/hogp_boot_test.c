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
#include "spec_extref_hogp_characteristics.h"
#include "spec_extref_hogp_host_rules.h"

/* Capture the actual production helper's ATT Write Command. */
#define PM_WRITE_MAX	8
static struct {
	int		called;
	int		result;
	uint16_t	handle;
	uint8_t		value;
	size_t		len;
	uint16_t	handles[PM_WRITE_MAX];
	uint8_t		values[PM_WRITE_MAX];
} pm_write;

int
att_write_cmd(struct att_conn *att, uint16_t handle, const void *data,
    size_t len)
{

	ATF_CHECK(att != NULL);
	if (pm_write.called < PM_WRITE_MAX) {
		pm_write.handles[pm_write.called] = handle;
		if (data != NULL && len > 0)
			pm_write.values[pm_write.called] =
			    *(const uint8_t *)data;
	}
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

/*
 * Look a normative rule up by its stable tag in the external-reference host
 * rule table.  Assertions below cite the rule rather than restating it, so a
 * change to the transcribed spec text is visible here.
 */
static const struct bt_extref_hogp_rule *
boot_rule(const char *id)
{
	size_t i;

	for (i = 0; i < BT_EXTREF_HOGP_NRULES; i++)
		if (strcmp(bt_extref_hogp_rules[i].id, id) == 0)
			return (&bt_extref_hogp_rules[i]);
	return (NULL);
}

/* ================================================================
 * H4 -- "for each HID Service on the GATT Server".
 *
 * A composite device exposes one Protocol Mode characteristic per HID Service
 * (HIDS 2.4 permits only one per service, so the multiplicity is across
 * services).  hogp_enter_boot_protocol_handles() is the form the caller uses
 * with handles accumulated across every discovered instance; the old caller
 * passed the primary instance's characteristic array only, so a second HID
 * Service stayed in Report Protocol Mode and its boot characteristics were
 * dead.
 *
 * GATES the fix: writing only handles[0] fails here.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(boot_mode_written_to_every_hid_service);
ATF_TC_BODY(boot_mode_written_to_every_hid_service, tc)
{
	struct att_conn att;
	/* Two HID Service instances; non-normative distinguishable handles. */
	static const uint16_t handles[] = { 0x0010, 0x0030 };
	const struct bt_extref_hogp_rule *rule;
	int i;

	rule = boot_rule("PROTOMODE-BOOT-WRITE");
	ATF_REQUIRE_MSG(rule != NULL, "missing PROTOMODE-BOOT-WRITE rule");
	ATF_CHECK_EQ_MSG(BT_EXTREF_HOGP_ROLE_BOOT_HOST, rule->role,
	    "the Protocol Mode write is a Boot Host obligation");
	ATF_CHECK_EQ_MSG(BT_EXTREF_REQ_SHALL, rule->level,
	    "%s is a shall", rule->id);

	memset(&att, 0, sizeof(att));
	memset(&pm_write, 0, sizeof(pm_write));
	ATF_REQUIRE_EQ(0, hogp_enter_boot_protocol_handles(&att, handles,
	    (int)(sizeof(handles) / sizeof(handles[0]))));

	ATF_CHECK_EQ_MSG(2, pm_write.called,
	    "Boot Protocol Mode must be written to EVERY HID Service "
	    "instance: %s", rule->text);
	for (i = 0; i < 2; i++) {
		ATF_CHECK_EQ_MSG(handles[i], pm_write.handles[i],
		    "write %d targeted the wrong Protocol Mode handle", i);
		ATF_CHECK_EQ_MSG(BT_EXTREF_PROTOCOL_MODE_BOOT,
		    pm_write.values[i], "write %d must carry Boot mode", i);
	}

	/* A failed write on the SECOND instance must fail closed too. */
	memset(&pm_write, 0, sizeof(pm_write));
	pm_write.result = -1;
	ATF_CHECK_EQ(EIO, hogp_enter_boot_protocol_handles(&att, handles, 2));

	/* No Protocol Mode characteristic anywhere: fail before any I/O. */
	memset(&pm_write, 0, sizeof(pm_write));
	ATF_CHECK_EQ(ENOENT, hogp_enter_boot_protocol_handles(&att, handles,
	    0));
	ATF_CHECK_EQ(0, pm_write.called);
	ATF_CHECK_EQ(EINVAL, hogp_enter_boot_protocol_handles(NULL, handles,
	    2));
}

/* ================================================================
 * H4 -- the accumulation the caller must perform.
 *
 * hogp_collect_protocol_mode_handles() appends, so the discovery loop can
 * call it once per HID Service instance and hand the whole list to the Boot
 * Host write.
 *
 * GATES the fix: a collector that reset *nout per call, or a caller that only
 * ever saw one instance, yields one handle here instead of two.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(protocol_mode_handles_accumulate_across_instances);
ATF_TC_BODY(protocol_mode_handles_accumulate_across_instances, tc)
{
	static const struct gatt_char inst_a[] = {
		{ .value_handle = 0x0010,
		  .uuid16 = BT_ASSIGNED_UUID_PROTOCOL_MODE },
		{ .value_handle = 0x0013,
		  .uuid16 = BT_ASSIGNED_UUID_BOOT_KEYBOARD_INPUT_REPORT },
	};
	static const struct gatt_char inst_b[] = {
		{ .value_handle = 0x0033,
		  .uuid16 = BT_ASSIGNED_UUID_BOOT_MOUSE_INPUT_REPORT },
		{ .value_handle = 0x0030,
		  .uuid16 = BT_ASSIGNED_UUID_PROTOCOL_MODE },
	};
	uint16_t out[HOGP_MAX_PROTOCOL_MODE_HANDLES];
	uint16_t one[1];
	int n = 0;

	memset(out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, hogp_collect_protocol_mode_handles(inst_a,
	    (int)(sizeof(inst_a) / sizeof(inst_a[0])), out,
	    (int)(sizeof(out) / sizeof(out[0])), &n));
	ATF_CHECK_EQ(1, n);
	ATF_REQUIRE_EQ(0, hogp_collect_protocol_mode_handles(inst_b,
	    (int)(sizeof(inst_b) / sizeof(inst_b[0])), out,
	    (int)(sizeof(out) / sizeof(out[0])), &n));
	ATF_CHECK_EQ_MSG(2, n,
	    "the second HID Service instance's Protocol Mode handle was lost");
	ATF_CHECK_EQ(0x0010, out[0]);
	ATF_CHECK_EQ(0x0030, out[1]);

	/* Overflow is reported, not silent, and does not lose what fits. */
	n = 0;
	ATF_CHECK_EQ(0, hogp_collect_protocol_mode_handles(inst_a, 2, one, 1,
	    &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(ENOSPC, hogp_collect_protocol_mode_handles(inst_b, 2, one,
	    1, &n));
	ATF_CHECK_EQ(1, n);
}

/* ================================================================
 * H5 -- Boot Host and Report Host are mutually exclusive.
 *
 * HOGP 2 lines 575/577 forbid being both, in both directions, and 4.11 line
 * 1189 says a Report Host has no reason to touch Protocol Mode at all.  The
 * daemon used to write Report Protocol Mode (0x01) from hogp_process_service()
 * and then Boot Protocol Mode (0x00) from the boot fallback on the same
 * connection.  The boot helper is where the Boot Host role is expressed: it
 * must never emit the Report value.
 *
 * GATES the fix at this layer; the companion assertion that no 0x01 is written
 * during discovery is in blued_role_test.c (protocol_mode_is_never_written_in
 * _report_role), which links the real hogp_process_service().
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(boot_host_never_writes_report_protocol_mode);
ATF_TC_BODY(boot_host_never_writes_report_protocol_mode, tc)
{
	struct att_conn att;
	static const uint16_t handles[] = { 0x0010, 0x0030 };
	const struct bt_extref_hogp_rule *excl_boot, *excl_report, *noreq;
	int i;

	excl_boot = boot_rule("ROLE-EXCL-BOOT");
	excl_report = boot_rule("ROLE-EXCL-REPORT");
	noreq = boot_rule("PROTOMODE-REPORT-NOREQ");
	ATF_REQUIRE(excl_boot != NULL && excl_report != NULL && noreq != NULL);
	ATF_CHECK_EQ_MSG(BT_EXTREF_REQ_SHALL_NOT, excl_boot->level,
	    "%s: %s", excl_boot->id, excl_boot->text);
	ATF_CHECK_EQ_MSG(BT_EXTREF_REQ_SHALL_NOT, excl_report->level,
	    "%s: %s", excl_report->id, excl_report->text);
	ATF_CHECK_EQ_MSG(BT_EXTREF_REQ_NO_REQUIREMENT, noreq->level,
	    "%s: %s", noreq->id, noreq->text);
	ATF_CHECK_EQ_MSG(BT_EXTREF_HOGP_ROLE_REPORT_HOST, noreq->role,
	    "the no-requirement clause is about the Report Host");

	memset(&att, 0, sizeof(att));
	memset(&pm_write, 0, sizeof(pm_write));
	ATF_REQUIRE_EQ(0, hogp_enter_boot_protocol_handles(&att, handles, 2));
	for (i = 0; i < pm_write.called; i++)
		ATF_CHECK_MSG(pm_write.values[i] !=
		    BT_EXTREF_PROTOCOL_MODE_REPORT,
		    "the Boot Host path wrote Report Protocol Mode (%s)",
		    excl_boot->text);

	/* The default the device already holds is Report mode (HIDS 2.4.1.1). */
	ATF_CHECK_EQ(BT_EXTREF_PROTOCOL_MODE_REPORT,
	    BT_EXTREF_PROTOCOL_MODE_DEFAULT);
	ATF_CHECK_EQ(HID_PROTOCOL_REPORT, BT_EXTREF_PROTOCOL_MODE_REPORT);
	ATF_CHECK_EQ(HID_PROTOCOL_BOOT, BT_EXTREF_PROTOCOL_MODE_BOOT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, boot_keyboard_enters_boot_mode);
	ATF_TP_ADD_TC(tp, boot_mouse_enters_boot_mode);
	ATF_TP_ADD_TC(tp, boot_mode_written_to_every_hid_service);
	ATF_TP_ADD_TC(tp, protocol_mode_handles_accumulate_across_instances);
	ATF_TP_ADD_TC(tp, boot_host_never_writes_report_protocol_mode);

	return (atf_no_error());
}
