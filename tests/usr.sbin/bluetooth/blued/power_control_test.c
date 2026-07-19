/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Conformance tests for LE Power Control / Path Loss Monitoring
 * (Bluetooth Core Specification 5.2).
 *
 * Two layers are exercised:
 *
 *   Spec section numbers follow the Core Spec 6.3 oracle: the LE Power
 *   Control commands are §7.8.117 (Enhanced Read TX Power Level, OCF 0x0076),
 *   §7.8.118 (Read Remote TX Power Level, 0x0077), §7.8.119 (Set Path Loss
 *   Reporting Parameters, 0x0078), §7.8.120 (Set Path Loss Reporting Enable,
 *   0x0079) and §7.8.121 (Set TX Power Reporting Enable, 0x007A).
 *
 *   1. Command-encoder conformance.  The BT 5.2 power-control encoders in
 *      hci_conn.c reach the controller through hci_devreq_logged() ->
 *      bt_devreq() (libbluetooth).  We interpose bt_devreq at link time
 *      (-Wl,--wrap=bt_devreq) exactly as hci_devreq_mock_test.c does, but
 *      the wrap here ALSO captures the outbound command (opcode, clen and
 *      the command-parameter bytes) so each encoder's wire encoding can be
 *      checked octet-for-octet against the spec command layout, then feeds
 *      a test-controlled Command Complete / Command Status back so the
 *      success / rejection / transport arms are all driven.
 *
 *   2. Event representation.  The LE Path Loss Threshold (§7.7.65.32) and
 *      LE Transmit Power Reporting (§7.7.65.33) meta-event structs in
 *      ng_hci.h are overlaid on hand-encoded spec event bytes and their
 *      fields checked.
 *
 * Oracle: every expected byte layout is hand-encoded from the Bluetooth
 * Core Specification Vol 4 Part E (commands) / Part E §7.7.65 (events),
 * cited per assertion, never from captured implementation output.
 *
 * FINDINGS surfaced by this file (see the marked cases and the report):
 *
 *   F1. (RESOLVED) The power-control encoders now pre-validate their
 *       enumerated parameters before any controller I/O: an out-of-range PHY
 *       (§7.8.117/.118 define only 0x01..0x04), a High_Threshold < Low_Threshold
 *       ordering (§7.8.119 lists Low_Threshold > High_Threshold as Invalid HCI
 *       Command Parameters, 0x12), and an out-of-range enable flag (§7.8.120/.121
 *       define only 0x00/0x01) are rejected with EINVAL.  The boundary cases
 *       below assert that spec-correct rejection and now pass as live checks.
 *
 *   F2. (RESOLVED) blued_event.c formerly dispatched LE Meta subevents
 *       0x01/0x03/0x04/0x05/0x0A/0x0C only and silently dropped subevent
 *       0x20 (Path Loss Threshold) and 0x21 (Transmit Power Reporting).
 *       The daemon now decodes both through the shared seam
 *       blued_parse_le_meta_event() (blued_le_meta.h); power_events_parsed
 *       drives that real decoder and checks the extracted fields
 *       (§7.7.65.32-33).
 *
 *   F3. Minor: an hci_conn.c inline comment (in
 *       hci_le_enhanced_read_tx_power_level) cites §7.8.116 for the PHY
 *       enumeration and another (in hci_le_read_remote_tx_power_level) cites
 *       §7.8.117; the Core Spec 6.3 oracle numbers those commands §7.8.117 and
 *       §7.8.118 respectively (the function-header comments there are correct).
 *       The OCFs (0x0076 / 0x0077) are authoritative, and every byte-layout
 *       assertion here keys off the OCF, so this is a source-comment nit only.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "blued_le_meta.h"
#include "spec_power_control_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Any non-negative fd works: __wrap_bt_devreq ignores it. */
#define FD	3

/* ================================================================
 * The --wrap seam: captures the outbound command and returns a
 * test-controlled Command Complete / Command Status.
 * ================================================================ */
static struct {
	int		fail;		/* nonzero -> return -1, errno=fail_errno */
	int		fail_errno;
	uint8_t		payload[64];	/* return params, status byte first */
	size_t		payload_len;

	/* Captured request (populated on every call). */
	int		called;
	uint16_t	opcode;
	uint8_t		cparam[64];
	size_t		clen;
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	W.called++;
	W.opcode = r->opcode;
	W.clen = r->clen;
	memset(W.cparam, 0, sizeof(W.cparam));
	if (r->cparam != NULL && r->clen > 0) {
		size_t n = r->clen < sizeof(W.cparam) ? r->clen :
		    sizeof(W.cparam);
		memcpy(W.cparam, r->cparam, n);
	}

	if (W.fail) {
		errno = W.fail_errno;
		return (-1);
	}
	/* Mirror bt_devreq's Command Complete contract: copy up to rlen
	 * bytes of return parameters into the caller-supplied rp buffer. */
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = W.payload_len < r->rlen ? W.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, W.payload, n);
	}
	return (0);
}

static void
mock_reset(void)
{
	memset(&W, 0, sizeof(W));
}

/* Controller returns a Command Complete carrying return-parameter bytes. */
static void
mock_ok_bytes(const void *p, size_t n)
{
	mock_reset();
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

/* Controller accepts: status 0x00, no further return parameters. */
static void
mock_ok(void)
{
	uint8_t st = BT_POWER_SPEC_STATUS_SUCCESS;

	mock_ok_bytes(&st, 1);
}

/* Controller rejects with status 0x0C = Command Disallowed
 * (Core Spec Vol 1 Part F §1.3 error code table). */
static void
mock_status_bad(void)
{
	uint8_t st = BT_POWER_SPEC_STATUS_COMMAND_DISALLOWED;

	mock_ok_bytes(&st, 1);
}

/* Transport failure: bt_devreq itself fails. */
static void
mock_xport_fail(int e)
{
	mock_reset();
	W.fail = 1;
	W.fail_errno = e;
}

/* Three-arm success/reject/transport coverage for a status-only command. */
#define CHECK_OK(call)		do {					\
	mock_ok();							\
	ATF_CHECK_EQ_MSG(0, (call), "success arm: expected 0");		\
} while (0)

#define CHECK_BAD(call)		do {					\
	mock_status_bad();						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "status!=0 arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "status!=0 arm: expected EIO");	\
} while (0)

#define CHECK_XPORT(call)	do {					\
	mock_xport_fail(EIO);						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "transport arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "transport arm: expected EIO");	\
} while (0)

#define CHECK_ALL(call)		do {					\
	CHECK_OK(call);							\
	CHECK_BAD(call);						\
	CHECK_XPORT(call);						\
} while (0)

/* Compare against a complete opcode from the independent specification oracle. */
#define CHECK_OPCODE(expected_opcode) \
	ATF_CHECK_EQ((expected_opcode), W.opcode)

/* ================================================================
 * §7.8.117  LE Enhanced Read Transmit Power Level  (OCF 0x0076)
 *   CP: Connection_Handle(2 LE) | PHY(1)                     -> clen 3
 *   RP: Status(1) | Connection_Handle(2) | PHY(1) |
 *       Current_TX_Power_Level(int8) | Max_TX_Power_Level(int8)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(enh_read_tx_power);
ATF_TC_BODY(enh_read_tx_power, tc)
{
	/* current = -20 dBm (0xEC), max = +10 dBm (0x0A) */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x02, 0xEC, 0x0A };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x02, &cur, &max));

	/* Command encoding conformance (§7.8.117). */
	CHECK_OPCODE(BT_POWER_SPEC_OP_ENH_READ_TX_POWER);
	ATF_REQUIRE_EQ(sizeof(bt_power_spec_cp_handle40_phy2m), W.clen);
	ATF_CHECK_EQ(0, memcmp(W.cparam, bt_power_spec_cp_handle40_phy2m,
	    W.clen));

	/* Return-parameter extraction: int8 dBm (§7.8.117). */
	ATF_CHECK_EQ(-20, cur);
	ATF_CHECK_EQ(10, max);

	CHECK_BAD(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x02,
	    &cur, &max));
	CHECK_XPORT(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x02,
	    &cur, &max));
}

/* ================================================================
 * §7.8.118  LE Read Remote Transmit Power Level  (OCF 0x0077)
 *   CP: Connection_Handle(2 LE) | PHY(1)                     -> clen 3
 *   Returns Command Status; the result arrives later via the
 *   LE Transmit Power Reporting event (§7.7.65.33).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_remote_tx_power);
ATF_TC_BODY(read_remote_tx_power, tc)
{

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));

	CHECK_OPCODE(BT_POWER_SPEC_OP_READ_REMOTE_TX_POWER);
	ATF_REQUIRE_EQ(sizeof(bt_power_spec_cp_handle40_phy1m), W.clen);
	ATF_CHECK_EQ(0, memcmp(W.cparam, bt_power_spec_cp_handle40_phy1m,
	    W.clen));

	CHECK_BAD(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));
	CHECK_XPORT(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));
}

/* ================================================================
 * §7.8.119  LE Set Path Loss Reporting Parameters  (OCF 0x0078)
 *   CP: Connection_Handle(2 LE) | High_Threshold(1) |
 *       High_Hysteresis(1) | Low_Threshold(1) | Low_Hysteresis(1) |
 *       Min_Time_Spent(2 LE)                                 -> clen 8
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_path_loss_params);
ATF_TC_BODY(set_path_loss_params, tc)
{

	mock_ok();
	/* high=0x40(64dB) hyst=0x04 low=0x10(16dB) hyst=0x04 min=0x000A */
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));

	CHECK_OPCODE(BT_POWER_SPEC_OP_SET_PATH_LOSS_PARAMS);
	ATF_REQUIRE_EQ(sizeof(bt_power_spec_cp_path_loss), W.clen);
	ATF_CHECK_EQ(0, memcmp(W.cparam, bt_power_spec_cp_path_loss, W.clen));

	CHECK_BAD(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));
	CHECK_XPORT(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));
}

/* ================================================================
 * §7.8.120  LE Set Path Loss Reporting Enable  (OCF 0x0079)
 *   CP: Connection_Handle(2 LE) | Enable(1)                  -> clen 3
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_path_loss_enable);
ATF_TC_BODY(set_path_loss_enable, tc)
{

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1));

	CHECK_OPCODE(BT_POWER_SPEC_OP_SET_PATH_LOSS_ENABLE);
	ATF_CHECK_EQ(3, W.clen);
	ATF_CHECK_EQ(0x40, W.cparam[0]);
	ATF_CHECK_EQ(0x00, W.cparam[1]);
	ATF_CHECK_EQ(0x01, W.cparam[2]);	/* enable */

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_enable(FD, 0x0040, 0));
	ATF_CHECK_EQ(0x00, W.cparam[2]);	/* disable */

	CHECK_BAD(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1));
	CHECK_XPORT(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1));
}

/* ================================================================
 * §7.8.121  LE Set Transmit Power Reporting Enable  (OCF 0x007A)
 *   CP: Connection_Handle(2 LE) | Local_Enable(1) |
 *       Remote_Enable(1)                                     -> clen 4
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_tx_power_reporting_enable);
ATF_TC_BODY(set_tx_power_reporting_enable, tc)
{

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 0));

	CHECK_OPCODE(BT_POWER_SPEC_OP_SET_TX_POWER_ENABLE);
	ATF_CHECK_EQ(4, W.clen);
	ATF_CHECK_EQ(0x40, W.cparam[0]);
	ATF_CHECK_EQ(0x00, W.cparam[1]);
	ATF_CHECK_EQ(0x01, W.cparam[2]);	/* local_enable */
	ATF_CHECK_EQ(0x00, W.cparam[3]);	/* remote_enable */

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_tx_power_reporting_enable(FD, 0x0040, 0, 1));
	ATF_CHECK_EQ(0x00, W.cparam[2]);
	ATF_CHECK_EQ(0x01, W.cparam[3]);

	CHECK_BAD(hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 1));
	CHECK_XPORT(hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 1));
}

/* ================================================================
 * Parameter boundary / validation.
 *
 * The encoders pre-validate their enumerated parameters (see F1, RESOLVED).
 * Each case asserts the spec-correct behaviour: reject an out-of-range value
 * with EINVAL *before* any controller I/O (W.called == 0).
 * ================================================================ */

/*
 * §7.8.117/.118: PHY is an enumerated field, valid values 0x01..0x04
 * (1M / 2M / Coded S=8 / Coded S=2).  0x00 and 0x05+ are invalid and
 * must be rejected before the command is issued.
 */
ATF_TC_WITHOUT_HEAD(boundary_phy_range);
ATF_TC_BODY(boundary_phy_range, tc)
{
	int8_t cur = 0, max = 0;

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x00, &cur, &max));		/* PHY 0 invalid */
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x05, &cur, &max));		/* PHY 5 invalid */
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_remote_tx_power_level(FD, 0x0040, 0x00));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");
}

/*
 * §7.8.119 (path loss params): High_Threshold must be >= Low_Threshold
 * for the low/normal/high zones to be well ordered.  A high < low pair
 * is a malformed configuration and must be rejected before I/O.
 */
ATF_TC_WITHOUT_HEAD(boundary_path_loss_threshold_order);
ATF_TC_BODY(boundary_path_loss_threshold_order, tc)
{

	mock_ok();
	errno = 0;
	/* high=0x10(16dB) < low=0x40(64dB): inverted zone bounds. */
	ATF_CHECK_EQ(-1, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x10, 0x04, 0x40, 0x04, 0x000A));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");
}

/*
 * §7.8.120/.121: the Enable flags are booleans; values other than
 * 0x00/0x01 are reserved for future use and must be rejected.
 */
ATF_TC_WITHOUT_HEAD(boundary_enable_flags);
ATF_TC_BODY(boundary_enable_flags, tc)
{

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_path_loss_reporting_enable(FD, 0x0040,
	    0x02));			/* reserved */
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0xFF, 0x00));		/* reserved local flag */
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");

	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0x00, 0x02));		/* reserved remote flag */
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");
}

/* ================================================================
 * §7.7.65.32  LE Path Loss Threshold event
 *   Subevent_Code(0x20) | Connection_Handle(2 LE) |
 *   Current_Path_Loss(1, dB) | Zone_Entered(1: 0=low,1=mid,2=high)
 *
 * The ng_hci.h event struct begins after the subevent code (the
 * subevent byte is the meta-event dispatch key, not part of the ep).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(path_loss_threshold_event_layout);
ATF_TC_BODY(path_loss_threshold_event_layout, tc)
{
	/* handle 0x0040, current path loss 0x2A (42 dB), zone 2 (high). */
	uint8_t body[4] = { 0x40, 0x00, 0x2A, 0x02 };
	ng_hci_le_path_loss_threshold_ep ep;

	ATF_CHECK_EQ_MSG(sizeof(ep), sizeof(body),
	    "ng_hci_le_path_loss_threshold_ep must be 4 bytes (§7.7.65.32)");
	memcpy(&ep, body, sizeof(ep));

	ATF_CHECK_EQ(0x0040, le16toh(ep.connection_handle));
	ATF_CHECK_EQ(42, ep.current_path_loss);
	ATF_CHECK_EQ(2, ep.zone_entered);	/* high zone */
}

/* ================================================================
 * §7.7.65.33  LE Transmit Power Reporting event
 *   Subevent_Code(0x21) | Status(1) | Connection_Handle(2 LE) |
 *   Reason(1: 0=local change,1=remote change,2=Read cmd completed) |
 *   PHY(1) | TX_Power_Level(int8, dBm) |
 *   TX_Power_Level_Flag(1: bit0=min,bit1=max) | Delta(int8, dB)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(tx_power_reporting_event_layout);
ATF_TC_BODY(tx_power_reporting_event_layout, tc)
{
	/*
	 * status ok, handle 0x0040, reason 1 (remote autonomous change),
	 * PHY 1 (1M), tx power -30 dBm (0xE2), flag 0x01 (at minimum),
	 * delta +5 dB (0x05).
	 *
	 * Reason 0x01 (remote change) is used here, not 0x02 (Read Remote
	 * command completed): Core Spec Vol 4 Part E §7.7.65.33 mandates that
	 * "When this event is generated with Reason set to 0x02, Delta shall
	 * be set to zero" -- there is no local change to report.  A nonzero
	 * Delta is only spec-faithful for an actual power change (Reason
	 * 0x00/0x01), so the signed-delta byte-layout check rides on Reason
	 * 0x01.
	 */
	uint8_t body[8] = { 0x00, 0x40, 0x00, 0x01, 0x01, 0xE2, 0x01, 0x05 };
	ng_hci_le_tx_power_reporting_ep ep;

	ATF_CHECK_EQ_MSG(sizeof(ep), sizeof(body),
	    "ng_hci_le_tx_power_reporting_ep must be 8 bytes (§7.7.65.33)");
	memcpy(&ep, body, sizeof(ep));

	ATF_CHECK_EQ(0x00, ep.status);
	ATF_CHECK_EQ(0x0040, le16toh(ep.connection_handle));
	ATF_CHECK_EQ(1, ep.reason);		/* remote autonomous change */
	ATF_CHECK_EQ(1, ep.phy);		/* 1M */
	ATF_CHECK_EQ(-30, (int8_t)ep.tx_power_level);
	ATF_CHECK_EQ(0x01, ep.tx_power_level_flag);	/* at minimum */
	ATF_CHECK_EQ(5, (int8_t)ep.delta);
}

/* ================================================================
 * §7.7.65.32-33  Daemon dispatch of the LE Power Control meta-events.
 *
 * This was FINDING F2 (the daemon enabled subevents 0x20/0x21 in the LE
 * event mask but never parsed them).  blued now decodes them through the
 * shared seam blued_parse_le_meta_event() (blued_le_meta.h), which
 * blued_event.c drives on the live HCI socket.  This case feeds the same
 * decoder the crafted spec event bytes and asserts the fields the daemon
 * extracts, so it is now a real conformance test rather than a recorded
 * gap.  Wire framing: [type(0x04) | HCI_LE_Meta(0x3E) | Param_Len |
 * Subevent | parameters] (Core Spec Vol 4 Part E §5.4.4, §7.7.65).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(power_events_parsed);
ATF_TC_BODY(power_events_parsed, tc)
{
	struct blued_le_meta_report rep;

	/*
	 * §7.7.65.32 LE Path Loss Threshold (subevent 0x20):
	 * Connection_Handle(2 LE)=0x0040 | Current_Path_Loss(1)=42dB |
	 * Zone_Entered(1)=2 (high).  Param_Total_Length = 5.
	 */
	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(
	    bt_power_spec_path_loss_event, sizeof(bt_power_spec_path_loss_event),
	    &rep), "0x20 must be consumed, not dropped");
	ATF_CHECK_EQ(BT_POWER_SPEC_SUBEVENT_PATH_LOSS, rep.subevent);
	ATF_CHECK_EQ(0x0040, rep.connection_handle);
	ATF_CHECK_EQ(42, rep.current_path_loss);
	ATF_CHECK_EQ(2, rep.zone_entered);	/* high zone */

	/*
	 * §7.7.65.33 LE Transmit Power Reporting (subevent 0x21):
	 * Status(1)=0 | Connection_Handle(2 LE)=0x0040 | Reason(1)=1 (remote
	 * autonomous change) | PHY(1)=1 (1M) | TX_Power_Level(int8)=-30dBm |
	 * TX_Power_Level_Flag(1)=0x01 (at minimum) | Delta(int8)=+5dB.
	 * Param_Total_Length = 9.
	 *
	 * Reason 0x01 (not 0x02) so the nonzero Delta is spec-faithful: Core
	 * Spec Vol 4 Part E §7.7.65.33 requires Delta == 0 when Reason == 0x02.
	 */
	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(
	    bt_power_spec_tx_power_event, sizeof(bt_power_spec_tx_power_event),
	    &rep), "0x21 must be consumed, not dropped");
	ATF_CHECK_EQ(BT_POWER_SPEC_SUBEVENT_TX_POWER, rep.subevent);
	ATF_CHECK(rep.has_status);
	ATF_CHECK_EQ(0x00, rep.status);
	ATF_CHECK_EQ(0x0040, rep.connection_handle);
	ATF_CHECK_EQ(1, rep.reason);		/* remote autonomous change */
	ATF_CHECK_EQ(1, rep.phy);		/* 1M */
	ATF_CHECK_EQ(-30, rep.tx_power_level);
	ATF_CHECK_EQ(0x01, rep.tx_power_level_flag);	/* at minimum */
	ATF_CHECK_EQ(5, rep.delta);

	/* A truncated power event is rejected as malformed (not misread). */
	ATF_CHECK_MSG(blued_parse_le_meta_event(bt_power_spec_tx_power_event,
	    sizeof(bt_power_spec_tx_power_event) - 1, &rep) < 0,
	    "short 0x21 must be flagged malformed");

	/* Closed Core 5.2 fields must not surface reserved controller values. */
	{
		uint8_t bad_path[sizeof(bt_power_spec_path_loss_event)];
		uint8_t bad_power[sizeof(bt_power_spec_tx_power_event)];

		memcpy(bad_path, bt_power_spec_path_loss_event, sizeof(bad_path));
		bad_path[7] = 0x03;	/* reserved Zone_Entered */
		ATF_CHECK_EQ(-1, blued_parse_le_meta_event(bad_path,
		    sizeof(bad_path), &rep));

		memcpy(bad_power, bt_power_spec_tx_power_event,
		    sizeof(bad_power));
		bad_power[10] = 0x80;	/* reserved flag bit */
		ATF_CHECK_EQ(-1, blued_parse_le_meta_event(bad_power,
		    sizeof(bad_power), &rep));
		memcpy(bad_power, bt_power_spec_tx_power_event,
		    sizeof(bad_power));
		bad_power[7] = 0x03;	/* reserved Reason */
		ATF_CHECK_EQ(-1, blued_parse_le_meta_event(bad_power,
		    sizeof(bad_power), &rep));
	}
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Command-encoder conformance (§7.8.117-121). */
	ATF_TP_ADD_TC(tp, enh_read_tx_power);
	ATF_TP_ADD_TC(tp, read_remote_tx_power);
	ATF_TP_ADD_TC(tp, set_path_loss_params);
	ATF_TP_ADD_TC(tp, set_path_loss_enable);
	ATF_TP_ADD_TC(tp, set_tx_power_reporting_enable);

	/* Parameter boundary tests (FINDING F1). */
	ATF_TP_ADD_TC(tp, boundary_phy_range);
	ATF_TP_ADD_TC(tp, boundary_path_loss_threshold_order);
	ATF_TP_ADD_TC(tp, boundary_enable_flags);

	/* Event representation (§7.7.65.32-33). */
	ATF_TP_ADD_TC(tp, path_loss_threshold_event_layout);
	ATF_TP_ADD_TC(tp, tx_power_reporting_event_layout);

	/* Event dispatch conformance (was FINDING F2, now parsed). */
	ATF_TP_ADD_TC(tp, power_events_parsed);

	return (atf_no_error());
}
