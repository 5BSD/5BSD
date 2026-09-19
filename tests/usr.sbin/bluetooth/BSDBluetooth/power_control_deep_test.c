/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep boundary/negative + byte-encoding conformance tests for the LE Power
 * Control command encoders (Bluetooth Core Specification 6.3).
 *
 * Target: the five power-control encoders in hci_conn.c
 *
 *   hci_le_enhanced_read_tx_power_level()      §7.8.117  OCF 0x0076
 *   hci_le_read_remote_tx_power_level()        §7.8.118  OCF 0x0077
 *   hci_le_set_path_loss_reporting_params()    §7.8.119  OCF 0x0078
 *   hci_le_set_path_loss_reporting_enable()    §7.8.120  OCF 0x0079
 *   hci_le_set_tx_power_reporting_enable()     §7.8.121  OCF 0x007A
 *
 * (Core Spec Vol 4 Part E §§7.8.117-7.8.121.)
 *
 * Technique: interpose bt_devreq() at link time (-Wl,--wrap=bt_devreq), the
 * same seam power_control_test.c / hci_devreq_mock_test.c use.  __wrap_bt_devreq
 * BOTH captures the outbound command (opcode, clen, command-parameter bytes)
 * so each field can be checked octet-for-octet at its exact little-endian
 * offset against the spec command layout, AND feeds a test-controlled Command
 * Complete / Command Status back so the success / rejection / transport arms
 * are driven.
 *
 * Oracle: every expected byte/error is hand-encoded from the Core Spec, cited
 * per assertion; never captured from implementation output.
 *
 * This file complements power_control_test.c with an exhaustive boundary and
 * negative matrix: every parameter of every command at min / max / just-out-
 * of-range / reserved values, the connection-handle range encoding, the PHY
 * enumeration accept/reject set, the path-loss threshold ordering, the enable
 * flags, and the READ-command return-parameter extraction at int8 dBm
 * boundaries and each tx_power_level_flag / delta sign.
 *
 * Observations surfaced here (see the marked cases and the report):
 *
 * Connection handles are validated against the 0x0000-0x0EFF range from
 * §7.8.117-121; RFU values are rejected before controller I/O.
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
#include "spec_power_control_core63_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Any non-negative fd works: __wrap_bt_devreq ignores it. */
#define FD	3
#define nitems(a)	(sizeof(a) / sizeof((a)[0]))

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
	uint8_t st = BT_POWER_STATUS_SUCCESS;

	mock_ok_bytes(&st, 1);
}

/* Controller rejects with status 0x0C = Command Disallowed
 * (Core Spec Vol 1 Part F §1.3 error code table). */
static void
mock_status_bad(void)
{
	uint8_t st = BT_POWER_ERROR_COMMAND_DISALLOWED;

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

/*
 * Three post-I/O arms shared by every command: success (status 0x00 -> 0),
 * controller rejection (status != 0 -> -1/EIO), transport failure
 * (bt_devreq fails -> -1/EIO).  The call expression is idempotent (all I/O
 * mocked), so it is evaluated once per arm.
 */
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

/* Compare against a complete opcode transcribed independently from the Core. */
#define CHECK_OPCODE(expected_opcode) \
	ATF_CHECK_EQ((expected_opcode), W.opcode)

/* Assert a 16-bit field is little-endian encoded at cparam[off]. */
#define CHECK_LE16(off, v)	do {					\
	ATF_CHECK_EQ_MSG((uint8_t)((v) & 0xFF), W.cparam[(off)],		\
	    "LE16 LSB @%d", (off));					\
	ATF_CHECK_EQ_MSG((uint8_t)(((v) >> 8) & 0xFF), W.cparam[(off)+1],\
	    "LE16 MSB @%d", (off)+1);					\
} while (0)

/* A reject must happen BEFORE any controller I/O. */
#define CHECK_PREIO_EINVAL(call)	do {				\
	mock_ok();							\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "expected pre-I/O reject");		\
	ATF_CHECK_EQ_MSG(EINVAL, errno, "expected EINVAL");		\
	ATF_CHECK_EQ_MSG(0, W.called, "must reject before I/O");	\
} while (0)

/* ================================================================
 * §7.8.117  LE Enhanced Read Transmit Power Level  (OCF 0x0076)
 *   CP: Connection_Handle(2 LE) | PHY(1)                     -> clen 3
 *   RP: Status(1) | Connection_Handle(2) | PHY(1) |
 *       Current_TX_Power_Level(int8) | Max_TX_Power_Level(int8)
 * ================================================================ */

/* Each valid PHY 0x01..0x04 encodes at offset 2; handle LE at 0..1. */
ATF_TC_WITHOUT_HEAD(enh_read_phy_1m);
ATF_TC_BODY(enh_read_phy_1m, tc)
{
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x01, 0x00, 0x00 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0123, 0x01,
	    &cur, &max));
	CHECK_OPCODE(BT_POWER_OP_ENH_READ_TX_POWER_LEVEL);
	ATF_CHECK_EQ(3, W.clen);		/* §7.8.117 CP is 3 octets */
	CHECK_LE16(0, 0x0123);			/* Connection_Handle LE */
	ATF_CHECK_EQ(0x01, W.cparam[2]);	/* PHY = LE 1M */
}

ATF_TC_WITHOUT_HEAD(enh_read_phy_2m);
ATF_TC_BODY(enh_read_phy_2m, tc)
{
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x02, 0x00, 0x00 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x02,
	    &cur, &max));
	ATF_CHECK_EQ(3, W.clen);
	ATF_CHECK_EQ(0x02, W.cparam[2]);	/* PHY = LE 2M */
}

ATF_TC_WITHOUT_HEAD(enh_read_phy_coded_s8);
ATF_TC_BODY(enh_read_phy_coded_s8, tc)
{
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x03, 0x00, 0x00 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x03,
	    &cur, &max));
	ATF_CHECK_EQ(0x03, W.cparam[2]);	/* PHY = Coded S=8 */
}

ATF_TC_WITHOUT_HEAD(enh_read_phy_coded_s2);
ATF_TC_BODY(enh_read_phy_coded_s2, tc)
{
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x04, 0x00, 0x00 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x04,
	    &cur, &max));
	ATF_CHECK_EQ(0x04, W.cparam[2]);	/* PHY = Coded S=2 */
}

/*
 * §7.8.117 PHY: 0x01..0x04 defined, "all other values Reserved for future
 * use".  0x00 (below range) and 0x05/0x06/0xFF (above range) must be rejected
 * with EINVAL before any I/O.  Both sub-conditions of (phy < 1 || phy > 4).
 */
ATF_TC_WITHOUT_HEAD(enh_read_phy_reject_zero);
ATF_TC_BODY(enh_read_phy_reject_zero, tc)
{
	int8_t cur = 0, max = 0;

	CHECK_PREIO_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x00, &cur, &max));
}

ATF_TC_WITHOUT_HEAD(enh_read_phy_reject_five);
ATF_TC_BODY(enh_read_phy_reject_five, tc)
{
	int8_t cur = 0, max = 0;

	CHECK_PREIO_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x05, &cur, &max));
}

ATF_TC_WITHOUT_HEAD(enh_read_phy_reject_ff);
ATF_TC_BODY(enh_read_phy_reject_ff, tc)
{
	int8_t cur = 0, max = 0;

	CHECK_PREIO_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0xFF, &cur, &max));
}

/*
 * §7.8.117 return parameters Current_/Max_TX_Power_Level are int8 dBm,
 * range -127..+20; 0x7F = "unavailable".  Extract at signed boundaries.
 */
ATF_TC_WITHOUT_HEAD(enh_read_extract_min_dbm);
ATF_TC_BODY(enh_read_extract_min_dbm, tc)
{
	/* cur = -127 dBm (0x81), max = +20 dBm (0x14). */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x01, 0x81, 0x14 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
	ATF_CHECK_EQ(-127, cur);
	ATF_CHECK_EQ(20, max);
}

ATF_TC_WITHOUT_HEAD(enh_read_extract_unavailable);
ATF_TC_BODY(enh_read_extract_unavailable, tc)
{
	/* cur = 0x7F (127, "unavailable" sentinel), max = 0x00 (0 dBm). */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x02, 0x7F, 0x00 };
	int8_t cur = 0, max = 99;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x02,
	    &cur, &max));
	ATF_CHECK_EQ(127, cur);		/* 0x7F as int8 */
	ATF_CHECK_EQ(0, max);
}

ATF_TC_WITHOUT_HEAD(enh_read_extract_neg_and_zero);
ATF_TC_BODY(enh_read_extract_neg_and_zero, tc)
{
	/* cur = -1 dBm (0xFF), max = -128 (0x80, one below spec min: still an
	 * int8, extraction must be verbatim two's complement). */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x03, 0xFF, 0x80 };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x03,
	    &cur, &max));
	ATF_CHECK_EQ(-1, cur);
	ATF_CHECK_EQ(-128, max);
}

/*
 * The extractor guards each out-pointer with a NULL check
 * (if (cur_level != NULL) / if (max_level != NULL)).  Drive the NULL arm of
 * each independently and both together: the call must still succeed.
 */
ATF_TC_WITHOUT_HEAD(enh_read_null_out_params);
ATF_TC_BODY(enh_read_null_out_params, tc)
{
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x01, 0xEC, 0x0A };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    NULL, NULL));		/* both NULL */

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, NULL));		/* max NULL, cur written */
	ATF_CHECK_EQ(-20, cur);

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    NULL, &max));		/* cur NULL, max written */
	ATF_CHECK_EQ(10, max);
}

/* Valid handles encode little-endian; RFU handles reject before I/O. */
ATF_TC_WITHOUT_HEAD(enh_read_handle_range);
ATF_TC_BODY(enh_read_handle_range, tc)
{
	static const uint16_t valid[] = {
		0x0000, 0x0001, 0x00FF, 0x0100, 0x0EFF
	};
	static const uint16_t rfu[] = { 0x0F00, 0x0FFF, 0xFFFF };
	uint8_t rp[6] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
	size_t i;

	for (i = 0; i < nitems(valid); i++) {
		mock_ok_bytes(rp, sizeof(rp));
		ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD,
		    valid[i], 0x01, NULL, NULL));
		ATF_CHECK_EQ_MSG(1, W.called, "handle 0x%04x transmitted",
		    valid[i]);
		CHECK_LE16(0, valid[i]);
	}
	for (i = 0; i < nitems(rfu); i++)
		CHECK_PREIO_EINVAL(hci_le_enhanced_read_tx_power_level(FD,
		    rfu[i], 0x01, NULL, NULL));
}

/* Three post-I/O arms. */
ATF_TC_WITHOUT_HEAD(enh_read_post_io_arms);
ATF_TC_BODY(enh_read_post_io_arms, tc)
{
	int8_t cur = 0, max = 0;

	CHECK_OK(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
	CHECK_BAD(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
	CHECK_XPORT(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
}

/* ================================================================
 * §7.8.118  LE Read Remote Transmit Power Level  (OCF 0x0077)
 *   CP: Connection_Handle(2 LE) | PHY(1)                     -> clen 3
 *   Returns Command Status; result arrives via LE Transmit Power
 *   Reporting event with Reason 0x02 (§7.7.65.33).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_remote_phy_1m);
ATF_TC_BODY(read_remote_phy_1m, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_read_remote_tx_power_level(FD, 0x0EFF, 0x01));
	CHECK_OPCODE(BT_POWER_OP_READ_REMOTE_TX_POWER_LEVEL);
	ATF_CHECK_EQ(3, W.clen);
	CHECK_LE16(0, 0x0EFF);			/* max valid handle */
	ATF_CHECK_EQ(0x01, W.cparam[2]);
}

ATF_TC_WITHOUT_HEAD(read_remote_phy_coded_s2);
ATF_TC_BODY(read_remote_phy_coded_s2, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_read_remote_tx_power_level(FD, 0x0040, 0x04));
	ATF_CHECK_EQ(3, W.clen);
	ATF_CHECK_EQ(0x04, W.cparam[2]);	/* PHY = Coded S=2 */
}

ATF_TC_WITHOUT_HEAD(read_remote_phy_all_valid);
ATF_TC_BODY(read_remote_phy_all_valid, tc)
{
	uint8_t p;

	for (p = 0x01; p <= 0x04; p++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_read_remote_tx_power_level(FD, 0x0040, p));
		ATF_CHECK_EQ_MSG(p, W.cparam[2], "PHY %u encoded", p);
	}
}

ATF_TC_WITHOUT_HEAD(read_remote_phy_reject_zero);
ATF_TC_BODY(read_remote_phy_reject_zero, tc)
{
	CHECK_PREIO_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x00));
}

ATF_TC_WITHOUT_HEAD(read_remote_phy_reject_five);
ATF_TC_BODY(read_remote_phy_reject_five, tc)
{
	CHECK_PREIO_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x05));
}

ATF_TC_WITHOUT_HEAD(read_remote_phy_reject_ff);
ATF_TC_BODY(read_remote_phy_reject_ff, tc)
{
	CHECK_PREIO_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0xFF));
}

ATF_TC_WITHOUT_HEAD(read_remote_handle_range);
ATF_TC_BODY(read_remote_handle_range, tc)
{
	static const uint16_t valid[] = { 0x0000, 0x0EFF };
	static const uint16_t rfu[] = { 0x0F00, 0xFFFF };
	size_t i;

	for (i = 0; i < nitems(valid); i++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_read_remote_tx_power_level(FD,
		    valid[i], 0x01));
		CHECK_LE16(0, valid[i]);
	}
	for (i = 0; i < nitems(rfu); i++)
		CHECK_PREIO_EINVAL(hci_le_read_remote_tx_power_level(FD,
		    rfu[i], 0x01));
}

ATF_TC_WITHOUT_HEAD(read_remote_post_io_arms);
ATF_TC_BODY(read_remote_post_io_arms, tc)
{
	CHECK_ALL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));
}

/* ================================================================
 * §7.8.119  LE Set Path Loss Reporting Parameters  (OCF 0x0078)
 *   CP: Connection_Handle(2 LE) | High_Threshold(1) |
 *       High_Hysteresis(1) | Low_Threshold(1) | Low_Hysteresis(1) |
 *       Min_Time_Spent(2 LE)                                 -> clen 8
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(plp_encoding_full);
ATF_TC_BODY(plp_encoding_full, tc)
{
	mock_ok();
	/* high=0x40 hyst=0x04 low=0x10 hyst=0x02 min=0x1234 */
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0ABC,
	    0x40, 0x04, 0x10, 0x02, 0x1234));
	CHECK_OPCODE(BT_POWER_OP_SET_PATH_LOSS_PARAMS);
	ATF_CHECK_EQ(8, W.clen);		/* §7.8.119 CP is 8 octets */
	CHECK_LE16(0, 0x0ABC);			/* Connection_Handle LE */
	ATF_CHECK_EQ(0x40, W.cparam[2]);	/* High_Threshold */
	ATF_CHECK_EQ(0x04, W.cparam[3]);	/* High_Hysteresis */
	ATF_CHECK_EQ(0x10, W.cparam[4]);	/* Low_Threshold */
	ATF_CHECK_EQ(0x02, W.cparam[5]);	/* Low_Hysteresis */
	CHECK_LE16(6, 0x1234);			/* Min_Time_Spent LE */
}

/* High_Threshold == Low_Threshold: zones degenerate but well ordered (the
 * guard is high < low), so accepted and encoded. */
ATF_TC_WITHOUT_HEAD(plp_threshold_equal);
ATF_TC_BODY(plp_threshold_equal, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x30, 0x00, 0x30, 0x00, 0x0001));
	ATF_CHECK_EQ(1, W.called);
	ATF_CHECK_EQ(0x30, W.cparam[2]);
	ATF_CHECK_EQ(0x30, W.cparam[4]);
}

/* High_Threshold > Low_Threshold: the normal case, accepted. */
ATF_TC_WITHOUT_HEAD(plp_threshold_high_gt_low);
ATF_TC_BODY(plp_threshold_high_gt_low, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x64, 0x05, 0x0A, 0x05, 0x000A));	/* 100dB high, 10dB low */
	ATF_CHECK_EQ(1, W.called);
}

/*
 * §7.8.119 Errors: "Low_Threshold is greater than High_Threshold" ->
 * Invalid HCI Command Parameters (0x12).  The encoder pre-rejects this with
 * EINVAL before any I/O (guard high_thresh < low_thresh).
 */
ATF_TC_WITHOUT_HEAD(plp_threshold_high_lt_low_reject);
ATF_TC_BODY(plp_threshold_high_lt_low_reject, tc)
{
	/* high=0x10(16dB) < low=0x40(64dB): inverted zone bounds. */
	CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x10, 0x04, 0x40, 0x04, 0x000A));
}

/* One-below-boundary: high = low - 1 must reject; high = low must accept. */
ATF_TC_WITHOUT_HEAD(plp_threshold_off_by_one);
ATF_TC_BODY(plp_threshold_off_by_one, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x1F, 0x00, 0x20, 0x00, 0x000A));	/* 31 < 32 -> reject */

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x20, 0x00, 0x20, 0x00, 0x000A));	/* 32 == 32 -> accept */
	ATF_CHECK_EQ(1, W.called);
}

/*
 * §7.8.119 High_Threshold value 0xFF = "High Threshold unused".  With
 * high=0xFF the guard high < low is never true, so any low is accepted and
 * 0xFF is transmitted verbatim.
 */
ATF_TC_WITHOUT_HEAD(plp_high_threshold_unused);
ATF_TC_BODY(plp_high_threshold_unused, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0xFF, 0x00, 0x80, 0x00, 0x000A));
	ATF_CHECK_EQ(1, W.called);
	ATF_CHECK_EQ(0xFF, W.cparam[2]);	/* High_Threshold unused */
	ATF_CHECK_EQ(0x80, W.cparam[4]);
}

/* Hysteresis fields are uint8 but constrained by the §7.8.119 zone equations;
 * assert the largest valid high-hysteresis boundary still encodes exactly. */
ATF_TC_WITHOUT_HEAD(plp_hysteresis_full_range);
ATF_TC_BODY(plp_hysteresis_full_range, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x80, 0x7F, 0x00, 0x00, 0x0000));
	ATF_CHECK_EQ(0x80, W.cparam[2]);	/* High_Threshold */
	ATF_CHECK_EQ(0x7F, W.cparam[3]);	/* High_Hysteresis */
	ATF_CHECK_EQ(0x00, W.cparam[4]);	/* Low_Threshold */
	ATF_CHECK_EQ(0x00, W.cparam[5]);	/* Low_Hysteresis */
	CHECK_LE16(6, 0x0000);			/* Min_Time_Spent */
}

/* Min_Time_Spent little-endian at offset 6, boundary values. */
ATF_TC_WITHOUT_HEAD(plp_min_time_endianness);
ATF_TC_BODY(plp_min_time_endianness, tc)
{
	static const uint16_t mts[] = { 0x0000, 0x0001, 0x00FF, 0x0100, 0xFFFF };
	size_t i;

	for (i = 0; i < sizeof(mts) / sizeof(mts[0]); i++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD,
		    0x0040, 0x40, 0x00, 0x10, 0x00, mts[i]));
		CHECK_LE16(6, mts[i]);
	}
}

ATF_TC_WITHOUT_HEAD(plp_handle_range);
ATF_TC_BODY(plp_handle_range, tc)
{
	static const uint16_t valid[] = { 0x0000, 0x0EFF };
	static const uint16_t rfu[] = { 0x0F00, 0xFFFF };
	size_t i;

	for (i = 0; i < nitems(valid); i++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_params(FD,
		    valid[i], 0x40, 0x00, 0x10, 0x00, 0x000A));
		CHECK_LE16(0, valid[i]);
	}
	for (i = 0; i < nitems(rfu); i++)
		CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_params(FD,
		    rfu[i], 0x40, 0x00, 0x10, 0x00, 0x000A));
}

ATF_TC_WITHOUT_HEAD(plp_post_io_arms);
ATF_TC_BODY(plp_post_io_arms, tc)
{
	CHECK_ALL(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));
}

/* §7.8.119 malformed path-loss zone configurations reject before I/O. */
ATF_TC_WITHOUT_HEAD(plp_gap_high_plus_hyst_overflow);
ATF_TC_BODY(plp_gap_high_plus_hyst_overflow, tc)
{
	/* high=0xF0 + hyst=0x20 = 0x110 > 0xFF. */
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0xF0, 0x20, 0x10, 0x04, 0x000A));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "spec requires reject before I/O");
}

ATF_TC_WITHOUT_HEAD(plp_gap_low_lt_low_hyst);
ATF_TC_BODY(plp_gap_low_lt_low_hyst, tc)
{
	/* low=0x04 < low_hyst=0x10. */
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x80, 0x04, 0x04, 0x10, 0x000A));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "spec requires reject before I/O");
}

ATF_TC_WITHOUT_HEAD(plp_gap_zone_overlap);
ATF_TC_BODY(plp_gap_zone_overlap, tc)
{
	/* low(0x30)+low_hyst(0x10)=0x40 > high(0x50)-high_hyst(0x20)=0x30. */
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x50, 0x20, 0x30, 0x10, 0x000A));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "spec requires reject before I/O");
}

/* ================================================================
 * §7.8.120  LE Set Path Loss Reporting Enable  (OCF 0x0079)
 *   CP: Connection_Handle(2 LE) | Enable(1)                  -> clen 3
 *   Enable: 0x00 disabled, 0x01 enabled, all other RFU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ple_encoding_enable);
ATF_TC_BODY(ple_encoding_enable, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_enable(FD, 0x0777, 0x01));
	CHECK_OPCODE(BT_POWER_OP_SET_PATH_LOSS_ENABLE);
	ATF_CHECK_EQ(3, W.clen);
	CHECK_LE16(0, 0x0777);
	ATF_CHECK_EQ(0x01, W.cparam[2]);	/* Enable */
}

ATF_TC_WITHOUT_HEAD(ple_encoding_disable);
ATF_TC_BODY(ple_encoding_disable, tc)
{
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_enable(FD, 0x0040, 0x00));
	ATF_CHECK_EQ(3, W.clen);
	ATF_CHECK_EQ(0x00, W.cparam[2]);	/* Disable */
}

/* §7.8.120 Enable > 0x01 is Reserved for Future Use -> reject before I/O. */
ATF_TC_WITHOUT_HEAD(ple_reject_two);
ATF_TC_BODY(ple_reject_two, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_enable(FD, 0x0040,
	    0x02));
}

ATF_TC_WITHOUT_HEAD(ple_reject_ff);
ATF_TC_BODY(ple_reject_ff, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_enable(FD, 0x0040,
	    0xFF));
}

ATF_TC_WITHOUT_HEAD(ple_handle_range);
ATF_TC_BODY(ple_handle_range, tc)
{
	static const uint16_t valid[] = { 0x0000, 0x0EFF };
	static const uint16_t rfu[] = { 0x0F00, 0xFFFF };
	size_t i;

	for (i = 0; i < nitems(valid); i++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_set_path_loss_reporting_enable(FD,
		    valid[i], 0x01));
		CHECK_LE16(0, valid[i]);
	}
	for (i = 0; i < nitems(rfu); i++)
		CHECK_PREIO_EINVAL(hci_le_set_path_loss_reporting_enable(FD,
		    rfu[i], 0x01));
}

ATF_TC_WITHOUT_HEAD(ple_post_io_arms);
ATF_TC_BODY(ple_post_io_arms, tc)
{
	CHECK_ALL(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 0x01));
	CHECK_ALL(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 0x00));
}

/* ================================================================
 * §7.8.121  LE Set Transmit Power Reporting Enable  (OCF 0x007A)
 *   CP: Connection_Handle(2 LE) | Local_Enable(1) |
 *       Remote_Enable(1)                                     -> clen 4
 *   Both flags: 0x00 disable, 0x01 enable, all other RFU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(tpr_encoding_combos);
ATF_TC_BODY(tpr_encoding_combos, tc)
{
	uint8_t l, rm;

	for (l = 0; l <= 1; l++) {
		for (rm = 0; rm <= 1; rm++) {
			mock_ok();
			ATF_CHECK_EQ(0,
			    hci_le_set_tx_power_reporting_enable(FD, 0x0555,
			    l, rm));
			CHECK_OPCODE(BT_POWER_OP_SET_TX_POWER_ENABLE);
			ATF_CHECK_EQ(4, W.clen);	/* §7.8.121 CP 4 octets */
			CHECK_LE16(0, 0x0555);
			ATF_CHECK_EQ_MSG(l, W.cparam[2],
			    "Local_Enable=%u", l);
			ATF_CHECK_EQ_MSG(rm, W.cparam[3],
			    "Remote_Enable=%u", rm);
		}
	}
}

/* Local_Enable > 0x01 RFU: reject.  Exercises the first sub-condition of
 * (local > 1 || remote > 1). */
ATF_TC_WITHOUT_HEAD(tpr_reject_local_two);
ATF_TC_BODY(tpr_reject_local_two, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0x02, 0x00));
}

ATF_TC_WITHOUT_HEAD(tpr_reject_local_ff);
ATF_TC_BODY(tpr_reject_local_ff, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0xFF, 0x01));
}

/* Remote_Enable > 0x01 RFU with a valid Local_Enable: reject.  Exercises the
 * second sub-condition (local valid -> first false, remote > 1 -> true). */
ATF_TC_WITHOUT_HEAD(tpr_reject_remote_two);
ATF_TC_BODY(tpr_reject_remote_two, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0x00, 0x02));
}

ATF_TC_WITHOUT_HEAD(tpr_reject_remote_ff);
ATF_TC_BODY(tpr_reject_remote_ff, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0x01, 0xFF));
}

/* Both flags reserved simultaneously: still a single rejection. */
ATF_TC_WITHOUT_HEAD(tpr_reject_both);
ATF_TC_BODY(tpr_reject_both, tc)
{
	CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0040,
	    0x02, 0x02));
}

ATF_TC_WITHOUT_HEAD(tpr_handle_range);
ATF_TC_BODY(tpr_handle_range, tc)
{
	static const uint16_t valid[] = { 0x0000, 0x0EFF };
	static const uint16_t rfu[] = { 0x0F00, 0xFFFF };
	size_t i;

	for (i = 0; i < nitems(valid); i++) {
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_set_tx_power_reporting_enable(FD,
		    valid[i], 0x01, 0x01));
		CHECK_LE16(0, valid[i]);
	}
	for (i = 0; i < nitems(rfu); i++)
		CHECK_PREIO_EINVAL(hci_le_set_tx_power_reporting_enable(FD,
		    rfu[i], 0x01, 0x01));
}

ATF_TC_WITHOUT_HEAD(tpr_post_io_arms);
ATF_TC_BODY(tpr_post_io_arms, tc)
{
	CHECK_ALL(hci_le_set_tx_power_reporting_enable(FD, 0x0040, 0x01, 0x01));
}

/* ================================================================
 * Success-path logging bodies.
 *
 * Each encoder emits a LOG_HCI(1, ...) trace on success; with blued_verbose
 * at its default 0 the _BLUED_LOG guard (blued_verbose >= lvl) is always
 * false, leaving the log body regions uncovered.  Drive every command's
 * success path once with verbose tracing enabled, in both the non-daemonized
 * (fprintf) and daemonized (syslog) branches, so the trace regions execute.
 * ATF isolates each test case in its own process, so toggling the globals
 * here does not disturb the other cases.  No behavioural assertions here —
 * this case exists purely to reach the verbose-gated regions; correctness of
 * each command is asserted in the dedicated cases above.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(success_path_logging);
ATF_TC_BODY(success_path_logging, tc)
{
	int8_t cur = 0, max = 0;
	int d;

	blued_verbose = 2;			/* satisfy blued_verbose >= 1 */
	for (d = 0; d <= 1; d++) {
		int arm;

		blued_daemonized = d;		/* both fprintf and syslog arms */

		/* arm 0: success trace; arm 1: "... failed" trace. */
		for (arm = 0; arm <= 1; arm++) {
			if (arm == 0)
				mock_ok();
			else
				mock_status_bad();
			(void)hci_le_enhanced_read_tx_power_level(FD, 0x0040,
			    0x01, &cur, &max);

			if (arm == 0)
				mock_ok();
			else
				mock_status_bad();
			(void)hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01);

			if (arm == 0)
				mock_ok();
			else
				mock_status_bad();
			(void)hci_le_set_path_loss_reporting_params(FD, 0x0040,
			    0x40, 0x04, 0x10, 0x04, 0x000A);

			if (arm == 0)
				mock_ok();
			else
				mock_status_bad();
			(void)hci_le_set_path_loss_reporting_enable(FD, 0x0040,
			    0x01);
			/* also the disable ("disabled" log ternary) success. */
			if (arm == 0) {
				mock_ok();
				(void)hci_le_set_path_loss_reporting_enable(FD,
				    0x0040, 0x00);
			}

			if (arm == 0)
				mock_ok();
			else
				mock_status_bad();
			(void)hci_le_set_tx_power_reporting_enable(FD, 0x0040,
			    0x01, 0x00);
		}
	}
	blued_verbose = 0;
	blued_daemonized = 0;
	ATF_CHECK(true);			/* reached without crashing */
}

/* ================================================================
 * §7.7.65.32  LE Path Loss Threshold event
 *   Subevent_Code(0x20) | Connection_Handle(2 LE) |
 *   Current_Path_Loss(1, dB; 0xFF unavailable) |
 *   Zone_Entered(1: 0=low,1=mid,2=high; other RFU)
 *
 * The ng_hci.h ep struct begins after the subevent byte (the subevent is the
 * meta-event dispatch key, not part of the ep).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(path_loss_event_zones);
ATF_TC_BODY(path_loss_event_zones, tc)
{
	ng_hci_le_path_loss_threshold_ep ep;
	uint8_t body[4];

	ATF_CHECK_EQ_MSG(4, sizeof(ep),
	    "ng_hci_le_path_loss_threshold_ep must be 4 bytes (§7.7.65.32)");

	/* handle 0x0EFF, path loss 0 dB, zone 0 (low). */
	body[0] = 0xFF; body[1] = 0x0E; body[2] = 0x00; body[3] = 0x00;
	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(0x0EFF, le16toh(ep.connection_handle));
	ATF_CHECK_EQ(0, ep.current_path_loss);
	ATF_CHECK_EQ(0, ep.zone_entered);		/* low zone */

	/* handle 0x0040, path loss 42 dB, zone 1 (middle). */
	body[0] = 0x40; body[1] = 0x00; body[2] = 0x2A; body[3] = 0x01;
	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(42, ep.current_path_loss);
	ATF_CHECK_EQ(1, ep.zone_entered);		/* middle zone */

	/* path loss 0xFF (unavailable), zone 2 (high). */
	body[0] = 0x40; body[1] = 0x00; body[2] = 0xFF; body[3] = 0x02;
	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(0xFF, ep.current_path_loss);	/* unavailable */
	ATF_CHECK_EQ(2, ep.zone_entered);		/* high zone */
}

/* ================================================================
 * §7.7.65.33  LE Transmit Power Reporting event
 *   Subevent_Code(0x21) | Status(1) | Connection_Handle(2 LE) |
 *   Reason(1: 0=local,1=remote,2=Read completed) | PHY(1) |
 *   TX_Power_Level(int8 dBm; 0x7E not-managing, 0x7F unavailable) |
 *   TX_Power_Level_Flag(1: bit0=min,bit1=max) | Delta(int8 dB)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(tx_power_event_read_completed);
ATF_TC_BODY(tx_power_event_read_completed, tc)
{
	/* status ok, handle 0x0040, reason 2 (Read completed), PHY 1,
	 * tx power -30 dBm (0xE2), flag 0x01 (at minimum), delta 0
	 * (spec: Delta shall be zero when Reason==0x02). */
	uint8_t body[8] = { 0x00, 0x40, 0x00, 0x02, 0x01, 0xE2, 0x01, 0x00 };
	ng_hci_le_tx_power_reporting_ep ep;

	ATF_CHECK_EQ_MSG(8, sizeof(ep),
	    "ng_hci_le_tx_power_reporting_ep must be 8 bytes (§7.7.65.33)");
	memcpy(&ep, body, sizeof(ep));

	ATF_CHECK_EQ(0x00, ep.status);
	ATF_CHECK_EQ(0x0040, le16toh(ep.connection_handle));
	ATF_CHECK_EQ(2, ep.reason);		/* Read remote completed */
	ATF_CHECK_EQ(1, ep.phy);		/* 1M */
	ATF_CHECK_EQ(-30, (int8_t)ep.tx_power_level);
	ATF_CHECK_EQ(0x01, ep.tx_power_level_flag);	/* bit0: at minimum */
	ATF_CHECK_EQ(0, (int8_t)ep.delta);
}

ATF_TC_WITHOUT_HEAD(tx_power_event_local_change);
ATF_TC_BODY(tx_power_event_local_change, tc)
{
	/* reason 0 (local change), PHY 2 (2M), tx power +20 dBm (0x14),
	 * flag 0x02 (at maximum), delta +5 dB (0x05). */
	uint8_t body[8] = { 0x00, 0x40, 0x00, 0x00, 0x02, 0x14, 0x02, 0x05 };
	ng_hci_le_tx_power_reporting_ep ep;

	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(0, ep.reason);			/* local change */
	ATF_CHECK_EQ(2, ep.phy);			/* 2M */
	ATF_CHECK_EQ(20, (int8_t)ep.tx_power_level);
	ATF_CHECK_EQ(0x02, ep.tx_power_level_flag);	/* bit1: at maximum */
	ATF_CHECK_EQ(5, (int8_t)ep.delta);		/* positive delta */
}

ATF_TC_WITHOUT_HEAD(tx_power_event_remote_boundaries);
ATF_TC_BODY(tx_power_event_remote_boundaries, tc)
{
	/* reason 1 (remote change), PHY 4 (Coded S=2), tx power -127 dBm
	 * (0x81, spec min), flag 0x03 (min+max both set), delta -8 dB
	 * (0xF8, negative). */
	uint8_t body[8] = { 0x00, 0x40, 0x00, 0x01, 0x04, 0x81, 0x03, 0xF8 };
	ng_hci_le_tx_power_reporting_ep ep;

	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(1, ep.reason);			/* remote change */
	ATF_CHECK_EQ(4, ep.phy);			/* Coded S=2 */
	ATF_CHECK_EQ(-127, (int8_t)ep.tx_power_level);	/* spec min dBm */
	ATF_CHECK_EQ(0x03, ep.tx_power_level_flag);	/* min AND max */
	ATF_CHECK_EQ(-8, (int8_t)ep.delta);		/* negative delta */
}

ATF_TC_WITHOUT_HEAD(tx_power_event_sentinels);
ATF_TC_BODY(tx_power_event_sentinels, tc)
{
	/* tx power 0x7E ("remote not managing power on this PHY"), flag 0x00
	 * (neither min nor max), status 0x0C (a failed Read completion). */
	uint8_t body[8] = { 0x0C, 0x40, 0x00, 0x02, 0x03, 0x7E, 0x00, 0x00 };
	ng_hci_le_tx_power_reporting_ep ep;

	memcpy(&ep, body, sizeof(ep));
	ATF_CHECK_EQ(0x0C, ep.status);			/* Read failed */
	ATF_CHECK_EQ(3, ep.phy);			/* Coded S=8 */
	ATF_CHECK_EQ(0x7E, ep.tx_power_level);		/* not-managing sentinel */
	ATF_CHECK_EQ(0x00, ep.tx_power_level_flag);	/* neither */
}

/* Subevent-code constants match the spec dispatch keys (§7.7.65.32-33). */
ATF_TC_WITHOUT_HEAD(power_event_subevent_codes);
ATF_TC_BODY(power_event_subevent_codes, tc)
{
	ATF_CHECK_EQ_MSG(0x20, NG_HCI_LEEV_PATH_LOSS_THRESHOLD,
	    "Path Loss Threshold subevent code is 0x20 (§7.7.65.32)");
	ATF_CHECK_EQ_MSG(0x21, NG_HCI_LEEV_TX_POWER_REPORTING,
	    "Transmit Power Reporting subevent code is 0x21 (§7.7.65.33)");
	ATF_CHECK_EQ_MSG(0x0076, NG_HCI_OCF_LE_ENH_READ_TX_POWER_LEVEL,
	    "Enhanced Read TX Power OCF is 0x0076 (§7.8.117)");
	ATF_CHECK_EQ_MSG(0x0077, NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL,
	    "Read Remote TX Power OCF is 0x0077 (§7.8.118)");
	ATF_CHECK_EQ_MSG(0x0078, NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS,
	    "Set Path Loss Reporting Params OCF is 0x0078 (§7.8.119)");
	ATF_CHECK_EQ_MSG(0x0079, NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE,
	    "Set Path Loss Reporting Enable OCF is 0x0079 (§7.8.120)");
	ATF_CHECK_EQ_MSG(0x007a, NG_HCI_OCF_LE_SET_TX_POWER_REPORTING_ENABLE,
	    "Set TX Power Reporting Enable OCF is 0x007A (§7.8.121)");
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* §7.8.117 LE Enhanced Read Transmit Power Level (OCF 0x0076). */
	ATF_TP_ADD_TC(tp, enh_read_phy_1m);
	ATF_TP_ADD_TC(tp, enh_read_phy_2m);
	ATF_TP_ADD_TC(tp, enh_read_phy_coded_s8);
	ATF_TP_ADD_TC(tp, enh_read_phy_coded_s2);
	ATF_TP_ADD_TC(tp, enh_read_phy_reject_zero);
	ATF_TP_ADD_TC(tp, enh_read_phy_reject_five);
	ATF_TP_ADD_TC(tp, enh_read_phy_reject_ff);
	ATF_TP_ADD_TC(tp, enh_read_extract_min_dbm);
	ATF_TP_ADD_TC(tp, enh_read_extract_unavailable);
	ATF_TP_ADD_TC(tp, enh_read_extract_neg_and_zero);
	ATF_TP_ADD_TC(tp, enh_read_null_out_params);
	ATF_TP_ADD_TC(tp, enh_read_handle_range);
	ATF_TP_ADD_TC(tp, enh_read_post_io_arms);

	/* §7.8.118 LE Read Remote Transmit Power Level (OCF 0x0077). */
	ATF_TP_ADD_TC(tp, read_remote_phy_1m);
	ATF_TP_ADD_TC(tp, read_remote_phy_coded_s2);
	ATF_TP_ADD_TC(tp, read_remote_phy_all_valid);
	ATF_TP_ADD_TC(tp, read_remote_phy_reject_zero);
	ATF_TP_ADD_TC(tp, read_remote_phy_reject_five);
	ATF_TP_ADD_TC(tp, read_remote_phy_reject_ff);
	ATF_TP_ADD_TC(tp, read_remote_handle_range);
	ATF_TP_ADD_TC(tp, read_remote_post_io_arms);

	/* §7.8.119 LE Set Path Loss Reporting Parameters (OCF 0x0078). */
	ATF_TP_ADD_TC(tp, plp_encoding_full);
	ATF_TP_ADD_TC(tp, plp_threshold_equal);
	ATF_TP_ADD_TC(tp, plp_threshold_high_gt_low);
	ATF_TP_ADD_TC(tp, plp_threshold_high_lt_low_reject);
	ATF_TP_ADD_TC(tp, plp_threshold_off_by_one);
	ATF_TP_ADD_TC(tp, plp_high_threshold_unused);
	ATF_TP_ADD_TC(tp, plp_hysteresis_full_range);
	ATF_TP_ADD_TC(tp, plp_min_time_endianness);
	ATF_TP_ADD_TC(tp, plp_handle_range);
	ATF_TP_ADD_TC(tp, plp_post_io_arms);
	ATF_TP_ADD_TC(tp, plp_gap_high_plus_hyst_overflow);
	ATF_TP_ADD_TC(tp, plp_gap_low_lt_low_hyst);
	ATF_TP_ADD_TC(tp, plp_gap_zone_overlap);

	/* §7.8.120 LE Set Path Loss Reporting Enable (OCF 0x0079). */
	ATF_TP_ADD_TC(tp, ple_encoding_enable);
	ATF_TP_ADD_TC(tp, ple_encoding_disable);
	ATF_TP_ADD_TC(tp, ple_reject_two);
	ATF_TP_ADD_TC(tp, ple_reject_ff);
	ATF_TP_ADD_TC(tp, ple_handle_range);
	ATF_TP_ADD_TC(tp, ple_post_io_arms);

	/* §7.8.121 LE Set Transmit Power Reporting Enable (OCF 0x007A). */
	ATF_TP_ADD_TC(tp, tpr_encoding_combos);
	ATF_TP_ADD_TC(tp, tpr_reject_local_two);
	ATF_TP_ADD_TC(tp, tpr_reject_local_ff);
	ATF_TP_ADD_TC(tp, tpr_reject_remote_two);
	ATF_TP_ADD_TC(tp, tpr_reject_remote_ff);
	ATF_TP_ADD_TC(tp, tpr_reject_both);
	ATF_TP_ADD_TC(tp, tpr_handle_range);
	ATF_TP_ADD_TC(tp, tpr_post_io_arms);

	/* Verbose success-path logging regions. */
	ATF_TP_ADD_TC(tp, success_path_logging);

	/* Event representation (§7.7.65.32-33). */
	ATF_TP_ADD_TC(tp, path_loss_event_zones);
	ATF_TP_ADD_TC(tp, tx_power_event_read_completed);
	ATF_TP_ADD_TC(tp, tx_power_event_local_change);
	ATF_TP_ADD_TC(tp, tx_power_event_remote_boundaries);
	ATF_TP_ADD_TC(tp, tx_power_event_sentinels);
	ATF_TP_ADD_TC(tp, power_event_subevent_codes);

	return (atf_no_error());
}
