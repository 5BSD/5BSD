/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep conformance tests for the LE Isochronous (ISO) TRANSPORT layer
 * (Bluetooth Core Specification 6.3): the CIS/BIG/ISO-data-path HCI
 * command encoders in hci_misc.c.  Scope is the isochronous TRANSPORT
 * only (Core Spec Vol 4 Part E §7.8.2, §7.8.96-7.8.116); the LE Audio
 * profiles (BAP/ASCS/PACS/CAP/VCP/...) are explicitly OUT of scope.
 *
 * This file is a density companion to iso_transport_test.c.  Where that
 * file establishes one nominal vector per command, this one drives EVERY
 * parameter to its spec boundary / reserved / out-of-range value, exercises
 * every optional-output NULL arm, the return-parameter extraction at
 * boundary values, and the host-side length/count validation before I/O.
 *
 * Oracle.  Every command byte offset, field range and return-parameter
 * offset asserted here is hand-encoded from the Core Spec (ranges cited
 * per case) — never captured from the implementation's own output.  Where
 * the encoder forwards an out-of-range field unchecked (it validates only
 * CIS_Count and the two length bounds), the assertion is that the byte is
 * forwarded VERBATIM and the divergence from the spec's stated range is
 * recorded as a FINDING in the case comment.
 *
 * Method.  The encoders reach the controller through
 * hci_devreq_logged() -> bt_devreq() (libbluetooth).  We interpose
 * bt_devreq at link time (-Wl,--wrap=bt_devreq).  __wrap_bt_devreq (a)
 * records the opcode / expected-event / cparam bytes the encoder built,
 * so the on-wire layout is asserted against the spec, and (b) returns a
 * test-controlled Command Complete / Command Status carrying chosen
 * return-parameter bytes so the post-I/O arms run.  C.calls proves that
 * host-side rejection returns EINVAL *before* any I/O.
 *
 * struct bt_devreq (see /usr/src/lib/libbluetooth/bluetooth.h):
 *     uint16_t opcode; uint8_t event; void *cparam; size_t clen;
 *     void *rparam; size_t rlen;
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_iso_transport_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Any non-negative fd works: __wrap_bt_devreq ignores it. */
#define FD	3

/* ================================================================
 * The --wrap seam: capture the built command, supply the response.
 * ================================================================ */
static struct {
	int		fail;		/* nonzero -> return -1, errno */
	int		fail_errno;
	uint8_t		payload[320];	/* return params, status byte first */
	size_t		payload_len;

	int		calls;		/* number of bt_devreq invocations */
	uint16_t	opcode;		/* r->opcode (host order) */
	uint8_t		event;		/* r->event expected-completion type */
	uint8_t		cmd[320];	/* r->cparam bytes */
	size_t		clen;		/* r->clen */
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	W.calls++;
	W.opcode = r->opcode;
	W.event = r->event;
	W.clen = r->clen;
	memset(W.cmd, 0, sizeof(W.cmd));
	if (r->cparam != NULL && r->clen > 0) {
		size_t n = r->clen < sizeof(W.cmd) ? r->clen : sizeof(W.cmd);
		memcpy(W.cmd, r->cparam, n);
	}

	if (W.fail) {
		errno = W.fail_errno;
		return (-1);
	}
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = W.payload_len < r->rlen ? W.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, W.payload, n);
	}
	return (0);
}

static void
reset(void)
{

	memset(&W, 0, sizeof(W));
}

static void
mock_ok_bytes(const void *p, size_t n)
{
	W.fail = 0;
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

static void
mock_ok(void)
{
	uint8_t st = BT_ISO_STATUS_SUCCESS;

	mock_ok_bytes(&st, 1);
}

static void
mock_status_bad(void)
{
	/* Vol 1, Part F §1.3: Command Disallowed has status code 0x0c. */
	uint8_t st = BT_ISO_ERROR_COMMAND_DISALLOWED;

	mock_ok_bytes(&st, 1);
}

static void
mock_xport_fail(int e)
{
	W.fail = 1;
	W.fail_errno = e;
}

static uint16_t
cmd_le16(size_t off)
{

	return ((uint16_t)W.cmd[off] | ((uint16_t)W.cmd[off + 1] << 8));
}

static uint32_t
cmd_le24(size_t off)
{

	return ((uint32_t)W.cmd[off] | ((uint32_t)W.cmd[off + 1] << 8) |
	    ((uint32_t)W.cmd[off + 2] << 16));
}

/*
 * Status-fail (rp.status != 0 -> -1/EIO) and transport-fail (bt_devreq
 * itself fails -> -1/errno) arms for a status-only command.  All I/O is
 * mocked, so every call is idempotent.
 */
#define CHECK_BAD(call)		do {					\
	reset(); mock_status_bad(); errno = 0;				\
	ATF_CHECK_EQ_MSG(-1, (call), "status!=0 arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "status!=0 arm: expected EIO");	\
} while (0)

#define CHECK_XPORT(call)	do {					\
	reset(); mock_xport_fail(EIO); errno = 0;			\
	ATF_CHECK_EQ_MSG(-1, (call), "transport arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "transport arm: expected EIO");	\
} while (0)

/* ================================================================
 * §7.8.2  LE Read Buffer Size v2  (OCF 0x0060)
 * No command parameters.
 * RP: Status(1) | LE_ACL_Data_Packet_Length(2 LE) |
 *     Total_Num_LE_ACL_Data_Packets(1) | ISO_Data_Packet_Length(2 LE) |
 *     Total_Num_ISO_Data_Packets(1)
 * This is the ISO buffer-sizing query; included as ISO transport.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_buffer_size_v2_extract);
ATF_TC_BODY(read_buffer_size_v2_extract, tc)
{
	/* Distinct boundary values, every multi-byte field little-endian. */
	uint8_t rp[7] = {
		0x00,			/* status */
		0xFB, 0x00,		/* LE ACL data packet length = 251 */
		0x18,			/* num LE ACL packets = 24 */
		0xFB, 0x03,		/* ISO data packet length = 0x03FB */
		0x0A			/* num ISO packets = 10 */
	};
	uint16_t acl_len = 0, iso_len = 0;
	uint8_t acl_num = 0, iso_num = 0;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(BT_ISO_OP_READ_BUFFER_SIZE_V2, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)0, W.clen);	/* no command parameters */
	ATF_CHECK_EQ(251, acl_len);
	ATF_CHECK_EQ(24, acl_num);
	ATF_CHECK_EQ(0x03FB, iso_len);
	ATF_CHECK_EQ(10, iso_num);

	CHECK_BAD(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num, &iso_len,
	    &iso_num));
	CHECK_XPORT(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num, &iso_len,
	    &iso_num));
}

/*
 * Core §7.8.2 defines the four return fields; accepting NULL destinations
 * for those fields is the local hci_util.h optional-output API contract.
 */
ATF_TC_WITHOUT_HEAD(read_buffer_size_v2_null_outs);
ATF_TC_BODY(read_buffer_size_v2_null_outs, tc)
{
	uint8_t rp[7] = { 0x00, 0xFB, 0x00, 0x18, 0xFB, 0x03, 0x0A };

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v2(FD, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(1, W.calls);
}

/* ================================================================
 * §7.8.96  LE Read ISO TX Sync  (OCF 0x0061)
 * CP: Connection_Handle(2 LE)
 * RP: Status(1) | Connection_Handle(2) | Packet_Sequence_Number(2) |
 *     TX_Time_Stamp(4) | Time_Offset(3 LE)
 * ================================================================ */

/* Return-parameter extraction at the maximum value of every RP field. */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync_rp_max);
ATF_TC_BODY(read_iso_tx_sync_rp_max, tc)
{
	uint8_t rp[12] = {
		0x00,			/* status */
		0xFF, 0x0E,		/* connection_handle 0x0EFF (12-bit max) */
		0xFF, 0xFF,		/* seq = 0xFFFF (max u16) */
		0xFF, 0xFF, 0xFF, 0xFF,	/* ts = 0xFFFFFFFF (max u32) */
		0xFF, 0xFF, 0xFF	/* time_offset = 0xFFFFFF (3-octet max) */
	};
	uint16_t seq = 0;
	uint32_t ts = 0, off = 0;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	/* Connection_Handle at its 12-bit maximum (Vol 4 Part E §5.4.2). */
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0EFF, &seq, &ts, &off));
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
	ATF_CHECK_EQ(0xFFFF, seq);
	ATF_CHECK_EQ(0xFFFFFFFFu, ts);
	ATF_CHECK_EQ(0x00FFFFFFu, off);	/* 3-octet field, high byte stays 0 */
}

/* Minimum Connection_Handle (0x0000) with an all-zero RP -> zero fields. */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync_rp_zero);
ATF_TC_BODY(read_iso_tx_sync_rp_zero, tc)
{
	uint8_t rp[12] = { 0 };		/* status 0, all fields 0 */
	uint16_t seq = 0xFFFF;
	uint32_t ts = 0xFFFFFFFF, off = 0xFFFFFFFF;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0000, &seq, &ts, &off));
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0000, cmd_le16(0));
	ATF_CHECK_EQ(0, seq);
	ATF_CHECK_EQ(0u, ts);
	ATF_CHECK_EQ(0u, off);
}

/*
 * Core §7.8.96 defines the three return fields; accepting NULL destinations
 * is the local hci_util.h optional-output API contract.
 */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync_null_outs);
ATF_TC_BODY(read_iso_tx_sync_null_outs, tc)
{
	uint8_t rp[12] = { 0x00, 0x40, 0x00, 0x34, 0x12,
	    0xEF, 0xCD, 0xAB, 0x89, 0x01, 0x02, 0x03 };

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0040, NULL, NULL, NULL));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(0x0040, cmd_le16(0));
}

/* ================================================================
 * §7.8.97  LE Set CIG Parameters  (OCF 0x0062)
 * CP header: CIG_ID(1) | SDU_Interval_C_To_P(3 LE) | SDU_Interval_P_To_C(3
 *   LE) | Worst_Case_SCA(1) | Packing(1) | Framing(1) |
 *   Max_Transport_Latency_C_To_P(2 LE) | Max_Transport_Latency_P_To_C(2 LE)
 *   | CIS_Count(1) | <records>
 * ================================================================ */

/*
 * Field-boundary encoding.  CIG_ID max 0xEF (§7.8.97 "Range: 0x00 to
 * 0xEF"); SDU_Interval max 0x0FFFFF ("Range: 0x0000FF to 0x0FFFFF");
 * Max_Transport_Latency max 0x0FA0 ("Range: 0x0005 to 0x0FA0"); Packing
 * and Framing 0/1.  All asserted byte-for-byte little-endian.
 */
ATF_TC_WITHOUT_HEAD(set_cig_field_maxima);
ATF_TC_BODY(set_cig_field_maxima, tc)
{
	uint8_t rp[3] = { 0x00, 0xEF, 0x00 };
	uint8_t out_cig = 0, out_cnt = 0;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD,
	    0xEF,		/* CIG_ID max */
	    0x0FFFFF,		/* SDU_Interval_C_To_P max */
	    0x0FFFFF,		/* SDU_Interval_P_To_C max */
	    0x00,		/* Worst_Case_SCA 0 (251 ppm) */
	    0x01,		/* Packing = interleaved */
	    0x01,		/* Framing = framed */
	    0x0FA0,		/* Max_Transport_Latency_C_To_P max */
	    0x0FA0,		/* Max_Transport_Latency_P_To_C max */
	    0x00,		/* CIS_Count 0 (no records) */
	    NULL, 0,
	    &out_cig, &out_cnt, NULL));
	ATF_CHECK_EQ((size_t)15, W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
	ATF_CHECK_EQ(0x0FFFFFu, cmd_le24(1));
	ATF_CHECK_EQ(0x0FFFFFu, cmd_le24(4));
	ATF_CHECK_EQ(0x00, W.cmd[7]);
	ATF_CHECK_EQ(0x01, W.cmd[8]);
	ATF_CHECK_EQ(0x01, W.cmd[9]);
	ATF_CHECK_EQ(0x0FA0, cmd_le16(10));
	ATF_CHECK_EQ(0x0FA0, cmd_le16(12));
	ATF_CHECK_EQ(0x00, W.cmd[14]);
}

/*
 * SDU_Interval minimum (0x0000FF) and Max_Transport_Latency minimum
 * (0x0005) byte layout (§7.8.97 stated ranges), with CIG_ID at its
 * maximum valid value (0xEF).  Reserved CIG_ID (> 0xEF) rejection is
 * covered by set_cig_cig_id_reserved.
 */
ATF_TC_WITHOUT_HEAD(set_cig_field_minima_reserved);
ATF_TC_BODY(set_cig_field_minima_reserved, tc)
{
	uint8_t rp[3] = { 0x00, 0xEF, 0x00 };
	uint8_t out_cig = 0, out_cnt = 0;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD,
	    0xEF,		/* CIG_ID max valid (0x00-0xEF) */
	    0x0000FF,		/* SDU_Interval_C_To_P min */
	    0x0000FF,		/* SDU_Interval_P_To_C min */
	    0x07,		/* Worst_Case_SCA max valid (0x00-0x07) */
	    0x00, 0x00,		/* Packing/Framing sequential/unframed */
	    0x0005, 0x0005,	/* Max_Transport_Latency min */
	    0x00, NULL, 0, &out_cig, &out_cnt, NULL));
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
	ATF_CHECK_EQ(0x0000FFu, cmd_le24(1));
	ATF_CHECK_EQ(0x0000FFu, cmd_le24(4));
	ATF_CHECK_EQ(0x07, W.cmd[7]);
	ATF_CHECK_EQ(0x0005, cmd_le16(10));
	ATF_CHECK_EQ(0x0005, cmd_le16(12));
	ATF_CHECK_EQ(0xEF, out_cig);
}

/*
 * CIS_Count host-side validation (§7.8.97 "Range: 0x00 to 0x1F").  The
 * encoder rejects CIS_Count > 0x1F with EINVAL BEFORE any I/O.  0x20 and
 * 0xFF are rejected; 0x1F is the accepted maximum.
 */
ATF_TC_WITHOUT_HEAD(set_cig_cis_count_reserved);
ATF_TC_BODY(set_cig_cis_count_reserved, tc)
{
	static uint8_t recs[31 * 9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[31];

	memset(recs, 0, sizeof(recs));

	/* 0x20 (32) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x00, 1000, 1000, 0, 0, 0,
	    10, 10, 0x20, recs, 32 * 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 0xFF -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x00, 1000, 1000, 0, 0, 0,
	    10, 10, 0xFF, recs, sizeof(recs), &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 0x1F (31) with a full 31*9 record block -> accepted, clen 294. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x05, 1000, 1000, 0, 0, 0,
	    10, 10, 0x1F, recs, 31 * 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)294, W.clen);
	ATF_CHECK_EQ(0x1F, W.cmd[14]);
}

/*
 * CIG_ID host-side validation (§7.8.97 "Range: 0x00 to 0xEF").  The
 * encoder rejects a reserved CIG_ID (> 0xEF) with EINVAL BEFORE any I/O;
 * 0xEF is the accepted maximum and lands verbatim at command offset 0.
 */
ATF_TC_WITHOUT_HEAD(set_cig_cig_id_reserved);
ATF_TC_BODY(set_cig_cig_id_reserved, tc)
{
	static uint8_t recs[9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[1];

	memset(recs, 0, sizeof(recs));

	/* 0xF0 (reserved) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0xF0, 1000, 1000, 0, 0, 0,
	    10, 10, 1, recs, 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 0xFF (reserved) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0xFF, 1000, 1000, 0, 0, 0,
	    10, 10, 1, recs, 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 0xEF (max valid) -> accepted, forwarded at offset 0. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0xEF, 1000, 1000, 0, 0, 0,
	    10, 10, 1, recs, 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
}

/*
 * RP extraction at the maximum reachable CIS_Count.  The controller
 * reports CIS_Count 31 and 31 Connection_Handles; the encoder must
 * extract all 31, little-endian, into out_cis_handles (§7.8.97 RP:
 * Status | CIG_ID | CIS_Count | Connection_Handle[i]).
 */
ATF_TC_WITHOUT_HEAD(set_cig_rp_31_handles);
ATF_TC_BODY(set_cig_rp_31_handles, tc)
{
	uint8_t rp[3 + 31 * 2];
	static uint8_t recs[31 * 9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[31];
	int i;

	memset(recs, 0, sizeof(recs));
	memset(handles, 0, sizeof(handles));
	rp[0] = 0x00;			/* status */
	rp[1] = 0x2A;			/* CIG_ID */
	rp[2] = 31;			/* CIS_Count */
	for (i = 0; i < 31; i++) {
		uint16_t h = (uint16_t)(0x0100 + i);
		rp[3 + i * 2] = h & 0xFF;
		rp[3 + i * 2 + 1] = (h >> 8) & 0xFF;
	}

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x2A, 1000, 1000, 0, 0, 0,
	    10, 10, 31, recs, 31 * 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(0x2A, out_cig);
	ATF_CHECK_EQ(31, out_cnt);
	for (i = 0; i < 31; i++)
		ATF_CHECK_EQ((uint16_t)(0x0100 + i), handles[i]);
}

/*
 * RP CIS_Count over-report clamp.  If the controller returns a CIS_Count
 * above the spec max (31), the encoder clamps the extraction loop to 31
 * so it cannot walk past rpbuf.  Drive CIS_Count = 0xFF in the RP and a
 * caller cis_count of 31, and confirm exactly 31 handles are copied.
 */
ATF_TC_WITHOUT_HEAD(set_cig_rp_count_clamp);
ATF_TC_BODY(set_cig_rp_count_clamp, tc)
{
	uint8_t rp[3 + 31 * 2];
	static uint8_t recs[31 * 9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[31];
	int i;

	memset(recs, 0, sizeof(recs));
	memset(handles, 0xEE, sizeof(handles));
	rp[0] = 0x00;
	rp[1] = 0x01;
	rp[2] = 0xFF;			/* bogus over-range CIS_Count */
	for (i = 0; i < 31; i++) {
		rp[3 + i * 2] = (uint8_t)(0x50 + i);
		rp[3 + i * 2 + 1] = 0x00;
	}

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x01, 1000, 1000, 0, 0, 0,
	    10, 10, 31, recs, 31 * 9, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(0xFF, out_cnt);	/* raw count passed through */
	/* Loop clamped to 31: handle 0..30 filled from rp. */
	for (i = 0; i < 31; i++)
		ATF_CHECK_EQ((uint16_t)(0x50 + i), handles[i]);
}

/*
 * RP extraction with caller CIS_Count below the controller's reported
 * count.  The extraction loop `i < n && i < cis_count` must stop at the
 * SMALLER of the two (the caller's out_cis_handles capacity), copying
 * only cis_count handles even though the controller reported more.
 */
ATF_TC_WITHOUT_HEAD(set_cig_rp_caller_short);
ATF_TC_BODY(set_cig_rp_caller_short, tc)
{
	uint8_t rp[3 + 31 * 2];
	static uint8_t recs[5 * 9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[5];
	int i;

	memset(recs, 0, sizeof(recs));
	memset(handles, 0, sizeof(handles));
	rp[0] = 0x00;
	rp[1] = 0x07;
	rp[2] = 31;			/* controller reports 31 handles */
	for (i = 0; i < 31; i++) {
		rp[3 + i * 2] = (uint8_t)(0x70 + i);
		rp[3 + i * 2 + 1] = 0x00;
	}

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	/* Caller only asked for 5 CIS -> only 5 handles must be extracted. */
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x07, 1000, 1000, 0, 0, 0,
	    10, 10, 5, recs, sizeof(recs), &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(31, out_cnt);	/* raw reported count */
	for (i = 0; i < 5; i++)
		ATF_CHECK_EQ((uint16_t)(0x70 + i), handles[i]);
}

/*
 * Core §7.8.97 defines these return fields; their NULL acceptance is the
 * local hci_util.h optional-output API contract.
 */
ATF_TC_WITHOUT_HEAD(set_cig_null_outs);
ATF_TC_BODY(set_cig_null_outs, tc)
{
	uint8_t recs[9] = { 0 };
	uint8_t rp[5] = { 0x00, 0x03, 0x01, 0x60, 0x00 };

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x03, 1000, 1000, 0, 0, 0,
	    10, 10, 1, recs, sizeof(recs), NULL, NULL, NULL));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)24, W.clen);
}

/* ================================================================
 * §7.8.99  LE Create CIS  (OCF 0x0064)
 * CP: CIS_Count(1) | { CIS_Connection_Handle(2 LE) |
 *     ACL_Connection_Handle(2 LE) } x CIS_Count.  Command Status.
 * ================================================================ */

/* Handle pair encoding at the 12-bit maximum handle value 0x0EFF. */
ATF_TC_WITHOUT_HEAD(create_cis_max_handles);
ATF_TC_BODY(create_cis_max_handles, tc)
{
	uint16_t cis_h[1] = { 0x0EFF };
	uint16_t acl_h[1] = { 0x0EFE };

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_cis(FD, 1, cis_h, acl_h));
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)(1 + 4), W.clen);
	ATF_CHECK_EQ(1, W.cmd[0]);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(1));
	ATF_CHECK_EQ(0x0EFE, cmd_le16(3));
}

/*
 * CIS_Count host-side validation (§7.8.99).  The encoder rejects
 * CIS_Count == 0 and CIS_Count > 0x1F with EINVAL BEFORE any I/O.  0x00
 * and 0x20 are rejected; the rejection must leave the wire untouched.
 */
ATF_TC_WITHOUT_HEAD(create_cis_count_reject);
ATF_TC_BODY(create_cis_count_reject, tc)
{
	uint16_t cis_h[32], acl_h[32];
	int i;

	for (i = 0; i < 32; i++) {
		cis_h[i] = (uint16_t)(0x0100 + i);
		acl_h[i] = (uint16_t)(0x0001 + i);
	}

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_cis(FD, 0, cis_h, acl_h));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_cis(FD, 0x20, cis_h, acl_h));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");
}

/* ================================================================
 * §7.8.100 Remove CIG / §7.8.101 Accept CIS / §7.8.102 Reject CIS
 * ================================================================ */

/* CIG_ID boundary (max 0xEF, §7.8.100 "Range: 0x00 to 0xEF"). */
ATF_TC_WITHOUT_HEAD(remove_cig_boundary);
ATF_TC_BODY(remove_cig_boundary, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_remove_cig(FD, 0xEF));
	ATF_CHECK_EQ((size_t)1, W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);

	/* 0x00 minimum. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_remove_cig(FD, 0x00));
	ATF_CHECK_EQ(0x00, W.cmd[0]);
}

/* §7.8.102: Reason is octet 2 after the little-endian Connection_Handle. */
ATF_TC_WITHOUT_HEAD(reject_cis_reason_encoding);
ATF_TC_BODY(reject_cis_reason_encoding, tc)
{

	reset();
	mock_ok();
	/* 0x0D Connection Rejected due to Limited Resources. */
	ATF_CHECK_EQ(0, hci_le_reject_cis_request(FD, 0x0EFF, 0x0D));
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)3, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
	ATF_CHECK_EQ(0x0D, W.cmd[2]);

	/* Vol 1, Part F §1.3: 0x15 = Remote Device Terminated due to Power Off. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_reject_cis_request(FD, 0x0040, 0x15));
	ATF_CHECK_EQ(0x0040, cmd_le16(0));
	ATF_CHECK_EQ(0x15, W.cmd[2]);
}

/* ================================================================
 * §7.8.103  LE Create BIG  (OCF 0x0068)  fixed 31-byte CP.
 * ================================================================ */

/*
 * All fields at maxima.  Num_BIS max 0x1F (§7.8.103 "Range: 0x01 to
 * 0x1F"); SDU_Interval max 0x0FFFFF; Max_SDU max 0x0FFF ("Range: 0x0001
 * to 0x0FFF"); Max_Transport_Latency max 0x0FA0; PHY = LE Coded (bit 2 =
 * 0x04); Packing/Framing 1/1; Encryption 1.  Byte-checked.
 * RTN spec range is 0x00 to 0x1E (§7.8.103 "Range: 0x00 to 0x1E"); 0x1E
 * is the accepted maximum and is asserted as verbatim pass-through at
 * offset 10 (reserved values above 0x1E are rejected before I/O, see
 * create_big_rtn_reserved).
 */
ATF_TC_WITHOUT_HEAD(create_big_field_maxima);
ATF_TC_BODY(create_big_field_maxima, tc)
{
	uint8_t bcode[16];
	int i;

	for (i = 0; i < 16; i++)
		bcode[i] = (uint8_t)(0xF0 + i);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_big(FD,
	    0xEF,		/* BIG_Handle max */
	    0xEF,		/* Advertising_Handle max */
	    0x1F,		/* Num_BIS max */
	    0x0FFFFF,		/* SDU_Interval max */
	    0x0FFF,		/* Max_SDU max */
	    0x0FA0,		/* Max_Transport_Latency max */
	    0x1E,		/* RTN max valid (0x00..0x1E) */
	    0x04,		/* PHY = LE Coded */
	    0x01, 0x01,		/* Packing/Framing */
	    0x01,		/* Encryption */
	    bcode));
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)31, W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
	ATF_CHECK_EQ(0xEF, W.cmd[1]);
	ATF_CHECK_EQ(0x1F, W.cmd[2]);
	ATF_CHECK_EQ(0x0FFFFFu, cmd_le24(3));
	ATF_CHECK_EQ(0x0FFF, cmd_le16(6));
	ATF_CHECK_EQ(0x0FA0, cmd_le16(8));
	ATF_CHECK_EQ(0x1E, W.cmd[10]);
	ATF_CHECK_EQ(0x04, W.cmd[11]);
	ATF_CHECK_EQ(0x01, W.cmd[12]);
	ATF_CHECK_EQ(0x01, W.cmd[13]);
	ATF_CHECK_EQ(0x01, W.cmd[14]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 15, bcode, 16));
}

/*
 * Minima and PHY bit combinations.  Num_BIS min 0x01; SDU_Interval min
 * 0x0000FF; Max_SDU min 0x0001; Encryption 0 with a NULL broadcast_code
 * (the unencrypted case) -> the 16 Broadcast_Code bytes stay zero.  PHY
 * = LE 1M (0x01).
 */
ATF_TC_WITHOUT_HEAD(create_big_minima_nullcode);
ATF_TC_BODY(create_big_minima_nullcode, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_big(FD,
	    0x00,		/* BIG_Handle min */
	    0x00,		/* Advertising_Handle min */
	    0x01,		/* Num_BIS min */
	    0x0000FF,		/* SDU_Interval min */
	    0x0001,		/* Max_SDU min */
	    0x0005,		/* Max_Transport_Latency min */
	    0x00,		/* RTN 0 */
	    0x01,		/* PHY = LE 1M */
	    0x00, 0x00,		/* Packing/Framing */
	    0x00,		/* Encryption off */
	    NULL));		/* NULL broadcast_code */
	ATF_CHECK_EQ((size_t)31, W.clen);
	ATF_CHECK_EQ(0x00, W.cmd[0]);
	ATF_CHECK_EQ(0x01, W.cmd[2]);
	ATF_CHECK_EQ(0x0000FFu, cmd_le24(3));
	ATF_CHECK_EQ(0x0001, cmd_le16(6));
	ATF_CHECK_EQ(0x0005, cmd_le16(8));
	ATF_CHECK_EQ(0x01, W.cmd[11]);
	ATF_CHECK_EQ(0x00, W.cmd[14]);
	/* NULL code -> memset-zeroed Broadcast_Code region. */
	uint8_t zero[16] = { 0 };
	ATF_CHECK_EQ(0, memcmp(W.cmd + 15, zero, 16));
}

/*
 * Num_BIS 0x00 and 0x20 are OUTSIDE the spec range (0x01-0x1F, §7.8.103);
 * the encoder must reject them with EINVAL BEFORE any I/O, matching the
 * CIS_Count guard in hci_le_set_cig_params().
 */
ATF_TC_WITHOUT_HEAD(create_big_num_bis_reserved);
ATF_TC_BODY(create_big_num_bis_reserved, tc)
{

	/* Num_BIS 0x00 (below range) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
		ATF_CHECK_EQ(-1, hci_le_create_big(FD, 0x01, 0x01, 0x00, 0x0000FF,
		    100, 10, 0, 0x02, 0, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* Num_BIS 0x20 (above range) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
		ATF_CHECK_EQ(-1, hci_le_create_big(FD, 0x01, 0x01, 0x20, 0x0000FF,
		    100, 10, 0, 0x02, 0, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");
}

/*
 * RTN 0xFF is OUTSIDE the spec range (0x00-0x1E, §7.8.103); the encoder
 * must reject it with EINVAL BEFORE any I/O.  0x1E is the accepted max.
 */
ATF_TC_WITHOUT_HEAD(create_big_rtn_reserved);
ATF_TC_BODY(create_big_rtn_reserved, tc)
{

	/* RTN 0xFF (reserved) -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
		ATF_CHECK_EQ(-1, hci_le_create_big(FD, 0x01, 0x01, 0x01, 0x0000FF,
		    100, 10, 0xFF, 0x02, 0, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* RTN 0x1E (max valid) -> accepted, forwarded at offset 10. */
	reset();
	mock_ok();
		ATF_CHECK_EQ(0, hci_le_create_big(FD, 0x01, 0x01, 0x01, 0x0000FF,
		    100, 10, 0x1E, 0x02, 0, 0, 0, NULL));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(0x1E, W.cmd[10]);
}

/*
 * PHY bitfield encoding (§7.8.103 PHY: bit0 LE 1M, bit1 LE 2M, bit2 LE
 * Coded).  Each single-bit value lands verbatim at command offset 11.
 */
ATF_TC_WITHOUT_HEAD(create_big_phy_bits);
ATF_TC_BODY(create_big_phy_bits, tc)
{
	uint8_t phy;

	for (phy = 0x01; phy <= 0x04; phy <<= 1) {
		reset();
		mock_ok();
			ATF_CHECK_EQ(0, hci_le_create_big(FD, 0x01, 0x01, 0x01,
			    0x0000FF, 100, 10, 0, phy, 0, 0, 0, NULL));
		ATF_CHECK_EQ(phy, W.cmd[11]);
	}
}

/* ================================================================
 * §7.8.105  LE Terminate BIG  (OCF 0x006A)  CP: BIG_Handle(1)|Reason(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(terminate_big_boundary);
ATF_TC_BODY(terminate_big_boundary, tc)
{

	reset();
	mock_ok();
	/* BIG_Handle max 0xEF; reason 0x13 Remote User Terminated Connection. */
	ATF_CHECK_EQ(0, hci_le_terminate_big(FD, 0xEF, 0x13));
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
	ATF_CHECK_EQ(0x13, W.cmd[1]);
}

/* ================================================================
 * §7.8.106  LE BIG Create Sync  (OCF 0x006B)
 * CP: BIG_Handle(1) | Sync_Handle(2 LE) | Encryption(1) |
 *     Broadcast_Code(16) | MSE(1) | BIG_Sync_Timeout(2 LE) | Num_BIS(1) |
 *     BIS[i](1) x Num_BIS.  Command Status.
 * ================================================================ */

/*
 * Field maxima.  Sync_Handle max 0x0EFF; MSE max 0x1F ("Range: 0x01 to
 * 0x1F"; 0x00 means "no preference"); BIG_Sync_Timeout max 0x4000
 * ("Range: 0x000A to 0x4000"); Num_BIS 0x1F with 31 BIS indices.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_maxima);
ATF_TC_BODY(big_create_sync_maxima, tc)
{
	uint8_t bcode[16];
	uint8_t bis[31];
	int i;

	for (i = 0; i < 16; i++)
		bcode[i] = (uint8_t)(0xA0 + i);
	for (i = 0; i < 31; i++)
		bis[i] = (uint8_t)(i + 1);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_create_sync(FD,
	    0xEF,		/* BIG_Handle max */
	    0x0EFF,		/* Sync_Handle max */
	    0x01,		/* Encryption */
	    bcode,
	    0x1F,		/* MSE max */
	    0x4000,		/* BIG_Sync_Timeout max */
	    0x1F,		/* Num_BIS max */
	    bis));
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)(24 + 31), W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(1));
	ATF_CHECK_EQ(0x01, W.cmd[3]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 4, bcode, 16));
	ATF_CHECK_EQ(0x1F, W.cmd[20]);
	ATF_CHECK_EQ(0x4000, cmd_le16(21));
	ATF_CHECK_EQ(0x1F, W.cmd[23]);
	for (i = 0; i < 31; i++)
		ATF_CHECK_EQ((uint8_t)(i + 1), W.cmd[24 + i]);
}

/*
	 * MSE "no preference" (0x00), BIG_Sync_Timeout minimum (0x000A),
	 * Encryption 0 with NULL broadcast_code, and Num_BIS minimum.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_minima_null);
ATF_TC_BODY(big_create_sync_minima_null, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_create_sync(FD,
	    0x00,		/* BIG_Handle min */
	    0x0000,		/* Sync_Handle min */
	    0x00,		/* Encryption off */
	    NULL,		/* NULL broadcast_code */
	    0x00,		/* MSE no preference */
		    0x000A,		/* BIG_Sync_Timeout min */
		    0x01,		/* Num_BIS min */
		    (uint8_t[]){ 0x01 }));
		ATF_CHECK_EQ((size_t)25, W.clen);
	ATF_CHECK_EQ(0x00, W.cmd[3]);
	ATF_CHECK_EQ(0x00, W.cmd[20]);
	ATF_CHECK_EQ(0x000A, cmd_le16(21));
		ATF_CHECK_EQ(0x01, W.cmd[23]);
	/* NULL code -> zeroed Broadcast_Code region. */
	uint8_t zero[16] = { 0 };
	ATF_CHECK_EQ(0, memcmp(W.cmd + 4, zero, 16));
}

/*
 * Num_BIS > 0 with a NULL bis_indices is invalid; the encoder must reject it
 * before I/O instead of emitting zero BIS indices.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_null_bis_nonzero);
ATF_TC_BODY(big_create_sync_null_bis_nonzero, tc)
{
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_big_create_sync(FD, 0x02, 0x0010, 0x00, NULL,
	    0x00, 0x0064, 0x03, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");
}

/*
 * BIG Create Sync range bound (§7.8.106).  Num_BIS is 0x01..0x1F.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_num_bis_bound);
ATF_TC_BODY(big_create_sync_num_bis_bound, tc)
{
	static uint8_t bis[32];
	uint8_t bcode[16];
	int i;

	for (i = 0; i < 32; i++)
		bis[i] = (uint8_t)(i + 1);
	memset(bcode, 0, sizeof(bcode));

	/* 32 -> outside the Core range -> EINVAL, no I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 32, bis));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 31 -> valid maximum. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 31, bis));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)(24 + 31), W.clen);
}

/* ================================================================
 * §7.8.109  LE Setup ISO Data Path  (OCF 0x006E)
 * CP: Connection_Handle(2 LE) | Data_Path_Direction(1) | Data_Path_ID(1) |
 *     Codec_ID(5) | Controller_Delay(3 LE) | Codec_Configuration_Length(1)
 *     | Codec_Configuration[len]
 * ================================================================ */

/*
	 * Direction = Output (0x01), Data_Path_ID = 0xFE (vendor-specific),
	 * Controller_Delay at Core 6.3 maximum 0x3D0900, Connection_Handle max.
 * Codec_ID copied verbatim (5 octets).
 */
ATF_TC_WITHOUT_HEAD(setup_iso_field_maxima);
ATF_TC_BODY(setup_iso_field_maxima, tc)
{
	uint8_t codec_id[5] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_setup_iso_data_path(FD,
		    0x0EFF,		/* Connection_Handle max */
		    0x01,		/* Direction = Output (Ctrlr->Host) */
		    0xFE,		/* Data_Path_ID max valid */
		    codec_id,
		    0x3D0900,		/* Controller_Delay max */
		    0, NULL));		/* no codec configuration */
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)13, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
	ATF_CHECK_EQ(0x01, W.cmd[2]);
	ATF_CHECK_EQ(0xFE, W.cmd[3]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 4, codec_id, 5));
	ATF_CHECK_EQ(0x3D0900u, cmd_le24(9));
	ATF_CHECK_EQ(0x00, W.cmd[12]);
}

/*
	 * Codec_ID is mandatory and a non-zero Codec_Configuration_Length must
	 * have backing bytes; both are rejected before command I/O.
 */
ATF_TC_WITHOUT_HEAD(setup_iso_null_codec);
ATF_TC_BODY(setup_iso_null_codec, tc)
{

	uint8_t codec_id[5] = { 0 };

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_iso_data_path(FD, 0x0060, 0x00, 0x00,
	    NULL, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_iso_data_path(FD, 0x0060, 0x00, 0x00,
	    codec_id, 0, 4, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);
}

/*
 * Codec_Configuration at the HCI packet maximum.  Section 7.8.109 has 13
 * fixed octets and §5.4.1 limits total command parameters to 255 octets,
 * so the largest encodable configuration is 242 octets.
 */
ATF_TC_WITHOUT_HEAD(setup_iso_codec_config_max);
ATF_TC_BODY(setup_iso_codec_config_max, tc)
{
	uint8_t codec_id[5] = { 0x01, 0, 0, 0, 0 };
	static uint8_t cfg[243];

	memset(cfg, 0xA7, sizeof(cfg));

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(0, hci_le_setup_iso_data_path(FD, 0x0060, 0x00, 0x00,
	    codec_id, 0x000000, 242, cfg));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)255, W.clen);
	ATF_CHECK_EQ(242, W.cmd[12]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 13, cfg, 242));

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_iso_data_path(FD, 0x0060, 0x00, 0x00,
	    codec_id, 0x000000, 243, cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);
}

/* ================================================================
 * §7.8.110  LE Remove ISO Data Path  (OCF 0x006F)
 * CP: Connection_Handle(2 LE) | Data_Path_Direction(1, bitfield)
 * ================================================================ */

/* Direction bitfield: bit0 = input, bit1 = output; each value distinct. */
ATF_TC_WITHOUT_HEAD(remove_iso_direction_bits);
ATF_TC_BODY(remove_iso_direction_bits, tc)
{
	uint8_t dir;

	for (dir = 0x01; dir <= 0x03; dir++) {
		reset();
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_remove_iso_data_path(FD, 0x0060, dir));
		ATF_CHECK_EQ((size_t)3, W.clen);
		ATF_CHECK_EQ(0x0060, cmd_le16(0));
		ATF_CHECK_EQ(dir, W.cmd[2]);
	}
}

/* Connection_Handle boundary values on Remove ISO Data Path. */
ATF_TC_WITHOUT_HEAD(remove_iso_handle_boundary);
ATF_TC_BODY(remove_iso_handle_boundary, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_remove_iso_data_path(FD, 0x0000, 0x01));
	ATF_CHECK_EQ(0x0000, cmd_le16(0));

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_remove_iso_data_path(FD, 0x0EFF, 0x02));
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
	ATF_CHECK_EQ(0x02, W.cmd[2]);
}

/* ================================================================
 * §7.8.108  LE Request Peer SCA  (OCF 0x006D)  CP: Connection_Handle(2)
 * Returns Command Status.  ISO-adjacent (SCA is a CIS timing input).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(request_peer_sca_encoding);
ATF_TC_BODY(request_peer_sca_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_request_peer_sca(FD, 0x0EFF));
	ATF_CHECK_EQ(BT_ISO_OP_REQUEST_PEER_SCA, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));

	CHECK_BAD(hci_le_request_peer_sca(FD, 0x0EFF));
	CHECK_XPORT(hci_le_request_peer_sca(FD, 0x0EFF));
}

/* ================================================================
 * §7.8.116  LE Read ISO Link Quality  (OCF 0x0075)
 * RP: Status(1) | Connection_Handle(2) | seven u32 counters (LE)
 * ================================================================ */

/* Return-parameter extraction with every counter at its u32 maximum. */
ATF_TC_WITHOUT_HEAD(read_iso_link_quality_max);
ATF_TC_BODY(read_iso_link_quality_max, tc)
{
	uint8_t rp[31];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0;

	memset(rp, 0xFF, sizeof(rp));	/* all counters = 0xFFFFFFFF */
	rp[0] = 0x00;			/* status */
	rp[1] = 0xFF; rp[2] = 0x0E;	/* connection_handle 0x0EFF */

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0EFF,
	    &a, &b, &c, &d, &e, &f, &g));
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
	ATF_CHECK_EQ(0xFFFFFFFFu, a);
	ATF_CHECK_EQ(0xFFFFFFFFu, b);
	ATF_CHECK_EQ(0xFFFFFFFFu, c);
	ATF_CHECK_EQ(0xFFFFFFFFu, d);
	ATF_CHECK_EQ(0xFFFFFFFFu, e);
	ATF_CHECK_EQ(0xFFFFFFFFu, f);
	ATF_CHECK_EQ(0xFFFFFFFFu, g);
}

/*
 * Core §7.8.116 defines the seven counters; accepting NULL destinations is
 * the local hci_util.h optional-output API contract.
 */
ATF_TC_WITHOUT_HEAD(read_iso_link_quality_null_outs);
ATF_TC_BODY(read_iso_link_quality_null_outs, tc)
{
	uint8_t rp[31];

	memset(rp, 0, sizeof(rp));

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0040,
	    NULL, NULL, NULL, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(1, W.calls);
}

/* ================================================================
 * hci_le_default_event_mask — feature-gated event bits.  Verify that the
 * Extended-Advertising and Periodic-Advertising feature groups add their
 * event bits, and that the ISO features combine correctly.  Bit positions
 * per Core Spec Vol 4 Part E §7.8.1 / the subevent codes in §7.7.65.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(default_event_mask_feature_gating);
ATF_TC_BODY(default_event_mask_feature_gating, tc)
{
	uint64_t m;

	/* Extended Advertising feature -> ext-adv event group. */
	m = hci_le_default_event_mask(BT_ISO_FEAT_EXT_ADVERTISING);
	ATF_CHECK((m & BT_ISO_MASK_EXT_ADV_REPORT) != 0);
	ATF_CHECK((m & BT_ISO_MASK_ADV_SET_TERM) != 0);
	ATF_CHECK((m & BT_ISO_MASK_SCAN_REQ_RCVD) != 0);

	/* Periodic Advertising feature -> per-adv event group. */
	m = hci_le_default_event_mask(BT_ISO_FEAT_PERIODIC_ADV);
	ATF_CHECK((m & BT_ISO_MASK_PER_ADV_SYNC_EST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_PER_ADV_REPORT) != 0);
	ATF_CHECK((m & BT_ISO_MASK_PER_ADV_SYNC_LOST) != 0);

	/* Both CIS roles at once -> both CIS events, no BIG events. */
	m = hci_le_default_event_mask(BT_ISO_FEAT_CIS_CENTRAL |
	    BT_ISO_FEAT_CIS_PERIPHERAL);
	ATF_CHECK((m & BT_ISO_MASK_CIS_ESTABLISHED) != 0);
	ATF_CHECK((m & BT_ISO_MASK_CIS_REQUEST) != 0);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CREATE_BIG));

	/* All ISO features together -> CIS + BIG event bits all set. */
	m = hci_le_default_event_mask(BT_ISO_FEAT_CIS_CENTRAL |
	    BT_ISO_FEAT_CIS_PERIPHERAL | BT_ISO_FEAT_BROADCASTER);
	ATF_CHECK((m & BT_ISO_MASK_CIS_ESTABLISHED) != 0);
	ATF_CHECK((m & BT_ISO_MASK_CIS_REQUEST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_CREATE_BIG) != 0);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_BIG_SYNC_LOST));
	m = hci_le_default_event_mask(BT_ISO_FEAT_SYNC_RECEIVER);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CREATE_BIG));
	ATF_CHECK((m & BT_ISO_MASK_BIG_SYNC_EST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_BIG_SYNC_LOST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_BIGINFO_REPORT) != 0);
}

/* ================================================================
 * Core Vol 4 Part E §§7.8.2 and 7.8.96-.116 define nonzero Status failure.
 * Mapping that failure to -1/EIO, and preserving bt_devreq errno, are local
 * hci_util.h API contracts.  These cases therefore have mixed authority.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_cig_error_arms);
ATF_TC_BODY(set_cig_error_arms, tc)
{
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[1] = { 0 };

	CHECK_BAD(hci_le_set_cig_params(FD, 0x01, 1000, 1000, 0, 0, 0, 10, 10,
	    0, NULL, 0, &out_cig, &out_cnt, handles));
	CHECK_XPORT(hci_le_set_cig_params(FD, 0x01, 1000, 1000, 0, 0, 0, 10, 10,
	    0, NULL, 0, &out_cig, &out_cnt, handles));
}

ATF_TC_WITHOUT_HEAD(create_cis_error_arms);
ATF_TC_BODY(create_cis_error_arms, tc)
{
	uint16_t cis_h[1] = { 0x0100 }, acl_h[1] = { 0x0001 };

	CHECK_BAD(hci_le_create_cis(FD, 1, cis_h, acl_h));
	CHECK_XPORT(hci_le_create_cis(FD, 1, cis_h, acl_h));
}

ATF_TC_WITHOUT_HEAD(create_big_error_arms);
ATF_TC_BODY(create_big_error_arms, tc)
{

	CHECK_BAD(hci_le_create_big(FD, 0x01, 0x01, 0x01, 0x0000FF, 100, 10, 0,
	    0x01, 0, 0, 0, NULL));
	CHECK_XPORT(hci_le_create_big(FD, 0x01, 0x01, 0x01, 0x0000FF, 100, 10,
	    0, 0x01, 0, 0, 0, NULL));
}

ATF_TC_WITHOUT_HEAD(big_create_sync_error_arms);
ATF_TC_BODY(big_create_sync_error_arms, tc)
{

	CHECK_BAD(hci_le_big_create_sync(FD, 0x00, 0x0001, 0, NULL, 0, 0x000A,
	    1, (uint8_t[]){ 1 }));
	CHECK_XPORT(hci_le_big_create_sync(FD, 0x00, 0x0001, 0, NULL, 0, 0x000A,
	    1, (uint8_t[]){ 1 }));
}

ATF_TC_WITHOUT_HEAD(setup_iso_error_arms);
ATF_TC_BODY(setup_iso_error_arms, tc)
{
	uint8_t codec_id[5] = { 0x03, 0, 0, 0, 0 };

	CHECK_BAD(hci_le_setup_iso_data_path(FD, 0x0060, 0, 0, codec_id, 0, 0,
	    NULL));
	CHECK_XPORT(hci_le_setup_iso_data_path(FD, 0x0060, 0, 0, codec_id, 0, 0,
	    NULL));
}

ATF_TC_WITHOUT_HEAD(remove_iso_error_arms);
ATF_TC_BODY(remove_iso_error_arms, tc)
{

	CHECK_BAD(hci_le_remove_iso_data_path(FD, 0x0060, 0x03));
	CHECK_XPORT(hci_le_remove_iso_data_path(FD, 0x0060, 0x03));
}

ATF_TC_WITHOUT_HEAD(remove_cig_error_arms);
ATF_TC_BODY(remove_cig_error_arms, tc)
{

	CHECK_BAD(hci_le_remove_cig(FD, 0x01));
	CHECK_XPORT(hci_le_remove_cig(FD, 0x01));
}

ATF_TC_WITHOUT_HEAD(accept_cis_error_arms);
ATF_TC_BODY(accept_cis_error_arms, tc)
{

	CHECK_BAD(hci_le_accept_cis_request(FD, 0x0060));
	CHECK_XPORT(hci_le_accept_cis_request(FD, 0x0060));
}

ATF_TC_WITHOUT_HEAD(reject_cis_error_arms);
ATF_TC_BODY(reject_cis_error_arms, tc)
{

	CHECK_BAD(hci_le_reject_cis_request(FD, 0x0060, 0x0D));
	CHECK_XPORT(hci_le_reject_cis_request(FD, 0x0060, 0x0D));
}

ATF_TC_WITHOUT_HEAD(terminate_big_error_arms);
ATF_TC_BODY(terminate_big_error_arms, tc)
{

	CHECK_BAD(hci_le_terminate_big(FD, 0x00, 0x16));
	CHECK_XPORT(hci_le_terminate_big(FD, 0x00, 0x16));
}

ATF_TC_WITHOUT_HEAD(big_terminate_sync_error_arms);
ATF_TC_BODY(big_terminate_sync_error_arms, tc)
{

	CHECK_BAD(hci_le_big_terminate_sync(FD, 0x00));
	CHECK_XPORT(hci_le_big_terminate_sync(FD, 0x00));
}

ATF_TC_WITHOUT_HEAD(read_iso_tx_sync_error_arms);
ATF_TC_BODY(read_iso_tx_sync_error_arms, tc)
{
	uint16_t seq = 0;
	uint32_t ts = 0, off = 0;

	CHECK_BAD(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	CHECK_XPORT(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
}

ATF_TC_WITHOUT_HEAD(read_iso_link_quality_error_arms);
ATF_TC_BODY(read_iso_link_quality_error_arms, tc)
{
	uint32_t a, b, c, d, e, f, g;

	CHECK_BAD(hci_le_read_iso_link_quality(FD, 0x0040, &a, &b, &c, &d, &e,
	    &f, &g));
	CHECK_XPORT(hci_le_read_iso_link_quality(FD, 0x0040, &a, &b, &c, &d, &e,
	    &f, &g));
}

ATF_TC_WITHOUT_HEAD(read_buffer_size_v2_error_arms);
ATF_TC_BODY(read_buffer_size_v2_error_arms, tc)
{
	uint16_t al, il;
	uint8_t an, in;

	CHECK_BAD(hci_le_read_buffer_size_v2(FD, &al, &an, &il, &in));
	CHECK_XPORT(hci_le_read_buffer_size_v2(FD, &al, &an, &il, &in));
}

ATF_TC_WITHOUT_HEAD(big_terminate_sync_encoding);
ATF_TC_BODY(big_terminate_sync_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_terminate_sync(FD, 0xEF));
	ATF_CHECK_EQ(BT_ISO_OP_BIG_TERMINATE_SYNC, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)1, W.clen);
	ATF_CHECK_EQ(0xEF, W.cmd[0]);
}

ATF_TC_WITHOUT_HEAD(accept_cis_encoding);
ATF_TC_BODY(accept_cis_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_accept_cis_request(FD, 0x0EFF));
	ATF_CHECK_EQ(BT_ISO_OP_ACCEPT_CIS, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0EFF, cmd_le16(0));
}

ATF_TC_WITHOUT_HEAD(set_cig_params_test_encoding);
ATF_TC_BODY(set_cig_params_test_encoding, tc)
{
	/* §7.8.98 command/return tables: fixed 15-byte header + 14 per CIS. */
	const struct hci_le_cig_params_test_cis cis[2] = {
		{
			.cis_id = 0x11,
			.nse = 0x03,
			.max_sdu_c_to_p = 0x0123,
			.max_sdu_p_to_c = 0x0456,
			.max_pdu_c_to_p = 0x0078,
			.max_pdu_p_to_c = 0x009A,
			.phy_c_to_p = 0x01,
			.phy_p_to_c = 0x02,
			.bn_c_to_p = 0x04,
			.bn_p_to_c = 0x05,
		},
		{
			.cis_id = 0x22,
			.nse = 0x1F,
			.max_sdu_c_to_p = 0x0FFF,
			.max_sdu_p_to_c = 0,
			.max_pdu_c_to_p = 0x00FB,
			.max_pdu_p_to_c = 0,
			.phy_c_to_p = 0x04,
			.phy_p_to_c = 0x04,
			.bn_c_to_p = 0x0F,
			.bn_p_to_c = 0,
		},
	};
	const uint8_t rp[] = {
		0x00, 0x33, 0x02, 0x40, 0x00, 0x41, 0x00,
	};
	uint8_t cig_id = 0, cis_count = 0;
	uint16_t handles[2] = { 0, 0 };

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params_test(FD, 0x33, 0x0000FF,
	    0x0FFFFF, 0x01, 0xFF, 0x0C80, 0x07, 0x01, 0x02, 2, cis,
	    &cig_id, &cis_count, handles));
	ATF_CHECK_EQ(BT_ISO_OP_SET_CIG_PARAMS_TEST, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)(15 + 2 * 14), W.clen);
	ATF_CHECK_EQ(0x33, W.cmd[0]);
	ATF_CHECK_EQ(0x0000FF, cmd_le24(1));
	ATF_CHECK_EQ(0x0FFFFF, cmd_le24(4));
	ATF_CHECK_EQ(0x01, W.cmd[7]);
	ATF_CHECK_EQ(0xFF, W.cmd[8]);
	ATF_CHECK_EQ(0x0C80, cmd_le16(9));
	ATF_CHECK_EQ(0x07, W.cmd[11]);
	ATF_CHECK_EQ(0x01, W.cmd[12]);
	ATF_CHECK_EQ(0x02, W.cmd[13]);
	ATF_CHECK_EQ(0x02, W.cmd[14]);
	ATF_CHECK_EQ(0x11, W.cmd[15]);
	ATF_CHECK_EQ(0x03, W.cmd[16]);
	ATF_CHECK_EQ(0x0123, cmd_le16(17));
	ATF_CHECK_EQ(0x0456, cmd_le16(19));
	ATF_CHECK_EQ(0x0078, cmd_le16(21));
	ATF_CHECK_EQ(0x009A, cmd_le16(23));
	ATF_CHECK_EQ(0x01, W.cmd[25]);
	ATF_CHECK_EQ(0x02, W.cmd[26]);
	ATF_CHECK_EQ(0x04, W.cmd[27]);
	ATF_CHECK_EQ(0x05, W.cmd[28]);
	ATF_CHECK_EQ(0x22, W.cmd[29]);
	ATF_CHECK_EQ(0x1F, W.cmd[30]);
	ATF_CHECK_EQ(0x0FFF, cmd_le16(31));
	ATF_CHECK_EQ(0x0000, cmd_le16(33));
	ATF_CHECK_EQ(0x00FB, cmd_le16(35));
	ATF_CHECK_EQ(0x0000, cmd_le16(37));
	ATF_CHECK_EQ(0x04, W.cmd[39]);
	ATF_CHECK_EQ(0x04, W.cmd[40]);
	ATF_CHECK_EQ(0x0F, W.cmd[41]);
	ATF_CHECK_EQ(0x00, W.cmd[42]);
	ATF_CHECK_EQ(0x33, cig_id);
	ATF_CHECK_EQ(0x02, cis_count);
	ATF_CHECK_EQ(0x0040, handles[0]);
	ATF_CHECK_EQ(0x0041, handles[1]);
}

ATF_TC_WITHOUT_HEAD(set_cig_params_test_validation);
ATF_TC_BODY(set_cig_params_test_validation, tc)
{
	/* §7.8.98 parameter ranges; EINVAL/no-I/O is the local API contract. */
	struct hci_le_cig_params_test_cis cis = {
		.cis_id = 0x01,
		.nse = 0x01,
		.max_sdu_c_to_p = 1,
		.max_sdu_p_to_c = 1,
		.max_pdu_c_to_p = 1,
		.max_pdu_p_to_c = 1,
		.phy_c_to_p = 0x01,
		.phy_p_to_c = 0x01,
		.bn_c_to_p = 1,
		.bn_p_to_c = 1,
	};

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0xF0, 0x0000FF,
	    0x0000FF, 1, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0, 0x0000FE,
	    0x0000FF, 1, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0, 0x0000FF,
	    0x0000FF, 0, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0, 0x0000FF,
	    0x0000FF, 1, 1, 3, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	cis.phy_c_to_p = 0x03;
	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0, 0x0000FF,
	    0x0000FF, 1, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);
	cis.phy_c_to_p = 0x01;

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params_test(FD, 0, 0x0000FF,
	    0x0000FF, 1, 1, 4, 0, 0, 0, 1, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	CHECK_BAD(hci_le_set_cig_params_test(FD, 0, 0x0000FF, 0x0000FF,
	    1, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
	CHECK_XPORT(hci_le_set_cig_params_test(FD, 0, 0x0000FF, 0x0000FF,
	    1, 1, 4, 0, 0, 0, 1, &cis, NULL, NULL, NULL));
}

ATF_TC_WITHOUT_HEAD(create_big_test_encoding);
ATF_TC_BODY(create_big_test_encoding, tc)
{
	/* §7.8.104 command table: exact 36-octet parameter sequence. */
	const uint8_t bcode[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_big_test(FD, 0x01, 0x02, 0x03,
	    0x010203, 0x0456, 0x07, 0x0809, 0x00FA, 0x04, 0x01, 0x02,
	    0x06, 0x05, 0x04, 0x01, bcode));
	ATF_CHECK_EQ(BT_ISO_OP_CREATE_BIG_TEST, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)36, W.clen);
	ATF_CHECK_EQ(0x01, W.cmd[0]);
	ATF_CHECK_EQ(0x02, W.cmd[1]);
	ATF_CHECK_EQ(0x03, W.cmd[2]);
	ATF_CHECK_EQ(0x010203, cmd_le24(3));
	ATF_CHECK_EQ(0x0456, cmd_le16(6));
	ATF_CHECK_EQ(0x07, W.cmd[8]);
	ATF_CHECK_EQ(0x0809, cmd_le16(9));
	ATF_CHECK_EQ(0x00FA, cmd_le16(11));
	ATF_CHECK_EQ(0x04, W.cmd[13]);
	ATF_CHECK_EQ(0x01, W.cmd[14]);
	ATF_CHECK_EQ(0x02, W.cmd[15]);
	ATF_CHECK_EQ(0x06, W.cmd[16]);
	ATF_CHECK_EQ(0x05, W.cmd[17]);
	ATF_CHECK_EQ(0x04, W.cmd[18]);
	ATF_CHECK_EQ(0x01, W.cmd[19]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 20, bcode, sizeof(bcode)));
}

ATF_TC_WITHOUT_HEAD(create_big_test_validation);
ATF_TC_BODY(create_big_test_validation, tc)
{
	/* §7.8.104 parameter ranges; EINVAL/no-I/O is the local API contract. */
	const uint8_t bcode[16] = { 1 };
	const uint8_t zcode[16] = { 0 };

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0xF0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 0, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FE,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    3, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 3, 0, 0, 1, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0x10, 0, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, bcode));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF,
	    4, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, zcode));
	ATF_CHECK_EQ(BT_ISO_OP_CREATE_BIG_TEST, W.opcode);

	CHECK_BAD(hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF, 4, 1, 1,
	    1, 1, 0, 0, 1, 1, 0, 0, NULL));
	CHECK_XPORT(hci_le_create_big_test(FD, 0, 0, 1, 0x0000FF, 4, 1, 1,
	    1, 1, 0, 0, 1, 1, 0, 0, NULL));
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Read Buffer Size v2 (§7.8.2). */
	ATF_TP_ADD_TC(tp, read_buffer_size_v2_extract);
	ATF_TP_ADD_TC(tp, read_buffer_size_v2_null_outs);
	ATF_TP_ADD_TC(tp, read_buffer_size_v2_error_arms);

	/* Read ISO TX Sync (§7.8.96). */
	ATF_TP_ADD_TC(tp, read_iso_tx_sync_rp_max);
	ATF_TP_ADD_TC(tp, read_iso_tx_sync_rp_zero);
	ATF_TP_ADD_TC(tp, read_iso_tx_sync_null_outs);
	ATF_TP_ADD_TC(tp, read_iso_tx_sync_error_arms);

	/* Set CIG Parameters (§7.8.97). */
	ATF_TP_ADD_TC(tp, set_cig_field_maxima);
	ATF_TP_ADD_TC(tp, set_cig_field_minima_reserved);
	ATF_TP_ADD_TC(tp, set_cig_cis_count_reserved);
	ATF_TP_ADD_TC(tp, set_cig_cig_id_reserved);
	ATF_TP_ADD_TC(tp, set_cig_rp_31_handles);
	ATF_TP_ADD_TC(tp, set_cig_rp_count_clamp);
	ATF_TP_ADD_TC(tp, set_cig_rp_caller_short);
	ATF_TP_ADD_TC(tp, set_cig_null_outs);
	ATF_TP_ADD_TC(tp, set_cig_error_arms);
	ATF_TP_ADD_TC(tp, set_cig_params_test_encoding);
	ATF_TP_ADD_TC(tp, set_cig_params_test_validation);

	/* Create CIS (§7.8.99). */
	ATF_TP_ADD_TC(tp, create_cis_max_handles);
	ATF_TP_ADD_TC(tp, create_cis_count_reject);
	ATF_TP_ADD_TC(tp, create_cis_error_arms);

	/* Remove CIG / Accept / Reject CIS (§7.8.100-102). */
	ATF_TP_ADD_TC(tp, remove_cig_boundary);
	ATF_TP_ADD_TC(tp, remove_cig_error_arms);
	ATF_TP_ADD_TC(tp, accept_cis_encoding);
	ATF_TP_ADD_TC(tp, accept_cis_error_arms);
	ATF_TP_ADD_TC(tp, reject_cis_reason_encoding);
	ATF_TP_ADD_TC(tp, reject_cis_error_arms);

	/* Create BIG (§7.8.103). */
	ATF_TP_ADD_TC(tp, create_big_field_maxima);
	ATF_TP_ADD_TC(tp, create_big_minima_nullcode);
	ATF_TP_ADD_TC(tp, create_big_num_bis_reserved);
	ATF_TP_ADD_TC(tp, create_big_rtn_reserved);
	ATF_TP_ADD_TC(tp, create_big_phy_bits);
	ATF_TP_ADD_TC(tp, create_big_error_arms);
	ATF_TP_ADD_TC(tp, create_big_test_encoding);
	ATF_TP_ADD_TC(tp, create_big_test_validation);

	/* Terminate BIG (§7.8.105). */
	ATF_TP_ADD_TC(tp, terminate_big_boundary);
	ATF_TP_ADD_TC(tp, terminate_big_error_arms);

	/* BIG Create Sync (§7.8.106). */
	ATF_TP_ADD_TC(tp, big_create_sync_maxima);
	ATF_TP_ADD_TC(tp, big_create_sync_minima_null);
	ATF_TP_ADD_TC(tp, big_create_sync_null_bis_nonzero);
	ATF_TP_ADD_TC(tp, big_create_sync_num_bis_bound);
	ATF_TP_ADD_TC(tp, big_create_sync_error_arms);

	/* BIG Terminate Sync (§7.8.107). */
	ATF_TP_ADD_TC(tp, big_terminate_sync_encoding);
	ATF_TP_ADD_TC(tp, big_terminate_sync_error_arms);

	/* Setup ISO Data Path (§7.8.109). */
	ATF_TP_ADD_TC(tp, setup_iso_field_maxima);
	ATF_TP_ADD_TC(tp, setup_iso_null_codec);
	ATF_TP_ADD_TC(tp, setup_iso_codec_config_max);
	ATF_TP_ADD_TC(tp, setup_iso_error_arms);

	/* Remove ISO Data Path (§7.8.110). */
	ATF_TP_ADD_TC(tp, remove_iso_direction_bits);
	ATF_TP_ADD_TC(tp, remove_iso_handle_boundary);
	ATF_TP_ADD_TC(tp, remove_iso_error_arms);

	/* Request Peer SCA (§7.8.108). */
	ATF_TP_ADD_TC(tp, request_peer_sca_encoding);

	/* Read ISO Link Quality (§7.8.116). */
	ATF_TP_ADD_TC(tp, read_iso_link_quality_max);
	ATF_TP_ADD_TC(tp, read_iso_link_quality_null_outs);
	ATF_TP_ADD_TC(tp, read_iso_link_quality_error_arms);

	/* Event mask feature gating. */
	ATF_TP_ADD_TC(tp, default_event_mask_feature_gating);

	return (atf_no_error());
}
