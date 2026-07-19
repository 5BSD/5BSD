/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Conformance tests for the LE Isochronous (ISO) TRANSPORT layer
 * (Bluetooth Core Specification 5.2): the CIS/BIG/ISO-data-path HCI
 * commands, their return-parameter extraction, and the ISO meta-event
 * byte layout.  Scope is the isochronous TRANSPORT only: the LE Audio
 * profiles (BAP/ASCS/PACS/CAP/VCP/...) are explicitly out of scope.
 *
 * Oracle.  Every command byte layout, every return-parameter offset and
 * every event field offset asserted here is hand-encoded from the Core
 * Spec Vol 4 Part E (command formats §7.8.96-7.8.116; event formats
 * §7.7.65.25-34), cited per assertion — never captured from the
 * implementation's own output.
 *
 * Method.  The ISO command encoders in hci_misc.c reach the controller
 * through hci_devreq_logged() -> hci_devreq_logged_locked() (hci_util.c)
 * -> bt_devreq() (libbluetooth).  We interpose bt_devreq at link time
 * (-Wl,--wrap=bt_devreq); __wrap_bt_devreq (a) records the command
 * opcode / expected-event / cparam bytes the encoder built, so we can
 * assert the on-wire layout against the spec, and (b) returns a
 * test-controlled Command Complete / Command Status so the post-I/O arms
 * (status!=0 rejection, success tail, return-param extraction) run.
 *
 * A per-call counter (C.calls) lets the boundary tests prove that
 * host-side parameter rejection returns EINVAL *before* any I/O: a
 * rejected command must leave C.calls unchanged.
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
#include "blued_le_meta.h"
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
	/* Controller response the encoder will read back. */
	int		fail;		/* nonzero -> return -1, errno */
	int		fail_errno;
	uint8_t		payload[320];	/* return params, status byte first */
	size_t		payload_len;

	/* Capture of the command the encoder built (the request). */
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

	/* Record the request unconditionally (even on simulated failure). */
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

/* Reset all capture/response state before a scenario. */
static void
reset(void)
{

	memset(&W, 0, sizeof(W));
}

/* Controller returns Command Complete carrying return-parameter bytes. */
static void
mock_ok_bytes(const void *p, size_t n)
{
	W.fail = 0;
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

/* Controller accepts: status 0x00, no further return parameters. */
static void
mock_ok(void)
{
	uint8_t st = BT_ISO_STATUS_SUCCESS;

	mock_ok_bytes(&st, 1);
}

/* Controller rejects: status 0x0C = Command Disallowed
 * (Core Spec Vol 1 Part F §1.3 error code table). */
static void
mock_status_bad(void)
{
	uint8_t st = BT_ISO_ERROR_COMMAND_DISALLOWED;

	mock_ok_bytes(&st, 1);
}

/* Transport failure: bt_devreq itself fails (e.g. recv error). */
static void
mock_xport_fail(int e)
{
	W.fail = 1;
	W.fail_errno = e;
}

/* Little-endian field readers over the captured command buffer. */
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
 * Three-arm success/reject/transport coverage for a status-only command.
 * Every ISO call below is idempotent because all I/O is mocked.
 */
#define CHECK_OK(call)		do {					\
	reset(); mock_ok();						\
	ATF_CHECK_EQ_MSG(0, (call), "success arm: expected 0");		\
} while (0)

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

#define CHECK_EINVAL(call)	do {					\
	reset(); mock_ok(); errno = 0;					\
	ATF_CHECK_EQ_MSG(-1, (call), "EINVAL arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EINVAL, errno, "EINVAL arm: expected EINVAL");	\
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");	\
} while (0)

#define CHECK_ALL(call)		do {					\
	CHECK_OK(call);							\
	CHECK_BAD(call);						\
	CHECK_XPORT(call);						\
} while (0)

/* ================================================================
 * §7.8.96  LE Read ISO TX Sync  (OCF 0x0061)
 * CP: Connection_Handle(2 LE)
 * RP: Status(1) | Connection_Handle(2) | Packet_Sequence_Number(2) |
 *     TX_Time_Stamp(4) | Time_Offset(3 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync);
ATF_TC_BODY(read_iso_tx_sync, tc)
{
	uint8_t rp[12] = {
		0x00,			/* status */
		0x40, 0x00,		/* connection_handle 0x0040 */
		0x34, 0x12,		/* seq = 0x1234 */
		0xEF, 0xCD, 0xAB, 0x89,	/* ts = 0x89ABCDEF */
		0x01, 0x02, 0x03	/* time_offset = 0x030201 (3 octets LE) */
	};
	uint16_t seq = 0;
	uint32_t ts = 0, off = 0;

	/* Success arm + return-parameter extraction per §7.8.96. */
	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(BT_ISO_OP_READ_TX_SYNC, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	/* CP: Connection_Handle little-endian. */
	ATF_CHECK_EQ(2, W.clen);
	ATF_CHECK_EQ(0x0040, cmd_le16(0));
	/* RP extraction. */
	ATF_CHECK_EQ(0x1234, seq);
	ATF_CHECK_EQ(0x89ABCDEF, ts);
	ATF_CHECK_EQ(0x00030201, off);	/* 3-octet field, high byte zero */

	CHECK_BAD(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	CHECK_XPORT(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
}

/* ================================================================
 * §7.8.97  LE Set CIG Parameters  (OCF 0x0062)
 * CP header: CIG_ID(1) | SDU_Interval_C_To_P(3 LE) | SDU_Interval_P_To_C(3
 *   LE) | Worst_Case_SCA(1) | Packing(1) | Framing(1) |
 *   Max_Transport_Latency_C_To_P(2 LE) | Max_Transport_Latency_P_To_C(2 LE)
 *   | CIS_Count(1) | <CIS_Count CIS parameter records>
 * RP: Status(1) | CIG_ID(1) | CIS_Count(1) | Connection_Handle[i](2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_cig_params_encoding);
ATF_TC_BODY(set_cig_params_encoding, tc)
{
	/* Two 9-byte CIS parameter records with a recognisable pattern. */
	uint8_t cis_params[18];
	uint8_t rp[5] = { 0x00, 0xA5, 0x02, 0x60, 0x00 };
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[2] = { 0, 0 };
	int i;

	for (i = 0; i < (int)sizeof(cis_params); i++)
		cis_params[i] = (uint8_t)(0x40 + i);

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	/* Distinctive header field values, all multi-byte fields LE. */
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD,
	    0xA5,		/* CIG_ID */
	    0x030201,		/* SDU_Interval_C_To_P */
	    0x0C0B0A,		/* SDU_Interval_P_To_C */
	    0x07,		/* Worst_Case_SCA */
	    0x01,		/* Packing = interleaved */
	    0x01,		/* Framing = framed */
		    0x0123,		/* Max_Transport_Latency_C_To_P */
		    0x0456,		/* Max_Transport_Latency_P_To_C */
	    0x02,		/* CIS_Count */
	    cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));

	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ(BT_ISO_OP_SET_CIG_PARAMS, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	/* clen = 15-byte header + CIS records. */
	ATF_CHECK_EQ((size_t)(15 + 18), W.clen);
	ATF_CHECK_EQ(0xA5, W.cmd[0]);
	ATF_CHECK_EQ(0x030201u, cmd_le24(1));
	ATF_CHECK_EQ(0x0C0B0Au, cmd_le24(4));
	ATF_CHECK_EQ(0x07, W.cmd[7]);
	ATF_CHECK_EQ(0x01, W.cmd[8]);
	ATF_CHECK_EQ(0x01, W.cmd[9]);
		ATF_CHECK_EQ(0x0123, cmd_le16(10));
		ATF_CHECK_EQ(0x0456, cmd_le16(12));
	ATF_CHECK_EQ(0x02, W.cmd[14]);
	/* CIS parameter records copied verbatim after the header. */
	ATF_CHECK_EQ(0, memcmp(W.cmd + 15, cis_params, sizeof(cis_params)));

	/* RP extraction per §7.8.97 (status at rpbuf[0]). */
	ATF_CHECK_EQ(0xA5, out_cig);
	ATF_CHECK_EQ(0x02, out_cnt);
	ATF_CHECK_EQ(0x0060, handles[0]);

	/* Rejection uses the return-buffer status byte, mapped to EIO. */
	reset();
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0xA5, 0x030201, 0x0C0B0A,
	    0x07, 0x01, 0x01, 0x0123, 0x0456, 0x02, cis_params,
	    sizeof(cis_params), &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EIO, errno);

	reset();
	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0xA5, 0x030201, 0x0C0B0A,
	    0x07, 0x01, 0x01, 0x0123, 0x0456, 0x02, cis_params,
	    sizeof(cis_params), &out_cig, &out_cnt, handles));
}

/*
 * §7.8.97 buffer-length bound.  The command buffer holds the 15-byte header
 * plus the maximum 31 CIS parameter records of 9 bytes each = 15 + 279 = 294.
 * The encoder's host-side rejection is cmdlen (= 15 + cis_params_len) >
 * sizeof(cmd) (294) -> EINVAL before I/O.  cis_params_len = 280 overflows
 * (295 > 294); 279 is the exact fit (294) and corresponds to a spec-legal
 * 31-CIS group (31 * 9), which must NOT be rejected.
	 * Host-side validation also rejects mismatched CIS_Count/record lengths.
	 */
ATF_TC_WITHOUT_HEAD(set_cig_params_buflen);
ATF_TC_BODY(set_cig_params_buflen, tc)
{
	static uint8_t big[280];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[31] = { 0 };

	memset(big, 0, sizeof(big));

	/* Overflow (15 + 280 = 295 > 294) -> EINVAL, no I/O issued. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x00, 1000, 1000, 0, 0, 0,
	    10, 10, 1, big, 280, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* Exact-fit length (15 + 279 = 294, a full 31-CIS group) is accepted. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x00, 1000, 1000, 0, 0, 0,
	    10, 10, 31, big, 279, &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)(BT_ISO_SET_CIG_HEADER_LEN +
	    BT_ISO_STREAM_COUNT_MAX * BT_ISO_CIS_PARAM_LEN), W.clen);
}

/* ================================================================
 * §7.8.99  LE Create CIS  (OCF 0x0064)
 * CP: CIS_Count(1) | { CIS_Connection_Handle(2 LE) |
 *     ACL_Connection_Handle(2 LE) } x CIS_Count
 * Returns Command Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(create_cis_encoding);
ATF_TC_BODY(create_cis_encoding, tc)
{
	uint16_t cis_h[2] = { 0x0100, 0x0101 };
	uint16_t acl_h[2] = { 0x0001, 0x0002 };

	/* One pair. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_cis(FD, 1, cis_h, acl_h));
	ATF_CHECK_EQ(BT_ISO_OP_CREATE_CIS, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)(1 + 4), W.clen);
	ATF_CHECK_EQ(1, W.cmd[0]);
	ATF_CHECK_EQ(0x0100, cmd_le16(1));	/* CIS handle */
	ATF_CHECK_EQ(0x0001, cmd_le16(3));	/* ACL handle */

	/* Two pairs, order preserved. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_cis(FD, 2, cis_h, acl_h));
	ATF_CHECK_EQ((size_t)(1 + 8), W.clen);
	ATF_CHECK_EQ(2, W.cmd[0]);
	ATF_CHECK_EQ(0x0100, cmd_le16(1));
	ATF_CHECK_EQ(0x0001, cmd_le16(3));
	ATF_CHECK_EQ(0x0101, cmd_le16(5));
	ATF_CHECK_EQ(0x0002, cmd_le16(7));

	CHECK_BAD(hci_le_create_cis(FD, 1, cis_h, acl_h));
	CHECK_XPORT(hci_le_create_cis(FD, 1, cis_h, acl_h));
}

/*
 * §7.8.99 CIS_Count bound.  The encoder rejects CIS_Count == 0 and
 * CIS_Count > 0x1F (31) with EINVAL before I/O; 31 is the accepted max.
 */
ATF_TC_WITHOUT_HEAD(create_cis_count_bounds);
ATF_TC_BODY(create_cis_count_bounds, tc)
{
	uint16_t cis_h[31], acl_h[31];
	int i;

	for (i = 0; i < 31; i++) {
		cis_h[i] = (uint16_t)(0x0100 + i);
		acl_h[i] = (uint16_t)(0x0001 + i);
	}

	/* Zero -> EINVAL before I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_cis(FD, 0, cis_h, acl_h));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 32 (> 0x1F) -> EINVAL before I/O. */
	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_create_cis(FD, 32, cis_h, acl_h));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.calls, "EINVAL must precede any I/O");

	/* 31 (0x1F) -> accepted, clen = 1 + 31*4 = 125. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_cis(FD, 31, cis_h, acl_h));
	ATF_CHECK_EQ(1, W.calls);
	ATF_CHECK_EQ((size_t)(1 + 31 * 4), W.clen);
	ATF_CHECK_EQ(31, W.cmd[0]);
}

/* ================================================================
 * §7.8.100  LE Remove CIG  (OCF 0x0065)   CP: CIG_ID(1)
 * §7.8.101  LE Accept CIS Request (OCF 0x0066)  CP: Connection_Handle(2)
 * §7.8.102  LE Reject CIS Request (OCF 0x0067)  CP: Conn_Handle(2)|Reason(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(remove_cig_encoding);
ATF_TC_BODY(remove_cig_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_remove_cig(FD, 0xA5));
	ATF_CHECK_EQ(BT_ISO_OP_REMOVE_CIG, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)1, W.clen);
	ATF_CHECK_EQ(0xA5, W.cmd[0]);

	CHECK_BAD(hci_le_remove_cig(FD, 0xA5));
	CHECK_XPORT(hci_le_remove_cig(FD, 0xA5));
	CHECK_EINVAL(hci_le_remove_cig(FD, BT_ISO_GROUP_HANDLE_MAX + 1));
}

ATF_TC_WITHOUT_HEAD(accept_cis_request_encoding);
ATF_TC_BODY(accept_cis_request_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_accept_cis_request(FD, 0x0EA1));
	ATF_CHECK_EQ(BT_ISO_OP_ACCEPT_CIS, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0EA1, cmd_le16(0));

	CHECK_BAD(hci_le_accept_cis_request(FD, 0x0EA1));
	CHECK_XPORT(hci_le_accept_cis_request(FD, 0x0EA1));
}

ATF_TC_WITHOUT_HEAD(reject_cis_request_encoding);
ATF_TC_BODY(reject_cis_request_encoding, tc)
{

	reset();
	mock_ok();
	/* Reason 0x0D = Connection Rejected due to Limited Resources. */
	ATF_CHECK_EQ(0, hci_le_reject_cis_request(FD, 0x0EA1,
	    BT_ISO_ERROR_LIMITED_RESOURCES));
	ATF_CHECK_EQ(BT_ISO_OP_REJECT_CIS, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)3, W.clen);
	ATF_CHECK_EQ(0x0EA1, cmd_le16(0));
	ATF_CHECK_EQ(BT_ISO_ERROR_LIMITED_RESOURCES, W.cmd[2]);

	CHECK_BAD(hci_le_reject_cis_request(FD, 0x0EA1,
	    BT_ISO_ERROR_LIMITED_RESOURCES));
	CHECK_XPORT(hci_le_reject_cis_request(FD, 0x0EA1,
	    BT_ISO_ERROR_LIMITED_RESOURCES));
}

/* ================================================================
 * §7.8.103  LE Create BIG  (OCF 0x0068)   fixed 31-byte CP:
 * BIG_Handle(1) | Advertising_Handle(1) | Num_BIS(1) | SDU_Interval(3 LE) |
 * Max_SDU(2 LE) | Max_Transport_Latency(2 LE) | RTN(1) | PHY(1) |
 * Packing(1) | Framing(1) | Encryption(1) | Broadcast_Code(16)
 * Returns Command Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(create_big_encoding);
ATF_TC_BODY(create_big_encoding, tc)
{
	uint8_t bcode[16];
	int i;

	for (i = 0; i < 16; i++)
		bcode[i] = (uint8_t)(0xB0 + i);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_big(FD,
	    0x03,		/* BIG_Handle */
	    0x07,		/* Advertising_Handle */
	    0x02,		/* Num_BIS */
	    0x0186A0,		/* SDU_Interval = 100000 us */
	    0x00FB,		/* Max_SDU */
	    0x0FA0,		/* Max_Transport_Latency */
	    0x04,		/* RTN */
	    0x02,		/* PHY = LE 2M */
	    0x01,		/* Packing = interleaved */
	    0x01,		/* Framing = framed */
	    0x01,		/* Encryption */
	    bcode));

	ATF_CHECK_EQ(BT_ISO_OP_CREATE_BIG, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)BT_ISO_CREATE_BIG_LEN, W.clen);
	ATF_CHECK_EQ(0x03, W.cmd[0]);
	ATF_CHECK_EQ(0x07, W.cmd[1]);
	ATF_CHECK_EQ(0x02, W.cmd[2]);
	ATF_CHECK_EQ(0x0186A0u, cmd_le24(3));
	ATF_CHECK_EQ(0x00FB, cmd_le16(6));
	ATF_CHECK_EQ(0x0FA0, cmd_le16(8));
	ATF_CHECK_EQ(0x04, W.cmd[10]);
	ATF_CHECK_EQ(BT_ISO_PHY_2M, W.cmd[11]);
	ATF_CHECK_EQ(BT_ISO_PACKING_INTERLEAVED, W.cmd[12]);
	ATF_CHECK_EQ(BT_ISO_FRAMING_FRAMED, W.cmd[13]);
	ATF_CHECK_EQ(BT_ISO_ENCRYPTION_ENABLED, W.cmd[14]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 15, bcode, 16));

	CHECK_BAD(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_XPORT(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0xF0, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0xF0, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0000FE, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0004, 0x04, 0x02, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x08, 0x01, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x02, 0x01, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x03, 0x01, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x00, bcode));
	CHECK_EINVAL(hci_le_create_big(FD, 0x03, 0x07, 0x02, 0x0186A0, 0x00FB,
	    0x0FA0, 0x04, 0x02, 0x01, 0x01, 0x01, NULL));
}

/* ================================================================
 * §7.8.105  LE Terminate BIG  (OCF 0x006A)  CP: BIG_Handle(1)|Reason(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(terminate_big_encoding);
ATF_TC_BODY(terminate_big_encoding, tc)
{

	reset();
	mock_ok();
	/* Reason 0x16 = Connection Terminated By Local Host. */
	ATF_CHECK_EQ(0, hci_le_terminate_big(FD, 0x03,
	    BT_ISO_ERROR_LOCAL_HOST));
	ATF_CHECK_EQ(BT_ISO_OP_TERMINATE_BIG, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x03, W.cmd[0]);
	ATF_CHECK_EQ(BT_ISO_ERROR_LOCAL_HOST, W.cmd[1]);

	CHECK_BAD(hci_le_terminate_big(FD, 0x03, BT_ISO_ERROR_LOCAL_HOST));
	CHECK_XPORT(hci_le_terminate_big(FD, 0x03,
	    BT_ISO_ERROR_LOCAL_HOST));
	CHECK_EINVAL(hci_le_terminate_big(FD, BT_ISO_GROUP_HANDLE_MAX + 1,
	    BT_ISO_ERROR_LOCAL_HOST));
}

/* ================================================================
 * §7.8.106  LE BIG Create Sync  (OCF 0x006B)   CP:
 * BIG_Handle(1) | Sync_Handle(2 LE) | Encryption(1) | Broadcast_Code(16) |
 * MSE(1) | BIG_Sync_Timeout(2 LE) | Num_BIS(1) | BIS[i](1) x Num_BIS
 * Returns Command Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(big_create_sync_encoding);
ATF_TC_BODY(big_create_sync_encoding, tc)
{
	uint8_t bcode[16];
	uint8_t bis[3] = { 0x01, 0x02, 0x03 };
	int i;

	for (i = 0; i < 16; i++)
		bcode[i] = (uint8_t)(0xC0 + i);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_create_sync(FD,
	    0x03,		/* BIG_Handle */
	    BT_ISO_HANDLE_MAX,	/* Sync_Handle */
	    BT_ISO_ENCRYPTION_ENABLED,
	    bcode,
	    BT_ISO_MSE_MAX,	/* MSE */
	    0x4000,		/* BIG_Sync_Timeout */
	    0x03,		/* Num_BIS */
	    bis));

	ATF_CHECK_EQ(BT_ISO_OP_BIG_CREATE_SYNC, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_STATUS, W.event);
	ATF_CHECK_EQ((size_t)(24 + 3), W.clen);
	ATF_CHECK_EQ(0x03, W.cmd[0]);
	ATF_CHECK_EQ(BT_ISO_HANDLE_MAX, cmd_le16(1));
	ATF_CHECK_EQ(BT_ISO_ENCRYPTION_ENABLED, W.cmd[3]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 4, bcode, 16));
	ATF_CHECK_EQ(0x1F, W.cmd[20]);
	ATF_CHECK_EQ(0x4000, cmd_le16(21));
	ATF_CHECK_EQ(0x03, W.cmd[23]);
	ATF_CHECK_EQ(0x01, W.cmd[24]);
	ATF_CHECK_EQ(0x02, W.cmd[25]);
	ATF_CHECK_EQ(0x03, W.cmd[26]);

	CHECK_BAD(hci_le_big_create_sync(FD, 0x03, 0x0EFF, 0x01, bcode, 0x1F,
	    0x4000, 0x03, bis));
	CHECK_XPORT(hci_le_big_create_sync(FD, 0x03, 0x0EFF, 0x01, bcode, 0x1F,
	    0x4000, 0x03, bis));
}

/*
 * §7.8.106 parameter bounds.  Num_BIS and BIS indices are 0x01..0x1F,
 * and the BIS index list is strictly increasing.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_bounds);
ATF_TC_BODY(big_create_sync_bounds, tc)
{
	uint8_t bis[32];
	uint8_t bcode[16];

	for (uint8_t i = 0; i < sizeof(bis); i++)
		bis[i] = (uint8_t)(i + 1);
	memset(bcode, 0, sizeof(bcode));

	CHECK_EINVAL(hci_le_big_create_sync(FD, 0xF0, 0x0001, 0, bcode, 0,
	    0x0064, 1, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0F00, 0, bcode, 0,
	    0x0064, 1, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 2, bcode, 0,
	    0x0064, 1, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0x20,
	    0x0064, 1, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0009, 1, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 0, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 32, bis));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 1, NULL));
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 1, NULL, 0,
	    0x0064, 1, bis));
	bis[1] = bis[0];
	CHECK_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 2, bis));
}

/* ================================================================
 * §7.8.107  LE BIG Terminate Sync  (OCF 0x006C)  CP: BIG_Handle(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(big_terminate_sync_encoding);
ATF_TC_BODY(big_terminate_sync_encoding, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_big_terminate_sync(FD, 0x03));
	ATF_CHECK_EQ(BT_ISO_OP_BIG_TERMINATE_SYNC, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)1, W.clen);
	ATF_CHECK_EQ(0x03, W.cmd[0]);

	CHECK_BAD(hci_le_big_terminate_sync(FD, 0x03));
	CHECK_XPORT(hci_le_big_terminate_sync(FD, 0x03));
	CHECK_EINVAL(hci_le_big_terminate_sync(FD,
	    BT_ISO_GROUP_HANDLE_MAX + 1));
}

/* ================================================================
 * §7.8.109  LE Setup ISO Data Path  (OCF 0x006E)   CP:
 * Connection_Handle(2 LE) | Data_Path_Direction(1) | Data_Path_ID(1) |
 * Codec_ID(5) | Controller_Delay(3 LE) | Codec_Configuration_Length(1) |
 * Codec_Configuration[len]
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(setup_iso_data_path_encoding);
ATF_TC_BODY(setup_iso_data_path_encoding, tc)
{
	uint8_t codec_id[5] = { 0x06, 0x0F, 0x00, 0x34, 0x12 };
	uint8_t codec_cfg[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_setup_iso_data_path(FD,
	    0x0060,		/* Connection_Handle */
	    BT_ISO_SETUP_PATH_INPUT,
	    BT_ISO_DATA_PATH_HCI,
	    codec_id,
	    0x0F4240,		/* Controller_Delay */
	    sizeof(codec_cfg),
	    codec_cfg));

	ATF_CHECK_EQ(BT_ISO_OP_SETUP_DATA_PATH, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)(13 + 4), W.clen);
	ATF_CHECK_EQ(0x0060, cmd_le16(0));
	ATF_CHECK_EQ(BT_ISO_SETUP_PATH_INPUT, W.cmd[2]);
	ATF_CHECK_EQ(BT_ISO_DATA_PATH_HCI, W.cmd[3]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 4, codec_id, 5));
	ATF_CHECK_EQ(0x0F4240u, cmd_le24(9));
	ATF_CHECK_EQ(4, W.cmd[12]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 13, codec_cfg, 4));

	/* No codec configuration -> length 0, clen 13. */
	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_setup_iso_data_path(FD, 0x0060, 0x01, 0x00,
	    codec_id, 0, 0, NULL));
	ATF_CHECK_EQ((size_t)13, W.clen);
	ATF_CHECK_EQ(0, W.cmd[12]);

	CHECK_BAD(hci_le_setup_iso_data_path(FD, 0x0060, 0, 0, codec_id, 0, 0,
	    NULL));
	CHECK_XPORT(hci_le_setup_iso_data_path(FD, 0x0060, 0, 0, codec_id, 0, 0,
	    NULL));
}

/*
	 * §7.8.109 has 13 fixed parameters.  The §5.4.1 HCI Command
	 * Parameter_Total_Length is one octet, leaving 255 - 13 = 242 octets.
	 */
ATF_TC_WITHOUT_HEAD(setup_iso_data_path_maxcfg);
ATF_TC_BODY(setup_iso_data_path_maxcfg, tc)
{
	uint8_t codec_id[5] = { 0x01, 0, 0, 0, 0 };
	static uint8_t cfg[243];

	memset(cfg, 0x5A, sizeof(cfg));

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(0, hci_le_setup_iso_data_path(FD, 0x0060, 0, 0, codec_id,
	    0, 242, cfg));
	ATF_CHECK_EQ_MSG(1, W.calls, "max codec_config_len is a reachable, "
	    "accepted length that exactly fills the command buffer");
	ATF_CHECK_EQ((size_t)255, W.clen);
	ATF_CHECK_EQ(242, W.cmd[12]);
	ATF_CHECK_EQ(0, memcmp(W.cmd + 13, cfg, 242));

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_iso_data_path(FD, 0x0060, 0, 0,
	    codec_id, 0, 243, cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);
}

/* ================================================================
 * §7.8.110  LE Remove ISO Data Path  (OCF 0x006F)
 * CP: Connection_Handle(2 LE) | Data_Path_Direction(1, bitfield)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(remove_iso_data_path_encoding);
ATF_TC_BODY(remove_iso_data_path_encoding, tc)
{

	reset();
	mock_ok();
	/* Direction bit0=input, bit1=output; 0x03 removes both. */
	ATF_CHECK_EQ(0, hci_le_remove_iso_data_path(FD, 0x0060,
	    BT_ISO_PATH_BOTH));
	ATF_CHECK_EQ(BT_ISO_OP_REMOVE_DATA_PATH, W.opcode);
	ATF_CHECK_EQ(BT_ISO_EVENT_COMMAND_COMPLETE, W.event);
	ATF_CHECK_EQ((size_t)3, W.clen);
	ATF_CHECK_EQ(0x0060, cmd_le16(0));
	ATF_CHECK_EQ(BT_ISO_PATH_BOTH, W.cmd[2]);

	CHECK_BAD(hci_le_remove_iso_data_path(FD, 0x0060, BT_ISO_PATH_BOTH));
	CHECK_XPORT(hci_le_remove_iso_data_path(FD, 0x0060,
	    BT_ISO_PATH_BOTH));
	CHECK_EINVAL(hci_le_remove_iso_data_path(FD, BT_ISO_HANDLE_MAX + 1,
	    BT_ISO_PATH_BOTH));
	CHECK_EINVAL(hci_le_remove_iso_data_path(FD, 0x0060, 0x00));
	CHECK_EINVAL(hci_le_remove_iso_data_path(FD, 0x0060, 0x04));
}

/* ================================================================
 * §7.8.116  LE Read ISO Link Quality  (OCF 0x0075)
 * CP: Connection_Handle(2 LE)
 * RP: Status(1) | Connection_Handle(2) | seven u32 counters (LE):
 *     TX_UnACKed | TX_Flushed | TX_Last_Subevent | Retransmitted |
 *     CRC_Error | RX_Unreceived | Duplicate
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_link_quality);
ATF_TC_BODY(read_iso_link_quality, tc)
{
	uint8_t rp[31];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0;
	int i;

	memset(rp, 0, sizeof(rp));
	rp[0] = 0x00;			/* status */
	rp[1] = 0x40; rp[2] = 0x00;	/* connection_handle 0x0040 */
	/* seven u32 counters 1..7, each little-endian at offset 3 + 4*i. */
	for (i = 0; i < 7; i++)
		rp[3 + i * 4] = (uint8_t)(i + 1);

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	ATF_CHECK_EQ(BT_ISO_OP_READ_LINK_QUALITY, W.opcode);
	ATF_CHECK_EQ((size_t)2, W.clen);
	ATF_CHECK_EQ(0x0040, cmd_le16(0));
	ATF_CHECK_EQ(1, a);	/* tx_unacked */
	ATF_CHECK_EQ(2, b);	/* tx_flushed */
	ATF_CHECK_EQ(3, c);	/* tx_last_subevent */
	ATF_CHECK_EQ(4, d);	/* retransmitted */
	ATF_CHECK_EQ(5, e);	/* crc_error */
	ATF_CHECK_EQ(6, f);	/* rx_unreceived */
	ATF_CHECK_EQ(7, g);	/* duplicate */

	CHECK_BAD(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	CHECK_XPORT(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
}

/*
 * Vol 4, Part E §§7.8.96, .99, .101, .102, and .116 specify every
 * Connection_Handle as 12 meaningful bits with range 0x0000..0x0EFF.
 * Exercise the exact upper endpoint and the first reserved value without
 * deriving either value from a production header.
 */
ATF_TC_WITHOUT_HEAD(handle_range_boundaries);
ATF_TC_BODY(handle_range_boundaries, tc)
{
	uint16_t valid[1] = { BT_ISO_HANDLE_MAX };
	uint16_t invalid[1] = { BT_ISO_HANDLE_MAX + 1 };
	uint16_t seq;
	uint32_t counters[7];

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, BT_ISO_HANDLE_MAX,
	    &seq, NULL, NULL));
	ATF_CHECK_EQ(BT_ISO_HANDLE_MAX, cmd_le16(0));
	CHECK_EINVAL(hci_le_read_iso_tx_sync(FD, BT_ISO_HANDLE_MAX + 1,
	    NULL, NULL, NULL));

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_accept_cis_request(FD, BT_ISO_HANDLE_MAX));
	CHECK_EINVAL(hci_le_accept_cis_request(FD, BT_ISO_HANDLE_MAX + 1));
	CHECK_EINVAL(hci_le_reject_cis_request(FD, BT_ISO_HANDLE_MAX + 1,
	    BT_ISO_ERROR_LIMITED_RESOURCES));

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_create_cis(FD, 1, valid, valid));
	CHECK_EINVAL(hci_le_create_cis(FD, 1, invalid, valid));
	CHECK_EINVAL(hci_le_create_cis(FD, 1, valid, invalid));

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, BT_ISO_HANDLE_MAX,
	    &counters[0], &counters[1], &counters[2], &counters[3],
	    &counters[4], &counters[5], &counters[6]));
	CHECK_EINVAL(hci_le_read_iso_link_quality(FD,
	    BT_ISO_HANDLE_MAX + 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
}

/* ================================================================
 * ISO meta-event enablement.  hci_le_default_event_mask() sets the LE
 * event-mask bits for the ISO meta-events based on the local features.
 * These bit positions map 1:1 to the subevent codes in §7.7.65.25-34.
 *
 * The daemon enables the ISO event bits it has structured handling for in
 * blued_event.c, so this test guards both the mask and the event layout used
 * by the parser.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(iso_event_mask);
ATF_TC_BODY(iso_event_mask, tc)
{
	uint64_t m;

	/* No ISO features -> no ISO event bits. */
	m = hci_le_default_event_mask(0);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CIS_ESTABLISHED));
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CIS_REQUEST));
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CREATE_BIG));

	/* CIS Central -> CIS Established (subevent 0x19, §7.7.65.25). */
	m = hci_le_default_event_mask(BT_ISO_FEAT_CIS_CENTRAL);
	ATF_CHECK((m & BT_ISO_MASK_CIS_ESTABLISHED) != 0);

	/* CIS Peripheral -> CIS Request (subevent 0x1A, §7.7.65.26). */
	m = hci_le_default_event_mask(BT_ISO_FEAT_CIS_PERIPHERAL);
	ATF_CHECK((m & BT_ISO_MASK_CIS_REQUEST) != 0);

	/* ISO Broadcaster -> all five BIG events (§7.7.65.27-30, 34). */
	m = hci_le_default_event_mask(BT_ISO_FEAT_BROADCASTER);
	ATF_CHECK((m & BT_ISO_MASK_CREATE_BIG) != 0);
	ATF_CHECK((m & BT_ISO_MASK_TERMINATE_BIG) != 0);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_BIG_SYNC_EST));
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_BIG_SYNC_LOST));
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_BIGINFO_REPORT));

	m = hci_le_default_event_mask(BT_ISO_FEAT_SYNC_RECEIVER);
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_CREATE_BIG));
	ATF_CHECK_EQ(0, (m & BT_ISO_MASK_TERMINATE_BIG));
	ATF_CHECK((m & BT_ISO_MASK_BIG_SYNC_EST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_BIG_SYNC_LOST) != 0);
	ATF_CHECK((m & BT_ISO_MASK_BIGINFO_REPORT) != 0);
}

/* ================================================================
 * ISO meta-event decode conformance (§7.7.65.25-30).
 *
 * This was a spec-layout oracle only, because blued_event.c did not parse
 * the ISO meta-events (it silently dropped subevents 0x19-0x1E even though
 * hci_le_default_event_mask() unmasks them -- see iso_event_mask).  blued
 * now decodes them through the shared seam blued_parse_le_meta_event()
 * (blued_le_meta.h), which blued_event.c drives on the live HCI socket.
 * This case feeds that real decoder the crafted spec event bytes and
 * asserts the extracted fields, so it is now a conformance test.  Wire
 * framing: [type(0x04) | HCI_LE_Meta(0x3E) | Param_Total_Length | Subevent
 * | parameters] (Core Spec Vol 4 Part E §5.4.4, §7.7.65).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(iso_meta_event_layout);
ATF_TC_BODY(iso_meta_event_layout, tc)
{
	struct blued_le_meta_report rep;

	/*
	 * §7.7.65.25 LE CIS Established (subevent 0x19).  Parameters:
	 * Status(1) | Connection_Handle(2 LE) | CIG_Sync_Delay(3 LE) |
	 * CIS_Sync_Delay(3 LE) | Transport_Latency_C_To_P(3 LE) |
	 * Transport_Latency_P_To_C(3 LE) | PHY_C_To_P(1) | PHY_P_To_C(1) |
	 * NSE(1) | BN_C_To_P(1) | BN_P_To_C(1) | FT_C_To_P(1) | FT_P_To_C(1) |
	 * Max_PDU_C_To_P(2 LE) | Max_PDU_P_To_C(2 LE) | ISO_Interval(2 LE).
	 */
	static const uint8_t cis_est[] = {
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_CIS_ESTABLISHED,
		BT_ISO_SUBEVENT_CIS_ESTABLISHED,
		BT_ISO_STATUS_SUCCESS,
		0x60, 0x00,		/* connection_handle = 0x0060 */
		0x01, 0x02, 0x03,	/* CIG_Sync_Delay = 0x030201 */
		0x04, 0x05, 0x06,	/* CIS_Sync_Delay = 0x060504 */
		0x07, 0x08, 0x09,	/* Transport_Latency_C_To_P */
		0x0A, 0x0B, 0x0C,	/* Transport_Latency_P_To_C */
		BT_ISO_PHY_1M,		/* PHY_C_To_P */
		BT_ISO_PHY_2M,		/* PHY_P_To_C */
		0x21,			/* NSE */
		0x01,			/* BN_C_To_P */
		0x01,			/* BN_P_To_C */
		0x02,			/* FT_C_To_P */
		0x02,			/* FT_P_To_C */
		0xFB, 0x00,		/* Max_PDU_C_To_P = 251 */
		0xFB, 0x00,		/* Max_PDU_P_To_C = 251 */
		0x18, 0x00		/* ISO_Interval = 0x0018 */
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(cis_est, sizeof(cis_est),
	    &rep), "0x19 must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_CIS_ESTABLISHED, rep.subevent);
	ATF_CHECK(rep.has_status);
	ATF_CHECK_EQ(BT_ISO_STATUS_SUCCESS, rep.status);
	ATF_CHECK_EQ(0x0060, rep.connection_handle);
	ATF_CHECK_EQ(BT_ISO_PHY_1M, rep.phy_c_to_p);
	ATF_CHECK_EQ(BT_ISO_PHY_2M, rep.phy_p_to_c);
	ATF_CHECK_EQ(0x21, rep.nse);
	ATF_CHECK_EQ(251, rep.max_pdu_c_to_p);
	ATF_CHECK_EQ(251, rep.max_pdu_p_to_c);
	ATF_CHECK_EQ(0x0018, rep.iso_interval);

	/* A truncated CIS Established is flagged malformed, not misread. */
	ATF_CHECK_MSG(blued_parse_le_meta_event(cis_est, sizeof(cis_est) - 1,
	    &rep) < 0, "short 0x19 must be malformed");

	/*
	 * §7.7.65.26 LE CIS Request (subevent 0x1A):
	 * ACL_Connection_Handle(2 LE) | CIS_Connection_Handle(2 LE) |
	 * CIG_ID(1) | CIS_ID(1).
	 */
	static const uint8_t cis_req[] = {
		/* Param_Total_Length = 7: subevent(1)+ACL(2)+CIS(2)+CIG_ID(1)+
		 * CIS_ID(1), per §5.4.4 (covers the subevent octet). */
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_CIS_REQUEST,
		BT_ISO_SUBEVENT_CIS_REQUEST,
		0x40, 0x00,		/* ACL_Connection_Handle = 0x0040 */
		0x60, 0x00,		/* CIS_Connection_Handle = 0x0060 */
		0x05,			/* CIG_ID */
		0x03			/* CIS_ID */
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(cis_req, sizeof(cis_req),
	    &rep), "0x1A must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_CIS_REQUEST, rep.subevent);
	ATF_CHECK_EQ(0x0040, rep.acl_connection_handle);
	ATF_CHECK_EQ(0x0060, rep.cis_connection_handle);
	ATF_CHECK_EQ(0x05, rep.cig_id);
	ATF_CHECK_EQ(0x03, rep.cis_id);

	/*
	 * §7.7.65.27 LE Create BIG Complete (subevent 0x1B):
	 * Status(1) | BIG_Handle(1) | BIG_Sync_Delay(3 LE) |
	 * Transport_Latency_BIG(3 LE) | PHY(1) | NSE(1) | BN(1) | PTO(1) |
	 * IRC(1) | Max_PDU(2 LE) | ISO_Interval(2 LE) | Num_BIS(1) |
	 * Connection_Handle[i](2 LE) x Num_BIS.
	 */
	static const uint8_t big_compl[] = {
		/* Param_Total_Length = 23: 19-octet fixed header (subevent..
		 * Num_BIS) + Num_BIS(2) * Connection_Handle(2), per §5.4.4. */
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_CREATE_BIG_2_BIS,
		BT_ISO_SUBEVENT_CREATE_BIG,
		BT_ISO_STATUS_SUCCESS,
		0x03,			/* BIG_Handle */
		0x11, 0x22, 0x33,	/* BIG_Sync_Delay = 0x332211 */
		0x44, 0x55, 0x66,	/* Transport_Latency_BIG = 0x665544 */
		BT_ISO_PHY_2M,		/* PHY */
		0x21,			/* NSE */
		0x01,			/* BN */
		0x00,			/* PTO */
		0x01,			/* IRC */
		0xFB, 0x00,		/* Max_PDU = 251 */
		0x18, 0x00,		/* ISO_Interval = 0x0018 */
		0x02,			/* Num_BIS = 2 */
		0x00, 0x01,		/* Connection_Handle[0] = 0x0100 */
		0x01, 0x01		/* Connection_Handle[1] = 0x0101 */
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(big_compl,
	    sizeof(big_compl), &rep), "0x1B must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_CREATE_BIG, rep.subevent);
	ATF_CHECK_EQ(BT_ISO_STATUS_SUCCESS, rep.status);
	ATF_CHECK_EQ(0x03, rep.big_handle);
	ATF_CHECK_EQ(0x0018, rep.iso_interval);
	ATF_CHECK_EQ(2, rep.num_bis);
	ATF_REQUIRE(rep.bis_handles != NULL);
	ATF_CHECK_EQ(0x0100, (uint16_t)(rep.bis_handles[0] |
	    (rep.bis_handles[1] << 8)));			/* handle[0] */
	ATF_CHECK_EQ(0x0101, (uint16_t)(rep.bis_handles[2] |
	    (rep.bis_handles[3] << 8)));			/* handle[1] */

	/*
	 * §7.7.65.28 LE Terminate BIG Complete (subevent 0x1C):
	 * BIG_Handle(1) | Reason(1).
	 */
	static const uint8_t big_term[] = {
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_TERMINATE_BIG,
		BT_ISO_SUBEVENT_TERMINATE_BIG,
		0x03,			/* BIG_Handle */
		BT_ISO_ERROR_LOCAL_HOST
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(big_term,
	    sizeof(big_term), &rep), "0x1C must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_TERMINATE_BIG, rep.subevent);
	ATF_CHECK_EQ(0x03, rep.big_handle);
	ATF_CHECK_EQ(BT_ISO_ERROR_LOCAL_HOST, rep.reason_code);

	/*
	 * §7.7.65.29 LE BIG Sync Established (subevent 0x1D):
	 * Status(1) | BIG_Handle(1) | Transport_Latency_BIG(3 LE) | NSE(1) |
	 * BN(1) | PTO(1) | IRC(1) | Max_PDU(2 LE) | ISO_Interval(2 LE) |
	 * Num_BIS(1) | Connection_Handle[i](2 LE).
	 */
	static const uint8_t big_sync[] = {
		/* Param_Total_Length = 17: 15-octet fixed header (subevent..
		 * Num_BIS) + Num_BIS(1) * Connection_Handle(2), per §5.4.4. */
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_BIG_SYNC_1_BIS,
		BT_ISO_SUBEVENT_BIG_SYNC_EST,
		BT_ISO_STATUS_SUCCESS,
		0x03,			/* BIG_Handle */
		0xAA, 0xBB, 0xCC,	/* Transport_Latency_BIG = 0xCCBBAA */
		0x21,			/* NSE */
		0x01,			/* BN */
		0x00,			/* PTO */
		0x01,			/* IRC */
		0xFB, 0x00,		/* Max_PDU = 251 */
		0x18, 0x00,		/* ISO_Interval = 0x0018 */
		0x01,			/* Num_BIS = 1 */
		0x00, 0x01		/* Connection_Handle[0] = 0x0100 */
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(big_sync,
	    sizeof(big_sync), &rep), "0x1D must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_BIG_SYNC_EST, rep.subevent);
	ATF_CHECK_EQ(BT_ISO_STATUS_SUCCESS, rep.status);
	ATF_CHECK_EQ(0x03, rep.big_handle);
	ATF_CHECK_EQ(1, rep.num_bis);
	ATF_REQUIRE(rep.bis_handles != NULL);
	ATF_CHECK_EQ(0x0100, (uint16_t)(rep.bis_handles[0] |
	    (rep.bis_handles[1] << 8)));			/* handle[0] */

	/*
	 * §7.7.65.30 LE BIG Sync Lost (subevent 0x1E):
	 * BIG_Handle(1) | Reason(1).
	 */
	static const uint8_t big_lost[] = {
		BT_ISO_H4_EVENT_PACKET, BT_ISO_EVENT_LE_META,
		BT_ISO_PARAM_LEN_BIG_SYNC_LOST,
		BT_ISO_SUBEVENT_BIG_SYNC_LOST,
		0x03,			/* BIG_Handle */
		BT_ISO_ERROR_FAILED_ESTABLISH
	};

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(big_lost,
	    sizeof(big_lost), &rep), "0x1E must be consumed, not dropped");
	ATF_CHECK_EQ(BT_ISO_SUBEVENT_BIG_SYNC_LOST, rep.subevent);
	ATF_CHECK_EQ(0x03, rep.big_handle);
	ATF_CHECK_EQ(BT_ISO_ERROR_FAILED_ESTABLISH, rep.reason_code);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Command encoders + return-parameter extraction (§7.8.96-116). */
	ATF_TP_ADD_TC(tp, read_iso_tx_sync);
	ATF_TP_ADD_TC(tp, set_cig_params_encoding);
	ATF_TP_ADD_TC(tp, set_cig_params_buflen);
	ATF_TP_ADD_TC(tp, create_cis_encoding);
	ATF_TP_ADD_TC(tp, create_cis_count_bounds);
	ATF_TP_ADD_TC(tp, remove_cig_encoding);
	ATF_TP_ADD_TC(tp, accept_cis_request_encoding);
	ATF_TP_ADD_TC(tp, reject_cis_request_encoding);
	ATF_TP_ADD_TC(tp, create_big_encoding);
	ATF_TP_ADD_TC(tp, terminate_big_encoding);
	ATF_TP_ADD_TC(tp, big_create_sync_encoding);
	ATF_TP_ADD_TC(tp, big_create_sync_bounds);
	ATF_TP_ADD_TC(tp, big_terminate_sync_encoding);
	ATF_TP_ADD_TC(tp, setup_iso_data_path_encoding);
	ATF_TP_ADD_TC(tp, setup_iso_data_path_maxcfg);
	ATF_TP_ADD_TC(tp, remove_iso_data_path_encoding);
	ATF_TP_ADD_TC(tp, read_iso_link_quality);
	ATF_TP_ADD_TC(tp, handle_range_boundaries);

	/* ISO meta-event enablement + byte-layout oracle (§7.7.65.25-34). */
	ATF_TP_ADD_TC(tp, iso_event_mask);
	ATF_TP_ADD_TC(tp, iso_meta_event_layout);

	return (atf_no_error());
}
