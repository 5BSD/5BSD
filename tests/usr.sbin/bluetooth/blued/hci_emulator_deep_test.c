/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator_deep_test.c - exhaustive edge / negative / lifecycle tests
 * for the userspace HCI controller emulator (hci_emulator.c).
 *
 * These complement hci_emulator_test.c (init/config happy path),
 * hci_emulator_link_test.c (two-controller link + ACL) and
 * hci_emulator_enc_test.c (clock/encryption/power happy path) by driving
 * the branches those miss: malformed/short command packets for EVERY
 * handler, unknown opcodes and raw input framing, per-command return-param
 * fields and getters, the resolving-list mutation path, fault injection
 * across command classes, the clock/timer queue (ordering, re-arm, zero /
 * large advances), encryption edges (unknown handle, forced-fail outcome,
 * peerless link), two-controller/ACL edges (unconnected/after-disconnect/
 * truncated ACL, connection-table exhaustion, non-connectable advertiser,
 * random own-address), and LE Power Control zone boundaries.
 *
 * ORACLE: the Bluetooth Core Spec Vol 4 Part E (HCI).  Every expected byte
 * is HAND-ENCODED from the spec and each case cites the section it checks;
 * nothing captures the emulator's own output and treats it as truth.
 * Struct sizes are taken from sys/netgraph/bluetooth/include/ng_hci.h so
 * the fed command lengths are byte-compatible with the in-tree stack.
 */

#include <atf-c.h>

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdint.h>
#include <string.h>

#include "hci_emulator.h"
#include "spec_hci_emulator_deep_oracles.h"

/* Opcode shorthands sourced only from the test-only Core 6.3 header. */
#define	OP_RESET HCI_DEEP_SPEC_OP_RESET
#define	OP_SET_EVENT_MASK HCI_DEEP_SPEC_OP_SET_EVENT_MASK
#define	OP_WRITE_LE_HOST_SUPPORTED HCI_DEEP_SPEC_OP_WRITE_LE_HOST_SUPPORTED
#define	OP_READ_BDADDR HCI_DEEP_SPEC_OP_READ_BDADDR
#define	OP_LE_SET_EVENT_MASK HCI_DEEP_SPEC_OP_LE_SET_EVENT_MASK
#define	OP_LE_SET_RANDOM_ADDRESS HCI_DEEP_SPEC_OP_LE_SET_RANDOM_ADDRESS
#define	OP_LE_SET_ADV_PARAMS HCI_DEEP_SPEC_OP_LE_SET_ADV_PARAMS
#define	OP_LE_SET_ADV_DATA HCI_DEEP_SPEC_OP_LE_SET_ADV_DATA
#define	OP_LE_SET_SCAN_RSP_DATA HCI_DEEP_SPEC_OP_LE_SET_SCAN_RSP_DATA
#define	OP_LE_SET_ADV_ENABLE HCI_DEEP_SPEC_OP_LE_SET_ADV_ENABLE
#define	OP_LE_SET_SCAN_PARAMS HCI_DEEP_SPEC_OP_LE_SET_SCAN_PARAMS
#define	OP_LE_SET_SCAN_ENABLE HCI_DEEP_SPEC_OP_LE_SET_SCAN_ENABLE
#define	OP_LE_ADD_RESOLV HCI_DEEP_SPEC_OP_LE_ADD_RESOLV
#define	OP_LE_REMOVE_RESOLV HCI_DEEP_SPEC_OP_LE_REMOVE_RESOLV
#define	OP_LE_CLEAR_RESOLV HCI_DEEP_SPEC_OP_LE_CLEAR_RESOLV
#define	OP_LE_SET_ADDR_RESOLUTION_ENABLE \
	HCI_DEEP_SPEC_OP_LE_SET_ADDR_RESOLUTION_ENABLE
#define	OP_DISCONNECT HCI_DEEP_SPEC_OP_DISCONNECT
#define	OP_LE_CREATE_CONNECTION HCI_DEEP_SPEC_OP_LE_CREATE_CONNECTION
#define	OP_LE_CREATE_CONNECTION_CANCEL \
	HCI_DEEP_SPEC_OP_LE_CREATE_CONNECTION_CANCEL
#define	OP_LE_ENABLE_ENCRYPTION HCI_DEEP_SPEC_OP_LE_ENABLE_ENCRYPTION
#define	OP_LE_LTK_REQ_REPLY HCI_DEEP_SPEC_OP_LE_LTK_REQ_REPLY
#define	OP_LE_LTK_REQ_NEG_REPLY HCI_DEEP_SPEC_OP_LE_LTK_REQ_NEG_REPLY
#define	OP_LE_READ_REMOTE_TX_POWER HCI_DEEP_SPEC_OP_LE_READ_REMOTE_TX_POWER
#define	OP_LE_SET_PATH_LOSS_PARAMS HCI_DEEP_SPEC_OP_LE_SET_PATH_LOSS_PARAMS
#define	OP_LE_SET_PATH_LOSS_ENABLE HCI_DEEP_SPEC_OP_LE_SET_PATH_LOSS_ENABLE
#define	OP_LE_SET_TX_POWER_REPORTING_ENABLE \
	HCI_DEEP_SPEC_OP_LE_SET_TX_POWER_REPORTING_ENABLE
#define	OP_LE_READ_BUFFER_SIZE_V2 HCI_DEEP_SPEC_OP_LE_READ_BUFFER_SIZE_V2
#define	OP_LE_READ_LOCAL_FEATURES HCI_DEEP_SPEC_OP_LE_READ_LOCAL_FEATURES
#define	OP_LE_SET_PERIODIC_ADV_PARAMS \
	HCI_DEEP_SPEC_OP_LE_SET_PERIODIC_ADV_PARAMS
#define	OP_LE_SET_PERIODIC_ADV_RCV_ENABLE \
	HCI_DEEP_SPEC_OP_LE_SET_PERIODIC_ADV_RCV_ENABLE
#define	OP_LE_PERIODIC_ADV_SYNC_TRANSFER \
	HCI_DEEP_SPEC_OP_LE_PERIODIC_ADV_SYNC_TRANSFER
#define	OP_LE_SET_CIG_PARAMS HCI_DEEP_SPEC_OP_LE_SET_CIG_PARAMS

/* Common status / reason codes, Vol 4 Part E §1.3 (Error Code table). */
#define	ST_SUCCESS		HCI_DEEP_SPEC_STATUS_SUCCESS
#define	ST_UNKNOWN_CMD		HCI_DEEP_SPEC_STATUS_UNKNOWN_COMMAND
#define	ST_UNKNOWN_CONN		HCI_DEEP_SPEC_STATUS_UNKNOWN_CONNECTION_ID
#define	ST_PIN_OR_KEY_MISSING	HCI_DEEP_SPEC_STATUS_PIN_OR_KEY_MISSING
#define	ST_MEM_CAP_EXCEEDED	HCI_DEEP_SPEC_STATUS_MEMORY_CAPACITY_EXCEEDED
#define	ST_CMD_DISALLOWED	HCI_DEEP_SPEC_STATUS_COMMAND_DISALLOWED
#define	ST_INVALID_PARAMS	HCI_DEEP_SPEC_STATUS_INVALID_PARAMETERS
#define	REASON_LOCAL_HOST_TERM	HCI_DEEP_SPEC_REASON_LOCAL_HOST_TERMINATED
#define	REASON_CONN_TIMEOUT	HCI_DEEP_SPEC_REASON_CONNECTION_TIMEOUT

#define	TEST_LE_FEAT_PERIODIC_ADV	HCI_DEEP_SPEC_FEAT_PERIODIC_ADV
#define	TEST_LE_FEAT_PAST_SENDER	HCI_DEEP_SPEC_FEAT_PAST_SENDER
#define	TEST_LE_FEAT_PAST_RECIPIENT	HCI_DEEP_SPEC_FEAT_PAST_RECIPIENT
#define	TEST_LE_FEAT_CIS_CENTRAL	HCI_DEEP_SPEC_FEAT_CIS_CENTRAL
#define	TEST_LE_FEAT_CIS_PERIPH		HCI_DEEP_SPEC_FEAT_CIS_PERIPHERAL
#define	TEST_LE_FEAT_ISO_BROADCASTER	HCI_DEEP_SPEC_FEAT_ISO_BROADCASTER
#define	TEST_LE_FEAT_SYNC_RECEIVER	HCI_DEEP_SPEC_FEAT_SYNC_RECEIVER
#define	TEST_LE_FEAT_POWER_CONTROL	HCI_DEEP_SPEC_FEAT_POWER_CONTROL
#define	TEST_LE_FEAT_PATH_LOSS_MONITORING \
	HCI_DEEP_SPEC_FEAT_PATH_LOSS_MONITORING

/* Nanoseconds per Supervision_Timeout unit (10 ms, §7.8.12). */
#define	SUP_UNIT_NS	HCI_DEEP_SPEC_SUPERVISION_UNIT_NS

/* ================================================================
 * Per-controller ordered output capture.
 * ================================================================ */
#define	CAP_MAX		32
struct cap {
	uint8_t	pkt[CAP_MAX][512];
	size_t	len[CAP_MAX];
	int	n;
};

static void
cap_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cap *c = ctx;

	if (c->n >= CAP_MAX)
		return;
	if (len > sizeof(c->pkt[0]))
		len = sizeof(c->pkt[0]);
	memcpy(c->pkt[c->n], pkt, len);
	c->len[c->n] = len;
	c->n++;
}

static void
cap_reset(struct cap *c)
{

	memset(c, 0, sizeof(*c));
}

/* Count captured packets whose event code (byte[1]) is code. */
static int
cap_count_event(const struct cap *c, uint8_t code)
{
	int i, n = 0;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 2 && c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == code)
			n++;
	return (n);
}

/* First captured event with the given event code (byte[1]). */
static const uint8_t *
cap_find_event(const struct cap *c, uint8_t code)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 2 && c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == code)
			return (c->pkt[i]);
	return (NULL);
}

/* First captured LE Meta (0x3E) event with subevent code sub (byte[3]). */
static const uint8_t *
cap_find_le_subevent(const struct cap *c, uint8_t sub)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 4 && c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == HCI_LINK_SPEC_NG_HCI_EVENT_LE && c->pkt[i][3] == sub)
			return (c->pkt[i]);
	return (NULL);
}

/* First Command Complete (§7.7.14) echoing opcode op (opcode at bytes 4..5). */
static const uint8_t *
cap_find_cc(const struct cap *c, uint16_t op)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 7 && c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_COMPL &&
		    le16dec(&c->pkt[i][4]) == op)
			return (c->pkt[i]);
	return (NULL);
}

/* First Command Status (§7.7.15) echoing opcode op (opcode at bytes 5..6). */
static const uint8_t *
cap_find_cs(const struct cap *c, uint16_t op)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 7 && c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_STATUS &&
		    le16dec(&c->pkt[i][5]) == op)
			return (c->pkt[i]);
	return (NULL);
}

/* Feed one typed command packet: 0x01 | opcode(2,LE) | plen | params. */
static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[300];

	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/* Feed one typed ACL packet: 0x02 | handle+flags(2,LE) | len(2,LE) | data. */
static void
feed_acl(struct hci_emu *e, uint16_t handle, const uint8_t *data, uint16_t dlen)
{
	uint8_t buf[512];

	buf[0] = HCI_LINK_SPEC_ACL_PKT;
	le16enc(&buf[1], HCI_LINK_SPEC_MAKE_HANDLE(handle, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT));
	le16enc(&buf[3], dlen);
	if (dlen != 0)
		memcpy(&buf[5], data, dlen);
	hci_emu_input(e, buf, (size_t)5 + dlen);
}

/* Assert a status-only Command Complete (§7.7.14): 0x04|0x0E|4|1|op|status. */
static void
check_cc_status(const uint8_t *ev, uint16_t op, uint8_t status)
{

	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_PKT, ev[0]);			/* 0x04 */
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_COMPL, ev[1]);	/* 0x0E */
	ATF_CHECK_EQ(4, ev[2]);					/* param_len */
	ATF_CHECK_EQ(1, ev[3]);					/* num_cmd_pkts */
	ATF_CHECK_EQ(op, le16dec(&ev[4]));			/* echoed opcode */
	ATF_CHECK_EQ(status, ev[6]);				/* status */
}

/* Assert a Command Status (§7.7.15): 0x04|0x0F|4|status|1|op. */
static void
check_cs(const uint8_t *ev, uint16_t op, uint8_t status)
{

	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_PKT, ev[0]);			/* 0x04 */
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_STATUS, ev[1]);	/* 0x0F */
	ATF_CHECK_EQ(4, ev[2]);					/* param_len */
	ATF_CHECK_EQ(status, ev[3]);				/* status */
	ATF_CHECK_EQ(1, ev[4]);					/* num_cmd_pkts */
	ATF_CHECK_EQ(op, le16dec(&ev[5]));			/* echoed opcode */
}

/* Assert a Command Complete carrying status + Connection_Handle (6 params). */
static void
check_cc_handle(const uint8_t *ev, uint16_t op, uint8_t status, uint16_t handle)
{

	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_COMPL, ev[1]);	/* 0x0E */
	ATF_CHECK_EQ(op, le16dec(&ev[4]));			/* opcode */
	ATF_CHECK_EQ(status, ev[6]);				/* status */
	ATF_CHECK_EQ(handle, le16dec(&ev[7]));			/* handle */
}

static uint64_t
read_le_features(struct hci_emu *e, struct cap *c)
{
	const uint8_t *ev;

	cap_reset(c);
	feed_cmd(e, OP_LE_READ_LOCAL_FEATURES, NULL, 0);
	ev = cap_find_cc(c, OP_LE_READ_LOCAL_FEATURES);
	ATF_REQUIRE(ev != NULL);
	ATF_REQUIRE_EQ(15, c->len[0]);
	ATF_CHECK_EQ(ST_SUCCESS, ev[6]);
	return (le64dec(&ev[7]));
}

/* Build the 25-byte LE_Create_Connection parameter block (§7.8.12). */
static uint8_t
build_create_conn(uint8_t p[25], uint8_t peer_addr_type,
    const uint8_t peer_addr[6], uint8_t own_addr_type, uint16_t interval,
    uint16_t latency, uint16_t sto)
{

	memset(p, 0, 25);
	le16enc(&p[0], 0x0060);		/* scan_interval */
	le16enc(&p[2], 0x0030);		/* scan_window */
	p[4] = 0x00;			/* initiator filter policy */
	p[5] = peer_addr_type;
	memcpy(&p[6], peer_addr, 6);
	p[12] = own_addr_type;
	le16enc(&p[13], interval);	/* conn_interval_min */
	le16enc(&p[15], interval);	/* conn_interval_max */
	le16enc(&p[17], latency);	/* conn_latency */
	le16enc(&p[19], sto);		/* supervision_timeout */
	le16enc(&p[21], 0x0000);	/* min_ce_length */
	le16enc(&p[23], 0x0000);	/* max_ce_length */
	return (25);
}

/* Set A up as a connectable ADV_IND advertiser (own address public). */
static void
setup_advertiser(struct hci_emu *a, const uint8_t addr[6], const uint8_t *ad,
    uint8_t adlen)
{
	uint8_t p[64];

	hci_emu_set_bd_addr(a, addr);
	p[0] = adlen;
	memcpy(&p[1], ad, adlen);
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + adlen));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
}

/*
 * Establish a link + connection: B (Central) connects to A (Peripheral).
 * On return both capture buffers hold only post-connection events.  The
 * supervision timeout is sto (in 10 ms units).
 */
static void
link_and_connect(struct hci_emu **ap, struct hci_emu **bp, struct cap *acap,
    struct cap *bcap, const uint8_t a_addr[6], const uint8_t b_addr[6],
    uint16_t sto)
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	struct hci_emu *a, *b;
	uint8_t p[25], plen;

	cap_reset(acap);
	cap_reset(bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, acap);
	hci_emu_set_output(b, cap_out, bcap);
	hci_emu_set_bd_addr(b, b_addr);
	hci_emu_link(a, b);

	setup_advertiser(a, a_addr, ad, sizeof(ad));

	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);

	cap_reset(acap);
	cap_reset(bcap);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, sto);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);

	*ap = a;
	*bp = b;
}

/* ================================================================
 * SECTION 1: malformed / short command packets.
 *
 * Vol 4 Part E §4.4 / §7.7.14 / §7.7.15: a command whose parameter total
 * length is short of the fixed size is answered in the command's normal
 * completion event with status Invalid HCI Command Parameters (0x12).
 * Config commands complete with Command Complete; commands that are
 * defined to return Command Status (Disconnect §7.1.6, LE_Create_Connection
 * §7.8.12, LE_Enable_Encryption §7.8.24, LE_Read_Remote_Tx_Power §7.8.118)
 * carry the 0x12 in a Command Status event instead.
 * ================================================================ */
/*
 * Feed a command that is one byte short of its fixed parameter size and
 * assert the failure is reported with Invalid HCI Command Parameters (0x12)
 * in the command's normal completion event.  "need" is the fixed size.
 */
static void
expect_short_cc(uint16_t op, uint8_t need)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[40];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);
	memset(p, 0, sizeof(p));
	cap_reset(&cp);
	feed_cmd(e, op, p, (uint8_t)(need - 1));
	check_cc_status(cap_find_cc(&cp, op), op, ST_INVALID_PARAMS);
	hci_emu_free(e);
}

static void
expect_short_cs(uint16_t op, uint8_t need)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[40];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);
	memset(p, 0, sizeof(p));
	cap_reset(&cp);
	feed_cmd(e, op, p, (uint8_t)(need - 1));
	check_cs(cap_find_cs(&cp, op), op, ST_INVALID_PARAMS);
	hci_emu_free(e);
}

/* One ATF case per command handler whose short-packet arm returns a
 * status-only Command Complete (§4.4, §7.7.14).  The fixed sizes are from
 * the cited §7.x command definitions / ng_hci.h struct sizes. */
ATF_TC_WITHOUT_HEAD(deep_short_set_event_mask);
ATF_TC_BODY(deep_short_set_event_mask, tc)
{ expect_short_cc(OP_SET_EVENT_MASK, 8); }			/* §7.3.1 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_event_mask);
ATF_TC_BODY(deep_short_le_set_event_mask, tc)
{ expect_short_cc(OP_LE_SET_EVENT_MASK, 8); }			/* §7.8.1 */

ATF_TC_WITHOUT_HEAD(deep_short_write_le_host_supported);
ATF_TC_BODY(deep_short_write_le_host_supported, tc)
{ expect_short_cc(OP_WRITE_LE_HOST_SUPPORTED, 2); }		/* §7.3.79 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_random_address);
ATF_TC_BODY(deep_short_le_set_random_address, tc)
{ expect_short_cc(OP_LE_SET_RANDOM_ADDRESS, 6); }		/* §7.8.4 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_adv_params);
ATF_TC_BODY(deep_short_le_set_adv_params, tc)
{ expect_short_cc(OP_LE_SET_ADV_PARAMS, 15); }			/* §7.8.5 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_scan_params);
ATF_TC_BODY(deep_short_le_set_scan_params, tc)
{ expect_short_cc(OP_LE_SET_SCAN_PARAMS, 7); }			/* §7.8.10 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_scan_enable);
ATF_TC_BODY(deep_short_le_set_scan_enable, tc)
{ expect_short_cc(OP_LE_SET_SCAN_ENABLE, 2); }			/* §7.8.11 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_adv_enable);
ATF_TC_BODY(deep_short_le_set_adv_enable, tc)
{ expect_short_cc(OP_LE_SET_ADV_ENABLE, 1); }			/* §7.8.9 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_addr_resolution_enable);
ATF_TC_BODY(deep_short_le_set_addr_resolution_enable, tc)
{ expect_short_cc(OP_LE_SET_ADDR_RESOLUTION_ENABLE, 1); }	/* §7.8.44 */

ATF_TC_WITHOUT_HEAD(deep_short_le_add_resolv);
ATF_TC_BODY(deep_short_le_add_resolv, tc)
{ expect_short_cc(OP_LE_ADD_RESOLV, 39); }			/* §7.8.38 */

ATF_TC_WITHOUT_HEAD(deep_short_le_remove_resolv);
ATF_TC_BODY(deep_short_le_remove_resolv, tc)
{ expect_short_cc(OP_LE_REMOVE_RESOLV, 7); }			/* §7.8.39 */

ATF_TC_WITHOUT_HEAD(deep_short_le_ltk_reply);
ATF_TC_BODY(deep_short_le_ltk_reply, tc)
{ expect_short_cc(OP_LE_LTK_REQ_REPLY, 18); }			/* §7.8.25 */

ATF_TC_WITHOUT_HEAD(deep_short_le_ltk_neg_reply);
ATF_TC_BODY(deep_short_le_ltk_neg_reply, tc)
{ expect_short_cc(OP_LE_LTK_REQ_NEG_REPLY, 2); }		/* §7.8.26 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_path_loss_params);
ATF_TC_BODY(deep_short_le_set_path_loss_params, tc)
{ expect_short_cc(OP_LE_SET_PATH_LOSS_PARAMS, 8); }		/* §7.8.119 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_path_loss_enable);
ATF_TC_BODY(deep_short_le_set_path_loss_enable, tc)
{ expect_short_cc(OP_LE_SET_PATH_LOSS_ENABLE, 3); }		/* §7.8.120 */

ATF_TC_WITHOUT_HEAD(deep_short_le_set_tx_power_reporting_enable);
ATF_TC_BODY(deep_short_le_set_tx_power_reporting_enable, tc)
{ expect_short_cc(OP_LE_SET_TX_POWER_REPORTING_ENABLE, 4); }	/* §7.8.121 */

/* One ATF case per command handler whose short-packet arm returns a
 * Command Status (§7.7.15): Disconnect, Create_Connection,
 * Enable_Encryption, Read_Remote_Tx_Power. */
ATF_TC_WITHOUT_HEAD(deep_short_disconnect);
ATF_TC_BODY(deep_short_disconnect, tc)
{ expect_short_cs(OP_DISCONNECT, 3); }				/* §7.1.6 */

ATF_TC_WITHOUT_HEAD(deep_short_le_create_connection);
ATF_TC_BODY(deep_short_le_create_connection, tc)
{ expect_short_cs(OP_LE_CREATE_CONNECTION, 25); }		/* §7.8.12 */

ATF_TC_WITHOUT_HEAD(deep_short_le_enable_encryption);
ATF_TC_BODY(deep_short_le_enable_encryption, tc)
{ expect_short_cs(OP_LE_ENABLE_ENCRYPTION, 28); }		/* §7.8.24 */

ATF_TC_WITHOUT_HEAD(deep_short_le_read_remote_tx_power);
ATF_TC_BODY(deep_short_le_read_remote_tx_power, tc)
{ expect_short_cs(OP_LE_READ_REMOTE_TX_POWER, 3); }		/* §7.8.118 */

/*
 * LE_Set_Advertising_Data (§7.8.7): the significant length byte must be
 * present and <= 31 and must not exceed the bytes actually supplied; a full
 * 31-byte payload is accepted.  All three failure shapes -> 0x12.
 */
ATF_TC_WITHOUT_HEAD(deep_adv_data_length_edges);
ATF_TC_BODY(deep_adv_data_length_edges, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[64];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);
	memset(p, 0, sizeof(p));

	/* Zero-length command (no significant-length byte at all). */
	cap_reset(&cp);
	feed_cmd(e, OP_LE_SET_ADV_DATA, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_DATA), OP_LE_SET_ADV_DATA,
	    ST_INVALID_PARAMS);

	/* Significant length 32 > 31. */
	cap_reset(&cp);
	p[0] = 32;
	feed_cmd(e, OP_LE_SET_ADV_DATA, p, 33);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_DATA), OP_LE_SET_ADV_DATA,
	    ST_INVALID_PARAMS);

	/* Significant length 10 but only 3 data bytes supplied. */
	cap_reset(&cp);
	p[0] = 10;
	feed_cmd(e, OP_LE_SET_ADV_DATA, p, 4);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_DATA), OP_LE_SET_ADV_DATA,
	    ST_INVALID_PARAMS);

	/* Boundary: exactly 31 bytes of AD is accepted (§7.8.7). */
	cap_reset(&cp);
	p[0] = 31;
	feed_cmd(e, OP_LE_SET_ADV_DATA, p, 32);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_DATA), OP_LE_SET_ADV_DATA,
	    ST_SUCCESS);

	hci_emu_free(e);
}

/* LE_Set_Scan_Response_Data (§7.8.8): same three length-validation shapes. */
ATF_TC_WITHOUT_HEAD(deep_scanrsp_data_length_edges);
ATF_TC_BODY(deep_scanrsp_data_length_edges, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[64];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);
	memset(p, 0, sizeof(p));

	cap_reset(&cp);
	feed_cmd(e, OP_LE_SET_SCAN_RSP_DATA, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_SCAN_RSP_DATA),
	    OP_LE_SET_SCAN_RSP_DATA, ST_INVALID_PARAMS);

	cap_reset(&cp);
	p[0] = 40;
	feed_cmd(e, OP_LE_SET_SCAN_RSP_DATA, p, 41);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_SCAN_RSP_DATA),
	    OP_LE_SET_SCAN_RSP_DATA, ST_INVALID_PARAMS);

	cap_reset(&cp);
	p[0] = 5;
	feed_cmd(e, OP_LE_SET_SCAN_RSP_DATA, p, 3);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_SCAN_RSP_DATA),
	    OP_LE_SET_SCAN_RSP_DATA, ST_INVALID_PARAMS);

	/* A full 31-byte scan response is accepted. */
	cap_reset(&cp);
	p[0] = 31;
	feed_cmd(e, OP_LE_SET_SCAN_RSP_DATA, p, 32);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_SCAN_RSP_DATA),
	    OP_LE_SET_SCAN_RSP_DATA, ST_SUCCESS);

	hci_emu_free(e);
}

/* ================================================================
 * SECTION 2: unknown opcode + raw input framing edges.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_unknown_opcode);
ATF_TC_BODY(deep_unknown_opcode, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint16_t bogus1 = HCI_DEEP_SPEC_OP_UNKNOWN_VENDOR;
	uint16_t bogus2 = HCI_DEEP_SPEC_OP_UNKNOWN_LE;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* Unknown opcode -> Command Complete Unknown HCI Command (§7.7.14). */
	cap_reset(&cp);
	feed_cmd(e, bogus1, NULL, 0);
	ATF_CHECK_EQ(1, cp.n);
	check_cc_status(cap_find_cc(&cp, bogus1), bogus1, ST_UNKNOWN_CMD);

	cap_reset(&cp);
	feed_cmd(e, bogus2, NULL, 0);
	check_cc_status(cap_find_cc(&cp, bogus2), bogus2, ST_UNKNOWN_CMD);

	hci_emu_free(e);
}

ATF_TC_WITHOUT_HEAD(deep_input_framing_edges);
ATF_TC_BODY(deep_input_framing_edges, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t buf[16];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* NULL packet: no output, no crash. */
	cap_reset(&cp);
	hci_emu_input(e, NULL, 8);
	ATF_CHECK_EQ(0, cp.n);

	/* Zero length: ignored. */
	cap_reset(&cp);
	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	hci_emu_input(e, buf, 0);
	ATF_CHECK_EQ(0, cp.n);

	/* Command header shorter than 4 bytes: ignored. */
	cap_reset(&cp);
	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	buf[1] = 0x03;
	buf[2] = 0x0c;
	hci_emu_input(e, buf, 3);
	ATF_CHECK_EQ(0, cp.n);

	/* Command claims 5 param bytes but only 2 are present: truncated. */
	cap_reset(&cp);
	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	le16enc(&buf[1], OP_SET_EVENT_MASK);
	buf[3] = 5;
	buf[4] = 0x00;
	buf[5] = 0x00;
	hci_emu_input(e, buf, 6);
	ATF_CHECK_EQ(0, cp.n);

	/* Unknown packet-type indicator: ignored. */
	cap_reset(&cp);
	buf[0] = 0x09;
	hci_emu_input(e, buf, 4);
	ATF_CHECK_EQ(0, cp.n);

	/* A well-formed Reset still works after all the junk (§7.3.2). */
	cap_reset(&cp);
	feed_cmd(e, OP_RESET, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_RESET), OP_RESET, ST_SUCCESS);

	hci_emu_free(e);
}

/* ================================================================
 * SECTION 3: resolving-list add / remove / clear / capacity.
 * Vol 4 Part E §7.8.38-.40.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_resolving_list_lifecycle);
ATF_TC_BODY(deep_resolving_list_lifecycle, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[39];
	int i;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* Remove from an empty list -> Unknown Connection Identifier (§7.8.39). */
	cap_reset(&cp);
	memset(p, 0, sizeof(p));
	p[0] = 0x00;
	p[1] = 0x01;			/* identity addr byte 0 */
	feed_cmd(e, OP_LE_REMOVE_RESOLV, p, 7);
	check_cc_status(cap_find_cc(&cp, OP_LE_REMOVE_RESOLV),
	    OP_LE_REMOVE_RESOLV, ST_UNKNOWN_CONN);
	ATF_CHECK_EQ(0, hci_emu_get_resolving_list_count(e));

	/* Add three distinct identities (§7.8.38). */
	for (i = 0; i < 3; i++) {
		cap_reset(&cp);
		memset(p, 0, sizeof(p));
		p[0] = 0x00;			/* public identity */
		p[1] = (uint8_t)(0x10 + i);	/* distinct identity address */
		feed_cmd(e, OP_LE_ADD_RESOLV, p, 39);
		check_cc_status(cap_find_cc(&cp, OP_LE_ADD_RESOLV),
		    OP_LE_ADD_RESOLV, ST_SUCCESS);
		ATF_CHECK_EQ(i + 1, hci_emu_get_resolving_list_count(e));
	}

	/* Remove the middle entry -> the tail shifts down (§7.8.39). */
	cap_reset(&cp);
	memset(p, 0, sizeof(p));
	p[0] = 0x00;
	p[1] = 0x11;			/* second identity */
	feed_cmd(e, OP_LE_REMOVE_RESOLV, p, 7);
	check_cc_status(cap_find_cc(&cp, OP_LE_REMOVE_RESOLV),
	    OP_LE_REMOVE_RESOLV, ST_SUCCESS);
	ATF_CHECK_EQ(2, hci_emu_get_resolving_list_count(e));

	/* Remove a never-present identity -> 0x02. */
	cap_reset(&cp);
	memset(p, 0, sizeof(p));
	p[0] = 0x00;
	p[1] = 0x7e;
	feed_cmd(e, OP_LE_REMOVE_RESOLV, p, 7);
	check_cc_status(cap_find_cc(&cp, OP_LE_REMOVE_RESOLV),
	    OP_LE_REMOVE_RESOLV, ST_UNKNOWN_CONN);

	/* Clear (§7.8.40): list emptied. */
	cap_reset(&cp);
	feed_cmd(e, OP_LE_CLEAR_RESOLV, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_LE_CLEAR_RESOLV), OP_LE_CLEAR_RESOLV,
	    ST_SUCCESS);
	ATF_CHECK_EQ(0, hci_emu_get_resolving_list_count(e));

	hci_emu_free(e);
}

/*
 * Filling the resolving list past its depth returns Memory Capacity
 * Exceeded (0x07) and does not grow the list (§7.8.38).  The emulator's
 * table depth is 8.
 */
ATF_TC_WITHOUT_HEAD(deep_resolving_list_capacity);
ATF_TC_BODY(deep_resolving_list_capacity, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[39];
	int i;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	cap_reset(&cp);
	hci_emu_set_output(e, cap_out, &cp);

	for (i = 0; i < 8; i++) {
		memset(p, 0, sizeof(p));
		p[0] = 0x00;
		p[1] = (uint8_t)(0x20 + i);
		feed_cmd(e, OP_LE_ADD_RESOLV, p, 39);
	}
	ATF_CHECK_EQ(8, hci_emu_get_resolving_list_count(e));

	/* Ninth add is rejected. */
	cap_reset(&cp);
	memset(p, 0, sizeof(p));
	p[0] = 0x00;
	p[1] = 0x99;
	feed_cmd(e, OP_LE_ADD_RESOLV, p, 39);
	check_cc_status(cap_find_cc(&cp, OP_LE_ADD_RESOLV), OP_LE_ADD_RESOLV,
	    ST_MEM_CAP_EXCEEDED);
	ATF_CHECK_EQ(8, hci_emu_get_resolving_list_count(e));

	hci_emu_free(e);
}

/* ================================================================
 * SECTION 4: Reset clears volatile state + back-to-back commands.
 * Vol 4 Part E §7.3.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_reset_clears_state);
ATF_TC_BODY(deep_reset_clears_state, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint8_t p[39];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	/* Dirty a pile of volatile state on B. */
	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);
	p[0] = 0x01;
	feed_cmd(b, OP_LE_SET_ADDR_RESOLUTION_ENABLE, p, 1);
	memset(p, 0, sizeof(p));
	p[0] = 0x00; p[1] = 0x55;
	feed_cmd(b, OP_LE_ADD_RESOLV, p, 39);
	memset(p, 0xff, 8);
	feed_cmd(b, OP_SET_EVENT_MASK, p, 8);
	feed_cmd(b, OP_LE_SET_EVENT_MASK, p, 8);
	ATF_CHECK_EQ(1, hci_emu_get_scan_enable(b));
	ATF_CHECK_EQ(1, hci_emu_get_addr_resolution_enable(b));
	ATF_CHECK_EQ(1, hci_emu_get_resolving_list_count(b));
	ATF_CHECK(hci_emu_get_event_mask(b) != 0);
	ATF_CHECK(hci_emu_get_le_event_mask(b) != 0);

	/* Reset clears it all, drops connections (§7.3.2). */
	cap_reset(&bcap);
	feed_cmd(b, OP_RESET, NULL, 0);
	check_cc_status(cap_find_cc(&bcap, OP_RESET), OP_RESET, ST_SUCCESS);
	ATF_CHECK_EQ(0, hci_emu_get_scan_enable(b));
	ATF_CHECK_EQ(0, hci_emu_get_addr_resolution_enable(b));
	ATF_CHECK_EQ(0, hci_emu_get_resolving_list_count(b));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));
	ATF_CHECK_EQ((uint64_t)0, hci_emu_get_event_mask(b));
	ATF_CHECK_EQ((uint64_t)0, hci_emu_get_le_event_mask(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

ATF_TC_WITHOUT_HEAD(deep_back_to_back_commands);
ATF_TC_BODY(deep_back_to_back_commands, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[8];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* Five commands fed back to back each produce exactly one response. */
	cap_reset(&cp);
	feed_cmd(e, OP_RESET, NULL, 0);
	feed_cmd(e, OP_READ_BDADDR, NULL, 0);
	p[0] = 0x01;
	feed_cmd(e, OP_LE_SET_ADV_ENABLE, p, 1);
	p[0] = 0x00;
	feed_cmd(e, OP_LE_SET_ADV_ENABLE, p, 1);
	feed_cmd(e, OP_LE_CLEAR_RESOLV, NULL, 0);

	ATF_CHECK_EQ(5, cp.n);
	ATF_CHECK(cap_find_cc(&cp, OP_RESET) != NULL);
	ATF_CHECK(cap_find_cc(&cp, OP_READ_BDADDR) != NULL);
	ATF_CHECK(cap_find_cc(&cp, OP_LE_SET_ADV_ENABLE) != NULL);
	ATF_CHECK(cap_find_cc(&cp, OP_LE_CLEAR_RESOLV) != NULL);
	/* adv_enable ended at 0 after the 1-then-0 toggle. */
	ATF_CHECK_EQ(0, hci_emu_get_adv_enable(e));

	hci_emu_free(e);
}

/* ================================================================
 * SECTION 5: fault injection across command classes.
 * Vol 4 Part E §1.3.  The hook forces a chosen status and skips the real
 * handler (return params omitted; spec-legal on failure).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_fault_injection_classes);
ATF_TC_BODY(deep_fault_injection_classes, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[8];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* Force an info-read command (Read_BD_ADDR) to Command Disallowed. */
	hci_emu_force_status(e, OP_READ_BDADDR, ST_CMD_DISALLOWED);
	/* Force a config command (LE_Set_Adv_Enable) to a different status. */
	hci_emu_force_status(e, OP_LE_SET_ADV_ENABLE, 0x1f);
	/* Force a Command-Status command (LE_Create_Connection) to a status. */
	hci_emu_force_status(e, OP_LE_CREATE_CONNECTION, 0x0c);

	/* The forced status is delivered as a status-only Command Complete
	 * regardless of the command's normal completion event kind. */
	cap_reset(&cp);
	feed_cmd(e, OP_READ_BDADDR, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_READ_BDADDR), OP_READ_BDADDR,
	    ST_CMD_DISALLOWED);

	cap_reset(&cp);
	p[0] = 0x01;
	feed_cmd(e, OP_LE_SET_ADV_ENABLE, p, 1);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_ENABLE),
	    OP_LE_SET_ADV_ENABLE, 0x1f);
	/* The real handler was skipped: adv did NOT enable. */
	ATF_CHECK_EQ(0, hci_emu_get_adv_enable(e));

	cap_reset(&cp);
	feed_cmd(e, OP_LE_CREATE_CONNECTION, p, 1);
	check_cc_status(cap_find_cc(&cp, OP_LE_CREATE_CONNECTION),
	    OP_LE_CREATE_CONNECTION, 0x0c);

	/* Updating an existing override in place changes the delivered status. */
	hci_emu_force_status(e, OP_READ_BDADDR, 0x11);
	cap_reset(&cp);
	feed_cmd(e, OP_READ_BDADDR, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_READ_BDADDR), OP_READ_BDADDR, 0x11);

	/* force_status(opcode 0x0000) is the documented "clear all" NOP. */
	hci_emu_force_status(e, 0x0000, 0x00);
	cap_reset(&cp);
	feed_cmd(e, OP_READ_BDADDR, NULL, 0);
	/* Now the real handler runs: status + BD_ADDR(6) (§7.4.6). */
	{
		const uint8_t *cc = cap_find_cc(&cp, OP_READ_BDADDR);
		ATF_REQUIRE(cc != NULL);
		ATF_CHECK_EQ(ST_SUCCESS, cc[6]);
		ATF_CHECK_EQ((uint8_t)(3 + 7), cc[2]);	/* status + 6-byte addr */
	}

	/* Re-arm and clear the other way, via the explicit clear entry point. */
	hci_emu_force_status(e, OP_LE_SET_ADV_ENABLE, 0x0c);
	hci_emu_clear_forced_status(e);
	cap_reset(&cp);
	p[0] = 0x01;
	feed_cmd(e, OP_LE_SET_ADV_ENABLE, p, 1);
	check_cc_status(cap_find_cc(&cp, OP_LE_SET_ADV_ENABLE),
	    OP_LE_SET_ADV_ENABLE, ST_SUCCESS);
	ATF_CHECK_EQ(1, hci_emu_get_adv_enable(e));

	hci_emu_free(e);
}

/*
 * A forced status on Disconnect suppresses the real teardown: the forced
 * Command Complete is emitted and the connection is left intact (no
 * Disconnection Complete on either side).
 */
ATF_TC_WITHOUT_HEAD(deep_fault_blocks_disconnect);
ATF_TC_BODY(deep_fault_blocks_disconnect, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint16_t bh;
	uint8_t p[3];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	hci_emu_force_status(b, OP_DISCONNECT, ST_CMD_DISALLOWED);
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x13;
	feed_cmd(b, OP_DISCONNECT, p, 3);

	/* Forced Command Complete, no Disconnection Complete anywhere. */
	check_cc_status(cap_find_cc(&bcap, OP_DISCONNECT), OP_DISCONNECT,
	    ST_CMD_DISALLOWED);
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) == NULL);
	ATF_CHECK(cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) == NULL);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 6: disconnect edges (unknown handle, reason propagation).
 * Vol 4 Part E §7.1.6, §7.7.5.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_disconnect_unknown_handle);
ATF_TC_BODY(deep_disconnect_unknown_handle, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[3];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	/* Disconnect a handle that was never connected -> Command Status 0x02. */
	cap_reset(&cp);
	le16enc(&p[0], 0x0040);
	p[2] = 0x13;
	feed_cmd(e, OP_DISCONNECT, p, 3);
	check_cs(cap_find_cs(&cp, OP_DISCONNECT), OP_DISCONNECT, ST_UNKNOWN_CONN);
	ATF_CHECK(cap_find_event(&cp, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) == NULL);

	hci_emu_free(e);
}

ATF_TC_WITHOUT_HEAD(deep_disconnect_reason_propagation);
ATF_TC_BODY(deep_disconnect_reason_propagation, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *bd, *ad;
	uint16_t ah, bh;
	uint8_t p[3];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Initiator supplies reason 0x15 (Remote Device Terminated, Low Power). */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x15;
	feed_cmd(b, OP_DISCONNECT, p, 3);

	/* Initiator sees Connection Terminated By Local Host (0x16, §7.1.6). */
	bd = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL);
	ATF_REQUIRE(bd != NULL);
	ATF_CHECK_EQ(bh, le16dec(&bd[4]));
	ATF_CHECK_EQ(REASON_LOCAL_HOST_TERM, bd[6]);

	/* Remote sees exactly the reason the initiator supplied (0x15). */
	ad = cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL);
	ATF_REQUIRE(ad != NULL);
	ATF_CHECK_EQ(ah, le16dec(&ad[4]));
	ATF_CHECK_EQ(0x15, ad[6]);

	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 7: adv/scan report gating over the simulated air.
 * A report appears only when one side advertises (connectably or not)
 * AND the other scans.  Vol 4 Part E §7.7.65.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_adv_after_scan_and_gating);
ATF_TC_BODY(deep_adv_after_scan_and_gating, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t p[64];

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_link(a, b);
	hci_emu_set_bd_addr(a, a_addr);

	/* B scans first, before anyone advertises: no report. */
	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);
	ATF_CHECK(cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP) == NULL);

	/* Now A enables advertising while B is already scanning: exactly one
	 * report is delivered to B by the adv-enable air path. */
	cap_reset(&bcap);
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	ATF_CHECK_EQ(1, cap_count_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE));
	ATF_CHECK(cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP) != NULL);

	/* A advertising but B NOT scanning: turning A off then on with B's
	 * scan disabled delivers no further report. */
	p[0] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);
	cap_reset(&bcap);
	p[0] = 0x00;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	ATF_CHECK(cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP) == NULL);

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Advertiser with a random own-address: the report and (if it connected)
 * the connection carry the random address, exercising the random branch of
 * the on-air address selection (§7.8.5 Own_Address_Type).
 */
ATF_TC_WITHOUT_HEAD(deep_random_own_address_report);
ATF_TC_BODY(deep_random_own_address_report, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_pub[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	const uint8_t a_rnd[6] = { 0xc0, 0xde, 0xca, 0xfe, 0xba, 0xbe };
	const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	const uint8_t *ev;
	uint8_t p[64];

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_link(a, b);

	/* A: public bd_addr set, but advertise with Own_Address_Type = random. */
	hci_emu_set_bd_addr(a, a_pub);
	feed_cmd(a, OP_LE_SET_RANDOM_ADDRESS, a_rnd, 6);

	memset(p, 0, sizeof(p));
	le16enc(&p[0], 0x0020);
	le16enc(&p[2], 0x0040);
	p[4] = 0x00;			/* ADV_IND */
	p[5] = 0x01;			/* Own_Address_Type = random */
	p[13] = 0x07;
	feed_cmd(a, OP_LE_SET_ADV_PARAMS, p, 15);

	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);

	/* B scans and must observe the RANDOM address with addr_type 0x01. */
	cap_reset(&bcap);
	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);
	ev = cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x01, ev[6]);			/* address type: random */
	ATF_CHECK_EQ(0, memcmp(&ev[7], a_rnd, 6));	/* the random address */

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 8: LE_Create_Connection pending / cancel edges.
 * Vol 4 Part E §7.8.12, §7.8.13.
 * ================================================================ */

/* Cancel with no outstanding create -> Command Disallowed (§7.8.13). */
ATF_TC_WITHOUT_HEAD(deep_create_connection_cancel_disallowed);
ATF_TC_BODY(deep_create_connection_cancel_disallowed, tc)
{
	struct hci_emu *e;
	struct cap cp;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	feed_cmd(e, OP_LE_CREATE_CONNECTION_CANCEL, NULL, 0);
	check_cc_status(cap_find_cc(&cp, OP_LE_CREATE_CONNECTION_CANCEL),
	    OP_LE_CREATE_CONNECTION_CANCEL, ST_CMD_DISALLOWED);
	/* No LE Connection Complete is emitted when nothing was pending. */
	ATF_CHECK(cap_find_event(&cp, HCI_LINK_SPEC_NG_HCI_EVENT_LE) == NULL);

	hci_emu_free(e);
}

/*
 * Create toward a non-connectable advertiser (ADV_NONCONN_IND, 0x03) stays
 * pending: the advertiser is present at the right address but not
 * connectable, so no connection forms and no LE Connection Complete arrives
 * until Cancel (§7.8.12 Advertising_Type / §7.8.13).
 */
ATF_TC_WITHOUT_HEAD(deep_create_connection_nonconnectable);
ATF_TC_BODY(deep_create_connection_nonconnectable, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t *cc;
	uint8_t p[25], plen;

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_link(a, b);
	hci_emu_set_bd_addr(a, a_addr);

	/* A advertises ADV_NONCONN_IND (0x03). */
	memset(p, 0, sizeof(p));
	le16enc(&p[0], 0x0020);
	le16enc(&p[2], 0x0040);
	p[4] = 0x03;			/* ADV_NONCONN_IND: not connectable */
	p[13] = 0x07;
	feed_cmd(a, OP_LE_SET_ADV_PARAMS, p, 15);
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);

	/* B tries to connect to A: accepted, but pending (no connection). */
	cap_reset(&bcap);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, 0x00c8);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);
	check_cs(cap_find_cs(&bcap, OP_LE_CREATE_CONNECTION),
	    OP_LE_CREATE_CONNECTION, ST_SUCCESS);
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE) == NULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	/* Cancel completes with an LE Connection Complete status 0x02. */
	cap_reset(&bcap);
	feed_cmd(b, OP_LE_CREATE_CONNECTION_CANCEL, NULL, 0);
	check_cc_status(cap_find_cc(&bcap, OP_LE_CREATE_CONNECTION_CANCEL),
	    OP_LE_CREATE_CONNECTION_CANCEL, ST_SUCCESS);
	cc = cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_CON_COMPL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(ST_UNKNOWN_CONN, cc[4]);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* Create with no physical link at all also stays pending. */
ATF_TC_WITHOUT_HEAD(deep_create_connection_no_link);
ATF_TC_BODY(deep_create_connection_no_link, tc)
{
	struct hci_emu *e;
	struct cap cp;
	const uint8_t peer[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	uint8_t p[25], plen;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	plen = build_create_conn(p, 0x00, peer, 0x00, 0x0028, 0x0000, 0x00c8);
	feed_cmd(e, OP_LE_CREATE_CONNECTION, p, plen);
	check_cs(cap_find_cs(&cp, OP_LE_CREATE_CONNECTION),
	    OP_LE_CREATE_CONNECTION, ST_SUCCESS);
	ATF_CHECK(cap_find_event(&cp, HCI_LINK_SPEC_NG_HCI_EVENT_LE) == NULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(e));

	hci_emu_free(e);
}

/* Create toward a linked peer that is not advertising at all: pending. */
ATF_TC_WITHOUT_HEAD(deep_create_connection_peer_silent);
ATF_TC_BODY(deep_create_connection_peer_silent, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	uint8_t p[25], plen;

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_set_bd_addr(a, a_addr);
	hci_emu_link(a, b);

	/* A is linked but never enabled advertising. */
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, 0x00c8);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);
	check_cs(cap_find_cs(&bcap, OP_LE_CREATE_CONNECTION),
	    OP_LE_CREATE_CONNECTION, ST_SUCCESS);
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE) == NULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * A connection created with Supervision_Timeout = 0 arms no supervision
 * timer (the emulator treats a zero duration as "off"): advancing the clock
 * far past any plausible deadline never tears it down.
 */
ATF_TC_WITHOUT_HEAD(deep_zero_supervision_timeout);
ATF_TC_BODY(deep_zero_supervision_timeout, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x0000);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	hci_emu_set_clock(b, 0);
	cap_reset(&bcap);
	hci_emu_advance(b, 3600ULL * 1000000000ULL);	/* an hour */
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) == NULL);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Connection-table exhaustion + handle allocation across many links.
 * Establish EMU_CONN_MAX (4) connections between the same pair by
 * re-advertising after each, verifying handles are distinct and the
 * getter reports the growing count; the 5th create finds both tables full
 * and stays pending.  Also exercises hci_emu_get_conn_handle() out of range.
 */
ATF_TC_WITHOUT_HEAD(deep_connection_table_exhaustion);
ATF_TC_BODY(deep_connection_table_exhaustion, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint16_t handles[4];
	uint8_t p[25], plen;
	int i, j;

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_set_bd_addr(a, a_addr);
	hci_emu_set_bd_addr(b, b_addr);
	hci_emu_link(a, b);

	for (i = 0; i < 4; i++) {
		/* (Re)start A advertising (it stops on each connection). */
		p[0] = sizeof(ad);
		memcpy(&p[1], ad, sizeof(ad));
		feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
		p[0] = 0x01;
		feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);

		plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000,
		    0x00c8);
		feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);
		ATF_CHECK_EQ(i + 1, hci_emu_get_conn_count(b));
		ATF_CHECK_EQ(i + 1, hci_emu_get_conn_count(a));
		ATF_REQUIRE(hci_emu_get_conn_handle(b, i, &handles[i]));
	}

	/* All four handles are distinct (§5.4.2 handle allocation). */
	for (i = 0; i < 4; i++)
		for (j = i + 1; j < 4; j++)
			ATF_CHECK(handles[i] != handles[j]);

	/* get_conn_handle beyond the populated count returns 0 (not found). */
	ATF_CHECK_EQ(0, hci_emu_get_conn_handle(b, 4, NULL));
	/* handle_out == NULL is tolerated for an in-range index. */
	ATF_CHECK_EQ(1, hci_emu_get_conn_handle(b, 0, NULL));

	/* Fifth create: both connection tables are full -> stays pending. */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	cap_reset(&bcap);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, 0x00c8);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);
	check_cs(cap_find_cs(&bcap, OP_LE_CREATE_CONNECTION),
	    OP_LE_CREATE_CONNECTION, ST_SUCCESS);
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE) == NULL);
	ATF_CHECK_EQ(4, hci_emu_get_conn_count(b));

	/*
	 * Free the first table slot by disconnecting handles[0]; the getter
	 * must then skip the now-inactive leading slot when walking to index 0
	 * (the connection-table iteration's "skip inactive" path).
	 */
	{
		uint16_t got;
		uint8_t p3[3];

		le16enc(&p3[0], handles[0]);
		p3[2] = 0x13;
		feed_cmd(b, OP_DISCONNECT, p3, 3);
		ATF_CHECK_EQ(3, hci_emu_get_conn_count(b));
		ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &got));
		ATF_CHECK(got != handles[0]);
	}

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 9: ACL data-path edges.  Vol 4 Part E §5.4.2, §7.7.19.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_acl_edges);
ATF_TC_BODY(deep_acl_edges, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t buf[16];
	uint16_t bh;

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* ACL on a handle with no connection: dropped, no output, no credit. */
	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, 0x0abc, payload, sizeof(payload));
	ATF_CHECK_EQ(0, bcap.n);
	ATF_CHECK_EQ(0, acap.n);

	/* Truncated ACL header (< 5 bytes): ignored. */
	cap_reset(&bcap);
	buf[0] = HCI_LINK_SPEC_ACL_PKT;
	buf[1] = 0x00;
	buf[2] = 0x00;
	hci_emu_input(b, buf, 3);
	ATF_CHECK_EQ(0, bcap.n);

	/* Header claims 8 payload bytes but only 2 are present: dropped. */
	cap_reset(&acap);
	cap_reset(&bcap);
	buf[0] = HCI_LINK_SPEC_ACL_PKT;
	le16enc(&buf[1], HCI_LINK_SPEC_MAKE_HANDLE(bh, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT));
	le16enc(&buf[3], 8);
	buf[5] = 0x00;
	buf[6] = 0x00;
	hci_emu_input(b, buf, 7);
	ATF_CHECK_EQ(0, bcap.n);
	ATF_CHECK_EQ(0, acap.n);

	/* Disconnect, then ACL on the (now stale) handle is dropped. */
	{
		uint8_t p[3];

		le16enc(&p[0], bh);
		p[2] = 0x13;
		feed_cmd(b, OP_DISCONNECT, p, 3);
	}
	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, bh, payload, sizeof(payload));
	ATF_CHECK_EQ(0, bcap.n);
	ATF_CHECK_EQ(0, acap.n);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 10: clock / timer-queue behaviour.  Vol 6 Part B §4.5.2 drives
 * the supervision timer; the queue mechanics are the emulator's Increment 3
 * seam (hci_emulator.h).
 * ================================================================ */

/* set_clock / get_clock round-trip and zero / large no-op advances. */
ATF_TC_WITHOUT_HEAD(deep_clock_get_set_advance);
ATF_TC_BODY(deep_clock_get_set_advance, tc)
{
	struct hci_emu *e;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);

	hci_emu_set_clock(e, 123456789ULL);
	ATF_CHECK_EQ(123456789ULL, hci_emu_get_clock(e));

	/* Advancing with no armed timer just moves "now". */
	hci_emu_advance(e, 0);
	ATF_CHECK_EQ(123456789ULL, hci_emu_get_clock(e));
	hci_emu_advance(e, 1000000000ULL);
	ATF_CHECK_EQ(1123456789ULL, hci_emu_get_clock(e));

	hci_emu_free(e);
}

/*
 * Two connections with different supervision timeouts arm two timers.  A
 * single advance past both deadlines fires them in deadline order, tearing
 * down both links.  The first-established link is given the LARGER timeout
 * so the second timer in the queue has the earlier deadline (exercising the
 * "earlier deadline found later in the queue" ordering branch of advance()).
 */
ATF_TC_WITHOUT_HEAD(deep_timer_ordering_multi);
ATF_TC_BODY(deep_timer_ordering_multi, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t p[25], plen;

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_set_bd_addr(a, a_addr);
	hci_emu_set_bd_addr(b, b_addr);
	hci_emu_link(a, b);
	hci_emu_set_clock(b, 0);

	/* First connection: large supervision timeout (0x0200 = 5.12 s). */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, 0x0200);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);

	/* Second connection: small supervision timeout (0x0010 = 160 ms). */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000, 0x0010);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);

	ATF_CHECK_EQ(2, hci_emu_get_conn_count(b));

	/*
	 * A single advance past BOTH deadlines: both timers are simultaneously
	 * due, and advance() must fire them in deadline order (the small-STO
	 * link first).  This drives the "earlier deadline found later in the
	 * queue" comparison in advance()'s selection loop.
	 */
	cap_reset(&acap);
	cap_reset(&bcap);
	hci_emu_advance(b, 0x0200 * SUP_UNIT_NS + 1000000ULL);
	ATF_CHECK_EQ(2, cap_count_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * ACL traffic re-arms the supervision timer (§4.5.2): advancing near the
 * deadline, then sending an ACL, resets the countdown so the link survives
 * a further sub-timeout advance, then finally times out.
 */
ATF_TC_WITHOUT_HEAD(deep_supervision_rearm_on_acl);
ATF_TC_BODY(deep_supervision_rearm_on_acl, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t payload[] = { 0x01, 0x02, 0x03 };
	uint16_t bh;

	/* Supervision timeout 0x0064 = 100 units = 1.0 s. */
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x0064);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	hci_emu_set_clock(b, 0);

	/* Advance to 0.9 s (short of 1.0 s): still connected. */
	hci_emu_advance(b, 900ULL * 1000000ULL);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	/* ACL traffic re-arms the timer relative to "now" (0.9 s). */
	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, bh, payload, sizeof(payload));

	/* Advance another 0.9 s (to 1.8 s absolute): had the timer NOT been
	 * re-armed it would have fired at 1.0 s; it survives. */
	hci_emu_advance(b, 900ULL * 1000000ULL);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) == NULL);

	/* Advance past the re-armed 1.0 s window (to 1.95 s): now it fires. */
	hci_emu_advance(b, 200ULL * 1000000ULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL) != NULL);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 11: encryption edges.  Vol 4 Part E §7.8.24-.26, §7.7.8.
 * ================================================================ */

/* Enable encryption on a handle with no connection -> Command Status 0x02. */
ATF_TC_WITHOUT_HEAD(deep_encryption_unknown_handle);
ATF_TC_BODY(deep_encryption_unknown_handle, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[28];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	memset(p, 0, sizeof(p));
	le16enc(&p[0], 0x0040);		/* no such connection */
	feed_cmd(e, OP_LE_ENABLE_ENCRYPTION, p, 28);
	check_cs(cap_find_cs(&cp, OP_LE_ENABLE_ENCRYPTION),
	    OP_LE_ENABLE_ENCRYPTION, ST_UNKNOWN_CONN);
	/* No LTK request is raised. */
	ATF_CHECK(cap_find_le_subevent(&cp, HCI_DEEP_SPEC_LEEV_LONG_TERM_KEY_REQUEST)
	    == NULL);

	/* LTK reply / negative-reply / path-loss on unknown handles report the
	 * error in their Command Complete (status + handle, §7.8.25-.26). */
	cap_reset(&cp);
	le16enc(&p[0], 0x0041);
	feed_cmd(e, OP_LE_LTK_REQ_REPLY, p, 18);
	check_cc_handle(cap_find_cc(&cp, OP_LE_LTK_REQ_REPLY),
	    OP_LE_LTK_REQ_REPLY, ST_UNKNOWN_CONN, 0x0041);
	ATF_CHECK(cap_find_event(&cp, HCI_LINK_SPEC_NG_HCI_EVENT_ENCRYPTION_CHANGE) == NULL);

	cap_reset(&cp);
	le16enc(&p[0], 0x0042);
	feed_cmd(e, OP_LE_LTK_REQ_NEG_REPLY, p, 2);
	check_cc_handle(cap_find_cc(&cp, OP_LE_LTK_REQ_NEG_REPLY),
	    OP_LE_LTK_REQ_NEG_REPLY, ST_UNKNOWN_CONN, 0x0042);

	hci_emu_free(e);
}

/*
 * Forced-fail encryption outcome: the settable success-path status is
 * non-zero, so the LTK reply completes with that error and encryption is
 * NOT enabled on either side (§7.7.8 Encryption_Change carries the status).
 */
ATF_TC_WITHOUT_HEAD(deep_encryption_forced_fail_outcome);
ATF_TC_BODY(deep_encryption_forced_fail_outcome, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *ev;
	uint16_t ah, bh;
	uint8_t p[28];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Model the controller failing the encryption start with 0x1a
	 * (Unsupported Remote Feature) on the success (LTK-reply) path. */
	hci_emu_set_encryption_outcome(a, 0x1a);
	hci_emu_set_encryption_outcome(b, 0x1a);

	cap_reset(&acap);
	cap_reset(&bcap);
	memset(p, 0, sizeof(p));
	le16enc(&p[0], bh);
	feed_cmd(b, OP_LE_ENABLE_ENCRYPTION, p, 28);

	/* A supplies the LTK, but the modeled outcome is a failure. */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], ah);
	feed_cmd(a, OP_LE_LTK_REQ_REPLY, p, 18);

	/* Both sides see Encryption Change status 0x1a, enabled = 0. */
	ev = cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_ENCRYPTION_CHANGE);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x1a, ev[3]);
	ATF_CHECK_EQ(0x00, ev[6]);
	ev = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_ENCRYPTION_CHANGE);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x1a, ev[3]);
	ATF_CHECK_EQ(0x00, ev[6]);

	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(a, ah));
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(b, bh));

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Encryption enable when the peer connection has vanished (peer reset):
 * the initiator still gets Command Status success, but no LTK request can
 * be raised on the peer (no peer connection object).
 */
ATF_TC_WITHOUT_HEAD(deep_encryption_peer_gone);
ATF_TC_BODY(deep_encryption_peer_gone, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint16_t bh;
	uint8_t p[28];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Reset A: A drops its connection object (keeps the physical link). */
	feed_cmd(a, OP_RESET, NULL, 0);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	/* B enables encryption: accepted, but A has no conn to request an LTK. */
	cap_reset(&acap);
	cap_reset(&bcap);
	memset(p, 0, sizeof(p));
	le16enc(&p[0], bh);
	feed_cmd(b, OP_LE_ENABLE_ENCRYPTION, p, 28);
	check_cs(cap_find_cs(&bcap, OP_LE_ENABLE_ENCRYPTION),
	    OP_LE_ENABLE_ENCRYPTION, ST_SUCCESS);
	ATF_CHECK(cap_find_le_subevent(&acap,
	    HCI_DEEP_SPEC_LEEV_LONG_TERM_KEY_REQUEST) == NULL);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* get_conn_encrypted for a handle that has no connection returns 0. */
ATF_TC_WITHOUT_HEAD(deep_get_conn_encrypted_nonexistent);
ATF_TC_BODY(deep_get_conn_encrypted_nonexistent, tc)
{
	struct hci_emu *e;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(e, 0x0040));
	hci_emu_free(e);
}

/* ================================================================
 * SECTION 12: LE Power Control edges.  Vol 4 Part E §7.8.117-.121,
 * §7.7.65.32-.33.
 * ================================================================ */

/* Read remote tx power on an unknown handle -> Command Status 0x02. */
ATF_TC_WITHOUT_HEAD(deep_read_remote_tx_power_unknown);
ATF_TC_BODY(deep_read_remote_tx_power_unknown, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t p[3];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	le16enc(&p[0], 0x0040);
	p[2] = 0x01;
	feed_cmd(e, OP_LE_READ_REMOTE_TX_POWER, p, 3);
	check_cs(cap_find_cs(&cp, OP_LE_READ_REMOTE_TX_POWER),
	    OP_LE_READ_REMOTE_TX_POWER, ST_UNKNOWN_CONN);
	ATF_CHECK(cap_find_le_subevent(&cp, HCI_LINK_SPEC_NG_HCI_LEEV_TX_POWER_REPORTING)
	    == NULL);

	hci_emu_free(e);
}

/*
 * Path-loss params / enable on an unknown handle report 0x02 in the
 * Command Complete (status + handle); enabling on a known handle with
 * enable = 0 stores the state but raises no threshold event.  Vol 4 Part E
 * §7.8.119-.120, §7.7.65.32.
 */
ATF_TC_WITHOUT_HEAD(deep_path_loss_unknown_and_disable);
ATF_TC_BODY(deep_path_loss_unknown_and_disable, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint16_t bh;
	uint8_t p[8];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Params on an unknown handle -> Command Complete status 0x02. */
	cap_reset(&bcap);
	memset(p, 0, sizeof(p));
	le16enc(&p[0], 0x0abc);
	feed_cmd(b, OP_LE_SET_PATH_LOSS_PARAMS, p, 8);
	check_cc_handle(cap_find_cc(&bcap, OP_LE_SET_PATH_LOSS_PARAMS),
	    OP_LE_SET_PATH_LOSS_PARAMS, ST_UNKNOWN_CONN, 0x0abc);

	/* Enable on an unknown handle -> 0x02, no event. */
	cap_reset(&bcap);
	le16enc(&p[0], 0x0abc);
	p[2] = 0x01;
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p, 3);
	check_cc_handle(cap_find_cc(&bcap, OP_LE_SET_PATH_LOSS_ENABLE),
	    OP_LE_SET_PATH_LOSS_ENABLE, ST_UNKNOWN_CONN, 0x0abc);
	ATF_CHECK(cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_PATH_LOSS_THRESHOLD)
	    == NULL);

	/* Enable = 0 on the real handle: success, but NO threshold event. */
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x00;
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p, 3);
	check_cc_handle(cap_find_cc(&bcap, OP_LE_SET_PATH_LOSS_ENABLE),
	    OP_LE_SET_PATH_LOSS_ENABLE, ST_SUCCESS, bh);
	ATF_CHECK(cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_PATH_LOSS_THRESHOLD)
	    == NULL);

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Path-loss zone boundaries (§7.7.65.32): with low_threshold = 0x30 and
 * high_threshold = 0x60, a current path loss <= low maps to the LOW zone
 * (0x00) and >= high maps to the HIGH zone (0x02).  The middle zone is
 * covered by the existing enc-test; here we pin the two extremes.
 */
ATF_TC_WITHOUT_HEAD(deep_path_loss_zone_boundaries);
ATF_TC_BODY(deep_path_loss_zone_boundaries, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *ev;
	uint16_t bh;
	uint8_t p[8];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Configure thresholds low=0x30 high=0x60. */
	memset(p, 0, sizeof(p));
	le16enc(&p[0], bh);
	p[2] = 0x60;			/* high_threshold */
	p[3] = 0x04;
	p[4] = 0x30;			/* low_threshold */
	p[5] = 0x04;
	le16enc(&p[6], 0x000a);
	feed_cmd(b, OP_LE_SET_PATH_LOSS_PARAMS, p, 8);

	/* Path loss exactly at the low threshold -> LOW zone (0x00). */
	hci_emu_set_conn_path_loss(b, bh, 0x30);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x01;
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p, 3);
	ev = cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_PATH_LOSS_THRESHOLD);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x30, ev[6]);			/* current path loss */
	ATF_CHECK_EQ(0x00, ev[7]);			/* LOW zone */

	/* Path loss at/above the high threshold -> HIGH zone (0x02). */
	hci_emu_set_conn_path_loss(b, bh, 0x70);
	cap_reset(&bcap);
	p[2] = 0x00;
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p, 3);	/* toggle off */
	cap_reset(&bcap);
	p[2] = 0x01;
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p, 3);	/* re-enable */
	ev = cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_PATH_LOSS_THRESHOLD);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x70, ev[6]);
	ATF_CHECK_EQ(0x02, ev[7]);			/* HIGH zone */

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * LE_Set_Transmit_Power_Reporting_Enable (§7.8.121): success on a known
 * handle stores the local/remote enables and returns Command Complete
 * (status + handle); an unknown handle returns 0x02.
 */
ATF_TC_WITHOUT_HEAD(deep_tx_power_reporting_enable);
ATF_TC_BODY(deep_tx_power_reporting_enable, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint16_t bh;
	uint8_t p[4];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Known handle, both enables set. */
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x01;			/* local_enable */
	p[3] = 0x01;			/* remote_enable */
	feed_cmd(b, OP_LE_SET_TX_POWER_REPORTING_ENABLE, p, 4);
	check_cc_handle(cap_find_cc(&bcap, OP_LE_SET_TX_POWER_REPORTING_ENABLE),
	    OP_LE_SET_TX_POWER_REPORTING_ENABLE, ST_SUCCESS, bh);

	/* Unknown handle -> status 0x02. */
	cap_reset(&bcap);
	le16enc(&p[0], 0x0abc);
	p[2] = 0x00;
	p[3] = 0x00;
	feed_cmd(b, OP_LE_SET_TX_POWER_REPORTING_ENABLE, p, 4);
	check_cc_handle(cap_find_cc(&bcap, OP_LE_SET_TX_POWER_REPORTING_ENABLE),
	    OP_LE_SET_TX_POWER_REPORTING_ENABLE, ST_UNKNOWN_CONN, 0x0abc);

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Read remote tx power when the peer connection is absent: the reported
 * level falls back to the LOCAL connection's modeled tx power (the emulator
 * uses the local level when it cannot fetch the peer's).  §7.7.65.33.
 */
ATF_TC_WITHOUT_HEAD(deep_read_remote_tx_power_local_fallback);
ATF_TC_BODY(deep_read_remote_tx_power_local_fallback, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *ev;
	uint16_t bh;
	uint8_t p[3];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Model B's own tx power, then drop A's connection object. */
	hci_emu_set_conn_tx_power(b, bh, (int8_t)-4);
	feed_cmd(a, OP_RESET, NULL, 0);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));

	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x02;			/* PHY = LE 2M */
	feed_cmd(b, OP_LE_READ_REMOTE_TX_POWER, p, 3);
	ev = cap_find_le_subevent(&bcap, HCI_LINK_SPEC_NG_HCI_LEEV_TX_POWER_REPORTING);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x02, ev[8]);			/* PHY echoed */
	ATF_CHECK_EQ((uint8_t)-4, ev[9]);		/* local fallback level */

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * SECTION 13: reusable controller profiles.
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(deep_profile_legacy_rejects_advanced_le_commands);
ATF_TC_BODY(deep_profile_legacy_rejects_advanced_le_commands, tc)
{
	struct hci_emu *e;
	struct cap c;
	uint8_t periodic_params[7] = { 0, 0x06, 0, 0x06, 0, 0, 0 };
	uint8_t past_recv[3] = { 0x01, 0x00, 0x01 };
	uint8_t past_xfer[6] = { 0x40, 0x00, 0x34, 0x12, 0x01, 0x00 };
	uint8_t tx_power[3] = { 0x40, 0x00, 0x01 };
	uint8_t path_loss[8] = { 0x40, 0x00, 0x20, 0x02, 0x08, 0x02, 0x01, 0x00 };
	uint8_t cig[24];
	uint64_t features;

	memset(&c, 0, sizeof(c));
	memset(cig, 0, sizeof(cig));
	cig[14] = 1;		/* CIS_Count */
	cig[15] = 1;		/* CIS_ID */

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &c);
	ATF_REQUIRE_EQ(0, hci_emu_apply_profile(e, HCI_EMU_PROFILE_LEGACY));

	features = read_le_features(e, &c);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_PERIODIC_ADV);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_PAST_SENDER);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_POWER_CONTROL);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_CIS_CENTRAL);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PERIODIC_ADV_PARAMS, periodic_params,
	    sizeof(periodic_params));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_PERIODIC_ADV_PARAMS),
	    OP_LE_SET_PERIODIC_ADV_PARAMS, ST_UNKNOWN_CMD);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PERIODIC_ADV_RCV_ENABLE, past_recv,
	    sizeof(past_recv));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_PERIODIC_ADV_RCV_ENABLE),
	    OP_LE_SET_PERIODIC_ADV_RCV_ENABLE, ST_UNKNOWN_CMD);

	cap_reset(&c);
	feed_cmd(e, OP_LE_PERIODIC_ADV_SYNC_TRANSFER, past_xfer,
	    sizeof(past_xfer));
	check_cc_status(cap_find_cc(&c, OP_LE_PERIODIC_ADV_SYNC_TRANSFER),
	    OP_LE_PERIODIC_ADV_SYNC_TRANSFER, ST_UNKNOWN_CMD);

	cap_reset(&c);
	feed_cmd(e, OP_LE_READ_REMOTE_TX_POWER, tx_power, sizeof(tx_power));
	check_cc_status(cap_find_cc(&c, OP_LE_READ_REMOTE_TX_POWER),
	    OP_LE_READ_REMOTE_TX_POWER, ST_UNKNOWN_CMD);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PATH_LOSS_PARAMS, path_loss, sizeof(path_loss));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_PATH_LOSS_PARAMS),
	    OP_LE_SET_PATH_LOSS_PARAMS, ST_UNKNOWN_CMD);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_CIG_PARAMS, cig, sizeof(cig));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_CIG_PARAMS),
	    OP_LE_SET_CIG_PARAMS, ST_UNKNOWN_CMD);

	hci_emu_free(e);
}

ATF_TC_WITHOUT_HEAD(deep_profile_periodic_and_past_are_feature_gated);
ATF_TC_BODY(deep_profile_periodic_and_past_are_feature_gated, tc)
{
	struct hci_emu *e;
	struct cap c;
	uint8_t periodic_params[7] = { 0, 0x06, 0, 0x06, 0, 0, 0 };
	uint8_t past_recv[3] = { 0x01, 0x00, 0x01 };
	uint8_t past_xfer[6] = { 0x40, 0x00, 0x34, 0x12, 0x01, 0x00 };
	uint64_t features;

	memset(&c, 0, sizeof(c));
	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &c);
	ATF_REQUIRE_EQ(0, hci_emu_apply_profile(e,
	    HCI_EMU_PROFILE_PERIODIC));

	features = read_le_features(e, &c);
	ATF_CHECK((features & TEST_LE_FEAT_PERIODIC_ADV) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_PAST_SENDER) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_PAST_RECIPIENT) != 0);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_CIS_CENTRAL);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_POWER_CONTROL);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PERIODIC_ADV_PARAMS, periodic_params,
	    sizeof(periodic_params));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_PERIODIC_ADV_PARAMS),
	    OP_LE_SET_PERIODIC_ADV_PARAMS, ST_SUCCESS);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PERIODIC_ADV_RCV_ENABLE, past_recv,
	    sizeof(past_recv));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_PERIODIC_ADV_RCV_ENABLE),
	    OP_LE_SET_PERIODIC_ADV_RCV_ENABLE, ST_SUCCESS);

	cap_reset(&c);
	feed_cmd(e, OP_LE_PERIODIC_ADV_SYNC_TRANSFER, past_xfer,
	    sizeof(past_xfer));
	check_cc_status(cap_find_cc(&c, OP_LE_PERIODIC_ADV_SYNC_TRANSFER),
	    OP_LE_PERIODIC_ADV_SYNC_TRANSFER, ST_SUCCESS);

	hci_emu_free(e);
}

ATF_TC_WITHOUT_HEAD(deep_profile_iso_and_power_report_capabilities);
ATF_TC_BODY(deep_profile_iso_and_power_report_capabilities, tc)
{
	struct hci_emu *e;
	struct cap c;
	uint8_t cig[24];
	uint8_t tx_power[3] = { 0x40, 0x00, 0x01 };
	uint8_t path_loss[8] = { 0x40, 0x00, 0x20, 0x02, 0x08, 0x02, 0x01, 0x00 };
	const uint8_t *ev;
	uint64_t features;

	memset(&c, 0, sizeof(c));
	memset(cig, 0, sizeof(cig));
	cig[14] = 1;		/* CIS_Count */
	cig[15] = 1;		/* CIS_ID */

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &c);
	ATF_REQUIRE_EQ(0, hci_emu_apply_profile(e, HCI_EMU_PROFILE_ISO));

	features = read_le_features(e, &c);
	ATF_CHECK((features & TEST_LE_FEAT_CIS_CENTRAL) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_CIS_PERIPH) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_ISO_BROADCASTER) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_SYNC_RECEIVER) != 0);

	cap_reset(&c);
	feed_cmd(e, OP_LE_READ_BUFFER_SIZE_V2, NULL, 0);
	ev = cap_find_cc(&c, OP_LE_READ_BUFFER_SIZE_V2);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(ST_SUCCESS, ev[6]);
	ATF_CHECK_EQ(512, le16dec(&ev[10]));
	ATF_CHECK_EQ(8, ev[12]);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_CIG_PARAMS, cig, sizeof(cig));
	ev = cap_find_cc(&c, OP_LE_SET_CIG_PARAMS);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(ST_SUCCESS, ev[6]);
	ATF_CHECK_EQ(1, ev[8]);		/* CIS_Count */
	ATF_CHECK(hci_emu_get_iso_count(e) >= 1);

	ATF_REQUIRE_EQ(0, hci_emu_apply_profile(e,
	    HCI_EMU_PROFILE_POWER_CONTROL));
	features = read_le_features(e, &c);
	ATF_CHECK((features & TEST_LE_FEAT_POWER_CONTROL) != 0);
	ATF_CHECK((features & TEST_LE_FEAT_PATH_LOSS_MONITORING) != 0);
	ATF_CHECK_EQ(0, features & TEST_LE_FEAT_CIS_CENTRAL);

	cap_reset(&c);
	feed_cmd(e, OP_LE_READ_REMOTE_TX_POWER, tx_power, sizeof(tx_power));
	check_cs(cap_find_cs(&c, OP_LE_READ_REMOTE_TX_POWER),
	    OP_LE_READ_REMOTE_TX_POWER, ST_UNKNOWN_CONN);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_PATH_LOSS_PARAMS, path_loss, sizeof(path_loss));
	ev = cap_find_cc(&c, OP_LE_SET_PATH_LOSS_PARAMS);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(ST_UNKNOWN_CONN, ev[6]);

	cap_reset(&c);
	feed_cmd(e, OP_LE_SET_CIG_PARAMS, cig, sizeof(cig));
	check_cc_status(cap_find_cc(&c, OP_LE_SET_CIG_PARAMS),
	    OP_LE_SET_CIG_PARAMS, ST_UNKNOWN_CMD);

	hci_emu_free(e);
}

/* ================================================================
 * SECTION 14: generic event injection surface.
 * ================================================================ */

/* hci_emu_inject_event builds 0x04 | code | plen | params verbatim. */
ATF_TC_WITHOUT_HEAD(deep_inject_event_generic);
ATF_TC_BODY(deep_inject_event_generic, tc)
{
	struct hci_emu *e;
	struct cap cp;
	const uint8_t params[] = { 0xaa, 0xbb, 0xcc };

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	hci_emu_inject_event(e, HCI_DEEP_SPEC_EVENT_HARDWARE_ERROR, params,
	    sizeof(params));
	ATF_CHECK_EQ(1, cp.n);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_PKT, cp.pkt[0][0]);
	ATF_CHECK_EQ(HCI_DEEP_SPEC_EVENT_HARDWARE_ERROR, cp.pkt[0][1]);
	ATF_CHECK_EQ(3, cp.pkt[0][2]);
	ATF_CHECK_EQ(0, memcmp(&cp.pkt[0][3], params, 3));
	ATF_CHECK_EQ((size_t)6, cp.len[0]);

	/* Zero-length params: header only. */
	cap_reset(&cp);
	hci_emu_inject_event(e, HCI_DEEP_SPEC_EVENT_HARDWARE_ERROR, NULL, 0);
	ATF_CHECK_EQ((size_t)3, cp.len[0]);
	ATF_CHECK_EQ(0, cp.pkt[0][2]);

	hci_emu_free(e);
}

/*
 * LE Advertising Report with over-long data is clamped to 31 bytes
 * (§7.7.65.2 Data_Length is a single byte and the AD field is capped).
 */
ATF_TC_WITHOUT_HEAD(deep_inject_adv_report_clamp);
ATF_TC_BODY(deep_inject_adv_report_clamp, tc)
{
	struct hci_emu *e;
	struct cap cp;
	uint8_t big[64];
	const uint8_t addr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	int i;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	for (i = 0; i < (int)sizeof(big); i++)
		big[i] = (uint8_t)i;

	cap_reset(&cp);
	hci_emu_inject_le_adv_report(e, 0x00, 0x00, addr, big, 60,
	    (int8_t)-55);
	ATF_REQUIRE_EQ(1, cp.n);
	/* Subevent 0x02, then num(1) etype(1) atype(1) addr(6) dlen(1). */
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP, cp.pkt[0][3]);
	ATF_CHECK_EQ(31, cp.pkt[0][13]);		/* data length clamped */
	/* First 31 data bytes preserved; RSSI trails them. */
	ATF_CHECK_EQ(0, memcmp(&cp.pkt[0][14], big, 31));
	ATF_CHECK_EQ((uint8_t)-55, cp.pkt[0][14 + 31]);

	hci_emu_free(e);
}

/* ================================================================
 * Section 14: defensive / boundary arms.
 * ================================================================ */

/*
 * inject_le_adv_report with adlen == 0: the "copy AD" arm is skipped and
 * the emitted report carries an empty AD section (length byte 0, no data,
 * RSSI immediately after).  Vol 4 Part E §7.7.65.2.
 */
ATF_TC_WITHOUT_HEAD(deep_adv_report_empty_ad);
ATF_TC_BODY(deep_adv_report_empty_ad, tc)
{
	struct hci_emu *e;
	struct cap cp;
	const uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, &cp);

	cap_reset(&cp);
	hci_emu_inject_le_adv_report(e, 0x00, 0x00, addr, NULL, 0, (int8_t)-40);
	ATF_REQUIRE_EQ(1, cp.n);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP, cp.pkt[0][3]);
	ATF_CHECK_EQ(0, cp.pkt[0][13]);			/* AD length = 0 */
	ATF_CHECK_EQ((uint8_t)-40, cp.pkt[0][14]);	/* RSSI right after */

	/*
	 * Caller-misuse guard: a non-zero adlen with a NULL ad pointer.  The
	 * "&& ad != NULL" short-circuit skips the copy, so no NULL deref and
	 * still exactly one report emitted.
	 */
	cap_reset(&cp);
	hci_emu_inject_le_adv_report(e, 0x00, 0x00, addr, NULL, 5, (int8_t)-40);
	ATF_CHECK_EQ(1, cp.n);

	hci_emu_free(e);
}

/*
 * The tx-power / path-loss setters must silently ignore an unknown
 * connection handle (emu_conn_by_handle() miss -> the c != NULL arm is not
 * taken).  With no connection at all, both setters are safe no-ops.
 */
ATF_TC_WITHOUT_HEAD(deep_conn_setters_unknown_handle);
ATF_TC_BODY(deep_conn_setters_unknown_handle, tc)
{
	struct hci_emu *e;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);

	/* No connections exist: both setters must be no-ops, not crash. */
	hci_emu_set_conn_tx_power(e, 0x0fff, (int8_t)-20);
	hci_emu_set_conn_path_loss(e, 0x0fff, 30);

	/* Contract cross-check: the unknown handle is still "not encrypted". */
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(e, 0x0fff));

	hci_emu_free(e);
}

/*
 * emu_emit() must tolerate an emulator with no output callback installed:
 * a command that would normally produce a Command Complete is processed
 * without delivering anything (the e->out != NULL guard skips the sink).
 */
ATF_TC_WITHOUT_HEAD(deep_emit_without_output);
ATF_TC_BODY(deep_emit_without_output, tc)
{
	struct hci_emu *e;
	uint8_t buf[4];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	/* Deliberately no hci_emu_set_output(). */

	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	le16enc(&buf[1], OP_RESET);
	buf[3] = 0x00;
	hci_emu_input(e, buf, 4);	/* would emit Command Complete: dropped */

	/* Reset still took effect despite the dropped event. */
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(e));

	hci_emu_free(e);
}

/*
 * hci_emu_get_conn_encrypted() with a live connection present but a
 * non-matching handle: the (active && handle == q) test fails on the
 * handle comparison, so the scan falls through to the not-found return 0.
 */
ATF_TC_WITHOUT_HEAD(deep_get_conn_encrypted_wrong_handle);
ATF_TC_BODY(deep_get_conn_encrypted_wrong_handle, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	uint16_t bh;

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* A conn is active, but this handle does not match it -> 0. */
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(b, (uint16_t)(bh ^ 0x0800)));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Section 1: malformed / short command packets (one per handler). */
	ATF_TP_ADD_TC(tp, deep_short_set_event_mask);
	ATF_TP_ADD_TC(tp, deep_short_le_set_event_mask);
	ATF_TP_ADD_TC(tp, deep_short_write_le_host_supported);
	ATF_TP_ADD_TC(tp, deep_short_le_set_random_address);
	ATF_TP_ADD_TC(tp, deep_short_le_set_adv_params);
	ATF_TP_ADD_TC(tp, deep_short_le_set_scan_params);
	ATF_TP_ADD_TC(tp, deep_short_le_set_scan_enable);
	ATF_TP_ADD_TC(tp, deep_short_le_set_adv_enable);
	ATF_TP_ADD_TC(tp, deep_short_le_set_addr_resolution_enable);
	ATF_TP_ADD_TC(tp, deep_short_le_add_resolv);
	ATF_TP_ADD_TC(tp, deep_short_le_remove_resolv);
	ATF_TP_ADD_TC(tp, deep_short_le_ltk_reply);
	ATF_TP_ADD_TC(tp, deep_short_le_ltk_neg_reply);
	ATF_TP_ADD_TC(tp, deep_short_le_set_path_loss_params);
	ATF_TP_ADD_TC(tp, deep_short_le_set_path_loss_enable);
	ATF_TP_ADD_TC(tp, deep_short_le_set_tx_power_reporting_enable);
	ATF_TP_ADD_TC(tp, deep_short_disconnect);
	ATF_TP_ADD_TC(tp, deep_short_le_create_connection);
	ATF_TP_ADD_TC(tp, deep_short_le_enable_encryption);
	ATF_TP_ADD_TC(tp, deep_short_le_read_remote_tx_power);
	ATF_TP_ADD_TC(tp, deep_adv_data_length_edges);
	ATF_TP_ADD_TC(tp, deep_scanrsp_data_length_edges);
	/* Section 2: unknown opcode + framing. */
	ATF_TP_ADD_TC(tp, deep_unknown_opcode);
	ATF_TP_ADD_TC(tp, deep_input_framing_edges);
	/* Section 3: resolving list. */
	ATF_TP_ADD_TC(tp, deep_resolving_list_lifecycle);
	ATF_TP_ADD_TC(tp, deep_resolving_list_capacity);
	/* Section 4: reset + back-to-back. */
	ATF_TP_ADD_TC(tp, deep_reset_clears_state);
	ATF_TP_ADD_TC(tp, deep_back_to_back_commands);
	/* Section 5: fault injection. */
	ATF_TP_ADD_TC(tp, deep_fault_injection_classes);
	ATF_TP_ADD_TC(tp, deep_fault_blocks_disconnect);
	/* Section 6: disconnect edges. */
	ATF_TP_ADD_TC(tp, deep_disconnect_unknown_handle);
	ATF_TP_ADD_TC(tp, deep_disconnect_reason_propagation);
	/* Section 7: adv/scan gating. */
	ATF_TP_ADD_TC(tp, deep_adv_after_scan_and_gating);
	ATF_TP_ADD_TC(tp, deep_random_own_address_report);
	/* Section 8: create-connection edges. */
	ATF_TP_ADD_TC(tp, deep_create_connection_cancel_disallowed);
	ATF_TP_ADD_TC(tp, deep_create_connection_nonconnectable);
	ATF_TP_ADD_TC(tp, deep_create_connection_no_link);
	ATF_TP_ADD_TC(tp, deep_create_connection_peer_silent);
	ATF_TP_ADD_TC(tp, deep_zero_supervision_timeout);
	ATF_TP_ADD_TC(tp, deep_connection_table_exhaustion);
	/* Section 9: ACL edges. */
	ATF_TP_ADD_TC(tp, deep_acl_edges);
	/* Section 10: clock / timers. */
	ATF_TP_ADD_TC(tp, deep_clock_get_set_advance);
	ATF_TP_ADD_TC(tp, deep_timer_ordering_multi);
	ATF_TP_ADD_TC(tp, deep_supervision_rearm_on_acl);
	/* Section 11: encryption edges. */
	ATF_TP_ADD_TC(tp, deep_encryption_unknown_handle);
	ATF_TP_ADD_TC(tp, deep_encryption_forced_fail_outcome);
	ATF_TP_ADD_TC(tp, deep_encryption_peer_gone);
	ATF_TP_ADD_TC(tp, deep_get_conn_encrypted_nonexistent);
	/* Section 12: power control edges. */
	ATF_TP_ADD_TC(tp, deep_read_remote_tx_power_unknown);
	ATF_TP_ADD_TC(tp, deep_path_loss_unknown_and_disable);
	ATF_TP_ADD_TC(tp, deep_path_loss_zone_boundaries);
	ATF_TP_ADD_TC(tp, deep_tx_power_reporting_enable);
	ATF_TP_ADD_TC(tp, deep_read_remote_tx_power_local_fallback);
	/* Section 13: reusable controller profiles. */
	ATF_TP_ADD_TC(tp, deep_profile_legacy_rejects_advanced_le_commands);
	ATF_TP_ADD_TC(tp, deep_profile_periodic_and_past_are_feature_gated);
	ATF_TP_ADD_TC(tp, deep_profile_iso_and_power_report_capabilities);
	/* Section 14: event injection. */
	ATF_TP_ADD_TC(tp, deep_inject_event_generic);
	ATF_TP_ADD_TC(tp, deep_inject_adv_report_clamp);
	/* Section 15: defensive / boundary arms. */
	ATF_TP_ADD_TC(tp, deep_adv_report_empty_ad);
	ATF_TP_ADD_TC(tp, deep_conn_setters_unknown_handle);
	ATF_TP_ADD_TC(tp, deep_emit_without_output);
	ATF_TP_ADD_TC(tp, deep_get_conn_encrypted_wrong_handle);

	return (atf_no_error());
}
