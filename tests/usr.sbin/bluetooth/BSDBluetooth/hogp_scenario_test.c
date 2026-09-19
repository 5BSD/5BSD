/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hogp_scenario_test.c - profile / HOGP end-to-end sessions driving the REAL
 * blued protocol code (att.c client, gatt.c) against hardware-free virtual
 * remote HID / sensor peers (btpeer.c) over an hci_emulator link.
 *
 * This is the "pair my keyboard and type" story at depth: for each accessory
 * type a full device SESSION runs -- connect (done in cli_setup) -> discover
 * the service topology -> read the profile's static characteristics ->
 * subscribe to the input / measurement CCCD -> drive the input stream and
 * assert every report surfaces byte for byte.
 *
 * Only the CLIENT direction is exercised: OUR att.c / gatt.c code is central
 * on emu A and blocks on its L2CAP socket; a pump thread owns the emu link and
 * the btpeer server on emu B and bridges the socket to the ACL path.  The
 * scaffolding (harness, pump thread, HCI mock trio, establish_conn) mirrors
 * btpeer_test.c; the fixtures and scenarios here are HOGP / sensor specific.
 *
 * ORACLE: every asserted byte is hand-derived from spec and cited inline:
 *   - HID report layout / report descriptors:	USB HID 1.11 (Section 6.2.2)
 *   - HID Usage IDs:				HID Usage Tables, Keyboard page 0x07
 *   - HID-over-GATT service / characteristics:	HOGP 1.1 + assigned UUIDs
 *   - ATT / GATT PDUs:				Core Spec Vol 3 Part F / Part G
 * A code-vs-spec disagreement is a FINDING: the spec value is kept (the test
 * fails) and reported.  Expected values are NEVER captured from the stack.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <atf-c.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "gatt.h"
#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "hci_emulator.h"
#include "btpeer.h"
#include "spec_oracles.h"
#include "spec_hogp_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

/*
 * Test-only Core wire namespace generated from Core 6.3 Vol 3 Part F
 * Tables 3.4 and 3.42, and Vol 3 Part G Table 3.5.  Scenario assertions and
 * fixture declarations therefore do not obtain their expected values from
 * att.h or gatt.h.
 */
#define HOGSCN_ORACLE(name, value) HOGSCN_##name = (value),
enum {
	BT_CORE63_ATT_ORACLES(HOGSCN_ORACLE)
	BT_CORE63_ATT_ERROR_ORACLES(HOGSCN_ORACLE)
	BT_CORE63_GATT_PROPERTY_ORACLES(HOGSCN_ORACLE)
};
#undef HOGSCN_ORACLE

/* Core 6.3 Vol 4 Part E §5.4.1: HCI Command packet indicator/header. */
enum {
	HOGSCN_HCI_COMMAND_PACKET = 0x01,
	HOGSCN_HCI_COMMAND_HEADER_LEN = 4
};

/*
 * Core 6.3 Vol 3 Part C §11.1.3 and CSS v12 Part A §1.3: Flags AD type,
 * General Discoverable Mode, and BR/EDR Not Supported.  Vol 4 Part E
 * §§7.8.10 and 7.8.12 define enable booleans and the public address type.
 */
enum {
	HOGSCN_AD_FLAGS_LENGTH = 2,
	HOGSCN_AD_TYPE_FLAGS = 0x01,
	HOGSCN_AD_FLAG_GENERAL_DISCOVERABLE = 0x02,
	HOGSCN_AD_FLAG_BREDR_NOT_SUPPORTED = 0x04,
	HOGSCN_HCI_DISABLE = 0x00,
	HOGSCN_HCI_ENABLE = 0x01,
	HOGSCN_HCI_ADDR_PUBLIC = 0x00
};

/* Core 6.3 Vol 4 Part E §7.8.12: valid deterministic test parameters. */
enum {
	HOGSCN_SCAN_INTERVAL_FIXTURE = 0x0060,
	HOGSCN_SCAN_WINDOW_FIXTURE = 0x0030,
	HOGSCN_CONN_INTERVAL_FIXTURE = 0x0028,
	HOGSCN_SUPERVISION_TIMEOUT_FIXTURE = 0x00c8,
	HOGSCN_CREATE_CONNECTION_PARAMS_LEN = 25
};

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (smp.c is linked, so these
 * must resolve; the real ones use bt_devreq on a kernel HCI node).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = HOGSCN_HCI_COMMAND_PACKET;
	buf[1] = (uint8_t)(opcode & 0xFF);
	buf[2] = (uint8_t)(opcode >> 8);
	buf[3] = plen;
	if (plen > 0 && params != NULL)
		memcpy(buf + 4, params, plen);
	return ((int)send(hci_fd, buf,
	    (size_t)HOGSCN_HCI_COMMAND_HEADER_LEN + plen, MSG_NOSIGNAL));
}

int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{
	return (0);
}

int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{
	return (0);
}

int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{
	return (0);
}

/* ================================================================
 * HCI command opcode shorthands
 * ================================================================ */
#define OP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define OP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define OP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define OP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)

static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = NG_HCI_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/*
 * Establish an LE connection over the emu link: periph advertises
 * (connectable), central scans and issues LE_Create_Connection (Vol 4 Part E
 * Section 7.8.5 / 7.8.10 / 7.8.12).
 */
static void
establish_conn(struct hci_emu *central, struct hci_emu *periph,
    const uint8_t caddr[6], const uint8_t paddr[6])
{
	static const uint8_t ad[] = {
		HOGSCN_AD_FLAGS_LENGTH,
		HOGSCN_AD_TYPE_FLAGS,
		HOGSCN_AD_FLAG_GENERAL_DISCOVERABLE |
		    HOGSCN_AD_FLAG_BREDR_NOT_SUPPORTED
	};
	uint8_t p[64];

	hci_emu_set_bd_addr(central, caddr);
	hci_emu_set_bd_addr(periph, paddr);

	/* Peripheral: set advertising data + enable (ADV_IND). */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(periph, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = HOGSCN_HCI_ENABLE;
	feed_cmd(periph, OP_LE_SET_ADV_ENABLE, p, 1);

	/* Central: scan then create connection. */
	p[0] = HOGSCN_HCI_ENABLE; p[1] = HOGSCN_HCI_DISABLE;
	feed_cmd(central, OP_LE_SET_SCAN_ENABLE, p, 2);

	memset(p, 0, HOGSCN_CREATE_CONNECTION_PARAMS_LEN);
	le16enc(&p[0], HOGSCN_SCAN_INTERVAL_FIXTURE);
	le16enc(&p[2], HOGSCN_SCAN_WINDOW_FIXTURE);
	p[4] = HOGSCN_HCI_DISABLE;	/* initiator filter policy */
	p[5] = HOGSCN_HCI_ADDR_PUBLIC;
	memcpy(&p[6], paddr, 6);
	p[12] = HOGSCN_HCI_ADDR_PUBLIC;
	le16enc(&p[13], HOGSCN_CONN_INTERVAL_FIXTURE);
	le16enc(&p[15], HOGSCN_CONN_INTERVAL_FIXTURE);
	le16enc(&p[17], 0x0000);	/* latency */
	le16enc(&p[19], HOGSCN_SUPERVISION_TIMEOUT_FIXTURE);
	feed_cmd(central, OP_LE_CREATE_CONNECTION, p,
	    HOGSCN_CREATE_CONNECTION_PARAMS_LEN);
}

/* ================================================================
 * CLIENT direction: OUR att.c / gatt.c behind emu A; btpeer is the server.
 * A pump thread bridges OUR blocking socket to the emu link.
 * ================================================================ */
struct cli_harness {
	struct hci_emu	*emu;		/* our controller (emu A, central) */
	uint16_t	handle;
	struct btpeer	*bp;
	int		att_bridge;	/* peer end of OUR att socket */
	int		smp_bridge;	/* peer end of OUR smp socket, or -1 */
	int		ctrl_r, ctrl_w;	/* control pipe to the pump thread */
	pthread_t	thr;
	bool		running;
};

/* Control commands posted from the main thread to the pump thread. */
enum pump_cmd_type { PUMP_STOP, PUMP_NOTIFY, PUMP_INDICATE };
struct pump_cmd {
	enum pump_cmd_type type;
	uint16_t	handle;
	uint8_t		val[64];
	uint16_t	len;
};

/* emu A output callback (pump thread): peer data -> OUR socket. */
static void
cli_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cli_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == NG_L2CAP_ATT_CID)
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
	else if (cid == NG_L2CAP_SMP_CID && h->smp_bridge >= 0)
		(void)send(h->smp_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
}

/* Frame a raw L2CAP payload from OUR socket and feed it to the emu. */
static void
cli_feed(struct cli_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(h->handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu, pkt, (size_t)9 + plen);
}

static void *
pump_thread(void *arg)
{
	struct cli_harness *h = arg;
	uint8_t buf[600];
	struct pollfd pfd[3];

	for (;;) {
		int nf = 0, i;

		pfd[nf].fd = h->att_bridge;
		pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->ctrl_r;
		pfd[nf].events = POLLIN; nf++;
		if (h->smp_bridge >= 0) {
			pfd[nf].fd = h->smp_bridge;
			pfd[nf].events = POLLIN; nf++;
		}
		if (poll(pfd, (nfds_t)nf, 2000) <= 0)
			continue;
		for (i = 0; i < nf; i++) {
			ssize_t n;

			if (!(pfd[i].revents & POLLIN))
				continue;
			if (pfd[i].fd == h->ctrl_r) {
				struct pump_cmd cmd;

				n = read(h->ctrl_r, &cmd, sizeof(cmd));
				if (n != (ssize_t)sizeof(cmd))
					continue;
				if (cmd.type == PUMP_STOP)
					return (NULL);
				if (cmd.type == PUMP_NOTIFY)
					btpeer_server_notify(h->bp, cmd.handle,
					    cmd.val, cmd.len);
				else if (cmd.type == PUMP_INDICATE)
					btpeer_server_indicate(h->bp,
					    cmd.handle, cmd.val, cmd.len);
			} else if (pfd[i].fd == h->att_bridge) {
				n = recv(h->att_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					cli_feed(h, NG_L2CAP_ATT_CID, buf,
					    (uint16_t)n);
			} else if (pfd[i].fd == h->smp_bridge) {
				n = recv(h->smp_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					cli_feed(h, NG_L2CAP_SMP_CID, buf,
					    (uint16_t)n);
			}
		}
	}
}

/*
 * Bring up the CLIENT-direction harness: OUR code is central on emu A,
 * btpeer is the peripheral server on emu B.  Returns OUR att socket fd in
 * *our_att_fd and (optionally) OUR smp socket fd in *our_smp_fd.
 */
static void
cli_setup(struct cli_harness *h, struct btpeer **bp_out, int *our_att_fd,
    int *our_smp_fd)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	struct hci_emu *emu_our, *emu_peer;
	struct btpeer *bp;
	int att_fds[2], smp_fds[2], ctrl[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));
	h->smp_bridge = -1;

	emu_our = hci_emu_new();
	emu_peer = hci_emu_new();
	ATF_REQUIRE(emu_our != NULL && emu_peer != NULL);
	hci_emu_link(emu_our, emu_peer);

	h->emu = emu_our;
	hci_emu_set_output(emu_our, cli_out, h);
	bp = btpeer_new(emu_peer);
	ATF_REQUIRE(bp != NULL);
	h->bp = bp;

	establish_conn(emu_our, emu_peer, caddr, paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(emu_our, 0, &h->handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(bp));

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) == 0);
	h->att_bridge = att_fds[1];
	*our_att_fd = att_fds[0];

	if (our_smp_fd != NULL) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0,
		    smp_fds) == 0);
		h->smp_bridge = smp_fds[1];
		*our_smp_fd = smp_fds[0];
	}

	ATF_REQUIRE(pipe(ctrl) == 0);
	h->ctrl_r = ctrl[0];
	h->ctrl_w = ctrl[1];

	*bp_out = bp;
}

static void
cli_start(struct cli_harness *h)
{

	ATF_REQUIRE_EQ(0, pthread_create(&h->thr, NULL, pump_thread, h));
	h->running = true;
}

static void
cli_post(struct cli_harness *h, const struct pump_cmd *cmd)
{

	ATF_REQUIRE_EQ((ssize_t)sizeof(*cmd),
	    write(h->ctrl_w, cmd, sizeof(*cmd)));
}

static void
cli_stop(struct cli_harness *h)
{
	struct pump_cmd cmd;

	if (h->running) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.type = PUMP_STOP;
		cli_post(h, &cmd);
		pthread_join(h->thr, NULL);
		h->running = false;
	}
}

/* Init OUR att_conn to use a preexisting connected socket (fd). */
static void
cli_att_conn(struct att_conn *ac, int fd)
{

	memset(ac, 0, sizeof(*ac));
	ac->fd = fd;
	ac->bearer_fd = -1;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
}

/* ================================================================
 * Shared scenario helpers.
 * ================================================================ */

/*
 * Subscribe: Write Request of a CCCD (0x2902) value (Vol 3 Part G 3.3.3.3):
 * bit 0 = Notification, bit 1 = Indication.  The value is written LE.
 */
static void
cli_subscribe(struct att_conn *ac, uint16_t cccd, uint16_t bits)
{
	uint8_t v[2];

	put_le16(v, bits);
	ATF_CHECK_EQ(0, att_write_req(ac, cccd, v, 2));
}

/* Post a Handle Value Notification (0x1B) from the peer server. */
static void
post_notify(struct cli_harness *h, uint16_t handle, const uint8_t *val,
    uint16_t len)
{
	struct pump_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = handle;
	cmd.len = len;
	memcpy(cmd.val, val, len);
	cli_post(h, &cmd);
}

/*
 * Receive exactly one Handle Value Notification (Vol 3 Part F 3.4.7.1) and
 * assert opcode 0x1B, the value handle, and the exact payload bytes.
 */
static void
expect_notify(struct att_conn *ac, uint16_t handle, const uint8_t *val,
    uint16_t len)
{
	uint8_t buf[80];
	size_t outlen = 0;

	ATF_REQUIRE_EQ(0, att_recv(ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ((size_t)(3 + len), outlen);
	ATF_CHECK_EQ(HOGSCN_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(handle, get_le16(buf + 1));
	ATF_CHECK_EQ(0, memcmp(buf + 3, val, len));
}

/* ================================================================
 * Device / profile fixtures.  Each maker builds a spec-shaped accessory
 * server on the peer and records the handles a scenario needs.  Handles are
 * allocated sequentially by btpeer from 0x0001: a service declaration takes
 * one handle, a characteristic takes two (declaration + value), a CCCD one.
 * ================================================================ */

/*
 * HID keyboard boot report descriptor (USB HID 1.11 Section 6.2.2 / HID Usage
 * Tables): 8-octet input report = modifier(1) | reserved(1) | keycode[6].
 */
static const uint8_t kbd_report_map[] = {
	0x05, 0x01,		/* Usage Page (Generic Desktop)		*/
	0x09, 0x06,		/* Usage (Keyboard)			*/
	0xA1, 0x01,		/* Collection (Application)		*/
	0x05, 0x07,		/*   Usage Page (Keyboard/Keypad)	*/
	0x19, 0xE0,		/*   Usage Minimum (LeftControl)	*/
	0x29, 0xE7,		/*   Usage Maximum (Right GUI)		*/
	0x15, 0x00,		/*   Logical Minimum (0)		*/
	0x25, 0x01,		/*   Logical Maximum (1)		*/
	0x75, 0x01,		/*   Report Size (1)			*/
	0x95, 0x08,		/*   Report Count (8)			*/
	0x81, 0x02,		/*   Input (Data,Var,Abs) - modifiers	*/
	0x95, 0x01,		/*   Report Count (1)			*/
	0x75, 0x08,		/*   Report Size (8)			*/
	0x81, 0x01,		/*   Input (Const) - reserved		*/
	0x95, 0x06,		/*   Report Count (6)			*/
	0x75, 0x08,		/*   Report Size (8)			*/
	0x15, 0x00,		/*   Logical Minimum (0)		*/
	0x25, 0x65,		/*   Logical Maximum (101)		*/
	0x05, 0x07,		/*   Usage Page (Keyboard/Keypad)	*/
	0x19, 0x00,		/*   Usage Minimum (0)			*/
	0x29, 0x65,		/*   Usage Maximum (101)		*/
	0x81, 0x00,		/*   Input (Data,Array) - keycodes	*/
	0xC0			/* End Collection			*/
};

/* HID mouse boot report descriptor: buttons(3 bits)+pad(5) | X(8) | Y(8). */
static const uint8_t mouse_report_map[] = {
	0x05, 0x01,		/* Usage Page (Generic Desktop)		*/
	0x09, 0x02,		/* Usage (Mouse)			*/
	0xA1, 0x01,		/* Collection (Application)		*/
	0x09, 0x01,		/*   Usage (Pointer)			*/
	0xA1, 0x00,		/*   Collection (Physical)		*/
	0x05, 0x09,		/*     Usage Page (Button)		*/
	0x19, 0x01,		/*     Usage Minimum (1)		*/
	0x29, 0x03,		/*     Usage Maximum (3)		*/
	0x15, 0x00,		/*     Logical Minimum (0)		*/
	0x25, 0x01,		/*     Logical Maximum (1)		*/
	0x95, 0x03,		/*     Report Count (3)			*/
	0x75, 0x01,		/*     Report Size (1)			*/
	0x81, 0x02,		/*     Input (Data,Var,Abs) - buttons	*/
	0x95, 0x01,		/*     Report Count (1)			*/
	0x75, 0x05,		/*     Report Size (5)			*/
	0x81, 0x01,		/*     Input (Const) - padding		*/
	0x05, 0x01,		/*     Usage Page (Generic Desktop)	*/
	0x09, 0x30,		/*     Usage (X)			*/
	0x09, 0x31,		/*     Usage (Y)			*/
	0x15, 0x81,		/*     Logical Minimum (-127)		*/
	0x25, 0x7F,		/*     Logical Maximum (127)		*/
	0x75, 0x08,		/*     Report Size (8)			*/
	0x95, 0x02,		/*     Report Count (2)			*/
	0x81, 0x06,		/*     Input (Data,Var,Rel) - X,Y	*/
	0xC0,			/*   End Collection			*/
	0xC0			/* End Collection			*/
};

/*
 * HID Information, HIDS 1.1 §2.10.2, Table 2.16:
 *   bcdHID = 0x0111 (v1.11, LE) | bCountryCode = 0x00 | Flags = 0x02
 * Flags bit1 = NormallyConnectable.
 */
static const uint8_t hid_info[4] = {
	(uint8_t)(BT_HIDS11_BCD_HID_1_11 & 0xff),
	(uint8_t)(BT_HIDS11_BCD_HID_1_11 >> 8),
	BT_HIDS11_COUNTRY_NOT_LOCALIZED,
	BT_HIDS11_FLAG_NORMALLY_CONNECTABLE
};

/*
 * HID keyboard fixture (HIDS 1.1 §2): HID Service carrying Protocol Mode
 * (0x2A4E), Report Map (0x2A4B), HID Information (0x2A4A), HID Control Point
 * (0x2A4C), a Report (0x2A4D) input report and its CCCD (0x2902).
 */
struct hid_keyboard {
	uint16_t	svc_start, svc_end;
	uint16_t	protocol_mode;		/* 0x2A4E value */
	uint16_t	report_map;		/* 0x2A4B value */
	uint16_t	hid_information;	/* 0x2A4A value */
	uint16_t	control_point;		/* 0x2A4C value */
	uint16_t	input_report;		/* 0x2A4D value */
	uint16_t	input_cccd;		/* 0x2902 */
	uint16_t	input_reference;	/* 0x2908 */
};

/*
 * Protocol Mode, HIDS 1.1 §2.4.1.1, Table 2.2:
 *   0x00 = Boot Protocol Mode, 0x01 = Report Protocol Mode.
 */
#define HID_PROTO_BOOT		BT_HIDS11_PROTOCOL_MODE_BOOT
#define HID_PROTO_REPORT	BT_HIDS11_PROTOCOL_MODE_REPORT

static void
make_keyboard(struct btpeer *bp, struct hid_keyboard *k)
{
	static const uint8_t pmode = HID_PROTO_REPORT;
	static const uint8_t cpoint = BT_HIDS11_CONTROL_POINT_SUSPEND;
	static const uint8_t rpt0[8] = { 0 };
	/* HOGP 1.1 §4.6.1.2: Report ID 1, Report Type Input. */
	static const uint8_t report_reference[2] = {
		1, BT_HOGP111_REPORT_TYPE_INPUT
	};

	memset(k, 0, sizeof(*k));
	k->svc_start = btpeer_add_service(bp, BT_ASSIGNED_UUID_HID_SERVICE);
	/* Protocol Mode: Read + Write Without Response (HOGP 4.11). */
	k->protocol_mode = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_PROTOCOL_MODE,
	    HOGSCN_GATT_PROP_READ | HOGSCN_GATT_PROP_WRITE_NO_RSP,
	    BTPEER_PERM_READ | BTPEER_PERM_WRITE, &pmode, 1);
	k->report_map = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_REPORT_MAP,
	    HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, kbd_report_map, (uint16_t)sizeof(kbd_report_map));
	k->hid_information = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_HID_INFORMATION,
	    HOGSCN_GATT_PROP_READ, BTPEER_PERM_READ, hid_info,
	    (uint16_t)sizeof(hid_info));
	/* HID Control Point: Write Without Response only (HOGP 4.9). */
	k->control_point = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_HID_CONTROL_POINT,
	    HOGSCN_GATT_PROP_WRITE_NO_RSP, BTPEER_PERM_WRITE, &cpoint, 1);
	k->input_report = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_REPORT,
	    HOGSCN_GATT_PROP_READ | HOGSCN_GATT_PROP_NOTIFY,
	    BTPEER_PERM_READ, rpt0,
	    (uint16_t)sizeof(rpt0));
	k->input_cccd = btpeer_add_cccd(bp);
	k->input_reference = btpeer_add_attr(bp,
	    BT_ASSIGNED_UUID_REPORT_REFERENCE, BTPEER_PERM_READ,
	    report_reference, sizeof(report_reference));
	k->svc_end = k->input_reference;
}

/* HID mouse fixture (HIDS 1.1 §§2.5-2.6). */
struct hid_mouse {
	uint16_t	svc_start, svc_end;
	uint16_t	report_map;
	uint16_t	input_report;
	uint16_t	input_cccd;
	uint16_t	input_reference;
};

static void
make_mouse(struct btpeer *bp, struct hid_mouse *m)
{
	static const uint8_t rpt0[3] = { 0 };
	/* HOGP 1.1 §4.6.1.2: Report ID 1, Report Type Input. */
	static const uint8_t report_reference[2] = {
		1, BT_HOGP111_REPORT_TYPE_INPUT
	};

	memset(m, 0, sizeof(*m));
	m->svc_start = btpeer_add_service(bp, BT_ASSIGNED_UUID_HID_SERVICE);
	m->report_map = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_REPORT_MAP,
	    HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, mouse_report_map,
	    (uint16_t)sizeof(mouse_report_map));
	m->input_report = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_REPORT,
	    HOGSCN_GATT_PROP_READ | HOGSCN_GATT_PROP_NOTIFY,
	    BTPEER_PERM_READ, rpt0,
	    (uint16_t)sizeof(rpt0));
	m->input_cccd = btpeer_add_cccd(bp);
	m->input_reference = btpeer_add_attr(bp,
	    BT_ASSIGNED_UUID_REPORT_REFERENCE, BTPEER_PERM_READ,
	    report_reference, sizeof(report_reference));
	m->svc_end = m->input_reference;
}

/* Battery Service (0x180F) fixture: Battery Level (0x2A19) + CCCD. */
struct battery_dev {
	uint16_t	svc_start, svc_end;
	uint16_t	level;
	uint16_t	cccd;
};

#define BATT_FULL	BT_GSS_BATTERY_LEVEL_FULL /* BAS 1.1 §3.1.1 */

static void
make_battery(struct btpeer *bp, struct battery_dev *b)
{
	static const uint8_t lvl = BATT_FULL;

	memset(b, 0, sizeof(*b));
	b->svc_start = btpeer_add_service(bp, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	b->level = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    HOGSCN_GATT_PROP_READ | HOGSCN_GATT_PROP_NOTIFY,
	    BTPEER_PERM_READ, &lvl, 1);
	b->cccd = btpeer_add_cccd(bp);
	b->svc_end = b->cccd;
}

/*
 * Device Information Service fixture with the eight pre-UDI characteristics
 * from DIS 1.2 Table 3.1.  Each is a Read-only value.
 */
struct dis_dev {
	uint16_t	svc_start, svc_end;
	uint16_t	manufacturer;	/* 0x2A29 */
	uint16_t	model_number;	/* 0x2A24 */
	uint16_t	serial_number;	/* 0x2A25 */
	uint16_t	firmware_rev;	/* 0x2A26 */
	uint16_t	hardware_rev;	/* 0x2A27 */
	uint16_t	software_rev;	/* 0x2A28 */
	uint16_t	system_id;	/* 0x2A23 */
	uint16_t	pnp_id;		/* 0x2A50 */
};

static const char	dis_manufacturer[] = "ACME Corp";
static const char	dis_model[] = "KB-101";
static const char	dis_serial[] = "SN-0001";
static const char	dis_firmware[] = "1.0.0";
static const char	dis_hardware[] = "rev-A";
static const char	dis_software[] = "2.0.0";
/* System ID: an 8-octet EUI-64 fixture, DIS 1.2 §3.7 and GSS §3.233. */
static const uint8_t	dis_system_id[8] = {
	0x01, 0x23, 0x45, 0x00, 0x00, 0xAB, 0xCD, 0xEF
};
/*
 * PnP ID, DIS 1.2 §3.9 and GSS §3.187: 7 octets =
 *   Vendor ID Source(1) | Vendor ID(2 LE) | Product ID(2 LE) |
 *   Product Version(2 LE).
 * Source 0x02 = USB Implementer's Forum; vendor 0x1234; product 0x5678;
 * version 0x0100.
 */
static const uint8_t	dis_pnp_id[7] = {
	BT_GSS_PNP_VENDOR_SOURCE_USB_IF,
	0x34, 0x12, 0x78, 0x56, 0x00, 0x01
};

static void
make_dis(struct btpeer *bp, struct dis_dev *d)
{

	memset(d, 0, sizeof(*d));
	d->svc_start = btpeer_add_service(bp,
	    BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	d->manufacturer = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_MANUFACTURER_NAME_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_manufacturer,
	    (uint16_t)strlen(dis_manufacturer));
	d->model_number = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_MODEL_NUMBER_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_model, (uint16_t)strlen(dis_model));
	d->serial_number = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_SERIAL_NUMBER_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_serial, (uint16_t)strlen(dis_serial));
	d->firmware_rev = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_FIRMWARE_REVISION_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_firmware, (uint16_t)strlen(dis_firmware));
	d->hardware_rev = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_HARDWARE_REVISION_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_hardware, (uint16_t)strlen(dis_hardware));
	d->software_rev = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_SOFTWARE_REVISION_STRING, HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_software, (uint16_t)strlen(dis_software));
	d->system_id = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_SYSTEM_ID,
	    HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_system_id, (uint16_t)sizeof(dis_system_id));
	d->pnp_id = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_PNP_ID,
	    HOGSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_pnp_id, (uint16_t)sizeof(dis_pnp_id));
	d->svc_end = d->pnp_id;
}

/*
 * Heart Rate Service (0x180D) fixture: Heart Rate Measurement (0x2A37, Notify)
 * + CCCD, and Body Sensor Location (0x2A38, Read).
 */
struct heartrate_dev {
	uint16_t	svc_start, svc_end;
	uint16_t	measurement;	/* 0x2A37 */
	uint16_t	cccd;
	uint16_t	body_location;	/* 0x2A38 */
};

/* Body Sensor Location: Chest, GSS §3.38.1 Table 3.63. */
#define HR_LOCATION_CHEST	BT_GSS_BODY_SENSOR_LOCATION_CHEST

static void
make_heartrate(struct btpeer *bp, struct heartrate_dev *hr)
{
	static const uint8_t loc = HR_LOCATION_CHEST;
	static const uint8_t m0[2] = { 0x00, 0x00 };

	memset(hr, 0, sizeof(*hr));
	hr->svc_start = btpeer_add_service(bp, BT_ASSIGNED_UUID_HEART_RATE_SERVICE);
	hr->measurement = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_HEART_RATE_MEASUREMENT,
	    HOGSCN_GATT_PROP_NOTIFY, BTPEER_PERM_READ, m0,
	    (uint16_t)sizeof(m0));
	hr->cccd = btpeer_add_cccd(bp);
	hr->body_location = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_BODY_SENSOR_LOCATION,
	    HOGSCN_GATT_PROP_READ, BTPEER_PERM_READ, &loc, 1);
	hr->svc_end = hr->body_location;
}

/*
 * Health Thermometer Service (0x1809) fixture: Temperature Measurement
 * (0x2A1C) is an INDICATE characteristic (HTS 1.0), used to exercise the
 * indication + Confirmation path.
 */
struct thermometer_dev {
	uint16_t	svc_start, svc_end;
	uint16_t	measurement;	/* 0x2A1C */
	uint16_t	cccd;
};

static void
make_thermometer(struct btpeer *bp, struct thermometer_dev *t)
{
	static const uint8_t m0[5] = { 0 };

	memset(t, 0, sizeof(*t));
	t->svc_start = btpeer_add_service(bp,
	    BT_ASSIGNED_UUID_HEALTH_THERMOMETER_SERVICE);
	t->measurement = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_TEMPERATURE_MEASUREMENT,
	    HOGSCN_GATT_PROP_INDICATE, BTPEER_PERM_READ, m0,
	    (uint16_t)sizeof(m0));
	t->cccd = btpeer_add_cccd(bp);
	t->svc_end = t->cccd;
}

/* ================================================================
 * HID input report vectors.
 *
 * Boot keyboard input report (USB HID 1.11 Section B.1):
 *   modifier(1) | reserved(1) | keycode[6].
 * HID Usage IDs (HID Usage Tables, Keyboard/Keypad page 0x07):
 *   h=0x0B, e=0x08, l=0x0F, o=0x12; the all-zero report is a key-up.
 * ================================================================ */
#define KEY_H	0x0B
#define KEY_E	0x08
#define KEY_L	0x0F
#define KEY_O	0x12

static void
kbd_report(uint8_t out[8], uint8_t keycode)
{

	memset(out, 0, 8);
	out[2] = keycode;	/* first keycode slot */
}

/* ================================================================
 * KEYBOARD sessions
 * ================================================================ */

/* Discover the HID service topology of a keyboard peer. */
ATF_TC_WITHOUT_HEAD(kbd_discover_topology);
ATF_TC_BODY(kbd_discover_topology, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	struct gatt_service svcs[GATT_MAX_SERVICES];
	struct gatt_char chars[GATT_MAX_CHARS];
	struct gatt_desc descs[GATT_MAX_DESCS];
	uint8_t ref[2];
	size_t ref_len = 0;
	int fd, nsvc = -1, nch = -1, nd = -1, i;
	bool hid = false, pmode = false, rmap = false, hinfo = false;
	bool cpoint = false, report = false, cccd = false, report_ref = false;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Primary service discovery (Vol 3 Part G 4.4.1): HID Service 0x1812. */
	ATF_REQUIRE_EQ(0, gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvc));
	for (i = 0; i < nsvc; i++)
		if (svcs[i].uuid16 == BT_ASSIGNED_UUID_HID_SERVICE)
			hid = true;
	ATF_CHECK(hid);

	/* Characteristic discovery over the HID group (Vol 3 Part G 4.6.1). */
	ATF_REQUIRE_EQ(0, gatt_discover_characteristics(&ac, k.svc_start,
	    k.svc_end, chars, GATT_MAX_CHARS, &nch));
	for (i = 0; i < nch; i++) {
		switch (chars[i].uuid16) {
		case BT_ASSIGNED_UUID_PROTOCOL_MODE: pmode = true; break;
		case BT_ASSIGNED_UUID_REPORT_MAP: rmap = true; break;
		case BT_ASSIGNED_UUID_HID_INFORMATION: hinfo = true; break;
		case BT_ASSIGNED_UUID_HID_CONTROL_POINT: cpoint = true; break;
		case BT_ASSIGNED_UUID_REPORT: report = true; break;
		}
	}
	ATF_CHECK(pmode);
	ATF_CHECK(rmap);
	ATF_CHECK(hinfo);
	ATF_CHECK(cpoint);
	ATF_CHECK(report);

	/* Descriptor discovery (Vol 3 Part G 4.7.1): the Report CCCD 0x2902. */
	ATF_REQUIRE_EQ(0, gatt_discover_descriptors(&ac, k.svc_start,
	    k.svc_end, descs, GATT_MAX_DESCS, &nd));
	for (i = 0; i < nd; i++)
		if (descs[i].uuid16 == BT_ASSIGNED_UUID_CCCD &&
		    descs[i].handle == k.input_cccd)
			cccd = true;
		else if (descs[i].uuid16 == BT_ASSIGNED_UUID_REPORT_REFERENCE &&
		    descs[i].handle == k.input_reference)
			report_ref = true;
	ATF_CHECK(cccd);
	ATF_CHECK(report_ref);
	/* HIDS 1.1 §2.5.3.2: Report ID followed by Report Type. */
	ATF_CHECK_EQ(0, att_read(&ac, k.input_reference, ref, sizeof(ref),
	    &ref_len));
	ATF_REQUIRE_EQ(sizeof(ref), ref_len);
	ATF_CHECK_EQ(1, ref[0]);
	ATF_CHECK_EQ(BT_HOGP111_REPORT_TYPE_INPUT, ref[1]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Report Map read must equal the exact descriptor bytes (HOGP 4.7). */
ATF_TC_WITHOUT_HEAD(kbd_read_report_map);
ATF_TC_BODY(kbd_read_report_map, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[80];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, k.report_map, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(sizeof(kbd_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, kbd_report_map, sizeof(kbd_report_map)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* HID Information (0x2A4A): bcdHID 0x0111, country 0, flags 0x02. */
ATF_TC_WITHOUT_HEAD(kbd_read_hid_information);
ATF_TC_BODY(kbd_read_hid_information, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[16];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, k.hid_information, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(BT_HIDS11_BCD_HID_1_11, get_le16(buf));
	ATF_CHECK_EQ(BT_HIDS11_COUNTRY_NOT_LOCALIZED, buf[2]);
	ATF_CHECK_EQ(BT_HIDS11_FLAG_NORMALLY_CONNECTABLE, buf[3]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Protocol Mode read (Report), write Boot (Write Without Response), read back. */
ATF_TC_WITHOUT_HEAD(kbd_protocol_mode_read_write);
ATF_TC_BODY(kbd_protocol_mode_read_write, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[4], mode;
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Default is Report Protocol Mode (HOGP 4.11 => 0x01). */
	ATF_CHECK_EQ(0, att_read(&ac, k.protocol_mode, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(HID_PROTO_REPORT, buf[0]);

	/* Switch to Boot Protocol Mode via Write Without Response (HOGP 4.11). */
	mode = HID_PROTO_BOOT;
	ATF_CHECK_EQ(0, att_write_cmd(&ac, k.protocol_mode, &mode, 1));

	/* Read back: the peer stored Boot Protocol Mode. */
	ATF_CHECK_EQ(0, att_read(&ac, k.protocol_mode, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(HID_PROTO_BOOT, buf[0]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Subscribe to the input CCCD, then read it back = 0x0001 (Vol 3 Part G 3.3.3.3). */
ATF_TC_WITHOUT_HEAD(kbd_subscribe_cccd_readback);
ATF_TC_BODY(kbd_subscribe_cccd_readback, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[4];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	cli_subscribe(&ac, k.input_cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	ATF_CHECK_EQ(0, att_read(&ac, k.input_cccd, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(2, outlen);
	ATF_CHECK_EQ(BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED,
	    get_le16(buf));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * The money case: read Report Map, subscribe, then type "hello" as a stream of
 * boot keyboard input reports and assert each HID Usage ID surfaces in order,
 * including the key-up between the repeated 'l' so the double press is two
 * distinct events.
 */
ATF_TC_WITHOUT_HEAD(kbd_type_hello);
ATF_TC_BODY(kbd_type_hello, tc)
{
	static const uint8_t seq[6] = {
		KEY_H, KEY_E, KEY_L, 0x00 /* key-up */, KEY_L, KEY_O
	};
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t rmap[80], report[8];
	size_t outlen = 0;
	int fd;
	unsigned int i;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* HOGP requires reading the Report Map before consuming reports. */
	ATF_REQUIRE_EQ(0, att_read(&ac, k.report_map, rmap, sizeof(rmap),
	    &outlen));
	ATF_REQUIRE_EQ(sizeof(kbd_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(rmap, kbd_report_map, sizeof(kbd_report_map)));

	/* Subscribe to the Input Report CCCD. */
	cli_subscribe(&ac, k.input_cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	/*
	 * Drive the keystroke stream ONE report at a time: post, then read.
	 * (AF_UNIX SOCK_SEQPACKET would coalesce several queued PDUs.)
	 */
	for (i = 0; i < sizeof(seq); i++) {
		kbd_report(report, seq[i]);
		post_notify(&h, k.input_report, report, sizeof(report));
		expect_notify(&ac, k.input_report, report, sizeof(report));
		/* The keycode lands in the first keycode slot (octet 2). */
	}

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Edge: reading the Input Report before the Report Map is legal at the ATT
 * layer -- the report characteristic is Read-able and returns its current
 * (zeroed) 8-octet value.  HOGP's "read Report Map first" is a profile
 * ordering, not an ATT-enforced one.
 */
ATF_TC_WITHOUT_HEAD(kbd_read_report_before_map);
ATF_TC_BODY(kbd_read_report_before_map, tc)
{
	static const uint8_t zero[8] = { 0 };
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[16];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, k.input_report, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(8, outlen);
	ATF_CHECK_EQ(0, memcmp(buf, zero, sizeof(zero)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * The Report Map (0x2A4B) is Read-only (HOGP 4.7): a Write Request must draw
 * an Error Response Write Not Permitted (Vol 3 Part F 3.4.1.1 code 0x03).
 */
ATF_TC_WITHOUT_HEAD(kbd_write_report_map_rejected);
ATF_TC_BODY(kbd_write_report_map_rejected, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	const uint8_t junk[1] = { 0xFF };
	int fd, rc;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	rc = att_write_req(&ac, k.report_map, junk, sizeof(junk));
	ATF_CHECK_EQ(HOGSCN_ATT_ERR_WRITE_NOT_PERMITTED, rc);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * HID Control Point (0x2A4C) accepts Write Without Response (HOGP 4.9):
 * write Suspend (0x00) and confirm the peer stored it.
 */
ATF_TC_WITHOUT_HEAD(kbd_control_point_write);
ATF_TC_BODY(kbd_control_point_write, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t stored[4];
	size_t slen = 0;
	const uint8_t suspend = BT_HIDS11_CONTROL_POINT_SUSPEND;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_write_cmd(&ac, k.control_point, &suspend, 1));

	cli_stop(&h);	/* pump idle: safe to inspect the peer store */
	ATF_CHECK_EQ(0, btpeer_get_value(bp, k.control_point, stored,
	    sizeof(stored), &slen));
	ATF_REQUIRE_EQ(1, slen);
	ATF_CHECK_EQ(BT_HIDS11_CONTROL_POINT_SUSPEND, stored[0]);

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * MOUSE session
 * ================================================================ */

/* Mouse Report Map read must equal the exact descriptor bytes. */
ATF_TC_WITHOUT_HEAD(mouse_read_report_map);
ATF_TC_BODY(mouse_read_report_map, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_mouse m;
	struct att_conn ac;
	uint8_t buf[80];
	uint8_t ref[2];
	size_t outlen = 0;
	size_t ref_len = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_mouse(bp, &m);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, m.report_map, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(sizeof(mouse_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, mouse_report_map, sizeof(mouse_report_map)));
	ATF_CHECK_EQ(0, att_read(&ac, m.input_reference, ref, sizeof(ref),
	    &ref_len));
	ATF_REQUIRE_EQ(sizeof(ref), ref_len);
	ATF_CHECK_EQ(1, ref[0]);
	ATF_CHECK_EQ(BT_HOGP111_REPORT_TYPE_INPUT, ref[1]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Mouse movement + click stream.  Boot mouse report (USB HID 1.11 App B.2):
 * buttons(1) | dx(1, signed) | dy(1, signed).  Move right, move down, click
 * button 1, release; assert each report surfaces byte for byte.
 */
ATF_TC_WITHOUT_HEAD(mouse_movement_stream);
ATF_TC_BODY(mouse_movement_stream, tc)
{
	static const uint8_t reports[4][3] = {
		{ 0x00, 0x0A, 0x00 },	/* dx = +10 (move right)		*/
		{ 0x00, 0x00, 0x0A },	/* dy = +10 (move down)		*/
		{ 0x01, 0x00, 0x00 },	/* button 1 down (click)	*/
		{ 0x00, 0x00, 0x00 }	/* button release		*/
	};
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_mouse m;
	struct att_conn ac;
	int fd;
	unsigned int i;

	cli_setup(&h, &bp, &fd, NULL);
	make_mouse(bp, &m);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	cli_subscribe(&ac, m.input_cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	for (i = 0; i < 4; i++) {
		post_notify(&h, m.input_report, reports[i], 3);
		expect_notify(&ac, m.input_report, reports[i], 3);
	}

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * BATTERY session
 * ================================================================ */

/* Battery Level read = 100% (BAS 1.0 uint8 percent). */
ATF_TC_WITHOUT_HEAD(battery_read_level);
ATF_TC_BODY(battery_read_level, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct battery_dev b;
	struct att_conn ac;
	uint8_t buf[4];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_battery(bp, &b);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, b.level, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(BATT_FULL, buf[0]);	/* 100 */

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Subscribe, read CCCD back, then a descending drain stream 99..96. */
ATF_TC_WITHOUT_HEAD(battery_drain_stream);
ATF_TC_BODY(battery_drain_stream, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct battery_dev b;
	struct att_conn ac;
	uint8_t buf[4];
	size_t outlen = 0;
	int fd;
	unsigned int lvl;

	cli_setup(&h, &bp, &fd, NULL);
	make_battery(bp, &b);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	cli_subscribe(&ac, b.cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	/* CCCD reads back the enabled Notification bit (Vol 3 Part G 3.3.3.3). */
	ATF_CHECK_EQ(0, att_read(&ac, b.cccd, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(2, outlen);
	ATF_CHECK_EQ(BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED,
	    get_le16(buf));

	/* Drain 100 -> 99 -> 98 -> 97 -> 96, one Notification per level. */
	for (lvl = 99; lvl >= 96; lvl--) {
		uint8_t v = (uint8_t)lvl;

		post_notify(&h, b.level, &v, 1);
		expect_notify(&ac, b.level, &v, 1);
	}

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * DEVICE INFORMATION SERVICE session
 * ================================================================ */

/* Discover the DIS and confirm all eight DIS characteristics are present. */
ATF_TC_WITHOUT_HEAD(dis_discover_all);
ATF_TC_BODY(dis_discover_all, tc)
{
	static const uint16_t want[8] = {
		BT_ASSIGNED_UUID_MANUFACTURER_NAME_STRING,
		BT_ASSIGNED_UUID_MODEL_NUMBER_STRING,
		BT_ASSIGNED_UUID_SERIAL_NUMBER_STRING,
		BT_ASSIGNED_UUID_FIRMWARE_REVISION_STRING,
		BT_ASSIGNED_UUID_HARDWARE_REVISION_STRING,
		BT_ASSIGNED_UUID_SOFTWARE_REVISION_STRING,
		BT_ASSIGNED_UUID_SYSTEM_ID,
		BT_ASSIGNED_UUID_PNP_ID
	};
	struct cli_harness h;
	struct btpeer *bp;
	struct dis_dev d;
	struct att_conn ac;
	struct gatt_service svcs[GATT_MAX_SERVICES];
	struct gatt_char chars[GATT_MAX_CHARS];
	int fd, nsvc = -1, nch = -1, i;
	unsigned int j;
	bool dis = false;

	cli_setup(&h, &bp, &fd, NULL);
	make_dis(bp, &d);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_REQUIRE_EQ(0, gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvc));
	for (i = 0; i < nsvc; i++)
		if (svcs[i].uuid16 ==
		    BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE)
			dis = true;
	ATF_CHECK(dis);

	ATF_REQUIRE_EQ(0, gatt_discover_characteristics(&ac, d.svc_start,
	    d.svc_end, chars, GATT_MAX_CHARS, &nch));
	ATF_CHECK_EQ(8, nch);
	for (j = 0; j < 8; j++) {
		bool found = false;

		for (i = 0; i < nch; i++)
			if (chars[i].uuid16 == want[j])
				found = true;
		ATF_CHECK_MSG(found, "DIS characteristic %04x missing", want[j]);
	}

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Read the six DIS UTF-8 string characteristics and assert exact bytes. */
ATF_TC_WITHOUT_HEAD(dis_read_strings);
ATF_TC_BODY(dis_read_strings, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct dis_dev d;
	struct att_conn ac;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_dis(bp, &d);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, d.manufacturer, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_manufacturer), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_manufacturer, outlen));

	ATF_CHECK_EQ(0, att_read(&ac, d.model_number, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_model), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_model, outlen));

	ATF_CHECK_EQ(0, att_read(&ac, d.serial_number, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_serial), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_serial, outlen));

	ATF_CHECK_EQ(0, att_read(&ac, d.firmware_rev, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_firmware), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_firmware, outlen));

	ATF_CHECK_EQ(0, att_read(&ac, d.hardware_rev, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_hardware), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_hardware, outlen));

	ATF_CHECK_EQ(0, att_read(&ac, d.software_rev, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_software), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_software, outlen));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* System ID (0x2A23): exactly 8 octets, exact bytes (DIS 1.1). */
ATF_TC_WITHOUT_HEAD(dis_read_system_id);
ATF_TC_BODY(dis_read_system_id, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct dis_dev d;
	struct att_conn ac;
	uint8_t buf[16];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_dis(bp, &d);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, d.system_id, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(8, outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_system_id, sizeof(dis_system_id)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * PnP ID (0x2A50): 7 octets = Vendor ID Source(1) | Vendor ID(2 LE) |
 * Product ID(2 LE) | Product Version(2 LE) (DIS 1.1).
 */
ATF_TC_WITHOUT_HEAD(dis_read_pnp_id);
ATF_TC_BODY(dis_read_pnp_id, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct dis_dev d;
	struct att_conn ac;
	uint8_t buf[16];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_dis(bp, &d);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, d.pnp_id, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(7, outlen);
	ATF_CHECK_EQ(BT_GSS_PNP_VENDOR_SOURCE_USB_IF, buf[0]);
	ATF_CHECK_EQ(0x1234, get_le16(buf + 1));	/* Vendor ID */
	ATF_CHECK_EQ(0x5678, get_le16(buf + 3));	/* Product ID */
	ATF_CHECK_EQ(0x0100, get_le16(buf + 5));	/* Product Version */

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * HEART RATE (measurement sensor) session
 * ================================================================ */

/* Discover Heart Rate Service + its two characteristics. */
ATF_TC_WITHOUT_HEAD(hr_discover);
ATF_TC_BODY(hr_discover, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct heartrate_dev hr;
	struct att_conn ac;
	struct gatt_service svcs[GATT_MAX_SERVICES];
	struct gatt_char chars[GATT_MAX_CHARS];
	int fd, nsvc = -1, nch = -1, i;
	bool svc = false, hrm = false, bsl = false;

	cli_setup(&h, &bp, &fd, NULL);
	make_heartrate(bp, &hr);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_REQUIRE_EQ(0, gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvc));
	for (i = 0; i < nsvc; i++)
		if (svcs[i].uuid16 == BT_ASSIGNED_UUID_HEART_RATE_SERVICE)
			svc = true;
	ATF_CHECK(svc);

	ATF_REQUIRE_EQ(0, gatt_discover_characteristics(&ac, hr.svc_start,
	    hr.svc_end, chars, GATT_MAX_CHARS, &nch));
	for (i = 0; i < nch; i++) {
		if (chars[i].uuid16 ==
		    BT_ASSIGNED_UUID_HEART_RATE_MEASUREMENT) {
			hrm = true;
			/* Notify property (Heart Rate Service 1.0). */
			ATF_CHECK_EQ(HOGSCN_GATT_PROP_NOTIFY,
			    chars[i].properties & HOGSCN_GATT_PROP_NOTIFY);
		}
		if (chars[i].uuid16 ==
		    BT_ASSIGNED_UUID_BODY_SENSOR_LOCATION)
			bsl = true;
	}
	ATF_CHECK(hrm);
	ATF_CHECK(bsl);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Body Sensor Location (0x2A38) = Chest (0x01). */
ATF_TC_WITHOUT_HEAD(hr_read_body_sensor_location);
ATF_TC_BODY(hr_read_body_sensor_location, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct heartrate_dev hr;
	struct att_conn ac;
	uint8_t buf[4];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_heartrate(bp, &hr);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, hr.body_location, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(HR_LOCATION_CHEST, buf[0]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Heart Rate Measurement (0x2A37) notification stream, uint8 format.
 * HRM value layout (Heart Rate Service 1.0): Flags(1) | HR Value.  Flags bit0
 * = Value Format: 0 => the next octet is an 8-bit bpm.  Stream 60,72,80,100.
 */
ATF_TC_WITHOUT_HEAD(hr_measurement_stream_uint8);
ATF_TC_BODY(hr_measurement_stream_uint8, tc)
{
	static const uint8_t bpms[4] = { 60, 72, 80, 100 };
	struct cli_harness h;
	struct btpeer *bp;
	struct heartrate_dev hr;
	struct att_conn ac;
	uint8_t rbuf[16];
	size_t outlen = 0;
	int fd;
	unsigned int i;

	cli_setup(&h, &bp, &fd, NULL);
	make_heartrate(bp, &hr);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	cli_subscribe(&ac, hr.cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	for (i = 0; i < 4; i++) {
		uint8_t meas[2] = { BT_HRS10_VALUE_FORMAT_UINT8, bpms[i] };

		post_notify(&h, hr.measurement, meas, 2);
		ATF_REQUIRE_EQ(0, att_recv(&ac, rbuf, sizeof(rbuf), &outlen));
		ATF_REQUIRE_EQ(5, outlen);	/* 1 op + 2 handle + 2 value */
		ATF_CHECK_EQ(HOGSCN_ATT_OP_HANDLE_NOTIFY, rbuf[0]);
		ATF_CHECK_EQ(hr.measurement, get_le16(rbuf + 1));
		ATF_CHECK_EQ(BT_HRS10_VALUE_FORMAT_UINT8, rbuf[3]);
		ATF_CHECK_EQ(bpms[i], rbuf[4]);		/* 8-bit bpm */
	}

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Heart Rate Measurement, uint16 format.  Flags bit0 = 1 => the HR Value is a
 * little-endian uint16 (Heart Rate Service 1.0).  Value 300 bpm => 0x012C LE.
 */
ATF_TC_WITHOUT_HEAD(hr_measurement_uint16);
ATF_TC_BODY(hr_measurement_uint16, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct heartrate_dev hr;
	struct att_conn ac;
	uint8_t rbuf[16];
	uint8_t meas[3] = { BT_HRS10_VALUE_FORMAT_UINT16, 0x2c, 0x01 };
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_heartrate(bp, &hr);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	cli_subscribe(&ac, hr.cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	post_notify(&h, hr.measurement, meas, 3);
	ATF_REQUIRE_EQ(0, att_recv(&ac, rbuf, sizeof(rbuf), &outlen));
	ATF_REQUIRE_EQ(6, outlen);		/* 1 op + 2 handle + 3 value */
	ATF_CHECK_EQ(HOGSCN_ATT_OP_HANDLE_NOTIFY, rbuf[0]);
	ATF_CHECK_EQ(hr.measurement, get_le16(rbuf + 1));
	ATF_CHECK_EQ(BT_HRS10_VALUE_FORMAT_UINT16, rbuf[3]);
	ATF_CHECK_EQ(300, get_le16(rbuf + 4));	/* 16-bit bpm */

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * Multiple CCCDs, indication path, and edge cases
 * ================================================================ */

/*
 * Two simultaneous CCCDs: a keyboard input report and a battery level, each
 * subscribed independently.  Both CCCDs read back Notification-enabled and
 * both streams surface on the shared bearer.
 */
ATF_TC_WITHOUT_HEAD(multiple_cccds_two_streams);
ATF_TC_BODY(multiple_cccds_two_streams, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct battery_dev b;
	struct att_conn ac;
	uint8_t buf[8], report[8];
	uint8_t lvl = 0x50;
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	make_battery(bp, &b);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Subscribe to both characteristics. */
	cli_subscribe(&ac, k.input_cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	cli_subscribe(&ac, b.cccd,
	    BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

	/* Both CCCDs read back the enabled Notification bit. */
	ATF_CHECK_EQ(0, att_read(&ac, k.input_cccd, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(2, outlen);
	ATF_CHECK_EQ(BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED,
	    get_le16(buf));
	ATF_CHECK_EQ(0, att_read(&ac, b.cccd, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(2, outlen);
	ATF_CHECK_EQ(BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED,
	    get_le16(buf));

	/* A keystroke on the HID input report. */
	kbd_report(report, KEY_H);
	post_notify(&h, k.input_report, report, sizeof(report));
	expect_notify(&ac, k.input_report, report, sizeof(report));

	/* A battery level on the battery characteristic. */
	post_notify(&h, b.level, &lvl, 1);
	expect_notify(&ac, b.level, &lvl, 1);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Indication path (Vol 3 Part F 3.4.7.2 / 3.4.7.3): a Health Thermometer
 * Temperature Measurement (0x2A1C) is Indicate-only (HTS 1.0).  Subscribe with
 * the Indication bit, receive a Handle Value Indication (0x1D), then OUR side
 * sends the Confirmation (0x1E).
 */
ATF_TC_WITHOUT_HEAD(indication_temperature_confirm);
ATF_TC_BODY(indication_temperature_confirm, tc)
{
	/*
	 * Temperature Measurement value (HTS 1.0): Flags(1) | Temperature
	 * (FLOAT, 4 octets IEEE-11073).  Flags bit0 = 0 => Celsius.  The exact
	 * float encoding is not asserted here; the indication transport is.
	 */
	static const uint8_t temp[5] = {
		BT_GSS_TEMPERATURE_FLAGS_CELSIUS_ONLY,
		0xf4, 0x00, 0x00, 0xfe
	};
	struct cli_harness h;
	struct btpeer *bp;
	struct thermometer_dev t;
	struct att_conn ac;
	struct pump_cmd cmd;
	uint8_t buf[16];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_thermometer(bp, &t);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Subscribe with the Indication bit (Vol 3 Part G 3.3.3.3 => 0x0002). */
	cli_subscribe(&ac, t.cccd,
	    BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED);

	/* Peer indicates a measurement. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_INDICATE;
	cmd.handle = t.measurement;
	cmd.len = (uint16_t)sizeof(temp);
	memcpy(cmd.val, temp, sizeof(temp));
	cli_post(&h, &cmd);

	/* OUR side surfaces the Indication (0x1D) with the exact payload... */
	ATF_REQUIRE_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(3 + sizeof(temp), outlen);
	ATF_CHECK_EQ(HOGSCN_ATT_OP_HANDLE_IND, buf[0]);
	ATF_CHECK_EQ(t.measurement, get_le16(buf + 1));
	ATF_CHECK_EQ(0, memcmp(buf + 3, temp, sizeof(temp)));
	/* ...and confirms it (0x1E). */
	ATF_CHECK_EQ(0, att_confirm(&ac));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/*
 * Edge: subscribing with the wrong CCCD bit.  Writing the Indication bit
 * (0x0002) to a notify-only characteristic's CCCD is accepted at the ATT layer
 * -- the CCCD is a writable 2-octet value with no server-side profile
 * validation here -- and reads back 0x0002 (Vol 3 Part G 3.3.3.3).  A HID
 * device that streams on Notification-enable therefore does NOT stream.
 */
ATF_TC_WITHOUT_HEAD(subscribe_wrong_cccd_bit);
ATF_TC_BODY(subscribe_wrong_cccd_bit, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[4];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Write the Indication bit to the notify-only Input Report CCCD. */
	cli_subscribe(&ac, k.input_cccd,
	    BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED);
	ATF_CHECK_EQ(0, att_read(&ac, k.input_cccd, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(2, outlen);
	ATF_CHECK_EQ(BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED,
	    get_le16(buf));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Reading an absent handle => Invalid Handle (Vol 3 Part F 3.4.1.1 code 0x01). */
ATF_TC_WITHOUT_HEAD(read_invalid_handle);
ATF_TC_BODY(read_invalid_handle, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct hid_keyboard k;
	struct att_conn ac;
	uint8_t buf[8];
	size_t outlen = 0;
	int fd, rc;

	cli_setup(&h, &bp, &fd, NULL);
	make_keyboard(bp, &k);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	rc = att_read(&ac, 0x0FFF, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(HOGSCN_ATT_ERR_INVALID_HANDLE, rc);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Keyboard sessions */
	ATF_TP_ADD_TC(tp, kbd_discover_topology);
	ATF_TP_ADD_TC(tp, kbd_read_report_map);
	ATF_TP_ADD_TC(tp, kbd_read_hid_information);
	ATF_TP_ADD_TC(tp, kbd_protocol_mode_read_write);
	ATF_TP_ADD_TC(tp, kbd_subscribe_cccd_readback);
	ATF_TP_ADD_TC(tp, kbd_type_hello);
	ATF_TP_ADD_TC(tp, kbd_read_report_before_map);
	ATF_TP_ADD_TC(tp, kbd_write_report_map_rejected);
	ATF_TP_ADD_TC(tp, kbd_control_point_write);

	/* Mouse session */
	ATF_TP_ADD_TC(tp, mouse_read_report_map);
	ATF_TP_ADD_TC(tp, mouse_movement_stream);

	/* Battery session */
	ATF_TP_ADD_TC(tp, battery_read_level);
	ATF_TP_ADD_TC(tp, battery_drain_stream);

	/* Device Information Service session */
	ATF_TP_ADD_TC(tp, dis_discover_all);
	ATF_TP_ADD_TC(tp, dis_read_strings);
	ATF_TP_ADD_TC(tp, dis_read_system_id);
	ATF_TP_ADD_TC(tp, dis_read_pnp_id);

	/* Heart Rate sensor session */
	ATF_TP_ADD_TC(tp, hr_discover);
	ATF_TP_ADD_TC(tp, hr_read_body_sensor_location);
	ATF_TP_ADD_TC(tp, hr_measurement_stream_uint8);
	ATF_TP_ADD_TC(tp, hr_measurement_uint16);

	/* Multiple CCCDs, indication path, edge cases */
	ATF_TP_ADD_TC(tp, multiple_cccds_two_streams);
	ATF_TP_ADD_TC(tp, indication_temperature_confirm);
	ATF_TP_ADD_TC(tp, subscribe_wrong_cccd_bit);
	ATF_TP_ADD_TC(tp, read_invalid_handle);

	return (atf_no_error());
}
