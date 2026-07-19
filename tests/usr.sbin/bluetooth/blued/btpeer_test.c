/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * btpeer_test.c - end-to-end scenarios driving the REAL blued protocol code
 * (att.c client, att_server*.c, gatt.c, smp*.c) against a hardware-free
 * virtual remote peer (btpeer.c) that rides an hci_emu link.
 *
 * Two controller emulators (hci_emulator.c) are joined with hci_emu_link();
 * one carries OUR code under test, the other carries btpeer.  ATT/SMP L2CAP
 * B-frames travel as LE ACL data through the emulator link -- no sockets to
 * the kernel, no radio.
 *
 * Two wiring directions are exercised:
 *
 *   SERVER direction (no thread): btpeer is the GATT CLIENT and OUR
 *   att_server is the code under test.  The whole request/response round trip
 *   unwinds inline through the emu link, so each btpeer_gatt_*() call is
 *   synchronous.  OUR att_server_handle() response is drained off a socket and
 *   fed back into the emu as the reply ACL.
 *
 *   CLIENT direction (pump thread): OUR att.c / smp.c code is the code under
 *   test and blocks on its L2CAP socket; a pump thread owns the emu link and
 *   btpeer and bridges the socket to the ACL path.  The main thread only ever
 *   touches its own socket, so nothing but the kernel socket is shared.
 *
 * ORACLE: every asserted value is hand-derived from the Bluetooth Core
 * Specification (<= 5.2); citations are inline.  A disagreement between a
 * spec-derived expectation and the stack is a finding about the stack.
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
#include "smp_internal.h"
#include "hci_emulator.h"
#include "btpeer.h"
#include "spec_btpeer_integration_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (mirrors
 * smp_pairing_test.c: the real ones use bt_devreq on a kernel HCI node).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = 0x01;
	buf[1] = (uint8_t)(opcode & 0xFF);
	buf[2] = (uint8_t)(opcode >> 8);
	buf[3] = plen;
	if (plen > 0 && params != NULL)
		memcpy(buf + 4, params, plen);
	return ((int)send(hci_fd, buf, (size_t)4 + plen, MSG_NOSIGNAL));
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
#define OP_LE_ENABLE_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)
#define OP_LE_LTK_REQ_REPLY \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY)

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
 * Section 7.8.5/7.8.10/7.8.12).  Mirrors hci_emulator_link_test.c.
 */
static void
establish_conn(struct hci_emu *central, struct hci_emu *periph,
    const uint8_t caddr[6], const uint8_t paddr[6])
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t p[64];

	hci_emu_set_bd_addr(central, caddr);
	hci_emu_set_bd_addr(periph, paddr);

	/* Peripheral: set advertising data + enable (ADV_IND). */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(periph, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(periph, OP_LE_SET_ADV_ENABLE, p, 1);

	/* Central: scan then create connection. */
	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(central, OP_LE_SET_SCAN_ENABLE, p, 2);

	memset(p, 0, 25);
	le16enc(&p[0], 0x0060);		/* scan_interval */
	le16enc(&p[2], 0x0030);		/* scan_window */
	p[4] = 0x00;			/* filter policy */
	p[5] = 0x00;			/* peer addr type: public */
	memcpy(&p[6], paddr, 6);
	p[12] = 0x00;			/* own addr type: public */
	le16enc(&p[13], 0x0028);	/* conn_interval_min */
	le16enc(&p[15], 0x0028);	/* conn_interval_max */
	le16enc(&p[17], 0x0000);	/* latency */
	le16enc(&p[19], 0x00c8);	/* supervision timeout */
	feed_cmd(central, OP_LE_CREATE_CONNECTION, p, 25);
}

/* ================================================================
 * SERVER direction: OUR att_server behind emu A; btpeer is the client.
 * ================================================================ */
struct srv_harness {
	struct hci_emu	*emu;		/* our controller (emu A) */
	uint16_t	handle;		/* our LE-ACL connection handle */
	struct att_conn	ac;
	struct att_db	db;
	int		bridge;		/* peer end of ac.fd socketpair */
};

/* Feed one L2CAP B-frame (payload) to our emu on CID cid -> reaches btpeer. */
static void
srv_tx(struct srv_harness *h, uint16_t cid, const uint8_t *payload,
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

/* emu A output callback: an ATT request from btpeer arrived. */
static void
srv_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct srv_harness *h = ctx;
	uint16_t l2_len, cid;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;			/* HCI event, not L2CAP data */
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len || cid != NG_L2CAP_ATT_CID)
		return;

	/* Drive the REAL server; its response is written to h->ac.fd. */
	att_server_handle(&h->ac, &h->db, &pkt[9], l2_len, -1, 0);

	/* Forward every response PDU back to btpeer as reply ACL. */
	while ((n = recv(h->bridge, rsp, sizeof(rsp), MSG_DONTWAIT)) > 0)
		srv_tx(h, NG_L2CAP_ATT_CID, rsp, (uint16_t)n);
}

static void
srv_setup(struct srv_harness *h, struct btpeer **bp_out)
{
	static const uint8_t caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	struct hci_emu *emu_our, *emu_peer;
	struct btpeer *bp;
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

	emu_our = hci_emu_new();
	emu_peer = hci_emu_new();
	ATF_REQUIRE(emu_our != NULL && emu_peer != NULL);
	hci_emu_link(emu_our, emu_peer);

	h->emu = emu_our;
	hci_emu_set_output(emu_our, srv_out, h);
	bp = btpeer_new(emu_peer);	/* installs emu_peer's output cb */
	ATF_REQUIRE(bp != NULL);

	/* btpeer (GATT client) is central; our server is the advertiser. */
	establish_conn(emu_peer, emu_our, paddr, caddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(emu_our, 0, &h->handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(bp));

	/* Our real ATT server connection state. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	h->ac.fd = fds[0];
	h->ac.bearer_fd = -1;
	h->ac.mtu = ATT_PDU_BUF_SIZE;
	h->ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(h->ac.buf != NULL);
	h->bridge = fds[1];

	*bp_out = bp;
}

/*
 * Build OUR server's attribute database (the code-under-test GATT server).
 * Handles are deterministic from insertion order (att_server.c allocates
 * sequentially from 0x0001):
 *
 *   0x0001 GAP primary service (0x1800)
 *   0x0002 Device Name char decl (0x2A00, READ)   value handle 0x0003
 *   0x0003 Device Name value  = "btpeer-dut"
 *   0x0004 Battery primary service (0x180F)
 *   0x0005 Battery Level char decl (0x2A19, READ|NOTIFY) value handle 0x0006
 *   0x0006 Battery Level value = 0x64 (100%, BAS 1.0 uint8 percent)
 *   0x0007 CCCD (0x2902)
 *   0x0008 Vendor primary service (0x1523)
 *   0x0009 Vendor char decl (0x1525, READ|WRITE)  value handle 0x000A
 *   0x000A Vendor value = { 0x00 }
 */
#define OUR_DEVNAME	"btpeer-dut"
#define OUR_BATT_LEVEL	BTPI_BATTERY_FULL_PERCENT
static struct att_attr srv_storage[32];
static uint8_t srv_valbuf[1024];

static void
srv_build_db(struct att_db *db)
{
	static const uint8_t initval[4] = { 0, 0, 0, 0 };
	static const uint8_t batt = OUR_BATT_LEVEL;

	attdb_init(db, srv_storage, 32, srv_valbuf, sizeof(srv_valbuf));
	attdb_add_service(db, BTPI_UUID_GAP_SERVICE);
	attdb_add_characteristic(db, BTPI_UUID_DEVICE_NAME, GATT_PROP_READ,
	    ATT_PERM_READ,
	    OUR_DEVNAME, (uint16_t)strlen(OUR_DEVNAME));
	attdb_add_service(db, BTPI_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(db, BTPI_UUID_BATTERY_LEVEL,
	    GATT_PROP_READ | GATT_PROP_NOTIFY,
	    ATT_PERM_READ, &batt, 1);
	attdb_add_cccd(db);
	attdb_add_service(db, 0x1523);
	attdb_add_characteristic(db, 0x1525, GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, initval, sizeof(initval));
}

static void
srv_teardown(struct srv_harness *h)
{

	free(h->ac.buf);
	close(h->ac.fd);
	close(h->bridge);
}

/* ---- SERVER-direction scenarios ---- */

ATF_TC_WITHOUT_HEAD(peer_exchange_mtu);
ATF_TC_BODY(peer_exchange_mtu, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint16_t smtu = 0;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);

	/* Exchange MTU (Vol 3 Part F 3.4.2): effective = min(client,server). */
	ATF_CHECK_EQ(0, btpeer_gatt_exchange_mtu(bp, 100, &smtu));
	ATF_CHECK_EQ(BTPI_ATT_MAX_MTU, smtu);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_discover_services);
ATF_TC_BODY(peer_discover_services, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_service svc[8];
	int n = -1;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Primary Service Discovery (Vol 3 Part G 4.4.1). */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_services(bp, svc, 8, &n));
	ATF_CHECK_EQ(3, n);
	ATF_CHECK_EQ(0x0001, svc[0].start);
	ATF_CHECK_EQ(BTPI_UUID_GAP_SERVICE, svc[0].uuid16);
	ATF_CHECK_EQ(0x0004, svc[1].start);
	ATF_CHECK_EQ(BTPI_UUID_BATTERY_SERVICE, svc[1].uuid16);
	ATF_CHECK_EQ(0x0008, svc[2].start);
	ATF_CHECK_EQ(0x1523, svc[2].uuid16);
	/* Group end of the last service = last handle (0x000A). */
	ATF_CHECK_EQ(0x000A, svc[2].end);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_discover_chars);
ATF_TC_BODY(peer_discover_chars, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_char ch[8];
	int n = -1;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Characteristic discovery of the Battery service (0x0004-0x0007). */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_chars(bp, 0x0004, 0x0007, ch, 8,
	    &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(0x0005, ch[0].decl);
	ATF_CHECK_EQ(0x0006, ch[0].value);
	ATF_CHECK_EQ(BTPI_UUID_BATTERY_LEVEL, ch[0].uuid16);
	/* Properties Read|Notify (Vol 3 Part G 3.3.1.1). */
	ATF_CHECK_EQ(BTPI_GATT_PROP_READ | BTPI_GATT_PROP_NOTIFY,
	    ch[0].props);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_discover_descs);
ATF_TC_BODY(peer_discover_descs, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_desc d[8];
	int n = -1, i, found = 0;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Descriptor discovery over the Battery service (Vol 3 Part G 4.7.1):
	 * the CCCD (0x2902) sits at handle 0x0007. */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_descs(bp, 0x0006, 0x0007, d, 8,
	    &n));
	for (i = 0; i < n; i++)
		if (d[i].uuid16 == BTPI_UUID_CCCD && d[i].handle == 0x0007)
			found = 1;
	ATF_CHECK_EQ(1, found);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_read_battery_level);
ATF_TC_BODY(peer_read_battery_level, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[64];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Request handle 0x0006 (Vol 3 Part F 3.4.4.3). */
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, 0x0006, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(OUR_BATT_LEVEL, buf[0]);	/* 100% (BAS uint8 percent) */

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_read_device_name);
ATF_TC_BODY(peer_read_device_name, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[64];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Device Name (0x2A00) value at handle 0x0003. */
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, 0x0003, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(OUR_DEVNAME), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, OUR_DEVNAME, outlen));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_write_vendor_char);
ATF_TC_BODY(peer_write_vendor_char, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t newval[3] = { 0xAA, 0xBB, 0xCC };

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Write Request to writable vendor value 0x000A (Vol 3 Part F 3.4.5.1). */
	ATF_CHECK_EQ(0, btpeer_gatt_write(bp, 0x000A, newval, sizeof(newval)));

	/* OUR server actually stored the bytes. */
	a = attdb_find_by_handle(&h.db, 0x000A);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(sizeof(newval), a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, newval, sizeof(newval)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_write_readonly_rejected);
ATF_TC_BODY(peer_write_readonly_rejected, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t code = 0, val = 0x11;
	int rc;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Writing the read-only Battery Level (0x0006) must yield an Error
	 * Response Write Not Permitted (Vol 3 Part F 3.4.1.1 code 0x03). */
	rc = btpeer_gatt_write(bp, 0x0006, &val, 1);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(BTPI_ATT_ERR_WRITE_NOT_PERMITTED, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(peer_read_invalid_handle);
ATF_TC_BODY(peer_read_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[8], code = 0;
	size_t outlen = 0;
	int rc;

	srv_setup(&h, &bp);
	srv_build_db(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Reading a nonexistent handle => Invalid Handle (0x01). */
	rc = btpeer_gatt_read(bp, 0x00FF, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(BTPI_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * CLIENT direction: OUR att.c/smp.c behind emu A; btpeer is the server.
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
 * Reusable btpeer device-profile fixtures.  Each maker builds a spec-shaped
 * accessory server on the peer and returns the handles a scenario needs.  A
 * later phase can extend this library with more device types.
 * ================================================================ */
struct btpeer_device {
	uint16_t	hid_svc_start, hid_svc_end;
	uint16_t	report_map;		/* Report Map value (HOGP) */
	uint16_t	input_report;		/* Input Report value */
	uint16_t	input_cccd;		/* Input Report CCCD */
	uint16_t	battery_svc_start, battery_svc_end;
	uint16_t	battery_level;		/* Battery Level value */
	uint16_t	battery_cccd;
	uint16_t	manuf_name;		/* DIS Manufacturer Name value */
	uint16_t	vendor_write;		/* a writable vendor value */
};

/*
 * HID keyboard boot report descriptor (USB HID 1.11 Section 6.2.2 / HID Usage
 * Tables): 8-octet input report = modifier(1) | reserved(1) | keycodes(6).
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

/* HID Information (0x2A4A): bcdHID=0x0111 | bCountryCode=0 | Flags. */
static const uint8_t hid_info[4] = { 0x11, 0x01, 0x00, 0x02 };

/* 8-octet boot keyboard input report for the 'a' key (HID Usage ID 0x04). */
	static const uint8_t hid_key_a[8] = { 0x00, 0x00,
	    BTPI_HID_KEYBOARD_A, 0, 0, 0, 0, 0 };

/* 3-octet boot mouse report: button 1 down, dx=+5, dy=-5 (0xFB = -5). */
static const uint8_t mouse_move[3] = { 0x01, 0x05, 0xFB };

/* Battery Level values (BAS 1.0: uint8 percentage). */
#define BATT_FULL	BTPI_BATTERY_FULL_PERCENT
#define BATT_DRAIN	0x63		/* 99% */

/* DIS 0x180A Manufacturer Name String (0x2A29). */
static const char dis_manuf[] = "ACME";

static uint16_t
peer_add_vendor_write(struct btpeer *bp)
{
	static const uint8_t v0 = 0x00;

	btpeer_add_service(bp, 0x1523);		/* vendor primary service */
	return (btpeer_add_characteristic(bp, 0x1525,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    BTPEER_PERM_READ | BTPEER_PERM_WRITE, &v0, 1));
}

/* HID keyboard (HOGP 1.0, Vol 3: HID Service 0x1812). */
static void
btpeer_make_keyboard(struct btpeer *bp, struct btpeer_device *dev)
{
	static const uint8_t rpt0[8] = { 0 };

	memset(dev, 0, sizeof(*dev));
	dev->hid_svc_start = btpeer_add_service(bp, BTPI_UUID_HID_SERVICE);
	dev->report_map = btpeer_add_characteristic(bp, BTPI_UUID_REPORT_MAP,
	    GATT_PROP_READ,
	    BTPEER_PERM_READ, kbd_report_map, (uint16_t)sizeof(kbd_report_map));
	btpeer_add_characteristic(bp, BTPI_UUID_HID_INFORMATION, GATT_PROP_READ,
	    BTPEER_PERM_READ,
	    hid_info, (uint16_t)sizeof(hid_info));
	dev->input_report = btpeer_add_characteristic(bp, BTPI_UUID_REPORT,
	    GATT_PROP_READ | GATT_PROP_NOTIFY, BTPEER_PERM_READ, rpt0,
	    (uint16_t)sizeof(rpt0));
	dev->input_cccd = btpeer_add_cccd(bp);
	dev->hid_svc_end = dev->input_cccd;
}

/* HID mouse (HOGP 1.0, HID Service 0x1812). */
static void
btpeer_make_mouse(struct btpeer *bp, struct btpeer_device *dev)
{
	static const uint8_t rpt0[3] = { 0 };

	memset(dev, 0, sizeof(*dev));
	dev->hid_svc_start = btpeer_add_service(bp, BTPI_UUID_HID_SERVICE);
	dev->report_map = btpeer_add_characteristic(bp, BTPI_UUID_REPORT_MAP,
	    GATT_PROP_READ,
	    BTPEER_PERM_READ, mouse_report_map,
	    (uint16_t)sizeof(mouse_report_map));
	dev->input_report = btpeer_add_characteristic(bp, BTPI_UUID_REPORT,
	    GATT_PROP_READ | GATT_PROP_NOTIFY, BTPEER_PERM_READ, rpt0,
	    (uint16_t)sizeof(rpt0));
	dev->input_cccd = btpeer_add_cccd(bp);
	dev->hid_svc_end = dev->input_cccd;
}

/* Sensor: Battery Service (0x180F) + Device Information Service (0x180A). */
static void
btpeer_make_battery(struct btpeer *bp, struct btpeer_device *dev)
{
	static const uint8_t lvl = BATT_FULL;

	memset(dev, 0, sizeof(*dev));
	dev->battery_svc_start = btpeer_add_service(bp,
	    BTPI_UUID_BATTERY_SERVICE);
	dev->battery_level = btpeer_add_characteristic(bp,
	    BTPI_UUID_BATTERY_LEVEL,
	    GATT_PROP_READ | GATT_PROP_NOTIFY, BTPEER_PERM_READ, &lvl, 1);
	dev->battery_cccd = btpeer_add_cccd(bp);
	dev->battery_svc_end = dev->battery_cccd;
	/* Device Information Service with a Manufacturer Name String. */
	btpeer_add_service(bp, BTPI_UUID_DEVICE_INFO_SERVICE);
	dev->manuf_name = btpeer_add_characteristic(bp,
	    BTPI_UUID_MANUFACTURER_NAME, GATT_PROP_READ,
	    BTPEER_PERM_READ, dis_manuf, (uint16_t)strlen(dis_manuf));
}

/* Generic HID keyboard + vendor writable char, for the layered scenarios. */
static void
peer_build_hid_db(struct btpeer *bp, uint16_t *report_val, uint16_t *cccd,
    uint16_t *vendor_val)
{
	struct btpeer_device dev;
	uint16_t vv;

	btpeer_make_keyboard(bp, &dev);
	vv = peer_add_vendor_write(bp);
	if (report_val != NULL)
		*report_val = dev.input_report;
	if (cccd != NULL)
		*cccd = dev.input_cccd;
	if (vendor_val != NULL)
		*vendor_val = vv;
}

/* ---- CLIENT-direction scenarios ---- */

ATF_TC_WITHOUT_HEAD(our_exchange_mtu_with_peer);
ATF_TC_BODY(our_exchange_mtu_with_peer, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);		/* peer offers 100 */
	cli_att_conn(&ac, fd);
	cli_start(&h);

	/* OUR att_exchange_mtu (Vol 3 Part F 3.4.2): effective min(247,100). */
	ATF_CHECK_EQ(0, att_exchange_mtu(&ac, 247));
	ATF_CHECK_EQ(100, ac.mtu);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_read_peer_report_map);
ATF_TC_BODY(our_read_peer_report_map, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint8_t buf[64];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_read of the peer HID Report Map (handle 0x0003). */
	ATF_CHECK_EQ(0, att_read(&ac, 0x0003, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(sizeof(kbd_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, kbd_report_map, sizeof(kbd_report_map)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_write_peer_char);
ATF_TC_BODY(our_write_peer_char, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t vendor = 0;
	uint8_t stored[8];
	size_t slen = 0;
	const uint8_t data[2] = { 0x5A, 0xA5 };
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, NULL, NULL, &vendor);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_write_req to the peer's writable value handle 0x0008. */
	ATF_CHECK_EQ(0, att_write_req(&ac, vendor, data, sizeof(data)));

	cli_stop(&h);	/* pump idle: safe to inspect btpeer */
	ATF_CHECK_EQ(0, btpeer_get_value(bp, vendor, stored, sizeof(stored),
	    &slen));
	ATF_REQUIRE_EQ(sizeof(data), slen);
	ATF_CHECK_EQ(0, memcmp(stored, data, sizeof(data)));

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_read_peer_invalid_handle);
ATF_TC_BODY(our_read_peer_invalid_handle, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint8_t buf[8];
	size_t outlen = 0;
	int fd, rc;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* att.c maps an ATT Error Response to its code; 0x0FFF is absent =>
	 * Invalid Handle 0x01 (Vol 3 Part F 3.4.1.1). */
	rc = att_read(&ac, 0x0FFF, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(BTPI_ATT_ERR_INVALID_HANDLE, rc);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_subscribe_peer_notifies);
ATF_TC_BODY(our_subscribe_peer_notifies, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t report_val = 0, cccd = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, &report_val, &cccd, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Subscribe: Write Request CCCD = 0x0001 (Vol 3 Part G 3.3.3.3). */
	{
		uint8_t v[2] = { BTPI_CCCD_NOTIFY & 0xff,
		    BTPI_CCCD_NOTIFY >> 8 };
		ATF_CHECK_EQ(0, att_write_req(&ac, cccd, v, 2));
	}

	/* The peer then pushes the 'a' key report as a Notification (0x1B).
	 * Posted after the Write Response drains so the two PDUs are not
	 * coalesced by AF_UNIX SOCK_SEQPACKET. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = report_val;
	cmd.len = (uint16_t)sizeof(hid_key_a);
	memcpy(cmd.val, hid_key_a, sizeof(hid_key_a));
	cli_post(&h, &cmd);

	/* OUR client surfaces the Handle Value Notification. */
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(3 + sizeof(hid_key_a), outlen);
	ATF_CHECK_EQ(BTPI_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(report_val, get_le16(buf + 1));
	ATF_CHECK_EQ(0, memcmp(buf + 3, hid_key_a, sizeof(hid_key_a)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_receives_indication_confirms);
ATF_TC_BODY(our_receives_indication_confirms, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t report_val = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd, NULL);
	peer_build_hid_db(bp, &report_val, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Peer sends a Handle Value Indication (Vol 3 Part F 3.4.7.2). */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_INDICATE;
	cmd.handle = report_val;
	cmd.len = (uint16_t)sizeof(hid_key_a);
	memcpy(cmd.val, hid_key_a, sizeof(hid_key_a));
	cli_post(&h, &cmd);

	/* OUR side surfaces it and returns a Confirmation (3.4.7.3). */
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_CHECK_EQ(BTPI_ATT_OP_HANDLE_INDICATE, buf[0]);
	ATF_CHECK_EQ(0, att_confirm(&ac));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---- Full-stack GATT discovery of a keyboard peer (L2CAP->ATT->GATT->HOGP) ---- */
ATF_TC_WITHOUT_HEAD(our_gatt_discover_keyboard);
ATF_TC_BODY(our_gatt_discover_keyboard, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	struct gatt_service svcs[GATT_MAX_SERVICES];
	struct gatt_char chars[GATT_MAX_CHARS];
	int fd, nsvc = -1, nch = -1, i;
	bool hid = false, rmap = false, report = false;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_keyboard(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR gatt.c primary service discovery (Vol 3 Part G 4.4.1). */
	ATF_REQUIRE_EQ(0,
	    gatt_discover_primary_services(&ac, svcs, GATT_MAX_SERVICES, &nsvc));
	for (i = 0; i < nsvc; i++)
		if (svcs[i].uuid16 == BTPI_UUID_HID_SERVICE)
			hid = true;
	ATF_CHECK(hid);

	/* OUR gatt.c characteristic discovery over the HID service group. */
	ATF_REQUIRE_EQ(0, gatt_discover_characteristics(&ac,
	    dev.hid_svc_start, dev.hid_svc_end, chars, GATT_MAX_CHARS, &nch));
	for (i = 0; i < nch; i++) {
		if (chars[i].uuid16 == BTPI_UUID_REPORT_MAP)
			rmap = true;
		if (chars[i].uuid16 == BTPI_UUID_REPORT)
			report = true;
	}
	ATF_CHECK(rmap);
	ATF_CHECK(report);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---- Keyboard: keystroke input report as a Notification (the money case) ---- */
ATF_TC_WITHOUT_HEAD(our_keyboard_keystroke);
ATF_TC_BODY(our_keyboard_keystroke, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	uint8_t buf[32], rmap[80];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_keyboard(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Read the Report Map first (HOGP requires it before reports). */
	ATF_REQUIRE_EQ(0, att_read(&ac, dev.report_map, rmap, sizeof(rmap),
	    &outlen));
	ATF_REQUIRE_EQ(sizeof(kbd_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(rmap, kbd_report_map, sizeof(kbd_report_map)));

	/* Subscribe to the Input Report CCCD (Vol 3 Part G 3.3.3.3). */
	{
		uint8_t v[2] = { BTPI_CCCD_NOTIFY & 0xff,
		    BTPI_CCCD_NOTIFY >> 8 };
		ATF_CHECK_EQ(0, att_write_req(&ac, dev.input_cccd, v, 2));
	}

	/* Press 'a': the peer emits the input report as a Notification. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = dev.input_report;
	cmd.len = (uint16_t)sizeof(hid_key_a);
	memcpy(cmd.val, hid_key_a, sizeof(hid_key_a));
	cli_post(&h, &cmd);

	/* The 'a' keystroke arrives as a Handle Value Notification. */
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(3 + sizeof(hid_key_a), outlen);
	ATF_CHECK_EQ(BTPI_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(dev.input_report, get_le16(buf + 1));
	ATF_CHECK_EQ(BTPI_HID_KEYBOARD_A, buf[5]);
	ATF_CHECK_EQ(0, memcmp(buf + 3, hid_key_a, sizeof(hid_key_a)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---- Mouse: report map read + movement report as a Notification ---- */
ATF_TC_WITHOUT_HEAD(our_mouse_report_map);
ATF_TC_BODY(our_mouse_report_map, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	uint8_t buf[80];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_mouse(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	ATF_CHECK_EQ(0, att_read(&ac, dev.report_map, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(sizeof(mouse_report_map), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, mouse_report_map, sizeof(mouse_report_map)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_mouse_movement);
ATF_TC_BODY(our_mouse_movement, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_mouse(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	{
		uint8_t v[2] = { BTPI_CCCD_NOTIFY & 0xff,
		    BTPI_CCCD_NOTIFY >> 8 };
		ATF_CHECK_EQ(0, att_write_req(&ac, dev.input_cccd, v, 2));
	}
	/* Move the mouse: the peer emits the movement report as a Notification. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = dev.input_report;
	cmd.len = (uint16_t)sizeof(mouse_move);
	memcpy(cmd.val, mouse_move, sizeof(mouse_move));
	cli_post(&h, &cmd);
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(3 + sizeof(mouse_move), outlen);
	ATF_CHECK_EQ(BTPI_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(dev.input_report, get_le16(buf + 1));
	ATF_CHECK_EQ(0x01, buf[3]);		/* button 1 down */
	ATF_CHECK_EQ(0x05, buf[4]);		/* dx = +5 */
	ATF_CHECK_EQ(0xFB, buf[5]);		/* dy = -5 */

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---- Sensor: read Battery Level + Manufacturer Name, then battery notify ---- */
ATF_TC_WITHOUT_HEAD(our_read_battery_and_manuf);
ATF_TC_BODY(our_read_battery_and_manuf, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_battery(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Battery Level: single uint8 percent (BAS 1.0). */
	ATF_CHECK_EQ(0, att_read(&ac, dev.battery_level, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(BATT_FULL, buf[0]);

	/* DIS Manufacturer Name String (0x2A29). */
	ATF_CHECK_EQ(0, att_read(&ac, dev.manuf_name, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(dis_manuf), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, dis_manuf, outlen));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(our_battery_notification);
ATF_TC_BODY(our_battery_notification, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct btpeer_device dev;
	struct att_conn ac;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd, NULL);
	btpeer_make_battery(bp, &dev);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Subscribe to Battery Level notifications. */
	{
		uint8_t v[2] = { BTPI_CCCD_NOTIFY & 0xff,
		    BTPI_CCCD_NOTIFY >> 8 };
		ATF_CHECK_EQ(0, att_write_req(&ac, dev.battery_cccd, v, 2));
	}

	/* Peer reports a drained level as a Notification. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = dev.battery_level;
	cmd.val[0] = BATT_DRAIN;
	cmd.len = 1;
	cli_post(&h, &cmd);

	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(BTPI_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(dev.battery_level, get_le16(buf + 1));
	ATF_CHECK_EQ(BATT_DRAIN, buf[3]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * Pairing: OUR smp_pair() (initiator) vs btpeer SMP responder, LE Legacy
 * Just Works (Vol 3 Part H 2.3.5.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(pair_legacy_just_works);
ATF_TC_BODY(pair_legacy_just_works, tc)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	struct cli_harness h;
	struct btpeer *bp;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd = -1, smp_fd = -1, hci_fds[2];
	int ret;

	cli_setup(&h, &bp, &att_fd, &smp_fd);
	/* Teach btpeer the c1 addresses (Vol 3 Part H 2.2.3): both sides use
	 * the identical ia/ra/iat/rat.  Public addresses => SMP type 0. */
	btpeer_smp_set_addrs(bp, paddr, BTPI_SMP_ADDR_PUBLIC, caddr,
	    BTPI_SMP_ADDR_PUBLIC);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);

	memset(&db, 0, sizeof(db));
	db.fd = -1;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fd;
	sc.hci_fd = hci_fds[0];
	sc.con_handle = h.handle;
	memcpy(sc.local_addr, caddr, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, paddr, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = &db;
	sc.io_capability = BTPI_SMP_IO_NO_INPUT_NO_OUTPUT;
	sc.min_key_size = BTPI_SMP_ENC_KEY_SIZE_MIN;

	cli_start(&h);

	/* OUR initiator drives the whole legacy handshake against btpeer. */
	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair returned %d (errno=%d)", ret, errno);

	cli_stop(&h);
	/* Peer completed the legacy handshake and derived the STK. */
	ATF_CHECK(btpeer_smp_done(bp));

	close(att_fd);
	close(smp_fd);
	close(hci_fds[0]);
	close(hci_fds[1]);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * Emulator LTK / encryption path (Vol 4 Part E Section 7.8.24/7.7.65.5/
 * 7.8.25/7.7.8): drive the real emulator LTK exchange with a chosen key so
 * the link goes encrypted on BOTH controllers, then confirm OUR att_server
 * enforces encryption on a protected attribute.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(encrypted_link_security_gates);
ATF_TC_BODY(encrypted_link_security_gates, tc)
{
	static const uint8_t caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	static const uint8_t ltk[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};
	struct hci_emu *emu_our, *emu_peer;
	struct btpeer *bp;
	struct att_conn ac;
	struct att_attr attr;
	uint16_t ch, ph;
	uint8_t p[28];

	signal(SIGPIPE, SIG_IGN);
	emu_our = hci_emu_new();
	emu_peer = hci_emu_new();
	ATF_REQUIRE(emu_our != NULL && emu_peer != NULL);
	hci_emu_link(emu_our, emu_peer);
	bp = btpeer_new(emu_peer);
	ATF_REQUIRE(bp != NULL);
	/* our side (central) drives; keep its output cb harmless. */
	{
		struct srv_harness dummy;
		memset(&dummy, 0, sizeof(dummy));
		dummy.emu = emu_our;
		hci_emu_set_output(emu_our, srv_out, &dummy);
		establish_conn(emu_our, emu_peer, caddr, paddr);
		ATF_REQUIRE(hci_emu_get_conn_handle(emu_our, 0, &ch));
		ATF_REQUIRE(hci_emu_get_conn_handle(emu_peer, 0, &ph));

		/* LE Enable Encryption on the central (Vol 4 Part E 7.8.24). */
		le16enc(&p[0], ch);
		memset(&p[2], 0, 8);		/* Rand = 0 (STK-style) */
		le16enc(&p[10], 0x0000);	/* EDIV = 0 */
		memcpy(&p[12], ltk, 16);
		feed_cmd(emu_our, OP_LE_ENABLE_ENCRYPTION, p, 28);

		/* Peripheral replies to the LTK request (Vol 4 Part E 7.8.25). */
		le16enc(&p[0], ph);
		memcpy(&p[2], ltk, 16);
		feed_cmd(emu_peer, OP_LE_LTK_REQ_REPLY, p, 18);

		/* Both controllers report the link encrypted (7.7.8). */
		ATF_CHECK_EQ(BTPI_HCI_ENCRYPTION_ON,
		    hci_emu_get_conn_encrypted(emu_our, ch));
		ATF_CHECK_EQ(BTPI_HCI_ENCRYPTION_ON,
		    hci_emu_get_conn_encrypted(emu_peer, ph));
	}

	/*
	 * Core Vol 3 Part F §3.2.5 distinguishes encrypted access from
	 * authenticated (MITM-protected) access.  The chosen LTK encrypts this
	 * emulator link but carries no MITM provenance: open the ATT gate with
	 * key material, accept READ_ENCRYPT, and reject READ_AUTHEN with the
	 * independently assigned 0x05 error.
	 */
	memset(&ac, 0, sizeof(ac));
	ATF_REQUIRE(att_conn_apply_encryption(&ac, true, false, 16, 16));
	ATF_CHECK(ac.encrypted);
	ATF_CHECK(!ac.authenticated);
	memset(&attr, 0, sizeof(attr));
	attr.perms = ATT_PERM_READ_ENCRYPT;
	ATF_CHECK_EQ(0, att_check_read_perm(&attr, &ac));
	attr.perms = ATT_PERM_READ_AUTHEN;
	ATF_CHECK_EQ(BTPI_ATT_ERR_INSUFFICIENT_AUTHENTICATION,
	    att_check_read_perm(&attr, &ac));

	btpeer_free(bp);
	hci_emu_free(emu_our);
	hci_emu_free(emu_peer);
	(void)ph;
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* SERVER direction: btpeer client vs OUR att_server */
	ATF_TP_ADD_TC(tp, peer_exchange_mtu);
	ATF_TP_ADD_TC(tp, peer_discover_services);
	ATF_TP_ADD_TC(tp, peer_discover_chars);
	ATF_TP_ADD_TC(tp, peer_discover_descs);
	ATF_TP_ADD_TC(tp, peer_read_battery_level);
	ATF_TP_ADD_TC(tp, peer_read_device_name);
	ATF_TP_ADD_TC(tp, peer_write_vendor_char);
	ATF_TP_ADD_TC(tp, peer_write_readonly_rejected);
	ATF_TP_ADD_TC(tp, peer_read_invalid_handle);

	/* CLIENT direction: OUR att.c/gatt.c vs btpeer device fixtures */
	ATF_TP_ADD_TC(tp, our_exchange_mtu_with_peer);
	ATF_TP_ADD_TC(tp, our_read_peer_report_map);
	ATF_TP_ADD_TC(tp, our_write_peer_char);
	ATF_TP_ADD_TC(tp, our_read_peer_invalid_handle);
	ATF_TP_ADD_TC(tp, our_subscribe_peer_notifies);
	ATF_TP_ADD_TC(tp, our_receives_indication_confirms);
	ATF_TP_ADD_TC(tp, our_gatt_discover_keyboard);
	ATF_TP_ADD_TC(tp, our_keyboard_keystroke);
	ATF_TP_ADD_TC(tp, our_mouse_report_map);
	ATF_TP_ADD_TC(tp, our_mouse_movement);
	ATF_TP_ADD_TC(tp, our_read_battery_and_manuf);
	ATF_TP_ADD_TC(tp, our_battery_notification);

	/* Pairing + emulator encryption */
	ATF_TP_ADD_TC(tp, pair_legacy_just_works);
	ATF_TP_ADD_TC(tp, encrypted_link_security_gates);

	return (atf_no_error());
}
