/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * gatt_scenario_test.c - a gatt-tester-equivalent, end-to-end suite of GATT
 * procedures driving the REAL blued protocol code (att.c client,
 * att_server*.c server, gatt.c) against a hardware-free virtual remote peer
 * (btpeer.c) over an hci_emulator link.  No kernel, no netgraph, no radio.
 *
 * Two wiring directions are exercised, both copied from btpeer_test.c:
 *
 *   SERVER direction (no thread, fully synchronous): btpeer is the GATT
 *   CLIENT and OUR att_server is the code under test.  Each btpeer_gatt_*()
 *   round-trips inline through the emu link.  This is the primary, highest
 *   value direction and carries the bulk of the deep coverage.
 *
 *   CLIENT direction (pump thread): OUR att.c / gatt.c is the code under test
 *   and btpeer is the accessory server.  A pump thread bridges OUR blocking
 *   L2CAP socket to the emu link.
 *
 * SPEC ORACLE: every asserted PDU byte / outcome is hand-derived from the
 * Bluetooth Core Specification 6.3, Vol 3 Part F (ATT) and Part G (GATT),
 * with an inline citation at each assertion.  Nothing here captures the code
 * under test's own output as the expectation; a disagreement between a
 * spec-derived value and the stack is a finding about the stack.
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

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

/* Independent wire constants generated from the cited Core 6.3 tables. */
#define GATSCN_ENUM(name, value) GATSCN_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(GATSCN_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(GATSCN_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(GATSCN_ENUM)
};
#undef GATSCN_ENUM

/* Vol 4 Part E §§5.4.1 and 7.8.5, 7.8.10, 7.8.12. */
enum {
	GATSCN_HCI_COMMAND_PACKET = 0x01,
	GATSCN_HCI_ACL_DATA_PACKET = 0x02,
	GATSCN_ENABLE = 0x01,
	GATSCN_DISABLE = 0x00,
	GATSCN_PUBLIC_ADDRESS = 0x00,
	GATSCN_SCAN_INTERVAL = 0x0060,
	GATSCN_SCAN_WINDOW = 0x0030,
	GATSCN_CONN_INTERVAL = 0x0028,
	GATSCN_CONN_LATENCY = 0x0000,
	GATSCN_SUPERVISION_TIMEOUT = 0x00c8,
	GATSCN_ATT_FIXED_CID = 0x0004,
};

/* Core 6.3 Vol 3 Part C §11; Assigned Numbers, GAP Data Types. */
static const uint8_t gatt_scenario_flags_ad[] = {
	BT_CORE63_AD_TYPE_SIZE + 1,
	BT_ASSIGNED_AD_TYPE_FLAGS,
	BT_CSS12_FLAGS_LE_GENERAL_DISCOVERABLE_NO_BREDR,
};

/* Local database fixture UUIDs: deliberately not Bluetooth assignments. */
enum {
	GATSCN_FIXTURE_VENDOR_SERVICE = 0x1523,
	GATSCN_FIXTURE_VENDOR_CHARACTERISTIC = 0x1525,
	GATSCN_FIXTURE_ABSENT_UUID = 0x1234,
	GATSCN_FIXTURE_ABSENT_HANDLE = 0x00ff,
	GATSCN_FIXTURE_FAR_ABSENT_HANDLE = 0x7fff,
	GATSCN_HANDLE_MIN = 0x0001,
	GATSCN_HANDLE_MAX = 0xffff,
	GATSCN_EXECUTE_CANCEL = 0x00,
	GATSCN_EXECUTE_COMMIT = 0x01,
	/* att_server.h local capacity; Core defines the error, not this size. */
	GATSCN_LOCAL_PREPARE_QUEUE_CAPACITY = 16,
};

/* Sequential handles produced by gs_build_std(); these are fixture layout. */
enum {
	GS_GAP_SERVICE = 0x0001,
	GS_DEVICE_NAME_DECL = 0x0002,
	GS_DEVICE_NAME_VALUE = 0x0003,
	GS_BATTERY_SERVICE = 0x0004,
	GS_BATTERY_DECL = 0x0005,
	GS_BATTERY_VALUE = 0x0006,
	GS_BATTERY_CCCD = 0x0007,
	GS_VENDOR_SERVICE = 0x0008,
	GS_VENDOR_DECL = 0x0009,
	GS_VENDOR_VALUE = 0x000a,
};

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (smp.c is linked so its
 * dispatcher's smp_verify_signature is real; these three are its only
 * hardware touch points).  Mirrors btpeer_test.c / smp_pairing_test.c.
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = GATSCN_HCI_COMMAND_PACKET;
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

static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = GATSCN_HCI_COMMAND_PACKET;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/*
 * Establish an LE connection over the emu link (Vol 4 Part E 7.8.5/7.8.10/
 * 7.8.12): peripheral advertises connectable, central scans then creates the
 * connection.  Mirrors btpeer_test.c.
 */
static void
establish_conn(struct hci_emu *central, struct hci_emu *periph,
    const uint8_t caddr[6], const uint8_t paddr[6])
{
	uint8_t p[64];

	hci_emu_set_bd_addr(central, caddr);
	hci_emu_set_bd_addr(periph, paddr);

	p[0] = sizeof(gatt_scenario_flags_ad);
	memcpy(&p[1], gatt_scenario_flags_ad,
	    sizeof(gatt_scenario_flags_ad));
	feed_cmd(periph, OP_LE_SET_ADV_DATA, p,
	    (uint8_t)(1 + sizeof(gatt_scenario_flags_ad)));
	p[0] = GATSCN_ENABLE;
	feed_cmd(periph, OP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = GATSCN_ENABLE; p[1] = GATSCN_DISABLE;
	feed_cmd(central, OP_LE_SET_SCAN_ENABLE, p, 2);

	memset(p, 0, 25);
	le16enc(&p[0], GATSCN_SCAN_INTERVAL);
	le16enc(&p[2], GATSCN_SCAN_WINDOW);
	p[4] = GATSCN_DISABLE;
	p[5] = GATSCN_PUBLIC_ADDRESS;
	memcpy(&p[6], paddr, 6);
	p[12] = GATSCN_PUBLIC_ADDRESS;
	le16enc(&p[13], GATSCN_CONN_INTERVAL);
	le16enc(&p[15], GATSCN_CONN_INTERVAL);
	le16enc(&p[17], GATSCN_CONN_LATENCY);
	le16enc(&p[19], GATSCN_SUPERVISION_TIMEOUT);
	feed_cmd(central, OP_LE_CREATE_CONNECTION, p, 25);
}

/* Profile constants (BAS 1.0: Battery Level is a uint8 percentage). */
#define BATT_FULL	BT_GSS_BATTERY_LEVEL_FULL	/* GSS §3.30. */
#define BATT_DRAIN	(BATT_FULL - 1)	/* Local changed-value fixture: 99%. */
#define OUR_DEVNAME	"gatt-dut"

/* ================================================================
 * SERVER direction: OUR att_server behind emu A; btpeer is the client.
 * ================================================================ */
struct srv_harness {
	struct hci_emu	*emu;
	uint16_t	handle;
	struct att_conn	ac;
	struct att_db	db;
	int		bridge;
};

/* Feed one L2CAP B-frame to our emu on CID cid -> reaches btpeer. */
static void
srv_tx(struct srv_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = GATSCN_HCI_ACL_DATA_PACKET;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(h->handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu, pkt, (size_t)9 + plen);
}

/* Drain every pending response PDU from our server and forward to btpeer. */
static void
srv_flush(struct srv_harness *h)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	while ((n = recv(h->bridge, rsp, sizeof(rsp), MSG_DONTWAIT)) > 0)
		srv_tx(h, GATSCN_ATT_FIXED_CID, rsp, (uint16_t)n);
}

/* emu A output callback: an ATT request from btpeer arrived. */
static void
srv_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct srv_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != GATSCN_HCI_ACL_DATA_PACKET)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len || cid != GATSCN_ATT_FIXED_CID)
		return;

	att_server_handle(&h->ac, &h->db, &pkt[9], l2_len, -1, 0);
	srv_flush(h);
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
	bp = btpeer_new(emu_peer);
	ATF_REQUIRE(bp != NULL);

	establish_conn(emu_peer, emu_our, paddr, caddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(emu_our, 0, &h->handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(bp));

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

static void
srv_teardown(struct srv_harness *h)
{

	free(h->ac.buf);
	close(h->ac.fd);
	close(h->bridge);
}

/*
 * Build OUR server's standard attribute database.  Handles are deterministic
 * from insertion order (att_server.c allocates sequentially from 0x0001):
 *
 *   0x0001 GAP primary service (0x1800)
 *   0x0002 Device Name char decl (0x2A00, READ)         value handle 0x0003
 *   0x0003 Device Name value = "gatt-dut"
 *   0x0004 Battery primary service (0x180F)
 *   0x0005 Battery Level char decl (0x2A19, READ|NOTIFY) value handle 0x0006
 *   0x0006 Battery Level value = 0x64
 *   0x0007 CCCD (0x2902)
 *   0x0008 Vendor primary service (0x1523)
 *   0x0009 Vendor char decl (0x1525, READ|WRITE)         value handle 0x000A
 *   0x000A Vendor value = { 0,0,0,0 }  (value_maxlen 4)
 */
static struct att_attr gs_std_store[32];
static uint8_t gs_std_valbuf[1024];

static void
gs_build_std(struct att_db *db)
{
	static const uint8_t initval[4] = { 0, 0, 0, 0 };
	static const uint8_t batt = BATT_FULL;

	attdb_init(db, gs_std_store, 32, gs_std_valbuf, sizeof(gs_std_valbuf));
	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(db, BT_ASSIGNED_UUID_DEVICE_NAME,
	    GATSCN_GATT_PROP_READ, ATT_PERM_READ,
	    OUR_DEVNAME, (uint16_t)strlen(OUR_DEVNAME));
	attdb_add_service(db, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_NOTIFY,
	    ATT_PERM_READ, &batt, 1);
	attdb_add_cccd(db);
	attdb_add_service(db, GATSCN_FIXTURE_VENDOR_SERVICE);
	attdb_add_characteristic(db, GATSCN_FIXTURE_VENDOR_CHARACTERISTIC,
	    GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, initval, sizeof(initval));
}

/* ---------------- SERVER-direction: MTU + discovery ---------------- */

ATF_TC_WITHOUT_HEAD(srv_exchange_mtu);
ATF_TC_BODY(srv_exchange_mtu, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint16_t smtu = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);

	/* Exchange MTU (Vol 3 Part F 3.4.2.2): the server returns its own
	 * Server Rx MTU; the effective MTU is min(client,server). */
	ATF_CHECK_EQ(0, btpeer_gatt_exchange_mtu(bp, 100, &smtu));
	ATF_CHECK_EQ(ATT_PDU_BUF_SIZE, smtu);	/* server offers 517 */

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_discover_all_primary_services);
ATF_TC_BODY(srv_discover_all_primary_services, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_service svc[8];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Discover All Primary Services via Read By Group Type (Vol 3 Part G
	 * 4.4.1).  Group End Handle of each service = last handle before the
	 * next service declaration (Vol 3 Part G 3.1). */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_services(bp, svc, 8, &n));
	ATF_CHECK_EQ(3, n);
	ATF_CHECK_EQ(GS_GAP_SERVICE, svc[0].start);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE, svc[0].uuid16);
	ATF_CHECK_EQ(GS_DEVICE_NAME_VALUE, svc[0].end);
	ATF_CHECK_EQ(GS_BATTERY_SERVICE, svc[1].start);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_BATTERY_SERVICE, svc[1].uuid16);
	ATF_CHECK_EQ(GS_BATTERY_CCCD, svc[1].end);
	ATF_CHECK_EQ(GS_VENDOR_SERVICE, svc[2].start);
	ATF_CHECK_EQ(GATSCN_FIXTURE_VENDOR_SERVICE, svc[2].uuid16);
	ATF_CHECK_EQ(GS_VENDOR_VALUE, svc[2].end);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_discover_primary_by_uuid);
ATF_TC_BODY(srv_discover_primary_by_uuid, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_service svc[4];
	uint8_t uuid_le[2];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	le16enc(uuid_le, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Discover Primary Service by Service UUID via Find By Type Value
	 * (Vol 3 Part F 3.4.3.3 / Vol 3 Part G 4.4.2): Attribute Type =
	 * 0x2800, Attribute Value = the 16-bit service UUID.  The Battery
	 * service occupies handles 0x0004..0x0007. */
	ATF_CHECK_EQ(0, btpeer_gatt_find_by_type_value(bp, GS_GAP_SERVICE,
	    0xffff, BT_ASSIGNED_UUID_PRIMARY_SERVICE, uuid_le, 2, svc, 4, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(GS_BATTERY_SERVICE, svc[0].start);
	ATF_CHECK_EQ(GS_BATTERY_CCCD, svc[0].end);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_discover_primary_by_uuid_absent);
ATF_TC_BODY(srv_discover_primary_by_uuid_absent, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_service svc[4];
	uint8_t uuid_le[2];
	uint8_t code = 0;
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	le16enc(uuid_le, GATSCN_FIXTURE_ABSENT_UUID);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* No primary service carries UUID 0x1234 => Attribute Not Found
	 * (Vol 3 Part F 3.4.1.1 code 0x0A) and no matches. */
	ATF_CHECK_EQ(0, btpeer_gatt_find_by_type_value(bp, GS_GAP_SERVICE,
	    0xffff, BT_ASSIGNED_UUID_PRIMARY_SERVICE, uuid_le, 2, svc, 4, &n));
	ATF_CHECK_EQ(0, n);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_ATTR_NOT_FOUND, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_discover_all_characteristics);
ATF_TC_BODY(srv_discover_all_characteristics, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_char ch[8];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Discover All Characteristics of the Battery service via Read By Type
	 * over 0x2803 (Vol 3 Part G 4.6.1).  Declaration format (Vol 3 Part G
	 * 3.3.1): Properties(1) | Value Handle(2) | Characteristic UUID(2). */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_chars(bp, GS_BATTERY_SERVICE,
	    GS_BATTERY_CCCD, ch, 8,
	    &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(GS_BATTERY_DECL, ch[0].decl);
	ATF_CHECK_EQ(GS_BATTERY_VALUE, ch[0].value);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_BATTERY_LEVEL, ch[0].uuid16);
	ATF_CHECK_EQ(GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_NOTIFY,
	    ch[0].props);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_discover_descriptors);
ATF_TC_BODY(srv_discover_descriptors, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_desc d[8];
	int n = -1, i, found = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Discover All Characteristic Descriptors via Find Information (Vol 3
	 * Part G 4.7.1): the Battery Level CCCD (0x2902) sits at 0x0007. */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_descs(bp, GS_BATTERY_VALUE,
	    GS_BATTERY_CCCD, d, 8,
	    &n));
	for (i = 0; i < n; i++)
		if (d[i].uuid16 == BT_ASSIGNED_UUID_CCCD &&
		    d[i].handle == GS_BATTERY_CCCD)
			found = 1;
	ATF_CHECK_EQ(1, found);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_by_type_char_decls);
ATF_TC_BODY(srv_read_by_type_char_decls, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_rbt_rec rec[8];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Generic Read By Type over the Characteristic type 0x2803 (Vol 3
	 * Part F 3.4.4.1).  Each record: Attribute Handle | declaration value
	 * (Vol 3 Part G 3.3.1).  The first is the Device Name declaration at
	 * handle 0x0002: props READ(0x02) | value handle 0x0003 | UUID 0x2A00. */
	ATF_CHECK_EQ(0, btpeer_gatt_read_by_type(bp, GATSCN_HANDLE_MIN,
	    GATSCN_HANDLE_MAX, BT_ASSIGNED_UUID_CHARACTERISTIC,
	    rec, 8, &n));
	ATF_CHECK_EQ(3, n);
	ATF_CHECK_EQ(GS_DEVICE_NAME_DECL, rec[0].handle);
	ATF_REQUIRE_EQ(5, rec[0].vlen);
	ATF_CHECK_EQ(GATSCN_GATT_PROP_READ, rec[0].val[0]);
	ATF_CHECK_EQ(GS_DEVICE_NAME_VALUE, get_le16(&rec[0].val[1]));
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_DEVICE_NAME, get_le16(&rec[0].val[3]));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_using_char_uuid);
ATF_TC_BODY(srv_read_using_char_uuid, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_rbt_rec rec[4];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Using Characteristic UUID via Read By Type over 0x2A19 (Vol 3
	 * Part F 3.4.4.1): one record, value handle 0x0006, value = 0x64. */
	ATF_CHECK_EQ(0, btpeer_gatt_read_by_type(bp, GATSCN_HANDLE_MIN,
	    GATSCN_HANDLE_MAX, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    rec, 4, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(GS_BATTERY_VALUE, rec[0].handle);
	ATF_REQUIRE_EQ(1, rec[0].vlen);
	ATF_CHECK_EQ(BATT_FULL, rec[0].val[0]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: reads ---------------- */

ATF_TC_WITHOUT_HEAD(srv_read_characteristic_value);
ATF_TC_BODY(srv_read_characteristic_value, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[64];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Characteristic Value via Read Request (Vol 3 Part F 3.4.4.3). */
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_BATTERY_VALUE, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(BATT_FULL, buf[0]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_device_name);
ATF_TC_BODY(srv_read_device_name, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[64];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Request of the Device Name value handle 0x0003 (Vol 3 Part F
	 * 3.4.4.3). */
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_DEVICE_NAME_VALUE, buf,
	    sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(strlen(OUR_DEVNAME), outlen);
	ATF_CHECK_EQ(0, memcmp(buf, OUR_DEVNAME, outlen));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_long_blob);
ATF_TC_BODY(srv_read_long_blob, tc)
{
	static struct att_attr store[8];
	static uint8_t valbuf[256];
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t pattern[40], full[64], buf[64];
	size_t got0 = 0, got1 = 0;
	int i;

	for (i = 0; i < (int)sizeof(pattern); i++)
		pattern[i] = (uint8_t)(0xA0 + i);

	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 8, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, GATSCN_FIXTURE_VENDOR_SERVICE); /* 0x0001 */
	attdb_add_characteristic(&h.db, GATSCN_FIXTURE_VENDOR_CHARACTERISTIC,
	    GATSCN_GATT_PROP_READ,
	    ATT_PERM_READ, pattern, sizeof(pattern));		/* val 0x0003 */

	/* Read Long Characteristic Value (Vol 3 Part F 3.4.4.5).  With ATT_MTU
	 * = 23 a Read Response can carry at most ATT_MTU-1 = 22 value octets, so
	 * the 40-octet value pages as Read (22) then Read Blob @22 (18). */
	h.ac.mtu = 23;
	btpeer_set_mtu(bp, 23);

	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, 0x0003, full, sizeof(full),
	    &got0));
	ATF_REQUIRE_EQ(22, got0);
	ATF_CHECK_EQ(0, btpeer_gatt_read_blob(bp, 0x0003, 22, buf, sizeof(buf),
	    &got1));
	ATF_REQUIRE_EQ(18, got1);
	memcpy(full + 22, buf, got1);
	ATF_CHECK_EQ(0, memcmp(full, pattern, sizeof(pattern)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_blob_invalid_offset);
ATF_TC_BODY(srv_read_blob_invalid_offset, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[8], code = 0;
	size_t outlen = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Blob with a value offset greater than the attribute length must
	 * yield Invalid Offset (Vol 3 Part F 3.4.4.5, code 0x07).  The Battery
	 * Level value is a single octet; offset 5 is out of range. */
	rc = btpeer_gatt_read_blob(bp, 0x0006, 5, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_OFFSET, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_multiple);
ATF_TC_BODY(srv_read_multiple, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint16_t handles[2] = { GS_DEVICE_NAME_VALUE, GS_BATTERY_VALUE };
	uint8_t buf[64];
	size_t outlen = 0, namelen;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read Multiple Request (Vol 3 Part F 3.4.4.7): the response is the set
	 * of values concatenated with no separators, in request order. */
	namelen = strlen(OUR_DEVNAME);
	ATF_CHECK_EQ(0, btpeer_gatt_read_multiple(bp, handles, 2, buf,
	    sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(namelen + 1, outlen);
	ATF_CHECK_EQ(0, memcmp(buf, OUR_DEVNAME, namelen));
	ATF_CHECK_EQ(BATT_FULL, buf[namelen]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_multiple_invalid_handle);
ATF_TC_BODY(srv_read_multiple_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint16_t handles[2] = { GS_BATTERY_VALUE,
	    GATSCN_FIXTURE_ABSENT_HANDLE };
	uint8_t buf[64], code = 0;
	size_t outlen = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* A nonexistent handle in the set => Invalid Handle (Vol 3 Part F
	 * 3.4.4.7 / 3.4.1.1, code 0x01). */
	rc = btpeer_gatt_read_multiple(bp, handles, 2, buf, sizeof(buf),
	    &outlen);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_invalid_handle);
ATF_TC_BODY(srv_read_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[8], code = 0;
	size_t outlen = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Read of an unallocated handle => Invalid Handle (Vol 3 Part F
	 * 3.4.1.1, code 0x01). */
	rc = btpeer_gatt_read(bp, GATSCN_FIXTURE_ABSENT_HANDLE, buf,
	    sizeof(buf), &outlen);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_not_permitted);
ATF_TC_BODY(srv_read_not_permitted, tc)
{
	static struct att_attr store[8];
	static uint8_t valbuf[128];
	static const uint8_t v = 0x00;
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t buf[8], code = 0;
	size_t outlen = 0;
	int rc;

	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 8, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, GATSCN_FIXTURE_VENDOR_SERVICE); /* 0x0001 */
	/* A write-only value attribute (no READ permission bit). */
	attdb_add_characteristic(&h.db, GATSCN_FIXTURE_VENDOR_CHARACTERISTIC,
	    GATSCN_GATT_PROP_WRITE,
	    ATT_PERM_WRITE, &v, 1);				/* val 0x0003 */
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Reading an attribute without read permission => Read Not Permitted
	 * (Vol 3 Part F 3.4.1.1, code 0x02). */
	rc = btpeer_gatt_read(bp, 0x0003, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_READ_NOT_PERMITTED, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: writes ---------------- */

ATF_TC_WITHOUT_HEAD(srv_write_characteristic_value);
ATF_TC_BODY(srv_write_characteristic_value, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t newval[3] = { 0xAA, 0xBB, 0xCC };

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Write Characteristic Value via Write Request (Vol 3 Part F 3.4.5.1);
	 * a Write Response acknowledges and the value is stored. */
	ATF_CHECK_EQ(0, btpeer_gatt_write(bp, GS_VENDOR_VALUE, newval,
	    sizeof(newval)));
	a = attdb_find_by_handle(&h.db, GS_VENDOR_VALUE);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(sizeof(newval), a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, newval, sizeof(newval)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_write_without_response);
ATF_TC_BODY(srv_write_without_response, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t newval[2] = { 0x11, 0x22 };

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Write Without Response via Write Command 0x52 (Vol 3 Part F 3.4.5.3):
	 * no response PDU, but the server still applies the value. */
	ATF_CHECK_EQ(0, btpeer_gatt_write_cmd(bp, GS_VENDOR_VALUE, newval,
	    sizeof(newval)));
	a = attdb_find_by_handle(&h.db, GS_VENDOR_VALUE);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(sizeof(newval), a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, newval, sizeof(newval)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_write_cmd_readonly_ignored);
ATF_TC_BODY(srv_write_cmd_readonly_ignored, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t v = 0x00;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* A Write Command targeting a non-writable attribute is silently
	 * dropped: commands never generate an Error Response (Vol 3 Part F
	 * 3.4.5.3).  The read-only Battery Level (0x0006) keeps its value. */
	ATF_CHECK_EQ(0, btpeer_gatt_write_cmd(bp, GS_BATTERY_VALUE, &v, 1));
	a = attdb_find_by_handle(&h.db, GS_BATTERY_VALUE);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(1, a->value_len);
	ATF_CHECK_EQ(BATT_FULL, a->value[0]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_write_readonly_rejected);
ATF_TC_BODY(srv_write_readonly_rejected, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t code = 0, val = 0x11;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Write Request to the read-only Battery Level (0x0006) => Write Not
	 * Permitted (Vol 3 Part F 3.4.1.1, code 0x03). */
	rc = btpeer_gatt_write(bp, GS_BATTERY_VALUE, &val, 1);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_WRITE_NOT_PERMITTED, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_write_invalid_handle);
ATF_TC_BODY(srv_write_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t code = 0, val = 0x11;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Write Request to an unallocated handle => Invalid Handle (Vol 3
	 * Part F 3.4.1.1, code 0x01). */
	rc = btpeer_gatt_write(bp, GATSCN_FIXTURE_ABSENT_HANDLE, &val, 1);
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_write_invalid_attr_len);
ATF_TC_BODY(srv_write_invalid_attr_len, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint8_t toobig[5] = { 1, 2, 3, 4, 5 };
	uint8_t code = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* The vendor value has value_maxlen 4; a 5-octet Write Request exceeds
	 * it => Invalid Attribute Value Length (Vol 3 Part F 3.4.1.1, 0x0D). */
	rc = btpeer_gatt_write(bp, GS_VENDOR_VALUE, toobig, sizeof(toobig));
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_ATTR_LEN, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: reliable / long write ---------------- */

ATF_TC_WITHOUT_HEAD(srv_prepare_write_echo);
ATF_TC_BODY(srv_prepare_write_echo, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t part[2] = { 0xDE, 0xAD };
	uint8_t echo[8];
	uint16_t eh = 0, eo = 0xFFFF;
	size_t elen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Prepare Write Request (Vol 3 Part F 3.4.6.1): the Prepare Write
	 * Response must echo the Attribute Handle, Value Offset and Part
	 * Attribute Value exactly (Vol 3 Part F 3.4.6.2). */
	ATF_CHECK_EQ(0, btpeer_gatt_prepare_write(bp, GS_VENDOR_VALUE, 0, part,
	    sizeof(part)));
	ATF_REQUIRE_EQ(1, btpeer_last_prepare_echo(bp, &eh, &eo, echo,
	    sizeof(echo), &elen));
	ATF_CHECK_EQ(GS_VENDOR_VALUE, eh);
	ATF_CHECK_EQ(0, eo);
	ATF_REQUIRE_EQ(sizeof(part), elen);
	ATF_CHECK_EQ(0, memcmp(echo, part, sizeof(part)));

	/* Execute Write with flags 0x01 commits the queued value (3.4.6.3). */
	ATF_CHECK_EQ(0, btpeer_gatt_execute_write(bp, GATSCN_EXECUTE_COMMIT));
	a = attdb_find_by_handle(&h.db, GS_VENDOR_VALUE);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(0, memcmp(a->value, part, sizeof(part)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_reliable_long_write);
ATF_TC_BODY(srv_reliable_long_write, tc)
{
	static struct att_attr store[8];
	static uint8_t valbuf[256];
	static uint8_t init[40];
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	uint8_t data[40];
	int i;

	for (i = 0; i < 40; i++)
		data[i] = (uint8_t)(0x10 + i);

	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 8, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, GATSCN_FIXTURE_VENDOR_SERVICE); /* 0x0001 */
	attdb_add_characteristic(&h.db, GATSCN_FIXTURE_VENDOR_CHARACTERISTIC,
	    GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    init, sizeof(init));				/* val 0x0003 */

	/* Reliable Long Write (Vol 3 Part G 4.9.4/4.9.5): with ATT_MTU 23 the
	 * 40-octet value is split into (MTU-5)=18-octet Prepare Write parts,
	 * each echoed and verified, then one Execute Write (0x01) commits. */
	h.ac.mtu = 23;
	btpeer_set_mtu(bp, 23);
	ATF_CHECK_EQ(0, btpeer_gatt_write_long(bp, 0x0003, data, sizeof(data)));
	a = attdb_find_by_handle(&h.db, 0x0003);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(sizeof(data), a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, data, sizeof(data)));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_execute_write_cancel);
ATF_TC_BODY(srv_execute_write_cancel, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *a;
	const uint8_t part[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Queue a value part, then Execute Write with flags 0x00 (Vol 3 Part F
	 * 3.4.6.3): the queue is discarded and the attribute is unchanged. */
	ATF_CHECK_EQ(0, btpeer_gatt_prepare_write(bp, GS_VENDOR_VALUE, 0, part,
	    sizeof(part)));
	ATF_CHECK_EQ(0, btpeer_gatt_execute_write(bp, GATSCN_EXECUTE_CANCEL));
	a = attdb_find_by_handle(&h.db, GS_VENDOR_VALUE);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE_EQ(4, a->value_len);
	ATF_CHECK_EQ(0x00, a->value[0]);
	ATF_CHECK_EQ(0x00, a->value[1]);
	ATF_CHECK_EQ(0x00, a->value[2]);
	ATF_CHECK_EQ(0x00, a->value[3]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_prepare_write_not_permitted);
ATF_TC_BODY(srv_prepare_write_not_permitted, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint8_t part[2] = { 0x01, 0x02 };
	uint8_t code = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Prepare Write on the read-only Battery Level => Write Not Permitted
	 * (Vol 3 Part F 3.4.6.1 / 3.4.1.1, code 0x03). */
	rc = btpeer_gatt_prepare_write(bp, GS_BATTERY_VALUE, 0, part,
	    sizeof(part));
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_WRITE_NOT_PERMITTED, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_prepare_write_invalid_handle);
ATF_TC_BODY(srv_prepare_write_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint8_t part[2] = { 0x01, 0x02 };
	uint8_t code = 0;
	int rc;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Prepare Write on an unallocated handle => Invalid Handle (Vol 3
	 * Part F 3.4.1.1, code 0x01). */
	rc = btpeer_gatt_prepare_write(bp, GATSCN_FIXTURE_ABSENT_HANDLE, 0,
	    part, sizeof(part));
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_prepare_queue_full);
ATF_TC_BODY(srv_prepare_queue_full, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t code = 0;
	int i, rc = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* The local server prepare queue holds 16 entries (att_server.h).
	 * The 17th Prepare Write must be rejected with Prepare Queue Full
	 * (Vol 3 Part F 3.4.1.1, code 0x09). */
	for (i = 0; i < GATSCN_LOCAL_PREPARE_QUEUE_CAPACITY; i++) {
		uint8_t b = (uint8_t)i;

		ATF_REQUIRE_EQ(0, btpeer_gatt_prepare_write(bp, GS_VENDOR_VALUE,
		    (uint16_t)i, &b, 1));
	}
	{
		uint8_t b = 0xEE;

		rc = btpeer_gatt_prepare_write(bp, GS_VENDOR_VALUE,
		    GATSCN_LOCAL_PREPARE_QUEUE_CAPACITY, &b, 1);
	}
	ATF_CHECK_EQ(1, rc);
	ATF_REQUIRE_EQ(1, btpeer_last_att_error(bp, NULL, NULL, &code));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_PREPARE_QUEUE_FULL, code);

	/* Drain the queue so teardown leaves no dangling prepared state. */
	(void)btpeer_gatt_execute_write(bp, GATSCN_EXECUTE_CANCEL);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: included services ---------------- */

ATF_TC_WITHOUT_HEAD(srv_find_included_services);
ATF_TC_BODY(srv_find_included_services, tc)
{
	static struct att_attr store[12];
	static uint8_t valbuf[256];
	static const uint8_t batt = BATT_FULL;
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_rbt_rec rec[4];
	int n = -1;

	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 12, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	/* Include declaration (Vol 3 Part G 3.2) for the Battery service that
	 * will occupy handles 0x0003..0x0005; value = start | end | UUID. */
	attdb_add_include(&h.db, 0x0001, 0x0003, 0x0005,
	    BT_ASSIGNED_UUID_BATTERY_SERVICE);			/* 0x0002 */
	attdb_add_service(&h.db, BT_ASSIGNED_UUID_BATTERY_SERVICE); /* 0x0003 */
	attdb_add_characteristic(&h.db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GATSCN_GATT_PROP_READ,
	    ATT_PERM_READ, &batt, 1);				/* val 0x0005 */
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Find Included Services via Read By Type over the Include type 0x2802
	 * (Vol 3 Part G 4.5.1).  One record: include handle 0x0002, value =
	 * {0x0003, 0x0005, 0x180F} little-endian. */
	ATF_CHECK_EQ(0, btpeer_gatt_read_by_type(bp, GATSCN_HANDLE_MIN,
	    GATSCN_HANDLE_MAX, BT_ASSIGNED_UUID_INCLUDE,
	    rec, 4, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(0x0002, rec[0].handle);
	ATF_REQUIRE_EQ(6, rec[0].vlen);
	ATF_CHECK_EQ(0x03, rec[0].val[0]);	/* included start LE lo */
	ATF_CHECK_EQ(0x00, rec[0].val[1]);
	ATF_CHECK_EQ(0x05, rec[0].val[2]);	/* included end LE lo */
	ATF_CHECK_EQ(0x00, rec[0].val[3]);
	ATF_CHECK_EQ(0x0F, rec[0].val[4]);	/* UUID 0x180F LE lo */
	ATF_CHECK_EQ(0x18, rec[0].val[5]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: robust caching / DB hash ---------------- */

ATF_TC_WITHOUT_HEAD(srv_db_hash_changes_on_mutation);
ATF_TC_BODY(srv_db_hash_changes_on_mutation, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t hash1[16], hash2[16];

	srv_setup(&h, &bp);
	gs_build_std(&h.db);

	/* The Database Hash is AES-CMAC over the concatenation of the
	 * caching-relevant attributes (Vol 3 Part G 7.3.1).  Removing the
	 * Vendor service (0x0008) changes the attribute set, so the recomputed
	 * hash MUST differ -- that structural dependence is the spec property. */
	attdb_compute_db_hash(&h.db, hash1);
	ATF_REQUIRE_EQ(0, attdb_remove_service(&h.db, GS_VENDOR_SERVICE));
	attdb_compute_db_hash(&h.db, hash2);
	ATF_CHECK(memcmp(hash1, hash2, 16) != 0);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_database_hash_exposed);
ATF_TC_BODY(srv_database_hash_exposed, tc)
{
	static struct att_attr store[16];
	static uint8_t valbuf[256];
	static const uint8_t placeholder[16] = { 0 };
	static const uint8_t batt = BATT_FULL;
	struct srv_harness h;
	struct btpeer *bp;
	struct att_attr *hattr;
	struct btpeer_rbt_rec rec[4];
	uint8_t hash[16];
	int n = -1;

	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 16, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	/* Database Hash characteristic (Vol 3 Part G 7.3.1), value handle
	 * 0x0003; its value is excluded from the hash (is_char_value). */
	attdb_add_characteristic(&h.db, BT_ASSIGNED_UUID_DATABASE_HASH,
	    GATSCN_GATT_PROP_READ, ATT_PERM_READ,
	    placeholder, sizeof(placeholder));
	attdb_add_service(&h.db, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	attdb_add_characteristic(&h.db, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GATSCN_GATT_PROP_READ, ATT_PERM_READ,
	    &batt, 1);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Publish the computed hash as the characteristic value, then read it
	 * back over ATT.  The Read By Type response value MUST equal the
	 * computed Database Hash -- a consistency check of the exposed
	 * characteristic against attdb_compute_db_hash (Vol 3 Part G 7.3.1). */
	attdb_compute_db_hash(&h.db, hash);
	hattr = attdb_find_by_handle(&h.db, 0x0003);
	ATF_REQUIRE(hattr != NULL);
	memcpy(hattr->value, hash, 16);
	hattr->value_len = 16;

	ATF_CHECK_EQ(0, btpeer_gatt_read_by_type(bp, GATSCN_HANDLE_MIN,
	    GATSCN_HANDLE_MAX, BT_ASSIGNED_UUID_DATABASE_HASH,
	    rec, 4, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(0x0003, rec[0].handle);
	ATF_REQUIRE_EQ(16, rec[0].vlen);
	ATF_CHECK_EQ(0, memcmp(rec[0].val, hash, 16));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_service_changed_rediscover);
ATF_TC_BODY(srv_service_changed_rediscover, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct btpeer_service svc[8];
	int n = -1;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Before mutation the client discovers three primary services. */
	ATF_CHECK_EQ(0, btpeer_gatt_discover_services(bp, svc, 8, &n));
	ATF_CHECK_EQ(3, n);

	/* Remove the Vendor service (a topology change that a real server
	 * would signal with a Service Changed indication, Vol 3 Part G 2.5.2).
	 * A re-discovery now returns only the two surviving services. */
	ATF_REQUIRE_EQ(0, attdb_remove_service(&h.db, GS_VENDOR_SERVICE));
	n = -1;
	ATF_CHECK_EQ(0, btpeer_gatt_discover_services(bp, svc, 8, &n));
	ATF_CHECK_EQ(2, n);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE, svc[0].uuid16);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_BATTERY_SERVICE, svc[1].uuid16);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* Notification/indication capture for the peer-client callback. */
struct notif_cap {
	bool		got;
	uint16_t	handle;
	uint8_t		val[64];
	uint16_t	len;
	bool		ind;
};

static void
gs_notify_cb(void *arg, uint16_t handle, const uint8_t *value, uint16_t len,
    bool indication)
{
	struct notif_cap *c = arg;

	c->got = true;
	c->handle = handle;
	c->ind = indication;
	if (len > sizeof(c->val))
		len = sizeof(c->val);
	c->len = len;
	if (value != NULL && len != 0)
		memcpy(c->val, value, len);
}

ATF_TC_WITHOUT_HEAD(srv_service_changed_indication);
ATF_TC_BODY(srv_service_changed_indication, tc)
{
	static struct att_attr store[8];
	static uint8_t valbuf[128];
	static const uint8_t sc_init[4] = { 0, 0, 0, 0 };
	/* Affected Attribute Handle Range {0x0001, 0xFFFF} (Vol 3 Part G 7.1). */
	const uint8_t range[4] = { 0x01, 0x00, 0xFF, 0xFF };
	struct srv_harness h;
	struct btpeer *bp;
	struct notif_cap cap;

	memset(&cap, 0, sizeof(cap));
	srv_setup(&h, &bp);
	attdb_init(&h.db, store, 8, valbuf, sizeof(valbuf));
	attdb_add_service(&h.db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	/* Service Changed characteristic (0x2A05, INDICATE), value handle
	 * 0x0003 (Vol 3 Part G 7.1). */
	attdb_add_characteristic(&h.db, BT_ASSIGNED_UUID_SERVICE_CHANGED,
	    GATSCN_GATT_PROP_INDICATE,
	    ATT_PERM_READ, sc_init, sizeof(sc_init));
	attdb_add_cccd(&h.db);					/* 0x0004 */
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	btpeer_on_notify(bp, gs_notify_cb, &cap);

	/* The server issues a Handle Value Indication for the Service Changed
	 * value handle (Vol 3 Part F 3.4.7.2).  btpeer auto-confirms (0x1E)
	 * and surfaces the PDU: opcode 0x1D, handle 0x0003, 4-octet range. */
	ATF_REQUIRE_EQ(0, att_send_indication(&h.ac, 0x0003, range,
	    sizeof(range)));
	srv_flush(&h);

	ATF_CHECK(cap.got);
	ATF_CHECK(cap.ind);
	ATF_CHECK_EQ(0x0003, cap.handle);
	ATF_REQUIRE_EQ(4, cap.len);
	ATF_CHECK_EQ(0, memcmp(cap.val, range, 4));
	/* Client-side classification helper (Vol 3 Part G 2.5.2): a 4-octet
	 * indication on the Service Changed value handle IS Service Changed. */
	ATF_CHECK(gatt_indication_is_service_changed(0x0003, 0x0003, 4));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: Read Multiple Variable (EATT) --------- */

/*
 * Read Multiple Variable Request (Vol 3 Part F 3.4.4.11): the response is a
 * Length-Value tuple list — for each handle a 2-octet full value length (LE)
 * then that many value octets.  Reachable on the fixed ATT channel; exercises
 * handle_read_multiple_variable (att_server_dispatch.c).
 */
ATF_TC_WITHOUT_HEAD(srv_read_multiple_variable);
ATF_TC_BODY(srv_read_multiple_variable, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	/* Device Name (0x0003) = "gatt-dut", Battery Level (0x0006) = 0x64. */
	const uint16_t handles[2] = { GS_DEVICE_NAME_VALUE, GS_BATTERY_VALUE };
	uint8_t buf[64];
	size_t outlen = 0, nl = strlen(OUR_DEVNAME);

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	ATF_CHECK_EQ(0, btpeer_gatt_read_multiple_variable(bp, handles, 2,
	    buf, sizeof(buf), &outlen));
	/* tuple0: len(2)=8 | "gatt-dut"; tuple1: len(2)=1 | 0x64. */
	ATF_REQUIRE_EQ(2 + nl + 2 + 1, outlen);
	ATF_CHECK_EQ(nl, get_le16(buf));
	ATF_CHECK_EQ(0, memcmp(buf + 2, OUR_DEVNAME, nl));
	ATF_CHECK_EQ(1, get_le16(buf + 2 + nl));
	ATF_CHECK_EQ(BATT_FULL, buf[2 + nl + 2]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_read_multiple_variable_invalid_handle);
ATF_TC_BODY(srv_read_multiple_variable_invalid_handle, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint16_t handles[2] = { GS_DEVICE_NAME_VALUE,
	    GATSCN_FIXTURE_FAR_ABSENT_HANDLE };
	uint8_t buf[64], code = 0;
	uint16_t ehandle = 0;
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);

	/* Vol 3 Part F 3.4.4.11: a nonexistent handle => Error Response with
	 * Invalid Handle (0x01) naming the offending handle. */
	ATF_CHECK_EQ(1, btpeer_gatt_read_multiple_variable(bp, handles, 2,
	    buf, sizeof(buf), &outlen));
	ATF_REQUIRE(btpeer_last_att_error(bp, NULL, &ehandle, &code));
	ATF_CHECK_EQ(GATSCN_FIXTURE_FAR_ABSENT_HANDLE, ehandle);
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, code);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: Multiple Handle Value NTF (0x23) ------- */

struct multi_cap {
	int		n;
	uint16_t	handle[4];
	uint8_t		val[4][32];
	uint16_t	len[4];
};

static void
gs_multi_cb(void *arg, uint16_t handle, const uint8_t *value, uint16_t len,
    bool indication)
{
	struct multi_cap *c = arg;

	if (indication || c->n >= 4)	/* 0x23 tuples are never indications */
		return;
	c->handle[c->n] = handle;
	if (len > sizeof(c->val[0]))
		len = sizeof(c->val[0]);
	c->len[c->n] = len;
	if (value != NULL && len != 0)
		memcpy(c->val[c->n], value, len);
	c->n++;
}

/*
 * Multiple Handle Value Notification (Vol 3 Part F 3.4.7.4): OUR server emits a
 * single 0x23 PDU carrying two {handle,length,value} tuples; btpeer surfaces
 * one callback per tuple, each a notification (not an indication).
 */
ATF_TC_WITHOUT_HEAD(srv_multi_handle_value_ntf);
ATF_TC_BODY(srv_multi_handle_value_ntf, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	struct multi_cap cap;
	const uint8_t v0[2] = { 0xAA, 0xBB };
	const uint8_t v1[1] = { 0x64 };
	const uint16_t handles[2] = { GS_DEVICE_NAME_VALUE, GS_BATTERY_VALUE };
	const uint8_t *values[2] = { v0, v1 };
	const uint16_t lengths[2] = { 2, 1 };

	memset(&cap, 0, sizeof(cap));
	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	btpeer_on_notify(bp, gs_multi_cb, &cap);

	ATF_REQUIRE_EQ(0, att_send_multiple_handle_value_ntf(&h.ac, handles,
	    values, lengths, 2));
	srv_flush(&h);

	ATF_REQUIRE_EQ(2, cap.n);
	ATF_CHECK_EQ(GS_DEVICE_NAME_VALUE, cap.handle[0]);
	ATF_REQUIRE_EQ(2, cap.len[0]);
	ATF_CHECK_EQ(0, memcmp(cap.val[0], v0, 2));
	ATF_CHECK_EQ(GS_BATTERY_VALUE, cap.handle[1]);
	ATF_REQUIRE_EQ(1, cap.len[1]);
	ATF_CHECK_EQ(0x64, cap.val[1][0]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ---------------- SERVER-direction: Signed Write Command (0xD2) ------------ */

/* Fixed peer CSRK (little-endian wire order) shared by test + btpeer. */
static const uint8_t gs_peer_csrk[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
};

/*
 * Signed Write Command (Vol 3 Part F 3.4.5.4, signing Vol 3 Part H 2.4.5):
 * a valid AES-CMAC signature over the message + sign counter using the peer's
 * CSRK is verified by OUR server, which then applies the write.  Exercises the
 * ATT_OP_LEGACY_SIGNED_WRITE_CMD arm + smp_verify_signature end to end.
 */
ATF_TC_WITHOUT_HEAD(srv_signed_write_verified);
ATF_TC_BODY(srv_signed_write_verified, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint8_t newval[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint8_t buf[16];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	/* OUR side received this CSRK during pairing key distribution. */
	memcpy(h.ac.peer_csrk, gs_peer_csrk, 16);
	h.ac.has_peer_csrk = true;

	/* Signed write to the vendor R/W value handle 0x000A, counter 10. */
	ATF_CHECK_EQ(0, btpeer_gatt_signed_write(bp, GS_VENDOR_VALUE, newval,
	    sizeof(newval), gs_peer_csrk, 10));

	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_VENDOR_VALUE, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(0, memcmp(buf, newval, 4));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_signed_write_bad_signature);
ATF_TC_BODY(srv_signed_write_bad_signature, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t wrong_csrk[16];
	const uint8_t newval[4] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t buf[16];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	memcpy(h.ac.peer_csrk, gs_peer_csrk, 16);
	h.ac.has_peer_csrk = true;

	/* Sign with a DIFFERENT CSRK: signature must fail, write is dropped. */
	memcpy(wrong_csrk, gs_peer_csrk, 16);
	wrong_csrk[0] ^= 0xFF;
	ATF_CHECK_EQ(0, btpeer_gatt_signed_write(bp, GS_VENDOR_VALUE, newval,
	    sizeof(newval), wrong_csrk, 20));

	/* Value unchanged (still the initial {0,0,0,0}). */
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_VENDOR_VALUE, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(0, buf[0] | buf[1] | buf[2] | buf[3]);

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(srv_signed_write_replay);
ATF_TC_BODY(srv_signed_write_replay, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	const uint8_t v1[4] = { 0x01, 0x02, 0x03, 0x04 };
	const uint8_t v2[4] = { 0x0A, 0x0B, 0x0C, 0x0D };
	uint8_t buf[16];
	size_t outlen = 0;

	srv_setup(&h, &bp);
	gs_build_std(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	memcpy(h.ac.peer_csrk, gs_peer_csrk, 16);
	h.ac.has_peer_csrk = true;

	/* First signed write with counter 10 is accepted. */
	ATF_CHECK_EQ(0, btpeer_gatt_signed_write(bp, GS_VENDOR_VALUE, v1,
	    sizeof(v1),
	    gs_peer_csrk, 10));
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_VENDOR_VALUE, buf, sizeof(buf),
	    &outlen));
	ATF_CHECK_EQ(0, memcmp(buf, v1, 4));

	/* Replay: a well-signed PDU reusing counter 10 must be dropped
	 * (Vol 3 Part H 2.4.5 replay protection): value stays v1. */
	ATF_CHECK_EQ(0, btpeer_gatt_signed_write(bp, GS_VENDOR_VALUE, v2,
	    sizeof(v2),
	    gs_peer_csrk, 10));
	ATF_CHECK_EQ(0, btpeer_gatt_read(bp, GS_VENDOR_VALUE, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(0, memcmp(buf, v1, 4));

	srv_teardown(&h);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

/* ================================================================
 * CLIENT direction: OUR att.c/gatt.c behind emu A; btpeer is the server.
 * A pump thread bridges OUR blocking socket to the emu link.
 * ================================================================ */
struct cli_harness {
	struct hci_emu	*emu;
	uint16_t	handle;
	struct btpeer	*bp;
	int		att_bridge;
	int		ctrl_r, ctrl_w;
	pthread_t	thr;
	bool		running;
};

enum pump_cmd_type { PUMP_STOP, PUMP_NOTIFY, PUMP_INDICATE };
struct pump_cmd {
	enum pump_cmd_type type;
	uint16_t	handle;
	uint8_t		val[64];
	uint16_t	len;
};

static void
cli_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cli_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != GATSCN_HCI_ACL_DATA_PACKET)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == GATSCN_ATT_FIXED_CID)
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
}

static void
cli_feed(struct cli_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = GATSCN_HCI_ACL_DATA_PACKET;
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
	struct pollfd pfd[2];

	for (;;) {
		int nf = 0, i;

		pfd[nf].fd = h->att_bridge;
		pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->ctrl_r;
		pfd[nf].events = POLLIN; nf++;
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
					cli_feed(h, GATSCN_ATT_FIXED_CID, buf,
					    (uint16_t)n);
			}
		}
	}
}

static void
cli_setup(struct cli_harness *h, struct btpeer **bp_out, int *our_att_fd)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	struct hci_emu *emu_our, *emu_peer;
	struct btpeer *bp;
	int att_fds[2], ctrl[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

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

static void
cli_att_conn(struct att_conn *ac, int fd)
{

	memset(ac, 0, sizeof(*ac));
	ac->fd = fd;
	ac->bearer_fd = -1;
	ac->mtu = BT_CORE63_ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
}

/*
 * Reusable btpeer sensor server: Battery Service (0x180F) with a notifiable
 * Battery Level + CCCD, and a Device Information Service (0x180A) with a
 * Manufacturer Name String.  Returns the value/CCCD handles the tests need.
 * Handles are deterministic:
 *   0x0001 Battery svc | 0x0002 decl | 0x0003 level | 0x0004 CCCD
 *   0x0005 DIS svc     | 0x0006 decl | 0x0007 manuf name
 */
static const char DIS_MANUF[] = "ACME";

static void
peer_build_sensor(struct btpeer *bp, uint16_t *batt_val, uint16_t *batt_cccd,
    uint16_t *manuf)
{
	static const uint8_t lvl = BATT_FULL;
	uint16_t bv, cc, mn;

	btpeer_add_service(bp, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	bv = btpeer_add_characteristic(bp, BT_ASSIGNED_UUID_BATTERY_LEVEL,
	    GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_NOTIFY,
	    BTPEER_PERM_READ, &lvl, 1);
	cc = btpeer_add_cccd(bp);
	btpeer_add_service(bp, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	mn = btpeer_add_characteristic(bp,
	    BT_ASSIGNED_UUID_MANUFACTURER_NAME_STRING, GATSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, DIS_MANUF, (uint16_t)strlen(DIS_MANUF));
	if (batt_val != NULL)
		*batt_val = bv;
	if (batt_cccd != NULL)
		*batt_cccd = cc;
	if (manuf != NULL)
		*manuf = mn;
}

/* A btpeer writable vendor value (service 0x1523, char 0x1525). */
static uint16_t
peer_add_vendor(struct btpeer *bp, uint16_t initlen)
{
	static uint8_t zero[64];

	memset(zero, 0, sizeof(zero));
	btpeer_add_service(bp, GATSCN_FIXTURE_VENDOR_SERVICE);
	return (btpeer_add_characteristic(bp,
	    GATSCN_FIXTURE_VENDOR_CHARACTERISTIC,
	    GATSCN_GATT_PROP_READ | GATSCN_GATT_PROP_WRITE,
	    BTPEER_PERM_READ | BTPEER_PERM_WRITE, zero, initlen));
}

/* ---------------- CLIENT-direction scenarios ---------------- */

ATF_TC_WITHOUT_HEAD(cli_exchange_mtu);
ATF_TC_BODY(cli_exchange_mtu, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	int fd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	cli_start(&h);

	/* OUR att_exchange_mtu (Vol 3 Part F 3.4.2.2): effective = min(247,100). */
	ATF_CHECK_EQ(0, att_exchange_mtu(&ac, 247));
	ATF_CHECK_EQ(100, ac.mtu);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_discover_primary_services);
ATF_TC_BODY(cli_discover_primary_services, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	struct gatt_service svcs[GATT_MAX_SERVICES];
	int fd, nsvc = -1, i;
	bool batt = false, dis = false;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR gatt.c Discover All Primary Services (Vol 3 Part G 4.4.1). */
	ATF_REQUIRE_EQ(0, gatt_discover_primary_services(&ac, svcs,
	    GATT_MAX_SERVICES, &nsvc));
	for (i = 0; i < nsvc; i++) {
		if (svcs[i].uuid16 == BT_ASSIGNED_UUID_BATTERY_SERVICE)
			batt = true;
		if (svcs[i].uuid16 == BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE)
			dis = true;
	}
	ATF_CHECK(batt);
	ATF_CHECK(dis);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_discover_primary_by_uuid);
ATF_TC_BODY(cli_discover_primary_by_uuid, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	struct gatt_service svcs[4];
	int fd, n = -1;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR Discover Primary Service by Service UUID (Vol 3 Part G 4.4.2):
	 * the Battery service spans handles 0x0001..0x0004. */
	ATF_REQUIRE_EQ(0, gatt_discover_primary_service_by_uuid(&ac,
	    BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 4, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(BT_ASSIGNED_UUID_BATTERY_SERVICE, svcs[0].uuid16);
	ATF_CHECK_EQ(0x0001, svcs[0].start_handle);
	ATF_CHECK_EQ(0x0004, svcs[0].end_handle);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_discover_characteristics);
ATF_TC_BODY(cli_discover_characteristics, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	struct gatt_char chars[GATT_MAX_CHARS];
	uint16_t batt_val = 0;
	int fd, nch = -1, i;
	bool found = false;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR Discover All Characteristics over the Battery service group
	 * 0x0001..0x0004 (Vol 3 Part G 4.6.1). */
	ATF_REQUIRE_EQ(0, gatt_discover_characteristics(&ac, 0x0001, 0x0004,
	    chars, GATT_MAX_CHARS, &nch));
	for (i = 0; i < nch; i++)
		if (chars[i].uuid16 == BT_ASSIGNED_UUID_BATTERY_LEVEL &&
		    chars[i].value_handle == batt_val)
			found = true;
	ATF_CHECK(found);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_discover_descriptors);
ATF_TC_BODY(cli_discover_descriptors, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	struct gatt_desc descs[GATT_MAX_DESCS];
	int fd, nd = -1, i;
	bool cccd = false;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR Discover All Characteristic Descriptors via Find Information over
	 * the Battery Level range 0x0003..0x0004 (Vol 3 Part G 4.7.1): the CCCD
	 * (0x2902) sits at 0x0004. */
	ATF_REQUIRE_EQ(0, gatt_discover_descriptors(&ac, 0x0003, 0x0004, descs,
	    GATT_MAX_DESCS, &nd));
	for (i = 0; i < nd; i++)
		if (descs[i].uuid16 == BT_ASSIGNED_UUID_CCCD)
			cccd = true;
	ATF_CHECK(cccd);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_read_characteristic_value);
ATF_TC_BODY(cli_read_characteristic_value, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t batt_val = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_read of the Battery Level (Vol 3 Part F 3.4.4.3). */
	ATF_CHECK_EQ(0, att_read(&ac, batt_val, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	ATF_CHECK_EQ(BATT_FULL, buf[0]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_read_using_char_uuid);
ATF_TC_BODY(cli_read_using_char_uuid, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t batt_val = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_read_by_type over 0x2A19 (Vol 3 Part F 3.4.4.1): the payload
	 * is Length | { handle(2) | value } records.  One value octet => record
	 * length 3, handle = Battery Level value handle, value = 0x64. */
	ATF_CHECK_EQ(0, att_read_by_type(&ac, GATSCN_HANDLE_MIN,
	    GATSCN_HANDLE_MAX, BT_ASSIGNED_UUID_BATTERY_LEVEL, buf,
	    sizeof(buf), &outlen));
	ATF_REQUIRE(outlen >= 4);
	ATF_CHECK_EQ(3, buf[0]);			/* record length */
	ATF_CHECK_EQ(batt_val, get_le16(buf + 1));
	ATF_CHECK_EQ(BATT_FULL, buf[3]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_read_long_blob);
ATF_TC_BODY(cli_read_long_blob, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint8_t pattern[40], full[64], buf[64];
	uint16_t val;
	size_t got0 = 0, got1 = 0;
	int fd, i;

	for (i = 0; i < (int)sizeof(pattern); i++)
		pattern[i] = (uint8_t)(0x30 + i);

	cli_setup(&h, &bp, &fd);
	btpeer_add_service(bp, GATSCN_FIXTURE_VENDOR_SERVICE);
	val = btpeer_add_characteristic(bp,
	    GATSCN_FIXTURE_VENDOR_CHARACTERISTIC, GATSCN_GATT_PROP_READ,
	    BTPEER_PERM_READ, pattern, sizeof(pattern));
	btpeer_set_mtu(bp, 23);
	cli_att_conn(&ac, fd);
	ac.mtu = 23;
	cli_start(&h);

	/* OUR Read Long Characteristic Value (Vol 3 Part F 3.4.4.5): att_read
	 * returns the first ATT_MTU-1 = 22 octets; att_read_blob @22 returns
	 * the remaining 18; the concatenation is the full 40-octet value. */
	ATF_CHECK_EQ(0, att_read(&ac, val, full, sizeof(full), &got0));
	ATF_REQUIRE_EQ(22, got0);
	ATF_CHECK_EQ(0, att_read_blob(&ac, val, 22, buf, sizeof(buf), &got1));
	ATF_REQUIRE_EQ(18, got1);
	memcpy(full + 22, buf, got1);
	ATF_CHECK_EQ(0, memcmp(full, pattern, sizeof(pattern)));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_read_multiple);
ATF_TC_BODY(cli_read_multiple, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t batt_val = 0, manuf = 0, handles[2];
	uint8_t buf[32];
	size_t outlen = 0, mlen;
	int fd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, NULL, &manuf);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_read_multiple (Vol 3 Part F 3.4.4.7): the response is the set
	 * of values concatenated in request order -> Battery Level (1) then
	 * Manufacturer Name ("ACME"). */
	handles[0] = batt_val;
	handles[1] = manuf;
	mlen = strlen(DIS_MANUF);
	ATF_CHECK_EQ(0, att_read_multiple(&ac, handles, 2, buf, sizeof(buf),
	    &outlen));
	ATF_REQUIRE_EQ(1 + mlen, outlen);
	ATF_CHECK_EQ(BATT_FULL, buf[0]);
	ATF_CHECK_EQ(0, memcmp(buf + 1, DIS_MANUF, mlen));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_write_characteristic_value);
ATF_TC_BODY(cli_write_characteristic_value, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t vendor;
	uint8_t stored[8];
	size_t slen = 0;
	const uint8_t data[2] = { 0x5A, 0xA5 };
	int fd;

	cli_setup(&h, &bp, &fd);
	vendor = peer_add_vendor(bp, 8);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_write_req to the peer's writable value (Vol 3 Part F 3.4.5.1). */
	ATF_CHECK_EQ(0, att_write_req(&ac, vendor, data, sizeof(data)));

	cli_stop(&h);
	ATF_CHECK_EQ(0, btpeer_get_value(bp, vendor, stored, sizeof(stored),
	    &slen));
	ATF_REQUIRE_EQ(sizeof(data), slen);
	ATF_CHECK_EQ(0, memcmp(stored, data, sizeof(data)));

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_write_without_response);
ATF_TC_BODY(cli_write_without_response, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t vendor;
	uint8_t stored[8];
	size_t slen = 0;
	const uint8_t data[3] = { 0x01, 0x02, 0x03 };
	int fd;

	cli_setup(&h, &bp, &fd);
	vendor = peer_add_vendor(bp, 8);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_write_cmd (Write Command 0x52, Vol 3 Part F 3.4.5.3): no
	 * response, but the peer applies the value. */
	ATF_CHECK_EQ(0, att_write_cmd(&ac, vendor, data, sizeof(data)));

	cli_stop(&h);	/* pump idle: the command has been consumed */
	ATF_CHECK_EQ(0, btpeer_get_value(bp, vendor, stored, sizeof(stored),
	    &slen));
	ATF_REQUIRE_EQ(sizeof(data), slen);
	ATF_CHECK_EQ(0, memcmp(stored, data, sizeof(data)));

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_reliable_long_write);
ATF_TC_BODY(cli_reliable_long_write, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t vendor;
	uint8_t data[40], stored[64];
	size_t slen = 0;
	int fd, i;

	for (i = 0; i < 40; i++)
		data[i] = (uint8_t)(0x50 + i);

	cli_setup(&h, &bp, &fd);
	vendor = peer_add_vendor(bp, sizeof(data));	/* value cap 40 */
	btpeer_set_mtu(bp, 23);
	cli_att_conn(&ac, fd);
	ac.mtu = 23;
	cli_start(&h);

	/* OUR att_write_long (Reliable/Long Write, Vol 3 Part G 4.9.4/4.9.5):
	 * chained Prepare Writes of (MTU-5)=18 octets, each echo verified by
	 * att_prepare_write, then one Execute Write commits the 40 octets. */
	ATF_CHECK_EQ(0, att_write_long(&ac, vendor, data, sizeof(data)));

	cli_stop(&h);
	ATF_CHECK_EQ(0, btpeer_get_value(bp, vendor, stored, sizeof(stored),
	    &slen));
	ATF_REQUIRE_EQ(sizeof(data), slen);
	ATF_CHECK_EQ(0, memcmp(stored, data, sizeof(data)));

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_prepare_execute_write);
ATF_TC_BODY(cli_prepare_execute_write, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t vendor;
	uint8_t stored[8];
	size_t slen = 0;
	const uint8_t part[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
	int fd;

	cli_setup(&h, &bp, &fd);
	/*
	 * Size the peer value to the part length: Execute Write applies queued
	 * parts in place and does not shrink the attribute (Vol 3 Part F
	 * 3.4.6.3), so an over-long initial value would leave trailing octets.
	 */
	vendor = peer_add_vendor(bp, sizeof(part));
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* OUR att_prepare_write then att_execute_write(0x01) (Vol 3 Part F
	 * 3.4.6.1 / 3.4.6.3).  att_prepare_write verifies the server echoes the
	 * handle, offset and value; Execute commits. */
	ATF_CHECK_EQ(0, att_prepare_write(&ac, vendor, 0, part, sizeof(part)));
	ATF_CHECK_EQ(0, att_execute_write(&ac, GATSCN_EXECUTE_COMMIT));

	cli_stop(&h);
	ATF_CHECK_EQ(0, btpeer_get_value(bp, vendor, stored, sizeof(stored),
	    &slen));
	ATF_REQUIRE_EQ(sizeof(part), slen);
	ATF_CHECK_EQ(0, memcmp(stored, part, sizeof(part)));

	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_notification);
ATF_TC_BODY(cli_notification, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t batt_val = 0, batt_cccd = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, &batt_cccd, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Subscribe: Write Request CCCD = 0x0001 (Vol 3 Part G 3.3.3.3). */
	{
		uint8_t v[2];

		le16enc(v, BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);

		ATF_CHECK_EQ(0, att_write_req(&ac, batt_cccd, v, 2));
	}

	/* Post the notification only after the Write Response has drained so
	 * the two PDUs are not coalesced by AF_UNIX SOCK_SEQPACKET. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_NOTIFY;
	cmd.handle = batt_val;
	cmd.val[0] = BATT_DRAIN;
	cmd.len = 1;
	cli_post(&h, &cmd);

	/* OUR client surfaces the Handle Value Notification (Vol 3 Part F
	 * 3.4.7.1): opcode 0x1B | handle | value. */
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(GATSCN_ATT_OP_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(batt_val, get_le16(buf + 1));
	ATF_CHECK_EQ(BATT_DRAIN, buf[3]);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_indication_confirm);
ATF_TC_BODY(cli_indication_confirm, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t batt_val = 0;
	uint8_t buf[32];
	size_t outlen = 0;
	int fd;
	struct pump_cmd cmd;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, &batt_val, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Peer sends a Handle Value Indication (Vol 3 Part F 3.4.7.2). */
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PUMP_INDICATE;
	cmd.handle = batt_val;
	cmd.val[0] = BATT_DRAIN;
	cmd.len = 1;
	cli_post(&h, &cmd);

	/* OUR side surfaces it (opcode 0x1D) and returns a Confirmation
	 * (0x1E, Vol 3 Part F 3.4.7.3). */
	ATF_CHECK_EQ(0, att_recv(&ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(4, outlen);
	ATF_CHECK_EQ(GATSCN_ATT_OP_HANDLE_IND, buf[0]);
	ATF_CHECK_EQ(batt_val, get_le16(buf + 1));
	ATF_CHECK_EQ(0, att_confirm(&ac));

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_read_invalid_handle);
ATF_TC_BODY(cli_read_invalid_handle, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint8_t buf[8];
	size_t outlen = 0;
	int fd, rc;

	cli_setup(&h, &bp, &fd);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Reading an absent handle: att.c maps the ATT Error Response to its
	 * code => Invalid Handle 0x01 (Vol 3 Part F 3.4.1.1). */
	rc = att_read(&ac, 0x0FFF, buf, sizeof(buf), &outlen);
	ATF_CHECK_EQ(GATSCN_ATT_ERR_INVALID_HANDLE, rc);

	cli_stop(&h);
	free(ac.buf);
	close(fd);
	btpeer_free(bp);
	hci_emu_free(h.emu);
}

ATF_TC_WITHOUT_HEAD(cli_write_not_permitted);
ATF_TC_BODY(cli_write_not_permitted, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t svc;
	const uint8_t data[2] = { 0xAA, 0xBB };
	int fd, rc;

	cli_setup(&h, &bp, &fd);
	svc = btpeer_add_service(bp, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	peer_build_sensor(bp, NULL, NULL, NULL);
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd);
	ac.mtu = 100;
	cli_start(&h);

	/* Writing a read-only attribute (a Primary Service declaration) =>
	 * Write Not Permitted 0x03 (Vol 3 Part F 3.4.1.1). */
	rc = att_write_req(&ac, svc, data, sizeof(data));
	ATF_CHECK_EQ(GATSCN_ATT_ERR_WRITE_NOT_PERMITTED, rc);

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

	/* SERVER direction: btpeer client vs OUR att_server (synchronous) */
	ATF_TP_ADD_TC(tp, srv_exchange_mtu);
	ATF_TP_ADD_TC(tp, srv_discover_all_primary_services);
	ATF_TP_ADD_TC(tp, srv_discover_primary_by_uuid);
	ATF_TP_ADD_TC(tp, srv_discover_primary_by_uuid_absent);
	ATF_TP_ADD_TC(tp, srv_discover_all_characteristics);
	ATF_TP_ADD_TC(tp, srv_discover_descriptors);
	ATF_TP_ADD_TC(tp, srv_read_by_type_char_decls);
	ATF_TP_ADD_TC(tp, srv_read_using_char_uuid);
	ATF_TP_ADD_TC(tp, srv_read_characteristic_value);
	ATF_TP_ADD_TC(tp, srv_read_device_name);
	ATF_TP_ADD_TC(tp, srv_read_long_blob);
	ATF_TP_ADD_TC(tp, srv_read_blob_invalid_offset);
	ATF_TP_ADD_TC(tp, srv_read_multiple);
	ATF_TP_ADD_TC(tp, srv_read_multiple_invalid_handle);
	ATF_TP_ADD_TC(tp, srv_read_invalid_handle);
	ATF_TP_ADD_TC(tp, srv_read_not_permitted);
	ATF_TP_ADD_TC(tp, srv_write_characteristic_value);
	ATF_TP_ADD_TC(tp, srv_write_without_response);
	ATF_TP_ADD_TC(tp, srv_write_cmd_readonly_ignored);
	ATF_TP_ADD_TC(tp, srv_write_readonly_rejected);
	ATF_TP_ADD_TC(tp, srv_write_invalid_handle);
	ATF_TP_ADD_TC(tp, srv_write_invalid_attr_len);
	ATF_TP_ADD_TC(tp, srv_prepare_write_echo);
	ATF_TP_ADD_TC(tp, srv_reliable_long_write);
	ATF_TP_ADD_TC(tp, srv_execute_write_cancel);
	ATF_TP_ADD_TC(tp, srv_prepare_write_not_permitted);
	ATF_TP_ADD_TC(tp, srv_prepare_write_invalid_handle);
	ATF_TP_ADD_TC(tp, srv_prepare_queue_full);
	ATF_TP_ADD_TC(tp, srv_find_included_services);
	ATF_TP_ADD_TC(tp, srv_db_hash_changes_on_mutation);
	ATF_TP_ADD_TC(tp, srv_database_hash_exposed);
	ATF_TP_ADD_TC(tp, srv_service_changed_rediscover);
	ATF_TP_ADD_TC(tp, srv_service_changed_indication);
	/* EATT Read Multiple Variable + multi-notify + Signed Write (0xD2). */
	ATF_TP_ADD_TC(tp, srv_read_multiple_variable);
	ATF_TP_ADD_TC(tp, srv_read_multiple_variable_invalid_handle);
	ATF_TP_ADD_TC(tp, srv_multi_handle_value_ntf);
	ATF_TP_ADD_TC(tp, srv_signed_write_verified);
	ATF_TP_ADD_TC(tp, srv_signed_write_bad_signature);
	ATF_TP_ADD_TC(tp, srv_signed_write_replay);

	/* CLIENT direction: OUR att.c/gatt.c vs btpeer accessory server */
	ATF_TP_ADD_TC(tp, cli_exchange_mtu);
	ATF_TP_ADD_TC(tp, cli_discover_primary_services);
	ATF_TP_ADD_TC(tp, cli_discover_primary_by_uuid);
	ATF_TP_ADD_TC(tp, cli_discover_characteristics);
	ATF_TP_ADD_TC(tp, cli_discover_descriptors);
	ATF_TP_ADD_TC(tp, cli_read_characteristic_value);
	ATF_TP_ADD_TC(tp, cli_read_using_char_uuid);
	ATF_TP_ADD_TC(tp, cli_read_long_blob);
	ATF_TP_ADD_TC(tp, cli_read_multiple);
	ATF_TP_ADD_TC(tp, cli_write_characteristic_value);
	ATF_TP_ADD_TC(tp, cli_write_without_response);
	ATF_TP_ADD_TC(tp, cli_reliable_long_write);
	ATF_TP_ADD_TC(tp, cli_prepare_execute_write);
	ATF_TP_ADD_TC(tp, cli_notification);
	ATF_TP_ADD_TC(tp, cli_indication_confirm);
	ATF_TP_ADD_TC(tp, cli_read_invalid_handle);
	ATF_TP_ADD_TC(tp, cli_write_not_permitted);

	return (atf_no_error());
}
