/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * dataflow_test.c - full-stack end-to-end DATA-FLOW scenarios: real
 * procedures pushing real data VOLUME and VARIETY through the whole in-tree
 * BLE stack with no kernel, netgraph, or radio.
 *
 * Each scenario composes the virtual CONTROLLER (hci_emulator.c) with a
 * virtual remote PEER (btpeer.c) driving OUR real daemon-side protocol code
 * (att.c client / att_server*.c / gatt.c / smp*.c), and asserts end-to-end
 * INTEGRITY -- reassembled data must match the source byte for byte, in order,
 * with no loss under load -- not merely "no error".
 *
 * Two composition directions are reused from the scenario harnesses:
 *   - SERVER direction (synchronous): OUR att_server is the code under test
 *     behind controller A; btpeer is the GATT client behind controller B.  A
 *     btpeer client call round-trips inline over the emulator link.
 *   - CLIENT direction (pump thread): OUR att.c/gatt.c is central and blocks on
 *     its L2CAP socket; a pump thread owns the emulator link + btpeer server
 *     and bridges OUR socket to the ACL path (the "pair my keyboard" story).
 * A third, controller-only harness drives the emulator's ISO (CIS/BIG) path.
 *
 * ORACLE: every asserted byte / expected behavior is derived from the
 * Bluetooth Core Specification and cited inline (Vol 3 Part F ATT / Part G
 * GATT / Part H SMP; Vol 4 Part E HCI / ISO).  A code-vs-spec or
 * peer-vs-emulator disagreement is a FINDING: the spec value is kept and the
 * test fails.
 *
 * AF_UNIX SOCK_SEQPACKET coalesces batched sends on this platform, so every
 * multi-PDU stream is driven strictly lockstep: send one PDU, receive one PDU.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

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
#include "spec_dataflow_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (the real ones use
 * bt_devreq on a kernel HCI node; here the emulator owns the LTK path).
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = BT_DF_SPEC_HCI_COMMAND_PACKET;
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
 * Shared HCI command shorthands + generic link bring-up.
 * ================================================================ */
static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = BT_DF_SPEC_HCI_COMMAND_PACKET;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/*
 * Establish an LE connection over the emu link (Vol 4 Part E 7.8.5/7.8.10/
 * 7.8.12): the peripheral advertises connectable, the central scans then
 * issues LE Create Connection.
 */
static void
establish_conn(struct hci_emu *central, struct hci_emu *periph,
    const uint8_t caddr[6], const uint8_t paddr[6])
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t p[64];

	hci_emu_set_bd_addr(central, caddr);
	hci_emu_set_bd_addr(periph, paddr);

	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(periph, BT_DF_SPEC_OP_LE_SET_ADV_DATA, p,
	    (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(periph, BT_DF_SPEC_OP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(central, BT_DF_SPEC_OP_LE_SET_SCAN_ENABLE, p, 2);

	memset(p, 0, 25);
	le16enc(&p[0], 0x0060);
	le16enc(&p[2], 0x0030);
	p[4] = 0x00;
	p[5] = 0x00;
	memcpy(&p[6], paddr, 6);
	p[12] = 0x00;
	le16enc(&p[13], 0x0028);
	le16enc(&p[15], 0x0028);
	le16enc(&p[17], 0x0000);
	le16enc(&p[19], 0x00c8);
	feed_cmd(central, BT_DF_SPEC_OP_LE_CREATE_CONNECTION, p, 25);
}

/* Count currently-open file descriptors (fd-leak detector). */
static int
count_open_fds(void)
{
	int fd, n = 0;

	for (fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return (n);
}

/* ================================================================
 * SCENARIO: ISO (CIS + BIG) data path through the emulator.
 *
 * With the emulator's new ISO command handlers, a CIS is set up between two
 * linked controllers and ISO SDUs are pushed both directions; a BIG carries a
 * broadcast ISO SDU one direction.  Asserts delivery + byte-exact framing
 * (Vol 4 Part E 5.4.5 ISO data packet, 7.8.97-.109, 7.7.65.25/.27/.29).
 * ================================================================ */

struct iso_cap {
	uint8_t	buf[600];
	size_t	len;
	int	count;
};

static void
iso_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct iso_cap *c = ctx;

	/* Capture only ISO data (0x05); ignore command/event traffic. */
	if (len < 1 || pkt[0] != BT_DF_SPEC_HCI_ISO_PACKET)
		return;
	if (len > sizeof(c->buf))
		len = sizeof(c->buf);
	memcpy(c->buf, pkt, len);
	c->len = len;
	c->count++;
}

/* Capture one complete HCI packet for an exact independent wire comparison. */
static void
raw_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct iso_cap *c = ctx;

	ATF_REQUIRE(len <= sizeof(c->buf));
	memcpy(c->buf, pkt, len);
	c->len = len;
	c->count++;
}

/*
 * Frame one complete-SDU ISO data packet (Vol 4 Part E 5.4.5): type(0x05) |
 * con_handle+PB(0b10)+TS(0) | data_load_length | seq_num | sdu_len_flags | SDU.
 */
static void
feed_iso(struct hci_emu *e, uint16_t handle, uint16_t seq, const uint8_t *sdu,
    uint16_t sdulen)
{
	uint8_t pkt[9 + 512];
	uint16_t chf = (uint16_t)((handle & BT_DF_SPEC_CONN_HANDLE_MASK) |
	    BT_DF_SPEC_ISO_COMPLETE_SDU_FLAGS);
	uint16_t load = (uint16_t)(BT_DF_SPEC_ISO_LOAD_HEADER_LEN + sdulen);

	pkt[0] = BT_DF_SPEC_HCI_ISO_PACKET;
	le16enc(&pkt[1], chf);
	le16enc(&pkt[3], load);
	le16enc(&pkt[5], seq);
	le16enc(&pkt[7], (uint16_t)(sdulen & 0x0fff));
	if (sdulen != 0)
		memcpy(&pkt[9], sdu, sdulen);
	hci_emu_input(e, pkt, (size_t)9 + sdulen);
}

/* Assert a captured ISO packet carries handle + seq + payload exactly. */
static void
check_iso(const struct iso_cap *c, uint16_t exp_handle, uint16_t exp_seq,
    const uint8_t *sdu, uint16_t sdulen)
{
	uint16_t chf;

	ATF_REQUIRE_EQ((size_t)(BT_DF_SPEC_ISO_HEADER_LEN + sdulen), c->len);
	chf = le16dec(&c->buf[1]);
	ATF_CHECK_EQ(exp_handle, chf & BT_DF_SPEC_CONN_HANDLE_MASK);
	ATF_CHECK_EQ(BT_DF_SPEC_ISO_COMPLETE_SDU_FLAGS, chf & 0x7000);
	ATF_CHECK_EQ((uint16_t)(BT_DF_SPEC_ISO_LOAD_HEADER_LEN + sdulen),
	    le16dec(&c->buf[3]) & BT_DF_SPEC_ISO_DATA_LEN_MASK);
	ATF_CHECK_EQ(exp_seq, le16dec(&c->buf[5]));
	ATF_CHECK_EQ(sdulen,
	    le16dec(&c->buf[7]) & BT_DF_SPEC_ISO_SDU_LEN_MASK);
	ATF_CHECK_EQ(0, memcmp(&c->buf[9], sdu, sdulen));
}

static void
iso_setup_data_path(struct hci_emu *e, uint16_t handle, uint8_t direction)
{
	uint8_t cp[13];

	memset(cp, 0, sizeof(cp));
	le16enc(&cp[0], handle);
	cp[2] = direction;
	cp[3] = BT_DF_SPEC_ISO_DATA_PATH_HCI;
	feed_cmd(e, BT_DF_SPEC_OP_LE_SETUP_ISO_DATA_PATH, cp, sizeof(cp));
}

ATF_TC_WITHOUT_HEAD(iso_cis_bidirectional_sdu);
ATF_TC_BODY(iso_cis_bidirectional_sdu, tc)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	struct hci_emu *a, *b;
	struct iso_cap capa, capb;
	uint8_t cig_cp[15 + 9];
	uint8_t cis_cp[1 + 4];
	uint8_t sdu_ab[200], sdu_ba[120];
	uint16_t acl_a, cis_a, cis_b;
	unsigned int i;

	memset(&capa, 0, sizeof(capa));
	memset(&capb, 0, sizeof(capb));
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_link(a, b);

	establish_conn(a, b, caddr, paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(a));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &acl_a));

	/* Capture ISO only, after the ACL/link events have been emitted. */
	hci_emu_set_output(a, iso_out, &capa);
	hci_emu_set_output(b, iso_out, &capb);

	/* LE Set CIG Parameters (7.8.97): 1 CIS in group 0. */
	memset(cig_cp, 0, sizeof(cig_cp));
	cig_cp[0] = 0x00;		/* CIG_ID */
	cig_cp[1] = 0x20; cig_cp[2] = 0x4e; cig_cp[3] = 0x00;	/* SDU int C->P */
	cig_cp[4] = 0x20; cig_cp[5] = 0x4e; cig_cp[6] = 0x00;	/* SDU int P->C */
	cig_cp[7] = 0x00;		/* worst-case SCA */
	cig_cp[8] = 0x00;		/* packing */
	cig_cp[9] = 0x00;		/* framing */
	le16enc(&cig_cp[10], 0x000a);	/* max transport latency C->P */
	le16enc(&cig_cp[12], 0x000a);	/* max transport latency P->C */
	cig_cp[14] = 0x01;		/* CIS_Count */
	cig_cp[15] = 0x00;		/* CIS_ID */
	le16enc(&cig_cp[16], 200);	/* Max_SDU C->P */
	le16enc(&cig_cp[18], 200);	/* Max_SDU P->C */
	cig_cp[20] = 0x01;		/* PHY C->P (1M) */
	cig_cp[21] = 0x01;		/* PHY P->C */
	cig_cp[22] = 0x00;		/* RTN C->P */
	cig_cp[23] = 0x00;		/* RTN P->C */
	feed_cmd(a, BT_DF_SPEC_OP_LE_SET_CIG_PARAMS, cig_cp, sizeof(cig_cp));
	ATF_REQUIRE_EQ(1, hci_emu_get_iso_count(a));
	ATF_REQUIRE(hci_emu_get_iso_handle(a, 0, &cis_a));

	/* LE Create CIS (7.8.99): bind CIS to its ACL connection. */
	cis_cp[0] = 0x01;		/* CIS_Count */
	le16enc(&cis_cp[1], cis_a);
	le16enc(&cis_cp[3], acl_a);
	feed_cmd(a, BT_DF_SPEC_OP_LE_CREATE_CIS, cis_cp, sizeof(cis_cp));

	/* CIS Established must have registered a peer-side stream on B. */
	ATF_REQUIRE_EQ(1, hci_emu_get_iso_count(b));
	ATF_REQUIRE(hci_emu_get_iso_handle(b, 0, &cis_b));

	/* Open both data-path directions on both endpoints (7.8.109). */
	iso_setup_data_path(a, cis_a, BT_DF_SPEC_ISO_DIR_INPUT);
	iso_setup_data_path(a, cis_a, BT_DF_SPEC_ISO_DIR_OUTPUT);
	iso_setup_data_path(b, cis_b, BT_DF_SPEC_ISO_DIR_INPUT);
	iso_setup_data_path(b, cis_b, BT_DF_SPEC_ISO_DIR_OUTPUT);
	ATF_CHECK_EQ(BT_DF_SPEC_ISO_BOTH_PATHS_OPEN,
	    hci_emu_get_iso_path_open(a, cis_a));
	ATF_CHECK_EQ(BT_DF_SPEC_ISO_BOTH_PATHS_OPEN,
	    hci_emu_get_iso_path_open(b, cis_b));

	for (i = 0; i < sizeof(sdu_ab); i++)
		sdu_ab[i] = (uint8_t)(0xA0 ^ i);
	for (i = 0; i < sizeof(sdu_ba); i++)
		sdu_ba[i] = (uint8_t)(0x5C + i);

	/* A -> B and B -> A, several sequenced SDUs each way. */
	for (i = 0; i < 8; i++) {
		feed_iso(a, cis_a, (uint16_t)i, sdu_ab, (uint16_t)sizeof(sdu_ab));
		check_iso(&capb, cis_b, (uint16_t)i, sdu_ab,
		    (uint16_t)sizeof(sdu_ab));

		feed_iso(b, cis_b, (uint16_t)(100 + i), sdu_ba,
		    (uint16_t)sizeof(sdu_ba));
		check_iso(&capa, cis_a, (uint16_t)(100 + i), sdu_ba,
		    (uint16_t)sizeof(sdu_ba));
	}
	ATF_CHECK_EQ(8, capb.count);
	ATF_CHECK_EQ(8, capa.count);

	hci_emu_free(a);
	hci_emu_free(b);
}

ATF_TC_WITHOUT_HEAD(iso_big_broadcast_sdu);
ATF_TC_BODY(iso_big_broadcast_sdu, tc)
{
	struct hci_emu *bc, *rx;
	struct iso_cap caprx;
	uint8_t big_cp[31];
	uint8_t sync_cp[25];
	uint8_t sdu[150];
	uint16_t bis_bc, bis_rx;
	unsigned int i;

	memset(&caprx, 0, sizeof(caprx));
	bc = hci_emu_new();
	rx = hci_emu_new();
	ATF_REQUIRE(bc != NULL && rx != NULL);
	hci_emu_link(bc, rx);

	hci_emu_set_output(rx, iso_out, &caprx);

	/* LE Create BIG (7.8.103): broadcaster, BIG_Handle 0, 1 BIS. */
	memset(big_cp, 0, sizeof(big_cp));
	big_cp[0] = 0x00;		/* BIG_Handle */
	big_cp[1] = 0x00;		/* Advertising_Handle */
	big_cp[2] = 0x01;		/* Num_BIS */
	big_cp[3] = 0x20; big_cp[4] = 0x4e; big_cp[5] = 0x00;	/* SDU interval */
	le16enc(&big_cp[6], 150);	/* Max_SDU */
	le16enc(&big_cp[8], 0x000a);	/* Max_Transport_Latency */
	big_cp[10] = 0x00;		/* RTN */
	big_cp[11] = 0x01;		/* PHY */
	feed_cmd(bc, BT_DF_SPEC_OP_LE_CREATE_BIG, big_cp, sizeof(big_cp));
	ATF_REQUIRE_EQ(1, hci_emu_get_iso_count(bc));
	ATF_REQUIRE(hci_emu_get_iso_handle(bc, 0, &bis_bc));

	/* LE BIG Create Sync (7.8.106): receiver syncs to 1 BIS. */
	memset(sync_cp, 0, sizeof(sync_cp));
	sync_cp[0] = 0x00;		/* BIG_Handle */
	le16enc(&sync_cp[1], 0x0000);	/* Sync_Handle */
	sync_cp[3] = 0x00;		/* Encryption */
	sync_cp[20] = 0x00;		/* MSE */
	le16enc(&sync_cp[21], 0x0064);	/* BIG_Sync_Timeout */
	sync_cp[23] = 0x01;		/* Num_BIS */
	sync_cp[24] = 0x01;		/* BIS[0] index */
	feed_cmd(rx, BT_DF_SPEC_OP_LE_BIG_CREATE_SYNC, sync_cp,
	    sizeof(sync_cp));
	ATF_REQUIRE_EQ(1, hci_emu_get_iso_count(rx));
	ATF_REQUIRE(hci_emu_get_iso_handle(rx, 0, &bis_rx));

	/* Broadcaster opens input path, receiver opens output path (7.8.109). */
	iso_setup_data_path(bc, bis_bc, BT_DF_SPEC_ISO_DIR_INPUT);
	iso_setup_data_path(rx, bis_rx, BT_DF_SPEC_ISO_DIR_OUTPUT);

	for (i = 0; i < sizeof(sdu); i++)
		sdu[i] = (uint8_t)(i * 3 + 7);

	for (i = 0; i < 16; i++) {
		feed_iso(bc, bis_bc, (uint16_t)i, sdu, (uint16_t)sizeof(sdu));
		check_iso(&caprx, bis_rx, (uint16_t)i, sdu,
		    (uint16_t)sizeof(sdu));
	}
	ATF_CHECK_EQ(16, caprx.count);

	hci_emu_free(bc);
	hci_emu_free(rx);
}

/*
 * LE Create BIG over-capacity (§7.8.103 / §7.7.65.27): a group that cannot
 * fit the controller's stream table must be rejected as a whole with Memory
 * Capacity Exceeded, never allocated partially.  A partial allocation would
 * emit a Create BIG Complete whose Num_BIS overcounts the connection handles
 * actually present -- a malformed event.  Fill the table to one free slot,
 * then request a two-BIS group and assert no partial stream was created.
 */
ATF_TC_WITHOUT_HEAD(iso_big_over_capacity);
ATF_TC_BODY(iso_big_over_capacity, tc)
{
	struct hci_emu *bc;
	struct iso_cap cap;
	uint8_t big_cp[31];
	static const uint8_t memory_capacity_status[] = {
		BT_DF_SPEC_HCI_EVENT_PACKET,
		BT_DF_SPEC_EVENT_COMMAND_STATUS, 0x04,
		BT_DF_SPEC_STATUS_MEMORY_CAPACITY,
		BT_DF_SPEC_NUM_COMMAND_PACKETS,
		(uint8_t)(BT_DF_SPEC_OP_LE_CREATE_BIG & 0xff),
		(uint8_t)(BT_DF_SPEC_OP_LE_CREATE_BIG >> 8)
	};

	bc = hci_emu_new();
	ATF_REQUIRE(bc != NULL);
	memset(&cap, 0, sizeof(cap));

	memset(big_cp, 0, sizeof(big_cp));
	big_cp[1] = 0x00;		/* Advertising_Handle */
	big_cp[3] = 0x20; big_cp[4] = 0x4e; big_cp[5] = 0x00;	/* SDU interval */
	le16enc(&big_cp[6], 150);	/* Max_SDU */
	le16enc(&big_cp[8], 0x000a);	/* Max_Transport_Latency */
	big_cp[11] = 0x01;		/* PHY */

	/* First group fills 7 of the 8 stream slots. */
	big_cp[0] = 0x00;		/* BIG_Handle */
	big_cp[2] = 0x07;		/* Num_BIS */
	feed_cmd(bc, BT_DF_SPEC_OP_LE_CREATE_BIG, big_cp, sizeof(big_cp));
	ATF_REQUIRE_EQ(7, hci_emu_get_iso_count(bc));

	/*
	 * Second group needs two BIS but only one slot is free: it must be
	 * rejected outright, leaving the stream count unchanged (a partial
	 * allocation would bump the count to 8).
	 */
	big_cp[0] = 0x01;		/* BIG_Handle */
	big_cp[2] = 0x02;		/* Num_BIS */
	/* Capture every output byte for the rejected command, not internal state. */
	hci_emu_set_output(bc, raw_out, &cap);
	feed_cmd(bc, BT_DF_SPEC_OP_LE_CREATE_BIG, big_cp, sizeof(big_cp));
	ATF_CHECK_EQ(7, hci_emu_get_iso_count(bc));
	ATF_REQUIRE_EQ(1, cap.count);
	ATF_REQUIRE_EQ((size_t)BT_DF_SPEC_COMMAND_STATUS_PACKET_LEN, cap.len);
	ATF_CHECK_EQ(0, memcmp(cap.buf, memory_capacity_status,
	    sizeof(memory_capacity_status)));

	hci_emu_free(bc);
}

/* ================================================================
 * SERVER direction (synchronous): OUR att_server behind emu A; btpeer is the
 * GATT client behind emu B.  Used for GATT throughput + soak + the encrypted
 * data exchange of the pairing-lifecycle scenario.
 * ================================================================ */
#define DF_LONG_LEN	2000		/* several-KB characteristic body */

struct srv_harness {
	struct hci_emu	*emu_our;
	struct hci_emu	*emu_peer;
	struct btpeer	*bp;
	uint16_t	handle;
	struct att_conn	ac;
	struct att_db	db;
	int		bridge;
	/* Attribute store (deterministic handles from insertion order). */
	struct att_attr	store[48];
	uint8_t		valbuf[DF_LONG_LEN * 4];
};

static void
srv_tx(struct srv_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[ATT_PDU_BUF_SIZE + 16];

	pkt[0] = BT_DF_SPEC_HCI_ACL_PACKET;
	le16enc(&pkt[1], h->handle & BT_DF_SPEC_CONN_HANDLE_MASK);
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu_our, pkt, (size_t)9 + plen);
}

static void
srv_flush(struct srv_harness *h)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	while ((n = recv(h->bridge, rsp, sizeof(rsp), MSG_DONTWAIT)) > 0)
		srv_tx(h, BT_DF_SPEC_L2CAP_CID_ATT, rsp, (uint16_t)n);
}

static void
srv_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct srv_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != BT_DF_SPEC_HCI_ACL_PACKET)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len || cid != BT_DF_SPEC_L2CAP_CID_ATT)
		return;

	att_server_handle(&h->ac, &h->db, &pkt[9], l2_len, -1, 0);
	srv_flush(h);
}

static void
srv_setup(struct srv_harness *h, struct btpeer **bp_out)
{
	static const uint8_t caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

	h->emu_our = hci_emu_new();
	h->emu_peer = hci_emu_new();
	ATF_REQUIRE(h->emu_our != NULL && h->emu_peer != NULL);
	hci_emu_link(h->emu_our, h->emu_peer);

	hci_emu_set_output(h->emu_our, srv_out, h);
	h->bp = btpeer_new(h->emu_peer);
	ATF_REQUIRE(h->bp != NULL);

	establish_conn(h->emu_peer, h->emu_our, paddr, caddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(h->emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu_our, 0, &h->handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(h->bp));

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	h->ac.fd = fds[0];
	h->ac.bearer_fd = -1;
	h->ac.mtu = ATT_PDU_BUF_SIZE;
	h->ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(h->ac.buf != NULL);
	h->bridge = fds[1];

	*bp_out = h->bp;
}

static void
srv_teardown(struct srv_harness *h)
{

	free(h->ac.buf);
	close(h->ac.fd);
	close(h->bridge);
	btpeer_free(h->bp);
	hci_emu_free(h->emu_our);
	hci_emu_free(h->emu_peer);
}

/*
 * SCENARIO: GATT throughput -- move a several-KB characteristic body via
 * Read Blob paging across an exchanged MTU and assert the reassembled value
 * matches the source byte for byte (Vol 3 Part F 3.4.4.5, Vol 3 Part G 4.8.3).
 */
ATF_TC_WITHOUT_HEAD(gatt_read_blob_multi_kb);
ATF_TC_BODY(gatt_read_blob_multi_kb, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t src[DF_LONG_LEN];
	uint8_t got[DF_LONG_LEN];
	uint16_t smtu = 0, vhandle;
	size_t total = 0;
	unsigned int i;

	for (i = 0; i < DF_LONG_LEN; i++)
		src[i] = (uint8_t)((i * 7 + 13) & 0xff);

	srv_setup(&h, &bp);
	attdb_init(&h.db, h.store, 48, h.valbuf, sizeof(h.valbuf));
	attdb_add_service(&h.db, 0x1523);
	vhandle = attdb_add_characteristic(&h.db, 0x1525,
	    BT_DF_SPEC_GATT_PROP_READ,
	    ATT_PERM_READ, src, sizeof(src));
	ATF_REQUIRE(vhandle != 0);

	/* Exchange MTU (Vol 3 Part F 3.4.2): effective = min(client, server). */
	ATF_CHECK_EQ(0, btpeer_gatt_exchange_mtu(bp, 100, &smtu));
	ATF_CHECK_EQ(ATT_PDU_BUF_SIZE, smtu);
	btpeer_set_mtu(bp, 100);

	/* Page the value in (100-1)-octet blobs until short read (Vol 3 G 4.8.3). */
	for (;;) {
		uint8_t blob[128];
		size_t outlen = 0;

		ATF_REQUIRE_EQ(0, btpeer_gatt_read_blob(bp, vhandle,
		    (uint16_t)total, blob, sizeof(blob), &outlen));
		ATF_REQUIRE(total + outlen <= sizeof(got));
		memcpy(got + total, blob, outlen);
		total += outlen;
		if (outlen < 100 - BT_DF_SPEC_ATT_READ_RSP_OVERHEAD)
			break;
	}
	ATF_CHECK_EQ((size_t)DF_LONG_LEN, total);
	ATF_CHECK_EQ(0, memcmp(src, got, DF_LONG_LEN));

	srv_teardown(&h);
}

/*
 * SCENARIO: GATT throughput -- write a long value via Prepare Write queue +
 * Execute Write (reliable long write, Vol 3 Part F 3.4.6, Vol 3 Part G 4.9.4),
 * then read it back and assert byte-for-byte round-trip integrity.
 *
 * Sizing: btpeer verifies each reliable-write part echo in a 64-octet buffer,
 * and OUR server's prepare queue holds ATT_PREPARE_QUEUE_MAX (16) entries, so
 * one Execute commits up to 16*64 = 1024 octets across 16 queued Prepares --
 * a full multi-part reliable write proving queue reassembly + commit.
 */
#define DF_PREP_LEN	1024
#define DF_PREP_MTU	(64 + BT_DF_SPEC_ATT_PREP_WRITE_OVERHEAD)

ATF_TC_WITHOUT_HEAD(gatt_prepared_write_reliable);
ATF_TC_BODY(gatt_prepared_write_reliable, tc)
{
	struct srv_harness h;
	struct btpeer *bp;
	uint8_t zero[DF_PREP_LEN];
	uint8_t src[DF_PREP_LEN];
	uint8_t got[DF_PREP_LEN];
	uint16_t smtu = 0, vhandle;
	size_t total = 0;
	unsigned int i;

	memset(zero, 0, sizeof(zero));
	for (i = 0; i < DF_PREP_LEN; i++)
		src[i] = (uint8_t)((i ^ (i >> 3)) & 0xff);

	srv_setup(&h, &bp);
	attdb_init(&h.db, h.store, 48, h.valbuf, sizeof(h.valbuf));
	attdb_add_service(&h.db, 0x1523);
	/* Seed with a full-length body so value_maxlen == DF_PREP_LEN. */
	vhandle = attdb_add_characteristic(&h.db, 0x1525,
	    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    zero, sizeof(zero));
	ATF_REQUIRE(vhandle != 0);

	ATF_CHECK_EQ(0, btpeer_gatt_exchange_mtu(bp, DF_PREP_MTU, &smtu));
	btpeer_set_mtu(bp, DF_PREP_MTU);

	/* Reliable long write: Prepare each (MTU-5) part with echo verify, then
	 * a single Execute Write (Vol 3 Part G 4.9.4 / Vol 3 Part F 3.4.6.3). */
	ATF_REQUIRE_EQ(0, btpeer_gatt_write_long(bp, vhandle, src, sizeof(src)));

	/* Read the committed value back and compare byte for byte. */
	for (;;) {
		uint8_t blob[128];
		size_t outlen = 0;

		ATF_REQUIRE_EQ(0, btpeer_gatt_read_blob(bp, vhandle,
		    (uint16_t)total, blob, sizeof(blob), &outlen));
		ATF_REQUIRE(total + outlen <= sizeof(got));
		memcpy(got + total, blob, outlen);
		total += outlen;
		if (outlen < (size_t)(DF_PREP_MTU - 1))
			break;
	}
	ATF_CHECK_EQ((size_t)DF_PREP_LEN, total);
	ATF_CHECK_EQ(0, memcmp(src, got, DF_PREP_LEN));

	srv_teardown(&h);
}

/*
 * SCENARIO: soak/load -- N bounded connect/use/disconnect cycles through the
 * whole server-direction path, asserting flat file-descriptor use (no leak)
 * across cycles.  Each cycle stands up two controllers, a peer, and a
 * SEQPACKET bridge, exchanges MTU + reads + writes real data, then tears
 * everything down.
 */
ATF_TC_WITHOUT_HEAD(soak_connect_use_disconnect);
ATF_TC_BODY(soak_connect_use_disconnect, tc)
{
	const uint8_t src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	int fd_after_warmup = -1;
	int cycle;

	for (cycle = 0; cycle < 64; cycle++) {
		struct srv_harness h;
		struct btpeer *bp;
		uint8_t wr[16], rd[64];
		uint16_t smtu = 0, vhandle;
		size_t outlen = 0;

		srv_setup(&h, &bp);
		attdb_init(&h.db, h.store, 48, h.valbuf, sizeof(h.valbuf));
		attdb_add_service(&h.db, BT_DF_SPEC_UUID_BATTERY_SERVICE);
		vhandle = attdb_add_characteristic(&h.db, 0x1525,
		    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_WRITE,
		    ATT_PERM_READ | ATT_PERM_WRITE, src, sizeof(src));

		ATF_REQUIRE_EQ(0, btpeer_gatt_exchange_mtu(bp, 100, &smtu));
		btpeer_set_mtu(bp, 100);

		memset(wr, (uint8_t)cycle, sizeof(wr));
		wr[0] = (uint8_t)cycle;
		ATF_REQUIRE_EQ(0, btpeer_gatt_write(bp, vhandle, wr, 8));
		ATF_REQUIRE_EQ(0, btpeer_gatt_read(bp, vhandle, rd,
		    sizeof(rd), &outlen));
		ATF_REQUIRE_EQ((size_t)8, outlen);
		ATF_CHECK_EQ(0, memcmp(rd, wr, 8));

		srv_teardown(&h);

		/* Baseline after the first two cycles (allocator warmup). */
		if (cycle == 1)
			fd_after_warmup = count_open_fds();
	}

	ATF_REQUIRE(fd_after_warmup > 0);
	ATF_CHECK_EQ_MSG(fd_after_warmup, count_open_fds(),
	    "file-descriptor count grew across %d soak cycles", 64);
}

/* ================================================================
 * CLIENT direction (pump thread): OUR att.c/gatt.c central behind emu A;
 * btpeer accessory server behind emu B.  Used for the HOGP keystroke stream
 * and the notification/indication throughput scenarios.
 * ================================================================ */
struct cli_harness {
	struct hci_emu	*emu;
	struct hci_emu	*emu_peer;
	uint16_t	handle;
	struct btpeer	*bp;
	int		att_bridge;
	int		ctrl_r, ctrl_w;
	pthread_t	thr;
	bool		running;
};

enum cli_cmd_type { CLI_STOP, CLI_NOTIFY, CLI_INDICATE };
struct cli_cmd {
	enum cli_cmd_type type;
	uint16_t	handle;
	uint8_t		val[256];
	uint16_t	len;
};

static void
cli_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cli_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != BT_DF_SPEC_HCI_ACL_PACKET)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == BT_DF_SPEC_L2CAP_CID_ATT)
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
}

static void
cli_feed(struct cli_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[ATT_PDU_BUF_SIZE + 16];

	pkt[0] = BT_DF_SPEC_HCI_ACL_PACKET;
	le16enc(&pkt[1], h->handle & BT_DF_SPEC_CONN_HANDLE_MASK);
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu, pkt, (size_t)9 + plen);
}

static void *
cli_pump(void *arg)
{
	struct cli_harness *h = arg;
	uint8_t buf[ATT_PDU_BUF_SIZE + 16];
	struct pollfd pfd[2];

	for (;;) {
		pfd[0].fd = h->att_bridge; pfd[0].events = POLLIN;
		pfd[1].fd = h->ctrl_r; pfd[1].events = POLLIN;
		if (poll(pfd, 2, 2000) <= 0)
			continue;
		if (pfd[1].revents & POLLIN) {
			struct cli_cmd cmd;
			ssize_t n = read(h->ctrl_r, &cmd, sizeof(cmd));

			if (n == (ssize_t)sizeof(cmd)) {
				if (cmd.type == CLI_STOP)
					return (NULL);
				if (cmd.type == CLI_NOTIFY)
					btpeer_server_notify(h->bp, cmd.handle,
					    cmd.val, cmd.len);
				else if (cmd.type == CLI_INDICATE)
					btpeer_server_indicate(h->bp,
					    cmd.handle, cmd.val, cmd.len);
			}
		}
		if (pfd[0].revents & POLLIN) {
			ssize_t n = recv(h->att_bridge, buf, sizeof(buf),
			    MSG_DONTWAIT);

			if (n > 0)
				cli_feed(h, BT_DF_SPEC_L2CAP_CID_ATT, buf,
				    (uint16_t)n);
		}
	}
}

static void
cli_setup(struct cli_harness *h, struct btpeer **bp_out, int *our_att_fd)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	int att_fds[2], ctrl[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

	h->emu = hci_emu_new();
	h->emu_peer = hci_emu_new();
	ATF_REQUIRE(h->emu != NULL && h->emu_peer != NULL);
	hci_emu_link(h->emu, h->emu_peer);

	hci_emu_set_output(h->emu, cli_out, h);
	h->bp = btpeer_new(h->emu_peer);
	ATF_REQUIRE(h->bp != NULL);

	establish_conn(h->emu, h->emu_peer, caddr, paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(h->emu));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu, 0, &h->handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(h->bp));

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) == 0);
	h->att_bridge = att_fds[1];
	*our_att_fd = att_fds[0];
	ATF_REQUIRE(pipe(ctrl) == 0);
	h->ctrl_r = ctrl[0];
	h->ctrl_w = ctrl[1];

	*bp_out = h->bp;
}

static void
cli_start(struct cli_harness *h)
{

	ATF_REQUIRE_EQ(0, pthread_create(&h->thr, NULL, cli_pump, h));
	h->running = true;
}

static void
cli_post(struct cli_harness *h, const struct cli_cmd *cmd)
{

	ATF_REQUIRE_EQ((ssize_t)sizeof(*cmd),
	    write(h->ctrl_w, cmd, sizeof(*cmd)));
}

static void
cli_stop(struct cli_harness *h)
{
	struct cli_cmd cmd;

	if (h->running) {
		memset(&cmd, 0, sizeof(cmd));
		cmd.type = CLI_STOP;
		cli_post(h, &cmd);
		pthread_join(h->thr, NULL);
		h->running = false;
	}
}

static void
cli_teardown(struct cli_harness *h, int our_att_fd)
{

	cli_stop(h);
	close(our_att_fd);
	close(h->att_bridge);
	close(h->ctrl_r);
	close(h->ctrl_w);
	btpeer_free(h->bp);
	hci_emu_free(h->emu);
	hci_emu_free(h->emu_peer);
}

static void
cli_att_conn(struct att_conn *ac, int fd, uint16_t mtu)
{

	memset(ac, 0, sizeof(*ac));
	ac->fd = fd;
	ac->bearer_fd = -1;
	ac->mtu = mtu;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
}

static void
post_notify(struct cli_harness *h, uint16_t handle, const uint8_t *val,
    uint16_t len)
{
	struct cli_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.type = CLI_NOTIFY;
	cmd.handle = handle;
	cmd.len = len;
	memcpy(cmd.val, val, len);
	cli_post(h, &cmd);
}

static void
post_indicate(struct cli_harness *h, uint16_t handle, const uint8_t *val,
    uint16_t len)
{
	struct cli_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.type = CLI_INDICATE;
	cmd.handle = handle;
	cmd.len = len;
	memcpy(cmd.val, val, len);
	cli_post(h, &cmd);
}

/* Receive one Handle Value Notification (Vol 3 Part F 3.4.7.1) and verify. */
static void
expect_notify(struct att_conn *ac, uint16_t handle, const uint8_t *val,
    uint16_t len)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t outlen = 0;

	ATF_REQUIRE_EQ(0, att_recv(ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ((size_t)(3 + len), outlen);
	ATF_CHECK_EQ(BT_DF_SPEC_ATT_HANDLE_NOTIFY, buf[0]);
	ATF_CHECK_EQ(handle, get_le16(buf + 1));
	ATF_CHECK_EQ(0, memcmp(buf + 3, val, len));
}

/*
 * SCENARIO: HOGP keystroke stream -- mount a keyboard peer, subscribe to its
 * input report, and stream MANY input-report notifications; assert every
 * report arrives intact and in order (Vol 3 Part F 3.4.7.1, HOGP 1.0).  Each
 * report embeds a rolling sequence in the keycode slot so ordering is proven.
 */
ATF_TC_WITHOUT_HEAD(hogp_keystroke_stream_500);
ATF_TC_BODY(hogp_keystroke_stream_500, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	uint16_t input_report, input_cccd;
	int fd;
	unsigned int i;

	cli_setup(&h, &bp, &fd);
	/* Build a HID keyboard: HID service, an 8-octet Report (0x2A4D)
	 * input characteristic (READ|NOTIFY) and its CCCD (Vol 3 Part G
	 * 3.3.3.3 / HOGP 1.0). */
	btpeer_add_service(bp, BT_DF_SPEC_UUID_HID_SERVICE);
	{
		const uint8_t zero8[8] = { 0 };

		input_report = btpeer_add_characteristic(bp,
		    BT_DF_SPEC_UUID_REPORT,
		    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_NOTIFY,
		    BTPEER_PERM_READ,
		    zero8, sizeof(zero8));
		input_cccd = btpeer_add_cccd(bp);
	}
	btpeer_set_mtu(bp, 100);
	cli_att_conn(&ac, fd, 100);
	cli_start(&h);

	/* Subscribe to notifications (Vol 3 Part G 3.3.3.3). */
	{
		uint8_t v[2];

		put_le16(v, BT_DF_SPEC_CCCD_NOTIFY);
		ATF_REQUIRE_EQ(0, att_write_req(&ac, input_cccd, v, 2));
	}

	/* Stream 500+ boot-keyboard input reports, lockstep (SEQPACKET). */
	for (i = 0; i < 512; i++) {
		uint8_t report[8] = { 0 };

		report[0] = (uint8_t)(i & 0x03);	/* modifier churn */
		report[2] = (uint8_t)(i & 0xff);	/* keycode slot: sequence lo */
		report[3] = (uint8_t)((i >> 8) & 0xff);	/* sequence hi */
		post_notify(&h, input_report, report, sizeof(report));
		expect_notify(&ac, input_report, report, sizeof(report));
	}

	cli_teardown(&h, fd);
	free(ac.buf);
}

/*
 * SCENARIO: GATT notification throughput -- move several KB from the peer
 * server to OUR client as a stream of Handle Value Notifications; reassemble
 * and assert the whole payload matches the source byte for byte, in order
 * (Vol 3 Part F 3.4.7.1).  Each chunk fits (MTU-3) octets.
 */
ATF_TC_WITHOUT_HEAD(gatt_notification_stream_multi_kb);
ATF_TC_BODY(gatt_notification_stream_multi_kb, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	static uint8_t src[4096];
	static uint8_t got[4096];
	uint16_t vhandle, cccd;
	const uint16_t mtu = 100;
	const uint16_t chunk = mtu - BT_DF_SPEC_ATT_VALUE_PDU_OVERHEAD;
	const uint8_t z1 = 0;
	uint8_t v[2];
	size_t off = 0;
	int fd;
	unsigned int i;

	for (i = 0; i < sizeof(src); i++)
		src[i] = (uint8_t)((i * 5 + 1) & 0xff);

	cli_setup(&h, &bp, &fd);
	btpeer_add_service(bp, 0x1523);
	vhandle = btpeer_add_characteristic(bp, 0x1525,
	    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_NOTIFY,
	    BTPEER_PERM_READ, &z1, 1);
	cccd = btpeer_add_cccd(bp);
	btpeer_set_mtu(bp, mtu);
	cli_att_conn(&ac, fd, mtu);
	cli_start(&h);

	put_le16(v, BT_DF_SPEC_CCCD_NOTIFY);
	ATF_REQUIRE_EQ(0, att_write_req(&ac, cccd, v, 2));

	/* Stream the whole payload as (MTU-3)-octet notifications, lockstep,
	 * and reassemble it (Vol 3 Part F 3.4.7.1). */
	while (off < sizeof(src)) {
		uint16_t n = (uint16_t)(sizeof(src) - off);

		if (n > chunk)
			n = chunk;
		post_notify(&h, vhandle, src + off, n);
		expect_notify(&ac, vhandle, src + off, n);
		memcpy(got + off, src + off, n);
		off += n;
	}
	ATF_CHECK_EQ(sizeof(src), off);
	ATF_CHECK_EQ(0, memcmp(src, got, sizeof(src)));

	cli_teardown(&h, fd);
	free(ac.buf);
}

/* Receive one Handle Value Indication (Vol 3 Part F 3.4.7.2), verify, and
 * send the Confirmation (0x1E, Vol 3 Part F 3.4.7.3). */
static void
expect_indicate_confirm(struct att_conn *ac, uint16_t handle,
    const uint8_t *val, uint16_t len)
{
	uint8_t buf[ATT_PDU_BUF_SIZE];
	size_t outlen = 0;

	ATF_REQUIRE_EQ(0, att_recv(ac, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ((size_t)(3 + len), outlen);
	ATF_CHECK_EQ(BT_DF_SPEC_ATT_HANDLE_INDICATE, buf[0]);
	ATF_CHECK_EQ(handle, get_le16(buf + 1));
	ATF_CHECK_EQ(0, memcmp(buf + 3, val, len));
	ATF_CHECK_EQ(0, att_confirm(ac));		/* Handle Value Confirmation */
}

/*
 * SCENARIO: GATT indication throughput -- move several KB from the peer server
 * to OUR client as a stream of confirmed Handle Value Indications; OUR client
 * confirms each (Vol 3 Part F 3.4.7.2/3.4.7.3), then reassemble and assert the
 * payload matches the source byte for byte, in order.
 */
ATF_TC_WITHOUT_HEAD(gatt_indication_stream_multi_kb);
ATF_TC_BODY(gatt_indication_stream_multi_kb, tc)
{
	struct cli_harness h;
	struct btpeer *bp;
	struct att_conn ac;
	static uint8_t src[2048];
	static uint8_t got[2048];
	uint16_t vhandle, cccd;
	const uint16_t mtu = 100;
	const uint16_t chunk = mtu - BT_DF_SPEC_ATT_VALUE_PDU_OVERHEAD;
	const uint8_t z1 = 0;
	uint8_t v[2];
	size_t off = 0;
	int fd;
	unsigned int i;

	for (i = 0; i < sizeof(src); i++)
		src[i] = (uint8_t)((i ^ 0xa5) & 0xff);

	cli_setup(&h, &bp, &fd);
	btpeer_add_service(bp, 0x1523);
	vhandle = btpeer_add_characteristic(bp, 0x1525,
	    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_INDICATE,
	    BTPEER_PERM_READ, &z1, 1);
	cccd = btpeer_add_cccd(bp);
	btpeer_set_mtu(bp, mtu);
	cli_att_conn(&ac, fd, mtu);
	cli_start(&h);

	put_le16(v, BT_DF_SPEC_CCCD_INDICATE);
	ATF_REQUIRE_EQ(0, att_write_req(&ac, cccd, v, 2));

	while (off < sizeof(src)) {
		uint16_t n = (uint16_t)(sizeof(src) - off);

		if (n > chunk)
			n = chunk;
		post_indicate(&h, vhandle, src + off, n);
		expect_indicate_confirm(&ac, vhandle, src + off, n);
		memcpy(got + off, src + off, n);
		off += n;
	}
	ATF_CHECK_EQ(sizeof(src), off);
	ATF_CHECK_EQ(0, memcmp(src, got, sizeof(src)));

	cli_teardown(&h, fd);
	free(ac.buf);
}

/* ================================================================
 * SMP pairing-lifecycle harness (pump thread owns emu link + btpeer).
 * ================================================================ */
static const uint8_t g_caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
static const uint8_t g_paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };

struct smp_harness {
	struct hci_emu	*emu_our;
	struct hci_emu	*emu_peer;
	uint16_t	our_handle, peer_handle;
	struct btpeer	*bp;
	int		att_bridge;
	int		smp_bridge;
	int		ctrl_r, ctrl_w;
	pthread_t	thr;
	bool		running;
};

enum smp_cmd_type { SMP_STOP };
struct smp_cmd { enum smp_cmd_type type; };

static void
smp_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct smp_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != BT_DF_SPEC_HCI_ACL_PACKET)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == BT_DF_SPEC_L2CAP_CID_ATT)
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
	else if (cid == BT_DF_SPEC_L2CAP_CID_SMP) {
		(void)send(h->smp_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
		usleep(2000);		/* SEQPACKET coalescing guard (Vol 3 H 3.6) */
	}
}

/* SMP PDU length by opcode (Vol 3 Part H 3.3, Table 3.1). */
static uint16_t
smp_pdu_len(uint8_t op)
{

	switch (op) {
	case BT_DF_SPEC_SMP_PAIRING_REQUEST:
	case BT_DF_SPEC_SMP_PAIRING_RESPONSE:
		return (BT_DF_SPEC_SMP_LEN_PAIRING);
	case BT_DF_SPEC_SMP_PAIRING_CONFIRM:
	case BT_DF_SPEC_SMP_PAIRING_RANDOM:
	case BT_DF_SPEC_SMP_ENCRYPTION_INFO:
	case BT_DF_SPEC_SMP_IDENTITY_INFO:
	case BT_DF_SPEC_SMP_SIGNING_INFO:
	case BT_DF_SPEC_SMP_DHKEY_CHECK:
		return (BT_DF_SPEC_SMP_LEN_128_BIT_VALUE);
	case BT_DF_SPEC_SMP_PAIRING_FAILED:
		return (BT_DF_SPEC_SMP_LEN_FAILED);
	case BT_DF_SPEC_SMP_MASTER_IDENT:
		return (BT_DF_SPEC_SMP_LEN_MASTER_IDENT);
	case BT_DF_SPEC_SMP_IDENTITY_ADDR_INFO:
		return (BT_DF_SPEC_SMP_LEN_IDENTITY_ADDR);
	case BT_DF_SPEC_SMP_SECURITY_REQUEST:
		return (BT_DF_SPEC_SMP_LEN_SECURITY_REQUEST);
	case BT_DF_SPEC_SMP_PUBLIC_KEY:
		return (BT_DF_SPEC_SMP_LEN_PUBLIC_KEY);
	case BT_DF_SPEC_SMP_KEYPRESS_NOTIFICATION:
		return (BT_DF_SPEC_SMP_LEN_KEYPRESS);
	default:		return (0);
	}
}

static void
smp_feed(struct smp_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = BT_DF_SPEC_HCI_ACL_PACKET;
	le16enc(&pkt[1], h->our_handle & BT_DF_SPEC_CONN_HANDLE_MASK);
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu_our, pkt, (size_t)9 + plen);
}

static void
smp_feed_datagram(struct smp_harness *h, const uint8_t *buf, ssize_t n)
{
	ssize_t off = 0;

	while (off < n) {
		uint16_t pl = smp_pdu_len(buf[off]);

		if (pl == 0 || off + pl > n) {
			smp_feed(h, BT_DF_SPEC_L2CAP_CID_SMP, &buf[off],
			    (uint16_t)(n - off));
			break;
		}
		smp_feed(h, BT_DF_SPEC_L2CAP_CID_SMP, &buf[off], pl);
		off += pl;
	}
}

static void
smp_drain(struct smp_harness *h)
{
	uint8_t buf[600];
	ssize_t n;
	int idle;

	for (idle = 0; idle < 3; idle++) {
		bool any = false;

		while ((n = recv(h->smp_bridge, buf, sizeof(buf),
		    MSG_DONTWAIT)) > 0) {
			smp_feed_datagram(h, buf, n);
			any = true;
		}
		while ((n = recv(h->att_bridge, buf, sizeof(buf),
		    MSG_DONTWAIT)) > 0) {
			smp_feed(h, BT_DF_SPEC_L2CAP_CID_ATT, buf, (uint16_t)n);
			any = true;
		}
		if (any)
			idle = 0;
		usleep(2000);
	}
}

static void *
smp_pump(void *arg)
{
	struct smp_harness *h = arg;
	uint8_t buf[600];
	struct pollfd pfd[3];

	for (;;) {
		int nf = 0, i;

		pfd[nf].fd = h->att_bridge; pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->smp_bridge; pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->ctrl_r; pfd[nf].events = POLLIN; nf++;
		if (poll(pfd, (nfds_t)nf, 2000) <= 0)
			continue;
		for (i = 0; i < nf; i++) {
			ssize_t n;

			if (!(pfd[i].revents & POLLIN))
				continue;
			if (pfd[i].fd == h->ctrl_r) {
				struct smp_cmd cmd;

				n = read(h->ctrl_r, &cmd, sizeof(cmd));
				if (n == (ssize_t)sizeof(cmd) &&
				    cmd.type == SMP_STOP) {
					smp_drain(h);
					return (NULL);
				}
			} else if (pfd[i].fd == h->att_bridge) {
				n = recv(h->att_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					smp_feed(h, BT_DF_SPEC_L2CAP_CID_ATT, buf,
					    (uint16_t)n);
			} else if (pfd[i].fd == h->smp_bridge) {
				n = recv(h->smp_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					smp_feed_datagram(h, buf, n);
			}
		}
	}
}

static void
smp_link_up(struct smp_harness *h)
{

	establish_conn(h->emu_our, h->emu_peer, g_caddr, g_paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(h->emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu_our, 0, &h->our_handle));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu_peer, 0, &h->peer_handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(h->bp));
}

static void
smp_setup(struct smp_harness *h, int *our_att_fd, int *our_smp_fd)
{
	int att_fds[2], smp_fds[2], ctrl[2];

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

	h->emu_our = hci_emu_new();
	h->emu_peer = hci_emu_new();
	ATF_REQUIRE(h->emu_our != NULL && h->emu_peer != NULL);
	hci_emu_link(h->emu_our, h->emu_peer);

	hci_emu_set_output(h->emu_our, smp_out, h);
	h->bp = btpeer_new(h->emu_peer);
	ATF_REQUIRE(h->bp != NULL);

	smp_link_up(h);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) == 0);
	h->att_bridge = att_fds[1];
	*our_att_fd = att_fds[0];
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	h->smp_bridge = smp_fds[1];
	*our_smp_fd = smp_fds[0];
	ATF_REQUIRE(pipe(ctrl) == 0);
	h->ctrl_r = ctrl[0];
	h->ctrl_w = ctrl[1];
}

static void
smp_start(struct smp_harness *h)
{

	ATF_REQUIRE_EQ(0, pthread_create(&h->thr, NULL, smp_pump, h));
	h->running = true;
}

static void
smp_stop(struct smp_harness *h)
{
	struct smp_cmd cmd = { .type = SMP_STOP };

	if (h->running) {
		ATF_REQUIRE_EQ((ssize_t)sizeof(cmd),
		    write(h->ctrl_w, &cmd, sizeof(cmd)));
		pthread_join(h->thr, NULL);
		h->running = false;
	}
}

static void
smp_teardown(struct smp_harness *h, int our_att_fd, int our_smp_fd)
{

	smp_stop(h);
	close(our_att_fd);
	close(our_smp_fd);
	close(h->att_bridge);
	close(h->smp_bridge);
	close(h->ctrl_r);
	close(h->ctrl_w);
	btpeer_free(h->bp);
	hci_emu_free(h->emu_our);
	hci_emu_free(h->emu_peer);
}

/*
 * Encrypt the emulator link on both controllers with a supplied key (Vol 4
 * Part E 7.8.24/7.8.25/7.7.8).  Single-threaded emu access (pump stopped).
 */
static void
smp_drive_encryption(struct smp_harness *h, const uint8_t key[16])
{
	uint8_t p[28];

	le16enc(&p[0], h->our_handle);
	memset(&p[2], 0, 8);		/* Rand = 0 */
	le16enc(&p[10], 0x0000);	/* EDIV = 0 */
	memcpy(&p[12], key, 16);
	feed_cmd(h->emu_our, BT_DF_SPEC_OP_LE_ENABLE_ENCRYPTION, p, 28);

	le16enc(&p[0], h->peer_handle);
	memcpy(&p[2], key, 16);
	feed_cmd(h->emu_peer, BT_DF_SPEC_OP_LE_LTK_REQ_REPLY, p, 18);

	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(h->emu_our, h->our_handle));
	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(h->emu_peer, h->peer_handle));
}

/* Tear the current emulator connection down (Vol 4 Part E 7.1.6). */
static void
smp_link_down(struct smp_harness *h)
{
	uint8_t cp[3];

	le16enc(&cp[0], h->our_handle);
	cp[2] = BT_DF_SPEC_REASON_REMOTE_USER_TERM;
	feed_cmd(h->emu_our, BT_DF_SPEC_OP_DISCONNECT, cp, sizeof(cp));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(h->emu_our));
}

/*
 * Exchange real GATT data over the (encrypted) link, driving btpeer as client
 * against OUR att_server: write a value, read it back, and read an
 * encryption-gated characteristic that only succeeds because the link is
 * encrypted (Vol 3 Part F 3.4.5/3.4.4, ATT_PERM_*_ENCRYPT).  The pump thread
 * must be stopped; this repurposes the same two controllers synchronously.
 */
static void
smp_encrypted_exchange(struct smp_harness *h, uint8_t tag)
{
	struct srv_harness sh;
	struct btpeer *bp = h->bp;
	uint8_t wr[16], rd[64], enc_secret[8];
	uint16_t vhandle, ehandle;
	uint16_t smtu = 0;
	size_t outlen = 0;
	unsigned int i;

	for (i = 0; i < sizeof(enc_secret); i++)
		enc_secret[i] = (uint8_t)(0xE0 + i);

	memset(&sh, 0, sizeof(sh));
	sh.emu_our = h->emu_our;
	sh.emu_peer = h->emu_peer;
	sh.bp = bp;
	sh.handle = h->our_handle;
	{
		int fds[2];

		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
		ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
		ATF_REQUIRE(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
		sh.ac.fd = fds[0];
		sh.ac.bearer_fd = -1;
		sh.ac.mtu = ATT_PDU_BUF_SIZE;
		sh.ac.encrypted = true;		/* link encrypted (Vol 3 C 10.2.1) */
		sh.ac.enc_key_size = 16;
		sh.ac.buf = malloc(ATT_MAX_MTU);
		ATF_REQUIRE(sh.ac.buf != NULL);
		sh.bridge = fds[1];
	}

	attdb_init(&sh.db, sh.store, 48, sh.valbuf, sizeof(sh.valbuf));
	attdb_add_service(&sh.db, 0x180F);
	{
		const uint8_t zero8[8] = { 0 };

		vhandle = attdb_add_characteristic(&sh.db, 0x1525,
		    BT_DF_SPEC_GATT_PROP_READ | BT_DF_SPEC_GATT_PROP_WRITE,
		    ATT_PERM_READ | ATT_PERM_WRITE, zero8, sizeof(zero8));
		ehandle = attdb_add_characteristic(&sh.db, 0x1526,
		    BT_DF_SPEC_GATT_PROP_READ, ATT_PERM_READ_ENCRYPT, enc_secret,
		    sizeof(enc_secret));
	}

	/* Route OUR controller's output through the server bridge synchronously. */
	hci_emu_set_output(h->emu_our, srv_out, &sh);

	ATF_REQUIRE_EQ(0, btpeer_gatt_exchange_mtu(bp, 100, &smtu));
	btpeer_set_mtu(bp, 100);

	memset(wr, tag, sizeof(wr));
	ATF_REQUIRE_EQ(0, btpeer_gatt_write(bp, vhandle, wr, 8));
	ATF_REQUIRE_EQ(0, btpeer_gatt_read(bp, vhandle, rd, sizeof(rd),
	    &outlen));
	ATF_REQUIRE_EQ((size_t)8, outlen);
	ATF_CHECK_EQ(0, memcmp(rd, wr, 8));

	/* Encryption-gated read succeeds only because the link is encrypted. */
	ATF_REQUIRE_EQ(0, btpeer_gatt_read(bp, ehandle, rd, sizeof(rd),
	    &outlen));
	ATF_REQUIRE_EQ((size_t)sizeof(enc_secret), outlen);
	ATF_CHECK_EQ(0, memcmp(rd, enc_secret, sizeof(enc_secret)));

	/* Restore the SMP-harness output callback for any later phase. */
	hci_emu_set_output(h->emu_our, smp_out, h);
	free(sh.ac.buf);
	close(sh.ac.fd);
	close(sh.bridge);
}

/*
 * SCENARIO: pairing lifecycle under data -- pair, bond, exchange encrypted
 * data, disconnect, reconnect and re-encrypt from the stored LTK (bonded fast
 * reconnect, no re-pairing), exchange data again, over several cycles.
 * Asserts a single stored bond throughout (no duplicate/leak), data integrity
 * every cycle, and flat file-descriptor use (Vol 3 Part H 2.4.4 / 3.5.1,
 * Vol 3 Part C 10.2.1).
 */
ATF_TC_WITHOUT_HEAD(pairing_lifecycle_under_data);
ATF_TC_BODY(pairing_lifecycle_under_data, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int hci_fds[2];
	int att_fd, smp_fd;
	int fd_baseline;
	uint8_t ltk[16];
	int cycle;

	smp_setup(&h, &att_fd, &smp_fd);

	/* btpeer is the pairing RESPONDER, Legacy Just Works, distributes its
	 * LTK so a bond is stored (Vol 3 Part H 2.3.5.1 Table 2.8). */
	btpeer_smp_set_addrs(h.bp, g_paddr, 0, g_caddr, 0);
	memset(&cfg, 0, sizeof(cfg));
	cfg.role = BTPEER_SMP_RESPONDER;
	cfg.method = BTPEER_SMP_JUST_WORKS;
	cfg.io_cap = SMP_IO_NO_INPUT_NO_OUTPUT;
	cfg.bonding = true;
	cfg.max_key_size = 16;
	cfg.local_key_dist = SMP_KEY_DIST_ENC_KEY;
	btpeer_smp_configure(h.bp, &cfg);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	memset(&sc, 0, sizeof(sc));
	smp_seed_policy_defaults(&sc);
	sc.fd = smp_fd;
	sc.hci_fd = hci_fds[0];
	sc.con_handle = h.our_handle;
	memcpy(sc.local_addr, g_caddr, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, g_paddr, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_KEYBOARD_DISPLAY;
	sc.min_key_size = 7;
	sc.neg_key_size = 16;

	smp_start(&h);
	ATF_CHECK_EQ_MSG(0, smp_pair(&sc), "smp_pair failed errno=%d", errno);
	smp_stop(&h);

	ATF_REQUIRE_MSG(db.count > 0, "a bond must be stored after pairing");
	ATF_CHECK(db.bonds[0].has_ltk);
	memcpy(ltk, db.bonds[0].ltk, 16);

	/* Cycle 0: encrypt with the freshly-derived LTK and exchange data. */
	smp_drive_encryption(&h, ltk);
	smp_encrypted_exchange(&h, 0x00);
	ATF_CHECK_EQ_MSG(1, db.count, "pairing must not duplicate the bond");

	fd_baseline = count_open_fds();

	/* Bonded fast-reconnect cycles: no re-pairing, re-encrypt from LTK. */
	for (cycle = 1; cycle <= 3; cycle++) {
		smp_link_down(&h);
		/* A reconnection is a new ATT bearer: forget the old handle/MTU
		 * so the peer re-binds and re-exchanges (Vol 3 Part F 3.4.2). */
		btpeer_reset_bearer(h.bp);
		smp_link_up(&h);
		sc.con_handle = h.our_handle;
		smp_drive_encryption(&h, ltk);
		smp_encrypted_exchange(&h, (uint8_t)cycle);

		/* Still exactly one bond; the LTK is unchanged (Vol 3 H 3.5.1). */
		ATF_CHECK_EQ_MSG(1, db.count, "reconnect must reuse the bond");
		ATF_CHECK_EQ(0, memcmp(db.bonds[0].ltk, ltk, 16));
		ATF_CHECK_EQ_MSG(fd_baseline, count_open_fds(),
		    "fd count grew across reconnect cycle");
	}

	close(hci_fds[0]);
	close(hci_fds[1]);
	smp_teardown(&h, att_fd, smp_fd);
}

/*
 * SCENARIO: L2CAP CoC / ECRED credit-based bulk transfer.
 *
 * FINDING / reachability note: the credit-based connection-oriented channel
 * (Vol 3 Part A 3.4 / 4.22-4.26) lives in the kernel ng_l2cap node; the
 * userspace daemon reaches it only through ble_coc_connect(), which is not
 * wired into the in-tree hci_emulator/btpeer path (ble_coc_connect returns -1
 * here).  A credit-based SDU therefore cannot be driven end to end in-process.
 * The reachable equivalent -- a multi-KB SDU segmented across an exchanged MTU
 * with flow paced one PDU at a time (the fixed-channel analogue of credit
 * exhaust/replenish) -- is covered by gatt_read_blob_multi_kb,
 * gatt_prepared_write_multi_kb and gatt_notification_stream_multi_kb.  This
 * case documents the boundary and asserts the CoC entry point is indeed
 * unreachable in-process, so the limitation is explicit rather than silent.
 */
ATF_TC_WITHOUT_HEAD(l2cap_coc_bulk_reachability);
ATF_TC_BODY(l2cap_coc_bulk_reachability, tc)
{

	ATF_CHECK_EQ(-1, ble_coc_connect(NULL, g_paddr, BDADDR_LE_PUBLIC, 0x0080,
	    247));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, iso_cis_bidirectional_sdu);
	ATF_TP_ADD_TC(tp, iso_big_broadcast_sdu);
	ATF_TP_ADD_TC(tp, iso_big_over_capacity);
	ATF_TP_ADD_TC(tp, gatt_read_blob_multi_kb);
	ATF_TP_ADD_TC(tp, gatt_prepared_write_reliable);
	ATF_TP_ADD_TC(tp, soak_connect_use_disconnect);
	ATF_TP_ADD_TC(tp, hogp_keystroke_stream_500);
	ATF_TP_ADD_TC(tp, gatt_notification_stream_multi_kb);
	ATF_TP_ADD_TC(tp, gatt_indication_stream_multi_kb);
	ATF_TP_ADD_TC(tp, pairing_lifecycle_under_data);
	ATF_TP_ADD_TC(tp, l2cap_coc_bulk_reachability);

	return (atf_no_error());
}
