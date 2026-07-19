/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * emu_peer_equiv_test.c - EMULATOR <-> PEER EQUIVALENCE differential test.
 *
 * Principle: the SPEC decides.  A bad emulator or a bad peer must not be
 * allowed to define "correct".  This suite proves that our two independent
 * test doubles agree with EACH OTHER and with the Bluetooth Core Specification
 * by driving the SAME golden data through both and asserting three-way,
 * byte-for-byte agreement (path A == path B == spec-golden):
 *
 *   Path A (PEER-driven): the virtual remote device btpeer.c, acting as GATT
 *   client, drives OUR real att_server over an hci_emulator link.  The ATT
 *   request btpeer encodes and puts on the wire, and the response OUR server
 *   emits, are BOTH captured and compared to the spec-golden PDUs.
 *
 *   Path B (EMULATOR-driven): the SAME spec-golden request bytes are injected
 *   directly as an ACL frame through the hci_emulator's controller boundary
 *   (as if a controller delivered them over the air), bypassing btpeer.  The
 *   delivered request (proving transport fidelity) and OUR server's response
 *   are captured and compared to the same spec-golden PDUs.
 *
 * SPEC ORACLE: every golden vector comes from profile_fixtures.c (each PDU
 * hand-encoded from the Core Spec) or is hand-encoded here directly from the
 * Core Spec (MTU exchange, service discovery, encrypted read).  Nothing is
 * captured from either double's output and treated as truth.  If the emulator
 * and peer agree with each other but BOTH differ from the golden bytes, the
 * byte-for-byte assertion still fails: that is a FINDING, and the spec is the
 * arbiter, never whichever double happens to match the code.
 *
 * Reference: Core Spec (<= 5.2) Vol 3 Part F (ATT), Part G (GATT),
 * Vol 4 Part E (HCI).
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

#include "hci_emulator.h"
#include "btpeer.h"
#include "profile_fixtures.h"
#include "spec_oracles.h"

#define TEST_LINKS_SMP		/* we link the real smp_crypto.c verifier */
#include "test_common.h"

#define EQ_ENUM(name, value) EQ_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(EQ_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(EQ_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(EQ_ENUM)
};
#undef EQ_ENUM

/* Test-only remapping; ATT/GATT production objects are compiled separately. */
#undef ATT_OP_ERROR_RSP
#define ATT_OP_ERROR_RSP EQ_ATT_OP_ERROR_RSP
#undef ATT_OP_MTU_REQ
#define ATT_OP_MTU_REQ EQ_ATT_OP_MTU_REQ
#undef ATT_OP_MTU_RSP
#define ATT_OP_MTU_RSP EQ_ATT_OP_MTU_RSP
#undef ATT_OP_READ_BY_TYPE_REQ
#define ATT_OP_READ_BY_TYPE_REQ EQ_ATT_OP_READ_BY_TYPE_REQ
#undef ATT_OP_READ_BY_TYPE_RSP
#define ATT_OP_READ_BY_TYPE_RSP EQ_ATT_OP_READ_BY_TYPE_RSP
#undef ATT_OP_READ_REQ
#define ATT_OP_READ_REQ EQ_ATT_OP_READ_REQ
#undef ATT_OP_READ_RSP
#define ATT_OP_READ_RSP EQ_ATT_OP_READ_RSP
#undef ATT_OP_READ_BY_GROUP_TYPE_REQ
#define ATT_OP_READ_BY_GROUP_TYPE_REQ EQ_ATT_OP_READ_BY_GROUP_TYPE_REQ
#undef ATT_OP_READ_BY_GROUP_TYPE_RSP
#define ATT_OP_READ_BY_GROUP_TYPE_RSP EQ_ATT_OP_READ_BY_GROUP_TYPE_RSP
#undef ATT_OP_WRITE_REQ
#define ATT_OP_WRITE_REQ EQ_ATT_OP_WRITE_REQ
#undef ATT_OP_WRITE_RSP
#define ATT_OP_WRITE_RSP EQ_ATT_OP_WRITE_RSP
#undef ATT_OP_READ_MULTIPLE_VARIABLE_REQ
#define ATT_OP_READ_MULTIPLE_VARIABLE_REQ EQ_ATT_OP_READ_MULTIPLE_VARIABLE_REQ
#undef ATT_OP_READ_MULTIPLE_VARIABLE_RSP
#define ATT_OP_READ_MULTIPLE_VARIABLE_RSP EQ_ATT_OP_READ_MULTIPLE_VARIABLE_RSP
#undef ATT_OP_HANDLE_NOTIFY
#define ATT_OP_HANDLE_NOTIFY EQ_ATT_OP_HANDLE_NOTIFY
#undef ATT_OP_MULTIPLE_HANDLE_VALUE_NTF
#define ATT_OP_MULTIPLE_HANDLE_VALUE_NTF EQ_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF
#undef ATT_ERR_INVALID_HANDLE
#define ATT_ERR_INVALID_HANDLE EQ_ATT_ERR_INVALID_HANDLE
#undef ATT_ERR_INSUFF_ENCRYPTION
#define ATT_ERR_INSUFF_ENCRYPTION EQ_ATT_ERR_INSUFF_ENCRYPTION
#undef GATT_PROP_READ
#define GATT_PROP_READ EQ_GATT_PROP_READ
#undef GATT_PROP_WRITE
#define GATT_PROP_WRITE EQ_GATT_PROP_WRITE

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (smp.c is linked so the
 * ATT signed-write verifier is real; these are its only hardware touch
 * points).  Mirrors gatt_scenario_test.c / btpeer_test.c.  These symbols are
 * intentionally non-static (they replace the real hci_*), hence the per-file
 * -Wno-missing-prototypes relax reported in the Makefile notes.
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
 * Establish an LE connection over the emu link (Vol 4 Part E 7.8.5/7.8.10/
 * 7.8.12): peripheral advertises connectable, central scans then creates the
 * connection.  Mirrors gatt_scenario_test.c.
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
	feed_cmd(periph, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(periph, OP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(central, OP_LE_SET_SCAN_ENABLE, p, 2);

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
	feed_cmd(central, OP_LE_CREATE_CONNECTION, p, 25);
}

/* ================================================================
 * Differential capture harness: OUR att_server behind emu (central); the peer
 * side (btpeer for path A, a passive observer for path B) sits behind emu_peer.
 * eq_out captures every ATT request that reaches OUR server and every response
 * OUR server emits, in order, so a single-op exchange can be diffed against the
 * golden PDUs regardless of who generated the request.
 * ================================================================ */
#define EQ_CAP	16

struct eqh {
	struct hci_emu	*emu;		/* OUR controller (central) */
	struct hci_emu	*emu_peer;	/* peer controller */
	uint16_t	handle;		/* OUR connection handle */
	uint16_t	peer_handle;	/* peer connection handle */
	struct att_conn	ac;
	struct att_db	db;
	int		bridge;		/* reads OUR server's outgoing PDUs */

	int		nreq;
	uint8_t		req[EQ_CAP][ATT_PDU_BUF_SIZE];
	size_t		reqn[EQ_CAP];
	int		nrsp;
	uint8_t		rsp[EQ_CAP][ATT_PDU_BUF_SIZE];
	size_t		rspn[EQ_CAP];

	/* peer-side notification observer (path A) */
	bool		ncb_got;
	uint16_t	ncb_handle;
	uint8_t		ncb_val[64];
	uint16_t	ncb_len;
	bool		ncb_ind;
};

/* Feed one L2CAP B-frame from OUR side into the link (reaches the peer). */
static void
eq_srv_tx(struct eqh *h, uint16_t cid, const uint8_t *payload, uint16_t plen)
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

/* Drain + capture every pending response PDU from OUR server, forward to peer. */
static void
eq_flush(struct eqh *h)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	while ((n = recv(h->bridge, rsp, sizeof(rsp), MSG_DONTWAIT)) > 0) {
		if (h->nrsp < EQ_CAP) {
			memcpy(h->rsp[h->nrsp], rsp, (size_t)n);
			h->rspn[h->nrsp] = (size_t)n;
			h->nrsp++;
		}
		eq_srv_tx(h, NG_L2CAP_ATT_CID, rsp, (uint16_t)n);
	}
}

/* OUR controller's output callback: an ATT request arrived from the link. */
static void
eq_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct eqh *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;			/* HCI events (e.g. Enc Change) ignored */
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len || cid != NG_L2CAP_ATT_CID)
		return;

	if (h->nreq < EQ_CAP) {
		memcpy(h->req[h->nreq], &pkt[9], l2_len);
		h->reqn[h->nreq] = l2_len;
		h->nreq++;
	}
	att_server_handle(&h->ac, &h->db, &pkt[9], l2_len, -1, 0);
	eq_flush(h);
}

/* Passive peer observer for path B (no btpeer): everything is captured on OUR
 * side already, so the peer controller's output is simply discarded. */
static void
eq_peer_obs(void *ctx __unused, const uint8_t *pkt __unused, size_t len __unused)
{
}

static void
eq_notify_cb(void *arg, uint16_t handle, const uint8_t *value, uint16_t len,
    bool indication)
{
	struct eqh *h = arg;

	h->ncb_got = true;
	h->ncb_handle = handle;
	h->ncb_ind = indication;
	if (len > sizeof(h->ncb_val))
		len = sizeof(h->ncb_val);
	h->ncb_len = len;
	if (value != NULL && len != 0)
		memcpy(h->ncb_val, value, len);
}

static void
eq_conn_init(struct eqh *h)
{
	int fds[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
	h->ac.fd = fds[0];
	h->ac.bearer_fd = -1;
	h->ac.mtu = ATT_PDU_BUF_SIZE;		/* 517: full values, no truncation */
	h->ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(h->ac.buf != NULL);
	h->bridge = fds[1];
}

/* Common two-controller link + connection.  want_peer=true attaches btpeer. */
static struct btpeer *
eq_setup(struct eqh *h, bool want_peer)
{
	static const uint8_t caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	struct hci_emu *our, *peer;
	struct btpeer *bp = NULL;

	signal(SIGPIPE, SIG_IGN);
	memset(h, 0, sizeof(*h));

	our = hci_emu_new();
	peer = hci_emu_new();
	ATF_REQUIRE(our != NULL && peer != NULL);
	hci_emu_link(our, peer);
	h->emu = our;
	h->emu_peer = peer;
	hci_emu_set_output(our, eq_out, h);

	if (want_peer) {
		bp = btpeer_new(peer);
		ATF_REQUIRE(bp != NULL);
	} else {
		hci_emu_set_output(peer, eq_peer_obs, h);
	}

	/* peer advertises (peripheral); OUR side scans + connects (central). */
	establish_conn(peer, our, paddr, caddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(our));
	ATF_REQUIRE(hci_emu_get_conn_handle(our, 0, &h->handle));
	ATF_REQUIRE(hci_emu_get_conn_handle(peer, 0, &h->peer_handle));
	if (want_peer)
		ATF_REQUIRE_EQ(0, btpeer_bind_conn(bp));

	eq_conn_init(h);
	return (bp);
}

static void
eq_teardown(struct eqh *h, struct btpeer *bp)
{

	if (bp != NULL)
		btpeer_free(bp);
	free(h->ac.buf);
	close(h->ac.fd);
	close(h->bridge);
	hci_emu_free(h->emu);
	hci_emu_free(h->emu_peer);
}

/*
 * Encrypt the link through the emulator's LTK path (Vol 4 Part E 7.8.24/
 * 7.7.65.5/7.8.25/7.7.8): OUR central enables encryption, the peripheral
 * replies with the LTK, both controllers report the link encrypted.  The
 * daemon would set ac.encrypted on the resulting Encryption Change; we mirror
 * that here, GATED on the emulator actually having encrypted the link, so the
 * emulator's encryption state is what governs the protected read.
 */
static void
eq_encrypt_via_ltk(struct eqh *h)
{
	static const uint8_t ltk[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};
	uint8_t p[28];

	le16enc(&p[0], h->handle);
	memset(&p[2], 0, 8);		/* Rand = 0 (STK-style) */
	le16enc(&p[10], 0x0000);	/* EDIV = 0 */
	memcpy(&p[12], ltk, 16);
	feed_cmd(h->emu, OP_LE_ENABLE_ENCRYPTION, p, 28);

	le16enc(&p[0], h->peer_handle);
	memcpy(&p[2], ltk, 16);
	feed_cmd(h->emu_peer, OP_LE_LTK_REQ_REPLY, p, 18);

	ATF_REQUIRE_EQ(1, hci_emu_get_conn_encrypted(h->emu, h->handle));
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_encrypted(h->emu_peer, h->peer_handle));
	h->ac.encrypted = true;
}

/* Inject a golden ATT request as an ACL frame at the peer controller boundary,
 * as if a real controller delivered it (path B). */
static void
eq_inject(struct eqh *h, const uint8_t *payload, uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(h->peer_handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], NG_L2CAP_ATT_CID);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu_peer, pkt, (size_t)9 + plen);
}

/*
 * Path A driver: make btpeer (GATT client) perform the operation the golden
 * request encodes, so the request btpeer independently encodes lands on the
 * wire and can be diffed against the golden bytes.  Return values are ignored;
 * the on-wire request/response are what the equivalence check compares (an
 * error response is captured just like a success response).
 */
static void
eq_peerA_drive(struct btpeer *bp, const uint8_t *req, size_t n)
{
	uint8_t buf[600];
	size_t outlen = 0;

	switch (req[0]) {
	case ATT_OP_READ_REQ:
		(void)btpeer_gatt_read(bp, get_le16(req + 1), buf, sizeof(buf),
		    &outlen);
		break;
	case ATT_OP_READ_BY_TYPE_REQ: {
		struct btpeer_rbt_rec rec[EQ_CAP];
		int c = 0;

		(void)btpeer_gatt_read_by_type(bp, get_le16(req + 1),
		    get_le16(req + 3), get_le16(req + 5), rec, EQ_CAP, &c);
		break;
	}
	case ATT_OP_READ_BY_GROUP_TYPE_REQ: {
		struct btpeer_service svc[EQ_CAP];
		int c = 0;

		(void)btpeer_gatt_discover_services(bp, svc, EQ_CAP, &c);
		break;
	}
	case ATT_OP_WRITE_REQ:
		(void)btpeer_gatt_write(bp, get_le16(req + 1), req + 3,
		    (uint16_t)(n - 3));
		break;
	case ATT_OP_MTU_REQ: {
		uint16_t smtu = 0;

		(void)btpeer_gatt_exchange_mtu(bp, get_le16(req + 1), &smtu);
		break;
	}
	case ATT_OP_READ_MULTIPLE_VARIABLE_REQ: {
		uint16_t hs[8];
		int nh = (int)((n - 1) / 2), i;

		if (nh > 8)
			nh = 8;
		for (i = 0; i < nh; i++)
			hs[i] = get_le16(req + 1 + 2 * i);
		(void)btpeer_gatt_read_multiple_variable(bp, hs, nh, buf,
		    sizeof(buf), &outlen);
		break;
	}
	default:
		atf_tc_fail("eq_peerA_drive: unhandled opcode 0x%02x", req[0]);
	}
}

/*
 * Core equivalence runner.  Drives the same golden request/response BOTH ways
 * and asserts path A == path B == golden (byte-for-byte on the PDUs).  If
 * vh != 0, also asserts the final attribute value equals expect[0..elen) on
 * both paths (equal final state).  encrypt=true first encrypts the link via
 * the emulator LTK path.
 */
static void
eq_run(void (*build)(struct att_db *), const uint8_t *greq, size_t greqn,
    const uint8_t *grsp, size_t grspn, bool encrypt,
    uint16_t vh, const uint8_t *expect, size_t elen)
{
	struct eqh h;
	struct btpeer *bp;
	struct att_attr *a;

	/* -------- Path A: PEER-driven (btpeer client vs OUR server) -------- */
	bp = eq_setup(&h, true);
	build(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	if (encrypt)
		eq_encrypt_via_ltk(&h);
	eq_peerA_drive(bp, greq, greqn);

	ATF_REQUIRE_MSG(h.nreq >= 1, "path A: no request reached OUR server");
	ATF_REQUIRE_EQ_MSG(greqn, h.reqn[0],
	    "path A: request length %zu != golden %zu", h.reqn[0], greqn);
	ATF_CHECK_EQ_MSG(0, memcmp(h.req[0], greq, greqn),
	    "path A: btpeer-encoded request bytes != spec golden");
	ATF_REQUIRE_MSG(h.nrsp >= 1, "path A: OUR server emitted no response");
	ATF_REQUIRE_EQ_MSG(grspn, h.rspn[0],
	    "path A: response length %zu != golden %zu", h.rspn[0], grspn);
	ATF_CHECK_EQ_MSG(0, memcmp(h.rsp[0], grsp, grspn),
	    "path A: OUR server response bytes != spec golden");
	if (vh != 0) {
		a = attdb_find_by_handle(&h.db, vh);
		ATF_REQUIRE(a != NULL);
		ATF_REQUIRE_EQ_MSG(elen, a->value_len,
		    "path A: final value length mismatch");
		ATF_CHECK_EQ_MSG(0, memcmp(a->value, expect, elen),
		    "path A: final attribute value != expected");
	}
	eq_teardown(&h, bp);

	/* -------- Path B: EMULATOR-driven (raw ACL injection) -------- */
	(void)eq_setup(&h, false);
	build(&h.db);
	if (encrypt)
		eq_encrypt_via_ltk(&h);
	eq_inject(&h, greq, (uint16_t)greqn);

	ATF_REQUIRE_EQ_MSG(1, h.nreq,
	    "path B: emulator delivered %d requests (expected 1)", h.nreq);
	ATF_REQUIRE_EQ_MSG(greqn, h.reqn[0],
	    "path B: delivered request length %zu != golden %zu", h.reqn[0],
	    greqn);
	ATF_CHECK_EQ_MSG(0, memcmp(h.req[0], greq, greqn),
	    "path B: emulator corrupted the injected request");
	ATF_REQUIRE_MSG(h.nrsp >= 1, "path B: OUR server emitted no response");
	ATF_REQUIRE_EQ_MSG(grspn, h.rspn[0],
	    "path B: response length %zu != golden %zu", h.rspn[0], grspn);
	ATF_CHECK_EQ_MSG(0, memcmp(h.rsp[0], grsp, grspn),
	    "path B: OUR server response bytes != spec golden");
	if (vh != 0) {
		a = attdb_find_by_handle(&h.db, vh);
		ATF_REQUIRE(a != NULL);
		ATF_REQUIRE_EQ_MSG(elen, a->value_len,
		    "path B: final value length mismatch");
		ATF_CHECK_EQ_MSG(0, memcmp(a->value, expect, elen),
		    "path B: final attribute value != expected");
	}
	eq_teardown(&h, NULL);
}

/* Convenience wrapper for a fixture golden op (request/response known-answer). */
static void
eq_run_op(const struct profile_fixture *fx, size_t opidx)
{
	const struct golden_op *op = &fx->ops[opidx];

	eq_run(fx->build, op->req, op->req_len, op->rsp, op->rsp_len, false,
	    0, NULL, 0);
}

/*
 * Notification runner.  OUR server originates a Handle Value Notification; the
 * PEER observer (btpeer's client-side notify callback, path A) and the
 * EMULATOR observer (the raw on-wire ATT PDU captured on OUR side, path B) must
 * BOTH decode to the golden notification.
 */
static void
eq_run_notify(const struct profile_fixture *fx)
{
	struct eqh h;
	struct btpeer *bp;

	ATF_REQUIRE(fx->has_notify);
	bp = eq_setup(&h, true);
	fx->build(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	btpeer_on_notify(bp, eq_notify_cb, &h);

	ATF_REQUIRE_EQ(0, att_send_notification(&h.ac, fx->notify_handle,
	    fx->notify_value, fx->notify_len));
	eq_flush(&h);

	/* EMULATOR-side: the exact on-wire PDU == spec golden notify PDU. */
	ATF_REQUIRE_MSG(h.nrsp >= 1, "notify: no PDU on the wire");
	ATF_REQUIRE_EQ_MSG(fx->notify_pdu_len, h.rspn[0],
	    "notify: PDU length %zu != golden %zu", h.rspn[0],
	    fx->notify_pdu_len);
	ATF_CHECK_EQ_MSG(0, memcmp(h.rsp[0], fx->notify_pdu, fx->notify_pdu_len),
	    "notify: on-wire PDU bytes != spec golden");

	/* PEER-side: btpeer independently decoded the same handle/value. */
	ATF_CHECK_MSG(h.ncb_got, "notify: peer observer saw nothing");
	ATF_CHECK_EQ(fx->notify_handle, h.ncb_handle);
	ATF_CHECK(!h.ncb_ind);
	ATF_REQUIRE_EQ_MSG(fx->notify_len, h.ncb_len,
	    "notify: peer value length mismatch");
	ATF_CHECK_EQ_MSG(0, memcmp(h.ncb_val, fx->notify_value, fx->notify_len),
	    "notify: peer-decoded value != spec golden");

	eq_teardown(&h, bp);
}

/*
 * Read Multiple Variable + Multiple Handle Value Notification equivalence
 * (Vol 3 Part F 3.4.4.9 / 3.4.7.4).  A two-characteristic DB: Appearance
 * (0x2A01, value 0x0003 = {0xC2,0x03}) and Battery Level (0x2A19, value 0x0006
 * = {0x64}).  Both are read/notified in one PDU carrying Length-Value (read) or
 * Handle-Length-Value (notify) tuples.  Golden bytes are hand-encoded here.
 */
static struct att_attr	g_rmv_store[16];
static uint8_t		g_rmv_vals[128];

static void
rmv_build(struct att_db *db)
{
	static const uint8_t app[2] = { 0xC2, 0x03 };	/* Appearance: Keyboard */
	static const uint8_t batt = 0x64;

	attdb_init(db, g_rmv_store, 16, g_rmv_vals, sizeof(g_rmv_vals));
	attdb_add_service(db, 0x1800);				/* 0x0001 */
	attdb_add_characteristic(db, 0x2A01, GATT_PROP_READ, ATT_PERM_READ,
	    app, sizeof(app));					/* val 0x0003 */
	attdb_add_service(db, 0x180F);				/* 0x0004 */
	attdb_add_characteristic(db, 0x2A19, GATT_PROP_READ, ATT_PERM_READ,
	    &batt, 1);						/* val 0x0006 */
}

/* Read Multiple Variable Request/Response (Vol 3 Part F 3.4.4.9/.10). */
static const uint8_t g_rmv_req[] = {
	ATT_OP_READ_MULTIPLE_VARIABLE_REQ, 0x03, 0x00, 0x06, 0x00
};
static const uint8_t g_rmv_rsp[] = {
	ATT_OP_READ_MULTIPLE_VARIABLE_RSP,
	0x02, 0x00, 0xC2, 0x03,		/* len=2, Appearance value */
	0x01, 0x00, 0x64		/* len=1, Battery Level value */
};

/* Multiple Handle Value Notification PDU (Vol 3 Part F 3.4.7.4). */
static const uint16_t g_mhvn_handles[2] = { 0x0003, 0x0006 };
static const uint8_t  g_mhvn_v0[2] = { 0xC2, 0x03 };
static const uint8_t  g_mhvn_v1[1] = { 0x64 };
static const uint8_t *g_mhvn_values[2] = { g_mhvn_v0, g_mhvn_v1 };
static const uint16_t g_mhvn_lengths[2] = { 2, 1 };
static const uint8_t  g_mhvn_pdu[] = {
	ATT_OP_MULTIPLE_HANDLE_VALUE_NTF,
	0x03, 0x00, 0x02, 0x00, 0xC2, 0x03,	/* handle 0x0003, len 2, value */
	0x06, 0x00, 0x01, 0x00, 0x64		/* handle 0x0006, len 1, value */
};

/* Multi-notify peer-observer capture (path A: btpeer decodes each tuple). */
struct mhvn_cap {
	int		n;
	uint16_t	handle[4];
	uint8_t		val[4][16];
	uint16_t	len[4];
	bool		any_ind;
};

static void
eq_mhvn_cb(void *arg, uint16_t handle, const uint8_t *value, uint16_t len,
    bool indication)
{
	struct mhvn_cap *c = arg;

	if (c->n >= 4)
		return;
	c->any_ind = c->any_ind || indication;
	c->handle[c->n] = handle;
	if (len > sizeof(c->val[0]))
		len = sizeof(c->val[0]);
	c->len[c->n] = len;
	if (value != NULL && len != 0)
		memcpy(c->val[c->n], value, len);
	c->n++;
}

/*
 * Multi-notify equivalence runner.  OUR server emits a single 0x23 PDU; path B
 * (emulator) asserts the on-wire PDU bytes == spec golden, and path A (btpeer)
 * asserts the peer independently decoded BOTH {handle,value} tuples.
 */
static void
eq_run_multi_notify(void)
{
	struct eqh h;
	struct btpeer *bp;
	struct mhvn_cap cap;

	memset(&cap, 0, sizeof(cap));
	bp = eq_setup(&h, true);
	rmv_build(&h.db);
	btpeer_set_mtu(bp, ATT_PDU_BUF_SIZE);
	btpeer_on_notify(bp, eq_mhvn_cb, &cap);

	ATF_REQUIRE_EQ(0, att_send_multiple_handle_value_ntf(&h.ac,
	    g_mhvn_handles, g_mhvn_values, g_mhvn_lengths, 2));
	eq_flush(&h);

	/* EMULATOR-side: exact on-wire PDU == spec golden. */
	ATF_REQUIRE_MSG(h.nrsp >= 1, "multi-notify: no PDU on the wire");
	ATF_REQUIRE_EQ_MSG(sizeof(g_mhvn_pdu), h.rspn[0],
	    "multi-notify: PDU length %zu != golden %zu", h.rspn[0],
	    sizeof(g_mhvn_pdu));
	ATF_CHECK_EQ_MSG(0, memcmp(h.rsp[0], g_mhvn_pdu, sizeof(g_mhvn_pdu)),
	    "multi-notify: on-wire PDU bytes != spec golden");

	/* PEER-side: btpeer decoded both tuples as notifications. */
	ATF_REQUIRE_EQ_MSG(2, cap.n, "multi-notify: peer decoded %d tuples", cap.n);
	ATF_CHECK(!cap.any_ind);
	ATF_CHECK_EQ(0x0003, cap.handle[0]);
	ATF_REQUIRE_EQ(2, cap.len[0]);
	ATF_CHECK_EQ(0, memcmp(cap.val[0], g_mhvn_v0, 2));
	ATF_CHECK_EQ(0x0006, cap.handle[1]);
	ATF_REQUIRE_EQ(1, cap.len[1]);
	ATF_CHECK_EQ(0x64, cap.val[1][0]);

	eq_teardown(&h, bp);
}

/* ================================================================
 * Hand-encoded spec-golden vectors not present in profile_fixtures.
 * ================================================================ */

/*
 * Exchange MTU (Vol 3 Part F 3.4.2): Client Rx MTU = 100 -> the server returns
 * its own Server Rx MTU (517 = 0x0205).  Request/Response layout 3.4.2.1/2.
 */
static const uint8_t g_mtu_req[] = { ATT_OP_MTU_REQ, 0x64, 0x00 };
static const uint8_t g_mtu_rsp[] = { ATT_OP_MTU_RSP, 0x05, 0x02 };

/*
 * Discover All Primary Services on the Battery fixture via Read By Group Type
 * (Vol 3 Part G 4.4.1; Vol 3 Part F 3.4.4.9/10).  The Battery service group is
 * 0x0001..0x0004, UUID 0x180F.  Response length byte = 6 (2 + 2 + 16-bit UUID).
 */
static const uint8_t g_rbgt_req[] = {
	ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28
};
static const uint8_t g_rbgt_rsp[] = {
	ATT_OP_READ_BY_GROUP_TYPE_RSP, 0x06,
	0x01, 0x00, 0x04, 0x00, 0x0F, 0x18
};

/*
 * Encrypted-read fixture: a single protected characteristic (READ requiring an
 * encrypted link) at value handle 0x0003.  Value is arbitrary test data.
 */
static struct att_attr	g_enc_store[8];
static uint8_t		g_enc_vals[128];
static const uint8_t	g_enc_secret[] = { 0xEC, 0x12, 0x34 };

static void
enc_build(struct att_db *db)
{

	attdb_init(db, g_enc_store, 8, g_enc_vals, sizeof(g_enc_vals));
	attdb_add_service(db, 0x1808);				/* 0x0001 */
	attdb_add_characteristic(db, 0x2A18, GATT_PROP_READ,
	    ATT_PERM_READ | ATT_PERM_READ_ENCRYPT,
	    g_enc_secret, sizeof(g_enc_secret));		/* val 0x0003 */
}

static const uint8_t g_enc_req[] = { ATT_OP_READ_REQ, 0x03, 0x00 };
/*
 * Unencrypted read of an encryption-protected attribute -> Error Response
 * (Vol 3 Part F 3.4.1.1) Insufficient Encryption (0x0F, Vol 3 Part F 3.2.5).
 */
static const uint8_t g_enc_rej_rsp[] = {
	ATT_OP_ERROR_RSP, ATT_OP_READ_REQ, 0x03, 0x00, ATT_ERR_INSUFF_ENCRYPTION
};
/* Encrypted read -> Read Response (Vol 3 Part F 3.4.4.4) with the value. */
static const uint8_t g_enc_ok_rsp[] = {
	ATT_OP_READ_RSP, 0xEC, 0x12, 0x34
};

/*
 * Writable-value fixture (spec-golden Write Request round-trip + final state).
 * Vol 3 Part F 3.4.5.1/3.4.5.2: Write Request -> Write Response (no params);
 * the value is stored.
 */
static struct att_attr	g_w_store[8];
static uint8_t		g_w_vals[64];

static void
w_build(struct att_db *db)
{
	static const uint8_t initval[4] = { 0, 0, 0, 0 };

	attdb_init(db, g_w_store, 8, g_w_vals, sizeof(g_w_vals));
	attdb_add_service(db, 0x1523);				/* 0x0001 */
	attdb_add_characteristic(db, 0x1525,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, initval, sizeof(initval));/* 0x0003 */
}

static const uint8_t g_w_req[] = { ATT_OP_WRITE_REQ, 0x03, 0x00, 0xAA, 0xBB };
static const uint8_t g_w_rsp[] = { ATT_OP_WRITE_RSP };
static const uint8_t g_w_expect[] = { 0xAA, 0xBB };

/* ================================================================
 * Equivalence cases: characteristic reads
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_read_device_name);
ATF_TC_BODY(eq_read_device_name, tc)
{
	eq_run_op(profile_fixture_gap(), 0);
}

ATF_TC_WITHOUT_HEAD(eq_read_appearance);
ATF_TC_BODY(eq_read_appearance, tc)
{
	eq_run_op(profile_fixture_gap(), 1);
}

ATF_TC_WITHOUT_HEAD(eq_read_battery_level);
ATF_TC_BODY(eq_read_battery_level, tc)
{
	eq_run_op(profile_fixture_battery(), 0);
}

ATF_TC_WITHOUT_HEAD(eq_read_manufacturer);
ATF_TC_BODY(eq_read_manufacturer, tc)
{
	eq_run_op(profile_fixture_dis(), 0);
}

ATF_TC_WITHOUT_HEAD(eq_read_hid_information);
ATF_TC_BODY(eq_read_hid_information, tc)
{
	eq_run_op(profile_fixture_hogp(), 0);
}

ATF_TC_WITHOUT_HEAD(eq_read_report_map);
ATF_TC_BODY(eq_read_report_map, tc)
{
	eq_run_op(profile_fixture_hogp(), 1);
}

ATF_TC_WITHOUT_HEAD(eq_read_protocol_mode);
ATF_TC_BODY(eq_read_protocol_mode, tc)
{
	eq_run_op(profile_fixture_hogp(), 3);
}

/* ---------- reads that must be rejected ---------- */

ATF_TC_WITHOUT_HEAD(eq_read_hr_measurement_rejected);
ATF_TC_BODY(eq_read_hr_measurement_rejected, tc)
{
	eq_run_op(profile_fixture_heart_rate(), 2);
}

ATF_TC_WITHOUT_HEAD(eq_read_service_changed_rejected);
ATF_TC_BODY(eq_read_service_changed_rejected, tc)
{
	eq_run_op(profile_fixture_gatt(), 0);
}

/* ================================================================
 * Equivalence cases: Read By Type / service discovery
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_readbytype_char_decls);
ATF_TC_BODY(eq_readbytype_char_decls, tc)
{
	eq_run_op(profile_fixture_gap(), 3);
}

ATF_TC_WITHOUT_HEAD(eq_readbytype_battery_level);
ATF_TC_BODY(eq_readbytype_battery_level, tc)
{
	eq_run_op(profile_fixture_battery(), 3);
}

ATF_TC_WITHOUT_HEAD(eq_readbytype_report_reference);
ATF_TC_BODY(eq_readbytype_report_reference, tc)
{
	eq_run_op(profile_fixture_hogp(), 5);
}

ATF_TC_WITHOUT_HEAD(eq_service_discovery_battery);
ATF_TC_BODY(eq_service_discovery_battery, tc)
{
	eq_run(profile_fixture_battery()->build, g_rbgt_req, sizeof(g_rbgt_req),
	    g_rbgt_rsp, sizeof(g_rbgt_rsp), false, 0, NULL, 0);
}

/* ================================================================
 * Equivalence cases: writes
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_write_cccd_indicate_accepted);
ATF_TC_BODY(eq_write_cccd_indicate_accepted, tc)
{
	eq_run_op(profile_fixture_gatt(), 1);
}

ATF_TC_WITHOUT_HEAD(eq_write_cccd_notify_accepted);
ATF_TC_BODY(eq_write_cccd_notify_accepted, tc)
{
	eq_run_op(profile_fixture_battery(), 1);
}

ATF_TC_WITHOUT_HEAD(eq_write_cccd_notify_rejected);
ATF_TC_BODY(eq_write_cccd_notify_rejected, tc)
{
	eq_run_op(profile_fixture_gatt(), 2);
}

ATF_TC_WITHOUT_HEAD(eq_write_value_with_state);
ATF_TC_BODY(eq_write_value_with_state, tc)
{
	eq_run(w_build, g_w_req, sizeof(g_w_req), g_w_rsp, sizeof(g_w_rsp),
	    false, 0x0003, g_w_expect, sizeof(g_w_expect));
}

/* ================================================================
 * Equivalence cases: MTU exchange
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_exchange_mtu);
ATF_TC_BODY(eq_exchange_mtu, tc)
{
	eq_run(w_build, g_mtu_req, sizeof(g_mtu_req), g_mtu_rsp,
	    sizeof(g_mtu_rsp), false, 0, NULL, 0);
}

/* ================================================================
 * Equivalence cases: notifications
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_notify_battery_level);
ATF_TC_BODY(eq_notify_battery_level, tc)
{
	eq_run_notify(profile_fixture_battery());
}

ATF_TC_WITHOUT_HEAD(eq_notify_heart_rate);
ATF_TC_BODY(eq_notify_heart_rate, tc)
{
	eq_run_notify(profile_fixture_heart_rate());
}

ATF_TC_WITHOUT_HEAD(eq_notify_hogp_keystroke);
ATF_TC_BODY(eq_notify_hogp_keystroke, tc)
{
	eq_run_notify(profile_fixture_hogp());
}

/* ================================================================
 * Equivalence cases: pairing -> encrypted read
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_encrypted_read_rejected);
ATF_TC_BODY(eq_encrypted_read_rejected, tc)
{
	/* No encryption on the link: the protected read is rejected 0x0F. */
	eq_run(enc_build, g_enc_req, sizeof(g_enc_req), g_enc_rej_rsp,
	    sizeof(g_enc_rej_rsp), false, 0, NULL, 0);
}

ATF_TC_WITHOUT_HEAD(eq_encrypted_read_after_pairing);
ATF_TC_BODY(eq_encrypted_read_after_pairing, tc)
{
	/* Emulator LTK exchange encrypts the link -> the protected read succeeds. */
	eq_run(enc_build, g_enc_req, sizeof(g_enc_req), g_enc_ok_rsp,
	    sizeof(g_enc_ok_rsp), true, 0, NULL, 0);
}

/* ================================================================
 * Deliberate-divergence guards: prove the equivalence check has teeth.
 * ================================================================ */

/*
 * Guard A: feed the EMULATOR an intentionally spec-WRONG request byte (corrupt
 * the read handle) for the Battery fixture and assert the differential check
 * CATCHES it -- OUR server's response no longer matches the spec-golden Read
 * Response, and is instead the spec-defined Invalid Handle error.
 */
ATF_TC_WITHOUT_HEAD(guard_emulator_wrong_byte);
ATF_TC_BODY(guard_emulator_wrong_byte, tc)
{
	const struct profile_fixture *fx = profile_fixture_battery();
	const struct golden_op *op = &fx->ops[0];	/* READ Battery Level */
	/* Invalid Handle error for the corrupted handle 0x0099 (Vol 3 Part F
	 * 3.4.1.1, code 0x01). */
	static const uint8_t inval[] = {
		ATT_OP_ERROR_RSP, ATT_OP_READ_REQ, 0x99, 0x00,
		ATT_ERR_INVALID_HANDLE
	};
	struct eqh h;
	uint8_t bad[8];

	ATF_REQUIRE(op->req_len <= sizeof(bad));
	memcpy(bad, op->req, op->req_len);
	bad[1] = 0x99;			/* corrupt the handle low byte */

	(void)eq_setup(&h, false);
	fx->build(&h.db);
	eq_inject(&h, bad, (uint16_t)op->req_len);

	ATF_REQUIRE_MSG(h.nrsp >= 1, "guard A: no response captured");
	/* The equivalence assertion (rsp == golden) WOULD fail: prove it. */
	ATF_CHECK_MSG(h.rspn[0] != op->rsp_len ||
	    memcmp(h.rsp[0], op->rsp, op->rsp_len) != 0,
	    "guard A: spec-wrong byte NOT caught (response matched golden)");
	/* And the divergence is the spec-defined Invalid Handle error. */
	ATF_REQUIRE_EQ(sizeof(inval), h.rspn[0]);
	ATF_CHECK_EQ(0, memcmp(h.rsp[0], inval, sizeof(inval)));

	eq_teardown(&h, NULL);
}

/* ---------- Guard B: client-direction pump harness (peer is accessory) ---------- */

struct cli_h {
	struct hci_emu	*emu;
	uint16_t	handle;
	struct btpeer	*bp;
	int		att_bridge;
	pthread_t	thr;
	bool		running;
};

static void
cli_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cli_h *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == NG_L2CAP_ATT_CID)
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
}

static void
cli_feed(struct cli_h *h, const uint8_t *payload, uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(h->handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], NG_L2CAP_ATT_CID);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu, pkt, (size_t)9 + plen);
}

static void *
cli_pump(void *arg)
{
	struct cli_h *h = arg;
	uint8_t buf[600];
	struct pollfd pfd;

	for (;;) {
		ssize_t n;

		pfd.fd = h->att_bridge;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) <= 0)
			return (NULL);
		if (!(pfd.revents & POLLIN))
			continue;
		n = recv(h->att_bridge, buf, sizeof(buf), MSG_DONTWAIT);
		if (n > 0)
			cli_feed(h, buf, (uint16_t)n);
	}
}

/*
 * Guard B: the PEER (btpeer accessory) serves a spec-WRONG Battery Level; OUR
 * client reads it and the value diverges from the spec golden (0x64) -- proving
 * that a peer double emitting spec-wrong data is caught by an equivalence check.
 */
ATF_TC_WITHOUT_HEAD(guard_peer_wrong_value);
ATF_TC_BODY(guard_peer_wrong_value, tc)
{
	static const uint8_t caddr[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	static const uint8_t paddr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	static const uint8_t wrong = 0x2A;		/* spec golden is 0x64 */
	struct cli_h h;
	struct hci_emu *our, *peer;
	struct att_conn ac;
	uint16_t batt_val;
	uint8_t buf[32];
	size_t outlen = 0;
	int att_fds[2];

	signal(SIGPIPE, SIG_IGN);
	memset(&h, 0, sizeof(h));

	our = hci_emu_new();
	peer = hci_emu_new();
	ATF_REQUIRE(our != NULL && peer != NULL);
	hci_emu_link(our, peer);
	h.emu = our;
	hci_emu_set_output(our, cli_out, &h);
	h.bp = btpeer_new(peer);
	ATF_REQUIRE(h.bp != NULL);

	establish_conn(our, peer, caddr, paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(our));
	ATF_REQUIRE(hci_emu_get_conn_handle(our, 0, &h.handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(h.bp));

	btpeer_add_service(h.bp, 0x180F);
	batt_val = btpeer_add_characteristic(h.bp, 0x2A19,
	    GATT_PROP_READ | GATT_PROP_NOTIFY, BTPEER_PERM_READ, &wrong, 1);
	btpeer_set_mtu(h.bp, 100);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) == 0);
	h.att_bridge = att_fds[1];
	memset(&ac, 0, sizeof(ac));
	ac.fd = att_fds[0];
	ac.bearer_fd = -1;
	ac.mtu = 100;
	ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac.buf != NULL);

	ATF_REQUIRE_EQ(0, pthread_create(&h.thr, NULL, cli_pump, &h));
	h.running = true;

	/* OUR att_read of the peer's Battery Level (Vol 3 Part F 3.4.4.3). */
	ATF_CHECK_EQ(0, att_read(&ac, batt_val, buf, sizeof(buf), &outlen));
	ATF_REQUIRE_EQ(1, outlen);
	/* The spec-wrong value the peer served diverges from the golden 0x64. */
	ATF_CHECK_MSG(buf[0] != 0x64,
	    "guard B: spec-wrong peer value NOT caught (matched golden)");
	ATF_CHECK_EQ(0x2A, buf[0]);

	pthread_join(h.thr, NULL);
	h.running = false;
	free(ac.buf);
	close(att_fds[0]);
	close(att_fds[1]);
	btpeer_free(h.bp);
	hci_emu_free(our);
	hci_emu_free(peer);
}

/* ================================================================
 * EATT Read Multiple Variable + Multiple Handle Value Notification
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eq_read_multiple_variable);
ATF_TC_BODY(eq_read_multiple_variable, tc)
{
	eq_run(rmv_build, g_rmv_req, sizeof(g_rmv_req), g_rmv_rsp,
	    sizeof(g_rmv_rsp), false, 0, NULL, 0);
}

ATF_TC_WITHOUT_HEAD(eq_multi_handle_value_ntf);
ATF_TC_BODY(eq_multi_handle_value_ntf, tc)
{
	eq_run_multi_notify();
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* characteristic reads */
	ATF_TP_ADD_TC(tp, eq_read_device_name);
	ATF_TP_ADD_TC(tp, eq_read_appearance);
	ATF_TP_ADD_TC(tp, eq_read_battery_level);
	ATF_TP_ADD_TC(tp, eq_read_manufacturer);
	ATF_TP_ADD_TC(tp, eq_read_hid_information);
	ATF_TP_ADD_TC(tp, eq_read_report_map);
	ATF_TP_ADD_TC(tp, eq_read_protocol_mode);
	ATF_TP_ADD_TC(tp, eq_read_hr_measurement_rejected);
	ATF_TP_ADD_TC(tp, eq_read_service_changed_rejected);

	/* Read By Type / service discovery */
	ATF_TP_ADD_TC(tp, eq_readbytype_char_decls);
	ATF_TP_ADD_TC(tp, eq_readbytype_battery_level);
	ATF_TP_ADD_TC(tp, eq_readbytype_report_reference);
	ATF_TP_ADD_TC(tp, eq_service_discovery_battery);

	/* writes */
	ATF_TP_ADD_TC(tp, eq_write_cccd_indicate_accepted);
	ATF_TP_ADD_TC(tp, eq_write_cccd_notify_accepted);
	ATF_TP_ADD_TC(tp, eq_write_cccd_notify_rejected);
	ATF_TP_ADD_TC(tp, eq_write_value_with_state);

	/* MTU exchange */
	ATF_TP_ADD_TC(tp, eq_exchange_mtu);

	/* notifications */
	ATF_TP_ADD_TC(tp, eq_notify_battery_level);
	ATF_TP_ADD_TC(tp, eq_notify_heart_rate);
	ATF_TP_ADD_TC(tp, eq_notify_hogp_keystroke);

	/* EATT Read Multiple Variable + Multiple Handle Value Notification */
	ATF_TP_ADD_TC(tp, eq_read_multiple_variable);
	ATF_TP_ADD_TC(tp, eq_multi_handle_value_ntf);

	/* pairing -> encrypted read */
	ATF_TP_ADD_TC(tp, eq_encrypted_read_rejected);
	ATF_TP_ADD_TC(tp, eq_encrypted_read_after_pairing);

	/* deliberate-divergence guards */
	ATF_TP_ADD_TC(tp, guard_emulator_wrong_byte);
	ATF_TP_ADD_TC(tp, guard_peer_wrong_value);

	return (atf_no_error());
}
