/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * btpeer_srv_pdu_test.c - byte-level spec-conformance tests for the virtual
 * peer's OWN emitted PDUs (btpeer.c), captured on the far side of the emu link.
 *
 * The other btpeer/equiv suites consume the peer's responses with a lenient
 * parser (OUR att client / att_server), so a wrong field in a peer PDU can
 * slip through unnoticed.  Here two emulators are linked, btpeer sits behind
 * emu_peer, and every ATT/SMP B-frame the peer emits is captured RAW on
 * emu_our's output and diffed against the byte layout mandated by the Core
 * Specification (Vol 3 Part F ATT, Vol 3 Part H SMP).  The oracle is the spec,
 * never the peer's current output.
 */

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <atf-c.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/* smp_crypto.c logs through this blued global; provide a quiet definition. */
extern atomic_int blued_verbose;
atomic_int blued_verbose = 0;

#include "hci_emulator.h"
#include "btpeer.h"
#include "smp.h"
#include "spec_btpeer_pdu_oracles.h"

/* HCI opcode shorthands. */
#define HOP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define HOP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define HOP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define HOP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)

/* ================================================================
 * Raw ATT/SMP PDU capture on emu_our's output.
 * ================================================================ */
#define SCAP_MAX	16
struct scap {
	uint8_t		pdu[SCAP_MAX][256];
	uint16_t	len[SCAP_MAX];
	uint16_t	cid[SCAP_MAX];
	int		n;
};

static void
scap_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct scap *c = ctx;
	uint16_t l2, cid;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;			/* only L2CAP data frames */
	l2 = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2 + 9 > len)
		return;
	if (c->n >= SCAP_MAX)
		return;
	if (l2 > sizeof(c->pdu[0]))
		l2 = sizeof(c->pdu[0]);
	memcpy(c->pdu[c->n], &pkt[9], l2);
	c->len[c->n] = l2;
	c->cid[c->n] = cid;
	c->n++;
}

/* Return the i-th captured PDU on a given CID (NULL if fewer than i+1). */
static const uint8_t *
scap_nth(const struct scap *c, uint16_t cid, int idx, uint16_t *lenout)
{
	int i, k = 0;

	for (i = 0; i < c->n; i++) {
		if (c->cid[i] != cid)
			continue;
		if (k == idx) {
			if (lenout != NULL)
				*lenout = c->len[i];
			return (c->pdu[i]);
		}
		k++;
	}
	return (NULL);
}

static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = NG_HCI_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/* Send one L2CAP B-frame from emu_our to the peer on the given CID. */
static void
tx(struct hci_emu *our, uint16_t handle, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(handle, NG_HCI_LE_PACKET_START,
	    NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(our, pkt, (size_t)9 + plen);
}

/* Link two emulators, attach a btpeer to the peripheral, connect, bind. */
struct rig {
	struct hci_emu	*our;
	struct hci_emu	*peer_emu;
	struct btpeer	*peer;
	struct scap	cap;
	uint16_t	our_handle;
};

static void
rig_setup(struct rig *r)
{
	static const uint8_t caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t p[64];

	memset(r, 0, sizeof(*r));
	r->our = hci_emu_new();
	r->peer_emu = hci_emu_new();
	ATF_REQUIRE(r->our != NULL && r->peer_emu != NULL);
	hci_emu_set_bd_addr(r->our, caddr);
	hci_emu_set_bd_addr(r->peer_emu, paddr);
	hci_emu_link(r->our, r->peer_emu);

	r->peer = btpeer_new(r->peer_emu);	/* sets peer_emu output */
	ATF_REQUIRE(r->peer != NULL);

	/* Peripheral advertises; central scans + connects. */
	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(r->peer_emu, HOP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(r->peer_emu, HOP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(r->our, HOP_LE_SET_SCAN_ENABLE, p, 2);
	memset(p, 0, 25);
	le16enc(&p[0], 0x0060);
	le16enc(&p[2], 0x0030);
	p[5] = 0x00;			/* peer addr type public */
	memcpy(&p[6], paddr, 6);
	p[12] = 0x00;			/* own addr type public */
	le16enc(&p[13], 0x0028);
	le16enc(&p[15], 0x0028);
	le16enc(&p[19], 0x00c8);
	feed_cmd(r->our, HOP_LE_CREATE_CONNECTION, p, 25);

	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(r->our));
	ATF_REQUIRE(hci_emu_get_conn_handle(r->our, 0, &r->our_handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(r->peer));

	/* Capture only what the peer emits from here on. */
	hci_emu_set_output(r->our, scap_out, &r->cap);
}

static void
rig_teardown(struct rig *r)
{

	btpeer_free(r->peer);
	hci_emu_free(r->our);
	hci_emu_free(r->peer_emu);
}

/* ================================================================
 * Error Response: the Attribute Handle In Error field must be the handle
 * from the failing request (Vol 3 Part F 3.4.1.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_error_response_handle);
ATF_TC_BODY(srv_error_response_handle, tc)
{
	struct rig r;
	const uint8_t *rsp;
	uint16_t rlen;
	uint8_t req[3];

	rig_setup(&r);
	/* Read Request for a handle that does not exist (0x0099). */
	req[0] = BTPEER_SPEC_ATT_OP_READ_REQ;
	le16enc(&req[1], 0x0099);
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_ATT_CID, req, 3);

	rsp = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &rlen);
	ATF_REQUIRE(rsp != NULL);
	ATF_REQUIRE_EQ(BTPEER_SPEC_ATT_ERROR_RSP_LEN, rlen);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_READ_REQ, rsp[1]);
	ATF_CHECK_EQ(0x0099, le16dec(&rsp[2]));			/* Handle In Error */
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_ERR_INVALID_HANDLE, rsp[4]);

	rig_teardown(&r);
}

/* ================================================================
 * Find Information Response: Format must be 0x01 (16-bit UUIDs) and each
 * record is Handle(2)|UUID(2) (Vol 3 Part F 3.4.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_find_info_format);
ATF_TC_BODY(srv_find_info_format, tc)
{
	struct rig r;
	const uint8_t *rsp;
	uint16_t rlen, svc;
	uint8_t req[5];

	rig_setup(&r);
	svc = btpeer_add_service(r.peer, 0x180F);		/* Battery Service */
	ATF_REQUIRE(svc != 0);

	req[0] = BTPEER_SPEC_ATT_OP_FIND_INFO_REQ;
	le16enc(&req[1], 0x0001);
	le16enc(&req[3], 0xFFFF);
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_ATT_CID, req, 5);

	rsp = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &rlen);
	ATF_REQUIRE(rsp != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_FIND_INFO_RSP, rsp[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_FIND_INFO_FORMAT_16, rsp[1]);
	ATF_REQUIRE(rlen >= 2 + BTPEER_SPEC_ATT_FIND_INFO_RECORD16_LEN);
	ATF_CHECK_EQ(svc, le16dec(&rsp[2]));			/* first handle */
	ATF_CHECK_EQ(BTPEER_SPEC_GATT_PRIMARY_SERVICE_UUID,
	    le16dec(&rsp[4]));

	rig_teardown(&r);
}

/* ================================================================
 * Read Response length is clamped to ATT_MTU-1 (Vol 3 Part F 3.4.4.4): a
 * value whose length equals the MTU must yield exactly MTU-1 value octets,
 * i.e. a total PDU of MTU octets -- never MTU+1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_read_mtu_clamp);
ATF_TC_BODY(srv_read_mtu_clamp, tc)
{
	struct rig r;
	const uint8_t *rsp;
	uint16_t rlen, h;
	uint8_t val[BTPEER_SPEC_ATT_DEFAULT_MTU];
	uint8_t req[3];
	int i;

	rig_setup(&r);
	btpeer_set_mtu(r.peer, BTPEER_SPEC_ATT_DEFAULT_MTU);
	for (i = 0; i < BTPEER_SPEC_ATT_DEFAULT_MTU; i++)
		val[i] = (uint8_t)(0x40 + i);
	h = btpeer_add_attr(r.peer, 0x2A00, BTPEER_PERM_READ, val, sizeof(val));
	ATF_REQUIRE(h != 0);

	req[0] = BTPEER_SPEC_ATT_OP_READ_REQ;
	le16enc(&req[1], h);
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_ATT_CID, req, 3);

	rsp = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &rlen);
	ATF_REQUIRE(rsp != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_READ_RSP, rsp[0]);
	/* opcode(1) + up to MTU-1 value octets = at most MTU (23) octets. */
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_DEFAULT_MTU, rlen);
	ATF_CHECK_EQ(0, memcmp(&rsp[1], val,
	    BTPEER_SPEC_ATT_DEFAULT_MTU - 1));

	rig_teardown(&r);
}

/* ================================================================
 * Prepare Write Response echoes Handle|Offset|Part Value verbatim
 * (Vol 3 Part F 3.4.6.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(srv_prepare_write_echo);
ATF_TC_BODY(srv_prepare_write_echo, tc)
{
	struct rig r;
	const uint8_t *rsp;
	uint16_t rlen, h;
	uint8_t init[4] = { 0, 0, 0, 0 };
	uint8_t req[9];
	static const uint8_t part[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	rig_setup(&r);
	h = btpeer_add_attr(r.peer, 0x2A00, BTPEER_PERM_READ | BTPEER_PERM_WRITE,
	    init, sizeof(init));
	ATF_REQUIRE(h != 0);

	req[0] = BTPEER_SPEC_ATT_OP_PREPARE_WRITE_REQ;
	le16enc(&req[1], h);
	le16enc(&req[3], 0x0002);			/* value offset */
	memcpy(&req[5], part, sizeof(part));
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_ATT_CID, req,
	    sizeof(req));

	rsp = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &rlen);
	ATF_REQUIRE(rsp != NULL);
	ATF_REQUIRE_EQ(9, rlen);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_PREPARE_WRITE_RSP, rsp[0]);
	ATF_CHECK_EQ(h, le16dec(&rsp[1]));		/* echoed handle */
	ATF_CHECK_EQ(0x0002, le16dec(&rsp[3]));		/* echoed offset */
	ATF_CHECK_EQ(0, memcmp(&rsp[5], part, sizeof(part)));	/* echoed value */

	rig_teardown(&r);
}

/* ================================================================
 * A Handle Value Indication from the server must be answered by the client
 * with a Handle Value Confirmation opcode 0x1E (Vol 3 Part F 3.4.7.3),
 * never a Notification (0x1B).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_indication_confirmation);
ATF_TC_BODY(client_indication_confirmation, tc)
{
	struct rig r;
	const uint8_t *rsp;
	uint16_t rlen;
	uint8_t ind[5];

	rig_setup(&r);
	ind[0] = BTPEER_SPEC_ATT_OP_HANDLE_IND;
	le16enc(&ind[1], 0x0010);
	ind[3] = 0xAA;
	ind[4] = 0xBB;
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_ATT_CID, ind,
	    sizeof(ind));

	rsp = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &rlen);
	ATF_REQUIRE(rsp != NULL);
	ATF_REQUIRE_EQ(1, rlen);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_HANDLE_CFM, rsp[0]);

	rig_teardown(&r);
}

/* ================================================================
 * Signed Write Command (Vol 3 Part F 3.4.5.4 / Vol 3 Part H 2.4.5):
 *   opcode(1) | handle(2) | value | SignCounter(4, LE) | MAC(8).
 * The MAC is the 8 least-significant octets of AES-CMAC(CSRK, message).
 * Compare it with a fixed value reproduced using an external CMAC provider.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(signed_write_mac_and_counter);
ATF_TC_BODY(signed_write_mac_and_counter, tc)
{
	struct rig r;
	const uint8_t *pdu;
	uint16_t plen;
	static const uint8_t csrk[16] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	static const uint8_t value[4] = { 0x01, 0x02, 0x03, 0x04 };
	const uint16_t handle = 0x0025;
	const uint32_t counter = 0x00000007;
	uint16_t mlen;

	rig_setup(&r);
	ATF_REQUIRE_EQ(0, btpeer_gatt_signed_write(r.peer, handle, value,
	    sizeof(value), csrk, counter));

	pdu = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_ATT_CID, 0, &plen);
	ATF_REQUIRE(pdu != NULL);
	ATF_REQUIRE_EQ(1 + 2 + sizeof(value) +
	    BTPEER_SPEC_SIGN_COUNTER_LEN + BTPEER_SPEC_SIGNATURE_LEN, plen);
	ATF_CHECK_EQ(BTPEER_SPEC_ATT_OP_LEGACY_SIGNED_WRITE_CMD, pdu[0]);
	ATF_CHECK_EQ(handle, le16dec(&pdu[1]));
	ATF_CHECK_EQ(0, memcmp(&pdu[3], value, sizeof(value)));

	/* SignCounter is little-endian (Vol 3 Part H 2.4.5). */
	mlen = (uint16_t)(3 + sizeof(value));
	ATF_CHECK_EQ(counter, le32dec(&pdu[mlen]));

	/*
	 * Compare with a fixed, externally reproduced Core §2.4.5 AES-CMAC
	 * oracle.  Do not call the smp_aes_cmac() implementation used by btpeer.
	 */
	ATF_CHECK_EQ(0, memcmp(&pdu[mlen + BTPEER_SPEC_SIGN_COUNTER_LEN],
	    btpeer_spec_signed_write_mac, BTPEER_SPEC_SIGNATURE_LEN));

	rig_teardown(&r);
}

/* ================================================================
 * SMP key distribution (Vol 3 Part H 3.6): drive a full LE Legacy Just
 * Works pairing with the peer as Responder and a scripted initiator, then
 * assert the peer's distributed key PDUs are byte-correct:
 *   Encryption Information (0x06): opcode | LTK(16)          = 17
 *   Central Identification (0x07): opcode | EDIV(2) | Rand(8) = 11
 *   Identity Information   (0x08): opcode | IRK(16)          = 17
 *   Identity Address Info  (0x09): opcode | Type(1) | Addr(6) = 8
 *   Signing Information    (0x0A): opcode | CSRK(16)         = 17
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(smp_key_distribution_pdus);
ATF_TC_BODY(smp_key_distribution_pdus, tc)
{
	struct rig r;
	struct btpeer_smp_cfg cfg;
	static const uint8_t iaddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	static const uint8_t raddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	static const uint8_t srand[16] = {
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
	};
	uint8_t mrand[16];
	uint8_t preq[7], pdu[17], tk[16], confirm[16];
	const uint8_t *pres, *kd;
	uint16_t l;
	int i;

	rig_setup(&r);

	memset(&cfg, 0, sizeof(cfg));
	cfg.role = BTPEER_SMP_RESPONDER;
	cfg.method = BTPEER_SMP_JUST_WORKS;
	cfg.io_cap = BTPEER_SPEC_SMP_IO_NO_INPUT_NO_OUTPUT;
	cfg.bonding = true;
	cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	/* Responder distributes all three key types (Vol 3 Part H 3.6.1). */
	cfg.local_key_dist = BTPEER_SPEC_SMP_KEY_DIST_ENC_KEY |
	    BTPEER_SPEC_SMP_KEY_DIST_ID_KEY |
	    BTPEER_SPEC_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	cfg.remote_key_dist = BTPEER_SPEC_SMP_KEY_DIST_NONE;
	btpeer_smp_configure(r.peer, &cfg);
	btpeer_smp_set_addrs(r.peer, raddr, 0 /* public */, iaddr, 0);
	btpeer_smp_set_srand(r.peer, srand);

	/* Initiator Pairing Request (Vol 3 Part H 3.5.1). */
	preq[0] = BTPEER_SPEC_SMP_PAIRING_REQUEST;
	preq[1] = BTPEER_SPEC_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = BTPEER_SPEC_SMP_OOB_NOT_PRESENT;
	preq[3] = BTPEER_SPEC_SMP_AUTH_BONDING;
	preq[4] = BT_CORE63_SMP_MAX_KEY_SIZE;
	preq[5] = BTPEER_SPEC_SMP_KEY_DIST_NONE;
	preq[6] = BTPEER_SPEC_SMP_KEY_DIST_ENC_KEY |
	    BTPEER_SPEC_SMP_KEY_DIST_ID_KEY |
	    BTPEER_SPEC_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_SMP_CID, preq,
	    BTPEER_SPEC_SMP_PAIRING_PDU_LEN);

	pres = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 0, &l);
	ATF_REQUIRE(pres != NULL);
	ATF_REQUIRE_EQ(BTPEER_SPEC_SMP_PAIRING_RESPONSE, pres[0]);
	ATF_REQUIRE_EQ(BTPEER_SPEC_SMP_PAIRING_PDU_LEN, l);

	/* Just Works TK = 0; initiator confirm via c1 (Vol 3 Part H 2.2.3). */
	memset(tk, 0, 16);
	for (i = 0; i < 16; i++)
		mrand[i] = (uint8_t)(0xB0 + i);
	ATF_REQUIRE(smp_c1(tk, mrand, preq, pres, 0, iaddr, 0, raddr,
	    confirm) >= 0);

	pdu[0] = BTPEER_SPEC_SMP_PAIRING_CONFIRM;
	memcpy(&pdu[1], confirm, 16);
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_SMP_CID, pdu,
	    BTPEER_SPEC_SMP_CONFIRM_RANDOM_PDU_LEN);

	pdu[0] = BTPEER_SPEC_SMP_PAIRING_RANDOM;
	memcpy(&pdu[1], mrand, 16);
	tx(r.our, r.our_handle, BTPEER_SPEC_NG_L2CAP_SMP_CID, pdu,
	    BTPEER_SPEC_SMP_CONFIRM_RANDOM_PDU_LEN);

	/* Captured SMP PDUs after PRes: [1]=Sconfirm [2]=Srandom then keys. */
	kd = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 3, &l);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_ENCRYPTION_INFORMATION, kd[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_ENC_INFO_PDU_LEN, l);

	kd = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 4, &l);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_CENTRAL_IDENTIFICATION, kd[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_CENTRAL_ID_PDU_LEN, l);

	kd = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 5, &l);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_IDENTITY_INFORMATION, kd[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_IDENTITY_INFO_PDU_LEN, l);
	for (i = 0; i < 16; i++)
		ATF_CHECK_EQ(0x55, kd[1 + i]);		/* peer IRK, round-trip */

	kd = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 6, &l);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_IDENTITY_ADDRESS_INFO, kd[0]);
	ATF_REQUIRE_EQ(BTPEER_SPEC_SMP_IDENTITY_ADDR_PDU_LEN, l);
	ATF_CHECK_EQ(BT_CORE63_SMP_ID_ADDR_PUBLIC, kd[1]);
	ATF_CHECK_EQ(0, memcmp(&kd[2], raddr, 6));	/* responder address */

	kd = scap_nth(&r.cap, BTPEER_SPEC_NG_L2CAP_SMP_CID, 7, &l);
	ATF_REQUIRE(kd != NULL);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_LEGACY_SIGNING_INFORMATION, kd[0]);
	ATF_CHECK_EQ(BTPEER_SPEC_SMP_SIGNING_INFO_PDU_LEN, l);
	for (i = 0; i < 16; i++)
		ATF_CHECK_EQ(0x66, kd[1 + i]);		/* peer CSRK, round-trip */

	rig_teardown(&r);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, srv_error_response_handle);
	ATF_TP_ADD_TC(tp, srv_find_info_format);
	ATF_TP_ADD_TC(tp, srv_read_mtu_clamp);
	ATF_TP_ADD_TC(tp, srv_prepare_write_echo);
	ATF_TP_ADD_TC(tp, client_indication_confirmation);
	ATF_TP_ADD_TC(tp, signed_write_mac_and_counter);
	ATF_TP_ADD_TC(tp, smp_key_distribution_pdus);

	return (atf_no_error());
}
