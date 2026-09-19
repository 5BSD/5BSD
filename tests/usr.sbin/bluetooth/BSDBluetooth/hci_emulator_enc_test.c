/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator_enc_test.c - spec-anchored tests for Increment 3 of the
 * userspace HCI controller emulator: a virtual clock / timer seam, the LE
 * encryption / LTK path, connection supervision timeout, and LE Power
 * Control (Core 5.2).
 *
 * Two emulators are joined with hci_emu_link() (A advertises = Peripheral,
 * B initiates = Central).  The oracle for every emitted byte is the
 * Bluetooth Core Spec Vol 4 Part E (HCI); each case cites the section it
 * checks and the expected bytes are HAND-ENCODED from the spec -- nothing
 * captures the emulator's own output and treats it as truth.
 */

#include <atf-c.h>

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdint.h>
#include <string.h>

#include "hci_emulator.h"
#include "spec_hci_emulator_enc_oracles.h"

/* Opcode shorthands (OGF/OCF -> 16-bit opcode). */
#define	OP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define	OP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define	OP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define	OP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)
#define	OP_LE_ENABLE_ENCRYPTION	BT_CORE63_HCI_OP_LE_ENABLE_ENCRYPTION
#define	OP_LE_LTK_REQ_REPLY	BT_CORE63_HCI_OP_LE_LTK_REQ_REPLY
#define	OP_LE_LTK_REQ_NEG_REPLY	BT_CORE63_HCI_OP_LE_LTK_REQ_NEG_REPLY
#define	OP_LE_READ_REMOTE_TX_POWER BT_CORE63_HCI_OP_LE_READ_REMOTE_TX_POWER
#define	OP_LE_SET_PATH_LOSS_PARAMS BT_CORE63_HCI_OP_LE_SET_PATH_LOSS_PARAMS
#define	OP_LE_SET_PATH_LOSS_ENABLE BT_CORE63_HCI_OP_LE_SET_PATH_LOSS_ENABLE

static void
assert_hci_enc_wire_contract(void)
{

	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_START_ENCRYPTION),
	    BT_CORE63_HCI_OP_LE_ENABLE_ENCRYPTION);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY),
	    BT_CORE63_HCI_OP_LE_LTK_REQ_REPLY);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY),
	    BT_CORE63_HCI_OP_LE_LTK_REQ_NEG_REPLY);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_REMOTE_TX_POWER_LEVEL),
	    BT_CORE63_HCI_OP_LE_READ_REMOTE_TX_POWER);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_PARAMS),
	    BT_CORE63_HCI_OP_LE_SET_PATH_LOSS_PARAMS);
	ATF_CHECK_EQ(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE),
	    BT_CORE63_HCI_OP_LE_SET_PATH_LOSS_ENABLE);
	ATF_CHECK_EQ(NG_HCI_EVENT_PKT, BT_CORE63_HCI_EVENT_PACKET);
	ATF_CHECK_EQ(NG_HCI_EVENT_ENCRYPTION_CHANGE,
	    BT_CORE63_HCI_EVENT_ENCRYPTION_CHANGE);
	ATF_CHECK_EQ(NG_HCI_LEEV_LONG_TERM_KEY_REQUEST,
	    BT_CORE63_HCI_LE_SUBEVENT_LTK_REQUEST);
	ATF_CHECK_EQ(NG_HCI_LEEV_PATH_LOSS_THRESHOLD,
	    BT_CORE63_HCI_LE_SUBEVENT_PATH_LOSS);
	ATF_CHECK_EQ(NG_HCI_LEEV_TX_POWER_REPORTING,
	    BT_CORE63_HCI_LE_SUBEVENT_TX_POWER);
}

/* ================================================================
 * Per-controller output capture (an ordered list of typed packets).
 * ================================================================ */
#define	CAP_MAX		16
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

/* Return the first captured packet whose event code (byte[1]) is code. */
static const uint8_t *
cap_find_event(const struct cap *c, uint8_t code, size_t *len_out)
{
	int i;

	for (i = 0; i < c->n; i++) {
		if (c->len[i] >= 2 && c->pkt[i][0] == NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == code) {
			if (len_out != NULL)
				*len_out = c->len[i];
			return (c->pkt[i]);
		}
	}
	return (NULL);
}

/*
 * Return the first captured LE Meta event (0x3E) with the given subevent
 * code (byte[3]).  Multiple LE Meta events can coexist on one controller
 * (e.g. Connection Complete then Transmit Power Reporting).
 */
static const uint8_t *
cap_find_le_subevent(const struct cap *c, uint8_t sub, size_t *len_out)
{
	int i;

	for (i = 0; i < c->n; i++) {
		if (c->len[i] >= 4 && c->pkt[i][0] == NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == NG_HCI_EVENT_LE && c->pkt[i][3] == sub) {
			if (len_out != NULL)
				*len_out = c->len[i];
			return (c->pkt[i]);
		}
	}
	return (NULL);
}

/* Feed one typed command packet: 0x01 | opcode(2,LE) | plen | params. */
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

/* Set A up as a connectable advertiser (own address public = bd_addr). */
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

/* Build the 25-byte LE_Create_Connection parameter block (§7.8.12). */
static uint8_t
build_create_conn(uint8_t p[25], uint8_t peer_addr_type,
    const uint8_t peer_addr[6], uint8_t own_addr_type, uint16_t interval,
    uint16_t latency, uint16_t sto)
{

	memset(p, 0, 25);
	le16enc(&p[0], 0x0060);
	le16enc(&p[2], 0x0030);
	p[4] = 0x00;
	p[5] = peer_addr_type;
	memcpy(&p[6], peer_addr, 6);
	p[12] = own_addr_type;
	le16enc(&p[13], interval);
	le16enc(&p[15], interval);
	le16enc(&p[17], latency);
	le16enc(&p[19], sto);
	le16enc(&p[21], 0x0000);
	le16enc(&p[23], 0x0000);
	return (25);
}

/*
 * Establish a link + connection: B (Central) connects to A (Peripheral)
 * with the given supervision timeout.  Both capture buffers are reset so
 * only post-connection events remain.
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

/* Assert an Encryption Change (event 0x08), Vol 4 Part E §7.7.8. */
static void
check_enc_change(const uint8_t *ev, uint16_t handle, uint8_t status,
    uint8_t enabled)
{

	ATF_CHECK_EQ(BT_CORE63_HCI_EVENT_PACKET, ev[0]);
	ATF_CHECK_EQ(BT_CORE63_HCI_EVENT_ENCRYPTION_CHANGE, ev[1]);
	ATF_CHECK_EQ(BT_CORE63_HCI_ENC_CHANGE_PARAM_SIZE, ev[2]);
	ATF_CHECK_EQ(status, ev[3]);				/* status */
	ATF_CHECK_EQ(handle, le16dec(&ev[4]));			/* handle */
	ATF_CHECK_EQ(enabled, ev[6]);				/* enc enabled */
}

/* ================================================================
 * LTK request -> reply -> Encryption Change on both sides.
 * Vol 4 Part E §7.8.24 (LE Enable Encryption), §7.7.65.5 (LTK Request),
 * §7.8.25 (LTK Request Reply), §7.7.8 (Encryption Change).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ltk_encryption_success);
ATF_TC_BODY(test_ltk_encryption_success, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t rand[8] =
	    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	const uint8_t ltk[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};
	const uint16_t ediv = 0xbeef;
	const uint8_t *ev, *cc;
	uint16_t ah, bh;
	uint8_t p[28];

	assert_hci_enc_wire_contract();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Central B enables encryption (§7.8.24). */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	memcpy(&p[2], rand, 8);
	le16enc(&p[10], ediv);
	memcpy(&p[12], ltk, 16);
	feed_cmd(b, OP_LE_ENABLE_ENCRYPTION, p,
	    BT_CORE63_HCI_LE_ENABLE_ENCRYPTION_PARAM_SIZE);

	/* B gets Command Status (§7.7.15) for the accepted command. */
	ev = cap_find_event(&bcap, NG_HCI_EVENT_COMMAND_STATUS, NULL);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(0x00, ev[3]);				/* success */
	ATF_CHECK_EQ(OP_LE_ENABLE_ENCRYPTION, le16dec(&ev[5]));

	/*
	 * Peripheral A raises LE Long Term Key Request (§7.7.65.5), subevent
	 * 0x05: Connection_Handle(2) | Random_Number(8) | EDIV(2).
	 */
	ev = cap_find_le_subevent(&acap, NG_HCI_LEEV_LONG_TERM_KEY_REQUEST,
	    NULL);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(BT_CORE63_HCI_LTK_REQUEST_PARAM_SIZE, ev[2]);
	ATF_CHECK_EQ(ah, le16dec(&ev[4]));			/* handle */
	ATF_CHECK_EQ(0, memcmp(&ev[6], rand, 8));		/* random_number */
	ATF_CHECK_EQ(ediv, le16dec(&ev[14]));			/* EDIV */

	/* A replies with the LTK (§7.8.25): Command Complete status+handle. */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], ah);
	memcpy(&p[2], ltk, 16);
	feed_cmd(a, OP_LE_LTK_REQ_REPLY, p,
	    BT_CORE63_HCI_LE_LTK_REPLY_PARAM_SIZE);

	cc = cap_find_event(&acap, NG_HCI_EVENT_COMMAND_COMPL, NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(BT_CORE63_HCI_COMMAND_COMPLETE_HANDLE_PARAM_SIZE, cc[2]);
	ATF_CHECK_EQ(OP_LE_LTK_REQ_REPLY, le16dec(&cc[4]));
	ATF_CHECK_EQ(0x00, cc[6]);				/* status success */
	ATF_CHECK_EQ(ah, le16dec(&cc[7]));			/* handle */

	/* Encryption Change on BOTH sides: success, enabled (§7.7.8). */
	ev = cap_find_event(&acap, NG_HCI_EVENT_ENCRYPTION_CHANGE, NULL);
	ATF_REQUIRE(ev != NULL);
	check_enc_change(ev, ah, BT_CORE63_HCI_STATUS_SUCCESS,
	    BT_CORE63_HCI_ENCRYPTION_AES_CCM);
	ev = cap_find_event(&bcap, NG_HCI_EVENT_ENCRYPTION_CHANGE, NULL);
	ATF_REQUIRE(ev != NULL);
	check_enc_change(ev, bh, BT_CORE63_HCI_STATUS_SUCCESS,
	    BT_CORE63_HCI_ENCRYPTION_AES_CCM);

	/* Both connections now report encrypted. */
	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(a, ah));
	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(b, bh));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * Encryption-fail path: the peripheral has no key and sends
 * LE_Long_Term_Key_Request_Negative_Reply (§7.8.26); the central
 * receives an Encryption Change with PIN or Key Missing (0x06) and
 * encryption disabled (§7.7.8).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_ltk_encryption_fail);
ATF_TC_BODY(test_ltk_encryption_fail, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t rand[8] = { 0 };
	const uint8_t ltk[16] = { 0 };
	const uint8_t *ev, *cc;
	uint16_t ah, bh;
	uint8_t p[28];

	assert_hci_enc_wire_contract();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Central B enables encryption. */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	memcpy(&p[2], rand, 8);
	le16enc(&p[10], 0x0000);
	memcpy(&p[12], ltk, 16);
	feed_cmd(b, OP_LE_ENABLE_ENCRYPTION, p,
	    BT_CORE63_HCI_LE_ENABLE_ENCRYPTION_PARAM_SIZE);

	/* A gets the LTK request. */
	ev = cap_find_le_subevent(&acap, NG_HCI_LEEV_LONG_TERM_KEY_REQUEST,
	    NULL);
	ATF_REQUIRE(ev != NULL);

	/* A refuses (§7.8.26): Command Complete status+handle. */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], ah);
	feed_cmd(a, OP_LE_LTK_REQ_NEG_REPLY, p,
	    BT_CORE63_HCI_LE_LTK_NEG_REPLY_PARAM_SIZE);

	cc = cap_find_event(&acap, NG_HCI_EVENT_COMMAND_COMPL, NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(OP_LE_LTK_REQ_NEG_REPLY, le16dec(&cc[4]));
	ATF_CHECK_EQ(0x00, cc[6]);				/* status success */
	ATF_CHECK_EQ(ah, le16dec(&cc[7]));			/* handle */

	/* Central B gets Encryption Change: PIN or Key Missing, disabled. */
	ev = cap_find_event(&bcap, NG_HCI_EVENT_ENCRYPTION_CHANGE, NULL);
	ATF_REQUIRE(ev != NULL);
	check_enc_change(ev, bh, BT_CORE63_HCI_ERR_PIN_OR_KEY_MISSING,
	    BT_CORE63_HCI_ENCRYPTION_DISABLED);

	/* Neither side ended up encrypted. */
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(a, ah));
	ATF_CHECK_EQ(0, hci_emu_get_conn_encrypted(b, bh));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * Supervision timeout via the virtual clock: with no traffic, the link
 * supervision timer (Supervision_Timeout = 0x00C8 = 200 * 10 ms = 2 s)
 * elapses and yields a Disconnection Complete (§7.7.5) with reason
 * Connection Timeout (0x08, Vol 6 Part B §4.5.2) on BOTH sides.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_supervision_timeout);
ATF_TC_BODY(test_supervision_timeout, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *bd, *ad;
	uint16_t ah, bh;

	assert_hci_enc_wire_contract();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Pin the clock and advance short of the timeout: nothing fires. */
	hci_emu_set_clock(b, 0);
	cap_reset(&acap);
	cap_reset(&bcap);
	hci_emu_advance(b, 1999u * 1000000ull);		/* 1.999 s < 2 s */
	ATF_CHECK(cap_find_event(&bcap, NG_HCI_EVENT_DISCON_COMPL, NULL)
	    == NULL);
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	/* Cross the 2 s deadline: Disconnection Complete on both sides. */
	hci_emu_advance(b, 2u * 1000000ull);		/* now 2.001 s */

	bd = cap_find_event(&bcap, NG_HCI_EVENT_DISCON_COMPL, NULL);
	ATF_REQUIRE(bd != NULL);
	ATF_CHECK_EQ(4, bd[2]);					/* param_len */
	ATF_CHECK_EQ(0x00, bd[3]);				/* status */
	ATF_CHECK_EQ(bh, le16dec(&bd[4]));			/* handle */
	ATF_CHECK_EQ(BT_CORE63_HCI_ERR_CONNECTION_TIMEOUT, bd[6]);

	ad = cap_find_event(&acap, NG_HCI_EVENT_DISCON_COMPL, NULL);
	ATF_REQUIRE(ad != NULL);
	ATF_CHECK_EQ(ah, le16dec(&ad[4]));			/* handle */
	ATF_CHECK_EQ(BT_CORE63_HCI_ERR_CONNECTION_TIMEOUT, ad[6]);

	/* Both connection tables are now empty. */
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * LE Power Control: LE_Read_Remote_Transmit_Power_Level (§7.8.118)
 * returns Command Status then an LE Transmit Power Reporting event
 * (§7.7.65.33) carrying the remote's modeled tx-power level.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_read_remote_tx_power);
ATF_TC_BODY(test_read_remote_tx_power, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *cs, *ev;
	uint16_t ah, bh;
	uint8_t p[3];

	assert_hci_enc_wire_contract();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Peripheral A's on-air tx power = +9 dBm (0x09). */
	hci_emu_set_conn_tx_power(a, ah, (int8_t)0x09);

	/* Central B reads the remote (A) tx power on PHY 0x01 (LE 1M). */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = BT_CORE63_HCI_PHY_LE_1M;
	feed_cmd(b, OP_LE_READ_REMOTE_TX_POWER, p,
	    BT_CORE63_HCI_LE_READ_TX_POWER_PARAM_SIZE);

	/* Command Status first (§7.7.15). */
	cs = cap_find_event(&bcap, NG_HCI_EVENT_COMMAND_STATUS, NULL);
	ATF_REQUIRE(cs != NULL);
	ATF_CHECK_EQ(0x00, cs[3]);
	ATF_CHECK_EQ(OP_LE_READ_REMOTE_TX_POWER, le16dec(&cs[5]));

	/*
	 * LE Transmit Power Reporting (§7.7.65.33), subevent 0x21:
	 * Status(1) | Connection_Handle(2) | Reason(1) | PHY(1) |
	 * TX_Power_Level(1) | TX_Power_Level_Flag(1) | Delta(1).
	 */
	ev = cap_find_le_subevent(&bcap, NG_HCI_LEEV_TX_POWER_REPORTING, NULL);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(BT_CORE63_HCI_TX_POWER_REPORT_PARAM_SIZE, ev[2]);
	ATF_CHECK_EQ(0x00, ev[4]);				/* status */
	ATF_CHECK_EQ(bh, le16dec(&ev[5]));			/* handle */
	ATF_CHECK_EQ(BT_CORE63_HCI_TX_POWER_REASON_READ_COMPLETE, ev[7]);
	ATF_CHECK_EQ(BT_CORE63_HCI_PHY_LE_1M, ev[8]);
	ATF_CHECK_EQ(0x09, ev[9]);				/* tx power +9 dBm */
	ATF_CHECK_EQ(0x00, ev[10]);				/* flag: neither */
	ATF_CHECK_EQ(0x00, ev[11]);				/* delta 0: Reason 0x02 (§7.7.65.33) */

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * LE Power Control: LE_Set_Path_Loss_Reporting_Parameters (§7.8.119) +
 * _Enable (§7.8.120).  Enabling reporting yields an initial LE Path Loss
 * Threshold event (§7.7.65.32) carrying the current path loss and zone.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_path_loss_reporting);
ATF_TC_BODY(test_path_loss_reporting, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *cc, *ev;
	uint16_t bh;
	uint8_t p[8];

	assert_hci_enc_wire_contract();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr, 0x00c8);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Model a current path loss of 0x50 (80 dB) on the central's link. */
	hci_emu_set_conn_path_loss(b, bh, 0x50);

	/*
	 * LE_Set_Path_Loss_Reporting_Parameters (§7.8.119): low_threshold
	 * 0x30 (48), high_threshold 0x60 (96) => 0x50 falls in the middle
	 * zone (0x01).  Command Complete carries status + handle.
	 */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x60;			/* high_threshold */
	p[3] = 0x04;			/* high_hysteresis */
	p[4] = 0x30;			/* low_threshold */
	p[5] = 0x04;			/* low_hysteresis */
	le16enc(&p[6], 0x000a);		/* min_time_spent */
	feed_cmd(b, OP_LE_SET_PATH_LOSS_PARAMS, p,
	    BT_CORE63_HCI_LE_PATH_LOSS_PARAMS_SIZE);

	cc = cap_find_event(&bcap, NG_HCI_EVENT_COMMAND_COMPL, NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(OP_LE_SET_PATH_LOSS_PARAMS, le16dec(&cc[4]));
	ATF_CHECK_EQ(0x00, cc[6]);				/* status */
	ATF_CHECK_EQ(bh, le16dec(&cc[7]));			/* handle */

	/* LE_Set_Path_Loss_Reporting_Enable(1) (§7.8.120). */
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = 0x01;			/* enable */
	feed_cmd(b, OP_LE_SET_PATH_LOSS_ENABLE, p,
	    BT_CORE63_HCI_LE_PATH_LOSS_ENABLE_SIZE);

	cc = cap_find_event(&bcap, NG_HCI_EVENT_COMMAND_COMPL, NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(OP_LE_SET_PATH_LOSS_ENABLE, le16dec(&cc[4]));
	ATF_CHECK_EQ(0x00, cc[6]);				/* status */

	/*
	 * LE Path Loss Threshold (§7.7.65.32), subevent 0x20:
	 * Connection_Handle(2) | Current_Path_Loss(1) | Zone_Entered(1).
	 */
	ev = cap_find_le_subevent(&bcap, NG_HCI_LEEV_PATH_LOSS_THRESHOLD, NULL);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(BT_CORE63_HCI_PATH_LOSS_REPORT_PARAM_SIZE, ev[2]);
	ATF_CHECK_EQ(bh, le16dec(&ev[4]));			/* handle */
	ATF_CHECK_EQ(0x50, ev[6]);				/* current path loss */
	ATF_CHECK_EQ(BT_CORE63_HCI_PATH_LOSS_ZONE_MIDDLE, ev[7]);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_ltk_encryption_success);
	ATF_TP_ADD_TC(tp, test_ltk_encryption_fail);
	ATF_TP_ADD_TC(tp, test_supervision_timeout);
	ATF_TP_ADD_TC(tp, test_read_remote_tx_power);
	ATF_TP_ADD_TC(tp, test_path_loss_reporting);

	return (atf_no_error());
}
