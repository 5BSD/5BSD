/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator_link_test.c - spec-anchored tests for Increment 2 of the
 * userspace HCI controller emulator: two-controller linking over a
 * simulated "air" (advertise -> scan -> connect) plus the ACL data path.
 *
 * Two emulators are joined with hci_emu_link().  The oracle for every
 * emitted byte is the Bluetooth Core Spec Vol 4 Part E (HCI); each case
 * cites the section it checks.  Output is captured per controller so the
 * event ordering on each side can be asserted.  Nothing here captures the
 * emulator's own output and treats it as the oracle -- the expected bytes
 * are hand-encoded from the spec.
 */

#include <atf-c.h>

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdint.h>
#include <string.h>

#include "hci_emulator.h"
#include "spec_hci_emulator_link_oracles.h"

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
		if (c->len[i] >= 2 &&
		    c->pkt[i][0] == HCI_LINK_SPEC_NG_HCI_EVENT_PKT &&
		    c->pkt[i][1] == code) {
			if (len_out != NULL)
				*len_out = c->len[i];
			return (c->pkt[i]);
		}
	}
	return (NULL);
}

/* Return the first captured ACL packet (type byte 0x02). */
static const uint8_t *
cap_find_acl(const struct cap *c, size_t *len_out)
{
	int i;

	for (i = 0; i < c->n; i++) {
		if (c->len[i] >= 1 && c->pkt[i][0] == HCI_LINK_SPEC_ACL_PKT) {
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

	buf[0] = HCI_LINK_SPEC_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/* Feed one typed ACL packet: 0x02 | handle+flags(2,LE) | len(2,LE) | data. */
static void
feed_acl(struct hci_emu *e, uint16_t handle, uint8_t pb, uint8_t bc,
    const uint8_t *data, uint16_t dlen)
{
	uint8_t buf[512];

	buf[0] = HCI_LINK_SPEC_ACL_PKT;
	le16enc(&buf[1], HCI_LINK_SPEC_MAKE_HANDLE(handle, pb, bc));
	le16enc(&buf[3], dlen);
	if (dlen != 0)
		memcpy(&buf[5], data, dlen);
	hci_emu_input(e, buf, (size_t)5 + dlen);
}

static void
feed_acl_with_trailer(struct hci_emu *e, uint16_t handle,
    const uint8_t *data, uint16_t dlen, const uint8_t *trailer,
    size_t trailer_len)
{
	uint8_t buf[512];

	ATF_REQUIRE((size_t)5 + dlen + trailer_len <= sizeof(buf));
	buf[0] = HCI_LINK_SPEC_ACL_PKT;
	le16enc(&buf[1], HCI_LINK_SPEC_MAKE_HANDLE(handle,
	    HCI_LINK_SPEC_LE_PACKET_START, HCI_LINK_SPEC_POINT_TO_POINT));
	le16enc(&buf[3], dlen);
	memcpy(&buf[5], data, dlen);
	memcpy(&buf[5 + dlen], trailer, trailer_len);
	hci_emu_input(e, buf, (size_t)5 + dlen + trailer_len);
}

/* Set A up as a connectable advertiser (own address public = bd_addr). */
static void
setup_advertiser(struct hci_emu *a, const uint8_t addr[6], const uint8_t *ad,
    uint8_t adlen)
{
	uint8_t p[64];

	hci_emu_set_bd_addr(a, addr);

	/* LE_Set_Advertising_Data (§7.8.7): significant length + AD bytes. */
	p[0] = adlen;
	memcpy(&p[1], ad, adlen);
	feed_cmd(a, HCI_LINK_SPEC_OP_LE_SET_ADV_DATA, p,
	    (uint8_t)(1 + adlen));

	/* LE_Set_Advertising_Enable(1) (§7.8.9): adv_type default ADV_IND. */
	p[0] = 0x01;
	feed_cmd(a, HCI_LINK_SPEC_OP_LE_SET_ADV_ENABLE, p, 1);
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

/*
 * Assert an LE Connection Complete (LE Meta 0x3E / subevent 0x01),
 * Vol 4 Part E §7.7.65.1: exact typed byte layout.
 */
static void
check_conn_complete(const uint8_t *ev, uint8_t status, uint16_t handle,
    uint8_t role, uint8_t peer_addr_type, const uint8_t peer_addr[6],
    uint16_t interval, uint16_t latency, uint16_t sto)
{

	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_PKT, ev[0]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_LE, ev[1]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_CONN_COMPLETE_PARAM_LEN, ev[2]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_CON_COMPL, ev[3]);
	ATF_CHECK_EQ(status, ev[4]);				/* status */
	ATF_CHECK_EQ(handle, le16dec(&ev[5]));			/* handle */
	ATF_CHECK_EQ(role, ev[7]);				/* role */
	ATF_CHECK_EQ(peer_addr_type, ev[8]);			/* peer addr type */
	ATF_CHECK_EQ(0, memcmp(&ev[9], peer_addr, 6));		/* peer address */
	ATF_CHECK_EQ(interval, le16dec(&ev[15]));		/* interval */
	ATF_CHECK_EQ(latency, le16dec(&ev[17]));		/* latency */
	ATF_CHECK_EQ(sto, le16dec(&ev[19]));			/* supervision to */
	ATF_CHECK_EQ(HCI_LINK_SPEC_CLOCK_ACCURACY_251_TO_500_PPM, ev[21]);
}

/* Establish a link + connection; B(central) connects to A(peripheral). */
static void
link_and_connect(struct hci_emu **ap, struct hci_emu **bp, struct cap *acap,
    struct cap *bcap, const uint8_t a_addr[6], const uint8_t b_addr[6])
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	struct hci_emu *a, *b;
	uint8_t p[25], plen;

	/*
	 * Zero the capture buffers BEFORE wiring up the output callback:
	 * setup_advertiser() below feeds commands that fire cap_out(), which
	 * indexes pkt[] by c->n.  An uninitialized c->n is a wild store.
	 */
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

	/* B scans, then initiates a connection to A. */
	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_SET_SCAN_ENABLE, p, 2);

	cap_reset(acap);
	cap_reset(bcap);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0x0000,
	    0x00c8);
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION, p, plen);

	*ap = a;
	*bp = b;
}

/* ================================================================
 * A advertises + B scans -> B observes one LE Advertising Report.
 * Vol 4 Part E §7.7.65.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_scan_report);
ATF_TC_BODY(test_adv_scan_report, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06, 0x03, 0x03, 0x0f, 0x18 };
	const uint8_t *ev;
	uint8_t p[2];

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_link(a, b);

	/* A advertises (connectable) with a defined address + AD payload. */
	setup_advertiser(a, a_addr, ad, sizeof(ad));

	/* Before B scans, B has seen nothing over the air. */
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE,
	    NULL) == NULL);

	/* B enables scanning: exactly one LE Advertising Report on B. */
	cap_reset(&bcap);
	p[0] = 0x01;	/* enable */
	p[1] = 0x00;	/* filter_duplicates off */
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_SET_SCAN_ENABLE, p, 2);

	ev = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE, NULL);
	ATF_REQUIRE(ev != NULL);
	/* §7.7.65.2 layout: 0x04|0x3E|plen|sub(0x02)|num(1)|etype|atype|
	 * addr(6)|dlen|data|rssi. */
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_PKT, ev[0]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_EVENT_LE, ev[1]);
	ATF_CHECK_EQ((uint8_t)(12 + sizeof(ad)), ev[2]);	/* param_len */
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP, ev[3]);
	ATF_CHECK_EQ(1, ev[4]);					/* num_reports */
	ATF_CHECK_EQ(HCI_LINK_SPEC_ADV_REPORT_ADV_IND, ev[5]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_ADDR_PUBLIC, ev[6]);
	ATF_CHECK_EQ(0, memcmp(&ev[7], a_addr, 6));		/* A's address */
	ATF_CHECK_EQ((uint8_t)sizeof(ad), ev[13]);		/* data length */
	ATF_CHECK_EQ(0, memcmp(&ev[14], ad, sizeof(ad)));	/* AD data */
	/* RSSI is a fixed simulated -70 dBm (0xBA). */
	ATF_CHECK_EQ((uint8_t)-70, ev[14 + sizeof(ad)]);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * B (Central) connects to A (Peripheral): Command Status on the
 * initiator, then an LE Connection Complete on each side with matching
 * handles and the correct roles.  Vol 4 Part E §7.7.15, §7.7.65.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_connect_roles_handles);
ATF_TC_BODY(test_connect_roles_handles, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *cs, *ba, *aa;
	uint16_t bh, ah;

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);

	/* Initiator (B) first gets Command Status (§7.7.15) for the cmd. */
	cs = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_STATUS,
	    NULL);
	ATF_REQUIRE(cs != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_COMMAND_STATUS_PARAM_LEN, cs[2]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, cs[3]);
	ATF_CHECK_EQ(1, cs[4]);					/* num_cmd_pkts */
	ATF_CHECK_EQ(HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION,
	    le16dec(&cs[5]));

	/* Both sides registered exactly one connection. */
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));

	/* Advertising stops on A once connected (§7.8.9). */
	ATF_CHECK_EQ(0, hci_emu_get_adv_enable(a));

	/* Initiator B: Central (role 0x00), peer = A's public address. */
	ba = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE, NULL);
	ATF_REQUIRE(ba != NULL);
	check_conn_complete(ba, HCI_LINK_SPEC_STATUS_SUCCESS, bh,
	    HCI_LINK_SPEC_ROLE_CENTRAL, HCI_LINK_SPEC_ADDR_PUBLIC, a_addr,
	    0x0028, 0x0000, 0x00c8);

	/* Advertiser A: Peripheral (role 0x01), peer = B's public address. */
	aa = cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_LE, NULL);
	ATF_REQUIRE(aa != NULL);
	check_conn_complete(aa, HCI_LINK_SPEC_STATUS_SUCCESS, ah,
	    HCI_LINK_SPEC_ROLE_PERIPHERAL, HCI_LINK_SPEC_ADDR_PUBLIC, b_addr,
	    0x0028, 0x0000, 0x00c8);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * ACL data path: B->A and A->B.  The peer receives the ACL payload with
 * the con_handle rewritten to its own handle; the sender receives a
 * Number Of Completed Packets event.  Vol 4 Part E §5.4.2, §7.7.19.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_acl_exchange);
ATF_TC_BODY(test_acl_exchange, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t payload_b2a[] = { 0x04, 0x00, 0x04, 0x00, 0x10, 0x01 };
	const uint8_t payload_a2b[] = { 0xde, 0xad, 0xbe, 0xef };
	const uint8_t *acl, *ncp;
	uint16_t bh, ah;
	size_t alen;

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));

	/* B -> A. */
	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, bh, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    payload_b2a, sizeof(payload_b2a));

	/* A received the ACL payload with con_handle rewritten to A's. */
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_ACL_PKT, acl[0]);
	ATF_CHECK_EQ(ah, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ(HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_PB(le16dec(&acl[1])));
	ATF_CHECK_EQ((uint16_t)sizeof(payload_b2a), le16dec(&acl[3]));
	ATF_CHECK_EQ((size_t)HCI_LINK_SPEC_ACL_HEADER_LEN +
	    sizeof(payload_b2a), alen);
	ATF_CHECK_EQ(0, memcmp(&acl[5], payload_b2a, sizeof(payload_b2a)));

	/* Sender B got Number Of Completed Packets (§7.7.19). */
	ncp = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_NUM_COMPL_PKTS,
	    NULL);
	ATF_REQUIRE(ncp != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NCP_PARAM_LEN, ncp[2]);
	ATF_CHECK_EQ(1, ncp[3]);				/* num_handles */
	ATF_CHECK_EQ(bh, le16dec(&ncp[4]));			/* handle */
	ATF_CHECK_EQ(1, le16dec(&ncp[6]));			/* completed=1 */

	/* A -> B, opposite direction. */
	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(a, ah, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    payload_a2b, sizeof(payload_a2b));

	acl = cap_find_acl(&bcap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(bh, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ(0, memcmp(&acl[5], payload_a2b, sizeof(payload_a2b)));

	ncp = cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_NUM_COMPL_PKTS,
	    NULL);
	ATF_REQUIRE(ncp != NULL);
	ATF_CHECK_EQ(ah, le16dec(&ncp[4]));
	ATF_CHECK_EQ(1, le16dec(&ncp[6]));

	hci_emu_free(a);
	hci_emu_free(b);
}

/*
 * Two ACL links between the same controllers retain independent handles.
 * HCI framing is bounded by Data_Total_Length; caller trailing bytes are not
 * part of the packet forwarded to the peer (Vol 4 Part E Section 5.4.2).
 */
ATF_TC_WITHOUT_HEAD(test_multiple_connections_routing);
ATF_TC_BODY(test_multiple_connections_routing, tc)
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t first[] = { 0x11, 0x12 };
	const uint8_t second[] = { 0x21, 0x22, 0x23 };
	const uint8_t trailer[] = { 0xde, 0xad };
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t *acl;
	uint8_t p[25], plen, discon[3];
	uint16_t ah0, ah1, bh0, bh1;
	size_t alen;

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah0));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh0));

	setup_advertiser(a, a_addr, ad, sizeof(ad));
	cap_reset(&acap);
	cap_reset(&bcap);
	plen = build_create_conn(p, 0x00, a_addr, 0x00, 0x0028, 0,
	    0x00c8);
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION, p, plen);
	ATF_CHECK_EQ(2, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(2, hci_emu_get_conn_count(b));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 1, &ah1));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 1, &bh1));
	ATF_CHECK(ah0 != ah1);
	ATF_CHECK(bh0 != bh1);

	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, bh0, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    first, sizeof(first));
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(ah0, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ(0, memcmp(&acl[5], first, sizeof(first)));

	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl_with_trailer(b, bh1, second, sizeof(second), trailer,
	    sizeof(trailer));
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(ah1, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ((size_t)HCI_LINK_SPEC_ACL_HEADER_LEN + sizeof(second),
	    alen);
	ATF_CHECK_EQ(0, memcmp(&acl[5], second, sizeof(second)));

	le16enc(discon, bh0);
	discon[2] = HCI_LINK_SPEC_REASON_REMOTE_USER_TERM;
	feed_cmd(b, HCI_LINK_SPEC_OP_DISCONNECT, discon, sizeof(discon));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));

	cap_reset(&acap);
	cap_reset(&bcap);
	feed_acl(b, bh1, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    second, sizeof(second));
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(ah1, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* Two distinct Centrals can concurrently connect to one Peripheral. */
ATF_TC_WITHOUT_HEAD(test_multiple_peer_controllers);
ATF_TC_BODY(test_multiple_peer_controllers, tc)
{
	static const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t c_addr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
	const uint8_t from_b[] = { 0xb1, 0xb2 };
	const uint8_t from_c[] = { 0xc1, 0xc2 };
	struct hci_emu *a, *b, *c;
	struct cap acap, bcap, ccap;
	const uint8_t *acl;
	uint8_t p[25], plen;
	uint16_t ah0, ah1, bh, ch;
	size_t alen;

	cap_reset(&acap);
	cap_reset(&bcap);
	cap_reset(&ccap);
	a = hci_emu_new();
	b = hci_emu_new();
	c = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL && c != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_set_output(c, cap_out, &ccap);
	hci_emu_set_bd_addr(b, b_addr);
	hci_emu_set_bd_addr(c, c_addr);
	hci_emu_link(a, b);
	hci_emu_link(a, c);

	setup_advertiser(a, a_addr, ad, sizeof(ad));
	plen = build_create_conn(p, 0, a_addr, 0, 0x0028, 0, 0x00c8);
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION, p, plen);
	setup_advertiser(a, a_addr, ad, sizeof(ad));
	feed_cmd(c, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION, p, plen);

	ATF_CHECK_EQ(2, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(b));
	ATF_CHECK_EQ(1, hci_emu_get_conn_count(c));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah0));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 1, &ah1));
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	ATF_REQUIRE(hci_emu_get_conn_handle(c, 0, &ch));

	cap_reset(&acap);
	feed_acl(b, bh, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    from_b, sizeof(from_b));
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(ah0, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ(0, memcmp(&acl[5], from_b, sizeof(from_b)));

	cap_reset(&acap);
	feed_acl(c, ch, HCI_LINK_SPEC_LE_PACKET_START,
	    HCI_LINK_SPEC_POINT_TO_POINT,
	    from_c, sizeof(from_c));
	acl = cap_find_acl(&acap, &alen);
	ATF_REQUIRE(acl != NULL);
	ATF_CHECK_EQ(ah1, HCI_LINK_SPEC_HANDLE(le16dec(&acl[1])));
	ATF_CHECK_EQ(0, memcmp(&acl[5], from_c, sizeof(from_c)));

	hci_emu_free(b);
	hci_emu_free(c);
	hci_emu_free(a);
}

/* ================================================================
 * Disconnect (§7.1.6): Command Status on the initiator, then a
 * Disconnection Complete (§7.7.5) on both sides.  Per §7.1.6 the
 * initiator's Reason is Connection Terminated By Local Host (0x16) and
 * the remote's Reason is the value the initiator supplied (0x13).  The
 * connection is torn down on both.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_disconnect);
ATF_TC_BODY(test_disconnect, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t *cs, *bd, *adc;
	uint16_t bh, ah;
	uint8_t p[3];

	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));

	/* B (initiator) disconnects with Reason 0x13 (Remote User Terminated). */
	cap_reset(&acap);
	cap_reset(&bcap);
	le16enc(&p[0], bh);
	p[2] = HCI_LINK_SPEC_REASON_REMOTE_USER_TERM;
	feed_cmd(b, HCI_LINK_SPEC_OP_DISCONNECT, p, 3);

	/* Command Status (§7.7.15) on the initiator. */
	cs = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_STATUS,
	    NULL);
	ATF_REQUIRE(cs != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, cs[3]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_OP_DISCONNECT, le16dec(&cs[5]));

	/* Initiator B: Disconnection Complete, reason 0x16 (§7.1.6, §7.7.5). */
	bd = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL,
	    NULL);
	ATF_REQUIRE(bd != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_DISCON_COMPLETE_PARAM_LEN, bd[2]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, bd[3]);
	ATF_CHECK_EQ(bh, le16dec(&bd[4]));			/* handle */
	ATF_CHECK_EQ(HCI_LINK_SPEC_REASON_LOCAL_HOST_TERM, bd[6]);

	/* Remote A: Disconnection Complete, reason = supplied 0x13 (§7.1.6). */
	adc = cap_find_event(&acap, HCI_LINK_SPEC_NG_HCI_EVENT_DISCON_COMPL,
	    NULL);
	ATF_REQUIRE(adc != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, adc[3]);
	ATF_CHECK_EQ(ah, le16dec(&adc[4]));			/* handle */
	ATF_CHECK_EQ(HCI_LINK_SPEC_REASON_REMOTE_USER_TERM, adc[6]);

	/* Both connection tables are now empty. */
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * Negative: LE_Create_Connection to an address that is not advertising.
 * Model: the command is accepted (Command Status success) but no
 * connection is formed -- it stays pending with no Connection Complete
 * (no radio timer in the emulator; a real controller would eventually
 * time out).  A subsequent LE_Create_Connection_Cancel (§7.8.13)
 * completes and yields an LE Connection Complete with status Unknown
 * Connection Identifier (0x02).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_connect_unknown_addr);
ATF_TC_BODY(test_connect_unknown_addr, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t nope[6]   = { 0x99, 0x99, 0x99, 0x99, 0x99, 0x99 };
	const uint8_t *cs, *cc;
	uint8_t p[25], plen;

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_link(a, b);

	/* A is present and advertising, but at a_addr, not "nope". */
	setup_advertiser(a, a_addr, (const uint8_t[]){ 0x02, 0x01, 0x06 }, 3);

	/* B tries to connect to an address nobody is advertising. */
	cap_reset(&acap);
	cap_reset(&bcap);
	plen = build_create_conn(p, 0x00, nope, 0x00, 0x0028, 0x0000, 0x00c8);
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION, p, plen);

	/* Command Status success, but no connection and no Conn Complete. */
	cs = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_STATUS,
	    NULL);
	ATF_REQUIRE(cs != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, cs[3]);
	ATF_CHECK(cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE,
	    NULL) == NULL);
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(a));
	ATF_CHECK_EQ(0, hci_emu_get_conn_count(b));

	/* Cancel: Command Complete (§7.8.13) then Conn Complete status 0x02. */
	cap_reset(&bcap);
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION_CANCEL, NULL, 0);

	cc = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_COMMAND_COMPL,
	    NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_OP_LE_CREATE_CONNECTION_CANCEL,
	    le16dec(&cc[4]));
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_SUCCESS, cc[6]);

	cc = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE, NULL);
	ATF_REQUIRE(cc != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_CON_COMPL, cc[3]);
	ATF_CHECK_EQ(HCI_LINK_SPEC_STATUS_UNKNOWN_CONNECTION_ID, cc[4]);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * LE Advertising Report Event_Type mapping (§7.7.65.2 vs §7.8.5).
 *
 * The Advertising_Type enumeration of LE_Set_Advertising_Parameters and the
 * Event_Type enumeration of the LE Advertising Report are NOT identical.
 * Advertising_Type 0x04 is ADV_DIRECT_IND (low duty cycle); in a report the
 * value 0x04 is reserved for SCAN_RSP and a directed advertiser is reported
 * with Event_Type 0x01 (ADV_DIRECT_IND).  A scanner that observes a low-duty
 * directed advertiser must therefore see Event_Type 0x01, never 0x04.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_report_directed_event_type);
ATF_TC_BODY(test_adv_report_directed_event_type, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06 };
	const uint8_t *ev;
	uint8_t p[16];

	cap_reset(&acap);
	cap_reset(&bcap);
	a = hci_emu_new();
	b = hci_emu_new();
	ATF_REQUIRE(a != NULL && b != NULL);
	hci_emu_set_output(a, cap_out, &acap);
	hci_emu_set_output(b, cap_out, &bcap);
	hci_emu_set_bd_addr(a, a_addr);
	hci_emu_link(a, b);

	/*
	 * LE_Set_Advertising_Parameters (§7.8.5), 15-byte param block:
	 * interval_min(2)|interval_max(2)|adv_type(1)|own_addr_type(1)|
	 * direct_addr_type(1)|direct_addr(6)|channel_map(1)|filter_policy(1).
	 * Advertising_Type = 0x04 (ADV_DIRECT_IND, low duty cycle).
	 */
	memset(p, 0, 15);
	le16enc(&p[0], 0x00a0);		/* interval_min */
	le16enc(&p[2], 0x00a0);		/* interval_max */
	p[4] = BT_CORE63_LE_ADV_TYPE_DIRECTED_LOW;
	p[5] = BT_CORE63_LE_ADV_OWN_ADDR_PUBLIC;
	p[13] = BT_CORE63_LE_EXT_ADV_CHANNEL_MAP_ALL;
	p[14] = BT_CORE63_LE_ADV_FILTER_POLICY_ALL;
	feed_cmd(a, HCI_LINK_SPEC_OP_LE_SET_ADV_PARAMS, p, 15);

	/* LE_Set_Advertising_Data (§7.8.7). */
	p[0] = (uint8_t)sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, HCI_LINK_SPEC_OP_LE_SET_ADV_DATA, p,
	    (uint8_t)(1 + sizeof(ad)));

	/* Enable advertising, then B scans and observes one report. */
	p[0] = 0x01;
	feed_cmd(a, HCI_LINK_SPEC_OP_LE_SET_ADV_ENABLE, p, 1);

	cap_reset(&bcap);
	p[0] = 0x01;	/* enable scanning */
	p[1] = 0x00;	/* filter duplicates off */
	feed_cmd(b, HCI_LINK_SPEC_OP_LE_SET_SCAN_ENABLE, p, 2);

	ev = cap_find_event(&bcap, HCI_LINK_SPEC_NG_HCI_EVENT_LE, NULL);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(HCI_LINK_SPEC_NG_HCI_LEEV_ADVREP, ev[3]);
	ATF_CHECK_EQ(1, ev[4]);				/* num_reports */
	/*
	 * Event_Type MUST be 0x01 (ADV_DIRECT_IND), NOT the raw Advertising_Type
	 * 0x04 -- which in a report means SCAN_RSP (§7.7.65.2, Table).
	 */
	ATF_CHECK_EQ(HCI_LINK_SPEC_ADV_REPORT_DIRECT_IND, ev[5]);

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_adv_scan_report);
	ATF_TP_ADD_TC(tp, test_connect_roles_handles);
	ATF_TP_ADD_TC(tp, test_acl_exchange);
	ATF_TP_ADD_TC(tp, test_multiple_connections_routing);
	ATF_TP_ADD_TC(tp, test_multiple_peer_controllers);
	ATF_TP_ADD_TC(tp, test_disconnect);
	ATF_TP_ADD_TC(tp, test_connect_unknown_addr);
	ATF_TP_ADD_TC(tp, test_adv_report_directed_event_type);

	return (atf_no_error());
}
