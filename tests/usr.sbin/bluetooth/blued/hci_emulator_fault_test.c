/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection coverage for the allocator FAILURE arms of the HCI
 * emulator (hci_emulator.c).
 *
 *   hci_emu_new():       calloc() == NULL -> return NULL   (hci_emulator.c:381)
 *   ACL-data forwarding: malloc() == NULL -> drop packet   (hci_emulator.c:1489)
 *
 * calloc() is referenced from exactly one site (the emulator-object
 * allocation in hci_emu_new()) and malloc() from exactly one site (the
 * per-packet scratch buffer on the ACL forward path), so a counted --wrap(3)
 * seam can target each failure precisely without disturbing setup.  --wrap
 * only redirects the references emitted from hci_emulator.o and this test
 * object; libc/ATF internal allocations are unaffected.
 *
 * Oracle: hci_emulator.h documents hci_emu_new() as returning a struct
 * hci_emu * or NULL, and the ACL forward path as delivering the rewritten
 * packet to the peer.  Under allocation failure the observable contract is a
 * NULL emulator and, respectively, a silently dropped ACL packet (the peer
 * receives nothing) with no crash.
 *
 * Links with: hci_emulator.c
 * LDFLAGS: -Wl,--wrap=malloc -Wl,--wrap=calloc
 */

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hci_emulator.h"
#include "spec_hci_emulator_fault_oracles.h"

static void
assert_hci_emulator_wire_contract(void)
{
	ATF_CHECK_EQ(BT_CORE63_HCI_COMMAND_PACKET, NG_HCI_CMD_PKT);
	ATF_CHECK_EQ(BT_CORE63_HCI_ACL_PACKET, NG_HCI_ACL_DATA_PKT);
	ATF_CHECK_EQ(BT_CORE63_HCI_OGF_LE, NG_HCI_OGF_LE);
	ATF_CHECK_EQ(BT_CORE63_HCI_OCF_LE_SET_ADV_DATA,
	    NG_HCI_OCF_LE_SET_ADVERTISING_DATA);
	ATF_CHECK_EQ(BT_CORE63_HCI_OCF_LE_SET_ADV_ENABLE,
	    NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE);
	ATF_CHECK_EQ(BT_CORE63_HCI_OCF_LE_SET_SCAN_ENABLE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	ATF_CHECK_EQ(BT_CORE63_HCI_OCF_LE_CREATE_CONNECTION,
	    NG_HCI_OCF_LE_CREATE_CONNECTION);
	ATF_CHECK_EQ(BT_CORE63_HCI_ACL_PB_FIRST_NONFLUSH,
	    NG_HCI_LE_PACKET_START);
	ATF_CHECK_EQ(BT_CORE63_HCI_ACL_BC_POINT_TO_POINT, NG_HCI_POINT2POINT);
}

/* ================================================================
 * Fault-injection seams (fail the Nth 1-based call when armed).
 * ================================================================ */
static long	fi_malloc_at, fi_malloc_n;
static long	fi_calloc_at, fi_calloc_n;

static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

static void
fault_reset(void)
{

	fi_malloc_at = fi_malloc_n = 0;
	fi_calloc_at = fi_calloc_n = 0;
}

extern void	*__real_malloc(size_t);
void *
__wrap_malloc(size_t size)
{

	if (fi_hit(&fi_malloc_at, &fi_malloc_n)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

extern void	*__real_calloc(size_t, size_t);
void *
__wrap_calloc(size_t nmemb, size_t size)
{

	if (fi_hit(&fi_calloc_at, &fi_calloc_n)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(nmemb, size));
}

/* ================================================================
 * Minimal capture + link/connect harness (mirrors the link test).
 * ================================================================ */
#define	OP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define	OP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define	OP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define	OP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)

struct cap {
	int		n;
	uint8_t		pkt[64][512];
	size_t		len[64];
};

static void
cap_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct cap *c = ctx;

	if (c->n < 64 && len <= sizeof(c->pkt[0])) {
		memcpy(c->pkt[c->n], pkt, len);
		c->len[c->n] = len;
		c->n++;
	}
}

static void
cap_reset(struct cap *c)
{

	memset(c, 0, sizeof(*c));
}

static int
cap_has_acl(const struct cap *c)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= 1 && c->pkt[i][0] == NG_HCI_ACL_DATA_PKT)
			return (1);
	return (0);
}

static int
cap_acl_index(const struct cap *c)
{
	int i;

	for (i = 0; i < c->n; i++)
		if (c->len[i] >= BT_CORE63_HCI_ACL_HEADER_SIZE &&
		    c->pkt[i][0] == BT_CORE63_HCI_ACL_PACKET)
			return (i);
	return (-1);
}

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

static void
feed_acl(struct hci_emu *e, uint16_t handle, const uint8_t *data, uint16_t dlen)
{
	uint8_t buf[512];

	buf[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&buf[1], NG_HCI_MK_CON_HANDLE(handle, NG_HCI_LE_PACKET_START,
	    NG_HCI_POINT2POINT));
	le16enc(&buf[3], dlen);
	if (dlen != 0)
		memcpy(&buf[5], data, dlen);
	hci_emu_input(e, buf, (size_t)5 + dlen);
}

static uint8_t
build_create_conn(uint8_t p[25], const uint8_t peer_addr[6])
{

	memset(p, 0, BT_CORE63_LE_CREATE_CONNECTION_PARAM_SIZE);
	le16enc(&p[0], 0x0060);
	le16enc(&p[2], 0x0030);
	p[4] = 0x00;
	p[5] = 0x00;			/* peer public */
	memcpy(&p[6], peer_addr, 6);
	p[12] = 0x00;			/* own public */
	le16enc(&p[13], 0x0028);
	le16enc(&p[15], 0x0028);
	le16enc(&p[17], 0x0000);
	le16enc(&p[19], 0x00c8);
	return (BT_CORE63_LE_CREATE_CONNECTION_PARAM_SIZE);
}

/* Bring up a fully-linked A(adv)<->B(init) connection.  Seams disarmed. */
static void
link_and_connect(struct hci_emu **ap, struct hci_emu **bp,
    struct cap *acap, struct cap *bcap, const uint8_t a_addr[6],
    const uint8_t b_addr[6])
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
	hci_emu_set_bd_addr(a, a_addr);
	hci_emu_set_bd_addr(b, b_addr);
	hci_emu_link(a, b);

	p[0] = (uint8_t)sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(a, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = 0x01;
	feed_cmd(a, OP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = 0x01; p[1] = 0x00;
	feed_cmd(b, OP_LE_SET_SCAN_ENABLE, p, 2);

	plen = build_create_conn(p, a_addr);
	feed_cmd(b, OP_LE_CREATE_CONNECTION, p, plen);

	*ap = a;
	*bp = b;
}

/* ================================================================
 * hci_emu_new(): calloc() fails -> NULL emulator.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_emu_new_calloc_fails);
ATF_TC_BODY(fault_emu_new_calloc_fails, tc)
{
	struct hci_emu *e;

	assert_hci_emulator_wire_contract();
	fault_reset();

	/* calloc is referenced only by hci_emu_new(); fail its allocation. */
	fi_calloc_n = 0;
	fi_calloc_at = 1;
	e = hci_emu_new();
	fi_calloc_at = 0;

	ATF_CHECK(e == NULL);
}

/* ================================================================
 * ACL forward: the per-packet malloc() fails -> the packet is dropped
 * and the peer receives no ACL data.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_acl_forward_malloc_fails);
ATF_TC_BODY(fault_acl_forward_malloc_fails, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	uint16_t bh;

	assert_hci_emulator_wire_contract();
	fault_reset();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));

	/* Arm the forward-buffer malloc to fail on the next ACL packet. */
	cap_reset(&acap);
	fi_malloc_n = 0;
	fi_malloc_at = 1;
	feed_acl(b, bh, payload, sizeof(payload));
	fi_malloc_at = 0;

	/* buf == NULL -> forward path returns early: A gets no ACL. */
	ATF_CHECK(!cap_has_acl(&acap));

	hci_emu_free(a);
	hci_emu_free(b);
}

/* ================================================================
 * Control: with the seams disarmed the same ACL packet is delivered.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_acl_forward_ok_when_disarmed);
ATF_TC_BODY(fault_acl_forward_ok_when_disarmed, tc)
{
	struct hci_emu *a, *b;
	struct cap acap, bcap;
	const uint8_t a_addr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };
	const uint8_t b_addr[6] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5 };
	const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	uint16_t ah, bh, wire_handle, wire_len;
	int acl_index;

	assert_hci_emulator_wire_contract();
	fault_reset();
	link_and_connect(&a, &b, &acap, &bcap, a_addr, b_addr);
	ATF_REQUIRE(hci_emu_get_conn_handle(b, 0, &bh));
	ATF_REQUIRE(hci_emu_get_conn_handle(a, 0, &ah));

	cap_reset(&acap);
	feed_acl(b, bh, payload, sizeof(payload));

	ATF_CHECK(cap_has_acl(&acap));
	acl_index = cap_acl_index(&acap);
	ATF_REQUIRE(acl_index >= 0);
	ATF_REQUIRE_EQ(BT_CORE63_HCI_ACL_HEADER_SIZE + sizeof(payload),
	    acap.len[acl_index]);
	wire_handle = le16dec(&acap.pkt[acl_index][1]);
	wire_len = le16dec(&acap.pkt[acl_index][3]);
	ATF_CHECK_EQ(ah, wire_handle & BT_CORE63_HCI_ACL_HANDLE_MASK);
	ATF_CHECK_EQ(0, wire_handle & ~BT_CORE63_HCI_ACL_HANDLE_MASK);
	ATF_CHECK_EQ(sizeof(payload), wire_len);
	ATF_CHECK_EQ(0, memcmp(&acap.pkt[acl_index][5], payload,
	    sizeof(payload)));

	hci_emu_free(a);
	hci_emu_free(b);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_emu_new_calloc_fails);
	ATF_TP_ADD_TC(tp, fault_acl_forward_malloc_fails);
	ATF_TP_ADD_TC(tp, fault_acl_forward_ok_when_disarmed);

	return (atf_no_error());
}
