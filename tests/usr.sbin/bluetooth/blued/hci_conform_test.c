/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI conformance regression tests.
 *
 * Covers:
 *   P3  — LE Event Mask feature-gated bits (Core Spec Vol 4 Part E §7.8.1):
 *         TX Power Reporting (bit 32), Path Loss Threshold (bit 31),
 *         Subrate Change (bit 34), and the Direction-Finding IQ report bits.
 *   P4  — HCI Set Event Mask Page 2 (§7.3.69): the Authenticated Payload
 *         Timeout Expired event (page-2 bit 23) is programmed.
 *   P16 — anonymous extended advertising reports (§7.7.65.13): Address_Type
 *         0xFF carries no address and must not be reported as public.
 *   P12 — scan Own_Address_Type (Vol 4 Part E §7.8.10): all four values,
 *         exact command layout, and rejection of the reserved range.
 *
 * The controller-command tests interpose bt_devreq() at link time
 * (-Wl,--wrap=bt_devreq), exactly like power_control_test.c.
 */

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

/* ================================================================
 * bt_devreq --wrap seam: capture the outbound command, return a
 * controller Command Complete with status 0x00.
 * ================================================================ */
static struct {
	int		called;
	uint16_t	opcode;
	uint8_t		cparam[64];
	size_t		clen;
	/* Last LE Set Scan Parameters command parameters seen. */
	bool		scan_params_seen;
	size_t		scan_params_len;
	uint8_t		scan_params[8];
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	W.called++;
	W.opcode = r->opcode;
	W.clen = r->clen;
	memset(W.cparam, 0, sizeof(W.cparam));
	if (r->cparam != NULL && r->clen > 0) {
		size_t n = r->clen < sizeof(W.cparam) ? r->clen :
		    sizeof(W.cparam);
		memcpy(W.cparam, r->cparam, n);
	}

	if (r->opcode == NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_PARAMETERS)) {
		W.scan_params_seen = true;
		W.scan_params_len = r->clen;
		memcpy(W.scan_params, r->cparam,
		    r->clen < sizeof(W.scan_params) ? r->clen :
		    sizeof(W.scan_params));
	}

	/* Command Complete: status 0x00 followed by zeroes. */
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	return (0);
}

static void
mock_reset(void)
{

	memset(&W, 0, sizeof(W));
}

/* ================================================================
 * P3 — LE Event Mask feature-gated bits (§7.8.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(le_event_mask_feature_bits);
ATF_TC_BODY(le_event_mask_feature_bits, tc)
{
	uint64_t none, m;

	/* With no optional features, none of the gated bits are set. */
	none = hci_le_default_event_mask(0);
	ATF_CHECK_EQ_MSG(0, none & BT_CORE63_LE_EVTMASK_TX_POWER_REPORT,
	    "TX Power Reporting must be masked off without LE Power Control");
	ATF_CHECK_EQ_MSG(0, none & BT_CORE63_LE_EVTMASK_PATH_LOSS_THRESH,
	    "Path Loss Threshold must be masked off without Path Loss "
	    "Monitoring");
	ATF_CHECK_EQ_MSG(0, none & BT_CORE63_LE_EVTMASK_SUBRATE_CHANGE,
	    "Subrate Change must be masked off without Connection Subrating");

	/* LE Power Control -> TX Power Reporting (subevent 0x21, bit 32). */
	m = hci_le_default_event_mask(BT_CORE63_LE_FEAT_POWER_CONTROL);
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_TX_POWER_REPORT) != 0,
	    "TX Power Reporting must be unmasked with LE Power Control");

	/* Path Loss Monitoring -> Path Loss Threshold (0x20, bit 31). */
	m = hci_le_default_event_mask(BT_CORE63_LE_FEAT_PATH_LOSS_MONITORING);
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_PATH_LOSS_THRESH) != 0,
	    "Path Loss Threshold must be unmasked with Path Loss Monitoring");

	/* Connection Subrating -> Subrate Change (0x23, bit 34). */
	m = hci_le_default_event_mask(BT_CORE63_LE_FEAT_CONN_SUBRATING);
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_SUBRATE_CHANGE) != 0,
	    "Subrate Change must be unmasked with Connection Subrating");

	/* Connection CTE -> Connection IQ Report + CTE Request Failed. */
	m = hci_le_default_event_mask(BT_CORE63_LE_FEAT_CONN_CTE_REQ);
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_CONN_IQ_REPORT) != 0,
	    "Connection IQ Report must be unmasked with Connection CTE");
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_CTE_REQ_FAILED) != 0,
	    "CTE Request Failed must be unmasked with Connection CTE");

	/* Connectionless CTE -> Connectionless IQ Report. */
	m = hci_le_default_event_mask(BT_CORE63_LE_FEAT_CONNLESS_CTE_RX);
	ATF_CHECK_MSG((m & BT_CORE63_LE_EVTMASK_CONNLESS_IQ_REPORT) != 0,
	    "Connectionless IQ Report must be unmasked with connectionless "
	    "CTE");
}

/* ================================================================
 * P4 — Set Event Mask Page 2 programs APTO and Encryption Change v2 (§7.3.69)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(event_mask_page2_apto);
ATF_TC_BODY(event_mask_page2_apto, tc)
{
	uint64_t expected;
	int i, rc;

	mock_reset();
	expected = BT_CORE63_HCI_EVENT_MASK_PAGE2_DEFAULT;
	rc = hci_set_event_mask_page2(FD, expected);
	ATF_CHECK_EQ(0, rc);

	ATF_CHECK_EQ_MSG(1, W.called, "one command must be issued");
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
	    BT_CORE63_HCI_SET_EVENT_MASK_PAGE2_OCF), W.opcode,
	    "opcode must be Set Event Mask Page 2 (0x0C63)");
	ATF_CHECK_EQ_MSG(8, W.clen, "page-2 mask is 8 octets");

	for (i = 0; i < 8; i++)
		ATF_CHECK_EQ_MSG((expected >> (i * 8)) & 0xff,
		    W.cparam[i], "page-2 mask octet %d", i);
}

/* ================================================================
 * P16 — anonymous extended advertising report (§7.7.65.13)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_adv_anonymous_no_address);
ATF_TC_BODY(ext_adv_anonymous_no_address, tc)
{
	static const uint8_t address[BT_CORE63_EXT_ADV_ADDRESS_SIZE] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66
	};
	static const struct {
		uint8_t wire_type;
		uint8_t internal_type;
	} addressed[] = {
		{ BT_CORE63_EXT_ADV_ADDR_PUBLIC, BDADDR_LE_PUBLIC },
		{ BT_CORE63_EXT_ADV_ADDR_RANDOM, BDADDR_LE_RANDOM },
		{ BT_CORE63_EXT_ADV_ADDR_PUBLIC_IDENTITY, BDADDR_LE_PUBLIC },
		{ BT_CORE63_EXT_ADV_ADDR_RANDOM_IDENTITY, BDADDR_LE_RANDOM },
	};
	uint8_t report[BT_CORE63_EXT_ADV_FIXED_SIZE];
	struct ble_scan_result sr;
	size_t consumed;
	uint8_t zero[BT_CORE63_EXT_ADV_ADDRESS_SIZE] = { 0 };
	size_t i;

	/*
	 * Core 6.3 Vol 4 Part E §7.7.65.13: Address_Type 0xFF means no
	 * address is provided and the six Address octets do not identify a peer.
	 */
	memset(report, 0, sizeof(report));
	report[BT_CORE63_EXT_ADV_PRIMARY_PHY_OFFSET] =
	    BT_CORE63_EXT_ADV_PRIMARY_PHY_1M;
	report[BT_CORE63_EXT_ADV_ADDRESS_TYPE_OFFSET] =
	    BT_CORE63_EXT_ADV_ADDR_ANONYMOUS;
	/* 0xAB is a non-normative poison marker that must not be copied. */
	memset(report + BT_CORE63_EXT_ADV_ADDRESS_OFFSET, 0xAB,
	    BT_CORE63_EXT_ADV_ADDRESS_SIZE);
	report[BT_CORE63_EXT_ADV_DATA_LENGTH_OFFSET] =
	    BT_CORE63_EXT_ADV_DATA_LENGTH_MIN;

	memset(&sr, 0, sizeof(sr));
	consumed = hci_parse_ext_adv_report(report, sizeof(report), &sr);
	ATF_CHECK_MSG(consumed == sizeof(report), "report must be consumed");

	/* The garbage address must not be carried through. */
	ATF_CHECK_MSG(memcmp(sr.addr, zero, sizeof(zero)) == 0,
	    "anonymous report must not copy the ignored address octets");
	ATF_CHECK_EQ_MSG(BLE_SCAN_ADDR_ANONYMOUS, sr.addr_type,
	    "anonymous report must use the non-device internal sentinel");
	ATF_CHECK_MSG(sr.addr_type != BDADDR_LE_PUBLIC,
	    "anonymous report must not be classified as a public device");
	ATF_CHECK_MSG(sr.addr_type != BDADDR_LE_RANDOM,
	    "anonymous report must not be classified as a random device");

	/* Exercise every address-bearing value in the same normative table. */
	/* The address octets are a non-normative distinguishable test vector. */
	for (i = 0; i < sizeof(addressed) / sizeof(addressed[0]); i++) {
		memset(report, 0, sizeof(report));
		report[BT_CORE63_EXT_ADV_PRIMARY_PHY_OFFSET] =
		    BT_CORE63_EXT_ADV_PRIMARY_PHY_1M;
		report[BT_CORE63_EXT_ADV_ADDRESS_TYPE_OFFSET] =
		    addressed[i].wire_type;
		memcpy(report + BT_CORE63_EXT_ADV_ADDRESS_OFFSET, address,
		    sizeof(address));
		report[BT_CORE63_EXT_ADV_DATA_LENGTH_OFFSET] =
		    BT_CORE63_EXT_ADV_DATA_LENGTH_MIN;

		memset(&sr, 0, sizeof(sr));
		consumed = hci_parse_ext_adv_report(report, sizeof(report), &sr);
		ATF_CHECK_EQ_MSG(sizeof(report), consumed,
		    "address type 0x%02x report must be consumed",
		    addressed[i].wire_type);
		ATF_CHECK_EQ_MSG(addressed[i].internal_type, sr.addr_type,
		    "address type 0x%02x internal classification",
		    addressed[i].wire_type);
		ATF_CHECK_MSG(memcmp(sr.addr, address, sizeof(address)) == 0,
		    "address type 0x%02x must preserve all six octets",
		    addressed[i].wire_type);
	}
}

/* ================================================================
 * P12 — LE Set Scan Parameters Own_Address_Type (§7.8.10)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_own_address_type_privacy);
ATF_TC_BODY(scan_own_address_type_privacy, tc)
{
	static const uint8_t own_address_types[] = {
		BT_CORE63_LE_OWN_ADDR_PUBLIC,
		BT_CORE63_LE_OWN_ADDR_RANDOM,
		BT_CORE63_LE_OWN_ADDR_RPA_PUBLIC_FALLBACK,
		BT_CORE63_LE_OWN_ADDR_RPA_RANDOM_FALLBACK,
	};
	struct ble_scan_result results[4];
	int nres, fd;
	size_t i;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);

	/*
	 * Core 6.3 Vol 4 Part E §7.8.10 defines all four Own_Address_Type
	 * values and the command-field order.  Exercise every value using only
	 * the separately generated oracle for the expected command octet.
	 */
	for (i = 0; i < sizeof(own_address_types); i++) {
		mock_reset();
		hci_scan_set_own_address_type(fd, own_address_types[i]);
		nres = 0;
		(void)hci_le_scan(fd, 0, results, 4, &nres);
		ATF_CHECK_MSG(W.scan_params_seen,
		    "LE Set Scan Parameters must be issued");
		ATF_CHECK_EQ_MSG(BT_CORE63_LE_SCAN_PARAMETERS_SIZE,
		    W.scan_params_len, "exact command parameter length");
		ATF_CHECK_EQ_MSG(own_address_types[i],
		    W.scan_params[BT_CORE63_LE_SCAN_OWN_ADDRESS_TYPE_OFFSET],
		    "Own_Address_Type 0x%02x must occupy its normative octet",
		    own_address_types[i]);
	}

	/* §7.8.10 reserves every value above 0x03; ignore such updates. */
	mock_reset();
	hci_scan_set_own_address_type(fd,
	    BT_CORE63_LE_OWN_ADDR_RESERVED_FIRST);
	nres = 0;
	(void)hci_le_scan(fd, 0, results, 4, &nres);
	ATF_CHECK(W.scan_params_seen);
	ATF_CHECK_EQ_MSG(BT_CORE63_LE_OWN_ADDR_RPA_RANDOM_FALLBACK,
	    W.scan_params[BT_CORE63_LE_SCAN_OWN_ADDRESS_TYPE_OFFSET],
	    "reserved update must preserve the last valid setting");

	close(fd);
}

/* ================================================================
 * L1 — directed advertising carries the Peer_Address (§7.8.5, §7.8.53).
 *
 * ADV_DIRECT_IND (legacy) and a directed extended-advertising event both
 * target a specific peer; the Peer_Address / Direct_Address command fields
 * must carry the target BD_ADDR + type.  Undirected commands must leave the
 * address zero, and a directed request without a target must be rejected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(directed_adv_carries_peer_address);
ATF_TC_BODY(directed_adv_carries_peer_address, tc)
{
	static const uint8_t peer[BT_CORE63_LE_ADV_PEER_ADDRESS_SIZE] =
	    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	static const uint8_t zero[BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_SIZE] = { 0 };
	static const struct {
		uint8_t adv_type;
		uint8_t peer_type;
	} legacy_directed[] = {
		{ BT_CORE63_LE_ADV_TYPE_DIRECTED_HIGH,
		    BT_CORE63_LE_ADV_PEER_ADDR_RANDOM },
		{ BT_CORE63_LE_ADV_TYPE_DIRECTED_LOW,
		    BT_CORE63_LE_ADV_PEER_ADDR_PUBLIC },
	};
	uint16_t ext_props;
	size_t i;

	/* The peer octets are a non-normative distinguishable test vector. */
	/*
	 * Core 6.3 Vol 4 Part E §7.8.5: both ADV_DIRECT_IND types require
	 * valid Peer_Address fields.  Offsets, sizes, values, and OCF below
	 * come only from the generated specification oracle.
	 */
	for (i = 0; i < sizeof(legacy_directed) /
	    sizeof(legacy_directed[0]); i++) {
		mock_reset();
		ATF_REQUIRE_EQ(0, hci_le_set_advertising_params_dir(FD,
		    BT_CORE63_LE_ADV_INTERVAL_MIN,
		    BT_CORE63_LE_ADV_INTERVAL_MIN,
		    legacy_directed[i].adv_type,
		    BT_CORE63_LE_ADV_OWN_ADDR_PUBLIC,
		    BT_CORE63_LE_ADV_FILTER_POLICY_ALL,
		    legacy_directed[i].peer_type, peer));
		ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
		    BT_CORE63_LE_SET_ADV_PARAMETERS_OCF), W.opcode,
		    "LE Set Advertising Parameters opcode");
		ATF_CHECK_EQ_MSG(BT_CORE63_LE_ADV_PARAMETERS_SIZE, W.clen,
		    "legacy advertising parameter size");
		ATF_CHECK_EQ_MSG(legacy_directed[i].adv_type,
		    W.cparam[BT_CORE63_LE_ADV_TYPE_OFFSET],
		    "directed advertising type");
		ATF_CHECK_EQ_MSG(legacy_directed[i].peer_type,
		    W.cparam[BT_CORE63_LE_ADV_PEER_ADDRESS_TYPE_OFFSET],
		    "Peer_Address_Type");
		ATF_CHECK_EQ_MSG(0, memcmp(
		    &W.cparam[BT_CORE63_LE_ADV_PEER_ADDRESS_OFFSET], peer,
		    sizeof(peer)), "Peer_Address must carry the target BD_ADDR");
	}

	/* Undirected (plain wrapper) must not populate Direct_Address. */
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_advertising_params(FD,
	    BT_CORE63_LE_ADV_INTERVAL_MIN, BT_CORE63_LE_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_ADV_TYPE_UNDIRECTED,
	    BT_CORE63_LE_ADV_OWN_ADDR_PUBLIC,
	    BT_CORE63_LE_ADV_FILTER_POLICY_ALL));
	ATF_CHECK_EQ_MSG(0, memcmp(
	    &W.cparam[BT_CORE63_LE_ADV_PEER_ADDRESS_OFFSET], zero,
	    BT_CORE63_LE_ADV_PEER_ADDRESS_SIZE),
	    "undirected advertising must leave Peer_Address zero");

	/* Both directed types reject a missing target before controller I/O. */
	for (i = 0; i < sizeof(legacy_directed) /
	    sizeof(legacy_directed[0]); i++) {
		mock_reset();
		errno = 0;
		ATF_CHECK_EQ(-1, hci_le_set_advertising_params_dir(FD,
		    BT_CORE63_LE_ADV_INTERVAL_MIN,
		    BT_CORE63_LE_ADV_INTERVAL_MIN,
		    legacy_directed[i].adv_type,
		    BT_CORE63_LE_ADV_OWN_ADDR_PUBLIC,
		    BT_CORE63_LE_ADV_FILTER_POLICY_ALL,
		    legacy_directed[i].peer_type, NULL));
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_EQ_MSG(0, W.called,
		    "directed adv with no target must not reach controller");
	}

	/*
	 * §7.8.53 Advertising_Event_Properties bits 0 and 2 select a
	 * connectable directed extended event.
	 */
	ext_props = BT_CORE63_LE_EXT_ADV_PROP_CONNECTABLE |
	    BT_CORE63_LE_EXT_ADV_PROP_DIRECTED;
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_ext_adv_params_dir(FD,
	    BT_CORE63_LE_EXT_ADV_HANDLE_MIN, ext_props,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_OWN_ADDR_PUBLIC,
	    BT_CORE63_LE_EXT_ADV_FILTER_POLICY_ALL,
	    BT_CORE63_LE_EXT_ADV_PRIMARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_SECONDARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_PEER_ADDR_PUBLIC, peer));
	ATF_CHECK_EQ_MSG(BT_CORE63_LE_EXT_ADV_PARAMETERS_SIZE, W.clen,
	    "extended advertising parameter size");
	ATF_CHECK_EQ_MSG(ext_props & 0xff,
	    W.cparam[BT_CORE63_LE_EXT_ADV_EVENT_PROPERTIES_OFFSET],
	    "extended advertising properties low octet");
	ATF_CHECK_EQ_MSG(ext_props >> 8,
	    W.cparam[BT_CORE63_LE_EXT_ADV_EVENT_PROPERTIES_OFFSET + 1],
	    "extended advertising properties high octet");
	ATF_CHECK_EQ_MSG(BT_CORE63_LE_EXT_ADV_PEER_ADDR_PUBLIC,
	    W.cparam[BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_TYPE_OFFSET],
	    "Peer_Address_Type");
	ATF_CHECK_EQ_MSG(0, memcmp(
	    &W.cparam[BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_OFFSET], peer,
	    sizeof(peer)),
	    "ext directed adv must carry the Peer_Address");

	/* An undirected extended event must leave the peer field empty. */
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_ext_adv_params_dir(FD,
	    BT_CORE63_LE_EXT_ADV_HANDLE_MIN,
	    BT_CORE63_LE_EXT_ADV_PROP_CONNECTABLE,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_OWN_ADDR_PUBLIC,
	    BT_CORE63_LE_EXT_ADV_FILTER_POLICY_ALL,
	    BT_CORE63_LE_EXT_ADV_PRIMARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_SECONDARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_PEER_ADDR_PUBLIC, peer));
	ATF_CHECK_EQ_MSG(0, memcmp(
	    &W.cparam[BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_OFFSET], zero,
	    BT_CORE63_LE_EXT_ADV_PEER_ADDRESS_SIZE),
	    "ext undirected advertising must leave Peer_Address zero");

	/* Directed ext-adv with no target is rejected. */
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_params_dir(FD,
	    BT_CORE63_LE_EXT_ADV_HANDLE_MIN, ext_props,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_INTERVAL_MIN,
	    BT_CORE63_LE_EXT_ADV_OWN_ADDR_PUBLIC,
	    BT_CORE63_LE_EXT_ADV_FILTER_POLICY_ALL,
	    BT_CORE63_LE_EXT_ADV_PRIMARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_SECONDARY_PHY_1M,
	    BT_CORE63_LE_EXT_ADV_PEER_ADDR_PUBLIC, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called,
	    "ext directed adv with no target must not reach controller");
}

/* ================================================================
 * L3 — peripheral connection-parameter update is feature-gated on the
 * Connection Parameters Request procedure (LE feature bit 1;
 * Core Spec Vol 6 Part B §4.6.2).  Without it the HCI LE Connection Update
 * must not be used (L2CAP signaling fallback path taken).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_param_update_feature_gate);
ATF_TC_BODY(conn_param_update_feature_gate, tc)
{

	/* Feature absent -> HCI path declined (fallback). */
	ATF_CHECK_MSG(!l2cap_conn_param_use_hci_update(0),
	    "no features -> must not use HCI LE Connection Update");
	ATF_CHECK_MSG(!l2cap_conn_param_use_hci_update(
	    BT_CORE63_LE_FEAT_ENCRYPTION | BT_CORE63_LE_FEAT_2M_PHY),
	    "other features without bit 1 -> must not use HCI path");

	/* Feature present -> HCI LE Connection Update path. */
	ATF_CHECK_MSG(l2cap_conn_param_use_hci_update(
	    BT_CORE63_LE_FEAT_CONN_PARAM_REQ),
	    "Connection Parameters Request -> HCI LE Connection Update");
	ATF_CHECK_MSG(l2cap_conn_param_use_hci_update(
	    BT_CORE63_LE_FEAT_ENCRYPTION |
	    BT_CORE63_LE_FEAT_CONN_PARAM_REQ | BT_CORE63_LE_FEAT_2M_PHY),
	    "bit 1 set among others -> HCI path");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, le_event_mask_feature_bits);
	ATF_TP_ADD_TC(tp, event_mask_page2_apto);
	ATF_TP_ADD_TC(tp, ext_adv_anonymous_no_address);
	ATF_TP_ADD_TC(tp, scan_own_address_type_privacy);
	ATF_TP_ADD_TC(tp, directed_adv_carries_peer_address);
	ATF_TP_ADD_TC(tp, conn_param_update_feature_gate);

	return (atf_no_error());
}
