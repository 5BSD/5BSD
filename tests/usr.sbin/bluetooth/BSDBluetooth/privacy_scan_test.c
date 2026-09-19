/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Runtime-privacy HCI emission tests.  Drives the primitives the PRIVACY /
 * RPA_TIMEOUT verbs use — LE Set Address Resolution Enable, LE Set RPA Timeout,
 * and the scan own-address-type threading — and asserts the exact command bytes
 * that reach the controller through the bt_devreq() --wrap seam (same technique
 * as ctl_adv_conn_test.c).  Proves PRIVACY on/off flips the scan path's
 * own-address type consistently.
 *
 * Core Spec references: Vol 6 Part B §6.4 (privacy), Vol 4 Part E §7.8.44 (Set
 * Address Resolution Enable), §7.8.45 (Set RPA Timeout), §7.8.10 (Set Scan
 * Parameters).
 */

#include <atf-c.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_privacy_scan_oracles.h"

atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Non-normative descriptor sentinel; no real descriptor is accessed. */
#define FD	3

static struct {
	int		called;
	uint16_t	opcode;
	uint8_t		cparam[64];
	size_t		clen;
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
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	return (0);
}

static void
mock_reset(void)
{

	memset(&W, 0, sizeof(W));
}

static uint16_t
le16(const uint8_t *p)
{

	return ((uint16_t)(p[0] | (p[1] << 8)));
}

static void
assert_privacy_hci_contract(void)
{

	ATF_CHECK_EQ(NG_HCI_OGF_LE, BT_CORE63_HCI_OGF_LE);
	ATF_CHECK_EQ(NG_HCI_OCF_LE_SET_SCAN_PARAMETERS,
	    BT_CORE63_HCI_OCF_LE_SET_SCAN_PARAMETERS);
	ATF_CHECK_EQ(NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE,
	    BT_CORE63_HCI_OCF_LE_SET_ADDR_RES_ENABLE);
	ATF_CHECK_EQ(NG_HCI_OCF_LE_SET_RPA_TIMEOUT,
	    BT_CORE63_HCI_OCF_LE_SET_RPA_TIMEOUT);
}

/* ================================================================
 * PRIVACY on|off -> LE Set Address Resolution Enable.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(addr_resolution_enable);
ATF_TC_BODY(addr_resolution_enable, tc)
{

	assert_privacy_hci_contract();
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_addr_resolution_enable(FD,
	    BT_CORE63_ADDR_RESOLUTION_ENABLED));
	ATF_CHECK_EQ_MSG(BT_CORE63_HCI_OP_LE_SET_ADDR_RES_ENABLE, W.opcode,
	    "set address resolution enable opcode");
	ATF_CHECK_EQ(W.clen, BT_CORE63_SET_ADDR_RES_ENABLE_PARAM_SIZE);
	ATF_CHECK_EQ_MSG(BT_CORE63_ADDR_RESOLUTION_ENABLED, W.cparam[0],
	    "resolution enabled");

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_addr_resolution_enable(FD,
	    BT_CORE63_ADDR_RESOLUTION_DISABLED));
	ATF_CHECK_EQ(BT_CORE63_HCI_OP_LE_SET_ADDR_RES_ENABLE, W.opcode);
	ATF_CHECK_EQ(W.clen, BT_CORE63_SET_ADDR_RES_ENABLE_PARAM_SIZE);
	ATF_CHECK_EQ_MSG(BT_CORE63_ADDR_RESOLUTION_DISABLED, W.cparam[0],
	    "resolution disabled");
}

/* ================================================================
 * RPA_TIMEOUT -> LE Set RPA Timeout bytes + range validation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpa_timeout_bytes);
ATF_TC_BODY(rpa_timeout_bytes, tc)
{

	assert_privacy_hci_contract();
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_rpa_timeout(FD,
	    BT_CORE63_RPA_TIMEOUT_DEFAULT_SECONDS));
	ATF_CHECK_EQ_MSG(BT_CORE63_HCI_OP_LE_SET_RPA_TIMEOUT, W.opcode,
	    "set RPA timeout opcode");
	ATF_CHECK_EQ(W.clen, BT_CORE63_SET_RPA_TIMEOUT_PARAM_SIZE);
	ATF_CHECK_EQ_MSG(BT_CORE63_RPA_TIMEOUT_DEFAULT_SECONDS,
	    le16(&W.cparam[0]), "RPA timeout seconds");

	/* Vol 4 Part E §7.8.45 inclusive accepted boundaries. */
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_rpa_timeout(FD,
	    BT_CORE63_RPA_TIMEOUT_MIN_SECONDS));
	ATF_CHECK_EQ(BT_CORE63_RPA_TIMEOUT_MIN_SECONDS, le16(W.cparam));
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_rpa_timeout(FD,
	    BT_CORE63_RPA_TIMEOUT_MAX_SECONDS));
	ATF_CHECK_EQ(BT_CORE63_RPA_TIMEOUT_MAX_SECONDS, le16(W.cparam));

	/* §7.8.45 adjacent out-of-range values are rejected before I/O. */
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_rpa_timeout(FD,
	    BT_CORE63_RPA_TIMEOUT_BELOW_MIN));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);
	ATF_CHECK_EQ(-1, hci_le_set_rpa_timeout(FD,
	    BT_CORE63_RPA_TIMEOUT_ABOVE_MAX));
	ATF_CHECK_EQ(0, W.called);
}

/* ================================================================
 * Scan own-address type follows the privacy toggle: switching it to RPA
 * (0x02) and back to public (0x00) is reflected in LE Set Scan Parameters.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_own_addr_switch);
ATF_TC_BODY(scan_own_addr_switch, tc)
{
	struct hci_scan_params p;

	assert_privacy_hci_contract();
	/* PRIVACY on -> RPA. */
	hci_scan_set_own_address_type(FD,
	    BT_CORE63_OWN_ADDR_RPA_PUBLIC_FALLBACK);
	hci_scan_params_default(&p);
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ_MSG(BT_CORE63_HCI_OP_LE_SET_SCAN_PARAMETERS, W.opcode,
	    "scan params opcode");
	ATF_CHECK_EQ(W.clen, BT_CORE63_SET_SCAN_PARAMETERS_PARAM_SIZE);
	ATF_CHECK_EQ_MSG(BT_CORE63_OWN_ADDR_RPA_PUBLIC_FALLBACK,
	    W.cparam[BT_CORE63_SCAN_OWN_ADDR_TYPE_OFFSET],
	    "own address type = RPA after PRIVACY on");

	/* PRIVACY off -> public, reverting the scan path. */
	hci_scan_set_own_address_type(FD, BT_CORE63_OWN_ADDR_PUBLIC);
	hci_scan_params_default(&p);
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ_MSG(BT_CORE63_OWN_ADDR_PUBLIC,
	    W.cparam[BT_CORE63_SCAN_OWN_ADDR_TYPE_OFFSET],
	    "own address type = public after PRIVACY off");
}

ATF_TC_WITHOUT_HEAD(scan_own_addr_is_per_adapter);
ATF_TC_BODY(scan_own_addr_is_per_adapter, tc)
{
	struct hci_scan_params p;

	assert_privacy_hci_contract();
	hci_scan_params_default(&p);
	hci_scan_set_own_address_type(FD,
	    BT_CORE63_OWN_ADDR_RPA_PUBLIC_FALLBACK);
	hci_scan_set_own_address_type(FD + 1, BT_CORE63_OWN_ADDR_PUBLIC);
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(BT_CORE63_OWN_ADDR_RPA_PUBLIC_FALLBACK,
	    W.cparam[BT_CORE63_SCAN_OWN_ADDR_TYPE_OFFSET]);
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD + 1, &p));
	ATF_CHECK_EQ(BT_CORE63_OWN_ADDR_PUBLIC,
	    W.cparam[BT_CORE63_SCAN_OWN_ADDR_TYPE_OFFSET]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, addr_resolution_enable);
	ATF_TP_ADD_TC(tp, rpa_timeout_bytes);
	ATF_TP_ADD_TC(tp, scan_own_addr_switch);
	ATF_TP_ADD_TC(tp, scan_own_addr_is_per_adapter);

	return (atf_no_error());
}
