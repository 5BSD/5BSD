/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Adapter runtime-setting and scan-filter HCI emission tests.
 *
 * Drives the parameter seam the operator SCAN / POWER / DISCOVERABLE verbs use —
 * the LE Set [Extended] Scan Parameters / Scan Enable encoders, the discoverable
 * advertising-data flags builder, and the post-scan result filter — and asserts
 * the exact HCI command bytes that reach the controller, captured through the
 * bt_devreq() --wrap seam (same technique as ctl_adv_conn_test.c).  Covers:
 *
 *   - active/passive scan type, interval, window, filter policy -> LE Set Scan
 *     Parameters (§7.8.10) and LE Set Extended Scan Parameters (§7.8.64)
 *   - duplicate-filter flag -> LE Set Scan Enable (power-off scan quiesce, §7.8.11)
 *   - parameter validation (bad interval/window rejected before any I/O)
 *   - general vs limited discoverable Flags AD (CSS Part A §1.3)
 *   - the uuid/rssi/name post-scan result filter predicate
 *
 * Core Spec references: Vol 4 Part E §7.8.10/§7.8.11 (LE Set Scan Parameters /
 * Enable), §7.8.64 (LE Set Extended Scan Parameters); Vol 3 Part C §9.2.3/§9.2.4
 * (general/limited discoverable mode).
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

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

/* ================================================================
 * bt_devreq --wrap seam: capture the outbound command.
 * ================================================================ */
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
		memset(r->rparam, 0, r->rlen);	/* status 0x00 */
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

/* ================================================================
 * LE Set Scan Parameters (legacy) — active/passive + itvl/window.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_params_legacy);
ATF_TC_BODY(scan_params_legacy, tc)
{
	struct hci_scan_params p;

	/* Passive scan, custom interval/window, accept-list policy. */
	hci_scan_params_default(&p);
	p.active = 0;
	p.interval = 0x0200;
	p.window = 0x0100;
	p.filter_policy = 1;

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_PARAMETERS), W.opcode, "scan params opcode");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[0], "passive scan type");
	ATF_CHECK_EQ_MSG(0x0200, le16(&W.cparam[1]), "scan interval");
	ATF_CHECK_EQ_MSG(0x0100, le16(&W.cparam[3]), "scan window");
	ATF_CHECK_EQ_MSG(0x01, W.cparam[6], "accept-list filter policy");

	/* Active scan default. */
	hci_scan_params_default(&p);
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ_MSG(0x01, W.cparam[0], "active scan type");
	ATF_CHECK_EQ_MSG(160, le16(&W.cparam[1]), "default interval 100ms");
	ATF_CHECK_EQ_MSG(80, le16(&W.cparam[3]), "default window 50ms");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[6], "accept-all filter policy");
}

/* ================================================================
 * LE Set Extended Scan Parameters — per-PHY block.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_params_extended);
ATF_TC_BODY(scan_params_extended, tc)
{
	struct hci_scan_params p;

	hci_scan_params_default(&p);
	p.active = 0;
	p.interval = 0x0140;
	p.window = 0x00A0;

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_ext_scan_params(FD, &p, 0x01));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS), W.opcode,
	    "ext scan params opcode");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[1], "accept-all filter policy");
	ATF_CHECK_EQ_MSG(0x01, W.cparam[2], "scanning PHYs = 1M");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[3], "passive scan type (1M block)");
	ATF_CHECK_EQ_MSG(0x0140, le16(&W.cparam[4]), "1M interval");
	ATF_CHECK_EQ_MSG(0x00A0, le16(&W.cparam[6]), "1M window");
}

/* ================================================================
 * Scan parameter validation rejects before any I/O.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_params_validation);
ATF_TC_BODY(scan_params_validation, tc)
{
	struct hci_scan_params p;

	/* Interval below the 0x0004 floor. */
	hci_scan_params_default(&p);
	p.interval = 0x0002;
	p.window = 0x0002;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "bad interval must not emit");

	/* Window larger than interval. */
	hci_scan_params_default(&p);
	p.interval = 0x0080;
	p.window = 0x0100;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);

	/* Same guard on the extended path. */
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_ext_scan_params(FD, &p, 0x01));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);
}

/* ================================================================
 * LE Set Scan Enable — the power-off scan quiesce.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(scan_enable_bytes);
ATF_TC_BODY(scan_enable_bytes, tc)
{

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_enable(FD, 0, 0));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE), W.opcode, "scan enable opcode");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[0], "scan disabled");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[1], "duplicate filter off");

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_scan_enable(FD, 1, 1));
	ATF_CHECK_EQ_MSG(0x01, W.cparam[0], "scan enabled");
	ATF_CHECK_EQ_MSG(0x01, W.cparam[1], "duplicate filter on");
}

/* ================================================================
 * Discoverable Flags AD — general (0x06) vs limited (0x05).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(discoverable_flags);
ATF_TC_BODY(discoverable_flags, tc)
{
	uint8_t buf[31];
	int len;

	/* General discoverable + BR/EDR not supported. */
	len = ble_build_adv_data_flags(buf, sizeof(buf),
	    AD_FLAG_GENERAL_DISC | AD_FLAG_BREDR_NOT_SUPP, "dev", NULL, 0);
	ATF_REQUIRE(len > 3);
	ATF_CHECK_EQ_MSG(0x02, buf[0], "Flags AD length");
	ATF_CHECK_EQ_MSG(0x01, buf[1], "Flags AD type");
	ATF_CHECK_EQ_MSG(0x06, buf[2], "general discoverable flags");

	/* Limited discoverable. */
	len = ble_build_adv_data_flags(buf, sizeof(buf),
	    AD_FLAG_LIMITED_DISC | AD_FLAG_BREDR_NOT_SUPP, "dev", NULL, 0);
	ATF_REQUIRE(len > 3);
	ATF_CHECK_EQ_MSG(0x05, buf[2], "limited discoverable flags");

	/* The default builder keeps general discoverable. */
	len = ble_build_adv_data(buf, sizeof(buf), NULL, NULL, 0);
	ATF_REQUIRE(len >= 3);
	ATF_CHECK_EQ_MSG(0x06, buf[2], "default flags = general discoverable");
}

/* ================================================================
 * Post-scan result filter predicate — uuid / rssi / name.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(result_filter);
ATF_TC_BODY(result_filter, tc)
{
	struct ble_scan_result sr;
	struct ble_scan_filter f;

	memset(&sr, 0, sizeof(sr));
	sr.rssi = -60;
	strlcpy(sr.name, "MyThermometer", sizeof(sr.name));
	sr.has_name = true;
	sr.svc_uuids[0] = 0x1809;	/* Health Thermometer */
	sr.svc_uuids[1] = 0x180F;
	sr.num_svc_uuids = 2;

	/* Empty filter matches everything. */
	memset(&f, 0, sizeof(f));
	ATF_CHECK(ble_scan_result_match(&sr, &f));
	ATF_CHECK(ble_scan_result_match(&sr, NULL));

	/* UUID present -> match; absent -> drop. */
	memset(&f, 0, sizeof(f));
	f.has_uuid = true;
	f.uuid16 = 0x1809;
	ATF_CHECK(ble_scan_result_match(&sr, &f));
	f.uuid16 = 0x181A;
	ATF_CHECK(!ble_scan_result_match(&sr, &f));

	/* RSSI floor. */
	memset(&f, 0, sizeof(f));
	f.has_rssi = true;
	f.rssi_min = -70;
	ATF_CHECK(ble_scan_result_match(&sr, &f));	/* -60 >= -70 */
	f.rssi_min = -50;
	ATF_CHECK(!ble_scan_result_match(&sr, &f));	/* -60 < -50 */

	/* Name substring. */
	memset(&f, 0, sizeof(f));
	f.has_name = true;
	strlcpy(f.name_sub, "Thermo", sizeof(f.name_sub));
	ATF_CHECK(ble_scan_result_match(&sr, &f));
	strlcpy(f.name_sub, "Heart", sizeof(f.name_sub));
	ATF_CHECK(!ble_scan_result_match(&sr, &f));

	/* A device with no name never matches a name filter. */
	sr.has_name = false;
	strlcpy(f.name_sub, "Thermo", sizeof(f.name_sub));
	ATF_CHECK(!ble_scan_result_match(&sr, &f));

	/* All clauses AND together. */
	sr.has_name = true;
	memset(&f, 0, sizeof(f));
	f.has_uuid = true; f.uuid16 = 0x1809;
	f.has_rssi = true; f.rssi_min = -70;
	f.has_name = true; strlcpy(f.name_sub, "Thermo", sizeof(f.name_sub));
	ATF_CHECK(ble_scan_result_match(&sr, &f));
	f.uuid16 = 0x2222;	/* one clause fails -> overall fail */
	ATF_CHECK(!ble_scan_result_match(&sr, &f));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scan_params_legacy);
	ATF_TP_ADD_TC(tp, scan_params_extended);
	ATF_TP_ADD_TC(tp, scan_params_validation);
	ATF_TP_ADD_TC(tp, scan_enable_bytes);
	ATF_TP_ADD_TC(tp, discoverable_flags);
	ATF_TP_ADD_TC(tp, result_filter);

	return (atf_no_error());
}
