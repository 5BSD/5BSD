/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Advertising / connection parameter HCI emission tests.
 *
 * Drives the parameter seam that the operator verbs use — hci_adv_configure()
 * (SET_ADV_PARAMS) plus the LE Connection Update / Set PHY / Set Data Length
 * encoders (CONNPARAMS_UPDATE / SET_PHY / SET_DATA_LEN) — and asserts the exact
 * HCI command bytes that reach the controller, captured through the bt_devreq()
 * --wrap seam (same technique as hci_conform_test.c).  Covers:
 *
 *   - legacy vs extended path selection against LE_FEAT_EXT_ADVERTISING
 *   - advertising type -> Advertising_Type / Advertising_Event_Properties
 *   - interval / channel map / TX power / PHY / directed peer fields
 *   - extended fallback to legacy when the controller lacks extended adv
 *   - parameter validation (directed requires a peer; bad interval/PHY/channels)
 *   - LE Connection Update / Set PHY / Set Data Length command bytes
 *
 * Core Spec references: Vol 4 Part E §7.8.5 (LE Set Advertising Parameters),
 * §7.8.53 (LE Set Extended Advertising Parameters), §7.8.18 (LE Connection
 * Update), §7.8.49 (LE Set PHY), §7.8.33 (LE Set Data Length).
 */

#include <atf-c.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/endian.h>

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

	/* Command Complete/Status: status 0x00 followed by zeroes. */
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

static uint32_t
le24(const uint8_t *p)
{

	return ((uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16)));
}

/* ================================================================
 * SET_ADV_PARAMS — legacy path (controller without extended adv)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_legacy);
ATF_TC_BODY(adv_params_legacy, tc)
{
	struct hci_adv_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_AUTO;
	cfg.kind = HCI_ADV_SCAN_UND;
	cfg.interval_min = 0x0100;
	cfg.interval_max = 0x0200;
	cfg.channel_map = 0x05;		/* ch37 + ch39 only */
	cfg.tx_power = 0x7F;
	cfg.own_addr_type = 0x00;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;

	mock_reset();
	/* No extended feature -> legacy LE Set Advertising Parameters. */
	ATF_REQUIRE_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK_MSG(!cfg.used_extended, "must take the legacy path");
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS), W.opcode,
	    "legacy advertising parameters opcode");
	ATF_CHECK_EQ_MSG(0x0100, le16(&W.cparam[0]), "interval_min");
	ATF_CHECK_EQ_MSG(0x0200, le16(&W.cparam[2]), "interval_max");
	ATF_CHECK_EQ_MSG(0x02, W.cparam[4], "ADV_SCAN_IND type");
	ATF_CHECK_EQ_MSG(0x05, W.cparam[13], "channel map (ch37+ch39)");
}

/* ================================================================
 * SET_ADV_PARAMS — extended path with PHY, TX power, channel map
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_extended);
ATF_TC_BODY(adv_params_extended, tc)
{
	struct hci_adv_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.interval_min = 0x000140;
	cfg.interval_max = 0x000280;
	cfg.channel_map = 0x07;
	cfg.tx_power = -8;
	cfg.own_addr_type = 0x01;
	cfg.primary_phy = 0x03;		/* Coded */
	cfg.secondary_phy = 0x02;	/* 2M */

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_adv_configure(FD, LE_FEAT_EXT_ADVERTISING, &cfg));
	ATF_CHECK_MSG(cfg.used_extended, "must take the extended path");
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_ADV_PARAMS), W.opcode,
	    "extended advertising parameters opcode");
	/* Connectable undirected -> event property bit0 only. */
	ATF_CHECK_EQ_MSG(0x0001, le16(&W.cparam[1]), "event properties");
	ATF_CHECK_EQ_MSG(0x000140u, le24(&W.cparam[3]), "primary interval min");
	ATF_CHECK_EQ_MSG(0x000280u, le24(&W.cparam[6]), "primary interval max");
	ATF_CHECK_EQ_MSG(0x07, W.cparam[9], "primary channel map");
	ATF_CHECK_EQ_MSG(0x01, W.cparam[10], "own address type");
	ATF_CHECK_EQ_MSG((uint8_t)(-8), W.cparam[19], "advertising TX power");
	ATF_CHECK_EQ_MSG(0x03, W.cparam[20], "primary PHY = Coded");
	ATF_CHECK_EQ_MSG(0x02, W.cparam[22], "secondary PHY = 2M");
}

/* ================================================================
 * SET_ADV_PARAMS — directed extended advertising carries the peer,
 * and the event properties mark connectable+directed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_directed);
ATF_TC_BODY(adv_params_directed, tc)
{
	struct hci_adv_config cfg;
	static const uint8_t peer[6] =
	    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.kind = HCI_ADV_CONN_DIR_LOW;
	cfg.interval_min = 0x000020;
	cfg.interval_max = 0x000020;
	cfg.channel_map = 0x07;
	cfg.tx_power = 0x7F;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	cfg.has_peer = true;
	cfg.peer_addr_type = 0x01;	/* random target */
	memcpy(cfg.peer_addr, peer, 6);

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_adv_configure(FD, LE_FEAT_EXT_ADVERTISING, &cfg));
	/* connectable(0x01) + directed(0x04) low duty = 0x0005. */
	ATF_CHECK_EQ_MSG(0x0005, le16(&W.cparam[1]),
	    "connectable + directed event properties");
	ATF_CHECK_EQ_MSG(0x01, W.cparam[11], "peer address type");
	ATF_CHECK_EQ_MSG(0, memcmp(&W.cparam[12], peer, 6),
	    "peer address carried");

	/* Legacy directed maps to ADV_DIRECT_IND high (0x01) and carries the
	 * Direct_Address. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_LEGACY;
	cfg.kind = HCI_ADV_CONN_DIR_HIGH;
	cfg.interval_min = 0x0020;
	cfg.interval_max = 0x0020;
	cfg.channel_map = 0x07;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	cfg.has_peer = true;
	cfg.peer_addr_type = 0x00;
	memcpy(cfg.peer_addr, peer, 6);

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK_EQ_MSG(0x01, W.cparam[4], "ADV_DIRECT_IND high duty type");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[6], "Direct_Address_Type");
	ATF_CHECK_EQ_MSG(0, memcmp(&W.cparam[7], peer, 6),
	    "Direct_Address carried");
}

/* ================================================================
 * SET_ADV_PARAMS — extended request falls back to legacy when the
 * controller does not support extended advertising.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_ext_fallback);
ATF_TC_BODY(adv_params_ext_fallback, tc)
{
	struct hci_adv_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.kind = HCI_ADV_NONCONN_UND;
	cfg.interval_min = 0x00A0;
	cfg.interval_max = 0x00A0;
	cfg.channel_map = 0x07;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK_MSG(!cfg.used_extended,
	    "extended request must fall back to legacy without the feature");
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_ADVERTISING_PARAMETERS), W.opcode,
	    "fallback uses the legacy opcode");
	ATF_CHECK_EQ_MSG(0x03, W.cparam[4], "ADV_NONCONN_IND type");
}

/* ================================================================
 * SET_ADV_PARAMS — parameter validation rejects before any I/O.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_params_validation);
ATF_TC_BODY(adv_params_validation, tc)
{
	struct hci_adv_config cfg;

	/* Directed kind with no peer. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.kind = HCI_ADV_CONN_DIR_LOW;
	cfg.interval_min = 0x000020;
	cfg.interval_max = 0x000020;
	cfg.channel_map = 0x07;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, LE_FEAT_EXT_ADVERTISING, &cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ_MSG(0, W.called, "directed without peer must not emit");

	/* Empty channel map. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.interval_min = 0x00A0;
	cfg.interval_max = 0x00A0;
	cfg.channel_map = 0x00;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);

	/* Invalid primary PHY (2M is not valid on the primary channel). */
	memset(&cfg, 0, sizeof(cfg));
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.interval_min = 0x00A0;
	cfg.interval_max = 0x00A0;
	cfg.channel_map = 0x07;
	cfg.primary_phy = 0x02;
	cfg.secondary_phy = 0x01;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, LE_FEAT_EXT_ADVERTISING, &cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);

	/* own_addr_type out of range. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.interval_min = 0x00A0;
	cfg.interval_max = 0x00A0;
	cfg.channel_map = 0x07;
	cfg.own_addr_type = 0x04;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);
}

/* ================================================================
 * CONNPARAMS_UPDATE — LE Connection Update command bytes + gate.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_update_bytes);
ATF_TC_BODY(conn_update_bytes, tc)
{

	mock_reset();
	/* min=0x0018 max=0x0028 latency=0x0004 timeout=0x0064. */
	ATF_REQUIRE_EQ(0, hci_le_connection_update(FD, 0x0040, 0x0018, 0x0028,
	    0x0004, 0x0064));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CONNECTION_UPDATE), W.opcode, "conn update opcode");
	ATF_CHECK_EQ_MSG(0x0040, le16(&W.cparam[0]), "connection handle");
	ATF_CHECK_EQ_MSG(0x0018, le16(&W.cparam[2]), "interval min");
	ATF_CHECK_EQ_MSG(0x0028, le16(&W.cparam[4]), "interval max");
	ATF_CHECK_EQ_MSG(0x0004, le16(&W.cparam[6]), "latency");
	ATF_CHECK_EQ_MSG(0x0064, le16(&W.cparam[8]), "supervision timeout");

	/* The verb feature-gates on this predicate (Core Spec Vol 6 Part B
	 * §4.6.2): no Connection Parameters Request procedure -> decline. */
	ATF_CHECK_MSG(!l2cap_conn_param_use_hci_update(0),
	    "no features -> HCI update declined");
	ATF_CHECK_MSG(l2cap_conn_param_use_hci_update(LE_FEAT_CONN_PARAM_REQ),
	    "feature present -> HCI update permitted");

	/* Out-of-range interval is rejected before any I/O. */
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_connection_update(FD, 0x0040, 0x0005, 0x0028,
	    0x0004, 0x0064));
	ATF_CHECK_EQ(0, W.called);
}

/* ================================================================
 * SET_PHY — LE Set PHY command bytes.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_phy_bytes);
ATF_TC_BODY(set_phy_bytes, tc)
{

	mock_reset();
	/* tx=1M|2M (0x03), rx=2M (0x02); both preferences present -> all=0. */
	ATF_REQUIRE_EQ(0, hci_le_set_phy(FD, 0x0041, 0x00, 0x03, 0x02, 0x0000));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_PHY),
	    W.opcode, "set PHY opcode");
	ATF_CHECK_EQ_MSG(0x0041, le16(&W.cparam[0]), "connection handle");
	ATF_CHECK_EQ_MSG(0x00, W.cparam[2], "all_phys");
	ATF_CHECK_EQ_MSG(0x03, W.cparam[3], "tx_phys mask");
	ATF_CHECK_EQ_MSG(0x02, W.cparam[4], "rx_phys mask");

	/* A zero mask means "no preference": all_phys carries the bit. */
	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_phy(FD, 0x0041, 0x01, 0x00, 0x04, 0x0000));
	ATF_CHECK_EQ_MSG(0x01, W.cparam[2], "all_phys: no TX preference");
	ATF_CHECK_EQ_MSG(0x04, W.cparam[4], "rx_phys = Coded");
}

/* ================================================================
 * SET_DATA_LEN — LE Set Data Length command bytes + validation.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_data_len_bytes);
ATF_TC_BODY(set_data_len_bytes, tc)
{

	mock_reset();
	ATF_REQUIRE_EQ(0, hci_le_set_data_length(FD, 0x0042, 0x00FB, 0x0848));
	ATF_CHECK_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_DATA_LENGTH), W.opcode, "set data length opcode");
	ATF_CHECK_EQ_MSG(0x0042, le16(&W.cparam[0]), "connection handle");
	ATF_CHECK_EQ_MSG(0x00FB, le16(&W.cparam[2]), "tx_octets");
	ATF_CHECK_EQ_MSG(0x0848, le16(&W.cparam[4]), "tx_time");

	/* tx_octets below the 0x001B floor is rejected before any I/O. */
	mock_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_data_length(FD, 0x0042, 0x0010, 0x0848));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.called);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, adv_params_legacy);
	ATF_TP_ADD_TC(tp, adv_params_extended);
	ATF_TP_ADD_TC(tp, adv_params_directed);
	ATF_TP_ADD_TC(tp, adv_params_ext_fallback);
	ATF_TP_ADD_TC(tp, adv_params_validation);
	ATF_TP_ADD_TC(tp, conn_update_bytes);
	ATF_TP_ADD_TC(tp, set_phy_bytes);
	ATF_TP_ADD_TC(tp, set_data_len_bytes);

	return (atf_no_error());
}
