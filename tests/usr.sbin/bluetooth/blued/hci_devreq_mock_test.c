/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI command success/failure path coverage via a linker --wrap seam.
 *
 * The HCI command encoders in hci_{adv,conn,privacy,misc}.c reach the
 * controller through hci_devreq_logged() -> hci_devreq_logged_locked()
 * (hci_util.c) -> bt_devreq() (libbluetooth).  A plain socketpair cannot
 * exercise the post-I/O arms of these encoders because bt_devreq() bails
 * out at bt_devfilter()->getsockopt(SOL_HCI_RAW) on a non-HCI fd.
 *
 * Those arms — the "controller returned status != 0x00" rejection and the
 * "return 0" success tail (plus the return-parameter extraction the READ
 * commands perform) — are live, spec-relevant code: the normal completion
 * path of every command.  Here we interpose bt_devreq at link time
 * (-Wl,--wrap=bt_devreq) with a test-controlled controller response so the
 * encoder runs its validation, then reaches:
 *
 *     if (hci_devreq_logged(fd, &r, to) < 0)   return (-1);  // transport
 *     if (rp.status != 0x00) { errno = EIO;    return (-1); } // rejection
 *     ... extract rp.<field> ...
 *     return (0);                                             // success
 *
 * Every expected return-parameter layout below is hand-encoded from the
 * Bluetooth Core Specification Vol 4 Part E §7 (cited per command); the
 * assertions check the encoder's extraction against the spec byte layout,
 * never against captured implementation output.
 *
 * struct bt_devreq (verified in /usr/src/lib/libbluetooth/bluetooth.h):
 *     uint16_t opcode; uint8_t event; void *cparam; size_t clen;
 *     void *rparam; size_t rlen;
 * Real bt_devreq fills rparam with up to rlen bytes of the Command Complete
 * return parameters (status byte first) and returns 0; on error it returns
 * -1 with errno set.  __wrap_bt_devreq reproduces exactly that contract.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

/* Any non-negative fd works: __wrap_bt_devreq ignores it and BTSnoop
 * logging is inactive, so no real socket operation is performed. */
#define FD	3

/* ================================================================
 * The --wrap seam: a test-controlled stand-in for bt_devreq().
 * ================================================================ */
static struct {
	int		fail;		/* nonzero -> return -1, errno=fail_errno */
	int		fail_errno;
	int		call_count;
	int		fail_at;	/* one-shot transport failure at this call */
	uint8_t		payload[320];	/* return params, status byte first */
	size_t		payload_len;
	size_t		last_clen;	/* captured command-parameter length */
	uint16_t	last_opcode;	/* captured request opcode */
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	/* Capture the on-wire command framing for length assertions. */
	W.last_clen = r->clen;
	W.last_opcode = r->opcode;

	W.call_count++;
	if (W.fail || (W.fail_at != 0 && W.call_count == W.fail_at)) {
		errno = W.fail_errno;
		return (-1);
	}
	/* Mirror bt_devreq's Command Complete contract: copy up to rlen
	 * bytes of return parameters into the caller-supplied rp buffer. */
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = W.payload_len < r->rlen ? W.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, W.payload, n);
	}
	return (0);
}

/* Controller returns a Command Complete carrying return-parameter bytes. */
static void
mock_ok_bytes(const void *p, size_t n)
{
	W.fail = 0;
	W.call_count = 0;
	W.fail_at = 0;
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

/* Controller accepts: status 0x00, no further return parameters. */
static void
mock_ok(void)
{
	uint8_t st = 0x00;

	mock_ok_bytes(&st, 1);
}

/* Controller rejects with status 0x0C = Command Disallowed
 * (Core Spec Vol 1 Part F §1.3 error code table). */
static void
mock_status_bad(void)
{
	uint8_t st = 0x0C;

	mock_ok_bytes(&st, 1);
}

/* Transport failure: bt_devreq itself fails (e.g. recv error). */
static void
mock_xport_fail(int e)
{
	W.fail = 1;
	W.fail_errno = e;
	W.call_count = 0;
	W.fail_at = 0;
}

static void
mock_xport_fail_at(int ordinal, int e)
{

	mock_ok();
	W.fail_at = ordinal;
	W.fail_errno = e;
}

/*
 * Three-arm coverage for a status-only (ng_hci_status_rp) command.
 * The call expression is side-effect-idempotent (all I/O is mocked).
 */
#define CHECK_OK(call)		do {					\
	mock_ok();							\
	ATF_CHECK_EQ_MSG(0, (call), "success arm: expected 0");		\
} while (0)

#define CHECK_BAD(call)		do {					\
	mock_status_bad();						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "status!=0 arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "status!=0 arm: expected EIO");	\
} while (0)

#define CHECK_XPORT(call)	do {					\
	mock_xport_fail(EIO);						\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "transport arm: expected -1");	\
	ATF_CHECK_EQ_MSG(EIO, errno, "transport arm: expected EIO");	\
} while (0)

#define CHECK_ALL(call)		do {					\
	CHECK_OK(call);							\
	CHECK_BAD(call);						\
	CHECK_XPORT(call);						\
} while (0)

/* ================================================================
 * hci_util.c — Read_BD_ADDR (Core Spec Vol 4 Part E §7.4.6)
 * RP: Status(1) | BD_ADDR(6)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_bd_addr);
ATF_TC_BODY(read_bd_addr, tc)
{
	uint8_t rp[7] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t bd[6];

	mock_ok_bytes(rp, sizeof(rp));
	memset(bd, 0, sizeof(bd));
	ATF_CHECK_EQ(0, hci_get_bdaddr(FD, bd));
	/* bdaddr_t is little-endian on the wire; the encoder copies the 6
	 * octets verbatim (Core Spec Vol 4 Part E §7.4.6). */
	ATF_CHECK_EQ(0x11, bd[0]);
	ATF_CHECK_EQ(0x66, bd[5]);

	/* Read_BD_ADDR reports failure as EIO (hci_util.c). */
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_get_bdaddr(FD, bd));
	ATF_CHECK_EQ(EIO, errno);

	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_get_bdaddr(FD, bd));
}

/* ================================================================
 * hci_adv.c — legacy advertising
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_legacy);
ATF_TC_BODY(adv_legacy, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };

	/* §7.8.5 interval range 0x0020-0x4000, Min<=Max. */
	CHECK_ALL(hci_le_set_advertising_params(FD, 0x0020, 0x0040,
	    0x00, 0x00, 0x00));
	CHECK_ALL(hci_le_set_advertising_data(FD, data, 3));
	CHECK_ALL(hci_le_set_scan_response_data(FD, data, 3));
	CHECK_ALL(hci_le_set_advertise_enable(FD, true));
	CHECK_ALL(hci_le_set_advertise_enable(FD, false));
}

/* ================================================================
 * hci_adv.c — extended advertising (BT 5.0)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_extended);
ATF_TC_BODY(adv_extended, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	/* §7.8.53 primary interval range 0x000020-0xFFFFFF. */
	CHECK_ALL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 0x00, 0x00, 0x01, 0x01));
	CHECK_ALL(hci_le_set_ext_adv_params(FD, 0, 0x0013,
	    0x000020, 0x000040, 0x00, 0x00));
	CHECK_ALL(hci_le_set_ext_adv_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_set_ext_adv_enable(FD, 1, 0));
	CHECK_ALL(hci_le_remove_adv_set(FD, 0));
	CHECK_ALL(hci_le_set_adv_set_random_address(FD, 0, addr));
	CHECK_ALL(hci_le_set_ext_scan_response_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_clear_adv_sets(FD));
}

/*
 * The LE Set Extended Advertising Data / Scan Response Data commands are sent
 * with a command-parameter length of exactly (4 fixed octets + data length),
 * NOT the full 251-octet struct (Core Spec Vol 4 Part E §7.8.54/§7.8.55: the
 * fixed header is Advertising_Handle, Operation, Fragment_Preference and
 * Advertising_Data_Length).  A wrong header size truncates or over-sends the
 * advertising data on the wire.  (Kills a `4 + len` -> `3 + len`/`sizeof(cp)`
 * clen encoding bug.)
 */
ATF_TC_WITHOUT_HEAD(ext_adv_data_clen);
ATF_TC_BODY(ext_adv_data_clen, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06, 0x04, 0x05 };

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 5));
	ATF_CHECK_EQ_MSG(4 + 5, W.last_clen,
	    "Set Ext Adv Data clen must be 4 + data_len, got %zu", W.last_clen);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_adv_data(FD, 0, data, 0));
	ATF_CHECK_EQ_MSG(4 + 0, W.last_clen,
	    "Set Ext Adv Data (0 bytes) clen must be 4, got %zu", W.last_clen);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_ext_scan_response_data(FD, 0, data, 5));
	ATF_CHECK_EQ_MSG(4 + 5, W.last_clen,
	    "Set Ext Scan Rsp Data clen must be 4 + data_len, got %zu",
	    W.last_clen);
}

/* ================================================================
 * hci_adv.c — LE Read Maximum Advertising Data Length (§7.8.57)
 * RP: Status(1) | Max_Advertising_Data_Length(2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_max_adv_data_length);
ATF_TC_BODY(read_max_adv_data_length, tc)
{
	uint8_t rp[3] = { 0x00, 0x00, 0x04 };	/* 0x0400 = 1024 */
	uint16_t max_len = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_max_adv_data_length(FD, &max_len));
	ATF_CHECK_EQ(0x0400, max_len);

	CHECK_BAD(hci_le_read_max_adv_data_length(FD, &max_len));
	CHECK_XPORT(hci_le_read_max_adv_data_length(FD, &max_len));

	/*
	 * NULL out-parameter must be rejected before the value is written
	 * (defensive API contract, matching the sibling read encoders).
	 * Without the guard the function dereferences NULL after the
	 * command completes -> latent crash.
	 */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_max_adv_data_length(FD, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

/* ================================================================
 * hci_adv.c — LE Read Number of Supported Advertising Sets (§7.8.58)
 * RP: Status(1) | Num_Supported_Advertising_Sets(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_num_supported_adv_sets);
ATF_TC_BODY(read_num_supported_adv_sets, tc)
{
	uint8_t rp[2] = { 0x00, 0x3F };		/* 63 sets */
	uint8_t nsets = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_num_supported_adv_sets(FD, &nsets));
	ATF_CHECK_EQ(0x3F, nsets);

	CHECK_BAD(hci_le_read_num_supported_adv_sets(FD, &nsets));
	CHECK_XPORT(hci_le_read_num_supported_adv_sets(FD, &nsets));

	/* NULL out-parameter must be rejected (see read_max_adv_data_length). */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_num_supported_adv_sets(FD, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

/* ================================================================
 * hci_adv.c — periodic advertising (BT 5.0)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_periodic);
ATF_TC_BODY(adv_periodic, tc)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	/* §7.8.61 interval range 0x0006-0xFFFF, Min<=Max. */
	CHECK_ALL(hci_le_set_periodic_adv_params(FD, 0, 0x0006, 0x0006, 0));
	CHECK_ALL(hci_le_set_periodic_adv_data(FD, 0, data, 3));
	CHECK_ALL(hci_le_set_periodic_adv_enable(FD, 1, 0));
	CHECK_ALL(hci_le_periodic_adv_create_sync(FD, 0, 0, 0, addr, 0, 0x000A));
	CHECK_ALL(hci_le_periodic_adv_create_sync_cancel(FD));
	CHECK_ALL(hci_le_periodic_adv_terminate_sync(FD, 0x0001));
	CHECK_ALL(hci_le_add_dev_to_periodic_adv_list(FD, 0, addr, 0));
	CHECK_ALL(hci_le_remove_dev_from_periodic_adv_list(FD, 0, addr, 0));
	CHECK_ALL(hci_le_clear_periodic_adv_list(FD));
}

/* ================================================================
 * hci_adv.c — LE Read Periodic Advertiser List Size (§7.8.73)
 * RP: Status(1) | Periodic_Advertiser_List_Size(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_periodic_adv_list_size);
ATF_TC_BODY(read_periodic_adv_list_size, tc)
{
	uint8_t rp[2] = { 0x00, 0x08 };
	uint8_t size = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_periodic_adv_list_size(FD, &size));
	ATF_CHECK_EQ(0x08, size);

	CHECK_BAD(hci_le_read_periodic_adv_list_size(FD, &size));
	CHECK_XPORT(hci_le_read_periodic_adv_list_size(FD, &size));
}

/* ================================================================
 * hci_adv.c — PAST (BT 5.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_past);
ATF_TC_BODY(adv_past, tc)
{

	CHECK_ALL(hci_le_set_periodic_adv_receive_enable(FD, 0x0001, 1));
	CHECK_ALL(hci_le_periodic_adv_sync_transfer(FD, 0x0001, 0x1234, 0x0001));
	CHECK_ALL(hci_le_periodic_adv_set_info_transfer(FD, 0x0001, 0x1234, 0));
	CHECK_ALL(hci_le_set_past_params(FD, 0x0001, 0, 0, 0x000A, 0));
	CHECK_ALL(hci_le_set_default_past_params(FD, 0, 0, 0x000A, 0));
}

/* ================================================================
 * hci_adv.c — Direction Finding / CTE (BT 5.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adv_cte);
ATF_TC_BODY(adv_cte, tc)
{
	uint8_t ant[2] = { 0, 1 };

	CHECK_ALL(hci_le_set_connless_cte_tx_params(FD, 0, 0x14, 0, 1, 2, ant));
	CHECK_ALL(hci_le_set_connless_cte_tx_enable(FD, 0, 1));
	CHECK_ALL(hci_le_set_connless_iq_sampling_enable(FD, 0x0001, 1, 1,
	    0, 2, ant));
	CHECK_ALL(hci_le_set_conn_cte_rx_params(FD, 0x0001, 1, 1, 2, ant));
	CHECK_ALL(hci_le_set_conn_cte_tx_params(FD, 0x0001, 0x01, 2, ant));
	CHECK_ALL(hci_le_conn_cte_req_enable(FD, 0x0001, 1, 0x000A, 0x14, 0));
	CHECK_ALL(hci_le_conn_cte_rsp_enable(FD, 0x0001, 1));
}

/* ================================================================
 * hci_adv.c — LE Read Antenna Information (§7.8.87)
 * RP: Status(1) | Supported_Switching_Sampling_Rates(1) |
 *     Num_Antennae(1) | Max_Switching_Pattern_Length(1) | Max_CTE_Length(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_antenna_info);
ATF_TC_BODY(read_antenna_info, tc)
{
	uint8_t rp[5] = { 0x00, 0x03, 0x02, 0x4B, 0x14 };
	uint8_t rates = 0, nant = 0, maxpat = 0, maxcte = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_antenna_info(FD, &rates, &nant,
	    &maxpat, &maxcte));
	ATF_CHECK_EQ(0x03, rates);
	ATF_CHECK_EQ(0x02, nant);
	ATF_CHECK_EQ(0x4B, maxpat);	/* 75 */
	ATF_CHECK_EQ(0x14, maxcte);	/* 20 */

	CHECK_BAD(hci_le_read_antenna_info(FD, &rates, &nant, &maxpat, &maxcte));
	CHECK_XPORT(hci_le_read_antenna_info(FD, &rates, &nant, &maxpat,
	    &maxcte));
}

/* ================================================================
 * hci_conn.c — connection parameter / data length / host feature
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_params);
ATF_TC_BODY(conn_params, tc)
{

	/*
	 * §7.8.18 conn update: interval 0x0006-0x0C80, latency <= 0x01F3,
	 * timeout 0x000A-0x0C80, and timeout*4 > interval_max*(1+latency).
	 * 0x000A*4 = 40 > 0x0006*1 = 6.
	 */
	CHECK_ALL(hci_le_connection_update(FD, 0x0040, 0x0006, 0x0006,
	    0, 0x000A));
	/* §7.8.33 tx_octets 0x001B-0x00FB, tx_time 0x0148-0x4290. */
	CHECK_ALL(hci_le_set_data_length(FD, 0x0040, 0x001B, 0x0148));
	CHECK_ALL(hci_le_write_suggested_default_data_length(FD, 0x001B,
	    0x0148));
	CHECK_ALL(hci_le_set_host_feature(FD, 32, 1));
	CHECK_ALL(hci_le_create_connection_cancel(FD));
}

/* ================================================================
 * hci_conn.c — PHY
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_phy);
ATF_TC_BODY(conn_phy, tc)
{

	CHECK_ALL(hci_le_set_default_phy(FD, 0x00, 0x07, 0x07));
	CHECK_ALL(hci_le_set_phy(FD, 0x0040, 0x00, 0x07, 0x07, 0x0000));
}

/* ================================================================
 * hci_conn.c — LE Read PHY (§7.8.47)
 * RP: Status(1) | Connection_Handle(2 LE) | TX_PHY(1) | RX_PHY(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_phy);
ATF_TC_BODY(read_phy, tc)
{
	uint8_t rp[5] = { 0x00, 0x40, 0x00, 0x02, 0x01 };  /* tx=2M rx=1M */
	uint8_t tx = 0, rx = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_phy(FD, 0x0040, &tx, &rx));
	ATF_CHECK_EQ(0x02, tx);
	ATF_CHECK_EQ(0x01, rx);

	CHECK_BAD(hci_le_read_phy(FD, 0x0040, &tx, &rx));
	CHECK_XPORT(hci_le_read_phy(FD, 0x0040, &tx, &rx));
}

/* ================================================================
 * hci_conn.c — subrating (BT 5.3) & power control (BT 5.2)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_subrate_power);
ATF_TC_BODY(conn_subrate_power, tc)
{

	CHECK_ALL(hci_le_set_default_subrate(FD, 1, 4, 0, 0, 0x000A));
	CHECK_ALL(hci_le_subrate_request(FD, 0x0040, 1, 4, 0, 0, 0x000A));
	CHECK_ALL(hci_le_read_remote_tx_power_level(FD, 0x0040, 0x01));
	CHECK_ALL(hci_le_set_path_loss_reporting_params(FD, 0x0040,
	    0x40, 0x04, 0x10, 0x04, 0x000A));
	CHECK_ALL(hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1));
	CHECK_ALL(hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 1));
}

/* ================================================================
 * hci_conn.c — LE Enhanced Read Transmit Power Level (§7.8.117)
 * RP: Status(1) | Connection_Handle(2) | PHY(1) |
 *     Current_TX_Power_Level(int8) | Max_TX_Power_Level(int8)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(enh_read_tx_power);
ATF_TC_BODY(enh_read_tx_power, tc)
{
	/* current = -20 dBm (0xEC), max = +10 dBm (0x0A) */
	uint8_t rp[6] = { 0x00, 0x40, 0x00, 0x01, 0xEC, 0x0A };
	int8_t cur = 0, max = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_enhanced_read_tx_power_level(FD, 0x0040,
	    0x01, &cur, &max));
	ATF_CHECK_EQ(-20, cur);
	ATF_CHECK_EQ(10, max);

	CHECK_BAD(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
	CHECK_XPORT(hci_le_enhanced_read_tx_power_level(FD, 0x0040, 0x01,
	    &cur, &max));
}

/* ================================================================
 * hci_conn.c — LE Extended Create Connection (§7.8.66)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_create_connection);
ATF_TC_BODY(ext_create_connection, tc)
{
	uint8_t peer[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t phy_params[16];		/* one PHY block, LE-encoded */

	memset(phy_params, 0, sizeof(phy_params));
	/* phys = 0x01 (1M) -> exactly one phy_params block. */
	CHECK_ALL(hci_le_ext_create_connection(FD, 0x00, 0x00, 0x00, peer,
	    0x01, phy_params, sizeof(phy_params)));
}

/* ================================================================
 * hci_privacy.c — resolving list, privacy, filter accept list
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(privacy);
ATF_TC_BODY(privacy, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t irk[16];

	memset(irk, 0xA5, sizeof(irk));
	/* Exercise the enabled side of the production HCI logging guard too.
	 * The command/result assertions below remain independent of logging. */
	atomic_store(&blued_verbose, 2);
	CHECK_ALL(hci_le_clear_resolving_list(FD));
	CHECK_ALL(hci_le_add_dev_resolving_list(FD, 0, addr, irk, irk));
	/* Core Spec Vol 4 Part E §7.8.39: removal uses the same three
	 * controller-result arms as the other resolving-list operations. */
	CHECK_ALL(hci_le_remove_dev_resolving_list(FD, 0, addr));
	CHECK_ALL(hci_le_set_addr_resolution_enable(FD, 1));
	CHECK_ALL(hci_le_set_privacy_mode(FD, 0, addr, 0));
	/* §7.8.45 RPA timeout range 1-0x0E10 s. */
	CHECK_ALL(hci_le_set_rpa_timeout(FD, 900));
	CHECK_ALL(hci_le_clear_filter_accept_list(FD));
	CHECK_ALL(hci_le_add_device_to_filter_accept_list(FD, 0, addr));
	CHECK_ALL(hci_le_remove_device_from_filter_accept_list(FD, 0, addr));

	/* Repeat the exact controller matrix with diagnostic output disabled. */
	atomic_store(&blued_verbose, 0);
	CHECK_ALL(hci_le_clear_resolving_list(FD));
	CHECK_ALL(hci_le_add_dev_resolving_list(FD, 0, addr, irk, irk));
	CHECK_ALL(hci_le_remove_dev_resolving_list(FD, 0, addr));
	CHECK_ALL(hci_le_set_addr_resolution_enable(FD, 1));
	CHECK_ALL(hci_le_set_privacy_mode(FD, 0, addr, 0));
	CHECK_ALL(hci_le_set_rpa_timeout(FD, 900));
	CHECK_ALL(hci_le_clear_filter_accept_list(FD));
	CHECK_ALL(hci_le_add_device_to_filter_accept_list(FD, 0, addr));
	CHECK_ALL(hci_le_remove_device_from_filter_accept_list(FD, 0, addr));
}

/* ================================================================
 * hci_misc.c — reset / masks / LTK / host support
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_core);
ATF_TC_BODY(misc_core, tc)
{
	uint8_t ltk[16];

	memset(ltk, 0x5A, sizeof(ltk));
	CHECK_ALL(hci_reset(FD));
	CHECK_ALL(hci_write_le_host_support(FD, 1, 0));
	CHECK_ALL(hci_set_event_mask(FD, 0x00001FFFFFFFFFFFULL));
	CHECK_ALL(hci_le_set_event_mask(FD, 0x000000000000001FULL));
	CHECK_ALL(hci_le_ltk_request_reply(FD, 0x0040, ltk));
	CHECK_ALL(hci_le_ltk_request_neg_reply(FD, 0x0040));
	/* §7.3.102 Set Min Encryption Key Size: range 7-16. */
	CHECK_ALL(hci_set_min_enc_key_size(FD, 16));
	CHECK_ALL(hci_le_write_auth_payload_timeout(FD, 0x0040, 0x0BB8));

	/* §7.3.94: handle range 0x0000-0x0EFF, timeout range 1-0xFFFF. */
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_write_auth_payload_timeout(FD, 0x0F00,
	    0x0BB8));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_write_auth_payload_timeout(FD, 0x0040, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
}

/* ================================================================
 * hci_misc.c — LE Read Local Supported Features (§7.8.3)
 * RP: Status(1) | LE_Features(8 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_local_features);
ATF_TC_BODY(read_local_features, tc)
{
	/* features = 0x00000000DEADBEEF, little-endian on the wire. */
	uint8_t rp[9] = { 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00 };
	uint64_t feats = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_local_features(FD, &feats));
	ATF_CHECK_EQ(0x00000000DEADBEEFULL, feats);

	CHECK_BAD(hci_le_read_local_features(FD, &feats));
	CHECK_XPORT(hci_le_read_local_features(FD, &feats));
}

/* ================================================================
 * hci_misc.c — LE Read Buffer Size v2 (§7.8.2)
 * RP: Status(1) | LE_ACL_Data_Packet_Length(2) |
 *     Total_Num_LE_ACL_Data_Packets(1) | ISO_Data_Packet_Length(2) |
 *     Total_Num_ISO_Data_Packets(1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_buffer_size_v2);
ATF_TC_BODY(read_buffer_size_v2, tc)
{
	/* acl_len=0x00FB(251), acl_num=0x0A, iso_len=0x0200(512), iso_num=0x08 */
	uint8_t rp[7] = { 0x00, 0xFB, 0x00, 0x0A, 0x00, 0x02, 0x08 };
	uint16_t acl_len = 0, iso_len = 0;
	uint8_t acl_num = 0, iso_num = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
	ATF_CHECK_EQ(0x00FB, acl_len);
	ATF_CHECK_EQ(0x0A, acl_num);
	ATF_CHECK_EQ(0x0200, iso_len);
	ATF_CHECK_EQ(0x08, iso_num);

	CHECK_BAD(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
	CHECK_XPORT(hci_le_read_buffer_size_v2(FD, &acl_len, &acl_num,
	    &iso_len, &iso_num));
}

/* ================================================================
 * hci_misc.c — LE Read ISO TX Sync (§7.8.96)
 * RP: Status(1) | Connection_Handle(2) | Packet_Sequence_Number(2) |
 *     TX_Time_Stamp(4) | Time_Offset(3 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_tx_sync);
ATF_TC_BODY(read_iso_tx_sync, tc)
{
	uint8_t rp[12] = {
		0x00,			/* status */
		0x40, 0x00,		/* connection_handle */
		0x34, 0x12,		/* seq = 0x1234 */
		0xEF, 0xCD, 0xAB, 0x89,	/* ts = 0x89ABCDEF */
		0x01, 0x02, 0x03	/* offset = 0x030201 */
	};
	uint16_t seq = 0;
	uint32_t ts = 0, off = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	ATF_CHECK_EQ(0x1234, seq);
	ATF_CHECK_EQ(0x89ABCDEF, ts);
	ATF_CHECK_EQ(0x00030201, off);

	CHECK_BAD(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
	CHECK_XPORT(hci_le_read_iso_tx_sync(FD, 0x0040, &seq, &ts, &off));
}

/* ================================================================
 * hci_misc.c — LE Set CIG Parameters (§7.8.97)
 * RP: Status(1) | CIG_ID(1) | CIS_Count(1) | Connection_Handle[i](2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(set_cig_params);
ATF_TC_BODY(set_cig_params, tc)
{
	uint8_t rp[5] = { 0x00, 0x05, 0x01, 0x60, 0x00 };  /* handle 0x0060 */
	uint8_t cis_params[9];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[1] = { 0 };

	memset(cis_params, 0, sizeof(cis_params));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(0x05, out_cig);
	ATF_CHECK_EQ(0x01, out_cnt);
	ATF_CHECK_EQ(0x0060, handles[0]);

	/* CIG params rejects with status byte at rpbuf[0]. */
	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
	ATF_CHECK_EQ(EIO, errno);

	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
	    0, 0, 10, 10, 1, cis_params, sizeof(cis_params),
	    &out_cig, &out_cnt, handles));
}

/* ================================================================
 * hci_misc.c — ISO channel management (CIG/CIS/BIG)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(misc_iso);
ATF_TC_BODY(misc_iso, tc)
{
	uint16_t cis_h[1] = { 0x0100 };
	uint16_t acl_h[1] = { 0x0001 };
	uint8_t bcode[16];
	uint8_t bis[1] = { 1 };
	uint8_t codec_id[5] = { 0x03, 0, 0, 0, 0 };  /* transparent */

	memset(bcode, 0, sizeof(bcode));
	CHECK_ALL(hci_le_create_cis(FD, 1, cis_h, acl_h));
	CHECK_ALL(hci_le_remove_cig(FD, 0x05));
	CHECK_ALL(hci_le_accept_cis_request(FD, 0x0040));
	CHECK_ALL(hci_le_reject_cis_request(FD, 0x0040, 0x0D));
	CHECK_ALL(hci_le_create_big(FD, 0, 0, 1, 10000, 100, 10, 0, 0x01,
	    0, 0, 0, bcode));
	CHECK_ALL(hci_le_terminate_big(FD, 0, 0x16));
	CHECK_ALL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0,
	    0x0064, 1, bis));
	CHECK_ALL(hci_le_big_terminate_sync(FD, 0));
	CHECK_ALL(hci_le_setup_iso_data_path(FD, 0x0040, 0, 0, codec_id,
	    0, 0, NULL));
	CHECK_ALL(hci_le_remove_iso_data_path(FD, 0x0040, 0x01));
	CHECK_ALL(hci_le_request_peer_sca(FD, 0x0040));
}

/* ================================================================
 * hci_misc.c — LE Read ISO Link Quality (§7.8.116)
 * RP: Status(1) | Connection_Handle(2) | seven u32 counters (LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_iso_link_quality);
ATF_TC_BODY(read_iso_link_quality, tc)
{
	uint8_t rp[31];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0;
	int i;

	memset(rp, 0, sizeof(rp));
	rp[0] = 0x00;			/* status */
	rp[1] = 0x40; rp[2] = 0x00;	/* connection_handle */
	/* seven u32 counters 1..7, each little-endian at offset 3 + 4*i */
	for (i = 0; i < 7; i++)
		rp[3 + i * 4] = (uint8_t)(i + 1);

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	ATF_CHECK_EQ(1, a);	/* tx_unacked */
	ATF_CHECK_EQ(2, b);	/* tx_flushed */
	ATF_CHECK_EQ(3, c);	/* tx_last_subevent */
	ATF_CHECK_EQ(4, d);	/* retransmitted */
	ATF_CHECK_EQ(5, e);	/* crc_error */
	ATF_CHECK_EQ(6, f);	/* rx_unreceived */
	ATF_CHECK_EQ(7, g);	/* duplicate */

	CHECK_BAD(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
	CHECK_XPORT(hci_le_read_iso_link_quality(FD, 0x0040,
	    &a, &b, &c, &d, &e, &f, &g));
}

/* ================================================================
 * hci_misc.c — Read Authenticated Payload Timeout (§7.3.93)
 * RP: Status(1) | Connection_Handle(2) | Authenticated_Payload_Timeout(2)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_auth_payload_timeout);
ATF_TC_BODY(read_auth_payload_timeout, tc)
{
	uint8_t rp[5] = { 0x00, 0x40, 0x00, 0xB8, 0x0B };  /* 0x0BB8 = 3000 */
	uint16_t to = 0;

	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_auth_payload_timeout(FD, 0x0040, &to));
	ATF_CHECK_EQ(0x0BB8, to);

	CHECK_BAD(hci_le_read_auth_payload_timeout(FD, 0x0040, &to));
	CHECK_XPORT(hci_le_read_auth_payload_timeout(FD, 0x0040, &to));

	/* §7.3.93: Connection_Handle is 12 bits meaningful, max 0x0EFF. */
	W.call_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_read_auth_payload_timeout(FD, 0x0F00, &to));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.call_count);
}

ATF_TC_WITHOUT_HEAD(scan_command_matrix);
ATF_TC_BODY(scan_command_matrix, tc)
{
	struct hci_scan_params p;
	struct ble_scan_result result;
	int nresults;

	hci_scan_params_default(&p);
	CHECK_ALL(hci_le_set_scan_params(FD, &p));
	CHECK_ALL(hci_le_set_scan_enable(FD, 1, 1));
	CHECK_ALL(hci_le_set_ext_scan_params(FD, &p, 0));

	/* Mesh scan selection covers legacy/extended enable and disable. */
	CHECK_ALL(hci_le_mesh_scan_set(FD, 0, false));
	CHECK_ALL(hci_le_mesh_scan_set(FD, LE_FEAT_EXT_ADVERTISING, false));
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_mesh_scan_set(FD, 0, true));
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_mesh_scan_set(FD,
	    LE_FEAT_EXT_ADVERTISING, true));
	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_mesh_scan_set(FD, 0, true));
	mock_xport_fail(EIO);
	ATF_CHECK_EQ(-1, hci_le_mesh_scan_set(FD,
	    LE_FEAT_EXT_ADVERTISING, true));

	/* Independent validation clauses. */
	p.active = 2;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	hci_scan_params_default(&p);
	p.window = 3;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_scan_params(FD, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, hci_le_scan_ex(FD, 0, &p, &result, 1,
	    &nresults));
	ATF_CHECK_EQ(-1, hci_le_ext_scan_ex(FD, 0, &p, &result, 1,
	    &nresults, 1));
}

ATF_TC_WITHOUT_HEAD(adv_config_and_mesh_burst_matrix);
ATF_TC_BODY(adv_config_and_mesh_burst_matrix, tc)
{
	struct hci_adv_config cfg;
	uint8_t ad[31];
	int kind, ordinal;

	memset(ad, 0xa5, sizeof(ad));
	memset(&cfg, 0, sizeof(cfg));
	cfg.interval_min = 0x00a0;
	cfg.interval_max = 0x00a0;
	cfg.channel_map = 0x07;
	cfg.tx_power = 0x7f;
	cfg.primary_phy = 0x01;
	cfg.secondary_phy = 0x01;
	cfg.has_peer = true;

	/* Every normalized kind reaches both wire-encoding switch arms. */
	for (kind = HCI_ADV_CONN_UND; kind <= HCI_ADV_NONCONN_UND; kind++) {
		cfg.kind = kind;
		cfg.mode = HCI_ADV_MODE_LEGACY;
		mock_ok();
		ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
		ATF_CHECK(!cfg.used_extended);

		cfg.mode = HCI_ADV_MODE_EXTENDED;
		mock_ok();
		ATF_CHECK_EQ(0, hci_adv_configure(FD,
		    LE_FEAT_EXT_ADVERTISING, &cfg));
		ATF_CHECK(cfg.used_extended);
	}

	/* AUTO and EXTENDED fall back when the feature bit is absent. */
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.mode = HCI_ADV_MODE_AUTO;
	mock_ok();
	ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK(!cfg.used_extended);
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	mock_ok();
	ATF_CHECK_EQ(0, hci_adv_configure(FD, 0, &cfg));
	ATF_CHECK(!cfg.used_extended);

	/* Configuration validation clauses are independent API contracts. */
	cfg.kind = HCI_ADV_CONN_DIR_HIGH;
	cfg.has_peer = false;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.kind = HCI_ADV_CONN_UND;
	cfg.has_peer = true;
	cfg.own_addr_type = 4;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.own_addr_type = 0;
	cfg.channel_map = 0;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));
	cfg.channel_map = 0x07;
	cfg.mode = HCI_ADV_MODE_EXTENDED;
	cfg.primary_phy = 2;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD,
	    LE_FEAT_EXT_ADVERTISING, &cfg));
	cfg.primary_phy = 1;
	cfg.secondary_phy = 4;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD,
	    LE_FEAT_EXT_ADVERTISING, &cfg));
	cfg.secondary_phy = 1;
	cfg.mode = HCI_ADV_MODE_LEGACY;
	cfg.interval_max = 0x10000;
	ATF_CHECK_EQ(-1, hci_adv_configure(FD, 0, &cfg));

	/* Data validation precedes controller I/O. */
	ATF_CHECK_EQ(-1, hci_le_set_advertising_data(FD, ad, 32));
	ATF_CHECK_EQ(-1, hci_le_set_advertising_data(FD, NULL, 1));
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_data(FD, 0, NULL, 1));
	ATF_CHECK_EQ(-1, hci_le_set_advertising_params_full(FD, 0x20, 0x20,
	    0, 0, 0, 0, 0, NULL));
	ATF_CHECK_EQ(-1, hci_le_set_ext_adv_params_full(FD, 0, 0, 0x20,
	    0x20, 0, 0, 1, 1, 0, 0x7f, 0, NULL));

	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, NULL, 1));
	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, ad, 0));
	ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, ad, 32));
	for (ordinal = 1; ordinal <= 3; ordinal++) {
		mock_xport_fail_at(ordinal, EIO);
		ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD, 0, ad, sizeof(ad)));
		mock_xport_fail_at(ordinal, EIO);
		ATF_CHECK_EQ(-1, hci_mesh_adv_burst(FD,
		    LE_FEAT_EXT_ADVERTISING, ad, sizeof(ad)));
	}
	mock_ok();
	ATF_CHECK_EQ(0, hci_mesh_adv_burst(FD, 0, ad, sizeof(ad)));
	mock_ok();
	ATF_CHECK_EQ(0, hci_mesh_adv_burst(FD,
	    LE_FEAT_EXT_ADVERTISING, ad, sizeof(ad)));
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, read_bd_addr);

	/* hci_adv.c */
	ATF_TP_ADD_TC(tp, adv_legacy);
	ATF_TP_ADD_TC(tp, adv_extended);
	ATF_TP_ADD_TC(tp, ext_adv_data_clen);
	ATF_TP_ADD_TC(tp, read_max_adv_data_length);
	ATF_TP_ADD_TC(tp, read_num_supported_adv_sets);
	ATF_TP_ADD_TC(tp, adv_periodic);
	ATF_TP_ADD_TC(tp, read_periodic_adv_list_size);
	ATF_TP_ADD_TC(tp, adv_past);
	ATF_TP_ADD_TC(tp, adv_cte);
	ATF_TP_ADD_TC(tp, read_antenna_info);

	/* hci_conn.c */
	ATF_TP_ADD_TC(tp, conn_params);
	ATF_TP_ADD_TC(tp, conn_phy);
	ATF_TP_ADD_TC(tp, read_phy);
	ATF_TP_ADD_TC(tp, conn_subrate_power);
	ATF_TP_ADD_TC(tp, enh_read_tx_power);
	ATF_TP_ADD_TC(tp, ext_create_connection);

	/* hci_privacy.c */
	ATF_TP_ADD_TC(tp, privacy);

	/* hci_misc.c */
	ATF_TP_ADD_TC(tp, misc_core);
	ATF_TP_ADD_TC(tp, read_local_features);
	ATF_TP_ADD_TC(tp, read_buffer_size_v2);
	ATF_TP_ADD_TC(tp, read_iso_tx_sync);
	ATF_TP_ADD_TC(tp, set_cig_params);
	ATF_TP_ADD_TC(tp, misc_iso);
	ATF_TP_ADD_TC(tp, read_iso_link_quality);
	ATF_TP_ADD_TC(tp, read_auth_payload_timeout);
	ATF_TP_ADD_TC(tp, scan_command_matrix);
	ATF_TP_ADD_TC(tp, adv_config_and_mesh_burst_matrix);

	return (atf_no_error());
}
