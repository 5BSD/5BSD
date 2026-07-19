/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI LE command ENCODER edge-case / negative tests.
 *
 * hci_event_test.c already pins the interval / latency / timeout / key-size
 * range checks.  This file fills the remaining host-side validation branches
 * and drives the "no explicit range check" encoders through their body so the
 * command-build path (and its downstream-failure branch) is exercised:
 *
 *   - legacy + extended + periodic advertising DATA length limits (7.8.7,
 *     7.8.8, 7.8.54, 7.8.55, 7.8.62)
 *   - the remaining Direction-Finding switching-pattern-length checks
 *     (connectionless IQ sampling, connection CTE Rx/Tx params, 7.8.82-7.8.84)
 *   - CIS/ISO command-buffer length checks: Set CIG Params (7.8.97),
 *     BIG Create Sync (7.8.106), Setup ISO Data Path (7.8.109)
 *   - resolving-list add / clear, address-resolution-enable, privacy-mode
 *     (7.8.38-7.8.44) and the filter-accept-list commands (7.8.15-7.8.17)
 *   - ble_build_adv_data boundary / overflow / per-AD-type (Vol 3 Part C 11)
 *
 * Oracle: parameter ranges are Core Spec Vol 4 Part E Section 7.8 (LE) /
 * 7.3 (Controller & Baseband); AD structures are Vol 3 Part C Section 11.
 * Ranges asserted are the SPEC's; where the implementation's check differs
 * from the spec that is called out in a comment and reported.
 *
 * REJECT() asserts host validation returns -1/EINVAL before any I/O.
 * ACCEPT() asserts a call passes validation — it still returns -1 because
 * test_fd() is a /dev/null fd with no controller behind it, but the failure
 * is NOT the EINVAL of a range check (bt_devreq maps fd<0 to EINVAL itself,
 * hence a real non-HCI fd).  Same pattern as hci_event_test.c.
 *
 * Link set: hci_encode_edge_test.c hci_util.c hci_adv.c hci_scan.c hci_conn.c
 * hci_privacy.c hci_misc.c hci_log.c   (+ libbluetooth, libcrypto).
 */

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "spec_hci_encode_edge_oracles.h"

/* Stub globals required by the hci_*.c logging macros (_BLUED_LOG). */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

static int
test_fd(void)
{
	static int fd = -1;

	if (fd < 0)
		fd = open("/dev/null", O_RDWR);
	return (fd);
}

static void
fill_cis_params(uint8_t *cis_params, uint8_t cis_count)
{

	memset(cis_params, 0, (size_t)cis_count * BT_HCI_CIS_PARAM_LEN);
	for (uint8_t i = 0; i < cis_count; i++) {
		uint8_t *cp = cis_params +
		    (size_t)i * BT_HCI_CIS_PARAM_LEN;

		cp[0] = i;
		cp[5] = 0x01;
		cp[6] = 0x01;
	}
}

#define REJECT(call)	do {						\
	int _r;								\
	errno = 0;							\
	_r = (call);							\
	ATF_CHECK_EQ_MSG(_r, -1, "expected rejection from " #call);	\
	ATF_CHECK_EQ_MSG(EINVAL, errno,					\
	    "expected EINVAL from " #call ", got errno=%d", errno);	\
} while (0)

#define ACCEPT(call)	do {						\
	errno = 0;							\
	(void)(call);							\
	ATF_CHECK_MSG(errno != EINVAL,					\
	    "validation wrongly rejected " #call);			\
} while (0)

/* ================================================================
 * Legacy advertising / scan-response DATA length (max 31 octets).
 * Core Spec Vol 4 Part E 7.8.7 / 7.8.8: Advertising_Data_Length and
 * Scan_Response_Data_Length range 0x00..0x1F (0..31).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(legacy_adv_data_len);
ATF_TC_BODY(legacy_adv_data_len, tc)
{
	uint8_t data[64];

	memset(data, 0, sizeof(data));

	/* 32 > 31 is rejected before any copy. */
	REJECT(hci_le_set_advertising_data(test_fd(), data,
	    BT_HCI_LEGACY_ADV_DATA_FIRST_INVALID));
	REJECT(hci_le_set_scan_response_data(test_fd(), data,
	    BT_HCI_LEGACY_ADV_DATA_FIRST_INVALID));
	REJECT(hci_le_set_advertising_data(test_fd(), NULL, 1));
	REJECT(hci_le_set_scan_response_data(test_fd(), NULL, 1));

	/* Exactly 31, and the empty case, pass validation. */
	ACCEPT(hci_le_set_advertising_data(test_fd(), data,
	    BT_HCI_LEGACY_ADV_DATA_MAX));
	ACCEPT(hci_le_set_advertising_data(test_fd(), NULL, 0));
	ACCEPT(hci_le_set_scan_response_data(test_fd(), data,
	    BT_HCI_LEGACY_ADV_DATA_MAX));
	ACCEPT(hci_le_set_scan_response_data(test_fd(), NULL, 0));
}

/* ================================================================
 * Extended advertising / scan-response DATA length.
 * Core Spec Vol 4 Part E 7.8.54 / 7.8.55.  The implementation caps a
 * single complete-data operation at NG_HCI_LE_EXT_ADV_DATA_MAX (251).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_adv_data_len);
ATF_TC_BODY(ext_adv_data_len, tc)
{
	uint8_t data[256];

	memset(data, 0, sizeof(data));

	REJECT(hci_le_set_ext_adv_data(test_fd(), 0, data,
	    BT_HCI_EXT_ADV_FRAGMENT_FIRST_INVALID));
	REJECT(hci_le_set_ext_scan_response_data(test_fd(), 0, data,
	    BT_HCI_EXT_ADV_FRAGMENT_FIRST_INVALID));
	REJECT(hci_le_set_ext_adv_data(test_fd(), 0, NULL, 1));
	REJECT(hci_le_set_ext_scan_response_data(test_fd(), 0, NULL, 1));

	ACCEPT(hci_le_set_ext_adv_data(test_fd(), 0, data,
	    BT_HCI_EXT_ADV_FRAGMENT_MAX));
	ACCEPT(hci_le_set_ext_adv_data(test_fd(), 0, NULL, 0));
	ACCEPT(hci_le_set_ext_scan_response_data(test_fd(), 0, data,
	    BT_HCI_EXT_ADV_FRAGMENT_MAX));
	ACCEPT(hci_le_set_ext_scan_response_data(test_fd(), 0, NULL, 0));
}

/* ================================================================
 * Periodic advertising DATA length.
 * Core Spec Vol 4 Part E 7.8.62.  Implementation cap is
 * NG_HCI_LE_PERIODIC_ADV_DATA_MAX (252).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(periodic_adv_data_len);
ATF_TC_BODY(periodic_adv_data_len, tc)
{
	uint8_t data[256];

	memset(data, 0, sizeof(data));

	REJECT(hci_le_set_periodic_adv_data(test_fd(), 0, data,
	    BT_HCI_PERIODIC_ADV_FRAGMENT_FIRST_INVALID));
	REJECT(hci_le_set_periodic_adv_data(test_fd(), 0, NULL, 1));
	ACCEPT(hci_le_set_periodic_adv_data(test_fd(), 0, data,
	    BT_HCI_PERIODIC_ADV_FRAGMENT_MAX));
	ACCEPT(hci_le_set_periodic_adv_data(test_fd(), 0, NULL, 0));
}

/* ================================================================
 * Direction Finding — switching-pattern-length bound (<= 75) for the
 * remaining CTE commands not covered by hci_event_test.c.
 * Core Spec Vol 4 Part E 7.8.82 (connectionless IQ sampling),
 * 7.8.83 (connection CTE Rx), 7.8.84 (connection CTE Tx).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cte_switching_len_bounds);
ATF_TC_BODY(cte_switching_len_bounds, tc)
{
	uint8_t antenna[76];

	memset(antenna, 0, sizeof(antenna));

	/* switching_pattern_len > 75 rejected before the antenna copy. */
	REJECT(hci_le_set_connless_iq_sampling_enable(test_fd(), 0, 1, 1, 0,
	    BT_HCI_CTE_SWITCH_PATTERN_FIRST_HIGH, antenna));
	REJECT(hci_le_set_conn_cte_rx_params(test_fd(), 0x40, 1, 1,
	    BT_HCI_CTE_SWITCH_PATTERN_FIRST_HIGH,
	    antenna));
	REJECT(hci_le_set_conn_cte_tx_params(test_fd(), 0x40,
	    BT_HCI_CTE_TYPE_AOA, BT_HCI_CTE_SWITCH_PATTERN_FIRST_HIGH,
	    antenna));
	REJECT(hci_le_set_connless_iq_sampling_enable(test_fd(), 0, 1, 1, 0,
	    BT_HCI_CTE_SWITCH_PATTERN_MIN - 1, antenna));
	REJECT(hci_le_set_conn_cte_rx_params(test_fd(), 0x40, 1, 1,
	    BT_HCI_CTE_SWITCH_PATTERN_MIN - 1, antenna));
	REJECT(hci_le_set_conn_cte_tx_params(test_fd(), 0x40,
	    BT_HCI_CTE_TYPE_AOA, BT_HCI_CTE_SWITCH_PATTERN_MIN - 1,
	    antenna));

	/* Exactly 75 (the max legal pattern) passes validation. */
	ACCEPT(hci_le_set_connless_iq_sampling_enable(test_fd(), 0, 1, 1, 0,
	    BT_HCI_CTE_SWITCH_PATTERN_MAX, antenna));
	ACCEPT(hci_le_set_conn_cte_rx_params(test_fd(), 0x40, 1, 1,
	    BT_HCI_CTE_SWITCH_PATTERN_MAX,
	    antenna));
	ACCEPT(hci_le_set_conn_cte_tx_params(test_fd(), 0x40,
	    BT_HCI_CTE_TYPE_AOA, BT_HCI_CTE_SWITCH_PATTERN_MAX,
	    antenna));
}

/* ================================================================
 * CIS/ISO command-buffer length checks.
 * ================================================================ */

/*
 * LE Set CIG Parameters (7.8.97).  The command is a 15-byte fixed portion
 * plus up to 31 nine-byte CIS entries.  This exceeds the generic 255-octet
 * HCI command shape; Core 6.3 explicitly defines the larger command and the
 * FreeBSD bt_devreq transport currently cannot emit more than 255 octets.
 * This test pins the encoder's local buffer bound; transport reachability is
 * tracked separately rather than calling the 31-CIS case end-to-end legal.
 */
ATF_TC_WITHOUT_HEAD(cig_params_len_bound);
ATF_TC_BODY(cig_params_len_bound, tc)
{
	uint8_t cis_params[BT_HCI_ISO_STREAM_COUNT_MAX *
	    BT_HCI_CIS_PARAM_LEN];
	uint8_t out_cig, out_cnt;
	uint16_t out_handles[BT_HCI_ISO_STREAM_COUNT_MAX];

	fill_cis_params(cis_params, BT_HCI_ISO_STREAM_COUNT_MAX);

	/*
	 * Command buffer is cmd[15 + 31*9] = 294: the §7.8.97 maximum is 31
	 * CIS entries of 9 bytes each after the 15-byte fixed header.
	 * cmdlen = 15 + cis_params_len, rejected when it exceeds 294
	 * (i.e. cis_params_len > 279).
	 */
	/* 15 + 280 = 295 > 294 -> rejected. */
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0, 0,
	    40, 40, BT_HCI_ISO_STREAM_COUNT_MAX, cis_params,
	    BT_HCI_ISO_STREAM_COUNT_MAX * BT_HCI_CIS_PARAM_LEN + 1,
	    &out_cig, &out_cnt, out_handles));

	/* 15 + 279 = 294 fits exactly (31 CIS * 9 bytes). */
	ACCEPT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0, 0,
	    40, 40, BT_HCI_ISO_STREAM_COUNT_MAX, cis_params,
	    BT_HCI_ISO_STREAM_COUNT_MAX * BT_HCI_CIS_PARAM_LEN,
	    &out_cig, &out_cnt, out_handles));
}

ATF_TC_WITHOUT_HEAD(cig_params_spec_ranges);
ATF_TC_BODY(cig_params_spec_ranges, tc)
{
	uint8_t cis_params[BT_HCI_CIS_PARAM_LEN];
	uint8_t out_cig, out_cnt;
	uint16_t out_handles[1];

	fill_cis_params(cis_params, 1);

	REJECT(hci_le_set_cig_params(test_fd(), 0, 0x0000FE, 10000, 0, 0,
	    0, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 0x100000, 0, 0,
	    0, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 8, 0,
	    0, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 2,
	    0, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0,
	    3, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0,
	    0, 4, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt, out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0,
	    0, 40, 0x0FA1, 1, cis_params, BT_HCI_CIS_PARAM_LEN, &out_cig,
	    &out_cnt,
	    out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0,
	    0, 40, 40, 1, NULL, BT_HCI_CIS_PARAM_LEN, &out_cig, &out_cnt,
	    out_handles));
	REJECT(hci_le_set_cig_params(test_fd(), 0, 10000, 10000, 0, 0,
	    0, 40, 40, 1, cis_params, BT_HCI_CIS_PARAM_LEN - 1, &out_cig,
	    &out_cnt, out_handles));

}

/*
 * LE Create CIS (7.8.99): CIS_Count range 0x01..0x1F.  The REJECT
 * boundaries are in hci_event_test.c; this adds the in-range ACCEPT so
 * the command-build path is covered rather than only the rejects.
 */
ATF_TC_WITHOUT_HEAD(create_cis_accept);
ATF_TC_BODY(create_cis_accept, tc)
{
	uint16_t cis[BT_HCI_ISO_STREAM_COUNT_MAX];
	uint16_t acl[BT_HCI_ISO_STREAM_COUNT_MAX];

	memset(cis, 0, sizeof(cis));
	memset(acl, 0, sizeof(acl));

	ACCEPT(hci_le_create_cis(test_fd(), 1, cis, acl));
	ACCEPT(hci_le_create_cis(test_fd(), BT_HCI_ISO_STREAM_COUNT_MAX, cis,
	    acl));
	REJECT(hci_le_create_cis(test_fd(), 1, NULL, acl));
	REJECT(hci_le_create_cis(test_fd(), 1, cis, NULL));
}

/*
 * LE BIG Create Sync (7.8.106): Num_BIS is 0x01..0x1F and BIS indices are
 * 0x01..0x1F in strictly increasing order.
 */
ATF_TC_WITHOUT_HEAD(big_create_sync_num_bis_bound);
ATF_TC_BODY(big_create_sync_num_bis_bound, tc)
{
	uint8_t bcode[16];
	uint8_t bis[BT_HCI_ISO_STREAM_COUNT_FIRST_HIGH];

	memset(bcode, 0, sizeof(bcode));
	for (uint8_t i = 0; i < sizeof(bis); i++)
		bis[i] = (uint8_t)(i + 1);

	/* Num_BIS above the Core range is rejected before I/O. */
	REJECT(hci_le_big_create_sync(test_fd(), 0, 0x0100, 0, bcode, 0,
	    0x0100, BT_HCI_ISO_STREAM_COUNT_FIRST_HIGH, bis));

	/* 31 is the valid maximum. */
	ACCEPT(hci_le_big_create_sync(test_fd(), 0, 0x0100, 0, bcode, 0,
	    0x0100, BT_HCI_ISO_STREAM_COUNT_MAX, bis));
}

/*
 * LE Setup ISO Data Path (7.8.109) has 13 fixed command-parameter octets.
 * The HCI Command packet Parameter_Total_Length is one octet (§5.4.1), so
 * 255 - 13 = 242 codec-configuration octets is the encodable maximum.
 */
ATF_TC_WITHOUT_HEAD(setup_iso_data_path_maxlen);
ATF_TC_BODY(setup_iso_data_path_maxlen, tc)
{
	uint8_t codec_id[5];
	uint8_t cfg[BT_HCI_SETUP_ISO_CODEC_CONFIG_FIRST_HIGH];

	memset(codec_id, 0, sizeof(codec_id));
	memset(cfg, 0, sizeof(cfg));

	ACCEPT(hci_le_setup_iso_data_path(test_fd(), 0x40,
	    BT_HCI_ISO_PATH_INPUT, 0x00, codec_id, 0,
	    BT_HCI_SETUP_ISO_CODEC_CONFIG_MAX, cfg));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40,
	    BT_HCI_ISO_PATH_INPUT, 0x00, codec_id, 0,
	    BT_HCI_SETUP_ISO_CODEC_CONFIG_FIRST_HIGH, cfg));
	REJECT(hci_le_setup_iso_data_path(test_fd(), BT_HCI_HANDLE_FIRST_RESERVED,
	    BT_HCI_ISO_PATH_INPUT, 0x00,
	    codec_id, 0, 0, NULL));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40,
	    BT_HCI_ISO_PATH_OUTPUT + 1, 0x00,
	    codec_id, 0, 0, NULL));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40,
	    BT_HCI_ISO_PATH_INPUT, BT_HCI_ISO_PATH_FIRST_RESERVED,
	    codec_id, 0, 0, NULL));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40, 0x00, 0x00,
	    NULL, 0, 0, NULL));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40, 0x00, 0x00,
	    codec_id, 0x3D0901, 0, NULL));
	REJECT(hci_le_setup_iso_data_path(test_fd(), 0x40, 0x00, 0x00,
	    codec_id, 0, 1, NULL));
}

/* ================================================================
 * hci_send_raw_cmd (Vol 4 Part A 5.4.1): plen is a uint8_t (max 255), so
 * drive an ACCEPT-style call at the maximum command-parameter length.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(raw_cmd_maxlen);
ATF_TC_BODY(raw_cmd_maxlen, tc)
{
	uint8_t params[BT_HCI_COMMAND_PARAM_MAX];

	memset(params, 0, sizeof(params));
	/*
	 * hci_send_raw_cmd bypasses bt_devreq and calls send() directly on
	 * the fd; on a /dev/null fd send() fails, so it returns -1 with a
	 * non-EINVAL errno.  The point is that the 255-octet payload passes
	 * the length guard and the packet is assembled.
	 */
	ACCEPT(hci_send_raw_cmd(test_fd(), 0x2005, params,
	    BT_HCI_COMMAND_PARAM_MAX));
	ACCEPT(hci_send_raw_cmd(test_fd(), 0x2005, NULL, 0));
	REJECT(hci_send_raw_cmd(test_fd(), 0x2005, NULL, 1));
}

/* ================================================================
 * LE Privacy — resolving-list add / clear, address-resolution-enable,
 * privacy-mode.  No host-side range check, but driving each covers the
 * command-build and downstream-failure branches (hci_privacy.c).
 * Core Spec Vol 4 Part E 7.8.38 / 7.8.40 / 7.8.44 / 7.8.77.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(privacy_resolving_list_drive);
ATF_TC_BODY(privacy_resolving_list_drive, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t peer_irk[16], local_irk[16];

	memset(peer_irk, 0xA5, sizeof(peer_irk));
	memset(local_irk, 0x5A, sizeof(local_irk));

	ACCEPT(hci_le_add_dev_resolving_list(test_fd(), 0x00, addr, peer_irk,
	    local_irk));
	ACCEPT(hci_le_clear_resolving_list(test_fd()));
	ACCEPT(hci_le_set_addr_resolution_enable(test_fd(), 1));
	ACCEPT(hci_le_set_addr_resolution_enable(test_fd(), 0));
	ACCEPT(hci_le_set_privacy_mode(test_fd(), 0x01, addr, 0x01));
}

/* ================================================================
 * LE Filter Accept List clear / add / remove (7.8.15-7.8.17).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(filter_accept_list_drive);
ATF_TC_BODY(filter_accept_list_drive, tc)
{
	uint8_t addr[6] = { 6, 5, 4, 3, 2, 1 };

	ACCEPT(hci_le_clear_filter_accept_list(test_fd()));
	ACCEPT(hci_le_add_device_to_filter_accept_list(test_fd(), 0x00, addr));
	ACCEPT(hci_le_remove_device_from_filter_accept_list(test_fd(), 0x01,
	    addr));
}

/* ================================================================
 * Extended-advertising management encoders with no range check —
 * drive each to cover the command-build path (hci_adv.c).
 * Core Spec Vol 4 Part E 7.8.52 / 7.8.56 / 7.8.57 / 7.8.58 / 7.8.59 /
 * 7.8.60.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ext_adv_mgmt_drive);
ATF_TC_BODY(ext_adv_mgmt_drive, tc)
{
	uint8_t addr[6] = { 0, 1, 2, 3, 4, 5 };
	uint16_t max_len;
	uint8_t num_sets;

	ACCEPT(hci_le_set_ext_adv_enable(test_fd(), 1, 0));
	ACCEPT(hci_le_set_ext_adv_enable(test_fd(), 0, 0));
	ACCEPT(hci_le_remove_adv_set(test_fd(), 0));
	ACCEPT(hci_le_clear_adv_sets(test_fd()));
	ACCEPT(hci_le_set_adv_set_random_address(test_fd(), 0, addr));
	ACCEPT(hci_le_read_max_adv_data_length(test_fd(), &max_len));
	ACCEPT(hci_le_read_num_supported_adv_sets(test_fd(), &num_sets));
}

/* ================================================================
 * Periodic-advertising + PAST encoders with no range check — drive
 * each to cover the command-build path (hci_adv.c).
 * Core Spec Vol 4 Part E 7.8.63 / 7.8.67-7.8.73 / 7.8.88-7.8.92.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(periodic_and_past_drive);
ATF_TC_BODY(periodic_and_past_drive, tc)
{
	uint8_t addr[6] = { 9, 8, 7, 6, 5, 4 };
	uint8_t size;

	ACCEPT(hci_le_set_periodic_adv_enable(test_fd(), 1, 0));
	ACCEPT(hci_le_periodic_adv_create_sync(test_fd(), 0, 0, 0x00, addr,
	    0, 0x000A));
	ACCEPT(hci_le_periodic_adv_create_sync_cancel(test_fd()));
	ACCEPT(hci_le_periodic_adv_terminate_sync(test_fd(), 0x0001));
	ACCEPT(hci_le_add_dev_to_periodic_adv_list(test_fd(), 0x00, addr, 0));
	ACCEPT(hci_le_remove_dev_from_periodic_adv_list(test_fd(), 0x00, addr,
	    0));
	ACCEPT(hci_le_clear_periodic_adv_list(test_fd()));
	ACCEPT(hci_le_read_periodic_adv_list_size(test_fd(), &size));

	/* PAST (BT 5.1). */
	ACCEPT(hci_le_set_periodic_adv_receive_enable(test_fd(), 0x0001, 1));
	ACCEPT(hci_le_periodic_adv_sync_transfer(test_fd(), 0x0040, 0, 0x0001));
	ACCEPT(hci_le_periodic_adv_set_info_transfer(test_fd(), 0x0040, 0, 0));
	ACCEPT(hci_le_set_past_params(test_fd(), 0x0040, 0, 0, 0x000A, 0));
	ACCEPT(hci_le_set_default_past_params(test_fd(), 0, 0, 0x000A, 0));
}

/* ================================================================
 * Remaining CTE / connection encoders with no range check.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cte_and_conn_drive);
ATF_TC_BODY(cte_and_conn_drive, tc)
{
	uint8_t rates, ant, maxpat, maxcte;

	ACCEPT(hci_le_set_connless_cte_tx_enable(test_fd(), 0, 1));
	ACCEPT(hci_le_conn_cte_req_enable(test_fd(), 0x40, 1, 0x000A, 0x14,
	    0x00));
	ACCEPT(hci_le_conn_cte_rsp_enable(test_fd(), 0x40, 1));
	ACCEPT(hci_le_read_antenna_info(test_fd(), &rates, &ant, &maxpat,
	    &maxcte));
	ACCEPT(hci_le_set_default_phy(test_fd(), 0x00, 0x07, 0x07));
	ACCEPT(hci_le_set_phy(test_fd(), 0x40, 0x00, 0x07, 0x07, 0));
	ACCEPT(hci_le_set_host_feature(test_fd(), 32, 1));
	ACCEPT(hci_le_create_connection_cancel(test_fd()));
}

/* ================================================================
 * Remaining ISO encoders with no range check (hci_misc.c).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(iso_drive);
ATF_TC_BODY(iso_drive, tc)
{
	uint16_t alen, ilen;
	uint8_t anum, inum;

	ACCEPT(hci_le_read_buffer_size_v2(test_fd(), &alen, &anum, &ilen,
	    &inum));
	ACCEPT(hci_le_remove_cig(test_fd(), 0));
	ACCEPT(hci_le_accept_cis_request(test_fd(), 0x40));
	ACCEPT(hci_le_reject_cis_request(test_fd(), 0x40, 0x0D));
	ACCEPT(hci_le_terminate_big(test_fd(), 0, 0x16));
	ACCEPT(hci_le_big_terminate_sync(test_fd(), 0));
	ACCEPT(hci_le_remove_iso_data_path(test_fd(), 0x40, 0x03));
	ACCEPT(hci_le_request_peer_sca(test_fd(), 0x40));
}

/* ================================================================
 * ble_build_adv_data — pure function; boundary / overflow / each AD
 * type.  Core Spec Vol 3 Part C 11 (AD structures), CSS Part A 1.1/1.2.
 * ================================================================ */

/* Exactly 3 bytes: only the Flags structure fits. */
ATF_TC_WITHOUT_HEAD(build_adv_flags_only);
ATF_TC_BODY(build_adv_flags_only, tc)
{
	uint8_t buf[3];
	int len;

	len = ble_build_adv_data(buf, sizeof(buf), NULL, NULL, 0);
	ATF_REQUIRE_EQ(len, 3);
	ATF_CHECK_EQ(buf[0], 2);
	ATF_CHECK_EQ(buf[1], BT_AD_TYPE_FLAGS);
	ATF_CHECK_EQ(buf[2], BT_AD_FLAGS_LE_GENERAL_ONLY);
}

/* buflen < 3 cannot hold even Flags -> -1. */
ATF_TC_WITHOUT_HEAD(build_adv_too_small);
ATF_TC_BODY(build_adv_too_small, tc)
{
	uint8_t buf[2];

	ATF_CHECK_EQ(ble_build_adv_data(buf, sizeof(buf), NULL, NULL, 0), -1);
}

/*
 * Complete UUID16 list (0x03) when the whole list fits, appended after
 * Flags with no name.
 */
ATF_TC_WITHOUT_HEAD(build_adv_uuid_complete);
ATF_TC_BODY(build_adv_uuid_complete, tc)
{
	uint8_t buf[BT_HCI_LEGACY_ADV_DATA_MAX];
	uint16_t uuids[] = { BT_UUID16_BATTERY_SERVICE,
	    BT_UUID16_HID_SERVICE };
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), NULL, uuids, 2);
	ATF_REQUIRE(len > 0);
	/* Flags(3) then UUID list: len, type, 4 uuid bytes. */
	ATF_CHECK_EQ(buf[3], 1 + 2 * 2);
	ATF_CHECK_EQ(buf[4], BT_AD_TYPE_UUID16_COMPLETE);
	ATF_CHECK_EQ(buf[5], 0x0F);
	ATF_CHECK_EQ(buf[6], 0x18);
	ATF_CHECK_EQ(buf[7], 0x12);
	ATF_CHECK_EQ(buf[8], 0x18);
}

/*
 * Partial UUID list: when the full list does not fit but at least one
 * UUID + header does, the type downgrades to Incomplete (0x02) and only
 * the UUIDs that fit are emitted.  CSS Part A 1.1.
 */
ATF_TC_WITHOUT_HEAD(build_adv_uuid_incomplete);
ATF_TC_BODY(build_adv_uuid_incomplete, tc)
{
	/* 3 flags + room for header(2) + one UUID(2) = 7 bytes total. */
	uint8_t buf[7];
	uint16_t uuids[] = { BT_UUID16_BATTERY_SERVICE,
	    BT_UUID16_HID_SERVICE, BT_UUID16_DEVICE_INFORMATION };
	int len, i;
	bool saw_incomplete = false;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), NULL, uuids, 3);
	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= 7);
	for (i = 0; i < len; ) {
		uint8_t adlen = buf[i];
		uint8_t adtype = buf[i + 1];
		if (adtype == BT_AD_TYPE_UUID16_INCOMPLETE) {
			saw_incomplete = true;
			ATF_CHECK_EQ(adlen, 1 + 2);	/* exactly one UUID */
		}
		i += adlen + 1;
	}
	ATF_CHECK(saw_incomplete);
}

/*
 * When fewer than 4 bytes remain, no UUID structure is emitted at all
 * (the "avail >= 4" else-if is false, fit = 0): output is just Flags.
 */
ATF_TC_WITHOUT_HEAD(build_adv_uuid_no_room);
ATF_TC_BODY(build_adv_uuid_no_room, tc)
{
	uint8_t buf[5];		/* 3 flags + 2 spare (< 4 needed for a UUID) */
	uint16_t uuids[] = { BT_UUID16_BATTERY_SERVICE };
	int len;

	memset(buf, 0xEE, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), NULL, uuids, 1);
	ATF_CHECK_EQ(len, 3);		/* only Flags emitted */
}

/*
 * A name that fits exactly keeps the Complete Local Name type (0x09);
 * one byte tighter forces truncation to the Shortened type (0x08).
 * Core Spec / CSS Part A 1.2.
 */
ATF_TC_WITHOUT_HEAD(build_adv_name_complete_vs_short);
ATF_TC_BODY(build_adv_name_complete_vs_short, tc)
{
	uint8_t buf[9];		/* 3 flags + [len,type] + up to 4 name bytes */
	int len;

	/* "Test" (4 bytes) fits exactly -> Complete Local Name. */
	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "Test", NULL, 0);
	ATF_REQUIRE(len > 0);
	ATF_CHECK_EQ(buf[4], BT_AD_TYPE_NAME_COMPLETE);
	ATF_CHECK_EQ(buf[3], 1 + 4);

	/* One byte less of room forces a Shortened Local Name. */
	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf) - 1, "Test", NULL, 0);
	ATF_REQUIRE(len > 0);
	ATF_CHECK_EQ(buf[4], BT_AD_TYPE_NAME_SHORTENED);
}

/*
 * When only two bytes remain after Flags there is no room for even a
 * one-character name (namelen clamps to 0) so the name structure is
 * dropped entirely and only Flags is emitted.
 */
ATF_TC_WITHOUT_HEAD(build_adv_name_dropped);
ATF_TC_BODY(build_adv_name_dropped, tc)
{
	uint8_t buf[5];		/* 3 flags + 2 spare: 2 < [len,type] + >=1 */
	int len;

	memset(buf, 0, sizeof(buf));
	len = ble_build_adv_data(buf, sizeof(buf), "Name", NULL, 0);
	ATF_CHECK_EQ(len, 3);		/* name did not fit, only Flags */
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	/* Advertising / scan-response data length checks. */
	ATF_TP_ADD_TC(tp, legacy_adv_data_len);
	ATF_TP_ADD_TC(tp, ext_adv_data_len);
	ATF_TP_ADD_TC(tp, periodic_adv_data_len);

	/* Direction finding. */
	ATF_TP_ADD_TC(tp, cte_switching_len_bounds);

	/* CIS / ISO length checks. */
	ATF_TP_ADD_TC(tp, cig_params_len_bound);
	ATF_TP_ADD_TC(tp, cig_params_spec_ranges);
	ATF_TP_ADD_TC(tp, create_cis_accept);
	ATF_TP_ADD_TC(tp, big_create_sync_num_bis_bound);
	ATF_TP_ADD_TC(tp, setup_iso_data_path_maxlen);

	/* Raw command length guard. */
	ATF_TP_ADD_TC(tp, raw_cmd_maxlen);

	/* Privacy / filter list. */
	ATF_TP_ADD_TC(tp, privacy_resolving_list_drive);
	ATF_TP_ADD_TC(tp, filter_accept_list_drive);

	/* No-range-check encoder drives. */
	ATF_TP_ADD_TC(tp, ext_adv_mgmt_drive);
	ATF_TP_ADD_TC(tp, periodic_and_past_drive);
	ATF_TP_ADD_TC(tp, cte_and_conn_drive);
	ATF_TP_ADD_TC(tp, iso_drive);

	/* ble_build_adv_data boundaries. */
	ATF_TP_ADD_TC(tp, build_adv_flags_only);
	ATF_TP_ADD_TC(tp, build_adv_too_small);
	ATF_TP_ADD_TC(tp, build_adv_uuid_complete);
	ATF_TP_ADD_TC(tp, build_adv_uuid_incomplete);
	ATF_TP_ADD_TC(tp, build_adv_uuid_no_room);
	ATF_TP_ADD_TC(tp, build_adv_name_complete_vs_short);
	ATF_TP_ADD_TC(tp, build_adv_name_dropped);

	return (atf_no_error());
}
