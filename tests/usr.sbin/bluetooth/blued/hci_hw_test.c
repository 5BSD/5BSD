/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF hardware integration tests for blued HCI commands.
 *
 * HARDWARE REQUIREMENTS
 *
 *   Requires a real Bluetooth adapter attached as ubt0 and root
 *   privileges.  Tests are skipped gracefully via atf_tc_skip()
 *   if no adapter is present or if the controller lacks a required
 *   feature (e.g., extended advertising, 2M PHY).
 *
 *   Tested adapters:
 *     - Intel AX201 (USB 8087:0026) — BT 5.2, all features
 *
 *   Any USB adapter supported by the ubt(4) driver should work.
 *   Common chipsets: Intel (8087:xxxx), Realtek (0bda:xxxx),
 *   Mediatek (0e8d:xxxx), Qualcomm/Atheros (0cf3:xxxx),
 *   Cambridge Silicon Radio (0a12:0001).
 *
 * RUNNING
 *
 *   These tests require root and a live adapter:
 *     # cd /usr/tests/usr.sbin/bluetooth/blued
 *     # kyua test hci_hw_test
 *
 *   Or run a single test:
 *     # kyua test hci_hw_test:hci_hw_legacy_adv_cycle
 *
 *   Without root or an adapter, all hardware tests are skipped.
 *   The two non-hardware tests (test_adv_data_format,
 *   test_adv_data_name_truncation) always run.
 *
 * ADDING NEW HARDWARE TESTS
 *
 *   Pattern: each test exercises one HCI command or a small
 *   command sequence, resets the controller first, and restores
 *   state on exit.  Follow this model:
 *
 *   1. Use ATF_TC (not ATF_TC_WITHOUT_HEAD) so you can set metadata:
 *        ATF_TC(my_test);
 *        ATF_TC_HEAD(my_test, tc)
 *        {
 *            atf_tc_set_md_var(tc, "require.user", "root");
 *            atf_tc_set_md_var(tc, "descr",
 *                "Core Spec Vol X Part Y §Z.Z: Feature Name");
 *        }
 *
 *   2. Open the adapter with open_adapter() — returns fd or skips.
 *
 *   3. Call hci_reset(fd) + usleep(100000) to start clean.
 *
 *   4. Feature-gate with hci_le_read_local_features():
 *        hci_le_read_local_features(fd, &features);
 *        if (!(features & LE_FEAT_XXX))
 *            atf_tc_skip("controller does not support XXX");
 *
 *   5. Exercise the HCI command(s) and check return values.
 *
 *   6. Clean up resources (clear lists, disable advertising, etc.)
 *      before close(fd).
 *
 *   7. Register the test in ATF_TP_ADD_TCS at the bottom of this
 *      file under the appropriate spec section comment.
 *
 *   8. Add SRCS to Makefile if new source files are needed:
 *        SRCS.hci_hw_test+= new_file.c
 *
 *   Feature flag reference (from hci_util.h):
 *     LE_FEAT_ENCRYPTION          (BT 4.0, mandatory)
 *     LE_FEAT_CONN_PARAM_REQ      (BT 4.1)
 *     LE_FEAT_DATA_LENGTH_EXT     (BT 4.2)
 *     LE_FEAT_LL_PRIVACY          (BT 4.2)
 *     LE_FEAT_2M_PHY              (BT 5.0)
 *     LE_FEAT_CODED_PHY           (BT 5.0)
 *     LE_FEAT_EXT_ADVERTISING     (BT 5.0)
 *     LE_FEAT_PERIODIC_ADV        (BT 5.0)
 *     LE_FEAT_CONN_CTE_REQ        (BT 5.1, direction finding)
 *     LE_FEAT_CONN_CTE_RSP        (BT 5.1, direction finding)
 *     LE_FEAT_CONNLESS_CTE_TX     (BT 5.1, connectionless CTE)
 *     LE_FEAT_CONNLESS_CTE_RX     (BT 5.1, connectionless CTE)
 *     LE_FEAT_POWER_CONTROL       (BT 5.2)
 *     LE_FEAT_CONN_SUBRATING      (BT 5.3)
 */

#include <sys/types.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ble_util.h"
#include "hci_log.h"
#include "hci_util.h"
#include "adv_builder.h"
#include "spec_hci_hw_oracles.h"

/* ble_util.h globals */
atomic_int blued_verbose = 1;	/* enable logging for diagnostics */
int blued_daemonized;

static int
open_adapter(void)
{
	int fd;

	fd = hci_open("ubt0");
	if (fd < 0)
		atf_tc_skip("no ubt0 adapter available");
	return (fd);
}

/* ================================================================
 * Adapter lifecycle — Core Spec Vol 4 Part E §7.1-7.4
 * ================================================================ */

ATF_TC(hci_open_close);
ATF_TC_HEAD(hci_open_close, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E: HCI adapter open/close");
}
ATF_TC_BODY(hci_open_close, tc)
{
	int fd = open_adapter();
	ATF_CHECK(fd >= 0);
	close(fd);
}

ATF_TC(hci_hw_reset);
ATF_TC_HEAD(hci_hw_reset, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.3.2: HCI Reset");
}
ATF_TC_BODY(hci_hw_reset, tc)
{
	int fd = open_adapter();
	ATF_CHECK_EQ(hci_reset(fd), 0);
	usleep(100000);
	close(fd);
}

ATF_TC(hci_hw_read_bdaddr);
ATF_TC_HEAD(hci_hw_read_bdaddr, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.4.6: Read BD_ADDR");
}
ATF_TC_BODY(hci_hw_read_bdaddr, tc)
{
	int fd = open_adapter();
	uint8_t addr[6] = {0};

	ATF_CHECK_EQ(hci_get_bdaddr(fd, addr), 0);
	/* At least one byte should be non-zero */
	int nonzero = 0;
	for (int i = 0; i < 6; i++)
		if (addr[i] != 0)
			nonzero++;
	ATF_CHECK_MSG(nonzero > 0, "BD_ADDR is all zeros");

	char str[18];
	bt_ntoa((bdaddr_t *)addr, str);
	printf("BD_ADDR: %s\n", str);
	close(fd);
}

ATF_TC(hci_hw_read_features);
ATF_TC_HEAD(hci_hw_read_features, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.3: LE Read Local Features");
}
ATF_TC_BODY(hci_hw_read_features, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;

	ATF_CHECK_EQ(hci_le_read_local_features(fd, &features), 0);
	ATF_CHECK_MSG(features != 0, "LE features are all zero");
	/* LE Encryption (bit 0) is mandatory */
	ATF_CHECK_MSG(features & BT_HW_FEAT_ENCRYPTION,
	    "LE Encryption not supported (mandatory feature)");
	printf("LE features: 0x%llx\n", (unsigned long long)features);
	if (features & BT_HW_FEAT_DATA_LENGTH_EXT)
		printf("  Data Length Extension: yes\n");
	if (features & BT_HW_FEAT_2M_PHY)
		printf("  2M PHY: yes\n");
	if (features & BT_HW_FEAT_EXT_ADVERTISING)
		printf("  Extended Advertising: yes\n");
	if (features & BT_HW_FEAT_LL_PRIVACY)
		printf("  LL Privacy: yes\n");
	if (features & BT_HW_FEAT_CONN_PARAM_REQ)
		printf("  Connection Parameter Request: yes\n");
	close(fd);
}

ATF_TC(hci_hw_read_buffer_size);
ATF_TC_HEAD(hci_hw_read_buffer_size, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.2: LE Read Buffer Size");
}
ATF_TC_BODY(hci_hw_read_buffer_size, tc)
{
	int fd = open_adapter();
	uint16_t acl_len = 0, iso_len = 0;
	uint8_t acl_num = 0, iso_num = 0;

	/* v2 may not be supported; just check it doesn't crash */
	int ret = hci_le_read_buffer_size_v2(fd, &acl_len, &acl_num,
	    &iso_len, &iso_num);
	if (ret == 0) {
		printf("LE Buffer: acl_len=%d acl_num=%d iso_len=%d iso_num=%d\n",
		    acl_len, acl_num, iso_len, iso_num);
		/*
		 * Vol 4 Part E §7.8.2 permits both LE ACL fields to be zero
		 * when the Controller shares the BR/EDR data buffers.
		 */
	} else {
		printf("LE Read Buffer Size v2 not supported (OK)\n");
	}
	close(fd);
}

/* ================================================================
 * Advertising — Core Spec Vol 4 Part E §7.8.5-7.8.10
 * ================================================================ */

ATF_TC(hci_hw_legacy_adv_cycle);
ATF_TC_HEAD(hci_hw_legacy_adv_cycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.5-10: Legacy advertising cycle");
}
ATF_TC_BODY(hci_hw_legacy_adv_cycle, tc)
{
	int fd = open_adapter();
	uint8_t adv_data[BT_HW_LEGACY_ADV_DATA_MAX];
	int adv_len;
	uint16_t uuids[] = { BT_HW_GAP_SERVICE_UUID };

	hci_reset(fd);
	usleep(100000);
	hci_write_le_host_support(fd, 1, 1);
	hci_node_init(fd);

	ATF_CHECK_EQ(hci_le_set_advertising_params(fd,
	    BT_HW_ADV_INTERVAL_SAMPLE, BT_HW_ADV_INTERVAL_SAMPLE, 0, 0, 0), 0);

	adv_len = ble_build_adv_data(adv_data, sizeof(adv_data),
	    "ATF-Test", uuids, 1);
	ATF_REQUIRE(adv_len > 0);
	ATF_CHECK_EQ(hci_le_set_advertising_data(fd, adv_data,
	    (uint8_t)adv_len), 0);

	/* Scan response */
	uint8_t scan_rsp[BT_HW_LEGACY_ADV_DATA_MAX];
	int sr_len = 0;
	scan_rsp[sr_len++] = 9; /* length */
	scan_rsp[sr_len++] = BT_HW_AD_TYPE_NAME_COMPLETE;
	memcpy(scan_rsp + sr_len, "ATF-Test", 8);
	sr_len += 8;
	ATF_CHECK_EQ(hci_le_set_scan_response_data(fd, scan_rsp,
	    (uint8_t)sr_len), 0);

	ATF_CHECK_EQ(hci_le_set_advertise_enable(fd, true), 0);
	usleep(200000); /* advertise briefly */
	ATF_CHECK_EQ(hci_le_set_advertise_enable(fd, false), 0);

	close(fd);
}

/* ================================================================
 * Privacy — Core Spec Vol 4 Part E §7.8.38-45
 * ================================================================ */

ATF_TC(hci_hw_resolving_list);
ATF_TC_HEAD(hci_hw_resolving_list, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.38-45: Resolving list lifecycle");
}
ATF_TC_BODY(hci_hw_resolving_list, tc)
{
	int fd = open_adapter();
	uint8_t test_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t test_irk[16];
	uint8_t zero_irk[16] = {0};

	hci_reset(fd);
	usleep(100000);

	arc4random_buf(test_irk, sizeof(test_irk));

	ATF_CHECK_EQ(hci_le_clear_resolving_list(fd), 0);
	ATF_CHECK_EQ(hci_le_add_dev_resolving_list(fd, BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr, test_irk, zero_irk), 0);
	ATF_CHECK_EQ(hci_le_set_rpa_timeout(fd, BT_HW_RPA_TIMEOUT_DEFAULT), 0);
	ATF_CHECK_EQ(hci_le_set_addr_resolution_enable(fd, 1), 0);
	ATF_CHECK_EQ(hci_le_set_addr_resolution_enable(fd, 0), 0);
	ATF_CHECK_EQ(hci_le_clear_resolving_list(fd), 0);

	close(fd);
}

/* ================================================================
 * Filter Accept List — Core Spec Vol 4 Part E §7.8.16-18
 * ================================================================ */

ATF_TC(hci_hw_filter_accept_list);
ATF_TC_HEAD(hci_hw_filter_accept_list, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.16-18: Filter Accept List");
}
ATF_TC_BODY(hci_hw_filter_accept_list, tc)
{
	int fd = open_adapter();
	uint8_t test_addr[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

	hci_reset(fd);
	usleep(100000);

	ATF_CHECK_EQ(hci_le_clear_filter_accept_list(fd), 0);
	ATF_CHECK_EQ(hci_le_add_device_to_filter_accept_list(fd,
	    BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr), 0);
	ATF_CHECK_EQ(hci_le_remove_device_from_filter_accept_list(fd,
	    BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr), 0);
	ATF_CHECK_EQ(hci_le_clear_filter_accept_list(fd), 0);

	close(fd);
}

/* ================================================================
 * Data Length + PHY — Core Spec Vol 4 Part E §7.8.33-35, §7.8.48
 * ================================================================ */

ATF_TC(hci_hw_data_length_defaults);
ATF_TC_HEAD(hci_hw_data_length_defaults, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.35: Suggested Default Data Length");
}
ATF_TC_BODY(hci_hw_data_length_defaults, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;

	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_DATA_LENGTH_EXT))
		atf_tc_skip("controller does not support DLE");

	ATF_CHECK_EQ(hci_le_write_suggested_default_data_length(fd,
	    BT_HW_DATA_OCTETS_MAX, BT_HW_DATA_TIME_MAX), 0);
	close(fd);
}

ATF_TC(hci_hw_default_phy);
ATF_TC_HEAD(hci_hw_default_phy, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.48: Set Default PHY");
}
ATF_TC_BODY(hci_hw_default_phy, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;

	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_2M_PHY))
		atf_tc_skip("controller does not support 2M PHY");

	ATF_CHECK_EQ(hci_le_set_default_phy(fd,
	    BT_HW_ALL_PHYS_HAVE_PREFERENCE, BT_HW_PHY_2M_BIT,
	    BT_HW_PHY_2M_BIT), 0);
	close(fd);
}

/* ================================================================
 * Advertising data encoding — Core Spec Vol 3 Part C §11
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(test_adv_data_format);
ATF_TC_BODY(test_adv_data_format, tc)
{
	uint8_t buf[BT_HW_LEGACY_ADV_DATA_MAX];
	uint16_t uuids[] = { BT_HW_GAP_SERVICE_UUID, 0xffe0 };
	int len;

	len = ble_build_adv_data(buf, sizeof(buf), "TestDev", uuids, 2);
	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= BT_HW_LEGACY_ADV_DATA_MAX);

	/* First element should be Flags */
	ATF_CHECK_EQ(buf[1], BT_HW_AD_TYPE_FLAGS);
	ATF_CHECK_EQ(buf[2], BT_HW_AD_FLAGS_GENERAL_NO_BREDR);

	/* Verify total length matches returned length */
	int pos = 0;
	int elements = 0;
	while (pos < len) {
		int elen = buf[pos];
		ATF_REQUIRE(elen > 0);
		pos += 1 + elen;
		elements++;
	}
	ATF_CHECK_EQ(pos, len);
	ATF_CHECK(elements >= 2); /* at least Flags + Name or UUIDs */
}

/* ================================================================
 * Scan — Core Spec Vol 4 Part E §7.8.11-12
 * ================================================================ */

ATF_TC(hci_hw_scan_2sec);
ATF_TC_HEAD(hci_hw_scan_2sec, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "10");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.11-12: LE Scan (2 seconds)");
}
ATF_TC_BODY(hci_hw_scan_2sec, tc)
{
	int fd = open_adapter();
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults = 0;

	hci_reset(fd);
	usleep(100000);
	hci_write_le_host_support(fd, 1, 1);
	hci_node_init(fd);

	int ret = hci_le_scan(fd, 2, results, BLE_MAX_SCAN_RESULTS,
	    &nresults);
	ATF_CHECK_EQ(ret, 0);
	printf("Scan found %d device(s)\n", nresults);
	for (int i = 0; i < nresults && i < 5; i++) {
		char addr[18];
		bt_ntoa((bdaddr_t *)results[i].addr, addr);
		printf("  %s rssi=%d %s\n", addr, results[i].rssi,
		    results[i].has_name ? results[i].name : "");
	}

	close(fd);
}

/* ================================================================
 * BLE 5.0: Extended Advertising — Core Spec Vol 4 Part E §7.8.53-56
 * ================================================================ */

ATF_TC(hci_hw_ext_adv_cycle);
ATF_TC_HEAD(hci_hw_ext_adv_cycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.53-56: Extended advertising cycle");
}
ATF_TC_BODY(hci_hw_ext_adv_cycle, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;
	uint8_t adv_data[BT_HW_LEGACY_ADV_DATA_MAX];
	int adv_len;
	uint16_t uuids[] = { BT_HW_GAP_SERVICE_UUID };

	hci_reset(fd);
	usleep(100000);
	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_EXT_ADVERTISING))
		atf_tc_skip("controller does not support extended advertising");

	hci_write_le_host_support(fd, 1, 1);
	hci_node_init(fd);

	/* Clear stale sets */
	hci_le_clear_adv_sets(fd);

	/* Set ext adv params (legacy connectable) */
	ATF_CHECK_EQ(hci_le_set_ext_adv_params(fd, BT_HW_ADV_HANDLE_MIN,
	    BT_HW_LEGACY_CONN_SCAN_PROPS, BT_HW_ADV_INTERVAL_SAMPLE,
	    BT_HW_ADV_INTERVAL_SAMPLE, 0, BT_HW_PUBLIC_ADDR_TYPE), 0);

	/* Set data */
	adv_len = ble_build_adv_data(adv_data, sizeof(adv_data),
	    "ATF-Ext", uuids, 1);
	ATF_REQUIRE(adv_len > 0);
	ATF_CHECK_EQ(hci_le_set_ext_adv_data(fd, BT_HW_ADV_HANDLE_MIN, adv_data,
	    (uint8_t)adv_len), 0);

	/* Set scan response */
	uint8_t sr[BT_HW_LEGACY_ADV_DATA_MAX];
	int sr_len = 0;
	sr[sr_len++] = 8;
	sr[sr_len++] = BT_HW_AD_TYPE_NAME_COMPLETE;
	memcpy(sr + sr_len, "ATF-Ext", 7);
	sr_len += 7;
	ATF_CHECK_EQ(hci_le_set_ext_scan_response_data(fd,
	    BT_HW_ADV_HANDLE_MIN, sr,
	    (uint8_t)sr_len), 0);

	/* Enable, brief advertise, disable */
	ATF_CHECK_EQ(hci_le_set_ext_adv_enable(fd, 1,
	    BT_HW_ADV_HANDLE_MIN), 0);
	usleep(200000);
	ATF_CHECK_EQ(hci_le_set_ext_adv_enable(fd, 0,
	    BT_HW_ADV_HANDLE_MIN), 0);

	/* Remove set */
	ATF_CHECK_EQ(hci_le_remove_adv_set(fd, BT_HW_ADV_HANDLE_MIN), 0);

	close(fd);
}

/* BLE 5.0: Periodic advertising — Core Spec Vol 4 Part E §7.8.61-.63. */
ATF_TC(hci_hw_periodic_adv_cycle);
ATF_TC_HEAD(hci_hw_periodic_adv_cycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.61-.63: periodic advertising cycle");
}
ATF_TC_BODY(hci_hw_periodic_adv_cycle, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;
	const uint8_t data[] = { 0x02, BT_HW_AD_TYPE_FLAGS,
	    BT_HW_AD_FLAGS_GENERAL_NO_BREDR };

	hci_reset(fd);
	usleep(100000);
	ATF_REQUIRE_EQ(0, hci_le_read_local_features(fd, &features));
	if ((features & BT_HW_FEAT_PERIODIC_ADVERTISING) == 0)
		atf_tc_skip("controller does not support periodic advertising");

	/* Periodic advertising is configured on the single deterministic set 0. */
	ATF_REQUIRE_EQ(0, hci_le_clear_adv_sets(fd));
	ATF_REQUIRE_EQ(0, hci_le_set_ext_adv_params(fd, BT_HW_ADV_HANDLE_MIN,
	    BT_HW_LEGACY_CONN_SCAN_PROPS, BT_HW_ADV_INTERVAL_SAMPLE,
	    BT_HW_ADV_INTERVAL_SAMPLE, 0, BT_HW_PUBLIC_ADDR_TYPE));
	ATF_REQUIRE_EQ(0, hci_le_set_periodic_adv_params(fd,
	    BT_HW_ADV_HANDLE_MIN, BT_HW_PERIODIC_INTERVAL_MIN,
	    BT_HW_PERIODIC_INTERVAL_SAMPLE, 0));
	ATF_REQUIRE_EQ(0, hci_le_set_periodic_adv_data(fd, 0, data,
	    sizeof(data)));
	ATF_REQUIRE_EQ(0, hci_le_set_periodic_adv_enable(fd, 1, 0));
	usleep(200000);
	ATF_CHECK_EQ(0, hci_le_set_periodic_adv_enable(fd, 0, 0));
	ATF_CHECK_EQ(0, hci_le_remove_adv_set(fd, 0));
	close(fd);
}

/* BLE 5.0: Advertising capabilities query */
ATF_TC(hci_hw_adv_capabilities);
ATF_TC_HEAD(hci_hw_adv_capabilities, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.57-58: Advertising capabilities");
}
ATF_TC_BODY(hci_hw_adv_capabilities, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;
	uint8_t num_sets = 0;
	uint16_t max_len = 0;

	hci_reset(fd);
	usleep(100000);
	hci_write_le_host_support(fd, 1, 1);
	hci_node_init(fd);
	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_EXT_ADVERTISING))
		atf_tc_skip("no extended advertising support");

	ATF_CHECK_EQ(hci_le_read_num_supported_adv_sets(fd, &num_sets), 0);
	ATF_CHECK(num_sets > 0);
	printf("Supported advertising sets: %d\n", num_sets);

	ATF_CHECK_EQ(hci_le_read_max_adv_data_length(fd, &max_len), 0);
	ATF_CHECK(max_len >= BT_HW_LEGACY_ADV_DATA_MAX);
	printf("Max advertising data length: %d\n", max_len);

	close(fd);
}

/* BLE 5.0: Extended scan */
ATF_TC(hci_hw_ext_scan_2sec);
ATF_TC_HEAD(hci_hw_ext_scan_2sec, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "10");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.64-65: Extended scan");
}
ATF_TC_BODY(hci_hw_ext_scan_2sec, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;
	struct ble_scan_result results[BLE_MAX_SCAN_RESULTS];
	int nresults = 0;

	hci_reset(fd);
	usleep(100000);
	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_EXT_ADVERTISING))
		atf_tc_skip("no extended scanning support");

	hci_write_le_host_support(fd, 1, 1);
	hci_node_init(fd);

	int ret = hci_le_ext_scan(fd, 2, results, BLE_MAX_SCAN_RESULTS,
	    &nresults, BT_HW_PHY_1M_BIT);
	ATF_CHECK_EQ(ret, 0);
	printf("Extended scan found %d device(s)\n", nresults);

	close(fd);
}

/* BLE 4.2: Privacy mode setting */
ATF_TC(hci_hw_privacy_mode);
ATF_TC_HEAD(hci_hw_privacy_mode, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 4 Part E §7.8.77: LE Set Privacy Mode");
}
ATF_TC_BODY(hci_hw_privacy_mode, tc)
{
	int fd = open_adapter();
	uint8_t test_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t irk[16] = {0}, zero_irk[16] = {0};
	uint64_t features = 0;

	hci_reset(fd);
	usleep(100000);
	hci_le_read_local_features(fd, &features);
	if (!(features & BT_HW_FEAT_LL_PRIVACY))
		atf_tc_skip("no LL Privacy support");

	hci_le_clear_resolving_list(fd);
	arc4random_buf(irk, sizeof(irk));
	ATF_CHECK_EQ(hci_le_add_dev_resolving_list(fd, BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr, irk, zero_irk), 0);

	/* Device privacy mode (0x01) */
	ATF_CHECK_EQ(hci_le_set_privacy_mode(fd, BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr, BT_HW_PRIVACY_MODE_DEVICE), 0);
	/* Network privacy mode (0x00) */
	ATF_CHECK_EQ(hci_le_set_privacy_mode(fd, BT_HW_PUBLIC_ADDR_TYPE,
	    test_addr, BT_HW_PRIVACY_MODE_NETWORK), 0);

	hci_le_clear_resolving_list(fd);
	close(fd);
}

/* BLE 4.1: Connection Parameter Request support check */
ATF_TC(hci_hw_conn_param_req);
ATF_TC_HEAD(hci_hw_conn_param_req, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Core Spec Vol 6 Part B §4.5: LL Connection Parameter Request");
}
ATF_TC_BODY(hci_hw_conn_param_req, tc)
{
	int fd = open_adapter();
	uint64_t features = 0;

	ATF_CHECK_EQ(hci_le_read_local_features(fd, &features), 0);
	/* Vol 6 Part B §4.6 marks this feature optional; absence is not failure. */
	if ((features & BT_HW_FEAT_CONN_PARAM_REQ) == 0)
		atf_tc_skip("controller lacks optional Connection Parameters Request");
	printf("LL Connection Parameter Request: supported\n");

	close(fd);
}

/* Advertising data: name truncation */
ATF_TC_WITHOUT_HEAD(test_adv_data_name_truncation);
ATF_TC_BODY(test_adv_data_name_truncation, tc)
{
	uint8_t buf[BT_HW_LEGACY_ADV_DATA_MAX];
	uint16_t uuids[] = { BT_HW_GAP_SERVICE_UUID };
	int len;

	/* Long name that won't fit in 31 bytes with flags + UUID */
	len = ble_build_adv_data(buf, sizeof(buf),
	    "This Name Is Way Too Long For BLE", uuids, 1);
	ATF_REQUIRE(len > 0);
	ATF_CHECK(len <= BT_HW_LEGACY_ADV_DATA_MAX);

	/* Should use Shortened Local Name (0x08) instead of Complete (0x09) */
	int found_name = 0;
	int pos = 0;
	while (pos < len) {
		int elen = buf[pos];
		uint8_t type = buf[pos + 1];
		if (type == BT_HW_AD_TYPE_NAME_SHORT ||
		    type == BT_HW_AD_TYPE_NAME_COMPLETE)
			found_name = type;
		pos += 1 + elen;
	}
	/* CSS Part A §1.8 requires the shortened type after truncation. */
	ATF_CHECK_EQ(found_name, BT_HW_AD_TYPE_NAME_SHORT);
}

/* ================================================================ */

ATF_TP_ADD_TCS(tp)
{

	/* Adapter lifecycle */
	ATF_TP_ADD_TC(tp, hci_open_close);
	ATF_TP_ADD_TC(tp, hci_hw_reset);
	ATF_TP_ADD_TC(tp, hci_hw_read_bdaddr);
	ATF_TP_ADD_TC(tp, hci_hw_read_features);
	ATF_TP_ADD_TC(tp, hci_hw_read_buffer_size);

	/* Advertising */
	ATF_TP_ADD_TC(tp, hci_hw_legacy_adv_cycle);

	/* Privacy */
	ATF_TP_ADD_TC(tp, hci_hw_resolving_list);

	/* Filter Accept List */
	ATF_TP_ADD_TC(tp, hci_hw_filter_accept_list);

	/* Data Length + PHY */
	ATF_TP_ADD_TC(tp, hci_hw_data_length_defaults);
	ATF_TP_ADD_TC(tp, hci_hw_default_phy);

	/* Advertising data encoding (no hardware needed) */
	ATF_TP_ADD_TC(tp, test_adv_data_format);

	/* Scan */
	ATF_TP_ADD_TC(tp, hci_hw_scan_2sec);

	/* BLE 4.1 */
	ATF_TP_ADD_TC(tp, hci_hw_conn_param_req);

	/* BLE 4.2 Privacy */
	ATF_TP_ADD_TC(tp, hci_hw_privacy_mode);

	/* BLE 5.0 Extended Advertising */
	ATF_TP_ADD_TC(tp, hci_hw_ext_adv_cycle);
	ATF_TP_ADD_TC(tp, hci_hw_periodic_adv_cycle);
	ATF_TP_ADD_TC(tp, hci_hw_adv_capabilities);
	ATF_TP_ADD_TC(tp, hci_hw_ext_scan_2sec);

	/* Advertising data edge cases */
	ATF_TP_ADD_TC(tp, test_adv_data_name_truncation);

	return (atf_no_error());
}
