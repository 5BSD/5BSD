/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Core 6.3/CSS v12 advertising parser oracles.
 * No production Bluetooth header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_SCAN_PARSE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_SCAN_PARSE_ORACLES_H

/* CSS v12 Part A §1 assigned AD types. */
#define BT_SP_SPEC_AD_FLAGS                 0x01
#define BT_SP_SPEC_AD_UUID16_INCOMPLETE     0x02
#define BT_SP_SPEC_AD_UUID16_COMPLETE       0x03
#define BT_SP_SPEC_AD_SHORT_NAME            0x08
#define BT_SP_SPEC_AD_COMPLETE_NAME         0x09
#define BT_SP_SPEC_AD_TX_POWER              0x0a
#define BT_SP_SPEC_AD_MANUFACTURER           0xff
#define BT_SP_SPEC_COMPANY_APPLE             0x004c
#define BT_SP_SPEC_UUID_BATTERY_SERVICE      0x180f
#define BT_SP_SPEC_UUID_HID_SERVICE          0x1812
#define BT_SP_SPEC_MFR_NONE                  0xffff

/* Core 6.3 Vol 4 Part E §7.7.65.13 report fields. */
#define BT_SP_SPEC_EXT_REPORT_FIXED_LEN      24
#define BT_SP_SPEC_EXT_REPORT_DATA_MAX       229
#define BT_SP_SPEC_ADDR_PUBLIC               0x00
#define BT_SP_SPEC_ADDR_RANDOM               0x01
#define BT_SP_SPEC_ADDR_PUBLIC_IDENTITY      0x02
#define BT_SP_SPEC_ADDR_RANDOM_IDENTITY      0x03
#define BT_SP_SPEC_ADDR_ANONYMOUS            0xff
#define BT_SP_SPEC_PRIMARY_PHY_1M            0x01
#define BT_SP_SPEC_PRIMARY_PHY_CODED         0x03
#define BT_SP_SPEC_DATA_STATUS_RESERVED      0x0060
#define BT_SP_SPEC_LEGACY_BIT                0x0010
#define BT_SP_SPEC_LEGACY_UNDEFINED          0x0011
#define BT_SP_SPEC_DATA_LEN_OFFSET           23
#define BT_SP_SPEC_ADDR_TYPE_OFFSET          2
#define BT_SP_SPEC_ADDR_OFFSET               3
#define BT_SP_SPEC_PRIMARY_PHY_OFFSET        9
#define BT_SP_SPEC_RSSI_OFFSET               13

#endif
