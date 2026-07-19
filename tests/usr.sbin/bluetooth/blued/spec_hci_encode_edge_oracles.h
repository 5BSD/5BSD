/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 HCI encoder-edge oracles.
 *
 * This file deliberately includes no production header.  Each value below
 * is transcribed from the named specification table so tests do not obtain
 * expected values from the implementation under test.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_ENCODE_EDGE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_ENCODE_EDGE_ORACLES_H

/* Vol 4, Part E §5.4.1: HCI Command Parameter_Total_Length is one octet. */
#define BT_HCI_COMMAND_PARAM_MAX                 0xff

/* Vol 4, Part E §§7.8.7-.8: legacy advertising payload range. */
#define BT_HCI_LEGACY_ADV_DATA_MAX               0x1f
#define BT_HCI_LEGACY_ADV_DATA_FIRST_INVALID     0x20

/* Vol 4, Part E §§7.8.54-.55 and .62: one command fragment sizes. */
#define BT_HCI_EXT_ADV_FRAGMENT_MAX              251
#define BT_HCI_EXT_ADV_FRAGMENT_FIRST_INVALID    252
#define BT_HCI_PERIODIC_ADV_FRAGMENT_MAX         252
#define BT_HCI_PERIODIC_ADV_FRAGMENT_FIRST_INVALID 253

/* Vol 4, Part E §§7.8.82-.84 parameter tables. */
#define BT_HCI_CTE_SWITCH_PATTERN_MIN            0x02
#define BT_HCI_CTE_SWITCH_PATTERN_MAX            0x4b
#define BT_HCI_CTE_SWITCH_PATTERN_FIRST_HIGH     0x4c
#define BT_HCI_CTE_TYPE_AOA                      0x01

/* Vol 4, Part E §§7.8.97, .99, .106 and .109. */
#define BT_HCI_CIG_FIXED_PARAM_LEN               15
#define BT_HCI_CIS_PARAM_LEN                     9
#define BT_HCI_ISO_STREAM_COUNT_MAX              0x1f
#define BT_HCI_ISO_STREAM_COUNT_FIRST_HIGH       0x20
#define BT_HCI_HANDLE_MAX                        0x0eff
#define BT_HCI_HANDLE_FIRST_RESERVED             0x0f00
#define BT_HCI_SETUP_ISO_FIXED_PARAM_LEN         13
#define BT_HCI_SETUP_ISO_CODEC_CONFIG_MAX        \
    (BT_HCI_COMMAND_PARAM_MAX - BT_HCI_SETUP_ISO_FIXED_PARAM_LEN)
#define BT_HCI_SETUP_ISO_CODEC_CONFIG_FIRST_HIGH \
    (BT_HCI_SETUP_ISO_CODEC_CONFIG_MAX + 1)
#define BT_HCI_ISO_PATH_INPUT                    0x00
#define BT_HCI_ISO_PATH_OUTPUT                   0x01
#define BT_HCI_ISO_PATH_FIRST_RESERVED           0xff
#define BT_HCI_CONTROLLER_DELAY_MAX              0x3d0900

/* Vol 4, Part E §7.8.109 and Assigned Numbers, Coding Format. */
#define BT_HCI_CODEC_TRANSPARENT                 0x03

/* Core Supplement 12, Part A §§1.1, 1.2 and 1.3. */
#define BT_AD_TYPE_FLAGS                         0x01
#define BT_AD_TYPE_UUID16_INCOMPLETE             0x02
#define BT_AD_TYPE_UUID16_COMPLETE               0x03
#define BT_AD_TYPE_NAME_SHORTENED                 0x08
#define BT_AD_TYPE_NAME_COMPLETE                  0x09
#define BT_AD_FLAGS_GENERAL_DISCOVERABLE          0x02
#define BT_AD_FLAGS_BR_EDR_NOT_SUPPORTED          0x04
#define BT_AD_FLAGS_LE_GENERAL_ONLY               \
    (BT_AD_FLAGS_GENERAL_DISCOVERABLE | BT_AD_FLAGS_BR_EDR_NOT_SUPPORTED)

/* Bluetooth Assigned Numbers, Service Class UUIDs. */
#define BT_UUID16_BATTERY_SERVICE                 0x180f
#define BT_UUID16_HID_SERVICE                     0x1812
#define BT_UUID16_DEVICE_INFORMATION              0x180a

#endif
