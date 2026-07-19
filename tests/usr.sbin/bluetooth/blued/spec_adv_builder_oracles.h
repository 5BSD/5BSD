/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Core 6.3 / CSS advertising-data assignments.
 * No production advertising header is included.
 */

#ifndef TESTS_BLUETOOTH_SPEC_ADV_BUILDER_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_ADV_BUILDER_ORACLES_H

/* Core 6.3 Vol 3 Part C §11 and CSS v12 Part A §1 data types. */
#define BT_ADV_SPEC_TYPE_FLAGS			0x01
#define BT_ADV_SPEC_TYPE_UUID16_INCOMPLETE	0x02
#define BT_ADV_SPEC_TYPE_UUID16_COMPLETE	0x03
#define BT_ADV_SPEC_TYPE_UUID128_COMPLETE	0x07
#define BT_ADV_SPEC_TYPE_NAME_SHORT		0x08
#define BT_ADV_SPEC_TYPE_NAME_COMPLETE		0x09
#define BT_ADV_SPEC_TYPE_TX_POWER		0x0a
#define BT_ADV_SPEC_TYPE_SERVICE_DATA16		0x16
#define BT_ADV_SPEC_TYPE_APPEARANCE		0x19
#define BT_ADV_SPEC_TYPE_MANUFACTURER		0xff

/* Core 6.3 Vol 3 Part C §11.1.3 Flags AD Type bits. */
#define BT_ADV_SPEC_FLAG_GENERAL_DISCOVERABLE	0x02
#define BT_ADV_SPEC_FLAG_BREDR_NOT_SUPPORTED	0x04

/* Core 6.3 Vol 4 Part E §7.8.7 legacy Advertising_Data_Length maximum. */
#define BT_ADV_SPEC_LEGACY_DATA_MAX		31

/* Core 6.3 Vol 4 Part E §7.8.54 HCI command fragment data maximum. */
#define BT_ADV_SPEC_EXT_COMMAND_DATA_MAX	251

/* CSS v12 Part A §1.1: one-octet Length includes Type plus Data. */
#define BT_ADV_SPEC_AD_DATA_MAX			254

#endif /* TESTS_BLUETOOTH_SPEC_ADV_BUILDER_ORACLES_H */
