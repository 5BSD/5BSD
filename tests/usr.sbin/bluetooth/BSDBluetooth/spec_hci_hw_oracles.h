/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 hardware-integration oracles.
 * No production Bluetooth header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_HW_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_HW_ORACLES_H

/* Core Vol 6 Part B §4.6, LE FeatureSet bit positions. */
#define BT_HW_FEAT_ENCRYPTION             (UINT64_C(1) << 0)
#define BT_HW_FEAT_CONN_PARAM_REQ         (UINT64_C(1) << 1)
#define BT_HW_FEAT_DATA_LENGTH_EXT        (UINT64_C(1) << 5)
#define BT_HW_FEAT_LL_PRIVACY             (UINT64_C(1) << 6)
#define BT_HW_FEAT_2M_PHY                 (UINT64_C(1) << 8)
#define BT_HW_FEAT_EXT_ADVERTISING        (UINT64_C(1) << 12)
#define BT_HW_FEAT_PERIODIC_ADVERTISING   (UINT64_C(1) << 13)

/* Core Vol 4 Part E command fields. */
#define BT_HW_PUBLIC_ADDR_TYPE            0x00u
#define BT_HW_ADV_HANDLE_MIN              0x00u
#define BT_HW_LEGACY_CONN_SCAN_PROPS      0x0013u
#define BT_HW_ADV_INTERVAL_SAMPLE         0x00a0u
#define BT_HW_PERIODIC_INTERVAL_MIN       0x0006u
#define BT_HW_PERIODIC_INTERVAL_SAMPLE    0x0010u
#define BT_HW_RPA_TIMEOUT_DEFAULT         0x0384u
#define BT_HW_DATA_OCTETS_MAX             0x00fbu
#define BT_HW_DATA_TIME_MAX               0x0848u
#define BT_HW_ALL_PHYS_HAVE_PREFERENCE    0x00u
#define BT_HW_PHY_1M_BIT                  0x01u
#define BT_HW_PHY_2M_BIT                  0x02u
#define BT_HW_PRIVACY_MODE_NETWORK        0x00u
#define BT_HW_PRIVACY_MODE_DEVICE         0x01u
#define BT_HW_LEGACY_ADV_DATA_MAX         31

/* Core Vol 3 Part C §11.1.3 and CSS Part A §§1.3, 1.8-1.9. */
#define BT_HW_AD_TYPE_FLAGS               0x01u
#define BT_HW_AD_TYPE_NAME_SHORT          0x08u
#define BT_HW_AD_TYPE_NAME_COMPLETE       0x09u
#define BT_HW_AD_FLAGS_GENERAL_NO_BREDR   0x06u
#define BT_HW_GAP_SERVICE_UUID            0x1800u

#endif
