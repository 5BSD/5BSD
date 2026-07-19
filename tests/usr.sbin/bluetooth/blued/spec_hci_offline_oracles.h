/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 LE feature/event-mask oracles.
 * No production Bluetooth header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_OFFLINE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_OFFLINE_ORACLES_H

/* Vol 6, Part B §4.6 feature positions. */
#define BT_OFF_FEAT_EXT_ADVERTISING       (1ULL << 12)
#define BT_OFF_FEAT_PERIODIC_ADVERTISING  (1ULL << 13)
#define BT_OFF_FEAT_CIS_CENTRAL           (1ULL << 28)
#define BT_OFF_FEAT_CIS_PERIPHERAL        (1ULL << 29)

/* Vol 4, Part E §7.8.39: bit position = LE subevent code - 1. */
#define BT_OFF_MASK_CONN_COMPLETE         (1ULL << 0)
#define BT_OFF_MASK_ADV_REPORT            (1ULL << 1)
#define BT_OFF_MASK_CONN_UPDATE           (1ULL << 2)
#define BT_OFF_MASK_LTK_REQUEST           (1ULL << 4)
#define BT_OFF_MASK_EXT_ADV_REPORT        (1ULL << 12)
#define BT_OFF_MASK_PERIODIC_SYNC_EST     (1ULL << 13)
#define BT_OFF_MASK_PERIODIC_REPORT       (1ULL << 14)
#define BT_OFF_MASK_PERIODIC_SYNC_LOST    (1ULL << 15)
#define BT_OFF_MASK_ADV_SET_TERMINATED    (1ULL << 17)
#define BT_OFF_MASK_SCAN_REQUEST          (1ULL << 18)
#define BT_OFF_MASK_CIS_ESTABLISHED       (1ULL << 24)
#define BT_OFF_MASK_CIS_REQUEST           (1ULL << 25)

#endif
