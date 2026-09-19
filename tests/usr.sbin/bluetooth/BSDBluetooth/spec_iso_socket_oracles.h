/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 Vol 4 Part E §5.4.5 ISO data oracles.
 * No production HCI or socket header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_ISO_SOCKET_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_ISO_SOCKET_ORACLES_H

#define BT_ISOS_H4_ISO_DATA             0x05
#define BT_ISOS_HCI_HEADER_LEN          5
#define BT_ISOS_DATA_LOAD_HEADER_LEN    4
#define BT_ISOS_TIMESTAMP_LEN           4
#define BT_ISOS_HANDLE_MASK             0x0fff
#define BT_ISOS_PB_SHIFT                12
#define BT_ISOS_PB_MASK                 0x03
#define BT_ISOS_TS_SHIFT                14
#define BT_ISOS_DATA_TOTAL_LEN_MASK     0x3fff
#define BT_ISOS_SDU_LEN_MASK            0x0fff
#define BT_ISOS_STATUS_SHIFT            13
#define BT_ISOS_STATUS_MASK             0x03

#define BT_ISOS_PB_FIRST                0x00
#define BT_ISOS_PB_CONTINUATION         0x01
#define BT_ISOS_PB_COMPLETE             0x02
#define BT_ISOS_PB_LAST                 0x03

#define BT_ISOS_STATUS_VALID            0x00
#define BT_ISOS_STATUS_POSSIBLY_INVALID 0x01
#define BT_ISOS_STATUS_LOST             0x02

#endif
