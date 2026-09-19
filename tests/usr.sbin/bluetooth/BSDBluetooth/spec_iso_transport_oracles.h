/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 ISO HCI transport oracles.
 *
 * This file deliberately includes no production Bluetooth header.  Values
 * are transcribed from Vol 4, Part E, with feature-bit assignments from
 * Vol 6, Part B.  Tests must compare production output with these values,
 * not with constants used by the implementation.
 */
#ifndef TESTS_BLUETOOTH_SPEC_ISO_TRANSPORT_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_ISO_TRANSPORT_ORACLES_H

/* Vol 4, Part E §§7.8.2 and 7.8.96-.116: OGF 0x08 with each OCF. */
#define BT_ISO_OP_READ_BUFFER_SIZE_V2       0x2060
#define BT_ISO_OP_READ_TX_SYNC             0x2061
#define BT_ISO_OP_SET_CIG_PARAMS           0x2062
#define BT_ISO_OP_SET_CIG_PARAMS_TEST      0x2063
#define BT_ISO_OP_CREATE_CIS               0x2064
#define BT_ISO_OP_REMOVE_CIG               0x2065
#define BT_ISO_OP_ACCEPT_CIS               0x2066
#define BT_ISO_OP_REJECT_CIS               0x2067
#define BT_ISO_OP_CREATE_BIG               0x2068
#define BT_ISO_OP_CREATE_BIG_TEST          0x2069
#define BT_ISO_OP_TERMINATE_BIG            0x206a
#define BT_ISO_OP_BIG_CREATE_SYNC          0x206b
#define BT_ISO_OP_BIG_TERMINATE_SYNC       0x206c
#define BT_ISO_OP_REQUEST_PEER_SCA         0x206d
#define BT_ISO_OP_SETUP_DATA_PATH          0x206e
#define BT_ISO_OP_REMOVE_DATA_PATH         0x206f
#define BT_ISO_OP_READ_LINK_QUALITY        0x2075

/* Vol 4, Part E §§5.4.4 and 7.7.14-.15, 7.7.65. */
#define BT_ISO_H4_EVENT_PACKET             0x04
#define BT_ISO_EVENT_COMMAND_COMPLETE      0x0e
#define BT_ISO_EVENT_COMMAND_STATUS        0x0f
#define BT_ISO_EVENT_LE_META               0x3e

/* Vol 4, Part E §§7.7.65.25-.30 and .34. */
#define BT_ISO_SUBEVENT_CIS_ESTABLISHED    0x19
#define BT_ISO_SUBEVENT_CIS_REQUEST        0x1a
#define BT_ISO_SUBEVENT_CREATE_BIG         0x1b
#define BT_ISO_SUBEVENT_TERMINATE_BIG      0x1c
#define BT_ISO_SUBEVENT_BIG_SYNC_EST       0x1d
#define BT_ISO_SUBEVENT_BIG_SYNC_LOST      0x1e
#define BT_ISO_SUBEVENT_BIGINFO_REPORT     0x22

/* Vol 4, Part E §7.8 command parameter table bounds and enumerations. */
#define BT_ISO_STATUS_SUCCESS              0x00
#define BT_ISO_ERROR_COMMAND_DISALLOWED    0x0c
#define BT_ISO_ERROR_LIMITED_RESOURCES     0x0d
#define BT_ISO_ERROR_LOCAL_HOST            0x16
#define BT_ISO_ERROR_FAILED_ESTABLISH      0x3d
#define BT_ISO_HANDLE_MAX                  0x0eff
#define BT_ISO_GROUP_HANDLE_MAX            0xef
#define BT_ISO_STREAM_COUNT_MAX            0x1f
#define BT_ISO_BIG_SYNC_TIMEOUT_MIN        0x000a
#define BT_ISO_MSE_MAX                     0x1f
#define BT_ISO_PHY_1M                      0x01
#define BT_ISO_PHY_2M                      0x02
#define BT_ISO_PACKING_INTERLEAVED         0x01
#define BT_ISO_FRAMING_FRAMED              0x01
#define BT_ISO_ENCRYPTION_ENABLED          0x01
#define BT_ISO_DATA_PATH_HCI               0x00
#define BT_ISO_SETUP_PATH_INPUT            0x00
#define BT_ISO_SETUP_PATH_OUTPUT           0x01
#define BT_ISO_PATH_INPUT                  0x01
#define BT_ISO_PATH_OUTPUT                 0x02
#define BT_ISO_PATH_BOTH                   0x03

/* Exact fixed wire sizes derived from the cited command/event tables. */
#define BT_ISO_CIS_PARAM_LEN               9
#define BT_ISO_SET_CIG_HEADER_LEN          15
#define BT_ISO_CREATE_CIS_PAIR_LEN         4
#define BT_ISO_CREATE_BIG_LEN              31
#define BT_ISO_BIG_SYNC_HEADER_LEN         24
#define BT_ISO_SETUP_PATH_HEADER_LEN       13
#define BT_ISO_CODEC_ID_LEN                5
#define BT_ISO_BROADCAST_CODE_LEN          16
#define BT_ISO_READ_TX_SYNC_RP_LEN         12
#define BT_ISO_READ_LINK_QUALITY_RP_LEN    31
#define BT_ISO_CIS_ESTABLISHED_LEN         28
#define BT_ISO_CIS_REQUEST_LEN             6
#define BT_ISO_CREATE_BIG_FIXED_LEN        18
#define BT_ISO_TERMINATE_BIG_LEN           2
#define BT_ISO_BIG_SYNC_FIXED_LEN          14
#define BT_ISO_BIG_SYNC_LOST_LEN           2
#define BT_ISO_PARAM_LEN_CIS_ESTABLISHED   29
#define BT_ISO_PARAM_LEN_CIS_REQUEST       7
#define BT_ISO_PARAM_LEN_CREATE_BIG_2_BIS  23
#define BT_ISO_PARAM_LEN_TERMINATE_BIG     3
#define BT_ISO_PARAM_LEN_BIG_SYNC_1_BIS    17
#define BT_ISO_PARAM_LEN_BIG_SYNC_LOST     3

/* Vol 6, Part B §4.6, Table 4.3 feature bits 12-13 and 28-31. */
#define BT_ISO_FEAT_EXT_ADVERTISING        (1ULL << 12)
#define BT_ISO_FEAT_PERIODIC_ADV           (1ULL << 13)
#define BT_ISO_FEAT_CIS_CENTRAL            (1ULL << 28)
#define BT_ISO_FEAT_CIS_PERIPHERAL         (1ULL << 29)
#define BT_ISO_FEAT_BROADCASTER            (1ULL << 30)
#define BT_ISO_FEAT_SYNC_RECEIVER          (1ULL << 31)

/* Vol 4, Part E §7.8.39: LE event-mask bit = subevent code - 1. */
#define BT_ISO_MASK_EXT_ADV_REPORT         (1ULL << 12)
#define BT_ISO_MASK_PER_ADV_SYNC_EST       (1ULL << 13)
#define BT_ISO_MASK_PER_ADV_REPORT         (1ULL << 14)
#define BT_ISO_MASK_PER_ADV_SYNC_LOST      (1ULL << 15)
#define BT_ISO_MASK_ADV_SET_TERM           (1ULL << 17)
#define BT_ISO_MASK_SCAN_REQ_RCVD          (1ULL << 18)
#define BT_ISO_MASK_CIS_ESTABLISHED        (1ULL << 24)
#define BT_ISO_MASK_CIS_REQUEST            (1ULL << 25)
#define BT_ISO_MASK_CREATE_BIG             (1ULL << 26)
#define BT_ISO_MASK_TERMINATE_BIG          (1ULL << 27)
#define BT_ISO_MASK_BIG_SYNC_EST           (1ULL << 28)
#define BT_ISO_MASK_BIG_SYNC_LOST          (1ULL << 29)
#define BT_ISO_MASK_BIGINFO_REPORT         (1ULL << 33)

#endif
