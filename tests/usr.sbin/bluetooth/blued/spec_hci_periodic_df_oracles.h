/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Core 6.3 Vol 4 Part E periodic advertising/PAST/DF oracles.
 * No production HCI header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_PERIODIC_DF_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_PERIODIC_DF_ORACLES_H

/* §§7.8.61-.92 command opcodes (OGF 0x08 already composed). */
#define BT_PDF_OP_SET_PERIODIC_ADV_PARAMS       0x203e
#define BT_PDF_OP_SET_PERIODIC_ADV_DATA         0x203f
#define BT_PDF_OP_SET_PERIODIC_ADV_ENABLE       0x2040
#define BT_PDF_OP_PERIODIC_CREATE_SYNC          0x2044
#define BT_PDF_OP_PERIODIC_CREATE_SYNC_CANCEL   0x2045
#define BT_PDF_OP_PERIODIC_TERMINATE_SYNC       0x2046
#define BT_PDF_OP_SET_CONNLESS_CTE_TX_PARAMS    0x2051
#define BT_PDF_OP_SET_CONN_CTE_TX_PARAMS        0x2055
#define BT_PDF_OP_CONN_CTE_REQ_ENABLE           0x2056
#define BT_PDF_OP_READ_ANTENNA_INFO             0x2058
#define BT_PDF_OP_PERIODIC_SYNC_TRANSFER        0x205a
#define BT_PDF_OP_PERIODIC_SET_INFO_TRANSFER    0x205b
#define BT_PDF_OP_SET_PAST_PARAMS               0x205c
#define BT_PDF_OP_SET_DEFAULT_PAST_PARAMS       0x205d

/* §§7.7.65.1 and .14-.33 subevent assignments. */
#define BT_PDF_H4_EVENT_PACKET                  0x04
#define BT_PDF_EVENT_LE_META                    0x3e
#define BT_PDF_SUBEVENT_CONN_COMPLETE           0x01
#define BT_PDF_SUBEVENT_SYNC_ESTABLISHED        0x0e
#define BT_PDF_SUBEVENT_PERIODIC_REPORT         0x0f
#define BT_PDF_SUBEVENT_SYNC_LOST               0x10
#define BT_PDF_SUBEVENT_CONNLESS_IQ             0x15
#define BT_PDF_SUBEVENT_CONN_IQ                 0x16
#define BT_PDF_SUBEVENT_CTE_FAILED              0x17
#define BT_PDF_SUBEVENT_PAST_RECEIVED           0x18
#define BT_PDF_SUBEVENT_CIS_ESTABLISHED         0x19
#define BT_PDF_SUBEVENT_CIS_REQUEST             0x1a
#define BT_PDF_SUBEVENT_CREATE_BIG_COMPLETE     0x1b
#define BT_PDF_SUBEVENT_TERMINATE_BIG_COMPLETE  0x1c
#define BT_PDF_SUBEVENT_BIG_SYNC_ESTABLISHED    0x1d
#define BT_PDF_SUBEVENT_BIG_SYNC_LOST           0x1e
#define BT_PDF_SUBEVENT_PATH_LOSS               0x20
#define BT_PDF_SUBEVENT_TX_POWER_REPORTING      0x21

/* Exact parameter sizes from the cited event tables, excluding subevent. */
#define BT_PDF_LEN_SYNC_ESTABLISHED             15
#define BT_PDF_LEN_PERIODIC_REPORT_FIXED        7
#define BT_PDF_LEN_SYNC_LOST                    2
#define BT_PDF_LEN_CONNLESS_IQ_FIXED            12
#define BT_PDF_LEN_CONN_IQ_FIXED                13
#define BT_PDF_LEN_CTE_FAILED                   3
#define BT_PDF_LEN_PAST_RECEIVED                19
#define BT_PDF_LEN_PATH_LOSS                    4
#define BT_PDF_LEN_TX_POWER_REPORTING           8
#define BT_PDF_LEN_CIS_ESTABLISHED              28
#define BT_PDF_LEN_CIS_REQUEST                  6
#define BT_PDF_LEN_CREATE_BIG_FIXED             18
#define BT_PDF_LEN_TERMINATE_BIG                2
#define BT_PDF_LEN_BIG_SYNC_FIXED               14
#define BT_PDF_LEN_BIG_SYNC_LOST                2

/* Command field bounds/values. */
#define BT_PDF_STATUS_SUCCESS                   0x00
#define BT_PDF_PERIODIC_INTERVAL_MIN            0x0006
#define BT_PDF_PERIODIC_INTERVAL_MAX            0xffff
#define BT_PDF_PERIODIC_PROP_INCLUDE_TX_POWER   0x0040
#define BT_PDF_PERIODIC_PROP_FIRST_RESERVED     0x0001
#define BT_PDF_DATA_OPERATION_COMPLETE          0x03
#define BT_PDF_ADDR_RANDOM                      0x01
#define BT_PDF_PHY_1M                           0x01
#define BT_PDF_CTE_PATTERN_MAX                  75
#define BT_PDF_DATA_STATUS_MORE                 0x01
#define BT_PDF_DATA_STATUS_RESERVED             0x03

#endif
