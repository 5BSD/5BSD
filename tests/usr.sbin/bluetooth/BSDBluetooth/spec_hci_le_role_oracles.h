/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 HCI event oracles.
 * Deliberately includes no production Bluetooth header.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_LE_ROLE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_LE_ROLE_ORACLES_H

/* Vol 4 Part E §7.7.65 and §7.7.65.1/.2/.10. */
#define BT_HR_SPEC_EVENT_LE_META                 0x3e
#define BT_HR_SPEC_EVENT_VENDOR                  0xff
#define BT_HR_SPEC_SUBEVENT_CONN_COMPLETE        0x01
#define BT_HR_SPEC_SUBEVENT_ADV_REPORT           0x02
#define BT_HR_SPEC_SUBEVENT_ENH_CONN_COMPLETE    0x0a
#define BT_HR_SPEC_CONN_COMPLETE_PARAM_LEN       18
#define BT_HR_SPEC_ENH_CONN_COMPLETE_PARAM_LEN   30
#define BT_HR_SPEC_ROLE_CENTRAL                  0x00
#define BT_HR_SPEC_ROLE_PERIPHERAL               0x01
#define BT_HR_SPEC_ADDR_PUBLIC                   0x00
#define BT_HR_SPEC_ADDR_RANDOM                   0x01
#define BT_HR_SPEC_ADDR_PUBLIC_IDENTITY          0x02
#define BT_HR_SPEC_LEGACY_ADV_DATA_MAX           31

/* Vol 4 Part E §7.7.65.25-.30. */
#define BT_HR_SPEC_SUBEVENT_CIS_ESTABLISHED      0x19
#define BT_HR_SPEC_SUBEVENT_CIS_REQUEST          0x1a
#define BT_HR_SPEC_SUBEVENT_CREATE_BIG_COMPLETE  0x1b
#define BT_HR_SPEC_SUBEVENT_TERMINATE_BIG_COMPLETE 0x1c
#define BT_HR_SPEC_SUBEVENT_BIG_SYNC_ESTABLISHED 0x1d
#define BT_HR_SPEC_SUBEVENT_BIG_SYNC_LOST        0x1e

/* Vol 1 Part F §1.3 status/reason assignments. */
#define BT_HR_SPEC_STATUS_SUCCESS                0x00
#define BT_HR_SPEC_ERR_PAGE_TIMEOUT              0x04
#define BT_HR_SPEC_REASON_CONN_TIMEOUT           0x08
#define BT_HR_SPEC_REASON_REMOTE_USER_TERM       0x13
#define BT_HR_SPEC_REASON_LOCAL_HOST_TERM        0x16
#define BT_HR_SPEC_ERR_CONN_FAILED_ESTABLISH     0x3e

/* Vol 4 Part E §7.7.19 and §7.7.38. */
#define BT_HR_SPEC_COMPLETED_RECORD_LEN          4
#define BT_HR_SPEC_COMPLETED_COUNT_LEN           1
#define BT_HR_SPEC_EXT_INQUIRY_DATA_LEN          240

#endif
