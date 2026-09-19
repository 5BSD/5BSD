/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 LE Power Control HCI oracles.
 *
 * No production Bluetooth header is included here.  Values are transcribed
 * from Vol 4, Part E §§7.7.65.32-.33 and 7.8.117-.121, with HCI error values
 * from Vol 1, Part F §1.3.
 */
#ifndef TESTS_BLUETOOTH_SPEC_POWER_CONTROL_CORE63_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_POWER_CONTROL_CORE63_ORACLES_H

/* OGF 0x08 composed with the OCF in each cited command table. */
#define BT_POWER_OP_ENH_READ_TX_POWER_LEVEL       0x2076
#define BT_POWER_OP_READ_REMOTE_TX_POWER_LEVEL    0x2077
#define BT_POWER_OP_SET_PATH_LOSS_PARAMS          0x2078
#define BT_POWER_OP_SET_PATH_LOSS_ENABLE          0x2079
#define BT_POWER_OP_SET_TX_POWER_ENABLE           0x207a

/* Vol 4, Part E §§7.7.65.32-.33. */
#define BT_POWER_SUBEVENT_PATH_LOSS_THRESHOLD     0x20
#define BT_POWER_SUBEVENT_TX_POWER_REPORTING      0x21

/* Vol 1, Part F §1.3 and Vol 4, Part E command parameter tables. */
#define BT_POWER_STATUS_SUCCESS                   0x00
#define BT_POWER_ERROR_COMMAND_DISALLOWED         0x0c
#define BT_POWER_HANDLE_MAX                       0x0eff
#define BT_POWER_PHY_1M                           0x01
#define BT_POWER_PHY_2M                           0x02
#define BT_POWER_PHY_CODED_S8                     0x03
#define BT_POWER_PHY_CODED_S2                     0x04
#define BT_POWER_ENABLE_OFF                       0x00
#define BT_POWER_ENABLE_ON                        0x01
#define BT_POWER_TX_DBM_MIN                       (-127)
#define BT_POWER_TX_DBM_MAX                       20
#define BT_POWER_TX_NOT_MANAGING                  0x7e
#define BT_POWER_TX_UNAVAILABLE                   0x7f

#endif
