/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Mesh Model 1.1.1 Generic-model oracles.
 *
 * No production header is included.  Message layouts and states are from
 * Mesh Model 1.1.1 Chapter 3 and Tables 3.1-3.15/3.36 onward; opcodes and
 * SIG model identifiers are from Bluetooth Assigned Numbers.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_GENERIC_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_GENERIC_ORACLES_H

/* Mesh Model 1.1.1 Tables 3.1-3.2. */
#define BTMG_OFF                           0x00
#define BTMG_ON                            0x01
#define BTMG_ONOFF_FIRST_PROHIBITED        0x02
#define BTMG_LEVEL_MIN                     (-32768)
#define BTMG_LEVEL_MAX                     32767

/* Mesh Model 1.1.1 §3.1.3 and Table 3.3. */
#define BTMG_ONPOWERUP_OFF                 0x00
#define BTMG_ONPOWERUP_DEFAULT             0x01
#define BTMG_ONPOWERUP_RESTORE             0x02
#define BTMG_ONPOWERUP_FIRST_PROHIBITED    0x03

/* Mesh Model 1.1.1 §1.3.2.2: Generic Transition Time. */
#define BTMG_TRANSITION_ONE_SECOND         0x0a
#define BTMG_TRANSITION_HALF_SECOND        0x05
#define BTMG_TRANSITION_RESERVED_STEPS     0x3f
#define BTMG_TRANSITION_ONE_STEP_1S        0x41
#define BTMG_DELAY_UNIT_MS                 5
#define BTMG_TID_WINDOW_MS                 6000

/* Mesh Model 1.1.1 §§3.2.1-3.2.2 message parameter lengths. */
#define BTMG_ONOFF_SET_MIN_LEN             2
#define BTMG_ONOFF_SET_TRANSITION_LEN      4
#define BTMG_ONOFF_STATUS_MIN_LEN          1
#define BTMG_ONOFF_STATUS_TARGET_LEN       3
#define BTMG_LEVEL_SET_MIN_LEN             3
#define BTMG_LEVEL_SET_TRANSITION_LEN      5
#define BTMG_DELTA_SET_MIN_LEN             5
#define BTMG_DELTA_SET_TRANSITION_LEN      7
#define BTMG_MOVE_SET_MIN_LEN              3
#define BTMG_MOVE_SET_TRANSITION_LEN       5
#define BTMG_LEVEL_STATUS_MIN_LEN          2
#define BTMG_LEVEL_STATUS_TARGET_LEN       5

/* Mesh Model 1.1.1 §3.2.5.14, Table 3.69, and Table 7.1. */
#define BTMG_POWER_RANGE_STATUS_SUCCESS    0x00
#define BTMG_POWER_RANGE_STATUS_MIN        0x01
#define BTMG_POWER_RANGE_STATUS_MAX        0x02

/* Mesh Model 1.1.1 §§3.1.6, 3.2.6, Tables 3.8-3.15/3.57. */
#define BTMG_BATTERY_LEVEL_MAX             100
#define BTMG_BATTERY_LEVEL_UNKNOWN         0xff
#define BTMG_BATTERY_TIME_UNKNOWN          0xffffff
#define BTMG_BATTERY_STATUS_LEN            8
#define BTMG_BATTERY_FLAGS_ALL_UNKNOWN     0xff
#define BTMG_BATTERY_FLAGS_VALID_SAMPLE    0x6a
#define BTMG_BATTERY_FLAGS_RESERVED_SAMPLE 0x2a

/* Mesh Model 1.1.1 §§3.1.7, 3.2.7 message sizes. */
#define BTMG_LOCATION_GLOBAL_LEN           10
#define BTMG_LOCATION_LOCAL_LEN            9

/* Bluetooth Assigned Numbers, Mesh Model identifiers. */
#define BTMG_MODEL_ONOFF_SRV               0x1000
#define BTMG_MODEL_ONOFF_CLI               0x1001
#define BTMG_MODEL_LEVEL_SRV               0x1002
#define BTMG_MODEL_LEVEL_CLI               0x1003
#define BTMG_MODEL_DTT_SRV                 0x1004
#define BTMG_MODEL_DTT_CLI                 0x1005
#define BTMG_MODEL_POWER_ONOFF_SRV         0x1006
#define BTMG_MODEL_POWER_ONOFF_SETUP_SRV   0x1007
#define BTMG_MODEL_POWER_ONOFF_CLI         0x1008
#define BTMG_MODEL_POWER_LEVEL_SRV         0x1009
#define BTMG_MODEL_POWER_LEVEL_SETUP_SRV   0x100a
#define BTMG_MODEL_POWER_LEVEL_CLI         0x100b
#define BTMG_MODEL_BATTERY_SRV             0x100c
#define BTMG_MODEL_BATTERY_CLI             0x100d
#define BTMG_MODEL_LOCATION_SRV            0x100e
#define BTMG_MODEL_LOCATION_SETUP_SRV      0x100f
#define BTMG_MODEL_LOCATION_CLI            0x1010

/* Bluetooth Assigned Numbers, Mesh Message opcodes. */
#define BTMG_OP_ONOFF_GET                  0x8201
#define BTMG_OP_ONOFF_SET                  0x8202
#define BTMG_OP_ONOFF_SET_UNACK            0x8203
#define BTMG_OP_ONOFF_STATUS               0x8204
#define BTMG_OP_LEVEL_GET                  0x8205
#define BTMG_OP_LEVEL_SET                  0x8206
#define BTMG_OP_LEVEL_SET_UNACK            0x8207
#define BTMG_OP_LEVEL_STATUS               0x8208
#define BTMG_OP_DELTA_SET                  0x8209
#define BTMG_OP_DELTA_SET_UNACK            0x820a
#define BTMG_OP_MOVE_SET                   0x820b
#define BTMG_OP_MOVE_SET_UNACK             0x820c
#define BTMG_OP_DTT_GET                    0x820d
#define BTMG_OP_DTT_SET                    0x820e
#define BTMG_OP_DTT_SET_UNACK              0x820f
#define BTMG_OP_DTT_STATUS                 0x8210
#define BTMG_OP_ONPOWERUP_GET              0x8211
#define BTMG_OP_ONPOWERUP_STATUS           0x8212
#define BTMG_OP_ONPOWERUP_SET              0x8213
#define BTMG_OP_ONPOWERUP_SET_UNACK        0x8214
#define BTMG_OP_POWER_LEVEL_GET            0x8215
#define BTMG_OP_POWER_LEVEL_SET            0x8216
#define BTMG_OP_POWER_LEVEL_SET_UNACK      0x8217
#define BTMG_OP_POWER_LEVEL_STATUS         0x8218
#define BTMG_OP_POWER_LAST_GET             0x8219
#define BTMG_OP_POWER_LAST_STATUS          0x821a
#define BTMG_OP_POWER_DEFAULT_GET          0x821b
#define BTMG_OP_POWER_DEFAULT_STATUS       0x821c
#define BTMG_OP_POWER_RANGE_GET            0x821d
#define BTMG_OP_POWER_RANGE_STATUS         0x821e
#define BTMG_OP_POWER_DEFAULT_SET          0x821f
#define BTMG_OP_POWER_DEFAULT_SET_UNACK    0x8220
#define BTMG_OP_POWER_RANGE_SET            0x8221
#define BTMG_OP_POWER_RANGE_SET_UNACK      0x8222
#define BTMG_OP_BATTERY_GET                0x8223
#define BTMG_OP_BATTERY_STATUS             0x8224
#define BTMG_OP_LOCATION_GLOBAL_GET        0x8225
#define BTMG_OP_LOCATION_LOCAL_GET         0x8226
#define BTMG_OP_LOCATION_LOCAL_STATUS      0x8227
#define BTMG_OP_LOCATION_LOCAL_SET         0x8228
#define BTMG_OP_LOCATION_LOCAL_SET_UNACK   0x8229
#define BTMG_OP_LOCATION_GLOBAL_STATUS     0x40
#define BTMG_OP_LOCATION_GLOBAL_SET        0x41
#define BTMG_OP_LOCATION_GLOBAL_SET_UNACK  0x42

#endif
