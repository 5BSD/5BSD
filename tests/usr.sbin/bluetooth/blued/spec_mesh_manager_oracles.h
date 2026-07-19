/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Mesh Protocol 1.1 manager/configuration wire oracles.
 *
 * Sources: MshPRT 1.1 §§3.4.2.2.1, 3.6.5, 4.2-4.4 and Bluetooth
 * Assigned Numbers (Mesh message opcodes and SIG model identifiers).
 * No production mesh header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_MANAGER_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_MANAGER_ORACLES_H

#define BT_MMGR_OPCODE_HI(v)             (((v) >> 8) & 0xffu)
#define BT_MMGR_OPCODE_LO(v)             ((v) & 0xffu)

/* MshPRT §3.4.2.2.1 address ranges. */
#define BT_MMGR_UNASSIGNED               0x0000u
#define BT_MMGR_UNICAST_MIN              0x0001u
#define BT_MMGR_UNICAST_MAX              0x7fffu
#define BT_MMGR_VIRTUAL_PREFIX           0x8000u
#define BT_MMGR_VIRTUAL_MAX              0xbfffu
#define BT_MMGR_VIRTUAL_MASK             0xc000u
#define BT_MMGR_GROUP_MIN                0xc000u
#define BT_MMGR_ALL_NODES                0xffffu
#define BT_MMGR_KEY_INDEX_MAX            0x0fffu
#define BT_MMGR_KEY_INDEX_FIRST_RESERVED 0x1000u

/* MshPRT §§4.2-4.4 foundation message opcodes. */
#define BT_MMGR_OP_APPKEY_ADD            0x0000u
#define BT_MMGR_OP_APPKEY_UPDATE         0x0001u
#define BT_MMGR_OP_APPKEY_STATUS         0x8003u
#define BT_MMGR_OP_COMP_DATA_GET         0x8008u
#define BT_MMGR_OP_BEACON_GET            0x8009u
#define BT_MMGR_OP_BEACON_SET            0x800au
#define BT_MMGR_OP_BEACON_STATUS         0x800bu
#define BT_MMGR_OP_DEFAULT_TTL_GET       0x800cu
#define BT_MMGR_OP_DEFAULT_TTL_SET       0x800du
#define BT_MMGR_OP_DEFAULT_TTL_STATUS    0x800eu
#define BT_MMGR_OP_FRIEND_SET            0x8010u
#define BT_MMGR_OP_FRIEND_STATUS         0x8011u
#define BT_MMGR_OP_GATT_PROXY_SET        0x8013u
#define BT_MMGR_OP_GATT_PROXY_STATUS     0x8014u
#define BT_MMGR_OP_KR_PHASE_GET          0x8015u
#define BT_MMGR_OP_KR_PHASE_SET          0x8016u
#define BT_MMGR_OP_MODEL_PUB_GET         0x8018u
#define BT_MMGR_OP_MODEL_PUB_VA_SET      0x801au
#define BT_MMGR_OP_MODEL_SUB_DELETE      0x801cu
#define BT_MMGR_OP_MODEL_SUB_DELETE_ALL  0x801du
#define BT_MMGR_OP_MODEL_SUB_OVERWRITE   0x801eu
#define BT_MMGR_OP_MODEL_SUB_VA_ADD      0x8020u
#define BT_MMGR_OP_MODEL_SUB_VA_DELETE   0x8021u
#define BT_MMGR_OP_MODEL_SUB_VA_OVERWRITE 0x8022u
#define BT_MMGR_OP_NET_TRANSMIT_GET      0x8023u
#define BT_MMGR_OP_NET_TRANSMIT_SET      0x8024u
#define BT_MMGR_OP_RELAY_GET             0x8026u
#define BT_MMGR_OP_RELAY_SET             0x8027u
#define BT_MMGR_OP_SIG_MODEL_SUB_GET     0x8029u
#define BT_MMGR_OP_LPN_POLLTIMEOUT_GET   0x802du
#define BT_MMGR_OP_MODEL_APP_BIND        0x803du
#define BT_MMGR_OP_MODEL_APP_UNBIND      0x803fu
#define BT_MMGR_OP_NETKEY_ADD            0x8040u
#define BT_MMGR_OP_NETKEY_DELETE         0x8041u
#define BT_MMGR_OP_NETKEY_UPDATE         0x8045u
#define BT_MMGR_OP_NODE_IDENTITY_GET     0x8046u
#define BT_MMGR_OP_NODE_IDENTITY_SET     0x8047u
#define BT_MMGR_OP_NODE_RESET            0x8049u
#define BT_MMGR_OP_SIG_MODEL_APP_GET     0x804bu
#define BT_MMGR_OP_HB_PUB_STATUS         0x0006u

/* MshPRT status/state values and key/address field bounds. */
#define BT_MMGR_STATUS_SUCCESS           0x00u
#define BT_MMGR_STATUS_INVALID_NETKEY    0x04u
#define BT_MMGR_KR_PHASE_NORMAL          0x00u
#define BT_MMGR_KR_PHASE_1               0x01u
#define BT_MMGR_KR_PHASE_2               0x02u
#define BT_MMGR_KR_TRANSITION_2          0x02u
#define BT_MMGR_KR_TRANSITION_3          0x03u
#define BT_MMGR_IDENTITY_RUNNING         0x01u
#define BT_MMGR_TRANS_MIC32_SIZE         4u

/* MshPRT §5 provisioning algorithm bit. */
#define BT_MMGR_PROV_ALGO_P256_CMAC      0x0001u

/* Assigned Numbers: SIG model identifiers exercised by discovery. */
#define BT_MMGR_MODEL_GEN_ONOFF_SRV      0x1000u
#define BT_MMGR_MODEL_GEN_LEVEL_SRV      0x1002u
#define BT_MMGR_MODEL_GEN_DTT_SRV        0x1004u
#define BT_MMGR_MODEL_GEN_POWER_ONOFF_SRV 0x1006u
#define BT_MMGR_MODEL_GEN_POWER_ONOFF_SETUP_SRV 0x1007u
#define BT_MMGR_MODEL_GEN_POWER_LEVEL_SRV 0x1009u
#define BT_MMGR_MODEL_GEN_POWER_LEVEL_SETUP_SRV 0x100au
#define BT_MMGR_MODEL_GEN_BATTERY_SRV    0x100cu
#define BT_MMGR_MODEL_GEN_LOCATION_SRV   0x100eu
#define BT_MMGR_MODEL_GEN_LOCATION_SETUP_SRV 0x100fu
#define BT_MMGR_MODEL_SENSOR_SRV         0x1100u
#define BT_MMGR_MODEL_SENSOR_SETUP_SRV   0x1101u
#define BT_MMGR_MODEL_TIME_SRV           0x1200u
#define BT_MMGR_MODEL_TIME_SETUP_SRV     0x1201u
#define BT_MMGR_MODEL_SCENE_SRV          0x1203u
#define BT_MMGR_MODEL_SCENE_SETUP_SRV    0x1204u
#define BT_MMGR_MODEL_SCHEDULER_SRV      0x1206u
#define BT_MMGR_MODEL_SCHEDULER_SETUP_SRV 0x1207u
#define BT_MMGR_MODEL_LIGHT_LIGHTNESS_SRV 0x1300u
#define BT_MMGR_MODEL_LIGHT_LIGHTNESS_SETUP_SRV 0x1301u
#define BT_MMGR_MODEL_LIGHT_CTL_SRV      0x1303u
#define BT_MMGR_MODEL_LIGHT_CTL_SETUP_SRV 0x1304u
#define BT_MMGR_MODEL_LIGHT_CTL_TEMP_SRV 0x1306u
#define BT_MMGR_MODEL_LIGHT_HSL_SRV      0x1307u
#define BT_MMGR_MODEL_LIGHT_HSL_SETUP_SRV 0x1308u
#define BT_MMGR_MODEL_LIGHT_HSL_HUE_SRV  0x130au
#define BT_MMGR_MODEL_LIGHT_HSL_SAT_SRV  0x130bu
#define BT_MMGR_MODEL_LIGHT_XYL_SRV      0x130cu
#define BT_MMGR_MODEL_LIGHT_XYL_SETUP_SRV 0x130du
#define BT_MMGR_MODEL_LIGHT_LC_SRV       0x130fu
#define BT_MMGR_MODEL_LIGHT_LC_SETUP_SRV 0x1310u

#endif
