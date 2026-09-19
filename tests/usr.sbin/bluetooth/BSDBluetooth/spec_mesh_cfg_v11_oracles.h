/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Mesh Protocol 1.1 Configuration-model wire oracles.
 * Sources: MshPRT 1.1 §§4.2.29-.30, 4.2.44-.47, 4.3.5-.12;
 * Bluetooth SIG Assigned Numbers message opcodes.  No production header.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_CFG_V11_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_CFG_V11_ORACLES_H

#define BT_MCFG11_OP_PRIV_BEACON_GET             0x8060u
#define BT_MCFG11_OP_PRIV_BEACON_SET             0x8061u
#define BT_MCFG11_OP_PRIV_BEACON_STATUS          0x8062u
#define BT_MCFG11_OP_PRIV_GATT_PROXY_GET         0x8063u
#define BT_MCFG11_OP_PRIV_GATT_PROXY_SET         0x8064u
#define BT_MCFG11_OP_PRIV_GATT_PROXY_STATUS      0x8065u
#define BT_MCFG11_OP_PRIV_NODE_IDENTITY_GET      0x8066u
#define BT_MCFG11_OP_PRIV_NODE_IDENTITY_SET      0x8067u
#define BT_MCFG11_OP_PRIV_NODE_IDENTITY_STATUS   0x8068u
#define BT_MCFG11_OP_OD_PRIV_PROXY_GET           0x8069u
#define BT_MCFG11_OP_OD_PRIV_PROXY_SET           0x806au
#define BT_MCFG11_OP_OD_PRIV_PROXY_STATUS        0x806bu
#define BT_MCFG11_OP_SAR_TRANSMITTER_GET         0x806cu
#define BT_MCFG11_OP_SAR_TRANSMITTER_SET         0x806du
#define BT_MCFG11_OP_SAR_TRANSMITTER_STATUS      0x806eu
#define BT_MCFG11_OP_SAR_RECEIVER_GET            0x806fu
#define BT_MCFG11_OP_SAR_RECEIVER_SET            0x8070u
#define BT_MCFG11_OP_SAR_RECEIVER_STATUS         0x8071u
#define BT_MCFG11_OP_AGGREGATOR_SEQUENCE         0x8072u
#define BT_MCFG11_OP_AGGREGATOR_STATUS           0x8073u
#define BT_MCFG11_OP_LARGE_COMP_DATA_GET         0x8074u
#define BT_MCFG11_OP_LARGE_COMP_DATA_STATUS      0x8075u
#define BT_MCFG11_OP_MODELS_METADATA_GET         0x8076u
#define BT_MCFG11_OP_MODELS_METADATA_STATUS      0x8077u
#define BT_MCFG11_OP_SOL_RPL_CLEAR                0x8078u
#define BT_MCFG11_OP_SOL_RPL_CLEAR_UNACK          0x8079u
#define BT_MCFG11_OP_SOL_RPL_STATUS               0x807au

/* MshPRT 1.1 §§4.2.29-.30, Tables 4.20-4.21. */
#define BT_MCFG11_SAR_TX_PARAM_LEN                4u
#define BT_MCFG11_SAR_RX_PARAM_LEN                3u
#define BT_MCFG11_SAR_TX_SAMPLE_0                 0x53u
#define BT_MCFG11_SAR_TX_SAMPLE_1                 0x72u
#define BT_MCFG11_SAR_TX_SAMPLE_2                 0x41u
#define BT_MCFG11_SAR_TX_SAMPLE_3                 0x06u
#define BT_MCFG11_SAR_RX_SAMPLE_0                 0xb2u
#define BT_MCFG11_SAR_RX_SAMPLE_1                 0x49u
#define BT_MCFG11_SAR_RX_SAMPLE_2                 0x02u

/* MshPRT 1.1 §§4.2.44-.47 and 4.3.5-.7/.12-.14. */
#define BT_MCFG11_DISABLED                        0x00u
#define BT_MCFG11_ENABLED                         0x01u
#define BT_MCFG11_PRIV_ID_STOPPED                 0x00u
#define BT_MCFG11_PRIV_ID_RUNNING                 0x01u
#define BT_MCFG11_PRIV_ID_NOT_SUPPORTED           0x02u
#define BT_MCFG11_STATUS_SUCCESS                  0x00u
#define BT_MCFG11_STATUS_INVALID_NETKEY_INDEX     0x04u
#define BT_MCFG11_KEY_INDEX_MAX                   0x0fffu

/* MshPRT 1.1 §§3.4.2.2.1, 4.3.9, and 4.3.10. */
#define BT_MCFG11_UNICAST_MIN                     0x0001u
#define BT_MCFG11_UNICAST_MAX                     0x7fffu
#define BT_MCFG11_RANGE_PRESENT                   0x8000u
#define BT_MCFG11_RANGE_LENGTH_MIN                1u
#define BT_MCFG11_AGG_SHORT_MAX                   0x7fu
#define BT_MCFG11_AGG_LONG_MAX                    0x7fffu
#define BT_MCFG11_ACCESS_OPCODE_LEN               2u

#endif
