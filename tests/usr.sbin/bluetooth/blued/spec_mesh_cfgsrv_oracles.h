/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Mesh Model 1.1.1 Configuration Server wire oracles.
 * No production Mesh header is included.
 */

#ifndef TESTS_BLUETOOTH_SPEC_MESH_CFGSRV_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_CFGSRV_ORACLES_H

#include <stdint.h>

/* Mesh Model 1.1.1 §4.3.4: Configuration status values. */
#define BT_MESH_CFGSRV_SUCCESS			0x00
#define BT_MESH_CFGSRV_INVALID_ADDRESS		0x01
#define BT_MESH_CFGSRV_INVALID_MODEL		0x02
#define BT_MESH_CFGSRV_INVALID_NETKEY_INDEX	0x04

/* Mesh Model 1.1.1 §4.3.4: request opcodes exercised as inputs. */
#define BT_MESH_CFGSRV_OP_APPKEY_ADD		0x0000
#define BT_MESH_CFGSRV_OP_APPKEY_UPDATE		0x0001
#define BT_MESH_CFGSRV_OP_BEACON_GET		0x8009
#define BT_MESH_CFGSRV_OP_BEACON_SET		0x800a
#define BT_MESH_CFGSRV_OP_DEFAULT_TTL_GET	0x800c
#define BT_MESH_CFGSRV_OP_FRIEND_GET		0x800f
#define BT_MESH_CFGSRV_OP_GATT_PROXY_GET	0x8012
#define BT_MESH_CFGSRV_OP_MODEL_SUB_ADD		0x801b
#define BT_MESH_CFGSRV_OP_NET_TRANSMIT_GET	0x8023
#define BT_MESH_CFGSRV_OP_NET_TRANSMIT_SET	0x8024
#define BT_MESH_CFGSRV_OP_RELAY_GET		0x8026
#define BT_MESH_CFGSRV_OP_RELAY_SET		0x8027
#define BT_MESH_CFGSRV_OP_SIG_MODEL_SUB_GET	0x8029
#define BT_MESH_CFGSRV_OP_MODEL_APP_BIND	0x803d
#define BT_MESH_CFGSRV_OP_NETKEY_ADD		0x8040
#define BT_MESH_CFGSRV_OP_NETKEY_UPDATE		0x8045
#define BT_MESH_CFGSRV_OP_SIG_MODEL_APP_GET	0x804b

/* Mesh Model 1.1.1 §7.3: Health request opcodes. */
#define BT_MESH_CFGSRV_OP_HEALTH_ATTENTION_SET	0x8005
#define BT_MESH_CFGSRV_OP_HEALTH_FAULT_CLEAR	0x802f
#define BT_MESH_CFGSRV_OP_HEALTH_FAULT_TEST	0x8032
#define BT_MESH_CFGSRV_OP_HEALTH_PERIOD_GET	0x8034
#define BT_MESH_CFGSRV_OP_HEALTH_PERIOD_SET	0x8035

/* Bluetooth SIG Assigned Numbers: SIG model identifiers. */
#define BT_MESH_CFGSRV_MODEL_CONFIG_SERVER	0x0000
#define BT_MESH_CFGSRV_MODEL_GENERIC_ONOFF_SERVER 0x1000
#define BT_MESH_CFGSRV_MODEL_GENERIC_LEVEL_SERVER 0x1002

/* Exact Access PDUs: two-octet opcodes are transmitted high octet first. */
static const uint8_t bt_mesh_cfgsrv_netkey_status_1[] = {
	0x80, 0x44, 0x00, 0x01, 0x00
};
static const uint8_t bt_mesh_cfgsrv_appkey_status_0_1[] = {
	0x80, 0x03, 0x00, 0x00, 0x10, 0x00
};
static const uint8_t bt_mesh_cfgsrv_model_app_status_elem1_app1_onoff[] = {
	0x80, 0x3e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x10
};
static const uint8_t bt_mesh_cfgsrv_model_sub_status_elem1_c001_onoff[] = {
	0x80, 0x1f, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x10
};
/*
 * Mesh Model 1.1.1 Table 4.75, Model Subscription Add:
 * opcode 0x801B, ElementAddress 0x0001, subscription Address 0x0005,
 * and SIG ModelIdentifier 0x1000.  Address 0x0005 is deliberately unicast;
 * §4.3.2.20 requires status Invalid Address (0x01) for this request.
 */
static const uint8_t bt_mesh_cfgsrv_model_sub_add_invalid_unicast[] = {
	0x80, 0x1b, 0x01, 0x00, 0x05, 0x00, 0x00, 0x10
};
static const uint8_t bt_mesh_cfgsrv_beacon_status_off[] = {
	0x80, 0x0b, 0x00
};
static const uint8_t bt_mesh_cfgsrv_default_ttl_status_7[] = {
	0x80, 0x0e, 0x07
};
static const uint8_t bt_mesh_cfgsrv_relay_status_off[] = {
	0x80, 0x28, 0x00, 0x00
};
static const uint8_t bt_mesh_cfgsrv_proxy_status_off[] = {
	0x80, 0x14, 0x00
};
/* Feature state 0x02 means Not Supported (Mesh Model 1.1.1 §4.2.4). */
static const uint8_t bt_mesh_cfgsrv_friend_status_not_supported[] = {
	0x80, 0x11, 0x02
};
static const uint8_t bt_mesh_cfgsrv_net_tx_status_zero[] = {
	0x80, 0x25, 0x00
};

#endif /* TESTS_BLUETOOTH_SPEC_MESH_CFGSRV_ORACLES_H */
