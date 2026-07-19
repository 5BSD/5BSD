/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Mesh Configuration Client response oracles.
 * No production mesh header is included.
 */

#ifndef TESTS_BLUETOOTH_SPEC_MESH_CFGCLIENT_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_CFGCLIENT_ORACLES_H

#include <stdint.h>

/* Mesh Protocol 1.1 §§4.2-4.4 Configuration messages/status codes. */
#define BT_MESH_CFG_SUCCESS			0x00
#define BT_MESH_CFG_OP_APPKEY_STATUS		0x8003
#define BT_MESH_CFG_OP_DEFAULT_TTL_GET		0x800c
#define BT_MESH_CFG_OP_DEFAULT_TTL_STATUS	0x800e
#define BT_MESH_CFG_OP_MODEL_APP_STATUS		0x803e
#define BT_MESH_CFG_OP_NODE_RESET_STATUS	0x804a

/* Bluetooth Assigned Numbers, Mesh Model identifiers. */
#define BT_MESH_MODEL_GENERIC_ONOFF_SERVER	0x1000

/*
 * Exact Access PDUs for the all-zero NetKey/AppKey indexes used by this test.
 * Two-octet opcodes are encoded most-significant octet first; multioctet
 * parameters are little-endian per Mesh Protocol 1.1 §§4.2-4.3.
 */
static const uint8_t bt_mesh_cfg_appkey_status_zero[] = {
	0x80, 0x03, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t bt_mesh_cfg_model_app_status_onoff[] = {
	0x80, 0x3e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10
};
static const uint8_t bt_mesh_cfg_node_reset_status[] = {
	0x80, 0x4a
};

#endif /* TESTS_BLUETOOTH_SPEC_MESH_CFGCLIENT_ORACLES_H */
