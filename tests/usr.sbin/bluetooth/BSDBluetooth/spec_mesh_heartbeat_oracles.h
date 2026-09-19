/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test-only Heartbeat oracles transcribed from Mesh Protocol 1.1 Sections
 * 3.6.7 and 4.2.18-4.3.2.66, Tables 3.47-3.50, 4.36-4.45, and
 * 4.143-4.148, plus Bluetooth Assigned Numbers.  No production includes.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_HEARTBEAT_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_HEARTBEAT_ORACLES_H

#define BT_MESH11_HB_CTL_OPCODE		0x0a
#define BT_MESH11_HB_FEATURE_RELAY	0x0001u
#define BT_MESH11_HB_FEATURE_PROXY	0x0002u
#define BT_MESH11_HB_FEATURE_FRIEND	0x0004u
#define BT_MESH11_HB_FEATURE_LOW_POWER	0x0008u
#define BT_MESH11_HB_FEATURE_MASK	0x000fu
#define BT_MESH11_HB_INIT_TTL_MAX	0x7f

#define BT_MESH11_CFG_OP_HB_PUB_STATUS	0x06u
#define BT_MESH11_CFG_OP_HB_PUB_GET	0x8038u
#define BT_MESH11_CFG_OP_HB_PUB_SET	0x8039u
#define BT_MESH11_CFG_OP_HB_SUB_GET	0x803au
#define BT_MESH11_CFG_OP_HB_SUB_SET	0x803bu
#define BT_MESH11_CFG_OP_HB_SUB_STATUS	0x803cu

#define BT_MESH11_HB_BODY_SIZE		3
#define BT_MESH11_HB_CTL_PDU_SIZE	4
#define BT_MESH11_HB_PUB_SET_PDU_SIZE	11
#define BT_MESH11_HB_PUB_STATUS_PDU_SIZE 11
#define BT_MESH11_HB_SUB_SET_PDU_SIZE	7
#define BT_MESH11_HB_SUB_STATUS_PDU_SIZE 11
#define BT_MESH11_HB_LOG_MAX		0x11
#define BT_MESH11_HB_COUNT_INDEFINITE	0xff
#define BT_MESH11_HB_MIN_HOPS_RESET	0x7f
#define BT_MESH11_HB_MAX_HOPS_RESET	0x00

/* Exact sample encodings assembled from Tables 3.47 and 4.143-4.148. */
static const unsigned char bt_mesh11_hb_body_proxy_lpn[3] = {
	0x7f, 0x00, 0x0a
};
static const unsigned char bt_mesh11_hb_ctl_proxy_lpn[4] = {
	0x0a, 0x7f, 0x00, 0x0a
};
static const unsigned char bt_mesh11_hb_pub_set_sample[11] = {
	0x80, 0x39, 0x01, 0xc0, 0x01, 0x02, 0x07, 0x07, 0x00, 0x23, 0x01
};
static const unsigned char bt_mesh11_hb_pub_status_sample[11] = {
	0x06, 0x00, 0x01, 0xc0, 0x01, 0x02, 0x07, 0x07, 0x00, 0x23, 0x01
};
static const unsigned char bt_mesh11_hb_sub_set_sample[7] = {
	0x80, 0x3b, 0x02, 0x00, 0x01, 0xc0, 0x03
};
static const unsigned char bt_mesh11_hb_sub_status_sample[11] = {
	0x80, 0x3c, 0x00, 0x02, 0x00, 0x01, 0xc0, 0x03, 0x02, 0x01, 0x03
};

#endif /* TESTS_BLUETOOTH_SPEC_MESH_HEARTBEAT_ORACLES_H */
