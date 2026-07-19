/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Mesh Protocol 1.1 network-integration oracles.
 * No production mesh header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_NETWORK_INTEGRATION_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_NETWORK_INTEGRATION_ORACLES_H

/* Mesh Protocol 1.1 §8.2 published security material. */
#define BT_MNET_SAMPLE_NETKEY_BYTES                                      \
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,                 \
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
#define BT_MNET_SAMPLE_APPKEY_BYTES                                      \
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,                 \
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
#define BT_MNET_SAMPLE_IV_INDEX          0x12345678u

/* Local distinct-key fixtures; these values have no normative significance. */
#define BT_MNET_FIXTURE_NETKEY_B_BYTES                                  \
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,                 \
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
#define BT_MNET_FIXTURE_NETKEY_C_BYTES                                  \
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,                 \
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
#define BT_MNET_FIXTURE_APPKEY_B_BYTES                                  \
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,                 \
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00

/* Mesh Protocol 1.1 §§3.4.2, 3.4.4, 3.9.8, and 3.11.4. */
#define BT_MNET_UNICAST_MIN              0x0001u
#define BT_MNET_GROUP_MIN                0xc000u
#define BT_MNET_GROUP_NEXT               0xc001u
#define BT_MNET_NID_MASK                 0x7fu
#define BT_MNET_TTL_NO_RELAY_MAX         1u
#define BT_MNET_TTL_RELAY_MIN            2u
#define BT_MNET_KR_NORMAL                0u
#define BT_MNET_KR_PHASE_1               1u
#define BT_MNET_KR_PHASE_2               2u
#define BT_MNET_KR_PHASE_3               3u

/* Mesh Protocol 1.1 §§3.6.6.3.1, 3.6.6.4.2, and 3.11.5-.6. */
#define BT_MNET_POLL_TIMEOUT_STEP_MS      100u
#define BT_MNET_POLL_TIMEOUT_SAMPLE      0x0000a0u
#define BT_MNET_IV_DWELL_SECONDS         345600u

/* Mesh Protocol 1.1 §6.6, Tables 6.5 and 6.7. */
#define BT_MNET_PROXY_OP_SET_FILTER      0x00u
#define BT_MNET_PROXY_OP_ADD_ADDR        0x01u
#define BT_MNET_PROXY_OP_REMOVE_ADDR     0x02u
#define BT_MNET_PROXY_OP_FILTER_STATUS   0x03u
#define BT_MNET_PROXY_FILTER_ACCEPT      0x00u
#define BT_MNET_PROXY_FILTER_REJECT      0x01u

/* Mesh Model 1.1.1 §3.2.1.3; Assigned Numbers message opcode. */
#define BT_MNET_OP_GEN_ONOFF_SET_UNACK   0x8203u
#define BT_MNET_GENERIC_ONOFF_OFF         0x00u
#define BT_MNET_GENERIC_ONOFF_ON          0x01u

#endif
