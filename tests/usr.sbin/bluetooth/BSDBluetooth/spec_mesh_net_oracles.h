/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Mesh Protocol 1.1.1 network-layer oracles.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_NET_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_NET_ORACLES_H

/* §8.2.2 network security material and §8.3 worked-message context. */
#define BT_MESH_SPEC_NET_ENCKEY_HEX "0953fa93e7caac9638f58820220a398e"
#define BT_MESH_SPEC_NET_PRIVKEY_HEX "8b84eedec100067d670971dd2aa700cf"
#define BT_MESH_SPEC_NET_NID		0x68u
#define BT_MESH_SPEC_NET_IV_INDEX	0x12345678u

/* §§3.4.3-3.4.5 Network PDU fields and advertising-bearer budget. */
#define BT_MESH_SPEC_NET_NID_MAX	0x7fu
#define BT_MESH_SPEC_NET_FLAG_MAX	1u
#define BT_MESH_SPEC_NET_TTL_MAX	0x7fu
#define BT_MESH_SPEC_NET_SEQ_MAX	0x00ffffffu
#define BT_MESH_SPEC_NET_HEADER_SIZE	9u
#define BT_MESH_SPEC_NET_MAX_PDU_SIZE	29u
#define BT_MESH_SPEC_NET_ACCESS_MIC_SIZE 4u
#define BT_MESH_SPEC_NET_CONTROL_MIC_SIZE 8u
#define BT_MESH_SPEC_NET_ACCESS_TRANSPORT_MAX 16u
#define BT_MESH_SPEC_NET_CONTROL_TRANSPORT_MAX 12u

#endif /* TESTS_BLUETOOTH_SPEC_MESH_NET_ORACLES_H */
