/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Mesh relay/configuration oracles.
 */
#ifndef TESTS_BLUETOOTH_SPEC_MESH_RELAY_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_RELAY_ORACLES_H

/* Mesh Protocol 1.1.1 §3.4.6.3 and Network PDU TTL field. */
#define BT_MESH_SPEC_TTL_NO_RELAY_MAX	1u
#define BT_MESH_SPEC_TTL_RELAY_MIN	2u
#define BT_MESH_SPEC_TTL_MAX		0x7fu
#define BT_MESH_SPEC_TTL_FIRST_RESERVED	0x80u

/* Mesh Protocol 1.1.1 §§4.2.20-4.2.21 and Config state formats. */
#define BT_MESH_SPEC_RETRANS_COUNT_BITS	3u
#define BT_MESH_SPEC_RETRANS_COUNT_MAX	7u
#define BT_MESH_SPEC_RETRANS_STEPS_BITS	5u
#define BT_MESH_SPEC_RETRANS_STEPS_MAX	31u
#define BT_MESH_SPEC_RETRANS_STEP_MS	10u
#define BT_MESH_SPEC_RETRANS_PACK(count, steps) \
	((uint8_t)(((count) & 0x07u) | (((steps) & 0x1fu) << 3)))

#endif /* TESTS_BLUETOOTH_SPEC_MESH_RELAY_ORACLES_H */
