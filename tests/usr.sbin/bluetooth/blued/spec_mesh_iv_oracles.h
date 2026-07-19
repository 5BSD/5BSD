/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Bluetooth Mesh IV Update test oracles.  This header does not
 * include mesh_iv.h; values here come from the adopted specification and its
 * qualification test suite, except for the explicitly labelled local policy.
 */

#ifndef TESTS_BLUETOOTH_SPEC_MESH_IV_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_MESH_IV_ORACLES_H

/* Mesh Protocol 1.1.1 §3.11.5 and Tables 3.83-3.84. */
#define BT_MESH_SPEC_IV_NORMAL			0
#define BT_MESH_SPEC_IV_UPDATE_IN_PROGRESS	1
#define BT_MESH_SPEC_IV_DWELL_HOURS		96u
#define BT_MESH_SPEC_IV_DWELL_SECONDS		345600u

/* Mesh Protocol 1.1.1 §3.11.6 and Table 3.85. */
#define BT_MESH_SPEC_IV_RECOVERY_MAX_INCREMENT	42u

/* Mesh Protocol 1.1.1 §3.9.3: SEQ is a 24-bit field. */
#define BT_MESH_SPEC_SEQ_MAX			0x00ffffffu

/*
 * lib/libmesh/mesh_iv.h MESH_IV_SEQ_TRIGGER local early-update policy.
 * The Mesh specification requires updating before exhaustion but assigns no
 * fixed trigger value; this is deliberately not a normative oracle.
 */
#define BT_MESH_IMPL_SEQ_TRIGGER		0x00800000u

#endif /* TESTS_BLUETOOTH_SPEC_MESH_IV_ORACLES_H */
