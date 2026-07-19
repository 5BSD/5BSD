/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Bluetooth Core 6.3 Secure Connections test oracles.
 * The generated input contains literals transcribed from the cited Core;
 * this header deliberately includes no production SMP header.
 */
#ifndef TESTS_BLUETOOTH_SPEC_SMP_DEEP_SC_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_SMP_DEEP_SC_ORACLES_H

#include "spec_core63_generated.h"

#define BTDS_ENUM(name, value) BTDS_##name = value,
enum {
	/* Core 6.3 Vol 3 Part H §3.3, Table 3.3. */
	BT_CORE63_SMP_COMMAND_ORACLES(BTDS_ENUM)
	/* Core 6.3 Vol 3 Part H §3.5.5, Table 3.7. */
	BT_CORE63_SMP_FAILURE_ORACLES(BTDS_ENUM)
	/* Core 6.3 Vol 3 Part H §3.5.1, Tables 3.4-3.5. */
	BT_CORE63_SMP_SCALAR_ORACLES(BTDS_ENUM)
	/* Core 6.3 Vol 3 Part H §3.6.1, Figure 3.11. */
	BT_CORE63_SMP_KEY_DIST_ORACLES(BTDS_ENUM)
};
#undef BTDS_ENUM

/* Core 6.3 Vol 3 Part H §3.5 command formats. */
#define BTDS_PAIRING_FEATURE_PDU_LEN	7
#define BTDS_CONFIRM_RANDOM_DHKEY_PDU_LEN 17
#define BTDS_PUBLIC_KEY_PDU_LEN		65
#define BTDS_PAIRING_FAILED_PDU_LEN	2
#define BTDS_IDENTITY_INFO_PDU_LEN	17
#define BTDS_IDENTITY_ADDR_PDU_LEN	8
#define BTDS_KEYPRESS_PDU_LEN		2
#define BTDS_MAX_ENCRYPTION_KEY_SIZE	16
#define BTDS_SC_VALUE_LEN		16
#define BTDS_P256_COORD_LEN		32
#define BTDS_P256_UNCOMPRESSED_LEN	65
#define BTDS_OOB_NOT_PRESENT		0x00
#define BTDS_KEY_DIST_NONE		0x00

/* Core 6.3 Vol 3 Part H §3.5.8, Figure 3.10. */
#define BTDS_KEYPRESS_STARTED		0x00

/* Core 6.3 Vol 3 Part H §3.6.5, Figure 3.15. */
#define BTDS_ID_ADDR_PUBLIC		0x00
#define BTDS_ID_ADDR_STATIC_RANDOM	0x01

/* Core 6.3 Vol 3 Part H §2.2.6, Table 2.1. */
#define BTDS_F4_PASSKEY_Z_BASE		0x80

#endif
