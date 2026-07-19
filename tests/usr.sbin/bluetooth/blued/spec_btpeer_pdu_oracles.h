/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent byte oracles for btpeer_srv_pdu_test.
 *
 * Opcode, error, SMP, and fixed-CID assignments are instantiated from the
 * generated Core 6.3 oracle header.  The generated header is produced from
 * bluetooth-specs/Core_Specification_6_3.txt and includes no production
 * Bluetooth headers.
 */

#ifndef TESTS_BLUETOOTH_SPEC_BTPEER_PDU_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_BTPEER_PDU_ORACLES_H

#include <stdint.h>

#include "spec_core63_generated.h"

#define BTPEER_SPEC_ENUM(name, value) BTPEER_SPEC_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_SMP_COMMAND_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_SMP_SCALAR_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_SMP_KEY_DIST_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_L2CAP_CID_ORACLES(BTPEER_SPEC_ENUM)
	BT_CORE63_PREVIOUSLY_USED_ORACLES(BTPEER_SPEC_ENUM)
};
#undef BTPEER_SPEC_ENUM

/* Core 6.3, Vol 3, Part F §§3.2.8, 3.4.1.1, and 3.4.3.2. */
#define BTPEER_SPEC_ATT_DEFAULT_MTU		23
#define BTPEER_SPEC_ATT_ERROR_RSP_LEN		5
#define BTPEER_SPEC_ATT_FIND_INFO_FORMAT_16	0x01
#define BTPEER_SPEC_ATT_FIND_INFO_RECORD16_LEN	4

/* Assigned Numbers, GATT Declarations: Primary Service declaration. */
#define BTPEER_SPEC_GATT_PRIMARY_SERVICE_UUID	0x2800

/* Core 6.3, Vol 3, Part H §§3.5.1-3.5.4 and 3.6.2-3.6.5. */
#define BTPEER_SPEC_SMP_PAIRING_PDU_LEN		7
#define BTPEER_SPEC_SMP_CONFIRM_RANDOM_PDU_LEN	17
#define BTPEER_SPEC_SMP_ENC_INFO_PDU_LEN		17
#define BTPEER_SPEC_SMP_CENTRAL_ID_PDU_LEN	11
#define BTPEER_SPEC_SMP_IDENTITY_INFO_PDU_LEN	17
#define BTPEER_SPEC_SMP_IDENTITY_ADDR_PDU_LEN	8
#define BTPEER_SPEC_SMP_SIGNING_INFO_PDU_LEN	17
#define BTPEER_SPEC_SMP_OOB_NOT_PRESENT		0x00
#define BTPEER_SPEC_SMP_KEY_DIST_NONE		0x00

/* Core 6.3, Vol 3, Part H §2.4.5. */
#define BTPEER_SPEC_SIGN_COUNTER_LEN		4
#define BTPEER_SPEC_SIGNATURE_LEN		8

/*
 * AES-CMAC(CSRK, 0xd2||0x0025_le||01020304||7_le), CSRK on-air bytes
 * 10..1f.  Independently reproduced with OpenSSL 3 CMAC using the Core
 * §2.4.5 byte-order rules; the signature is the least-significant 64 bits.
 */
static const uint8_t btpeer_spec_signed_write_mac[8] = {
	0x39, 0x0b, 0xe6, 0xd5, 0xe3, 0xf9, 0xb0, 0xe9
};

#endif /* TESTS_BLUETOOTH_SPEC_BTPEER_PDU_ORACLES_H */
