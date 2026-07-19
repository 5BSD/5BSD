/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 ATT server-negative oracles.
 * Vol 3 Part F §§3.2-3.4 and Part G §2.5.2.1. No production headers.
 */
#ifndef TESTS_BLUETOOTH_SPEC_ATT_SERVER_NEGATIVE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_ATT_SERVER_NEGATIVE_ORACLES_H

#define BT_ASN_OP_ERROR_RSP                 0x01
#define BT_ASN_OP_MTU_REQ                   0x02
#define BT_ASN_OP_MTU_RSP                   0x03
#define BT_ASN_OP_FIND_INFO_REQ             0x04
#define BT_ASN_OP_FIND_INFO_RSP             0x05
#define BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ    0x06
#define BT_ASN_OP_READ_BY_TYPE_REQ          0x08
#define BT_ASN_OP_READ_BY_TYPE_RSP          0x09
#define BT_ASN_OP_READ_REQ                  0x0a
#define BT_ASN_OP_READ_RSP                  0x0b
#define BT_ASN_OP_READ_BLOB_REQ             0x0c
#define BT_ASN_OP_READ_MULTIPLE_REQ         0x0e
#define BT_ASN_OP_READ_BY_GROUP_TYPE_REQ    0x10
#define BT_ASN_OP_WRITE_REQ                 0x12
#define BT_ASN_OP_WRITE_RSP                 0x13
#define BT_ASN_OP_PREPARE_WRITE_REQ         0x16
#define BT_ASN_OP_PREPARE_WRITE_RSP         0x17
#define BT_ASN_OP_EXECUTE_WRITE_REQ         0x18
#define BT_ASN_OP_EXECUTE_WRITE_RSP         0x19
#define BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ 0x20
#define BT_ASN_OP_WRITE_CMD                 0x52
#define BT_ASN_OP_SIGNED_WRITE_CMD          0xd2

#define BT_ASN_ERR_INVALID_HANDLE           0x01
#define BT_ASN_ERR_WRITE_NOT_PERMITTED      0x03
#define BT_ASN_ERR_INVALID_PDU              0x04
#define BT_ASN_ERR_REQUEST_NOT_SUPPORTED    0x06
#define BT_ASN_ERR_INVALID_OFFSET           0x07
#define BT_ASN_ERR_PREPARE_QUEUE_FULL       0x09
#define BT_ASN_ERR_ATTRIBUTE_NOT_FOUND      0x0a
#define BT_ASN_ERR_ATTRIBUTE_NOT_LONG       0x0b
#define BT_ASN_ERR_INVALID_ATTRIBUTE_LENGTH 0x0d
#define BT_ASN_ERR_UNSUPPORTED_GROUP_TYPE   0x10
#define BT_ASN_ERR_DATABASE_OUT_OF_SYNC     0x12

#define BT_ASN_OPCODE_METHOD_MASK           0x3f
#define BT_ASN_OPCODE_COMMAND_FLAG          0x40
#define BT_ASN_DEFAULT_MTU                  23
#define BT_ASN_MAX_MTU                      517
#define BT_ASN_ERROR_RSP_LEN                5
#define BT_ASN_EXEC_CANCEL                  0x00
#define BT_ASN_EXEC_COMMIT                  0x01
#define BT_ASN_SIGNATURE_LEN                12

/* Assigned Numbers and Vol 3 Part G §3.3.1/Table 3.5. */
#define BT_ASN_UUID_PRIMARY_SERVICE         0x2800
#define BT_ASN_UUID_CHARACTERISTIC          0x2803
#define BT_ASN_UUID_GAP_SERVICE             0x1800
#define BT_ASN_UUID_DEVICE_NAME             0x2a00
#define BT_ASN_GATT_PROP_READ               0x02
#define BT_ASN_GATT_PROP_WRITE              0x08
#define BT_ASN_GATT_PROP_NOTIFY             0x10

#endif
