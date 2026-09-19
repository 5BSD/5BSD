/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent Bluetooth Core 6.3 and Assigned Numbers oracles for
 * btpeer_test.  No production Bluetooth header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_BTPEER_INTEGRATION_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_BTPEER_INTEGRATION_ORACLES_H

/* Core 6.3, Vol 3, Part F §3.2.9 and §3.4.7. */
#define BTPI_ATT_MAX_MTU                 517
#define BTPI_ATT_OP_HANDLE_NOTIFY        0x1b
#define BTPI_ATT_OP_HANDLE_INDICATE      0x1d

/* Core 6.3, Vol 3, Part F §3.4.1.1, Table 3.4. */
#define BTPI_ATT_ERR_INVALID_HANDLE      0x01
#define BTPI_ATT_ERR_WRITE_NOT_PERMITTED 0x03
#define BTPI_ATT_ERR_INSUFFICIENT_AUTHENTICATION 0x05

/* Core 6.3, Vol 3, Part G §3.3.1.1, Table 3.5. */
#define BTPI_GATT_PROP_READ              0x02
#define BTPI_GATT_PROP_WRITE             0x08
#define BTPI_GATT_PROP_NOTIFY            0x10

/* Core 6.3, Vol 3, Part G §3.3.3.3. */
#define BTPI_CCCD_NOTIFY                 0x0001
#define BTPI_CCCD_INDICATE               0x0002

/* Bluetooth Assigned Numbers: services, characteristics, descriptor. */
#define BTPI_UUID_GAP_SERVICE            0x1800
#define BTPI_UUID_DEVICE_INFO_SERVICE    0x180a
#define BTPI_UUID_BATTERY_SERVICE        0x180f
#define BTPI_UUID_HID_SERVICE            0x1812
#define BTPI_UUID_DEVICE_NAME            0x2a00
#define BTPI_UUID_BATTERY_LEVEL          0x2a19
#define BTPI_UUID_MANUFACTURER_NAME      0x2a29
#define BTPI_UUID_HID_INFORMATION        0x2a4a
#define BTPI_UUID_REPORT_MAP             0x2a4b
#define BTPI_UUID_REPORT                 0x2a4d
#define BTPI_UUID_CCCD                   0x2902

/* Battery Service 1.1, §3.1: percentage range. */
#define BTPI_BATTERY_FULL_PERCENT        100

/* USB HID Usage Tables 1.5, §10: Keyboard a and A selection. */
#define BTPI_HID_KEYBOARD_A              0x04

/* Core 6.3, Vol 3, Part H §§3.5.1 and 3.5.6. */
#define BTPI_SMP_ADDR_PUBLIC             0x00
#define BTPI_SMP_IO_NO_INPUT_NO_OUTPUT   0x03
#define BTPI_SMP_ENC_KEY_SIZE_MIN        0x07

/* Core 6.3, Vol 4, Part E §7.7.8: Encryption_Enabled. */
#define BTPI_HCI_ENCRYPTION_ON            0x01

#endif
