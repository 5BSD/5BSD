/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test-only capture oracles.  The BTSnoop container values are independently
 * cross-checked against BlueZ tools/btsnoop.c and src/shared/btsnoop.h.  H4
 * packet indicators and HCI Reset are from Bluetooth Core 6.3 Vol 4 Part A
 * §2/Table 2.1 and Vol 4 Part E §7.3.2.  No production headers are included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_HCI_LOG_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_LOG_ORACLES_H

static const uint8_t bt_btsnoop_magic[8] = {
	0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00
};

#define BT_BTSNOOP_VERSION		1
#define BT_BTSNOOP_DATALINK_H4		1002
#define BT_BTSNOOP_FILE_HEADER_SIZE	16
#define BT_BTSNOOP_RECORD_HEADER_SIZE	24
#define BT_BTSNOOP_FLAG_SENT_COMMAND	0x02
#define BT_BTSNOOP_FLAG_SENT_DATA	0x00
#define BT_BTSNOOP_FLAG_RECEIVED_DATA	0x01
#define BT_BTSNOOP_FLAG_RECEIVED_EVENT	0x03
#define BT_BTSNOOP_DROPS_NONE		0

#define BT_CORE63_H4_COMMAND_PACKET	0x01
#define BT_CORE63_H4_ACL_PACKET		0x02
#define BT_CORE63_H4_EVENT_PACKET	0x04
#define BT_CORE63_HCI_RESET_OPCODE_LE0	0x03
#define BT_CORE63_HCI_RESET_OPCODE_LE1	0x0c
#define BT_CORE63_HCI_RESET_PARAM_LEN	0x00
#define BT_CORE63_HCI_COMMAND_HEADER_SIZE 3

/* Complete HCI_Reset command and successful Command Complete event. */
static const uint8_t bt_core63_hci_reset_command[] = {
	0x03, 0x0c, 0x00
};
static const uint8_t bt_core63_hci_reset_complete_event[] = {
	0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00
};

/* Vol 4 Part E §5.4.2 and Vol 3 Part A §§2.1, 3/Table 3.1. */
#define BT_CORE63_ACL_PB_FIRST_AUTO_FLUSH	0x02
#define BT_CORE63_ACL_HEADER_SIZE		4
#define BT_CORE63_L2CAP_BASIC_HEADER_SIZE	4
#define BT_CORE63_L2CAP_CID_ATT			0x0004
/* Non-normative valid connection-handle sentinel for framing tests. */
#define BT_TEST_ACL_CONNECTION_HANDLE		0x0040

/* Vol 3 Part F §§3.3.1, 3.4.2: Exchange MTU Request for default LE MTU 23. */
static const uint8_t bt_core63_att_exchange_mtu_23[] = {
	0x02, 0x17, 0x00
};

#endif /* TESTS_BLUETOOTH_SPEC_HCI_LOG_ORACLES_H */
