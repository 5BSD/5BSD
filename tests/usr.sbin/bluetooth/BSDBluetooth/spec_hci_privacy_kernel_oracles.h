/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent Core 6.3 HCI initiator/privacy and CIS command assignments.
 * No Netgraph or production Bluetooth header is included.
 */

#ifndef TESTS_BLUETOOTH_SPEC_HCI_PRIVACY_KERNEL_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_HCI_PRIVACY_KERNEL_ORACLES_H

/* Core 6.3 Vol 4 Part A §2 and Vol 4 Part E command definitions. */
#define BT_HK_SPEC_HCI_COMMAND_PACKET		0x01
#define BT_HK_SPEC_OP_LE_CREATE_CONNECTION	0x200d
#define BT_HK_SPEC_OP_LE_CREATE_CIS		0x2064

/* Core 6.3 Vol 4 Part E §7.8.12 address-type enumerations. */
#define BT_HK_SPEC_PEER_PUBLIC_IDENTITY		0x00
#define BT_HK_SPEC_PEER_RANDOM_IDENTITY		0x01
#define BT_HK_SPEC_OWN_PUBLIC			0x00
#define BT_HK_SPEC_OWN_RPA_PUBLIC_FALLBACK	0x02
#define BT_HK_SPEC_OWN_RPA_RANDOM_FALLBACK	0x03

/* Core 6.3 Vol 4 Part E §7.8.99 LE Create CIS parameter layout. */
#define BT_HK_SPEC_CREATE_CIS_PARAM_LEN_ONE	5
#define BT_HK_SPEC_CREATE_CIS_COUNT_ONE		1

#endif /* TESTS_BLUETOOTH_SPEC_HCI_PRIVACY_KERNEL_ORACLES_H */
