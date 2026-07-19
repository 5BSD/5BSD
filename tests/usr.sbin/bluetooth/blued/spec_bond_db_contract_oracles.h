/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent test copy of blued's documented private bond-store contract.
 * These are implementation oracles, not Bluetooth SIG wire assignments, and
 * this file deliberately includes no production header.
 */
#ifndef TESTS_BLUETOOTH_SPEC_BOND_DB_CONTRACT_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_BOND_DB_CONTRACT_ORACLES_H

/* usr.sbin/bluetooth/blued/smp.h: bounded in-memory bond database contract. */
#define BLUED_BOND_DB_MAX_RECORDS	32

/* usr.sbin/bluetooth/blued/smp_keys.c: encrypted on-disk format v5. */
#define BLUED_BOND_DB_ENCRYPTED_MAGIC	"BONDE"
#define BLUED_BOND_DB_ENCRYPTED_MAGIC_LEN	5
#define BLUED_BOND_DB_CURRENT_VERSION	5u
#define BLUED_BOND_DB_PBKDF2_SALT_LEN	16
#define BLUED_BOND_DB_GCM_IV_LEN	12
#define BLUED_BOND_DB_GCM_TAG_LEN	16
#define BLUED_BOND_DB_CIPHERTEXT_LEN_OFFSET \
	(BLUED_BOND_DB_ENCRYPTED_MAGIC_LEN + 4 + \
	 BLUED_BOND_DB_PBKDF2_SALT_LEN + BLUED_BOND_DB_GCM_IV_LEN + \
	 BLUED_BOND_DB_GCM_TAG_LEN)
#define BLUED_BOND_DB_ENCRYPTED_HEADER_LEN \
	(BLUED_BOND_DB_CIPHERTEXT_LEN_OFFSET + 4)

/*
 * FreeBSD ng_bluetooth.h private API: public=1 and random=2.  At the SMP/HCI
 * wire boundary blued translates these to the Core 6.3 values 0x00 and 0x01.
 */
#define BLUED_BOND_ADDR_PUBLIC	1
#define BLUED_BOND_ADDR_RANDOM	2
#define BT_CORE63_DEVICE_ADDR_PUBLIC_WIRE	0x00
#define BT_CORE63_DEVICE_ADDR_RANDOM_WIRE	0x01

/* Core 6.3 Vol 3 Part F §3.3.3.3, Client Characteristic Configuration. */
#define BT_CORE63_CCCD_NOTIFY_ENABLED	0x0001
#define BT_CORE63_CCCD_INDICATE_ENABLED	0x0002
#define BT_CORE63_CCCD_NOTIFY_AND_INDICATE_ENABLED	0x0003

#endif /* TESTS_BLUETOOTH_SPEC_BOND_DB_CONTRACT_ORACLES_H */
