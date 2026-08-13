/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent PC4 bond-record contract and Core SMP field bounds.
 * PC4/BREC is a blued interchange format, not a Bluetooth SIG format.
 */

#ifndef TESTS_BLUETOOTH_SPEC_BOND_MIGRATE_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_BOND_MIGRATE_ORACLES_H

#include <stdint.h>

/* smp_keys.c PC4 format contract: magic | LE32 version | LE32 struct size. */
#define BT_BOND_PC4_MAGIC_LEN		4
#define BT_BOND_PC4_VERSION_OFFSET	4
#define BT_BOND_PC4_STRUCT_SIZE_OFFSET	8
#define BT_BOND_PC4_HEADER_LEN		12
/* v2 added the HOGP hid_ctrl_handle + multi-instance report-map handles. */
#define BT_BOND_PC4_VERSION		2

static const uint8_t bt_bond_pc4_prefix[] = {
	'B', 'R', 'E', 'C', 0x02, 0x00, 0x00, 0x00
};

/* Core 6.3 Vol 3 Part H §2.3.4 and Vol 6 Part B §1.3 address types. */
#define BT_BOND_SPEC_ADDR_PUBLIC	0x01
#define BT_BOND_SPEC_ADDR_RANDOM	0x02
#define BT_BOND_SPEC_KEY_SIZE_MIN	7
#define BT_BOND_SPEC_KEY_SIZE_MAX	16

/* Explicit PC4 implementation limits from the public smp.h contract. */
#define BT_BOND_PC4_MAX_CCCDS		16
#define BT_BOND_PC4_MAX_BONDS		32

#endif /* TESTS_BLUETOOTH_SPEC_BOND_MIGRATE_ORACLES_H */
