/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent LE Privacy oracles.  No production Bluetooth header is used.
 */

#ifndef TESTS_BLUETOOTH_SPEC_PRIVACY_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_PRIVACY_ORACLES_H

#include <stdint.h>

#include "spec_core63_generated.h"
#include "spec_privacy_scan_oracles.h"

/*
 * Core 6.3 Vol 3 Part H Appendix D.7, converted from published big-endian
 * notation to the little-endian arrays consumed by smp_rpa_matches().
 * RPA = hash || prand = 0dfbaa || 708194 in published notation.
 */
static const uint8_t bt_privacy_d7_irk_le[16] = {
	0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34,
	0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02, 0xec
};
static const uint8_t bt_privacy_d7_rpa_le[6] = {
	0xaa, 0xfb, 0x0d, 0x94, 0x81, 0x70
};

#endif /* TESTS_BLUETOOTH_SPEC_PRIVACY_ORACLES_H */
