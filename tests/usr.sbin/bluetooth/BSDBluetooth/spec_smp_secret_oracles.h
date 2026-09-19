/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Independent test constants for blued's local bond-secret storage contract.
 * This is an implementation security contract, not a Bluetooth SIG wire
 * requirement: a 256-bit root is stored as exactly 32 raw octets in an
 * owner-only regular file and is loaded without transformation.
 */
#ifndef TESTS_BLUETOOTH_SPEC_SMP_SECRET_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_SMP_SECRET_ORACLES_H

#define BLUED_TEST_BOND_SECRET_SIZE	32
#define BLUED_TEST_BOND_SECRET_TRUNCATED_SIZE 31
#define BLUED_TEST_BOND_SECRET_MODE	0600
#define BLUED_TEST_BOND_SECRET_INSECURE_MODE 0644
#define BLUED_TEST_DIRECTORY_MODE	0700

/* Non-normative recognizable test patterns. */
#define BLUED_TEST_SECRET_EXISTING_BYTE	0xa5
#define BLUED_TEST_SECRET_RACING_BYTE	0x6c
#define BLUED_TEST_SECRET_INSECURE_BYTE	0x5a

#endif /* TESTS_BLUETOOTH_SPEC_SMP_SECRET_ORACLES_H */
