/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Independent SMP timeout oracles; no production header is included.
 */
#ifndef TESTS_BLUETOOTH_SPEC_SMP_TIMEOUT_ORACLES_H
#define TESTS_BLUETOOTH_SPEC_SMP_TIMEOUT_ORACLES_H

/* Bluetooth Core 6.3 Vol 3 Part H §3.4. */
#define BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS	30u

/*
 * smp.c rate-limit policy.  Core §3.4 requires appropriate delays after
 * repeated attempts but deliberately does not prescribe these numbers.
 */
#define BT_SMP_IMPL_RATE_LIMIT_ADMITTED		3u
#define BT_SMP_IMPL_RATE_LIMIT_FIRST_REJECTED	4u
#define BT_SMP_IMPL_RATE_LIMIT_BASE_SECONDS	60u
#define BT_SMP_IMPL_RATE_LIMIT_BACKOFF_CAP_SECONDS 900u
#define BT_SMP_IMPL_GLOBAL_PRESSURE_PEERS	32u

#endif /* TESTS_BLUETOOTH_SPEC_SMP_TIMEOUT_ORACLES_H */
