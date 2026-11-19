/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider of the shared object the capprotect tracing fixture loads
 * late (capprotect_usdt_lib.c).
 */
provider cpulib {
	probe hit();
};
