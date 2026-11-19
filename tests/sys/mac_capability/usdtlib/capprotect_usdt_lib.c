/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A shared object with the cpulib USDT provider, which the capprotect
 * tracing fixture (capprotect_usdt_helper) dlopen()s after its first
 * registration (capprotect_dtrace_test.sh, usdt_glob_later_dlopen).
 */

#ifdef WITH_DTRACE
#include "capprotect_usdt_lib_provider.h"
#else
#define	CPULIB_HIT()	do { } while (0)
#endif

void	capprotect_usdt_lib_hit(void);

void
capprotect_usdt_lib_hit(void)
{

	CPULIB_HIT();
}
