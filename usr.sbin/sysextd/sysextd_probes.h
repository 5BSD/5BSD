/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for sysextd(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so sysextd builds identically with and without
 * DTrace.  Mirrors the logd(8) provider convention.
 */
#ifdef WITH_DTRACE
#include "sysextd_provider.h"
#define	SYSEXTD_PROBE_LIST(client, count, result) \
	SYSEXTD_LIST(__DECONST(char *, client), count, result)
#else
#define	SYSEXTD_PROBE_LIST(client, count, result) \
	do { (void)(client); (void)(count); (void)(result); } while (0)
#endif
