/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_BSDMEMORY_TRACE_PRESSURE_H
#define USR_SBIN_BSDMEMORY_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include "bsdmemory_provider.h"
#endif
#ifdef WITH_DTRACE
#define BSDMEMORY_TRACE_DEPENDENCY_HEALTH(a0, a1, a2) \
	BSDMEMORY_DEPENDENCY_HEALTH(a0, a1, a2)
#else
#define BSDMEMORY_TRACE_DEPENDENCY_HEALTH(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#endif
