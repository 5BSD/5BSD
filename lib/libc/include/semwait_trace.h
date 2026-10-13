/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SEMWAIT_TRACE_H_
#define _SEMWAIT_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <nameres_provider.h>
extern const unsigned char __bsd_dof_anchor_nameres_provider
    __attribute__((visibility("hidden")));
static const void * const semwait_dtrace_anchor
    __attribute__((used, retain)) = &__bsd_dof_anchor_nameres_provider;

#define TRACE_SEMWAIT_PARK__START(a0, a1, a2) do { \
	if (SEMWAIT_PARK_START_ENABLED()) \
		SEMWAIT_PARK_START((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_SEMWAIT_PARK__DONE(a0, a1, a2) do { \
	if (SEMWAIT_PARK_DONE_ENABLED()) \
		SEMWAIT_PARK_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_SEMWAIT_WAKE__START(a0) do { \
	if (SEMWAIT_WAKE_START_ENABLED()) \
		SEMWAIT_WAKE_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_SEMWAIT_WAKE__DONE(a0, a1, a2) do { \
	if (SEMWAIT_WAKE_DONE_ENABLED()) \
		SEMWAIT_WAKE_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_SEMWAIT_PARK__START(a0, a1, a2) do { } while (0)
#define TRACE_SEMWAIT_PARK__DONE(a0, a1, a2) do { } while (0)
#define TRACE_SEMWAIT_WAKE__START(a0) do { } while (0)
#define TRACE_SEMWAIT_WAKE__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
