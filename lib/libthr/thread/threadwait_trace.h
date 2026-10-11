/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _THREADWAIT_TRACE_H_
#define _THREADWAIT_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <threadwait_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_threadwait_provider __attribute__((visibility("hidden")));
static const void * const threadwait_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_threadwait_provider;
#define TRACE_THREADWAIT_MUTEX__START(a0) do { \
	if (THREADWAIT_MUTEX_START_ENABLED()) \
		THREADWAIT_MUTEX_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_THREADWAIT_MUTEX__DONE(a0, a1) do { \
	if (THREADWAIT_MUTEX_DONE_ENABLED()) \
		THREADWAIT_MUTEX_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_CONDITION__START(a0, a1) do { \
	if (THREADWAIT_CONDITION_START_ENABLED()) \
		THREADWAIT_CONDITION_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_CONDITION__DONE(a0, a1) do { \
	if (THREADWAIT_CONDITION_DONE_ENABLED()) \
		THREADWAIT_CONDITION_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_JOIN__START(a0) do { \
	if (THREADWAIT_JOIN_START_ENABLED()) \
		THREADWAIT_JOIN_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_THREADWAIT_JOIN__DONE(a0, a1) do { \
	if (THREADWAIT_JOIN_DONE_ENABLED()) \
		THREADWAIT_JOIN_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_THREADWAIT_MUTEX__START(a0) do { } while (0)
#define TRACE_THREADWAIT_MUTEX__DONE(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_CONDITION__START(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_CONDITION__DONE(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_JOIN__START(a0) do { } while (0)
#define TRACE_THREADWAIT_JOIN__DONE(a0, a1) do { } while (0)
#endif
#endif
