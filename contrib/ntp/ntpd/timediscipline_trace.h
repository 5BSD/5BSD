/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TIMEDISCIPLINE_TRACE_H_
#define _TIMEDISCIPLINE_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <timediscipline_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_timediscipline_provider __attribute__((visibility("hidden")));
static const void * const timediscipline_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_timediscipline_provider;
#define TRACE_TIMEDISCIPLINE_SELECT__START(a0) do { \
	if (TIMEDISCIPLINE_SELECT_START_ENABLED()) \
		TIMEDISCIPLINE_SELECT_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_TIMEDISCIPLINE_SELECT__DONE(a0, a1) do { \
	if (TIMEDISCIPLINE_SELECT_DONE_ENABLED()) \
		TIMEDISCIPLINE_SELECT_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_TIMEDISCIPLINE_ADJUST__START(a0) do { \
	if (TIMEDISCIPLINE_ADJUST_START_ENABLED()) \
		TIMEDISCIPLINE_ADJUST_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_TIMEDISCIPLINE_ADJUST__DONE(a0, a1) do { \
	if (TIMEDISCIPLINE_ADJUST_DONE_ENABLED()) \
		TIMEDISCIPLINE_ADJUST_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_TIMEDISCIPLINE_SELECT__START(a0) do { } while (0)
#define TRACE_TIMEDISCIPLINE_SELECT__DONE(a0, a1) do { } while (0)
#define TRACE_TIMEDISCIPLINE_ADJUST__START(a0) do { } while (0)
#define TRACE_TIMEDISCIPLINE_ADJUST__DONE(a0, a1) do { } while (0)
#endif
#endif
