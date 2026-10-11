/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _MOUNTOP_TRACE_H_
#define _MOUNTOP_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <mountop_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_mountop_provider __attribute__((visibility("hidden")));
static const void * const mountop_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_mountop_provider;
#define TRACE_MOUNTOP_OPERATION__START(a0) do { \
	if (MOUNTOP_OPERATION_START_ENABLED()) \
		MOUNTOP_OPERATION_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_MOUNTOP_OPERATION__DONE(a0, a1) do { \
	if (MOUNTOP_OPERATION_DONE_ENABLED()) \
		MOUNTOP_OPERATION_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_MOUNTOP_OPERATION__START(a0) do { } while (0)
#define TRACE_MOUNTOP_OPERATION__DONE(a0, a1) do { } while (0)
#endif
#endif
