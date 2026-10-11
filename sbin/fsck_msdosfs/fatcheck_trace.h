/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FATCHECK_TRACE_H_
#define _FATCHECK_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <fatcheck_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_fatcheck_provider __attribute__((visibility("hidden")));
static const void * const fatcheck_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_fatcheck_provider;
#define TRACE_FATCHECK_CHECK__START(a0) do { \
	if (FATCHECK_CHECK_START_ENABLED()) \
		FATCHECK_CHECK_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_FATCHECK_CHECK__DONE(a0, a1) do { \
	if (FATCHECK_CHECK_DONE_ENABLED()) \
		FATCHECK_CHECK_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_FATCHECK_CHECK__START(a0) do { } while (0)
#define TRACE_FATCHECK_CHECK__DONE(a0, a1) do { } while (0)
#endif
#endif
