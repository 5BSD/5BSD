/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _EXPORTS_TRACE_H_
#define _EXPORTS_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <exports_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_exports_provider __attribute__((visibility("hidden")));
static const void * const exports_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_exports_provider;
#define TRACE_EXPORTS_RELOAD__START(a0) do { \
	if (EXPORTS_RELOAD_START_ENABLED()) \
		EXPORTS_RELOAD_START((int)(a0)); \
} while (0)
#define TRACE_EXPORTS_RELOAD__DONE(a0) do { \
	if (EXPORTS_RELOAD_DONE_ENABLED()) \
		EXPORTS_RELOAD_DONE((int)(a0)); \
} while (0)
#else
#define TRACE_EXPORTS_RELOAD__START(a0) do { } while (0)
#define TRACE_EXPORTS_RELOAD__DONE(a0) do { } while (0)
#endif
#endif
