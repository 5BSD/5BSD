/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FFSCHECK_TRACE_H_
#define _FFSCHECK_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <ffscheck_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_ffscheck_provider __attribute__((visibility("hidden")));
static const void * const ffscheck_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_ffscheck_provider;
#define TRACE_FFSCHECK_PHASE__START(a0) do { \
	if (FFSCHECK_PHASE_START_ENABLED()) \
		FFSCHECK_PHASE_START((int)(a0)); \
} while (0)
#define TRACE_FFSCHECK_PHASE__DONE(a0) do { \
	if (FFSCHECK_PHASE_DONE_ENABLED()) \
		FFSCHECK_PHASE_DONE((int)(a0)); \
} while (0)
#else
#define TRACE_FFSCHECK_PHASE__START(a0) do { } while (0)
#define TRACE_FFSCHECK_PHASE__DONE(a0) do { } while (0)
#endif
#endif
