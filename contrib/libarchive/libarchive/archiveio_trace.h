/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _ARCHIVEIO_TRACE_H_
#define _ARCHIVEIO_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <archiveio_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_archiveio_provider __attribute__((visibility("hidden")));
static const void * const archiveio_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_archiveio_provider;
#define TRACE_ARCHIVEIO_OPERATION__START(a0, a1, a2) do { \
	if (ARCHIVEIO_OPERATION_START_ENABLED()) \
		ARCHIVEIO_OPERATION_START((uintptr_t)(a0), (int)(a1), (uintptr_t)(a2)); \
} while (0)
#define TRACE_ARCHIVEIO_OPERATION__DONE(a0, a1, a2) do { \
	if (ARCHIVEIO_OPERATION_DONE_ENABLED()) \
		ARCHIVEIO_OPERATION_DONE((uintptr_t)(a0), (int)(a1), (int64_t)(a2)); \
} while (0)

#define TRACE_ARCHIVEIO_SKIP__START(a0) do { \
	if (ARCHIVEIO_SKIP_START_ENABLED()) \
		ARCHIVEIO_SKIP_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_ARCHIVEIO_SKIP__DONE(a0, a1) do { \
	if (ARCHIVEIO_SKIP_DONE_ENABLED()) \
		ARCHIVEIO_SKIP_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_ARCHIVEIO_SKIP__START(a0) do { } while (0)
#define TRACE_ARCHIVEIO_SKIP__DONE(a0, a1) do { } while (0)
#define TRACE_ARCHIVEIO_OPERATION__START(a0, a1, a2) do { } while (0)
#define TRACE_ARCHIVEIO_OPERATION__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
