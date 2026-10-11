/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _NAMERES_TRACE_H_
#define _NAMERES_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <nameres_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_nameres_provider __attribute__((visibility("hidden")));
static const void * const nameres_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_nameres_provider;
#define TRACE_NAMERES_QUERY__START(a0, a1, a2) do { \
	if (NAMERES_QUERY_START_ENABLED()) \
		NAMERES_QUERY_START((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_NAMERES_QUERY__DONE(a0, a1, a2) do { \
	if (NAMERES_QUERY_DONE_ENABLED()) \
		NAMERES_QUERY_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_NAMERES_SERVER__START(a0, a1, a2) do { \
	if (NAMERES_SERVER_START_ENABLED()) \
		NAMERES_SERVER_START((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_NAMERES_SERVER__DONE(a0, a1, a2, a3) do { \
	if (NAMERES_SERVER_DONE_ENABLED()) \
		NAMERES_SERVER_DONE((uintptr_t)(a0), (int)(a1), (int)(a2), (int)(a3)); \
} while (0)
#define TRACE_NAMERES_DISPATCH__START(a0, a1) do { \
	if (NAMERES_DISPATCH_START_ENABLED()) \
		NAMERES_DISPATCH_START((uintptr_t)(a0), (uintptr_t)(a1)); \
} while (0)
#define TRACE_NAMERES_DISPATCH__DONE(a0, a1) do { \
	if (NAMERES_DISPATCH_DONE_ENABLED()) \
		NAMERES_DISPATCH_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_NAMERES_BACKEND__START(a0, a1) do { \
	if (NAMERES_BACKEND_START_ENABLED()) \
		NAMERES_BACKEND_START((uintptr_t)(a0), (uintptr_t)(a1)); \
} while (0)
#define TRACE_NAMERES_BACKEND__DONE(a0, a1, a2) do { \
	if (NAMERES_BACKEND_DONE_ENABLED()) \
		NAMERES_BACKEND_DONE((uintptr_t)(a0), (uintptr_t)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_NAMERES_QUERY__START(a0, a1, a2) do { } while (0)
#define TRACE_NAMERES_QUERY__DONE(a0, a1, a2) do { } while (0)
#define TRACE_NAMERES_SERVER__START(a0, a1, a2) do { } while (0)
#define TRACE_NAMERES_SERVER__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_NAMERES_DISPATCH__START(a0, a1) do { } while (0)
#define TRACE_NAMERES_DISPATCH__DONE(a0, a1) do { } while (0)
#define TRACE_NAMERES_BACKEND__START(a0, a1) do { } while (0)
#define TRACE_NAMERES_BACKEND__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
