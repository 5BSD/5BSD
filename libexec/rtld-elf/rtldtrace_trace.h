/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _RTLDTRACE_TRACE_H_
#define _RTLDTRACE_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <rtldtrace_provider.h>
#define TRACE_RTLDTRACE_LOAD__START(a0, a1) do { \
	if (RTLDTRACE_LOAD_START_ENABLED()) \
		RTLDTRACE_LOAD_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_RTLDTRACE_LOAD__DONE(a0, a1) do { \
	if (RTLDTRACE_LOAD_DONE_ENABLED()) \
		RTLDTRACE_LOAD_DONE((uintptr_t)(a0), (uintptr_t)(a1)); \
} while (0)
#define TRACE_RTLDTRACE_RELOCATE__START(a0) do { \
	if (RTLDTRACE_RELOCATE_START_ENABLED()) \
		RTLDTRACE_RELOCATE_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_RTLDTRACE_RELOCATE__DONE(a0, a1) do { \
	if (RTLDTRACE_RELOCATE_DONE_ENABLED()) \
		RTLDTRACE_RELOCATE_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_RTLDTRACE_INIT__START(a0) do { \
	if (RTLDTRACE_INIT_START_ENABLED()) \
		RTLDTRACE_INIT_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_RTLDTRACE_INIT__DONE(a0) do { \
	if (RTLDTRACE_INIT_DONE_ENABLED()) \
		RTLDTRACE_INIT_DONE((uintptr_t)(a0)); \
} while (0)
#define TRACE_RTLDTRACE_DLOPEN__START(a0, a1, a2) do { \
	if (RTLDTRACE_DLOPEN_START_ENABLED()) \
		RTLDTRACE_DLOPEN_START((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_RTLDTRACE_DLOPEN__DONE(a0, a1, a2, a3) do { \
	if (RTLDTRACE_DLOPEN_DONE_ENABLED()) \
		RTLDTRACE_DLOPEN_DONE((uintptr_t)(a0), (int)(a1), (int)(a2), (uintptr_t)(a3)); \
} while (0)
#define TRACE_RTLDTRACE_DLCLOSE__START(a0) do { \
	if (RTLDTRACE_DLCLOSE_START_ENABLED()) \
		RTLDTRACE_DLCLOSE_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_RTLDTRACE_DLCLOSE__DONE(a0, a1) do { \
	if (RTLDTRACE_DLCLOSE_DONE_ENABLED()) \
		RTLDTRACE_DLCLOSE_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_RTLDTRACE_DLCLOSE__DONE(a0, a1) do { } while (0)
#define TRACE_RTLDTRACE_DLCLOSE__START(a0) do { } while (0)
#define TRACE_RTLDTRACE_DLOPEN__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_RTLDTRACE_DLOPEN__START(a0, a1, a2) do { } while (0)
#define TRACE_RTLDTRACE_LOAD__START(a0, a1) do { } while (0)
#define TRACE_RTLDTRACE_LOAD__DONE(a0, a1) do { } while (0)
#define TRACE_RTLDTRACE_RELOCATE__START(a0) do { } while (0)
#define TRACE_RTLDTRACE_RELOCATE__DONE(a0, a1) do { } while (0)
#define TRACE_RTLDTRACE_INIT__START(a0) do { } while (0)
#define TRACE_RTLDTRACE_INIT__DONE(a0) do { } while (0)
#endif
#endif
