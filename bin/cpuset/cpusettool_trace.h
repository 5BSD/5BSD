/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CPUSETTOOL_TRACE_H_
#define _CPUSETTOOL_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <cpusettool_provider.h>
#define TRACE_CPUSETTOOL_OPERATION__START(a0, a1, a2) do { \
	if (CPUSETTOOL_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		CPUSETTOOL_OPERATION_START((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CPUSETTOOL_OPERATION__DONE(a0, a1, a2, a3, a4) do { \
	if (CPUSETTOOL_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CPUSETTOOL_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3), (int)(a4)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_CPUSETTOOL_OPERATION__START(a0, a1, a2) do { } while (0)
#define TRACE_CPUSETTOOL_OPERATION__DONE(a0, a1, a2, a3, a4) do { } while (0)
#endif
#endif
