/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINKOP_TRACE_H_
#define _LINKOP_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <linkop_provider.h>
#define TRACE_LINKOP_OPERATION__START(a0) do { \
	if (LINKOP_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		LINKOP_OPERATION_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_LINKOP_OPERATION__DONE(a0, a1, a2) do { \
	if (LINKOP_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		LINKOP_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_LINKOP_OPERATION__START(a0) do { } while (0)
#define TRACE_LINKOP_OPERATION__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
