/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FLUSHALL_TRACE_H_
#define _FLUSHALL_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <flushall_provider.h>
#define TRACE_FLUSHALL_OPERATION__START(a0) do { \
	if (FLUSHALL_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		FLUSHALL_OPERATION_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_FLUSHALL_OPERATION__DONE(a0) do { \
	if (FLUSHALL_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		FLUSHALL_OPERATION_DONE((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_FLUSHALL_OPERATION__START(a0) do { } while (0)
#define TRACE_FLUSHALL_OPERATION__DONE(a0) do { } while (0)
#endif
#endif
