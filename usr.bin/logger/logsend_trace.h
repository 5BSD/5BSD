/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOGSEND_TRACE_H_
#define _LOGSEND_TRACE_H_
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#ifdef WITH_COVERAGE_DTRACE
#include <logsend_provider.h>
#define TRACE_LOGSEND_OPERATION__START(a0) do { \
	if (LOGSEND_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		LOGSEND_OPERATION_START((size_t)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_LOGSEND_OPERATION__DONE(a0, a1, a2) do { \
	if (LOGSEND_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		LOGSEND_OPERATION_DONE((size_t)(a0), (int64_t)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_LOGSEND_LOCAL__START(a0) do { \
	if (LOGSEND_LOCAL_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		LOGSEND_LOCAL_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_LOGSEND_LOCAL__DONE(a0) do { \
	if (LOGSEND_LOCAL_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		LOGSEND_LOCAL_DONE((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_LOGSEND_OPERATION__START(a0) do { } while (0)
#define TRACE_LOGSEND_OPERATION__DONE(a0, a1, a2) do { } while (0)
#define TRACE_LOGSEND_LOCAL__START(a0) do { } while (0)
#define TRACE_LOGSEND_LOCAL__DONE(a0) do { } while (0)
#endif
#endif
