/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _RESIZEIO_TRACE_H_
#define _RESIZEIO_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <resizeio_provider.h>
#define TRACE_RESIZEIO_OPERATION__START(a0, a1, a2, a3) do { \
	if (RESIZEIO_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		RESIZEIO_OPERATION_START((int)(a0), (int)(a1), (int64_t)(a2), (int64_t)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_RESIZEIO_OPERATION__DONE(a0, a1, a2, a3) do { \
	if (RESIZEIO_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		RESIZEIO_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_RESIZEIO_OPERATION__START(a0, a1, a2, a3) do { } while (0)
#define TRACE_RESIZEIO_OPERATION__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
