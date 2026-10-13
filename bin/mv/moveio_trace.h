/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _MOVEIO_TRACE_H_
#define _MOVEIO_TRACE_H_

#include <errno.h>
#include <stdint.h>

#ifdef WITH_COVERAGE_DTRACE
#include <moveio_provider.h>

#define TRACE_MOVEIO_RENAME__START() do { \
	if (MOVEIO_RENAME_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_RENAME_START(); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_MOVEIO_RENAME__DONE(a0, a1) do { \
	if (MOVEIO_RENAME_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_RENAME_DONE((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_MOVEIO_FALLBACK__START(a0) do { \
	if (MOVEIO_FALLBACK_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_FALLBACK_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_MOVEIO_FALLBACK__DONE(a0) do { \
	if (MOVEIO_FALLBACK_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_FALLBACK_DONE((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_MOVEIO_CHILD__START(a0) do { \
	if (MOVEIO_CHILD_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_CHILD_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_MOVEIO_CHILD__DONE(a0, a1, a2, a3) do { \
	if (MOVEIO_CHILD_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		MOVEIO_CHILD_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_MOVEIO_RENAME__START() do { } while (0)
#define TRACE_MOVEIO_RENAME__DONE(a0, a1) do { } while (0)
#define TRACE_MOVEIO_FALLBACK__START(a0) do { } while (0)
#define TRACE_MOVEIO_FALLBACK__DONE(a0) do { } while (0)
#define TRACE_MOVEIO_CHILD__START(a0) do { } while (0)
#define TRACE_MOVEIO_CHILD__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
