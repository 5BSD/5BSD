/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _ATTRTOOL_TRACE_H_
#define _ATTRTOOL_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <attrtool_provider.h>
#define TRACE_ATTRTOOL_DELETE__START(a0, a1) do { \
	if (ATTRTOOL_DELETE_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_DELETE_START((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_DELETE__DONE(a0, a1, a2, a3) do { \
	if (ATTRTOOL_DELETE_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_DELETE_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_SET__START(a0, a1, a2, a3) do { \
	if (ATTRTOOL_SET_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_SET_START((int)(a0), (int)(a1), (size_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_SET__DONE(a0, a1, a2, a3, a4, a5) do { \
	if (ATTRTOOL_SET_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_SET_DONE((int)(a0), (int)(a1), (size_t)(a2), (int)(a3), (int64_t)(a4), (int)(a5)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_LIST__START(a0, a1, a2, a3) do { \
	if (ATTRTOOL_LIST_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_LIST_START((int)(a0), (int)(a1), (size_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_LIST__DONE(a0, a1, a2, a3, a4, a5) do { \
	if (ATTRTOOL_LIST_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_LIST_DONE((int)(a0), (int)(a1), (size_t)(a2), (int)(a3), (int64_t)(a4), (int)(a5)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_GET__START(a0, a1, a2, a3) do { \
	if (ATTRTOOL_GET_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_GET_START((int)(a0), (int)(a1), (size_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_ATTRTOOL_GET__DONE(a0, a1, a2, a3, a4, a5) do { \
	if (ATTRTOOL_GET_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		ATTRTOOL_GET_DONE((int)(a0), (int)(a1), (size_t)(a2), (int)(a3), (int64_t)(a4), (int)(a5)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_ATTRTOOL_DELETE__START(a0, a1) do { } while (0)
#define TRACE_ATTRTOOL_DELETE__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_ATTRTOOL_SET__START(a0, a1, a2, a3) do { } while (0)
#define TRACE_ATTRTOOL_SET__DONE(a0, a1, a2, a3, a4, a5) do { } while (0)
#define TRACE_ATTRTOOL_LIST__START(a0, a1, a2, a3) do { } while (0)
#define TRACE_ATTRTOOL_LIST__DONE(a0, a1, a2, a3, a4, a5) do { } while (0)
#define TRACE_ATTRTOOL_GET__START(a0, a1, a2, a3) do { } while (0)
#define TRACE_ATTRTOOL_GET__DONE(a0, a1, a2, a3, a4, a5) do { } while (0)
#endif
#endif
