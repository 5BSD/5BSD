/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FILEFLAGS_TRACE_H_
#define _FILEFLAGS_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <fileflags_provider.h>
#define TRACE_FILEFLAGS_OPERATION__START(a0) do { \
	if (FILEFLAGS_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		FILEFLAGS_OPERATION_START((uint64_t)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_FILEFLAGS_OPERATION__DONE(a0, a1, a2) do { \
	if (FILEFLAGS_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		FILEFLAGS_OPERATION_DONE((uint64_t)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_FILEFLAGS_OPERATION__START(a0) do { } while (0)
#define TRACE_FILEFLAGS_OPERATION__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
