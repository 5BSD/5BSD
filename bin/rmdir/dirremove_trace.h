/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DIRREMOVE_TRACE_H_
#define _DIRREMOVE_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <dirremove_provider.h>
#define TRACE_DIRREMOVE_OPERATION__START(a0) do { \
	if (DIRREMOVE_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		DIRREMOVE_OPERATION_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DIRREMOVE_OPERATION__DONE(a0, a1, a2) do { \
	if (DIRREMOVE_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DIRREMOVE_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_DIRREMOVE_OPERATION__START(a0) do { } while (0)
#define TRACE_DIRREMOVE_OPERATION__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
