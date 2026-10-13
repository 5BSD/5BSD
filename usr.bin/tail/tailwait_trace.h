/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TAILWAIT_TRACE_H_
#define _TAILWAIT_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <tailwait_provider.h>
#define TRACE_TAILWAIT_OPERATION__START(a0, a1) do { \
	if (TAILWAIT_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		TAILWAIT_OPERATION_START((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TAILWAIT_OPERATION__DONE(a0, a1, a2, a3) do { \
	if (TAILWAIT_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		TAILWAIT_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_TAILWAIT_OPERATION__START(a0, a1) do { } while (0)
#define TRACE_TAILWAIT_OPERATION__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
