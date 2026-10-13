/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TIMEOUTSIG_TRACE_H_
#define _TIMEOUTSIG_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <timeoutsig_provider.h>
#define TRACE_TIMEOUTSIG_OPERATION__START(a0, a1) do { \
	if (TIMEOUTSIG_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		TIMEOUTSIG_OPERATION_START((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TIMEOUTSIG_OPERATION__DONE(a0, a1, a2, a3) do { \
	if (TIMEOUTSIG_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		TIMEOUTSIG_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TIMEOUTSIG_REAPER__START(a0) do { \
	if (TIMEOUTSIG_REAPER_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		TIMEOUTSIG_REAPER_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TIMEOUTSIG_REAPER__DONE(a0, a1, a2) do { \
	if (TIMEOUTSIG_REAPER_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		TIMEOUTSIG_REAPER_DONE((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_TIMEOUTSIG_OPERATION__START(a0, a1) do { } while (0)
#define TRACE_TIMEOUTSIG_OPERATION__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_TIMEOUTSIG_REAPER__START(a0) do { } while (0)
#define TRACE_TIMEOUTSIG_REAPER__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
