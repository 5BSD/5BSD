/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DAEMONWAIT_TRACE_H_
#define _DAEMONWAIT_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <daemonwait_provider.h>
#define TRACE_DAEMONWAIT_OPERATION__START(a0, a1) do { \
	if (DAEMONWAIT_OPERATION_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		DAEMONWAIT_OPERATION_START((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DAEMONWAIT_OPERATION__DONE(a0, a1, a2, a3) do { \
	if (DAEMONWAIT_OPERATION_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DAEMONWAIT_OPERATION_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_DAEMONWAIT_OPERATION__START(a0, a1) do { } while (0)
#define TRACE_DAEMONWAIT_OPERATION__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
