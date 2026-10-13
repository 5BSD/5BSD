/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRON_TRACE_H_
#define _CRON_TRACE_H_

#include <errno.h>
#include <stdint.h>

#ifdef WITH_DTRACE
#include <cron_provider.h>

#define TRACE_CRON_JOB__LAUNCH(a0, a1, a2) do { \
	if (CRON_JOB_LAUNCH_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_JOB_LAUNCH((int)(a0), (uint32_t)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CRON_JOB__EXEC__ERROR(a0) do { \
	if (CRON_JOB_EXEC_ERROR_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_JOB_EXEC_ERROR((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CRON_CHILD__WAIT__START(a0) do { \
	if (CRON_CHILD_WAIT_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_CHILD_WAIT_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CRON_CHILD__WAIT__DONE(a0, a1, a2, a3) do { \
	if (CRON_CHILD_WAIT_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_CHILD_WAIT_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_CRON_JOB__LAUNCH(a0, a1, a2) do { } while (0)
#define TRACE_CRON_JOB__EXEC__ERROR(a0) do { } while (0)
#define TRACE_CRON_CHILD__WAIT__START(a0) do { } while (0)
#define TRACE_CRON_CHILD__WAIT__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
