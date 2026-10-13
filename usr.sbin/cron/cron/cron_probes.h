/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef CRON_PROBES_H
#define CRON_PROBES_H

#include <errno.h>
#include <stdint.h>

#ifdef WITH_DTRACE
#include <cron_provider.h>

#define CRON_PROBE_JOB_RUN(user, cmd) do { \
	if (CRON_JOB_RUN_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_JOB_RUN(__DECONST(char *, user), __DECONST(char *, cmd)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define CRON_PROBE_JOB_DONE(user, status) do { \
	if (CRON_JOB_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CRON_JOB_DONE(__DECONST(char *, user), (int)(status)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define CRON_PROBE_JOB_RUN(user, cmd) do { } while (0)
#define CRON_PROBE_JOB_DONE(user, status) do { } while (0)
#endif

#endif /* CRON_PROBES_H */
