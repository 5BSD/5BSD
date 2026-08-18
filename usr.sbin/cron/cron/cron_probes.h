/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef CRON_PROBES_H
#define CRON_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) do { if (0){(void)(a);(void)(b);} } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) do { if (0){(void)(a);(void)(b);(void)(c);} } while (0)
#endif

#define	CRON_PROBE_JOB_RUN(user,cmd) \
	DTRACE_PROBE2(cron, job__run, user, cmd)
#define	CRON_PROBE_JOB_DONE(user,status) \
	DTRACE_PROBE2(cron, job__done, user, status)

#endif /* CRON_PROBES_H */
