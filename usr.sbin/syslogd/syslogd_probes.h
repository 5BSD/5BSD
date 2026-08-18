/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SYSLOGD_PROBES_H
#define SYSLOGD_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) do { if (0){(void)(a);(void)(b);} } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) do { if (0){(void)(a);(void)(b);(void)(c);} } while (0)
#endif

#define	SYSLOGD_PROBE_MSG_ACCEPT(hostname,len) \
	DTRACE_PROBE2(syslogd, msg__accept, hostname, len)

#endif /* SYSLOGD_PROBES_H */
