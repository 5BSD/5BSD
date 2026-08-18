/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef INETD_PROBES_H
#define INETD_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) do { if (0){(void)(a);(void)(b);} } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) do { if (0){(void)(a);(void)(b);(void)(c);} } while (0)
#endif

#define	INETD_PROBE_SPAWN(service,proto,user) \
	DTRACE_PROBE3(inetd, spawn, service, proto, user)
#define	INETD_PROBE_REFUSE(service,proto) \
	DTRACE_PROBE2(inetd, refuse, service, proto)

#endif /* INETD_PROBES_H */
