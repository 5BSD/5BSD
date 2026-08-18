/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for jail(8).  Provider: jail
 */

#ifndef JAIL_PROBES_H
#define JAIL_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#endif

#define	JAIL_PROBE_PARAM_SET(name, flags, jid)	\
	DTRACE_PROBE3(jail, param__set, name, flags, jid)

#endif /* JAIL_PROBES_H */
