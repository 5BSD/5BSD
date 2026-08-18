/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_netdb service.
 *
 * Provider: cap_netdb
 *
 * Usage:
 *   dtrace -n 'cap_netdb*:::'        -- trace all probes
 *   dtrace -n 'cap_netdb*:::command' -- netdb operations dispatched
 */

#ifndef CAP_NETDB_PROBES_H
#define CAP_NETDB_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#endif

/* Final result of a dispatched command (error == 0 -> success). */
#define	CAP_NETDB_PROBE_COMMAND(cmd, error)	\
	DTRACE_PROBE2(cap_netdb, command, cmd, error)

#endif /* CAP_NETDB_PROBES_H */
