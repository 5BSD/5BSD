/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_syslog service.
 *
 * Provider: cap_syslog
 *
 * Usage:
 *   dtrace -n 'cap_syslog*:::'        -- trace all probes
 *   dtrace -n 'cap_syslog*:::command' -- syslog operations dispatched
 */

#ifndef CAP_SYSLOG_PROBES_H
#define CAP_SYSLOG_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#endif

/* Final result of a dispatched command (error == 0 -> handled). */
#define	CAP_SYSLOG_PROBE_COMMAND(cmd, error)	\
	DTRACE_PROBE2(cap_syslog, command, cmd, error)

#endif /* CAP_SYSLOG_PROBES_H */
