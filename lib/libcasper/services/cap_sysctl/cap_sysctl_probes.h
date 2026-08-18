/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_sysctl service.
 *
 * Provider: cap_sysctl
 *
 * Usage:
 *   dtrace -n 'cap_sysctl*:::'            -- trace all probes
 *   dtrace -n 'cap_sysctl*:::allow'      -- per-request allow/deny decisions
 *   dtrace -n 'cap_sysctl*:::stage-name' -- name-based builder updates
 */

#ifndef CAP_SYSCTL_PROBES_H
#define CAP_SYSCTL_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#endif

/* Name/MIB allow-list check result (allowed == 1 -> permitted). */
#define	CAP_SYSCTL_PROBE_ALLOW(name, allowed)	\
	DTRACE_PROBE2(cap_sysctl, allow, name, allowed)
/* A limit builder staged access to a named sysctl. */
#define	CAP_SYSCTL_PROBE_STAGE_NAME(name, operation)	\
	DTRACE_PROBE2(cap_sysctl, stage__name, name, operation)
/* A limit builder staged access to a sysctl MIB. */
#define	CAP_SYSCTL_PROBE_STAGE_MIB(miblen, operation)	\
	DTRACE_PROBE2(cap_sysctl, stage__mib, miblen, operation)

#endif /* CAP_SYSCTL_PROBES_H */
