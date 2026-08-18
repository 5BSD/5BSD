/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_fileargs service.
 *
 * Provider: cap_fileargs
 *
 * Usage:
 *   dtrace -n 'cap_fileargs*:::'       -- trace all probes
 *   dtrace -n 'cap_fileargs*:::allow'  -- per-path allow/deny decisions
 *   dtrace -n 'cap_fileargs*:::limit'  -- file-arg limit installation
 */

#ifndef CAP_FILEARGS_PROBES_H
#define CAP_FILEARGS_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#endif

/* Path-permission check result (allowed == 1 -> permitted). */
#define	CAP_FILEARGS_PROBE_ALLOW(path, operation, allowed)	\
	DTRACE_PROBE3(cap_fileargs, allow, path, operation, allowed)
/* A channel installed its file-arg limits. */
#define	CAP_FILEARGS_PROBE_LIMIT(operations, flags)	\
	DTRACE_PROBE2(cap_fileargs, limit, operations, flags)

#endif /* CAP_FILEARGS_PROBES_H */
