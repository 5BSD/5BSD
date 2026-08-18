/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_grp service.
 *
 * Provider: cap_grp
 *
 * Usage:
 *   dtrace -n 'cap_grp*:::'            -- trace all probes
 *   dtrace -n 'cap_grp*:::allow'      -- per-command allow/deny decisions
 *   dtrace -n 'cap_grp*:::limit-cmds' -- command-set narrowing
 */

#ifndef CAP_GRP_PROBES_H
#define CAP_GRP_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE1(provider, name, arg1) \
	do { if (0) { (void)(arg1); } } while (0)
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#endif

/* Command-permission predicate result (allowed == 1 -> permitted). */
#define	CAP_GRP_PROBE_ALLOW(cmd, allowed)	\
	DTRACE_PROBE2(cap_grp, allow, cmd, allowed)
/* A channel narrowed the allowed-command set to this command. */
#define	CAP_GRP_PROBE_LIMIT_CMDS(cmd)	\
	DTRACE_PROBE1(cap_grp, limit__cmds, cmd)
/* A channel narrowed the allowed-field set to this field. */
#define	CAP_GRP_PROBE_LIMIT_FIELDS(field)	\
	DTRACE_PROBE1(cap_grp, limit__fields, field)
/* A channel narrowed the allowed-group set to this group name. */
#define	CAP_GRP_PROBE_LIMIT_GROUPS(group)	\
	DTRACE_PROBE1(cap_grp, limit__groups, group)
/* Final result of a dispatched command (error == 0 -> allowed). */
#define	CAP_GRP_PROBE_COMMAND(cmd, error)	\
	DTRACE_PROBE2(cap_grp, command, cmd, error)

#endif /* CAP_GRP_PROBES_H */
