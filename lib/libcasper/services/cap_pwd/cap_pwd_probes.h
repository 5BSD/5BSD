/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_pwd service.
 *
 * Provider: cap_pwd
 *
 * Usage:
 *   dtrace -n 'cap_pwd*:::'            -- trace all probes
 *   dtrace -n 'cap_pwd*:::allow'      -- per-command allow/deny decisions
 *   dtrace -n 'cap_pwd*:::limit-cmds' -- command-set narrowing
 */

#ifndef CAP_PWD_PROBES_H
#define CAP_PWD_PROBES_H

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
#define	CAP_PWD_PROBE_ALLOW(cmd, allowed)	\
	DTRACE_PROBE2(cap_pwd, allow, cmd, allowed)
/* A channel narrowed the allowed-command set to this command. */
#define	CAP_PWD_PROBE_LIMIT_CMDS(cmd)	\
	DTRACE_PROBE1(cap_pwd, limit__cmds, cmd)
/* A channel narrowed the allowed-field set to this field. */
#define	CAP_PWD_PROBE_LIMIT_FIELDS(field)	\
	DTRACE_PROBE1(cap_pwd, limit__fields, field)
/* A channel narrowed the allowed-user set to this user name. */
#define	CAP_PWD_PROBE_LIMIT_USERS(user)	\
	DTRACE_PROBE1(cap_pwd, limit__users, user)
/* Final result of a dispatched command (error == 0 -> allowed). */
#define	CAP_PWD_PROBE_COMMAND(cmd, error)	\
	DTRACE_PROBE2(cap_pwd, command, cmd, error)

#endif /* CAP_PWD_PROBES_H */
