/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_dns service.
 *
 * Provider: cap_dns
 *
 * Usage:
 *   dtrace -n 'cap_dns*:::'           -- trace all probes
 *   dtrace -n 'cap_dns*:::allow-type' -- resolver-type allow/deny decisions
 *   dtrace -n 'cap_dns*:::limit-type' -- resolver-type limit narrowing
 */

#ifndef CAP_DNS_PROBES_H
#define CAP_DNS_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE1(provider, name, arg1) \
	do { if (0) { (void)(arg1); } } while (0)
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#endif

/* Resolver-type allow-list check result (allowed == 1 -> permitted). */
#define	CAP_DNS_PROBE_ALLOW_TYPE(type, allowed)	\
	DTRACE_PROBE2(cap_dns, allow__type, type, allowed)
/* Address-family allow-list check result (allowed == 1 -> permitted). */
#define	CAP_DNS_PROBE_ALLOW_FAMILY(family, allowed)	\
	DTRACE_PROBE2(cap_dns, allow__family, family, allowed)
/* A channel narrowed the allowed resolver-type set to this type. */
#define	CAP_DNS_PROBE_LIMIT_TYPE(type)	\
	DTRACE_PROBE1(cap_dns, limit__type, type)
/* A channel narrowed the allowed address-family set to this family. */
#define	CAP_DNS_PROBE_LIMIT_FAMILY(family)	\
	DTRACE_PROBE1(cap_dns, limit__family, family)
/* Final result of a dispatched command (error == 0 -> success). */
#define	CAP_DNS_PROBE_COMMAND(cmd, error)	\
	DTRACE_PROBE2(cap_dns, command, cmd, error)

#endif /* CAP_DNS_PROBES_H */
