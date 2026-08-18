/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper userland capability broker.
 *
 * Provider: casper
 *
 * Usage:
 *   dtrace -n 'casper*:::'              -- trace all probes
 *   dtrace -n 'casper*:::cmd-return'   -- every request's allow/deny outcome
 *   dtrace -n 'casper*:::service-open' -- capability-channel opens
 */

#ifndef CASPER_PROBES_H
#define CASPER_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#endif

/* A request arrived on a service connection. */
#define	CASPER_PROBE_CMD_DISPATCH(service, cmd)	\
	DTRACE_PROBE2(casper, cmd__dispatch, service, cmd)
/* A connection narrowed its limits. */
#define	CASPER_PROBE_LIMIT_SET(service, error)	\
	DTRACE_PROBE2(casper, limit__set, service, error)
/* Final allow/deny decision for a request (error == 0 -> allowed). */
#define	CASPER_PROBE_CMD_RETURN(service, cmd, error)	\
	DTRACE_PROBE3(casper, cmd__return, service, cmd, error)
/* A process opened a capability channel to a service. */
#define	CASPER_PROBE_SERVICE_OPEN(service, error)	\
	DTRACE_PROBE2(casper, service__open, service, error)

#endif /* CASPER_PROBES_H */
