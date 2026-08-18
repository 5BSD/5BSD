/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for the Casper cap_net service.
 *
 * Provider: cap_net
 *
 * Usage:
 *   dtrace -n 'cap_net*:::'           -- trace all probes
 *   dtrace -n 'cap_net*:::allow-host' -- host/service allow/deny decisions
 *   dtrace -n 'cap_net*:::stage-host' -- host/service builder updates
 */

#ifndef CAP_NET_PROBES_H
#define CAP_NET_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE1(provider, name, arg1) \
	do { if (0) { (void)(arg1); } } while (0)
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#endif

/* Mode-permission check result (allowed == 1 -> permitted). */
#define	CAP_NET_PROBE_ALLOW_MODE(mode, allowed)	\
	DTRACE_PROBE2(cap_net, allow__mode, mode, allowed)
/* Address-family check result (allowed == 1 -> permitted). */
#define	CAP_NET_PROBE_ALLOW_FAMILY(family, allowed)	\
	DTRACE_PROBE2(cap_net, allow__family, family, allowed)
/* Host/service allow-list check result (allowed == 1 -> permitted). */
#define	CAP_NET_PROBE_ALLOW_HOST(host, serv, allowed)	\
	DTRACE_PROBE3(cap_net, allow__host, host, serv, allowed)
/* Raw sockaddr allow-list check result (allowed == 1 -> permitted). */
#define	CAP_NET_PROBE_ALLOW_ADDR(saddrsize, allowed)	\
	DTRACE_PROBE2(cap_net, allow__addr, saddrsize, allowed)
/* A limit builder staged the allowed capability mode. */
#define	CAP_NET_PROBE_STAGE_MODE(mode)	\
	DTRACE_PROBE1(cap_net, stage__mode, mode)
/* A limit builder staged an allowed host/service entry. */
#define	CAP_NET_PROBE_STAGE_HOST(host, serv)	\
	DTRACE_PROBE2(cap_net, stage__host, host, serv)

#endif /* CAP_NET_PROBES_H */
