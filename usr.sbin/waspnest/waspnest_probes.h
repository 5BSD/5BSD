/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for waspnest(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so waspnest builds identically with and without
 * DTrace.  Mirrors the logd(8) provider convention.
 */
#ifdef WITH_DTRACE
#include "waspnest_provider.h"
#define	WASPNEST_PROBE_VSOCK_LIST(client, port_base, port_limit, result) \
	WASPNEST_VSOCK_LIST(__DECONST(char *, client), port_base, port_limit, \
	    result)
#define	WASPNEST_PROBE_RECLAIM(label, reclaimed, reason) \
	WASPNEST_RECLAIM(__DECONST(char *, label), reclaimed, \
	    __DECONST(char *, reason))
#else
#define	WASPNEST_PROBE_VSOCK_LIST(client, port_base, port_limit, result) \
	do { (void)(client); (void)(port_base); (void)(port_limit); \
	    (void)(result); } while (0)
#define	WASPNEST_PROBE_RECLAIM(label, reclaimed, reason) \
	do { (void)(label); (void)(reclaimed); (void)(reason); } while (0)
#endif
