/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for warden(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so warden builds identically with and without
 * DTrace.  Mirrors the waspnest(8)/tzfsd(8) provider convention.
 */
#ifndef _WARDEN_PROBES_H_
#define	_WARDEN_PROBES_H_

#ifdef WITH_DTRACE
#include "warden_provider.h"
#define	WARDEN_PROBE_RECLAIM(label, reclaimed, reason) \
	WARDEN_RECLAIM(__DECONST(char *, label), reclaimed, \
	    __DECONST(char *, reason))
#else
#define	WARDEN_PROBE_RECLAIM(label, reclaimed, reason) \
	do { (void)(label); (void)(reclaimed); (void)(reason); } while (0)
#endif

#endif /* _WARDEN_PROBES_H_ */
