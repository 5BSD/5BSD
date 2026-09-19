/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for warden(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so warden builds identically with and without
 * DTrace.  Mirrors the bsdextension(8)/logd(8) provider convention.
 */
#ifndef WARDEN_PROBES_H
#define WARDEN_PROBES_H

#include <sys/cdefs.h>

#ifdef WITH_DTRACE
#include "warden_provider.h"
#define	WARDEN_PROBE_ENTER(client, jid, result) \
	WARDEN_ENTER(__DECONST(char *, client), jid, result)
#define	WARDEN_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	WARDEN_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#else
#define	WARDEN_PROBE_ENTER(client, jid, result) \
	do { (void)(client); (void)(jid); (void)(result); } while (0)
#define	WARDEN_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#endif

#endif /* WARDEN_PROBES_H */
