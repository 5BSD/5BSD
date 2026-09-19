/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for bsdnamespace(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so bsdnamespace builds identically with and without
 * DTrace.  Mirrors the bsdextension(8)/bsdlog(8) provider convention.
 */
#ifndef BSDNAMESPACE_PROBES_H
#define BSDNAMESPACE_PROBES_H

#include <sys/cdefs.h>

#ifdef WITH_DTRACE
#include "bsdnamespace_provider.h"
#define	BSDNAMESPACE_PROBE_ENTER(client, jid, result) \
	BSDNAMESPACE_ENTER(__DECONST(char *, client), jid, result)
#define	BSDNAMESPACE_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	BSDNAMESPACE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#else
#define	BSDNAMESPACE_PROBE_ENTER(client, jid, result) \
	do { (void)(client); (void)(jid); (void)(result); } while (0)
#define	BSDNAMESPACE_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#endif

#endif /* BSDNAMESPACE_PROBES_H */
