/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probe shims for bsdextension(8).  Under -DWITH_DTRACE (MK_DTRACE builds) these
 * expand to the dtrace(1)-generated provider macros; otherwise they compile to
 * argument-consuming no-ops, so bsdextension builds identically with and without
 * DTrace.  Mirrors the bsdlog(8) provider convention.
 */
#ifdef WITH_DTRACE
#include "bsdextension_provider.h"
#define	BSDEXTENSION_PROBE_LIST(client, count, result) \
	BSDEXTENSION_LIST(__DECONST(char *, client), count, result)
#define	BSDEXTENSION_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	BSDEXTENSION_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#else
#define	BSDEXTENSION_PROBE_LIST(client, count, result) \
	do { (void)(client); (void)(count); (void)(result); } while (0)
#define	BSDEXTENSION_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#endif
