/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * sysctl(9) nodes for the statistics OpenBSD exports through its sysctl
 * MIBs (net.inet.pfsync.stats, net.pflow.stats).  5BSD names them
 * net.pfsync.stats and net.pflow.stats; netstat -s -p pfsync|pflow reads
 * them.  The values are struct pfsyncstats (<net/if_pfsync.h>) and struct
 * pflowstats (<net/if_pflow.h>), filled by the vendor handlers.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>

int	pfsync_sysctl_pfsyncstat(void *, size_t *, void *);

SYSCTL_DECL(_net);

static int
pf_sysctl_pfsync_stats(SYSCTL_HANDLER_ARGS)
{
	struct pfsyncstats st;
	size_t len = sizeof(st);
	int error;

	if (req->newptr != NULL)
		return (EPERM);
	error = pfsync_sysctl_pfsyncstat(&st, &len, NULL);
	if (error != 0)
		return (error);
	return (SYSCTL_OUT(req, &st, sizeof(st)));
}

static int
pf_sysctl_pflow_stats(SYSCTL_HANDLER_ARGS)
{
	struct pflowstats st;
	size_t len = sizeof(st);
	int mib[1] = { NET_PFLOW_STATS };
	int error;

	if (req->newptr != NULL)
		return (EPERM);
	error = pflow_sysctl(mib, 1, &st, &len, NULL, 0);
	if (error != 0)
		return (error);
	return (SYSCTL_OUT(req, &st, sizeof(st)));
}

static SYSCTL_NODE(_net, OID_AUTO, pfsync, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "pfsync(4)");
SYSCTL_PROC(_net_pfsync, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    pf_sysctl_pfsync_stats, "S,pfsyncstats",
    "pfsync statistics (struct pfsyncstats, net/if_pfsync.h)");

static SYSCTL_NODE(_net, OID_AUTO, pflow, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "pflow(4)");
SYSCTL_PROC(_net_pflow, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    pf_sysctl_pflow_stats, "S,pflowstats",
    "pflow statistics (struct pflowstats, net/if_pflow.h)");
