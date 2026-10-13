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
 * These counters are host aggregates, not per-VNET statistics.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>

int	pfsync_sysctl_pfsyncstat(void *, size_t *, void *);

SYSCTL_DECL(_net);

/*
 * Vendor counters are allocated once by pf_fbsd_load (SI_ORDER_SECOND)
 * and outlive all VNETs.  PF rejects module unload.  Static sysctl nodes
 * may already be visible while module initialization is in progress;
 * publish readiness only after the counter allocation has completed.
 */
static u_int pf_stats_ready;

static void
pf_stats_init(void *arg __unused)
{
	atomic_store_rel_int(&pf_stats_ready, 1);
}
SYSINIT(pf_stats, SI_SUB_PROTO_FIREWALL, SI_ORDER_LAST, pf_stats_init, NULL);

static int
pf_sysctl_pfsync_stats(SYSCTL_HANDLER_ARGS)
{
	struct pfsyncstats st;
	size_t len = sizeof(st);
	int error;

	if (req->newptr != NULL)
		return (EPERM);
	if (atomic_load_acq_int(&pf_stats_ready) == 0)
		return (EAGAIN);
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
	if (atomic_load_acq_int(&pf_stats_ready) == 0)
		return (EAGAIN);
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
    "Host aggregate pfsync statistics (struct pfsyncstats, net/if_pfsync.h)");

static SYSCTL_NODE(_net, OID_AUTO, pflow, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "pflow(4)");
SYSCTL_PROC(_net_pflow, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    pf_sysctl_pflow_stats, "S,pflowstats",
    "Host aggregate pflow statistics (struct pflowstats, net/if_pflow.h)");
