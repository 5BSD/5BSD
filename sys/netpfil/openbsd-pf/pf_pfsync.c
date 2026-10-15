/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * pfsync(4) on the 5BSD stack: the carp(4) demotion OpenBSD pfsync
 * applies to the "carp" interface group.
 *
 * carp (marked "5BSD: carp" in if_pfsync.c): OpenBSD demotes the carp
 * group by 32 while a bulk update is outstanding and by 1 while the
 * syncdev link is down.  carp(4) on 5BSD has one demotion counter per
 * vnet (net.inet.carp.demotion) and no carp group, so the OpenBSD counts
 * are summed here and, while the sum is positive, the counter carries
 * net.pfsync.carp_demotion_factor (default 240, as FreeBSD pfsync did).
 * What was applied is remembered, so changing the factor never leaves
 * a residue.  Without carp(4) nothing is applied; carp(4) loaded later
 * sees the demotion from pfsync's next adjustment on.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <netinet/ip_carp.h>	/* the shadow header: carp_group_demote_adj */

SYSCTL_DECL(_net_pfsync);

/* ------------------------------------------------------------------ */
/* carp(4) demotion                                                     */
/* ------------------------------------------------------------------ */

/* sys/netinet/ip_carp.h; the shadow header hides the 5BSD one here. */
extern void	(*carp_demote_adj_p)(int, char *);

#define	PFSYNC_CARP_DEMOTE_DEFAULT	240	/* CARP_MAXSKEW */
#define	PFSYNC_CARP_DEMOTE_MAX		255

VNET_DEFINE_STATIC(int, pfsync_carp_adj) = PFSYNC_CARP_DEMOTE_DEFAULT;
VNET_DEFINE_STATIC(int, pfsync_carp_count);	/* sum of OpenBSD demotions */
VNET_DEFINE_STATIC(int, pfsync_carp_applied);	/* in net.inet.carp.demotion */
#define	V_pfsync_carp_adj	VNET(pfsync_carp_adj)
#define	V_pfsync_carp_count	VNET(pfsync_carp_count)
#define	V_pfsync_carp_applied	VNET(pfsync_carp_applied)

static struct mtx pfsync_carp_mtx;
MTX_SYSINIT(pfsync_carp_mtx, &pfsync_carp_mtx, "pfsync carp", MTX_DEF);

/* Bring net.inet.carp.demotion in line with the current count. */
static void
pfsync_carp_apply(char *reason)
{
	void (*adj)(int, char *);
	int want;

	mtx_assert(&pfsync_carp_mtx, MA_OWNED);

	want = V_pfsync_carp_count > 0 ? V_pfsync_carp_adj : 0;
	adj = atomic_load_ptr(&carp_demote_adj_p);
	if (adj == NULL) {
		/* carp(4) is not loaded: its counter does not exist. */
		V_pfsync_carp_applied = 0;
		return;
	}
	if (want != V_pfsync_carp_applied) {
		(*adj)(want - V_pfsync_carp_applied, reason);
		V_pfsync_carp_applied = want;
	}
}

void
carp_group_demote_adj(struct ifnet *ifp, int adj, char *reason)
{
	CURVNET_SET(ifp->if_vnet);
	mtx_lock(&pfsync_carp_mtx);
	V_pfsync_carp_count += adj;
	KASSERT(V_pfsync_carp_count >= 0,
	    ("%s: %s: demotion count %d after %d (%s)", __func__,
	    ifp->if_xname, V_pfsync_carp_count, adj, reason));
	if (V_pfsync_carp_count < 0)
		V_pfsync_carp_count = 0;
	pfsync_carp_apply(reason);
	mtx_unlock(&pfsync_carp_mtx);
	CURVNET_RESTORE();
}

static int
pfsync_carp_adj_sysctl(SYSCTL_HANDLER_ARGS)
{
	int error, factor;

	factor = V_pfsync_carp_adj;
	error = sysctl_handle_int(oidp, &factor, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (factor < 0 || factor > PFSYNC_CARP_DEMOTE_MAX)
		return (EINVAL);

	mtx_lock(&pfsync_carp_mtx);
	V_pfsync_carp_adj = factor;
	pfsync_carp_apply("pfsync demotion factor");
	mtx_unlock(&pfsync_carp_mtx);
	return (0);
}
SYSCTL_PROC(_net_pfsync, OID_AUTO, carp_demotion_factor,
    CTLFLAG_VNET | CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    pfsync_carp_adj_sysctl, "I",
    "pfsync's CARP demotion factor adjustment");
