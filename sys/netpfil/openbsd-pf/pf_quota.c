/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Per-VNET pf resource quotas.
 *
 * The pf pools (pool(9) on UMA, openbsd_compat.c) are shared by every
 * VNET.  OpenBSD enforces "set limit" as a pool hard limit counted over
 * all of a pool's items, so on 5BSD one VNET jail could fill a pool and
 * leave the host's pf failing closed.  Here each VNET counts its own
 * items of every pool that has a pf limit (pf_pool_limits[], PF_LIMIT_*)
 * and is refused at its own limit, before the shared pool is touched:
 *
 *   host (vnet0)   the pool's hard limit, the host's own "set limit"
 *                  (OpenBSD semantics: no hard limit until one is set)
 *   VNET jail      the host's limit scaled by net.pf.vnet_limit_pct,
 *                  whether or not the host has loaded it
 *
 * There is no global limit for these pools: a jail cannot use up the
 * host's budget, nor another jail's.  Every item carries a trailer naming
 * the accounting of the VNET that allocated it, so a free from a purge
 * task, a timeout, a packet freed in another context or after the VNET
 * is gone always credits the right VNET.  The accounting is reference
 * counted (one reference for the VNET, one per item) and outlives its
 * VNET until its last item is freed.  Charging and crediting are atomic
 * and never sleep or take a lock.
 *
 * A VNET jail still only restates limits (DIOCSETLIMIT with the host's
 * value or its own effective value); DIOCGETLIMIT reports its effective
 * limit, so pfctl -sm in a jail shows the quota, and pfctl -si its own
 * counts (pf_status is per VNET).  net.pf.vnet_count, net.pf.vnet_limit
 * and net.pf.vnet_refused show the current VNET's counts, effective
 * limits and refusals.
 */

#include "openbsd_compat.h"

#include <sys/jail.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

extern struct pool pfr_kentry_pl[PFRKE_MAX];

struct pf_quota {
	u_int		pq_ref;			/* the VNET + one per item */
	volatile u_int	pq_count[PF_LIMIT_MAX];	/* items out */
	u_long		pq_refused[PF_LIMIT_MAX];
};

VNET_DEFINE_STATIC(struct pf_quota *, pf_quota);
#define	V_pf_quota	VNET(pf_quota)

/* Host-only: a VNET jail's limit, in percent of the host's. */
static u_int pf_vnet_limit_pct = 100;

/* The PF_LIMIT_* index + 1 of a pool with a pf limit, or 0. */
int
pf_quota_pool_index(struct pool *pp)
{
	int i;

	for (i = 0; i < PF_LIMIT_MAX; i++)
		if (pf_pool_limits[i].pp == pp)
			return (i + 1);
	/* Every kind of table entry counts as a table entry. */
	for (i = 0; i < PFRKE_MAX; i++)
		if (pp == &pfr_kentry_pl[i])
			return (PF_LIMIT_TABLE_ENTRIES + 1);
	return (0);
}

static int
pf_quota_host(void)
{
	return (IS_DEFAULT_VNET(curvnet));
}

/* A VNET jail's effective limit: the host's limit scaled down. */
static u_int
pf_quota_jail_limit(int i)
{
	uint64_t l;

	l = pf_pool_limits[i].limit;
	l = l * atomic_load_int(&pf_vnet_limit_pct) / 100;
	if (l == 0 && pf_pool_limits[i].limit != 0)
		l = 1;
	return ((u_int)l);
}

/*
 * The current VNET's effective limit; UINT_MAX for none.  A limit of 0
 * means none, for the host's hard limit as for "set limit ... 0".
 */
static u_int
pf_quota_limit(int i)
{
	u_int l;

	if (!pf_quota_host())
		l = pf_quota_jail_limit(i);
	else
		l = ((struct pool *)pf_pool_limits[i].pp)->pr_hardlimit;
	return (l != 0 ? l : UINT_MAX);
}

/*
 * Charge one item of limit i to the current VNET.  On success *qp holds a
 * reference for the item (NULL: not accounted).  The host keeps OpenBSD's
 * rule that a PR_WAITOK caller without PR_LIMITFAIL is not refused; a VNET
 * jail is refused at its quota whatever the flags (every caller of these
 * pools handles failure).
 */
int
pf_quota_charge(int i, int flags, struct pf_quota **qp)
{
	struct pf_quota *q;
	u_int lim, n;
	int host;

	*qp = NULL;
#ifdef VIMAGE
	if (curvnet == NULL)
		return (0);
#endif
	host = pf_quota_host();
	if ((q = V_pf_quota) == NULL)
		return (host ? 0 : ENOMEM);
	lim = pf_quota_limit(i);
	n = atomic_fetchadd_int(&q->pq_count[i], 1);
	if (n >= lim && (!host || (flags & (PR_LIMITFAIL | PR_NOWAIT)))) {
		atomic_subtract_int(&q->pq_count[i], 1);
		atomic_add_long(&q->pq_refused[i], 1);
		return (ENOMEM);
	}
	refcount_acquire(&q->pq_ref);
	*qp = q;
	return (0);
}

/* Credit one item of limit i to the VNET that was charged for it. */
void
pf_quota_release(struct pf_quota *q, int i)
{
	if (q == NULL)
		return;
	atomic_subtract_int(&q->pq_count[i], 1);
	if (refcount_release(&q->pq_ref))
		free(q, M_PF);
}

/* Items of limit i the current VNET holds. */
u_int
pf_quota_count(int i)
{
	struct pf_quota *q;

#ifdef VIMAGE
	if (curvnet == NULL)
		return (0);
#endif
	q = V_pf_quota;
	return (q != NULL ? atomic_load_int(&q->pq_count[i]) : 0);
}

void	pf_quota_vnet_init(void);
void
pf_quota_vnet_init(void)
{
	struct pf_quota *q;

	q = malloc(sizeof(*q), M_PF, M_WAITOK | M_ZERO);
	refcount_init(&q->pq_ref, 1);
	V_pf_quota = q;
}

/* The VNET's pf is torn down: items still out keep the accounting. */
void	pf_quota_vnet_fini(void);
void
pf_quota_vnet_fini(void)
{
	struct pf_quota *q;
	int i;

	if ((q = V_pf_quota) == NULL)
		return;
	V_pf_quota = NULL;
	for (i = 0; i < PF_LIMIT_MAX; i++)
		if (atomic_load_int(&q->pq_count[i]) != 0)
			printf("pf: vnet %p torn down with %u items of limit "
			    "%d out\n", curvnet,
			    atomic_load_int(&q->pq_count[i]), i);
	if (refcount_release(&q->pq_ref))
		free(q, M_PF);
}

/*
 * DIOCGETLIMIT in a VNET jail: its effective limit.  DIOCSETLIMIT in a
 * VNET jail: it may restate the host's limit or its own effective limit
 * (pfctl loads every limit with each ruleset and restores the limits it
 * read on exit) but not change either.
 */
int	pf_quota_getlimit(struct pfioc_limit *);
int
pf_quota_getlimit(struct pfioc_limit *pl)
{
	if (pl->index < 0 || pl->index >= PF_LIMIT_MAX)
		return (EINVAL);
	PF_LOCK();
	pl->limit = pf_quota_jail_limit(pl->index);
	PF_UNLOCK();
	return (0);
}

int	pf_quota_setlimit(struct pfioc_limit *);
int
pf_quota_setlimit(struct pfioc_limit *pl)
{
	int error = 0;

	if (pl->index < 0 || pl->index >= PF_LIMIT_MAX)
		return (EINVAL);
	PF_LOCK();
	if (pl->limit != pf_pool_limits[pl->index].limit &&
	    pl->limit != pf_quota_jail_limit(pl->index))
		error = EPERM;
	PF_UNLOCK();
	return (error);
}

/* ------------------------------------------------------------------ */
/* sysctl: net.pf                                                      */
/* ------------------------------------------------------------------ */

SYSCTL_DECL(_net);
static SYSCTL_NODE(_net, OID_AUTO, pf, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "pf(4)");

static int
pf_quota_sysctl_pct(SYSCTL_HANDLER_ARGS)
{
	u_int pct;
	int error;

	pct = atomic_load_int(&pf_vnet_limit_pct);
	error = sysctl_handle_int(oidp, &pct, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	/* Only the host sets the jails' share (sysctl writes may be gated). */
	if (req->td != NULL && jailed(req->td->td_ucred))
		return (EPERM);
	if (pct < 1 || pct > 100)
		return (EINVAL);
	atomic_store_int(&pf_vnet_limit_pct, pct);
	return (0);
}
SYSCTL_PROC(_net_pf, OID_AUTO, vnet_limit_pct,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, NULL, 0,
    pf_quota_sysctl_pct, "IU",
    "A VNET jail's pf limits, in percent of the host's (1-100; host only)");

static int
pf_quota_sysctl_count(SYSCTL_HANDLER_ARGS)
{
	u_int v = pf_quota_count(arg2);

	return (sysctl_handle_int(oidp, &v, 0, req));
}

static int
pf_quota_sysctl_limit(SYSCTL_HANDLER_ARGS)
{
	u_int v = pf_quota_limit(arg2);

	return (sysctl_handle_int(oidp, &v, 0, req));
}

static int
pf_quota_sysctl_refused(SYSCTL_HANDLER_ARGS)
{
	struct pf_quota *q = V_pf_quota;
	u_long v;

	v = q != NULL ? atomic_load_long(&q->pq_refused[arg2]) : 0;
	return (sysctl_handle_long(oidp, &v, 0, req));
}

static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_count,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "pf items this VNET holds, by limit");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_limit,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "This VNET's effective pf limits (4294967295: none)");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_refused,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Allocations refused at this VNET's pf limits");

#define	PF_QUOTA_SYSCTL(name, i)					\
	SYSCTL_PROC(_net_pf_vnet_count, OID_AUTO, name,			\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_count, "IU",			\
	    "Items this VNET holds");					\
	SYSCTL_PROC(_net_pf_vnet_limit, OID_AUTO, name,			\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_limit, "IU",			\
	    "This VNET's effective limit");				\
	SYSCTL_PROC(_net_pf_vnet_refused, OID_AUTO, name,		\
	    CTLTYPE_ULONG | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_refused, "LU",			\
	    "Allocations refused at this VNET's limit")

PF_QUOTA_SYSCTL(states, PF_LIMIT_STATES);
PF_QUOTA_SYSCTL(src_nodes, PF_LIMIT_SRC_NODES);
PF_QUOTA_SYSCTL(frags, PF_LIMIT_FRAGS);
PF_QUOTA_SYSCTL(tables, PF_LIMIT_TABLES);
PF_QUOTA_SYSCTL(table_entries, PF_LIMIT_TABLE_ENTRIES);
PF_QUOTA_SYSCTL(pktdelay_pkts, PF_LIMIT_PKTDELAY_PKTS);
PF_QUOTA_SYSCTL(anchors, PF_LIMIT_ANCHORS);
