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
 * and is refused at its limits, before the shared pool is touched:
 *
 *   host (vnet0)   the pool's hard limit, the host's own "set limit"
 *                  (OpenBSD semantics: no hard limit until one is set)
 *   VNET jail      the host's limit scaled by net.pf.vnet_limit_pct,
 *                  whether or not the host has loaded it; shared with
 *                  the jail's descendant VNET jails: an item counts in
 *                  its VNET and in every ancestor VNET jail
 *   all jails      together at most the host's limit scaled by
 *                  net.pf.vnet_total_pct (default 200), and fragment
 *                  entries at most the mbuf clusters the host's own
 *                  frags limit leaves
 *
 * The jails' total is separate from the host's own count, so the host's
 * budget is always reachable.  Every item carries a trailer naming the
 * accounting of the VNET that allocated it (and whether its ancestors
 * were charged), so a free from a purge task, a timeout, a packet freed
 * in another context or after the VNET is gone always credits the right
 * VNETs.  The accounting is reference counted (one reference for the
 * VNET, one per item, one per child VNET) and outlives its VNET until its
 * last item is freed.  Charging and crediting are lock-free compare-and-
 * set loops that never sleep and never count past a limit.
 *
 * A VNET jail still only restates limits (DIOCSETLIMIT with the host's
 * value or its own effective value); DIOCGETLIMIT reports its effective
 * limit, so pfctl -sm in a jail shows the quota, and pfctl -si its own
 * counts (pf_status is per VNET).  The adaptive timeouts a jail inherits
 * from the host's configuration are scaled to its quota
 * (pf_quota_adaptive()).  net.pf.vnet_count, net.pf.vnet_limit and
 * net.pf.vnet_refused show the current VNET's counts (with its child
 * VNETs'), effective limits and refusals; net.pf.vnet_total_count and
 * net.pf.vnet_total_limit the jails' total.
 */

#include "openbsd_compat.h"

#include <sys/jail.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

extern struct pool pfr_kentry_pl[PFRKE_MAX];

struct pf_quota {
	u_int		pq_ref;		/* the VNET, its items, child VNETs */
	int		pq_host;	/* vnet0: not in the jails' total */
	struct pf_quota	*pq_parent;	/* the nearest ancestor VNET jail's */
	volatile u_int	pq_count[PF_LIMIT_MAX];	/* items out, with children's */
	u_long		pq_refused[PF_LIMIT_MAX];
};

/* The trailer: the owner's accounting; bit 0: its ancestors were charged. */
#define	PF_QUOTA_ANCESTORS	((uintptr_t)1)

VNET_DEFINE_STATIC(struct pf_quota *, pf_quota);
#define	V_pf_quota	VNET(pf_quota)

/* Host-only: a VNET jail's limit, in percent of the host's. */
static u_int pf_vnet_limit_pct = 100;
/* Host-only: all VNET jails' items together, in percent of the host's. */
static u_int pf_vnet_total_pct = 200;
/* Items all VNET jails hold together. */
static volatile u_int pf_quota_total[PF_LIMIT_MAX];
static u_long pf_quota_total_refused[PF_LIMIT_MAX];

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

/* The host's limit scaled by pct, at least 1 unless 0; 0 means none. */
static u_int
pf_quota_scaled(int i, u_int pct)
{
	uint64_t l;

	l = pf_pool_limits[i].limit;
	l = l * pct / 100;
	if (l == 0 && pf_pool_limits[i].limit != 0)
		l = 1;
	return (l > UINT_MAX ? UINT_MAX : (u_int)l);
}

/* A VNET jail's limit as DIOCGETLIMIT reports it. */
static u_int
pf_quota_jail_limit(int i)
{
	return (pf_quota_scaled(i, atomic_load_int(&pf_vnet_limit_pct)));
}

/* The host's hard limit for limit i, or 0. */
static u_int
pf_quota_host_limit(int i)
{
	return (((struct pool *)pf_pool_limits[i].pp)->pr_hardlimit);
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
		l = pf_quota_host_limit(i);
	return (l != 0 ? l : UINT_MAX);
}

/* The limit on all VNET jails' items together; UINT_MAX for none. */
static u_int
pf_quota_total_limit(int i)
{
	u_int l, h;
	int ncl;

	l = pf_quota_scaled(i, atomic_load_int(&pf_vnet_total_pct));
	if (l == 0)
		l = UINT_MAX;
	if (i == PF_LIMIT_FRAGS) {
		/* Fragments hold mbuf clusters: leave the host's share. */
		ncl = atomic_load_int(&nmbclusters);
		h = pf_quota_host_limit(i);
		ncl = (h != 0 && h < (u_int)ncl) ? ncl - (int)h : (h != 0 ? 0 :
		    ncl);
		if ((u_int)ncl < l)
			l = (u_int)ncl;
	}
	return (l);
}

/* Count one more in *c unless that reaches lim. */
static int
pf_quota_inc(volatile u_int *c, u_int lim)
{
	u_int n;

	n = atomic_load_int(c);
	do {
		if (n >= lim)
			return (0);
	} while (!atomic_fcmpset_int(c, &n, n + 1));
	return (1);
}

static void
pf_quota_free(struct pf_quota *q)
{
	struct pf_quota *p;

	while (q != NULL && refcount_release(&q->pq_ref)) {
		p = q->pq_parent;
		free(q, M_PF);
		q = p;			/* the child's reference */
	}
}

/*
 * Charge one item of limit i to the current VNET: to the VNET, to its
 * ancestor VNET jails and to the jails' total.  On success *tokp is the
 * item's trailer and holds a reference (0: not accounted).  The host
 * keeps OpenBSD's rule that a PR_WAITOK caller without PR_LIMITFAIL is
 * not refused; a VNET jail is refused at its limits whatever the flags
 * (every caller of these pools handles failure).
 */
int
pf_quota_charge(int i, int flags, uintptr_t *tokp)
{
	struct pf_quota *q, *p, *a;
	u_int lim;

	*tokp = 0;
#ifdef VIMAGE
	if (curvnet == NULL)
		return (0);
#endif
	if ((q = V_pf_quota) == NULL)
		return (pf_quota_host() ? 0 : ENOMEM);
	lim = pf_quota_limit(i);
	if (q->pq_host) {
		if (!pf_quota_inc(&q->pq_count[i], lim)) {
			if (flags & (PR_LIMITFAIL | PR_NOWAIT))
				goto refused;
			atomic_add_int(&q->pq_count[i], 1);
		}
		goto charged;
	}
	if (!pf_quota_inc(&q->pq_count[i], lim))
		goto refused;
	/* A jail's quota is shared by its descendant VNET jails. */
	p = (struct pf_quota *)atomic_load_acq_ptr((uintptr_t *)&q->pq_parent);
	for (a = p; a != NULL; a = a->pq_parent)
		if (!pf_quota_inc(&a->pq_count[i], lim))
			break;
	if (a != NULL ||
	    !pf_quota_inc(&pf_quota_total[i], pf_quota_total_limit(i))) {
		if (a == NULL)
			atomic_add_long(&pf_quota_total_refused[i], 1);
		while (p != a) {
			atomic_subtract_int(&p->pq_count[i], 1);
			p = p->pq_parent;
		}
		atomic_subtract_int(&q->pq_count[i], 1);
		goto refused;
	}
	if (p != NULL)
		*tokp = PF_QUOTA_ANCESTORS;
charged:
	refcount_acquire(&q->pq_ref);
	*tokp |= (uintptr_t)q;
	return (0);
refused:
	atomic_add_long(&q->pq_refused[i], 1);
	return (ENOMEM);
}

/* Credit one item of limit i to the VNETs that were charged for it. */
void
pf_quota_release(uintptr_t tok, int i)
{
	struct pf_quota *q, *a;

	q = (struct pf_quota *)(tok & ~PF_QUOTA_ANCESTORS);
	if (q == NULL)
		return;
	atomic_subtract_int(&q->pq_count[i], 1);
	if (!q->pq_host) {
		if (tok & PF_QUOTA_ANCESTORS)
			for (a = q->pq_parent; a != NULL; a = a->pq_parent)
				atomic_subtract_int(&a->pq_count[i], 1);
		atomic_subtract_int(&pf_quota_total[i], 1);
	}
	pf_quota_free(q);
}

/* Items of limit i the current VNET (with its child VNETs) holds. */
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

/*
 * A VNET jail inherits the host's adaptive timeouts (pfctl derives them
 * from the states limit it restates, the defaults are 60000/120000).
 * Above its own states limit they would never take effect: scale them
 * to the jail's limit, as the limit is scaled.
 */
void
pf_quota_adaptive(u_int32_t *start, u_int32_t *end)
{
	u_int h, l;

	if (pf_quota_host() || *end == 0)
		return;
	h = pf_pool_limits[PF_LIMIT_STATES].limit;
	l = pf_quota_jail_limit(PF_LIMIT_STATES);
	if (l == 0 || l >= h || *end <= l)
		return;
	*start = (uint64_t)*start * l / h;
	*end = (uint64_t)*end * l / h;
}

void	pf_quota_vnet_init(void);
void
pf_quota_vnet_init(void)
{
	struct pf_quota *q;

	q = malloc(sizeof(*q), M_PF, M_WAITOK | M_ZERO);
	refcount_init(&q->pq_ref, 1);
	q->pq_host = pf_quota_host();
	V_pf_quota = q;
}

/*
 * A jail with its own VNET was created (allprison_lock held): its
 * accounting is also charged to the nearest ancestor VNET jail's, so a
 * jail's quota is shared by all its descendants.  Items charged before
 * the link carry no ancestor bit and are credited to the VNET alone.
 */
void	pf_quota_jail_link(struct prison *);
void
pf_quota_jail_link(struct prison *pr)
{
#ifdef VIMAGE
	struct prison *ppr;
	struct pf_quota *q, *pq;

	if (pr == &prison0 || !prison_owns_vnet(pr) || pr->pr_vnet == NULL)
		return;
	for (ppr = pr->pr_parent; ppr != &prison0 && !prison_owns_vnet(ppr);
	    ppr = ppr->pr_parent)
		;
	if (ppr == &prison0 || ppr->pr_vnet == NULL)
		return;
	/*
	 * Parents first: an item's trailer records only that its ancestors
	 * were charged, and its credit walks the chain as it is then, so a
	 * chain must not grow above a linked jail (pf loaded with nested
	 * jails, linked in allprison order, where a child may come first).
	 */
	pf_quota_jail_link(ppr);
	q = VNET_VNET(pr->pr_vnet, pf_quota);
	pq = VNET_VNET(ppr->pr_vnet, pf_quota);
	if (q == NULL || pq == NULL || q == pq || q->pq_parent != NULL)
		return;
	refcount_acquire(&pq->pq_ref);
	atomic_store_rel_ptr((uintptr_t *)&q->pq_parent, (uintptr_t)pq);
#endif
}

/* pf loaded while jails exist: link their VNETs (after pf_fbsd_vnet_init). */
static void
pf_quota_link_existing(void *arg __unused)
{
	struct prison *pr;

	sx_slock(&allprison_lock);
	TAILQ_FOREACH(pr, &allprison, pr_list)
		pf_quota_jail_link(pr);
	sx_sunlock(&allprison_lock);
}
SYSINIT(pf_quota_link, SI_SUB_PROTO_FIREWALL, SI_ORDER_ANY,
    pf_quota_link_existing, NULL);

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
			    "%d out (with child vnets')\n", curvnet,
			    atomic_load_int(&q->pq_count[i]), i);
	pf_quota_free(q);
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

/* A host-only percentage (arg2: the maximum). */
static int
pf_quota_sysctl_pct(SYSCTL_HANDLER_ARGS)
{
	u_int *p = arg1;
	u_int pct;
	int error;

	pct = atomic_load_int(p);
	error = sysctl_handle_int(oidp, &pct, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	/* Only the host sets the jails' shares (sysctl writes may be gated). */
	if (req->td != NULL && jailed(req->td->td_ucred))
		return (EPERM);
	if (pct < 1 || pct > (u_int)arg2)
		return (EINVAL);
	atomic_store_int(p, pct);
	return (0);
}
SYSCTL_PROC(_net_pf, OID_AUTO, vnet_limit_pct,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &pf_vnet_limit_pct, 100,
    pf_quota_sysctl_pct, "IU",
    "A VNET jail's pf limits, in percent of the host's (1-100; host only)");
SYSCTL_PROC(_net_pf, OID_AUTO, vnet_total_pct,
    CTLTYPE_UINT | CTLFLAG_RWTUN | CTLFLAG_MPSAFE, &pf_vnet_total_pct, 10000,
    pf_quota_sysctl_pct, "IU",
    "All VNET jails' pf items together, in percent of the host's limits "
    "(1-10000; host only)");

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

static int
pf_quota_sysctl_total_count(SYSCTL_HANDLER_ARGS)
{
	u_int v = atomic_load_int(&pf_quota_total[arg2]);

	return (sysctl_handle_int(oidp, &v, 0, req));
}

static int
pf_quota_sysctl_total_limit(SYSCTL_HANDLER_ARGS)
{
	u_int v = pf_quota_total_limit(arg2);

	return (sysctl_handle_int(oidp, &v, 0, req));
}

static int
pf_quota_sysctl_total_refused(SYSCTL_HANDLER_ARGS)
{
	u_long v = atomic_load_long(&pf_quota_total_refused[arg2]);

	return (sysctl_handle_long(oidp, &v, 0, req));
}

static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_count,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "pf items this VNET and its child VNETs hold, by limit");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_limit,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "This VNET's effective pf limits (4294967295: none)");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_refused,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Allocations refused at this VNET's pf limits");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_total_count,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "pf items all VNET jails hold together, by limit");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_total_limit,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "The limits on all VNET jails' pf items together (4294967295: none)");
static SYSCTL_NODE(_net_pf, OID_AUTO, vnet_total_refused,
    CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Allocations refused at the VNET jails' total");

#define	PF_QUOTA_SYSCTL(name, i)					\
	SYSCTL_PROC(_net_pf_vnet_count, OID_AUTO, name,			\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_count, "IU",			\
	    "Items this VNET and its child VNETs hold");		\
	SYSCTL_PROC(_net_pf_vnet_limit, OID_AUTO, name,			\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_limit, "IU",			\
	    "This VNET's effective limit");				\
	SYSCTL_PROC(_net_pf_vnet_refused, OID_AUTO, name,		\
	    CTLTYPE_ULONG | CTLFLAG_RD | CTLFLAG_VNET | CTLFLAG_MPSAFE,	\
	    NULL, (i), pf_quota_sysctl_refused, "LU",			\
	    "Allocations refused at this VNET's limits");		\
	SYSCTL_PROC(_net_pf_vnet_total_count, OID_AUTO, name,		\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE,			\
	    NULL, (i), pf_quota_sysctl_total_count, "IU",		\
	    "Items all VNET jails hold together");			\
	SYSCTL_PROC(_net_pf_vnet_total_limit, OID_AUTO, name,		\
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE,			\
	    NULL, (i), pf_quota_sysctl_total_limit, "IU",		\
	    "The limit on all VNET jails' items together");		\
	SYSCTL_PROC(_net_pf_vnet_total_refused, OID_AUTO, name,		\
	    CTLTYPE_ULONG | CTLFLAG_RD | CTLFLAG_MPSAFE,			\
	    NULL, (i), pf_quota_sysctl_total_refused, "LU",		\
	    "Allocations refused at the VNET jails' total")

PF_QUOTA_SYSCTL(states, PF_LIMIT_STATES);
PF_QUOTA_SYSCTL(src_nodes, PF_LIMIT_SRC_NODES);
PF_QUOTA_SYSCTL(frags, PF_LIMIT_FRAGS);
PF_QUOTA_SYSCTL(tables, PF_LIMIT_TABLES);
PF_QUOTA_SYSCTL(table_entries, PF_LIMIT_TABLE_ENTRIES);
PF_QUOTA_SYSCTL(pktdelay_pkts, PF_LIMIT_PKTDELAY_PKTS);
PF_QUOTA_SYSCTL(anchors, PF_LIMIT_ANCHORS);
