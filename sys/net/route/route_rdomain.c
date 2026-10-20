/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Routing domains (rdomain(4)) on FIBs, after OpenBSD's if_createrdomain()
 * and if_setrdomain() (sys/net/if.c).
 *
 * A routing table is a FIB.  A routing domain is a FIB that is its own
 * domain; it owns a loopback interface lo<N> and its interfaces.  Other
 * FIBs (net.fibs, route -T N add) are routing tables of domain 0 unless
 * made routing domains.  Interfaces of a routing domain receive into the
 * domain's FIB (if_fib); addresses are local only inside their domain, and
 * sockets see only packets of their domain (see rt_fib_scope()).
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sx.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_clone.h>
#include <net/vnet.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/route/route_ctl.h>
#include <net/route/route_var.h>

#include <netinet/in.h>

static struct sx rdomain_lock;
SX_SYSINIT(rdomain_lock, &rdomain_lock, "rdomain");

/* Is routing table fib empty (no IPv4 or IPv6 prefix)? */
static bool
rt_fib_empty(u_int fib)
{
	struct rib_head *rnh;
	int af[] = { AF_INET, AF_INET6 };

	for (u_int i = 0; i < nitems(af); i++) {
		rnh = rt_tables_get_rnh_safe(fib, af[i]);
		if (rnh != NULL && rnh->rnh_prefixes != 0)
			return (false);
	}
	return (true);
}

/*
 * Is the route one of those rc.d/routing adds to every FIB through lo0:
 * the loopback addresses and the IPv6 reject routes?
 */
static int
rt_lo0_route(const struct rtentry *rt, const struct nhop_object *nh,
    void *arg __unused)
{
#ifdef INET6
	static const struct {
		uint8_t	pfx[16];
		int	plen;
	} rej6[] = {
		{ { 0 }, 96 },					/* ::/96 */
		{ { [10] = 0xff, [11] = 0xff }, 96 },		/* ::ffff:0.0.0.0/96 */
		{ { 0xfe, 0x80 }, 10 },				/* fe80::/10 */
		{ { 0xff, 0x02 }, 16 },				/* ff02::/16 */
	};
	struct in6_addr a6;
#endif
#ifdef INET
	struct in_addr a4;
#endif
	uint32_t scope __unused;
	int plen __unused;

	if (NH_IS_NHGRP(nh) || nh->nh_ifp != V_loif)
		return (0);
	switch (rt_get_family(rt)) {
#ifdef INET
	case AF_INET:
		rt_get_inet_prefix_plen(rt, &a4, &plen, &scope);
		return (plen == 32 && a4.s_addr == htonl(INADDR_LOOPBACK));
#endif
#ifdef INET6
	case AF_INET6:
		rt_get_inet6_prefix_plen(rt, &a6, &plen, &scope);
		if (plen == 128 && IN6_IS_ADDR_LOOPBACK(&a6))
			return (1);
		if ((nhop_get_rtflags(nh) & RTF_REJECT) == 0)
			return (0);
		for (u_int i = 0; i < nitems(rej6); i++)
			if (plen == rej6[i].plen &&
			    memcmp(&a6, rej6[i].pfx, sizeof(a6)) == 0)
				return (1);
		return (0);
#endif
	}
	return (0);
}

static int
rt_count_other(struct rtentry *rt, void *arg)
{
	if (!rt_lo0_route(rt, rt->rt_nhop, NULL))
		(*(u_int *)arg)++;
	return (0);
}

/*
 * Clear an existing FIB that is to become a routing domain when all it
 * holds is what rc.d/routing gives every FIB through lo0 (net.fibs): the
 * loopback addresses and IPv6 reject routes.  They are domain 0's, whose
 * loopback lo0 is; the new domain gets its own on lo<N>, as a new OpenBSD
 * routing domain starts empty.  A FIB with any other route is left alone
 * and cannot become a domain.
 */
static void
rt_fib_clear_lo0(u_int fib)
{
	int af[] = { AF_INET, AF_INET6 };
	u_int other = 0;

	for (u_int i = 0; i < nitems(af); i++)
		rib_walk(fib, af[i], false, rt_count_other, &other);
	if (other != 0)
		return;
	for (u_int i = 0; i < nitems(af); i++)
		rib_walk_del(fib, af[i], rt_lo0_route, NULL, true);
}

static bool
rt_fib_is_rdomain(u_int fib)
{
	return (fib == 0 ||
	    (fib <= RT_TABLEID_MAX && (V_rt_l2map[fib] & 0xffff) == fib));
}

/*
 * Loopback interface of the routing domain of FIB fib: lo<N> for routing
 * domain N, the default loopback (lo0) for routing domain 0.
 */
struct ifnet *
rt_fib_loif(u_int fib)
{
	struct ifnet *ifp;
	u_int idx;

	if (__predict_true(V_rt_rdomains == 0))
		return (V_loif);
	idx = V_rt_l2map[rt_fib_l2(fib)] >> 16;
	if (idx == 0)
		return (V_loif);
	ifp = ifnet_byindex(idx);
	return (ifp != NULL ? ifp : V_loif);
}

/* Is ifp the loopback interface of its routing domain (other than lo0)? */
bool
rt_rdomain_isloif(struct ifnet *ifp)
{
	u_int rd;

	if (__predict_true(V_rt_rdomains == 0))
		return (false);
	rd = rt_fib_l2(ifp->if_fib);
	return (rd != 0 && (V_rt_l2map[rd] >> 16) == ifp->if_index);
}

/* The detach lock also serializes routing-domain interface moves. */
int
rt_rdomain_can_destroy(struct ifnet *ifp)
{
	struct ifnet *p;
	u_int rd;
	int error = 0;

	sx_assert(&ifnet_detach_sxlock, SA_XLOCKED);
	if (!rt_rdomain_isloif(ifp))
		return (0);
	rd = rt_fib_l2(ifp->if_fib);
	IFNET_RLOCK();
	CK_STAILQ_FOREACH(p, &V_ifnet, if_link) {
		if (p != ifp && rt_fib_l2(p->if_fib) == rd) {
			error = EBUSY;
			break;
		}
	}
	IFNET_RUNLOCK();
	return (error);
}

/* The default loopback has detached; release its routing domain. */
void
rt_rdomain_ifdetach(struct ifnet *ifp)
{
	u_int rd;

	if (!rt_rdomain_isloif(ifp))
		return;
	sx_xlock(&rdomain_lock);
	rd = rt_fib_l2(ifp->if_fib);
	if ((V_rt_l2map[rd] >> 16) == ifp->if_index) {
		V_rt_l2map[rd] = 0;
		atomic_thread_fence_rel();
		V_rt_rdomains--;
	}
	sx_xunlock(&rdomain_lock);
}

/*
 * Changing a process' or socket's FIB within its routing domain keeps the
 * FreeBSD (unprivileged) setfib(2) semantics; entering another routing
 * domain needs privilege, as setrtable(2) does on OpenBSD.
 */
int
rt_fib_change_check(struct thread *td, u_int oldfib, u_int newfib)
{

	if (rt_fib_same_rdomain(oldfib, newfib))
		return (0);
	return (priv_check(td, PRIV_NET_SETIFFIB));
}

/* Set the routing domain map entry of FIB fib; l2 0 removes the domain. */
static void
rt_rdomain_map(u_int fib, uint32_t l2)
{
	sx_xlock(&rdomain_lock);
	if (V_rt_l2map[fib] == 0 && l2 != 0)
		V_rt_rdomains++;
	else if (V_rt_l2map[fib] != 0 && l2 == 0)
		V_rt_rdomains--;
	V_rt_l2map[fib] = l2;
	atomic_thread_fence_rel();
	sx_xunlock(&rdomain_lock);
}

/*
 * Create routing domain rdomain with its loopback interface lo<rdomain>
 * (OpenBSD if_createrdomain()).  ifp is the interface being configured,
 * which may be that loopback interface itself.  EEXIST means the routing
 * domain already exists or the table cannot become one.
 */
static int
rt_rdomain_create_locked(u_int rdomain, struct ifnet *ifp)
{
	char loname[IFNAMSIZ];
	struct ifnet *loifp;
	uint32_t old;
	bool added, pending;
	int error;

	sx_assert(&ifnet_detach_sxlock, SA_XLOCKED);

	if (rdomain > RT_TABLEID_MAX)
		return (EINVAL);
	if (rt_fib_is_rdomain(rdomain))
		return (EEXIST);
	/*
	 * A table that does not exist yet becomes a (pending, loopback-less)
	 * domain before it is created, so that grow_rtables() does not copy
	 * the interface routes of domain 0 into it (net.add_addr_allfibs).
	 * The detach lock keeps others from seeing the domain half made.
	 */
	pending = rdomain >= V_rt_numfibs;
	added = false;
	if (pending)
		rt_rdomain_map(rdomain, rdomain);
	if ((error = rt_tables_add(rdomain)) != 0)
		goto fail;
	added = pending;
	error = EEXIST;
	if (!pending)
		rt_fib_clear_lo0(rdomain);
	if (!rt_fib_empty(rdomain))
		goto fail;

	snprintf(loname, sizeof(loname), "lo%u", rdomain);
	error = if_clone_create(loname, sizeof(loname), NULL);
	if ((loifp = ifunit_ref(loname)) == NULL) {
		if (error == 0)
			error = ENXIO;
		goto fail;
	}
	if (error != 0 && (loifp != ifp || error != EEXIST)) {
		if_rele(loifp);
		goto fail;
	}
	if ((loifp->if_flags & IFF_LOOPBACK) == 0) {
		if_rele(loifp);
		error = EINVAL;
		goto fail;
	}
	/* An existing lo<N> may be another domain's loopback, renamed. */
	if (loifp == V_loif || rt_rdomain_isloif(loifp)) {
		if_rele(loifp);
		error = EPERM;
		goto fail;
	}

	old = V_rt_l2map[rdomain];
	rt_rdomain_map(rdomain, rdomain | ((uint32_t)loifp->if_index << 16));

	error = rt_rdomain_setif(loifp, rdomain, true);
	if_rele(loifp);
	if (error == 0)
		return (0);
	/* The map entry must not name a loopback that is not in the domain. */
	rt_rdomain_map(rdomain, old);
fail:
	if (pending)
		rt_rdomain_map(rdomain, 0);
	/*
	 * The table stays, now an ordinary FIB of domain 0: give it the
	 * interface routes its creation skipped (net.add_addr_allfibs).
	 */
	if (added) {
		int af[] = { AF_INET, AF_INET6 };

		for (u_int i = 0; i < nitems(af); i++) {
			struct rib_head *src, *dst;

			src = rt_tables_get_rnh(RT_DEFAULT_FIB, af[i]);
			dst = rt_tables_get_rnh(rdomain, af[i]);
			if (src != NULL && dst != NULL)
				rib_copy_kernel_routes(src, dst);
		}
	}
	return (error);
}

/*
 * Move ifp into FIB fib (OpenBSD if_setrdomain() when rdomain is set,
 * FreeBSD SIOCSIFFIB otherwise).  Leaving a routing domain removes the
 * interface's addresses and routes, as they belong to the old domain.
 */
static int
rt_rdomain_setif_locked(struct ifnet *ifp, u_int fib, bool rdomain)
{
	u_int ord, nrd;
	bool up;

	if (fib >= V_rt_numfibs)
		return (rdomain ? ESRCH : EINVAL);
	if (rdomain && !rt_fib_is_rdomain(fib))
		return (EINVAL);
	ord = rt_fib_l2(ifp->if_fib);
	nrd = rt_fib_l2(fib);
	/* A domain keeps its loopback; lo0 is the loopback of domain 0. */
	if (ord != nrd && (ifp == V_loif || rt_rdomain_isloif(ifp)))
		return (EPERM);

	if (ord == nrd) {
		ifp->if_fib = fib;
		return (0);
	}

	/*
	 * Tear down what belongs to the old routing domain.  Take the
	 * interface down so that everything that cares gets a message and
	 * the automatic IPv6 configuration is redone in the new domain.
	 */
	up = (ifp->if_flags & IFF_UP) != 0;
	if (up)
		if_down(ifp);
	if_purgeaddrs(ifp);
	rt_flushifroutes(ifp);
	ifp->if_fib = fib;
	if (up)
		if_up(ifp);
	return (0);
}

/* Serialize creation and moves with clone destruction and VNET moves. */
int
rt_rdomain_create(u_int rdomain, struct ifnet *ifp)
{
	int error;

	sx_xlock(&ifnet_detach_sxlock);
	error = rt_rdomain_create_locked(rdomain, ifp);
	sx_xunlock(&ifnet_detach_sxlock);
	return (error);
}

int
rt_rdomain_setif(struct ifnet *ifp, u_int fib, bool rdomain)
{
	int error;

	sx_xlock(&ifnet_detach_sxlock);
	error = rt_rdomain_setif_locked(ifp, fib, rdomain);
	sx_xunlock(&ifnet_detach_sxlock);
	return (error);
}
