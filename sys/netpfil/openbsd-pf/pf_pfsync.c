/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * pfsync(4) on the 5BSD stack: the carp(4) demotion OpenBSD pfsync
 * applies to the "carp" interface group, and the 5BSD extension of an
 * IPv6 synchronisation peer.
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
 *
 * pfsync6 (marked "5BSD: pfsync6"): see struct pfsync6 in
 * openbsd_compat.h.  pfsync messages and their OpenBSD wire format do
 * not change; only the network header does.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <netinet/ip_carp.h>	/* the shadow header: carp_group_demote_adj */
#include <netinet6/scope6_var.h>

#undef	ip6_output		/* this file calls the 5BSD ip6_output() */

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

/* ------------------------------------------------------------------ */
/* IPv6 synchronisation peer                                            */
/* ------------------------------------------------------------------ */

int
pfsync6_check(const struct in6_addr *a)
{
	if (IN6_IS_ADDR_UNSPECIFIED(a))
		return (0);
#ifdef INET6
	if (IN6_IS_ADDR_V4MAPPED(a) || IN6_IS_ADDR_V4COMPAT(a) ||
	    IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_MC_INTFACELOCAL(a))
		return (EINVAL);
	return (0);
#else
	return (EAFNOSUPPORT);
#endif
}

/*
 * pfsync_up(), net lock held: resolve the peer in the syncdev's scope
 * zone and join it if it is a group.  The pfsync MTU keeps room for the
 * longer IPv6 header.
 */
int
pfsync6_up(struct pfsync6 *p6, struct ifnet *ifp, struct ifnet *ifp0)
{
#ifdef INET6
	struct in6_addr dst;
	int error;

	KASSERT(!p6->p6_up && p6->p6_inm == NULL,
	    ("%s: %s already up", __func__, ifp->if_xname));

	if (ifp0->if_mtu <= PFSYNC6_HDREXTRA + sizeof(struct ip) +
	    PFSYNC_HDRLEN)
		return (EINVAL);

	dst = p6->p6_peer;
	error = in6_setscope(&dst, ifp0, NULL);
	if (error != 0)
		return (error);

	if (IN6_IS_ADDR_MULTICAST(&dst)) {
		if ((ifp0->if_flags & IFF_MULTICAST) == 0)
			return (ENODEV);
		error = in6_joingroup(ifp0, &dst, NULL, &p6->p6_inm, 0);
		if (error != 0) {
			p6->p6_inm = NULL;
			return (error);
		}
	}

	if (ifp->if_mtu + PFSYNC6_HDREXTRA > ifp0->if_mtu)
		ifp->if_mtu = ifp0->if_mtu - PFSYNC6_HDREXTRA;

	p6->p6_dst = dst;
	p6->p6_ifidx = ifp0->if_index;
	p6->p6_up = 1;
	return (0);
#else
	return (EAFNOSUPPORT);
#endif
}

/* pfsync_down(), net lock held, after pfsync stopped sending. */
void
pfsync6_down(struct pfsync6 *p6)
{
#ifdef INET6
	if (p6->p6_inm != NULL) {
		(void)in6_leavegroup(p6->p6_inm, NULL);
		p6->p6_inm = NULL;
	}
#endif
	p6->p6_up = 0;
	p6->p6_ifidx = 0;
	memset(&p6->p6_dst, 0, sizeof(p6->p6_dst));
}

/*
 * Send a pfsync packet built behind pfsync's IPv4 template to the IPv6
 * peer: swap the IPv4 header for an IPv6 one with hop limit 255.
 * Consumes the mbuf.
 */
int
pfsync6_output(struct pfsync6 *p6, struct mbuf *m)
{
#ifdef INET6
	struct epoch_tracker et;
	struct ip6_moptions im6o, *im6op = NULL;
	struct ip6_hdr *ip6;
	struct ifnet *ifp;
	u_int fib;
	int error, plen;

	fib = M_GETFIB(m);
	if (m->m_pkthdr.len < sizeof(struct ip)) {
		m_freem(m);
		return (EINVAL);
	}
	m_adj(m, sizeof(struct ip));
	plen = m->m_pkthdr.len;
	M_PREPEND(m, sizeof(*ip6), M_NOWAIT);
	if (m == NULL)
		return (ENOBUFS);

	ip6 = mtod(m, struct ip6_hdr *);
	memset(ip6, 0, sizeof(*ip6));
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(plen);
	ip6->ip6_nxt = IPPROTO_PFSYNC;
	ip6->ip6_hlim = PFSYNC_DFLTTL;
	ip6->ip6_dst = p6->p6_dst;

	NET_EPOCH_ENTER(et);
	ifp = ifnet_byindex(p6->p6_ifidx);
	if (ifp == NULL) {
		error = ENXIO;
		goto drop;
	}
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		memset(&im6o, 0, sizeof(im6o));
		im6o.im6o_multicast_ifp = ifp;
		im6o.im6o_multicast_hlim = PFSYNC_DFLTTL;
		im6o.im6o_multicast_loop = 0;
		ip6_mfilter_init(&im6o.im6o_head);
		im6op = &im6o;
	}
	error = in6_selectsrc_nbr(fib, &ip6->ip6_dst, im6op, ifp,
	    &ip6->ip6_src);
	if (error != 0)
		goto drop;

	error = ip6_output(m, NULL, NULL, 0, im6op, NULL, NULL);
	NET_EPOCH_EXIT(et);
	return (error);
drop:
	NET_EPOCH_EXIT(et);
	m_freem(m);
	return (error);
#else
	m_freem(m);
	return (EAFNOSUPPORT);
#endif
}
