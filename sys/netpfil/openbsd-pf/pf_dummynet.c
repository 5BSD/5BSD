/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2026 The 5BSD Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 5BSD extension: pf "dnpipe" and "dnqueue" send packets through
 * dummynet(4), as FreeBSD pf did (pf_dummynet_route() and
 * pf_pdesc_to_dnflow() in FreeBSD sys/netpfil/pf/pf.c).
 *
 * pf_test() hands a passed packet to dummynet once (PF_DN_TAG_DONE).
 * Dummynet reinjects it into ip_input()/ip_output() after its delay;
 * pf_test() then sees PF_DN_TAG_INFLIGHT and passes it without
 * evaluating it again.  A route-to packet carries its interface and next
 * hop in the tag and is sent there on reinjection, through the output
 * tail pf_route() would have run (checksums, MTU, fragmentation).
 *
 * An inbound route-to packet is filtered outbound by a nested pf_test()
 * in pf_route() (PF_DN_TAG_ROUTING): a pipe that pf_test() picks is kept
 * in the tag (dn_dpipe) for pf_route(), which knows the next hop.  A
 * packet pf reassembled (IPv6) is shaped whole and refragmented on
 * reinjection, as pf_route6() and the end of pf_test() would have.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

#include <netinet/ip_var.h>
#include <netinet/ip_dn_flow.h>
#include <netpfil/dummynet/dn_packet.h>

SDT_PROBE_DEFINE4(pf, ip, dummynet, submit, "struct pf_pdesc *",
    "struct pf_state *", "uint32_t", "uint32_t");
SDT_PROBE_DEFINE2(pf, ip, dummynet, returned, "uint32_t", "int");
SDT_PROBE_DEFINE1(pf, ip, dummynet, reinject, "struct ifnet *");
SDT_PROBE_DEFINE3(pf, ip, dummynet, error, "struct pf_pdesc *", "int",
    "const char *");

/* pf.c; queues the error through the deferred send path. */
void	pf_send_icmp(struct mbuf *, u_int8_t, u_int8_t, int, sa_family_t,
	    struct pf_rule *, u_int);

CTASSERT(sizeof(struct sockaddr_in6) <=
    sizeof(((struct pkthdr_pf *)NULL)->dn_dst));

/* Forget the dummynet pass; dummynet's own rule tag is not pf's. */
static void
pf_dn_clear(struct mbuf *m, struct pkthdr_pf *t)
{
	struct m_tag *mtag;

	t->dn_flags &= ~(PF_DN_TAG_INFLIGHT | PF_DN_TAG_ROUTE_TO |
	    PF_DN_TAG_DUPTO);
	t->dn_dflags = 0;
	mtag = m_tag_locate(m, MTAG_IPFW_RULE, 0, NULL);
	if (mtag != NULL)
		m_tag_delete(m, mtag);
}

/*
 * pf_route()/pf_route6() hand a route-to packet to dummynet before
 * their output tail; finish it here as they would have: checksums
 * (if_output_tso), the MTU check, IPv4 fragmentation and the
 * "fragmentation needed"/"packet too big" errors.
 */
static void
pf_dn_route_out(struct mbuf *m, struct ifnet *ifp, struct sockaddr *nh,
    int dupto)
{
	struct mbuf_list ml;
	struct ip *ip;
	int af;

	if (m->m_len < (int)sizeof(struct ip) &&
	    (m = m_pullup(m, sizeof(struct ip))) == NULL)
		return;
	ip = mtod(m, struct ip *);
	af = (ip->ip_v == IPVERSION) ? AF_INET : AF_INET6;
#ifdef INET6
	if (af == AF_INET6) {
		struct m_tag *mtag;

		mtag = m_tag_find(m, PACKET_TAG_PF_REASSEMBLED, NULL);
		if (mtag != NULL) {
			(void)pf_refragment6(&m, mtag,
			    (struct sockaddr_in6 *)nh, ifp, NULL);
			return;
		}
	}
#endif
	if (obsd_output_tso(ifp, &m, af, nh, ifp->if_mtu) || m == NULL)
		return;

	switch (af) {
	case AF_INET:
		ip = mtod(m, struct ip *);
		if (ip->ip_off & htons(IP_DF)) {
			ipstat_inc(ips_cantfrag);
			if (!dupto)
				pf_send_icmp(m, ICMP_UNREACH,
				    ICMP_UNREACH_NEEDFRAG, ifp->if_mtu, AF_INET,
				    NULL, m->m_pkthdr.ph_rtableid);
			break;
		}
		if (ip_fragment(m, &ml, ifp, ifp->if_mtu) == 0 &&
		    if_output_ml(ifp, &ml, nh, NULL) == 0)
			ipstat_inc(ips_fragmented);
		return;		/* ip_fragment() consumed the packet */
#ifdef INET6
	case AF_INET6:
		ip6stat_inc(ip6s_cantfrag);
		if (!dupto)
			pf_send_icmp(m, ICMP6_PACKET_TOO_BIG, 0, ifp->if_mtu,
			    AF_INET6, NULL, m->m_pkthdr.ph_rtableid);
		break;
#endif
	}
	m_freem(m);
}

/*
 * A packet coming back from dummynet has already been filtered: pass it,
 * and send a route-to packet to the interface pf chose.  Returns 1 when
 * pf_test() must return PF_PASS (*m0 may then be NULL).
 */
int
pf_dn_reinjected(struct mbuf **m0)
{
	struct pkthdr_pf *t;
	struct ifnet *ifp;
	struct sockaddr_in6 nh;
	int dupto;

	if ((PF_MTAG_R(*m0)->dn_flags & PF_DN_TAG_INFLIGHT) == 0)
		return (0);
	t = PF_MTAG_W(*m0);
	if (t == NULL)
		return (0);

	if ((t->dn_flags & PF_DN_TAG_ROUTE_TO) == 0) {
		SDT_PROBE1(pf, ip, dummynet, reinject,
		    (*m0)->m_pkthdr.rcvif);
		pf_dn_clear(*m0, t);
		return (1);
	}

	NET_EPOCH_ASSERT();
	memcpy(&nh, t->dn_dst, sizeof(nh));
	dupto = (t->dn_flags & PF_DN_TAG_DUPTO) != 0;
	ifp = ifnet_byindexgen(t->dn_ifidx, t->dn_ifgen);
	/* The index table is global: the interface may be in another VNET. */
	if (ifp != NULL && (ifp->if_vnet != curvnet ||
	    (ifp->if_flags & IFF_DYING) != 0))
		ifp = NULL;
	pf_dn_clear(*m0, t);
	SDT_PROBE1(pf, ip, dummynet, reinject, ifp);
	if (ifp == NULL)
		m_freem(*m0);
	else
		pf_dn_route_out(*m0, ifp, (struct sockaddr *)&nh, dupto);
	*m0 = NULL;
	return (1);
}

/*
 * pf does not maintain the IPv4 header checksum (OpenBSD recomputes it on
 * output); an inbound packet is reinjected into ip_input(), which checks
 * it, after a TTL decrement or translation.
 */
static void
pf_dn_ip_hdr_cksum(struct mbuf *m)
{
	struct ip *ip;

	if (m->m_pkthdr.csum_flags & CSUM_IP)
		return;		/* computed by the hardware or ip_output */
	if (m->m_len < (int)sizeof(struct ip))
		return;
	ip = mtod(m, struct ip *);
	if (ip->ip_v != IPVERSION || m->m_len < (ip->ip_hl << 2))
		return;
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum_hdr(ip);
}

/* pf_route(): the nested outbound pf_test() keeps its pipe for us. */
void
pf_dn_routing(struct mbuf *m, int on)
{
	struct pkthdr_pf *t;

	if (on) {
		if ((t = PF_MTAG_W(m)) != NULL) {
			t->dn_flags |= PF_DN_TAG_ROUTING;
			t->dn_dflags = 0;
		}
	} else if (PF_MTAG_R(m)->dn_flags & PF_DN_TAG_ROUTING)
		PF_MTAG_W(m)->dn_flags &= ~PF_DN_TAG_ROUTING;
}

/*
 * Hand a passed packet to its dummynet pipe or queue.  st and r give the
 * pipes (the state's actions; for a stateless pass, the actions of the
 * rules that matched, in pd).  ifp, dst and rt are set for route-to (rt
 * gives the gateway, if any).  refrag: a forwarded IPv6 packet pf
 * reassembled leaves as fragments after dummynet.  Returns 1 if the
 * packet was taken (*m0 is NULL: queued in dummynet or dropped), 0 if it
 * continues.
 */
int
pf_dn_output(struct pf_pdesc *pd, struct pf_state *st, struct pf_rule *r,
    struct ifnet *ifp, struct sockaddr *dst, struct rtentry *rt,
    struct mbuf **m0, int refrag)
{
	struct ip_fw_args dnflow;
	struct pf_state_key *sk = NULL;
	struct pkthdr_pf *t;
	struct pf_rule *dr = r;
	u_int16_t pipe, rpipe, sel = 0;
	u_int8_t flags;
	sa_family_t af;
	int dndir, ispipe = 0;

	if (PF_MTAG_R(*m0)->dn_flags & PF_DN_TAG_DONE)
		return (0);

	if (st != NULL) {
		pipe = st->dnpipe;
		rpipe = st->dnrpipe;
		flags = st->dnflags;
		if (st->rule.ptr != NULL)
			dr = st->rule.ptr;
	} else if (pd->dn_rule != NULL) {
		pipe = pd->dn_pipe;
		rpipe = pd->dn_rpipe;
		flags = pd->dn_flags;
		dr = pd->dn_rule;
	} else {
		pipe = r->dn.pipe;
		rpipe = r->dn.rpipe;
		flags = r->dn.flags;
	}
	if (pipe != 0 || rpipe != 0) {
		dndir = dr->direction;
		if (dndir == PF_INOUT)
			dndir = (st != NULL) ? st->direction : pd->dir;
		if (pd->dir != dndir && rpipe != 0)
			sel = rpipe;
		else if (pd->dir == dndir && pipe != 0)
			sel = pipe;
		ispipe = (flags & PF_DN_IS_PIPE) != 0;
	}
	/* route-to: the pipe the outbound pf_test() chose, if ours is none. */
	if (ifp != NULL && (PF_MTAG_R(*m0)->dn_dflags & PF_DN_DEFER_SET)) {
		if (sel == 0) {
			sel = PF_MTAG_R(*m0)->dn_dpipe;
			ispipe = (PF_MTAG_R(*m0)->dn_dflags &
			    PF_DN_DEFER_PIPE) != 0;
		}
		PF_MTAG_W(*m0)->dn_dflags = 0;
	}
	if (sel == 0)
		return (0);
	if (ifp == NULL && (PF_MTAG_R(*m0)->dn_flags & PF_DN_TAG_ROUTING)) {
		/* Nested in pf_route(): it submits with the next hop. */
		if ((t = PF_MTAG_W(*m0)) == NULL)
			goto drop;
		t->dn_dpipe = sel;
		t->dn_dflags = PF_DN_DEFER_SET | (ispipe ? PF_DN_DEFER_PIPE : 0);
		return (0);
	}

	memset(&dnflow, 0, sizeof(dnflow));
	dnflow.rule.info = sel;

	if (ip_dn_io_ptr == NULL) {
		SDT_PROBE3(pf, ip, dummynet, error, pd, ENXIO,
		    "dummynet not loaded");
		goto drop;
	}
	if ((t = PF_MTAG_W(*m0)) == NULL) {
		SDT_PROBE3(pf, ip, dummynet, error, pd, ENOMEM,
		    "packet tag allocation");
		goto drop;
	}

	if (ifp != NULL) {
		const struct sockaddr *nh;

		/* Dummynet hands the reinjected packet to if_output(). */
		if (mb_unmapped_to_ext(*m0, m0) != 0) {
			SDT_PROBE3(pf, ip, dummynet, error, pd, ENOMEM,
			    "unmapped mbuf");
			return (1);
		}
		if ((t = PF_MTAG_W(*m0)) == NULL)
			goto drop;
		/* The link-layer next hop, as pf_route()'s output would. */
		nh = dst;
		if (rt != NULL && (rt->rt_nh->nh_flags & NHF_GATEWAY))
			nh = &rt->rt_nh->gw_sa;
		if (nh->sa_len > sizeof(t->dn_dst)) {
			SDT_PROBE3(pf, ip, dummynet, error, pd, EAFNOSUPPORT,
			    "next hop");
			goto drop;
		}
		t->dn_flags |= PF_DN_TAG_ROUTE_TO;
		if (st != NULL && st->rt == PF_DUPTO)
			t->dn_flags |= PF_DN_TAG_DUPTO;
		t->dn_ifidx = ifp->if_index;
		t->dn_ifgen = ifp->if_idxgen;
		memset(t->dn_dst, 0, sizeof(t->dn_dst));
		memcpy(t->dn_dst, nh, nh->sa_len);
	}
	pf_dn_ip_hdr_cksum(*m0);

	/*
	 * A connection redirected to loopback must be delivered locally when
	 * dummynet reinjects it.
	 */
	if (pd->dir == PF_IN && pd->destchg &&
	    ((pd->af == AF_INET && IN_LOOPBACK(ntohl(pd->dst->v4.s_addr))) ||
	    (pd->af == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&pd->dst->v6))))
		(*m0)->m_pkthdr.rcvif = V_loif;

	if (pd->sport != NULL)
		dnflow.f_id.src_port = ntohs(*pd->sport);
	if (pd->dport != NULL)
		dnflow.f_id.dst_port = ntohs(*pd->dport);
	dnflow.flags = (pd->dir == PF_IN) ? IPFW_ARGS_IN : IPFW_ARGS_OUT;
	dnflow.rule.info |= IPFW_IS_DUMMYNET;
	if (ispipe)
		dnflow.rule.info |= IPFW_IS_PIPE;
	dnflow.f_id.proto = pd->proto;
	dnflow.f_id.extra = dnflow.rule.info;

	/* Classify on the pre-translation (stack side) addresses. */
	af = pd->naf;
	if (st != NULL) {
		sk = st->key[PF_SK_STACK];
		af = sk->af;
	}
	switch (af) {
	case AF_INET:
		dnflow.f_id.addr_type = 4;
		dnflow.f_id.src_ip = ntohl(sk != NULL ?
		    sk->addr[pd->sidx].v4.s_addr : pd->src->v4.s_addr);
		dnflow.f_id.dst_ip = ntohl(sk != NULL ?
		    sk->addr[pd->didx].v4.s_addr : pd->dst->v4.s_addr);
		break;
	case AF_INET6:
		dnflow.f_id.addr_type = 6;
		dnflow.f_id.src_ip6 = sk != NULL ?
		    sk->addr[pd->sidx].v6 : pd->src->v6;
		dnflow.f_id.dst_ip6 = sk != NULL ?
		    sk->addr[pd->didx].v6 : pd->dst->v6;
		break;
	}
	/* Dummynet reinjects through the post-translation family (af-to). */
	if (pd->naf == AF_INET6)
		dnflow.flags |= IPFW_ARGS_IP6;

	t->dn_flags |= PF_DN_TAG_INFLIGHT | PF_DN_TAG_DONE;
	if (refrag && m_tag_find(*m0, PACKET_TAG_PF_REASSEMBLED, NULL) != NULL)
		t->dn_flags |= PF_DN_TAG_REFRAG;
	SDT_PROBE4(pf, ip, dummynet, submit, pd, st, dnflow.rule.info,
	    dnflow.flags);
	ip_dn_io_ptr(m0, &dnflow);
	SDT_PROBE2(pf, ip, dummynet, returned, dnflow.rule.info,
	    (*m0 != NULL));
	if (*m0 == NULL)
		return (1);
	/* Passed straight through: continue as if it was never queued. */
	if ((t = PF_MTAG_W(*m0)) != NULL) {
		pf_dn_clear(*m0, t);
		t->dn_flags &= ~PF_DN_TAG_REFRAG;	/* pf_test() refragments */
	}
	return (0);

drop:
	m_freem(*m0);
	*m0 = NULL;
	return (1);
}
