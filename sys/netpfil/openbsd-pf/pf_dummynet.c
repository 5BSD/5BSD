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
 * hop in the tag and is sent there on reinjection.
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

CTASSERT(sizeof(struct sockaddr_in6) <=
    sizeof(((struct pkthdr_pf *)NULL)->dn_dst));

/* Forget the dummynet pass; dummynet's own rule tag is not pf's. */
static void
pf_dn_clear(struct mbuf *m, struct pkthdr_pf *t)
{
	struct m_tag *mtag;

	t->dn_flags &= ~(PF_DN_TAG_INFLIGHT | PF_DN_TAG_ROUTE_TO);
	mtag = m_tag_locate(m, MTAG_IPFW_RULE, 0, NULL);
	if (mtag != NULL)
		m_tag_delete(m, mtag);
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
	struct sockaddr_in6 dst;

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
	memcpy(&dst, t->dn_dst, sizeof(dst));
	ifp = ifnet_byindexgen(t->dn_ifidx, t->dn_ifgen);
	pf_dn_clear(*m0, t);
	SDT_PROBE1(pf, ip, dummynet, reinject, ifp);
	if (ifp == NULL) {
		m_freem(*m0);
	} else
		(void)(*ifp->if_output)(ifp, *m0, (struct sockaddr *)&dst,
		    NULL);
	*m0 = NULL;
	return (1);
}

/*
 * Hand a passed packet to its dummynet pipe or queue.  st and r give the
 * pipes (the state's actions, or the rule's for a stateless pass).  ifp
 * and dst are set for route-to.  Returns 1 if the packet was taken
 * (*m0 is NULL: queued in dummynet or dropped), 0 if it continues.
 */
int
pf_dn_output(struct pf_pdesc *pd, struct pf_state *st, struct pf_rule *r,
    struct ifnet *ifp, struct sockaddr *dst, struct mbuf **m0)
{
	struct ip_fw_args dnflow;
	struct pf_state_key *sk = NULL;
	struct pkthdr_pf *t;
	struct pf_rule *dr = r;
	u_int16_t pipe, rpipe;
	u_int8_t flags;
	sa_family_t af;
	int dndir;

	if (st != NULL) {
		pipe = st->dnpipe;
		rpipe = st->dnrpipe;
		flags = st->dnflags;
		if (st->rule.ptr != NULL)
			dr = st->rule.ptr;
	} else {
		pipe = r->dn.pipe;
		rpipe = r->dn.rpipe;
		flags = r->dn.flags;
	}
	if (pipe == 0 && rpipe == 0)
		return (0);
	if (PF_MTAG_R(*m0)->dn_flags & PF_DN_TAG_DONE)
		return (0);

	dndir = dr->direction;
	if (dndir == PF_INOUT)
		dndir = (st != NULL) ? st->direction : pd->dir;

	memset(&dnflow, 0, sizeof(dnflow));
	if (pd->dir != dndir && rpipe != 0)
		dnflow.rule.info = rpipe;
	else if (pd->dir == dndir && pipe != 0)
		dnflow.rule.info = pipe;
	else
		return (0);

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
		/* Dummynet hands the reinjected packet to if_output(). */
		if (mb_unmapped_to_ext(*m0, m0) != 0) {
			SDT_PROBE3(pf, ip, dummynet, error, pd, ENOMEM,
			    "unmapped mbuf");
			return (1);
		}
		if ((t = PF_MTAG_W(*m0)) == NULL)
			goto drop;
		t->dn_flags |= PF_DN_TAG_ROUTE_TO;
		t->dn_ifidx = ifp->if_index;
		t->dn_ifgen = ifp->if_idxgen;
		memset(t->dn_dst, 0, sizeof(t->dn_dst));
		memcpy(t->dn_dst, dst, dst->sa_len);
	}

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
	if (flags & PF_DN_IS_PIPE)
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
	SDT_PROBE4(pf, ip, dummynet, submit, pd, st, dnflow.rule.info,
	    dnflow.flags);
	ip_dn_io_ptr(m0, &dnflow);
	SDT_PROBE2(pf, ip, dummynet, returned, dnflow.rule.info,
	    (*m0 != NULL));
	if (*m0 == NULL)
		return (1);
	/* Passed straight through: continue as if it was never queued. */
	if ((t = PF_MTAG_W(*m0)) != NULL)
		pf_dn_clear(*m0, t);
	return (0);

drop:
	m_freem(*m0);
	*m0 = NULL;
	return (1);
}
