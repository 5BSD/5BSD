/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD divert(4) for pf "divert-packet port N": raw sockets of
 * protocol IPPROTO_DIVERT in the inet and inet6 domains.  A socket bound
 * to port N receives the packets pf diverts to that port, with the
 * address of the receiving interface (inbound) or the unspecified
 * address (outbound) as the source address.  A packet written back with
 * an unspecified destination address is sent out; with a local address
 * it is received on the interface that has that address.  Reinjected
 * packets carry PF_TAG_DIVERTED_PACKET so pf does not divert them again.
 *
 * This is the 5BSD implementation of the OpenBSD interface; it is not
 * related to the PF_DIVERT domain of ipdivert(4).
 */

#include "openbsd_compat.h"

#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <net/netisr.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#endif

#include <net/pfvar.h>

#undef	ip_output
#undef	ip6_output

#ifndef IPPROTO_DIVERT
#define	IPPROTO_DIVERT		258	/* OpenBSD and 5BSD value */
#endif

#define	DIVERT_SENDSPACE	(65536 + 100)
#define	DIVERT_RECVSPACE	(65536 + 100)

struct pfdiv_cb {
	LIST_ENTRY(pfdiv_cb)	 dc_list;
	struct socket		*dc_so;
	struct vnet		*dc_vnet;
	int			 dc_af;
	u_int16_t		 dc_port;	/* network order, 0 unbound */
};

static LIST_HEAD(, pfdiv_cb) pfdiv_list = LIST_HEAD_INITIALIZER(pfdiv_list);
static struct mtx pfdiv_mtx;
MTX_SYSINIT(pfdiv_mtx, &pfdiv_mtx, "pf divert", MTX_DEF);

static int
pfdiv_attach(struct socket *so, int proto, struct thread *td)
{
	struct pfdiv_cb *dc;
	int error;

	if (td != NULL && (error = priv_check(td, PRIV_NETINET_DIVERT)) != 0)
		return (error);
	error = soreserve(so, DIVERT_SENDSPACE, DIVERT_RECVSPACE);
	if (error != 0)
		return (error);
	dc = malloc(sizeof(*dc), M_PF, M_WAITOK | M_ZERO);
	dc->dc_so = so;
	dc->dc_vnet = so->so_vnet;
	dc->dc_af = so->so_proto->pr_domain->dom_family;
	so->so_pcb = dc;
	mtx_lock(&pfdiv_mtx);
	LIST_INSERT_HEAD(&pfdiv_list, dc, dc_list);
	mtx_unlock(&pfdiv_mtx);
	return (0);
}

static void
pfdiv_detach(struct socket *so)
{
	struct pfdiv_cb *dc = so->so_pcb;

	mtx_lock(&pfdiv_mtx);
	LIST_REMOVE(dc, dc_list);
	mtx_unlock(&pfdiv_mtx);
	so->so_pcb = NULL;
	free(dc, M_PF);
}

static int
pfdiv_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct pfdiv_cb *dc = so->so_pcb, *o;
	u_int16_t port;

	switch (dc->dc_af) {
	case AF_INET:
		if (nam->sa_family != AF_INET ||
		    nam->sa_len != sizeof(struct sockaddr_in))
			return (EINVAL);
		port = ((struct sockaddr_in *)nam)->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
		if (nam->sa_family != AF_INET6 ||
		    nam->sa_len != sizeof(struct sockaddr_in6))
			return (EINVAL);
		port = ((struct sockaddr_in6 *)nam)->sin6_port;
		break;
#endif
	default:
		return (EAFNOSUPPORT);
	}
	if (port == 0)
		return (EINVAL);
	mtx_lock(&pfdiv_mtx);
	LIST_FOREACH(o, &pfdiv_list, dc_list) {
		if (o != dc && o->dc_vnet == dc->dc_vnet &&
		    o->dc_af == dc->dc_af && o->dc_port == port) {
			mtx_unlock(&pfdiv_mtx);
			return (EADDRINUSE);
		}
	}
	dc->dc_port = port;
	mtx_unlock(&pfdiv_mtx);
	return (0);
}

static int
pfdiv_sockaddr(struct socket *so, struct sockaddr *sa)
{
	struct pfdiv_cb *dc = so->so_pcb;

	switch (dc->dc_af) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		*sin = (struct sockaddr_in){
			.sin_len = sizeof(*sin),
			.sin_family = AF_INET,
			.sin_port = dc->dc_port,
		};
		break;
	}
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		*sin6 = (struct sockaddr_in6){
			.sin6_len = sizeof(*sin6),
			.sin6_family = AF_INET6,
			.sin6_port = dc->dc_port,
		};
		break;
	}
#endif
	}
	return (0);
}

/*
 * OpenBSD recomputes the transport checksum of every packet written to a
 * divert socket (and the IPv4 header checksum of inbound ones).
 */
static int
pfdiv_cksum4(struct mbuf **mp, int inbound)
{
	struct mbuf *m = *mp;
	struct ip *ip = mtod(m, struct ip *);
	int off = ip->ip_hl << 2, len = ntohs(ip->ip_len);

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		if (len < off + (int)sizeof(struct tcphdr))
			return (EINVAL);
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		break;
	case IPPROTO_UDP:
		if (len < off + (int)sizeof(struct udphdr))
			return (EINVAL);
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
		break;
	case IPPROTO_ICMP:
		if (len < off + ICMP_MINLEN)
			return (EINVAL);
		m->m_pkthdr.csum_data = offsetof(struct icmp, icmp_cksum);
		break;
	default:
		goto hdr;
	}
	if ((ip->ip_off & htons(IP_MF | IP_OFFMASK)) != 0)
		goto hdr;	/* a fragment: no transport header to fix */
	m = *mp = m_pullup(m, off + m->m_pkthdr.csum_data + sizeof(u_short));
	if (m == NULL)
		return (ENOBUFS);
	ip = mtod(m, struct ip *);
	if (ip->ip_p == IPPROTO_ICMP) {
		*(u_short *)(mtod(m, caddr_t) + off + m->m_pkthdr.csum_data) =
		    0;
		*(u_short *)(mtod(m, caddr_t) + off + m->m_pkthdr.csum_data) =
		    in_cksum_skip(m, len, off);
	} else {
		*(u_short *)(mtod(m, caddr_t) + off + m->m_pkthdr.csum_data) =
		    in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    htons(ip->ip_p + len - off));
		in_delayed_cksum(m);
	}
	m->m_pkthdr.csum_flags &= ~(CSUM_DELAY_DATA | CSUM_DATA_VALID |
	    CSUM_PSEUDO_HDR);
hdr:
	if (inbound) {
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, off);
	}
	return (0);
}

static int
pfdiv_send4(struct socket *so, struct mbuf *m, struct sockaddr_in *sin)
{
	struct epoch_tracker et;
	struct ifaddr *ifa;
	struct ip *ip;
	int error, off;

	if (m->m_pkthdr.len > IP_MAXPACKET) {
		m_freem(m);
		return (EMSGSIZE);
	}
	if (m->m_len < (int)sizeof(struct ip) &&
	    (m = m_pullup(m, sizeof(struct ip))) == NULL)
		return (EINVAL);
	ip = mtod(m, struct ip *);
	off = ip->ip_hl << 2;
	if (ip->ip_v != IPVERSION || off < (int)sizeof(struct ip) ||
	    ntohs(ip->ip_len) != m->m_pkthdr.len || off > m->m_pkthdr.len) {
		m_freem(m);
		return (EINVAL);
	}
	if (m->m_len < off && (m = m_pullup(m, off)) == NULL)
		return (EINVAL);

	m->m_pkthdr.rcvif = NULL;
	m->m_nextpkt = NULL;
	M_SETFIB(m, so->so_fibnum);
	PF_MTAG_W(m)->flags |= PF_TAG_DIVERTED_PACKET;

	if (sin->sin_addr.s_addr == INADDR_ANY) {
		if ((error = pfdiv_cksum4(&m, 0)) != 0) {
			m_freem(m);
			return (error);
		}
		NET_EPOCH_ENTER(et);
		error = ip_output(m, NULL, NULL, IP_ALLOWBROADCAST |
		    IP_RAWOUTPUT, NULL, NULL);
		NET_EPOCH_EXIT(et);
		return (error);
	}

	/* Inbound: received on the interface that has the address. */
	NET_EPOCH_ENTER(et);
	ifa = ifa_ifwithaddr((struct sockaddr *)&(struct sockaddr_in){
	    .sin_len = sizeof(struct sockaddr_in), .sin_family = AF_INET,
	    .sin_addr = sin->sin_addr });
	if (ifa == NULL) {
		NET_EPOCH_EXIT(et);
		m_freem(m);
		return (EADDRNOTAVAIL);
	}
	m->m_pkthdr.rcvif = ifa->ifa_ifp;
	NET_EPOCH_EXIT(et);
	if ((error = pfdiv_cksum4(&m, 1)) != 0) {
		m_freem(m);
		return (error);
	}
	return (netisr_queue(NETISR_IP, m));
}

#ifdef INET6
static int
pfdiv_cksum6(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	int off, nxt = -1, len;
	u_short *sum;
	u_short csum;

	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off < 0)
		return (0);
	len = sizeof(*ip6) + ntohs(ip6->ip6_plen) - off;
	switch (nxt) {
	case IPPROTO_TCP:
		if (len < (int)sizeof(struct tcphdr))
			return (EINVAL);
		off += offsetof(struct tcphdr, th_sum);
		break;
	case IPPROTO_UDP:
		if (len < (int)sizeof(struct udphdr))
			return (EINVAL);
		off += offsetof(struct udphdr, uh_sum);
		break;
	case IPPROTO_ICMPV6:
		if (len < (int)sizeof(struct icmp6_hdr))
			return (EINVAL);
		off += offsetof(struct icmp6_hdr, icmp6_cksum);
		break;
	default:
		return (0);
	}
	m = *mp = m_pullup(m, off + sizeof(u_short));
	if (m == NULL)
		return (ENOBUFS);
	sum = (u_short *)(mtod(m, caddr_t) + off);
	*sum = 0;
	off -= (nxt == IPPROTO_TCP ? offsetof(struct tcphdr, th_sum) :
	    nxt == IPPROTO_UDP ? offsetof(struct udphdr, uh_sum) :
	    offsetof(struct icmp6_hdr, icmp6_cksum));
	csum = in6_cksum(m, nxt, off, len);
	if (csum == 0 && nxt == IPPROTO_UDP)
		csum = 0xffff;
	*sum = csum;
	m->m_pkthdr.csum_flags &= ~(CSUM_DELAY_DATA_IPV6 | CSUM_DATA_VALID |
	    CSUM_PSEUDO_HDR);
	return (0);
}

static int
pfdiv_send6(struct socket *so, struct mbuf *m, struct sockaddr_in6 *sin6)
{
	struct epoch_tracker et;
	struct ifaddr *ifa;
	struct ip6_hdr *ip6;
	struct sockaddr_in6 a;
	int error;

	if (m->m_len < (int)sizeof(struct ip6_hdr) &&
	    (m = m_pullup(m, sizeof(struct ip6_hdr))) == NULL)
		return (EINVAL);
	ip6 = mtod(m, struct ip6_hdr *);
	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION ||
	    sizeof(*ip6) + ntohs(ip6->ip6_plen) != (u_int)m->m_pkthdr.len) {
		m_freem(m);
		return (EINVAL);
	}

	m->m_pkthdr.rcvif = NULL;
	m->m_nextpkt = NULL;
	M_SETFIB(m, so->so_fibnum);
	PF_MTAG_W(m)->flags |= PF_TAG_DIVERTED_PACKET;
	if ((error = pfdiv_cksum6(&m)) != 0) {
		m_freem(m);
		return (error);
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
		NET_EPOCH_ENTER(et);
		error = ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
		NET_EPOCH_EXIT(et);
		return (error);
	}

	a = *sin6;
	a.sin6_port = 0;
	if (sa6_embedscope(&a, 0) != 0) {
		m_freem(m);
		return (EINVAL);
	}
	NET_EPOCH_ENTER(et);
	ifa = ifa_ifwithaddr((struct sockaddr *)&a);
	if (ifa == NULL) {
		NET_EPOCH_EXIT(et);
		m_freem(m);
		return (EADDRNOTAVAIL);
	}
	m->m_pkthdr.rcvif = ifa->ifa_ifp;
	NET_EPOCH_EXIT(et);
	return (netisr_queue(NETISR_IPV6, m));
}
#endif

static int
pfdiv_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
    struct mbuf *control, struct thread *td)
{
	struct pfdiv_cb *dc = so->so_pcb;

	if (control != NULL)
		m_freem(control);
	if (nam == NULL) {
		m_freem(m);
		return (EDESTADDRREQ);
	}
	switch (dc->dc_af) {
	case AF_INET:
		if (nam->sa_family != AF_INET ||
		    nam->sa_len != sizeof(struct sockaddr_in))
			break;
		return (pfdiv_send4(so, m, (struct sockaddr_in *)nam));
#ifdef INET6
	case AF_INET6:
		if (nam->sa_family != AF_INET6 ||
		    nam->sa_len != sizeof(struct sockaddr_in6))
			break;
		return (pfdiv_send6(so, m, (struct sockaddr_in6 *)nam));
#endif
	}
	m_freem(m);
	return (EAFNOSUPPORT);
}

/* Called by pf with the packet that matched "divert-packet port". */
static void
pfdiv_input(int af, struct mbuf *m, int dir, u_int16_t port)
{
	struct pfdiv_cb *dc;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ifaddr *ifa;
	struct socket *so;
	union {
		struct sockaddr		sa;
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
	} su;

	memset(&su, 0, sizeof(su));
	su.sa.sa_family = af;
	su.sa.sa_len = af == AF_INET ? sizeof(su.sin) : sizeof(su.sin6);
	if (dir == PF_IN && ifp != NULL) {
		NET_EPOCH_ASSERT();
		CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != af)
				continue;
			if (af == AF_INET) {
				su.sin.sin_addr =
				    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				break;
			}
			/*
			 * Prefer an address that needs no scope: the
			 * program writes the packet back to this address.
			 */
			su.sin6.sin6_addr = ((struct sockaddr_in6 *)
			    ifa->ifa_addr)->sin6_addr;
			if (!IN6_IS_SCOPE_LINKLOCAL(&su.sin6.sin6_addr))
				break;
		}
		if (af == AF_INET6) {
			if (IN6_IS_SCOPE_LINKLOCAL(&su.sin6.sin6_addr))
				(void)sa6_recoverscope(&su.sin6);
		}
	}

	mtx_lock(&pfdiv_mtx);
	LIST_FOREACH(dc, &pfdiv_list, dc_list)
		if (dc->dc_vnet == curvnet && dc->dc_af == af &&
		    dc->dc_port == port)
			break;
	if (dc == NULL) {
		mtx_unlock(&pfdiv_mtx);
		m_freem(m);
		return;
	}
	so = dc->dc_so;
	SOCKBUF_LOCK(&so->so_rcv);
	if (sbappendaddr_locked(&so->so_rcv, &su.sa, m, NULL) == 0) {
		SOCKBUF_UNLOCK(&so->so_rcv);
		mtx_unlock(&pfdiv_mtx);
		m_freem(m);
		return;
	}
	sorwakeup_locked(so);
	mtx_unlock(&pfdiv_mtx);
}

void
divert_packet(struct mbuf *m, int dir, u_int16_t port)
{
	pfdiv_input(AF_INET, m, dir, port);
}

#ifdef INET6
void
divert6_packet(struct mbuf *m, int dir, u_int16_t port)
{
	pfdiv_input(AF_INET6, m, dir, port);
}
#endif

static struct protosw pfdiv_protosw = {
	.pr_type =	SOCK_RAW,
	.pr_protocol =	IPPROTO_DIVERT,
	.pr_flags =	PR_ATOMIC | PR_ADDR,
	.pr_attach =	pfdiv_attach,
	.pr_detach =	pfdiv_detach,
	.pr_bind =	pfdiv_bind,
	.pr_send =	pfdiv_send,
	.pr_sockaddr =	pfdiv_sockaddr,
};

#ifdef INET6
static struct protosw pfdiv6_protosw = {
	.pr_type =	SOCK_RAW,
	.pr_protocol =	IPPROTO_DIVERT,
	.pr_flags =	PR_ATOMIC | PR_ADDR,
	.pr_attach =	pfdiv_attach,
	.pr_detach =	pfdiv_detach,
	.pr_bind =	pfdiv_bind,
	.pr_send =	pfdiv_send,
	.pr_sockaddr =	pfdiv_sockaddr,
};
#endif

void	pf_divert_attach(void);
void
pf_divert_attach(void)
{
	int error;

	error = protosw_register(&inetdomain, &pfdiv_protosw);
	if (error != 0)
		printf("pf: divert(4) for inet not registered: %d\n", error);
#ifdef INET6
	error = protosw_register(&inet6domain, &pfdiv6_protosw);
	if (error != 0)
		printf("pf: divert(4) for inet6 not registered: %d\n", error);
#endif
}
