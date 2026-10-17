/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * OpenBSD network stack entry points used by OpenBSD PF, implemented on
 * the 5BSD stack: route lookups (rtalloc on FIB nexthops), IP output,
 * forwarding and fragmentation with OpenBSD calling conventions,
 * deferred sends (ip_send) that avoid re-entering pf with its locks
 * held, protocol checksums, pcb lookups, divert(4) and interface
 * attachment for the pflog/pfsync/pflow pseudo-interfaces.
 */

#include "openbsd_compat.h"

#include <sys/module.h>
#include <netinet/sctp_crc32.h>
#include <net/pfvar.h>
#include <net/if_clone.h>

#undef	if_clone		/* this file uses the 5BSD cloner API */
#undef	if_attach
#undef	if_detach
#undef	ip_output
#undef	ip6_output
#undef	ip_forward
#undef	ip6_forward
#undef	icmp_error
#undef	icmp6_error
#undef	ip_fragment
#undef	ip6_fragment
#undef	in_pcbref
#undef	ip_moptions
#undef	in_addmulti
#undef	in_delmulti
#undef	socreate
#undef	sobind
#undef	soclose
#undef	sosend
#undef	in_pcblookup
#undef	in6_pcblookup
#undef	bpfattach

/* ------------------------------------------------------------------ */
/* Routes: OpenBSD rtentry results backed by referenced nexthops       */
/* ------------------------------------------------------------------ */

static uma_zone_t obsd_rt_zone;

static void
obsd_rt_zone_init(void *arg)
{
	obsd_rt_zone = uma_zcreate("pf rtentry", sizeof(struct obsd_rtentry),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
}
SYSINIT(obsd_rt_zone, SI_SUB_PROTO_FIREWALL, SI_ORDER_ANY,
    obsd_rt_zone_init, NULL);

#define	OBSD_RTF_UP		0x1
#define	OBSD_RTF_GATEWAY	0x2
#define	OBSD_RTF_HOST		0x4
#define	OBSD_RTF_REJECT		0x8
#define	OBSD_RTF_BLACKHOLE	0x1000

static struct rtentry *
obsd_rt_from_nh(struct nhop_object *nh)
{
	struct obsd_rtentry *rt;

	if (nh == NULL)
		return (NULL);
	rt = uma_zalloc(obsd_rt_zone, M_NOWAIT | M_ZERO);
	if (rt == NULL) {
		nhop_free(nh);
		return (NULL);
	}
	rt->rt_nh = nh;
	rt->rt_ifa = nh->nh_ifa;
	rt->rt_ifidx = nh->nh_ifp != NULL ? nh->nh_ifp->if_index : 0;
	rt->rt_flags = OBSD_RTF_UP;
	if (nh->nh_flags & NHF_GATEWAY)
		rt->rt_flags |= OBSD_RTF_GATEWAY;
	if (nh->nh_flags & NHF_HOST)
		rt->rt_flags |= OBSD_RTF_HOST;
	if (nh->nh_flags & NHF_REJECT)
		rt->rt_flags |= OBSD_RTF_REJECT;
	if (nh->nh_flags & NHF_BLACKHOLE)
		rt->rt_flags |= OBSD_RTF_BLACKHOLE;
	return (rt);
}

static struct rtentry *
obsd_rtalloc_flow(struct sockaddr *dst, unsigned int tableid, uint32_t flowid)
{
	struct nhop_object *nh = NULL;
	struct epoch_tracker et;

	if (tableid >= rt_numfibs)
		return (NULL);
	NET_EPOCH_ENTER(et);
	switch (dst->sa_family) {
	case AF_INET:
		nh = fib4_lookup(tableid, satosin(dst)->sin_addr, 0, NHR_REF,
		    flowid);
		break;
#ifdef INET6
	case AF_INET6:
		nh = fib6_lookup(tableid, &satosin6(dst)->sin6_addr,
		    satosin6(dst)->sin6_scope_id, NHR_REF, flowid);
		break;
#endif
	}
	NET_EPOCH_EXIT(et);
	return (obsd_rt_from_nh(nh));
}

struct rtentry *
rtalloc(struct sockaddr *dst, int flags, unsigned int tableid)
{
	return (obsd_rtalloc_flow(dst, tableid, 0));
}

struct rtentry *
rtalloc_mpath(struct sockaddr *dst, uint32_t *src, unsigned int tableid)
{
	uint32_t flowid = 0;

	if (src != NULL)
		flowid = src[0];
	return (obsd_rtalloc_flow(dst, tableid, flowid));
}

struct rtentry *
rtable_iterate(struct rtentry *rt)
{
	/* 5BSD exposes multipath members through nexthop groups only. */
	rtfree(rt);
	return (NULL);
}

void
rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	nhop_free(rt->rt_nh);
	uma_zfree(obsd_rt_zone, rt);
}

int
rtisvalid(struct rtentry *rt)
{
	if (rt == NULL)
		return (0);
	if (!NH_IS_VALID(rt->rt_nh))
		return (0);
	if (rt->rt_flags & (OBSD_RTF_REJECT | OBSD_RTF_BLACKHOLE))
		return (0);
	return (1);
}

int
rtable_exists(unsigned int tableid)
{
	return (tableid < rt_numfibs);
}

unsigned int
rtable_l2(unsigned int tableid)
{
	/* Routing domains on FIBs (rdomain(4), net/route/route_rdomain.c). */
	return (rt_fib_l2(tableid));
}

/* Next-hop destination for an interface output call. */
static const struct sockaddr *
obsd_rt_nexthop(struct rtentry *rt, const struct sockaddr *dst)
{
	if (rt != NULL && (rt->rt_nh->nh_flags & NHF_GATEWAY))
		return (&rt->rt_nh->gw_sa);
	return (dst);
}

/* ------------------------------------------------------------------ */
/* Checksums                                                           */
/* ------------------------------------------------------------------ */

void
obsd_in_hdr_cksum_out(struct mbuf *m)
{
	struct ip *ip = mtod(m, struct ip *);

	ip->ip_sum = 0;
	ip->ip_sum = in_cksum_hdr(ip);
	m->m_pkthdr.csum_flags &= ~CSUM_IP;
}

/*
 * OpenBSD semantics: M_*_CSUM_OUT asks for a complete checksum of the
 * transport header and payload.  The pf glue only lets pf-set flags
 * reach here (delayed checksums of the 5BSD stack are finalised before
 * pf_test()), so the checksum is computed from scratch in software.
 */
void
in_proto_cksum_out(struct mbuf *m, struct ifnet *ifp)
{
	struct ip *ip = mtod(m, struct ip *);
	int hlen, len;
	u_int16_t csum;

	hlen = ip->ip_hl << 2;
	len = ntohs(ip->ip_len) - hlen;
	if (m->m_pkthdr.csum_flags & CSUM_IP_TCP) {
		struct tcphdr *th;

		if (m->m_len < hlen + (int)sizeof(*th) &&
		    (m = m_pullup(m, hlen + sizeof(*th))) == NULL)
			return;
		th = (struct tcphdr *)(mtod(m, caddr_t) + hlen);
		th->th_sum = 0;
		th->th_sum = obsd_in4_cksum(m, IPPROTO_TCP, hlen, len);
	} else if (m->m_pkthdr.csum_flags & CSUM_IP_UDP) {
		struct udphdr *uh;

		if (m->m_len < hlen + (int)sizeof(*uh) &&
		    (m = m_pullup(m, hlen + sizeof(*uh))) == NULL)
			return;
		uh = (struct udphdr *)(mtod(m, caddr_t) + hlen);
		uh->uh_sum = 0;
		csum = obsd_in4_cksum(m, IPPROTO_UDP, hlen, len);
		uh->uh_sum = csum == 0 ? 0xffff : csum;
	}
	/* M_*_CSUM_OUT sets the IPv4 and IPv6 flags: clear both. */
	m->m_pkthdr.csum_flags &= ~(CSUM_IP_TCP | CSUM_IP_UDP |
	    CSUM_IP6_TCP | CSUM_IP6_UDP);
}

#ifdef INET6
void
in6_proto_cksum_out(struct mbuf *m, struct ifnet *ifp)
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	int off, nxt, plen, sumoff;
	u_int16_t csum;

	if ((m->m_pkthdr.csum_flags & (CSUM_IP6_TCP | CSUM_IP6_UDP)) == 0) {
		m->m_pkthdr.csum_flags &= ~(CSUM_IP_TCP | CSUM_IP_UDP);
		return;
	}
	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off < (int)sizeof(*ip6))
		goto done;
	plen = sizeof(*ip6) + ntohs(ip6->ip6_plen) - off;
	/* Extension headers may leave the transport header in a later mbuf. */
	if (nxt == IPPROTO_TCP)
		sumoff = off + offsetof(struct tcphdr, th_sum);
	else if (nxt == IPPROTO_UDP)
		sumoff = off + offsetof(struct udphdr, uh_sum);
	else
		goto done;
	if (plen <= 0 || sumoff + (int)sizeof(csum) > m->m_pkthdr.len)
		goto done;
	csum = 0;
	m_copyback(m, sumoff, sizeof(csum), &csum, M_NOWAIT);
	csum = in6_cksum(m, nxt, off, plen);
	if (nxt == IPPROTO_UDP && csum == 0)
		csum = 0xffff;
	m_copyback(m, sumoff, sizeof(csum), &csum, M_NOWAIT);
done:
	m->m_pkthdr.csum_flags &= ~(CSUM_IP6_TCP | CSUM_IP6_UDP |
	    CSUM_IP_TCP | CSUM_IP_UDP);
}
#endif

/* Finalise every checksum before handing a pf packet to the stack. */
static void
obsd_cksum_out(struct mbuf *m, int af)
{
	switch (af) {
	case AF_INET:
		in_proto_cksum_out(m, NULL);
		obsd_in_hdr_cksum_out(m);
		break;
#ifdef INET6
	case AF_INET6:
		in6_proto_cksum_out(m, NULL);
		break;
#endif
	}
}

#ifdef INET6
int
frag6_deletefraghdr(struct mbuf *m, int offset)
{
	return (ip6_deletefraghdr(m, offset, M_NOWAIT));
}
#endif

/* ------------------------------------------------------------------ */
/* Output, forwarding and errors                                       */
/* ------------------------------------------------------------------ */

int
obsd_ip_output(struct mbuf *m, struct mbuf *opt, struct route *ro, int flags,
    struct obsd_ip_moptions *oimo, struct inpcb *inp, u_int32_t ipsecflowinfo)
{
	struct epoch_tracker et;
	struct ip_moptions imo, *imop = NULL;
	struct ifnet *ifp = NULL;
	int error;

	in_proto_cksum_out(m, NULL);
	NET_EPOCH_ENTER(et);
	if (oimo != NULL) {
		memset(&imo, 0, sizeof(imo));
		if (oimo->imo_ifidx != 0)
			ifp = ifnet_byindex(oimo->imo_ifidx);
		imo.imo_multicast_ifp = ifp;
		imo.imo_multicast_ttl = oimo->imo_ttl;
		imo.imo_multicast_loop = oimo->imo_loop;
		imo.imo_multicast_vif = -1;
		STAILQ_INIT(&imo.imo_head);
		imop = &imo;
	}
	error = ip_output(m, opt, NULL, flags & IP_RAWOUTPUT, imop, inp);
	NET_EPOCH_EXIT(et);
	return (error);
}

struct in_multi *
obsd_in_addmulti(struct in_addr *ap, struct ifnet *ifp)
{
	struct in_multi *inm = NULL;

	if (in_joingroup(ifp, ap, NULL, &inm) != 0)
		return (NULL);
	return (inm);
}

void
obsd_in_delmulti(struct in_multi *inm)
{
	if (inm != NULL)
		(void)in_leavegroup(inm, NULL);
}

struct mbuf *
obsd_mclgetl(struct mbuf *m, int how, u_int len)
{
	int size;

	if (len <= MCLBYTES)
		size = MCLBYTES;
	else if (len <= MJUMPAGESIZE)
		size = MJUMPAGESIZE;
	else if (len <= MJUM9BYTES)
		size = MJUM9BYTES;
	else
		return (m);
	(void)m_cljget(m, how, size);
	return (m);
}

#ifdef INET6
int
obsd_ip6_output(struct mbuf *m, struct ip6_pktopts *opt, struct route_in6 *ro,
    int flags, struct ip6_moptions *im6o, struct inpcb *inp)
{
	struct epoch_tracker et;
	int error;

	in6_proto_cksum_out(m, NULL);
	NET_EPOCH_ENTER(et);
	error = ip6_output(m, opt, NULL, 0, im6o, NULL, inp);
	NET_EPOCH_EXIT(et);
	return (error);
}
#endif

void
obsd_ip_forward(struct mbuf *m, struct ifnet *ifp, struct route *ro, int flags)
{
	struct epoch_tracker et;

	obsd_cksum_out(m, AF_INET);
	NET_EPOCH_ENTER(et);
	ip_forward(m, 0);
	NET_EPOCH_EXIT(et);
}

#ifdef INET6
void
obsd_ip6_forward(struct mbuf *m, struct route_in6 *ro, int flags)
{
	struct epoch_tracker et;

	obsd_cksum_out(m, AF_INET6);
	NET_EPOCH_ENTER(et);
	ip6_forward(m, 0);
	NET_EPOCH_EXIT(et);
}
#endif

/*
 * Deferred packet transmission.  OpenBSD queues ip_send()/ip6_send() and
 * icmp errors to the softnet thread; pf calls them with its locks held,
 * so sending synchronously would re-enter pf through pfil.
 */
struct obsd_sendq_item {
	int	af;
	int	kind;
#define	OBSD_SEND_OUTPUT	1
#define	OBSD_SEND_ICMP		2
	int	type, code, param;
	u_int32_t dest;
	struct vnet *vnet;	/* vnet of the pf instance that queued it */
	int	rcvif;		/* m_pkthdr.rcvif was serialised */
};
static struct mbuf_queue obsd_sendq;
static struct task obsd_send_task;

static void
obsd_send_run(void *arg)
{
	struct epoch_tracker et;
	struct mbuf_list ml;
	struct mbuf *m;
	struct m_tag *mtag;
	struct obsd_sendq_item *it;

	mq_delist(&obsd_sendq, &ml);
	while ((m = ml_dequeue(&ml)) != NULL) {
		mtag = m_tag_locate(m, MTAG_ABI_COMPAT, 0x50465351 /* PFSQ */,
		    NULL);
		if (mtag == NULL) {
			m_freem(m);
			continue;
		}
		it = (struct obsd_sendq_item *)(mtag + 1);
		CURVNET_SET(it->vnet);
		NET_EPOCH_ENTER(et);
		/*
		 * The receiving interface may have gone while the packet
		 * was queued.  icmp_error() and icmp6_error() use it; a
		 * packet pf builds itself (ip_send()) can go without.
		 */
		if (it->rcvif && m_rcvif_restore(m) == NULL) {
			if (it->kind != OBSD_SEND_OUTPUT) {
				NET_EPOCH_EXIT(et);
				CURVNET_RESTORE();
				m_freem(m);
				continue;
			}
			m->m_pkthdr.rcvif = NULL;
		}
		switch (it->kind) {
		case OBSD_SEND_OUTPUT: {
			int af = it->af;	/* "it" lives in the tag */

			m_tag_delete(m, mtag);
			/*
			 * OpenBSD's M_*_CSUM_OUT asks for the whole checksum;
			 * the 5BSD stack expects a seeded one.  Compute it.
			 */
			obsd_cksum_out(m, af);
			if (af == AF_INET)
				ip_output(m, NULL, NULL, 0, NULL, NULL);
#ifdef INET6
			else
				ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
#endif
			break;
		}
		case OBSD_SEND_ICMP:
			if (it->af == AF_INET) {
				int type = it->type, code = it->code,
				    param = it->param;
				u_int32_t dest = it->dest;

				m_tag_delete(m, mtag);
				icmp_error(m, type, code, dest, param);
			}
#ifdef INET6
			else {
				int type = it->type, code = it->code,
				    param = it->param;

				m_tag_delete(m, mtag);
				icmp6_error(m, type, code, param);
			}
#endif
			break;
		default:
			m_freem(m);
		}
		NET_EPOCH_EXIT(et);
		CURVNET_RESTORE();
	}
}

/* Send what a vnet's pf queued before that vnet goes away. */
void	obsd_sendq_drain(void);
void
obsd_sendq_drain(void)
{
	taskq_del_barrier(systq, &obsd_send_task);
	obsd_send_run(NULL);
}

static void
obsd_sendq_init(void *arg)
{
	mq_init(&obsd_sendq, 4096, IPL_SOFTNET);
	task_set(&obsd_send_task, obsd_send_run, NULL);
}
SYSINIT(obsd_sendq, SI_SUB_PROTO_FIREWALL, SI_ORDER_SECOND,
    obsd_sendq_init, NULL);

static void
obsd_sendq_enqueue(struct mbuf *m, int af, int kind, int type, int code,
    u_int32_t dest, int param)
{
	struct m_tag *mtag;
	struct obsd_sendq_item *it;

	mtag = m_tag_alloc(MTAG_ABI_COMPAT, 0x50465351, sizeof(*it), M_NOWAIT);
	if (mtag == NULL) {
		m_freem(m);
		return;
	}
	it = (struct obsd_sendq_item *)(mtag + 1);
	it->af = af;
	it->kind = kind;
	it->type = type;
	it->code = code;
	it->dest = dest;
	it->param = param;
	it->vnet = curvnet;
	/* No interface pointer while queued (see obsd_send_run()). */
	it->rcvif = 0;
	if ((m->m_pkthdr.csum_flags & CSUM_SND_TAG) == 0 &&
	    m->m_pkthdr.rcvif != NULL) {
		m_rcvif_serialize(m);
		it->rcvif = 1;
	}
	m_tag_prepend(m, mtag);
	if (mq_enqueue(&obsd_sendq, m) == 0)
		task_add(systq, &obsd_send_task);
}

void
ip_send(struct mbuf *m)
{
	in_proto_cksum_out(m, NULL);
	obsd_sendq_enqueue(m, AF_INET, OBSD_SEND_OUTPUT, 0, 0, 0, 0);
}

#ifdef INET6
void
ip6_send(struct mbuf *m)
{
	in6_proto_cksum_out(m, NULL);
	obsd_sendq_enqueue(m, AF_INET6, OBSD_SEND_OUTPUT, 0, 0, 0, 0);
}
#endif

void
obsd_icmp_error(struct mbuf *m, int type, int code, u_int32_t dest, int mtu)
{
	obsd_sendq_enqueue(m, AF_INET, OBSD_SEND_ICMP, type, code, dest, mtu);
}

#ifdef INET6
void
obsd_icmp6_error(struct mbuf *m, int type, int code, int param)
{
	obsd_sendq_enqueue(m, AF_INET6, OBSD_SEND_ICMP, type, code, 0, param);
}
#endif

/* ------------------------------------------------------------------ */
/* Fragmentation and interface output (pf_route, pf_refragment6)       */
/* ------------------------------------------------------------------ */

int
obsd_ip_fragment(struct mbuf *m, struct mbuf_list *ml, struct ifnet *ifp,
    u_long mtu)
{
	struct ip *ip = mtod(m, struct ip *);
	struct mbuf *n;
	int error;

	ml_init(ml);
	in_proto_cksum_out(m, NULL);
	/* ip_fragment() computes header checksums only for CSUM_IP packets. */
	m->m_pkthdr.csum_flags |= CSUM_IP;
	error = ip_fragment(ip, &m, mtu, ifp->if_hwassist);
	if (error) {
		/* Native failure may leave a partially constructed packet chain. */
		for (; m != NULL; m = n) {
			n = m->m_nextpkt;
			m->m_nextpkt = NULL;
			m_freem(m);
		}
		return (error);
	}
	for (; m != NULL; m = n) {
		n = m->m_nextpkt;
		m->m_nextpkt = NULL;
		ml_enqueue(ml, m);
	}
	return (0);
}

#ifdef INET6
int
obsd_ip6_fragment(struct mbuf *m, struct mbuf_list *ml, int hlen,
    u_char nextproto, u_long mtu)
{
	struct mbuf *n;
	int error;

	ml_init(ml);
	/* Match OpenBSD's minimum fragment payload; avoid a zero-length loop. */
	if (mtu < (u_long)hlen + sizeof(struct ip6_frag) + 8) {
		m_freem(m);
		return (EMSGSIZE);
	}
	/* OpenBSD passes the MTU, 5BSD the payload of one fragment. */
	error = ip6_fragment(NULL, m, hlen, nextproto,
	    (mtu - hlen - sizeof(struct ip6_frag)) & ~7,
	    htonl(ip6_randomid()));
	/* Native ip6_fragment() appends fragments after the original packet. */
	n = m->m_nextpkt;
	m->m_nextpkt = NULL;
	m_freem(m);
	for (m = n; m != NULL; m = n) {
		n = m->m_nextpkt;
		m->m_nextpkt = NULL;
		if (error != 0)
			m_freem(m);
		else
			ml_enqueue(ml, m);
	}
	return (error);
}
#endif

static int
obsd_ifoutput(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
    struct rtentry *rt)
{
	struct epoch_tracker et;
	int error;

	/*
	 * As ip_output() and ip6_output(): an interface without
	 * IFCAP_MEXTPG cannot take unmapped (sendfile, KTLS) mbufs.
	 */
	if ((ifp->if_capenable & IFCAP_MEXTPG) == 0 &&
	    (error = mb_unmapped_to_ext(m, &m)) != 0)
		return (error);
	NET_EPOCH_ENTER(et);
	error = ifp->if_output(ifp, m, obsd_rt_nexthop(rt, dst), NULL);
	NET_EPOCH_EXIT(et);
	return (error);
}

/*
 * Another interface of this VNET that uses kif (FreeBSD allows two
 * interfaces one name; pfi_detach_ifnet() hands the kif over to it).
 * Called with PF_LOCK held; does not sleep.
 */
/* Whether ifp is (still) on the current VNET's interface list. */
bool
obsd_if_linked(struct ifnet *ifp)
{
	struct epoch_tracker et;
	struct ifnet *iter;

	NET_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(iter, &V_ifnet, if_link)
		if (iter == ifp)
			break;
	NET_EPOCH_EXIT(et);
	return (iter != NULL);
}

struct ifnet *
obsd_if_find_pfkif(void *kif, struct ifnet *skip)
{
	struct epoch_tracker et;
	struct ifnet *ifp;

	NET_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link)
		if (ifp != skip && ifp->if_pf_kif == kif &&
		    (ifp->if_flags & IFF_DYING) == 0)
			break;
	NET_EPOCH_EXIT(et);
	return (ifp);
}

int
if_output_obsd(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	return (obsd_ifoutput(ifp, m, dst, rt));
}

/*
 * Returns non-zero when the packet was handled (sent, or dropped with
 * an error, *mp may be NULL); zero when it is too big for the interface
 * and the caller has to fragment or send an error.  af is the packet's
 * family; nh the link-layer next hop (route-to's gateway or destination).
 */
int
obsd_output_tso(struct ifnet *ifp, struct mbuf **mp, int af,
    const struct sockaddr *nh, u_int mtu)
{
	struct mbuf *m = *mp;

	/*
	 * The software checksums here and in the caller's fragmentation
	 * path, and the interface, need mapped data (see obsd_ifoutput()).
	 */
	if ((ifp->if_capenable & IFCAP_MEXTPG) == 0 &&
	    mb_unmapped_to_ext(m, mp) != 0)
		return (1);		/* freed, *mp is NULL */
	m = *mp;
	if (m->m_pkthdr.len > mtu &&
	    (m->m_pkthdr.csum_flags & CSUM_TSO & ifp->if_hwassist) == 0)
		return (0);
	obsd_cksum_out(m, af);
	/* route-to skips ip_output(): finish a delayed SCTP CRC32c here. */
	if (m->m_pkthdr.csum_flags & (CSUM_SCTP | CSUM_SCTP_IPV6) &
	    ~ifp->if_hwassist) {
		int nxt, off;
		uint32_t sum = 0;

		if (af == AF_INET)
			off = mtod(m, struct ip *)->ip_hl << 2;
		else {
			nxt = -1;
			off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
			if (nxt != IPPROTO_SCTP)
				off = -1;
		}
		if (off < 0 || off + 12 > m->m_pkthdr.len) {
			m_freem(m);
			*mp = NULL;
			return (1);
		}

		/* As sctp_delayed_cksum(), which needs options SCTP. */
		m_copyback(m, off + 8, sizeof(sum), &sum, M_NOWAIT);
		sum = sctp_calculate_cksum(m, off);
		m_copyback(m, off + 8, sizeof(sum), &sum, M_NOWAIT);
		m->m_pkthdr.csum_flags &= ~(CSUM_SCTP | CSUM_SCTP_IPV6);
	}
	*mp = NULL;
	(void)obsd_ifoutput(ifp, m, nh, NULL);
	return (1);
}

int
if_output_tso(struct ifnet *ifp, struct mbuf **mp, struct sockaddr *dst,
    struct rtentry *rt, u_int mtu)
{
	return (obsd_output_tso(ifp, mp, dst->sa_family,
	    obsd_rt_nexthop(rt, dst), mtu));
}

int
if_output_ml(struct ifnet *ifp, struct mbuf_list *ml, struct sockaddr *dst,
    struct rtentry *rt)
{
	struct mbuf *m;
	int error = 0;

	while ((m = ml_dequeue(ml)) != NULL) {
		error = obsd_ifoutput(ifp, m, dst, rt);
		if (error)
			break;
	}
	ml_purge(ml);
	return (error);
}

/* Delayed packets (pf "set delay") are sent on the interface directly. */
int
if_enqueue(struct ifnet *ifp, struct mbuf *m)
{
	struct epoch_tracker et;
	int error;

	NET_EPOCH_ENTER(et);
	error = ifp->if_transmit(ifp, m);
	NET_EPOCH_EXIT(et);
	return (error);
}

/* ------------------------------------------------------------------ */
/* pcb lookups: OpenBSD tables are tokens for the 5BSD pcbinfos        */
/* ------------------------------------------------------------------ */

struct inpcbtable *const obsd_tcbtable = (struct inpcbtable *)(uintptr_t)1;
struct inpcbtable *const obsd_udbtable = (struct inpcbtable *)(uintptr_t)2;
struct inpcbtable *const obsd_tcb6table = (struct inpcbtable *)(uintptr_t)3;
struct inpcbtable *const obsd_udb6table = (struct inpcbtable *)(uintptr_t)4;

static struct inpcbinfo *
obsd_pcbinfo(struct inpcbtable *t)
{
	switch ((uintptr_t)t) {
	case 1:
	case 3:
		return (&V_tcbinfo);
	default:
		return (&V_udbinfo);
	}
}

static struct inpcb *
obsd_pcb_ref_unlock(struct inpcb *inp)
{
	if (inp == NULL)
		return (NULL);
	in_pcbref(inp);
	INP_RUNLOCK(inp);
	return (inp);
}

struct inpcb *
obsd_in_pcblookup(struct inpcbtable *t, struct in_addr faddr, u_int fport,
    struct in_addr laddr, u_int lport, u_int rtable)
{
	return (obsd_pcb_ref_unlock(in_pcblookup(obsd_pcbinfo(t), faddr, fport,
	    laddr, lport, INPLOOKUP_RLOCKPCB, NULL)));
}

struct inpcb *
obsd_in_pcblookup_listen(struct inpcbtable *t, struct in_addr laddr,
    u_int lport, struct mbuf *m, u_int rtable)
{
	struct in_addr any = { INADDR_ANY };

	return (obsd_pcb_ref_unlock(in_pcblookup(obsd_pcbinfo(t), any, 0,
	    laddr, lport, INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, NULL)));
}

#ifdef INET6
struct inpcb *
obsd_in6_pcblookup(struct inpcbtable *t, const struct in6_addr *faddr,
    u_int fport, const struct in6_addr *laddr, u_int lport, u_int rtable)
{
	return (obsd_pcb_ref_unlock(in6_pcblookup(obsd_pcbinfo(t),
	    __DECONST(struct in6_addr *, faddr), fport,
	    __DECONST(struct in6_addr *, laddr), lport, INPLOOKUP_RLOCKPCB,
	    NULL)));
}

struct inpcb *
obsd_in6_pcblookup_listen(struct inpcbtable *t, struct in6_addr *laddr,
    u_int lport, struct mbuf *m, u_int rtable)
{
	return (obsd_pcb_ref_unlock(in6_pcblookup(obsd_pcbinfo(t),
	    &in6addr_any, 0, laddr, lport,
	    INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB, NULL)));
}
#endif

struct inpcb *
obsd_in_pcbref(struct inpcb *inp)
{
	if (inp != NULL)
		in_pcbref(inp);
	return (inp);
}

/*
 * pf drops pcb references with its own locks held, while the stack holds
 * the pcb lock when it calls into pf: never take the pcb lock here.  A
 * reference that is not the last is released directly; the last one (the
 * stack already freed the pcb) is released from a task.
 */
struct obsd_pcbrele {
	STAILQ_ENTRY(obsd_pcbrele) r_next;
	struct inpcb	*r_inp;
};
static STAILQ_HEAD(, obsd_pcbrele) obsd_pcbrele_q =
    STAILQ_HEAD_INITIALIZER(obsd_pcbrele_q);
static struct mtx obsd_pcbrele_mtx;
MTX_SYSINIT(obsd_pcbrele, &obsd_pcbrele_mtx, "pf pcb release", MTX_DEF);
static void obsd_pcbrele_run(void *);
static struct task obsd_pcbrele_task =
    TASK_INITIALIZER(obsd_pcbrele_run, NULL);

static void
obsd_pcbrele_run(void *arg)
{
	struct obsd_pcbrele *r;
	struct inpcb *inp;

	for (;;) {
		mtx_lock(&obsd_pcbrele_mtx);
		r = STAILQ_FIRST(&obsd_pcbrele_q);
		if (r != NULL)
			STAILQ_REMOVE_HEAD(&obsd_pcbrele_q, r_next);
		mtx_unlock(&obsd_pcbrele_mtx);
		if (r == NULL)
			break;
		inp = r->r_inp;
		free(r, M_PF);
		INP_RLOCK(inp);
		if (!in_pcbrele_rlocked(inp))
			INP_RUNLOCK(inp);
	}
}

void
obsd_in_pcbunref(struct inpcb *inp)
{
	struct obsd_pcbrele *r;

	if (inp == NULL)
		return;
	if (refcount_release_if_not_last(&inp->inp_refcount))
		return;
	r = malloc(sizeof(*r), M_PF, M_NOWAIT);
	if (r == NULL) {
		/* Last reference and no memory: release it here. */
		INP_RLOCK(inp);
		if (!in_pcbrele_rlocked(inp))
			INP_RUNLOCK(inp);
		return;
	}
	r->r_inp = inp;
	mtx_lock(&obsd_pcbrele_mtx);
	STAILQ_INSERT_TAIL(&obsd_pcbrele_q, r, r_next);
	mtx_unlock(&obsd_pcbrele_mtx);
	task_add(systq, &obsd_pcbrele_task);
}

/* ------------------------------------------------------------------ */
/* Pseudo-interfaces (pflog, pfsync, pflow)                            */
/* ------------------------------------------------------------------ */

/*
 * OpenBSD calls if_ioctl with the net lock held and the pf pseudo-
 * interface drivers drop and retake it; provide that context.
 */
static if_ioctl_fn_t obsd_ioctl_by_type[256];

static int
obsd_if_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error;

	NET_LOCK();
	error = obsd_ioctl_by_type[ifp->if_type](ifp, cmd, data);
	NET_UNLOCK();
	return (error);
}

static struct obsd_if_clone *obsd_cloner_byname(const char *);

/* A driver name that outlives the caller (for if_initname()). */
static const char *
obsd_strdup_name(const char *name)
{
	char *n;

	n = malloc(strlen(name) + 1, M_PF, M_WAITOK);
	strcpy(n, name);
	return (n);
}

void
obsd_if_attach(struct ifnet *ifp)
{
	if (ifp->if_ioctl != NULL && ifp->if_ioctl != obsd_if_ioctl) {
		obsd_ioctl_by_type[ifp->if_type] = ifp->if_ioctl;
		ifp->if_ioctl = obsd_if_ioctl;
	}
	char name[IFNAMSIZ];
	const char *p;
	int unit;

	/* OpenBSD drivers only fill in if_xname. */
	strlcpy(name, ifp->if_xname, sizeof(name));
	for (p = name; *p != '\0' && (*p < '0' || *p > '9'); p++)
		;
	unit = *p != '\0' ? strtol(p, NULL, 10) : 0;
	name[p - name] = '\0';
	/*
	 * if_initname() keeps the driver name pointer: use the cloner's
	 * name, which the 5BSD cloner lookup on destroy compares with.
	 */
	{
		struct obsd_if_clone *oifc = obsd_cloner_byname(name);

		if_initname(ifp, oifc != NULL ? oifc->ifc_name :
		    obsd_strdup_name(name), unit);
	}
	/*
	 * pflog, pfsync and pflow keep their softc in the creating VNET's
	 * state (V_pfsyncif, V_pflowif_list) and carry that VNET's
	 * traffic: they cannot be lent to another VNET.
	 */
	ifp->if_kflags |= IFKF_NOVMOVE;
	if_attach(ifp);
}

void
obsd_if_detach(struct ifnet *ifp)
{
	if (ifp->if_bpf != NULL)
		bpfdetach(ifp);
	if_detach(ifp);
	if_free(ifp);
}

#define	OBSD_MAX_CLONERS	4
static struct obsd_if_clone *obsd_cloners[OBSD_MAX_CLONERS];
/* Cloners are registered once and attached in every vnet. */
VNET_DEFINE_STATIC(struct if_clone *, obsd_vnet_ifc[OBSD_MAX_CLONERS]);
#define	V_obsd_vnet_ifc	VNET(obsd_vnet_ifc)

static struct obsd_if_clone *
obsd_cloner_byname(const char *name)
{
	int i;

	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] != NULL &&
		    strcmp(obsd_cloners[i]->ifc_name, name) == 0)
			return (obsd_cloners[i]);
	return (NULL);
}

static int
obsd_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	struct obsd_if_clone *oifc;

	oifc = NULL;
	for (int i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] != NULL && V_obsd_vnet_ifc[i] == ifc)
			oifc = obsd_cloners[i];
	if (oifc == NULL)
		return (ENXIO);
	return (oifc->ifc_create(oifc, unit));
}

static void
obsd_clone_destroy(struct ifnet *ifp)
{
	struct obsd_if_clone *oifc;

	oifc = obsd_cloner_byname(ifp->if_dname);
	if (oifc != NULL)
		(void)oifc->ifc_destroy(ifp);
}

void
obsd_if_clone_attach(struct obsd_if_clone *oifc)
{
	int i;

	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] == NULL) {
			obsd_cloners[i] = oifc;
			break;
		}
}

void
obsd_if_clone_detach(struct obsd_if_clone *oifc)
{
	int i;

	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] == oifc)
			obsd_cloners[i] = NULL;
}

/* Attach every registered cloner in the current vnet. */
void	obsd_if_clone_vnet_attach(void);
void
obsd_if_clone_vnet_attach(void)
{
	int i;

	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] != NULL && V_obsd_vnet_ifc[i] == NULL)
			V_obsd_vnet_ifc[i] = if_clone_simple(
			    obsd_cloners[i]->ifc_name, obsd_clone_create,
			    obsd_clone_destroy, 0);
}

/* Detach the cloners of the current vnet, destroying their interfaces. */
void	obsd_if_clone_vnet_detach(void);
void
obsd_if_clone_vnet_detach(void)
{
	int i;

	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (V_obsd_vnet_ifc[i] != NULL) {
			(if_clone_detach)(V_obsd_vnet_ifc[i]);
			V_obsd_vnet_ifc[i] = NULL;
		}
}

/* ------------------------------------------------------------------ */
/* Kernel sockets (pflow export)                                       */
/* ------------------------------------------------------------------ */

int
obsd_socreate(int dom, struct socket **aso, int type, int proto)
{
	return (socreate(dom, aso, type, proto, curthread->td_ucred,
	    curthread));
}

int
obsd_sobind(struct socket *so, struct mbuf *nam)
{
	return (sobind(so, mtod(nam, struct sockaddr *), curthread));
}

int
obsd_sosend(struct socket *so, struct mbuf *nam, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags)
{
	struct sockaddr *sa = NULL;

	if (nam != NULL && nam->m_len > 0)
		sa = mtod(nam, struct sockaddr *);
	return (sosend(so, sa, uio, top, control, flags, curthread));
}
