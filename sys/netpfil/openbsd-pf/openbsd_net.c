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
#include <netinet/ip_divert.h>
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
	/* Routing domains: every FIB is its own domain until D2 lands. */
	return (tableid);
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
	m->m_pkthdr.csum_flags &= ~(CSUM_IP_TCP | CSUM_IP_UDP);
}

#ifdef INET6
void
in6_proto_cksum_out(struct mbuf *m, struct ifnet *ifp)
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	int off, nxt, plen;
	u_int16_t csum;

	if ((m->m_pkthdr.csum_flags & (CSUM_IP6_TCP | CSUM_IP6_UDP)) == 0)
		return;
	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off < (int)sizeof(*ip6))
		goto done;
	plen = sizeof(*ip6) + ntohs(ip6->ip6_plen) - off;
	if (nxt == IPPROTO_TCP) {
		struct tcphdr *th;

		if (m->m_len < off + (int)sizeof(*th))
			goto done;
		th = (struct tcphdr *)(mtod(m, caddr_t) + off);
		th->th_sum = 0;
		th->th_sum = in6_cksum(m, IPPROTO_TCP, off, plen);
	} else if (nxt == IPPROTO_UDP) {
		struct udphdr *uh;

		if (m->m_len < off + (int)sizeof(*uh))
			goto done;
		uh = (struct udphdr *)(mtod(m, caddr_t) + off);
		uh->uh_sum = 0;
		csum = in6_cksum(m, IPPROTO_UDP, off, plen);
		uh->uh_sum = csum == 0 ? 0xffff : csum;
	}
done:
	m->m_pkthdr.csum_flags &= ~(CSUM_IP6_TCP | CSUM_IP6_UDP);
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

int
frag6_deletefraghdr(struct mbuf *m, int offset)
{
	return (ip6_deletefraghdr(m, offset, M_NOWAIT));
}

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
		NET_EPOCH_ENTER(et);
		switch (it->kind) {
		case OBSD_SEND_OUTPUT:
			m_tag_delete(m, mtag);
			if (it->af == AF_INET)
				ip_output(m, NULL, NULL, 0, NULL, NULL);
#ifdef INET6
			else
				ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
#endif
			break;
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
	}
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
	error = ip_fragment(ip, &m, mtu, ifp->if_hwassist);
	if (error) {
		m_freem(m);
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
	error = ip6_fragment(NULL, m, hlen, nextproto, mtu - hlen,
	    htonl(ip6_randomid()));
	if (error) {
		m_freem(m);
		return (error);
	}
	for (; m != NULL; m = n) {
		n = m->m_nextpkt;
		m->m_nextpkt = NULL;
		ml_enqueue(ml, m);
	}
	return (0);
}
#endif

static int
obsd_ifoutput(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
    struct rtentry *rt)
{
	struct epoch_tracker et;
	int error;

	NET_EPOCH_ENTER(et);
	error = ifp->if_output(ifp, m, obsd_rt_nexthop(rt, dst), NULL);
	NET_EPOCH_EXIT(et);
	return (error);
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
 * and the caller has to fragment or send an error.
 */
int
if_output_tso(struct ifnet *ifp, struct mbuf **mp, struct sockaddr *dst,
    struct rtentry *rt, u_int mtu)
{
	struct mbuf *m = *mp;
	int af = dst->sa_family;

	if (m->m_pkthdr.len > mtu &&
	    (m->m_pkthdr.csum_flags & CSUM_TSO & ifp->if_hwassist) == 0)
		return (0);
	obsd_cksum_out(m, af);
	*mp = NULL;
	(void)obsd_ifoutput(ifp, m, dst, rt);
	return (1);
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
/* divert(4): divert-packet port                                       */
/* ------------------------------------------------------------------ */

void
divert_packet(struct mbuf *m, int dir, u_int16_t port)
{
	if (ip_divert_ptr == NULL) {
		m_freem(m);
		return;
	}
	ip_divert_ptr(m, port, dir == PF_IN);
}

#ifdef INET6
void
divert6_packet(struct mbuf *m, int dir, u_int16_t port)
{
	divert_packet(m, dir, port);
}
#endif

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

void
obsd_in_pcbunref(struct inpcb *inp)
{
	if (inp == NULL)
		return;
	if (rw_wowned(&inp->inp_lock)) {
		/* Called under the pcb lock (in_pcbfree hook): not the last ref. */
		(void)refcount_release(&inp->inp_refcount);
		return;
	}
	INP_RLOCK(inp);
	if (!in_pcbrele_rlocked(inp))
		INP_RUNLOCK(inp);
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
	if_initname(ifp, name, unit);
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
		if (obsd_cloners[i] != NULL && obsd_cloners[i]->ifc_fbsd == ifc)
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
	oifc->ifc_fbsd = if_clone_simple(oifc->ifc_name, obsd_clone_create,
	    obsd_clone_destroy, 0);
}

void
obsd_if_clone_detach(struct obsd_if_clone *oifc)
{
	int i;

	if (oifc->ifc_fbsd != NULL)
		if_clone_detach(oifc->ifc_fbsd);
	oifc->ifc_fbsd = NULL;
	for (i = 0; i < OBSD_MAX_CLONERS; i++)
		if (obsd_cloners[i] == oifc)
			obsd_cloners[i] = NULL;
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
