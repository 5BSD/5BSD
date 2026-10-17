/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * 5BSD attachment of OpenBSD PF: module lifecycle, /dev/pf, pfil(9)
 * hooks into the IPv4/IPv6 input and output paths, interface and
 * interface-group events, and the mbuf/inpcb hooks that release pf
 * references held by packets and sockets.
 *
 * Packet checksums: OpenBSD pf treats M_*_CSUM_OUT as "compute the whole
 * checksum later".  5BSD delayed checksums carry a pseudo-header seed
 * instead, so outbound delayed checksums are finalised before pf_test()
 * and any checksum request pf adds is computed in software afterwards.
 * Inbound hardware checksum results are cleared so the stack verifies
 * the (possibly rewritten) packet after pf.
 */

#include "openbsd_compat.h"

#include <sys/module.h>
#include <sys/bitstring.h>
#include <sys/jail.h>

#include <net/pfvar.h>
#include <net/pfvar_priv.h>
#include <net/if_pflog.h>

/* OpenBSD entry points (pf_ioctl.c, if_pflog.c, pf_if.c, pf.c). */
void	pfattach(int);
int	pfopen(dev_t, int, int, struct proc *);
int	pfclose(dev_t, int, int, struct proc *);
int	pfioctl(dev_t, u_long, caddr_t, int, struct proc *);
void	pflogattach(int);
void	pflowattach(int);
void	pfsyncattach(int);
int	pfsync_input4(struct mbuf **, int *, int, int, struct netstack *);
int	pfsync_input6(struct mbuf **, int *, int, int, struct netstack *);
void	pf_mbuf_unlink_state_key(struct mbuf *);
void	pf_mbuf_unlink_inpcb(struct mbuf *);
int	pf_mbuf_link_state_key(struct mbuf *, struct pf_state_key *);
int	pf_mbuf_link_inpcb(struct mbuf *, struct inpcb *);
struct pf_state_key *pf_state_key_ref(struct pf_state_key *);
void	pf_state_key_unref(struct pf_state_key *);
int	pf_ouraddr(struct mbuf *);
struct pf_divert *pf_find_divert(struct mbuf *);
void	pf_inp_unlink(struct inpcb *);
void	pf_remove_divert_state(struct inpcb *);
void	obsd_ifhooks_run(struct ifnet *, int);
void	pfi_attach_ifnet(struct ifnet *);
void	pfi_detach_ifnet(struct ifnet *);
void	pfi_attach_ifgroup(struct ifg_group *);
void	pfi_detach_ifgroup(struct ifg_group *);
void	pfi_group_addmember(const char *);
int	pf_states_clr(struct pfioc_state_kill *);
int	pf_begin_rules(u_int32_t *, const char *);
int	pf_commit_rules(u_int32_t, char *);
void	pf_purge(void *);
unsigned int pf_purge_expired_states(unsigned int, unsigned int);
void	pf_osfp_flush(void);
void	pf_remove_queues(void);
void	pfi_vnet_fini(void);
void	pf_normalize_vnet_fini(void);
void	pf_syncookies_vnet_fini(void);
void	obsd_if_clone_vnet_attach(void);
void	obsd_if_clone_vnet_detach(void);
void	obsd_sendq_drain(void);
void	obsd_pcbrele_drain(void);
void	pf_divert_attach(void);
void	pf_jail_attach(void);
/* 5BSD: ether (pf_ether.c) */
int	pf_eth_is_ioctl(u_long);
int	pf_eth_ioctl(u_long, caddr_t, int);
void	pf_eth_hook_update(void);
void	pf_eth_vnet_init(void);
void	pf_eth_vnet_unhook(void);
void	pf_eth_vnet_fini(void);
/* Per-VNET quotas (pf_quota.c), route labels (openbsd_compat.c). */
void	pf_quota_vnet_init(void);
void	pf_quota_vnet_fini(void);
int	pf_quota_getlimit(struct pfioc_limit *);
int	pf_quota_setlimit(struct pfioc_limit *);
void	obsd_rtlabel_vnet_fini(void);
/* Per-VNET tag and queue ids (pf_ioctl.c). */
TAILQ_HEAD(PF_KTAG(pf_tags), pf_tagname);
PF_VNET_DECLARE(struct PF_KTAG(pf_tags), pf_tags);
PF_VNET_DECLARE(struct PF_KTAG(pf_tags), pf_qids);
extern struct pool pf_tag_pl;
extern struct sx pfioctl_rw;
PF_VNET_DECLARE(struct cpumem *, pf_status_fcounters);
PF_VNET_DECLARE(struct pf_statelim_list, pf_statelim_list_active);
PF_VNET_DECLARE(struct pf_source_list, pf_source_gc);
PF_VNET_DECLARE(struct task, pf_purge_states_task);
PF_VNET_DECLARE(int, pfr_ktable_cnt);

/*
 * VNET: every vnet runs its own OpenBSD pf instance (rulesets, states,
 * tables, anchors, interfaces, pflog/pfsync/pflow, tag, queue and route
 * label ids).  The pools and the pf locks are shared; each vnet is held to
 * its own limits in the pools (pf_quota.c).  pf_fbsd_ready is set once a
 * vnet's instance is initialised and cleared before it is torn down.
 */
VNET_DEFINE_STATIC(int, pf_fbsd_ready);
#define	V_pf_fbsd_ready	VNET(pf_fbsd_ready)

int	pf_fbsd_vnet_ready(void);
int
pf_fbsd_vnet_ready(void)
{
	return (V_pf_fbsd_ready);
}

/* ------------------------------------------------------------------ */
/* mbuf and inpcb reference hooks                                      */
/* ------------------------------------------------------------------ */

/* The pf tag of a packet is freed: drop its state-key and pcb references. */
static void
pf_fbsd_mtag_unlink(struct pkthdr_pf *p)
{
	struct pf_state_key *sk = p->statekey;
	struct inpcb *inp = p->inp;

	p->statekey = NULL;
	p->inp = NULL;
	if (sk != NULL)
		pf_state_key_unref(sk);
	if (inp != NULL)
		in_pcbunref(inp);
}

/* The pf tag was copied with the packet: the copy takes its own references. */
static void
pf_fbsd_mtag_copy(struct pkthdr_pf *p)
{
	if (p->statekey != NULL)
		(void)pf_state_key_ref(p->statekey);
	if (p->inp != NULL)
		(void)in_pcbref(p->inp);
}

/* Writable metadata allocation failures must be handled by the caller. */
static counter_u64_t pf_fbsd_mtag_nomem;

static struct pkthdr_pf *
pf_fbsd_mtag_alloc_failed(void)
{
	counter_u64_add(pf_fbsd_mtag_nomem, 1);
	return (NULL);
}

struct pkthdr_pf *
obsd_pf_mtag_w(struct mbuf *m)
{
	struct pkthdr_pf *p = m_pf_get(m);

	return (p != NULL ? p : pf_fbsd_mtag_alloc_failed());
}

struct pkthdr_pf *
obsd_pf_pdtag(struct pf_pdesc *pd, int write)
{
	struct mbuf *m = pd->m;
	struct pkthdr_pf *p;
	struct m_tag *t;

	/* The cached tag is valid while it is still the packet's first. */
	if (pd->pfh_m == m && pd->pfh_t != NULL &&
	    SLIST_FIRST(&m->m_pkthdr.tags) == pd->pfh_t)
		return ((struct pkthdr_pf *)(pd->pfh_t + 1));
	pd->pfh_m = m;
	pd->pfh_t = NULL;
	t = SLIST_EMPTY(&m->m_pkthdr.tags) ? NULL :
	    m_tag_locate(m, MTAG_ABI_COMPAT, PACKET_TAG_PF, NULL);
	if (t == NULL) {
		if (!write)
			return (__DECONST(struct pkthdr_pf *, &m_pf_default));
		if ((p = m_pf_get(m)) == NULL)
			return (pf_fbsd_mtag_alloc_failed());
		t = (struct m_tag *)p - 1;
	}
	if (SLIST_FIRST(&m->m_pkthdr.tags) == t)
		pd->pfh_t = t;
	return ((struct pkthdr_pf *)(t + 1));
}

/*
 * in_pcbfree() calls the hook with the pcb write-locked, while
 * pf_socket_lookup() locks pcbs with PF_LOCK held.  The hook therefore
 * only unlinks the pcb under pf_inp_mtx and leaves the state update of
 * OpenBSD's pf_remove_divert_state(), which takes PF_LOCK, to a task.
 */
struct pf_fbsd_divert_rm {
	STAILQ_ENTRY(pf_fbsd_divert_rm) next;
	struct pf_state_key	*sk;
};
STAILQ_HEAD(pf_fbsd_divert_rmq, pf_fbsd_divert_rm);
VNET_DEFINE_STATIC(struct pf_fbsd_divert_rmq, pf_fbsd_divert_q);
VNET_DEFINE_STATIC(struct task, pf_fbsd_divert_task);
VNET_DEFINE_STATIC(int, pf_fbsd_divert_closing);
#define	V_pf_fbsd_divert_q	VNET(pf_fbsd_divert_q)
#define	V_pf_fbsd_divert_task	VNET(pf_fbsd_divert_task)
#define	V_pf_fbsd_divert_closing VNET(pf_fbsd_divert_closing)
static struct mtx pf_fbsd_divert_mtx;
MTX_SYSINIT(pf_fbsd_divert, &pf_fbsd_divert_mtx, "pf divert pcb", MTX_DEF);

static void
pf_fbsd_divert_run(void *arg __unused)
{
	struct pf_fbsd_divert_rmq q;
	struct pf_fbsd_divert_rm *r;

	STAILQ_INIT(&q);
	mtx_lock(&pf_fbsd_divert_mtx);
	STAILQ_CONCAT(&q, &V_pf_fbsd_divert_q);
	mtx_unlock(&pf_fbsd_divert_mtx);
	while ((r = STAILQ_FIRST(&q)) != NULL) {
		STAILQ_REMOVE_HEAD(&q, next);
		/* Skips a state a new socket has linked to meanwhile. */
		pf_remove_divert_state_key(r->sk);
		free(r, M_PF);
	}
}

/* No more deferred work for this vnet; finish what is queued. */
static void
pf_fbsd_divert_drain(void)
{
	mtx_lock(&pf_fbsd_divert_mtx);
	V_pf_fbsd_divert_closing = 1;
	mtx_unlock(&pf_fbsd_divert_mtx);
	taskq_del_barrier(systq, &V_pf_fbsd_divert_task);
	pf_fbsd_divert_run(NULL);
}

static void
pf_fbsd_inpcb_free(struct inpcb *inp)
{
	struct pf_fbsd_divert_rm *r;
	struct pf_state_key *sk;

	INP_WLOCK_ASSERT(inp);

	mtx_enter(&pf_inp_mtx);
	sk = pf_state_key_ref(inp->inp_pf_sk);
	mtx_leave(&pf_inp_mtx);
	pf_inp_unlink(inp);
	if (sk == NULL)
		return;

	r = malloc(sizeof(*r), M_PF, M_NOWAIT);
	CURVNET_SET_QUIET(inp->inp_socket->so_vnet);
	mtx_lock(&pf_fbsd_divert_mtx);
	if (r != NULL && !V_pf_fbsd_divert_closing) {
		r->sk = sk;
		STAILQ_INSERT_TAIL(&V_pf_fbsd_divert_q, r, next);
		task_add(systq, &V_pf_fbsd_divert_task);
		r = NULL;
		sk = NULL;
	}
	mtx_unlock(&pf_fbsd_divert_mtx);
	CURVNET_RESTORE();
	/* Not queued: a diverted state then expires by its timeout. */
	free(r, M_PF);
	if (sk != NULL)
		pf_state_key_unref(sk);
}

/* Standalone PF delay owns each frame until transmission or VNET teardown. */
TAILQ_HEAD(pf_fbsd_delay_head, pf_pktdelay);
VNET_DEFINE_STATIC(struct pf_fbsd_delay_head, pf_fbsd_delays);
VNET_DEFINE_STATIC(unsigned int, pf_fbsd_delay_count);
VNET_DEFINE_STATIC(int, pf_fbsd_delay_closing);
/* Callbacks that took their frame off the list and still use the VNET. */
VNET_DEFINE_STATIC(unsigned int, pf_fbsd_delay_running);
#define V_pf_fbsd_delays VNET(pf_fbsd_delays)
#define V_pf_fbsd_delay_count VNET(pf_fbsd_delay_count)
#define V_pf_fbsd_delay_closing VNET(pf_fbsd_delay_closing)
#define V_pf_fbsd_delay_running VNET(pf_fbsd_delay_running)
static struct mtx pf_fbsd_delay_mtx;
MTX_SYSINIT(pf_fbsd_delay, &pf_fbsd_delay_mtx, "pf delay", MTX_DEF);

static void
pf_fbsd_delay_release(struct pf_pktdelay *p)
{
	if_put(p->ifp);
	pool_put(&pf_pktdelay_pl, p);
}

static void
pf_fbsd_delay_run(void *arg)
{
	struct pf_pktdelay *p = arg;
	struct epoch_tracker et;
	struct ifnet *ifp;

	mtx_lock(&pf_fbsd_delay_mtx);
	if (p->cancelled) {
		mtx_unlock(&pf_fbsd_delay_mtx);
		return; /* The teardown caller drains this task and frees it. */
	}
	TAILQ_REMOVE(&V_pf_fbsd_delays, p, entry);
	V_pf_fbsd_delay_count--;
	V_pf_fbsd_delay_running++;
	mtx_unlock(&pf_fbsd_delay_mtx);

	NET_EPOCH_ENTER(et);
	ifp = if_get(p->ifp->if_index);
	/* An interface index can be reused while its old reference survives. */
	if (ifp == p->ifp && (p->m->m_pkthdr.rcvif == NULL ||
	    m_rcvif_restore(p->m) != NULL))
		(void)ifp->if_transmit(ifp, p->m);
	else
		m_freem(p->m);
	if_put(ifp);
	NET_EPOCH_EXIT(et);
	pf_fbsd_delay_release(p);
	mtx_lock(&pf_fbsd_delay_mtx);
	if (--V_pf_fbsd_delay_running == 0 && V_pf_fbsd_delay_closing)
		wakeup(&V_pf_fbsd_delay_running);
	mtx_unlock(&pf_fbsd_delay_mtx);
}

int
obsd_pf_delay_packet(struct mbuf *m, unsigned int ifidx)
{
	struct pf_pktdelay *p;
	struct pkthdr_pf *tag;
	unsigned int delay;

	tag = PF_MTAG_W(m);
	if (tag == NULL)
		goto drop;
	/* Serialize limit admission with DIOCSETLIMIT and other transmitters. */
	PF_LOCK();
	p = pool_get(&pf_pktdelay_pl, PR_NOWAIT | PR_ZERO);
	PF_UNLOCK();
	if (p == NULL)
		goto drop;
	p->ifp = if_get(ifidx);
	if (p->ifp == NULL) {
		pool_put(&pf_pktdelay_pl, p);
		goto drop;
	}
	p->m = m;
	timeout_set(&p->to, pf_fbsd_delay_run, p);
	mtx_lock(&pf_fbsd_delay_mtx);
	if (V_pf_fbsd_delay_closing || !V_pf_fbsd_ready) {
		mtx_unlock(&pf_fbsd_delay_mtx);
		pf_fbsd_delay_release(p);
		goto drop;
	}
	delay = tag->delay;
	PF_SDT3(queue, packet, delay, tag->qid, delay, ifidx);
	if (m->m_pkthdr.rcvif != NULL)
		m_rcvif_serialize(m);
	tag->delay = 0; /* Clear before publication, including a zero-delay race. */
	TAILQ_INSERT_TAIL(&V_pf_fbsd_delays, p, entry);
	V_pf_fbsd_delay_count++;
	timeout_add_msec(&p->to, delay);
	mtx_unlock(&pf_fbsd_delay_mtx);
	return (0);
drop:
	m_freem(m);
	return (ENOBUFS);
}

static int
pf_fbsd_delay_transmit(struct ifnet *ifp, struct mbuf *m)
{
	return (pf_delay_pkt(m, ifp->if_index));
}

static void
pf_fbsd_delay_drain(void)
{
	struct pf_pktdelay *p;

	mtx_lock(&pf_fbsd_delay_mtx);
	V_pf_fbsd_delay_closing = 1;
	while ((p = TAILQ_FIRST(&V_pf_fbsd_delays)) != NULL) {
		TAILQ_REMOVE(&V_pf_fbsd_delays, p, entry);
		V_pf_fbsd_delay_count--;
		p->cancelled = 1;
		mtx_unlock(&pf_fbsd_delay_mtx);
		timeout_del_barrier(&p->to);
		m_freem(p->m);
		pf_fbsd_delay_release(p);
		mtx_lock(&pf_fbsd_delay_mtx);
	}
	/*
	 * A callback may already have removed its frame before closing:
	 * wait for this VNET's, not for the whole shared task queue (other
	 * VNETs keep queueing; this runs under ifnet_detach_sxlock).
	 */
	while (V_pf_fbsd_delay_running != 0)
		mtx_sleep(&V_pf_fbsd_delay_running, &pf_fbsd_delay_mtx, 0,
		    "pfdelay", 0);
	mtx_unlock(&pf_fbsd_delay_mtx);
}

/* ------------------------------------------------------------------ */
/* pfil hooks                                                          */
/* ------------------------------------------------------------------ */

static int
pf_fbsd_test(int af, int dir, struct ifnet *ifp, struct mbuf **m)
{
	int action;

	SDT_PROBE3(pf, ip, test, entry, af, dir, ifp);
	action = pf_test(af, dir, ifp, m);
	SDT_PROBE3(pf, ip, test, finish, action, dir, ifp);
	return (action);
}

/*
 * Output: OpenBSD passes the sending socket with the packet so pf can
 * link it to the state (divert-reply, pf_ouraddr()).  The reference is
 * dropped again if the packet comes back from pf; the caller holds the
 * pcb, so it is never the last one.
 */
static int
pf_fbsd_test_out(int af, int dir, struct ifnet *ifp, struct mbuf **m,
    struct inpcb *inp)
{
	int action, linked = 0;

	if (inp != NULL && PF_MTAG_R(*m)->inp == NULL) {
		if (pf_mbuf_link_inpcb(*m, inp) != 0)
			return (PF_DROP);
		linked = 1;
	}
	action = pf_fbsd_test(af, dir, ifp, m);
	if (linked && *m != NULL && PF_MTAG_R(*m)->inp == inp) {
		PF_MTAG_W(*m)->inp = NULL;
		(void)refcount_release(&inp->inp_refcount);
	}
	return (action);
}

/*
 * Input: as OpenBSD's in_ouraddr()/pf_ouraddr(), a packet pf diverted
 * (divert-to) or that belongs to a state linked to a local socket
 * (divert-reply, non-local SO_BINDANY addresses) is delivered locally.
 * For divert-to the transport looks up the socket by the divert address
 * and port, carried as the stack's PACKET_TAG_IPFORWARD next hop (the
 * port in host order, as that tag stores it).
 */
static void
pf_fbsd_ours(struct mbuf *m, int af)
{
	struct pf_divert *divert;
	struct m_tag *mtag;

	if (pf_ouraddr(m) != 1)
		return;
	m->m_flags |= M_FASTFWD_OURS;
	if ((PF_MTAG_R(m)->flags & PF_TAG_DIVERTED) == 0 ||
	    (divert = pf_find_divert(m)) == NULL ||
	    divert->type != PF_DIVERT_TO)	/* divert-reply: own address */
		return;
	switch (af) {
#ifdef INET
	case AF_INET: {
		struct sockaddr_in *sin;

		mtag = m_tag_get(PACKET_TAG_IPFORWARD, sizeof(*sin), M_NOWAIT);
		if (mtag == NULL)
			return;
		sin = (struct sockaddr_in *)(mtag + 1);
		memset(sin, 0, sizeof(*sin));
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = divert->addr.v4;
		sin->sin_port = ntohs(divert->port);
		m_tag_prepend(m, mtag);
		m->m_flags |= M_IP_NEXTHOP;
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6;

		mtag = m_tag_get(PACKET_TAG_IPFORWARD, sizeof(*sin6), M_NOWAIT);
		if (mtag == NULL)
			return;
		sin6 = (struct sockaddr_in6 *)(mtag + 1);
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = divert->addr.v6;
		sin6->sin6_port = ntohs(divert->port);
		m_tag_prepend(m, mtag);
		m->m_flags |= M_IP6_NEXTHOP;
		break;
	}
#endif
	}
}

static pfil_return_t
pf_fbsd_result(int action, struct mbuf **m)
{
	if (*m == NULL)
		return (PFIL_CONSUMED);
	if (action != PF_PASS) {
		m_freem(*m);
		*m = NULL;
		return (PFIL_DROPPED);
	}
	return (PFIL_PASS);
}

/*
 * A packet that re-enters the stack (reflected ICMP errors, loopback)
 * may still carry the state key linked on its previous input; OpenBSD
 * drops it in m_resethdr().  Do the same before inbound filtering.
 */
static void
pf_fbsd_in_csum(struct mbuf *m)
{
	if (PF_MTAG_R(m)->statekey != NULL)
		pf_mbuf_unlink_state_key(m);
	m->m_pkthdr.csum_flags &= ~(CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
	    CSUM_SCTP_VALID);
}

#ifdef INET
/*
 * OpenBSD always recomputes the IPv4 header checksum on output, so pf
 * does not maintain ip_sum when it rewrites a header.  The 5BSD stack
 * forwards with incremental updates; refresh the checksum after pf.
 */
static void
pf_fbsd_ip_hdr_cksum(struct mbuf *m)
{
	struct ip *ip;

	if (m->m_pkthdr.csum_flags & CSUM_IP)
		return;		/* computed by the hardware or ip_output */
	if (m->m_len < (int)sizeof(struct ip))
		return;
	ip = mtod(m, struct ip *);
	if (m->m_len < (ip->ip_hl << 2))
		return;
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum_hdr(ip);
}

static pfil_return_t
pf_fbsd_check_in(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	pfil_return_t rv;

	pf_fbsd_in_csum(*m);
	rv = pf_fbsd_result(pf_fbsd_test(AF_INET, PF_IN, ifp, m), m);
	if (rv == PFIL_PASS) {
		pf_fbsd_ip_hdr_cksum(*m);
		pf_fbsd_ours(*m, AF_INET);
	}
	return (rv);
}

static pfil_return_t
pf_fbsd_check_out(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	struct mbuf *n = *m;
	struct ip *ip;
	pfil_return_t rv;

	if ((n->m_pkthdr.csum_flags & CSUM_TSO) == 0 &&
	    (n->m_pkthdr.csum_flags & CSUM_DELAY_DATA)) {
		in_delayed_cksum(n);
		n->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	}
	rv = pf_fbsd_result(pf_fbsd_test_out(AF_INET,
	    (flags & PFIL_FWD) ? PF_FWD : PF_OUT, ifp, m, inp), m);
	if (rv != PFIL_PASS)
		return (rv);
	n = *m;
	pf_fbsd_ip_hdr_cksum(n);
	if (n->m_pkthdr.csum_flags & CSUM_TSO) {
		/* Re-seed the TSO pseudo header after a translation. */
		ip = mtod(n, struct ip *);
		if (ip->ip_p == IPPROTO_TCP && n->m_len >=
		    (ip->ip_hl << 2) + (int)sizeof(struct tcphdr)) {
			struct tcphdr *th = (struct tcphdr *)((caddr_t)ip +
			    (ip->ip_hl << 2));

			th->th_sum = in_pseudo(ip->ip_src.s_addr,
			    ip->ip_dst.s_addr, htons(IPPROTO_TCP));
		}
	} else if (n->m_pkthdr.csum_flags & (CSUM_IP_TCP | CSUM_IP_UDP))
		in_proto_cksum_out(n, ifp);
	return (rv);
}
#endif

#ifdef INET6
static pfil_return_t
pf_fbsd_check6_in(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	pfil_return_t rv;

	pf_fbsd_in_csum(*m);
	rv = pf_fbsd_result(pf_fbsd_test(AF_INET6, PF_IN, ifp, m), m);
	if (rv == PFIL_PASS)
		pf_fbsd_ours(*m, AF_INET6);
	return (rv);
}

static pfil_return_t
pf_fbsd_check6_out(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	struct mbuf *n = *m;
	pfil_return_t rv;
	int off, nxt;

	if ((n->m_pkthdr.csum_flags & CSUM_TSO) == 0 &&
	    (n->m_pkthdr.csum_flags & CSUM_DELAY_DATA_IPV6)) {
		/*
		 * The transport header follows any extension headers
		 * (IPV6_HOPOPTS, IPV6_DSTOPTS, IPV6_RTHDR socket options).
		 */
		nxt = -1;
		off = ip6_lasthdr(n, 0, IPPROTO_IPV6, &nxt);
		if (off < (int)sizeof(struct ip6_hdr) || off >= n->m_pkthdr.len) {
			m_freem(n);
			*m = NULL;
			return (PFIL_DROPPED);
		}
		in6_delayed_cksum(n, n->m_pkthdr.len - off, off);
		n->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA_IPV6;
	}
	rv = pf_fbsd_result(pf_fbsd_test_out(AF_INET6,
	    (flags & PFIL_FWD) ? PF_FWD : PF_OUT, ifp, m, inp), m);
	if (rv != PFIL_PASS)
		return (rv);
	n = *m;
	if (n->m_pkthdr.csum_flags & CSUM_TSO) {
		/* Re-seed the TSO pseudo header after a translation. */
		nxt = -1;
		off = ip6_lasthdr(n, 0, IPPROTO_IPV6, &nxt);
		if (nxt == IPPROTO_TCP && off >= (int)sizeof(struct ip6_hdr) &&
		    n->m_len >= off + (int)sizeof(struct tcphdr)) {
			struct tcphdr *th = (struct tcphdr *)(mtod(n, caddr_t) +
			    off);

			th->th_sum = in6_cksum_pseudo(mtod(n, struct ip6_hdr *),
			    0, IPPROTO_TCP, 0);
		}
	} else if (n->m_pkthdr.csum_flags & (CSUM_IP6_TCP | CSUM_IP6_UDP))
		in6_proto_cksum_out(n, ifp);
	return (rv);
}
#endif

/*
 * pfsync input runs in task context: OpenBSD processes it under the
 * (sleepable) net lock and pfsync takes sleepable locks, which must not
 * be acquired inside the net epoch of the IP input path.
 */
VNET_DEFINE_STATIC(struct mbuf_queue, pf_pfsync_inq);
VNET_DEFINE_STATIC(struct task, pf_pfsync_intask);
#define	V_pf_pfsync_inq		VNET(pf_pfsync_inq)
#define	V_pf_pfsync_intask	VNET(pf_pfsync_intask)

static void
pf_fbsd_pfsync_intask(void *arg)
{
	struct epoch_tracker et;
	struct mbuf_list ml;
	struct mbuf *m;
	struct ifnet *ifp;
	int off;

	mq_delist(&V_pf_pfsync_inq, &ml);
	while ((m = ml_dequeue(&ml)) != NULL) {
		/*
		 * The receiving interface may have gone while the packet was
		 * queued (it was serialised at enqueue); drop it then.  Hold a
		 * reference rather than the epoch: the input below takes
		 * sleepable locks, which is why it runs in this task.
		 */
		NET_EPOCH_ENTER(et);
		if ((ifp = m_rcvif_restore(m)) == NULL) {
			NET_EPOCH_EXIT(et);
			m_freem(m);
			continue;
		}
		if_ref(ifp);
		NET_EPOCH_EXIT(et);
		NET_LOCK_SHARED();
#ifdef INET6
		/* pfsync6: the IPv6 input below queues bare headers only. */
		if ((mtod(m, struct ip6_hdr *)->ip6_vfc & IPV6_VERSION_MASK) ==
		    IPV6_VERSION) {
			off = sizeof(struct ip6_hdr);
			(void)pfsync_input6(&m, &off, IPPROTO_PFSYNC, AF_INET6,
			    NULL);
		} else
#endif
		{
			off = mtod(m, struct ip *)->ip_hl << 2;
			(void)pfsync_input4(&m, &off, IPPROTO_PFSYNC, AF_INET,
			    NULL);
		}
		NET_UNLOCK_SHARED();
		if_rele(ifp);
	}
}

static int
pf_fbsd_pfsync_input(struct mbuf **mp, int *offp, int proto)
{
	if (!V_pf_fbsd_ready) {
		m_freem(*mp);
		*mp = NULL;
		return (IPPROTO_DONE);
	}
	m_rcvif_serialize(*mp);		/* no interface reference while queued */
	if (mq_enqueue(&V_pf_pfsync_inq, *mp) == 0)
		task_add(systq, &V_pf_pfsync_intask);
	*mp = NULL;
	return (IPPROTO_DONE);
}

#ifdef INET6
/*
 * 5BSD: pfsync6 -- pfsync from an IPv6 peer.  pfsync sends no extension
 * headers; anything but the bare IPv6 header in front of the pfsync
 * header is dropped, so the task above finds the offset again.
 */
static int
pf_fbsd_pfsync6_input(struct mbuf **mp, int *offp, int proto)
{
	if (*offp != sizeof(struct ip6_hdr)) {
		m_freem(*mp);
		*mp = NULL;
		return (IPPROTO_DONE);
	}
	return (pf_fbsd_pfsync_input(mp, offp, proto));
}
#endif

VNET_DEFINE_STATIC(pfil_hook_t, pf_ip4_in_hook);
VNET_DEFINE_STATIC(pfil_hook_t, pf_ip4_out_hook);
VNET_DEFINE_STATIC(pfil_hook_t, pf_ip6_in_hook);
VNET_DEFINE_STATIC(pfil_hook_t, pf_ip6_out_hook);
#define	pf_ip4_in_hook	VNET(pf_ip4_in_hook)
#define	pf_ip4_out_hook	VNET(pf_ip4_out_hook)
#define	pf_ip6_in_hook	VNET(pf_ip6_in_hook)
#define	pf_ip6_out_hook	VNET(pf_ip6_out_hook)

static void
pf_fbsd_hook(void)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_modname = "pf",
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
	};
	int ret __diagused;

#ifdef INET
	pha.pa_type = PFIL_TYPE_IP4;
	pha.pa_mbuf_chk = pf_fbsd_check_in;
	pha.pa_flags = PFIL_IN;
	pha.pa_rulname = "default-in";
	pf_ip4_in_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_inet_pfil_head;
	pla.pa_hook = pf_ip4_in_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
	pha.pa_mbuf_chk = pf_fbsd_check_out;
	pha.pa_flags = PFIL_OUT;
	pha.pa_rulname = "default-out";
	pf_ip4_out_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_inet_pfil_head;
	pla.pa_hook = pf_ip4_out_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
#endif
#ifdef INET6
	pha.pa_type = PFIL_TYPE_IP6;
	pha.pa_mbuf_chk = pf_fbsd_check6_in;
	pha.pa_flags = PFIL_IN;
	pha.pa_rulname = "default-in6";
	pf_ip6_in_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_inet6_pfil_head;
	pla.pa_hook = pf_ip6_in_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
	pha.pa_mbuf_chk = pf_fbsd_check6_out;
	pha.pa_flags = PFIL_OUT;
	pha.pa_rulname = "default-out6";
	pf_ip6_out_hook = pfil_add_hook(&pha);
	pla.pa_flags = PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR;
	pla.pa_head = V_inet6_pfil_head;
	pla.pa_hook = pf_ip6_out_hook;
	ret = pfil_link(&pla);
	MPASS(ret == 0);
#endif
}

static void
pf_fbsd_unhook(void)
{
#ifdef INET
	pfil_remove_hook(pf_ip4_in_hook);
	pfil_remove_hook(pf_ip4_out_hook);
#endif
#ifdef INET6
	pfil_remove_hook(pf_ip6_in_hook);
	pfil_remove_hook(pf_ip6_out_hook);
#endif
}

/* ------------------------------------------------------------------ */
/* Interface and group events                                          */
/* ------------------------------------------------------------------ */

#define	OBSD_HOOK_ADDR		1
#define	OBSD_HOOK_DETACH	2
#define	OBSD_HOOK_LINK		3

static eventhandler_tag pf_ifattach_tag, pf_ifdetach_tag, pf_ifaddr_tag;
static eventhandler_tag pf_iflink_tag, pf_grpattach_tag, pf_grpdetach_tag;
static eventhandler_tag pf_grpchange_tag, pf_ifrename_tag;

static void
pf_fbsd_ifattach(void *arg, struct ifnet *ifp)
{
	CURVNET_SET(ifp->if_vnet);
	if (V_pf_fbsd_ready)
		pfi_attach_ifnet(ifp);
	CURVNET_RESTORE();
}

static void
pf_fbsd_ifdetach(void *arg, struct ifnet *ifp)
{
	CURVNET_SET(ifp->if_vnet);
	obsd_ifhooks_run(ifp, OBSD_HOOK_DETACH);
	if (V_pf_fbsd_ready)
		pfi_detach_ifnet(ifp);
	CURVNET_RESTORE();
}

/*
 * FreeBSD renames interfaces (ifconfig name, podman's CNI bridges, jail
 * managers); OpenBSD cannot.  pf finds interfaces by name, so move the
 * interface from the kif of its old name to the kif of its new one, as
 * FreeBSD pf did, without the detach hooks: the interface itself stays.
 * See pfi_rename_ifnet().
 */
static void
pf_fbsd_ifrename(void *arg, struct ifnet *ifp, const char *old_name)
{
	/*
	 * if_rename() holds no locks here.  ifnet_detach_sxlock serialises
	 * the rename with if_detach(), VNET moves and VNET teardown (which
	 * runs pf's uninit under it), so the interface cannot leave while
	 * pf moves it between kifs, and two renames cannot interleave.
	 */
	sx_xlock(&ifnet_detach_sxlock);
	CURVNET_SET(ifp->if_vnet);
	if (V_pf_fbsd_ready && (ifp->if_flags & IFF_DYING) == 0 &&
	    obsd_if_linked(ifp))
		pfi_rename_ifnet(ifp, old_name);
	CURVNET_RESTORE();
	sx_xunlock(&ifnet_detach_sxlock);
}

static void
pf_fbsd_ifaddr(void *arg, struct ifnet *ifp, struct ifaddr *ifa, int event)
{
	obsd_ifhooks_run(ifp, OBSD_HOOK_ADDR);
}

static void
pf_fbsd_iflink(void *arg, struct ifnet *ifp, int state)
{
	obsd_ifhooks_run(ifp, OBSD_HOOK_LINK);
}

static void
pf_fbsd_grpattach(void *arg, struct ifg_group *ifg)
{
	if (V_pf_fbsd_ready)
		pfi_attach_ifgroup(ifg);
}

static void
pf_fbsd_grpdetach(void *arg, struct ifg_group *ifg)
{
	if (V_pf_fbsd_ready)
		pfi_detach_ifgroup(ifg);
}

static void
pf_fbsd_grpchange(void *arg, const char *gname)
{
	if (V_pf_fbsd_ready)
		pfi_group_addmember(gname); /* locks; add and delete alike */
}

/*
 * Attach one existing interface, unless it has left this VNET meanwhile or
 * is attached already: pfi_attach_ifnet_existing() checks under PF_LOCK,
 * and the departure handler of an interface unlinked later detaches it.
 */
static int
pf_fbsd_attach_one(if_t ifp, void *arg __unused)
{
	pfi_attach_ifnet_existing(ifp);
	return (0);
}

static void
pf_fbsd_attach_existing(void)
{
	struct ifg_group *ifg;
	struct ifnet *ifp;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(ifg, &V_ifg_head, ifg_next)
		pfi_attach_ifgroup(ifg);
	NET_EPOCH_EXIT(et);
	/*
	 * pfi_attach_ifnet() may sleep, so walk with references
	 * (if_foreach_sleep()), not in the net epoch.  This runs from a
	 * VNET_SYSINIT, under vnet_sysinit_sxlock, so it must not take
	 * ifnet_detach_sxlock (vnet_destroy() takes them the other way).
	 */
	(void)if_foreach_sleep(NULL, NULL, pf_fbsd_attach_one, NULL);
}

/* ------------------------------------------------------------------ */
/* /dev/pf: OpenBSD clones one minor per open                          */
/* ------------------------------------------------------------------ */

#define	PF_FBSD_UNITS	(CLONE_MAPSZ * NBBY)	/* units 1..1023 */
static bitstr_t bit_decl(pf_units, PF_FBSD_UNITS);
static struct mtx pf_units_mtx;
MTX_SYSINIT(pf_units_mtx, &pf_units_mtx, "pf units", MTX_DEF);
static struct cdev *pf_dev;

struct pf_fbsd_open {
	int		 unit;
	volatile u_int	 state;	/* PF_FBSD_FRESH, _USED or _BINDING */
	struct vnet	*vnet;	/* the opener's vnet: all ioctls act on it */
	struct ucred	*cred;	/* holds the prison, and so the vnet */
	struct prison	*bound;	/* DIOCBINDJAIL: held, its vnet replaces */
};

#define	PF_FBSD_FRESH	0	/* no ioctl yet: DIOCBINDJAIL is allowed */
#define	PF_FBSD_USED	1
#define	PF_FBSD_BINDING	2

static dev_t
pf_fbsd_minor(int unit)
{
	return (makedev(0, unit << CLONE_SHIFT));
}

static void
pf_fbsd_dtor(void *arg)
{
	struct pf_fbsd_open *po = arg;

	CURVNET_SET(po->vnet);
	(void)pfclose(pf_fbsd_minor(po->unit), 0, 0, curproc);
	CURVNET_RESTORE();
	if (po->bound != NULL)
		prison_free(po->bound);
	crfree(po->cred);
	mtx_lock(&pf_units_mtx);
	bit_clear(pf_units, po->unit);
	mtx_unlock(&pf_units_mtx);
	free(po, M_PF);
}

static int
pf_fbsd_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct pf_fbsd_open *po;
	int unit, error;

	/*
	 * A jail without its own vnet shares the host's network stack and
	 * would administer the host's pf: only the host and vnet jails may
	 * open /dev/pf, whatever devfs exposes.
	 */
	if (jailed(td->td_ucred) && !prison_owns_vnet(td->td_ucred->cr_prison))
		return (EPERM);

	mtx_lock(&pf_units_mtx);
	bit_ffc_at(pf_units, 1, PF_FBSD_UNITS, &unit);
	if (unit < 0) {
		mtx_unlock(&pf_units_mtx);
		return (ENXIO);
	}
	bit_set(pf_units, unit);
	mtx_unlock(&pf_units_mtx);

	po = malloc(sizeof(*po), M_PF, M_WAITOK | M_ZERO);
	po->unit = unit;
	po->vnet = TD_TO_VNET(td);
	CURVNET_SET(po->vnet);
	error = V_pf_fbsd_ready ? 0 : ENXIO;
	if (error == 0)
		error = pfopen(pf_fbsd_minor(unit), flags, fmt, td->td_proc);
	CURVNET_RESTORE();
	if (error == 0) {
		po->cred = crhold(td->td_ucred);
		error = devfs_set_cdevpriv(po, pf_fbsd_dtor);
		if (error)
			crfree(po->cred);
	}
	if (error) {
		mtx_lock(&pf_units_mtx);
		bit_clear(pf_units, unit);
		mtx_unlock(&pf_units_mtx);
		free(po, M_PF);
	}
	return (error);
}

/*
 * DIOCBINDJAIL: move a descriptor that has not issued any other ioctl to
 * the vnet of jail *jidp.  The jail must be a living descendant of both
 * the jail that opened /dev/pf and the caller's jail, so a descriptor can
 * only be narrowed to a jail its holders already govern.  BSDNetwork(8)
 * uses this to give a jailed client of system.Network.PF the state table
 * of its own vnet; a non-VNET jail shares its parent's vnet.  The jail is
 * held (and with it the vnet) until the descriptor is closed.
 */
static int
pf_fbsd_bindjail(struct pf_fbsd_open *po, int jid, struct thread *td)
{
	struct prison *pr;
	int error;

	if (!atomic_cmpset_acq_int(&po->state, PF_FBSD_FRESH, PF_FBSD_BINDING))
		return (EBUSY);
	sx_slock(&allprison_lock);
	pr = prison_find_child(td->td_ucred->cr_prison, jid);
	if (pr == NULL)
		error = ESRCH;
	else if (!prison_isalive(pr))
		error = ESRCH;
	else if (!prison_ischild(po->cred->cr_prison, pr))
		error = EPERM;
	else if (!prison_owns_vnet(pr))
		/* As pf_fbsd_open(): its pf would be the parent's. */
		error = EPERM;
	else {
		prison_hold_locked(pr);
		error = 0;
	}
	if (pr != NULL)
		mtx_unlock(&pr->pr_mtx);
	sx_sunlock(&allprison_lock);
	if (error == 0) {
		CURVNET_SET(pr->pr_vnet);
		if (!V_pf_fbsd_ready)
			error = ENXIO;
		CURVNET_RESTORE();
		if (error != 0)
			prison_free(pr);
	}
	if (error == 0) {
		/* Fresh: no transaction to drop in the old vnet (pfclose). */
		po->bound = pr;
		po->vnet = pr->pr_vnet;
	}
	atomic_store_rel_int(&po->state, error == 0 ? PF_FBSD_USED :
	    PF_FBSD_FRESH);
	return (error);
}

/* Every ioctl but DIOCBINDJAIL ends the descriptor's fresh state. */
static int
pf_fbsd_use(struct pf_fbsd_open *po)
{
	u_int state;

	for (;;) {
		state = atomic_load_acq_int(&po->state);
		if (state == PF_FBSD_USED)
			return (0);
		if (state == PF_FBSD_BINDING)
			return (EBUSY);
		if (atomic_cmpset_acq_int(&po->state, state, PF_FBSD_USED))
			return (0);
	}
}

static int
pf_fbsd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	struct pf_fbsd_open *po;
	int error;

	if ((error = devfs_get_cdevpriv((void **)&po)) != 0)
		return (error);
	SDT_PROBE2(pf, ioctl, ioctl, entry, cmd, po->unit);
	if (cmd == DIOCBINDJAIL) {
		error = pf_fbsd_bindjail(po, *(int *)data, td);
		SDT_PROBE3(pf, ioctl, ioctl, return, cmd, po->unit, error);
		return (error);
	}
	if ((error = pf_fbsd_use(po)) != 0) {
		SDT_PROBE3(pf, ioctl, ioctl, return, cmd, po->unit, error);
		return (error);
	}
	CURVNET_SET(po->vnet);
	if (!V_pf_fbsd_ready)
		error = ENXIO;
	/* The host owns the limits; a VNET jail has its quota (pf_quota.c). */
	else if (cmd == DIOCSETLIMIT && !IS_DEFAULT_VNET(curvnet))
		error = pf_quota_setlimit((struct pfioc_limit *)data);
	else if (cmd == DIOCGETLIMIT && !IS_DEFAULT_VNET(curvnet))
		error = pf_quota_getlimit((struct pfioc_limit *)data);
	else if (cmd == DIOCADDQUEUE)
		/*
		 * Queueing (HFSC, FQ-CoDel) is not attached to the 5BSD
		 * interface queues yet: refuse queue definitions up front so
		 * the transaction is rolled back with nothing half-committed.
		 */
		error = EOPNOTSUPP;
	else if (pf_eth_is_ioctl(cmd))
		error = pf_eth_ioctl(cmd, data, flags);
	else {
		error = pfioctl(pf_fbsd_minor(po->unit), cmd, data, flags,
		    td->td_proc);
		/* A transaction may have filled or emptied the ether rules. */
		if (cmd == DIOCXCOMMIT && error == 0)
			pf_eth_hook_update();
	}
	CURVNET_RESTORE();
	SDT_PROBE3(pf, ioctl, ioctl, return, cmd, po->unit, error);
	return (error);
}

static struct cdevsw pf_cdevsw = {
	.d_version =	D_VERSION,
	.d_name =	"pf",
	.d_open =	pf_fbsd_open,
	.d_ioctl =	pf_fbsd_ioctl,
};

/* ------------------------------------------------------------------ */
/* Module                                                              */
/* ------------------------------------------------------------------ */

static void
pf_fbsd_locks_init(void)
{
	rw_init(&pf_lock, "pf_lock");
	rw_init(&pf_state_lock, "pf_state_lock");
	rw_init(&pfioctl_rw, "pfioctl_rw");
	mtx_init(&pf_inp_mtx, IPL_SOFTNET);
}

static void
pf_fbsd_vnet_init(void *arg __unused)
{
	TAILQ_INIT(&V_pf_fbsd_delays);
	V_pf_fbsd_delay_count = 0;
	V_pf_fbsd_delay_closing = 0;
	mtx_init(&pf_state_list.pfs_mtx, IPL_SOFTNET);
	rw_init(&pf_state_list.pfs_rwl, "pfstates");
	TAILQ_INIT(&pf_state_list.pfs_list);
	TAILQ_INIT(&pf_statelim_list_active);
	TAILQ_INIT(&pf_statelim_list_inactive);
	TAILQ_INIT(&pf_sourcelim_list_active);
	TAILQ_INIT(&pf_sourcelim_list_inactive);
	TAILQ_INIT(&pf_source_gc);

	pf_quota_vnet_init();	/* before the first pool_get */
	pfattach(1);
	pf_eth_vnet_init();
	mq_init(&V_pf_pfsync_inq, 1024, IPL_SOFTNET);
	task_set(&V_pf_pfsync_intask, pf_fbsd_pfsync_intask, NULL);
	STAILQ_INIT(&V_pf_fbsd_divert_q);
	V_pf_fbsd_divert_closing = 0;
	task_set(&V_pf_fbsd_divert_task, pf_fbsd_divert_run, NULL);
	obsd_if_clone_vnet_attach();

	V_pf_fbsd_ready = 1;
	pf_fbsd_attach_existing();
	pf_fbsd_hook();
}
VNET_SYSINIT(pf_fbsd_vnet_init, SI_SUB_PROTO_FIREWALL, SI_ORDER_THIRD,
    pf_fbsd_vnet_init, NULL);

/* Empty one ruleset (and with it, the anchor once nothing refers to it). */
static void
pf_fbsd_flush_ruleset(const char *path)
{
	char anchor[MAXPATHLEN];
	u_int32_t ticket;

	strlcpy(anchor, path, sizeof(anchor));
	NET_LOCK();
	PF_LOCK();
	if (pf_begin_rules(&ticket, anchor) == 0)
		(void)pf_commit_rules(ticket, anchor);
	PF_UNLOCK();
	NET_UNLOCK();
}

static void
pf_fbsd_flush_rulesets(void)
{
	struct pf_anchor *a;
	char (*paths)[MAXPATHLEN];
	int i, n, pass;

	paths = malloc(64 * MAXPATHLEN, M_PF, M_WAITOK);
	for (pass = 0; pass < 32; pass++) {
		pf_fbsd_flush_ruleset("");
		n = 0;
		PF_LOCK();
		RB_FOREACH(a, pf_anchor_global, &pf_anchors) {
			if (n == 64)
				break;
			strlcpy(paths[n++], a->path, MAXPATHLEN);
		}
		PF_UNLOCK();
		if (n == 0)
			break;
		/* Children first: their removal empties their parents. */
		for (i = n - 1; i >= 0; i--)
			pf_fbsd_flush_ruleset(paths[i]);
	}
	free(paths, M_PF);
}

/*
 * The vnet's tag, queue and route label ids: its rules and states are
 * gone, so any id left is a leaked reference; free it with the vnet.
 */
static void
pf_fbsd_ids_fini(void)
{
	struct pf_tagname *t;
	int n = 0;

	PF_LOCK();
	while ((t = TAILQ_FIRST(&pf_tags)) != NULL) {
		TAILQ_REMOVE(&pf_tags, t, entries);
		pool_put(&pf_tag_pl, t);
		n++;
	}
	while ((t = TAILQ_FIRST(&pf_qids)) != NULL) {
		TAILQ_REMOVE(&pf_qids, t, entries);
		pool_put(&pf_tag_pl, t);
		n++;
	}
	PF_UNLOCK();
	if (n != 0)
		printf("pf: vnet %p torn down with %d tag or queue ids\n",
		    curvnet, n);
	obsd_rtlabel_vnet_fini();
}

static void
pf_fbsd_vnet_uninit(void *arg __unused)
{
	struct pfioc_state_kill psk;
	struct pfr_table filter;
	struct pf_src_node *sn;
	struct ifg_group *ifg;
	struct ifnet *ifp;
	struct epoch_tracker et;
	int i, ndel;

	/* No new packets for this pf. */
	pf_fbsd_unhook();
	pf_eth_vnet_unhook();
	NET_EPOCH_WAIT();
	pf_fbsd_delay_drain();

	/*
	 * pflog, pfsync and pflow interfaces of this vnet; their departure
	 * and group events still reach pf.  Then no more opens or events.
	 */
	obsd_if_clone_vnet_detach();
	V_pf_fbsd_ready = 0;
	/*
	 * pfsync input checks the flag in the net epoch of the IP input
	 * path and then queues for its task, which is drained and purged
	 * below: wait out an input that saw it still set.
	 */
	NET_EPOCH_WAIT();

	NET_LOCK();
	PF_LOCK();
	pf_status.running = 0;
	pf_remove_queues();
	PF_UNLOCK();
	NET_UNLOCK();

	/* Rules, anchors, limiters and queues; then tables and states. */
	pf_eth_vnet_fini();	/* ether rules hold tables and kifs */
	pf_fbsd_flush_rulesets();
	memset(&filter, 0, sizeof(filter));
	NET_LOCK();
	PF_LOCK();
	(void)pfr_clr_tables(&filter, &ndel, PFR_FLAG_ALLRSETS);
	PF_UNLOCK();
	NET_UNLOCK();
	pf_fbsd_flush_rulesets();

	memset(&psk, 0, sizeof(psk));
	(void)pf_states_clr(&psk);
	for (i = 0; i < 1000 && pf_status.states != 0; i++)
		(void)pf_purge_expired_states(UINT_MAX, 1024);
	pf_fbsd_divert_drain();

	NET_LOCK();
	PF_LOCK();
	RB_FOREACH(sn, pf_src_tree, &tree_src_tracking)
		sn->expire = 1;
	PF_UNLOCK();
	NET_UNLOCK();
	pf_purge(NULL);
	pf_osfp_flush();
	pf_normalize_vnet_fini();

	/* Timers and tasks re-arm each other: stop both twice. */
	for (i = 0; i < 3; i++) {
		timeout_del_barrier(&pf_purge_to);
		timeout_del_barrier(&pf_purge_states_to);
		taskq_del_barrier(systqmp, &pf_purge_task);
		taskq_del_barrier(systqmp, &pf_purge_states_task);
	}
	pf_syncookies_vnet_fini();
	taskq_del_barrier(systq, &V_pf_pfsync_intask);
	mq_purge(&V_pf_pfsync_inq);
	obsd_sendq_drain();
	obsd_pcbrele_drain();	/* before the protocols' pcb zones go */

	/*
	 * Interfaces still present in this vnet, then their groups:
	 * pfi_detach_ifnet() updates the kifs of the interface's groups.
	 */
	IFNET_RLOCK();
	CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		if_ref(ifp);
		IFNET_RUNLOCK();
		pfi_detach_ifnet(ifp);
		IFNET_RLOCK();
		if_rele(ifp);
	}
	IFNET_RUNLOCK();
	NET_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(ifg, &V_ifg_head, ifg_next)
		pfi_detach_ifgroup(ifg);
	NET_EPOCH_EXIT(et);

	if (pf_status.states != 0 || pf_status.src_nodes != 0 ||
	    pfr_ktable_cnt != 0 || !RB_EMPTY(&pf_anchors))
		printf("pf: vnet %p torn down with %u states, %u src nodes, "
		    "%d tables, anchors %s\n", curvnet, pf_status.states,
		    pf_status.src_nodes, pfr_ktable_cnt,
		    RB_EMPTY(&pf_anchors) ? "none" : "left");

	pfi_vnet_fini();
	pf_fbsd_ids_fini();
	counters_free(pf_status_fcounters, FCNT_MAX);
	pf_status_fcounters = NULL;
	cpumem_free(pf_anchor_stack, M_PF,
	    sizeof(struct pf_anchor_stackframe) * (PF_ANCHOR_STACK_MAX + 2));
	pf_anchor_stack = NULL;
	mtx_destroy(&V_pf_pfsync_inq.mq_mtx.mtx);
	mtx_destroy(&pf_frag_mtx.mtx);
	mtx_destroy(&pf_state_list.pfs_mtx.mtx);
	sx_destroy(&pf_state_list.pfs_rwl);
	pf_quota_vnet_fini();
}
VNET_SYSUNINIT(pf_fbsd_vnet_uninit, SI_SUB_PROTO_FIREWALL, SI_ORDER_THIRD,
    pf_fbsd_vnet_uninit, NULL);

static int
pf_fbsd_load(void)
{
	obsd_nmbclust = nmbclusters;
	bit_set(pf_units, 0);		/* unit 0 is never handed out */
	pf_fbsd_locks_init();

	/* Register the cloners; each vnet attaches them in its init. */
	pflogattach(1);
	pflowattach(1);
	pfsyncattach(1);
	(void)ipproto_register(IPPROTO_PFSYNC, pf_fbsd_pfsync_input, NULL);
#ifdef INET6
	(void)ip6proto_register(IPPROTO_PFSYNC, pf_fbsd_pfsync6_input, NULL);
#endif
	pf_divert_attach();
	pf_jail_attach();

	pf_fbsd_mtag_nomem = counter_u64_alloc(M_WAITOK);
	pf_mtag_unlink_hook = pf_fbsd_mtag_unlink;
	pf_mtag_copy_hook = pf_fbsd_mtag_copy;
	pf_inpcb_free_hook = pf_fbsd_inpcb_free;
	pf_delay_transmit_hook = pf_fbsd_delay_transmit;

	pf_ifattach_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
	    pf_fbsd_ifattach, NULL, EVENTHANDLER_PRI_ANY);
	/*
	 * Before netinet's in_ifdetach(): pfsync's detach hook leaves its
	 * multicast group, which in_purgemaddrs() would otherwise release
	 * (and free) under it.
	 */
	pf_ifdetach_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    pf_fbsd_ifdetach, NULL, EVENTHANDLER_PRI_FIRST);
	pf_ifaddr_tag = EVENTHANDLER_REGISTER(ifaddr_event_ext,
	    pf_fbsd_ifaddr, NULL, EVENTHANDLER_PRI_ANY);
	pf_ifrename_tag = EVENTHANDLER_REGISTER(ifnet_rename_event,
	    pf_fbsd_ifrename, NULL, EVENTHANDLER_PRI_ANY);
	pf_iflink_tag = EVENTHANDLER_REGISTER(ifnet_link_event,
	    pf_fbsd_iflink, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpattach_tag = EVENTHANDLER_REGISTER(group_attach_event,
	    pf_fbsd_grpattach, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpdetach_tag = EVENTHANDLER_REGISTER(group_detach_event,
	    pf_fbsd_grpdetach, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpchange_tag = EVENTHANDLER_REGISTER(group_change_event,
	    pf_fbsd_grpchange, NULL, EVENTHANDLER_PRI_ANY);

	pf_dev = make_dev(&pf_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "pf");
	return (0);
}

static int
pf_fbsd_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		/* Per-vnet instances start from pf_fbsd_vnet_init(). */
		return (pf_fbsd_load());
	case MOD_UNLOAD:
		/*
		 * Packets and sockets hold references to pf state keys, so
		 * OpenBSD PF cannot be unloaded.
		 */
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t pf_fbsd_mod = {
	"pf",
	pf_fbsd_modevent,
	0
};

DECLARE_MODULE(pf, pf_fbsd_mod, SI_SUB_PROTO_FIREWALL, SI_ORDER_SECOND);
MODULE_VERSION(pf, 2);
