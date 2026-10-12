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
void	pf_mbuf_unlink_state_key(struct mbuf *);
void	pf_mbuf_unlink_inpcb(struct mbuf *);
void	pf_mbuf_link_state_key(struct mbuf *, struct pf_state_key *);
void	pf_mbuf_link_inpcb(struct mbuf *, struct inpcb *);
void	pf_inp_unlink(struct inpcb *);
void	pf_remove_divert_state(struct inpcb *);
void	obsd_ifhooks_run(struct ifnet *, int);
void	pfi_attach_ifnet(struct ifnet *);
void	pfi_detach_ifnet(struct ifnet *);
void	pfi_attach_ifgroup(struct ifg_group *);
void	pfi_detach_ifgroup(struct ifg_group *);
void	pfi_group_addmember(const char *);
extern struct sx pfioctl_rw;

/* ------------------------------------------------------------------ */
/* mbuf and inpcb reference hooks                                      */
/* ------------------------------------------------------------------ */

static void
pf_fbsd_mbuf_unlink(struct mbuf *m)
{
	pf_mbuf_unlink_state_key(m);
	pf_mbuf_unlink_inpcb(m);
}

static void
pf_fbsd_mbuf_link(struct mbuf *to, const struct mbuf *from)
{
	if (from->m_pkthdr.pf.statekey != NULL)
		pf_mbuf_link_state_key(to, from->m_pkthdr.pf.statekey);
	if (from->m_pkthdr.pf.inp != NULL)
		pf_mbuf_link_inpcb(to, from->m_pkthdr.pf.inp);
}

static void
pf_fbsd_inpcb_free(struct inpcb *inp)
{
	pf_remove_divert_state(inp);
	pf_inp_unlink(inp);
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

static void
pf_fbsd_in_csum(struct mbuf *m)
{
	m->m_pkthdr.csum_flags &= ~(CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
	    CSUM_SCTP_VALID);
}

#ifdef INET
static pfil_return_t
pf_fbsd_check_in(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	pf_fbsd_in_csum(*m);
	return (pf_fbsd_result(pf_fbsd_test(AF_INET, PF_IN, ifp, m), m));
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
	rv = pf_fbsd_result(pf_fbsd_test(AF_INET,
	    (flags & PFIL_FWD) ? PF_FWD : PF_OUT, ifp, m), m);
	if (rv != PFIL_PASS)
		return (rv);
	n = *m;
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
	pf_fbsd_in_csum(*m);
	return (pf_fbsd_result(pf_fbsd_test(AF_INET6, PF_IN, ifp, m), m));
}

static pfil_return_t
pf_fbsd_check6_out(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	struct mbuf *n = *m;
	pfil_return_t rv;

	if ((n->m_pkthdr.csum_flags & CSUM_TSO) == 0 &&
	    (n->m_pkthdr.csum_flags & CSUM_DELAY_DATA_IPV6)) {
		in6_delayed_cksum(n, n->m_pkthdr.len - sizeof(struct ip6_hdr),
		    sizeof(struct ip6_hdr));
		n->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA_IPV6;
	}
	rv = pf_fbsd_result(pf_fbsd_test(AF_INET6,
	    (flags & PFIL_FWD) ? PF_FWD : PF_OUT, ifp, m), m);
	if (rv != PFIL_PASS)
		return (rv);
	n = *m;
	if ((n->m_pkthdr.csum_flags & CSUM_TSO) == 0 &&
	    (n->m_pkthdr.csum_flags & (CSUM_IP6_TCP | CSUM_IP6_UDP)))
		in6_proto_cksum_out(n, ifp);
	return (rv);
}
#endif

/*
 * pfsync input runs in task context: OpenBSD processes it under the
 * (sleepable) net lock and pfsync takes sleepable locks, which must not
 * be acquired inside the net epoch of the IP input path.
 */
static struct mbuf_queue pf_pfsync_inq;
static struct task pf_pfsync_intask;

static void
pf_fbsd_pfsync_intask(void *arg)
{
	struct mbuf_list ml;
	struct mbuf *m;
	int off;

	mq_delist(&pf_pfsync_inq, &ml);
	while ((m = ml_dequeue(&ml)) != NULL) {
		off = mtod(m, struct ip *)->ip_hl << 2;
		NET_LOCK_SHARED();
		(void)pfsync_input4(&m, &off, IPPROTO_PFSYNC, AF_INET, NULL);
		NET_UNLOCK_SHARED();
	}
}

static int
pf_fbsd_pfsync_input(struct mbuf **mp, int *offp, int proto)
{
	if (mq_enqueue(&pf_pfsync_inq, *mp) == 0)
		task_add(systq, &pf_pfsync_intask);
	*mp = NULL;
	return (IPPROTO_DONE);
}

static pfil_hook_t pf_ip4_in_hook, pf_ip4_out_hook;
static pfil_hook_t pf_ip6_in_hook, pf_ip6_out_hook;

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

/* ------------------------------------------------------------------ */
/* Interface and group events                                          */
/* ------------------------------------------------------------------ */

#define	OBSD_HOOK_ADDR		1
#define	OBSD_HOOK_DETACH	2
#define	OBSD_HOOK_LINK		3

static eventhandler_tag pf_ifattach_tag, pf_ifdetach_tag, pf_ifaddr_tag;
static eventhandler_tag pf_iflink_tag, pf_grpattach_tag, pf_grpdetach_tag;
static eventhandler_tag pf_grpchange_tag;

static void
pf_fbsd_ifattach(void *arg, struct ifnet *ifp)
{
	pfi_attach_ifnet(ifp);
}

static void
pf_fbsd_ifdetach(void *arg, struct ifnet *ifp)
{
	obsd_ifhooks_run(ifp, OBSD_HOOK_DETACH);
	pfi_detach_ifnet(ifp);
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
	pfi_attach_ifgroup(ifg);
}

static void
pf_fbsd_grpdetach(void *arg, struct ifg_group *ifg)
{
	pfi_detach_ifgroup(ifg);
}

static void
pf_fbsd_grpchange(void *arg, const char *gname)
{
	pfi_group_addmember(gname);	/* locks; add and delete are alike */
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
	/* pfi_attach_ifnet() may sleep; walk with references. */
	IFNET_RLOCK();
	CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		if_ref(ifp);
		IFNET_RUNLOCK();
		pfi_attach_ifnet(ifp);
		IFNET_RLOCK();
		if_rele(ifp);
	}
	IFNET_RUNLOCK();
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
	int	unit;
};

static dev_t
pf_fbsd_minor(int unit)
{
	return (makedev(0, unit << CLONE_SHIFT));
}

static void
pf_fbsd_dtor(void *arg)
{
	struct pf_fbsd_open *po = arg;

	(void)pfclose(pf_fbsd_minor(po->unit), 0, 0, curproc);
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
	error = pfopen(pf_fbsd_minor(unit), flags, fmt, td->td_proc);
	if (error == 0)
		error = devfs_set_cdevpriv(po, pf_fbsd_dtor);
	if (error) {
		mtx_lock(&pf_units_mtx);
		bit_clear(pf_units, unit);
		mtx_unlock(&pf_units_mtx);
		free(po, M_PF);
	}
	return (error);
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
	error = pfioctl(pf_fbsd_minor(po->unit), cmd, data, flags,
	    td->td_proc);
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
	mtx_init(&pf_state_list.pfs_mtx, IPL_SOFTNET);
	rw_init(&pf_state_list.pfs_rwl, "pfstates");
}

static int
pf_fbsd_load(void)
{
	obsd_nmbclust = nmbclusters;
	bit_set(pf_units, 0);		/* unit 0 is never handed out */
	pf_fbsd_locks_init();

	pfattach(1);
	pflogattach(1);
	pflowattach(1);
	pfsyncattach(1);
	mq_init(&pf_pfsync_inq, 1024, IPL_SOFTNET);
	task_set(&pf_pfsync_intask, pf_fbsd_pfsync_intask, NULL);
	(void)ipproto_register(IPPROTO_PFSYNC, pf_fbsd_pfsync_input, NULL);

	pf_mbuf_unlink_hook = pf_fbsd_mbuf_unlink;
	pf_mbuf_link_hook = pf_fbsd_mbuf_link;
	pf_inpcb_free_hook = pf_fbsd_inpcb_free;

	pf_ifattach_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
	    pf_fbsd_ifattach, NULL, EVENTHANDLER_PRI_ANY);
	pf_ifdetach_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    pf_fbsd_ifdetach, NULL, EVENTHANDLER_PRI_ANY);
	pf_ifaddr_tag = EVENTHANDLER_REGISTER(ifaddr_event_ext,
	    pf_fbsd_ifaddr, NULL, EVENTHANDLER_PRI_ANY);
	pf_iflink_tag = EVENTHANDLER_REGISTER(ifnet_link_event,
	    pf_fbsd_iflink, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpattach_tag = EVENTHANDLER_REGISTER(group_attach_event,
	    pf_fbsd_grpattach, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpdetach_tag = EVENTHANDLER_REGISTER(group_detach_event,
	    pf_fbsd_grpdetach, NULL, EVENTHANDLER_PRI_ANY);
	pf_grpchange_tag = EVENTHANDLER_REGISTER(group_change_event,
	    pf_fbsd_grpchange, NULL, EVENTHANDLER_PRI_ANY);
	pf_fbsd_attach_existing();

	pf_fbsd_hook();

	pf_dev = make_dev(&pf_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "pf");
	return (0);
}

static int
pf_fbsd_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD: {
		int error;

		/* pf state is global for now: it filters the default vnet. */
		CURVNET_SET(vnet0);
		error = pf_fbsd_load();
		CURVNET_RESTORE();
		return (error);
	}
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
