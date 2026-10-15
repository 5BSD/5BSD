/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * The "egress" interface group, as on OpenBSD: it holds the interfaces
 * that the default routes (IPv4 0.0.0.0/0 and IPv6 ::/0) of routing
 * table 0 point to, so that pf rules and ifconfig(8) can name the uplink
 * without knowing its interface name ("pass out on egress",
 * "nat-to (egress)").
 *
 * OpenBSD rebuilds the group from rtable 0 whenever a default route is
 * added or changed.  Here a routing table subscription on FIB 0 of each
 * VNET notices default route changes (additions, changes and deletions)
 * and a task brings the group membership in line with the routing table.
 * The task runs outside the routing table lock because if_addgroup() and
 * if_delgroup() sleep.  Reject and blackhole routes do not count.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/route.h>
#include <net/route/nhop.h>
#include <net/route/route_ctl.h>
#include <net/route/route_var.h>
#include <net/vnet.h>

#include <netinet/in.h>

#if defined(INET) || defined(INET6)

/* At most one path set per address family, each up to the multipath width. */
#define	EGRESS_MAX	(2 * RIB_MAX_MPATH_WIDTH)

struct egress_set {
	struct ifnet	*ifp[EGRESS_MAX];
	int		 count;
};

VNET_DEFINE_STATIC(struct task, egress_task);
#define	V_egress_task	VNET(egress_task)
VNET_DEFINE_STATIC(struct rib_subscription *, egress_rs4);
#define	V_egress_rs4	VNET(egress_rs4)
VNET_DEFINE_STATIC(struct rib_subscription *, egress_rs6);
#define	V_egress_rs6	VNET(egress_rs6)

static bool
egress_set_has(const struct egress_set *set, const struct ifnet *ifp)
{
	for (int i = 0; i < set->count; i++)
		if (set->ifp[i] == ifp)
			return (true);
	return (false);
}

static void
egress_set_add(struct egress_set *set, struct nhop_object *nh)
{
	struct ifnet *ifp;

	NET_EPOCH_ASSERT();

	if (nh->nh_flags & (NHF_REJECT | NHF_BLACKHOLE))
		return;
	ifp = nh->nh_ifp;
	if (egress_set_has(set, ifp) || set->count >= EGRESS_MAX)
		return;
	if (if_try_ref(ifp))
		set->ifp[set->count++] = ifp;
}

/* Collect the interfaces of the default route of @family in FIB 0. */
static void
egress_collect(struct egress_set *set, int family)
{
	struct route_nhop_data rnd;
	struct sockaddr_storage dst;
	struct rib_head *rnh;
	struct nhop_object *nh;
	const struct weightened_nhop *wn;
	uint32_t num;
	RIB_RLOCK_TRACKER;

	NET_EPOCH_ASSERT();

	rnh = rt_tables_get_rnh(0, family);
	if (rnh == NULL)
		return;

	bzero(&dst, sizeof(dst));
	dst.ss_family = family;
	switch (family) {
#ifdef INET
	case AF_INET:
		dst.ss_len = sizeof(struct sockaddr_in);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		dst.ss_len = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		return;
	}

	RIB_RLOCK(rnh);
	if (rib_lookup_prefix_plen(rnh, (struct sockaddr *)&dst, 0,
	    &rnd) != NULL &&
	    (nh = rnd.rnd_nhop) != NULL) {
		if (NH_IS_NHGRP(nh)) {
			wn = nhgrp_get_nhops(rnd.rnd_nhgrp, &num);
			for (uint32_t i = 0; i < num; i++)
				egress_set_add(set, wn[i].nh);
		} else
			egress_set_add(set, nh);
	}
	RIB_RUNLOCK(rnh);
}

static bool
egress_is_member(struct ifnet *ifp)
{
	struct ifg_list *ifgl;
	struct epoch_tracker et;
	bool member = false;

	NET_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(ifgl, &ifp->if_groups, ifgl_next)
		if (strcmp(ifgl->ifgl_group->ifg_group, IFG_EGRESS) == 0) {
			member = true;
			break;
		}
	NET_EPOCH_EXIT(et);
	return (member);
}

static int
egress_sync_one(struct ifnet *ifp, void *arg)
{
	struct egress_set *set = arg;
	bool want, have;

	want = egress_set_has(set, ifp);
	have = egress_is_member(ifp);
	if (want && !have)
		(void)if_addgroup(ifp, IFG_EGRESS);
	else if (!want && have)
		(void)if_delgroup(ifp, IFG_EGRESS);
	return (0);
}

static void
egress_task_fn(void *arg, int pending __unused)
{
	struct vnet *vnet __unused = arg;	/* unused without VIMAGE */
	struct egress_set *set;
	struct epoch_tracker et;

	set = malloc(sizeof(*set), M_TEMP, M_WAITOK | M_ZERO);

	CURVNET_SET(vnet);
	NET_EPOCH_ENTER(et);
#ifdef INET
	egress_collect(set, AF_INET);
#endif
#ifdef INET6
	egress_collect(set, AF_INET6);
#endif
	NET_EPOCH_EXIT(et);

	(void)if_foreach_sleep(NULL, NULL, egress_sync_one, set);
	CURVNET_RESTORE();

	for (int i = 0; i < set->count; i++)
		if_rele(set->ifp[i]);
	free(set, M_TEMP);
}

/*
 * Routing table change, called with the table locked: if it is a default
 * route, schedule a rebuild.
 */
static void
egress_rib_change(struct rib_head *rnh, struct rib_cmd_info *rc, void *arg)
{
	struct task *task = arg;
	int plen;

	plen = -1;
	switch (rnh->rib_family) {
#ifdef INET
	case AF_INET: {
		struct in_addr addr;
		uint32_t scopeid;

		rt_get_inet_prefix_plen(rc->rc_rt, &addr, &plen, &scopeid);
		break;
	}
#endif
#ifdef INET6
	case AF_INET6: {
		struct in6_addr addr6;
		uint32_t scopeid;

		rt_get_inet6_prefix_plen(rc->rc_rt, &addr6, &plen, &scopeid);
		break;
	}
#endif
	}
	if (plen == 0)
		taskqueue_enqueue(taskqueue_thread, task);
}

static struct rib_subscription *
egress_subscribe(int family)
{
	struct rib_head *rnh;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	rnh = rt_tables_get_rnh(0, family);
	NET_EPOCH_EXIT(et);
	if (rnh == NULL)
		return (NULL);
	/* The argument is this vnet's task: callers need not set curvnet. */
	return (rib_subscribe_internal(rnh, egress_rib_change, &V_egress_task,
	    RIB_NOTIFY_IMMEDIATE, true));
}

static void
vnet_egress_init(const void *unused __unused)
{
	TASK_INIT(&V_egress_task, 0, egress_task_fn, curvnet);
#ifdef INET
	V_egress_rs4 = egress_subscribe(AF_INET);
#endif
#ifdef INET6
	V_egress_rs6 = egress_subscribe(AF_INET6);
#endif
}
/* After vnet_rtables_init() (SI_ORDER_FOURTH) created the tables. */
VNET_SYSINIT(vnet_egress_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY,
    vnet_egress_init, NULL);

#ifdef VIMAGE
static void
vnet_egress_uninit(const void *unused __unused)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	if (V_egress_rs4 != NULL)
		rib_unsubscribe(V_egress_rs4);
	if (V_egress_rs6 != NULL)
		rib_unsubscribe(V_egress_rs6);
	NET_EPOCH_EXIT(et);
	V_egress_rs4 = V_egress_rs6 = NULL;
	/* No new rebuilds can be queued; wait for a pending one. */
	taskqueue_drain(taskqueue_thread, &V_egress_task);
}
/* Before rtables_destroy() (SI_ORDER_FIRST) frees the tables. */
VNET_SYSUNINIT(vnet_egress_uninit, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY,
    vnet_egress_uninit, NULL);
#endif

#endif /* INET || INET6 */
