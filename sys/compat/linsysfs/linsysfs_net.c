/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Dmitry Chagin <dchagin@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/vnet.h>

#include <compat/linux/linux.h>
#include <compat/linux/linux_common.h>
#include <fs/pseudofs/pseudofs.h>

#include <compat/linsysfs/linsysfs.h>

struct pfs_node *net, *net_class;
static eventhandler_tag if_arrival_tag, if_attached_tag, if_departure_tag;
static eventhandler_tag if_rename_tag;

static uint32_t net_latch_count = 0;
static struct mtx net_latch_mtx;
MTX_SYSINIT(net_latch_mtx, &net_latch_mtx, "lsfnet", MTX_DEF);

struct ifp_nodes_queue {
	TAILQ_ENTRY(ifp_nodes_queue) ifp_nodes_next;
	if_t ifp;
	struct vnet *vnet;
	struct pfs_node *pn;
	struct pfs_node *link;
};
TAILQ_HEAD(,ifp_nodes_queue) ifp_nodes_q;

static void
linsysfs_net_latch_hold(void)
{

	mtx_lock(&net_latch_mtx);
	if (net_latch_count++ > 0)
		mtx_sleep(&net_latch_count, &net_latch_mtx, PDROP, "lsfnet", 0);
	else
		mtx_unlock(&net_latch_mtx);
}

static void
linsysfs_net_latch_rele(void)
{

	mtx_lock(&net_latch_mtx);
	if (--net_latch_count > 0)
		wakeup_one(&net_latch_count);
	mtx_unlock(&net_latch_mtx);
}

static int
linsysfs_if_addr(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	struct l_sockaddr lsa;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	if (ifp != NULL && (error = linux_ifhwaddr(ifp, &lsa)) == 0)
		error = sbuf_printf(sb, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
		    lsa.sa_data[0], lsa.sa_data[1], lsa.sa_data[2],
		    lsa.sa_data[3], lsa.sa_data[4], lsa.sa_data[5]);
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_addrlen(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d\n", LINUX_IFHWADDRLEN);
	return (0);
}

static int
linsysfs_if_flags(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	if (ifp != NULL)
		error = sbuf_printf(sb, "0x%x\n", linux_ifflags(ifp));
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_ifindex(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	if (ifp != NULL)
		error = sbuf_printf(sb, "%u\n", if_getindex(ifp));
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_uevent(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	if (ifp != NULL)
		error = sbuf_printf(sb, "INTERFACE=%s\nIFINDEX=%u\n",
		    pn->pn_parent->pn_name, if_getindex(ifp));
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_mtu(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp( pn->pn_parent->pn_name);
	if (ifp != NULL)
		error = sbuf_printf(sb, "%u\n", if_getmtu(ifp));
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_txq_len(PFS_FILL_ARGS)
{

	/* XXX */
	sbuf_printf(sb, "1000\n");
	return (0);
}

/* Only counters with matching native meanings are exposed. */
static const struct {
	const char *name;
	ift_counter counter;
} linsysfs_net_counters[] = {
	{ "rx_packets", IFCOUNTER_IPACKETS },
	{ "tx_packets", IFCOUNTER_OPACKETS },
	{ "rx_bytes", IFCOUNTER_IBYTES },
	{ "tx_bytes", IFCOUNTER_OBYTES },
	{ "rx_errors", IFCOUNTER_IERRORS },
	{ "tx_errors", IFCOUNTER_OERRORS },
	{ "rx_dropped", IFCOUNTER_IQDROPS },
	{ "tx_dropped", IFCOUNTER_OQDROPS },
	{ "multicast", IFCOUNTER_IMCASTS },
	{ "collisions", IFCOUNTER_COLLISIONS },
};

static int
linsysfs_if_counter(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	uint64_t value;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_parent->pn_name);
	error = ENOENT;
	if (ifp != NULL) {
		value = if_getcounter(ifp, (ift_counter)(uintptr_t)pn->pn_data);
		error = sbuf_printf(sb, "%ju\n", (uintmax_t)value);
	}
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_linkstate(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	if_t ifp;
	int error, state, flags;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	error = ENOENT;
	if (ifp != NULL) {
		flags = if_getflags(ifp);
		state = if_getlinkstate(ifp);
		if (strcmp(pn->pn_name, "carrier") == 0) {
			if ((flags & IFF_UP) == 0)
				error = EINVAL;
			else
				error = sbuf_printf(sb, "%d\n",
				    state != LINK_STATE_DOWN);
		} else {
			error = sbuf_printf(sb, "%s\n",
			    (flags & IFF_UP) == 0 || state == LINK_STATE_DOWN ?
			    "down" : state == LINK_STATE_UP ? "up" : "unknown");
		}
	}
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_type(PFS_FILL_ARGS)
{
	struct epoch_tracker et;
	struct l_sockaddr lsa;
	if_t ifp;
	int error;

	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	ifp = ifname_linux_to_ifp(pn->pn_parent->pn_name);
	if (ifp != NULL && (error = linux_ifhwaddr(ifp, &lsa)) == 0)
		error = sbuf_printf(sb, "%d\n", lsa.sa_family);
	else
		error = ENOENT;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	/* pseudofs handles a full sbuf as a short read. */
	return (error == -1 ? 0 : error);
}

static int
linsysfs_if_visible(PFS_VIS_ARGS)
{
	struct epoch_tracker et;
	int visible;

	/* Match names inside the reader's VNET without traversing a mutable list. */
	CURVNET_SET(TD_TO_VNET(td));
	NET_EPOCH_ENTER(et);
	visible = ifname_linux_to_ifp(pn->pn_name) != NULL;
	NET_EPOCH_EXIT(et);
	CURVNET_RESTORE();
	return (visible);
}

static int
linsysfs_if_class_link(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "../../devices/virtual/net/%s", pn->pn_name);
	return (0);
}

static int
linsysfs_if_subsystem_link(PFS_FILL_ARGS)
{
	sbuf_cat(sb, "../../../../class/net");
	return (0);
}

static int
linsysfs_net_addif(if_t ifp, void *arg)
{
	struct ifp_nodes_queue *nq, *nq_tmp;
	struct pfs_node *nic, *link, *stats, *counter, *dir = arg;
	u_int i;
	char ifname[LINUX_IFNAMSIZ];
	struct epoch_tracker et;
	int ret;

	NET_EPOCH_ENTER(et);
	ret = ifname_bsd_to_linux_ifp(ifp, ifname, sizeof(ifname));
	NET_EPOCH_EXIT(et);
	/* Native rename accepts names that cannot be Linux path components. */
	if (ret <= 0 || ret >= sizeof(ifname) || strcmp(ifname, ".") == 0 ||
	    strcmp(ifname, "..") == 0)
		return (EINVAL);
	for (const char *cp = ifname; *cp != '\0'; cp++)
		if (*cp == '/' || *cp == ':' || isspace((unsigned char)*cp))
			return (EINVAL);

	nic = pfs_find_node(dir, ifname);
	if (nic == NULL) {
		pfs_create_dir(dir, &nic, ifname, NULL, linsysfs_if_visible,
		    NULL, 0);
		pfs_create_link(nic, NULL, "subsystem",
		    linsysfs_if_subsystem_link, NULL, NULL, NULL, 0);
		pfs_create_file(nic, NULL, "address", &linsysfs_if_addr, NULL,
		    NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "addr_len", &linsysfs_if_addrlen,
		    NULL, NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "flags", &linsysfs_if_flags, NULL,
		    NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "ifindex", &linsysfs_if_ifindex,
		    NULL, NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "uevent", &linsysfs_if_uevent,
		    NULL, NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "mtu", &linsysfs_if_mtu, NULL, NULL,
		    NULL, PFS_RD);
		pfs_create_file(nic, NULL, "tx_queue_len", &linsysfs_if_txq_len,
		    NULL, NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "type", &linsysfs_if_type, NULL,
		    NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "carrier", &linsysfs_if_linkstate,
		    NULL, NULL, NULL, PFS_RD);
		pfs_create_file(nic, NULL, "operstate", &linsysfs_if_linkstate,
		    NULL, NULL, NULL, PFS_RD);
		if (pfs_create_dir(nic, &stats, "statistics", NULL, NULL,
		    NULL, 0) == 0) {
			for (i = 0; i < nitems(linsysfs_net_counters); i++) {
				if (pfs_create_file(stats, &counter,
				    linsysfs_net_counters[i].name,
				    &linsysfs_if_counter, NULL, NULL, NULL,
				    PFS_RD) == 0)
					counter->pn_data = (void *)(uintptr_t)
					    linsysfs_net_counters[i].counter;
			}
		}
	}
	link = pfs_find_node(net_class, ifname);
	if (link == NULL)
		pfs_create_link(net_class, &link, ifname, linsysfs_if_class_link,
		    NULL, linsysfs_if_visible, NULL, 0);
	/*
	 * There is a small window between registering the if_arrival
	 * eventhandler and creating a list of interfaces.
	 */
	TAILQ_FOREACH_SAFE(nq, &ifp_nodes_q, ifp_nodes_next, nq_tmp) {
		if (nq->ifp == ifp && nq->vnet == curvnet)
			return (0);
	}
	nq = malloc(sizeof(*nq), M_LINSYSFS, M_WAITOK);
	nq->pn = nic;
	nq->link = link;
	nq->ifp = ifp;
	nq->vnet = curvnet;
	TAILQ_INSERT_TAIL(&ifp_nodes_q, nq, ifp_nodes_next);
	return (0);
}

static void
linsysfs_net_delif(if_t ifp)
{
	struct ifp_nodes_queue *nq, *nq_tmp;
	struct pfs_node *pn, *link;

	pn = link = NULL;
	TAILQ_FOREACH_SAFE(nq, &ifp_nodes_q, ifp_nodes_next, nq_tmp) {
		if (nq->ifp == ifp && nq->vnet == curvnet) {
			TAILQ_REMOVE(&ifp_nodes_q, nq, ifp_nodes_next);
			pn = nq->pn;
			link = nq->link;
			free(nq, M_LINSYSFS);
			break;
		}
	}
	if (pn == NULL)
		return;
	TAILQ_FOREACH_SAFE(nq, &ifp_nodes_q, ifp_nodes_next, nq_tmp) {
		if (nq->pn == pn)
			return;
	}
	pfs_destroy(link);
	pfs_destroy(pn);
}

/* The latch keeps queue names and sysfs publication ordered with events. */
static const char *
linsysfs_net_name(if_t ifp)
{
	struct ifp_nodes_queue *nq;

	TAILQ_FOREACH(nq, &ifp_nodes_q, ifp_nodes_next)
		if (nq->ifp == ifp && nq->vnet == curvnet)
			return (nq->pn->pn_name);
	return (NULL);
}

static void
linsysfs_if_arrival(void *arg __unused, if_t ifp)
{
	linsysfs_net_latch_hold();
	(void)linsysfs_net_addif(ifp, net);
	linsysfs_net_latch_rele();
}

static void
linsysfs_if_attached(void *arg __unused, if_t ifp)
{
	const char *name;

	/* Arrival precedes if_link_ifnet; publish only after lookup can find it. */
	linsysfs_net_latch_hold();
	name = linsysfs_net_name(ifp);
	if (name != NULL)
		linux_net_uevent(ifp, "add", name, NULL);
	linsysfs_net_latch_rele();
}

static void
linsysfs_if_departure(void *arg __unused, if_t ifp)
{
	char name[LINUX_IFNAMSIZ];
	const char *old;

	linsysfs_net_latch_hold();
	old = linsysfs_net_name(ifp);
	if (old != NULL) {
		strlcpy(name, old, sizeof(name));
		linsysfs_net_delif(ifp);
		linux_net_uevent(ifp, "remove", name, NULL);
	}
	linsysfs_net_latch_rele();
}

static void
linsysfs_if_rename(void *arg __unused, if_t ifp)
{
	char oldname[LINUX_IFNAMSIZ];
	const char *name;

	linsysfs_net_latch_hold();
	name = linsysfs_net_name(ifp);
	if (name != NULL)
		strlcpy(oldname, name, sizeof(oldname));
	else
		oldname[0] = '\0';
	linsysfs_net_delif(ifp);
	(void)linsysfs_net_addif(ifp, net);
	name = linsysfs_net_name(ifp);
	if (name != NULL && oldname[0] != '\0') {
		if (strcmp(name, oldname) != 0)
			linux_net_uevent(ifp, "move", name, oldname);
	} else if (name != NULL)
		linux_net_uevent(ifp, "add", name, NULL);
	else if (oldname[0] != '\0')
		linux_net_uevent(ifp, "remove", oldname, NULL);
	linsysfs_net_latch_rele();
}

void
linsysfs_net_init(void)
{
	VNET_ITERATOR_DECL(vnet_iter);

	MPASS(net != NULL);
	TAILQ_INIT(&ifp_nodes_q);

	if_arrival_tag = EVENTHANDLER_REGISTER(ifnet_arrival_event,
	    linsysfs_if_arrival, NULL, EVENTHANDLER_PRI_ANY);
	if_attached_tag = EVENTHANDLER_REGISTER(ifnet_attached_event,
	    linsysfs_if_attached, NULL, EVENTHANDLER_PRI_ANY);
	if_departure_tag = EVENTHANDLER_REGISTER(ifnet_departure_event,
	    linsysfs_if_departure, NULL, EVENTHANDLER_PRI_ANY);
	if_rename_tag = EVENTHANDLER_REGISTER(ifnet_rename_event,
	    linsysfs_if_rename, NULL, EVENTHANDLER_PRI_ANY);

	linsysfs_net_latch_hold();
	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		if_foreach_sleep(NULL, NULL, linsysfs_net_addif, net);
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();
	linsysfs_net_latch_rele();
}

void
linsysfs_net_uninit(void)
{
	struct ifp_nodes_queue *nq, *nq_tmp;

	EVENTHANDLER_DEREGISTER(ifnet_attached_event, if_attached_tag);
	EVENTHANDLER_DEREGISTER(ifnet_arrival_event, if_arrival_tag);
	EVENTHANDLER_DEREGISTER(ifnet_departure_event, if_departure_tag);
	EVENTHANDLER_DEREGISTER(ifnet_rename_event, if_rename_tag);

	linsysfs_net_latch_hold();
	TAILQ_FOREACH_SAFE(nq, &ifp_nodes_q, ifp_nodes_next, nq_tmp) {
		TAILQ_REMOVE(&ifp_nodes_q, nq, ifp_nodes_next);
		free(nq, M_LINSYSFS);
	}
	linsysfs_net_latch_rele();
}
