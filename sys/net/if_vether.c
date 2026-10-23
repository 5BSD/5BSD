/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * vether(4): virtual Ethernet interface, as on OpenBSD.  A vether
 * interface looks like a normal Ethernet interface (link-layer address,
 * ARP, neighbour discovery, multicast) but has no hardware: transmitted
 * frames are passed to BPF and dropped unless the interface is a bridge
 * member.  It is used to give a host or a routing domain an Ethernet
 * address without a physical port, and by the OpenBSD routing regress
 * tests.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_clone.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/vnet.h>

static const char vethername[] = "vether";

VNET_DEFINE_STATIC(struct if_clone *, vether_cloner);
#define	V_vether_cloner	VNET(vether_cloner)

static int
vether_transmit(struct ifnet *ifp, struct mbuf *m)
{
	BPF_MTAP(ifp, m);
	if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
	if_inc_counter(ifp, IFCOUNTER_OBYTES, m->m_pkthdr.len);
	if (m->m_flags & (M_BCAST | M_MCAST))
		if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);
	m_freem(m);
	return (0);
}

static void
vether_qflush(struct ifnet *ifp __unused)
{
}

static void
vether_init(void *arg)
{
	struct ifnet *ifp = arg;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
}

static int
vether_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			ifp->if_drv_flags |= IFF_DRV_RUNNING;
		else
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		return (0);
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		return (0);
	case SIOCSIFMTU:
		if (ifr->ifr_mtu < ETHERMIN || ifr->ifr_mtu > ETHERMTU_JUMBO)
			return (EINVAL);
		ifp->if_mtu = ifr->ifr_mtu;
		return (0);
	default:
		return (ether_ioctl(ifp, cmd, data));
	}
}

static int
vether_clone_create(struct if_clone *ifc, char *name, size_t len,
    struct ifc_data *ifd, struct ifnet **ifpp)
{
	struct ifnet *ifp;
	uint8_t eaddr[ETHER_ADDR_LEN];

	ifp = if_alloc(IFT_ETHER);
	if_initname(ifp, vethername, ifd->unit);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_capabilities = ifp->if_capenable = IFCAP_VLAN_MTU;
	ifp->if_init = vether_init;
	ifp->if_ioctl = vether_ioctl;
	ifp->if_transmit = vether_transmit;
	ifp->if_qflush = vether_qflush;
	ifp->if_softc = ifp;
	ifp->if_link_state = LINK_STATE_UP;

	/* Random, locally administered unicast address (as OpenBSD). */
	arc4rand(eaddr, sizeof(eaddr), 0);
	eaddr[0] &= ~0x01;
	eaddr[0] |= 0x02;
	ether_ifattach(ifp, eaddr);
	if_link_state_change(ifp, LINK_STATE_UP);
	*ifpp = ifp;
	return (0);
}

static int
vether_clone_destroy(struct if_clone *ifc, struct ifnet *ifp, uint32_t flags)
{
	ether_ifdetach(ifp);
	if_free(ifp);
	return (0);
}

static void
vnet_vether_init(const void *unused __unused)
{
	struct if_clone_addreq req = {
		.create_f = vether_clone_create,
		.destroy_f = vether_clone_destroy,
		.flags = IFC_F_AUTOUNIT,
	};

	V_vether_cloner = ifc_attach_cloner(vethername, &req);
}
VNET_SYSINIT(vnet_vether_init, SI_SUB_PSEUDO, SI_ORDER_ANY,
    vnet_vether_init, NULL);

static void
vnet_vether_uninit(const void *unused __unused)
{
	ifc_detach_cloner(V_vether_cloner);
}
VNET_SYSUNINIT(vnet_vether_uninit, SI_SUB_PSEUDO, SI_ORDER_ANY,
    vnet_vether_uninit, NULL);

static int
vether_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
	case MOD_UNLOAD:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t vether_mod = {
	"if_vether",
	vether_modevent,
	NULL
};

DECLARE_MODULE(if_vether, vether_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_vether, 1);
