/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * ng_hci_virt - virtual HCI controller netgraph node.
 *
 * A software controller transport that presents the identical upstream
 * contract as ng_ubt (the USB controller driver): a single netgraph hook
 * ("hook") that connects to the ng_hci node's "drv" hook and carries
 * type-prefixed HCI packets in both directions.  The stack (ng_hci,
 * ng_l2cap, blued) cannot tell it apart from a real adapter, so the whole
 * Bluetooth stack can be brought up end-to-end with NO hardware.
 *
 * The controller-facing side of the node is bridged to userspace through a
 * per-instance cloning character device /dev/vhciN.  The kernel half does
 * no HCI parsing at all: the drv-hook wire format (a 1-byte packet-type
 * indicator followed by the HCI payload) is byte-identical to what the
 * userspace controller emulator already speaks, so the node is a straight
 * pipe.
 *
 *   host -> controller (Command 0x01 / ACL 0x02 / SCO 0x03 / ISO 0x05):
 *       delivered down the hook by ng_hci, queued, handed to read(2).
 *   controller -> host (Event 0x04 / ACL 0x02 / SCO 0x03 / ISO 0x05):
 *       write(2)n by userspace, forwarded up the hook to ng_hci.
 *
 * Instances are created and destroyed through the /dev/vhci control device
 * (VHCI_CREATE / VHCI_DESTROY ioctls).  The design and coding idiom mirror
 * the in-tree virtual HID transport, sys/dev/hid/vhid.c.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/uio.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>

#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_hci_virt.h>

/* Depth of the host->controller queue awaiting read(2), in packets. */
#define	VHCI_QLEN	64

MALLOC_DEFINE(M_NG_HCI_VIRT, "ng_hci_virt", "Virtual HCI controller");

/*
 * Per-instance state.  Referenced simultaneously by the netgraph node
 * (as node private) and by the /dev/vhciN cdev (as si_drv1); sc->mtx
 * serialises the two contexts around the rx queue and the hook pointer.
 */
struct vhci_softc {
	struct mtx	mtx;
	int		unit;
	struct cdev	*cdev;
	node_p		node;		/* our netgraph node */
	hook_p		hook;		/* upstream hook to ng_hci "drv" */
	struct mbufq	rxq;		/* host->controller, awaiting read() */
	struct selinfo	rsel;		/* poll/select readers */
	bool		open;		/* /dev/vhciN is open */
	bool		dying;		/* teardown in progress */
	bool		waiting;	/* a reader is asleep on rxq */
};

/* Module-global registry of instances, guarded by vhci_gmtx. */
static struct mtx		vhci_gmtx;
static struct vhci_softc	*vhci_units[NG_HCI_VIRT_MAX_UNITS];
static struct cdev		*vhci_ctl_dev;

/* Reserve a slot while make_dev_s runs without holding vhci_gmtx. */
#define	VHCI_SENTINEL	((struct vhci_softc *)(uintptr_t)1)

/* ------------------------------------------------------------------ *
 * Netgraph node methods
 * ------------------------------------------------------------------ */

static ng_constructor_t	ng_hci_virt_constructor;
static ng_shutdown_t	ng_hci_virt_shutdown;
static ng_newhook_t	ng_hci_virt_newhook;
static ng_connect_t	ng_hci_virt_connect;
static ng_rcvdata_t	ng_hci_virt_rcvdata;
static ng_disconnect_t	ng_hci_virt_disconnect;

static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_HCI_VIRT_NODE_TYPE,
	.constructor =	ng_hci_virt_constructor,
	.shutdown =	ng_hci_virt_shutdown,
	.newhook =	ng_hci_virt_newhook,
	.connect =	ng_hci_virt_connect,
	.rcvdata =	ng_hci_virt_rcvdata,
	.disconnect =	ng_hci_virt_disconnect,
};

/*
 * vhci nodes may only be created through /dev/vhci (they need a backing
 * softc + cdev), never with an unbacked `ngctl mkpeer . vhci ...`.
 */
static int
ng_hci_virt_constructor(node_p node)
{
	return (EINVAL);
}

/* Forward decl: reclaim an instance orphaned by an external ngctl shutdown. */
static void	vhci_external_reclaim(struct vhci_softc *sc);

static int
ng_hci_virt_shutdown(node_p node)
{
	struct vhci_softc *sc = NG_NODE_PRIVATE(node);
	bool owned_ref = false;
	bool external = false;

	/*
	 * The node dies here whether the teardown was initiated by
	 * VHCI_DESTROY / module unload (NG_NODE_REALLY_DIE + ng_rmnode_self)
	 * or by an external `ngctl shutdown vhciN:'.  Sever the softc's back
	 * pointer under the lock so a later destroy path will not touch a
	 * freed node.
	 */
	if (sc != NULL) {
		mtx_lock(&sc->mtx);
		if (sc->node != NULL) {
			sc->node = NULL;
			owned_ref = true;	/* we hold the softc's node ref */
			/*
			 * If sc->dying is not yet set, no VHCI_DESTROY /
			 * unload is reclaiming this instance: we were reached
			 * by an external `ngctl shutdown' and must reclaim the
			 * cdev + unit slot ourselves (finding 103).
			 */
			external = !sc->dying;
		}
		sc->hook = NULL;
		mtx_unlock(&sc->mtx);

		if (external)
			vhci_external_reclaim(sc);
	}

	NG_NODE_SET_PRIVATE(node, NULL);
	if (owned_ref)
		NG_NODE_UNREF(node);	/* release the softc reference (102) */
	NG_NODE_UNREF(node);		/* release the existence reference */

	return (0);
}

/*
 * Finding 103: an external `ngctl shutdown vhciN' fires this node's shutdown
 * method without ever passing through vhci_destroy()/vhci_teardown(), so the
 * cdev and the vhci_units[] slot would otherwise leak — and repeated external
 * shutdowns would exhaust the unit table (ENOSPC on the next VHCI_CREATE).
 * Claim the slot (arbitrated against a concurrent destroy/unload by
 * vhci_gmtx, exactly as those paths do) and, if we win it, tear down the
 * softc side ourselves.  The node itself is already being destroyed by the
 * caller, so we touch only the cdev/queue/softc here.
 */
static void
vhci_external_reclaim(struct vhci_softc *sc)
{
	bool owned;

	mtx_lock(&vhci_gmtx);
	owned = (sc->unit >= 0 && sc->unit < NG_HCI_VIRT_MAX_UNITS &&
	    vhci_units[sc->unit] == sc);
	if (owned)
		vhci_units[sc->unit] = NULL;
	mtx_unlock(&vhci_gmtx);
	if (!owned)
		return;			/* VHCI_DESTROY/unload owns this sc */

	/* Release any blocked reader and refuse new opens before destroy_dev. */
	mtx_lock(&sc->mtx);
	sc->dying = true;
	if (sc->waiting) {
		sc->waiting = false;
		wakeup(sc);
	}
	selwakeup(&sc->rsel);
	mtx_unlock(&sc->mtx);

	destroy_dev(sc->cdev);
	mbufq_drain(&sc->rxq);
	seldrain(&sc->rsel);
	mtx_destroy(&sc->mtx);
	free(sc, M_NG_HCI_VIRT);
}

static int
ng_hci_virt_newhook(node_p node, hook_p hook, const char *name)
{
	struct vhci_softc *sc = NG_NODE_PRIVATE(node);

	if (sc == NULL)
		return (ENXIO);
	if (strcmp(name, NG_HCI_VIRT_HOOK) != 0)
		return (EINVAL);

	mtx_lock(&sc->mtx);
	if (sc->hook != NULL) {
		mtx_unlock(&sc->mtx);
		return (EISCONN);
	}
	sc->hook = hook;
	mtx_unlock(&sc->mtx);

	return (0);
}

static int
ng_hci_virt_connect(hook_p hook)
{
	/*
	 * Preserve ordering with the peer ng_hci node exactly as ng_ubt
	 * does: force the peer's incoming data onto the netgraph queue so
	 * command/event ordering is not reordered by direct dispatch.
	 */
	NG_HOOK_FORCE_QUEUE(NG_HOOK_PEER(hook));

	return (0);
}

static int
ng_hci_virt_disconnect(hook_p hook)
{
	struct vhci_softc *sc = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));

	if (sc != NULL) {
		mtx_lock(&sc->mtx);
		if (hook == sc->hook)
			sc->hook = NULL;
		mtx_unlock(&sc->mtx);
	}

	return (0);
}

/*
 * Data arriving down the hook from ng_hci is host->controller traffic
 * (HCI Command / ACL / SCO / ISO, already type-prefixed).  Queue it for
 * the userspace controller emulator to read().
 */
static int
ng_hci_virt_rcvdata(hook_p hook, item_p item)
{
	struct vhci_softc *sc = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct mbuf *m;
	int error = 0;

	if (sc == NULL) {
		NG_FREE_ITEM(item);
		return (ENXIO);
	}

	NGI_GET_M(item, m);
	NG_FREE_ITEM(item);

	if (m == NULL)
		return (0);

	mtx_lock(&sc->mtx);
	if (!sc->open) {
		/* No emulator attached: drop, like a controller with no host. */
		mtx_unlock(&sc->mtx);
		NG_FREE_M(m);
		return (0);
	}
	if (mbufq_enqueue(&sc->rxq, m) != 0) {
		/*
		 * Finding 39: the rxq is full.  An HCI Command
		 * (NG_HCI_CMD_PKT) must never be silently discarded: its
		 * Command_Complete / Command_Status would then never be
		 * generated, so ng_hci's num_cmd_pkts flow-control credit is
		 * never returned and the command pipeline stalls until reset.
		 * A blind drop-oldest can evict exactly such a queued command.
		 * Instead:
		 *   - drop the NEWEST packet (the incoming one) when it is data,
		 *     leaving every already-queued packet — including any
		 *     command — intact;
		 *   - only when the incoming packet is itself a command do we
		 *     evict the oldest queued packet to make room, and never
		 *     when that oldest packet is also a command.
		 * The packet-type indicator is the first payload octet (the
		 * drv-hook wire format is a type byte followed by the HCI PDU).
		 */
		uint8_t itype = (m->m_len > 0) ? *mtod(m, uint8_t *) : 0;
		struct mbuf *head = mbufq_first(&sc->rxq);
		uint8_t htype = (head != NULL && head->m_len > 0) ?
		    *mtod(head, uint8_t *) : 0;

		if (itype == NG_HCI_CMD_PKT && htype != NG_HCI_CMD_PKT) {
			struct mbuf *old = mbufq_dequeue(&sc->rxq);

			if (old != NULL)
				m_freem(old);
			(void)mbufq_enqueue(&sc->rxq, m);
		} else {
			/* Drop the newest; keep queued commands intact. */
			m_freem(m);
		}
		error = ENOBUFS;
	}
	if (sc->waiting) {
		sc->waiting = false;
		wakeup(sc);
	}
	selwakeup(&sc->rsel);
	mtx_unlock(&sc->mtx);

	return (error);
}

/*
 * Forward one type-prefixed controller->host packet up the hook to ng_hci.
 * Called from cdev write context (not a netgraph thread); mirror ng_ubt's
 * hook-ref dance so a concurrent disconnect cannot free the hook underneath
 * NG_SEND_DATA_ONLY().
 */
static int
vhci_send_upstream(struct vhci_softc *sc, struct mbuf *m)
{
	hook_p hook;
	int error;

	mtx_lock(&sc->mtx);
	hook = sc->hook;
	if (hook != NULL)
		NG_HOOK_REF(hook);
	mtx_unlock(&sc->mtx);

	if (hook == NULL) {
		/* Host stack not attached yet: drop the event. */
		NG_FREE_M(m);
		return (0);
	}

	NG_SEND_DATA_ONLY(error, hook, m);
	NG_HOOK_UNREF(hook);

	return (error);
}

/* ------------------------------------------------------------------ *
 * Per-instance cdev methods (/dev/vhciN)
 * ------------------------------------------------------------------ */

static d_open_t		vhci_dev_open;
static d_close_t	vhci_dev_close;
static d_read_t		vhci_dev_read;
static d_write_t	vhci_dev_write;
static d_poll_t		vhci_dev_poll;

static struct cdevsw vhci_dev_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vhci_dev_open,
	.d_close =	vhci_dev_close,
	.d_read =	vhci_dev_read,
	.d_write =	vhci_dev_write,
	.d_poll =	vhci_dev_poll,
	.d_name =	"vhci",
};

static int
vhci_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct vhci_softc *sc = dev->si_drv1;

	if (sc == NULL)
		return (ENXIO);

	mtx_lock(&sc->mtx);
	if (sc->dying) {
		mtx_unlock(&sc->mtx);
		return (ENXIO);
	}
	if (sc->open) {
		mtx_unlock(&sc->mtx);
		return (EBUSY);
	}
	sc->open = true;
	mtx_unlock(&sc->mtx);

	return (0);
}

static int
vhci_dev_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct vhci_softc *sc = dev->si_drv1;

	if (sc == NULL)
		return (0);

	mtx_lock(&sc->mtx);
	sc->open = false;
	mbufq_drain(&sc->rxq);
	if (sc->waiting) {
		sc->waiting = false;
		wakeup(sc);
	}
	mtx_unlock(&sc->mtx);

	return (0);
}

/*
 * read(2): return exactly one queued host->controller packet, blocking
 * (unless O_NONBLOCK) until one is available.
 */
static int
vhci_dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct vhci_softc *sc = dev->si_drv1;
	struct mbuf *m;
	uint8_t buf[NG_HCI_VIRT_MTU];
	int len, error;

	if (sc == NULL)
		return (ENXIO);

	mtx_lock(&sc->mtx);
	for (;;) {
		if (!sc->open || sc->dying) {
			mtx_unlock(&sc->mtx);
			return (ENXIO);
		}
		m = mbufq_dequeue(&sc->rxq);
		if (m != NULL)
			break;
		if (ioflag & O_NONBLOCK) {
			mtx_unlock(&sc->mtx);
			return (EWOULDBLOCK);
		}
		sc->waiting = true;
		error = msleep(sc, &sc->mtx, PCATCH, "vhcird", 0);
		if (error != 0) {
			mtx_unlock(&sc->mtx);
			return (error);
		}
	}
	mtx_unlock(&sc->mtx);

	len = m->m_pkthdr.len;
	if (len > (int)sizeof(buf) || len > uio->uio_resid) {
		m_freem(m);
		return (EMSGSIZE);
	}
	m_copydata(m, 0, len, buf);
	m_freem(m);

	error = uiomove(buf, len, uio);

	return (error);
}

/*
 * write(2): inject exactly one type-prefixed controller->host packet
 * (HCI Event / ACL / SCO / ISO) up the stack.
 */
static int
vhci_dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct vhci_softc *sc = dev->si_drv1;
	struct mbuf *m;
	int len, error;

	if (sc == NULL)
		return (ENXIO);

	len = uio->uio_resid;
	if (len < 1 || len > NG_HCI_VIRT_MTU)
		return (EINVAL);

	m = m_get2(len, M_WAITOK, MT_DATA, M_PKTHDR);
	error = uiomove(mtod(m, void *), len, uio);
	if (error != 0) {
		m_freem(m);
		return (error);
	}
	m->m_len = len;
	m->m_pkthdr.len = len;

	return (vhci_send_upstream(sc, m));
}

static int
vhci_dev_poll(struct cdev *dev, int events, struct thread *td)
{
	struct vhci_softc *sc = dev->si_drv1;
	int revents = 0;

	if (sc == NULL)
		return (POLLERR);

	/* A controller endpoint is always writable. */
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	if (events & (POLLIN | POLLRDNORM)) {
		mtx_lock(&sc->mtx);
		if (!sc->open)
			revents |= POLLHUP;
		else if (mbufq_len(&sc->rxq) > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &sc->rsel);
		mtx_unlock(&sc->mtx);
	}

	return (revents);
}

/* ------------------------------------------------------------------ *
 * Instance create / destroy
 * ------------------------------------------------------------------ */

static int
vhci_create(int *unitp)
{
	struct vhci_softc *sc;
	struct make_dev_args mda;
	char name[16];
	int unit, error;

	mtx_lock(&vhci_gmtx);
	for (unit = 0; unit < NG_HCI_VIRT_MAX_UNITS; unit++) {
		if (vhci_units[unit] == NULL)
			break;
	}
	if (unit >= NG_HCI_VIRT_MAX_UNITS) {
		mtx_unlock(&vhci_gmtx);
		return (ENOSPC);
	}
	vhci_units[unit] = VHCI_SENTINEL;	/* reserve the slot */
	mtx_unlock(&vhci_gmtx);

	sc = malloc(sizeof(*sc), M_NG_HCI_VIRT, M_WAITOK | M_ZERO);
	mtx_init(&sc->mtx, "ng_hci_virt", NULL, MTX_DEF);
	mbufq_init(&sc->rxq, VHCI_QLEN);
	sc->unit = unit;

	/* Create and name the netgraph node. */
	error = ng_make_node_common(&typestruct, &sc->node);
	if (error != 0)
		goto fail_node;
	NG_NODE_SET_PRIVATE(sc->node, sc);
	NG_NODE_FORCE_WRITER(sc->node);

	/*
	 * Finding 102: hold an explicit reference for the copy of the node
	 * pointer cached in sc->node, independent of the node's create-time
	 * existence reference.  Otherwise an external `ngctl shutdown vhciN'
	 * running concurrently with VHCI_DESTROY/unload can drop the last ref
	 * (via ng_hci_virt_shutdown -> NG_NODE_UNREF) and free the node while
	 * vhci_teardown() still dereferences sc->node.  Whichever path clears
	 * sc->node (shutdown or teardown) releases this reference.
	 */
	NG_NODE_REF(sc->node);

	snprintf(name, sizeof(name), NG_HCI_VIRT_NODE_TYPE "%d", unit);
	error = ng_name_node(sc->node, name);
	if (error != 0)
		goto fail_named;

	/* Create the userspace endpoint /dev/vhciN. */
	make_dev_args_init(&mda);
	mda.mda_devsw = &vhci_dev_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0600;
	mda.mda_unit = unit;
	error = make_dev_s(&mda, &sc->cdev, NG_HCI_VIRT_NODE_TYPE "%d", unit);
	if (error != 0)
		goto fail_named;
	sc->cdev->si_drv1 = sc;

	mtx_lock(&vhci_gmtx);
	vhci_units[unit] = sc;
	mtx_unlock(&vhci_gmtx);

	*unitp = unit;
	return (0);

fail_named:
	NG_NODE_SET_PRIVATE(sc->node, NULL);
	NG_NODE_REALLY_DIE(sc->node);
	ng_rmnode_self(sc->node);
	NG_NODE_UNREF(sc->node);	/* release the softc reference (finding 102) */
fail_node:
	mtx_lock(&vhci_gmtx);
	vhci_units[unit] = NULL;
	mtx_unlock(&vhci_gmtx);
	mbufq_drain(&sc->rxq);
	mtx_destroy(&sc->mtx);
	free(sc, M_NG_HCI_VIRT);

	return (error);
}

/*
 * Tear down one instance.  The caller must have already removed sc from
 * vhci_units[] so no new opener can find it.
 */
static void
vhci_teardown(struct vhci_softc *sc)
{
	node_p node;

	/*
	 * Release any thread blocked in read() and refuse further opens
	 * before destroy_dev(), which will otherwise wait forever for a
	 * sleeping reader to leave the driver.
	 */
	mtx_lock(&sc->mtx);
	sc->dying = true;
	if (sc->waiting) {
		sc->waiting = false;
		wakeup(sc);
	}
	selwakeup(&sc->rsel);
	mtx_unlock(&sc->mtx);

	/* Drains in-flight cdev operations and blocks new opens. */
	destroy_dev(sc->cdev);

	/*
	 * Remove the netgraph node (fires disconnect + shutdown), unless it
	 * was already torn down out from under us by an external ngctl
	 * shutdown, in which case ng_hci_virt_shutdown() has cleared sc->node.
	 */
	mtx_lock(&sc->mtx);
	node = sc->node;
	sc->node = NULL;
	mtx_unlock(&sc->mtx);
	if (node != NULL) {
		/*
		 * We observed sc->node non-NULL, so we own the softc's node
		 * reference (finding 102).  It keeps the node struct valid
		 * across REALLY_DIE + ng_rmnode_self (which triggers
		 * ng_hci_virt_shutdown and drops the existence reference);
		 * release it once we are done touching the node.  If an
		 * external shutdown cleared sc->node first, it already dropped
		 * this reference and node is NULL here.
		 */
		NG_NODE_REALLY_DIE(node);
		ng_rmnode_self(node);
		NG_NODE_UNREF(node);
	}

	mbufq_drain(&sc->rxq);
	seldrain(&sc->rsel);
	mtx_destroy(&sc->mtx);
	free(sc, M_NG_HCI_VIRT);
}

static int
vhci_destroy(int unit)
{
	struct vhci_softc *sc;

	if (unit < 0 || unit >= NG_HCI_VIRT_MAX_UNITS)
		return (EINVAL);

	mtx_lock(&vhci_gmtx);
	sc = vhci_units[unit];
	if (sc == NULL || sc == VHCI_SENTINEL) {
		mtx_unlock(&vhci_gmtx);
		return (ENOENT);
	}
	mtx_lock(&sc->mtx);
	if (sc->open) {
		mtx_unlock(&sc->mtx);
		mtx_unlock(&vhci_gmtx);
		return (EBUSY);
	}
	mtx_unlock(&sc->mtx);
	vhci_units[unit] = NULL;
	mtx_unlock(&vhci_gmtx);

	vhci_teardown(sc);

	return (0);
}

/* ------------------------------------------------------------------ *
 * Control cdev methods (/dev/vhci)
 * ------------------------------------------------------------------ */

static d_ioctl_t	vhci_ctl_ioctl;

static struct cdevsw vhci_ctl_cdevsw = {
	.d_version =	D_VERSION,
	.d_ioctl =	vhci_ctl_ioctl,
	.d_name =	"vhci",
};

static int
vhci_ctl_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	error = priv_check(td, PRIV_DRIVER);
	if (error != 0)
		return (error);

	switch (cmd) {
	case VHCI_CREATE:
		return (vhci_create((int *)data));

	case VHCI_DESTROY:
		return (vhci_destroy(*(int *)data));

	default:
		return (ENOTTY);
	}
}

/* ------------------------------------------------------------------ *
 * Module glue
 * ------------------------------------------------------------------ */

static int
ng_hci_virt_mod_load(void)
{
	struct make_dev_args mda;
	int error;

	mtx_init(&vhci_gmtx, "ng_hci_virt g", NULL, MTX_DEF);

	error = ng_newtype(&typestruct);
	if (error != 0) {
		printf("%s: cannot register netgraph type %s, error=%d\n",
		    __func__, NG_HCI_VIRT_NODE_TYPE, error);
		mtx_destroy(&vhci_gmtx);
		return (error);
	}

	make_dev_args_init(&mda);
	mda.mda_devsw = &vhci_ctl_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0600;
	error = make_dev_s(&mda, &vhci_ctl_dev, NG_HCI_VIRT_CTL_NAME);
	if (error != 0) {
		printf("%s: cannot create /dev/%s, error=%d\n", __func__,
		    NG_HCI_VIRT_CTL_NAME, error);
		(void)ng_rmtype(&typestruct);
		mtx_destroy(&vhci_gmtx);
		return (error);
	}

	return (0);
}

static int
ng_hci_virt_mod_unload(void)
{
	int i;

	/* Refuse to unload while any instance is still open. */
	mtx_lock(&vhci_gmtx);
	for (i = 0; i < NG_HCI_VIRT_MAX_UNITS; i++) {
		struct vhci_softc *sc = vhci_units[i];

		if (sc == NULL || sc == VHCI_SENTINEL)
			continue;
		mtx_lock(&sc->mtx);
		if (sc->open) {
			mtx_unlock(&sc->mtx);
			mtx_unlock(&vhci_gmtx);
			return (EBUSY);
		}
		mtx_unlock(&sc->mtx);
	}
	mtx_unlock(&vhci_gmtx);

	if (vhci_ctl_dev != NULL)
		destroy_dev(vhci_ctl_dev);

	/* Destroy any remaining (idle) instances. */
	for (i = 0; i < NG_HCI_VIRT_MAX_UNITS; i++) {
		struct vhci_softc *sc;

		mtx_lock(&vhci_gmtx);
		sc = vhci_units[i];
		if (sc == NULL || sc == VHCI_SENTINEL) {
			mtx_unlock(&vhci_gmtx);
			continue;
		}
		vhci_units[i] = NULL;
		mtx_unlock(&vhci_gmtx);
		vhci_teardown(sc);
	}

	ng_rmtype(&typestruct);
	mtx_destroy(&vhci_gmtx);

	return (0);
}

static int
ng_hci_virt_modevent(module_t mod, int event, void *data)
{
	int error;

	switch (event) {
	case MOD_LOAD:
		error = ng_hci_virt_mod_load();
		break;

	case MOD_UNLOAD:
		error = ng_hci_virt_mod_unload();
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t ng_hci_virt_mod = {
	"ng_hci_virt",
	ng_hci_virt_modevent,
	NULL
};

DECLARE_MODULE(ng_hci_virt, ng_hci_virt_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(ng_hci_virt, NG_BLUETOOTH_VERSION);
MODULE_DEPEND(ng_hci_virt, netgraph, NG_ABI_VERSION, NG_ABI_VERSION,
    NG_ABI_VERSION);
MODULE_DEPEND(ng_hci_virt, ng_hci, NG_BLUETOOTH_VERSION, NG_BLUETOOTH_VERSION,
    NG_BLUETOOTH_VERSION);
MODULE_DEPEND(ng_hci_virt, ng_bluetooth, NG_BLUETOOTH_VERSION,
    NG_BLUETOOTH_VERSION, NG_BLUETOOTH_VERSION);
