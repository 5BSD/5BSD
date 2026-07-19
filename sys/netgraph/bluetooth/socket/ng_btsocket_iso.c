/*
 * ng_btsocket_iso.c
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 Kory Heard
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitstring.h>
#include <sys/domain.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/filedesc.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/vnet.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/bluetooth/include/ng_bluetooth.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/include/ng_btsocket.h>
#include <netgraph/bluetooth/include/ng_btsocket_iso.h>

#include <sys/sdt.h>

SDT_PROVIDER_DECLARE(bluetooth);

/*
 * Largest ISO Data_Total_Length we will honor from a controller
 * (Core Spec Vol 4 Part E §5.4.5).  It is bounded by what a single HCI
 * ISO fragment can physically carry in one mbuf cluster: MCLBYTES is the
 * cluster size and sizeof(ng_hci_isodata_pkt_t) is the fixed 5-byte HCI
 * ISO header that every fragment (including continuations) carries.  This
 * cap is what keeps ISOAL segmentation in ng_btsocket_iso_send2() from
 * copying past the destination fragment buffer (finding #1) and gives all
 * fragment classes one coherent max_pdu (finding #7).
 */
#define NG_BTSOCKET_ISO_MAX_PKT_SIZE \
	((u_int16_t)(MCLBYTES - sizeof(ng_hci_isodata_pkt_t)))

/* Socket layer probes for ISO */
SDT_PROBE_DEFINE1(bluetooth, socket, connect, iso,
    "uint16_t"		/* con_handle */
);

SDT_PROBE_DEFINE1(bluetooth, socket, disconnect, iso,
    "uint16_t"		/* con_handle */
);

SDT_PROBE_DEFINE2(bluetooth, socket, send, iso,
    "uint16_t",		/* con_handle */
    "int"		/* length */
);

SDT_PROBE_DEFINE2(bluetooth, socket, recv, iso,
    "uint16_t",		/* con_handle */
    "int"		/* length */
);

/* MALLOC define */
#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_BTSOCKET_ISO, "netgraph_btsocks_iso",
		"Netgraph Bluetooth ISO sockets");
#else
#define M_NETGRAPH_BTSOCKET_ISO M_NETGRAPH
#endif /* NG_SEPARATE_MALLOC */

/* Netgraph node methods */
static ng_constructor_t	ng_btsocket_iso_node_constructor;
static ng_rcvmsg_t	ng_btsocket_iso_node_rcvmsg;
static ng_shutdown_t	ng_btsocket_iso_node_shutdown;
static ng_newhook_t	ng_btsocket_iso_node_newhook;
static ng_connect_t	ng_btsocket_iso_node_connect;
static ng_rcvdata_t	ng_btsocket_iso_node_rcvdata;
static ng_disconnect_t	ng_btsocket_iso_node_disconnect;

static void		ng_btsocket_iso_input   (void *, int);
static void		ng_btsocket_iso_rtclean (void *, int);
static int		ng_btsocket_iso_frag_ring_put
				(ng_btsocket_iso_pcb_p, u_int8_t, int);

/* Netgraph type descriptor */
static struct ng_type	typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_BTSOCKET_ISO_NODE_TYPE,
	.constructor =	ng_btsocket_iso_node_constructor,
	.rcvmsg =	ng_btsocket_iso_node_rcvmsg,
	.shutdown =	ng_btsocket_iso_node_shutdown,
	.newhook =	ng_btsocket_iso_node_newhook,
	.connect =	ng_btsocket_iso_node_connect,
	.rcvdata =	ng_btsocket_iso_node_rcvdata,
	.disconnect =	ng_btsocket_iso_node_disconnect,
};

/* Globals */
static u_int32_t				ng_btsocket_iso_debug_level;
static node_p					ng_btsocket_iso_node;
static struct ng_bt_itemq			ng_btsocket_iso_queue;
static struct mtx				ng_btsocket_iso_queue_mtx;
static struct task				ng_btsocket_iso_queue_task;
static struct mtx				ng_btsocket_iso_sockets_mtx;
static LIST_HEAD(, ng_btsocket_iso_pcb)		ng_btsocket_iso_sockets;
static LIST_HEAD(, ng_btsocket_iso_rtentry)	ng_btsocket_iso_rt;
static struct mtx				ng_btsocket_iso_rt_mtx;
static struct task				ng_btsocket_iso_rt_task;
static struct timeval				ng_btsocket_iso_lasttime;
static int					ng_btsocket_iso_curpps;

/* Sysctl tree */
SYSCTL_DECL(_net_bluetooth_iso_sockets);
static SYSCTL_NODE(_net_bluetooth_iso_sockets, OID_AUTO, seq,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Bluetooth SEQPACKET ISO sockets family");
SYSCTL_UINT(_net_bluetooth_iso_sockets_seq, OID_AUTO, debug_level,
	CTLFLAG_RW,
	&ng_btsocket_iso_debug_level, NG_BTSOCKET_WARN_LEVEL,
	"Bluetooth SEQPACKET ISO sockets debug level");
SYSCTL_UINT(_net_bluetooth_iso_sockets_seq, OID_AUTO, queue_len,
	CTLFLAG_RD,
	&ng_btsocket_iso_queue.len, 0,
	"Bluetooth SEQPACKET ISO sockets input queue length");
SYSCTL_UINT(_net_bluetooth_iso_sockets_seq, OID_AUTO, queue_maxlen,
	CTLFLAG_RD,
	&ng_btsocket_iso_queue.maxlen, 0,
	"Bluetooth SEQPACKET ISO sockets input queue max. length");
SYSCTL_UINT(_net_bluetooth_iso_sockets_seq, OID_AUTO, queue_drops,
	CTLFLAG_RD,
	&ng_btsocket_iso_queue.drops, 0,
	"Bluetooth SEQPACKET ISO sockets input queue drops");

/* Debug */
#define NG_BTSOCKET_ISO_INFO \
	if (ng_btsocket_iso_debug_level >= NG_BTSOCKET_INFO_LEVEL && \
	    ppsratecheck(&ng_btsocket_iso_lasttime, &ng_btsocket_iso_curpps, 1)) \
		printf

#define NG_BTSOCKET_ISO_WARN \
	if (ng_btsocket_iso_debug_level >= NG_BTSOCKET_WARN_LEVEL && \
	    ppsratecheck(&ng_btsocket_iso_lasttime, &ng_btsocket_iso_curpps, 1)) \
		printf

#define NG_BTSOCKET_ISO_ERR \
	if (ng_btsocket_iso_debug_level >= NG_BTSOCKET_ERR_LEVEL && \
	    ppsratecheck(&ng_btsocket_iso_lasttime, &ng_btsocket_iso_curpps, 1)) \
		printf

#define NG_BTSOCKET_ISO_ALERT \
	if (ng_btsocket_iso_debug_level >= NG_BTSOCKET_ALERT_LEVEL && \
	    ppsratecheck(&ng_btsocket_iso_lasttime, &ng_btsocket_iso_curpps, 1)) \
		printf

/*
 * Netgraph message processing routines
 */

static int ng_btsocket_iso_process_lp_con_cfm
	(struct ng_mesg *, ng_btsocket_iso_rtentry_p);
static int ng_btsocket_iso_process_lp_con_ind
	(struct ng_mesg *, ng_btsocket_iso_rtentry_p);
static int ng_btsocket_iso_process_lp_discon_ind
	(struct ng_mesg *, ng_btsocket_iso_rtentry_p);

/*
 * Send LP messages to the lower layer
 */

static int  ng_btsocket_iso_send_lp_con_req
	(ng_btsocket_iso_pcb_p);
static int  ng_btsocket_iso_send_lp_con_rsp
	(ng_btsocket_iso_rtentry_p, bdaddr_p, u_int16_t, int);
static int  ng_btsocket_iso_send_lp_discon_req
	(ng_btsocket_iso_pcb_p);

static int ng_btsocket_iso_send2
	(ng_btsocket_iso_pcb_p);

/*
 * Timeout processing routines
 */

static void ng_btsocket_iso_timeout         (ng_btsocket_iso_pcb_p);
static void ng_btsocket_iso_untimeout       (ng_btsocket_iso_pcb_p);
static void ng_btsocket_iso_process_timeout (void *);

/*
 * Other stuff
 */

static ng_btsocket_iso_pcb_p	ng_btsocket_iso_pcb_by_addr(bdaddr_p);
static ng_btsocket_iso_pcb_p	ng_btsocket_iso_pcb_by_handle(bdaddr_p, int);
static void			ng_btsocket_iso_abort_rx_reassembly
				(bdaddr_p, int);

#define ng_btsocket_iso_wakeup_input_task() \
	taskqueue_enqueue(taskqueue_swi, &ng_btsocket_iso_queue_task)

#define ng_btsocket_iso_wakeup_route_task() \
	taskqueue_enqueue(taskqueue_swi, &ng_btsocket_iso_rt_task)

/*****************************************************************************
 *****************************************************************************
 **                        Netgraph node interface
 *****************************************************************************
 *****************************************************************************/

/*
 * Netgraph node constructor. Do not allow to create node of this type.
 */

static int
ng_btsocket_iso_node_constructor(node_p node)
{
	return (EINVAL);
} /* ng_btsocket_iso_node_constructor */

/*
 * Do local shutdown processing. Let old node go and create new fresh one.
 */

static int
ng_btsocket_iso_node_shutdown(node_p node)
{
	int	error = 0;

	NG_NODE_UNREF(node);

	/* Create new node */
	error = ng_make_node_common(&typestruct, &ng_btsocket_iso_node);
	if (error != 0) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not create Netgraph node, error=%d\n", __func__, error);

		ng_btsocket_iso_node = NULL;

		return (error);
	}

	error = ng_name_node(ng_btsocket_iso_node,
				NG_BTSOCKET_ISO_NODE_TYPE);
	if (error != 0) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not name Netgraph node, error=%d\n", __func__, error);

		NG_NODE_UNREF(ng_btsocket_iso_node);
		ng_btsocket_iso_node = NULL;

		return (error);
	}

	return (0);
} /* ng_btsocket_iso_node_shutdown */

/*
 * We allow any hook to be connected to the node.
 */

static int
ng_btsocket_iso_node_newhook(node_p node, hook_p hook, char const *name)
{
	return (0);
} /* ng_btsocket_iso_node_newhook */

/*
 * Just say "YEP, that's OK by me!"
 */

static int
ng_btsocket_iso_node_connect(hook_p hook)
{
	NG_HOOK_SET_PRIVATE(hook, NULL);
	NG_HOOK_REF(hook); /* Keep extra reference to the hook */

	return (0);
} /* ng_btsocket_iso_node_connect */

/*
 * Hook disconnection. Schedule route cleanup task
 */

static int
ng_btsocket_iso_node_disconnect(hook_p hook)
{
	/*
	 * If hook has private information than we must have this hook in
	 * the routing table and must schedule cleaning for the routing table.
	 * Otherwise hook was connected but we never got "hook_info" message,
	 * so we have never added this hook to the routing table and it save
	 * to just delete it.
	 */

	if (NG_HOOK_PRIVATE(hook) != NULL)
		return (ng_btsocket_iso_wakeup_route_task());

	NG_HOOK_UNREF(hook); /* Remove extra reference */

	return (0);
} /* ng_btsocket_iso_node_disconnect */

/*
 * Process incoming messages
 */

static int
ng_btsocket_iso_node_rcvmsg(node_p node, item_p item, hook_p hook)
{
	struct ng_mesg	*msg = NGI_MSG(item); /* item still has message */
	int		 error = 0;

	if (msg != NULL && msg->header.typecookie == NGM_HCI_COOKIE) {
		mtx_lock(&ng_btsocket_iso_queue_mtx);
		if (NG_BT_ITEMQ_FULL(&ng_btsocket_iso_queue)) {
			NG_BTSOCKET_ISO_ERR(
"%s: Input queue is full (msg)\n", __func__);

			NG_BT_ITEMQ_DROP(&ng_btsocket_iso_queue);
			NG_FREE_ITEM(item);
			error = ENOBUFS;
		} else {
			if (hook != NULL) {
				NG_HOOK_REF(hook);
				NGI_SET_HOOK(item, hook);
			}

			NG_BT_ITEMQ_ENQUEUE(&ng_btsocket_iso_queue, item);
			error = ng_btsocket_iso_wakeup_input_task();
		}
		mtx_unlock(&ng_btsocket_iso_queue_mtx);
	} else {
		NG_FREE_ITEM(item);
		error = EINVAL;
	}

	return (error);
} /* ng_btsocket_iso_node_rcvmsg */

/*
 * Receive data on a hook
 */

static int
ng_btsocket_iso_node_rcvdata(hook_p hook, item_p item)
{
	int	error = 0;

	mtx_lock(&ng_btsocket_iso_queue_mtx);
	if (NG_BT_ITEMQ_FULL(&ng_btsocket_iso_queue)) {
		NG_BTSOCKET_ISO_ERR(
"%s: Input queue is full (data)\n", __func__);

		NG_BT_ITEMQ_DROP(&ng_btsocket_iso_queue);
		NG_FREE_ITEM(item);
		error = ENOBUFS;
	} else {
		NG_HOOK_REF(hook);
		NGI_SET_HOOK(item, hook);

		NG_BT_ITEMQ_ENQUEUE(&ng_btsocket_iso_queue, item);
		error = ng_btsocket_iso_wakeup_input_task();
	}
	mtx_unlock(&ng_btsocket_iso_queue_mtx);

	return (error);
} /* ng_btsocket_iso_node_rcvdata */

/*
 * Process LP_ConnectCfm event from the lower layer protocol
 */

static int
ng_btsocket_iso_process_lp_con_cfm(struct ng_mesg *msg,
		ng_btsocket_iso_rtentry_p rt)
{
	ng_hci_lp_con_cfm_ep	*ep = NULL;
	ng_btsocket_iso_pcb_t	*pcb = NULL;
	int			 error = 0;

	if (msg->header.arglen != sizeof(*ep))
		return (EMSGSIZE);

	ep = (ng_hci_lp_con_cfm_ep *)(msg->data);

	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	/* Look for the socket with the token */
	pcb = ng_btsocket_iso_pcb_by_handle(&rt->src, ep->con_handle);
	if (pcb == NULL) {
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		return (ENOENT);
	}

	/* pcb is locked */

	NG_BTSOCKET_ISO_INFO(
"%s: Got LP_ConnectCfm response, src bdaddr=%x:%x:%x:%x:%x:%x, " \
"dst bdaddr=%x:%x:%x:%x:%x:%x, status=%d, handle=%d, state=%d\n",
		__func__,
		pcb->src.b[5], pcb->src.b[4], pcb->src.b[3],
		pcb->src.b[2], pcb->src.b[1], pcb->src.b[0],
		pcb->dst.b[5], pcb->dst.b[4], pcb->dst.b[3],
		pcb->dst.b[2], pcb->dst.b[1], pcb->dst.b[0],
		ep->status, ep->con_handle, pcb->state);

	if (pcb->state != NG_BTSOCKET_ISO_CONNECTING) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);

		return (ENOENT);
	}

	ng_btsocket_iso_untimeout(pcb);

	if (ep->status == 0) {
		/*
		 * Connection is open. Update connection handle and
		 * socket state
		 */

		pcb->con_handle = ep->con_handle;
		pcb->state = NG_BTSOCKET_ISO_OPEN;
		SDT_PROBE1(bluetooth, socket, connect, iso,
		    pcb->con_handle);
		soisconnected(pcb->so);
	} else {
		/*
		 * We have failed to open connection, so disconnect the socket
		 */

		pcb->so->so_error = ECONNREFUSED;
		pcb->state = NG_BTSOCKET_ISO_CLOSED;
		soisdisconnected(pcb->so);
	}

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	return (error);
} /* ng_btsocket_iso_process_lp_con_cfm */

/*
 * Process LP_ConnectInd indicator. Find socket that listens on address.
 * Find exact or closest match.
 */

static int
ng_btsocket_iso_process_lp_con_ind(struct ng_mesg *msg,
		ng_btsocket_iso_rtentry_p rt)
{
	ng_hci_lp_con_ind_ep	*ep = NULL;
	ng_btsocket_iso_pcb_t	*pcb = NULL, *pcb1 = NULL;
	int			 error = 0;
	u_int16_t		 status = 0;

	if (msg->header.arglen != sizeof(*ep))
		return (EMSGSIZE);

	ep = (ng_hci_lp_con_ind_ep *)(msg->data);

	NG_BTSOCKET_ISO_INFO(
"%s: Got LP_ConnectInd indicator, src bdaddr=%x:%x:%x:%x:%x:%x, " \
"dst bdaddr=%x:%x:%x:%x:%x:%x\n",
		__func__,
		rt->src.b[5], rt->src.b[4], rt->src.b[3],
		rt->src.b[2], rt->src.b[1], rt->src.b[0],
		ep->bdaddr.b[5], ep->bdaddr.b[4], ep->bdaddr.b[3],
		ep->bdaddr.b[2], ep->bdaddr.b[1], ep->bdaddr.b[0]);

	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	pcb = ng_btsocket_iso_pcb_by_addr(&rt->src);
	if (pcb != NULL) {
		struct socket *so1;

		/* pcb is locked */

		CURVNET_SET(pcb->so->so_vnet);
		so1 = sonewconn(pcb->so, 0);
		CURVNET_RESTORE();

		if (so1 == NULL) {
			status = NG_HCI_ERROR_REJECTED_LIMITED_RESOURCES;
			goto respond;
		}

		/*
		 * If we got here then we have created new socket.
		 * Complete connection.  If we were listening on
		 * specific address then copy source address from
		 * listening socket, otherwise copy source address
		 * from hook's routing information.
		 */

		pcb1 = so2iso_pcb(so1);
		KASSERT((pcb1 != NULL),
("%s: pcb1 == NULL\n", __func__));

		mtx_lock(&pcb1->pcb_mtx);

		if (bcmp(&pcb->src, NG_HCI_BDADDR_ANY, sizeof(pcb->src)) != 0)
			bcopy(&pcb->src, &pcb1->src, sizeof(pcb1->src));
		else
			bcopy(&rt->src, &pcb1->src, sizeof(pcb1->src));

		pcb1->flags &= ~NG_BTSOCKET_ISO_CLIENT;

		bcopy(&ep->bdaddr, &pcb1->dst, sizeof(pcb1->dst));
		pcb1->con_handle = ep->con_handle;
		pcb1->rt = rt;
	} else
		/* Nobody listens on requested BDADDR */
		status = NG_HCI_ERROR_UNSPECIFIED;

respond:
	error = ng_btsocket_iso_send_lp_con_rsp(rt, &ep->bdaddr,
	    ep->con_handle, status);
	if (pcb1 != NULL) {
		if (error != 0) {
			pcb1->so->so_error = error;
			pcb1->state = NG_BTSOCKET_ISO_CLOSED;
			soisdisconnected(pcb1->so);
		} else {
			pcb1->state = NG_BTSOCKET_ISO_CONNECTING;
			soisconnecting(pcb1->so);

			ng_btsocket_iso_timeout(pcb1);
		}

		mtx_unlock(&pcb1->pcb_mtx);
	}

	if (pcb != NULL)
		mtx_unlock(&pcb->pcb_mtx);

	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	return (error);
} /* ng_btsocket_iso_process_lp_con_ind */

/*
 * Process LP_DisconnectInd indicator
 */

static int
ng_btsocket_iso_process_lp_discon_ind(struct ng_mesg *msg,
		ng_btsocket_iso_rtentry_p rt)
{
	ng_hci_lp_discon_ind_ep	*ep = NULL;
	ng_btsocket_iso_pcb_t	*pcb = NULL;

	/* Check message */
	if (msg->header.arglen != sizeof(*ep))
		return (EMSGSIZE);

	ep = (ng_hci_lp_discon_ind_ep *)(msg->data);

	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	/* Look for the socket with given connection handle */
	pcb = ng_btsocket_iso_pcb_by_handle(&rt->src, ep->con_handle);
	if (pcb == NULL) {
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
		return (0);
	}

	/*
	 * Disconnect the socket. If there was any pending request we can
	 * not do anything here anyway.
	 */

	/* pcb is locked */

	NG_BTSOCKET_ISO_INFO(
"%s: Got LP_DisconnectInd indicator, src bdaddr=%x:%x:%x:%x:%x:%x, " \
"dst bdaddr=%x:%x:%x:%x:%x:%x, handle=%d, state=%d\n",
		__func__,
		pcb->src.b[5], pcb->src.b[4], pcb->src.b[3],
		pcb->src.b[2], pcb->src.b[1], pcb->src.b[0],
		pcb->dst.b[5], pcb->dst.b[4], pcb->dst.b[3],
		pcb->dst.b[2], pcb->dst.b[1], pcb->dst.b[0],
		pcb->con_handle, pcb->state);

	if (pcb->flags & NG_BTSOCKET_ISO_TIMO)
		ng_btsocket_iso_untimeout(pcb);
	if (pcb->tx_unsynced > 0) {
		if (rt->pending >= pcb->tx_unsynced)
			rt->pending -= pcb->tx_unsynced;
		else
			rt->pending = 0;
		pcb->tx_unsynced = 0;
	}

	SDT_PROBE1(bluetooth, socket, disconnect, iso,
	    pcb->con_handle);

	pcb->state = NG_BTSOCKET_ISO_CLOSED;
	soisdisconnected(pcb->so);

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);

	return (0);
} /* ng_btsocket_iso_process_lp_discon_ind */

/*
 * Send LP_ConnectReq request (using CIS link type)
 */

static int
ng_btsocket_iso_send_lp_con_req(ng_btsocket_iso_pcb_p pcb)
{
	struct ng_mesg		*msg = NULL;
	ng_hci_lp_con_req_ep	*ep = NULL;
	int			 error = 0;

	mtx_assert(&pcb->pcb_mtx, MA_OWNED);

	if (pcb->rt == NULL ||
	    pcb->rt->hook == NULL || NG_HOOK_NOT_VALID(pcb->rt->hook))
		return (ENETDOWN);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_REQ,
		sizeof(*ep), M_NOWAIT);
	if (msg == NULL)
		return (ENOMEM);

	ep = (ng_hci_lp_con_req_ep *)(msg->data);
	ep->link_type = NG_HCI_LINK_ISO_CIS;
	bcopy(&pcb->dst, &ep->bdaddr, sizeof(ep->bdaddr));
	ep->con_handle = pcb->con_handle;

	NG_SEND_MSG_HOOK(error, ng_btsocket_iso_node, msg, pcb->rt->hook, 0);

	return (error);
} /* ng_btsocket_iso_send_lp_con_req */

/*
 * Send LP_ConnectRsp response
 */

static int
ng_btsocket_iso_send_lp_con_rsp(ng_btsocket_iso_rtentry_p rt, bdaddr_p dst,
		u_int16_t con_handle, int status)
{
	struct ng_mesg		*msg = NULL;
	ng_hci_lp_con_rsp_ep	*ep = NULL;
	int			 error = 0;

	if (rt == NULL || rt->hook == NULL || NG_HOOK_NOT_VALID(rt->hook))
		return (ENETDOWN);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_CON_RSP,
		sizeof(*ep), M_NOWAIT);
	if (msg == NULL)
		return (ENOMEM);

	ep = (ng_hci_lp_con_rsp_ep *)(msg->data);
	ep->status = status;
	ep->link_type = NG_HCI_LINK_ISO_CIS;
	bcopy(dst, &ep->bdaddr, sizeof(ep->bdaddr));
	ep->con_handle = con_handle;

	NG_SEND_MSG_HOOK(error, ng_btsocket_iso_node, msg, rt->hook, 0);

	return (error);
} /* ng_btsocket_iso_send_lp_con_rsp */

/*
 * Send LP_DisconReq request
 */

static int
ng_btsocket_iso_send_lp_discon_req(ng_btsocket_iso_pcb_p pcb)
{
	struct ng_mesg		*msg = NULL;
	ng_hci_lp_discon_req_ep	*ep = NULL;
	int			 error = 0;

	mtx_assert(&pcb->pcb_mtx, MA_OWNED);

	if (pcb->rt == NULL ||
	    pcb->rt->hook == NULL || NG_HOOK_NOT_VALID(pcb->rt->hook))
		return (ENETDOWN);

	NG_MKMESSAGE(msg, NGM_HCI_COOKIE, NGM_HCI_LP_DISCON_REQ,
		sizeof(*ep), M_NOWAIT);
	if (msg == NULL)
		return (ENOMEM);

	ep = (ng_hci_lp_discon_req_ep *)(msg->data);
	ep->con_handle = pcb->con_handle;
	ep->reason = NG_HCI_ERROR_USER_ENDED_CON;

	NG_SEND_MSG_HOOK(error, ng_btsocket_iso_node, msg, pcb->rt->hook, 0);

	return (error);
} /* ng_btsocket_iso_send_lp_discon_req */

static int
ng_btsocket_iso_frag_ring_put(ng_btsocket_iso_pcb_p pcb, u_int8_t nfrags,
    int final)
{
	u_int8_t next;

	KASSERT(nfrags > 0,
	    ("%s: zero-fragment ISO completion entry", __func__));

	next = (pcb->frag_ring_head + 1) % NG_BTSOCKET_ISO_FRAG_RING_SZ;
	if (next == pcb->frag_ring_tail)
		return (ENOBUFS);

	pcb->frag_ring[pcb->frag_ring_head] = nfrags;
	pcb->frag_ring_is_final[pcb->frag_ring_head] = final != 0;
	pcb->frag_ring_head = next;

	return (0);
}

/*****************************************************************************
 *****************************************************************************
 **                              Socket interface
 *****************************************************************************
 *****************************************************************************/

/*
 * ISO sockets data input routine
 */

static void
ng_btsocket_iso_data_input(struct mbuf *m, hook_p hook)
{
	ng_hci_isodata_pkt_t		*hdr = NULL;
	ng_btsocket_iso_pcb_t		*pcb = NULL;
	ng_btsocket_iso_rtentry_t	*rt = NULL;
	u_int16_t			 con_handle;
	u_int16_t			 iso_sdu_len = 0;
	u_int8_t			 pb_flag = 0x02; /* default: complete SDU */
	int				 has_sdu_len = 0;

	if (hook == NULL) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Invalid source hook for ISO data packet\n", __func__);
		goto drop;
	}

	rt = (ng_btsocket_iso_rtentry_t *) NG_HOOK_PRIVATE(hook);
	if (rt == NULL) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not find out source bdaddr for ISO data packet\n", __func__);
		goto drop;
	}

	/* Make sure we can access header */
	if (m->m_pkthdr.len < sizeof(*hdr)) {
		NG_BTSOCKET_ISO_ERR(
"%s: ISO data packet too small, len=%d\n", __func__, m->m_pkthdr.len);
		goto drop;
	}

	if (m->m_len < sizeof(*hdr)) {
		m = m_pullup(m, sizeof(*hdr));
		if (m == NULL)
			goto drop;
	}

	/* Strip ISO packet header and verify packet length */
	hdr = mtod(m, ng_hci_isodata_pkt_t *);
	con_handle = NG_HCI_ISO_CON_HANDLE(le16toh(hdr->con_handle));

	SDT_PROBE2(bluetooth, socket, recv, iso,
	    con_handle, m->m_pkthdr.len);
	{
		u_int16_t	data_total_len, ch_flags;
		u_int8_t	ts_flag;

		data_total_len = NG_HCI_ISO_DATA_LENGTH(le16toh(hdr->length));
		ch_flags = le16toh(hdr->con_handle);
		pb_flag = NG_HCI_ISO_PB_FLAG(ch_flags);
		ts_flag = NG_HCI_ISO_TS_FLAG(ch_flags);

		m_adj(m, sizeof(*hdr));

		if (data_total_len != m->m_pkthdr.len) {
			NG_BTSOCKET_ISO_ERR(
"%s: Bad ISO data packet length, len=%d, length=%d\n",
				__func__, m->m_pkthdr.len, data_total_len);
			goto abort_rx_drop;
		}

		/*
		 * Per Core Spec Vol 4 Part E §5.4.5 the 4-byte Time_Stamp is
		 * part of the ISO Data Load, which is present only on the first
		 * fragment (PB_Flag 0b00) or a complete SDU (0b10) -- the same
		 * packets that carry the data-load sub-header.  A TS_Flag set on
		 * a continuation (0b01) or last (0b11) fragment is malformed and
		 * MUST NOT consume 4 bytes of payload (finding #5).
		 */
		if (ts_flag && (pb_flag == 0x00 || pb_flag == 0x02)) {
			if (m->m_pkthdr.len < 4) {
				NG_BTSOCKET_ISO_ERR(
"%s: ISO packet too short for timestamp, len=%d\n",
					__func__, m->m_pkthdr.len);
				goto abort_rx_drop;
			}
			m_adj(m, 4);
		}

		/*
		 * Strip the ISO Data Load sub-header when present per
		 * Core Spec Vol 4 Part E §5.4.5: Packet_Sequence_Number,
		 * ISO_SDU_Length, and Packet_Status_Flag are present when
		 * PB_Flag = 0b00 (first fragment) or 0b10 (complete SDU).
		 */
		if (pb_flag == 0x00 || pb_flag == 0x02) {
			ng_hci_iso_data_load_hdr_t *dlhdr;

			if (m->m_pkthdr.len <
			    (int)sizeof(ng_hci_iso_data_load_hdr_t)) {
				NG_BTSOCKET_ISO_ERR(
"%s: ISO data packet too short for data load header, len=%d\n",
					__func__, m->m_pkthdr.len);
				goto abort_rx_drop;
			}

			if (m->m_len <
			    (int)sizeof(ng_hci_iso_data_load_hdr_t)) {
				m = m_pullup(m,
				    sizeof(ng_hci_iso_data_load_hdr_t));
				if (m == NULL)
					goto abort_rx_drop;
			}

			dlhdr = mtod(m, ng_hci_iso_data_load_hdr_t *);
			iso_sdu_len = NG_HCI_ISO_SDU_LENGTH(
			    le16toh(dlhdr->sdu_len_flags));
			has_sdu_len = 1;

			/* Check Packet_Status_Flag for data validity */
			if (NG_HCI_ISO_PKT_STATUS(
			    le16toh(dlhdr->sdu_len_flags)) == 0x02) {
				/*
				 * Lost data invalidates any in-progress ISOAL
				 * SDU on this handle.  Drop this packet and
				 * clear stale fragments so a later continuation
				 * or last fragment cannot complete old bytes.
				 */
				NG_BTSOCKET_ISO_INFO(
"%s: ISO data lost (PSF=0b10), handle=%d\n",
					__func__, con_handle);
				goto abort_rx_drop;
			}

			m_adj(m, sizeof(ng_hci_iso_data_load_hdr_t));
		}

		if (pb_flag == 0x02 && has_sdu_len &&
		    m->m_pkthdr.len != iso_sdu_len) {
			NG_BTSOCKET_ISO_ERR(
"%s: complete ISO SDU length mismatch, got=%d, expected=%d, handle=%d\n",
			    __func__, m->m_pkthdr.len, iso_sdu_len,
			    con_handle);
			goto abort_rx_drop;
		}

		if (pb_flag == 0x00 && has_sdu_len &&
		    (iso_sdu_len > NG_BTSOCKET_ISO_MAX_REASM ||
		     m->m_pkthdr.len > iso_sdu_len)) {
			NG_BTSOCKET_ISO_ERR(
"%s: first ISO fragment exceeds declared SDU length, got=%d, expected=%d, handle=%d\n",
			    __func__, m->m_pkthdr.len, iso_sdu_len,
			    con_handle);
			goto abort_rx_drop;
		}
	}

	/*
	 * Now process packet
	 */

	NG_BTSOCKET_ISO_INFO(
"%s: Received ISO data packet: src bdaddr=%x:%x:%x:%x:%x:%x, handle=%d, " \
"length=%d\n",	__func__,
		rt->src.b[5], rt->src.b[4], rt->src.b[3],
		rt->src.b[2], rt->src.b[1], rt->src.b[0],
		con_handle, m->m_pkthdr.len);

	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	/* Find socket */
	pcb = ng_btsocket_iso_pcb_by_handle(&rt->src, con_handle);
	if (pcb == NULL) {
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		goto drop;
	}

	/* pcb is locked */

	if (pcb->state != NG_BTSOCKET_ISO_OPEN) {
		NG_BTSOCKET_ISO_ERR(
"%s: No connected socket found, src bdaddr=%x:%x:%x:%x:%x:%x, state=%d\n",
			__func__,
			rt->src.b[5], rt->src.b[4], rt->src.b[3],
			rt->src.b[2], rt->src.b[1], rt->src.b[0],
			pcb->state);

		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		goto drop;
	}

	/*
	 * ISOAL reassembly (Core Spec Vol 6 Part G §2).
	 * PB_Flag=0b10: complete SDU — deliver immediately.
	 * PB_Flag=0b00: first fragment — start reassembly.
	 * PB_Flag=0b01: continuation — append to reassembly buffer.
	 * PB_Flag=0b11: last fragment — append and deliver.
	 */
	if (pb_flag == 0x02) {
		/* Complete SDU — deliver directly */
		if (pcb->rx_frag != NULL) {
			NG_BTSOCKET_ISO_WARN(
"%s: discarding stale reassembly buffer, handle=%d\n",
			    __func__, con_handle);
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_frag = NULL;
			pcb->rx_sdu_len = 0;
		}
	} else if (pb_flag == 0x00) {
		/* First fragment — start reassembly */
		if (pcb->rx_frag != NULL) {
			NG_BTSOCKET_ISO_WARN(
"%s: new first fragment replaces incomplete reassembly, handle=%d\n",
			    __func__, con_handle);
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_frag = NULL;
			pcb->rx_sdu_len = 0;
		}
		/*
		 * Bound the reassembly at the very first fragment (finding #4).
		 * A single first fragment can be as large as Data_Total_Length
		 * (14-bit, ~16 KB); an SDU cannot exceed NG_BTSOCKET_ISO_MAX_REASM
		 * (0x0FFF, Core Spec Vol 4 Part E §5.4.5), so reject it now
		 * rather than growing an oversized buffer.
		 */
		if (m->m_pkthdr.len > NG_BTSOCKET_ISO_MAX_REASM) {
			NG_BTSOCKET_ISO_ERR(
"%s: first fragment exceeds max SDU, len=%d, handle=%d\n",
			    __func__, m->m_pkthdr.len, con_handle);
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		pcb->rx_sdu_len = iso_sdu_len;
		pcb->rx_frag = m;
		m = NULL;
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		goto done;
	} else if (pb_flag == 0x01) {
		/* Continuation fragment — append */
		if (pcb->rx_frag == NULL) {
			NG_BTSOCKET_ISO_ERR(
"%s: continuation fragment without first, handle=%d\n",
			    __func__, con_handle);
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		if (pcb->rx_sdu_len == 0 ||
		    pcb->rx_frag->m_pkthdr.len + m->m_pkthdr.len >
		    pcb->rx_sdu_len) {
			NG_BTSOCKET_ISO_ERR(
"%s: continuation exceeds declared ISO SDU length, got=%d, add=%d, expected=%d, handle=%d\n",
			    __func__, pcb->rx_frag->m_pkthdr.len,
			    m->m_pkthdr.len, pcb->rx_sdu_len, con_handle);
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_sdu_len = 0;
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		{
			int frag_len = m->m_pkthdr.len;
			m_cat(pcb->rx_frag, m);
			m = NULL; /* consumed by m_cat */
			pcb->rx_frag->m_pkthdr.len += frag_len;
		}
		if (pcb->rx_frag->m_pkthdr.len > NG_BTSOCKET_ISO_MAX_REASM) {
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_frag = NULL;
			pcb->rx_sdu_len = 0;
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto done;
		}
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		goto done;
	} else if (pb_flag == 0x03) {
		/* Last fragment — complete reassembly */
		if (pcb->rx_frag == NULL) {
			NG_BTSOCKET_ISO_ERR(
"%s: last fragment without first, handle=%d\n",
			    __func__, con_handle);
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		if (pcb->rx_sdu_len == 0 ||
		    pcb->rx_frag->m_pkthdr.len + m->m_pkthdr.len >
		    pcb->rx_sdu_len) {
			NG_BTSOCKET_ISO_ERR(
"%s: last fragment exceeds declared ISO SDU length, got=%d, add=%d, expected=%d, handle=%d\n",
			    __func__, pcb->rx_frag->m_pkthdr.len,
			    m->m_pkthdr.len, pcb->rx_sdu_len, con_handle);
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_sdu_len = 0;
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		m_cat(pcb->rx_frag, m);
		m = pcb->rx_frag;
		pcb->rx_frag = NULL;
		/* Update pkthdr.len after reassembly */
		{
			struct mbuf *t;
			m->m_pkthdr.len = 0;
			for (t = m; t != NULL; t = t->m_next)
				m->m_pkthdr.len += t->m_len;
		}
		if (m->m_pkthdr.len != pcb->rx_sdu_len) {
			NG_BTSOCKET_ISO_ERR(
"%s: reassembled ISO SDU length mismatch, got=%d, expected=%d, handle=%d\n",
			    __func__, m->m_pkthdr.len, pcb->rx_sdu_len,
			    con_handle);
			pcb->rx_sdu_len = 0;
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
		pcb->rx_sdu_len = 0;
		/*
		 * Enforce the SDU bound on the completed record too (finding
		 * #4): a first(0b00)+last(0b11) pair with no continuation must
		 * not deliver more than NG_BTSOCKET_ISO_MAX_REASM bytes
		 * (Core Spec Vol 4 Part E §5.4.5).
		 */
		if (m->m_pkthdr.len > NG_BTSOCKET_ISO_MAX_REASM) {
			NG_BTSOCKET_ISO_ERR(
"%s: reassembled SDU exceeds max, len=%d, handle=%d\n",
			    __func__, m->m_pkthdr.len, con_handle);
			mtx_unlock(&pcb->pcb_mtx);
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			goto drop;
		}
	}

	/* Check if we have enough space in socket receive queue */
	if (m != NULL && m->m_pkthdr.len > sbspace(&pcb->so->so_rcv)) {
		NG_BTSOCKET_ISO_ERR(
"%s: Not enough space in socket receive queue. Dropping ISO data packet, " \
"src bdaddr=%x:%x:%x:%x:%x:%x, len=%d, space=%ld\n",
			__func__,
			rt->src.b[5], rt->src.b[4], rt->src.b[3],
			rt->src.b[2], rt->src.b[1], rt->src.b[0],
			m->m_pkthdr.len,
			sbspace(&pcb->so->so_rcv));

		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		goto drop;
	}

	/* Append packet to the socket receive queue and wakeup */
	if (m != NULL) {
		sbappendrecord(&pcb->so->so_rcv, m);
		m = NULL;
	}

	sorwakeup(pcb->so);

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);
drop:
done:
	NG_FREE_M(m); /* checks for m != NULL */
	return;

abort_rx_drop:
	ng_btsocket_iso_abort_rx_reassembly(&rt->src, con_handle);
	goto drop;
} /* ng_btsocket_iso_data_input */

/*
 * ISO sockets default message input routine
 */

static void
ng_btsocket_iso_default_msg_input(struct ng_mesg *msg, hook_p hook)
{
	ng_btsocket_iso_rtentry_t	*rt = NULL;

	if (hook == NULL || NG_HOOK_NOT_VALID(hook))
		return;

	rt = (ng_btsocket_iso_rtentry_t *) NG_HOOK_PRIVATE(hook);

	switch (msg->header.cmd) {
	case NGM_HCI_NODE_UP: {
		ng_hci_node_up_ep	*ep = NULL;

		if (msg->header.arglen != sizeof(*ep))
			break;

		ep = (ng_hci_node_up_ep *)(msg->data);
		if (bcmp(&ep->bdaddr, NG_HCI_BDADDR_ANY, sizeof(bdaddr_t)) == 0)
			break;

		if (rt == NULL) {
			rt = malloc(sizeof(*rt),
				M_NETGRAPH_BTSOCKET_ISO, M_NOWAIT|M_ZERO);
			if (rt == NULL)
				break;

			NG_HOOK_SET_PRIVATE(hook, rt);

			mtx_lock(&ng_btsocket_iso_rt_mtx);

			LIST_INSERT_HEAD(&ng_btsocket_iso_rt, rt, next);
		} else
			mtx_lock(&ng_btsocket_iso_rt_mtx);

		bcopy(&ep->bdaddr, &rt->src, sizeof(rt->src));
		/*
		 * Clamp the controller-advertised ISO Data_Total_Length to a
		 * coherent, safe range (finding #1/#3/#7).  0 means "unknown"
		 * -> conservative default.  The upper bound is the most an HCI
		 * ISO fragment can carry in a single mbuf cluster, which is
		 * what stops send2() segmentation from being driven past the
		 * fragment buffer.  Written under rt_mtx so send2()'s read is
		 * never torn against this update.
		 */
		if (ep->pkt_size <= sizeof(ng_hci_iso_data_load_hdr_t))
			rt->pkt_size = NG_BTSOCKET_ISO_DEFAULT_PKT_SIZE;
		else if (ep->pkt_size > NG_BTSOCKET_ISO_MAX_PKT_SIZE)
			rt->pkt_size = NG_BTSOCKET_ISO_MAX_PKT_SIZE;
		else
			rt->pkt_size = ep->pkt_size;
		rt->num_pkts = ep->num_pkts;
		rt->hook = hook;

		mtx_unlock(&ng_btsocket_iso_rt_mtx);

		NG_BTSOCKET_ISO_INFO(
"%s: Updating hook \"%s\", src bdaddr=%x:%x:%x:%x:%x:%x, pkt_size=%d, " \
"num_pkts=%d\n",	__func__, NG_HOOK_NAME(hook),
			rt->src.b[5], rt->src.b[4], rt->src.b[3],
			rt->src.b[2], rt->src.b[1], rt->src.b[0],
			rt->pkt_size, rt->num_pkts);
		} break;

	case NGM_HCI_SYNC_CON_QUEUE: {
		ng_hci_sync_con_queue_ep	*ep = NULL;
		ng_btsocket_iso_pcb_t		*pcb = NULL;

		if (rt == NULL || msg->header.arglen != sizeof(*ep))
			break;

		ep = (ng_hci_sync_con_queue_ep *)(msg->data);

		/*
		 * pending/num_pkts/pkt_size are shared route state read and
		 * written from multiple contexts; serialize every access under
		 * rt_mtx (finding #3).  Lock order is rt_mtx -> sockets_mtx ->
		 * pcb_mtx, matching connect()'s rt_mtx -> pcb_mtx.  send2()
		 * below therefore always runs with rt_mtx held.
		 */
		mtx_lock(&ng_btsocket_iso_rt_mtx);

		mtx_lock(&ng_btsocket_iso_sockets_mtx);

		/* Find socket */
		pcb = ng_btsocket_iso_pcb_by_handle(&rt->src, ep->con_handle);
		if (pcb == NULL) {
			mtx_unlock(&ng_btsocket_iso_sockets_mtx);
			mtx_unlock(&ng_btsocket_iso_rt_mtx);
			break;
		}

		/* pcb is locked */
		{
			u_int16_t done;

			done = min((u_int16_t)ep->completed, pcb->tx_unsynced);
			pcb->tx_unsynced -= done;
			if (rt->pending >= done)
				rt->pending -= done;
			else
				rt->pending = 0;
			if (done != ep->completed)
				NG_BTSOCKET_ISO_WARN(
"%s: completion exceeds socket credit accounting, handle=%d, " \
"completed=%d, credited=%d\n", __func__, ep->con_handle,
				    ep->completed, done);
			ep->completed = done;
		}

		/* Check state */
		if (pcb->state == NG_BTSOCKET_ISO_OPEN) {
			/* Remove timeout */
			ng_btsocket_iso_untimeout(pcb);

			/*
			 * Retire completed HCI ISO packets from the send queue.
			 * A large SDU can be emitted over multiple controller
			 * credit windows, so frag-ring entries describe batches;
			 * only an entry marked final completes and drops the
			 * socket-buffer record.
			 */
			while (ep->completed > 0) {
				if (pcb->frag_ring_rem == 0 &&
				    pcb->frag_ring_tail !=
				    pcb->frag_ring_head) {
					pcb->frag_ring_rem = pcb->frag_ring[
					    pcb->frag_ring_tail];
					pcb->frag_ring_final = pcb->frag_ring_is_final[
					    pcb->frag_ring_tail];
					pcb->frag_ring_tail =
					    (pcb->frag_ring_tail + 1) %
					    NG_BTSOCKET_ISO_FRAG_RING_SZ;
				}
				if (pcb->frag_ring_rem > 0) {
					pcb->frag_ring_rem--;
					if (pcb->frag_ring_rem == 0 &&
					    pcb->frag_ring_final) {
						sbdroprecord(&pcb->so->so_snd);
						pcb->tx_sdu_offset = 0;
						pcb->tx_sdu_seq_num = 0;
						pcb->frag_ring_final = 0;
					}
				} else {
					NG_BTSOCKET_ISO_WARN(
"%s: completion without ISO fragment-ring entry, handle=%d\n",
					    __func__, ep->con_handle);
				}
				ep->completed--;
			}

			/* Send more if we have any */
			if (sbavail(&pcb->so->so_snd) > 0) {
				if (pcb->frag_ring_rem == 0 &&
				    pcb->frag_ring_tail == pcb->frag_ring_head) {
					if (ng_btsocket_iso_send2(pcb) == 0)
						ng_btsocket_iso_timeout(pcb);
				} else {
					/* Partial completions still need a progress watchdog. */
					ng_btsocket_iso_timeout(pcb);
				}
			}

			/* Wake up writers */
			sowwakeup(pcb->so);
		}

		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
	} break;

	default:
		NG_BTSOCKET_ISO_WARN(
"%s: Unknown message, cmd=%d\n", __func__, msg->header.cmd);
		break;
	}

	NG_FREE_MSG(msg); /* Checks for msg != NULL */
} /* ng_btsocket_iso_default_msg_input */

/*
 * ISO sockets LP message input routine
 */

static void
ng_btsocket_iso_lp_msg_input(struct ng_mesg *msg, hook_p hook)
{
	ng_btsocket_iso_rtentry_p	 rt = NULL;

	if (hook == NULL) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Invalid source hook for LP message\n", __func__);
		goto drop;
	}

	rt = (ng_btsocket_iso_rtentry_p) NG_HOOK_PRIVATE(hook);
	if (rt == NULL) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not find out source bdaddr for LP message\n", __func__);
		goto drop;
	}

	switch (msg->header.cmd) {
	case NGM_HCI_LP_CON_CFM: /* Connection Confirmation Event */
		ng_btsocket_iso_process_lp_con_cfm(msg, rt);
		break;

	case NGM_HCI_LP_CON_IND: /* Connection Indication Event */
		ng_btsocket_iso_process_lp_con_ind(msg, rt);
		break;

	case NGM_HCI_LP_DISCON_IND: /* Disconnection Indication Event */
		ng_btsocket_iso_process_lp_discon_ind(msg, rt);
		break;

	default:
		NG_BTSOCKET_ISO_WARN(
"%s: Unknown LP message, cmd=%d\n", __func__, msg->header.cmd);
		break;
	}
drop:
	NG_FREE_MSG(msg);
} /* ng_btsocket_iso_lp_msg_input */

/*
 * ISO sockets input routine
 */

static void
ng_btsocket_iso_input(void *context, int pending)
{
	item_p	item = NULL;
	hook_p	hook = NULL;

	for (;;) {
		mtx_lock(&ng_btsocket_iso_queue_mtx);
		NG_BT_ITEMQ_DEQUEUE(&ng_btsocket_iso_queue, item);
		mtx_unlock(&ng_btsocket_iso_queue_mtx);

		if (item == NULL)
			break;

		NGI_GET_HOOK(item, hook);
		if (hook != NULL && NG_HOOK_NOT_VALID(hook))
			goto drop;

		switch(item->el_flags & NGQF_TYPE) {
		case NGQF_DATA: {
			struct mbuf     *m = NULL;

			NGI_GET_M(item, m);
			ng_btsocket_iso_data_input(m, hook);
			} break;

		case NGQF_MESG: {
			struct ng_mesg  *msg = NULL;

			NGI_GET_MSG(item, msg);

			switch (msg->header.cmd) {
			case NGM_HCI_LP_CON_CFM:
			case NGM_HCI_LP_CON_IND:
			case NGM_HCI_LP_DISCON_IND:
				ng_btsocket_iso_lp_msg_input(msg, hook);
				break;

			default:
				ng_btsocket_iso_default_msg_input(msg, hook);
				break;
			}
			} break;

		default:
			KASSERT(0,
("%s: invalid item type=%ld\n", __func__, (item->el_flags & NGQF_TYPE)));
			break;
		}
drop:
		if (hook != NULL)
			NG_HOOK_UNREF(hook);

		NG_FREE_ITEM(item);
	}
} /* ng_btsocket_iso_input */

/*
 * Route cleanup task. Gets scheduled when hook is disconnected. Here we
 * will find all sockets that use "invalid" hook and disconnect them.
 */

static void
ng_btsocket_iso_rtclean(void *context, int pending)
{
	ng_btsocket_iso_pcb_p		pcb = NULL, pcb_next = NULL;
	ng_btsocket_iso_rtentry_p	rt = NULL;

	/*
	 * First disconnect all sockets that use "invalid" hook
	 */

	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	for(pcb = LIST_FIRST(&ng_btsocket_iso_sockets); pcb != NULL; ) {
		mtx_lock(&pcb->pcb_mtx);
		pcb_next = LIST_NEXT(pcb, next);

		if (pcb->rt != NULL &&
		    pcb->rt->hook != NULL && NG_HOOK_NOT_VALID(pcb->rt->hook)) {
			if (pcb->flags & NG_BTSOCKET_ISO_TIMO)
				ng_btsocket_iso_untimeout(pcb);

			pcb->rt = NULL;
			pcb->so->so_error = ENETDOWN;
			pcb->state = NG_BTSOCKET_ISO_CLOSED;
			soisdisconnected(pcb->so);
		}

		mtx_unlock(&pcb->pcb_mtx);
		pcb = pcb_next;
	}

	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	/*
	 * Now cleanup routing table
	 */

	mtx_lock(&ng_btsocket_iso_rt_mtx);

	for (rt = LIST_FIRST(&ng_btsocket_iso_rt); rt != NULL; ) {
		ng_btsocket_iso_rtentry_p	rt_next = LIST_NEXT(rt, next);

		if (rt->hook != NULL && NG_HOOK_NOT_VALID(rt->hook)) {
			LIST_REMOVE(rt, next);

			NG_HOOK_SET_PRIVATE(rt->hook, NULL);
			NG_HOOK_UNREF(rt->hook); /* Remove extra reference */

			bzero(rt, sizeof(*rt));
			free(rt, M_NETGRAPH_BTSOCKET_ISO);
		}

		rt = rt_next;
	}

	mtx_unlock(&ng_btsocket_iso_rt_mtx);
} /* ng_btsocket_iso_rtclean */

/*
 * Initialize everything
 */

static void
ng_btsocket_iso_init(void *arg __unused)
{
	int	error = 0;

	ng_btsocket_iso_node = NULL;
	ng_btsocket_iso_debug_level = NG_BTSOCKET_WARN_LEVEL;

	/* Register Netgraph node type */
	error = ng_newtype(&typestruct);
	if (error != 0) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not register Netgraph node type, error=%d\n", __func__, error);

		return;
	}

	/* Create Netgraph node */
	error = ng_make_node_common(&typestruct, &ng_btsocket_iso_node);
	if (error != 0) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not create Netgraph node, error=%d\n", __func__, error);

		ng_btsocket_iso_node = NULL;

		return;
	}

	error = ng_name_node(ng_btsocket_iso_node, NG_BTSOCKET_ISO_NODE_TYPE);
	if (error != 0) {
		NG_BTSOCKET_ISO_ALERT(
"%s: Could not name Netgraph node, error=%d\n", __func__, error);

		NG_NODE_UNREF(ng_btsocket_iso_node);
		ng_btsocket_iso_node = NULL;

		return;
	}

	/* Create input queue */
	NG_BT_ITEMQ_INIT(&ng_btsocket_iso_queue, 300);
	mtx_init(&ng_btsocket_iso_queue_mtx,
		"btsocks_iso_queue_mtx", NULL, MTX_DEF);
	TASK_INIT(&ng_btsocket_iso_queue_task, 0,
		ng_btsocket_iso_input, NULL);

	/* Create list of sockets */
	LIST_INIT(&ng_btsocket_iso_sockets);
	mtx_init(&ng_btsocket_iso_sockets_mtx,
		"btsocks_iso_sockets_mtx", NULL, MTX_DEF);

	/* Routing table */
	LIST_INIT(&ng_btsocket_iso_rt);
	mtx_init(&ng_btsocket_iso_rt_mtx,
		"btsocks_iso_rt_mtx", NULL, MTX_DEF);
	TASK_INIT(&ng_btsocket_iso_rt_task, 0,
		ng_btsocket_iso_rtclean, NULL);
} /* ng_btsocket_iso_init */
SYSINIT(ng_btsocket_iso_init, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD,
    ng_btsocket_iso_init, NULL);

/*
 * Abort connection on socket
 */

void
ng_btsocket_iso_abort(struct socket *so)
{
	so->so_error = ECONNABORTED;

	(void) ng_btsocket_iso_disconnect(so);
} /* ng_btsocket_iso_abort */

void
ng_btsocket_iso_close(struct socket *so)
{
	(void) ng_btsocket_iso_disconnect(so);
} /* ng_btsocket_iso_close */

/*
 * Create and attach new socket
 */

int
ng_btsocket_iso_attach(struct socket *so, int proto, struct thread *td)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);
	int			error;

	/* Check socket and protocol */
	if (ng_btsocket_iso_node == NULL)
		return (EPROTONOSUPPORT);
	if (so->so_type != SOCK_SEQPACKET)
		return (ESOCKTNOSUPPORT);

	if (pcb != NULL)
		return (EISCONN);

	/* Reserve send and receive space if it is not reserved yet */
	if ((so->so_snd.sb_hiwat == 0) || (so->so_rcv.sb_hiwat == 0)) {
		error = soreserve(so, NG_BTSOCKET_ISO_SENDSPACE,
					NG_BTSOCKET_ISO_RECVSPACE);
		if (error != 0)
			return (error);
	}

	/* Allocate the PCB */
	pcb = malloc(sizeof(*pcb),
		M_NETGRAPH_BTSOCKET_ISO, M_NOWAIT | M_ZERO);
	if (pcb == NULL)
		return (ENOMEM);

	/* Link the PCB and the socket */
	so->so_pcb = (caddr_t) pcb;
	pcb->so = so;
	pcb->state = NG_BTSOCKET_ISO_CLOSED;

	/*
	 * Mark PCB mutex as DUPOK to prevent "duplicated lock of
	 * the same type" message.
	 */

	mtx_init(&pcb->pcb_mtx, "btsocks_iso_pcb_mtx", NULL,
		MTX_DEF|MTX_DUPOK);

	callout_init_mtx(&pcb->timo, &pcb->pcb_mtx, 0);

	/*
	 * Add the PCB to the list
	 *
	 * If td != NULL we were called from socket(), otherwise from
	 * sonewconn() which already holds the sockets mutex.
	 */

	if (td != NULL)
		mtx_lock(&ng_btsocket_iso_sockets_mtx);
	else
		mtx_assert(&ng_btsocket_iso_sockets_mtx, MA_OWNED);

	LIST_INSERT_HEAD(&ng_btsocket_iso_sockets, pcb, next);

	if (td != NULL)
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);

        return (0);
} /* ng_btsocket_iso_attach */

/*
 * Bind socket
 */

int
ng_btsocket_iso_bind(struct socket *so, struct sockaddr *nam,
		struct thread *td)
{
	ng_btsocket_iso_pcb_t	*pcb = NULL;
	struct sockaddr_iso	*sa = (struct sockaddr_iso *) nam;

	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	/* Verify address */
	if (sa == NULL)
		return (EINVAL);
	if (sa->iso_family != AF_BLUETOOTH)
		return (EAFNOSUPPORT);
	if (sa->iso_len != sizeof(*sa))
		return (EINVAL);

	mtx_lock(&ng_btsocket_iso_sockets_mtx);

	/*
	 * Check if other socket has this address already (look for exact
	 * match in bdaddr) and assign socket address if it's available.
	 */

	if (bcmp(&sa->iso_bdaddr, NG_HCI_BDADDR_ANY,
	    sizeof(sa->iso_bdaddr)) != 0) {
		LIST_FOREACH(pcb, &ng_btsocket_iso_sockets, next) {
			mtx_lock(&pcb->pcb_mtx);

			if (bcmp(&pcb->src, &sa->iso_bdaddr,
			    sizeof(bdaddr_t)) == 0) {
				mtx_unlock(&pcb->pcb_mtx);
				mtx_unlock(&ng_btsocket_iso_sockets_mtx);

				return (EADDRINUSE);
			}

			mtx_unlock(&pcb->pcb_mtx);
		}
	}

	pcb = so2iso_pcb(so);
	if (pcb == NULL) {
		mtx_unlock(&ng_btsocket_iso_sockets_mtx);
		return (EINVAL);
	}

	mtx_lock(&pcb->pcb_mtx);
	bcopy(&sa->iso_bdaddr, &pcb->src, sizeof(pcb->src));
	mtx_unlock(&pcb->pcb_mtx);

	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	return (0);
} /* ng_btsocket_iso_bind */

/*
 * Connect socket
 */

int
ng_btsocket_iso_connect(struct socket *so, struct sockaddr *nam,
		struct thread *td)
{
	ng_btsocket_iso_pcb_t		*pcb = so2iso_pcb(so);
	struct sockaddr_iso		*sa = (struct sockaddr_iso *) nam;
	ng_btsocket_iso_rtentry_t	*rt = NULL;
	int				 have_src, error = 0;

	/* Check socket */
	if (pcb == NULL)
		return (EINVAL);
	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	/* Verify address */
	if (sa == NULL)
		return (EINVAL);
	if (sa->iso_family != AF_BLUETOOTH)
		return (EAFNOSUPPORT);
	if (sa->iso_len != sizeof(*sa))
		return (EINVAL);
	if (bcmp(&sa->iso_bdaddr, NG_HCI_BDADDR_ANY, sizeof(bdaddr_t)) == 0)
		return (EDESTADDRREQ);

	/* ISO/CIS is LE-only: validate address type */
	if (sa->iso_bdaddr_type != 0x00 && sa->iso_bdaddr_type != 0x01)
		return (EINVAL);

	/* Connection handle must be in valid range (12-bit, 0x000-0xEFF) */
	if (sa->iso_cis_handle > 0x0EFF)
		return (EINVAL);

	/*
	 * Routing. Socket should be bound to some source address. The source
	 * address can be ANY. Destination address must be set and it must not
	 * be ANY. If source address is ANY then find first rtentry that has
	 * src != dst.
	 */

	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&pcb->pcb_mtx);

	if (pcb->state == NG_BTSOCKET_ISO_CONNECTING) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);

		return (EINPROGRESS);
	}

	/*
	 * Only a CLOSED socket may (re)connect.  An OPEN or DISCONNECTING
	 * socket already owns a live CIS and route; overwriting them here
	 * would leak the connection and corrupt routing state.  Match the
	 * SCO/L2CAP sibling and report EISCONN (finding #2).
	 */
	if (pcb->state != NG_BTSOCKET_ISO_CLOSED) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);

		return (EISCONN);
	}

	if (bcmp(&sa->iso_bdaddr, &pcb->src, sizeof(pcb->src)) == 0) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);

		return (EINVAL);
	}

	/* Store destination address and address type */
	bcopy(&sa->iso_bdaddr, &pcb->dst, sizeof(pcb->dst));
	pcb->dst_type = sa->iso_bdaddr_type;
	pcb->con_handle = sa->iso_cis_handle;

	pcb->rt = NULL;
	have_src = bcmp(&pcb->src, NG_HCI_BDADDR_ANY, sizeof(pcb->src));

	LIST_FOREACH(rt, &ng_btsocket_iso_rt, next) {
		if (rt->hook == NULL || NG_HOOK_NOT_VALID(rt->hook))
			continue;

		/* Match src and dst */
		if (have_src) {
			if (bcmp(&pcb->src, &rt->src, sizeof(rt->src)) == 0)
				break;
		} else {
			if (bcmp(&pcb->dst, &rt->src, sizeof(rt->src)) != 0)
				break;
		}
	}

	if (rt != NULL) {
		pcb->rt = rt;

		if (!have_src)
			bcopy(&rt->src, &pcb->src, sizeof(pcb->src));
	} else
		error = EHOSTUNREACH;

	/*
	 * Send LP_Connect request
	 */

	if (error == 0) {
		error = ng_btsocket_iso_send_lp_con_req(pcb);
		if (error == 0) {
			pcb->flags |= NG_BTSOCKET_ISO_CLIENT;
			pcb->state = NG_BTSOCKET_ISO_CONNECTING;
			soisconnecting(pcb->so);

			ng_btsocket_iso_timeout(pcb);
		}
	}

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);

	return (error);
} /* ng_btsocket_iso_connect */

/*
 * Process ioctl's calls on socket
 *
 * This socket is the ISO *data plane*: it exchanges HCI ISO data packets
 * with ng_hci over the netgraph hook once a CIS/BIS handle is OPEN and the
 * Controller has a data path for it.  The ISO *control plane* -- CIG
 * provisioning (LE Set CIG Parameters, Core Spec Vol 4 Part E §7.8.97) and
 * ISO data-path setup (LE Setup ISO Data Path, §7.8.109) -- is driven by
 * the host daemon over its raw HCI command socket, not through this socket:
 * a single HCI-command writer avoids command/handle races, and the socket
 * layer deliberately does not originate arbitrary HCI commands.  There are
 * therefore no ISO control ioctls; unknown requests return EINVAL.
 */

int
ng_btsocket_iso_control(struct socket *so, u_long cmd, void *data,
		struct ifnet *ifp, struct thread *td)
{
	return (EINVAL);
} /* ng_btsocket_iso_control */

/*
 * Process getsockopt/setsockopt system calls
 */

int
ng_btsocket_iso_ctloutput(struct socket *so, struct sockopt *sopt)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);
	int			error, tmp;

	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);
	if (pcb == NULL)
		return (EINVAL);

	if (sopt->sopt_level != SOL_ISO)
		return (0);

	mtx_lock(&pcb->pcb_mtx);

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		if (pcb->state != NG_BTSOCKET_ISO_OPEN) {
			error = ENOTCONN;
			break;
		}

		if (pcb->rt == NULL) {
			mtx_unlock(&pcb->pcb_mtx);
			return (ENETDOWN);
		}

		switch (sopt->sopt_name) {
		case SO_ISO_MTU:
			tmp = pcb->rt->pkt_size;
			error = sooptcopyout(sopt, &tmp, sizeof(tmp));
			break;

		case SO_ISO_CONNINFO:
			tmp = pcb->con_handle;
			error = sooptcopyout(sopt, &tmp, sizeof(tmp));
			break;

		default:
			error = EINVAL;
			break;
		}
		break;

	case SOPT_SET:
		error = ENOPROTOOPT;
		break;

	default:
		error = EINVAL;
		break;
	}

	mtx_unlock(&pcb->pcb_mtx);

	return (error);
} /* ng_btsocket_iso_ctloutput */

/*
 * Detach and destroy socket
 */

void
ng_btsocket_iso_detach(struct socket *so)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);

	KASSERT(pcb != NULL, ("ng_btsocket_iso_detach: pcb == NULL"));

	if (ng_btsocket_iso_node == NULL)
		return;

	mtx_lock(&ng_btsocket_iso_sockets_mtx);
	mtx_lock(&pcb->pcb_mtx);

	if (pcb->flags & NG_BTSOCKET_ISO_TIMO)
		ng_btsocket_iso_untimeout(pcb);

	if (pcb->state == NG_BTSOCKET_ISO_OPEN)
		ng_btsocket_iso_send_lp_discon_req(pcb);

	pcb->state = NG_BTSOCKET_ISO_CLOSED;

	/* Free ISOAL reassembly buffer if any */
	if (pcb->rx_frag != NULL) {
		NG_FREE_M(pcb->rx_frag);
		pcb->rx_frag = NULL;
	}
	pcb->rx_sdu_len = 0;

	LIST_REMOVE(pcb, next);

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);

	callout_drain(&pcb->timo);

	soisdisconnected(so);
	so->so_pcb = NULL;

	mtx_destroy(&pcb->pcb_mtx);
	bzero(pcb, sizeof(*pcb));
	free(pcb, M_NETGRAPH_BTSOCKET_ISO);
} /* ng_btsocket_iso_detach */

/*
 * Disconnect socket
 */

int
ng_btsocket_iso_disconnect(struct socket *so)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);

	if (pcb == NULL)
		return (EINVAL);
	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	mtx_lock(&pcb->pcb_mtx);

	if (pcb->state == NG_BTSOCKET_ISO_DISCONNECTING) {
		mtx_unlock(&pcb->pcb_mtx);

		return (EINPROGRESS);
	}

	if (pcb->flags & NG_BTSOCKET_ISO_TIMO)
		ng_btsocket_iso_untimeout(pcb);

	if (pcb->state == NG_BTSOCKET_ISO_OPEN) {
		ng_btsocket_iso_send_lp_discon_req(pcb);

		pcb->state = NG_BTSOCKET_ISO_DISCONNECTING;
		soisdisconnecting(so);

		ng_btsocket_iso_timeout(pcb);
	} else {
		pcb->state = NG_BTSOCKET_ISO_CLOSED;
		soisdisconnected(so);
	}

	mtx_unlock(&pcb->pcb_mtx);

	return (0);
} /* ng_btsocket_iso_disconnect */

/*
 * Listen on socket
 */

int
ng_btsocket_iso_listen(struct socket *so, int backlog, struct thread *td)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);
	int			error;

	if (pcb == NULL)
		return (EINVAL);
	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	SOCK_LOCK(so);
	mtx_lock(&pcb->pcb_mtx);

	error = solisten_proto_check(so);
	if (error != 0)
		goto out;
	solisten_proto(so, backlog);
out:
	mtx_unlock(&pcb->pcb_mtx);
	SOCK_UNLOCK(so);

	return (error);
} /* ng_btsocket_iso_listen */

/*
 * Return peer address for getpeername(2).
 */
int
ng_btsocket_iso_peeraddr(struct socket *so, struct sockaddr *sa)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);
	struct sockaddr_iso *iso = (struct sockaddr_iso *)sa;

	if (pcb == NULL)
		return (EINVAL);
	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	*iso = (struct sockaddr_iso ){
		.iso_len = sizeof(struct sockaddr_iso),
		.iso_family = AF_BLUETOOTH,
	};
	mtx_lock(&pcb->pcb_mtx);
	bcopy(&pcb->dst, &iso->iso_bdaddr, sizeof(iso->iso_bdaddr));
	iso->iso_bdaddr_type = pcb->dst_type;
	iso->iso_cis_handle = pcb->con_handle;
	mtx_unlock(&pcb->pcb_mtx);

	return (0);
}

/*
 * Send data to socket
 */

int
ng_btsocket_iso_send(struct socket *so, int flags, struct mbuf *m,
		struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	ng_btsocket_iso_pcb_t	*pcb = so2iso_pcb(so);
	int			 error = 0;

	if (ng_btsocket_iso_node == NULL) {
		error = ENETDOWN;
		goto drop;
	}

	/* Check socket and input */
	if (pcb == NULL || m == NULL || control != NULL) {
		error = EINVAL;
		goto drop;
	}

	/*
	 * send2() touches the shared route counters, so it must run under
	 * rt_mtx as well as pcb_mtx.  Acquire rt_mtx first to keep the global
	 * rt_mtx -> pcb_mtx lock order used by connect() and the input task
	 * (finding #3); every exit below releases both.
	 */
	mtx_lock(&ng_btsocket_iso_rt_mtx);
	mtx_lock(&pcb->pcb_mtx);

	/* Make sure socket is connected */
	if (pcb->state != NG_BTSOCKET_ISO_OPEN) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
		error = ENOTCONN;
		goto drop;
	}

	/* Check route */
	if (pcb->rt == NULL ||
	    pcb->rt->hook == NULL || NG_HOOK_NOT_VALID(pcb->rt->hook)) {
		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
		error = ENETDOWN;
		goto drop;
	}

	/*
	 * Validate HCI ISO framing limits (Core Spec Vol 4 Part E §5.4.5).
	 * ISO_SDU_Length is 12 bits: max 0x0FFF.
	 * SDUs larger than one controller packet are segmented by ISOAL
	 * in send2().
	 * Data_Total_Length is 14 bits: max 0x3FFF; it covers the 4-byte
	 * ISO Data Load sub-header plus the SDU payload.
	 */
	if (m->m_pkthdr.len > 0x0FFF) {
		NG_BTSOCKET_ISO_ERR(
"%s: SDU too large for 12-bit ISO_SDU_Length, len=%d\n",
			__func__, m->m_pkthdr.len);

		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
		error = EMSGSIZE;
		goto drop;
	}
	if (m->m_pkthdr.len + (int)sizeof(ng_hci_iso_data_load_hdr_t) > 0x3FFF) {
		NG_BTSOCKET_ISO_ERR(
"%s: ISO Data Load too large for 14-bit Data_Total_Length, len=%d\n",
			__func__, m->m_pkthdr.len);

		mtx_unlock(&pcb->pcb_mtx);
		mtx_unlock(&ng_btsocket_iso_rt_mtx);
		error = EMSGSIZE;
		goto drop;
	}

	/*
	 * First put packet on socket send queue. Then check if we have
	 * pending timeout. If we do not have timeout then we must send
	 * packet and schedule timeout. Otherwise do nothing and wait for
	 * NGM_HCI_SYNC_CON_QUEUE message.
	 */

	SDT_PROBE2(bluetooth, socket, send, iso,
	    pcb->con_handle, m->m_pkthdr.len);

	sbappendrecord(&pcb->so->so_snd, m);
	m = NULL;

	if (!(pcb->flags & NG_BTSOCKET_ISO_TIMO)) {
		error = ng_btsocket_iso_send2(pcb);
		if (error == 0)
			ng_btsocket_iso_timeout(pcb);
		else
			sbdroprecord(&pcb->so->so_snd); /* XXX */
	}

	mtx_unlock(&pcb->pcb_mtx);
	mtx_unlock(&ng_btsocket_iso_rt_mtx);
drop:
	NG_FREE_M(m); /* checks for != NULL */
	NG_FREE_M(control);

	return (error);
} /* ng_btsocket_iso_send */

/*
 * Send first packet in the socket queue to the ISO layer via HCI.
 * Implements ISOAL Unframed mode (Core Spec Vol 6 Part G §2):
 * - SDUs that fit in a single HCI ISO packet are sent as PB_Flag=0b10
 *   (complete SDU) with the ISO Data Load sub-header.
 * - SDUs larger than the controller's max packet size are segmented
 *   into first (PB_Flag=0b00), continuation (0b01), and last (0b11)
 *   fragments.  Only the first fragment carries the sub-header.
 *
 * Core Spec Vol 4 Part E Section 5.4.5.
 */

static int
ng_btsocket_iso_send2(ng_btsocket_iso_pcb_p pcb)
{
	struct  mbuf			*m = NULL, *frag = NULL;
	ng_hci_isodata_pkt_t		*hdr = NULL;
	ng_hci_iso_data_load_hdr_t	*dlhdr = NULL;
	u_int16_t			 sdu_len, max_pdu, frag_len, offset;
	u_int16_t			 pkt_size;
	u_int16_t			 saved_seq_num;
	int				 error = 0;
	int				 total_hdr;
	u_int8_t			 pb_flag;

	/*
	 * pcb_mtx guards the socket/queue state; rt_mtx guards the shared
	 * route counters (pending/num_pkts/pkt_size).  Both are held by every
	 * caller (ng_btsocket_iso_send, NGM_HCI_SYNC_CON_QUEUE) so that these
	 * fields cannot be torn or raced here (finding #3).
	 */
	mtx_assert(&pcb->pcb_mtx, MA_OWNED);
	mtx_assert(&ng_btsocket_iso_rt_mtx, MA_OWNED);

	total_hdr = sizeof(*hdr) + sizeof(*dlhdr);

	/*
	 * Snapshot the negotiated ISO Data_Total_Length once (it is already
	 * clamped to NG_BTSOCKET_ISO_MAX_PKT_SIZE on NGM_HCI_NODE_UP) and
	 * derive one coherent max_pdu for every fragment class (finding #7).
	 * max_pdu is the largest SDU payload that fits a first/complete HCI
	 * ISO packet: pkt_size is Data_Total_Length capacity, which for
	 * first/complete includes the 4-byte data-load sub-header, so we
	 * subtract it; a continuation/last fragment carries no sub-header and
	 * so may use the full pkt_size (Core Spec Vol 4 Part E §5.4.5).
	 */
	pkt_size = pcb->rt->pkt_size;
	if (pkt_size <= (u_int16_t)sizeof(*dlhdr))
		pkt_size = NG_BTSOCKET_ISO_DEFAULT_PKT_SIZE; /* fallback */
	max_pdu = pkt_size - sizeof(*dlhdr);

	while (pcb->rt->pending < pcb->rt->num_pkts &&
	       sbavail(&pcb->so->so_snd) > 0) {
		offset = 0;

		/* Get a copy of the first packet on send queue */
		m = m_dup(pcb->so->so_snd.sb_mb, M_NOWAIT);
		if (m == NULL) {
			error = ENOBUFS;
			break;
		}

		sdu_len = m->m_pkthdr.len;

		if (sdu_len <= max_pdu) {
			/*
			 * Complete SDU fits in one packet — no segmentation.
			 * PB_Flag = 0b10 (complete SDU).
			 */
			M_PREPEND(m, total_hdr, M_NOWAIT);
			if (m != NULL && m->m_len < total_hdr)
				m = m_pullup(m, total_hdr);
			if (m == NULL) {
				error = ENOBUFS;
				break;
			}

			hdr = mtod(m, ng_hci_isodata_pkt_t *);
			hdr->type = NG_HCI_ISO_DATA_PKT;
			hdr->con_handle = htole16(
			    (pcb->con_handle & 0x0fff) | (0x02 << 12));
			hdr->length = htole16(sizeof(*dlhdr) + sdu_len);

			dlhdr = (ng_hci_iso_data_load_hdr_t *)(hdr + 1);
			dlhdr->seq_num = htole16(pcb->iso_seq_num);
			dlhdr->sdu_len_flags = htole16(sdu_len & 0x0fff);

			/* Check frag ring space before sending */
			if ((pcb->frag_ring_head + 1) %
			    NG_BTSOCKET_ISO_FRAG_RING_SZ ==
			    pcb->frag_ring_tail) {
				NG_FREE_M(m);
				break; /* sbdroprecord skipped: offset == 0 */
			}

			NG_SEND_DATA_ONLY(error, pcb->rt->hook, m);
			if (error != 0)
				break;
			pcb->iso_seq_num++;
			pcb->rt->pending++;
			pcb->tx_unsynced++;
			error = ng_btsocket_iso_frag_ring_put(pcb, 1, 1);
			if (error != 0)
				break;
			offset = sdu_len; /* mark SDU as fully sent */
			break;
		} else {
			/*
			 * ISOAL segmentation: SDU is too large for one
			 * HCI ISO packet.  Split into fragments.
			 * First fragment carries the sub-header; subsequent
			 * fragments have only the HCI ISO header.
			 */
			offset = pcb->tx_sdu_offset;
			if (offset == 0) {
				saved_seq_num = pcb->iso_seq_num;
				pcb->tx_sdu_seq_num = saved_seq_num;
			} else
				saved_seq_num = pcb->tx_sdu_seq_num;
			{
			int nfrags = 0;
			while (offset < sdu_len &&
			    pcb->rt->pending < pcb->rt->num_pkts &&
			    (pcb->frag_ring_head + 1) %
			    NG_BTSOCKET_ISO_FRAG_RING_SZ !=
			    pcb->frag_ring_tail) {
				int hdr_size;
				int remaining = sdu_len - offset;

				if (offset == 0) {
					/* First fragment */
					hdr_size = total_hdr;
					frag_len = min(remaining, max_pdu);
				} else {
					/* Continuation or last — no sub-header,
					 * full pkt_size available for payload */
					hdr_size = sizeof(*hdr);
					frag_len = min(remaining, pkt_size);
				}

				/*
				 * CRITICAL (finding #1): bound every fragment so
				 * that hdr_size + frag_len fits in a single mbuf
				 * cluster.  Without this, an oversized negotiated
				 * pkt_size (or SDU) makes m_copydata() below write
				 * far past the MHLEN/MCLBYTES destination buffer.
				 * The remainder is picked up on the next loop
				 * iteration, so the full SDU still reassembles per
				 * §5.4.5.  (pkt_size is already clamped on NODE_UP;
				 * this is the defence-in-depth invariant.)
				 */
				if (frag_len > (u_int16_t)(MCLBYTES - hdr_size))
					frag_len = (u_int16_t)(MCLBYTES - hdr_size);

				/*
				 * PB_Flag is decided AFTER the cap: a capped
				 * fragment may no longer reach the end of the SDU,
				 * so what looked like a "last" fragment becomes a
				 * "continuation".  The first fragment is always
				 * 0b00 here (a fitting SDU took the complete-SDU
				 * path above).
				 */
				if (offset == 0)
					pb_flag = 0x00;		/* first */
				else if (offset + frag_len >= sdu_len)
					pb_flag = 0x03;		/* last */
				else
					pb_flag = 0x01;		/* continuation */

				KASSERT(hdr_size + frag_len <= (int)MCLBYTES,
				    ("%s: ISO fragment hdr=%d + payload=%d "
				     "exceeds cluster %d", __func__, hdr_size,
				     (int)frag_len, (int)MCLBYTES));

				MGETHDR(frag, M_NOWAIT, MT_DATA);
				if (frag == NULL) {
					error = ENOBUFS;
					break;
				}
				if (hdr_size + frag_len > MHLEN &&
				    !(MCLGET(frag, M_NOWAIT))) {
					NG_FREE_M(frag);
					error = ENOBUFS;
					break;
				}

				/* Copy fragment header */
				hdr = mtod(frag, ng_hci_isodata_pkt_t *);
				hdr->type = NG_HCI_ISO_DATA_PKT;
				hdr->con_handle = htole16(
				    (pcb->con_handle & 0x0fff) |
				    ((u_int16_t)pb_flag << 12));

				if (offset == 0) {
					/* First: include sub-header */
					hdr->length = htole16(
					    sizeof(*dlhdr) + frag_len);
					dlhdr = (ng_hci_iso_data_load_hdr_t *)
					    (hdr + 1);
					dlhdr->seq_num =
					    htole16(saved_seq_num);
					dlhdr->sdu_len_flags =
					    htole16(sdu_len & 0x0fff);
					m_copydata(m, offset, frag_len,
					    (caddr_t)(dlhdr + 1));
				} else {
					/* Continuation/last: no sub-header */
					hdr->length = htole16(frag_len);
					m_copydata(m, offset, frag_len,
					    (caddr_t)(hdr + 1));
				}

				frag->m_pkthdr.len = frag->m_len =
				    hdr_size + frag_len;

				NG_SEND_DATA_ONLY(error, pcb->rt->hook, frag);
				if (error != 0)
					break;
				pcb->rt->pending++;
				pcb->tx_unsynced++;
				offset += frag_len;
				nfrags++;
				/* The ring count is one octet; finish this batch at 255. */
				if (nfrags == UINT8_MAX)
					break;
			}

			if (nfrags > 0) {
				error = ng_btsocket_iso_frag_ring_put(pcb,
				    (u_int8_t)nfrags, offset >= sdu_len);
				if (error != 0)
					break;
			}

			if (offset >= sdu_len) {
				pcb->iso_seq_num = saved_seq_num + 1;
			} else if (offset > pcb->tx_sdu_offset)
				pcb->tx_sdu_offset = offset;
			}

			NG_FREE_M(m);
			if (error != 0)
				break;
			if (offset < sdu_len)
				break;
			break;
		}

	}

	return ((pcb->rt->pending > 0) ? 0 : error);
} /* ng_btsocket_iso_send2 */

/*
 * Get socket address
 */

int
ng_btsocket_iso_sockaddr(struct socket *so, struct sockaddr *sa)
{
	ng_btsocket_iso_pcb_p	pcb = so2iso_pcb(so);
	struct sockaddr_iso *iso = (struct sockaddr_iso *)sa;

	if (pcb == NULL)
		return (EINVAL);
	if (ng_btsocket_iso_node == NULL)
		return (EINVAL);

	*iso = (struct sockaddr_iso ){
		.iso_len = sizeof(struct sockaddr_iso),
		.iso_family = AF_BLUETOOTH,
	};
	mtx_lock(&pcb->pcb_mtx);
	bcopy(&pcb->src, &iso->iso_bdaddr, sizeof(iso->iso_bdaddr));
	mtx_unlock(&pcb->pcb_mtx);

	return (0);
}

/*****************************************************************************
 *****************************************************************************
 **                              Misc. functions
 *****************************************************************************
 *****************************************************************************/

/*
 * Look for the socket that listens on given source address.
 * Exact match has priority over wildcard (BDADDR_ANY).
 * Caller must hold ng_btsocket_iso_sockets_mtx.
 * Returns with locked pcb.
 */

static ng_btsocket_iso_pcb_p
ng_btsocket_iso_pcb_by_addr(bdaddr_p bdaddr)
{
	ng_btsocket_iso_pcb_p	p = NULL, p1 = NULL;

	mtx_assert(&ng_btsocket_iso_sockets_mtx, MA_OWNED);

	LIST_FOREACH(p, &ng_btsocket_iso_sockets, next) {
		mtx_lock(&p->pcb_mtx);

		if (p->so == NULL || !SOLISTENING(p->so)) {
			mtx_unlock(&p->pcb_mtx);
			continue;
		}

		if (bcmp(&p->src, bdaddr, sizeof(p->src)) == 0)
			return (p); /* return with locked pcb */

		if (bcmp(&p->src, NG_HCI_BDADDR_ANY, sizeof(p->src)) == 0)
			p1 = p;

		mtx_unlock(&p->pcb_mtx);
	}

	if (p1 != NULL)
		mtx_lock(&p1->pcb_mtx);

	return (p1);
} /* ng_btsocket_iso_pcb_by_addr */

/*
 * Look for the socket that assigned to given source address and handle.
 * Caller must hold ng_btsocket_iso_sockets_mtx.
 * Returns with locked pcb.
 */

static ng_btsocket_iso_pcb_p
ng_btsocket_iso_pcb_by_handle(bdaddr_p src, int con_handle)
{
	ng_btsocket_iso_pcb_p	p = NULL;

	mtx_assert(&ng_btsocket_iso_sockets_mtx, MA_OWNED);

	LIST_FOREACH(p, &ng_btsocket_iso_sockets, next) {
		mtx_lock(&p->pcb_mtx);

		if (p->con_handle == con_handle &&
		    p->state != NG_BTSOCKET_ISO_CLOSED &&
		    bcmp(src, &p->src, sizeof(p->src)) == 0)
			return (p); /* return with locked pcb */

		mtx_unlock(&p->pcb_mtx);
	}

	return (NULL);
} /* ng_btsocket_iso_pcb_by_handle */

/*
 * Drop any partial ISOAL SDU for this source/handle after an HCI ISO packet
 * tells us the current SDU stream is not usable.
 */

static void
ng_btsocket_iso_abort_rx_reassembly(bdaddr_p src, int con_handle)
{
	ng_btsocket_iso_pcb_p	pcb = NULL;

	mtx_lock(&ng_btsocket_iso_sockets_mtx);
	pcb = ng_btsocket_iso_pcb_by_handle(src, con_handle);
	if (pcb != NULL) {
		if (pcb->rx_frag != NULL) {
			NG_FREE_M(pcb->rx_frag);
			pcb->rx_frag = NULL;
		}
		pcb->rx_sdu_len = 0;
		mtx_unlock(&pcb->pcb_mtx);
	}
	mtx_unlock(&ng_btsocket_iso_sockets_mtx);
} /* ng_btsocket_iso_abort_rx_reassembly */

/*
 * Set timeout on socket
 */

static void
ng_btsocket_iso_timeout(ng_btsocket_iso_pcb_p pcb)
{
	mtx_assert(&pcb->pcb_mtx, MA_OWNED);

	if (!(pcb->flags & NG_BTSOCKET_ISO_TIMO)) {
		pcb->flags |= NG_BTSOCKET_ISO_TIMO;
		callout_reset(&pcb->timo, bluetooth_iso_rtx_timeout(),
					ng_btsocket_iso_process_timeout, pcb);
	} else
		KASSERT(0,
("%s: Duplicated socket timeout?!\n", __func__));
} /* ng_btsocket_iso_timeout */

/*
 * Unset timeout on socket
 */

static void
ng_btsocket_iso_untimeout(ng_btsocket_iso_pcb_p pcb)
{
	mtx_assert(&pcb->pcb_mtx, MA_OWNED);

	if (pcb->flags & NG_BTSOCKET_ISO_TIMO) {
		callout_stop(&pcb->timo);
		pcb->flags &= ~NG_BTSOCKET_ISO_TIMO;
	} else
		KASSERT(0,
("%s: No socket timeout?!\n", __func__));
} /* ng_btsocket_iso_untimeout */

/*
 * Process timeout on socket
 */

static void
ng_btsocket_iso_process_timeout(void *xpcb)
{
	ng_btsocket_iso_pcb_p	 pcb = (ng_btsocket_iso_pcb_p) xpcb;

	mtx_assert(&pcb->pcb_mtx, MA_OWNED);

	pcb->so->so_error = ETIMEDOUT;

	switch (pcb->state) {
	case NG_BTSOCKET_ISO_CONNECTING:
		/* Connect timeout - close the socket */
		pcb->flags &= ~NG_BTSOCKET_ISO_TIMO;
		pcb->state = NG_BTSOCKET_ISO_CLOSED;
		soisdisconnected(pcb->so);
		break;

	case NG_BTSOCKET_ISO_OPEN:
		/*
		 * Lost completion accounting cannot be recovered safely: abort the
		 * CIS and reset every fragment cursor before dropping the in-flight
		 * record.  Leaving the PCB OPEN would let a late "final" completion
		 * drop the following application SDU.
		 */
		/* Respect the global rt_mtx -> pcb_mtx order without blocking. */
		if (pcb->rt != NULL && !mtx_trylock(&ng_btsocket_iso_rt_mtx)) {
			callout_reset(&pcb->timo, 1,
			    ng_btsocket_iso_process_timeout, pcb);
			return;
		}
		pcb->flags &= ~NG_BTSOCKET_ISO_TIMO;
		(void)ng_btsocket_iso_send_lp_discon_req(pcb);
		if (pcb->rt != NULL) {
			if (pcb->rt->pending >= pcb->tx_unsynced)
				pcb->rt->pending -= pcb->tx_unsynced;
			else
				pcb->rt->pending = 0;
			pcb->tx_unsynced = 0;
		}
		pcb->frag_ring_head = pcb->frag_ring_tail = 0;
		pcb->frag_ring_rem = 0;
		pcb->frag_ring_final = 0;
		pcb->tx_sdu_offset = 0;
		pcb->tx_sdu_seq_num = 0;
		sbdroprecord(&pcb->so->so_snd);
		pcb->state = NG_BTSOCKET_ISO_CLOSED;
		soisdisconnected(pcb->so);
		sowwakeup(pcb->so);
		if (pcb->rt != NULL)
			mtx_unlock(&ng_btsocket_iso_rt_mtx);
		break;

	case NG_BTSOCKET_ISO_DISCONNECTING:
		/* Disconnect timeout - disconnect the socket anyway */
		pcb->flags &= ~NG_BTSOCKET_ISO_TIMO;
		pcb->state = NG_BTSOCKET_ISO_CLOSED;
		soisdisconnected(pcb->so);
		break;

	default:
		NG_BTSOCKET_ISO_ERR(
"%s: Invalid socket state=%d\n", __func__, pcb->state);
		break;
	}

} /* ng_btsocket_iso_process_timeout */
