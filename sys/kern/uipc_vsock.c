/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * AF_VSOCK socket domain implementation.
 *
 * This file provides the socket-layer protocol for AF_VSOCK, analogous to
 * kern/uipc_usrreq.c for AF_UNIX.  It implements:
 *   - Socket domain registration (DOMAIN_SET)
 *   - All socket protocol operations (attach, bind, listen, connect, etc.)
 *   - PCB (protocol control block) management
 *   - Loopback transport (direct mbuf delivery via peer pointers)
 *   - RX packet handler (protocol state machine for incoming virtio packets)
 *   - Transport registration interface for remote transport drivers
 *
 * The remote transport (e.g. virtio) registers via vsock_transport_register()
 * and is called through the vtvsock_transport function pointer table.
 * When no remote transport is registered, only loopback is available.
 */

#include <sys/param.h>
#include <sys/callout.h>
#include <sys/counter.h>
#include <sys/domain.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/uio.h>
#include <sys/vsock.h>

#include <kern/uipc_vsock.h>

/* -----------------------------------------------------------------------
 * DTrace SDT probes
 * ---------------------------------------------------------------------- */

SDT_PROVIDER_DEFINE(vsock);
SDT_PROBE_DEFINE3(vsock, , , connect__established,
    "uint64_t",	/* remote CID */
    "uint32_t",	/* remote port */
    "int");	/* is_local */
SDT_PROBE_DEFINE2(vsock, , , connect__refused,
    "uint64_t",	/* remote CID */
    "uint32_t");	/* remote port */
SDT_PROBE_DEFINE2(vsock, , , send,
    "size_t",	/* bytes */
    "int");	/* SOCK_SEQPACKET */
SDT_PROBE_DEFINE2(vsock, , , receive,
    "size_t",	/* bytes */
    "int");	/* SOCK_SEQPACKET */
SDT_PROBE_DEFINE2(vsock, , , disconnect,
    "uint64_t",	/* remote CID */
    "uint32_t");	/* remote port */

/* -----------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */

MALLOC_DEFINE(M_VTVSOCK, "vtvsock", "virtio vsock");

/* Global mutex: protects bound/connected lists and PCB state fields.
 * Lock ordering: vtvsock_mtx -> SOCK_RECVBUF_LOCK / SOCK_SENDBUF_LOCK.
 * Never acquire vtvsock_mtx while holding a socket buffer lock.         */
struct mtx vtvsock_mtx;
MTX_SYSINIT(vtvsock, &vtvsock_mtx, "vtvsock", MTX_DEF);

static LIST_HEAD(, vtvsock_pcb) vtvsock_bound =
    LIST_HEAD_INITIALIZER(vtvsock_bound);
static LIST_HEAD(, vtvsock_pcb) vtvsock_conn =
    LIST_HEAD_INITIALIZER(vtvsock_conn);

uint64_t vtvsock_guest_cid = VSOCK_CID_LOCAL;

/* Remote transport, registered by virtio_vsock on attach. */
static const struct vtvsock_transport *vtvsock_remote_transport;
static uint64_t vtvsock_remote_features;

/* Tunable default buffer sizes for new sockets. */
static u_int vtvsock_buf_default = VTVSOCK_DEFAULT_BUF_ALLOC;
static u_int vtvsock_buf_min = VTVSOCK_DEFAULT_BUF_MIN;
static u_int vtvsock_buf_max = VTVSOCK_DEFAULT_BUF_MAX;
static u_int vtvsock_seqpacket_frag_max = VTVSOCK_DEFAULT_SEQPACKET_FRAG_MAX;

SYSCTL_U64(_kern, OID_AUTO, vsock_guest_cid, CTLFLAG_RD,
    &vtvsock_guest_cid, 0, "VSOCK guest CID");

counter_u64_t vtvsock_cnt_tx_packets;
counter_u64_t vtvsock_cnt_tx_bytes;
counter_u64_t vtvsock_cnt_rx_packets;
counter_u64_t vtvsock_cnt_rx_bytes;
counter_u64_t vtvsock_cnt_rx_drops;
counter_u64_t vtvsock_cnt_conns;

SYSCTL_NODE(_kern, OID_AUTO, vsock, CTLFLAG_RD, 0, "VSOCK");

/*
 * Parameterized sysctl handler for vtvsock_buf_{default,min,max}.
 * arg1 points to the variable; arg2 selects the validation rule:
 *   0 = buf_default: must be in [buf_min, buf_max]
 *   1 = buf_min:     must be <= buf_max and <= buf_default
 *   2 = buf_max:     must be >= buf_min and >= buf_default
 */
static int
sysctl_vsock_buf(SYSCTL_HANDLER_ARGS)
{
	u_int val = *(u_int *)arg1;
	int error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	switch (arg2) {
	case 0:	/* buf_default */
		if (val < vtvsock_buf_min || val > vtvsock_buf_max)
			return (EINVAL);
		break;
	case 1:	/* buf_min */
		if (val > vtvsock_buf_max || val > vtvsock_buf_default)
			return (EINVAL);
		break;
	case 2:	/* buf_max */
		if (val < vtvsock_buf_min || val < vtvsock_buf_default)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	*(u_int *)arg1 = val;
	return (0);
}
SYSCTL_PROC(_kern_vsock, OID_AUTO, buf_default,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &vtvsock_buf_default, 0, sysctl_vsock_buf, "IU",
    "Default buffer size for new VSOCK sockets (bytes)");
SYSCTL_PROC(_kern_vsock, OID_AUTO, buf_min,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &vtvsock_buf_min, 1, sysctl_vsock_buf, "IU",
    "Minimum buffer size for new VSOCK sockets (bytes)");
SYSCTL_PROC(_kern_vsock, OID_AUTO, buf_max,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    &vtvsock_buf_max, 2, sysctl_vsock_buf, "IU",
    "Maximum buffer size for new VSOCK sockets (bytes)");
SYSCTL_UINT(_kern_vsock, OID_AUTO, seqpacket_frag_max,
    CTLFLAG_RW | CTLFLAG_MPSAFE, &vtvsock_seqpacket_frag_max, 0,
    "Maximum SEQPACKET fragments before RST (0 = unlimited)");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, tx_packets, CTLFLAG_RD,
    &vtvsock_cnt_tx_packets, "Packets sent");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, tx_bytes, CTLFLAG_RD,
    &vtvsock_cnt_tx_bytes, "Payload bytes sent");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, rx_packets, CTLFLAG_RD,
    &vtvsock_cnt_rx_packets, "Packets received");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, rx_bytes, CTLFLAG_RD,
    &vtvsock_cnt_rx_bytes, "Payload bytes received");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, rx_drops, CTLFLAG_RD,
    &vtvsock_cnt_rx_drops, "Packets dropped");
SYSCTL_COUNTER_U64(_kern_vsock, OID_AUTO, connections, CTLFLAG_RD,
    &vtvsock_cnt_conns, "Connections established");

static int
sysctl_vsock_pcblist(SYSCTL_HANDLER_ARGS)
{
	struct vtvsock_pcb *pcb;
	struct xvsock_pcb xvp;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	mtx_lock(&vtvsock_mtx);

	/* Walk the bound list (listeners and bound-but-not-connected). */
	LIST_FOREACH(pcb, &vtvsock_bound, link) {
		if (pcb->on_connlist)
			continue; /* will be visited in the conn list */
		bzero(&xvp, sizeof(xvp));
		xvp.xvp_len = sizeof(xvp);
		xvp.xvp_state = pcb->state;
		xvp.xvp_local_cid = pcb->local.svm_cid;
		xvp.xvp_local_port = pcb->local.svm_port;
		if (pcb->so != NULL) {
			xvp.xvp_type = pcb->so->so_type;
			xvp.xvp_so_gencnt = pcb->so->so_gencnt;
		}
		xvp.xvp_buf_alloc = pcb->buf_alloc;
		error = SYSCTL_OUT(req, &xvp, sizeof(xvp));
		if (error != 0)
			break;
	}

	/* Walk the connected list. */
	if (error == 0) {
		LIST_FOREACH(pcb, &vtvsock_conn, connlink) {
			bzero(&xvp, sizeof(xvp));
			xvp.xvp_len = sizeof(xvp);
			xvp.xvp_state = pcb->state;
			xvp.xvp_local_cid = pcb->local.svm_cid;
			xvp.xvp_remote_cid = pcb->remote.svm_cid;
			xvp.xvp_local_port = pcb->local.svm_port;
			xvp.xvp_remote_port = pcb->remote.svm_port;
			if (pcb->so != NULL) {
				xvp.xvp_type = pcb->so->so_type;
				xvp.xvp_so_gencnt = pcb->so->so_gencnt;
			}
			xvp.xvp_buf_alloc = pcb->buf_alloc;
			xvp.xvp_rx_bytes = pcb->rx_bytes;
			xvp.xvp_tx_cnt = pcb->tx_cnt;
			xvp.xvp_peer_buf_alloc = pcb->peer_buf_alloc;
			xvp.xvp_peer_fwd_cnt = pcb->peer_fwd_cnt;
			error = SYSCTL_OUT(req, &xvp, sizeof(xvp));
			if (error != 0)
				break;
		}
	}

	mtx_unlock(&vtvsock_mtx);
	return (error);
}
SYSCTL_PROC(_kern_vsock, OID_AUTO, pcblist,
    CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_vsock_pcblist, "S,xvsock_pcb",
    "List of active VSOCK protocol control blocks");

/* -----------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */

static int	vsock_dom_probe(void);
static int	vsock_attach(struct socket *, int, struct thread *);
static void	vsock_detach(struct socket *);
static void	vsock_close(struct socket *);
static int	vsock_bind(struct socket *, struct sockaddr *, struct thread *);
static int	vsock_listen(struct socket *, int, struct thread *);
static int	vsock_accept(struct socket *, struct sockaddr *);
static int	vsock_connect(struct socket *, struct sockaddr *, struct thread *);
static int	vsock_peeraddr(struct socket *, struct sockaddr *);
static int	vsock_sockaddr(struct socket *, struct sockaddr *);
static int	vsock_ctloutput(struct socket *, struct sockopt *);
static int	vsock_setsbopt(struct socket *, struct sockopt *);
static int	vsock_soreceive(struct socket *, struct sockaddr **, struct uio *,
		    struct mbuf **, struct mbuf **, int *);
static int	vsock_send(struct socket *, int, struct mbuf *, struct sockaddr *,
		    struct mbuf *, struct thread *);
static int	vsock_disconnect(struct socket *);
static int	vsock_shutdown(struct socket *, enum shutdown_how);
static void	vsock_abort(struct socket *);

static struct vtvsock_pcb *vtvsock_pcb_alloc(struct socket *);
static void	vtvsock_pcb_free(struct vtvsock_pcb *);
static void	vtvsock_pcb_insert_bound_locked(struct vtvsock_pcb *);
static int	vtvsock_copy_to_sockaddr(const struct sockaddr_vm *,
		    struct sockaddr *);
static struct vtvsock_pcb *vtvsock_pcb_lookup_bound_locked(uint64_t, uint32_t);
static struct vtvsock_pcb *vtvsock_pcb_lookup_connected_locked(uint64_t,
		    uint32_t, uint64_t, uint32_t);

static bool	vtvsock_is_local(uint64_t dst_cid);

static int	vtvsock_local_send(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
static int	vtvsock_local_disconnect(struct vtvsock_pcb *);
static int	vtvsock_local_shutdown(struct vtvsock_pcb *, enum shutdown_how);

/* vtvsock_close_timeout is declared non-static in uipc_vsock.h */
static void	vtvsock_connect_timeout(void *);

static void	vsock_transport_reset_locked(void);

/* -----------------------------------------------------------------------
 * Loopback transport dispatch table
 * ---------------------------------------------------------------------- */

static const struct vtvsock_transport vtvsock_local_transport = {
	.send =		vtvsock_local_send,
	.disconnect =	vtvsock_local_disconnect,
	.shutdown =	vtvsock_local_shutdown,
};

/* -----------------------------------------------------------------------
 * Protocol switch and domain
 * ---------------------------------------------------------------------- */

static struct protosw vsock_stream_protosw = {
	.pr_type =	SOCK_STREAM,
	.pr_protocol =	0,
	.pr_flags =	PR_CONNREQUIRED,
	.pr_attach =	vsock_attach,
	.pr_bind =	vsock_bind,
	.pr_listen =	vsock_listen,
	.pr_accept =	vsock_accept,
	.pr_connect =	vsock_connect,
	.pr_peeraddr =	vsock_peeraddr,
	.pr_sockaddr =	vsock_sockaddr,
	.pr_ctloutput =	vsock_ctloutput,
	.pr_setsbopt =	vsock_setsbopt,
	.pr_soreceive =	vsock_soreceive,
	.pr_send =	vsock_send,
	.pr_sosend =	sosend_generic,
	.pr_disconnect =	vsock_disconnect,
	.pr_close =	vsock_close,
	.pr_detach =	vsock_detach,
	.pr_shutdown =	vsock_shutdown,
	.pr_abort =	vsock_abort,
};

static struct protosw vsock_seqpacket_protosw = {
	.pr_type =	SOCK_SEQPACKET,
	.pr_protocol =	0,
	.pr_flags =	PR_ATOMIC | PR_CONNREQUIRED,
	.pr_attach =	vsock_attach,
	.pr_bind =	vsock_bind,
	.pr_listen =	vsock_listen,
	.pr_accept =	vsock_accept,
	.pr_connect =	vsock_connect,
	.pr_peeraddr =	vsock_peeraddr,
	.pr_sockaddr =	vsock_sockaddr,
	.pr_ctloutput =	vsock_ctloutput,
	.pr_setsbopt =	vsock_setsbopt,
	.pr_soreceive =	vsock_soreceive,
	.pr_send =	vsock_send,
	.pr_sosend =	sosend_generic,
	.pr_disconnect =	vsock_disconnect,
	.pr_close =	vsock_close,
	.pr_detach =	vsock_detach,
	.pr_shutdown =	vsock_shutdown,
	.pr_abort =	vsock_abort,
};

static struct domain vsockdomain = {
	.dom_family =	AF_VSOCK,
	.dom_name =	"vsock",
	.dom_probe =	vsock_dom_probe,
	.dom_nprotosw =	2,
	.dom_protosw =	{ &vsock_stream_protosw, &vsock_seqpacket_protosw },
};

DOMAIN_SET(vsock);

/* -----------------------------------------------------------------------
 * Utility helpers
 * ---------------------------------------------------------------------- */

/*
 * Returns true if dst_cid should be handled as a local loopback.
 * CID 1 (VSOCK_CID_LOCAL) and the guest's own CID are local.
 */
static bool
vtvsock_is_local(uint64_t dst_cid)
{
	return (dst_cid == VSOCK_CID_LOCAL || dst_cid == vtvsock_guest_cid);
}

void
vtvsock_pcb_set_addr(struct sockaddr_vm *svm, uint64_t cid, uint32_t port)
{
	bzero(svm, sizeof(*svm));
	svm->svm_len = sizeof(struct sockaddr_vm);
	svm->svm_family = AF_VSOCK;
	svm->svm_reserved1 = 0;
	svm->svm_port = port;
	svm->svm_cid = cid;
}

static int
vtvsock_copy_to_sockaddr(const struct sockaddr_vm *svm, struct sockaddr *sa)
{
	struct sockaddr_vm *dst;

	if (sa == NULL)
		return (EINVAL);
	dst = (struct sockaddr_vm *)sa;
	*dst = *svm;
	dst->svm_len = sizeof(struct sockaddr_vm);
	dst->svm_family = AF_VSOCK;
	return (0);
}

/* -----------------------------------------------------------------------
 * PCB lifecycle
 * ---------------------------------------------------------------------- */

static struct vtvsock_pcb *
vtvsock_pcb_alloc(struct socket *so)
{
	struct vtvsock_pcb *pcb;

	pcb = malloc(sizeof(*pcb), M_VTVSOCK, M_WAITOK | M_ZERO);
	pcb->so = so;
	pcb->transport = &vtvsock_local_transport;
	vtvsock_pcb_set_addr(&pcb->local, UINT64_MAX, VSOCK_PORT_ANY);
	vtvsock_pcb_set_addr(&pcb->remote, UINT64_MAX, VSOCK_PORT_ANY);
	pcb->state = VTVSOCK_CLOSED;
	pcb->on_boundlist = false;
	pcb->on_connlist = false;
	pcb->buffer_min = vtvsock_buf_min;
	pcb->buffer_max = vtvsock_buf_max;
	pcb->connect_timeout = 0;  /* 0 means use default VTVSOCK_CONNECT_TIMEOUT */
	pcb->buf_alloc = vtvsock_buf_default;
	pcb->peer_shutdown = 0;
	pcb->seqpacket_partial = NULL;
	callout_init_mtx(&pcb->close_callout, &vtvsock_mtx, 0);
	callout_init_mtx(&pcb->connect_callout, &vtvsock_mtx, 0);
	return (pcb);
}

static void
vtvsock_pcb_free(struct vtvsock_pcb *pcb)
{
	/* Free any partially-assembled SEQPACKET mbuf chain. */
	if (pcb->seqpacket_partial != NULL) {
		m_freem(pcb->seqpacket_partial);
		pcb->seqpacket_partial = NULL;
	}
	/*
	 * NOTE: callout_drain() must NOT be called here; vsock_detach()
	 * already drained the callouts before calling vtvsock_pcb_free().
	 */
	free(pcb, M_VTVSOCK);
}

/* Must be called with vtvsock_mtx held. */
void
vtvsock_pcb_remove_lists_locked(struct vtvsock_pcb *pcb)
{
	if (pcb->on_boundlist) {
		LIST_REMOVE(pcb, link);
		pcb->on_boundlist = false;
	}
	if (pcb->on_connlist) {
		LIST_REMOVE(pcb, connlink);
		pcb->on_connlist = false;
	}
	if (pcb->peer != NULL) {
		pcb->peer->peer = NULL;
		pcb->peer = NULL;
	}
}

/* Must be called with vtvsock_mtx held. */
static void
vtvsock_pcb_insert_bound_locked(struct vtvsock_pcb *pcb)
{
	if (pcb->on_boundlist)
		return;
	LIST_INSERT_HEAD(&vtvsock_bound, pcb, link);
	pcb->on_boundlist = true;
}

/* Must be called with vtvsock_mtx held. */
void
vtvsock_pcb_insert_connected_locked(struct vtvsock_pcb *pcb)
{
	if (pcb->on_connlist)
		return;
	LIST_INSERT_HEAD(&vtvsock_conn, pcb, connlink);
	pcb->on_connlist = true;
}

/* -----------------------------------------------------------------------
 * PCB lookup (must be called with vtvsock_mtx held)
 * ---------------------------------------------------------------------- */

static struct vtvsock_pcb *
vtvsock_pcb_lookup_bound_locked(uint64_t cid, uint32_t port)
{
	struct vtvsock_pcb *pcb;

	LIST_FOREACH(pcb, &vtvsock_bound, link) {
		if (pcb->local.svm_cid == cid && pcb->local.svm_port == port)
			return (pcb);
	}
	return (NULL);
}

static struct vtvsock_pcb *
vtvsock_pcb_lookup_connected_locked(uint64_t src_cid, uint32_t src_port,
    uint64_t dst_cid, uint32_t dst_port)
{
	struct vtvsock_pcb *pcb;

	LIST_FOREACH(pcb, &vtvsock_conn, connlink) {
		if (pcb->local.svm_cid == dst_cid &&
		    pcb->local.svm_port == dst_port &&
		    pcb->remote.svm_cid == src_cid &&
		    pcb->remote.svm_port == src_port)
			return (pcb);
	}
	return (NULL);
}

/* -----------------------------------------------------------------------
 * Credit flow control helpers
 * ---------------------------------------------------------------------- */

/*
 * Available send credit: how many bytes the peer can still accept.
 * This is the peer's advertised capacity minus the bytes currently
 * in-flight (sent but not yet consumed by the peer).
 */
int32_t
vtvsock_credit_available(struct vtvsock_pcb *pcb)
{
	return ((int32_t)(pcb->peer_buf_alloc -
	    (pcb->tx_cnt - pcb->peer_fwd_cnt)));
}

/*
 * Consume up to 'wanted' bytes of send credit; return amount granted.
 * Must be called with vtvsock_mtx held (or otherwise serialized).
 */
uint32_t
vtvsock_get_credit(struct vtvsock_pcb *pcb, uint32_t wanted)
{
	int32_t avail;
	uint32_t got;

	avail = vtvsock_credit_available(pcb);
	if (avail <= 0)
		return (0);
	got = MIN(wanted, (uint32_t)avail);
	pcb->tx_cnt += got;
	return (got);
}

/* -----------------------------------------------------------------------
 * Close and connect timeout callbacks
 * ---------------------------------------------------------------------- */

/*
 * Fired if graceful close doesn't complete within VTVSOCK_CLOSE_TIMEOUT.
 * Sends RST and force-closes the socket.
 * Called with vtvsock_mtx held (callout_init_mtx).
 *
 * Check pcb->so != NULL before touching the socket (the callout
 * may fire after vsock_detach has set so->so_pcb = NULL, but the callout
 * was armed before drain; with callout_drain in detach this is a belt-and-
 * suspenders guard).
 */
void
vtvsock_close_timeout(void *arg)
{
	struct vtvsock_pcb *pcb = arg;
	struct socket *so;

	so = pcb->so;
	if (so == NULL)
		return;

	if (vtvsock_remote_transport != NULL &&
	    pcb->state == VTVSOCK_CLOSING) {
		(void)vtvsock_remote_transport->send_rst(
		    pcb->local.svm_cid, pcb->local.svm_port,
		    pcb->remote.svm_cid, pcb->remote.svm_port,
		    (so->so_type == SOCK_SEQPACKET) ?
		    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM);
	}
	pcb->state = VTVSOCK_CLOSED;
	vtvsock_pcb_remove_lists_locked(pcb);

	soisdisconnected(so);
}

/*
 * Fired if OP_RESPONSE is not received within VTVSOCK_CONNECT_TIMEOUT.
 * Aborts the connect attempt.
 * Called with vtvsock_mtx held.
 *
 * Guard pcb->so access.
 */
static void
vtvsock_connect_timeout(void *arg)
{
	struct vtvsock_pcb *pcb = arg;
	struct socket *so;

	so = pcb->so;
	if (so == NULL)
		return;

	if (pcb->state == VTVSOCK_CONNECTING) {
		pcb->state = VTVSOCK_CLOSED;
		vtvsock_pcb_remove_lists_locked(pcb);
		SOCK_LOCK(so);
		so->so_error = ETIMEDOUT;
		SOCK_UNLOCK(so);
		wakeup(&pcb->state);
	}
}

/* -----------------------------------------------------------------------
 * Domain probe
 * ---------------------------------------------------------------------- */

static int
vsock_dom_probe(void)
{
	return (0);
}

/* -----------------------------------------------------------------------
 * Socket protocol operations
 * ---------------------------------------------------------------------- */

static int
vsock_attach(struct socket *so, int proto, struct thread *td)
{
	struct vtvsock_pcb *pcb;
	int error;

	(void)proto;
	(void)td;

	if (so->so_pcb != NULL)
		return (EISCONN);

	if (so->so_type != SOCK_STREAM && so->so_type != SOCK_SEQPACKET)
		return (EPROTOTYPE);

	/*
	 * SEQPACKET requires VIRTIO_VSOCK_F_SEQPACKET to have been
	 * negotiated with the host.  Loopback-only SEQPACKET is still
	 * permitted when no remote transport is registered (features == 0).
	 */
	if (so->so_type == SOCK_SEQPACKET) {
		if (vtvsock_remote_features != 0 &&
		    !(vtvsock_remote_features & VIRTIO_VSOCK_F_SEQPACKET))
			return (EPROTONOSUPPORT);
	}

	/*
	 * §5.10.3.1: If F_NO_IMPLIED_STREAM was negotiated and
	 * F_STREAM was not, STREAM sockets are not supported.
	 * If no remote transport is present (features == 0), or
	 * F_NO_IMPLIED_STREAM was not negotiated, STREAM support is implied.
	 */
	if (so->so_type == SOCK_STREAM) {
		if (vtvsock_remote_features != 0 &&
		    (vtvsock_remote_features & VIRTIO_VSOCK_F_NO_IMPLIED_STREAM) &&
		    !(vtvsock_remote_features & VIRTIO_VSOCK_F_STREAM))
			return (EPROTONOSUPPORT);
	}

	pcb = vtvsock_pcb_alloc(so);
	so->so_pcb = pcb;
	error = soreserve(so, vtvsock_buf_default, vtvsock_buf_default);
	if (error != 0) {
		so->so_pcb = NULL;
		vtvsock_pcb_free(pcb);
		return (error);
	}
	return (0);
}

/*
 * Use callout_drain() so we wait for any in-progress callout
 * to complete before tearing down the PCB.  callout_drain() must be called
 * WITHOUT vtvsock_mtx held (the callout handler acquires it).
 * Set pcb->so = NULL under the lock so the timeout callbacks can guard.
 */
static void
vsock_detach(struct socket *so)
{
	struct vtvsock_pcb *pcb;

	pcb = so->so_pcb;
	if (pcb == NULL)
		return;

	/*
	 * Remove from lists first so the RX handler can't find this PCB,
	 * then NULL the socket pointer.  Both under the lock because the
	 * RX handler holds vtvsock_mtx during PCB lookup and MPASS(so!=NULL).
	 */
	mtx_lock(&vtvsock_mtx);
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->so = NULL;
	mtx_unlock(&vtvsock_mtx);

	/*
	 * callout_drain() waits for any in-progress handler to finish and
	 * prevents future firings.  Must NOT be called with vtvsock_mtx held
	 * since the handler acquires that lock.
	 */
	callout_drain(&pcb->close_callout);
	callout_drain(&pcb->connect_callout);

	so->so_pcb = NULL;
	vtvsock_pcb_free(pcb);
}

static void
vsock_close(struct socket *so)
{
	(void)vsock_disconnect(so);
}

static int
vsock_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct vtvsock_pcb *pcb = so->so_pcb;
	struct sockaddr_vm *svm = (struct sockaddr_vm *)nam;

	(void)td;

	if (pcb == NULL || svm == NULL)
		return (EINVAL);
	if (svm->svm_family != AF_VSOCK ||
	    svm->svm_len != sizeof(*svm))
		return (EINVAL);
	if (svm->svm_reserved1 != 0)
		return (EINVAL);

	/* CID 0 is never valid for binding. */
	if (svm->svm_cid == 0)
		return (EINVAL);

	if (svm->svm_cid == VSOCK_CID_ANY)
		svm->svm_cid = vtvsock_guest_cid;
	if (svm->svm_cid != vtvsock_guest_cid)
		return (EAFNOSUPPORT);

	mtx_lock(&vtvsock_mtx);
	if (pcb->state != VTVSOCK_CLOSED && pcb->state != VTVSOCK_BOUND) {
		mtx_unlock(&vtvsock_mtx);
		return (EINVAL);
	}
	if (pcb->on_boundlist) {
		/* Already bound; remove from list to re-bind. */
		LIST_REMOVE(pcb, link);
		pcb->on_boundlist = false;
	}
	if (svm->svm_port == 0 || svm->svm_port == VSOCK_PORT_ANY) {
		int tries;
		for (tries = 0; tries < 65536; tries++) {
			svm->svm_port = 1024 +
			    (arc4random_uniform(VSOCK_PORT_ANY - 1024));
			if (vtvsock_pcb_lookup_bound_locked(svm->svm_cid,
			    svm->svm_port) == NULL)
				break;
		}
		if (tries == 65536) {
			mtx_unlock(&vtvsock_mtx);
			return (EADDRNOTAVAIL);
		}
	} else if (vtvsock_pcb_lookup_bound_locked(svm->svm_cid,
	    svm->svm_port) != NULL) {
		mtx_unlock(&vtvsock_mtx);
		return (EADDRINUSE);
	}
	pcb->local = *svm;
	pcb->local.svm_len = sizeof(struct sockaddr_vm);
	pcb->state = VTVSOCK_BOUND;
	vtvsock_pcb_insert_bound_locked(pcb);
	mtx_unlock(&vtvsock_mtx);
	return (0);
}

static int
vsock_listen(struct socket *so, int backlog, struct thread *td)
{
	struct vtvsock_pcb *pcb = so->so_pcb;
	int error;

	(void)td;

	if (pcb == NULL)
		return (EINVAL);
	if (pcb->state != VTVSOCK_BOUND)
		return (EINVAL);

	SOCK_LOCK(so);
	error = solisten_proto_check(so);
	if (error != 0) {
		SOCK_UNLOCK(so);
		return (error);
	}

	mtx_lock(&vtvsock_mtx);
	pcb->state = VTVSOCK_LISTEN;
	mtx_unlock(&vtvsock_mtx);
	solisten_proto(so, backlog);	/* sets SO_ACCEPTCONN, releases SOCK_LOCK */
	return (0);
}

static int
vsock_accept(struct socket *so, struct sockaddr *sa)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL)
		return (EINVAL);
	return (vtvsock_copy_to_sockaddr(&pcb->remote, sa));
}

/*
 * vsock_connect — initiate a connection.
 *
 * For local peers (loopback), directly create the accepted socket via
 * sonewconn and mark both ends ESTABLISHED.
 *
 * For remote peers (virtio transport), send OP_REQUEST and sleep until
 * OP_RESPONSE arrives or the connect times out.
 */
static int
vsock_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct vtvsock_pcb *pcb = so->so_pcb;
	struct sockaddr_vm *dst = (struct sockaddr_vm *)nam;
	struct vtvsock_pcb *listener, *child;
	struct socket *child_so;
	bool auto_bound;
	int error;

	(void)td;

	if (pcb == NULL || dst == NULL)
		return (EINVAL);
	if (dst->svm_family != AF_VSOCK ||
	    dst->svm_len != sizeof(*dst))
		return (EINVAL);
	if (dst->svm_reserved1 != 0)
		return (EINVAL);

	mtx_lock(&vtvsock_mtx);

	/* Reject connect on listening sockets. */
	if (pcb->state == VTVSOCK_LISTEN) {
		mtx_unlock(&vtvsock_mtx);
		return (EOPNOTSUPP);
	}

	if (pcb->state == VTVSOCK_ESTABLISHED ||
	    pcb->state == VTVSOCK_CONNECTING) {
		mtx_unlock(&vtvsock_mtx);
		return (EISCONN);
	}
	if (pcb->state == VTVSOCK_CLOSING) {
		mtx_unlock(&vtvsock_mtx);
		return (ECONNRESET);
	}

	/* Assign a local port if not already bound. */
	auto_bound = false;
	if (pcb->local.svm_port == VSOCK_PORT_ANY ||
	    pcb->local.svm_port == 0) {
		uint32_t port;
		int tries;
		for (tries = 0; tries < 65536; tries++) {
			port = 1024 +
			    (arc4random_uniform(VSOCK_PORT_ANY - 1024));
			if (vtvsock_pcb_lookup_bound_locked(vtvsock_guest_cid,
			    port) == NULL)
				break;
		}
		if (tries == 65536) {
			mtx_unlock(&vtvsock_mtx);
			return (EADDRNOTAVAIL);
		}
		vtvsock_pcb_set_addr(&pcb->local, vtvsock_guest_cid, port);
		vtvsock_pcb_insert_bound_locked(pcb);
		auto_bound = true;
	}

	pcb->remote = *dst;
	pcb->remote.svm_len = sizeof(struct sockaddr_vm);

	if (vtvsock_is_local(dst->svm_cid)) {
		/* ---- Local loopback path ---- */
		/*
		 * Normalize the lookup CID: listeners bind with
		 * vtvsock_guest_cid, so VSOCK_CID_LOCAL (1) must be
		 * mapped to the actual guest CID for the lookup to match.
		 */
		listener = vtvsock_pcb_lookup_bound_locked(vtvsock_guest_cid,
		    dst->svm_port);
		if (listener == NULL || listener->state != VTVSOCK_LISTEN ||
		    listener->so->so_type != so->so_type) {
			SDT_PROBE2(vsock, , , connect__refused,
			    dst->svm_cid, dst->svm_port);
			error = ECONNREFUSED;
			goto fail;
		}

		child_so = sonewconn(listener->so, 0);
		if (child_so == NULL) {
			error = ECONNREFUSED;
			goto fail;
		}
		child = child_so->so_pcb;
		child->local = listener->local;
		child->remote = pcb->local;
		child->peer = pcb;
		child->state = VTVSOCK_ESTABLISHED;
		child->transport = &vtvsock_local_transport;
		/* Inherit credit defaults. */
		child->buf_alloc = vtvsock_buf_default;
		child->peer_buf_alloc = pcb->buf_alloc;
		vtvsock_pcb_insert_connected_locked(child);

		pcb->peer = child;
		pcb->state = VTVSOCK_ESTABLISHED;
		pcb->transport = &vtvsock_local_transport;
		pcb->peer_buf_alloc = child->buf_alloc;
		vtvsock_pcb_insert_connected_locked(pcb);

		soisconnected(so);
		soisconnected(child_so);
		SDT_PROBE3(vsock, , , connect__established,
		    dst->svm_cid, dst->svm_port, 1);
		mtx_unlock(&vtvsock_mtx);
		return (0);
	}

	/* ---- Remote transport path ---- */
	if (vtvsock_remote_transport == NULL) {
		error = ENXIO;
		goto fail;
	}

	/*
	 * The virtio-vsock wire protocol uses 64-bit CIDs, but current
	 * hypervisors only assign 32-bit values.  Reject oversized CIDs
	 * early so we don't send a CID the host can't match.
	 */
	if (dst->svm_cid > UINT32_MAX) {
		error = EAFNOSUPPORT;
		goto fail;
	}
	pcb->state = VTVSOCK_CONNECTING;
	pcb->transport = vtvsock_remote_transport;
	vtvsock_pcb_insert_connected_locked(pcb);
	soisconnecting(so);

	error = vtvsock_remote_transport->send_pkt(pcb,
	    VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
	if (error != 0)
		goto fail;

	/* Arm connect timeout. */
	callout_reset(&pcb->connect_callout,
	    pcb->connect_timeout > 0 ? pcb->connect_timeout :
	    VTVSOCK_CONNECT_TIMEOUT,
	    vtvsock_connect_timeout, pcb);

	/* Sleep until ESTABLISHED or error. */
	while (pcb->state == VTVSOCK_CONNECTING) {
		error = msleep(&pcb->state, &vtvsock_mtx, PSOCK | PCATCH,
		    "vsconn", 0);
		if (error != 0)
			break;
	}
	callout_stop(&pcb->connect_callout);

	if (error == 0 && pcb->state != VTVSOCK_ESTABLISHED) {
		SOCK_LOCK(so);
		error = so->so_error != 0 ? so->so_error : ECONNREFUSED;
		so->so_error = 0;
		SOCK_UNLOCK(so);
	}
	if (error != 0)
		goto fail;
	mtx_unlock(&vtvsock_mtx);
	return (0);

fail:
	if (auto_bound) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
	} else {
		if (pcb->on_connlist) {
			LIST_REMOVE(pcb, connlink);
			pcb->on_connlist = false;
		}
		if (pcb->peer != NULL) {
			pcb->peer->peer = NULL;
			pcb->peer = NULL;
		}
		pcb->state = VTVSOCK_BOUND;
	}
	mtx_unlock(&vtvsock_mtx);
	return (error);
}

static int
vsock_peeraddr(struct socket *so, struct sockaddr *nam)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL || pcb->state != VTVSOCK_ESTABLISHED)
		return (ENOTCONN);
	return (vtvsock_copy_to_sockaddr(&pcb->remote, nam));
}

static int
vsock_sockaddr(struct socket *so, struct sockaddr *nam)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL)
		return (EINVAL);
	return (vtvsock_copy_to_sockaddr(&pcb->local, nam));
}

static int
vsock_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct vtvsock_pcb *pcb = so->so_pcb;
	uint64_t val64;
	int error;

	if (pcb == NULL)
		return (EINVAL);

	if (sopt->sopt_level != SOL_VSOCK)
		return (EOPNOTSUPP);

	switch (sopt->sopt_name) {
	case SO_VM_SOCKETS_BUFFER_SIZE:
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &val64, sizeof(val64),
			    sizeof(val64));
			if (error != 0)
				return (error);
			if (val64 < pcb->buffer_min)
				val64 = pcb->buffer_min;
			if (val64 > pcb->buffer_max)
				val64 = pcb->buffer_max;
			int ival = (int)MIN(val64, (uint64_t)__INT_MAX);
			error = so_setsockopt(so, SOL_SOCKET, SO_SNDBUF,
			    &ival, sizeof(ival));
			if (error != 0)
				return (error);
			error = so_setsockopt(so, SOL_SOCKET, SO_RCVBUF,
			    &ival, sizeof(ival));
			if (error != 0)
				return (error);
			/* Advertise updated RX capacity to peer. */
			mtx_lock(&vtvsock_mtx);
			pcb->buf_alloc = (uint32_t)ival;
			if (pcb->state == VTVSOCK_ESTABLISHED &&
			    pcb->transport != &vtvsock_local_transport &&
			    vtvsock_remote_transport != NULL)
				vtvsock_remote_transport->send_credit_update(pcb);
			mtx_unlock(&vtvsock_mtx);
			return (0);
		}
		val64 = so->so_rcv.sb_hiwat;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	case SO_VM_SOCKETS_BUFFER_MIN_SIZE:
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &val64, sizeof(val64),
			    sizeof(val64));
			if (error != 0)
				return (error);
			pcb->buffer_min = val64;
			if (pcb->buffer_max < pcb->buffer_min)
				pcb->buffer_max = pcb->buffer_min;
			return (0);
		}
		val64 = pcb->buffer_min;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	case SO_VM_SOCKETS_BUFFER_MAX_SIZE:
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &val64, sizeof(val64),
			    sizeof(val64));
			if (error != 0)
				return (error);
			pcb->buffer_max = val64;
			if (pcb->buffer_min > pcb->buffer_max)
				pcb->buffer_min = pcb->buffer_max;
			return (0);
		}
		val64 = pcb->buffer_max;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	case SO_VM_SOCKETS_PEER_HOST_VM_ID:
		if (sopt->sopt_dir != SOPT_GET)
			return (EOPNOTSUPP);
		if (pcb->state != VTVSOCK_ESTABLISHED)
			return (ENOTCONN);
		val64 = pcb->remote.svm_cid;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	case SO_VM_SOCKETS_CONNECT_TIMEOUT:
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &val64, sizeof(val64),
			    sizeof(val64));
			if (error != 0)
				return (error);
			if (val64 > 0) {
				/* Clamp to avoid overflow in ticks. */
				if (val64 > 360000)
					val64 = 360000; /* 1 hour max */
				pcb->connect_timeout =
				    (int)(val64 * hz / 100);
			} else
				pcb->connect_timeout = 0;
			return (0);
		}
		if (pcb->connect_timeout > 0)
			val64 = (uint64_t)pcb->connect_timeout * 100 / hz;
		else
			val64 = (uint64_t)VTVSOCK_CONNECT_TIMEOUT * 100 / hz;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	default:
		return (EOPNOTSUPP);
	}
}

/*
 * Wrap the default sbsetopt to send a CREDIT_UPDATE after SO_RCVLOWAT
 * changes.  sosetopt() dispatches SO_RCVLOWAT to pr_setsbopt, not
 * pr_ctloutput, so the credit notification must live here.
 */
static int
vsock_setsbopt(struct socket *so, struct sockopt *sopt)
{
	struct vtvsock_pcb *pcb;
	int error;

	error = sbsetopt(so, sopt);
	if (error != 0)
		return (error);

	if (sopt->sopt_name == SO_RCVLOWAT &&
	    sopt->sopt_dir == SOPT_SET) {
		pcb = so->so_pcb;
		if (pcb != NULL) {
			mtx_lock(&vtvsock_mtx);
			if (pcb->state == VTVSOCK_ESTABLISHED &&
			    pcb->transport != &vtvsock_local_transport &&
			    vtvsock_remote_transport != NULL &&
			    pcb->rx_bytes < (uint32_t)so->so_rcv.sb_lowat)
				vtvsock_remote_transport->send_credit_update(pcb);
			mtx_unlock(&vtvsock_mtx);
		}
	}
	return (0);
}

/*
 * fwd_cnt is incremented here in the dequeue (application recv) path,
 * matching Linux semantics.  The credit update trigger also lives here.
 *
 * Uses Linux's credit trigger condition: send an update when unreported
 * consumption approaches our buffer capacity, or rx_bytes falls below the
 * low-water mark.
 */
static int
vsock_soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	struct vtvsock_pcb *pcb;
	uint32_t before, after, consumed;
	uint32_t unreported;
	bool is_local;
	int error;

	if (psa != NULL)
		*psa = NULL;
	if (mp0 != NULL)
		*mp0 = NULL;
	if (controlp != NULL)
		*controlp = NULL;

	/* Snapshot buffer occupancy before receive. */
	SOCK_RECVBUF_LOCK(so);
	before = (uint32_t)sbavail(&so->so_rcv);
	SOCK_RECVBUF_UNLOCK(so);

	error = (so->so_type == SOCK_SEQPACKET ?
	    soreceive_dgram(so, psa, uio, mp0, controlp, flagsp) :
	    soreceive_stream(so, psa, uio, mp0, controlp, flagsp));

	/*
	 * After data is consumed from the receive buffer, update our
	 * rx_bytes tracking and fwd_cnt, then send CREDIT_UPDATE to the
	 * peer if needed.
	 */
	/*
	 * Acquire vtvsock_mtx before reading so_pcb to prevent a
	 * concurrent vsock_detach() from freeing the PCB (use-after-free).
	 */
	mtx_lock(&vtvsock_mtx);
	pcb = so->so_pcb;
	is_local = (pcb != NULL &&
	    pcb->transport == &vtvsock_local_transport);
	if (pcb != NULL && pcb->transport != &vtvsock_local_transport &&
	    vtvsock_remote_transport != NULL &&
	    pcb->state == VTVSOCK_ESTABLISHED) {
		SOCK_RECVBUF_LOCK(so);
		after = (uint32_t)sbavail(&so->so_rcv);
		SOCK_RECVBUF_UNLOCK(so);

		if (before > after) {
			consumed = before - after;
			SDT_PROBE2(vsock, , , receive,
			    (size_t)consumed,
			    so->so_type == SOCK_SEQPACKET);
			if (pcb->rx_bytes >= consumed)
				pcb->rx_bytes -= consumed;
			else
				pcb->rx_bytes = 0;
			/* Increment fwd_cnt in the dequeue path. */
			pcb->fwd_cnt += consumed;

			/*
			 * Trigger credit update when unreported
			 * consumption approaches our buffer capacity,
			 * or rx_bytes has drained below the socket
			 * low-water mark.
			 */
			unreported = pcb->fwd_cnt - pcb->last_fwd_cnt;
			if (pcb->state == VTVSOCK_ESTABLISHED &&
			    vtvsock_remote_transport != NULL &&
			    ((pcb->buf_alloc > VTVSOCK_MAX_PKT_BUF &&
			    unreported >= pcb->buf_alloc -
			    VTVSOCK_MAX_PKT_BUF) ||
			    pcb->rx_bytes < (uint32_t)so->so_rcv.sb_lowat))
				vtvsock_remote_transport->send_credit_update(pcb);

			/*
			 * If the peer has fully shut down both directions
			 * and our rx queue is now drained, send RST and
			 * tear down.  This handles the deferred case where
			 * OP_SHUTDOWN arrived while rx_bytes > 0.
			 */
			if (pcb->peer_shutdown ==
			    (VIRTIO_VSOCK_SHUTDOWN_RCV |
			     VIRTIO_VSOCK_SHUTDOWN_SEND) &&
			    pcb->rx_bytes == 0 &&
			    pcb->state == VTVSOCK_ESTABLISHED) {
				pcb->state = VTVSOCK_CLOSED;
				vtvsock_pcb_remove_lists_locked(pcb);
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    pcb->local.svm_cid,
					    pcb->local.svm_port,
					    pcb->remote.svm_cid,
					    pcb->remote.svm_port,
					    (so->so_type == SOCK_SEQPACKET) ?
					    VIRTIO_VSOCK_TYPE_SEQPACKET :
					    VIRTIO_VSOCK_TYPE_STREAM);
				mtx_unlock(&vtvsock_mtx);
				soisdisconnected(so);
				return (error);
			}
		}
		mtx_unlock(&vtvsock_mtx);
	} else {
		mtx_unlock(&vtvsock_mtx);
	}

	/*
	 * For local loopback, wake the peer's send path which may be
	 * sleeping in vtvsock_local_send waiting for receive buffer space.
	 *
	 * Use is_local (captured under vtvsock_mtx above) instead of
	 * dereferencing pcb->transport, and re-read pcb from so->so_pcb
	 * under the lock, because a racing vsock_detach() may have freed
	 * the original pcb between the unlock above and here.
	 */
	if (error == 0 && is_local) {
		SOCK_RECVBUF_LOCK(so);
		after = (uint32_t)sbavail(&so->so_rcv);
		SOCK_RECVBUF_UNLOCK(so);
		if (before > after) {
			mtx_lock(&vtvsock_mtx);
			pcb = so->so_pcb;
			if (pcb != NULL && pcb->peer != NULL)
				wakeup(&pcb->peer->tx_cnt);
			mtx_unlock(&vtvsock_mtx);
		}
	}

	return (error);
}

static int
vsock_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct thread *td)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL) {
		m_freem(m);
		if (control != NULL)
			m_freem(control);
		return (EINVAL);
	}
	if (pcb->state != VTVSOCK_ESTABLISHED) {
		m_freem(m);
		if (control != NULL)
			m_freem(control);
		return (ENOTCONN);
	}
	SDT_PROBE2(vsock, , , send, m_length(m, NULL),
	    so->so_type == SOCK_SEQPACKET);
	return (pcb->transport->send(pcb, flags, m, addr, control, td));
}

static int
vsock_disconnect(struct socket *so)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL)
		return (EINVAL);
	SDT_PROBE2(vsock, , , disconnect,
	    pcb->remote.svm_cid, pcb->remote.svm_port);
	return (pcb->transport->disconnect(pcb));
}

static int
vsock_shutdown(struct socket *so, enum shutdown_how how)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL)
		return (EINVAL);
	return (pcb->transport->shutdown(pcb, how));
}

static void
vsock_abort(struct socket *so)
{
	(void)vsock_disconnect(so);
}

/* -----------------------------------------------------------------------
 * Local (loopback) transport
 * ---------------------------------------------------------------------- */

/*
 * Send data to the peer socket's receive buffer directly.
 * Lock ordering: acquire vtvsock_mtx first, then peer's SOCK_RECVBUF_LOCK.
 */
static int
vtvsock_local_send(struct vtvsock_pcb *pcb, int flags, struct mbuf *m,
    struct sockaddr *addr, struct mbuf *control, struct thread *td)
{
	struct socket *peer_so;
	size_t len;
	int error;

	(void)flags;
	(void)addr;
	(void)td;

	if (control != NULL) {
		m_freem(control);
		control = NULL;
	}

	len = m_length(m, NULL);
	if (len == 0) {
		m_freem(m);
		return (0);
	}

	mtx_lock(&vtvsock_mtx);
	if (pcb->peer == NULL || pcb->state != VTVSOCK_ESTABLISHED) {
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (EPIPE);
	}
	peer_so = pcb->peer->so;
	if (peer_so == NULL) {
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (EPIPE);
	}

	SOCK_RECVBUF_LOCK(peer_so);
	/* Peer has shut down receive; no point sending. */
	if (peer_so->so_rcv.sb_state & SBS_CANTRCVMORE) {
		SOCK_RECVBUF_UNLOCK(peer_so);
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (EPIPE);
	}
	/* SEQPACKET: entire message must fit atomically. */
	if (pcb->so->so_type == SOCK_SEQPACKET &&
	    len > (size_t)peer_so->so_rcv.sb_hiwat) {
		SOCK_RECVBUF_UNLOCK(peer_so);
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (EMSGSIZE);
	}
	while ((size_t)sbspace(&peer_so->so_rcv) < len) {
		if (pcb->so->so_state & SS_NBIO) {
			SOCK_RECVBUF_UNLOCK(peer_so);
			mtx_unlock(&vtvsock_mtx);
			m_freem(m);
			return (EWOULDBLOCK);
		}
		SOCK_RECVBUF_UNLOCK(peer_so);
		/*
		 * Sleep with vtvsock_mtx as the interlock so it is
		 * released during the sleep and other threads can make
		 * progress.
		 */
		error = msleep(&pcb->tx_cnt, &vtvsock_mtx,
		    PSOCK | PCATCH, "vsocklsnd", hz);
		if (error != 0 && error != EWOULDBLOCK) {
			mtx_unlock(&vtvsock_mtx);
			m_freem(m);
			return (error);
		}
		if (pcb->peer == NULL || pcb->state != VTVSOCK_ESTABLISHED) {
			mtx_unlock(&vtvsock_mtx);
			m_freem(m);
			return (EPIPE);
		}
		peer_so = pcb->peer->so;
		if (peer_so == NULL) {
			mtx_unlock(&vtvsock_mtx);
			m_freem(m);
			return (EPIPE);
		}
		SOCK_RECVBUF_LOCK(peer_so);
		/* Re-check after re-acquiring the lock. */
		if (peer_so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			SOCK_RECVBUF_UNLOCK(peer_so);
			mtx_unlock(&vtvsock_mtx);
			m_freem(m);
			return (EPIPE);
		}
	}
	if (pcb->so->so_type == SOCK_SEQPACKET)
		sbappendrecord_locked(&peer_so->so_rcv, m);
	else
		sbappendstream_locked(&peer_so->so_rcv, m, 0);
	sorwakeup_locked(peer_so);
	mtx_unlock(&vtvsock_mtx);
	return (0);
}

static int
vtvsock_local_disconnect(struct vtvsock_pcb *pcb)
{
	struct socket *so = pcb->so;
	struct socket *peer_so = NULL;

	/*
	 * Hold vtvsock_mtx across the peer_so dereference and the
	 * SOCK_RECVBUF_LOCK acquisition to prevent the peer from
	 * detaching (which sets peer->so = NULL) between our read
	 * and use.
	 */
	mtx_lock(&vtvsock_mtx);
	if (pcb->peer != NULL) {
		peer_so = pcb->peer->so;
		/* Wake any peer thread blocked in vtvsock_local_send. */
		wakeup(&pcb->peer->tx_cnt);
	}
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->state = VTVSOCK_CLOSED;

	if (peer_so != NULL) {
		SOCK_RECVBUF_LOCK(peer_so);
		socantrcvmore_locked(peer_so);
	}
	mtx_unlock(&vtvsock_mtx);

	soisdisconnected(so);
	return (0);
}

static int
vtvsock_local_shutdown(struct vtvsock_pcb *pcb, enum shutdown_how how)
{
	struct socket *so = pcb->so;
	struct socket *peer_so;

	/*
	 * Hold vtvsock_mtx across the peer_so dereference and the socket
	 * buffer lock acquisitions to prevent the peer from detaching
	 * (which sets peer->so = NULL) between our read and use.
	 *
	 * Lock ordering: vtvsock_mtx -> SOCK_RECVBUF_LOCK / SOCK_SENDBUF_LOCK.
	 */
	mtx_lock(&vtvsock_mtx);
	peer_so = pcb->peer != NULL ? pcb->peer->so : NULL;

	switch (how) {
	case SHUT_RD:
		/*
		 * Mark our recv buffer as closed, then wake the peer
		 * sender so it sees SBS_CANTRCVMORE and returns EPIPE.
		 * Lock ordering: vtvsock_mtx -> SOCK_RECVBUF_LOCK.
		 */
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		if (pcb->peer != NULL)
			wakeup(&pcb->peer->tx_cnt);
		mtx_unlock(&vtvsock_mtx);
		break;
	case SHUT_WR:
		if (peer_so != NULL) {
			SOCK_RECVBUF_LOCK(peer_so);
			socantrcvmore_locked(peer_so);
		}
		mtx_unlock(&vtvsock_mtx);
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	case SHUT_RDWR:
		if (peer_so != NULL) {
			SOCK_RECVBUF_LOCK(peer_so);
			socantrcvmore_locked(peer_so);
		}
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		if (pcb->peer != NULL)
			wakeup(&pcb->peer->tx_cnt);
		mtx_unlock(&vtvsock_mtx);
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	default:
		mtx_unlock(&vtvsock_mtx);
		break;
	}
	return (0);
}

/* -----------------------------------------------------------------------
 * RX packet handler
 *
 * Called from the transport interrupt handler with no locks held.
 * Acquires vtvsock_mtx around list lookups and PCB state changes, then
 * releases it before acquiring socket buffer locks.
 *
 * The caller retains ownership of 'buf' — this function does not free it.
 * The transport interrupt handler is responsible for recycling or freeing
 * the buffer after this function returns.
 *
 * All header fields are decoded from little-endian.  fwd_cnt is NOT
 * incremented here; that happens in vsock_soreceive.  Peer credit state
 * is extracted from every packet before the opcode switch.
 * ---------------------------------------------------------------------- */

void
vsock_rx_packet(void *buf, uint32_t len)
{
	struct virtio_vsock_hdr *hdr;
	struct vtvsock_pcb *pcb;
	struct socket *so;
	uint8_t *payload;
	size_t payload_len;
	struct mbuf *m;
	uint64_t hdr_src_cid, hdr_dst_cid;
	uint32_t hdr_src_port, hdr_dst_port;
	uint32_t hdr_len, hdr_flags, hdr_buf_alloc, hdr_fwd_cnt;
	uint16_t hdr_type, hdr_op;
	int teardown_errno = 0;
	bool teardown_rst = false;

	if (len < sizeof(*hdr))
		return;
	hdr = buf;

	hdr_src_cid   = le64toh(hdr->src_cid);
	hdr_dst_cid   = le64toh(hdr->dst_cid);
	hdr_src_port  = le32toh(hdr->src_port);
	hdr_dst_port  = le32toh(hdr->dst_port);
	hdr_len       = le32toh(hdr->len);
	hdr_type      = le16toh(hdr->type);
	hdr_op        = le16toh(hdr->op);
	hdr_flags     = le32toh(hdr->flags);
	hdr_buf_alloc = le32toh(hdr->buf_alloc);
	hdr_fwd_cnt   = le32toh(hdr->fwd_cnt);

	counter_u64_add(vtvsock_cnt_rx_packets, 1);

	payload = (uint8_t *)buf + sizeof(*hdr);
	payload_len = len - sizeof(*hdr);
	if (payload_len > hdr_len)
		payload_len = hdr_len;

	/* Validate type field (§5.10.6.4.1: RST for unknown type). */
	if (hdr_type != VIRTIO_VSOCK_TYPE_STREAM &&
	    hdr_type != VIRTIO_VSOCK_TYPE_SEQPACKET) {
		mtx_lock(&vtvsock_mtx);
		if (vtvsock_remote_transport != NULL)
			(void)vtvsock_remote_transport->send_rst(
			    hdr_dst_cid, hdr_dst_port,
			    hdr_src_cid, hdr_src_port, hdr_type);
		mtx_unlock(&vtvsock_mtx);
		return;
	}

	mtx_lock(&vtvsock_mtx);

	/*
	 * Locate the PCB.  For OP_REQUEST, look for a listening socket in
	 * the bound list.  For all other ops, look in the connected list.
	 */
	if (hdr_op == VIRTIO_VSOCK_OP_REQUEST) {
		pcb = vtvsock_pcb_lookup_bound_locked(hdr_dst_cid, hdr_dst_port);
		if (pcb == NULL || pcb->state != VTVSOCK_LISTEN) {
			/* No listener; send RST (under lock for VQ safety). */
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_rst(
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			return;
		}
	} else {
		pcb = vtvsock_pcb_lookup_connected_locked(hdr_src_cid,
		    hdr_src_port, hdr_dst_cid, hdr_dst_port);
		if (pcb == NULL) {
			/*
			 * Unknown connection.  For RST don't reply (avoid
			 * RST loops).  For anything else, send RST.
			 * Keep lock held to serialize TX VQ access.
			 */
			if (hdr_op != VIRTIO_VSOCK_OP_RST &&
			    vtvsock_remote_transport != NULL) {
				(void)vtvsock_remote_transport->send_rst(
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port,
				    hdr_type);
			}
			mtx_unlock(&vtvsock_mtx);
			return;
		}
	}

	so = pcb->so;
	MPASS(so != NULL);

	/*
	 * Extract peer credit state from every incoming packet before
	 * dispatching on opcode.  This ensures credit advances even when
	 * the peer piggybacks updates on data or control packets.
	 * For OP_REQUEST (no established PCB yet) we skip this since the
	 * child PCB is initialized below with the peer's credit values.
	 */
	if (hdr_op != VIRTIO_VSOCK_OP_REQUEST) {
		pcb->peer_buf_alloc = hdr_buf_alloc;
		/*
		 * Validate peer_fwd_cnt: it must not claim to have
		 * consumed more bytes than we have sent (tx_cnt).
		 * Use signed comparison to handle 32-bit wrap correctly.
		 */
		if ((int32_t)(hdr_fwd_cnt - pcb->tx_cnt) > 0) {
			teardown_rst = true;
			goto teardown_close;
		}
		pcb->peer_fwd_cnt = hdr_fwd_cnt;
		wakeup(&pcb->tx_cnt);
	}

	/* Validate packet type matches the socket type for non-REQUEST ops. */
	if (hdr_op != VIRTIO_VSOCK_OP_REQUEST) {
		uint16_t expected_type = (so->so_type == SOCK_SEQPACKET) ?
		    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM;
		if (hdr_type != expected_type) {
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_rst(
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			return;
		}
	}

	switch (hdr_op) {
	case VIRTIO_VSOCK_OP_REQUEST:
		/*
		 * Incoming connection request on a listening socket.
		 * Create a new socket via sonewconn, assign PCB, send
		 * OP_RESPONSE.
		 */
		{
			struct socket *child_so;
			struct vtvsock_pcb *child;

			if (so->so_options & SO_ACCEPTCONN &&
			    (so->so_rcv.sb_state & SBS_CANTRCVMORE)) {
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    hdr_dst_cid, hdr_dst_port,
					    hdr_src_cid, hdr_src_port,
					    hdr_type);
				mtx_unlock(&vtvsock_mtx);
				return;
			}

			/*
			 * Validate that the requested type (STREAM vs
			 * SEQPACKET) matches the listener's socket type.
			 * Reject mismatches with RST per §5.10.6.4.
			 */
			{
				uint16_t expected = (so->so_type ==
				    SOCK_SEQPACKET) ?
				    VIRTIO_VSOCK_TYPE_SEQPACKET :
				    VIRTIO_VSOCK_TYPE_STREAM;
				if (hdr_type != expected) {
					if (vtvsock_remote_transport != NULL)
						(void)vtvsock_remote_transport->
						    send_rst(
						    hdr_dst_cid, hdr_dst_port,
						    hdr_src_cid, hdr_src_port,
						    hdr_type);
					mtx_unlock(&vtvsock_mtx);
					return;
				}
			}

			child_so = sonewconn(so, 0);
			if (child_so == NULL) {
				/* Backlog full; reject. */
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    hdr_dst_cid, hdr_dst_port,
					    hdr_src_cid, hdr_src_port,
					    hdr_type);
				mtx_unlock(&vtvsock_mtx);
				return;
			}
			child = child_so->so_pcb;
			child->local = pcb->local;
			vtvsock_pcb_set_addr(&child->remote,
			    hdr_src_cid, hdr_src_port);
			child->state = VTVSOCK_ESTABLISHED;
			child->transport = vtvsock_remote_transport;
			/* Credit from peer (already decoded above). */
			child->peer_buf_alloc = hdr_buf_alloc;
			child->peer_fwd_cnt   = hdr_fwd_cnt;
			child->buf_alloc = vtvsock_buf_default;
			vtvsock_pcb_insert_connected_locked(child);

			/* Send OP_RESPONSE using the child's addresses. */
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_pkt(child,
				    VIRTIO_VSOCK_OP_RESPONSE, 0, NULL, 0);

			soisconnected(child_so);
			counter_u64_add(vtvsock_cnt_conns, 1);
		}
		mtx_unlock(&vtvsock_mtx);
		break;

	case VIRTIO_VSOCK_OP_RESPONSE:
		/*
		 * Connection accepted by the remote peer.
		 * peer_buf_alloc / peer_fwd_cnt already updated above.
		 * Transition to ESTABLISHED.
		 */
		if (pcb->state == VTVSOCK_CONNECTING) {
			pcb->state = VTVSOCK_ESTABLISHED;
			callout_stop(&pcb->connect_callout);
			wakeup(&pcb->state);
			SDT_PROBE3(vsock, , , connect__established,
			    pcb->remote.svm_cid, pcb->remote.svm_port, 0);
			mtx_unlock(&vtvsock_mtx);
			soisconnected(so);
			counter_u64_add(vtvsock_cnt_conns, 1);
		} else {
			mtx_unlock(&vtvsock_mtx);
		}
		break;

	case VIRTIO_VSOCK_OP_RST:
		/*
		 * Remote peer sent RST.  Forcibly close.
		 */
		if (pcb->state != VTVSOCK_CLOSED) {
			teardown_errno = ECONNRESET;
			goto teardown_close;
		} else {
			mtx_unlock(&vtvsock_mtx);
		}
		break;

	case VIRTIO_VSOCK_OP_SHUTDOWN:
		/*
		 * Peer is shutting down one or both directions.
		 *
		 * Accumulate peer_shutdown flags and detect when the
		 * peer has fully shut down both directions.
		 */
		{
			uint32_t sflags = hdr_flags;

			/* Accumulate peer shutdown state. */
			pcb->peer_shutdown |= (sflags &
			    (VIRTIO_VSOCK_SHUTDOWN_RCV |
			     VIRTIO_VSOCK_SHUTDOWN_SEND));

			if (pcb->peer_shutdown ==
			    (VIRTIO_VSOCK_SHUTDOWN_RCV |
			     VIRTIO_VSOCK_SHUTDOWN_SEND) &&
			    pcb->rx_bytes == 0) {
				/*
				 * Peer has fully shut down and our RX queue
				 * is empty — send RST and close.
				 */
				teardown_rst = true;
				goto teardown_close;
			} else {
				/* Wake credit-blocked senders immediately. */
				wakeup(&pcb->tx_cnt);
				mtx_unlock(&vtvsock_mtx);
				/* Apply individual half-shutdown notifications. */
				if (sflags & VIRTIO_VSOCK_SHUTDOWN_RCV) {
					SOCK_SENDBUF_LOCK(so);
					socantsendmore_locked(so);
				}
				if (sflags & VIRTIO_VSOCK_SHUTDOWN_SEND) {
					SOCK_RECVBUF_LOCK(so);
					socantrcvmore_locked(so);
				}
			}
		}
		break;

	case VIRTIO_VSOCK_OP_RW:
		/*
		 * Data payload.
		 *
		 * sowwakeup to unblock writers waiting on send space.
		 * fwd_cnt is NOT incremented here; the dequeue path does it.
		 * Cumulative rx_bytes overflow check protects our RX buffer.
		 * SEQPACKET fragments are reassembled via seqpacket_partial.
		 */
		if (pcb->state != VTVSOCK_ESTABLISHED) {
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_rst(
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			break;
		}

		if (payload_len == 0) {
			/*
			 * For SEQPACKET, a zero-length fragment with EOM
			 * must still deliver the accumulated partial.
			 */
			if (so->so_type == SOCK_SEQPACKET &&
			    (hdr_flags & VIRTIO_VSOCK_SEQ_EOM) &&
			    pcb->seqpacket_partial != NULL) {
				m = pcb->seqpacket_partial;
				pcb->seqpacket_partial = NULL;
				if (hdr_flags & VIRTIO_VSOCK_SEQ_EOR) {
					struct mbuf *last;
					for (last = m; last->m_next != NULL;
					    last = last->m_next)
						;
					last->m_flags |= M_EOR;
				}
				mtx_unlock(&vtvsock_mtx);
				sowwakeup(so);
				SOCK_RECVBUF_LOCK(so);
				sbappendrecord_locked(&so->so_rcv, m);
				sorwakeup_locked(so);
			} else {
				mtx_unlock(&vtvsock_mtx);
				sowwakeup(so);
			}
			break;
		}

		/*
		 * Cumulative overflow check: reject if accepting this
		 * packet would exceed our total advertised receive buffer.
		 */
		if (payload_len > pcb->buf_alloc ||
		    pcb->rx_bytes > pcb->buf_alloc - (uint32_t)payload_len) {
			teardown_rst = true;
			teardown_errno = ENOBUFS;
			goto teardown_close;
		}

		m = m_getm2(NULL, payload_len, M_NOWAIT, MT_DATA, M_PKTHDR);
		if (m == NULL) {
			/* Out of mbufs; send RST. */
			teardown_rst = true;
			goto teardown_close;
		}
		m_copyback(m, 0, payload_len, payload);

		/*
		 * Only update rx_bytes here (enqueue path).
		 * fwd_cnt is updated in vsock_soreceive (dequeue path).
		 */
		pcb->rx_bytes += (uint32_t)payload_len;
		counter_u64_add(vtvsock_cnt_rx_bytes, payload_len);

		if (so->so_type == SOCK_SEQPACKET) {
			/*
			 * SEQPACKET fragment reassembly: accumulate fragments
			 * until EOM is set, then deliver the complete record
			 * to the socket buffer.
			 *
			 * Limit total reassembly size to buf_alloc to prevent
			 * a buggy or malicious peer from consuming unbounded
			 * kernel memory by never sending EOM.
			 */
			if (pcb->seqpacket_partial != NULL) {
				size_t partial_len =
				    m_length(pcb->seqpacket_partial, NULL);
				u_int frag_max = vtvsock_seqpacket_frag_max;
				if (partial_len + payload_len > pcb->buf_alloc ||
				    (frag_max > 0 &&
				    pcb->seqpacket_frag_count >= frag_max)) {
					m_freem(m);
					teardown_rst = true;
					teardown_errno = EMSGSIZE;
					goto teardown_close;
				}
				pcb->seqpacket_frag_count++;
				m_cat(pcb->seqpacket_partial, m);
				m = NULL;
			} else {
				pcb->seqpacket_partial = m;
				pcb->seqpacket_frag_count = 1;
				m = NULL;
			}

			if (hdr_flags & VIRTIO_VSOCK_SEQ_EOM) {
				/* EOM set: deliver the complete record. */
				m = pcb->seqpacket_partial;
				pcb->seqpacket_partial = NULL;
				pcb->seqpacket_frag_count = 0;
				if (hdr_flags & VIRTIO_VSOCK_SEQ_EOR) {
					struct mbuf *last;
					for (last = m; last->m_next != NULL;
					    last = last->m_next)
						;
					last->m_flags |= M_EOR;
				}
				mtx_unlock(&vtvsock_mtx);
				sowwakeup(so);
				SOCK_RECVBUF_LOCK(so);
				sbappendrecord_locked(&so->so_rcv, m);
				sorwakeup_locked(so);
			} else {
				/* More fragments coming; hold the partial. */
				mtx_unlock(&vtvsock_mtx);
				sowwakeup(so);
			}
		} else {
			/* SOCK_STREAM: deliver immediately. */
			mtx_unlock(&vtvsock_mtx);
			sowwakeup(so);
			SOCK_RECVBUF_LOCK(so);
			sbappendstream_locked(&so->so_rcv, m, 0);
			sorwakeup_locked(so);
		}
		break;

	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		/*
		 * Peer is advertising new/updated RX capacity.
		 * peer_buf_alloc / peer_fwd_cnt already updated above.
		 * wakeup(&pcb->tx_cnt) also already done above.
		 */
		mtx_unlock(&vtvsock_mtx);
		sowwakeup(so);
		break;

	case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
		/*
		 * Peer is asking us to report our current RX credit.
		 */
		if (vtvsock_remote_transport != NULL)
			vtvsock_remote_transport->send_credit_update(pcb);
		mtx_unlock(&vtvsock_mtx);
		break;

	default: {
		static struct timeval vtvsock_warn_lasttime;
		static int vtvsock_warn_curpps;

		/*
		 * Unknown opcode: silently ignore.  The spec mandates RST
		 * for unknown *types* (handled above), not unknown ops.
		 * Sending RST here would break forward compatibility with
		 * future spec extensions.
		 */
		if (ppsratecheck(&vtvsock_warn_lasttime, &vtvsock_warn_curpps, 1))
			printf("vtvsock: unknown op %u from host, ignoring\n",
			    hdr_op);
		mtx_unlock(&vtvsock_mtx);
		break;
	}}

	return;

teardown_close:
	counter_u64_add(vtvsock_cnt_rx_drops, 1);
	callout_stop(&pcb->close_callout);
	callout_stop(&pcb->connect_callout);
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->state = VTVSOCK_CLOSED;
	wakeup(&pcb->state);
	wakeup(&pcb->tx_cnt);
	if (teardown_rst && vtvsock_remote_transport != NULL)
		(void)vtvsock_remote_transport->send_rst(
		    hdr_dst_cid, hdr_dst_port,
		    hdr_src_cid, hdr_src_port, hdr_type);
	mtx_unlock(&vtvsock_mtx);
	if (teardown_errno != 0) {
		SOCK_LOCK(so);
		so->so_error = teardown_errno;
		SOCK_UNLOCK(so);
	}
	soisdisconnected(so);
}

/* -----------------------------------------------------------------------
 * Transport reset
 *
 * Reset all remote connections.  Called from vsock_transport_unregister()
 * with vtvsock_mtx held, and exported as vsock_transport_reset() for
 * use by the transport driver on TRANSPORT_RESET events.
 * ---------------------------------------------------------------------- */

static void
vsock_transport_reset_locked(void)
{
	struct vtvsock_pcb *pcb, *tmp;
	struct socket *so;

	/* Reset all connected sockets. */
	LIST_FOREACH_SAFE(pcb, &vtvsock_conn, connlink, tmp) {
		so = pcb->so;
		KASSERT(so != NULL,
		    ("%s: pcb %p on connlist with NULL so", __func__, pcb));
		callout_stop(&pcb->close_callout);
		callout_stop(&pcb->connect_callout);
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		wakeup(&pcb->state);
		SOCK_LOCK(so);
		so->so_error = ECONNRESET;
		SOCK_UNLOCK(so);
		soisdisconnected(so);
	}
}

void
vsock_transport_reset(void)
{
	mtx_lock(&vtvsock_mtx);
	vsock_transport_reset_locked();
	mtx_unlock(&vtvsock_mtx);
}

/* -----------------------------------------------------------------------
 * Transport registration
 *
 * Called by the remote transport driver (e.g. virtio_vsock) on
 * attach/detach to register/unregister itself with the socket domain.
 * ---------------------------------------------------------------------- */

void
vsock_transport_register(const struct vtvsock_transport *ops,
    uint64_t guest_cid, uint64_t features)
{
	mtx_lock(&vtvsock_mtx);
	vtvsock_remote_transport = ops;
	vtvsock_guest_cid = guest_cid;
	vtvsock_remote_features = features;
	/* Update listener CIDs to the new guest CID */
	{
		struct vtvsock_pcb *lpcb;
		LIST_FOREACH(lpcb, &vtvsock_bound, link) {
			if (lpcb->state == VTVSOCK_LISTEN ||
			    lpcb->state == VTVSOCK_BOUND)
				lpcb->local.svm_cid = guest_cid;
		}
	}
	mtx_unlock(&vtvsock_mtx);
}

void
vsock_transport_unregister(void)
{
	mtx_lock(&vtvsock_mtx);
	vtvsock_remote_transport = NULL;
	vtvsock_remote_features = 0;
	vtvsock_guest_cid = VSOCK_CID_LOCAL;
	/* Reset all remote connections */
	vsock_transport_reset_locked();
	mtx_unlock(&vtvsock_mtx);
}

/* -----------------------------------------------------------------------
 * Module glue
 * ---------------------------------------------------------------------- */

static int
vsock_modevent(module_t mod, int type, void *data)
{
	(void)mod;
	(void)data;

	switch (type) {
	case MOD_LOAD:
		vtvsock_cnt_tx_packets = counter_u64_alloc(M_WAITOK);
		vtvsock_cnt_tx_bytes = counter_u64_alloc(M_WAITOK);
		vtvsock_cnt_rx_packets = counter_u64_alloc(M_WAITOK);
		vtvsock_cnt_rx_bytes = counter_u64_alloc(M_WAITOK);
		vtvsock_cnt_rx_drops = counter_u64_alloc(M_WAITOK);
		vtvsock_cnt_conns = counter_u64_alloc(M_WAITOK);
		return (0);
	case MOD_UNLOAD:
		counter_u64_free(vtvsock_cnt_tx_packets);
		counter_u64_free(vtvsock_cnt_tx_bytes);
		counter_u64_free(vtvsock_cnt_rx_packets);
		counter_u64_free(vtvsock_cnt_rx_bytes);
		counter_u64_free(vtvsock_cnt_rx_drops);
		counter_u64_free(vtvsock_cnt_conns);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t vsock_mod = { "vsock", vsock_modevent, NULL };
DECLARE_MODULE(vsock, vsock_mod, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_VERSION(vsock, 1);
