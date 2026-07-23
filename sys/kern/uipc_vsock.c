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
#include <sys/conf.h>
#include <sys/counter.h>
#include <sys/domain.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/uio.h>
#include <sys/vsock.h>

#include <net/vnet.h>

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
/*
 * Metadata-only observability probes (FOI: no payload contents are ever
 * passed -- only header fields, lengths, credit counters, and error codes).
 */
SDT_PROBE_DEFINE3(vsock, , , connect__request,
    "uint64_t",	/* remote CID */
    "uint32_t",	/* remote port */
    "int");	/* is_local */
SDT_PROBE_DEFINE2(vsock, , , connect__timeout,
    "uint64_t",	/* remote CID */
    "uint32_t");	/* remote port */
SDT_PROBE_DEFINE6(vsock, , , pkt__rx,
    "uint16_t",	/* op */
    "uint64_t",	/* src CID */
    "uint32_t",	/* src port */
    "uint32_t",	/* dst port */
    "uint32_t",	/* payload len */
    "uint32_t");	/* flags */
SDT_PROBE_DEFINE5(vsock, , , pkt__drop,
    "const char *",	/* stable reason string; never packet data */
    "uint16_t",	/* op */
    "uint64_t",	/* src CID */
    "uint32_t",	/* src port */
    "uint32_t");	/* dst port */
SDT_PROBE_DEFINE4(vsock, , , rst__received,
    "uint64_t",	/* remote CID */
    "uint32_t",	/* remote port */
    "int",	/* previous state */
    "int");	/* teardown errno */
SDT_PROBE_DEFINE4(vsock, , , shutdown,
    "uint64_t",	/* remote CID */
    "uint32_t",	/* remote port */
    "uint32_t",	/* flags: RCV/SEND bits */
    "int");	/* is_send: 1 = we sent it, 0 = received */
SDT_PROBE_DEFINE4(vsock, , , credit__update__recv,
    "uint64_t",	/* remote CID */
    "uint32_t",	/* remote port */
    "uint32_t",	/* peer_buf_alloc */
    "uint32_t");	/* peer_fwd_cnt */

/* -----------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */

MALLOC_DEFINE(M_VTVSOCK, "vtvsock", "virtio vsock");

/*
 * The kernel-internal connection state enum is exported to userspace verbatim
 * in xvsock_pcb.xvp_state as the VSOCK_ST_* ABI values.  Lock the two together
 * at compile time so a reordering of enum vtvsock_state cannot silently change
 * what sockstat(1)/netstat(1) report.
 */
CTASSERT(VTVSOCK_CLOSED == VSOCK_ST_CLOSED);
CTASSERT(VTVSOCK_BOUND == VSOCK_ST_BOUND);
CTASSERT(VTVSOCK_LISTEN == VSOCK_ST_LISTEN);
CTASSERT(VTVSOCK_CONNECTING == VSOCK_ST_CONNECTING);
CTASSERT(VTVSOCK_ESTABLISHED == VSOCK_ST_ESTABLISHED);
CTASSERT(VTVSOCK_CLOSING == VSOCK_ST_CLOSING);

/* Global mutex: protects bound/connected lists and PCB state fields.
 * Lock ordering: vtvsock_mtx -> SOCK_RECVBUF_LOCK / SOCK_SENDBUF_LOCK.
 * Never acquire vtvsock_mtx while holding a socket buffer lock.         */
struct mtx vtvsock_mtx;
MTX_SYSINIT(vtvsock, &vtvsock_mtx, "vtvsock", MTX_DEF);

static LIST_HEAD(, vtvsock_pcb) vtvsock_bound =
    LIST_HEAD_INITIALIZER(vtvsock_bound);

/*
 * Connected PCBs live in a hash table keyed by the (local,remote) 4-tuple.
 * A malicious peer can drive one inbound packet per connection, and every
 * packet does a connected-PCB lookup under the global mutex; a flat list made
 * that O(N) and turned a large connection count into a CPU/lock DoS.  Hashing
 * keeps the hot vsock_rx_packet lookup near O(1).  A statically-initialized
 * array of LIST_HEADs is all-zero, i.e. an array of empty lists, so no runtime
 * init is needed.  vtvsock_conn_count bounds the total (see vtvsock_max_conn).
 */
#define	VTVSOCK_CONNHASH_SHIFT	8
#define	VTVSOCK_CONNHASH_SIZE	(1u << VTVSOCK_CONNHASH_SHIFT)
#define	VTVSOCK_CONNHASH_MASK	(VTVSOCK_CONNHASH_SIZE - 1)
static LIST_HEAD(, vtvsock_pcb) vtvsock_conn[VTVSOCK_CONNHASH_SIZE];
static u_int vtvsock_conn_count;
static u_int vtvsock_max_conn = VTVSOCK_DEFAULT_MAX_CONN;

static u_int
vtvsock_connhash(uint64_t lcid, uint32_t lport, uint64_t rcid, uint32_t rport)
{
	uint32_t h;

	h = (uint32_t)lcid ^ (uint32_t)(lcid >> 32);
	h ^= lport * 2654435761u;
	h ^= (uint32_t)rcid ^ (uint32_t)(rcid >> 32);
	h ^= rport * 2654435761u;
	h ^= h >> 16;
	return (h & VTVSOCK_CONNHASH_MASK);
}

uint64_t vtvsock_guest_cid = VSOCK_CID_LOCAL;

/* Remote transport, registered by virtio_vsock on attach. */
static const struct vtvsock_transport *vtvsock_remote_transport;
static const void *vtvsock_remote_transport_owner;
static uint64_t vtvsock_remote_features;

/* Tunable default buffer sizes for new sockets. */
static u_int vtvsock_buf_default = VTVSOCK_DEFAULT_BUF_ALLOC;
static u_int vtvsock_buf_min = VTVSOCK_DEFAULT_BUF_MIN;
static u_int vtvsock_buf_max = VTVSOCK_DEFAULT_BUF_MAX;
static u_int vtvsock_seqpacket_frag_max = VTVSOCK_DEFAULT_SEQPACKET_FRAG_MAX;

counter_u64_t vtvsock_cnt_tx_packets;
counter_u64_t vtvsock_cnt_tx_bytes;
counter_u64_t vtvsock_cnt_rx_packets;
counter_u64_t vtvsock_cnt_rx_bytes;
counter_u64_t vtvsock_cnt_rx_drops;
counter_u64_t vtvsock_cnt_conns;

static void
vtvsock_rx_drop(const char *reason __unused, uint16_t op __unused,
    uint64_t src_cid __unused, uint32_t src_port __unused,
    uint32_t dst_port __unused)
{
	counter_u64_add(vtvsock_cnt_rx_drops, 1);
	SDT_PROBE5(vsock, , , pkt__drop, reason, op, src_cid, src_port,
	    dst_port);
}

SYSCTL_NODE(_kern, OID_AUTO, vsock, CTLFLAG_RD, 0, "VSOCK");

SYSCTL_U64(_kern_vsock, OID_AUTO, guest_cid, CTLFLAG_RD,
    &vtvsock_guest_cid, 0, "VSOCK guest CID");
SYSCTL_UINT(_kern_vsock, OID_AUTO, cur_connections, CTLFLAG_RD,
    &vtvsock_conn_count, 0, "Current number of connected VSOCK PCBs");
SYSCTL_UINT(_kern_vsock, OID_AUTO, max_connections, CTLFLAG_RW | CTLFLAG_MPSAFE,
    &vtvsock_max_conn, 0, "Maximum simultaneously connected VSOCK PCBs");

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

	/* Walk the connected hash table. */
	for (u_int i = 0; error == 0 && i < VTVSOCK_CONNHASH_SIZE; i++) {
		LIST_FOREACH(pcb, &vtvsock_conn[i], connlink) {
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
static int	vsock_sosend(struct socket *, struct sockaddr *, struct uio *,
		    struct mbuf *, struct mbuf *, int, struct thread *);
static int	vsock_disconnect(struct socket *);
static int	vsock_shutdown(struct socket *, enum shutdown_how);
static void	vsock_abort(struct socket *);
static int	vsock_sopoll(struct socket *, int, struct thread *);
static int	vsock_kqfilter(struct socket *, struct knote *);
static int	vsock_control(struct socket *, unsigned long, void *,
		    struct ifnet *, struct thread *);

static struct vtvsock_pcb *vtvsock_pcb_alloc(struct socket *);
static void	vtvsock_pcb_free(struct vtvsock_pcb *);
static void	vtvsock_pcb_insert_bound_locked(struct vtvsock_pcb *);
static void	vtvsock_pcb_set_addr(struct sockaddr_vm *, uint64_t, uint32_t);
static void	vtvsock_pcb_insert_connected_locked(struct vtvsock_pcb *);
static void	vtvsock_pcb_remove_connected_locked(struct vtvsock_pcb *);
static uint32_t	vtvsock_credit_available(struct vtvsock_pcb *);
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
	.pr_sosend =	vsock_sosend,
	.pr_disconnect =	vsock_disconnect,
	.pr_close =	vsock_close,
	.pr_detach =	vsock_detach,
	.pr_shutdown =	vsock_shutdown,
	.pr_abort =	vsock_abort,
	.pr_sopoll =	vsock_sopoll,
	.pr_kqfilter =	vsock_kqfilter,
	.pr_control =	vsock_control,
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
	.pr_sosend =	vsock_sosend,
	.pr_disconnect =	vsock_disconnect,
	.pr_close =	vsock_close,
	.pr_detach =	vsock_detach,
	.pr_shutdown =	vsock_shutdown,
	.pr_abort =	vsock_abort,
	.pr_sopoll =	vsock_sopoll,
	.pr_kqfilter =	vsock_kqfilter,
	.pr_control =	vsock_control,
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

static void
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

/*
 * Validate the caller-controlled svm_flags and svm_zero padding of a
 * sockaddr_vm passed to bind()/connect().  Reject unknown flag bits and any
 * non-zero padding so those bytes remain available for future ABI use and a
 * ported Linux program that sets an unsupported flag fails loudly (EINVAL)
 * rather than getting silently different semantics.  VMADDR_FLAG_TO_HOST is
 * accepted as a no-op on this single-transport system.
 */
static int
vtvsock_validate_addr_flags(const struct sockaddr_vm *svm)
{
	if ((svm->svm_flags & ~VMADDR_FLAG_ALL) != 0)
		return (EINVAL);
	if (svm->svm_zero[0] != 0 || svm->svm_zero[1] != 0 ||
	    svm->svm_zero[2] != 0)
		return (EINVAL);
	return (0);
}

/* -----------------------------------------------------------------------
 * PCB lifecycle
 * ---------------------------------------------------------------------- */

static struct vtvsock_pcb *
vtvsock_pcb_alloc(struct socket *so)
{
	struct vtvsock_pcb *pcb;

	/*
	 * M_NOWAIT, not M_WAITOK: vsock_attach() (our pr_attach) runs via
	 * sonewconn() in the inbound-connection path while vtvsock_mtx is held,
	 * and sleeping under that mutex is illegal.  soalloc() in sonewconn() is
	 * likewise M_NOWAIT, so this is the only allocation on that path that
	 * could sleep.  Callers must handle a NULL return.
	 */
	pcb = malloc(sizeof(*pcb), M_VTVSOCK, M_NOWAIT | M_ZERO);
	if (pcb == NULL)
		return (NULL);
	pcb->so = so;
	pcb->transport = &vtvsock_local_transport;
	knlist_init_mtx(&pcb->tx_knlist, &vtvsock_mtx);
	vtvsock_pcb_set_addr(&pcb->local, VSOCK_CID_ANY, VSOCK_PORT_ANY);
	vtvsock_pcb_set_addr(&pcb->remote, VSOCK_CID_ANY, VSOCK_PORT_ANY);
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
	knlist_destroy(&pcb->tx_knlist);
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
	vtvsock_pcb_remove_connected_locked(pcb);
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
static void
vtvsock_pcb_insert_connected_locked(struct vtvsock_pcb *pcb)
{
	u_int idx;

	if (pcb->on_connlist)
		return;
	idx = vtvsock_connhash(pcb->local.svm_cid, pcb->local.svm_port,
	    pcb->remote.svm_cid, pcb->remote.svm_port);
	LIST_INSERT_HEAD(&vtvsock_conn[idx], pcb, connlink);
	pcb->on_connlist = true;
	vtvsock_conn_count++;
}

/* Must be called with vtvsock_mtx held. */
static void
vtvsock_pcb_remove_connected_locked(struct vtvsock_pcb *pcb)
{
	if (!pcb->on_connlist)
		return;
	LIST_REMOVE(pcb, connlink);
	pcb->on_connlist = false;
	KASSERT(vtvsock_conn_count > 0,
	    ("%s: connected count underflow", __func__));
	vtvsock_conn_count--;
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
	u_int idx;

	idx = vtvsock_connhash(dst_cid, dst_port, src_cid, src_port);
	LIST_FOREACH(pcb, &vtvsock_conn[idx], connlink) {
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
static uint32_t
vtvsock_credit_available(struct vtvsock_pcb *pcb)
{
	uint32_t used;

	/*
	 * Spec 5.10.6.3: peer_free = peer_buf_alloc - (tx_cnt - peer_fwd_cnt).
	 * Compute entirely in uint32_t, matching the bhyve host side
	 * (vtvsock_peer_credit).  tx_cnt and peer_fwd_cnt are free-running
	 * counters, so their unsigned difference (bytes in flight) is correct
	 * across wraparound; the previous int32_t cast treated any window
	 * >= 2GiB as negative and starved connections whose peer advertised a
	 * buf_alloc above 0x7fffffff.
	 */
	used = pcb->tx_cnt - pcb->peer_fwd_cnt;
	if (used >= pcb->peer_buf_alloc)
		return (0);
	return (pcb->peer_buf_alloc - used);
}

/*
 * Bytes the transport can accept for this connection right now, i.e. how
 * much a sender may copy in without risking a transient failure after the
 * data has left the caller's uio.  Loopback: free space in the peer's
 * receive buffer.  Remote: available send credit.  vtvsock_mtx held.
 */
static size_t
vtvsock_tx_space(struct vtvsock_pcb *pcb)
{
	struct socket *peer_so;
	long space;

	mtx_assert(&vtvsock_mtx, MA_OWNED);

	if (pcb->transport == &vtvsock_local_transport) {
		if (pcb->peer == NULL || (peer_so = pcb->peer->so) == NULL)
			return (0);
		space = sbspace(&peer_so->so_rcv);
		return (space > 0 ? (size_t)space : 0);
	}
	return (vtvsock_credit_available(pcb));
}

/*
 * Consume up to 'wanted' bytes of send credit; return amount granted.
 * Must be called with vtvsock_mtx held (or otherwise serialized).
 */
uint32_t
vtvsock_get_credit(struct vtvsock_pcb *pcb, uint32_t wanted)
{
	uint32_t avail, got;

	avail = vtvsock_credit_available(pcb);
	if (avail == 0)
		return (0);
	got = MIN(wanted, avail);
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

	/*
	 * Fire for a graceful close that stalled (CLOSING) and for a connection
	 * the peer fully shut down while our RX queue was non-empty (still
	 * ESTABLISHED, deferred teardown) where the local app never drained.
	 * Both cases RST and reclaim the PCB.
	 */
	if (vtvsock_remote_transport != NULL &&
	    (pcb->state == VTVSOCK_CLOSING ||
	     (pcb->state == VTVSOCK_ESTABLISHED &&
	      pcb->peer_shutdown == (VIRTIO_VSOCK_SHUTDOWN_RCV |
	      VIRTIO_VSOCK_SHUTDOWN_SEND)))) {
		/*
		 * send_pkt, not send_rst: the PCB is live here, so the RST
		 * can carry our real buf_alloc/fwd_cnt as §5.10.6.3.1
		 * requires of every packet on a stream flow.
		 */
		(void)vtvsock_remote_transport->send_pkt(pcb,
		    VIRTIO_VSOCK_OP_RST, 0, NULL, 0);
	}
	pcb->state = VTVSOCK_CLOSED;
	vtvsock_pcb_remove_lists_locked(pcb);
	vsock_tx_wakeup_locked(pcb);
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
		SDT_PROBE2(vsock, , , connect__timeout,
		    pcb->remote.svm_cid, pcb->remote.svm_port);
		pcb->state = VTVSOCK_CLOSED;
		vtvsock_pcb_remove_lists_locked(pcb);
		vsock_tx_wakeup_locked(pcb);
		SOCK_LOCK(so);
		so->so_error = ETIMEDOUT;
		SOCK_UNLOCK(so);
		/*
		 * Clear SS_ISCONNECTING so the fd does not stay wedged in
		 * EALREADY.  For a non-blocking connect() (already returned
		 * EINPROGRESS, not sleeping) this is what completes the attempt;
		 * the wakeup below covers a blocking connect() still in msleep.
		 * soisdisconnected() leaves so_error intact.
		 */
		soisdisconnected(so);
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

/*
 * Derive the buf_alloc advertised to the peer from a socket's real receive
 * high-water mark, so the credit window tracks actual buffer capacity
 * (honoring any SO_RCVBUF / listener sizing) rather than a static default.
 * Clamp to INT32_MAX so the peer_free window math (peer_buf_alloc - in_flight)
 * stays within a signed 32-bit range on both this side and the peer.
 */
static uint32_t
vtvsock_buf_alloc_from_so(struct socket *so)
{
	u_long hiwat = so->so_rcv.sb_hiwat;

	if (hiwat > INT32_MAX)
		hiwat = INT32_MAX;
	return ((uint32_t)hiwat);
}

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
	 * permitted when no remote transport is registered.  Key the gate on
	 * transport presence, not features != 0: a legacy host that
	 * negotiates zero feature bits still registers a transport (STREAM
	 * implied) and must not admit SEQPACKET sockets that can only fail
	 * later at connect.
	 *
	 * STREAM is supported unless the device negotiated
	 * F_NO_IMPLIED_STREAM without F_STREAM (virtio 1.4 §5.10.3: with no
	 * bits negotiated, or SEQPACKET alone, stream is implied).
	 *
	 * These fields are read without vtvsock_mtx: attach also runs via
	 * sonewconn() on the RX path with the mutex already held, so it must
	 * not lock.  The unlocked read only races module load/unload of the
	 * transport, and either ordering is acceptable.
	 */
	if (so->so_type == SOCK_SEQPACKET) {
		if (vtvsock_remote_transport != NULL &&
		    !(vtvsock_remote_features & VIRTIO_VSOCK_F_SEQPACKET))
			return (EPROTONOSUPPORT);
	} else {
		if (vtvsock_remote_transport != NULL &&
		    (vtvsock_remote_features &
		    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM) != 0 &&
		    (vtvsock_remote_features & VIRTIO_VSOCK_F_STREAM) == 0)
			return (EPROTONOSUPPORT);
	}

	pcb = vtvsock_pcb_alloc(so);
	if (pcb == NULL)
		return (ENOBUFS);
	so->so_pcb = pcb;
	/*
	 * A socket created via socket(2) arrives with unset buffers and we size
	 * them here.  A socket created via accept(2) has already had its buffers
	 * reserved from the listener by the accept shim (soattach()), sized from
	 * whatever SO_RCVBUF the listener configured; preserve that instead of
	 * clobbering it back to the global default.  This also keeps the reserve
	 * (and its RLIMIT_SBSIZE accounting) out of the RX/interrupt thread that
	 * drives accept on the virtio path.
	 */
	if (so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, vtvsock_buf_default, vtvsock_buf_default);
		if (error != 0) {
			so->so_pcb = NULL;
			vtvsock_pcb_free(pcb);
			return (error);
		}
	}
	pcb->buf_alloc = vtvsock_buf_alloc_from_so(so);
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
	/*
	 * Tear down transport-locked write knotes before publishing pcb->so ==
	 * NULL or freeing the PCB.  knlist_clear() may temporarily drop and
	 * reacquire vtvsock_mtx while waiting for an active callback.
	 */
	knlist_clear(&pcb->tx_knlist, 1);
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

	if (pcb == NULL || svm == NULL)
		return (EINVAL);
	if (svm->svm_family != AF_VSOCK ||
	    svm->svm_len != sizeof(*svm))
		return (EINVAL);
	if (svm->svm_reserved1 != 0)
		return (EINVAL);
	if (vtvsock_validate_addr_flags(svm) != 0)
		return (EINVAL);

	/*
	 * HYPERVISOR (0) can never name a local endpoint.  HOST (2) is bindable
	 * only when a host-side userspace transport registered it as our local
	 * CID.  ANY (0xffffffff) is the "any local CID" wildcard, remapped to
	 * our local CID below.  LOCAL (1) is always bindable and denotes a
	 * loopback-only endpoint, matching Linux (a listener bound to
	 * VMADDR_CID_LOCAL is reachable only via loopback connects to CID 1,
	 * never from the remote transport).  Guest-side transports sanitize
	 * HOST before registration.
	 */
	if (svm->svm_cid == VSOCK_CID_HYPERVISOR)
		return (EINVAL);
	if (svm->svm_cid == VSOCK_CID_HOST &&
	    vtvsock_guest_cid != VSOCK_CID_HOST)
		return (EADDRNOTAVAIL);

	/*
	 * Binding an explicit port below 1024 (including literal port 0)
	 * requires privilege, matching the reserved-port convention and
	 * Linux's CAP_NET_BIND_SERVICE gate for vsock.  Auto-bind
	 * (VSOCK_PORT_ANY) always uses >= 1024.
	 */
	if (svm->svm_port != VSOCK_PORT_ANY &&
	    svm->svm_port < 1024 && td != NULL) {
		int error = priv_check(td, PRIV_NETINET_RESERVEDPORT);
		if (error != 0)
			return (error);
	}

	/*
	 * VSOCK_CID_ANY (== Linux VMADDR_CID_ANY, 0xffffffff) means "any local
	 * CID": bind it to our actual guest CID.  0xffffffff is a reserved CID
	 * that can never be a real address, so the overload is unambiguous.
	 * Note bound_local is keyed on the caller's explicit CID before the
	 * remap: in loopback-only mode (guest_cid == LOCAL) an ANY bind also
	 * lands on CID 1 but is NOT loopback-pinned -- it migrates to the
	 * real guest CID when a transport registers.
	 */
	bool bound_local = (svm->svm_cid == VSOCK_CID_LOCAL);
	if (svm->svm_cid == VSOCK_CID_ANY)
		svm->svm_cid = (uint32_t)vtvsock_guest_cid;
	if (svm->svm_cid != vtvsock_guest_cid &&
	    svm->svm_cid != VSOCK_CID_LOCAL)
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
	/*
	 * Only VSOCK_PORT_ANY requests auto-assignment; literal port 0 is a
	 * valid (privileged) port, as on Linux.
	 */
	if (svm->svm_port == VSOCK_PORT_ANY) {
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
	pcb->bound_local = bound_local;
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

	/*
	 * Lock order is vtvsock_mtx -> socket locks everywhere else (the RX
	 * delivery path holds vtvsock_mtx across soisconnected()/sonewconn()/
	 * sbappend*).  Take vtvsock_mtx OUTER here too -- the previous
	 * SOCK_LOCK -> vtvsock_mtx nesting was a lock-order reversal.  Holding
	 * vtvsock_mtx across the state change and solisten_proto() also makes
	 * them atomic against a concurrent inbound OP_REQUEST.
	 */
	mtx_lock(&vtvsock_mtx);
	SOCK_LOCK(so);
	error = solisten_proto_check(so);
	if (error != 0) {
		SOCK_UNLOCK(so);
		mtx_unlock(&vtvsock_mtx);
		return (error);
	}
	pcb->state = VTVSOCK_LISTEN;
	solisten_proto(so, backlog);	/* sets SO_ACCEPTCONN; SOCK_LOCK stays held */
	SOCK_UNLOCK(so);
	mtx_unlock(&vtvsock_mtx);
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
	bool did_connecting;
	int error;

	(void)td;

	if (pcb == NULL || dst == NULL)
		return (EINVAL);
	if (dst->svm_family != AF_VSOCK ||
	    dst->svm_len != sizeof(*dst))
		return (EINVAL);
	if (dst->svm_reserved1 != 0)
		return (EINVAL);
	if (vtvsock_validate_addr_flags(dst) != 0)
		return (EINVAL);

	mtx_lock(&vtvsock_mtx);

	/* Reject connect on listening sockets. */
	if (pcb->state == VTVSOCK_LISTEN) {
		mtx_unlock(&vtvsock_mtx);
		return (EOPNOTSUPP);
	}

	if (pcb->state == VTVSOCK_ESTABLISHED) {
		mtx_unlock(&vtvsock_mtx);
		return (EISCONN);
	}
	if (pcb->state == VTVSOCK_CONNECTING) {
		/*
		 * A connect already in flight: EALREADY, not EISCONN, matching
		 * Linux vsock_connect (SS_CONNECTING -> -EALREADY).  On the
		 * normal syscall path kern_connectat() already intercepts
		 * SS_ISCONNECTING with EALREADY before reaching here; this
		 * keeps direct pr_connect callers consistent too.
		 */
		mtx_unlock(&vtvsock_mtx);
		return (EALREADY);
	}
	if (pcb->state == VTVSOCK_CLOSING) {
		mtx_unlock(&vtvsock_mtx);
		return (ECONNRESET);
	}

	/* Assign a local port if not already bound. */
	auto_bound = false;
	did_connecting = false;
	if (pcb->local.svm_port == VSOCK_PORT_ANY) {
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
		 * Lookup CID matching (mirrors Linux vsock_find_bound_socket
		 * as closely as the CID_ANY->guest_cid bind remap allows):
		 * a connect to VSOCK_CID_LOCAL (1) prefers a loopback-pinned
		 * listener bound explicitly to CID 1, then falls back to the
		 * guest CID (which is where CID_ANY binds are stored).  A
		 * connect to the guest's own CID matches only guest-CID
		 * listeners -- loopback-pinned listeners are not reachable
		 * through it, nor from the remote transport.
		 */
		listener = NULL;
		if (dst->svm_cid == VSOCK_CID_LOCAL)
			listener = vtvsock_pcb_lookup_bound_locked(
			    VSOCK_CID_LOCAL, dst->svm_port);
		if (listener == NULL)
			listener = vtvsock_pcb_lookup_bound_locked(
			    vtvsock_guest_cid, dst->svm_port);
		if (listener == NULL || listener->state != VTVSOCK_LISTEN ||
		    listener->so->so_type != so->so_type) {
			SDT_PROBE2(vsock, , , connect__refused,
			    dst->svm_cid, dst->svm_port);
			/*
			 * Report ECONNRESET, not the POSIX ECONNREFUSED: Linux
			 * vsock refuses a connection (including over its loopback
			 * transport) by RST, which surfaces to connect(2) as
			 * ECONNRESET.  We match that uniformly across loopback and
			 * the remote virtio path (see the OP_RST handler) so ported
			 * applications see one consistent errno.
			 */
			error = ECONNRESET;
			goto fail;
		}

		/*
		 * sonewconn() -> soattach() asserts curvnet == the child's
		 * so_vnet (inherited from the listener).  The caller's vnet
		 * context is not guaranteed to match the listener's (and the
		 * transport RX path has none at all), so establish it here.
		 */
		CURVNET_SET(listener->so->so_vnet);
		child_so = sonewconn(listener->so, 0);
		CURVNET_RESTORE();
		if (child_so == NULL) {
			/* Backlog full / insufficient resources: RST on Linux
			 * (§5.10.6.5) -> ECONNRESET, as above. */
			error = ECONNRESET;
			goto fail;
		}
		child = child_so->so_pcb;
		child->local = listener->local;
		child->remote = pcb->local;
		child->peer = pcb;
		child->state = VTVSOCK_ESTABLISHED;
		child->transport = &vtvsock_local_transport;
		/* Advertise the child's real receive capacity, not the default. */
		child->buf_alloc = vtvsock_buf_alloc_from_so(child_so);
		child->peer_buf_alloc = pcb->buf_alloc;
		vtvsock_pcb_insert_connected_locked(child);

		pcb->peer = child;
		pcb->state = VTVSOCK_ESTABLISHED;
		pcb->transport = &vtvsock_local_transport;
		pcb->peer_buf_alloc = child->buf_alloc;
		vtvsock_pcb_insert_connected_locked(pcb);

		soisconnected(so);
		soisconnected(child_so);
		vsock_tx_wakeup_locked(pcb);
		vsock_tx_wakeup_locked(child);
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
	 * A socket explicitly bound to VSOCK_CID_LOCAL is loopback-only: its
	 * bound CID cannot go on the wire as the source (§5.10.6.4.1 requires
	 * guest_cid there).
	 */
	if (pcb->bound_local && pcb->local.svm_cid != vtvsock_guest_cid) {
		error = EADDRNOTAVAIL;
		goto fail;
	}

	/*
	 * svm_cid is a 32-bit field (as on Linux), so the CID can never exceed
	 * what the wire protocol and current hypervisors accept -- no oversize
	 * check is needed here.
	 */
	pcb->state = VTVSOCK_CONNECTING;
	pcb->transport = vtvsock_remote_transport;
	vtvsock_pcb_insert_connected_locked(pcb);
	soisconnecting(so);
	did_connecting = true;

	SDT_PROBE3(vsock, , , connect__request, dst->svm_cid, dst->svm_port, 0);
	error = vtvsock_remote_transport->send_pkt(pcb,
	    VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
	if (error != 0)
		goto fail;

	/* Arm connect timeout. */
	callout_reset(&pcb->connect_callout,
	    pcb->connect_timeout > 0 ? pcb->connect_timeout :
	    VTVSOCK_CONNECT_TIMEOUT,
	    vtvsock_connect_timeout, pcb);

	/*
	 * Non-blocking connect: leave the OP_REQUEST in flight and the
	 * connect-timeout callout armed, then return EINPROGRESS immediately.
	 * SS_ISCONNECTING stays set (so kern_connectat() reports EINPROGRESS);
	 * the RX path (OP_RESPONSE/OP_RST) and the timeout callout drive
	 * soisconnected()/soisdisconnected() asynchronously.  Loopback connects
	 * completed synchronously above and never reach here.
	 */
	if (so->so_state & SS_NBIO) {
		mtx_unlock(&vtvsock_mtx);
		return (EINPROGRESS);
	}

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
		/*
		 * Remote connect ended without establishing.  Prefer the async
		 * error the RX/timeout path recorded (ECONNRESET from a peer RST,
		 * ETIMEDOUT from the connect callout); default to ECONNRESET to
		 * match Linux vsock, whose only non-timeout connect failure is an
		 * RST.  (Loopback refusals also return ECONNRESET, synchronously
		 * above, and never reach here.)
		 */
		error = so->so_error != 0 ? so->so_error : ECONNRESET;
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
		vtvsock_pcb_remove_connected_locked(pcb);
		if (pcb->peer != NULL) {
			pcb->peer->peer = NULL;
			pcb->peer = NULL;
		}
		pcb->state = VTVSOCK_BOUND;
	}
	vsock_tx_wakeup_locked(pcb);
	/*
	 * If we advanced to CONNECTING (soisconnecting()), clear SS_ISCONNECTING
	 * on every failure path -- send_pkt error, EINTR/signal from msleep, and
	 * the error==0/!ESTABLISHED fallback (connect timeout or peer RST) --
	 * mirroring the RST teardown path.  Otherwise the fd would be stuck
	 * returning EALREADY forever.  Loopback ECONNRESET/ENXIO failures never
	 * called soisconnecting(), so they must not be marked disconnected.
	 */
	/*
	 * Clear SS_ISCONNECTING on failure so the fd isn't wedged in EALREADY.
	 * If the async path (RST teardown in vsock_rx_packet, or the connect
	 * timeout callout) already disconnected the socket, SS_ISCONNECTING is
	 * already clear -- skip the redundant second soisdisconnected() call.
	 * Only the synchronous failures (send_pkt error, EINTR from msleep)
	 * still have it set and need the call.
	 */
	if (did_connecting) {
		bool need_disc;

		SOCK_LOCK(so);
		need_disc = (so->so_state & SS_ISCONNECTING) != 0;
		SOCK_UNLOCK(so);
		if (need_disc)
			soisdisconnected(so);
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

	/*
	 * Accept both SOL_VSOCK and AF_VSOCK as the option level.  Linux
	 * applies the SO_VM_SOCKETS_* options at level AF_VSOCK, so code
	 * ported from Linux passes AF_VSOCK here.
	 */
	if (sopt->sopt_level != SOL_VSOCK && sopt->sopt_level != AF_VSOCK)
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
			/*
			 * The SO_RCVBUF set above re-enters vsock_setsbopt,
			 * which ties buf_alloc to the new receive buffer
			 * (grow-only on an established connection, so a shrink
			 * can't trip the peer's cumulative-overflow guard) and
			 * advertises the change to the peer with a single
			 * CREDIT_UPDATE.  Do not duplicate that here.
			 */
			return (0);
		}
		/*
		 * On a listening socket the sockbufs are overlaid by the
		 * listen-queue union; the buffer sizes live in sol_sbrcv_hiwat
		 * (same rule as sogetopt's SO_RCVBUF).
		 */
		val64 = SOLISTENING(so) ? so->sol_sbrcv_hiwat :
		    so->so_rcv.sb_hiwat;
		return (sooptcopyout(sopt, &val64, sizeof(val64)));

	case SO_VM_SOCKETS_BUFFER_MIN_SIZE:
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &val64, sizeof(val64),
			    sizeof(val64));
			if (error != 0)
				return (error);
			/* Clamp to a sane range (buf_alloc is a uint32_t
			 * capped at INT_MAX by BUFFER_SIZE). */
			if (val64 > (uint64_t)__INT_MAX)
				val64 = __INT_MAX;
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
			if (val64 > (uint64_t)__INT_MAX)
				val64 = __INT_MAX;
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
	case SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW: {
		struct timeval tv;
		int ticks;

		/*
		 * Both option numbers take a struct timeval only, matching
		 * Linux (opt 8 is the 64-bit-time variant).  A buffer smaller
		 * than a timeval is rejected with EINVAL.
		 */
		if (sopt->sopt_dir == SOPT_SET) {
			error = sooptcopyin(sopt, &tv, sizeof(tv),
			    sizeof(tv));
			if (error != 0)
				return (error);
			/*
			 * Reject a malformed or out-of-range timeval with
			 * ERANGE, matching Linux (which returns -ERANGE here);
			 * a ported program checking the timeout errno sees the
			 * same value.
			 */
			if (tv.tv_sec < 0 || tv.tv_usec < 0 ||
			    tv.tv_usec >= 1000000)
				return (ERANGE);
			pcb->connect_timeout =
			    (tv.tv_sec == 0 && tv.tv_usec == 0) ?
			    0 : tvtohz(&tv);
			return (0);
		}
		/* GET: always a struct timeval. */
		ticks = pcb->connect_timeout > 0 ? pcb->connect_timeout :
		    VTVSOCK_CONNECT_TIMEOUT;
		tv.tv_sec = ticks / hz;
		/* Widen before the multiply: (ticks % hz) * 1000000 overflows
		 * a 32-bit int once hz > 2147. */
		tv.tv_usec = (suseconds_t)((int64_t)(ticks % hz) * 1000000 / hz);
		return (sooptcopyout(sopt, &tv, sizeof(tv)));
	}

	case SO_VM_SOCKETS_TRUSTED:
	case SO_VM_SOCKETS_NONBLOCK_TXRX:
		/*
		 * VMCI-transport-specific options with no virtio-vsock
		 * equivalent.  Recognized (so ported Linux code compiles and
		 * gets a clean errno) but not supported.
		 */
		return (EOPNOTSUPP);

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

	if (sopt->sopt_dir != SOPT_SET)
		return (0);

	pcb = so->so_pcb;
	if (pcb == NULL)
		return (0);

	if (sopt->sopt_name == SO_RCVBUF) {
		/*
		 * A raw SO_RCVBUF changed the real receive buffer; keep the
		 * advertised credit window (buf_alloc) tied to it, otherwise
		 * the peer's view of our free space diverges from reality.
		 * Grow-only on an established connection (see BUFFER_SIZE) so
		 * a shrink can't trip the peer's cumulative-overflow guard.
		 */
		uint32_t nbuf;

		SOCK_RECVBUF_LOCK(so);
		nbuf = (uint32_t)MIN((uint64_t)so->so_rcv.sb_hiwat,
		    (uint64_t)__INT_MAX);
		SOCK_RECVBUF_UNLOCK(so);
		mtx_lock(&vtvsock_mtx);
		if (pcb->state == VTVSOCK_ESTABLISHED) {
			if (nbuf > pcb->buf_alloc) {
				pcb->buf_alloc = nbuf;
				if (pcb->transport != &vtvsock_local_transport &&
				    vtvsock_remote_transport != NULL)
					vtvsock_remote_transport->
					    send_credit_update(pcb);
			}
		} else
			pcb->buf_alloc = nbuf;
		mtx_unlock(&vtvsock_mtx);
	} else if (sopt->sopt_name == SO_RCVLOWAT) {
		uint32_t lowat;

		SOCK_RECVBUF_LOCK(so);
		lowat = (uint32_t)so->so_rcv.sb_lowat;
		SOCK_RECVBUF_UNLOCK(so);
		mtx_lock(&vtvsock_mtx);
		if (pcb->state == VTVSOCK_ESTABLISHED &&
		    pcb->transport != &vtvsock_local_transport &&
		    vtvsock_remote_transport != NULL &&
		    pcb->rx_bytes < lowat)
			vtvsock_remote_transport->send_credit_update(pcb);
		mtx_unlock(&vtvsock_mtx);
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
	uint32_t before, after, occupancy, consumed;
	uint32_t unreported, credit_thresh, lowat;
	size_t partial_len;
	bool is_local;
	int error;

	if (psa != NULL)
		*psa = NULL;
	if (mp0 != NULL)
		*mp0 = NULL;
	if (controlp != NULL)
		*controlp = NULL;

	/*
	 * Snapshot buffer occupancy before the (possibly blocking) receive.
	 * Only the local-loopback wakeup path below consumes this before/after
	 * delta (local sockets do not maintain rx_bytes); the remote credit
	 * path derives consumed from rx_bytes instead, to stay race-free
	 * against a concurrent RX enqueue during the receive.
	 */
	SOCK_RECVBUF_LOCK(so);
	before = (uint32_t)sbavail(&so->so_rcv);
	SOCK_RECVBUF_UNLOCK(so);

	/*
	 * SEQPACKET uses soreceive_generic(), not soreceive_dgram():
	 * our protosw is PR_ATOMIC | PR_CONNREQUIRED, and soreceive_dgram()
	 * asserts !PR_CONNREQUIRED (panic on INVARIANTS) and strips MSG_EOR.
	 * soreceive_generic() honors PR_ATOMIC record boundaries and
	 * propagates M_EOR -> MSG_EOR and MSG_TRUNC, as AF_UNIX SOCK_SEQPACKET
	 * does.
	 */
	error = (so->so_type == SOCK_SEQPACKET ?
	    soreceive_generic(so, psa, uio, mp0, controlp, flagsp) :
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
		lowat = (uint32_t)so->so_rcv.sb_lowat;
		SOCK_RECVBUF_UNLOCK(so);

		/*
		 * Compute how many bytes this recv removed from our receive
		 * buffer, race-free.  rx_bytes is the authoritative occupancy
		 * counter, maintained under vtvsock_mtx as packets are
		 * enqueued; for SEQPACKET it also counts bytes still held in an
		 * incomplete reassembly (seqpacket_partial) that have not yet
		 * reached the socket buffer.  So the bytes currently sitting in
		 * the socket buffer are (rx_bytes - partial_len), and the amount
		 * this recv drained is that minus the post-recv sbavail.
		 *
		 * Deriving consumed from the counters -- rather than a
		 * before/after sbavail delta straddling the (blocking)
		 * soreceive -- avoids under-counting when the RX handler appends
		 * concurrently during the receive.  Such an under-count is not
		 * self-correcting: it permanently deflates fwd_cnt (shrinking the
		 * peer's send window until it stalls) and inflates rx_bytes
		 * (eventually tripping the cumulative-overflow RST on a healthy
		 * connection).  This form is still correct under MSG_PEEK (sbavail
		 * unchanged -> consumed 0) and for a truncated SEQPACKET record
		 * (the whole record leaves the buffer).  We hold vtvsock_mtx, so
		 * rx_bytes and seqpacket_partial are stable against the RX path.
		 */
		partial_len = (pcb->seqpacket_partial != NULL) ?
		    m_length(pcb->seqpacket_partial, NULL) : 0;
		occupancy = (pcb->rx_bytes > (uint32_t)partial_len) ?
		    pcb->rx_bytes - (uint32_t)partial_len : 0;
		consumed = (occupancy > after) ? (occupancy - after) : 0;

		if (consumed > 0) {
			SDT_PROBE2(vsock, , , receive,
			    (size_t)consumed,
			    so->so_type == SOCK_SEQPACKET);
			if (pcb->rx_bytes >= consumed)
				pcb->rx_bytes -= consumed;
			else
				pcb->rx_bytes = 0;
			pcb->fwd_cnt += consumed;

			/*
			 * Return credit eagerly: once we have consumed at least
			 * our trigger threshold since the last update, or rx_bytes
			 * has drained below the low-water mark, send an update.
			 * The threshold is min(buf_alloc/2, 64KB): buf_alloc/2
			 * keeps small buffers from stalling the sender until the
			 * receive buffer fully drains, and the fixed cap reuses
			 * Linux's VIRTIO_VSOCK_MAX_PKT_BUF_SIZE (64KB) value so a
			 * large window returns credit after ~64KB of headroom.
			 *
			 * Note this is deliberately MORE eager than Linux, which
			 * triggers on free_space < 64KB (i.e. after consuming
			 * buf_alloc-64KB): ours favors fewer sender stalls at the
			 * cost of a few more CREDIT_UPDATE packets.  Both also fire
			 * on the low-water condition.  It is not a strict port of
			 * Linux's formula.
			 */
			credit_thresh = pcb->buf_alloc / 2;
			if (credit_thresh > VTVSOCK_MAX_PKT_BUF)
				credit_thresh = VTVSOCK_MAX_PKT_BUF;
			unreported = pcb->fwd_cnt - pcb->last_fwd_cnt;
			if (unreported >= credit_thresh ||
			    pcb->rx_bytes < lowat)
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
				/* App drained in time; cancel the close timer. */
				callout_stop(&pcb->close_callout);
				vtvsock_pcb_remove_lists_locked(pcb);
				vsock_tx_wakeup_locked(pcb);
				/*
				 * send_pkt, not send_rst: the PCB is live, so
				 * the RST carries real credit fields per
				 * §5.10.6.3.1.
				 */
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->
					    send_pkt(pcb,
					    VIRTIO_VSOCK_OP_RST, 0, NULL, 0);
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
			if (pcb != NULL && pcb->peer != NULL) {
				/* Re-arm blocking, poll/select, and kqueue writers. */
				vsock_tx_wakeup_locked(pcb->peer);
			}
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
	/*
	 * virtio-vsock has no out-of-band channel.  Reject MSG_OOB with
	 * EOPNOTSUPP (matching Linux) rather than silently sending it as
	 * ordinary in-band data.
	 */
	if (flags & PRUS_OOB) {
		m_freem(m);
		if (control != NULL)
			m_freem(control);
		return (EOPNOTSUPP);
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

/*
 * Custom poll: vsock hands data straight to the transport in pr_send and
 * never fills so_snd, so sopoll_generic() always reports the socket
 * writable.  For a connected remote socket, mask POLLOUT off when the peer's
 * advertised send window (credit) is exhausted, so poll/select/kqueue do not
 * spuriously report writability and make userspace busy-spin on a send() that
 * would block.  A later CREDIT_UPDATE calls sowwakeup(), re-running the poll.
 * Matches Linux vsock_poll()'s use of vsock_stream_has_space().  POLLIN is
 * left to the generic path (so_rcv reflects deliverable data correctly, and
 * SEQPACKET partials stay invisible until EOM).
 */
static int
vsock_sopoll(struct socket *so, int events, struct thread *td)
{
	struct vtvsock_pcb *pcb;
	bool blocked;
	int revents;

	revents = sopoll_generic(so, events, td);

	if ((revents & (POLLOUT | POLLWRNORM)) != 0) {
		blocked = false;
		mtx_lock(&vtvsock_mtx);
		pcb = so->so_pcb;
		if (pcb != NULL &&
		    pcb->state == VTVSOCK_ESTABLISHED &&
		    (vtvsock_tx_space(pcb) == 0 ||
		    (pcb->transport->tx_ready != NULL &&
		    !pcb->transport->tx_ready(pcb)))) {
			/*
			 * sopoll_generic() considered the empty protocol send buffer
			 * writable, so it did not register this waiter.  Register while
			 * holding vtvsock_mtx, the same lock transports hold when they
			 * transition back to ready and call
			 * vsock_transport_tx_wakeup_locked().  This closes the
			 * ready-before-selrecord lost-wakeup window.
			 */
			SOCK_LOCK(so);
			SOCK_SENDBUF_LOCK(so);
			selrecord(td, &so->so_wrsel);
			so->so_snd.sb_flags |= SB_SEL;
			SOCK_SENDBUF_UNLOCK(so);
			SOCK_UNLOCK(so);
			blocked = true;
		}
		if (blocked)
			revents &= ~(POLLOUT | POLLWRNORM);
		mtx_unlock(&vtvsock_mtx);
	}
	return (revents);
}

static void
vsock_filt_sowdetach(struct knote *kn)
{
	struct vtvsock_pcb *pcb = kn->kn_hook;

	mtx_lock(&vtvsock_mtx);
	knlist_remove(&pcb->tx_knlist, kn, 1);
	mtx_unlock(&vtvsock_mtx);
}

static int
vsock_filt_sowrite(struct knote *kn, long hint __unused)
{
	struct vtvsock_pcb *pcb = kn->kn_hook;
	size_t space;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	kn->kn_data = 0;
	if (pcb->state == VTVSOCK_CLOSED ||
	    pcb->state == VTVSOCK_CLOSING) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	if (pcb->state != VTVSOCK_ESTABLISHED ||
	    pcb->so == NULL)
		return (0);
	space = vtvsock_tx_space(pcb);
	kn->kn_data = MIN(space, (size_t)INT64_MAX);
	if (space == 0 ||
	    (pcb->transport->tx_ready != NULL &&
	    !pcb->transport->tx_ready(pcb)))
		return (0);
	if ((kn->kn_sfflags & NOTE_LOWAT) != 0)
		return (space >= (size_t)kn->kn_sdata);
	return (1);
}

static const struct filterops vsock_write_filtops = {
	.f_isfd = 1,
	.f_detach = vsock_filt_sowdetach,
	.f_event = vsock_filt_sowrite,
	.f_copy = knote_triv_copy,
};

/*
 * Use the generic socket filters for receive/empty state.  EVFILT_WRITE needs
 * a vsock-specific list and callback because so_snd never reflects peer credit
 * or a shared transport queue.
 */
static int
vsock_kqfilter(struct socket *so, struct knote *kn)
{
	struct vtvsock_pcb *pcb;

	if (kn->kn_filter != EVFILT_WRITE)
		return (sokqfilter_generic(so, kn));
	mtx_lock(&vtvsock_mtx);
	pcb = so->so_pcb;
	if (pcb == NULL || pcb->so == NULL) {
		mtx_unlock(&vtvsock_mtx);
		return (EINVAL);
	}
	kn->kn_fop = &vsock_write_filtops;
	kn->kn_hook = pcb;
	knlist_add(&pcb->tx_knlist, kn, 1);
	mtx_unlock(&vtvsock_mtx);
	return (0);
}

/*
 * Re-evaluate every kind of writer: a blocking send sleeping on tx_cnt,
 * poll/select waiters on so_wrsel, and transport-aware EVFILT_WRITE knotes.
 * Caller holds vtvsock_mtx so the readiness transition and knote evaluation
 * are serialized.
 */
void
vsock_tx_wakeup_locked(struct vtvsock_pcb *pcb)
{
	mtx_assert(&vtvsock_mtx, MA_OWNED);
	wakeup(&pcb->tx_cnt);
	if (pcb->so != NULL)
		sowwakeup(pcb->so);
	KNOTE_LOCKED(&pcb->tx_knlist, 0);
}

/*
 * A transport-wide queue became writable.  Remote PCBs share that queue, so
 * wake every socket using this transport; its next poll/send rechecks credit
 * and queue capacity under vtvsock_mtx.
 */
void
vsock_transport_tx_wakeup_locked(const struct vtvsock_transport *transport)
{
	struct vtvsock_pcb *pcb;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	for (u_int i = 0; i < VTVSOCK_CONNHASH_SIZE; i++) {
		LIST_FOREACH(pcb, &vtvsock_conn[i], connlink) {
			if (pcb->transport != transport ||
			    pcb->state != VTVSOCK_ESTABLISHED || pcb->so == NULL)
				continue;
			vsock_tx_wakeup_locked(pcb);
		}
	}
}

/*
 * Protocol ioctls.  FIONREAD/FIONWRITE are handled generically by the socket
 * layer; only vsock-specific commands reach here.  SIOCOUTQ reports the bytes
 * sent to the peer but not yet consumed by it (tx_cnt - peer_fwd_cnt), the
 * flow-control "in flight" count -- matching Linux's SIOCOUTQ semantics.
 */
static int
vsock_control(struct socket *so, unsigned long cmd, void *data,
    struct ifnet *ifp __unused, struct thread *td __unused)
{
	struct vtvsock_pcb *pcb;
	int inflight;

	switch (cmd) {
	case IOCTL_VM_SOCKETS_GET_LOCAL_CID:
		/*
		 * Linux serves this from /dev/vsock (also provided here, see
		 * vsock_dev_ioctl); accepting it on the socket as well costs
		 * nothing and helps ported code that has an fd handy.
		 */
		*(uint32_t *)data = (uint32_t)vtvsock_guest_cid;
		return (0);
	case SIOCOUTQ:
		inflight = 0;
		mtx_lock(&vtvsock_mtx);
		pcb = so->so_pcb;
		if (pcb != NULL && pcb->state == VTVSOCK_ESTABLISHED) {
			uint32_t flight = pcb->tx_cnt - pcb->peer_fwd_cnt;

			/*
			 * Bytes in flight is a small unsigned value in normal
			 * operation.  Clamp to INT_MAX so a misbehaving peer that
			 * advanced peer_fwd_cnt past tx_cnt (unsigned wrap) cannot
			 * make SIOCOUTQ report a negative count.
			 */
			inflight = (flight > (uint32_t)__INT_MAX) ?
			    __INT_MAX : (int)flight;
		}
		mtx_unlock(&vtvsock_mtx);
		*(int *)data = inflight;
		return (0);
	default:
		return (EOPNOTSUPP);
	}
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
	if (len == 0 && pcb->so->so_type != SOCK_SEQPACKET) {
		/* A zero-length STREAM write is a no-op (no bytes, no record). */
		m_freem(m);
		return (0);
	}
	/*
	 * A zero-length SEQPACKET write delivers an empty record (Linux
	 * semantics): fall through so the empty mbuf is appended to the peer
	 * as a distinct 0-byte message, which recv() returns as 0.
	 */

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

/*
 * pr_sosend: advance user data only after the transport accepts it.
 *
 * sosend_generic() drains the uio into mbufs BEFORE calling pr_send, and
 * sousrsend() clears transient errors (EWOULDBLOCK/EINTR/ERESTART) for
 * stream sockets whenever the uio shows progress.  A pr_send that fails
 * transiently after the copy therefore reports a successful write while the
 * data has been freed -- silent loss.  The socket IO send lock is per socket,
 * while remote sockets share a transport queue, so a successful tx_ready()
 * check cannot reserve capacity against a sender on another socket.  Copy
 * through a cloned uio and advance the caller's uio only after send() accepts
 * the packet.  A transient post-copy failure then leaves the caller's
 * accounting unchanged and can be retried safely.
 */
static int
vsock_sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags, struct thread *td)
{
	struct vtvsock_pcb *pcb;
	struct mbuf *m;
	struct uio *copy_uio;
	ssize_t resid;
	size_t space, chunk, cap;
	sbintime_t timo;
	bool cantsend, nbio, remote, seqpacket;
	int error;

	/*
	 * sendfile(2) and friends pass a prebuilt chain instead of a uio;
	 * there is no post-copy loss hazard to prevent in that case (the
	 * caller owns retry semantics), so keep the generic path.
	 */
	if (top != NULL || uio == NULL)
		return (sosend_generic(so, addr, uio, top, control, flags,
		    td));

	if (control != NULL) {
		m_freem(control);
		control = NULL;
	}
	if (flags & MSG_OOB)
		return (EOPNOTSUPP);

	seqpacket = (so->so_type == SOCK_SEQPACKET);
	nbio = (so->so_state & SS_NBIO) || (flags & MSG_DONTWAIT);
	resid = uio->uio_resid;

	/* A zero-length STREAM write is a no-op (no bytes, no record). */
	if (!seqpacket && resid == 0)
		return (0);

	error = SOCK_IO_SEND_LOCK(so, SBLOCKWAIT(flags));
	if (error != 0)
		return (error);

	do {
		SOCK_SENDBUF_LOCK(so);
		cantsend = (so->so_snd.sb_state & SBS_CANTSENDMORE) != 0;
		SOCK_SENDBUF_UNLOCK(so);
		if (cantsend) {
			error = EPIPE;
			break;
		}
		SOCK_LOCK(so);
		if (so->so_error != 0) {
			error = so->so_error;
			so->so_error = 0;
			SOCK_UNLOCK(so);
			break;
		}
		SOCK_UNLOCK(so);

		mtx_lock(&vtvsock_mtx);
		pcb = so->so_pcb;
		if (pcb == NULL || pcb->state != VTVSOCK_ESTABLISHED) {
			mtx_unlock(&vtvsock_mtx);
			error = ENOTCONN;
			break;
		}

		if (seqpacket) {
			/*
			 * Atomic record: reject one that can never fit
			 * (mirrors the transports' own EMSGSIZE checks).
			 */
			cap = (pcb->transport == &vtvsock_local_transport) ?
			    (pcb->peer != NULL && pcb->peer->so != NULL ?
			    pcb->peer->so->so_rcv.sb_hiwat : 0) :
			    pcb->peer_buf_alloc;
			if (cap != 0 && (size_t)resid > cap) {
				mtx_unlock(&vtvsock_mtx);
				error = EMSGSIZE;
				break;
			}
		}

		/* Wait until the transport can take (part of) the data. */
		while ((space = vtvsock_tx_space(pcb)) <
		    (seqpacket ? (size_t)resid : 1) &&
		    !(seqpacket && resid == 0)) {
			/*
			 * Peer cannot receive anymore: EPIPE, not a stall.
			 * For loopback that is a peer that shut down its
			 * receive side OR one that disconnected/detached
			 * entirely (peer/so pointer already cleared) --
			 * space can never appear again in either case.
			 */
			if ((pcb->peer_shutdown &
			    VIRTIO_VSOCK_SHUTDOWN_RCV) != 0 ||
			    (pcb->transport == &vtvsock_local_transport &&
			    (pcb->peer == NULL || pcb->peer->so == NULL ||
			    (pcb->peer->so->so_rcv.sb_state &
			    SBS_CANTRCVMORE) != 0))) {
				mtx_unlock(&vtvsock_mtx);
				error = EPIPE;
				goto release;
			}
			if (nbio) {
				mtx_unlock(&vtvsock_mtx);
				error = EWOULDBLOCK;
				goto release;
			}
			/*
			 * Solicit a CREDIT_UPDATE on a remote stall
			 * (spec 5.10.6.3); loopback relies on the reader's
			 * periodic wakeup below.
			 */
			if (pcb->transport != &vtvsock_local_transport)
				(void)pcb->transport->send_pkt(pcb,
				    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0,
				    NULL, 0);
			/*
			 * SO_SNDTIMEO bounds the whole wait; without one,
			 * poll at 1s so a loopback reader draining without
			 * an explicit wakeup still unblocks us promptly.
			 */
			timo = so->so_snd.sb_timeo;
			error = msleep_sbt(&pcb->tx_cnt, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsosnd",
			    timo != 0 ? timo : SBT_1S, 0, 0);
			if (error == EWOULDBLOCK) {
				if (timo != 0) {
					mtx_unlock(&vtvsock_mtx);
					goto release;
				}
				error = 0;	/* poll tick; re-check */
			} else if (error != 0) {
				mtx_unlock(&vtvsock_mtx);
				goto release;
			}
			pcb = so->so_pcb;
			if (pcb == NULL ||
			    pcb->state != VTVSOCK_ESTABLISHED) {
				mtx_unlock(&vtvsock_mtx);
				error = ENOTCONN;
				goto release;
			}
		}
		/*
		 * Credit is available.  For a NON-blocking send, also require
		 * the transport to be able to accept a packet right now: the
		 * m_uiotombuf() below consumes the uio, and a transport that
		 * then failed EWOULDBLOCK on a full TX ring would silently
		 * drop those bytes while sousrsend() reports them as written
		 * (progress clears the transient error).  Returning
		 * EWOULDBLOCK here -- before the copy -- keeps short-write
		 * semantics honest.  Blocking sends don't need this: the
		 * transport waits for ring space internally and retries.
		 */
		if (nbio && pcb->transport->tx_ready != NULL &&
		    !pcb->transport->tx_ready(pcb)) {
			mtx_unlock(&vtvsock_mtx);
			error = EWOULDBLOCK;
			goto release;
		}
		remote = pcb->transport != &vtvsock_local_transport;
		mtx_unlock(&vtvsock_mtx);

		chunk = seqpacket ? (size_t)resid :
		    MIN(space, (size_t)resid);
		/*
		 * Keep each remote STREAM handoff to one wire packet.  A transport
		 * may otherwise enqueue several fragments and then fail, after the
		 * whole chunk has already been removed from the caller's uio.  One
		 * packet per call makes transport acceptance atomic and preserves
		 * accurate short-write accounting in this layer.
		 */
		if (!seqpacket && remote)
			chunk = MIN(chunk, (size_t)VSOCK_TRANSPORT_MAX_PAYLOAD);
		if (chunk > INT_MAX) {
			error = EMSGSIZE;
			break;
		}
		if (chunk > 0) {
			copy_uio = cloneuio(uio);
			if (copy_uio == NULL) {
				error = ENOBUFS;
				break;
			}
			m = m_uiotombuf(copy_uio, M_WAITOK, (int)chunk, 0, 0);
			freeuio(copy_uio);
			if (m == NULL) {
				error = ENOBUFS;
				break;
			}
		} else {
			/* Zero-length SEQPACKET record (Linux semantics). */
			m = m_gethdr(M_WAITOK, MT_DATA);
			m->m_len = 0;
			m->m_pkthdr.len = 0;
		}
		if (seqpacket && (flags & MSG_EOR) != 0)
			m->m_flags |= M_EOR | M_PROTO1;

		error = pcb->transport->send(pcb,
		    nbio ? VTVSOCK_SEND_F_NONBLOCK : 0, m, NULL, NULL, td);
		if (error != 0)
			break;
		uioadvance(uio, chunk);
		resid = uio->uio_resid;
	} while (resid > 0);

release:
	SOCK_IO_SEND_UNLOCK(so);
	return (error);
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
		vsock_tx_wakeup_locked(pcb->peer);
	}
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->state = VTVSOCK_CLOSED;
	vsock_tx_wakeup_locked(pcb);

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
			vsock_tx_wakeup_locked(pcb->peer);
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
			vsock_tx_wakeup_locked(pcb->peer);
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

static struct mbuf *
vsock_mbuf_from_buffer(const void *buf, size_t len)
{
	const uint8_t *src;
	struct mbuf *m, *n;
	size_t copied, chunk;

	if (len > INT_MAX)
		return (NULL);
	m = m_getm2(NULL, (int)len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (NULL);

	/*
	 * m_getm2() allocates enough storage, but leaves every m_len at zero.
	 * Fill that storage directly.  m_copyback() is not suitable here: it
	 * skips zero-length elements in a preallocated chain, then may allocate
	 * more M_NOWAIT mbufs without reporting a partial copy to its caller.
	 */
	src = buf;
	copied = 0;
	for (n = m; n != NULL && copied < len; n = n->m_next) {
		chunk = MIN((size_t)M_TRAILINGSPACE(n), len - copied);
		memcpy(mtod(n, void *), src + copied, chunk);
		n->m_len = (int)chunk;
		copied += chunk;
	}
	if (__predict_false(copied != len)) {
		m_freem(m);
		return (NULL);
	}
	m->m_pkthdr.len = (int)len;
	return (m);
}

void
vsock_rx_packet(const void *owner, void *buf, uint32_t len)
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
	bool teardown_drop = false;	/* true only for genuine packet drops */

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

	/*
	 * Attribute every packet to the transport instance that dequeued it.
	 * A driver drops the transport lock while entering the socket domain,
	 * so unregister/replacement can otherwise race this call and leave a
	 * newly-created PCB with a NULL or unrelated transport.  Check once
	 * before accounting, and again below whenever the domain lock is taken.
	 */
	mtx_lock(&vtvsock_mtx);
	if (owner == NULL || vtvsock_remote_transport == NULL ||
	    vtvsock_remote_transport_owner != owner) {
		mtx_unlock(&vtvsock_mtx);
		return;
	}
	mtx_unlock(&vtvsock_mtx);

	counter_u64_add(vtvsock_cnt_rx_packets, 1);

	/* Metadata-only trace of every inbound packet (no payload). */
	SDT_PROBE6(vsock, , , pkt__rx, hdr_op, hdr_src_cid, hdr_src_port,
	    hdr_dst_port, hdr_len, hdr_flags);

	payload = (uint8_t *)buf + sizeof(*hdr);
	payload_len = len - sizeof(*hdr);
	if (payload_len < hdr_len) {
		/*
		 * hdr.len is the payload size.  A transport buffer may contain
		 * trailing bytes, but it must contain the complete advertised
		 * payload; accepting a short buffer would silently truncate STREAM
		 * data or prematurely complete a SEQPACKET message.
		 */
		vtvsock_rx_drop("truncated-payload", hdr_op, hdr_src_cid,
		    hdr_src_port, hdr_dst_port);
		mtx_lock(&vtvsock_mtx);
		if (vtvsock_remote_transport_owner == owner &&
		    hdr_op != VIRTIO_VSOCK_OP_RST &&
		    vtvsock_remote_transport != NULL)
			(void)vtvsock_remote_transport->send_rst(
			    vtvsock_guest_cid, hdr_dst_port, hdr_src_cid,
			    hdr_src_port, hdr_type);
		mtx_unlock(&vtvsock_mtx);
		return;
	}
	payload_len = hdr_len;

	/*
	 * Only OP_RW carries payload.  Reject a payload-bearing control packet
	 * before PCB lookup or credit ingestion: otherwise a malformed
	 * CREDIT_UPDATE/SHUTDOWN could mutate a live connection while its
	 * unaccounted payload bytes were silently ignored.
	 */
	if (hdr_op != VIRTIO_VSOCK_OP_RW && payload_len != 0) {
		vtvsock_rx_drop("control-payload", hdr_op, hdr_src_cid,
		    hdr_src_port, hdr_dst_port);
		return;
	}

	/* Validate type field (§5.10.6.4.1: RST for unknown type). */
	if (hdr_type != VIRTIO_VSOCK_TYPE_STREAM &&
	    hdr_type != VIRTIO_VSOCK_TYPE_SEQPACKET) {
		vtvsock_rx_drop("unknown-type", hdr_op, hdr_src_cid,
		    hdr_src_port, hdr_dst_port);
		mtx_lock(&vtvsock_mtx);
		if (vtvsock_remote_transport_owner == owner &&
		    vtvsock_remote_transport != NULL)
			(void)vtvsock_remote_transport->send_rst(
			    vtvsock_guest_cid, hdr_dst_port,
			    hdr_src_cid, hdr_src_port, hdr_type);
		mtx_unlock(&vtvsock_mtx);
		return;
	}

	mtx_lock(&vtvsock_mtx);
	if (vtvsock_remote_transport == NULL ||
	    vtvsock_remote_transport_owner != owner) {
		mtx_unlock(&vtvsock_mtx);
		return;
	}

	/*
	 * Locate the PCB.  For OP_REQUEST, look for a listening socket in
	 * the bound list.  For all other ops, look in the connected list.
	 */
	if (hdr_op == VIRTIO_VSOCK_OP_REQUEST) {
		/*
		 * A REQUEST whose 4-tuple already names a connection is a
		 * duplicate (peer retransmission or a simultaneous connect)
		 * and must never reach the listener: sonewconn() would create
		 * a second PCB with an identical tuple, shadowing the first
		 * in the connected hash and orphaning it in the accept queue.
		 * Match Linux: while CONNECTING the connect is aborted with
		 * RST + EPROTO (virtio_transport_recv_connecting's default
		 * arm); on an established connection the packet is ignored
		 * (virtio_transport_recv_connected returns -EINVAL, no
		 * action).
		 */
		pcb = vtvsock_pcb_lookup_connected_locked(hdr_src_cid,
		    hdr_src_port, hdr_dst_cid, hdr_dst_port);
		if (pcb != NULL) {
			if (pcb->state == VTVSOCK_CONNECTING) {
				so = pcb->so;
				MPASS(so != NULL);
				teardown_rst = true;
				teardown_errno = EPROTO;
				goto teardown_close;
			}
			mtx_unlock(&vtvsock_mtx);
			return;
		}
		pcb = vtvsock_pcb_lookup_bound_locked(hdr_dst_cid, hdr_dst_port);
		if (pcb == NULL || pcb->state != VTVSOCK_LISTEN) {
			/* No listener; send RST (under lock for VQ safety). */
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_rst(
				    vtvsock_guest_cid, hdr_dst_port,
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
				    vtvsock_guest_cid, hdr_dst_port,
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
	 * CLOSING: we have sent OP_SHUTDOWN(both) and are waiting for the
	 * peer's RST to complete the clean disconnect (§5.10.6.5).  Mirror
	 * Linux virtio_transport_recv_disconnecting: act only on OP_RST, which
	 * finishes teardown; silently drop every other op without replying or
	 * mutating this dying PCB's credit/shutdown state.  Without this gate a
	 * straggler OP_RW drew a spurious RST (state != ESTABLISHED) and
	 * control ops needlessly churned credit on a connection already going
	 * away.
	 */
	if (pcb->state == VTVSOCK_CLOSING) {
		if (hdr_op == VIRTIO_VSOCK_OP_RST) {
			SDT_PROBE4(vsock, , , rst__received,
			    pcb->remote.svm_cid, pcb->remote.svm_port,
			    pcb->state, 0);
			goto teardown_close;	/* teardown_errno stays 0 */
		}
		mtx_unlock(&vtvsock_mtx);
		return;
	}

	/*
	 * Validate packet type matches the socket type for non-REQUEST ops,
	 * BEFORE ingesting any credit below, so a malformed-type packet cannot
	 * mutate our credit view or trip a teardown.  OP_RST is excluded: it
	 * tears the connection down regardless of type, and replying to a
	 * wrong-type RST with an RST would be a needless RST-for-RST.
	 */
	if (hdr_op != VIRTIO_VSOCK_OP_REQUEST &&
	    hdr_op != VIRTIO_VSOCK_OP_RST) {
		uint16_t expected_type = (so->so_type == SOCK_SEQPACKET) ?
		    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM;
		if (hdr_type != expected_type) {
			vtvsock_rx_drop("socket-type-mismatch", hdr_op,
			    hdr_src_cid, hdr_src_port, hdr_dst_port);
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_rst(
				    vtvsock_guest_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			return;
		}
	}

	/*
	 * Extract peer credit state from every incoming packet before
	 * dispatching on opcode, so credit advances even when the peer
	 * piggybacks updates on data or control packets.  Skip OP_REQUEST (no
	 * established PCB yet; the child PCB is initialized below with the
	 * peer's credit values) and OP_RST (carries no credit, and validating
	 * it could set teardown_rst and make us reply to an RST with an RST --
	 * the RST case below tears the connection down directly).
	 */
	if (hdr_op != VIRTIO_VSOCK_OP_REQUEST && hdr_op != VIRTIO_VSOCK_OP_RST) {
		pcb->peer_buf_alloc = hdr_buf_alloc;
		/*
		 * Validate peer_fwd_cnt: it must not claim to have
		 * consumed more bytes than we have sent (tx_cnt).
		 * Use signed comparison to handle 32-bit wrap correctly.
		 */
		if ((int32_t)(hdr_fwd_cnt - pcb->tx_cnt) > 0) {
			teardown_rst = true;
			teardown_drop = true;
			goto teardown_close;
		}
		/*
		 * fwd_cnt is monotonic non-decreasing (it counts bytes the peer
		 * has consumed).  A peer that rewinds it -- broken or hostile --
		 * would inflate our in-flight estimate (tx_cnt - peer_fwd_cnt)
		 * in vtvsock_credit_available() and wrongly stall the sender.
		 * Never move it backward.
		 */
		if ((int32_t)(hdr_fwd_cnt - pcb->peer_fwd_cnt) > 0)
			pcb->peer_fwd_cnt = hdr_fwd_cnt;
		vsock_tx_wakeup_locked(pcb);
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
			short rcv_state;

			SOCK_RECVBUF_LOCK(so);
			rcv_state = so->so_rcv.sb_state;
			SOCK_RECVBUF_UNLOCK(so);
			if (so->so_options & SO_ACCEPTCONN &&
			    (rcv_state & SBS_CANTRCVMORE)) {
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    vtvsock_guest_cid, hdr_dst_port,
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
						    vtvsock_guest_cid, hdr_dst_port,
						    hdr_src_cid, hdr_src_port,
						    hdr_type);
					mtx_unlock(&vtvsock_mtx);
					return;
				}
			}

			/*
			 * Global backstop against peer-driven connection growth
			 * (in addition to the per-listener so_qlimit sonewconn
			 * enforces below).  Reject with RST once the connected
			 * table is at its ceiling.
			 */
			if (vtvsock_conn_count >= vtvsock_max_conn) {
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    vtvsock_guest_cid, hdr_dst_port,
					    hdr_src_cid, hdr_src_port,
					    hdr_type);
				mtx_unlock(&vtvsock_mtx);
				return;
			}

			/*
			 * The transport RX path runs in an interrupt thread
			 * with no vnet context; sonewconn() -> soattach()
			 * asserts curvnet matches the listener's vnet.
			 */
			CURVNET_SET(so->so_vnet);
			child_so = sonewconn(so, 0);
			CURVNET_RESTORE();
			if (child_so == NULL) {
				/* Backlog full; reject. */
				if (vtvsock_remote_transport != NULL)
					(void)vtvsock_remote_transport->send_rst(
					    vtvsock_guest_cid, hdr_dst_port,
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
			/*
			 * An OP_REQUEST forwards no bytes; start peer_fwd_cnt at
			 * 0 rather than trusting the header's fwd_cnt (which the
			 * validated-credit path above rejects when it exceeds
			 * tx_cnt).  We have sent nothing, so any nonzero value
			 * here would be bogus.
			 */
			child->peer_fwd_cnt = 0;
			child->buf_alloc = vtvsock_buf_alloc_from_so(child_so);
			vtvsock_pcb_insert_connected_locked(child);

			/* Send OP_RESPONSE using the child's addresses. */
			if (vtvsock_remote_transport != NULL)
				(void)vtvsock_remote_transport->send_pkt(child,
				    VIRTIO_VSOCK_OP_RESPONSE, 0, NULL, 0);

			soisconnected(child_so);
			vsock_tx_wakeup_locked(child);
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
			soisconnected(so);
			vsock_tx_wakeup_locked(pcb);
			counter_u64_add(vtvsock_cnt_conns, 1);
			mtx_unlock(&vtvsock_mtx);
		} else {
			mtx_unlock(&vtvsock_mtx);
		}
		break;

	case VIRTIO_VSOCK_OP_RST:
		/*
		 * Remote peer sent RST.  Forcibly close.  Match Linux vsock's
		 * peer-observable errno semantics so ported applications behave
		 * identically:
		 *   - RST while still CONNECTING: connect(2) reports ECONNRESET
		 *     (Linux virtio_transport_recv_connecting sets
		 *     sk_err = ECONNRESET), not the POSIX ECONNREFUSED.
		 *   - RST on an established connection: a clean abort delivered
		 *     as EOF to the reader and EPIPE to the writer, with NO
		 *     so_error set (Linux virtio_transport_do_close sets
		 *     SOCK_DONE, never sk_err).  soisdisconnected() below issues
		 *     socantrcvmore()/socantsendmore() to produce exactly that.
		 * (An explicit RST differs from a flow-control violation we
		 * detect ourselves, which still reports ECONNRESET below --
		 * there real bytes were dropped, so EOF would hide data loss.)
		 */
		if (pcb->state != VTVSOCK_CLOSED) {
			teardown_errno = (pcb->state == VTVSOCK_CONNECTING) ?
			    ECONNRESET : 0;
			SDT_PROBE4(vsock, , , rst__received,
			    pcb->remote.svm_cid, pcb->remote.svm_port,
			    pcb->state, teardown_errno);
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

			SDT_PROBE4(vsock, , , shutdown, pcb->remote.svm_cid,
			    pcb->remote.svm_port, sflags, 0 /* received */);

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
				/*
				 * Apply half-shutdown notifications with
				 * vtvsock_mtx still held so a racing close()
				 * cannot free so (delivery-path UAF fix).
				 * socant*more_locked() release the sockbuf lock.
				 */
				if (sflags & VIRTIO_VSOCK_SHUTDOWN_RCV) {
					SOCK_SENDBUF_LOCK(so);
					socantsendmore_locked(so);
				}
				if (sflags & VIRTIO_VSOCK_SHUTDOWN_SEND) {
					SOCK_RECVBUF_LOCK(so);
					socantrcvmore_locked(so);
				}
				/*
				 * Peer fully shut down but our RX queue still
				 * holds undelivered bytes, so teardown is
				 * deferred until the app drains (see
				 * vsock_soreceive).  Arm the close timer so a
				 * local app that never reads cannot pin the
				 * connection ESTABLISHED forever -- teardown is
				 * now time-bounded independent of app activity.
				 * A normal drain to rx_bytes==0 stops this
				 * callout on the deferred-teardown path.
				 */
				if (pcb->peer_shutdown ==
				    (VIRTIO_VSOCK_SHUTDOWN_RCV |
				     VIRTIO_VSOCK_SHUTDOWN_SEND) &&
				    pcb->state == VTVSOCK_ESTABLISHED) {
					/*
					 * Drop the (local,remote) 4-tuple from
					 * the connected hash now, while keeping
					 * the socket alive for the app to drain.
					 * Matches Linux virtio_transport_recv_
					 * connected, which vsock_remove_sock()s
					 * as soon as peer_shutdown == SHUTDOWN_MASK
					 * so a peer that immediately reconnects on
					 * the same source port succeeds instead of
					 * being rejected as a duplicate until we
					 * drain or the close timer fires.  The peer
					 * has said it will not send (SEND bit), so
					 * no further RW is expected; a late RST just
					 * hits the no-PCB drop path.  Drain and the
					 * close callout both key off the PCB itself
					 * and tolerate it already being off the
					 * connected list.
					 */
					vtvsock_pcb_remove_connected_locked(pcb);
					callout_reset(&pcb->close_callout,
					    VTVSOCK_CLOSE_TIMEOUT,
					    vtvsock_close_timeout, pcb);
				}
				mtx_unlock(&vtvsock_mtx);
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
				    vtvsock_guest_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			break;
		}

		if (payload_len == 0) {
			/*
			 * SEQPACKET zero-length fragment with EOM: deliver the
			 * record.  If a partial reassembly is in progress this
			 * flushes it; otherwise it delivers a zero-length
			 * message (Linux semantics), which recv() returns as a
			 * distinct 0-byte record with the connection still open.
			 */
			if (so->so_type == SOCK_SEQPACKET &&
			    (hdr_flags & VIRTIO_VSOCK_SEQ_EOM)) {
				if (pcb->seqpacket_partial != NULL) {
					m = pcb->seqpacket_partial;
					pcb->seqpacket_partial = NULL;
					pcb->seqpacket_frag_count = 0;
				} else {
					m = m_gethdr(M_NOWAIT, MT_DATA);
					if (m != NULL) {
						m->m_len = 0;
						m->m_pkthdr.len = 0;
					}
				}
				if (m == NULL) {
					sowwakeup(so);
					mtx_unlock(&vtvsock_mtx);
					break;
				}
				{
					struct mbuf *last;
					for (last = m; last->m_next != NULL;
					    last = last->m_next)
						;
					/* EOR mirrors the sender's MSG_EOR. */
					if (hdr_flags & VIRTIO_VSOCK_SEQ_EOR)
						last->m_flags |= M_EOR;
				}
				sowwakeup(so);
				SOCK_RECVBUF_LOCK(so);
				sbappendrecord_locked(&so->so_rcv, m);
				sorwakeup_locked(so);
				mtx_unlock(&vtvsock_mtx);
			} else {
				sowwakeup(so);
				mtx_unlock(&vtvsock_mtx);
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
			teardown_drop = true;
			/* Peer-caused reset: POSIX/Linux report ECONNRESET. */
			teardown_errno = ECONNRESET;
			goto teardown_close;
		}

		m = vsock_mbuf_from_buffer(payload, payload_len);
		if (m == NULL) {
			/* Out of mbufs; send RST. */
			teardown_rst = true;
			teardown_drop = true;
			goto teardown_close;
		}

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
					teardown_drop = true;
					/* Peer-caused reset: report ECONNRESET. */
					teardown_errno = ECONNRESET;
					goto teardown_close;
				}
				pcb->seqpacket_frag_count++;
				m_catpkt(pcb->seqpacket_partial, m);
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
				{
					struct mbuf *last;
					for (last = m; last->m_next != NULL;
					    last = last->m_next)
						;
					/* EOR mirrors the sender's MSG_EOR. */
					if (hdr_flags & VIRTIO_VSOCK_SEQ_EOR)
						last->m_flags |= M_EOR;
				}
				sowwakeup(so);
				SOCK_RECVBUF_LOCK(so);
				sbappendrecord_locked(&so->so_rcv, m);
				sorwakeup_locked(so);
				mtx_unlock(&vtvsock_mtx);
			} else {
				/* More fragments coming; hold the partial. */
				sowwakeup(so);
				mtx_unlock(&vtvsock_mtx);
			}
		} else {
			/* SOCK_STREAM: deliver immediately. */
			sowwakeup(so);
			SOCK_RECVBUF_LOCK(so);
			sbappendstream_locked(&so->so_rcv, m, 0);
			sorwakeup_locked(so);
			mtx_unlock(&vtvsock_mtx);
		}
		break;

	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		/*
		 * Peer is advertising new/updated RX capacity.
		 * peer_buf_alloc / peer_fwd_cnt already updated above.
		 * wakeup(&pcb->tx_cnt) also already done above.
		 */
		SDT_PROBE4(vsock, , , credit__update__recv, pcb->remote.svm_cid,
		    pcb->remote.svm_port, pcb->peer_buf_alloc, pcb->peer_fwd_cnt);
		sowwakeup(so);
		mtx_unlock(&vtvsock_mtx);
		break;

	case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
		/*
		 * Peer is asking us to report our current RX credit.
		 */
		if (vtvsock_remote_transport != NULL)
			vtvsock_remote_transport->send_credit_update(pcb);
		mtx_unlock(&vtvsock_mtx);
		break;

	case VIRTIO_VSOCK_OP_INVALID:
		/*
		 * Op 0 is the "invalid" sentinel, not an unknown/future op.
		 * Ignore it in every state -- in particular do NOT let it fall
		 * to the default arm below, which aborts a CONNECTING socket
		 * with RST + EPROTO.  Matches Linux virtio_transport_recv_
		 * connecting, which has an explicit `case OP_INVALID: break;`.
		 */
		mtx_unlock(&vtvsock_mtx);
		break;

	default: {
		static struct timeval vtvsock_warn_lasttime;
		static int vtvsock_warn_curpps;

		/*
		 * Unknown opcode.  While CONNECTING, treat it as a protocol
		 * error and abort the connect with RST + EPROTO, as Linux
		 * virtio_transport_recv_connecting does.  Once established,
		 * silently ignore: the spec mandates RST only for unknown
		 * *types* (§5.10.6.4.1, handled above), not unknown ops, and
		 * resetting here would break forward compatibility with
		 * future spec extensions (Linux likewise leaves an
		 * established connection up).
		 */
		if (pcb->state == VTVSOCK_CONNECTING) {
			teardown_rst = true;
			teardown_errno = EPROTO;
			goto teardown_close;
		}
		if (ppsratecheck(&vtvsock_warn_lasttime, &vtvsock_warn_curpps, 1))
			printf("vtvsock: unknown op %u from host, ignoring\n",
			    hdr_op);
		mtx_unlock(&vtvsock_mtx);
		break;
	}}

	return;

teardown_close:
	/*
	 * Only count genuine drops (a packet we could not accept: bad
	 * peer_fwd_cnt, buffer overflow, mbuf exhaustion, oversized SEQPACKET
	 * record).  A received OP_RST or a completed bidirectional SHUTDOWN is
	 * routine teardown, not a drop, and must not inflate rx_drops.
	 */
	if (teardown_drop)
		vtvsock_rx_drop("connection-teardown", hdr_op, hdr_src_cid,
		    hdr_src_port, hdr_dst_port);
	callout_stop(&pcb->close_callout);
	callout_stop(&pcb->connect_callout);
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->state = VTVSOCK_CLOSED;
	wakeup(&pcb->state);
	vsock_tx_wakeup_locked(pcb);
	/*
	 * send_pkt, not send_rst: the PCB is live here, so the RST carries
	 * our real buf_alloc/fwd_cnt as §5.10.6.3.1 requires of every packet
	 * on a stream flow (send_rst is for flows with no PCB and stamps
	 * zeros, like Linux's virtio_transport_reset_no_sock).
	 */
	if (teardown_rst && vtvsock_remote_transport != NULL)
		(void)vtvsock_remote_transport->send_pkt(pcb,
		    VIRTIO_VSOCK_OP_RST, 0, NULL, 0);
	/*
	 * Hold vtvsock_mtx across the socket-state updates below so a
	 * concurrent vsock_detach() (which takes vtvsock_mtx before freeing
	 * the socket) cannot free so out from under us -- the delivery-path
	 * UAF fix, mirroring vsock_transport_reset_locked().
	 */
	if (teardown_errno != 0) {
		SOCK_LOCK(so);
		so->so_error = teardown_errno;
		SOCK_UNLOCK(so);
	}
	soisdisconnected(so);
	mtx_unlock(&vtvsock_mtx);
}

/* -----------------------------------------------------------------------
 * Transport reset
 *
 * Reset all remote connections.  Called from vsock_transport_unregister()
 * and from the driver's TRANSPORT_RESET event handler, always with
 * vtvsock_mtx held.
 * ---------------------------------------------------------------------- */

void
vsock_transport_reset_locked(void)
{
	struct vtvsock_pcb *pcb, *tmp;
	struct socket *so;

	/* Reset all connected sockets across every hash bucket. */
	for (u_int i = 0; i < VTVSOCK_CONNHASH_SIZE; i++) {
		LIST_FOREACH_SAFE(pcb, &vtvsock_conn[i], connlink, tmp) {
			so = pcb->so;
			KASSERT(so != NULL,
			    ("%s: pcb %p on connlist with NULL so",
			    __func__, pcb));
			callout_stop(&pcb->close_callout);
			callout_stop(&pcb->connect_callout);
			vtvsock_pcb_remove_lists_locked(pcb);
			pcb->state = VTVSOCK_CLOSED;
			wakeup(&pcb->state);
			vsock_tx_wakeup_locked(pcb);
			SOCK_LOCK(so);
			so->so_error = ECONNRESET;
			SOCK_UNLOCK(so);
			soisdisconnected(so);
		}
	}
}

/* -----------------------------------------------------------------------
 * Transport registration
 *
 * Called by the remote transport driver (e.g. virtio_vsock) on
 * attach/detach to register/unregister itself with the socket domain.
 * ---------------------------------------------------------------------- */

int
vsock_transport_register_locked(const struct vtvsock_transport *ops,
    const void *owner, uint64_t guest_cid, uint64_t features)
{
	struct vtvsock_pcb *lpcb;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	KASSERT(ops != NULL, ("%s: NULL transport", __func__));
	KASSERT(owner != NULL, ("%s: NULL owner", __func__));
	if (vtvsock_remote_transport != NULL &&
	    vtvsock_remote_transport_owner != owner)
		return (EBUSY);
	vtvsock_remote_transport = ops;
	vtvsock_remote_transport_owner = owner;
	/*
	 * HYPERVISOR, ANY, and the 64-bit all-ones value can never be a local
	 * endpoint.  HOST is valid for the privileged userspace transport;
	 * guest-side transports sanitize it before registration.
	 */
	if (guest_cid == VSOCK_CID_HYPERVISOR || guest_cid == VSOCK_CID_ANY ||
	    guest_cid == UINT64_C(0xffffffffffffffff))
		guest_cid = VSOCK_CID_LOCAL;
	vtvsock_guest_cid = guest_cid;
	vtvsock_remote_features = features;
	/*
	 * Update listener CIDs to the new guest CID.  Loopback-pinned
	 * sockets (explicitly bound to VSOCK_CID_LOCAL) keep CID 1: they
	 * were never reachable through the transport and must stay
	 * loopback-only across a registration or TRANSPORT_RESET.
	 */
	LIST_FOREACH(lpcb, &vtvsock_bound, link) {
		if ((lpcb->state == VTVSOCK_LISTEN ||
		    lpcb->state == VTVSOCK_BOUND) && !lpcb->bound_local)
			lpcb->local.svm_cid = guest_cid;
	}
	return (0);
}

int
vsock_transport_register(const struct vtvsock_transport *ops,
    const void *owner, uint64_t guest_cid, uint64_t features)
{
	int error;

	mtx_lock(&vtvsock_mtx);
	error = vsock_transport_register_locked(ops, owner, guest_cid, features);
	mtx_unlock(&vtvsock_mtx);
	return (error);
}

void
vsock_transport_unregister(const void *owner)
{
	mtx_lock(&vtvsock_mtx);
	if (vtvsock_remote_transport_owner != owner) {
		mtx_unlock(&vtvsock_mtx);
		return;
	}
	vtvsock_remote_transport = NULL;
	vtvsock_remote_transport_owner = NULL;
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
		if (vsock_cdev_create() != 0) {
			counter_u64_free(vtvsock_cnt_tx_packets);
			counter_u64_free(vtvsock_cnt_tx_bytes);
			counter_u64_free(vtvsock_cnt_rx_packets);
			counter_u64_free(vtvsock_cnt_rx_bytes);
			counter_u64_free(vtvsock_cnt_rx_drops);
			counter_u64_free(vtvsock_cnt_conns);
			return (ENXIO);
		}
		return (0);
	case MOD_QUIESCE:
	case MOD_UNLOAD:
		/*
		 * Refuse to unload.  The AF_VSOCK domain is installed via
		 * DOMAIN_SET, which FreeBSD cannot retract: vsockdomain has no
		 * DOMF_UNLOADABLE, so domain_remove() is a no-op and the
		 * protosw dispatch table stays registered forever.  Freeing
		 * the counters and /dev/vsock here (and letting the module
		 * text be unmapped) would leave the live domain's pr_* entry
		 * points and the kern.vsock.* sysctls pointing into freed
		 * memory -- a guaranteed panic on the next AF_VSOCK socket op
		 * or counter update.  Reject the unload instead, as ng_socket
		 * (another DOMAIN_SET module) does.  MOD_QUIESCE returning
		 * EBUSY also makes `kldunload -f` report the module as busy.
		 */
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t vsock_mod = { "vsock", vsock_modevent, NULL };
DECLARE_MODULE(vsock, vsock_mod, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_VERSION(vsock, 1);
