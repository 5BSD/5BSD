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
 * VirtIO VSOCK guest-side driver.
 *
 * Implements AF_VSOCK SOCK_STREAM and SOCK_SEQPACKET over the virtio-vsock
 * transport (OASIS virtio v1.3, section 5.10).  Supports:
 *   - Full connection state machine (REQUEST/RESPONSE/RST/SHUTDOWN)
 *   - Credit-based flow control (CREDIT_UPDATE / CREDIT_REQUEST)
 *   - Local (guest-to-guest) loopback via peer pointer
 *   - Remote (guest-to-host or host-to-guest) via virtqueues
 *   - SEQPACKET EOM/EOR framing with fragment reassembly
 *   - Event queue (TRANSPORT_RESET)
 *   - Close and connect timeouts via callout(9)
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/counter.h>
#include <sys/domain.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/sglist.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vsock.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

/* -----------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define	VTVSOCK_MAXQ			3
#define	VTVSOCK_RX_BUFSZ		(sizeof(struct virtio_vsock_hdr) + \
					 64 * 1024)
#define	VTVSOCK_RX_FILL			32

#define	VTVSOCK_MAX_PKT_BUF		(64  * 1024)
#define	VTVSOCK_DEFAULT_BUF_ALLOC	(128 * 1024)
#define	VTVSOCK_CLOSE_TIMEOUT		(hz * 8)
#define	VTVSOCK_CONNECT_TIMEOUT		(hz * 30)

/* -----------------------------------------------------------------------
 * Connection state machine
 * ---------------------------------------------------------------------- */

enum vtvsock_state {
	VTVSOCK_CLOSED = 0,
	VTVSOCK_BOUND,
	VTVSOCK_LISTEN,
	VTVSOCK_CONNECTING,	/* OP_REQUEST sent, waiting for OP_RESPONSE */
	VTVSOCK_ESTABLISHED,
	VTVSOCK_CLOSING,	/* graceful shutdown in progress */
};

/* -----------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------- */

struct vtvsock_softc {
	device_t		 sc_dev;
	struct mtx		 sc_mtx;
	struct virtqueue	*sc_rxvq;
	struct virtqueue	*sc_txvq;
	struct virtqueue	*sc_eventvq;
	uint64_t		 sc_features;
	uint64_t		 sc_guest_cid;
};

struct vtvsock_transport;

struct vtvsock_pcb {
	struct socket			*so;
	struct vtvsock_pcb		*peer;		/* loopback only */
	const struct vtvsock_transport	*transport;
	struct sockaddr_vm		 local;
	struct sockaddr_vm		 remote;

	/* State machine */
	enum vtvsock_state		 state;

	/* Membership tracking */
	bool				 on_boundlist;
	bool				 on_connlist;

	/* Buffer limits (SOL_VSOCK opts) */
	uint64_t			 buffer_min;
	uint64_t			 buffer_max;
	int			 connect_timeout; /* ticks, 0 = default */

	/* Credit-based flow control */
	uint32_t			 buf_alloc;	/* our advertised RX cap */
	uint32_t			 peer_buf_alloc;/* peer's last advertised */
	uint32_t			 tx_cnt;	/* bytes we've been granted */
	uint32_t			 peer_fwd_cnt;	/* peer's last consumed cnt */
	uint32_t			 fwd_cnt;	/* bytes we consumed from RX */
	uint32_t			 last_fwd_cnt;	/* fwd_cnt last sent */
	uint32_t			 rx_bytes;	/* bytes in our RX queue */

	/* Peer shutdown tracking */
	uint32_t			 peer_shutdown;

	/* SEQPACKET fragment reassembly */
	struct mbuf			*seqpacket_partial;

	/* Timers */
	struct callout			 close_callout;
	struct callout			 connect_callout;

	LIST_ENTRY(vtvsock_pcb)		 link;		/* bound list */
	LIST_ENTRY(vtvsock_pcb)		 connlink;	/* connected list */
};

struct vtvsock_transport {
	int	(*send)(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
	int	(*disconnect)(struct vtvsock_pcb *);
	int	(*shutdown)(struct vtvsock_pcb *, enum shutdown_how);
};

/* -----------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */

static MALLOC_DEFINE(M_VTVSOCK, "vtvsock", "virtio vsock");

/* Global mutex: protects bound/connected lists and PCB state fields.
 * Lock ordering: vtvsock_mtx -> SOCK_RECVBUF_LOCK / SOCK_SENDBUF_LOCK.
 * Never acquire vtvsock_mtx while holding a socket buffer lock.         */
static struct mtx vtvsock_mtx;
MTX_SYSINIT(vtvsock, &vtvsock_mtx, "vtvsock", MTX_DEF);

static LIST_HEAD(, vtvsock_pcb) vtvsock_bound =
    LIST_HEAD_INITIALIZER(vtvsock_bound);
static LIST_HEAD(, vtvsock_pcb) vtvsock_conn =
    LIST_HEAD_INITIALIZER(vtvsock_conn);

static uint64_t vtvsock_guest_cid = UINT64_MAX;

static _Atomic(struct vtvsock_softc *) vtvsock_sc;

SYSCTL_U64(_kern, OID_AUTO, vsock_guest_cid, CTLFLAG_RD,
    &vtvsock_guest_cid, 0, "VSOCK guest CID");

static counter_u64_t vtvsock_cnt_tx_packets;
static counter_u64_t vtvsock_cnt_tx_bytes;
static counter_u64_t vtvsock_cnt_rx_packets;
static counter_u64_t vtvsock_cnt_rx_bytes;
static counter_u64_t vtvsock_cnt_rx_drops;
static counter_u64_t vtvsock_cnt_conns;

SYSCTL_NODE(_kern, OID_AUTO, vsock, CTLFLAG_RD, 0, "VSOCK statistics");
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
static int	vsock_soreceive(struct socket *, struct sockaddr **, struct uio *,
		    struct mbuf **, struct mbuf **, int *);
static int	vsock_send(struct socket *, int, struct mbuf *, struct sockaddr *,
		    struct mbuf *, struct thread *);
static int	vsock_disconnect(struct socket *);
static int	vsock_shutdown(struct socket *, enum shutdown_how);
static void	vsock_abort(struct socket *);

static struct vtvsock_pcb *vtvsock_pcb_alloc(struct socket *);
static void	vtvsock_pcb_free(struct vtvsock_pcb *);
static void	vtvsock_pcb_remove_lists_locked(struct vtvsock_pcb *);
static void	vtvsock_pcb_insert_bound_locked(struct vtvsock_pcb *);
static void	vtvsock_pcb_insert_connected_locked(struct vtvsock_pcb *);
static void	vtvsock_pcb_set_addr(struct sockaddr_vm *, uint64_t, uint32_t);
static int	vtvsock_copy_to_sockaddr(const struct sockaddr_vm *,
		    struct sockaddr *);
static struct vtvsock_pcb *vtvsock_pcb_lookup_bound_locked(uint64_t, uint32_t);
static struct vtvsock_pcb *vtvsock_pcb_lookup_connected_locked(uint64_t,
		    uint32_t, uint64_t, uint32_t);

static bool	vtvsock_is_local(uint64_t dst_cid);
static int32_t	vtvsock_credit_available(struct vtvsock_pcb *);
static uint32_t	vtvsock_get_credit(struct vtvsock_pcb *, uint32_t);

static int	vtvsock_local_send(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
static int	vtvsock_local_disconnect(struct vtvsock_pcb *);
static int	vtvsock_local_shutdown(struct vtvsock_pcb *, enum shutdown_how);

static int	vtvsock_virtio_send(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
static int	vtvsock_virtio_disconnect(struct vtvsock_pcb *);
static int	vtvsock_virtio_shutdown(struct vtvsock_pcb *, enum shutdown_how);

static int	vtvsock_queue_rx_buffers(struct vtvsock_softc *);
static int	vtvsock_send_pkt_locked(struct vtvsock_pcb *, uint16_t,
		    uint32_t, const void *, size_t);
static int	vtvsock_send_rst_locked(struct vtvsock_softc *, uint64_t,
		    uint32_t, uint64_t, uint32_t, uint16_t);
static void	vtvsock_send_credit_update_locked(struct vtvsock_pcb *);
static void	vtvsock_handle_rx_packet(struct vtvsock_softc *, void *,
		    uint32_t);
static void	vtvsock_reset_all_locked(struct vtvsock_softc *);
static void	vtvsock_close_timeout(void *);
static void	vtvsock_connect_timeout(void *);

static void	vtvsock_rx_intr(void *);
static void	vtvsock_tx_intr(void *);
static void	vtvsock_event_intr(void *);

static struct vtvsock_softc *vtvsock_global_softc(void);

/* -----------------------------------------------------------------------
 * Transport dispatch tables
 * ---------------------------------------------------------------------- */

static const struct vtvsock_transport vtvsock_local_transport = {
	.send =		vtvsock_local_send,
	.disconnect =	vtvsock_local_disconnect,
	.shutdown =	vtvsock_local_shutdown,
};

static const struct vtvsock_transport vtvsock_virtio_transport = {
	.send =		vtvsock_virtio_send,
	.disconnect =	vtvsock_virtio_disconnect,
	.shutdown =	vtvsock_virtio_shutdown,
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
	.pr_flags =	PR_ATOMIC | PR_ADDR | PR_CONNREQUIRED,
	.pr_attach =	vsock_attach,
	.pr_bind =	vsock_bind,
	.pr_listen =	vsock_listen,
	.pr_accept =	vsock_accept,
	.pr_connect =	vsock_connect,
	.pr_peeraddr =	vsock_peeraddr,
	.pr_sockaddr =	vsock_sockaddr,
	.pr_ctloutput =	vsock_ctloutput,
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
 * VirtIO feature descriptor
 * ---------------------------------------------------------------------- */

static struct virtio_feature_desc vtvsock_feature_desc[] = {
	{ VIRTIO_VSOCK_F_STREAM, "Stream" },
	{ VIRTIO_VSOCK_F_SEQPACKET, "SeqPacket" },
	{ VIRTIO_VSOCK_F_NO_IMPLIED_STREAM, "NoImpliedStream" },
	{ 0, NULL }
};

/* -----------------------------------------------------------------------
 * Utility helpers
 * ---------------------------------------------------------------------- */

static struct vtvsock_softc *
vtvsock_global_softc(void)
{
	return (atomic_load_ptr(&vtvsock_sc));
}

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
	pcb->buffer_min = VTVSOCK_DEFAULT_BUF_ALLOC;
	pcb->buffer_max = 2 * 1024 * 1024;
	pcb->connect_timeout = 0;  /* 0 means use default VTVSOCK_CONNECT_TIMEOUT */
	pcb->buf_alloc = VTVSOCK_DEFAULT_BUF_ALLOC;
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
static void
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
static void
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
static inline int32_t
vtvsock_credit_available(struct vtvsock_pcb *pcb)
{
	return ((int32_t)(pcb->peer_buf_alloc -
	    (pcb->tx_cnt - pcb->peer_fwd_cnt)));
}

/*
 * Consume up to 'wanted' bytes of send credit; return amount granted.
 * Must be called with vtvsock_mtx held (or otherwise serialized).
 */
static uint32_t
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
 * Virtqueue packet transmission
 * ---------------------------------------------------------------------- */

/*
 * Enqueue one packet onto the TX virtqueue.
 * 'flags' is placed in hdr->flags (e.g. shutdown bits, EOM/EOR bits).
 * Must NOT be called with socket buffer locks held.
 * Must be called with vtvsock_mtx held to serialize TX virtqueue access.
 */
static int
vtvsock_send_pkt_locked(struct vtvsock_pcb *pcb, uint16_t op, uint32_t flags,
    const void *payload, size_t payload_len)
{
	struct vtvsock_softc *sc;
	struct virtio_vsock_hdr *hdr;
	struct sglist_seg segs[2];
	struct sglist sg;
	uint8_t *pkt;
	int error;

	sc = vtvsock_global_softc();
	if (sc == NULL || sc->sc_txvq == NULL)
		return (ENXIO);

	pkt = malloc(sizeof(*hdr) + payload_len, M_VTVSOCK, M_NOWAIT);
	if (pkt == NULL)
		return (ENOMEM);

	hdr = (struct virtio_vsock_hdr *)pkt;
	hdr->src_cid    = htole64(pcb->local.svm_cid);
	hdr->dst_cid    = htole64(pcb->remote.svm_cid);
	hdr->src_port   = htole32(pcb->local.svm_port);
	hdr->dst_port   = htole32(pcb->remote.svm_port);
	hdr->len        = htole32((uint32_t)payload_len);
	hdr->type       = htole16((pcb->so->so_type == SOCK_SEQPACKET) ?
	    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM);
	hdr->op         = htole16(op);
	hdr->flags      = htole32(flags);
	/* Always stamp current credit state so peer can update. */
	hdr->buf_alloc  = htole32(pcb->buf_alloc);
	hdr->fwd_cnt    = htole32(pcb->fwd_cnt);

	if (payload_len != 0 && payload != NULL)
		memcpy(pkt + sizeof(*hdr), payload, payload_len);

	sglist_init(&sg, 2, segs);
	error = sglist_append(&sg, pkt, sizeof(*hdr) + payload_len);
	if (error != 0) {
		free(pkt, M_VTVSOCK);
		return (error);
	}
	error = virtqueue_enqueue(sc->sc_txvq, pkt, &sg, sg.sg_nseg, 0);
	if (error != 0) {
		free(pkt, M_VTVSOCK);
		return (error == ENOSPC ? EWOULDBLOCK : error);
	}
	virtqueue_notify(sc->sc_txvq);
	counter_u64_add(vtvsock_cnt_tx_packets, 1);
	counter_u64_add(vtvsock_cnt_tx_bytes, payload_len);
	return (0);
}

/*
 * Send an RST for a connection that has no corresponding PCB, or that
 * we're forcibly resetting.  Caller provides addresses explicitly because
 * the PCB may be gone or incompletely initialized.
 *
 * 'type' should match the connection's socket type (VIRTIO_VSOCK_TYPE_STREAM
 * or VIRTIO_VSOCK_TYPE_SEQPACKET).  Use VIRTIO_VSOCK_TYPE_STREAM as the
 * default when the type is unknown (e.g. no PCB).
 *
 * Must be called with vtvsock_mtx held to serialize TX virtqueue access.
 */
static int
vtvsock_send_rst_locked(struct vtvsock_softc *sc, uint64_t src_cid,
    uint32_t src_port, uint64_t dst_cid, uint32_t dst_port, uint16_t type)
{
	struct virtio_vsock_hdr *hdr;
	struct sglist_seg segs[1];
	struct sglist sg;
	int error;

	if (sc == NULL || sc->sc_txvq == NULL)
		return (ENXIO);

	hdr = malloc(sizeof(*hdr), M_VTVSOCK, M_NOWAIT | M_ZERO);
	if (hdr == NULL)
		return (ENOMEM);

	hdr->src_cid   = htole64(src_cid);
	hdr->dst_cid   = htole64(dst_cid);
	hdr->src_port  = htole32(src_port);
	hdr->dst_port  = htole32(dst_port);
	hdr->len       = htole32(0);
	hdr->type      = htole16(type);
	hdr->op        = htole16(VIRTIO_VSOCK_OP_RST);
	hdr->flags     = htole32(0);
	hdr->buf_alloc = htole32(0);
	hdr->fwd_cnt   = htole32(0);

	sglist_init(&sg, 1, segs);
	error = sglist_append(&sg, hdr, sizeof(*hdr));
	if (error != 0) {
		free(hdr, M_VTVSOCK);
		return (error);
	}
	error = virtqueue_enqueue(sc->sc_txvq, hdr, &sg, sg.sg_nseg, 0);
	if (error != 0) {
		free(hdr, M_VTVSOCK);
		return (error == ENOSPC ? EWOULDBLOCK : error);
	}
	virtqueue_notify(sc->sc_txvq);
	return (0);
}

/*
 * Send a CREDIT_UPDATE to the peer so it knows we've freed RX buffer space.
 * Must be called with vtvsock_mtx held.
 */
static void
vtvsock_send_credit_update_locked(struct vtvsock_pcb *pcb)
{
	if (pcb->state != VTVSOCK_ESTABLISHED)
		return;
	(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
	    0, NULL, 0);
	pcb->last_fwd_cnt = pcb->fwd_cnt;
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
static void
vtvsock_close_timeout(void *arg)
{
	struct vtvsock_pcb *pcb = arg;
	struct socket *so;
	struct vtvsock_softc *sc;

	so = pcb->so;
	if (so == NULL)
		return;

	sc = vtvsock_global_softc();
	if (sc != NULL && pcb->state == VTVSOCK_CLOSING) {
		(void)vtvsock_send_rst_locked(sc,
		    pcb->local.svm_cid, pcb->local.svm_port,
		    pcb->remote.svm_cid, pcb->remote.svm_port,
		    (so->so_type == SOCK_SEQPACKET) ?
		    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM);
	}
	pcb->state = VTVSOCK_CLOSED;
	vtvsock_pcb_remove_lists_locked(pcb);

	SOCK_RECVBUF_LOCK(so);
	socantrcvmore_locked(so);
	SOCK_SENDBUF_LOCK(so);
	socantsendmore_locked(so);
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
	struct vtvsock_softc *sc;

	(void)proto;
	(void)td;

	if (so->so_type != SOCK_STREAM && so->so_type != SOCK_SEQPACKET)
		return (EPROTOTYPE);

	sc = vtvsock_global_softc();

	/*
	 * SEQPACKET requires VIRTIO_VSOCK_F_SEQPACKET to have been
	 * negotiated with the host.  Loopback-only SEQPACKET is still
	 * permitted when no device is attached (sc == NULL).
	 */
	if (so->so_type == SOCK_SEQPACKET) {
		if (sc != NULL &&
		    !(sc->sc_features & VIRTIO_VSOCK_F_SEQPACKET))
			return (EPROTONOSUPPORT);
	}

	/*
	 * §5.10.3.1: If F_NO_IMPLIED_STREAM was negotiated and
	 * F_STREAM was not, STREAM sockets are not supported.
	 * If no device is present, or F_NO_IMPLIED_STREAM was not
	 * negotiated, STREAM support is implied.
	 */
	if (so->so_type == SOCK_STREAM) {
		if (sc != NULL &&
		    (sc->sc_features & VIRTIO_VSOCK_F_NO_IMPLIED_STREAM) &&
		    !(sc->sc_features & VIRTIO_VSOCK_F_STREAM))
			return (EPROTONOSUPPORT);
	}

	pcb = vtvsock_pcb_alloc(so);
	so->so_pcb = pcb;
	return (soreserve(so, VTVSOCK_DEFAULT_BUF_ALLOC,
	    VTVSOCK_DEFAULT_BUF_ALLOC));
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

	if (svm->svm_cid == VSOCK_CID_ANY || svm->svm_cid == 0) {
		if (vtvsock_guest_cid == UINT64_MAX)
			return (ENXIO);
		svm->svm_cid = vtvsock_guest_cid;
	}
	if (svm->svm_cid != vtvsock_guest_cid)
		return (EAFNOSUPPORT);

	mtx_lock(&vtvsock_mtx);
	if (pcb->on_boundlist) {
		/* Already bound; remove from list to re-bind. */
		LIST_REMOVE(pcb, link);
		pcb->on_boundlist = false;
	}
	if (svm->svm_port == 0 || svm->svm_port == VSOCK_PORT_ANY) {
		int tries;
		for (tries = 0; tries < 65536; tries++) {
			svm->svm_port = 1024 +
			    (arc4random() % (VSOCK_PORT_ANY - 1024));
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
	int error;

	(void)td;

	if (pcb == NULL || dst == NULL)
		return (EINVAL);
	if (dst->svm_family != AF_VSOCK ||
	    dst->svm_len != sizeof(*dst))
		return (EINVAL);
	if (dst->svm_reserved1 != 0)
		return (EINVAL);
	if (vtvsock_guest_cid == UINT64_MAX)
		return (ENXIO);

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

	/* Assign a local port if not already bound. */
	if (pcb->local.svm_port == VSOCK_PORT_ANY ||
	    pcb->local.svm_port == 0) {
		uint32_t port;
		int tries;
		for (tries = 0; tries < 65536; tries++) {
			port = 1024 +
			    (arc4random() % (VSOCK_PORT_ANY - 1024));
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
		if (listener == NULL || listener->state != VTVSOCK_LISTEN) {
			vtvsock_pcb_remove_lists_locked(pcb);
			pcb->state = VTVSOCK_CLOSED;
			mtx_unlock(&vtvsock_mtx);
			return (ECONNREFUSED);
		}

		child_so = sonewconn(listener->so, 0);
		if (child_so == NULL) {
			vtvsock_pcb_remove_lists_locked(pcb);
			pcb->state = VTVSOCK_CLOSED;
			mtx_unlock(&vtvsock_mtx);
			return (ECONNREFUSED);
		}
		child = child_so->so_pcb;
		child->local = listener->local;
		child->remote = pcb->local;
		child->peer = pcb;
		child->state = VTVSOCK_ESTABLISHED;
		child->transport = &vtvsock_local_transport;
		/* Inherit credit defaults. */
		child->buf_alloc = VTVSOCK_DEFAULT_BUF_ALLOC;
		child->peer_buf_alloc = pcb->buf_alloc;
		vtvsock_pcb_insert_connected_locked(child);

		pcb->peer = child;
		pcb->state = VTVSOCK_ESTABLISHED;
		pcb->transport = &vtvsock_local_transport;
		pcb->peer_buf_alloc = child->buf_alloc;
		vtvsock_pcb_insert_connected_locked(pcb);

		soisconnecting(so);
		soisconnected(so);
		soisconnected(child_so);
		mtx_unlock(&vtvsock_mtx);
		return (0);
	}

	/* ---- Virtio remote path ---- */
	/*
	 * The virtio-vsock wire protocol uses 64-bit CIDs, but current
	 * hypervisors only assign 32-bit values.  Reject oversized CIDs
	 * early so we don't send a CID the host can't match.
	 */
	if (dst->svm_cid > UINT32_MAX) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		mtx_unlock(&vtvsock_mtx);
		return (EAFNOSUPPORT);
	}
	pcb->state = VTVSOCK_CONNECTING;
	pcb->transport = &vtvsock_virtio_transport;
	vtvsock_pcb_insert_connected_locked(pcb);
	soisconnecting(so);

	error = vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_REQUEST, 0,
	    NULL, 0);
	if (error != 0) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		mtx_unlock(&vtvsock_mtx);
		return (error);
	}

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

	if (error == 0 && pcb->state != VTVSOCK_ESTABLISHED)
		error = so->so_error != 0 ? so->so_error : ECONNREFUSED;
	if (error != 0) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
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
	 * Intercept SOL_SOCKET / SO_RCVLOWAT: after the generic handler
	 * applies the new low-water mark, send a CREDIT_UPDATE to the peer
	 * if rx_bytes is below the new threshold (Linux parity:
	 * notify_set_rcvlowat).
	 */
	if (sopt->sopt_level == SOL_SOCKET &&
	    sopt->sopt_name == SO_RCVLOWAT &&
	    sopt->sopt_dir == SOPT_SET) {
		error = sosetopt(so, sopt);
		if (error != 0)
			return (error);
		mtx_lock(&vtvsock_mtx);
		if (pcb->state == VTVSOCK_ESTABLISHED &&
		    pcb->transport == &vtvsock_virtio_transport &&
		    pcb->rx_bytes < (uint32_t)so->so_rcv.sb_lowat)
			vtvsock_send_credit_update_locked(pcb);
		mtx_unlock(&vtvsock_mtx);
		return (0);
	}

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
			pcb->buf_alloc = (uint32_t)MIN(val64, UINT32_MAX);
			if (pcb->state == VTVSOCK_ESTABLISHED &&
			    pcb->transport == &vtvsock_virtio_transport)
				vtvsock_send_credit_update_locked(pcb);
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
	pcb = so->so_pcb;
	if (pcb != NULL && pcb->transport == &vtvsock_virtio_transport &&
	    pcb->state == VTVSOCK_ESTABLISHED) {
		SOCK_RECVBUF_LOCK(so);
		after = (uint32_t)sbavail(&so->so_rcv);
		SOCK_RECVBUF_UNLOCK(so);

		if (before > after) {
			consumed = before - after;
			mtx_lock(&vtvsock_mtx);
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
			if (unreported >= pcb->buf_alloc -
			    VTVSOCK_MAX_PKT_BUF ||
			    pcb->rx_bytes < (uint32_t)so->so_rcv.sb_lowat)
				vtvsock_send_credit_update_locked(pcb);
			mtx_unlock(&vtvsock_mtx);
		}
	}

	/*
	 * For local loopback, wake the peer's send path which may be
	 * sleeping in vtvsock_local_send waiting for receive buffer space.
	 */
	if (error == 0 && pcb != NULL &&
	    pcb->transport == &vtvsock_local_transport) {
		SOCK_RECVBUF_LOCK(so);
		after = (uint32_t)sbavail(&so->so_rcv);
		SOCK_RECVBUF_UNLOCK(so);
		if (before > after) {
			mtx_lock(&vtvsock_mtx);
			if (pcb->peer != NULL)
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
	return (pcb->transport->send(pcb, flags, m, addr, control, td));
}

static int
vsock_disconnect(struct socket *so)
{
	struct vtvsock_pcb *pcb = so->so_pcb;

	if (pcb == NULL)
		return (EINVAL);
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

	SOCK_RECVBUF_LOCK(so);
	socantrcvmore_locked(so);
	SOCK_SENDBUF_LOCK(so);
	socantsendmore_locked(so);
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
		mtx_unlock(&vtvsock_mtx);
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
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
		mtx_unlock(&vtvsock_mtx);
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
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
 * Virtio remote transport
 * ---------------------------------------------------------------------- */

/*
 * Send data over the virtio TX queue.
 *
 * Each message is sent as one or more virtio packets capped at
 * VTVSOCK_MAX_PKT_BUF bytes each, subject to credit availability.
 * For SEQPACKET, EOM|EOR is set on the last fragment.
 *
 * On virtqueue_enqueue failure, return the consumed credit.
 */
static int
vtvsock_virtio_send(struct vtvsock_pcb *pcb, int flags, struct mbuf *m,
    struct sockaddr *addr, struct mbuf *control, struct thread *td)
{
	struct vtvsock_softc *sc;
	struct virtio_vsock_hdr *hdr;
	struct sglist_seg segs[2];
	struct sglist sg;
	uint8_t *buf;
	size_t total, offset, chunk;
	uint32_t credit;
	uint32_t pkt_flags;
	bool seqpacket;
	int error;

	(void)flags;	/* PRUS_*; MSG_EOR arrives via M_EOR on the mbuf */
	(void)addr;
	(void)td;

	if (control != NULL) {
		m_freem(control);
		control = NULL;
	}

	sc = vtvsock_global_softc();
	if (sc == NULL) {
		m_freem(m);
		return (ENXIO);
	}

	total = m_length(m, NULL);
	if (total == 0) {
		m_freem(m);
		return (0);
	}

	seqpacket = (pcb->so->so_type == SOCK_SEQPACKET);
	offset = 0;
	error = 0;

	mtx_lock(&vtvsock_mtx);

	while (offset < total) {
		chunk = MIN(total - offset, (size_t)VTVSOCK_MAX_PKT_BUF);

		/* Check send credit; sleep if exhausted and blocking. */
		for (;;) {
			credit = vtvsock_get_credit(pcb, (uint32_t)chunk);
			if (credit != 0)
				break;
			if (pcb->state != VTVSOCK_ESTABLISHED) {
				error = EPIPE;
				goto out;
			}
			if (pcb->so->so_state & SS_NBIO) {
				error = EWOULDBLOCK;
				goto out;
			}
			/* Sleep until CREDIT_UPDATE wakes us. */
			error = msleep(&pcb->tx_cnt, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsocktx", hz);
			if (error != 0) {
				if (error == EWOULDBLOCK)
					continue; /* timeout: retry */
				goto out;
			}
		}
		chunk = MIN(chunk, (size_t)credit);

		buf = malloc(sizeof(*hdr) + chunk, M_VTVSOCK, M_NOWAIT);
		if (buf == NULL) {
			/* Return credit consumed by vtvsock_get_credit. */
			pcb->tx_cnt -= (uint32_t)chunk;
			error = ENOMEM;
			break;
		}

		hdr = (struct virtio_vsock_hdr *)buf;
		hdr->src_cid   = htole64(pcb->local.svm_cid);
		hdr->dst_cid   = htole64(pcb->remote.svm_cid);
		hdr->src_port  = htole32(pcb->local.svm_port);
		hdr->dst_port  = htole32(pcb->remote.svm_port);
		hdr->len       = htole32((uint32_t)chunk);
		hdr->type      = htole16(seqpacket ?
		    VIRTIO_VSOCK_TYPE_SEQPACKET : VIRTIO_VSOCK_TYPE_STREAM);
		hdr->op        = htole16(VIRTIO_VSOCK_OP_RW);
		hdr->buf_alloc = htole32(pcb->buf_alloc);
		hdr->fwd_cnt   = htole32(pcb->fwd_cnt);

		/*
		 * EOM on the final fragment of a SEQPACKET message.
		 * EOR only when the application passed MSG_EOR
		 * (propagated as M_EOR on the mbuf by sosend_generic).
		 */
		pkt_flags = 0;
		if (seqpacket && (offset + chunk >= total)) {
			pkt_flags = VIRTIO_VSOCK_SEQ_EOM;
			if (m->m_flags & M_EOR)
				pkt_flags |= VIRTIO_VSOCK_SEQ_EOR;
		}
		hdr->flags = htole32(pkt_flags);

		m_copydata(m, (int)offset, (int)chunk, buf + sizeof(*hdr));

		sglist_init(&sg, 2, segs);
		error = sglist_append(&sg, buf,
		    sizeof(*hdr) + chunk);
		if (error != 0) {
			/* Return credit on sglist failure. */
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			break;
		}
		error = virtqueue_enqueue(sc->sc_txvq, buf, &sg,
		    sg.sg_nseg, 0);
		if (error != 0) {
			/* Return credit on enqueue failure. */
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			if (error == ENOSPC)
				error = EWOULDBLOCK;
			break;
		}
		virtqueue_notify(sc->sc_txvq);
		offset += chunk;
	}

out:
	/*
	 * For SEQPACKET, partial sends leave orphaned fragments in the
	 * peer's reassembly buffer (no EOM).  The fragments are already
	 * on the wire, so the peer will accumulate them in
	 * seqpacket_partial with no EOM ever arriving.  Send RST to
	 * force the peer to tear down the connection and discard the
	 * incomplete record.  Do NOT roll back tx_cnt — the peer has
	 * already received those bytes and accounted for them.
	 */
	if (seqpacket && offset > 0 && offset < total) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		(void)vtvsock_send_rst_locked(sc,
		    pcb->local.svm_cid, pcb->local.svm_port,
		    pcb->remote.svm_cid, pcb->remote.svm_port,
		    VIRTIO_VSOCK_TYPE_SEQPACKET);
		wakeup(&pcb->state);
		error = (error != 0) ? error : EIO;
		offset = 0;
	}
	mtx_unlock(&vtvsock_mtx);
	m_freem(m);

	return (offset > 0 ? 0 : error);
}

/*
 * Gracefully close the virtio connection.
 * Send OP_SHUTDOWN both directions, then arm the close timeout.
 */
static int
vtvsock_virtio_disconnect(struct vtvsock_pcb *pcb)
{
	struct socket *so = pcb->so;
	uint32_t shut_flags;

	mtx_lock(&vtvsock_mtx);

	if (pcb->state == VTVSOCK_ESTABLISHED ||
	    pcb->state == VTVSOCK_CONNECTING) {
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV |
		    VIRTIO_VSOCK_SHUTDOWN_SEND;
		(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
		    shut_flags, NULL, 0);
		pcb->state = VTVSOCK_CLOSING;
		callout_reset(&pcb->close_callout, VTVSOCK_CLOSE_TIMEOUT,
		    vtvsock_close_timeout, pcb);
		soisdisconnecting(so);
	} else if (pcb->state != VTVSOCK_CLOSED) {
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		soisdisconnected(so);
	}

	mtx_unlock(&vtvsock_mtx);
	return (0);
}

static int
vtvsock_virtio_shutdown(struct vtvsock_pcb *pcb, enum shutdown_how how)
{
	struct socket *so = pcb->so;
	uint32_t shut_flags;

	shut_flags = 0;
	switch (how) {
	case SHUT_RD:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV;
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		break;
	case SHUT_WR:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_SEND;
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	case SHUT_RDWR:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV |
		    VIRTIO_VSOCK_SHUTDOWN_SEND;
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	}

	mtx_lock(&vtvsock_mtx);
	(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
	    shut_flags, NULL, 0);
	mtx_unlock(&vtvsock_mtx);
	return (0);
}

/* -----------------------------------------------------------------------
 * RX virtqueue handling
 * ---------------------------------------------------------------------- */

/*
 * Refill the RX virtqueue with receive buffers.
 * Each buffer is large enough for the header plus max payload.
 */
static int
vtvsock_queue_rx_buffers(struct vtvsock_softc *sc)
{
	struct sglist_seg segs[1];
	struct sglist sg;
	void *buf;
	int error;

	sglist_init(&sg, 1, segs);
	while (!virtqueue_full(sc->sc_rxvq)) {
		buf = malloc(VTVSOCK_RX_BUFSZ, M_VTVSOCK, M_NOWAIT | M_ZERO);
		if (buf == NULL)
			return (ENOMEM);
		error = sglist_append(&sg, buf, VTVSOCK_RX_BUFSZ);
		if (error != 0) {
			free(buf, M_VTVSOCK);
			return (error);
		}
		error = virtqueue_enqueue(sc->sc_rxvq, buf, &sg, 0, sg.sg_nseg);
		sglist_reset(&sg);
		if (error != 0) {
			free(buf, M_VTVSOCK);
			if (error == ENOSPC)
				return (0);
			return (error);
		}
	}
	virtqueue_notify(sc->sc_rxvq);
	return (0);
}

/*
 * Process one received virtio packet.
 *
 * Called from vtvsock_rx_intr() with no locks held.  Acquires vtvsock_mtx
 * around list lookups and PCB state changes, then releases it before
 * acquiring socket buffer locks.
 *
 * All header fields are decoded from little-endian.  fwd_cnt is NOT
 * incremented here; that happens in vsock_soreceive.  Peer credit state
 * is extracted from every packet before the opcode switch.
 */
static void
vtvsock_handle_rx_packet(struct vtvsock_softc *sc, void *buf, uint32_t len)
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

	if (len < sizeof(*hdr)) {
		free(buf, M_VTVSOCK);
		return;
	}
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
		(void)vtvsock_send_rst_locked(sc,
		    hdr_dst_cid, hdr_dst_port,
		    hdr_src_cid, hdr_src_port, hdr_type);
		mtx_unlock(&vtvsock_mtx);
		free(buf, M_VTVSOCK);
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
			(void)vtvsock_send_rst_locked(sc,
			    hdr_dst_cid, hdr_dst_port,
			    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			free(buf, M_VTVSOCK);
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
			if (hdr_op != VIRTIO_VSOCK_OP_RST) {
				(void)vtvsock_send_rst_locked(sc,
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port,
				    hdr_type);
			}
			mtx_unlock(&vtvsock_mtx);
			free(buf, M_VTVSOCK);
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
			(void)vtvsock_send_rst_locked(sc,
			    hdr_dst_cid, hdr_dst_port,
			    hdr_src_cid, hdr_src_port, hdr_type);
			mtx_unlock(&vtvsock_mtx);
			free(buf, M_VTVSOCK);
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
				(void)vtvsock_send_rst_locked(sc,
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port, hdr_type);
				mtx_unlock(&vtvsock_mtx);
				free(buf, M_VTVSOCK);
				return;
			}

			child_so = sonewconn(so, 0);
			if (child_so == NULL) {
				/* Backlog full; reject. */
				(void)vtvsock_send_rst_locked(sc,
				    hdr_dst_cid, hdr_dst_port,
				    hdr_src_cid, hdr_src_port,
				    hdr_type);
				mtx_unlock(&vtvsock_mtx);
				free(buf, M_VTVSOCK);
				return;
			}
			child = child_so->so_pcb;
			child->local = pcb->local;
			vtvsock_pcb_set_addr(&child->remote,
			    hdr_src_cid, hdr_src_port);
			child->state = VTVSOCK_ESTABLISHED;
			child->transport = &vtvsock_virtio_transport;
			/* Credit from peer (already decoded above). */
			child->peer_buf_alloc = hdr_buf_alloc;
			child->peer_fwd_cnt   = hdr_fwd_cnt;
			child->buf_alloc = VTVSOCK_DEFAULT_BUF_ALLOC;
			vtvsock_pcb_insert_connected_locked(child);

			/* Send OP_RESPONSE using the child's addresses. */
			(void)vtvsock_send_pkt_locked(child,
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
			(void)vtvsock_send_rst_locked(sc,
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
				if (partial_len + payload_len > pcb->buf_alloc) {
					m_freem(m);
					teardown_rst = true;
					teardown_errno = EMSGSIZE;
					goto teardown_close;
				}
				m_cat(pcb->seqpacket_partial, m);
				m = NULL;
			} else {
				pcb->seqpacket_partial = m;
				m = NULL;
			}

			if (hdr_flags & VIRTIO_VSOCK_SEQ_EOM) {
				/* EOM set: deliver the complete record. */
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
		vtvsock_send_credit_update_locked(pcb);
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

	free(buf, M_VTVSOCK);
	return;

teardown_close:
	counter_u64_add(vtvsock_cnt_rx_drops, 1);
	callout_stop(&pcb->close_callout);
	callout_stop(&pcb->connect_callout);
	vtvsock_pcb_remove_lists_locked(pcb);
	pcb->state = VTVSOCK_CLOSED;
	wakeup(&pcb->state);
	wakeup(&pcb->tx_cnt);
	if (teardown_rst)
		(void)vtvsock_send_rst_locked(sc,
		    hdr_dst_cid, hdr_dst_port,
		    hdr_src_cid, hdr_src_port, hdr_type);
	mtx_unlock(&vtvsock_mtx);
	if (teardown_errno != 0) {
		SOCK_LOCK(so);
		so->so_error = teardown_errno;
		SOCK_UNLOCK(so);
	}
	SOCK_RECVBUF_LOCK(so);
	socantrcvmore_locked(so);
	SOCK_SENDBUF_LOCK(so);
	socantsendmore_locked(so);
	soisdisconnected(so);
	free(buf, M_VTVSOCK);
	return;
}

/*
 * Handle the event virtqueue.
 * VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: tear down all connections.
 */
static void
vtvsock_reset_all_locked(struct vtvsock_softc *sc)
{
	struct vtvsock_pcb *pcb, *tmp;
	struct socket *so;

	/* Reset all connected sockets. */
	LIST_FOREACH_SAFE(pcb, &vtvsock_conn, connlink, tmp) {
		so = pcb->so;
		callout_stop(&pcb->close_callout);
		callout_stop(&pcb->connect_callout);
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		wakeup(&pcb->state);
		SOCK_LOCK(so);
		so->so_error = ECONNRESET;
		SOCK_UNLOCK(so);
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		soisdisconnected(so);
	}
}

/* -----------------------------------------------------------------------
 * Virtqueue interrupt handlers
 * ---------------------------------------------------------------------- */

static void
vtvsock_rx_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	void *buf;
	uint32_t len;

	while ((buf = virtqueue_dequeue(sc->sc_rxvq, &len)) != NULL)
		vtvsock_handle_rx_packet(sc, buf, len);

	(void)vtvsock_queue_rx_buffers(sc);
}

static void
vtvsock_tx_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	void *buf;

	/*
	 * Reclaim completed TX descriptors.
	 * Must hold vtvsock_mtx to serialize with vtvsock_send_pkt_locked()
	 * and vtvsock_virtio_send() which enqueue to the same virtqueue.
	 */
	mtx_lock(&vtvsock_mtx);
	while ((buf = virtqueue_dequeue(sc->sc_txvq, NULL)) != NULL)
		free(buf, M_VTVSOCK);
	mtx_unlock(&vtvsock_mtx);
}

/*
 * Event virtqueue interrupt handler.
 */
static void
vtvsock_event_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	struct virtio_vsock_event *evt;
	uint32_t len;

	while ((evt = virtqueue_dequeue(sc->sc_eventvq, &len)) != NULL) {
		if (len >= sizeof(*evt)) {
			if (le32toh(evt->id) ==
			    VIRTIO_VSOCK_EVENT_TRANSPORT_RESET) {
				/* Guest CID may have changed; re-read it. */
				virtio_read_device_config(sc->sc_dev, 0,
				    &sc->sc_guest_cid,
				    sizeof(sc->sc_guest_cid));
				vtvsock_guest_cid =
				    le64toh(sc->sc_guest_cid);

				mtx_lock(&vtvsock_mtx);
				/*
				 * Update listener CIDs to the new guest CID
				 * so they remain operational per §5.10.6.7.1.
				 */
				{
					struct vtvsock_pcb *lpcb;
					LIST_FOREACH(lpcb, &vtvsock_bound, link) {
						if (lpcb->state == VTVSOCK_LISTEN)
							lpcb->local.svm_cid =
							    vtvsock_guest_cid;
					}
				}
				vtvsock_reset_all_locked(sc);
				mtx_unlock(&vtvsock_mtx);
			}
		}
		/* Re-enqueue event buffer. */
		{
			struct sglist_seg segs[1];
			struct sglist sg;
			int evterr;

			sglist_init(&sg, 1, segs);
			evterr = sglist_append(&sg, evt, sizeof(*evt));
			if (evterr == 0)
				evterr = virtqueue_enqueue(sc->sc_eventvq,
				    evt, &sg, 0, sg.sg_nseg);
			if (evterr != 0) {
				device_printf(sc->sc_dev,
				    "failed to re-enqueue event buffer\n");
				free(evt, M_VTVSOCK);
			}
		}
	}
	virtqueue_notify(sc->sc_eventvq);
}

/* -----------------------------------------------------------------------
 * VirtIO device probe / attach / detach
 * ---------------------------------------------------------------------- */

static int
vtvsock_probe(device_t dev)
{
	if (virtio_get_device_type(dev) != VIRTIO_ID_VSOCK)
		return (ENXIO);
	device_set_desc(dev, "VirtIO VSOCK Transport");
	return (BUS_PROBE_DEFAULT);
}

/*
 * VirtIO device attach: negotiate features, set up virtqueues, read CID.
 */
static int
vtvsock_attach(device_t dev)
{
	struct vtvsock_softc *sc;
	struct vq_alloc_info vq_info[VTVSOCK_MAXQ];
	struct virtio_vsock_event *evt;
	struct sglist_seg segs[1];
	struct sglist sg;
	int i, error;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	mtx_init(&sc->sc_mtx, "vtvsock", NULL, MTX_DEF);

	vtvsock_cnt_tx_packets = counter_u64_alloc(M_WAITOK);
	vtvsock_cnt_tx_bytes = counter_u64_alloc(M_WAITOK);
	vtvsock_cnt_rx_packets = counter_u64_alloc(M_WAITOK);
	vtvsock_cnt_rx_bytes = counter_u64_alloc(M_WAITOK);
	vtvsock_cnt_rx_drops = counter_u64_alloc(M_WAITOK);
	vtvsock_cnt_conns = counter_u64_alloc(M_WAITOK);

	virtio_set_feature_desc(dev, vtvsock_feature_desc);
	sc->sc_features = virtio_negotiate_features(dev,
	    VIRTIO_VSOCK_F_STREAM |
	    VIRTIO_VSOCK_F_SEQPACKET |
	    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM);
	error = virtio_finalize_features(dev);
	if (error != 0)
		goto fail;

	VQ_ALLOC_INFO_INIT(&vq_info[0], 0, vtvsock_rx_intr, sc, &sc->sc_rxvq,
	    "%s rx", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[1], 0, vtvsock_tx_intr, sc, &sc->sc_txvq,
	    "%s tx", device_get_nameunit(dev));
	VQ_ALLOC_INFO_INIT(&vq_info[2], 0, vtvsock_event_intr, sc,
	    &sc->sc_eventvq, "%s event", device_get_nameunit(dev));

	error = virtio_alloc_virtqueues(dev, VTVSOCK_MAXQ, vq_info);
	if (error != 0)
		goto fail;

	error = virtio_setup_intr(dev, INTR_TYPE_MISC | INTR_MPSAFE);
	if (error != 0)
		goto fail;

	/*
	 * Read the guest CID from device config.  The virtio device config
	 * is little-endian; convert with le64toh() before storing into our
	 * host-endian global.
	 */
	virtio_read_device_config(dev, 0, &sc->sc_guest_cid,
	    sizeof(sc->sc_guest_cid));
	vtvsock_guest_cid = le64toh(sc->sc_guest_cid);

	/* Pre-populate RX virtqueue. */
	error = vtvsock_queue_rx_buffers(sc);
	if (error != 0)
		goto fail;

	/* Pre-populate event virtqueue with a handful of event buffers. */
	sglist_init(&sg, 1, segs);
	for (i = 0; i < 4; i++) {
		evt = malloc(sizeof(*evt), M_VTVSOCK, M_WAITOK | M_ZERO);
		sglist_reset(&sg);
		if (sglist_append(&sg, evt, sizeof(*evt)) != 0) {
			free(evt, M_VTVSOCK);
			break;
		}
		if (virtqueue_enqueue(sc->sc_eventvq, evt, &sg, 0,
		    sg.sg_nseg) != 0) {
			free(evt, M_VTVSOCK);
			break;
		}
	}
	virtqueue_notify(sc->sc_eventvq);

	/* Publish the softc globally so the socket layer can find it. */
	atomic_store_ptr(&vtvsock_sc, sc);

	return (0);

fail:
	counter_u64_free(vtvsock_cnt_tx_packets);
	counter_u64_free(vtvsock_cnt_tx_bytes);
	counter_u64_free(vtvsock_cnt_rx_packets);
	counter_u64_free(vtvsock_cnt_rx_bytes);
	counter_u64_free(vtvsock_cnt_rx_drops);
	counter_u64_free(vtvsock_cnt_conns);
	virtio_stop(dev);
	mtx_destroy(&sc->sc_mtx);
	return (error);
}

static int
vtvsock_detach(device_t dev)
{
	struct vtvsock_softc *sc;
	void *buf;

	sc = device_get_softc(dev);

	/* Stop accepting new traffic and reset all open connections. */
	atomic_store_ptr(&vtvsock_sc, NULL);

	mtx_lock(&vtvsock_mtx);
	vtvsock_reset_all_locked(sc);
	mtx_unlock(&vtvsock_mtx);

	virtio_stop(dev);

	/* Drain TX queue: free any pending TX buffers. */
	if (sc->sc_txvq != NULL) {
		while ((buf = virtqueue_dequeue(sc->sc_txvq, NULL)) != NULL)
			free(buf, M_VTVSOCK);
	}
	/* Drain RX queue. */
	if (sc->sc_rxvq != NULL) {
		while ((buf = virtqueue_dequeue(sc->sc_rxvq, NULL)) != NULL)
			free(buf, M_VTVSOCK);
	}
	/* Drain event queue. */
	if (sc->sc_eventvq != NULL) {
		while ((buf = virtqueue_dequeue(sc->sc_eventvq, NULL)) != NULL)
			free(buf, M_VTVSOCK);
	}

	counter_u64_free(vtvsock_cnt_tx_packets);
	counter_u64_free(vtvsock_cnt_tx_bytes);
	counter_u64_free(vtvsock_cnt_rx_packets);
	counter_u64_free(vtvsock_cnt_rx_bytes);
	counter_u64_free(vtvsock_cnt_rx_drops);
	counter_u64_free(vtvsock_cnt_conns);

	mtx_destroy(&sc->sc_mtx);
	return (0);
}

/* -----------------------------------------------------------------------
 * Module glue
 * ---------------------------------------------------------------------- */

static device_method_t vtvsock_methods[] = {
	DEVMETHOD(device_probe,		vtvsock_probe),
	DEVMETHOD(device_attach,	vtvsock_attach),
	DEVMETHOD(device_detach,	vtvsock_detach),
	DEVMETHOD_END
};

static driver_t vtvsock_driver = {
	"virtio_vsock",
	vtvsock_methods,
	sizeof(struct vtvsock_softc)
};

VIRTIO_DRIVER_MODULE(virtio_vsock, vtvsock_driver, NULL, NULL);
MODULE_VERSION(virtio_vsock, 1);
MODULE_DEPEND(virtio_vsock, virtio, 1, 1, 1);
VIRTIO_SIMPLE_PNPINFO(virtio_vsock, VIRTIO_ID_VSOCK,
    "VirtIO VSOCK Transport");
