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
 * VirtIO VSOCK PCI transport driver.
 *
 * This file implements the VirtIO PCI device driver for the vsock transport
 * (OASIS virtio v1.3, section 5.10).  It manages:
 *   - Device probe / attach / detach lifecycle
 *   - RX / TX / event virtqueue setup and interrupt handling
 *   - Packet transmission (send_pkt, send_rst, send_credit_update)
 *   - Transport operations dispatched from the AF_VSOCK socket domain
 *
 * The AF_VSOCK socket domain (PCB management, socket ops, protocol state
 * machine, loopback transport, RX packet handling) lives in kern/uipc_vsock.c.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/sglist.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/sdt.h>
#include <sys/vsock.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

#include <kern/uipc_vsock.h>

SDT_PROVIDER_DECLARE(vsock);
SDT_PROBE_DEFINE3(vsock, , , credit__stall,
    "uint32_t",	/* peer_buf_alloc */
    "uint32_t",	/* tx_cnt */
    "uint32_t");	/* peer_fwd_cnt */
SDT_PROBE_DEFINE3(vsock, , , credit__update__send,
    "uint32_t",	/* buf_alloc */
    "uint32_t",	/* fwd_cnt */
    "uint32_t");	/* rx_bytes */

/* -----------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define	VTVSOCK_MAXQ			3
#define	VTVSOCK_RX_BUFSZ		(sizeof(struct virtio_vsock_hdr) + \
					 64 * 1024)

/* -----------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------- */

struct vtvsock_softc {
	device_t		 sc_dev;
	struct virtqueue	*sc_rxvq;
	struct virtqueue	*sc_txvq;
	struct virtqueue	*sc_eventvq;
	uint64_t		 sc_features;
	uint64_t		 sc_guest_cid;
};

/* -----------------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------------- */

static _Atomic(struct vtvsock_softc *) vtvsock_sc;

/* -----------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */

static int	vtvsock_virtio_send(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
static int	vtvsock_virtio_disconnect(struct vtvsock_pcb *);
static int	vtvsock_virtio_shutdown(struct vtvsock_pcb *, enum shutdown_how);

static int	vtvsock_queue_rx_buffers(struct vtvsock_softc *);
static int	vtvsock_send_pkt_locked(struct vtvsock_pcb *, uint16_t,
		    uint32_t, const void *, size_t);
static int	vtvsock_send_rst_locked(uint64_t, uint32_t, uint64_t,
		    uint32_t, uint16_t);
static void	vtvsock_send_credit_update_locked(struct vtvsock_pcb *);

static void	vtvsock_rx_intr(void *);
static void	vtvsock_tx_intr(void *);
static void	vtvsock_event_intr(void *);

static struct vtvsock_softc *vtvsock_global_softc(void);

/* -----------------------------------------------------------------------
 * Transport dispatch table
 * ---------------------------------------------------------------------- */

static const struct vtvsock_transport vtvsock_virtio_transport = {
	.send =			vtvsock_virtio_send,
	.disconnect =		vtvsock_virtio_disconnect,
	.shutdown =		vtvsock_virtio_shutdown,
	.send_pkt =		vtvsock_send_pkt_locked,
	.send_rst =		vtvsock_send_rst_locked,
	.send_credit_update =	vtvsock_send_credit_update_locked,
};

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
	if (__predict_false(payload_len > UINT32_MAX)) {
		free(pkt, M_VTVSOCK);
		return (EINVAL);
	}
	hdr->len        = htole32((uint32_t)payload_len);
	KASSERT(pcb->so != NULL, ("%s: pcb %p has NULL so", __func__, pcb));
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
vtvsock_send_rst_locked(uint64_t src_cid, uint32_t src_port,
    uint64_t dst_cid, uint32_t dst_port, uint16_t type)
{
	struct vtvsock_softc *sc;
	struct virtio_vsock_hdr *hdr;
	struct sglist_seg segs[1];
	struct sglist sg;
	int error;

	sc = vtvsock_global_softc();
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
	SDT_PROBE3(vsock, , , credit__update__send,
	    pcb->buf_alloc, pcb->fwd_cnt, pcb->rx_bytes);
	(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
	    0, NULL, 0);
	pcb->last_fwd_cnt = pcb->fwd_cnt;
}

/* -----------------------------------------------------------------------
 * Virtio remote transport operations
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

	total = m_length(m, NULL);
	if (total == 0) {
		m_freem(m);
		return (0);
	}

	KASSERT(pcb->so != NULL, ("%s: pcb %p has NULL so", __func__, pcb));
	seqpacket = (pcb->so->so_type == SOCK_SEQPACKET);
	offset = 0;
	error = 0;

	mtx_lock(&vtvsock_mtx);

	/* Re-check softc under lock to close the detach race window. */
	sc = vtvsock_global_softc();
	if (sc == NULL) {
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (ENXIO);
	}

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
			if (pcb->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) {
				error = EPIPE;
				goto out;
			}
			if (pcb->so->so_state & SS_NBIO) {
				error = EWOULDBLOCK;
				goto out;
			}
			SDT_PROBE3(vsock, , , credit__stall,
			    pcb->peer_buf_alloc, pcb->tx_cnt,
			    pcb->peer_fwd_cnt);
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
		if (error == ENOSPC) {
			/*
			 * TX ring full.  Drain completed descriptors
			 * inline (we hold vtvsock_mtx, so the TX
			 * interrupt can't run) and retry once.
			 *
			 * Linux uses a deferred work queue for this,
			 * but inline drain handles the common case of
			 * stale completions without the complexity.
			 */
			void *txbuf;

			while ((txbuf = virtqueue_dequeue(sc->sc_txvq,
			    NULL)) != NULL)
				free(txbuf, M_VTVSOCK);
			error = virtqueue_enqueue(sc->sc_txvq, buf, &sg,
			    sg.sg_nseg, 0);
		}
		if (error != 0) {
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			if (error == ENOSPC)
				error = EWOULDBLOCK;
			break;
		}
		virtqueue_notify(sc->sc_txvq);
		counter_u64_add(vtvsock_cnt_tx_packets, 1);
		counter_u64_add(vtvsock_cnt_tx_bytes, chunk);
		offset += chunk;
	}

out:
	/*
	 * Handle partial sends (some chunks enqueued, then error).
	 *
	 * SEQPACKET: orphaned fragments have no EOM, leaving the peer's
	 * reassembly buffer in limbo.  RST tears down the connection so
	 * the peer discards the incomplete record.
	 *
	 * STREAM: the sent bytes are on the wire and will be delivered.
	 * The remaining bytes are lost.  We return error to the caller
	 * rather than returning success (which would silently lose data).
	 * The caller (sosend_generic) stops the send and propagates the
	 * error to userspace; the application should treat it as a
	 * partial write and close/reconnect.  Do NOT roll back tx_cnt —
	 * the peer has already received and accounted for those bytes.
	 */
	if (offset > 0 && offset < total) {
		if (seqpacket) {
			vtvsock_pcb_remove_lists_locked(pcb);
			pcb->state = VTVSOCK_CLOSED;
			(void)vtvsock_send_rst_locked(
			    pcb->local.svm_cid, pcb->local.svm_port,
			    pcb->remote.svm_cid, pcb->remote.svm_port,
			    VIRTIO_VSOCK_TYPE_SEQPACKET);
			wakeup(&pcb->state);
			mtx_unlock(&vtvsock_mtx);
			soisdisconnected(pcb->so);
			m_freem(m);
			return (error != 0 ? error : EIO);
		}
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

	/*
	 * Send the shutdown packet under vtvsock_mtx first, then apply
	 * local socket state changes.  This matches the documented lock
	 * ordering (vtvsock_mtx -> sockbuf locks) and keeps the pattern
	 * consistent with vtvsock_local_shutdown.
	 */
	shut_flags = 0;
	switch (how) {
	case SHUT_RD:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV;
		break;
	case SHUT_WR:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_SEND;
		break;
	case SHUT_RDWR:
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV |
		    VIRTIO_VSOCK_SHUTDOWN_SEND;
		break;
	}

	mtx_lock(&vtvsock_mtx);
	(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
	    shut_flags, NULL, 0);
	mtx_unlock(&vtvsock_mtx);

	switch (how) {
	case SHUT_RD:
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		break;
	case SHUT_WR:
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	case SHUT_RDWR:
		SOCK_RECVBUF_LOCK(so);
		socantrcvmore_locked(so);
		SOCK_SENDBUF_LOCK(so);
		socantsendmore_locked(so);
		break;
	}
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

/* -----------------------------------------------------------------------
 * Virtqueue interrupt handlers
 * ---------------------------------------------------------------------- */

/*
 * RX virtqueue interrupt handler.
 *
 * Dequeues completed RX buffers and hands them to the domain layer
 * via vsock_rx_packet().  Buffers are recycled back into the virtqueue
 * after processing, avoiding per-packet allocation in the receive path.
 */
static void
vtvsock_rx_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	struct sglist_seg segs[1];
	struct sglist sg;
	void *buf;
	uint32_t len;

	sglist_init(&sg, 1, segs);
	while ((buf = virtqueue_dequeue(sc->sc_rxvq, &len)) != NULL) {
		if (len > VTVSOCK_RX_BUFSZ)
			len = VTVSOCK_RX_BUFSZ;
		vsock_rx_packet(buf, len);

		/*
		 * Recycle the buffer back into the RX virtqueue.
		 * The payload was copied into mbufs by vsock_rx_packet(),
		 * so the buffer is safe to reuse without zeroing.
		 */
		sglist_reset(&sg);
		if (sglist_append(&sg, buf, VTVSOCK_RX_BUFSZ) == 0 &&
		    virtqueue_enqueue(sc->sc_rxvq, buf, &sg,
		    0, sg.sg_nseg) == 0)
			continue;
		/* Enqueue failed; free and let the queue shrink. */
		free(buf, M_VTVSOCK);
	}
	virtqueue_notify(sc->sc_rxvq);
}

/*
 * TX virtqueue interrupt handler.
 *
 * Reclaims completed TX descriptors.  Must hold vtvsock_mtx to serialize
 * with vtvsock_send_pkt_locked() and vtvsock_virtio_send() which enqueue
 * to the same virtqueue.
 */
static void
vtvsock_tx_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	void *buf;

	mtx_lock(&vtvsock_mtx);
	while ((buf = virtqueue_dequeue(sc->sc_txvq, NULL)) != NULL)
		free(buf, M_VTVSOCK);
	mtx_unlock(&vtvsock_mtx);
}

/*
 * Event virtqueue interrupt handler.
 *
 * Handles VIRTIO_VSOCK_EVENT_TRANSPORT_RESET by re-reading the guest CID,
 * re-registering the transport with the domain layer, and resetting all
 * active connections.
 */
static void
vtvsock_event_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;
	struct virtio_vsock_event *evt;
	uint32_t len;
	uint64_t new_cid;

	while ((evt = virtqueue_dequeue(sc->sc_eventvq, &len)) != NULL) {
		if (len >= sizeof(*evt)) {
			if (le32toh(evt->id) ==
			    VIRTIO_VSOCK_EVENT_TRANSPORT_RESET) {
				/* Guest CID may have changed; re-read it. */
				virtio_read_device_config(sc->sc_dev, 0,
				    &sc->sc_guest_cid,
				    sizeof(sc->sc_guest_cid));
				new_cid = sc->sc_guest_cid;

				vsock_transport_register(
				    &vtvsock_virtio_transport,
				    new_cid, sc->sc_features);
				vsock_transport_reset();
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
 * VirtIO device attach: negotiate features, set up virtqueues, read CID,
 * and register the transport with the AF_VSOCK domain layer.
 */
static int
vtvsock_attach(device_t dev)
{
	struct vtvsock_softc *sc;
	struct vq_alloc_info vq_info[VTVSOCK_MAXQ];
	struct virtio_vsock_event *evt;
	struct sglist_seg segs[1];
	struct sglist sg;
	void *drain_buf;
	int i, error;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;

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
	 * Read the guest CID from device config.
	 * virtio_read_device_config() already returns host-endian values
	 * on FreeBSD; do not apply le64toh() again.
	 */
	virtio_read_device_config(dev, 0, &sc->sc_guest_cid,
	    sizeof(sc->sc_guest_cid));

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

	/* Publish the softc globally so the transport ops can find it. */
	atomic_store_ptr(&vtvsock_sc, sc);

	/* Register with the AF_VSOCK domain layer. */
	vsock_transport_register(&vtvsock_virtio_transport,
	    sc->sc_guest_cid, sc->sc_features);

	return (0);

fail:
	virtio_stop(dev);
	/* Drain any buffers enqueued before the failure. */
	{
		int last;

		if (sc->sc_rxvq != NULL) {
			last = 0;
			while ((drain_buf = virtqueue_drain(sc->sc_rxvq,
			    &last)) != NULL)
				free(drain_buf, M_VTVSOCK);
		}
		if (sc->sc_eventvq != NULL) {
			last = 0;
			while ((drain_buf = virtqueue_drain(sc->sc_eventvq,
			    &last)) != NULL)
				free(drain_buf, M_VTVSOCK);
		}
	}
	return (error);
}

static int
vtvsock_detach(device_t dev)
{
	struct vtvsock_softc *sc;
	void *buf;

	sc = device_get_softc(dev);

	/* Stop accepting new traffic. */
	mtx_lock(&vtvsock_mtx);
	atomic_store_ptr(&vtvsock_sc, NULL);
	mtx_unlock(&vtvsock_mtx);

	/* Unregister from the AF_VSOCK domain layer (resets all connections). */
	vsock_transport_unregister();

	/* Disable interrupts before stopping the device. */
	if (sc->sc_rxvq != NULL)
		virtqueue_disable_intr(sc->sc_rxvq);
	if (sc->sc_txvq != NULL)
		virtqueue_disable_intr(sc->sc_txvq);
	if (sc->sc_eventvq != NULL)
		virtqueue_disable_intr(sc->sc_eventvq);

	virtio_stop(dev);

	/* Drain all virtqueues — virtqueue_drain retrieves all submitted
	 * buffers (both pending and completed), unlike virtqueue_dequeue
	 * which only returns completed entries from the used ring. */
	{
		int last;

		if (sc->sc_txvq != NULL) {
			last = 0;
			while ((buf = virtqueue_drain(sc->sc_txvq, &last)) != NULL)
				free(buf, M_VTVSOCK);
		}
		if (sc->sc_rxvq != NULL) {
			last = 0;
			while ((buf = virtqueue_drain(sc->sc_rxvq, &last)) != NULL)
				free(buf, M_VTVSOCK);
		}
		if (sc->sc_eventvq != NULL) {
			last = 0;
			while ((buf = virtqueue_drain(sc->sc_eventvq, &last)) != NULL)
				free(buf, M_VTVSOCK);
		}
	}

	/* (no per-device lock to destroy) */
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
MODULE_DEPEND(virtio_vsock, vsock, 1, 1, 1);
VIRTIO_SIMPLE_PNPINFO(virtio_vsock, VIRTIO_ID_VSOCK,
    "VirtIO VSOCK Transport");
