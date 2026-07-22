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
 * (OASIS virtio v1.2/1.3, section 5.10).  It manages:
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
#include <sys/lock.h>
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

#include "virtio_if.h"

SDT_PROVIDER_DECLARE(vsock);
SDT_PROBE_DEFINE3(vsock, , , credit__stall,
    "uint32_t",	/* peer_buf_alloc */
    "uint32_t",	/* tx_cnt */
    "uint32_t");	/* peer_fwd_cnt */
SDT_PROBE_DEFINE3(vsock, , , credit__update__send,
    "uint32_t",	/* buf_alloc */
    "uint32_t",	/* fwd_cnt */
    "uint32_t");	/* rx_bytes */
/* Metadata-only trace of every outbound wire packet (no payload). */
SDT_PROBE_DEFINE6(vsock, , , pkt__tx,
    "uint16_t",	/* op */
    "uint64_t",	/* src CID */
    "uint32_t",	/* src port */
    "uint32_t",	/* dst port */
    "uint32_t",	/* payload len */
    "uint32_t");	/* flags */

/* -----------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define	VTVSOCK_MAXQ			3
#define	VTVSOCK_RX_BUFSZ		(sizeof(struct virtio_vsock_hdr) + \
					 64 * 1024)

/*
 * Worst-case scatter/gather segment count for a maximum-sized RX or TX
 * packet buffer.  malloc(9) returns virtually- but not necessarily
 * physically-contiguous memory for multi-page allocations, so
 * sglist_append() emits up to one segment per physical page (plus one to
 * cover a possibly non-page-aligned start).  The on-stack segment arrays
 * and the sglist_init() counts MUST be at least this large, otherwise
 * sglist_append() fails with EFBIG and the buffer is rejected -- which
 * breaks attach (every ~64KB RX buffer) and large sends (TX).
 */
#define	VTVSOCK_RX_SEGS			((int)howmany(VTVSOCK_RX_BUFSZ, \
					    PAGE_SIZE) + 1)
#define	VTVSOCK_TX_SEGS			((int)howmany( \
					    sizeof(struct virtio_vsock_hdr) + \
					    VTVSOCK_MAX_PKT_BUF, PAGE_SIZE) + 1)

/*
 * Bound for the software holding queue of control/reply packets (RST,
 * RESPONSE, CREDIT_UPDATE, SHUTDOWN, ...) that cannot be placed on the TX
 * virtqueue because the host is keeping the ring full.  Rather than dropping
 * such a reply -- which silently fails an inbound connect (lost RESPONSE),
 * stalls the peer (lost CREDIT_UPDATE), or leaks a stale peer connection
 * (lost RST), violating virtio 1.2/1.3 §5.10.6.1.1 -- we retain it and drain
 * it from vtvsock_tx_intr as descriptors complete (mirroring the send list in
 * Linux's virtio_transport).  The bound keeps a wedged host from growing guest
 * memory without limit.  RX-generated replies are additionally kept lossless by
 * VTVSOCK_TXQ_HIWAT backpressure (see vtvsock_rx_process_locked), so the
 * drop-newest-and-bump-sc_txq_drops path below is a last resort reached only by
 * app-driven control packets (e.g. a burst of CREDIT_UPDATE/SHUTDOWN) while the
 * host keeps the ring wedged.  All access is under vtvsock_mtx.
 */
#define	VTVSOCK_TXQ_MAX			256

/*
 * High-water mark on the reply holding queue at which the RX path applies
 * backpressure instead of risking a drop.  Each processed RX packet generates
 * at most one control reply, so once sc_txq_count reaches this mark the RX
 * path stops consuming the RX virtqueue (leaving buffers on the ring so the
 * host is throttled) rather than enqueueing more work whose replies could
 * overflow the queue.  vtvsock_tx_intr resumes RX once the queue drains back
 * below the mark.  This makes RX-generated replies lossless -- honoring the
 * intent of virtio 1.4 §5.10.6.1 ("stop processing rather than exhaust
 * resources") and mirroring Linux's queued_replies / virtio_transport_
 * more_replies throttle.  The margin below VTVSOCK_TXQ_MAX absorbs any
 * app-driven control packets (credit updates, shutdown) that share the queue.
 */
#define	VTVSOCK_TXQ_HIWAT		(VTVSOCK_TXQ_MAX - 16)

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

	/*
	 * Bounded FIFO software holding queue for control/reply packets that
	 * could not be enqueued onto the TX virtqueue because the ring was
	 * full (see VTVSOCK_TXQ_MAX).  Each slot holds a fully-built packet
	 * buffer (struct virtio_vsock_hdr + payload); the total length is
	 * recovered on drain from the header's len field.  Drained by
	 * vtvsock_tx_intr as TX descriptors complete.  All fields are
	 * protected by vtvsock_mtx.
	 */
	void			*sc_txq_pkts[VTVSOCK_TXQ_MAX];
	uint32_t		 sc_txq_head;
	uint32_t		 sc_txq_tail;
	uint32_t		 sc_txq_count;
	uint64_t		 sc_txq_drops;

	/*
	 * Set when the RX path stopped consuming the RX virtqueue because the
	 * reply holding queue hit VTVSOCK_TXQ_HIWAT (see vtvsock_rx_process_
	 * locked).  vtvsock_tx_intr resumes RX once sc_txq drains below the
	 * mark.  Protected by vtvsock_mtx.
	 */
	bool			 sc_rx_stalled;
	/* Packets currently being delivered with vtvsock_mtx dropped. */
	u_int			 sc_rx_inflight;
	/* Reset events sleeping until an in-flight RX delivery finishes. */
	u_int			 sc_event_inflight;
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

static int	vtvsock_queue_rx_buffers(struct vtvsock_softc *, bool);
static int	vtvsock_ctrl_submit(struct vtvsock_softc *, void *,
		    struct sglist *);
static void	vtvsock_txq_drain(struct vtvsock_softc *);
static int	vtvsock_send_pkt_locked(struct vtvsock_pcb *, uint16_t,
		    uint32_t, const void *, size_t);
static int	vtvsock_send_rst_locked(uint64_t, uint32_t, uint64_t,
		    uint32_t, uint16_t);
static void	vtvsock_send_credit_update_locked(struct vtvsock_pcb *);

static void	vtvsock_rx_intr(void *);
static void	vtvsock_tx_intr(void *);
static void	vtvsock_event_intr(void *);
static bool	vtvsock_virtio_tx_ready(struct vtvsock_pcb *);

static struct vtvsock_softc *vtvsock_global_softc(void);

/* -----------------------------------------------------------------------
 * Transport dispatch table
 * ---------------------------------------------------------------------- */

static const struct vtvsock_transport vtvsock_virtio_transport = {
	.send =			vtvsock_virtio_send,
	.disconnect =		vtvsock_virtio_disconnect,
	.shutdown =		vtvsock_virtio_shutdown,
	.tx_ready =		vtvsock_virtio_tx_ready,
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

/*
 * Sanitize the guest CID read from device config.  Per virtio 1.2/1.3 §5.10.4
 * the CID occupies the low 32 bits of guest_cid (upper 32 reserved and
 * zeroed) and must not be a reserved value: 0 (hypervisor), 1 (local),
 * 2 (host), or 0xffffffff.  Mask the reserved high bits so a host that
 * leaves garbage there cannot register a bogus 64-bit CID, and warn on a
 * reserved value.  A reserved value falls back to CID_LOCAL, leaving only
 * loopback available instead of registering a guest transport as CID_HOST.
 */
static uint64_t
vtvsock_sanitize_cid(device_t dev, uint64_t cid)
{
	cid &= 0xffffffffULL;
	if (cid == VSOCK_CID_HYPERVISOR || cid == VSOCK_CID_LOCAL ||
	    cid == VSOCK_CID_HOST || cid == 0xffffffffULL) {
		device_printf(dev,
		    "warning: host assigned reserved guest CID %ju\n",
		    (uintmax_t)cid);
		cid = VSOCK_CID_LOCAL;
	}
	return (cid);
}

/* -----------------------------------------------------------------------
 * Virtqueue packet transmission
 * ---------------------------------------------------------------------- */

/*
 * Reclaim and free all completed TX descriptors.  Caller holds vtvsock_mtx.
 */
static void
vtvsock_txvq_reclaim(struct vtvsock_softc *sc)
{
	void *buf;

	while ((buf = virtqueue_dequeue(sc->sc_txvq, NULL)) != NULL)
		free(buf, M_VTVSOCK);
}

/*
 * Enqueue a fully-built packet onto the TX virtqueue.  If the ring has no room
 * -- ENOSPC (full) or EMSGSIZE (fewer free descriptors than this packet's
 * segment count; we use direct descriptors) -- reclaim completed descriptors
 * inline (safe: we hold vtvsock_mtx, so vtvsock_tx_intr cannot run) and retry
 * once, then give up with EWOULDBLOCK.  Notifies the device on success.
 * Caller holds vtvsock_mtx and retains ownership of 'cookie' on error.
 */
/*
 * Transport tx_ready: can the TX virtqueue accept at least one full packet
 * right now?  A packet uses up to VTVSOCK_TX_SEGS direct descriptors, so it
 * fits only if that many are free.  Used by the socket layer to fail a
 * non-blocking send before it copies user data (see vsock_sosend), so a full
 * ring cannot silently drop bytes.  Caller holds vtvsock_mtx.
 */
static bool
vtvsock_virtio_tx_ready(struct vtvsock_pcb *pcb __unused)
{
	struct vtvsock_softc *sc = vtvsock_global_softc();

	if (sc == NULL || sc->sc_txvq == NULL)
		return (false);
	/*
	 * A software holding queue in front of the ring means the ring is
	 * already (or was just) full; not ready either way.
	 */
	if (sc->sc_txq_count != 0)
		return (false);
	return (virtqueue_nfree(sc->sc_txvq) >= VTVSOCK_TX_SEGS);
}

static int
vtvsock_txvq_enqueue(struct vtvsock_softc *sc, void *cookie, struct sglist *sg)
{
	int error;

	error = virtqueue_enqueue(sc->sc_txvq, cookie, sg, sg->sg_nseg, 0);
	if (error == ENOSPC || error == EMSGSIZE) {
		vtvsock_txvq_reclaim(sc);
		error = virtqueue_enqueue(sc->sc_txvq, cookie, sg, sg->sg_nseg, 0);
		if (error == ENOSPC || error == EMSGSIZE) {
			/*
			 * ENOSPC (ring full) and a fits-in-ring EMSGSIZE (fewer
			 * free descriptors than needed right now) are transient:
			 * report EWOULDBLOCK so the caller retries once
			 * descriptors complete.  But if the packet needs more
			 * segments than the ring holds in total, EMSGSIZE is
			 * permanent (free_cnt can never reach sg_nseg) -- keep it
			 * as a hard error so the caller drops instead of
			 * retrying forever.
			 */
			if (error == EMSGSIZE &&
			    sg->sg_nseg > virtqueue_size(sc->sc_txvq))
				;	/* permanent: propagate EMSGSIZE */
			else
				error = EWOULDBLOCK;
		}
	}
	if (error == 0)
		virtqueue_notify(sc->sc_txvq);
	return (error);
}

/*
 * Submit a control/reply packet (RST, RESPONSE, CREDIT_UPDATE, SHUTDOWN, ...)
 * for transmission, taking ownership of 'pkt' in every case.  Try the TX
 * virtqueue first; if the ring is full, retain the packet on the bounded
 * software holding queue so the reply is not lost -- it is drained by
 * vtvsock_tx_intr as descriptors complete.  If the holding queue is also full,
 * drop the newest packet (freeing it) and bump sc_txq_drops so a wedged host
 * cannot grow the queue without bound.  Returns 0 if the packet was enqueued
 * or held, non-zero if it was dropped or failed unrecoverably; the caller must
 * NOT free 'pkt' regardless (ownership is always consumed here).
 * Caller holds vtvsock_mtx.
 */
static int
vtvsock_ctrl_submit(struct vtvsock_softc *sc, void *pkt, struct sglist *sg)
{
	int error;

	mtx_assert(&vtvsock_mtx, MA_OWNED);

	/*
	 * Preserve FIFO ordering: if packets are already waiting on the
	 * software queue the ring is (or was just) full, so hold this one
	 * behind them rather than letting it jump ahead onto the virtqueue.
	 */
	if (sc->sc_txq_count == 0) {
		error = vtvsock_txvq_enqueue(sc, pkt, sg);
		if (error == 0)
			return (0);
		if (error != EWOULDBLOCK) {
			/* Unrecoverable (e.g. sglist too large): drop. */
			free(pkt, M_VTVSOCK);
			return (error);
		}
	}

	if (sc->sc_txq_count >= VTVSOCK_TXQ_MAX) {
		/* Bounded: drop newest, account for it, do not grow. */
		sc->sc_txq_drops++;
		free(pkt, M_VTVSOCK);
		return (EWOULDBLOCK);
	}

	sc->sc_txq_pkts[sc->sc_txq_tail] = pkt;
	sc->sc_txq_tail = (sc->sc_txq_tail + 1) % VTVSOCK_TXQ_MAX;
	sc->sc_txq_count++;
	return (0);
}

/*
 * Drain the software holding queue onto the TX virtqueue, in FIFO order,
 * until it empties or the ring fills again.  Once a packet is accepted by
 * virtqueue_enqueue() the virtqueue owns it (freed on completion by
 * vtvsock_txvq_reclaim), so there is no double-free with the software queue.
 * Called from vtvsock_tx_intr after reclaiming completed descriptors.
 * Caller holds vtvsock_mtx.
 */
static void
vtvsock_txq_drain(struct vtvsock_softc *sc)
{
	struct sglist_seg segs[VTVSOCK_TX_SEGS];
	struct sglist sg;
	struct virtio_vsock_hdr *hdr;
	void *pkt;
	bool drained;
	int error;

	mtx_assert(&vtvsock_mtx, MA_OWNED);

	drained = false;
	while (sc->sc_txq_count != 0) {
		pkt = sc->sc_txq_pkts[sc->sc_txq_head];
		hdr = (struct virtio_vsock_hdr *)pkt;

		sglist_init(&sg, VTVSOCK_TX_SEGS, segs);
		error = sglist_append(&sg, pkt,
		    sizeof(*hdr) + le32toh(hdr->len));
		if (error == 0)
			error = virtqueue_enqueue(sc->sc_txvq, pkt, &sg,
			    sg.sg_nseg, 0);
		if (error == ENOSPC || error == EMSGSIZE)
			break;		/* ring still full; retry on next TX completion */

		/* Slot consumed (enqueued to the vq, or dropped as unrecoverable). */
		sc->sc_txq_pkts[sc->sc_txq_head] = NULL;
		sc->sc_txq_head = (sc->sc_txq_head + 1) % VTVSOCK_TXQ_MAX;
		sc->sc_txq_count--;
		if (error != 0) {
			/* Should not happen with worst-case sglist sizing. */
			free(pkt, M_VTVSOCK);
			sc->sc_txq_drops++;
			continue;
		}
		drained = true;
	}
	if (drained)
		virtqueue_notify(sc->sc_txvq);
}

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
	struct sglist_seg segs[VTVSOCK_TX_SEGS];
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

	SDT_PROBE6(vsock, , , pkt__tx, op, pcb->local.svm_cid,
	    pcb->local.svm_port, pcb->remote.svm_port,
	    (uint32_t)payload_len, flags);

	sglist_init(&sg, VTVSOCK_TX_SEGS, segs);
	error = sglist_append(&sg, pkt, sizeof(*hdr) + payload_len);
	if (error != 0) {
		free(pkt, M_VTVSOCK);
		return (error);
	}
	/*
	 * Control/reply packets (RESPONSE, RST, CREDIT_UPDATE, SHUTDOWN) route
	 * through here and must not be silently dropped when the ring is full:
	 * a lost RESPONSE fails an inbound connect, a lost CREDIT_UPDATE stalls
	 * the peer, a lost RST leaks a stale connection (virtio 1.2/1.3 §5.10.6.1).
	 * vtvsock_ctrl_submit() reclaims and retries, then retains the packet on
	 * the bounded software holding queue (drained by vtvsock_tx_intr) rather
	 * than dropping it; it always consumes ownership of 'pkt'.
	 */
	error = vtvsock_ctrl_submit(sc, pkt, &sg);
	if (error != 0)
		return (error);
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
	struct sglist_seg segs[VTVSOCK_TX_SEGS];
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

	sglist_init(&sg, VTVSOCK_TX_SEGS, segs);
	error = sglist_append(&sg, hdr, sizeof(*hdr));
	if (error != 0) {
		free(hdr, M_VTVSOCK);
		return (error);
	}
	/*
	 * Route through vtvsock_ctrl_submit() so a full TX ring is drained and
	 * retried, then the RST is retained on the bounded software holding
	 * queue rather than dropped: §5.10.6.4.1 requires an RST reply for
	 * unknown-type packets, and dropped teardown/timeout RSTs leak a stale
	 * connection on the peer.  It always consumes ownership of 'hdr'.
	 */
	return (vtvsock_ctrl_submit(sc, hdr, &sg));
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
	/*
	 * Advance last_fwd_cnt only if the update actually made it onto the TX
	 * ring.  If it was dropped (ring full / ENOMEM) but we advanced anyway,
	 * the re-fire threshold (unreported = fwd_cnt - last_fwd_cnt) collapses
	 * to 0 and no later update fires, permanently stalling the peer's view
	 * of our free receive space.
	 */
	if (vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_CREDIT_UPDATE,
	    0, NULL, 0) == 0)
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
	struct sglist_seg segs[VTVSOCK_TX_SEGS];
	struct sglist sg;
	uint8_t *buf;
	size_t total, offset, chunk;
	uint32_t credit;
	uint32_t pkt_flags;
	bool nonblocking, seqpacket;
	bool credit_req_sent;
	int error;

	(void)addr;
	(void)td;

	if (control != NULL) {
		m_freem(control);
		control = NULL;
	}

	KASSERT(pcb->so != NULL, ("%s: pcb %p has NULL so", __func__, pcb));
	seqpacket = (pcb->so->so_type == SOCK_SEQPACKET);
	nonblocking = (flags & VTVSOCK_SEND_F_NONBLOCK) != 0 ||
	    (pcb->so->so_state & SS_NBIO) != 0;

	total = m_length(m, NULL);
	if (total == 0) {
		/*
		 * A zero-length STREAM write is a no-op.  A zero-length
		 * SEQPACKET write delivers an empty record (Linux semantics):
		 * send a single zero-payload RW with EOM (and EOR if the
		 * application passed MSG_EOR) so the peer delivers a distinct
		 * 0-byte message.
		 */
		error = 0;
		if (seqpacket) {
			uint32_t zflags = VIRTIO_VSOCK_SEQ_EOM;

			if (m->m_flags & M_PROTO1)
				zflags |= VIRTIO_VSOCK_SEQ_EOR;
			mtx_lock(&vtvsock_mtx);
			if (pcb->state != VTVSOCK_ESTABLISHED)
				error = EPIPE;
			else
				error = vtvsock_send_pkt_locked(pcb,
				    VIRTIO_VSOCK_OP_RW, zflags, NULL, 0);
			mtx_unlock(&vtvsock_mtx);
		}
		m_freem(m);
		return (error);
	}
	offset = 0;
	error = 0;
	credit_req_sent = false;

	mtx_lock(&vtvsock_mtx);

	/* Re-check softc under lock to close the detach race window. */
	sc = vtvsock_global_softc();
	if (sc == NULL) {
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (ENXIO);
	}

	/*
	 * SEQPACKET is atomic: a record that cannot fit in the peer's advertised
	 * receive buffer can never be delivered (the peer caps reassembly at its
	 * buf_alloc and would RST mid-record).  Reject it up front with EMSGSIZE
	 * -- matching the loopback transport (vtvsock_local_send) -- rather than
	 * streaming fragments that provoke a remote reset (ECONNRESET).
	 */
	if (seqpacket && pcb->peer_buf_alloc != 0 &&
	    total > pcb->peer_buf_alloc) {
		mtx_unlock(&vtvsock_mtx);
		m_freem(m);
		return (EMSGSIZE);
	}

	while (offset < total) {
		chunk = MIN(total - offset, (size_t)VTVSOCK_MAX_PKT_BUF);

		/* Check send credit; sleep if exhausted and blocking. */
		for (;;) {
			/*
			 * Validate the connection BEFORE consuming credit, so
			 * the check also runs after a wakeup with credit
			 * available and between chunks of a large write.
			 * Otherwise a teardown (peer RST, transport reset)
			 * racing the credit sleep would let the remaining
			 * chunks be "sent" into a closed connection and
			 * reported as success.
			 */
			if (pcb->state != VTVSOCK_ESTABLISHED ||
			    (pcb->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV)) {
				error = EPIPE;
				goto out;
			}
			credit = vtvsock_get_credit(pcb, (uint32_t)chunk);
			if (credit != 0)
				break;
			if (nonblocking) {
				error = EWOULDBLOCK;
				goto out;
			}
			SDT_PROBE3(vsock, , , credit__stall,
			    pcb->peer_buf_alloc, pcb->tx_cnt,
			    pcb->peer_fwd_cnt);
			/*
			 * Solicit a fresh CREDIT_UPDATE from the peer on the
			 * first stall (spec 5.10.6.3, matching Linux's
			 * virtio_transport_send_credit_request).  Without this
			 * a lost or aggressively-batched CREDIT_UPDATE would
			 * leave us polling on the 1s timeout below.  Best-effort:
			 * ignore a send failure, the timeout still retries.
			 */
			if (!credit_req_sent) {
				(void)vtvsock_send_pkt_locked(pcb,
				    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0, NULL, 0);
				credit_req_sent = true;
			}
			/* Sleep until CREDIT_UPDATE wakes us. */
			error = msleep(&pcb->tx_cnt, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsocktx", hz);
			if (error != 0 && error != EWOULDBLOCK)
				goto out;
			error = 0;
			/*
			 * Re-fetch the softc after any sleep, mirroring the
			 * TX-ring-full sleep below: a concurrent detach
			 * clears the global softc (under vtvsock_mtx) before
			 * tearing the virtqueues down, so continuing with the
			 * stale pointer would touch a dying device.
			 */
			sc = vtvsock_global_softc();
			if (sc == NULL) {
				error = ENXIO;
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
		 * EOR only when the application passed MSG_EOR, which
		 * vsock_sosend() propagates as M_PROTO1.
		 */
		pkt_flags = 0;
		if (seqpacket && (offset + chunk >= total)) {
			pkt_flags = VIRTIO_VSOCK_SEQ_EOM;
			if (m->m_flags & M_PROTO1)
				pkt_flags |= VIRTIO_VSOCK_SEQ_EOR;
		}
		hdr->flags = htole32(pkt_flags);

		SDT_PROBE6(vsock, , , pkt__tx, (uint16_t)VIRTIO_VSOCK_OP_RW,
		    pcb->local.svm_cid, pcb->local.svm_port,
		    pcb->remote.svm_port, (uint32_t)chunk, pkt_flags);

		m_copydata(m, (int)offset, (int)chunk, buf + sizeof(*hdr));

		sglist_init(&sg, VTVSOCK_TX_SEGS, segs);
		error = sglist_append(&sg, buf,
		    sizeof(*hdr) + chunk);
		if (error != 0) {
			/* Return credit on sglist failure. */
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			break;
		}
		/*
		 * Preserve FIFO ordering against control/reply packets already
		 * parked on the software holding queue (RST, SHUTDOWN, RESPONSE,
		 * or a CREDIT op that found the ring full): flush them onto the ring
		 * first so this data packet cannot jump ahead of an older
		 * control packet.  We hold vtvsock_mtx, so this is atomic with
		 * the enqueue below.  RW data itself is never routed through the
		 * (bounded, drop-newest) holding queue -- that could silently gap
		 * a STREAM byte stream -- so ordering is enforced by draining, not
		 * by parking the data.
		 */
		if (sc->sc_txq_count != 0)
			vtvsock_txq_drain(sc);
		error = vtvsock_txvq_enqueue(sc, buf, &sg);
		if (error == EWOULDBLOCK && !nonblocking &&
		    pcb->state == VTVSOCK_ESTABLISHED) {
			/*
			 * TX ring is full (not a credit stall -- credit was
			 * granted above).  For a blocking socket, wait for
			 * vtvsock_tx_intr to reclaim completed descriptors and
			 * retry this same chunk rather than abandoning the tail
			 * of a STREAM write (which would silently gap the byte
			 * stream).  Roll back the credit consumed for this chunk;
			 * it is re-taken when the loop rebuilds the packet.
			 */
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			error = msleep(&sc->sc_txvq, &vtvsock_mtx,
			    PSOCK | PCATCH, "vsocktxr", hz);
			if (error != 0 && error != EWOULDBLOCK)
				break;		/* signal: propagate EINTR */
			/*
			 * A concurrent detach may have torn the transport down
			 * while we slept (it wakes us via &sc->sc_txvq).  Re-fetch
			 * the softc under the lock and bail if it is gone, so we
			 * never re-enqueue against a freed sc.
			 */
			sc = vtvsock_global_softc();
			if (sc == NULL) {
				error = ENXIO;
				break;
			}
			error = 0;
			continue;		/* retry the same offset */
		}
		if (error != 0) {
			/* Return the credit consumed for this chunk. */
			pcb->tx_cnt -= (uint32_t)chunk;
			free(buf, M_VTVSOCK);
			break;
		}
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

	if (pcb->state == VTVSOCK_ESTABLISHED) {
		shut_flags = VIRTIO_VSOCK_SHUTDOWN_RCV |
		    VIRTIO_VSOCK_SHUTDOWN_SEND;
		(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_SHUTDOWN,
		    shut_flags, NULL, 0);
		pcb->state = VTVSOCK_CLOSING;
		callout_reset(&pcb->close_callout, VTVSOCK_CLOSE_TIMEOUT,
		    vtvsock_close_timeout, pcb);
		soisdisconnecting(so);
	} else if (pcb->state == VTVSOCK_CONNECTING) {
		/*
		 * The connection never reached ESTABLISHED, so there is no
		 * graceful half-close to perform.  Abort it with OP_RST (as
		 * Linux does for a not-yet-connected flow) and go straight to
		 * CLOSED rather than sending a bidirectional OP_SHUTDOWN for a
		 * 4-tuple the peer never accepted.  Stop the connect timeout so
		 * it cannot fire on a PCB that has already left CONNECTING, but
		 * because that callout is what would otherwise wake a blocking
		 * connect() still in msleep(&pcb->state), issue the wakeup here
		 * ourselves -- mirroring vtvsock_connect_timeout().  The waking
		 * connect() observes the cleared SS_ISCONNECTING and returns
		 * ECONNRESET.
		 */
		callout_stop(&pcb->connect_callout);
		(void)vtvsock_send_pkt_locked(pcb, VIRTIO_VSOCK_OP_RST,
		    0, NULL, 0);
		vtvsock_pcb_remove_lists_locked(pcb);
		pcb->state = VTVSOCK_CLOSED;
		soisdisconnected(so);
		wakeup(&pcb->state);
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
	/*
	 * Only inform the peer over the wire when the connection is actually
	 * established.  On a BOUND-only, CONNECTING, CLOSING, or CLOSED socket
	 * there is no valid live 4-tuple to shut down: an OP_SHUTDOWN here
	 * would emit a spurious control packet -- to dst_cid/dst_port 0 for a
	 * never-connected socket, or a duplicate for one already tearing down
	 * -- which the peer may answer with RST.  Linux vsock_shutdown()
	 * likewise only acts on an established connection.  The local
	 * socket-buffer shutdown below still applies in every state (matching
	 * vtvsock_local_shutdown, which always closes the local buffers and
	 * only notifies a peer when one exists).
	 */
	if (pcb->state == VTVSOCK_ESTABLISHED)
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
vtvsock_queue_rx_buffers(struct vtvsock_softc *sc, bool notify)
{
	struct sglist_seg segs[VTVSOCK_RX_SEGS];
	struct sglist sg;
	void *buf;
	int error;

	sglist_init(&sg, VTVSOCK_RX_SEGS, segs);
	error = 0;
	while (!virtqueue_full(sc->sc_rxvq)) {
		buf = malloc(VTVSOCK_RX_BUFSZ, M_VTVSOCK, M_NOWAIT | M_ZERO);
		if (buf == NULL) {
			error = ENOMEM;
			break;
		}
		error = sglist_append(&sg, buf, VTVSOCK_RX_BUFSZ);
		if (error != 0) {
			free(buf, M_VTVSOCK);
			break;
		}
		error = virtqueue_enqueue(sc->sc_rxvq, buf, &sg, 0, sg.sg_nseg);
		sglist_reset(&sg);
		if (error != 0) {
			free(buf, M_VTVSOCK);
			/*
			 * We post each ~64KB buffer as a chain of up to
			 * VTVSOCK_RX_SEGS direct descriptors (indirect
			 * descriptors are not negotiated).  virtqueue_enqueue()
			 * returns ENOSPC when the ring is full and EMSGSIZE when
			 * fewer than that many descriptors remain -- both simply
			 * mean "no room for another buffer", so stop and keep
			 * what we already posted.
			 */
			if (error == ENOSPC || error == EMSGSIZE)
				error = 0;
			break;
		}
	}
	/*
	 * Kick the device unless the caller is the attach-time preload:
	 * notifying before DRIVER_OK violates virtio 1.2 §3.1.1, so attach
	 * defers the notify to vtvsock_attach_completed().
	 */
	if (notify)
		virtqueue_notify(sc->sc_rxvq);
	return (error);
}

/* -----------------------------------------------------------------------
 * Virtqueue interrupt handlers
 * ---------------------------------------------------------------------- */

/*
 * Process completed RX buffers: dequeue each, hand it to the domain layer via
 * vsock_rx_packet(), and recycle it back into the RX virtqueue (avoiding
 * per-packet allocation).
 *
 * Reply backpressure: vsock_rx_packet() may generate one control reply per
 * packet (RST/RESPONSE/CREDIT_UPDATE), parked on sc_txq when the TX ring is
 * full.  If sc_txq_count reaches VTVSOCK_TXQ_HIWAT we STOP consuming the RX
 * ring -- leaving completed buffers undequeued so the host is throttled -- and
 * do NOT re-arm the RX interrupt; vtvsock_tx_intr resumes us once the reply
 * queue drains.  This keeps RX-generated replies lossless (§5.10.6.1), matching
 * Linux's more_replies throttle, rather than dropping the newest reply.
 *
 * Caller holds vtvsock_mtx; it is dropped only around vsock_rx_packet() (which
 * re-acquires it internally -- holding it there would recurse and deadlock) and
 * is held on return.
 */
static void
vtvsock_rx_process_locked(struct vtvsock_softc *sc)
{
	struct sglist_seg segs[VTVSOCK_RX_SEGS];
	struct sglist sg;
	void *buf;
	uint32_t len;

	mtx_assert(&vtvsock_mtx, MA_OWNED);
	/*
	 * If detach completed before this handler acquired the lock it cleared
	 * (or replaced) the global softc and drained the ring.  Bail before the
	 * dequeue loop -- otherwise the loop finds the ring empty and falls
	 * through to vtvsock_queue_rx_buffers() below, re-posting fresh buffers
	 * into (and re-arming the interrupt on) an about-to-be-freed virtqueue,
	 * which virtqueue_free() then leaks.
	 */
	if (vtvsock_global_softc() != sc)
		return;
	sglist_init(&sg, VTVSOCK_RX_SEGS, segs);
again:
	while (sc->sc_txq_count < VTVSOCK_TXQ_HIWAT &&
	    (buf = virtqueue_dequeue(sc->sc_rxvq, &len)) != NULL) {
		sc->sc_rx_inflight++;
		mtx_unlock(&vtvsock_mtx);

		if (len > VTVSOCK_RX_BUFSZ)
			len = VTVSOCK_RX_BUFSZ;
		vsock_rx_packet(sc, buf, len);

		/*
		 * Recycle the buffer back into the RX virtqueue.
		 * The payload was copied into mbufs by vsock_rx_packet(),
		 * so the buffer is safe to reuse without zeroing.
		 */
		mtx_lock(&vtvsock_mtx);
		KASSERT(sc->sc_rx_inflight > 0,
		    ("%s: RX in-flight count underflow", __func__));
		sc->sc_rx_inflight--;
		wakeup(&sc->sc_rx_inflight);
		/*
		 * If detach began while the lock was dropped it cleared the
		 * global softc and will drain the ring; re-enqueuing now would
		 * leak this buffer into an about-to-be-drained ring.  Free it
		 * and stop instead.
		 */
		if (vtvsock_global_softc() != sc) {
			free(buf, M_VTVSOCK);
			return;
		}
		sglist_reset(&sg);
		if (sglist_append(&sg, buf, VTVSOCK_RX_BUFSZ) != 0 ||
		    virtqueue_enqueue(sc->sc_rxvq, buf, &sg,
		    0, sg.sg_nseg) != 0)
			/* Enqueue failed; free and let the queue shrink. */
			free(buf, M_VTVSOCK);
	}

	if (sc->sc_txq_count >= VTVSOCK_TXQ_HIWAT) {
		/*
		 * Reply queue is full: apply backpressure by leaving the
		 * remaining RX buffers on the ring.  Mask the RX interrupt so
		 * the device does not storm us with completions we cannot
		 * process (each would re-enter this function only to fall
		 * straight back into this branch); vtvsock_tx_intr calls us
		 * again once it drains sc_txq below the high-water mark, and the
		 * normal exit below re-arms via virtqueue_enable_intr.
		 */
		virtqueue_disable_intr(sc->sc_rxvq);
		sc->sc_rx_stalled = true;
		return;
	}
	sc->sc_rx_stalled = false;

	/*
	 * Top the RX ring back up before re-arming.  The recycle above
	 * re-posts each consumed buffer 1:1, but a transient enqueue failure
	 * can shrink the ring with no path to grow back; refilling here (à la
	 * Linux's virtio_vsock_rx_fill) keeps a run of failures from
	 * monotonically starving the receive path.  Notifies the device.
	 */
	(void)vtvsock_queue_rx_buffers(sc, true);
	/* Re-arm; if the device raced in more buffers, drain them too. */
	if (virtqueue_enable_intr(sc->sc_rxvq) != 0) {
		virtqueue_disable_intr(sc->sc_rxvq);
		goto again;
	}
}

/*
 * RX virtqueue interrupt handler.  vtvsock_mtx serializes virtqueue access
 * against the TX/event handlers and against detach's drain.
 */
static void
vtvsock_rx_intr(void *arg)
{
	struct vtvsock_softc *sc = arg;

	mtx_lock(&vtvsock_mtx);
	vtvsock_rx_process_locked(sc);
	mtx_unlock(&vtvsock_mtx);
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

	mtx_lock(&vtvsock_mtx);
	/* See vtvsock_rx_process_locked: skip if detach already tore down. */
	if (vtvsock_global_softc() != sc) {
		mtx_unlock(&vtvsock_mtx);
		return;
	}
again:
	vtvsock_txvq_reclaim(sc);
	/*
	 * Now that descriptors have freed up, push any control/reply packets
	 * that were held on the software queue while the ring was full back
	 * onto the TX virtqueue (before re-arming, so newly freed space is
	 * used for the backlog).  See vtvsock_ctrl_submit / VTVSOCK_TXQ_MAX.
	 */
	vtvsock_txq_drain(sc);
	if (virtqueue_enable_intr(sc->sc_txvq) != 0) {
		virtqueue_disable_intr(sc->sc_txvq);
		goto again;
	}
	/*
	 * If the RX path stalled itself because the reply holding queue was
	 * full (see vtvsock_rx_process_locked), resume it now that draining
	 * sc_txq has freed room below the high-water mark.
	 */
	if (sc->sc_rx_stalled && sc->sc_txq_count < VTVSOCK_TXQ_HIWAT)
		vtvsock_rx_process_locked(sc);
	/*
	 * Wake any blocking sender waiting for TX ring space now that
	 * completed descriptors have been reclaimed (see vtvsock_virtio_send).
	 */
	wakeup(&sc->sc_txvq);
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
	struct sglist_seg segs[1];
	struct sglist sg;
	struct virtio_vsock_event *evt;
	uint32_t len;
	uint64_t new_cid;
	bool reset;

	sglist_init(&sg, 1, segs);
	mtx_lock(&vtvsock_mtx);
	/* See vtvsock_rx_process_locked: skip if detach already tore down. */
	if (vtvsock_global_softc() != sc) {
		mtx_unlock(&vtvsock_mtx);
		return;
	}
again:
	while ((evt = virtqueue_dequeue(sc->sc_eventvq, &len)) != NULL) {
		/*
		 * If detach has begun it cleared the global softc (and will
		 * unregister the transport and drain the ring).  Skip processing
		 * and free instead of recycling into an about-to-be-drained ring.
		 */
		if (vtvsock_global_softc() == NULL) {
			free(evt, M_VTVSOCK);
			continue;
		}

		reset = (len >= sizeof(*evt) &&
		    le32toh(evt->id) == VIRTIO_VSOCK_EVENT_TRANSPORT_RESET);

		if (reset) {
			/*
			 * Transport reset (e.g. live migration): the guest CID
			 * may have changed.  Re-read + sanitize it and re-register
			 * / reset connections -- all UNDER vtvsock_mtx via the
			 * _locked entry points.  Not dropping the lock makes this
			 * atomic against detach's unregister: without it, detach
			 * could clear the transport in the window and this handler
			 * would re-install a pointer into the soon-to-be-unloaded
			 * module (a dangling-transport UAF).  The softc==NULL check
			 * above already excludes a detach that started earlier.
			 */
			/*
			 * RX drops vtvsock_mtx while entering the socket domain.  Let
			 * any packet already dequeued finish before resetting domain
			 * state; otherwise an old-generation packet could create a new
			 * connection immediately after TRANSPORT_RESET.
			 */
			sc->sc_event_inflight++;
			while (sc->sc_rx_inflight != 0 &&
			    vtvsock_global_softc() == sc)
				(void)msleep(&sc->sc_rx_inflight, &vtvsock_mtx,
				    0, "vtrst", 0);
			if (vtvsock_global_softc() != sc) {
				KASSERT(sc->sc_event_inflight > 0,
				    ("%s: event in-flight count underflow",
				    __func__));
				sc->sc_event_inflight--;
				wakeup(&sc->sc_event_inflight);
				free(evt, M_VTVSOCK);
				goto out;
			}
			KASSERT(sc->sc_event_inflight > 0,
			    ("%s: event in-flight count underflow", __func__));
			sc->sc_event_inflight--;
			wakeup(&sc->sc_event_inflight);
			virtio_read_device_config(sc->sc_dev, 0,
			    &new_cid, sizeof(new_cid));
			new_cid = vtvsock_sanitize_cid(sc->sc_dev, new_cid);
			sc->sc_guest_cid = new_cid;
			KASSERT(vsock_transport_register_locked(
			    &vtvsock_virtio_transport, sc, new_cid,
			    sc->sc_features) == 0,
			    ("%s: lost transport ownership", __func__));
			vsock_transport_reset_locked();
			/*
			 * reset_locked woke per-pcb credit sleepers, but a
			 * sender parked on a full TX ring sleeps on &sc_txvq
			 * (not reachable from the socket layer); wake it here
			 * so it observes its now-CLOSED connection immediately
			 * instead of waiting out its 1 s poll.
			 */
			wakeup(&sc->sc_txvq);
		}

		/* Recycle the event buffer back into the event virtqueue. */
		sglist_reset(&sg);
		if (sglist_append(&sg, evt, sizeof(*evt)) != 0 ||
		    virtqueue_enqueue(sc->sc_eventvq, evt, &sg, 0,
		    sg.sg_nseg) != 0) {
			device_printf(sc->sc_dev,
			    "failed to re-enqueue event buffer\n");
			free(evt, M_VTVSOCK);
		}
	}
	virtqueue_notify(sc->sc_eventvq);
	if (virtqueue_enable_intr(sc->sc_eventvq) != 0) {
		virtqueue_disable_intr(sc->sc_eventvq);
		goto again;
	}
out:
	mtx_unlock(&vtvsock_mtx);
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
	/*
	 * Accept F_NO_IMPLIED_STREAM when offered (virtio 1.4 §5.10.3.1
	 * SHOULD).  The socket layer uses it to refuse SOCK_STREAM against a
	 * seqpacket-only device (NO_IMPLIED_STREAM without F_STREAM).
	 */
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

	/*
	 * Reject an undersized ring at attach rather than at first I/O.  With
	 * indirect descriptors not negotiated (see vtvsock_queue_rx_buffers), a
	 * max-size buffer occupies VTVSOCK_{RX,TX}_SEGS contiguous ring slots;
	 * a ring smaller than that can never carry one, so the rx/tx path would
	 * be permanently wedged (EMSGSIZE forever).  Fail loudly with a clear
	 * message instead of limping along deaf on rx or unable to send.
	 */
	if (virtqueue_size(sc->sc_rxvq) < VTVSOCK_RX_SEGS ||
	    virtqueue_size(sc->sc_txvq) < VTVSOCK_TX_SEGS) {
		device_printf(dev,
		    "virtqueue too small: rx %d (need %zu), tx %d (need %zu)\n",
		    virtqueue_size(sc->sc_rxvq), (size_t)VTVSOCK_RX_SEGS,
		    virtqueue_size(sc->sc_txvq), (size_t)VTVSOCK_TX_SEGS);
		error = ENXIO;
		goto fail;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC | INTR_MPSAFE);
	if (error != 0)
		goto fail;

	/*
	 * Read the guest CID from device config.
	 * virtio_read_device_config() already returns host-endian values
	 * on FreeBSD; do not apply le64toh() again.  Sanitize per §5.10.4
	 * (mask reserved high bits, warn on a reserved CID).
	 */
	virtio_read_device_config(dev, 0, &sc->sc_guest_cid,
	    sizeof(sc->sc_guest_cid));
	sc->sc_guest_cid = vtvsock_sanitize_cid(dev, sc->sc_guest_cid);

	/*
	 * Device initialization order per virtio 1.2/1.3 §5.10.5: populate the
	 * event virtqueue (step 2) before the rx virtqueue (step 3).
	 */
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
	/*
	 * If not even one event buffer could be posted (e.g. the host
	 * negotiated an event ring too small, or the very first enqueue
	 * failed), the guest can never receive a TRANSPORT_RESET event.  Fail
	 * attach loudly rather than run deaf to resets -- mirroring the rx
	 * virtqueue guard below.
	 */
	if (virtqueue_empty(sc->sc_eventvq)) {
		device_printf(dev,
		    "event virtqueue too small to post an event buffer\n");
		error = ENXIO;
		goto fail;
	}

	/*
	 * Pre-populate the RX virtqueue.  Post the buffers but do NOT notify
	 * the device yet: notifying before DRIVER_OK violates virtio 1.2
	 * §3.1.1.  The notify happens in vtvsock_attach_completed(), which the
	 * bus calls after it sets DRIVER_OK.
	 */
	error = vtvsock_queue_rx_buffers(sc, false);
	if (error != 0)
		goto fail;
	/*
	 * Each ~64KB buffer needs up to VTVSOCK_RX_SEGS direct descriptors; if
	 * the host negotiated an rx ring too small to hold even one, the preload
	 * posted nothing and the device would be silently deaf (refill only runs
	 * after a dequeue).  Fail loudly instead.
	 */
	if (virtqueue_empty(sc->sc_rxvq)) {
		device_printf(dev,
		    "rx virtqueue too small to post a receive buffer\n");
		error = ENXIO;
		goto fail;
	}

	/*
	 * Everything the device can observe -- publishing the softc, going live
	 * with the AF_VSOCK domain, notifying the queues, and enabling
	 * interrupts -- is deferred to vtvsock_attach_completed(), which the
	 * virtio bus calls after it sets DRIVER_OK (virtio 1.2 §3.1.1).  Until
	 * then the rings are merely populated, which the spec permits.
	 */
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

/*
 * Called by the virtio bus after it sets DRIVER_OK, i.e. once the device is
 * permitted to be used (virtio 1.2 §3.1.1).  Only here do we make the device
 * live: publish the softc, register the transport with the AF_VSOCK domain,
 * notify the queues whose buffers were posted during attach, and enable
 * interrupts.  This runs synchronously right after vtvsock_attach() returns.
 */
static int
vtvsock_attach_completed(device_t dev)
{
	struct vtvsock_softc *sc = device_get_softc(dev);
	int error;

	/*
	 * Claim transport ownership and publish the softc as one operation.
	 * In particular, a second device must not overwrite the first device's
	 * softc and then clear it when transport registration returns EBUSY.
	 */
	mtx_lock(&vtvsock_mtx);
	if (vtvsock_global_softc() != NULL)
		error = EBUSY;
	else
		error = vsock_transport_register_locked(
		    &vtvsock_virtio_transport, sc, sc->sc_guest_cid,
		    sc->sc_features);
	if (error == 0)
		atomic_store_ptr(&vtvsock_sc, sc);
	mtx_unlock(&vtvsock_mtx);
	if (error != 0) {
		device_printf(dev, "another AF_VSOCK transport is active\n");
		return (error);
	}

	/*
	 * DRIVER_OK is set: it is now legal to notify the device about the rx
	 * and event buffers posted during attach.
	 */
	virtqueue_notify(sc->sc_rxvq);
	virtqueue_notify(sc->sc_eventvq);

	/*
	 * Enable virtqueue interrupts.  virtqueue_alloc() leaves them masked
	 * (VRING_AVAIL_F_NO_INTERRUPT).  virtqueue_enable_intr() returns
	 * non-zero when the used ring already holds entries the device
	 * completed while interrupts were masked; enable is not retroactive, so
	 * run the handler once to drain what is already there (it re-arms via
	 * its own disable/enable loop).
	 */
	if (virtqueue_enable_intr(sc->sc_rxvq) != 0)
		vtvsock_rx_intr(sc);
	if (virtqueue_enable_intr(sc->sc_txvq) != 0)
		vtvsock_tx_intr(sc);
	if (virtqueue_enable_intr(sc->sc_eventvq) != 0)
		vtvsock_event_intr(sc);

	return (0);
}

static int
vtvsock_detach(device_t dev)
{
	struct vtvsock_softc *sc;
	void *buf;
	bool owner;

	sc = device_get_softc(dev);

	/* Stop accepting new traffic. */
	mtx_lock(&vtvsock_mtx);
	owner = vtvsock_global_softc() == sc;
	if (owner)
		atomic_store_ptr(&vtvsock_sc, NULL);
	/*
	 * Wake any sender blocked in vtvsock_virtio_send waiting on the TX ring
	 * (msleep on &sc->sc_txvq).  It re-fetches the softc after waking, sees
	 * it cleared above, and bails with ENXIO instead of stalling until its
	 * 1s timeout.
	 */
	wakeup(&sc->sc_txvq);
	mtx_unlock(&vtvsock_mtx);

	/* Unregister from the AF_VSOCK domain layer (resets all connections). */
	if (owner)
		vsock_transport_unregister(sc);

	/*
	 * Hold vtvsock_mtx across interrupt-disable, device stop, AND drain.
	 * The rx/tx/event handlers take vtvsock_mtx around every virtqueue
	 * access, so the lock serializes this teardown against a handler still
	 * in flight on another CPU: MPSAFE interrupts keep running until
	 * bus_teardown_intr, which the bus performs only after detach returns.
	 * Without the lock here, disable_intr()/virtio_stop() could issue
	 * virtqueue MMIO concurrently with a handler doing the same.
	 */
	mtx_lock(&vtvsock_mtx);
	/*
	 * An RX handler may have dequeued a buffer and dropped vtvsock_mtx
	 * around vsock_rx_packet() before detach cleared the global softc.
	 * Wait for it to regain the lock, discard that owned buffer, and leave
	 * the handler before stopping or draining the virtqueues.  Otherwise
	 * detach can return while the handler still references sc, and the
	 * device softc may be freed underneath it by the bus.
	 */
	while (sc->sc_rx_inflight != 0)
		(void)msleep(&sc->sc_rx_inflight, &vtvsock_mtx, 0,
		    "vtdrain", 0);
	while (sc->sc_event_inflight != 0)
		(void)msleep(&sc->sc_event_inflight, &vtvsock_mtx, 0,
		    "vtevent", 0);

	/* Disable interrupts before stopping the device. */
	if (sc->sc_rxvq != NULL)
		virtqueue_disable_intr(sc->sc_rxvq);
	if (sc->sc_txvq != NULL)
		virtqueue_disable_intr(sc->sc_txvq);
	if (sc->sc_eventvq != NULL)
		virtqueue_disable_intr(sc->sc_eventvq);

	virtio_stop(dev);

	/*
	 * Drain all virtqueues — virtqueue_drain retrieves all submitted
	 * buffers (both pending and completed), unlike virtqueue_dequeue
	 * which only returns completed entries from the used ring.
	 */
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

	/*
	 * Free any control/reply packets still held on the software TX queue.
	 * These were never submitted to the virtqueue, so virtqueue_drain()
	 * above did not reach them; without this they would leak on unload.
	 */
	while (sc->sc_txq_count != 0) {
		free(sc->sc_txq_pkts[sc->sc_txq_head], M_VTVSOCK);
		sc->sc_txq_pkts[sc->sc_txq_head] = NULL;
		sc->sc_txq_head = (sc->sc_txq_head + 1) % VTVSOCK_TXQ_MAX;
		sc->sc_txq_count--;
	}

	mtx_unlock(&vtvsock_mtx);

	return (0);
}

/* -----------------------------------------------------------------------
 * Module glue
 * ---------------------------------------------------------------------- */

static device_method_t vtvsock_methods[] = {
	DEVMETHOD(device_probe,		vtvsock_probe),
	DEVMETHOD(device_attach,	vtvsock_attach),
	DEVMETHOD(device_detach,	vtvsock_detach),

	/* virtio bus interface */
	DEVMETHOD(virtio_attach_completed, vtvsock_attach_completed),

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
