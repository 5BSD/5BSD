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
 * VirtIO vsock device emulation for bhyve.
 *
 * This implements a protocol-aware virtio-vsock host transport.  The bhyve
 * device acts as CID 2 (VSOCK_CID_HOST).  All host-side I/O uses Unix
 * sockets rooted in a directory fd.
 *
 * Two connection directions are supported:
 *
 * Host-to-guest:
 *   1. Host app connects to the control socket at <dir>/sock.
 *   2. App sends a vsock_ctl_msg (cmd=VSOCK_CTL_CONNECT, port, type).
 *   3. bhyve creates a socketpair, sends OP_REQUEST to the guest.
 *   4. On OP_RESPONSE, bhyve replies on the control connection with
 *      status=0 and passes one end of the socketpair via SCM_RIGHTS.
 *   5. Raw data flows over the socketpair; bhyve relays to the guest.
 *
 * Guest-to-host:
 *   1. Guest connects to VSOCK_CID_HOST:port.
 *   2. bhyve calls connectat(dfd, ...) to connect to <dir>/<port>
 *      (e.g., <dir>/80 for port 80).  The socket type matches the
 *      guest connection type.
 *   3. If a host application is listening there, the connection is relayed
 *      bidirectionally.  If not, bhyve sends OP_RST to the guest.
 *
 * Credit flow control per virtio-vsock spec is implemented on the host side.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/linker_set.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "mevent.h"
#include "pci_emul.h"
#include "sockstream.h"
#include "virtio.h"
#include <sys/vsock.h>

/* Virtqueue indices */
#define	VTVSOCK_RXQ		0	/* host -> guest */
#define	VTVSOCK_TXQ		1	/* guest -> host */
#define	VTVSOCK_EVENTQ		2	/* event queue (unused by host) */
#define	VTVSOCK_MAXQ		3

#define	VTVSOCK_RINGSZ		256
#define	VTVSOCK_MAX_IOV		64

/* Maximum single virtio-vsock payload we will handle */
#define	VTVSOCK_MAX_PKT		(64 * 1024)

/*
 * Host-side receive buffer advertised to the guest.  128 KiB gives enough
 * headroom to keep the pipe full without consuming excessive memory per
 * connection.
 */
#define	VTVSOCK_BUF_ALLOC	(128 * 1024)

/*
 * Send a CREDIT_UPDATE when we have freed at least this many bytes since the
 * last update we sent to the guest.
 */
#define	VTVSOCK_CREDIT_UPDATE_THRESHOLD	(VTVSOCK_BUF_ALLOC / 4)

/* First dynamically-assigned host-side port number */
#define	VTVSOCK_PORT_MIN	1024

/* Maximum simultaneous connections (prevents resource exhaustion) */
#define	VTVSOCK_MAX_CONNS	256

/* Control protocol command */
#define	VSOCK_CTL_CONNECT	1

struct vsock_ctl_msg {
	uint32_t	cmd;		/* VSOCK_CTL_CONNECT */
	uint32_t	port;		/* guest port number */
	uint32_t	type;		/* SOCK_STREAM or SOCK_SEQPACKET */
	int32_t		status;		/* reply: 0 on success, -errno on failure */
};

static int pci_vtvsock_debug;
#define	DPRINTF(params)	if (pci_vtvsock_debug) PRINTLN params
#define	WPRINTF(params)	PRINTLN params

static time_t
monotonic_seconds(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec);
}

#ifndef WITHOUT_CAPSICUM
/*
 * Lock down an fd that bhyve keeps for its own use.  The fd cannot be
 * transferred (CAP_XFER_NONE), survives neither exec nor fork, and
 * carries no ambient authority.
 */
static void
vtvsock_cap_lockdown(int fd)
{

	(void)cap_xfer_limit(fd, CAP_XFER_NONE);
	(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
	(void)cap_ambient_limit(fd);
}

/*
 * Prepare an fd that will be passed to a host application via
 * SCM_RIGHTS.  The fd can be transferred exactly once (to the app),
 * then it is pinned.  Close-on-exec, close-on-fork, and no-ambient
 * are set so the receiving app must be sandboxed and cannot further
 * propagate the descriptor.
 */
static void
vtvsock_cap_lockdown_xfer_once(int fd)
{

	(void)cap_xfer_limit(fd, CAP_XFER_ONCE);
	(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
	(void)cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
	(void)cap_ambient_limit(fd);
}
#endif

/*
 * Per-connection state.  Each host-side Unix socket connection (or
 * guest-initiated connection accepted by the host) is represented by one of
 * these, linked into vsc_conns.
 */
struct vtvsock_conn {
	TAILQ_ENTRY(vtvsock_conn) link;
	struct pci_vtvsock_softc *sc;		/* backpointer to softc */
	int			fd;		/* host-side Unix socket fd (-1 if none) */
	int			ctl_fd;		/* control conn fd for reply (-1 if guest-initiated) */
	int			reply_fd;	/* fd to send back to host via SCM_RIGHTS (-1 if N/A) */
	uint32_t		local_port;	/* host CID 2 port (auto-assigned) */
	uint32_t		guest_port;	/* guest-side port */
	struct mevent		*evp;		/* mevent for reads on fd */
	uint16_t		type;		/* VIRTIO_VSOCK_TYPE_{STREAM,SEQPACKET} */

	/* State machine */
	enum {
		CONN_CONNECTING,	/* OP_REQUEST sent, awaiting OP_RESPONSE */
		CONN_ESTABLISHED,	/* data flowing */
		CONN_CLOSING,		/* shutdown in progress */
	} state;

	/* Peer shutdown tracking (accumulated, never cleared per §5.10.6.5) */
	uint32_t		peer_shutdown;

	/* Monotonic seconds when CONN_CLOSING was entered; 0 if not closing */
	time_t			close_time;

	/* Credit tracking (host side) */
	uint32_t		buf_alloc;	/* our recv buffer capacity */
	uint32_t		fwd_cnt;	/* bytes we have consumed from guest */
	uint32_t		last_fwd_cnt;	/* fwd_cnt at last CREDIT_UPDATE sent */
	uint32_t		tx_cnt;		/* bytes we have sent to guest */
	uint32_t		peer_buf_alloc;	/* guest's advertised capacity */
	uint32_t		peer_fwd_cnt;	/* guest's last reported consumed */
};

TAILQ_HEAD(vtvsock_conn_list, vtvsock_conn);

/*
 * Per-control-connection state.  Each host app that connects to the control
 * socket gets one of these until its request is fully handled.
 */
struct vtvsock_ctl_conn {
	int			fd;
	struct mevent		*evp;
	TAILQ_ENTRY(vtvsock_ctl_conn) link;
};

TAILQ_HEAD(vtvsock_ctl_conn_list, vtvsock_ctl_conn);

struct pci_vtvsock_softc {
	struct virtio_softc	vsc_vs;
	struct vqueue_info	vsc_queues[VTVSOCK_MAXQ];
	pthread_mutex_t		vsc_mtx;

	struct virtio_vsock_config vsc_config;
	uint64_t		vsc_features;
	uint64_t		vsc_guest_cid;

	char			*vsc_path;
	int			vsc_dfd;	/* directory fd for connectat() */
	int			vsc_ctl_fd;	/* control socket (listener) */
	struct mevent		*vsc_ctl_evp;

	/* Active connections */
	struct vtvsock_conn_list vsc_conns;
	uint32_t		vsc_conn_count;
	uint32_t		vsc_next_port;	/* next port to try assigning */

	/* Pending control connections */
	struct vtvsock_ctl_conn_list vsc_ctl_conns;
};

/* Forward declarations */
static void pci_vtvsock_reset(void *);
static void pci_vtvsock_notify_rx(void *, struct vqueue_info *);
static void pci_vtvsock_notify_tx(void *, struct vqueue_info *);
static void pci_vtvsock_notify_event(void *, struct vqueue_info *);
static int  pci_vtvsock_cfgread(void *, int, int, uint32_t *);
static int  pci_vtvsock_cfgwrite(void *, int, int, uint32_t);
static void pci_vtvsock_neg_features(void *, uint64_t);
static int  pci_vtvsock_legacy_config(nvlist_t *, const char *);
static void vtvsock_conn_data_cb(int, enum ev_type, void *);
static void vtvsock_conn_close(struct pci_vtvsock_softc *,
    struct vtvsock_conn *);

static struct virtio_consts vtvsock_vi_consts = {
	.vc_name =		"vtvsock",
	.vc_nvq =		VTVSOCK_MAXQ,
	.vc_cfgsize =		sizeof(struct virtio_vsock_config),
	.vc_reset =		pci_vtvsock_reset,
	.vc_cfgread =		pci_vtvsock_cfgread,
	.vc_cfgwrite =		pci_vtvsock_cfgwrite,
	.vc_apply_features =	pci_vtvsock_neg_features,
	.vc_hv_caps =		VIRTIO_VSOCK_F_STREAM |
				VIRTIO_VSOCK_F_SEQPACKET |
				VIRTIO_VSOCK_F_NO_IMPLIED_STREAM,
};

/* -------------------------------------------------------------------------
 * Utility helpers
 * ---------------------------------------------------------------------- */

/*
 * Copy up to <len> bytes of <src> into the scatter/gather list <iov>/<niov>,
 * starting at byte offset <*offp> within the iov.  Advances *offp.
 * Returns the number of bytes actually written.
 */
static size_t
iov_copyout(const void *src, size_t len, const struct iovec *iov, int niov,
    size_t *offp)
{
	size_t skip = *offp;
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		uint8_t *base = (uint8_t *)iov[i].iov_base;
		size_t   cap  = iov[i].iov_len;

		if (skip >= cap) {
			skip -= cap;
			continue;
		}
		base += skip;
		cap  -= skip;
		skip  = 0;

		size_t n = MIN(cap, len - done);
		memcpy(base, (const uint8_t *)src + done, n);
		done += n;
	}
	*offp += done;
	return (done);
}

/*
 * Total byte capacity of an iov array.
 */
static size_t
iov_total(const struct iovec *iov, int niov)
{
	size_t total = 0;
	for (int i = 0; i < niov; i++)
		total += iov[i].iov_len;
	return (total);
}

/*
 * Copy bytes out of an iov array into a flat buffer, starting from the
 * beginning of the iov.  Returns the number of bytes copied.
 */
static size_t
iov_copyin(void *dst, size_t len, const struct iovec *iov, int niov)
{
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		size_t n = MIN(iov[i].iov_len, len - done);
		memcpy((uint8_t *)dst + done, iov[i].iov_base, n);
		done += n;
	}
	return (done);
}

/*
 * Copy bytes out of an iov array into a flat buffer, starting from byte
 * offset <skip> within the iov.  Returns the number of bytes copied.
 */
static size_t
iov_copyin_offset(void *dst, size_t len, const struct iovec *iov, int niov,
    size_t skip)
{
	size_t done = 0;

	for (int i = 0; i < niov && done < len; i++) {
		uint8_t *base = (uint8_t *)iov[i].iov_base;
		size_t   cap  = iov[i].iov_len;

		if (skip >= cap) {
			skip -= cap;
			continue;
		}
		base += skip;
		cap  -= skip;
		skip  = 0;

		size_t n = MIN(cap, len - done);
		memcpy((uint8_t *)dst + done, base, n);
		done += n;
	}
	return (done);
}

/*
 * Send a file descriptor over a Unix socket via SCM_RIGHTS, accompanied
 * by <datalen> bytes of inline data.
 */
static int
vtvsock_send_fd(int sock, int fd, const void *data, size_t datalen)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr hdr;
		uint8_t buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = __DECONST(void *, data);
	iov.iov_len = datalen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return (sendmsg(sock, &msg, 0) >= 0 ? 0 : -1);
}

/* -------------------------------------------------------------------------
 * Port allocation
 * ---------------------------------------------------------------------- */

/*
 * Allocate a host-side port not already in use.  Must be called with
 * vsc_mtx held.  Returns 0 on failure (extremely unlikely in practice).
 */
static uint32_t
vtvsock_alloc_port(struct pci_vtvsock_softc *sc)
{
	uint32_t start = sc->vsc_next_port;
	struct vtvsock_conn *c;

	for (;;) {
		uint32_t port = sc->vsc_next_port;

		/* Wrap around, skipping the reserved range */
		if (sc->vsc_next_port == UINT32_MAX)
			sc->vsc_next_port = VTVSOCK_PORT_MIN;
		else
			sc->vsc_next_port++;

		/* Check for collision */
		bool used = false;
		TAILQ_FOREACH(c, &sc->vsc_conns, link) {
			if (c->local_port == port) {
				used = true;
				break;
			}
		}
		if (!used)
			return (port);

		/* Full wrap: no port available */
		if (sc->vsc_next_port == start)
			return (0);
	}
}

/* -------------------------------------------------------------------------
 * Connection lifecycle
 * ---------------------------------------------------------------------- */

static struct vtvsock_conn *
vtvsock_conn_alloc(struct pci_vtvsock_softc *sc, int fd, uint32_t guest_port)
{
	struct vtvsock_conn *conn;
	uint32_t port;

	if (sc->vsc_conn_count >= VTVSOCK_MAX_CONNS) {
		WPRINTF(("vtvsock: connection limit reached (%u)",
		    VTVSOCK_MAX_CONNS));
		return (NULL);
	}

	port = vtvsock_alloc_port(sc);
	if (port == 0) {
		WPRINTF(("vtvsock: no free host ports"));
		return (NULL);
	}

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return (NULL);

	conn->sc         = sc;
	conn->fd         = fd;
	conn->ctl_fd     = -1;
	conn->reply_fd   = -1;
	conn->local_port = port;
	conn->guest_port = guest_port;
	conn->state      = CONN_CONNECTING;
	conn->type       = VIRTIO_VSOCK_TYPE_STREAM;
	conn->buf_alloc  = VTVSOCK_BUF_ALLOC;
	conn->evp        = NULL;

	TAILQ_INSERT_TAIL(&sc->vsc_conns, conn, link);
	sc->vsc_conn_count++;
	return (conn);
}

/*
 * Find an established connection by (guest_src_cid, guest_src_port,
 * dst_cid, dst_port).  We are the destination (CID 2).
 *
 * For packets from the guest: src_cid == guest_cid, src_port == guest_port,
 * dst_cid == VSOCK_CID_HOST, dst_port == local_port.
 */
static struct vtvsock_conn *
vtvsock_conn_find(struct pci_vtvsock_softc *sc,
    uint64_t src_cid __unused, uint32_t src_port,
    uint64_t dst_cid __unused, uint32_t dst_port)
{
	struct vtvsock_conn *c;

	TAILQ_FOREACH(c, &sc->vsc_conns, link) {
		if (c->guest_port == src_port && c->local_port == dst_port)
			return (c);
	}
	return (NULL);
}

/*
 * Tear down a connection: remove its mevent, close the fd (if any), and free
 * the structure.  Must be called with vsc_mtx held.
 */
static void
vtvsock_conn_close(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{
	TAILQ_REMOVE(&sc->vsc_conns, conn, link);
	sc->vsc_conn_count--;

	if (conn->evp != NULL) {
		mevent_delete_close(conn->evp);	/* also closes conn->fd */
		conn->evp = NULL;
		conn->fd  = -1;
	} else if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	if (conn->reply_fd >= 0) {
		close(conn->reply_fd);
		conn->reply_fd = -1;
	}

	/*
	 * Clean up the associated ctl_conn if this was a host-initiated
	 * connection.  The ctl_fd is owned by the ctl_conn; close it
	 * there so the mevent teardown is handled properly.
	 */
	if (conn->ctl_fd >= 0) {
		struct vtvsock_ctl_conn *cc, *cctmp;

		TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
			if (cc->fd == conn->ctl_fd) {
				TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
				if (cc->evp != NULL)
					mevent_delete_close(cc->evp);
				else
					close(cc->fd);
				free(cc);
				break;
			}
		}
		conn->ctl_fd = -1;
	}

	free(conn);
}

/* -------------------------------------------------------------------------
 * Injecting packets into the RX (host->guest) virtqueue
 * ---------------------------------------------------------------------- */

/*
 * Build a virtio_vsock_hdr + optional payload and inject it into the RX
 * virtqueue.  Must be called with vsc_mtx held.
 *
 * Returns 0 on success, -1 if no descriptors were available.
 */
static int
vtvsock_inject_rx(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    uint16_t op, uint32_t flags, const void *payload, uint32_t paylen)
{
	struct vqueue_info *vq = &sc->vsc_queues[VTVSOCK_RXQ];
	struct virtio_vsock_hdr hdr;
	struct vi_req req;
	struct iovec iov[VTVSOCK_MAX_IOV];
	int n;
	size_t off, avail;

	if (!vq_has_descs(vq))
		return (-1);

	memset(&hdr, 0, sizeof(hdr));
	hdr.src_cid    = htole64(VSOCK_CID_HOST);
	hdr.dst_cid    = htole64(sc->vsc_guest_cid);
	hdr.src_port   = htole32(conn->local_port);
	hdr.dst_port   = htole32(conn->guest_port);
	hdr.len        = htole32(paylen);
	hdr.type       = htole16(conn->type);
	hdr.op         = htole16(op);
	hdr.flags      = htole32(flags);
	hdr.buf_alloc  = htole32(conn->buf_alloc);
	hdr.fwd_cnt    = htole32(conn->fwd_cnt);

	n = vq_getchain(vq, iov, VTVSOCK_MAX_IOV, &req);
	if (n <= 0)
		return (-1);

	avail = iov_total(iov, n);
	if (avail < sizeof(hdr) + paylen) {
		WPRINTF(("vtvsock: rx descriptor too small (%zu < %zu)",
		    avail, sizeof(hdr) + paylen));
		vq_relchain(vq, req.idx, 0);
		vq_endchains(vq, 0);
		return (-1);
	}

	off = 0;
	iov_copyout(&hdr, sizeof(hdr), iov, n, &off);
	if (paylen > 0 && payload != NULL)
		iov_copyout(payload, paylen, iov, n, &off);

	vq_relchain(vq, req.idx, (uint32_t)off);
	vq_endchains(vq, 1);
	return (0);
}

/*
 * Send a control packet with no payload.
 */
static int
vtvsock_send_ctrl(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    uint16_t op, uint32_t flags)
{
	return (vtvsock_inject_rx(sc, conn, op, flags, NULL, 0));
}

/* -------------------------------------------------------------------------
 * Credit helpers
 * ---------------------------------------------------------------------- */

/*
 * Return the number of bytes we can still send to the guest for this
 * connection before the guest's receive buffer is full.
 */
static uint32_t
vtvsock_peer_credit(const struct vtvsock_conn *conn)
{
	int32_t avail;

	avail = (int32_t)(conn->peer_buf_alloc -
	    (conn->tx_cnt - conn->peer_fwd_cnt));
	if (avail <= 0)
		return (0);
	return ((uint32_t)avail);
}

/*
 * Decide whether we need to send a CREDIT_UPDATE to the guest.  We do so
 * when we have freed a significant amount of buffer space since the last
 * update we sent.
 */
static bool
vtvsock_need_credit_update(const struct vtvsock_conn *conn)
{
	return ((conn->fwd_cnt - conn->last_fwd_cnt) >=
	    VTVSOCK_CREDIT_UPDATE_THRESHOLD);
}

/* -------------------------------------------------------------------------
 * TX (guest -> host) virtqueue processing
 * ---------------------------------------------------------------------- */

/*
 * Process one virtio_vsock_hdr packet from the guest.
 * Must be called with vsc_mtx held.
 */
static void
vtvsock_process_tx_pkt(struct pci_vtvsock_softc *sc,
    const struct virtio_vsock_hdr *hdr, const uint8_t *payload, uint32_t paylen)
{
	uint64_t src_cid  = le64toh(hdr->src_cid);
	uint64_t dst_cid  = le64toh(hdr->dst_cid);
	uint32_t src_port = le32toh(hdr->src_port);
	uint32_t dst_port = le32toh(hdr->dst_port);
	uint16_t op       = le16toh(hdr->op);
	uint16_t type     = le16toh(hdr->type);
	uint32_t flags    = le32toh(hdr->flags);
	struct vtvsock_conn *conn;

	DPRINTF(("vtvsock: tx pkt op=%u src=%llu:%u dst=%llu:%u len=%u",
	    op, (unsigned long long)src_cid, src_port,
	    (unsigned long long)dst_cid, dst_port, paylen));

	/* Validate destination */
	if (dst_cid != VSOCK_CID_HOST) {
		DPRINTF(("vtvsock: dropping pkt for unknown cid %llu",
		    (unsigned long long)dst_cid));
		return;
	}

	/* Validate source CID: reject packets claiming to be from a different guest */
	if (src_cid != sc->vsc_guest_cid) {
		DPRINTF(("vtvsock: dropping spoofed pkt: src_cid %llu != guest_cid %llu",
		    (unsigned long long)src_cid,
		    (unsigned long long)sc->vsc_guest_cid));
		return;
	}

	/*
	 * Validate type field (§5.10.6.4.2: RST for unknown type).
	 * Must create a temporary conn to send the RST with correct
	 * addressing; use a stack-local struct for this purpose.
	 */
	if (type != VIRTIO_VSOCK_TYPE_STREAM &&
	    type != VIRTIO_VSOCK_TYPE_SEQPACKET) {
		struct vtvsock_conn tmp;

		memset(&tmp, 0, sizeof(tmp));
		tmp.local_port = dst_port;
		tmp.guest_port = src_port;
		tmp.type       = type;
		tmp.fd         = -1;
		tmp.ctl_fd     = -1;
		tmp.reply_fd   = -1;
		WPRINTF(("vtvsock: unknown type %u from guest, sending RST",
		    type));
		(void)vtvsock_send_ctrl(sc, &tmp, VIRTIO_VSOCK_OP_RST, 0);
		return;
	}

	/*
	 * Extract peer credit state from every incoming packet (not just
	 * OP_CREDIT_UPDATE).  The guest piggybacks buf_alloc/fwd_cnt on
	 * all packet types.  Skip OP_REQUEST since the connection doesn't
	 * exist yet (credit is extracted in the handler below).
	 */
	if (op != VIRTIO_VSOCK_OP_REQUEST) {
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn != NULL) {
			uint32_t new_fwd_cnt;

			conn->peer_buf_alloc = le32toh(hdr->buf_alloc);
			/*
			 * Validate peer_fwd_cnt: must not claim to have
			 * consumed more bytes than we have sent (tx_cnt).
			 * Use signed comparison for 32-bit wrap safety.
			 */
			new_fwd_cnt = le32toh(hdr->fwd_cnt);
			if ((int32_t)(new_fwd_cnt - conn->tx_cnt) > 0) {
				DPRINTF(("vtvsock: guest fwd_cnt %u > "
				    "tx_cnt %u, sending RST",
				    new_fwd_cnt, conn->tx_cnt));
				(void)vtvsock_send_ctrl(sc, conn,
				    VIRTIO_VSOCK_OP_RST, 0);
				vtvsock_conn_close(sc, conn);
				return;
			}
			conn->peer_fwd_cnt = new_fwd_cnt;
		} else if (op != VIRTIO_VSOCK_OP_RST) {
			/*
			 * §5.10.6.4: packet for an unknown connection
			 * that is not itself a RST — reply with RST.
			 */
			struct vtvsock_conn tmp;

			memset(&tmp, 0, sizeof(tmp));
			tmp.local_port = dst_port;
			tmp.guest_port = src_port;
			tmp.type       = type;
			tmp.fd         = -1;
			tmp.ctl_fd     = -1;
			tmp.reply_fd   = -1;
			DPRINTF(("vtvsock: no conn for op %u %u:%u, "
			    "sending RST", op, src_port, dst_port));
			(void)vtvsock_send_ctrl(sc, &tmp,
			    VIRTIO_VSOCK_OP_RST, 0);
			return;
		} else {
			/* RST for unknown connection — silently ignore. */
			return;
		}
	}

	switch (op) {
	case VIRTIO_VSOCK_OP_REQUEST:
		/*
		 * Guest wants to connect to a host-side port.
		 *
		 * Try to connectat() to a host-side Unix socket at
		 * "<port>" relative to vsc_dfd.  If a host application
		 * is listening there, relay data bidirectionally.
		 * If not, reject with RST.
		 */
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn != NULL) {
			DPRINTF(("vtvsock: duplicate REQUEST for %u:%u, RST",
			    src_port, dst_port));
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RST, 0);
			vtvsock_conn_close(sc, conn);
			break;
		}
		{
			struct sockaddr_un csun;
			char portstr[16];
			int cfd;
#ifndef WITHOUT_CAPSICUM
			cap_rights_t crights;
#endif

			snprintf(portstr, sizeof(portstr), "%u", dst_port);

			memset(&csun, 0, sizeof(csun));
			csun.sun_family = AF_UNIX;
			csun.sun_len    = sizeof(csun);
			strlcpy(csun.sun_path, portstr, sizeof(csun.sun_path));

			cfd = socket(AF_UNIX,
			    (type == VIRTIO_VSOCK_TYPE_SEQPACKET ?
			    SOCK_SEQPACKET : SOCK_STREAM) | SOCK_NONBLOCK, 0);
			if (cfd < 0) {
				DPRINTF(("vtvsock: socket for guest REQUEST "
				    "failed: %s", strerror(errno)));
				/* Send RST so guest doesn't hang. */
				{
					struct vtvsock_conn tmp;
					memset(&tmp, 0, sizeof(tmp));
					tmp.local_port = dst_port;
					tmp.guest_port = src_port;
					tmp.type       = type;
					tmp.fd         = -1;
					tmp.ctl_fd     = -1;
					tmp.reply_fd   = -1;
					(void)vtvsock_send_ctrl(sc, &tmp,
					    VIRTIO_VSOCK_OP_RST, 0);
				}
				break;
			}
			if (connectat(sc->vsc_dfd, cfd,
			    (struct sockaddr *)&csun, csun.sun_len) < 0) {
				DPRINTF(("vtvsock: no host listener at %s/%s: %s",
				    sc->vsc_path, portstr, strerror(errno)));
				close(cfd);
				/* No listener; reject the connection. */
				{
					struct vtvsock_conn tmp;
					memset(&tmp, 0, sizeof(tmp));
					tmp.local_port = dst_port;
					tmp.guest_port = src_port;
					tmp.type       = type;
					tmp.fd         = -1;
					tmp.ctl_fd     = -1;
					tmp.reply_fd   = -1;
					(void)vtvsock_send_ctrl(sc, &tmp,
					    VIRTIO_VSOCK_OP_RST, 0);
				}
				break;
			}

#ifndef WITHOUT_CAPSICUM
			cap_rights_init(&crights, CAP_EVENT, CAP_RECV,
			    CAP_SEND);
			if (caph_rights_limit(cfd, &crights) == -1) {
				close(cfd);
				/* Send RST so guest doesn't hang. */
				{
					struct vtvsock_conn tmp;
					memset(&tmp, 0, sizeof(tmp));
					tmp.local_port = dst_port;
					tmp.guest_port = src_port;
					tmp.type       = type;
					tmp.fd         = -1;
					tmp.ctl_fd     = -1;
					tmp.reply_fd   = -1;
					(void)vtvsock_send_ctrl(sc, &tmp,
					    VIRTIO_VSOCK_OP_RST, 0);
				}
				break;
			}
			vtvsock_cap_lockdown(cfd);
#endif

			conn = vtvsock_conn_alloc(sc, cfd, src_port);
			if (conn == NULL) {
				WPRINTF(("vtvsock: cannot alloc conn for "
				    "guest REQUEST"));
				close(cfd);
				/* Send RST so guest doesn't hang. */
				{
					struct vtvsock_conn tmp;
					memset(&tmp, 0, sizeof(tmp));
					tmp.local_port = dst_port;
					tmp.guest_port = src_port;
					tmp.type       = type;
					tmp.fd         = -1;
					tmp.ctl_fd     = -1;
					tmp.reply_fd   = -1;
					(void)vtvsock_send_ctrl(sc, &tmp,
					    VIRTIO_VSOCK_OP_RST, 0);
				}
				break;
			}
			conn->local_port     = dst_port;
			conn->type           = type;
			conn->ctl_fd         = -1;
			conn->reply_fd       = -1;
			conn->peer_buf_alloc = le32toh(hdr->buf_alloc);
			conn->peer_fwd_cnt   = le32toh(hdr->fwd_cnt);
			conn->state          = CONN_ESTABLISHED;

			conn->evp = mevent_add(cfd, EVF_READ,
			    vtvsock_conn_data_cb, conn);
			if (conn->evp == NULL) {
				WPRINTF(("vtvsock: mevent_add failed for "
				    "guest-initiated conn"));
				(void)vtvsock_send_ctrl(sc, conn,
				    VIRTIO_VSOCK_OP_RST, 0);
				vtvsock_conn_close(sc, conn);
				break;
			}

			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RESPONSE, 0);
			DPRINTF(("vtvsock: relay guest conn guest_port=%u "
			    "host_port=%u via %s/%s", src_port, dst_port,
			    sc->vsc_path, portstr));
		}
		break;

	case VIRTIO_VSOCK_OP_RESPONSE:
		/*
		 * Guest is responding to our OP_REQUEST; move the connection
		 * from CONNECTING to ESTABLISHED.
		 */
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL || conn->state != CONN_CONNECTING) {
			DPRINTF(("vtvsock: unexpected RESPONSE for %u:%u",
			    src_port, dst_port));
			break;
		}
		/* peer_buf_alloc/peer_fwd_cnt already set in pre-switch. */
		conn->state          = CONN_ESTABLISHED;

		/*
		 * Host-initiated connection: send reply + fd back to the
		 * host app via the control connection.
		 */
		if (conn->ctl_fd >= 0 && conn->reply_fd >= 0) {
			struct vsock_ctl_msg reply;

			memset(&reply, 0, sizeof(reply));
			reply.cmd    = VSOCK_CTL_CONNECT;
			reply.port   = conn->guest_port;
			reply.status = 0;

			if (vtvsock_send_fd(conn->ctl_fd, conn->reply_fd,
			    &reply, sizeof(reply)) < 0) {
				WPRINTF(("vtvsock: failed to send reply fd: %s",
				    strerror(errno)));
			}

			close(conn->reply_fd);
			conn->reply_fd = -1;

			/*
			 * Remove the ctl_conn from the list and close it.
			 * The ctl_conn's mevent was already used; find and
			 * clean it up.
			 */
			{
				struct vtvsock_ctl_conn *cc, *cctmp;
				TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns,
				    link, cctmp) {
					if (cc->fd == conn->ctl_fd) {
						TAILQ_REMOVE(&sc->vsc_ctl_conns,
						    cc, link);
						if (cc->evp != NULL)
							mevent_delete_close(cc->evp);
						else
							close(cc->fd);
						free(cc);
						break;
					}
				}
			}
			conn->ctl_fd = -1;
		}

		/* Arm the mevent now that the connection is established */
		if (conn->fd >= 0) {
			conn->evp = mevent_add(conn->fd, EVF_READ,
			    vtvsock_conn_data_cb, conn);
			if (conn->evp == NULL) {
				WPRINTF(("vtvsock: mevent_add failed after "
				    "RESPONSE"));
				(void)vtvsock_send_ctrl(sc, conn,
				    VIRTIO_VSOCK_OP_RST, 0);
				vtvsock_conn_close(sc, conn);
			}
		}
		DPRINTF(("vtvsock: connection established local_port=%u "
		    "guest_port=%u", dst_port, src_port));
		break;

	case VIRTIO_VSOCK_OP_RST:
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL)
			break;
		DPRINTF(("vtvsock: RST local_port=%u guest_port=%u",
		    conn->local_port, conn->guest_port));

		/*
		 * If this was a host-initiated connection that the guest
		 * rejected, send an error reply to the host app.
		 */
		if (conn->ctl_fd >= 0) {
			struct vsock_ctl_msg reply;

			memset(&reply, 0, sizeof(reply));
			reply.cmd    = VSOCK_CTL_CONNECT;
			reply.port   = conn->guest_port;
			reply.status = -ECONNREFUSED;

			(void)send(conn->ctl_fd, &reply, sizeof(reply), 0);
		}

		vtvsock_conn_close(sc, conn);
		break;

	case VIRTIO_VSOCK_OP_SHUTDOWN:
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL)
			break;
		DPRINTF(("vtvsock: SHUTDOWN flags=0x%x local_port=%u "
		    "guest_port=%u", flags, conn->local_port, conn->guest_port));

		/*
		 * Accumulate peer shutdown flags (§5.10.6.5: "These hints
		 * are permanent once sent and successive packets with bits
		 * clear do not reset them").
		 *
		 * SHUTDOWN_RCV: guest will not receive — half-close our
		 *   send direction (shutdown write side of host fd).
		 * SHUTDOWN_SEND: guest will not send — half-close our
		 *   receive direction (shutdown read side of host fd).
		 *
		 * Only RST and tear down when both directions are shut.
		 */
		conn->peer_shutdown |= (flags &
		    (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND));

		if (conn->fd >= 0) {
			if (flags & VIRTIO_VSOCK_SHUTDOWN_RCV)
				shutdown(conn->fd, SHUT_WR);
			if (flags & VIRTIO_VSOCK_SHUTDOWN_SEND) {
				if (conn->evp != NULL) {
					mevent_disable(conn->evp);
				}
			}
		}

		if (conn->peer_shutdown ==
		    (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND)) {
			conn->state = CONN_CLOSING;
			conn->close_time = monotonic_seconds();
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RST, 0);
			vtvsock_conn_close(sc, conn);
		}
		break;

	case VIRTIO_VSOCK_OP_RW:
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL) {
			DPRINTF(("vtvsock: RW for unknown conn %u:%u",
			    src_port, dst_port));
			break;
		}
		if (conn->state == CONN_CLOSING) {
			/*
			 * We sent SHUTDOWN but guest hasn't processed it
			 * yet.  Accept the data for credit accounting but
			 * discard the payload — there's no host consumer.
			 */
			conn->fwd_cnt += paylen;
			break;
		}
		if (conn->state != CONN_ESTABLISHED) {
			DPRINTF(("vtvsock: RW for non-established conn "
			    "%u:%u (state %d)", src_port, dst_port,
			    conn->state));
			break;
		}

		/* Update credit: we consumed paylen bytes from the guest */
		conn->fwd_cnt += paylen;

		/* Forward payload to host Unix socket, if connected */
		if (conn->fd >= 0 && paylen > 0) {
			const uint8_t *p = payload;
			uint32_t remain = paylen;
			int retries = 0;

			while (remain > 0) {
				ssize_t sent = send(conn->fd, p, remain,
				    MSG_NOSIGNAL);
				if (sent < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK) {
						/*
						 * Host socket is full.  Drop
						 * the mutex so other vsock
						 * activity can proceed, sleep
						 * briefly, then retry.
						 *
						 * Cap retries to prevent a
						 * malicious guest from stalling
						 * the TX processing loop
						 * indefinitely.
						 *
						 * Re-lookup the connection
						 * after re-acquiring the lock:
						 * it may have been closed by a
						 * concurrent callback while the
						 * mutex was released.
						 */
						if (++retries > 50) {
							WPRINTF(("vtvsock: "
							    "send retries "
							    "exhausted, "
							    "closing conn"));
							(void)vtvsock_send_ctrl(
							    sc, conn,
							    VIRTIO_VSOCK_OP_RST,
							    0);
							vtvsock_conn_close(sc,
							    conn);
							conn = NULL;
							break;
						}
						pthread_mutex_unlock(
						    &sc->vsc_mtx);
						usleep(1000);
						pthread_mutex_lock(
						    &sc->vsc_mtx);
						conn = vtvsock_conn_find(sc,
						    src_cid, src_port,
						    dst_cid, dst_port);
						if (conn == NULL ||
						    conn->state !=
						    CONN_ESTABLISHED ||
						    conn->fd < 0)
							break;
						continue;
					}
					WPRINTF(("vtvsock: send to host fd "
					    "failed: %s", strerror(errno)));
					(void)vtvsock_send_ctrl(sc, conn,
					    VIRTIO_VSOCK_OP_RST, 0);
					vtvsock_conn_close(sc, conn);
					break;
				}
				p += sent;
				remain -= (uint32_t)sent;
			}
			if (remain > 0)
				break;
		}

		/* Possibly send CREDIT_UPDATE */
		if (vtvsock_need_credit_update(conn)) {
			conn->last_fwd_cnt = conn->fwd_cnt;
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
		}
		break;

	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		/*
		 * Peer is advertising new/updated RX capacity.
		 * peer_buf_alloc and peer_fwd_cnt were already extracted
		 * and validated in the pre-switch credit parsing above.
		 * Re-lookup the connection for the mevent re-enable below.
		 */
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL)
			break;
		DPRINTF(("vtvsock: CREDIT_UPDATE local_port=%u peer_buf=%u "
		    "peer_fwd=%u", conn->local_port,
		    conn->peer_buf_alloc, conn->peer_fwd_cnt));
		/*
		 * If credit opened up and we have a host fd that may have
		 * deferred data, re-enable the mevent so the event loop
		 * retries the send.  Avoid recursive vtvsock_conn_data_cb
		 * calls which risk use-after-free during TAILQ iteration.
		 */
		if (conn->state == CONN_ESTABLISHED &&
		    vtvsock_peer_credit(conn) > 0 &&
		    conn->fd >= 0 && conn->evp != NULL) {
			mevent_enable(conn->evp);
		}
		break;

	case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
		conn = vtvsock_conn_find(sc, src_cid, src_port, dst_cid,
		    dst_port);
		if (conn == NULL)
			break;
		/* Reply with our current credit state */
		conn->last_fwd_cnt = conn->fwd_cnt;
		(void)vtvsock_send_ctrl(sc, conn,
		    VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
		break;

	default:
		WPRINTF(("vtvsock: unknown op %u from guest, ignoring", op));
		break;
	}
}

/* -------------------------------------------------------------------------
 * Virtqueue notify callbacks
 * ---------------------------------------------------------------------- */

/*
 * TX queue: guest -> host.
 *
 * Each descriptor chain contains a virtio_vsock_hdr followed by (optional)
 * payload bytes.  We parse the header and dispatch to vtvsock_process_tx_pkt.
 */
static void
pci_vtvsock_notify_tx(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtvsock_softc *sc = vsc;
	struct virtio_vsock_hdr hdr;
	struct vi_req req;
	struct iovec iov[VTVSOCK_MAX_IOV];
	uint8_t *payload = NULL;
	int n;

	pthread_mutex_lock(&sc->vsc_mtx);

	while (vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, VTVSOCK_MAX_IOV, &req);
		if (n <= 0)
			break;

		size_t total = iov_total(iov, n);
		if (total < sizeof(hdr)) {
			WPRINTF(("vtvsock: tx pkt too small (%zu)", total));
			vq_relchain(vq, req.idx, 0);
			continue;
		}

		iov_copyin(&hdr, sizeof(hdr), iov, n);

		uint32_t paylen = le32toh(hdr.len);
		if (paylen > VTVSOCK_MAX_PKT) {
			WPRINTF(("vtvsock: tx payload too large (%u), dropping",
			    paylen));
			vq_relchain(vq, req.idx, 0);
			continue;
		}

		/* Extract payload from iov (skip the header bytes) */
		if (paylen > 0) {
			free(payload);
			payload = malloc(paylen);
			if (payload == NULL) {
				WPRINTF(("vtvsock: payload malloc failed"));
				vq_relchain(vq, req.idx, 0);
				continue;
			}
			/*
			 * The iov may contain header + payload contiguously.
			 * We need to copy just the payload portion.  Build a
			 * temporary flat buffer of the whole chain and slice it.
			 */
			if (total >= sizeof(hdr) + paylen) {
				iov_copyin_offset(payload, paylen, iov, n,
				    sizeof(hdr));
			} else {
				/* Payload truncated; treat as empty */
				paylen = 0;
			}
		}

		vtvsock_process_tx_pkt(sc, &hdr, payload, paylen);
		/* TX is output-only; device does not write back to the desc. */
		vq_relchain(vq, req.idx, 0);
	}

	vq_endchains(vq, 1);
	free(payload);

	/*
	 * Reap stale CONN_CLOSING connections that the guest never
	 * acknowledged with RST (e.g., wedged guest).  8 seconds matches
	 * the kernel driver's VTVSOCK_CLOSE_TIMEOUT.
	 */
	{
		struct vtvsock_conn *conn, *tmp;
		time_t now = monotonic_seconds();

		TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp) {
			if (conn->state == CONN_CLOSING &&
			    conn->close_time != 0 &&
			    now - conn->close_time >= 8) {
				DPRINTF(("vtvsock: reaping stale CLOSING conn "
				    "local_port=%u", conn->local_port));
				(void)vtvsock_send_ctrl(sc, conn,
				    VIRTIO_VSOCK_OP_RST, 0);
				vtvsock_conn_close(sc, conn);
			}
		}
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

/*
 * RX notify: the guest has added new descriptors to the RX ring.
 *
 * If data was deferred because the ring was full (no descriptors), the
 * mevent won't re-fire on its own (edge-triggered).  Re-enable the
 * mevent for each established connection so the event loop retries.
 */
static void
pci_vtvsock_notify_rx(void *vsc, struct vqueue_info *vq __unused)
{
	struct pci_vtvsock_softc *sc = vsc;
	struct vtvsock_conn *conn;

	pthread_mutex_lock(&sc->vsc_mtx);
	TAILQ_FOREACH(conn, &sc->vsc_conns, link) {
		if (conn->state == CONN_ESTABLISHED &&
		    conn->fd >= 0 && conn->evp != NULL)
			mevent_enable(conn->evp);
	}
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_vtvsock_notify_event(void *vsc __unused, struct vqueue_info *vq __unused)
{
	/* Event queue is reserved by the spec; no host-side action. */
}

/* -------------------------------------------------------------------------
 * Host Unix socket I/O
 * ---------------------------------------------------------------------- */

/*
 * mevent callback: the host Unix socket fd for a connection is readable.
 *
 * State CONN_CONNECTING: ignore (we are waiting for OP_RESPONSE from guest).
 * State CONN_ESTABLISHED: read data and inject into RX virtqueue.
 * State CONN_CLOSING:  ignore.
 */
static void
vtvsock_conn_data_cb(int fd __unused, enum ev_type t __unused, void *arg)
{
	struct vtvsock_conn *conn = arg;
	struct pci_vtvsock_softc *sc = conn->sc;
	uint8_t *buf = NULL;
	ssize_t n;

	pthread_mutex_lock(&sc->vsc_mtx);

	switch (conn->state) {
	case CONN_CONNECTING:
		/* Nothing to do; waiting for OP_RESPONSE in notify_tx path */
		break;

	case CONN_ESTABLISHED: {
		/*
		 * Read data from the host-side Unix fd and inject
		 * into the RX (host->guest) virtqueue.
		 */
		uint32_t maxread;
		ssize_t readlen;
		int avail;

		/*
		 * Use FIONREAD to discover available bytes.  If 0
		 * (spurious wakeup or imminent EOF), use a small buffer
		 * so recv() can distinguish EOF (returns 0) from no-data
		 * (returns EAGAIN).
		 */
		avail = 0;
		(void)ioctl(conn->fd, FIONREAD, &avail);
		if (avail > 0)
			readlen = MIN(avail, VTVSOCK_MAX_PKT);
		else
			readlen = 4096;

		/* Cap by peer credit */
		maxread = vtvsock_peer_credit(conn);
		if (maxread == 0) {
			DPRINTF(("vtvsock: no peer credit, deferring send"));
			break;
		}
		if ((uint32_t)readlen > maxread)
			readlen = (ssize_t)maxread;

		/*
		 * Verify RX ring has descriptors BEFORE consuming data
		 * from the Unix socket.
		 */
		if (!vq_has_descs(&sc->vsc_queues[VTVSOCK_RXQ])) {
			DPRINTF(("vtvsock: RX ring full, deferring"));
			break;
		}

		buf = malloc((size_t)readlen);
		if (buf == NULL) {
			WPRINTF(("vtvsock: malloc failed for rx payload"));
			break;
		}
		n = recv(conn->fd, buf, (size_t)readlen, MSG_DONTWAIT);
		if (n <= 0) {
			free(buf);
			buf = NULL;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;
			if (n == 0) {
				/* EOF — host peer closed */
				DPRINTF(("vtvsock: host fd closed, sending "
				    "SHUTDOWN to guest"));
				conn->state = CONN_CLOSING;
				conn->close_time = monotonic_seconds();
				if (conn->evp != NULL)
					mevent_disable(conn->evp);
				(void)vtvsock_send_ctrl(sc, conn,
				    VIRTIO_VSOCK_OP_SHUTDOWN,
				    VIRTIO_VSOCK_SHUTDOWN_RCV |
				    VIRTIO_VSOCK_SHUTDOWN_SEND);
				break;
			}
			goto conn_error;
		}

		/*
		 * For SEQPACKET connections, each injected OP_RW is one
		 * complete message — set EOM|EOR so the guest sees proper
		 * message boundaries.  For STREAM, flags stay 0.
		 */
		{
			uint32_t rw_flags = 0;
			if (conn->type == VIRTIO_VSOCK_TYPE_SEQPACKET)
				rw_flags = VIRTIO_VSOCK_SEQ_EOM |
				    VIRTIO_VSOCK_SEQ_EOR;

			if (vtvsock_inject_rx(sc, conn, VIRTIO_VSOCK_OP_RW,
			    rw_flags, buf, (uint32_t)n) != 0) {
				WPRINTF(("vtvsock: RX injection failed, "
				    "closing"));
				free(buf);
				buf = NULL;
				goto conn_error;
			}
		}
		conn->tx_cnt += (uint32_t)n;

		free(buf);
		buf = NULL;
		break;
	}

	case CONN_CLOSING:
		break;

	default:
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
	return;

conn_error:
	DPRINTF(("vtvsock: connection error on fd %d, closing", conn->fd));
	(void)vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_RST, 0);
	vtvsock_conn_close(sc, conn);
	pthread_mutex_unlock(&sc->vsc_mtx);
}

/* -------------------------------------------------------------------------
 * Control socket handling
 * ---------------------------------------------------------------------- */

/*
 * mevent callback: a control connection fd is readable.
 * Read the vsock_ctl_msg and handle the command.
 */
static void
pci_vtvsock_ctl_conn_cb(int fd, enum ev_type t __unused, void *arg)
{
	struct pci_vtvsock_softc *sc = arg;
	struct vtvsock_ctl_conn *cc, *cctmp;
	struct vsock_ctl_msg msg;
	ssize_t nr;

	pthread_mutex_lock(&sc->vsc_mtx);

	/* Find the ctl_conn for this fd */
	cc = NULL;
	TAILQ_FOREACH(cctmp, &sc->vsc_ctl_conns, link) {
		if (cctmp->fd == fd) {
			cc = cctmp;
			break;
		}
	}
	if (cc == NULL) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	nr = recv(fd, &msg, sizeof(msg), MSG_DONTWAIT);
	if (nr != (ssize_t)sizeof(msg)) {
		/* Incomplete read or error — close the control connection */
		if (nr == 0 || (nr < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
			TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
			if (cc->evp != NULL)
				mevent_delete_close(cc->evp);
			else
				close(cc->fd);
			free(cc);
		}
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	switch (msg.cmd) {
	case VSOCK_CTL_CONNECT: {
		int pair[2];
		int stype;
		struct vtvsock_conn *conn;
		uint16_t vtype;
#ifndef WITHOUT_CAPSICUM
		cap_rights_t crights;
#endif

		if (msg.type == SOCK_SEQPACKET) {
			stype = SOCK_SEQPACKET;
			vtype = VIRTIO_VSOCK_TYPE_SEQPACKET;
		} else {
			stype = SOCK_STREAM;
			vtype = VIRTIO_VSOCK_TYPE_STREAM;
		}

		if (socketpair(AF_UNIX, stype, 0, pair) < 0) {
			struct vsock_ctl_msg reply;
			int err = errno;

			WPRINTF(("vtvsock: socketpair failed: %s",
			    strerror(err)));
			memset(&reply, 0, sizeof(reply));
			reply.cmd    = VSOCK_CTL_CONNECT;
			reply.port   = msg.port;
			reply.status = -err;
			(void)send(fd, &reply, sizeof(reply), 0);
			pthread_mutex_unlock(&sc->vsc_mtx);
			return;
		}

		/* pair[0] is bhyve's end; pair[1] goes to the host app */
		if (fcntl(pair[0], F_SETFL, O_NONBLOCK) < 0) {
			WPRINTF(("vtvsock: fcntl pair[0] failed: %s",
			    strerror(errno)));
			close(pair[0]);
			close(pair[1]);
			goto ctl_connect_fail;
		}

#ifndef WITHOUT_CAPSICUM
		cap_rights_init(&crights, CAP_EVENT, CAP_RECV, CAP_SEND);
		if (caph_rights_limit(pair[0], &crights) == -1) {
			WPRINTF(("vtvsock: rights on pair[0] failed"));
			close(pair[0]);
			close(pair[1]);
			goto ctl_connect_fail;
		}
		vtvsock_cap_lockdown(pair[0]);
		vtvsock_cap_lockdown_xfer_once(pair[1]);
#endif

		conn = vtvsock_conn_alloc(sc, pair[0], msg.port);
		if (conn == NULL) {
			WPRINTF(("vtvsock: cannot alloc conn for ctl connect"));
			close(pair[0]);
			close(pair[1]);
			goto ctl_connect_fail;
		}

		conn->type     = vtype;
		conn->ctl_fd   = fd;
		conn->reply_fd = pair[1];
		conn->state    = CONN_CONNECTING;
		/* Don't arm mevent on pair[0] yet — wait for ESTABLISHED.
		 * Disable the ctl_conn mevent so a second message can't
		 * arrive while we're waiting for OP_RESPONSE. */
		if (cc->evp != NULL)
			mevent_disable(cc->evp);

		DPRINTF(("vtvsock: sending OP_REQUEST to guest port %u "
		    "from host port %u (ctl)", msg.port, conn->local_port));

		if (vtvsock_send_ctrl(sc, conn,
		    VIRTIO_VSOCK_OP_REQUEST, 0) != 0) {
			struct vsock_ctl_msg reply;

			WPRINTF(("vtvsock: RX ring full, cannot send "
			    "OP_REQUEST"));
			/*
			 * Send the error reply BEFORE closing the
			 * connection, because vtvsock_conn_close() will
			 * tear down the ctl_conn and close its fd.
			 */
			memset(&reply, 0, sizeof(reply));
			reply.cmd    = VSOCK_CTL_CONNECT;
			reply.port   = msg.port;
			reply.status = -ENOMEM;
			(void)send(fd, &reply, sizeof(reply), 0);
			vtvsock_conn_close(sc, conn);
			break;
		}

		pthread_mutex_unlock(&sc->vsc_mtx);
		return;

ctl_connect_fail:
		{
			struct vsock_ctl_msg reply;

			memset(&reply, 0, sizeof(reply));
			reply.cmd    = VSOCK_CTL_CONNECT;
			reply.port   = msg.port;
			reply.status = -ENOMEM;
			(void)send(fd, &reply, sizeof(reply), 0);
		}
		break;
	}

	default:
		WPRINTF(("vtvsock: unknown ctl cmd %u", msg.cmd));
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

/*
 * mevent callback: the control socket listener has a new connection.
 */
static void
pci_vtvsock_ctl_accept(int fd __unused, enum ev_type t __unused, void *arg)
{
	struct pci_vtvsock_softc *sc = arg;
	struct sockaddr_un sun;
	socklen_t slen;
	struct vtvsock_ctl_conn *cc;
	int s;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	slen = sizeof(sun);
	s = accept(sc->vsc_ctl_fd, (struct sockaddr *)&sun, &slen);
	if (s < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			WPRINTF(("vtvsock: ctl accept failed: %s",
			    strerror(errno)));
		return;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		WPRINTF(("vtvsock: fcntl O_NONBLOCK failed: %s",
		    strerror(errno)));
		close(s);
		return;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_RECV, CAP_SEND);
	if (caph_rights_limit(s, &rights) == -1) {
		WPRINTF(("vtvsock: Unable to apply rights for ctl conn"));
		close(s);
		return;
	}
	vtvsock_cap_lockdown(s);
#endif

	cc = calloc(1, sizeof(*cc));
	if (cc == NULL) {
		close(s);
		return;
	}
	cc->fd = s;

	pthread_mutex_lock(&sc->vsc_mtx);
	TAILQ_INSERT_TAIL(&sc->vsc_ctl_conns, cc, link);
	pthread_mutex_unlock(&sc->vsc_mtx);

	cc->evp = mevent_add(s, EVF_READ, pci_vtvsock_ctl_conn_cb, sc);
	if (cc->evp == NULL) {
		WPRINTF(("vtvsock: mevent_add failed for ctl conn"));
		pthread_mutex_lock(&sc->vsc_mtx);
		TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
		pthread_mutex_unlock(&sc->vsc_mtx);
		close(s);
		free(cc);
		return;
	}
}

/* -------------------------------------------------------------------------
 * Virtio device callbacks
 * ---------------------------------------------------------------------- */

static void
pci_vtvsock_reset(void *vsc)
{
	struct pci_vtvsock_softc *sc = vsc;
	struct vtvsock_conn *conn, *tmp;
	struct vtvsock_ctl_conn *cc, *cctmp;

	DPRINTF(("vtvsock: device reset requested"));

	pthread_mutex_lock(&sc->vsc_mtx);
	/* Close all active connections */
	TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp)
		vtvsock_conn_close(sc, conn);
	/* Close all pending control connections */
	TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
		TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
		if (cc->evp != NULL)
			mevent_delete_close(cc->evp);
		else
			close(cc->fd);
		free(cc);
	}
	pthread_mutex_unlock(&sc->vsc_mtx);

	vi_reset_dev(&sc->vsc_vs);
}

static void
pci_vtvsock_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtvsock_softc *sc = vsc;

	sc->vsc_features = negotiated_features;
}

static int
pci_vtvsock_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtvsock_softc *sc = vsc;

	if (offset < 0 || size < 0 || size > (int)sizeof(uint32_t) ||
	    (unsigned)offset + (unsigned)size > sizeof(sc->vsc_config)) {
		*retval = 0;
		return (-1);
	}
	memcpy(retval, (uint8_t *)&sc->vsc_config + offset, size);
	return (0);
}

static int
pci_vtvsock_cfgwrite(void *vsc __unused, int offset __unused,
    int size __unused, uint32_t val __unused)
{
	/* Config space is read-only from the guest's perspective */
	return (1);
}

/* -------------------------------------------------------------------------
 * Legacy config string parsing
 * ---------------------------------------------------------------------- */

static int
pci_vtvsock_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *opt, *tofree, *str;
	int error;

	tofree = str = strdup(opts);
	if (str == NULL)
		return (-1);

	error = 0;
	while ((opt = strsep(&str, ",")) != NULL) {
		char *key, *val;

		key = strsep(&opt, "=");
		val = opt;
		if (key == NULL || val == NULL) {
			error = -1;
			break;
		}
		set_config_value_node(nvl, key, val);
	}
	free(tofree);
	return (error);
}

/* -------------------------------------------------------------------------
 * Device init
 * ---------------------------------------------------------------------- */

static int
pci_vtvsock_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtvsock_softc *sc;
	const char *cidstr, *path;
	pthread_mutexattr_t mtx_attr;
	struct sockaddr_un sun;
	int s   = -1;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (-1);

	sc->vsc_ctl_fd = -1;
	sc->vsc_dfd    = -1;
	sc->vsc_config.guest_cid = 0;
	sc->vsc_next_port = VTVSOCK_PORT_MIN;
	TAILQ_INIT(&sc->vsc_conns);
	TAILQ_INIT(&sc->vsc_ctl_conns);

	/* --- Validate and store CID --- */
	cidstr = get_config_value_node(nvl, "cid");
	if (cidstr == NULL) {
		WPRINTF(("vtvsock: cid is required"));
		goto failed;
	}
	char *endptr;
	errno = 0;
	uint64_t cid = strtoull(cidstr, &endptr, 0);
	if (errno != 0 || *endptr != '\0' || endptr == cidstr) {
		WPRINTF(("vtvsock: invalid cid '%s'", cidstr));
		goto failed;
	}
	if (cid < 3) {
		WPRINTF(("vtvsock: cid must be >= 3 (got %llu)",
		    (unsigned long long)cid));
		goto failed;
	}
	if (cid == VSOCK_CID_ANY) {
		WPRINTF(("vtvsock: cid 0xffffffffffffffff is reserved"));
		goto failed;
	}
	if (cid > UINT32_MAX) {
		WPRINTF(("vtvsock: cid must fit in 32 bits (got %llu)",
		    (unsigned long long)cid));
		goto failed;
	}
	sc->vsc_guest_cid = cid;
	sc->vsc_config.guest_cid = htole64(cid);

	/* --- Validate path (directory) --- */
	path = get_config_value_node(nvl, "path");
	if (path == NULL) {
		WPRINTF(("vtvsock: path is required"));
		goto failed;
	}
	sc->vsc_path = strdup(path);
	if (sc->vsc_path == NULL)
		goto failed;

	/* --- Mutex (recursive so virtio layer can re-enter) --- */
	if (pthread_mutexattr_init(&mtx_attr) != 0)
		goto failed;
	if (pthread_mutexattr_settype(&mtx_attr,
	    PTHREAD_MUTEX_RECURSIVE) != 0) {
		pthread_mutexattr_destroy(&mtx_attr);
		goto failed;
	}
	if (pthread_mutex_init(&sc->vsc_mtx, &mtx_attr) != 0) {
		pthread_mutexattr_destroy(&mtx_attr);
		goto failed;
	}
	pthread_mutexattr_destroy(&mtx_attr);

	/* --- Link virtio softc --- */
	vi_softc_linkup(&sc->vsc_vs, &vtvsock_vi_consts, sc, pi,
	    sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	for (int i = 0; i < VTVSOCK_MAXQ; i++)
		sc->vsc_queues[i].vq_qsize = VTVSOCK_RINGSZ;
	sc->vsc_queues[VTVSOCK_RXQ].vq_notify   = pci_vtvsock_notify_rx;
	sc->vsc_queues[VTVSOCK_TXQ].vq_notify   = pci_vtvsock_notify_tx;
	sc->vsc_queues[VTVSOCK_EVENTQ].vq_notify = pci_vtvsock_notify_event;

	/* --- PCI identity --- */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_VSOCK);
	pci_set_cfgdata16(pi, PCIR_VENDOR,  VIRTIO_VENDOR);
	pci_set_cfgdata8(pi,  PCIR_CLASS,   PCIC_SIMPLECOMM);
	pci_set_cfgdata8(pi,  PCIR_SUBCLASS, 0);

	/* --- Open directory fd --- */
	sc->vsc_dfd = open(path, O_RDONLY | O_DIRECTORY);
	if (sc->vsc_dfd < 0) {
		WPRINTF(("vtvsock: open dir '%s' failed: %s", path,
		    strerror(errno)));
		goto failed;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_CONNECTAT, CAP_LOOKUP);
	if (caph_rights_limit(sc->vsc_dfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox on dfd");
	vtvsock_cap_lockdown(sc->vsc_dfd);
#endif

	/* --- Create control socket at <dir>/sock --- */
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		WPRINTF(("vtvsock: socket failed: %s", strerror(errno)));
		goto failed;
	}

	/* Remove stale socket file from a previous run, if any. */
	(void)unlinkat(sc->vsc_dfd, "sock", 0);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len    = sizeof(sun);
	strlcpy(sun.sun_path, "sock", sizeof(sun.sun_path));

	if (bindat(sc->vsc_dfd, s, (struct sockaddr *)&sun, sun.sun_len) < 0) {
		WPRINTF(("vtvsock: bindat sock failed: %s", strerror(errno)));
		goto failed;
	}
	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		WPRINTF(("vtvsock: fcntl failed: %s", strerror(errno)));
		goto failed;
	}
	/* Require capability mode for connecting clients. */
#ifndef WITHOUT_CAPSICUM
	{
		int one = 1;
		(void)setsockopt(s, 0, LOCAL_CAP_CONNECT, &one, sizeof(one));
	}
#endif
	/* Backlog of 16 allows a burst of incoming host connections */
	if (listen(s, 16) < 0) {
		WPRINTF(("vtvsock: listen failed: %s", strerror(errno)));
		goto failed;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_RECV, CAP_SEND);
	if (caph_rights_limit(s, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox on ctl");
	vtvsock_cap_lockdown(s);
#endif

	sc->vsc_ctl_fd  = s;
	sc->vsc_ctl_evp = mevent_add(s, EVF_READ, pci_vtvsock_ctl_accept, sc);
	if (sc->vsc_ctl_evp == NULL) {
		WPRINTF(("vtvsock: mevent_add for control socket failed"));
		goto failed;
	}

	/* --- Virtio interrupt and BAR --- */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	vi_set_io_bar(&sc->vsc_vs, 0);

	return (0);

failed:
	if (s >= 0)
		close(s);
	if (sc != NULL) {
		struct vtvsock_conn *conn, *tmp;
		struct vtvsock_ctl_conn *cc, *cctmp;
		TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp)
			vtvsock_conn_close(sc, conn);
		TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
			TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
			if (cc->evp != NULL)
				mevent_delete_close(cc->evp);
			else
				close(cc->fd);
			free(cc);
		}
		if (sc->vsc_dfd >= 0)
			close(sc->vsc_dfd);
		if (sc->vsc_ctl_evp != NULL)
			mevent_delete(sc->vsc_ctl_evp);
		free(sc->vsc_path);
		pthread_mutex_destroy(&sc->vsc_mtx);
		free(sc);
	}
	return (-1);
}

/* -------------------------------------------------------------------------
 * PCI device registration
 * ---------------------------------------------------------------------- */

static const struct pci_devemu pci_de_vtvsock = {
	.pe_emu =		"virtio-vsock",
	.pe_init =		pci_vtvsock_init,
	.pe_barwrite =		vi_pci_write,
	.pe_barread =		vi_pci_read,
	.pe_legacy_config =	pci_vtvsock_legacy_config,
};
PCI_EMUL_SET(pci_de_vtvsock);
