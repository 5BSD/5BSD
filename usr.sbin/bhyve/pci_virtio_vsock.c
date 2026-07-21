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
 *
 * ---------------------------------------------------------------------------
 * Host application contract (what a host-side consumer needs to know)
 * ---------------------------------------------------------------------------
 * A host app talks to the guest over an ordinary Unix-domain socket (one end
 * of a socketpair for host-to-guest, or an accept()ed connection under <dir>
 * for guest-to-host).  The socket TYPE mirrors the vsock connection: a
 * SOCK_SEQPACKET vsock connection is relayed over a Unix SOCK_SEQPACKET
 * socket, SOCK_STREAM over SOCK_STREAM.  Bytes flow transparently; the device
 * handles all credit/flow-control.  A few SEQPACKET record semantics are
 * NOT obvious and follow from FreeBSD's Unix-socket behavior:
 *
 *   1. RECORD = ONE send.  To have the guest receive a datum as a single
 *      record, write it with a single send()/write() (or sendmsg()).  On
 *      FreeBSD a SOCK_SEQPACKET record boundary is marked by MSG_EOR; two
 *      plain write()s WITHOUT MSG_EOR coalesce into one record.  So a host
 *      app that dribbles one logical record across several write()s (no
 *      MSG_EOR) can have it split or merged.  Best practice: one send per
 *      record, and set MSG_EOR to make the boundary explicit.
 *
 *   2. RECORD SIZE.  Host->guest: the relay socketpair is sized to
 *      VTVSOCK_BUF_ALLOC (256 KiB), but the deliverable-record limit for a
 *      connection is the guest's advertised buf_alloc.  The device waits until
 *      current credit covers the whole record, then fragments it across
 *      on-wire packets while preserving one record boundary.  A record larger
 *      than the guest's full advertised window cannot be delivered; the host
 *      send may fail at the relay-socket limit, or the device resets the
 *      connection if it receives such a record.  Guest->host: records are
 *      reassembled up to 4 MiB -- BUT to RECEIVE a record larger than ~64 KiB
 *      the host app must raise SO_RCVBUF on its ACCEPTED socket.  FreeBSD caps a
 *      SOCK_SEQPACKET record at net.local.seqpacket.maxseqpacket (64 KiB) by
 *      default, and setting SO_RCVBUF on the LISTENER does NOT propagate to the
 *      accepted socket; without it a larger guest->host record is truncated to
 *      64 KiB on receipt (the device reassembled it correctly).
 *
 *   3. NO EMPTY RECORDS host->guest.  FreeBSD silently drops a zero-length
 *      SOCK_SEQPACKET send, so a host app cannot deliver an empty record to
 *      the guest (a zero-length send is a no-op, not a zero-length datagram).
 *
 *   4. HALF-CLOSE.  shutdown(fd, SHUT_WR) propagates to the guest as a vsock
 *      SHUTDOWN (the reverse direction stays open); a full close() tears the
 *      connection down.
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
#include <poll.h>
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
#include "pci_virtio_vsock_probes.h"
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
 * Host-side receive buffer advertised to the guest.  256 KiB matches the
 * kernel default (kern.vsock.buf_default) and Linux's default.
 */
#define	VTVSOCK_BUF_ALLOC	(256 * 1024)

/*
 * Upper bound on the guest-advertised receive window (peer_buf_alloc) that we
 * will honor.  The guest fully controls hdr.buf_alloc; a SEQPACKET host message
 * is read into a single malloc bounded by peer credit (<= peer_buf_alloc), so
 * clamping here keeps a pathological guest from sizing a huge host allocation.
 * 16x the default window is far above any legitimate configuration.
 */
#define	VTVSOCK_MAX_PEER_BUF_ALLOC	(4 * 1024 * 1024)

/*
 * Device-global cap on outstanding SEQPACKET reassembly bytes across ALL
 * connections.  Each connection is already bounded to
 * VTVSOCK_MAX_PEER_BUF_ALLOC (4 MiB), but with up to VTVSOCK_MAX_CONNS (256)
 * connections that would let a guest pin ~1 GiB of host memory in partially
 * reassembled records.  Bound the aggregate to 64 MiB (16 full-size records in
 * flight simultaneously -- far above any legitimate workload); a connection
 * whose next fragment would exceed the aggregate budget is reset.
 */
#define	VTVSOCK_MAX_TOTAL_REASM		(64 * 1024 * 1024)

/*
 * Device-global cap on outstanding asynchronous guest->host TX backlog bytes
 * parked in conn->tx_buf across ALL connections.  As with reassembly above,
 * the per-connection tx_buf cap (STREAM: buf_alloc; SEQPACKET:
 * VTVSOCK_MAX_PEER_BUF_ALLOC = 4 MiB) bounds a single connection, but with up
 * to VTVSOCK_MAX_CONNS (256) connections whose host consumer has stalled a
 * guest could otherwise pin ~1 GiB of host memory in parked records.  Bound
 * the aggregate to 64 MiB; a connection whose next append would exceed the
 * aggregate budget is reset.
 */
#define	VTVSOCK_MAX_TOTAL_TXBUF		(64 * 1024 * 1024)

/*
 * Send a CREDIT_UPDATE when we have freed at least this many bytes since the
 * last update we sent to the guest.
 */
#define	VTVSOCK_CREDIT_UPDATE_THRESHOLD	(VTVSOCK_BUF_ALLOC / 4)

/* First dynamically-assigned host-side port number */
#define	VTVSOCK_PORT_MIN	1024

/* Maximum simultaneous connections (prevents resource exhaustion) */
#define	VTVSOCK_MAX_CONNS	256

/* Maximum pending control connections */
#define	VTVSOCK_MAX_CTL_CONNS	16

/*
 * Capacity of the pending-reply ring: control packets (RESPONSE, RST,
 * SHUTDOWN, CREDIT_UPDATE) that could not be injected because the guest RX
 * ring had no descriptors.  §5.10.6.1.2 requires the device to keep
 * processing the tx virtqueue using resources outside the rings; without
 * this, a full RX ring silently dropped replies -- a lost RESPONSE turned a
 * successful connect into a guest-side timeout, a lost RST leaked a stale
 * guest connection.  Control packets are header-only, so the ring stores
 * bare headers (44 bytes each) and is flushed from pci_vtvsock_notify_rx as
 * the guest posts descriptors.  Bounded so a guest that never replenishes
 * its RX ring cannot grow host memory.
 */
#define	VTVSOCK_PEND_MAX	128

/*
 * Idle timeout (seconds) for a control connection that has connected but not
 * yet sent a VSOCK_CTL_CONNECT.  Without this, a host process could open and
 * hold all VTVSOCK_MAX_CTL_CONNS slots indefinitely.  Enforced by the periodic
 * reaper; ctl_conns with a request already in flight are referenced by their
 * vtvsock_conn and are exempt (that conn has its own connect timeout).
 */
#define	VTVSOCK_CTL_IDLE_TIMEOUT	30

/*
 * Stale-connection reaper cadence (milliseconds).  The reaper fires on this
 * periodic timer -- independent of guest TX activity -- so host-initiated
 * connect timeouts (CONN_CONNECTING) and unacknowledged closes (CONN_CLOSING)
 * are enforced even when the guest is silent or wedged.
 */
#define	VTVSOCK_REAP_INTERVAL_MS	1000

/* Control protocol command */
#define	VSOCK_CTL_CONNECT	1

struct vsock_ctl_msg {
	uint32_t	cmd;		/* VSOCK_CTL_CONNECT */
	uint32_t	port;		/* guest port number */
	uint32_t	type;		/* SOCK_STREAM or SOCK_SEQPACKET */
	int32_t		status;		/* reply: 0 on success, -errno on failure */
};

_Static_assert(sizeof(struct vsock_ctl_msg) == 16,
    "vsock control message ABI changed");

static int pci_vtvsock_debug;
#define	DPRINTF(params)						\
	do {							\
		if (pci_vtvsock_debug) {				\
			EPRINTLN params;				\
			fflush(stderr);				\
		}						\
	} while (0)
/* Per-packet tracing: BHYVE_VTVSOCK_DEBUG=2+ only -- the volume swamps
 * normal logs.  Debug output is flushed so failure cleanup cannot lose it. */
#define	DPRINTF2(params)					\
	do {							\
		if (pci_vtvsock_debug >= 2) {			\
			EPRINTLN params;				\
			fflush(stderr);				\
		}						\
	} while (0)
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
}

/*
 * A connection fd carries CAP_IOCTL (in its rights) so the STREAM RX path can
 * FIONREAD it to size reads; restrict the allowed ioctls to exactly FIONREAD.
 * Without this the ioctl fails ENOTCAPABLE in capability mode and every
 * host->guest STREAM read silently falls back to a 4 KiB chunk.
 */
static void
vtvsock_cap_limit_fionread(int fd)
{
	const cap_ioctl_t cmds[] = { FIONREAD };

	(void)caph_ioctls_limit(fd, cmds, nitems(cmds));
}

/*
 * Prepare an fd that will be passed to a host application via
 * SCM_RIGHTS.  The fd can be transferred exactly once (to the app),
 * then it is pinned.  Close-on-exec and no-ambient are set so the
 * receiving app cannot further propagate the descriptor.
 *
 * Close-on-fork is intentionally NOT set: a host application may
 * legitimately fork workers that use the vsock connection.
 */
static void
vtvsock_cap_lockdown_xfer_once(int fd)
{

	(void)cap_xfer_limit(fd, CAP_XFER_ONCE);
	(void)cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
}
#endif

/*
 * Enlarge a relay socket's buffers to one full advertised window
 * (VTVSOCK_BUF_ALLOC) so a host<->guest SEQPACKET record up to the credit
 * window is carried through the Unix socket whole, rather than being chopped
 * at the kernel default (net.local.seqpacket.recvspace, 64 KiB).  Both
 * SO_SNDBUF and SO_RCVBUF are set on each end so the sender's outstanding-data
 * limit and the receiver's holding capacity line up at the same value by
 * construction (rather than depending on two independent sysctl defaults
 * agreeing).  Buffers are on-demand ceilings (sb_hiwat), so this costs no
 * memory until data actually queues.
 *
 * Best-effort and non-fatal: a host whose kern.ipc.maxsockbuf is below the
 * request refuses it (ENOBUFS) and the socket keeps its default -- the
 * connection still works, just with the smaller single-record ceiling.  Must
 * be called BEFORE the fd's rights are limited: setsockopt(SO_*BUF) needs an
 * unrestricted descriptor.  Not capsicum-guarded (setsockopt is not a cap
 * helper), so the WITHOUT_CAPSICUM harness build links it too.
 */
static void
vtvsock_set_relay_bufsize(int fd, uint32_t guest_port)
{
	int want = VTVSOCK_BUF_ALLOC;
	int got = 0;
	socklen_t len = sizeof(got);

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &want, sizeof(want)) < 0)
		DPRINTF(("vtvsock: SO_SNDBUF %d failed: %s (keeping default)",
		    want, strerror(errno)));
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want)) < 0)
		DPRINTF(("vtvsock: SO_RCVBUF %d failed: %s (keeping default)",
		    want, strerror(errno)));
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &len) < 0)
		got = 0;
	VSOCK_PROBE_RELAY_BUFSIZE(guest_port, (uint32_t)want, (uint32_t)got);
	if ((uint32_t)got < (uint32_t)want)
		WPRINTF(("vtvsock: relay socket buffer %d < requested %d "
		    "(records above %d bytes will fragment)", got, want, got));
}

/*
 * Per-connection state.  Each host-side Unix socket connection (or
 * guest-initiated connection accepted by the host) is represented by one of
 * these, linked into vsc_conns.
 */
struct vtvsock_conn {
	TAILQ_ENTRY(vtvsock_conn) link;
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
	bool			host_eof;	/* host app closed/shut its write side */
	time_t			stall_time;	/* when RX evp was disabled on credit stall (0=not) */

	/* Monotonic seconds when the CONNECTING/CLOSING timer started; 0 else */
	time_t			close_time;

	/* Credit tracking (host side) */
	uint32_t		buf_alloc;	/* our recv buffer capacity */
	uint32_t		fwd_cnt;	/* bytes we have consumed from guest */
	uint32_t		last_fwd_cnt;	/* fwd_cnt at last CREDIT_UPDATE sent */
	uint32_t		tx_cnt;		/* bytes we have sent to guest */
	uint32_t		peer_buf_alloc;	/* guest's advertised capacity */
	uint32_t		peer_fwd_cnt;	/* guest's last reported consumed */

	/*
	 * SEQPACKET inbound (guest->host) reassembly.  A guest record may
	 * arrive as several OP_RW fragments (EOM on the last); we accumulate
	 * them here and deliver the whole record to the host SOCK_SEQPACKET fd
	 * as one datagram (with MSG_EOR) so the message boundary is preserved.
	 * Unused for STREAM connections.
	 */
	uint8_t			*rx_reasm;	/* accumulation buffer (or NULL) */
	uint32_t		rx_reasm_len;	/* bytes accumulated so far */
	uint32_t		rx_reasm_cap;	/* allocated capacity */

	/*
	 * Asynchronous guest->host TX backlog.  When the host Unix socket
	 * cannot accept a guest OP_RW immediately (EAGAIN / short write), the
	 * residual bytes are parked here and drained by tx_evp (an EVF_WRITE
	 * mevent) on writability, so the vCPU thread NEVER blocks in send()/
	 * poll() while holding vsc_mtx.  Bounded: a STREAM backlog is capped at
	 * buf_alloc, and a SEQPACKET record is all-or-nothing with at most one
	 * pending record; exceeding the cap resets the connection.  Credit
	 * accounting is unchanged (fwd_cnt is advanced when the guest packet is
	 * accepted, exactly as before), so this only bounds host memory.
	 */
	uint8_t			*tx_buf;	/* pending bytes for conn->fd */
	uint32_t		tx_buf_len;	/* valid bytes at tx_buf[0] */
	uint32_t		tx_buf_cap;	/* allocated capacity */
	bool			tx_buf_eor;	/* SEQPACKET: MSG_EOR on drain */
	struct mevent		*tx_evp;	/* EVF_WRITE drainer (or NULL) */

	/*
	 * Host->guest RX residual.  recv() on the host fd is all-or-nothing, so
	 * a large record is read whole and injected into the guest RX virtqueue
	 * as several OP_RW fragments.  If the guest RX ring empties mid-record,
	 * the un-injected tail is parked here (ownership of the recv() buffer is
	 * transferred) and re-injected when the guest posts more descriptors
	 * (pci_vtvsock_notify_rx re-enables conn->evp), instead of discarding
	 * the tail and resetting the connection.  At most one record is ever
	 * pending; the buffer was already allocated for the recv, so parking it
	 * adds no peak memory.  tx_cnt is advanced per fragment as injected.
	 */
	uint8_t			*rx_resid;	/* un-injected bytes (or NULL) */
	uint32_t		rx_resid_len;	/* total valid bytes */
	uint32_t		rx_resid_off;	/* bytes already injected */
	bool			rx_resid_seq;	/* SEQPACKET: set EOM on final frag */
	bool			rx_resid_eor;	/* SEQPACKET: also set EOR (host MSG_EOR) */
};

TAILQ_HEAD(vtvsock_conn_list, vtvsock_conn);

/*
 * Per-control-connection state.  Each host app that connects to the control
 * socket gets one of these until its request is fully handled.
 */
struct vtvsock_ctl_conn {
	int			fd;
	struct mevent		*evp;
	time_t			created;	/* monotonic secs; for idle reaping */
	struct vsock_ctl_msg	msg;		/* request accumulated from stream */
	size_t			msg_off;	/* bytes received into msg */
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
	struct mevent		*vsc_reap_evp;	/* periodic stale-conn reaper */

	/* Active connections */
	struct vtvsock_conn_list vsc_conns;
	uint32_t		vsc_conn_count;
	uint32_t		vsc_next_port;	/* next port to try assigning */

	/* Pending control connections */
	struct vtvsock_ctl_conn_list vsc_ctl_conns;
	uint32_t		vsc_ctl_conn_count;

	/*
	 * Aggregate SEQPACKET reassembly bytes outstanding across all
	 * connections (sum of every conn->rx_reasm_len).  Guarded by vsc_mtx;
	 * enforced against VTVSOCK_MAX_TOTAL_REASM in vtvsock_seqpkt_rx.
	 */
	uint32_t		vsc_reasm_total;

	/*
	 * Aggregate asynchronous TX backlog bytes parked in conn->tx_buf across
	 * all connections (sum of every conn->tx_buf_len).  Guarded by vsc_mtx;
	 * enforced against VTVSOCK_MAX_TOTAL_TXBUF in vtvsock_tx_buf_append.
	 */
	uint32_t		vsc_txbuf_total;

	/*
	 * Pending-reply ring (see VTVSOCK_PEND_MAX): fully-built headers of
	 * control packets awaiting guest RX descriptors, FIFO.  Guarded by
	 * vsc_mtx.
	 */
	struct virtio_vsock_hdr	vsc_pend[VTVSOCK_PEND_MAX];
	uint32_t		vsc_pend_head;
	uint32_t		vsc_pend_count;
	uint64_t		vsc_pend_drops;
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
static void vtvsock_conn_write_cb(int, enum ev_type, void *);
static void vtvsock_conn_close(struct pci_vtvsock_softc *,
    struct vtvsock_conn *);
static void vtvsock_host_eof(struct pci_vtvsock_softc *,
    struct vtvsock_conn *);

static struct virtio_consts vtvsock_vi_consts = {
	.vc_name =		"vtvsock",
	.vc_nvq =		VTVSOCK_MAXQ,
	.vc_cfgsize =		sizeof(struct virtio_vsock_config),
	.vc_reset =		pci_vtvsock_reset,
	.vc_cfgread =		pci_vtvsock_cfgread,
	.vc_cfgwrite =		pci_vtvsock_cfgwrite,
	.vc_apply_features =	pci_vtvsock_neg_features,
	/*
	 * NO_IMPLIED_STREAM is offered per virtio 1.4 §5.10.3.2 (SHOULD),
	 * always together with F_STREAM: this device supports stream, the
	 * bit only makes that support explicit for 1.4-aware drivers.
	 */
	.vc_hv_caps =		VIRTIO_VSOCK_F_STREAM |
				VIRTIO_VSOCK_F_SEQPACKET |
				VIRTIO_VSOCK_F_NO_IMPLIED_STREAM,
};

/* -------------------------------------------------------------------------
 * Utility helpers
 * ---------------------------------------------------------------------- */

/*
 * Bounded scatter/gather copy helpers (iov_copyout, iov_total, iov_copyin,
 * iov_copyin_offset) live in a header so they can be unit-tested independently
 * of the bhyve device; see pci_virtio_vsock_iov.h and
 * tests/sys/kern/vsock_iov_test.c.
 */
#include "pci_virtio_vsock_iov.h"

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

	return (sendmsg(sock, &msg, MSG_NOSIGNAL) >= 0 ? 0 : -1);
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
	uint32_t start;
	struct vtvsock_conn *c;

	/* UINT32_MAX is VSOCK_PORT_ANY and ports below 1024 are reserved. */
	if (sc->vsc_next_port < VTVSOCK_PORT_MIN ||
	    sc->vsc_next_port == UINT32_MAX)
		sc->vsc_next_port = VTVSOCK_PORT_MIN;
	start = sc->vsc_next_port;

	for (;;) {
		uint32_t port = sc->vsc_next_port;

		/* Wrap around, skipping the reserved range */
		if (sc->vsc_next_port == UINT32_MAX - 1)
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
		/* Guest-reachable (256 distinct ports); DPRINTF to avoid flood. */
		DPRINTF(("vtvsock: connection limit reached (%u)",
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
	VSOCK_PROBE_CONN_REQUEST((uint32_t)sc->vsc_guest_cid, guest_port);
	VSOCK_PROBE_CONN_COUNT(sc->vsc_conn_count);
	return (conn);
}

/*
 * Find an established connection by its port pair.  This is a single-guest
 * device and we are always the destination (VSOCK_CID_HOST), so the CIDs are
 * fixed and the (guest_port, local_port) pair identifies the connection:
 * src_port == guest_port, dst_port == local_port.
 */
static struct vtvsock_conn *
vtvsock_conn_find(struct pci_vtvsock_softc *sc, uint32_t src_port,
    uint32_t dst_port)
{
	struct vtvsock_conn *c;

	TAILQ_FOREACH(c, &sc->vsc_conns, link) {
		if (c->guest_port == src_port && c->local_port == dst_port)
			return (c);
	}
	return (NULL);
}

/*
 * Release a connection's SEQPACKET reassembly buffer once its current record
 * has been fully consumed (delivered to the host socket, dropped, or moved to
 * the TX backlog).  The device-global reassembly budget (vsc_reasm_total)
 * tracks only live bytes and is released here, so the backing allocation must
 * be freed too -- retaining peak capacity for the life of the connection would
 * let a guest deliver one ~VTVSOCK_MAX_PEER_BUF_ALLOC record on each of
 * VTVSOCK_MAX_CONNS connections in turn and pin ~1 GiB of never-freed memory
 * while the live aggregate never exceeds a single record.  Safe to call with
 * rx_reasm == NULL / rx_reasm_len == 0.  Must be called with vsc_mtx held.
 */
static void
vtvsock_reasm_release(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{
	sc->vsc_reasm_total -= conn->rx_reasm_len;
	conn->rx_reasm_len = 0;
	free(conn->rx_reasm);
	conn->rx_reasm = NULL;
	conn->rx_reasm_cap = 0;
}

/*
 * Release a connection's guest->host TX backlog buffer once it has fully
 * drained.  As with the reassembly buffer above, vsc_txbuf_total tracks only
 * live bytes, so the backing allocation is freed rather than retained for the
 * life of the connection; otherwise a guest could balloon each connection's
 * tx_buf in turn and pin memory far beyond the intended aggregate budget.  The
 * buffer is reallocated on demand by vtvsock_tx_buf_append, and in steady
 * state (host keeping up) no tx_buf is allocated at all, so this frees only
 * after a backpressure episode clears.  Safe to call with tx_buf == NULL /
 * tx_buf_len == 0.  Must be called with vsc_mtx held.
 */
static void
vtvsock_txbuf_release(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{
	sc->vsc_txbuf_total -= conn->tx_buf_len;
	conn->tx_buf_len = 0;
	free(conn->tx_buf);
	conn->tx_buf = NULL;
	conn->tx_buf_cap = 0;
	conn->tx_buf_eor = false;
}

/*
 * Tear down a connection: remove its mevent, close the fd (if any), and free
 * the structure.  Must be called with vsc_mtx held.
 */
static void
vtvsock_conn_close(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{
	VSOCK_PROBE_CONN_RESET((uint32_t)sc->vsc_guest_cid, conn->guest_port,
	    (uint32_t)conn->state);
	TAILQ_REMOVE(&sc->vsc_conns, conn, link);
	sc->vsc_conn_count--;
	VSOCK_PROBE_CONN_COUNT(sc->vsc_conn_count);

	/*
	 * Drop this connection's share of the global reassembly / TX backlog
	 * budgets and free the backing buffers.
	 */
	vtvsock_reasm_release(sc, conn);
	vtvsock_txbuf_release(sc, conn);

	/*
	 * The async TX drainer shares conn->fd with conn->evp; delete it first
	 * WITHOUT closing (mevent_delete_close on conn->evp below owns the fd
	 * close) so the fd is not closed twice.
	 */
	if (conn->tx_evp != NULL) {
		mevent_delete(conn->tx_evp);
		conn->tx_evp = NULL;
	}

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
				sc->vsc_ctl_conn_count--;
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

	/* rx_reasm / tx_buf were already freed by the *_release() helpers. */
	free(conn->rx_resid);
	free(conn);
}

/* -------------------------------------------------------------------------
 * Injecting packets into the RX (host->guest) virtqueue
 * ---------------------------------------------------------------------- */

/*
 * Build the wire header for a host->guest packet on 'conn'.
 */
static void
vtvsock_build_hdr(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    uint16_t op, uint32_t flags, uint32_t paylen, struct virtio_vsock_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->src_cid    = htole64(VSOCK_CID_HOST);
	hdr->dst_cid    = htole64(sc->vsc_guest_cid);
	hdr->src_port   = htole32(conn->local_port);
	hdr->dst_port   = htole32(conn->guest_port);
	hdr->len        = htole32(paylen);
	hdr->type       = htole16(conn->type);
	hdr->op         = htole16(op);
	hdr->flags      = htole32(flags);
	hdr->buf_alloc  = htole32(conn->buf_alloc);
	hdr->fwd_cnt    = htole32(conn->fwd_cnt);
}

/*
 * Inject a prebuilt header + optional payload into the RX virtqueue.
 * Must be called with vsc_mtx held.
 *
 * Returns 0 on success, -1 if no descriptors were available or the chain
 * was malformed (a malformed chain is consumed and released).
 */
static int
vtvsock_inject_raw(struct pci_vtvsock_softc *sc,
    const struct virtio_vsock_hdr *hdrp, const void *payload, uint32_t paylen)
{
	struct vqueue_info *vq = &sc->vsc_queues[VTVSOCK_RXQ];
	struct vi_req req;
	struct iovec iov[VTVSOCK_MAX_IOV];
	int n;
	size_t off, avail;

	if (!vq_has_descs(vq)) {
		DPRINTF2(("vtvsock: RX inject unavailable op=%u ring=%d "
		    "enabled=%u status=%#x caps=%#x last_avail=%u "
		    "avail_idx=%u used_idx=%u pending=%u",
		    le16toh(hdrp->op), vq_ring_ready(vq), vq->vq_enabled,
		    sc->vsc_vs.vs_status, sc->vsc_vs.vs_negotiated_caps,
		    vq->vq_last_avail,
		    vq->vq_avail == NULL ? 0 : vq->vq_avail->idx,
		    vq->vq_used == NULL ? 0 : vq->vq_used->idx,
		    sc->vsc_pend_count));
		return (-1);
	}

	n = vq_getchain(vq, iov, VTVSOCK_MAX_IOV, &req);
	if (n <= 0) {
		DPRINTF2(("vtvsock: RX getchain failed op=%u result=%d "
		    "last_avail=%u avail_idx=%u",
		    le16toh(hdrp->op), n, vq->vq_last_avail,
		    vq->vq_avail->idx));
		return (-1);
	}
	DPRINTF2(("vtvsock: RX chain op=%u head=%u n=%d readable=%d "
	    "writable=%d last_avail=%u avail_idx=%u",
	    le16toh(hdrp->op), req.idx, n, req.readable, req.writable,
	    vq->vq_last_avail, vq->vq_avail->idx));
	if (n > VTVSOCK_MAX_IOV) {
		/*
		 * vq_getchain() can return more descriptors than it stored in
		 * iov[] (it caps the fill at VTVSOCK_MAX_IOV but keeps counting;
		 * see virtio.c).  Using the unclamped count in the iov_* helpers
		 * would walk past iov[] into uninitialized stack -- a
		 * guest-triggerable OOB.  Drop the over-long chain.
		 */
		VSOCK_PROBE_DESC_DROP("rx-chain-too-long");
		DPRINTF(("vtvsock: rx descriptor chain too long (%d), dropping",
		    n));
		vq_relchain(vq, req.idx, 0);
		vq_endchains(vq, 0);
		return (-1);
	}
	if (iov_has_null_base(iov, n)) {
		/* Descriptor addr outside guest RAM; copying would crash us. */
		VSOCK_PROBE_DESC_DROP("rx-bad-descriptor-addr");
		DPRINTF(("vtvsock: rx descriptor with bad address, dropping"));
		vq_relchain(vq, req.idx, 0);
		vq_endchains(vq, 0);
		return (-1);
	}
	if (req.readable != 0 || req.writable == 0) {
		/*
		 * §5.10.6.4: RX (host->guest) buffers must be *entirely*
		 * device-writable.  vq_getchain() places readable descriptors
		 * first (iov[0 .. req.readable)) and writable ones after, but
		 * the iov_copyout() below writes from iov[0] across the whole
		 * chain and iov_total() sums every entry.  So a chain that is
		 * not wholly writable is malformed two ways: a readable prefix
		 * would make us write the header/payload into a guest read-only
		 * descriptor, and counting a readable descriptor's bytes toward
		 * capacity would let an undersized writable region pass the
		 * sufficiency check below.  A conformant guest posts an
		 * all-writable chain; drop anything else rather than trust the
		 * guest-controlled descriptor ordering.
		 */
		VSOCK_PROBE_DESC_DROP("rx-not-writable");
		DPRINTF(("vtvsock: rx descriptor chain not wholly writable, "
		    "dropping"));
		vq_relchain(vq, req.idx, 0);
		vq_endchains(vq, 0);
		return (-1);
	}

	avail = iov_total(iov, n);
	if (avail <= sizeof(*hdrp)) {
		/*
		 * The chain cannot hold even the header.  A conformant guest
		 * posts RX buffers large enough for a header plus payload;
		 * drop a malformed one.
		 */
		VSOCK_PROBE_DESC_DROP("rx-descriptor-too-small");
		DPRINTF(("vtvsock: rx descriptor too small for header (%zu)",
		    avail));
		vq_relchain(vq, req.idx, 0);
		vq_endchains(vq, 0);
		return (-1);
	}

	/*
	 * Write as much payload as fits THIS guest RX buffer: header plus
	 * min(paylen, avail - header).  The guest posts fixed-size RX buffers
	 * -- a virtio transport detail, distinct from the vsock credit window
	 * (Linux posts 4 KiB, 5BSD larger) -- and a single packet must fit one
	 * buffer.  A payload larger than the buffer is fragmented across
	 * successive buffers by the caller (vtvsock_rx_inject_frags), NOT
	 * dropped; the guest driver reassembles the packets back into the
	 * socket transparently to the application.  Because a short write is
	 * not the end of a SEQPACKET record, strip EOM/EOR from it -- only the
	 * packet carrying the record's final bytes keeps them.  Returns the
	 * number of PAYLOAD bytes written (0 for a header-only control packet),
	 * or -1 if no usable descriptor was available.  w is bounded by paylen,
	 * and every caller caps paylen at VTVSOCK_MAX_PKT (64 KiB), so the (int)
	 * return is always non-negative.
	 */
	{
		uint32_t cap = (uint32_t)(avail - sizeof(*hdrp));
		uint32_t w = (paylen < cap) ? paylen : cap;
		struct virtio_vsock_hdr h = *hdrp;

		h.len = htole32(w);
		if (w < paylen) {
			uint32_t f = le32toh(h.flags);

			f &= ~(uint32_t)(VIRTIO_VSOCK_SEQ_EOM |
			    VIRTIO_VSOCK_SEQ_EOR);
			h.flags = htole32(f);
		}
		off = 0;
		iov_copyout(&h, sizeof(h), iov, n, &off);
		if (w > 0 && payload != NULL)
			iov_copyout(payload, w, iov, n, &off);
		{
			uint16_t avail_flags, event_idx, old_used;

			avail_flags = vq->vq_avail == NULL ? 0 :
			    vq->vq_avail->flags;
			event_idx = vq->vq_avail == NULL ? 0 :
			    VQ_USED_EVENT_IDX(vq);
			old_used = vq->vq_save_used;
			vq_relchain(vq, req.idx, (uint32_t)off);
			vq_endchains(vq, 1);
			DPRINTF2(("vtvsock: RX published op=%u bytes=%zu "
			    "used=%u->%u event=%u avail_flags=%#x "
			    "event_idx=%d msix=%d vector=%u",
			    le16toh(hdrp->op), off, old_used,
			    vq->vq_used == NULL ? 0 : vq->vq_used->idx,
			    event_idx, avail_flags,
			    (sc->vsc_vs.vs_negotiated_caps &
			    VIRTIO_RING_F_EVENT_IDX) != 0,
			    pci_msix_enabled(sc->vsc_vs.vs_pi),
			    vq->vq_msix_idx));
		}
		return ((int)w);
	}
}

/*
 * Push parked control replies onto the RX virtqueue, FIFO, until the ring
 * runs out of descriptors again.  Must be called with vsc_mtx held.
 */
static void
vtvsock_pend_flush(struct pci_vtvsock_softc *sc)
{
	while (sc->vsc_pend_count != 0) {
		if (vtvsock_inject_raw(sc, &sc->vsc_pend[sc->vsc_pend_head],
		    NULL, 0) != 0)
			break;
		sc->vsc_pend_head = (sc->vsc_pend_head + 1) % VTVSOCK_PEND_MAX;
		sc->vsc_pend_count--;
	}
}

/*
 * True when the RX virtqueue can accept a new injection: every parked
 * control reply has been flushed (they were built first and must keep FIFO
 * order on the wire) and a descriptor is available.  Must be called with
 * vsc_mtx held.
 */
static bool
vtvsock_rx_ready(struct pci_vtvsock_softc *sc)
{
	vtvsock_pend_flush(sc);
	return (sc->vsc_pend_count == 0 &&
	    vq_has_descs(&sc->vsc_queues[VTVSOCK_RXQ]));
}

/*
 * Build a virtio_vsock_hdr + optional payload and inject it into the RX
 * virtqueue.  Must be called with vsc_mtx held.
 *
 * Returns 0 on success, -1 if the ring cannot take the packet right now
 * (no descriptors, or older control replies are still pending) or the
 * descriptor chain was malformed.
 */
static int
vtvsock_inject_rx(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    uint16_t op, uint32_t flags, const void *payload, uint32_t paylen)
{
	struct virtio_vsock_hdr hdr;

	vtvsock_build_hdr(sc, conn, op, flags, paylen, &hdr);
	if (!vtvsock_rx_ready(sc))
		return (-1);
	return (vtvsock_inject_raw(sc, &hdr, payload, paylen));
}

/*
 * Send a control packet with no payload.  Never silently lost to a full RX
 * ring: if the packet cannot be injected now it is parked on the bounded
 * pending-reply ring and flushed as the guest posts descriptors
 * (§5.10.6.1.2 -- resources outside the virtqueues; mirrors the guest
 * driver's TX holding queue).  Returns 0 when the packet was injected or
 * parked (delivery is then guaranteed while the device lives), -1 only if
 * the pending ring itself overflowed and the packet was dropped.
 */
static int
vtvsock_send_ctrl(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    uint16_t op, uint32_t flags)
{
	struct virtio_vsock_hdr hdr;
	bool ready;

	vtvsock_build_hdr(sc, conn, op, flags, 0, &hdr);
	ready = vtvsock_rx_ready(sc);
	DPRINTF2(("vtvsock: send ctrl op=%u host_port=%u guest_port=%u "
	    "ready=%d pending=%u", op, conn->local_port, conn->guest_port,
	    ready, sc->vsc_pend_count));
	if (ready &&
	    vtvsock_inject_raw(sc, &hdr, NULL, 0) == 0)
		return (0);
	if (sc->vsc_pend_count >= VTVSOCK_PEND_MAX) {
		sc->vsc_pend_drops++;
		VSOCK_PROBE_PEND_DROP(sc->vsc_pend_count);
		DPRINTF(("vtvsock: pending-reply ring full, dropping op %u",
		    op));
		return (-1);
	}
	sc->vsc_pend[(sc->vsc_pend_head + sc->vsc_pend_count) %
	    VTVSOCK_PEND_MAX] = hdr;
	sc->vsc_pend_count++;
	DPRINTF2(("vtvsock: parked ctrl op=%u pending=%u", op,
	    sc->vsc_pend_count));
	return (0);
}

/*
 * Send an OP_RST for a packet or connection we have no vtvsock_conn for
 * (unknown type/connection, or a failed connection setup).  vtvsock_send_ctrl()
 * addresses the RST from a conn, so synthesize a minimal stack one.
 * local_port is the host-side port (RST source); guest_port is the guest-side
 * port (RST destination).
 */
static void
vtvsock_send_rst_noconn(struct pci_vtvsock_softc *sc, uint32_t local_port,
    uint32_t guest_port, uint16_t type)
{
	struct vtvsock_conn tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.local_port = local_port;
	tmp.guest_port = guest_port;
	tmp.type       = type;
	tmp.fd         = -1;
	tmp.ctl_fd     = -1;
	tmp.reply_fd   = -1;
	(void)vtvsock_send_ctrl(sc, &tmp, VIRTIO_VSOCK_OP_RST, 0);
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
	uint32_t used;

	/*
	 * Spec §5.10.6.3: peer_free = peer_buf_alloc - (tx_cnt - peer_fwd_cnt).
	 * tx_cnt and peer_fwd_cnt are free-running counters, so their unsigned
	 * difference (bytes in flight) is correct across wraparound.  Compute
	 * entirely in uint32_t: the previous (int32_t) cast treated any result
	 * >= 2GiB as negative, starving connections whose peer advertised a
	 * buf_alloc above 0x7fffffff.
	 */
	used = conn->tx_cnt - conn->peer_fwd_cnt;
	if (used >= conn->peer_buf_alloc)
		return (0);
	return (conn->peer_buf_alloc - used);
}

/*
 * Stop host reads that cannot make progress for lack of guest credit, request
 * one fresh credit report, and remember when the stall began.  The timestamp
 * suppresses duplicate requests and lets the reaper probe for a host peer that
 * disappeared while the read event was disabled.  Actual data progress clears
 * it; a CREDIT_UPDATE alone may still be too small for an atomic record.
 */
static void
vtvsock_mark_credit_stall(struct pci_vtvsock_softc *sc,
    struct vtvsock_conn *conn)
{

	if (conn->evp != NULL)
		mevent_disable(conn->evp);
	if (conn->stall_time == 0) {
		(void)vtvsock_send_ctrl(sc, conn,
		    VIRTIO_VSOCK_OP_CREDIT_REQUEST, 0);
		conn->stall_time = monotonic_seconds();
	}
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

/*
 * Send a CREDIT_UPDATE if enough consumption is unreported.  Advance
 * last_fwd_cnt only when the update was injected or parked (send_ctrl == 0);
 * advancing on a drop would suppress every future update and stall the
 * guest's view of our free space.  Must be called with vsc_mtx held.
 */
static void
vtvsock_maybe_credit_update(struct pci_vtvsock_softc *sc,
    struct vtvsock_conn *conn)
{
	if (vtvsock_need_credit_update(conn) &&
	    vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0) {
		conn->last_fwd_cnt = conn->fwd_cnt;
		VSOCK_PROBE_CREDIT_UPDATE((uint32_t)sc->vsc_guest_cid,
		    conn->guest_port, conn->fwd_cnt);
	}
}

/* -------------------------------------------------------------------------
 * Asynchronous guest->host TX backlog
 *
 * The guest OP_RW handlers run on the vCPU thread with vsc_mtx held.  When the
 * host Unix socket cannot accept the bytes immediately, we must not block in
 * poll()/send() under the lock (that stalls the vCPU AND wedges the mevent
 * thread, which blocks on vsc_mtx).  Instead we park the residual in
 * conn->tx_buf and drain it from vtvsock_conn_write_cb (an EVF_WRITE mevent) on
 * writability.  The backlog is bounded; overflowing the bound resets the conn.
 * ---------------------------------------------------------------------- */

/*
 * Append <len> bytes to conn->tx_buf, growing it up to <cap>.  Returns 0 on
 * success, -1 if the append would exceed the cap (caller resets the conn).
 */
static int
vtvsock_tx_buf_append(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    const uint8_t *data, uint32_t len)
{
	uint32_t cap = (conn->type == VIRTIO_VSOCK_TYPE_SEQPACKET) ?
	    VTVSOCK_MAX_PEER_BUF_ALLOC : conn->buf_alloc;
	uint32_t need = conn->tx_buf_len + len;

	if (need < conn->tx_buf_len || need > cap)	/* overflow or over cap */
		return (-1);
	/*
	 * Enforce the device-global TX backlog budget: the per-conn cap above
	 * bounds one connection, but the aggregate across all connections must
	 * also stay bounded so a fleet of stalled connections cannot pin ~1 GiB
	 * of host memory in parked records.
	 */
	if (sc->vsc_txbuf_total + len < sc->vsc_txbuf_total ||	/* overflow */
	    sc->vsc_txbuf_total + len > VTVSOCK_MAX_TOTAL_TXBUF)
		return (-1);
	if (need > conn->tx_buf_cap) {
		uint8_t *nb = realloc(conn->tx_buf, need);

		if (nb == NULL)
			return (-1);
		conn->tx_buf = nb;
		conn->tx_buf_cap = need;
	}
	memcpy(conn->tx_buf + conn->tx_buf_len, data, len);
	conn->tx_buf_len = need;
	sc->vsc_txbuf_total += len;
	return (0);
}

/*
 * Ensure the EVF_WRITE drainer for this connection is registered and enabled.
 * Returns 0 on success, -1 on failure (caller resets the conn).
 */
static int
vtvsock_tx_arm(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{
	if (conn->tx_evp == NULL) {
		/* mevent_add() returns an enabled event, which is what we want
		 * here: there is backlog to drain. */
		conn->tx_evp = mevent_add(conn->fd, EVF_WRITE,
		    vtvsock_conn_write_cb, sc);
		if (conn->tx_evp == NULL)
			return (-1);
	} else {
		mevent_enable(conn->tx_evp);
	}
	return (0);
}

/*
 * Forward guest STREAM payload to the host fd without ever blocking under the
 * lock: attempt one non-blocking send of whatever the socket will take (only
 * when no backlog is already queued, to preserve byte order), then park the
 * residual in conn->tx_buf for the EVF_WRITE drainer.  On an unrecoverable
 * error or a backlog overflow this sends RST, closes the conn, sets
 * *connp = NULL, and returns -1; otherwise 0.  Caller holds vsc_mtx.
 */
static int
vtvsock_stream_tx(struct pci_vtvsock_softc *sc, struct vtvsock_conn **connp,
    const uint8_t *data, uint32_t len)
{
	struct vtvsock_conn *conn = *connp;
	const uint8_t *p = data;
	uint32_t remain = len;

	if (conn->tx_buf_len == 0) {
		ssize_t sent = send(conn->fd, p, remain, MSG_NOSIGNAL);

		if (sent < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				WPRINTF(("vtvsock: send to host fd failed: %s",
				    strerror(errno)));
				goto reset;
			}
			/* Not writable now; buffer everything below. */
		} else {
			/* Consumed by the host socket: report to the guest. */
			conn->fwd_cnt += (uint32_t)sent;
			p += sent;
			remain -= (uint32_t)sent;
		}
		if (remain == 0)
			return (0);		/* fully sent inline */
	}

	if (vtvsock_tx_buf_append(sc, conn, p, remain) != 0) {
		VSOCK_PROBE_TX_OVERFLOW((uint32_t)sc->vsc_guest_cid,
		    conn->guest_port, remain);
		WPRINTF(("vtvsock: STREAM TX backlog exceeds %u bytes, "
		    "resetting", conn->buf_alloc));
		goto reset;
	}
	if (vtvsock_tx_arm(sc, conn) != 0) {
		WPRINTF(("vtvsock: cannot arm TX drainer, resetting"));
		goto reset;
	}
	return (0);

reset:
	(void)vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_RST, 0);
	vtvsock_conn_close(sc, conn);
	*connp = NULL;
	return (-1);
}

/* -------------------------------------------------------------------------
 * TX (guest -> host) virtqueue processing
 * ---------------------------------------------------------------------- */

/*
 * Handle an inbound SEQPACKET OP_RW fragment (guest->host).  Fragments are
 * accumulated per-connection until EOM, then the complete record is delivered
 * to the host SOCK_SEQPACKET fd as a single datagram (with MSG_EOR when the
 * guest set EOR), preserving the message boundary.  Linux fragments SEQPACKET
 * records larger than 64 KiB, so without this a large record would arrive at
 * the host app as several datagrams.  A zero-length record (EOM with no data)
 * is delivered as an empty datagram.  On unrecoverable error this sends RST,
 * closes the connection, sets *connp = NULL, and returns -1; otherwise 0.
 * Must be called with vsc_mtx held.
 */
static int
vtvsock_seqpkt_rx(struct pci_vtvsock_softc *sc, struct vtvsock_conn **connp,
    const struct virtio_vsock_hdr *hdr, const uint8_t *payload, uint32_t paylen)
{
	struct vtvsock_conn *conn = *connp;
	uint32_t rwflags = le32toh(hdr->flags);
	int msgflags;
	ssize_t sent;

	if (conn->fd < 0) {
		/* No host consumer: discard as consumed. */
		conn->fwd_cnt += paylen;
		return (0);
	}

	if (paylen > 0) {
		uint32_t need = conn->rx_reasm_len + paylen;

		if (need < conn->rx_reasm_len ||	/* overflow */
		    need > VTVSOCK_MAX_PEER_BUF_ALLOC) {
			VSOCK_PROBE_REASM_OVERFLOW((uint32_t)sc->vsc_guest_cid,
			    conn->guest_port, need);
			WPRINTF(("vtvsock: SEQPACKET record exceeds %u bytes, "
			    "resetting", VTVSOCK_MAX_PEER_BUF_ALLOC));
			goto reset;
		}
		/*
		 * Enforce the device-global reassembly budget.  The per-conn cap
		 * above bounds a single connection, but the aggregate across all
		 * connections must also stay bounded (see VTVSOCK_MAX_TOTAL_REASM)
		 * so a fleet of connections cannot pin ~1 GiB of host memory in
		 * partially reassembled records.
		 */
		if (sc->vsc_reasm_total + paylen < sc->vsc_reasm_total ||
		    sc->vsc_reasm_total + paylen > VTVSOCK_MAX_TOTAL_REASM) {
			VSOCK_PROBE_REASM_OVERFLOW((uint32_t)sc->vsc_guest_cid,
			    conn->guest_port, sc->vsc_reasm_total);
			WPRINTF(("vtvsock: aggregate SEQPACKET reassembly budget "
			    "(%u) exceeded, resetting", VTVSOCK_MAX_TOTAL_REASM));
			goto reset;
		}
		if (need > conn->rx_reasm_cap) {
			uint8_t *nb = realloc(conn->rx_reasm, need);

			if (nb == NULL) {
				WPRINTF(("vtvsock: SEQPACKET reasm alloc "
				    "failed, resetting"));
				goto reset;
			}
			conn->rx_reasm = nb;
			conn->rx_reasm_cap = need;
		}
		memcpy(conn->rx_reasm + conn->rx_reasm_len, payload, paylen);
		conn->rx_reasm_len = need;
		sc->vsc_reasm_total += paylen;
		/*
		 * Credit SEQPACKET bytes to the guest as they are accepted into
		 * the reassembly buffer -- the host has taken responsibility for
		 * them (bounded by VTVSOCK_MAX_PEER_BUF_ALLOC), so the guest may
		 * free them and keep sending.  A record LARGER than the host's
		 * advertised buf_alloc otherwise deadlocks: the guest exhausts
		 * its send window mid-record while the host, crediting only at
		 * EOM, never reopens it.  The caller's maybe_credit_update()
		 * pushes the incremental window out.  Delivery to the host
		 * socket (inline send, EMSGSIZE drop, or tx_buf drain) must NOT
		 * re-credit these bytes.  STREAM keeps delivery-time crediting
		 * (its intentional slow-reader throttle); this is SEQPACKET-only.
		 */
		conn->fwd_cnt += paylen;
	}

	if ((rwflags & VIRTIO_VSOCK_SEQ_EOM) == 0)
		return (0);	/* more fragments coming */

	/*
	 * EOM: deliver the whole record as one datagram.  Try a single
	 * non-blocking send; if the host socket cannot take it right now, park
	 * the record for the EVF_WRITE drainer instead of blocking in poll()
	 * under vsc_mtx.  A SEQPACKET record is all-or-nothing, so at most one
	 * record may be pending at a time: a second completed record while one
	 * is still queued overflows the backlog and resets the connection.
	 */
	msgflags = MSG_NOSIGNAL |
	    ((rwflags & VIRTIO_VSOCK_SEQ_EOR) ? MSG_EOR : 0);

	if (conn->tx_buf_len == 0) {
		sent = send(conn->fd, conn->rx_reasm, conn->rx_reasm_len,
		    msgflags);
		if (sent >= 0) {		/* SEQPACKET send is all-or-nothing */
			/* Bytes were credited at reassembly-accept time. */
			vtvsock_reasm_release(sc, conn);	/* ready for next */
			return (0);
		}
		if (errno == EMSGSIZE) {
			/*
			 * The record is larger than the host SOCK_SEQPACKET
			 * socket can ever accept (SO_SNDBUF).  A SEQPACKET
			 * record is indivisible, so it can never be delivered;
			 * drop just this record (counted as consumed) and keep
			 * the connection up rather than letting a guest reset
			 * its own connection by emitting an over-large record.
			 */
			WPRINTF(("vtvsock: SEQPACKET record %u bytes exceeds "
			    "host socket limit, dropping record",
			    conn->rx_reasm_len));
			/* Bytes were credited at reassembly-accept time. */
			vtvsock_reasm_release(sc, conn);
			return (0);
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			WPRINTF(("vtvsock: SEQPACKET send to host failed: %s",
			    strerror(errno)));
			goto reset;
		}
		/* Not writable now; fall through to buffer the record. */
	}

	if (conn->tx_buf_len != 0) {
		/* A previous record is still draining; cannot queue a second. */
		WPRINTF(("vtvsock: SEQPACKET TX backlog, resetting"));
		goto reset;
	}
	if (vtvsock_tx_buf_append(sc, conn, conn->rx_reasm, conn->rx_reasm_len)
	    != 0) {
		VSOCK_PROBE_TX_OVERFLOW((uint32_t)sc->vsc_guest_cid,
		    conn->guest_port, conn->rx_reasm_len);
		WPRINTF(("vtvsock: SEQPACKET TX backlog exceeds %u bytes, "
		    "resetting", VTVSOCK_MAX_PEER_BUF_ALLOC));
		goto reset;
	}
	conn->tx_buf_eor = (msgflags & MSG_EOR) != 0;
	if (vtvsock_tx_arm(sc, conn) != 0) {
		WPRINTF(("vtvsock: cannot arm TX drainer, resetting"));
		goto reset;
	}
	/* Record moved to tx_buf; release its reassembly buffer + budget. */
	vtvsock_reasm_release(sc, conn);
	return (0);

reset:
	(void)vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_RST, 0);
	vtvsock_conn_close(sc, conn);
	*connp = NULL;
	return (-1);
}

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

	DPRINTF2(("vtvsock: tx pkt op=%u src=%llu:%u dst=%llu:%u len=%u",
	    op, (unsigned long long)src_cid, src_port,
	    (unsigned long long)dst_cid, dst_port, paylen));

	/* Validate destination */
	if (dst_cid != VSOCK_CID_HOST) {
		VSOCK_PROBE_DESC_DROP("unknown-dst-cid");
		DPRINTF(("vtvsock: dropping pkt for unknown cid %llu",
		    (unsigned long long)dst_cid));
		return;
	}

	/* Validate source CID: reject packets claiming to be from a different guest */
	if (src_cid != sc->vsc_guest_cid) {
		VSOCK_PROBE_DESC_DROP("spoofed-src-cid");
		DPRINTF(("vtvsock: dropping spoofed pkt: src_cid %llu != guest_cid %llu",
		    (unsigned long long)src_cid,
		    (unsigned long long)sc->vsc_guest_cid));
		return;
	}

	/* Validate type field (§5.10.6.4.2: RST for unknown type). */
	if (type != VIRTIO_VSOCK_TYPE_STREAM &&
	    type != VIRTIO_VSOCK_TYPE_SEQPACKET) {
		DPRINTF(("vtvsock: unknown type %u from guest, sending RST",
		    type));
		vtvsock_send_rst_noconn(sc, dst_port, src_port, type);
		return;
	}

	/*
	 * Extract peer credit state from every incoming packet (not just
	 * OP_CREDIT_UPDATE).  The guest piggybacks buf_alloc/fwd_cnt on
	 * all packet types.  Skip OP_REQUEST since the connection doesn't
	 * exist yet (credit is extracted in the handler below), and skip
	 * OP_RST: an RST only tears the connection down, so validating its
	 * (guest-controlled) fwd_cnt could make us answer an RST with an RST
	 * for an already-dying connection -- the guest driver excludes RST
	 * from the same check for exactly this reason (see uipc_vsock.c).
	 */
	if (op != VIRTIO_VSOCK_OP_REQUEST && op != VIRTIO_VSOCK_OP_RST) {
		conn = vtvsock_conn_find(sc, src_port, dst_port);
		if (conn != NULL) {
			uint32_t new_fwd_cnt;

			conn->peer_buf_alloc = le32toh(hdr->buf_alloc);
			if (conn->peer_buf_alloc > VTVSOCK_MAX_PEER_BUF_ALLOC)
				conn->peer_buf_alloc = VTVSOCK_MAX_PEER_BUF_ALLOC;
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
		} else {
			/*
			 * §5.10.6.4: packet for an unknown connection
			 * that is not itself a RST — reply with RST.  (OP_RST
			 * is excluded by the outer guard, so an RST for an
			 * unknown connection falls through to the switch,
			 * where the OP_RST case finds no conn and drops it
			 * silently -- no RST-for-RST.)
			 */
			DPRINTF(("vtvsock: no conn for op %u %u:%u, "
			    "sending RST", op, src_port, dst_port));
			vtvsock_send_rst_noconn(sc, dst_port, src_port, type);
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
		conn = vtvsock_conn_find(sc, src_port, dst_port);
		if (conn != NULL) {
			if (conn->state == CONN_CONNECTING) {
				/*
				 * Port-key collision with a host-initiated
				 * connect still awaiting this guest's
				 * OP_RESPONSE.  Do NOT tear it down: doing so
				 * would let the guest abort a pending host-side
				 * connect via a colliding REQUEST.  Ignore the
				 * duplicate; the guest's own connect times out.
				 */
				DPRINTF(("vtvsock: REQUEST collides with pending "
				    "host connect %u:%u, ignoring",
				    src_port, dst_port));
				break;
			}
			DPRINTF(("vtvsock: duplicate REQUEST for %u:%u, RST",
			    src_port, dst_port));
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RST, 0);
			vtvsock_conn_close(sc, conn);
			break;
		}
		/*
		 * A new flow has not transmitted any bytes, so the peer cannot
		 * already have consumed data from it.  Accepting a nonzero
		 * initial fwd_cnt makes the unsigned credit calculation account
		 * for bytes that never existed and can immediately starve the
		 * connection.  Reject it before opening the host relay socket.
		 */
		if (le32toh(hdr->fwd_cnt) != 0) {
			DPRINTF(("vtvsock: REQUEST with nonzero initial "
			    "fwd_cnt %u, sending RST", le32toh(hdr->fwd_cnt)));
			vtvsock_send_rst_noconn(sc, dst_port, src_port, type);
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
				vtvsock_send_rst_noconn(sc, dst_port, src_port,
				    type);
				break;
			}
			/* Size buffers before rights lockdown (needs an
			 * unrestricted fd); the accepted host end is sized by
			 * the host listener itself. */
			vtvsock_set_relay_bufsize(cfd, src_port);
			if (connectat(sc->vsc_dfd, cfd,
			    (struct sockaddr *)&csun, csun.sun_len) < 0) {
				DPRINTF(("vtvsock: no host listener at %s/%s: %s",
				    sc->vsc_path, portstr, strerror(errno)));
				close(cfd);
				/* No listener; reject the connection. */
				vtvsock_send_rst_noconn(sc, dst_port, src_port,
				    type);
				break;
			}

#ifndef WITHOUT_CAPSICUM
			/*
			 * CAP_SHUTDOWN: the OP_SHUTDOWN handler half-closes
			 * this fd with shutdown(2) to propagate the guest's
			 * half-close to the host application.  CAP_IOCTL: the
			 * STREAM RX path FIONREADs it to size reads.
			 */
			cap_rights_init(&crights, CAP_EVENT, CAP_RECV,
			    CAP_SEND, CAP_SHUTDOWN, CAP_IOCTL);
			if (caph_rights_limit(cfd, &crights) == -1) {
				close(cfd);
				/* Send RST so guest doesn't hang. */
				vtvsock_send_rst_noconn(sc, dst_port, src_port,
				    type);
				break;
			}
			vtvsock_cap_limit_fionread(cfd);
			vtvsock_cap_lockdown(cfd);
#endif

			conn = vtvsock_conn_alloc(sc, cfd, src_port);
			if (conn == NULL) {
				/* Guest-reachable at the conn cap; DPRINTF. */
				DPRINTF(("vtvsock: cannot alloc conn for "
				    "guest REQUEST"));
				close(cfd);
				/* Send RST so guest doesn't hang. */
				vtvsock_send_rst_noconn(sc, dst_port, src_port,
				    type);
				break;
			}
			conn->local_port     = dst_port;
			conn->type           = type;
			conn->ctl_fd         = -1;
			conn->reply_fd       = -1;
			conn->peer_buf_alloc = le32toh(hdr->buf_alloc);
			if (conn->peer_buf_alloc > VTVSOCK_MAX_PEER_BUF_ALLOC)
				conn->peer_buf_alloc = VTVSOCK_MAX_PEER_BUF_ALLOC;
			conn->peer_fwd_cnt   = le32toh(hdr->fwd_cnt);
			conn->state          = CONN_ESTABLISHED;
			VSOCK_PROBE_CONN_ESTABLISHED((uint32_t)sc->vsc_guest_cid,
			    conn->guest_port);

			conn->evp = mevent_add(cfd, EVF_READ,
			    vtvsock_conn_data_cb, sc);
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
		conn = vtvsock_conn_find(sc, src_port, dst_port);
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
						sc->vsc_ctl_conn_count--;
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
			    vtvsock_conn_data_cb, sc);
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
		conn = vtvsock_conn_find(sc, src_port, dst_port);
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

			(void)send(conn->ctl_fd, &reply, sizeof(reply), MSG_NOSIGNAL);
		}

		vtvsock_conn_close(sc, conn);
		break;

	case VIRTIO_VSOCK_OP_SHUTDOWN:
		conn = vtvsock_conn_find(sc, src_port, dst_port);
		if (conn == NULL)
			break;
		VSOCK_PROBE_CONN_SHUTDOWN((uint32_t)sc->vsc_guest_cid,
		    conn->guest_port, flags);
		DPRINTF(("vtvsock: SHUTDOWN flags=0x%x local_port=%u "
		    "guest_port=%u", flags, conn->local_port, conn->guest_port));

		/*
		 * Accumulate peer shutdown flags (§5.10.6.5: "These hints
		 * are permanent once sent and successive packets with bits
		 * clear do not reset them").
		 *
		 * conn->fd is the host application; bhyve writes it for the
		 * guest->host stream and reads it (via conn->evp) for the
		 * host->guest stream.
		 *
		 * SHUTDOWN_SEND: guest will not send -- no more guest->host
		 *   data, so signal EOF to the host app: shutdown(fd, SHUT_WR).
		 * SHUTDOWN_RCV: guest will not receive -- it won't accept more
		 *   host->guest data, so stop injecting it: disable conn->evp
		 *   (and SHUT_RD the host fd).
		 *
		 * Only RST and tear down when both directions are shut.
		 */
		conn->peer_shutdown |= (flags &
		    (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND));

		if (conn->fd >= 0) {
			if ((flags & VIRTIO_VSOCK_SHUTDOWN_SEND) &&
			    shutdown(conn->fd, SHUT_WR) != 0)
				WPRINTF(("vtvsock: SHUT_WR on host fd "
				    "failed: %s", strerror(errno)));
			if (flags & VIRTIO_VSOCK_SHUTDOWN_RCV) {
				if (shutdown(conn->fd, SHUT_RD) != 0)
					WPRINTF(("vtvsock: SHUT_RD on host "
					    "fd failed: %s",
					    strerror(errno)));
				if (conn->evp != NULL)
					mevent_disable(conn->evp);
			}
		}

		if (conn->peer_shutdown ==
		    (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND)) {
			conn->state = CONN_CLOSING;
			conn->close_time = monotonic_seconds();
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RST, 0);
			vtvsock_conn_close(sc, conn);
		} else if ((conn->peer_shutdown &
		    VIRTIO_VSOCK_SHUTDOWN_SEND) != 0 && conn->host_eof &&
		    conn->state == CONN_ESTABLISHED) {
			/*
			 * The host application already closed its side and the
			 * guest has now finished sending: nothing can flow in
			 * either direction anymore.
			 */
			conn->state = CONN_CLOSING;
			conn->close_time = monotonic_seconds();
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_SHUTDOWN,
			    VIRTIO_VSOCK_SHUTDOWN_RCV |
			    VIRTIO_VSOCK_SHUTDOWN_SEND);
		}
		break;

	case VIRTIO_VSOCK_OP_RW:
		conn = vtvsock_conn_find(sc, src_port, dst_port);
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

		/*
		 * fwd_cnt is NOT advanced here.  It advances when the bytes
		 * actually leave our buffer -- delivered to the host fd
		 * (inline in vtvsock_stream_tx/vtvsock_seqpkt_rx, or on drain
		 * in vtvsock_conn_write_cb) or deliberately discarded.
		 * Advancing on acceptance (as this used to) told the guest
		 * its data was consumed while it was really parked in
		 * tx_buf, so a merely-slow host reader never throttled the
		 * guest and instead tripped the backlog cap and reset the
		 * connection -- data loss §5.10.6.3 exists to prevent.  With
		 * consumption-time accounting the guest's credit window
		 * (buf_alloc - in flight) reflects reality and a conformant
		 * guest blocks; only a credit-violating guest can now
		 * overflow the backlog caps.
		 */

		/*
		 * The connection's type is fixed at OP_REQUEST time; a data
		 * packet whose header type disagrees is a guest protocol
		 * violation (e.g. SEQPACKET framing on a STREAM connection).
		 * Drop the payload; count it consumed so credit stays
		 * consistent.
		 */
		if (type != conn->type) {
			DPRINTF(("vtvsock: RW type %u mismatches conn type %u "
			    "on %u:%u, dropping", type, conn->type,
			    src_port, dst_port));
			conn->fwd_cnt += paylen;
			vtvsock_maybe_credit_update(sc, conn);
			break;
		}

		if (conn->type == VIRTIO_VSOCK_TYPE_SEQPACKET) {
			/*
			 * SEQPACKET: reassemble fragments to the EOM boundary
			 * and deliver each complete record to the host socket
			 * as one datagram, preserving the message boundary even
			 * for records the guest fragmented above 64 KiB.
			 */
			if (vtvsock_seqpkt_rx(sc, &conn, hdr, payload,
			    paylen) != 0)
				break;		/* conn was reset/closed */
		} else if (conn->fd >= 0 && paylen > 0) {
			/*
			 * STREAM: forward the bytes to the host fd.  This never
			 * blocks under vsc_mtx: any bytes the socket cannot take
			 * immediately are parked in the async TX backlog and
			 * drained by an EVF_WRITE mevent.  On an unrecoverable
			 * error or backlog overflow the conn is reset and
			 * cleared, so the credit-update block below is guarded on
			 * conn != NULL.
			 */
			if (vtvsock_stream_tx(sc, &conn, payload, paylen) != 0)
				break;		/* conn was reset/closed */
		} else {
			/* No host consumer for these bytes: discard as
			 * consumed. */
			conn->fwd_cnt += paylen;
		}

		/* Report any inline consumption (see vtvsock_maybe_credit_update). */
		if (conn != NULL)
			vtvsock_maybe_credit_update(sc, conn);
		break;

	case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
		/*
		 * Peer is advertising new/updated RX capacity.
		 * peer_buf_alloc and peer_fwd_cnt were already extracted
		 * and validated in the pre-switch credit parsing above.
		 * Re-lookup the connection for the mevent re-enable below.
		 */
		conn = vtvsock_conn_find(sc, src_port, dst_port);
		if (conn == NULL)
			break;
		DPRINTF2(("vtvsock: CREDIT_UPDATE local_port=%u peer_buf=%u "
		    "peer_fwd=%u", conn->local_port,
		    conn->peer_buf_alloc, conn->peer_fwd_cnt));
		/*
		 * If credit opened up and we have a host fd that may have
		 * deferred data, re-enable the mevent so the event loop
		 * retries the send.  Avoid recursive vtvsock_conn_data_cb
		 * calls which risk use-after-free during TAILQ iteration.
		 */
		if (conn->state == CONN_ESTABLISHED &&
		    !(conn->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) &&
		    !conn->host_eof &&
		    vtvsock_peer_credit(conn) > 0 &&
		    conn->fd >= 0 && conn->evp != NULL) {
			mevent_enable(conn->evp);
		}
		break;

	case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
		conn = vtvsock_conn_find(sc, src_port, dst_port);
		if (conn == NULL)
			break;
		/* Reply with our current credit state (only mark sent if it was). */
		if (vtvsock_send_ctrl(sc, conn,
		    VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0) == 0)
			conn->last_fwd_cnt = conn->fwd_cnt;
		break;

	default:
		DPRINTF(("vtvsock: unknown op %u from guest, ignoring", op));
		break;
	}
}

/* -------------------------------------------------------------------------
 * Virtqueue notify callbacks
 * ---------------------------------------------------------------------- */

/*
 * Reap stale connections whose guest never completed the handshake or
 * acknowledged a close.  Caller must hold vsc_mtx.
 *
 *   CONN_CLOSING    : the guest never sent the RST that completes a clean
 *                     shutdown; force it after 8s (matches the kernel
 *                     driver's VTVSOCK_CLOSE_TIMEOUT).
 *   CONN_CONNECTING : a host-initiated connect the guest never answered;
 *                     time out after 30s and notify the waiting host app.
 */
static void
vtvsock_reap_stale(struct pci_vtvsock_softc *sc)
{
	struct vtvsock_conn *conn, *tmp;
	time_t now = monotonic_seconds();

	TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp) {
		/*
		 * A connection whose RX event has stayed disabled on a credit
		 * stall for several seconds is making no progress: if the host
		 * peer died while stalled, the EOF is invisible (we are not
		 * reading) and the connection would ping-pong
		 * CREDIT_REQUEST/UPDATE forever.  ONLY such long-stalled
		 * connections are probed.  A live peer with buffered data keeps
		 * the stall marker but advances its probe time; actual forwarding
		 * clears it.  MSG_PEEK distinguishes a real EOF (0) from
		 * merely-no-data (EAGAIN).
		 */
		if (conn->state == CONN_ESTABLISHED && conn->fd >= 0 &&
		    !conn->host_eof && conn->stall_time != 0 &&
		    now - conn->stall_time >= 5) {
			char pb;
			struct iovec piov = { &pb, sizeof(pb) };
			struct msghdr pmsg = { .msg_iov = &piov,
			    .msg_iovlen = 1 };
			ssize_t pn;

			/*
			 * recvmsg (not recv): on a SEQPACKET fd recv()==0 is
			 * ambiguous -- it is returned both for a real EOF and
			 * for a legitimate 0-length record at the head of the
			 * buffer.  Only a 0-length read WITHOUT MSG_EOR is a
			 * peer EOF; a 0-length record carries MSG_EOR.  (STREAM
			 * never sets MSG_EOR, so recv()==0 stays EOF there.)
			 */
			pn = recvmsg(conn->fd, &pmsg,
			    MSG_PEEK | MSG_DONTWAIT);
			if (pn == 0 && (pmsg.msg_flags & MSG_EOR) == 0) {
				DPRINTF(("vtvsock: reaper: host peer of "
				    "stalled local_port=%u is gone",
				    conn->local_port));
				vtvsock_host_eof(sc, conn);
			} else if (pn > 0 ||
			    (pn == 0 && (pmsg.msg_flags & MSG_EOR) != 0)) {
				/*
				 * Data (or an empty record) is buffered, so the host
				 * peer is alive.  Keep the nonzero stall marker until
				 * data actually progresses, but rate-limit another
				 * probe to the next interval.
				 */
				conn->stall_time = now;
			}
		}
		if (conn->close_time == 0)
			continue;
		if (conn->state == CONN_CLOSING &&
		    now - conn->close_time >= 8) {
			DPRINTF(("vtvsock: reaping stale CLOSING conn "
			    "local_port=%u", conn->local_port));
			(void)vtvsock_send_ctrl(sc, conn,
			    VIRTIO_VSOCK_OP_RST, 0);
			vtvsock_conn_close(sc, conn);
		} else if (conn->state == CONN_CONNECTING &&
		    now - conn->close_time >= 30) {
			DPRINTF(("vtvsock: reaping stale CONNECTING "
			    "conn local_port=%u", conn->local_port));
			/*
			 * Guest never responded; send error to the host app
			 * if this was a host-initiated conn.
			 */
			if (conn->ctl_fd >= 0) {
				struct vsock_ctl_msg reply;

				memset(&reply, 0, sizeof(reply));
				reply.cmd    = VSOCK_CTL_CONNECT;
				reply.port   = conn->guest_port;
				reply.status = -ETIMEDOUT;
				(void)send(conn->ctl_fd, &reply,
				    sizeof(reply), MSG_NOSIGNAL);
			}
			vtvsock_conn_close(sc, conn);
		}
	}

	/*
	 * Reap idle control connections: a host process that connected to the
	 * control socket but never sent a VSOCK_CTL_CONNECT would otherwise pin
	 * a ctl slot indefinitely.  A ctl_conn whose request is in flight is
	 * referenced by its vtvsock_conn (conn->ctl_fd) and is torn down when
	 * that conn completes or times out, so skip referenced ones here.
	 */
	{
		struct vtvsock_ctl_conn *cc, *cctmp;

		TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
			struct vtvsock_conn *ref;
			bool referenced = false;

			if (now - cc->created < VTVSOCK_CTL_IDLE_TIMEOUT)
				continue;
			TAILQ_FOREACH(ref, &sc->vsc_conns, link) {
				if (ref->ctl_fd == cc->fd) {
					referenced = true;
					break;
				}
			}
			if (referenced)
				continue;
			DPRINTF(("vtvsock: reaping idle ctl conn fd=%d", cc->fd));
			TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
			sc->vsc_ctl_conn_count--;
			if (cc->evp != NULL)
				mevent_delete_close(cc->evp);
			else
				close(cc->fd);
			free(cc);
		}
	}
}

/*
 * Periodic timer callback (EVF_TIMER): runs the stale-connection reaper
 * independent of guest TX activity, so host-side timeouts fire even when the
 * guest is silent or wedged.  See VTVSOCK_REAP_INTERVAL_MS.
 */
static void
pci_vtvsock_reap_timer(int fd __unused, enum ev_type type __unused, void *arg)
{
	struct pci_vtvsock_softc *sc = arg;

	pthread_mutex_lock(&sc->vsc_mtx);
	vtvsock_reap_stale(sc);
	pthread_mutex_unlock(&sc->vsc_mtx);
}

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
		if (n > VTVSOCK_MAX_IOV) {
			/*
			 * vq_getchain() can return more descriptors than it
			 * placed in iov[] (it caps filling at VTVSOCK_MAX_IOV
			 * but keeps counting); the trailing iov[] entries are
			 * uninitialized stack.  Feeding the unclamped count to
			 * the iov_* helpers is a guest-triggerable OOB
			 * read/host-memory infoleak.  Drop over-long chains.
			 */
			VSOCK_PROBE_DESC_DROP("tx-chain-too-long");
			DPRINTF(("vtvsock: tx descriptor chain too long (%d), "
			    "dropping", n));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		if (iov_has_null_base(iov, n)) {
			/* Descriptor addr outside guest RAM; copy would crash. */
			VSOCK_PROBE_DESC_DROP("tx-bad-descriptor-addr");
			DPRINTF(("vtvsock: tx descriptor with bad address, "
			    "dropping"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		if (req.writable != 0 || req.readable == 0) {
			/*
			 * §5.10.6.4: TX (guest->host) buffers must be
			 * *entirely* device-readable.  vq_getchain() places
			 * readable descriptors first (iov[0 .. req.readable))
			 * and writable ones after, but iov_copyin()/iov_total()
			 * below read from iov[0] across the whole chain.  A
			 * writable prefix would make us parse guest-writable
			 * bytes as the header/payload, and no readable region at
			 * all is an empty packet.  A conformant guest posts an
			 * all-readable chain; drop anything else rather than
			 * trust the guest-controlled descriptor ordering.
			 */
			DPRINTF(("vtvsock: tx descriptor chain not wholly "
			    "readable, dropping"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}

		size_t total = iov_total(iov, n);
		if (total < sizeof(hdr)) {
			DPRINTF(("vtvsock: tx pkt too small (%zu)", total));
			vq_relchain(vq, req.idx, 0);
			continue;
		}

		iov_copyin(&hdr, sizeof(hdr), iov, n);

		uint32_t paylen = le32toh(hdr.len);
		if (paylen > VTVSOCK_MAX_PKT) {
			DPRINTF(("vtvsock: tx payload too large (%u), dropping",
			    paylen));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		if (paylen > 0 && le16toh(hdr.op) != VIRTIO_VSOCK_OP_RW) {
			/*
			 * Per virtio-vsock only OP_RW carries a data payload.
			 * A control op (RESPONSE/RST/SHUTDOWN/CREDIT_*) that
			 * declares hdr.len > 0 is malformed: those bytes are
			 * never credit-accounted (only OP_RW advances fwd_cnt),
			 * so copying them wastes host work and can desync flow
			 * control.  Drop the packet.
			 */
			DPRINTF(("vtvsock: control op %u with %u payload bytes, "
			    "dropping", le16toh(hdr.op), paylen));
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
				/*
				 * Guest declared hdr.len larger than the bytes
				 * it actually supplied.  Drop the whole packet
				 * (as with an over-large len) rather than
				 * silently truncating to empty: zeroing paylen
				 * would advance neither side's credit view and
				 * desync flow control on the connection.
				 */
				DPRINTF(("vtvsock: tx pkt len %u exceeds chain "
				    "(%zu), dropping", paylen, total));
				free(payload);
				payload = NULL;
				vq_relchain(vq, req.idx, 0);
				continue;
			}
		}

		vtvsock_process_tx_pkt(sc, &hdr, payload, paylen);
		/* TX is output-only; device does not write back to the desc. */
		vq_relchain(vq, req.idx, 0);
	}

	vq_endchains(vq, 1);
	free(payload);

	/* Opportunistically reap while we hold the lock (also timer-driven). */
	vtvsock_reap_stale(sc);

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
	/*
	 * Parked control replies go out first, in the descriptors the guest
	 * just posted, before any connection data is re-enabled behind them.
	 */
	vtvsock_pend_flush(sc);
	TAILQ_FOREACH(conn, &sc->vsc_conns, link) {
		/*
		 * Do not re-enable the host-read mevent for a connection whose
		 * guest half-closed the receive direction (SHUTDOWN_RCV, §5.10.6.5):
		 * the guest will not accept more host->guest data, and a read on the
		 * SHUT_RD host fd would return 0 and be misread as a peer EOF that
		 * tears down the still-open guest->host direction.
		 */
		if (conn->state == CONN_ESTABLISHED &&
		    !(conn->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) &&
		    !conn->host_eof &&
		    conn->fd >= 0 && conn->evp != NULL &&
		    (conn->rx_resid != NULL ||
		    vtvsock_peer_credit(conn) > 0)) {
			/*
			 * Only re-arm the host-read event when the connection
			 * can actually make progress: it has a parked record
			 * tail to finish injecting (already credit-accounted),
			 * or the guest has advertised receive credit.  Without
			 * this credit gate a connection stalled on a full guest
			 * window is re-enabled on every RX refill, immediately
			 * re-stalls, and busy-loops at the guest's notify rate.
			 * A zero-credit connection stays disabled until its
			 * CREDIT_UPDATE arrives.  A partial-credit atomic record
			 * may be retried by an RX notification, but stall_time
			 * remains intact so the retry neither sends another
			 * CREDIT_REQUEST nor escapes reaper accounting.
			 */
			mevent_enable(conn->evp);
		}
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
 * Inject buf[*offp .. len) into the guest RX virtqueue as OP_RW fragments, each
 * at most VTVSOCK_MAX_PKT bytes.  For a SEQPACKET record the final fragment
 * carries EOM (message boundary, always) and, when the host peer set POSIX
 * MSG_EOR on the record (eor), also SEQ_EOR -- so the guest's recv() reports
 * MSG_EOR exactly where the host set it (§5.10.6.6.1), not on every message.
 * *offp and conn->tx_cnt are advanced per injected fragment.  Returns:
 *    0  fully injected (*offp == len)
 *    1  the RX ring ran out of descriptors mid-record (*offp < len; the caller
 *       parks the tail and retries when the guest posts more descriptors)
 *   -1  an injection error occurred (the caller resets the connection)
 */
static int
vtvsock_rx_inject_frags(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn,
    const uint8_t *buf, uint32_t len, uint32_t *offp, bool is_seqpacket,
    bool eor)
{
	uint32_t off = *offp;

	while (off < len) {
		uint32_t frag = MIN(len - off, (uint32_t)VTVSOCK_MAX_PKT);
		uint32_t rw_flags = 0;
		int w;

		if (is_seqpacket && off + frag >= len) {
			rw_flags = VIRTIO_VSOCK_SEQ_EOM;
			if (eor)
				rw_flags |= VIRTIO_VSOCK_SEQ_EOR;
		}

		/*
		 * rx_ready, not just vq_has_descs: parked control replies
		 * must reach the wire before new data, so data defers (parks
		 * in rx_resid) while the pending ring drains.
		 */
		if (!vtvsock_rx_ready(sc)) {
			*offp = off;
			return (1);
		}
		/*
		 * inject_rx writes only what fits the guest RX buffer it pulls
		 * and returns the payload bytes actually written (it strips
		 * EOM/EOR when it writes a partial, so the record boundary
		 * lands on the packet with the last bytes).  Advance by that
		 * amount; a payload larger than one buffer therefore spans
		 * several packets across successive buffers.
		 */
		w = vtvsock_inject_rx(sc, conn, VIRTIO_VSOCK_OP_RW, rw_flags,
		    buf + off, frag);
		if (w < 0) {
			*offp = off;
			return (-1);
		}
		if (w == 0) {
			/* No descriptor progress; park and retry when the
			 * guest posts more (as for a full ring). */
			*offp = off;
			return (1);
		}
		conn->tx_cnt += (uint32_t)w;
		off += (uint32_t)w;
	}
	*offp = off;
	return (0);
}

/*
 * recv() on the host fd returned 0: the host application closed or shut
 * down its write side.  That alone is only a HALF-close -- the app may
 * still be reading the guest->host stream (a client that sent its
 * request and shut down writes while awaiting the reply).  Relay it as
 * SHUTDOWN(SEND) ("the host will not send more") and keep the
 * connection relaying guest->host.  Only when the guest has also shut
 * its send direction is the connection truly finished; then tear down.
 */
static void
vtvsock_host_eof(struct pci_vtvsock_softc *sc, struct vtvsock_conn *conn)
{

	if (conn->host_eof)
		return;		/* stray re-delivery; already relayed */
	conn->host_eof = true;
	if (conn->evp != NULL)
		mevent_disable(conn->evp);
	if (conn->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_SEND) {
		DPRINTF(("vtvsock: host fd closed, both directions done, "
		    "closing local_port=%u", conn->local_port));
		conn->state = CONN_CLOSING;
		conn->close_time = monotonic_seconds();
		(void)vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_SHUTDOWN,
		    VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND);
	} else {
		DPRINTF(("vtvsock: host fd EOF, half-close relay "
		    "local_port=%u", conn->local_port));
		(void)vtvsock_send_ctrl(sc, conn, VIRTIO_VSOCK_OP_SHUTDOWN,
		    VIRTIO_VSOCK_SHUTDOWN_SEND);
	}
}

/*
 * mevent callback: the host Unix socket fd for a connection is readable.
 *
 * State CONN_CONNECTING: ignore (we are waiting for OP_RESPONSE from guest).
 * State CONN_ESTABLISHED: read data and inject into RX virtqueue.
 * State CONN_CLOSING:  ignore.
 */
static void
vtvsock_conn_data_cb(int fd, enum ev_type t __unused, void *arg)
{
	struct pci_vtvsock_softc *sc = arg;
	struct vtvsock_conn *conn;
	uint8_t *buf = NULL;
	ssize_t n;

	pthread_mutex_lock(&sc->vsc_mtx);

	/*
	 * Re-look-up the connection by fd under the lock.  This callback is
	 * registered with sc (not a raw conn pointer) because the vCPU thread
	 * can free the conn (OP_RST / OP_SHUTDOWN / device reset) concurrently
	 * with this callback being dispatched on the mevent thread -- a cached
	 * pointer would be a use-after-free.  If the conn is gone the event is
	 * stale; return.  (Same idiom as pci_vtvsock_ctl_conn_cb.)
	 */
	TAILQ_FOREACH(conn, &sc->vsc_conns, link) {
		if (conn->fd == fd)
			break;
	}
	if (conn == NULL) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

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
		bool is_seqpacket;
		bool record_eor = false;	/* host set MSG_EOR on this record */

		is_seqpacket = (conn->type == VIRTIO_VSOCK_TYPE_SEQPACKET);

		/*
		 * The guest half-closed the receive direction (SHUTDOWN_RCV,
		 * §5.10.6.5): it will not accept more host->guest data.  The read
		 * mevent should already be disabled, but guard here too so a stray
		 * wakeup neither injects unwanted data nor misreads the SHUT_RD
		 * host-fd recv()==0 as a peer EOF -- which would escalate the
		 * legitimate half-close into a full teardown of the still-open
		 * guest->host direction.  The guest->host path (writes to conn->fd)
		 * stays open until the guest also sends SHUTDOWN_SEND.
		 */
		if (conn->peer_shutdown & VIRTIO_VSOCK_SHUTDOWN_RCV) {
			if (conn->evp != NULL)
				mevent_disable(conn->evp);
			break;
		}

		/*
		 * Re-inject any record tail parked when the guest RX ring
		 * emptied mid-record on a prior dispatch, before reading new
		 * data.  These bytes were already read from the host socket and
		 * committed, so they proceed regardless of current peer credit.
		 */
		if (conn->rx_resid != NULL) {
			int r;

			r = vtvsock_rx_inject_frags(sc, conn, conn->rx_resid,
			    conn->rx_resid_len, &conn->rx_resid_off,
			    conn->rx_resid_seq, conn->rx_resid_eor);
			if (r < 0)
				goto conn_error;
			if (r > 0) {
				/* Ring filled again; keep the tail, wait. */
				if (conn->evp != NULL)
					mevent_disable(conn->evp);
				break;
			}
			free(conn->rx_resid);
			conn->rx_resid = NULL;
			conn->rx_resid_len = conn->rx_resid_off = 0;
		}

		/* Check peer credit — how many bytes the guest can accept. */
		maxread = vtvsock_peer_credit(conn);
		if (maxread == 0) {
			VSOCK_PROBE_CREDIT_STALL((uint32_t)sc->vsc_guest_cid,
			    conn->guest_port);
			DPRINTF(("vtvsock: no peer credit, requesting update"));
			/*
			 * Solicit a fresh CREDIT_UPDATE (spec §5.10.6.3), stop
			 * the level-triggered read event from spinning, and let
			 * the reaper distinguish a wedged connection from a
			 * briefly throttled one.
			 */
			vtvsock_mark_credit_stall(sc, conn);
			break;
		}

		if (is_seqpacket) {
			/*
			 * SEQPACKET sizing.  A record must be injected
			 * atomically (peer credit must cover it entirely) and
			 * with EOM set only on its true final fragment, so we
			 * need the exact length of the next record BEFORE
			 * consuming it.
			 *
			 * Portability trap: FreeBSD's recvmsg(MSG_PEEK|
			 * MSG_TRUNC) reports only the number of bytes COPIED
			 * into the probe iov (== min(iov_len, record)), NOT the
			 * full datagram length the way Linux does.  A 1-byte
			 * probe therefore reports 1 for every record; and
			 * because a short SEQPACKET read on FreeBSD leaves the
			 * unread tail queued (rather than discarding it), a
			 * record sized that way is not merely truncated but
			 * shredded into a stream of 1-byte records -- invisible
			 * to byte-stream test tools, but a true record-oriented
			 * receiver (e.g. Linux) sees only the first byte.
			 *
			 * Instead use FIONREAD (bytes queued) for the size.  If
			 * every queued byte already fits peer credit the next
			 * record does too (recv returns exactly one record), so
			 * we can read straight away.  Only when the queue
			 * exceeds credit do we MSG_PEEK the next record in full
			 * to learn its exact length for the gate.
			 */
			struct msghdr pmsg;
			struct iovec piov;
			uint8_t dummy;
			ssize_t msgsize;

			avail = 0;
			(void)ioctl(conn->fd, FIONREAD, &avail);
			if (avail <= 0) {
				/*
				 * No bytes queued: a zero-length record
				 * (MSG_EOR, 0 bytes), a real EOF (peer closed),
				 * or a spurious wakeup.  recvmsg peek to
				 * disambiguate via msg_flags -- a plain recv()
				 * cannot tell a 0-length record from EOF and
				 * would tear the connection down on every empty
				 * record.
				 */
				memset(&pmsg, 0, sizeof(pmsg));
				piov.iov_base = &dummy;
				piov.iov_len = sizeof(dummy);
				pmsg.msg_iov = &piov;
				pmsg.msg_iovlen = 1;
				msgsize = recvmsg(conn->fd, &pmsg,
				    MSG_PEEK | MSG_DONTWAIT);
				if (msgsize < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK)
						break;
					goto conn_error;
				}
				if (msgsize > 0) {
					/*
					 * Raced: bytes arrived between FIONREAD
					 * and the peek.  Retry on the next
					 * level-triggered wakeup.
					 */
					break;
				}
				if ((pmsg.msg_flags & MSG_EOR) == 0) {
					/* Real EOF: the host peer has closed. */
					vtvsock_host_eof(sc, conn);
					break;
				}
				/*
				 * Legitimate empty SEQPACKET record (MSG_EOR
				 * set, zero bytes).  recv() with a zero-length
				 * buffer would not dequeue it, so consume it
				 * explicitly with recvmsg and forward a single
				 * empty OP_RW carrying the record boundary so
				 * the guest delivers an empty datagram.
				 */
				{
					struct msghdr dmsg;
					uint32_t eflags = VIRTIO_VSOCK_SEQ_EOM |
					    VIRTIO_VSOCK_SEQ_EOR;

					if (!vtvsock_rx_ready(sc)) {
						DPRINTF(("vtvsock: RX ring "
						    "full, deferring"));
						if (conn->evp != NULL)
							mevent_disable(
							    conn->evp);
						break;
					}
					memset(&dmsg, 0, sizeof(dmsg));
					(void)recvmsg(conn->fd, &dmsg,
					    MSG_DONTWAIT);
					if (vtvsock_inject_rx(sc, conn,
					    VIRTIO_VSOCK_OP_RW, eflags, NULL, 0) == 0)
						conn->stall_time = 0;
				}
				break;
			}

			if ((uint32_t)avail <= maxread) {
				/*
				 * Everything queued fits peer credit, so the
				 * next record (<= avail) certainly does.  Read
				 * the whole queue in one shot; recv returns
				 * exactly one complete record, so the buffer
				 * holds a full record and EOM lands correctly.
				 */
				msgsize = avail;
			} else {
				/*
				 * The queue exceeds credit, but the next record
				 * alone may still fit.  Peek it in full to get
				 * its exact length (recv returns one record; a
				 * buffer >= the record captures it whole).
				 */
				uint8_t *pbuf = malloc((size_t)avail);

				if (pbuf == NULL) {
					WPRINTF(("vtvsock: malloc failed for "
					    "rx size probe"));
					break;
				}
				msgsize = recv(conn->fd, pbuf, (size_t)avail,
				    MSG_PEEK | MSG_DONTWAIT);
				free(pbuf);
				if (msgsize < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK)
						break;
					goto conn_error;
				}
				if (msgsize == 0)
					break;	/* raced to empty */
				if ((uint32_t)msgsize > conn->peer_buf_alloc) {
					/*
					 * The record is larger than the guest's
					 * entire advertised receive window: it
					 * can never be reassembled there, so no
					 * amount of credit recovery will let it
					 * through.  Deferring would deadlock;
					 * reset the connection instead.
					 */
					WPRINTF(("vtvsock: SEQPACKET record %zd "
					    "> peer window %u, resetting",
					    msgsize, conn->peer_buf_alloc));
					goto conn_error;
				}
				if ((uint32_t)msgsize > maxread) {
					/*
					 * Fits the window but not current
					 * credit; defer until CREDIT_UPDATE.
					 */
					DPRINTF(("vtvsock: SEQPACKET record %zd "
					    "> credit %u, deferring",
					    msgsize, maxread));
					vtvsock_mark_credit_stall(sc, conn);
					break;
				}
			}
			readlen = msgsize;
		} else {
			/*
			 * STREAM: read whatever is available, capped
			 * by credit and max packet size.  Use FIONREAD
			 * to discover available bytes.  If 0 (spurious
			 * wakeup or imminent EOF), use a small buffer
			 * so recv() can distinguish EOF from no-data.
			 */
			avail = 0;
			(void)ioctl(conn->fd, FIONREAD, &avail);
			if (avail > 0)
				readlen = MIN(avail, VTVSOCK_MAX_PKT);
			else
				readlen = 4096;
			if ((uint32_t)readlen > maxread)
				readlen = (ssize_t)maxread;
		}

		/*
		 * Verify the RX ring can take an injection BEFORE consuming
		 * data from the Unix socket (descriptors available and no
		 * parked control replies ahead of us).
		 */
		if (!vtvsock_rx_ready(sc)) {
			VSOCK_PROBE_RX_RINGFULL((uint32_t)sc->vsc_guest_cid,
			    conn->guest_port);
			DPRINTF(("vtvsock: RX ring full, deferring"));
			/*
			 * Disable mevent to prevent a level-triggered
			 * busy-loop: the host fd is still readable, so an
			 * enabled EVFILT_READ event would re-dispatch this
			 * callback immediately and spin at 100% CPU on the
			 * shared mevent thread.  pci_vtvsock_notify_rx
			 * re-enables established connections' mevents when
			 * the guest posts RX descriptors.
			 */
			if (conn->evp != NULL)
				mevent_disable(conn->evp);
			break;
		}

		buf = malloc((size_t)readlen);
		if (buf == NULL) {
			WPRINTF(("vtvsock: malloc failed for rx payload"));
			break;
		}
		if (is_seqpacket) {
			/*
			 * SEQPACKET: recvmsg (not plain recv) so msg_flags is
			 * available -- the host peer's MSG_EOR must be
			 * propagated to the guest as SEQ_EOR on the final
			 * fragment (§5.10.6.6.1) rather than assumed set on
			 * every record.
			 */
			struct msghdr rmsg;
			struct iovec riov;

			memset(&rmsg, 0, sizeof(rmsg));
			riov.iov_base = buf;
			riov.iov_len = (size_t)readlen;
			rmsg.msg_iov = &riov;
			rmsg.msg_iovlen = 1;
			n = recvmsg(conn->fd, &rmsg, MSG_DONTWAIT);
			record_eor = (n >= 0) &&
			    (rmsg.msg_flags & MSG_EOR) != 0;
		} else {
			/* STREAM has no record boundary; plain recv. */
			n = recv(conn->fd, buf, (size_t)readlen, MSG_DONTWAIT);
		}
		if (n <= 0) {
			free(buf);
			buf = NULL;
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;
			if (n == 0) {
				/* EOF — host peer closed */
				vtvsock_host_eof(sc, conn);
				break;
			}
			goto conn_error;
		}
		conn->stall_time = 0;

		/*
		 * Inject into the RX (host->guest) virtqueue.
		 *
		 * SEQPACKET messages that exceed VTVSOCK_MAX_PKT are
		 * fragmented into multiple OP_RW packets; EOM|EOR is
		 * set only on the final fragment so the guest reassembles
		 * the complete record.  For STREAM, readlen is already
		 * capped at VTVSOCK_MAX_PKT so the loop runs once.
		 */
		{
			uint32_t off = 0;
			int r;

			r = vtvsock_rx_inject_frags(sc, conn, buf,
			    (uint32_t)n, &off, is_seqpacket, record_eor);
			if (r < 0) {
				WPRINTF(("vtvsock: RX injection failed, "
				    "closing"));
				free(buf);
				buf = NULL;
				goto conn_error;
			}
			if (r > 0) {
				/*
				 * RX ring emptied mid-record.  Park the
				 * un-injected tail (transfer ownership of buf)
				 * and re-inject when the guest posts more
				 * descriptors, rather than discarding the tail
				 * and resetting the connection.
				 */
				conn->rx_resid = buf;
				conn->rx_resid_len = (uint32_t)n;
				conn->rx_resid_off = off;
				conn->rx_resid_seq = is_seqpacket;
				conn->rx_resid_eor = record_eor;
				buf = NULL;
				if (conn->evp != NULL)
					mevent_disable(conn->evp);
				break;
			}
		}

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

/*
 * mevent callback (EVF_WRITE): the host Unix socket fd for a connection has
 * become writable.  Drain the async guest->host TX backlog parked in
 * conn->tx_buf (see the "Asynchronous guest->host TX backlog" section) so the
 * vCPU thread never has to block in send()/poll() under vsc_mtx.  When the
 * backlog is fully drained the drainer is disabled (it is level-triggered, so
 * leaving it enabled would spin while the socket stays writable).
 *
 * Draining is consumption: fwd_cnt advances here as bytes reach the host
 * socket (see the OP_RW handler), so each drain widens the guest's credit
 * window -- announce it with a CREDIT_UPDATE when enough has accumulated,
 * or a guest blocked on credit would only learn via its 1s CREDIT_REQUEST
 * poll.
 */
static void
vtvsock_conn_write_cb(int fd, enum ev_type t __unused, void *arg)
{
	struct pci_vtvsock_softc *sc = arg;
	struct vtvsock_conn *conn;

	pthread_mutex_lock(&sc->vsc_mtx);

	/* Re-look-up by fd under the lock (the conn may have been freed). */
	TAILQ_FOREACH(conn, &sc->vsc_conns, link) {
		if (conn->fd == fd)
			break;
	}
	if (conn == NULL) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	if (conn->tx_buf_len == 0) {
		if (conn->tx_evp != NULL)
			mevent_disable(conn->tx_evp);
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	if (conn->type == VIRTIO_VSOCK_TYPE_SEQPACKET) {
		int msgflags = MSG_NOSIGNAL |
		    (conn->tx_buf_eor ? MSG_EOR : 0);
		ssize_t sent = send(conn->fd, conn->tx_buf, conn->tx_buf_len,
		    msgflags);

		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				pthread_mutex_unlock(&sc->vsc_mtx);
				return;		/* stay armed; retry later */
			}
			goto write_error;
		}
		/*
		 * Record consumed whole: release its buffer.  The bytes were
		 * credited to the guest at reassembly-accept time (see
		 * vtvsock_seqpkt_rx), so do NOT advance fwd_cnt again here.
		 */
		vtvsock_txbuf_release(sc, conn);
	} else {
		/* STREAM: push as much as the socket will take. */
		while (conn->tx_buf_len > 0) {
			ssize_t sent = send(conn->fd, conn->tx_buf,
			    conn->tx_buf_len, MSG_NOSIGNAL);

			if (sent < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/* Partial drain still freed credit. */
					vtvsock_maybe_credit_update(sc, conn);
					pthread_mutex_unlock(&sc->vsc_mtx);
					return;	/* stay armed; retry later */
				}
				goto write_error;
			}
			if (sent == 0) {
				/*
				 * The socket accepted nothing this round; treat
				 * it as a transient would-block rather than
				 * spinning forever under vsc_mtx.  Stay armed and
				 * retry on the next writable event.
				 */
				vtvsock_maybe_credit_update(sc, conn);
				pthread_mutex_unlock(&sc->vsc_mtx);
				return;
			}
			conn->fwd_cnt += (uint32_t)sent;
			conn->tx_buf_len -= (uint32_t)sent;
			sc->vsc_txbuf_total -= (uint32_t)sent;
			if (conn->tx_buf_len > 0)
				memmove(conn->tx_buf, conn->tx_buf + sent,
				    conn->tx_buf_len);
		}
	}

	/*
	 * Fully drained: free the backing buffer (no-op if the SEQPACKET branch
	 * above already released it) so an idle connection retains no capacity,
	 * and disable the drainer until there is backlog again.
	 */
	vtvsock_txbuf_release(sc, conn);
	vtvsock_maybe_credit_update(sc, conn);
	if (conn->tx_evp != NULL)
		mevent_disable(conn->tx_evp);
	pthread_mutex_unlock(&sc->vsc_mtx);
	return;

write_error:
	WPRINTF(("vtvsock: TX drain to host fd failed: %s", strerror(errno)));
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

	nr = recv(fd, (uint8_t *)&cc->msg + cc->msg_off,
	    sizeof(cc->msg) - cc->msg_off, MSG_DONTWAIT);
	DPRINTF2(("vtvsock: ctl fd=%d recv=%zd offset=%zu", fd, nr,
	    cc->msg_off));
	if (nr <= 0) {
		/*
		 * EOF and hard errors terminate the request.  A would-block leaves
		 * the partially accumulated SOCK_STREAM frame intact.
		 */
		if (nr == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
			TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
			sc->vsc_ctl_conn_count--;
			if (cc->evp != NULL)
				mevent_delete_close(cc->evp);
			else
				close(cc->fd);
			free(cc);
		}
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	cc->msg_off += nr;
	if (cc->msg_off < sizeof(cc->msg)) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	msg = cc->msg;
	cc->msg_off = 0;
	DPRINTF2(("vtvsock: ctl request fd=%d cmd=%u port=%u type=%u",
	    fd, msg.cmd, msg.port, msg.type));

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
		} else if (msg.type == SOCK_STREAM) {
			stype = SOCK_STREAM;
			vtype = VIRTIO_VSOCK_TYPE_STREAM;
		} else {
			struct vsock_ctl_msg reply;

			WPRINTF(("vtvsock: unsupported ctl socket type %u",
			    msg.type));
			reply = msg;
			reply.status = -ESOCKTNOSUPPORT;
			(void)send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
			break;
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
			(void)send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
			pthread_mutex_unlock(&sc->vsc_mtx);
			return;
		}

		/*
		 * Size both ends to one advertised window before either is
		 * rights-limited or handed to the app, so a full-window record
		 * traverses the relay whole.  pair[1] is passed to the host app
		 * via SCM_RIGHTS, which inherits the larger buffer for free.
		 */
		vtvsock_set_relay_bufsize(pair[0], msg.port);
		vtvsock_set_relay_bufsize(pair[1], msg.port);

		/* pair[0] is bhyve's end; pair[1] goes to the host app */
		if (fcntl(pair[0], F_SETFL, O_NONBLOCK) < 0) {
			WPRINTF(("vtvsock: fcntl pair[0] failed: %s",
			    strerror(errno)));
			close(pair[0]);
			close(pair[1]);
			goto ctl_connect_fail;
		}

#ifndef WITHOUT_CAPSICUM
		cap_rights_init(&crights, CAP_EVENT, CAP_RECV, CAP_SEND,
		    CAP_SHUTDOWN, CAP_IOCTL);
		if (caph_rights_limit(pair[0], &crights) == -1) {
			WPRINTF(("vtvsock: rights on pair[0] failed"));
			close(pair[0]);
			close(pair[1]);
			goto ctl_connect_fail;
		}
		vtvsock_cap_limit_fionread(pair[0]);
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

		conn->type       = vtype;
		conn->ctl_fd     = fd;
		conn->reply_fd   = pair[1];
		conn->state      = CONN_CONNECTING;
		conn->close_time = monotonic_seconds();
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
			(void)send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
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
			(void)send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
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
	DPRINTF2(("vtvsock: accepted control fd=%d", s));

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
	cc->created = monotonic_seconds();

	pthread_mutex_lock(&sc->vsc_mtx);
	if (sc->vsc_ctl_conn_count >= VTVSOCK_MAX_CTL_CONNS) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		WPRINTF(("vtvsock: ctl connection limit reached (%u)",
		    VTVSOCK_MAX_CTL_CONNS));
		close(s);
		free(cc);
		return;
	}
	/*
	 * Arm the mevent and publish cc while holding vsc_mtx, so a concurrent
	 * device reset (pci_vtvsock_reset on the vCPU thread) cannot free cc in
	 * the window between publishing it and assigning cc->evp -- which would
	 * be a UAF write.  Lock order vsc_mtx -> mevent qlock is the global
	 * order (no LOR), and pci_vtvsock_ctl_conn_cb re-looks-up cc under
	 * vsc_mtx, so it cannot run until we insert cc and unlock.
	 */
	cc->evp = mevent_add(s, EVF_READ, pci_vtvsock_ctl_conn_cb, sc);
	if (cc->evp == NULL) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		WPRINTF(("vtvsock: mevent_add failed for ctl conn"));
		close(s);
		free(cc);
		return;
	}
	TAILQ_INSERT_TAIL(&sc->vsc_ctl_conns, cc, link);
	sc->vsc_ctl_conn_count++;
	DPRINTF2(("vtvsock: armed control fd=%d count=%u", s,
	    sc->vsc_ctl_conn_count));
	pthread_mutex_unlock(&sc->vsc_mtx);
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
	/* Discard parked control replies; the rings are being reset. */
	sc->vsc_pend_head = 0;
	sc->vsc_pend_count = 0;
	/* Close all active connections */
	TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp)
		vtvsock_conn_close(sc, conn);
	/* Close all pending control connections */
	TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
		TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
		sc->vsc_ctl_conn_count--;
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
	DPRINTF(("vtvsock: negotiated features=%#jx device_caps=%#jx",
	    (uintmax_t)negotiated_features,
	    (uintmax_t)vtvsock_vi_consts.vc_hv_caps));
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

	/*
	 * Enable verbose per-packet DPRINTF tracing when requested.  Guest-
	 * triggerable parse/drop diagnostics are logged at this level (not
	 * WPRINTF) so a hostile guest cannot flood the host log by default.
	 */
	if (getenv("BHYVE_VTVSOCK_DEBUG") != NULL) {
		pci_vtvsock_debug = atoi(getenv("BHYVE_VTVSOCK_DEBUG"));
		if (pci_vtvsock_debug < 1)
			pci_vtvsock_debug = 1;
	}

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
	if (cid >= UINT32_MAX) {
		/*
		 * 0xffffffff (== UINT32_MAX == VSOCK_CID_ANY) is a reserved CID
		 * per virtio 1.2/1.3 §5.10.4, and anything above it does not fit
		 * the 32-bit CID space.  Reject both.
		 */
		WPRINTF(("vtvsock: cid must be < 0xffffffff (got %llu)",
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
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto failed;

	/* --- PCI identity --- */
	if (vi_pci_is_modern(&sc->vsc_vs))
		vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_VSOCK);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_VSOCK);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_VSOCK);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi,  PCIR_CLASS,   PCIC_SIMPLECOMM);
	/* "other" subclass: subclass 0 (UART) invites serial-driver probes */
	pci_set_cfgdata8(pi,  PCIR_SUBCLASS, 0x80);

	/* --- Open directory fd --- */
	sc->vsc_dfd = open(path, O_RDONLY | O_DIRECTORY);
	if (sc->vsc_dfd < 0) {
		WPRINTF(("vtvsock: open dir '%s' failed: %s", path,
		    strerror(errno)));
		goto failed;
	}

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

#ifndef WITHOUT_CAPSICUM
	/*
	 * The control socket is bound; from here on the directory fd is
	 * only used for connectat() of guest-initiated connections, so
	 * drop bind/unlink authority.
	 */
	cap_rights_init(&rights, CAP_CONNECTAT, CAP_LOOKUP);
	if (caph_rights_limit(sc->vsc_dfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox on dfd");
	vtvsock_cap_lockdown(sc->vsc_dfd);
#endif
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
	/*
	 * CAP_FCNTL is needed because accepted connections inherit this
	 * limit and the accept path sets O_NONBLOCK on them; each accepted
	 * fd is then re-limited without CAP_FCNTL.
	 */
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_RECV, CAP_SEND,
	    CAP_FCNTL);
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

	/*
	 * Periodic reaper timer: enforces host-side connect/close timeouts
	 * independent of guest TX activity (a silent guest must not be able to
	 * pin host fds or block a host app's connect() forever).
	 */
	sc->vsc_reap_evp = mevent_add(VTVSOCK_REAP_INTERVAL_MS, EVF_TIMER,
	    pci_vtvsock_reap_timer, sc);
	if (sc->vsc_reap_evp == NULL) {
		WPRINTF(("vtvsock: mevent_add for reap timer failed"));
		goto failed;
	}

	/* --- Virtio interrupt and BAR --- */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	if (vi_pci_is_modern(&sc->vsc_vs)) {
		if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
			goto failed;
	} else
		vi_set_io_bar(&sc->vsc_vs, 0);

	return (0);

failed:
	if (s >= 0)
		close(s);
	/* sc is always allocated here (NULL is checked right after calloc). */
	{
		struct vtvsock_conn *conn, *tmp;
		struct vtvsock_ctl_conn *cc, *cctmp;
		TAILQ_FOREACH_SAFE(conn, &sc->vsc_conns, link, tmp)
			vtvsock_conn_close(sc, conn);
		TAILQ_FOREACH_SAFE(cc, &sc->vsc_ctl_conns, link, cctmp) {
			TAILQ_REMOVE(&sc->vsc_ctl_conns, cc, link);
			sc->vsc_ctl_conn_count--;
			if (cc->evp != NULL)
				mevent_delete_close(cc->evp);
			else
				close(cc->fd);
			free(cc);
		}
		if (sc->vsc_dfd >= 0)
			close(sc->vsc_dfd);
		if (sc->vsc_reap_evp != NULL)
			mevent_delete(sc->vsc_reap_evp);
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
	.pe_cfgwrite =		vi_pci_modern_cfgwrite,
	.pe_cfgread =		vi_pci_modern_cfgread,
	.pe_barwrite =		vi_pci_write,
	.pe_barread =		vi_pci_read,
	.pe_legacy_config =	pci_vtvsock_legacy_config,
};
PCI_EMUL_SET(pci_de_vtvsock);
