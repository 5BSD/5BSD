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
 * Internal kernel header for AF_VSOCK socket domain.
 *
 * This header defines the interface between the vsock socket domain
 * (kern/uipc_vsock.c) and transport drivers (dev/virtio/vsock/virtio_vsock.c).
 * Not a public header — internal to kernel only.
 */

#ifndef _KERN_UIPC_VSOCK_H_
#define _KERN_UIPC_VSOCK_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/callout.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/vsock.h>

/* -----------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define	VTVSOCK_DEFAULT_BUF_ALLOC	(256 * 1024)
#define	VTVSOCK_DEFAULT_BUF_MIN		128
#define	VTVSOCK_DEFAULT_BUF_MAX		(256 * 1024)
#define	VTVSOCK_MAX_PKT_BUF		(64  * 1024)
#define	VTVSOCK_DEFAULT_SEQPACKET_FRAG_MAX	256
#define	VTVSOCK_CLOSE_TIMEOUT		(hz * 8)
#define	VTVSOCK_CONNECT_TIMEOUT		(hz * 30)

/* -----------------------------------------------------------------------
 * Connection state machine
 * ---------------------------------------------------------------------- */

enum vtvsock_state {
	VTVSOCK_CLOSED = 0,
	VTVSOCK_BOUND,
	VTVSOCK_LISTEN,
	VTVSOCK_CONNECTING,
	VTVSOCK_ESTABLISHED,
	VTVSOCK_CLOSING,
};

/* -----------------------------------------------------------------------
 * Transport interface
 *
 * The remote transport (e.g. virtio) registers these ops with the
 * socket domain layer.  The loopback transport is built into the
 * domain layer and does not use this interface.
 * ---------------------------------------------------------------------- */

struct vtvsock_pcb;

struct vtvsock_transport {
	/* Data path: socket layer → transport */
	int	(*send)(struct vtvsock_pcb *, int, struct mbuf *,
		    struct sockaddr *, struct mbuf *, struct thread *);
	int	(*disconnect)(struct vtvsock_pcb *);
	int	(*shutdown)(struct vtvsock_pcb *, enum shutdown_how);
	/* Control path: protocol state machine → transport */
	int	(*send_pkt)(struct vtvsock_pcb *, uint16_t op, uint32_t flags,
		    const void *payload, size_t len);
	int	(*send_rst)(uint64_t src_cid, uint32_t src_port,
		    uint64_t dst_cid, uint32_t dst_port, uint16_t type);
	void	(*send_credit_update)(struct vtvsock_pcb *);
};

/* -----------------------------------------------------------------------
 * Per-connection state (PCB)
 * ---------------------------------------------------------------------- */

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
	int				 connect_timeout; /* ticks, 0 = default */

	/* Credit-based flow control */
	uint32_t			 buf_alloc;
	uint32_t			 peer_buf_alloc;
	uint32_t			 tx_cnt;
	uint32_t			 peer_fwd_cnt;
	uint32_t			 fwd_cnt;
	uint32_t			 last_fwd_cnt;
	uint32_t			 rx_bytes;

	/* Peer shutdown tracking */
	uint32_t			 peer_shutdown;

	/* SEQPACKET fragment reassembly */
	struct mbuf			*seqpacket_partial;
	uint32_t			 seqpacket_frag_count;

	/* Timers */
	struct callout			 close_callout;
	struct callout			 connect_callout;

	LIST_ENTRY(vtvsock_pcb)		 link;		/* bound list */
	LIST_ENTRY(vtvsock_pcb)		 connlink;	/* connected list */
};

/* -----------------------------------------------------------------------
 * Shared globals (defined in uipc_vsock.c)
 * ---------------------------------------------------------------------- */

MALLOC_DECLARE(M_VTVSOCK);

extern struct mtx	vtvsock_mtx;
extern uint64_t		vtvsock_guest_cid;

extern counter_u64_t	vtvsock_cnt_tx_packets;
extern counter_u64_t	vtvsock_cnt_tx_bytes;
extern counter_u64_t	vtvsock_cnt_rx_packets;
extern counter_u64_t	vtvsock_cnt_rx_bytes;
extern counter_u64_t	vtvsock_cnt_rx_drops;
extern counter_u64_t	vtvsock_cnt_conns;

/* -----------------------------------------------------------------------
 * Functions exported by uipc_vsock.c
 * ---------------------------------------------------------------------- */

/* Transport registration (called by virtio_vsock on attach/detach) */
void	vsock_transport_register(const struct vtvsock_transport *ops,
	    uint64_t guest_cid, uint64_t features);
void	vsock_transport_unregister(void);

/* RX callback (called by virtio_vsock interrupt handler) */
void	vsock_rx_packet(void *buf, uint32_t len);

/* Transport reset (called on TRANSPORT_RESET event) */
void	vsock_transport_reset(void);

/* PCB helpers (needed by virtio transport ops in virtio_vsock.c) */
void	vtvsock_pcb_set_addr(struct sockaddr_vm *, uint64_t, uint32_t);
void	vtvsock_pcb_remove_lists_locked(struct vtvsock_pcb *);
void	vtvsock_pcb_insert_connected_locked(struct vtvsock_pcb *);

/* Credit helpers */
int32_t		vtvsock_credit_available(struct vtvsock_pcb *);
uint32_t	vtvsock_get_credit(struct vtvsock_pcb *, uint32_t);

/* Timeout callbacks (used by transport disconnect to arm close callout) */
void	vtvsock_close_timeout(void *);

#endif /* !_KERN_UIPC_VSOCK_H_ */
