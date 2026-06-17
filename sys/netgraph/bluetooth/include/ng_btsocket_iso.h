/*
 * ng_btsocket_iso.h
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

#ifndef _NETGRAPH_BTSOCKET_ISO_H_
#define _NETGRAPH_BTSOCKET_ISO_H_

/*
 * ISO routing entry
 */

struct ng_hook;
struct ng_message;

struct ng_btsocket_iso_rtentry {
	bdaddr_t				 src;  /* source BD_ADDR */
	u_int16_t				 pkt_size; /* max ISO packet size */
	u_int16_t				 num_pkts; /* buffer size */
	int32_t					 pending; /* pending packets */
	struct ng_hook				*hook; /* downstream hook */
	LIST_ENTRY(ng_btsocket_iso_rtentry)	 next; /* link to next */
};
typedef struct ng_btsocket_iso_rtentry		ng_btsocket_iso_rtentry_t;
typedef struct ng_btsocket_iso_rtentry *	ng_btsocket_iso_rtentry_p;

/*****************************************************************************
 *****************************************************************************
 **                   SOCK_SEQPACKET ISO sockets                            **
 *****************************************************************************
 *****************************************************************************/

#define NG_BTSOCKET_ISO_SENDSPACE	(64 * 1024)
#define NG_BTSOCKET_ISO_RECVSPACE	(64 * 1024)
#define NG_BTSOCKET_ISO_MAX_REASM	0x0FFF	/* ISO SDU max length */

/*
 * Bluetooth ISO socket PCB
 */

struct ng_btsocket_iso_pcb {
	struct socket			*so;	     /* Pointer to socket */

	bdaddr_t			 src;	     /* Source address */
	bdaddr_t			 dst;	     /* Destination address */
	u_int8_t			 dst_type;   /* Destination address type */

	u_int16_t			 con_handle; /* CIS/BIS connection handle */
	u_int16_t			 iso_seq_num; /* ISO Packet_Sequence_Number */

	/* Fragment-to-SDU mapping for SYNC_CON_QUEUE sbdroprecord */
#define NG_BTSOCKET_ISO_FRAG_RING_SZ	16
	u_int8_t			 frag_ring[NG_BTSOCKET_ISO_FRAG_RING_SZ];
	u_int8_t			 frag_ring_head; /* next write slot */
	u_int8_t			 frag_ring_tail; /* next read slot */
	u_int8_t			 frag_ring_rem;  /* remaining frags for tail SDU */

	u_int16_t			 flags;      /* socket flags */
#define NG_BTSOCKET_ISO_CLIENT		(1 << 0)     /* socket is client */
#define NG_BTSOCKET_ISO_TIMO		(1 << 1)     /* timeout pending */

	u_int8_t			 state;      /* socket state */
#define NG_BTSOCKET_ISO_CLOSED		0            /* socket closed */
#define NG_BTSOCKET_ISO_CONNECTING	1            /* wait for connect */
#define NG_BTSOCKET_ISO_OPEN		2            /* socket open */
#define NG_BTSOCKET_ISO_DISCONNECTING	3            /* wait for disconnect */

	struct callout			 timo;       /* timeout */

	struct mbuf			*rx_frag;    /* ISOAL reassembly buffer */

	ng_btsocket_iso_rtentry_p	 rt;         /* routing info */

	struct mtx			 pcb_mtx;    /* pcb mutex */

	LIST_ENTRY(ng_btsocket_iso_pcb)	 next;       /* link to next PCB */
};
typedef struct ng_btsocket_iso_pcb	ng_btsocket_iso_pcb_t;
typedef struct ng_btsocket_iso_pcb *	ng_btsocket_iso_pcb_p;

#define	so2iso_pcb(so) \
	((struct ng_btsocket_iso_pcb *)((so)->so_pcb))

/*
 * Bluetooth ISO socket methods
 */

#ifdef _KERNEL

void ng_btsocket_iso_abort      (struct socket *);
void ng_btsocket_iso_close      (struct socket *);
int  ng_btsocket_iso_attach     (struct socket *, int, struct thread *);
int  ng_btsocket_iso_bind       (struct socket *, struct sockaddr *,
                                   struct thread *);
int  ng_btsocket_iso_connect    (struct socket *, struct sockaddr *,
                                   struct thread *);
int  ng_btsocket_iso_control    (struct socket *, u_long, void *,
                                   struct ifnet *, struct thread *);
int  ng_btsocket_iso_ctloutput  (struct socket *, struct sockopt *);
void ng_btsocket_iso_detach     (struct socket *);
int  ng_btsocket_iso_disconnect (struct socket *);
int  ng_btsocket_iso_listen    (struct socket *, int, struct thread *);
int  ng_btsocket_iso_peeraddr   (struct socket *, struct sockaddr *);
int  ng_btsocket_iso_send       (struct socket *, int, struct mbuf *,
                                   struct sockaddr *, struct mbuf *,
                                   struct thread *);
int  ng_btsocket_iso_sockaddr   (struct socket *, struct sockaddr *);

#endif /* _KERNEL */

#endif /* _NETGRAPH_BTSOCKET_ISO_H_ */
