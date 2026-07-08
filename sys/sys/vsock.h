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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_VSOCK_H_
#define	_SYS_VSOCK_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioccom.h>

#define	VSOCK_CID_HYPERVISOR	UINT32_C(0)
#define	VSOCK_CID_LOCAL		UINT32_C(1)
#define	VSOCK_CID_HOST		UINT32_C(2)
#define	VSOCK_CID_ANY		UINT32_C(0xffffffff)	/* wildcard local CID */

#define	VSOCK_PORT_ANY		UINT32_C(0xffffffff)	/* auto-assign */

/* Linux-compatible aliases for source portability. */
#define	VMADDR_CID_HYPERVISOR	VSOCK_CID_HYPERVISOR
#define	VMADDR_CID_LOCAL	VSOCK_CID_LOCAL
#define	VMADDR_CID_HOST		VSOCK_CID_HOST
#define	VMADDR_CID_ANY		VSOCK_CID_ANY

/* svm_flags bits (Linux-compatible). */
#define	VMADDR_FLAG_TO_HOST	0x01
/* Mask of all svm_flags bits this implementation understands. */
#define	VMADDR_FLAG_ALL		(VMADDR_FLAG_TO_HOST)
#define	VMADDR_PORT_ANY		VSOCK_PORT_ANY

#define	SOL_VSOCK		287

/*
 * SIOCOUTQ (Linux SIOCOUTQ parity): number of bytes sent to the peer but not
 * yet consumed by it (in flight), handled by the vsock protocol's pr_control.
 * The read-side counterpart, Linux SIOCINQ, is provided by the generic
 * FIONREAD ioctl (bytes available to read).  Note: this uses the FreeBSD
 * ioctl encoding, not the Linux numeric value.
 */
#define	SIOCOUTQ	_IOR('v', 128, int)

#define	SO_VM_SOCKETS_BUFFER_SIZE	0
#define	SO_VM_SOCKETS_BUFFER_MIN_SIZE	1
#define	SO_VM_SOCKETS_BUFFER_MAX_SIZE	2
#define	SO_VM_SOCKETS_PEER_HOST_VM_ID	3	/* read-only: peer CID */
#define	SO_VM_SOCKETS_TRUSTED		5	/* VMCI-only; unsupported */
#define	SO_VM_SOCKETS_CONNECT_TIMEOUT	6	/* struct timeval */
#define	SO_VM_SOCKETS_NONBLOCK_TXRX	7	/* VMCI-only; unsupported */
#define	SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW 8	/* struct timeval */

#define	VIRTIO_VSOCK_F_STREAM		(1ULL << 0)
#define	VIRTIO_VSOCK_F_SEQPACKET	(1ULL << 1)
/*
 * Bit 2 is intentionally NOT offered.  The ratified virtio-vsock spec
 * (virtio 1.2/1.3 §5.10.3) defines only F_STREAM (0) and F_SEQPACKET (1).
 * Bit 2 is contested between two unratified proposals -- NO_IMPLIED_STREAM
 * (OASIS issue #142) and F_DGRAM (LKML) -- so negotiating it risks being
 * misread as DGRAM by a real QEMU/vhost peer.  Do not add a bit-2 feature.
 */

struct virtio_vsock_config {
	uint64_t	guest_cid;
} __packed;

struct virtio_vsock_event {
	uint32_t	id;
} __packed;

struct virtio_vsock_hdr {
	uint64_t	src_cid;
	uint64_t	dst_cid;
	uint32_t	src_port;
	uint32_t	dst_port;
	uint32_t	len;
	uint16_t	type;
	uint16_t	op;
	uint32_t	flags;
	uint32_t	buf_alloc;
	uint32_t	fwd_cnt;
} __packed;

enum virtio_vsock_type {
	VIRTIO_VSOCK_TYPE_STREAM = 1,
	VIRTIO_VSOCK_TYPE_SEQPACKET = 2,
};

enum virtio_vsock_op {
	VIRTIO_VSOCK_OP_INVALID = 0,
	VIRTIO_VSOCK_OP_REQUEST = 1,
	VIRTIO_VSOCK_OP_RESPONSE = 2,
	VIRTIO_VSOCK_OP_RST = 3,
	VIRTIO_VSOCK_OP_SHUTDOWN = 4,
	VIRTIO_VSOCK_OP_RW = 5,
	VIRTIO_VSOCK_OP_CREDIT_UPDATE = 6,
	VIRTIO_VSOCK_OP_CREDIT_REQUEST = 7,
};

enum virtio_vsock_shutdown {
	VIRTIO_VSOCK_SHUTDOWN_RCV = 1,
	VIRTIO_VSOCK_SHUTDOWN_SEND = 2,
};

enum virtio_vsock_rw {
	VIRTIO_VSOCK_SEQ_EOM = 1,
	VIRTIO_VSOCK_SEQ_EOR = 2,
};

#define	VIRTIO_VSOCK_EVENT_TRANSPORT_RESET	0

/*
 * ABI note: matches Linux's sockaddr_vm field types -- 32-bit svm_cid and an
 * svm_flags byte (VMADDR_FLAG_TO_HOST) -- so Linux-ported userspace needs no
 * field changes.  The structural difference is the leading BSD svm_len byte
 * (Linux has none): here {svm_len:1, svm_family:1} occupy the same first two
 * bytes as Linux's 2-byte svm_family, so svm_reserved1, svm_port, svm_cid, and
 * svm_flags land at identical offsets (2/4/8/12) and widths.  (svm_family
 * itself is 1 byte here vs Linux's 2 -- only the combined len+family region
 * matches; sockaddr_vm never travels on the wire, so this is inconsequential.)
 * Real CIDs are always 32-bit (the wire virtio_vsock_hdr carries them
 * zero-extended to 64 bits).
 */
struct sockaddr_vm {
	uint8_t		svm_len;
	sa_family_t	svm_family;
	uint16_t	svm_reserved1;
	uint32_t	svm_port;
	uint32_t	svm_cid;
	uint8_t		svm_flags;
	uint8_t		svm_zero[3];	/* pad to 16 bytes; must be zero */
};

/*
 * Lock the on-wire and ABI layouts at compile time: a stray field edit here
 * would silently break interoperability with real Linux/qemu virtio-vsock
 * peers -- the exact class of bug -Werror cannot catch.
 */
_Static_assert(sizeof(struct virtio_vsock_hdr) == 44,
    "virtio_vsock_hdr must be 44 bytes on the wire");
_Static_assert(sizeof(struct virtio_vsock_config) == 8,
    "virtio_vsock_config must be 8 bytes");
_Static_assert(sizeof(struct virtio_vsock_event) == 4,
    "virtio_vsock_event must be 4 bytes");
_Static_assert(sizeof(struct sockaddr_vm) == 16,
    "sockaddr_vm ABI layout must be 16 bytes");

/*
 * Connection state values exported in xvsock_pcb.xvp_state.
 * Must match the kernel-internal enum vtvsock_state.
 */
#define	VSOCK_ST_CLOSED		0
#define	VSOCK_ST_BOUND		1
#define	VSOCK_ST_LISTEN		2
#define	VSOCK_ST_CONNECTING	3
#define	VSOCK_ST_ESTABLISHED	4
#define	VSOCK_ST_CLOSING	5

/*
 * Exported PCB info for userspace tools (sockstat, netstat).
 * Returned by the kern.vsock.pcblist sysctl.
 */
struct xvsock_pcb {
	uint32_t	xvp_len;	/* sizeof(struct xvsock_pcb) */
	int32_t		xvp_state;	/* enum vtvsock_state */
	uint64_t	xvp_local_cid;
	uint64_t	xvp_remote_cid;
	uint32_t	xvp_local_port;
	uint32_t	xvp_remote_port;
	int32_t		xvp_type;	/* SOCK_STREAM or SOCK_SEQPACKET */
	uint32_t	xvp_buf_alloc;
	uint32_t	xvp_rx_bytes;
	uint32_t	xvp_tx_cnt;
	uint32_t	xvp_peer_buf_alloc;
	uint32_t	xvp_peer_fwd_cnt;
	uint64_t	xvp_so_gencnt;	/* socket generation counter */
};

#endif /* _SYS_VSOCK_H_ */
