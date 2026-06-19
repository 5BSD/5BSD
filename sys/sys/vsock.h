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

#define	VSOCK_CID_ANY		UINT64_C(0xffffffffffffffff)
#define	VSOCK_CID_LOCAL		UINT64_C(1)
#define	VSOCK_CID_HOST		UINT64_C(2)

#define	VSOCK_PORT_ANY		UINT32_C(0xffffffff)
#define	VSOCK_PORT_HOST		UINT32_C(2)

#define	SOL_VSOCK		287

#define	SO_VM_SOCKETS_BUFFER_SIZE	0
#define	SO_VM_SOCKETS_BUFFER_MIN_SIZE	1
#define	SO_VM_SOCKETS_BUFFER_MAX_SIZE	2
#define	SO_VM_SOCKETS_CONNECT_TIMEOUT	6

#define	VIRTIO_VSOCK_F_STREAM		(1ULL << 0)
#define	VIRTIO_VSOCK_F_SEQPACKET	(1ULL << 1)
#define	VIRTIO_VSOCK_F_NO_IMPLIED_STREAM (1ULL << 2)

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
 * ABI note: differs from Linux's sockaddr_vm in two ways:
 *  1. svm_cid is uint64_t (Linux uses unsigned int / 32-bit).  The wire
 *     protocol (virtio_vsock_hdr) uses 64-bit CIDs, so our layout avoids
 *     truncation at the socket layer.
 *  2. svm_len follows BSD convention (absent in Linux).  Linux has an
 *     svm_flags field (for VMADDR_FLAG_TO_HOST) which we omit;
 *     svm_reserved1 occupies that space.
 *
 * Userspace code ported from Linux must be adjusted for these differences.
 */
struct sockaddr_vm {
	uint8_t		svm_len;
	sa_family_t	svm_family;
	uint16_t	svm_reserved1;
	uint32_t	svm_port;
	uint64_t	svm_cid;
};

#endif /* _SYS_VSOCK_H_ */
