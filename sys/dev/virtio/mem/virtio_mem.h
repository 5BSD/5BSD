/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _VIRTIO_MEM_H
#define _VIRTIO_MEM_H

/*
 * VirtIO 1.4 section 5.15: memory device (virtio-mem).  All multi-byte fields
 * on the request virtqueue and in device configuration space are little-endian
 * on the wire.  The wire structures below therefore store their fields in
 * little-endian form and are converted at the point of use.
 */

/* Device-specific feature bits (VirtIO 1.4 section 5.15.3). */
#define VIRTIO_MEM_F_ACPI_PXM			0
#define VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE	1

/* Request types (VirtIO 1.4 section 5.15.6, struct virtio_mem_req::type). */
#define VIRTIO_MEM_REQ_PLUG		0
#define VIRTIO_MEM_REQ_UNPLUG		1
#define VIRTIO_MEM_REQ_UNPLUG_ALL	2
#define VIRTIO_MEM_REQ_STATE		3

/* Response codes (struct virtio_mem_resp::type). */
#define VIRTIO_MEM_RESP_ACK		0
#define VIRTIO_MEM_RESP_NACK		1
#define VIRTIO_MEM_RESP_BUSY		2
#define VIRTIO_MEM_RESP_ERROR		3

/* Block states returned by a STATE request (struct virtio_mem_resp::state). */
#define VIRTIO_MEM_STATE_PLUGGED	0
#define VIRTIO_MEM_STATE_UNPLUGGED	1
#define VIRTIO_MEM_STATE_MIXED		2

/*
 * Request layout, 24 bytes on the wire.  PLUG, UNPLUG and STATE carry an
 * address and block count; UNPLUG_ALL carries only the type.  All reserved
 * fields are transmitted as zero.
 */
struct virtio_mem_req {
	uint16_t	type;		/* VIRTIO_MEM_REQ_*, little-endian */
	uint16_t	reserved0[3];
	uint64_t	addr;		/* little-endian guest physical address */
	uint16_t	nb_blocks;	/* little-endian block count */
	uint16_t	reserved1[3];
} __packed;

/*
 * Response layout, 10 bytes on the wire.  The state field is only meaningful
 * for an acknowledged STATE request.
 */
struct virtio_mem_resp {
	uint16_t	type;		/* VIRTIO_MEM_RESP_*, little-endian */
	uint16_t	reserved0[3];
	uint16_t	state;		/* VIRTIO_MEM_STATE_*, little-endian */
} __packed;

/*
 * Device configuration space, 56 bytes (VirtIO 1.4 section 5.15.4).  Read
 * through the transport's device-config accessors, which convert each field
 * from its little-endian wire form to guest-native byte order.
 */
struct virtio_mem_config {
	uint64_t	block_size;
	uint16_t	node_id;
	uint8_t		reserved[6];
	uint64_t	addr;
	uint64_t	region_size;
	uint64_t	usable_region_size;
	uint64_t	plugged_size;
	uint64_t	requested_size;
};

#endif /* _VIRTIO_MEM_H */
