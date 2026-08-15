/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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

#ifndef _DEV_VIRTIO_FS_VIRTIO_FS_H_
#define	_DEV_VIRTIO_FS_VIRTIO_FS_H_

/*
 * VirtIO filesystem (virtio-fs, device ID 26) guest transport definitions.
 *
 * This driver carries the FUSE protocol over VirtIO request queues instead of
 * the /dev/fuse character device.  The device model this driver targets is the
 * non-GPL bhyve host at usr.sbin/bhyve/pci_virtio_fs.c; the on-wire config and
 * feature layout below match that contract (and the public VirtIO 1.2/1.4
 * virtio-fs specification).
 */

/*
 * Device-specific feature bits.  Only VIRTIO_FS_F_NOTIFICATION is defined by
 * the device; the first driver slice does NOT negotiate it (see the design
 * plan, docs/waspnest-virtio-fs-5bsd-driver-plan.md).  DAX, packed rings,
 * queue reset and suspend are transport/common features negotiated (or not)
 * elsewhere and are likewise out of scope for this slice.
 */
#define	VIRTIO_FS_F_NOTIFICATION	0x1	/* bit 0: FUSE notification queue */

/* Bounded tag length carried in the device configuration space. */
#define	VIRTIO_FS_TAG_SIZE		36

/*
 * Device configuration layout (little-endian).  "tag" is NUL-padded but not
 * required to be NUL-terminated when it fills the whole field.  "notify_buf_
 * size" is present only when VIRTIO_FS_F_NOTIFICATION is offered.
 */
struct virtio_fs_config {
	uint8_t		tag[VIRTIO_FS_TAG_SIZE];
	uint32_t	num_request_queues;
	uint32_t	notify_buf_size;
} __packed;

/*
 * Guest-visible virtqueue layout for this slice (notification queue not
 * negotiated):
 *
 *	queue 0			high-priority queue (FORGET/INTERRUPT)
 *	queue 1 .. N		ordinary FUSE request queues
 *
 * Request queue zero is queue index 1; the high-priority queue is never a
 * substitute for a request queue.
 */
#define	VIRTIO_FS_VQ_HIPRIO		0
#define	VIRTIO_FS_VQ_REQUEST_BASE	1

#endif /* _DEV_VIRTIO_FS_VIRTIO_FS_H_ */
