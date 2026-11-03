/*-
 * Copyright (c) 2017 Juniper Networks, Inc.
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
 *
 */

#ifndef __VIRTIO_9P_CONFIG__
#define __VIRTIO_9P_CONFIG__

/* Mount point feature specified in config variable */
#define VIRTIO_9PNET_F_MOUNT_TAG 1

struct virtio_9pnet_config {
	/* Mount tag length */
	uint16_t mount_tag_len;
	/* non NULL terminated tag name */
	uint8_t mount_tag[0];
};

#ifdef _KERNEL
struct p9_req_t;
struct sglist;

/*
 * A request and its response are each one buffer from p9fs_buf_zone.  Those
 * buffers are virtually but not physically contiguous, so a buffer needs one
 * segment per page it touches.  The scatter list holds two P9FS_MTU buffers;
 * a channel whose queue cannot take that many segments offers a smaller msize.
 */
#define VT9P_BUF_NSEGS(size)	(howmany((size), PAGE_SIZE) + 1)
#define VT9P_MAX_NSEGS		(2 * VT9P_BUF_NSEGS(P9FS_MTU))
#define VT9P_NSEGS_MSIZE(nsegs)	(((nsegs) / 2 - 1) * PAGE_SIZE)

u_int	vt9p_queue_max_msize(int nsegs, int qsize, bool indirect);
int	vt9p_req_sglist(struct sglist *sg, struct p9_req_t *req,
	    int *readable, int *writable);
#endif /* _KERNEL */
#endif /* __VIRTIO_9P_CONFIG__ */
