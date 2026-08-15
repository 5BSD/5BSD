/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_CHAIN_H_
#define	_BHYVE_VIRTIO_FS_CHAIN_H_

#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>

struct virtio_fs_chain {
	const struct iovec *readable_iov;
	const struct iovec *writable_iov;
	size_t readable_count;
	size_t writable_count;
	size_t request_length;
	size_t response_capacity;
};

int	virtio_fs_chain_validate(const struct iovec *, size_t, size_t,
	    size_t, bool, size_t, struct virtio_fs_chain *);
int	virtio_fs_chain_gather(const struct virtio_fs_chain *, void *,
	    size_t);
int	virtio_fs_chain_scatter(const struct virtio_fs_chain *, const void *,
	    size_t);

#endif
