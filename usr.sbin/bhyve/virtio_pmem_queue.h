/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_VIRTIO_PMEM_QUEUE_H_
#define	_BHYVE_VIRTIO_PMEM_QUEUE_H_

#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>

#include "virtio_pmem_host.h"

struct virtio_pmem_chain {
	uint8_t request[BHYVE_VIRTIO_PMEM_REQUEST_SIZE];
	struct iovec response[BHYVE_VIRTIO_PMEM_RESPONSE_SIZE];
	size_t response_count;
};

int	virtio_pmem_chain_prepare(const struct iovec *, int, int, int,
	    struct virtio_pmem_chain *);
int	virtio_pmem_chain_complete(const struct virtio_pmem_chain *, int,
	    size_t *);

#endif
