/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_QUEUE_H_
#define	_BHYVE_VIRTIO_IOMMU_QUEUE_H_

#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>

#include "virtio_iommu_request.h"

#define	BHYVE_VIOMMU_MAX_CHAIN_SEGMENTS	256U

struct virtio_iommu_state;

int	virtio_iommu_queue_process(struct virtio_iommu_state *,
	    const struct virtio_iommu_request_options *, const struct iovec *,
	    size_t, size_t, size_t, bool, size_t *);

#endif
