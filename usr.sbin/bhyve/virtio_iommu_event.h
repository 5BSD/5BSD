/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_EVENT_H_
#define	_BHYVE_VIRTIO_IOMMU_EVENT_H_

#include <sys/uio.h>

#include <stddef.h>

struct virtio_iommu_state;

int	virtio_iommu_event_process(struct virtio_iommu_state *,
	    const struct iovec *, size_t, size_t *);

#endif
