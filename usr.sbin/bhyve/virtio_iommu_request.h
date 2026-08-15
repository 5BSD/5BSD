/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_IOMMU_REQUEST_H_
#define	_BHYVE_VIRTIO_IOMMU_REQUEST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtio_iommu_state;

/*
 * Keep the maximum PROBE payload at the request boundary as well as at the
 * virtqueue adapter.  The executor is also used by model and future backend
 * callers, which must not be able to construct a response larger than the
 * device's bounded queue contract.
 */
#define	BHYVE_VIOMMU_MAX_PROBE_SIZE	4096U

struct virtio_iommu_request_options {
	bool map_unmap;
	bool probe;
	bool bypass_config;
	uint32_t probe_size;
};

int	virtio_iommu_request_execute(struct virtio_iommu_state *,
	    const struct virtio_iommu_request_options *, const void *, size_t,
	    void *, size_t, size_t *);
int	virtio_iommu_request_execute_bounded(struct virtio_iommu_state *,
	    const struct virtio_iommu_request_options *, const void *, size_t,
	    size_t, void *, size_t, size_t *);

#endif
