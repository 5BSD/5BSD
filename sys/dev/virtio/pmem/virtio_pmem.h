/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_PMEM_H_
#define _DEV_VIRTIO_PMEM_H_

#include <sys/types.h>

/* VirtIO 1.4, persistent-memory device feature and request layout. */
#define VIRTIO_PMEM_F_SHMEM_REGION	(1ULL << 0)

#define VIRTIO_PMEM_SHMEM_REGION_ID	0U
#define VIRTIO_PMEM_REQ_TYPE_FLUSH	0U
#define VIRTIO_PMEM_RESP_OK		0U
#define VIRTIO_PMEM_RESP_ERR		UINT32_MAX

struct virtio_pmem_config {
	uint64_t start;
	uint64_t size;
} __packed;

struct virtio_pmem_req {
	uint32_t type;
} __packed;

struct virtio_pmem_resp {
	uint32_t ret;
} __packed;

#endif /* _DEV_VIRTIO_PMEM_H_ */
