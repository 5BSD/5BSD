/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_BLOCK_VIRTIO_BLK_CAPACITY_H_
#define _DEV_VIRTIO_BLOCK_VIRTIO_BLK_CAPACITY_H_

#ifndef _KERNEL
#include <stdbool.h>
#endif
#include <sys/types.h>

/* VirtIO block capacity is always expressed in 512-byte sectors. */
#define VIRTIO_BLK_CAPACITY_SECTOR_SIZE 512

/*
 * Convert a VirtIO block sector count without depending on a host-native
 * storage type.  Callers supply the representable byte limit for their
 * consumer (for example, OFF_MAX for geom_disk).  Leave *bytes unchanged on
 * failure so this may safely be used during configuration-change handling.
 */
static inline bool
virtio_blk_capacity_to_bytes(uint64_t sectors, uint64_t max_bytes,
    uint64_t *bytes)
{

	if (sectors > max_bytes / VIRTIO_BLK_CAPACITY_SECTOR_SIZE)
		return (false);
	if (bytes != NULL)
		*bytes = sectors * VIRTIO_BLK_CAPACITY_SECTOR_SIZE;
	return (true);
}

#endif /* _DEV_VIRTIO_BLOCK_VIRTIO_BLK_CAPACITY_H_ */
