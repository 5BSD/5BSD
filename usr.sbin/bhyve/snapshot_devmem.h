/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_SNAPSHOT_DEVMEM_H_
#define	_BHYVE_SNAPSHOT_DEVMEM_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#define	BHYVE_DEVMEM_NAME_SIZE	16U
#define	BHYVE_DEVMEM_REGION_F_FIXED_ROM	1U

struct bhyve_devmem_region {
	char name[BHYVE_DEVMEM_NAME_SIZE];
	void *host_base;
	size_t length;
	uint32_t flags;
};

/*
 * Append or restore the portable device-memory extension at
 * normal_memory_size.  The caller supplies regions in any order; identities
 * are matched by name and length.  Fixed ROM regions select format version 2;
 * version 1 cannot restore into a destination with fixed ROM.  No extension
 * is emitted for zero regions.
 */
int	bhyve_devmem_snapshot_save(int fd, off_t normal_memory_size,
	    const struct bhyve_devmem_region *regions, size_t region_count,
	    size_t *extension_size);
int	bhyve_devmem_snapshot_validate(int fd, off_t normal_memory_size,
	    off_t file_size, const struct bhyve_devmem_region *regions,
	    size_t region_count);
int	bhyve_devmem_snapshot_restore(int fd, off_t normal_memory_size,
	    off_t file_size, const struct bhyve_devmem_region *regions,
	    size_t region_count);

#endif /* _BHYVE_SNAPSHOT_DEVMEM_H_ */
