/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_SNAPSHOT_DEVMEM_H_
#define	_BHYVE_SNAPSHOT_DEVMEM_H_

#include <sys/types.h>

#include <stddef.h>

#define	BHYVE_DEVMEM_NAME_SIZE	16U

struct bhyve_devmem_region {
	char name[BHYVE_DEVMEM_NAME_SIZE];
	void *host_base;
	size_t length;
};

/*
 * Append or restore the portable generic-device-memory extension at
 * normal_memory_size.  The caller supplies regions in any order; identities
 * are matched by name and length.  No extension is emitted for zero regions.
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
