/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _FILESYSTEMCMP_DISK_H_
#define	_FILESYSTEMCMP_DISK_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <filesystemcmp_protocol.h>

struct disk_store;

int	disk_store_create(int, bool, uint64_t, uint32_t, uint32_t,
	    struct disk_store **);
void	disk_store_destroy(struct disk_store *);
int	disk_root(struct disk_store *, struct filesystemcmp_handle *);
int	disk_lookup(struct disk_store *, struct filesystemcmp_handle,
	    const void *, size_t, struct filesystemcmp_handle *);
int	disk_create(struct disk_store *, struct filesystemcmp_handle,
	    const void *, size_t, uint32_t, uint32_t,
	    struct filesystemcmp_handle *);
int	disk_open(struct disk_store *, struct filesystemcmp_handle, uint32_t);
ssize_t	disk_read(struct disk_store *, struct filesystemcmp_handle, uint64_t,
	    void *, size_t);
ssize_t	disk_write(struct disk_store *, struct filesystemcmp_handle, uint64_t,
	    const void *, size_t);
int	disk_stat(struct disk_store *, struct filesystemcmp_handle,
	    struct filesystemcmp_stat_reply *);
int	disk_unlink(struct disk_store *, struct filesystemcmp_handle,
	    const void *, size_t);
int	disk_rename(struct disk_store *, struct filesystemcmp_handle,
	    const void *, size_t, struct filesystemcmp_handle, const void *,
	    size_t);
int	disk_close(struct disk_store *, struct filesystemcmp_handle);
int	disk_sync(struct disk_store *, struct filesystemcmp_handle);
int	disk_dup(struct disk_store *, struct filesystemcmp_handle,
	    struct filesystemcmp_handle *);

#endif
