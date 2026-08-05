/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _FILESYSTEMCMP_SCRATCH_H_
#define	_FILESYSTEMCMP_SCRATCH_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include <filesystemcmp_protocol.h>

struct scratch_store;

struct scratch_limits {
	uint64_t	max_bytes;
	uint32_t	max_objects;
	uint32_t	max_file_bytes;
};

int	scratch_store_create(const struct scratch_limits *,
	    struct scratch_store **);
void	scratch_store_destroy(struct scratch_store *);
int	scratch_root(struct scratch_store *, struct filesystemcmp_handle *);
int	scratch_lookup(struct scratch_store *, struct filesystemcmp_handle,
	    const void *, size_t, struct filesystemcmp_handle *);
int	scratch_create(struct scratch_store *, struct filesystemcmp_handle,
	    const void *, size_t, uint32_t, uint32_t,
	    struct filesystemcmp_handle *);
int	scratch_open(struct scratch_store *, struct filesystemcmp_handle,
	    uint32_t);
ssize_t	scratch_read(struct scratch_store *, struct filesystemcmp_handle,
	    uint64_t, void *, size_t);
ssize_t	scratch_write(struct scratch_store *, struct filesystemcmp_handle,
	    uint64_t, const void *, size_t);
int	scratch_stat(struct scratch_store *, struct filesystemcmp_handle,
	    struct filesystemcmp_stat_reply *);
int	scratch_unlink(struct scratch_store *, struct filesystemcmp_handle,
	    const void *, size_t);
int	scratch_rename(struct scratch_store *, struct filesystemcmp_handle,
	    const void *, size_t, struct filesystemcmp_handle, const void *,
	    size_t);
uint64_t scratch_bytes(const struct scratch_store *);
uint32_t scratch_objects(const struct scratch_store *);

#endif
