/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _FILESYSTEMCMP_STORE_H_
#define	_FILESYSTEMCMP_STORE_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include <filesystemcmp_protocol.h>

#include "scratch.h"

struct filesystem_store;

int	filesystem_store_create(const struct scratch_limits *, int, int,
	    struct filesystem_store **);
void	filesystem_store_destroy(struct filesystem_store *);
uint32_t filesystem_store_features(const struct filesystem_store *);
int	filesystem_store_root(struct filesystem_store *, uint32_t,
	    struct filesystemcmp_handle *);
int	filesystem_store_lookup(struct filesystem_store *,
	    struct filesystemcmp_handle, const void *, size_t,
	    struct filesystemcmp_handle *);
int	filesystem_store_create_object(struct filesystem_store *,
	    struct filesystemcmp_handle, const void *, size_t, uint32_t,
	    uint32_t, struct filesystemcmp_handle *);
int	filesystem_store_open(struct filesystem_store *,
	    struct filesystemcmp_handle, uint32_t);
ssize_t	filesystem_store_read(struct filesystem_store *,
	    struct filesystemcmp_handle, uint64_t, void *, size_t);
ssize_t	filesystem_store_write(struct filesystem_store *,
	    struct filesystemcmp_handle, uint64_t, const void *, size_t);
int	filesystem_store_stat(struct filesystem_store *,
	    struct filesystemcmp_handle, struct filesystemcmp_stat_reply *);
int	filesystem_store_unlink(struct filesystem_store *,
	    struct filesystemcmp_handle, const void *, size_t);
int	filesystem_store_rename(struct filesystem_store *,
	    struct filesystemcmp_handle, const void *, size_t,
	    struct filesystemcmp_handle, const void *, size_t);
int	filesystem_store_close(struct filesystem_store *,
	    struct filesystemcmp_handle);
int	filesystem_store_sync(struct filesystem_store *,
	    struct filesystemcmp_handle);
int	filesystem_store_dup(struct filesystem_store *,
	    struct filesystemcmp_handle, struct filesystemcmp_handle *);

#endif
