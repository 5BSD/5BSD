/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIOFSD_HANDLE_H_
#define	_VIRTIOFSD_HANDLE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtiofsd_handles;
struct virtiofsd_handles_restore;
typedef int (*virtiofsd_handle_reopen_cb)(void *, uint64_t, const void *,
    size_t, bool, uint64_t, int *);

int	virtiofsd_handles_create(size_t, struct virtiofsd_handles **);
void	virtiofsd_handles_destroy(struct virtiofsd_handles *);
int	virtiofsd_handles_insert(struct virtiofsd_handles *, int, uint64_t,
	    bool, uint64_t *);
int	virtiofsd_handles_insert_identity(struct virtiofsd_handles *, int,
	    uint64_t, bool, const void *, size_t, uint64_t *);
int	virtiofsd_handles_dup(struct virtiofsd_handles *, uint64_t, bool,
	    int *, uint64_t *);
int	virtiofsd_handles_remove(struct virtiofsd_handles *, uint64_t, bool);
int	virtiofsd_handles_remove_node(struct virtiofsd_handles *, uint64_t,
	    bool, uint64_t);
size_t	virtiofsd_handles_count(struct virtiofsd_handles *);
int	virtiofsd_handles_state_size(struct virtiofsd_handles *, size_t *);
int	virtiofsd_handles_state_write(struct virtiofsd_handles *, void *,
	    size_t, size_t *);
int	virtiofsd_handles_restore_prepare(struct virtiofsd_handles *,
	    virtiofsd_handle_reopen_cb, void *, const void *, size_t,
	    struct virtiofsd_handles_restore **);
void	virtiofsd_handles_restore_commit(struct virtiofsd_handles *,
	    struct virtiofsd_handles_restore *);
void	virtiofsd_handles_restore_destroy(
	    struct virtiofsd_handles_restore *);

#endif
