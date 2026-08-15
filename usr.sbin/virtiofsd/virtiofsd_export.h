/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIOFSD_EXPORT_H_
#define	_VIRTIOFSD_EXPORT_H_

#include <sys/stat.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	VIRTIOFSD_ROOT_NODEID	UINT64_C(1)
#define	VIRTIOFSD_NAME_MAX	255U

struct virtiofsd_export;
struct virtiofsd_export_restore;
struct statfs;

int	virtiofsd_export_create(int, size_t, struct virtiofsd_export **);
void	virtiofsd_export_destroy(struct virtiofsd_export *);
void	virtiofsd_export_reset(struct virtiofsd_export *);
size_t	virtiofsd_export_node_count(struct virtiofsd_export *);
int	virtiofsd_export_state_size(struct virtiofsd_export *, size_t *);
int	virtiofsd_export_state_write(struct virtiofsd_export *, void *,
	    size_t, size_t *);
int	virtiofsd_export_restore_prepare(struct virtiofsd_export *,
	    const void *, size_t, struct virtiofsd_export_restore **);
int	virtiofsd_export_restore_open(struct virtiofsd_export_restore *,
	    uint64_t, bool, int *);
int	virtiofsd_export_restore_open_path(struct virtiofsd_export_restore *,
	    uint64_t, const void *, size_t, bool, uint64_t, int *);
void	virtiofsd_export_restore_commit(struct virtiofsd_export *,
	    struct virtiofsd_export_restore *);
void	virtiofsd_export_restore_destroy(struct virtiofsd_export_restore *);
int	virtiofsd_export_lookup(struct virtiofsd_export *, uint64_t,
	    const void *, size_t, uint64_t *, struct stat *);
int	virtiofsd_export_forget(struct virtiofsd_export *, uint64_t,
	    uint64_t);
int	virtiofsd_export_stat(struct virtiofsd_export *, uint64_t,
	    struct stat *);
int	virtiofsd_export_open(struct virtiofsd_export *, uint64_t, int,
	    int *);
int	virtiofsd_export_path(struct virtiofsd_export *, uint64_t, void *,
	    size_t, size_t *);
int	virtiofsd_export_readlink(struct virtiofsd_export *, uint64_t,
	    void *, size_t, size_t *);
int	virtiofsd_export_statfs(struct virtiofsd_export *, uint64_t,
	    struct statfs *);
int	virtiofsd_export_component_valid(const void *, size_t);

#endif
