/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libtrustedzfs: userland API over TrustedZFS dataset handles.
 *
 * A handle is a file descriptor over the ZFS management plane, carrying a
 * rights mask fixed at creation (see zfshandle(4) concepts in
 * docs/trustedzfs-design.md).  tzfs_open() is the only name-based call;
 * everything else operates through descriptors, works after cap_enter(2)
 * (except tzfs_blkopen(), see below), and composes with cap_rights_limit(2)
 * and cap_ioctls_limit(2).
 *
 * All functions return 0 on success (or a file descriptor >= 0 where
 * documented) and -1 with errno set on error.
 */

#ifndef _TRUSTEDZFS_H_
#define	_TRUSTEDZFS_H_

#include <sys/types.h>
#include <sys/zfshandle.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

__BEGIN_DECLS

/* Minting and derivation.  Each returns a new handle fd. */
int	tzfs_open(const char *dataset, uint64_t rights, uint32_t flags);
int	tzfs_derive(int zfd, uint64_t rights);
int	tzfs_openat(int zfd, const char *relname, uint64_t rights,
	    uint32_t flags);

/* Introspection. */
int	tzfs_info(int zfd, struct zfd_info_args *info);
int	tzfs_stat(int zfd, struct zfd_stat_args *st);

/*
 * All properties as a packed native-encoded nvlist, malloc(3)ed into
 * *bufp (caller frees).  Unpack with nvlist_unpack(3) from libnvpair if
 * structured access is wanted.
 */
int	tzfs_get_props(int zfd, void **bufp, size_t *lenp);
int	tzfs_set_prop_string(int zfd, const char *prop, const char *val);
int	tzfs_set_prop_uint64(int zfd, const char *prop, uint64_t val);

/* Snapshot lifecycle.  Snapshot names are components (no '@'). */
int	tzfs_snapshot(int zfd, const char *snap);
int	tzfs_snap_destroy(int zfd, const char *snap);
int	tzfs_rollback(int zfd, const char *snap);	/* NULL = latest */
int	tzfs_hold(int zfd, const char *snap, const char *tag);
int	tzfs_release(int zfd, const char *snap, const char *tag);

/*
 * Dataset lifecycle.  Relative names resolve under the handle (subtree
 * grants); NULL/"" means the handle's own dataset where noted.  Creation
 * calls return a handle fd for the new dataset.
 */
int	tzfs_create(int zfd, const char *relname, uint32_t handle_flags);
int	tzfs_create_volume(int zfd, const char *relname, uint64_t volsize,
	    uint64_t volblocksize);
int	tzfs_destroy(int zfd, const char *relname);	/* NULL = self */
int	tzfs_rename(int zfd, const char *from, const char *to);
int	tzfs_clone(int zfd, int origin_zfd, const char *origin_snap,
	    const char *relname);

/*
 * Streams.  tzfs_send() writes a full or incremental stream for the given
 * snapshot to out_fd (which needs CAP_WRITE).  tzfs_recv() reads the
 * stream's BEGIN record from in_fd itself, then receives the remainder
 * into reltarget ("child@snap" or "@snap"); in_fd needs CAP_READ.
 */
int	tzfs_send(int zfd, const char *snap, const char *fromsnap,
	    int out_fd, uint32_t flags);
int	tzfs_recv(int zfd, const char *reltarget, int in_fd, bool force);

/*
 * zvol bridge: open the handle's volume as a block-device fd.  Currently
 * resolves through devfs, so it fails with ECAPMODE inside capability
 * mode — open before cap_enter(2), like disk opens generally.
 */
int	tzfs_blkopen(int zfd, bool writable);

/*
 * Anonymous mount: mount the handle's filesystem outside the global
 * namespace and return a directory fd of its root — the only way in.
 * The handle anchors the mount: tzfs_unmount() or closing the handle
 * forcibly unmounts it, after which dirfd operations fail.
 */
int	tzfs_mount(int zfd, bool rdonly);
int	tzfs_unmount(int zfd);

/*
 * Pool handles: thin, deliberately.  tzfs_pool_open() mints by pool name
 * (rights beyond the implicit read/watch pair require root); stats,
 * props (e.g. bootfs), scrub control, and the one-way root-dataset
 * bridge are the whole delegable surface.
 */
int	tzfs_pool_open(const char *pool, uint64_t rights);
int	tzfs_pool_stat(int zpd, struct zpd_stat_args *st);
int	tzfs_pool_get_props(int zpd, void **bufp, size_t *lenp);
int	tzfs_pool_set_prop_string(int zpd, const char *prop,
	    const char *val);
int	tzfs_pool_scrub(int zpd, uint32_t cmd);
int	tzfs_pool_root_open(int zpd, uint64_t rights, uint32_t flags);

__END_DECLS

#endif /* !_TRUSTEDZFS_H_ */
