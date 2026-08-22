/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libtrustedzfs: thin, dependency-free wrappers over the TrustedZFS
 * handle ioctls.  See trustedzfs.h for the API contract.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trustedzfs.h"

#define	ZFS_DEV	"/dev/zfs"
#define	TZFS_NVLIST_MAX	(16U * 1024U * 1024U)

struct tzfs_ioctl_map {
	tzfs_opset_t op;
	cap_ioctl_t cmd;
};

static const struct tzfs_ioctl_map tzfs_dataset_ioctl_map[] = {
	{ TZFS_OP_INFO, ZFD_INFO },
	{ TZFS_OP_DERIVE, ZFD_DERIVE },
	{ TZFS_OP_OPENAT, ZFD_OPENAT },
	{ TZFS_OP_STAT, ZFD_STAT },
	{ TZFS_OP_GET_PROPS, ZFD_GET_PROPS },
	{ TZFS_OP_GET_ONE_PROP, ZFD_GET_ONE_PROP },
	{ TZFS_OP_LIST_CHILDREN, ZFD_LIST_CHILDREN },
	{ TZFS_OP_LIST_SNAPSHOTS, ZFD_LIST_SNAPS },
	{ TZFS_OP_HOLDS, ZFD_HOLDS },
	{ TZFS_OP_LIST_BOOKMARKS, ZFD_LIST_BOOKMARKS },
	{ TZFS_OP_SET_PROP, ZFD_SET_PROP },
	{ TZFS_OP_INHERIT, ZFD_INHERIT },
	{ TZFS_OP_SNAPSHOT, ZFD_SNAPSHOT },
	{ TZFS_OP_BOOKMARK, ZFD_BOOKMARK },
	{ TZFS_OP_SNAP_DESTROY, ZFD_SNAP_DESTROY },
	{ TZFS_OP_DESTROY_BOOKMARK, ZFD_DESTROY_BOOKMARK },
	{ TZFS_OP_ROLLBACK, ZFD_ROLLBACK },
	{ TZFS_OP_CREATE, ZFD_CREATE },
	{ TZFS_OP_DESTROY, ZFD_DESTROY },
	{ TZFS_OP_RENAME, ZFD_RENAME },
	{ TZFS_OP_CLONE, ZFD_CLONE },
	{ TZFS_OP_PROMOTE, ZFD_PROMOTE },
	{ TZFS_OP_SEND, ZFD_SEND },
	{ TZFS_OP_RECV, ZFD_RECV },
	{ TZFS_OP_HOLD, ZFD_HOLD },
	{ TZFS_OP_RELEASE, ZFD_RELEASE },
	{ TZFS_OP_BLKOPEN, ZFD_BLKOPEN },
	{ TZFS_OP_MOUNT, ZFD_MOUNT },
	{ TZFS_OP_UNMOUNT, ZFD_UNMOUNT },
};

static const struct tzfs_ioctl_map tzfs_pool_ioctl_map[] = {
	{ TZFS_OP_INFO, ZFD_INFO },
	{ TZFS_OP_DERIVE, ZFD_DERIVE },
	{ TZFS_OP_POOL_STAT, ZPD_STAT },
	{ TZFS_OP_POOL_GET_PROPS, ZPD_GET_PROPS },
	{ TZFS_OP_POOL_SET_PROP, ZPD_SET_PROP },
	{ TZFS_OP_POOL_SCRUB, ZPD_SCRUB },
	{ TZFS_OP_POOL_ROOT_OPEN, ZPD_ROOT_OPEN },
};

static int
tzfs_limit_ioctls(int fd, tzfs_opset_t ops, tzfs_opset_t valid,
    const struct tzfs_ioctl_map *map, size_t nmap)
{
	struct zfd_limit_args limit;
	struct stat sb;
	cap_ioctl_t cmds[nmap + 1];
	size_t i, ncmds;

	if ((ops & ~valid) != 0) {
		errno = EINVAL;
		return (-1);
	}
	/* A real handle must accept the inheritable kernel ceiling. */
	memset(&limit, 0, sizeof(limit));
	limit.zl_ops = ops;
	if (ioctl(fd, ZFD_LIMIT, &limit) == -1) {
		int saved = errno;

		/* Socket-backed tests exercise only the generic Capsicum mapping. */
		if (fstat(fd, &sb) == -1 || !S_ISSOCK(sb.st_mode)) {
			errno = saved;
			return (-1);
		}
	}
	/* Retain only the monotonic, kernel-enforced narrowing operation itself. */
	cmds[0] = ZFD_LIMIT;
	ncmds = 1;
	for (i = 0; i < nmap; i++) {
		if ((ops & map[i].op) != 0)
			cmds[ncmds++] = map[i].cmd;
	}
	return (cap_ioctls_limit(fd, cmds, ncmds));
}

int
tzfs_limit_dataset_ioctls(int zfd, tzfs_opset_t ops)
{
	return (tzfs_limit_ioctls(zfd, ops, TZFS_OP_DATASET_ALL,
	    tzfs_dataset_ioctl_map, nitems(tzfs_dataset_ioctl_map)));
}

int
tzfs_limit_pool_ioctls(int zpd, tzfs_opset_t ops)
{
	return (tzfs_limit_ioctls(zpd, ops, TZFS_OP_POOL_ALL,
	    tzfs_pool_ioctl_map, nitems(tzfs_pool_ioctl_map)));
}

int
tzfs_limit_dataset_ioctls_by_rights(int zfd, uint64_t rights, uint32_t flags)
{
	tzfs_opset_t ops;

	if ((rights & ~ZH_ALL_RIGHTS) != 0 || (flags & ~ZHF_ALL) != 0 ||
	    ((flags & ZHF_SEND_CONSUME) != 0 &&
	    (flags & ZHF_SEND_ONCE) == 0)) {
		errno = EINVAL;
		return (-1);
	}
	/* Every dataset handle has ZH_PROPS_READ and ZH_EVENT implicitly. */
	ops = TZFS_OP_INFO | TZFS_OP_DERIVE | TZFS_OP_OPENAT | TZFS_OP_STAT |
	    TZFS_OP_GET_PROPS | TZFS_OP_GET_ONE_PROP |
	    TZFS_OP_LIST_SNAPSHOTS | TZFS_OP_HOLDS |
	    TZFS_OP_LIST_BOOKMARKS;
	if ((flags & ZHF_SUBTREE) != 0)
		ops |= TZFS_OP_LIST_CHILDREN;
	if ((rights & ZH_PROPS_WRITE) != 0)
		ops |= TZFS_OP_SET_PROP | TZFS_OP_INHERIT;
	if ((rights & ZH_SNAPSHOT) != 0)
		ops |= TZFS_OP_SNAPSHOT;
	if ((rights & ZH_BOOKMARK) != 0)
		ops |= TZFS_OP_BOOKMARK;
	if ((rights & ZH_SNAP_DESTROY) != 0)
		ops |= TZFS_OP_SNAP_DESTROY | TZFS_OP_DESTROY_BOOKMARK;
	if ((rights & ZH_ROLLBACK) != 0)
		ops |= TZFS_OP_ROLLBACK;
	if ((rights & ZH_CREATE) != 0)
		ops |= TZFS_OP_CREATE | TZFS_OP_CLONE;
	if ((rights & ZH_DESTROY) != 0)
		ops |= TZFS_OP_DESTROY;
	if ((rights & ZH_RENAME) != 0)
		ops |= TZFS_OP_RENAME;
	if ((rights & ZH_PROMOTE) != 0)
		ops |= TZFS_OP_PROMOTE;
	if ((rights & ZH_SEND) != 0)
		ops |= TZFS_OP_SEND;
	if ((rights & ZH_RECV) != 0)
		ops |= TZFS_OP_RECV;
	if ((rights & ZH_MOUNT) != 0)
		ops |= TZFS_OP_BLKOPEN | TZFS_OP_MOUNT | TZFS_OP_UNMOUNT;
	if ((rights & ZH_HOLD) != 0)
		ops |= TZFS_OP_HOLD;
	if ((rights & ZH_RELEASE) != 0)
		ops |= TZFS_OP_RELEASE;
	if ((rights & ZH_CLONE_SRC) != 0)
		ops |= TZFS_OP_CLONE_SOURCE;
	return (tzfs_limit_dataset_ioctls(zfd, ops));
}

int
tzfs_limit_pool_ioctls_by_rights(int zpd, uint64_t rights)
{
	tzfs_opset_t ops;

	if ((rights & ~ZH_ALL_RIGHTS) != 0) {
		errno = EINVAL;
		return (-1);
	}
	ops = TZFS_OP_INFO | TZFS_OP_DERIVE | TZFS_OP_POOL_STAT |
	    TZFS_OP_POOL_GET_PROPS | TZFS_OP_POOL_ROOT_OPEN;
	if ((rights & ZH_PROPS_WRITE) != 0)
		ops |= TZFS_OP_POOL_SET_PROP;
	if ((rights & ZH_SCRUB) != 0)
		ops |= TZFS_OP_POOL_SCRUB;
	return (tzfs_limit_pool_ioctls(zpd, ops));
}

static int
tzfs_str_arg(char *dst, size_t dstlen, const char *src, bool required)
{
	if (src == NULL || src[0] == '\0') {
		if (required) {
			errno = EINVAL;
			return (-1);
		}
		dst[0] = '\0';
		return (0);
	}
	if (strlcpy(dst, src, dstlen) >= dstlen) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	return (0);
}

int
tzfs_open(const char *dataset, uint64_t rights, uint32_t flags)
{
	struct zfs_dataset_open_args args;
	int devfd, saved;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zdo_name, sizeof(args.zdo_name), dataset,
	    true) == -1)
		return (-1);
	args.zdo_rights = rights;
	args.zdo_flags = flags;
	args.zdo_fd = -1;

	devfd = open(ZFS_DEV, O_RDWR | O_CLOEXEC);
	if (devfd == -1)
		return (-1);
	if (ioctl(devfd, ZFS_IOC_DATASET_OPEN, &args) == -1) {
		saved = errno;
		(void) close(devfd);
		errno = saved;
		return (-1);
	}
	(void) close(devfd);
	return (args.zdo_fd);
}

int
tzfs_derive(int zfd, uint64_t rights)
{
	struct zfd_derive_args args;

	memset(&args, 0, sizeof(args));
	args.zd_rights = rights;
	args.zd_fd = -1;
	if (ioctl(zfd, ZFD_DERIVE, &args) == -1)
		return (-1);
	return (args.zd_fd);
}

int
tzfs_openat(int zfd, const char *relname, uint64_t rights, uint32_t flags)
{
	struct zfd_openat_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zo_relname, sizeof(args.zo_relname), relname,
	    true) == -1)
		return (-1);
	args.zo_rights = rights;
	args.zo_flags = flags;
	args.zo_fd = -1;
	if (ioctl(zfd, ZFD_OPENAT, &args) == -1)
		return (-1);
	return (args.zo_fd);
}

int
tzfs_info(int zfd, struct zfd_info_args *info)
{
	return (ioctl(zfd, ZFD_INFO, info));
}

int
tzfs_stat(int zfd, struct zfd_stat_args *st)
{
	return (ioctl(zfd, ZFD_STAT, st));
}

int
tzfs_get_props(int zfd, void **bufp, size_t *lenp)
{
	struct zfd_get_props_args args;
	void *buf;
	size_t len;
	int saved;

	if (bufp == NULL || lenp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*bufp = NULL;
	*lenp = 0;

	len = 64 * 1024;
	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return (-1);
		memset(&args, 0, sizeof(args));
		args.zgp_buf = (uint64_t)(uintptr_t)buf;
		args.zgp_buflen = len;
		if (ioctl(zfd, ZFD_GET_PROPS, &args) == 0) {
			*bufp = buf;
			*lenp = args.zgp_size;
			return (0);
		}
		saved = errno;
		free(buf);
		if (saved != ENOMEM || args.zgp_size <= len) {
			errno = saved;
			return (-1);
		}
		if (args.zgp_size > TZFS_NVLIST_MAX) {
			errno = EOVERFLOW;
			return (-1);
		}
		len = args.zgp_size;
	}
}

static int
tzfs_set_prop(int zfd, const char *prop, const char *strval, uint64_t intval,
    bool is_string)
{
	struct zfd_set_prop_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zsp_name, sizeof(args.zsp_name), prop,
	    true) == -1)
		return (-1);
	if (is_string && tzfs_str_arg(args.zsp_strval,
	    sizeof(args.zsp_strval), strval, true) == -1)
		return (-1);
	args.zsp_intval = intval;
	args.zsp_is_string = is_string ? 1 : 0;
	return (ioctl(zfd, ZFD_SET_PROP, &args));
}

int
tzfs_set_prop_string(int zfd, const char *prop, const char *val)
{
	return (tzfs_set_prop(zfd, prop, val, 0, true));
}

int
tzfs_set_prop_uint64(int zfd, const char *prop, uint64_t val)
{
	return (tzfs_set_prop(zfd, prop, NULL, val, false));
}

static int
tzfs_snap_op(int zfd, unsigned long cmd, const char *snap)
{
	struct zfd_snapshot_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zsn_snapname, sizeof(args.zsn_snapname), snap,
	    true) == -1)
		return (-1);
	return (ioctl(zfd, cmd, &args));
}

int
tzfs_snapshot(int zfd, const char *snap)
{
	return (tzfs_snap_op(zfd, ZFD_SNAPSHOT, snap));
}

int
tzfs_snap_destroy(int zfd, const char *snap)
{
	return (tzfs_snap_op(zfd, ZFD_SNAP_DESTROY, snap));
}

int
tzfs_rollback(int zfd, const char *snap)
{
	struct zfd_rollback_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zr_snapname, sizeof(args.zr_snapname), snap,
	    false) == -1)
		return (-1);
	return (ioctl(zfd, ZFD_ROLLBACK, &args));
}

/* Shared buffer-growing wrapper for the nvlist-returning list verbs. */
static int
tzfs_list_ioctl(int zfd, unsigned long cmd, void **bufp, size_t *lenp)
{
	struct zfd_get_props_args args;
	void *buf;
	size_t len;
	int saved;

	if (bufp == NULL || lenp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*bufp = NULL;
	*lenp = 0;

	len = 64 * 1024;
	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return (-1);
		memset(&args, 0, sizeof(args));
		args.zgp_buf = (uint64_t)(uintptr_t)buf;
		args.zgp_buflen = len;
		if (ioctl(zfd, cmd, &args) == 0) {
			*bufp = buf;
			*lenp = args.zgp_size;
			return (0);
		}
		saved = errno;
		free(buf);
		if (saved != ENOMEM || args.zgp_size <= len) {
			errno = saved;
			return (-1);
		}
		if (args.zgp_size > TZFS_NVLIST_MAX) {
			errno = EOVERFLOW;
			return (-1);
		}
		len = args.zgp_size;
	}
}

int
tzfs_list_children(int zfd, void **bufp, size_t *lenp)
{
	return (tzfs_list_ioctl(zfd, ZFD_LIST_CHILDREN, bufp, lenp));
}

int
tzfs_list_snapshots(int zfd, void **bufp, size_t *lenp)
{
	return (tzfs_list_ioctl(zfd, ZFD_LIST_SNAPS, bufp, lenp));
}

int
tzfs_holds(int zfd, void **bufp, size_t *lenp)
{
	return (tzfs_list_ioctl(zfd, ZFD_HOLDS, bufp, lenp));
}

int
tzfs_list_bookmarks(int zfd, void **bufp, size_t *lenp)
{
	return (tzfs_list_ioctl(zfd, ZFD_LIST_BOOKMARKS, bufp, lenp));
}

int
tzfs_get_one_prop(int zfd, const char *prop, char *strval, size_t strvallen,
    uint64_t *intval, int *is_string, uint32_t *source)
{
	struct zfd_get_one_prop_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zgo_name, sizeof(args.zgo_name), prop,
	    true) == -1)
		return (-1);
	if (ioctl(zfd, ZFD_GET_ONE_PROP, &args) == -1)
		return (-1);
	if (is_string != NULL)
		*is_string = args.zgo_is_string ? 1 : 0;
	if (source != NULL)
		*source = args.zgo_source;
	if (args.zgo_is_string) {
		if (strval != NULL && strvallen > 0 &&
		    strlcpy(strval, args.zgo_strval, strvallen) >= strvallen) {
			errno = ERANGE;
			return (-1);
		}
	} else if (intval != NULL) {
		*intval = args.zgo_intval;
	}
	return (0);
}

int
tzfs_inherit(int zfd, const char *prop, bool received)
{
	struct zfd_inherit_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zin_name, sizeof(args.zin_name), prop,
	    true) == -1)
		return (-1);
	args.zin_received = received ? 1 : 0;
	return (ioctl(zfd, ZFD_INHERIT, &args));
}

int
tzfs_promote(int zfd)
{
	return (ioctl(zfd, ZFD_PROMOTE));
}

int
tzfs_bookmark(int zfd, const char *snap, const char *bookmark)
{
	struct zfd_bookmark_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zbm_snapname, sizeof(args.zbm_snapname), snap,
	    false) == -1)
		return (-1);
	if (tzfs_str_arg(args.zbm_bookname, sizeof(args.zbm_bookname),
	    bookmark, true) == -1)
		return (-1);
	return (ioctl(zfd, ZFD_BOOKMARK, &args));
}

int
tzfs_destroy_bookmark(int zfd, const char *bookmark)
{
	struct zfd_bookmark_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zbm_bookname, sizeof(args.zbm_bookname),
	    bookmark, true) == -1)
		return (-1);
	return (ioctl(zfd, ZFD_DESTROY_BOOKMARK, &args));
}

static int
tzfs_hold_op(int zfd, unsigned long cmd, const char *snap, const char *tag)
{
	struct zfd_hold_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zh_snapname, sizeof(args.zh_snapname), snap,
	    false) == -1)
		return (-1);
	if (tzfs_str_arg(args.zh_tag, sizeof(args.zh_tag), tag, true) == -1)
		return (-1);
	return (ioctl(zfd, cmd, &args));
}

int
tzfs_hold(int zfd, const char *snap, const char *tag)
{
	return (tzfs_hold_op(zfd, ZFD_HOLD, snap, tag));
}

int
tzfs_release(int zfd, const char *snap, const char *tag)
{
	return (tzfs_hold_op(zfd, ZFD_RELEASE, snap, tag));
}

int
tzfs_create(int zfd, const char *relname, uint32_t handle_flags)
{
	struct zfd_create_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zc_relname, sizeof(args.zc_relname), relname,
	    true) == -1)
		return (-1);
	args.zc_type = ZFD_TYPE_FILESYSTEM;
	args.zc_handle_flags = handle_flags;
	args.zc_fd = -1;
	if (ioctl(zfd, ZFD_CREATE, &args) == -1)
		return (-1);
	return (args.zc_fd);
}

int
tzfs_create_volume(int zfd, const char *relname, uint64_t volsize,
    uint64_t volblocksize)
{
	struct zfd_create_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zc_relname, sizeof(args.zc_relname), relname,
	    true) == -1)
		return (-1);
	args.zc_type = ZFD_TYPE_VOLUME;
	args.zc_volsize = volsize;
	args.zc_volblocksize = volblocksize;
	args.zc_fd = -1;
	if (ioctl(zfd, ZFD_CREATE, &args) == -1)
		return (-1);
	return (args.zc_fd);
}

int
tzfs_destroy(int zfd, const char *relname)
{
	struct zfd_destroy_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zd_relname, sizeof(args.zd_relname), relname,
	    false) == -1)
		return (-1);
	return (ioctl(zfd, ZFD_DESTROY, &args));
}

int
tzfs_rename(int zfd, const char *from, const char *to)
{
	struct zfd_rename_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zr_from, sizeof(args.zr_from), from,
	    false) == -1)
		return (-1);
	if (tzfs_str_arg(args.zr_to, sizeof(args.zr_to), to, true) == -1)
		return (-1);
	return (ioctl(zfd, ZFD_RENAME, &args));
}

int
tzfs_clone(int zfd, int origin_zfd, const char *origin_snap,
    const char *relname)
{
	struct zfd_clone_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zc_relname, sizeof(args.zc_relname), relname,
	    true) == -1)
		return (-1);
	if (tzfs_str_arg(args.zc_origin_snap, sizeof(args.zc_origin_snap),
	    origin_snap, false) == -1)
		return (-1);
	args.zc_origin_fd = origin_zfd;
	args.zc_fd = -1;
	if (ioctl(zfd, ZFD_CLONE, &args) == -1)
		return (-1);
	return (args.zc_fd);
}

int
tzfs_send(int zfd, const char *snap, const char *fromsnap, int out_fd,
    uint32_t flags)
{
	struct zfd_send_args args;

	if ((flags & ~ZFD_SEND_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zs_snapname, sizeof(args.zs_snapname), snap,
	    false) == -1)
		return (-1);
	if (tzfs_str_arg(args.zs_fromsnap, sizeof(args.zs_fromsnap),
	    fromsnap, false) == -1)
		return (-1);
	args.zs_out_fd = out_fd;
	args.zs_flags = flags;
	return (ioctl(zfd, ZFD_SEND, &args));
}

int
tzfs_recv(int zfd, const char *reltarget, int in_fd, bool force)
{
	struct zfd_recv_args args;
	size_t off;
	ssize_t n;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zr_reltarget, sizeof(args.zr_reltarget),
	    reltarget, true) == -1)
		return (-1);

	/* The kernel expects the caller to have consumed the BEGIN record. */
	for (off = 0; off < ZFD_BEGIN_RECORD_SIZE; off += (size_t)n) {
		n = read(in_fd, args.zr_begin_record + off,
		    ZFD_BEGIN_RECORD_SIZE - off);
		if (n == 0) {
			errno = EINVAL;
			return (-1);
		}
		if (n == -1) {
			if (errno == EINTR) {
				n = 0;
				continue;
			}
			return (-1);
		}
	}
	args.zr_input_fd = in_fd;
	args.zr_force = force ? 1 : 0;
	return (ioctl(zfd, ZFD_RECV, &args));
}

int
tzfs_blkopen(int zfd, bool writable)
{
	struct zfd_blkopen_args args;

	memset(&args, 0, sizeof(args));
	args.zb_write = writable ? 1 : 0;
	args.zb_fd = -1;
	if (ioctl(zfd, ZFD_BLKOPEN, &args) == -1)
		return (-1);
	return (args.zb_fd);
}

int
tzfs_mount(int zfd, bool rdonly)
{
	struct zfd_mount_args args;

	memset(&args, 0, sizeof(args));
	args.zm_rdonly = rdonly ? 1 : 0;
	args.zm_fd = -1;
	if (ioctl(zfd, ZFD_MOUNT, &args) == -1)
		return (-1);
	return (args.zm_fd);
}

int
tzfs_unmount(int zfd)
{
	return (ioctl(zfd, ZFD_UNMOUNT));
}

int
tzfs_pool_open(const char *pool, uint64_t rights)
{
	struct zfs_pool_open_args args;
	int devfd, saved;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zpo_name, sizeof(args.zpo_name), pool,
	    true) == -1)
		return (-1);
	args.zpo_rights = rights;
	args.zpo_fd = -1;

	devfd = open(ZFS_DEV, O_RDWR | O_CLOEXEC);
	if (devfd == -1)
		return (-1);
	if (ioctl(devfd, ZFS_IOC_POOL_OPEN, &args) == -1) {
		saved = errno;
		(void) close(devfd);
		errno = saved;
		return (-1);
	}
	(void) close(devfd);
	return (args.zpo_fd);
}

int
tzfs_pool_stat(int zpd, struct zpd_stat_args *st)
{
	return (ioctl(zpd, ZPD_STAT, st));
}

int
tzfs_pool_get_props(int zpd, void **bufp, size_t *lenp)
{
	struct zfd_get_props_args args;
	void *buf;
	size_t len;
	int saved;

	if (bufp == NULL || lenp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*bufp = NULL;
	*lenp = 0;

	len = 64 * 1024;
	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return (-1);
		memset(&args, 0, sizeof(args));
		args.zgp_buf = (uint64_t)(uintptr_t)buf;
		args.zgp_buflen = len;
		if (ioctl(zpd, ZPD_GET_PROPS, &args) == 0) {
			*bufp = buf;
			*lenp = args.zgp_size;
			return (0);
		}
		saved = errno;
		free(buf);
		if (saved != ENOMEM || args.zgp_size <= len) {
			errno = saved;
			return (-1);
		}
		if (args.zgp_size > TZFS_NVLIST_MAX) {
			errno = EOVERFLOW;
			return (-1);
		}
		len = args.zgp_size;
	}
}

int
tzfs_pool_set_prop_string(int zpd, const char *prop, const char *val)
{
	struct zfd_set_prop_args args;

	memset(&args, 0, sizeof(args));
	if (tzfs_str_arg(args.zsp_name, sizeof(args.zsp_name), prop,
	    true) == -1)
		return (-1);
	if (tzfs_str_arg(args.zsp_strval, sizeof(args.zsp_strval), val,
	    true) == -1)
		return (-1);
	args.zsp_is_string = 1;
	return (ioctl(zpd, ZPD_SET_PROP, &args));
}

int
tzfs_pool_scrub(int zpd, uint32_t cmd)
{
	struct zpd_scrub_args args;

	memset(&args, 0, sizeof(args));
	args.zs_cmd = cmd;
	return (ioctl(zpd, ZPD_SCRUB, &args));
}

int
tzfs_pool_root_open(int zpd, uint64_t rights, uint32_t flags)
{
	struct zpd_root_open_args args;

	memset(&args, 0, sizeof(args));
	args.zr_rights = rights;
	args.zr_flags = flags;
	args.zr_fd = -1;
	if (ioctl(zpd, ZPD_ROOT_OPEN, &args) == -1)
		return (-1);
	return (args.zr_fd);
}
