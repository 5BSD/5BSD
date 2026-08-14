/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared helpers for TrustedZFS dataset-handle tests.
 *
 * Each test creates a private file-backed pool in the ATF work directory,
 * named after the test case so the cleanup routine (which runs in a separate
 * process) can find it.  Datasets are created with mountpoint=none so the
 * tests never interact with the mount namespace.
 */

#ifndef _ZFSHANDLE_TEST_HELPERS_H_
#define	_ZFSHANDLE_TEST_HELPERS_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/zfshandle.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	ZHT_VDEV_FILE	"vdev.img"
#define	ZHT_VDEV_SIZE	"256m"

static char zht_pool[128];

static inline void
zht_poolname(const atf_tc_t *tc, char *buf, size_t len)
{
	snprintf(buf, len, "zht_%s", atf_tc_get_ident(tc));
}

static inline int
zht_systemf(const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	return (system(cmd));
}

static inline void
zht_require(const atf_tc_t *tc __unused)
{
	struct stat sb;

	if (stat("/dev/zfs", &sb) != 0)
		atf_tc_skip("ZFS not available (/dev/zfs missing)");
	if (geteuid() != 0)
		atf_tc_skip("requires root");
}

static inline void
zht_pool_create(const atf_tc_t *tc)
{
	char cwd[1024];

	zht_poolname(tc, zht_pool, sizeof(zht_pool));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	/* Preexisting pool from a crashed run: clear it. */
	(void)zht_systemf("zpool destroy -f %s >/dev/null 2>&1", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("truncate -s %s %s", ZHT_VDEV_SIZE,
	    ZHT_VDEV_FILE));
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zpool create -f -O mountpoint=none %s %s/%s",
	    zht_pool, cwd, ZHT_VDEV_FILE));
}

static inline void
zht_pool_cleanup(const atf_tc_t *tc)
{
	char pool[128];

	zht_poolname(tc, pool, sizeof(pool));
	(void)zht_systemf("zpool destroy -f %s >/dev/null 2>&1", pool);
}

/* Mint a handle; returns fd or -1 with errno set. */
static inline int
zht_open(const char *name, uint64_t rights, uint32_t flags)
{
	struct zfs_dataset_open_args args;
	int devfd, error, serrno;

	devfd = open("/dev/zfs", O_RDWR);
	if (devfd < 0)
		return (-1);
	memset(&args, 0, sizeof(args));
	strlcpy(args.zdo_name, name, sizeof(args.zdo_name));
	args.zdo_rights = rights;
	args.zdo_flags = flags;
	args.zdo_fd = -1;
	error = ioctl(devfd, ZFS_IOC_DATASET_OPEN, &args);
	serrno = errno;
	close(devfd);
	if (error != 0) {
		errno = serrno;
		return (-1);
	}
	return (args.zdo_fd);
}

static inline int
zht_open_req(const char *name, uint64_t rights, uint32_t flags)
{
	int fd;

	fd = zht_open(name, rights, flags);
	ATF_REQUIRE_MSG(fd >= 0, "minting handle for %s failed: %s", name,
	    strerror(errno));
	return (fd);
}

static inline int
zfd_info(int fd, struct zfd_info_args *info)
{
	memset(info, 0, sizeof(*info));
	return (ioctl(fd, ZFD_INFO, info));
}

static inline int
zfd_stat(int fd, struct zfd_stat_args *st)
{
	memset(st, 0, sizeof(*st));
	return (ioctl(fd, ZFD_STAT, st));
}

static inline int
zfd_snapshot(int fd, const char *snap)
{
	struct zfd_snapshot_args args;

	memset(&args, 0, sizeof(args));
	strlcpy(args.zsn_snapname, snap, sizeof(args.zsn_snapname));
	return (ioctl(fd, ZFD_SNAPSHOT, &args));
}

static inline int
zfd_snap_destroy(int fd, const char *snap)
{
	struct zfd_snapshot_args args;

	memset(&args, 0, sizeof(args));
	strlcpy(args.zsn_snapname, snap, sizeof(args.zsn_snapname));
	return (ioctl(fd, ZFD_SNAP_DESTROY, &args));
}

static inline int
zfd_rollback(int fd, const char *snap)
{
	struct zfd_rollback_args args;

	memset(&args, 0, sizeof(args));
	if (snap != NULL)
		strlcpy(args.zr_snapname, snap, sizeof(args.zr_snapname));
	return (ioctl(fd, ZFD_ROLLBACK, &args));
}

static inline int
zfd_set_prop_str(int fd, const char *prop, const char *val)
{
	struct zfd_set_prop_args args;

	memset(&args, 0, sizeof(args));
	strlcpy(args.zsp_name, prop, sizeof(args.zsp_name));
	strlcpy(args.zsp_strval, val, sizeof(args.zsp_strval));
	args.zsp_is_string = 1;
	return (ioctl(fd, ZFD_SET_PROP, &args));
}

static inline int
zfd_derive(int fd, uint64_t rights)
{
	struct zfd_derive_args args;
	int error;

	memset(&args, 0, sizeof(args));
	args.zd_rights = rights;
	args.zd_fd = -1;
	error = ioctl(fd, ZFD_DERIVE, &args);
	return (error == 0 ? args.zd_fd : -1);
}

static inline int
zfd_openat(int fd, const char *relname, uint64_t rights, uint32_t flags)
{
	struct zfd_openat_args args;
	int error;

	memset(&args, 0, sizeof(args));
	strlcpy(args.zo_relname, relname, sizeof(args.zo_relname));
	args.zo_rights = rights;
	args.zo_flags = flags;
	args.zo_fd = -1;
	error = ioctl(fd, ZFD_OPENAT, &args);
	return (error == 0 ? args.zo_fd : -1);
}

static inline int
zfd_get_props(int fd, void *buf, size_t buflen, uint64_t *sizep)
{
	struct zfd_get_props_args args;
	int error;

	memset(&args, 0, sizeof(args));
	args.zgp_buf = (uint64_t)(uintptr_t)buf;
	args.zgp_buflen = buflen;
	error = ioctl(fd, ZFD_GET_PROPS, &args);
	if (sizep != NULL)
		*sizep = args.zgp_size;
	return (error);
}

#endif /* !_ZFSHANDLE_TEST_HELPERS_H_ */
