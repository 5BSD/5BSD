/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS Phase 3 tests: anonymous mounts.  The dirfd is the only way
 * in; the handle anchors the mount.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <fcntl.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

static int
anon_mount_count(void)
{
	return (zht_systemf("mount | grep -q '\\[anon\\]'"));
}

ATF_TC_WITH_CLEANUP(mount_dirfd_io);
ATF_TC_HEAD(mount_dirfd_io, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "anonymous mount: file I/O through the dirfd, no path access");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mount_dirfd_io, tc)
{
	char ds[256], buf[64];
	int zfd, dirfd, fd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(zfd >= 0);

	dirfd = tzfs_mount(zfd, false);
	ATF_REQUIRE_MSG(dirfd >= 0, "mount: %s", strerror(errno));

	/* Visible on the mount list as [anon]... */
	ATF_REQUIRE_EQ(0, anon_mount_count());

	/* ...and fully usable through the dirfd. */
	fd = openat(dirfd, "hello.txt", O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, write(fd, "world", 5));
	close(fd);
	fd = openat(dirfd, "hello.txt", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, read(fd, buf, sizeof(buf)));
	ATF_REQUIRE_EQ(0, memcmp(buf, "world", 5));
	close(fd);

	ATF_REQUIRE_EQ(0, tzfs_unmount(zfd));
	close(dirfd);
	close(zfd);
}
ATF_TC_CLEANUP(mount_dirfd_io, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(unmount_revokes);
ATF_TC_HEAD(unmount_revokes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ZFD_UNMOUNT forcibly revokes the dirfd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unmount_revokes, tc)
{
	char ds[256];
	int zfd, dirfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(zfd >= 0);
	dirfd = tzfs_mount(zfd, false);
	ATF_REQUIRE(dirfd >= 0);

	ATF_REQUIRE_EQ(0, tzfs_unmount(zfd));
	ATF_REQUIRE_EQ(-1, openat(dirfd, "x", O_CREAT | O_RDWR, 0644));
	ATF_REQUIRE(anon_mount_count() != 0);

	/* Second unmount reports nothing mounted. */
	ATF_REQUIRE_ERRNO(ENOENT, tzfs_unmount(zfd) == -1);

	close(dirfd);
	close(zfd);
}
ATF_TC_CLEANUP(unmount_revokes, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(close_unmounts);
ATF_TC_HEAD(close_unmounts, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "closing the anchoring handle unmounts");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_unmounts, tc)
{
	char ds[256];
	int zfd, dirfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(zfd >= 0);
	dirfd = tzfs_mount(zfd, false);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE_EQ(0, anon_mount_count());

	close(zfd);
	/* Forced unmount runs from the close path. */
	ATF_REQUIRE(anon_mount_count() != 0);
	ATF_REQUIRE_EQ(-1, openat(dirfd, "y", O_CREAT | O_RDWR, 0644));
	close(dirfd);
}
ATF_TC_CLEANUP(close_unmounts, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(data_persists);
ATF_TC_HEAD(data_persists, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "data written through an anonymous mount survives remount");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(data_persists, tc)
{
	char ds[256], buf[64];
	int zfd, dirfd, fd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_MOUNT, 0);
	ATF_REQUIRE(zfd >= 0);

	dirfd = tzfs_mount(zfd, false);
	ATF_REQUIRE(dirfd >= 0);
	fd = openat(dirfd, "keep.txt", O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(4, write(fd, "data", 4));
	close(fd);
	ATF_REQUIRE_EQ(0, tzfs_unmount(zfd));
	close(dirfd);

	dirfd = tzfs_mount(zfd, true);	/* read-only remount */
	ATF_REQUIRE(dirfd >= 0);
	fd = openat(dirfd, "keep.txt", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(4, read(fd, buf, sizeof(buf)));
	ATF_REQUIRE_EQ(0, memcmp(buf, "data", 4));
	close(fd);
	ATF_REQUIRE_EQ(0, tzfs_unmount(zfd));
	close(dirfd);
	close(zfd);
}
ATF_TC_CLEANUP(data_persists, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mount_dirfd_io);
	ATF_TP_ADD_TC(tp, unmount_revokes);
	ATF_TP_ADD_TC(tp, close_unmounts);
	ATF_TP_ADD_TC(tp, data_persists);
	return (atf_no_error());
}
