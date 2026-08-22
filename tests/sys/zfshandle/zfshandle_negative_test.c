/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS negative tests: the failure paths a capability system lives
 * or dies by.  Every gated verb must refuse without its right, every
 * argument boundary must be enforced, cross-type verbs must be rejected,
 * containment must not be escapable, type mismatches must fail, and a
 * dead/consumed handle must refuse everything.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

#define	ALL_DS_RIGHTS	(ZH_PROPS_WRITE | ZH_SNAPSHOT | ZH_SNAP_DESTROY | \
	ZH_ROLLBACK | ZH_CLONE_SRC | ZH_CREATE | ZH_DESTROY | ZH_SEND | \
	ZH_RECV | ZH_MOUNT | ZH_HOLD | ZH_RENAME | ZH_PROMOTE | \
	ZH_BOOKMARK | ZH_RELEASE)

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

/*
 * Each gated verb, exercised through a handle that holds EVERY right
 * EXCEPT the one it needs -- so a missing rights check anywhere shows up
 * as a verb that unexpectedly succeeds.
 */
ATF_TC_WITH_CLEANUP(missing_right_refused);
ATF_TC_HEAD(missing_right_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "every gated verb fails with EPERM when its right is absent");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(missing_right_refused, tc)
{
	char ds[256];
	int fd, cfd;

	zht_setup(tc, ds, sizeof(ds));
	/* A child + snapshot to operate on. */
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/c", ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs snapshot %s@s", ds));

#define	WITHOUT(right)	tzfs_open(ds, ALL_DS_RIGHTS & ~(right), ZHF_SUBTREE)
	/* PROPS_WRITE gates set and inherit. */
	fd = WITHOUT(ZH_PROPS_WRITE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_set_prop_string(fd, "zht:k", "v") == -1);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_inherit(fd, "zht:k", false) == -1);
	close(fd);

	/* SNAPSHOT gates snapshot only. */
	fd = WITHOUT(ZH_SNAPSHOT);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_snapshot(fd, "n") == -1);
	close(fd);

	fd = WITHOUT(ZH_BOOKMARK);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_bookmark(fd, "s", "b") == -1);
	close(fd);

	/* SNAP_DESTROY gates snap-destroy and bookmark-destroy. */
	fd = WITHOUT(ZH_SNAP_DESTROY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_snap_destroy(fd, "s") == -1);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_destroy_bookmark(fd, "b") == -1);
	close(fd);

	fd = WITHOUT(ZH_ROLLBACK);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_rollback(fd, "s") == -1);
	close(fd);

	fd = WITHOUT(ZH_CREATE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_create(fd, "nope", 0) == -1);
	close(fd);

	fd = WITHOUT(ZH_PROMOTE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_promote(fd) == -1);
	close(fd);

	fd = WITHOUT(ZH_DESTROY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_destroy(fd, "c") == -1);
	close(fd);

	fd = WITHOUT(ZH_RENAME);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_rename(fd, "c", "renamed") == -1);
	close(fd);

	fd = WITHOUT(ZH_SEND);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM,
	    tzfs_send(fd, "s", NULL, STDOUT_FILENO, 0) == -1);
	close(fd);

	fd = WITHOUT(ZH_HOLD);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_hold(fd, "s", "t") == -1);
	close(fd);

	fd = WITHOUT(ZH_RELEASE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_release(fd, "s", "t") == -1);
	close(fd);

	/* CLONE_SRC on the origin: a full-rights dest, origin lacking it. */
	fd = tzfs_open(ds, ALL_DS_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);
	cfd = tzfs_open(ds, ZH_SNAPSHOT, ZHF_SUBTREE);	/* no CLONE_SRC */
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_clone(fd, cfd, "s", "cl") == -1);
	close(cfd);
	close(fd);
#undef WITHOUT
}
ATF_TC_CLEANUP(missing_right_refused, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(bad_arguments);
ATF_TC_HEAD(bad_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "argument boundaries: empty, oversized, wrong separators");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bad_arguments, tc)
{
	char ds[256], huge[ZFSHANDLE_NAME_MAX + 64];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ALL_DS_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);

	/* Empty required names. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_snapshot(fd, "") == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_get_one_prop(fd, "", NULL, 0, NULL,
	    NULL, NULL) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_create(fd, "", 0) == -1);

	/* A snapshot component may not itself contain '@'. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_snapshot(fd, "a@b") == -1);
	/* A child name may not contain '@'. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_create(fd, "a@b", 0) == -1);

	/* Oversized name is caught at the library boundary. */
	memset(huge, 'x', sizeof(huge) - 1);
	huge[sizeof(huge) - 1] = '\0';
	ATF_REQUIRE_ERRNO(ENAMETOOLONG, tzfs_snapshot(fd, huge) == -1);

	close(fd);

	/* Minting rejects bad rights and flags. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_open(ds, ~0ULL, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_open(ds, 0, 0x8000) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_open("", 0, 0) == -1);
}
ATF_TC_CLEANUP(bad_arguments, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(containment_escape);
ATF_TC_HEAD(containment_escape, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "openat cannot escape the subtree grant");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(containment_escape, tc)
{
	char ds[256];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/c", ds));
	fd = tzfs_open(ds, ZH_SNAPSHOT, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);

	/* Every escape vector is rejected before resolution. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_openat(fd, "..", 0, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_openat(fd, "/abs", 0, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_openat(fd, "c/../..", 0, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_openat(fd, "", 0, 0) == -1);
	/* Rights cannot grow across openat. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    tzfs_openat(fd, "c", ZH_DESTROY, 0) == -1);
	/* A non-subtree handle cannot descend at all. */
	close(fd);
	fd = tzfs_open(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, tzfs_openat(fd, "c", 0, 0) == -1);
	close(fd);
}
ATF_TC_CLEANUP(containment_escape, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(type_mismatch);
ATF_TC_HEAD(type_mismatch, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "filesystem/volume/pool verbs reject the wrong object type");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(type_mismatch, tc)
{
	struct zpd_stat_args pst;
	struct zfd_stat_args dst;
	char ds[256];
	int fd, vfd, zpd, tries, bfd;

	zht_setup(tc, ds, sizeof(ds));
	fd = tzfs_open(ds, ALL_DS_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);

	/* blkopen on a filesystem is ENOTBLK. */
	ATF_REQUIRE_ERRNO(ENOTBLK, tzfs_blkopen(fd, false) == -1);

	/* mount on a volume is EINVAL (only ZPL filesystems mount). */
	vfd = tzfs_create_volume(fd, "vol", 8 * 1024 * 1024, 0);
	ATF_REQUIRE(vfd >= 0);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_mount(vfd, false) == -1);
	/* ...but blkopen on that volume works (positive control). */
	bfd = -1;
	for (tries = 0; tries < 50 && bfd < 0; tries++) {
		bfd = tzfs_blkopen(vfd, false);
		if (bfd < 0)
			usleep(100000);
	}
	ATF_REQUIRE(bfd >= 0);
	close(bfd);
	close(vfd);

	/* Cross-plane: pool verb on a dataset handle and vice versa. */
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_pool_stat(fd, &pst) == -1);
	close(fd);

	zpd = tzfs_pool_open(zht_pool, 0);
	ATF_REQUIRE(zpd >= 0);
	ATF_REQUIRE_ERRNO(EINVAL, zfd_stat(zpd, &dst) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_snapshot(zpd, "x") == -1);
	close(zpd);
}
ATF_TC_CLEANUP(type_mismatch, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(dead_handle_refuses_all);
ATF_TC_HEAD(dead_handle_refuses_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a destroyed or consumed handle refuses every op with ENXIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dead_handle_refuses_all, tc)
{
	struct zfd_stat_args st;
	struct zfd_info_args info;
	char ds[256];
	void *buf;
	size_t len;
	int fd, sfd, streamfd;

	zht_setup(tc, ds, sizeof(ds));

	/* Destroyed underneath: representative verbs across categories. */
	fd = tzfs_open(ds, ALL_DS_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs destroy %s", ds));
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(fd, &st) == -1);
	ATF_REQUIRE_ERRNO(ENXIO, tzfs_snapshot(fd, "n") == -1);
	ATF_REQUIRE_ERRNO(ENXIO, tzfs_list_snapshots(fd, &buf, &len) == -1);
	ATF_REQUIRE_ERRNO(ENXIO,
	    tzfs_get_one_prop(fd, "used", NULL, 0, NULL, NULL, NULL) == -1);
	/* INFO still answers, reporting invalid. */
	ATF_REQUIRE_EQ(0, zfd_info(fd, &info));
	ATF_REQUIRE_EQ(0, info.zi_valid);
	close(fd);

	/* Consumed by ZHF_SEND_CONSUME: same dead behavior. */
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
	fd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SEND,
	    ZHF_SEND_ONCE | ZHF_SEND_CONSUME);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "s1"));
	sfd = tzfs_openat(fd, "@s1", ZH_SEND, 0);
	ATF_REQUIRE(sfd >= 0);
	streamfd = open("out.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(streamfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, streamfd, 0));
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(sfd, &st) == -1);
	ATF_REQUIRE_ERRNO(ENXIO,
	    tzfs_send(sfd, NULL, NULL, streamfd, 0) == -1);
	close(streamfd);
	close(sfd);
	close(fd);
}
ATF_TC_CLEANUP(dead_handle_refuses_all, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(wrong_fd_type);
ATF_TC_HEAD(wrong_fd_type, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "handle ioctls on a non-handle fd, and clone with a "
	    "non-handle origin, are rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wrong_fd_type, tc)
{
	struct zfd_info_args info;
	char ds[256];
	int fd, p[2];

	zht_setup(tc, ds, sizeof(ds));

	/* A pipe fd is not a handle. */
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_REQUIRE_ERRNO(ENOTTY, zfd_info(p[0], &info) == -1);

	/* Clone with a non-handle origin fd is EBADF. */
	fd = tzfs_open(ds, ALL_DS_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(fd, "s"));
	ATF_REQUIRE_ERRNO(EBADF, tzfs_clone(fd, p[0], "s", "cl") == -1);
	close(p[0]);
	close(p[1]);
	close(fd);
}
ATF_TC_CLEANUP(wrong_fd_type, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, missing_right_refused);
	ATF_TP_ADD_TC(tp, bad_arguments);
	ATF_TP_ADD_TC(tp, containment_escape);
	ATF_TP_ADD_TC(tp, type_mismatch);
	ATF_TP_ADD_TC(tp, dead_handle_refuses_all);
	ATF_TP_ADD_TC(tp, wrong_fd_type);
	return (atf_no_error());
}
