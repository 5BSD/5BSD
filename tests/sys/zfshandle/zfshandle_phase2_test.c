/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS Phase 2 tests, driven through libtrustedzfs: dataset
 * lifecycle (create/rename/clone/destroy), replication streams, holds,
 * and the zvol block bridge.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

#define	PARENT_RIGHTS	(ZH_CREATE | ZH_DESTROY | ZH_SNAPSHOT | \
	ZH_SNAP_DESTROY | ZH_CLONE_SRC | ZH_SEND | ZH_RECV | ZH_HOLD | \
	ZH_RELEASE | ZH_MOUNT | ZH_ROLLBACK | ZH_PROPS_WRITE | ZH_RENAME)

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

ATF_TC_WITH_CLEANUP(lifecycle);
ATF_TC_HEAD(lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "create/snapshot/clone/rename/destroy through handles");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(lifecycle, tc)
{
	struct zfd_info_args info;
	char ds[256], want[256];
	int pfd, cfd, clfd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);

	/* Create a child; the returned handle carries parent rights. */
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE_MSG(cfd >= 0, "create: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_info(cfd, &info));
	snprintf(want, sizeof(want), "%s/child", ds);
	ATF_REQUIRE_STREQ(want, info.zi_name);

	/* Snapshot it and clone from the snapshot (two-handle op). */
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "base"));
	clfd = tzfs_clone(pfd, cfd, "base", "clone1");
	ATF_REQUIRE_MSG(clfd >= 0, "clone: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_info(clfd, &info));
	snprintf(want, sizeof(want), "%s/clone1", ds);
	ATF_REQUIRE_STREQ(want, info.zi_name);

	/* Rename the child via the parent; its handle follows. */
	ATF_REQUIRE_EQ(0, tzfs_rename(pfd, "child", "child2"));
	ATF_REQUIRE_EQ(0, tzfs_info(cfd, &info));
	snprintf(want, sizeof(want), "%s/child2", ds);
	ATF_REQUIRE_STREQ(want, info.zi_name);

	/* Teardown in dependency order, self-destroy via each handle. */
	ATF_REQUIRE_EQ(0, tzfs_destroy(clfd, NULL));
	ATF_REQUIRE_EQ(0, tzfs_snap_destroy(cfd, "base"));
	ATF_REQUIRE_EQ(0, tzfs_destroy(cfd, NULL));
	ATF_REQUIRE_EQ(0, tzfs_info(cfd, &info));
	ATF_REQUIRE_EQ(0, info.zi_valid);

	close(clfd);
	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(lifecycle, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(phase2_rights);
ATF_TC_HEAD(phase2_rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Phase 2 verbs are gated on their rights");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(phase2_rights, tc)
{
	char ds[256];
	int pfd, weak, cfd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "s"));

	/* No ZH_CREATE: create and clone-destination refused. */
	weak = tzfs_open(ds, ZH_SNAPSHOT, ZHF_SUBTREE);
	ATF_REQUIRE(weak >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_create(weak, "nope", 0) == -1);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_clone(weak, cfd, "s", "nope") == -1);
	close(weak);

	/* Origin without ZH_CLONE_SRC refused. */
	weak = tzfs_derive(cfd, ZH_SNAPSHOT);
	ATF_REQUIRE(weak >= 0);
	ATF_REQUIRE_ERRNO(EPERM, tzfs_clone(pfd, weak, "s", "nope") == -1);
	close(weak);

	/* No ZH_SEND. */
	weak = tzfs_derive(cfd, 0);
	ATF_REQUIRE(weak >= 0);
	ATF_REQUIRE_ERRNO(EPERM,
	    tzfs_send(weak, "s", NULL, STDOUT_FILENO, 0) == -1);
	close(weak);

	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(phase2_rights, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(stream_roundtrip);
ATF_TC_HEAD(stream_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "send to a file, recv it back, full + incremental");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(stream_roundtrip, tc)
{
	char ds[256];
	int pfd, cfd, rfd, filefd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "s1"));

	/* Full stream out... */
	filefd = open("stream.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(filefd >= 0);
	ATF_REQUIRE_MSG(tzfs_send(cfd, "s1", NULL, filefd, 0) == 0,
	    "send: %s", strerror(errno));

	/* ...and back in as a new child. */
	ATF_REQUIRE(lseek(filefd, 0, SEEK_SET) == 0);
	ATF_REQUIRE_MSG(tzfs_recv(pfd, "restored@s1", filefd, false) == 0,
	    "recv: %s", strerror(errno));
	close(filefd);

	/*
	 * A received snapshot keeps the sender's snapshot guid — guid
	 * equality proves the stream carried the real dataset.  (User
	 * properties do NOT travel in bare streams; that is zfs send -p
	 * userland behavior, so they cannot be used as the witness.)
	 */
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "[ \"$(zfs get -H -o value guid %s/child@s1)\" = "
	    "\"$(zfs get -H -o value guid %s/restored@s1)\" ]", ds, ds));

	/* Incremental on top. */
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "s2"));
	filefd = open("incr.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(filefd >= 0);
	ATF_REQUIRE_MSG(tzfs_send(cfd, "s2", "s1", filefd, 0) == 0,
	    "incremental send: %s", strerror(errno));
	ATF_REQUIRE(lseek(filefd, 0, SEEK_SET) == 0);
	ATF_REQUIRE_MSG(tzfs_recv(pfd, "restored@s2", filefd, false) == 0,
	    "incremental recv: %s", strerror(errno));
	close(filefd);

	ATF_REQUIRE_EQ(0, zht_systemf(
	    "[ \"$(zfs get -H -o value guid %s/child@s2)\" = "
	    "\"$(zfs get -H -o value guid %s/restored@s2)\" ]", ds, ds));

	rfd = tzfs_openat(pfd, "restored", 0, 0);
	ATF_REQUIRE(rfd >= 0);
	close(rfd);
	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(stream_roundtrip, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(holds);
ATF_TC_HEAD(holds, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a held snapshot cannot be destroyed until released");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(holds, tc)
{
	char ds[256];
	int pfd, cfd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "s1"));

	ATF_REQUIRE_MSG(tzfs_hold(cfd, "s1", "zht-tag") == 0,
	    "hold: %s", strerror(errno));
	ATF_REQUIRE_ERRNO(EBUSY, tzfs_snap_destroy(cfd, "s1") == -1);
	ATF_REQUIRE_MSG(tzfs_release(cfd, "s1", "zht-tag") == 0,
	    "release: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_snap_destroy(cfd, "s1"));

	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(holds, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(zvol_bridge);
ATF_TC_HEAD(zvol_bridge, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "create a volume, write/read via blkopen, snapshot+rollback");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(zvol_bridge, tc)
{
	char ds[256], buf[8192], chk[8192];
	int pfd, vfd, bfd, tries;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);

	vfd = tzfs_create_volume(pfd, "vol0", 16 * 1024 * 1024, 0);
	ATF_REQUIRE_MSG(vfd >= 0, "create_volume: %s", strerror(errno));

	/* The devfs node materializes asynchronously; retry briefly. */
	bfd = -1;
	for (tries = 0; tries < 50 && bfd < 0; tries++) {
		bfd = tzfs_blkopen(vfd, true);
		if (bfd < 0)
			usleep(100000);
	}
	ATF_REQUIRE_MSG(bfd >= 0, "blkopen: %s", strerror(errno));

	memset(buf, 0xA5, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf),
	    pwrite(bfd, buf, sizeof(buf), 0));
	ATF_REQUIRE_EQ((ssize_t)sizeof(chk),
	    pread(bfd, chk, sizeof(chk), 0));
	ATF_REQUIRE_EQ(0, memcmp(buf, chk, sizeof(buf)));

	/* Snapshot, scribble, roll back, expect the original pattern. */
	ATF_REQUIRE_EQ(0, fsync(bfd));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(vfd, "clean"));
	memset(buf, 0x5A, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf),
	    pwrite(bfd, buf, sizeof(buf), 0));
	ATF_REQUIRE_EQ(0, fsync(bfd));
	close(bfd);

	ATF_REQUIRE_MSG(tzfs_rollback(vfd, "clean") == 0,
	    "rollback: %s", strerror(errno));

	bfd = -1;
	for (tries = 0; tries < 50 && bfd < 0; tries++) {
		bfd = tzfs_blkopen(vfd, false);
		if (bfd < 0)
			usleep(100000);
	}
	ATF_REQUIRE(bfd >= 0);
	memset(buf, 0xA5, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)sizeof(chk),
	    pread(bfd, chk, sizeof(chk), 0));
	ATF_REQUIRE_EQ(0, memcmp(buf, chk, sizeof(buf)));
	close(bfd);

	close(vfd);
	close(pfd);
}
ATF_TC_CLEANUP(zvol_bridge, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lifecycle);
	ATF_TP_ADD_TC(tp, phase2_rights);
	ATF_TP_ADD_TC(tp, stream_roundtrip);
	ATF_TP_ADD_TC(tp, holds);
	ATF_TP_ADD_TC(tp, zvol_bridge);
	return (atf_no_error());
}
