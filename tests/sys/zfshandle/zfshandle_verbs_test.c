/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS extended-verb tests: enumeration (children/snaps/holds/
 * bookmarks), single-property get, inherit, promote, bookmarks, wait,
 * and send-once semantics.  Driven through libtrustedzfs.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

#define	PARENT_RIGHTS	(ZH_CREATE | ZH_DESTROY | ZH_SNAPSHOT | \
	ZH_SNAP_DESTROY | ZH_CLONE_SRC | ZH_SEND | ZH_HOLD | \
	ZH_ROLLBACK | ZH_PROPS_WRITE)

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

/* Count entries in a packed name-set nvlist by grepping the raw buffer. */
static int
buf_has(const void *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle);
	const char *p = buf;
	size_t i;

	if (len < nl)
		return (0);
	for (i = 0; i + nl <= len; i++)
		if (memcmp(p + i, needle, nl) == 0)
			return (1);
	return (0);
}

ATF_TC_WITH_CLEANUP(list_children);
ATF_TC_HEAD(list_children, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "list_children enumerates a subtree; needs the subtree flag");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_children, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd;

	zht_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/a", ds));
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s/b", ds));

	/* Non-subtree handle cannot enumerate. */
	zfd = tzfs_open(ds, 0, 0);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    tzfs_list_children(zfd, &buf, &len) == -1);
	close(zfd);

	zfd = tzfs_open(ds, 0, ZHF_SUBTREE);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_list_children(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s/a", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	snprintf(want, sizeof(want), "%s/b", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(list_children, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(list_snapshots);
ATF_TC_HEAD(list_snapshots, tc)
{
	atf_tc_set_md_var(tc, "descr", "list_snapshots enumerates snapshots");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_snapshots, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s2"));

	ATF_REQUIRE_EQ(0, tzfs_list_snapshots(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s@s1", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	snprintf(want, sizeof(want), "%s@s2", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(list_snapshots, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(property_triad);
ATF_TC_HEAD(property_triad, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "get one property, set it, inherit (clear) it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(property_triad, tc)
{
	char ds[256], val[256];
	uint64_t iv;
	int zfd, is_str;
	uint32_t src;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_PROPS_WRITE, 0);
	ATF_REQUIRE(zfd >= 0);

	/* A numeric read-only property (used) comes back as an int. */
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(zfd, "compression", val,
	    sizeof(val), &iv, &is_str, &src));

	/* Set a user property, read it back, then inherit-clear it. */
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(zfd, "zht:k", "hello"));
	ATF_REQUIRE_EQ(0, tzfs_get_one_prop(zfd, "zht:k", val, sizeof(val),
	    &iv, &is_str, &src));
	ATF_REQUIRE_EQ(1, is_str);
	ATF_REQUIRE_STREQ("hello", val);

	ATF_REQUIRE_EQ(0, tzfs_inherit(zfd, "zht:k", false));
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_get_one_prop(zfd, "zht:k", val, sizeof(val), &iv, &is_str,
	    &src) == -1);

	/* Missing property -> ENOENT. */
	ATF_REQUIRE_ERRNO(ENOENT,
	    tzfs_get_one_prop(zfd, "zht:absent", val, sizeof(val), &iv,
	    &is_str, &src) == -1);
	close(zfd);
}
ATF_TC_CLEANUP(property_triad, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(holds_and_bookmarks);
ATF_TC_HEAD(holds_and_bookmarks, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "enumerate holds and bookmarks; create/destroy bookmarks");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(holds_and_bookmarks, tc)
{
	char ds[256], want[256];
	void *buf;
	size_t len;
	int zfd, sfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY | ZH_HOLD,
	    ZHF_SUBTREE);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));

	/* Hold the snapshot, enumerate holds via a snapshot handle. */
	sfd = tzfs_openat(zfd, "@s1", ZH_HOLD, 0);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_hold(zfd, "s1", "keeper"));
	ATF_REQUIRE_EQ(0, tzfs_holds(sfd, &buf, &len));
	ATF_REQUIRE(buf_has(buf, len, "keeper"));
	free(buf);
	ATF_REQUIRE_EQ(0, tzfs_release(zfd, "s1", "keeper"));
	close(sfd);

	/* Bookmark the snapshot, list bookmarks, destroy it. */
	ATF_REQUIRE_MSG(tzfs_bookmark(zfd, "s1", "bm1") == 0,
	    "bookmark: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_list_bookmarks(zfd, &buf, &len));
	snprintf(want, sizeof(want), "%s#bm1", ds);
	ATF_REQUIRE(buf_has(buf, len, want));
	free(buf);
	ATF_REQUIRE_EQ(0, tzfs_destroy_bookmark(zfd, "bm1"));
	ATF_REQUIRE_EQ(0, tzfs_list_bookmarks(zfd, &buf, &len));
	ATF_REQUIRE(!buf_has(buf, len, want));
	free(buf);
	close(zfd);
}
ATF_TC_CLEANUP(holds_and_bookmarks, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(promote_clone);
ATF_TC_HEAD(promote_clone, tc)
{
	atf_tc_set_md_var(tc, "descr", "promote a clone above its origin");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(promote_clone, tc)
{
	char ds[256], clone[256];
	int pfd, cfd, clfd;

	zht_setup(tc, ds, sizeof(ds));
	pfd = tzfs_open(ds, PARENT_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(pfd >= 0);
	cfd = tzfs_create(pfd, "child", 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(cfd, "base"));
	clfd = tzfs_clone(pfd, cfd, "base", "clone1");
	ATF_REQUIRE(clfd >= 0);

	/* Before promote, the clone's origin is child@base. */
	snprintf(clone, sizeof(clone), "%s/clone1", ds);
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs get -H -o value origin %s | grep -q @base", clone));

	ATF_REQUIRE_MSG(tzfs_promote(clfd) == 0,
	    "promote: %s", strerror(errno));
	/* After promote, the clone has no origin. */
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs get -H -o value origin %s | grep -qx -", clone));

	close(clfd);
	close(cfd);
	close(pfd);
}
ATF_TC_CLEANUP(promote_clone, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(send_once);
ATF_TC_HEAD(send_once, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "send-once: keep-open-but-unsendable vs consume");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(send_once, tc)
{
	struct zfd_stat_args st;
	char ds[256];
	int zfd, sfd, fd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = tzfs_open(ds, ZH_SNAPSHOT | ZH_SEND, 0);
	ATF_REQUIRE(zfd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(zfd, "s1"));

	/* Case ONCE: after one send, further sends fail; handle stays valid. */
	sfd = tzfs_openat(zfd, "@s1", ZH_SEND, 0);
	ATF_REQUIRE(sfd >= 0);
	fd = open("stream1.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, fd, ZFD_SEND_ONCE));
	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	ATF_REQUIRE_ERRNO(EALREADY,
	    tzfs_send(sfd, NULL, NULL, fd, 0) == -1);
	/* Still valid for other ops. */
	ATF_REQUIRE_EQ(0, zfd_stat(sfd, &st));
	close(fd);
	close(sfd);

	/* Case ONCE|CONSUME: the handle is invalidated after the send. */
	sfd = tzfs_openat(zfd, "@s1", ZH_SEND, 0);
	ATF_REQUIRE(sfd >= 0);
	fd = open("stream2.zfs", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_send(sfd, NULL, NULL, fd,
	    ZFD_SEND_ONCE | ZFD_SEND_CONSUME));
	ATF_REQUIRE_ERRNO(ENXIO, zfd_stat(sfd, &st) == -1);
	close(fd);
	close(sfd);
	close(zfd);
}
ATF_TC_CLEANUP(send_once, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, list_children);
	ATF_TP_ADD_TC(tp, list_snapshots);
	ATF_TP_ADD_TC(tp, property_triad);
	ATF_TP_ADD_TC(tp, holds_and_bookmarks);
	ATF_TP_ADD_TC(tp, promote_clone);
	ATF_TP_ADD_TC(tp, send_once);
	return (atf_no_error());
}
