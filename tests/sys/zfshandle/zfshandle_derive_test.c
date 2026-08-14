/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS derivation tests: DERIVE only narrows, OPENAT stays inside the
 * grant, subtree and snapshot-of-self semantics.
 */

#include "zfshandle_test_helpers.h"

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

ATF_TC_WITH_CLEANUP(derive_narrows);
ATF_TC_HEAD(derive_narrows, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Derived handle has only requested rights; parent keeps its own");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(derive_narrows, tc)
{
	struct zfd_info_args info;
	char ds[256];
	int fd, dfd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY | ZH_PROPS_WRITE,
	    0);

	dfd = zfd_derive(fd, ZH_SNAPSHOT);
	ATF_REQUIRE(dfd >= 0);
	ATF_REQUIRE_EQ(0, zfd_info(dfd, &info));
	ATF_REQUIRE_EQ(ZH_SNAPSHOT | ZH_IMPLICIT_RIGHTS, info.zi_rights);

	ATF_REQUIRE_EQ(0, zfd_snapshot(dfd, "s1"));
	ATF_REQUIRE_ERRNO(EPERM, zfd_set_prop_str(dfd, "zht:k", "v") == -1);
	ATF_REQUIRE_ERRNO(EPERM, zfd_snap_destroy(dfd, "s1") == -1);

	/* Parent unaffected. */
	ATF_REQUIRE_EQ(0, zfd_snap_destroy(fd, "s1"));
	ATF_REQUIRE_EQ(0, zfd_set_prop_str(fd, "zht:k", "v"));

	close(dfd);
	close(fd);
}
ATF_TC_CLEANUP(derive_narrows, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(derive_cannot_widen);
ATF_TC_HEAD(derive_cannot_widen, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Deriving more rights than held fails with ENOTCAPABLE");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(derive_cannot_widen, tc)
{
	char ds[256];
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);

	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    zfd_derive(fd, ZH_SNAPSHOT | ZH_ROLLBACK) == -1);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    zfd_derive(fd, ZH_DESTROY) == -1);
	/* Re-deriving what we hold (or less) is fine. */
	ATF_REQUIRE(zfd_derive(fd, 0) >= 0);

	close(fd);
}
ATF_TC_CLEANUP(derive_cannot_widen, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(openat_subtree);
ATF_TC_HEAD(openat_subtree, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "OPENAT descends only through subtree handles and only downward");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(openat_subtree, tc)
{
	struct zfd_info_args info;
	char ds[256], child[256];
	int fd, cfd;

	zht_setup(tc, ds, sizeof(ds));
	snprintf(child, sizeof(child), "%s/child", ds);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", child));

	/* Non-subtree handle cannot descend. */
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    zfd_openat(fd, "child", ZH_SNAPSHOT, 0) == -1);
	close(fd);

	/* Subtree handle can. */
	fd = zht_open_req(ds, ZH_SNAPSHOT, ZHF_SUBTREE);
	cfd = zfd_openat(fd, "child", ZH_SNAPSHOT, 0);
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE_EQ(0, zfd_info(cfd, &info));
	ATF_REQUIRE_STREQ(child, info.zi_name);
	ATF_REQUIRE_EQ(0, zfd_snapshot(cfd, "cs"));
	close(cfd);

	/* Rights cannot grow across openat. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    zfd_openat(fd, "child", ZH_SNAPSHOT | ZH_DESTROY, 0) == -1);

	/* Escapes are rejected. */
	ATF_REQUIRE_ERRNO(EINVAL,
	    zfd_openat(fd, "..", ZH_SNAPSHOT, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zfd_openat(fd, "/other", ZH_SNAPSHOT, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zfd_openat(fd, "child/../../etc", ZH_SNAPSHOT, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zfd_openat(fd, "", ZH_SNAPSHOT, 0) == -1);

	close(fd);
}
ATF_TC_CLEANUP(openat_subtree, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(openat_snapshot_self);
ATF_TC_HEAD(openat_snapshot_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "\"@snap\" of self opens without a subtree grant");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(openat_snapshot_self, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args st;
	char ds[256], snapname[256];
	int fd, sfd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE_EQ(0, zfd_snapshot(fd, "s1"));

	sfd = zfd_openat(fd, "@s1", 0, 0);
	ATF_REQUIRE(sfd >= 0);
	ATF_REQUIRE_EQ(0, zfd_info(sfd, &info));
	snprintf(snapname, sizeof(snapname), "%s@s1", ds);
	ATF_REQUIRE_STREQ(snapname, info.zi_name);
	ATF_REQUIRE_EQ(0, zfd_stat(sfd, &st));

	close(sfd);
	close(fd);
}
ATF_TC_CLEANUP(openat_snapshot_self, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, derive_narrows);
	ATF_TP_ADD_TC(tp, derive_cannot_widen);
	ATF_TP_ADD_TC(tp, openat_subtree);
	ATF_TP_ADD_TC(tp, openat_snapshot_self);
	return (atf_no_error());
}
