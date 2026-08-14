/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS Phase 4 tests: thin pool handles.
 */

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

ATF_TC_WITH_CLEANUP(pool_stat);
ATF_TC_HEAD(pool_stat, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ZPD_STAT reports sane guid/space/state");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pool_stat, tc)
{
	struct zpd_stat_args st;
	char ds[256];
	int zpd;

	zht_setup(tc, ds, sizeof(ds));
	zpd = tzfs_pool_open(zht_pool, 0);
	ATF_REQUIRE_MSG(zpd >= 0, "pool_open: %s", strerror(errno));

	ATF_REQUIRE_EQ(0, tzfs_pool_stat(zpd, &st));
	ATF_REQUIRE(st.zp_guid != 0);
	ATF_REQUIRE(st.zp_size > 0);
	ATF_REQUIRE(st.zp_alloc <= st.zp_size);
	ATF_REQUIRE_EQ(0, st.zp_state);	/* POOL_STATE_ACTIVE */
	close(zpd);
}
ATF_TC_CLEANUP(pool_stat, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(pool_props_bootfs);
ATF_TC_HEAD(pool_props_bootfs, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pool property writes through a handle (the oracle-init "
	    "BE-activation sliver: bootfs)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pool_props_bootfs, tc)
{
	char ds[256];
	void *buf;
	size_t len;
	int zpd;

	zht_setup(tc, ds, sizeof(ds));
	zpd = tzfs_pool_open(zht_pool, ZH_PROPS_WRITE);
	ATF_REQUIRE(zpd >= 0);

	ATF_REQUIRE_MSG(tzfs_pool_set_prop_string(zpd, "bootfs", ds) == 0,
	    "set bootfs: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zpool get -H -o value bootfs %s | grep -qx %s", zht_pool, ds));

	ATF_REQUIRE_EQ(0, tzfs_pool_get_props(zpd, &buf, &len));
	ATF_REQUIRE(len > 0);
	free(buf);
	close(zpd);
}
ATF_TC_CLEANUP(pool_props_bootfs, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(pool_rights);
ATF_TC_HEAD(pool_rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "pool verbs gate on rights; verb sets do not cross");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pool_rights, tc)
{
	struct zfd_info_args info;
	struct zpd_stat_args pst;
	struct zfd_stat_args dst;
	char ds[256];
	int zpd, zfd;

	zht_setup(tc, ds, sizeof(ds));

	/* Implicit-rights pool handle: stat yes, mutate no. */
	zpd = tzfs_pool_open(zht_pool, 0);
	ATF_REQUIRE(zpd >= 0);
	ATF_REQUIRE_EQ(0, tzfs_pool_stat(zpd, &pst));
	ATF_REQUIRE_ERRNO(EPERM,
	    tzfs_pool_set_prop_string(zpd, "comment", "x") == -1);
	ATF_REQUIRE_ERRNO(EPERM,
	    tzfs_pool_scrub(zpd, ZPD_SCRUB_START) == -1);

	/* Dataset verbs are invalid on a pool handle... */
	ATF_REQUIRE_ERRNO(EINVAL, zfd_stat(zpd, &dst) == -1);
	/* ...but the generic INFO works and reports validity. */
	ATF_REQUIRE_EQ(0, zfd_info(zpd, &info));
	ATF_REQUIRE_EQ(1, info.zi_valid);

	/* Pool verbs are invalid on a dataset handle. */
	zfd = zht_open_req(ds, 0, 0);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_pool_stat(zfd, &pst) == -1);
	close(zfd);
	close(zpd);
}
ATF_TC_CLEANUP(pool_rights, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(pool_scrub);
ATF_TC_HEAD(pool_scrub, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "scrub control through a ZH_SCRUB handle");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pool_scrub, tc)
{
	struct zpd_stat_args st;
	char ds[256];
	int zpd;

	zht_setup(tc, ds, sizeof(ds));
	zpd = tzfs_pool_open(zht_pool, ZH_SCRUB);
	ATF_REQUIRE(zpd >= 0);

	ATF_REQUIRE_MSG(tzfs_pool_scrub(zpd, ZPD_SCRUB_START) == 0,
	    "scrub start: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_pool_stat(zpd, &st));
	/* Tiny pool: the scrub may already be done; func records it ran. */
	ATF_REQUIRE(st.zp_scan_func != 0);
	(void) tzfs_pool_scrub(zpd, ZPD_SCRUB_STOP);
	close(zpd);
}
ATF_TC_CLEANUP(pool_scrub, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(root_open_bridge);
ATF_TC_HEAD(root_open_bridge, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ZPD_ROOT_OPEN bridges down to a dataset handle, one-way, "
	    "rights-limited");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(root_open_bridge, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args dst;
	char ds[256];
	int zpd, zfd;

	zht_setup(tc, ds, sizeof(ds));
	zpd = tzfs_pool_open(zht_pool, ZH_SNAPSHOT);
	ATF_REQUIRE(zpd >= 0);

	zfd = tzfs_pool_root_open(zpd, ZH_SNAPSHOT, ZHF_SUBTREE);
	ATF_REQUIRE_MSG(zfd >= 0, "root_open: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, zfd_info(zfd, &info));
	ATF_REQUIRE_STREQ(zht_pool, info.zi_name);
	ATF_REQUIRE_EQ(0, zfd_stat(zfd, &dst));
	ATF_REQUIRE_EQ(0, zfd_snapshot(zfd, "via-pool"));

	/* Rights cannot grow across the bridge. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE,
	    tzfs_pool_root_open(zpd, ZH_DESTROY, 0) == -1);

	close(zfd);
	close(zpd);
}
ATF_TC_CLEANUP(root_open_bridge, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pool_stat);
	ATF_TP_ADD_TC(tp, pool_props_bootfs);
	ATF_TP_ADD_TC(tp, pool_rights);
	ATF_TP_ADD_TC(tp, pool_scrub);
	ATF_TP_ADD_TC(tp, root_open_bridge);
	return (atf_no_error());
}
