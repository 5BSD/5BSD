/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <trustedzfs.h>
#include "zfshandle_test_helpers.h"

ATF_TC_WITH_CLEANUP(hold_results);
ATF_TC_HEAD(hold_results, tc)
{
	atf_tc_set_md_var(tc, "descr", "Single-snapshot hold/release reports per-object errors and enforces retention");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(hold_results, tc)
{
	int root, claim;

	zht_require(tc);
	zht_pool_create(tc);
	root = tzfs_open(zht_pool, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	claim = tzfs_create(root, "records", ZHF_SUBTREE);
	ATF_REQUIRE(claim >= 0);
	ATF_CHECK_ERRNO(ENOENT, tzfs_hold(claim, "missing", "recovery") == -1);
	ATF_CHECK_ERRNO(ENOENT, tzfs_release(claim, "missing", "recovery") == -1);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(claim, "saved"));
	ATF_CHECK_ERRNO(ENOENT, tzfs_release(claim, "saved", "missing") == -1);
	ATF_REQUIRE_EQ(0, tzfs_hold(claim, "saved", "recovery"));
	ATF_CHECK_ERRNO(EEXIST, tzfs_hold(claim, "saved", "recovery") == -1);
	ATF_CHECK_ERRNO(EBUSY, tzfs_snap_destroy(claim, "saved") == -1);
	ATF_REQUIRE_EQ(0, tzfs_release(claim, "saved", "recovery"));
	ATF_CHECK_ERRNO(ENOENT, tzfs_release(claim, "saved", "recovery") == -1);
	ATF_REQUIRE_EQ(0, tzfs_snap_destroy(claim, "saved"));
	ATF_CHECK_ERRNO(ENOENT, tzfs_hold(claim, "saved", "recovery") == -1);
	close(claim);
	close(root);
}
ATF_TC_CLEANUP(hold_results, tc)
{
	zht_pool_cleanup(tc);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hold_results);
	return (atf_no_error());
}
