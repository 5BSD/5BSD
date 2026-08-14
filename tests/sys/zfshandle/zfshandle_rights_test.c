/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS rights-matrix tests: every gated verb succeeds exactly when the
 * handle carries the corresponding right, implicit rights always work, and
 * non-handle fds are rejected.
 */

#include <sys/eventfd.h>

#include "zfshandle_test_helpers.h"

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

ATF_TC_WITH_CLEANUP(implicit_rights);
ATF_TC_HEAD(implicit_rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A zero-rights handle can inspect but not mutate");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(implicit_rights, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args st;
	char ds[256], buf[65536];
	uint64_t size;
	int fd;

	zht_setup(tc, ds, sizeof(ds));
	fd = zht_open_req(ds, 0, 0);

	/* Implicit: INFO, STAT, GET_PROPS. */
	ATF_REQUIRE_EQ(0, zfd_info(fd, &info));
	ATF_REQUIRE_EQ(1, info.zi_valid);
	ATF_REQUIRE_STREQ(ds, info.zi_name);
	ATF_REQUIRE((info.zi_rights & ZH_PROPS_READ) != 0);
	ATF_REQUIRE((info.zi_rights & ZH_EVENT) != 0);
	ATF_REQUIRE_EQ(0, zfd_stat(fd, &st));
	ATF_REQUIRE(st.zs_ds_guid == info.zi_ds_guid);
	ATF_REQUIRE_EQ(0, zfd_get_props(fd, buf, sizeof(buf), &size));
	ATF_REQUIRE(size > 0);

	/* Every gated verb must fail with EPERM. */
	ATF_REQUIRE_ERRNO(EPERM, zfd_snapshot(fd, "s1") == -1);
	ATF_REQUIRE_ERRNO(EPERM, zfd_snap_destroy(fd, "s1") == -1);
	ATF_REQUIRE_ERRNO(EPERM, zfd_rollback(fd, NULL) == -1);
	ATF_REQUIRE_ERRNO(EPERM, zfd_set_prop_str(fd, "zht:k", "v") == -1);

	close(fd);
}
ATF_TC_CLEANUP(implicit_rights, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(right_gates_verb);
ATF_TC_HEAD(right_gates_verb, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Each verb succeeds with its right and fails without it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(right_gates_verb, tc)
{
	char ds[256];
	int fd;

	zht_setup(tc, ds, sizeof(ds));

	/* ZH_SNAPSHOT */
	fd = zht_open_req(ds, ZH_SNAPSHOT, 0);
	ATF_REQUIRE_EQ(0, zfd_snapshot(fd, "s1"));
	ATF_REQUIRE_ERRNO(EPERM, zfd_snap_destroy(fd, "s1") == -1);
	close(fd);

	/* ZH_ROLLBACK (to the snapshot just taken) */
	fd = zht_open_req(ds, ZH_ROLLBACK, 0);
	ATF_REQUIRE_EQ(0, zfd_rollback(fd, "s1"));
	ATF_REQUIRE_ERRNO(EPERM, zfd_snapshot(fd, "s2") == -1);
	close(fd);

	/* ZH_SNAP_DESTROY */
	fd = zht_open_req(ds, ZH_SNAP_DESTROY, 0);
	ATF_REQUIRE_EQ(0, zfd_snap_destroy(fd, "s1"));
	ATF_REQUIRE_ERRNO(EPERM, zfd_snapshot(fd, "s2") == -1);
	close(fd);

	/* ZH_PROPS_WRITE */
	fd = zht_open_req(ds, ZH_PROPS_WRITE, 0);
	ATF_REQUIRE_EQ(0, zfd_set_prop_str(fd, "zht:key", "val"));
	ATF_REQUIRE_ERRNO(EPERM, zfd_rollback(fd, NULL) == -1);
	close(fd);

	/* Verify the property landed via the CLI. */
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs get -H -o value zht:key %s | grep -qx val", ds));
}
ATF_TC_CLEANUP(right_gates_verb, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(mint_validation);
ATF_TC_HEAD(mint_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Minting rejects bad rights, bad names, missing datasets");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_validation, tc)
{
	char ds[256];

	zht_setup(tc, ds, sizeof(ds));

	ATF_REQUIRE_ERRNO(EINVAL,
	    zht_open(ds, ~0ULL, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zht_open(ds, 0, 0xdead0000) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zht_open("", 0, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
	    zht_open("not/a//valid name", 0, 0) == -1);
	ATF_REQUIRE_ERRNO(ENOENT,
	    zht_open("zht_nonexistent_pool_xyzzy/none", 0, 0) == -1);
}
ATF_TC_CLEANUP(mint_validation, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC(forged_fd);
ATF_TC_HEAD(forged_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ZFD verbs on non-handle fds are rejected");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(forged_fd, tc)
{
	struct zfd_info_args info;
	int efd;

	zht_require(tc);
	efd = eventfd(0, 0);
	ATF_REQUIRE(efd >= 0);
	ATF_REQUIRE_ERRNO(ENOTTY, zfd_info(efd, &info) == -1);
	close(efd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, implicit_rights);
	ATF_TP_ADD_TC(tp, right_gates_verb);
	ATF_TP_ADD_TC(tp, mint_validation);
	ATF_TP_ADD_TC(tp, forged_fd);
	return (atf_no_error());
}
