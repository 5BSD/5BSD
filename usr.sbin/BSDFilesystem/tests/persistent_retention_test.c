/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the actual reclamation callbacks against private ZFS datasets. */
#include <sys/types.h>
#include <trustedzfs.h>
#include "../layout.c"
#include "zfshandle_test_helpers.h"

static void
check_retention(const atf_tc_t *tc, bool group, bool startup, bool empty_groups)
{
	const char payload[] = "retained generation still owns this data";
	struct bsdfilesystem_state st = {0};
	struct capreclaim r = CAPRECLAIM_INIT;
	struct capreclaim_stats stats;
	struct zfd_info_args before, after;
	char dataset[256], data[sizeof(payload)];
	int root, parent, claim, directory, file, catalogue;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/provider", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	root = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	parent = group ? tzfs_create(root, BSDFILESYSTEM_SHARED_DIR, ZHF_SUBTREE) : dup(root);
	ATF_REQUIRE(parent >= 0);
	claim = tzfs_create(parent, "retired", ZHF_SUBTREE);
	ATF_REQUIRE(claim >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(claim, &before));
	directory = tzfs_mount(claim, false);
	ATF_REQUIRE(directory >= 0);
	file = openat(directory, "payload", O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(file >= 0);
	ATF_REQUIRE_EQ(sizeof(payload), write(file, payload, sizeof(payload)));
	ATF_REQUIRE_EQ(0, fsync(file));
	close(file);
	close(directory);
	ATF_REQUIRE_EQ(0, tzfs_unmount(claim));
	close(claim);

	ATF_REQUIRE_EQ(0, mkdir("catalogue", 0700));
	/* Bundle cases use an unrelated live owner to avoid the empty-set floor.
	 * Group cases also exercise the production allow_empty_live policy.
	 * Neither a boot pass nor repeated absence supplies deletion authority. */
	if (!empty_groups)
		ATF_REQUIRE_EQ(0, mkdir(group ? "catalogue/keeper" :
		    "catalogue/keeper.cap", 0700));
	catalogue = open("catalogue", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(catalogue >= 0);
	st.persistent_fd = root;
	r.enumerate = group ? groups_enumerate : persistent_enumerate;
	r.destroy = group ? groups_destroy : persistent_destroy;
	r.arg = &st;
	r.stats = &stats;
	r.sources[0].fd = catalogue;
	r.sources[0].strip_cap = !group;
	r.allow_empty_live = group;
	r.nsources = 1;
	if (!startup) {
		ATF_REQUIRE_EQ(0, capreclaim_run(&r, CAPRECLAIM_TIMER));
		ATF_REQUIRE(!stats.floored);
		ATF_REQUIRE_EQ(1, stats.norphans);
		ATF_REQUIRE_EQ(0, stats.ndestroyed);
	}
	ATF_REQUIRE(capreclaim_run(&r, startup ? CAPRECLAIM_BOOT : CAPRECLAIM_TIMER) >= 0);
	ATF_REQUIRE(!stats.floored);
	ATF_REQUIRE_EQ(empty_groups ? 0 : 1, stats.nlive);
	ATF_REQUIRE_EQ(1, stats.nowned);
	ATF_REQUIRE_EQ(1, stats.norphans);
	ATF_CHECK_EQ(0, stats.ndestroyed);
	claim = tzfs_openat(parent, "retired", ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE_MSG(claim >= 0, "catalogue absence destroyed retained state: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_info(claim, &after));
	ATF_CHECK_EQ(before.zi_ds_guid, after.zi_ds_guid);
	directory = tzfs_mount(claim, true);
	ATF_REQUIRE(directory >= 0);
	file = openat(directory, "payload", O_RDONLY);
	ATF_REQUIRE(file >= 0);
	ATF_REQUIRE_EQ(sizeof(payload), read(file, data, sizeof(data)));
	ATF_CHECK_EQ(0, memcmp(payload, data, sizeof(payload)));
	close(file);
	close(directory);
	close(claim);
	capreclaim_fini(&r);
	close(catalogue);
	close(parent);
	close(root);
}

#define RETENTION_CASE(name, group, startup, empty_groups) \
ATF_TC_WITH_CLEANUP(name); \
ATF_TC_HEAD(name, tc) { \
	atf_tc_set_md_var(tc, "require.user", "root"); \
	atf_tc_set_md_var(tc, "timeout", "180"); \
} \
ATF_TC_BODY(name, tc) { check_retention(tc, group, startup, empty_groups); } \
ATF_TC_CLEANUP(name, tc) { zht_pool_cleanup(tc); }

RETENTION_CASE(bundle_timer_retention, false, false, false)
RETENTION_CASE(bundle_startup_retention, false, true, false)
RETENTION_CASE(group_timer_retention, true, false, false)
RETENTION_CASE(group_startup_retention, true, true, false)

RETENTION_CASE(empty_group_timer_retention, true, false, true)
RETENTION_CASE(empty_group_startup_retention, true, true, true)

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bundle_timer_retention);
	ATF_TP_ADD_TC(tp, bundle_startup_retention);
	ATF_TP_ADD_TC(tp, group_timer_retention);
	ATF_TP_ADD_TC(tp, group_startup_retention);
	ATF_TP_ADD_TC(tp, empty_group_timer_retention);
	ATF_TP_ADD_TC(tp, empty_group_startup_retention);
	return (atf_no_error());
}
