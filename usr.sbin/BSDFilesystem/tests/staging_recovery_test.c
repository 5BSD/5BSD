/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <trustedzfs.h>
#include "bsdfilesystem.h"
#include "zfshandle_test_helpers.h"

ATF_TC_WITH_CLEANUP(interrupted_commit_preserves_original);
ATF_TC_HEAD(interrupted_commit_preserves_original, tc)
{
	atf_tc_set_md_var(tc, "descr", "Startup staging sweep preserves the original claim after interrupted commit");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(interrupted_commit_preserves_original, tc)
{
	const char *version = "v0000000000000001";
	const char payload[] = "original claim must survive interrupted commit";
	struct bsdfilesystem_state st = {0};
	struct zfd_info_args original_info, recovered_info;
	char dataset[256], backup[BSDFILESYSTEM_NAME_MAX], readback[sizeof(payload)];
	int root, original, clone, directory, file, recovered;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/provider", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	root = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	original = tzfs_create(root, "records", ZHF_SUBTREE);
	ATF_REQUIRE(original >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(original, &original_info));
	directory = tzfs_mount(original, false);
	ATF_REQUIRE(directory >= 0);
	file = openat(directory, "payload", O_CREAT | O_EXCL | O_RDWR, 0600);
	ATF_REQUIRE(file >= 0);
	ATF_REQUIRE_EQ(sizeof(payload), write(file, payload, sizeof(payload)));
	ATF_REQUIRE_EQ(0, fsync(file));
	close(file);
	close(directory);
	ATF_REQUIRE_EQ(0, tzfs_unmount(original));
	ATF_REQUIRE_EQ(0, tzfs_snapshot(original, version));
	clone = tzfs_clone(root, original, version, version);
	ATF_REQUIRE(clone >= 0);
	ATF_REQUIRE_ERRNO(EINVAL,
	    tzfs_set_prop_string(clone, BSDFILESYSTEM_TXN_BASE_PROP, NULL) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_set_prop_string(clone, "", "value") == -1);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(clone, BSDFILESYSTEM_TXN_BASE_PROP, "records"));
	/* Actual commit sequence up to the interruption point; no ZFS stubs.
	 * Closing handles represents loss of the committing worker's anchors.
	 * This is a provider-restart boundary, not a power-loss simulation. */
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(clone, BSDFILESYSTEM_TXN_BASE_PROP, ""));
	ATF_REQUIRE_EQ(0, tzfs_promote(clone));
	snprintf(backup, sizeof(backup), "%s%s", BSDFILESYSTEM_STAGING_PREFIX, version);
	ATF_REQUIRE_EQ(0, tzfs_rename(root, "records", backup));
	close(clone);
	close(original);
	st.persistent_fd = root;
	ATF_CHECK_EQ(-1, bsdfilesystem_reap_staging(&st));
	clone = tzfs_openat(root, version, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE_MSG(clone >= 0, "startup sweep destroyed unresolved staging clone");
	close(clone);
	recovered = tzfs_openat(root, backup, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE_MSG(recovered >= 0,
	    "startup sweep destroyed the original claim at the interrupted-commit boundary: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, tzfs_info(recovered, &recovered_info));
	ATF_CHECK_EQ(original_info.zi_ds_guid, recovered_info.zi_ds_guid);
	directory = tzfs_mount(recovered, true);
	ATF_REQUIRE(directory >= 0);
	file = openat(directory, "payload", O_RDONLY);
	ATF_REQUIRE(file >= 0);
	ATF_REQUIRE_EQ(sizeof(payload), read(file, readback, sizeof(readback)));
	ATF_CHECK_EQ(0, memcmp(payload, readback, sizeof(payload)));
	close(file);
	close(directory);
	close(recovered);
	close(root);
}
ATF_TC_CLEANUP(interrupted_commit_preserves_original, tc)
{
	zht_pool_cleanup(tc);
}
/* A live mounted transaction is not disposable merely because its timestamp
 * is old. In particular, EBUSY from destroying its parent must not arrive
 * after deleting its snapshots. */
ATF_TC_WITH_CLEANUP(idle_preserves_live_transaction);
ATF_TC_HEAD(idle_preserves_live_transaction, tc)
{
	atf_tc_set_md_var(tc, "descr", "Idle sweep preserves snapshots of a live transaction");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(idle_preserves_live_transaction, tc)
{
	const char *version = "v0000000000000001";
	struct bsdfilesystem_state st = {0};
	char dataset[256];
	int root, original, clone, directory;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/provider", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	root = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	original = tzfs_create(root, "records", ZHF_SUBTREE);
	ATF_REQUIRE(original >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(original, version));
	clone = tzfs_clone(root, original, version, version);
	ATF_REQUIRE(clone >= 0);
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(clone,
	    BSDFILESYSTEM_TXN_BASE_PROP, "records"));
	directory = tzfs_mount(clone, false);
	ATF_REQUIRE(directory >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(clone, "retained"));
	st.persistent_fd = root;
	st.cfg.staging_idle_grace = 1;
	(void)bsdfilesystem_reap_idle_staging(&st);
	/* Duplicate creation must fail: the original snapshot still exists. */
	ATF_REQUIRE_ERRNO(EEXIST, tzfs_snapshot(clone, "retained") == -1);
	close(directory);
	close(clone);
	close(original);
	close(root);
}
ATF_TC_CLEANUP(idle_preserves_live_transaction, tc)
{
	zht_pool_cleanup(tc);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, interrupted_commit_preserves_original);
	ATF_TP_ADD_TC(tp, idle_preserves_live_transaction);
	return (atf_no_error());
}
