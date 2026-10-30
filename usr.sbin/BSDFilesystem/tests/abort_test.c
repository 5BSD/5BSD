/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include "../request.c"
#include "zfshandle_test_helpers.h"

static bool
has_snapshot(int fd, const char *version)
{
	void *buf;
	size_t length, count;
	char **names;
	bool found = false;

	ATF_REQUIRE_EQ(0, tzfs_list_snapshots(fd, &buf, &length));
	ATF_REQUIRE_EQ(0, bsdfilesystem_nvl_names(buf, length, &names, &count));
	free(buf);
	for (size_t i = 0; i < count; i++) {
		const char *at = strchr(names[i], '@');
		ATF_REQUIRE(at != NULL);
		if (strcmp(at + 1, version) == 0)
			found = true;
	}
	bsdfilesystem_nvl_names_free(names, count);
	return (found);
}

ATF_TC_WITH_CLEANUP(abort_origin_real_zfs);
ATF_TC_HEAD(abort_origin_real_zfs, tc)
{
	atf_tc_set_md_var(tc, "descr", "Abort rejects another claim and incomplete commit, then removes its own transaction");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(abort_origin_real_zfs, tc)
{
	struct bsdfilesystem_state st = {0};
	struct tzfs_conn conn = {0};
	struct bsdfilesystem_version_request request = {0};
	struct tzfs_msg message;
	struct zfd_info_args before, after;
	char dataset[256], ns[BSDFILESYSTEM_MAXPATH];
	int root, parent, original, clone, check;

	zht_require(tc);
	zht_pool_create(tc);
	snprintf(dataset, sizeof(dataset), "%s/provider", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", dataset));
	root = tzfs_open(dataset, ZH_ALL_RIGHTS, ZHF_SUBTREE);
	ATF_REQUIRE(root >= 0);
	st.persistent_fd = root;
	strlcpy(st.cfg.persistent, dataset, sizeof(st.cfg.persistent));
	strlcpy(conn.container, "org.test.abort/client", sizeof(conn.container));
	conn_anchors_init(&conn);
	request.op = BSDFILESYSTEM_OP_TXN_ABORT;
	request.lifetime = BSDFILESYSTEM_PERSISTENT;
	request.scope = BSDFILESYSTEM_SCOPE_UNIT;
	gen_version_id(request.version, sizeof(request.version));
	ATF_REQUIRE(storage_namespace_scope(conn.container, (const char (*)[64])conn.groups,
	    request.scope, request.group, request.lifetime, ns, sizeof(ns)));
	parent = bsdfilesystem_ensure_path(root, ns, ZH_ALL_RIGHTS);
	ATF_REQUIRE(parent >= 0);
	original = tzfs_create(parent, "records", ZHF_SUBTREE);
	ATF_REQUIRE(original >= 0);
	ATF_REQUIRE_EQ(0, tzfs_snapshot(original, request.version));
	clone = tzfs_clone(parent, original, request.version, request.version);
	ATF_REQUIRE(clone >= 0);
	ATF_REQUIRE_EQ(0, tzfs_info(clone, &before));
	ATF_REQUIRE_EQ(0, tzfs_set_prop_string(clone,
	    BSDFILESYSTEM_TXN_BASE_PROP, "records"));
	close(clone);

	for (unsigned i = 0; i < 3; i++) {
		strlcpy(request.dataset, i == 0 ? "other" : "records",
		    sizeof(request.dataset));
		if (i != 0) {
			clone = tzfs_openat(parent, request.version, ZH_ALL_RIGHTS, ZHF_SUBTREE);
			ATF_REQUIRE(clone >= 0);
			ATF_REQUIRE_EQ(0, tzfs_set_prop_string(clone,
			    BSDFILESYSTEM_TXN_BASE_PROP, i == 1 ? "" : "records"));
			close(clone);
		}
		memset(&message, 0, sizeof(message));
		message.reply_fd = -1;
		bsdfilesystem_serve_version(&st, &conn, &request, &message);
		ATF_REQUIRE(message.replied);
		ATF_REQUIRE_EQ(i == 2 ? 0 : EINVAL, message.reply.rp.status);
		check = tzfs_openat(parent, request.version, ZH_ALL_RIGHTS, ZHF_SUBTREE);
		if (i == 2) {
			ATF_REQUIRE_ERRNO(ENOENT, check == -1);
			ATF_REQUIRE(!has_snapshot(original, request.version));
		} else {
			ATF_REQUIRE(check >= 0);
			ATF_REQUIRE_EQ(0, tzfs_info(check, &after));
			ATF_CHECK_EQ(before.zi_ds_guid, after.zi_ds_guid);
			close(check);
			ATF_REQUIRE(has_snapshot(original, request.version));
		}
	}
	close(original);
	close(parent);
	close(root);
}
ATF_TC_CLEANUP(abort_origin_real_zfs, tc)
{
	zht_pool_cleanup(tc);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, abort_origin_real_zfs);
	return (atf_no_error());
}
