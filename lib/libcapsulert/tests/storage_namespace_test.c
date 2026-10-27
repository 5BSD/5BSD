/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include "storage_namespace.h"
#include "bsdfilesystem_proto.h"

ATF_TC_WITHOUT_HEAD(selection_and_membership);
ATF_TC_BODY(selection_and_membership, tc)
{
	struct storage_namespace_selection selected;
	char owner[64] = "cap.123", container[64] = "Bundle/Unit";
	char groups[4][64] = {"team", "team", "other", ""};
	char name[256];
	(void)tc;
	ATF_REQUIRE(storage_namespace_select(owner, container, groups, &selected) == 0);
	ATF_CHECK_EQ(9, selected.count); /* one boot, four bundle, four group */
	ATF_CHECK_STREQ("cap.123", selected.entries[0].name);
	ATF_CHECK_EQ(STORAGE_NAMESPACE_BOOT, selected.entries[0].kind);
	ATF_CHECK_STREQ("Bundle/Unit/persistent", selected.entries[1].name);
	ATF_CHECK_STREQ("Bundle/shared/persistent", selected.entries[2].name);
	ATF_CHECK_STREQ("Shared/team/persistent", selected.entries[3].name);
	ATF_CHECK_STREQ("Shared/other/cache", selected.entries[8].name);
	ATF_CHECK(!storage_namespace_scope(container, groups, BSDFILESYSTEM_SCOPE_GROUP,
	    "foreign", BSDFILESYSTEM_PERSISTENT, name, sizeof(name)));
	ATF_CHECK(!storage_namespace_scope(container, groups, BSDFILESYSTEM_SCOPE_UNIT,
	    "", 999, name, sizeof(name)));
	container[0] = '\0';
	ATF_REQUIRE(storage_namespace_select(owner, container, groups, &selected) == 0);
	ATF_CHECK_EQ(1, selected.count); /* Group membership alone is not a container. */
}

ATF_TC_WITHOUT_HEAD(reject_aliases_and_malformed);
ATF_TC_BODY(reject_aliases_and_malformed, tc)
{
	struct storage_namespace_selection selected, empty = {0};
	char owner[64] = "cap.123", container[64], groups[4][64] = {{0}};
	const char *bad[] = {"Shared/Unit", "sHaReD/Unit", "Bundle/shared", "Bundle/SHARED",
	    "../unit", "Bundle/../unit", "Bundle/unit/extra", "Bundle/unit@snap", "Bundle/"};
	(void)tc;
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		strlcpy(container, bad[i], sizeof(container)); memset(&selected, 0xa5, sizeof(selected));
		ATF_CHECK_ERRNO(EINVAL, storage_namespace_select(owner, container, groups, &selected) == -1);
		ATF_CHECK(memcmp(&selected, &empty, sizeof(empty)) == 0);
	}
	strlcpy(container, "Bundle/Unit", sizeof(container));
	memset(groups[0], 'x', sizeof(groups[0]));
	ATF_CHECK_ERRNO(EINVAL, storage_namespace_select(owner, container, groups, &selected) == -1);
	strlcpy(groups[0], "v0123456789abcdef", sizeof(groups[0]));
	ATF_CHECK_ERRNO(EINVAL, storage_namespace_select(owner, container, groups, &selected) == -1);
	strlcpy(groups[0], "del-txn", sizeof(groups[0]));
	ATF_CHECK_ERRNO(EINVAL, storage_namespace_select(owner, container, groups, &selected) == -1);
	groups[0][0] = '\0'; strlcpy(owner, "owner@snapshot", sizeof(owner));
	ATF_CHECK_ERRNO(EINVAL, storage_namespace_select(owner, container, groups, &selected) == -1);
	ATF_CHECK(memcmp(&selected, &empty, sizeof(empty)) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, selection_and_membership);
	ATF_TP_ADD_TC(tp, reject_aliases_and_malformed);
	return (atf_no_error());
}
