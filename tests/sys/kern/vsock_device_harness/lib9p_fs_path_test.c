/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct tests for the filesystem backend's protocol-component validation.
 */

#include <atf-c.h>

/*
 * Include the implementation so the test exercises the exact internal
 * component builder used by create, link, rename, and unlink operations.
 * Unreferenced backend sections are discarded by the rootless harness.
 */
#include "backend/fs.c"

ATF_TC_WITHOUT_HEAD(single_component_names);
ATF_TC_BODY(single_component_names, tc)
{
	struct fs_fid ff;
	struct l9p_fid fid;
	char path[MAXPATHLEN];

	memset(&ff, 0, sizeof(ff));
	memset(&fid, 0, sizeof(fid));
	ff.ff_name = __DECONST(char *, "parent");
	fid.lo_aux = &ff;

	ATF_CHECK_EQ(fs_buildname(&fid, "child", path, sizeof(path)), 0);
	ATF_CHECK_STREQ(path, "parent/child");
	ATF_CHECK_EQ(fs_buildname(&fid, "", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, ".", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, "..", path, sizeof(path)), EINVAL);
	ATF_CHECK_EQ(fs_buildname(&fid, "nested/child", path, sizeof(path)),
	    EINVAL);

	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "renamed", sizeof(path)), 0);
	ATF_CHECK_STREQ(path, "parent/renamed");
	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "../outside", sizeof(path)), EINVAL);

	ATF_REQUIRE(strlcpy(path, "parent", sizeof(path)) < sizeof(path));
	ATF_CHECK_EQ(fs_dpf(path, "child", strlen("parent/child")),
	    ENAMETOOLONG);
	ATF_CHECK_STREQ(path, "parent");
	ATF_CHECK_EQ(fs_buildname(&fid, "child", path,
	    strlen("parent/child")), ENAMETOOLONG);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, single_component_names);
	return (atf_no_error());
}
