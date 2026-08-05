/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "store.h"

ATF_TC(namespaces_and_isolation);
ATF_TC_HEAD(namespaces_and_isolation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "scratch, persistent, and bundle handles are distinct authorities");
}
ATF_TC_BODY(namespaces_and_isolation, tc)
{
	struct scratch_limits limits = {
		.max_bytes = UINT64_MAX,
		.max_objects = 16,
		.max_file_bytes = 1024,
	};
	struct filesystem_store *store;
	struct filesystemcmp_handle scratch, persistent, bundle, file;
	char name[64];
	int bundlefd, persistentfd;

	ATF_REQUIRE_EQ(0, mkdir("persistent", 0700));
	ATF_REQUIRE_EQ(0, mkdir("bundle", 0700));
	persistentfd = open("persistent", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(persistentfd >= 0);
	bundlefd = open("bundle", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(bundlefd >= 0);
	ATF_REQUIRE_EQ(0, filesystem_store_create(&limits, persistentfd,
	    bundlefd, &store));
	ATF_CHECK_EQ(FILESYSTEMCMP_FEATURE_INLINE_IO |
	    FILESYSTEMCMP_FEATURE_PERSISTENT | FILESYSTEMCMP_FEATURE_BUNDLE,
	    filesystem_store_features(store));
	ATF_REQUIRE_EQ(0, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &scratch));
	ATF_REQUIRE_EQ(0, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT, &persistent));
	ATF_REQUIRE_EQ(0, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_BUNDLE, &bundle));
	ATF_CHECK(scratch.object != persistent.object);
	ATF_CHECK(persistent.object != bundle.object);

	snprintf(name, sizeof(name), "store.%ld", (long)getpid());
	ATF_REQUIRE_EQ(0, filesystem_store_create_object(store, persistent,
	    name, strlen(name), FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &file));
	ATF_REQUIRE_EQ(1, filesystem_store_write(store, file, 0, "p", 1));
	ATF_REQUIRE_EQ(0, filesystem_store_sync(store, file));
	ATF_REQUIRE_EQ(0, filesystem_store_sync(store, persistent));
	ATF_REQUIRE_EQ(0, filesystem_store_sync(store, scratch));
	errno = 0;
	ATF_CHECK_EQ(-1, filesystem_store_create_object(store, bundle, "x", 1,
	    FILESYSTEMCMP_CREATE_EXCLUSIVE, 0600, &file));
	ATF_CHECK_EQ(EROFS, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, filesystem_store_rename(store, persistent, name,
	    strlen(name), scratch, "x", 1));
	ATF_CHECK_EQ(EXDEV, errno);
	ATF_REQUIRE_EQ(0, filesystem_store_unlink(store, persistent, name,
	    strlen(name)));
	ATF_REQUIRE_EQ(0, filesystem_store_sync(store, persistent));
	filesystem_store_destroy(store);
	close(bundlefd);
	close(persistentfd);
}

ATF_TC(optional_namespaces);
ATF_TC_HEAD(optional_namespaces, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "unprovisioned durable namespaces are not advertised or opened");
}
ATF_TC_BODY(optional_namespaces, tc)
{
	struct scratch_limits limits = {
		.max_bytes = 4096,
		.max_objects = 16,
		.max_file_bytes = 1024,
	};
	struct filesystem_store *store;
	struct filesystemcmp_handle root;

	ATF_REQUIRE_EQ(0, filesystem_store_create(&limits, -1, -1, &store));
	ATF_CHECK_EQ(FILESYSTEMCMP_FEATURE_INLINE_IO,
	    filesystem_store_features(store));
	errno = 0;
	ATF_CHECK_EQ(-1, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT, &root));
	ATF_CHECK_EQ(ENOENT, errno);
	filesystem_store_destroy(store);
}

ATF_TC(handle_duplication);
ATF_TC_HEAD(handle_duplication, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "duplicated durable handles have independent close lifetimes");
}
ATF_TC_BODY(handle_duplication, tc)
{
	struct scratch_limits limits = {
		.max_bytes = 4096,
		.max_objects = 16,
		.max_file_bytes = 1024,
	};
	struct filesystem_store *store;
	struct filesystemcmp_handle root, duplicate;
	int rootfd;

	ATF_REQUIRE_EQ(0, mkdir("persistent-dup", 0700));
	rootfd = open("persistent-dup",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	ATF_REQUIRE_EQ(0, filesystem_store_create(&limits, rootfd, -1,
	    &store));
	ATF_REQUIRE_EQ(0, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT, &root));
	ATF_REQUIRE_EQ(0, filesystem_store_dup(store, root, &duplicate));
	ATF_CHECK(duplicate.object != root.object);
	ATF_REQUIRE_EQ(0, filesystem_store_close(store, duplicate));
	ATF_REQUIRE_EQ(0, filesystem_store_sync(store, root));
	ATF_REQUIRE_EQ(0, filesystem_store_root(store,
	    FILESYSTEMCMP_NAMESPACE_SCRATCH, &root));
	ATF_REQUIRE_EQ(0, filesystem_store_dup(store, root, &duplicate));
	ATF_CHECK_EQ(root.object, duplicate.object);
	filesystem_store_destroy(store);
	close(rootfd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, namespaces_and_isolation);
	ATF_TP_ADD_TC(tp, optional_namespaces);
	ATF_TP_ADD_TC(tp, handle_duplication);
	return (atf_no_error());
}
