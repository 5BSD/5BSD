/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 *
 * Run the production recursive cleanup against a deterministic ZFS boundary.
 * No pool or host dataset is touched.  The mounted parent rejects its final
 * destruction; the child and snapshot are otherwise independently removable.
 */
#include <sys/types.h>
#include <sys/zfshandle.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <trustedzfs.h>
#include "bsdfilesystem.h"

typedef struct nvlist nvlist_t;
int nvlist_alloc(nvlist_t **, unsigned, int);
int nvlist_add_boolean(nvlist_t *, const char *);
int nvlist_pack(nvlist_t *, char **, size_t *, int, int);
void nvlist_free(nvlist_t *);

int __wrap_tzfs_openat(int, const char *, uint64_t, uint32_t);
int __wrap_tzfs_info(int, struct zfd_info_args *);
int __wrap_tzfs_list_children(int, void **, size_t *);
int __wrap_tzfs_list_snapshots(int, void **, size_t *);
int __wrap_tzfs_snap_destroy(int, const char *);
int __wrap_tzfs_destroy(int, const char *);

static int parent_fd, child_fd;
static unsigned children_removed, snapshots_removed;

static int
pack_names(const char *name, void **buf, size_t *len)
{
	nvlist_t *nvl;
	char *packed = NULL;

	ATF_REQUIRE_EQ(0, nvlist_alloc(&nvl, 1, 0));
	if (name != NULL)
		ATF_REQUIRE_EQ(0, nvlist_add_boolean(nvl, name));
	*len = 0;
	ATF_REQUIRE_EQ(0, nvlist_pack(nvl, &packed, len, 0, 0));
	nvlist_free(nvl);
	*buf = packed;
	return (0);
}

int
__wrap_tzfs_openat(int fd, const char *name, uint64_t rights __unused,
    uint32_t flags __unused)
{
	int opened = open("/dev/null", O_RDONLY);

	ATF_REQUIRE(opened >= 0);
	if (strcmp(name, "lease") == 0)
		parent_fd = opened;
	else {
		ATF_REQUIRE_EQ(parent_fd, fd);
		ATF_REQUIRE_STREQ("child", name);
		child_fd = opened;
	}
	return (opened);
}

int
__wrap_tzfs_info(int fd, struct zfd_info_args *info)
{
	ATF_REQUIRE(fd == parent_fd || fd == child_fd);
	memset(info, 0, sizeof(*info));
	strlcpy(info->zi_name, fd == parent_fd ? "pool/lease" :
	    "pool/lease/child", sizeof(info->zi_name));
	return (0);
}

int
__wrap_tzfs_list_children(int fd, void **buf, size_t *len)
{
	ATF_REQUIRE(fd == parent_fd || fd == child_fd);
	return (pack_names(fd == parent_fd ? "pool/lease/child" : NULL,
	    buf, len));
}

int
__wrap_tzfs_list_snapshots(int fd, void **buf, size_t *len)
{
	ATF_REQUIRE(fd == parent_fd || fd == child_fd);
	return (pack_names(fd == parent_fd ? "pool/lease@keep" : NULL,
	    buf, len));
}

int
__wrap_tzfs_snap_destroy(int fd, const char *name)
{
	ATF_REQUIRE_EQ(parent_fd, fd);
	ATF_REQUIRE_STREQ("keep", name);
	snapshots_removed++;
	return (0);
}

int
__wrap_tzfs_destroy(int fd, const char *name)
{
	if (strcmp(name, "child") == 0) {
		ATF_REQUIRE_EQ(parent_fd, fd);
		children_removed++;
		return (0);
	}
	ATF_REQUIRE_STREQ("lease", name);
	errno = EBUSY;
	return (-1);
}

ATF_TC_WITHOUT_HEAD(busy_parent_preserves_descendants);
ATF_TC_BODY(busy_parent_preserves_descendants, tc)
{
	ATF_REQUIRE_ERRNO(EBUSY, bsdfilesystem_destroy_tree(-1, "lease") == -1);
	/* A busy result must not be used as proof that the tree is untouched. */
	atf_tc_expect_fail("storage ownership gate missing; see BSDFilesystem(8) LIMITATIONS");
	ATF_CHECK_EQ_MSG(0, children_removed, "live tree lost a child");
	ATF_CHECK_EQ_MSG(0, snapshots_removed, "live tree lost a snapshot");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, busy_parent_preserves_descendants);
	return (atf_no_error());
}
