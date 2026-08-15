/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtiofsd_export.c"

static int
export_fixture(char path[static 32])
{
	int fd, rootfd;

	strcpy(path, "/tmp/virtiofsd-export.XXXXXX");
	ATF_REQUIRE(mkdtemp(path) != NULL);
	rootfd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(rootfd >= 0);
	fd = openat(rootfd, "file", O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(write(fd, "waspnest", 8), 8);
	ATF_REQUIRE_EQ(close(fd), 0);
	ATF_REQUIRE_EQ(linkat(rootfd, "file", rootfd, "hardlink", 0), 0);
	ATF_REQUIRE_EQ(mkdirat(rootfd, "dir", 0700), 0);
	ATF_REQUIRE_EQ(symlinkat("/etc", rootfd, "escape"), 0);
	ATF_REQUIRE_EQ(mkfifoat(rootfd, "fifo", 0600), 0);
	return (rootfd);
}

static void
export_cleanup(int rootfd, const char *path)
{

	ATF_REQUIRE_EQ(unlinkat(rootfd, "hardlink", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "file", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "escape", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "fifo", 0), 0);
	ATF_REQUIRE_EQ(unlinkat(rootfd, "dir", AT_REMOVEDIR), 0);
	ATF_REQUIRE_EQ(close(rootfd), 0);
	ATF_REQUIRE_EQ(rmdir(path), 0);
}

ATF_TC_WITHOUT_HEAD(component_validation_is_protocol_bounded);
ATF_TC_BODY(component_validation_is_protocol_bounded, tc)
{
	char maximum[VIRTIOFSD_NAME_MAX];
	char too_long[VIRTIOFSD_NAME_MAX + 1];

	memset(maximum, 'x', sizeof(maximum));
	memset(too_long, 'y', sizeof(too_long));
	ATF_CHECK_EQ(virtiofsd_export_component_valid("file", 4), 0);
	ATF_CHECK_EQ(virtiofsd_export_component_valid(maximum,
	    sizeof(maximum)), 0);
	ATF_CHECK_EQ(virtiofsd_export_component_valid(NULL, 1), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid("", 0), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid(".", 1), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid("..", 2), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid("a/b", 3), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid("a\0b", 3), EINVAL);
	ATF_CHECK_EQ(virtiofsd_export_component_valid(too_long,
	    sizeof(too_long)), EINVAL);
}

ATF_TC_WITHOUT_HEAD(nodes_are_confined_stable_and_generation_checked);
ATF_TC_BODY(nodes_are_confined_stable_and_generation_checked, tc)
{
	struct virtiofsd_export *export;
	struct stat first_stat, hardlink_stat, symlink_stat;
	char path[32], buffer[16] = {};
	size_t link_length;
	uint64_t first, hardlink, escaped, replacement;
	int datafd, error, rootfd;

	rootfd = export_fixture(path);
	ATF_REQUIRE_EQ(virtiofsd_export_create(rootfd, 3, &export), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &first, &first_stat), 0);
	ATF_REQUIRE(first != VIRTIOFSD_ROOT_NODEID);
	ATF_REQUIRE(S_ISREG(first_stat.st_mode));
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "hardlink", 8, &hardlink,
	    &hardlink_stat), 0);
	ATF_CHECK_EQ(first, hardlink);
	ATF_CHECK_EQ(first_stat.st_ino, hardlink_stat.st_ino);
	ATF_REQUIRE_EQ(virtiofsd_export_open(export, first, O_RDONLY,
	    &datafd), 0);
	ATF_REQUIRE_EQ(read(datafd, buffer, 8), 8);
	ATF_CHECK_STREQ(buffer, "waspnest");
	ATF_REQUIRE_EQ(close(datafd), 0);

	/* The symlink itself is visible, but cannot become a lookup root. */
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "escape", 6, &escaped, &symlink_stat), 0);
	ATF_REQUIRE(S_ISLNK(symlink_stat.st_mode));
	ATF_REQUIRE_EQ(virtiofsd_export_readlink(export, escaped, buffer,
	    sizeof(buffer), &link_length), 0);
	ATF_CHECK_EQ(link_length, 4);
	ATF_CHECK_EQ(memcmp(buffer, "/etc", 4), 0);
	ATF_CHECK_EQ(virtiofsd_export_lookup(export, escaped, "passwd", 6,
	    &replacement, &symlink_stat), ENOTDIR);
	error = virtiofsd_export_open(export, escaped, O_RDONLY, &datafd);
	ATF_CHECK_MSG(error == EMLINK, "symlink reopen returned %d", error);
	ATF_CHECK_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "fifo", 4, &replacement, &symlink_stat),
	    EOPNOTSUPP);

	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, first, 1), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, first, 1), 0);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, first, &first_stat),
	    ESTALE);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &replacement, &first_stat), 0);
	ATF_CHECK(first != replacement);
	ATF_CHECK_EQ(virtiofsd_export_forget(export, first, 1), ESTALE);

	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, escaped, 1), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, replacement, 1), 0);
	virtiofsd_export_destroy(export);
	export_cleanup(rootfd, path);
}

ATF_TC_WITHOUT_HEAD(capacity_failure_preserves_existing_nodes);
ATF_TC_BODY(capacity_failure_preserves_existing_nodes, tc)
{
	struct virtiofsd_export *export;
	struct stat sb;
	char path[32];
	uint64_t file, other;
	int rootfd;

	rootfd = export_fixture(path);
	ATF_REQUIRE_EQ(virtiofsd_export_create(rootfd, 2, &export), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &file, &sb), 0);
	ATF_CHECK_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "dir", 3, &other, &sb), ENOSPC);
	ATF_REQUIRE_EQ(virtiofsd_export_stat(export, file, &sb), 0);
	ATF_CHECK(S_ISREG(sb.st_mode));
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, file, 1), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "dir", 3, &other, &sb), 0);
	ATF_CHECK(S_ISDIR(sb.st_mode));
	ATF_CHECK(file != other);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, other, 1), 0);
	virtiofsd_export_destroy(export);
	export_cleanup(rootfd, path);
}

ATF_TC_WITHOUT_HEAD(export_open_enforces_read_only_authority);
ATF_TC_BODY(export_open_enforces_read_only_authority, tc)
{
	struct virtiofsd_export *export;
	struct stat sb;
	char path[32];
	uint64_t file;
	int datafd, rootfd;

	rootfd = export_fixture(path);
	ATF_REQUIRE_EQ(virtiofsd_export_create(rootfd, 2, &export), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &file, &sb), 0);
	datafd = -1;
	ATF_CHECK_EQ(virtiofsd_export_open(export, file, O_WRONLY,
	    &datafd), EROFS);
	ATF_CHECK_EQ(datafd, -1);
	ATF_CHECK_EQ(virtiofsd_export_open(export, file, O_RDWR,
	    &datafd), EROFS);
	ATF_CHECK_EQ(datafd, -1);
	ATF_CHECK_EQ(virtiofsd_export_open(export, file,
	    O_RDONLY | O_TRUNC, &datafd), EROFS);
	ATF_CHECK_EQ(datafd, -1);
	ATF_CHECK_EQ(virtiofsd_export_open(export, file,
	    O_RDONLY | O_APPEND, &datafd), EROFS);
	ATF_CHECK_EQ(datafd, -1);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, file, 1), 0);
	virtiofsd_export_destroy(export);
	export_cleanup(rootfd, path);
}

ATF_TC_WITHOUT_HEAD(reset_reclaims_nodes_and_preserves_stale_ids);
ATF_TC_BODY(reset_reclaims_nodes_and_preserves_stale_ids, tc)
{
	struct virtiofsd_export *export;
	struct stat sb;
	char path[32];
	uint64_t file, replacement;
	int rootfd;

	rootfd = export_fixture(path);
	ATF_REQUIRE_EQ(virtiofsd_export_create(rootfd, 2, &export), 0);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "file", 4, &file, &sb), 0);

	virtiofsd_export_reset(export);
	ATF_CHECK_EQ(virtiofsd_export_stat(export, file, &sb), ESTALE);
	ATF_CHECK_EQ(virtiofsd_export_forget(export, file, 1), ESTALE);
	ATF_REQUIRE_EQ(virtiofsd_export_lookup(export,
	    VIRTIOFSD_ROOT_NODEID, "dir", 3, &replacement, &sb), 0);
	ATF_CHECK(file != replacement);
	ATF_REQUIRE_EQ(virtiofsd_export_forget(export, replacement, 1), 0);
	virtiofsd_export_destroy(export);
	export_cleanup(rootfd, path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, component_validation_is_protocol_bounded);
	ATF_TP_ADD_TC(tp, nodes_are_confined_stable_and_generation_checked);
	ATF_TP_ADD_TC(tp, capacity_failure_preserves_existing_nodes);
	ATF_TP_ADD_TC(tp, export_open_enforces_read_only_authority);
	ATF_TP_ADD_TC(tp, reset_reclaims_nodes_and_preserves_stale_ids);
	return (atf_no_error());
}
