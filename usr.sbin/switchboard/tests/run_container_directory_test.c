/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "run_container_directory.h"

ATF_TC_WITHOUT_HEAD(held_directory_and_rights);
ATF_TC_BODY(held_directory_and_rights, tc)
{
	struct stat held, cwd, replacement;
	cap_rights_t rights, expected, actual;
	int origin, fd;

	origin = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(origin >= 0);
	ATF_REQUIRE_EQ(0, mkdir("container", 0700));
	fd = open("container", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&rights, CAP_FCHDIR, CAP_FSTAT, CAP_LOOKUP);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, fstat(fd, &held));
	ATF_REQUIRE_EQ(0, rename("container", "held"));
	ATF_REQUIRE_EQ(0, mkdir("container", 0700));
	ATF_REQUIRE_EQ(0, stat("container", &replacement));
	ATF_REQUIRE(held.st_ino != replacement.st_ino);
	ATF_REQUIRE_EQ(0, sb_run_container_enter(fd));
	ATF_REQUIRE_EQ(0, stat(".", &cwd));
	ATF_CHECK_EQ(held.st_dev, cwd.st_dev);
	ATF_CHECK_EQ(held.st_ino, cwd.st_ino);
	cap_rights_init(&expected, CAP_FSTAT, CAP_LOOKUP);
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &actual));
	ATF_CHECK(cap_rights_contains(&expected, &actual));
	ATF_CHECK(cap_rights_contains(&actual, &expected));
	ATF_REQUIRE_EQ(0, fchdir(origin));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, fchdir(fd) == -1);
	close(fd);
	close(origin);
}

ATF_TC_WITHOUT_HEAD(missing_launch_right);
ATF_TC_BODY(missing_launch_right, tc)
{
	struct stat before, after;
	cap_rights_t rights;
	int fd;

	ATF_REQUIRE_EQ(0, stat(".", &before));
	ATF_REQUIRE_EQ(0, mkdir("container", 0700));
	fd = open("container", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&rights, CAP_FSTAT, CAP_LOOKUP);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, sb_run_container_enter(fd) == -1);
	ATF_REQUIRE_EQ(0, stat(".", &after));
	ATF_CHECK_EQ(before.st_dev, after.st_dev);
	ATF_CHECK_EQ(before.st_ino, after.st_ino);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fresh_only);
ATF_TC_BODY(fresh_only, tc)
{
	struct stat before, after;
	int parent, fd, sentinel, fresh;
	char byte;

	parent = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(parent >= 0);
	fd = sb_run_container_create(parent, "container");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &before));
	ATF_CHECK_EQ(0700, before.st_mode & 0777);
	sentinel = openat(fd, "state", O_CREAT | O_EXCL | O_WRONLY, 0600);
	ATF_REQUIRE(sentinel >= 0);
	ATF_REQUIRE_EQ(1, write(sentinel, "x", 1));
	close(sentinel);
	ATF_REQUIRE_ERRNO(EEXIST,
	    sb_run_container_create(parent, "container") == -1);
	ATF_REQUIRE_EQ(0, fstatat(parent, "container", &after, 0));
	ATF_CHECK_EQ(before.st_ino, after.st_ino);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_REQUIRE_EQ(0, fstatat(fd, "state", &after, 0));
	ATF_CHECK_EQ(1, after.st_size);
	sentinel = openat(fd, "state", O_RDONLY);
	ATF_REQUIRE(sentinel >= 0);
	ATF_REQUIRE_EQ(1, read(sentinel, &byte, 1));
	ATF_CHECK_EQ('x', byte);
	close(sentinel);
	ATF_REQUIRE_EQ(0, symlinkat("container", parent, "alias"));
	ATF_REQUIRE_ERRNO(EEXIST,
	    sb_run_container_create(parent, "alias") == -1);
	ATF_REQUIRE_EQ(0, mkdirat(parent, "empty", 0700));
	ATF_REQUIRE_ERRNO(EEXIST,
	    sb_run_container_create(parent, "empty") == -1);
	ATF_REQUIRE_EQ(0, unlinkat(fd, "state", 0));
	ATF_REQUIRE_EQ(0, unlinkat(parent, "container", AT_REMOVEDIR));
	fresh = sb_run_container_create(parent, "container");
	ATF_REQUIRE(fresh >= 0);
	ATF_REQUIRE_EQ(0, fstat(fresh, &after));
	ATF_CHECK(before.st_ino != after.st_ino);
	close(fresh);
	close(fd);
	close(parent);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fresh_only);
	ATF_TP_ADD_TC(tp, held_directory_and_rights);
	ATF_TP_ADD_TC(tp, missing_launch_right);
	return (atf_no_error());
}
