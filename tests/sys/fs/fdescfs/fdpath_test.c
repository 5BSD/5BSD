/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
mount_fds(void)
{
	char path[PATH_MAX];
	struct iovec iov[] = {
	    { __DECONST(char *, "fstype"), sizeof("fstype") },
	    { __DECONST(char *, "fdescfs"), sizeof("fdescfs") },
	    { __DECONST(char *, "fspath"), sizeof("fspath") },
	    { path, 0 },
	    { __DECONST(char *, "linrdlnk"), sizeof("linrdlnk") },
	    { NULL, 0 },
	};

	ATF_REQUIRE_EQ(0, mkdir("fds", 0700));
	ATF_REQUIRE(realpath("fds", path) != NULL);
	iov[3].iov_len = strlen(path) + 1;
	ATF_REQUIRE_MSG(nmount(iov, nitems(iov), 0) == 0,
	    "nmount: %s", strerror(errno));
}

ATF_TC_WITH_CLEANUP(directory_walk);
ATF_TC_HEAD(directory_walk, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "fdescfs");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(directory_walk, tc)
{
	char path[PATH_MAX], link[PATH_MAX], target[PATH_MAX];
	cap_rights_t rights;
	int dir, fd, file;
	ssize_t len;

	mount_fds();
	ATF_REQUIRE_EQ(0, mkdir("dir", 0700));
	dir = open("dir", O_PATH | O_DIRECTORY);
	ATF_REQUIRE(dir >= 0);
	snprintf(path, sizeof(path), "fds/%d", dir);
	len = readlink(path, link, sizeof(link) - 1);
	ATF_REQUIRE(len > 0);
	link[len] = '\0';
	ATF_REQUIRE(realpath("dir", target) != NULL);
	ATF_CHECK_STREQ(target, link);
	snprintf(path, sizeof(path), "fds/%d/", dir);
	fd = open(path, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE_MSG(fd >= 0, "trailing slash: %s", strerror(errno));
	close(fd);

	snprintf(path, sizeof(path), "fds/%d/child", dir);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "create via fd: %s", strerror(errno));
	close(fd);
	ATF_CHECK_EQ(0, access("dir/child", F_OK));
	ATF_CHECK_ERRNO(EEXIST, open(path, O_WRONLY | O_CREAT | O_EXCL,
	    0600) == -1);
	ATF_REQUIRE_EQ(0, rename("dir", "moved"));
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "walk renamed directory: %s", strerror(errno));
	close(fd);

	ATF_REQUIRE_EQ(0, symlink("child", "moved/link"));
	snprintf(path, sizeof(path), "fds/%d/link", dir);
	ATF_CHECK_ERRNO(ELOOP, open(path, O_RDONLY | O_NOFOLLOW) == -1);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	file = open("moved/child", O_RDONLY);
	ATF_REQUIRE(file >= 0);
	snprintf(path, sizeof(path), "fds/%d/child", file);
	ATF_CHECK_ERRNO(ENOTDIR, open(path, O_RDONLY) == -1);
	close(file);
	ATF_CHECK_ERRNO(EBADF, open(path, O_RDONLY) == -1);
	file = open("moved", O_RDONLY | O_DIRECTORY | O_RESOLVE_BENEATH);
	ATF_REQUIRE(file >= 0);
	snprintf(path, sizeof(path), "fds/%d/child", file);
	ATF_CHECK_ERRNO(ENOTCAPABLE, open(path, O_RDONLY) == -1);
	close(file);

	snprintf(path, sizeof(path), "fds/%d/child", dir);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ);
	ATF_REQUIRE_EQ(0, cap_rights_limit(dir, &rights));
	ATF_CHECK_ERRNO(ENOTCAPABLE, open(path, O_RDONLY) == -1);
	fd = openat(dir, "child", O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "restricted openat: %s", strerror(errno));
	close(fd);
	close(dir);
}
ATF_TC_CLEANUP(directory_walk, tc)
{
	(void)unmount("fds", 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, directory_walk);
	return (atf_no_error());
}
