/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * open(2)/openat(2) semantics for an unattached process.
 *
 * What it tries to break: openatfp became a wrapper around
 * openatfp_dqimpl, and namei's start-directory code (fgetvp_lookup_start)
 * learned about vnode-less served starts.  The flag validation order
 * (openflags before any lookup), vn_open_cred's O_CREAT/O_EXCL/O_DIRECTORY
 * matrix, O_NOFOLLOW's EMLINK, O_PATH, O_EMPTY_PATH reopen, O_TRUNC
 * (including with O_RDONLY) and O_RESOLVE_BENEATH, as at 3f330ee172d.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

static off_t
size_of(const char *path)
{
	struct stat sb;

	ATF_REQUIRE(stat(path, &sb) == 0);
	return (sb.st_size);
}

static void
close_if(int fd)
{

	if (fd >= 0)
		close(fd);
}

ATF_TC_WITHOUT_HEAD(flag_validation_first);
ATF_TC_BODY(flag_validation_first, tc)
{

	/* openflags() runs before falloc and namei: EINVAL wins. */
	CHECK_ERR(openat(-1, "nodir/x", O_ACCMODE), EINVAL);
	CHECK_ERR(openat(-1, NULL, O_EXEC | O_RDWR), EINVAL);
	CHECK_ERR(open(NULL, 0x40000000), EINVAL);
	CHECK_ERR(open("nodir/x", O_RDONLY | 0x4000 /* FHASLOCK */), EINVAL);
	/* vn_open_cred's flag test comes before its namei. */
	CHECK_ERR(open("nodir/x", O_CREAT | O_EXCL | O_DIRECTORY, 0644),
	    EINVAL);
	CHECK_ERR(openat(AT_FDCWD, "nodir/x", O_CREAT | O_EMPTY_PATH, 0644),
	    EINVAL);
	/* ...but after copyinstr of the path?  No: flags first, then path. */
	CHECK_ERR(open(NULL, O_CREAT | O_EXCL | O_DIRECTORY, 0644), EINVAL);
	ATF_CHECK(pc_dirent_count(".") == 0);
}

ATF_TC_WITHOUT_HEAD(creat_excl);
ATF_TC_BODY(creat_excl, tc)
{
	int fd;

	pc_mkfile("f", "data\n");
	pc_mkdir("d");
	pc_symlink("missing_target", "dangling");
	pc_symlink("f", "lf");
	CHECK_ERR(open("f", O_CREAT | O_EXCL | O_WRONLY, 0644), EEXIST);
	CHECK_ERR(open("d", O_CREAT | O_EXCL | O_RDONLY, 0644), EEXIST);
	/* O_EXCL clears FOLLOW: an existing link, dangling or not, exists. */
	CHECK_ERR(open("dangling", O_CREAT | O_EXCL | O_WRONLY, 0644), EEXIST);
	ATF_CHECK(access("missing_target", F_OK) == -1 && errno == ENOENT);
	CHECK_ERR(open("lf", O_CREAT | O_EXCL | O_WRONLY, 0644), EEXIST);
	/* A fresh name is created with the requested mode minus umask. */
	umask(022);
	fd = open("new", O_CREAT | O_EXCL | O_WRONLY, 0666);
	CHECK_OK(fd);
	close_if(fd);
	{
		struct stat sb;

		ATF_REQUIRE(stat("new", &sb) == 0);
		ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0644);
		ATF_CHECK(S_ISREG(sb.st_mode));
	}
	/* Twice: EEXIST, the file kept. */
	CHECK_ERR(open("new", O_CREAT | O_EXCL | O_RDWR, 0644), EEXIST);
	ATF_CHECK_EQ(size_of("f"), 5);
}

ATF_TC_WITHOUT_HEAD(creat_follows_dangling);
ATF_TC_BODY(creat_follows_dangling, tc)
{
	int fd;

	/*
	 * O_CREAT without O_EXCL keeps FOLLOW: a dangling final link is
	 * followed and its target created.
	 */
	pc_mkdir("d");
	pc_symlink("d/made", "dangling");
	fd = open("dangling", O_CREAT | O_WRONLY, 0644);
	CHECK_OK(fd);
	close_if(fd);
	ATF_CHECK(access("d/made", F_OK) == 0);
	{
		struct stat sb;

		ATF_REQUIRE(lstat("dangling", &sb) == 0);
		ATF_CHECK(S_ISLNK(sb.st_mode));
	}
	/* With O_NOFOLLOW the existing link is EMLINK, nothing created. */
	pc_symlink("d/made2", "dangling2");
	CHECK_ERR(open("dangling2", O_CREAT | O_NOFOLLOW | O_WRONLY, 0644),
	    EMLINK);
	ATF_CHECK(access("d/made2", F_OK) == -1);
}

ATF_TC_WITHOUT_HEAD(creat_directory_matrix);
ATF_TC_BODY(creat_directory_matrix, tc)
{
	int fd;

	pc_mkdir("d");
	pc_mkfile("f", NULL);
	/* O_CREAT on an existing directory: EISDIR. */
	CHECK_ERR(open("d", O_CREAT | O_RDONLY, 0644), EISDIR);
	/* O_CREAT | O_DIRECTORY (no O_EXCL) is a plain LOOKUP open. */
	fd = open("d", O_CREAT | O_DIRECTORY | O_RDONLY, 0644);
	CHECK_OK(fd);
	close_if(fd);
	CHECK_ERR(open("newd", O_CREAT | O_DIRECTORY | O_RDONLY, 0644),
	    ENOENT);
	ATF_CHECK(access("newd", F_OK) == -1);
	CHECK_ERR(open("f", O_CREAT | O_DIRECTORY | O_RDONLY, 0644), ENOTDIR);
	CHECK_ERR(open("f", O_DIRECTORY | O_RDONLY), ENOTDIR);
	CHECK_ERR(open("d", O_WRONLY), EISDIR);
	CHECK_ERR(open("d", O_RDONLY | O_TRUNC), EISDIR);
	fd = open("d", O_DIRECTORY | O_RDONLY);
	CHECK_OK(fd);
	close_if(fd);
}

ATF_TC_WITHOUT_HEAD(trunc);
ATF_TC_BODY(trunc, tc)
{
	int fd;

	pc_mkfile("f", "0123456789");
	fd = open("f", O_WRONLY | O_TRUNC);
	CHECK_OK(fd);
	close_if(fd);
	ATF_CHECK_EQ(size_of("f"), 0);

	pc_mkfile("f", "0123456789");
	fd = open("f", O_RDWR | O_CREAT | O_TRUNC, 0644);
	CHECK_OK(fd);
	close_if(fd);
	ATF_CHECK_EQ(size_of("f"), 0);

	/*
	 * O_RDONLY | O_TRUNC: vn_open_vnode asks for VWRITE, then openatfp
	 * truncates through fo_truncate (vn_truncate has no FWRITE test).
	 */
	pc_mkfile("f", "0123456789");
	fd = open("f", O_RDONLY | O_TRUNC);
	CHECK_OK(fd);
	close_if(fd);
	ATF_CHECK_EQ(size_of("f"), 0);

	/* Without write permission the open is refused, nothing truncated. */
	if (!pc_is_root()) {
		pc_mkfile("ro", "0123456789");
		ATF_REQUIRE(chmod("ro", 0444) == 0);
		CHECK_ERR(open("ro", O_RDONLY | O_TRUNC), EACCES);
		CHECK_ERR(open("ro", O_WRONLY | O_TRUNC), EACCES);
		ATF_CHECK_EQ(size_of("ro"), 10);
	}
	/* A newly created file is not "truncated" (O_TRUNC dropped). */
	fd = open("fresh", O_RDWR | O_CREAT | O_EXCL | O_TRUNC, 0644);
	CHECK_OK(fd);
	close_if(fd);
}

ATF_TC_WITHOUT_HEAD(nofollow);
ATF_TC_BODY(nofollow, tc)
{
	struct stat sb;
	int fd;

	pc_mkdir("d");
	pc_mkfile("d/f", "data\n");
	pc_symlink("d/f", "lf");
	pc_symlink("d", "ld");
	/* A final symlink without O_PATH: EMLINK (vn_open_vnode). */
	CHECK_ERR(open("lf", O_RDONLY | O_NOFOLLOW), EMLINK);
	CHECK_ERR(open("ld", O_RDONLY | O_NOFOLLOW | O_DIRECTORY), EMLINK);
	CHECK_ERR(open("lf", O_WRONLY | O_NOFOLLOW | O_TRUNC), EMLINK);
	ATF_CHECK_EQ(size_of("d/f"), 5);
	/* Only the final component is affected. */
	fd = open("ld/f", O_RDONLY | O_NOFOLLOW);
	CHECK_OK(fd);
	close_if(fd);
	/* O_DIRECTORY follows a link to a directory. */
	fd = open("ld", O_RDONLY | O_DIRECTORY);
	CHECK_OK(fd);
	close_if(fd);
	/* O_PATH | O_NOFOLLOW opens the link itself. */
	fd = open("lf", O_PATH | O_NOFOLLOW);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &sb) == 0 && S_ISLNK(sb.st_mode));
		close(fd);
	}
	/* O_PATH alone follows it. */
	fd = open("lf", O_PATH);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode));
		close(fd);
	}
	/* O_PATH | O_NOFOLLOW | O_DIRECTORY on a link: ENOTDIR. */
	CHECK_ERR(open("ld", O_PATH | O_NOFOLLOW | O_DIRECTORY), ENOTDIR);
}

ATF_TC_WITHOUT_HEAD(o_path);
ATF_TC_BODY(o_path, tc)
{
	struct sockaddr_un sun;
	struct stat sb;
	char c;
	int fd, s;

	pc_mkfile("f", "data\n");
	ATF_REQUIRE(mkfifo("fifo", 0644) == 0);
	fd = open("f", O_PATH | O_RDWR);
	CHECK_OK(fd);
	if (fd >= 0) {
		CHECK_ERR(read(fd, &c, 1), EBADF);
		CHECK_ERR(write(fd, "x", 1), EBADF);
		CHECK_OK(fstat(fd, &sb));
		close(fd);
	}
	/* O_PATH on a FIFO does not block for a writer. */
	fd = open("fifo", O_PATH);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &sb) == 0 && S_ISFIFO(sb.st_mode));
		close(fd);
	}
	/* Non-blocking FIFO opens: a reader succeeds, a lone writer ENXIO. */
	CHECK_ERR(open("fifo", O_WRONLY | O_NONBLOCK), ENXIO);
	fd = open("fifo", O_RDONLY | O_NONBLOCK);
	CHECK_OK(fd);
	close_if(fd);
	/* A UNIX socket node: open is EOPNOTSUPP, O_PATH works. */
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, "sock", sizeof(sun.sun_path));
	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, sizeof(sun)) == 0);
	CHECK_ERR(open("sock", O_RDONLY), EOPNOTSUPP);
	fd = open("sock", O_PATH);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &sb) == 0 && S_ISSOCK(sb.st_mode));
		close(fd);
	}
	close(s);
}

ATF_TC_WITHOUT_HEAD(empty_path_reopen);
ATF_TC_BODY(empty_path_reopen, tc)
{
	struct stat a, b;
	char buf[8];
	int dfd, fd, lfd, pfd, r;

	pc_mkdir("d");
	pc_mkfile("f", "data\n");
	pc_symlink("f", "lf");
	pfd = open("f", O_PATH);
	ATF_REQUIRE(pfd >= 0);
	/* Without O_EMPTY_PATH, "" is ENOENT whatever the descriptor. */
	CHECK_ERR(openat(pfd, "", O_RDONLY), ENOENT);
	CHECK_ERR(openat(-1, "", O_RDONLY), ENOENT);
	CHECK_ERR(openat(AT_FDCWD, "", O_RDONLY), ENOENT);
	/* O_EMPTY_PATH reopens the O_PATH file for reading. */
	fd = openat(pfd, "", O_EMPTY_PATH | O_RDONLY);
	CHECK_OK(fd);
	if (fd >= 0) {
		r = (int)read(fd, buf, sizeof(buf));
		ATF_CHECK_EQ(r, 5);
		ATF_CHECK(fstat(fd, &a) == 0 && stat("f", &b) == 0 &&
		    a.st_ino == b.st_ino);
		close(fd);
	}
	/* Write access is checked against the vnode. */
	if (!pc_is_root()) {
		ATF_REQUIRE(chmod("f", 0444) == 0);
		CHECK_ERR(openat(pfd, "", O_EMPTY_PATH | O_RDWR), EACCES);
		ATF_REQUIRE(chmod("f", 0644) == 0);
	}
	/* A directory descriptor and AT_FDCWD name the directory itself. */
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);
	fd = openat(dfd, "", O_EMPTY_PATH | O_RDONLY);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &a) == 0 && stat("d", &b) == 0 &&
		    a.st_ino == b.st_ino);
		close(fd);
	}
	fd = openat(AT_FDCWD, "", O_EMPTY_PATH | O_RDONLY | O_DIRECTORY);
	CHECK_OK(fd);
	if (fd >= 0) {
		ATF_CHECK(fstat(fd, &a) == 0 && stat(".", &b) == 0 &&
		    a.st_ino == b.st_ino);
		close(fd);
	}
	/* A non-empty path with O_EMPTY_PATH is an ordinary lookup. */
	fd = openat(AT_FDCWD, "f", O_EMPTY_PATH | O_RDONLY);
	CHECK_OK(fd);
	close_if(fd);
	/* A symlink opened O_PATH | O_NOFOLLOW reopens as EMLINK. */
	lfd = open("lf", O_PATH | O_NOFOLLOW);
	ATF_REQUIRE(lfd >= 0);
	CHECK_ERR(openat(lfd, "", O_EMPTY_PATH | O_RDONLY), EMLINK);
	fd = openat(lfd, "", O_EMPTY_PATH | O_PATH);
	CHECK_OK(fd);
	close_if(fd);
	/* Vnode-less descriptors and bad ones. */
	CHECK_ERR(openat(pc_pipefd(), "", O_EMPTY_PATH | O_RDONLY), ENOTDIR);
	CHECK_ERR(openat(pc_sockfd(), "", O_EMPTY_PATH | O_RDONLY), ENOTDIR);
	CHECK_ERR(openat(-1, "", O_EMPTY_PATH | O_RDONLY), EBADF);
	CHECK_ERR(openat(1000000, "", O_EMPTY_PATH | O_RDONLY), EBADF);
	/* O_EMPTY_PATH | O_DIRECTORY on a file. */
	CHECK_ERR(openat(pfd, "", O_EMPTY_PATH | O_RDONLY | O_DIRECTORY),
	    ENOTDIR);
	close(pfd);
	close(lfd);
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(resolve_beneath);
ATF_TC_BODY(resolve_beneath, tc)
{
	int dfd, fd;

	pc_mkfile("outside", "o\n");
	pc_mkdir("top");
	pc_mkdir("top/sub");
	pc_mkfile("top/f", "f\n");
	pc_mkfile("top/sub/g", "g\n");
	pc_symlink("../outside", "top/up");
	pc_symlink("/etc/passwd", "top/abs");
	pc_symlink("sub/g", "top/down");
	pc_symlink("../f", "top/sub/back");
	dfd = open("top", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);

	fd = openat(dfd, "f", O_RDONLY | O_RESOLVE_BENEATH);
	CHECK_OK(fd);
	close_if(fd);
	fd = openat(dfd, "sub/../f", O_RDONLY | O_RESOLVE_BENEATH);
	CHECK_OK(fd);
	close_if(fd);
	fd = openat(dfd, "down", O_RDONLY | O_RESOLVE_BENEATH);
	CHECK_OK(fd);
	close_if(fd);
	/* A link that goes up but stays beneath dfd. */
	fd = openat(dfd, "sub/back", O_RDONLY | O_RESOLVE_BENEATH);
	CHECK_OK(fd);
	close_if(fd);

	CHECK_ERR(openat(dfd, "../outside", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(openat(dfd, "sub/../../outside", O_RDONLY |
	    O_RESOLVE_BENEATH), ENOTCAPABLE);
	CHECK_ERR(openat(dfd, "..", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(openat(dfd, "/etc/passwd", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(openat(dfd, "up", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(openat(dfd, "abs", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	/* O_CREAT under O_RESOLVE_BENEATH: refused before anything exists. */
	CHECK_ERR(openat(dfd, "../made", O_RDWR | O_CREAT | O_RESOLVE_BENEATH,
	    0644), ENOTCAPABLE);
	ATF_CHECK(access("made", F_OK) == -1);
	/* AT_FDCWD: beneath the current directory. */
	fd = openat(AT_FDCWD, "outside", O_RDONLY | O_RESOLVE_BENEATH);
	CHECK_OK(fd);
	close_if(fd);
	CHECK_ERR(openat(AT_FDCWD, "../x", O_RDONLY | O_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(open("/", O_RDONLY | O_RESOLVE_BENEATH), ENOTCAPABLE);
	/* The same lookups without the flag succeed. */
	fd = openat(dfd, "../outside", O_RDONLY);
	CHECK_OK(fd);
	close_if(fd);
	fd = openat(dfd, "up", O_RDONLY);
	CHECK_OK(fd);
	close_if(fd);
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(fd_resolve_beneath);
ATF_TC_BODY(fd_resolve_beneath, tc)
{
	int dfd, fd, sub;

	pc_mkfile("outside", "o\n");
	pc_mkdir("top");
	pc_mkdir("top/sub");
	pc_mkdir("top/sub/inner");
	pc_mkfile("top/f", "f\n");
	dfd = open("top", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);
	ATF_REQUIRE(fcntl(dfd, F_SETFD, FD_RESOLVE_BENEATH) == 0);
	ATF_CHECK((fcntl(dfd, F_GETFD) & FD_RESOLVE_BENEATH) != 0);
	/* Every lookup relative to the descriptor is beneath it. */
	CHECK_ERR(openat(dfd, "../outside", O_RDONLY), ENOTCAPABLE);
	/*
	 * An absolute path never consults the descriptor (namei_setup takes
	 * the root before fgetvp_lookup), so the descriptor's
	 * UF_RESOLVE_BENEATH does not apply to it.
	 */
	fd = openat(dfd, "/", O_RDONLY | O_DIRECTORY);
	CHECK_OK(fd);
	close_if(fd);
	fd = openat(dfd, "f", O_RDONLY);
	CHECK_OK(fd);
	close_if(fd);
	{
		struct stat sb;

		CHECK_ERR(fstatat(dfd, "../outside", &sb, 0), ENOTCAPABLE);
		CHECK_OK(fstatat(dfd, "f", &sb, 0));
	}
	/* A directory opened through it inherits the restriction. */
	sub = openat(dfd, "sub", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(sub >= 0);
	ATF_CHECK((fcntl(sub, F_GETFD) & FD_RESOLVE_BENEATH) != 0);
	CHECK_ERR(openat(sub, "../f", O_RDONLY), ENOTCAPABLE);
	/* fchdir to a beneath-only descriptor is refused. */
	CHECK_ERR(fchdir(dfd), ENOTCAPABLE);
	/* A directory cannot be renamed relative to it. */
	CHECK_ERR(renameat(dfd, "sub/inner", dfd, "moved"), ENOTCAPABLE);
	ATF_CHECK(access("top/sub/inner", F_OK) == 0);
	/* A regular file can. */
	CHECK_OK(renameat(dfd, "f", dfd, "g"));
	close(sub);
	close(dfd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, flag_validation_first);
	ATF_TP_ADD_TC(tp, creat_excl);
	ATF_TP_ADD_TC(tp, creat_follows_dangling);
	ATF_TP_ADD_TC(tp, creat_directory_matrix);
	ATF_TP_ADD_TC(tp, trunc);
	ATF_TP_ADD_TC(tp, nofollow);
	ATF_TP_ADD_TC(tp, o_path);
	ATF_TP_ADD_TC(tp, empty_path_reopen);
	ATF_TP_ADD_TC(tp, resolve_beneath);
	ATF_TP_ADD_TC(tp, fd_resolve_beneath);
	return (atf_no_error());
}
