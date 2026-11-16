/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Namespace system calls (mkdir, mkfifo, mknod, unlink, rmdir, funlinkat,
 * rename, renameat2, link, linkat, symlink) and the order in which they
 * report several simultaneous errors.
 *
 * What it tries to break: each of these became a kern_X wrapper declaring
 * a lookup intent (two slots for rename and link), symlinkat now copies
 * the target before the impl for attached processes, funlinkat consults a
 * served descriptor before getvnode_path.  The unattached answers, and in
 * particular which errno wins when two arguments are wrong, must be those
 * of 3f330ee172d (flag checks, then the first path's copy and lookup, then
 * the second's).
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

ATF_TC_WITHOUT_HEAD(mkdir_family);
ATF_TC_BODY(mkdir_family, tc)
{
	struct stat sb;

	pc_mkdir("d");
	pc_mkfile("f", NULL);
	pc_symlink("nowhere", "dangling");
	pc_symlink("d", "ld");
	CHECK_ERR(mkdir("d", 0755), EEXIST);
	CHECK_ERR(mkdir("f", 0755), EEXIST);
	/* CREATE does not follow the final link: it exists. */
	CHECK_ERR(mkdir("dangling", 0755), EEXIST);
	ATF_CHECK(access("nowhere", F_OK) == -1);
	CHECK_ERR(mkdir("ld", 0755), EEXIST);
	CHECK_ERR(mkdir("nodir/x", 0755), ENOENT);
	CHECK_ERR(mkdirat(AT_FDCWD, "f/x", 0755), ENOTDIR);
	umask(022);
	CHECK_OK(mkdir("m", 0777));
	ATF_REQUIRE(stat("m", &sb) == 0);
	ATF_CHECK(S_ISDIR(sb.st_mode));
	ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0755);
	/* An intermediate link is followed. */
	CHECK_OK(mkdir("ld/sub", 0700));
	ATF_CHECK(stat("d/sub", &sb) == 0 && S_ISDIR(sb.st_mode));
	/* mkfifo / mknod S_IFIFO */
	CHECK_OK(mkfifo("fifo", 0666));
	ATF_REQUIRE(lstat("fifo", &sb) == 0);
	ATF_CHECK(S_ISFIFO(sb.st_mode));
	ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0644);
	CHECK_ERR(mkfifo("fifo", 0644), EEXIST);
	CHECK_ERR(mkfifo("dangling", 0644), EEXIST);
	CHECK_OK(mknod("fifo2", S_IFIFO | 0600, 0));
	ATF_REQUIRE(lstat("fifo2", &sb) == 0);
	ATF_CHECK(S_ISFIFO(sb.st_mode));
	CHECK_ERR(mknodat(AT_FDCWD, "fifo2", S_IFIFO | 0600, 0), EEXIST);
}

ATF_TC_WITHOUT_HEAD(mknod_types);
ATF_TC_BODY(mknod_types, tc)
{

	/* The type is checked before the lookup (kern_mknodat). */
	CHECK_ERR(mknod("nodir/x", S_IFREG | 0644, 0), EINVAL);
	CHECK_ERR(mknod("nodir/x", S_IFDIR | 0755, 0), EINVAL);
	CHECK_ERR(mknod("nodir/x", S_IFLNK | 0755, 0), EINVAL);
	CHECK_ERR(mknod("nodir/x", S_IFSOCK | 0755, 0), EINVAL);
	CHECK_ERR(mknod(NULL, 0, 0), EINVAL);
	/* S_IFIFO with a device number falls through to EINVAL. */
	CHECK_ERR(mknod("x", S_IFIFO | 0644, 1), EINVAL);
	ATF_CHECK(access("x", F_OK) == -1);
	if (!pc_is_root()) {
		/* Privilege before the lookup. */
		CHECK_ERR(mknod("nodir/x", S_IFCHR | 0644, 0), EPERM);
		CHECK_ERR(mknod(NULL, S_IFBLK | 0644, 0), EPERM);
		CHECK_ERR(mknod("x", S_IFWHT | 0644, 0), EPERM);
	} else {
		/* Privileged: VNOVAL as the device is EINVAL, then lookup. */
		CHECK_ERR(mknod("nodir/x", S_IFCHR | 0644, (dev_t)-1 /* VNOVAL */),
		    EINVAL);
		CHECK_ERR(mknod("nodir/x", S_IFCHR | 0644, 0), ENOENT);
	}
	ATF_CHECK(pc_dirent_count(".") == 0);
}

ATF_TC_WITHOUT_HEAD(unlink_rmdir);
ATF_TC_BODY(unlink_rmdir, tc)
{

	pc_mkdir("d");
	pc_mkdir("full");
	pc_mkfile("full/f", NULL);
	pc_mkfile("f", NULL);
	pc_symlink("d", "ld");
	pc_symlink("f", "lf");
	CHECK_ERR(unlink("d"), EPERM);
	CHECK_ERR(unlinkat(AT_FDCWD, "d", 0), EPERM);
	CHECK_ERR(rmdir("f"), ENOTDIR);
	CHECK_ERR(unlinkat(AT_FDCWD, "f", AT_REMOVEDIR), ENOTDIR);
	/* rmdir does not follow the final link. */
	CHECK_ERR(rmdir("ld"), ENOTDIR);
	/* TBC: ZFS may report EEXIST, which POSIX also allows. */
	{
		int e = ERRNO_OF(rmdir("full"));

		ATF_CHECK_MSG(e == ENOTEMPTY || e == EEXIST, "rmdir: %d", e);
	}
	CHECK_ERR(rmdir("missing"), ENOENT);
	CHECK_ERR(unlink("missing"), ENOENT);
	CHECK_ERR(unlinkat(AT_FDCWD, "f", 0x1), EINVAL);
	CHECK_ERR(unlinkat(-1, NULL, AT_REMOVEDIR | 0x1), EINVAL);
	CHECK_ERR(unlinkat(AT_FDCWD, "../x", AT_RESOLVE_BENEATH), ENOTCAPABLE);
	/* unlink removes the link, not its target. */
	CHECK_OK(unlink("lf"));
	ATF_CHECK(access("f", F_OK) == 0);
	CHECK_OK(unlink("ld"));
	ATF_CHECK(access("d", F_OK) == 0);
	/* An intermediate link is followed. */
	pc_symlink("full", "lfull");
	CHECK_OK(unlink("lfull/f"));
	CHECK_OK(rmdir("full"));
	CHECK_OK(unlinkat(AT_FDCWD, "d", AT_REMOVEDIR));
	CHECK_OK(unlink("f"));
	CHECK_OK(unlink("lfull"));
	ATF_CHECK(pc_dirent_count(".") == 0);
}

ATF_TC_WITHOUT_HEAD(funlinkat_fd);
ATF_TC_BODY(funlinkat_fd, tc)
{
	int a, b, da, db, pa;

	pc_mkfile("a", NULL);
	pc_mkfile("b", NULL);
	pc_mkdir("da");
	pc_mkdir("db");
	a = open("a", O_RDONLY);
	b = open("b", O_RDONLY);
	pa = open("a", O_PATH);
	da = open("da", O_DIRECTORY | O_RDONLY);
	db = open("db", O_PATH | O_DIRECTORY);
	ATF_REQUIRE(a >= 0 && b >= 0 && pa >= 0 && da >= 0 && db >= 0);
	/* The descriptor is checked before the path is looked up. */
	CHECK_ERR(funlinkat(AT_FDCWD, "missing", pc_pipefd(), 0), EINVAL);
	CHECK_ERR(funlinkat(AT_FDCWD, NULL, pc_sockfd(), 0), EINVAL);
	CHECK_ERR(funlinkat(AT_FDCWD, "missing", -1, 0), EBADF);
	CHECK_ERR(funlinkat(AT_FDCWD, "missing", 1000000, 0), EBADF);
	CHECK_ERR(funlinkat(AT_FDCWD, "missing", a, 0), ENOENT);
	/* A different file: EDEADLK, nothing removed. */
	CHECK_ERR(funlinkat(AT_FDCWD, "a", b, 0), EDEADLK);
	ATF_CHECK(access("a", F_OK) == 0);
	/* The directory variant uses getvnode: O_PATH is EBADF. */
	CHECK_ERR(funlinkat(AT_FDCWD, "db", db, AT_REMOVEDIR), EBADF);
	CHECK_ERR(funlinkat(AT_FDCWD, "db", pc_pipefd(), AT_REMOVEDIR),
	    EINVAL);
	CHECK_ERR(funlinkat(AT_FDCWD, "db", da, AT_REMOVEDIR), EDEADLK);
	ATF_CHECK(access("db", F_OK) == 0);
	/* Flags before the descriptor. */
	CHECK_ERR(funlinkat(AT_FDCWD, "a", pc_pipefd(), 0x1), EINVAL);
	/* The file variant accepts O_PATH. */
	CHECK_OK(funlinkat(AT_FDCWD, "a", pa, 0));
	ATF_CHECK(access("a", F_OK) == -1);
	CHECK_OK(funlinkat(AT_FDCWD, "b", b, 0));
	CHECK_OK(funlinkat(AT_FDCWD, "da", da, AT_REMOVEDIR));
	ATF_CHECK(access("da", F_OK) == -1);
	/* The file is gone: the descriptor of the unlinked a is still a. */
	close(a);
	close(b);
	close(pa);
	close(da);
	close(db);
}

ATF_TC_WITHOUT_HEAD(rename_semantics);
ATF_TC_BODY(rename_semantics, tc)
{
	ino_t ia, ib;

	pc_mkfile("a", "a\n");
	pc_mkfile("b", "bb\n");
	pc_mkdir("d");
	pc_mkdir("e");
	pc_mkdir("full");
	pc_mkfile("full/x", NULL);
	pc_symlink("a", "la");

	ia = pc_ino("a", true);
	CHECK_OK(rename("a", "b"));
	ATF_CHECK_EQ(pc_ino("b", true), ia);
	ATF_CHECK(access("a", F_OK) == -1);
	CHECK_ERR(rename("d", "b"), ENOTDIR);
	CHECK_ERR(rename("b", "d"), EISDIR);
	/* TBC: ZFS may report EEXIST, which POSIX also allows. */
	{
		int e = ERRNO_OF(rename("d", "full"));

		ATF_CHECK_MSG(e == ENOTEMPTY || e == EEXIST, "rename: %d", e);
	}
	/* Into its own child: fvp == tdvp. */
	CHECK_ERR(rename("d", "d/x"), EINVAL);
	ia = pc_ino("d", true);
	CHECK_OK(rename("d", "e"));
	ATF_CHECK_EQ(pc_ino("e", true), ia);
	/* A directory to a new name with a trailing slash. */
	CHECK_OK(rename("e", "g/"));
	ATF_CHECK(access("g", F_OK) == 0);
	/* Two links to one file: nothing happens, both remain. */
	ATF_REQUIRE(link("b", "b2") == 0);
	CHECK_OK(rename("b", "b2"));
	ATF_CHECK(access("b", F_OK) == 0 && access("b2", F_OK) == 0);
	CHECK_OK(rename("b", "b"));
	ATF_CHECK(access("b", F_OK) == 0);
	/* rename moves a symlink itself (the source is not followed). */
	ib = pc_ino("la", true);
	CHECK_OK(rename("la", "lb"));
	ATF_CHECK_EQ(pc_ino("lb", true), ib);
	CHECK_ERR(rename("missing", "x"), ENOENT);
	CHECK_ERR(rename("b", "nodir/x"), ENOENT);
	CHECK_ERR(rename("b", "b2/x"), ENOTDIR);
	ATF_CHECK(access("b", F_OK) == 0);
}

/* Whether this file system implements AT_RENAME_EXCHANGE. */
static int
exchange_probe(void)
{
	int e;

	pc_mkfile("probe1", NULL);
	pc_mkfile("probe2", NULL);
	e = ERRNO_OF(renameat2(AT_FDCWD, "probe1", AT_FDCWD, "probe2",
	    AT_RENAME_EXCHANGE));
	pc_remove("probe1");
	pc_remove("probe2");
	return (e);
}

ATF_TC_WITHOUT_HEAD(renameat2_flags);
ATF_TC_BODY(renameat2_flags, tc)
{
	ino_t ia, ib;
	int e;

	pc_mkfile("a", "a\n");
	pc_mkfile("b", "b\n");
	/* Flag errors before any lookup. */
	CHECK_ERR(renameat2(-1, NULL, -1, NULL, AT_RENAME_NOREPLACE |
	    AT_RENAME_EXCHANGE), EINVAL);
	CHECK_ERR(renameat2(-1, NULL, -1, NULL, 0x4), EINVAL);
	CHECK_ERR(renameat2(-1, NULL, -1, NULL, 0x80000000), EINVAL);
	/* NOREPLACE */
	CHECK_ERR(renameat2(AT_FDCWD, "a", AT_FDCWD, "b", AT_RENAME_NOREPLACE),
	    EEXIST);
	ATF_CHECK(access("a", F_OK) == 0);
	ia = pc_ino("a", true);
	CHECK_OK(renameat2(AT_FDCWD, "a", AT_FDCWD, "c", AT_RENAME_NOREPLACE));
	ATF_CHECK_EQ(pc_ino("c", true), ia);
	CHECK_ERR(renameat2(AT_FDCWD, "missing", AT_FDCWD, "b",
	    AT_RENAME_NOREPLACE), ENOENT);
	/*
	 * EXCHANGE: the source is looked up for RENAME, a missing one is
	 * ENOENT before the target is looked at.  The pre-1c kernel panics
	 * here under MAC (kern_renameat_mac dereferences the NULL ni_vp).
	 */
	if (pc_pre1c(tc))
		fprintf(stderr, "pre1c: EXCHANGE missing-source rows skipped: "
		    "they panic that kernel (/home/koryheard/5bsd-issues/"
		    "2026-11-08-renameat2-exchange-mac-panic.md)\n");
	else {
		CHECK_ERR(renameat2(AT_FDCWD, "missing", -1, "b",
		    AT_RENAME_EXCHANGE), ENOENT);
		CHECK_ERR(renameat2(AT_FDCWD, "missing", AT_FDCWD, "b",
		    AT_RENAME_EXCHANGE), ENOENT);
	}
	/* A missing target: ENOENT (kern_renameat), nothing moved. */
	CHECK_ERR(renameat2(AT_FDCWD, "b", AT_FDCWD, "missing",
	    AT_RENAME_EXCHANGE), ENOENT);
	ATF_CHECK(access("b", F_OK) == 0);
	e = exchange_probe();
	if (e != 0) {
		/* TBC: the file system's VOP_RENAME refuses the flag. */
		atf_tc_skip("AT_RENAME_EXCHANGE not implemented here: %s",
		    strerror(e));
	}
	ia = pc_ino("b", true);
	ib = pc_ino("c", true);
	CHECK_OK(renameat2(AT_FDCWD, "b", AT_FDCWD, "c", AT_RENAME_EXCHANGE));
	ATF_CHECK_EQ(pc_ino("b", true), ib);
	ATF_CHECK_EQ(pc_ino("c", true), ia);
}

ATF_TC_WITHOUT_HEAD(link_semantics);
ATF_TC_BODY(link_semantics, tc)
{
	struct stat sb;

	pc_mkfile("f", NULL);
	pc_mkdir("d");
	pc_symlink("f", "lf");
	pc_symlink("nowhere", "dangling");
	CHECK_OK(link("f", "f2"));
	ATF_CHECK_EQ(pc_ino("f2", true), pc_ino("f", true));
	ATF_REQUIRE(stat("f", &sb) == 0);
	ATF_CHECK_EQ(sb.st_nlink, 2);
	CHECK_ERR(link("f", "f2"), EEXIST);
	CHECK_ERR(link("f", "d"), EEXIST);
	CHECK_ERR(link("d", "d2"), EPERM);
	CHECK_ERR(link("missing", "x"), ENOENT);
	CHECK_ERR(link("f", "nodir/x"), ENOENT);
	/* link(2) follows a final symlink (sys_link: AT_SYMLINK_FOLLOW). */
	CHECK_OK(link("lf", "viaf"));
	ATF_CHECK_EQ(pc_ino("viaf", true), pc_ino("f", true));
	CHECK_ERR(link("dangling", "x"), ENOENT);
	/* linkat without the flag links the symlink itself. */
	CHECK_OK(linkat(AT_FDCWD, "lf", AT_FDCWD, "lf2", 0));
	ATF_CHECK_EQ(pc_ino("lf2", true), pc_ino("lf", true));
	CHECK_OK(linkat(AT_FDCWD, "dangling", AT_FDCWD, "dangling2", 0));
	CHECK_OK(linkat(AT_FDCWD, "lf", AT_FDCWD, "viaf2", AT_SYMLINK_FOLLOW));
	ATF_CHECK_EQ(pc_ino("viaf2", true), pc_ino("f", true));
	CHECK_ERR(linkat(AT_FDCWD, "f", AT_FDCWD, "x", 0x1), EINVAL);
	/* CREATE of the new name does not follow: an existing link exists. */
	CHECK_ERR(link("f", "dangling"), EEXIST);
	ATF_CHECK(access("nowhere", F_OK) == -1);
}

ATF_TC_WITHOUT_HEAD(symlink_semantics);
ATF_TC_BODY(symlink_semantics, tc)
{
	char buf[MAXPATHLEN + 1], *target;
	struct stat sb;
	ssize_t n;
	int e;

	pc_mkfile("f", NULL);
	CHECK_ERR(symlink("t", "f"), EEXIST);
	CHECK_ERR(symlink("t", "nodir/x"), ENOENT);
	/* The target is stored verbatim, never resolved. */
	CHECK_OK(symlink("a//b/../c/./", "weird"));
	n = readlink("weird", buf, sizeof(buf));
	ATF_CHECK_EQ(n, (ssize_t)strlen("a//b/../c/./"));
	ATF_CHECK(n > 0 && memcmp(buf, "a//b/../c/./", (size_t)n) == 0);
	/* The target is copied before the link name is looked up. */
	CHECK_ERR(symlink(NULL, "nodir/x"), EFAULT);
	CHECK_ERR(symlink(pc_unmapped(), NULL), EFAULT);
	CHECK_ERR(symlink(pc_straddle("abc", false), "x"), EFAULT);
	ATF_CHECK(access("x", F_OK) == -1 && errno == ENOENT);
	target = malloc(MAXPATHLEN + 1);
	ATF_REQUIRE(target != NULL);
	pc_name(target, MAXPATHLEN, 't');
	CHECK_ERR(symlink(target, NULL), ENAMETOOLONG);
	CHECK_ERR(symlinkat(target, -1, "x"), ENAMETOOLONG);
	/*
	 * MAXPATHLEN - 1 bytes is a valid argument.  TBC: whether the file
	 * system stores a target that long (UFS, ZFS and tmpfs do).
	 */
	pc_name(target, MAXPATHLEN - 1, 't');
	e = ERRNO_OF(symlink(target, "long"));
	ATF_CHECK_MSG(e == 0 || e == ENAMETOOLONG,
	    "symlink with a MAXPATHLEN - 1 target: %s", strerror(e));
	if (e == 0) {
		n = readlink("long", buf, sizeof(buf));
		ATF_CHECK_EQ(n, MAXPATHLEN - 1);
		/* Following it: the expanded path does not fit (ENAMETOOLONG)
		 * once the remaining path is appended. */
		CHECK_ERR(stat("long", &sb), ENAMETOOLONG);
	}
	free(target);
	/*
	 * An empty target.  TBC: the file systems accept it; following an
	 * empty link is ENOENT (namei_follow_link, linklen == 0).
	 */
	e = ERRNO_OF(symlink("", "empty"));
	if (e == 0) {
		CHECK_ERR(stat("empty", &sb), ENOENT);
		CHECK_ERR(stat("empty/x", &sb), ENOENT);
		CHECK_OK(lstat("empty", &sb));
		ATF_CHECK(S_ISLNK(sb.st_mode));
		ATF_CHECK_EQ(readlink("empty", buf, sizeof(buf)), 0);
	} else
		ATF_CHECK_MSG(e == EINVAL || e == ENOENT,
		    "symlink with an empty target: %s", strerror(e));
}

ATF_TC_WITHOUT_HEAD(error_order_rename_link);
ATF_TC_BODY(error_order_rename_link, tc)
{

	pc_mkfile("exists", NULL);
	pc_mkdir("d");
	/* renameat: the source's lookup comes first. */
	CHECK_ERR(renameat(AT_FDCWD, "missing", -1, "x"), ENOENT);
	CHECK_ERR(renameat(AT_FDCWD, "missing", pc_pipefd(), "x"), ENOENT);
	CHECK_ERR(renameat(AT_FDCWD, "exists", -1, "x"), EBADF);
	CHECK_ERR(renameat(AT_FDCWD, "exists", pc_pipefd(), "x"), ENOTDIR);
	CHECK_ERR(renameat(-1, "missing", -1, "x"), EBADF);
	CHECK_ERR(renameat(-1, "missing", AT_FDCWD, NULL), EBADF);
	CHECK_ERR(renameat(AT_FDCWD, NULL, -1, "x"), EFAULT);
	CHECK_ERR(rename("missing", ""), ENOENT);
	CHECK_ERR(rename("exists", ""), ENOENT);
	CHECK_ERR(rename("", "x"), ENOENT);
	CHECK_ERR(rename("exists", NULL), EFAULT);
	CHECK_ERR(rename("missing", NULL), ENOENT);
	ATF_CHECK(access("exists", F_OK) == 0);
	/* linkat: flags, then the source, the directory test, the target. */
	CHECK_ERR(linkat(-1, NULL, -1, NULL, 0x1), EINVAL);
	CHECK_ERR(linkat(AT_FDCWD, "missing", AT_FDCWD, "", 0), ENOENT);
	CHECK_ERR(linkat(AT_FDCWD, "exists", AT_FDCWD, "", 0), ENOENT);
	CHECK_ERR(linkat(AT_FDCWD, "missing", -1, "x", 0), ENOENT);
	CHECK_ERR(linkat(AT_FDCWD, "exists", -1, "x", 0), EBADF);
	CHECK_ERR(linkat(AT_FDCWD, "exists", AT_FDCWD, NULL, 0), EFAULT);
	CHECK_ERR(linkat(AT_FDCWD, "d", -1, "x", 0), EPERM);
	CHECK_ERR(linkat(AT_FDCWD, "d", AT_FDCWD, NULL, 0), EPERM);
	CHECK_ERR(link("", "x"), ENOENT);
	CHECK_ERR(link(NULL, ""), EFAULT);
	/* symlinkat: the target's copy, then the name's lookup. */
	CHECK_ERR(symlinkat(NULL, -1, "x"), EFAULT);
	CHECK_ERR(symlinkat("t", -1, "x"), EBADF);
	CHECK_ERR(symlinkat("t", -1, NULL), EFAULT);
	CHECK_ERR(symlinkat("t", -1, ""), ENOENT);
	/* mkdirat / mkfifoat / mknodat */
	CHECK_ERR(mkdirat(-1, NULL, 0755), EFAULT);
	CHECK_ERR(mkdirat(-1, "", 0755), ENOENT);
	CHECK_ERR(mkdirat(-1, "x", 0755), EBADF);
	CHECK_ERR(mkfifoat(-1, "x", 0644), EBADF);
	CHECK_ERR(mknodat(-1, "x", S_IFREG, 0), EINVAL);
	CHECK_ERR(mknodat(-1, "x", S_IFIFO, 0), EBADF);
	/* unlinkat / funlinkat */
	CHECK_ERR(unlinkat(-1, "", 0), ENOENT);
	CHECK_ERR(unlinkat(-1, "x", 0), EBADF);
	CHECK_ERR(funlinkat(-1, "x", pc_pipefd(), 0), EINVAL);
	ATF_CHECK(access("x", F_OK) == -1);
}

ATF_TC_WITHOUT_HEAD(error_order_attr);
ATF_TC_BODY(error_order_attr, tc)
{
	struct timeval tv[2];
	struct timespec ts[2];
	char name[EXTATTR_MAXNAMELEN + 2], buf[16];
	int ifd;

	pc_mkfile("exists", NULL);
	pc_mkdir("d");
	/* utimes family: the times are copied and checked before namei. */
	CHECK_ERR(utimes("missing", (const struct timeval *)(uintptr_t)
	    pc_unmapped()), EFAULT);
	CHECK_ERR(lutimes("missing", (const struct timeval *)(uintptr_t)
	    pc_unmapped()), EFAULT);
	CHECK_ERR(futimesat(-1, "missing", (const struct timeval *)(uintptr_t)
	    pc_unmapped()), EFAULT);
	tv[0].tv_sec = tv[1].tv_sec = 0;
	tv[0].tv_usec = 0;
	tv[1].tv_usec = 1000000;
	CHECK_ERR(utimes("missing", tv), EINVAL);
	CHECK_ERR(utimes(NULL, tv), EINVAL);
	CHECK_ERR(lutimes("missing", tv), EINVAL);
	CHECK_ERR(futimesat(-1, "x", tv), EINVAL);
	tv[1].tv_usec = -1;
	CHECK_ERR(utimes("exists", tv), EINVAL);
	tv[1].tv_usec = 0;
	CHECK_ERR(utimes("missing", tv), ENOENT);
	CHECK_ERR(utimes(NULL, tv), EFAULT);
	/* utimensat: flags, then the times, then the path. */
	CHECK_ERR(utimensat(-1, NULL, (const struct timespec *)(uintptr_t)
	    pc_unmapped(), 0x8000), EINVAL);
	CHECK_ERR(utimensat(-1, "x", (const struct timespec *)(uintptr_t)
	    pc_unmapped(), 0), EFAULT);
	ts[0].tv_sec = ts[1].tv_sec = 0;
	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_nsec = -5;
	CHECK_ERR(utimensat(-1, NULL, ts, 0), EINVAL);
	ts[1].tv_nsec = 1000000000L;
	CHECK_ERR(utimensat(AT_FDCWD, "missing", ts, 0), EINVAL);
	ts[0].tv_nsec = UTIME_NOW;
	CHECK_ERR(utimensat(AT_FDCWD, "missing", ts, 0), EINVAL);
	/* UTIME_OMIT twice still looks the path up. */
	ts[0].tv_nsec = ts[1].tv_nsec = UTIME_OMIT;
	CHECK_ERR(utimensat(AT_FDCWD, "missing", ts, 0), ENOENT);
	CHECK_ERR(utimensat(-1, "x", ts, 0), EBADF);
	CHECK_OK(utimensat(AT_FDCWD, "exists", ts, 0));
	/* truncate: a negative length before the lookup. */
	CHECK_ERR(truncate("missing", -1), EINVAL);
	CHECK_ERR(truncate(NULL, -1), EINVAL);
	CHECK_ERR(truncate("missing", 0), ENOENT);
	CHECK_ERR(truncate("d", 0), EISDIR);
	/* access: flags and mode before the lookup. */
	CHECK_ERR(faccessat(-1, NULL, 0x100, 0), EINVAL);
	CHECK_ERR(faccessat(-1, NULL, F_OK, 0x8), EINVAL);
	CHECK_ERR(access(NULL, 0x1000), EINVAL);
	CHECK_ERR(access("missing", R_OK | 0x10), EINVAL);
	CHECK_ERR(access(NULL, F_OK), EFAULT);
	/* chmod/chown/chflags *at: the flag mask first. */
	CHECK_ERR(fchmodat(-1, NULL, 0644, 0x1), EINVAL);
	CHECK_ERR(fchownat(-1, NULL, 0, 0, 0x1), EINVAL);
	CHECK_ERR(chflagsat(-1, NULL, 0, 0x1), EINVAL);
	{
		struct stat sb;

		CHECK_ERR(fstatat(-1, NULL, &sb, 0x1), EINVAL);
	}
	/* extattr: the attribute name is copied before the path. */
	CHECK_ERR(extattr_get_file("missing", EXTATTR_NAMESPACE_USER,
	    pc_unmapped(), buf, sizeof(buf)), EFAULT);
	CHECK_ERR(extattr_set_file(NULL, EXTATTR_NAMESPACE_USER,
	    pc_unmapped(), buf, sizeof(buf)), EFAULT);
	CHECK_ERR(extattr_delete_link("missing", EXTATTR_NAMESPACE_USER,
	    NULL), EFAULT);
	pc_name(name, EXTATTR_MAXNAMELEN + 1, 'a');
	CHECK_ERR(extattr_get_file("missing", EXTATTR_NAMESPACE_USER, name,
	    buf, sizeof(buf)), ENAMETOOLONG);
	CHECK_ERR(extattr_get_file("missing", EXTATTR_NAMESPACE_USER, "a",
	    buf, sizeof(buf)), ENOENT);
	CHECK_ERR(extattr_list_file(NULL, EXTATTR_NAMESPACE_USER, buf,
	    sizeof(buf)), EFAULT);
	/* ACL set: the lookup comes before the ACL copy. */
	CHECK_ERR(syscall(SYS___acl_set_file, "missing", ACL_TYPE_ACCESS,
	    pc_unmapped()), ENOENT);
	CHECK_ERR(syscall(SYS___acl_set_file, NULL, ACL_TYPE_ACCESS,
	    pc_unmapped()), EFAULT);
	CHECK_ERR(syscall(SYS___acl_get_file, "missing", ACL_TYPE_ACCESS,
	    pc_unmapped()), ENOENT);
	/* inotify: the mask, then the inotify descriptor, then the path. */
	ifd = inotify_init1(IN_CLOEXEC);
	ATF_REQUIRE(ifd >= 0);
	CHECK_ERR(inotify_add_watch(ifd, NULL, 0), EINVAL);
	CHECK_ERR(inotify_add_watch(ifd, NULL, IN_MASK_ADD | IN_MASK_CREATE |
	    IN_OPEN), EINVAL);
	CHECK_ERR(inotify_add_watch(-1, "missing", IN_ALL_EVENTS), EBADF);
	CHECK_ERR(inotify_add_watch(pc_pipefd(), "missing", IN_ALL_EVENTS),
	    EINVAL);
	CHECK_ERR(inotify_add_watch(ifd, NULL, IN_ALL_EVENTS), EFAULT);
	CHECK_ERR(inotify_add_watch_at(ifd, -1, "missing", IN_ALL_EVENTS),
	    EBADF);
	CHECK_ERR(inotify_add_watch(ifd, "missing", IN_ALL_EVENTS), ENOENT);
	CHECK_ERR(inotify_add_watch(ifd, "exists", IN_ALL_EVENTS | IN_ONLYDIR),
	    ENOTDIR);
	close(ifd);
	/* __realpathat: flags first. */
	CHECK_ERR(syscall(SYS___realpathat, -1, NULL, NULL, 0, 1), EINVAL);
	/* chroot: the lookup before the privilege check. */
	CHECK_ERR(chroot("missing"), ENOENT);
	CHECK_ERR(chroot(NULL), EFAULT);
	if (!pc_is_root()) {
		int unpriv;

		if (pc_sysctl_get("security.bsd.unprivileged_chroot",
		    &unpriv) && unpriv == 0) {
			CHECK_ERR(chroot("exists"), EPERM);
			CHECK_ERR(chroot("d"), EPERM);
		}
		/* getfh: flags, then privilege, then the path. */
		{
			fhandle_t fh;

			memset(&fh, 0, sizeof(fh));

			CHECK_ERR(getfhat(AT_FDCWD, "missing", &fh, 0x1),
			    EINVAL);
			CHECK_ERR(getfh("missing", &fh), EPERM);
			CHECK_ERR(fhopen(&fh, O_CREAT), EPERM);
			CHECK_ERR(fhlink(&fh, "x"), EPERM);
		}
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mkdir_family);
	ATF_TP_ADD_TC(tp, mknod_types);
	ATF_TP_ADD_TC(tp, unlink_rmdir);
	ATF_TP_ADD_TC(tp, funlinkat_fd);
	ATF_TP_ADD_TC(tp, rename_semantics);
	ATF_TP_ADD_TC(tp, renameat2_flags);
	ATF_TP_ADD_TC(tp, link_semantics);
	ATF_TP_ADD_TC(tp, symlink_semantics);
	ATF_TP_ADD_TC(tp, error_order_rename_link);
	ATF_TP_ADD_TC(tp, error_order_attr);
	return (atf_no_error());
}
