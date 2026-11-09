/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Directory descriptors and AT_EMPTY_PATH for every *at path call.
 *
 * What it tries to break: fgetvp_lookup became fgetvp_lookup_start, which
 * treats a vnode-less descriptor specially when it is a served directory;
 * fchmodat, fchownat, chflagsat, utimensat, faccessat, readlinkat and
 * linkat gained an AT_EMPTY_PATH fallback taken after namei's ENOTDIR for
 * served descriptors.  For ordinary descriptors (pipes, sockets, kqueues,
 * files, O_PATH, O_SEARCH, closed and reused numbers) the answers must be
 * those of 3f330ee172d: EBADF for a bad number, ENOTDIR for a vnode-less
 * or non-directory start, the empty-path ENOENT before the descriptor is
 * looked at, and fstatat(AT_EMPTY_PATH)'s kern_fstat fallback (the only
 * one that existed).
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

enum at_kind { A_FILE, A_DIR, A_NEW, A_LINK };

struct at_op {
	const char	*name;
	enum at_kind	 kind;
	int		(*fn)(int, const char *);
};

static int inofd = -1;

static int
at_openat(int d, const char *p)
{
	int fd;

	fd = openat(d, p, O_RDONLY);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
at_fstatat(int d, const char *p)
{
	struct stat sb;

	return (fstatat(d, p, &sb, 0));
}

static int
at_faccessat(int d, const char *p)
{

	return (faccessat(d, p, R_OK, 0));
}

static int
at_fchmodat(int d, const char *p)
{

	return (fchmodat(d, p, 0644, 0));
}

static int
at_fchownat(int d, const char *p)
{

	return (fchownat(d, p, (uid_t)-1, (gid_t)-1, 0));
}

static int
at_chflagsat(int d, const char *p)
{
	struct stat sb;

	/* Rewrite the current flags: no change, works on any file system. */
	if (fstatat(d, p, &sb, 0) != 0)
		sb.st_flags = 0;
	return (chflagsat(d, p, sb.st_flags, 0));
}

static int
at_utimensat(int d, const char *p)
{

	return (utimensat(d, p, NULL, 0));
}

static int
at_futimesat(int d, const char *p)
{

	return (futimesat(d, p, NULL));
}

static int
at_realpathat(int d, const char *p)
{
	char buf[PATH_MAX];

	return (syscall(SYS___realpathat, d, p, buf, sizeof(buf), 0));
}

static int
at_inotify(int d, const char *p)
{
	int wd;

	wd = inotify_add_watch_at(inofd, d, p, IN_ALL_EVENTS);
	if (wd >= 0)
		(void)inotify_rm_watch(inofd, wd);
	return (wd < 0 ? -1 : 0);
}

static int
at_unlinkat(int d, const char *p)
{

	return (unlinkat(d, p, 0));
}

static int
at_funlinkat(int d, const char *p)
{

	return (funlinkat(d, p, FD_NONE, 0));
}

static int
at_renameat_from(int d, const char *p)
{

	return (renameat(d, p, AT_FDCWD, "zz_renamed"));
}

static int
at_renameat_to(int d, const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (renameat(AT_FDCWD, "zz_src", d, p));
}

static int
at_renameat2_to(int d, const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (renameat2(AT_FDCWD, "zz_src", d, p, AT_RENAME_NOREPLACE));
}

static int
at_linkat_from(int d, const char *p)
{

	return (linkat(d, p, AT_FDCWD, "zz_linked", 0));
}

static int
at_linkat_to(int d, const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (linkat(AT_FDCWD, "zz_src", d, p, 0));
}

static int
at_unlinkat_dir(int d, const char *p)
{

	return (unlinkat(d, p, AT_REMOVEDIR));
}

static int
at_mkdirat(int d, const char *p)
{

	return (mkdirat(d, p, 0755));
}

static int
at_mkfifoat(int d, const char *p)
{

	return (mkfifoat(d, p, 0644));
}

static int
at_mknodat(int d, const char *p)
{

	return (mknodat(d, p, S_IFIFO | 0644, 0));
}

static int
at_symlinkat(int d, const char *p)
{

	return (symlinkat("zz_tgt", d, p));
}

static int
at_openat_creat(int d, const char *p)
{
	int fd;

	fd = openat(d, p, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
at_readlinkat(int d, const char *p)
{
	char buf[PATH_MAX];

	return (readlinkat(d, p, buf, sizeof(buf)) == -1 ? -1 : 0);
}

static const struct at_op ops[] = {
	{ "openat", A_FILE, at_openat },
	{ "fstatat", A_FILE, at_fstatat },
	{ "faccessat", A_FILE, at_faccessat },
	{ "fchmodat", A_FILE, at_fchmodat },
	{ "fchownat", A_FILE, at_fchownat },
	{ "chflagsat", A_FILE, at_chflagsat },
	{ "utimensat", A_FILE, at_utimensat },
	{ "futimesat", A_FILE, at_futimesat },
	{ "__realpathat", A_FILE, at_realpathat },
	{ "inotify_add_watch_at", A_FILE, at_inotify },
	{ "unlinkat", A_FILE, at_unlinkat },
	{ "funlinkat", A_FILE, at_funlinkat },
	{ "renameat_from", A_FILE, at_renameat_from },
	{ "renameat_to", A_FILE, at_renameat_to },
	{ "linkat_from", A_FILE, at_linkat_from },
	{ "unlinkat_dir", A_DIR, at_unlinkat_dir },
	{ "mkdirat", A_NEW, at_mkdirat },
	{ "mkfifoat", A_NEW, at_mkfifoat },
	{ "mknodat", A_NEW, at_mknodat },
	{ "symlinkat", A_NEW, at_symlinkat },
	{ "openat_creat", A_NEW, at_openat_creat },
	{ "linkat_to", A_NEW, at_linkat_to },
	{ "renameat2_to", A_NEW, at_renameat2_to },
	{ "readlinkat", A_LINK, at_readlinkat },
};
#define	NOPS	(sizeof(ops) / sizeof(ops[0]))

static void
setup(void)
{

	inofd = inotify_init1(IN_CLOEXEC);
	ATF_REQUIRE(inofd >= 0);
	pc_mkdir("d");
	pc_mkdir("d2");
	pc_mkfile("zz_tgt", "target\n");
}

static void
cleanup(void)
{

	pc_remove("zz_src");
	pc_remove("zz_renamed");
	pc_remove("zz_linked");
}

/* Make the operated object at dir/name. */
static void
prepare(const struct at_op *op, const char *dir, const char *name)
{
	char path[PATH_MAX];

	cleanup();
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	pc_remove(path);
	switch (op->kind) {
	case A_FILE:
		pc_mkfile(path, "data\n");
		break;
	case A_DIR:
		pc_mkdir(path);
		break;
	case A_NEW:
		break;
	case A_LINK:
		pc_symlink("zz_tgt", path);
		break;
	}
}

static void
run(const struct at_op *op, const char *desc, int dfd, const char *path,
    int want)
{
	int got;

	got = ERRNO_OF(op->fn(dfd, path));
	ATF_CHECK_MSG(got == want, "%s: %s: got %d (%s), expected %d (%s)",
	    op->name, desc, got, strerror(got), want, strerror(want));
}

ATF_TC_WITHOUT_HEAD(dirfd_kinds);
ATF_TC_BODY(dirfd_kinds, tc)
{
	char abs[PATH_MAX], cwd[PATH_MAX];
	size_t i;
	int dfd, opath, ffd, kq, closed, osearch, p, s;

	setup();
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	opath = open("d", O_PATH | O_DIRECTORY);
	osearch = open("d", O_SEARCH | O_DIRECTORY);
	ffd = open("zz_tgt", O_RDONLY);
	kq = kqueue();
	p = pc_pipefd();
	s = pc_sockfd();
	/* A high number, closed: the lowest-free allocator never reuses it. */
	closed = dup2(ffd, 900);
	ATF_REQUIRE(dfd >= 0 && opath >= 0 && osearch >= 0 && ffd >= 0 &&
	    kq >= 0 && closed >= 0);
	ATF_REQUIRE(close(closed) == 0);

	for (i = 0; i < NOPS; i++) {
		/* Directory descriptors of every open mode work. */
		prepare(&ops[i], "d", "x");
		run(&ops[i], "AT_FDCWD", AT_FDCWD, "d/x", 0);
		prepare(&ops[i], "d", "x");
		run(&ops[i], "O_RDONLY directory", dfd, "x", 0);
		prepare(&ops[i], "d", "x");
		run(&ops[i], "O_PATH directory", opath, "x", 0);
		prepare(&ops[i], "d", "x");
		run(&ops[i], "O_SEARCH directory", osearch, "x", 0);

		/* Bad numbers: EBADF. */
		prepare(&ops[i], "d", "x");
		run(&ops[i], "fd -1", -1, "x", EBADF);
		run(&ops[i], "fd -2", -2, "x", EBADF);
		run(&ops[i], "fd 1000000", 1000000, "x", EBADF);
		run(&ops[i], "fd INT_MAX", INT_MAX, "x", EBADF);
		run(&ops[i], "closed fd", closed, "x", EBADF);

		/* Non-directory starts: ENOTDIR, vnode or not. */
		run(&ops[i], "regular file fd", ffd, "x", ENOTDIR);
		run(&ops[i], "pipe fd", p, "x", ENOTDIR);
		run(&ops[i], "socket fd", s, "x", ENOTDIR);
		run(&ops[i], "kqueue fd", kq, "x", ENOTDIR);

		/* An absolute path ignores the descriptor entirely. */
		prepare(&ops[i], "d", "x");
		snprintf(abs, sizeof(abs), "%s/d/x", cwd);
		run(&ops[i], "absolute path, fd -1", -1, abs, 0);
		prepare(&ops[i], "d", "x");
		run(&ops[i], "absolute path, pipe fd", p, abs, 0);
		prepare(&ops[i], "d", "x");
		run(&ops[i], "absolute path, file fd", ffd, abs, 0);

		/*
		 * The path is copied and checked for emptiness before the
		 * descriptor is used: EFAULT / ENAMETOOLONG / ENOENT win
		 * over EBADF and ENOTDIR.
		 */
		run(&ops[i], "NULL path, fd -1", -1, NULL, EFAULT);
		run(&ops[i], "NULL path, pipe fd", p, NULL, EFAULT);
		run(&ops[i], "empty path, fd -1", -1, "",
		    ops[i].kind == A_LINK ? EBADF : ENOENT);
		run(&ops[i], "empty path, file fd", ffd, "",
		    ops[i].kind == A_LINK ? EINVAL : ENOENT);
		run(&ops[i], "empty path, pipe fd", p, "",
		    ops[i].kind == A_LINK ? ENOTDIR : ENOENT);
		cleanup();
		pc_remove("d/x");
	}
	close(dfd);
	close(opath);
	close(osearch);
	close(ffd);
	close(kq);
}

ATF_TC_WITHOUT_HEAD(dirfd_reused_number);
ATF_TC_BODY(dirfd_reused_number, tc)
{
	struct stat sb;
	int a, b;

	setup();
	pc_mkfile("d/onlya", NULL);
	pc_mkfile("d2/onlyb", NULL);
	a = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(a >= 0);
	CHECK_OK(fstatat(a, "onlya", &sb, 0));
	ATF_REQUIRE(close(a) == 0);
	/* The lowest free number is reused for the other directory. */
	b = open("d2", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE_EQ(a, b);
	CHECK_ERR(fstatat(b, "onlya", &sb, 0), ENOENT);
	CHECK_OK(fstatat(b, "onlyb", &sb, 0));
	ATF_CHECK_EQ(sb.st_ino, pc_ino("d2/onlyb", true));
	/* Reused for a regular file: ENOTDIR now. */
	ATF_REQUIRE(close(b) == 0);
	b = open("zz_tgt", O_RDONLY);
	ATF_REQUIRE_EQ(a, b);
	CHECK_ERR(fstatat(b, "onlyb", &sb, 0), ENOTDIR);
	/* dup2 over it with a directory again. */
	a = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dup2(a, b) == b);
	CHECK_OK(fstatat(b, "onlya", &sb, 0));
	close(a);
	close(b);
}

ATF_TC(osearch_skips_exec_check);
ATF_TC_HEAD(osearch_skips_exec_check, tc)
{

	atf_tc_set_md_var(tc, "descr", "an O_SEARCH directory descriptor "
	    "searches the directory without its execute permission");
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(osearch_skips_exec_check, tc)
{
	struct stat sb;
	int rd, sfd;

	pc_mkdir("d");
	pc_mkfile("d/f", "data\n");
	sfd = open("d", O_SEARCH | O_DIRECTORY);
	rd = open("d", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(sfd >= 0 && rd >= 0);
	ATF_REQUIRE(chmod("d", 0600) == 0);
	/* NOEXECCHECK for the first component of an O_SEARCH start. */
	CHECK_OK(fstatat(sfd, "f", &sb, 0));
	CHECK_ERR(fstatat(rd, "f", &sb, 0), EACCES);
	CHECK_ERR(stat("d/f", &sb), EACCES);
	ATF_REQUIRE(chmod("d", 0755) == 0);
	close(sfd);
	close(rd);
}

ATF_TC_WITHOUT_HEAD(emptypath_fstatat);
ATF_TC_BODY(emptypath_fstatat, tc)
{
	struct stat sb, ref;
	int dfd, ffd, lfd, opath, p, s;

	setup();
	pc_symlink("zz_tgt", "lnk");
	ffd = open("zz_tgt", O_RDONLY);
	opath = open("zz_tgt", O_PATH);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	lfd = open("lnk", O_PATH | O_NOFOLLOW);
	p = pc_pipefd();
	s = pc_sockfd();
	ATF_REQUIRE(ffd >= 0 && opath >= 0 && dfd >= 0 && lfd >= 0);
	ATF_REQUIRE(stat("zz_tgt", &ref) == 0);

	CHECK_OK(fstatat(ffd, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK_EQ(sb.st_ino, ref.st_ino);
	CHECK_OK(fstatat(opath, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK_EQ(sb.st_ino, ref.st_ino);
	CHECK_OK(fstatat(dfd, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK_EQ(sb.st_ino, pc_ino("d", true));
	CHECK_OK(fstatat(AT_FDCWD, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK_EQ(sb.st_ino, pc_ino(".", true));
	/* The O_PATH link itself, with or without NOFOLLOW. */
	CHECK_OK(fstatat(lfd, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK(S_ISLNK(sb.st_mode));
	CHECK_OK(fstatat(lfd, "", &sb, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));
	ATF_CHECK(S_ISLNK(sb.st_mode));
	/*
	 * Vnode-less descriptors: namei's ENOTDIR with NIRES_EMPTYPATH
	 * falls back to kern_fstat (kern_statat at 3f330ee172d).
	 */
	memset(&sb, 0, sizeof(sb));
	CHECK_OK(fstatat(p, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK(S_ISFIFO(sb.st_mode));
	memset(&sb, 0, sizeof(sb));
	CHECK_OK(fstatat(s, "", &sb, AT_EMPTY_PATH));
	ATF_CHECK(S_ISSOCK(sb.st_mode));
	{
		struct stat viafd;

		ATF_REQUIRE(fstat(p, &viafd) == 0);
		ATF_REQUIRE(fstatat(p, "", &sb, AT_EMPTY_PATH) == 0);
		ATF_CHECK_EQ(sb.st_ino, viafd.st_ino);
		ATF_CHECK_EQ(sb.st_dev, viafd.st_dev);
	}
	/* Bad descriptors. */
	CHECK_ERR(fstatat(-1, "", &sb, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(fstatat(1000000, "", &sb, AT_EMPTY_PATH), EBADF);
	/* Without the flag, "" is ENOENT for every descriptor. */
	CHECK_ERR(fstatat(ffd, "", &sb, 0), ENOENT);
	CHECK_ERR(fstatat(p, "", &sb, 0), ENOENT);
	CHECK_ERR(fstatat(-1, "", &sb, 0), ENOENT);
	/* A bad flag: EINVAL before anything. */
	CHECK_ERR(fstatat(-1, NULL, &sb, 0x80000000), EINVAL);
	/* A bad stat buffer: EFAULT on copyout, after a good lookup. */
	CHECK_ERR(fstatat(ffd, "", (struct stat *)(uintptr_t)pc_unmapped(),
	    AT_EMPTY_PATH), EFAULT);
	CHECK_ERR(fstatat(p, "", (struct stat *)(uintptr_t)pc_unmapped(),
	    AT_EMPTY_PATH), EFAULT);
	close(ffd);
	close(opath);
	close(dfd);
	close(lfd);
}

ATF_TC_WITHOUT_HEAD(emptypath_setattr);
ATF_TC_BODY(emptypath_setattr, tc)
{
	struct timespec ts[2];
	struct stat sb, before;
	int ffd, opath, p, s, e1, e2;

	setup();
	ffd = open("zz_tgt", O_RDONLY);
	opath = open("zz_tgt", O_PATH);
	ATF_REQUIRE(ffd >= 0 && opath >= 0);
	p = pc_pipefd();
	s = pc_sockfd();

	/* fchmodat */
	CHECK_OK(fchmodat(ffd, "", 0600, AT_EMPTY_PATH));
	ATF_REQUIRE(fstat(ffd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0600);
	CHECK_OK(fchmodat(opath, "", 0640, AT_EMPTY_PATH));
	ATF_REQUIRE(fstat(ffd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0640);
	CHECK_ERR(fchmodat(p, "", 0600, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(fchmodat(s, "", 0600, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(fchmodat(-1, "", 0600, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(fchmodat(ffd, "", 0600, 0), ENOENT);
	CHECK_ERR(fchmodat(ffd, "", 0600, AT_EMPTY_PATH | 0x80000000),
	    EINVAL);

	/* fchownat */
	CHECK_OK(fchownat(ffd, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH));
	CHECK_OK(fchownat(opath, "", geteuid(), (gid_t)-1, AT_EMPTY_PATH));
	CHECK_ERR(fchownat(p, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH),
	    ENOTDIR);
	CHECK_ERR(fchownat(s, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH),
	    ENOTDIR);
	CHECK_ERR(fchownat(-1, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(fchownat(ffd, "", (uid_t)-1, (gid_t)-1, 0), ENOENT);

	/* chflagsat: the same answer as fchflags on the file (oracle). */
	e1 = ERRNO_OF(chflagsat(ffd, "", UF_NODUMP, AT_EMPTY_PATH));
	e2 = ERRNO_OF(fchflags(ffd, UF_NODUMP));
	ATF_CHECK_EQ_MSG(e1, e2, "chflagsat(AT_EMPTY_PATH) %d, fchflags %d",
	    e1, e2);
	if (e1 == 0) {
		ATF_REQUIRE(fstat(ffd, &sb) == 0);
		ATF_CHECK((sb.st_flags & UF_NODUMP) != 0);
		CHECK_OK(chflagsat(opath, "", 0, AT_EMPTY_PATH));
		ATF_REQUIRE(fstat(ffd, &sb) == 0);
		ATF_CHECK((sb.st_flags & UF_NODUMP) == 0);
	}
	CHECK_ERR(chflagsat(p, "", 0, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(chflagsat(s, "", 0, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(chflagsat(-1, "", 0, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(chflagsat(ffd, "", 0, 0), ENOENT);

	/* utimensat */
	ts[0].tv_sec = 1000000;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = 2000000;
	ts[1].tv_nsec = 0;
	CHECK_OK(utimensat(ffd, "", ts, AT_EMPTY_PATH));
	ATF_REQUIRE(fstat(ffd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_atim.tv_sec, 1000000);
	ATF_CHECK_EQ(sb.st_mtim.tv_sec, 2000000);
	before = sb;
	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_nsec = UTIME_OMIT;
	CHECK_OK(utimensat(opath, "", ts, AT_EMPTY_PATH));
	ATF_REQUIRE(fstat(ffd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_mtim.tv_sec, before.st_mtim.tv_sec);
	/* namei runs even for UTIME_OMIT twice: still ENOTDIR / EBADF. */
	CHECK_ERR(utimensat(p, "", ts, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(utimensat(-1, "", ts, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(utimensat(s, "", NULL, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(utimensat(ffd, "", NULL, 0), ENOENT);

	/* faccessat */
	CHECK_OK(faccessat(ffd, "", F_OK, AT_EMPTY_PATH));
	CHECK_OK(faccessat(opath, "", R_OK, AT_EMPTY_PATH));
	CHECK_OK(faccessat(AT_FDCWD, "", X_OK, AT_EMPTY_PATH));
	CHECK_ERR(faccessat(p, "", F_OK, AT_EMPTY_PATH), ENOTDIR);
	CHECK_ERR(faccessat(s, "", R_OK, AT_EMPTY_PATH | AT_EACCESS), ENOTDIR);
	CHECK_ERR(faccessat(-1, "", F_OK, AT_EMPTY_PATH), EBADF);
	CHECK_ERR(faccessat(ffd, "", F_OK, 0), ENOENT);
	if (!pc_is_root()) {
		ATF_REQUIRE(fchmod(ffd, 0400) == 0);
		CHECK_ERR(faccessat(ffd, "", W_OK, AT_EMPTY_PATH), EACCES);
	}
	close(ffd);
	close(opath);
}

ATF_TC_WITHOUT_HEAD(emptypath_readlinkat);
ATF_TC_BODY(emptypath_readlinkat, tc)
{
	char buf[64];
	volatile size_t huge = SIZE_MAX;
	ssize_t n;
	int dfd, ffd, lfd;

	setup();
	pc_symlink("zz_tgt", "lnk");
	lfd = open("lnk", O_PATH | O_NOFOLLOW);
	ffd = open("zz_tgt", O_RDONLY);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(lfd >= 0 && ffd >= 0 && dfd >= 0);
	/* readlinkat always looks up with EMPTYPATH. */
	memset(buf, 0, sizeof(buf));
	n = readlinkat(lfd, "", buf, sizeof(buf));
	ATF_CHECK_EQ(n, 6);
	ATF_CHECK(memcmp(buf, "zz_tgt", 6) == 0);
	/* A short buffer: truncated, the count returned. */
	n = readlinkat(lfd, "", buf, 3);
	ATF_CHECK_EQ(n, 3);
	CHECK_ERR(readlinkat(ffd, "", buf, sizeof(buf)), EINVAL);
	CHECK_ERR(readlinkat(dfd, "", buf, sizeof(buf)), EINVAL);
	CHECK_ERR(readlinkat(AT_FDCWD, "", buf, sizeof(buf)), EINVAL);
	CHECK_ERR(readlink("", buf, sizeof(buf)), EINVAL);
	CHECK_ERR(readlinkat(pc_pipefd(), "", buf, sizeof(buf)), ENOTDIR);
	CHECK_ERR(readlinkat(pc_sockfd(), "", buf, sizeof(buf)), ENOTDIR);
	CHECK_ERR(readlinkat(-1, "", buf, sizeof(buf)), EBADF);
	/* count > IOSIZE_MAX: EINVAL before the lookup. */
	CHECK_ERR(readlinkat(-1, NULL, buf, huge), EINVAL);
	CHECK_ERR(readlink("nonexistent", buf, huge), EINVAL);
	/* A bad buffer: EFAULT after the lookup. */
	CHECK_ERR(readlinkat(lfd, "", (char *)(uintptr_t)pc_unmapped(),
	    sizeof(buf)), EFAULT);
	CHECK_ERR(readlink("nonexistent", (char *)(uintptr_t)pc_unmapped(),
	    sizeof(buf)), ENOENT);
	close(lfd);
	close(ffd);
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(emptypath_linkat);
ATF_TC_BODY(emptypath_linkat, tc)
{
	int dfd, ffd, opath;

	setup();
	ffd = open("zz_tgt", O_RDONLY);
	opath = open("zz_tgt", O_PATH);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(ffd >= 0 && opath >= 0 && dfd >= 0);
	/* Vnode-less and bad descriptors fail in namei, privileged or not. */
	CHECK_ERR(linkat(pc_pipefd(), "", AT_FDCWD, "new", AT_EMPTY_PATH),
	    ENOTDIR);
	CHECK_ERR(linkat(pc_sockfd(), "", AT_FDCWD, "new", AT_EMPTY_PATH),
	    ENOTDIR);
	CHECK_ERR(linkat(-1, "", AT_FDCWD, "new", AT_EMPTY_PATH), EBADF);
	CHECK_ERR(linkat(ffd, "", AT_FDCWD, "new", 0), ENOENT);
	CHECK_ERR(linkat(ffd, "", AT_FDCWD, "new", 0x80000000), EINVAL);
	ATF_CHECK(access("new", F_OK) == -1);
	if (!pc_is_root()) {
		/* Linking by descriptor needs PRIV_VFS_FHOPEN. */
		CHECK_ERR(linkat(ffd, "", AT_FDCWD, "new", AT_EMPTY_PATH),
		    EPERM);
		CHECK_ERR(linkat(opath, "", AT_FDCWD, "new", AT_EMPTY_PATH),
		    EPERM);
		CHECK_ERR(linkat(dfd, "", AT_FDCWD, "new", AT_EMPTY_PATH),
		    EPERM);
		ATF_CHECK(access("new", F_OK) == -1);
	} else {
		CHECK_OK(linkat(ffd, "", AT_FDCWD, "new", AT_EMPTY_PATH));
		ATF_CHECK_EQ(pc_ino("new", true), pc_ino("zz_tgt", true));
		CHECK_OK(linkat(opath, "", dfd, "new2", AT_EMPTY_PATH));
		ATF_CHECK_EQ(pc_ino("d/new2", true), pc_ino("zz_tgt", true));
		CHECK_ERR(linkat(ffd, "", AT_FDCWD, "new", AT_EMPTY_PATH),
		    EEXIST);
		/* A directory cannot be linked (EPERM, POSIX). */
		CHECK_ERR(linkat(dfd, "", AT_FDCWD, "dirlink", AT_EMPTY_PATH),
		    EPERM);
	}
	/* The target's errors come after the source's. */
	CHECK_ERR(linkat(pc_pipefd(), "", -1, "new3", AT_EMPTY_PATH), ENOTDIR);
	close(ffd);
	close(opath);
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(emptypath_not_supported);
ATF_TC_BODY(emptypath_not_supported, tc)
{
	char buf[PATH_MAX];
	int ffd;

	setup();
	ffd = open("zz_tgt", O_RDONLY);
	ATF_REQUIRE(ffd >= 0);
	/* Calls without AT_EMPTY_PATH in their flag mask: EINVAL. */
	CHECK_ERR(unlinkat(ffd, "", AT_EMPTY_PATH), EINVAL);
	CHECK_ERR(funlinkat(ffd, "", FD_NONE, AT_EMPTY_PATH), EINVAL);
	CHECK_ERR(renameat2(ffd, "", AT_FDCWD, "x", AT_EMPTY_PATH), EINVAL);
	CHECK_ERR(syscall(SYS___realpathat, ffd, "", buf, sizeof(buf),
	    AT_EMPTY_PATH), EINVAL);
	/* ...and calls that never take it see "" as ENOENT. */
	CHECK_ERR(mkdirat(ffd, "", 0755), ENOENT);
	CHECK_ERR(mkfifoat(ffd, "", 0644), ENOENT);
	CHECK_ERR(symlinkat("t", ffd, ""), ENOENT);
	CHECK_ERR(syscall(SYS___realpathat, ffd, "", buf, sizeof(buf), 0),
	    ENOENT);
	CHECK_ERR(futimesat(ffd, "", NULL), ENOENT);
	close(ffd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, dirfd_kinds);
	ATF_TP_ADD_TC(tp, dirfd_reused_number);
	ATF_TP_ADD_TC(tp, osearch_skips_exec_check);
	ATF_TP_ADD_TC(tp, emptypath_fstatat);
	ATF_TP_ADD_TC(tp, emptypath_setattr);
	ATF_TP_ADD_TC(tp, emptypath_readlinkat);
	ATF_TP_ADD_TC(tp, emptypath_linkat);
	ATF_TP_ADD_TC(tp, emptypath_not_supported);
	return (atf_no_error());
}
