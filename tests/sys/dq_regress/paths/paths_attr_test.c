/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Attribute and query path calls: chmod/lchmod/fchmodat, chown/lchown/
 * fchownat, chflags/lchflags/chflagsat (including flags above 32 bits,
 * VNOVAL and UF/SF flags as root), utimes/lutimes/futimesat/utimensat,
 * truncate, access/eaccess/faccessat(AT_EACCESS), pathconf/lpathconf,
 * statfs, __realpathat, extattr and ACL path calls, inotify_add_watch,
 * chdir/fchdir/chroot and getfh/fhopen/fhlink/fhlinkat/fhreadlink.
 *
 * What it tries to break: the setattr family gained wrappers that build a
 * SETATTR body (times copied in once, chflags split at 32 bits, a
 * privilege pre-computation), accessat a served-identity path, truncate an
 * RLIMIT_FSIZE pre-test.  For an unattached process the impl alone runs
 * and must give 3f330ee172d's answers.  Where the answer belongs to the
 * file system, the oracle is the descriptor variant of the same call on
 * the same file (fchflags, futimes, fpathconf, fstatfs, extattr_*_fd,
 * acl_get_fd), which never does a path lookup.
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

static struct stat
st(const char *path, bool nofollow)
{
	struct stat sb;

	ATF_REQUIRE_MSG((nofollow ? lstat(path, &sb) : stat(path, &sb)) == 0,
	    "stat %s: %s", path, strerror(errno));
	return (sb);
}

/* Run fn in a child; the child's failures are reported by its status. */
static void
in_child(void (*fn)(void))
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		fn();
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child failed: status %#x (exit code = failing line)", status);
}

/* In a child: exit with the line number on a failed expectation. */
#define	C_EXPECT(cond) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "child line %d: %s (errno %d)\n",	\
		    __LINE__, #cond, errno);				\
		_exit(__LINE__ & 0xff ? __LINE__ & 0xff : 1);		\
	}								\
} while (0)

ATF_TC_WITHOUT_HEAD(chmod_family);
ATF_TC_BODY(chmod_family, tc)
{
	struct stat sl, sb;
	mode_t lmode;
	int e, fd;

	pc_mkfile("f", NULL);
	pc_symlink("f", "lf");
	lmode = st("lf", true).st_mode & ALLPERMS;
	CHECK_OK(chmod("f", 0600));
	ATF_CHECK_EQ(st("f", false).st_mode & ALLPERMS, 0600);
	/* chmod follows the final link. */
	CHECK_OK(chmod("lf", 0640));
	ATF_CHECK_EQ(st("f", false).st_mode & ALLPERMS, 0640);
	ATF_CHECK_EQ(st("lf", true).st_mode & ALLPERMS, lmode);
	CHECK_OK(fchmodat(AT_FDCWD, "lf", 0604, 0));
	ATF_CHECK_EQ(st("f", false).st_mode & ALLPERMS, 0604);
	/*
	 * lchmod / AT_SYMLINK_NOFOLLOW change the link.  TBC: a file system
	 * may refuse a link's mode (EOPNOTSUPP); then both calls agree and
	 * nothing changes.
	 */
	e = ERRNO_OF(lchmod("lf", 0700));
	ATF_CHECK_MSG(e == 0 || e == EOPNOTSUPP, "lchmod: %s", strerror(e));
	ATF_CHECK_EQ(ERRNO_OF(fchmodat(AT_FDCWD, "lf", 0700,
	    AT_SYMLINK_NOFOLLOW)), e);
	sl = st("lf", true);
	sb = st("f", false);
	if (e == 0)
		ATF_CHECK_EQ(sl.st_mode & ALLPERMS, 0700);
	ATF_CHECK_EQ(sb.st_mode & ALLPERMS, 0604);
	/* lchmod of a regular file is chmod. */
	CHECK_OK(lchmod("f", 0644));
	ATF_CHECK_EQ(st("f", false).st_mode & ALLPERMS, 0644);
	/* The same result as fchmod (oracle) for the whole mode word. */
	fd = open("f", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	e = ERRNO_OF(fchmod(fd, 0644 | S_ISUID));
	ATF_CHECK_EQ(ERRNO_OF(chmod("f", 0644 | S_ISUID)), e);
	ATF_CHECK_EQ(ERRNO_OF(fchmod(fd, 0644)), 0);
	close(fd);
	CHECK_ERR(chmod("missing", 0644), ENOENT);
	CHECK_ERR(lchmod("nodir/f", 0644), ENOENT);
}

ATF_TC_WITHOUT_HEAD(chown_family);
ATF_TC_BODY(chown_family, tc)
{
	struct stat sb;

	pc_mkfile("f", NULL);
	pc_symlink("f", "lf");
	CHECK_OK(chown("f", (uid_t)-1, (gid_t)-1));
	CHECK_OK(chown("f", geteuid(), getegid()));
	CHECK_OK(lchown("lf", (uid_t)-1, (gid_t)-1));
	CHECK_OK(fchownat(AT_FDCWD, "lf", geteuid(), (gid_t)-1,
	    AT_SYMLINK_NOFOLLOW));
	if (!pc_is_root()) {
		/* Giving a file away or to a foreign group: EPERM. */
		CHECK_ERR(chown("f", 0, (gid_t)-1), EPERM);
		CHECK_ERR(chown("lf", 0, (gid_t)-1), EPERM);
		CHECK_ERR(lchown("lf", 0, (gid_t)-1), EPERM);
		CHECK_ERR(chown("f", (uid_t)-1, 31337), EPERM);
	} else {
		/* lchown changes the link, chown the target. */
		CHECK_OK(lchown("lf", 4242, 4343));
		sb = st("lf", true);
		ATF_CHECK_EQ(sb.st_uid, 4242);
		ATF_CHECK_EQ(sb.st_gid, 4343);
		ATF_CHECK_EQ(st("f", false).st_uid, 0);
		CHECK_OK(chown("lf", 4444, (gid_t)-1));
		ATF_CHECK_EQ(st("f", false).st_uid, 4444);
		ATF_CHECK_EQ(st("lf", true).st_uid, 4242);
		CHECK_OK(fchownat(AT_FDCWD, "f", 0, 0, 0));
	}
	CHECK_ERR(chown("missing", (uid_t)-1, (gid_t)-1), ENOENT);
	CHECK_ERR(lchown("", (uid_t)-1, (gid_t)-1), ENOENT);
}

ATF_TC_WITHOUT_HEAD(chflags_family);
ATF_TC_BODY(chflags_family, tc)
{
	static const u_long words[] = {
		UF_NODUMP, 0, (u_long)1 << 32, (u_long)1 << 40,
		UF_NODUMP | ((u_long)1 << 33), (u_long)0x7fffffff << 1,
		SF_ARCHIVED, SF_NOUNLINK, (u_long)-1 /* VNOVAL */,
		(u_long)-2,
	};
	struct stat sb;
	size_t i;
	int e, o, twin, level;

	pc_mkfile("f", NULL);
	pc_mkfile("twin", NULL);
	pc_symlink("f", "lf");
	twin = open("twin", O_RDONLY);
	ATF_REQUIRE(twin >= 0);
	/*
	 * chflags(path, w) and fchflags(fd, w) reach the same setfflags():
	 * the same errno for every word, including words above 32 bits and
	 * VNOVAL (setfflags' EOPNOTSUPP).
	 */
	if (!pc_sysctl_get("kern.securelevel", &level))
		level = 1;
	for (i = 0; i < nitems(words); i++) {
		/* As root above securelevel 0 an SF flag could not be undone. */
		if (pc_is_root() && level > 0 &&
		    (words[i] & SF_SETTABLE) != 0)
			continue;
		o = ERRNO_OF(fchflags(twin, words[i]));
		e = ERRNO_OF(chflags("f", words[i]));
		ATF_CHECK_MSG(e == o, "chflags(%#lx): %d, fchflags %d",
		    words[i], e, o);
		e = ERRNO_OF(chflagsat(AT_FDCWD, "f", words[i], 0));
		ATF_CHECK_MSG(e == o, "chflagsat(%#lx): %d, fchflags %d",
		    words[i], e, o);
		if (o == 0) {
			ATF_CHECK_EQ(st("f", false).st_flags,
			    st("twin", false).st_flags);
		}
		(void)fchflags(twin, 0);
		(void)chflags("f", 0);
	}
	CHECK_ERR(chflags("f", (u_long)-1), EOPNOTSUPP);
	CHECK_ERR(fchflags(twin, (u_long)-1), EOPNOTSUPP);
	/* chflags follows the final link. */
	if (ERRNO_OF(fchflags(twin, UF_NODUMP)) == 0) {
		CHECK_OK(chflags("lf", UF_NODUMP));
		ATF_CHECK((st("f", false).st_flags & UF_NODUMP) != 0);
		CHECK_OK(chflags("lf", 0));
		/* lchflags changes the link (TBC: or EOPNOTSUPP). */
		e = ERRNO_OF(lchflags("lf", UF_NODUMP));
		ATF_CHECK_MSG(e == 0 || e == EOPNOTSUPP, "lchflags: %d", e);
		ATF_CHECK_EQ(ERRNO_OF(chflagsat(AT_FDCWD, "lf", UF_NODUMP,
		    AT_SYMLINK_NOFOLLOW)), e);
		ATF_CHECK((st("f", false).st_flags & UF_NODUMP) == 0);
		if (e == 0)
			ATF_CHECK((st("lf", true).st_flags & UF_NODUMP) != 0);
		(void)lchflags("lf", 0);
	}
	/* UF_IMMUTABLE as the owner: the file cannot be removed. */
	if (ERRNO_OF(fchflags(twin, UF_IMMUTABLE)) == 0) {
		(void)fchflags(twin, 0);
		CHECK_OK(chflags("f", UF_IMMUTABLE));
		CHECK_ERR(unlink("f"), EPERM);
		CHECK_ERR(rename("f", "g"), EPERM);
		CHECK_ERR(chmod("f", 0600), EPERM);
		CHECK_ERR(truncate("f", 0), EPERM);
		CHECK_ERR(open("f", O_WRONLY), EPERM);
		CHECK_OK(chflags("f", 0));
		sb = st("f", false);
		ATF_CHECK_EQ(sb.st_flags & UF_IMMUTABLE, 0);
	}
	/* System flags without privilege: the same answer as fchflags. */
	if (!pc_is_root()) {
		o = ERRNO_OF(fchflags(twin, SF_IMMUTABLE));
		ATF_CHECK_EQ(ERRNO_OF(chflags("f", SF_IMMUTABLE)), o);
		ATF_CHECK(o != 0);
	}
	CHECK_ERR(chflags("missing", 0), ENOENT);
	CHECK_ERR(chflagsat(AT_FDCWD, "f", 0, AT_REMOVEDIR), EINVAL);
	close(twin);
}

ATF_TC(chflags_sf_root);
ATF_TC_HEAD(chflags_sf_root, tc)
{

	atf_tc_set_md_var(tc, "descr", "SF_ flags set and cleared by path "
	    "as root behave as with fchflags");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(chflags_sf_root, tc)
{
	int level, twin, o;

	if (!pc_sysctl_get("kern.securelevel", &level) || level > 0)
		atf_tc_skip("securelevel > 0: system flags cannot be cleared");
	pc_mkfile("f", NULL);
	pc_mkfile("twin", NULL);
	twin = open("twin", O_RDONLY);
	ATF_REQUIRE(twin >= 0);
	o = ERRNO_OF(fchflags(twin, SF_IMMUTABLE));
	(void)fchflags(twin, 0);
	if (o != 0)
		atf_tc_skip("SF_IMMUTABLE unsupported here: %s", strerror(o));
	CHECK_OK(chflags("f", SF_IMMUTABLE));
	ATF_CHECK((st("f", false).st_flags & SF_IMMUTABLE) != 0);
	CHECK_ERR(unlink("f"), EPERM);
	CHECK_ERR(open("f", O_RDWR), EPERM);
	CHECK_ERR(utimes("f", NULL), EPERM);
	CHECK_OK(chflags("f", 0));
	CHECK_OK(chflags("f", SF_APPEND | SF_NOUNLINK));
	CHECK_ERR(unlink("f"), EPERM);
	CHECK_ERR(truncate("f", 0), EPERM);
	/* An SF flag word above 32 bits: the same as fchflags. */
	o = ERRNO_OF(fchflags(twin, SF_NOUNLINK | ((u_long)1 << 35)));
	ATF_CHECK_EQ(ERRNO_OF(chflags("f", SF_NOUNLINK | ((u_long)1 << 35))),
	    o);
	(void)fchflags(twin, 0);
	CHECK_OK(chflags("f", 0));
	CHECK_OK(unlink("f"));
	close(twin);
}

ATF_TC_WITHOUT_HEAD(utimes_family);
ATF_TC_BODY(utimes_family, tc)
{
	struct timeval tv[2];
	struct timespec ts[2];
	struct stat a, b, before;
	time_t now;
	int twin;

	pc_mkfile("f", NULL);
	pc_mkfile("twin", NULL);
	pc_symlink("f", "lf");
	twin = open("twin", O_RDWR);
	ATF_REQUIRE(twin >= 0);

	/* Explicit times, usec converted to nsec; birthtime as futimes. */
	tv[0].tv_sec = 1000;
	tv[0].tv_usec = 500;
	tv[1].tv_sec = 2000;
	tv[1].tv_usec = 999999;
	CHECK_OK(utimes("f", tv));
	ATF_REQUIRE(futimes(twin, tv) == 0);
	a = st("f", false);
	b = st("twin", false);
	ATF_CHECK_EQ(a.st_atim.tv_sec, 1000);
	ATF_CHECK_EQ(a.st_atim.tv_nsec, 500000);
	ATF_CHECK_EQ(a.st_mtim.tv_sec, 2000);
	ATF_CHECK_EQ(a.st_mtim.tv_nsec, 999999000);
	/*
	 * setutimes moves the birthtime back to an earlier mtime; when the
	 * file system does so for the descriptor call it must for the path.
	 */
	if (b.st_birthtim.tv_sec == 2000)
		ATF_CHECK_EQ(a.st_birthtim.tv_sec, 2000);
	/* NULL: now (VA_UTIMES_NULL). */
	now = time(NULL);
	CHECK_OK(utimes("f", NULL));
	a = st("f", false);
	ATF_CHECK(a.st_mtim.tv_sec >= now - 2 && a.st_mtim.tv_sec <= now + 2);
	ATF_CHECK(a.st_atim.tv_sec >= now - 2 && a.st_atim.tv_sec <= now + 2);
	/* utimes follows the link; lutimes changes the link only. */
	CHECK_OK(utimes("lf", tv));
	ATF_CHECK_EQ(st("f", false).st_mtim.tv_sec, 2000);
	before = st("f", false);
	tv[1].tv_sec = 3000;
	CHECK_OK(lutimes("lf", tv));
	ATF_CHECK_EQ(st("lf", true).st_mtim.tv_sec, 3000);
	ATF_CHECK_EQ(st("f", false).st_mtim.tv_sec, before.st_mtim.tv_sec);
	/* lutimes of a regular file is utimes. */
	CHECK_OK(lutimes("f", tv));
	ATF_CHECK_EQ(st("f", false).st_mtim.tv_sec, 3000);
	CHECK_OK(futimesat(AT_FDCWD, "f", NULL));
	CHECK_OK(futimesat(AT_FDCWD, "lf", tv));

	/* utimensat: UTIME_NOW, UTIME_OMIT, mixed, NOFOLLOW. */
	ts[0].tv_sec = 4000;
	ts[0].tv_nsec = 1;
	ts[1].tv_sec = 5000;
	ts[1].tv_nsec = 999999999;
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	a = st("f", false);
	ATF_CHECK_EQ(a.st_atim.tv_sec, 4000);
	ATF_CHECK_EQ(a.st_atim.tv_nsec, 1);
	ATF_CHECK_EQ(a.st_mtim.tv_nsec, 999999999);
	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_sec = 6000;
	ts[1].tv_nsec = 0;
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	b = st("f", false);
	ATF_CHECK_EQ(b.st_atim.tv_sec, 4000);
	ATF_CHECK_EQ(b.st_mtim.tv_sec, 6000);
	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_nsec = UTIME_OMIT;
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	a = st("f", false);
	ATF_CHECK_EQ(a.st_mtim.tv_sec, 6000);
	ATF_CHECK_EQ(a.st_atim.tv_sec, 4000);
	ts[0].tv_nsec = UTIME_NOW;
	ts[1].tv_nsec = UTIME_OMIT;
	now = time(NULL);
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	a = st("f", false);
	ATF_CHECK(a.st_atim.tv_sec >= now - 2);
	ATF_CHECK_EQ(a.st_mtim.tv_sec, 6000);
	ts[0].tv_nsec = ts[1].tv_nsec = UTIME_NOW;
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	ATF_CHECK(st("f", false).st_mtim.tv_sec >= now - 2);
	ts[0].tv_sec = ts[1].tv_sec = 7000;
	ts[0].tv_nsec = ts[1].tv_nsec = 0;
	before = st("f", false);
	CHECK_OK(utimensat(AT_FDCWD, "lf", ts, AT_SYMLINK_NOFOLLOW));
	ATF_CHECK_EQ(st("lf", true).st_mtim.tv_sec, 7000);
	ATF_CHECK_EQ(st("f", false).st_mtim.tv_sec, before.st_mtim.tv_sec);
	CHECK_OK(utimensat(AT_FDCWD, "lf", ts, 0));
	ATF_CHECK_EQ(st("f", false).st_mtim.tv_sec, 7000);
	/* The birthtime follows an earlier mtime as with futimens. */
	ts[0].tv_sec = ts[1].tv_sec = 10;
	CHECK_OK(utimensat(AT_FDCWD, "f", ts, 0));
	ATF_REQUIRE(futimens(twin, ts) == 0);
	if (st("twin", false).st_birthtim.tv_sec == 10)
		ATF_CHECK_EQ(st("f", false).st_birthtim.tv_sec, 10);
	CHECK_ERR(utimes("missing", NULL), ENOENT);
	CHECK_ERR(lutimes("missing", NULL), ENOENT);
	close(twin);
}

static void
child_fsize(void)
{
	struct rlimit rl;
	int e1, e2;

	signal(SIGXFSZ, SIG_IGN);
	rl.rlim_cur = rl.rlim_max = 4096;
	C_EXPECT(setrlimit(RLIMIT_FSIZE, &rl) == 0);
	/*
	 * TBC: kern_truncate never applies RLIMIT_FSIZE itself; the file
	 * system's VOP_SETATTR may (EFBIG).  Accept either, and require the
	 * second call to agree with the first.
	 */
	e1 = ERRNO_OF(truncate("f", 1 << 20));
	C_EXPECT(e1 == 0 || e1 == EFBIG);
	e2 = ERRNO_OF(truncate("f", 1 << 20));
	C_EXPECT(e2 == e1);
	/* Shrinking below the limit is always allowed. */
	C_EXPECT(truncate("f", 100) == 0);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(truncate_family);
ATF_TC_BODY(truncate_family, tc)
{

	pc_mkfile("f", "0123456789");
	pc_symlink("f", "lf");
	pc_mkdir("d");
	CHECK_OK(truncate("f", 1 << 20));
	ATF_CHECK_EQ(st("f", false).st_size, 1 << 20);
	CHECK_OK(truncate("lf", 3));
	ATF_CHECK_EQ(st("f", false).st_size, 3);
	CHECK_OK(truncate("f", 0));
	ATF_CHECK_EQ(st("f", false).st_size, 0);
	CHECK_ERR(truncate("d", 0), EISDIR);
	CHECK_ERR(truncate("f", -1), EINVAL);
	CHECK_ERR(truncate("missing", 0), ENOENT);
	if (!pc_is_root()) {
		ATF_REQUIRE(chmod("f", 0444) == 0);
		CHECK_ERR(truncate("f", 10), EACCES);
		ATF_REQUIRE(chmod("f", 0644) == 0);
	}
	in_child(child_fsize);
}

static void
child_eaccess(void)
{

	/* Real uid nobody, effective uid root. */
	C_EXPECT(setreuid(65534, 0) == 0);
	C_EXPECT(getuid() == 65534 && geteuid() == 0);
	C_EXPECT(access("secret", R_OK) == -1 && errno == EACCES);
	C_EXPECT(faccessat(AT_FDCWD, "secret", R_OK, 0) == -1 &&
	    errno == EACCES);
	C_EXPECT(eaccess("secret", R_OK) == 0);
	C_EXPECT(faccessat(AT_FDCWD, "secret", R_OK, AT_EACCESS) == 0);
	/* Search permission on the way is the real user's too. */
	C_EXPECT(access("closed/f", F_OK) == -1 && errno == EACCES);
	C_EXPECT(eaccess("closed/f", F_OK) == 0);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(access_family);
ATF_TC_BODY(access_family, tc)
{

	pc_mkfile("f", NULL);
	pc_mkfile("x", NULL);
	pc_symlink("f", "lf");
	pc_symlink("nowhere", "dangling");
	ATF_REQUIRE(chmod("x", 0755) == 0);
	CHECK_OK(access("f", F_OK));
	CHECK_OK(access("f", R_OK | W_OK));
	CHECK_OK(access("x", X_OK));
	CHECK_OK(access("lf", R_OK));
	CHECK_ERR(access("dangling", F_OK), ENOENT);
	CHECK_OK(faccessat(AT_FDCWD, "dangling", F_OK, AT_SYMLINK_NOFOLLOW));
	/* Even root needs an execute bit on a regular file. */
	CHECK_ERR(access("f", X_OK), EACCES);
	CHECK_ERR(eaccess("f", X_OK), EACCES);
	if (!pc_is_root()) {
		ATF_REQUIRE(chmod("f", 0400) == 0);
		CHECK_ERR(access("f", W_OK), EACCES);
		CHECK_ERR(faccessat(AT_FDCWD, "f", W_OK, AT_EACCESS), EACCES);
		CHECK_OK(access("f", R_OK));
	} else {
		pc_mkfile("secret", NULL);
		ATF_REQUIRE(chmod("secret", 0600) == 0);
		pc_mkdir("closed");
		pc_mkfile("closed/f", NULL);
		ATF_REQUIRE(chmod("closed", 0700) == 0);
		in_child(child_eaccess);
	}
}

ATF_TC_WITHOUT_HEAD(pathconf_family);
ATF_TC_BODY(pathconf_family, tc)
{
	static const int names[] = {
		_PC_LINK_MAX, _PC_MAX_CANON, _PC_MAX_INPUT, _PC_NAME_MAX,
		_PC_PATH_MAX, _PC_PIPE_BUF, _PC_CHOWN_RESTRICTED,
		_PC_NO_TRUNC, _PC_VDISABLE, _PC_ASYNC_IO, _PC_PRIO_IO,
		_PC_SYNC_IO, _PC_ALLOC_SIZE_MIN, _PC_FILESIZEBITS,
		_PC_REC_INCR_XFER_SIZE, _PC_REC_MAX_XFER_SIZE,
		_PC_REC_MIN_XFER_SIZE, _PC_REC_XFER_ALIGN, _PC_SYMLINK_MAX,
		_PC_ACL_EXTENDED, _PC_ACL_PATH_MAX, _PC_CAP_PRESENT,
		_PC_INF_PRESENT, _PC_MAC_PRESENT, _PC_ACL_NFS4,
		_PC_MIN_HOLE_SIZE, 9999, -1,
	};
	static const char *const objs[] = { "f", "d", "fifo" };
	size_t i, j;
	long pv, fv;
	int fd, pe, fe;

	pc_mkfile("f", NULL);
	pc_mkdir("d");
	ATF_REQUIRE(mkfifo("fifo", 0644) == 0);
	pc_symlink("f", "lf");
	for (j = 0; j < nitems(objs); j++) {
		fd = open(objs[j], O_RDONLY | O_NONBLOCK);
		ATF_REQUIRE(fd >= 0);
		for (i = 0; i < nitems(names); i++) {
			errno = 0;
			pv = pathconf(objs[j], names[i]);
			pe = errno;
			errno = 0;
			fv = fpathconf(fd, names[i]);
			fe = errno;
			ATF_CHECK_MSG(pv == fv && pe == fe,
			    "%s name %d: pathconf %ld/%d, fpathconf %ld/%d",
			    objs[j], names[i], pv, pe, fv, fe);
			errno = 0;
			pv = lpathconf(objs[j], names[i]);
			pe = errno;
			ATF_CHECK_MSG(pv == fv && pe == fe,
			    "%s name %d: lpathconf %ld/%d, fpathconf %ld/%d",
			    objs[j], names[i], pv, pe, fv, fe);
		}
		close(fd);
	}
	/* pathconf follows the link. */
	ATF_CHECK_EQ(pathconf("lf", _PC_NAME_MAX), pathconf("f", _PC_NAME_MAX));
	CHECK_ERR(pathconf("missing", _PC_NAME_MAX), ENOENT);
	CHECK_ERR(lpathconf("", _PC_NAME_MAX), ENOENT);
}

ATF_TC_WITHOUT_HEAD(statfs_family);
ATF_TC_BODY(statfs_family, tc)
{
	static const char *const objs[] = { "f", ".", "/", "lf", "d/.." };
	struct statfs ps, fs;
	size_t i;
	int fd;

	pc_mkfile("f", NULL);
	pc_mkdir("d");
	pc_symlink("f", "lf");
	for (i = 0; i < nitems(objs); i++) {
		fd = open(objs[i], O_RDONLY);
		ATF_REQUIRE(fd >= 0);
		CHECK_OK(statfs(objs[i], &ps));
		ATF_REQUIRE(fstatfs(fd, &fs) == 0);
		ATF_CHECK_MSG(memcmp(&ps.f_fsid, &fs.f_fsid,
		    sizeof(ps.f_fsid)) == 0, "%s: fsid", objs[i]);
		ATF_CHECK_EQ(ps.f_type, fs.f_type);
		ATF_CHECK_STREQ(ps.f_fstypename, fs.f_fstypename);
		ATF_CHECK_STREQ(ps.f_mntonname, fs.f_mntonname);
		ATF_CHECK_EQ(ps.f_flags, fs.f_flags);
		close(fd);
	}
	CHECK_ERR(statfs("missing", &ps), ENOENT);
	CHECK_ERR(statfs("f", (struct statfs *)(uintptr_t)pc_unmapped()),
	    EFAULT);
	CHECK_ERR(statfs("missing", (struct statfs *)(uintptr_t)pc_unmapped()),
	    ENOENT);
}

static int
realpathat(int fd, const char *path, char *buf, size_t size)
{

	return (syscall(SYS___realpathat, fd, path, buf, size, 0));
}

ATF_TC_WITHOUT_HEAD(realpath_family);
ATF_TC_BODY(realpath_family, tc)
{
	char cwd[PATH_MAX], want[PATH_MAX + 16], buf[PATH_MAX];
	size_t len;
	int dfd;

	/* The oracle: getcwd(3) (vn_getcwd), which does no lookup. */
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	pc_mkdir("d");
	pc_mkdir("d/e");
	pc_mkfile("f", NULL);
	pc_symlink("d/e", "le");
	pc_symlink("f", "lf");
	ATF_REQUIRE(link("f", "hard") == 0);

	snprintf(want, sizeof(want), "%s/f", cwd);
	CHECK_OK(realpathat(AT_FDCWD, "f", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	CHECK_OK(realpathat(AT_FDCWD, "d/../f", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	CHECK_OK(realpathat(AT_FDCWD, "lf", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	CHECK_OK(realpathat(AT_FDCWD, ".//f", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	/* A hard link is named by the name used to reach it. */
	snprintf(want, sizeof(want), "%s/hard", cwd);
	CHECK_OK(realpathat(AT_FDCWD, "hard", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	/* Directories, through a link and relative to a descriptor. */
	snprintf(want, sizeof(want), "%s/d/e", cwd);
	CHECK_OK(realpathat(AT_FDCWD, "le", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);
	CHECK_OK(realpathat(dfd, "e", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, want);
	CHECK_OK(realpathat(dfd, "e/..", buf, sizeof(buf)));
	snprintf(want, sizeof(want), "%s/d", cwd);
	ATF_CHECK_STREQ(buf, want);
	CHECK_OK(realpathat(AT_FDCWD, ".", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, cwd);
	CHECK_OK(realpathat(AT_FDCWD, "/", buf, sizeof(buf)));
	ATF_CHECK_STREQ(buf, "/");
	/* The buffer must hold the path and its NUL. */
	snprintf(want, sizeof(want), "%s/f", cwd);
	len = strlen(want) + 1;
	CHECK_OK(realpathat(AT_FDCWD, "f", buf, len));
	/*
	 * Too small for the path: vn_fullpath_hardlink's ENOMEM (the
	 * ENAMETOOLONG test after it cannot trigger), below 2 bytes EINVAL.
	 */
	CHECK_ERR(realpathat(AT_FDCWD, "f", buf, len - 1), ENOMEM);
	CHECK_ERR(realpathat(AT_FDCWD, "f", buf, 1), EINVAL);
	CHECK_ERR(realpathat(AT_FDCWD, "f", buf, 0), EINVAL);
	CHECK_ERR(realpathat(AT_FDCWD, "f", (char *)(uintptr_t)pc_unmapped(),
	    sizeof(buf)), EFAULT);
	CHECK_ERR(realpathat(AT_FDCWD, "missing", buf, sizeof(buf)), ENOENT);
	CHECK_ERR(realpathat(dfd, "missing", buf, 0), ENOENT);
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(extattr_family);
ATF_TC_BODY(extattr_family, tc)
{
	char pbuf[64], fbuf[64];
	ssize_t pn, fn;
	int fd, pe, fe;

	pc_mkfile("f", NULL);
	pc_mkfile("twin", NULL);
	pc_symlink("f", "lf");
	fd = open("twin", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	if (extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, "probe", "v", 1) == -1)
		atf_tc_skip("user extended attributes unsupported: %s",
		    strerror(errno));
	(void)extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, "probe");

#define	SAME(pcall, fcall) do {						\
	errno = 0;							\
	pn = (pcall);							\
	pe = errno;							\
	errno = 0;							\
	fn = (fcall);							\
	fe = errno;							\
	ATF_CHECK_MSG(pn == fn && pe == fe,				\
	    "line %d: path %zd/%d, fd %zd/%d", __LINE__, pn, pe, fn, fe);\
} while (0)

	SAME(extattr_set_file("f", EXTATTR_NAMESPACE_USER, "k", "value", 5),
	    extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, "k", "value", 5));
	memset(pbuf, 0, sizeof(pbuf));
	memset(fbuf, 0, sizeof(fbuf));
	SAME(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "k", pbuf,
	    sizeof(pbuf)), extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "k",
	    fbuf, sizeof(fbuf)));
	ATF_CHECK(memcmp(pbuf, fbuf, sizeof(pbuf)) == 0);
	/* Through the link (followed) and its size query. */
	SAME(extattr_get_file("lf", EXTATTR_NAMESPACE_USER, "k", NULL, 0),
	    extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "k", NULL, 0));
	SAME(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "k", pbuf, 2),
	    extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "k", fbuf, 2));
	SAME(extattr_list_file("f", EXTATTR_NAMESPACE_USER, pbuf,
	    sizeof(pbuf)), extattr_list_fd(fd, EXTATTR_NAMESPACE_USER, fbuf,
	    sizeof(fbuf)));
	ATF_CHECK(memcmp(pbuf, fbuf, (size_t)(pn > 0 ? pn : 0)) == 0);
	SAME(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "nope", pbuf,
	    sizeof(pbuf)), extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "nope",
	    fbuf, sizeof(fbuf)));
	SAME(extattr_get_file("f", 99, "k", pbuf, sizeof(pbuf)),
	    extattr_get_fd(fd, 99, "k", fbuf, sizeof(fbuf)));
	SAME(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "", pbuf,
	    sizeof(pbuf)), extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "",
	    fbuf, sizeof(fbuf)));
	SAME(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "k",
	    (void *)(uintptr_t)pc_unmapped(), sizeof(pbuf)),
	    extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "k",
	    (void *)(uintptr_t)pc_unmapped(), sizeof(fbuf)));
	SAME(extattr_delete_file("f", EXTATTR_NAMESPACE_USER, "k"),
	    extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, "k"));
	SAME(extattr_delete_file("f", EXTATTR_NAMESPACE_USER, "k"),
	    extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, "k"));
	/* The _link variants on a regular file are the _file ones. */
	SAME(extattr_set_link("f", EXTATTR_NAMESPACE_USER, "k", "v", 1),
	    extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, "k", "v", 1));
	SAME(extattr_get_link("f", EXTATTR_NAMESPACE_USER, "k", NULL, 0),
	    extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, "k", NULL, 0));
	SAME(extattr_list_link("f", EXTATTR_NAMESPACE_USER, NULL, 0),
	    extattr_list_fd(fd, EXTATTR_NAMESPACE_USER, NULL, 0));
	SAME(extattr_delete_link("f", EXTATTR_NAMESPACE_USER, "k"),
	    extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, "k"));
#undef SAME
	/* The _link variants do not follow: the link has no "k". */
	ATF_REQUIRE(extattr_set_file("lf", EXTATTR_NAMESPACE_USER, "k", "v",
	    1) == 1);
	ATF_CHECK(extattr_get_file("f", EXTATTR_NAMESPACE_USER, "k", NULL,
	    0) == 1);
	ATF_CHECK(extattr_get_link("lf", EXTATTR_NAMESPACE_USER, "k", NULL,
	    0) == -1);
	CHECK_ERR(extattr_get_file("missing", EXTATTR_NAMESPACE_USER, "k",
	    NULL, 0), ENOENT);
	CHECK_ERR(extattr_list_link("nodir/x", EXTATTR_NAMESPACE_USER, NULL,
	    0), ENOENT);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(acl_family);
ATF_TC_BODY(acl_family, tc)
{
	acl_t pa, fa;
	acl_type_t type;
	char *pt, *ft;
	int fd, pe, fe;
	long r;

	pc_mkfile("f", NULL);
	pc_symlink("f", "lf");
	if (pathconf("f", _PC_ACL_NFS4) > 0)
		type = ACL_TYPE_NFS4;
	else if (pathconf("f", _PC_ACL_EXTENDED) > 0)
		type = ACL_TYPE_ACCESS;
	else
		atf_tc_skip("no ACL support on this file system");
	fd = open("f", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	pa = acl_get_file("f", type);
	fa = acl_get_fd_np(fd, type);
	ATF_REQUIRE(pa != NULL && fa != NULL);
	pt = acl_to_text(pa, NULL);
	ft = acl_to_text(fa, NULL);
	ATF_REQUIRE(pt != NULL && ft != NULL);
	ATF_CHECK_STREQ(pt, ft);
	acl_free(pt);
	acl_free(ft);
	/* Following a link. */
	acl_free(pa);
	pa = acl_get_file("lf", type);
	ATF_CHECK(pa != NULL);
	/* Setting through the path, read back through the descriptor. */
	if (pa != NULL) {
		CHECK_OK(acl_set_file("f", type, pa));
		acl_free(pa);
	}
	/* The raw calls agree with the descriptor ones. */
	errno = 0;
	r = syscall(SYS___acl_aclcheck_file, "f", type, fa);
	pe = r == -1 ? errno : 0;
	errno = 0;
	r = syscall(SYS___acl_aclcheck_fd, fd, type, fa);
	fe = r == -1 ? errno : 0;
	ATF_CHECK_EQ(pe, fe);
	/* An unsupported type: the same error as the descriptor call. */
	errno = 0;
	r = syscall(SYS___acl_get_file, "f", ACL_TYPE_DEFAULT,
	    (void *)(uintptr_t)pc_unmapped());
	pe = r == -1 ? errno : 0;
	errno = 0;
	r = syscall(SYS___acl_get_fd, fd, ACL_TYPE_DEFAULT,
	    (void *)(uintptr_t)pc_unmapped());
	fe = r == -1 ? errno : 0;
	ATF_CHECK_EQ(pe, fe);
	CHECK_ERR(acl_get_file("missing", type) == NULL ? -1 : 0, ENOENT);
	acl_free(fa);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(inotify_family);
ATF_TC_BODY(inotify_family, tc)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	struct inotify_event *ev;
	ssize_t n;
	int ifd, wd, wl, wf, wd2;

	pc_mkfile("f", NULL);
	pc_mkdir("d");
	pc_symlink("f", "lf");
	ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	ATF_REQUIRE(ifd >= 0);
	wd = inotify_add_watch(ifd, "f", IN_MODIFY | IN_ATTRIB);
	CHECK_OK(wd);
	ATF_REQUIRE(chmod("f", 0600) == 0);
	n = read(ifd, buf, sizeof(buf));
	ATF_CHECK(n >= (ssize_t)sizeof(struct inotify_event));
	if (n >= (ssize_t)sizeof(struct inotify_event)) {
		ev = (struct inotify_event *)(void *)buf;
		ATF_CHECK_EQ(ev->wd, wd);
		ATF_CHECK((ev->mask & IN_ATTRIB) != 0);
	}
	/*
	 * The same vnode through the followed link: the existing watch
	 * (vn_inotify_add_watch returns the watch of the vnode).  With
	 * IN_DONT_FOLLOW the link itself is watched: a different one.
	 */
	wf = inotify_add_watch(ifd, "lf", IN_MODIFY);
	CHECK_OK(wf);
	ATF_CHECK_EQ(wf, wd);
	wl = inotify_add_watch(ifd, "lf", IN_MODIFY | IN_DONT_FOLLOW);
	CHECK_OK(wl);
	ATF_CHECK(wl != wd);
	CHECK_ERR(inotify_add_watch(ifd, "f", IN_MODIFY | IN_ONLYDIR), ENOTDIR);
	wd2 = inotify_add_watch(ifd, "d", IN_CREATE | IN_ONLYDIR);
	CHECK_OK(wd2);
	CHECK_ERR(inotify_add_watch(ifd, "f", IN_MODIFY | IN_MASK_CREATE),
	    EEXIST);
	CHECK_ERR(inotify_add_watch(ifd, "missing", IN_MODIFY), ENOENT);
	if (!pc_is_root()) {
		ATF_REQUIRE(chmod("f", 0200) == 0);
		CHECK_ERR(inotify_add_watch(ifd, "f", IN_MODIFY), EACCES);
	}
	close(ifd);
}

static void
child_chroot(void)
{
	struct stat a, b;
	int fd;

	C_EXPECT(chroot("jail") == 0);
	/* The working directory is outside the new root, as chroot(2) says. */
	C_EXPECT(chdir("/") == 0);
	C_EXPECT(stat("/inside", &a) == 0);
	C_EXPECT(stat("/../../inside", &b) == 0);
	C_EXPECT(a.st_ino == b.st_ino);
	C_EXPECT(stat("/outside", &a) == -1 && errno == ENOENT);
	/* An absolute symlink resolves in the new root. */
	C_EXPECT(stat("/abslink", &a) == 0 && a.st_ino == b.st_ino);
	fd = open("/", O_RDONLY | O_DIRECTORY);
	C_EXPECT(fd >= 0);
	C_EXPECT(fstatat(fd, "../inside", &a, 0) == 0);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(chdir_family);
ATF_TC_BODY(chdir_family, tc)
{
	char cwd[PATH_MAX], buf[PATH_MAX], want[PATH_MAX + 8];
	int cwdfd, dfd, ffd, pfd;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	cwdfd = open(".", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(cwdfd >= 0);
	pc_mkdir("d");
	pc_mkfile("f", NULL);
	pc_symlink("d", "ld");
	CHECK_ERR(chdir("f"), ENOTDIR);
	CHECK_ERR(chdir("missing"), ENOENT);
	CHECK_ERR(chdir(""), ENOENT);
	CHECK_ERR(chdir(NULL), EFAULT);
	CHECK_OK(chdir("ld"));
	ATF_REQUIRE(getcwd(buf, sizeof(buf)) != NULL);
	snprintf(want, sizeof(want), "%s/d", cwd);
	ATF_CHECK_STREQ(buf, want);
	ATF_REQUIRE(fchdir(cwdfd) == 0);
	ffd = open("f", O_RDONLY);
	dfd = open("d", O_PATH | O_DIRECTORY);
	pfd = pc_pipefd();
	ATF_REQUIRE(ffd >= 0 && dfd >= 0);
	CHECK_ERR(fchdir(ffd), ENOTDIR);
	CHECK_ERR(fchdir(pfd), EINVAL);
	CHECK_ERR(fchdir(-1), EBADF);
	CHECK_OK(fchdir(dfd));
	ATF_REQUIRE(getcwd(buf, sizeof(buf)) != NULL);
	ATF_CHECK_STREQ(buf, want);
	ATF_REQUIRE(fchdir(cwdfd) == 0);
	if (!pc_is_root()) {
		ATF_REQUIRE(chmod("d", 0600) == 0);
		CHECK_ERR(chdir("d"), EACCES);
		CHECK_ERR(fchdir(dfd), EACCES);
		ATF_REQUIRE(chmod("d", 0755) == 0);
	} else {
		CHECK_ERR(chroot("f"), ENOTDIR);
		pc_mkdir("jail");
		pc_mkfile("jail/inside", NULL);
		pc_mkfile("outside", NULL);
		pc_symlink("/inside", "jail/abslink");
		in_child(child_chroot);
	}
	close(cwdfd);
	close(ffd);
	close(dfd);
}

ATF_TC(fh_family);
ATF_TC_HEAD(fh_family, tc)
{

	atf_tc_set_md_var(tc, "descr", "getfh/fhopen/fhlink/fhlinkat/"
	    "fhreadlink round trips as root");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fh_family, tc)
{
	fhandle_t fh, lfh;
	struct stat a, b;
	char buf[64];
	int dfd, fd, e;

	pc_mkfile("f", "content\n");
	pc_symlink("f", "lf");
	pc_mkdir("d");
	e = ERRNO_OF(getfh("f", &fh));
	if (e == EOPNOTSUPP)
		atf_tc_skip("file handles unsupported here");
	ATF_REQUIRE_EQ(e, 0);
	fd = fhopen(&fh, O_RDONLY);
	CHECK_OK(fd);
	if (fd >= 0) {
		memset(buf, 0, sizeof(buf));
		ATF_CHECK_EQ(read(fd, buf, sizeof(buf)), 8);
		ATF_CHECK_STREQ(buf, "content\n");
		close(fd);
	}
	CHECK_OK(fhstat(&fh, &a));
	ATF_REQUIRE(stat("f", &b) == 0);
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	/* getfh follows a link; getfhat(AT_SYMLINK_NOFOLLOW) does not. */
	memset(&lfh, 0, sizeof(lfh));
	CHECK_OK(getfh("lf", &lfh));
	ATF_CHECK(memcmp(&lfh, &fh, sizeof(fh)) == 0);
	CHECK_OK(getfhat(AT_FDCWD, "lf", &lfh, AT_SYMLINK_NOFOLLOW));
	ATF_CHECK(memcmp(&lfh, &fh, sizeof(fh)) != 0);
	memset(buf, 0, sizeof(buf));
	ATF_CHECK_EQ(fhreadlink(&lfh, buf, sizeof(buf)), 1);
	ATF_CHECK_STREQ(buf, "f");
	/* fhlink / fhlinkat create a new name for the same file. */
	CHECK_OK(fhlink(&fh, "viafh"));
	ATF_CHECK_EQ(pc_ino("viafh", true), b.st_ino);
	dfd = open("d", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);
	CHECK_OK(fhlinkat(&fh, dfd, "viafh2"));
	ATF_CHECK_EQ(pc_ino("d/viafh2", true), b.st_ino);
	CHECK_ERR(fhlink(&fh, "viafh"), EEXIST);
	CHECK_ERR(fhlinkat(&fh, -1, "x"), EBADF);
	CHECK_ERR(fhlinkat(&fh, pc_pipefd(), "x"), ENOTDIR);
	CHECK_ERR(fhlink(&fh, "nodir/x"), ENOENT);
	CHECK_ERR(fhlink(&fh, NULL), EFAULT);
	CHECK_ERR(fhopen(&fh, O_CREAT | O_RDWR), EINVAL);
	CHECK_ERR(getfh("missing", &fh), ENOENT);
	CHECK_ERR(getfhat(-1, "f", &fh, 0), EBADF);
	CHECK_ERR(getfhat(AT_FDCWD, "f", &fh, AT_EMPTY_PATH), EINVAL);
	close(dfd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, chmod_family);
	ATF_TP_ADD_TC(tp, chown_family);
	ATF_TP_ADD_TC(tp, chflags_family);
	ATF_TP_ADD_TC(tp, chflags_sf_root);
	ATF_TP_ADD_TC(tp, utimes_family);
	ATF_TP_ADD_TC(tp, truncate_family);
	ATF_TP_ADD_TC(tp, access_family);
	ATF_TP_ADD_TC(tp, pathconf_family);
	ATF_TP_ADD_TC(tp, statfs_family);
	ATF_TP_ADD_TC(tp, realpath_family);
	ATF_TP_ADD_TC(tp, extattr_family);
	ATF_TP_ADD_TC(tp, acl_family);
	ATF_TP_ADD_TC(tp, inotify_family);
	ATF_TP_ADD_TC(tp, chdir_family);
	ATF_TP_ADD_TC(tp, fh_family);
	return (atf_no_error());
}
