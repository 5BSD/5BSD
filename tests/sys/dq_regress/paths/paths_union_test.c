/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * /dev/fd lookups through stacked file systems over fdescfs.
 *
 * What it tries to break: a nodup fdescfs lookup of a descriptor that
 * carries reduced capability rights or UF_RESOLVE_BENEATH hands that
 * metadata to namei by writing through vfs_lookup_nameidata(cnp)
 * (ni_resflags, ni_filecaps).  That function trusts NAMEILOOKUP to mean
 * "cnp is the ni_cnd of a nameidata".  unionfs looks up its lower layer
 * with a stack copy of the componentname; if the copy kept NAMEILOOKUP,
 * fdescfs below unionfs wrote into unionfs_lookup()'s stack frame.
 *
 * WARNING: on a kernel without the fix the limited and beneath cases
 * corrupt the kernel stack.  Run them only in a disposable VM.
 *
 * Every case mounts the same fdescfs configuration three ways under the
 * work directory: directly ("fd"), below a read-only unionfs ("u") and
 * below nullfs ("n"), and compares each stacked lookup with the direct
 * one.  nullfs passes the caller's componentname down, so it must match
 * the direct mount exactly.  unionfs cannot pass the metadata through its
 * copy, so for a descriptor with lookup metadata fdescfs refuses the
 * handoff with ENOTCAPABLE (its answer when there is no nameidata); it
 * must never succeed with different rights.  When neither layer has the
 * name unionfs_lookup() reports the upper layer's error, so the refusal
 * reaches the caller as the empty upper directory's ENOENT, as does a
 * closed descriptor number (EBADF on the direct mount).  Descriptors
 * without lookup metadata must give the direct answer through both.
 *
 * With -v pre1c=yes (a baseline on the kernel from before stage 1c,
 * which lacks the unionfs fix) the limited and beneath cases are skipped.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntopts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

static const char *const nodup[] = { "nodup", NULL };
static const char *const linrdlnk[] = { "linrdlnk", NULL };
static const char *const nodup_linrdlnk[] = { "nodup", "linrdlnk", NULL };

/* Mount points, removed by the cleanup in reverse order of mounting. */
static const char *const mounts[] = { "n", "u", "upper", "u", "fd" };

/* What a lookup of a /dev/fd path and an open of the result gave. */
struct lookup_result {
	int		lr_stat_error;
	ino_t		lr_ino;
	int		lr_open_error;
	char		lr_byte;	/* first byte of a regular file */
	cap_rights_t	lr_rights;
	int		lr_fioclex;	/* errno of FIOCLEX on the copy */
	int		lr_fionclex;	/* errno of FIONCLEX on the copy */
	int		lr_dotdot;	/* errno of openat(copy, "..") */
};

static void
mount_fs(const char *fstype, const char *fspath, const char *from,
    const char *const *opts, int flags)
{
	struct iovec *iov;
	char errmsg[256];
	int error, iovlen;

	iov = NULL;
	iovlen = 0;
	build_iovec(&iov, &iovlen, "fstype", __DECONST(char *, fstype),
	    (size_t)-1);
	build_iovec(&iov, &iovlen, "fspath", __DECONST(char *, fspath),
	    (size_t)-1);
	if (from != NULL)
		build_iovec(&iov, &iovlen, "from", __DECONST(char *, from),
		    (size_t)-1);
	for (; opts != NULL && *opts != NULL; opts++)
		build_iovec(&iov, &iovlen, __DECONST(char *, *opts), NULL,
		    (size_t)-1);
	build_iovec(&iov, &iovlen, "errmsg", errmsg, sizeof(errmsg));
	errmsg[0] = '\0';
	error = nmount(iov, iovlen, flags);
	free_iovec(&iov, &iovlen);
	if (error != 0 && (errno == ENODEV || errno == ENOEXEC ||
	    errno == EOPNOTSUPP))
		atf_tc_skip("cannot mount %s on %s: %s", fstype, fspath,
		    errmsg[0] != '\0' ? errmsg : strerror(errno));
	ATF_REQUIRE_MSG(error == 0, "nmount %s on %s: %s", fstype, fspath,
	    errmsg[0] != '\0' ? errmsg : strerror(errno));
}

/*
 * fdescfs with opts on "fd" and on "u"; a read-only unionfs over "u" with
 * the empty directory "upper" on top (read-only, so lookups never create
 * shadow directories); nullfs on "n" over "fd".  "upper" is a tmpfs: with
 * the union's upper layer on UFS, unmounting the stack records both
 * ufs -> fdescfs and fdescfs -> ufs, a WITNESS false positive between
 * different vnodes of one lock class (5bsd-issues
 * 2026-11-08-unionfs-fdescfs-unmount-witness-fp.md).
 */
static void
setup_stacks(const char *const *opts)
{
	char path[PATH_MAX];

	ATF_REQUIRE_EQ(0, mkdir("fd", 0755));
	ATF_REQUIRE_EQ(0, mkdir("u", 0755));
	ATF_REQUIRE_EQ(0, mkdir("n", 0755));
	ATF_REQUIRE_EQ(0, mkdir("upper", 0755));
	mount_fs("fdescfs", "fd", NULL, opts, 0);
	mount_fs("fdescfs", "u", NULL, opts, 0);
	mount_fs("tmpfs", "upper", NULL, NULL, 0);
	ATF_REQUIRE(realpath("upper", path) != NULL);
	mount_fs("unionfs", "u", path, NULL, MNT_RDONLY);
	ATF_REQUIRE(realpath("fd", path) != NULL);
	mount_fs("nullfs", "n", path, NULL, 0);
}

static void
cleanup_stacks(void)
{
	size_t i;

	for (i = 0; i < nitems(mounts); i++)
		(void)unmount(mounts[i], MNT_FORCE);
}

static void
probe(const char *top, int fd, const char *suffix, int oflags,
    struct lookup_result *r)
{
	struct stat sb;
	char path[64];
	int copy, dfd, len;

	memset(r, 0, sizeof(*r));
	len = snprintf(path, sizeof(path), "%s/%d%s", top, fd, suffix);
	ATF_REQUIRE(len > 0 && (size_t)len < sizeof(path));

	r->lr_stat_error = ERRNO_OF(stat(path, &sb));
	if (r->lr_stat_error == 0)
		r->lr_ino = sb.st_ino;

	errno = 0;
	copy = open(path, oflags);
	if (copy == -1) {
		r->lr_open_error = errno;
		return;
	}
	ATF_REQUIRE_EQ(0, fstat(copy, &sb));
	if (S_ISREG(sb.st_mode))
		ATF_REQUIRE_EQ(1, read(copy, &r->lr_byte, 1));
	ATF_REQUIRE_EQ(0, cap_rights_get(copy, &r->lr_rights));
	r->lr_fioclex = ERRNO_OF(ioctl(copy, FIOCLEX, 0));
	r->lr_fionclex = ERRNO_OF(ioctl(copy, FIONCLEX, 0));
	if (S_ISDIR(sb.st_mode)) {
		errno = 0;
		dfd = openat(copy, "..", O_RDONLY | O_DIRECTORY);
		r->lr_dotdot = dfd == -1 ? errno : 0;
		if (dfd != -1)
			ATF_REQUIRE_EQ(0, close(dfd));
	}
	ATF_REQUIRE_EQ(0, close(copy));
}

/*
 * Compare the lookup of path through top with the direct one.  With
 * fail_closed, top may instead refuse both the stat and the open with
 * unionfs's ENOENT (see above).
 */
static void
compare(const char *top, int fd, const char *suffix, int oflags,
    bool fail_closed)
{
	struct lookup_result direct, other;

	probe("fd", fd, suffix, oflags, &direct);
	probe(top, fd, suffix, oflags, &other);
	if (fail_closed && other.lr_stat_error == ENOENT &&
	    other.lr_open_error == ENOENT)
		return;
	ATF_CHECK_EQ_MSG(direct.lr_stat_error, other.lr_stat_error,
	    "%s/%d%s: stat errno %d, direct %d", top, fd, suffix,
	    other.lr_stat_error, direct.lr_stat_error);
	ATF_CHECK_EQ_MSG(direct.lr_ino, other.lr_ino,
	    "%s/%d%s: inode %ju, direct %ju", top, fd, suffix,
	    (uintmax_t)other.lr_ino, (uintmax_t)direct.lr_ino);
	ATF_CHECK_EQ_MSG(direct.lr_open_error, other.lr_open_error,
	    "%s/%d%s: open errno %d, direct %d", top, fd, suffix,
	    other.lr_open_error, direct.lr_open_error);
	if (direct.lr_open_error != 0 || other.lr_open_error != 0)
		return;
	ATF_CHECK_EQ_MSG(direct.lr_byte, other.lr_byte,
	    "%s/%d%s: read differs", top, fd, suffix);
	ATF_CHECK_MSG(cap_rights_contains(&direct.lr_rights,
	    &other.lr_rights) &&
	    cap_rights_contains(&other.lr_rights, &direct.lr_rights),
	    "%s/%d%s: capability rights differ", top, fd, suffix);
	ATF_CHECK_EQ_MSG(direct.lr_fioclex, other.lr_fioclex,
	    "%s/%d%s: FIOCLEX errno %d, direct %d", top, fd, suffix,
	    other.lr_fioclex, direct.lr_fioclex);
	ATF_CHECK_EQ_MSG(direct.lr_fionclex, other.lr_fionclex,
	    "%s/%d%s: FIONCLEX errno %d, direct %d", top, fd, suffix,
	    other.lr_fionclex, direct.lr_fionclex);
	ATF_CHECK_EQ_MSG(direct.lr_dotdot, other.lr_dotdot,
	    "%s/%d%s: openat .. errno %d, direct %d", top, fd, suffix,
	    other.lr_dotdot, direct.lr_dotdot);
}

static int
make_file(const char *path)
{
	int fd;

	ATF_REQUIRE((fd = open(path, O_RDWR | O_CREAT, 0644)) >= 0);
	ATF_REQUIRE_EQ(1, write(fd, "x", 1));
	ATF_REQUIRE_EQ(0, lseek(fd, 0, SEEK_SET));
	return (fd);
}

/* A file descriptor with reduced rights and ioctls. */
static int
make_limited_file(void)
{
	cap_ioctl_t cmds[] = { FIOCLEX };
	cap_rights_t rights;
	int fd;

	fd = make_file("limited");
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, &rights));
	ATF_REQUIRE_EQ(0, cap_ioctls_limit(fd, cmds, nitems(cmds)));
	return (fd);
}

/*
 * The limited lookups are repeated so that a write into a stale stack
 * frame has many chances to hit live state.
 */
#define	ROUNDS	32

/*
 * The limited and beneath cases corrupt the kernel stack of a kernel
 * without the unionfs fix: skip them in a pre-1c baseline.
 */
static void
skip_unfixed(const atf_tc_t *tc)
{

	if (pc_pre1c(tc))
		atf_tc_skip("pre1c: corrupts the stack of an unfixed kernel "
		    "(/home/koryheard/5bsd-issues/"
		    "2026-11-08-unionfs-nameilookup-stack-write.md)");
}

static void
check_limited(const atf_tc_t *tc, const char *const *opts)
{
	int fd, i;

	skip_unfixed(tc);
	setup_stacks(opts);
	fd = make_limited_file();
	for (i = 0; i < ROUNDS; i++) {
		compare("n", fd, "", O_RDONLY, false);
		compare("u", fd, "", O_RDONLY, true);
	}
	ATF_REQUIRE_EQ(0, close(fd));
}

#define	UNION_TC(name, description)					\
	ATF_TC_WITH_CLEANUP(name);					\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "descr", description);		\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "60");			\
	}								\
	ATF_TC_CLEANUP(name, tc)					\
	{								\
		cleanup_stacks();					\
	}

UNION_TC(nodup_plain,
    "nodup lookups of unrestricted descriptors match the direct mount");
ATF_TC_BODY(nodup_plain, tc)
{
	struct lookup_result r;
	int dirfd, fd;

	setup_stacks(nodup);
	fd = make_file("plain");
	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	ATF_REQUIRE((dirfd = open("dir", O_RDONLY | O_DIRECTORY)) >= 0);
	compare("n", fd, "", O_RDONLY, false);
	compare("u", fd, "", O_RDONLY, false);
	compare("n", dirfd, "", O_RDONLY | O_DIRECTORY, false);
	compare("u", dirfd, "", O_RDONLY | O_DIRECTORY, false);
	/*
	 * A closed descriptor number: EBADF directly and through nullfs;
	 * unionfs reports its upper layer's ENOENT.
	 */
	compare("n", 1000, "", O_RDONLY, false);
	probe("u", 1000, "", O_RDONLY, &r);
	ATF_CHECK_EQ_MSG(ENOENT, r.lr_stat_error, "u/1000: stat errno %d",
	    r.lr_stat_error);
	ATF_CHECK_EQ_MSG(ENOENT, r.lr_open_error, "u/1000: open errno %d",
	    r.lr_open_error);
	ATF_REQUIRE_EQ(0, close(dirfd));
	ATF_REQUIRE_EQ(0, close(fd));
}

UNION_TC(nodup_limited,
    "nodup lookups of a descriptor with limited rights and ioctls");
ATF_TC_BODY(nodup_limited, tc)
{
	check_limited(tc, nodup);
}

UNION_TC(nodup_linrdlnk_limited,
    "nodup,linrdlnk lookups of a descriptor with limited rights");
ATF_TC_BODY(nodup_linrdlnk_limited, tc)
{
	check_limited(tc, nodup_linrdlnk);
}

UNION_TC(nodup_beneath,
    "nodup lookups of an FD_RESOLVE_BENEATH directory descriptor");
ATF_TC_BODY(nodup_beneath, tc)
{
	int dirfd, i;

	skip_unfixed(tc);
	setup_stacks(nodup);
	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	ATF_REQUIRE((dirfd = open("dir", O_RDONLY | O_DIRECTORY)) >= 0);
	ATF_REQUIRE_EQ(0, fcntl(dirfd, F_SETFD, FD_RESOLVE_BENEATH));
	for (i = 0; i < ROUNDS; i++) {
		compare("n", dirfd, "", O_RDONLY | O_DIRECTORY, false);
		compare("u", dirfd, "", O_RDONLY | O_DIRECTORY, true);
	}
	ATF_REQUIRE_EQ(0, close(dirfd));
}

UNION_TC(linrdlnk_traverse,
    "linrdlnk traversal through a directory descriptor");
ATF_TC_BODY(linrdlnk_traverse, tc)
{
	int dirfd, fd;

	setup_stacks(linrdlnk);
	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	fd = make_file("dir/marker");
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE((dirfd = open("dir", O_RDONLY | O_DIRECTORY)) >= 0);
	compare("n", dirfd, "/marker", O_RDONLY, false);
	compare("u", dirfd, "/marker", O_RDONLY, false);
	compare("n", dirfd, "/", O_RDONLY | O_DIRECTORY, false);
	compare("u", dirfd, "/", O_RDONLY | O_DIRECTORY, false);
	ATF_REQUIRE_EQ(0, close(dirfd));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, nodup_plain);
	ATF_TP_ADD_TC(tp, nodup_limited);
	ATF_TP_ADD_TC(tp, nodup_linrdlnk_limited);
	ATF_TP_ADD_TC(tp, nodup_beneath);
	ATF_TP_ADD_TC(tp, linrdlnk_traverse);
	return (atf_no_error());
}
