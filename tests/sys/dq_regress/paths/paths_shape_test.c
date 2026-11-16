/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Path shapes against every path system call.
 *
 * Each operation of the table is run on a family of adversarial path
 * strings: NULL, an unmapped pointer, a string running into an unmapped
 * page, the empty string, MAXPATHLEN and MAXPATHLEN - 1 bytes, components
 * of NAME_MAX and NAME_MAX + 1 bytes, a missing or non-directory
 * intermediate component, trailing slashes, "x/." and "x/..", repeated
 * slashes, a symlink loop and a chain of exactly MAXSYMLINKS links.
 *
 * What it tries to break: the stage-1c wrappers copy, inspect or post the
 * path before the real lookup for attached processes; namei_setup and
 * namei gained hooks.  An unattached process must see exactly the errors
 * namei() at 3f330ee172d gives: copyinstr's EFAULT/ENAMETOOLONG first, the
 * empty-path ENOENT before any start-directory work, ENAMETOOLONG for a
 * long component, ELOOP after MAXSYMLINKS (32) links, and so on.
 */

#include <sys/param.h>
#include <sys/extattr.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

/* What must exist at the operated path before the call. */
enum op_kind {
	K_FILE,		/* a regular file */
	K_DIR,		/* an empty directory */
	K_NEW,		/* nothing: the call creates it */
	K_LINK,		/* a symlink to the regular file "zz_tgt" */
};

struct op {
	const char	*name;
	enum op_kind	 kind;
	int		(*fn)(const char *);
	/*
	 * When non-NULL, success on a well-formed path is not guaranteed by
	 * every file system: the expected errno is the one this descriptor
	 * variant of the operation gives on the same object (no lookup).
	 */
	int		(*oracle)(int);
	/*
	 * The operated path's last component is looked up for DELETE or
	 * RENAME (vfs_lookup refuses a final "." or ".." with EINVAL).
	 */
	bool		 modlast;
};

static int inofd = -1;

static int
inotify_fd(void)
{

	if (inofd == -1) {
		inofd = inotify_init1(IN_CLOEXEC);
		ATF_REQUIRE(inofd >= 0);
	}
	return (inofd);
}

static int
op_open(const char *p)
{
	int fd;

	fd = open(p, O_RDONLY);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
op_openat(const char *p)
{
	int fd;

	fd = openat(AT_FDCWD, p, O_RDONLY);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
op_openpath(const char *p)
{
	int fd;

	fd = open(p, O_PATH);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
op_stat(const char *p)
{
	struct stat sb;

	return (stat(p, &sb));
}

static int
op_lstat(const char *p)
{
	struct stat sb;

	return (lstat(p, &sb));
}

static int
op_fstatat(const char *p)
{
	struct stat sb;

	return (fstatat(AT_FDCWD, p, &sb, AT_SYMLINK_NOFOLLOW));
}

static int
op_access(const char *p)
{

	return (access(p, F_OK));
}

static int
op_eaccess(const char *p)
{

	return (eaccess(p, R_OK));
}

static int
op_faccessat(const char *p)
{

	return (faccessat(AT_FDCWD, p, R_OK, AT_EACCESS));
}

static int
op_chmod(const char *p)
{

	return (chmod(p, 0644));
}

static int
op_lchmod(const char *p)
{

	return (lchmod(p, 0644));
}

static int
or_fchmod(int fd)
{

	return (fchmod(fd, 0644));
}

static int
op_fchmodat(const char *p)
{

	return (fchmodat(AT_FDCWD, p, 0644, 0));
}

static int
op_chown(const char *p)
{

	return (chown(p, (uid_t)-1, (gid_t)-1));
}

static int
op_lchown(const char *p)
{

	return (lchown(p, (uid_t)-1, (gid_t)-1));
}

static int
op_fchownat(const char *p)
{

	return (fchownat(AT_FDCWD, p, (uid_t)-1, (gid_t)-1,
	    AT_SYMLINK_NOFOLLOW));
}

static int
op_chflags(const char *p)
{

	return (chflags(p, 0));
}

static int
op_lchflags(const char *p)
{

	return (lchflags(p, 0));
}

static int
op_chflagsat(const char *p)
{

	return (chflagsat(AT_FDCWD, p, 0, 0));
}

static int
or_fchflags(int fd)
{

	return (fchflags(fd, 0));
}

static int
op_utimes(const char *p)
{

	return (utimes(p, NULL));
}

static int
op_lutimes(const char *p)
{

	return (lutimes(p, NULL));
}

static int
op_futimesat(const char *p)
{

	return (futimesat(AT_FDCWD, p, NULL));
}

static int
op_utimensat(const char *p)
{

	return (utimensat(AT_FDCWD, p, NULL, 0));
}

static int
op_truncate(const char *p)
{

	return (truncate(p, 0));
}

static int
op_pathconf(const char *p)
{

	return (pathconf(p, _PC_NAME_MAX) == -1 ? -1 : 0);
}

static int
op_lpathconf(const char *p)
{

	return (lpathconf(p, _PC_NAME_MAX) == -1 ? -1 : 0);
}

static int
op_statfs(const char *p)
{
	struct statfs sf;

	return (statfs(p, &sf));
}

static int
op_realpath(const char *p)
{
	char buf[PATH_MAX];

	return (syscall(SYS___realpathat, AT_FDCWD, p, buf, sizeof(buf), 0));
}

static int
op_xattr_list(const char *p)
{

	return (extattr_list_file(p, EXTATTR_NAMESPACE_USER, NULL, 0) == -1 ?
	    -1 : 0);
}

static int
op_xattr_list_link(const char *p)
{

	return (extattr_list_link(p, EXTATTR_NAMESPACE_USER, NULL, 0) == -1 ?
	    -1 : 0);
}

static int
or_xattr_list(int fd)
{

	return (extattr_list_fd(fd, EXTATTR_NAMESPACE_USER, NULL, 0) == -1 ?
	    -1 : 0);
}

static int
op_inotify(const char *p)
{
	int wd;

	wd = inotify_add_watch(inotify_fd(), p, IN_ALL_EVENTS);
	if (wd >= 0)
		(void)inotify_rm_watch(inotify_fd(), wd);
	return (wd < 0 ? -1 : 0);
}

static int
op_unlink(const char *p)
{

	return (unlink(p));
}

static int
op_unlinkat(const char *p)
{

	return (unlinkat(AT_FDCWD, p, 0));
}

static int
op_funlinkat(const char *p)
{

	return (funlinkat(AT_FDCWD, p, FD_NONE, 0));
}

static int
op_rename_from(const char *p)
{

	return (rename(p, "zz_renamed"));
}

static int
op_renameat2_from(const char *p)
{

	return (renameat2(AT_FDCWD, p, AT_FDCWD, "zz_renamed",
	    AT_RENAME_NOREPLACE));
}

static int
op_rename_over(const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (rename("zz_src", p));
}

static int
op_link_from(const char *p)
{

	return (link(p, "zz_linked"));
}

static int
op_linkat_from(const char *p)
{

	return (linkat(AT_FDCWD, p, AT_FDCWD, "zz_linked", AT_SYMLINK_FOLLOW));
}

static int
op_rmdir(const char *p)
{

	return (rmdir(p));
}

static int
op_unlinkat_dir(const char *p)
{

	return (unlinkat(AT_FDCWD, p, AT_REMOVEDIR));
}

static int
op_chdir(const char *p)
{
	int cwd, error, saved;

	cwd = open(".", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(cwd >= 0);
	error = chdir(p);
	saved = errno;
	if (error == 0)
		ATF_REQUIRE(fchdir(cwd) == 0);
	close(cwd);
	errno = saved;
	return (error);
}

static int
op_mkdir(const char *p)
{

	return (mkdir(p, 0755));
}

static int
op_mkdirat(const char *p)
{

	return (mkdirat(AT_FDCWD, p, 0755));
}

static int
op_mkfifo(const char *p)
{

	return (mkfifo(p, 0644));
}

static int
op_mkfifoat(const char *p)
{

	return (mkfifoat(AT_FDCWD, p, 0644));
}

static int
op_mknod_fifo(const char *p)
{

	return (mknod(p, S_IFIFO | 0644, 0));
}

static int
op_symlink_to(const char *p)
{

	return (symlink("zz_tgt", p));
}

static int
op_symlinkat_to(const char *p)
{

	return (symlinkat("zz_tgt", AT_FDCWD, p));
}

static int
op_link_to(const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (link("zz_src", p));
}

static int
op_linkat_to(const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (linkat(AT_FDCWD, "zz_src", AT_FDCWD, p, 0));
}

static int
op_creat_excl(const char *p)
{
	int fd;

	fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
op_creat(const char *p)
{
	int fd;

	fd = openat(AT_FDCWD, p, O_RDWR | O_CREAT, 0644);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static int
op_rename_to_new(const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (rename("zz_src", p));
}

static int
op_renameat2_to_new(const char *p)
{

	pc_mkfile("zz_src", NULL);
	return (renameat2(AT_FDCWD, "zz_src", AT_FDCWD, p,
	    AT_RENAME_NOREPLACE));
}

static int
op_readlink(const char *p)
{
	char buf[PATH_MAX];

	return (readlink(p, buf, sizeof(buf)) == -1 ? -1 : 0);
}

static int
op_readlinkat(const char *p)
{
	char buf[PATH_MAX];

	return (readlinkat(AT_FDCWD, p, buf, sizeof(buf)) == -1 ? -1 : 0);
}

static const struct op ops[] = {
	{ "open", K_FILE, op_open, NULL, false },
	{ "openat", K_FILE, op_openat, NULL, false },
	{ "open_O_PATH", K_FILE, op_openpath, NULL, false },
	{ "stat", K_FILE, op_stat, NULL, false },
	{ "lstat", K_FILE, op_lstat, NULL, false },
	{ "fstatat", K_FILE, op_fstatat, NULL, false },
	{ "access", K_FILE, op_access, NULL, false },
	{ "eaccess", K_FILE, op_eaccess, NULL, false },
	{ "faccessat", K_FILE, op_faccessat, NULL, false },
	{ "chmod", K_FILE, op_chmod, NULL, false },
	{ "lchmod", K_FILE, op_lchmod, or_fchmod, false },
	{ "fchmodat", K_FILE, op_fchmodat, NULL, false },
	{ "chown", K_FILE, op_chown, NULL, false },
	{ "lchown", K_FILE, op_lchown, NULL, false },
	{ "fchownat", K_FILE, op_fchownat, NULL, false },
	{ "chflags", K_FILE, op_chflags, or_fchflags, false },
	{ "lchflags", K_FILE, op_lchflags, or_fchflags, false },
	{ "chflagsat", K_FILE, op_chflagsat, or_fchflags, false },
	{ "utimes", K_FILE, op_utimes, NULL, false },
	{ "lutimes", K_FILE, op_lutimes, NULL, false },
	{ "futimesat", K_FILE, op_futimesat, NULL, false },
	{ "utimensat", K_FILE, op_utimensat, NULL, false },
	{ "truncate", K_FILE, op_truncate, NULL, false },
	{ "pathconf", K_FILE, op_pathconf, NULL, false },
	{ "lpathconf", K_FILE, op_lpathconf, NULL, false },
	{ "statfs", K_FILE, op_statfs, NULL, false },
	{ "__realpathat", K_FILE, op_realpath, NULL, false },
	{ "extattr_list_file", K_FILE, op_xattr_list, or_xattr_list, false },
	{ "extattr_list_link", K_FILE, op_xattr_list_link, or_xattr_list, false },
	{ "inotify_add_watch", K_FILE, op_inotify, NULL, false },
	{ "unlink", K_FILE, op_unlink, NULL, true },
	{ "unlinkat", K_FILE, op_unlinkat, NULL, true },
	{ "funlinkat", K_FILE, op_funlinkat, NULL, true },
	{ "rename_from", K_FILE, op_rename_from, NULL, true },
	{ "renameat2_from", K_FILE, op_renameat2_from, NULL, true },
	{ "rename_over", K_FILE, op_rename_over, NULL, true },
	{ "link_from", K_FILE, op_link_from, NULL, false },
	{ "linkat_from", K_FILE, op_linkat_from, NULL, false },
	{ "rmdir", K_DIR, op_rmdir, NULL, true },
	{ "unlinkat_dir", K_DIR, op_unlinkat_dir, NULL, true },
	{ "chdir", K_DIR, op_chdir, NULL, false },
	{ "mkdir", K_NEW, op_mkdir, NULL, false },
	{ "mkdirat", K_NEW, op_mkdirat, NULL, false },
	{ "mkfifo", K_NEW, op_mkfifo, NULL, false },
	{ "mkfifoat", K_NEW, op_mkfifoat, NULL, false },
	{ "mknod_fifo", K_NEW, op_mknod_fifo, NULL, false },
	{ "symlink", K_NEW, op_symlink_to, NULL, false },
	{ "symlinkat", K_NEW, op_symlinkat_to, NULL, false },
	{ "link_to", K_NEW, op_link_to, NULL, false },
	{ "linkat_to", K_NEW, op_linkat_to, NULL, false },
	{ "open_creat_excl", K_NEW, op_creat_excl, NULL, false },
	{ "openat_creat", K_NEW, op_creat, NULL, false },
	{ "rename_to", K_NEW, op_rename_to_new, NULL, true },
	{ "renameat2_to", K_NEW, op_renameat2_to_new, NULL, true },
	{ "readlink", K_LINK, op_readlink, NULL, false },
	{ "readlinkat", K_LINK, op_readlinkat, NULL, false },
};
#define	NOPS	(sizeof(ops) / sizeof(ops[0]))

/* Remove the helpers the operations leave behind. */
static void
cleanup(void)
{

	pc_remove("zz_src");
	pc_remove("zz_renamed");
	pc_remove("zz_linked");
	pc_remove("zz_tgt");
}

/* Make the object the operation needs at path (which must be fresh). */
static void
prepare(const struct op *op, const char *path)
{

	cleanup();
	pc_remove(path);
	pc_mkfile("zz_tgt", "target\n");
	switch (op->kind) {
	case K_FILE:
		pc_mkfile(path, "data\n");
		break;
	case K_DIR:
		pc_mkdir(path);
		break;
	case K_NEW:
		break;
	case K_LINK:
		pc_symlink("zz_tgt", path);
		break;
	}
}

/* The errno a well-formed call on path gives (0 for success). */
static int
expected_ok(const struct op *op, const char *path)
{
	int fd, e;

	if (op->oracle == NULL)
		return (0);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	e = ERRNO_OF(op->oracle(fd));
	close(fd);
	return (e);
}

static void
run(const struct op *op, const char *desc, const char *path, int want)
{
	int got;

	got = ERRNO_OF(op->fn(path));
	ATF_CHECK_MSG(got == want, "%s: %s: got %d (%s), expected %d (%s)",
	    op->name, desc, got, strerror(got), want, strerror(want));
}

/* Every operation on the same malformed path gives the same errno. */
static void
all_ops_fail(const char *desc, const char *path, int want)
{
	size_t i;
	int before;

	for (i = 0; i < NOPS; i++) {
		cleanup();
		pc_mkfile("zz_tgt", "target\n");
		before = pc_dirent_count(".");
		run(&ops[i], desc, path, want);
		/* A failed call created nothing (zz_src is the op's own). */
		pc_remove("zz_src");
		ATF_CHECK_MSG(pc_dirent_count(".") == before,
		    "%s: %s: the directory changed", ops[i].name, desc);
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(null_path);
ATF_TC_BODY(null_path, tc)
{
	size_t i;

	/* copyinstr of NULL: EFAULT from every call, nothing looked up. */
	for (i = 0; i < NOPS; i++) {
		cleanup();
		pc_mkfile("zz_tgt", "target\n");
		run(&ops[i], "NULL", NULL, EFAULT);
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(unmapped_path);
ATF_TC_BODY(unmapped_path, tc)
{

	all_ops_fail("unmapped pointer", pc_unmapped(), EFAULT);
}

ATF_TC_WITHOUT_HEAD(straddle_path);
ATF_TC_BODY(straddle_path, tc)
{

	/*
	 * The bytes "zz_newname" end at an unmapped page with no NUL: the
	 * copy faults (EFAULT) and no prefix of the name is ever looked up
	 * or created.
	 */
	pc_mkdir("zz_newname_d");
	all_ops_fail("straddling pointer", pc_straddle("zz_newname", false),
	    EFAULT);
	/* Also a name that exists as a prefix of the mapped bytes. */
	pc_mkfile("x", "data\n");
	all_ops_fail("straddling pointer to existing prefix",
	    pc_straddle("xx", false), EFAULT);
}

ATF_TC_WITHOUT_HEAD(straddle_exact);
ATF_TC_BODY(straddle_exact, tc)
{
	const char *p;
	size_t i;

	/* The NUL is the last mapped byte: an ordinary, complete path. */
	p = pc_straddle("x", true);
	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], "x");
		run(&ops[i], "NUL at page end", p, expected_ok(&ops[i], "x"));
		pc_remove("x");
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(empty_path);
ATF_TC_BODY(empty_path, tc)
{
	size_t i;

	/*
	 * namei: an empty path without EMPTYPATH is ENOENT.  readlink(2)
	 * always looks up with EMPTYPATH (kern_readlinkat), so "" names the
	 * current directory and readlink of a directory is EINVAL.
	 */
	for (i = 0; i < NOPS; i++) {
		cleanup();
		pc_mkfile("zz_tgt", "target\n");
		run(&ops[i], "empty", "",
		    ops[i].kind == K_LINK ? EINVAL : ENOENT);
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(maxpathlen);
ATF_TC_BODY(maxpathlen, tc)
{
	char *buf;

	/* strlen == MAXPATHLEN: no NUL within MAXPATHLEN bytes. */
	buf = malloc(MAXPATHLEN + 1);
	ATF_REQUIRE(buf != NULL);
	pc_mkfile("x", "data\n");
	pc_longpath(buf, MAXPATHLEN, ".", "x");
	all_ops_fail("MAXPATHLEN bytes", buf, ENAMETOOLONG);
	pc_longpath(buf, MAXPATHLEN + 0, "", "x");
	all_ops_fail("MAXPATHLEN bytes, absolute", buf, ENAMETOOLONG);
	free(buf);
}

ATF_TC_WITHOUT_HEAD(maxpathlen_minus_one);
ATF_TC_BODY(maxpathlen_minus_one, tc)
{
	char *buf;
	size_t i;

	/* strlen == MAXPATHLEN - 1 fits: an ordinary lookup of "x". */
	buf = malloc(MAXPATHLEN);
	ATF_REQUIRE(buf != NULL);
	pc_longpath(buf, MAXPATHLEN - 1, ".", "x");
	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], "x");
		run(&ops[i], "MAXPATHLEN - 1 bytes", buf,
		    expected_ok(&ops[i], "x"));
		if (ops[i].kind == K_NEW)
			ATF_CHECK_MSG(access("x", F_OK) == 0 ||
			    errno != ENOENT, "%s: x was not created",
			    ops[i].name);
		pc_remove("x");
	}
	cleanup();
	free(buf);
}

ATF_TC_WITHOUT_HEAD(name_max);
ATF_TC_BODY(name_max, tc)
{
	char name[NAME_MAX + 2];
	size_t i;

	if (pathconf(".", _PC_NAME_MAX) < NAME_MAX)
		atf_tc_skip("the file system's names are shorter than NAME_MAX");
	/* A final component of exactly NAME_MAX bytes is valid. */
	pc_name(name, NAME_MAX, 'n');
	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], name);
		run(&ops[i], "NAME_MAX component", name,
		    expected_ok(&ops[i], name));
		pc_remove(name);
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(name_max_plus_one);
ATF_TC_BODY(name_max_plus_one, tc)
{
	char name[NAME_MAX + 2], path[NAME_MAX + 16];

	/* vfs_lookup's cn_namelen > NAME_MAX test, final and intermediate. */
	pc_name(name, NAME_MAX + 1, 'n');
	all_ops_fail("NAME_MAX + 1 final component", name, ENAMETOOLONG);
	snprintf(path, sizeof(path), "%s/x", name);
	all_ops_fail("NAME_MAX + 1 intermediate component", path,
	    ENAMETOOLONG);
	pc_mkdir("d");
	snprintf(path, sizeof(path), "d/%s", name);
	all_ops_fail("NAME_MAX + 1 component in a directory", path,
	    ENAMETOOLONG);
}

ATF_TC_WITHOUT_HEAD(missing_intermediate);
ATF_TC_BODY(missing_intermediate, tc)
{

	all_ops_fail("missing intermediate", "nodir/x", ENOENT);
	all_ops_fail("missing intermediate, deep", "nodir/a/b/c/x", ENOENT);
}

ATF_TC_WITHOUT_HEAD(file_intermediate);
ATF_TC_BODY(file_intermediate, tc)
{

	static const char *const dots[] = { "f/.", "f/.." };
	size_t i, j;
	int got;

	pc_mkfile("f", "data\n");
	all_ops_fail("file as intermediate", "f/x", ENOTDIR);
	/*
	 * "f/." and "f/..": LOOKUP and CREATE reach VOP_LOOKUP on a regular
	 * file, ENOTDIR.  For a DELETE or RENAME last component vfs_lookup
	 * refuses the "." / ".." name with EINVAL before VOP_LOOKUP (unlink
	 * reports it as EPERM), but the lockless lookup, when enabled, answers
	 * ENOTDIR from cache_fplookup_dot/_dotdot first.  TBC: which one the
	 * pre-1c kernel gives depends on whether fast lookup is enabled (a MAC
	 * policy with a lookup hook disables it); both are accepted here.
	 */
	for (j = 0; j < nitems(dots); j++) {
		for (i = 0; i < NOPS; i++) {
			cleanup();
			pc_mkfile("zz_tgt", "target\n");
			if (!ops[i].modlast) {
				run(&ops[i], "file then dot(dot)", dots[j],
				    ENOTDIR);
				continue;
			}
			got = ERRNO_OF(ops[i].fn(dots[j]));
			ATF_CHECK_MSG(got == ENOTDIR || got == EINVAL ||
			    got == EPERM, "%s: %s: got %d (%s)", ops[i].name,
			    dots[j], got, strerror(got));
		}
	}
	cleanup();
	ATF_CHECK(access("f", F_OK) == 0);
}

ATF_TC_WITHOUT_HEAD(trailing_slash);
ATF_TC_BODY(trailing_slash, tc)
{
	size_t i;
	int want;

	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], "x");
		switch (ops[i].kind) {
		case K_FILE:
			/* A trailing slash on a non-directory: ENOTDIR. */
			want = ENOTDIR;
			break;
		case K_DIR:
			want = 0;
			break;
		case K_NEW:
			/*
			 * Creating "x/" is allowed only for a directory
			 * (WILLBEDIR); anything else is ENOENT.
			 */
			want = (ops[i].fn == op_mkdir ||
			    ops[i].fn == op_mkdirat) ? 0 : ENOENT;
			break;
		case K_LINK:
			/*
			 * A trailing slash follows the link (vfs_lookup:
			 * FOLLOW | TRAILINGSLASH), reaching the regular file
			 * zz_tgt: ENOTDIR.
			 */
			want = ENOTDIR;
			break;
		}
		run(&ops[i], "trailing slash", "x/", want);
		pc_remove("x");
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(repeated_slashes);
ATF_TC_BODY(repeated_slashes, tc)
{
	char cwd[PATH_MAX], path[PATH_MAX + 32];
	size_t i;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	pc_mkdir("d");
	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], "d/x");
		run(&ops[i], "repeated slashes", "d////x",
		    expected_ok(&ops[i], "d/x"));
		pc_remove("d/x");
		prepare(&ops[i], "d/x");
		snprintf(path, sizeof(path), "//%s//.//d/.//x", cwd);
		run(&ops[i], "absolute with // and /./", path,
		    expected_ok(&ops[i], "d/x"));
		pc_remove("d/x");
		prepare(&ops[i], "d/x");
		run(&ops[i], "through d/../d", "d/../d/x",
		    expected_ok(&ops[i], "d/x"));
		pc_remove("d/x");
	}
	cleanup();
}

ATF_TC_WITHOUT_HEAD(symlink_loop);
ATF_TC_BODY(symlink_loop, tc)
{

	pc_symlink("loop2", "loop1");
	pc_symlink("loop1", "loop2");
	pc_symlink("self", "self");
	/* Intermediate links are always followed: ELOOP for everyone. */
	all_ops_fail("loop as intermediate", "loop1/x", ELOOP);
	all_ops_fail("self loop as intermediate", "self/x", ELOOP);
}

ATF_TC_WITHOUT_HEAD(symlink_chain);
ATF_TC_BODY(symlink_chain, tc)
{
	size_t i;

	/*
	 * namei_follow_link: ELOOP once ni_loopcnt reaches MAXSYMLINKS, so a
	 * chain of exactly MAXSYMLINKS links resolves and one more does not.
	 */
	ATF_REQUIRE_EQ(MAXSYMLINKS, 32);
	pc_mkdir("d");
	pc_symlink_chain("ok", MAXSYMLINKS, "d");
	pc_symlink_chain("long", MAXSYMLINKS + 1, "d");
	for (i = 0; i < NOPS; i++) {
		prepare(&ops[i], "d/x");
		run(&ops[i], "MAXSYMLINKS chain", "ok0/x",
		    expected_ok(&ops[i], "d/x"));
		pc_remove("d/x");
	}
	cleanup();
	all_ops_fail("MAXSYMLINKS + 1 chain", "long0/x", ELOOP);
}

ATF_TC_WITHOUT_HEAD(dot_and_dotdot_final);
ATF_TC_BODY(dot_and_dotdot_final, tc)
{
	struct stat a, b;

	pc_mkdir("d");
	pc_mkdir("d/e");
	/* LOOKUP of "." and "..". */
	REQUIRE_OK(stat("d", &a));
	REQUIRE_OK(stat("d/.", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	REQUIRE_OK(stat("d/e/..", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	REQUIRE_OK(stat(".", &a));
	REQUIRE_OK(stat("d/..", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	/* A final "." or ".." for DELETE or RENAME is EINVAL. */
	CHECK_ERR(rmdir("d/e/."), EINVAL);
	CHECK_ERR(rmdir("d/e/.."), EINVAL);
	CHECK_ERR(rmdir("."), EINVAL);
	CHECK_ERR(rmdir(".."), EINVAL);
	CHECK_ERR(unlinkat(AT_FDCWD, "d/.", AT_REMOVEDIR), EINVAL);
	/* funlinkat turns namei's EINVAL into EPERM. */
	CHECK_ERR(unlink("d/."), EPERM);
	CHECK_ERR(unlink("d/.."), EPERM);
	CHECK_ERR(unlink("."), EPERM);
	CHECK_ERR(rename("d/e/.", "zz_renamed"), EINVAL);
	CHECK_ERR(rename("d/e/..", "zz_renamed"), EINVAL);
	CHECK_ERR(rename("d/e", "d/."), EINVAL);
	CHECK_ERR(rename("d/e", "d/.."), EINVAL);
	/* CREATE of an existing "." / "..": the entry exists. */
	CHECK_ERR(mkdir("d/.", 0755), EEXIST);
	CHECK_ERR(mkdir("d/..", 0755), EEXIST);
	CHECK_ERR(mkfifo(".", 0644), EEXIST);
	CHECK_ERR(symlink("t", "d/."), EEXIST);
	/* Nothing was removed. */
	CHECK_OK(stat("d/e", &a));
}

ATF_TC_WITHOUT_HEAD(root_and_dot);
ATF_TC_BODY(root_and_dot, tc)
{
	struct stat a, b;
	int fd;

	REQUIRE_OK(stat("/", &a));
	REQUIRE_OK(stat("///", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	ATF_CHECK_EQ(a.st_dev, b.st_dev);
	REQUIRE_OK(stat("/..", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	REQUIRE_OK(stat("/../../.", &b));
	ATF_CHECK_EQ(a.st_ino, b.st_ino);
	/*
	 * The degenerate name "/" for anything but LOOKUP is EISDIR
	 * (vfs_lookup); the root is never modified.
	 */
	CHECK_ERR(mkdir("/", 0755), EISDIR);
	CHECK_ERR(mkdir("//", 0755), EISDIR);
	CHECK_ERR(rmdir("/"), EISDIR);
	CHECK_ERR(unlink("/"), EISDIR);
	CHECK_ERR(rename("/", "zz_renamed"), EISDIR);
	CHECK_ERR(mkfifo("/", 0644), EISDIR);
	CHECK_ERR(symlink("t", "/"), EISDIR);
	/* link: LOOKUP of "/" succeeds, a directory cannot be linked. */
	CHECK_ERR(link("/", "zz_linked"), EPERM);
	/* open of a directory for writing. */
	CHECK_ERR(open("/", O_WRONLY), EISDIR);
	CHECK_ERR(open(".", O_RDWR), EISDIR);
	CHECK_ERR(open("/", O_CREAT | O_RDONLY, 0644), EISDIR);
	fd = open("/", O_RDONLY | O_DIRECTORY);
	CHECK_OK(fd);
	if (fd >= 0)
		close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, null_path);
	ATF_TP_ADD_TC(tp, unmapped_path);
	ATF_TP_ADD_TC(tp, straddle_path);
	ATF_TP_ADD_TC(tp, straddle_exact);
	ATF_TP_ADD_TC(tp, empty_path);
	ATF_TP_ADD_TC(tp, maxpathlen);
	ATF_TP_ADD_TC(tp, maxpathlen_minus_one);
	ATF_TP_ADD_TC(tp, name_max);
	ATF_TP_ADD_TC(tp, name_max_plus_one);
	ATF_TP_ADD_TC(tp, missing_intermediate);
	ATF_TP_ADD_TC(tp, file_intermediate);
	ATF_TP_ADD_TC(tp, trailing_slash);
	ATF_TP_ADD_TC(tp, repeated_slashes);
	ATF_TP_ADD_TC(tp, symlink_loop);
	ATF_TP_ADD_TC(tp, symlink_chain);
	ATF_TP_ADD_TC(tp, dot_and_dotdot_final);
	ATF_TP_ADD_TC(tp, root_and_dot);
	return (atf_no_error());
}
