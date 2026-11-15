/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-c: served cwd and root (D135, D169, D175,
 * D177).  chdir, fchdir, chroot and fchroot into served directories and
 * back; ATTACH's served starts and their rules (the cwd defaults to the
 * root and must be under it; the child's open directories under chroot's
 * rule or DQ_ATTACH_F_NODIRS); the pwd_* clearing; the open-directory rule
 * with served directories; a chroot nested in the served tree against
 * chroot(2); the kernel's guard on served results under a served root;
 * real descriptors under a served root (DQ_TREE_F_OUTSIDE_PASS);
 * restricted lookups; revocation and a dead controller; inheritance; and
 * the start snapshot (D177) against a racing chroot.
 *
 * getcwd and realpath are called through their system calls (__getcwd,
 * __sys___realpathat) wherever the kernel's answer is asserted: libc
 * falls back to a userland walk when they fail.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include "dq_tree_harness.h"

int	__getcwd(char *, size_t);
int	__sys___realpathat(int, const char *, char *, size_t, int);

#define	ALLOW	"kern.chroot_allow_open_directories"

struct res {
	char	cwd[8][PATH_MAX];
	int	err[32];
	char	data[64];
};

/* The kernel's getcwd: the path, or the errno. */
static void
kcwd(char *buf, int *errp)
{

	if (__getcwd(buf, PATH_MAX) != 0) {
		*errp = errno;
		buf[0] = '\0';
	} else
		*errp = 0;
}

static void
krealpath(const char *p, char *buf, int *errp)
{

	if (__sys___realpathat(AT_FDCWD, p, buf, PATH_MAX, 0) != 0) {
		*errp = errno;
		buf[0] = '\0';
	} else
		*errp = 0;
}

static void
read_into(const char *path, char *buf, size_t len, int *errp)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		*errp = errno;
		return;
	}
	n = read(fd, buf, len - 1);
	buf[n > 0 ? n : 0] = '\0';
	*errp = n < 0 ? errno : 0;
	close(fd);
}

static int
get_allow(void)
{
	size_t len;
	int v;

	len = sizeof(v);
	ATF_REQUIRE(sysctlbyname(ALLOW, &v, &len, NULL, 0) == 0);
	return (v);
}

static void
set_allow(int v)
{

	ATF_REQUIRE(sysctlbyname(ALLOW, NULL, NULL, &v, sizeof(v)) == 0);
}

/* Cleanups put the sysctl back to its default; bodies restore it too. */
static void
reset_allow(void)
{
	int v = 1;

	(void)sysctlbyname(ALLOW, NULL, NULL, &v, sizeof(v));
}

/*
 * ATTACH with the served root and cwd; the controller closes its own
 * descriptor of the root before the child runs (the attachment shares
 * the struct file, Q8).
 */
static void
attach_starts_fn(void *arg __unused, void *out)
{
	struct res *r = out;
	struct stat st;
	char buf[4], path[PATH_MAX];
	int fd;

	kcwd(r->cwd[0], &r->err[0]);
	r->err[1] = TS_ERR(stat("a", &st));
	read_into("a", r->data, sizeof(r->data), &r->err[2]);
	r->err[3] = TS_ERR(chdir("d"));
	kcwd(r->cwd[1], &r->err[4]);
	r->err[5] = TS_ERR(chdir(".."));
	kcwd(r->cwd[2], &r->err[6]);
	/* ".." at the served root stays there (the controller clamps). */
	r->err[7] = TS_ERR(chdir(".."));
	kcwd(r->cwd[3], &r->err[8]);
	r->err[9] = TS_ERR(chdir("a"));
	r->err[10] = TS_ERR(chdir("nope"));
	krealpath("d/../a", path, &r->err[11]);
	strlcpy(r->cwd[4], path, PATH_MAX);
	r->err[12] = TS_ERR(stat("/abs", &st));
	/* fchdir of a served file: ENOTDIR. */
	fd = open("a", O_RDONLY);
	r->err[14] = fd < 0 ? errno : TS_ERR(fchdir(fd));
	if (fd >= 0)
		close(fd);
	/* A served directory opened O_RESOLVE_BENEATH: ENOTCAPABLE. */
	fd = open("d", O_RDONLY | O_DIRECTORY | O_RESOLVE_BENEATH);
	r->err[15] = fd < 0 ? errno : TS_ERR(fchdir(fd));
	if (fd >= 0)
		close(fd);
	/* fchdir of a served directory descriptor. */
	fd = open("d/e", O_RDONLY | O_DIRECTORY);
	r->err[16] = fd < 0 ? errno : TS_ERR(fchdir(fd));
	if (fd >= 0)
		close(fd);
	/* The descriptor is closed: the cwd keeps the object (D45). */
	kcwd(r->cwd[5], &r->err[17]);
	r->err[18] = TS_ERR(stat("../f", &st));
	r->err[19] = TS_ERR(chdir("/d"));
	kcwd(r->cwd[6], &r->err[20]);
	/*
	 * A buffer too short for "/d": the system call's ENOMEM, which
	 * getcwd(3) reports as ERANGE.
	 */
	r->err[13] = __getcwd(buf, 2) != 0 ? errno : 0;
	r->err[21] = getcwd(buf, 2) == NULL ? errno : 0;
	/* A final "." or ".." names the directory reached (from /d). */
	r->err[22] = TS_ERR(lstat(".", &st));
	r->err[23] = TS_ERR(stat("e/..", &st));
	r->err[24] = TS_ERR(stat("/..", &st));
	/* An empty symbolic link: readlink(2) 0 bytes, followed ENOENT. */
	r->err[25] = (int)readlink("/empty", buf, sizeof(buf));
	r->err[26] = TS_ERR(stat("/empty/a", &st));
}

TS_TC(attach_starts);
ATF_TC_BODY(attach_starts, tc)
{
	struct ts s;
	struct res r;
	int status;

	ts_make_tree("t");
	ts_symlink("t", "empty", "");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	memset(&r, 0, sizeof(r));
	r.err[25] = -2;
	status = ts_child_ex(&s, s.sroot, s.sroot, false, true,
	    attach_starts_fn, NULL, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_STREQ("/", r.cwd[0]);
	TS_CHECK_ERRNO(0, r.err[1], "stat a");
	TS_CHECK_ERRNO(0, r.err[2], "read a");
	ATF_CHECK_STREQ("tree\n", r.data);
	TS_CHECK_ERRNO(0, r.err[3], "chdir d");
	ATF_CHECK_STREQ("/d", r.cwd[1]);
	TS_CHECK_ERRNO(0, r.err[5], "chdir ..");
	ATF_CHECK_STREQ("/", r.cwd[2]);
	TS_CHECK_ERRNO(0, r.err[7], "chdir .. at the root");
	ATF_CHECK_STREQ("/", r.cwd[3]);
	TS_CHECK_ERRNO(ENOTDIR, r.err[9], "chdir a file");
	TS_CHECK_ERRNO(ENOENT, r.err[10], "chdir nope");
	TS_CHECK_ERRNO(0, r.err[11], "realpath d/../a");
	ATF_CHECK_STREQ("/a", r.cwd[4]);
	TS_CHECK_ERRNO(0, r.err[12], "stat /abs (absolute link in the tree)");
	TS_CHECK_ERRNO(ENOMEM, r.err[13], "__getcwd short buffer");
	TS_CHECK_ERRNO(ERANGE, r.err[21], "getcwd(3) short buffer");
	TS_CHECK_ERRNO(0, r.err[22], "lstat . from /d");
	TS_CHECK_ERRNO(0, r.err[23], "stat e/.. from /d");
	TS_CHECK_ERRNO(0, r.err[24], "stat /.. at the served root");
	ATF_CHECK_EQ_MSG(0, r.err[25], "readlink of an empty link: %d",
	    r.err[25]);
	TS_CHECK_ERRNO(ENOENT, r.err[26], "stat through an empty link");
	TS_CHECK_ERRNO(ENOTDIR, r.err[14], "fchdir served file");
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[15], "fchdir O_RESOLVE_BENEATH");
	TS_CHECK_ERRNO(0, r.err[16], "fchdir served dir");
	ATF_CHECK_STREQ("/d/e", r.cwd[5]);
	TS_CHECK_ERRNO(0, r.err[18], "stat ../f from /d/e");
	TS_CHECK_ERRNO(0, r.err[19], "chdir /d");
	ATF_CHECK_STREQ("/d", r.cwd[6]);
	ATF_CHECK(ts_count_op(&s, 0, DQ_ROP_CHDIR) >= 5);
	ts_stop(&s);
}

/*
 * A child that waits on a pipe, holding a real directory open when asked;
 * returns its process descriptor once the child has closed every other
 * descriptor above stderr.  The controller's descriptors include real
 * directories (the backing tree, and the tree's backing descriptor of
 * each served directory) that ATTACH's open-directory rule would count,
 * and the parent must not attach before they are gone.
 */
static int
waiting_child(struct ts *s __unused, bool holddir, int rel[2])
{
	pid_t pid;
	int dfd, fd, pd, ready[2];
	char c;

	dfd = holddir ? open(".", O_RDONLY | O_DIRECTORY) : -1;
	ATF_REQUIRE(!holddir || dfd >= 0);
	ATF_REQUIRE(pipe(rel) == 0 && pipe(ready) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		for (fd = STDERR_FILENO + 1; fd <= MAX(MAX(rel[0], ready[1]),
		    dfd); fd++)
			if (fd != rel[0] && fd != ready[1] && fd != dfd)
				close(fd);
		closefrom(MAX(MAX(rel[0], ready[1]), dfd) + 1);
		(void)write(ready[1], "r", 1);
		close(ready[1]);
		(void)read(rel[0], &c, 1);
		_exit(0);
	}
	ATF_REQUIRE(read(ready[0], &c, 1) == 1);
	close(ready[0]);
	close(ready[1]);
	if (dfd >= 0)
		close(dfd);
	return (pd);
}

static void
release_child(int pd, int rel[2])
{

	(void)write(rel[1], "g", 1);
	close(rel[0]);
	close(rel[1]);
	close(pd);
}

/* ATTACH's start descriptors are validated before anything commits. */
TS_TC(attach_starts_invalid);
ATF_TC_BODY(attach_starts_invalid, tc)
{
	struct ts s, s2;
	struct dq_ident_file *ident;
	struct dq_policy pol;
	uint64_t oid;
	int fd, ofd, pd, rel[2];

	ts_make_tree("t");
	ts_make_tree("t2");
	ATF_REQUIRE(mkdir("elsewhere", 0755) == 0);
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	ts_start(&s2, "t2", DQ_TREE_F_ROOT);
	pd = waiting_child(&s, false, rel);
	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	/* A served directory of this queue that is not under the root. */
	ident = malloc(sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	ATF_REQUIRE(dq_ident_from_lstat(ident, "/elsewhere", AT_FDCWD,
	    "elsewhere") == 0);
	dq_policy_default_dir(&pol);
	ATF_REQUIRE(dq_mint_dir(s.q, ident, &pol, &oid, &ofd, NULL) == 0);
	free(ident);

	TS_CHECK_ERRNO(EINVAL, TS_ERR(dq_attach_starts(s.q, pd, fd, -1)),
	    "real directory as root");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(dq_attach_starts(s.q, pd, -1, fd)),
	    "real directory as cwd");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(dq_attach_starts(s.q, pd, s2.sroot,
	    -1)), "another queue's served directory");
	TS_CHECK_ERRNO(EBADF, TS_ERR(dq_attach_starts(s.q, pd, 1000, -1)),
	    "a bad descriptor");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(dq_attach_starts(s.q, pd, s.sroot,
	    ofd)), "a cwd not under the root");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(dq_attach_starts_flags(s.q, pd, s.sroot,
	    s.sroot, 0x2)), "an unknown flag");
	ATF_REQUIRE(dq_revoke(s2.q, s2.rootid) == 0);
	TS_CHECK_ERRNO(EIO, TS_ERR(dq_attach_starts(s2.q, pd, s2.sroot, -1)),
	    "a revoked served directory");
	/* Nothing committed: the child can still be attached. */
	TS_CHECK_ERRNO(0, TS_ERR(dq_attach_starts(s.q, pd, s.sroot, s.sroot)),
	    "valid starts");
	release_child(pd, rel);
	close(fd);
	close(ofd);
	ts_stop(&s);
	ts_stop(&s2);
}

/* A root without a cwd: the cwd is the root. */
static void
cwd_default_fn(void *arg __unused, void *out)
{
	struct res *r = out;
	struct stat st;

	kcwd(r->cwd[0], &r->err[0]);
	r->err[1] = TS_ERR(stat("a", &st));
}

TS_TC(attach_cwd_defaults_to_root);
ATF_TC_BODY(attach_cwd_defaults_to_root, tc)
{
	struct ts s;
	struct res r;
	int status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, -1, cwd_default_fn, NULL, &r,
	    sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "getcwd");
	ATF_CHECK_STREQ("/", r.cwd[0]);
	TS_CHECK_ERRNO(0, r.err[1], "stat a from the root as cwd");
	ts_stop(&s);
}

/*
 * The child's open real directories (D184): with a served root, chroot's
 * own rule exactly (kern.chroot_allow_open_directories: 0 refuses, 1
 * refuses only when already chrooted; EPERM); DQ_ATTACH_F_NODIRS, with or
 * without a root, refuses any (EBUSY).
 */
TS_TC_CLEANUP(attach_open_dirs);
ATF_TC_BODY(attach_open_dirs, tc)
{
	struct ts s;
	int pd, rel[2], saved;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	saved = get_allow();

	set_allow(1);
	pd = waiting_child(&s, true, rel);
	TS_CHECK_ERRNO(0, TS_ERR(dq_attach_starts(s.q, pd, s.sroot, -1)),
	    "allow 1, not chrooted, a directory open");
	release_child(pd, rel);

	set_allow(0);
	pd = waiting_child(&s, true, rel);
	TS_CHECK_ERRNO(EPERM, TS_ERR(dq_attach_starts(s.q, pd, s.sroot, -1)),
	    "allow 0, a directory open");
	/* Without a served root the rule does not apply. */
	TS_CHECK_ERRNO(0, TS_ERR(dq_attach_starts(s.q, pd, -1, -1)),
	    "allow 0, no served root");
	release_child(pd, rel);

	set_allow(2);
	pd = waiting_child(&s, true, rel);
	TS_CHECK_ERRNO(EBUSY, TS_ERR(dq_attach_starts_flags(s.q, pd, s.sroot,
	    -1, DQ_ATTACH_F_NODIRS)), "NODIRS, a directory open");
	TS_CHECK_ERRNO(EBUSY, TS_ERR(dq_attach_starts_flags(s.q, pd, -1, -1,
	    DQ_ATTACH_F_NODIRS)), "NODIRS without a root, a directory open");
	TS_CHECK_ERRNO(0, TS_ERR(dq_attach_starts(s.q, pd, s.sroot, -1)),
	    "allow 2, a directory open");
	release_child(pd, rel);
	pd = waiting_child(&s, false, rel);
	TS_CHECK_ERRNO(0, TS_ERR(dq_attach_starts_flags(s.q, pd, s.sroot, -1,
	    DQ_ATTACH_F_NODIRS)), "NODIRS, no directory open");
	release_child(pd, rel);
	set_allow(saved);
	ts_stop(&s);
}
ATF_TC_CLEANUP(attach_open_dirs, tc)
{

	reset_allow();
}

/*
 * fchdir to a served directory without a served root: its raw di_path
 * (a real-namespace path, D174); a real chdir clears it (D169).
 */
struct fchdir_arg {
	int	sroot;
	char	real[PATH_MAX];
	int	realfd;
};

static void
fchdir_fn(void *arg, void *out)
{
	struct fchdir_arg *a = arg;
	struct res *r = out;
	struct stat st;

	r->err[0] = TS_ERR(fchdir(a->sroot));
	kcwd(r->cwd[0], &r->err[1]);
	r->err[2] = TS_ERR(stat("a", &st));
	r->err[3] = TS_ERR(chdir(a->real));
	kcwd(r->cwd[1], &r->err[4]);
	/* The real cwd: "a" is not there. */
	r->err[5] = TS_ERR(stat("a", &st));
	r->err[6] = TS_ERR(fchdir(a->sroot));
	r->err[7] = TS_ERR(stat("a", &st));
	r->err[8] = TS_ERR(fchdir(a->realfd));
	kcwd(r->cwd[2], &r->err[9]);
	r->err[10] = TS_ERR(stat("a", &st));
}

TS_TC(fchdir_served);
ATF_TC_BODY(fchdir_served, tc)
{
	struct ts s;
	struct res r;
	struct fchdir_arg a;
	int status;

	ts_make_tree("t");
	ATF_REQUIRE(mkdir("real", 0755) == 0);
	ts_start(&s, "t", 0);
	a.sroot = s.sroot;
	ATF_REQUIRE(realpath("real", a.real) != NULL);
	a.realfd = open("real", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(a.realfd >= 0);
	memset(&r, 0, sizeof(r));
	status = ts_child_ex(&s, -1, -1, true, false, fchdir_fn, &a, &r,
	    sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "fchdir served");
	ATF_CHECK_STREQ(s.backing, r.cwd[0]);
	TS_CHECK_ERRNO(0, r.err[2], "stat a from the served cwd");
	TS_CHECK_ERRNO(0, r.err[3], "chdir real");
	ATF_CHECK_STREQ(a.real, r.cwd[1]);
	TS_CHECK_ERRNO(ENOENT, r.err[5], "stat a from the real cwd");
	TS_CHECK_ERRNO(0, r.err[6], "fchdir served again");
	TS_CHECK_ERRNO(0, r.err[7], "stat a again");
	TS_CHECK_ERRNO(0, r.err[8], "fchdir real");
	ATF_CHECK_STREQ(a.real, r.cwd[2]);
	TS_CHECK_ERRNO(ENOENT, r.err[10], "stat a after fchdir real");
	close(a.realfd);
	ts_stop(&s);
}

/*
 * D163 as amended by D184: an unattached process (the controller here)
 * using a served directory as a start is EACCES.  Other descriptors keep
 * their answers: a device vnode ENOTDIR; a pipe, a socket and a kqueue
 * EINVAL.
 */
TS_TC(fchdir_unattached);
ATF_TC_BODY(fchdir_unattached, tc)
{
	struct ts s;
	struct stat st;
	int p[2], so, kq;

	ts_make_tree("t");
	ts_start(&s, "t", 0);
	TS_CHECK_ERRNO(EACCES, TS_ERR(fchdir(s.sroot)), "fchdir");
	TS_CHECK_ERRNO(EACCES, TS_ERR(fchroot(s.sroot)), "fchroot");
	TS_CHECK_ERRNO(EACCES, TS_ERR(fstatat(s.sroot, "a", &st, 0)),
	    "a served dirfd");
	TS_CHECK_ERRNO(ENOTDIR, TS_ERR(fchdir(s.q)), "fchdir of /dev/dq");
	ATF_REQUIRE(pipe(p) == 0);
	so = socket(AF_UNIX, SOCK_STREAM, 0);
	kq = kqueue();
	ATF_REQUIRE(so >= 0 && kq >= 0);
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchdir(p[0])), "fchdir pipe");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchdir(so)), "fchdir socket");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchdir(kq)), "fchdir kqueue");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchroot(p[0])), "fchroot pipe");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchroot(so)), "fchroot socket");
	TS_CHECK_ERRNO(EINVAL, TS_ERR(fchroot(kq)), "fchroot kqueue");
	close(p[0]);
	close(p[1]);
	close(so);
	close(kq);
	ts_stop(&s);
}

/*
 * fchroot to a served directory, chroot answered FD, and a chroot nested
 * in the tree compared with chroot(2) of the same backing directory:
 * "/..", "/../f", an absolute link and "/" resolve at the nested root.
 */
#define	NNEST	4

struct nest {
	int		sroot;
	int		err[NNEST];
	ino_t		ino[NNEST];
};

static void
nested_names(struct nest *n)
{
	static const char *const names[NNEST] = { "/..", "/../f", "/abs2",
	    "/" };
	struct stat st;
	int i;

	for (i = 0; i < NNEST; i++) {
		n->err[i] = TS_ERR(stat(names[i], &st));
		n->ino[i] = n->err[i] == 0 ? st.st_ino : 0;
	}
}

static void
fchroot_fn(void *arg, void *out)
{
	struct nest *n = arg;
	struct res *r = out;
	struct stat st;

	r->err[0] = TS_ERR(fchroot(n->sroot));
	/* A real cwd under a served root has no presented path. */
	kcwd(r->cwd[0], &r->err[1]);
	r->err[2] = TS_ERR(chdir("/"));
	kcwd(r->cwd[1], &r->err[3]);
	r->err[4] = TS_ERR(stat("/a", &st));
	r->err[5] = TS_ERR(chroot("d"));
	kcwd(r->cwd[2], &r->err[6]);
	r->err[7] = TS_ERR(chdir("/"));
	kcwd(r->cwd[3], &r->err[8]);
	r->err[9] = TS_ERR(stat("/f", &st));
	r->err[10] = TS_ERR(stat("/a", &st));
	r->err[11] = TS_ERR(chroot("/nope"));
	r->err[12] = TS_ERR(chroot("/f"));
	nested_names(n);
	memcpy(r->data, n, sizeof(*n));
}

TS_TC_CLEANUP(fchroot_served);
ATF_TC_BODY(fchroot_served, tc)
{
	struct ts s;
	struct res r;
	struct nest n, real;
	char dir[PATH_MAX];
	int i, p[2], saved, status;
	size_t got;
	pid_t pid;

	_Static_assert(sizeof(struct nest) <= sizeof(r.data), "nest fits");
	ts_make_tree("t");
	ts_symlink("t", "d/abs2", "/f");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	saved = get_allow();
	/* 2: the child keeps its served root descriptor open. */
	set_allow(2);
	memset(&r, 0, sizeof(r));
	memset(&n, 0, sizeof(n));
	n.sroot = s.sroot;
	status = ts_child_ex(&s, -1, -1, true, false, fchroot_fn, &n,
	    &r, sizeof(r));
	set_allow(saved);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "fchroot served");
	TS_CHECK_ERRNO(ENOENT, r.err[1], "getcwd real cwd under served root");
	TS_CHECK_ERRNO(0, r.err[2], "chdir /");
	ATF_CHECK_STREQ("/", r.cwd[1]);
	TS_CHECK_ERRNO(0, r.err[4], "stat /a");
	TS_CHECK_ERRNO(0, r.err[5], "chroot d (answered FD)");
	/* The cwd (the old root) is not under the new root. */
	TS_CHECK_ERRNO(ENOENT, r.err[6], "getcwd outside the new root");
	TS_CHECK_ERRNO(0, r.err[7], "chdir / in the new root");
	ATF_CHECK_STREQ("/", r.cwd[3]);
	TS_CHECK_ERRNO(0, r.err[9], "stat /f (d/f)");
	TS_CHECK_ERRNO(ENOENT, r.err[10], "stat /a outside the new root");
	TS_CHECK_ERRNO(ENOENT, r.err[11], "chroot /nope");
	TS_CHECK_ERRNO(ENOTDIR, r.err[12], "chroot of a file");

	/* chroot(2) of the backing d: the oracle for the nested names. */
	memcpy(&n, r.data, sizeof(n));
	snprintf(dir, sizeof(dir), "%s/d", s.backing);
	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		memset(&real, 0, sizeof(real));
		if (chroot(dir) == 0 && chdir("/") == 0)
			nested_names(&real);
		_exit(write(p[1], &real, sizeof(real)) ==
		    (ssize_t)sizeof(real) ? 0 : DQT_EXIT_NORESULT);
	}
	(void)close(p[1]);
	got = dqt_read_full(p[0], &real, sizeof(real));
	(void)close(p[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	dqt_require_exit0(status, "the chroot(2) oracle");
	ATF_REQUIRE_EQ(sizeof(real), got);
	for (i = 0; i < NNEST; i++) {
		ATF_CHECK_EQ_MSG(real.err[i], n.err[i], "name %d: errno", i);
		ATF_CHECK_EQ_MSG(real.ino[i], n.ino[i], "name %d: inode", i);
	}
	close(p[0]);
	close(p[1]);
	ts_stop(&s);
}
ATF_TC_CLEANUP(fchroot_served, tc)
{

	reset_allow();
}

/*
 * The open-directory rule with served directories: 0 refuses with a
 * served directory open; 1 counts a served root as being chrooted.  An
 * unattached process's served directories are no lookup starts and do
 * not count, so its chroot(2) is unchanged.
 */
static void
refuse0_fn(void *arg, void *out)
{
	int *sroot = arg;
	struct res *r = out;

	r->err[0] = TS_ERR(fchroot(*sroot));
	/*
	 * A name in the tree: chroot(2) refuses open directories after the
	 * lookup, and the tree answers a real-start name outside it EACCES.
	 */
	r->err[1] = TS_ERR(chroot("t"));
}

/*
 * Close every directory descriptor the child inherited: the controller's
 * (the tree's backing descriptor of each served directory) are real
 * directories that would count against chroot.
 */
static void
close_real_dirs(void)
{
	struct stat st;
	int fd, maxfd;

	maxfd = getdtablesize();
	for (fd = STDERR_FILENO + 1; fd < maxfd; fd++)
		if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode))
			close(fd);
}

static void
refuse1_fn(void *arg __unused, void *out)
{
	struct res *r = out;
	int fd;

	close_real_dirs();
	fd = open("d", O_RDONLY | O_DIRECTORY);
	r->err[0] = fd < 0 ? errno : 0;
	r->err[1] = TS_ERR(chroot("d"));
	if (fd >= 0)
		close(fd);
	r->err[2] = TS_ERR(chroot("d"));
}

TS_TC_CLEANUP(chroot_refuse_served_dirs);
ATF_TC_BODY(chroot_refuse_served_dirs, tc)
{
	struct ts s;
	struct res r;
	pid_t pid;
	int saved, status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	saved = get_allow();
	set_allow(0);
	memset(&r, 0, sizeof(r));
	status = ts_child_ex(&s, -1, -1, true, false, refuse0_fn, &s.sroot,
	    &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(EPERM, r.err[0], "fchroot with a served dir open");
	TS_CHECK_ERRNO(EPERM, r.err[1], "chroot with a served dir open");
	/*
	 * An unattached child of the controller holding only s.sroot: no
	 * real directory open, so chroot succeeds as it would without it.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (dup2(s.sroot, 0) == -1)
			_exit(errno);
		closefrom(1);
		_exit(chroot("/") == 0 ? 0 : errno);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	TS_CHECK_ERRNO(0, WEXITSTATUS(status),
	    "allow 0: an unattached process's served dir does not count");
	set_allow(1);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, s.sroot, refuse1_fn, NULL, &r,
	    sizeof(r));
	set_allow(saved);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "open d");
	TS_CHECK_ERRNO(EPERM, r.err[1], "allow 1: a served root is chrooted");
	TS_CHECK_ERRNO(0, r.err[2], "allow 1: no directory open");
	ts_stop(&s);
}
ATF_TC_CLEANUP(chroot_refuse_served_dirs, tc)
{

	reset_allow();
}

/*
 * A revoked served cwd and root: lookups EIO, getcwd keeps its frozen
 * path (D169).  Then the controller exits: still EIO, still frozen.
 */
struct sync_arg {
	int	tochild[2];
	int	toparent[2];
};

static void
revoke_fn(void *arg, void *out)
{
	struct sync_arg *a = arg;
	struct res *r = out;
	struct stat st;
	char c;

	r->err[0] = TS_ERR(chdir("d"));
	r->err[1] = TS_ERR(stat("f", &st));
	(void)write(a->toparent[1], "1", 1);
	(void)read(a->tochild[0], &c, 1);
	r->err[2] = TS_ERR(stat("/a", &st));
	r->err[3] = TS_ERR(stat("f", &st));
	kcwd(r->cwd[0], &r->err[4]);
	(void)write(a->toparent[1], "2", 1);
	(void)read(a->tochild[0], &c, 1);
	r->err[5] = TS_ERR(stat("f", &st));
	kcwd(r->cwd[1], &r->err[6]);
	r->err[7] = TS_ERR(chdir("/"));
}

static void *
revoke_parent(void *arg)
{
	struct ts *s = arg;
	struct sync_arg *a = s->hookarg;
	char c;

	(void)read(a->toparent[0], &c, 1);
	(void)dq_revoke(s->q, s->rootid);
	(void)write(a->tochild[1], "g", 1);
	(void)read(a->toparent[0], &c, 1);
	s->stop = 1;
	pthread_join(s->thr, NULL);
	close(s->q);
	s->q = -1;
	(void)write(a->tochild[1], "g", 1);
	return (NULL);
}

TS_TC(revoke_and_exit);
ATF_TC_BODY(revoke_and_exit, tc)
{
	struct ts s;
	struct res r;
	struct sync_arg a;
	pthread_t thr;
	int status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	ATF_REQUIRE(pipe(a.tochild) == 0 && pipe(a.toparent) == 0);
	s.hookarg = &a;
	ATF_REQUIRE(pthread_create(&thr, NULL, revoke_parent, &s) == 0);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, s.sroot, revoke_fn, &a, &r, sizeof(r));
	pthread_join(thr, NULL);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "chdir d");
	TS_CHECK_ERRNO(0, r.err[1], "stat f");
	TS_CHECK_ERRNO(EIO, r.err[2], "stat /a, root revoked");
	TS_CHECK_ERRNO(0, r.err[3], "stat f, cwd live");
	TS_CHECK_ERRNO(0, r.err[4], "getcwd");
	ATF_CHECK_STREQ("/d", r.cwd[0]);
	TS_CHECK_ERRNO(EIO, r.err[5], "stat f, queue closed");
	TS_CHECK_ERRNO(0, r.err[6], "getcwd, queue closed");
	ATF_CHECK_STREQ("/d", r.cwd[1]);
	TS_CHECK_ERRNO(EIO, r.err[7], "chdir /, queue closed");
	if (s.sroot >= 0)
		close(s.sroot);
	dq_tree_destroy(s.tree);
	close(s.bfd);
}

/* fork carries the served cwd and root (D123). */
static void
fork_fn(void *arg __unused, void *out)
{
	struct res *r = out;
	struct res g;
	struct stat st;
	int p[2], status;
	pid_t pid;

	r->err[0] = TS_ERR(chdir("d"));
	if (pipe(p) != 0) {
		r->err[1] = errno;
		return;
	}
	pid = fork();
	if (pid == -1) {
		r->err[1] = errno;
		return;
	}
	if (pid == 0) {
		memset(&g, 0, sizeof(g));
		kcwd(g.cwd[0], &g.err[0]);
		g.err[1] = TS_ERR(stat("f", &st));
		g.err[2] = TS_ERR(stat("/a", &st));
		_exit(write(p[1], &g, sizeof(g)) == (ssize_t)sizeof(g) ? 0 :
		    DQT_EXIT_NORESULT);
	}
	(void)close(p[1]);
	memset(&g, 0, sizeof(g));
	/* A grandchild that did not report is an error the test sees. */
	if (dqt_read_full(p[0], &g, sizeof(g)) != sizeof(g) ||
	    waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		memset(&g, 0, sizeof(g));
		r->err[1] = ECHILD;
	}
	(void)close(p[0]);
	strlcpy(r->cwd[0], g.cwd[0], PATH_MAX);
	r->err[2] = g.err[0];
	r->err[3] = g.err[1];
	r->err[4] = g.err[2];
}

TS_TC(fork_inherits);
ATF_TC_BODY(fork_inherits, tc)
{
	struct ts s;
	struct res r;
	int status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, s.sroot, fork_fn, NULL, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "chdir d");
	TS_CHECK_ERRNO(0, r.err[2], "grandchild getcwd");
	ATF_CHECK_STREQ("/d", r.cwd[0]);
	TS_CHECK_ERRNO(0, r.err[3], "grandchild stat f");
	TS_CHECK_ERRNO(0, r.err[4], "grandchild stat /a");
	ts_stop(&s);
}

/*
 * A stress test, not a proof of D177 (root_escape_race is that): a thread
 * switches the cwd between a served directory and a real one while a
 * sibling looks a name up; every event is consistent (a served start
 * names the root object, a real start is hinted with a real cwd).
 */
struct race_arg {
	int		sroot;
	char		real[PATH_MAX];
	char		orig[PATH_MAX];
	volatile int	stop;
};

static void *
race_switcher(void *arg)
{
	struct race_arg *a = arg;
	int i;

	for (i = 0; i < 300; i++) {
		(void)fchdir(a->sroot);
		(void)chdir(a->real);
	}
	a->stop = 1;
	return (NULL);
}

static void
race_fn(void *arg, void *out)
{
	struct race_arg *a = arg;
	struct res *r = out;
	struct stat st;
	pthread_t thr;

	if (pthread_create(&thr, NULL, race_switcher, a) != 0) {
		r->err[0] = errno;
		return;
	}
	while (!a->stop)
		(void)stat("a", &st);
	pthread_join(thr, NULL);
}

TS_TC(cwd_switch_stress);
ATF_TC_BODY(cwd_switch_stress, tc)
{
	struct ts s;
	struct res r;
	struct race_arg a;
	struct ts_ev *e;
	int i, nserved, nreal, status;

	ts_make_tree("t");
	ATF_REQUIRE(mkdir("real", 0755) == 0);
	ts_start(&s, "t", 0);
	memset(&a, 0, sizeof(a));
	a.sroot = s.sroot;
	ATF_REQUIRE(realpath("real", a.real) != NULL);
	ATF_REQUIRE(getcwd(a.orig, sizeof(a.orig)) != NULL);
	memset(&r, 0, sizeof(r));
	status = ts_child_ex(&s, -1, -1, true, false, race_fn, &a, &r,
	    sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "thread");
	nserved = nreal = 0;
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nev; i++) {
		e = &s.ev[i];
		if (e->op != DQ_ROP_STAT || strcmp(e->path, "a") != 0)
			continue;
		if (e->start_kind == DQ_START_SERVED) {
			nserved++;
			ATF_CHECK_EQ_MSG(s.rootid, e->start,
			    "event %d: served start %ju", i,
			    (uintmax_t)e->start);
		} else if (e->start_kind == DQ_START_REAL_CWD) {
			nreal++;
			ATF_CHECK_MSG(strcmp(e->hint, a.real) == 0 ||
			    strcmp(e->hint, a.orig) == 0,
			    "event %d: real start hinted %s", i, e->hint);
		} else
			ATF_CHECK_MSG(false, "event %d: start kind %u", i,
			    e->start_kind);
	}
	pthread_mutex_unlock(&s.mtx);
	printf("served starts %d, real starts %d\n", nserved, nreal);
	ATF_CHECK(nserved + nreal > 0);
	ts_stop(&s);
}

/*
 * D172(a) inside a REAL walk: "/r/x" is answered REAL with a real link
 * whose target is absolute; the kernel consults that target again from
 * the served root (DQ_START_SERVED, the root, DQ_RF_SYMLINK_RESTART) and
 * the controller's ENOENT is the answer.
 *
 * root_escape_race (D177) adds a sibling thread switching the
 * root between the served one and the real "/" (chroot answered REAL,
 * then fchroot back): a lookup that started under the served root must
 * re-enter there, never at the real "/", where the target exists.
 */
struct esc {
	char		lnk[PATH_MAX];		/* a real link -> marker */
	char		marker[PATH_MAX];	/* a real file */
	int		sroot;
	volatile int	stop;
};

static int
esc_hook(struct ts *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct esc *e = s->hookarg;

	if ((rb->drs_rflags & DQ_RF_SYMLINK_RESTART) != 0 &&
	    rb->drs_start_kind == DQ_START_SERVED) {
		(void)dq_reply_resolve_errno(s->q, ev->de_id, ENOENT);
		return (1);
	}
	if (rb->drs_op == DQ_ROP_STAT && strcmp(path, "/r/x") == 0) {
		(void)dq_reply_resolve_real(s->q, ev->de_id, e->lnk);
		return (1);
	}
	if (rb->drs_op == DQ_ROP_CHROOT && strcmp(path, "/escape") == 0) {
		(void)dq_reply_resolve_real(s->q, ev->de_id, "/");
		return (1);
	}
	return (0);
}

static void
make_esc(struct ts *s, struct esc *e)
{
	char cwd[PATH_MAX];

	memset(e, 0, sizeof(*e));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(e->marker, sizeof(e->marker), "%s/marker", cwd);
	snprintf(e->lnk, sizeof(e->lnk), "%s/lnk", cwd);
	ts_file(cwd, "marker", "m\n");
	ATF_REQUIRE(symlink(e->marker, e->lnk) == 0);
	e->sroot = s->sroot;
	s->hookarg = e;
	s->hook = esc_hook;
}

static void
d172a_fn(void *arg __unused, void *out)
{
	struct res *r = out;
	struct stat st;

	r->err[0] = TS_ERR(stat("/r/x", &st));
}

TS_TC(d172a_in_real_walk);
ATF_TC_BODY(d172a_in_real_walk, tc)
{
	struct ts s;
	struct res r;
	struct esc e;
	struct ts_ev *ev;
	int i, n, status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	make_esc(&s, &e);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, s.sroot, d172a_fn, NULL, &r,
	    sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(ENOENT, r.err[0], "the target from the served root");
	n = 0;
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nev; i++) {
		ev = &s.ev[i];
		if ((ev->rflags & DQ_RF_SYMLINK_RESTART) == 0)
			continue;
		n++;
		ATF_CHECK_EQ(DQ_START_SERVED, ev->start_kind);
		ATF_CHECK_EQ(s.rootid, ev->start);
		ATF_CHECK_STREQ(e.marker, ev->path);
	}
	pthread_mutex_unlock(&s.mtx);
	ATF_CHECK_EQ(1, n);
	ts_stop(&s);
}

static void *
esc_switcher(void *arg)
{
	struct esc *e = arg;

	while (!e->stop) {
		(void)chroot("/escape");
		(void)fchroot(e->sroot);
	}
	return (NULL);
}

static void
esc_fn(void *arg, void *out)
{
	struct esc *e = arg;
	struct res *r = out;
	struct stat st;
	pthread_t thr;
	int found, i;

	if (pthread_create(&thr, NULL, esc_switcher, e) != 0) {
		r->err[0] = errno;
		return;
	}
	found = 0;
	for (i = 0; i < 3000; i++)
		if (stat("/r/x", &st) == 0)
			found++;
	e->stop = 1;
	pthread_join(thr, NULL);
	r->err[1] = found;
}

TS_TC_CLEANUP(root_escape_race);
ATF_TC_BODY(root_escape_race, tc)
{
	struct ts s;
	struct res r;
	struct esc e;
	int i, n, saved, status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	make_esc(&s, &e);
	saved = get_allow();
	/* The child chroots and keeps its served root descriptor open. */
	set_allow(2);
	memset(&r, 0, sizeof(r));
	status = ts_child_ex(&s, s.sroot, s.sroot, true, false, esc_fn, &e,
	    &r, sizeof(r));
	set_allow(saved);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "thread");
	ATF_CHECK_EQ_MSG(0, r.err[1], "%d lookups re-entered at the real root",
	    r.err[1]);
	n = 0;
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nev; i++)
		if ((s.ev[i].rflags & DQ_RF_SYMLINK_RESTART) != 0)
			n++;
	pthread_mutex_unlock(&s.mtx);
	printf("re-entries at the served root: %d\n", n);
	ts_stop(&s);
}
ATF_TC_CLEANUP(root_escape_race, tc)
{

	reset_allow();
}

/*
 * A real directory under a served root, received after ATTACH: names
 * from it are outside the tree, refused EACCES by dq_serve_tree by
 * default and PASSed with DQ_TREE_F_OUTSIDE_PASS.
 */
static int
recv_fd(int so)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char c, cbuf[CMSG_SPACE(sizeof(int))];
	int fd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	if (recvmsg(so, &msg, 0) != 1)
		return (-1);
	cm = CMSG_FIRSTHDR(&msg);
	if (cm == NULL || cm->cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(cm), sizeof(fd));
	return (fd);
}

static void
send_fd(int so, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char c = 'f', cbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(fd));
	(void)sendmsg(so, &msg, 0);
}

struct realfd_arg {
	int	so;
	int	realfd;
};

static void *
realfd_sender(void *arg)
{
	struct realfd_arg *a = arg;

	send_fd(a->so, a->realfd);
	return (NULL);
}

static void
realfd_fn(void *arg, void *out)
{
	struct realfd_arg *a = arg;
	struct res *r = out;
	struct stat st;
	int fd;

	fd = recv_fd(a->so);
	r->err[0] = fd < 0 ? EBADF : 0;
	r->err[1] = TS_ERR(fstatat(fd, "x", &st, 0));
	r->err[2] = TS_ERR(fchdir(fd));
	r->err[3] = TS_ERR(stat("x", &st));
	r->err[4] = TS_ERR(stat("/a", &st));
}

static void
realfd_case(uint32_t flags, int want)
{
	struct ts s;
	struct res r;
	struct realfd_arg a, pa;
	pthread_t thr;
	int sp[2], status;

	ts_make_tree("t");
	ATF_REQUIRE(mkdir("w", 0755) == 0);
	ts_file("w", "x", "x\n");
	ts_start(&s, "t", DQ_TREE_F_ROOT | flags);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	pa.so = sp[0];
	pa.realfd = open("w", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(pa.realfd >= 0);
	a.so = sp[1];
	a.realfd = -1;
	ATF_REQUIRE(pthread_create(&thr, NULL, realfd_sender, &pa) == 0);
	memset(&r, 0, sizeof(r));
	/* The real directory reaches the child only after ATTACH. */
	status = ts_child(&s, s.sroot, s.sroot, realfd_fn, &a, &r, sizeof(r));
	pthread_join(thr, NULL);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(0, r.err[0], "received");
	TS_CHECK_ERRNO(want, r.err[1], "fstatat(realfd, x)");
	TS_CHECK_ERRNO(0, r.err[2], "fchdir(realfd)");
	TS_CHECK_ERRNO(want, r.err[3], "stat x from the real cwd");
	TS_CHECK_ERRNO(0, r.err[4], "stat /a from the served root");
	close(pa.realfd);
	close(sp[0]);
	close(sp[1]);
	ts_stop(&s);
}

TS_TC(real_fd_outside_refused);
ATF_TC_BODY(real_fd_outside_refused, tc)
{

	realfd_case(0, EACCES);
}

TS_TC(real_fd_outside_pass);
ATF_TC_BODY(real_fd_outside_pass, tc)
{

	realfd_case(DQ_TREE_F_OUTSIDE_PASS, 0);
}

/*
 * The kernel's guard (D174, D184): under a served root, a served
 * result whose di_path is not at or under the root's at a component
 * boundary is ENOTCAPABLE and the object retires, from a served start
 * and from a real one (a received real directory).
 */
struct guard {
	char	sibling[PATH_MAX];	/* the root's path + "x": /ab, /a */
	char	outside[PATH_MAX];
};

static int
guard_hook(struct ts *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct guard *g = s->hookarg;
	struct dq_ident_file *ident;
	struct dq_policy pol;
	uint64_t id;
	const char *as;

	if (strcmp(path, "/boundary") == 0 || strcmp(path, "rx") == 0)
		as = g->sibling;
	else if (strcmp(path, "/outfd") == 0)
		as = g->outside;
	else
		return (0);
	ident = malloc(sizeof(*ident));
	if (ident == NULL ||
	    dq_ident_from_lstat(ident, as, s->bfd, "a") != 0) {
		free(ident);
		(void)dq_reply_resolve_errno(s->q, ev->de_id, EIO);
		return (1);
	}
	if (rb->drs_op == DQ_ROP_OPEN) {
		dq_policy_default(&pol);
		(void)dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0,
		    ident, &pol, &id, NULL);
	} else
		(void)dq_reply_resolve_attr(s->q, ev->de_id, ident);
	free(ident);
	return (1);
}

static void
guard_fn(void *arg, void *out)
{
	struct realfd_arg *a = arg;
	struct res *r = out;
	struct stat st;
	int fd;

	r->err[0] = TS_ERR(stat("/boundary", &st));
	fd = open("/outfd", O_RDONLY);
	r->err[1] = fd < 0 ? errno : 0;
	fd = recv_fd(a->so);
	r->err[2] = fd < 0 ? EBADF : TS_ERR(fstatat(fd, "rx", &st, 0));
}

TS_TC(guard_outside_root);
ATF_TC_BODY(guard_outside_root, tc)
{
	struct ts s;
	struct res r;
	struct guard g;
	struct realfd_arg a, pa;
	struct dq_stats2 st0, st1;
	pthread_t thr;
	int sp[2], status;

	ts_make_tree("t");
	ATF_REQUIRE(mkdir("w", 0755) == 0);
	ts_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_OUTSIDE_PASS);
	snprintf(g.sibling, sizeof(g.sibling), "%sx", s.backing);
	strlcpy(g.outside, "/dq_cwd_test_elsewhere/a", sizeof(g.outside));
	s.hookarg = &g;
	s.hook = guard_hook;
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	pa.so = sp[0];
	pa.realfd = open("w", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(pa.realfd >= 0);
	a.so = sp[1];
	a.realfd = -1;
	ATF_REQUIRE(pthread_create(&thr, NULL, realfd_sender, &pa) == 0);
	ATF_REQUIRE(dq_get_stats2(s.q, &st0) == 0);
	memset(&r, 0, sizeof(r));
	status = ts_child(&s, s.sroot, s.sroot, guard_fn, &a, &r, sizeof(r));
	pthread_join(thr, NULL);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[0], "ATTR at /ab under root /a");
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[1], "FD outside the root");
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[2], "ATTR from a real start");
	ATF_REQUIRE(dq_get_stats2(s.q, &st1) == 0);
	ATF_CHECK_MSG(st1.ds2_resolve_retired > st0.ds2_resolve_retired,
	    "the refused FD answer retired its object");
	close(pa.realfd);
	close(sp[0]);
	close(sp[1]);
	ts_stop(&s);
}

/*
 * Restricted lookups under a served cwd and root: O_RESOLVE_BENEATH (an
 * absolute name and a leading "..": ENOTCAPABLE, no event) and capability
 * mode (AT_FDCWD: ECAPMODE; an absolute name from a served directory
 * descriptor: ENOTCAPABLE; a relative one is served).  RINROOT has no
 * native interface (Linux openat2 only).
 */
static void
restricted_fn(void *arg, void *out)
{
	int *sroot = arg;
	struct res *r = out;
	struct stat st;
	int fd;

	fd = open("/a", O_RDONLY | O_RESOLVE_BENEATH);
	r->err[0] = fd < 0 ? errno : 0;
	fd = open("a", O_RDONLY | O_RESOLVE_BENEATH);
	r->err[1] = fd < 0 ? errno : 0;
	r->err[2] = TS_ERR(chdir("d"));
	fd = open("../a", O_RDONLY | O_RESOLVE_BENEATH);
	r->err[3] = fd < 0 ? errno : 0;
	if (cap_enter() != 0) {
		r->err[4] = errno;
		return;
	}
	r->err[5] = TS_ERR(stat("f", &st));
	r->err[6] = TS_ERR(fstatat(*sroot, "/a", &st, 0));
	r->err[7] = TS_ERR(fstatat(*sroot, "a", &st, 0));
}

TS_TC(restricted_under_served);
ATF_TC_BODY(restricted_under_served, tc)
{
	struct ts s;
	struct res r;
	int n0, status;

	ts_make_tree("t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	n0 = ts_nev(&s);
	memset(&r, 0, sizeof(r));
	status = ts_child_ex(&s, s.sroot, s.sroot, true, false, restricted_fn,
	    &s.sroot, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[0], "BENEATH, absolute");
	TS_CHECK_ERRNO(0, r.err[1], "BENEATH, relative");
	TS_CHECK_ERRNO(0, r.err[2], "chdir d");
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[3], "BENEATH, leading ..");
	TS_CHECK_ERRNO(0, r.err[4], "cap_enter");
	TS_CHECK_ERRNO(ECAPMODE, r.err[5], "capability mode, AT_FDCWD");
	TS_CHECK_ERRNO(ENOTCAPABLE, r.err[6], "capability mode, absolute");
	TS_CHECK_ERRNO(0, r.err[7], "capability mode, served dirfd");
	/* Posted: the relative open, the chdir and the dirfd stat. */
	ATF_CHECK_EQ(n0 + 3, ts_nev(&s));
	ts_stop(&s);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, attach_starts);
	ATF_TP_ADD_TC(tp, attach_starts_invalid);
	ATF_TP_ADD_TC(tp, attach_cwd_defaults_to_root);
	ATF_TP_ADD_TC(tp, attach_open_dirs);
	ATF_TP_ADD_TC(tp, fchdir_served);
	ATF_TP_ADD_TC(tp, fchdir_unattached);
	ATF_TP_ADD_TC(tp, fchroot_served);
	ATF_TP_ADD_TC(tp, chroot_refuse_served_dirs);
	ATF_TP_ADD_TC(tp, revoke_and_exit);
	ATF_TP_ADD_TC(tp, fork_inherits);
	ATF_TP_ADD_TC(tp, cwd_switch_stress);
	ATF_TP_ADD_TC(tp, d172a_in_real_walk);
	ATF_TP_ADD_TC(tp, root_escape_race);
	ATF_TP_ADD_TC(tp, real_fd_outside_refused);
	ATF_TP_ADD_TC(tp, real_fd_outside_pass);
	ATF_TP_ADD_TC(tp, guard_outside_root);
	ATF_TP_ADD_TC(tp, restricted_under_served);
	return (atf_no_error());
}
