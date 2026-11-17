/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-c: the presented-path contract (D174).
 * A process's own getcwd, realpath, kinfo and linprocfs paths under a
 * served root are relative to it (ENOENT when not underneath, and for
 * real objects); another process's are presented against the viewer: a
 * viewer attached to the same queue with a served root sees them against
 * its own root, any other viewer sees the raw di_path.  A revoked root
 * keeps its frozen path.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <libutil.h>

#include "dqt_tree.h"

/* The kernel's answers, without libc's userland fallbacks. */
int	__getcwd(char *, size_t);
int	__sys___realpathat(int, const char *, char *, size_t, int);

#define	NPATH	12

#define	ALLOW	"kern.chroot_allow_open_directories"

struct pres {
	int	err[NPATH];
	char	path[NPATH][PATH_MAX];
	int	vtype[NPATH];
};

/* kinfo_getfile rows of pid: CWD, ROOT and the descriptor fd. */
static void
kinfo_rows(pid_t pid, int fd, char *cwd, char *root, char *fdpath,
    int *cwdtype, int *errp)
{
	struct kinfo_file *kif;
	int cnt, i;

	cwd[0] = root[0] = fdpath[0] = '\0';
	*cwdtype = -1;
	kif = kinfo_getfile(pid, &cnt);
	if (kif == NULL) {
		*errp = errno;
		strlcpy(cwd, "<none>", PATH_MAX);
		return;
	}
	*errp = 0;
	strlcpy(cwd, "<no row>", PATH_MAX);
	strlcpy(root, "<no row>", PATH_MAX);
	strlcpy(fdpath, "<no row>", PATH_MAX);
	for (i = 0; i < cnt; i++) {
		if (kif[i].kf_fd == KF_FD_TYPE_CWD) {
			strlcpy(cwd, kif[i].kf_path, PATH_MAX);
			*cwdtype = kif[i].kf_vnode_type;
		} else if (kif[i].kf_fd == KF_FD_TYPE_ROOT)
			strlcpy(root, kif[i].kf_path, PATH_MAX);
		else if (fd >= 0 && kif[i].kf_fd == fd)
			strlcpy(fdpath, kif[i].kf_path, PATH_MAX);
	}
	free(kif);
}

/* KERN_PROC_CWD: the one CWD row. */
static void
proc_cwd(pid_t pid, char *out, int *errp)
{
	struct kinfo_file kif;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_CWD;
	mib[3] = pid;
	len = sizeof(kif);
	memset(&kif, 0, sizeof(kif));
	if (sysctl(mib, 4, &kif, &len, NULL, 0) != 0) {
		*errp = errno;
		out[0] = '\0';
		return;
	}
	*errp = 0;
	strlcpy(out, kif.kf_path, PATH_MAX);
}

static void
cwd_into(char *buf, int *errp)
{

	if (__getcwd(buf, PATH_MAX) != 0) {
		*errp = errno;
		buf[0] = '\0';
	} else
		*errp = 0;
}

static void
realpath_into(const char *p, char *buf, int *errp)
{

	if (__sys___realpathat(AT_FDCWD, p, buf, PATH_MAX, 0) != 0) {
		*errp = errno;
		buf[0] = '\0';
	} else
		*errp = 0;
}

/* The process's own view under a served root and cwd. */
static void
own_fn(void *arg __unused, void *out)
{
	struct pres *r = out;
	int fd, e;

	r->err[0] = DQT_ERRNO_OF(chdir("d"));
	cwd_into(r->path[1], &r->err[1]);
	realpath_into("f", r->path[2], &r->err[2]);
	realpath_into("/ds/f", r->path[3], &r->err[3]);
	realpath_into("../a", r->path[4], &r->err[4]);
	fd = open("f", O_RDONLY);
	r->err[5] = fd < 0 ? errno : 0;
	kinfo_rows(getpid(), fd, r->path[5], r->path[6], r->path[7],
	    &r->vtype[5], &e);
	r->err[6] = e;
	proc_cwd(getpid(), r->path[8], &r->err[8]);
	realpath_into("nope", r->path[9], &r->err[9]);
	if (fd >= 0)
		close(fd);
}

DQT_TREE_TC(own_presented);
ATF_TC_BODY(own_presented, tc)
{
	struct dqt_tree s;
	struct pres r;
	int status;

	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child(&s, s.sroot, s.sroot, own_fn, NULL, &r,
	    sizeof(r));
	dqt_require_exit0(status, "child");
	DQT_CHECK_ERRNO(0, r.err[0], "chdir d");
	ATF_CHECK_STREQ("/d", r.path[1]);
	DQT_CHECK_ERRNO(0, r.err[2], "realpath f");
	ATF_CHECK_STREQ("/d/f", r.path[2]);
	DQT_CHECK_ERRNO(0, r.err[3], "realpath /ds/f");
	ATF_CHECK_STREQ("/d/f", r.path[3]);
	DQT_CHECK_ERRNO(0, r.err[4], "realpath ../a");
	ATF_CHECK_STREQ("/a", r.path[4]);
	DQT_CHECK_ERRNO(0, r.err[5], "open f");
	DQT_CHECK_ERRNO(0, r.err[6], "kinfo_getfile");
	ATF_CHECK_STREQ("/d", r.path[5]);
	ATF_CHECK_EQ(KF_VTYPE_VDIR, r.vtype[5]);
	ATF_CHECK_STREQ("/", r.path[6]);
	ATF_CHECK_STREQ("/d/f", r.path[7]);
	DQT_CHECK_ERRNO(0, r.err[8], "KERN_PROC_CWD");
	ATF_CHECK_STREQ("/d", r.path[8]);
	DQT_CHECK_ERRNO(ENOENT, r.err[9], "realpath nope");
	dqt_tree_stop(&s);
}

/*
 * Real objects under a served root have no presented path: a real cwd
 * (fchdir to a real directory), a PASSed real object, a REAL answer to
 * realpath itself.  Their kinfo rows keep the real vnode path.
 */
struct real_arg {
	int	realfd;
	char	real[PATH_MAX];
};

static int
real_hook(struct dqt_tree *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	char p[PATH_MAX];

	if (rb->drs_op != DQ_ROP_REALPATH || strcmp(path, "/hookreal") != 0)
		return (0);
	snprintf(p, sizeof(p), "%s/a", s->backing);
	(void)dq_reply_resolve_real(s->q, ev->de_id, p);
	return (1);
}

static void
real_fn(void *arg, void *out)
{
	struct real_arg *a = arg;
	struct pres *r = out;
	char root[PATH_MAX], fdp[PATH_MAX];
	int e;

	/* REALPATH answered REAL: ENOENT (Q6, D167). */
	realpath_into("/hookreal", r->path[0], &r->err[0]);
	r->err[1] = DQT_ERRNO_OF(fchdir(a->realfd));
	cwd_into(r->path[2], &r->err[2]);
	realpath_into("x", r->path[3], &r->err[3]);
	kinfo_rows(getpid(), -1, r->path[4], root, fdp, &r->vtype[4], &e);
	r->err[4] = e;
	strlcpy(r->path[5], root, PATH_MAX);
}

DQT_TREE_TC(real_under_served_root);
ATF_TC_BODY(real_under_served_root, tc)
{
	struct dqt_tree s;
	struct pres r;
	struct real_arg a;
	int status;

	dqt_tree_make("t");
	ATF_REQUIRE(mkdir("w", 0755) == 0);
	dqt_tree_file("w", "x", "x\n");
	/* The real object is PASSed: the kernel's ENOENT is under test. */
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_OUTSIDE_PASS);
	s.hook = real_hook;
	a.realfd = open("w", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(a.realfd >= 0);
	ATF_REQUIRE(realpath("w", a.real) != NULL);
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child(&s, s.sroot, s.sroot, real_fn, &a, &r,
	    sizeof(r));
	dqt_require_exit0(status, "child");
	DQT_CHECK_ERRNO(ENOENT, r.err[0], "realpath answered REAL");
	DQT_CHECK_ERRNO(0, r.err[1], "fchdir real");
	DQT_CHECK_ERRNO(ENOENT, r.err[2], "getcwd: real cwd, served root");
	DQT_CHECK_ERRNO(ENOENT, r.err[3], "realpath of a real object");
	DQT_CHECK_ERRNO(0, r.err[4], "kinfo");
	/*
	 * Under a served root a real object shows no path, in kinfo too
	 * (C4, Q1's default; it showed the real vnode's path).
	 */
	ATF_CHECK_STREQ("", r.path[4]);
	ATF_CHECK_STREQ("/", r.path[5]);
	close(a.realfd);
	dqt_tree_stop(&s);
}

/*
 * The viewer rule (D174, 0s).  A: served root and cwd, cwd d, f open.
 * Viewers: the test (unattached: raw), B (same queue, same served root:
 * presented), C (same queue, chrooted to d: against d, empty when not
 * underneath).
 */
struct view_arg {
	int	tochild[2];
	int	toparent[2];
	pid_t	apid;
	int	afd;
	int	lpfd;		/* linprocfs, or -1 */
	bool	chroot_d;
};

static void
a_fn(void *arg, void *out)
{
	struct view_arg *v = arg;
	struct pres *r = out;
	pid_t me;
	int fd;
	char c;

	r->err[0] = DQT_ERRNO_OF(chdir("d"));
	fd = open("f", O_RDONLY);
	r->err[1] = fd < 0 ? errno : 0;
	me = getpid();
	(void)write(v->toparent[1], &me, sizeof(me));
	(void)write(v->toparent[1], &fd, sizeof(fd));
	(void)read(v->tochild[0], &c, 1);
}

static void
lp_link(int lpfd, pid_t pid, const char *what, char *out, int *errp)
{
	char name[64];
	ssize_t n;

	snprintf(name, sizeof(name), "%d/%s", (int)pid, what);
	n = readlinkat(lpfd, name, out, PATH_MAX - 1);
	if (n < 0) {
		*errp = errno;
		out[0] = '\0';
	} else {
		*errp = 0;
		out[n] = '\0';
	}
}

static void
viewer_fn(void *arg, void *out)
{
	struct view_arg *v = arg;
	struct pres *r = out;
	char fdname[32];
	int e;

	if (v->chroot_d)
		r->err[0] = DQT_ERRNO_OF(chroot("d"));
	kinfo_rows(v->apid, v->afd, r->path[1], r->path[2], r->path[3],
	    &r->vtype[1], &e);
	r->err[1] = e;
	proc_cwd(v->apid, r->path[4], &r->err[4]);
	if (v->lpfd >= 0) {
		lp_link(v->lpfd, v->apid, "cwd", r->path[5], &r->err[5]);
		lp_link(v->lpfd, v->apid, "root", r->path[6], &r->err[6]);
		snprintf(fdname, sizeof(fdname), "fd/%d", v->afd);
		lp_link(v->lpfd, v->apid, fdname, r->path[7], &r->err[7]);
	}
}

static bool
mount_linprocfs(const char *dir)
{
	struct iovec iov[6];

	if (modfind("linprocfs") < 0 && kldload("linprocfs") < 0 &&
	    errno != EEXIST)
		return (false);
	if (mkdir(dir, 0755) != 0)
		return (false);
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "linprocfs");
	iov[1].iov_len = sizeof("linprocfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, dir);
	iov[3].iov_len = strlen(dir) + 1;
	return (nmount(iov, 4, 0) == 0);
}

DQT_TREE_TC_CLEANUP(viewer_rule);
ATF_TC_BODY(viewer_rule, tc)
{
	struct dqt_tree s;
	struct pres ra, rb, rc, rt;
	struct view_arg v;
	char buf[PATH_MAX], fdname[32];
	size_t got;
	int pd, status, e, ready[2], go[2], back[2];
	pid_t pid;
	char c;
	bool lp;

	dqt_tree_make("t");
	/* The viewers read linprocfs through a real directory: PASS it. */
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_OUTSIDE_PASS);
	lp = mount_linprocfs("lp");
	memset(&v, 0, sizeof(v));
	v.lpfd = lp ? open("lp", O_RDONLY | O_DIRECTORY) : -1;
	ATF_REQUIRE(pipe(v.tochild) == 0 && pipe(v.toparent) == 0);

	/* A, run by hand: it stays alive while the viewers look. */
	ATF_REQUIRE(pipe(ready) == 0 && pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s.q);
		close(s.sroot);
		close(s.bfd);
		(void)write(ready[1], "r", 1);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		memset(&ra, 0, sizeof(ra));
		a_fn(&v, &ra);
		_exit(write(back[1], &ra, sizeof(ra)) == (ssize_t)sizeof(ra) ?
		    0 : DQT_EXIT_NORESULT);
	}
	/* Only A holds the write ends: its death is an EOF here. */
	close(ready[1]);
	close(go[0]);
	close(back[1]);
	ATF_REQUIRE(read(ready[0], &c, 1) == 1);
	ATF_REQUIRE(dq_attach_starts(s.q, pd, s.sroot, s.sroot) == 0);
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	ATF_REQUIRE(read(v.toparent[0], &v.apid, sizeof(v.apid)) ==
	    sizeof(v.apid));
	ATF_REQUIRE(read(v.toparent[0], &v.afd, sizeof(v.afd)) ==
	    sizeof(v.afd));
	ATF_REQUIRE_MSG(v.afd >= 0, "A could not open f");

	/* The test itself: unattached, the raw di_path. */
	memset(&rt, 0, sizeof(rt));
	kinfo_rows(v.apid, v.afd, rt.path[1], rt.path[2], rt.path[3],
	    &rt.vtype[1], &e);
	DQT_CHECK_ERRNO(0, e, "unattached kinfo");
	snprintf(buf, sizeof(buf), "%s/d", s.backing);
	ATF_CHECK_STREQ(buf, rt.path[1]);
	ATF_CHECK_STREQ(s.backing, rt.path[2]);
	snprintf(buf, sizeof(buf), "%s/d/f", s.backing);
	ATF_CHECK_STREQ(buf, rt.path[3]);
	proc_cwd(v.apid, rt.path[4], &e);
	snprintf(buf, sizeof(buf), "%s/d", s.backing);
	ATF_CHECK_STREQ(buf, rt.path[4]);
	if (lp) {
		lp_link(v.lpfd, v.apid, "cwd", rt.path[5], &e);
		ATF_CHECK_STREQ(buf, rt.path[5]);
		lp_link(v.lpfd, v.apid, "root", rt.path[6], &e);
		ATF_CHECK_STREQ(s.backing, rt.path[6]);
		snprintf(fdname, sizeof(fdname), "fd/%d", v.afd);
		lp_link(v.lpfd, v.apid, fdname, rt.path[7], &e);
		snprintf(buf, sizeof(buf), "%s/d/f", s.backing);
		ATF_CHECK_STREQ(buf, rt.path[7]);
	}

	/* B: same queue, same served root: presented. */
	memset(&rb, 0, sizeof(rb));
	status = dqt_tree_child(&s, s.sroot, s.sroot, viewer_fn, &v, &rb,
	    sizeof(rb));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	DQT_CHECK_ERRNO(0, rb.err[1], "B kinfo");
	ATF_CHECK_STREQ("/d", rb.path[1]);
	ATF_CHECK_STREQ("/", rb.path[2]);
	ATF_CHECK_STREQ("/d/f", rb.path[3]);
	ATF_CHECK_STREQ("/d", rb.path[4]);
	if (lp) {
		/* linprocfs agrees with kinfo. */
		ATF_CHECK_STREQ("/d", rb.path[5]);
		ATF_CHECK_STREQ("/", rb.path[6]);
		ATF_CHECK_STREQ("/d/f", rb.path[7]);
	}

	/*
	 * C: chrooted to d: against d; A's root is not underneath.  C holds
	 * the linprocfs directory open and is already (served-)chrooted, so
	 * the open-directory rule is relaxed for it.
	 */
	memset(&rc, 0, sizeof(rc));
	v.chroot_d = true;
	dqt_sysctl_save_set_int(ALLOW, 2);
	status = dqt_tree_child(&s, s.sroot, s.sroot, viewer_fn, &v, &rc,
	    sizeof(rc));
	ATF_REQUIRE(dqt_sysctl_restore(ALLOW));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	DQT_CHECK_ERRNO(0, rc.err[0], "C chroot d");
	ATF_CHECK_STREQ("/", rc.path[1]);
	ATF_CHECK_STREQ("", rc.path[2]);
	ATF_CHECK_STREQ("/f", rc.path[3]);
	if (lp) {
		ATF_CHECK_STREQ("/", rc.path[5]);
		ATF_CHECK_STREQ("/f", rc.path[7]);
	}

	/* A's own view. */
	ATF_REQUIRE(write(v.tochild[1], "g", 1) == 1);
	memset(&ra, 0, sizeof(ra));
	got = dqt_read_full(back[0], &ra, sizeof(ra));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	dqt_require_exit0(status, "A");
	ATF_REQUIRE_EQ(sizeof(ra), got);
	DQT_CHECK_ERRNO(0, ra.err[0], "A chdir d");
	close(pd);
	if (v.lpfd >= 0)
		close(v.lpfd);
	dqt_tree_stop(&s);
}
ATF_TC_CLEANUP(viewer_rule, tc)
{

	(void)unmount("lp", MNT_FORCE);
	/* The body restores it; after a failure, the value it found. */
	(void)dqt_sysctl_restore(ALLOW);
}

/*
 * A revoked served root and cwd keep their frozen presented path in
 * getcwd and in kinfo (D169); lookups through them are EIO.
 */
static void
revoked_fn(void *arg, void *out)
{
	struct view_arg *v = arg;
	struct pres *r = out;
	struct stat st;
	char fdp[PATH_MAX];
	char c;
	int e;

	(void)write(v->toparent[1], "1", 1);
	(void)read(v->tochild[0], &c, 1);
	cwd_into(r->path[0], &r->err[0]);
	kinfo_rows(getpid(), -1, r->path[1], r->path[2], fdp, &r->vtype[1],
	    &e);
	r->err[1] = e;
	r->err[2] = DQT_ERRNO_OF(stat("a", &st));
	r->err[3] = DQT_ERRNO_OF(stat("/a", &st));
}

static void *
revoker(void *arg)
{
	struct dqt_tree *s = arg;
	struct view_arg *v = s->hookarg;
	char c;

	(void)read(v->toparent[0], &c, 1);
	(void)dq_revoke(s->q, s->rootid);
	(void)write(v->tochild[1], "g", 1);
	return (NULL);
}

DQT_TREE_TC(revoked_frozen);
ATF_TC_BODY(revoked_frozen, tc)
{
	struct dqt_tree s;
	struct pres r;
	struct view_arg v;
	pthread_t thr;
	int status;

	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	memset(&v, 0, sizeof(v));
	ATF_REQUIRE(pipe(v.tochild) == 0 && pipe(v.toparent) == 0);
	s.hookarg = &v;
	ATF_REQUIRE(pthread_create(&thr, NULL, revoker, &s) == 0);
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child(&s, s.sroot, s.sroot, revoked_fn, &v, &r,
	    sizeof(r));
	pthread_join(thr, NULL);
	dqt_require_exit0(status, "child");
	DQT_CHECK_ERRNO(0, r.err[0], "getcwd, revoked");
	ATF_CHECK_STREQ("/", r.path[0]);
	DQT_CHECK_ERRNO(0, r.err[1], "kinfo, revoked");
	/* The row is the frozen presented path, the same as getcwd's. */
	ATF_CHECK_STREQ(r.path[0], r.path[1]);
	ATF_CHECK_STREQ("/", r.path[2]);
	DQT_CHECK_ERRNO(EIO, r.err[2], "relative lookup, revoked cwd");
	DQT_CHECK_ERRNO(EIO, r.err[3], "absolute lookup, revoked root");
	dqt_tree_stop(&s);
}

/*
 * T-A10: what a program under a served root sees of the paths of real
 * objects it holds: a file the supervisor substituted (SWAP), a real file
 * reached through a real directory descriptor (PASS) and its mapping, by
 * every route that shows a path (F_KINFO, kinfo_getfile, kinfo_getvmmap,
 * linprocfs maps and an fdescfs link).  The test, unattached, looks at
 * the same process too.
 */
#define	RO_SWAP		0	/* the substituted file */
#define	RO_PASS		1	/* the real file through the real dirfd */

struct ro_arg {
	int	 tochild[2];
	int	 toparent[2];
	int	 realdir;	/* a real directory, inherited */
	int	 lpfd;		/* linprocfs */
	int	 fdescfd;	/* an fdescfs instance (rdlnk) */
};

struct ro_res {
	int	 err[8];
	int	 fd[2];
	char	 kinfo[2][PATH_MAX];	/* F_KINFO */
	char	 table[2][PATH_MAX];	/* kinfo_getfile */
	char	 vmmap[PATH_MAX];	/* kinfo_getvmmap of the mapping */
	char	 lpmap[PATH_MAX];	/* linprocfs maps of the mapping */
	char	 link[2][PATH_MAX];	/* fdescfs readlink */
	char	 lpfdl[2][PATH_MAX];	/* linprocfs <pid>/fd/<n> */
	char	 lpcwd[PATH_MAX];	/* linprocfs <ppid>/cwd */
	char	 lproot[PATH_MAX];	/* linprocfs <ppid>/root */
	int	 lperr[4];		/* their readlink errnos */
	uintptr_t start;
};

static int
ro_swap_hook(struct dqt_tree *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	char p[PATH_MAX];
	int fd;

	if (rb->drs_op != DQ_ROP_OPEN || strcmp(path, "/a") != 0)
		return (0);
	snprintf(p, sizeof(p), "%s/a", s->backing);
	fd = open(p, O_RDONLY | O_CLOEXEC | O_CLOFORK);
	if (fd < 0)
		(void)dq_reply_resolve_errno(s->q, ev->de_id, EIO);
	else if (dq_reply_resolve_swap(s->q, ev->de_id, fd, 0) != 0) {
		if (errno != ECANCELED) {
			(void)close(fd);
			(void)dq_reply_resolve_errno(s->q, ev->de_id, EIO);
		}
	}
	/* Taken (0, ECANCELED): the kernel closed fd. */
	return (1);
}

static void
ro_kve(pid_t pid, uintptr_t start, char *out)
{
	struct kinfo_vmentry *kve;
	int cnt, i;

	strlcpy(out, "<no row>", PATH_MAX);
	kve = kinfo_getvmmap(pid, &cnt);
	for (i = 0; kve != NULL && i < cnt; i++)
		if (kve[i].kve_start == start)
			strlcpy(out, kve[i].kve_path, PATH_MAX);
	free(kve);
}

static void
ro_table(pid_t pid, const int *fds, char out[2][PATH_MAX])
{
	struct kinfo_file *kif;
	int cnt, i, j;

	for (j = 0; j < 2; j++)
		strlcpy(out[j], "<no row>", PATH_MAX);
	kif = kinfo_getfile(pid, &cnt);
	for (i = 0; kif != NULL && i < cnt; i++)
		for (j = 0; j < 2; j++)
			if (kif[i].kf_fd == fds[j])
				strlcpy(out[j], kif[i].kf_path, PATH_MAX);
	free(kif);
}

static int
ro_lpmap(int lpfd, pid_t pid, uintptr_t start, char *out)
{
	char name[64], buf[16384], key[32], *line, *next, *sp;
	ssize_t n;
	int fd;

	out[0] = '\0';
	snprintf(name, sizeof(name), "%d/maps", (int)pid);
	fd = openat(lpfd, name, O_RDONLY);
	if (fd < 0)
		return (errno);
	n = dqt_read_full(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	buf[n] = '\0';
	snprintf(key, sizeof(key), "%016lx-", (unsigned long)start);
	for (line = buf; line != NULL && *line != '\0'; line = next) {
		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		if (strncmp(line, key, strlen(key)) != 0)
			continue;
		sp = strrchr(line, ' ');
		strlcpy(out, sp != NULL ? sp + 1 : "", PATH_MAX);
		return (0);
	}
	return (ENOENT);
}

/* readlinkat of a linprocfs link: 0 and out, or the errno and "". */
static int
ro_lplink(int lpfd, const char *name, char *out)
{
	ssize_t n;

	n = readlinkat(lpfd, name, out, PATH_MAX - 1);
	if (n < 0) {
		out[0] = '\0';
		return (errno);
	}
	out[n] = '\0';
	return (0);
}

static void
ro_fn(void *argp, void *out)
{
	struct ro_arg *a = argp;
	struct ro_res *r = out;
	struct kinfo_file kif;
	char name[32];
	void *p;
	ssize_t n;
	pid_t me;
	int i;
	char c;

	r->fd[RO_SWAP] = open("/a", O_RDONLY);
	r->err[0] = r->fd[RO_SWAP] < 0 ? errno : 0;
	r->fd[RO_PASS] = openat(a->realdir, "x", O_RDONLY);
	r->err[1] = r->fd[RO_PASS] < 0 ? errno : 0;
	for (i = 0; i < 2; i++) {
		memset(&kif, 0, sizeof(kif));
		kif.kf_structsize = sizeof(kif);
		if (fcntl(r->fd[i], F_KINFO, &kif) == 0)
			strlcpy(r->kinfo[i], kif.kf_path, PATH_MAX);
		else
			r->err[2] = errno;
		snprintf(name, sizeof(name), "%d", r->fd[i]);
		n = readlinkat(a->fdescfd, name, r->link[i], PATH_MAX - 1);
		if (n < 0) {
			r->err[4 + i] = errno;
			r->link[i][0] = '\0';
		} else
			r->link[i][n] = '\0';
	}
	ro_table(getpid(), r->fd, r->table);
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, r->fd[RO_PASS], 0);
	r->err[3] = p == MAP_FAILED ? errno : 0;
	r->start = p == MAP_FAILED ? 0 : (uintptr_t)p;
	ro_kve(getpid(), r->start, r->vmmap);
	r->err[6] = ro_lpmap(a->lpfd, getpid(), r->start, r->lpmap);
	/* linprocfs: its own descriptors, and the unattached parent's cwd and
	   root (real directories outside the served root). */
	for (i = 0; i < 2; i++) {
		snprintf(name, sizeof(name), "%d/fd/%d", (int)getpid(),
		    r->fd[i]);
		r->lperr[i] = ro_lplink(a->lpfd, name, r->lpfdl[i]);
	}
	snprintf(name, sizeof(name), "%d/cwd", (int)getppid());
	r->lperr[2] = ro_lplink(a->lpfd, name, r->lpcwd);
	snprintf(name, sizeof(name), "%d/root", (int)getppid());
	r->lperr[3] = ro_lplink(a->lpfd, name, r->lproot);
	me = getpid();
	(void)write(a->toparent[1], &me, sizeof(me));
	(void)write(a->toparent[1], r, sizeof(*r));
	(void)read(a->tochild[0], &c, 1);
}

static bool
ro_mount_linprocfs(const char *dir)
{
	struct iovec iov[4];

	if (modfind("linprocfs") < 0 && kldload("linprocfs") < 0 &&
	    errno != EEXIST)
		return (false);
	if (mkdir(dir, 0755) != 0)
		return (false);
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "linprocfs");
	iov[1].iov_len = sizeof("linprocfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, dir);
	iov[3].iov_len = strlen(dir) + 1;
	return (nmount(iov, 4, 0) == 0);
}

DQT_TREE_TC_CLEANUP(real_object_paths_served_root);
ATF_TC_BODY(real_object_paths_served_root, tc)
{
	struct dqt_tree s;
	struct ro_arg a;
	struct ro_res r, ra;
	char real[2][PATH_MAX], view[2][PATH_MAX], vm[PATH_MAX];
	int pd, status, ready[2], go[2], back[2];
	size_t got;
	pid_t apid, pid;
	char c;

	dqt_tree_make("t");
	ATF_REQUIRE(mkdir("w", 0755) == 0);
	dqt_tree_file("w", "x", "x\n");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_OUTSIDE_PASS);
	s.hook = ro_swap_hook;
	dqt_mount_fdesc("rdlnk");
	ATF_REQUIRE_MSG(ro_mount_linprocfs("lp"), "linprocfs: %s",
	    strerror(errno));
	memset(&a, 0, sizeof(a));
	a.realdir = open("w", O_RDONLY | O_DIRECTORY);
	a.lpfd = open("lp", O_RDONLY | O_DIRECTORY);
	a.fdescfd = open(DQT_FDESC_DIR, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(a.realdir >= 0 && a.lpfd >= 0 && a.fdescfd >= 0);
	ATF_REQUIRE(pipe(a.tochild) == 0 && pipe(a.toparent) == 0);
	snprintf(real[RO_SWAP], PATH_MAX, "%s/a", s.backing);
	ATF_REQUIRE(realpath("w/x", real[RO_PASS]) != NULL);

	ATF_REQUIRE(pipe(ready) == 0 && pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s.q);
		close(s.sroot);
		close(s.bfd);
		(void)write(ready[1], "r", 1);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		memset(&ra, 0, sizeof(ra));
		ro_fn(&a, &ra);
		_exit(write(back[1], &ra, sizeof(ra)) == (ssize_t)sizeof(ra) ?
		    0 : DQT_EXIT_NORESULT);
	}
	close(ready[1]);
	close(go[0]);
	close(back[1]);
	ATF_REQUIRE(read(ready[0], &c, 1) == 1);
	ATF_REQUIRE(dq_attach_starts(s.q, pd, s.sroot, s.sroot) == 0);
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	ATF_REQUIRE(read(a.toparent[0], &apid, sizeof(apid)) == sizeof(apid));
	ATF_REQUIRE(dqt_read_full(a.toparent[0], &r, sizeof(r)) == sizeof(r));

	/* The test, unattached: real objects show their real paths. */
	ro_table(apid, r.fd, view);
	ATF_CHECK_STREQ(real[RO_SWAP], view[RO_SWAP]);
	ATF_CHECK_STREQ(real[RO_PASS], view[RO_PASS]);
	ro_kve(apid, r.start, vm);
	ATF_CHECK_STREQ(real[RO_PASS], vm);
	ATF_CHECK_EQ(0, ro_lpmap(a.lpfd, apid, r.start, vm));
	ATF_CHECK_STREQ(real[RO_PASS], vm);

	ATF_REQUIRE(write(a.tochild[1], "g", 1) == 1);
	got = dqt_read_full(back[0], &ra, sizeof(ra));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	dqt_require_exit0(status, "A");
	ATF_REQUIRE_EQ(sizeof(ra), got);
	DQT_CHECK_ERRNO(0, ra.err[0], "open /a (SWAP)");
	DQT_CHECK_ERRNO(0, ra.err[1], "openat real");
	DQT_CHECK_ERRNO(0, ra.err[2], "F_KINFO");
	DQT_CHECK_ERRNO(0, ra.err[3], "mmap");
	/*
	 * T-A10, Q1's default: under a served root a real object shows no
	 * path by any route (the program saw the backing paths, outside
	 * its root): empty kf_path and kve_path, and fdescfs ENOENT, as
	 * when vn_fullpath fails.
	 */
	ATF_CHECK_STREQ("", ra.kinfo[RO_SWAP]);
	ATF_CHECK_STREQ("", ra.kinfo[RO_PASS]);
	ATF_CHECK_STREQ("", ra.table[RO_SWAP]);
	ATF_CHECK_STREQ("", ra.table[RO_PASS]);
	ATF_CHECK_STREQ("", ra.vmmap);
	DQT_CHECK_ERRNO(0, ra.err[6], "linprocfs maps");
	ATF_CHECK_STREQ("", ra.lpmap);
	DQT_CHECK_ERRNO(ENOENT, ra.err[4], "fdescfs link, SWAP");
	DQT_CHECK_ERRNO(ENOENT, ra.err[5], "fdescfs link, PASS");
	/*
	 * linprocfs shows no real path either (review 1 M3; it showed them):
	 * an fd link is ENOENT, as fdescfs's, and the cwd and root links of
	 * real directories read "unknown", linprocfs's answer when it has
	 * no path.
	 */
	DQT_CHECK_ERRNO(ENOENT, ra.lperr[0], "linprocfs fd link, SWAP");
	DQT_CHECK_ERRNO(ENOENT, ra.lperr[1], "linprocfs fd link, PASS");
	DQT_CHECK_ERRNO(0, ra.lperr[2], "linprocfs cwd of the parent");
	DQT_CHECK_ERRNO(0, ra.lperr[3], "linprocfs root of the parent");
	ATF_CHECK_STREQ("unknown", ra.lpcwd);
	ATF_CHECK_STREQ("unknown", ra.lproot);
	close(pd);
	close(a.realdir);
	close(a.lpfd);
	close(a.fdescfd);
	dqt_tree_stop(&s);
}
ATF_TC_CLEANUP(real_object_paths_served_root, tc)
{

	(void)unmount("lp", MNT_FORCE);
	dqt_umount_fdesc();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, own_presented);
	ATF_TP_ADD_TC(tp, real_under_served_root);
	ATF_TP_ADD_TC(tp, viewer_rule);
	ATF_TP_ADD_TC(tp, revoked_frozen);
	ATF_TP_ADD_TC(tp, real_object_paths_served_root);
	return (atf_no_error());
}
