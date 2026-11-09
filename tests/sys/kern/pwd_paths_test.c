/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * Regression tests for the real (unattached) paths DescriptorQueue stage
 * 1c-iii-c changes: chdir, fchdir, chroot and fchroot with getcwd(3) and
 * the pwd_* functions; realpath(3) (kern___realpathat); kinfo_getfile(3)
 * and KERN_PROC_CWD (kern_proc_filedesc_out, kern_proc_cwd_out, where the
 * reader's root decides, as vn_fullpath does); linprocfs' cwd, root, exe
 * and fd links; chroot_refuse_vdir_fds under
 * kern.chroot_allow_open_directories 0, 1 and 2; and exec's AT_EXECPATH
 * and kern.proc.pathname.  The expected values are what the kernel did
 * before 1c-iii-c (base 33ef5272d53).
 *
 * under_dqpass runs the other cases attached to a pass-everything queue
 * (tests/sys/dq/dqpass), so the same values prove those paths transparent
 * (jail is left out: jail_attach is refused while attached, I5).
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <stdarg.h>
#include <libutil.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	HELPER		"pwd_paths_helper"
#define	ALLOW		"kern.chroot_allow_open_directories"

static char base[PATH_MAX];

/* The work directory: base/a/b/f, base/l -> a/b/f, base/ds -> a. */
static void
setup(void)
{
	int fd;

	ATF_REQUIRE(getcwd(base, sizeof(base)) != NULL);
	ATF_REQUIRE(mkdir("a", 0755) == 0);
	ATF_REQUIRE(mkdir("a/b", 0755) == 0);
	fd = open("a/b/f", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_REQUIRE(symlink("a/b/f", "l") == 0);
	ATF_REQUIRE(symlink("a", "ds") == 0);
}

static void
bpath(char *buf, const char *rel)
{

	snprintf(buf, PATH_MAX, "%s%s%s", base, rel[0] != '\0' ? "/" : "",
	    rel);
}

#define	CHECK_CWD(want) do {						\
	char _b[PATH_MAX];						\
	ATF_CHECK_MSG(getcwd(_b, sizeof(_b)) != NULL, "getcwd: %s",	\
	    strerror(errno));						\
	ATF_CHECK_STREQ((want), _b);					\
} while (0)

/* A child's result: one line of text, compared by the parent. */
struct line {
	char	s[4 * PATH_MAX];
};

typedef void (*child_fn)(struct line *, void *);

static void
in_child(child_fn fn, void *arg, struct line *out)
{
	int p[2], status;
	pid_t pid;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		memset(out, 0, sizeof(*out));
		fn(out, arg);
		(void)write(p[1], out, sizeof(*out));
		_exit(0);
	}
	memset(out, 0, sizeof(*out));
	(void)read(p[0], out, sizeof(*out));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	close(p[0]);
	close(p[1]);
}

static void
appendf(struct line *l, const char *fmt, ...) __printflike(2, 3);

static void
appendf(struct line *l, const char *fmt, ...)
{
	va_list ap;
	size_t n;

	n = strlen(l->s);
	va_start(ap, fmt);
	vsnprintf(l->s + n, sizeof(l->s) - n, fmt, ap);
	va_end(ap);
}

static void
cwd_line(struct line *l, const char *tag)
{
	char b[PATH_MAX];

	if (getcwd(b, sizeof(b)) != NULL)
		appendf(l, "%s=%s;", tag, b);
	else
		appendf(l, "%s=E%d;", tag, errno);
}

ATF_TC_WITHOUT_HEAD(getcwd_chdir);
ATF_TC_BODY(getcwd_chdir, tc)
{
	char p[PATH_MAX];

	setup();
	bpath(p, "a/b");
	ATF_REQUIRE(chdir(p) == 0);
	CHECK_CWD(p);
	ATF_REQUIRE(chdir("..") == 0);
	bpath(p, "a");
	CHECK_CWD(p);
	ATF_REQUIRE(chdir("b") == 0);
	bpath(p, "a/b");
	CHECK_CWD(p);
	/* Through a directory symlink: the resolved directory. */
	bpath(p, "ds/b");
	ATF_REQUIRE(chdir(p) == 0);
	bpath(p, "a/b");
	CHECK_CWD(p);
	ATF_CHECK_ERRNO(ENOTDIR, chdir("f") == -1);
	ATF_CHECK_ERRNO(ENOENT, chdir("nope") == -1);
}

ATF_TC_WITHOUT_HEAD(getcwd_fchdir);
ATF_TC_BODY(getcwd_fchdir, tc)
{
	char p[PATH_MAX];
	int fd;

	setup();
	fd = open("a", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(fchdir(fd) == 0);
	bpath(p, "a");
	CHECK_CWD(p);
	close(fd);
	/* The descriptor is gone; the cwd stays. */
	CHECK_CWD(p);
	fd = open("b/f", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_ERRNO(ENOTDIR, fchdir(fd) == -1);
	close(fd);
}

static void
chroot_fn(struct line *l, void *arg)
{
	bool usefd = arg != NULL;
	char p[PATH_MAX];
	int fd;

	bpath(p, "a");
	if (chdir(p) != 0) {
		appendf(l, "chdir=E%d;", errno);
		return;
	}
	if (usefd) {
		fd = open(base, O_RDONLY | O_DIRECTORY);
		appendf(l, "fchroot=%d;", fchroot(fd) == 0 ? 0 : errno);
		close(fd);
	} else
		appendf(l, "chroot=%d;", chroot(base) == 0 ? 0 : errno);
	cwd_line(l, "cwd");
	appendf(l, "chdir=%d;", chdir("/") == 0 ? 0 : errno);
	cwd_line(l, "cwd");
	appendf(l, "chdir=%d;", chdir("a/b") == 0 ? 0 : errno);
	cwd_line(l, "cwd");
	appendf(l, "chdir=%d;", chdir("../../..") == 0 ? 0 : errno);
	cwd_line(l, "cwd");
}

ATF_TC(getcwd_chroot);
ATF_TC_HEAD(getcwd_chroot, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(getcwd_chroot, tc)
{
	struct line l;

	setup();
	in_child(chroot_fn, NULL, &l);
	/* ".." at the root stays at the root. */
	ATF_CHECK_STREQ("chroot=0;cwd=/a;chdir=0;cwd=/;chdir=0;cwd=/a/b;"
	    "chdir=0;cwd=/;", l.s);
}

ATF_TC(getcwd_fchroot);
ATF_TC_HEAD(getcwd_fchroot, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(getcwd_fchroot, tc)
{
	struct line l;

	setup();
	in_child(chroot_fn, &l, &l);
	ATF_CHECK_STREQ("fchroot=0;cwd=/a;chdir=0;cwd=/;chdir=0;cwd=/a/b;"
	    "chdir=0;cwd=/;", l.s);
}

ATF_TC_WITHOUT_HEAD(getcwd_removed);
ATF_TC_BODY(getcwd_removed, tc)
{
	char b[PATH_MAX], p[PATH_MAX];

	setup();
	ATF_REQUIRE(mkdir("gone", 0755) == 0);
	ATF_REQUIRE(chdir("gone") == 0);
	bpath(p, "gone");
	ATF_REQUIRE(rmdir(p) == 0);
	ATF_CHECK_ERRNO(ENOENT, getcwd(b, sizeof(b)) == NULL);
}

static void
jail_fn(struct line *l, void *arg __unused)
{
	int jid;

	jid = jail_setv(JAIL_CREATE | JAIL_ATTACH, "path", base,
	    "host.hostname", "pwdpaths", NULL);
	if (jid < 0) {
		appendf(l, "jail=E%d;", errno);
		return;
	}
	cwd_line(l, "cwd");
	appendf(l, "chdir=%d;", chdir("a") == 0 ? 0 : errno);
	cwd_line(l, "cwd");
}

ATF_TC(getcwd_jail);
ATF_TC_HEAD(getcwd_jail, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(getcwd_jail, tc)
{
	struct line l;

	setup();
	in_child(jail_fn, NULL, &l);
	/* jail_attach changes the cwd to the jail's root. */
	ATF_CHECK_STREQ("cwd=/;chdir=0;cwd=/a;", l.s);
}

ATF_TC_WITHOUT_HEAD(realpath_names);
ATF_TC_BODY(realpath_names, tc)
{
	char got[PATH_MAX], want[PATH_MAX], abs[PATH_MAX];

	setup();
	bpath(want, "a/b/f");
#define	RP(name, w) do {						\
	ATF_CHECK_MSG(realpath((name), got) != NULL, "realpath %s: %s",	\
	    (name), strerror(errno));					\
	ATF_CHECK_STREQ((w), got);					\
} while (0)
	strlcpy(abs, want, sizeof(abs));
	RP(abs, want);
	RP("a/b/f", want);
	RP("./a//b/./f", want);
	RP("l", want);
	RP("ds/b/f", want);
	RP("a/b/../b/f", want);
	bpath(want, "a");
	/* ".." after a symlink is the parent of its target. */
	RP("ds/../a", want);
	RP("ds", want);
	bpath(want, "");
	RP(".", want);
#undef RP
	ATF_CHECK_ERRNO(ENOENT, realpath("nope", got) == NULL);
	ATF_CHECK_ERRNO(ENOTDIR, realpath("a/b/f/x", got) == NULL);
}

/* kinfo rows of pid: CWD, ROOT, and two descriptors. */
static void
kinfo_line(struct line *l, pid_t pid, int fd1, int fd2)
{
	struct kinfo_file *kif, k1;
	size_t len;
	int cnt, i, mib[4];

	kif = kinfo_getfile(pid, &cnt);
	if (kif == NULL) {
		appendf(l, "kinfo=E%d;", errno);
		return;
	}
	for (i = 0; i < cnt; i++) {
		if (kif[i].kf_fd == KF_FD_TYPE_CWD)
			appendf(l, "cwd=%s:%d;", kif[i].kf_path,
			    kif[i].kf_vnode_type);
		else if (kif[i].kf_fd == KF_FD_TYPE_ROOT)
			appendf(l, "root=%s;", kif[i].kf_path);
	}
	for (i = 0; i < cnt; i++) {
		if (kif[i].kf_fd == fd1 || kif[i].kf_fd == fd2)
			appendf(l, "fd=%s:%d;", kif[i].kf_path,
			    kif[i].kf_vnode_type);
	}
	free(kif);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_CWD;
	mib[3] = pid;
	len = sizeof(k1);
	if (sysctl(mib, 4, &k1, &len, NULL, 0) == 0)
		appendf(l, "proc_cwd=%s;", k1.kf_path);
	else
		appendf(l, "proc_cwd=E%d;", errno);
}

static void
want_rows(char *w, size_t wlen, const char *cwd, const char *root,
    const char *f, const char *d)
{

	snprintf(w, wlen, "cwd=%s:%d;root=%s;fd=%s:%d;fd=%s:%d;proc_cwd=%s;",
	    cwd, KF_VTYPE_VDIR, root, f, KF_VTYPE_VREG, d, KF_VTYPE_VDIR, cwd);
}

ATF_TC_WITHOUT_HEAD(kinfo_self);
ATF_TC_BODY(kinfo_self, tc)
{
	struct line l;
	char w[4 * PATH_MAX], c[PATH_MAX], f[PATH_MAX], d[PATH_MAX];
	int fd, dfd;

	setup();
	fd = open("a/b/f", O_RDONLY);
	dfd = open("a/b", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0 && dfd >= 0 && fd < dfd);
	ATF_REQUIRE(chdir("a") == 0);
	memset(&l, 0, sizeof(l));
	kinfo_line(&l, getpid(), fd, dfd);
	bpath(c, "a");
	bpath(f, "a/b/f");
	bpath(d, "a/b");
	want_rows(w, sizeof(w), c, "/", f, d);
	ATF_CHECK_STREQ(w, l.s);
}

/*
 * Another process's rows, read by an unchrooted reader and by a reader
 * chrooted to base; then the target chrooted to base, read by the
 * unchrooted reader.  The reader's root decides (vn_fullpath).
 */
struct target {
	int	go[2];
	int	back[2];
	pid_t	pid;
	int	fd, dfd;
};

static void
start_target(struct target *t, bool chrooted)
{
	char c;

	ATF_REQUIRE(pipe(t->go) == 0 && pipe(t->back) == 0);
	t->fd = open("a/b/f", O_RDONLY);
	t->dfd = open("a/b", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(t->fd >= 0 && t->dfd >= 0 && t->fd < t->dfd);
	t->pid = fork();
	ATF_REQUIRE(t->pid >= 0);
	if (t->pid == 0) {
		if (chrooted && chroot(base) != 0)
			_exit(1);
		if (chdir(chrooted ? "/a" : "a") != 0)
			_exit(1);
		(void)write(t->back[1], "r", 1);
		(void)read(t->go[0], &c, 1);
		_exit(0);
	}
	ATF_REQUIRE(read(t->back[0], &c, 1) == 1);
}

static void
stop_target(struct target *t)
{
	int status;

	(void)write(t->go[1], "g", 1);
	(void)waitpid(t->pid, &status, 0);
	close(t->fd);
	close(t->dfd);
	close(t->go[0]); close(t->go[1]);
	close(t->back[0]); close(t->back[1]);
}

static void
chrooted_reader_fn(struct line *l, void *arg)
{
	struct target *t = arg;

	if (chroot(base) != 0) {
		appendf(l, "chroot=E%d;", errno);
		return;
	}
	kinfo_line(l, t->pid, t->fd, t->dfd);
}

ATF_TC(kinfo_other);
ATF_TC_HEAD(kinfo_other, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kinfo_other, tc)
{
	struct target t;
	struct line l;
	char w[4 * PATH_MAX], c[PATH_MAX], f[PATH_MAX], d[PATH_MAX];

	setup();
	bpath(c, "a");
	bpath(f, "a/b/f");
	bpath(d, "a/b");
	start_target(&t, false);
	memset(&l, 0, sizeof(l));
	kinfo_line(&l, t.pid, t.fd, t.dfd);
	want_rows(w, sizeof(w), c, "/", f, d);
	ATF_CHECK_STREQ(w, l.s);
	/* A reader chrooted to base: paths below its root. */
	in_child(chrooted_reader_fn, &t, &l);
	want_rows(w, sizeof(w), "/a", "/", "/a/b/f", "/a/b");
	ATF_CHECK_STREQ(w, l.s);
	stop_target(&t);

	/* The target chrooted to base, the reader not: full paths. */
	start_target(&t, true);
	memset(&l, 0, sizeof(l));
	kinfo_line(&l, t.pid, t.fd, t.dfd);
	want_rows(w, sizeof(w), c, base, f, d);
	ATF_CHECK_STREQ(w, l.s);
	stop_target(&t);
}

static bool
mount_linprocfs(const char *dir)
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

static void
lp_link(const char *lp, pid_t pid, const char *what, char *out)
{
	char name[PATH_MAX];
	ssize_t n;

	snprintf(name, sizeof(name), "%s/%d/%s", lp, (int)pid, what);
	n = readlink(name, out, PATH_MAX - 1);
	if (n < 0)
		snprintf(out, PATH_MAX, "E%d", errno);
	else
		out[n] = '\0';
}

ATF_TC_WITH_CLEANUP(linprocfs_links);
ATF_TC_HEAD(linprocfs_links, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(linprocfs_links, tc)
{
	struct target t;
	char got[PATH_MAX], want[PATH_MAX], lp[PATH_MAX], name[32];
	char selfcwd[PATH_MAX];
	ssize_t n;
	size_t len;
	int mib[4];

	setup();
	bpath(lp, "lp");
	if (!mount_linprocfs(lp))
		atf_tc_skip("linprocfs cannot be mounted");
	start_target(&t, false);
	lp_link(lp, t.pid, "cwd", got);
	bpath(want, "a");
	ATF_CHECK_STREQ(want, got);
	lp_link(lp, t.pid, "root", got);
	ATF_CHECK_STREQ("/", got);
	snprintf(name, sizeof(name), "fd/%d", t.fd);
	lp_link(lp, t.pid, name, got);
	bpath(want, "a/b/f");
	ATF_CHECK_STREQ(want, got);
	snprintf(name, sizeof(name), "fd/%d", t.dfd);
	lp_link(lp, t.pid, name, got);
	bpath(want, "a/b");
	ATF_CHECK_STREQ(want, got);
	/* exe is the text vnode's path, as kern.proc.pathname gives it. */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = t.pid;
	len = sizeof(want);
	ATF_REQUIRE(sysctl(mib, 4, want, &len, NULL, 0) == 0);
	lp_link(lp, t.pid, "exe", got);
	ATF_CHECK_STREQ(want, got);
	stop_target(&t);
	/* The reader's own view through /proc/self is the same. */
	ATF_REQUIRE(chdir("a") == 0);
	snprintf(selfcwd, sizeof(selfcwd), "%s/self/cwd", lp);
	n = readlink(selfcwd, got, sizeof(got) - 1);
	ATF_REQUIRE_MSG(n > 0, "readlink %s: %s", selfcwd, strerror(errno));
	got[n] = '\0';
	bpath(want, "a");
	ATF_CHECK_STREQ(want, got);
}
ATF_TC_CLEANUP(linprocfs_links, tc)
{

	(void)unmount("lp", MNT_FORCE);
}

/* Exec name -> the helper's output. */
static void
run_helper(const char *dir, const char *name, int fd, char *out, size_t len)
{
	char *argv[2];
	ssize_t n;
	size_t got;
	int p[2], status;
	pid_t pid;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		dup2(p[1], STDOUT_FILENO);
		if (dir != NULL && chdir(dir) != 0)
			_exit(126);
		argv[0] = __DECONST(char *, HELPER);
		argv[1] = NULL;
		if (fd >= 0)
			fexecve(fd, argv, NULL);
		else
			execve(name, argv, NULL);
		printf("exec-error=%d\n", errno);
		_exit(127);
	}
	close(p[1]);
	got = 0;
	while (got < len - 1 && (n = read(p[0], out + got,
	    len - 1 - got)) > 0)
		got += n;
	out[got] = '\0';
	close(p[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
}

ATF_TC_WITHOUT_HEAD(execpath);
ATF_TC_BODY(execpath, tc)
{
	char out[2 * PATH_MAX], want[2 * PATH_MAX];
	char src[PATH_MAX], real[PATH_MAX], hp[PATH_MAX], link[PATH_MAX];
	int fd;

	setup();
	snprintf(hp, sizeof(hp), "%s/%s",
	    atf_tc_get_config_var(tc, "srcdir"), HELPER);
	ATF_REQUIRE(realpath(atf_tc_get_config_var(tc, "srcdir"), src) !=
	    NULL);
	ATF_REQUIRE(realpath(hp, real) != NULL);
	/* An absolute name: verbatim. */
	run_helper(NULL, hp, -1, out, sizeof(out));
	snprintf(want, sizeof(want), "execpath=%s\npathname=%s\n", hp, real);
	ATF_CHECK_STREQ(want, out);
	/* A relative name: the image vnode's full path (IS_PATH). */
	run_helper(src, "./" HELPER, -1, out, sizeof(out));
	snprintf(want, sizeof(want), "execpath=%s\npathname=%s\n", real, real);
	ATF_CHECK_STREQ(want, out);
	/* Through a symlink, absolute: the name verbatim. */
	bpath(link, "hl");
	ATF_REQUIRE(symlink(real, link) == 0);
	run_helper(NULL, link, -1, out, sizeof(out));
	snprintf(want, sizeof(want), "execpath=%s\npathname=%s\n", link, real);
	ATF_CHECK_STREQ(want, out);
	/* Through a symlink, relative: the resolved image's path. */
	run_helper(base, "./hl", -1, out, sizeof(out));
	snprintf(want, sizeof(want), "execpath=%s\npathname=%s\n", real, real);
	ATF_CHECK_STREQ(want, out);
	/*
	 * fexecve: no name; do_execve() gives AT_EXECPATH the image vnode's
	 * full path, as for a relative name.
	 */
	fd = open(real, O_RDONLY | O_EXEC);
	if (fd < 0)
		fd = open(real, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	run_helper(NULL, NULL, fd, out, sizeof(out));
	snprintf(want, sizeof(want), "execpath=%s\npathname=%s\n", real,
	    real);
	ATF_CHECK_STREQ(want, out);
	close(fd);
}

/*
 * chroot_refuse_vdir_fds: with a directory open, 0 refuses every
 * chroot, 1 refuses only once chrooted, 2 never.
 */
static void
refuse_fn(struct line *l, void *arg __unused)
{
	int fd;

	fd = open(base, O_RDONLY | O_DIRECTORY);
	appendf(l, "first=%d;", chroot(base) == 0 ? 0 : errno);
	/* Relative to the cwd (base), valid whether or not first worked. */
	appendf(l, "second=%d;", chroot("a") == 0 ? 0 : errno);
	appendf(l, "fchroot=%d;", fchroot(fd) == 0 ? 0 : errno);
	close(fd);
}

static void
set_allow(int v)
{

	ATF_REQUIRE(sysctlbyname(ALLOW, NULL, NULL, &v, sizeof(v)) == 0);
}

ATF_TC_WITH_CLEANUP(chroot_open_directories);
ATF_TC_HEAD(chroot_open_directories, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(chroot_open_directories, tc)
{
	struct line l;
	size_t len;
	int saved;
	FILE *f;

	setup();
	len = sizeof(saved);
	ATF_REQUIRE(sysctlbyname(ALLOW, &saved, &len, NULL, 0) == 0);
	f = fopen("allow.saved", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%d\n", saved);
	fclose(f);
	set_allow(0);
	in_child(refuse_fn, NULL, &l);
	ATF_CHECK_STREQ("first=1;second=1;fchroot=1;", l.s);
	set_allow(1);
	in_child(refuse_fn, NULL, &l);
	ATF_CHECK_STREQ("first=0;second=1;fchroot=1;", l.s);
	set_allow(2);
	in_child(refuse_fn, NULL, &l);
	ATF_CHECK_STREQ("first=0;second=0;fchroot=0;", l.s);
	set_allow(saved);
}
ATF_TC_CLEANUP(chroot_open_directories, tc)
{
	FILE *f;
	int v;

	f = fopen("allow.saved", "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d", &v) == 1)
		(void)sysctlbyname(ALLOW, NULL, NULL, &v, sizeof(v));
	fclose(f);
}

/*
 * The same cases attached to dqpass's pass-everything queue (stage 1c):
 * every value must be the same.
 */
static const char *const dqpass_cases[] = {
	"getcwd_chdir", "getcwd_fchdir", "getcwd_chroot", "getcwd_fchroot",
	"getcwd_removed", "realpath_names", "kinfo_self", "kinfo_other",
	"linprocfs_links", "execpath", "chroot_open_directories",
};

ATF_TC(under_dqpass);
ATF_TC_HEAD(under_dqpass, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(under_dqpass, tc)
{
	char self[PATH_MAX], dqpass[PATH_MAX], cmd[4 * PATH_MAX];
	char res[PATH_MAX], line[256], dir[PATH_MAX];
	const char *srcdir;
	FILE *f;
	size_t i;
	int rc;

	srcdir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(self, sizeof(self), "%s/pwd_paths_test", srcdir);
	snprintf(dqpass, sizeof(dqpass), "%s/../dq/dqpass", srcdir);
	if (access("/dev/dq", F_OK) != 0)
		atf_tc_skip("no /dev/dq");
	if (access(dqpass, X_OK) != 0)
		atf_tc_skip("dqpass is not installed");
	/*
	 * A baseline on the kernel from before stage 1c (-v pre1c=yes):
	 * dqpass there predates the attachment these cases need.
	 */
	if (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false))
		atf_tc_skip("pre1c: dqpass's attachment differs on that kernel");
	ATF_REQUIRE(getcwd(base, sizeof(base)) != NULL);
	for (i = 0; i < nitems(dqpass_cases); i++) {
		/* Each case in a fresh directory of its own. */
		snprintf(dir, sizeof(dir), "%s/%s", base, dqpass_cases[i]);
		ATF_REQUIRE(mkdir(dir, 0755) == 0);
		snprintf(res, sizeof(res), "%s/result", dir);
		snprintf(cmd, sizeof(cmd), "cd %s && %s -o %s/report %s "
		    "-s %s -r %s %s >%s/out 2>&1; cd %s && %s -s %s %s:cleanup "
		    ">/dev/null 2>&1", dir, dqpass, dir, self, srcdir, res,
		    dqpass_cases[i], dir, dir, self, srcdir, dqpass_cases[i]);
		rc = system(cmd);
		f = fopen(res, "r");
		if (f == NULL || fgets(line, sizeof(line), f) == NULL) {
			atf_tc_fail_nonfatal("%s: no result (status %#x)",
			    dqpass_cases[i], rc);
			if (f != NULL)
				fclose(f);
			continue;
		}
		fclose(f);
		ATF_CHECK_MSG(strncmp(line, "passed", 6) == 0 ||
		    strncmp(line, "skipped", 7) == 0,
		    "%s under dqpass: %s", dqpass_cases[i], line);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, getcwd_chdir);
	ATF_TP_ADD_TC(tp, getcwd_fchdir);
	ATF_TP_ADD_TC(tp, getcwd_chroot);
	ATF_TP_ADD_TC(tp, getcwd_fchroot);
	ATF_TP_ADD_TC(tp, getcwd_removed);
	ATF_TP_ADD_TC(tp, getcwd_jail);
	ATF_TP_ADD_TC(tp, realpath_names);
	ATF_TP_ADD_TC(tp, kinfo_self);
	ATF_TP_ADD_TC(tp, kinfo_other);
	ATF_TP_ADD_TC(tp, linprocfs_links);
	ATF_TP_ADD_TC(tp, execpath);
	ATF_TP_ADD_TC(tp, chroot_open_directories);
	ATF_TP_ADD_TC(tp, under_dqpass);
	return (atf_no_error());
}
