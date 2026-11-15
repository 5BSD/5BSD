/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-a: served answers from real starts (D156-
 * D177).  An attached child resolves names under a served prefix; the
 * controller (a thread of the test) answers from a backing tree with
 * dq_serve_tree()'s iii-a mode, or a test hook answers by hand to reach
 * the reply path's refusals.  The real backing files are the oracle.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <aio.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#include "dq_test.h"

#define	SRV_MAX_SEEN	256

struct srv;
/* A hook returns 1 when it answered the event itself. */
typedef int (*srv_hook_t)(struct srv *, const struct dq_event *,
    const struct dq_resolve_body *, const char *path);

struct srv {
	int		 q;
	pthread_t	 thr;
	pthread_mutex_t	 mtx;
	volatile int	 stop;
	int		 rootfd;		/* the backing tree */
	char		 backing[PATH_MAX];
	char		 prefix[PATH_MAX];	/* its real-namespace name */
	struct dq_tree	*tree;
	srv_hook_t	 hook;
	int		 hook_state;
	int		 hook_errno;		/* last reply ioctl errno in hook */
	int		 hook_errno2;
	int		 fault_errno;
	int		 notcap;		/* answer ENOTCAPABLE to STAT */
	/* A minted object served from a backing file outside the tree. */
	uint64_t	 extra_id;
	int		 extra_fd;
	struct dq_ident_file extra_ident;
	unsigned	 extra_setattrs;
	/* Every RESOLVE seen: op, accept, mode, cmode. */
	struct {
		uint32_t op, accept, rflags, mode, cmode;
		char	 path[128];
		bool	 has_setattr;
		struct dq_setattr_body sb;
	}		 seen[SRV_MAX_SEEN];
	int		 nseen;
	unsigned	 closes;
};

static int
srv_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct srv *s = arg;
	const struct dq_resolve_body *rb;
	const struct dq_setattr_body *sb;
	const char *path;

	(void)q;
	if (ev->de_op == DQ_OP_CLOSE) {
		pthread_mutex_lock(&s->mtx);
		s->closes++;
		pthread_mutex_unlock(&s->mtx);
	}
	if (ev->de_op == DQ_OP_RESOLVE &&
	    dq_event_resolve_ext(ev, &rb, &path, NULL, NULL, NULL, &sb) == 0) {
		pthread_mutex_lock(&s->mtx);
		if (s->nseen < SRV_MAX_SEEN) {
			s->seen[s->nseen].op = rb->drs_op;
			s->seen[s->nseen].accept = rb->drs_accept;
			s->seen[s->nseen].rflags = rb->drs_rflags;
			s->seen[s->nseen].mode = rb->drs_mode;
			s->seen[s->nseen].cmode = rb->drs_cmode;
			strlcpy(s->seen[s->nseen].path, path,
			    sizeof(s->seen[0].path));
			s->seen[s->nseen].has_setattr = sb != NULL;
			if (sb != NULL)
				s->seen[s->nseen].sb = *sb;
			s->nseen++;
		}
		pthread_mutex_unlock(&s->mtx);
		if (s->hook != NULL && s->hook(s, ev, rb, path))
			return (0);
	}
	if (s->extra_id != 0 && ev->de_object == s->extra_id) {
		struct dq_serve_opts o;

		memset(&o, 0, sizeof(o));
		o.so_ident = &s->extra_ident;
		if (ev->de_op == DQ_OP_SETATTR)
			s->extra_setattrs++;
		(void)dq_serve_file(s->q, ev, body, bodylen, s->extra_fd, &o);
		return (0);
	}
	(void)dq_serve_tree(s->tree, ev, body, bodylen);
	return (0);
}

static void *
srv_main(void *arg)
{
	struct srv *s = arg;
	struct pollfd pfd;

	while (!s->stop && s->q >= 0) {
		pfd.fd = s->q;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		(void)dq_dispatch(s->q, srv_handler, s);
	}
	return (NULL);
}

/*
 * A backing tree in the test's work directory with a file "a" (bytes
 * "served\n"), a directory "d" and a symlink "l" -> "a"; the prefix is a
 * real-namespace directory name that does not exist.
 */
static void
srv_start(struct srv *s, uint32_t flags)
{
	char cwd[PATH_MAX];
	int fd;

	memset(s, 0, sizeof(*s));
	pthread_mutex_init(&s->mtx, NULL);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(s->backing, sizeof(s->backing), "%s/backing", cwd);
	snprintf(s->prefix, sizeof(s->prefix), "%s/served", cwd);
	ATF_REQUIRE(mkdir(s->backing, 0755) == 0 || errno == EEXIST);
	fd = open("backing/a", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(7, write(fd, "served\n", 7));
	close(fd);
	(void)mkdir("backing/d", 0755);
	(void)symlink("a", "backing/l");
	s->rootfd = open(s->backing, O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(s->rootfd >= 0);
	s->q = dq_open();
	ATF_REQUIRE_MSG(s->q >= 0, "dq_open: %s", strerror(errno));
	s->tree = dq_tree_create(s->q, s->rootfd, s->prefix, flags);
	ATF_REQUIRE(s->tree != NULL);
	ATF_REQUIRE(pthread_create(&s->thr, NULL, srv_main, s) == 0);
}

static void
srv_stop(struct srv *s)
{

	s->stop = 1;
	pthread_join(s->thr, NULL);
	dq_tree_destroy(s->tree);
	if (s->q >= 0)
		close(s->q);
	close(s->rootfd);
}

static int
srv_find(struct srv *s, uint32_t op, const char *tail)
{
	size_t tl;
	int i;

	tl = tail != NULL ? strlen(tail) : 0;
	pthread_mutex_lock(&s->mtx);
	for (i = s->nseen - 1; i >= 0; i--) {
		size_t pl = strlen(s->seen[i].path);

		if (s->seen[i].op == op && (tail == NULL ||
		    (pl >= tl && strcmp(s->seen[i].path + pl - tl, tail) == 0)))
			break;
	}
	pthread_mutex_unlock(&s->mtx);
	return (i);
}

static void
srv_stats(struct srv *s, struct dq_stats2 *st)
{

	memset(st, 0, sizeof(*st));
	ATF_REQUIRE(dq_get_stats2(s->q, st) == 0);
}

/* Wait (up to 5 s) for the queue's live objects to reach n. */
static uint64_t
srv_wait_live(struct srv *s, uint64_t n)
{
	struct dq_stats2 st;
	int i;

	for (i = 0; i < 500; i++) {
		srv_stats(s, &st);
		if (st.ds2_objects_live == n)
			break;
		usleep(10000);
	}
	return (st.ds2_objects_live);
}

/*
 * Wait (up to 5 s) for the controller to have read n CLOSE records, and
 * return how many it has.  The object leaves the live count before its
 * CLOSE is posted (from dq_taskq) and read, so the count is not sampled
 * right after srv_wait_live.
 */
static int
srv_wait_closes(struct srv *s, int n)
{
	int closes, i;

	for (i = 0; i < 500; i++) {
		pthread_mutex_lock(&s->mtx);
		closes = s->closes;
		pthread_mutex_unlock(&s->mtx);
		if (closes >= n)
			break;
		usleep(10000);
	}
	return (closes);
}

/*
 * Run fn in an attached child; its int results come back over a pipe.
 */
#define	RES_MAX		32
typedef void (*child_fn_t)(struct srv *, int *res);

static void
run_child_as(struct srv *s, child_fn_t fn, int *res, uid_t uid, bool attach)
{
	int go[2], back[2], pd, status;
	size_t got;
	pid_t pid;
	char c;

	memset(res, 0, sizeof(int) * RES_MAX);
	ATF_REQUIRE(pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int r[RES_MAX];

		close(s->q);
		/* An attached process cannot change credentials (I5). */
		if (uid != (uid_t)-1 && (setgid(uid) != 0 || setuid(uid) != 0))
			_exit(2);
		memset(r, 0, sizeof(r));
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		fn(s, r);
		_exit(write(back[1], r, sizeof(r)) == (ssize_t)sizeof(r) ?
		    0 : DQT_EXIT_NORESULT);
	}
	/* Only the child holds the write ends: its death is an EOF here. */
	close(go[0]);
	close(back[1]);
	if (attach)
		ATF_REQUIRE_MSG(dq_attach(s->q, pd) == 0, "attach: %s",
		    strerror(errno));
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	got = dqt_read_full(back[0], res, sizeof(int) * RES_MAX);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	close(pd);
	close(go[1]);
	close(back[0]);
	dqt_require_exit0(status, "requester");
	ATF_REQUIRE_EQ(sizeof(int) * RES_MAX, got);
}

static void
run_child(struct srv *s, child_fn_t fn, int *res)
{

	run_child_as(s, fn, res, (uid_t)-1, true);
}

/* The last RESOLVE of op with an empty path, or -1. */
static int
srv_find_empty(struct srv *s, uint32_t op)
{
	int i;

	pthread_mutex_lock(&s->mtx);
	for (i = s->nseen - 1; i >= 0; i--)
		if (s->seen[i].op == op && s->seen[i].path[0] == '\0')
			break;
	pthread_mutex_unlock(&s->mtx);
	return (i);
}

/* Fill an identity for name from a backing node. */
static void
srv_ident(struct srv *s, const char *rel, const char *name,
    struct dq_ident_file *id)
{
	struct stat st;
	struct statfs sf;

	ATF_REQUIRE(fstatat(s->rootfd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0);
	ATF_REQUIRE(fstatfs(s->rootfd, &sf) == 0);
	strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
	ATF_REQUIRE(dq_ident_from_stat(id, name, &st, &sf, -1) == 0);
}

#define	ERR(x)	((x) < 0 ? errno : 0)

/* open -> FD: data, fstat, the identity's name, no write. */
static void
c_open(struct srv *s, int *r)
{
	char path[PATH_MAX], buf[64], rp[PATH_MAX];
	struct kinfo_file kif;
	struct stat st;
	int fd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	if (fd < 0)
		return;
	r[1] = (int)read(fd, buf, sizeof(buf));
	r[2] = r[1] == 7 && memcmp(buf, "served\n", 7) == 0;
	r[3] = ERR(fstat(fd, &st));
	r[4] = (int)st.st_size;
	r[5] = S_ISREG(st.st_mode);
	r[6] = write(fd, "x", 1) < 0 ? errno : 0;
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	r[7] = ERR(fcntl(fd, F_KINFO, &kif));
	/* kf_path presents the served name. */
	r[9] = strcmp(kif.kf_path, path) == 0;
	/* realpath(3) of the served name presents it (D174, real root). */
	r[8] = realpath(path, rp) != NULL && strcmp(rp, path) == 0;
	close(fd);
	/* One real lookup outside the prefix: the tree PASSes it. */
	r[10] = ERR(stat("/", &st));
}

ATF_TC_WITHOUT_HEAD(open_fd);
ATF_TC_BODY(open_fd, tc)
{
	struct srv s;
	struct dq_stats2 st;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	run_child(&s, c_open, r);
	ATF_CHECK_EQ_MSG(0, r[0], "open: %s", strerror(r[0]));
	ATF_CHECK_EQ(7, r[1]);
	ATF_CHECK(r[2]);
	ATF_CHECK_EQ(0, r[3]);
	ATF_CHECK_EQ(7, r[4]);
	ATF_CHECK(r[5]);
	ATF_CHECK_EQ(EBADF, r[6]);
	ATF_CHECK_EQ(0, r[7]);		/* F_KINFO answers */
	ATF_CHECK(r[9]);
	ATF_CHECK_EQ(0, r[10]);
	ATF_CHECK(r[8]);
	i = srv_find(&s, DQ_ROP_OPEN, "/a");
	ATF_REQUIRE(i >= 0);
	/* REAL is offered to unrestricted lookups too (1c-iii-b). */
	ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS) | DQ_RACCEPT(DQ_RESOLVE_FD) |
	    DQ_RACCEPT(DQ_RESOLVE_REAL) |
	    DQ_RACCEPT(DQ_RESOLVE_SWAP),
	    s.seen[i].accept);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK(st.ds2_resolve_served >= 2);
	ATF_CHECK_EQ(0, st.ds2_resolve_retired);
	/* PASS answers still count (the child's real lookups). */
	ATF_CHECK(st.ds2_resolve_pass >= 1);
	ATF_CHECK(st.ds2_resolve_pass + st.ds2_resolve_served <=
	    st.ds2_resolves);
	ATF_CHECK_EQ(0, dq_tree_objects(s.tree));
	srv_stop(&s);
}

/* O_CREAT: drs_cmode, the controller creates, the write reaches it. */
static void
c_create(struct srv *s, int *r)
{
	char path[PATH_MAX];
	int fd;

	umask(022);
	snprintf(path, sizeof(path), "%s/new", s->prefix);
	fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0666);
	r[0] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		r[1] = (int)write(fd, "hello", 5);
		close(fd);
	}
	/* O_EXCL again: the controller's EEXIST. */
	fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0666);
	r[2] = fd < 0 ? errno : 0;
	if (fd >= 0)
		close(fd);
	/* O_DIRECTORY on a served file: ENOTDIR, the object retired. */
	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY | O_DIRECTORY);
	r[3] = fd < 0 ? errno : 0;
}

ATF_TC_WITHOUT_HEAD(open_create);
ATF_TC_BODY(open_create, tc)
{
	struct srv s;
	struct dq_stats2 st;
	struct stat sb;
	char buf[16];
	int r[RES_MAX], i, fd;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_create, r);
	ATF_CHECK_EQ_MSG(0, r[0], "create: %s", strerror(r[0]));
	ATF_CHECK_EQ(5, r[1]);
	ATF_CHECK_EQ(EEXIST, r[2]);
	ATF_CHECK_EQ(ENOTDIR, r[3]);
	i = srv_find(&s, DQ_ROP_OPEN, "/new");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(0644, s.seen[i].cmode);
	fd = open("backing/new", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(5, read(fd, buf, sizeof(buf)));
	ATF_CHECK(fstat(fd, &sb) == 0 && (sb.st_mode & 0777) == 0644);
	close(fd);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK_EQ(1, st.ds2_resolve_retired);	/* the O_DIRECTORY one */
	srv_stop(&s);
}

/* stat family -> ATTR against the backing file. */
static void
c_stat(struct srv *s, int *r)
{
	char path[PATH_MAX], lpath[PATH_MAX], buf[64];
	struct stat st, lst;
	struct statfs sf;
	ssize_t n;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	snprintf(lpath, sizeof(lpath), "%s/l", s->prefix);
	r[0] = ERR(stat(path, &st));
	r[1] = (int)st.st_size;
	r[2] = (int)st.st_ino;
	r[3] = ERR(access(path, R_OK));
	r[4] = ERR(lstat(lpath, &lst));
	r[5] = S_ISLNK(lst.st_mode);
	n = readlink(lpath, buf, sizeof(buf));
	r[6] = (int)n;
	r[7] = n == 1 && buf[0] == 'a';
	r[8] = ERR(stat(lpath, &st));	/* follows l -> a */
	r[9] = (int)st.st_ino;
	r[10] = ERR(statfs(path, &sf));
	r[11] = pathconf(path, _PC_NAME_MAX) > 0;
	r[12] = ERR(readlink(path, buf, sizeof(buf)));	/* not a link */
	snprintf(path, sizeof(path), "%s/missing", s->prefix);
	r[13] = ERR(stat(path, &st));
}

ATF_TC_WITHOUT_HEAD(stat_attr);
ATF_TC_BODY(stat_attr, tc)
{
	struct srv s;
	struct stat real;
	int r[RES_MAX];

	srv_start(&s, 0);
	ATF_REQUIRE(stat("backing/a", &real) == 0);
	run_child(&s, c_stat, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(7, r[1]);
	ATF_CHECK_EQ((int)real.st_ino, r[2]);
	ATF_CHECK_EQ(0, r[3]);
	ATF_CHECK_EQ(0, r[4]);
	ATF_CHECK(r[5]);
	ATF_CHECK_EQ(1, r[6]);
	ATF_CHECK(r[7]);
	ATF_CHECK_EQ(0, r[8]);
	ATF_CHECK_EQ((int)real.st_ino, r[9]);
	ATF_CHECK_EQ(0, r[10]);
	ATF_CHECK(r[11]);
	ATF_CHECK_EQ(EINVAL, r[12]);
	ATF_CHECK_EQ(ENOENT, r[13]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/* Mutating operations -> OK, performed in the backing tree. */
static void
c_mutate(struct srv *s, int *r)
{
	char a[PATH_MAX], b[PATH_MAX];

	umask(022);
#define	P(buf, name) snprintf(buf, sizeof(buf), "%s/%s", s->prefix, name)
	P(a, "m");
	r[0] = ERR(mkdir(a, 0777));
	P(a, "f");
	r[1] = ERR(mkfifo(a, 0666));
	P(a, "a"); P(b, "b");
	r[2] = ERR(link(a, b));
	P(a, "b"); P(b, "c");
	r[3] = ERR(rename(a, b));
	P(a, "c");
	r[4] = ERR(unlink(a));
	P(a, "m");
	r[5] = ERR(rmdir(a));
	P(a, "s");
	r[6] = ERR(symlink("target-text", a));
	P(a, "a");
	r[7] = ERR(chmod(a, 0600));
	r[8] = ERR(truncate(a, 3));
	r[9] = ERR(utimes(a, NULL));
	/* Set-id bits never reach a served identity (I3): EPERM. */
	r[10] = ERR(chmod(a, 04600));
	/* A rename across the prefix: EXDEV. */
	r[11] = ERR(rename(a, "/tmp/dq_served_outside"));
#undef P
}

ATF_TC_WITHOUT_HEAD(mutate_ok);
ATF_TC_BODY(mutate_ok, tc)
{
	struct srv s;
	struct stat st;
	char buf[32];
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_mutate, r);
	for (i = 0; i <= 9; i++)
		ATF_CHECK_EQ_MSG(0, r[i], "step %d: %s", i, strerror(r[i]));
	ATF_CHECK_EQ(EPERM, r[10]);
	ATF_CHECK_EQ(EXDEV, r[11]);
	ATF_CHECK(lstat("backing/m", &st) != 0);
	ATF_CHECK(lstat("backing/f", &st) == 0 && S_ISFIFO(st.st_mode));
	ATF_CHECK(lstat("backing/c", &st) != 0);
	ATF_CHECK(readlink("backing/s", buf, sizeof(buf)) == 11);
	ATF_CHECK(stat("backing/a", &st) == 0 && st.st_size == 3 &&
	    (st.st_mode & 07777) == 0600);
	i = srv_find(&s, DQ_ROP_SETATTR, "/a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK(s.seen[i].has_setattr);
	/* The set-id chmod withholds OK (FD then gives EPERM). */
	ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS) | DQ_RACCEPT(DQ_RESOLVE_FD) |
	    DQ_RACCEPT(DQ_RESOLVE_REAL), s.seen[i].accept);
	ATF_CHECK_EQ(DQ_SETATTR_MODE, s.seen[i].sb.dsa_mask);
	i = srv_find(&s, DQ_ROP_MKDIR, "/m");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(0755, s.seen[i].cmode);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * The accept set (D158): restricted lookups take PASS only; kinds
 * outside it are EINVAL to the controller with the event in flight.
 */
static int
h_wrong_kind(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct stat st;
	struct statfs sf;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	/* ATTR to an OPEN: refused, the event stays. */
	(void)fstatat(s->rootfd, "a", &st, 0);
	(void)fstatfs(s->rootfd, &sf);
	strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
	(void)dq_ident_from_stat(&id, "/x/a", &st, &sf, -1);
	errno = 0;
	if (dq_reply_resolve_attr(s->q, ev->de_id, &id) != 0)
		s->hook_errno = errno;
	/* OK too. */
	if (dq_reply_resolve_ok(s->q, ev->de_id) != 0)
		s->hook_errno2 = errno;
	return (0);	/* then the tree answers FD */
}

static void
c_open_beneath(struct srv *s, int *r)
{
	char path[PATH_MAX];
	int fd, dfd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	if (fd >= 0)
		close(fd);
	/* O_RESOLVE_BENEATH from a real dirfd: PASS only. */
	dfd = open("/", O_DIRECTORY | O_RDONLY);
	fd = openat(dfd, path + 1, O_RDONLY | O_RESOLVE_BENEATH);
	r[1] = fd < 0 ? errno : 0;
	close(dfd);
}

ATF_TC_WITHOUT_HEAD(accept_set);
ATF_TC_BODY(accept_set, tc)
{
	struct srv s;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	s.hook = h_wrong_kind;
	run_child(&s, c_open_beneath, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(EINVAL, s.hook_errno);
	ATF_CHECK_EQ(EINVAL, s.hook_errno2);
	/* PASSed: the real path does not exist. */
	ATF_CHECK_EQ(ENOENT, r[1]);
	i = srv_find(&s, DQ_ROP_OPEN, NULL);
	ATF_REQUIRE(i >= 0);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_BENEATH) != 0);
	ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS), s.seen[i].accept);
	srv_stop(&s);
}

/*
 * The reply path's refusals (D130, D171): a drm_objectp that faults is
 * EFAULT with the event in flight; DQ_MINT_F_CREATED without O_CREAT and
 * DQ_MINT_F_WRITE under DENY are EINVAL with their reason; a LINK whose
 * size is not the target's, or not a symlink, or with bytes after the
 * NUL, is EINVAL.
 */
static int
h_refusals(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	struct stat st;
	struct statfs sf;
	uint64_t oid;
	int32_t reason;
	char raw[8 + sizeof(struct dq_resolve_attr) + 16];
	struct dq_resolve_reply *rr = (void *)raw;
	struct dq_resolve_attr *ra = (void *)(rr + 1);
	struct dq_resolve_target *rt = (void *)(ra + 1);

	if (strstr(path, "/a") == NULL && strstr(path, "/l") == NULL)
		return (0);
	if (rb->drs_op == DQ_ROP_OPEN) {
		(void)fstatat(s->rootfd, "a", &st, 0);
		(void)fstatfs(s->rootfd, &sf);
		strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
		(void)dq_ident_from_stat(&id, path, &st, &sf, -1);
		dq_policy_default(&pol);
		if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0, &id,
		    &pol, (uint64_t *)(uintptr_t)8, NULL) != 0)
			s->fault_errno = errno;		/* EFAULT */
		reason = 0;
		if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE,
		    DQ_MINT_F_CREATED, &id, &pol, &oid, &reason) != 0)
			s->hook_errno = errno * 100 + reason;
		if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE,
		    DQ_MINT_F_WRITE, &id, &pol, &oid, &reason) != 0)
			s->hook_errno2 = errno * 100 + reason;
		return (0);	/* the tree answers */
	}
	if (rb->drs_op == DQ_ROP_READLINK) {
		(void)fstatat(s->rootfd, "l", &st, AT_SYMLINK_NOFOLLOW);
		(void)fstatfs(s->rootfd, &sf);
		strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
		memset(raw, 0, sizeof(raw));
		rr->drr_kind = DQ_RESOLVE_LINK;
		(void)dq_ident_from_stat(&ra->dra_ident, path, &st, &sf, -1);
		rt->drt_len = 1;
		rt->drt_target[0] = 'a';
		ra->dra_ident.di_size = 2;	/* != drt_len */
		s->hook_state = dq_reply(s->q, ev->de_id, 0, raw, sizeof(raw)) ?
		    errno : 0;
		ra->dra_ident.di_size = 1;
		rt->drt_target[3] = 'x';	/* garbage after the NUL */
		s->hook_state += 100 * (dq_reply(s->q, ev->de_id, 0, raw,
		    sizeof(raw)) ? errno : 0);
		rt->drt_target[3] = '\0';
		ra->dra_ident.di_mode = S_IFREG | 0644;	/* not a symlink */
		s->hook_state += 10000 * (dq_reply(s->q, ev->de_id, 0, raw,
		    sizeof(raw)) ? errno : 0);
		return (0);
	}
	return (0);
}

static void
c_refusals(struct srv *s, int *r)
{
	char path[PATH_MAX], buf[8];
	int fd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	if (fd >= 0)
		close(fd);
	snprintf(path, sizeof(path), "%s/l", s->prefix);
	r[1] = (int)readlink(path, buf, sizeof(buf));
}

ATF_TC_WITHOUT_HEAD(reply_refusals);
ATF_TC_BODY(reply_refusals, tc)
{
	struct srv s;
	struct dq_stats2 st;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_refusals;
	run_child(&s, c_refusals, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(1, r[1]);
	ATF_CHECK_EQ(EFAULT, s.fault_errno);
	ATF_CHECK_EQ(EINVAL * 100 + DQ_REASON_FLAGS, s.hook_errno);
	ATF_CHECK_EQ(EINVAL * 100 + DQ_REASON_FLAGS, s.hook_errno2);
	ATF_CHECK_EQ(EINVAL + 100 * EINVAL + 10000 * EINVAL, s.hook_state);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	/* The faulting copyout linked nothing: no object, no CLOSE owed. */
	ATF_CHECK_EQ(0, st.ds2_resolve_retired);
	srv_stop(&s);
}

/*
 * A failure after the reply (D171): EMFILE at install retires the id
 * through the file's last close, with exactly one CLOSE (the revoked
 * case is revoke_before_bind).
 */
static void
c_emfile(struct srv *s, int *r)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	/* Fill the table (RLIMIT_NOFILE 64): the next install is EMFILE. */
	fd = open("/dev/null", O_RDONLY);
	while (fd >= 0 && dup(fd) >= 0)
		;
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
}

ATF_TC_WITHOUT_HEAD(post_reply_emfile);
ATF_TC_BODY(post_reply_emfile, tc)
{
	struct srv s;
	struct dq_stats2 st;
	struct rlimit rl, save;
	int r[RES_MAX];

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &save) == 0);
	rl = save;
	rl.rlim_cur = 64;
	ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &rl) == 0);
	srv_start(&s, 0);
	run_child(&s, c_emfile, r);
	(void)setrlimit(RLIMIT_NOFILE, &save);
	ATF_CHECK_EQ(EMFILE, r[0]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK_EQ(1, st.ds2_objects_total);
	/* Retired through the file's last close, with its CLOSE. */
	ATF_CHECK_EQ(1, srv_wait_closes(&s, 1));
	ATF_CHECK_EQ(0, dq_tree_objects(s.tree));
	srv_stop(&s);
}

/* Answer an OPEN of .../a with FD, policy subscribing CLOSE. */
static int
h_fd_close(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	s->hook_errno = dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0,
	    &id, &pol, &oid, NULL) == 0 ? 0 : errno;
	return (1);
}

/*
 * ENFILE: the file table is filled, not bounded.  falloc refuses a caller
 * without PRIV_MAXFILES once kern.openfiles reaches kern.maxfiles less a
 * twentieth (falloc_noinstall), and the requester here has no privilege.
 * kern.maxfiles is not written: the capability plane lets only its sysctl
 * provider write it (mac_capability_system.c, sys_check_sysctl).
 *
 * Root fillers open /dev/null up to ENFILE_BELOW short of that bound
 * before the open, so the requester's own falloc succeeds; the hook, with
 * the RESOLVE in hand, opens the rest and ENFILE_OVER more and answers FD
 * (the controller opens nothing for the answer), so the falloc of the
 * bind is the one refused.  Other unprivileged processes are refused
 * meanwhile, from the hook until the body closes the hook's files.
 */
#define	ENFILE_UID	65534
#define	ENFILE_BELOW	256
#define	ENFILE_OVER	64
#define	ENFILE_HOOKMAX	1024
#define	ENFILE_FILLERS	64

static int enfile_bound;		/* refused at kern.openfiles >= this */
static int enfile_fds[ENFILE_HOOKMAX];
static int enfile_nfds;
static int enfile_err;

static int
enfile_openfiles(void)
{
	size_t len;
	int n;

	len = sizeof(n);
	if (sysctlbyname("kern.openfiles", &n, &len, NULL, 0) != 0)
		return (-1);
	return (n);
}

/*
 * A process that opens up to n files and holds them until it is killed
 * (the close of its process descriptor does that, so the files go with
 * the test however it ends).  Returns how many it holds.
 */
static int
enfile_filler(int n, int *pdp)
{
	struct rlimit rl;
	pid_t pid;
	int got, i, p[2];

	ATF_REQUIRE_EQ(0, pipe(p));
	pid = pdfork(pdp, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		(void)close(p[0]);
		rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
		(void)setrlimit(RLIMIT_NOFILE, &rl);
		for (i = 0; i < n; i++) {
			if (open("/dev/null", O_RDONLY) == -1)
				break;
		}
		if (write(p[1], &i, sizeof(i)) != sizeof(i))
			_exit(1);
		for (;;)
			(void)pause();
	}
	(void)close(p[1]);
	got = 0;
	ATF_REQUIRE_EQ((ssize_t)sizeof(got), read(p[0], &got, sizeof(got)));
	(void)close(p[0]);
	return (got);
}

static int
h_enfile(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;
	int fd, need, now;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL ||
	    s->hook_state != 0)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	/* Twice: other processes open and close files meanwhile. */
	for (;;) {
		now = enfile_openfiles();
		if (now == -1) {
			enfile_err = errno;
			return (0);
		}
		need = enfile_bound + ENFILE_OVER - now;
		if (need <= 0)
			break;
		while (need-- > 0) {
			fd = -1;
			if (enfile_nfds < ENFILE_HOOKMAX)
				fd = open("/dev/null", O_RDONLY);
			if (fd == -1) {
				enfile_err = enfile_nfds < ENFILE_HOOKMAX ?
				    errno : E2BIG;
				return (0);
			}
			enfile_fds[enfile_nfds++] = fd;
		}
	}
	s->hook_state = 1;
	if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0, &id, &pol,
	    &oid, NULL) != 0)
		s->hook_errno = errno;
	/* The body closes the files once the child's open is done. */
	return (1);
}

static void
c_enfile(struct srv *s, int *r)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
}

ATF_TC(post_reply_enfile);
ATF_TC_HEAD(post_reply_enfile, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "600");
}
ATF_TC_BODY(post_reply_enfile, tc)
{
	struct srv s;
	struct dq_stats2 st;
	size_t len;
	int filler[ENFILE_FILLERS], got, i, maxfiles, nfillers, now, want;
	int r[RES_MAX], status;

	len = sizeof(maxfiles);
	ATF_REQUIRE(sysctlbyname("kern.maxfiles", &maxfiles, &len, NULL,
	    0) == 0);
	enfile_bound = maxfiles - maxfiles / 20;
	ATF_REQUIRE_MSG(maxfiles - enfile_bound > 2 * ENFILE_OVER &&
	    enfile_bound > 2 * ENFILE_BELOW, "kern.maxfiles %d is too small "
	    "for this case", maxfiles);
	srv_start(&s, 0);
	ATF_REQUIRE(chmod(".", 0755) == 0);
	s.hook = h_enfile;
	for (nfillers = 0;; nfillers++) {
		now = enfile_openfiles();
		ATF_REQUIRE(now != -1);
		want = enfile_bound - ENFILE_BELOW - now;
		if (want <= 0)
			break;
		ATF_REQUIRE_MSG(nfillers < ENFILE_FILLERS, "%d fillers left "
		    "kern.openfiles at %d of %d", nfillers, now, enfile_bound);
		got = enfile_filler(want, &filler[nfillers]);
		ATF_REQUIRE_MSG(got > 0, "a filler could open nothing "
		    "(kern.openfiles %d of %d)", now, enfile_bound);
	}
	printf("kern.maxfiles %d, bound %d, %d fillers, kern.openfiles %d\n",
	    maxfiles, enfile_bound, nfillers, now);
	run_child_as(&s, c_enfile, r, ENFILE_UID, true);
	now = enfile_openfiles();
	for (i = 0; i < enfile_nfds; i++)
		(void)close(enfile_fds[i]);
	/*
	 * The fillers are waited for: closing a quarter of a million files
	 * takes them a while, and the case does not leave that running
	 * under the next one.
	 */
	for (i = 0; i < nfillers; i++) {
		(void)pdkill(filler[i], SIGKILL);
		(void)pdwait(filler[i], &status, WEXITED, NULL, NULL);
		(void)close(filler[i]);
	}
	printf("the hook opened %d files; kern.openfiles was %d\n",
	    enfile_nfds, now);
	ATF_REQUIRE_MSG(s.hook_state == 1, "the hook did not answer: %s",
	    strerror(enfile_err));
	ATF_CHECK_EQ(0, s.hook_errno);
	ATF_CHECK_EQ(ENFILE, r[0]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK_EQ(1, st.ds2_resolve_retired);
	ATF_CHECK_EQ(1, srv_wait_closes(&s, 1));
	srv_stop(&s);
}

/*
 * The same ENFILE through debug.dq.fail_bind_enfile: dq_file_bind fails
 * as falloc would, the object retires with exactly one CLOSE.
 */
ATF_TC(post_reply_enfile_inject);
ATF_TC_HEAD(post_reply_enfile_inject, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(post_reply_enfile_inject, tc)
{
	struct srv s;
	struct dq_stats2 st;
	u_int one = 1, zero = 0;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_fd_close;
	ATF_REQUIRE(sysctlbyname("debug.dq.fail_bind_enfile", NULL, NULL,
	    &one, sizeof(one)) == 0);
	run_child(&s, c_enfile, r);
	(void)sysctlbyname("debug.dq.fail_bind_enfile", NULL, NULL, &zero,
	    sizeof(zero));
	ATF_CHECK_EQ(ENFILE, r[0]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK_EQ(1, st.ds2_resolve_retired);
	ATF_CHECK_EQ(1, srv_wait_closes(&s, 1));
	srv_stop(&s);
}

/*
 * D157: a dropped completion (debug.dqres.drop_completion) lets
 * EDQRESOLVED escape; syscallenter maps it to EIO.  The INVARIANTS
 * assertion is suppressed for the injected syscall (TDP2_DQ_INJECTED), so
 * this runs on GENERIC.
 */
static void
c_stat_one(struct srv *s, int *r)
{
	char path[PATH_MAX];
	struct stat st;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	r[0] = ERR(stat(path, &st));
	r[1] = ERR(stat(path, &st));	/* the next one completes */
}

ATF_TC(dropped_completion_eio);
ATF_TC_HEAD(dropped_completion_eio, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dropped_completion_eio, tc)
{
	struct srv s;
	u_int one = 1, zero = 0;
	int r[RES_MAX];

	srv_start(&s, 0);
	ATF_REQUIRE(sysctlbyname("debug.dqres.drop_completion", NULL, NULL,
	    &one, sizeof(one)) == 0);
	run_child(&s, c_stat_one, r);
	(void)sysctlbyname("debug.dqres.drop_completion", NULL, NULL, &zero,
	    sizeof(zero));
	ATF_CHECK_EQ(EIO, r[0]);
	ATF_CHECK_EQ(0, r[1]);
	srv_stop(&s);
}

/* The reply's pager object cannot be made: ENOMEM, event in flight. */
static int
h_vmfail(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	u_int one = 1;
	struct dq_ident_file id;
	struct dq_policy pol;
	struct stat st;
	struct statfs sf;
	uint64_t oid;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	(void)fstatat(s->rootfd, "a", &st, 0);
	(void)fstatfs(s->rootfd, &sf);
	strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
	(void)dq_ident_from_stat(&id, path, &st, &sf, -1);
	dq_policy_default(&pol);
	(void)sysctlbyname("debug.dq.fail_vm_create", NULL, NULL, &one,
	    sizeof(one));
	if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0, &id, &pol,
	    &oid, NULL) != 0)
		s->hook_errno = errno;
	return (0);
}

ATF_TC(vm_create_enomem);
ATF_TC_HEAD(vm_create_enomem, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(vm_create_enomem, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_vmfail;
	run_child(&s, c_open, r);
	ATF_CHECK_EQ(ENOMEM, s.hook_errno);
	ATF_CHECK_EQ(0, r[0]);		/* the tree's answer completed it */
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * O_PATH on a served file (4.7), O_EXLOCK through a LOCK event, and the
 * descriptor is not transferable (CAP_XFER_NONE until 1c-iv).
 */
static void
c_opath(struct srv *s, int *r)
{
	char path[PATH_MAX], buf[4], cbuf[CMSG_SPACE(sizeof(int))];
	struct pollfd pfd;
	struct stat st;
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	int fd, sv[2];

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_PATH);
	r[0] = fd < 0 ? errno : 0;
	if (fd < 0)
		return;
	r[1] = read(fd, buf, 1) < 0 ? errno : 0;
	r[2] = ERR(fstat(fd, &st));
	r[3] = fchmod(fd, 0644) < 0 ? errno : 0;
	pfd.fd = fd;
	pfd.events = POLLIN;
	r[4] = poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLNVAL) != 0;
	close(fd);

	fd = open(path, O_RDONLY | O_EXLOCK | O_NONBLOCK);
	r[5] = fd < 0 ? errno : 0;
	if (fd < 0)
		return;
	r[6] = ERR(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	r[7] = sendmsg(sv[0], &msg, 0) < 0 ? errno : 0;
	r[8] = (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_exlock_xfer);
ATF_TC_BODY(opath_exlock_xfer, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	run_child(&s, c_opath, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(EBADF, r[1]);
	ATF_CHECK_EQ(0, r[2]);
	ATF_CHECK_EQ(EBADF, r[3]);
	ATF_CHECK(r[4]);
	ATF_CHECK_EQ_MSG(0, r[5], "O_EXLOCK: %s", strerror(r[5]));
	ATF_CHECK_EQ(ENOTCAPABLE, r[7]);
	ATF_CHECK(!r[8]);		/* O_CLOEXEC only as asked */
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * An O_PATH served file answers as an O_PATH vnode does (D244).  The same
 * calls are made on the served file by an attached child and on its
 * backing file by an unattached one, and the answers are compared; the
 * rows aio(4), fdescfs and F_SETFL used to answer differently are also
 * checked by value.  Changes by name go through a private fdescfs.
 */
enum {
	OP_OPEN, OP_READ, OP_LSEEK, OP_IOCTL, OP_POLL, OP_MMAP, OP_FSYNC,
	OP_FDATASYNC, OP_FTRUNCATE, OP_FCHMOD, OP_FCHOWN, OP_FUTIMENS,
	OP_FCHFLAGS, OP_FLOCK, OP_SETLK, OP_SETFL, OP_FSTAT, OP_FSTATFS,
	OP_FPATHCONF, OP_AIO_FSYNC, OP_LIO_NOP, OP_LIO_NOP_ERROR,
	OP_FD_CHMOD, OP_FD_CHOWN, OP_FD_UTIMES, OP_FD_TRUNCATE, OP__N
};
_Static_assert(OP__N <= RES_MAX, "RES_MAX");

static const char *const opath_op_names[OP__N] = {
	"open", "read", "lseek", "ioctl", "poll", "mmap", "fsync",
	"fdatasync", "ftruncate", "fchmod", "fchown", "futimens",
	"fchflags", "flock", "F_SETLK", "F_SETFL", "fstat", "fstatfs",
	"fpathconf", "aio_fsync", "lio_listio", "LIO_NOP aio_error",
	"chmod /dev/fd/N", "chown /dev/fd/N", "utimes /dev/fd/N",
	"truncate /dev/fd/N",
};

#define	OPATH_UID	65534

static bool opath_served;

static int
opath_open(struct srv *s, int flags)
{
	char path[PATH_MAX];

	if (opath_served)
		snprintf(path, sizeof(path), "%s/a", s->prefix);
	else
		snprintf(path, sizeof(path), "%s/a", s->backing);
	return (open(path, flags));
}

static void
c_opath_calls(struct srv *s, int *r)
{
	struct aiocb cb, *list[1];
	struct flock fl;
	struct pollfd pfd;
	struct stat st;
	struct statfs sf;
	char path[32], c;
	void *p;
	int fd, n;

	fd = opath_open(s, O_PATH);
	r[OP_OPEN] = ERR(fd);
	if (fd < 0)
		return;
	r[OP_READ] = ERR(read(fd, &c, 1));
	r[OP_LSEEK] = ERR(lseek(fd, 0, SEEK_CUR));
	r[OP_IOCTL] = ERR(ioctl(fd, FIONREAD, &n));
	pfd.fd = fd;
	pfd.events = POLLIN;
	r[OP_POLL] = poll(&pfd, 1, 0) == 1 ? pfd.revents : -1;
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE, fd, 0);
	r[OP_MMAP] = p == MAP_FAILED ? errno : 0;
	r[OP_FSYNC] = ERR(fsync(fd));
	r[OP_FDATASYNC] = ERR(fdatasync(fd));
	r[OP_FTRUNCATE] = ERR(ftruncate(fd, 7));
	r[OP_FCHMOD] = ERR(fchmod(fd, 0600));
	r[OP_FCHOWN] = ERR(fchown(fd, OPATH_UID, -1));
	r[OP_FUTIMENS] = ERR(futimens(fd, NULL));
	r[OP_FCHFLAGS] = ERR(fchflags(fd, 0));
	r[OP_FLOCK] = ERR(flock(fd, LOCK_SH | LOCK_NB));
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	r[OP_SETLK] = ERR(fcntl(fd, F_SETLK, &fl));
	r[OP_SETFL] = ERR(fcntl(fd, F_SETFL, O_NONBLOCK));
	r[OP_FSTAT] = ERR(fstat(fd, &st));
	r[OP_FSTATFS] = ERR(fstatfs(fd, &sf));
	r[OP_FPATHCONF] = ERR(fpathconf(fd, _PC_NAME_MAX));

	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	r[OP_AIO_FSYNC] = ERR(aio_fsync(O_SYNC, &cb));
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_lio_opcode = LIO_NOP;
	list[0] = &cb;
	r[OP_LIO_NOP] = ERR(lio_listio(LIO_NOWAIT, list, 1, NULL));
	r[OP_LIO_NOP_ERROR] = aio_error(&cb);

	snprintf(path, sizeof(path), DQT_FDESC_DIR "/%d", fd);
	r[OP_FD_CHMOD] = ERR(chmod(path, 0600));
	r[OP_FD_CHOWN] = ERR(chown(path, OPATH_UID, -1));
	r[OP_FD_UTIMES] = ERR(utimes(path, NULL));
	r[OP_FD_TRUNCATE] = ERR(truncate(path, 0));
	close(fd);
}

/* What the calls by name left on the backing file; put it back. */
static void
opath_backing_changed(const char *who)
{
	struct stat st;

	ATF_REQUIRE_EQ(0, stat("backing/a", &st));
	ATF_CHECK_EQ_MSG(0600, st.st_mode & ALLPERMS, "%s: mode %o", who,
	    st.st_mode & ALLPERMS);
	ATF_CHECK_EQ_MSG(OPATH_UID, st.st_uid, "%s: owner %d", who,
	    st.st_uid);
	ATF_CHECK_EQ_MSG(7, st.st_size, "%s: size %jd", who,
	    (intmax_t)st.st_size);
	ATF_REQUIRE_EQ(0, chmod("backing/a", 0644));
	ATF_REQUIRE_EQ(0, chown("backing/a", 0, -1));
}

ATF_TC_WITH_CLEANUP(opath_as_vnode);
ATF_TC_HEAD(opath_as_vnode, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(opath_as_vnode, tc)
{
	struct srv s;
	int i, served[RES_MAX], vnode[RES_MAX];

	if (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false))
		atf_tc_skip("pre1c: the kernel has no served directories");
	srv_start(&s, 0);
	dqt_mount_fdesc(NULL);
	opath_served = false;
	run_child_as(&s, c_opath_calls, vnode, (uid_t)-1, false);
	ATF_REQUIRE_EQ(0, vnode[OP_OPEN]);
	opath_backing_changed("vnode");
	opath_served = true;
	run_child(&s, c_opath_calls, served);
	ATF_REQUIRE_EQ_MSG(0, served[OP_OPEN], "open: %s",
	    strerror(served[OP_OPEN]));
	opath_backing_changed("served");
	for (i = 0; i < OP__N; i++)
		ATF_CHECK_EQ_MSG(vnode[i], served[i],
		    "%s: vnode %d, served %d", opath_op_names[i], vnode[i],
		    served[i]);

	ATF_CHECK_EQ(EBADF, served[OP_AIO_FSYNC]);
	ATF_CHECK_EQ(EIO, served[OP_LIO_NOP]);
	ATF_CHECK_EQ(EBADF, served[OP_LIO_NOP_ERROR]);
	ATF_CHECK_EQ(0, served[OP_FD_CHMOD]);
	ATF_CHECK_EQ(0, served[OP_FD_CHOWN]);
	ATF_CHECK_EQ(0, served[OP_FD_UTIMES]);
	ATF_CHECK_EQ(EBADF, served[OP_FD_TRUNCATE]);
	ATF_CHECK_EQ(EBADF, served[OP_SETFL]);
	ATF_CHECK_EQ(EBADF, served[OP_FCHMOD]);
	ATF_CHECK_EQ(EOPNOTSUPP, served[OP_FLOCK]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}
ATF_TC_CLEANUP(opath_as_vnode, tc)
{
	dqt_umount_fdesc();
}

/*
 * fexecve(2) lets an O_PATH descriptor past its open-mode test, a served
 * one too, and then wants a vnode: a served file, however it was opened,
 * has none to execute.  aio_fsync(2) on a served file that is not O_PATH
 * is queued as any request on a file aio(4) does not know to be safe is:
 * refused unless vfs.aio.enable_unsafe is set, the descriptor's own fsync
 * if it is.
 */
static void
c_served_fexecve_aio(struct srv *s, int *r)
{
	char *const argv[] = { __DECONST(char *, "a"), NULL };
	char *const envp[] = { NULL };
	struct aiocb cb, *done;
	int fd;

	opath_served = true;
	fd = opath_open(s, O_PATH);
	r[0] = ERR(fd);
	r[1] = ERR(fexecve(fd, argv, envp));
	close(fd);
	fd = opath_open(s, O_RDONLY);
	r[2] = ERR(fd);
	r[3] = ERR(fexecve(fd, argv, envp));
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	r[4] = ERR(aio_fsync(O_SYNC, &cb));
	if (r[4] == 0) {
		r[5] = aio_waitcomplete(&done, NULL) < 0 ? errno : 0;
		r[6] = done == &cb;
	}
	close(fd);
}

ATF_TC_WITHOUT_HEAD(served_fexecve_aio_fsync);
ATF_TC_BODY(served_fexecve_aio_fsync, tc)
{
	struct srv s;
	size_t len;
	int r[RES_MAX], unsafe;

	if (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false))
		atf_tc_skip("pre1c: the kernel has no served directories");
	len = sizeof(unsafe);
	ATF_REQUIRE_EQ(0, sysctlbyname("vfs.aio.enable_unsafe", &unsafe, &len,
	    NULL, 0));
	srv_start(&s, 0);
	run_child(&s, c_served_fexecve_aio, r);
	ATF_REQUIRE_EQ(0, r[0]);
	ATF_CHECK_EQ(EINVAL, r[1]);
	ATF_REQUIRE_EQ(0, r[2]);
	ATF_CHECK_EQ(EINVAL, r[3]);
	if (unsafe == 0) {
		ATF_CHECK_EQ(EOPNOTSUPP, r[4]);
	} else {
		ATF_CHECK_EQ(0, r[4]);
		ATF_CHECK_EQ(0, r[5]);
		ATF_CHECK(r[6]);
	}
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * The Linux calls that tell an O_PATH descriptor apart: mmap(2) is EBADF
 * and syncfs(2) succeeds, for a served file as for a vnode.  A Linux
 * program built here inherits the descriptor.
 */
#define	OPATH_LINUX_FD	9

static void
c_opath_linux(struct srv *s, int *r)
{
	char *const argv[] = { __DECONST(char *, "dq_opath_linux"), NULL };
	char *const envp[] = { NULL };
	pid_t pid;
	int fd, status;

	fd = opath_open(s, O_PATH);
	r[0] = ERR(fd);
	if (fd < 0)
		return;
	pid = fork();
	if (pid == 0) {
		if (dup2(fd, OPATH_LINUX_FD) != OPATH_LINUX_FD)
			_exit(126);
		execve("./dq_opath_linux", argv, envp);
		_exit(127);
	}
	r[1] = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
	close(fd);
}

ATF_TC(opath_linux);
ATF_TC_HEAD(opath_linux, tc)
{
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.progs", "clang");
	atf_tc_set_md_var(tc, "require.kmods", "linux64");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(opath_linux, tc)
{
	struct srv s;
	char cmd[PATH_MAX + 256];
	int r[RES_MAX];

	if (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false))
		atf_tc_skip("pre1c: the kernel has no served directories");
	snprintf(cmd, sizeof(cmd), "clang --target=x86_64-linux-gnu "
	    "-fuse-ld=lld -nostdlib -static -fno-stack-protector "
	    "-fno-builtin -O2 -Wall -Wextra -Werror -o dq_opath_linux "
	    "%s/dq_opath_linux.c", atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s", cmd);

	srv_start(&s, 0);
	opath_served = false;
	run_child_as(&s, c_opath_linux, r, (uid_t)-1, false);
	ATF_REQUIRE_EQ(0, r[0]);
	ATF_CHECK_EQ_MSG(0, r[1], "vnode: mmap/syncfs bits %#x", r[1]);
	opath_served = true;
	run_child(&s, c_opath_linux, r);
	ATF_REQUIRE_EQ(0, r[0]);
	ATF_CHECK_EQ_MSG(0, r[1], "served: mmap/syncfs bits %#x", r[1]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * AT_EMPTY_PATH on a served descriptor (D164), held by an unattached
 * process (the minted descriptor inherited; the queue is O_CLOFORK): the
 * descriptor's own operation with no RESOLVE; fchmodat reaches the
 * object's SETATTR; readlinkat is EINVAL; linkat is EXDEV.
 */
static int emptypath_mfd = -1;

static void
c_emptypath_unattached(struct srv *s, int *r)
{
	struct stat st;
	char buf[8];

	(void)s;
	r[0] = ERR(faccessat(emptypath_mfd, "", R_OK, AT_EMPTY_PATH));
	r[1] = ERR(fstatat(emptypath_mfd, "", &st, AT_EMPTY_PATH));
	r[2] = ERR(readlinkat(emptypath_mfd, "", buf, sizeof(buf)));
	r[3] = ERR(linkat(emptypath_mfd, "", AT_FDCWD, "lnk", AT_EMPTY_PATH));
	r[4] = ERR(fchmodat(emptypath_mfd, "", 0640, AT_EMPTY_PATH));
	r[5] = ERR(fchownat(emptypath_mfd, "", -1, -1, AT_EMPTY_PATH));
}

ATF_TC_WITHOUT_HEAD(emptypath_fallbacks);
ATF_TC_BODY(emptypath_fallbacks, tc)
{
	struct srv s;
	struct dq_policy pol;
	struct stat st;
	char cwd[PATH_MAX], name[PATH_MAX];
	int r[RES_MAX];

	srv_start(&s, 0);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(name, sizeof(name), "%s/backing/a", cwd);
	srv_ident(&s, "a", name, &s.extra_ident);
	s.extra_fd = openat(s.rootfd, "a", O_RDWR);
	ATF_REQUIRE(s.extra_fd >= 0);
	dq_policy_default(&pol);
	pthread_mutex_lock(&s.mtx);
	ATF_REQUIRE(dq_mint_file(s.q, &s.extra_ident, &pol, &s.extra_id,
	    &emptypath_mfd, NULL) == 0);
	pthread_mutex_unlock(&s.mtx);
	ATF_REQUIRE(fcntl(emptypath_mfd, F_SETFD, 0) == 0);
	run_child_as(&s, c_emptypath_unattached, r, (uid_t)-1, false);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(0, r[1]);
	ATF_CHECK_EQ(EINVAL, r[2]);
	ATF_CHECK_EQ(EXDEV, r[3]);
	ATF_CHECK_EQ_MSG(0, r[4], "fchmodat: %s", strerror(r[4]));
	ATF_CHECK_EQ(0, r[5]);
	ATF_CHECK(s.extra_setattrs >= 1);
	ATF_CHECK(stat("backing/a", &st) == 0 && (st.st_mode & 0777) == 0640);
	pthread_mutex_lock(&s.mtx);
	ATF_CHECK_EQ(0, s.nseen);	/* unattached: no RESOLVE at all */
	pthread_mutex_unlock(&s.mtx);
	close(emptypath_mfd);
	srv_stop(&s);
	close(s.extra_fd);
}

/*
 * An attached child: the fallbacks on a served descriptor post no
 * RESOLVE; an empty path on a real descriptor is consulted with PASS
 * only (review item 2): fstatat, linkat and O_EMPTY_PATH.
 */
static void
c_emptypath_attached(struct srv *s, int *r)
{
	char path[PATH_MAX];
	struct stat st;
	int fd, rfd, ofd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	if (fd < 0)
		return;
	r[1] = ERR(faccessat(fd, "", R_OK, AT_EMPTY_PATH));
	r[2] = ERR(fstatat(fd, "", &st, AT_EMPTY_PATH));
	r[3] = ERR(fchmodat(fd, "", 0640, AT_EMPTY_PATH));
	r[4] = ERR(linkat(fd, "", AT_FDCWD, "lnk2", AT_EMPTY_PATH));
	close(fd);
	rfd = open("backing/a", O_RDONLY);	/* a real descriptor */
	r[5] = rfd < 0 ? errno : 0;
	r[6] = ERR(fstatat(rfd, "", &st, AT_EMPTY_PATH));
	ofd = openat(rfd, "", O_EMPTY_PATH | O_RDONLY);
	r[7] = ofd < 0 ? errno : 0;
	if (ofd >= 0)
		close(ofd);
	(void)linkat(rfd, "", AT_FDCWD, "lnk3", AT_EMPTY_PATH);
	close(rfd);
}

ATF_TC_WITHOUT_HEAD(emptypath_attached);
ATF_TC_BODY(emptypath_attached, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_emptypath_attached, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(0, r[1]);
	ATF_CHECK_EQ(0, r[2]);
	ATF_CHECK_EQ_MSG(0, r[3], "fchmodat: %s", strerror(r[3]));
	ATF_CHECK_EQ(EXDEV, r[4]);
	ATF_CHECK(stat("backing/a", &st) == 0 && (st.st_mode & 0777) == 0640);
	ATF_CHECK_EQ(-1, srv_find(&s, DQ_ROP_SETATTR, NULL));
	ATF_CHECK_EQ(0, r[5]);
	ATF_CHECK_EQ(0, r[6]);
	ATF_CHECK_EQ(0, r[7]);
	/* The real descriptor's empty paths: PASS only. */
	i = srv_find_empty(&s, DQ_ROP_STAT);
	if (i >= 0)
		ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS), s.seen[i].accept);
	i = srv_find_empty(&s, DQ_ROP_OPEN);
	if (i >= 0)
		ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS), s.seen[i].accept);
	i = srv_find_empty(&s, DQ_ROP_LINK);
	if (i >= 0)
		ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS), s.seen[i].accept);
	ATF_CHECK(srv_find_empty(&s, DQ_ROP_STAT) >= 0 ||
	    srv_find_empty(&s, DQ_ROP_OPEN) >= 0);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * Review item 1: an object reply whose first word is 2 (DQ_RESOLVE_FD) is
 * not a mint: a 2-byte write (dwr_written 2), a READ whose data starts
 * 02 00 00 00 and a GETLK answered F_UNLCK (dlr_type 2) all succeed.
 */
static void
c_two(struct srv *s, int *r)
{
	char path[PATH_MAX], buf[8];
	struct flock fl;
	int fd;

	snprintf(path, sizeof(path), "%s/two", s->prefix);
	fd = open(path, O_RDWR);
	r[0] = fd < 0 ? errno : 0;
	if (fd < 0)
		return;
	r[1] = (int)pwrite(fd, "\002\000", 2, 8);
	r[2] = (int)pread(fd, buf, 4, 0);
	r[3] = r[2] == 4 && memcmp(buf, "\002\000\000\000", 4) == 0;
	/* GETLK answered F_UNLCK: dlr_type 2 == DQ_RESOLVE_FD (run 37). */
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	r[4] = ERR(fcntl(fd, F_GETLK, &fl));
	r[5] = fl.l_type == F_UNLCK;
	close(fd);
}

ATF_TC_WITHOUT_HEAD(object_reply_not_mint);
ATF_TC_BODY(object_reply_not_mint, tc)
{
	struct srv s;
	int r[RES_MAX], fd;

	srv_start(&s, DQ_TREE_F_WRITE);
	fd = openat(s.rootfd, "two", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(8, write(fd, "\002\000\000\000abcd", 8));
	close(fd);
	run_child(&s, c_two, r);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(2, r[1]);
	ATF_CHECK_EQ(4, r[2]);
	ATF_CHECK(r[3]);
	ATF_CHECK_EQ(0, r[4]);
	ATF_CHECK(r[5]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * Revoked between the reply and the bind: EIO (or, when the requester
 * bound first, EIO on its next use); one CLOSE either way.
 */
static int
h_revoke(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0, &id, &pol,
	    &oid, NULL) == 0)
		s->hook_errno = dq_revoke(s->q, oid) == 0 ? 0 : errno;
	else
		s->hook_errno = -1;
	return (1);
}

static void
c_open_read(struct srv *s, int *r)
{
	char path[PATH_MAX], buf[8];
	int fd;

	snprintf(path, sizeof(path), "%s/a", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		r[1] = read(fd, buf, sizeof(buf)) < 0 ? errno : 0;
		close(fd);
	}
}

ATF_TC_WITHOUT_HEAD(revoke_before_bind);
ATF_TC_BODY(revoke_before_bind, tc)
{
	struct srv s;
	struct dq_stats2 st;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_revoke;
	run_child(&s, c_open_read, r);
	ATF_CHECK_EQ(0, s.hook_errno);
	ATF_CHECK_MSG(r[0] == EIO || (r[0] == 0 && r[1] == EIO),
	    "open %d read %d", r[0], r[1]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	/* Which branch ran: the bind refused (retired) or a later use. */
	printf("revoke_before_bind: %s branch (retired %ju)\n",
	    r[0] == EIO ? "bind" : "use", (uintmax_t)st.ds2_resolve_retired);
	ATF_CHECK_EQ(r[0] == EIO ? 1 : 0, st.ds2_resolve_retired);
	ATF_CHECK_EQ(1, srv_wait_closes(&s, 1));
	srv_stop(&s);
}

/* The queue closes while the requester holds the answer: EIO. */
static int
h_close(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;
	int q;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	s->hook_errno = dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0,
	    &id, &pol, &oid, NULL) == 0 ? 0 : errno;
	q = s->q;
	s->q = -1;
	s->stop = 1;
	close(q);
	return (1);
}

ATF_TC_WITHOUT_HEAD(queue_close_held_answer);
ATF_TC_BODY(queue_close_held_answer, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_close;
	run_child(&s, c_open_read, r);
	ATF_CHECK_EQ(0, s.hook_errno);
	ATF_CHECK_MSG(r[0] == EIO || (r[0] == 0 && r[1] == EIO),
	    "open %d read %d", r[0], r[1]);
	printf("queue_close_held_answer: %s branch\n",
	    r[0] == EIO ? "bind" : "use");
	/* A closed queue owes no CLOSE; none was read before it closed. */
	pthread_mutex_lock(&s.mtx);
	ATF_CHECK_EQ(0, s.closes);
	pthread_mutex_unlock(&s.mtx);
	srv_stop(&s);
}

/*
 * The link step: ENOSPC at kern.dq.max_objects (the tree then answers
 * EIO, never leaving the event in flight) and ENXIO when the queue is
 * closing (debug.dq.fail_link_closing).
 */
static int
h_enxio(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;
	u_int one = 1;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/a") == NULL)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	(void)sysctlbyname("debug.dq.fail_link_closing", NULL, NULL, &one,
	    sizeof(one));
	if (dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, 0, &id, &pol,
	    &oid, NULL) != 0)
		s->hook_errno = errno;
	return (0);	/* the event is still in flight: the tree answers */
}

ATF_TC(link_enospc_enxio);
ATF_TC_HEAD(link_enospc_enxio, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(link_enospc_enxio, tc)
{
	struct srv s;
	struct dq_policy pol;
	struct dq_ident_file id;
	char cwd[PATH_MAX], name[PATH_MAX];
	u_int one = 1, save;
	size_t len;
	uint64_t oid;
	int r[RES_MAX], mfd;

	srv_start(&s, 0);
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(name, sizeof(name), "%s/backing/a", cwd);
	srv_ident(&s, "a", name, &id);
	dq_policy_default(&pol);
	ATF_REQUIRE(dq_mint_file(s.q, &id, &pol, &oid, &mfd, NULL) == 0);
	len = sizeof(save);
	ATF_REQUIRE(sysctlbyname("kern.dq.max_objects", &save, &len, &one,
	    sizeof(one)) == 0);
	run_child(&s, c_open, r);
	(void)sysctlbyname("kern.dq.max_objects", NULL, NULL, &save,
	    sizeof(save));
	ATF_CHECK_EQ(EIO, r[0]);	/* ENOSPC to the tree, EIO after */
	close(mfd);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));

	s.hook = h_enxio;
	run_child(&s, c_open, r);
	ATF_CHECK_EQ(ENXIO, s.hook_errno);
	ATF_CHECK_EQ(0, r[0]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * D166 as a non-root requester, on identities the hook presents: another
 * owner's 0600 file (EACCES), an append-only file opened for writing
 * without O_APPEND (EPERM), a read-only file opened O_RDONLY | O_TRUNC
 * (EACCES).  Each refused answer retires with its CLOSE.
 */
#define	DAC_UID		65534
static int
h_dac(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{
	struct dq_ident_file id;
	struct dq_policy pol;
	uint64_t oid;
	uint32_t mf;

	if (rb->drs_op != DQ_ROP_OPEN || strstr(path, "/dac") == NULL)
		return (0);
	srv_ident(s, "a", path, &id);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	mf = 0;
	if (strstr(path, "/dac1") != NULL) {
		id.di_uid = 0;
		id.di_mode = S_IFREG | 0600;
	} else if (strstr(path, "/dac2") != NULL) {
		id.di_uid = DAC_UID;
		id.di_mode = S_IFREG | 0644;
		id.di_flags = UF_APPEND;
		pol.dp_write = DQ_EVENT;
		mf = DQ_MINT_F_WRITE;
	} else {
		id.di_uid = DAC_UID;
		id.di_mode = S_IFREG | 0444;
	}
	(void)dq_reply_resolve_fd(s->q, ev->de_id, DQ_KIND_FILE, mf, &id, &pol,
	    &oid, NULL);
	return (1);
}

static void
c_dac(struct srv *s, int *r)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/dac1", s->prefix);
	fd = open(path, O_RDONLY);
	r[0] = fd < 0 ? errno : 0;
	snprintf(path, sizeof(path), "%s/dac2", s->prefix);
	fd = open(path, O_WRONLY);
	r[1] = fd < 0 ? errno : 0;
	snprintf(path, sizeof(path), "%s/dac3", s->prefix);
	fd = open(path, O_RDONLY | O_TRUNC);
	r[2] = fd < 0 ? errno : 0;
}

ATF_TC(dac_nonroot);
ATF_TC_HEAD(dac_nonroot, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dac_nonroot, tc)
{
	struct srv s;
	struct dq_stats2 st;
	int r[RES_MAX];

	srv_start(&s, 0);
	ATF_REQUIRE(chmod(".", 0755) == 0);
	s.hook = h_dac;
	run_child_as(&s, c_dac, r, DAC_UID, true);
	ATF_CHECK_EQ(EACCES, r[0]);
	ATF_CHECK_EQ(EPERM, r[1]);
	ATF_CHECK_EQ(EACCES, r[2]);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stats(&s, &st);
	ATF_CHECK_EQ(3, st.ds2_resolve_retired);
	pthread_mutex_lock(&s.mtx);
	ATF_CHECK_EQ(3, s.closes);
	pthread_mutex_unlock(&s.mtx);
	srv_stop(&s);
}

/* ENOTCAPABLE on an unrestricted event: EIO to the requester, counted. */
static int
h_notcap(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path)
{

	if (rb->drs_op != DQ_ROP_STAT || strstr(path, "/a") == NULL)
		return (0);
	s->hook_errno = dq_reply_resolve_errno(s->q, ev->de_id,
	    ENOTCAPABLE) == 0 ? 0 : errno;
	return (1);
}

ATF_TC_WITHOUT_HEAD(enotcapable_unrestricted);
ATF_TC_BODY(enotcapable_unrestricted, tc)
{
	struct srv s;
	struct dq_stats2 st;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_notcap;
	run_child(&s, c_stat_one, r);
	ATF_CHECK_EQ(0, s.hook_errno);
	ATF_CHECK_EQ(EIO, r[0]);
	srv_stats(&s, &st);
	ATF_CHECK(st.ds2_bad_replies >= 1);
	srv_stop(&s);
}

/*
 * Truncation through FD past RLIMIT_FSIZE: OK is withheld; the kernel
 * raises SIGXFSZ and answers EFBIG.  O_RDONLY | O_TRUNC truncates (the
 * kernel's fo_truncate after D166).
 */
static volatile sig_atomic_t xfsz;

static void
on_xfsz(int sig __unused)
{

	xfsz++;
}

static void
c_trunc(struct srv *s, int *r)
{
	struct rlimit rl;
	char path[PATH_MAX];
	int fd;

	signal(SIGXFSZ, on_xfsz);
	rl.rlim_cur = rl.rlim_max = 4;
	(void)setrlimit(RLIMIT_FSIZE, &rl);
	snprintf(path, sizeof(path), "%s/a", s->prefix);
	r[0] = ERR(truncate(path, 100));
	r[1] = xfsz;
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	(void)setrlimit(RLIMIT_FSIZE, &rl);
	fd = open(path, O_RDONLY | O_TRUNC);
	r[2] = fd < 0 ? errno : 0;
	if (fd >= 0)
		close(fd);
}

ATF_TC_WITHOUT_HEAD(truncate_rlimit_otrunc);
ATF_TC_BODY(truncate_rlimit_otrunc, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_trunc, r);
	ATF_CHECK_EQ(EFBIG, r[0]);
	ATF_CHECK_EQ(1, r[1]);
	i = srv_find(&s, DQ_ROP_TRUNCATE, "/a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS) | DQ_RACCEPT(DQ_RESOLVE_FD) |
	    DQ_RACCEPT(DQ_RESOLVE_REAL), s.seen[i].accept);
	ATF_CHECK_EQ(0, r[2]);
	ATF_CHECK(stat("backing/a", &st) == 0 && st.st_size == 0);
	ATF_CHECK_EQ(0, srv_wait_live(&s, 0));
	srv_stop(&s);
}

/*
 * Review items 3 and 4: chflags with a word wider than 32 bits goes
 * through FD (EOPNOTSUPP, OK withheld); a tree without DQ_TREE_F_WRITE
 * answers every mutation EROFS; AT_RENAME_NOREPLACE is honoured; utimes
 * with NULL times posts the _NOW flags.
 */
static void
c_items34(struct srv *s, int *r)
{
	char a[PATH_MAX], b[PATH_MAX];
	int fd;

	snprintf(a, sizeof(a), "%s/a", s->prefix);
	r[0] = ERR(chflags(a, 1UL << 40));
	r[1] = ERR(utimes(a, NULL));
	snprintf(b, sizeof(b), "%s/m", s->prefix);
	r[2] = ERR(mkdir(b, 0755));
	r[3] = ERR(unlink(a));
	fd = open(a, O_WRONLY);
	r[4] = fd < 0 ? errno : 0;
	snprintf(b, sizeof(b), "%s/l", s->prefix);
	r[5] = ERR(renameat2(AT_FDCWD, a, AT_FDCWD, b, AT_RENAME_NOREPLACE));
}

ATF_TC_WITHOUT_HEAD(chflags_readonly_tree);
ATF_TC_BODY(chflags_readonly_tree, tc)
{
	struct srv s;
	int r[RES_MAX], i;
	bool now;

	srv_start(&s, 0);
	run_child(&s, c_items34, r);
	ATF_CHECK_EQ(EROFS, r[0]);	/* read-only tree; see rename_noreplace */
	ATF_CHECK_EQ(EROFS, r[1]);
	ATF_CHECK_EQ(EROFS, r[2]);
	ATF_CHECK_EQ(EROFS, r[3]);
	ATF_CHECK_EQ(EROFS, r[4]);
	ATF_CHECK_EQ(EROFS, r[5]);
	now = false;
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nseen; i++) {
		if (s.seen[i].op == DQ_ROP_SETATTR && s.seen[i].has_setattr &&
		    s.seen[i].sb.dsa_mask == (DQ_SETATTR_ATIME |
		    DQ_SETATTR_MTIME | DQ_SETATTR_ATIME_NOW |
		    DQ_SETATTR_MTIME_NOW | DQ_SETATTR_F_UTIMES_NULL))
			now = true;
		if (s.seen[i].op == DQ_ROP_SETATTR && s.seen[i].has_setattr &&
		    s.seen[i].sb.dsa_mask == 0)
			ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_PASS) |
			    DQ_RACCEPT(DQ_RESOLVE_FD) |
			    DQ_RACCEPT(DQ_RESOLVE_REAL), s.seen[i].accept);
	}
	pthread_mutex_unlock(&s.mtx);
	ATF_CHECK(now);
	srv_stop(&s);
}

static void
c_noreplace(struct srv *s, int *r)
{
	char a[PATH_MAX], b[PATH_MAX];

	snprintf(a, sizeof(a), "%s/a", s->prefix);
	snprintf(b, sizeof(b), "%s/l", s->prefix);
	r[0] = ERR(renameat2(AT_FDCWD, a, AT_FDCWD, b, AT_RENAME_NOREPLACE));
	/* A flags word wider than 32 bits: FD, the file's EOPNOTSUPP. */
	r[1] = ERR(chflags(a, 1UL << 40));
}

ATF_TC_WITHOUT_HEAD(rename_noreplace);
ATF_TC_BODY(rename_noreplace, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX];

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_noreplace, r);
	ATF_CHECK_EQ(EEXIST, r[0]);
	ATF_CHECK(lstat("backing/a", &st) == 0);
	ATF_CHECK_EQ(EOPNOTSUPP, r[1]);
	srv_stop(&s);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, open_fd);
	ATF_TP_ADD_TC(tp, open_create);
	ATF_TP_ADD_TC(tp, stat_attr);
	ATF_TP_ADD_TC(tp, mutate_ok);
	ATF_TP_ADD_TC(tp, accept_set);
	ATF_TP_ADD_TC(tp, reply_refusals);
	ATF_TP_ADD_TC(tp, post_reply_emfile);
	ATF_TP_ADD_TC(tp, post_reply_enfile);
	ATF_TP_ADD_TC(tp, post_reply_enfile_inject);
	ATF_TP_ADD_TC(tp, dropped_completion_eio);
	ATF_TP_ADD_TC(tp, vm_create_enomem);
	ATF_TP_ADD_TC(tp, opath_exlock_xfer);
	ATF_TP_ADD_TC(tp, opath_as_vnode);
	ATF_TP_ADD_TC(tp, served_fexecve_aio_fsync);
	ATF_TP_ADD_TC(tp, opath_linux);
	ATF_TP_ADD_TC(tp, emptypath_fallbacks);
	ATF_TP_ADD_TC(tp, emptypath_attached);
	ATF_TP_ADD_TC(tp, object_reply_not_mint);
	ATF_TP_ADD_TC(tp, revoke_before_bind);
	ATF_TP_ADD_TC(tp, queue_close_held_answer);
	ATF_TP_ADD_TC(tp, link_enospc_enxio);
	ATF_TP_ADD_TC(tp, dac_nonroot);
	ATF_TP_ADD_TC(tp, enotcapable_unrestricted);
	ATF_TP_ADD_TC(tp, truncate_rlimit_otrunc);
	ATF_TP_ADD_TC(tp, chflags_readonly_tree);
	ATF_TP_ADD_TC(tp, rename_noreplace);
	return (atf_no_error());
}
