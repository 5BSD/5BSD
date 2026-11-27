/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-b: served directories and served starts
 * (D162-D172).  The controller (a thread of the test) serves a backing
 * tree with dq_serve_tree()'s iii-b mode and mints its root as a served
 * directory; an attached child inherits that descriptor and uses it as a
 * lookup start.  A hook answers by hand where a row needs a particular
 * reply.  The real backing tree is the oracle.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#include "dqt.h"

/* Every case is root (a controller of /dev/dq) and bounded in time. */
#define	DQ_TC_HEAD_BODY(name)						\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "120");		\
	}
#define	DQ_TC(name)	ATF_TC(name); DQ_TC_HEAD_BODY(name)
#define	DQ_TC_CLEANUP(name)	ATF_TC_WITH_CLEANUP(name); DQ_TC_HEAD_BODY(name)

#define	SEEN_MAX	256
#define	RES_MAX		32

struct srv;
/* A hook returns 1 when it answered the event itself. */
typedef int (*srv_hook_t)(struct srv *, const struct dq_event *,
    const struct dq_resolve_body *, const char *path, const void *body,
    size_t bodylen);

struct srv {
	int		 q;
	struct dqt_server server;	/* the controller thread */
	pthread_mutex_t	 mtx;
	int		 rootfd;		/* the backing tree */
	char		 backing[PATH_MAX];
	char		 prefix[PATH_MAX];	/* its real-namespace name */
	struct dq_tree	*tree;
	int		 sroot;			/* the served root (minted) */
	uint64_t	 sroot_id;
	srv_hook_t	 hook;
	int		 hook_state;
	int		 hook_err[4];
	struct {
		uint32_t op, accept, rflags, start_kind, mode;
		uint64_t start, start2, object;
		char	 path[128];
	}		 seen[SEEN_MAX];
	int		 nseen;
	unsigned	 readdirs;
};

static int
srv_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct srv *s = arg;
	const struct dq_resolve_body *rb;
	const char *path;

	(void)q;
	path = NULL;
	rb = NULL;
	if (ev->de_op == DQ_OP_READDIR) {
		pthread_mutex_lock(&s->mtx);
		s->readdirs++;
		pthread_mutex_unlock(&s->mtx);
	}
	if (ev->de_op == DQ_OP_RESOLVE &&
	    dq_event_resolve_ext(ev, &rb, &path, NULL, NULL, NULL, NULL) == 0) {
		pthread_mutex_lock(&s->mtx);
		if (s->nseen < SEEN_MAX) {
			s->seen[s->nseen].op = rb->drs_op;
			s->seen[s->nseen].accept = rb->drs_accept;
			s->seen[s->nseen].rflags = rb->drs_rflags;
			s->seen[s->nseen].start_kind = rb->drs_start_kind;
			s->seen[s->nseen].start = rb->drs_start;
			s->seen[s->nseen].start2 = rb->drs_start2;
			s->seen[s->nseen].object = rb->drs_object;
			s->seen[s->nseen].mode = rb->drs_mode;
			strlcpy(s->seen[s->nseen].path, path,
			    sizeof(s->seen[0].path));
			s->nseen++;
		}
		pthread_mutex_unlock(&s->mtx);
	}
	if (s->hook != NULL && s->hook(s, ev, rb, path, body, bodylen))
		return (0);
	(void)dq_serve_tree(s->tree, ev, body, bodylen);
	return (0);
}

/*
 * A backing tree with a file "a" ("served\n"), a directory "d" holding
 * "f", a symlink "l" -> "a", and a FIFO "p"; served at prefix (a name
 * that does not exist) in iii-b mode, its root minted.
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
	fd = open("backing/d/f", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	(void)symlink("a", "backing/l");
	(void)mkfifo("backing/p", 0644);
	s->rootfd = open(s->backing, O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(s->rootfd >= 0);
	s->q = dqt_open_queue();
	s->tree = dq_tree_create(s->q, s->rootfd, s->prefix,
	    DQ_TREE_F_SERVED | flags);
	ATF_REQUIRE(s->tree != NULL);
	ATF_REQUIRE_MSG(dq_tree_root(s->tree, &s->sroot, &s->sroot_id) == 0,
	    "dq_tree_root: %s", strerror(errno));
	dqt_server_start(&s->server, s->q, srv_handler, s);
}

static void
srv_stop(struct srv *s)
{
	int error;

	error = dqt_server_stop(&s->server);
	ATF_CHECK_EQ_MSG(0, error, "controller thread: %s", strerror(error));
	close(s->sroot);
	dq_tree_destroy(s->tree);
	close(s->q);
	close(s->rootfd);
}

/* The last RESOLVE of op whose path ends in tail (NULL: any), or -1. */
static int
srv_find(struct srv *s, uint32_t op, const char *tail)
{
	size_t tl, pl;
	int i;

	tl = tail != NULL ? strlen(tail) : 0;
	pthread_mutex_lock(&s->mtx);
	for (i = s->nseen - 1; i >= 0; i--) {
		pl = strlen(s->seen[i].path);
		if (s->seen[i].op == op && (tail == NULL ||
		    (pl >= tl && strcmp(s->seen[i].path + pl - tl, tail) == 0)))
			break;
	}
	pthread_mutex_unlock(&s->mtx);
	return (i);
}

/* The last RESOLVE of op with exactly this path, or -1. */
static int
srv_find_exact(struct srv *s, uint32_t op, const char *path)
{
	int i;

	pthread_mutex_lock(&s->mtx);
	for (i = s->nseen - 1; i >= 0; i--)
		if (s->seen[i].op == op && strcmp(s->seen[i].path, path) == 0)
			break;
	pthread_mutex_unlock(&s->mtx);
	return (i);
}

static int
srv_count(struct srv *s, uint32_t op)
{
	int i, n;

	n = 0;
	pthread_mutex_lock(&s->mtx);
	for (i = 0; i < s->nseen; i++)
		if (s->seen[i].op == op)
			n++;
	pthread_mutex_unlock(&s->mtx);
	return (n);
}

static void
srv_stats(struct srv *s, struct dq_stats2 *st)
{

	memset(st, 0, sizeof(*st));
	ATF_REQUIRE(dq_get_stats2(s->q, st) == 0);
}

typedef void (*child_fn_t)(struct srv *, int *res);

struct run_arg {
	struct srv	*s;
	child_fn_t	 fn;
};

static void
run_fn(void *arg, int *res)
{
	struct run_arg *ra = arg;

	ra->fn(ra->s, res);
}

/* Run fn in a child (attached unless told not to); int results back. */
static void
run_child_as(struct srv *s, child_fn_t fn, int *res, bool attach)
{
	struct run_arg ra = { s, fn };

	dqt_run_ints(s->q, run_fn, &ra, res, RES_MAX, (uid_t)-1, attach);
}

static void
run_child(struct srv *s, child_fn_t fn, int *res)
{

	run_child_as(s, fn, res, true);
}

/*
 * An errno check that names the value it got (strerror_r: strerror's
 * buffer would be shared by both strings).
 */
#define	CHECK_ERRNO(exp, got) do {					\
	int e_ = (exp), g_ = (got);					\
	char eb_[64], gb_[64];						\
									\
	(void)strerror_r(e_, eb_, sizeof(eb_));				\
	(void)strerror_r(g_, gb_, sizeof(gb_));				\
	ATF_CHECK_EQ_MSG(e_, g_, "%s: expected %d (%s), got %d (%s)",	\
	    #got, e_, eb_, g_, gb_);					\
} while (0)

/*
 * Drain an observer: the records of op, and the RESOLVE replies whose
 * answer (the first word of the reply data) is kind.
 */
struct obs_count {
	uint32_t	 op, kind;
	int		 nop, nkind;
};

static void
obs_event(const struct dq_event *ev, void *arg)
{
	struct obs_count *oc = arg;
	const struct dq_reply_record *rr;
	const void *data;
	size_t len;

	if (ev->de_op == oc->op)
		oc->nop++;
	if (ev->de_op == DQ_OP_REPLY &&
	    dq_event_reply_record(ev, &rr, &data, &len) == 0 &&
	    data != NULL && len >= sizeof(struct dq_resolve_reply) &&
	    ((const struct dq_resolve_reply *)data)->drr_kind == oc->kind)
		oc->nkind++;
}

/* Until the observer has been quiet for 200 ms. */
static void
obs_drain(int obs, uint32_t op, int *nop, uint32_t kind, int *nkind)
{
	struct obs_count oc = { op, kind, 0, 0 };
	int error;

	error = dqt_serve_until(obs, -1, NULL, obs_event, &oc, 200);
	ATF_REQUIRE_MSG(error == ETIMEDOUT, "observer: %s", strerror(error));
	*nop = oc.nop;
	*nkind = oc.nkind;
}

/* A directory's entries as "name:type" lines, sorted. */
static int
cmpname(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

static void
listing_of(int d, char *out, size_t outlen)
{
	char buf[4096], *names[128], *p;
	struct dirent *dp;
	off_t base;
	ssize_t n;
	int i, k;

	k = 0;
	out[0] = '\0';
	if (lseek(d, 0, SEEK_SET) != 0)
		return;
	while ((n = getdirentries(d, buf, sizeof(buf), &base)) > 0)
		for (p = buf; p < buf + n; p += dp->d_reclen) {
			dp = (struct dirent *)(void *)p;
			if (k < 128)
				(void)asprintf(&names[k++], "%s:%u",
				    dp->d_name, dp->d_type);
		}
	qsort(names, k, sizeof(names[0]), cmpname);
	for (i = 0; i < k; i++) {
		strlcat(out, names[i], outlen);
		strlcat(out, "\n", outlen);
		free(names[i]);
	}
}

/*
 * Every *at call from the served root: the results match the backing
 * tree, each lookup is posted with start SERVED (drs_start = the root),
 * PASS is never in the accept set, and both paths of a rename starting
 * served are one event with both starts.
 */
static void
c_dirfd_ops(struct srv *s, int *r)
{
	struct stat st;
	char buf[64];
	int fd, d;

	r[0] = DQT_ERRNO_OF(fstatat(s->sroot, "a", &st, 0));
	r[1] = (int)st.st_size;
	fd = openat(s->sroot, "a", O_RDONLY);
	r[2] = DQT_ERRNO_OF(fd);
	r[3] = fd >= 0 ? (int)read(fd, buf, sizeof(buf)) : -1;
	r[4] = fd >= 0 && r[3] == 7 && memcmp(buf, "served\n", 7) == 0;
	if (fd >= 0)
		close(fd);
	memset(buf, 0, sizeof(buf));
	r[5] = (int)readlinkat(s->sroot, "l", buf, sizeof(buf));
	r[6] = strcmp(buf, "a") == 0;
	r[7] = DQT_ERRNO_OF(faccessat(s->sroot, "a", R_OK, 0));
	r[8] = DQT_ERRNO_OF(mkdirat(s->sroot, "nd", 0755));
	r[9] = DQT_ERRNO_OF(renameat(s->sroot, "nd", s->sroot, "nd2"));
	r[10] = DQT_ERRNO_OF(unlinkat(s->sroot, "nd2", AT_REMOVEDIR));
	r[11] = DQT_ERRNO_OF(symlinkat("a", s->sroot, "nl"));
	r[12] = DQT_ERRNO_OF(unlinkat(s->sroot, "nl", 0));
	/* A served subdirectory is a start too; ".." stays in the tree. */
	d = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	r[13] = DQT_ERRNO_OF(d);
	if (d >= 0) {
		r[14] = DQT_ERRNO_OF(fstat(d, &st));
		r[15] = S_ISDIR(st.st_mode);
		r[16] = DQT_ERRNO_OF(fstatat(d, "f", &st, 0));
		r[17] = DQT_ERRNO_OF(fstatat(d, "../a", &st, 0));
		r[18] = (int)st.st_size;
		close(d);
	}
	r[19] = DQT_ERRNO_OF(fstatat(s->sroot, "missing", &st, 0));
	r[20] = DQT_ERRNO_OF(fchmodat(s->sroot, "a", 0640, 0));
}

DQ_TC(dirfd_ops);
ATF_TC_BODY(dirfd_ops, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_dirfd_ops, r);
	CHECK_ERRNO(0, r[0]);
	ATF_CHECK_EQ(7, r[1]);
	CHECK_ERRNO(0, r[2]);
	ATF_CHECK_EQ(1, r[4]);
	ATF_CHECK_EQ(1, r[5]);
	ATF_CHECK_EQ(1, r[6]);
	CHECK_ERRNO(0, r[7]);
	CHECK_ERRNO(0, r[8]);
	CHECK_ERRNO(0, r[9]);
	CHECK_ERRNO(0, r[10]);
	CHECK_ERRNO(0, r[11]);
	CHECK_ERRNO(0, r[12]);
	CHECK_ERRNO(0, r[13]);
	CHECK_ERRNO(0, r[14]);
	ATF_CHECK_EQ(1, r[15]);
	CHECK_ERRNO(0, r[16]);
	CHECK_ERRNO(0, r[17]);
	ATF_CHECK_EQ(7, r[18]);
	CHECK_ERRNO(ENOENT, r[19]);
	CHECK_ERRNO(0, r[20]);
	/* The oracle: the backing tree saw the mutations. */
	ATF_CHECK(fstatat(s.rootfd, "nd2", &st, 0) != 0 && errno == ENOENT);
	ATF_CHECK(fstatat(s.rootfd, "a", &st, 0) == 0 &&
	    (st.st_mode & ALLPERMS) == 0640);
	/* Posted from the served root, never PASS. */
	/*
	 * The root's own lookup (exactly "a": a tail match would find
	 * "../a", which the nested served directory d started, run 43).
	 */
	i = srv_find_exact(&s, DQ_ROP_STAT, "a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(DQ_START_SERVED, s.seen[i].start_kind);
	ATF_CHECK_EQ_MSG(s.sroot_id, s.seen[i].start,
	    "op %u path %s: drs_start %ju", s.seen[i].op, s.seen[i].path,
	    (uintmax_t)s.seen[i].start);
	/* "../a" from d starts at d: served, another object than the root. */
	i = srv_find_exact(&s, DQ_ROP_STAT, "../a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(DQ_START_SERVED, s.seen[i].start_kind);
	ATF_CHECK_MSG(s.seen[i].start != 0 && s.seen[i].start != s.sroot_id,
	    "op %u path %s: drs_start %ju", s.seen[i].op, s.seen[i].path,
	    (uintmax_t)s.seen[i].start);
	for (i = 0; i < s.nseen; i++)
		if (s.seen[i].start_kind == DQ_START_SERVED)
			ATF_CHECK_MSG((s.seen[i].accept &
			    DQ_RACCEPT(DQ_RESOLVE_PASS)) == 0,
			    "op %u path %s: PASS offered", s.seen[i].op,
			    s.seen[i].path);
	i = srv_find(&s, DQ_ROP_RENAME, "nd");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(s.sroot_id, s.seen[i].start);
	ATF_CHECK_EQ(s.sroot_id, s.seen[i].start2);
	ATF_CHECK_EQ(1, srv_count(&s, DQ_ROP_RENAME));
	srv_stop(&s);
}

/*
 * PASS to a served start is EINVAL to the controller and the event stays
 * in flight; the next answer (ENOENT) completes it.
 */
static int
h_pass(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{

	(void)body; (void)bodylen;
	if (rb == NULL || strcmp(path, "pass") != 0)
		return (0);
	s->hook_err[0] = dq_reply_resolve_pass(s->q, ev->de_id) == 0 ? 0 :
	    errno;
	s->hook_err[1] = dq_reply_resolve_errno(s->q, ev->de_id, ENOENT) ==
	    0 ? 0 : errno;
	return (1);
}

static void
c_pass(struct srv *s, int *r)
{
	struct stat st;

	r[0] = DQT_ERRNO_OF(fstatat(s->sroot, "pass", &st, 0));
}

DQ_TC(pass_refused);
ATF_TC_BODY(pass_refused, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_pass;
	run_child(&s, c_pass, r);
	CHECK_ERRNO(ENOENT, r[0]);
	CHECK_ERRNO(EINVAL, s.hook_err[0]);
	CHECK_ERRNO(0, s.hook_err[1]);
	srv_stop(&s);
}

/*
 * REAL (D167): the name continues as the real path; a REAL answered to
 * every re-consultation of a self-referencing symlink ends in ELOOP; a
 * REAL to a restricted lookup (O_RESOLVE_BENEATH) is EINVAL to the
 * controller (not in the accept set).
 */
static int
h_real(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	char real[PATH_MAX];

	(void)body; (void)bodylen;
	if (rb == NULL)
		return (0);
	if (strcmp(path, "realfile") == 0) {
		snprintf(real, sizeof(real), "%s/a", s->backing);
		s->hook_err[0] = dq_reply_resolve_real(s->q, ev->de_id,
		    real) == 0 ? 0 : errno;
		return (1);
	}
	if (strstr(path, "loop") != NULL) {
		snprintf(real, sizeof(real), "%s/loop", s->backing);
		s->hook_state++;
		(void)dq_reply_resolve_real(s->q, ev->de_id, real);
		return (1);
	}
	if (strcmp(path, "beneath") == 0) {
		snprintf(real, sizeof(real), "%s/a", s->backing);
		s->hook_err[1] = dq_reply_resolve_real(s->q, ev->de_id,
		    real) == 0 ? 0 : errno;
		(void)dq_reply_resolve_errno(s->q, ev->de_id, ENOENT);
		return (1);
	}
	return (0);
}

static void
c_real(struct srv *s, int *r)
{
	char buf[16];
	int fd;

	fd = openat(s->sroot, "realfile", O_RDONLY);
	r[0] = DQT_ERRNO_OF(fd);
	if (fd >= 0) {
		r[1] = (int)read(fd, buf, sizeof(buf));
		close(fd);
	}
	r[2] = DQT_ERRNO_OF(openat(s->sroot, "loop", O_RDONLY));
	r[3] = DQT_ERRNO_OF(openat(s->sroot, "beneath", O_RDONLY | O_RESOLVE_BENEATH));
}

DQ_TC(real_answer);
ATF_TC_BODY(real_answer, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	/* A real symlink to itself: every step re-consults (D172 (b)). */
	ATF_REQUIRE(symlink("loop", "backing/loop") == 0);
	s.hook = h_real;
	run_child(&s, c_real, r);
	CHECK_ERRNO(0, r[0]);
	ATF_CHECK_EQ(7, r[1]);
	CHECK_ERRNO(ELOOP, r[2]);
	/* MAXSYMLINKS counts symlinks and REAL rewrites together. */
	ATF_CHECK(s.hook_state > 1 && s.hook_state <= MAXSYMLINKS);
	CHECK_ERRNO(0, s.hook_err[0]);
	CHECK_ERRNO(EINVAL, s.hook_err[1]);
	CHECK_ERRNO(ENOENT, r[3]);
	srv_stop(&s);
}

/*
 * Who may start at a served directory (D162, D163): a served file as a
 * dirfd is ENOTDIR and an unattached process, or the controller, gets
 * EACCES (D184; EDEADLK is for a process attached to another queue), all
 * with no event; a revoked directory is EIO.
 */
static void
c_starts(struct srv *s, int *r)
{
	struct stat st;
	int fd;

	fd = openat(s->sroot, "a", O_RDONLY);
	r[0] = DQT_ERRNO_OF(fd);
	r[1] = DQT_ERRNO_OF(fstatat(fd, "x", &st, 0));
}

static void
c_stat_root(struct srv *s, int *r)
{
	struct stat st;

	r[0] = DQT_ERRNO_OF(fstatat(s->sroot, "a", &st, 0));
}

DQ_TC(start_rules);
ATF_TC_BODY(start_rules, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX], n;

	srv_start(&s, 0);
	run_child(&s, c_starts, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(ENOTDIR, r[1]);
	n = s.nseen;
	run_child_as(&s, c_stat_root, r, false);
	CHECK_ERRNO(EACCES, r[0]);
	ATF_CHECK(fstatat(s.sroot, "a", &st, 0) != 0 && errno == EACCES);
	ATF_CHECK_EQ(n, s.nseen);
	ATF_REQUIRE(dq_revoke(s.q, s.sroot_id) == 0);
	run_child(&s, c_stat_root, r);
	CHECK_ERRNO(EIO, r[0]);
	ATF_CHECK_EQ(n, s.nseen);
	srv_stop(&s);
}

/*
 * Two-path operations (D170): a served and a real start are EXDEV with no
 * event (ds2_resolve_exdev counts them); fhlink into a served directory
 * too.  funlinkat's descriptor: a served one names the object
 * (drs_object), with a real path EDEADLK; a real one with a served path
 * EDEADLK.
 */
static void
c_two_path(struct srv *s, int *r)
{
	char real[PATH_MAX];
	fhandle_t fh;
	int fd, rfd;

	snprintf(real, sizeof(real), "%s/../realx", s->backing);
	r[0] = DQT_ERRNO_OF(renameat(s->sroot, "a", AT_FDCWD, real));
	r[1] = DQT_ERRNO_OF(linkat(AT_FDCWD, real, s->sroot, "b", 0));
	rfd = open(real, O_CREAT | O_RDWR, 0644);
	r[2] = DQT_ERRNO_OF(rfd);
	r[3] = DQT_ERRNO_OF(getfh(real, &fh));
	r[4] = DQT_ERRNO_OF(fhlinkat(&fh, s->sroot, "fhl"));
	fd = openat(s->sroot, "d/f", O_RDONLY);
	r[5] = DQT_ERRNO_OF(fd);
	r[6] = DQT_ERRNO_OF(funlinkat(AT_FDCWD, real, fd, 0));
	r[7] = DQT_ERRNO_OF(funlinkat(s->sroot, "a", rfd, 0));
	r[8] = DQT_ERRNO_OF(funlinkat(s->sroot, "d/f", fd, 0));
}

DQ_TC(two_path);
ATF_TC_BODY(two_path, tc)
{
	struct srv s;
	struct dq_stats2 st;
	struct stat sb;
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_two_path, r);
	CHECK_ERRNO(EXDEV, r[0]);
	CHECK_ERRNO(EXDEV, r[1]);
	CHECK_ERRNO(0, r[2]);
	CHECK_ERRNO(EXDEV, r[4]);
	CHECK_ERRNO(0, r[5]);
	CHECK_ERRNO(EDEADLK, r[6]);
	CHECK_ERRNO(EDEADLK, r[7]);
	CHECK_ERRNO(0, r[8]);
	ATF_CHECK_EQ(-1, srv_find(&s, DQ_ROP_RENAME, NULL));
	srv_stats(&s, &st);
	ATF_CHECK(st.ds2_resolve_exdev >= 3);
	i = srv_find(&s, DQ_ROP_UNLINK, "d/f");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK(s.seen[i].object != 0);
	ATF_CHECK(fstatat(s.rootfd, "d/f", &sb, 0) != 0 && errno == ENOENT);
	srv_stop(&s);
}

/*
 * B2 (D165): under O_RESOLVE_BENEATH an absolute path and a leading ".."
 * (also after "." and empty components) are refused ENOTCAPABLE with no
 * event; "d/../a" is posted and its in-tree answer accepted; an answer
 * whose presented path is outside the start ("/prefix" + "x" without a
 * separator) is ENOTCAPABLE by the post-check, and the object retires.
 */
static int
h_i8(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	struct dq_ident_file *id;
	struct stat st;
	struct statfs sf;
	char name[PATH_MAX];

	(void)body; (void)bodylen;
	if (rb == NULL || strcmp(path, "d/outside") != 0)
		return (0);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(fstatat(s->rootfd, "a", &st, 0) == 0);
	ATF_REQUIRE(fstatfs(s->rootfd, &sf) == 0);
	strlcpy(sf.f_mntonname, "/", sizeof(sf.f_mntonname));
	/* A sibling whose name extends the root's without a '/'. */
	snprintf(name, sizeof(name), "%sx", s->prefix);
	ATF_REQUIRE(dq_ident_from_stat(id, name, &st, &sf, -1) == 0);
	s->hook_err[0] = dq_reply_resolve_attr(s->q, ev->de_id, id) == 0 ?
	    0 : errno;
	free(id);
	return (1);
}

static void
c_i8(struct srv *s, int *r)
{
	struct stat st;

	r[0] = DQT_ERRNO_OF(fstatat(s->sroot, "../a", &st, AT_RESOLVE_BENEATH));
	r[1] = DQT_ERRNO_OF(fstatat(s->sroot, "./../a", &st, AT_RESOLVE_BENEATH));
	r[2] = DQT_ERRNO_OF(fstatat(s->sroot, ".//../a", &st, AT_RESOLVE_BENEATH));
	r[3] = DQT_ERRNO_OF(fstatat(s->sroot, "/etc", &st, AT_RESOLVE_BENEATH));
	r[4] = DQT_ERRNO_OF(fstatat(s->sroot, "d/../a", &st, AT_RESOLVE_BENEATH));
	r[5] = (int)st.st_size;
	r[6] = DQT_ERRNO_OF(fstatat(s->sroot, "d/outside", &st, AT_RESOLVE_BENEATH));
}

DQ_TC(i8_beneath);
ATF_TC_BODY(i8_beneath, tc)
{
	struct srv s;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	s.hook = h_i8;
	run_child(&s, c_i8, r);
	CHECK_ERRNO(ENOTCAPABLE, r[0]);
	CHECK_ERRNO(ENOTCAPABLE, r[1]);
	CHECK_ERRNO(ENOTCAPABLE, r[2]);
	CHECK_ERRNO(ENOTCAPABLE, r[3]);
	CHECK_ERRNO(0, r[4]);
	ATF_CHECK_EQ(7, r[5]);
	CHECK_ERRNO(ENOTCAPABLE, r[6]);
	CHECK_ERRNO(0, s.hook_err[0]);
	/* No event for the pre-checked ones. */
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, "../a"));
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, "./../a"));
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, ".//../a"));
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, "/etc"));
	i = srv_find(&s, DQ_ROP_STAT, "d/../a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_BENEATH) != 0);
	ATF_CHECK((s.seen[i].accept & DQ_RACCEPT(DQ_RESOLVE_REAL)) == 0);
	srv_stop(&s);
}

/*
 * vfs.lookup_cap_dotdot=0 in capability mode: any ".." from a served
 * start is refused before posting (B2).  O_RESOLVE_BENEATH on the start
 * descriptor is inherited by a served FD answer, and the answer's rights
 * are the start's intersected with the policy's (D159).
 */
static void
c_capmode(struct srv *s, int *r)
{
	cap_rights_t rights, got;
	struct stat st;
	int fd, d;

	d = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(d);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATAT,
	    CAP_FCNTL);
	r[1] = DQT_ERRNO_OF(cap_rights_limit(s->sroot, &rights));
	r[2] = DQT_ERRNO_OF(fcntl(s->sroot, F_SETFD, FD_RESOLVE_BENEATH));
	fd = openat(s->sroot, "a", O_RDONLY);
	r[3] = DQT_ERRNO_OF(fd);
	if (fd >= 0) {
		r[4] = DQT_ERRNO_OF(cap_rights_get(fd, &got));
		r[5] = cap_rights_is_set(&got, CAP_READ);
		r[6] = cap_rights_is_set(&got, CAP_WRITE);
		r[7] = (fcntl(fd, F_GETFD) & FD_RESOLVE_BENEATH) != 0;
	}
	r[8] = DQT_ERRNO_OF(cap_enter());
	r[9] = DQT_ERRNO_OF(fstatat(d, "../a", &st, 0));
	/* Not leading: refused only because lookup_cap_dotdot is 0. */
	r[10] = DQT_ERRNO_OF(fstatat(s->sroot, "d/../a", &st, 0));
}

DQ_TC_CLEANUP(capmode_rights);
ATF_TC_BODY(capmode_rights, tc)
{
	struct srv s;
	int r[RES_MAX];

	dqt_sysctl_save_set_int("vfs.lookup_cap_dotdot", 0);
	srv_start(&s, 0);
	run_child(&s, c_capmode, r);
	ATF_REQUIRE(dqt_sysctl_restore("vfs.lookup_cap_dotdot"));
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(0, r[2]);
	CHECK_ERRNO(0, r[3]);
	CHECK_ERRNO(0, r[4]);
	ATF_CHECK_EQ(1, r[5]);
	CHECK_ERRNO(0, r[6]);
	ATF_CHECK_EQ(1, r[7]);
	CHECK_ERRNO(0, r[8]);
	CHECK_ERRNO(ENOTCAPABLE, r[9]);
	CHECK_ERRNO(ENOTCAPABLE, r[10]);
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, "../a"));
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, "d/../a"));
	srv_stop(&s);
}
ATF_TC_CLEANUP(capmode_rights, tc)
{

	(void)dqt_sysctl_restore("vfs.lookup_cap_dotdot");
}

/*
 * The install of an FD answer from a served start (D159): the lowest free
 * number, close-on-exec and close-on-fork only as the open asked, and the
 * rights, the fcntl limit and the ioctl list of the start descriptor
 * intersected with the policy's.  The ioctl list has three cases: a start
 * with a list, a start with an empty list, a start without CAP_IOCTL.
 */
static int
c_nioctls(int fd, cap_ioctl_t *first)
{
	cap_ioctl_t cmds[4];
	ssize_t n;

	cmds[0] = 0;
	n = cap_ioctls_get(fd, cmds, nitems(cmds));
	*first = cmds[0];
	return (n == CAP_IOCTLS_ALL ? -2 : (int)n);
}

static void
c_install_limits(struct srv *s, int *r)
{
	cap_rights_t rights, got;
	cap_ioctl_t cmd, first;
	uint32_t fcntls;
	int fd, lo;

	/* The start as minted. */
	lo = dup(s->sroot);
	(void)close(lo);
	fd = openat(s->sroot, "a", O_RDONLY);
	r[0] = fd == lo;
	r[1] = fcntl(fd, F_GETFD);
	(void)cap_rights_get(fd, &got);
	r[2] = cap_rights_is_set(&got, CAP_IOCTL);
	r[3] = c_nioctls(fd, &first);
	fcntls = 0;
	r[4] = DQT_ERRNO_OF(cap_fcntls_get(fd, &fcntls));
	r[5] = (int)fcntls;
	(void)close(fd);
	fd = openat(s->sroot, "a", O_RDONLY | O_CLOEXEC | O_CLOFORK);
	r[6] = fcntl(fd, F_GETFD);
	(void)close(fd);

	/* A start with an fcntl limit and a one-command ioctl list. */
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FCNTL,
	    CAP_IOCTL);
	r[7] = DQT_ERRNO_OF(cap_rights_limit(s->sroot, &rights));
	r[8] = DQT_ERRNO_OF(cap_fcntls_limit(s->sroot, CAP_FCNTL_GETFL));
	cmd = FIONREAD;
	r[9] = DQT_ERRNO_OF(cap_ioctls_limit(s->sroot, &cmd, 1));
	fd = openat(s->sroot, "a", O_RDONLY);
	r[10] = DQT_ERRNO_OF(fd);
	(void)cap_rights_get(fd, &got);
	r[11] = cap_rights_is_set(&got, CAP_READ);
	r[12] = cap_rights_is_set(&got, CAP_WRITE);
	r[13] = cap_rights_is_set(&got, CAP_IOCTL);
	r[14] = c_nioctls(fd, &first);
	r[15] = first == FIONREAD;
	fcntls = 0;
	(void)cap_fcntls_get(fd, &fcntls);
	r[16] = (int)fcntls;
	(void)close(fd);

	/* The start's list emptied. */
	r[17] = DQT_ERRNO_OF(cap_ioctls_limit(s->sroot, NULL, 0));
	fd = openat(s->sroot, "a", O_RDONLY);
	(void)cap_rights_get(fd, &got);
	r[18] = c_nioctls(fd, &first);
	r[19] = cap_rights_is_set(&got, CAP_IOCTL);
	(void)close(fd);

	/* A start with neither CAP_IOCTL nor CAP_FCNTL. */
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT);
	r[20] = DQT_ERRNO_OF(cap_rights_limit(s->sroot, &rights));
	fd = openat(s->sroot, "a", O_RDONLY);
	(void)cap_rights_get(fd, &got);
	r[21] = cap_rights_is_set(&got, CAP_IOCTL);
	r[22] = c_nioctls(fd, &first);
	r[23] = cap_rights_is_set(&got, CAP_FCNTL);
	fcntls = 0;
	r[24] = DQT_ERRNO_OF(cap_fcntls_get(fd, &fcntls));
	r[25] = (int)fcntls;
	(void)close(fd);
}

DQ_TC(fd_install_limits);
ATF_TC_BODY(fd_install_limits, tc)
{
	static const int want[26] = {
		[0] = 1, [1] = 0, [2] = 1, [3] = -2, [4] = 0,
		[5] = CAP_FCNTL_ALL, [6] = FD_CLOEXEC | FD_CLOFORK,
		[7] = 0, [8] = 0, [9] = 0, [10] = 0,
		[11] = 1, [12] = 0, [13] = 1, [14] = 1, [15] = 1,
		[16] = CAP_FCNTL_GETFL,
		[17] = 0, [18] = 0, [19] = 1,
		[20] = 0, [21] = 0, [22] = 0, [23] = 0, [24] = 0, [25] = 0,
	};
	struct srv s;
	int r[RES_MAX];
	u_int i;

	srv_start(&s, 0);
	run_child(&s, c_install_limits, r);
	for (i = 0; i < nitems(want); i++) {
		printf("r[%u] = %d\n", i, r[i]);
		ATF_CHECK_EQ_MSG(want[i], r[i], "r[%u] is %d, expected %d",
		    i, r[i], want[i]);
	}
	srv_stop(&s);
}

/*
 * A restricted lookup from a served start is not offered SWAP: the kernel
 * checks a served answer against the start's presented path (D165) and
 * has nothing to check a swapped real file against.  The unrestricted
 * open from the same start is offered it.
 */
static int
h_noswap(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	int fd, i;

	(void)body; (void)bodylen;
	if (rb == NULL || rb->drs_op != DQ_ROP_OPEN || strcmp(path, "a") != 0)
		return (0);
	i = s->hook_state++;
	if (i >= 3)
		return (0);
	s->hook_err[i] = dq_resolve_accepts(rb, DQ_RESOLVE_SWAP) ? 1 : 0;
	if (i > 0) {
		fd = openat(s->rootfd, "a", O_RDONLY | O_CLOEXEC | O_CLOFORK);
		ATF_REQUIRE(fd >= 0);
		errno = 0;
		if (dq_reply_resolve_swap(s->q, ev->de_id, fd, 0) == -1) {
			if (errno == EINVAL)
				s->hook_err[i] |= 2;
			(void)close(fd);	/* refused: still ours */
		}
	}
	return (0);		/* the tree answers the open */
}

static void
c_noswap(struct srv *s, int *r)
{
	char b[8];
	int fd;

	fd = openat(s->sroot, "a", O_RDONLY);
	r[0] = DQT_ERRNO_OF(fd);
	(void)close(fd);
	fd = openat(s->sroot, "a", O_RDONLY | O_RESOLVE_BENEATH);
	r[1] = DQT_ERRNO_OF(fd);
	(void)close(fd);
	r[2] = DQT_ERRNO_OF(cap_enter());
	fd = openat(s->sroot, "a", O_RDONLY);
	r[3] = DQT_ERRNO_OF(fd);
	r[4] = (int)read(fd, b, sizeof(b));
}

DQ_TC(restricted_no_swap);
ATF_TC_BODY(restricted_no_swap, tc)
{
	struct srv s;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	s.hook = h_noswap;
	run_child(&s, c_noswap, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(0, r[2]);
	CHECK_ERRNO(0, r[3]);
	ATF_CHECK_EQ(7, r[4]);
	ATF_CHECK_EQ(3, s.hook_state);
	/* Offered to the unrestricted open. */
	ATF_CHECK_EQ(1, s.hook_err[0]);
	/* Not offered, and refused as a reply, under BENEATH and STRICTREL. */
	ATF_CHECK_EQ(2, s.hook_err[1]);
	ATF_CHECK_EQ(2, s.hook_err[2]);
	i = srv_find_exact(&s, DQ_ROP_OPEN, "a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_STRICTREL) != 0);
	ATF_CHECK((s.seen[i].accept & DQ_RACCEPT(DQ_RESOLVE_FD)) != 0);
	srv_stop(&s);
}

/*
 * O_EMPTY_PATH on a served directory reopens it through the controller
 * (D164: OPEN, EMPTYPATH, start SERVED); AT_EMPTY_PATH calls stay the
 * descriptor's own (no event); /dev/fd/N/child stays ENOTDIR (D29).
 */
static void
c_emptypath(struct srv *s, int *r)
{
	char path[64];
	struct stat st;
	int fd;

	fd = openat(s->sroot, "", O_EMPTY_PATH | O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(fd);
	if (fd >= 0) {
		r[1] = DQT_ERRNO_OF(fstat(fd, &st));
		r[2] = S_ISDIR(st.st_mode);
	}
	r[3] = DQT_ERRNO_OF(fstatat(s->sroot, "", &st, AT_EMPTY_PATH));
	r[4] = S_ISDIR(st.st_mode);
	/*
	 * A plain fdescfs node of the descriptor is not a directory
	 * (fdesc_lookup: ENOTDIR below a non-root node), served or not.
	 * The devfs /dev/fd of a system without fdescfs has only 0-2, where
	 * a higher descriptor is ENOENT: the test mounts its own.
	 */
	snprintf(path, sizeof(path), "%s/%d/a", DQT_FDESC_DIR, s->sroot);
	r[5] = DQT_ERRNO_OF(stat(path, &st));
}

DQ_TC_CLEANUP(emptypath);
ATF_TC_BODY(emptypath, tc)
{
	struct srv s;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	dqt_mount_fdesc(NULL);
	run_child(&s, c_emptypath, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	ATF_CHECK_EQ(1, r[2]);
	CHECK_ERRNO(0, r[3]);
	ATF_CHECK_EQ(1, r[4]);
	CHECK_ERRNO(ENOTDIR, r[5]);
	i = srv_find_exact(&s, DQ_ROP_OPEN, "");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(s.sroot_id, s.seen[i].start);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_EMPTYPATH) != 0);
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_STAT, ""));
	srv_stop(&s);
}
ATF_TC_CLEANUP(emptypath, tc)
{

	dqt_umount_fdesc();
}

/*
 * Served symbolic links (D168): O_PATH | O_NOFOLLOW opens one (fstat
 * S_IFLNK, kinfo VLNK, readlinkat(fd, "") its target); O_NOFOLLOW alone
 * is EMLINK; lchmod is answered FD(SYMLINK) and goes through the
 * object-level setattr, as does fchmodat(fd, "", AT_EMPTY_PATH) of an
 * O_PATH served descriptor (a file's too, the iii-a carry-over), while
 * fchmod(2) of the O_PATH descriptor is still EBADF.
 */
static void
c_symlink(struct srv *s, int *r)
{
	struct kinfo_file kif;
	struct stat st;
	char buf[16];
	int fd, ffd;

	fd = openat(s->sroot, "l", O_PATH | O_NOFOLLOW);
	r[0] = DQT_ERRNO_OF(fd);
	if (fd < 0)
		return;
	r[1] = DQT_ERRNO_OF(fstat(fd, &st));
	r[2] = S_ISLNK(st.st_mode);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	r[3] = DQT_ERRNO_OF(fcntl(fd, F_KINFO, &kif));
	r[4] = kif.kf_un.kf_file.kf_file_type == KF_VTYPE_VLNK;
	memset(buf, 0, sizeof(buf));
	r[5] = (int)readlinkat(fd, "", buf, sizeof(buf));
	r[6] = strcmp(buf, "a") == 0;
	r[7] = DQT_ERRNO_OF(openat(s->sroot, "l", O_RDONLY | O_NOFOLLOW));
	r[8] = DQT_ERRNO_OF(fchmodat(s->sroot, "l", 0700, AT_SYMLINK_NOFOLLOW));
	r[9] = DQT_ERRNO_OF(fchmod(fd, 0600));
	r[10] = DQT_ERRNO_OF(fchmodat(fd, "", 0750, AT_EMPTY_PATH));
	ffd = openat(s->sroot, "a", O_PATH);
	r[11] = DQT_ERRNO_OF(ffd);
	r[12] = DQT_ERRNO_OF(fchmodat(ffd, "", 0604, AT_EMPTY_PATH));
	r[13] = DQT_ERRNO_OF(fchownat(ffd, "", (uid_t)-1, (gid_t)-1, AT_EMPTY_PATH));
	r[14] = DQT_ERRNO_OF(fchmod(ffd, 0600));
	/* kqueue on the O_PATH symlink: FKQALLOWED, as vn_open_vnode. */
	{
		struct kevent kev;
		int kq;

		kq = kqueue();
		EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_ATTRIB,
		    0, NULL);
		r[15] = DQT_ERRNO_OF(kevent(kq, &kev, 1, NULL, 0, NULL));
		close(kq);
	}
}

DQ_TC(symlink_opath);
ATF_TC_BODY(symlink_opath, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX];

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_symlink, r);
	ATF_REQUIRE_EQ(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	ATF_CHECK_EQ(1, r[2]);
	CHECK_ERRNO(0, r[3]);
	ATF_CHECK_EQ(1, r[4]);
	ATF_CHECK_EQ(1, r[5]);
	ATF_CHECK_EQ(1, r[6]);
	CHECK_ERRNO(EMLINK, r[7]);
	CHECK_ERRNO(0, r[8]);
	CHECK_ERRNO(EBADF, r[9]);
	CHECK_ERRNO(0, r[10]);
	CHECK_ERRNO(0, r[11]);
	CHECK_ERRNO(0, r[12]);
	CHECK_ERRNO(0, r[13]);
	CHECK_ERRNO(EBADF, r[14]);
	CHECK_ERRNO(0, r[15]);
	/* The oracle: the backing link and file took the modes. */
	ATF_CHECK(fstatat(s.rootfd, "l", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
	    (st.st_mode & ALLPERMS) == 0750);
	ATF_CHECK(fstatat(s.rootfd, "a", &st, 0) == 0 &&
	    (st.st_mode & ALLPERMS) == 0604);
	srv_stop(&s);
}

/*
 * Served directories (D168): getdirentries(2) through READDIR lists the
 * backing entries; a buffer smaller than a struct dirent is EINVAL with no
 * event; read(2) is EISDIR, mmap(2) EINVAL, SEEK_DATA EINVAL; kinfo says
 * VDIR; rewinding (lseek to 0, the first cookie) lists them again.
 */
static void
c_dir(struct srv *s, int *r)
{
	struct kinfo_file kif;
	char buf[4096], *p;
	struct dirent *dp;
	off_t base;
	ssize_t n;
	int seen, d;

	d = openat(s->sroot, ".", O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(d);
	if (d < 0)
		return;
	seen = 0;
	while ((n = getdirentries(d, buf, sizeof(buf), &base)) > 0) {
		for (p = buf; p < buf + n; p += dp->d_reclen) {
			dp = (struct dirent *)(void *)p;
			if (strcmp(dp->d_name, "a") == 0)
				seen |= 1;
			else if (strcmp(dp->d_name, "d") == 0 &&
			    dp->d_type == DT_DIR)
				seen |= 2;
			else if (strcmp(dp->d_name, "l") == 0 &&
			    dp->d_type == DT_LNK)
				seen |= 4;
			else if (strcmp(dp->d_name, "p") == 0)
				seen |= 8;
			if (dp->d_pad0 != 0 || dp->d_pad1 != 0)
				seen |= 64;
		}
	}
	r[1] = (int)n;
	r[2] = seen;
	r[3] = (int)getdirentries(d, buf, 16, &base) < 0 ? errno : 0;
	r[4] = read(d, buf, sizeof(buf)) < 0 ? errno : 0;
	r[5] = mmap(NULL, 4096, PROT_READ, MAP_SHARED, d, 0) == MAP_FAILED ?
	    errno : 0;
	r[6] = lseek(d, 0, SEEK_DATA) < 0 ? errno : 0;
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	r[7] = DQT_ERRNO_OF(fcntl(d, F_KINFO, &kif));
	r[8] = kif.kf_un.kf_file.kf_file_type == KF_VTYPE_VDIR;
	r[9] = (int)lseek(d, 0, SEEK_SET);
	r[10] = (int)getdirentries(d, buf, sizeof(buf), &base) > 0;
	r[11] = (int)base;
	r[12] = write(d, "x", 1) < 0 ? errno : 0;
	/* The whole listing equals the backing directory's (read real). */
	{
		char served[4096], real[4096];
		int bd;

		listing_of(d, served, sizeof(served));
		bd = open(s->backing, O_RDONLY | O_DIRECTORY);
		listing_of(bd, real, sizeof(real));
		close(bd);
		r[13] = served[0] != '\0' && strcmp(served, real) == 0;
	}
	/* A directory is not opened for writing (vn_open_vnode). */
	r[14] = DQT_ERRNO_OF(openat(s->sroot, ".", O_RDWR));
	/* kqueue on a served directory. */
	{
		struct kevent kev;
		int kq;

		kq = kqueue();
		EV_SET(&kev, d, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE,
		    0, NULL);
		r[15] = DQT_ERRNO_OF(kevent(kq, &kev, 1, NULL, 0, NULL));
		EV_SET(&kev, d, EVFILT_READ, EV_ADD, 0, 0, NULL);
		r[16] = DQT_ERRNO_OF(kevent(kq, &kev, 1, NULL, 0, NULL));
		close(kq);
	}
}

DQ_TC(readdir_oracle);
ATF_TC_BODY(readdir_oracle, tc)
{
	struct srv s;
	int r[RES_MAX], nrd, nreal, obs;
	unsigned before;

	srv_start(&s, 0);
	/* An observer sees every READDIR (with data). */
	obs = dq_mint_observer(s.q, DQ_OBS_F_DATA);
	ATF_REQUIRE(obs >= 0);
	run_child(&s, c_dir, r);
	ATF_REQUIRE_EQ(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	ATF_CHECK_EQ(15, r[2]);
	CHECK_ERRNO(EINVAL, r[3]);
	CHECK_ERRNO(EISDIR, r[4]);
	CHECK_ERRNO(EINVAL, r[5]);
	CHECK_ERRNO(EINVAL, r[6]);
	CHECK_ERRNO(0, r[7]);
	ATF_CHECK_EQ(1, r[8]);
	CHECK_ERRNO(0, r[9]);
	ATF_CHECK_EQ(1, r[10]);
	CHECK_ERRNO(0, r[11]);
	CHECK_ERRNO(EBADF, r[12]);
	ATF_CHECK_EQ(1, r[13]);
	CHECK_ERRNO(EISDIR, r[14]);
	CHECK_ERRNO(0, r[15]);
	CHECK_ERRNO(0, r[16]);
	before = s.readdirs;
	ATF_CHECK(before >= 3);
	obs_drain(obs, DQ_OP_READDIR, &nrd, DQ_RESOLVE_REAL, &nreal);
	ATF_CHECK_EQ((int)s.readdirs, nrd);
	close(obs);
	srv_stop(&s);
}

/*
 * Malformed READDIR replies (D168) are EINVAL to the controller and leave
 * the event in flight: a record whose d_reclen is not a multiple of 8, a
 * name with '/', a cookie past OFF_MAX, an empty answer that is not the
 * end; then a valid answer completes the call.
 */
static int
h_readdir(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	const struct dq_readdir_body *db;
	char rec[512];
	struct dirent *dp;
	size_t len;

	(void)rb; (void)path; (void)body; (void)bodylen;
	if (ev->de_op != DQ_OP_READDIR || dq_event_readdir(ev, &db) != 0)
		return (0);
	len = 0;
	ATF_REQUIRE(dq_dirent_add(rec, sizeof(rec), &len, 5, 1, DT_REG,
	    "x") == 0);
	dp = (struct dirent *)(void *)rec;
	dp->d_reclen += 1;
	s->hook_err[0] = dq_reply_readdir(s->q, ev->de_id, 1, 0, rec, len) ==
	    0 ? 0 : errno;
	dp->d_reclen -= 1;
	dp->d_name[0] = '/';
	s->hook_err[1] = dq_reply_readdir(s->q, ev->de_id, 1, 0, rec, len) ==
	    0 ? 0 : errno;
	dp->d_name[0] = 'x';
	s->hook_err[2] = dq_reply_readdir(s->q, ev->de_id,
	    (uint64_t)OFF_MAX + 1, 0, rec, len) == 0 ? 0 : errno;
	s->hook_err[3] = dq_reply_readdir(s->q, ev->de_id, 1, 0, rec, 0) ==
	    0 ? 0 : errno;
	/* The other validator rows: each is EINVAL (bit i set if not). */
	s->hook_state = 0;
	{
		char big[1024];
		size_t blen;
		int k;

		for (k = 0; k < 6; k++) {
			blen = 0;
			memset(big, 0, sizeof(big));
			(void)dq_dirent_add(big, sizeof(big), &blen, 5, 1,
			    k == 0 ? DT_REG : DT_DIR, k == 0 ? "." : "xy");
			dp = (struct dirent *)(void *)big;
			if (k == 1)
				dp->d_name[0] = '\0';	/* inner NUL */
			if (k == 2)
				dp->d_type = 3;		/* unknown d_type */
			if (k == 3)
				dp->d_reclen = 24;	/* < GENERIC_DIRSIZ */
			if (k == 4) {
				/* More records than the request's 512. */
				while (blen < 600)
					(void)dq_dirent_add(big, sizeof(big),
					    &blen, 6, 1, DT_REG, "zz");
			}
			if (k == 5)
				dp->d_namlen = 0;
			if (dq_reply_readdir(s->q, ev->de_id, 1, 0, big, blen)
			    == 0 || errno != EINVAL)
				s->hook_state |= 1 << k;
		}
	}
	(void)dq_reply_readdir(s->q, ev->de_id, 1, 1, rec, len);
	return (1);
}

static void
c_readdir_one(struct srv *s, int *r)
{
	char buf[4096];
	struct dirent *dp;
	off_t base;
	ssize_t n;

	n = getdirentries(s->sroot, buf, 512, &base);
	r[0] = n < 0 ? errno : 0;
	dp = (struct dirent *)(void *)buf;
	r[1] = n > 0 && strcmp(dp->d_name, "x") == 0;
	r[2] = (int)lseek(s->sroot, 0, SEEK_CUR);
}

DQ_TC(readdir_malformed);
ATF_TC_BODY(readdir_malformed, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_readdir;
	run_child(&s, c_readdir_one, r);
	CHECK_ERRNO(0, r[0]);
	ATF_CHECK_EQ(1, r[1]);
	ATF_CHECK_EQ(1, r[2]);
	CHECK_ERRNO(EINVAL, s.hook_err[0]);
	CHECK_ERRNO(EINVAL, s.hook_err[1]);
	CHECK_ERRNO(EINVAL, s.hook_err[2]);
	CHECK_ERRNO(EINVAL, s.hook_err[3]);
	ATF_CHECK_EQ_MSG(0, s.hook_state, "validator rows accepted: %#x",
	    s.hook_state);
	srv_stop(&s);
}

/*
 * Symlink re-entry (D172 (b)): a PASSed lookup from a real start that
 * meets a symlink is consulted again with what remains, start REAL_SYMDIR
 * (relative target, hint the link's directory) and DQ_RF_SYMLINK_RESTART.
 * A FIFO under the tree opened from the served root is answered REAL
 * (the backing node), as are names the tree does not hold.
 */
/* REAL answered to a re-consultation (the hook) maps realfile3. */
static int
h_resym(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	char real[PATH_MAX];

	(void)body; (void)bodylen;
	if (rb == NULL || (rb->drs_rflags & DQ_RF_SYMLINK_RESTART) == 0 ||
	    strcmp(path, "realfile3") != 0)
		return (0);
	snprintf(real, sizeof(real), "%s/a", s->backing);
	s->hook_err[0] = dq_reply_resolve_real(s->q, ev->de_id, real) == 0 ?
	    0 : errno;
	s->hook_state++;
	return (1);
}

static void
c_resymlink(struct srv *s, int *r)
{
	struct stat st;
	int fd;

	r[0] = DQT_ERRNO_OF(stat("reallink", &st));
	fd = openat(s->sroot, "p", O_RDONLY | O_NONBLOCK);
	r[1] = DQT_ERRNO_OF(fd);
	if (fd >= 0) {
		r[2] = DQT_ERRNO_OF(fstat(fd, &st));
		r[3] = S_ISFIFO(st.st_mode);
	}
	/* A served answer (ATTR) to a re-consultation into the prefix. */
	r[4] = DQT_ERRNO_OF(stat("toprefix", &st));
	r[5] = (int)st.st_size;
	/* REAL to a re-consultation: the backing "a", 7 bytes. */
	r[6] = DQT_ERRNO_OF(stat("reallink3", &st));
	r[7] = (int)st.st_size;
}

DQ_TC(symlink_reconsult);
ATF_TC_BODY(symlink_reconsult, tc)
{
	struct srv s;
	int r[RES_MAX], i, obs, nres, nreal;

	srv_start(&s, 0);
	ATF_REQUIRE(close(open("realfile", O_CREAT | O_RDWR, 0644)) == 0);
	ATF_REQUIRE(symlink("realfile", "reallink") == 0);
	ATF_REQUIRE(close(open("realfile3", O_CREAT | O_RDWR, 0644)) == 0);
	ATF_REQUIRE(symlink("realfile3", "reallink3") == 0);
	ATF_REQUIRE(symlink("served/a", "toprefix") == 0);
	s.hook = h_resym;
	obs = dq_mint_observer(s.q, DQ_OBS_F_DATA);
	ATF_REQUIRE(obs >= 0);
	run_child(&s, c_resymlink, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(0, r[2]);
	ATF_CHECK_EQ(1, r[3]);
	CHECK_ERRNO(0, r[4]);
	ATF_CHECK_EQ(7, r[5]);
	CHECK_ERRNO(0, r[6]);
	ATF_CHECK_EQ(7, r[7]);
	ATF_CHECK_EQ(1, s.hook_state);
	CHECK_ERRNO(0, s.hook_err[0]);
	/* The FIFO's open and the hook's answer were REAL replies. */
	obs_drain(obs, DQ_OP_RESOLVE, &nres, DQ_RESOLVE_REAL, &nreal);
	ATF_CHECK(nreal >= 2);
	close(obs);
	i = srv_find(&s, DQ_ROP_STAT, "realfile");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK_EQ(DQ_START_REAL_SYMDIR, s.seen[i].start_kind);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_SYMLINK_RESTART) != 0);
	ATF_CHECK((s.seen[i].accept & DQ_RACCEPT(DQ_RESOLVE_PASS)) != 0);
	srv_stop(&s);
}

/*
 * Round 2, finding 1: both starts served, the second checked against its
 * own descriptor before anything is posted.  A second descriptor without
 * CAP_RENAMEAT_TARGET is ENOTCAPABLE; with FD_RESOLVE_BENEATH a leading
 * ".." of the second path is ENOTCAPABLE; neither posts.  An allowed
 * limited second start posts DQ_RF_STRICTREL2.  In capability mode a
 * second path starting at the working directory is ECAPMODE and a ".."
 * leading the second path ENOTCAPABLE, with no event.
 */
static void
c_slot1(struct srv *s, int *r)
{
	cap_rights_t rights;
	int d1, d2, d3;

	d1 = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	d2 = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	d3 = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(d1) + DQT_ERRNO_OF(d2) + DQT_ERRNO_OF(d3);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ);
	r[1] = DQT_ERRNO_OF(cap_rights_limit(d1, &rights));
	r[2] = DQT_ERRNO_OF(renameat(s->sroot, "a", d1, "x1"));
	r[3] = DQT_ERRNO_OF(fcntl(d2, F_SETFD, FD_RESOLVE_BENEATH));
	r[4] = DQT_ERRNO_OF(renameat(s->sroot, "a", d2, "../x2"));
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_RENAMEAT_TARGET,
	    CAP_CREATE);
	r[5] = DQT_ERRNO_OF(cap_rights_limit(d3, &rights));
	r[6] = DQT_ERRNO_OF(renameat(s->sroot, "a", d3, "x3"));
	r[7] = DQT_ERRNO_OF(renameat(s->sroot, "x3x", d3, "x4"));
	r[8] = DQT_ERRNO_OF(cap_enter());
	r[9] = DQT_ERRNO_OF(renameat(s->sroot, "d/x3", AT_FDCWD, "x5"));
	r[10] = DQT_ERRNO_OF(renameat(s->sroot, "d/x3", s->sroot, "../x6"));
}

DQ_TC(slot1_restricted);
ATF_TC_BODY(slot1_restricted, tc)
{
	struct srv s;
	struct stat st;
	int r[RES_MAX], i;

	srv_start(&s, DQ_TREE_F_WRITE);
	run_child(&s, c_slot1, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(ENOTCAPABLE, r[2]);
	CHECK_ERRNO(0, r[3]);
	CHECK_ERRNO(ENOTCAPABLE, r[4]);
	CHECK_ERRNO(0, r[5]);
	CHECK_ERRNO(0, r[6]);
	CHECK_ERRNO(ENOENT, r[7]);
	CHECK_ERRNO(0, r[8]);
	CHECK_ERRNO(ECAPMODE, r[9]);
	CHECK_ERRNO(ENOTCAPABLE, r[10]);
	/* Only the allowed renames were posted, flagged. */
	ATF_CHECK_EQ(2, srv_count(&s, DQ_ROP_RENAME));
	i = srv_find_exact(&s, DQ_ROP_RENAME, "a");
	ATF_REQUIRE(i >= 0);
	ATF_CHECK((s.seen[i].rflags & DQ_RF_STRICTREL2) != 0);
	ATF_CHECK(fstatat(s.rootfd, "d/x3", &st, 0) == 0);
	ATF_CHECK(fstatat(s.rootfd, "d/x1", &st, 0) != 0);
	srv_stop(&s);
}

/*
 * Round 2, finding 2: a vnode-less second start behind a real first one
 * is refused as its lookup would be, before posting: another queue's
 * served directory EXDEV (counted), a served file ENOTDIR, a closed
 * descriptor EBADF.  Finding 4: funlinkat(AT_REMOVEDIR) (frmdirat) of a
 * served directory descriptor needs CAP_LOOKUP on it.
 */
static int other_root = -1, other_q = -1, other_file = -1;

static void
c_vnodeless(struct srv *s, int *r)
{
	cap_rights_t rights;
	int fd;

	if (other_q >= 0)
		close(other_q);
	r[0] = DQT_ERRNO_OF(renameat(AT_FDCWD, "realsrc", other_root, "x"));
	r[1] = DQT_ERRNO_OF(renameat(AT_FDCWD, "realsrc", other_file, "x"));
	r[2] = DQT_ERRNO_OF(renameat(AT_FDCWD, "realsrc", 999, "x"));
	r[3] = DQT_ERRNO_OF(mkdirat(s->sroot, "rd", 0755));
	fd = openat(s->sroot, "rd", O_RDONLY | O_DIRECTORY);
	r[4] = DQT_ERRNO_OF(fd);
	cap_rights_init(&rights, CAP_READ);
	r[5] = DQT_ERRNO_OF(cap_rights_limit(fd, &rights));
	r[6] = DQT_ERRNO_OF(funlinkat(s->sroot, "rd", fd, AT_REMOVEDIR));
	fd = openat(s->sroot, "rd", O_RDONLY | O_DIRECTORY);
	r[7] = DQT_ERRNO_OF(funlinkat(s->sroot, "rd", fd, AT_REMOVEDIR));
}

DQ_TC(vnodeless_slot1);
ATF_TC_BODY(vnodeless_slot1, tc)
{
	struct srv s;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct dq_stats2 st;
	uint64_t obj;
	int r[RES_MAX], n, reason;

	srv_start(&s, DQ_TREE_F_WRITE);
	ATF_REQUIRE(close(open("realsrc", O_CREAT | O_RDWR, 0644)) == 0);
	/* Another queue's served directory, and a served file of ours. */
	other_q = dqt_open_queue();
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(dq_ident_from_lstat(id, s.backing, s.rootfd, "d") == 0);
	strlcpy(id->di_statfs.ds_mntonname, "/",
	    sizeof(id->di_statfs.ds_mntonname));
	dq_policy_default_dir(&pol);
	ATF_REQUIRE_MSG(dq_mint_dir(other_q, id, &pol, &obj, &other_root,
	    &reason) == 0, "mint_dir: %s reason %d", strerror(errno), reason);
	ATF_REQUIRE(dq_ident_from_lstat(id, s.backing, s.rootfd, "a") == 0);
	strlcpy(id->di_statfs.ds_mntonname, "/",
	    sizeof(id->di_statfs.ds_mntonname));
	dq_policy_default(&pol);
	ATF_REQUIRE(dq_mint_file(s.q, id, &pol, &obj, &other_file,
	    &reason) == 0);
	free(id);
	n = srv_count(&s, DQ_ROP_RENAME);
	run_child(&s, c_vnodeless, r);
	CHECK_ERRNO(EXDEV, r[0]);
	CHECK_ERRNO(ENOTDIR, r[1]);
	CHECK_ERRNO(EBADF, r[2]);
	/*
	 * Round 4: another queue's directory (r[0]) is refused before
	 * posting; the served file and the bad descriptor behind a real
	 * first path are posted PASS-only and fail at their own lookup.
	 */
	ATF_CHECK_EQ(n + 2, srv_count(&s, DQ_ROP_RENAME));
	pthread_mutex_lock(&s.mtx);
	for (int k = 0; k < s.nseen; k++)
		if (s.seen[k].op == DQ_ROP_RENAME &&
		    strcmp(s.seen[k].path, "realsrc") == 0)
			ATF_CHECK_EQ_MSG(DQ_RACCEPT(DQ_RESOLVE_PASS),
			    s.seen[k].accept, "rename %s: accept %#x",
			    s.seen[k].path, s.seen[k].accept);
	pthread_mutex_unlock(&s.mtx);
	srv_stats(&s, &st);
	ATF_CHECK(st.ds2_resolve_exdev >= 1);
	CHECK_ERRNO(0, r[3]);
	CHECK_ERRNO(0, r[4]);
	CHECK_ERRNO(0, r[5]);
	CHECK_ERRNO(ENOTCAPABLE, r[6]);
	CHECK_ERRNO(0, r[7]);
	close(other_root);
	close(other_file);
	close(other_q);
	srv_stop(&s);
}

/*
 * Round 2, finding 3: a REAL rewrite keeps a trailing slash: "rs/" mapped
 * to a file is ENOTDIR, an O_CREAT of "rn/" mapped to a new name ENOENT
 * (as FreeBSD), and "rl/" mapped to a symbolic link to a directory follows it even
 * under AT_SYMLINK_NOFOLLOW.
 */
static int
h_slash(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	char real[PATH_MAX];
	const char *to;

	(void)body; (void)bodylen;
	if (rb == NULL)
		return (0);
	if (strcmp(path, "rs/") == 0)
		to = "a";
	else if (strcmp(path, "rn/") == 0)
		to = "newname";
	else if (strcmp(path, "rl/") == 0)
		to = "dl";
	else
		return (0);
	snprintf(real, sizeof(real), "%s/%s", s->backing, to);
	(void)dq_reply_resolve_real(s->q, ev->de_id, real);
	return (1);
}

static void
c_slash(struct srv *s, int *r)
{
	struct stat st;

	r[0] = DQT_ERRNO_OF(openat(s->sroot, "rs/", O_RDONLY));
	r[1] = DQT_ERRNO_OF(openat(s->sroot, "rn/", O_CREAT | O_RDWR, 0644));
	r[2] = DQT_ERRNO_OF(fstatat(s->sroot, "rl/", &st, AT_SYMLINK_NOFOLLOW));
	r[3] = S_ISDIR(st.st_mode);
}

DQ_TC(real_trailing_slash);
ATF_TC_BODY(real_trailing_slash, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	ATF_REQUIRE(symlink("d", "backing/dl") == 0);
	s.hook = h_slash;
	run_child(&s, c_slash, r);
	/*
	 * The oracle: the same names on the real file system, unattached.
	 * (O_CREAT of a missing "name/" is ENOENT in FreeBSD: vfs_lookup
	 * allows a trailing slash on a new name only with WILLBEDIR; run 44
	 * showed the plan's EISDIR was wrong, the kernel was right.)
	 */
	{
		char p[PATH_MAX];
		struct stat st;
		int o0, o1, o2;

		snprintf(p, sizeof(p), "%s/a/", s.backing);
		o0 = DQT_ERRNO_OF(open(p, O_RDONLY));
		snprintf(p, sizeof(p), "%s/newname_oracle/", s.backing);
		o1 = DQT_ERRNO_OF(open(p, O_CREAT | O_RDWR, 0644));
		snprintf(p, sizeof(p), "%s/dl/", s.backing);
		o2 = DQT_ERRNO_OF(fstatat(AT_FDCWD, p, &st, AT_SYMLINK_NOFOLLOW));
		CHECK_ERRNO(o0, r[0]);
		ATF_CHECK_EQ_MSG(o1, r[1], "O_CREAT of name/: real %d served %d",
		    o1, r[1]);
		CHECK_ERRNO(o2, r[2]);
		CHECK_ERRNO(ENOTDIR, r[0]);
		CHECK_ERRNO(ENOENT, r[1]);
		ATF_CHECK_EQ(1, r[3]);
		ATF_CHECK(fstatat(s.rootfd, "newname", &st, 0) != 0);
	}
	srv_stop(&s);
}

/*
 * REAL is not offered when the start descriptor's rights are limited
 * (STRICTREL): the controller's REAL is EINVAL, its errno completes.
 */
static int
h_limited(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	char real[PATH_MAX];

	(void)body; (void)bodylen;
	if (rb == NULL || strcmp(path, "lim") != 0)
		return (0);
	s->hook_state = (rb->drs_rflags & DQ_RF_STRICTREL) != 0;
	snprintf(real, sizeof(real), "%s/a", s->backing);
	s->hook_err[0] = dq_reply_resolve_real(s->q, ev->de_id, real) == 0 ?
	    0 : errno;
	(void)dq_reply_resolve_errno(s->q, ev->de_id, ENOENT);
	return (1);
}

static void
c_limited(struct srv *s, int *r)
{
	cap_rights_t rights;
	struct stat st;

	cap_rights_init(&rights, CAP_LOOKUP, CAP_FSTATAT);
	r[0] = DQT_ERRNO_OF(cap_rights_limit(s->sroot, &rights));
	r[1] = DQT_ERRNO_OF(fstatat(s->sroot, "lim", &st, 0));
}

DQ_TC(real_limited_rights);
ATF_TC_BODY(real_limited_rights, tc)
{
	struct srv s;
	int r[RES_MAX];

	srv_start(&s, 0);
	s.hook = h_limited;
	run_child(&s, c_limited, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(ENOENT, r[1]);
	ATF_CHECK_EQ(1, s.hook_state);
	CHECK_ERRNO(EINVAL, s.hook_err[0]);
	srv_stop(&s);
}

/*
 * The re-consultation's skips (D172): a lookup under O_RESOLVE_BENEATH,
 * the carried second path of a rename, and a capability-mode lookup meet
 * symbolic links without a DQ_RF_SYMLINK_RESTART event.  (An exempt
 * region, the kernel's own lookups such as the linker's, cannot be
 * driven from here.)
 */
static void
c_skips(struct srv *s, int *r)
{
	struct stat st;
	int d;

	(void)s;
	d = open(".", O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(fstatat(d, "sk_link1", &st, AT_RESOLVE_BENEATH));
	r[1] = DQT_ERRNO_OF(renameat(AT_FDCWD, "sk_src", AT_FDCWD, "sk_dirlink/dst"));
	r[2] = DQT_ERRNO_OF(cap_enter());
	r[3] = DQT_ERRNO_OF(fstatat(d, "sk_link2", &st, 0));
}

DQ_TC(reconsult_skips);
ATF_TC_BODY(reconsult_skips, tc)
{
	struct srv s;
	int r[RES_MAX], i;

	srv_start(&s, 0);
	ATF_REQUIRE(close(open("sk_file", O_CREAT | O_RDWR, 0644)) == 0);
	ATF_REQUIRE(close(open("sk_src", O_CREAT | O_RDWR, 0644)) == 0);
	ATF_REQUIRE(mkdir("sk_dir", 0755) == 0);
	ATF_REQUIRE(symlink("sk_file", "sk_link1") == 0);
	ATF_REQUIRE(symlink("sk_file", "sk_link2") == 0);
	ATF_REQUIRE(symlink("sk_dir", "sk_dirlink") == 0);
	run_child(&s, c_skips, r);
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(0, r[2]);
	CHECK_ERRNO(0, r[3]);
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nseen; i++)
		ATF_CHECK_MSG((s.seen[i].rflags & DQ_RF_SYMLINK_RESTART) == 0,
		    "re-consulted %s (op %u)", s.seen[i].path, s.seen[i].op);
	pthread_mutex_unlock(&s.mtx);
	srv_stop(&s);
}

/*
 * Round 3: the tree applies the lookup's restrictions.  In capability
 * mode from a served subdirectory d, "sub/../../a" and a backing symbolic
 * link "up" -> ".." used as "up/a" leave d: ENOTCAPABLE, nothing removed
 * or renamed.  A real second start behind a served first is EXDEV; an
 * empty second path ENOENT with no event; rename("missing", badfd, "x")
 * ENOENT (the second start's error comes in FreeBSD's order); "rf/."
 * answered REAL with a file keeps ENOTDIR; a backing symbolic link whose
 * expansion overflows is ENAMETOOLONG.
 */
static int
h_r3(struct srv *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path, const void *body,
    size_t bodylen)
{
	char real[PATH_MAX];

	(void)body; (void)bodylen;
	if (rb == NULL || strcmp(path, "rf/.") != 0)
		return (0);
	snprintf(real, sizeof(real), "%s/a", s->backing);
	(void)dq_reply_resolve_real(s->q, ev->de_id, real);
	return (1);
}

static void
c_r3(struct srv *s, int *r)
{
	char longp[256];
	struct stat st;
	int d, rd;

	r[0] = DQT_ERRNO_OF(fstatat(s->sroot, "rf/.", &st, 0));
	memset(longp, 'y', sizeof(longp) - 1);
	memcpy(longp, "long/", 5);
	longp[sizeof(longp) - 1] = '\0';
	r[1] = DQT_ERRNO_OF(fstatat(s->sroot, longp, &st, 0));
	r[2] = DQT_ERRNO_OF(renameat(s->sroot, "a", s->sroot, ""));
	r[3] = DQT_ERRNO_OF(renameat(AT_FDCWD, "missing_r3", 999, "x"));
	d = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	rd = open(".", O_RDONLY | O_DIRECTORY);
	r[4] = DQT_ERRNO_OF(d) + DQT_ERRNO_OF(rd);
	r[5] = DQT_ERRNO_OF(cap_enter());
	r[6] = DQT_ERRNO_OF(unlinkat(d, "sub/../../a", 0));
	r[7] = DQT_ERRNO_OF(renameat(d, "sub/../../a", d, "moved"));
	r[8] = DQT_ERRNO_OF(unlinkat(d, "up/a", 0));
	r[9] = DQT_ERRNO_OF(renameat(s->sroot, "a", rd, "x"));
}

DQ_TC(round3_rows);
ATF_TC_BODY(round3_rows, tc)
{
	struct srv s;
	struct stat st;
	char tgt[1001];
	int r[RES_MAX], n;

	srv_start(&s, DQ_TREE_F_WRITE);
	ATF_REQUIRE(mkdir("backing/d/sub", 0755) == 0);
	ATF_REQUIRE(symlink("..", "backing/d/up") == 0);
	/* 1000 bytes of target: with the rest of the path, past MAXPATHLEN. */
	memset(tgt, 'z', sizeof(tgt) - 1);
	tgt[sizeof(tgt) - 1] = '\0';
	ATF_REQUIRE(symlink(tgt, "backing/long") == 0);
	s.hook = h_r3;
	n = srv_count(&s, DQ_ROP_RENAME);
	run_child(&s, c_r3, r);
	CHECK_ERRNO(ENOTDIR, r[0]);
	CHECK_ERRNO(ENAMETOOLONG, r[1]);
	CHECK_ERRNO(ENOENT, r[2]);
	CHECK_ERRNO(ENOENT, r[3]);
	CHECK_ERRNO(0, r[4]);
	CHECK_ERRNO(0, r[5]);
	CHECK_ERRNO(ENOTCAPABLE, r[6]);
	CHECK_ERRNO(ENOTCAPABLE, r[7]);
	CHECK_ERRNO(ENOTCAPABLE, r[8]);
	CHECK_ERRNO(EXDEV, r[9]);
	/* Nothing left the subdirectory: "a" is still at the root. */
	ATF_CHECK(fstatat(s.rootfd, "a", &st, 0) == 0);
	ATF_CHECK(fstatat(s.rootfd, "d/moved", &st, 0) != 0);
	/* The empty second path and the mixed one posted no RENAME. */
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_RENAME, "a"));
	(void)n;
	srv_stop(&s);
}

/*
 * Round 4.  A served second start whose descriptor is
 * cap_lookup_capmode(2)-marked, used outside capability mode, is
 * ENOTCAPABLE before posting, as its lookup would be.  An empty second
 * path behind a real first path lets the first path's error come first
 * (ENOTDIR for "realfile_r4/x"), as in FreeBSD.  Under capability mode
 * with vfs.lookup_cap_dotdot_nonlocal=0, a ".." inside the tree on a
 * local file system is still allowed (a non-local backing mount is not
 * available to the test; the rule is dq_tree_dir_local's).
 */
static void
c_r4(struct srv *s, int *r)
{
	struct stat st;
	int d2, d;

	d2 = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	r[0] = DQT_ERRNO_OF(d2);
	r[1] = DQT_ERRNO_OF(cap_lookup_capmode(d2));
	r[2] = DQT_ERRNO_OF(renameat(s->sroot, "a", d2, "x"));
	r[3] = DQT_ERRNO_OF(renameat(AT_FDCWD, "realfile_r4/x", 999, ""));
	r[4] = DQT_ERRNO_OF(renameat(AT_FDCWD, "realfile_r4/x", AT_FDCWD, ""));
	d = openat(s->sroot, "d", O_RDONLY | O_DIRECTORY);
	r[5] = DQT_ERRNO_OF(cap_enter());
	r[6] = DQT_ERRNO_OF(fstatat(d, "sub/../f", &st, 0));
}

DQ_TC_CLEANUP(round4_rows);
ATF_TC_BODY(round4_rows, tc)
{
	struct srv s;
	int r[RES_MAX];

	dqt_sysctl_save_set_int("vfs.lookup_cap_dotdot_nonlocal", 0);
	srv_start(&s, DQ_TREE_F_WRITE);
	ATF_REQUIRE(mkdir("backing/d/sub", 0755) == 0);
	ATF_REQUIRE(close(open("realfile_r4", O_CREAT | O_RDWR, 0644)) == 0);
	run_child(&s, c_r4, r);
	ATF_REQUIRE(dqt_sysctl_restore("vfs.lookup_cap_dotdot_nonlocal"));
	CHECK_ERRNO(0, r[0]);
	CHECK_ERRNO(0, r[1]);
	CHECK_ERRNO(ENOTCAPABLE, r[2]);
	ATF_CHECK_EQ(-1, srv_find_exact(&s, DQ_ROP_RENAME, "a"));
	CHECK_ERRNO(ENOTDIR, r[3]);
	CHECK_ERRNO(ENOTDIR, r[4]);
	CHECK_ERRNO(0, r[5]);
	CHECK_ERRNO(0, r[6]);
	srv_stop(&s);
}
ATF_TC_CLEANUP(round4_rows, tc)
{

	(void)dqt_sysctl_restore("vfs.lookup_cap_dotdot_nonlocal");
}

/*
 * Start hints of real starts (dq-standing-decisions §9.1, review 1 M3):
 * pinned before the standing rules, whose relative matching reads the hint
 * of a process under the global root.  The hints below must stay the same
 * strings.  The harness controller (dqt_ctl) answers PASS and records each
 * event's start kind and hint.
 */

/* The recorded RESOLVE of op with exactly this path and start, or -1. */
static int
hint_find(struct dqt_ctl *c, uint32_t op, const char *path, uint32_t kind,
    struct dqt_resolve_seen *rs)
{
	int i, n;

	n = -1;
	dqt_lock(c);
	for (i = 0; i < c->nrs; i++) {
		if (c->rs[i].op == op && c->rs[i].start_kind == kind &&
		    strcmp(c->rs[i].path, path) == 0) {
			*rs = c->rs[i];
			n = i;
			break;
		}
	}
	dqt_unlock(c);
	return (n);
}

/* The real work directory, short enough for the harness's records. */
static void
hint_cwd(char *cwd, size_t len)
{

	ATF_REQUIRE(len >= PATH_MAX && realpath(".", cwd) != NULL);
	ATF_REQUIRE_MSG(strlen(cwd) + sizeof("/absdir/inner") <= DQT_RPATH,
	    "work directory %s too long for the records", cwd);
}

struct hint_res {
	struct dqt_rr	 r[4];
};

static void
c_hints(void *arg __unused, void *result)
{
	struct hint_res *r = result;
	struct stat st;
	int d;

	/* A cwd start; a dirfd start; a relative link's re-consultation. */
	DQT_RR(r->r[0], stat("hdir/hint-f", &st));
	DQT_RR(r->r[1], open("hdir", O_RDONLY | O_DIRECTORY));
	d = (int)r->r[1].rv;
	if (d >= 0) {
		DQT_RR(r->r[2], fstatat(d, "hint-f", &st, 0));
		(void)close(d);
	}
	DQT_RR(r->r[3], stat("hdir/hint-l", &st));
}

DQ_TC(start_hint_global_root);
ATF_TC_BODY(start_hint_global_root, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct hint_res r;
	char cwd[PATH_MAX], want[PATH_MAX];
	int fd, k;

	hint_cwd(cwd, sizeof(cwd));
	ATF_REQUIRE_EQ(0, mkdir("hdir", 0755));
	fd = open("hdir/hint-f", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);
	ATF_REQUIRE_EQ(0, symlink("hint-f", "hdir/hint-l"));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, c_hints, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	for (k = 0; k < 4; k++)
		CHECK_ERRNO(0, r.r[k].err);

	/* The working directory, relative to the process's root ("/"). */
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "hdir/hint-f",
	    DQ_START_REAL_CWD, &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_STARTPATH_VALID) != 0);
	ATF_CHECK((rs.rflags & DQ_RF_SYMLINK_RESTART) == 0);
	ATF_CHECK_STREQ(cwd, rs.startpath);

	/* The directory descriptor's directory. */
	snprintf(want, sizeof(want), "%s/hdir", cwd);
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "hint-f", DQ_START_REAL_DIRFD,
	    &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_STARTPATH_VALID) != 0);
	ATF_CHECK_STREQ(want, rs.startpath);

	/* The link's directory, at the re-consultation of its target. */
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "hdir/hint-l",
	    DQ_START_REAL_CWD, &rs) != -1);
	ATF_CHECK_STREQ(cwd, rs.startpath);
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "hint-f", DQ_START_REAL_SYMDIR,
	    &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_SYMLINK_RESTART) != 0);
	ATF_CHECK((rs.rflags & DQ_RF_STARTPATH_VALID) != 0);
	ATF_CHECK_STREQ(want, rs.startpath);
	dqt_fini(&c);
}

static void
c_outside(void *arg __unused, void *result)
{
	struct hint_res *r = result;
	struct stat st;
	int d;

	DQT_RR(r->r[0], open("outside", O_RDONLY | O_DIRECTORY));
	d = (int)r->r[0].rv;
	DQT_RR(r->r[1], chroot("newroot"));
	if (d >= 0)
		DQT_RR(r->r[2], fstatat(d, "of", &st, 0));
}

/*
 * The §7.7 finding, fixed by Q15: a directory descriptor opened before
 * chroot(2) names a start outside the new root, and its global path would
 * read like a path under the new root, so the controller gets no hint
 * (dq_resolve_test:startpath_outside_root_invalid pins the rest).
 */
DQ_TC(relative_hint_outside_root);
ATF_TC_BODY(relative_hint_outside_root, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct hint_res r;
	char cwd[PATH_MAX];
	int fd;

	hint_cwd(cwd, sizeof(cwd));
	ATF_REQUIRE_EQ(0, mkdir("outside", 0755));
	ATF_REQUIRE_EQ(0, mkdir("newroot", 0755));
	fd = open("outside/of", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, c_outside, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	CHECK_ERRNO(0, r.r[0].err);
	CHECK_ERRNO(0, r.r[1].err);
	CHECK_ERRNO(0, r.r[2].err);
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "of", DQ_START_REAL_DIRFD,
	    &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_STARTPATH_VALID) == 0);
	ATF_CHECK_STREQ("", rs.startpath);
	dqt_fini(&c);
}

static void
c_abslink(void *arg __unused, void *result)
{
	struct hint_res *r = result;
	struct stat st;

	DQT_RR(r->r[0], stat("abs-l/inner", &st));
}

/*
 * A PASSed lookup meeting a symbolic link with an absolute target is
 * consulted again: start REAL_ROOT, the target followed by what remains,
 * DQ_RF_SYMLINK_RESTART, no hint.  (symlink_reconsult pins the relative
 * target, REAL_SYMDIR.)
 */
DQ_TC(symlink_reconsult_absolute);
ATF_TC_BODY(symlink_reconsult_absolute, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct hint_res r;
	char cwd[PATH_MAX], target[PATH_MAX], want[PATH_MAX];
	int fd;

	hint_cwd(cwd, sizeof(cwd));
	ATF_REQUIRE_EQ(0, mkdir("absdir", 0755));
	fd = open("absdir/inner", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);
	snprintf(target, sizeof(target), "%s/absdir", cwd);
	snprintf(want, sizeof(want), "%s/absdir/inner", cwd);
	ATF_REQUIRE_EQ(0, symlink(target, "abs-l"));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, c_abslink, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	CHECK_ERRNO(0, r.r[0].err);
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, "abs-l/inner",
	    DQ_START_REAL_CWD, &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_SYMLINK_RESTART) == 0);
	ATF_REQUIRE(hint_find(&c, DQ_ROP_STAT, want, DQ_START_REAL_ROOT,
	    &rs) != -1);
	ATF_CHECK((rs.rflags & DQ_RF_SYMLINK_RESTART) != 0);
	ATF_CHECK((rs.rflags & DQ_RF_STARTPATH_VALID) == 0);
	ATF_CHECK_STREQ("", rs.startpath);
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, dirfd_ops);
	ATF_TP_ADD_TC(tp, pass_refused);
	ATF_TP_ADD_TC(tp, real_answer);
	ATF_TP_ADD_TC(tp, start_rules);
	ATF_TP_ADD_TC(tp, two_path);
	ATF_TP_ADD_TC(tp, i8_beneath);
	ATF_TP_ADD_TC(tp, capmode_rights);
	ATF_TP_ADD_TC(tp, fd_install_limits);
	ATF_TP_ADD_TC(tp, restricted_no_swap);
	ATF_TP_ADD_TC(tp, emptypath);
	ATF_TP_ADD_TC(tp, symlink_opath);
	ATF_TP_ADD_TC(tp, readdir_oracle);
	ATF_TP_ADD_TC(tp, readdir_malformed);
	ATF_TP_ADD_TC(tp, symlink_reconsult);
	ATF_TP_ADD_TC(tp, slot1_restricted);
	ATF_TP_ADD_TC(tp, vnodeless_slot1);
	ATF_TP_ADD_TC(tp, real_trailing_slash);
	ATF_TP_ADD_TC(tp, real_limited_rights);
	ATF_TP_ADD_TC(tp, reconsult_skips);
	ATF_TP_ADD_TC(tp, round3_rows);
	ATF_TP_ADD_TC(tp, round4_rows);
	ATF_TP_ADD_TC(tp, start_hint_global_root);
	ATF_TP_ADD_TC(tp, relative_hint_outside_root);
	ATF_TP_ADD_TC(tp, symlink_reconsult_absolute);
	return (atf_no_error());
}
