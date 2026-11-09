/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-c test harness: a dq_serve_tree()
 * controller thread over a backing tree, its minted root (the served
 * root and cwd ATTACH can give), an event recorder, an optional hook that
 * answers chosen events itself, and attached children that report a
 * fixed-size result through a pipe.  Children never use ATF macros.
 */

#ifndef _DQ_TREE_HARNESS_H_
#define	_DQ_TREE_HARNESS_H_

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#define	TS_TC_HEAD_BODY(name)						\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "180");		\
	}
#define	TS_TC(name)	ATF_TC(name); TS_TC_HEAD_BODY(name)
#define	TS_TC_CLEANUP(name)	ATF_TC_WITH_CLEANUP(name); TS_TC_HEAD_BODY(name)

#define	TS_NEV		512

/* One recorded RESOLVE event. */
struct ts_ev {
	uint32_t	op;
	uint32_t	start_kind;
	uint32_t	rclass;
	uint32_t	rflags;
	uint32_t	accept;
	uint64_t	start;
	char		path[256];
	char		hint[256];
};

struct ts;
/* A hook answers an event itself (returns 1) or leaves it to the tree. */
typedef int (*ts_hook_fn)(struct ts *, const struct dq_event *,
    const struct dq_resolve_body *, const char *path);

struct ts {
	int		 q;
	int		 bfd;		/* the backing tree */
	int		 sroot;		/* the minted root (controller's fd) */
	uint64_t	 rootid;
	struct dq_tree	*tree;
	pthread_t	 thr;
	volatile int	 stop;
	char		 backing[PATH_MAX];	/* its real path = the prefix */
	pthread_mutex_t	 mtx;
	int		 nev;
	struct ts_ev	 ev[TS_NEV];
	ts_hook_fn	 hook;
	void		*hookarg;
};

static __unused int
ts_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	const struct dq_resolve_body *rb;
	const char *path, *path2, *sp, *sp2;
	const struct dq_setattr_body *sb;
	struct ts *s = arg;
	struct ts_ev *e;

	(void)q;
	if (ev->de_op == DQ_OP_RESOLVE &&
	    dq_event_resolve_ext(ev, &rb, &path, &path2, &sp, &sp2,
	    &sb) == 0) {
		pthread_mutex_lock(&s->mtx);
		if (s->nev < TS_NEV) {
			e = &s->ev[s->nev++];
			e->op = rb->drs_op;
			e->start_kind = rb->drs_start_kind;
			e->rclass = rb->drs_flags;
			e->rflags = rb->drs_rflags;
			e->accept = rb->drs_accept;
			e->start = rb->drs_start;
			strlcpy(e->path, path, sizeof(e->path));
			strlcpy(e->hint, (rb->drs_rflags &
			    DQ_RF_STARTPATH_VALID) != 0 ? sp : "",
			    sizeof(e->hint));
		}
		pthread_mutex_unlock(&s->mtx);
		if (s->hook != NULL && s->hook(s, ev, rb, path))
			return (0);
	}
	(void)dq_serve_tree(s->tree, ev, body, bodylen);
	return (0);
}

static __unused void *
ts_main(void *arg)
{
	struct ts *s = arg;
	struct pollfd pfd;

	while (!s->stop) {
		pfd.fd = s->q;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		(void)dq_dispatch(s->q, ts_handler, s);
	}
	return (NULL);
}

/* A file with contents under dir. */
static __unused void
ts_file(const char *dir, const char *name, const char *data)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	ATF_REQUIRE(write(fd, data, strlen(data)) == (ssize_t)strlen(data));
	close(fd);
}

static __unused void
ts_mkdir(const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	ATF_REQUIRE_MSG(mkdir(path, 0755) == 0, "%s: %s", path,
	    strerror(errno));
}

static __unused void
ts_symlink(const char *dir, const char *name, const char *target)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	ATF_REQUIRE(symlink(target, path) == 0);
}

/*
 * The standard tree: a ("tree\n"), d/, d/f ("f\n"), d/e/, l -> a,
 * ds -> d, abs -> /d/f (an absolute link, inside the served root).
 */
static __unused void
ts_make_tree(const char *dir)
{

	ATF_REQUIRE(mkdir(dir, 0755) == 0);
	ts_file(dir, "a", "tree\n");
	ts_mkdir(dir, "d");
	ts_file(dir, "d/f", "f\n");
	ts_mkdir(dir, "d/e");
	ts_symlink(dir, "l", "a");
	ts_symlink(dir, "ds", "d");
	ts_symlink(dir, "abs", "/d/f");
}

/* Serve dir (made by the caller) with flags | DQ_TREE_F_SERVED. */
static __unused void
ts_start(struct ts *s, const char *dir, uint32_t flags)
{

	memset(s, 0, sizeof(*s));
	if (access("/dev/dq", F_OK) != 0)
		atf_tc_skip("no /dev/dq");
	ATF_REQUIRE(realpath(dir, s->backing) != NULL);
	s->bfd = open(s->backing, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(s->bfd >= 0);
	pthread_mutex_init(&s->mtx, NULL);
	s->q = dq_open();
	ATF_REQUIRE(s->q >= 0);
	s->tree = dq_tree_create(s->q, s->bfd, s->backing,
	    DQ_TREE_F_SERVED | flags);
	ATF_REQUIRE_MSG(s->tree != NULL, "dq_tree_create: %s",
	    strerror(errno));
	ATF_REQUIRE(dq_tree_root(s->tree, &s->sroot, &s->rootid) == 0);
	ATF_REQUIRE(pthread_create(&s->thr, NULL, ts_main, s) == 0);
}

static __unused void
ts_stop(struct ts *s)
{

	s->stop = 1;
	pthread_join(s->thr, NULL);
	if (s->sroot >= 0)
		close(s->sroot);
	dq_tree_destroy(s->tree);
	if (s->q >= 0)
		close(s->q);
	if (s->bfd >= 0)
		close(s->bfd);
}

static __unused int
ts_nev(struct ts *s)
{
	int n;

	pthread_mutex_lock(&s->mtx);
	n = s->nev;
	pthread_mutex_unlock(&s->mtx);
	return (n);
}

/* How many recorded events, from index from, have this op. */
static __unused int
ts_count_op(struct ts *s, int from, uint32_t op)
{
	int i, n;

	n = 0;
	pthread_mutex_lock(&s->mtx);
	for (i = from; i < s->nev; i++)
		if (s->ev[i].op == op)
			n++;
	pthread_mutex_unlock(&s->mtx);
	return (n);
}

typedef void (*ts_child_fn)(void *arg, void *out);

/*
 * Run fn in a pdfork child attached to s->q with the given served starts
 * (-1 for none), sending back outlen bytes of out; returns the child's
 * wait status.  The child closes the controller's root descriptor unless
 * keep_sroot (an inherited served directory counts against chroot).
 */
static __unused int
ts_child_ex(struct ts *s, int rootfd, int cwdfd, bool keep_sroot,
    bool close_before_go, ts_child_fn fn, void *arg, void *out, size_t outlen)
{
	int ready[2], go[2], back[2], pd, status;
	ssize_t n;
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(ready) == 0 && pipe(go) == 0 && pipe(back) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s->q);
		if (!keep_sroot && s->sroot >= 0)
			close(s->sroot);
		/* The backing tree is the controller's, never the child's. */
		if (s->bfd >= 0)
			close(s->bfd);
		(void)write(ready[1], "r", 1);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		fn(arg, out);
		(void)write(back[1], out, outlen);
		_exit(0);
	}
	ATF_REQUIRE(read(ready[0], &c, 1) == 1);
	ATF_REQUIRE_MSG(dq_attach_starts(s->q, pd, rootfd, cwdfd) == 0,
	    "attach: %s", strerror(errno));
	if (close_before_go && s->sroot >= 0) {
		/* The attachment shares the struct file (Q8). */
		close(s->sroot);
		s->sroot = -1;
	}
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	n = read(back[0], out, outlen);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	if (n != (ssize_t)outlen)
		memset(out, 0, outlen);
	close(ready[0]); close(ready[1]);
	close(go[0]); close(go[1]);
	close(back[0]); close(back[1]);
	close(pd);
	return (status);
}

static __unused int
ts_child(struct ts *s, int rootfd, int cwdfd, ts_child_fn fn, void *arg,
    void *out, size_t outlen)
{

	return (ts_child_ex(s, rootfd, cwdfd, false, false, fn, arg, out,
	    outlen));
}

/* An errno of a call: 0 on success. */
#define	TS_ERR(x)	((x) < 0 ? errno : 0)

/* strerror(3) shares one buffer: format each errno into its own. */
#define	TS_CHECK_ERRNO(want, got, what) do {				\
	char _ws[64], _gs[64];						\
	int _w = (want), _g = (got);					\
	(void)strerror_r(_w, _ws, sizeof(_ws));				\
	(void)strerror_r(_g, _gs, sizeof(_gs));				\
	ATF_CHECK_EQ_MSG(_w, _g, "%s: want %d (%s), got %d (%s)",	\
	    (what), _w, _ws, _g, _gs);					\
} while (0)

#endif /* !_DQ_TREE_HARNESS_H_ */
