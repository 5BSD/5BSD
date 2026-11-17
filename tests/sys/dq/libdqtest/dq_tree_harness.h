/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The served-tree harness of the DescriptorQueue tests (dqt_tree.c): a
 * dq_serve_tree() controller thread over a backing tree, its minted root
 * (the served root and cwd ATTACH can give), an event recorder, an
 * optional hook that answers chosen events itself, and attached children
 * that report a fixed-size result through a pipe.  Children never use ATF
 * macros.
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#include "dq_test.h"

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
	struct dqt_server server;	/* the controller thread */
	char		 backing[PATH_MAX];	/* its real path = the prefix */
	pthread_mutex_t	 mtx;
	int		 nev;
	struct ts_ev	 ev[TS_NEV];
	ts_hook_fn	 hook;
	void		*hookarg;
};

/* A file with contents, a directory and a symlink under dir. */
void	ts_file(const char *dir, const char *name, const char *data);
void	ts_mkdir(const char *dir, const char *name);
void	ts_symlink(const char *dir, const char *name, const char *target);
/*
 * The standard tree: a ("tree\n"), d/, d/f ("f\n"), d/e/, l -> a,
 * ds -> d, abs -> /d/f (an absolute link, inside the served root).
 */
void	ts_make_tree(const char *dir);

/* Serve dir (made by the caller) with flags | DQ_TREE_F_SERVED. */
void	ts_start(struct ts *s, const char *dir, uint32_t flags);
void	ts_stop(struct ts *s);
int	ts_nev(struct ts *s);
/* How many recorded events, from index from, have this op. */
int	ts_count_op(struct ts *s, int from, uint32_t op);

typedef void (*ts_child_fn)(void *arg, void *out);

/*
 * Run fn in a pdfork child attached to s->q with the given served starts
 * (-1 for none), sending back outlen bytes of out; returns the child's
 * wait status.  The child closes the controller's root descriptor unless
 * keep_sroot (an inherited served directory counts against chroot).
 */
int	ts_child_ex(struct ts *s, int rootfd, int cwdfd, bool keep_sroot,
	    bool close_before_go, ts_child_fn fn, void *arg, void *out,
	    size_t outlen);
int	ts_child(struct ts *s, int rootfd, int cwdfd, ts_child_fn fn,
	    void *arg, void *out, size_t outlen);

/* An errno of a call: 0 on success. */
#define	TS_ERR(x)	DQT_ERRNO_OF(x)

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
