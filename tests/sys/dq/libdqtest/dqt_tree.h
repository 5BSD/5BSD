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

#ifndef _DQT_TREE_H_
#define	_DQT_TREE_H_

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

#include "dqt.h"

#define	DQT_TREE_TC_HEAD_BODY(name)					\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "180");		\
	}
#define	DQT_TREE_TC(name)	ATF_TC(name); DQT_TREE_TC_HEAD_BODY(name)
#define	DQT_TREE_TC_CLEANUP(name)					\
	ATF_TC_WITH_CLEANUP(name); DQT_TREE_TC_HEAD_BODY(name)

#define	DQT_TREE_NEV		512

/* One recorded RESOLVE event. */
struct dqt_tree_ev {
	uint32_t	op;
	uint32_t	start_kind;
	uint32_t	rclass;
	uint32_t	rflags;
	uint32_t	accept;
	uint64_t	start;
	char		path[256];
	char		hint[256];
};

struct dqt_tree;
/* A hook answers an event itself (returns 1) or leaves it to the tree. */
typedef int (*dqt_tree_hook_fn)(struct dqt_tree *, const struct dq_event *,
    const struct dq_resolve_body *, const char *path);

struct dqt_tree {
	int		 q;
	int		 bfd;		/* the backing tree */
	int		 sroot;		/* the minted root (controller's fd) */
	uint64_t	 rootid;
	struct dq_tree	*tree;
	struct dqt_server server;	/* the controller thread */
	char		 backing[PATH_MAX];	/* its real path = the prefix */
	pthread_mutex_t	 mtx;
	int		 nev;
	struct dqt_tree_ev	 ev[DQT_TREE_NEV];
	dqt_tree_hook_fn	 hook;
	void		*hookarg;
};

/* A file with contents, a directory and a symlink under dir. */
void	dqt_tree_file(const char *dir, const char *name, const char *data);
void	dqt_tree_mkdir(const char *dir, const char *name);
void	dqt_tree_symlink(const char *dir, const char *name, const char *target);
/*
 * The standard tree: a ("tree\n"), d/, d/f ("f\n"), d/e/, l -> a,
 * ds -> d, abs -> /d/f (an absolute link, inside the served root).
 */
void	dqt_tree_make(const char *dir);

/* Serve dir (made by the caller) with flags | DQ_TREE_F_SERVED. */
void	dqt_tree_start(struct dqt_tree *s, const char *dir, uint32_t flags);
void	dqt_tree_stop(struct dqt_tree *s);
int	dqt_tree_nev(struct dqt_tree *s);
/* How many recorded events, from index from, have this op. */
int	dqt_tree_count_op(struct dqt_tree *s, int from, uint32_t op);

typedef void (*dqt_tree_child_fn)(void *arg, void *out);

/*
 * Run fn in a pdfork child attached to s->q with the given served starts
 * (-1 for none), sending back outlen bytes of out; returns the child's
 * wait status.  The child closes the controller's root descriptor unless
 * keep_sroot (an inherited served directory counts against chroot).
 */
int	dqt_tree_child_ex(struct dqt_tree *s, int rootfd, int cwdfd,
	    bool keep_sroot, bool close_before_go, dqt_tree_child_fn fn,
	    void *arg, void *out, size_t outlen);
int	dqt_tree_child(struct dqt_tree *s, int rootfd, int cwdfd,
	    dqt_tree_child_fn fn, void *arg, void *out, size_t outlen);
/* As dqt_tree_child, the child running as uid (set before the attach). */
int	dqt_tree_child_uid(struct dqt_tree *s, int rootfd, int cwdfd, uid_t uid,
	    dqt_tree_child_fn fn, void *arg, void *out, size_t outlen);

#endif /* !_DQT_TREE_H_ */
