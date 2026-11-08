/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-b audit records (D151, plan 4.13): a lookup
 * from a served directory records the start object ("dq_start"), a
 * served descriptor answered records its object ("dq_object"), and a
 * REAL rewrite records the rewritten path.  The controller is a thread
 * serving a backing tree with dq_serve_tree()'s iii-b mode; the attached
 * child makes the calls; the audit pipe is the oracle (utils.c).
 */

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

#include "utils.h"

static struct pollfd fds[1];
static FILE *pipestream;

struct srv {
	int		 q;
	int		 rootfd;
	int		 sroot;
	char		 backing[PATH_MAX];
	struct dq_tree	*tree;
	pthread_t	 thr;
	volatile int	 stop;
};

static int
srv_handler(int q, const struct dq_event *ev, const void *body,
    size_t bodylen, void *arg)
{
	struct srv *s = arg;
	const struct dq_resolve_body *rb;
	const char *path;
	char real[PATH_MAX];

	(void)q;
	/* "realname" is answered REAL with the backing "a" (D167). */
	if (ev->de_op == DQ_OP_RESOLVE &&
	    dq_event_resolve(ev, &rb, &path, NULL, NULL, NULL) == 0 &&
	    strcmp(path, "realname") == 0) {
		snprintf(real, sizeof(real), "%s/realtarget_dq", s->backing);
		(void)dq_reply_resolve_real(s->q, ev->de_id, real);
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

	while (!s->stop) {
		pfd.fd = s->q;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		(void)dq_dispatch(s->q, srv_handler, s);
	}
	return (NULL);
}

static void
srv_start(struct srv *s)
{
	char cwd[PATH_MAX], prefix[PATH_MAX];
	int fd;

	if (access("/dev/dq", F_OK) != 0)
		atf_tc_skip("no /dev/dq");
	memset(s, 0, sizeof(*s));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(s->backing, sizeof(s->backing), "%s/backing", cwd);
	snprintf(prefix, sizeof(prefix), "%s/served", cwd);
	ATF_REQUIRE(mkdir(s->backing, 0755) == 0);
	fd = open("backing/a", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	fd = open("backing/realtarget_dq", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	s->rootfd = open(s->backing, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(s->rootfd >= 0);
	s->q = dq_open();
	ATF_REQUIRE(s->q >= 0);
	s->tree = dq_tree_create(s->q, s->rootfd, prefix, DQ_TREE_F_SERVED);
	ATF_REQUIRE(s->tree != NULL);
	ATF_REQUIRE(dq_tree_root(s->tree, &s->sroot, NULL) == 0);
	ATF_REQUIRE(pthread_create(&s->thr, NULL, srv_main, s) == 0);
}

static void
srv_stop(struct srv *s)
{

	s->stop = 1;
	pthread_join(s->thr, NULL);
	close(s->sroot);
	dq_tree_destroy(s->tree);
	close(s->q);
	close(s->rootfd);
}

/* Run fn in an attached child. */
static void
run_attached(struct srv *s, void (*fn)(struct srv *))
{
	int go[2], pd, status;
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(go) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s->q);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		fn(s);
		_exit(0);
	}
	ATF_REQUIRE_MSG(dq_attach(s->q, pd) == 0, "attach: %s",
	    strerror(errno));
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	close(pd);
	close(go[0]);
	close(go[1]);
}

static void
c_stat(struct srv *s)
{
	struct stat st;

	(void)fstatat(s->sroot, "a", &st, 0);
}

static void
c_open(struct srv *s)
{

	(void)openat(s->sroot, "a", O_RDONLY);
}

static void
c_real(struct srv *s)
{
	struct stat st;

	(void)fstatat(s->sroot, "realname", &st, 0);
}

ATF_TC_WITH_CLEANUP(served_start_stat);
ATF_TC_HEAD(served_start_stat, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstatat(2) from a served directory "
	    "records the start object (dq_start) and the path as given");
}
ATF_TC_BODY(served_start_stat, tc)
{
	struct srv s;

	srv_start(&s);
	pipestream = setup(fds, "fa");
	run_attached(&s, c_stat);
	/* The path token is the name as given ("a"), then dq_start. */
	check_audit(fds, "fstatat.*,path,a,.*dq_start", pipestream);
	srv_stop(&s);
}
ATF_TC_CLEANUP(served_start_stat, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(served_object_open);
ATF_TC_HEAD(served_object_open, tc)
{
	atf_tc_set_md_var(tc, "descr", "openat(2) answered with a served file "
	    "records the start (dq_start) and the object (dq_object)");
}
ATF_TC_BODY(served_object_open, tc)
{
	struct srv s;

	srv_start(&s);
	pipestream = setup(fds, "fr");
	run_attached(&s, c_open);
	check_audit(fds, "openat.*dq_start.*dq_object", pipestream);
	srv_stop(&s);
}
ATF_TC_CLEANUP(served_object_open, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(real_rewrite_path);
ATF_TC_HEAD(real_rewrite_path, tc)
{
	atf_tc_set_md_var(tc, "descr", "a REAL answer records the rewritten "
	    "path (the backing file), not the name given");
}
ATF_TC_BODY(real_rewrite_path, tc)
{
	struct srv s;

	srv_start(&s);
	pipestream = setup(fds, "fa");
	run_attached(&s, c_real);
	/*
	 * The rewritten path, unique to this answer, in the same record as
	 * the served start's token.
	 */
	check_audit(fds, "fstatat.*,path,[^,]*/backing/realtarget_dq,"
	    ".*dq_start", pipestream);
	srv_stop(&s);
}
ATF_TC_CLEANUP(real_rewrite_path, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, served_start_stat);
	ATF_TP_ADD_TC(tp, served_object_open);
	ATF_TP_ADD_TC(tp, real_rewrite_path);
	return (atf_no_error());
}
