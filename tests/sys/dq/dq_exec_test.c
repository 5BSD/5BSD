/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue stage 1c-iii-c: exec under a served root (D167, D175).
 * A tree holds a dynamic program, its libraries and its own copy of the
 * run-time linker.  The image is answered REAL; the ELF interpreter is
 * consulted at the served root and answered REAL of the tree's copy (the
 * test finds that copy among the process's mappings); #! interpreters
 * likewise.  AT_EXECPATH is the name in the served namespace: an absolute
 * name verbatim, a relative one joined lexically to the served cwd's
 * presented path.  An errno for the interpreter kills the new image.
 */

#include <sys/param.h>
#include <sys/user.h>

#include <libutil.h>

#include "dq_tree_harness.h"

#define	HELPER	"dq_exec_helper"

/* Copy src to dir/dst (dst absolute), creating its directories. */
static void
copy_into(const char *dir, const char *src, const char *dst, mode_t mode)
{
	char path[PATH_MAX], buf[65536], *p;
	ssize_t n;
	int in, out;

	snprintf(path, sizeof(path), "%s%s", dir, dst);
	for (p = path + strlen(dir) + 1; (p = strchr(p, '/')) != NULL; p++) {
		*p = '\0';
		(void)mkdir(path, 0755);
		*p = '/';
	}
	in = open(src, O_RDONLY);
	ATF_REQUIRE_MSG(in >= 0, "%s: %s", src, strerror(errno));
	out = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
	ATF_REQUIRE_MSG(out >= 0, "%s: %s", path, strerror(errno));
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE(write(out, buf, n) == n);
	close(in);
	close(out);
}

/* The tree: /bin/helper, its libraries, /libexec/ld-elf.so.1, scripts. */
static void
make_exec_tree(const atf_tc_t *tc, const char *dir)
{
	char helper[PATH_MAX], cmd[PATH_MAX + 64], line[PATH_MAX];
	FILE *f;

	ATF_REQUIRE(mkdir(dir, 0755) == 0);
	snprintf(helper, sizeof(helper), "%s/%s",
	    atf_tc_get_config_var(tc, "srcdir"), HELPER);
	copy_into(dir, helper, "/bin/helper", 0755);
	copy_into(dir, "/libexec/ld-elf.so.1", "/libexec/ld-elf.so.1", 0555);
	snprintf(cmd, sizeof(cmd), "ldd -f '%%p\\n' %s", helper);
	f = popen(cmd, "r");
	ATF_REQUIRE(f != NULL);
	while (fgets(line, sizeof(line), f) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '/')
			copy_into(dir, line, line, 0444);
	}
	pclose(f);
	ts_symlink(dir, "lnk", "bin");
	ts_file(dir, "s.sh", "#!/bin/helper\n");
	ts_file(dir, "rel.sh", "#!bin/helper\n");
	{
		char p[PATH_MAX];

		snprintf(p, sizeof(p), "%s/s.sh", dir);
		ATF_REQUIRE(chmod(p, 0755) == 0);
		snprintf(p, sizeof(p), "%s/rel.sh", dir);
		ATF_REQUIRE(chmod(p, 0755) == 0);
	}
}

struct xrun {
	char	out[4096];
	int	status;
	pid_t	pid;
};

/*
 * Exec path in a child attached with the served root and cwd, after
 * chdir(cwd) when cwd is not NULL; the image's standard output comes
 * back.  With waitfn, it is called with the child's pid while the image
 * waits on its standard input.
 */
static void
xrun(struct ts *s, const char *cwd, const char *path, bool wait,
    void (*waitfn)(struct ts *, pid_t, void *), void *arg, struct xrun *x)
{
	char *argv[3];
	int ready[2], go[2], outp[2], inp[2], pd;
	ssize_t n;
	size_t len;
	pid_t pid;
	char c;

	memset(x, 0, sizeof(*x));
	ATF_REQUIRE(pipe(ready) == 0 && pipe(go) == 0 && pipe(outp) == 0 &&
	    pipe(inp) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(s->q);
		close(s->bfd);
		(void)write(ready[1], "r", 1);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		if (cwd != NULL && chdir(cwd) != 0) {
			dprintf(outp[1], "chdir %d\n", errno);
			_exit(126);
		}
		dup2(outp[1], STDOUT_FILENO);
		dup2(inp[0], STDIN_FILENO);
		/*
		 * The image must not hold the write end of its own standard
		 * input, or it never sees end-of-file.
		 */
		close(inp[1]);
		close(outp[0]);
		argv[0] = __DECONST(char *, path);
		argv[1] = __DECONST(char *, wait ? "wait" : NULL);
		argv[2] = NULL;
		execve(path, argv, NULL);
		dprintf(outp[1], "execve %d\n", errno);
		_exit(127);
	}
	close(outp[1]);
	close(inp[0]);
	ATF_REQUIRE(read(ready[0], &c, 1) == 1);
	ATF_REQUIRE(dq_attach_starts(s->q, pd, s->sroot, s->sroot) == 0);
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	x->pid = pid;
	if (waitfn != NULL) {
		/* The image printed its lines before it waits. */
		len = 0;
		while (len < sizeof(x->out) - 1 && strstr(x->out, "argv") ==
		    NULL && (n = read(outp[0], x->out + len,
		    sizeof(x->out) - 1 - len)) > 0)
			len += n;
		waitfn(s, pid, arg);
	} else
		len = 0;
	close(inp[1]);
	while (len < sizeof(x->out) - 1 &&
	    (n = read(outp[0], x->out + len, sizeof(x->out) - 1 - len)) > 0)
		len += n;
	x->out[len] = '\0';
	ATF_REQUIRE(waitpid(pid, &x->status, 0) == pid);
	close(outp[0]);
	close(ready[0]); close(ready[1]);
	close(go[0]); close(go[1]);
	close(pd);
}

static void
check_line(const struct xrun *x, const char *want)
{

	ATF_CHECK_MSG(strstr(x->out, want) != NULL,
	    "\"%s\" not in output:\n%s", want, x->out);
}

TS_TC(exec_default_eacces);
ATF_TC_BODY(exec_default_eacces, tc)
{
	struct ts s;
	struct xrun x;

	make_exec_tree(tc, "t");
	ts_start(&s, "t", DQ_TREE_F_ROOT);
	xrun(&s, NULL, "/bin/helper", false, NULL, NULL, &x);
	check_line(&x, "execve 13\n");
	ts_stop(&s);
}

TS_TC(exec_real_execpath);
ATF_TC_BODY(exec_real_execpath, tc)
{
	struct ts s;
	struct xrun x;

	make_exec_tree(tc, "t");
	ts_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_EXEC_REAL);
	/* An absolute name: verbatim. */
	xrun(&s, NULL, "/bin/helper", false, NULL, NULL, &x);
	ATF_CHECK(WIFEXITED(x.status) && WEXITSTATUS(x.status) == 0);
	check_line(&x, "execpath=/bin/helper\n");
	check_line(&x, "cwd=/\n");
	/* A relative name: joined to the served cwd. */
	xrun(&s, "/bin", "./helper", false, NULL, NULL, &x);
	ATF_CHECK(WIFEXITED(x.status) && WEXITSTATUS(x.status) == 0);
	check_line(&x, "execpath=/bin/helper\n");
	check_line(&x, "cwd=/bin\n");
	/*
	 * Through a symlinked served directory: the lexical join keeps the
	 * link (documented; IS_PATH would give the resolved name).
	 */
	xrun(&s, "/", "lnk/helper", false, NULL, NULL, &x);
	ATF_CHECK(WIFEXITED(x.status) && WEXITSTATUS(x.status) == 0);
	check_line(&x, "execpath=/lnk/helper\n");
	ts_stop(&s);
}

struct interp_arg {
	char	want[PATH_MAX];
	bool	found;
};

static void
find_interp(struct ts *s __unused, pid_t pid, void *arg)
{
	struct interp_arg *a = arg;
	struct kinfo_vmentry *kve;
	int cnt, i;

	kve = kinfo_getvmmap(pid, &cnt);
	if (kve == NULL)
		return;
	for (i = 0; i < cnt; i++)
		if (strcmp(kve[i].kve_path, a->want) == 0)
			a->found = true;
	free(kve);
}

TS_TC(interp_from_tree);
ATF_TC_BODY(interp_from_tree, tc)
{
	struct ts s;
	struct xrun x;
	struct interp_arg a;
	struct ts_ev *e;
	int i, n;

	make_exec_tree(tc, "t");
	ts_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_EXEC_REAL);
	memset(&a, 0, sizeof(a));
	snprintf(a.want, sizeof(a.want), "%s/libexec/ld-elf.so.1", s.backing);
	xrun(&s, NULL, "/bin/helper", true, find_interp, &a, &x);
	ATF_CHECK(WIFEXITED(x.status) && WEXITSTATUS(x.status) == 0);
	ATF_CHECK_MSG(a.found, "%s is not mapped: the interpreter did not "
	    "come from the tree", a.want);
	/* The interpreter was consulted at the served root (class 3). */
	n = 0;
	pthread_mutex_lock(&s.mtx);
	for (i = 0; i < s.nev; i++) {
		e = &s.ev[i];
		if (e->op != DQ_ROP_EXEC_INTERP)
			continue;
		n++;
		ATF_CHECK_EQ(DQ_START_SERVED, e->start_kind);
		ATF_CHECK_EQ(s.rootid, e->start);
		ATF_CHECK_EQ(DQ_RCLASS_KERNEL, e->rclass);
		ATF_CHECK_EQ(DQ_RACCEPT(DQ_RESOLVE_REAL), e->accept);
	}
	pthread_mutex_unlock(&s.mtx);
	ATF_CHECK(n >= 1);
	ts_stop(&s);
}

TS_TC(shell_interp);
ATF_TC_BODY(shell_interp, tc)
{
	struct ts s;
	struct xrun x;

	make_exec_tree(tc, "t");
	ts_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_EXEC_REAL);
	/* #! from the tree: the interpreter runs with the script. */
	xrun(&s, NULL, "/s.sh", false, NULL, NULL, &x);
	ATF_CHECK(WIFEXITED(x.status) && WEXITSTATUS(x.status) == 0);
	check_line(&x, "argv0=/bin/helper\n");
	check_line(&x, "argv1=/s.sh\n");
	check_line(&x, "execpath=/bin/helper\n");
	/* A relative #! interpreter under a served cwd: EXDEV (D175). */
	xrun(&s, NULL, "/rel.sh", false, NULL, NULL, &x);
	check_line(&x, "execve 18\n");
	ts_stop(&s);
}

static int
interp_enoent(struct ts *s, const struct dq_event *ev,
    const struct dq_resolve_body *rb, const char *path __unused)
{

	if (rb->drs_op != DQ_ROP_EXEC_INTERP)
		return (0);
	(void)dq_reply_resolve_errno(s->q, ev->de_id, ENOENT);
	return (1);
}

/*
 * The interpreter is consulted after exec_new_vmspace: an errno kills
 * the new image (the old one is gone), as 1c-i's class-3 lookups do.
 */
TS_TC(interp_errno_kills);
ATF_TC_BODY(interp_errno_kills, tc)
{
	struct ts s;
	struct xrun x;

	make_exec_tree(tc, "t");
	ts_start(&s, "t", DQ_TREE_F_ROOT | DQ_TREE_F_EXEC_REAL);
	s.hook = interp_enoent;
	xrun(&s, NULL, "/bin/helper", false, NULL, NULL, &x);
	ATF_CHECK_MSG(WIFSIGNALED(x.status), "status %#x, output:\n%s",
	    x.status, x.out);
	ATF_CHECK(strstr(x.out, "execve") == NULL);
	ts_stop(&s);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, exec_default_eacces);
	ATF_TP_ADD_TC(tp, exec_real_execpath);
	ATF_TP_ADD_TC(tp, interp_from_tree);
	ATF_TP_ADD_TC(tp, shell_interp);
	ATF_TP_ADD_TC(tp, interp_errno_kills);
	return (atf_no_error());
}
