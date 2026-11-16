/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The MAC boundary of a served file (D93, D94, B9).
 *
 * fallocate and fspacectl: posix_fallocate(2) and fspacectl(2) now run
 * mac_file_check_write at the boundary for every descriptor type; on a
 * served file that is the only check (no vnode is reached).  The test
 * counts the mac_framework file_check_write probe for the requester's pid
 * with dtrace(1).  It fails where dtrace or the probe is unavailable (the
 * test guests preload dtraceall: under the capability plane a late kldload
 * is denied) or where no policy implements the hook (the guests preload
 * mac_test_hooks, which does): a skip in a plane-on run is not a pass.
 *
 * abac: a served object carries no label of its own; mac_abac evaluates the
 * requester against the label of the controller's credential, captured when
 * the queue was opened.  Fails unless mac_abac is present, its default is
 * allow, and it can be switched to enforcing for the test.
 */

#include <sys/param.h>
#include <sys/mac.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

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

#include "dq_test.h"

#define	DATA_LEN	4096
#define	DTRACE		"/usr/sbin/dtrace"

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

/*
 * A requester that waits for one byte on go before running fn, so a
 * tracer can be attached to its pid first.
 */
struct gated_arg {
	int		 go[2];
	void		(*fn)(void *, void *);
	void		*arg;
};

static void
child_gated(void *arg, void *result)
{
	struct gated_arg *g = arg;
	char b;

	(void)close(g->go[1]);
	if (read(g->go[0], &b, 1) != 1)
		_exit(3);
	g->fn(g->arg, result);
}

/*
 * Count the probes of a mac_framework hook (file_check_write, ...) fired
 * by the requester running fn.
 * Returns the count, or -1 (with a reason) when dtrace cannot trace it.
 */
static long
count_hook(const char *hook, void (*fn)(void *, void *), void *arg,
    void *result,
    size_t resultlen, char *why, size_t whylen)
{
	struct gated_arg g;
	struct dqt_child ch;
	char prog[512], line[256];
	FILE *out;
	long count;
	pid_t dpid;
	int status, pfd[2];
	char b;

	if (access(DTRACE, X_OK) != 0) {
		(void)snprintf(why, whylen, "no %s", DTRACE);
		return (-1);
	}
	ATF_REQUIRE_EQ(0, pipe(g.go));
	g.fn = fn;
	g.arg = arg;
	dqt_spawn(&ch, child_gated, &g);
	(void)close(g.go[0]);
	(void)snprintf(prog, sizeof(prog),
	    "BEGIN { printf(\"ready\\n\"); } "
	    "mac_framework::%s: /pid == %d/ { n++; } "
	    "END { printf(\"count %%d\\n\", n); }", hook, (int)ch.pid);
	ATF_REQUIRE_EQ(0, pipe(pfd));
	dpid = fork();
	ATF_REQUIRE(dpid != -1);
	if (dpid == 0) {
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)dup2(pfd[1], STDERR_FILENO);
		(void)close(pfd[0]);
		execl(DTRACE, "dtrace", "-q", "-n", prog, (char *)NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	out = fdopen(pfd[0], "r");
	ATF_REQUIRE(out != NULL);
	count = -1;
	why[0] = '\0';
	while (fgets(line, sizeof(line), out) != NULL) {
		if (strcmp(line, "ready\n") == 0) {
			count = 0;
			break;
		}
		if (why[0] == '\0')
			(void)strlcpy(why, line, whylen);
	}
	/* Release the requester either way; it must not hang. */
	b = 'g';
	(void)write(g.go[1], &b, 1);
	(void)close(g.go[1]);
	status = dqt_wait(&ch, result, resultlen);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "requester status %#x", status);
	if (count == 0) {
		(void)kill(dpid, SIGINT);
		count = -1;
		while (fgets(line, sizeof(line), out) != NULL) {
			if (sscanf(line, "count %ld", &count) == 1)
				break;
		}
		if (count == -1)
			(void)strlcpy(why, "dtrace printed no count", whylen);
	} else {
		(void)kill(dpid, SIGKILL);
		if (why[0] == '\0')
			(void)strlcpy(why, "dtrace exited before tracing",
			    whylen);
	}
	(void)fclose(out);
	(void)waitpid(dpid, &status, 0);
	return (count);
}

struct space_res {
	struct dqt_rr	 falloc, space, write;
};

static void
child_noop(void *arg __unused, void *result __unused)
{
}

static void
child_real_write(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct space_res *r = result;
	char buf[8];

	memset(buf, 'r', sizeof(buf));
	r->write.rv = pwrite(fd, buf, sizeof(buf), 0);
	r->write.err = r->write.rv == -1 ? errno : 0;
}

static void
child_space(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct space_res *r = result;
	struct spacectl_range rq;

	r->falloc.err = posix_fallocate(fd, 0, DATA_LEN * 2);
	r->falloc.rv = r->falloc.err == 0 ? 0 : -1;
	rq.r_offset = 0;
	rq.r_len = 16;
	r->space.rv = fspacectl(fd, SPACECTL_DEALLOC, &rq, 0, NULL);
	r->space.err = r->space.rv == -1 ? errno : 0;
}

ATF_TC(fallocate_fspacectl_check_write);
ATF_TC_HEAD(fallocate_fspacectl_check_write, tc)
{
	atf_tc_set_md_var(tc, "descr", "D94: posix_fallocate and fspacectl "
	    "on a served file each run mac_file_check_write once at the "
	    "boundary (the mac_framework file_check_write probe, counted for "
	    "the requester's pid)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fallocate_fspacectl_check_write, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct space_res r;
	char why[256];
	long base, n;
	int backing;

	dqt_fill(data, sizeof(data), 1);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(backing);
	backing = open(path, O_RDWR);
	ATF_REQUIRE(backing != -1);

	/*
	 * The requester's own harness write counts too: dqt_spawn returns
	 * the result over a pipe with write(2), which runs the same hook.
	 * Measure that baseline with a requester that does nothing, then
	 * calibrate: a write on the real file must add exactly one.
	 */
	memset(&r, 0, sizeof(r));
	base = count_hook("file_check_write", child_noop, NULL, &r, sizeof(r),
	    why, sizeof(why));
	if (base == -1)
		atf_tc_fail("dtrace: %s", why);
	memset(&r, 0, sizeof(r));
	n = count_hook("file_check_write", child_real_write, &backing, &r,
	    sizeof(r), why, sizeof(why));
	ATF_REQUIRE_MSG(n != -1, "dtrace: %s", why);
	if (n == base)
		atf_tc_fail("no MAC policy implements file_check_write");
	ATF_REQUIRE_EQ(8, r.write.rv);
	ATF_REQUIRE_EQ_MSG(base + 1, n, "calibration: baseline %ld, a real "
	    "write %ld", base, n);

	dqt_init(&c);
	o = dqt_mint_backing(&c, backing, path, NULL, DQ_MINT_F_WRITE);
	memset(&r, 0, sizeof(r));
	n = count_hook("file_check_write", child_space, &o->fd, &r,
	    sizeof(r), why, sizeof(why));
	ATF_REQUIRE_MSG(n != -1, "dtrace: %s", why);
	ATF_CHECK_EQ_MSG(2, n - base, "file_check_write fired %ld times over "
	    "a baseline of %ld", n, base);
	ATF_CHECK_EQ(1, c.events[DQ_OP_FALLOCATE]);
	ATF_CHECK_EQ(1, c.events[DQ_OP_FSPACECTL]);
	dqt_fini(&c);
	(void)close(backing);
}

static void
child_real_read(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct space_res *r = result;
	char buf[8];

	r->write.rv = pread(fd, buf, sizeof(buf), 0);
	r->write.err = r->write.rv == -1 ? errno : 0;
}

static void
child_sendfile_one(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct space_res *r = result;
	off_t sbytes;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		_exit(5);
	sbytes = 0;
	r->space.rv = sendfile(fd, sv[0], 0, 100, NULL, &sbytes, 0);
	r->space.err = r->space.rv == -1 ? errno : (int)sbytes;
	(void)close(sv[0]);
	(void)close(sv[1]);
}

ATF_TC(sendfile_check_read);
ATF_TC_HEAD(sendfile_check_read, tc)
{
	atf_tc_set_md_var(tc, "descr", "N8: sendfile of a served file runs "
	    "mac_file_check_read once (the syscall runs no file hook of its "
	    "own; a vnode is checked by its VOP_READ path)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sendfile_check_read, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct space_res r;
	char why[256];
	long base, n;
	int oracle;

	dqt_fill(data, sizeof(data), 3);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	/* The harness's own reads count too: measure them, then calibrate. */
	memset(&r, 0, sizeof(r));
	base = count_hook("file_check_read", child_noop, NULL, &r, sizeof(r),
	    why, sizeof(why));
	if (base == -1)
		atf_tc_fail("dtrace: %s", why);
	memset(&r, 0, sizeof(r));
	n = count_hook("file_check_read", child_real_read, &oracle, &r,
	    sizeof(r), why, sizeof(why));
	ATF_REQUIRE_MSG(n != -1, "dtrace: %s", why);
	if (n == base)
		atf_tc_fail("no MAC policy implements file_check_read");
	ATF_REQUIRE_EQ_MSG(base + 1, n, "calibration: baseline %ld, a real "
	    "read %ld", base, n);

	dqt_init(&c);
	o = dqt_mint(&c, oracle, path, data, sizeof(data), NULL);
	memset(&r, 0, sizeof(r));
	n = count_hook("file_check_read", child_sendfile_one, &o->fd, &r,
	    sizeof(r), why, sizeof(why));
	ATF_REQUIRE_MSG(n != -1, "dtrace: %s", why);
	ATF_CHECK_EQ_MSG(0, r.space.rv, "sendfile: %d", r.space.err);
	ATF_CHECK_EQ(100, r.space.err);
	ATF_CHECK_EQ_MSG(1, n - base, "file_check_read fired %ld times over "
	    "a baseline of %ld", n, base);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * abac
 */

#define	ABAC_CTL	"/usr/sbin/mac_abac_ctl"
#define	ABAC_STATE	"abac.state"
#define	ABAC_RULES	"abac.rules"

static int
run(const char *cmd, char *out, size_t outlen)
{
	FILE *p;
	size_t n;

	p = popen(cmd, "r");
	if (p == NULL)
		return (-1);
	n = 0;
	if (out != NULL) {
		n = fread(out, 1, outlen - 1, p);
		out[n] = '\0';
	} else {
		char sink[256];

		while (fread(sink, 1, sizeof(sink), p) > 0)
			continue;
	}
	return (pclose(p));
}

static bool
abac_present(void)
{
	size_t len;
	int mode;

	len = sizeof(mode);
	return (sysctlbyname("security.mac.mac_abac.mode", &mode, &len, NULL,
	    0) == 0 && access(ABAC_CTL, X_OK) == 0);
}

struct abac_res {
	struct dqt_rr	 read1, read2, stat2, write2;
	int		 stage;		/* how far the labelled controller got */
};

/* Exit codes of the labelled controller C, past ABAC_C_OK. */
#define	ABAC_C_OK	0
#define	ABAC_C_LABEL	10	/* mac_set_proc to the controller label */
#define	ABAC_C_QUEUE	11	/* dq_open */
#define	ABAC_C_MINT	12	/* dq_mint_file_flags */
#define	ABAC_C_THREAD	13	/* the serving thread */
#define	ABAC_C_FORK	14	/* the requester */
#define	ABAC_C_REQ	15	/* the requester did not exit cleanly */

struct abac_ctl {
	int		 q;
	int		 backing;
	volatile int	 stop;
	struct dq_serve_opts opts;
};

/* C's controller thread: every record to dq_serve_file. */
static void *
abac_serve(void *arg)
{
	struct abac_ctl *a = arg;
	const struct dq_event *ev;
	const void *body;
	struct pollfd pfd;
	size_t bodylen;
	ssize_t got;
	char *buf;

	buf = malloc(256 * 1024);
	if (buf == NULL)
		return (NULL);
	while (!a->stop) {
		pfd.fd = a->q;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		if (dq_read_events(a->q, buf, 256 * 1024, &got) != 0)
			continue;
		for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
		    ev = dq_event_next(buf, (size_t)got, ev)) {
			body = dq_event_body(ev, &bodylen);
			(void)dq_serve_file(a->q, ev, body, bodylen, a->backing,
			    &a->opts);
		}
	}
	free(buf);
	return (NULL);
}

/* R: the requester, with both objects inherited; reports by the pipe. */
static void
abac_requester(int fd1, int fd2, int resfd)
{
	struct abac_res r;
	struct stat sb;
	char buf[16];

	memset(&r, 0, sizeof(r));
	r.stage = 100;
	r.read1.rv = pread(fd1, buf, sizeof(buf), 0);
	r.read1.err = r.read1.rv == -1 ? errno : 0;
	r.read2.rv = pread(fd2, buf, sizeof(buf), 0);
	r.read2.err = r.read2.rv == -1 ? errno : 0;
	r.stat2.rv = fstat(fd2, &sb);
	r.stat2.err = r.stat2.rv == -1 ? errno : 0;
	memset(buf, 'w', sizeof(buf));
	r.write2.rv = pwrite(fd2, buf, sizeof(buf), 0);
	r.write2.err = r.write2.rv == -1 ? errno : 0;
	(void)write(resfd, &r, sizeof(r));
	_exit(0);
}

/*
 * C: the labelled controller.  It takes the denied label, opens queue 2
 * (which captures that credential), mints the backing file writable,
 * serves it, and forks R.  No ATF calls here (this is a forked child),
 * no pipe or file is created after the relabel (each would carry the
 * label the rule denies), and the result goes through the pipe the test
 * made before forking.
 */
static void
abac_controller(int fd1, int resfd, const struct dq_ident_file *ident)
{
	struct abac_ctl a;
	struct dq_policy pol;
	pthread_t thr;
	uint64_t object;
	mac_t label;
	pid_t rpid;
	int fd2, reason, status;

	if (mac_from_text(&label, "mac_abac/type=dqtest_ctl") != 0 ||
	    mac_set_proc(label) != 0)
		_exit(ABAC_C_LABEL);
	mac_free(label);
	memset(&a, 0, sizeof(a));
	a.backing = open(path, O_RDWR | O_CLOEXEC);
	a.q = dq_open();
	if (a.q == -1 || a.backing == -1)
		_exit(ABAC_C_QUEUE);
	dq_policy_default(&pol);
	pol.dp_write = DQ_EVENT;
	if (dq_mint_file_flags(a.q, ident, &pol, DQ_MINT_F_WRITE, &object,
	    &fd2, &reason) != 0)
		_exit(ABAC_C_MINT);
	if (pthread_create(&thr, NULL, abac_serve, &a) != 0)
		_exit(ABAC_C_THREAD);
	rpid = fork();
	if (rpid == -1)
		_exit(ABAC_C_FORK);
	if (rpid == 0)
		abac_requester(fd1, fd2, resfd);
	(void)close(fd2);
	status = 0;
	(void)waitpid(rpid, &status, 0);
	a.stop = 1;
	(void)pthread_join(thr, NULL);
	_exit(WIFEXITED(status) && WEXITSTATUS(status) == 0 ? ABAC_C_OK :
	    ABAC_C_REQ);
}

ATF_TC_WITH_CLEANUP(abac_controller_label);
ATF_TC_HEAD(abac_controller_label, tc)
{
	atf_tc_set_md_var(tc, "descr", "B9: under mac_abac a denying rule "
	    "against the controller credential's label refuses read, write and "
	    "fstat of the objects of a queue opened under that label (EACCES), "
	    "and not those of a queue an unlabelled controller opened");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(abac_controller_label, tc)
{
	struct dqt_ctl c1;
	struct dqt_object *o1;
	struct dq_ident_file *ident;
	struct abac_res r;
	struct statfs sfs;
	struct stat sb;
	char out[256], cmd[512];
	FILE *f;
	unsigned id;
	ssize_t n;
	pid_t cpid;
	int backing, resp[2], status;

	if (!abac_present())
		atf_tc_fail("mac_abac is not present");
	if (run(ABAC_CTL " default", out, sizeof(out)) != 0 ||
	    strstr(out, "allow") == NULL)
		atf_tc_fail("mac_abac default is not allow: %s", out);
	if (run(ABAC_CTL " mode", out, sizeof(out)) != 0)
		atf_tc_fail("mac_abac_ctl mode failed");
	/* Remember the mode for the cleanup. */
	f = fopen(ABAC_STATE, "w");
	ATF_REQUIRE(f != NULL);
	(void)fprintf(f, "%s", strstr(out, "enforcing") != NULL ? "enforcing" :
	    strstr(out, "disabled") != NULL ? "disabled" : "permissive");
	(void)fclose(f);

	dqt_fill(data, sizeof(data), 2);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(backing);
	backing = open(path, O_RDWR);
	ATF_REQUIRE(backing != -1);
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(backing, path, ident, &sb, &sfs);

	/* Queue 1: this process, never relabelled, is its controller. */
	dqt_init(&c1);
	o1 = dqt_mint_backing(&c1, backing, path, NULL, DQ_MINT_F_WRITE);
	/* Every pipe the labelled side needs exists before it is labelled. */
	ATF_REQUIRE_EQ(0, pipe(resp));

	if (run(ABAC_CTL " rule add 'deny read,write,stat * -> "
	    "type=dqtest_ctl'", out, sizeof(out)) != 0 ||
	    sscanf(out, "rule %u added", &id) != 1)
		atf_tc_fail("rule add: %s", out);
	f = fopen(ABAC_RULES, "w");
	ATF_REQUIRE(f != NULL);
	(void)fprintf(f, "%u\n", id);
	(void)fclose(f);
	ATF_REQUIRE_EQ(0, run(ABAC_CTL " mode enforcing", NULL, 0));

	cpid = fork();
	ATF_REQUIRE(cpid != -1);
	if (cpid == 0) {
		(void)close(resp[0]);
		abac_controller(o1->fd, resp[1], ident);
	}
	(void)close(resp[1]);
	memset(&r, 0, sizeof(r));
	n = read(resp[0], &r, sizeof(r));
	(void)close(resp[0]);
	ATF_REQUIRE_EQ(cpid, waitpid(cpid, &status, 0));

	(void)snprintf(cmd, sizeof(cmd), ABAC_CTL " rule remove %u", id);
	(void)run(cmd, NULL, 0);
	(void)run(ABAC_CTL " mode permissive", NULL, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) == ABAC_C_LABEL)
		atf_tc_fail("mac_set_proc to the controller label refused");
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == ABAC_C_OK,
	    "labelled controller status %#x", status);
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(r), n, "result read %zd", n);
	ATF_REQUIRE_EQ(100, r.stage);
	ATF_CHECK_EQ_MSG(16, r.read1.rv, "unlabelled queue read: %s",
	    strerror(r.read1.err));
	ATF_CHECK_EQ(-1, r.read2.rv);
	ATF_CHECK_EQ(EACCES, r.read2.err);
	ATF_CHECK_EQ(-1, r.stat2.rv);
	ATF_CHECK_EQ(EACCES, r.stat2.err);
	ATF_CHECK_EQ(-1, r.write2.rv);
	ATF_CHECK_EQ(EACCES, r.write2.err);
	ATF_CHECK_EQ(1, c1.events[DQ_OP_READ]);
	dqt_fini(&c1);
	free(ident);
	(void)close(backing);
}
ATF_TC_CLEANUP(abac_controller_label, tc)
{
	char cmd[256], mode[32];
	unsigned id;
	FILE *f;

	f = fopen(ABAC_RULES, "r");
	if (f != NULL) {
		if (fscanf(f, "%u", &id) == 1) {
			(void)snprintf(cmd, sizeof(cmd),
			    ABAC_CTL " rule remove %u", id);
			(void)run(cmd, NULL, 0);
		}
		(void)fclose(f);
	}
	f = fopen(ABAC_STATE, "r");
	if (f != NULL) {
		if (fscanf(f, "%31s", mode) == 1) {
			(void)snprintf(cmd, sizeof(cmd), ABAC_CTL " mode %s",
			    mode);
			(void)run(cmd, NULL, 0);
		}
		(void)fclose(f);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fallocate_fspacectl_check_write);
	ATF_TP_ADD_TC(tp, sendfile_check_read);
	ATF_TP_ADD_TC(tp, abac_controller_label);
	return (atf_no_error());
}
