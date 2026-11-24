/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The process boundary today, the half that needs a queue (dq-boundary
 * design, part b0, section 6.1 items 2, 9, 12, 13 and the queue ABI rows
 * of 18): what an UNATTACHED process gets when the process it names is
 * attached to a dq(4) controller, and what the plane's services do with a
 * process descriptor.
 *
 * Today attachment makes no difference to any of it: the boundary slices
 * (b3 visibility, b4 signals and terminals, b5 plane services) are what
 * introduce one, and only for an actor that is itself attached.  An
 * unattached actor, which is every row here, must get these answers after
 * every slice.  The tables are what the kernel of commit f52f6da3d34
 * does, recorded by running this program on it.
 *
 * The test process is the controller (the dq harness answers PASS to
 * every resolution), so it runs with the capability plane on and a
 * /dev/dq; without them the cases fail, they do not skip.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <sys/cap_authority.h>

#include <dev/dq/dq.h>
#include <libdq.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_accounting_proto.h"
#include "mac_capability_capprotect_proto.h"
#include "mac_capability_coalition_proto.h"
#include "mac_capability_identity_proto.h"
#include "mac_capability_node_proto.h"
#include "mac_capability_test_helpers.h"

#include "dqt.h"
#include "procnet_boundary.h"

static char	helper[PATH_MAX];
static char	ktrfile[PATH_MAX];

/* A pin does not skip: the plane and the queue device are there. */
static void
require_plane(void)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 1 };

	len = sizeof(kp);
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), &kp, &len, NULL, 0));
	ATF_REQUIRE_MSG(strcmp(kp.ki_comm, "capsule") == 0, "the capability "
	    "plane is off (PID 1 is %s): this pin runs with it on",
	    kp.ki_comm);
	ATF_REQUIRE_MSG(access("/dev/dq", F_OK) == 0, "/dev/dq: %s",
	    strerror(errno));
}

static void
setup(const atf_tc_t *tc, const char *name)
{
	char dir[PATH_MAX];

	require_plane();
	pn_srcfile(tc, "procnet_boundary_helper", helper, sizeof(helper));
	ATF_REQUIRE_MSG(access(helper, X_OK) == 0, "%s: %s", helper,
	    strerror(errno));
	pn_pubdir(name, dir, sizeof(dir));
	ATF_REQUIRE(chmod(dir, 01777) == 0);
	ATF_REQUIRE((size_t)snprintf(ktrfile, sizeof(ktrfile), "%s/ktrace.out",
	    dir) < sizeof(ktrfile));
}

/* A pdfork child attached to the queue before it runs anything. */
struct attached {
	pid_t		 pid;
	int		 pd;
	int		 go;		/* write a byte: the child goes on */
};

static int
nnp_of(pid_t pid)
{
	int v;

	v = -1;
	if (procctl(P_PID, pid, PROC_NO_NEW_PRIVS_STATUS, &v) != 0)
		return (-errno);
	return (v);
}

static void	held_kill(struct attached *);

/*
 * Every row here is an UNATTACHED actor that attaches its own child.  A
 * test process that is itself attached (the suite run under dqpass by
 * dq_oracle_test) cannot be that actor: its child inherits the attachment
 * and its P2_NO_NEW_PRIVS, and DQ_IOC_ATTACH refuses a process that is
 * attached already with EBUSY (dq(4), "Attachment and resolution", the
 * Attaching and Inheritance paragraphs).  That is a documented refusal,
 * not one of the answers recorded here, so the case is skipped;
 * dqpass.expected names these cases and the two results.
 *
 * no_new_privs alone does not show attachment (a parent may have set it
 * by procctl(2)), so the refusal itself is the evidence.  A test process
 * with no_new_privs whose child can be attached is not attached: the pin
 * that attach sets the flag cannot be made there, and the case fails; so
 * does an attach refused for any other reason.
 */
static void
require_unattached_actor(struct dqt_ctl *c, struct attached *a)
{
	int error;

	if (nnp_of(getpid()) != PROC_NO_NEW_PRIVS_ENABLE)
		return;
	error = dq_attach(c->q, a->pd) == 0 ? 0 : errno;
	held_kill(a);
	if (error == EBUSY)
		atf_tc_skip("the test process is itself attached to a dq(4) "
		    "queue: its child inherits the attachment and cannot be "
		    "attached again (EBUSY, dq(4)); the case needs an "
		    "unattached actor");
	if (error == 0)
		atf_tc_fail("the test process has no_new_privs set but is "
		    "not attached (its child was attached): run it without "
		    "no_new_privs");
	atf_tc_fail("the test process has no_new_privs set and dq_attach "
	    "of its child failed: %s", strerror(error));
}

/*
 * Fork a child that waits for a byte and then runs fn(arg); attach it if
 * c is not NULL.  The child has not exec'd, as attach requires.
 */
static void
held_child(struct dqt_ctl *c, struct attached *a, void (*fn)(void *),
    void *arg)
{
	int go[2];
	char b;

	ATF_REQUIRE_EQ(0, pipe(go));
	a->pid = pdfork(&a->pd, 0);
	ATF_REQUIRE_MSG(a->pid != -1, "pdfork: %s", strerror(errno));
	if (a->pid == 0) {
		(void)close(go[1]);
		if (read(go[0], &b, 1) != 1)
			_exit(PN_X_SETUP);
		(void)close(go[0]);
		fn(arg);
		_exit(PN_X_SETUP);
	}
	(void)close(go[0]);
	a->go = go[1];
	if (c != NULL) {
		require_unattached_actor(c, a);
		ATF_REQUIRE_EQ(PROC_NO_NEW_PRIVS_DISABLE, nnp_of(a->pid));
		ATF_REQUIRE_EQ_MSG(0, dq_attach(c->q, a->pd), "dq_attach: %s",
		    strerror(errno));
		/* The mark attach leaves: the child is attached. */
		ATF_REQUIRE_EQ(PROC_NO_NEW_PRIVS_ENABLE, nnp_of(a->pid));
	}
}

static void
held_go(struct attached *a)
{

	ATF_REQUIRE_EQ(1, write(a->go, "x", 1));
}

static void
held_kill(struct attached *a)
{
	int status;

	(void)pdkill(a->pd, SIGKILL);
	(void)pdwait(a->pd, &status, WEXITED, NULL, NULL);
	(void)close(a->pd);
	(void)close(a->go);
}

struct texec {
	int	in, out;
};

static void
target_exec(void *arg)
{
	struct texec *x = arg;

	bp_target_exec(helper, false, x->in, x->out, PN_UID, PN_GID);
}

/*
 * Item 2.  The table of procnet_boundary_test:probe_same_uid with the
 * one difference that the target is attached to a controller: an
 * unattached actor of the same uid gets the same answers.  b3 hides
 * outside processes from inside actors; it never hides an inside process
 * from an outside one, so this column stays.
 */
ATF_TC_WITH_CLEANUP(probe_attached_target);
ATF_TC_HEAD(probe_attached_target, tc)
{
	atf_tc_set_md_var(tc, "descr", "Every by-pid call of an unattached "
	    "process on an attached process of its own uid");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(probe_attached_target, tc)
{
	struct dqt_ctl c;
	struct attached a;
	struct bp_target t;
	struct bp_args args;
	struct bp_result r;
	struct dq_stats2 st;
	struct texec x;
	int in[2], out[2], want[BP_NROWS];

	setup(tc, "probe_attached_target");
	dqt_init(&c);
	ATF_REQUIRE_EQ(0, pipe(in));
	ATF_REQUIRE_EQ(0, pipe(out));
	x.in = in[0];
	x.out = out[1];
	held_child(&c, &a, target_exec, &x);
	(void)close(in[0]);
	(void)close(out[1]);
	held_go(&a);
	t.pid = a.pid;
	t.in = in[1];
	t.out = out[0];
	bp_target_ready(&t);
	/* It exec'd through the controller and is still attached. */
	ATF_CHECK(dqt_count_resolve(&c, "procnet_boundary_helper", 0) >= 1);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(1, st.ds2_attached);
	ATF_CHECK_EQ(PROC_NO_NEW_PRIVS_ENABLE, nnp_of(a.pid));

	args.pid = t.pid;
	args.tid = t.tid;
	args.ktrfile = ktrfile;
	bp_actor(&args, &r, PN_UID, PN_GID, NULL);
	bp_fill(want, 0);
	bp_check("attached target", &r, want);

	bp_target_end(&t);
	(void)close(a.pd);
	(void)close(a.go);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(probe_attached_target, tc)
{
	pn_pubdir_remove("probe_attached_target");
}

/* --- item 9 ------------------------------------------------------------- */

static int
fork_and_open(void *arg __unused)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (PN_X_SETUP);
	if (pid == 0) {
		(void)open("/nonexistent/dqt-unattached-grandchild", O_RDONLY);
		_exit(errno == ENOENT ? 0 : PN_X_WRONG);
	}
	(void)open("/nonexistent/dqt-unattached-child", O_RDONLY);
	if (errno != ENOENT)
		return (PN_X_WRONG);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (PN_X_WRONG);
	return (WEXITSTATUS(status));
}

static void
pause_fn(void *arg __unused)
{

	for (;;)
		(void)pause();
}

/*
 * Item 9.  A process forked by an unattached parent is unattached: with a
 * controller serving (and one process attached to it, so the queue is
 * live), the lookups of an unattached child and of its own fork post
 * nothing to the queue, and the fork has no P2_NO_NEW_PRIVS.  The launch
 * slices (LA-1 auto-attach) make children of ATTACHED parents attached;
 * this is the control that stays.
 */
ATF_TC_WITHOUT_HEAD(unattached_fork_not_consulted);
ATF_TC_BODY(unattached_fork_not_consulted, tc)
{
	struct dqt_ctl c;
	struct attached a;
	struct dq_stats2 before, after;

	require_plane();
	dqt_init(&c);
	held_child(&c, &a, pause_fn, NULL);
	dqt_stats2(&c, &before);
	ATF_CHECK_EQ(1, before.ds2_attached);
	PN_CHECK_ERRNO(0, pn_child(fork_and_open, NULL, PN_UID, PN_GID),
	    "the unattached child and its fork");
	dqt_stats2(&c, &after);
	ATF_CHECK_EQ(0, dqt_count_resolve(&c, "dqt-unattached", 0));
	ATF_CHECK_EQ(before.ds2_resolves, after.ds2_resolves);
	ATF_CHECK_EQ(before.ds2_events_posted, after.ds2_events_posted);
	ATF_CHECK_EQ(1, after.ds2_attached);
	held_kill(&a);
	dqt_fini(&c);
}

/* --- item 13 ------------------------------------------------------------ */

static void
sigio_nop(int sig __unused)
{
}

static void
sigio_wait_fn(void *arg)
{
	struct timespec ts = { 20, 0 };
	sigset_t set;
	int *ready = arg;

	pn_drop(PN_UID, PN_GID);
	if (write(*ready, "r", 1) != 1)
		_exit(PN_X_SETUP);
	sigemptyset(&set);
	sigaddset(&set, SIGIO);
	_exit(sigtimedwait(&set, NULL, &ts) == SIGIO ? 0 : 1);
}

struct setown {
	int	fd, wfd;
	pid_t	pgid;
};

static int
setown_fn(void *arg)
{
	struct setown *s = arg;

	if (fcntl(s->fd, F_SETOWN, -s->pgid) != 0)
		return (errno);
	if (fcntl(s->fd, F_GETOWN) != -s->pgid)
		return (PN_X_WRONG);
	if (fcntl(s->fd, F_SETFL, O_ASYNC) != 0 || write(s->wfd, "x", 1) != 1)
		return (PN_X_SETUP);
	return (0);
}

/*
 * Item 13.  A process group with one attached and one unattached member,
 * named as the SIGIO owner of a pipe by a third, unattached process of
 * the same uid and session: F_SETOWN is accepted and SIGIO reaches both
 * members.  b4 filters group delivery for an ATTACHED setter (members
 * outside its confinement are passed over); for an unattached setter the
 * whole group still gets the signal.
 */
ATF_TC_WITHOUT_HEAD(sigio_group_with_attached);
ATF_TC_BODY(sigio_group_with_attached, tc)
{
	struct dqt_ctl c;
	struct attached in, out;
	struct setown s;
	sigset_t set;
	int p[2], ready[2], status;
	char b[2];

	require_plane();
	dqt_init(&c);
	/*
	 * SIGIO is ignored by default, and an ignored signal is dropped
	 * when it is sent even if it is blocked: the members need a
	 * handler.  Blocked across the forks: it cannot come too early.
	 */
	ATF_REQUIRE(signal(SIGIO, sigio_nop) != SIG_ERR);
	sigemptyset(&set);
	sigaddset(&set, SIGIO);
	ATF_REQUIRE_EQ(0, sigprocmask(SIG_BLOCK, &set, NULL));
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_REQUIRE_EQ(0, pipe(ready));

	held_child(&c, &in, sigio_wait_fn, &ready[1]);
	held_child(NULL, &out, sigio_wait_fn, &ready[1]);
	ATF_REQUIRE_EQ(0, setpgid(in.pid, in.pid));
	ATF_REQUIRE_EQ(0, setpgid(out.pid, in.pid));
	held_go(&in);
	held_go(&out);
	/* Both have dropped to the setter's uid. */
	ATF_REQUIRE_EQ(1, read(ready[0], &b[0], 1));
	ATF_REQUIRE_EQ(1, read(ready[0], &b[1], 1));

	s.fd = p[0];
	s.wfd = p[1];
	s.pgid = in.pid;
	PN_CHECK_ERRNO(0, pn_child(setown_fn, &s, PN_UID, PN_GID),
	    "F_SETOWN to the mixed group");

	ATF_REQUIRE_EQ(0, pdwait(in.pd, &status, WEXITED, NULL, NULL));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the attached member got no SIGIO (status %#x)", status);
	ATF_REQUIRE_EQ(0, pdwait(out.pd, &status, WEXITED, NULL, NULL));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the unattached member got no SIGIO (status %#x)", status);
	(void)close(in.pd);
	(void)close(out.pd);
	dqt_fini(&c);
}

/* --- items 1-2, Linux ABI ----------------------------------------------- */

static char	linux_prog[PATH_MAX];

struct lexec {
	int	in, out;
};

static void
linux_target_exec(void *arg)
{
	struct lexec *x = arg;

	if (dup2(x->in, 0) != 0 || dup2(x->out, 1) != 1)
		_exit(PN_X_SETUP);
	closefrom(3);
	(void)execl(linux_prog, linux_prog, "target-drop", linux_prog, NULL);
	_exit(PN_X_SETUP);
}

/* The whole of a small text file. */
static void
slurp(const char *path, char *buf, size_t len)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	n = read(fd, buf, len - 1);
	ATF_REQUIRE(n >= 0);
	buf[n] = '\0';
	(void)close(fd);
}

/*
 * Items 1 and 2, Linux ABI.  The by-pid Linux calls of an unattached
 * Linux process of the same uid on a Linux process that IS attached to a
 * controller.  The rows recorded on the kernel of commit f52f6da3d34 are
 * linux_boundary_attached.exp; they are the "live" rows of
 * linux_boundary_test, where the target is not attached.  b3 never hides
 * an inside process from an outside one.
 */
ATF_TC_WITH_CLEANUP(linux_probe_attached_target);
ATF_TC_HEAD(linux_probe_attached_target, tc)
{
	atf_tc_set_md_var(tc, "descr", "Every by-pid Linux call of an "
	    "unattached Linux process on an attached one of its uid");
	atf_tc_set_md_var(tc, "require.user", "root");
	/*
	 * The Linux test data is amd64.  The prober is built here with
	 * the base compiler and linker; a guest without them fails this
	 * case, it does not skip it (the same in linux_boundary_test).
	 */
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(linux_probe_attached_target, tc)
{
	struct dqt_ctl c;
	struct attached a;
	struct lexec x;
	char cmd[3 * PATH_MAX], dir[PATH_MAX], got[8192], outf[PATH_MAX];
	char pidstr[16], src[PATH_MAX], tidstr[16], want[8192];
	pid_t pid;
	int fd, ids[2], in[2], out[2], status;

	require_plane();
	/* A pin does not skip: the Linux ABI is loaded, or this fails. */
	ATF_REQUIRE_MSG(system("kldstat -q -m linux64elf") == 0,
	    "the 64-bit Linux ABI (linux64) is not loaded");
	pn_pubdir("linux_attached", dir, sizeof(dir));
	pn_srcfile(tc, "linux_boundary.c", src, sizeof(src));
	(void)snprintf(linux_prog, sizeof(linux_prog), "%s/linux_boundary",
	    dir);
	(void)snprintf(outf, sizeof(outf), "%s/rows", dir);
	(void)snprintf(cmd, sizeof(cmd), "clang --target=x86_64-linux-gnu "
	    "-fuse-ld=lld -nostdlib -static -fno-stack-protector "
	    "-fno-builtin -O2 -Wall -Wextra -Werror -o %s %s && "
	    "brandelf -t Linux %s", linux_prog, src, linux_prog);
	ATF_REQUIRE_MSG(system(cmd) == 0, "building the Linux program");

	dqt_init(&c);
	ATF_REQUIRE_EQ(0, pipe(in));
	ATF_REQUIRE_EQ(0, pipe(out));
	x.in = in[0];
	x.out = out[1];
	held_child(&c, &a, linux_target_exec, &x);
	(void)close(in[0]);
	(void)close(out[1]);
	held_go(&a);
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(ids), read(out[0], ids,
	    sizeof(ids)), "the Linux target did not report");
	ATF_REQUIRE_EQ(a.pid, ids[0]);
	ATF_CHECK(dqt_count_resolve(&c, "linux_boundary", 0) >= 1);
	ATF_CHECK_EQ(PROC_NO_NEW_PRIVS_ENABLE, nnp_of(a.pid));

	(void)snprintf(pidstr, sizeof(pidstr), "%d", ids[0]);
	(void)snprintf(tidstr, sizeof(tidstr), "%d", ids[1]);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		fd = open(outf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1 || dup2(fd, 1) != 1)
			_exit(PN_X_SETUP);
		(void)alarm(840);
		(void)execl(linux_prog, linux_prog, "probe", pidstr, tidstr,
		    NULL);
		_exit(PN_X_SETUP);
	}
	status = pn_wait(pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "actor status %#x", status);

	slurp(outf, got, sizeof(got));
	pn_srcfile(tc, "linux_boundary_attached.exp", src, sizeof(src));
	slurp(src, want, sizeof(want));
	printf("%s", got);
	ATF_CHECK_STREQ(want, got);

	/* End of file on its stdin: it exits 0, unhurt by the probe. */
	(void)close(in[1]);
	(void)close(out[0]);
	ATF_REQUIRE_EQ(0, pdwait(a.pd, &status, WEXITED, NULL, NULL));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "target status %#x", status);
	(void)close(a.pd);
	(void)close(a.go);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(linux_probe_attached_target, tc)
{
	pn_pubdir_remove("linux_attached");
}

/* --- item 12 ------------------------------------------------------------ */

static int
svc_call(int fd, const void *req, size_t reqlen, const int *req_fds, int nfds,
    void *reply, size_t replylen)
{
	struct mac_capability_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.req_fds = req_fds;
	ca.req_nfds = nfds;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

enum {
	SV_NODE_CONNECT, SV_NODE_CALL, SV_NODE_STATUS, SV_NODE_PID,
	SV_ACCT_CONNECT, SV_ACCT_CALL, SV_ACCT_STATUS,
	SV_IDENT_CONNECT, SV_IDENT_CALL, SV_IDENT_STATUS, SV_IDENT_NONCE,
	SV_COAL_CONNECT, SV_COAL_RESP_CALL, SV_COAL_RESP_STATUS,
	SV_COAL_ENLIST_CALL, SV_COAL_ENLIST_STATUS,
	SV_COAL_RESP2_CALL, SV_COAL_RESP2_STATUS,
	SV_AUTH_NO_ISSUER, SV_AUTH_PD_ISSUER,
	SV_CP_CONNECT, SV_CP_CALL, SV_CP_KILL0,
	SV_N
};

static const char *const sv_names[SV_N] = {
	"node: connect", "node: STAT call", "node: STAT status",
	"node: STAT names the process",
	"accounting: connect", "accounting: GET_RULES call",
	"accounting: GET_RULES status",
	"identity: connect", "identity: QUERY call", "identity: QUERY status",
	"identity: QUERY nonce is not 0",
	"coalition: connect", "coalition: SET_RESPONSIBLE call",
	"coalition: SET_RESPONSIBLE status, target in no coalition",
	"coalition: ENLIST call", "coalition: ENLIST status",
	"coalition: SET_RESPONSIBLE call, target enlisted",
	"coalition: SET_RESPONSIBLE status, target enlisted",
	"authority: CHECK_INVOCATION, no issuer",
	"authority: CHECK_INVOCATION, the procdesc as issuer",
	"capprotect: connect", "capprotect: PROTECT call",
	"kill(pid, 0) by the protector after",
};

/* Every plane service that takes a process descriptor, on pd. */
static void
services(int pd, pid_t pid, int *r, int *coalp)
{
	struct node_request nreq;
	struct node_stat_reply nrep;
	struct acct_get_rules_request greq;
	struct acct_rules_reply grep;
	struct identity_request ireq;
	struct identity_reply irep;
	struct coalition_set_responsible_req rreq;
	struct coalition_req_hdr ereq;
	struct coalition_reply rrep;
	struct cap_authority_check_invocation ci;
	struct cp_request creq;
	int fd, i;

	for (i = 0; i < SV_N; i++)
		r[i] = BP_NA;

	fd = mac_capability_connect("node");
	r[SV_NODE_CONNECT] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		memset(&nreq, 0, sizeof(nreq));
		memset(&nrep, 0xff, sizeof(nrep));
		nreq.op = NODE_OP_STAT;
		r[SV_NODE_CALL] = PN_ERR(svc_call(fd, &nreq, sizeof(nreq), &pd,
		    1, &nrep, sizeof(nrep)));
		if (r[SV_NODE_CALL] == 0) {
			r[SV_NODE_STATUS] = (int)nrep.status;
			r[SV_NODE_PID] = nrep.pid == pid;
		}
		(void)close(fd);
	}

	fd = mac_capability_connect("accounting");
	r[SV_ACCT_CONNECT] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		memset(&greq, 0, sizeof(greq));
		memset(&grep, 0xff, sizeof(grep));
		greq.op = ACCT_OP_GET_RULES;
		r[SV_ACCT_CALL] = PN_ERR(svc_call(fd, &greq, sizeof(greq), &pd,
		    1, &grep, sizeof(grep)));
		if (r[SV_ACCT_CALL] == 0)
			r[SV_ACCT_STATUS] = (int)grep.status;
		(void)close(fd);
	}

	fd = mac_capability_connect("identity");
	r[SV_IDENT_CONNECT] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		memset(&ireq, 0, sizeof(ireq));
		memset(&irep, 0, sizeof(irep));
		ireq.op = IDENTITY_OP_QUERY;
		r[SV_IDENT_CALL] = PN_ERR(svc_call(fd, &ireq, sizeof(ireq),
		    &pd, 1, &irep, sizeof(irep)));
		if (r[SV_IDENT_CALL] == 0) {
			r[SV_IDENT_STATUS] = (int)irep.status;
			r[SV_IDENT_NONCE] = irep.nonce != 0;
		}
		(void)close(fd);
	}

	/*
	 * A fresh coalition; the edge goes with it at close.  The process
	 * descriptor is resolved to its process and the process to the
	 * coalition it is a member of (coalition_resolve_responsible_fd()).
	 * The target is in none at first, so the status is the ESRCH of
	 * coalition_of_proc_ref(): the descriptor did resolve.  Then the
	 * target is enlisted in a second coalition, which the caller keeps
	 * until the target is dead, and a third names it: status 0.
	 */
	fd = mac_capability_connect("coalition");
	r[SV_COAL_CONNECT] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		memset(&rreq, 0, sizeof(rreq));
		memset(&rrep, 0xff, sizeof(rrep));
		rreq.op = COALITION_OP_SET_RESPONSIBLE;
		r[SV_COAL_RESP_CALL] = PN_ERR(svc_call(fd, &rreq, sizeof(rreq),
		    &pd, 1, &rrep, sizeof(rrep)));
		if (r[SV_COAL_RESP_CALL] == 0)
			r[SV_COAL_RESP_STATUS] = rrep.status;
		(void)close(fd);
	}
	*coalp = mac_capability_connect("coalition");
	if (*coalp >= 0) {
		memset(&ereq, 0, sizeof(ereq));
		memset(&rrep, 0xff, sizeof(rrep));
		ereq.op = COALITION_OP_ENLIST;
		r[SV_COAL_ENLIST_CALL] = PN_ERR(svc_call(*coalp, &ereq,
		    sizeof(ereq), &pd, 1, &rrep, sizeof(rrep)));
		if (r[SV_COAL_ENLIST_CALL] == 0)
			r[SV_COAL_ENLIST_STATUS] = rrep.status;
	}
	fd = mac_capability_connect("coalition");
	if (fd >= 0 && r[SV_COAL_ENLIST_STATUS] == 0) {
		memset(&rreq, 0, sizeof(rreq));
		memset(&rrep, 0xff, sizeof(rrep));
		rreq.op = COALITION_OP_SET_RESPONSIBLE;
		r[SV_COAL_RESP2_CALL] = PN_ERR(svc_call(fd, &rreq,
		    sizeof(rreq), &pd, 1, &rrep, sizeof(rrep)));
		if (r[SV_COAL_RESP2_CALL] == 0)
			r[SV_COAL_RESP2_STATUS] = rrep.status;
	}
	if (fd >= 0)
		(void)close(fd);

	/*
	 * Software authority is cap_process(2), not a service.  Only PID 1
	 * can make an issuer, and the issuer is validated before the
	 * process descriptor is looked at: what a plain root process can
	 * reach is the refusal.  These two rows pin the issuer refusal
	 * only; the path that resolves the process descriptor needs a
	 * fixture launched by SwitchBoard and is not pinned here.
	 */
	memset(&ci, 0, sizeof(ci));
	ci.token_fd = -1;
	ci.process_fd = pd;
	ci.process_identity = 1;
	ci.execution_nonce = 1;
	r[SV_AUTH_NO_ISSUER] = PN_ERR(syscall(SYS_cap_process,
	    CAP_AUTH_CHECK_INVOCATION, -1, 0, &ci));
	r[SV_AUTH_PD_ISSUER] = PN_ERR(syscall(SYS_cap_process,
	    CAP_AUTH_CHECK_INVOCATION, pd, 0, &ci));

	/* Last: the shield stays on the target until it exits. */
	fd = mac_capability_connect("capprotect");
	r[SV_CP_CONNECT] = fd < 0 ? errno : 0;
	if (fd >= 0) {
		memset(&creq, 0, sizeof(creq));
		creq.op = CP_OP_PROTECT;
		creq.flags = CP_SF_CORE;
		r[SV_CP_CALL] = PN_ERR(svc_call(fd, &creq, sizeof(creq), &pd,
		    1, NULL, 0));
		r[SV_CP_KILL0] = PN_ERR(kill(pid, 0));
		(void)close(fd);
	}
}

static void
services_check(const char *scenario, const int *got, const int *want)
{
	int i;

	for (i = 0; i < SV_N; i++) {
		printf("%s: %-52s got %d want %d\n", scenario, sv_names[i],
		    got[i], want[i]);
		ATF_CHECK_EQ_MSG(want[i], got[i], "%s: %s: got %d, recorded "
		    "%d", scenario, sv_names[i], got[i], want[i]);
	}
}

/*
 * Item 12.  Each service of the capability plane that resolves a process
 * descriptor to a process (node, accounting, identity, coalition,
 * capprotect; and software authority, a system call), called by an
 * unattached root process with the descriptor of an unattached child and
 * of an attached one: the result and status of the cheapest operation of
 * each.  Today the two columns are the same.  b5 (the plane's process
 * descriptor resolutions, D321) refuses an ATTACHED caller naming an
 * outside process; it does not change either column here.
 */
ATF_TC_WITHOUT_HEAD(plane_services_procdesc);
ATF_TC_BODY(plane_services_procdesc, tc)
{
	/* (-2: not reached) */
	static const int want[SV_N] = {
		0, 0, NODE_STATUS_OK, 1,
		0, 0, ACCT_STATUS_OK,
		0, 0, IDENTITY_STATUS_OK, 1,
		0, 0, ESRCH,
		0, 0, 0, 0,
		EBADF, EINVAL,
		0, 0, 0,
	};
	struct dqt_ctl c;
	struct attached in, out;
	int coal, got[SV_N];

	require_plane();
	dqt_init(&c);
	held_child(NULL, &out, pause_fn, NULL);
	services(out.pd, out.pid, got, &coal);
	services_check("unattached target", got, want);
	held_kill(&out);
	if (coal >= 0)
		(void)close(coal);

	held_child(&c, &in, pause_fn, NULL);
	services(in.pd, in.pid, got, &coal);
	services_check("attached target", got, want);
	held_kill(&in);
	if (coal >= 0)
		(void)close(coal);
	dqt_fini(&c);
}

/* --- the queue ABI rows of item 18 -------------------------------------- */

/*
 * Item 18.  Command 13 of the queue, _IOWR('j', 13, 16 bytes), is
 * DQ_IOC_QUEUE_FLAGS since ux-2 (dq-transparency C8, b02f7856b28): on a
 * queue an all-zero argument (no flag set or cleared) is accepted and
 * returns the old flags, 0.  The row was ENOTTY before C8 and was to flip
 * there; it did not, because the guest stages ran dq_regress binaries
 * built before C8, which hid it.  An observer's descriptor is limited to
 * its own commands and still answers ENOTCAPABLE (the command is not in
 * the observer's ioctl list).
 */
ATF_TC_WITHOUT_HEAD(queue_ioctl_13_flags);
ATF_TC_BODY(queue_ioctl_13_flags, tc)
{
	char arg[16];
	int obs, q;

	require_plane();
	q = dq_open();
	ATF_REQUIRE_MSG(q != -1, "dq_open: %s", strerror(errno));
	obs = dq_mint_observer(q, 0);
	ATF_REQUIRE_MSG(obs != -1, "dq_mint_observer: %s", strerror(errno));
	memset(arg, 0, sizeof(arg));
	ATF_CHECK_EQ_MSG(0, ioctl(q, _IOWR('j', 13, char[16]), arg),
	    "DQ_IOC_QUEUE_FLAGS: %s", strerror(errno));
	/* Not in the observer's ioctl list: refused before dq_ioctl(). */
	PN_EXPECT(ENOTCAPABLE, ioctl(obs, _IOWR('j', 13, char[16]), arg));
	(void)close(obs);
	(void)close(q);
}

/*
 * Item 18.  GET_STATS2 answers ds2_size and ds2_pad0 0 on a queue and on
 * an observer.  The size was 320 until the merge of dev into
 * dq/transparency-1-r2 (6754772dbe2): both branches had used its spare
 * words, and the owner chose (2026-11-19) to grow the struct by one
 * reserved 64-byte line, to 400.  b6c renames ds2_pad0 ds2_qflags and
 * reports the queue's user flag word in it, which is 0 for a queue that
 * set none.
 */
ATF_TC_WITHOUT_HEAD(stats2_size);
ATF_TC_BODY(stats2_size, tc)
{
	struct dq_stats2 st;
	int obs, q;

	require_plane();
	q = dq_open();
	ATF_REQUIRE_MSG(q != -1, "dq_open: %s", strerror(errno));
	obs = dq_mint_observer(q, 0);
	ATF_REQUIRE_MSG(obs != -1, "dq_mint_observer: %s", strerror(errno));
	ATF_CHECK_EQ(400, sizeof(st));
	memset(&st, 0xa5, sizeof(st));
	ATF_REQUIRE_EQ(0, dq_get_stats2(q, &st));
	ATF_CHECK_EQ(400, st.ds2_size);
	ATF_CHECK_EQ(0, st.ds2_pad0);
	memset(&st, 0xa5, sizeof(st));
	ATF_REQUIRE_EQ(0, dq_get_stats2(obs, &st));
	ATF_CHECK_EQ(400, st.ds2_size);
	ATF_CHECK_EQ(0, st.ds2_pad0);
	(void)close(obs);
	(void)close(q);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, probe_attached_target);
	ATF_TP_ADD_TC(tp, unattached_fork_not_consulted);
	ATF_TP_ADD_TC(tp, sigio_group_with_attached);
	ATF_TP_ADD_TC(tp, linux_probe_attached_target);
	ATF_TP_ADD_TC(tp, plane_services_procdesc);
	ATF_TP_ADD_TC(tp, queue_ioctl_13_flags);
	ATF_TP_ADD_TC(tp, stats2_size);
	return (atf_no_error());
}
