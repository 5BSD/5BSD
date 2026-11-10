/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * DQ_IOC_ATTACH (stage 1c-i, D138, D147, D148, D150): who can be attached,
 * what the attachment does to the process, and how it is inherited.  An
 * attached process's lookups post RESOLVE events the harness answers PASS;
 * a lookup of a path carrying a unique tag shows whether a process is
 * attached (the event names the tag and carries DQ_CALLER_F_ATTACHED).
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

/* A stat(2) of a path naming the tag: posts STAT when attached. */
static int
probe_lookup(const char *tag)
{
	struct stat sb;
	char p[64];

	(void)snprintf(p, sizeof(p), "dqt-probe-%s", tag);
	return (stat(p, &sb) == -1 ? errno : 0);
}

struct basic_res {
	int		 probe;
	int		 nnp_rv, nnp;
};

static void
child_basic(void *arg __unused, void *result)
{
	struct basic_res *r = result;

	r->probe = probe_lookup("basic");
	r->nnp_rv = procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS, &r->nnp);
}

ATF_TC(attach_basic);
ATF_TC_HEAD(attach_basic, tc)
{
	atf_tc_set_md_var(tc, "descr", "a pdforked child that has not exec'd "
	    "is attached: its lookups post RESOLVE (class USER, caller "
	    "ATTACHED) and PASS keeps their real result; ATTACH sets "
	    "P2_NO_NEW_PRIVS; ds2_attached counts it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(attach_basic, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct basic_res r;
	struct dq_stats2 st;
	int i, status;

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_basic, NULL);
	memset(&r, 0, sizeof(r));
	status = dqt_attach_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(ENOENT, r.probe);		/* PASS: the real answer */
	ATF_CHECK_EQ(0, r.nnp_rv);
	ATF_CHECK_EQ(PROC_NO_NEW_PRIVS_ENABLE, r.nnp);
	i = dqt_find_resolve(&c, "dqt-probe-basic", DQ_ROP_STAT, 0);
	ATF_REQUIRE_MSG(i != -1, "no RESOLVE STAT for the probe");
	ATF_CHECK_EQ(DQ_RCLASS_USER, c.rs[i].cls);
	ATF_CHECK((c.rs[i].rflags & DQ_RF_USER) != 0);
	ATF_CHECK((c.rs[i].caller_flags & DQ_CALLER_F_ATTACHED) != 0);
	ATF_CHECK_EQ(ch.pid, c.rs[i].pid);
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "dqt-probe-basic", 0));
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(1, st.ds2_attached);
	ATF_CHECK(st.ds2_resolves >= 1);
	ATF_CHECK(st.ds2_resolve_pass >= 1);
	ATF_CHECK_EQ(0, st.ds2_resolve_unmarked);
	dqt_fini(&c);
}

/* A pdfork child that waits on a pipe until told to exit (or exec). */
struct idle {
	pid_t		 pid;
	int		 pd;
	int		 go[2];
};

static void
idle_spawn(struct idle *s, int rfflags, const char *exec_path)
{
	char b;

	ATF_REQUIRE_EQ(0, pipe(s->go));
	if (rfflags != 0)
		s->pid = pdrfork(&s->pd, 0, rfflags);
	else
		s->pid = pdfork(&s->pd, 0);
	ATF_REQUIRE_MSG(s->pid != -1, "pdfork: %s", strerror(errno));
	if (s->pid == 0) {
		if (exec_path != NULL) {
			execl(exec_path, exec_path, "30", (char *)NULL);
			_exit(3);
		}
		(void)read(s->go[0], &b, 1);
		_exit(0);
	}
}

static void
idle_end(struct idle *s)
{
	int status;

	(void)write(s->go[1], "x", 1);
	(void)pdkill(s->pd, SIGKILL);
	(void)pdwait(s->pd, &status, WEXITED, NULL, NULL);
	(void)close(s->pd);
	(void)close(s->go[0]);
	(void)close(s->go[1]);
}

#define	REFUSED(call, want) do {					\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "%s succeeded", #call);		\
	ATF_CHECK_EQ_MSG((want), errno, "%s: errno %d want %d", #call,	\
	    errno, (want));						\
} while (0)

ATF_TC(attach_refusals);
ATF_TC_HEAD(attach_refusals, tc)
{
	atf_tc_set_md_var(tc, "descr", "ATTACH refuses: a descriptor that is "
	    "not a process descriptor, a wrong version, flags, served start "
	    "fds (EINVAL); itself, a child that exec'd, one already attached "
	    "(here or to another queue), one holding the queue, one sharing "
	    "the descriptor table (rfork without RFFDG) (EBUSY); an exited "
	    "child (ESRCH)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(attach_refusals, tc)
{
	struct dqt_ctl c, c2;
	struct dq_attach_args args;
	struct idle s;
	struct kevent kev;
	struct timespec ts = { 5, 0 };
	int fd, kq, qdup, self, status;

	dqt_init(&c);
	dqt_init_manual(&c2);

	/* Not a process descriptor; malformed arguments. */
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	REFUSED(dq_attach(c.q, fd), EINVAL);
	(void)close(fd);
	idle_spawn(&s, 0, NULL);
	memset(&args, 0, sizeof(args));
	args.da_version = DQ_API_VERSION + 1;
	args.da_procfd = s.pd;
	args.da_rootfd = args.da_cwdfd = -1;
	REFUSED(ioctl(c.q, DQ_IOC_ATTACH, &args), EINVAL);
	/* Version 1 had a 96-byte RESOLVE body: refused (D184). */
	ATF_REQUIRE_EQ(2, DQ_API_VERSION);
	args.da_version = 1;
	REFUSED(ioctl(c.q, DQ_IOC_ATTACH, &args), EINVAL);
	args.da_version = DQ_API_VERSION;
	args.da_flags = ~(uint32_t)DQ_ATTACH_F_NODIRS;	/* undefined bits */
	REFUSED(ioctl(c.q, DQ_IOC_ATTACH, &args), EINVAL);
	args.da_flags = 0;
	args.da_rootfd = 0;	/* not a served directory */
	REFUSED(ioctl(c.q, DQ_IOC_ATTACH, &args), EINVAL);
	args.da_rootfd = -1;
	args.da_pad0 = 1;
	REFUSED(ioctl(c.q, DQ_IOC_ATTACH, &args), EINVAL);

	/* Attached once; again here or elsewhere is EBUSY. */
	ATF_REQUIRE_EQ(0, dq_attach(c.q, s.pd));
	REFUSED(dq_attach(c.q, s.pd), EBUSY);
	REFUSED(dq_attach(c2.q, s.pd), EBUSY);
	idle_end(&s);

	/* Itself. */
	self = pdopenpid(getpid(), 0);
	if (self != -1) {
		REFUSED(dq_attach(c.q, self), EBUSY);
		(void)close(self);
	}

	/* A child that exec'd (P_EXEC). */
	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	idle_spawn(&s, 0, "/bin/sleep");
	EV_SET(&kev, s.pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXEC, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == 0) {
		ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &ts));
		REFUSED(dq_attach(c.q, s.pd), EBUSY);
	}
	idle_end(&s);
	(void)close(kq);

	/* A child holding the queue (a copy without close-on-fork). */
	qdup = fcntl(c.q, F_DUPFD, 0);
	ATF_REQUIRE(qdup != -1);
	idle_spawn(&s, 0, NULL);
	REFUSED(dq_attach(c.q, s.pd), EBUSY);
	idle_end(&s);
	(void)close(qdup);

	/*
	 * A child sharing the descriptor table.  No native route shares the
	 * descriptor table alone: rfork(2) without RFFDG or RFCFDG shares both
	 * the table and the pwddesc, so this case is refused by pd_procs as
	 * well as by fd_refcnt.  The table-only route is Linux clone(2) with
	 * CLONE_FILES and without CLONE_FS, which needs the Linux ABI and is
	 * not tested here.
	 */
	idle_spawn(&s, RFPROC | RFPROCDESC, NULL);
	REFUSED(dq_attach(c.q, s.pd), EBUSY);
	idle_end(&s);

	/* An exited child (not reaped: the descriptor still names it). */
	idle_spawn(&s, 0, NULL);
	(void)write(s.go[1], "x", 1);
	ATF_REQUIRE_EQ(0, pdwait(s.pd, &status, WEXITED, NULL, NULL));
	REFUSED(dq_attach(c.q, s.pd), ESRCH);
	(void)close(s.pd);
	(void)close(s.go[0]);
	(void)close(s.go[1]);

	dqt_fini(&c2);
	dqt_fini(&c);
}

enum inh { INH_FORK, INH_VFORK, INH_RFFDG, INH_RFCFDG_PROC, INH_PDFORK,
    INH_RFCFDG_SELF, INH_NKINDS };
static const char *const inh_tag[INH_NKINDS] = { "fork", "vfork", "rffdg",
    "rfcfdg", "pdfork", "selfcfdg" };

struct inh_res {
	int		 probe[INH_NKINDS];
	pid_t		 pid[INH_NKINDS];
};

/* Each kind of child probes once; the results come back by exit status. */
static void
child_inherit(void *arg __unused, void *result)
{
	struct inh_res *r = result;
	pid_t pid;
	int k, pd, status;

	for (k = 0; k < INH_NKINDS; k++) {
		pd = -1;
		switch (k) {
		case INH_FORK:
			pid = fork();
			break;
		case INH_VFORK:
			pid = vfork();
			if (pid == 0)
				_exit(probe_lookup(inh_tag[k]));
			break;
		case INH_RFFDG:
			pid = rfork(RFPROC | RFFDG);
			break;
		case INH_RFCFDG_PROC:
			pid = rfork(RFPROC | RFCFDG);
			break;
		case INH_PDFORK:
			pid = pdfork(&pd, 0);
			break;
		default:
			/*
			 * A process replacing its own table and pwddesc
			 * (rfork(RFCFDG) without RFPROC, pd_replace): in a
			 * child of its own, since a clean table loses the
			 * result pipe.
			 */
			pid = fork();
			if (pid == 0)
				_exit(rfork(RFCFDG) == 0 ?
				    probe_lookup(inh_tag[k]) : 99);
			break;
		}
		if (pid == 0)
			_exit(probe_lookup(inh_tag[k]));
		r->pid[k] = pid;
		if (pd != -1) {
			(void)pdwait(pd, &status, WEXITED, NULL, NULL);
			(void)close(pd);
		} else
			(void)waitpid(pid, &status, 0);
		r->probe[k] = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}
}

ATF_TC(inheritance);
ATF_TC_HEAD(inheritance, tc)
{
	atf_tc_set_md_var(tc, "descr", "the attachment is inherited by fork, "
	    "vfork, rfork(RFFDG), rfork(RFCFDG|RFPROC) and pdfork children, "
	    "and survives rfork(RFCFDG) without RFPROC replacing the "
	    "process's own table: each one's lookup posts RESOLVE as that "
	    "process, attached");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(inheritance, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct inh_res r;
	char tag[64];
	int i, k, status;

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_inherit, NULL);
	memset(&r, 0, sizeof(r));
	status = dqt_attach_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	for (k = 0; k < INH_NKINDS; k++) {
		(void)snprintf(tag, sizeof(tag), "dqt-probe-%s", inh_tag[k]);
		ATF_CHECK_EQ_MSG(ENOENT, r.probe[k], "%s: probe %d", inh_tag[k],
		    r.probe[k]);
		i = dqt_find_resolve(&c, tag, DQ_ROP_STAT, 0);
		ATF_CHECK_MSG(i != -1, "%s: not consulted", inh_tag[k]);
		if (i == -1)
			continue;
		ATF_CHECK_EQ_MSG(r.pid[k], c.rs[i].pid, "%s: pid", inh_tag[k]);
		ATF_CHECK((c.rs[i].caller_flags & DQ_CALLER_F_ATTACHED) != 0);
	}
	dqt_fini(&c);
}

ATF_TC(failed_exec_still_attachable);
ATF_TC_HEAD(failed_exec_still_attachable, tc)
{
	atf_tc_set_md_var(tc, "descr", "a child whose exec failed has not "
	    "exec'd (P_EXEC is set only at the commit point) and can be "
	    "attached");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(failed_exec_still_attachable, tc)
{
	struct dqt_ctl c;
	struct idle s;
	struct dqt_sync y;
	char b;

	dqt_init(&c);
	dqt_sync_init(&y);
	ATF_REQUIRE_EQ(0, pipe(s.go));
	s.pid = pdfork(&s.pd, 0);
	ATF_REQUIRE(s.pid != -1);
	if (s.pid == 0) {
		(void)execl("/nonexistent/dqt", "dqt", (char *)NULL);
		dqt_sync_post(y.toparent[1]);
		(void)read(s.go[0], &b, 1);
		_exit(0);
	}
	ATF_REQUIRE(dqt_sync_wait(y.toparent[0], DQT_WAIT_MS));
	ATF_CHECK_EQ_MSG(0, dq_attach(c.q, s.pd), "ATTACH: %s",
	    strerror(errno));
	idle_end(&s);
	dqt_fini(&c);
}

/*
 * An attached child that proves it is attached (a probe lookup), tells the
 * parent, and then exits 3 or sleeps until a signal ends it.
 */
struct exit_arg {
	const char	*tag;
	int		 ready;		/* write end */
	bool		 sleep;
};

static void
child_exit_status(void *arg, void *result __unused)
{
	struct exit_arg *a = arg;
	sigset_t none;
	char b;

	b = probe_lookup(a->tag) == ENOENT ? 'a' : 'x';
	if (write(a->ready, &b, 1) != 1)
		_exit(98);
	if (!a->sleep)
		_exit(3);
	/* The parent's mask blocks everything; this process takes signals. */
	sigemptyset(&none);
	(void)sigprocmask(SIG_SETMASK, &none, NULL);
	for (;;)
		pause();
}

static void
sigchld_noop(int sig __unused)
{
}

/* Take the one pending SIGCHLD; nothing else may be pending afterwards. */
static void
one_sigchld(const char *what, pid_t pid, int code, int st)
{
	struct timespec ts = { 5, 0 };
	sigset_t chld, pend;
	siginfo_t si;
	int sig;

	sigemptyset(&chld);
	sigaddset(&chld, SIGCHLD);
	memset(&si, 0, sizeof(si));
	ATF_REQUIRE_MSG(sigtimedwait(&chld, &si, &ts) == SIGCHLD,
	    "%s: no SIGCHLD: %s", what, strerror(errno));
	ATF_CHECK_EQ_MSG(pid, si.si_pid, "%s: si_pid %d", what, si.si_pid);
	ATF_CHECK_EQ_MSG(code, si.si_code, "%s: si_code %d", what,
	    si.si_code);
	ATF_CHECK_EQ_MSG(st, si.si_status, "%s: si_status %d", what,
	    si.si_status);
	dqt_msleep(100);
	sigemptyset(&pend);
	ATF_REQUIRE_EQ(0, sigpending(&pend));
	for (sig = 1; sig < NSIG; sig++)
		ATF_CHECK_MSG(!sigismember(&pend, sig),
		    "%s: signal %d is pending as well", what, sig);
}

ATF_TC(attached_exit_status);
ATF_TC_HEAD(attached_exit_status, tc)
{
	atf_tc_set_md_var(tc, "descr", "an attached child that exits 3, and "
	    "one killed by a plain kill(SIGTERM), are reported to the parent "
	    "as any child is: one SIGCHLD each, waitpid status 3 and "
	    "SIGTERM, no other signal");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(attached_exit_status, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct dq_stats2 st;
	struct exit_arg a;
	struct sigaction sa;
	sigset_t all, old;
	int ready[2], status;
	char b;

	dqt_require_plane();
	/* Every signal blocked, the reader thread's too: all stay pending. */
	sigfillset(&all);
	ATF_REQUIRE_EQ(0, sigprocmask(SIG_BLOCK, &all, &old));
	/*
	 * SIGCHLD needs a handler to be counted at all: one whose action
	 * is the default (ignore) is discarded when posted, blocked or not.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_noop;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGCHLD, &sa, NULL));
	dqt_init(&c);
	ATF_REQUIRE_EQ(0, pipe(ready));
	a.ready = ready[1];

	/* _exit(3). */
	a.tag = "exit3";
	a.sleep = false;
	dqt_attach_spawn(&c, &ch, child_exit_status, &a);
	b = 0;
	ATF_REQUIRE_EQ(1, read(ready[0], &b, 1));
	ATF_CHECK_EQ_MSG('a', b, "the child's probe did not PASS");
	one_sigchld("exit 3", ch.pid, CLD_EXITED, 3);
	ATF_CHECK_MSG(dqt_find_resolve(&c, "dqt-probe-exit3", DQ_ROP_STAT,
	    0) != -1, "exit 3: the child was not attached");
	status = -1;
	ATF_REQUIRE_EQ(ch.pid, waitpid(ch.pid, &status, 0));
	ATF_CHECK_EQ_MSG(W_EXITCODE(3, 0), status, "exit 3: status %#x",
	    status);
	ATF_CHECK_EQ(0, close(ch.pd));
	(void)close(ch.pipefd);

	/* kill(SIGTERM) by the parent, an ordinary sender. */
	a.tag = "sigterm";
	a.sleep = true;
	dqt_attach_spawn(&c, &ch, child_exit_status, &a);
	b = 0;
	ATF_REQUIRE_EQ(1, read(ready[0], &b, 1));
	ATF_CHECK_EQ_MSG('a', b, "the child's probe did not PASS");
	ATF_CHECK_MSG(dqt_find_resolve(&c, "dqt-probe-sigterm", DQ_ROP_STAT,
	    0) != -1, "SIGTERM: the child was not attached");
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ_MSG(2, (int)st.ds2_attached, "ds2_attached %ju",
	    (uintmax_t)st.ds2_attached);
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGTERM));
	one_sigchld("SIGTERM", ch.pid, CLD_KILLED, SIGTERM);
	status = -1;
	ATF_REQUIRE_EQ(ch.pid, waitpid(ch.pid, &status, 0));
	ATF_CHECK_EQ_MSG(W_EXITCODE(0, SIGTERM), status,
	    "SIGTERM: status %#x", status);
	ATF_CHECK_EQ(0, close(ch.pd));
	(void)close(ch.pipefd);

	ATF_CHECK_EQ(-1, waitpid(-1, &status, WNOHANG));
	ATF_CHECK_EQ(ECHILD, errno);
	dqt_fini(&c);
	ATF_REQUIRE_EQ(0, sigprocmask(SIG_SETMASK, &old, NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, attach_basic);
	ATF_TP_ADD_TC(tp, attach_refusals);
	ATF_TP_ADD_TC(tp, inheritance);
	ATF_TP_ADD_TC(tp, failed_exec_still_attachable);
	ATF_TP_ADD_TC(tp, attached_exit_status);
	return (atf_no_error());
}
