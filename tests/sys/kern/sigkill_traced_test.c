/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SIGKILL sent to a process that a debugger holds stopped.
 *
 * A tracer may hold a stopped tracee with SIGKILL pending for as long as
 * it keeps the tracee stopped, and it sees the signal as a stop of its own
 * when it resumes the tracee.  What it cannot do is make the signal vanish
 * by letting go: once the tracee is detached, resumed or orphaned by the
 * debugger's exit, the pending SIGKILL is acted upon.  These cases cover
 * the tracee whose threads were stopped where they slept, which is how a
 * transparent PT_ATTACH (debug.ptrace_attach_transparent) leaves a
 * sleeping process, next to the tracee that stopped at a signal of its
 * own.
 *
 * The debugger is a third process, as a real one is; the test stays the
 * target's parent and holds its process descriptor.  Nothing synchronises
 * by sleeping: a state is waited for, with a bound, in what the kernel
 * reports for the process.
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	WAIT_MS		10000	/* bound on any awaited state */
#define	MAXTHR		8

/* What the target does while it is debugged. */
enum kind {
	K_READ,		/* one thread, asleep in read(2) */
	K_MT_SLEEP,	/* two threads, both asleep in read(2) */
	K_MT_MASK,	/* the same, the initial thread blocking SIGUSR1 */
	K_MT_SPIN_2ND,	/* initial thread asleep, second one computing */
	K_MT_SPIN_1ST,	/* initial thread computing, second one asleep */
	K_VFORK,	/* asleep uninterruptibly for a vfork(2) child */
};

/* Where the tracee is when SIGKILL is sent. */
enum stage {
	S_ATTACHED,	/* stopped by PT_ATTACH, stop not yet waited for */
	S_WAITED,	/* stopped by PT_ATTACH, stop collected */
	S_CONTINUED,	/* attached and resumed: not stopped */
	S_SIGSTOP,	/* resumed, then stopped at a signal of its own */
};

enum how { H_KILL, H_PDKILL, H_PDCLOSE };

/* How the debugger lets go afterwards. */
enum rel {
	R_HOLD,		/* it does not */
	R_DETACH,	/* PT_DETACH */
	R_CONT,		/* PT_CONTINUE, then passes the SIGKILL it is shown */
	R_EXIT,		/* the debugger exits */
};

enum op { OP_ATTACH, OP_WAIT, OP_CONT, OP_DETACH, OP_EXIT };

struct cmd {
	int	op;
	int	arg;
};

struct reply {
	int	rv;
	int	error;
	int	status;
};

struct fx {
	pid_t	tgt;		/* the target */
	pid_t	vchild;		/* its vfork(2) child, K_VFORK */
	pid_t	dbg;		/* the debugger */
	int	pd;		/* the target's process descriptor, or -1 */
	int	wfd;		/* write side of the pipe the target reads */
	int	cfd;		/* commands to the debugger */
	int	rfd;		/* its replies */
};

static long
now_ms(void)
{
	struct timespec ts;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* The threads of pid as the kernel reports them; a count, or -errno. */
static int
snap(pid_t pid, struct kinfo_proc *kp, bool threads)
{
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID | (threads ? KERN_PROC_INC_THREAD : 0);
	mib[3] = pid;
	len = (threads ? MAXTHR : 1) * sizeof(*kp);
	if (sysctl(mib, nitems(mib), kp, &len, NULL, 0) == -1)
		return (-errno);
	if (len == 0)
		return (-ESRCH);
	return (len / sizeof(*kp));
}

/* The process state (ki_stat), or -errno when the pid names no process. */
static int
proc_stat(pid_t pid)
{
	struct kinfo_proc kp;
	int n;

	n = snap(pid, &kp, false);
	return (n < 0 ? n : kp.ki_stat);
}

static bool
kill_pending(pid_t pid)
{
	struct kinfo_proc kp;

	return (snap(pid, &kp, false) == 1 &&
	    sigismember(&kp.ki_siglist, SIGKILL) == 1);
}

/*
 * Threads of pid that are on a sleep queue: with stat 0 all of them, the
 * ones stopped where they slept included, else those in that state.
 */
static int
nasleep(pid_t pid, int stat, int *nthreadsp)
{
	struct kinfo_proc kp[MAXTHR];
	int i, n, asleep;

	n = snap(pid, kp, true);
	if (nthreadsp != NULL)
		*nthreadsp = n;
	for (asleep = 0, i = 0; i < n; i++) {
		if (kp[i].ki_wmesg[0] != '\0' &&
		    (stat == 0 || kp[i].ki_stat == stat))
			asleep++;
	}
	return (asleep);
}

/* Record the state the kernel reports, for the reader of a failed run. */
static void
show(const char *tag, pid_t pid)
{
	struct kinfo_proc kp[MAXTHR], pk;
	int i, n;

	n = snap(pid, kp, true);
	if (n < 0 || snap(pid, &pk, false) != 1) {
		fprintf(stderr, "%-10s pid %d: %s\n", tag, pid,
		    strerror(n < 0 ? -n : ESRCH));
		return;
	}
	for (i = 0; i < n; i++) {
		fprintf(stderr, "%-10s pid %d tid %d stat %d p_flag %#lx "
		    "td_flags %#lx wmesg \"%s\" SIGKILL %s\n", tag, pid,
		    kp[i].ki_tid, kp[i].ki_stat, kp[i].ki_flag,
		    kp[i].ki_tdflags, kp[i].ki_wmesg,
		    sigismember(&pk.ki_siglist, SIGKILL) == 1 ? "pending" :
		    sigismember(&kp[i].ki_siglist, SIGKILL) == 1 ?
		    "pending on thread" : "no");
	}
}

/* Wait for the process to be in the given state. */
static bool
wait_stat(pid_t pid, int want)
{
	long end;

	for (end = now_ms() + WAIT_MS; proc_stat(pid) != want;) {
		if (now_ms() > end)
			return (false);
		usleep(1000);
	}
	return (true);
}

/* Wait for the process to have died: a zombie, or reaped already. */
static bool
wait_dead(pid_t pid)
{
	long end;
	int st;

	for (end = now_ms() + WAIT_MS;;) {
		st = proc_stat(pid);
		if (st == SZOMB || st == -ESRCH)
			return (true);
		if (now_ms() > end)
			return (false);
		usleep(1000);
	}
}

/* Wait for the given number of the target's threads to be asleep. */
static bool
wait_asleep(pid_t pid, int nthreads, int want)
{
	long end;
	int n;

	for (end = now_ms() + WAIT_MS;;) {
		if (nasleep(pid, SSLEEP, &n) == want && n == nthreads)
			return (true);
		if (now_ms() > end)
			return (false);
		usleep(1000);
	}
}

static void *
target_reader(void *arg)
{
	char c;

	(void)read(*(int *)arg, &c, 1);
	_exit(0);
}

static void *
target_spinner(void *arg)
{
	volatile unsigned long n;
	char c;

	c = 0;
	(void)write(*(int *)arg, &c, 1);
	for (n = 0;; n++)
		;
	return (NULL);
}

/* The target: rfd is the pipe it sleeps on, yfd tells the test it runs. */
static void
target(enum kind kind, int rfd, int yfd)
{
	pthread_t thr;
	sigset_t set;
	pid_t pid;

	switch (kind) {
	case K_READ:
		break;
	case K_MT_MASK:
		/* A SIGUSR1 sent to the process is the second thread's. */
		sigemptyset(&set);
		sigaddset(&set, SIGUSR1);
		if (pthread_create(&thr, NULL, target_reader, &rfd) != 0 ||
		    pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
			_exit(1);
		break;
	case K_MT_SLEEP:
		if (pthread_create(&thr, NULL, target_reader, &rfd) != 0)
			_exit(1);
		break;
	case K_MT_SPIN_2ND:
		if (pthread_create(&thr, NULL, target_spinner, &yfd) != 0)
			_exit(1);
		break;
	case K_MT_SPIN_1ST:
		if (pthread_create(&thr, NULL, target_reader, &rfd) != 0)
			_exit(1);
		target_spinner(&yfd);
		break;
	case K_VFORK:
		pid = vfork();
		if (pid == -1)
			_exit(1);
		if (pid == 0) {
			pid = getpid();
			(void)write(yfd, &pid, sizeof(pid));
			target_reader(&rfd);
		}
		break;
	}
	target_reader(&rfd);
}

/* The debugger: carry out the test's requests on the target. */
static void
debugger(pid_t tgt, int cfd, int rfd)
{
	struct cmd c;
	struct reply r;
	long end;

	while (read(cfd, &c, sizeof(c)) == sizeof(c)) {
		memset(&r, 0, sizeof(r));
		switch (c.op) {
		case OP_ATTACH:
			r.rv = ptrace(PT_ATTACH, tgt, NULL, 0);
			break;
		case OP_WAIT:
			/* 0 when the target has nothing to report in time. */
			for (end = now_ms() + WAIT_MS;;) {
				r.rv = waitpid(tgt, &r.status, WNOHANG);
				if (r.rv != 0 || now_ms() > end)
					break;
				usleep(1000);
			}
			break;
		case OP_CONT:
			r.rv = ptrace(PT_CONTINUE, tgt, (caddr_t)1, c.arg);
			break;
		case OP_DETACH:
			r.rv = ptrace(PT_DETACH, tgt, (caddr_t)1, 0);
			break;
		default:
			_exit(0);
		}
		if (r.rv == -1)
			r.error = errno;
		if (write(rfd, &r, sizeof(r)) != sizeof(r))
			break;
	}
	_exit(1);
}

/* Have the debugger do one thing; false if it could not be asked. */
static bool
dbg(struct fx *fx, enum op op, int arg, struct reply *r)
{
	struct cmd c;
	struct reply dummy;

	c.op = op;
	c.arg = arg;
	if (r == NULL)
		r = &dummy;
	if (write(fx->cfd, &c, sizeof(c)) != sizeof(c))
		return (false);
	if (read(fx->rfd, r, sizeof(*r)) != sizeof(*r))
		return (false);
	if (r->rv == -1)
		fprintf(stderr, "debugger: op %d: %s\n", op,
		    strerror(r->error));
	return (true);
}

/* Start the target, wait until it is where its kind leaves it. */
static void
fx_start(struct fx *fx, enum kind kind, bool procdesc)
{
	int cp[2], rp[2], tp[2], yp[2];
	char c;

	memset(fx, 0, sizeof(*fx));
	fx->pd = -1;
	ATF_REQUIRE_EQ(0, pipe(tp));
	ATF_REQUIRE_EQ(0, pipe(yp));
	fx->tgt = procdesc ? pdfork(&fx->pd, 0) : fork();
	ATF_REQUIRE(fx->tgt != -1);
	if (fx->tgt == 0) {
		close(tp[1]);
		close(yp[0]);
		target(kind, tp[0], yp[1]);
	}
	ATF_REQUIRE_EQ(0, close(tp[0]));
	ATF_REQUIRE_EQ(0, close(yp[1]));
	fx->wfd = tp[1];

	switch (kind) {
	case K_READ:
		ATF_REQUIRE(wait_asleep(fx->tgt, 1, 1));
		break;
	case K_MT_SLEEP:
	case K_MT_MASK:
		ATF_REQUIRE(wait_asleep(fx->tgt, 2, 2));
		break;
	case K_MT_SPIN_2ND:
	case K_MT_SPIN_1ST:
		ATF_REQUIRE_EQ(1, read(yp[0], &c, 1));
		ATF_REQUIRE(wait_asleep(fx->tgt, 2, 1));
		break;
	case K_VFORK:
		ATF_REQUIRE_EQ((ssize_t)sizeof(fx->vchild),
		    read(yp[0], &fx->vchild, sizeof(fx->vchild)));
		ATF_REQUIRE(wait_asleep(fx->vchild, 1, 1));
		ATF_REQUIRE(wait_asleep(fx->tgt, 1, 1));
		break;
	}
	ATF_REQUIRE_EQ(0, close(yp[0]));

	ATF_REQUIRE_EQ(0, pipe(cp));
	ATF_REQUIRE_EQ(0, pipe(rp));
	fx->dbg = fork();
	ATF_REQUIRE(fx->dbg != -1);
	if (fx->dbg == 0) {
		/* Only the test holds the descriptor and the pipe. */
		if (fx->pd != -1)
			close(fx->pd);
		close(fx->wfd);
		close(cp[1]);
		close(rp[0]);
		debugger(fx->tgt, cp[0], rp[1]);
	}
	ATF_REQUIRE_EQ(0, close(cp[0]));
	ATF_REQUIRE_EQ(0, close(rp[1]));
	fx->cfd = cp[1];
	fx->rfd = rp[0];
}

/* The debugger exits; the test, its parent, collects it. */
static void
fx_dbg_exit(struct fx *fx)
{
	struct cmd c;
	int status;

	if (fx->dbg == 0)
		return;
	c.op = OP_EXIT;
	c.arg = 0;
	(void)write(fx->cfd, &c, sizeof(c));
	ATF_CHECK_EQ(fx->dbg, waitpid(fx->dbg, &status, 0));
	fx->dbg = 0;
}

/* Leave nothing behind, whatever state the case ended in. */
static void
fx_end(struct fx *fx)
{
	int status;

	fx_dbg_exit(fx);
	if (fx->vchild != 0)
		(void)kill(fx->vchild, SIGKILL);
	if (proc_stat(fx->tgt) != -ESRCH) {
		(void)kill(fx->tgt, SIGKILL);
		if (wait_dead(fx->tgt))
			(void)waitpid(fx->tgt, &status, WNOHANG);
	}
	if (fx->pd != -1)
		(void)close(fx->pd);
	(void)close(fx->wfd);
	(void)close(fx->cfd);
	(void)close(fx->rfd);
}

static int
sysctl_get(const char *name)
{
	size_t len;
	int val;

	len = sizeof(val);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &val, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	return (val);
}

static void
sysctl_set(const char *name, int val)
{
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &val,
	    sizeof(val)), "%s: %s", name, strerror(errno));
}

#define	STEP(cond) do {							\
	if (!(cond)) {							\
		atf_tc_fail_nonfatal("%s:%d: %s not met", __FILE__,	\
		    __LINE__, #cond);					\
		goto out;						\
	}								\
} while (0)

#define	STOPPED_AT(r, pid, sig)						\
	((r).rv == (pid) && WIFSTOPPED((r).status) &&			\
	    WSTOPSIG((r).status) == (sig))
#define	KILLED(rv, status, pid)						\
	((rv) == (pid) && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)

#define	TRANSPARENT	"debug.ptrace_attach_transparent"
#define	KILL_ON_EXIT	"kern.kill_on_debugger_exit"

/*
 * One case: bring the tracee to the stage, send SIGKILL, have the debugger
 * let go, and expect the death.  transparent and kill_on_exit are values
 * to run under, or -1 for the defaults (a transparent attach).
 */
static void
run(enum kind kind, enum stage stage, enum how how, enum rel rel,
    int transparent, int kill_on_exit)
{
	struct fx fx;
	struct reply r;
	int nsleepers, nthreads, okill_on_exit, otransparent, status;

	otransparent = okill_on_exit = -1;
	if (transparent == -1) {
		if (sysctl_get(TRANSPARENT) != 1)
			atf_tc_skip(TRANSPARENT " is not set");
	} else {
		otransparent = sysctl_get(TRANSPARENT);
		sysctl_set(TRANSPARENT, transparent);
	}
	if (kill_on_exit != -1) {
		okill_on_exit = sysctl_get(KILL_ON_EXIT);
		sysctl_set(KILL_ON_EXIT, kill_on_exit);
	}
	nthreads = kind == K_READ || kind == K_VFORK ? 1 : 2;
	nsleepers = kind == K_MT_SLEEP || kind == K_MT_MASK ? 2 : 1;

	fx_start(&fx, kind, how == H_PDKILL || how == H_PDCLOSE);
	show("asleep", fx.tgt);

	STEP(dbg(&fx, OP_ATTACH, 0, &r) && r.rv == 0);
	show("attached", fx.tgt);
	if (stage != S_ATTACHED) {
		STEP(dbg(&fx, OP_WAIT, 0, &r) &&
		    STOPPED_AT(r, fx.tgt, SIGSTOP));
		show("waited", fx.tgt);
	}
	if (stage == S_CONTINUED || stage == S_SIGSTOP) {
		STEP(dbg(&fx, OP_CONT, 0, &r) && r.rv == 0);
		STEP(wait_asleep(fx.tgt, nthreads, nsleepers));
		show("continued", fx.tgt);
	}
	if (stage == S_SIGSTOP) {
		STEP(kill(fx.tgt, SIGUSR1) == 0);
		STEP(dbg(&fx, OP_WAIT, 0, &r) &&
		    STOPPED_AT(r, fx.tgt, SIGUSR1));
		show("sigstop", fx.tgt);
	}

	switch (how) {
	case H_KILL:
		STEP(kill(fx.tgt, SIGKILL) == 0);
		break;
	case H_PDKILL:
		STEP(pdkill(fx.pd, SIGKILL) == 0);
		break;
	case H_PDCLOSE:
		STEP(close(fx.pd) == 0);
		fx.pd = -1;
		break;
	}
	show("killed", fx.tgt);
	if (stage != S_CONTINUED) {
		/* The debugger holds it: stopped, the signal pending. */
		STEP(proc_stat(fx.tgt) == SSTOP);
		STEP(kill_pending(fx.tgt));
	}

	switch (rel) {
	case R_HOLD:
		goto out;
	case R_DETACH:
		STEP(dbg(&fx, OP_DETACH, 0, &r) && r.rv == 0);
		break;
	case R_CONT:
		if (stage != S_CONTINUED)
			STEP(dbg(&fx, OP_CONT, 0, &r) && r.rv == 0);
		/* The debugger is shown the signal, and passes it on. */
		STEP(dbg(&fx, OP_WAIT, 0, &r) &&
		    STOPPED_AT(r, fx.tgt, SIGKILL));
		show("reported", fx.tgt);
		STEP(dbg(&fx, OP_CONT, SIGKILL, &r) && r.rv == 0);
		STEP(dbg(&fx, OP_WAIT, 0, &r) &&
		    KILLED(r.rv, r.status, fx.tgt));
		break;
	case R_EXIT:
		fx_dbg_exit(&fx);
		break;
	}
	show("released", fx.tgt);

	/* A vfork(2) parent cannot go before its child lets it. */
	if (kind == K_VFORK)
		STEP(kill(fx.vchild, SIGKILL) == 0);
	if (!wait_dead(fx.tgt)) {
		show("alive", fx.tgt);
		atf_tc_fail_nonfatal("the target outlived SIGKILL");
		goto out;
	}
	/*
	 * A target with a process descriptor is left to fx_end(): closing
	 * the descriptor reaps it, and waitpid(2) is not the test's to use
	 * once the descriptor is closed or the debugger collected the status.
	 */
	if (fx.pd == -1 && how != H_PDCLOSE) {
		status = 0;
		STEP(KILLED(waitpid(fx.tgt, &status, 0), status, fx.tgt));
	}
out:
	fx_end(&fx);
	if (otransparent != -1)
		sysctl_set(TRANSPARENT, otransparent);
	if (okill_on_exit != -1)
		sysctl_set(KILL_ON_EXIT, okill_on_exit);
}

#define	CASE(name, user, descr, ...)					\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	if (user[0] != '\0')						\
		atf_tc_set_md_var(tc, "require.user", user);		\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	run(__VA_ARGS__);						\
}

/*
 * The tracee that is not stopped where it slept: it stopped at a signal
 * of its own, or runs.
 */
CASE(continued__kill__reported, "",
    "SIGKILL from kill(2) wakes a resumed tracee and is shown to the debugger",
    K_READ, S_CONTINUED, H_KILL, R_CONT, -1, -1)
CASE(continued__pdkill__reported, "",
    "SIGKILL from pdkill(2) wakes a resumed tracee and is shown to the debugger",
    K_READ, S_CONTINUED, H_PDKILL, R_CONT, -1, -1)
CASE(continued__pdclose__reported, "",
    "SIGKILL from the last close of the process descriptor wakes a resumed "
    "tracee and is shown to the debugger",
    K_READ, S_CONTINUED, H_PDCLOSE, R_CONT, -1, -1)
CASE(sigstop__kill__detach, "",
    "SIGKILL sent to a tracee stopped at a signal kills it at PT_DETACH",
    K_READ, S_SIGSTOP, H_KILL, R_DETACH, -1, -1)
CASE(sigstop__kill__continue, "",
    "SIGKILL sent to a tracee stopped at a signal is shown at PT_CONTINUE",
    K_READ, S_SIGSTOP, H_KILL, R_CONT, -1, -1)
CASE(mt_sigstop__kill__detach, "",
    "SIGKILL sent to a threaded tracee stopped at a signal kills it at "
    "PT_DETACH",
    K_MT_SLEEP, S_SIGSTOP, H_KILL, R_DETACH, -1, -1)
CASE(legacy_attach__kill__detach, "root",
    "SIGKILL sent after a PT_ATTACH that wakes the sleeper kills it at "
    "PT_DETACH",
    K_READ, S_WAITED, H_KILL, R_DETACH, 0, -1)
CASE(legacy_attach__kill__continue, "root",
    "SIGKILL sent after a PT_ATTACH that wakes the sleeper is shown at "
    "PT_CONTINUE",
    K_READ, S_WAITED, H_KILL, R_CONT, 0, -1)

/* The debugger may hold the tracee stopped with SIGKILL pending. */
CASE(attached__kill__hold, "",
    "A tracee stopped where it slept stays stopped under SIGKILL",
    K_READ, S_ATTACHED, H_KILL, R_HOLD, -1, -1)
CASE(waited__kill__hold, "",
    "A tracee stopped where it slept stays stopped under SIGKILL after the "
    "debugger collected the stop",
    K_READ, S_WAITED, H_KILL, R_HOLD, -1, -1)
CASE(waited__kill__debugger_exit_kills, "root",
    "A debugger exiting under kern.kill_on_debugger_exit kills the tracee",
    K_READ, S_WAITED, H_KILL, R_EXIT, 1, 1)
CASE(vfork_parent__kill__detach, "",
    "SIGKILL sent to a stopped tracee waiting for its vfork(2) child kills "
    "it once detached and let go by the child",
    K_VFORK, S_WAITED, H_KILL, R_DETACH, -1, -1)
CASE(mt_spin_2nd__kill__detach, "",
    "SIGKILL sent to a tracee stopped with its initial thread asleep and "
    "another suspended kills it at PT_DETACH",
    K_MT_SPIN_2ND, S_WAITED, H_KILL, R_DETACH, -1, -1)
CASE(mt_spin_1st__kill__detach, "",
    "SIGKILL sent to a tracee stopped with its initial thread suspended "
    "and another asleep kills it at PT_DETACH",
    K_MT_SPIN_1ST, S_WAITED, H_KILL, R_DETACH, -1, -1)

/* The tracee stopped where it slept dies when the debugger lets go. */
CASE(waited__kill__detach, "",
    "SIGKILL from kill(2) to a tracee stopped where it slept kills it at "
    "PT_DETACH",
    K_READ, S_WAITED, H_KILL, R_DETACH, -1, -1)
CASE(waited__pdkill__detach, "",
    "SIGKILL from pdkill(2) to a tracee stopped where it slept kills it at "
    "PT_DETACH",
    K_READ, S_WAITED, H_PDKILL, R_DETACH, -1, -1)
CASE(waited__pdclose__detach, "",
    "The last close of the process descriptor of a tracee stopped where it "
    "slept kills it at PT_DETACH",
    K_READ, S_WAITED, H_PDCLOSE, R_DETACH, -1, -1)
CASE(waited__kill__continue, "",
    "SIGKILL sent to a tracee stopped where it slept is shown at PT_CONTINUE",
    K_READ, S_WAITED, H_KILL, R_CONT, -1, -1)
CASE(waited__kill__debugger_exit, "root",
    "SIGKILL sent to a tracee stopped where it slept kills it when the "
    "debugger exits without kern.kill_on_debugger_exit",
    K_READ, S_WAITED, H_KILL, R_EXIT, 1, 0)
CASE(attached__kill__debugger_exit, "root",
    "SIGKILL sent to a tracee whose attach stop was never collected kills "
    "it when the debugger exits without kern.kill_on_debugger_exit",
    K_READ, S_ATTACHED, H_KILL, R_EXIT, 1, 0)
CASE(mt_sleepers__kill__detach, "",
    "SIGKILL sent to a tracee with every thread stopped where it slept "
    "kills it at PT_DETACH",
    K_MT_SLEEP, S_WAITED, H_KILL, R_DETACH, -1, -1)
CASE(mt_other_sigstop__kill__detach, "",
    "SIGKILL sent to a tracee stopped at a signal taken by another thread, "
    "its initial thread stopped where it slept, kills it at PT_DETACH",
    K_MT_MASK, S_SIGSTOP, H_KILL, R_DETACH, -1, -1)
CASE(legacy_mt_other_sigstop__kill__detach, "root",
    "The same after a PT_ATTACH that wakes the sleepers",
    K_MT_MASK, S_SIGSTOP, H_KILL, R_DETACH, 0, -1)

/*
 * SIGKILL against PT_DETACH: whichever the kernel sees first, the target
 * dies.
 */
ATF_TC(waited__kill_races_detach);
ATF_TC_HEAD(waited__kill_races_detach, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SIGKILL racing PT_DETACH of a tracee stopped where it slept "
	    "kills it");
}
ATF_TC_BODY(waited__kill_races_detach, tc)
{
	struct fx fx;
	struct cmd c;
	struct reply r;
	volatile int spin;
	int i, status;

	if (sysctl_get(TRANSPARENT) != 1)
		atf_tc_skip(TRANSPARENT " is not set");
	for (i = 0; i < 24; i++) {
		fx_start(&fx, K_READ, false);
		STEP(dbg(&fx, OP_ATTACH, 0, &r) && r.rv == 0);
		STEP(dbg(&fx, OP_WAIT, 0, &r) &&
		    STOPPED_AT(r, fx.tgt, SIGSTOP));
		/* Ask for the detach, and do not wait for it. */
		c.op = OP_DETACH;
		c.arg = 0;
		STEP(write(fx.cfd, &c, sizeof(c)) == sizeof(c));
		for (spin = 0; spin < (i % 8) * 2000; spin++)
			;
		STEP(kill(fx.tgt, SIGKILL) == 0);
		STEP(read(fx.rfd, &r, sizeof(r)) == sizeof(r) && r.rv == 0);
		if (!wait_dead(fx.tgt)) {
			show("alive", fx.tgt);
			atf_tc_fail_nonfatal("round %d: the target outlived "
			    "SIGKILL", i);
			goto out;
		}
		status = 0;
		STEP(KILLED(waitpid(fx.tgt, &status, 0), status, fx.tgt));
		fx_end(&fx);
	}
	return;
out:
	fx_end(&fx);
}

/* No debugger: SIGKILL ends a process stopped by SIGSTOP in its sleep. */
ATF_TC(untraced_stopped__kill);
ATF_TC_HEAD(untraced_stopped__kill, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SIGKILL kills an untraced process stopped in its sleep");
}
ATF_TC_BODY(untraced_stopped__kill, tc)
{
	struct fx fx;
	int status;

	fx_start(&fx, K_READ, false);
	STEP(kill(fx.tgt, SIGSTOP) == 0);
	STEP(wait_stat(fx.tgt, SSTOP));
	show("stopped", fx.tgt);
	STEP(kill(fx.tgt, SIGKILL) == 0);
	STEP(wait_dead(fx.tgt));
	status = 0;
	STEP(KILLED(waitpid(fx.tgt, &status, 0), status, fx.tgt));
out:
	fx_end(&fx);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, continued__kill__reported);
	ATF_TP_ADD_TC(tp, continued__pdkill__reported);
	ATF_TP_ADD_TC(tp, continued__pdclose__reported);
	ATF_TP_ADD_TC(tp, sigstop__kill__detach);
	ATF_TP_ADD_TC(tp, sigstop__kill__continue);
	ATF_TP_ADD_TC(tp, mt_sigstop__kill__detach);
	ATF_TP_ADD_TC(tp, legacy_attach__kill__detach);
	ATF_TP_ADD_TC(tp, legacy_attach__kill__continue);
	ATF_TP_ADD_TC(tp, attached__kill__hold);
	ATF_TP_ADD_TC(tp, waited__kill__hold);
	ATF_TP_ADD_TC(tp, waited__kill__debugger_exit_kills);
	ATF_TP_ADD_TC(tp, vfork_parent__kill__detach);
	ATF_TP_ADD_TC(tp, untraced_stopped__kill);
	ATF_TP_ADD_TC(tp, mt_spin_1st__kill__detach);
	ATF_TP_ADD_TC(tp, mt_spin_2nd__kill__detach);
	ATF_TP_ADD_TC(tp, waited__kill__detach);
	ATF_TP_ADD_TC(tp, waited__pdkill__detach);
	ATF_TP_ADD_TC(tp, waited__pdclose__detach);
	ATF_TP_ADD_TC(tp, waited__kill__continue);
	ATF_TP_ADD_TC(tp, waited__kill__debugger_exit);
	ATF_TP_ADD_TC(tp, attached__kill__debugger_exit);
	ATF_TP_ADD_TC(tp, mt_sleepers__kill__detach);
	ATF_TP_ADD_TC(tp, mt_other_sigstop__kill__detach);
	ATF_TP_ADD_TC(tp, legacy_mt_other_sigstop__kill__detach);
	ATF_TP_ADD_TC(tp, waited__kill_races_detach);
	return (atf_no_error());
}
