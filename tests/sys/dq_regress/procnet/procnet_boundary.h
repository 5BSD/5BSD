/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The probe table shared by the boundary pins (dq-boundary design 6.1,
 * items 1-5): every call by which one process names another by pid, with
 * the errno an actor gets for a given target.  The same table is run
 * against an unattached target, an attached target, a pid that names
 * nothing, and from a jail, so that the later boundary slices (b3, b4) can
 * be seen to leave every cell alone for an unattached actor and to give an
 * inside actor, for an outside pid, exactly the "names nothing" column.
 *
 * The design lists the native /proc/<pid> nodes too.  This system has no
 * native procfs (no sys/fs/procfs); the linprocfs nodes are rows of the
 * Linux half, linux_boundary_test.
 *
 * An actor is a forked child that has dropped to an unprivileged uid and
 * runs bp_probe(); a target is procnet_boundary_helper in "pause" mode
 * (see there for why it must have exec'd).  Neither is the other's parent.
 */

#ifndef _PROCNET_BOUNDARY_H_
#define	_PROCNET_BOUNDARY_H_

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/ktrace.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/rtprio.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <sys/uio.h>
#include <sys/user.h>

#include "procnet_common.h"

/*
 * A row that the scenario cannot drive (no descriptor to pass).  pddupfd()
 * is this in every refusing column: it needs the descriptor pdopenpid()
 * was refused there, so its own p_candebug() refusal is not pinned.
 */
#define	BP_NA		(-2)

enum bp_row {
	BP_PT_ATTACH,		/* ptrace(PT_ATTACH), then wait and detach */
	BP_PDOPENPID,
	BP_PDDUPFD,		/* through the pdopenpid descriptor */
	BP_KCMP,		/* kcmp(self, pid, KCMP_FILE, 0, 0) */
	BP_SC_FILEDESC,		/* kern.proc.filedesc.<pid> */
	BP_SC_VMMAP,
	BP_SC_ARGS,
	BP_SC_ENV,
	BP_KILL0,
	BP_SIGQUEUE0,
	BP_THR_KILL2,		/* thr_kill2(pid, tid, 0) */
	BP_TRACE_STATUS,	/* procctl(PROC_TRACE_STATUS) */
	BP_RTPRIO,		/* rtprio(RTP_LOOKUP) */
	BP_CPUSET,		/* cpuset_getaffinity(CPU_WHICH_PID) */
	BP_GETPRIORITY,
	BP_GETPGID,
	BP_KQ_PROC,		/* EVFILT_PROC, NOTE_EXIT */
	BP_KTRACE,		/* ktrace(KTROP_SET) by pid, then KTROP_CLEAR */
	BP_FSETOWN,		/* fcntl(F_SETOWN, pid) on a pipe */
	BP_NROWS
};

static const char *const bp_rowname[BP_NROWS] = {
	"ptrace(PT_ATTACH)", "pdopenpid", "pddupfd", "kcmp",
	"kern.proc.filedesc", "kern.proc.vmmap", "kern.proc.args",
	"kern.proc.env", "kill(pid, 0)", "sigqueue(pid, 0)", "thr_kill2",
	"procctl(PROC_TRACE_STATUS)", "rtprio(RTP_LOOKUP)",
	"cpuset_getaffinity", "getpriority", "getpgid", "EVFILT_PROC",
	"ktrace", "fcntl(F_SETOWN)",
};

struct bp_args {
	pid_t		 pid;
	long		 tid;		/* a thread of pid (any value if none) */
	const char	*ktrfile;	/* a file the actor may create */
};

struct bp_result {
	int		 got[BP_NROWS];
	int		 debug;	/* security.bsd.unprivileged_proc_debug seen */
};

static inline int
bp_sysctl_pid(int what, pid_t pid)
{
	static char buf[256 * 1024];
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, what, pid };

	len = sizeof(buf);
	return (PN_ERR(sysctl(mib, nitems(mib), buf, &len, NULL, 0)));
}

/* Runs in the actor.  Leaves the target as it found it. */
static inline void
bp_probe(const struct bp_args *a, struct bp_result *r)
{
	struct rtprio rtp;
	struct kevent kev;
	union sigval sv;
	cpuset_t mask;
	int e, fd, i, kq, p[2], pd, status;

	for (i = 0; i < BP_NROWS; i++)
		r->got[i] = BP_NA;

	e = PN_ERR(ptrace(PT_ATTACH, a->pid, NULL, 0));
	if (e == 0) {
		/* The stop of the attach, then let it go. */
		if (waitpid(a->pid, &status, 0) != a->pid ||
		    !WIFSTOPPED(status) ||
		    ptrace(PT_DETACH, a->pid, (caddr_t)1, 0) != 0)
			e = PN_X_WRONG;
	}
	r->got[BP_PT_ATTACH] = e;

	/*
	 * PD_DAEMON: the last close of a pdopenpid(pid, 0) descriptor
	 * kills the process it names (procdesc_close), as that of a
	 * pdfork() descriptor does, and the probe must leave its target.
	 */
	pd = pdopenpid(a->pid, PD_DAEMON);
	r->got[BP_PDOPENPID] = pd == -1 ? errno : 0;
	if (pd != -1) {
		fd = pddupfd(pd, 0, 0);
		r->got[BP_PDDUPFD] = fd == -1 ? errno : 0;
		if (fd != -1)
			(void)close(fd);
		(void)close(pd);
	}

	r->got[BP_KCMP] = PN_ERR(kcmp(getpid(), a->pid, KCMP_FILE, 0, 0));
	r->got[BP_SC_FILEDESC] = bp_sysctl_pid(KERN_PROC_FILEDESC, a->pid);
	r->got[BP_SC_VMMAP] = bp_sysctl_pid(KERN_PROC_VMMAP, a->pid);
	r->got[BP_SC_ARGS] = bp_sysctl_pid(KERN_PROC_ARGS, a->pid);
	r->got[BP_SC_ENV] = bp_sysctl_pid(KERN_PROC_ENV, a->pid);
	r->got[BP_KILL0] = PN_ERR(kill(a->pid, 0));
	sv.sival_int = 0;
	r->got[BP_SIGQUEUE0] = PN_ERR(sigqueue(a->pid, 0, sv));
	r->got[BP_THR_KILL2] = PN_ERR(thr_kill2(a->pid, a->tid, 0));
	r->got[BP_TRACE_STATUS] = PN_ERR(procctl(P_PID, a->pid,
	    PROC_TRACE_STATUS, &status));
	r->got[BP_RTPRIO] = PN_ERR(rtprio(RTP_LOOKUP, a->pid, &rtp));
	r->got[BP_CPUSET] = PN_ERR(cpuset_getaffinity(CPU_LEVEL_WHICH,
	    CPU_WHICH_PID, a->pid, sizeof(mask), &mask));
	errno = 0;
	(void)getpriority(PRIO_PROCESS, a->pid);
	r->got[BP_GETPRIORITY] = errno;
	r->got[BP_GETPGID] = PN_ERR(getpgid(a->pid));

	kq = kqueue();
	if (kq != -1) {
		EV_SET(&kev, a->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
		r->got[BP_KQ_PROC] = PN_ERR(kevent(kq, &kev, 1, NULL, 0,
		    NULL));
		(void)close(kq);
	}

	/* ktrace(2) wants an existing file. */
	fd = open(a->ktrfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd != -1) {
		(void)close(fd);
		e = PN_ERR(ktrace(a->ktrfile, KTROP_SET, KTRFAC_SYSCALL,
		    a->pid));
		if (e == 0 && ktrace(a->ktrfile, KTROP_CLEAR, KTRFAC_SYSCALL,
		    a->pid) != 0)
			e = PN_X_WRONG;
		r->got[BP_KTRACE] = e;
		(void)unlink(a->ktrfile);
	}

	if (pipe(p) == 0) {
		r->got[BP_FSETOWN] = PN_ERR(fcntl(p[0], F_SETOWN, a->pid));
		(void)close(p[0]);
		(void)close(p[1]);
	}
}

/* Compare one scenario with its expectation; print the whole column. */
static inline void
bp_check(const char *scenario, const struct bp_result *r, const int *want)
{
	int i, bad;

	bad = 0;
	for (i = 0; i < BP_NROWS; i++) {
		if (r->got[i] != want[i])
			bad++;
		printf("%s: %-28s got %d want %d%s\n", scenario, bp_rowname[i],
		    r->got[i], want[i], r->got[i] != want[i] ? "  <== FAIL" :
		    "");
	}
	ATF_CHECK_MSG(bad == 0, "%s: %d of %d rows not as recorded (table on "
	    "stdout; -2 is a row that was not driven)", scenario, bad,
	    BP_NROWS);
}

/* An expectation column with every row the same. */
static inline void
bp_fill(int *want, int e)
{
	int i;

	for (i = 0; i < BP_NROWS; i++)
		want[i] = e;
}

/*
 * A target: the helper, running as uid/gid, with its pid and thread id
 * read from its report.  bp_target_start() forks; the child calls
 * bp_target_exec() (after whatever the test does to it first).
 */
struct bp_target {
	pid_t		 pid;
	long		 tid;
	int		 in;		/* our end of its stdin */
	int		 out;		/* our end of its stdout */
};

static inline void
bp_target_exec(const char *helper, bool notrace, int in, int out, uid_t uid,
    gid_t gid)
{

	if (dup2(in, 0) == -1 || dup2(out, 1) == -1)
		_exit(PN_X_SETUP);
	closefrom(3);
	if (uid != 0)
		pn_drop(uid, gid);
	execl(helper, "procnet_boundary_helper", "pause",
	    notrace ? "notrace" : NULL, (char *)NULL);
	_exit(PN_X_SETUP);
}

/* Read "<pid> <tid>\n": the target is past exec and at rest. */
static inline void
bp_target_ready(struct bp_target *t)
{
	char buf[64];
	size_t off;
	ssize_t n;
	int pid;

	off = 0;
	do {
		n = read(t->out, buf + off, sizeof(buf) - 1 - off);
		ATF_REQUIRE_MSG(n > 0, "the target did not report (%zd): it "
		    "failed before or at exec", n);
		off += (size_t)n;
		buf[off] = '\0';
	} while (strchr(buf, '\n') == NULL);
	ATF_REQUIRE_EQ(2, sscanf(buf, "%d %ld", &pid, &t->tid));
	ATF_REQUIRE_EQ(t->pid, (pid_t)pid);
}

static inline void
bp_target_start(struct bp_target *t, const char *helper, bool notrace,
    uid_t uid, gid_t gid)
{
	int in[2], out[2];

	ATF_REQUIRE_EQ(0, pipe(in));
	ATF_REQUIRE_EQ(0, pipe(out));
	t->pid = fork();
	ATF_REQUIRE(t->pid != -1);
	if (t->pid == 0)
		bp_target_exec(helper, notrace, in[0], out[1], uid, gid);
	(void)close(in[0]);
	(void)close(out[1]);
	t->in = in[1];
	t->out = out[0];
	bp_target_ready(t);
}

/* End of file on its stdin; it must exit 0 (nothing a probe did hurt it). */
static inline void
bp_target_end(struct bp_target *t)
{
	int status;

	(void)close(t->in);
	(void)close(t->out);
	status = pn_wait(t->pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "target status %#x", status);
}

/* A pid that names nothing: a child that has been reaped. */
static inline pid_t
bp_dead_pid(void)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(0);
	(void)pn_wait(pid);
	return (pid);
}

/*
 * Run the probe in an actor: a child that (optionally) enters a new jail
 * rooted at "/", drops to uid/gid, and reports over a pipe.  jail is NULL
 * or the name of the new jail, which lives as long as the actor does and
 * takes its allow.unprivileged_proc_debug from the host at creation.
 */
static inline void
bp_enter_jail(const char *name)
{
	struct iovec iov[4];

	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, name);
	iov[1].iov_len = strlen(name) + 1;
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, "/");
	iov[3].iov_len = sizeof("/");
	if (jail_set(iov, nitems(iov), JAIL_CREATE | JAIL_ATTACH) == -1)
		_exit(PN_X_SETUP);
}

static inline void
bp_actor(const struct bp_args *a, struct bp_result *r, uid_t uid, gid_t gid,
    const char *jail)
{
	pid_t pid;
	int p[2], status;

	ATF_REQUIRE_EQ(0, pipe(p));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		struct bp_result cr;
		size_t len;

		(void)close(p[0]);
		(void)alarm(60);
		if (jail != NULL)
			bp_enter_jail(jail);
		if (uid != 0)
			pn_drop(uid, gid);
		bp_probe(a, &cr);
		len = sizeof(cr.debug);
		if (sysctlbyname("security.bsd.unprivileged_proc_debug",
		    &cr.debug, &len, NULL, 0) != 0)
			_exit(PN_X_SETUP);
		if (write(p[1], &cr, sizeof(cr)) != (ssize_t)sizeof(cr))
			_exit(PN_X_SETUP);
		_exit(0);
	}
	(void)close(p[1]);
	ATF_REQUIRE_EQ_MSG((ssize_t)sizeof(*r), read(p[0], r, sizeof(*r)),
	    "the actor did not report");
	(void)close(p[0]);
	status = pn_wait(pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "actor status %#x", status);
}

#endif /* !_PROCNET_BOUNDARY_H_ */
