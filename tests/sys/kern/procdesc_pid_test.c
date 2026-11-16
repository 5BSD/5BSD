/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The pid of a process that has a process descriptor.
 *
 * A process descriptor keeps the pid of its process allocated after the
 * process has exited and its parent, if it has one that may, has waited
 * for it.  The number goes back to the allocator on one of two paths:
 *
 * - The process is still attached to the descriptor at the last close
 *   (the zombie that stays listed, kept by the descriptor's zombie
 *   reference).  procdesc_close() detaches it and sets pd_pid to -1, and
 *   proc_reap() clears the pid itself (the proc_id_clear() of
 *   kern_exit.c).  This is the path the three cases here take.
 * - The process was reaped in full while still attached: proc_reap()
 *   leaves the pid to procdesc_reap(), and procdesc_free() clears it
 *   with the last reference to the descriptor.
 *
 * The cases pin both halves by behaviour, whichever path is taken: the
 * pid is not given to a new process while a descriptor is open, and it
 * is given out again once the last one is closed.  That the process is
 * no longer found (ESRCH) does not show the second half; a pid left
 * allocated would stay reserved for ever with the process gone.
 *
 * Not proven against a kernel that leaks the pid on purpose: no such
 * kernel was built.  The hold check is the nearest thing to it, the same
 * loop run on a pid that is still allocated.
 *
 * Pids are allocated in sequence from the last one given out and wrap at
 * kern.pid_max (fork_findpid).  Each case lowers kern.pid_max before it
 * creates its process, so that a pass over the whole pid space is a few
 * hundred forks instead of a walk of 99999 pids, and counts passes by the
 * wraps it sees in the pids of its own children.  Nothing is bounded by
 * time.  The program is exclusive: other tests must not see the small pid
 * space, and must not fork into it.
 */

#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	PID_MAX_SYSCTL	"kern.pid_max"
#define	RANDOMPID	"kern.randompid"

/* The lowered pid space, and the most live processes it is used with. */
#define	PID_LOW		1000
#define	PROCS_MOST	(PID_LOW / 4)

/*
 * A pass hands out at most PID_LOW pids, and no check needs more than
 * four wraps; anything beyond this many forks is a failure, not a wait.
 */
#define	FORKS_MOST	(8 * PID_LOW)

/* Failure bound of the waits on a state; never slept in full. */
#define	WAIT_MS		120000

/*
 * Change a sysctl, leaving the old value in a file of that name in the
 * work directory for the cleanup.
 */
static void
sysctl_change(const char *name, int val)
{
	FILE *fp;
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &old, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	fp = fopen(name, "wx");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fprintf(fp, "%d\n", old) > 0);
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &val,
	    sizeof(val)), "%s: %s", name, strerror(errno));
}

/* Put a changed sysctl back; without effect if it was not changed. */
static void
sysctl_restore(const char *name)
{
	FILE *fp;
	int old;

	fp = fopen(name, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &old) != 1 ||
	    sysctlbyname(name, NULL, NULL, &old, sizeof(old)) != 0)
		fprintf(stderr, "%s was not restored\n", name);
	else
		(void)unlink(name);
	(void)fclose(fp);
}

static void
pid_space_restore(void)
{
	sysctl_restore(PID_MAX_SYSCTL);
	sysctl_restore(RANDOMPID);
}

/*
 * Make the pid space small and sequential.  Live processes with higher
 * pids are not disturbed (sysctl_kern_pid_max).
 */
static void
pid_space_lower(void)
{
	size_t len;
	int mib[3], val;

	/*
	 * The allocator must not be asked for a pid it does not have.  A
	 * system this full cannot be given the small pid space, and then
	 * nothing is checked: that is a failure, not a skip.
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;
	len = 0;
	ATF_REQUIRE_EQ(0, sysctl(mib, nitems(mib), NULL, &len, NULL, 0));
	if (len / sizeof(struct kinfo_proc) > PROCS_MOST)
		atf_tc_fail("too many processes for a pid space of %d",
		    PID_LOW);

	len = sizeof(val);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(RANDOMPID, &val, &len, NULL, 0),
	    RANDOMPID ": %s", strerror(errno));
	if (val != 0)
		sysctl_change(RANDOMPID, 0);
	sysctl_change(PID_MAX_SYSCTL, PID_LOW);
}

/* The process state (ki_stat), or -errno when the pid names no process. */
static int
proc_stat(pid_t pid)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(kp);
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == -1)
		return (-errno);
	if (len == 0)
		return (-ESRCH);
	return (kp.ki_stat);
}

/* Poll until proc_stat(pid) is want. */
static int
proc_stat_wait(pid_t pid, int want)
{
	int i, st;

	st = 0;
	for (i = 0; i <= WAIT_MS; i++) {
		st = proc_stat(pid);
		if (st == want)
			break;
		usleep(1000);
	}
	return (st);
}

enum { P_NOT_SEEN, P_OURS, P_FOREIGN };

/*
 * Fork and reap children until the pids they get have wrapped `wraps'
 * times, which is `wraps' - 1 passes over every pid of the lowered space
 * (the pids rise between two wraps, whoever else forks).  With `stop',
 * return as soon as `want' is seen in use again: as the pid of a child
 * of ours, or of a process somebody else forked meanwhile.
 */
static int
pid_passes(pid_t want, int wraps, bool stop)
{
	pid_t pid, prev;
	int forks, seen, status;

	seen = P_NOT_SEEN;
	prev = 0;
	for (forks = 0; wraps > 0; forks++) {
		ATF_REQUIRE_MSG(forks < FORKS_MOST,
		    "the pids did not wrap in %d forks", forks);
		if (stop && proc_stat(want) != -ESRCH)
			return (P_FOREIGN);
		pid = fork();
		ATF_REQUIRE_MSG(pid != -1, "fork: %s", strerror(errno));
		if (pid == 0)
			_exit(0);
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_REQUIRE_MSG(pid < PID_LOW, "pid %d with " PID_MAX_SYSCTL
		    " %d", (int)pid, PID_LOW);
		if (pid == want) {
			seen = P_OURS;
			if (stop)
				break;
		}
		if (pid < prev)
			wraps--;
		prev = pid;
	}
	return (seen);
}

/* Two passes over the pid space do not hand out the pid. */
static void
pid_is_held(pid_t pid)
{
	int seen;

	seen = pid_passes(pid, 3, false);
	ATF_CHECK_EQ_MSG(P_NOT_SEEN, seen,
	    "pid %d was given to a new process while a descriptor held it",
	    (int)pid);
}

/*
 * The pid is handed out again.  The next pass must reach it; it is given
 * three, because a process forked by somebody else may take the pid and
 * be gone again between two looks.
 */
static void
pid_is_released(pid_t pid)
{
	int seen, st;

	/* The process is gone first, so that a new one can be told. */
	st = proc_stat_wait(pid, -ESRCH);
	ATF_REQUIRE_EQ_MSG(-ESRCH, st, "state %d after the last close", st);
	seen = pid_passes(pid, 4, true);
	ATF_CHECK_MSG(seen != P_NOT_SEEN,
	    "pid %d was not handed out again in three passes over the pid "
	    "space", (int)pid);
	if (seen == P_FOREIGN)
		printf("pid %d went to a process of somebody else\n",
		    (int)pid);
}

/*
 * A forks B with fork(2) and an unrelated process C opens B with
 * pdopenpid(2).  B exits and A reaps it with waitpid(2): C's descriptor
 * holds the pid.  C closes: the pid is released.  (The rest of this
 * scenario is procdesc:foreign_open_parent_wait.)
 */
ATF_TC_WITH_CLEANUP(foreign_open_reaped);
ATF_TC_HEAD(foreign_open_reaped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "a pdopenpid(2) descriptor holds the "
	    "pid of a reaped process, and its close releases the pid");
}
ATF_TC_BODY(foreign_open_reaped, tc)
{
	pid_t b, c;
	int bgo[2], ccmd[2], crep[2], pd, rv, st, status;
	char ch;

	pid_space_lower();
	ATF_REQUIRE_EQ(0, pipe(bgo));
	ATF_REQUIRE_EQ(0, pipe(ccmd));
	ATF_REQUIRE_EQ(0, pipe(crep));

	b = fork();
	ATF_REQUIRE(b != -1);
	if (b == 0) {
		close(bgo[1]);
		close(ccmd[0]);
		close(ccmd[1]);
		close(crep[0]);
		close(crep[1]);
		if (read(bgo[0], &ch, 1) != 1)
			_exit(8);
		_exit(9);
	}
	ATF_REQUIRE_MSG(b < PID_LOW, "B has pid %d", (int)b);
	c = fork();
	ATF_REQUIRE(c != -1);
	if (c == 0) {
		close(bgo[0]);
		close(bgo[1]);
		close(ccmd[1]);
		close(crep[0]);
		pd = pdopenpid(b, 0);
		rv = pd == -1 ? errno : 0;
		if (write(crep[1], &rv, sizeof(rv)) != sizeof(rv) || pd == -1)
			_exit(11);
		if (read(ccmd[0], &ch, 1) != 1)
			_exit(12);
		rv = close(pd) == -1 ? errno : 0;
		if (write(crep[1], &rv, sizeof(rv)) != sizeof(rv))
			_exit(13);
		if (read(ccmd[0], &ch, 1) != 1)
			_exit(14);
		_exit(0);
	}
	close(bgo[0]);
	close(ccmd[0]);
	close(crep[1]);
	ATF_REQUIRE_EQ(sizeof(rv), (size_t)read(crep[0], &rv, sizeof(rv)));
	ATF_REQUIRE_MSG(rv == 0, "pdopenpid in C: %s", strerror(rv));

	ch = 'g';
	ATF_REQUIRE_EQ(1, write(bgo[1], &ch, 1));
	ATF_REQUIRE_EQ(b, waitpid(b, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 9,
	    "B status %#x", status);

	/* Reaped, and C's descriptor is all that is left of B. */
	pid_is_held(b);
	st = proc_stat(b);
	ATF_CHECK_EQ_MSG(SZOMB, st, "B state %d while C holds it", st);

	ch = 'c';
	ATF_REQUIRE_EQ(1, write(ccmd[1], &ch, 1));
	ATF_REQUIRE_EQ(sizeof(rv), (size_t)read(crep[0], &rv, sizeof(rv)));
	ATF_REQUIRE_MSG(rv == 0, "close in C: %s", strerror(rv));
	pid_is_released(b);

	ch = 'x';
	ATF_REQUIRE_EQ(1, write(ccmd[1], &ch, 1));
	ATF_REQUIRE_EQ(c, waitpid(c, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "C status %#x", status);
	pid_space_restore();
}
ATF_TC_CLEANUP(foreign_open_reaped, tc)
{
	pid_space_restore();
}

/*
 * pdfork(2) without flags: the parent reaps the child with waitpid(2)
 * and its own descriptor holds the pid until it is closed.
 */
ATF_TC_WITH_CLEANUP(pdfork_reaped);
ATF_TC_HEAD(pdfork_reaped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "the pdfork(2) descriptor holds the "
	    "pid of a reaped child, and its close releases the pid");
}
ATF_TC_BODY(pdfork_reaped, tc)
{
	pid_t pid;
	int pd, st, status;

	pid_space_lower();
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0)
		_exit(5);
	ATF_REQUIRE_MSG(pid < PID_LOW, "the child has pid %d", (int)pid);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 5,
	    "status %#x", status);

	pid_is_held(pid);
	st = proc_stat(pid);
	ATF_CHECK_EQ_MSG(SZOMB, st, "state %d while the descriptor is open",
	    st);

	ATF_REQUIRE_EQ(0, close(pd));
	pid_is_released(pid);
	pid_space_restore();
}
ATF_TC_CLEANUP(pdfork_reaped, tc)
{
	pid_space_restore();
}

/*
 * pdfork(PD_NOWAITPID) by the child's own reaper.  Nobody can wait for
 * the child; it stays a zombie under its pid until the descriptor is
 * closed, and the close both reaps it and releases the pid.  (The rest
 * of this scenario is procdesc:nowaitpid_parent_is_reaper.)
 */
ATF_TC_WITH_CLEANUP(nowaitpid_reaper_close);
ATF_TC_HEAD(nowaitpid_reaper_close, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "the pid of an exited "
	    "pdfork(PD_NOWAITPID) child of its reaper is held until the "
	    "descriptor is closed, and released by the close");
}
ATF_TC_BODY(nowaitpid_reaper_close, tc)
{
	struct pollfd pfd;
	pid_t pid;
	int pd, st;

	pid_space_lower();
	ATF_REQUIRE_EQ_MSG(0, procctl(P_PID, getpid(), PROC_REAP_ACQUIRE,
	    NULL), "PROC_REAP_ACQUIRE: %s", strerror(errno));
	pid = pdfork(&pd, PD_NOWAITPID);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0)
		_exit(5);
	ATF_REQUIRE_MSG(pid < PID_LOW, "the child has pid %d", (int)pid);
	pfd.fd = pd;
	pfd.events = POLLHUP;
	pfd.revents = 0;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, WAIT_MS));
	st = proc_stat_wait(pid, SZOMB);
	ATF_REQUIRE_EQ_MSG(SZOMB, st, "state %d after the exit", st);

	pid_is_held(pid);
	st = proc_stat(pid);
	ATF_CHECK_EQ_MSG(SZOMB, st, "state %d while the descriptor is open",
	    st);

	ATF_REQUIRE_EQ(0, close(pd));
	pid_is_released(pid);
	pid_space_restore();
}
ATF_TC_CLEANUP(nowaitpid_reaper_close, tc)
{
	pid_space_restore();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, foreign_open_reaped);
	ATF_TP_ADD_TC(tp, pdfork_reaped);
	ATF_TP_ADD_TC(tp, nowaitpid_reaper_close);
	return (atf_no_error());
}
