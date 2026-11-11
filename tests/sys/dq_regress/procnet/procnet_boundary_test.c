/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The process boundary as a process that is NOT attached to a dq(4)
 * controller sees it today (dq-boundary design, part b0, section 6.1).
 *
 * The boundary slices make the processes outside a confinement invisible
 * to the programs inside it, and close the terminal, job-control, SIGIO
 * and no-new-privileges paths between the two.  Every one of those paths
 * is shared with programs nothing is attached to.  These cases record
 * what such a program gets now, so that each slice can be shown to leave
 * it alone.  The tables are what the kernel of commit f52f6da3d34 does,
 * recorded by running this program on it; nothing here is derived from
 * the design alone.
 *
 * Unless a case says otherwise, no later slice is expected to change it:
 * that is what it is for.  The cases whose columns a slice will reuse as
 * the oracle of the inside view say so.
 *
 * The halves that need a queue are in procnet_outside_test; named IPC is
 * procnet_ipc_test; the Linux ABI is linux_boundary_test.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <poll.h>
#include <pthread.h>
#include <termios.h>

#include "procnet_boundary.h"

static char	helper[PATH_MAX];
static char	ktrfile[PATH_MAX];

#define	DEBUG_SYSCTL	"security.bsd.unprivileged_proc_debug"
#define	DEBUG_SAVE	"proc_debug.saved"

static void
bp_setup(const atf_tc_t *tc, const char *name)
{
	char dir[PATH_MAX];

	pn_srcfile(tc, "procnet_boundary_helper", helper, sizeof(helper));
	ATF_REQUIRE_MSG(access(helper, X_OK) == 0, "%s: %s", helper,
	    strerror(errno));
	pn_pubdir(name, dir, sizeof(dir));
	ATF_REQUIRE(chmod(dir, 01777) == 0);
	ATF_REQUIRE((size_t)snprintf(ktrfile, sizeof(ktrfile), "%s/ktrace.out",
	    dir) < sizeof(ktrfile));
}

/* Set the host's unprivileged_proc_debug; the cleanup puts it back. */
static void
debug_set(int v)
{
	char buf[16];
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_EQ(0, sysctlbyname(DEBUG_SYSCTL, &old, &len, NULL, 0));
	if (access(DEBUG_SAVE, F_OK) != 0) {
		(void)snprintf(buf, sizeof(buf), "%d", old);
		pn_writefile(DEBUG_SAVE, buf, strlen(buf), 0600);
	}
	ATF_REQUIRE_EQ(0, sysctlbyname(DEBUG_SYSCTL, NULL, NULL, &v,
	    sizeof(v)));
}

static void
debug_restore(void)
{
	char buf[16];
	ssize_t n;
	int fd, v;

	fd = open(DEBUG_SAVE, O_RDONLY);
	if (fd == -1)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	v = atoi(buf);
	(void)sysctlbyname(DEBUG_SYSCTL, NULL, NULL, &v, sizeof(v));
}

/*
 * One column of the table: a target run as tuid, probed by an actor that
 * is PN_UID, jailed if jail is not NULL, with the host's
 * unprivileged_proc_debug set to debug first.
 */
static void
column(const char *scenario, uid_t tuid, bool notrace, bool dead,
    const char *jail, int debug, const int *want)
{
	struct bp_target t;
	struct bp_args a;
	struct bp_result r;

	debug_set(debug);
	memset(&t, 0, sizeof(t));
	if (dead) {
		t.pid = bp_dead_pid();
		t.tid = 100000;		/* the first thread id there is */
	} else
		bp_target_start(&t, helper, notrace, tuid, tuid);
	a.pid = t.pid;
	a.tid = t.tid;
	a.ktrfile = ktrfile;
	bp_actor(&a, &r, PN_UID, PN_GID, jail);
	ATF_CHECK_EQ_MSG(debug, r.debug, "the actor saw " DEBUG_SYSCTL "=%d",
	    r.debug);
	bp_check(scenario, &r, want);
	if (!dead)
		bp_target_end(&t);
}

#define	BP_CASE(name, descr)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	debug_restore();						\
	pn_pubdir_remove(#name);					\
}									\
ATF_TC_BODY(name, tc)

/*
 * Item 1.  An unattached actor and an unattached target of the same uid,
 * neither the other's parent: every call works.  b3/b4 must leave this
 * column alone; the same column for an attached target is
 * procnet_outside_test:probe_attached_target.
 */
BP_CASE(probe_same_uid, "Every by-pid call of an unattached process on an "
    "unattached process of its own uid")
{
	int want[BP_NROWS];

	bp_setup(tc, "probe_same_uid");
	bp_fill(want, 0);
	column("same uid", PN_UID, false, false, NULL, 1, want);
}

/*
 * Item 3.  The existence oracle: what each call says of a pid that names
 * nothing.  b3 gives an inside actor exactly this column for a pid that
 * names an outside process, so the two columns that follow (a process
 * that exists but may not be touched) show what must NOT leak.
 */
BP_CASE(probe_names_nothing, "Every by-pid call on a pid that names no "
    "process")
{
	int want[BP_NROWS];

	bp_setup(tc, "probe_names_nothing");
	bp_fill(want, ESRCH);
	want[BP_PDDUPFD] = BP_NA;
	column("names nothing", PN_UID, false, true, NULL, 1, want);
}

/*
 * Item 3, beside the above: a process that exists and belongs to another
 * uid.  Today existence shows (EPERM against ESRCH, and the calls that
 * need only p_cansee() succeed).  PROC_TRACE_STATUS is among those;
 * cpuset_getaffinity() is not (it asks p_cansched()).
 */
BP_CASE(probe_other_uid, "Every by-pid call on a process of another uid")
{
	int want[BP_NROWS];

	size_t len;
	int see;

	bp_setup(tc, "probe_other_uid");
	/* With it off the column is ESRCH: another pin, not this one. */
	len = sizeof(see);
	ATF_REQUIRE_EQ(0, sysctlbyname("security.bsd.see_other_uids", &see,
	    &len, NULL, 0));
	ATF_REQUIRE_MSG(see == 1, "security.bsd.see_other_uids is %d: this "
	    "pin records the default, 1", see);
	bp_fill(want, EPERM);
	want[BP_PDDUPFD] = BP_NA;
	want[BP_SC_ARGS] = 0;
	want[BP_TRACE_STATUS] = 0;
	want[BP_RTPRIO] = 0;
	want[BP_GETPRIORITY] = 0;
	want[BP_GETPGID] = 0;
	want[BP_KQ_PROC] = 0;
	want[BP_FSETOWN] = 0;
	column("other uid", PN_NOBODY, false, false, NULL, 1, want);
}

/*
 * Item 4.  A jailed actor and an unjailed target of the same uid, with
 * unprivileged debugging allowed: prison_check() answers ESRCH, the
 * answer for a pid that names nothing.  This is the model b3 follows.
 * Two calls do not fit it today: ktrace(2) turns every refusal of a
 * single pid into EPERM, and fsetown() tests only the session of the
 * process it is given, so F_SETOWN succeeds across the jail.
 */
BP_CASE(probe_jailed_debug_on, "Every by-pid call of a jailed process on "
    "an unjailed one, unprivileged_proc_debug=1")
{
	char name[32];
	int want[BP_NROWS];

	bp_setup(tc, "probe_jailed_debug_on");
	(void)snprintf(name, sizeof(name), "bp_on_%d", (int)getpid());
	bp_fill(want, ESRCH);
	want[BP_PDDUPFD] = BP_NA;
	want[BP_KTRACE] = EPERM;
	want[BP_FSETOWN] = 0;
	column("jailed, debug on", PN_UID, false, false, name, 1, want);
}

/*
 * Items 4 and 5.  The same with unprivileged debugging off: p_candebug()
 * tests PRIV_DEBUG_UNPRIV before prison_check(), so its callers answer
 * EPERM for a process the jail cannot see, and ESRCH only for a pid that
 * names nothing.  The order is the kernel's (kern_prot.c p_candebug());
 * b3 puts its test before both and must not move these.  PT_ATTACH is
 * not among them: ptrace(2) asks p_cansee() before p_candebug() and
 * answers ESRCH.  F_SETOWN succeeds, as with debugging on.
 */
BP_CASE(probe_jailed_debug_off, "Every by-pid call of a jailed process on "
    "an unjailed one, unprivileged_proc_debug=0")
{
	char name[32];
	int want[BP_NROWS];

	bp_setup(tc, "probe_jailed_debug_off");
	(void)snprintf(name, sizeof(name), "bp_off_%d", (int)getpid());
	bp_fill(want, ESRCH);
	want[BP_PDDUPFD] = BP_NA;
	want[BP_PDOPENPID] = EPERM;
	want[BP_KCMP] = EPERM;
	want[BP_SC_FILEDESC] = EPERM;
	want[BP_SC_VMMAP] = EPERM;
	want[BP_SC_ENV] = EPERM;
	want[BP_KTRACE] = EPERM;
	want[BP_FSETOWN] = 0;
	column("jailed, debug off", PN_UID, false, false, name, 0, want);
}

/*
 * Item 5.  p_candebug() order, no jail: unprivileged debugging off
 * refuses the debugging calls on one's own process with EPERM and
 * leaves the visibility calls alone.
 */
BP_CASE(probe_debug_off, "Every by-pid call on a process of the same uid, "
    "unprivileged_proc_debug=0")
{
	int want[BP_NROWS];

	bp_setup(tc, "probe_debug_off");
	bp_fill(want, 0);
	want[BP_PDDUPFD] = BP_NA;
	want[BP_PT_ATTACH] = EPERM;
	want[BP_PDOPENPID] = EPERM;
	want[BP_KCMP] = EPERM;
	want[BP_SC_FILEDESC] = EPERM;
	want[BP_SC_VMMAP] = EPERM;
	want[BP_SC_ENV] = EPERM;
	want[BP_KTRACE] = EPERM;
	column("debug off", PN_UID, false, false, NULL, 0, want);
}

/*
 * Item 5.  A target that disabled tracing (P2_NOTRACE, the last test of
 * p_candebug()): EPERM for the debugging calls, the rest as for any
 * process of the same uid.
 */
BP_CASE(probe_notrace, "Every by-pid call on a process of the same uid "
    "that disabled tracing")
{
	int want[BP_NROWS];

	bp_setup(tc, "probe_notrace");
	bp_fill(want, 0);
	want[BP_PDDUPFD] = BP_NA;
	want[BP_PT_ATTACH] = EPERM;
	want[BP_PDOPENPID] = EPERM;
	want[BP_KCMP] = EPERM;
	want[BP_SC_FILEDESC] = EPERM;
	want[BP_SC_VMMAP] = EPERM;
	want[BP_SC_ENV] = EPERM;
	want[BP_KTRACE] = EPERM;
	column("notrace", PN_UID, true, false, NULL, 1, want);
}

/* --- terminals ---------------------------------------------------------- */

/* A pty: the master, and the slave's name. */
static int
pty_open(char *slave, size_t len)
{
	int m;

	m = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE_MSG(m != -1, "posix_openpt: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, grantpt(m));
	ATF_REQUIRE_EQ(0, unlockpt(m));
	ATF_REQUIRE(strlcpy(slave, ptsname(m), len) < len);
	/* The users of it drop to PN_UID. */
	ATF_REQUIRE_EQ(0, chmod(slave, 0666));
	return (m);
}

/* In a child: a new session whose controlling terminal is the slave. */
static int
tty_session(const char *slave)
{
	struct termios t;
	int fd;

	if (setsid() == -1)
		_exit(PN_X_SETUP);
	fd = open(slave, O_RDWR);
	if (fd == -1 || ioctl(fd, TIOCSCTTY, 0) != 0)
		_exit(PN_X_SETUP);
	if (tcgetattr(fd, &t) != 0)
		_exit(PN_X_SETUP);
	cfmakeraw(&t);
	if (tcsetattr(fd, TCSANOW, &t) != 0)
		_exit(PN_X_SETUP);
	return (fd);
}

/*
 * Run fn(slave name) in a child; its report is a row of ints.  With a
 * master, what the terminal prints is read and thrown away until the
 * report comes: a program that waits for its output to drain (sh -i
 * does, in tcsetattr(TCSADRAIN)) would otherwise wait for ever.
 */
static void
rows_from_child_m(void (*fn)(const char *, int *), const char *slave,
    int *rows, int nrows, int m)
{
	struct pollfd pfd[2];
	char junk[512];
	pid_t pid;
	ssize_t want;
	int n, p[2], status;

	ATF_REQUIRE_EQ(0, pipe(p));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		int r[32];

		(void)close(p[0]);
		(void)alarm(60);
		memset(r, 0xff, sizeof(r));
		fn(slave, r);
		if (write(p[1], r, sizeof(int) * (size_t)nrows) !=
		    (ssize_t)(sizeof(int) * (size_t)nrows))
			_exit(PN_X_SETUP);
		_exit(0);
	}
	(void)close(p[1]);
	want = (ssize_t)(sizeof(int) * (size_t)nrows);
	while (m != -1) {
		pfd[0].fd = p[0];
		pfd[0].events = POLLIN;
		pfd[1].fd = m;
		pfd[1].events = POLLIN;
		pfd[0].revents = pfd[1].revents = 0;
		/* The child's alarm bounds this: its death ends the pipe. */
		n = poll(pfd, 2, INFTIM);
		ATF_REQUIRE_MSG(n > 0 || errno == EINTR, "poll: %s",
		    strerror(errno));
		if (n <= 0)
			continue;
		if (pfd[0].revents != 0)
			break;
		if (pfd[1].revents != 0 && read(m, junk, sizeof(junk)) <= 0)
			break;
	}
	ATF_REQUIRE_EQ_MSG(want, read(p[0], rows, (size_t)want),
	    "the child did not report");
	(void)close(p[0]);
	status = pn_wait(pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child status %#x", status);
}

static void
rows_from_child(void (*fn)(const char *, int *), const char *slave, int *rows,
    int nrows)
{

	rows_from_child_m(fn, slave, rows, nrows, -1);
}

static void
rows_check(const char *const *names, const int *got, const int *want, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		printf("%-44s got %d want %d\n", names[i], got[i], want[i]);
		ATF_CHECK_EQ_MSG(want[i], got[i], "%s: got %d, recorded %d",
		    names[i], got[i], want[i]);
	}
}

static char	other_slave[PATH_MAX];

static void
tiocsti_child(const char *slave, int *r)
{
	char c;
	int fd, fd2;

	fd = tty_session(slave);
	fd2 = open(other_slave, O_RDWR | O_NOCTTY);
	if (fd2 == -1)
		_exit(PN_X_SETUP);
	pn_drop(PN_UID, PN_GID);
	c = 'x';
	r[0] = PN_ERR(ioctl(fd, TIOCSTI, &c));
	/* The byte is input of the terminal now. */
	c = '\0';
	r[1] = read(fd, &c, 1) == 1 ? c : -1;
	c = 'y';
	r[2] = PN_ERR(ioctl(fd2, TIOCSTI, &c));
}

/*
 * Item 6.  TIOCSTI by an unattached, unprivileged process: accepted on
 * its controlling terminal (security.bsd.allow_tiocsti is on by default)
 * and the byte is read back as input; EACCES on a terminal that is not
 * its controlling terminal.  b4 refuses an attached caller only.
 */
ATF_TC_WITHOUT_HEAD(tiocsti_controlling_tty);
ATF_TC_BODY(tiocsti_controlling_tty, tc)
{
	static const char *const names[] = {
		"TIOCSTI on the controlling terminal",
		"the byte read back from it",
		"TIOCSTI on another terminal",
	};
	static const int want[] = { 0, 'x', EACCES };
	char slave[PATH_MAX];
	size_t len;
	int allow, got[3], m, m2;

	len = sizeof(allow);
	ATF_REQUIRE_EQ(0, sysctlbyname("security.bsd.allow_tiocsti", &allow,
	    &len, NULL, 0));
	ATF_REQUIRE_EQ_MSG(1, allow, "security.bsd.allow_tiocsti is not at "
	    "its default");
	m = pty_open(slave, sizeof(slave));
	m2 = pty_open(other_slave, sizeof(other_slave));
	rows_from_child(tiocsti_child, slave, got, nitems(got));
	rows_check(names, got, want, nitems(got));
	(void)close(m);
	(void)close(m2);
}

/*
 * A member of the session for the job-control case: it does what the
 * byte it reads from "cmd" says, and answers on "ans" where it can.
 *   'w' write a byte to the terminal, answer the errno
 *   'r' read from the terminal (never answers if it is stopped)
 */
static pid_t
jc_member(int tty, int *cmdp, int *ansp)
{
	pid_t pid;
	int ans[2], cmd[2], e;
	char c;

	if (pipe(cmd) != 0 || pipe(ans) != 0)
		_exit(PN_X_SETUP);
	pid = fork();
	if (pid == -1)
		_exit(PN_X_SETUP);
	if (pid == 0) {
		/* The session leader ignores SIGTTOU; a member does not. */
		(void)signal(SIGTTOU, SIG_DFL);
		(void)close(cmd[1]);
		(void)close(ans[0]);
		while (read(cmd[0], &c, 1) == 1) {
			if (c == 'w')
				e = write(tty, "o", 1) == 1 ? 0 : errno;
			else
				e = read(tty, &c, 1) == 1 ? 0 : errno;
			(void)write(ans[1], &e, sizeof(e));
		}
		_exit(0);
	}
	(void)close(cmd[0]);
	(void)close(ans[1]);
	*cmdp = cmd[1];
	*ansp = ans[0];
	return (pid);
}

/* The signal a child stopped with, or -1. */
static int
stopsig(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, WUNTRACED) != pid || !WIFSTOPPED(status))
		return (-1);
	return (WSTOPSIG(status));
}

enum {
	JC_TCGETPGRP, JC_SETPGID_NEW, JC_TCSETPGRP_SAME, JC_TCGETPGRP_A,
	JC_TCSETPGRP_BACK, JC_TCSETPGRP_OTHER, JC_TCSETPGRP_NONE,
	JC_SETPGID_JOIN, JC_GETPGID_JOIN, JC_SETPGID_OTHER, JC_WRITE_BG,
	JC_TTIN, JC_TTIN_GROUP, JC_TTOU, JC_N
};

static pid_t	jc_outside_pgid;

static void
jc_child(const char *slave, int *r)
{
	struct termios t;
	pid_t a, b;
	int acmd, aans, bcmd, bans, e, fd;

	fd = tty_session(slave);
	pn_drop(PN_UID, PN_GID);
	/* tcsetpgrp() from the background is otherwise a SIGTTOU stop. */
	(void)signal(SIGTTOU, SIG_IGN);

	r[JC_TCGETPGRP] = tcgetpgrp(fd) == getpgrp();
	a = jc_member(fd, &acmd, &aans);
	b = jc_member(fd, &bcmd, &bans);
	r[JC_SETPGID_NEW] = PN_ERR(setpgid(a, a));
	r[JC_TCSETPGRP_SAME] = PN_ERR(tcsetpgrp(fd, a));
	r[JC_TCGETPGRP_A] = tcgetpgrp(fd) == a;
	r[JC_TCSETPGRP_BACK] = PN_ERR(tcsetpgrp(fd, getpgrp()));
	r[JC_TCSETPGRP_OTHER] = PN_ERR(tcsetpgrp(fd, jc_outside_pgid));
	r[JC_TCSETPGRP_NONE] = PN_ERR(tcsetpgrp(fd, 99999));
	r[JC_SETPGID_JOIN] = PN_ERR(setpgid(b, a));
	r[JC_GETPGID_JOIN] = getpgid(b) == a;
	r[JC_SETPGID_OTHER] = PN_ERR(setpgid(b, jc_outside_pgid));

	/* a and b are the background group a; the session leader is fg. */
	e = -1;
	if (write(acmd, "w", 1) != 1 || read(aans, &e, sizeof(e)) !=
	    (ssize_t)sizeof(e))
		_exit(PN_X_SETUP);
	r[JC_WRITE_BG] = e;
	if (write(acmd, "r", 1) != 1)
		_exit(PN_X_SETUP);
	r[JC_TTIN] = stopsig(a);
	/*
	 * The signal went to the group: b, which did nothing, is stopped
	 * too.  End a, take b's stop and continue b, alone in the group.
	 */
	r[JC_TTIN_GROUP] = stopsig(b);
	(void)kill(a, SIGKILL);
	(void)waitpid(a, NULL, 0);
	if (kill(b, SIGCONT) != 0)
		_exit(PN_X_SETUP);
	if (tcgetattr(fd, &t) != 0)
		_exit(PN_X_SETUP);
	t.c_lflag |= TOSTOP;
	if (tcsetattr(fd, TCSANOW, &t) != 0)
		_exit(PN_X_SETUP);
	if (write(bcmd, "w", 1) != 1)
		_exit(PN_X_SETUP);
	r[JC_TTOU] = stopsig(b);
	(void)kill(b, SIGKILL);
	(void)waitpid(b, NULL, 0);
}

/*
 * Item 7.  Job control inside one session of unattached, unprivileged
 * processes: tcsetpgrp() to a group of the session, refused (EPERM) for a
 * group of another session and for none; setpgid() into an existing group
 * of the session, refused (EPERM) for another session's; a background
 * write passes without TOSTOP; a background read stops its whole group
 * with SIGTTIN and a background write under TOSTOP with SIGTTOU.  The
 * design adds no rule to setpgid() or TIOCSPGRP: its T3 (b3) requires
 * that they keep working, so every row here must stay.
 */
ATF_TC_WITHOUT_HEAD(job_control);
ATF_TC_BODY(job_control, tc)
{
	static const char *const names[JC_N] = {
		"tcgetpgrp is the session leader's group",
		"setpgid(child, child)",
		"tcsetpgrp to a group of the session",
		"tcgetpgrp is that group",
		"tcsetpgrp back, from the background",
		"tcsetpgrp to a group of another session",
		"tcsetpgrp to no group",
		"setpgid into an existing group",
		"getpgid is that group",
		"setpgid into a group of another session",
		"background write without TOSTOP",
		"background read stops with",
		"  and the other member of its group with",
		"background write under TOSTOP stops with",
	};
	static const int want[JC_N] = { 1, 0, 0, 1, 0, EPERM, EPERM, 0, 1,
	    EPERM, 0, SIGTTIN, SIGTTIN, SIGTTOU };
	char slave[PATH_MAX];
	int got[JC_N], m;

	jc_outside_pgid = getpgrp();
	m = pty_open(slave, sizeof(slave));
	rows_from_child(jc_child, slave, got, JC_N);
	rows_check(names, got, want, JC_N);
	(void)close(m);
}

/* --- a job-control shell under a launcher ------------------------------- */

enum { SH_EXIT, SH_TTY_BACK, SH_LAUNCHER, SH_SHELL, SH_N };

static void
shell_child(const char *slave, int *r)
{
	static const char line[] = "exit 7\n";
	pid_t pid;
	size_t i;
	int fd, status;

	fd = tty_session(slave);
	/* The shell's input: one line, queued before it starts. */
	for (i = 0; i < sizeof(line) - 1; i++)
		if (ioctl(fd, TIOCSTI, &line[i]) != 0)
			_exit(PN_X_SETUP);
	pid = fork();
	if (pid == -1)
		_exit(PN_X_SETUP);
	if (pid == 0) {
		/* In the launcher's group, as a launcher's child is. */
		if (ktrace(ktrfile, KTROP_SET, KTRFAC_SYSCALL | KTRFAC_SYSRET,
		    getpid()) != 0)
			_exit(PN_X_SETUP);
		if (dup2(fd, 0) != 0 || dup2(fd, 1) != 1 || dup2(fd, 2) != 2)
			_exit(PN_X_SETUP);
		(void)execle("/bin/sh", "sh", "-i", NULL,
		    (char *[]){ __DECONST(char *, "PATH=/bin:/usr/bin"),
		    __DECONST(char *, "HOME=/nonexistent"),
		    __DECONST(char *, "TERM=dumb"), NULL });
		_exit(PN_X_SETUP);
	}
	if (waitpid(pid, &status, 0) != pid)
		_exit(PN_X_SETUP);
	r[SH_EXIT] = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	r[SH_TTY_BACK] = tcgetpgrp(fd) == getpgrp();
	r[SH_LAUNCHER] = (int)getpid();
	r[SH_SHELL] = (int)pid;
}

/* "self" or "launcher" for a pid or group in a trace of the shell. */
static const char *
sh_who(register_t v, pid_t shell, pid_t launcher)
{

	return (v == 0 ? "0" : v == shell ? "shell" : v == launcher ?
	    "launcher" : "other");
}

/*
 * Item 17, native.  An interactive sh(1) started by a launcher that
 * stays in the job (the shell starts in the launcher's process group,
 * which is the terminal's foreground group): the shell moves itself to
 * a group of its own and gives that group the terminal; on exit it
 * returns to the launcher's group first and gives the terminal back
 * second (sh's setjobctl(0): setpgid(), then tcsetpgrp()), so the last
 * TIOCSPGRP is made by a member of the launcher's group.  The pin
 * is the sequence of setpgid() calls and TIOCSPGRP ioctls the shell
 * makes, each with its result, from a ktrace(2) of the shell alone.
 * This is the oracle of the design's T3 (b3): an attached shell must
 * make the same four calls when the launcher's group is outside.
 * The Linux bash(1) half is not written: the Linux test data has no
 * shell.
 */
ATF_TC_WITH_CLEANUP(shell_handback);
ATF_TC_HEAD(shell_handback, tc)
{
	atf_tc_set_md_var(tc, "descr", "The setpgid and tcsetpgrp calls of "
	    "an interactive sh under a launcher in its job");
}
ATF_TC_BODY(shell_handback, tc)
{
	static const char *const names[] = {
		"the shell's exit status",
		"the terminal is the launcher's group's again",
	};
	static const int want[] = { 7, 1 };
	static const char recorded[] =
	    "setpgid(0, shell)=0 TIOCSPGRP=0 setpgid(0, launcher)=0 "
	    "TIOCSPGRP=0 ";
	struct ktr_header h;
	struct ktr_syscall *sc;
	struct ktr_sysret *sr;
	char buf[1024], seq[1024], slave[PATH_MAX];
	size_t off;
	pid_t launcher, shell;
	int fd, got[SH_N], m, pending;

	bp_setup(tc, "shell_handback");
	/* ktrace(2) opens the trace file; it does not create it. */
	fd = open(ktrfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", ktrfile, strerror(errno));
	ATF_REQUIRE_EQ(0, close(fd));
	m = pty_open(slave, sizeof(slave));
	rows_from_child_m(shell_child, slave, got, SH_N, m);
	rows_check(names, got, want, 2);
	launcher = got[SH_LAUNCHER];
	shell = got[SH_SHELL];
	(void)close(m);

	fd = open(ktrfile, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", ktrfile, strerror(errno));
	seq[0] = '\0';
	off = 0;
	pending = 0;
	while (read(fd, &h, sizeof(h)) == (ssize_t)sizeof(h)) {
		ATF_REQUIRE((h.ktr_type & KTR_VERSIONED) != 0);
		ATF_REQUIRE(h.ktr_len >= 0);
		if ((size_t)h.ktr_len > sizeof(buf)) {
			ATF_REQUIRE(lseek(fd, h.ktr_len, SEEK_CUR) != -1);
			continue;
		}
		ATF_REQUIRE_EQ(h.ktr_len, read(fd, buf, (size_t)h.ktr_len));
		if (h.ktr_pid != shell)
			continue;
		switch (h.ktr_type & ~KTR_TYPE) {
		case KTR_SYSCALL:
			sc = (struct ktr_syscall *)(void *)buf;
			pending = 0;
			if (sc->ktr_code == SYS_setpgid && sc->ktr_narg >= 2) {
				off += (size_t)snprintf(seq + off,
				    sizeof(seq) - off, "setpgid(%s, %s)",
				    sh_who(sc->ktr_args[0], shell, launcher),
				    sh_who(sc->ktr_args[1], shell, launcher));
				pending = 1;
			} else if (sc->ktr_code == SYS_ioctl &&
			    sc->ktr_narg >= 2 &&
			    (u_long)sc->ktr_args[1] == TIOCSPGRP) {
				off += (size_t)snprintf(seq + off,
				    sizeof(seq) - off, "TIOCSPGRP");
				pending = 1;
			}
			break;
		case KTR_SYSRET:
			sr = (struct ktr_sysret *)(void *)buf;
			if (pending)
				off += (size_t)snprintf(seq + off,
				    sizeof(seq) - off, "=%d ", sr->ktr_error);
			pending = 0;
			break;
		}
		ATF_REQUIRE(off < sizeof(seq) - 64);
	}
	(void)close(fd);
	printf("the shell's calls: %s\n", seq);
	ATF_CHECK_STREQ(recorded, seq);
}
ATF_TC_CLEANUP(shell_handback, tc)
{
	pn_pubdir_remove("shell_handback");
}

/* --- SIGIO -------------------------------------------------------------- */

static void
sigio_nop(int sig __unused)
{
}

/* A child that exits 0 when a SIGIO arrives (it is blocked: no race). */
static pid_t
sigio_waiter(void)
{
	struct timespec ts = { 20, 0 };
	sigset_t set;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		_exit(PN_X_SETUP);
	if (pid == 0) {
		sigemptyset(&set);
		sigaddset(&set, SIGIO);
		_exit(sigtimedwait(&set, NULL, &ts) == SIGIO ? 0 : 1);
	}
	return (pid);
}

static int
exit_code(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

enum { SO_SETOWN_PID, SO_GETOWN_PID, SO_PID_GOT, SO_SETOWN_GRP,
    SO_GETOWN_GRP, SO_GRP_GOT1, SO_GRP_GOT2, SO_N };

static void
sigio_child(const char *unused __unused, int *r)
{
	sigset_t set;
	pid_t a, b, c;
	int p[2], q[2];

	pn_drop(PN_UID, PN_GID);
	/*
	 * SIGIO is ignored by default, and an ignored signal is dropped
	 * when it is sent even if it is blocked: a waiter needs a handler.
	 */
	if (signal(SIGIO, sigio_nop) == SIG_ERR)
		_exit(PN_X_SETUP);
	sigemptyset(&set);
	sigaddset(&set, SIGIO);
	if (sigprocmask(SIG_BLOCK, &set, NULL) != 0 || pipe(p) != 0 ||
	    pipe(q) != 0)
		_exit(PN_X_SETUP);

	a = sigio_waiter();
	r[SO_SETOWN_PID] = PN_ERR(fcntl(p[0], F_SETOWN, a));
	r[SO_GETOWN_PID] = fcntl(p[0], F_GETOWN) == a;
	if (fcntl(p[0], F_SETFL, O_ASYNC) != 0 || write(p[1], "x", 1) != 1)
		_exit(PN_X_SETUP);
	r[SO_PID_GOT] = exit_code(a);

	b = sigio_waiter();
	c = sigio_waiter();
	if (setpgid(b, b) != 0 || setpgid(c, b) != 0)
		_exit(PN_X_SETUP);
	r[SO_SETOWN_GRP] = PN_ERR(fcntl(q[0], F_SETOWN, -b));
	r[SO_GETOWN_GRP] = fcntl(q[0], F_GETOWN) == -b;
	if (fcntl(q[0], F_SETFL, O_ASYNC) != 0 || write(q[1], "x", 1) != 1)
		_exit(PN_X_SETUP);
	r[SO_GRP_GOT1] = exit_code(b);
	r[SO_GRP_GOT2] = exit_code(c);
}

/*
 * Item 8.  F_SETOWN to a process and to a process group of the caller's
 * session, all unattached: accepted, and SIGIO reaches the process and
 * every member of the group.  b4 refuses or filters across the boundary
 * only.  The group with an attached member is
 * procnet_outside_test:sigio_group_with_attached.
 */
ATF_TC_WITHOUT_HEAD(sigio_owner);
ATF_TC_BODY(sigio_owner, tc)
{
	static const char *const names[SO_N] = {
		"F_SETOWN to a process of the session",
		"F_GETOWN is that process",
		"exit of the owner (0: it got SIGIO)",
		"F_SETOWN to a group of the session",
		"F_GETOWN is that group",
		"exit of the first member (0: SIGIO)",
		"exit of the second member (0: SIGIO)",
	};
	static const int want[SO_N] = { 0, 1, 0, 0, 1, 0, 0 };
	int got[SO_N];

	rows_from_child(sigio_child, NULL, got, SO_N);
	rows_check(names, got, want, SO_N);
}

/* --- no new privileges -------------------------------------------------- */

static int
nnp_status(pid_t pid)
{
	int v;

	v = -1;
	if (procctl(P_PID, pid, PROC_NO_NEW_PRIVS_STATUS, &v) != 0)
		return (-errno);
	return (v);
}

static void
nnp_child(const char *unused __unused, int *r)
{
	pid_t pid;
	int v;

	r[0] = nnp_status(getpid());
	v = PROC_NO_NEW_PRIVS_ENABLE;
	r[1] = PN_ERR(procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &v));
	r[2] = nnp_status(getpid());
	pid = fork();
	if (pid == -1)
		_exit(PN_X_SETUP);
	if (pid == 0)
		_exit(nnp_status(getpid()));
	r[3] = exit_code(pid);
	/* One-way: it cannot be turned off again. */
	v = PROC_NO_NEW_PRIVS_DISABLE;
	r[4] = PN_ERR(procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &v));
}

/*
 * Item 9.  P2_NO_NEW_PRIVS: off in an unattached process, set by
 * procctl(2), inherited by a fork, and never cleared.  dq attach sets the
 * same flag; b0 pins the plain mechanism the launch slices rely on.  That
 * the fork of an unattached parent consults no supervisor is
 * procnet_outside_test:unattached_fork_not_consulted.
 */
ATF_TC_WITHOUT_HEAD(no_new_privs_fork);
ATF_TC_BODY(no_new_privs_fork, tc)
{
	static const char *const names[] = {
		"PROC_NO_NEW_PRIVS_STATUS at first",
		"PROC_NO_NEW_PRIVS_CTL enable",
		"status after",
		"status in a fork",
		"PROC_NO_NEW_PRIVS_CTL disable",
	};
	static const int want[] = { PROC_NO_NEW_PRIVS_DISABLE, 0,
	    PROC_NO_NEW_PRIVS_ENABLE, PROC_NO_NEW_PRIVS_ENABLE, EINVAL };
	int got[5];

	rows_from_child(nnp_child, NULL, got, nitems(got));
	rows_check(names, got, want, nitems(got));
}

/* --- a child killed by a third process ---------------------------------- */

/* How long a victim waits to be killed before it gives up. */
#define	VICTIM_BOUND	280

static int
kill_it(void *arg)
{
	int *a = arg;

	return (PN_ERR(kill(a[0], a[1])));
}

/*
 * A child of this process that runs as PN_UID and waits to be killed.
 * It says so on a pipe once it has dropped its uid: a killer of PN_UID
 * that ran before the drop would be refused (EPERM) and leave the
 * parent waiting for a death that never comes.  Its own alarm bounds
 * that wait in any case; a victim that dies of SIGALRM fails the
 * status rows.
 */
static pid_t
victim(int *pdp)
{
	pid_t pid;
	int p[2];
	char c;

	ATF_REQUIRE_EQ(0, pipe(p));
	pid = pdp != NULL ? pdfork(pdp, 0) : fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)close(p[0]);
		(void)alarm(VICTIM_BOUND);
		pn_drop(PN_UID, PN_GID);
		if (write(p[1], "u", 1) != 1)
			_exit(PN_X_SETUP);
		(void)close(p[1]);
		for (;;)
			(void)pause();
	}
	(void)close(p[1]);
	ATF_REQUIRE_EQ_MSG(1, read(p[0], &c, 1),
	    "the victim did not report its uid drop");
	(void)close(p[0]);
	return (pid);
}

/* The third process kills; a refusal ends the case, and the victim. */
static void
third_party_kill(pid_t pid, int sig)
{
	int a[2], error;

	a[0] = pid;
	a[1] = sig;
	error = pn_child(kill_it, a, PN_UID, PN_GID);
	if (error != 0) {
		(void)kill(pid, SIGKILL);
		atf_tc_fail("kill by a third process: %d", error);
	}
}

/*
 * Item 11.  What the parent of a process killed by a third process (not
 * its parent, same uid) sees from wait6(2) and from pdwait(2): the
 * signal as the wait status, CLD_KILLED, and the child's pid and uid in
 * the siginfo.  The control and boundary slices let a supervisor do the
 * killing; the parent's view must stay this.
 */
ATF_TC_WITHOUT_HEAD(third_party_kill_status);
ATF_TC_BODY(third_party_kill_status, tc)
{
	static const int sigs[] = { SIGKILL, SIGTERM };
	struct __wrusage wru;
	siginfo_t si;
	pid_t pid;
	size_t i;
	int pd, status;

	for (i = 0; i < nitems(sigs); i++) {
		/* wait6 */
		pid = victim(NULL);
		third_party_kill(pid, sigs[i]);
		memset(&si, 0, sizeof(si));
		status = 0;
		ATF_REQUIRE_EQ(pid, wait6(P_PID, pid, &status, WEXITED, &wru,
		    &si));
		ATF_CHECK_EQ(sigs[i], status);
		ATF_CHECK_EQ(SIGCHLD, si.si_signo);
		ATF_CHECK_EQ(CLD_KILLED, si.si_code);
		ATF_CHECK_EQ(sigs[i], si.si_status);
		ATF_CHECK_EQ(pid, si.si_pid);
		ATF_CHECK_EQ(PN_UID, si.si_uid);

		/* pdwait */
		pid = victim(&pd);
		third_party_kill(pid, sigs[i]);
		memset(&si, 0, sizeof(si));
		status = 0;
		ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, &wru, &si));
		ATF_CHECK_EQ(sigs[i], status);
		ATF_CHECK_EQ(SIGCHLD, si.si_signo);
		ATF_CHECK_EQ(CLD_KILLED, si.si_code);
		ATF_CHECK_EQ(sigs[i], si.si_status);
		ATF_CHECK_EQ(pid, si.si_pid);
		ATF_CHECK_EQ(PN_UID, si.si_uid);
		(void)close(pd);
	}
}

/* --- fork under load ---------------------------------------------------- */

#define	MARK_FD		200
#define	NCHURN		4

static volatile int	churn_stop;

static void *
churn(void *arg __unused)
{
	int fd, fd2;

	while (churn_stop == 0) {
		fd = open("/dev/null", O_RDONLY);
		if (fd == -1)
			continue;
		fd2 = dup(fd);
		(void)close(fd);
		if (fd2 != -1)
			(void)close(fd2);
	}
	return (NULL);
}

static void
churn_start(pthread_t *t, struct stat *mark)
{
	int fd, i;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(MARK_FD, dup2(fd, MARK_FD));
	(void)close(fd);
	ATF_REQUIRE_EQ(0, fstat(MARK_FD, mark));
	churn_stop = 0;
	for (i = 0; i < NCHURN; i++)
		ATF_REQUIRE_EQ(0, pthread_create(&t[i], NULL, churn, NULL));
}

static void
churn_end(pthread_t *t)
{
	int i;

	churn_stop = 1;
	for (i = 0; i < NCHURN; i++)
		ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
	(void)close(MARK_FD);
}

/* In a forked child: the marked descriptor came across whole. */
static int
mark_ok(const struct stat *mark)
{
	struct stat sb;

	if (fstat(MARK_FD, &sb) != 0 || sb.st_dev != mark->st_dev ||
	    sb.st_ino != mark->st_ino || sb.st_rdev != mark->st_rdev)
		return (1);
	return (0);
}

/*
 * Item 15.  fork(2) from a process whose other threads open, dup and
 * close descriptors all the while: every one of 64 children has the
 * descriptor that was open throughout, and exits 0.  The boundary and
 * launch slices add work to fork (membership, inherited flags) under the
 * descriptor-table and process locks; an unattached process must not
 * notice.
 */
ATF_TC_WITHOUT_HEAD(fork_mt_fd_churn);
ATF_TC_BODY(fork_mt_fd_churn, tc)
{
	pthread_t t[NCHURN];
	struct stat mark;
	pid_t pid;
	int i, status;

	churn_start(t, &mark);
	for (i = 0; i < 64; i++) {
		pid = fork();
		ATF_REQUIRE(pid != -1);
		if (pid == 0)
			_exit(mark_ok(&mark));
		status = pn_wait(pid);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "fork %d: status %#x", i, status);
	}
	churn_end(t);
}

/* Item 15: the same with vfork(2). */
ATF_TC_WITHOUT_HEAD(vfork_mt_fd_churn);
ATF_TC_BODY(vfork_mt_fd_churn, tc)
{
	pthread_t t[NCHURN];
	struct stat mark;
	pid_t pid;
	int i, status;

	churn_start(t, &mark);
	for (i = 0; i < 64; i++) {
		pid = vfork();
		ATF_REQUIRE(pid != -1);
		if (pid == 0)
			_exit(fcntl(MARK_FD, F_GETFD) == -1 ? 1 : 0);
		status = pn_wait(pid);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "vfork %d: status %#x", i, status);
	}
	churn_end(t);
}

#define	NBURST		8
#define	PERBURST	32

static void *
burst(void *arg)
{
	int *bad = arg;
	pid_t pid;
	int i, status;

	for (i = 0; i < PERBURST; i++) {
		pid = fork();
		if (pid == 0)
			_exit(fcntl(MARK_FD, F_GETFD) == -1 ? 1 : 0);
		if (pid == -1 || waitpid(pid, &status, 0) != pid ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			(*bad)++;
	}
	return (NULL);
}

/*
 * Item 15.  A burst of concurrent forks: eight threads fork and reap 32
 * children each; all 256 exist, have the marked descriptor and exit 0.
 */
ATF_TC_WITHOUT_HEAD(fork_burst);
ATF_TC_BODY(fork_burst, tc)
{
	pthread_t t[NBURST];
	int bad[NBURST], fd, i;

	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(MARK_FD, dup2(fd, MARK_FD));
	memset(bad, 0, sizeof(bad));
	for (i = 0; i < NBURST; i++)
		ATF_REQUIRE_EQ(0, pthread_create(&t[i], NULL, burst, &bad[i]));
	for (i = 0; i < NBURST; i++) {
		ATF_REQUIRE_EQ(0, pthread_join(t[i], NULL));
		ATF_CHECK_EQ_MSG(0, bad[i], "thread %d: %d of %d forks went "
		    "wrong", i, bad[i], PERBURST);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, probe_same_uid);
	ATF_TP_ADD_TC(tp, probe_names_nothing);
	ATF_TP_ADD_TC(tp, probe_other_uid);
	ATF_TP_ADD_TC(tp, probe_jailed_debug_on);
	ATF_TP_ADD_TC(tp, probe_jailed_debug_off);
	ATF_TP_ADD_TC(tp, probe_debug_off);
	ATF_TP_ADD_TC(tp, probe_notrace);
	ATF_TP_ADD_TC(tp, tiocsti_controlling_tty);
	ATF_TP_ADD_TC(tp, job_control);
	ATF_TP_ADD_TC(tp, shell_handback);
	ATF_TP_ADD_TC(tp, sigio_owner);
	ATF_TP_ADD_TC(tp, no_new_privs_fork);
	ATF_TP_ADD_TC(tp, third_party_kill_status);
	ATF_TP_ADD_TC(tp, fork_mt_fd_churn);
	ATF_TP_ADD_TC(tp, vfork_mt_fd_churn);
	ATF_TP_ADD_TC(tp, fork_burst);
	return (atf_no_error());
}
