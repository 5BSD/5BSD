/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * clone(2)/clone3(2) flag handling and the wait4/waitid __WALL/__WCLONE/
 * __WNOTHREAD options.  Namespace flags must be rejected (no namespaces
 * exist; Linux without CONFIG_*_NS returns EINVAL) rather than degrading
 * into a plain fork.  Exit status = failed check number.
 */
#define	CHILD_STATUS	7

static const struct timespec pause = { 0, 20000000 };

/* Raw fork-style clone: no new stack, so the child shares nothing. */
static long
do_clone(unsigned long flags)
{
	long pid;

	pid = call(SYS_clone, flags, 0, 0, 0, 0, 0);
	if (pid == 0)
		(void)sys1(SYS_exit_group, CHILD_STATUS);
	return (pid);
}

static long
do_clone3(u64 flags, u64 exit_signal)
{
	struct clone_args ca;
	long pid;

	xmemset(&ca, 0, sizeof(ca));
	ca.flags = flags;
	ca.exit_signal = exit_signal;
	pid = sys2(SYS_clone3, &ca, sizeof(ca));
	if (pid == 0)
		(void)sys1(SYS_exit_group, CHILD_STATUS);
	return (pid);
}

static int
reaped_ok(long pid, long options)
{
	int status = 0;
	long r;

	r = sys4(SYS_wait4, pid, &status, options, 0);
	return (r == pid && (status & 0x7f) == 0 &&
	    ((status >> 8) & 0xff) == CHILD_STATUS);
}

static int
no_children(void)
{
	int status;

	return (sys4(SYS_wait4, -1, &status, WNOHANG | __WALL, 0) == -ECHILD);
}

static int
test(int argc, char **argv, char **envp)
{
	unsigned long nsflags[] = { CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS,
	    CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET };
	unsigned long okflags[] = { CLONE_SYSVSEM, CLONE_IO, CLONE_UNTRACED,
	    CLONE_PTRACE, CLONE_FS, CLONE_FILES };
	unsigned long mask[2];
	long pid, i;
	int status;

	(void)argc; (void)argv; (void)envp;

	/* 1: a fork-style clone with SIGCHLD works and is reaped. */
	pid = do_clone(SIGCHLD);
	if (pid <= 0) return (1);
	if (!reaped_ok(pid, 0)) return (1);

	/* 2-8: every namespace flag is EINVAL and creates no child. */
	for (i = 0; i < 7; i++) {
		if (do_clone(nsflags[i] | SIGCHLD) != -EINVAL) return (2 + i);
		if (!no_children()) return (2 + i);
	}
	/* 9: combinations too, with and without an exit signal. */
	if (do_clone(CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD) != -EINVAL)
		return (9);
	if (do_clone(CLONE_NEWPID) != -EINVAL) return (9);
	if (!no_children()) return (9);

	/* 10-15: flags Linux accepts as no-ops for a fork still fork. */
	for (i = 0; i < 6; i++) {
		pid = do_clone(okflags[i] | SIGCHLD);
		if (pid <= 0) return (10 + i);
		if (!reaped_ok(pid, 0)) return (10 + i);
	}

	/*
	 * 16-18: a child with exit signal 0 (no SIGCHLD) is invisible to a
	 * plain wait4 (ECHILD), and reaped by __WALL.
	 */
	pid = do_clone(0);
	if (pid <= 0) return (16);
	(void)sys2(SYS_nanosleep, &pause, 0);
	if (sys4(SYS_wait4, pid, &status, WNOHANG, 0) != -ECHILD) return (17);
	if (!reaped_ok(pid, __WALL)) return (18);

	/* 19-20: a child with another exit signal is reaped by __WCLONE. */
	mask[0] = 1UL << (SIGUSR1 - 1);
	mask[1] = 0;
	(void)sys4(SYS_rt_sigprocmask, SIG_BLOCK, mask, 0, 8);
	pid = do_clone(SIGUSR1);
	if (pid <= 0) return (19);
	if (!reaped_ok(pid, __WCLONE)) return (20);

	/* 21: __WCLONE does not see a SIGCHLD child (ECHILD)... */
	pid = do_clone(SIGCHLD);
	if (pid <= 0) return (21);
	(void)sys2(SYS_nanosleep, &pause, 0);
	if (sys4(SYS_wait4, pid, &status, WNOHANG | __WCLONE, 0) != -ECHILD)
		return (21);
	/* 22: ...__WALL does. */
	if (!reaped_ok(pid, __WALL)) return (22);
	/* 23: __WNOTHREAD is accepted (a subset of the per-process wait). */
	pid = do_clone(SIGCHLD);
	if (pid <= 0) return (23);
	if (!reaped_ok(pid, __WNOTHREAD)) return (23);
	/* 24: __WALL|__WCLONE together behave as __WALL. */
	pid = do_clone(SIGCHLD);
	if (pid <= 0) return (24);
	if (!reaped_ok(pid, __WALL | __WCLONE)) return (24);

	/* 25-26: waitid honours __WALL and __WCLONE the same way. */
	pid = do_clone(0);
	if (pid <= 0) return (25);
	{
		long si[16];

		xmemset(si, 0, sizeof(si));
		if (sys5(SYS_waitid, P_PID, pid, si, WEXITED | WNOHANG, 0) !=
		    -ECHILD) return (25);
		if (sys5(SYS_waitid, P_PID, pid, si, WEXITED | __WALL, 0) != 0)
			return (26);
		/* si_pid at offset 16, si_status at 24. */
		if (((int *)si)[4] != pid || ((int *)si)[6] != CHILD_STATUS)
			return (26);
	}

	/* 27-28: unknown wait option bits are EINVAL. */
	if (sys4(SYS_wait4, -1, &status, 0x100, 0) != -EINVAL) return (27);
	if (sys5(SYS_waitid, P_ALL, 0, 0, WEXITED | 0x100, 0) != -EINVAL)
		return (28);

	/* 29-31: clone3 rejects the namespace flags and NEWTIME too. */
	if (do_clone3(CLONE_NEWUSER, SIGCHLD) != -EINVAL) return (29);
	if (do_clone3(CLONE_NEWNS | CLONE_NEWPID, SIGCHLD) != -EINVAL)
		return (30);
	if (do_clone3(CLONE_NEWTIME, SIGCHLD) != -EINVAL) return (31);
	if (!no_children()) return (31);
	/* 32: an unknown high clone3 flag bit is EINVAL. */
	if (do_clone3(1ULL << 40, SIGCHLD) != -EINVAL) return (32);
	/* 33: a plain clone3 fork works. */
	pid = do_clone3(0, SIGCHLD);
	if (pid <= 0) return (33);
	if (!reaped_ok(pid, 0)) return (33);
	/* 34: clone3 with exit_signal 0 needs __WALL as well. */
	pid = do_clone3(0, 0);
	if (pid <= 0) return (34);
	(void)sys2(SYS_nanosleep, &pause, 0);
	if (sys4(SYS_wait4, pid, &status, WNOHANG, 0) != -ECHILD) return (34);
	if (!reaped_ok(pid, __WALL)) return (34);
	/* 35: clone3 with CLONE_SYSVSEM|CLONE_IO forks normally. */
	pid = do_clone3(CLONE_SYSVSEM | CLONE_IO, SIGCHLD);
	if (pid <= 0) return (35);
	if (!reaped_ok(pid, 0)) return (35);
	/* 36: nothing was left behind. */
	if (!no_children()) return (36);
	return (0);
}

