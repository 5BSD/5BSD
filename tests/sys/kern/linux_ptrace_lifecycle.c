/* SPDX-License-Identifier: BSD-2-Clause */
/* amd64 Linux ptrace lifecycle oracle; run only in disposable guests. */
#include "linux_test.h"
#define PTRACE 101

static int
kill_tracee(int attach, int sender, int options)
{
	long child, killer;
	int st;
	child = fork_process();
	if (child < 0)
		return 1;
	if (child == 0) {
		if (!attach) {
			if (sys4(PTRACE, 0, 0, 0, 0))
				sys1(SYS_exit, 90);
			sys2(SYS_kill, sys0(SYS_getpid), 19);
		}
		for (;;)
			sys0(SYS_sched_yield);
	}
	if (attach && sys4(PTRACE, 16, child, 0, 0))
		return 2;
	if (sys4(SYS_wait4, child, &st, 0, 0) != child || (st & 255) != 127)
		return 3;
	if (options && sys4(PTRACE, 0x4200, child, 0, 0x100000))
		return 4;
	if (sender) {
		killer = fork_process();
		if (killer < 0)
			return 5;
		if (killer == 0)
			sys1(SYS_exit, sys2(SYS_kill, child, 9) != 0);
		if (sys4(SYS_wait4, killer, &st, 0, 0) != killer || st != 0)
			return 6;
	} else if (sys2(SYS_kill, child, 9))
		return 7;
	if (sys4(SYS_wait4, child, &st, 0, 0) != child || st != 9)
		return 8;
	if (sys4(SYS_wait4, child, &st, 1, 0) != -ECHILD)
		return 9;
	return 0;
}

static int
kill_during_reads(void)
{
	long child, killer, ret;
	int st;
	unsigned char buffer[8192];
	struct {
		void *base;
		u64 len;
	} v;
	struct {
		long sec, nsec;
	} ts = { 0, 1000000 };
	child = fork_process();
	if (child < 0)
		return 101;
	if (!child) {
		if (sys4(PTRACE, 0, 0, 0, 0))
			sys1(SYS_exit, 90);
		__asm__ volatile("int3" ::: "memory");
		for (;;)
			sys0(SYS_sched_yield);
	}
	if (sys4(SYS_wait4, child, &st, 0, 0) != child || st != 0x57f)
		return 102;
	killer = fork_process();
	if (killer < 0)
		return 103;
	if (!killer) {
		sys2(SYS_nanosleep, &ts, 0);
		sys1(SYS_exit, sys2(SYS_kill, child, 9) != 0);
	}
	for (int i = 0; i < 10000; i++) {
		v.base = buffer;
		v.len = sizeof(buffer);
		ret = sys4(PTRACE, 0x4204, child, 0x202, &v);
		if (ret == -ESRCH)
			break;
		if (ret)
			return 104;
	}
	if (sys4(SYS_wait4, killer, &st, 0, 0) != killer || st)
		return 105;
	if (sys4(SYS_wait4, child, &st, 0, 0) != child || st != 9)
		return 106;
	return 0;
}

static int
test(int argc, char **argv, char **envp)
{
	int error;
	(void)argc;
	(void)argv;
	(void)envp;
	for (int i = 0; i < 8; i++) {
		error = kill_tracee(i & 1, i & 2, i & 4);
		if (error)
			return 10 * (i + 1) + error;
	}
	for (int i = 0; i < 16; i++) {
		error = kill_during_reads();
		if (error)
			return error;
	}
	return 0;
}
