/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 PTRACE_SEIZE no-stop attachment and atomic-option contract. */
#include "linux_test.h"

#define PTRACE 101
#define PTRACE_CONT 7
#define PTRACE_DETACH 17
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SEIZE 0x4206
#define PTRACE_O_TRACEEXIT 64
#define PTRACE_EVENT_EXIT 6
#define SIGUSR1 10
#define SIGKILL 9
#define WNOHANG 1
#define __WALL 0x40000000

struct shared {
	volatile u64 ticks;
	volatile u32 leave;
};

static long
trace(long request, long pid, long addr, long data)
{
	return (sys4(PTRACE, request, pid, addr, data));
}

static struct shared *
shared_page(void)
{
	long p;

	p = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	return (p < 0 ? 0 : (struct shared *)p);
}

static long
spawn(struct shared *s, int code)
{
	long pid;

	pid = fork_process();
	if (pid != 0)
		return (pid);
	while (!s->leave) {
		s->ticks++;
		(void)sys0(SYS_sched_yield);
	}
	sys1(SYS_exit, code);
	return (0);
}

static int
wait_running(struct shared *s)
{
	u64 old;

	for (int i = 0; i != 10000 && s->ticks < 32; i++)
		(void)sys0(SYS_sched_yield);
	if (s->ticks < 32)
		return (1);
	old = s->ticks;
	for (int i = 0; i != 10000 && s->ticks == old; i++)
		(void)sys0(SYS_sched_yield);
	return (s->ticks == old);
}

static int
test(int argc, char **argv, char **envp)
{
	struct shared *s;

	(void)argc;
	(void)argv;
	(void)envp;
	long pid;
	int st, info[32];
	u64 before;

	/* Argument and target errors are checked before changing trace state. */
	if (trace(PTRACE_SEIZE, 999999, 0, 0) != -ESRCH)
		return (1);
	if (trace(PTRACE_SEIZE, sys0(SYS_getpid), 0, 0) != -EPERM)
		return (2);

	s = shared_page();
	if (s == 0)
		return (3);
	pid = spawn(s, 17);
	if (pid < 0 || wait_running(s) != 0)
		return (4);
	if (trace(PTRACE_SEIZE, pid, 1, 0) != -EIO ||
	    trace(PTRACE_SEIZE, pid, 0, 1UL << 31) != -EIO)
		return (5);
	before = s->ticks;
	if (trace(PTRACE_SEIZE, pid, 0, 0) != 0)
		return (6);
	/* SEIZE must return without stopping the tracee or creating wait status. */
	if (wait_running(s) != 0 || s->ticks == before ||
	    sys4(SYS_wait4, pid, &st, WNOHANG | __WALL, 0) != 0)
		return (7);
	/* Requests that require a ptrace-stop still fail while it runs. */
	if (trace(PTRACE_SETOPTIONS, pid, 0, 0) != -ESRCH)
		return (8);
	if (sys2(SYS_kill, pid, SIGUSR1) != 0 ||
	    sys4(SYS_wait4, pid, &st, __WALL, 0) != pid || st != 0x0a7f)
		return (9);
	if (trace(PTRACE_GETSIGINFO, pid, 0, (long)info) != 0 ||
	    info[0] != SIGUSR1)
		return (10);
	if (trace(PTRACE_DETACH, pid, 0, 0) != 0)
		return (11);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &st, 0, 0) != pid || st != (17 << 8))
		return (12);

	/* Options supplied to SEIZE are active before the tracee can exit. */
	s->ticks = 0;
	s->leave = 0;
	pid = spawn(s, 23);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEEXIT) != 0)
		return (13);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &st, __WALL, 0) != pid ||
	    ((u32)st >> 16) != PTRACE_EVENT_EXIT || (st & 0xffff) != 0x057f)
		return (14);
	if (trace(PTRACE_CONT, pid, 0, 0) != 0 ||
	    sys4(SYS_wait4, pid, &st, __WALL, 0) != pid || st != (23 << 8))
		return (15);
	return (0);
}
