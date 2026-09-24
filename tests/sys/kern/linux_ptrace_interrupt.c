/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 PTRACE_INTERRUPT seized-stop lifecycle contract. */
#include "linux_test.h"

#define PTRACE 101
#define PTRACE_CONT 7
#define PTRACE_SINGLESTEP 9
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_SYSCALL 24
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define PTRACE_EVENT_STOP 128
#define SIGTRAP 5
#define SIGUSR1 10
#define SIGSTOP 19
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
wait_event(long pid, int expected)
{
	int status;

	if (sys4(SYS_wait4, pid, &status, __WALL, 0) != pid)
		return (1);
	return (status != expected);
}

static int
test(int argc, char **argv, char **envp)
{
	struct shared *s;
	long pid;
	int info[32], status;

	(void)argc;
	(void)argv;
	(void)envp;
	if (trace(PTRACE_INTERRUPT, 999999, 0, 0) != -ESRCH)
		return (1);
	s = shared_page();
	if (s == 0)
		return (2);

	/* INTERRUPT is rejected for a traditional ATTACH relationship. */
	pid = spawn(s, 17);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_ATTACH, pid, 0, 0) != 0 ||
	    wait_event(pid, SIGSTOP << 8 | 0x7f) != 0)
		return (3);
	if (trace(PTRACE_INTERRUPT, pid, 0, 0) != -EIO)
		return (4);
	if (trace(PTRACE_DETACH, pid, 0, 0) != 0)
		return (5);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != (17 << 8))
		return (6);

	/* A seized running target enters a PTRACE_EVENT_STOP trap. */
	s->ticks = 0;
	s->leave = 0;
	pid = spawn(s, 23);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_SEIZE, pid, 0, 0) != 0)
		return (7);
	/* Linux ignores addr and data for INTERRUPT. */
	if (trace(PTRACE_INTERRUPT, pid, 1, 2) != 0 ||
	    wait_event(pid, PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f) != 0)
		return (8);
	if (trace(PTRACE_GETSIGINFO, pid, 0, (long)info) != 0 ||
	    info[0] != SIGTRAP || info[2] != (PTRACE_EVENT_STOP << 8 | SIGTRAP))
		return (9);

	/* An interrupt requested in a ptrace-stop produces a later stop. */
	if (trace(PTRACE_INTERRUPT, pid, 0, 0) != 0 ||
	    trace(PTRACE_CONT, pid, 0, 0) != 0 ||
	    wait_event(pid, PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f) != 0)
		return (10);
	/* A queued interrupt also takes precedence over syscall tracing. */
	if (trace(PTRACE_INTERRUPT, pid, 0, 0) != 0 ||
	    trace(PTRACE_SYSCALL, pid, 0, 0) != 0 ||
	    wait_event(pid, PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f) != 0)
		return (11);
	/* SINGLESTEP may win the race, but cannot consume the queued interrupt. */
	if (trace(PTRACE_INTERRUPT, pid, 0, 0) != 0 ||
	    trace(PTRACE_SINGLESTEP, pid, 0, 0) != 0 ||
	    sys4(SYS_wait4, pid, &status, __WALL, 0) != pid)
		return (15);
	if (status == (SIGTRAP << 8 | 0x7f)) {
		if (trace(PTRACE_CONT, pid, 0, 0) != 0 ||
		    wait_event(pid, PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 |
		    0x7f) != 0)
			return (16);
	} else if (status != (PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f))
		return (17);
	if (trace(PTRACE_CONT, pid, 0, 0) != 0 || wait_running(s) != 0)
		return (18);

	/* A pending interrupt does not disturb the current signal stop. */
	if (sys2(SYS_kill, pid, SIGUSR1) != 0 ||
	    wait_event(pid, SIGUSR1 << 8 | 0x7f) != 0 ||
	    trace(PTRACE_INTERRUPT, pid, 0, 0) != 0 ||
	    trace(PTRACE_CONT, pid, 0, 0) != 0 ||
	    wait_event(pid, PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f) != 0)
		return (12);
	if (trace(PTRACE_DETACH, pid, 0, 0) != 0)
		return (13);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != (23 << 8))
		return (14);
	return (0);
}
