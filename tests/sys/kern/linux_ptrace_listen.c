/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 PTRACE_LISTEN group-stop, visibility, and wakeup contract. */
#include "linux_test.h"

#define PTRACE 101
#define PTRACE_PEEKDATA 2
#define PTRACE_CONT 7
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define PTRACE_LISTEN 0x4208
#define PTRACE_EVENT_STOP 128
#define SIGTRAP 5
#define SIGCONT 18
#define SIGSTOP 19
#define __WALL 0x40000000

#define SIGNAL_STOP_STATUS (SIGSTOP << 8 | 0x7f)
#define CONT_STOP_STATUS (SIGCONT << 8 | 0x7f)
#define GROUP_STOP_STATUS (PTRACE_EVENT_STOP << 16 | SIGSTOP << 8 | 0x7f)
#define TRAP_STOP_STATUS (PTRACE_EVENT_STOP << 16 | SIGTRAP << 8 | 0x7f)

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
wait_status(long pid, int expected)
{
	int status;

	if (sys4(SYS_wait4, pid, &status, __WALL, 0) != pid)
		return (1);
	return (status != expected);
}

static int
seize_group_stop(struct shared *s, long *pidp)
{
	long pid;
	int status;

	s->ticks = 0;
	s->leave = 0;
	pid = spawn(s, 31);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_SEIZE, pid, 0, 0) != 0)
		return (1);
	if (sys2(SYS_kill, pid, SIGSTOP) != 0 ||
	    wait_status(pid, SIGNAL_STOP_STATUS) != 0)
		return (2);
	/* The first stop is signal delivery, not yet an event/group stop. */
	if (trace(PTRACE_LISTEN, pid, 0, 0) != -EIO)
		return (3);
	if (trace(PTRACE_CONT, pid, 0, SIGSTOP) != 0 ||
	    wait_status(pid, GROUP_STOP_STATUS) != 0)
		return (4);
	*pidp = pid;
	(void)status;
	return (0);
}

static int
kill_reap(long pid)
{
	int status;

	if (sys2(SYS_kill, pid, SIGKILL) != 0 ||
	    sys4(SYS_wait4, pid, &status, __WALL, 0) != pid)
		return (1);
	return (status != SIGKILL);
}

static int
target_errors(void)
{
	struct shared *s;
	long pid;
	int status;

	if (trace(PTRACE_LISTEN, 999999, 0, 0) != -ESRCH)
		return (1);
	s = shared_page();
	if (s == 0)
		return (2);
	pid = spawn(s, 17);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_ATTACH, pid, 0, 0) != 0 ||
	    wait_status(pid, SIGNAL_STOP_STATUS) != 0)
		return (3);
	if (trace(PTRACE_LISTEN, pid, 0, 0) != -EIO ||
	    trace(PTRACE_DETACH, pid, 0, 0) != 0)
		return (4);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != (17 << 8))
		return (5);

	s->ticks = 0;
	s->leave = 0;
	pid = spawn(s, 19);
	if (pid < 0 || wait_running(s) != 0 ||
	    trace(PTRACE_SEIZE, pid, 0, 0) != 0)
		return (6);
	if (trace(PTRACE_LISTEN, pid, 0, 0) != -ESRCH)
		return (7);
	return (kill_reap(pid) == 0 ? 0 : 8);
}

static int
listen_interrupt(void)
{
	struct shared *s;
	long pid;
	u64 before;
	int info[32], status;

	s = shared_page();
	if (s == 0 || seize_group_stop(s, &pid) != 0)
		return (1);
	for (int i = 0; i != 32; i++)
		info[i] = 0x55555555;
	if (trace(PTRACE_GETSIGINFO, pid, 0, (long)info) != 0 ||
	    info[0] != SIGSTOP || info[2] != (PTRACE_EVENT_STOP << 8 | SIGSTOP))
		return (2);
	/* Linux ignores addr/data for LISTEN. */
	if (trace(PTRACE_LISTEN, pid, 11, 22) != 0)
		return (3);
	before = s->ticks;
	status = -1;
	if (sys4(SYS_wait4, pid, &status, __WALL | WNOHANG, 0) != 0 ||
	    status != -1)
		return (4);
	for (int i = 0; i != 10000; i++)
		(void)sys0(SYS_sched_yield);
	if (s->ticks != before)
		return (5);
	/* A listener is not an actionable ptrace stop. */
	if (trace(PTRACE_GETSIGINFO, pid, 0, (long)info) != -ESRCH ||
	    trace(PTRACE_PEEKDATA, pid, (long)s, 0) != -ESRCH ||
	    trace(PTRACE_LISTEN, pid, 0, 0) != -ESRCH ||
	    trace(PTRACE_CONT, pid, 0, 0) != -ESRCH)
		return (6);
	if (trace(PTRACE_INTERRUPT, pid, 99, 88) != 0 ||
	    wait_status(pid, GROUP_STOP_STATUS) != 0)
		return (7);
	return (kill_reap(pid) == 0 ? 0 : 8);
}

static int
listen_sigcont(void)
{
	struct shared *s;
	long pid;
	u64 before;
	int info[32], status;

	s = shared_page();
	if (s == 0 || seize_group_stop(s, &pid) != 0 ||
	    trace(PTRACE_LISTEN, pid, 0, 0) != 0)
		return (1);
	if (sys2(SYS_kill, pid, SIGCONT) != 0 ||
	    wait_status(pid, TRAP_STOP_STATUS) != 0)
		return (2);
	if (trace(PTRACE_GETSIGINFO, pid, 0, (long)info) != 0 ||
	    info[0] != SIGTRAP || info[2] != (PTRACE_EVENT_STOP << 8 | SIGTRAP))
		return (3);
	before = s->ticks;
	if (trace(PTRACE_CONT, pid, 0, 0) != 0 ||
	    wait_status(pid, CONT_STOP_STATUS) != 0 || s->ticks != before)
		return (4);
	if (trace(PTRACE_CONT, pid, 0, 0) != 0 || wait_running(s) != 0)
		return (5);
	s->leave = 1;
	if (sys4(SYS_wait4, pid, &status, __WALL, 0) != pid ||
	    status != (31 << 8))
		return (6);
	return (0);
}

static int
repeated_interrupt(void)
{
	struct shared *s;
	long pid;

	s = shared_page();
	if (s == 0 || seize_group_stop(s, &pid) != 0)
		return (1);
	for (int i = 0; i != 16; i++) {
		if (trace(PTRACE_LISTEN, pid, i, i + 1) != 0 ||
		    trace(PTRACE_INTERRUPT, pid, i + 2, i + 3) != 0 ||
		    wait_status(pid, GROUP_STOP_STATUS) != 0)
			return (2 + i);
	}
	return (kill_reap(pid) == 0 ? 0 : 20);
}

static int
listen_kill(void)
{
	struct shared *s;
	long pid;

	s = shared_page();
	if (s == 0 || seize_group_stop(s, &pid) != 0 ||
	    trace(PTRACE_LISTEN, pid, 0, 0) != 0)
		return (1);
	return (kill_reap(pid) == 0 ? 0 : 2);
}

static const struct subtest tests[] = {
	{ "target_errors", target_errors },
	{ "listen_interrupt", listen_interrupt },
	{ "listen_sigcont", listen_sigcont },
	{ "repeated_interrupt", repeated_interrupt },
	{ "listen_kill", listen_kill },
};

static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	return (run_subtests(argc, argv, tests,
	    (int)(sizeof(tests) / sizeof(tests[0]))));
}
