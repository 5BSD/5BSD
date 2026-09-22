/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 USER-area, ARCH_PRCTL and hardware watchpoint oracle. */
#include "linux_test.h"
#define PTRACE 101
static long child;
static volatile u64 watched;
static long
pt(long op, u64 off, u64 data)
{
	return sys4(PTRACE, op, child, off, data);
}
static int
stop(void)
{
	int st;
	return sys4(SYS_wait4, child, &st, 0, 0) != child || st != 0x57f;
}
static int
finish(void)
{
	int st;
	if (pt(7, 0, 0))
		return 1;
	for (int i = 0; i < 8; i++) {
		if (sys4(SYS_wait4, child, &st, 0, 0) != child)
			return 1;
		if (st == 0)
			return 0;
		/* The traced parent's wait for its child also reports SIGCHLD. */
		if (st != 0x117f || pt(7, 0, 0))
			return 1;
	}
	return 1;
}
static int
start(void)
{
	child = fork_process();
	if (child < 0)
		return 1;
	if (!child) {
		u64 val;
		if (sys4(PTRACE, 0, 0, 0, 0))
			sys1(SYS_exit, 90);
		__asm__ volatile("mov $0x1234,%%r12; int3; mov %%r12,%0"
		    : "=r"(val)::"r12", "memory");
		if (val != 0x5678)
			sys1(SYS_exit, 91);
		watched = 42;
		__asm__ volatile("int3" ::: "memory");
		long grandchild = fork_process();
		int status;
		if (grandchild < 0)
			sys1(SYS_exit, 92);
		if (grandchild == 0) {
			watched = 99;
			sys1(SYS_exit, 0);
		}
		if (sys4(SYS_wait4, grandchild, &status, 0, 0) != grandchild ||
		    status)
			sys1(SYS_exit, 93);
		sys1(SYS_exit, 0);
	}
	return stop();
}
static int
test(int argc, char **argv, char **envp)
{
	u64 value, oldfs, oldgs, regs[27], dr[8];
	if (argc > 1 && xstreq(argv[1], "unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001))
			return 90;
		char *args[] = { argv[0], "worker", 0 };
		sys3(SYS_execve, argv[0], args, envp);
		return 91;
	}
	(void)envp;
	if (start())
		return 1;
	if (pt(12, 0, (u64)regs))
		return 2;
	if (regs[17] != 0x33 || regs[20] != 0x2b)
		return 3;
	for (int i = 0; i < 27; i++) {
		value = 0;
		if (pt(3, i * 8, (u64)&value) || value != regs[i])
			return 4;
	}
	if (pt(6, 24, 0x5678) || pt(3, 24, (u64)&value) || value != 0x5678)
		return 5;
	for (u64 off = 216; off < 848; off += 8) {
		value = 1;
		if (pt(3, off, (u64)&value) || value || pt(6, off, 0) != -EIO)
			return 6;
	}
	if (pt(3, 1, (u64)&value) != -EIO)
		return 71;
	if (pt(3, 928, (u64)&value) != -EIO)
		return 72;
	if (pt(6, 928, 0) != -EIO)
		return 73;
	if (pt(3, 0, 1) != -EFAULT)
		return 74;
	for (int i = 0; i < 8; i++)
		if (pt(3, 848 + i * 8, (u64)&dr[i]))
			return 8;
	if (dr[0] || dr[1] || dr[2] || dr[3] || dr[4] || dr[5] ||
	    dr[6] != 0xffff0ff0 || dr[7])
		return 9;
	if (pt(6, 880, 0) != -EIO || pt(6, 888, 0) != -EIO)
		return 10;
	if (pt(6, 896, 0x123456789abcdef0UL) || pt(3, 896, (u64)&value) ||
	    value != 0x123456789abcdef0UL)
		return 11;
	if (pt(6, 896, dr[6]))
		return 12;
	if (pt(6, 848, ~0UL) != -EINVAL)
		return 13;
	if (pt(30, (u64)&oldfs, 0x1003) || pt(30, (u64)&oldgs, 0x1004))
		return 14;
	if (oldfs != regs[21] || oldgs != regs[22])
		return 15;
	if (pt(30, 0x12345000, 0x1002) || pt(30, (u64)&value, 0x1003) ||
	    value != 0x12345000)
		return 16;
	if (pt(30, 0x23456000, 0x1001) || pt(3, 176, (u64)&value) ||
	    value != 0x23456000)
		return 17;
	if (pt(30, ~0UL, 0x1002) != -EPERM || pt(30, 1, 0x1003) != -EFAULT ||
	    pt(30, 0, 0) != -EINVAL)
		return 18;
	if (pt(30, oldfs, 0x1002) || pt(30, oldgs, 0x1001))
		return 19;
	if (pt(6, 848, (u64)&watched) || pt(6, 904, 0x90001))
		return 20;
	if (pt(3, 904, (u64)&value) || value != 0x90001)
		return 21;
	if (pt(6, 904, 0x20001) != -EINVAL || pt(3, 904, (u64)&value) ||
	    value != 0x90001)
		return 22;
	if (pt(7, 0, 0) || stop())
		return 23;
	if (pt(3, 896, (u64)&value) || !(value & 1))
		return 24;
	if (pt(6, 904, 0) || pt(7, 0, 0) || stop())
		return 25;
	/* New children must not inherit the active hardware watchpoint. */
	if (pt(6, 904, 0x90001))
		return 27;
	if (finish())
		return 26;
	return 0;
}
