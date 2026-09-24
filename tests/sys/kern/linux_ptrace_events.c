/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 ptrace event oracle. Disposable guests only. */
#include "linux_test.h"
#define PTRACE 101
static char *self;
static char **environment;
static long
trace(long request, long pid, long data)
{
	return sys4(PTRACE, request, pid, 0, data);
}
static void
number(long n)
{
	char s[32]; int i = 0;
	if (n < 0) { wr1("-"); n = -n; }
	do { s[i++] = '0' + n % 10; n /= 10; } while (n);
	while (i) sys3(SYS_write, 1, &s[--i], 1);
}
#define CHECK(x, n) do { if (!(x)) { wr1("EVENT_FAIL "); number(n); wr1("\n"); return n; } } while (0)
/* Do not return through a C frame in the shared-stack vfork child. */
static long
vfork_child(void)
{
	long r;
	__asm__ volatile("mov $58,%%eax; syscall; test %%rax,%%rax; jnz 1f; "
	    "mov $60,%%eax; mov $23,%%edi; syscall; ud2; 1:"
	    : "=a"(r) : : "rcx", "r11", "rdi", "memory");
	return r;
}
static int
run(int kind, int options, int expected)
{
	int st, seen[7] = {0}, alive = 1, childst;
	long pid = fork_process(), grand = 0, got;
	CHECK(pid >= 0, 1);
	if (!pid) {
		if (trace(0, 0, 0)) sys1(SYS_exit, 90);
		sys2(SYS_kill, sys0(SYS_getpid), 19);
		if (kind == 0) {
			char *av[] = {self, "--exec-child", 0};
			sys3(SYS_execve, self, av, environment);
			sys1(SYS_exit, 91);
		}
		if (kind == 1) got = fork_process();
		else if (kind == 2) got = vfork_child();
		else if (kind == 3) got = sys5(SYS_clone, 0, 0, 0, 0, 0);
		else got = -1;
		if (kind >= 1 && kind <= 3) {
			if (got < 0) sys1(SYS_exit, 92);
			if (!got) sys1(SYS_exit, 23);
			if (sys4(SYS_wait4, got, &childst, 0x40000000, 0) != got || childst != 23 << 8)
				sys1(SYS_exit, 93);
		}
		if (kind == 5) sys2(SYS_kill, sys0(SYS_getpid), 15);
		sys1(SYS_exit, 7);
	}
	CHECK(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x137f, 2);
	u64 message = ~0UL;
	CHECK(trace(0x4201, pid, (long)&message) == 0 && message == 0, 3);
	CHECK(trace(0x4200, pid, options) == 0, 4);
	CHECK(trace(0x4200, pid, 1UL << 32) == -EINVAL, 5);
	CHECK(trace(7, pid, 0) == 0, 6);
	for (int i = 0; alive && i < 100; i++) {
		got = sys4(SYS_wait4, -1, &st, 0x40000000, 0);
		CHECK(got > 0, 10);
		if ((st & 255) != 127) {
			if (got == pid) CHECK(st == (kind == 5 ? 15 : 7 << 8), 11);
			else CHECK(st == 23 << 8, 12);
			alive--;
			continue;
		}
		int event = (u32)st >> 16;
		if (event) {
			wr1("EVENT "); number(event); wr1("\n");
			CHECK(event <= 6, 13);
			seen[event]++;
			message = ~0UL;
			CHECK(trace(0x4201, got, (long)&message) == 0, 14);
			CHECK(trace(0x4201, got, 1) == -EFAULT, 15);
			int info[32];
			CHECK(trace(0x4202, got, (long)info) == 0 && info[0] == 5 &&
			    info[2] == ((event << 8) | 5) && info[4] == got, 27);
			if (event >= 1 && event <= 3) {
				CHECK(event == expected && got == pid && message > 0, 16);
				grand = message; alive++;
			} else if (event == 4) CHECK(message == (u64)pid, 17);
			else if (event == 5) CHECK(message > 0 && (!grand || message == (u64)grand), 18);
			else if (event == 6) {
				CHECK(message == (u64)(got == pid ? (kind == 5 ? 15 : 7 << 8) : 23 << 8), 19);
				u64 regs[27];
				CHECK(trace(12, got, (long)regs) == 0, 20);
			}
		}
		int signal = (st >> 8) & 255;
		CHECK(trace(7, got, !event && signal == 15 ? 15 : 0) == 0, 21);
	}
	CHECK(alive == 0, 22);
	CHECK(seen[expected] == (expected ? 1 : 0), 23);
	if (kind == 2 && (options & 32)) CHECK(seen[5] == 1, 24);
	if (options & 64) CHECK(seen[6] == (expected >= 1 && expected <= 3 ? 2 : 1), 25);
	CHECK(trace(0x4201, pid, 0) == -ESRCH, 26);
	return 0;
}
static int exec_event(void) { return run(0, 16, 4); }
static int fork_event(void) { return run(1, 2 | 64, 1); }
static int vfork_event(void) { return run(2, 4 | 32 | 64, 2); }
static int clone_event(void) { return run(3, 8 | 64, 3); }
static int exit_event(void) { return run(4, 64, 0); }
static int signal_exit(void) { return run(5, 64, 0); }
static int vfork_done(void) { return run(2, 32, 0); }
static int
selective(void)
{
	for (int kind = 1; kind <= 3; kind++) {
		for (int option = 1; option <= 3; option++) {
			int error = run(kind, 1 << option,
			    kind == option ? kind : 0);
			if (error != 0)
				return error;
		}
	}
	return 0;
}
static int
isolation(void)
{
	long p[2]; int st;
	for (int i = 0; i < 2; i++) {
		p[i] = fork_process();
		CHECK(p[i] >= 0, 30);
		if (!p[i]) {
			if (trace(0, 0, 0)) sys1(SYS_exit, 90);
			sys2(SYS_kill, sys0(SYS_getpid), 19);
			sys0(SYS_getpid);
			sys1(SYS_exit, 0);
		}
		CHECK(sys4(SYS_wait4, p[i], &st, 0, 0) == p[i] && st == 0x137f, 31);
		CHECK(trace(0x4200, p[i], i == 0 ? 1 : 0) == 0, 32);
	}
	for (int i = 0; i < 2; i++) {
		CHECK(trace(24, p[i], 0) == 0, 33);
		CHECK(sys4(SYS_wait4, p[i], &st, 0, 0) == p[i] &&
		    st == (i == 0 ? 0x857f : 0x57f), 34);
		CHECK(trace(0x4200, p[i], 0) == 0, 35);
		CHECK(trace(24, p[i], 0) == 0, 36);
		CHECK(sys4(SYS_wait4, p[i], &st, 0, 0) == p[i] && st == 0x57f, 37);
		CHECK(trace(7, p[i], 0) == 0, 38);
		CHECK(sys4(SYS_wait4, p[i], &st, 0, 0) == p[i] && st == 0, 39);
	}
	return 0;
}
static int
waitid_event(void)
{
	int st, info[32];
	long pid = fork_process();
	CHECK(pid >= 0, 40);
	if (!pid) {
		if (trace(0, 0, 0)) sys1(SYS_exit, 90);
		sys2(SYS_kill, sys0(SYS_getpid), 19);
		char *av[] = {self, "--exec-child", 0};
		sys3(SYS_execve, self, av, environment);
		sys1(SYS_exit, 91);
	}
	CHECK(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x137f, 41);
	CHECK(trace(0x4200, pid, 16) == 0 && trace(7, pid, 0) == 0, 42);
	xmemset(info, 0, sizeof(info));
	long rc = sys5(SYS_waitid, 1, pid, info, 2, 0);
	wr1("WAITID "); number(rc); wr1(" "); number(info[4]); wr1(" "); number(info[2]); wr1(" "); number(info[6]); wr1("\n");
	CHECK(rc == 0 && info[4] == pid &&
	    info[2] == 4 && info[6] == 0x405, 43);
	u64 message = 0;
	CHECK(trace(0x4201, pid, (long)&message) == 0 && message == (u64)pid, 44);
	CHECK(trace(7, pid, 0) == 0, 45);
	CHECK(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 7 << 8, 46);
	return 0;
}
static int
test(int argc, char **argv, char **envp)
{
	self = argv[0]; environment = envp;
	if (argc == 2 && xstreq(argv[1], "--exec-child")) return 7;
	if (argc == 2 && xstreq(argv[1], "--workload")) {
		long pid = fork_process(); int st;
		if (pid < 0) return 90;
		if (!pid) sys1(SYS_exit, 23);
		if (sys4(SYS_wait4, pid, &st, 0, 0) != pid || st != 23 << 8) return 91;
		char *av[] = {self, "--exec-child", 0};
		sys3(SYS_execve, self, av, environment);
		return 92;
	}
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001)) return 90;
		char *av[] = { self, argv[1], 0 };
		sys3(SYS_execve, self, av, envp);
		return 91;
	}
	static const struct subtest cases[] = {
		{"exec", exec_event}, {"fork", fork_event}, {"vfork", vfork_event},
		{"clone", clone_event}, {"exit", exit_event}, {"signal", signal_exit},
		{"vfork_done", vfork_done}, {"selective", selective}, {"isolation", isolation}, {"waitid", waitid_event}
	};
	return run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0]));
}
