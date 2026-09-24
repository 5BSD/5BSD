/* SPDX-License-Identifier: BSD-2-Clause */
/* Pending-signal and tracing relationship probes: disposable amd64 VMs only. */
#include "linux_test.h"
#define PTR 101
struct peek_args {
	u64 off;
	u32 flags;
	int nr;
};
static char *self;
static char **env;
static void
num(long n)
{
	char b[32];
	int i = 0;
	if (n < 0) {
		wr1("-");
		n = -n;
	}
	do {
		b[i++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (i)
		sys3(SYS_write, 1, &b[--i], 1);
}
#define C(x, n)                               \
	do {                                  \
		if (!(x)) {                   \
			wr1("PENDING_FAIL "); \
			num(n);               \
			wr1("\n");            \
			return n;             \
		}                             \
	} while (0)
static long
tr(long r, long p, long d)
{
	return sys4(PTR, r, p, 0, d);
}
static long
peek(long p, struct peek_args *a, void *out)
{
	return sys4(PTR, 0x4209, p, a, out);
}
static int
pending(int kind)
{
	int st, info[32] = { 0 }, out[4][32];
	int n = kind == 4 ? 2 : 3;
	long pid = fork_process();
	C(pid >= 0, 1);
	if (!pid) {
		u64 mask = (1UL << 34) | (1UL << 35) | (1UL << 9) | (1UL << 11);
		if (sys4(SYS_rt_sigprocmask, 0, &mask, 0, 8) || tr(0, 0, 0))
			sys1(SYS_exit, 90);
		sys2(SYS_kill, sys0(SYS_getpid), 19);
		sys1(SYS_exit, 7);
	}
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x137f, 2);
	struct peek_args a = { 0, kind == 1 ? 0 : 1, 4 };
	for (int i = 0; i < n; i++) {
		xmemset(info, 0, sizeof(info));
		info[0] = kind == 4 ? 10 + 2 * i : 35 + i % 2;
		info[2] = -1;
		info[4] = sys0(SYS_getpid);
		info[5] = sys0(SYS_getuid);
		info[6] = 101 + i;
		C((kind == 1 ? sys4(297, pid, pid, info[0], info) :
			       sys3(129, pid, info[0], info)) == 0,
		    3);
	}
	C(peek(pid, &a, out) == n, 4);
	for (int i = 0; i < n; i++)
		C(out[i][0] == (kind == 4 ? 10 + 2 * i : 35 + i % 2) &&
			out[i][2] == -1 && out[i][4] == sys0(SYS_getpid) &&
			out[i][5] == sys0(SYS_getuid) && out[i][6] == 101 + i,
		    5);
	C(peek(pid, &a, out) == n, 6); /* Peeking must not consume the queue. */
	a.off = 1;
	a.nr = 1;
	C(peek(pid, &a, out) == 1 && out[0][6] == 102, 7);
	a.off = 3;
	C(peek(pid, &a, out) == 0, 8);
	a.off = ~0UL;
	C(peek(pid, &a, out) == 0, 9);
	a.off = 0;
	a.flags ^= 1;
	C(peek(pid, &a, out) == 0, 10);
	a.flags ^= 1;
	if (kind == 2) {
		a.flags = 2;
		C(peek(pid, &a, out) == -EINVAL, 11);
		a.flags = 1;
		a.nr = -1;
		C(peek(pid, &a, out) == -EINVAL, 12);
		a.nr = 0;
		C(peek(pid, &a, 0) == 0, 13);
		C(peek(pid, 0, out) == -EFAULT, 14);
		a.nr = 1;
		C(peek(pid, &a, 0) == -EFAULT, 15);
		C(peek(999999, 0, 0) == -ESRCH, 16);
	}
	if (kind == 3) {
		long mem = sys6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
		C(mem > 0, 17);
		C(sys3(SYS_mprotect, mem + 4096, 4096, 0) == 0, 18);
		a.nr = 3;
		C(peek(pid, &a, (void *)(mem + 4096 - 128)) == 1, 19);
		C(peek(pid, &a, (void *)(mem + 4096 - 64)) == -EFAULT, 20);
		C(sys3(SYS_mprotect, mem, 4096, 1) == 0, 21);
		C(peek(pid, &a, (void *)mem) == -EFAULT, 22);
		sys2(SYS_munmap, mem, 8192);
		C(peek(pid, &a, out) == 3, 23);
	}
	C(tr(7, pid, 9) == 0, 24);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 9, 25);
	C(peek(pid, &a, out) == -ESRCH, 26);
	return 0;
}
static int
reattach(void)
{
	int ready[2], go[2], st;
	char byte = 1;
	C(sys2(SYS_pipe2, ready, 0) == 0 && sys2(SYS_pipe2, go, 0) == 0, 30);
	long pid = fork_process();
	C(pid >= 0, 31);
	if (!pid) {
		if (tr(0, 0, 0))
			sys1(SYS_exit, 90);
		sys2(SYS_kill, sys0(SYS_getpid), 19);
		sys2(SYS_dup2, ready[1], 10);
		sys2(SYS_dup2, go[0], 11);
		char *av[] = { self, "--ready", 0 };
		sys3(SYS_execve, self, av, env);
		sys1(SYS_exit, 91);
	}
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x137f, 32);
	C(tr(0x4200, pid, 1 | 16 | 64) == 0, 33);
	C(tr(7, pid, 0) == 0, 46);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x4057f, 47);
	u64 message = 0;
	C(tr(0x4201, pid, (long)&message) == 0 && message == (u64)pid, 48);
	C(tr(17, pid, 65) == -EIO, 34); /* Failed detach must retain options. */
	C(tr(17, pid, 0) == 0, 35);
	C(sys3(SYS_read, ready[0], &byte, 1) == 1, 36);
	C(tr(16, pid, 0) == 0, 37);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x137f, 38);
	message = 0;
	C(tr(0x4201, pid, (long)&message) == 0 && message == 0, 49);
	C(tr(24, pid, 0) == 0, 39);
	C(sys3(SYS_write, go[1], &byte, 1) == 1, 40);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x57f, 41);
	C(tr(7, pid, 0) == 0, 42);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 0x57f,
	    43); /* Legacy exec stop. */
	C(tr(7, pid, 0) == 0, 44);
	C(sys4(SYS_wait4, pid, &st, 0, 0) == pid && st == 7 << 8, 45);
	for (int i = 0; i < 2; i++) {
		sys1(SYS_close, ready[i]);
		sys1(SYS_close, go[i]);
	}
	return 0;
}
static int
test(int argc, char **argv, char **envp)
{
	self = argv[0];
	env = envp;
	if (argc > 1 && xstreq(argv[1], "--exec-child"))
		return 7;
	if (argc > 1 && xstreq(argv[1], "--ready")) {
		char byte = 1;
		sys3(SYS_write, 10, &byte, 1);
		sys3(SYS_read, 11, &byte, 1);
		char *av[] = { self, "--exec-child", 0 };
		sys3(SYS_execve, self, av, env);
		return 91;
	}
	if (argc < 2)
		return 100;
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		C(sys1(106, 65534) == 0 && sys1(105, 65534) == 0, 101);
		char *av[] = { self, argv[1], 0 };
		sys3(SYS_execve, self, av, env);
		return 102;
	}
	if (xstreq(argv[1], "shared"))
		return pending(0);
	if (xstreq(argv[1], "standard"))
		return pending(4);
	if (xstreq(argv[1], "thread"))
		return pending(1);
	if (xstreq(argv[1], "validation"))
		return pending(2);
	if (xstreq(argv[1], "faults"))
		return pending(3);
	if (xstreq(argv[1], "reattach")) {
		for (int i = 0; i < 8; i++) {
			int r = reattach();
			if (r)
				return r;
		}
		return 0;
	}
	if (xstreq(argv[1], "lifetime")) {
		for (int i = 0; i < 32; i++) {
			int r = pending(i % 2);
			if (r)
				return r;
		}
		return 0;
	}
	return 103;
}
