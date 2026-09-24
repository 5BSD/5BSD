/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 io_pgetevents temporary signal-mask regression. */
typedef unsigned long u64;
struct io_event {
	u64 data, obj;
	long res, res2;
};
struct timespec {
	long sec, nsec;
};
struct aio_sigset {
	const void *mask;
	u64 size;
};
struct sigaction {
	void (*handler)(int);
	u64 flags;
	void (*restorer)(void);
	u64 mask;
};
static long
call(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d, r8 __asm__("r8") = e,
			  r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall"
	    : "=a"(ret)
	    : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
	    : "rcx", "r11", "memory");
	return ret;
}
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n hlt\n");
void restorer(void);
static volatile int hits;
static void
handler(int signo)
{
	if (signo == 10)
		hits++;
}
static int
test(void)
{
	u64 ctx = 0, blocked = 1UL << 9, empty = 0, old = 0, current = 0;
	struct io_event ev;
	struct timespec one = { 1, 0 }, zero = { 0, 0 };
	struct aio_sigset sig = { &empty, 8 };
	struct sigaction sa = { handler, 0x04000000 | 0x10000000, restorer, 0 },
			 oldsa;
	long rc;
	if (call(206, 4, (long)&ctx, 0, 0, 0, 0) != 0)
		return 1;
	if (call(13, 10, (long)&sa, (long)&oldsa, 8, 0, 0) != 0)
		return 2;
	if (call(14, 0, (long)&blocked, (long)&old, 8, 0, 0) != 0)
		return 3;
	if (call(62, call(39, 0, 0, 0, 0, 0, 0), 10, 0, 0, 0, 0) != 0)
		return 4;
	if (call(333, ctx, 1, 1, (long)&ev, (long)&zero, 0) != 0)
		return 12;
	if (hits != 0)
		return 13;
	rc = call(333, ctx, 1, 1, (long)&ev, (long)&one, (long)&sig);
	if (rc != -4 || hits != 1)
		return 5;
	if (call(14, 0, 0, (long)&current, 8, 0, 0) != 0 ||
	    !(current & blocked))
		return 6;
	rc = call(333, ctx, 1, 1, (long)&ev, (long)&zero, (long)&sig);
	if (rc != 0)
		return 7;
	if (call(14, 0, 0, (long)&current, 8, 0, 0) != 0 ||
	    !(current & blocked))
		return 8;
	if (call(333, ctx, 0, 1, (long)&ev, 1, (long)&sig) != -14)
		return 14;
	if (call(14, 0, 0, (long)&current, 8, 0, 0) != 0 ||
	    !(current & blocked))
		return 15;
	if (call(14, 2, (long)&old, 0, 8, 0, 0) != 0)
		return 9;
	if (call(13, 10, (long)&oldsa, 0, 8, 0, 0) != 0)
		return 10;
	if (call(207, ctx, 0, 0, 0, 0, 0) != 0)
		return 11;
	return 0;
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
