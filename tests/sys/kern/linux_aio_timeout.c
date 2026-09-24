/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 legacy-AIO timeout conversion and interruption regression. */
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
	return (ret);
}
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n hlt\n");
void restorer(void);
static volatile int hits;
static void
handler(int signo)
{
	if (signo == 14)
		hits++;
}
static int
test(void)
{
	u64 ctx = 0, empty = 0;
	struct io_event ev;
	struct timespec high = { 0, 1000000000 }, negsec = { -1, 0 },
			negnsec = { 0, -1 }, zero = { 0, 0 };
	struct aio_sigset sig = { &empty, 8 };
	struct sigaction sa = { handler, 0x04000000, restorer, 0 };

	if (call(206, 4, (long)&ctx, 0, 0, 0, 0) != 0)
		return (1);
	if (call(13, 14, (long)&sa, 0, 8, 0, 0) != 0)
		return (2);
	if (call(208, ctx, 0, 1, (long)&ev, (long)&high, 0) != 0 ||
	    call(333, ctx, 0, 1, (long)&ev, (long)&high, (long)&sig) != 0)
		return (3);
	if (call(208, ctx, 1, 1, (long)&ev, (long)&high, 0) != 0 ||
	    call(333, ctx, 1, 1, (long)&ev, (long)&high, (long)&sig) != 0)
		return (4);
	if (call(208, ctx, 0, 1, (long)&ev, (long)&negsec, 0) != 0 ||
	    call(333, ctx, 0, 1, (long)&ev, (long)&negsec, (long)&sig) != 0 ||
	    call(208, ctx, 0, 1, (long)&ev, (long)&negnsec, 0) != 0 ||
	    call(333, ctx, 0, 1, (long)&ev, (long)&negnsec, (long)&sig) != 0)
		return (5);
	if (call(208, ctx, 0, 1, (long)&ev, 1, 0) != -14 ||
	    call(333, ctx, 0, 1, (long)&ev, 1, (long)&sig) != -14)
		return (6);
	if (call(208, ctx, 2, 1, (long)&ev, (long)&zero, 0) != -22 ||
	    call(333, ctx, 2, 1, (long)&ev, (long)&zero, (long)&sig) != -22)
		return (7);
	call(37, 1, 0, 0, 0, 0, 0);
	if (call(208, ctx, 1, 1, (long)&ev, (long)&negsec, 0) != -4 ||
	    hits != 1)
		return (8);
	call(37, 1, 0, 0, 0, 0, 0);
	if (call(333, ctx, 1, 1, (long)&ev, (long)&negsec, (long)&sig) != -4 ||
	    hits != 2)
		return (9);
	call(37, 1, 0, 0, 0, 0, 0);
	if (call(208, ctx, 1, 1, (long)&ev, (long)&negnsec, 0) != -4 ||
	    hits != 3)
		return (10);
	call(37, 1, 0, 0, 0, 0, 0);
	if (call(333, ctx, 1, 1, (long)&ev, (long)&negnsec, (long)&sig) != -4 ||
	    hits != 4)
		return (11);
	call(37, 0, 0, 0, 0, 0, 0);
	if (call(207, ctx, 0, 0, 0, 0, 0) != 0)
		return (12);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
