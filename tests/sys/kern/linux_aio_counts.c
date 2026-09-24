/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 legacy-AIO completion-count boundary regression. */
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef signed short s16;
struct io_event { u64 data, obj; long res, res2; };
struct timespec { long sec, nsec; };
struct iocb {
	u64 data;
	u32 key, rw_flags;
	u16 opcode;
	s16 reqprio;
	u32 fd;
	u64 buf, nbytes;
	long offset;
	u64 reserved2;
	u32 flags, resfd;
};
static long
call(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d, r8 __asm__("r8") = e,
	    r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b),
	    "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return (ret);
}
static long
get(u64 ctx, long min, long nr, struct io_event *ev,
    struct timespec *ts, int with_mask)
{
	return (call(with_mask ? 333 : 208, ctx, min, nr, (long)ev,
	    (long)ts, 0));
}
static int
test(void)
{
	static const long counts[] = { 0, 1, 65535, 65536, 65537,
	    2147483647L, 2147483648L, 0x7fffffffffffffffL };
	struct timespec zero = { 0, 0 }, second = { 1, 0 };
	struct io_event ev;
	struct iocb cb = { 0 }, *jobs[2] = { &cb, (void *)1 };
	u64 ctx = 0, probe;
	int pipefd[2], abi;
	unsigned i;
	char byte = 'x';

	probe = 0;
	if (call(206, 65537, (long)&probe, 0, 0, 0, 0) != -11 || probe != 0 ||
	    call(206, 4194304, (long)&probe, 0, 0, 0, 0) != -11 ||
	    call(206, 4194305, (long)&probe, 0, 0, 0, 0) != -22 ||
	    call(206, 0x80000000U, (long)&probe, 0, 0, 0, 0) != -11 ||
	    call(206, 0x80000001U, (long)&probe, 0, 0, 0, 0) != -11 ||
	    call(206, 0xffffffffU, (long)&probe, 0, 0, 0, 0) != -22)
		return (18);
	probe = 1;
	if (call(206, 65537, (long)&probe, 0, 0, 0, 0) != -22 || probe != 1 ||
	    call(206, 65537, 1, 0, 0, 0, 0) != -14 ||
	    call(206, 0, 1, 0, 0, 0, 0) != -14)
		return (19);
	if (call(206, 4, (long)&ctx, 0, 0, 0, 0) != 0)
		return (1);
	for (abi = 0; abi < 2; abi++) {
		if (get(ctx, 0, -1, &ev, &zero, abi) != -22 ||
		    get(ctx, -1, 0, &ev, &zero, abi) != -22 ||
		    get(ctx, 1, 0, &ev, &zero, abi) != -22 ||
		    get(ctx, 2, 1, &ev, &zero, abi) != -22)
			return (2 + abi);
		for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
			if (get(ctx, 0, counts[i], &ev, &zero, abi) != 0)
				return (4 + abi);
			if (counts[i] != 0 &&
			    get(ctx, 1, counts[i], &ev, &zero, abi) != 0)
				return (6 + abi);
		}
		if (get(ctx, counts[7], counts[7], &ev, &zero,
		    abi) != 0)
			return (8 + abi);
	}
	if (call(209, ctx, -1, 1, 0, 0, 0) != -22 ||
	    call(209, ctx, 0, 1, 0, 0, 0) != 0 ||
	    call(209, ctx, 65537, 1, 0, 0, 0) != -14 ||
	    call(209, ctx, counts[7], 1, 0, 0, 0) != -14)
		return (17);
	if (call(293, (long)pipefd, 0, 0, 0, 0, 0) != 0)
		return (10);
	cb.data = 0xabc;
	cb.opcode = 5;
	cb.fd = pipefd[0];
	cb.buf = 1; /* POLLIN */
	if (call(1, pipefd[1], (long)&byte, 1, 0, 0, 0) != 1)
		return (11);
	for (abi = 0; abi < 2; abi++) {
		if (call(209, ctx, abi == 0 ? 65537 : counts[7],
		    (long)jobs, 0, 0, 0) != 1)
			return (12 + abi);
		if (get(ctx, 1, counts[7], &ev, &second, abi) != 1 ||
		    ev.data != cb.data || ev.obj != (u64)&cb ||
		    (ev.res & 1) == 0 || ev.res2 != 0)
			return (14 + abi);
	}
	if (call(207, ctx, 0, 0, 0, 0, 0) != 0)
		return (16);
	call(3, pipefd[0], 0, 0, 0, 0, 0);
	call(3, pipefd[1], 0, 0, 0, 0, 0);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
