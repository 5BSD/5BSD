/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test: no Linux libc or sysroot required.
 * Exit status identifies the failed check.
 */
struct iovec { void *base; unsigned long len; };

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

static int
test(void)
{
	char path[] = "vectored2.data";
	char a[] = "ab", b[] = "cd", buf[4] = {0};
	struct iovec out[2] = {{a, 2}, {b, 2}}, in = {buf, 4};
	long fd, pipefd[1];
	int pipes[2];

	fd = call(2, (long)path, 2 | 64 | 128, 0600, 0, 0, 0);
	if (fd < 0) return (1);
	/* Unlink immediately; all remaining checks use the open description. */
	if (call(87, (long)path, 0, 0, 0, 0, 0) != 0) return (2);
	if (call(328, fd, (long)out, 2, 8, 0, 0) != 4) return (3);
	if (call(8, fd, 0, 1, 0, 0, 0) != 0) return (4);
	if (call(327, fd, (long)&in, 1, 8, 0, 0) != 4) return (5);
	if (buf[0] != 'a' || buf[1] != 'b' ||
	    buf[2] != 'c' || buf[3] != 'd') return (6);
	if (call(8, fd, 8, 0, 0, 0, 0) != 8) return (7);
	if (call(327, fd, (long)&in, 1, -1, 0, 0) != 4) return (8);
	if (call(8, fd, 0, 1, 0, 0, 0) != 12) return (9);
	if (call(328, fd, (long)out, 2, -1, 0, 0) != 4) return (10);
	if (call(8, fd, 0, 1, 0, 0, 0) != 16) return (11);
	if (call(327, fd, (long)&in, 1, -2, 0, 0) != -22) return (12);
	if (call(328, fd, (long)out, 2, -2, 0, 0) != -22) return (13);
	if (call(327, fd, (long)&in, 1, 0, 0, 0x40000000) != -95)
		return (14);
	if (call(328, fd, (long)out, 2, 0, 0, 0x40000000) != -95)
		return (15);
	if (call(327, fd, (long)&in, 0x100000001L, 0, 0, 0) != -22)
		return (16);
	if (call(327, -1, (long)&in, 1, 0, 0, 0) != -9) return (17);
	if (call(328, fd, (long)out, 0, 0, 0, 0) != 0) return (18);
	/* amd64 uses all 64 bits of pos_l; pos_h is ignored. */
	if (call(328, fd, (long)out, 2, 0x100000008L, 0, 0) != 4)
		return (19);
	if (call(327, fd, (long)&in, 1, 0x100000008L, 123, 0) != 4)
		return (20);
	(void)call(3, fd, 0, 0, 0, 0, 0);
	/* Offset -1 must also work on nonseekable descriptors. */
	if (call(22, (long)pipes, 0, 0, 0, 0, 0) != 0) return (21);
	pipefd[0] = pipes[1];
	if (call(328, pipefd[0], (long)out, 2, -1, 0, 0) != 4)
		return (22);
	if (call(327, pipes[0], (long)&in, 1, -1, 0, 0) != 4)
		return (23);
	if (call(327, pipes[0], (long)&in, 1, 0, 0, 0) != -29)
		return (24);
	return (0);
}

void
_start(void)
{
	(void)call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
