/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 ioperm reference and VM gate. */
static long
call(long n, long a, long b, long c)
{
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c) : "rcx", "r11", "memory");
	return (ret);
}
static long
ioperm(unsigned long from, unsigned long num, int enable)
{
	return (call(173, from, num, enable));
}
static int
test(void)
{
	if (ioperm(0x80, 1, 0) != 0)
		return (1);
	if (ioperm(0x80, 1, 1) != 0 || ioperm(0x80, 1, 0) != 0)
		return (2);
	if (ioperm(65535, 1, 1) != 0 || ioperm(65535, 1, 0) != 0)
		return (3);
	if (ioperm(65536, 1, 0) != -22 ||
	    ioperm(65535, 2, 0) != -22 ||
	    ioperm(0, 0, 0) != -22 ||
	    ioperm(~0UL, 2, 0) != -22)
		return (4);
	if (call(117, 1000, 1000, 1000) != 0)
		return (5);
	if (ioperm(0x80, 1, 1) != -1 || ioperm(0x80, 1, 0) != 0)
		return (6);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0);
	__builtin_unreachable();
}
