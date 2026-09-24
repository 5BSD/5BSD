/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 iopl privilege transition regression. */
static long
call(long n, long a, long b, long c)
{
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c) : "rcx", "r11", "memory");
	return (ret);
}
static int
test(void)
{
	if (call(172, 4, 0, 0) != -22 || call(172, 0, 0, 0) != 0)
		return (1);
	if (call(172, 3, 0, 0) != 0)
		return (2);
	if (call(117, 1000, 1000, 1000) != 0)
		return (3);
	if (call(172, 3, 0, 0) != 0 || call(172, 2, 0, 0) != 0)
		return (4);
	if (call(172, 3, 0, 0) != -1)
		return (5);
	if (call(172, 0, 0, 0) != 0 || call(172, 1, 0, 0) != -1)
		return (6);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0);
	__builtin_unreachable();
}
