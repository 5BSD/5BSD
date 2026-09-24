/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 swapon discard-policy oracle and VM probe. */
static const char linux_low[] = "/dev/vdb";
static const char linux_high[] = "/dev/vdc";
static const char freebsd_low[] = "/dev/vtbd1";
static const char freebsd_high[] = "/dev/vtbd2";
static char marker[4096], readback[4096];
#define MARKER_OFFSET (1024 * 1024)
#define DISCARD 0x10000
#define ONCE 0x20000
#define PAGES 0x40000
static long
call(long n, long a, long b, long c)
{
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c) : "rcx", "r11", "memory");
	return (ret);
}
static long
call4(long n, long a, long b, long c, long d)
{
	long ret;
	register long r10 __asm__("r10") = d;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
	return (ret);
}
static int
run(const char *device, int flags, int expect_marker)
{
	long fd;
	unsigned i;

	fd = call(2, (long)device, 2, 0);
	if (fd < 0)
		return (1);
	for (i = 0; i < sizeof(marker); i++)
		marker[i] = 0x5a;
	if (call4(18, fd, (long)marker, sizeof(marker), MARKER_OFFSET) !=
	    sizeof(marker))
		return (2);
	if (call(167, (long)device, flags, 0) != 0)
		return (3);
	if (call(168, (long)device, 0, 0) != 0)
		return (4);
	if (call4(17, fd, (long)readback, sizeof(readback), MARKER_OFFSET) !=
	    sizeof(readback))
		return (5);
	for (i = 0; expect_marker && i < sizeof(readback); i++) {
		if (readback[i] != 0x5a)
			return (6);
	}
	if (call(3, fd, 0, 0) != 0)
		return (7);
	return (0);
}
static int
test(void)
{
	const char *low, *high;
	int error;

	low = call(21, (long)linux_low, 0, 0) == 0 ?
	    linux_low : freebsd_low;
	high = low == linux_low ? linux_high : freebsd_high;
	if (call(21, (long)high, 0, 0) != 0)
		return (10);
#ifdef DISCARD_PAGES_ONLY
	return (call(167, (long)high, DISCARD | PAGES, 0) == 0 ? 0 : 11);
#endif
	error = run(high, DISCARD | ONCE, 0);
	if (error != 0)
		return (20 + error);
	error = run(high, DISCARD | PAGES, 0);
	if (error != 0)
		return (30 + error);
	error = run(high, DISCARD | ONCE | PAGES, 0);
	if (error != 0)
		return (40 + error);
	error = run(high, ONCE | PAGES, 0);
	if (error != 0)
		return (50 + error);
	error = run(high, DISCARD, 0);
	if (error != 0)
		return (60 + error);
	error = run(low, DISCARD | ONCE, 0);
	if (error != 0)
		return (70 + error);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0);
	__builtin_unreachable();
}
