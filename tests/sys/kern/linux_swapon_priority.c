/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 swap-priority probe; build with -DSWAP_CLEANUP for phase 2. */
static const char linux_low[] = "/dev/vdb";
static const char linux_high[] = "/dev/vdc";
static const char freebsd_low[] = "/dev/vtbd1";
static const char freebsd_high[] = "/dev/vtbd2";
static const char swaps[] = "/proc/swaps";
static char text[4096];
static long
call(long n, long a, long b, long c)
{
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c) : "rcx", "r11", "memory");
	return (ret);
}
static int
matches(const char *p, const char *q)
{
	while (*q != 0 && *p == *q) {
		p++;
		q++;
	}
	return (*q == 0 && (*p == ' ' || *p == '\t'));
}
static int
priority(const char *device)
{
	char *p, *end, *q;
	long fd, n;
	int value, sign, place;

	fd = call(2, (long)swaps, 0, 0);
	if (fd < 0)
		return (-100000);
	n = call(0, fd, (long)text, sizeof(text) - 1);
	call(3, fd, 0, 0);
	if (n <= 0)
		return (-100000);
	text[n] = 0;
	for (p = text; *p != 0;) {
		end = p;
		while (*end != 0 && *end != '\n')
			end++;
		if (matches(p, device)) {
			q = end;
			while (q > p && (q[-1] == ' ' || q[-1] == '\t'))
				q--;
			value = 0;
			place = 1;
			while (q > p && q[-1] >= '0' && q[-1] <= '9') {
				q--;
				value += (q[0] - '0') * place;
				place *= 10;
			}
			sign = q > p && q[-1] == '-' ? -1 : 1;
			return (sign * value);
		}
		p = *end == 0 ? end : end + 1;
	}
	return (-100000);
}
static int
test(void)
{
	const char *low, *high;

	low = call(21, (long)linux_low, 0, 0) == 0 ?
	    linux_low : freebsd_low;
	high = low == linux_low ? linux_high : freebsd_high;
	if (call(21, (long)high, 0, 0) != 0)
		return (1);
#ifndef SWAP_CLEANUP
	/* Priority bits alone must not enable explicit priority. */
	if (call(167, (long)low, 7, 0) != 0)
		return (2);
	if (call(167, (long)high, 0x8000 | 100, 0) != 0) {
		call(168, (long)low, 0, 0);
		return (3);
	}
	if (priority(low) >= 0 || priority(high) != 100)
		return (4);
	if (call(167, (long)high, 0x8000 | 100, 0) != -16)
		return (5);
#else
	error = call(168, (long)high, 0, 0);
	if (error != 0)
		return (6);
	if (call(168, (long)low, 0, 0) != 0)
		return (7);
	if (call(167, (long)low, 0x8000, 0) != 0)
		return (8);
	if (priority(low) != 0)
		return (9);
	if (call(168, (long)low, 0, 0) != 0)
		return (10);
	/* Discard flags are accepted on a device without discard support. */
	if (call(167, (long)low, 0x10000 | 0x20000 | 0x40000, 0) != 0)
		return (11);
	if (call(168, (long)low, 0, 0) != 0)
		return (12);
#endif
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0);
	__builtin_unreachable();
}
