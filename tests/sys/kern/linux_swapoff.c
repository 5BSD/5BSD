/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux amd64 swapoff reference and disposable VM gate. */
static const char linux_device[] = "/dev/vdb";
static const char freebsd_device[] = "/dev/vtbd1";
static const char missing[] = "/no-such-swap-device";
static const char root[] = "/";
static const char empty[] = "";
static const char link[] = "/tmp/linux-swapoff-gate-link";
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
	const char *device;

	device = call(21, (long)linux_device, 0, 0) == 0 ?
	    linux_device : freebsd_device;
	if (call(21, (long)device, 0, 0) != 0)
		return (1);
	if (call(168, (long)missing, 0, 0) != -2)
		return (21);
	if (call(168, (long)root, 0, 0) != -21)
		return (22);
	if (call(168, 1, 0, 0) != -14 ||
	    call(168, 0, 0, 0) != -14)
		return (23);
	if (call(168, (long)empty, 0, 0) != -2)
		return (25);
	if (call(168, (long)device, 0, 0) != -22)
		return (24);
	if (call(167, (long)device, 0, 0) != 0)
		return (3);
	if (call(168, (long)device, 0, 0) != 0 ||
	    call(168, (long)device, 0, 0) != -22)
		return (4);
	/* A device activated by one path can be deactivated by its symlink. */
	call(87, (long)link, 0, 0);
	if (call(88, (long)device, (long)link, 0) != 0)
		return (7);
	if (call(167, (long)device, 0, 0) != 0)
		return (8);
	if (call(168, (long)link, 0, 0) != 0 ||
	    call(168, (long)device, 0, 0) != -22)
		return (9);
	if (call(87, (long)link, 0, 0) != 0 ||
	    call(168, (long)link, 0, 0) != -2)
		return (10);
	if (call(117, 1000, 1000, 1000) != 0)
		return (5);
	if (call(168, (long)device, 0, 0) != -1 ||
	    call(168, (long)missing, 0, 0) != -1)
		return (6);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(60, test(), 0, 0);
	__builtin_unreachable();
}
