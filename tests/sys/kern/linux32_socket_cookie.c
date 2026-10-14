/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding i386 Linux SO_COOKIE ABI check. */
typedef unsigned long long u64;
static long
call(long nr, long a, long b, long c)
{
	long result;

	__asm__ volatile("int $0x80" : "=a"(result) : "a"(nr), "b"(a),
	    "c"(b), "d"(c) : "memory");
	return (result);
}

static long
socketcall(long op, void *args)
{
	return (call(102, op, (long)args, 0));
}

static int __attribute__((used))
check(void)
{
	long sockargs[] = { 2, 2, 0 };
	long fd, copy;
	u64 cookie = 0, repeated = 0;
	int len;
	struct { long fd, level, option, value, length; } getargs;

	fd = socketcall(1, sockargs);
	if (fd < 0)
		return (1);
	getargs.fd = fd;
	getargs.level = 1;
	getargs.option = 57;
	getargs.value = (long)&cookie;
	getargs.length = (long)&len;
	len = 8;
	if (socketcall(15, &getargs) != 0 || len != 8 || cookie == 0)
		return (2);
	copy = call(41, fd, 0, 0);
	if (copy < 0)
		return (3);
	getargs.fd = copy;
	getargs.value = (long)&repeated;
	len = 8;
	if (socketcall(15, &getargs) != 0 || len != 8 || repeated != cookie)
		return (4);
	len = 4;
	if (socketcall(15, &getargs) != -22)
		return (5);
	(void)call(6, copy, 0, 0);
	(void)call(6, fd, 0, 0);
	return (0);
}

__asm__(".text\n.globl _start\n_start:\ncall check\nmov %eax,%ebx\nmov $1,%eax\nint $0x80\n");
