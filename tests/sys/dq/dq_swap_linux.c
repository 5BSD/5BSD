/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * dq_swap_test's Linux program: a freestanding amd64 Linux program, built
 * by the test with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It opens "orig" read-only, reads it and exits with a bit for each step
 * that did not go as it does for the file the supervisor swaps in, whose
 * content is "SUBSTITUTE".
 */

#define	LINUX_SYS_read		0
#define	LINUX_SYS_open		2
#define	LINUX_SYS_close		3
#define	LINUX_SYS_exit_group	231

void	_start(void);

static long
linux_syscall(long n, long a, long b, long c)
{
	long ret;

	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b),
	    "d"(c) : "rcx", "r11", "memory");
	return (ret);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	static const char want[] = "SUBSTITUTE";
	char buf[32];
	long fd, n;
	int bad, i;

	bad = 0;
	fd = linux_syscall(LINUX_SYS_open, (long)"orig", 0 /* O_RDONLY */, 0);
	if (fd < 0)
		bad |= 1;
	else {
		n = linux_syscall(LINUX_SYS_read, fd, (long)buf, sizeof(buf));
		if (n != (long)sizeof(want) - 1)
			bad |= 2;
		else {
			for (i = 0; i < (int)sizeof(want) - 1; i++) {
				if (buf[i] != want[i])
					bad |= 4;
			}
		}
		if (linux_syscall(LINUX_SYS_close, fd, 0, 0) != 0)
			bad |= 8;
	}
	(void)linux_syscall(LINUX_SYS_exit_group, bad, 0, 0);
	for (;;)
		;
}
