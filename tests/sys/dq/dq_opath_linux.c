/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_served_test's Linux half of the O_PATH rows: a freestanding amd64
 * Linux program, built by the test with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It inherits an O_PATH descriptor as descriptor 9 and exits with a bit
 * for each call that did not answer as Linux does for one: mmap(2) is
 * EBADF, syncfs(2) succeeds.
 */

#define	OPATH_FD		9

#define	LINUX_SYS_mmap		9
#define	LINUX_SYS_exit_group	231
#define	LINUX_SYS_syncfs	306
#define	LINUX_EBADF		9
#define	LINUX_PROT_READ		1
#define	LINUX_MAP_PRIVATE	2

void	_start(void);

static long
linux_syscall(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;

	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b),
	    "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return (ret);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	int bad;

	bad = 0;
	if (linux_syscall(LINUX_SYS_mmap, 0, 4096, LINUX_PROT_READ,
	    LINUX_MAP_PRIVATE, OPATH_FD, 0) != -LINUX_EBADF)
		bad |= 1;
	if (linux_syscall(LINUX_SYS_syncfs, OPATH_FD, 0, 0, 0, 0, 0) != 0)
		bad |= 2;
	(void)linux_syscall(LINUX_SYS_exit_group, bad, 0, 0, 0, 0, 0);
	for (;;)
		;
}
