/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The freestanding amd64 Linux programs of the dq tests (dq_*_linux.c):
 * the system call numbers they use and the one system call shim, built
 * with them by the Makefile (no Linux headers or libc).
 */

#ifndef _DQ_LINUX_H_
#define	_DQ_LINUX_H_

#define	LINUX_SYS_read		0
#define	LINUX_SYS_write		1
#define	LINUX_SYS_open		2
#define	LINUX_SYS_close		3
#define	LINUX_SYS_mmap		9
#define	LINUX_SYS_ioctl		16
#define	LINUX_SYS_pipe		22
#define	LINUX_SYS_clone		56
#define	LINUX_SYS_wait4		61
#define	LINUX_SYS_exit_group	231
#define	LINUX_SYS_newfstatat	262
#define	LINUX_SYS_unshare	272
#define	LINUX_SYS_syncfs	306
#define	LINUX_SYS_pidfd_open	434
#define	LINUX_SYS_openat2	437
#define	LINUX_SYS_pidfd_getfd	438

/* A Linux system call: the result, or a negated Linux errno. */
static inline long
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

#endif /* !_DQ_LINUX_H_ */
