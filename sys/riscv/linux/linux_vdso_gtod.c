/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/elf.h>
#include <sys/errno.h>
#include <sys/stdarg.h>
#include <sys/stddef.h>
#include <sys/time.h>
#define _KERNEL
#include <sys/vdso.h>
#undef _KERNEL

#include <limits.h>
#include <stdbool.h>

#include <machine/atomic.h>
#include <machine/vdso.h>

#include <riscv/linux/linux.h>
#include <riscv/linux/linux_syscall.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_time.h>

uintptr_t *kern_timekeep_base = NULL;
uint32_t kern_tsc_selector = 0;

static long
linux_vdso_syscall(long nr, long arg0, long arg1, long arg2)
{
	register long a0 asm("a0") = arg0;
	register long a1 asm("a1") = arg1;
	register long a2 asm("a2") = arg2;
	register long a7 asm("a7") = nr;

	asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
	return (a0);
}

static int
write(int fd, const void *buf, size_t size)
{
	return (linux_vdso_syscall(LINUX_SYS_linux_write, fd,
	    (long)buf, size));
}

static int
__vdso_clock_gettime_fallback(clockid_t clock_id, struct l_timespec *ts)
{
	return (linux_vdso_syscall(LINUX_SYS_linux_clock_gettime,
	    clock_id, (long)ts, 0));
}

static int
__vdso_gettimeofday_fallback(l_timeval *tv, struct timezone *tz)
{
	return (linux_vdso_syscall(LINUX_SYS_gettimeofday,
	    (long)tv, (long)tz, 0));
}

static int
__vdso_clock_getres_fallback(clockid_t clock_id, struct l_timespec *ts)
{
	return (linux_vdso_syscall(LINUX_SYS_linux_clock_getres,
	    clock_id, (long)ts, 0));
}

int
__vdso_gettc(const struct vdso_timehands *th, u_int *tc)
{
	uint64_t counter;

	if (th->th_algo != VDSO_TH_ALGO_RISCV_RDTIME)
		return (ENOSYS);
	asm volatile("rdtime %0" : "=r"(counter));
	*tc = counter;
	return (0);
}

#include <compat/linux/linux_vdso_gtod.inc>
