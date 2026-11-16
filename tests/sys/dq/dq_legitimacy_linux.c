/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * dq_legitimacy_test's Linux half: a freestanding amd64 Linux program,
 * built at buildworld time (Makefile) with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It opens /dev/dq, finds a queue the test opened as descriptor 9, and
 * writes the raw result of each call (a descriptor, 0, or a negated Linux
 * errno) to its standard output as an array of long.
 *
 * The ioctl requests are group 'j' number 7 (DQ_IOC_GET_STATS natively) in
 * three encodings: no direction, the Linux read encoding and the FreeBSD
 * read encoding.  The Linux ioctl entry looks at the low 16 bits only.
 */

#include "dq_linux.h"

#define	NRES			8

#define	LINUX_O_RDWR		2
#define	LINUX_FIONBIO		0x5421

#define	J7_NONE			0x00006a07UL
#define	J7_LINUX_READ		0x80086a07UL
#define	J7_FREEBSD_READ		0x40086a07UL

void	_start(void);

static long
lx_ioctl(long fd, unsigned long request, void *arg)
{

	return (linux_syscall(LINUX_SYS_ioctl, fd, (long)request, (long)arg,
	    0, 0, 0));
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	static char buf[4096];
	long r[NRES];
	long null, q;
	int on;

	on = 1;
	q = linux_syscall(LINUX_SYS_open, (long)"/dev/dq", LINUX_O_RDWR, 0,
	    0, 0, 0);
	r[0] = q;
	r[1] = lx_ioctl(q, J7_NONE, buf);
	r[2] = lx_ioctl(q, J7_LINUX_READ, buf);
	r[3] = lx_ioctl(q, J7_FREEBSD_READ, buf);
	r[4] = lx_ioctl(q, LINUX_FIONBIO, &on);
	r[5] = linux_syscall(LINUX_SYS_read, q, (long)buf, sizeof(buf), 0, 0,
	    0);
	null = linux_syscall(LINUX_SYS_open, (long)"/dev/null", LINUX_O_RDWR,
	    0, 0, 0, 0);
	r[6] = null;
	r[7] = lx_ioctl(null, J7_LINUX_READ, buf);
	(void)linux_syscall(LINUX_SYS_write, 1, (long)r, sizeof(r), 0, 0, 0);
	(void)linux_syscall(LINUX_SYS_exit_group, 0, 0, 0, 0, 0, 0);
	for (;;)
		;
}
