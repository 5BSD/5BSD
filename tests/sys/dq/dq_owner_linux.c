/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_owner_test's Linux half: a freestanding amd64 Linux program, built at
 * buildworld time (Makefile) with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It reads four words from its standard input (mode, pid, queue descriptor
 * number, ordinary descriptor number) and writes the raw result of each
 * call (a descriptor, 0, or a negated Linux errno) to its standard output
 * as an array of long.
 *
 * Mode 0: pidfd_open(pid), then pidfd_getfd of the two numbers.
 * Mode 1: it opens a queue itself, makes a process that shares its
 * descriptor table (clone with CLONE_FILES), and both call
 * unshare(CLONE_FILES); the sharer also reads the queue.
 */

#include "dq_linux.h"

#define	NRES			10

#define	LINUX_O_RDWR		2
#define	LINUX_FIONBIO		0x5421
#define	LINUX_CLONE_FILES	0x400
#define	LINUX_SIGCHLD		17

void	_start(void);

#define	SC1(n, a)		linux_syscall((n), (long)(a), 0, 0, 0, 0, 0)
#define	SC3(n, a, b, c)							\
	linux_syscall((n), (long)(a), (long)(b), (long)(c), 0, 0, 0)

static void
unshare_rows(long *r)
{
	static char buf[4096];
	long c[2], child, q;
	int on, p1[2], p2[2];
	char b;

	on = 1;
	q = SC3(LINUX_SYS_open, "/dev/dq", LINUX_O_RDWR, 0);
	r[3] = q;
	if (SC1(LINUX_SYS_pipe, p1) != 0 || SC1(LINUX_SYS_pipe, p2) != 0)
		return;
	/* No CLONE_VM: the child runs on its copy of this stack. */
	child = SC3(LINUX_SYS_clone, LINUX_CLONE_FILES | LINUX_SIGCHLD, 0, 0);
	r[4] = child;
	if (child == 0) {
		c[0] = SC1(LINUX_SYS_unshare, LINUX_CLONE_FILES);
		c[1] = SC3(LINUX_SYS_read, q, buf, sizeof(buf));
		(void)SC3(LINUX_SYS_write, p1[1], c, sizeof(c));
		/* Stay in the table until the owner has tried too. */
		(void)SC3(LINUX_SYS_read, p2[0], &b, 1);
		(void)SC1(LINUX_SYS_exit_group, 0);
	}
	if (child < 0)
		return;
	if (SC3(LINUX_SYS_read, p1[0], c, sizeof(c)) == (long)sizeof(c)) {
		r[5] = c[0];
		r[6] = c[1];
	}
	r[7] = SC1(LINUX_SYS_unshare, LINUX_CLONE_FILES);
	r[8] = SC3(LINUX_SYS_ioctl, q, LINUX_FIONBIO, &on);
	r[9] = SC3(LINUX_SYS_read, q, buf, sizeof(buf));
	(void)SC3(LINUX_SYS_write, p2[1], "x", 1);
	(void)linux_syscall(LINUX_SYS_wait4, child, 0, 0, 0, 0, 0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	long in[4], r[NRES];
	int i;

	for (i = 0; i < NRES; i++)
		r[i] = 0x5555;
	if (SC3(LINUX_SYS_read, 0, in, sizeof(in)) != (long)sizeof(in))
		(void)SC1(LINUX_SYS_exit_group, 3);
	if (in[0] == 0) {
		r[0] = SC3(LINUX_SYS_pidfd_open, in[1], 0, 0);
		r[1] = SC3(LINUX_SYS_pidfd_getfd, r[0], in[2], 0);
		r[2] = SC3(LINUX_SYS_pidfd_getfd, r[0], in[3], 0);
	} else
		unshare_rows(r);
	(void)SC3(LINUX_SYS_write, 1, r, sizeof(r));
	(void)SC1(LINUX_SYS_exit_group, 0);
	for (;;)
		;
}
