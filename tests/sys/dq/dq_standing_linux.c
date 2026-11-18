/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * dq_standing_test's Linux half: a freestanding amd64 Linux program,
 * built at buildworld time (Makefile) with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It inherits a directory as descriptor 9, stats "/etc" (an absolute
 * name a "/" standing rule matches) and opens "/rin-f" with openat2(2)
 * RESOLVE_IN_ROOT from the descriptor (RINROOT: the name is relative to
 * it), and exits with a bit for each call that failed.
 */

#include "dq_linux.h"

#define	DIR_FD			9
#define	LINUX_AT_FDCWD		(-100)
#define	LINUX_RESOLVE_IN_ROOT	0x10

struct linux_open_how {
	unsigned long	flags;
	unsigned long	mode;
	unsigned long	resolve;
};

void	_start(void);

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	struct linux_open_how how;
	char st[256];
	long fd;
	int bad;

	bad = 0;
	if (linux_syscall(LINUX_SYS_newfstatat, LINUX_AT_FDCWD, (long)"/etc",
	    (long)st, 0, 0, 0) != 0)
		bad |= 1;
	how.flags = 0;			/* O_RDONLY */
	how.mode = 0;
	how.resolve = LINUX_RESOLVE_IN_ROOT;
	fd = linux_syscall(LINUX_SYS_openat2, DIR_FD, (long)"/rin-f",
	    (long)&how, sizeof(how), 0, 0);
	if (fd < 0)
		bad |= 2;
	else
		(void)linux_syscall(LINUX_SYS_close, fd, 0, 0, 0, 0, 0);
	(void)linux_syscall(LINUX_SYS_exit_group, bad, 0, 0, 0, 0, 0);
	for (;;)
		;
}
