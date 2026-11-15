/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_swap_test's Linux program: a freestanding amd64 Linux program, built at
 * buildworld time (Makefile) with
 *   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static ...
 * It opens "orig" read-only, reads it and exits with a bit for each step
 * that did not go as it does for the file the supervisor swaps in, whose
 * content is "SUBSTITUTE".
 */

#include "dq_linux.h"

void	_start(void);

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	static const char want[] = "SUBSTITUTE";
	char buf[32];
	long fd, n;
	int bad, i;

	bad = 0;
	fd = linux_syscall(LINUX_SYS_open, (long)"orig", 0 /* O_RDONLY */, 0,
	    0, 0, 0);
	if (fd < 0)
		bad |= 1;
	else {
		n = linux_syscall(LINUX_SYS_read, fd, (long)buf, sizeof(buf), 0,
		    0, 0);
		if (n != (long)sizeof(want) - 1)
			bad |= 2;
		else {
			for (i = 0; i < (int)sizeof(want) - 1; i++) {
				if (buf[i] != want[i])
					bad |= 4;
			}
		}
		if (linux_syscall(LINUX_SYS_close, fd, 0, 0, 0, 0, 0) != 0)
			bad |= 8;
	}
	(void)linux_syscall(LINUX_SYS_exit_group, bad, 0, 0, 0, 0, 0);
	for (;;)
		;
}
