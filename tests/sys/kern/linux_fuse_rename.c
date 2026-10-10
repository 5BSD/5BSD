/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux syscall entry for the native FUSE NOREPLACE protocol fixture. */
#include "linux_test.h"

static int
test(int argc, char **argv, char **envp)
{
	long result;

	(void)envp;
	if (argc != 3)
		return (255);
	result = sys5(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], 1);
	return (result == 0 ? 0 : (result < 0 && result > -255 ? -result : 255));
}
