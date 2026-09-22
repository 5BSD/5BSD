/* SPDX-License-Identifier: BSD-2-Clause */
/* Native amd64 backend regression for Linux ioperm compatibility. */
#include <sys/types.h>
#include <machine/sysarch.h>
#include <errno.h>
#include <unistd.h>

int
main(void)
{
	struct i386_ioperm_args perm = {
		.start = 0x80, .length = 1, .enable = 0
	};

	if (sysarch(I386_SET_IOPERM, &perm) != 0)
		return (1);
	perm.enable = 1;
	if (sysarch(I386_SET_IOPERM, &perm) != 0)
		return (2);
	perm.enable = 0;
	if (sysarch(I386_GET_IOPERM, &perm) != 0 || perm.enable != 1)
		return (3);
	if (setresuid(1000, 1000, 1000) != 0)
		return (4);
	perm.enable = 1;
	errno = 0;
	if (sysarch(I386_SET_IOPERM, &perm) != -1 || errno != EPERM)
		return (5);
	perm.enable = 0;
	if (sysarch(I386_SET_IOPERM, &perm) != 0 ||
	    sysarch(I386_GET_IOPERM, &perm) != 0 || perm.enable != 0)
		return (6);
	perm.start = 65536;
	errno = 0;
	if (sysarch(I386_SET_IOPERM, &perm) != -1 || errno != EINVAL)
		return (7);
	return (0);
}
