/* SPDX-License-Identifier: BSD-2-Clause */
/* Dynamic-loader boundary fixture, launched only in the isolated test VM. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
	struct cap_authority_info info;

	if (syscall(SYS_cap_process, CAP_AUTH_INFO, -1, 0, &info) == -1 ||
	    !info.valid || info.kind != CAP_AUTH_MANAGED || !issetugid())
		return (1);
	return (0);
}
