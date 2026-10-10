/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procctl.h>
#include <errno.h>
#include "oom_protect.h"
int
svc_oom_protect(pid_t child, bool requested, bool trusted_system)
{
	int flags = PPROT_SET;
	if (!requested)
		return (0);
	if (!trusted_system)
		return (errno = EPERM, -1);
	if (child <= 0)
		return (errno = EINVAL, -1);
	/* No DESCEND or INHERIT: protection belongs to this process only. */
	return (procctl(P_PID, child, PROC_SPROTECT, &flags));
}
