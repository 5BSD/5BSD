/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/capsicum.h>
#include <fcntl.h>
#include "bootstrap_exec.h"

/* Called in Capsule's child after remapping, before the manager exec.
 * The one permitted exec consumes ONCE in the kernel before user code runs. */
int
bootstrap_confine_manager_fd(int fd)
{

	if (fcntl(fd, F_SETFD, 0) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) == -1)
		return (-1);
	return (0);
}
