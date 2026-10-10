/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <libservice.h>
#include <security/oes/oes.h>
#include <unistd.h>

#include "oes_factory.h"

int
bsdfilesystem_oes_open_notify(int rootfd)
{
	static const unsigned long commands[] = {
		OES_IOC_SUBSCRIBE,
		OES_IOC_SUBSCRIBE_BITMAP,
		OES_IOC_GET_SUBSCRIPTIONS,
		OES_IOC_GET_MODE,
		OES_IOC_GET_SCOPE,
		OES_IOC_GET_STATS,
	};
	struct oes_mode_args mode = { 0 };
	struct oes_scope_args scope = { 0 };
	cap_rights_t rights;
	int fd, saved;

	fd = openat(rootfd, "dev/oes",
	    O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_RESOLVE_BENEATH);
	if (fd == -1)
		return (-1);
	/* Verify the kernel contract before issuing any attenuated descriptor.
	 */
	if (ioctl(fd, OES_IOC_GET_MODE, &mode) == -1 ||
	    ioctl(fd, OES_IOC_GET_SCOPE, &scope) == -1)
		goto fail;
	if (mode.ema_mode != OES_MODE_NOTIFY ||
	    scope.esa_scope != OES_SCOPE_GLOBAL) {
		errno = EPROTO;
		goto fail;
	}
	cap_rights_init(&rights, CAP_READ, CAP_EVENT, CAP_IOCTL, CAP_FSTAT);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, commands, nitems(commands)) == -1 ||
	    service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE) == -1)
		goto fail;
	return (fd);
fail:
	saved = errno;
	(void)close(fd);
	return (errno = saved, -1);
}
