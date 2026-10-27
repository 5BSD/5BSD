/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SERVICE_LOOKUP_IDENTITY_H
#define SERVICE_LOOKUP_IDENTITY_H
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <errno.h>
#include <unistd.h>
#include "libservice.h"
static inline int
service_lookup_identity(int *fd)
{
	cap_rights_t rights;
	int saved;
	u_int mode;
	*fd = -1;
	if (cap_getmode(&mode) == -1)
		return (-1);
	/* pdself is capability-mode-only. Ambient callers name only themselves;
	 * never change the caller's mode merely to perform service discovery. */
	if (mode != 0) {
		if (pdself(fd, PD_DAEMON | PD_CLOEXEC) == -1)
			return (errno == ENOSYS ? 0 : -1);
	} else if ((*fd = pdopenpid(getpid(), PD_DAEMON | PD_CLOEXEC)) == -1)
		return (errno == ENOSYS ? 0 : -1);
	if (cap_rights_limit(*fd, cap_rights_init(&rights, CAP_PDGETPID,
	    CAP_EVENT, CAP_KQUEUE_EVENT)) == 0)
		return (0);
	saved = errno; close(*fd); *fd = -1; return (errno = saved, -1);
}
/* Outer lookup ownership survives cancellation delivered when the inner RPC
 * restores cancellation state. The reply FD may already have been returned. */
struct service_lookup_owned {
	int *process, *reply;
	struct service_session **session;
};
static inline void
service_lookup_cleanup(void *arg)
{
	struct service_lookup_owned *owned = arg;
	if (owned->session != NULL && *owned->session != NULL) {
		service_session_close(*owned->session);
		*owned->session = NULL;
	}
	if (*owned->process >= 0) { close(*owned->process); *owned->process = -1; }
	if (*owned->reply >= 0) { close(*owned->reply); *owned->reply = -1; }
}
#endif
