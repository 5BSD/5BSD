/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client library for communicating with authorityd(8) via its
 * control socket.
 */

#ifndef _AUTHORITYCTL_H_
#define	_AUTHORITYCTL_H_

#include <sys/types.h>
#include <stdint.h>

#include "authorityd_ctl.h"

/*
 * Public aliases for wire protocol constants defined in authorityd_ctl.h.
 */
#define	AUTHORITYCTL_VERSION	CTL_VERSION
#define	AUTHORITYCTL_MAX_PAYLOAD	CTL_MAX_PAYLOAD

/* Opcodes. */
#define	AUTHORITYCTL_SHUTDOWN	CTL_OP_SHUTDOWN
#define	AUTHORITYCTL_STATUS	CTL_OP_STATUS
#define	AUTHORITYCTL_RELOAD	CTL_OP_RELOAD
#define	AUTHORITYCTL_SUMMARY_MAX	CTL_SUMMARY_MAX

/* Lifecycle opcodes (valid only when authorityd is PID 1). */
#define	AUTHORITYCTL_REBOOT	CTL_OP_REBOOT
#define	AUTHORITYCTL_HALT		CTL_OP_HALT
#define	AUTHORITYCTL_POWEROFF	CTL_OP_POWEROFF
#define	AUTHORITYCTL_POWERCYCLE	CTL_OP_POWERCYCLE
#define	AUTHORITYCTL_SINGLE	CTL_OP_SINGLE
#define	AUTHORITYCTL_REROOT	CTL_OP_REROOT
#define	AUTHORITYCTL_RESCAN	CTL_OP_RESCAN
#define	AUTHORITYCTL_CATATONIA	CTL_OP_CATATONIA

/* Status reply from authorityd. */
struct authorityctl_status {
	int		error;		/* 0 on success, errno on failure */
	uint64_t	uptime_usec;	/* daemon uptime in microseconds */
};

__BEGIN_DECLS
int	authorityctl_open(const char *sockpath);
int	authorityctl_status(int fd, struct authorityctl_status *st,
	    char *summary, size_t sumlen);
int	authorityctl_shutdown(int fd);
int	authorityctl_reload(int fd, char *summary, size_t sumlen);
int	authorityctl_lifecycle(int fd, uint32_t op);
__END_DECLS

#endif /* !_AUTHORITYCTL_H_ */
