/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client library for communicating with oracled(8) via its
 * control socket.
 */

#ifndef _ORACLECTL_H_
#define	_ORACLECTL_H_

#include <sys/types.h>
#include <stdint.h>

#include "oracled_ctl.h"

/*
 * Public aliases for wire protocol constants defined in oracled_ctl.h.
 */
#define	ORACLECTL_VERSION	CTL_VERSION
#define	ORACLECTL_MAX_PAYLOAD	CTL_MAX_PAYLOAD

/* Opcodes. */
#define	ORACLECTL_SHUTDOWN	CTL_OP_SHUTDOWN
#define	ORACLECTL_STATUS	CTL_OP_STATUS
#define	ORACLECTL_RELOAD	CTL_OP_RELOAD
#define	ORACLECTL_SUMMARY_MAX	CTL_SUMMARY_MAX

/* Lifecycle opcodes (valid only when oracled is PID 1). */
#define	ORACLECTL_REBOOT	CTL_OP_REBOOT
#define	ORACLECTL_HALT		CTL_OP_HALT
#define	ORACLECTL_POWEROFF	CTL_OP_POWEROFF
#define	ORACLECTL_POWERCYCLE	CTL_OP_POWERCYCLE
#define	ORACLECTL_SINGLE	CTL_OP_SINGLE
#define	ORACLECTL_REROOT	CTL_OP_REROOT
#define	ORACLECTL_RESCAN	CTL_OP_RESCAN
#define	ORACLECTL_CATATONIA	CTL_OP_CATATONIA

/* Status reply from oracled. */
struct oraclectl_status {
	int		error;		/* 0 on success, errno on failure */
	uint64_t	uptime_usec;	/* daemon uptime in microseconds */
};

__BEGIN_DECLS
int	oraclectl_open(const char *sockpath);
int	oraclectl_status(int fd, struct oraclectl_status *st,
	    char *summary, size_t sumlen);
int	oraclectl_shutdown(int fd);
int	oraclectl_reload(int fd, char *summary, size_t sumlen);
int	oraclectl_lifecycle(int fd, uint32_t op);
__END_DECLS

#endif /* !_ORACLECTL_H_ */
