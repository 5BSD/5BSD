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
#define	ORACLECTL_CHECK		CTL_OP_CHECK
#define	ORACLECTL_LOAD		CTL_OP_LOAD
#define	ORACLECTL_SERVICES	CTL_OP_SERVICES
#define	ORACLECTL_VERIFY	CTL_OP_VERIFY
#define	ORACLECTL_SUMMARY_MAX	CTL_SUMMARY_MAX

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
int	oraclectl_check(int fd, const char *filename,
	    char *summary, size_t sumlen);
int	oraclectl_load(int fd, const char *filename,
	    char *summary, size_t sumlen);
int	oraclectl_services(int fd, uint32_t flags, char *summary,
	    size_t sumlen);
int	oraclectl_verify(int fd, char *summary, size_t sumlen);
__END_DECLS

#endif /* !_ORACLECTL_H_ */
