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

/*
 * Wire protocol constants — duplicated here so library users
 * do not need the daemon's private headers.
 */
#define	ORACLED_CTL_SOCK	"/var/run/oracled.sock"
#define	ORACLECTL_VERSION	1
#define	ORACLECTL_MAX_PAYLOAD	1024

/* Opcodes. */
#define	ORACLECTL_SHUTDOWN	1
#define	ORACLECTL_STATUS	2
#define	ORACLECTL_RELOAD	3
#define	ORACLECTL_KLDLOAD	4
#define	ORACLECTL_KLDUNLOAD	5
#define	ORACLECTL_REBOOT	6
#define	ORACLECTL_CHECK		7
#define	ORACLECTL_LOAD		8
#define	ORACLECTL_SERVICES	9
#define	ORACLECTL_SUMMARY_MAX	2048

/* Status reply from oracled. */
struct oraclectl_status {
	int		error;		/* 0 on success, errno on failure */
	uint32_t	flags;		/* op-specific (e.g., kldload id) */
	uint64_t	uptime_usec;	/* daemon uptime in microseconds */
};

__BEGIN_DECLS
int	oraclectl_open(const char *sockpath);
int	oraclectl_status(int fd, struct oraclectl_status *st);
int	oraclectl_shutdown(int fd);
int	oraclectl_reload(int fd, char *summary, size_t sumlen);
int	oraclectl_kldload(int fd, const char *module, int *idp);
int	oraclectl_kldunload(int fd, const char *module);
int	oraclectl_reboot(int fd, int howto);
int	oraclectl_check(int fd, const char *filename,
	    char *summary, size_t sumlen);
int	oraclectl_load(int fd, const char *filename,
	    char *summary, size_t sumlen);
int	oraclectl_services(int fd, char *summary, size_t sumlen);
__END_DECLS

#endif /* !_ORACLECTL_H_ */
