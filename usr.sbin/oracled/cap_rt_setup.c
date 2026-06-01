/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT core lifecycle for oracled.
 *
 * Owns the static service fd variables and provides getter/setter
 * access for sibling cap_rt_*.c files.  Contains setup, teardown,
 * and the shared helpers cap_rt_svc_connect / cap_rt_do_call.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_capprotect_proto.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>
#include <dev/cap_rt/cap_rt_system_proto.h>
#include <dev/cap_rt/cap_rt_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "gates.h"
#include "probes.h"
#include "cap_rt_priv.h"

/* Service instance fds — shared across cap_rt_*.c files. */
int cap_rt_fd = -1;
int cap_rt_isolation_fd = -1;
int cap_rt_capprotect_fd = -1;
int cap_rt_system_fd = -1;

/* --- Shared helpers --- */

/*
 * Helper: perform a simple CAP_RT_CALL with no fd-passing.
 */
int
cap_rt_do_call(int fd, const void *req, size_t reqlen,
    void *reply, size_t replylen)
{
	struct cap_rt_call_args call;

	memset(&call, 0, sizeof(call));
	call.req = req;
	call.req_len = reqlen;
	call.reply = reply;
	call.reply_len = replylen;
	return (ioctl(fd, CAP_RT_CALL, &call));
}

/*
 * Helper: connect to a named cap_rt service.
 */
int
cap_rt_svc_connect(const char *name)
{
	struct cap_rt_connect_args conn;
	int fd;

	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, name, sizeof(conn.name));
	if (ioctl(cap_rt_fd, CAP_RT_CONNECT, &conn) == -1) {
		syslog(LOG_ERR, "cap_rt connect %s: %m", name);
		return (-1);
	}
	fd = conn.fd;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "cap_rt connect %s: fcntl CLOEXEC: %m",
		    name);
		close(fd);
		return (-1);
	}
	return (fd);
}

/* --- Setup / teardown --- */

/*
 * Initialize all cap_rt services.  Called once during startup.
 * Errors are logged but not fatal — oracled degrades gracefully.
 */
int
cap_rt_setup(void)
{

	cap_rt_fd = open("/dev/cap_rt", O_RDWR | O_CLOEXEC);
	if (cap_rt_fd == -1) {
		syslog(LOG_WARNING, "open /dev/cap_rt: %m");
		return (-1);
	}
	syslog(LOG_INFO, "opened /dev/cap_rt");

	if (isolate_resources() == -1)
		syslog(LOG_WARNING, "failed to connect isolation service");

	if (claim_system_gates() == -1)
		syslog(LOG_WARNING, "failed to claim system operations");

	if (apply_integrity() == -1)
		syslog(LOG_WARNING, "failed to activate integrity protection");

	return (0);
}

/*
 * Release all cap_rt services.  Order matters: capprotect first
 * (removes integrity protection), then isolation (releases
 * claims), then the control device itself.
 */
void
cap_rt_teardown(void)
{

	if (cap_rt_capprotect_fd >= 0) {
		close(cap_rt_capprotect_fd);
		cap_rt_capprotect_fd = -1;
		syslog(LOG_INFO, "integrity protection released");
	}
	if (cap_rt_system_fd >= 0) {
		close(cap_rt_system_fd);
		cap_rt_system_fd = -1;
		syslog(LOG_INFO, "system gates released");
	}
	if (cap_rt_isolation_fd >= 0) {
		close(cap_rt_isolation_fd);
		cap_rt_isolation_fd = -1;
		syslog(LOG_INFO, "isolation claim released");
	}
	if (cap_rt_fd >= 0) {
		close(cap_rt_fd);
		cap_rt_fd = -1;
		syslog(LOG_INFO, "closed /dev/cap_rt");
	}
}

/*
 * Mint a new instance of a service from an existing instance fd.
 * Uses CAP_RT_MINT_INSTANCE — the service must have CAP_RT_SVC_MINTABLE.
 * Returns the new instance fd on success, -1 on failure.
 */
int
cap_rt_mint_instance(int instance_fd)
{
	struct cap_rt_mint_instance_args ma;

	memset(&ma, 0, sizeof(ma));
	if (ioctl(instance_fd, CAP_RT_MINT_INSTANCE, &ma) == -1) {
		syslog(LOG_WARNING, "cap_rt_mint_instance: %m");
		return (-1);
	}
	if (fcntl(ma.fd, F_SETFD, FD_CLOEXEC) == -1) {
		close(ma.fd);
		return (-1);
	}
	return (ma.fd);
}

/*
 * Create a service instance for delegation to serviced.
 * Connects to the named service and returns the instance fd.
 */
int
cap_rt_connect_for_delegate(const char *name)
{

	return (cap_rt_svc_connect(name));
}
