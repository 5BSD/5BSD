/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * cap_rt service setup: isolation claims and capprotect shield.
 */

#include <sys/ioctl.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_capprotect_proto.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"

/*
 * Connect to the "isolation" cap_rt service and claim /dev/cap_rt.
 *
 * On success, sets isolation_fd to the service instance fd.
 * The claim persists as long as isolation_fd is open.
 */
int
isolate_cap_rt_device(void)
{
	struct cap_rt_connect_args conn;
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int dev_fd, iso_fd;

	if (cap_rt_fd < 0)
		return (-1);

	/* Connect to the isolation service. */
	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, "isolation", sizeof(conn.name));
	if (ioctl(cap_rt_fd, CAP_RT_CONNECT, &conn) == -1) {
		syslog(LOG_ERR, "cap_rt connect isolation: %m");
		return (-1);
	}
	iso_fd = conn.fd;

	/*
	 * Open /dev/cap_rt a second time to pass as the claim target.
	 * The isolation service identifies the vnode from this fd.
	 */
	dev_fd = open("/dev/cap_rt", O_RDONLY | O_CLOEXEC);
	if (dev_fd == -1) {
		syslog(LOG_ERR, "open /dev/cap_rt for isolation claim: %m");
		close(iso_fd);
		return (-1);
	}

	/* FI_OP_CLAIM with the device fd attached. */
	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &dev_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(iso_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_ERR, "cap_rt isolation claim /dev/cap_rt: %m");
		close(dev_fd);
		close(iso_fd);
		return (-1);
	}

	close(dev_fd);
	isolation_fd = iso_fd;
	syslog(LOG_INFO, "claimed /dev/cap_rt via isolation");
	return (0);
}

/*
 * Shield oracled via the capprotect service.
 *
 * Block foreign nonces from debugging, signalling, tracing, or
 * manipulating the scheduler priority of this process.
 *
 * On success, sets capprotect_fd to the shield instance fd.
 * The shield persists as long as capprotect_fd is open.
 */

/*
 * Shield flags: protect oracled from external interference.
 *
 * Base flags (always active):
 *   CP_SF_PTRACE   — block debugger attach
 *   CP_SF_SIGNAL   — block signals from foreign nonces
 *   CP_SF_WAIT     — block wait4 status scraping
 *   CP_SF_SCHED    — block priority/affinity manipulation
 *   CP_SF_KTRACE   — block passive syscall tracing
 *
 * Production flags (added when not in debug mode):
 *   CP_SF_VISIBLE  — hide from ps/top/procfs enumeration
 *   CP_SF_CORE     — suppress core dumps to prevent secret leakage
 *
 * Never included:
 *   CP_SF_SIGKILL  — must remain killable from a root console.
 *   CP_SF_NOPRIVS  — oracled needs root to manage processes.
 *   CP_SF_NOFORK   — oracled will spawn service children.
 *   CP_SF_NOIPC    — may need IPC for future service management.
 *   CP_SF_NOFDRECV — oracled will receive fds from clients.
 */
#define	ORACLED_SHIELD_BASE	(CP_SF_PTRACE | CP_SF_SIGNAL | \
				 CP_SF_WAIT | CP_SF_SCHED | CP_SF_KTRACE)
#define	ORACLED_SHIELD_PROD	(CP_SF_VISIBLE | CP_SF_CORE)

static const struct {
	uint32_t	flag;
	const char	*name;
} shield_flag_names[] = {
	{ CP_SF_PTRACE,		"ptrace" },
	{ CP_SF_SIGNAL,		"signal" },
	{ CP_SF_VISIBLE,	"visible" },
	{ CP_SF_WAIT,		"wait" },
	{ CP_SF_SIGKILL,	"sigkill" },
	{ CP_SF_SIGCONT,	"sigcont" },
	{ CP_SF_SCHED,		"sched" },
	{ CP_SF_CORE,		"core" },
	{ CP_SF_KTRACE,		"ktrace" },
	{ CP_SF_NOPRIVS,	"noprivs" },
	{ CP_SF_NOFORK,		"nofork" },
	{ CP_SF_NOIPC,		"noipc" },
	{ CP_SF_NOFDRECV,	"nofdrecv" },
};

static void
log_shield_flags(uint32_t flags)
{
	char buf[256];
	size_t off;
	unsigned i;

	off = 0;
	for (i = 0; i < sizeof(shield_flag_names) /
	    sizeof(shield_flag_names[0]); i++) {
		if (!(flags & shield_flag_names[i].flag))
			continue;
		if (off > 0 && off < sizeof(buf) - 1)
			buf[off++] = ' ';
		off += strlcpy(buf + off, shield_flag_names[i].name,
		    sizeof(buf) - off);
	}
	if (off == 0)
		strlcpy(buf, "(none)", sizeof(buf));

	syslog(LOG_INFO, "capprotect shield active: %s", buf);
}

int
shield_self(void)
{
	struct cap_rt_connect_args conn;
	struct cap_rt_call_args call;
	struct cp_request req;
	uint32_t flags;
	int cp_fd;

	if (cap_rt_fd < 0)
		return (-1);

	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, "capprotect", sizeof(conn.name));
	if (ioctl(cap_rt_fd, CAP_RT_CONNECT, &conn) == -1) {
		syslog(LOG_ERR, "cap_rt connect capprotect: %m");
		return (-1);
	}
	cp_fd = conn.fd;

	flags = ORACLED_SHIELD_BASE;
	if (!foreground)
		flags |= ORACLED_SHIELD_PROD;

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply_len = 0;

	if (ioctl(cp_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_ERR, "cap_rt capprotect shield: %m");
		close(cp_fd);
		return (-1);
	}

	capprotect_fd = cp_fd;
	log_shield_flags(flags);
	return (0);
}
