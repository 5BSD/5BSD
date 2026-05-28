/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT service integration for oracled.
 *
 * Opens /dev/cap_rt, claims it via isolation, and activates the
 * capprotect shield.  All cap_rt service fd lifecycle is managed
 * here.  Callers use cap_rt_setup() and cap_rt_teardown().
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/cap_rt/cap_rt_ioctl.h>
#include <dev/cap_rt/cap_rt_capprotect_proto.h>
#include <dev/cap_rt/cap_rt_isolation_proto.h>
#include <dev/cap_rt/cap_rt_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

/* Service instance fds — module-private. */
static int cap_rt_fd = -1;
static int isolation_fd = -1;
static int capprotect_fd = -1;
static int system_fd = -1;

/*
 * Build the integrity flags bitmask from config.
 */
static uint32_t
integrity_flags_from_config(void)
{
	uint32_t flags;

	flags = 0;
	if (od.cfg.integrity_ptrace)
		flags |= CP_SF_PTRACE;
	if (od.cfg.integrity_signal)
		flags |= CP_SF_SIGNAL;
	if (od.cfg.integrity_visible)
		flags |= CP_SF_VISIBLE;
	if (od.cfg.integrity_wait)
		flags |= CP_SF_WAIT;
	if (od.cfg.integrity_sched)
		flags |= CP_SF_SCHED;
	if (od.cfg.integrity_core)
		flags |= CP_SF_CORE;
	if (od.cfg.integrity_ktrace)
		flags |= CP_SF_KTRACE;
	return (flags);
}

static const struct {
	uint32_t	flag;
	const char	*name;
} integrity_flag_names[] = {
	{ CP_SF_PTRACE,		"ptrace" },
	{ CP_SF_SIGNAL,		"signal" },
	{ CP_SF_VISIBLE,	"visible" },
	{ CP_SF_WAIT,		"wait" },
	{ CP_SF_SCHED,		"sched" },
	{ CP_SF_CORE,		"core" },
	{ CP_SF_KTRACE,		"ktrace" },
};

static void
log_integrity_flags(uint32_t flags)
{
	char buf[256];
	size_t off;
	unsigned i;

	off = 0;
	for (i = 0; i < nitems(integrity_flag_names); i++) {
		if (!(flags & integrity_flag_names[i].flag))
			continue;
		if (off > 0 && off < sizeof(buf) - 1)
			buf[off++] = ' ';
		off += strlcpy(buf + off, integrity_flag_names[i].name,
		    sizeof(buf) - off);
	}
	if (off == 0)
		strlcpy(buf, "(none)", sizeof(buf));

	syslog(LOG_INFO, "integrity active: %s", buf);
}

/*
 * Helper: connect to a named cap_rt service.
 */
static int
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
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (fd);
}

/*
 * Claim a single vnode (file or directory) via the isolation
 * service.  The isolation_fd must already be connected.
 */
static int
claim_path(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		syslog(LOG_WARNING, "isolation: open %s: %m", path);
		ORACLED_PROBE_CLAIM_PATH_FAIL(path);
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "isolation: claim %s: %m", path);
		ORACLED_PROBE_CLAIM_PATH_FAIL(path);
		close(fd);
		return (-1);
	}

	close(fd);
	syslog(LOG_INFO, "isolation: claimed %s", path);
	ORACLED_PROBE_CLAIM_PATH(path);
	return (0);
}

/*
 * Claim a network endpoint via the isolation service.
 */
static int
claim_net(const struct oracled_net_claim *nc)
{
	struct cap_rt_call_args call;
	struct fi_net_request req;
	struct fi_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port = htons(nc->port);
	req.direction = nc->direction;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(isolation_fd, CAP_RT_CALL, &call) == -1) {
		ORACLED_PROBE_CLAIM_NET_FAIL(nc->port, nc->protocol);
		syslog(LOG_WARNING, "isolation: claim port %u/%s: %m",
		    nc->port,
		    nc->protocol == IPPROTO_TCP ? "tcp" :
		    nc->protocol == IPPROTO_UDP ? "udp" : "any");
		return (-1);
	}

	ORACLED_PROBE_CLAIM_NET(nc->port, nc->protocol);
	syslog(LOG_INFO, "isolation: claimed port %u/%s %s",
	    nc->port,
	    nc->protocol == IPPROTO_TCP ? "tcp" :
	    nc->protocol == IPPROTO_UDP ? "udp" : "any",
	    nc->direction == 0x01 ? "bind" :
	    nc->direction == 0x02 ? "connect" : "any");
	return (0);
}

/*
 * Connect to the isolation service and claim all configured
 * resources.
 */
static int
isolate_resources(void)
{
	int claimed, failed, i, total;

	isolation_fd = cap_rt_svc_connect("isolation");
	if (isolation_fd == -1)
		return (-1);

	claimed = failed = 0;

	/* Always claim /dev/cap_rt — oracled owns this device. */
	if (claim_path("/dev/cap_rt") == 0)
		claimed++;
	else
		failed++;

	/* Claim configured paths (files and directories). */
	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		if (claim_path(od.cfg.claim_paths[i]) == 0)
			claimed++;
		else
			failed++;
	}

	/* Claim configured network endpoints. */
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		if (claim_net(&od.cfg.claim_net[i]) == 0)
			claimed++;
		else
			failed++;
	}

	total = claimed + failed;
	if (failed > 0)
		syslog(LOG_WARNING, "claims: %d/%d succeeded, "
		    "%d failed", claimed, total, failed);
	else if (total > 0)
		syslog(LOG_INFO, "claims: %d/%d succeeded",
		    claimed, total);

	return (0);
}

static int
apply_integrity(void)
{
	struct cap_rt_call_args call;
	struct cp_request req;
	uint32_t flags;
	int cp_fd;

	cp_fd = cap_rt_svc_connect("capprotect");
	if (cp_fd == -1)
		return (-1);

	flags = integrity_flags_from_config();

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply_len = 0;

	if (ioctl(cp_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_ERR, "capprotect shield: %m");
		close(cp_fd);
		return (-1);
	}

	capprotect_fd = cp_fd;
	ORACLED_PROBE_INTEGRITY(flags);
	log_integrity_flags(flags);
	return (0);
}

/*
 * Claim system operations via the cap_rt_system service.
 */
static int
claim_system_gates(void)
{
	struct cap_rt_call_args call;
	struct sys_request req;

	if (od.cfg.claim_system == 0)
		return (0);

	system_fd = cap_rt_svc_connect("system");
	if (system_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = od.cfg.claim_system;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply_len = 0;

	if (ioctl(system_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "system: claim gates 0x%x: %m",
		    od.cfg.claim_system);
		close(system_fd);
		system_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "system: claimed gates 0x%x",
	    od.cfg.claim_system);
	return (0);
}

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

	if (capprotect_fd >= 0) {
		close(capprotect_fd);
		capprotect_fd = -1;
		syslog(LOG_INFO, "integrity protection released");
	}
	if (system_fd >= 0) {
		close(system_fd);
		system_fd = -1;
		syslog(LOG_INFO, "system gates released");
	}
	if (isolation_fd >= 0) {
		close(isolation_fd);
		isolation_fd = -1;
		syslog(LOG_INFO, "isolation claim released");
	}
	if (cap_rt_fd >= 0) {
		close(cap_rt_fd);
		cap_rt_fd = -1;
		syslog(LOG_INFO, "closed /dev/cap_rt");
	}
}
