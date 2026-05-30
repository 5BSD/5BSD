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

#include <dev/cap_rt/cap_rt_coalition_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "probes.h"

/*
 * Helper: perform a simple CAP_RT_CALL with no fd-passing.
 */
static int
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

/* Pair service protocol (defined in kernel module, no public header). */
#define	PAIR_OP_CREATE	1

/* Service instance fds — module-private. */
static int cap_rt_fd = -1;
static int isolation_fd = -1;
static int capprotect_fd = -1;
static int system_fd = -1;

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
		BUF_APPEND(buf, sizeof(buf), &off, "%s%s",
		    off > 0 ? " " : "", integrity_flag_names[i].name);
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
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "cap_rt connect %s: fcntl CLOEXEC: %m",
		    name);
		close(fd);
		return (-1);
	}
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
	struct fi_net_request req;
	struct fi_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port = htons(nc->port);
	req.direction = nc->direction;

	if (cap_rt_do_call(isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		ORACLED_PROBE_CLAIM_NET_FAIL(nc->port, nc->protocol);
		syslog(LOG_WARNING, "isolation: claim port %u/%s: %m",
		    nc->port, net_protocol_name(nc->protocol));
		return (-1);
	}

	ORACLED_PROBE_CLAIM_NET(nc->port, nc->protocol);
	syslog(LOG_INFO, "isolation: claimed port %u/%s %s",
	    nc->port, net_protocol_name(nc->protocol),
	    net_direction_name(nc->direction));
	return (0);
}

/*
 * Connect to the isolation service and claim all configured
 * resources.
 */
static int
isolate_resources(void)
{
	unsigned int i;
	int claimed, failed, total;

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
	struct cp_request req;
	uint32_t flags;
	int cp_fd;

	cp_fd = cap_rt_svc_connect("capprotect");
	if (cp_fd == -1)
		return (-1);

	flags = od.cfg.integrity_flags;

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	if (cap_rt_do_call(cp_fd, &req, sizeof(req), NULL, 0) == -1) {
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
	struct sys_request req;

	if (od.cfg.claim_system == 0)
		return (0);

	system_fd = cap_rt_svc_connect("system");
	if (system_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = od.cfg.claim_system;

	if (cap_rt_do_call(system_fd, &req, sizeof(req), NULL, 0) == -1) {
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
 * Mint an isolation access token for a claimed path.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_path_token(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd, token_fd;

	if (isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_path_token: isolation not connected");
		return (-1);
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		syslog(LOG_WARNING, "mint_path_token: open %s: %m", path);
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_path_token: mint %s: %m", path);
		close(fd);
		return (-1);
	}

	close(fd);
	return (token_fd);
}

/*
 * Mint a network isolation access token.
 * The oracle must already hold network claims; the token covers
 * all of the oracle's claimed endpoints.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_net_token(void)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int token_fd;

	if (isolation_fd == -1) {
		syslog(LOG_WARNING, "mint_net_token: isolation not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_MINT_NET;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply = &reply;
	call.reply_len = sizeof(reply);
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_net_token: %m");
		return (-1);
	}

	return (token_fd);
}

/*
 * Mint a system access token for the given gate bitmask.
 * Returns the token fd on success, -1 on failure.
 */
int
cap_rt_mint_system_token(uint32_t gates)
{
	struct cap_rt_call_args call;
	struct sys_request req;
	int token_fd;

	if (system_fd == -1) {
		syslog(LOG_WARNING, "mint_system_token: system not connected");
		return (-1);
	}

	token_fd = -1;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	req.gates = gates;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.reply_len = 0;
	call.reply_fds = &token_fd;
	call.reply_nfds = 1;

	if (ioctl(system_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "mint_system_token: mint 0x%x: %m", gates);
		return (-1);
	}

	return (token_fd);
}

/*
 * Create a cap_rt pair channel.
 * Sets *oracle_end and *child_end to the two paired fds.
 * Returns 0 on success, -1 on failure.
 */
int
cap_rt_create_pair(int *oracle_end, int *child_end)
{
	struct cap_rt_sendmsg_args sa;
	struct cap_rt_recvmsg_args ra;
	uint32_t op;
	int pair_fd, peer_fd;

	if (cap_rt_fd == -1)
		return (-1);

	pair_fd = cap_rt_svc_connect("pair");
	if (pair_fd == -1)
		return (-1);

	op = PAIR_OP_CREATE;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &op;
	sa.payload_len = sizeof(op);

	if (ioctl(pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
		syslog(LOG_WARNING, "create_pair: sendmsg: %m");
		close(pair_fd);
		return (-1);
	}

	peer_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.fds = &peer_fd;
	ra.nfds = 1;

	if (ioctl(pair_fd, CAP_RT_RECVMSG, &ra) == -1) {
		syslog(LOG_WARNING, "create_pair: recvmsg: %m");
		close(pair_fd);
		return (-1);
	}

	if (peer_fd < 0) {
		syslog(LOG_WARNING, "create_pair: recvmsg returned no fd");
		close(pair_fd);
		return (-1);
	}

	if (fcntl(pair_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_pair: fcntl CLOEXEC pair_fd: %m");
		close(pair_fd);
		close(peer_fd);
		return (-1);
	}
	if (fcntl(peer_fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_WARNING, "create_pair: fcntl CLOEXEC peer_fd: %m");
		close(pair_fd);
		close(peer_fd);
		return (-1);
	}

	*oracle_end = pair_fd;
	*child_end = peer_fd;
	return (0);
}

/*
 * Create a coalition instance.
 * Returns the coalition fd on success, -1 on failure.
 */
int
cap_rt_create_coalition(void)
{
	int fd;

	if (cap_rt_fd == -1)
		return (-1);
	fd = cap_rt_svc_connect("coalition");
	if (fd >= 0)
		(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	return (fd);
}

/*
 * Coalition helpers — wrap CAP_RT_CALL ioctls for the coalition
 * service so that callers don't need to know the wire protocol.
 */
int
cap_rt_coalition_enlist(int coalition_fd, int member_fd)
{
	struct cap_rt_call_args call;
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_ENLIST;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &member_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_set_leader(int coalition_fd, int leader_fd)
{
	struct cap_rt_call_args call;
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_SET_LEADER;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &leader_fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(coalition_fd, CAP_RT_CALL, &call) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_set_deadline(int coalition_fd, int timeout_ms,
    int sig, int grace_ms)
{
	struct coalition_set_deadline_req dreq;
	struct coalition_reply reply;

	memset(&dreq, 0, sizeof(dreq));
	dreq.op = COALITION_OP_SET_DEADLINE;
	dreq.timeout_ms = (uint32_t)timeout_ms;
	dreq.signal = sig;
	dreq.grace_ms = (uint32_t)grace_ms;

	if (cap_rt_do_call(coalition_fd, &dreq, sizeof(dreq),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_terminate(int coalition_fd)
{
	struct coalition_req_hdr req;
	struct coalition_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = COALITION_OP_TERMINATE;

	if (cap_rt_do_call(coalition_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1)
		return (-1);
	return (reply.status);
}

int
cap_rt_coalition_recv_event(int coalition_fd, uint32_t *flagsp)
{
	struct cap_rt_recvmsg_args ra;
	struct coalition_event_msg ev;

	memset(&ev, 0, sizeof(ev));
	memset(&ra, 0, sizeof(ra));
	ra.payload = &ev;
	ra.payload_len = sizeof(ev);

	if (ioctl(coalition_fd, CAP_RT_RECVMSG, &ra) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (1);
		return (-1);
	}

	if (ra.payload_len < sizeof(ev))
		return (-1);
	*flagsp = ev.flags;
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
