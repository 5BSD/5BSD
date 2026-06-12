/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT claim primitives for oracled.
 *
 * Provides individual claim/release operations for paths, network
 * endpoints, jails, and system gates, plus the lifecycle functions
 * (isolate_resources, apply_integrity, claim_system_gates) called
 * during initial setup.
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
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_svc_proto.h"
#include "probes.h"
#include "cap_rt_priv.h"

/* --- Static helpers --- */

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

	syslog(LOG_INFO, "cap_rt: integrity active: %s", buf);
}

/* --- Claim / release primitives --- */

/*
 * Claim a single vnode (file or directory) via the isolation
 * service.  The isolation_fd must already be connected.
 */
int
cap_rt_claim_path(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
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

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
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
int
cap_rt_claim_net(const struct ort_net_claim *nc)
{
	struct fi_net_request req;
	struct fi_reply reply;
	char portbuf[32];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port_min = htons(nc->port_min);
	req.port_max = htons(nc->port_max);
	req.direction = nc->direction;
	req.prefix = nc->prefix;
	memcpy(req.addr, nc->addr, sizeof(req.addr));
	net_claim_port_string(nc, portbuf, sizeof(portbuf));

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		ORACLED_PROBE_CLAIM_NET_FAIL(nc->port_min, nc->port_max,
		    nc->protocol);
		syslog(LOG_WARNING, "isolation: claim port %s/%s: %m",
		    portbuf, ort_net_protocol_name(nc->protocol));
		return (-1);
	}

	ORACLED_PROBE_CLAIM_NET(nc->port_min, nc->port_max, nc->protocol);
	syslog(LOG_INFO, "isolation: claimed port %s/%s %s",
	    portbuf, ort_net_protocol_name(nc->protocol),
	    ort_net_direction_name(nc->direction));
	return (0);
}

int
cap_rt_claim_jail(const struct oracled_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;
	char jailbuf[ORACLED_JAIL_DESC_MAX];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));
	jail_claim_string(jc, jailbuf, sizeof(jailbuf));

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: claim jail %s: %m", jailbuf);
		return (-1);
	}

	syslog(LOG_INFO, "isolation: claimed jail %s actions=0x%x",
	    jailbuf, jc->actions);
	return (0);
}

/*
 * Release a single vnode claim via the isolation service.
 */
int
cap_rt_release_path(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		syslog(LOG_WARNING, "isolation: release open %s: %m", path);
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
		syslog(LOG_WARNING, "isolation: release %s: %m", path);
		close(fd);
		return (-1);
	}

	close(fd);
	syslog(LOG_INFO, "isolation: released %s", path);
	ORACLED_PROBE_CLAIM_PATH_RELEASE(path);
	return (0);
}

/*
 * Release a network endpoint claim via the isolation service.
 */
int
cap_rt_release_net(const struct ort_net_claim *nc)
{
	struct fi_net_request req;
	struct fi_reply reply;
	char portbuf[32];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port_min = htons(nc->port_min);
	req.port_max = htons(nc->port_max);
	req.direction = nc->direction;
	req.prefix = nc->prefix;
	memcpy(req.addr, nc->addr, sizeof(req.addr));
	net_claim_port_string(nc, portbuf, sizeof(portbuf));

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: release port %s/%s: %m",
		    portbuf, ort_net_protocol_name(nc->protocol));
		return (-1);
	}

	syslog(LOG_INFO, "isolation: released port %s/%s %s",
	    portbuf, ort_net_protocol_name(nc->protocol),
	    ort_net_direction_name(nc->direction));
	ORACLED_PROBE_CLAIM_NET_RELEASE(nc->port_min, nc->port_max,
	    nc->protocol);
	return (0);
}

int
cap_rt_release_jail(const struct oracled_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;
	char jailbuf[ORACLED_JAIL_DESC_MAX];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));
	jail_claim_string(jc, jailbuf, sizeof(jailbuf));

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: release jail %s: %m",
		    jailbuf);
		return (-1);
	}

	syslog(LOG_INFO, "isolation: released jail %s", jailbuf);
	ORACLED_PROBE_CLAIM_JAIL_RELEASE(jc->name, jc->actions);
	return (0);
}

/*
 * Release system gate claims.
 */
int
cap_rt_release_system_gates(uint32_t gates)
{
	struct sys_request req;

	if (cap_rt_system_fd == -1 || gates == 0)
		return (0);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_RELEASE;
	req.gates = gates;

	if (cap_rt_do_call(cap_rt_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: release gates 0x%x: %m", gates);
		return (-1);
	}

	syslog(LOG_INFO, "system: released gates 0x%x", gates);
	ORACLED_PROBE_CLAIM_SYSTEM_RELEASE(gates);
	return (0);
}

/* --- Lifecycle functions called from cap_rt_setup --- */

/*
 * Connect to the isolation service and claim all configured
 * resources.
 */
int
isolate_resources(void)
{
	unsigned int i;
	int claimed, failed, total;

	cap_rt_isolation_fd = cap_rt_svc_connect("isolation");
	if (cap_rt_isolation_fd == -1)
		return (-1);

	claimed = failed = 0;

	/* Always claim /dev/cap_rt — oracled owns this device. */
	if (cap_rt_claim_path("/dev/cap_rt") == 0)
		claimed++;
	else
		failed++;

	/*
	 * Claim configured paths.  Skip paths that no longer exist
	 * so that stale entries left in oracled.conf after an upgrade
	 * do not prevent startup.  Other access errors (EACCES, EIO)
	 * are still fatal — they indicate a real problem.
	 */
	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		if (access(od.cfg.claim_paths[i], F_OK) != 0 &&
		    errno == ENOENT) {
			syslog(LOG_WARNING,
			    "isolation: skipping nonexistent claim path %s",
			    od.cfg.claim_paths[i]);
			continue;
		}
		if (cap_rt_claim_path(od.cfg.claim_paths[i]) == 0)
			claimed++;
		else
			failed++;
	}

	/* Claim configured network endpoints. */
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		if (cap_rt_claim_net(&od.cfg.claim_net[i]) == 0)
			claimed++;
		else
			failed++;
	}

	/* Claim configured jails. */
	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		if (cap_rt_claim_jail(&od.cfg.claim_jail[i]) == 0)
			claimed++;
		else
			failed++;
	}

	total = claimed + failed;
	if (failed > 0) {
		syslog(LOG_ERR, "cap_rt: claims %d/%d succeeded, "
		    "%d failed", claimed, total, failed);
		return (-1);
	} else if (total > 0) {
		syslog(LOG_INFO, "cap_rt: claims %d/%d succeeded",
		    claimed, total);
	}

	return (0);
}

int
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

	cap_rt_capprotect_fd = cp_fd;
	ORACLED_PROBE_INTEGRITY(flags);
	log_integrity_flags(flags);
	return (0);
}

/*
 * Claim system operations via the cap_rt_system service.
 */
int
claim_system_gates(void)
{
	struct sys_request req;

	if (od.cfg.claim_system == 0)
		return (0);

	cap_rt_system_fd = cap_rt_svc_connect("system");
	if (cap_rt_system_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = od.cfg.claim_system;

	if (cap_rt_do_call(cap_rt_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: claim gates 0x%x: %m",
		    od.cfg.claim_system);
		close(cap_rt_system_fd);
		cap_rt_system_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "system: claimed gates 0x%x",
	    od.cfg.claim_system);
	return (0);
}

/*
 * Claim specific system gate bits via the cap_rt_system service.
 * Used by the dynamic claim handler.
 */
int
cap_rt_claim_system_gate_bits(uint32_t gates)
{
	struct sys_request req;

	if (gates == 0)
		return (0);

	if (cap_rt_system_fd == -1) {
		cap_rt_system_fd = cap_rt_svc_connect("system");
		if (cap_rt_system_fd == -1)
			return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	if (cap_rt_do_call(cap_rt_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: claim gates 0x%x: %m", gates);
		return (-1);
	}

	syslog(LOG_INFO, "system: claimed gates 0x%x", gates);
	return (0);
}
