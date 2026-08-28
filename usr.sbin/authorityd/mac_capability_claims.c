/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY claim primitives for authorityd.
 *
 * Provides individual claim/release operations for paths, network
 * endpoints, jails, and system gates, plus the lifecycle functions
 * (isolate_resources, apply_integrity, claim_system_gates) called
 * during initial setup.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "authorityd.h"
#include "authorityd_svc_proto.h"
#include "probes.h"
#include "mac_capability_priv.h"

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

	syslog(LOG_INFO, "mac_capability: integrity active: %s", buf);
}

/* --- Claim / release primitives --- */

/*
 * Claim a single vnode (file or directory) via the isolation
 * service.  The isolation_fd must already be connected.
 */
int
mac_capability_claim_path(const char *path)
{
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd == -1) {
		syslog(LOG_WARNING, "isolation: open %s: %m", path);
		AUTHORITYD_PROBE_CLAIM_PATH_FAIL(path);
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM;

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), &fd, 1, &reply, sizeof(reply), NULL, 0) == -1) {
		syslog(LOG_WARNING, "isolation: claim %s: %m", path);
		AUTHORITYD_PROBE_CLAIM_PATH_FAIL(path);
		close(fd);
		return (-1);
	}

	close(fd);
	syslog(LOG_INFO, "isolation: claimed %s", path);
	AUTHORITYD_PROBE_CLAIM_PATH(path);
	return (0);
}

/*
 * Claim a network endpoint via the isolation service.
 */
int
mac_capability_claim_net(const struct ort_net_claim *nc)
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

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		AUTHORITYD_PROBE_CLAIM_NET_FAIL(nc->port_min, nc->port_max,
		    nc->protocol);
		syslog(LOG_WARNING, "isolation: claim port %s/%s: %m",
		    portbuf, ort_net_protocol_name(nc->protocol));
		return (-1);
	}

	AUTHORITYD_PROBE_CLAIM_NET(nc->port_min, nc->port_max, nc->protocol);
	syslog(LOG_INFO, "isolation: claimed port %s/%s %s",
	    portbuf, ort_net_protocol_name(nc->protocol),
	    ort_net_direction_name(nc->direction));
	return (0);
}

int
mac_capability_claim_jail(const struct authorityd_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;
	char jailbuf[AUTHORITYD_JAIL_DESC_MAX];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));
	jail_claim_string(jc, jailbuf, sizeof(jailbuf));

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: claim jail %s: %m", jailbuf);
		return (-1);
	}

	syslog(LOG_INFO, "isolation: claimed jail %s actions=0x%x",
	    jailbuf, jc->actions);
	return (0);
}

int
mac_capability_claim_vsock(const struct ort_vsock_claim *vc)
{
	struct fi_vsock_request req;
	struct fi_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM_VSOCK;
	req.cid = vc->cid;
	req.port_min = vc->port_min;
	req.port_max = vc->port_max;
	req.direction = vc->direction;
	return (mac_capability_do_call(mac_capability_isolation_fd, &req,
	    sizeof(req), &reply, sizeof(reply)));
}

/*
 * Release a single vnode claim via the isolation service.
 */
int
mac_capability_release_path(const char *path)
{
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

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), &fd, 1, &reply, sizeof(reply), NULL, 0) == -1) {
		syslog(LOG_WARNING, "isolation: release %s: %m", path);
		close(fd);
		return (-1);
	}

	close(fd);
	syslog(LOG_INFO, "isolation: released %s", path);
	AUTHORITYD_PROBE_CLAIM_PATH_RELEASE(path);
	return (0);
}

int
mac_capability_release_vsock(const struct ort_vsock_claim *vc)
{
	struct fi_vsock_request req;
	struct fi_reply reply;

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE_VSOCK;
	req.cid = vc->cid;
	req.port_min = vc->port_min;
	req.port_max = vc->port_max;
	req.direction = vc->direction;
	return (mac_capability_do_call(mac_capability_isolation_fd, &req,
	    sizeof(req), &reply, sizeof(reply)));
}

/*
 * Release a network endpoint claim via the isolation service.
 */
int
mac_capability_release_net(const struct ort_net_claim *nc)
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

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: release port %s/%s: %m",
		    portbuf, ort_net_protocol_name(nc->protocol));
		return (-1);
	}

	syslog(LOG_INFO, "isolation: released port %s/%s %s",
	    portbuf, ort_net_protocol_name(nc->protocol),
	    ort_net_direction_name(nc->direction));
	AUTHORITYD_PROBE_CLAIM_NET_RELEASE(nc->port_min, nc->port_max,
	    nc->protocol);
	return (0);
}

int
mac_capability_release_jail(const struct authorityd_jail_claim *jc)
{
	struct fi_jail_request req;
	struct fi_reply reply;
	char jailbuf[AUTHORITYD_JAIL_DESC_MAX];

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE_JAIL;
	req.jid = jc->jid;
	req.actions = jc->actions;
	strlcpy(req.name, jc->name, sizeof(req.name));
	jail_claim_string(jc, jailbuf, sizeof(jailbuf));

	if (mac_capability_do_call(mac_capability_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: release jail %s: %m",
		    jailbuf);
		return (-1);
	}

	syslog(LOG_INFO, "isolation: released jail %s", jailbuf);
	AUTHORITYD_PROBE_CLAIM_JAIL_RELEASE(jc->name, jc->actions);
	return (0);
}

/*
 * Release system gate claims.
 */
int
mac_capability_release_system_gates(uint32_t gates)
{
	struct sys_request req;

	if (mac_capability_system_fd == -1 || gates == 0)
		return (0);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_RELEASE;
	req.gates = gates;

	if (mac_capability_do_call(mac_capability_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: release gates 0x%x: %m", gates);
		return (-1);
	}

	syslog(LOG_INFO, "system: released gates 0x%x", gates);
	AUTHORITYD_PROBE_CLAIM_SYSTEM_RELEASE(gates);
	return (0);
}

/* --- Lifecycle functions called from mac_capability_setup --- */

/*
 * Connect to the isolation service and claim all configured
 * resources.
 */
int
isolate_resources(void)
{
	unsigned int i;
	int claimed, failed, total;

	mac_capability_isolation_fd = mac_capability_svc_connect("isolation");
	if (mac_capability_isolation_fd == -1)
		return (-1);

	claimed = failed = 0;

	/* Always claim /dev/mac_capability — authorityd owns this device. */
	if (mac_capability_claim_path("/dev/mac_capability") == 0)
		claimed++;
	else
		failed++;

	/*
	 * Claim configured paths.  Skip paths that no longer exist
	 * so that stale entries left in authorityd.conf after an upgrade
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
		if (mac_capability_claim_path(od.cfg.claim_paths[i]) == 0)
			claimed++;
		else
			failed++;
	}

	/* Claim configured network endpoints. */
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		if (mac_capability_claim_net(&od.cfg.claim_net[i]) == 0)
			claimed++;
		else
			failed++;
	}

	/* Claim configured jails. */
	for (i = 0; i < od.cfg.nclaim_jail; i++) {
		if (mac_capability_claim_jail(&od.cfg.claim_jail[i]) == 0)
			claimed++;
		else
			failed++;
	}

	total = claimed + failed;
	if (failed > 0) {
		syslog(LOG_ERR, "mac_capability: claims %d/%d succeeded, "
		    "%d failed", claimed, total, failed);
		return (-1);
	} else if (total > 0) {
		syslog(LOG_INFO, "mac_capability: claims %d/%d succeeded",
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

	cp_fd = mac_capability_svc_connect("capprotect");
	if (cp_fd == -1)
		return (-1);

	/* Defense in depth: configuration may never reopen PID signalling. */
	flags = od.cfg.integrity_flags | AUTHORITYD_REQUIRED_INTEGRITY_FLAGS;

	/*
	 * When Authority is PID 1 the CP_SF_SIGNAL shield is DEFERRED until
	 * the lifecycle control socket is actually listening (see
	 * apply_signal_shield(), called from oi_ctl_try_setup()).
	 * shutdown(8)/reboot(8)/halt(8) prefer the authenticated control
	 * socket (CTL_OP_REBOOT etc., see docs/authority-control-abi-design.md)
	 * and fall back to the signal ABI when the socket is absent.  If the
	 * signal shield goes up before the socket exists — e.g. a boot where
	 * serviced fails to converge and PID 1 drops to recovery — the
	 * fallback kill(1, SIGINT) is silently denied and the machine
	 * becomes unshutdownable (observed as a hard wedge after
	 * shutdown(8)'s wall message, 2026-08-14).  Shield-without-socket
	 * must therefore never occur: signal protection is raised only
	 * once the socket replacement for the signal ABI is reachable.
	 * The KILL/CONT shields and all other integrity flags still apply
	 * from engine start.  Kernel-internal signals are unaffected by
	 * the shield either way (the MAC proc_check_signal hook fires only
	 * on the kill(2) user path), so SIGCHLD reaping, SIGALRM timeouts,
	 * and authorityd's own pdkill authority over serviced always work.
	 */
	if (getpid() == 1)
		flags &= ~CP_SF_SIGNAL;
	od.cfg.integrity_flags = flags;

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;

	if (mac_capability_do_call(cp_fd, &req, sizeof(req), NULL, 0) == -1) {
		syslog(LOG_ERR, "capprotect shield: %m");
		close(cp_fd);
		return (-1);
	}

	mac_capability_capprotect_fd = cp_fd;
	AUTHORITYD_PROBE_INTEGRITY(flags);
	log_integrity_flags(flags);
	return (0);
}

/*
 * Raise the deferred CP_SF_SIGNAL shield once the control socket is
 * listening.  The kernel's shield table refcounts flags per nonce, so a
 * second capprotect connection adding CP_SF_SIGNAL composes with the
 * shield applied at engine start; the connection is kept open for the
 * lifetime of PID 1 so the flag never drops.  Idempotent.
 */
int
apply_signal_shield(void)
{
	static int signal_shield_fd = -1;
	struct cp_request req;
	int cp_fd;

	if (signal_shield_fd != -1 ||
	    (od.cfg.integrity_flags & CP_SF_SIGNAL) != 0)
		return (0);

	cp_fd = mac_capability_svc_connect("capprotect");
	if (cp_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = CP_SF_SIGNAL;
	if (mac_capability_do_call(cp_fd, &req, sizeof(req), NULL, 0) == -1) {
		syslog(LOG_ERR, "capprotect signal shield: %m");
		close(cp_fd);
		return (-1);
	}

	signal_shield_fd = cp_fd;
	od.cfg.integrity_flags |= CP_SF_SIGNAL;
	AUTHORITYD_PROBE_INTEGRITY(od.cfg.integrity_flags);
	log_integrity_flags(od.cfg.integrity_flags);
	return (0);
}

/*
 * Claim system operations via the mac_capability_system service.
 */
int
claim_system_gates(void)
{
	struct sys_request req;

	if (od.cfg.claim_system == 0)
		return (0);

	mac_capability_system_fd = mac_capability_svc_connect("system");
	if (mac_capability_system_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = od.cfg.claim_system;

	if (mac_capability_do_call(mac_capability_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: claim gates 0x%x: %m",
		    od.cfg.claim_system);
		close(mac_capability_system_fd);
		mac_capability_system_fd = -1;
		return (-1);
	}

	syslog(LOG_INFO, "system: claimed gates 0x%x",
	    od.cfg.claim_system);
	return (0);
}

/*
 * Claim specific system gate bits via the mac_capability_system service.
 * Used by the dynamic claim handler.
 */
int
mac_capability_claim_system_gate_bits(uint32_t gates)
{
	struct sys_request req;

	if (gates == 0)
		return (0);

	if (mac_capability_system_fd == -1) {
		mac_capability_system_fd = mac_capability_svc_connect("system");
		if (mac_capability_system_fd == -1)
			return (-1);
		if (mac_capability_confine_authority_fd(mac_capability_system_fd,
		    "system") == -1) {
			close(mac_capability_system_fd);
			mac_capability_system_fd = -1;
			return (-1);
		}
	}

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	if (mac_capability_do_call(mac_capability_system_fd, &req, sizeof(req),
	    NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: claim gates 0x%x: %m", gates);
		return (-1);
	}

	syslog(LOG_INFO, "system: claimed gates 0x%x", gates);
	return (0);
}
