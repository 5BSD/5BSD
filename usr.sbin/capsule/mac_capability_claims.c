/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * MAC_CAPABILITY claim primitives for capsule.
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

#include "capsule_daemon.h"
#include "capsule_svc_proto.h"
#include "probes.h"
#include "mac_capability_priv.h"

/*
 * Per-OID sysctl isolation (docs/capability-sysctl-isolation.md, Phase 2):
 * the standing scoped SYS_GATE_SYSCTL claim's dedicated connection and its
 * independent reference count.  Kept on a connection SEPARATE from the coarse
 * mac_capability_system_fd so the kernel's per-connection claim bookkeeping
 * (which refs a gate only once per connection and overwrites sp_gates) can ref
 * SYS_GATE_SYSCTL into Capsule's per-nonce claim and satisfy the scoped
 * mint, regardless of what the coarse connection has already claimed.
 */
static int	sysctl_scoped_fd = -1;
static unsigned	sysctl_scoped_refcount;

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
		CAPSULE_PROBE_CLAIM_PATH_FAIL(path);
		return (-1);
	}

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_CLAIM;

	if (mac_capability_do_call_fds(mac_capability_isolation_fd,
	    &req, sizeof(req), &fd, 1, &reply, sizeof(reply), NULL, 0) == -1) {
		syslog(LOG_WARNING, "isolation: claim %s: %m", path);
		CAPSULE_PROBE_CLAIM_PATH_FAIL(path);
		close(fd);
		return (-1);
	}

	close(fd);
	syslog(LOG_INFO, "isolation: claimed %s", path);
	CAPSULE_PROBE_CLAIM_PATH(path);
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
		CAPSULE_PROBE_CLAIM_NET_FAIL(nc->port_min, nc->port_max,
		    nc->protocol);
		syslog(LOG_WARNING, "isolation: claim port %s/%s: %m",
		    portbuf, ort_net_protocol_name(nc->protocol));
		return (-1);
	}

	CAPSULE_PROBE_CLAIM_NET(nc->port_min, nc->port_max, nc->protocol);
	syslog(LOG_INFO, "isolation: claimed port %s/%s %s",
	    portbuf, ort_net_protocol_name(nc->protocol),
	    ort_net_direction_name(nc->direction));
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
	CAPSULE_PROBE_CLAIM_NET_RELEASE(nc->port_min, nc->port_max,
	    nc->protocol);
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
	CAPSULE_PROBE_CLAIM_SYSTEM_RELEASE(gates);
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

	/* Always claim /dev/mac_capability — capsule owns this device. */
	if (mac_capability_claim_path("/dev/mac_capability") == 0)
		claimed++;
	else
		failed++;

	/* Claim configured network endpoints. */
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		if (mac_capability_claim_net(&od.cfg.claim_net[i]) == 0)
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
	flags = od.cfg.integrity_flags | CAPSULE_REQUIRED_INTEGRITY_FLAGS;

	/*
	 * The CP_SF_SIGNAL shield is UNCONDITIONAL, including when Capsule is
	 * PID 1 (docs/lifecycle-capability-design.md, P4b).  Lifecycle/status/
	 * reload are reached through capsulectl(8) over serviced's capability
	 * plane, and reboot(8)/shutdown(8)/halt(8) delegate to it (falling back to
	 * reboot(2), the kernel escape) rather than signalling init.  Nothing
	 * drives a lifecycle transition by kill(1, SIG*) any more, so the shield
	 * goes up from engine start: a userland signal can never reach init's
	 * legacy transition handler.  (This retires the former deferral, which
	 * kept the signal ABI open until a control socket was listening so
	 * shutdown(8)'s kill(1) fallback worked; with delegation there is no such
	 * fallback to protect, so the earlier "unshutdownable wedge" concern no
	 * longer applies.)  Kernel-internal signals are unaffected by the shield
	 * (the MAC proc_check_signal hook fires only on the kill(2) user path), so
	 * SIGCHLD reaping, SIGALRM timeouts, and capsule's own pdkill authority
	 * over serviced always work.
	 */
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
	CAPSULE_PROBE_INTEGRITY(flags);
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
	CAPSULE_PROBE_INTEGRITY(od.cfg.integrity_flags);
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
		if (mac_capability_confine_capsule_fd(mac_capability_system_fd,
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

/*
 * --- Per-OID sysctl isolation (Phase 2) ---
 *
 * Capsule owns the scoped SYSCTL claim; localsysctl is a delivered-token
 * writer (it never opens the device).  oidset points at the OPAQUE marshalled
 * sys_sysctl_oidset serviced built from the manifest isolate list; Capsule
 * bounds-checks its length and relays the bytes into the kernel SYS_OP_CLAIM's
 * OID-set trailer under its own nonce, never interpreting sysctl specifics.
 */
int
mac_capability_claim_system_sysctl(const void *oidset, size_t oidset_len)
{
	uint8_t buf[sizeof(struct sys_request) +
	    CAPSULE_MINT_SYSTEM_PAYLOAD_MAX];
	struct sys_request *req;

	if (oidset == NULL || oidset_len == 0 ||
	    oidset_len > CAPSULE_MINT_SYSTEM_PAYLOAD_MAX)
		return (-1);

	if (sysctl_scoped_fd == -1) {
		sysctl_scoped_fd = mac_capability_svc_connect("system");
		if (sysctl_scoped_fd == -1)
			return (-1);
		if (mac_capability_confine_capsule_fd(sysctl_scoped_fd,
		    "system") == -1) {
			close(sysctl_scoped_fd);
			sysctl_scoped_fd = -1;
			return (-1);
		}
	}

	req = (struct sys_request *)buf;
	memset(req, 0, sizeof(*req));
	req->op = SYS_OP_CLAIM;
	req->gates = SYS_GATE_SYSCTL;
	memcpy(buf + sizeof(*req), oidset, oidset_len);

	if (mac_capability_do_call(sysctl_scoped_fd, buf,
	    sizeof(*req) + oidset_len, NULL, 0) == -1) {
		syslog(LOG_WARNING, "system: scoped sysctl claim: %m");
		/*
		 * If nothing was held yet, this dedicated connection never
		 * created a claim; drop it so a later attempt reconnects fresh.
		 */
		if (sysctl_scoped_refcount == 0) {
			close(sysctl_scoped_fd);
			sysctl_scoped_fd = -1;
		}
		return (-1);
	}

	sysctl_scoped_refcount++;
	syslog(LOG_INFO, "system: scoped sysctl claim (refs=%u)",
	    sysctl_scoped_refcount);
	return (0);
}

/*
 * Mint a token scoped to the standing SYSCTL claim.  The dedicated connection's
 * claim gates cover SYS_GATE_SYSCTL, so SYS_OP_MINT on it yields a SYSCTL token
 * whose owner is Capsule nonce; localsysctl authorizes it to its own nonce
 * via service_provider_authorize_capabilities(3).  Returns the token fd or -1.
 */
int
mac_capability_mint_system_sysctl_token(void)
{
	struct sys_request req;
	int token_fd;

	if (sysctl_scoped_fd == -1) {
		syslog(LOG_WARNING, "system: scoped sysctl mint: no claim");
		return (-1);
	}
	token_fd = -1;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	req.gates = SYS_GATE_SYSCTL;
	if (mac_capability_do_call_fds(sysctl_scoped_fd, &req, sizeof(req),
	    NULL, 0, NULL, 0, &token_fd, 1) == -1) {
		syslog(LOG_WARNING, "system: scoped sysctl mint: %m");
		return (-1);
	}
	return (token_fd);
}

/*
 * Drop one reference on the standing scoped SYSCTL claim.  At zero, release the
 * claim (SYS_OP_RELEASE with an empty payload releases the whole SYSCTL gate for
 * this owner) and close the dedicated connection.  Returns 1 if a scoped claim
 * was held (so the caller need not run the coarse release for SYS_GATE_SYSCTL),
 * 0 if nothing scoped was held.
 */
int
mac_capability_release_system_sysctl(void)
{

	if (sysctl_scoped_refcount == 0)
		return (0);
	sysctl_scoped_refcount--;
	if (sysctl_scoped_refcount == 0 && sysctl_scoped_fd != -1) {
		struct sys_request req;

		memset(&req, 0, sizeof(req));
		req.op = SYS_OP_RELEASE;
		req.gates = SYS_GATE_SYSCTL;
		(void)mac_capability_do_call(sysctl_scoped_fd, &req,
		    sizeof(req), NULL, 0);
		(void)close(sysctl_scoped_fd);
		sysctl_scoped_fd = -1;
		syslog(LOG_INFO, "system: released scoped sysctl claim");
	}
	return (1);
}

/*
 * Force-drop the standing scoped SYSCTL claim (serviced exit sweep).  Closing
 * the dedicated connection revokes the claim in the kernel.
 */
void
mac_capability_sweep_system_sysctl(void)
{

	if (sysctl_scoped_fd != -1) {
		(void)close(sysctl_scoped_fd);
		sysctl_scoped_fd = -1;
		syslog(LOG_INFO,
		    "system: sweep released scoped sysctl claim");
	}
	sysctl_scoped_refcount = 0;
}
