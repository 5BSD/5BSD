/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * CAP_RT claim management for oracled.
 *
 * Handles path claims, network claims, system gate claims,
 * their release, and the reload-with-effective-config logic.
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

/* --- Static helpers --- */

static bool
net_claim_eq(const struct oracled_net_claim *a,
    const struct oracled_net_claim *b)
{

	return (a->domain == b->domain &&
	    a->protocol == b->protocol &&
	    a->port == b->port &&
	    a->direction == b->direction);
}

static bool
net_claim_in(const struct oracled_net_claim *needle,
    const struct oracled_net_claim *haystack, unsigned nhaystack)
{
	unsigned i;

	for (i = 0; i < nhaystack; i++) {
		if (net_claim_eq(needle, &haystack[i]))
			return (true);
	}
	return (false);
}

static bool
path_in(const char *path, const char paths[][PATH_MAX], unsigned npaths)
{
	unsigned i;

	for (i = 0; i < npaths; i++) {
		if (strcmp(path, paths[i]) == 0)
			return (true);
	}
	return (false);
}

static bool
query_path_claimed(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	if (cap_rt_isolation_fd == -1)
		return (false);

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (false);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_QUERY;

	memset(&call, 0, sizeof(call));
	call.req = &req;
	call.req_len = sizeof(req);
	call.req_fds = &fd;
	call.req_nfds = 1;
	call.reply = &reply;
	call.reply_len = sizeof(reply);

	if (ioctl(cap_rt_isolation_fd, CAP_RT_CALL, &call) == -1) {
		close(fd);
		return (false);
	}

	close(fd);
	return ((reply.flags & FI_QF_MINE) != 0);
}

/* --- Integrity flag table (shared with cap_rt_format_status) --- */

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

	syslog(LOG_INFO, "cap_rt: integrity active: %s", buf);
}

/* --- Claim / release primitives --- */

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

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
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
 * Release a single vnode claim via the isolation service.
 */
static int
release_path(const char *path)
{
	struct cap_rt_call_args call;
	struct fi_request req;
	struct fi_reply reply;
	int fd;

	if (cap_rt_isolation_fd == -1)
		return (-1);

	fd = open(path, O_RDONLY | O_CLOEXEC);
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
	return (0);
}

/*
 * Release a network endpoint claim via the isolation service.
 */
static int
release_net(const struct oracled_net_claim *nc)
{
	struct fi_net_request req;
	struct fi_reply reply;

	if (cap_rt_isolation_fd == -1)
		return (-1);

	memset(&req, 0, sizeof(req));
	req.op = FI_OP_RELEASE_NET;
	req.domain = nc->domain;
	req.protocol = nc->protocol;
	req.port = htons(nc->port);
	req.direction = nc->direction;

	if (cap_rt_do_call(cap_rt_isolation_fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == -1) {
		syslog(LOG_WARNING, "isolation: release port %u/%s: %m",
		    nc->port, net_protocol_name(nc->protocol));
		return (-1);
	}

	syslog(LOG_INFO, "isolation: released port %u/%s %s",
	    nc->port, net_protocol_name(nc->protocol),
	    net_direction_name(nc->direction));
	return (0);
}

/*
 * Release system gate claims.
 */
static int
release_system_gates(uint32_t gates)
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
		syslog(LOG_WARNING, "cap_rt: claims %d/%d succeeded, "
		    "%d failed", claimed, total, failed);
	else if (total > 0)
		syslog(LOG_INFO, "cap_rt: claims %d/%d succeeded",
		    claimed, total);

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

/* --- Reload --- */

/*
 * Reload resource claims and build an effective config reflecting
 * what the kernel actually holds.  Acquire new claims first, then
 * release old claims no longer needed.
 *
 * The effective config (written to *effective) reflects ground truth:
 * - Claims that were successfully acquired are included
 * - Claims that failed to acquire are excluded (old claim kept if it
 *   existed, otherwise not present)
 * - Claims that failed to release remain in the effective config
 *
 * The caller should use the effective config to update od.cfg so
 * status reports match kernel state.
 *
 * Integrity flags are a one-way latch and not modified here.
 */
int
cap_rt_reload_claims(const struct oracled_config *newcfg)
{
	const struct oracled_config *oldcfg;
	unsigned i;
	int acquired, released, failed;
	bool path_ok[ORACLED_MAX_PATH_CLAIMS];
	bool net_ok[ORACLED_MAX_NET_CLAIMS];
	uint32_t gates_acquired, gates_released;

	oldcfg = &od.cfg;
	acquired = released = failed = 0;
	gates_acquired = 0;
	gates_released = 0;

	if (cap_rt_isolation_fd == -1 && cap_rt_system_fd == -1) {
		syslog(LOG_WARNING, "reload: cap_rt not available, "
		    "skipping claims update");
		return (0);
	}

	/* Track which new claims succeed. */
	for (i = 0; i < newcfg->nclaim_paths; i++)
		path_ok[i] = true;
	for (i = 0; i < newcfg->nclaim_net; i++)
		net_ok[i] = true;

	/*
	 * Phase 1: Acquire new path claims.
	 */
	for (i = 0; i < newcfg->nclaim_paths; i++) {
		if (!path_in(newcfg->claim_paths[i],
		    oldcfg->claim_paths, oldcfg->nclaim_paths)) {
			if (claim_path(newcfg->claim_paths[i]) == 0) {
				acquired++;
			} else {
				path_ok[i] = false;
				failed++;
			}
		}
	}

	/*
	 * Phase 2: Acquire new network claims.
	 */
	for (i = 0; i < newcfg->nclaim_net; i++) {
		if (!net_claim_in(&newcfg->claim_net[i],
		    oldcfg->claim_net, oldcfg->nclaim_net)) {
			if (claim_net(&newcfg->claim_net[i]) == 0) {
				acquired++;
			} else {
				net_ok[i] = false;
				failed++;
			}
		}
	}

	/*
	 * Phase 3: Acquire new system gates.
	 */
	if (newcfg->claim_system != oldcfg->claim_system) {
		uint32_t new_gates;

		new_gates = newcfg->claim_system & ~oldcfg->claim_system;
		if (new_gates != 0 && cap_rt_system_fd != -1) {
			struct sys_request req;

			memset(&req, 0, sizeof(req));
			req.op = SYS_OP_CLAIM;
			req.gates = new_gates;
			if (cap_rt_do_call(cap_rt_system_fd, &req,
			    sizeof(req), NULL, 0) == -1) {
				syslog(LOG_WARNING,
				    "reload: claim new gates 0x%x: %m",
				    new_gates);
				failed++;
			} else {
				syslog(LOG_INFO,
				    "reload: claimed new gates 0x%x",
				    new_gates);
				gates_acquired = new_gates;
				acquired++;
			}
		}
	}

	/*
	 * Phase 4: Release old path claims no longer in config.
	 */
	for (i = 0; i < oldcfg->nclaim_paths; i++) {
		if (!path_in(oldcfg->claim_paths[i],
		    newcfg->claim_paths, newcfg->nclaim_paths)) {
			if (release_path(oldcfg->claim_paths[i]) == 0)
				released++;
			else
				failed++;
		}
	}

	/*
	 * Phase 5: Release old network claims no longer in config.
	 */
	for (i = 0; i < oldcfg->nclaim_net; i++) {
		if (!net_claim_in(&oldcfg->claim_net[i],
		    newcfg->claim_net, newcfg->nclaim_net)) {
			if (release_net(&oldcfg->claim_net[i]) == 0)
				released++;
			else
				failed++;
		}
	}

	/*
	 * Phase 6: Release old system gates no longer in config.
	 */
	if (newcfg->claim_system != oldcfg->claim_system) {
		uint32_t old_gates;

		old_gates = oldcfg->claim_system & ~newcfg->claim_system;
		if (old_gates != 0) {
			if (release_system_gates(old_gates) == 0) {
				gates_released = old_gates;
				released++;
			} else {
				failed++;
			}
		}
	}

	/*
	 * Phase 7: Build effective config — only include claims that
	 * are actually held by the kernel.  This is written back to
	 * the newcfg struct (which the caller passes to
	 * config_apply_claims).
	 */
	{
		struct oracled_config *eff;
		unsigned n;

		/*
		 * Cast away const — the caller owns this struct and
		 * expects us to adjust it to reflect ground truth.
		 */
		eff = __DECONST(struct oracled_config *, newcfg);

		/* Paths: keep only those that succeeded or were already held. */
		n = 0;
		for (i = 0; i < newcfg->nclaim_paths; i++) {
			if (path_ok[i]) {
				if (n != i)
					strlcpy(eff->claim_paths[n],
					    newcfg->claim_paths[i], PATH_MAX);
				n++;
			} else {
				syslog(LOG_WARNING, "reload: dropping failed "
				    "claim %s from effective config",
				    newcfg->claim_paths[i]);
			}
		}
		eff->nclaim_paths = n;

		/* Network: keep only those that succeeded or were already held. */
		n = 0;
		for (i = 0; i < newcfg->nclaim_net; i++) {
			if (net_ok[i]) {
				if (n != i)
					eff->claim_net[n] = newcfg->claim_net[i];
				n++;
			} else {
				syslog(LOG_WARNING, "reload: dropping failed "
				    "net claim port %u from effective config",
				    newcfg->claim_net[i].port);
			}
		}
		eff->nclaim_net = n;

		/* System gates: add only what was acquired, remove only
		 * what was released. */
		eff->claim_system = oldcfg->claim_system;
		eff->claim_system |= gates_acquired;
		eff->claim_system &= ~gates_released;
	}

	syslog(LOG_INFO, "reload: claims %d acquired, %d released, %d failed",
	    acquired, released, failed);
	return (failed > 0 ? -1 : 0);
}

/*
 * Format current claim status into a buffer for status reporting.
 */
void
cap_rt_format_status(char *buf, size_t bufsz, size_t *offp)
{
	unsigned i;
	bool first, verified;

	/* Integrity flags. */
	BUF_APPEND(buf, bufsz, offp, "INTEGRITY:\n  ");
	if (od.cfg.integrity_flags == 0) {
		BUF_APPEND(buf, bufsz, offp, "(none)");
	} else {
		first = true;
		for (i = 0; i < nitems(integrity_flag_names); i++) {
			if (od.cfg.integrity_flags &
			    integrity_flag_names[i].flag) {
				BUF_APPEND(buf, bufsz, offp, "%s%s",
				    first ? "" : " ",
				    integrity_flag_names[i].name);
				first = false;
			}
		}
		BUF_APPEND(buf, bufsz, offp, " (0x%x)",
		    od.cfg.integrity_flags);
	}
	BUF_APPEND(buf, bufsz, offp, "\n");

	/* Path claims — verified against kernel via FI_OP_QUERY. */
	BUF_APPEND(buf, bufsz, offp, "\nCLAIMS:\n");
	BUF_APPEND(buf, bufsz, offp, "  paths:    %u",
	    od.cfg.nclaim_paths + 1);	/* +1 for /dev/cap_rt */
	verified = query_path_claimed("/dev/cap_rt");
	BUF_APPEND(buf, bufsz, offp, "\n    /dev/cap_rt%s\n",
	    verified ? "" : " [NOT HELD]");
	for (i = 0; i < od.cfg.nclaim_paths; i++) {
		verified = query_path_claimed(od.cfg.claim_paths[i]);
		BUF_APPEND(buf, bufsz, offp, "    %s%s\n",
		    od.cfg.claim_paths[i],
		    verified ? "" : " [NOT HELD]");
	}

	/* Network claims.  FI_OP_QUERY_NET is not yet implemented
	 * in the kernel (reserved as op 6), so we report config
	 * state only.  TODO: verify when FI_OP_QUERY_NET lands. */
	BUF_APPEND(buf, bufsz, offp, "  network:  %u\n",
	    od.cfg.nclaim_net);
	for (i = 0; i < od.cfg.nclaim_net; i++) {
		const struct oracled_net_claim *nc = &od.cfg.claim_net[i];

		BUF_APPEND(buf, bufsz, offp, "    %s/%u %s\n",
		    net_protocol_name(nc->protocol), nc->port,
		    net_direction_name(nc->direction));
	}

	/* System gates. */
	BUF_APPEND(buf, bufsz, offp, "  system:   ");
	if (od.cfg.claim_system == 0) {
		BUF_APPEND(buf, bufsz, offp, "(none)\n");
	} else {
		first = true;
		for (i = 0; i < nitems(gate_names); i++) {
			if (od.cfg.claim_system & gate_names[i].gate) {
				BUF_APPEND(buf, bufsz, offp, "%s%s",
				    first ? "" : " ",
				    gate_names[i].name);
				first = false;
			}
		}
		BUF_APPEND(buf, bufsz, offp, " (0x%x)\n",
		    od.cfg.claim_system);
	}
}
