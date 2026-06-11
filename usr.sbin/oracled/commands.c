/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Control socket command handlers.
 *
 * Each function implements a single control opcode.  The dispatch
 * table in control.c calls these.
 */

#include <sys/linker.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ucl.h>

#include "oracled.h"
#include "oracled_ctl.h"
#include "commands.h"
#include "oracled_svc_proto.h"
#include "probes.h"

/*
 * Apply claim-related fields from newcfg into the live config.
 * Used by cmd_reload() and the SIGHUP handler in event.c.
 */
void
config_apply_claims(const struct oracled_config *newcfg)
{

	memcpy(od.cfg.claim_paths, newcfg->claim_paths,
	    sizeof(od.cfg.claim_paths));
	memcpy(od.cfg.claim_path_source, newcfg->claim_path_source,
	    sizeof(od.cfg.claim_path_source));
	memcpy(od.cfg.claim_path_refcount, newcfg->claim_path_refcount,
	    sizeof(od.cfg.claim_path_refcount));
	od.cfg.nclaim_paths = newcfg->nclaim_paths;
	memcpy(od.cfg.claim_net, newcfg->claim_net,
	    sizeof(od.cfg.claim_net));
	memcpy(od.cfg.claim_net_source, newcfg->claim_net_source,
	    sizeof(od.cfg.claim_net_source));
	memcpy(od.cfg.claim_net_refcount, newcfg->claim_net_refcount,
	    sizeof(od.cfg.claim_net_refcount));
	od.cfg.nclaim_net = newcfg->nclaim_net;
	memcpy(od.cfg.claim_jail, newcfg->claim_jail,
	    sizeof(od.cfg.claim_jail));
	memcpy(od.cfg.claim_jail_source, newcfg->claim_jail_source,
	    sizeof(od.cfg.claim_jail_source));
	memcpy(od.cfg.claim_jail_refcount, newcfg->claim_jail_refcount,
	    sizeof(od.cfg.claim_jail_refcount));
	od.cfg.nclaim_jail = newcfg->nclaim_jail;
	od.cfg.claim_system = newcfg->claim_system;
	od.cfg.claim_system_policy = newcfg->claim_system_policy;
	od.cfg.claim_system_service = newcfg->claim_system_service;
	memcpy(od.cfg.claim_system_refcount, newcfg->claim_system_refcount,
	    sizeof(od.cfg.claim_system_refcount));
}

void
cmd_status(uint64_t uptime, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	size_t off;

	reply->status = CTL_STATUS_OK;
	reply->uptime_usec = uptime;

	if (summary == NULL || sumlen == 0)
		return;

	off = 0;

	/* Config source. */
	BUF_APPEND(summary, sumlen, &off, "CONFIG:\n");
	BUF_APPEND(summary, sumlen, &off, "  file:         %s%s\n",
	    od.conffile,
	    od.cfg.loaded_from_file ? "" : " (defaults)");
	BUF_APPEND(summary, sumlen, &off, "  service_mgr:  %s\n",
	    od.cfg.service_manager);

	BUF_APPEND(summary, sumlen, &off, "\n");

	/* Capability claims and integrity from cap_rt. */
	if (!od.test_mode)
		cap_rt_format_status(summary, sumlen, &off);
	else {
		BUF_APPEND(summary, sumlen, &off,
		    "INTEGRITY:\n  (test mode)\n");
		BUF_APPEND(summary, sumlen, &off,
		    "\nCLAIMS:\n  (test mode)\n");
	}

	/* Bootstrap status. */
	BUF_APPEND(summary, sumlen, &off, "\nSERVICED:\n");
	BUF_APPEND(summary, sumlen, &off, "  status: %s\n",
	    oracle_proto_is_ready() ? "ready" : "not ready");
	if (bootstrap_pid() > 0)
		BUF_APPEND(summary, sumlen, &off, "  pid:    %jd\n",
		    (intmax_t)bootstrap_pid());

	reply->flags = (uint32_t)off;
}

int
cmd_shutdown(uid_t euid, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: shutdown denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_SHUTDOWN, euid);
		return (0);
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: shutdown uid %u", euid);
	return (1);
}

void
cmd_reload(uid_t euid, int kq __unused, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	struct oracled_config newcfg;
	size_t off;
	int claims_failed;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_RELOAD, euid);
		return;
	}

	syslog(LOG_INFO, "control: reload uid %u", euid);
	ORACLED_PROBE_RELOAD();

	off = 0;
	claims_failed = 0;

	/*
	 * Phase 1: Re-read configuration file for claims changes.
	 * Acquire new claims before releasing old ones so running
	 * services never lose a claim they depend on.
	 */
	config_init_defaults(&newcfg);
	if (config_load(&newcfg, od.conffile) == -1) {
		syslog(LOG_WARNING, "reload: config parse error, "
		    "keeping existing config");
		BUF_APPEND(summary, sumlen, &off,
		    "warning: config parse error, claims unchanged\n");
	} else {
		if (!od.test_mode) {
			claims_failed = cap_rt_reload_claims(&newcfg);
			if (claims_failed == -1)
				BUF_APPEND(summary, sumlen, &off,
				    "warning: some claim changes failed\n");
		}
		config_apply_claims(&newcfg);
	}

	/*
	 * Service manifest reload is handled by serviced.
	 * SIGHUP is forwarded to serviced by the bootstrap.
	 */
	reply->status = CTL_STATUS_OK;
	reply->flags = (uint32_t)off;
}

/*
 * cmd_check and cmd_load are handled by serviced.
 * Kept as stubs so the control socket dispatch doesn't break.
 */
void
cmd_check(uid_t euid __unused, const char *filename __unused,
    struct ctl_reply *reply, char *summary, size_t sumlen)
{

	reply->status = ENOSYS;
	snprintf(summary, sumlen,
	    "check: use servicectl(8) instead of oraclectl");
	reply->flags = (uint32_t)strlen(summary);
}

void
cmd_load(uid_t euid __unused, const char *filename __unused,
    int kq __unused, struct ctl_reply *reply, char *summary, size_t sumlen)
{

	reply->status = ENOSYS;
	snprintf(summary, sumlen,
	    "load: use servicectl(8) instead of oraclectl");
	reply->flags = (uint32_t)strlen(summary);
}

void
cmd_services(uid_t euid __unused, uint32_t flags __unused,
    struct ctl_reply *reply, char *summary, size_t sumlen)
{
	size_t off;

	off = 0;
	BUF_APPEND(summary, sumlen, &off,
	    "oracled: authority init (services managed by serviced)\n");
	BUF_APPEND(summary, sumlen, &off,
	    "serviced: %s\n",
	    oracle_proto_is_ready() ? "ready" : "not ready");
	BUF_APPEND(summary, sumlen, &off,
	    "serviced pid: %jd\n", (intmax_t)bootstrap_pid());

	reply->status = CTL_STATUS_OK;
	reply->flags = (uint32_t)off;
}

