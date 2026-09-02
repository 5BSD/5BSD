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
#include <unistd.h>

#include "authorityd.h"
#include "authorityd_ctl.h"
#include "commands.h"
#include "authorityd_svc_proto.h"
#include "probes.h"

/*
 * Apply claim-related fields from newcfg into the live config.
 * Used by cmd_reload() and the SIGHUP handler in event.c.
 */
void
config_apply_claims(const struct authorityd_config *newcfg)
{

	memcpy(od.cfg.claim_net, newcfg->claim_net,
	    sizeof(od.cfg.claim_net));
	memcpy(od.cfg.claim_net_source, newcfg->claim_net_source,
	    sizeof(od.cfg.claim_net_source));
	memcpy(od.cfg.claim_net_refcount, newcfg->claim_net_refcount,
	    sizeof(od.cfg.claim_net_refcount));
	od.cfg.nclaim_net = newcfg->nclaim_net;
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

	/* Capability claims and integrity from mac_capability. */
	if (!od.test_mode)
		mac_capability_format_status(summary, sumlen, &off);
	else {
		BUF_APPEND(summary, sumlen, &off,
		    "INTEGRITY:\n  (test mode)\n");
		BUF_APPEND(summary, sumlen, &off,
		    "\nCLAIMS:\n  (test mode)\n");
	}

	/* Bootstrap status. */
	BUF_APPEND(summary, sumlen, &off, "\nSERVICED:\n");
	BUF_APPEND(summary, sumlen, &off, "  status: %s\n",
	    authority_proto_is_ready() ? "ready" : "not ready");
	if (bootstrap_pid() > 0)
		BUF_APPEND(summary, sumlen, &off, "  pid:    %jd\n",
		    (intmax_t)bootstrap_pid());

	reply->flags = (uint32_t)off;
}

int
cmd_shutdown(uid_t euid, struct ctl_reply *reply)
{

	/*
	 * CTL_OP_SHUTDOWN stops the authorityd daemon.  When authorityd is
	 * PID 1 there is no daemon to stop and no coherent "stop the
	 * capability world but stay multi-user" state, so reject it:
	 * whole-system lifecycle uses the CTL_OP_REBOOT/HALT/SINGLE/...
	 * ops instead.
	 */
	if (getpid() == 1) {
		reply->status = EPERM;
		syslog(LOG_WARNING,
		    "control: shutdown rejected: authorityd is PID 1");
		AUTHORITYD_PROBE_CTL_DENY(CTL_OP_SHUTDOWN, euid);
		return (0);
	}
	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: shutdown denied uid %u", euid);
		AUTHORITYD_PROBE_CTL_DENY(CTL_OP_SHUTDOWN, euid);
		return (0);
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: shutdown uid %u", euid);
	return (1);
}

/*
 * System lifecycle request (reboot/halt/single-user/reroot/...).  Valid
 * only when authorityd is PID 1; an ordinary daemon has no authority to
 * reboot the machine.  Records the request in od.lifecycle_request for
 * authority-init's event loop to translate into a state transition, and
 * returns 1 so control.c sets CTL_ACTION_LIFECYCLE.  This is the
 * authenticated replacement for init(8)'s signal ABI.
 */
int
cmd_lifecycle(uid_t euid, uint32_t op, struct ctl_reply *reply)
{

	/*
	 * MIGRATION (docs/capability-authority-model.md, phase P4): the getpid()==1
	 * and euid==0 gates below are transitional.  The end state authorizes by a
	 * presented lifecycle capability served by the spine (so it survives
	 * serviced's death); the capability is the authority, not the PID or uid.
	 * reboot(2) remains only as the kernel escape hatch.
	 */
	if (getpid() != 1) {
		reply->status = EPERM;
		syslog(LOG_WARNING,
		    "control: lifecycle op %u rejected: not PID 1", op);
		AUTHORITYD_PROBE_CTL_DENY(op, euid);
		return (0);
	}
	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: lifecycle op %u denied uid %u",
		    op, euid);
		AUTHORITYD_PROBE_CTL_DENY(op, euid);
		return (0);
	}

	/*
	 * Accept.  The opcode is not stashed in shared state here — it
	 * travels with the per-connection action (see CTL_ACTION_OP), so
	 * concurrent lifecycle requests cannot race on which op is
	 * applied.
	 */
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: lifecycle op %u uid %u", op, euid);
	return (1);
}

void
cmd_reload(uid_t euid, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	struct authorityd_config newcfg;
	size_t off;
	int claims_failed;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied uid %u", euid);
		AUTHORITYD_PROBE_CTL_DENY(CTL_OP_RELOAD, euid);
		return;
	}

	syslog(LOG_INFO, "control: reload uid %u", euid);
	AUTHORITYD_PROBE_RELOAD();

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
			claims_failed = mac_capability_reload_claims(&newcfg);
			if (claims_failed == -1)
				BUF_APPEND(summary, sumlen, &off,
				    "warning: some claim changes failed\n");
		}
		config_apply_claims(&newcfg);
	}

	/*
	 * The control socket is the supported administrative authority after
	 * Authority installs its signal shield.  Forward the authenticated reload
	 * to serviced just as the legacy SIGHUP compatibility path does.
	 */
	bootstrap_signal(SIGHUP);
	reply->status = CTL_STATUS_OK;
	reply->flags = (uint32_t)off;
}
