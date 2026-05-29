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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "oracled.h"
#include "oracled_ctl.h"
#include "commands.h"
#include "probes.h"

/*
 * Resolve a manifest filename to a safe absolute path within
 * the manifest directory.  Returns 0 on success with the path
 * written to buf, or -1 if the resolved path escapes the
 * manifest directory (symlink, .., etc.).
 */
static int
resolve_manifest_path(const char *filename, char *buf, size_t bufsz)
{
	char constructed[PATH_MAX], resolved[PATH_MAX];
	size_t dirlen;
	int n;

	n = snprintf(constructed, sizeof(constructed), "%s/%s",
	    od.cfg.manifest_dir, filename);
	if (n < 0 || (size_t)n >= sizeof(constructed))
		return (-1);

	if (realpath(constructed, resolved) == NULL)
		return (-1);

	/* Verify the resolved path is within manifest_dir. */
	dirlen = strlen(od.cfg.manifest_dir);
	if (strncmp(resolved, od.cfg.manifest_dir, dirlen) != 0 ||
	    (resolved[dirlen] != '/' && resolved[dirlen] != '\0'))
		return (-1);

	strlcpy(buf, resolved, bufsz);
	return (0);
}

void
cmd_status(uint64_t uptime, struct ctl_reply *reply)
{

	reply->status = CTL_STATUS_OK;
	reply->uptime_usec = uptime;
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
cmd_reload(uid_t euid, int kq, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_RELOAD, euid);
		return;
	}

	syslog(LOG_INFO, "control: reload uid %u", euid);

	if (supervisor_reload(kq, summary, sumlen) == -1)
		reply->status = EIO;
	else
		reply->status = CTL_STATUS_OK;
	reply->flags = (uint32_t)strlen(summary);
}

void
cmd_check(uid_t euid, const char *filename, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	char path[PATH_MAX];

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: check denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_CHECK, euid);
		return;
	}

	if (resolve_manifest_path(filename, path, sizeof(path)) == -1) {
		reply->status = EINVAL;
		snprintf(summary, sumlen, "error: invalid manifest path");
		reply->flags = (uint32_t)strlen(summary);
		syslog(LOG_WARNING, "control: check \"%s\": path rejected",
		    filename);
		return;
	}

	if (supervisor_check_manifest(path, summary, sumlen) == -1) {
		reply->status = EINVAL;
		syslog(LOG_INFO, "control: check \"%s\": %s", filename,
		    summary);
	} else {
		reply->status = CTL_STATUS_OK;
		syslog(LOG_INFO, "control: check \"%s\": OK", filename);
	}
	reply->flags = (uint32_t)strlen(summary);
}

void
cmd_load(uid_t euid, const char *filename, int kq, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	char path[PATH_MAX];

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: load denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_LOAD, euid);
		return;
	}

	if (resolve_manifest_path(filename, path, sizeof(path)) == -1) {
		reply->status = EINVAL;
		snprintf(summary, sumlen, "error: invalid manifest path");
		reply->flags = (uint32_t)strlen(summary);
		syslog(LOG_WARNING, "control: load \"%s\": path rejected",
		    filename);
		return;
	}

	if (supervisor_load_manifest(path, kq, summary, sumlen) == -1) {
		reply->status = EINVAL;
		syslog(LOG_WARNING, "control: load \"%s\": %s", filename,
		    summary);
	} else {
		reply->status = CTL_STATUS_OK;
		syslog(LOG_INFO, "control: load \"%s\": OK", filename);
	}
	reply->flags = (uint32_t)strlen(summary);
}

void
cmd_services(struct ctl_reply *reply, char *summary, size_t sumlen)
{
	static const char *state_names[] = {
		"stopped", "starting", "running", "stopping"
	};
	struct timespec now;
	size_t off, rem;
	unsigned i;
	int n;

	if (sumlen == 0) {
		reply->status = CTL_STATUS_OK;
		reply->flags = 0;
		return;
	}

#define	SVC_APPEND(...)	do {					\
	rem = (off < sumlen) ? sumlen - off : 0;		\
	n = snprintf(summary + off, rem, __VA_ARGS__);		\
	if (n > 0) off += (size_t)n;				\
	if (off >= sumlen) off = sumlen - 1;			\
} while (0)

	clock_gettime(CLOCK_MONOTONIC, &now);

	off = 0;
	if (od.services == NULL || od.nservices == 0) {
		SVC_APPEND("no services loaded\n");
	} else {
		for (i = 0; i < od.nservices; i++) {
			struct svc_runtime *svc = &od.services[i];
			const char *state;

			if ((unsigned)svc->state < nitems(state_names))
				state = state_names[svc->state];
			else
				state = "unknown";

			SVC_APPEND("%-20s %-8s", svc->manifest.label, state);

			if (svc->state == SVC_STATE_RUNNING ||
			    svc->state == SVC_STATE_STARTING) {
				long up = now.tv_sec - svc->last_start.tv_sec;
				if (svc->last_start.tv_sec > 0)
					SVC_APPEND(" pid %-6jd up %lds",
					    (intmax_t)svc->pid, up);
				else
					SVC_APPEND(" pid %-6jd",
					    (intmax_t)svc->pid);
			}

			SVC_APPEND(" restart=%s",
			    svc->manifest.restart == SVC_RESTART_ALWAYS ?
			    "always" :
			    svc->manifest.restart == SVC_RESTART_ON_FAILURE ?
			    "on-failure" : "never");

			if (svc->restart_count > 0)
				SVC_APPEND(" restarts=%u",
				    svc->restart_count);

			SVC_APPEND("\n");
		}
	}

#undef SVC_APPEND

	reply->status = CTL_STATUS_OK;
	reply->flags = (uint32_t)off;
}

void
cmd_kldload(uid_t euid, const char *name, struct ctl_reply *reply)
{
	int id;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: kldload denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_KLDLOAD, euid);
		return;
	}

	id = kldload(name);
	if (id == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "control: kldload \"%s\": %m", name);
	} else {
		reply->status = CTL_STATUS_OK;
		reply->flags = id;
		syslog(LOG_INFO, "control: kldload \"%s\" id %d uid %u",
		    name, id, euid);
	}
}

void
cmd_kldunload(uid_t euid, const char *name, struct ctl_reply *reply)
{
	int id;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: kldunload denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_KLDUNLOAD, euid);
		return;
	}

	id = kldfind(name);
	if (id == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "control: kldunload \"%s\": %m", name);
		return;
	}

	if (kldunload(id) == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "control: kldunload \"%s\" id %d: %m",
		    name, id);
	} else {
		reply->status = CTL_STATUS_OK;
		syslog(LOG_INFO, "control: kldunload \"%s\" uid %u",
		    name, euid);
	}
}

void
cmd_reboot(uid_t euid, uint32_t howto, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reboot denied uid %u", euid);
		ORACLED_PROBE_CTL_DENY(CTL_OP_REBOOT, euid);
		return;
	}

	/* Only allow clean reboot (0) and poweroff (RB_POWEROFF). */
	if (howto != 0 && howto != RB_POWEROFF) {
		reply->status = EINVAL;
		syslog(LOG_WARNING, "control: reboot rejected howto=0x%x "
		    "uid %u", howto, euid);
		return;
	}

	syslog(LOG_INFO, "control: reboot howto=0x%x uid %u", howto, euid);
	reply->status = CTL_STATUS_OK;
}
