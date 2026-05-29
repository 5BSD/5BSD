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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "oracled.h"
#include "oracled_ctl.h"
#include "commands.h"

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
		return (0);
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: shutdown uid %u", euid);
	return (1);
}

int
cmd_reload(uid_t euid, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied uid %u", euid);
		return (0);
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: reload uid %u", euid);
	return (1);
}

void
cmd_check(uid_t euid, const char *filename, struct ctl_reply *reply,
    char *summary, size_t sumlen)
{
	char path[PATH_MAX];

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: check denied uid %u", euid);
		return;
	}

	snprintf(path, sizeof(path), "%s/%s", od.cfg.manifest_dir, filename);

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
		return;
	}

	snprintf(path, sizeof(path), "%s/%s", od.cfg.manifest_dir, filename);

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
		return;
	}

	syslog(LOG_INFO, "control: reboot howto=0x%x uid %u", howto, euid);
	reply->status = CTL_STATUS_OK;
}
