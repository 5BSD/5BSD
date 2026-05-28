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
#include <syslog.h>

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

void
cmd_reload(uid_t euid, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied uid %u", euid);
		return;
	}
	/* TODO: implement actual config reload. */
	reply->status = ENOTSUP;
	syslog(LOG_INFO, "control: reload not yet implemented");
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
