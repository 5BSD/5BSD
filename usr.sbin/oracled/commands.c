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
#include <unistd.h>

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
		syslog(LOG_WARNING, "control: shutdown denied for uid %u",
		    euid);
		return (0);
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: shutdown by uid %u", euid);
	return (1);
}

void
cmd_reload(uid_t euid, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reload denied for uid %u",
		    euid);
		return;
	}
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: reload by uid %u", euid);
}

void
cmd_kldload(uid_t euid, const char *name, struct ctl_reply *reply)
{
	int id;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: kldload denied for uid %u",
		    euid);
		return;
	}

	syslog(LOG_INFO, "control: kldload \"%s\" by uid %u", name, euid);

	id = kldload(name);
	if (id == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "kldload \"%s\": %m", name);
	} else {
		reply->status = CTL_STATUS_OK;
		reply->flags = id;
		syslog(LOG_INFO, "kldload \"%s\": id %d", name, id);
	}
}

void
cmd_kldunload(uid_t euid, const char *name, struct ctl_reply *reply)
{
	int id;

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: kldunload denied for uid %u",
		    euid);
		return;
	}

	syslog(LOG_INFO, "control: kldunload \"%s\" by uid %u", name, euid);

	id = kldfind(name);
	if (id == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "kldfind \"%s\": %m", name);
		return;
	}

	if (kldunload(id) == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "kldunload \"%s\" (id %d): %m", name, id);
	} else {
		reply->status = CTL_STATUS_OK;
		syslog(LOG_INFO, "kldunload \"%s\": done", name);
	}
}

void
cmd_reboot(uid_t euid, uint32_t howto, struct ctl_reply *reply)
{

	if (euid != 0) {
		reply->status = EPERM;
		syslog(LOG_WARNING, "control: reboot denied for uid %u",
		    euid);
		return;
	}

	syslog(LOG_INFO, "control: reboot (howto 0x%x) by uid %u",
	    howto, euid);
	reply->status = CTL_STATUS_OK;
}
