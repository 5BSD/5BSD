/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/reboot.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <capability.h>
#include "rebootd_proto.h"

#define	REBOOT_ALLOWED_FLAGS	(RB_HALT | RB_POWEROFF | RB_REROOT)
#define	REBOOT_SERVICE_NAME	"org.5bsd.system.reboot"
#define	REBOOT_ALLOW_FILE	"/etc/rebootd.allow"
#define	REBOOT_CLIENT_TIMEOUT	30

static volatile sig_atomic_t shutdown_pending;

static int
send_reply(int fd, int32_t status)
{
	struct reboot_reply reply;

	memset(&reply, 0, sizeof(reply));
	reply.status = status;
	return (cap_daemon_send(fd, &reply, sizeof(reply)));
}

static void
handle_reboot_op(const struct reboot_req *req, struct reboot_reply *reply,
    const char *label)
{
	int howto;

	if ((req->flags & ~REBOOT_ALLOWED_FLAGS) != 0) {
		syslog(LOG_WARNING, "reboot denied for %s: invalid flags 0x%x",
		    label, req->flags);
		reply->status = REBOOT_STATUS_ERR;
		return;
	}

	howto = req->flags;
	syslog(LOG_NOTICE, "reboot requested by %s (flags 0x%x)",
	    label, howto);

	shutdown_pending = 1;
	if (reboot(howto) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(0x%x): %m", howto);
		reply->status = REBOOT_STATUS_ERR;
	} else
		reply->status = REBOOT_STATUS_OK;
}

static void
handle_shutdown_op(struct reboot_reply *reply, const char *label)
{

	syslog(LOG_NOTICE, "shutdown requested by %s", label);
	shutdown_pending = 1;
	if (reboot(RB_HALT | RB_POWEROFF) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(RB_HALT|RB_POWEROFF): %m");
		reply->status = REBOOT_STATUS_ERR;
	} else
		reply->status = REBOOT_STATUS_OK;
}

static int
handle_client(int fd, const char *label, void *arg __unused)
{
	struct reboot_req req;
	struct reboot_reply reply;
	ssize_t n;
	int allowed;

	for (;;) {
		n = cap_daemon_recv(fd, &req, sizeof(req),
		    REBOOT_CLIENT_TIMEOUT);
		if (n <= 0)
			break;
		if ((size_t)n != sizeof(req)) {
			(void)send_reply(fd, REBOOT_STATUS_ERR);
			continue;
		}

		memset(&reply, 0, sizeof(reply));
		switch (req.op) {
		case REBOOT_OP_REBOOT:
			allowed = cap_daemon_label_allowed(REBOOT_ALLOW_FILE,
			    label);
			if (!allowed) {
				syslog(LOG_WARNING, "reboot denied for %s by %s",
				    label, REBOOT_ALLOW_FILE);
				(void)send_reply(fd, REBOOT_STATUS_PERM);
				break;
			}
			handle_reboot_op(&req, &reply, label);
			(void)cap_daemon_send(fd, &reply, sizeof(reply));
			break;
		case REBOOT_OP_SHUTDOWN:
			allowed = cap_daemon_label_allowed(REBOOT_ALLOW_FILE,
			    label);
			if (!allowed) {
				syslog(LOG_WARNING,
				    "shutdown denied for %s by %s",
				    label, REBOOT_ALLOW_FILE);
				(void)send_reply(fd, REBOOT_STATUS_PERM);
				break;
			}
			handle_shutdown_op(&reply, label);
			(void)cap_daemon_send(fd, &reply, sizeof(reply));
			break;
		case REBOOT_OP_STATUS:
			reply.status = shutdown_pending ?
			    REBOOT_STATUS_PENDING : REBOOT_STATUS_OK;
			(void)cap_daemon_send(fd, &reply, sizeof(reply));
			break;
		default:
			(void)send_reply(fd, REBOOT_STATUS_ERR);
			break;
		}
	}

	return (0);
}

int
main(void)
{
	struct cap_daemon_config cfg;

	openlog("rebootd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	memset(&cfg, 0, sizeof(cfg));
	cfg.service_name = REBOOT_SERVICE_NAME;
	cfg.handler = handle_client;
	cfg.client_timeout = REBOOT_CLIENT_TIMEOUT;

	if (cap_daemon_run(&cfg) == -1) {
		syslog(LOG_ERR, "cap_daemon_run: %m");
		closelog();
		return (1);
	}

	syslog(LOG_INFO, "shutting down");
	closelog();
	return (0);
}
