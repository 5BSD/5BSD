/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * rebootd — reboot and shutdown manager.
 *
 * Runs under serviced.  Receives a system gate token for reboot
 * from the Oracle, then exposes controlled reboot/shutdown to
 * authorized clients via the naming registry.
 *
 * On profiles where reboot is not gated (e.g., desktop, server),
 * this service starts but has no token — processes can reboot
 * directly without going through rebootd.
 */

#include <sys/param.h>
#include <sys/reboot.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include "rebootd_proto.h"

/* Only allow safe howto flags through. */
#define	REBOOT_ALLOWED_FLAGS	(RB_HALT | RB_POWEROFF | RB_REROOT)

static volatile sig_atomic_t quit;
static volatile sig_atomic_t shutdown_pending;

static void
handle_signal(int sig __unused)
{
	quit = 1;
}

static void
handle_reboot_op(const struct reboot_req *req, struct reboot_reply *reply,
    const char *client_label)
{
	int howto;

	howto = req->flags & REBOOT_ALLOWED_FLAGS;

	syslog(LOG_NOTICE, "reboot requested by %s (flags 0x%x)",
	    client_label, howto);

	/*
	 * Mark shutdown as pending before attempting reboot.
	 * reboot(2) does not return on success; if it fails,
	 * concurrent status queries will see PENDING until we clear it.
	 */
	shutdown_pending = 1;
	if (reboot(howto) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(0x%x): %m", howto);
		reply->status = REBOOT_STATUS_ERR;
	} else {
		/* Not reached. */
		reply->status = REBOOT_STATUS_OK;
	}
}

static void
handle_shutdown_op(struct reboot_reply *reply, const char *client_label)
{

	syslog(LOG_NOTICE, "shutdown requested by %s", client_label);

	shutdown_pending = 1;
	if (reboot(RB_HALT | RB_POWEROFF) == -1) {
		shutdown_pending = 0;
		syslog(LOG_ERR, "reboot(RB_HALT|RB_POWEROFF): %m");
		reply->status = REBOOT_STATUS_ERR;
	} else {
		reply->status = REBOOT_STATUS_OK;
	}
}

static void
handle_status_op(struct reboot_reply *reply)
{

	reply->status = shutdown_pending ?
	    REBOOT_STATUS_PENDING : REBOOT_STATUS_OK;
}

static void
handle_client(int client_fd, const char *client_label)
{
	struct reboot_req req;
	struct reboot_reply reply;
	ssize_t n;

	for (;;) {
		n = service_recv(client_fd, &req, sizeof(req), NULL);
		if (n <= 0)
			break;
		if ((size_t)n < sizeof(uint32_t))
			break;

		memset(&reply, 0, sizeof(reply));

		switch (req.op) {
		case REBOOT_OP_REBOOT:
			if ((size_t)n < sizeof(req))
				break;
			handle_reboot_op(&req, &reply, client_label);
			service_send(client_fd, &reply, sizeof(reply));
			break;

		case REBOOT_OP_SHUTDOWN:
			handle_shutdown_op(&reply, client_label);
			service_send(client_fd, &reply, sizeof(reply));
			break;

		case REBOOT_OP_STATUS:
			handle_status_op(&reply);
			service_send(client_fd, &reply, sizeof(reply));
			break;

		default:
			reply.status = REBOOT_STATUS_ERR;
			service_send(client_fd, &reply, sizeof(reply));
			break;
		}
	}

	close(client_fd);
}

int
main(void)
{
	char label[64];
	int client_fd;

	openlog("rebootd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if (service_init() == -1)
		errx(1, "service_init failed");
	if (service_register("org.5bsd.system.reboot") == -1)
		errx(1, "service_register failed");
	if (service_ready() == -1)
		errx(1, "service_ready failed");

	syslog(LOG_INFO, "started, registered as org.5bsd.system.reboot");

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	while (!quit) {
		client_fd = service_accept(label, sizeof(label));
		if (client_fd == -1) {
			if (quit)
				break;
			syslog(LOG_WARNING, "accept: %m");
			continue;
		}
		syslog(LOG_INFO, "client connected: %s", label);
		handle_client(client_fd, label);
	}

	syslog(LOG_INFO, "shutting down");
	closelog();
	return (0);
}
