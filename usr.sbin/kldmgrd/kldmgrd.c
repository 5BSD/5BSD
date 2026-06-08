/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * kldmgrd — kernel module loading manager.
 *
 * Runs under serviced.  Receives system gate tokens for kldload
 * and kldunload from the Oracle, then exposes controlled module
 * loading to authorized clients via the naming registry.
 *
 * On profiles where kldload/kldunload are not gated (e.g., desktop),
 * this service starts but has no tokens — clients can load modules
 * directly without going through kldmgrd.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include "kldmgrd_proto.h"

static volatile sig_atomic_t quit;

static void
handle_signal(int sig __unused)
{
	quit = 1;
}

static void
handle_load(const struct kldmgr_req *req, struct kldmgr_reply *reply)
{
	int id;

	if (req->name[0] == '\0') {
		reply->status = KLDMGR_STATUS_ERR;
		reply->id = -1;
		return;
	}

	id = kldload(req->name);
	if (id == -1) {
		syslog(LOG_WARNING, "kldload %s: %m", req->name);
		reply->status = (errno == ENOENT) ?
		    KLDMGR_STATUS_NOTFOUND : KLDMGR_STATUS_ERR;
		reply->id = -1;
	} else {
		syslog(LOG_INFO, "loaded %s (id %d)", req->name, id);
		reply->status = KLDMGR_STATUS_OK;
		reply->id = id;
	}
}

static void
handle_unload(const struct kldmgr_req *req, struct kldmgr_reply *reply)
{
	int id;

	if (req->name[0] == '\0') {
		reply->status = KLDMGR_STATUS_ERR;
		reply->id = -1;
		return;
	}

	id = kldfind(req->name);
	if (id == -1) {
		reply->status = KLDMGR_STATUS_NOTFOUND;
		reply->id = -1;
		return;
	}

	if (kldunload(id) == -1) {
		syslog(LOG_WARNING, "kldunload %s (id %d): %m", req->name, id);
		reply->status = KLDMGR_STATUS_ERR;
		reply->id = -1;
	} else {
		syslog(LOG_INFO, "unloaded %s (id %d)", req->name, id);
		reply->status = KLDMGR_STATUS_OK;
		reply->id = id;
	}
}

static int
handle_list(int client_fd)
{
	char buf[sizeof(struct kldmgr_list_reply) +
	    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
	struct kldmgr_list_reply *reply = (void *)buf;
	struct kld_file_stat stat;
	int id;
	uint32_t count;

	memset(buf, 0, sizeof(buf));
	reply->status = KLDMGR_STATUS_OK;
	count = 0;

	for (id = kldnext(0); id > 0 && count < KLDMGR_LIST_MAX;
	    id = kldnext(id)) {
		stat.version = sizeof(stat);
		if (kldstat(id, &stat) == -1)
			continue;
		reply->entries[count].id = id;
		strlcpy(reply->entries[count].name, stat.name,
		    KLDMGR_NAME_MAX);
		count++;
	}
	reply->count = count;

	return (service_send(client_fd, buf,
	    sizeof(*reply) + count * sizeof(struct kldmgr_list_entry)));
}

static void
handle_client(int client_fd)
{
	struct kldmgr_req req;
	struct kldmgr_reply reply;
	ssize_t n;

	for (;;) {
		n = service_recv(client_fd, &req, sizeof(req), NULL);
		if (n <= 0)
			break;
		if ((size_t)n < sizeof(uint32_t))
			break;

		memset(&reply, 0, sizeof(reply));

		switch (req.op) {
		case KLDMGR_OP_LOAD:
			if ((size_t)n < sizeof(req))
				break;
			handle_load(&req, &reply);
			service_send(client_fd, &reply, sizeof(reply));
			break;

		case KLDMGR_OP_UNLOAD:
			if ((size_t)n < sizeof(req))
				break;
			handle_unload(&req, &reply);
			service_send(client_fd, &reply, sizeof(reply));
			break;

		case KLDMGR_OP_LIST:
			handle_list(client_fd);
			break;

		default:
			reply.status = KLDMGR_STATUS_ERR;
			reply.id = -1;
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

	openlog("kldmgrd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if (service_init() == -1)
		errx(1, "service_init failed");
	if (service_register("org.5bsd.system.kldmgr") == -1)
		errx(1, "service_register failed");
	if (service_ready() == -1)
		errx(1, "service_ready failed");

	syslog(LOG_INFO, "started, registered as org.5bsd.system.kldmgr");

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
		handle_client(client_fd);
	}

	syslog(LOG_INFO, "shutting down");
	closelog();
	return (0);
}
