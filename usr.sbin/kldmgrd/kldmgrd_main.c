/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <capability.h>
#include "kldmgrd_proto.h"

#define	KLDMGR_SERVICE_NAME	"org.5bsd.system.kldmgr"
#define	KLDMGR_ALLOW_FILE	"/etc/kldmgrd.allow"
#define	KLDMGR_CLIENT_TIMEOUT	30

static int
module_name_valid(const char *name, size_t len)
{
	size_t i, nlen;

	nlen = strnlen(name, len);
	if (nlen == 0 || nlen >= len)
		return (0);
	for (i = 0; i < nlen; i++) {
		if ((name[i] >= 'a' && name[i] <= 'z') ||
		    (name[i] >= 'A' && name[i] <= 'Z') ||
		    (name[i] >= '0' && name[i] <= '9') ||
		    name[i] == '_' || name[i] == '-' || name[i] == '.')
			continue;
		return (0);
	}
	return (1);
}

static int
send_reply(int fd, int32_t status, int32_t id)
{
	struct kldmgr_reply reply;

	memset(&reply, 0, sizeof(reply));
	reply.status = status;
	reply.id = id;
	return (cap_daemon_send(fd, &reply, sizeof(reply)));
}

static void
handle_load(const struct kldmgr_req *req, struct kldmgr_reply *reply)
{
	int id;

	reply->id = -1;
	if (!module_name_valid(req->name, sizeof(req->name))) {
		reply->status = KLDMGR_STATUS_ERR;
		return;
	}

	id = kldload(req->name);
	if (id == -1) {
		syslog(LOG_WARNING, "kldload %s: %m", req->name);
		reply->status = (errno == ENOENT) ?
		    KLDMGR_STATUS_NOTFOUND : KLDMGR_STATUS_ERR;
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

	reply->id = -1;
	if (!module_name_valid(req->name, sizeof(req->name))) {
		reply->status = KLDMGR_STATUS_ERR;
		return;
	}

	id = kldfind(req->name);
	if (id == -1) {
		reply->status = KLDMGR_STATUS_NOTFOUND;
		return;
	}

	if (kldunload(id) == -1) {
		syslog(LOG_WARNING, "kldunload %s (id %d): %m",
		    req->name, id);
		reply->status = KLDMGR_STATUS_ERR;
	} else {
		syslog(LOG_INFO, "unloaded %s (id %d)", req->name, id);
		reply->status = KLDMGR_STATUS_OK;
		reply->id = id;
	}
}

static int
handle_list(int fd)
{
	char buf[sizeof(struct kldmgr_list_reply) +
	    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
	struct kldmgr_list_reply *reply;
	struct kld_file_stat stat;
	uint32_t count;
	int id;

	memset(buf, 0, sizeof(buf));
	reply = (void *)buf;
	reply->status = KLDMGR_STATUS_OK;

	count = 0;
	for (id = kldnext(0); id > 0 && count < KLDMGR_LIST_MAX;
	    id = kldnext(id)) {
		stat.version = sizeof(stat);
		if (kldstat(id, &stat) == -1)
			continue;
		reply->entries[count].id = id;
		strlcpy(reply->entries[count].name, stat.name,
		    sizeof(reply->entries[count].name));
		count++;
	}
	reply->count = count;

	return (cap_daemon_send(fd, buf,
	    sizeof(*reply) + count * sizeof(struct kldmgr_list_entry)));
}

static int
handle_client(int fd, const char *label, void *arg __unused)
{
	struct kldmgr_req req;
	struct kldmgr_reply reply;
	ssize_t n;

	if (!cap_daemon_label_allowed(KLDMGR_ALLOW_FILE, label)) {
		syslog(LOG_WARNING, "client %s denied by %s",
		    label, KLDMGR_ALLOW_FILE);
		return (send_reply(fd, KLDMGR_STATUS_PERM, -1));
	}

	for (;;) {
		n = cap_daemon_recv(fd, &req, sizeof(req), KLDMGR_CLIENT_TIMEOUT);
		if (n <= 0)
			break;
		if ((size_t)n < sizeof(req.op)) {
			(void)send_reply(fd, KLDMGR_STATUS_ERR, -1);
			continue;
		}

		switch (req.op) {
		case KLDMGR_OP_LOAD:
			if ((size_t)n != sizeof(req)) {
				(void)send_reply(fd, KLDMGR_STATUS_ERR, -1);
				break;
			}
			memset(&reply, 0, sizeof(reply));
			handle_load(&req, &reply);
			(void)cap_daemon_send(fd, &reply, sizeof(reply));
			break;
		case KLDMGR_OP_UNLOAD:
			if ((size_t)n != sizeof(req)) {
				(void)send_reply(fd, KLDMGR_STATUS_ERR, -1);
				break;
			}
			memset(&reply, 0, sizeof(reply));
			handle_unload(&req, &reply);
			(void)cap_daemon_send(fd, &reply, sizeof(reply));
			break;
		case KLDMGR_OP_LIST:
			if ((size_t)n != sizeof(req)) {
				(void)send_reply(fd, KLDMGR_STATUS_ERR, -1);
				break;
			}
			(void)handle_list(fd);
			break;
		default:
			(void)send_reply(fd, KLDMGR_STATUS_ERR, -1);
			break;
		}
	}

	return (0);
}

int
main(void)
{
	struct cap_daemon_config cfg;

	openlog("kldmgrd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	memset(&cfg, 0, sizeof(cfg));
	cfg.service_name = KLDMGR_SERVICE_NAME;
	cfg.handler = handle_client;
	cfg.client_timeout = KLDMGR_CLIENT_TIMEOUT;

	if (cap_daemon_run(&cfg) == -1) {
		syslog(LOG_ERR, "cap_daemon_run: %m");
		closelog();
		return (1);
	}

	syslog(LOG_INFO, "shutting down");
	closelog();
	return (0);
}
