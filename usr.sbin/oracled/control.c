/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Control socket for oracled.
 *
 * Provides a unix domain socket at /var/run/oracled.sock for
 * administrative commands.  This is interim infrastructure — the
 * long-term plan replaces it with cap_rt pair channels when
 * oracled becomes the system init.
 *
 * Each client connection is one-shot: accept, authenticate via
 * getpeereid(), read request + payload, dispatch, write reply,
 * close.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <sys/linker.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_ctl.h"

int reboot_howto;

static struct timeval start_time;

static uint64_t
uptime_usec(void)
{
	struct timeval now, delta;

	gettimeofday(&now, NULL);
	timersub(&now, &start_time, &delta);
	return ((uint64_t)delta.tv_sec * 1000000 + delta.tv_usec);
}

int
setup_control_socket(void)
{
	struct sockaddr_un un;
	int fd;

	gettimeofday(&start_time, NULL);

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "control socket: %m");
		return (-1);
	}

	(void)unlink(ORACLED_CTL_SOCK);

	memset(&un, 0, sizeof(un));
	un.sun_family = PF_LOCAL;
	strlcpy(un.sun_path, ORACLED_CTL_SOCK, sizeof(un.sun_path));

	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		syslog(LOG_ERR, "control bind %s: %m", ORACLED_CTL_SOCK);
		close(fd);
		return (-1);
	}

	if (chmod(ORACLED_CTL_SOCK, 0700) == -1) {
		syslog(LOG_ERR, "control chmod %s: %m", ORACLED_CTL_SOCK);
		close(fd);
		(void)unlink(ORACLED_CTL_SOCK);
		return (-1);
	}

	if (listen(fd, 5) == -1) {
		syslog(LOG_ERR, "control listen: %m");
		close(fd);
		(void)unlink(ORACLED_CTL_SOCK);
		return (-1);
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "control fcntl: %m");
		close(fd);
		(void)unlink(ORACLED_CTL_SOCK);
		return (-1);
	}

	syslog(LOG_INFO, "control socket %s", ORACLED_CTL_SOCK);
	return (fd);
}

void
teardown_control_socket(void)
{

	if (control_fd >= 0) {
		close(control_fd);
		control_fd = -1;
		(void)unlink(ORACLED_CTL_SOCK);
	}
}

/*
 * Read exactly len bytes from fd with a timeout.  Returns 0 on
 * success, -1 on short read, error, or timeout.
 */
static int
readn(int fd, void *buf, size_t len)
{
	struct timeval tv;
	ssize_t n;
	size_t off;

	/* 5-second timeout prevents a hung client from blocking the
	 * event loop.  Set once — persists for the fd's lifetime. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	for (off = 0; off < len; ) {
		n = read(fd, (char *)buf + off, len - off);
		if (n <= 0)
			return (-1);
		off += n;
	}
	return (0);
}

/*
 * Require root.  Returns 0 if authorized, fills reply and returns
 * -1 if not.
 */
static int
require_root(uid_t euid, const char *op, struct ctl_reply *reply)
{

	if (euid == 0)
		return (0);
	reply->status = EPERM;
	syslog(LOG_WARNING, "control: %s denied for uid %u", op, euid);
	return (-1);
}

/* ----------------------------------------------------------------
 * Command handlers
 * ---------------------------------------------------------------- */

static void
cmd_status(struct ctl_reply *reply)
{

	reply->status = CTL_STATUS_OK;
	reply->uptime_usec = uptime_usec();
}

static int
cmd_shutdown(uid_t euid, struct ctl_reply *reply)
{

	if (require_root(euid, "shutdown", reply) != 0)
		return (0);
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: shutdown by uid %u", euid);
	return (1);
}

static void
cmd_reload(uid_t euid, struct ctl_reply *reply)
{

	if (require_root(euid, "reload", reply) != 0)
		return;
	reply->status = CTL_STATUS_OK;
	syslog(LOG_INFO, "control: reload by uid %u", euid);
}

static void
cmd_kldload(uid_t euid, int cfd, uint32_t datalen, struct ctl_reply *reply)
{
	char name[CTL_MAX_PAYLOAD + 1];
	int id;

	if (require_root(euid, "kldload", reply) != 0)
		return;
	if (datalen == 0 || datalen > CTL_MAX_PAYLOAD) {
		reply->status = EINVAL;
		return;
	}

	if (readn(cfd, name, datalen) != 0) {
		reply->status = EIO;
		return;
	}
	name[datalen] = '\0';

	syslog(LOG_INFO, "control: kldload \"%s\" by uid %u", name, euid);

	id = kldload(name);
	if (id == -1) {
		reply->status = errno;
		syslog(LOG_WARNING, "kldload \"%s\": %m", name);
	} else {
		reply->status = CTL_STATUS_OK;
		reply->flags = id;	/* return module id */
		syslog(LOG_INFO, "kldload \"%s\": id %d", name, id);
	}
}

static void
cmd_kldunload(uid_t euid, int cfd, uint32_t datalen, struct ctl_reply *reply)
{
	char name[CTL_MAX_PAYLOAD + 1];
	int id;

	if (require_root(euid, "kldunload", reply) != 0)
		return;
	if (datalen == 0 || datalen > CTL_MAX_PAYLOAD) {
		reply->status = EINVAL;
		return;
	}

	if (readn(cfd, name, datalen) != 0) {
		reply->status = EIO;
		return;
	}
	name[datalen] = '\0';

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

static void
cmd_reboot(uid_t euid, uint32_t howto, struct ctl_reply *reply)
{

	if (require_root(euid, "reboot", reply) != 0)
		return;

	syslog(LOG_INFO, "control: reboot (howto 0x%x) by uid %u",
	    howto, euid);
	reply->status = CTL_STATUS_OK;

	/*
	 * Reply first, then reboot.  The client receives the ack
	 * before the system goes down.
	 */
}

/* ----------------------------------------------------------------
 * Connection dispatcher
 * ---------------------------------------------------------------- */

/*
 * Handle a single client connection.  Returns a bitmask:
 *   CTL_ACTION_SHUTDOWN — caller should initiate graceful shutdown
 *   CTL_ACTION_REBOOT   — caller should reboot the system
 */
int
handle_control_connection(void)
{
	struct ctl_request req;
	struct ctl_reply reply;
	uid_t euid;
	gid_t egid;
	int cfd, action;

	action = 0;

	cfd = accept(control_fd, NULL, NULL);
	if (cfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "control accept: %m");
		return (0);
	}

	if (getpeereid(cfd, &euid, &egid) != 0) {
		syslog(LOG_WARNING, "control getpeereid: %m");
		close(cfd);
		return (0);
	}

	if (readn(cfd, &req, sizeof(req)) != 0) {
		syslog(LOG_WARNING, "control read: short");
		close(cfd);
		return (0);
	}

	memset(&reply, 0, sizeof(reply));

	if (req.version != CTL_VERSION) {
		reply.status = ENOTSUP;
		goto out;
	}

	switch (req.op) {
	case CTL_OP_STATUS:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		cmd_status(&reply);
		break;
	case CTL_OP_SHUTDOWN:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		if (cmd_shutdown(euid, &reply))
			action = CTL_ACTION_SHUTDOWN;
		break;
	case CTL_OP_RELOAD:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		cmd_reload(euid, &reply);
		break;
	case CTL_OP_KLDLOAD:
		cmd_kldload(euid, cfd, req.datalen, &reply);
		break;
	case CTL_OP_KLDUNLOAD:
		cmd_kldunload(euid, cfd, req.datalen, &reply);
		break;
	case CTL_OP_REBOOT:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		cmd_reboot(euid, req.flags, &reply);
		if (reply.status == CTL_STATUS_OK) {
			reboot_howto = req.flags;
			action = CTL_ACTION_REBOOT;
		}
		break;
	default:
		reply.status = ENOTSUP;
		break;
	}

out:
	(void)write(cfd, &reply, sizeof(reply));
	close(cfd);
	return (action);
}
