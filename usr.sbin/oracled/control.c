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
 * getpeereid(), read request + optional payload, dispatch to
 * command handler, write reply, close.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_ctl.h"
#include "commands.h"

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

	(void)unlink(od.cfg.control_socket);

	memset(&un, 0, sizeof(un));
	un.sun_family = PF_LOCAL;
	strlcpy(un.sun_path, od.cfg.control_socket, sizeof(un.sun_path));

	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		syslog(LOG_ERR, "control bind %s: %m",
		    od.cfg.control_socket);
		close(fd);
		return (-1);
	}

	if (chmod(od.cfg.control_socket, od.cfg.control_socket_mode) == -1) {
		syslog(LOG_ERR, "control chmod %s: %m",
		    od.cfg.control_socket);
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}

	if (listen(fd, 5) == -1) {
		syslog(LOG_ERR, "control listen: %m");
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "control fcntl: %m");
		close(fd);
		(void)unlink(od.cfg.control_socket);
		return (-1);
	}

	syslog(LOG_INFO, "control socket %s", od.cfg.control_socket);
	return (fd);
}

void
teardown_control_socket(void)
{

	if (od.control_fd >= 0) {
		close(od.control_fd);
		od.control_fd = -1;
		(void)unlink(od.cfg.control_socket);
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
 * Read a payload string from the client fd.  Validates length,
 * reads the data, and null-terminates.  Returns 0 on success.
 */
static int
read_payload(int cfd, uint32_t datalen, char *buf, size_t bufsz,
    struct ctl_reply *reply)
{

	if (datalen == 0 || datalen >= bufsz) {
		reply->status = EINVAL;
		return (-1);
	}
	if (readn(cfd, buf, datalen) != 0) {
		reply->status = EIO;
		return (-1);
	}
	buf[datalen] = '\0';
	return (0);
}

/* ----------------------------------------------------------------
 * Connection dispatcher
 * ---------------------------------------------------------------- */

int
handle_control_connection(void)
{
	struct ctl_request req;
	struct ctl_reply reply;
	uid_t euid;
	gid_t egid;
	int cfd, action;
	char payload[CTL_MAX_PAYLOAD + 1];

	action = 0;

	cfd = accept(od.control_fd, NULL, NULL);
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
		cmd_status(uptime_usec(), &reply);
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
		if (read_payload(cfd, req.datalen, payload,
		    sizeof(payload), &reply) == 0)
			cmd_kldload(euid, payload, &reply);
		break;
	case CTL_OP_KLDUNLOAD:
		if (read_payload(cfd, req.datalen, payload,
		    sizeof(payload), &reply) == 0)
			cmd_kldunload(euid, payload, &reply);
		break;
	case CTL_OP_REBOOT:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		cmd_reboot(euid, req.flags, &reply);
		if (reply.status == CTL_STATUS_OK) {
			od.reboot_howto = req.flags;
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
