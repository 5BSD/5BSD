/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Control socket for oracled.
 *
 * Provides a unix domain socket at /var/run/oracled.sock for
 * administrative commands (status, shutdown, reload).  System
 * operations (kldload, reboot) are here temporarily and will
 * move to separate service programs in Phase 2.
 *
 * Each client connection is one-shot: accept, authenticate via
 * getpeereid(), read request + optional payload, dispatch to
 * command handler, write reply, close.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "oracled.h"
#include "oracled_ctl.h"
#include "commands.h"
#include "probes.h"

/* Module-private state. */
static int control_sock = -1;
static struct timespec start_time;

static uint64_t
uptime_usec(void)
{
	struct timespec now;
	uint64_t sec;
	long nsec;

	clock_gettime(CLOCK_MONOTONIC, &now);
	sec = now.tv_sec - start_time.tv_sec;
	nsec = now.tv_nsec - start_time.tv_nsec;
	if (nsec < 0) {
		sec--;
		nsec += 1000000000L;
	}
	return (sec * 1000000 + nsec / 1000);
}

int
ctl_setup(void)
{
	struct sockaddr_un un;
	mode_t old_umask;
	int fd;

	clock_gettime(CLOCK_MONOTONIC, &start_time);

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "control socket: %m");
		return (-1);
	}

	if (strlen(od.cfg.control_socket) >= sizeof(un.sun_path)) {
		syslog(LOG_ERR, "control socket path too long: %s",
		    od.cfg.control_socket);
		close(fd);
		return (-1);
	}

	(void)unlink(od.cfg.control_socket);

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, od.cfg.control_socket, sizeof(un.sun_path));

	old_umask = umask(0077);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		syslog(LOG_ERR, "control bind %s: %m",
		    od.cfg.control_socket);
		(void)umask(old_umask);
		close(fd);
		return (-1);
	}
	(void)umask(old_umask);

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

	control_sock = fd;
	syslog(LOG_INFO, "control socket %s", od.cfg.control_socket);
	return (0);
}

void
ctl_teardown(void)
{

	if (control_sock >= 0) {
		close(control_sock);
		control_sock = -1;
		(void)unlink(od.cfg.control_socket);
	}
}

int
ctl_fd(void)
{

	return (control_sock);
}

/*
 * Read exactly len bytes from fd with a timeout.
 */
static int
readn(int fd, void *buf, size_t len)
{
	struct timeval tv;
	ssize_t n;
	size_t off;

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	for (off = 0; off < len; ) {
		n = read(fd, (char *)buf + off, len - off);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			return (-1);
		off += n;
	}
	return (0);
}

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

	if (strchr(buf, '/') != NULL) {
		reply->status = EINVAL;
		syslog(LOG_WARNING, "control: payload contains '/'");
		return (-1);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * Connection dispatcher
 *
 * Returns a CTL_ACTION_* bitmask.  If CTL_ACTION_REBOOT is set,
 * *reboot_howto is filled with the requested flags.
 * ---------------------------------------------------------------- */

int
ctl_handle(int *reboot_howto)
{
	struct ctl_request req;
	struct ctl_reply reply;
	uid_t euid;
	gid_t egid;
	int cfd, action;
	char payload[CTL_MAX_PAYLOAD + 1];
	char summary[CTL_SUMMARY_MAX];

	action = CTL_ACTION_NONE;
	summary[0] = '\0';

	cfd = accept4(control_sock, NULL, NULL, SOCK_CLOEXEC);
	if (cfd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			syslog(LOG_WARNING, "control accept: %m");
		return (CTL_ACTION_NONE);
	}

	if (getpeereid(cfd, &euid, &egid) != 0) {
		syslog(LOG_WARNING, "control getpeereid: %m");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	ORACLED_PROBE_CTL_ACCEPT(euid);

	if (readn(cfd, &req, sizeof(req)) != 0) {
		syslog(LOG_WARNING, "control read: short");
		close(cfd);
		return (CTL_ACTION_NONE);
	}

	memset(&reply, 0, sizeof(reply));

	if (req.version != CTL_VERSION) {
		reply.status = ENOTSUP;
		goto out;
	}

	ORACLED_PROBE_CTL_CMD(req.op, euid);

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
		if (cmd_reload(euid, &reply))
			action = CTL_ACTION_RELOAD;
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
			*reboot_howto = req.flags;
			action = CTL_ACTION_REBOOT;
		}
		break;
	case CTL_OP_CHECK:
		if (read_payload(cfd, req.datalen, payload,
		    sizeof(payload), &reply) == 0)
			cmd_check(euid, payload, &reply,
			    summary, sizeof(summary));
		break;
	case CTL_OP_LOAD:
		if (read_payload(cfd, req.datalen, payload,
		    sizeof(payload), &reply) == 0)
			cmd_load(euid, payload, event_kq, &reply,
			    summary, sizeof(summary));
		break;
	case CTL_OP_SERVICES:
		if (req.datalen != 0) {
			reply.status = EINVAL;
			break;
		}
		cmd_services(&reply, summary, sizeof(summary));
		break;
	default:
		reply.status = ENOTSUP;
		break;
	}

out:
	(void)write(cfd, &reply, sizeof(reply));
	/* Send summary text for opcodes that use it. */
	if ((req.op == CTL_OP_CHECK || req.op == CTL_OP_LOAD ||
	    req.op == CTL_OP_SERVICES) && reply.flags > 0)
		(void)write(cfd, summary, reply.flags);
	close(cfd);
	return (action);
}
