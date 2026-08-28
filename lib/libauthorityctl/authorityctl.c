/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client library for the authorityd(8) control socket.
 *
 * The caller opens a connection with authorityctl_open(), sends
 * one command, then closes the fd.  Each daemon connection is
 * one-shot — the daemon closes after replying, so fds cannot
 * be reused across calls.
 *
 * All functions return 0 on success or an errno on failure.
 * The return value may be a transport error (from read/write)
 * or a daemon-reported error (from the reply status field).
 * They never call err(), exit(), or write to stderr.
 */

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "authorityctl.h"

static int
control_readn(int fd, void *buf, size_t len)
{
	struct timeval tv;
	ssize_t n;
	size_t off;

	/* 30-second timeout protects against unresponsive daemon. */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	for (off = 0; off < len; ) {
		n = read(fd, (char *)buf + off, len - off);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (n == 0)
			return (ECONNRESET);
		off += n;
	}
	return (0);
}

static int
control_writen(int fd, const void *buf, size_t len)
{
	struct timeval tv;
	ssize_t n;
	size_t off;

	/* Bound a stalled peer and never turn a transport error into SIGPIPE. */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	for (off = 0; off < len; ) {
		n = send(fd, (const char *)buf + off, len - off,
		    MSG_NOSIGNAL);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (n == 0)
			return (EIO);
		off += n;
	}
	return (0);
}

static int do_call_summary(int fd, uint32_t op, uint32_t flags,
    const void *data, uint32_t datalen,
    char *summary, size_t sumlen, struct ctl_reply *rpl);

static int
do_call(int fd, uint32_t op, uint32_t flags,
    const void *data, uint32_t datalen, struct ctl_reply *rpl)
{
	struct ctl_request req;
	int error;

	memset(&req, 0, sizeof(req));
	req.version = AUTHORITYCTL_VERSION;
	req.op = op;
	req.flags = flags;
	req.datalen = datalen;

	error = control_writen(fd, &req, sizeof(req));
	if (error != 0)
		return (error);
	if (datalen > 0) {
		error = control_writen(fd, data, datalen);
		if (error != 0)
			return (error);
	}

	error = control_readn(fd, rpl, sizeof(*rpl));
	return (error);
}

/*
 * Open a connection to the authorityd control socket.
 * Returns a connected fd on success, or -1 with errno set.
 */
int
authorityctl_open(const char *path)
{
	struct sockaddr_un un;
	int fd;

	if (path == NULL)
		path = AUTHORITYD_CTL_SOCK;

	if (strlen(path) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return (-1);

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, path, sizeof(un.sun_path));

	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		int saved = errno;
		close(fd);
		errno = saved;
		return (-1);
	}
	return (fd);
}

int
authorityctl_status(int fd, struct authorityctl_status *st,
    char *summary, size_t sumlen)
{
	struct ctl_reply rpl;
	int error;

	memset(&rpl, 0, sizeof(rpl));
	error = do_call_summary(fd, AUTHORITYCTL_STATUS, 0, NULL, 0,
	    summary, sumlen, &rpl);
	if (st != NULL) {
		st->error = error;
		st->uptime_usec = rpl.uptime_usec;
	}
	return (error);
}

int
authorityctl_shutdown(int fd)
{
	struct ctl_reply rpl;
	int error;

	error = do_call(fd, AUTHORITYCTL_SHUTDOWN, 0, NULL, 0, &rpl);
	if (error != 0)
		return (error);
	return (rpl.status);
}

/*
 * Helper: do_call + read summary text from reply.flags bytes.
 */
static int
do_call_summary(int fd, uint32_t op, uint32_t flags,
    const void *data, uint32_t datalen,
    char *summary, size_t sumlen, struct ctl_reply *rpl)
{
	int error;
	uint32_t textlen;

	error = do_call(fd, op, flags, data, datalen, rpl);
	if (error != 0)
		return (error);

	textlen = rpl->flags;
	if (textlen > AUTHORITYCTL_SUMMARY_MAX)
		return (EPROTO);
	if (textlen > 0 && summary != NULL && sumlen > 0) {
		if (textlen >= sumlen)
			textlen = (uint32_t)(sumlen - 1);
		error = control_readn(fd, summary, textlen);
		if (error != 0)
			return (error);
		summary[textlen] = '\0';
	} else if (summary != NULL && sumlen > 0) {
		summary[0] = '\0';
	}
	return (rpl->status);
}

int
authorityctl_reload(int fd, char *summary, size_t sumlen)
{
	struct ctl_reply rpl;

	return (do_call_summary(fd, AUTHORITYCTL_RELOAD, 0, NULL, 0,
	    summary, sumlen, &rpl));
}

/*
 * Request a system lifecycle transition (reboot, halt, single-user,
 * ...) from authority-init.  op is one of the AUTHORITYCTL_* lifecycle
 * opcodes.  Returns 0 if the request was accepted (the transition then
 * proceeds asynchronously), or an errno — notably EPERM if the peer is
 * not root or authorityd is not PID 1.
 */
int
authorityctl_lifecycle(int fd, uint32_t op)
{
	struct ctl_reply rpl;
	int error;

	memset(&rpl, 0, sizeof(rpl));
	error = do_call(fd, op, 0, NULL, 0, &rpl);
	if (error != 0)
		return (error);
	return (rpl.status);
}
