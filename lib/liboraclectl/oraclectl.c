/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client library for the oracled(8) control socket.
 *
 * The caller opens a connection with oraclectl_open(), sends
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

#include "oraclectl.h"

static int
readn(int fd, void *buf, size_t len)
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
writen(int fd, const void *buf, size_t len)
{
	ssize_t n;
	size_t off;

	for (off = 0; off < len; ) {
		n = write(fd, (const char *)buf + off, len - off);
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

static int
do_call(int fd, uint32_t op, uint32_t flags,
    const void *data, uint32_t datalen, struct ctl_reply *rpl)
{
	struct ctl_request req;
	int error;

	memset(&req, 0, sizeof(req));
	req.version = ORACLECTL_VERSION;
	req.op = op;
	req.flags = flags;
	req.datalen = datalen;

	error = writen(fd, &req, sizeof(req));
	if (error != 0)
		return (error);
	if (datalen > 0) {
		error = writen(fd, data, datalen);
		if (error != 0)
			return (error);
	}

	error = readn(fd, rpl, sizeof(*rpl));
	return (error);
}

/*
 * Open a connection to the oracled control socket.
 * Returns a connected fd on success, or -1 with errno set.
 */
int
oraclectl_open(const char *path)
{
	struct sockaddr_un un;
	int fd;

	if (path == NULL)
		path = ORACLED_CTL_SOCK;

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
oraclectl_status(int fd, struct oraclectl_status *st)
{
	struct ctl_reply rpl;
	int error;

	error = do_call(fd, ORACLECTL_STATUS, 0, NULL, 0, &rpl);
	if (error != 0)
		return (error);
	if (st != NULL) {
		st->error = rpl.status;
		st->uptime_usec = rpl.uptime_usec;
	}
	return (rpl.status);
}

int
oraclectl_shutdown(int fd)
{
	struct ctl_reply rpl;
	int error;

	error = do_call(fd, ORACLECTL_SHUTDOWN, 0, NULL, 0, &rpl);
	if (error != 0)
		return (error);
	return (rpl.status);
}

int
oraclectl_kldload(int fd, const char *module, int *idp)
{
	struct ctl_reply rpl;
	size_t len;
	int error;

	len = strlen(module);
	if (len == 0 || len > ORACLECTL_MAX_PAYLOAD)
		return (EINVAL);

	error = do_call(fd, ORACLECTL_KLDLOAD, 0, module, len, &rpl);
	if (error != 0)
		return (error);
	if (rpl.status == 0 && idp != NULL)
		*idp = (int)rpl.flags;
	return (rpl.status);
}

int
oraclectl_kldunload(int fd, const char *module)
{
	struct ctl_reply rpl;
	size_t len;
	int error;

	len = strlen(module);
	if (len == 0 || len > ORACLECTL_MAX_PAYLOAD)
		return (EINVAL);

	error = do_call(fd, ORACLECTL_KLDUNLOAD, 0, module, len, &rpl);
	if (error != 0)
		return (error);
	return (rpl.status);
}

int
oraclectl_reboot(int fd, int howto)
{
	struct ctl_reply rpl;
	int error;

	error = do_call(fd, ORACLECTL_REBOOT, (uint32_t)howto,
	    NULL, 0, &rpl);
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
	if (textlen > 0 && summary != NULL && sumlen > 0) {
		if (textlen >= sumlen)
			textlen = (uint32_t)(sumlen - 1);
		error = readn(fd, summary, textlen);
		if (error != 0)
			return (error);
		summary[textlen] = '\0';
	} else if (summary != NULL && sumlen > 0) {
		summary[0] = '\0';
	}
	return (rpl->status);
}

int
oraclectl_check(int fd, const char *filename,
    char *summary, size_t sumlen)
{
	struct ctl_reply rpl;
	size_t len;

	len = strlen(filename);
	if (len == 0 || len > ORACLECTL_MAX_PAYLOAD)
		return (EINVAL);

	return (do_call_summary(fd, ORACLECTL_CHECK, 0, filename, len,
	    summary, sumlen, &rpl));
}

int
oraclectl_load(int fd, const char *filename,
    char *summary, size_t sumlen)
{
	struct ctl_reply rpl;
	size_t len;

	len = strlen(filename);
	if (len == 0 || len > ORACLECTL_MAX_PAYLOAD)
		return (EINVAL);

	return (do_call_summary(fd, ORACLECTL_LOAD, 0, filename, len,
	    summary, sumlen, &rpl));
}

int
oraclectl_reload(int fd, char *summary, size_t sumlen)
{
	struct ctl_reply rpl;

	return (do_call_summary(fd, ORACLECTL_RELOAD, 0, NULL, 0,
	    summary, sumlen, &rpl));
}

int
oraclectl_services(int fd, uint32_t flags, char *summary, size_t sumlen)
{
	struct ctl_reply rpl;

	return (do_call_summary(fd, ORACLECTL_SERVICES, flags, NULL, 0,
	    summary, sumlen, &rpl));
}
