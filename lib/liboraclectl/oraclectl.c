/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client library for the oracled(8) control socket.
 *
 * Each function opens a connection, sends a request, reads the
 * reply, and closes.  The caller provides an fd from
 * oraclectl_open() for reuse across multiple calls, or passes -1
 * to let the function connect and disconnect automatically.
 *
 * All functions return 0 on success or an errno on failure.
 * They never call err(), exit(), or write to stderr.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "oraclectl.h"

/* Wire protocol structs — match oracled_ctl.h exactly. */
struct ctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	datalen;
} __packed;

struct ctl_reply {
	uint32_t	status;
	uint32_t	flags;
	uint64_t	uptime_usec;
} __packed;

static int
readn(int fd, void *buf, size_t len)
{
	ssize_t n;
	size_t off;

	for (off = 0; off < len; ) {
		n = read(fd, (char *)buf + off, len - off);
		if (n <= 0)
			return (n == 0 ? ECONNRESET : errno);
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
		if (n <= 0)
			return (errno);
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
		st->flags = rpl.flags;
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
oraclectl_reload(int fd)
{
	struct ctl_reply rpl;
	int error;

	error = do_call(fd, ORACLECTL_RELOAD, 0, NULL, 0, &rpl);
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
