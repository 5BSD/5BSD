/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oraclectl — command-line interface to oracled(8).
 *
 * Connects to the oracled control socket, sends a single command,
 * prints the result, and exits.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "oracled_ctl.h"

static const char *sockpath = ORACLED_CTL_SOCK;

static int
ctl_connect(void)
{
	struct sockaddr_un un;
	int fd;

	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		err(EX_OSERR, "socket");

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, sockpath, sizeof(un.sun_path));

	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1)
		err(EX_UNAVAILABLE, "connect %s", sockpath);

	return (fd);
}

static void
ctl_send(int fd, uint32_t op, uint32_t flags,
    const void *data, uint32_t datalen)
{
	struct ctl_request req;

	memset(&req, 0, sizeof(req));
	req.version = CTL_VERSION;
	req.op = op;
	req.flags = flags;
	req.datalen = datalen;

	if (write(fd, &req, sizeof(req)) != sizeof(req))
		err(EX_IOERR, "write request");
	if (datalen > 0) {
		if (write(fd, data, datalen) != (ssize_t)datalen)
			err(EX_IOERR, "write payload");
	}
}

static struct ctl_reply
ctl_recv(int fd)
{
	struct ctl_reply reply;
	size_t off;
	ssize_t n;

	for (off = 0; off < sizeof(reply); ) {
		n = read(fd, (char *)&reply + off, sizeof(reply) - off);
		if (n <= 0) {
			if (n == 0)
				errx(EX_PROTOCOL, "connection closed");
			err(EX_IOERR, "read reply");
		}
		off += n;
	}
	return (reply);
}

static int
check_reply(struct ctl_reply *reply, const char *cmd)
{

	if (reply->status == CTL_STATUS_OK)
		return (0);
	if (reply->status == EPERM) {
		warnx("%s: permission denied", cmd);
		return (EX_NOPERM);
	}
	warnx("%s: %s", cmd, strerror(reply->status));
	return (1);
}

/* ----------------------------------------------------------------
 * Commands
 * ---------------------------------------------------------------- */

static int
cmd_status(void)
{
	struct ctl_reply reply;
	uint64_t up;
	int fd;

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_STATUS, 0, NULL, 0);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, "status"));

	up = reply.uptime_usec;
	printf("oracled: running\n");
	if (up < 1000000ULL)
		printf("uptime:  %llu ms\n",
		    (unsigned long long)(up / 1000));
	else if (up < 60000000ULL)
		printf("uptime:  %llu seconds\n",
		    (unsigned long long)(up / 1000000));
	else if (up < 3600000000ULL)
		printf("uptime:  %llu minutes\n",
		    (unsigned long long)(up / 60000000));
	else
		printf("uptime:  %llu hours\n",
		    (unsigned long long)(up / 3600000000ULL));
	return (0);
}

static int
cmd_shutdown(void)
{
	struct ctl_reply reply;
	int fd;

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_SHUTDOWN, 0, NULL, 0);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, "shutdown"));

	printf("oracled: shutdown initiated\n");
	return (0);
}

static int
cmd_reload(void)
{
	struct ctl_reply reply;
	int fd;

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_RELOAD, 0, NULL, 0);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, "reload"));

	printf("oracled: reload initiated\n");
	return (0);
}

static int
cmd_kldload(const char *module)
{
	struct ctl_reply reply;
	size_t len;
	int fd;

	len = strlen(module);
	if (len == 0 || len > CTL_MAX_PAYLOAD)
		errx(EX_USAGE, "invalid module name");

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_KLDLOAD, 0, module, len);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, module));

	printf("%s: loaded (id %u)\n", module, reply.flags);
	return (0);
}

static int
cmd_kldunload(const char *module)
{
	struct ctl_reply reply;
	size_t len;
	int fd;

	len = strlen(module);
	if (len == 0 || len > CTL_MAX_PAYLOAD)
		errx(EX_USAGE, "invalid module name");

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_KLDUNLOAD, 0, module, len);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, module));

	printf("%s: unloaded\n", module);
	return (0);
}

static int
cmd_reboot(void)
{
	struct ctl_reply reply;
	int fd;

	fd = ctl_connect();
	ctl_send(fd, CTL_OP_REBOOT, 0, NULL, 0);
	reply = ctl_recv(fd);
	close(fd);

	if (reply.status != CTL_STATUS_OK)
		return (check_reply(&reply, "reboot"));

	printf("oracled: reboot initiated\n");
	return (0);
}

/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: oraclectl [-s socket] command [args]\n"
	    "       oraclectl status\n"
	    "       oraclectl shutdown\n"
	    "       oraclectl reload\n"
	    "       oraclectl kldload <module>\n"
	    "       oraclectl kldunload <module>\n"
	    "       oraclectl reboot\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockpath = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "status") == 0 && argc == 1)
		return (cmd_status());
	if (strcmp(argv[0], "shutdown") == 0 && argc == 1)
		return (cmd_shutdown());
	if (strcmp(argv[0], "reload") == 0 && argc == 1)
		return (cmd_reload());
	if (strcmp(argv[0], "kldload") == 0 && argc == 2)
		return (cmd_kldload(argv[1]));
	if (strcmp(argv[0], "kldunload") == 0 && argc == 2)
		return (cmd_kldunload(argv[1]));
	if (strcmp(argv[0], "reboot") == 0 && argc == 1)
		return (cmd_reboot());

	usage();
	return (EX_USAGE);
}
