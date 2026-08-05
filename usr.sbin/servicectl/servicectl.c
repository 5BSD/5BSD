/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * servicectl — command-line interface to serviced(8).
 *
 * Each invocation opens a connection to serviced's control socket,
 * sends one command, prints the result, and exits.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "serviced_ctl.h"
#include "servicectl.h"

static const char *sockpath = SERVICED_CTL_SOCK;

static int
sctl_connect(void)
{
	struct sockaddr_un un;
	int fd;

	if (strlen(sockpath) >= sizeof(un.sun_path))
		errx(EX_USAGE, "socket path is too long");
	fd = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		err(EX_UNAVAILABLE, "socket");

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_LOCAL;
	strlcpy(un.sun_path, sockpath, sizeof(un.sun_path));

	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1)
		err(EX_UNAVAILABLE, "connect %s", sockpath);

	return (fd);
}

static void
write_all(int fd, const void *buf, size_t len)
{
	struct timeval timeout;
	ssize_t amount;
	size_t offset;

	timeout.tv_sec = 30;
	timeout.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
	    sizeof(timeout));
	for (offset = 0; offset < len; ) {
		amount = send(fd, (const char *)buf + offset, len - offset,
		    MSG_NOSIGNAL);
		if (amount == -1) {
			if (errno == EINTR)
				continue;
			err(1, "send");
		}
		if (amount == 0)
			errx(1, "send: peer made no progress");
		offset += (size_t)amount;
	}
}

static void
read_all(int fd, void *buf, size_t len)
{
	struct timeval timeout;
	ssize_t amount;
	size_t offset;

	timeout.tv_sec = 30;
	timeout.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout));
	for (offset = 0; offset < len; ) {
		amount = recv(fd, (char *)buf + offset, len - offset, 0);
		if (amount == -1) {
			if (errno == EINTR)
				continue;
			err(1, "recv");
		}
		if (amount == 0)
			errx(1, "recv: unexpected end of stream");
		offset += (size_t)amount;
	}
}

/*
 * Send a request, read the reply header and optional summary text.
 * Returns the status code (0 = success).
 */
static int
sctl_rpc(uint32_t op, uint32_t flags, const char *payload,
    char *summary, size_t sumlen)
{
	struct sctl_request req;
	struct sctl_reply reply;
	size_t payload_length;
	uint32_t datalen;
	int fd;

	payload_length = payload != NULL ? strlen(payload) : 0;
	if (payload_length > SERVICED_CTL_MAX_PAYLOAD)
		errx(EX_USAGE, "request payload exceeds protocol limit");
	datalen = (uint32_t)payload_length;

	fd = sctl_connect();

	memset(&req, 0, sizeof(req));
	req.version = SERVICED_CTL_VERSION;
	req.op = op;
	req.flags = flags;
	req.datalen = datalen;

	write_all(fd, &req, sizeof(req));
	if (datalen > 0)
		write_all(fd, payload, datalen);

	read_all(fd, &reply, sizeof(reply));
	if (reply.flags > SERVICED_CTL_SUMMARY_MAX)
		errx(1, "invalid reply summary length");

	if (reply.flags > 0 && summary != NULL && sumlen > 0) {
		size_t toread;

		toread = reply.flags;
		if (toread >= sumlen)
			toread = sumlen - 1;
		read_all(fd, summary, toread);
		summary[toread] = '\0';

		/* Drain any remaining bytes. */
		if (reply.flags > toread) {
			char drain[256];
			size_t rem;

			rem = reply.flags - toread;
			while (rem > 0) {
				size_t chunk;
				ssize_t n;

				chunk = rem > sizeof(drain) ? sizeof(drain) : rem;
				n = read(fd, drain, chunk);
				if (n <= 0)
					break;
				rem -= (size_t)n;
			}
		}
	}

	close(fd);
	return ((int)reply.status);
}

static int
cmd_status(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_STATUS, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("status: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("serviced: running\n");
	return (0);
}

static int
cmd_services(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_SERVICES, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("services: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	return (0);
}

static int
cmd_reload(void)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_RELOAD, 0, NULL, summary, sizeof(summary));
	if (error != 0) {
		warnx("reload: %s", strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s", summary);
	else
		printf("reload: ok\n");
	return (0);
}

static int
cmd_stop(const char *label)
{
	char summary[SERVICED_CTL_SUMMARY_MAX];
	int error;

	summary[0] = '\0';
	error = sctl_rpc(SCTL_OP_STOP_SVC, 0, label,
	    summary, sizeof(summary));
	if (error != 0) {
		warnx("stop: %s", summary[0] != '\0' ?
		    summary : strerror(error));
		return (1);
	}
	if (summary[0] != '\0')
		printf("%s\n", summary);
	else
		printf("stop: ok\n");
	return (0);
}

static void
usage(void)
{

	fprintf(stderr,
	    "usage: servicectl [-s socket] command [args]\n"
	    "\n"
	    "commands:\n"
	    "  status              show serviced status and service list\n"
	    "  services            list loaded services\n"
	    "  reload              reload service bundles\n"
	    "  stop <label>        stop a running service\n"
	    "  install <path.cap>  install a .cap bundle to /Capabilities/\n"
	    "  verify <path.cap> [...] validate bundles and dependencies\n"
	    "  deps <program>      suggest component manifest dependencies\n"
	    "  bundles             list all registered bundles\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *cmd;
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

	cmd = argv[0];

	if (strcmp(cmd, "status") == 0 && argc == 1)
		return (cmd_status());
	if (strcmp(cmd, "services") == 0 && argc == 1)
		return (cmd_services());
	if (strcmp(cmd, "reload") == 0 && argc == 1)
		return (cmd_reload());
	if (strcmp(cmd, "stop") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "stop requires a service label");
		return (cmd_stop(argv[1]));
	}
	if (strcmp(cmd, "install") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "install requires a .cap bundle path");
		return (cmd_install(argv[1]));
	}
	if (strcmp(cmd, "verify") == 0) {
		if (argc < 2)
			errx(EX_USAGE, "verify requires a .cap bundle path");
		return (cmd_verify(argc - 1, argv + 1));
	}
	if (strcmp(cmd, "deps") == 0) {
		if (argc != 2)
			errx(EX_USAGE, "deps requires an executable path");
		return (cmd_deps(argv[1]));
	}
	if (strcmp(cmd, "bundles") == 0 && argc == 1)
		return (cmd_bundles());

	warnx("unknown command: %s", cmd);
	usage();
	return (1);
}
