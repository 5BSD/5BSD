/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capd_lookup_exec: run a command with a chosen discovery route installed in
 * its kernel process slot, so the command reaches a SwitchBoard through the
 * normal process route and needs no special path of its own.
 *
 *   -s SOCKET  the route a test-local Capsule holds from its own SwitchBoard,
 *              fetched from its control socket (CTL_OP_LOOKUP, root only);
 *   -i         the route this process inherited, taken out of the slot,
 *              cleared, and installed again (checks install-then-exec
 *              against a live plane without a private stack).
 *
 * The slot replaces whatever route was inherited, so a command run through
 * -s can never reach the system SwitchBoard by accident.
 */

#include <sys/types.h>
#include <sys/cap_process.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <capsule_ctl.h>
#include <libservice_session.h>

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capd_lookup_exec -s socket | -i command [argument ...]\n");
	exit(EX_USAGE);
}

static void
write_all(int s, const void *buf, size_t len)
{
	const char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(s, p, len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(EX_IOERR, "control request");
		}
		p += n;
		len -= (size_t)n;
	}
}

/* Ask a test-local Capsule for its route; returns an owned descriptor. */
static int
capsule_route(const char *path)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct ctl_request req;
	struct ctl_reply reply;
	struct sockaddr_un sun;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	size_t got;
	ssize_t n;
	int fd, s;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(EX_USAGE, "socket path too long: %s", path);
	s = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s == -1)
		err(EX_OSERR, "socket");
	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(EX_UNAVAILABLE, "connect %s", path);
	memset(&req, 0, sizeof(req));
	req.op = CTL_OP_LOOKUP;
	write_all(s, &req, sizeof(req));

	fd = -1;
	got = 0;
	while (got < sizeof(reply)) {
		memset(&control, 0, sizeof(control));
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = (char *)&reply + got;
		iov.iov_len = sizeof(reply) - got;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);
		n = recvmsg(s, &msg, MSG_CMSG_CLOEXEC);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(EX_IOERR, "control reply");
		}
		if (n == 0)
			errx(EX_PROTOCOL, "short control reply");
		if ((msg.msg_flags & MSG_CTRUNC) != 0)
			errx(EX_PROTOCOL, "control reply carried extra rights");
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_RIGHTS ||
			    cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || fd != -1)
				errx(EX_PROTOCOL, "unexpected control message");
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
		}
		got += (size_t)n;
	}
	(void)close(s);
	if (reply.status != 0) {
		if (fd != -1)
			errx(EX_PROTOCOL, "refusal carried a descriptor");
		errc(EX_UNAVAILABLE, (int)reply.status,
		    "Capsule refused the discovery route");
	}
	if (fd == -1)
		errx(EX_PROTOCOL, "control reply carried no route");
	return (fd);
}

/* Take the inherited route out of the slot; returns an owned descriptor. */
static int
inherited_route(void)
{
	int fd;

	fd = (int)syscall(SYS_cap_process, MAC_CAP_PROCESS_GET, -1, 0, NULL);
	if (fd == -1)
		err(EX_UNAVAILABLE, "no inherited discovery route");
	if (service_clear_ambient_lookup() == -1)
		err(EX_OSERR, "service_clear_ambient_lookup");
	if (syscall(SYS_cap_process, MAC_CAP_PROCESS_GET, -1, 0, NULL) != -1 ||
	    errno != ENOENT)
		errx(EX_SOFTWARE, "the slot still holds a route after clear");
	return (fd);
}

int
main(int argc, char **argv)
{
	const char *socket_path;
	bool inherited;
	int ch, fd;

	socket_path = NULL;
	inherited = false;
	while ((ch = getopt(argc, argv, "is:")) != -1) {
		switch (ch) {
		case 'i':
			inherited = true;
			break;
		case 's':
			socket_path = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1 || inherited == (socket_path != NULL))
		usage();

	fd = inherited ? inherited_route() : capsule_route(socket_path);
	if (service_install_ambient_lookup(fd) == -1)
		err(EX_OSERR, "service_install_ambient_lookup");
	/* The slot holds its own reference and is inherited across exec. */
	(void)close(fd);
	execvp(argv[0], argv);
	err(errno == ENOENT ? 127 : 126, "%s", argv[0]);
}
