/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * oesd - Endpoint Security Capabilities Daemon
 *
 * This is the system daemon that owns /dev/oes and creates
 * restricted handles for third-party security vendors.
 *
 * Usage: oesd [-d] [-s socket_path]
 *   -d  Debug mode (don't daemonize)
 *   -s  Unix socket path (default: /var/run/oesd.sock)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/capsicum.h>
#include <sys/event.h>

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "liboes.h"

#define DEFAULT_SOCKET_PATH	"/var/run/oesd.sock"

static bool debug_mode;
static volatile sig_atomic_t running = 1;

static void
usage(void)
{
	fprintf(stderr, "usage: oesd [-d] [-s socket_path]\n");
	exit(1);
}

static void
sighandler(int sig __unused)
{
	running = 0;
}

/*
 * Send a file descriptor over a Unix socket
 */
static int
send_fd(int sock, int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy = 'F';

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(sock, &msg, 0) < 0)
		return (-1);

	return (0);
}

/*
 * Create a restricted oes fd for a third-party client
 */
static int
create_vendor_fd(int oes_fd)
{
	int vendor_fd;
	cap_rights_t rights;
	cap_ioctl_t allowed[] = OES_IOCTLS_THIRD_PARTY_INIT;

	/* Duplicate the fd */
	vendor_fd = dup(oes_fd);
	if (vendor_fd < 0)
		return (-1);

	/* Limit allowed ioctls */
	if (cap_ioctls_limit(vendor_fd, allowed, nitems(allowed)) < 0) {
		close(vendor_fd);
		return (-1);
	}

	/* Limit capability rights */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_IOCTL);
	if (cap_rights_limit(vendor_fd, &rights) < 0) {
		close(vendor_fd);
		return (-1);
	}

	return (vendor_fd);
}

/*
 * Handle a client connection
 */
static void
handle_client(int client_sock, int oes_fd)
{
	int vendor_fd;

	vendor_fd = create_vendor_fd(oes_fd);
	if (vendor_fd < 0) {
		syslog(LOG_ERR, "failed to create vendor fd: %m");
		return;
	}

	if (send_fd(client_sock, vendor_fd) < 0) {
		syslog(LOG_ERR, "failed to send fd to client: %m");
	} else {
		syslog(LOG_INFO, "sent restricted fd to client");
	}

	close(vendor_fd);
}

/*
 * Event handler for our own oes events
 */
static bool
event_handler(oes_client_t *client, const oes_message_t *msg, void *ctx __unused)
{

	if (debug_mode) {
		printf("Event: %s pid=%d comm=%s\n",
		    oes_event_name(msg->em_event),
		    msg->em_process.ep_pid,
		    msg->em_process.ep_comm);
	}

	/* For AUTH events, always allow (we're just monitoring) */
	if (oes_is_auth_event(msg)) {
		oes_respond_allow(client, msg);
	}

	return (running != 0);
}

int
main(int argc, char *argv[])
{
	oes_client_t *client;
	int oes_fd, listen_sock, kq;
	struct sockaddr_un sun;
	struct kevent kev[2];
	const char *socket_path = DEFAULT_SOCKET_PATH;
	int ch, n;

	while ((ch = getopt(argc, argv, "ds:")) != -1) {
		switch (ch) {
		case 'd':
			debug_mode = true;
			break;
		case 's':
			socket_path = optarg;
			break;
		default:
			usage();
		}
	}

	/* Open the OES device */
	client = oes_client_create();
	if (client == NULL)
		err(1, "oes_client_create");

	oes_fd = oes_client_fd(client);

	/* Set AUTH mode so we can respond to events */
	if (oes_set_mode(client, OES_MODE_AUTH, 0, 0) < 0)
		err(1, "oes_set_mode");

	/* Subscribe to all events */
	if (oes_subscribe_all(client, true, true) < 0)
		err(1, "oes_subscribe_all");

	/* Mute ourselves to avoid recursion */
	if (oes_mute_self(client) < 0)
		err(1, "oes_mute_self");

	/* Create Unix socket for client connections */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sock < 0)
		err(1, "socket");

	unlink(socket_path);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	if (bind(listen_sock, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "bind");

	if (listen(listen_sock, 5) < 0)
		err(1, "listen");

	/* Daemonize unless debug mode */
	if (!debug_mode) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog("oesd", LOG_PID, LOG_DAEMON);
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	syslog(LOG_INFO, "started, listening on %s", socket_path);

	/* Create kqueue for multiplexing */
	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	EV_SET(&kev[0], oes_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[1], listen_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, kev, 2, NULL, 0, NULL) < 0)
		err(1, "kevent register");

	/* Main loop */
	while (running) {
		n = kevent(kq, NULL, 0, kev, 2, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}

		for (int i = 0; i < n; i++) {
			if ((int)kev[i].ident == oes_fd) {
				/* OES event available - drain batch */
				const oes_message_t *msg;
				while (oes_read_event(client, &msg,
				    false) == 0) {
					event_handler(client, msg, NULL);
				}
			} else if ((int)kev[i].ident == listen_sock) {
				/* New client connection */
				int client_sock = accept(listen_sock, NULL, NULL);
				if (client_sock >= 0) {
					handle_client(client_sock, oes_fd);
					close(client_sock);
				}
			}
		}
	}

	syslog(LOG_INFO, "shutting down");

	close(kq);
	close(listen_sock);
	unlink(socket_path);
	oes_client_destroy(client);

	return (0);
}
