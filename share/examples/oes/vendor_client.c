/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * vendor_client - Example third-party OES client
 *
 * Demonstrates how a third-party security vendor would:
 * 1. Connect to oesd and receive a restricted fd
 * 2. Subscribe to events
 * 3. Process events in a loop
 *
 * Note: This client cannot enter AUTH mode because oesd
 * restricts the ioctls available on the fd it provides.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "liboes.h"

#define DEFAULT_SOCKET_PATH	"/var/run/oesd.sock"

/*
 * Receive a file descriptor over a Unix socket
 */
static int
recv_fd(int sock)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0)
		return (-1);

	if (msg.msg_flags & MSG_CTRUNC)
		return (-1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		return (-1);

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	return (fd);
}

/*
 * Connect to oesd and get a restricted oes fd
 */
static int
connect_to_oesd(const char *socket_path)
{
	struct sockaddr_un sun;
	int sock, fd;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return (-1);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(sock);
		return (-1);
	}

	fd = recv_fd(sock);
	close(sock);

	return (fd);
}

/*
 * Event handler
 */
static bool
event_handler(oes_client_t *client __unused, const oes_message_t *msg,
    void *ctx __unused)
{

	printf("[%s] pid=%d uid=%d comm=%s",
	    oes_event_name(msg->em_event),
	    msg->em_process.ep_pid,
	    msg->em_process.ep_uid,
	    msg->em_process.ep_comm);

	/* Print file path for file events */
	switch (msg->em_event) {
	case OES_EVENT_NOTIFY_EXEC:
	case OES_EVENT_AUTH_EXEC: {
		const char *exe = oes_file_path(msg,
		    &msg->em_event_data.exec.executable);
		if (exe[0] != '\0')
			printf(" exe=%s", exe);
		break;
	}
	case OES_EVENT_NOTIFY_OPEN:
	case OES_EVENT_AUTH_OPEN: {
		const char *path = oes_file_path(msg,
		    &msg->em_event_data.open.file);
		if (path[0] != '\0')
			printf(" file=%s", path);
		break;
	}
	default:
		break;
	}

	printf("\n");

	/*
	 * Note: If we receive AUTH events (in PASSIVE mode), we don't
	 * respond - they're informational only. The system daemon
	 * handles the actual responses.
	 *
	 * If we try to call oes_respond() or oes_set_mode(OES_MODE_AUTH),
	 * we'll get ENOTCAPABLE because oesd restricted our ioctls.
	 */

	return (true);  /* Continue processing */
}

int
main(int argc, char *argv[])
{
	oes_client_t *client;
	const char *socket_path = DEFAULT_SOCKET_PATH;
	int fd;
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			socket_path = optarg;
			break;
		default:
			fprintf(stderr, "usage: vendor_client [-s socket_path]\n");
			return (1);
		}
	}

	/* Connect to oesd and get restricted fd */
	printf("Connecting to oesd at %s...\n", socket_path);
	fd = connect_to_oesd(socket_path);
	if (fd < 0)
		err(1, "connect_to_oesd");

	printf("Received restricted fd %d\n", fd);

	/* Create client from the received fd */
	client = oes_client_create_from_fd(fd);
	if (client == NULL)
		err(1, "oes_client_create_from_fd");

	/*
	 * Try to set AUTH mode - this should fail with ENOTCAPABLE
	 * because oesd restricted our ioctls.
	 */
	printf("Attempting to set AUTH mode (should fail)...\n");
	if (oes_set_mode(client, OES_MODE_AUTH, 0, 0) < 0) {
		printf("  Failed as expected: %s\n", strerror(errno));
	} else {
		printf("  Unexpectedly succeeded!\n");
	}

	/* Subscribe to NOTIFY events only (we can't do AUTH) */
	printf("Subscribing to NOTIFY events...\n");
	if (oes_subscribe_all(client, false, true) < 0)
		err(1, "oes_subscribe_all");

	/* Mute ourselves */
	if (oes_mute_self(client) < 0)
		err(1, "oes_mute_self");

	printf("Listening for events (Ctrl+C to stop)...\n\n");

	/* Process events */
	if (oes_dispatch(client, event_handler, NULL) < 0)
		err(1, "oes_dispatch");

	oes_client_destroy(client);
	close(fd);

	return (0);
}
