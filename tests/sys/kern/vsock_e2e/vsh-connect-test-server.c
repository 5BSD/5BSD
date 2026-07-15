/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal stand-in for bhyve's vsock control socket.  It validates one
 * CONNECT request, returns a data socket through SCM_RIGHTS, and echoes one
 * connection.  This lets the E2E rig prove vsh-connect without a VM.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct vsock_ctl_msg {
	uint32_t cmd;
	uint32_t port;
	uint32_t type;
	int32_t status;
};

#define	VSOCK_CTL_CONNECT	1
#define	ECHO_BUFSIZE		(8U * 1024 * 1024)

static void
write_all(int fd, const void *buffer, size_t length)
{
	const char *p = buffer;
	ssize_t n;

	while (length != 0) {
		n = write(fd, p, length);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "write");
		}
		if (n == 0)
			errx(1, "zero-length write");
		p += n;
		length -= (size_t)n;
	}
}

static void
echo_data(int fd)
{
	char *buf;
	size_t used = 0;
	ssize_t n;

	buf = malloc(ECHO_BUFSIZE);
	if (buf == NULL)
		err(1, "malloc echo buffer");

	/* Drain through EOF before echoing.  This intentionally tests the
	 * client's half-close path and cannot deadlock with a client that is
	 * still filling a small AF_UNIX send buffer. */
	while (used < ECHO_BUFSIZE &&
	    (n = read(fd, buf + used, ECHO_BUFSIZE - used)) > 0)
		used += (size_t)n;
	if (n < 0)
		err(1, "read data socket");
	if (used == ECHO_BUFSIZE)
		errx(1, "test payload exceeds %u bytes", ECHO_BUFSIZE);
	write_all(fd, buf, used);
	free(buf);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un sun;
	struct vsock_ctl_msg request, response;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char control[CMSG_SPACE(sizeof(int))];
	int accepted, data[2], listener, type;
	ssize_t n;

	if (argc != 3)
		errx(2, "usage: vsh-connect-test-server socket-path stream|seq");
	if (strcmp(argv[2], "stream") == 0)
		type = SOCK_STREAM;
	else if (strcmp(argv[2], "seq") == 0)
		type = SOCK_SEQPACKET;
	else
		errx(2, "socket type must be stream or seq");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	if (strlcpy(sun.sun_path, argv[1], sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(2, "control socket path is too long");
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0)
		err(1, "socket");
	(void)unlink(argv[1]);
	if (bind(listener, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "bind %s", argv[1]);
	if (listen(listener, 1) < 0)
		err(1, "listen");

	accepted = accept(listener, NULL, NULL);
	if (accepted < 0)
		err(1, "accept");
	n = recv(accepted, &request, sizeof(request), MSG_WAITALL);
	if (n != sizeof(request))
		errx(1, "short control request: %zd", n);
	if (request.cmd != VSOCK_CTL_CONNECT || request.type != (uint32_t)type)
		errx(1, "invalid control request: cmd=%u type=%u",
		    request.cmd, request.type);
	if (socketpair(AF_UNIX, type, 0, data) < 0)
		err(1, "socketpair");

	memset(&response, 0, sizeof(response));
	response.cmd = request.cmd;
	response.port = request.port;
	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	/* Deliberately fragment the stream reply around the SCM_RIGHTS message.
	 * A real control socket may split its 16-byte response at any boundary. */
	iov.iov_base = &response;
	iov.iov_len = sizeof(response) / 2;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &data[0], sizeof(data[0]));
	if (sendmsg(accepted, &msg, 0) != (ssize_t)iov.iov_len)
		err(1, "send control response");
	write_all(accepted, (char *)&response + iov.iov_len,
	    sizeof(response) - iov.iov_len);
	close(data[0]);
	close(accepted);
	close(listener);
	echo_data(data[1]);
	close(data[1]);
	return (0);
}
