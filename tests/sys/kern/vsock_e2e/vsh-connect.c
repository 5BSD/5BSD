/*
 * vsh-connect — host→guest connector through the bhyve vsock device's
 * control socket (e2e suite version).
 *
 * usage: vsh-connect [-s] [-w] <dir> <port>
 *
 *   -s   request SOCK_SEQPACKET
 *   -w   verify a built-in echo, then wait for peer disconnect
 *
 * The device sets LOCAL_CAP_CONNECT on the control socket, so the
 * client must be in capability mode: open the socket directory first,
 * cap_enter(), then connectat(dirfd, "sock").  On success bhyve hands
 * back one end of a socketpair via SCM_RIGHTS; relay stdin/stdout over
 * it full-duplex with half-close (stdin EOF -> shutdown(SHUT_WR)).
 *
 * exit: 0 relay done, 4 connection refused by guest, other = error.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/capsicum.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* mirrors struct vsock_ctl_msg in pci_virtio_vsock.c */
struct vsock_ctl_msg { uint32_t cmd, port, type; int32_t status; };
#define VSOCK_CTL_CONNECT 1

static int
write_all(int fd, const void *buffer, size_t length)
{
	const char *p = buffer;
	ssize_t n;

	while (length != 0) {
		n = write(fd, p, length);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0) {
			errno = EIO;
			return (-1);
		}
		p += n;
		length -= (size_t)n;
	}
	return (0);
}

static int
write_socket(int fd, const void *buffer, size_t length, bool seqpacket)
{
	ssize_t n;

	if (!seqpacket)
		return (write_all(fd, buffer, length));
	do {
		n = send(fd, buffer, length, MSG_EOR);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return (-1);
	if ((size_t)n != length) {
		errno = EMSGSIZE;
		return (-1);
	}
	return (0);
}

static int
recv_control_reply(int fd, struct vsock_ctl_msg *reply, int *datafd)
{
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char control[CMSG_SPACE(sizeof(int))];
	size_t offset = 0;
	ssize_t n;

	while (offset < sizeof(*reply)) {
		memset(&msg, 0, sizeof(msg));
		memset(control, 0, sizeof(control));
		iov.iov_base = (char *)reply + offset;
		iov.iov_len = sizeof(*reply) - offset;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		do {
			n = recvmsg(fd, &msg, 0);
		} while (n < 0 && errno == EINTR);
		if (n < 0)
			return (-1);
		if (n == 0) {
			errno = ECONNRESET;
			return (-1);
		}
		if ((msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
			errno = EMSGSIZE;
			return (-1);
		}
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_RIGHTS)
				continue;
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
				errno = EPROTO;
				return (-1);
			}
			if (*datafd >= 0) {
				errno = EPROTO;
				return (-1);
			}
			memcpy(datafd, CMSG_DATA(cmsg), sizeof(*datafd));
		}
		offset += (size_t)n;
	}
	return (0);
}

static int
parse_port(const char *text, uint32_t *port)
{
	char *end;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0' || value == 0 ||
	    value > UINT32_MAX)
		return (-1);
	*port = (uint32_t)value;
	return (0);
}

/*
 * One-record mode (-1): slurp all of stdin and send it as a SINGLE record
 * with MSG_EOR, then drain the reply to stdout.  This lets us exercise a
 * host->guest SEQPACKET record larger than one read() chunk without the
 * default streaming relay chopping it at 64 KiB -- the record boundary is the
 * sender's MSG_EOR, exactly as the contract requires.  Cap the slurp at 4 MiB
 * (the device's max reassembled record).
 */
static int
relay_oneshot(int sfd, bool seqpacket)
{
	size_t cap = 4u * 1024 * 1024, len = 0;
	char *buf = malloc(cap);
	char extra;
	ssize_t n;

	if (buf == NULL) { perror("malloc"); return (1); }
	while (len < cap) {
		n = read(0, buf + len, cap - len);
		if (n < 0) { if (errno == EINTR) continue; perror("read"); free(buf); return (1); }
		if (n == 0) break;	/* EOF: whole record collected */
		len += (size_t)n;
	}
	if (len == cap) {
		do {
			n = read(0, &extra, 1);
		} while (n < 0 && errno == EINTR);
		if (n != 0) {
			if (n < 0)
				perror("read");
			else
				fprintf(stderr, "input exceeds 4 MiB record limit\n");
			free(buf);
			return (1);
		}
	}
	if (write_socket(sfd, buf, len, seqpacket) < 0) {
		perror("write"); free(buf); return (1);
	}
	(void)shutdown(sfd, SHUT_WR);
	for (;;) {
		n = read(sfd, buf, cap);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("read socket");
			free(buf);
			return (1);
		}
		if (n == 0) break;
		if (write_all(1, buf, (size_t)n) < 0) {
			perror("write stdout");
			free(buf);
			return (1);
		}
	}
	free(buf);
	return (0);
}

static int
relay(int sfd, bool seqpacket)
{
	char buf[65536];
	struct pollfd pfd[2];
	bool in_open = true, sock_open = true;
	ssize_t n;

	while (sock_open || in_open) {
		pfd[0].fd = in_open ? 0 : -1;
		pfd[0].events = POLLIN;
		pfd[1].fd = sock_open ? sfd : -1;
		pfd[1].events = POLLIN;
		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			return (1);
		}
		if (pfd[0].revents & (POLLIN | POLLHUP)) {
			do {
				n = read(0, buf, sizeof(buf));
			} while (n < 0 && errno == EINTR);
			if (n > 0) {
				if (write_socket(sfd, buf, (size_t)n,
				    seqpacket) < 0)
					return (1);
			} else if (n == 0) {
				(void)shutdown(sfd, SHUT_WR);
				in_open = false;
			} else
				return (1);
		}
		if (pfd[1].revents & (POLLIN | POLLHUP)) {
			do {
				n = read(sfd, buf, sizeof(buf));
			} while (n < 0 && errno == EINTR);
			if (n > 0) {
				if (write_all(1, buf, (size_t)n) < 0)
					return (1);
			} else if (n == 0) {
				sock_open = false;
				if (!in_open)
					break;
			} else
				return (1);
		}
	}
	return (0);
}

/*
 * Lifecycle mode: prove that the connection is live before an external test
 * resets/reboots the peer, then wait for the established endpoint to close.
 * Keeping this independent of stdin prevents an input EOF from half-closing
 * the socket before the lifecycle event under test.
 */
static int
wait_for_disconnect(int sfd, bool seqpacket)
{
	static const char token[] = "VSOCK-LIFECYCLE";
	char buf[sizeof(token) - 1];
	size_t offset;
	ssize_t n;

	if (write_socket(sfd, token, sizeof(token) - 1, seqpacket) < 0) {
		perror("write lifecycle probe");
		return (1);
	}
	offset = 0;
	while (offset < sizeof(buf)) {
		do {
			n = read(sfd, buf + offset, sizeof(buf) - offset);
		} while (n < 0 && errno == EINTR);
		if (n <= 0) {
			if (n < 0)
				perror("read lifecycle echo");
			else
				fprintf(stderr, "EOF before lifecycle echo\n");
			return (1);
		}
		offset += (size_t)n;
	}
	if (memcmp(buf, token, sizeof(buf)) != 0) {
		fprintf(stderr, "lifecycle echo mismatch\n");
		return (1);
	}
	printf("READY\n");
	fflush(stdout);

	for (;;) {
		do {
			n = read(sfd, buf, sizeof(buf));
		} while (n < 0 && errno == EINTR);
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == ECONNRESET || errno == ENOTCONN)
				break;
			perror("wait for lifecycle disconnect");
			return (1);
		}
	}
	printf("DISCONNECTED\n");
	return (0);
}

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM;
	int oneshot = 0, wait_disconnect = 0;
	int ch, dfd, cs, datafd = -1;
	uint32_t port;
	cap_rights_t rights;
	struct sockaddr_un sun;
	struct vsock_ctl_msg m, r;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "s1w")) != -1) {
		switch (ch) {
		case 's': type = SOCK_SEQPACKET; break;
		case '1': oneshot = 1; break;	/* send all stdin as ONE record */
		case 'w': wait_disconnect = 1; break;
		default:
			fprintf(stderr, "usage: %s [-s] [-1|-w] <dir> <port>\n",
			    argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2) {
		fprintf(stderr, "usage: vsh-connect [-s] [-1|-w] <dir> <port>\n");
		return (2);
	}
	if (oneshot && wait_disconnect) {
		fprintf(stderr, "-1 and -w are mutually exclusive\n");
		return (2);
	}
	if (parse_port(argv[1], &port) < 0) {
		fprintf(stderr, "invalid port: %s\n", argv[1]);
		return (2);
	}

	dfd = open(argv[0], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0) { perror("open dir"); return (1); }

	cap_rights_init(&rights, CAP_CONNECTAT, CAP_LOOKUP);
	if (cap_rights_limit(dfd, &rights) < 0 && errno != ENOSYS) {
		perror("cap_rights_limit");
		return (1);
	}
	if (cap_enter() < 0) { perror("cap_enter"); return (1); }

	cs = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cs < 0) { perror("socket"); return (1); }
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, "sock", sizeof(sun.sun_path));
	if (connectat(dfd, cs, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		perror("connectat ctl");
		return (1);
	}

	memset(&m, 0, sizeof(m));
	m.cmd = VSOCK_CTL_CONNECT;
	m.port = port;
	m.type = (uint32_t)type;
	if (write_all(cs, &m, sizeof(m)) < 0) {
		perror("write ctl");
		return (1);
	}

	if (recv_control_reply(cs, &r, &datafd) < 0) {
		perror("receive control reply");
		return (1);
	}
	if (r.cmd != VSOCK_CTL_CONNECT || r.port != m.port) {
		fprintf(stderr, "invalid control reply: cmd=%u port=%u\n",
		    r.cmd, r.port);
		return (1);
	}
	if (r.status != 0) {
		fprintf(stderr, "connect refused: status=%d (%s)\n",
		    r.status, strerror(-r.status));
		return (4);
	}
	if (datafd < 0) {
		fprintf(stderr, "no data fd returned\n");
		return (1);
	}
	close(cs);
	if (oneshot)
		return (relay_oneshot(datafd, type == SOCK_SEQPACKET));
	if (wait_disconnect)
		return (wait_for_disconnect(datafd, type == SOCK_SEQPACKET));
	return (relay(datafd, type == SOCK_SEQPACKET));
}
