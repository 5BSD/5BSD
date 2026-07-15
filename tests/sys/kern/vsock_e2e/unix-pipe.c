/*
 * unix-pipe — netcat-style AF_UNIX tool for the e2e suite (host side of
 * the bhyve vsock device: per-port sockets in the device's path= dir).
 *
 * Client:    unix-pipe [-s] <path>
 * Listener:  unix-pipe -l [-s] [-e] [-n maxconns] <path>
 *
 *   -s   SOCK_SEQPACKET instead of SOCK_STREAM
 *   -e   echo mode (listener): fork per connection, echo bytes back
 *   -n   exit after accepting this many connections (echo mode)
 *
 * Same full-duplex/half-close relay semantics as vsock-pipe.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RELAY_BUFSIZE (4U * 1024 * 1024)

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
parse_count(const char *text, long *count)
{
	char *end;
	long value;

	errno = 0;
	value = strtol(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0' || value <= 0)
		return (-1);
	*count = value;
	return (0);
}

/*
 * Enlarge a data socket's buffers so a large guest->host (or host->guest)
 * SEQPACKET record is not truncated to net.local.seqpacket.maxseqpacket (64
 * KiB).  MUST be set on the ACCEPTED/connected socket, not the listener --
 * FreeBSD does not propagate the listener's SO_RCVBUF to accepted sockets.
 */
static void
bump_bufs(int fd)
{
	int big = 4 * 1024 * 1024;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
}

static int
relay(int sfd, bool seqpacket)
{
	char *buf;
	struct pollfd pfd[2];
	bool in_open = true, sock_open = true;
	int error = 0;

	bump_bufs(sfd);
	ssize_t n;
	buf = malloc(RELAY_BUFSIZE);
	if (buf == NULL)
		return (1);

	while (sock_open || in_open) {
		pfd[0].fd = in_open ? 0 : -1;
		pfd[0].events = POLLIN;
		pfd[1].fd = sock_open ? sfd : -1;
		pfd[1].events = POLLIN;
		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			error = 1;
			break;
		}
		if (pfd[0].revents & (POLLIN | POLLHUP)) {
			do {
				n = read(0, buf, RELAY_BUFSIZE);
			} while (n < 0 && errno == EINTR);
			if (n > 0) {
				if (write_socket(sfd, buf, (size_t)n,
				    seqpacket) < 0) {
					error = 1;
					break;
				}
			} else if (n == 0) {
				(void)shutdown(sfd, SHUT_WR);
				in_open = false;
			} else {
				error = 1;
				break;
			}
		}
		if (pfd[1].revents & (POLLIN | POLLHUP)) {
			do {
				n = read(sfd, buf, RELAY_BUFSIZE);
			} while (n < 0 && errno == EINTR);
			if (n > 0) {
				if (write_all(1, buf, (size_t)n) < 0) {
					error = 1;
					break;
				}
			} else if (n == 0) {
				sock_open = false;
				if (!in_open)
					break;
			} else {
				error = 1;
				break;
			}
		}
	}
	free(buf);
	return (error);
}

static int
drain(int c)
{
	char *buf;
	ssize_t n;
	int error = 0;

	bump_bufs(c);
	buf = malloc(RELAY_BUFSIZE);
	if (buf == NULL)
		return (1);

	while ((n = read(c, buf, RELAY_BUFSIZE)) > 0)
		if (write_all(1, buf, (size_t)n) < 0) {
			error = 1;
			break;
		}
	if (n < 0)
		error = 1;
	free(buf);
	close(c);
	return (error);
}

static void
echo_conn(int c, bool seqpacket)
{
	char *buf;
	ssize_t n;

	bump_bufs(c);
	buf = malloc(RELAY_BUFSIZE);
	if (buf == NULL) {
		close(c);
		return;
	}

	while ((n = read(c, buf, RELAY_BUFSIZE)) > 0)
		if (write_socket(c, buf, (size_t)n, seqpacket) < 0)
			break;
	free(buf);
	close(c);
}

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM;
	bool listen_mode = false, echo_mode = false, drain_mode = false;
	bool count_set = false;
	long maxconns = -1;
	int ch, s;
	struct sockaddr_un sun;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	while ((ch = getopt(argc, argv, "lsen:d")) != -1) {
		switch (ch) {
		case 'l': listen_mode = true; break;
		case 's': type = SOCK_SEQPACKET; break;
		case 'e': echo_mode = true; break;
		case 'd': drain_mode = true; break;
		case 'n':
			if (parse_count(optarg, &maxconns) < 0) {
				fprintf(stderr, "invalid connection count: %s\n", optarg);
				return (2);
			}
			count_set = true;
			break;
		default:
			fprintf(stderr, "usage: %s [-s] <path> | "
			    "%s -l [-s] [-e] [-n max] <path>\n",
			    argv[0], argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) { fprintf(stderr, "path?\n"); return (2); }
	if ((!listen_mode && (echo_mode || drain_mode || count_set)) ||
	    (echo_mode && drain_mode) || (count_set && !echo_mode)) {
		fprintf(stderr, "invalid listener option combination\n");
		return (2);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	if (strlcpy(sun.sun_path, argv[0], sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		fprintf(stderr, "socket path is too long\n");
		return (2);
	}

	s = socket(AF_UNIX, type, 0);
	if (s < 0) { perror("socket"); return (1); }

	if (listen_mode) {
		(void)unlink(argv[0]);
		if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
			perror("bind"); return (1);
		}
		if (listen(s, 256) < 0) { perror("listen"); return (1); }
		if (drain_mode) {
			int c = accept(s, NULL, NULL);
			if (c < 0) { perror("accept"); return (1); }
			return (drain(c));
		}
		if (!echo_mode) {
			int c = accept(s, NULL, NULL);
			if (c < 0) { perror("accept"); return (1); }
			return (relay(c, type == SOCK_SEQPACKET));
		}
		for (long i = 0; maxconns < 0 || i < maxconns; i++) {
			int c = accept(s, NULL, NULL);
			if (c < 0) {
				if (errno == EINTR) { i--; continue; }
				perror("accept"); return (1);
			}
			switch (fork()) {
			case 0:
				close(s);
				echo_conn(c, type == SOCK_SEQPACKET);
				_exit(0);
			case -1:
				echo_conn(c, type == SOCK_SEQPACKET);
				break;
			default:
				close(c);
				break;
			}
		}
		return (0);
	}

	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		return (1);
	}
	return (relay(s, type == SOCK_SEQPACKET));
}
