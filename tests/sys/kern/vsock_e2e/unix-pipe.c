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
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
relay(int sfd)
{
	char buf[65536];
	struct pollfd pfd[2];
	bool in_open = true, sock_open = true;

	bump_bufs(sfd);
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
			n = read(0, buf, sizeof(buf));
			if (n > 0) {
				if (write(sfd, buf, n) != n)
					return (1);
			} else {
				(void)shutdown(sfd, SHUT_WR);
				in_open = false;
			}
		}
		if (pfd[1].revents & (POLLIN | POLLHUP)) {
			n = read(sfd, buf, sizeof(buf));
			if (n > 0) {
				if (write(1, buf, n) != n)
					return (1);
			} else {
				sock_open = false;
				if (!in_open)
					break;
			}
		}
	}
	return (0);
}

static int
drain(int c)
{
	char buf[65536];
	ssize_t n;

	bump_bufs(c);

	while ((n = read(c, buf, sizeof(buf))) > 0)
		if (write(1, buf, n) != n)
			return (1);
	close(c);
	return (n < 0 ? 1 : 0);
}

static void
echo_conn(int c)
{
	char buf[65536];
	ssize_t n;

	bump_bufs(c);

	while ((n = read(c, buf, sizeof(buf))) > 0)
		if (write(c, buf, n) != n)
			break;
	close(c);
}

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM;
	bool listen_mode = false, echo_mode = false, drain_mode = false;
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
		case 'n': maxconns = strtol(optarg, NULL, 0); break;
		default:
			fprintf(stderr, "usage: %s [-s] <path> | "
			    "%s -l [-s] [-e] [-n max] <path>\n",
			    argv[0], argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1) { fprintf(stderr, "path?\n"); return (2); }

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(sun);
	strlcpy(sun.sun_path, argv[0], sizeof(sun.sun_path));

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
			return (relay(c));
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
				echo_conn(c);
				_exit(0);
			case -1:
				echo_conn(c);
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
	return (relay(s));
}
