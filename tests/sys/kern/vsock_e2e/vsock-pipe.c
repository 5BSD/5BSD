/*
 * vsock-pipe — netcat-style AF_VSOCK tool for the e2e suite (guest side).
 *
 * Client:    vsock-pipe [-s] <cid> <port>
 * Listener:  vsock-pipe -l [-s] [-e] <port>
 *
 *   -s   SOCK_SEQPACKET instead of SOCK_STREAM
 *   -e   echo mode (listener): fork per connection, echo bytes back
 *
 * Full-duplex poll relay: stdin EOF sends shutdown(SHUT_WR); exits when
 * the socket reaches EOF and stdin is drained.  Suitable for bulk
 * one-way transfers and interactive echo alike.
 */
#include <sys/socket.h>
#include <stdint.h>
#include <sys/vsock.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int
relay(int sfd)
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
				/* peer done sending; keep draining stdin */
			}
		}
	}
	return (0);
}

static void
echo_conn(int c)
{
	char buf[65536];
	ssize_t n;

	while ((n = read(c, buf, sizeof(buf))) > 0)
		if (write(c, buf, n) != n)
			break;
	close(c);
}

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM;
	bool listen_mode = false, echo_mode = false;
	int ch, s;
	struct sockaddr_vm sa;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	while ((ch = getopt(argc, argv, "lse")) != -1) {
		switch (ch) {
		case 'l': listen_mode = true; break;
		case 's': type = SOCK_SEQPACKET; break;
		case 'e': echo_mode = true; break;
		default:
			fprintf(stderr, "usage: %s [-s] <cid> <port> | "
			    "%s -l [-s] [-e] <port>\n", argv[0], argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;

	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_len = sizeof(sa);

	s = socket(AF_VSOCK, type, 0);
	if (s < 0) { perror("socket"); return (1); }

	if (listen_mode) {
		if (argc < 1) { fprintf(stderr, "port?\n"); return (2); }
		sa.svm_cid = VSOCK_CID_ANY;
		sa.svm_port = (uint32_t)strtoul(argv[0], NULL, 0);
		if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			perror("bind"); return (1);
		}
		if (listen(s, 128) < 0) { perror("listen"); return (1); }
		if (!echo_mode) {
			int c = accept(s, NULL, NULL);
			if (c < 0) { perror("accept"); return (1); }
			return (relay(c));
		}
		for (;;) {
			int c = accept(s, NULL, NULL);
			if (c < 0) {
				if (errno == EINTR)
					continue;
				perror("accept"); return (1);
			}
			switch (fork()) {
			case 0:
				close(s);
				echo_conn(c);
				_exit(0);
			case -1:
				perror("fork");
				/* FALLTHROUGH: serve inline */
				echo_conn(c);
				break;
			default:
				close(c);
				break;
			}
		}
	}

	if (argc < 2) { fprintf(stderr, "cid port?\n"); return (2); }
	sa.svm_cid = (uint32_t)strtoul(argv[0], NULL, 0);
	sa.svm_port = (uint32_t)strtoul(argv[1], NULL, 0);
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		return (errno == ECONNRESET ? 3 : 1);
	}
	return (relay(s));
}
