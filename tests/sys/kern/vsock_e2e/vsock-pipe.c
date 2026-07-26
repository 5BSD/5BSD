/*
 * vsock-pipe — netcat-style AF_VSOCK tool for the e2e suite (guest side).
 *
 * Client:    vsock-pipe [-s] [-1|-w] <cid> <port>
 * Listener:  vsock-pipe -l [-s] [-e] [-n maxconns] <port>
 *
 *   -s   SOCK_SEQPACKET instead of SOCK_STREAM
 *   -e   echo mode (listener): fork per connection, echo bytes back
 *   -n   exit after accepting this many connections (echo mode)
 *   -w   verify a built-in echo, then wait for peer disconnect
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
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RELAY_BUFSIZE (4U * 1024 * 1024)
#define VSOCK_RECORD_MAX (256U * 1024)

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

static int
parse_u32(const char *text, uint32_t *value)
{
	char *end;
	uintmax_t parsed;

	errno = 0;
	parsed = strtoumax(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX)
		return (-1);
	*value = (uint32_t)parsed;
	return (0);
}

static void
bump_bufs(int fd)
{
	int big = RELAY_BUFSIZE;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
}

/*
 * -1: slurp all of stdin and send it as a SINGLE record with MSG_EOR (SEQPACKET)
 * so a guest->host record larger than one stdin read() chunk is delivered as one
 * record, then drain the reply.  A record is bounded by the transport's
 * advertised receive window; bhyve and Linux default and cap it at 256 KiB.
 */
static int
relay_oneshot(int sfd, bool seqpacket)
{
	size_t cap = VSOCK_RECORD_MAX, len = 0;
	char *buf = malloc(cap);
	char extra;
	ssize_t n;

	if (buf == NULL) { perror("malloc"); return (1); }
	while (len < cap) {
		n = read(0, buf + len, cap - len);
		if (n < 0) { if (errno == EINTR) continue; perror("read");
			free(buf); return (1); }
		if (n == 0) break;
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
				fprintf(stderr,
				    "input exceeds 256 KiB record limit\n");
			free(buf);
			return (1);
		}
	}
	if (seqpacket) {
		struct iovec io = { buf, len };
		struct msghdr mh;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov = &io; mh.msg_iovlen = 1;
		if (sendmsg(sfd, &mh, MSG_EOR) != (ssize_t)len) {
			perror("sendmsg"); free(buf); return (1);
		}
	} else if (write(sfd, buf, len) != (ssize_t)len) {
		perror("write"); free(buf); return (1);
	}
	(void)shutdown(sfd, SHUT_WR);
	for (;;) {
		n = read(sfd, buf, cap);
		if (n < 0) { if (errno == EINTR) continue; break; }
		if (n == 0) break;
		if (write(1, buf, (size_t)n) != n) break;
	}
	free(buf);
	return (0);
}

static int
relay(int sfd, bool seqpacket)
{
	char *buf;
	struct pollfd pfd[2];
	bool in_open = true, sock_open = true;
	int error = 0;
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
			n = read(0, buf, RELAY_BUFSIZE);
			if (n > 0) {
				if (write_socket(sfd, buf, (size_t)n,
				    seqpacket) < 0) {
					error = 1;
					break;
				}
			} else if (n == 0) {
				(void)shutdown(sfd, SHUT_WR);
				in_open = false;
			} else if (errno != EINTR) {
				error = 1;
				break;
			}
		}
		if (pfd[1].revents & (POLLIN | POLLHUP)) {
			n = read(sfd, buf, RELAY_BUFSIZE);
			if (n > 0) {
				if (write_all(1, buf, (size_t)n) < 0) {
					error = 1;
					break;
				}
			} else if (n == 0) {
				sock_open = false;
				if (!in_open)
					break;
				/* peer done sending; keep draining stdin */
			} else if (errno != EINTR) {
				error = 1;
				break;
			}
		}
	}
	free(buf);
	return (error);
}

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

static int
drain(int c)
{
	char *buf;
	ssize_t n;
	int error = 0;

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
	bool oneshot = false, wait_disconnect = false, count_set = false;
	long maxconns = -1, accepted = 0;
	int ch, s;
	struct sockaddr_vm sa;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	while ((ch = getopt(argc, argv, "lsen:d1w")) != -1) {
		switch (ch) {
		case 'l': listen_mode = true; break;
		case 's': type = SOCK_SEQPACKET; break;
		case 'e': echo_mode = true; break;
		case 'd': drain_mode = true; break;
		case '1': oneshot = true; break;  /* send all stdin as ONE record */
		case 'w': wait_disconnect = true; break;
		case 'n':
			if (parse_count(optarg, &maxconns) < 0) {
				fprintf(stderr, "invalid connection count: %s\n", optarg);
				return (2);
			}
			count_set = true;
			break;
		default:
			fprintf(stderr, "usage: %s [-s] [-1|-w] <cid> <port> | "
			    "%s -l [-s] [-e] [-n max] <port>\n", argv[0], argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;

	memset(&sa, 0, sizeof(sa));
	sa.svm_family = AF_VSOCK;
	sa.svm_len = sizeof(sa);
	if ((!listen_mode && (echo_mode || drain_mode || count_set)) ||
	    (listen_mode && (oneshot || wait_disconnect)) ||
	    (echo_mode && drain_mode) || (count_set && !echo_mode) ||
	    (oneshot && wait_disconnect)) {
		fprintf(stderr, "invalid option combination\n");
		return (2);
	}
	if (listen_mode) {
		if (argc != 1 || parse_u32(argv[0], &sa.svm_port) < 0) {
			fprintf(stderr, "invalid port\n");
			return (2);
		}
		sa.svm_cid = VSOCK_CID_ANY;
	} else {
		if (argc != 2 || parse_u32(argv[0], &sa.svm_cid) < 0 ||
		    parse_u32(argv[1], &sa.svm_port) < 0) {
			fprintf(stderr, "invalid CID or port\n");
			return (2);
		}
	}

	s = socket(AF_VSOCK, type, 0);
	if (s < 0) { perror("socket"); return (1); }

	if (listen_mode) {
		if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			perror("bind"); return (1);
		}
		if (listen(s, 128) < 0) { perror("listen"); return (1); }
		if (drain_mode) {
			int c = accept(s, NULL, NULL);
			if (c < 0) { perror("accept"); return (1); }
			bump_bufs(c);
			return (drain(c));
		}
		if (!echo_mode) {
			int c = accept(s, NULL, NULL);
			if (c < 0) { perror("accept"); return (1); }
			bump_bufs(c);
			return (relay(c, type == SOCK_SEQPACKET));
		}
		for (;;) {
			int c = accept(s, NULL, NULL);
			if (c < 0) {
				if (errno == EINTR)
					continue;
				perror("accept"); return (1);
			}
			bump_bufs(c);
			accepted++;
			switch (fork()) {
			case 0:
				close(s);
				echo_conn(c, type == SOCK_SEQPACKET);
				_exit(0);
			case -1:
				perror("fork");
				/* FALLTHROUGH: serve inline */
				echo_conn(c, type == SOCK_SEQPACKET);
				break;
			default:
				close(c);
				break;
			}
			if (maxconns > 0 && accepted >= maxconns)
				return (0);
		}
	}

	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		return (errno == ECONNRESET ? 3 : 1);
	}
	bump_bufs(s);
	if (oneshot)
		return (relay_oneshot(s, type == SOCK_SEQPACKET));
	if (wait_disconnect)
		return (wait_for_disconnect(s, type == SOCK_SEQPACKET));
	return (relay(s, type == SOCK_SEQPACKET));
}
