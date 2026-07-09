/*
 * vsh-connect — host→guest connector through the bhyve vsock device's
 * control socket (e2e suite version).
 *
 * usage: vsh-connect [-s] <dir> <port>
 *
 *   -s   request SOCK_SEQPACKET
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
			}
		}
	}
	return (0);
}

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM;
	int ch, dfd, cs, datafd = -1;
	cap_rights_t rights;
	struct sockaddr_un sun;
	struct vsock_ctl_msg m, r;
	struct iovec io;
	struct msghdr mh;
	char cbuf[CMSG_SPACE(sizeof(int))];
	ssize_t rn;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		case 's': type = SOCK_SEQPACKET; break;
		default:
			fprintf(stderr, "usage: %s [-s] <dir> <port>\n",
			    argv[0]);
			return (2);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2) {
		fprintf(stderr, "usage: vsh-connect [-s] <dir> <port>\n");
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
	m.port = (uint32_t)strtoul(argv[1], NULL, 0);
	m.type = (uint32_t)type;
	if (write(cs, &m, sizeof(m)) != sizeof(m)) {
		perror("write ctl");
		return (1);
	}

	memset(cbuf, 0, sizeof(cbuf));
	io.iov_base = &r;
	io.iov_len = sizeof(r);
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &io;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);
	rn = recvmsg(cs, &mh, 0);
	if (rn < 0) { perror("recvmsg"); return (1); }
	if (rn != (ssize_t)sizeof(r)) {
		fprintf(stderr, "short/closed ctl reply (%zd bytes)\n", rn);
		return (1);
	}
	if (r.status != 0) {
		fprintf(stderr, "connect refused: status=%d (%s)\n",
		    r.status, strerror(-r.status));
		return (4);
	}
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c != NULL;
	    c = CMSG_NXTHDR(&mh, c))
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
			memcpy(&datafd, CMSG_DATA(c), sizeof(datafd));
	if (datafd < 0) {
		fprintf(stderr, "no data fd returned\n");
		return (1);
	}
	close(cs);
	return (relay(datafd));
}
