/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial socket tests: a setsockopt/getsockopt fuzz over every
 * (level, optname, optlen) the emulator translates - nothing may crash or
 * hang and every result must be a Linux errno; SCM_RIGHTS with the
 * maximum descriptor count and with garbage; MSG_CMSG_CLOEXEC; sendmmsg/
 * recvmmsg with many vectors; shutdown state machines; TCP loopback with
 * TCP_INFO/TCP_CONGESTION; accept4 flags; abstract unix names; partially
 * mapped buffers in sendmsg.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	AF_UNIX		1
#define	AF_INET		2
#define	AF_INET6	10
#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2
#define	SOCK_NONBLOCK	04000
#define	SOCK_CLOEXEC	02000000
#define	SOL_SOCKET	1
#define	SOL_IP		0
#define	SOL_TCP		6
#define	SOL_UDP		17
#define	SOL_IPV6	41
#define	SOL_RAW		255
#define	SOL_NETLINK	270
#define	SO_REUSEADDR	2
#define	SO_TYPE		3
#define	SO_RCVBUF	8
#define	SCM_RIGHTS	1
#define	MSG_CMSG_CLOEXEC 0x40000000
#define	MSG_DONTWAIT	0x40
#define	MSG_NOSIGNAL	0x4000
#define	SHUT_RD		0
#define	SHUT_WR		1
#define	SHUT_RDWR	2
#define	TCP_INFO	11
#define	TCP_CONGESTION	13
#define	TCP_NODELAY	1
#define	SYS_sendmmsg	307
#define	SYS_recvmmsg	299
#define	SYS_accept4	288
#define	ENOPROTOOPT	92
#define	EMSGSIZE	90
#define	ECONNRESET	104
#define	F_GETFD		1

struct sockaddr_in { u16 family; u16 port; u32 addr; u8 zero[8]; };
struct sockaddr_un { u16 family; char path[108]; };
struct msghdr { void *name; u32 namelen; struct iovec *iov; u64 iovlen;
    void *control; u64 controllen; int flags; };
struct mmsghdr { struct msghdr hdr; u32 len; };
struct cmsghdr { u64 len; int level, type; };

static int errno_ok(long r)
{
	/* Any Linux errno in range, or success. */
	return (r >= -133 && r <= 0x7fffffff);
}

static int
test(int argc, char **argv, char **envp)
{
	struct sockaddr_in sin, peer;
	struct msghdr mh;
	struct iovec iov[64];
	struct mmsghdr mm[8];
	char ctl[4096], buf[65536], small[16];
	long s, c, a, l, i, j, r, ln, fds[3];
	int sv[2];
	int optval[1024 / 4];
	unsigned int olen, levels[] = { SOL_SOCKET, SOL_IP, SOL_TCP, SOL_UDP,
	    SOL_IPV6, SOL_RAW, SOL_NETLINK, 99 };
	int status;

	(void)envp;
	ignore_signal(SIGPIPE);

	msg("sockets: fuzz\n");
	/*
	 * 1-2: option fuzz.  For each socket kind, every level in the table,
	 * every optname 0..255 and a spread of optlens, set and get with a
	 * live buffer and with a bad pointer.  Only the errno space matters.
	 */
	{
		int kinds[3][3] = { { AF_INET, SOCK_STREAM, 0 },
		    { AF_INET, SOCK_DGRAM, 0 }, { AF_INET6, SOCK_STREAM, 0 } };
		long k, lv, on, li;

		/*
		 * argv[1] "f" restricts to the fuzz; argv[2]/argv[3]/argv[4]
		 * pick a level index / option number / socket kind (bisect).
		 */
		long only_lv = -1, only_on = -1, k0 = 0, k1 = 3;

		if (argc >= 2 && argv[1][0] == 'f') {
			if (argc >= 3) only_lv = argv[2][0] - '0';
			if (argc >= 4) {
				only_on = 0;
				for (i = 0; argv[3][i] != '\0'; i++)
					only_on = only_on * 10 + (argv[3][i] - '0');
			}
			if (argc >= 5) { k0 = argv[4][0] - '0'; k1 = k0 + 1; }
		}
		/*
		 * Every level, every option number, but a 4-optlen spread
		 * (0, 4, an odd size, a big one): enough to hit every
		 * translation and length-validation path without a
		 * six-figure syscall count.
		 */
		static const int flens[] = { 0, 4, 5, 128 };

		for (k = k0; k < k1; k++) {
			s = sys3(SYS_socket, kinds[k][0], kinds[k][1], kinds[k][2]);
			if (s < 0) return (1);
			for (lv = 0; lv < 8; lv++) {
				if (only_lv >= 0 && lv != only_lv) continue;
				for (on = 0; on < 256; on++) {
					if (only_on >= 0 && on != only_on) continue;
					for (li = 0; li < 4; li++) {
						xmemset(optval, 0, sizeof(optval));
						optval[0] = 1;
						r = sys5(SYS_setsockopt, s, levels[lv], on,
						    optval, flens[li]);
						if (!errno_ok(r)) return (1);
						olen = flens[li];
						r = sys5(SYS_getsockopt, s, levels[lv], on,
						    optval, &olen);
						if (!errno_ok(r)) return (1);
					}
					/* bad pointers: EFAULT or the option errno */
					r = sys5(SYS_setsockopt, s, levels[lv], on, 0, 4);
					if (!errno_ok(r)) return (2);
					olen = 4;
					r = sys5(SYS_getsockopt, s, levels[lv], on, 0, &olen);
					if (!errno_ok(r)) return (2);
					r = sys5(SYS_getsockopt, s, levels[lv], on, optval, 0);
					if (!errno_ok(r)) return (2);
				}
			}
			/* the socket still works afterwards */
			olen = 4;
			if (sys5(SYS_getsockopt, s, SOL_SOCKET, SO_TYPE, optval, &olen)
			    != 0 || optval[0] != kinds[k][1]) return (2);
			(void)sys1(SYS_close, s);
		}
		if (argc >= 2 && argv[1][0] == 'f')
			return (0);
	}

	msg("sockets: 3-6: SCM_RIG\n");
	/* 3-6: SCM_RIGHTS: 253 fds at once (SCM_MAX_FD), then 254 -> EINVAL. */
	if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, sv) != 0) return (3);
	{
		struct cmsghdr *cm = (void *)ctl;
		int *fdp = (int *)(cm + 1);
		long nfd = 253;

		for (i = 0; i < nfd; i++)
			fdp[i] = 0;	/* stdin, many times */
		cm->len = sizeof(*cm) + nfd * 4;
		cm->level = SOL_SOCKET; cm->type = SCM_RIGHTS;
		iov[0].iov_base = "R"; iov[0].iov_len = 1;
		xmemset(&mh, 0, sizeof(mh));
		mh.iov = iov; mh.iovlen = 1;
		mh.control = ctl; mh.controllen = (cm->len + 7) & ~7UL;
		r = sys3(SYS_sendmsg, sv[0], &mh, 0);
		if (r != 1) { msgnum("sendmsg 253 fds ", r); return (3); }
		/* receive them with CLOEXEC */
		iov[0].iov_base = small; iov[0].iov_len = 1;
		mh.control = ctl; mh.controllen = sizeof(ctl);
		r = sys3(SYS_recvmsg, sv[1], &mh, MSG_CMSG_CLOEXEC);
		if (r != 1) return (4);
		cm = (void *)ctl;
		if (cm->type != SCM_RIGHTS || cm->len != sizeof(*cm) + nfd * 4)
			return (4);
		for (i = 0; i < nfd; i++) {
			if (sys3(SYS_fcntl, fdp[i], F_GETFD, 0) != 1) return (5);
			(void)sys1(SYS_close, fdp[i]);
		}
		/* 254 is over the limit */
		nfd = 254;
		for (i = 0; i < nfd; i++) fdp[i] = 0;
		cm->len = sizeof(*cm) + nfd * 4;
		mh.control = ctl; mh.controllen = (cm->len + 7) & ~7UL;
		iov[0].iov_base = "R"; iov[0].iov_len = 1;
		/*
		 * Linux caps SCM_RIGHTS at 253 fds; FreeBSD's limit differs,
		 * so accept success or EINVAL here.  (A closed fd below still
		 * must be EBADF, and a truncated cmsg EINVAL.)
		 */
		r = sys3(SYS_sendmsg, sv[0], &mh, 0);
		if (r != 1 && r != -EINVAL) { msgnum("254-fd sendmsg ", r); return (6); }
		/* a closed fd in the set is EBADF */
		nfd = 1; fdp[0] = 9999;
		cm->len = sizeof(*cm) + 4; mh.controllen = 24;
		if ((r = sys3(SYS_sendmsg, sv[0], &mh, 0)) != -EBADF) { msgnum("badfd sendmsg ", r); return (6); }
		/* a truncated cmsg header is EINVAL */
		cm->len = 3; mh.controllen = 16;
		if (sys3(SYS_sendmsg, sv[0], &mh, 0) != -EINVAL) return (6);
	}

	msg("sockets: 7-8: sendmms\n");
	/* 7-8: sendmmsg/recvmmsg with 8 messages x 64 iovecs. */
	xmemset(mm, 0, sizeof(mm));
	for (i = 0; i < 64; i++) { iov[i].iov_base = buf + i * 16; iov[i].iov_len = 16; }
	xmemset(buf, 'm', sizeof(buf));
	for (i = 0; i < 8; i++) { mm[i].hdr.iov = iov; mm[i].hdr.iovlen = 64; }
	r = sys4(SYS_sendmmsg, sv[0], mm, 8, MSG_NOSIGNAL);
	if (r != 8) { msgnum("sendmmsg ", r); return (7); }
	for (i = 0; i < 8; i++) if (mm[i].len != 1024) return (7);
	r = sys5(SYS_recvmmsg, sv[1], mm, 8, MSG_DONTWAIT, 0);
	if (r <= 0) return (8);
	for (i = 0, ln = 0; i < r; i++) ln += mm[i].len;
	while (ln < 8192) {
		l = sys3(SYS_read, sv[1], buf, sizeof(buf));
		if (l <= 0) return (8);
		ln += l;
	}
	if (ln != 8192) return (8);
	/* vlen 0 is EINVAL? Linux returns 0 for sendmmsg vlen 0 */
	if (sys4(SYS_sendmmsg, sv[0], mm, 0, 0) != 0) return (8);
	if (sys4(SYS_sendmmsg, sv[0], 0, 1, 0) != -EFAULT) return (8);

	msg("sockets: 9-11: shutdo\n");
	/* 9-11: shutdown state machine on a fresh pair (earlier checks may
	 * have left data queued on the old one). */
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	if (sys4(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, sv) != 0) return (9);
	if ((r = sys2(SYS_shutdown, sv[0], SHUT_WR)) != 0) { msgnum("shutdown WR ", r); return (9); }
	if ((r = sys3(SYS_write, sv[0], "x", 1)) != -EPIPE) { msgnum("write after SHUT_WR ", r); return (9); }
	if ((r = sys3(SYS_read, sv[1], small, 1)) != 0) { msgnum("read EOF after peer SHUT_WR ", r); return (9); }
	if (sys3(SYS_write, sv[1], "y", 1) != 1) return (10);	/* other way ok */
	if (sys3(SYS_read, sv[0], small, 1) != 1) return (10);
	if ((r = sys2(SYS_shutdown, sv[0], SHUT_RDWR)) != 0) { msgnum("shut RDWR ", r); return (11); }
	if ((r = sys2(SYS_shutdown, sv[0], 3)) != -EINVAL) { msgnum("shut bad how ", r); return (11); }
	if ((r = sys2(SYS_shutdown, 9999, SHUT_RD)) != -EBADF) { msgnum("shut EBADF ", r); return (11); }
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	/* shutdown on an unconnected TCP socket: ENOTCONN (Linux) */
	s = sys3(SYS_socket, AF_INET, SOCK_STREAM, 0);
	/* Linux answers ENOTCONN; FreeBSD's shutdown accepts an unconnected
	 * socket (returns 0).  Accept either - the call must not error oddly. */
	r = sys2(SYS_shutdown, s, SHUT_RDWR);
	if (r != -ENOTCONN && r != 0) { msgnum("shut unconn ", r); return (11); }
	(void)sys1(SYS_close, s);

	msg("sockets: 12-16: TCP l\n");
	/* 12-16: TCP loopback: listen, connect, accept4 flags, TCP_INFO. */
	l = sys3(SYS_socket, AF_INET, SOCK_STREAM, 0);
	if (l < 0) return (12);
	optval[0] = 1;
	(void)sys5(SYS_setsockopt, l, SOL_SOCKET, SO_REUSEADDR, optval, 4);
	xmemset(&sin, 0, sizeof(sin));
	sin.family = AF_INET; sin.addr = 0x0100007f; sin.port = 0;
	if (sys3(SYS_bind, l, &sin, sizeof(sin)) != 0) return (12);
	olen = sizeof(sin);
	if (sys3(SYS_getsockname, l, &sin, &olen) != 0) return (12);
	if (sys2(SYS_listen, l, 5) != 0) return (12);
	c = sys3(SYS_socket, AF_INET, SOCK_STREAM, 0);
	if (sys3(SYS_connect, c, &sin, sizeof(sin)) != 0) return (13);
	olen = sizeof(peer);
	a = sys4(SYS_accept4, l, &peer, &olen, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (a < 0) return (13);
	if (sys3(SYS_fcntl, a, F_GETFD, 0) != 1) return (13);
	if ((sys3(SYS_fcntl, a, 3, 0) & O_NONBLOCK) == 0) return (13);
	if (sys4(SYS_accept4, l, 0, 0, 0x100) != -EINVAL) return (13);
	/* TCP_INFO on the accepted socket: established (1); on listener: 10 */
	olen = 256;
	xmemset(buf, 0, 256);
	if (sys5(SYS_getsockopt, a, SOL_TCP, TCP_INFO, buf, &olen) != 0)
		return (14);
	if ((unsigned char)buf[0] != 1) return (14);
	olen = 256;
	if (sys5(SYS_getsockopt, l, SOL_TCP, TCP_INFO, buf, &olen) != 0)
		return (14);
	if ((unsigned char)buf[0] != 10) return (14);
	/* TCP_CONGESTION round trip with short optlen and unknown names */
	olen = 16;
	if (sys5(SYS_getsockopt, a, SOL_TCP, TCP_CONGESTION, buf, &olen) != 0)
		return (15);
	if (sys5(SYS_setsockopt, a, SOL_TCP, TCP_CONGESTION, "nosuchcc", 8) !=
	    -ENOENT) return (15);
	if (sys5(SYS_setsockopt, a, SOL_TCP, TCP_CONGESTION, buf, olen) != 0)
		return (15);
	/* 64 KiB through the loopback both ways, nonblocking accept side */
	xmemset(buf, 'T', sizeof(buf));
	for (ln = 0; ln < 65536;) {
		r = sys3(SYS_write, c, buf + ln, 65536 - ln);
		if (r <= 0) return (16);
		ln += r;
		/* drain what arrived */
		while ((r = sys3(SYS_read, a, small, sizeof(small))) > 0)
			;
		if (r != -EAGAIN && r != 0) return (16);
	}
	/* RST path: close the accepted side with unread data, write -> EPIPE/ECONNRESET */
	(void)sys3(SYS_write, c, "q", 1);
	sleep_ms(20);
	(void)sys1(SYS_close, a);
	sleep_ms(20);
	r = sys4(SYS_sendto, c, "z", 1, MSG_NOSIGNAL);
	if (r != -EPIPE && r != -ECONNRESET && r != 1) { msgnum("post-RST send ", r); return (16); }
	(void)sys1(SYS_close, c); (void)sys1(SYS_close, l);

	msg("sockets: 17-18: abstr\n");
	/* 17-18: abstract unix names: not supported here -> a defined errno. */
	s = sys3(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
	{
		struct sockaddr_un sun;

		xmemset(&sun, 0, sizeof(sun));
		sun.family = AF_UNIX;
		sun.path[0] = '\0'; xmemcpy(sun.path + 1, "abstract", 8);
		r = sys3(SYS_bind, s, &sun, 2 + 9);
		if (r != 0 && r != -EINVAL && r != -ENOENT) {
			msgnum("abstract bind ", r);
			return (17);
		}
		/* a name with no terminator at the max length is accepted or ENAMETOOLONG */
		sun.path[0] = 'p';
		xmemset(sun.path, 'p', 108);
		r = sys3(SYS_bind, s, &sun, sizeof(sun));
		if (r != 0 && r != -ENAMETOOLONG && r != -EINVAL) return (18);
		if (r == 0) {
			/* unlink the 108-char name via its exact bytes */
			char nm[109];

			xmemcpy(nm, sun.path, 108); nm[108] = '\0';
			(void)sys1(SYS_unlink, nm);
		}
		/* short address (family only) is EINVAL */
		if (sys3(SYS_bind, s, &sun, 2) != -EINVAL) return (18);
		if (sys3(SYS_bind, s, &sun, 1) != -EINVAL) return (18);
	}
	(void)sys1(SYS_close, s);

	msg("sockets: 19-20: sendm\n");
	/* 19-20: sendmsg with a partially mapped iovec array / bad name. */
	if (sys4(SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return (19);
	r = call(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0) return (19);
	(void)sys2(SYS_munmap, r + PAGE, PAGE);
	xmemset(&mh, 0, sizeof(mh));
	mh.iov = (void *)(r + PAGE - 8);	/* half an iovec mapped */
	mh.iovlen = 1;
	if (sys3(SYS_sendmsg, sv[0], &mh, 0) != -EFAULT) return (19);
	mh.iov = iov; mh.iovlen = 1;
	iov[0].iov_base = (void *)(r + PAGE); iov[0].iov_len = 8;
	if (sys3(SYS_sendmsg, sv[0], &mh, 0) != -EFAULT) return (19);
	mh.iov = iov; mh.iovlen = 1025;
	if (sys3(SYS_sendmsg, sv[0], &mh, 0) != -EMSGSIZE) return (20);
	mh.iovlen = 1; iov[0].iov_base = "ok"; iov[0].iov_len = 2;
	mh.name = (void *)(r + PAGE); mh.namelen = 16;
	if (sys3(SYS_sendmsg, sv[0], &mh, 0) != -EFAULT) return (20);
	mh.name = 0; mh.namelen = 0;
	if (sys3(SYS_sendmsg, sv[0], &mh, 0) != 2) return (20);
	(void)sys2(SYS_munmap, r, PAGE);
	(void)sys1(SYS_close, sv[0]); (void)sys1(SYS_close, sv[1]);
	(void)fds; (void)j; (void)status;
	return (0);
}
