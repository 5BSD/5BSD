/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Socket helper for the 5BSD PF seam tests (sockets.sh, rdomain.sh): the
 * OpenBSD socket interfaces that 5BSD adds to the FreeBSD stack for PF
 * (SO_BINDANY, SO_RXQ_OVFL, IP_RECVDSTPORT, IPV6_RECVDSTPORT, divert(4)
 * sockets of protocol IPPROTO_DIVERT, SO_RTABLE).  Every mode prints its
 * results as "key=value" lines for the shell tests to match and exits
 * non-zero when an operation it needs fails.  Each mode is bounded by an
 * alarm so a test never hangs.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef IPPROTO_DIVERT
#define	IPPROTO_DIVERT	258
#endif

#define	TIMEOUT	10

static void
usage(void)
{
	fprintf(stderr,
	    "usage: sockhelper consts\n"
	    "       sockhelper bindany [-n] inet|inet6 addr\n"
	    "       sockhelper tcp-serve addr port\n"
	    "       sockhelper tcp-connect [-b srcaddr] addr port\n"
	    "       sockhelper udp-recvdst inet|inet6 addr port\n"
	    "       sockhelper rxq-ovfl [-n] port\n"
	    "       sockhelper divert inet|inet6 port [reinject]\n"
	    "       sockhelper divert-open inet|inet6\n"
	    "       sockhelper rtable n\n");
	exit(2);
}

static const char *
errname(int e)
{
	switch (e) {
	case 0:			return ("ok");
	case EPERM:		return ("EPERM");
	case EACCES:		return ("EACCES");
	case EINVAL:		return ("EINVAL");
	case EADDRNOTAVAIL:	return ("EADDRNOTAVAIL");
	case EADDRINUSE:	return ("EADDRINUSE");
	case ENOPROTOOPT:	return ("ENOPROTOOPT");
	case EPROTONOSUPPORT:	return ("EPROTONOSUPPORT");
	case ECONNREFUSED:	return ("ECONNREFUSED");
	case ETIMEDOUT:		return ("ETIMEDOUT");
	case ENOENT:		return ("ENOENT");
	case EINTR:		return ("EINTR");
	default:		return (strerror(e));
	}
}

static int
parse_af(const char *s)
{
	if (strcmp(s, "inet") == 0)
		return (AF_INET);
	if (strcmp(s, "inet6") == 0)
		return (AF_INET6);
	usage();
	return (-1);
}

/* Fill a sockaddr for addr (numeric) and port; returns its length. */
static socklen_t
mksa(struct sockaddr_storage *ss, const char *addr, int port)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET, addr, &sin->sin_addr) == 1) {
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		return (sizeof(*sin));
	}
	if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) == 1) {
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		return (sizeof(*sin6));
	}
	errx(2, "bad address %s", addr);
}

static const char *
sa_ntop(const struct sockaddr *sa, char *buf, size_t len)
{
	if (sa->sa_family == AF_INET)
		return (inet_ntop(AF_INET,
		    &((const struct sockaddr_in *)(const void *)sa)->sin_addr, buf, len));
	if (sa->sa_family == AF_INET6)
		return (inet_ntop(AF_INET6,
		    &((const struct sockaddr_in6 *)(const void *)sa)->sin6_addr, buf, len));
	snprintf(buf, len, "af%d", sa->sa_family);
	return (buf);
}

static void
ready(void)
{
	printf("READY\n");
	fflush(stdout);
}

/* The numeric values 5BSD allocated for the OpenBSD interfaces. */
static int
mode_consts(void)
{
	printf("SO_BINDANY=0x%08x\n", SO_BINDANY);
	printf("SO_RXQ_OVFL=0x%08x\n", SO_RXQ_OVFL);
	printf("SCM_RXQ_OVFL=0x%02x\n", SCM_RXQ_OVFL);
	printf("SO_RTABLE=0x%04x\n", SO_RTABLE);
	printf("SO_FIB=0x%04x\n", SO_FIB);
	printf("IP_RECVDSTPORT=%d\n", IP_RECVDSTPORT);
	printf("IPV6_RECVDSTPORT=%d\n", IPV6_RECVDSTPORT);
	printf("IPPROTO_DIVERT=%d\n", IPPROTO_DIVERT);
	return (0);
}

/*
 * Set SO_BINDANY (unless -n), read it back, then bind to addr, which the
 * caller chooses to be non-local.
 */
static int
mode_bindany(int argc, char **argv)
{
	struct sockaddr_storage ss;
	socklen_t slen, olen;
	int s, on = 1, val[2] = { 0, 0 }, noset = 0, e;

	if (argc > 0 && strcmp(argv[0], "-n") == 0) {
		noset = 1;
		argc--, argv++;
	}
	if (argc != 2)
		usage();
	s = socket(parse_af(argv[0]), SOCK_STREAM, 0);
	if (s == -1)
		err(1, "socket");
	if (!noset) {
		e = setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, sizeof(on)) ==
		    -1 ? errno : 0;
		printf("setsockopt=%s\n", errname(e));
		/* A larger buffer: the returned length must be an int. */
		olen = sizeof(val);
		if (getsockopt(s, SOL_SOCKET, SO_BINDANY, val, &olen) == -1)
			printf("getsockopt=%s\n", errname(errno));
		else
			printf("getsockopt=%s value=%d len=%u\n", errname(0),
			    val[0] != 0, (unsigned)olen);
	}
	slen = mksa(&ss, argv[1], 0);
	e = bind(s, (struct sockaddr *)&ss, slen) == -1 ? errno : 0;
	printf("bind=%s\n", errname(e));
	close(s);
	return (0);
}

static int
mode_tcp_serve(int argc, char **argv)
{
	struct sockaddr_storage ss, peer;
	socklen_t slen, plen;
	char buf[INET6_ADDRSTRLEN];
	const char msg[] = "hello from server\n";
	int s, c, on = 1;

	if (argc != 2)
		usage();
	slen = mksa(&ss, argv[0], atoi(argv[1]));
	s = socket(ss.ss_family, SOCK_STREAM, 0);
	if (s == -1)
		err(1, "socket");
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(s, (struct sockaddr *)&ss, slen) == -1)
		err(1, "bind");
	if (listen(s, 1) == -1)
		err(1, "listen");
	ready();
	plen = sizeof(peer);
	c = accept(s, (struct sockaddr *)&peer, &plen);
	if (c == -1)
		err(1, "accept");
	printf("peer=%s\n", sa_ntop((struct sockaddr *)&peer, buf,
	    sizeof(buf)));
	fflush(stdout);
	if (write(c, msg, sizeof(msg) - 1) != sizeof(msg) - 1)
		err(1, "write");
	shutdown(c, SHUT_WR);
	close(c);
	close(s);
	return (0);
}

static int
mode_tcp_connect(int argc, char **argv)
{
	struct sockaddr_storage ss, src, local;
	socklen_t slen, srclen, llen;
	char buf[256], abuf[INET6_ADDRSTRLEN];
	const char *srcaddr = NULL;
	ssize_t n, got = 0;
	int s, on = 1;

	if (argc >= 2 && strcmp(argv[0], "-b") == 0) {
		srcaddr = argv[1];
		argc -= 2, argv += 2;
	}
	if (argc != 2)
		usage();
	slen = mksa(&ss, argv[0], atoi(argv[1]));
	s = socket(ss.ss_family, SOCK_STREAM, 0);
	if (s == -1)
		err(1, "socket");
	if (srcaddr != NULL) {
		if (setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, sizeof(on)) ==
		    -1)
			err(1, "setsockopt SO_BINDANY");
		srclen = mksa(&src, srcaddr, 0);
		if (bind(s, (struct sockaddr *)&src, srclen) == -1)
			err(1, "bind %s", srcaddr);
	}
	if (connect(s, (struct sockaddr *)&ss, slen) == -1) {
		printf("connect=%s\n", errname(errno));
		return (1);
	}
	printf("connect=ok\n");
	llen = sizeof(local);
	if (getsockname(s, (struct sockaddr *)&local, &llen) == 0)
		printf("local=%s\n", sa_ntop((struct sockaddr *)&local, abuf,
		    sizeof(abuf)));
	while ((n = read(s, buf + got, sizeof(buf) - 1 - got)) > 0)
		got += n;
	buf[got] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	printf("reply=%s\n", buf);
	close(s);
	return (got > 0 ? 0 : 1);
}

/*
 * Receive one datagram with the OpenBSD destination-port control message
 * (IP_RECVDSTPORT / IPV6_RECVDSTPORT) and the destination address
 * (IP_RECVDSTADDR / IPV6_PKTINFO).
 */
static int
mode_udp_recvdst(int argc, char **argv)
{
	struct sockaddr_storage ss, from;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char data[512], cbuf[512], abuf[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN] = "none";
	socklen_t slen;
	ssize_t n;
	int af, s, on = 1, dport = -1;

	if (argc != 3)
		usage();
	af = parse_af(argv[0]);
	slen = mksa(&ss, argv[1], atoi(argv[2]));
	if (ss.ss_family != af)
		errx(2, "address family mismatch");
	s = socket(af, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");
	if (af == AF_INET) {
		if (setsockopt(s, IPPROTO_IP, IP_RECVDSTPORT, &on,
		    sizeof(on)) == -1)
			err(1, "IP_RECVDSTPORT");
		if (setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &on,
		    sizeof(on)) == -1)
			err(1, "IP_RECVDSTADDR");
	} else {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVDSTPORT, &on,
		    sizeof(on)) == -1)
			err(1, "IPV6_RECVDSTPORT");
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		    sizeof(on)) == -1)
			err(1, "IPV6_RECVPKTINFO");
	}
	if (bind(s, (struct sockaddr *)&ss, slen) == -1)
		err(1, "bind");
	ready();

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = data;
	iov.iov_len = sizeof(data) - 1;
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	n = recvmsg(s, &msg, 0);
	if (n == -1)
		err(1, "recvmsg");
	data[n] = '\0';
	data[strcspn(data, "\n")] = '\0';
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		if ((cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_RECVDSTPORT) ||
		    (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_RECVDSTPORT)) {
			uint16_t p;

			memcpy(&p, CMSG_DATA(cm), sizeof(p));
			dport = ntohs(p);
		} else if (cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_RECVDSTADDR) {
			inet_ntop(AF_INET, CMSG_DATA(cm), dst, sizeof(dst));
		} else if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo pi;

			memcpy(&pi, CMSG_DATA(cm), sizeof(pi));
			inet_ntop(AF_INET6, &pi.ipi6_addr, dst, sizeof(dst));
		}
	}
	printf("from=%s dstaddr=%s dstport=%d data=%s\n",
	    sa_ntop((struct sockaddr *)&from, abuf, sizeof(abuf)), dst, dport,
	    data);
	close(s);
	return (dport == -1 ? 1 : 0);
}

/* Return the SCM_RXQ_OVFL count of a message, or -1 if it has none. */
static long
rxq_drops(struct msghdr *msg)
{
	struct cmsghdr *cm;
	uint32_t d;

	for (cm = CMSG_FIRSTHDR(msg); cm != NULL; cm = CMSG_NXTHDR(msg, cm))
		if (cm->cmsg_level == SOL_SOCKET &&
		    cm->cmsg_type == SCM_RXQ_OVFL) {
			memcpy(&d, CMSG_DATA(cm), sizeof(d));
			return (d);
		}
	return (-1);
}

static ssize_t
recv_drops(int s, long *drops, int flags)
{
	struct msghdr msg;
	struct iovec iov;
	char data[2048], cbuf[256];
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = data;
	iov.iov_len = sizeof(data);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	n = recvmsg(s, &msg, flags);
	if (n >= 0)
		*drops = rxq_drops(&msg);
	return (n);
}

/*
 * Overflow the receive buffer of a UDP socket on 127.0.0.1:port, drain
 * it, send one more datagram and report the SCM_RXQ_OVFL count it
 * carries.  With -n SO_RXQ_OVFL stays off and no count may appear.
 */
static int
mode_rxq_ovfl(int argc, char **argv)
{
	struct sockaddr_storage ss;
	socklen_t slen, olen;
	char payload[512];
	long d, maxd = -1, last;
	int r, w, on = 1, rcvbuf = 2048, val = 0, sent = 0, queued = 0, i;
	int noset = 0;

	if (argc > 0 && strcmp(argv[0], "-n") == 0) {
		noset = 1;
		argc--, argv++;
	}
	if (argc != 1)
		usage();
	slen = mksa(&ss, "127.0.0.1", atoi(argv[0]));
	r = socket(AF_INET, SOCK_DGRAM, 0);
	w = socket(AF_INET, SOCK_DGRAM, 0);
	if (r == -1 || w == -1)
		err(1, "socket");
	if (setsockopt(r, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) ==
	    -1)
		err(1, "SO_RCVBUF");
	if (!noset &&
	    setsockopt(r, SOL_SOCKET, SO_RXQ_OVFL, &on, sizeof(on)) == -1)
		err(1, "SO_RXQ_OVFL");
	olen = sizeof(val);
	if (getsockopt(r, SOL_SOCKET, SO_RXQ_OVFL, &val, &olen) == -1)
		err(1, "getsockopt SO_RXQ_OVFL");
	printf("option=%d\n", val != 0);
	if (bind(r, (struct sockaddr *)&ss, slen) == -1)
		err(1, "bind");
	memset(payload, 'x', sizeof(payload));
	for (i = 0; i < 64; i++)
		if (sendto(w, payload, sizeof(payload), 0,
		    (struct sockaddr *)&ss, slen) == sizeof(payload))
			sent++;
	usleep(200000);
	while (recv_drops(r, &d, MSG_DONTWAIT) >= 0) {
		queued++;
		if (d > maxd)
			maxd = d;
	}
	/* One more datagram, appended after the drops. */
	if (sendto(w, payload, 16, 0, (struct sockaddr *)&ss, slen) != 16)
		err(1, "sendto");
	if (recv_drops(r, &last, 0) < 0)
		err(1, "recvmsg");
	printf("sent=%d received=%d lost=%d drops=%ld\n", sent, queued,
	    sent - queued, last);
	close(r);
	close(w);
	if (noset)
		return (last == -1 && maxd == -1 ? 0 : 1);
	return (last > 0 && last <= sent - queued ? 0 : 1);
}

static int
divert_socket(int af)
{
	return (socket(af, SOCK_RAW, IPPROTO_DIVERT));
}

static int
mode_divert_open(int argc, char **argv)
{
	int s;

	if (argc != 1)
		usage();
	s = divert_socket(parse_af(argv[0]));
	printf("socket=%s\n", errname(s == -1 ? errno : 0));
	return (s == -1);
}

/*
 * Bind a divert(4) socket to a port, receive one packet that pf diverts
 * there (divert-packet port N), print it, and optionally write it back.
 */
static int
mode_divert(int argc, char **argv)
{
	struct sockaddr_storage ss, from;
	socklen_t flen;
	char pkt[65536], abuf[INET6_ADDRSTRLEN], sbuf[INET6_ADDRSTRLEN];
	char dbuf[INET6_ADDRSTRLEN];
	int af, s, reinject = 0, proto, off;
	ssize_t n;
	uint16_t dport = 0;

	if (argc != 2 && argc != 3)
		usage();
	af = parse_af(argv[0]);
	if (argc == 3) {
		if (strcmp(argv[2], "reinject") != 0)
			usage();
		reinject = 1;
	}
	s = divert_socket(af);
	if (s == -1)
		err(1, "socket(IPPROTO_DIVERT)");
	memset(&ss, 0, sizeof(ss));
	if (af == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(atoi(argv[1]));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;

		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(atoi(argv[1]));
	}
	if (bind(s, (struct sockaddr *)&ss, ss.ss_len) == -1)
		err(1, "bind");
	ready();
	flen = sizeof(from);
	n = recvfrom(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &flen);
	if (n == -1)
		err(1, "recvfrom");
	if (af == AF_INET) {
		struct ip *ip = (struct ip *)pkt;

		if (n < (ssize_t)sizeof(*ip))
			errx(1, "short packet");
		proto = ip->ip_p;
		off = ip->ip_hl << 2;
		inet_ntop(AF_INET, &ip->ip_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &ip->ip_dst, dbuf, sizeof(dbuf));
	} else {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;

		if (n < (ssize_t)sizeof(*ip6))
			errx(1, "short packet");
		proto = ip6->ip6_nxt;
		off = sizeof(*ip6);
		inet_ntop(AF_INET6, &ip6->ip6_src, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, &ip6->ip6_dst, dbuf, sizeof(dbuf));
	}
	if ((proto == IPPROTO_UDP || proto == IPPROTO_TCP) && n >= off + 4)
		memcpy(&dport, pkt + off + 2, sizeof(dport));
	printf("from=%s proto=%d src=%s dst=%s dport=%u len=%zd\n",
	    sa_ntop((struct sockaddr *)&from, abuf, sizeof(abuf)), proto,
	    sbuf, dbuf, ntohs(dport), n);
	fflush(stdout);
	if (reinject) {
		if (sendto(s, pkt, n, 0, (struct sockaddr *)&from, flen) != n)
			err(1, "sendto (reinject)");
		printf("reinjected=ok\n");
	}
	close(s);
	return (0);
}

/* SO_RTABLE (OpenBSD name of SO_SETFIB): select a routing table. */
static int
mode_rtable(int argc, char **argv)
{
	socklen_t olen;
	int s, t, val = -1, e;

	if (argc != 1)
		usage();
	t = atoi(argv[0]);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");
	e = setsockopt(s, SOL_SOCKET, SO_RTABLE, &t, sizeof(t)) == -1 ?
	    errno : 0;
	olen = sizeof(val);
	if (getsockopt(s, SOL_SOCKET, SO_RTABLE, &val, &olen) == -1)
		err(1, "getsockopt SO_RTABLE");
	printf("setsockopt=%s rtable=%d\n", errname(e), val);
	close(s);
	return (0);
}

static void
timeout(int sig __unused)
{
	static const char msg[] = "timeout\n";

	write(STDOUT_FILENO, msg, sizeof(msg) - 1);
	_exit(3);
}

int
main(int argc, char **argv)
{
	const char *mode;

	if (argc < 2)
		usage();
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGALRM, timeout);
	alarm(TIMEOUT);
	mode = argv[1];
	argc -= 2;
	argv += 2;
	if (strcmp(mode, "consts") == 0)
		return (mode_consts());
	if (strcmp(mode, "bindany") == 0)
		return (mode_bindany(argc, argv));
	if (strcmp(mode, "tcp-serve") == 0)
		return (mode_tcp_serve(argc, argv));
	if (strcmp(mode, "tcp-connect") == 0)
		return (mode_tcp_connect(argc, argv));
	if (strcmp(mode, "udp-recvdst") == 0)
		return (mode_udp_recvdst(argc, argv));
	if (strcmp(mode, "rxq-ovfl") == 0)
		return (mode_rxq_ovfl(argc, argv));
	if (strcmp(mode, "divert") == 0)
		return (mode_divert(argc, argv));
	if (strcmp(mode, "divert-open") == 0)
		return (mode_divert_open(argc, argv));
	if (strcmp(mode, "rtable") == 0)
		return (mode_rtable(argc, argv));
	usage();
	return (2);
}
