/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Traffic helper for the dummynet seam tests (dummynet.sh): bulk TCP
 * transfers timed at the receiver, and UDP probes that measure the
 * one-way delay in each direction and the loss.  All jails share the
 * host's CLOCK_MONOTONIC, so a timestamp taken by the sender in one VNET
 * jail can be compared with one taken by the receiver in another.
 *
 *   sink	TCP receiver: accepts n connections (each in its own process)
 *		and prints "port bytes ms" for each, ms being the time from
 *		its first to its last byte.  With -w, a connection is closed
 *		w seconds after its first byte, so concurrent flows are
 *		compared over the same time window.
 *   send	TCP sender: writes for up to t seconds or until the receiver
 *		closes; prints "bytes ms".
 *   uecho	UDP echo server: stamps each probe with its receive time and
 *		returns it (unless -q); prints "recv n peer addr" on exit
 *		(-T timeout, SIGTERM or SIGINT).
 *   uprobe	UDP prober: sends n probes i ms apart and prints
 *		"sent n recv m fwd_min x fwd_med x back_min x back_med x
 *		rtt_min x rtt_med x" (milliseconds; "-" without replies).
 *
 * Every mode is bounded by an alarm so a test never hangs.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	PROBE_MAGIC	0x646e666cU	/* "dnfl" */
#define	MAXPROBES	100000
#define	MAXDGRAM	9000

struct probe {
	uint32_t	magic;
	uint32_t	seq;
	uint64_t	tx;		/* sender's CLOCK_MONOTONIC, ns */
	uint64_t	rx;		/* echo server's CLOCK_MONOTONIC, ns */
};

static volatile sig_atomic_t stop;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: dnflow sink [-6] [-b addr] -p port [-n conns] [-w secs] "
	    "[-T secs]\n"
	    "       dnflow send [-t secs] [-T secs] addr port\n"
	    "       dnflow uecho [-6q] [-b addr] -p port [-T secs]\n"
	    "       dnflow uprobe [-n count] [-i ms] [-W ms] [-s size] "
	    "addr port\n");
	exit(2);
}

static uint64_t
now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		err(1, "clock_gettime");
	return ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec);
}

static void
on_signal(int sig __unused)
{
	stop = 1;
}

/* Install a handler that interrupts blocking calls (no SA_RESTART). */
static void
catch(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, NULL) != 0)
		err(1, "sigaction");
}

static long
number(const char *s, long min, long max, const char *what)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < min || v > max)
		errx(2, "bad %s: %s", what, s);
	return (v);
}

static void
resolve(const char *addr, const char *port, int socktype,
    struct sockaddr_storage *ss, socklen_t *len)
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	error = getaddrinfo(addr, port, &hints, &res);
	if (error != 0)
		errx(2, "%s port %s: %s", addr, port, gai_strerror(error));
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	*len = res->ai_addrlen;
	freeaddrinfo(res);
}

static int
bound_socket(const char *addr, const char *port, int socktype)
{
	struct sockaddr_storage ss;
	socklen_t len;
	int s, on = 1;

	resolve(addr, port, socktype, &ss, &len);
	s = socket(ss.ss_family, socktype, 0);
	if (s < 0)
		err(1, "socket");
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
		err(1, "SO_REUSEADDR");
	if (bind(s, (struct sockaddr *)&ss, len) != 0)
		err(1, "bind %s port %s", addr, port);
	return (s);
}

/* One line, one write(2): lines from concurrent processes stay whole. */
static void
emit(const char *fmt, ...) __printflike(1, 2);

static void
emit(const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n > 0)
		(void)write(STDOUT_FILENO, line,
		    (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
}

static void
sink_conn(int fd, int port, long window, long timeout)
{
	static char buf[65536];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	uint64_t first = 0, last = 0, t, bytes = 0;
	ssize_t n;

	catch(SIGALRM);
	alarm((unsigned)timeout);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
		err(1, "SO_RCVTIMEO");
	while (!stop) {
		n = read(fd, buf, sizeof(buf));
		t = now_ns();
		if (n > 0) {
			if (first == 0)
				first = t;
			last = t;
			bytes += (uint64_t)n;
		} else if (n == 0 || (errno != EAGAIN && errno != EINTR))
			break;
		if (first != 0 && window > 0 &&
		    t - first >= (uint64_t)window * 1000000000ULL)
			break;
	}
	emit("%d %ju %ju\n", port, (uintmax_t)bytes,
	    (uintmax_t)((last - first) / 1000000));
	close(fd);
}

static int
do_sink(int argc, char **argv)
{
	const char *addr = NULL, *port = NULL;
	long conns = 1, window = 0, timeout = 120, i;
	int ch, s, fd, v6 = 0, status, rv = 0;
	pid_t pid;

	while ((ch = getopt(argc, argv, "6b:n:p:T:w:")) != -1) {
		switch (ch) {
		case '6':
			v6 = 1;
			break;
		case 'b':
			addr = optarg;
			break;
		case 'n':
			conns = number(optarg, 1, 1024, "connection count");
			break;
		case 'p':
			port = optarg;
			break;
		case 'T':
			timeout = number(optarg, 1, 3600, "timeout");
			break;
		case 'w':
			window = number(optarg, 1, 3600, "window");
			break;
		default:
			usage();
		}
	}
	if (port == NULL || optind != argc)
		usage();
	if (addr == NULL)
		addr = v6 ? "::" : "0.0.0.0";

	alarm((unsigned)timeout + 5);
	s = bound_socket(addr, port, SOCK_STREAM);
	if (listen(s, (int)conns) != 0)
		err(1, "listen");
	for (i = 0; i < conns; i++) {
		fd = accept(s, NULL, NULL);
		if (fd < 0)
			err(1, "accept");
		pid = fork();
		if (pid < 0)
			err(1, "fork");
		if (pid == 0) {
			close(s);
			sink_conn(fd, atoi(port), window, timeout);
			_exit(0);
		}
		close(fd);
	}
	close(s);
	while (wait(&status) > 0)
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			rv = 1;
	return (rv);
}

static int
do_send(int argc, char **argv)
{
	static char buf[65536];
	struct sockaddr_storage ss;
	socklen_t len;
	uint64_t start, t, limit, bytes = 0;
	long secs = 30, timeout = 120;
	ssize_t n;
	int ch, s = -1, i;

	while ((ch = getopt(argc, argv, "t:T:")) != -1) {
		switch (ch) {
		case 't':
			secs = number(optarg, 1, 3600, "duration");
			break;
		case 'T':
			timeout = number(optarg, 1, 3600, "timeout");
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();

	signal(SIGPIPE, SIG_IGN);
	catch(SIGALRM);
	alarm((unsigned)timeout);
	resolve(argv[0], argv[1], SOCK_STREAM, &ss, &len);
	memset(buf, 'd', sizeof(buf));

	/* The receiver may still be starting: retry for 20 seconds. */
	for (i = 0; i < 100 && !stop; i++) {
		s = socket(ss.ss_family, SOCK_STREAM, 0);
		if (s < 0)
			err(1, "socket");
		if (connect(s, (struct sockaddr *)&ss, len) == 0)
			break;
		if (errno != ECONNREFUSED && errno != ETIMEDOUT &&
		    errno != EHOSTUNREACH && errno != ENETUNREACH)
			err(1, "connect %s port %s", argv[0], argv[1]);
		close(s);
		s = -1;
		usleep(200000);
	}
	if (s < 0)
		errx(1, "cannot connect to %s port %s", argv[0], argv[1]);

	start = now_ns();
	limit = (uint64_t)secs * 1000000000ULL;
	for (t = start; t - start < limit && !stop; t = now_ns()) {
		n = write(s, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;	/* the receiver closed its window */
		}
		bytes += (uint64_t)n;
	}
	(void)shutdown(s, SHUT_WR);
	/* Wait (bounded by the alarm) for the receiver to finish. */
	while (!stop && read(s, buf, sizeof(buf)) > 0)
		;
	emit("%ju %ju\n", (uintmax_t)bytes,
	    (uintmax_t)((now_ns() - start) / 1000000));
	close(s);
	return (0);
}

static int
do_uecho(int argc, char **argv)
{
	static char buf[MAXDGRAM];
	struct sockaddr_storage from;
	char peer[INET6_ADDRSTRLEN] = "-";
	const char *addr = NULL, *port = NULL;
	struct probe p;
	socklen_t flen;
	long timeout = 120, count = 0;
	ssize_t n;
	int ch, s, v6 = 0, quiet = 0;

	while ((ch = getopt(argc, argv, "6b:p:qT:")) != -1) {
		switch (ch) {
		case '6':
			v6 = 1;
			break;
		case 'b':
			addr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'T':
			timeout = number(optarg, 1, 3600, "timeout");
			break;
		default:
			usage();
		}
	}
	if (port == NULL || optind != argc)
		usage();
	if (addr == NULL)
		addr = v6 ? "::" : "0.0.0.0";

	catch(SIGALRM);
	catch(SIGTERM);
	catch(SIGINT);
	alarm((unsigned)timeout);
	s = bound_socket(addr, port, SOCK_DGRAM);
	while (!stop) {
		flen = sizeof(from);
		n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from,
		    &flen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "recvfrom");
		}
		if ((size_t)n < sizeof(p))
			continue;
		memcpy(&p, buf, sizeof(p));
		if (p.magic != PROBE_MAGIC)
			continue;
		p.rx = now_ns();
		memcpy(buf, &p, sizeof(p));
		if (count++ == 0) {
			if (from.ss_family == AF_INET)
				inet_ntop(AF_INET,
				    &((struct sockaddr_in *)&from)->sin_addr,
				    peer, sizeof(peer));
			else
				inet_ntop(AF_INET6,
				    &((struct sockaddr_in6 *)&from)->sin6_addr,
				    peer, sizeof(peer));
		}
		if (!quiet)
			(void)sendto(s, buf, (size_t)n, 0,
			    (struct sockaddr *)&from, flen);
	}
	emit("recv %ld peer %s\n", count, peer);
	return (0);
}

static int
cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return ((x > y) - (x < y));
}

/* "min x med y" of n values in nanoseconds, printed in milliseconds. */
static void
stats(char *out, size_t len, const char *name, uint64_t *v, long n)
{
	if (n == 0) {
		snprintf(out, len, "%s_min - %s_med -", name, name);
		return;
	}
	qsort(v, (size_t)n, sizeof(*v), cmp_u64);
	snprintf(out, len, "%s_min %.1f %s_med %.1f", name, v[0] / 1e6, name,
	    v[n / 2] / 1e6);
}

static int
do_uprobe(int argc, char **argv)
{
	static char buf[MAXDGRAM];
	static uint64_t fwd[MAXPROBES], back[MAXPROBES], rtt[MAXPROBES];
	static unsigned char seen[MAXPROBES];
	struct sockaddr_storage ss;
	struct pollfd pfd;
	struct probe p;
	char f[64], b[64], r[64];
	socklen_t len;
	uint64_t next, end, t, interval, wait_ns;
	long count = 100, ival = 20, waitms = 3000, size = 64, sent = 0;
	long got = 0, timeout;
	ssize_t n;
	int ch, s, ms;

	while ((ch = getopt(argc, argv, "i:n:s:W:")) != -1) {
		switch (ch) {
		case 'i':
			ival = number(optarg, 0, 10000, "interval");
			break;
		case 'n':
			count = number(optarg, 1, MAXPROBES, "count");
			break;
		case 's':
			size = number(optarg, (long)sizeof(p), MAXDGRAM,
			    "size");
			break;
		case 'W':
			waitms = number(optarg, 0, 60000, "wait");
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();

	timeout = (count * ival + waitms) / 1000 + 30;
	catch(SIGALRM);
	alarm((unsigned)timeout);
	resolve(argv[0], argv[1], SOCK_DGRAM, &ss, &len);
	s = socket(ss.ss_family, SOCK_DGRAM, 0);
	if (s < 0)
		err(1, "socket");
	memset(buf, 'p', sizeof(buf));
	pfd.fd = s;
	pfd.events = POLLIN;
	interval = (uint64_t)ival * 1000000ULL;
	wait_ns = (uint64_t)waitms * 1000000ULL;
	next = now_ns();
	end = 0;
	while (!stop) {
		t = now_ns();
		if (sent < count && t >= next) {
			p.magic = PROBE_MAGIC;
			p.seq = (uint32_t)sent;
			p.tx = t;
			p.rx = 0;
			memcpy(buf, &p, sizeof(p));
			/* Errors (no route, blocked) count as lost probes. */
			(void)sendto(s, buf, (size_t)size, 0,
			    (struct sockaddr *)&ss, len);
			sent++;
			next += interval;
			if (sent == count)
				end = t + wait_ns;
			continue;
		}
		if (sent == count && (t >= end || got == count))
			break;
		if (sent < count)
			ms = (int)((next - t) / 1000000);
		else
			ms = (int)((end - t) / 1000000);
		if (poll(&pfd, 1, ms + 1) <= 0)
			continue;
		n = recv(s, buf, sizeof(buf), 0);
		t = now_ns();
		if (n < (ssize_t)sizeof(p))
			continue;
		memcpy(&p, buf, sizeof(p));
		if (p.magic != PROBE_MAGIC || p.seq >= (uint32_t)sent ||
		    seen[p.seq] || p.rx < p.tx || t < p.rx)
			continue;
		seen[p.seq] = 1;
		fwd[got] = p.rx - p.tx;
		back[got] = t - p.rx;
		rtt[got] = t - p.tx;
		got++;
	}
	stats(f, sizeof(f), "fwd", fwd, got);
	stats(b, sizeof(b), "back", back, got);
	stats(r, sizeof(r), "rtt", rtt, got);
	emit("sent %ld recv %ld %s %s %s\n", sent, got, f, b, r);
	return (0);
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		usage();
	argc--;
	argv++;
	optreset = optind = 1;
	if (strcmp(argv[0], "sink") == 0)
		return (do_sink(argc, argv));
	if (strcmp(argv[0], "send") == 0)
		return (do_send(argc, argv));
	if (strcmp(argv[0], "uecho") == 0)
		return (do_uecho(argc, argv));
	if (strcmp(argv[0], "uprobe") == 0)
		return (do_uprobe(argc, argv));
	usage();
}
