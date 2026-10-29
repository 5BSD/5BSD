/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_fake_receiver - minimal OTLP/HTTP receiver for offline tests.
 *
 * Listens on 127.0.0.1 (an ephemeral port unless -P is given), writes
 * the port to the -p file once listening, and stores every request as
 * <dir>/NNNN.hdr (request line and headers) and <dir>/NNNN.json (body,
 * gunzipped when Content-Encoding is gzip).  The HTTP status of the
 * n-th response is the n-th entry of -s (the last entry repeats); 0
 * closes the connection without responding.  Exits after -n requests,
 * or with status 1 after -t seconds without completing them; with -n 0
 * it records requests until -t seconds have passed and exits 0.
 */

#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#define	HDR_MAX		(64 * 1024)
#define	BODY_MAX	(32 * 1024 * 1024)
#define	STATUS_MAX	64

static int statuses[STATUS_MAX];
static int nstatuses;

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: otlp_fake_receiver -p portfile -d dir "
	    "[-n count] [-t seconds] [-s status,...] [-P port]\n");
	exit(2);
}

static double
now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* Read until "\r\n\r\n"; returns header length incl. terminator or -1. */
static ssize_t
read_headers(int fd, char *buf, size_t cap, size_t *have)
{
	char *end;
	ssize_t r;

	*have = 0;
	for (;;) {
		r = read(fd, buf + *have, cap - 1 - *have);
		if (r <= 0)
			return (-1);
		*have += (size_t)r;
		buf[*have] = '\0';
		end = strstr(buf, "\r\n\r\n");
		if (end != NULL)
			return (end + 4 - buf);
		if (*have >= cap - 1)
			return (-1);
	}
}

static const char *
header_value(const char *hdrs, const char *name)
{
	const char *p;
	size_t len;

	len = strlen(name);
	for (p = strstr(hdrs, "\r\n"); p != NULL; p = strstr(p, "\r\n")) {
		p += 2;
		if (strncasecmp(p, name, len) == 0 && p[len] == ':') {
			p += len + 1;
			while (*p == ' ')
				p++;
			return (p);
		}
	}
	return (NULL);
}

static void
write_file(const char *path, const void *data, size_t len)
{
	FILE *f;
	char tmp[1024];

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	f = fopen(tmp, "w");
	if (f == NULL || fwrite(data, 1, len, f) != len || fclose(f) != 0)
		err(1, "%s", tmp);
	if (rename(tmp, path) != 0)
		err(1, "rename %s", path);
}

static unsigned char *
gunzip(const unsigned char *in, size_t inlen, size_t *outlen)
{
	z_stream zs;
	unsigned char *out;
	size_t cap;
	int r;

	memset(&zs, 0, sizeof(zs));
	if (inflateInit2(&zs, 15 + 16) != Z_OK)
		return (NULL);
	cap = inlen * 4 + 1024;
	out = malloc(cap);
	if (out == NULL)
		return (NULL);
	zs.next_in = __DECONST(unsigned char *, in);
	zs.avail_in = (uInt)inlen;
	for (;;) {
		zs.next_out = out + zs.total_out;
		zs.avail_out = (uInt)(cap - zs.total_out);
		r = inflate(&zs, Z_NO_FLUSH);
		if (r == Z_STREAM_END)
			break;
		if (r != Z_OK || cap >= BODY_MAX) {
			free(out);
			inflateEnd(&zs);
			return (NULL);
		}
		if (zs.avail_out == 0) {
			cap *= 2;
			out = reallocf(out, cap);
			if (out == NULL)
				return (NULL);
		}
	}
	*outlen = zs.total_out;
	inflateEnd(&zs);
	return (out);
}

/* Serve one connection; returns 1 if a request was recorded. */
static int
serve(int fd, const char *dir, int seq)
{
	char hdr[HDR_MAX], path[1024], resp[256];
	unsigned char *body, *plain;
	const char *cl, *ce;
	size_t have, len, plainlen, got;
	ssize_t hlen, r;
	int status;

	hlen = read_headers(fd, hdr, sizeof(hdr), &have);
	if (hlen < 0)
		return (0);
	cl = header_value(hdr, "Content-Length");
	len = cl != NULL ? strtoul(cl, NULL, 10) : 0;
	if (len > BODY_MAX)
		return (0);
	body = malloc(len + 1);
	if (body == NULL)
		return (0);
	got = have - (size_t)hlen;
	if (got > len)
		got = len;
	memcpy(body, hdr + hlen, got);
	while (got < len) {
		r = read(fd, body + got, len - got);
		if (r <= 0) {
			free(body);
			return (0);
		}
		got += (size_t)r;
	}
	hdr[hlen] = '\0';
	snprintf(path, sizeof(path), "%s/%04d.hdr", dir, seq);
	write_file(path, hdr, (size_t)hlen);
	ce = header_value(hdr, "Content-Encoding");
	plain = body;
	plainlen = len;
	if (ce != NULL && strncasecmp(ce, "gzip", 4) == 0) {
		plain = gunzip(body, len, &plainlen);
		if (plain == NULL)
			errx(1, "request %d: invalid gzip body", seq);
	}
	snprintf(path, sizeof(path), "%s/%04d.json", dir, seq);
	write_file(path, plain, plainlen);
	if (plain != body)
		free(plain);
	free(body);

	status = statuses[seq < nstatuses ? seq : nstatuses - 1];
	if (status != 0) {
		snprintf(resp, sizeof(resp), "HTTP/1.1 %d Test\r\n"
		    "Content-Type: application/json\r\n"
		    "Content-Length: 2\r\nConnection: close\r\n\r\n{}",
		    status);
		(void)write(fd, resp, strlen(resp));
	}
	return (1);
}

int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	struct pollfd pfd;
	socklen_t slen;
	const char *portfile, *dir;
	char *tok, *list, buf[32], tmp[1024];
	double timeout, deadline;
	int ch, fd, cfd, count, max, port, one;
	FILE *f;

	portfile = dir = NULL;
	max = 1;
	timeout = 30;
	port = 0;
	statuses[0] = 200;
	nstatuses = 1;
	while ((ch = getopt(argc, argv, "d:n:p:P:s:t:")) != -1) {
		switch (ch) {
		case 'd':
			dir = optarg;
			break;
		case 'n':
			max = atoi(optarg);
			break;
		case 'p':
			portfile = optarg;
			break;
		case 'P':
			port = atoi(optarg);
			break;
		case 's':
			nstatuses = 0;
			list = strdup(optarg);
			while ((tok = strsep(&list, ",")) != NULL &&
			    nstatuses < STATUS_MAX)
				statuses[nstatuses++] = atoi(tok);
			break;
		case 't':
			timeout = atof(optarg);
			break;
		default:
			usage();
		}
	}
	if (portfile == NULL || dir == NULL || nstatuses == 0)
		usage();
	signal(SIGPIPE, SIG_IGN);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		err(1, "socket");
	one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons((uint16_t)port);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
		err(1, "bind");
	if (listen(fd, 16) != 0)
		err(1, "listen");
	slen = sizeof(sin);
	if (getsockname(fd, (struct sockaddr *)&sin, &slen) != 0)
		err(1, "getsockname");
	snprintf(buf, sizeof(buf), "%d\n", ntohs(sin.sin_port));
	snprintf(tmp, sizeof(tmp), "%s.tmp", portfile);
	f = fopen(tmp, "w");
	if (f == NULL || fputs(buf, f) == EOF || fclose(f) != 0 ||
	    rename(tmp, portfile) != 0)
		err(1, "%s", portfile);

	count = 0;
	deadline = now() + timeout;
	while (max == 0 || count < max) {
		pfd.fd = fd;
		pfd.events = POLLIN;
		if (now() >= deadline) {
			if (max == 0)
				break;
			errx(1, "timeout after %d of %d requests", count, max);
		}
		if (poll(&pfd, 1, (int)((deadline - now()) * 1000) + 1) <= 0)
			continue;
		cfd = accept(fd, NULL, NULL);
		if (cfd == -1)
			continue;
		count += serve(cfd, dir, count);
		close(cfd);
	}
	close(fd);
	return (0);
}
