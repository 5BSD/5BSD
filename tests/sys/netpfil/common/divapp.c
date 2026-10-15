/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Igor Ostapenko <pm@igoro.pro>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Used by divert(4) related tests */

#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <sysexits.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>


/*
 * 5BSD: pf "divert-packet port N" delivers to OpenBSD divert(4) sockets,
 * one per address family (AF_INET/AF_INET6, SOCK_RAW, IPPROTO_DIVERT).
 * A packet is written back with the address recvfrom() returned:
 * inbound packets carry the receiving interface address and are
 * received again, outbound ones the unspecified address and are sent.
 */
struct context {
	unsigned short divert_port;
	bool divert_back;
	bool expect_single_pkt;

	int fd[2];
	int rfd;
	struct sockaddr_storage ss;
	socklen_t ss_len;
	char pkt[IP_MAXPACKET];
	ssize_t pkt_n;
};

static void
init(struct context *c)
{
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	c->fd[0] = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
	if (c->fd[0] == -1)
		err(EX_OSERR, "init: Cannot create inet divert socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(c->divert_port);
	if (bind(c->fd[0], (struct sockaddr *)&sin, sizeof(sin)) != 0)
		err(EX_OSERR, "init: Cannot bind inet divert socket");

	c->fd[1] = socket(AF_INET6, SOCK_RAW, IPPROTO_DIVERT);
	if (c->fd[1] == -1)
		err(EX_OSERR, "init: Cannot create inet6 divert socket");
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(c->divert_port);
	if (bind(c->fd[1], (struct sockaddr *)&sin6, sizeof(sin6)) != 0)
		err(EX_OSERR, "init: Cannot bind inet6 divert socket");
}

static ssize_t
recv_pkt(struct context *c)
{
	fd_set readfds;
	struct timeval timeout;
	int s;

	FD_ZERO(&readfds);
	FD_SET(c->fd[0], &readfds);
	FD_SET(c->fd[1], &readfds);
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;

	s = select((c->fd[0] > c->fd[1] ? c->fd[0] : c->fd[1]) + 1,
	    &readfds, 0, 0, &timeout);
	if (s == -1)
		errx(EX_IOERR, "recv_pkt: select() errors.");
	if (s < 1) /* timeout */
		return (-1);

	c->rfd = FD_ISSET(c->fd[0], &readfds) ? c->fd[0] : c->fd[1];
	c->ss_len = sizeof(c->ss);
	c->pkt_n = recvfrom(c->rfd, c->pkt, sizeof(c->pkt), 0,
	    (struct sockaddr *) &c->ss, &c->ss_len);
	if (c->pkt_n == -1)
		errx(EX_IOERR, "recv_pkt: recvfrom() errors.");

	return (c->pkt_n);
}

static void
send_pkt(struct context *c)
{
	ssize_t n;

	n = sendto(c->rfd, c->pkt, c->pkt_n, 0,
	    (struct sockaddr *) &c->ss, c->ss_len);
	if (n == -1)
		err(EX_IOERR, "send_pkt: sendto() errors");
	if (n != c->pkt_n)
		errx(EX_IOERR, "send_pkt: sendto() sent %zd of %zd bytes.",
		    n, c->pkt_n);
}

int
main(int argc, char *argv[])
{
	struct context c;
	int npkt;

	if (argc < 2)
		errx(EX_USAGE,
		    "Usage: %s <divert-port> [expect-single-pkt] [divert-back]",
		    argv[0]);

	memset(&c, 0, sizeof(struct context));

	c.divert_port = (unsigned short) strtol(argv[1], NULL, 10);
	if (c.divert_port == 0)
		errx(EX_USAGE, "divert port is not defined.");

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "expect-single-pkt") == 0)
			c.expect_single_pkt = true;
		if (strcmp(argv[i], "divert-back") == 0)
			c.divert_back = true;
	}


	init(&c);

	npkt = 0;
	while (recv_pkt(&c) > 0) {
		if (c.divert_back)
			send_pkt(&c);
		npkt++;
		if (c.expect_single_pkt && npkt >= 20) {
			/*
			 * Single-packet expectation detects potential packet
			 * loops, so break the loop eventually.
			 */
			break;
		}
	}

	if (npkt == 0)
		errx(EXIT_FAILURE, "%d: no packets received.", c.divert_port);
	if (c.expect_single_pkt && npkt != 1)
		errx(EXIT_FAILURE, "%d: more than one received, npkt=%d.",
		    c.divert_port, npkt);

	return (EXIT_SUCCESS);
}
