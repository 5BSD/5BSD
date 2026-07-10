/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * vsock-recrx: guest-side record-oriented receiver for the vsock e2e suite.
 *
 * Unlike vsock-pipe (a byte-stream relay that concatenates), this does ONE
 * recv() per SEQPACKET record and reports each record's length, then a final
 * summary "TOTAL recs=<n> bytes=<total>".  Record boundaries are therefore
 * visible: a host->guest record delivered whole shows one line of its full
 * length; a record that was shredded/split shows several short lines.  This is
 * the only way to test host->guest SEQPACKET *framing* (byte-stream tools
 * cannot see it -- they glue fragments back together).
 *
 * Ships as source (like vsock-pipe.c); compile in the guest, which provides
 * <sys/vsock.h> at runtime:  cc -o /root/vsock-recrx vsock-recrx.c
 *
 * Usage: vsock-recrx <port>
 */
#include <sys/socket.h>
#include <sys/vsock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct sockaddr_vm a;
	char *buf;
	size_t bufsz = 4u * 1024 * 1024 + 4096;	/* > device max record */
	unsigned long recs = 0, total = 0;
	int l, c, port;
	ssize_t n;

	if (argc < 2) {
		fprintf(stderr, "usage: vsock-recrx <port>\n");
		return (2);
	}
	port = atoi(argv[1]);
	if ((buf = malloc(bufsz)) == NULL) {
		perror("malloc");
		return (1);
	}
	if ((l = socket(AF_VSOCK, SOCK_SEQPACKET, 0)) < 0) {
		perror("socket");
		return (1);
	}
	memset(&a, 0, sizeof(a));
	a.svm_family = AF_VSOCK;
	a.svm_cid = VMADDR_CID_ANY;
	a.svm_port = port;
	if (bind(l, (struct sockaddr *)&a, sizeof(a)) < 0) {
		perror("bind");
		return (1);
	}
	if (listen(l, 1) < 0) {
		perror("listen");
		return (1);
	}
	printf("recrx listening on %d\n", port);
	fflush(stdout);
	if ((c = accept(l, NULL, NULL)) < 0) {
		perror("accept");
		return (1);
	}
	for (;;) {
		n = recv(c, buf, bufsz, 0);
		if (n < 0) {
			perror("recv");
			break;
		}
		if (n == 0)
			break;		/* peer closed */
		recs++;
		total += (unsigned long)n;
		printf("RECORD len=%zd\n", n);
		fflush(stdout);
	}
	printf("TOTAL recs=%lu bytes=%lu\n", recs, total);
	fflush(stdout);
	free(buf);
	return (0);
}
