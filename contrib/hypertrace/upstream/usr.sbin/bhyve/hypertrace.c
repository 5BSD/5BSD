/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <machine/vmm.h>

#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>
#include <vmmapi.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif

#include "hypertrace.h"

static int rx_sockfd = -1;
static int wx_sockfd = -1;
static int inbound_dirfd = -1;
static int sockdir = -1;
static int rx_configured = 0;
static int wx_configured = 0;
static pthread_t dtraced_connecttd;
static pthread_mutex_t dtraced_connectmtx = PTHREAD_MUTEX_INITIALIZER;

static void *initsockets(void *);
static void rx_set_unconfigured(void);
static void wx_set_unconfigured(void);
static int rx_is_configured(void);
static int wx_is_configured(void);

int
hypertrace_init(struct vmctx *ctx)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif
	rx_sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (rx_sockfd == -1) {
		fprintf(stderr, "RX socket() failed: %s\n", strerror(errno));
		return (-1);
	}

	wx_sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (wx_sockfd == -1) {
		fprintf(stderr, "WX socket() failed: %s\n", strerror(errno));
		return (-1);
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_RECV, CAP_SEND);
	if (caph_rights_limit(rx_sockfd, &rights) == -1)
		errx(EX_OSERR, "caph_rights_limit() failed for rx_sockfd");

	cap_rights_init(&rights, CAP_SEND, CAP_RECV);
	if (caph_rights_limit(wx_sockfd, &rights) == -1)
		errx(EX_OSERR, "caph_rights_limit() failed for wx_sockfd");
#endif

	sockdir = open("/var/ddtrace", O_DIRECTORY);
	if (sockdir == -1) {
		fprintf(stderr, "open(/var/ddtrace): %s\n", strerror(errno));
		return (-1);
	}
	fprintf(stderr, "sockdir = %d\n", sockdir);

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_CONNECTAT);
	if (caph_rights_limit(sockdir, &rights) == -1)
		errx(EX_OSERR, "caph_rights_limit() failed for sockdir");
#endif

	inbound_dirfd = open("/var/ddtrace/inbound", O_DIRECTORY);
	if (inbound_dirfd == -1) {
		fprintf(stderr, "open(/var/ddtrace/inbound): %s\n",
		    strerror(errno));
		return (-1);
	}

	pthread_create(&dtraced_connecttd, NULL, initsockets, ctx);
	return (0);
}

static int
dtraced_sockinit(int *sock, struct vmctx *ctx, unsigned long long subs)
{
	size_t l;
	struct sockaddr_un addr;
	dtd_initmsg_t initmsg;

	memset(&initmsg, 0, sizeof(initmsg));
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, "sub.sock", sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		fprintf(stderr,
		    "attempting to copy %s failed (need %zu bytes)\n",
		    DTRACED_SOCKPATH, l);
		return (-1);
	}

	*sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (*sock == -1) {
		fprintf(stderr, "socket() failed with: %s\n", strerror(errno));
		return (-1);
	}

	fprintf(stderr, "connect attempt to %d/%s\n", sockdir, addr.sun_path);
	if (connectat(sockdir, *sock,
	    (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "connectat() failed with: %s\n",
		    strerror(errno));
		return (-1);
	}

	if (recv(*sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "read() initmsg failed with: %s",
		    strerror(errno));
		return (-1);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		fprintf(stderr, "Expected dtraced kind, got %d\n",
		    initmsg.kind);
		return (-1);
	}

	l = strlcpy(initmsg.ident, vm_get_name(ctx), DTRACED_FDIDENTLEN);
	if (l >= DTRACED_FDIDENTLEN) {
		fprintf(stderr, "could copy vm name: strlen(%s) >= %zu\n",
		    vm_get_name(ctx), l);
		return (-1);
	}

	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = subs;

	if (send(*sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "send() initmsg failed with: %s",
		    strerror(errno));
		return (-1);
	}

	return (0);
}

static int
dtraced_sockinit_rx(struct vmctx *ctx)
{
	unsigned long long subs = DTD_SUB_ELFWRITE | DTD_SUB_KILL |
	    DTD_SUB_CLEANUP;
	return (dtraced_sockinit(&rx_sockfd, ctx, subs));
}

static int
dtraced_sockinit_wx(struct vmctx *ctx)
{
	unsigned long long subs = DTD_SUB_READDATA;
	return (dtraced_sockinit(&wx_sockfd, ctx, subs));
}

static void *
initsockets(void *_ctx)
{
	struct vmctx *ctx = _ctx;
	int _sleep = 0;
	int rval_rx, rval_wx;

	for (;;) {
		/*
		 * Attempt to re-establish a connection every 5 seconds if
		 * necessary.
		 */
		if (__predict_true(_sleep))
			sleep(5);

		_sleep = 1;
		/*
		 *  Check if we are configured first. We don't want to
		 * reconnect if we already have an established connection.
		 */
		if (hypertrace_configured())
			continue;

		close(rx_sockfd);
		close(wx_sockfd);
		rval_rx = dtraced_sockinit_rx(ctx);
		rval_wx = dtraced_sockinit_wx(ctx);

		(void)pthread_mutex_lock(&dtraced_connectmtx);
		rx_configured = !rval_rx;
		wx_configured = !rval_wx;

		fprintf(stderr, "rx_configured = %d, wx_configured = %d\n",
		    rx_configured, wx_configured);
		(void)pthread_mutex_unlock(&dtraced_connectmtx);
	}

	pthread_exit(NULL);
}

/*
 * If we have the file-descriptor, we also have at least the
 * default configuration of the device. Thus, it is sufficient
 * to simply check if the fd is not -1.
 */
int
hypertrace_configured(void)
{
	int rval;

	pthread_mutex_lock(&dtraced_connectmtx);
	rval = rx_configured && wx_configured;
	pthread_mutex_unlock(&dtraced_connectmtx);

	return (rval);
}

/*
 * Read events from the device. This may or may not be a blocking
 * read, depending on the configuration of vtdtr.
 */
int
hypertrace_read(void **buf, dtraced_hdr_t *hdr)
{
	ssize_t rval;
	uintptr_t curpos;
	size_t nbytes, len;

	if (buf == NULL) {
		fprintf(stderr, "hypertrace: buf is NULL\n");
		return (-1);
	}

	if (!rx_is_configured())
		return (-1);

	if ((rval = recv(rx_sockfd, hdr, DTRACED_MSGHDRSIZE, 0)) <= 0) {
		fprintf(stderr, "recv(sub.sock) failed: %s\n", strerror(errno));
		rx_set_unconfigured();
		return (-1);
	}

	assert(rval == DTRACED_MSGHDRSIZE);
	switch (hdr->msg_type) {
	case DTRACED_MSG_ELF:
		len = hdr->elf.len;
		*buf = malloc(len);
		if (*buf == NULL) {
			fprintf(stderr,
			    "hypertrace: failed to allocate buf (len = %zu)\n",
			    len);
			return (-1);
		}

		memset(*buf, 0, len);

		curpos = (uintptr_t)*buf;
		nbytes = len;
		while ((rval = recv(rx_sockfd, (void *)curpos, nbytes, 0)) !=
		    (ssize_t)nbytes) {
			if (rval < 0) {
				fprintf(stderr, "recv() failed with: %s\n",
				    strerror(errno));
				return (-1);
			}

			assert(rval != 0);

			curpos += rval;
			nbytes -= rval;
		}

		assert((ssize_t)nbytes == rval);

		if (rval == 0) {
			fprintf(stderr,
			    "hypertrace: received 0 bytes from %d\n",
			    rx_sockfd);

			rx_set_unconfigured();
			return (-1);
		}

		return (0);

	case DTRACED_MSG_CLEANUP:
		*buf = NULL;
		return (0);

	default:
		*buf = NULL;
		return (0);
	}

	return (0);
}

int
hypertrace_write(void *buf, size_t len)
{
	unsigned char data = 0;
	ssize_t rval;

	if (buf == NULL) {
		fprintf(stderr, "hypertrace_write(): buf == NULL\n");
		return (-1);
	}

	if (!wx_is_configured())
		return (-1);

	if (send(wx_sockfd, &len, sizeof(len), 0) < 0) {
		fprintf(stderr, "send() failed with: %s\n", strerror(errno));
		wx_set_unconfigured();
		return (-1);
	}

	if ((rval = send(wx_sockfd, buf, len, 0)) < 0) {
		fprintf(stderr, "send() failed with: %s\n", strerror(errno));
		wx_set_unconfigured();
		return (-1);
	}

	if (recv(wx_sockfd, &data, 1, 0) < 0) {
		fprintf(stderr, "recv() failed with: %s\n", strerror(errno));
		wx_set_unconfigured();
		return (-1);
	}

	if (data != 1) {
		fprintf(stderr, "received %02x, expected %02x\n", data, 1);
		wx_set_unconfigured();
		return (-1);
	}

	return (0);
}

void
hypertrace_destroy(void)
{

	close(rx_sockfd);
	close(wx_sockfd);
	close(inbound_dirfd);
	close(sockdir);
}

int
hypertrace_newelf(char *name)
{

	return (openat(inbound_dirfd, name, O_CREAT | O_WRONLY, 0600));
}

int
hypertrace_rename(char *n1, char *n2)
{

	return (renameat(inbound_dirfd, n1, inbound_dirfd, n2));
}

int
hypertrace_access(char *path)
{

	return (faccessat(inbound_dirfd, path, F_OK, 0));
}

static void
rx_set_unconfigured(void)
{

	(void)pthread_mutex_lock(&dtraced_connectmtx);
	rx_configured = 0;
	fprintf(stderr, "hypertrace: unconfigured RX\n");
	(void)pthread_mutex_unlock(&dtraced_connectmtx);
}

static void
wx_set_unconfigured(void)
{

	(void)pthread_mutex_lock(&dtraced_connectmtx);
	wx_configured = 0;
	fprintf(stderr, "hypertrace: unconfigured WX\n");
	(void)pthread_mutex_unlock(&dtraced_connectmtx);
}

static int
rx_is_configured(void)
{
	int rv;

	(void)pthread_mutex_lock(&dtraced_connectmtx);
	rv = rx_configured;
	(void)pthread_mutex_unlock(&dtraced_connectmtx);

	return (rv);
}

static int
wx_is_configured(void)
{
	int rv;

	(void)pthread_mutex_lock(&dtraced_connectmtx);
	rv = wx_configured;
	(void)pthread_mutex_unlock(&dtraced_connectmtx);

	return (rv);
}
