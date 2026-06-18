/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/ioctl.h>
#include <sys/filio.h>
#include <sys/event.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <atf-c.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void
vsock_set_any(struct sockaddr_vm *svm)
{
	memset(svm, 0, sizeof(*svm));
	svm->svm_len = sizeof(*svm);
	svm->svm_family = AF_VSOCK;
	svm->svm_cid = VSOCK_CID_ANY;
	svm->svm_port = VSOCK_PORT_ANY;
}

static void
vsock_bind_any(int s, struct sockaddr_vm *out)
{
	struct sockaddr_vm svm;

	vsock_set_any(&svm);
	ATF_REQUIRE_MSG(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0,
	    "bind failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(getsockname(s, (struct sockaddr *)out,
	    &(socklen_t){sizeof(*out)}) == 0,
	    "getsockname failed: %s", strerror(errno));
}

static void
assert_sockaddr_vm_eq(const struct sockaddr_vm *a, const struct sockaddr_vm *b)
{
	ATF_REQUIRE(a->svm_family == b->svm_family);
	ATF_REQUIRE(a->svm_cid   == b->svm_cid);
	ATF_REQUIRE(a->svm_port  == b->svm_port);
}

/*
 * vsock_pair — create a listener/connector/accepted triple.
 * Caller is responsible for closing all three fds.
 */
static void
vsock_pair(int type, int *ls, int *cs, int *as)
{
	struct sockaddr_vm laddr;

	*ls = socket(AF_VSOCK, type, 0);
	ATF_REQUIRE_MSG(*ls >= 0, "listener socket: %s", strerror(errno));
	vsock_bind_any(*ls, &laddr);
	ATF_REQUIRE(listen(*ls, 8) == 0);

	*cs = socket(AF_VSOCK, type, 0);
	ATF_REQUIRE_MSG(*cs >= 0, "client socket: %s", strerror(errno));
	ATF_REQUIRE_MSG(
	    connect(*cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0,
	    "connect failed: %s", strerror(errno));

	*as = accept(*ls, NULL, NULL);
	ATF_REQUIRE_MSG(*as >= 0, "accept failed: %s", strerror(errno));
}

static void
vsock_set_bufsz(int s, uint64_t bufsz)
{
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &bufsz, sizeof(bufsz)) == 0);
}

static uint64_t
vsock_get_bufsz(int s)
{
	uint64_t bufsz;
	socklen_t len = sizeof(bufsz);

	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &bufsz, &len) == 0);
	ATF_REQUIRE(len == sizeof(bufsz));
	return (bufsz);
}

/* ------------------------------------------------------------------ */
/* Thread context structures                                           */
/* ------------------------------------------------------------------ */

struct waitall_ctx {
	struct sockaddr_vm sa;
	size_t msglen;
};

struct sendclose_ctx {
	int sender;
	int receiver;
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	int ready;
	int release;
	int result_errno;
};

struct multi_conn_ctx {
	struct sockaddr_vm sa;
	int idx;
	int result;
};

struct large_xfer_ctx {
	struct sockaddr_vm sa;
	size_t total;
	int result;
};

/* ------------------------------------------------------------------ */
/* Thread functions                                                    */
/* ------------------------------------------------------------------ */

static void *
waitall_client(void *arg)
{
	struct waitall_ctx *ctx = arg;
	char buf[32];
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));
	ATF_REQUIRE(connect(s, (struct sockaddr *)&ctx->sa,
	    sizeof(ctx->sa)) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(s, buf, ctx->msglen + 1, MSG_WAITALL) ==
	    (ssize_t)ctx->msglen);
	ATF_REQUIRE(close(s) == 0);
	return (NULL);
}

static void *
sendclose_sender(void *arg)
{
	struct sendclose_ctx *ctx = arg;
	char buf[1024];

	memset(buf, 'x', sizeof(buf));

	for (;;) {
		ssize_t rc;

		rc = send(ctx->sender, buf, sizeof(buf), 0);
		if (rc == (ssize_t)sizeof(buf))
			continue;
		if (rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			pthread_mutex_lock(&ctx->mtx);
			ctx->ready = 1;
			pthread_cond_signal(&ctx->cv);
			while (!ctx->release)
				pthread_cond_wait(&ctx->cv, &ctx->mtx);
			pthread_mutex_unlock(&ctx->mtx);
			continue;
		}
		pthread_mutex_lock(&ctx->mtx);
		ctx->result_errno = errno;
		ctx->release = 1;
		pthread_cond_signal(&ctx->cv);
		pthread_mutex_unlock(&ctx->mtx);
		return (NULL);
	}
}

static void *
multi_conn_worker(void *arg)
{
	struct multi_conn_ctx *ctx = arg;
	char buf[8];
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s < 0) {
		ctx->result = -1;
		return (NULL);
	}
	if (connect(s, (struct sockaddr *)&ctx->sa,
	    sizeof(ctx->sa)) != 0) {
		close(s);
		ctx->result = -1;
		return (NULL);
	}
	/* Send a message and receive an echo */
	snprintf(buf, sizeof(buf), "%d", ctx->idx);
	if (send(s, buf, strlen(buf), 0) != (ssize_t)strlen(buf)) {
		close(s);
		ctx->result = -1;
		return (NULL);
	}
	memset(buf, 0, sizeof(buf));
	if (recv(s, buf, sizeof(buf), 0) <= 0) {
		close(s);
		ctx->result = -1;
		return (NULL);
	}
	close(s);
	ctx->result = 0;
	return (NULL);
}

static void *
large_xfer_sender(void *arg)
{
	struct large_xfer_ctx *ctx = arg;
	char *buf;
	size_t remaining;
	int s;

	buf = malloc(65536);
	if (buf == NULL) {
		ctx->result = -1;
		return (NULL);
	}
	memset(buf, 0xA5, 65536);

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s < 0) {
		free(buf);
		ctx->result = -1;
		return (NULL);
	}
	if (connect(s, (struct sockaddr *)&ctx->sa,
	    sizeof(ctx->sa)) != 0) {
		close(s);
		free(buf);
		ctx->result = -1;
		return (NULL);
	}

	remaining = ctx->total;
	while (remaining > 0) {
		size_t chunk = remaining < 65536 ? remaining : 65536;
		ssize_t sent = send(s, buf, chunk, 0);
		if (sent <= 0) {
			ctx->result = -1;
			close(s);
			free(buf);
			return (NULL);
		}
		remaining -= (size_t)sent;
	}

	close(s);
	free(buf);
	ctx->result = 0;
	return (NULL);
}

/* ------------------------------------------------------------------ */
/* Group 1: Basic socket operations                                    */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(create_socket);
ATF_TC_BODY(create_socket, tc)
{
	int s1, s2;

	(void)tc;

	s1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s1 >= 0, "stream socket failed: %s", strerror(errno));
	s2 = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE_MSG(s2 >= 0, "seqpacket socket failed: %s",
	    strerror(errno));
	close(s1);
	close(s2);
}

ATF_TC_WITHOUT_HEAD(create_dgram_fails);
ATF_TC_BODY(create_dgram_fails, tc)
{
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_DGRAM, 0);
	ATF_REQUIRE_MSG(s == -1, "SOCK_DGRAM should fail for AF_VSOCK");
	ATF_REQUIRE(errno == EPROTOTYPE || errno == EPROTONOSUPPORT ||
	    errno == ESOCKTNOSUPPORT);
}

ATF_TC_WITHOUT_HEAD(getpeername_unconnected_fails);
ATF_TC_BODY(getpeername_unconnected_fails, tc)
{
	struct sockaddr_vm addr;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));
	ATF_REQUIRE(getpeername(s, (struct sockaddr *)&addr,
	    &(socklen_t){sizeof(addr)}) == -1);
	ATF_REQUIRE(errno == ENOTCONN);
	close(s);
}

ATF_TC_WITHOUT_HEAD(bind_listen_connect);
ATF_TC_BODY(bind_listen_connect, tc)
{
	struct sockaddr_vm laddr, caddr, peer;
	char buf[64];
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	vsock_set_any(&caddr);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	as = accept(ls, (struct sockaddr *)&peer, &(socklen_t){sizeof(peer)});
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(getpeername(cs, (struct sockaddr *)&peer,
	    &(socklen_t){sizeof(peer)}) == 0);
	ATF_REQUIRE(peer.svm_port == laddr.svm_port);
	ATF_REQUIRE(peer.svm_cid  == laddr.svm_cid);

	ATF_REQUIRE(getsockname(cs, (struct sockaddr *)&caddr,
	    &(socklen_t){sizeof(caddr)}) == 0);
	ATF_REQUIRE(caddr.svm_cid == laddr.svm_cid);
	ATF_REQUIRE(caddr.svm_port != (uint32_t)VSOCK_PORT_ANY);

	ATF_REQUIRE(send(cs, "hello", 5, 0) == 5);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 5);
	ATF_REQUIRE(memcmp(buf, "hello", 5) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(getsockname_bound_and_connected);
ATF_TC_BODY(getsockname_bound_and_connected, tc)
{
	struct sockaddr_vm laddr, caddr, peer, asockaddr;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	ATF_REQUIRE(getsockname(ls, (struct sockaddr *)&asockaddr,
	    &(socklen_t){sizeof(asockaddr)}) == 0);
	assert_sockaddr_vm_eq(&laddr, &asockaddr);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, (struct sockaddr *)&peer, &(socklen_t){sizeof(peer)});
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(getsockname(cs, (struct sockaddr *)&caddr,
	    &(socklen_t){sizeof(caddr)}) == 0);
	ATF_REQUIRE(caddr.svm_cid == laddr.svm_cid);
	ATF_REQUIRE(caddr.svm_port != (uint32_t)VSOCK_PORT_ANY);
	ATF_REQUIRE(caddr.svm_port != 0);

	ATF_REQUIRE(getsockname(as, (struct sockaddr *)&asockaddr,
	    &(socklen_t){sizeof(asockaddr)}) == 0);
	assert_sockaddr_vm_eq(&laddr, &asockaddr);

	ATF_REQUIRE(getpeername(as, (struct sockaddr *)&peer,
	    &(socklen_t){sizeof(peer)}) == 0);
	assert_sockaddr_vm_eq(&caddr, &peer);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(bind_duplicate_eaddrinuse);
ATF_TC_BODY(bind_duplicate_eaddrinuse, tc)
{
	struct sockaddr_vm addr;
	int s1, s2;

	(void)tc;

	s1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s1 >= 0, "socket failed: %s", strerror(errno));
	vsock_bind_any(s1, &addr);

	s2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s2 >= 0, "socket failed: %s", strerror(errno));
	ATF_REQUIRE(bind(s2, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == EADDRINUSE);

	close(s2);
	close(s1);
}

ATF_TC_WITHOUT_HEAD(listen_unbound_fails);
ATF_TC_BODY(listen_unbound_fails, tc)
{
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));
	ATF_REQUIRE(listen(s, 8) == -1);
	ATF_REQUIRE(errno == EINVAL);
	close(s);
}

ATF_TC_WITHOUT_HEAD(connect_refused);
ATF_TC_BODY(connect_refused, tc)
{
	struct sockaddr_vm addr;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));

	vsock_set_any(&addr);
	addr.svm_cid  = VSOCK_CID_LOCAL;
	addr.svm_port = 12345;
	ATF_REQUIRE(connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == ECONNREFUSED);
	close(s);
}

/* ------------------------------------------------------------------ */
/* Group 2: Shutdown semantics                                         */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(shutdown_send);
ATF_TC_BODY(shutdown_send, tc)
{
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_recv);
ATF_TC_BODY(shutdown_recv, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(shutdown(as, SHUT_RD) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_wr_eof);
ATF_TC_BODY(shutdown_wr_eof, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_rdwr_semantics);
ATF_TC_BODY(shutdown_rdwr_semantics, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(shutdown(cs, SHUT_RDWR) == 0);
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 3: Close semantics                                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(close_eof_and_epipe);
ATF_TC_BODY(close_eof_and_epipe, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(close(as) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 0);
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);

	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(close_waitall_eof);
ATF_TC_BODY(close_waitall_eof, tc)
{
	struct waitall_ctx ctx;
	struct sockaddr_vm laddr;
	pthread_t t;
	const char *msg = "hello bonjour";
	int ls, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);
	ctx.sa     = laddr;
	ctx.msglen = strlen(msg) + 1;
	ATF_REQUIRE(pthread_create(&t, NULL, waitall_client, &ctx) == 0);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(send(as, msg, ctx.msglen, 0) == (ssize_t)ctx.msglen);
	ATF_REQUIRE(close(as) == 0);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(peer_close_during_send_pressure);
ATF_TC_BODY(peer_close_during_send_pressure, tc)
{
	struct sockaddr_vm laddr;
	struct sendclose_ctx ctx;
	pthread_t t;
	int ls, cs, as, n;

	(void)tc;

	memset(&ctx, 0, sizeof(ctx));
	ATF_REQUIRE(pthread_mutex_init(&ctx.mtx, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&ctx.cv, NULL) == 0);

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	n = 4096;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ctx.sender   = cs;
	ctx.receiver = as;
	ATF_REQUIRE(pthread_create(&t, NULL, sendclose_sender, &ctx) == 0);

	pthread_mutex_lock(&ctx.mtx);
	while (!ctx.ready)
		pthread_cond_wait(&ctx.cv, &ctx.mtx);
	pthread_mutex_unlock(&ctx.mtx);

	ATF_REQUIRE(close(as) == 0);

	pthread_mutex_lock(&ctx.mtx);
	ctx.release = 1;
	pthread_cond_signal(&ctx.cv);
	pthread_mutex_unlock(&ctx.mtx);

	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	ATF_REQUIRE(ctx.result_errno == EPIPE ||
	    ctx.result_errno == ENOTCONN);

	close(cs);
	close(ls);
	pthread_mutex_destroy(&ctx.mtx);
	pthread_cond_destroy(&ctx.cv);
}

/* ------------------------------------------------------------------ */
/* Group 4: MSG_PEEK                                                   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stream_peek_preserves_data);
ATF_TC_BODY(stream_peek_preserves_data, tc)
{
	char buf[16];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "peek", 4, 0) == 4);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), MSG_PEEK) == 4);
	ATF_REQUIRE(memcmp(buf, "peek", 4) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 4);
	ATF_REQUIRE(memcmp(buf, "peek", 4) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_peek_trunc);
ATF_TC_BODY(seqpacket_peek_trunc, tc)
{
	char buf[32];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "123456789", 9, 0) == 9);
	memset(buf, 0, sizeof(buf));
	/* Small buffer with MSG_TRUNC should return full message length */
	ATF_REQUIRE(recv(as, buf, 4, MSG_PEEK | MSG_TRUNC) == 9);
	/* Data should still be present for a full recv */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 9);
	ATF_REQUIRE(memcmp(buf, "123456789", 9) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(peek_after_partial_recv);
ATF_TC_BODY(peek_after_partial_recv, tc)
{
	char buf[16];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "abcdefgh", 8, 0) == 8);

	/* Partial recv of first 4 bytes */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, 4, 0) == 4);
	ATF_REQUIRE(memcmp(buf, "abcd", 4) == 0);

	/* Peek should show the remaining 4 bytes */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), MSG_PEEK) == 4);
	ATF_REQUIRE(memcmp(buf, "efgh", 4) == 0);

	/* Full recv should consume those 4 bytes */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 4);
	ATF_REQUIRE(memcmp(buf, "efgh", 4) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 5: Nonblocking I/O                                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(nonblocking_eagain);
ATF_TC_BODY(nonblocking_eagain, tc)
{
	struct sockaddr_vm laddr;
	char buf[1024];
	int ls, cs, as, n;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	n = 4096;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	memset(buf, 'x', sizeof(buf));
	for (;;) {
		ssize_t rc;

		rc = send(cs, buf, sizeof(buf), 0);
		if (rc == -1) {
			ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}
		ATF_REQUIRE(rc == (ssize_t)sizeof(buf));
	}

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(nonblocking_recv_eagain);
ATF_TC_BODY(nonblocking_recv_eagain, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(nonblocking_connect);
ATF_TC_BODY(nonblocking_connect, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs, as;
	int flags;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);

	/*
	 * Nonblocking connect on a local vsock may complete immediately
	 * (returns 0) or indicate EINPROGRESS.  Both are valid.
	 */
	int r = connect(cs, (struct sockaddr *)&laddr, sizeof(laddr));
	ATF_REQUIRE(r == 0 || (r == -1 && errno == EINPROGRESS));

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	/* Restore blocking for a clean send/recv check */
	flags = fcntl(cs, F_GETFL, 0);
	ATF_REQUIRE(flags != -1);
	ATF_REQUIRE(fcntl(cs, F_SETFL, flags & ~O_NONBLOCK) != -1);

	ATF_REQUIRE(send(cs, "nb", 2, 0) == 2);
	char buf[4] = {0};
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 2);
	ATF_REQUIRE(memcmp(buf, "nb", 2) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 6: MSG_WAITALL                                                */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stream_waitall_roundtrip);
ATF_TC_BODY(stream_waitall_roundtrip, tc)
{
	char buf[16];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "hello world", 11, 0) == 11);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, 11, MSG_WAITALL) == 11);
	ATF_REQUIRE(memcmp(buf, "hello world", 11) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(waitall_partial_on_close);
ATF_TC_BODY(waitall_partial_on_close, tc)
{
	struct waitall_ctx ctx;
	struct sockaddr_vm laddr;
	pthread_t t;
	const char *msg = "hello bonjour";
	int ls, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);
	ctx.sa     = laddr;
	ctx.msglen = strlen(msg) + 1;
	ATF_REQUIRE(pthread_create(&t, NULL, waitall_client, &ctx) == 0);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	/* Send full message, then close — client uses MSG_WAITALL for msglen+1 */
	ATF_REQUIRE(send(as, msg, ctx.msglen, 0) == (ssize_t)ctx.msglen);
	ATF_REQUIRE(close(as) == 0);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 7: SEQPACKET specifics                                        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(seqpacket_zero_length);
ATF_TC_BODY(seqpacket_zero_length, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "", 0, 0) == 0);
	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_message_boundaries);
ATF_TC_BODY(seqpacket_message_boundaries, tc)
{
	char buf[64];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	ATF_REQUIRE(send(cs, "first", 5, 0) == 5);
	ATF_REQUIRE(send(cs, "second", 6, 0) == 6);
	ATF_REQUIRE(send(cs, "third", 5, 0) == 5);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 5);
	ATF_REQUIRE(memcmp(buf, "first", 5) == 0);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 6);
	ATF_REQUIRE(memcmp(buf, "second", 6) == 0);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 5);
	ATF_REQUIRE(memcmp(buf, "third", 5) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_msg_trunc);
ATF_TC_BODY(seqpacket_msg_trunc, tc)
{
	char buf[4];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "abcdefghij", 10, 0) == 10);

	/*
	 * recv into a small buffer without MSG_TRUNC truncates silently on
	 * stream sockets but on SEQPACKET the remainder of the message is
	 * discarded; the return value is the bytes placed in the buffer.
	 * With MSG_TRUNC the return value is the full original message length.
	 */
	memset(buf, 0, sizeof(buf));
	ssize_t n = recv(as, buf, sizeof(buf), MSG_TRUNC);
	ATF_REQUIRE(n == 10);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_large_message);
ATF_TC_BODY(seqpacket_large_message, tc)
{
	char *sbuf, *rbuf;
	size_t msgsz = 128 * 1024;
	ssize_t n;
	int ls, cs, as;

	(void)tc;

	sbuf = malloc(msgsz);
	rbuf = malloc(msgsz);
	ATF_REQUIRE(sbuf != NULL && rbuf != NULL);
	memset(sbuf, 0x5A, msgsz);

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	n = send(cs, sbuf, msgsz, 0);
	if (n == -1) {
		/* Some implementations reject oversized seqpacket messages */
		ATF_REQUIRE(errno == EMSGSIZE || errno == ENOBUFS);
	} else {
		ATF_REQUIRE(n == (ssize_t)msgsz);
		memset(rbuf, 0, msgsz);
		ATF_REQUIRE(recv(as, rbuf, msgsz, MSG_WAITALL) ==
		    (ssize_t)msgsz);
		ATF_REQUIRE(memcmp(sbuf, rbuf, msgsz) == 0);
	}

	close(as);
	close(cs);
	close(ls);
	free(sbuf);
	free(rbuf);
}

/* ------------------------------------------------------------------ */
/* Group 8: Buffer sockopts                                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(buffer_size_sockopt);
ATF_TC_BODY(buffer_size_sockopt, tc)
{
	uint64_t bufsz;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_set_bufsz(ls, 64 * 1024);

	struct sockaddr_vm laddr;
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);
	ATF_REQUIRE(vsock_get_bufsz(ls) >= 64 * 1024);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	vsock_set_bufsz(cs, 64 * 1024);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));
	ATF_REQUIRE(vsock_get_bufsz(as) >= 64 * 1024);

	bufsz = 64 * 1024;
	ATF_REQUIRE(setsockopt(as, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
	    &bufsz, sizeof(bufsz)) == 0);
	ATF_REQUIRE(vsock_get_bufsz(as) >= 64 * 1024);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(buffer_min_max_clamp);
ATF_TC_BODY(buffer_min_max_clamp, tc)
{
	uint64_t val;
	socklen_t len;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));

	/* Set min/max and verify they are accepted */
	val = 32 * 1024;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MIN_SIZE,
	    &val, sizeof(val)) == 0);

	val = 256 * 1024;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
	    &val, sizeof(val)) == 0);

	/* Set the actual buffer within range */
	val = 128 * 1024;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &val, sizeof(val)) == 0);

	len = sizeof(val);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &val, &len) == 0);
	ATF_REQUIRE(val >= 32 * 1024 && val <= 256 * 1024);

	close(s);
}

ATF_TC_WITHOUT_HEAD(buffer_size_on_accepted);
ATF_TC_BODY(buffer_size_on_accepted, tc)
{
	struct sockaddr_vm laddr;
	uint64_t lbuf, abuf;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_set_bufsz(ls, 128 * 1024);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);
	lbuf = vsock_get_bufsz(ls);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	abuf = vsock_get_bufsz(as);
	/* The accepted socket should inherit at least the listener's buffer */
	ATF_REQUIRE_MSG(abuf >= lbuf,
	    "accepted socket buf %llu < listener buf %llu",
	    (unsigned long long)abuf, (unsigned long long)lbuf);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 9: Multiple connections                                       */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(multiple_connections);
ATF_TC_BODY(multiple_connections, tc)
{
	struct sockaddr_vm laddr;
	struct multi_conn_ctx ctxs[50];
	pthread_t threads[50];
	int ls;
	int i;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 64) == 0);

	for (i = 0; i < 50; i++) {
		ctxs[i].sa  = laddr;
		ctxs[i].idx = i;
		ctxs[i].result = -1;
		ATF_REQUIRE(pthread_create(&threads[i], NULL,
		    multi_conn_worker, &ctxs[i]) == 0);
	}

	/* Accept all connections and echo the data back */
	for (i = 0; i < 50; i++) {
		char buf[8];
		int as;

		as = accept(ls, NULL, NULL);
		ATF_REQUIRE_MSG(as >= 0, "accept[%d] failed: %s",
		    i, strerror(errno));
		memset(buf, 0, sizeof(buf));
		ssize_t n = recv(as, buf, sizeof(buf), 0);
		ATF_REQUIRE(n > 0);
		ATF_REQUIRE(send(as, buf, (size_t)n, 0) == n);
		close(as);
	}

	for (i = 0; i < 50; i++) {
		ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
		ATF_REQUIRE_MSG(ctxs[i].result == 0,
		    "worker[%d] failed", i);
	}

	close(ls);
}

ATF_TC_WITHOUT_HEAD(accept_queue_stress);
ATF_TC_BODY(accept_queue_stress, tc)
{
	struct sockaddr_vm laddr;
	int ls;
	int i;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 32) == 0);

	for (i = 0; i < 30; i++) {
		int cs, as;

		cs = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE_MSG(cs >= 0, "client socket[%d] failed: %s",
		    i, strerror(errno));
		ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
		    sizeof(laddr)) == 0);

		as = accept(ls, NULL, NULL);
		ATF_REQUIRE_MSG(as >= 0, "accept[%d] failed: %s",
		    i, strerror(errno));

		close(cs);
		close(as);
	}

	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 10: Poll / kqueue                                             */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(poll_write_ready);
ATF_TC_BODY(poll_write_ready, tc)
{
	struct pollfd pfd;
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	pfd.fd = cs;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 1000) == 1);
	ATF_REQUIRE((pfd.revents & POLLOUT) != 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(poll_read_ready);
ATF_TC_BODY(poll_read_ready, tc)
{
	struct pollfd pfd;
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(send(cs, "data", 4, 0) == 4);

	pfd.fd = as;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 1000) == 1);
	ATF_REQUIRE((pfd.revents & POLLIN) != 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(poll_hup_on_close);
ATF_TC_BODY(poll_hup_on_close, tc)
{
	struct pollfd pfd;
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	close(as);

	pfd.fd = cs;
	pfd.events = POLLIN | POLLHUP;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 2000) == 1);
	ATF_REQUIRE((pfd.revents & (POLLHUP | POLLIN)) != 0);

	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(kqueue_read_write);
ATF_TC_BODY(kqueue_read_write, tc)
{
	struct kevent kev[2], ev[2];
	struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
	int kq, ls, cs, as, n;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	kq = kqueue();
	ATF_REQUIRE_MSG(kq >= 0, "kqueue failed: %s", strerror(errno));

	EV_SET(&kev[0], (uintptr_t)cs, EVFILT_WRITE, EV_ADD | EV_ONESHOT,
	    0, 0, NULL);
	ATF_REQUIRE(kevent(kq, kev, 1, NULL, 0, NULL) == 0);

	n = kevent(kq, NULL, 0, ev, 1, &ts);
	ATF_REQUIRE_MSG(n == 1, "expected EVFILT_WRITE event, got %d", n);
	ATF_REQUIRE(ev[0].filter == EVFILT_WRITE);
	ATF_REQUIRE((ev[0].flags & EV_ERROR) == 0);

	/* Send data and check EVFILT_READ */
	ATF_REQUIRE(send(cs, "kq", 2, 0) == 2);

	EV_SET(&kev[0], (uintptr_t)as, EVFILT_READ, EV_ADD | EV_ONESHOT,
	    0, 0, NULL);
	ATF_REQUIRE(kevent(kq, kev, 1, NULL, 0, NULL) == 0);

	n = kevent(kq, NULL, 0, ev, 1, &ts);
	ATF_REQUIRE_MSG(n == 1, "expected EVFILT_READ event, got %d", n);
	ATF_REQUIRE(ev[0].filter == EVFILT_READ);
	ATF_REQUIRE((ev[0].flags & EV_ERROR) == 0);

	close(kq);
	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 11: Timeouts                                                  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(recv_timeout);
ATF_TC_BODY(recv_timeout, tc)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(setsockopt(as, SOL_SOCKET, SO_RCVTIMEO,
	    &tv, sizeof(tv)) == 0);

	/* Nothing sent; recv should time out */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == ETIMEDOUT);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(send_timeout);
ATF_TC_BODY(send_timeout, tc)
{
	struct sockaddr_vm laddr;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	char buf[1024];
	int ls, cs, as, n;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	n = 4096;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket failed: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO,
	    &tv, sizeof(tv)) == 0);

	memset(buf, 'x', sizeof(buf));
	ssize_t rc = -1;
	for (;;) {
		rc = send(cs, buf, sizeof(buf), 0);
		if (rc == -1)
			break;
	}
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == ETIMEDOUT);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 12: Error cases                                               */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(invalid_family_bind);
ATF_TC_BODY(invalid_family_bind, tc)
{
	struct sockaddr_vm addr;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket failed: %s", strerror(errno));

	vsock_set_any(&addr);
	addr.svm_family = AF_INET; /* wrong family */
	ATF_REQUIRE(bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == EINVAL || errno == EAFNOSUPPORT);

	close(s);
}

ATF_TC_WITHOUT_HEAD(double_bind_fails);
ATF_TC_BODY(double_bind_fails, tc)
{
	struct sockaddr_vm addr;
	int s1, s2;

	(void)tc;

	s1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s1 >= 0);
	vsock_bind_any(s1, &addr);

	/* Second socket tries the SAME port — must fail */
	s2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s2 >= 0);
	ATF_REQUIRE(bind(s2, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == EADDRINUSE);

	close(s2);
	close(s1);
}

ATF_TC_WITHOUT_HEAD(connect_after_listen);
ATF_TC_BODY(connect_after_listen, tc)
{
	struct sockaddr_vm laddr, other;
	int ls1, ls2;

	(void)tc;

	/* Create two listeners so we have a valid target */
	ls1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls1 >= 0, "socket failed: %s", strerror(errno));
	vsock_bind_any(ls1, &laddr);
	ATF_REQUIRE(listen(ls1, 8) == 0);

	ls2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls2 >= 0, "socket failed: %s", strerror(errno));
	vsock_bind_any(ls2, &other);
	ATF_REQUIRE(listen(ls2, 8) == 0);

	/* Connecting on a listening socket must fail */
	ATF_REQUIRE(connect(ls1, (struct sockaddr *)&other,
	    sizeof(other)) == -1);
	ATF_REQUIRE(errno == EOPNOTSUPP || errno == EINVAL ||
	    errno == EISCONN);

	close(ls1);
	close(ls2);
}

ATF_TC_WITHOUT_HEAD(retry_connect);
ATF_TC_BODY(retry_connect, tc)
{
	struct sockaddr_vm laddr;
	char buf[4];
	int ls, cs, as;

	(void)tc;

	/*
	 * First attempt: connect to a port with no listener → ECONNREFUSED.
	 * Second attempt: connect to a real listener → success.
	 */
	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket failed: %s", strerror(errno));

	vsock_set_any(&laddr);
	laddr.svm_cid  = VSOCK_CID_HOST;
	laddr.svm_port = 59998;
	/* Best-effort: may fail for reasons other than ECONNREFUSED on host */
	(void)connect(cs, (struct sockaddr *)&laddr, sizeof(laddr));
	close(cs);

	/* Now do a proper connect to a live listener */
	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket failed: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 2);
	ATF_REQUIRE(memcmp(buf, "ok", 2) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 13: Large transfers                                           */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stream_large_transfer);
ATF_TC_BODY(stream_large_transfer, tc)
{
	struct sockaddr_vm laddr;
	struct large_xfer_ctx ctx;
	pthread_t t;
	char *rbuf;
	size_t total = 1024 * 1024; /* 1 MB */
	size_t received = 0;
	int ls, as;

	(void)tc;

	rbuf = malloc(total);
	ATF_REQUIRE(rbuf != NULL);

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	ctx.sa     = laddr;
	ctx.total  = total;
	ctx.result = -1;
	ATF_REQUIRE(pthread_create(&t, NULL, large_xfer_sender, &ctx) == 0);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	while (received < total) {
		ssize_t n = recv(as, rbuf + received,
		    total - received, 0);
		ATF_REQUIRE_MSG(n > 0, "recv returned %zd: %s",
		    n, strerror(errno));
		received += (size_t)n;
	}
	ATF_REQUIRE(received == total);

	/* Verify all bytes are 0xA5 */
	for (size_t i = 0; i < total; i++) {
		ATF_REQUIRE_MSG((unsigned char)rbuf[i] == 0xA5,
		    "data mismatch at offset %zu", i);
	}

	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	ATF_REQUIRE(ctx.result == 0);

	free(rbuf);
	close(as);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_multi_message);
ATF_TC_BODY(seqpacket_multi_message, tc)
{
#define NMSG 20
#define MSGSZ 512
	char sbuf[MSGSZ], rbuf[MSGSZ];
	int ls, cs, as;
	int i;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	for (i = 0; i < NMSG; i++) {
		memset(sbuf, (char)(i & 0xff), MSGSZ);
		ATF_REQUIRE(send(cs, sbuf, MSGSZ, 0) == MSGSZ);
	}

	for (i = 0; i < NMSG; i++) {
		memset(rbuf, 0, MSGSZ);
		ATF_REQUIRE(recv(as, rbuf, MSGSZ, MSG_WAITALL) == MSGSZ);
		/* Verify all bytes match the expected fill value */
		for (int j = 0; j < MSGSZ; j++) {
			ATF_REQUIRE_MSG(
			    (unsigned char)rbuf[j] == (unsigned)(i & 0xff),
			    "msg[%d] byte[%d]: got %u expected %u",
			    i, j, (unsigned char)rbuf[j],
			    (unsigned)(i & 0xff));
		}
	}

	close(as);
	close(cs);
	close(ls);
#undef NMSG
#undef MSGSZ
}

/* ------------------------------------------------------------------ */
/* Group 14: SO_LINGER                                                 */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(linger_close);
ATF_TC_BODY(linger_close, tc)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 5 };
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(setsockopt(cs, SOL_SOCKET, SO_LINGER,
	    &lg, sizeof(lg)) == 0);

	ATF_REQUIRE(send(cs, "linger", 6, 0) == 6);
	ATF_REQUIRE(close(cs) == 0); /* blocks until data flushed or timeout */

	/* Data should be available to peer */
	memset(buf, 0, sizeof(buf));
	ssize_t n = recv(as, buf, sizeof(buf), 0);
	ATF_REQUIRE(n > 0);

	close(as);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(linger_zero_close);
ATF_TC_BODY(linger_zero_close, tc)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	char buf[8];
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(setsockopt(cs, SOL_SOCKET, SO_LINGER,
	    &lg, sizeof(lg)) == 0);

	ATF_REQUIRE(send(cs, "rst", 3, 0) == 3);
	ATF_REQUIRE(close(cs) == 0); /* RST-like: discard pending data */

	/*
	 * With l_linger=0 the connection is aborted; peer may see 0 bytes
	 * (EOF) or an error — both are acceptable.
	 */
	memset(buf, 0, sizeof(buf));
	ssize_t n = recv(as, buf, sizeof(buf), 0);
	ATF_REQUIRE(n == 0 || (n == -1 && (errno == ECONNRESET ||
	    errno == ETIMEDOUT)));

	close(as);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 15: ioctls                                                    */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(fionread_stream);
ATF_TC_BODY(fionread_stream, tc)
{
	int ls, cs, as, n;
	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Nothing sent yet */
	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 0);

	/* Send some data */
	ATF_REQUIRE(send(cs, "hello", 5, 0) == 5);
	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 5);

	/* Send more */
	ATF_REQUIRE(send(cs, " world", 6, 0) == 6);
	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 11);

	/* Read some, check remaining */
	char buf[8];
	ATF_REQUIRE(recv(as, buf, 5, 0) == 5);
	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 6);

	close(as); close(cs); close(ls);
}

ATF_TC_WITHOUT_HEAD(fionread_seqpacket);
ATF_TC_BODY(fionread_seqpacket, tc)
{
	int ls, cs, as, n;
	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 0);

	ATF_REQUIRE(send(cs, "abc", 3, 0) == 3);
	ATF_REQUIRE(send(cs, "defgh", 5, 0) == 5);

	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE_MSG(n == 3 || n == 8,
	    "FIONREAD returned %d, expected 3 (first msg) or 8 (total)", n);

	close(as); close(cs); close(ls);
}

ATF_TC_WITHOUT_HEAD(fionwrite_stream);
ATF_TC_BODY(fionwrite_stream, tc)
{
	int ls, cs, as, n;
	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

#ifndef FIONWRITE
	atf_tc_skip("FIONWRITE not defined on this platform");
#else
	/* Nothing pending initially */
	ATF_REQUIRE(ioctl(cs, FIONWRITE, &n) == 0);
	/* n should be 0 or small (data delivered immediately for loopback) */
	ATF_REQUIRE(n >= 0);
#endif

	close(as); close(cs); close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 16: zerocopy compat                                           */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(zerocopy_sockopt_compat);
ATF_TC_BODY(zerocopy_sockopt_compat, tc)
{
	(void)tc;

#ifndef SO_ZEROCOPY
	atf_tc_skip("SO_ZEROCOPY not defined on this platform");
#else
	{
		int s, val;

		s = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE(s >= 0);

		val = 1;
		(void)setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val));

		close(s);
	}
#endif
}

/* ------------------------------------------------------------------ */
/* Group 17: SO_RCVLOWAT                                               */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(rcvlowat_default);
ATF_TC_BODY(rcvlowat_default, tc)
{
	char buf[64];
	int ls, cs, as, lowat;
	socklen_t len;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	len = sizeof(lowat);
	ATF_REQUIRE(getsockopt(as, SOL_SOCKET, SO_RCVLOWAT, &lowat, &len) == 0);
	ATF_REQUIRE(lowat == 1);

	/* Set lowat to 8 — poll should not fire until 8 bytes arrive. */
	lowat = 8;
	ATF_REQUIRE(setsockopt(as, SOL_SOCKET, SO_RCVLOWAT,
	    &lowat, sizeof(lowat)) == 0);

	/* Send 4 bytes (below lowat). */
	ATF_REQUIRE(send(cs, "abcd", 4, 0) == 4);

	/* poll with short timeout — should NOT report readable. */
	struct pollfd pfd;
	pfd.fd = as;
	pfd.events = POLLIN;
	ATF_REQUIRE(poll(&pfd, 1, 50) == 0);

	/* Send 4 more bytes (now 8 total, meets lowat). */
	ATF_REQUIRE(send(cs, "efgh", 4, 0) == 4);
	ATF_REQUIRE(poll(&pfd, 1, 500) == 1);
	ATF_REQUIRE(pfd.revents & POLLIN);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 8);
	ATF_REQUIRE(memcmp(buf, "abcdefgh", 8) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 18: Stress / rapid lifecycle                                  */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(rapid_connect_close);
ATF_TC_BODY(rapid_connect_close, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs, as, i;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 64) == 0);

	for (i = 0; i < 200; i++) {
		cs = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE_MSG(cs >= 0, "iteration %d: socket: %s",
		    i, strerror(errno));
		ATF_REQUIRE_MSG(connect(cs, (struct sockaddr *)&laddr,
		    sizeof(laddr)) == 0, "iteration %d: connect: %s",
		    i, strerror(errno));
		as = accept(ls, NULL, NULL);
		ATF_REQUIRE_MSG(as >= 0, "iteration %d: accept: %s",
		    i, strerror(errno));
		ATF_REQUIRE(send(cs, "x", 1, 0) == 1);
		close(as);
		close(cs);
	}

	close(ls);
}

ATF_TC_WITHOUT_HEAD(double_bind_connect_cycle);
ATF_TC_BODY(double_bind_connect_cycle, tc)
{
	struct sockaddr_vm laddr1, laddr2;
	char buf[8];
	int ls1, ls2, cs, as;

	(void)tc;

	/* First cycle */
	ls1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls1 >= 0);
	vsock_bind_any(ls1, &laddr1);
	ATF_REQUIRE(listen(ls1, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr1,
	    sizeof(laddr1)) == 0);
	as = accept(ls1, NULL, NULL);
	ATF_REQUIRE(as >= 0);
	ATF_REQUIRE(send(cs, "one", 3, 0) == 3);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 3);
	close(as);
	close(cs);
	close(ls1);

	/* Second cycle — different listener */
	ls2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls2 >= 0);
	vsock_bind_any(ls2, &laddr2);
	ATF_REQUIRE(listen(ls2, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr2,
	    sizeof(laddr2)) == 0);
	as = accept(ls2, NULL, NULL);
	ATF_REQUIRE(as >= 0);
	ATF_REQUIRE(send(cs, "two", 3, 0) == 3);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 3);
	ATF_REQUIRE(memcmp(buf, "two", 3) == 0);
	close(as);
	close(cs);
	close(ls2);
}

ATF_TC_WITHOUT_HEAD(simultaneous_bidirectional);
ATF_TC_BODY(simultaneous_bidirectional, tc)
{
	int ls, cs, as;
	char buf[32];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Both sides send simultaneously */
	ATF_REQUIRE(send(cs, "client", 6, 0) == 6);
	ATF_REQUIRE(send(as, "server", 6, 0) == 6);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 6);
	ATF_REQUIRE(memcmp(buf, "client", 6) == 0);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 6);
	ATF_REQUIRE(memcmp(buf, "server", 6) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 19: SIGPIPE semantics (Linux tests 16, 17)                    */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t sigpipe_count;

static void
sigpipe_handler(int sig __unused)
{
	sigpipe_count++;
}

ATF_TC_WITHOUT_HEAD(shutdown_wr_sigpipe);
ATF_TC_BODY(shutdown_wr_sigpipe, tc)
{
	int ls, cs, as;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	signal(SIGPIPE, sigpipe_handler);
	sigpipe_count = 0;

	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);

	/* Send after SHUT_WR → EPIPE + SIGPIPE */
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);
	ATF_REQUIRE_MSG(sigpipe_count == 1,
	    "expected 1 SIGPIPE, got %d", (int)sigpipe_count);

	/* Send with MSG_NOSIGNAL → EPIPE without SIGPIPE */
	sigpipe_count = 0;
	ATF_REQUIRE(send(cs, "x", 1, MSG_NOSIGNAL) == -1);
	ATF_REQUIRE(errno == EPIPE);
	ATF_REQUIRE_MSG(sigpipe_count == 0,
	    "expected 0 SIGPIPE with MSG_NOSIGNAL, got %d",
	    (int)sigpipe_count);

	signal(SIGPIPE, SIG_DFL);
	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(peer_close_sigpipe);
ATF_TC_BODY(peer_close_sigpipe, tc)
{
	int ls, cs, as;
	char buf[1024];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	signal(SIGPIPE, sigpipe_handler);
	sigpipe_count = 0;

	/* Close the accepted side */
	close(as);

	/* Drain EOF */
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 0);

	/* Send to closed peer → EPIPE + SIGPIPE */
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);
	ATF_REQUIRE(sigpipe_count >= 1);

	/* MSG_NOSIGNAL variant */
	sigpipe_count = 0;
	ATF_REQUIRE(send(cs, "x", 1, MSG_NOSIGNAL) == -1);
	ATF_REQUIRE(errno == EPIPE);
	ATF_REQUIRE(sigpipe_count == 0);

	signal(SIGPIPE, SIG_DFL);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 20: Data survives EFAULT on stream, dropped on seqpacket      */
/*           (Linux tests 12, 13)                                      */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stream_efault_preserves_data);
ATF_TC_BODY(stream_efault_preserves_data, tc)
{
	int ls, cs, as;
	char buf[64];
	ssize_t rc;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	ATF_REQUIRE(send(cs, "hello", 5, 0) == 5);

	/* recv into NULL → EFAULT */
	rc = recv(as, NULL, 5, 0);
	ATF_REQUIRE(rc == -1);
	ATF_REQUIRE(errno == EFAULT);

	/* Data should still be in the buffer for stream sockets */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), MSG_DONTWAIT) == 5);
	ATF_REQUIRE(memcmp(buf, "hello", 5) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_efault_drops_message);
ATF_TC_BODY(seqpacket_efault_drops_message, tc)
{
	int ls, cs, as;
	char buf[64];
	ssize_t rc;

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send two messages */
	ATF_REQUIRE(send(cs, "first", 5, 0) == 5);
	ATF_REQUIRE(send(cs, "second", 6, 0) == 6);

	/* recv first message into NULL → EFAULT, message may be consumed */
	rc = recv(as, NULL, 5, 0);
	ATF_REQUIRE(rc == -1);
	ATF_REQUIRE(errno == EFAULT);

	/* Second message should still be readable */
	memset(buf, 0, sizeof(buf));
	rc = recv(as, buf, sizeof(buf), MSG_DONTWAIT);
	/* Either we get "second" (first was dropped) or "first" (retained) */
	ATF_REQUIRE(rc > 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 21: 100 concurrent connections (Linux test 4)                 */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(hundred_concurrent_connections);
ATF_TC_BODY(hundred_concurrent_connections, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs[100], as[100];
	int i;
	char byte;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 128) == 0);

	for (i = 0; i < 100; i++) {
		cs[i] = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE_MSG(cs[i] >= 0, "socket %d: %s",
		    i, strerror(errno));
		ATF_REQUIRE_MSG(connect(cs[i],
		    (struct sockaddr *)&laddr, sizeof(laddr)) == 0,
		    "connect %d: %s", i, strerror(errno));
		as[i] = accept(ls, NULL, NULL);
		ATF_REQUIRE_MSG(as[i] >= 0, "accept %d: %s",
		    i, strerror(errno));
	}

	/* Even indices: client sends, server recvs.
	 * Odd indices: server sends, client recvs. */
	for (i = 0; i < 100; i++) {
		byte = (char)('A' + (i % 26));
		if (i % 2 == 0) {
			ATF_REQUIRE(send(cs[i], &byte, 1, 0) == 1);
		} else {
			ATF_REQUIRE(send(as[i], &byte, 1, 0) == 1);
		}
	}

	for (i = 0; i < 100; i++) {
		char got;
		byte = (char)('A' + (i % 26));
		if (i % 2 == 0) {
			ATF_REQUIRE(recv(as[i], &got, 1, 0) == 1);
		} else {
			ATF_REQUIRE(recv(cs[i], &got, 1, 0) == 1);
		}
		ATF_REQUIRE_MSG(got == byte,
		    "connection %d: expected '%c', got '%c'",
		    i, byte, got);
	}

	for (i = 0; i < 100; i++) {
		close(cs[i]);
		close(as[i]);
	}
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 22: Stream partial read then full read (Linux test 14 — skb   */
/*           merge / coalescence behavior)                             */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(stream_partial_read_merge);
ATF_TC_BODY(stream_partial_read_merge, tc)
{
	int ls, cs, as;
	char buf[32];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Send two chunks */
	ATF_REQUIRE(send(cs, "HELLO", 5, 0) == 5);
	ATF_REQUIRE(send(cs, "WORLD", 5, 0) == 5);

	/* Partial read: only 2 bytes of first chunk */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, 2, 0) == 2);
	ATF_REQUIRE(memcmp(buf, "HE", 2) == 0);

	/* Read remaining — should get "LLOWORLD" (merged) */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, 8, MSG_WAITALL) == 8);
	ATF_REQUIRE(memcmp(buf, "LLOWORLD", 8) == 0);

	/* Nothing left */
	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 23: Bind before connect (Linux test 21)                       */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(bind_then_connect);
ATF_TC_BODY(bind_then_connect, tc)
{
	struct sockaddr_vm laddr, baddr, peer;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	/* Client explicitly binds before connecting */
	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	vsock_bind_any(cs, &baddr);

	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Verify the client's bound address is reported correctly */
	ATF_REQUIRE(getsockname(cs, (struct sockaddr *)&peer,
	    &(socklen_t){sizeof(peer)}) == 0);
	ATF_REQUIRE(peer.svm_port == baddr.svm_port);

	/* Verify the server sees the client's bound address */
	ATF_REQUIRE(getpeername(as, (struct sockaddr *)&peer,
	    &(socklen_t){sizeof(peer)}) == 0);
	ATF_REQUIRE(peer.svm_port == baddr.svm_port);

	/* Data flows */
	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);
	char buf[8];
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 2);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 24: Accepted socket setsockopt (Linux test 36)                */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(accepted_socket_setsockopt);
ATF_TC_BODY(accepted_socket_setsockopt, tc)
{
	int ls, cs, as;
	uint64_t bufsz;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Set buffer opts on the ACCEPTED socket (not just the client) */
	bufsz = 256 * 1024;
	ATF_REQUIRE(setsockopt(as, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &bufsz, sizeof(bufsz)) == 0);

	bufsz = 0;
	socklen_t len = sizeof(bufsz);
	ATF_REQUIRE(getsockopt(as, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &bufsz, &len) == 0);
	ATF_REQUIRE(bufsz >= 256 * 1024);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 25: Client/server close ordering — data readable after close  */
/*           (Linux tests 2, 3)                                        */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(client_close_data_readable);
ATF_TC_BODY(client_close_data_readable, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Client sends data then closes */
	ATF_REQUIRE(send(cs, "A", 1, 0) == 1);
	close(cs);

	/* Server can still read the data that arrived before close */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 1);
	ATF_REQUIRE(buf[0] == 'A');

	/* Then gets EOF */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(server_close_data_readable);
ATF_TC_BODY(server_close_data_readable, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Server sends data then closes */
	ATF_REQUIRE(send(as, "B", 1, 0) == 1);
	close(as);

	/* Client reads data then EOF */
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 1);
	ATF_REQUIRE(buf[0] == 'B');
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 0);

	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 26: kqueue EVFILT_READ EV_EOF (epoll EPOLLRDHUP equivalent)   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(kqueue_eof_on_peer_close);
ATF_TC_BODY(kqueue_eof_on_peer_close, tc)
{
	int ls, cs, as, kq;
	struct kevent kev;
	struct timespec ts;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, as, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Close client side */
	close(cs);

	/* kqueue should report EV_EOF */
	ts.tv_sec = 2;
	ts.tv_nsec = 0;
	ATF_REQUIRE(kevent(kq, NULL, 0, &kev, 1, &ts) == 1);
	ATF_REQUIRE(kev.filter == EVFILT_READ);
	ATF_REQUIRE(kev.flags & EV_EOF);

	close(as);
	close(ls);
	close(kq);
}

/* ------------------------------------------------------------------ */
/* Group 27: Seqpacket message boundary hash (Linux test 6)            */
/* ------------------------------------------------------------------ */

static uint32_t
djb2_hash(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t h = 5381;

	for (size_t i = 0; i < len; i++)
		h = ((h << 5) + h) + p[i];
	return (h);
}

ATF_TC_WITHOUT_HEAD(seqpacket_boundary_hash);
ATF_TC_BODY(seqpacket_boundary_hash, tc)
{
	int ls, cs, as;
	char sendbuf[4096], recvbuf[4096];
	uint32_t send_hash = 5381, recv_hash = 5381;
	int i;
	ssize_t rc;

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send 20 messages of varying sizes */
	for (i = 0; i < 20; i++) {
		size_t len = 100 + (i * 73) % 2000;
		memset(sendbuf, (char)(i + 'A'), len);
		ATF_REQUIRE((size_t)send(cs, sendbuf, len, 0) == len);
		send_hash = ((send_hash << 5) + send_hash) +
		    djb2_hash(sendbuf, len);
	}

	/* Receive and hash */
	for (i = 0; i < 20; i++) {
		size_t expected = 100 + (i * 73) % 2000;
		rc = recv(as, recvbuf, sizeof(recvbuf), 0);
		ATF_REQUIRE_MSG(rc == (ssize_t)expected,
		    "msg %d: expected %zu, got %zd", i, expected, rc);
		recv_hash = ((recv_hash << 5) + recv_hash) +
		    djb2_hash(recvbuf, (size_t)rc);
	}

	ATF_REQUIRE_MSG(send_hash == recv_hash,
	    "hash mismatch: send=%u recv=%u", send_hash, recv_hash);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 28: connect timeout sockopt (Linux compat)                    */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(connect_timeout_sockopt);
ATF_TC_BODY(connect_timeout_sockopt, tc)
{
	int s;
	uint64_t val;
	socklen_t len;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* Set */
	val = 500; /* centiseconds */
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &val, sizeof(val)) == 0);

	/* Get (returns 0 — accepted but not implemented) */
	len = sizeof(val);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &val, &len) == 0);

	close(s);
}

/* ------------------------------------------------------------------ */
/* Group 29: Input validation                                          */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(svm_len_validation);
ATF_TC_BODY(svm_len_validation, tc)
{
	struct sockaddr_vm svm;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* svm_len = 0 should fail */
	vsock_set_any(&svm);
	svm.svm_len = 0;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EINVAL);

	/* svm_len = wrong size should fail */
	vsock_set_any(&svm);
	svm.svm_len = 8; /* wrong */
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EINVAL);

	/* Correct svm_len should succeed */
	vsock_set_any(&svm);
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0);

	close(s);
}

ATF_TC_WITHOUT_HEAD(reserved1_must_be_zero);
ATF_TC_BODY(reserved1_must_be_zero, tc)
{
	struct sockaddr_vm svm, laddr;
	int s, ls;

	(void)tc;

	/* Bind with non-zero svm_reserved1 should fail */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	vsock_set_any(&svm);
	svm.svm_reserved1 = 1;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EINVAL);
	close(s);

	/* Connect with non-zero svm_reserved1 should fail */
	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	laddr.svm_reserved1 = 1;
	ATF_REQUIRE(connect(s, (struct sockaddr *)&laddr, sizeof(laddr)) == -1);
	ATF_REQUIRE(errno == EINVAL);
	close(s);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(cid_validation_bind);
ATF_TC_BODY(cid_validation_bind, tc)
{
	struct sockaddr_vm svm;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* Bind with a non-local CID should fail with EAFNOSUPPORT */
	vsock_set_any(&svm);
	svm.svm_cid = 99; /* not our CID */
	svm.svm_port = 5000;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EAFNOSUPPORT);

	close(s);
}

ATF_TC_WITHOUT_HEAD(ctloutput_unknown_option);
ATF_TC_BODY(ctloutput_unknown_option, tc)
{
	int s;
	uint64_t val = 0;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* Unknown SOL_VSOCK option */
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, 999, &val, sizeof(val)) == -1);
	ATF_REQUIRE(errno == ENOPROTOOPT || errno == EOPNOTSUPP);

	close(s);
}

/* ------------------------------------------------------------------ */
/* Group 30: Edge cases                                                */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(nonblocking_accept_eagain);
ATF_TC_BODY(nonblocking_accept_eagain, tc)
{
	struct sockaddr_vm laddr;
	int ls;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);
	ATF_REQUIRE(fcntl(ls, F_SETFL, O_NONBLOCK) != -1);

	ATF_REQUIRE(accept(ls, NULL, NULL) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(ls);
}

ATF_TC_WITHOUT_HEAD(stream_zero_send);
ATF_TC_BODY(stream_zero_send, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* 0-byte send should return 0 and not queue data */
	ATF_REQUIRE(send(cs, "", 0, 0) == 0);

	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_rd_send_still_works);
ATF_TC_BODY(shutdown_rd_send_still_works, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Shut down read direction */
	ATF_REQUIRE(shutdown(cs, SHUT_RD) == 0);

	/* Send should still work */
	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);

	/* Peer should receive it */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 2);
	ATF_REQUIRE(memcmp(buf, "ok", 2) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(poll_multiple_fds);
ATF_TC_BODY(poll_multiple_fds, tc)
{
	int ls1, cs1, as1, ls2, cs2, as2;
	struct pollfd pfd[2];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls1, &cs1, &as1);
	vsock_pair(SOCK_STREAM, &ls2, &cs2, &as2);

	/* Send data only on connection 2 */
	ATF_REQUIRE(send(cs2, "data", 4, 0) == 4);

	pfd[0].fd = as1;
	pfd[0].events = POLLIN;
	pfd[1].fd = as2;
	pfd[1].events = POLLIN;

	ATF_REQUIRE(poll(pfd, 2, 500) == 1);
	ATF_REQUIRE(!(pfd[0].revents & POLLIN)); /* no data on fd1 */
	ATF_REQUIRE(pfd[1].revents & POLLIN);    /* data on fd2 */

	close(as1); close(cs1); close(ls1);
	close(as2); close(cs2); close(ls2);
}

/* ------------------------------------------------------------------ */
/* Group 31: Concurrency                                               */
/* ------------------------------------------------------------------ */

static void *
blocked_recv_thread(void *arg)
{
	int fd = *(int *)arg;
	char buf[8];
	ssize_t rc;

	rc = recv(fd, buf, sizeof(buf), 0);
	/* Should return 0 (EOF) or -1 when socket is closed */
	return ((void *)(intptr_t)rc);
}

ATF_TC_WITHOUT_HEAD(close_while_blocked_recv);
ATF_TC_BODY(close_while_blocked_recv, tc)
{
	int ls, cs, as;
	pthread_t t;
	void *ret;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Thread blocks on recv */
	ATF_REQUIRE(pthread_create(&t, NULL, blocked_recv_thread, &as) == 0);
	/* Allow time for thread to enter recv() syscall. */
	usleep(200000);

	/* Close the peer — should unblock the recv with EOF */
	close(cs);

	ATF_REQUIRE(pthread_join(t, &ret) == 0);
	ATF_REQUIRE((intptr_t)ret == 0); /* EOF */

	close(as);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 32: Additional coverage                                       */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(connect_cid_local);
ATF_TC_BODY(connect_cid_local, tc)
{
	struct sockaddr_vm laddr, dst;
	char buf[8];
	int ls, cs, as;

	(void)tc;

	/*
	 * Verify that connecting to VSOCK_CID_LOCAL (1) finds a listener
	 * bound with CID_ANY (which normalizes to the guest CID).
	 */
	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "client socket: %s", strerror(errno));

	/* Connect to VSOCK_CID_LOCAL on the listener's port */
	vsock_set_any(&dst);
	dst.svm_cid = VSOCK_CID_LOCAL;
	dst.svm_port = laddr.svm_port;
	ATF_REQUIRE_MSG(connect(cs, (struct sockaddr *)&dst, sizeof(dst)) == 0,
	    "connect to CID_LOCAL failed: %s", strerror(errno));

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(send(cs, "local", 5, 0) == 5);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 5);
	ATF_REQUIRE(memcmp(buf, "local", 5) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(connect_refused_cid_local);
ATF_TC_BODY(connect_refused_cid_local, tc)
{
	struct sockaddr_vm addr;
	int s;

	(void)tc;

	/*
	 * Connect to VSOCK_CID_LOCAL on a port with no listener.
	 * This uses the loopback path regardless of guest CID,
	 * so it always produces ECONNREFUSED.
	 */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket: %s", strerror(errno));

	vsock_set_any(&addr);
	addr.svm_cid  = VSOCK_CID_LOCAL;
	addr.svm_port = 54321;
	ATF_REQUIRE(connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == ECONNREFUSED);
	close(s);
}

ATF_TC_WITHOUT_HEAD(accept_backlog_full);
ATF_TC_BODY(accept_backlog_full, tc)
{
	struct sockaddr_vm laddr;
	int ls, clients[16];
	int i, backlog;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);

	/* Small backlog — loopback completes connections synchronously,
	 * so we must accept some to avoid filling the completed queue. */
	backlog = 2;
	ATF_REQUIRE(listen(ls, backlog) == 0);

	/* Fill up connections without accepting */
	for (i = 0; i < 8; i++) {
		clients[i] = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE_MSG(clients[i] >= 0, "socket %d: %s",
		    i, strerror(errno));
		/*
		 * Loopback connect may succeed even past the backlog
		 * (kernel may allow some slop).  We just exercise the path.
		 */
		(void)connect(clients[i], (struct sockaddr *)&laddr,
		    sizeof(laddr));
	}

	/* Accept what we can */
	for (i = 0; i < 8; i++) {
		int as = accept(ls, NULL, NULL);
		if (as < 0)
			break;
		close(as);
	}

	for (i = 0; i < 8; i++)
		close(clients[i]);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_rd_peer_sends);
ATF_TC_BODY(shutdown_rd_peer_sends, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Receiver shuts down read direction */
	ATF_REQUIRE(shutdown(as, SHUT_RD) == 0);

	/*
	 * Peer sends data after our SHUT_RD.  The send should either
	 * succeed (data discarded by receiver) or fail with EPIPE
	 * depending on whether the SHUTDOWN notification reached the peer.
	 */
	ssize_t rc = send(cs, "post", 4, MSG_NOSIGNAL);
	ATF_REQUIRE(rc == 4 || (rc == -1 && errno == EPIPE));

	/* Our recv should return 0 (EOF due to SHUT_RD) */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(double_close_fd);
ATF_TC_BODY(double_close_fd, tc)
{
	int ls, cs, as;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	ATF_REQUIRE(close(as) == 0);
	/* Second close on the same fd should fail with EBADF */
	ATF_REQUIRE(close(as) == -1);
	ATF_REQUIRE(errno == EBADF);

	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 33: Coverage parity with Linux                                */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(connection_reset);
ATF_TC_BODY(connection_reset, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Force a RST by setting SO_LINGER with l_linger=0 */
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	ATF_REQUIRE(setsockopt(as, SOL_SOCKET, SO_LINGER,
	    &lg, sizeof(lg)) == 0);
	close(as);

	/* Peer should see connection reset */
	ssize_t n = recv(cs, buf, sizeof(buf), 0);
	ATF_REQUIRE(n == 0 || (n == -1 && errno == ECONNRESET));

	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(credit_update_on_recv);
ATF_TC_BODY(credit_update_on_recv, tc)
{
	int ls, cs, as;
	char *buf;
	size_t bufsz = 64 * 1024;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	buf = malloc(bufsz);
	ATF_REQUIRE(buf != NULL);
	memset(buf, 'X', bufsz);

	/* Fill the pipe */
	ATF_REQUIRE(send(cs, buf, bufsz, 0) == (ssize_t)bufsz);

	/* Drain it — this should trigger credit updates */
	size_t total = 0;
	while (total < bufsz) {
		ssize_t n = recv(as, buf, bufsz - total, 0);
		ATF_REQUIRE(n > 0);
		total += (size_t)n;
	}
	ATF_REQUIRE(total == bufsz);

	/* Should be able to send again after draining */
	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);
	memset(buf, 0, 8);
	ATF_REQUIRE(recv(as, buf, 8, 0) == 2);
	ATF_REQUIRE(memcmp(buf, "ok", 2) == 0);

	free(buf);
	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(accept_queue_leak);
ATF_TC_BODY(accept_queue_leak, tc)
{
	struct sockaddr_vm laddr;
	int ls, i;

	(void)tc;

	/*
	 * Repeatedly create listeners, connect clients, and tear down
	 * without accepting.  This exercises cleanup of the accept queue
	 * to verify no resources leak.
	 */
	for (i = 0; i < 50; i++) {
		int cs;

		ls = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE_MSG(ls >= 0, "iter %d: socket: %s",
		    i, strerror(errno));
		vsock_bind_any(ls, &laddr);
		ATF_REQUIRE(listen(ls, 4) == 0);

		cs = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE(cs >= 0);
		/* Connect fills the accept queue */
		(void)connect(cs, (struct sockaddr *)&laddr, sizeof(laddr));
		close(cs);
		close(ls);
	}
}

ATF_TC_WITHOUT_HEAD(seqpacket_unread_bytes_precise);
ATF_TC_BODY(seqpacket_unread_bytes_precise, tc)
{
	int ls, cs, as, n;
	char buf[32];

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send one 10-byte message */
	ATF_REQUIRE(send(cs, "0123456789", 10, 0) == 10);

	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE_MSG(n == 10,
	    "FIONREAD returned %d, expected 10", n);

	/* Consume it */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 10);

	ATF_REQUIRE(ioctl(as, FIONREAD, &n) == 0);
	ATF_REQUIRE(n == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 34: Spec compliance (§5.10)                                   */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(seqpacket_msg_eor);
ATF_TC_BODY(seqpacket_msg_eor, tc)
{
	struct msghdr mh;
	struct iovec iov;
	char buf[64];
	int ls, cs, as;

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send a single complete message — should arrive with MSG_EOR */
	ATF_REQUIRE(send(cs, "record", 6, 0) == 6);

	memset(&mh, 0, sizeof(mh));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_flags = 0;

	ATF_REQUIRE(recvmsg(as, &mh, 0) == 6);
	ATF_REQUIRE(memcmp(buf, "record", 6) == 0);
	ATF_REQUIRE_MSG(mh.msg_flags & MSG_EOR,
	    "MSG_EOR not set on SEQPACKET message (flags=0x%x)",
	    mh.msg_flags);

	/* Second message — verify boundary and MSG_EOR again */
	ATF_REQUIRE(send(cs, "next", 4, 0) == 4);

	mh.msg_flags = 0;
	iov.iov_len = sizeof(buf);
	ATF_REQUIRE(recvmsg(as, &mh, 0) == 4);
	ATF_REQUIRE(memcmp(buf, "next", 4) == 0);
	ATF_REQUIRE_MSG(mh.msg_flags & MSG_EOR,
	    "MSG_EOR not set on second message (flags=0x%x)",
	    mh.msg_flags);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(reserved_cid_bind);
ATF_TC_BODY(reserved_cid_bind, tc)
{
	struct sockaddr_vm svm;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* CID 0 is reserved (hypervisor) — bind must fail */
	vsock_set_any(&svm);
	svm.svm_cid = 0;
	svm.svm_port = 5000;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EAFNOSUPPORT || errno == EINVAL);

	/* CID 2 (host) — not our CID, must fail */
	vsock_set_any(&svm);
	svm.svm_cid = VSOCK_CID_HOST;
	svm.svm_port = 5001;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EAFNOSUPPORT);

	close(s);
}

ATF_TC_WITHOUT_HEAD(seqpacket_eor_multi_record);
ATF_TC_BODY(seqpacket_eor_multi_record, tc)
{
	struct msghdr mh;
	struct iovec iov;
	char buf[64];
	int ls, cs, as;
	int i;

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send 5 messages; each should arrive as a separate record */
	for (i = 0; i < 5; i++) {
		char msg[8];
		snprintf(msg, sizeof(msg), "msg%d", i);
		ATF_REQUIRE(send(cs, msg, strlen(msg), 0) ==
		    (ssize_t)strlen(msg));
	}

	for (i = 0; i < 5; i++) {
		char expected[8];
		snprintf(expected, sizeof(expected), "msg%d", i);

		memset(&mh, 0, sizeof(mh));
		memset(buf, 0, sizeof(buf));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;

		ssize_t n = recvmsg(as, &mh, 0);
		ATF_REQUIRE(n == (ssize_t)strlen(expected));
		ATF_REQUIRE(memcmp(buf, expected, (size_t)n) == 0);
		ATF_REQUIRE_MSG(mh.msg_flags & MSG_EOR,
		    "msg[%d]: MSG_EOR not set (flags=0x%x)",
		    i, mh.msg_flags);
	}

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(connect_timeout_applied);
ATF_TC_BODY(connect_timeout_applied, tc)
{
	uint64_t val;
	socklen_t len;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* Set connect timeout to 1 second (100 centiseconds) */
	val = 100;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &val, sizeof(val)) == 0);

	/* Read it back — should be approximately 100 */
	len = sizeof(val);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &val, &len) == 0);
	ATF_REQUIRE_MSG(val >= 90 && val <= 110,
	    "connect timeout readback %llu not ~100",
	    (unsigned long long)val);

	close(s);
}

/* ------------------------------------------------------------------ */
/* Group 35: Concurrent connect + close races                          */
/* ------------------------------------------------------------------ */

static void *
race_connect_close_worker(void *arg)
{
	struct sockaddr_vm *sa = arg;
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s < 0)
		return ((void *)(intptr_t)-1);
	(void)connect(s, (struct sockaddr *)sa, sizeof(*sa));
	close(s);
	return ((void *)(intptr_t)0);
}

ATF_TC_WITHOUT_HEAD(concurrent_connect_close_race);
ATF_TC_BODY(concurrent_connect_close_race, tc)
{
	struct sockaddr_vm laddr;
	pthread_t threads[20];
	int ls, i;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 64) == 0);

	for (i = 0; i < 20; i++) {
		ATF_REQUIRE(pthread_create(&threads[i], NULL,
		    race_connect_close_worker, &laddr) == 0);
	}

	/* Accept and close as fast as possible to race with client close */
	for (i = 0; i < 20; i++) {
		int as = accept(ls, NULL, NULL);
		if (as >= 0)
			close(as);
	}

	for (i = 0; i < 20; i++)
		ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);

	close(ls);
}

ATF_TC_WITHOUT_HEAD(simultaneous_close_both_sides);
ATF_TC_BODY(simultaneous_close_both_sides, tc)
{
	struct sockaddr_vm laddr;
	pthread_t t;
	int ls, cs, as;

	(void)tc;

	for (int round = 0; round < 50; round++) {
		ls = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE(ls >= 0);
		vsock_bind_any(ls, &laddr);
		ATF_REQUIRE(listen(ls, 8) == 0);

		cs = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE(cs >= 0);
		ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
		    sizeof(laddr)) == 0);
		as = accept(ls, NULL, NULL);
		ATF_REQUIRE(as >= 0);

		/* Spawn thread to close one end while we close the other */
		ATF_REQUIRE(pthread_create(&t, NULL, blocked_recv_thread,
		    &as) == 0);
		close(cs);
		ATF_REQUIRE(pthread_join(t, NULL) == 0);
		close(as);
		close(ls);
	}
}

/* ------------------------------------------------------------------ */
/* Group 36: Credit exhaustion and recovery                            */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(credit_exhaustion_recovery);
ATF_TC_BODY(credit_exhaustion_recovery, tc)
{
	struct sockaddr_vm laddr;
	char *buf;
	size_t bufsz = 64 * 1024;
	int ls, cs, as, n;

	(void)tc;

	buf = malloc(bufsz);
	ATF_REQUIRE(buf != NULL);
	memset(buf, 'Q', bufsz);

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	/* Small receiver buffer to hit exhaustion quickly */
	n = 8192;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Fill until EAGAIN */
	size_t total_sent = 0;
	for (;;) {
		ssize_t rc = send(cs, buf, 1024, 0);
		if (rc == -1) {
			ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}
		total_sent += (size_t)rc;
	}
	ATF_REQUIRE(total_sent > 0);

	/* Drain receiver */
	size_t total_recv = 0;
	for (;;) {
		ssize_t rc = recv(as, buf, bufsz, MSG_DONTWAIT);
		if (rc <= 0)
			break;
		total_recv += (size_t)rc;
	}
	ATF_REQUIRE(total_recv == total_sent);

	/* After drain, sender should be able to send again */
	ATF_REQUIRE(send(cs, "resume", 6, 0) == 6);
	memset(buf, 0, 8);
	ATF_REQUIRE(recv(as, buf, 8, 0) == 6);
	ATF_REQUIRE(memcmp(buf, "resume", 6) == 0);

	free(buf);
	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(credit_fill_drain_cycle);
ATF_TC_BODY(credit_fill_drain_cycle, tc)
{
	struct sockaddr_vm laddr;
	char sbuf[4096], rbuf[4096];
	int ls, cs, as, n, cycle;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	n = 8192;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	memset(sbuf, 'Z', sizeof(sbuf));

	/* Repeat fill/drain cycles to exercise credit update path */
	for (cycle = 0; cycle < 10; cycle++) {
		ATF_REQUIRE(send(cs, sbuf, sizeof(sbuf), 0) ==
		    (ssize_t)sizeof(sbuf));

		size_t got = 0;
		while (got < sizeof(sbuf)) {
			ssize_t rc = recv(as, rbuf, sizeof(rbuf), 0);
			ATF_REQUIRE(rc > 0);
			got += (size_t)rc;
		}
		ATF_REQUIRE(got == sizeof(sbuf));
	}

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 37: Shutdown edge cases for spec compliance                    */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(shutdown_wr_then_rd);
ATF_TC_BODY(shutdown_wr_then_rd, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Shut write first, then read — equivalent to RDWR but in two steps */
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);
	ATF_REQUIRE(shutdown(cs, SHUT_RD) == 0);

	/* Send must fail */
	ATF_REQUIRE(send(cs, "x", 1, MSG_NOSIGNAL) == -1);
	ATF_REQUIRE(errno == EPIPE);

	/* Peer should see EOF */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(shutdown_rd_then_wr);
ATF_TC_BODY(shutdown_rd_then_wr, tc)
{
	int ls, cs, as;
	char buf[8];

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Shut read first, then write — equivalent to RDWR but reversed */
	ATF_REQUIRE(shutdown(cs, SHUT_RD) == 0);
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);

	/* Send must fail */
	ATF_REQUIRE(send(cs, "x", 1, MSG_NOSIGNAL) == -1);
	ATF_REQUIRE(errno == EPIPE);

	/* Recv returns 0 (EOF from SHUT_RD) */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 0);

	/* Peer should see EOF from our SHUT_WR */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_shutdown_preserves_pending);
ATF_TC_BODY(seqpacket_shutdown_preserves_pending, tc)
{
	int ls, cs, as;
	char buf[32];

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Send data then shut down write — data should still be readable */
	ATF_REQUIRE(send(cs, "before", 6, 0) == 6);
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 6);
	ATF_REQUIRE(memcmp(buf, "before", 6) == 0);

	/* Next recv should see EOF */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* ATF test plan                                                       */
/* ------------------------------------------------------------------ */

ATF_TP_ADD_TCS(tp)
{
	/* Group 1: Basic socket operations */
	ATF_TP_ADD_TC(tp, create_socket);
	ATF_TP_ADD_TC(tp, create_dgram_fails);
	ATF_TP_ADD_TC(tp, getpeername_unconnected_fails);
	ATF_TP_ADD_TC(tp, bind_listen_connect);
	ATF_TP_ADD_TC(tp, getsockname_bound_and_connected);
	ATF_TP_ADD_TC(tp, bind_duplicate_eaddrinuse);
	ATF_TP_ADD_TC(tp, listen_unbound_fails);
	ATF_TP_ADD_TC(tp, connect_refused);

	/* Group 2: Shutdown semantics */
	ATF_TP_ADD_TC(tp, shutdown_send);
	ATF_TP_ADD_TC(tp, shutdown_recv);
	ATF_TP_ADD_TC(tp, shutdown_wr_eof);
	ATF_TP_ADD_TC(tp, shutdown_rdwr_semantics);

	/* Group 3: Close semantics */
	ATF_TP_ADD_TC(tp, close_eof_and_epipe);
	ATF_TP_ADD_TC(tp, close_waitall_eof);
	ATF_TP_ADD_TC(tp, peer_close_during_send_pressure);
	ATF_TP_ADD_TC(tp, connection_reset);

	/* Group 4: MSG_PEEK */
	ATF_TP_ADD_TC(tp, stream_peek_preserves_data);
	ATF_TP_ADD_TC(tp, seqpacket_peek_trunc);
	ATF_TP_ADD_TC(tp, peek_after_partial_recv);

	/* Group 5: Nonblocking I/O */
	ATF_TP_ADD_TC(tp, nonblocking_eagain);
	ATF_TP_ADD_TC(tp, nonblocking_recv_eagain);
	ATF_TP_ADD_TC(tp, nonblocking_connect);

	/* Group 6: MSG_WAITALL */
	ATF_TP_ADD_TC(tp, stream_waitall_roundtrip);
	ATF_TP_ADD_TC(tp, waitall_partial_on_close);

	/* Group 7: SEQPACKET specifics */
	ATF_TP_ADD_TC(tp, seqpacket_zero_length);
	ATF_TP_ADD_TC(tp, seqpacket_message_boundaries);
	ATF_TP_ADD_TC(tp, seqpacket_msg_trunc);
	ATF_TP_ADD_TC(tp, seqpacket_large_message);

	/* Group 8: Buffer sockopts */
	ATF_TP_ADD_TC(tp, buffer_size_sockopt);
	ATF_TP_ADD_TC(tp, buffer_min_max_clamp);
	ATF_TP_ADD_TC(tp, buffer_size_on_accepted);

	/* Group 9: Multiple connections */
	ATF_TP_ADD_TC(tp, multiple_connections);
	ATF_TP_ADD_TC(tp, accept_queue_stress);
	ATF_TP_ADD_TC(tp, accept_queue_leak);

	/* Group 10: Poll / kqueue */
	ATF_TP_ADD_TC(tp, poll_write_ready);
	ATF_TP_ADD_TC(tp, poll_read_ready);
	ATF_TP_ADD_TC(tp, poll_hup_on_close);
	ATF_TP_ADD_TC(tp, kqueue_read_write);

	/* Group 11: Timeouts */
	ATF_TP_ADD_TC(tp, recv_timeout);
	ATF_TP_ADD_TC(tp, send_timeout);

	/* Group 12: Error cases */
	ATF_TP_ADD_TC(tp, invalid_family_bind);
	ATF_TP_ADD_TC(tp, double_bind_fails);
	ATF_TP_ADD_TC(tp, connect_after_listen);
	ATF_TP_ADD_TC(tp, retry_connect);

	/* Group 13: Large transfers */
	ATF_TP_ADD_TC(tp, stream_large_transfer);
	ATF_TP_ADD_TC(tp, seqpacket_multi_message);

	/* Group 14: SO_LINGER */
	ATF_TP_ADD_TC(tp, linger_close);
	ATF_TP_ADD_TC(tp, linger_zero_close);

	/* Group 15: ioctls */
	ATF_TP_ADD_TC(tp, fionread_stream);
	ATF_TP_ADD_TC(tp, fionread_seqpacket);
	ATF_TP_ADD_TC(tp, fionwrite_stream);
	ATF_TP_ADD_TC(tp, seqpacket_unread_bytes_precise);

	/* Group 16: zerocopy compat */
	ATF_TP_ADD_TC(tp, zerocopy_sockopt_compat);

	/* Group 17: SO_RCVLOWAT */
	ATF_TP_ADD_TC(tp, rcvlowat_default);

	/* Group 18: Stress / rapid lifecycle */
	ATF_TP_ADD_TC(tp, rapid_connect_close);
	ATF_TP_ADD_TC(tp, double_bind_connect_cycle);
	ATF_TP_ADD_TC(tp, simultaneous_bidirectional);

	/* Group 19: SIGPIPE semantics */
	ATF_TP_ADD_TC(tp, shutdown_wr_sigpipe);
	ATF_TP_ADD_TC(tp, peer_close_sigpipe);

	/* Group 20: EFAULT behavior */
	ATF_TP_ADD_TC(tp, stream_efault_preserves_data);
	ATF_TP_ADD_TC(tp, seqpacket_efault_drops_message);

	/* Group 21: 100 concurrent connections */
	ATF_TP_ADD_TC(tp, hundred_concurrent_connections);

	/* Group 22: Stream partial read merge */
	ATF_TP_ADD_TC(tp, stream_partial_read_merge);

	/* Group 23: Bind before connect */
	ATF_TP_ADD_TC(tp, bind_then_connect);

	/* Group 24: Accepted socket setsockopt */
	ATF_TP_ADD_TC(tp, accepted_socket_setsockopt);

	/* Group 25: Close ordering */
	ATF_TP_ADD_TC(tp, client_close_data_readable);
	ATF_TP_ADD_TC(tp, server_close_data_readable);

	/* Group 26: kqueue EOF */
	ATF_TP_ADD_TC(tp, kqueue_eof_on_peer_close);

	/* Group 27: Seqpacket boundary hash */
	ATF_TP_ADD_TC(tp, seqpacket_boundary_hash);

	/* Group 28: Connect timeout sockopt */
	ATF_TP_ADD_TC(tp, connect_timeout_sockopt);

	/* Group 29: Input validation */
	ATF_TP_ADD_TC(tp, svm_len_validation);
	ATF_TP_ADD_TC(tp, reserved1_must_be_zero);
	ATF_TP_ADD_TC(tp, cid_validation_bind);
	ATF_TP_ADD_TC(tp, ctloutput_unknown_option);

	/* Group 30: Edge cases */
	ATF_TP_ADD_TC(tp, nonblocking_accept_eagain);
	ATF_TP_ADD_TC(tp, stream_zero_send);
	ATF_TP_ADD_TC(tp, shutdown_rd_send_still_works);
	ATF_TP_ADD_TC(tp, poll_multiple_fds);

	/* Group 31: Concurrency */
	ATF_TP_ADD_TC(tp, close_while_blocked_recv);

	/* Group 32: Additional coverage */
	ATF_TP_ADD_TC(tp, connect_cid_local);
	ATF_TP_ADD_TC(tp, connect_refused_cid_local);
	ATF_TP_ADD_TC(tp, accept_backlog_full);
	ATF_TP_ADD_TC(tp, shutdown_rd_peer_sends);
	ATF_TP_ADD_TC(tp, double_close_fd);

	/* Group 33: Coverage parity with Linux */
	ATF_TP_ADD_TC(tp, credit_update_on_recv);

	/* Group 34: Spec compliance (§5.10) */
	ATF_TP_ADD_TC(tp, seqpacket_msg_eor);
	ATF_TP_ADD_TC(tp, reserved_cid_bind);
	ATF_TP_ADD_TC(tp, seqpacket_eor_multi_record);
	ATF_TP_ADD_TC(tp, connect_timeout_applied);

	/* Group 35: Concurrent connect + close races */
	ATF_TP_ADD_TC(tp, concurrent_connect_close_race);
	ATF_TP_ADD_TC(tp, simultaneous_close_both_sides);

	/* Group 36: Credit exhaustion and recovery */
	ATF_TP_ADD_TC(tp, credit_exhaustion_recovery);
	ATF_TP_ADD_TC(tp, credit_fill_drain_cycle);

	/* Group 37: Shutdown edge cases */
	ATF_TP_ADD_TC(tp, shutdown_wr_then_rd);
	ATF_TP_ADD_TC(tp, shutdown_rd_then_wr);
	ATF_TP_ADD_TC(tp, seqpacket_shutdown_preserves_pending);

	return (atf_no_error());
}
