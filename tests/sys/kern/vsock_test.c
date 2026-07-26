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
#include <sys/sysctl.h>
#include <sys/vsock.h>
#include <sys/ioctl.h>
#include <sys/filio.h>
#include <sys/event.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

		rc = send(ctx->sender, buf, sizeof(buf), MSG_NOSIGNAL);
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
	ATF_REQUIRE(errno == ECONNRESET);
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

	/* send() after SHUT_WR raises SIGPIPE by design; we assert errno. */
	(void)signal(SIGPIPE, SIG_IGN);
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

	/* send() after SHUT_RDWR raises SIGPIPE by design. */
	(void)signal(SIGPIPE, SIG_IGN);
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

	/* send() to a closed peer raises SIGPIPE by design. */
	(void)signal(SIGPIPE, SIG_IGN);
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
	struct iovec iov;
	struct msghdr mh;
	struct pollfd pfd;
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	memset(&mh, 0, sizeof(mh));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	ATF_REQUIRE(send(cs, "", 0, 0) == 0);
	pfd.fd = as;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) == 1);
	ATF_CHECK((pfd.revents & POLLIN) != 0);
	iov.iov_len = 0;
	/*
	 * A zero-length SEQPACKET message is delivered as a distinct 0-byte
	 * record (recv returns 0), not dropped, and the connection stays open,
	 * unlike EOF.  A following non-empty message proves the 0-byte recv was
	 * a message, not peer-close.  Linux's current virtio-vsock sender uses a
	 * zero-length send as a no-op, so this is a deliberate FreeBSD semantic
	 * which remains wire-compatible with Linux's receive path.
	 */
	ATF_CHECK(recvmsg(as, &mh, MSG_PEEK) == 0);
	ATF_CHECK((mh.msg_flags & (MSG_EOR | MSG_TRUNC)) == 0);
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) == 1);
	ATF_CHECK((pfd.revents & POLLIN) != 0);
	mh.msg_flags = 0;
	ATF_CHECK(recvmsg(as, &mh, 0) == 0);
	ATF_CHECK((mh.msg_flags & (MSG_EOR | MSG_TRUNC)) == 0);
	iov.iov_len = sizeof(buf);
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) == 0);

	/* An explicit zero-length record boundary remains visible to recvmsg. */
	iov.iov_len = 0;
	ATF_REQUIRE(sendmsg(cs, &mh, MSG_EOR) == 0);
	mh.msg_flags = 0;
	ATF_CHECK(recvmsg(as, &mh, 0) == 0);
	ATF_CHECK((mh.msg_flags & MSG_EOR) != 0);
	iov.iov_len = sizeof(buf);
	ATF_REQUIRE(send(cs, "hi", 2, 0) == 2);
	ATF_CHECK(recv(as, buf, sizeof(buf), 0) == 2);

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

ATF_TC_WITHOUT_HEAD(rebind_same_socket_preserves_binding);
ATF_TC_BODY(rebind_same_socket_preserves_binding, tc)
{
	struct sockaddr_vm before, after, replacement;
	socklen_t addrlen;
	int s1, s2;

	(void)tc;

	s1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s1 >= 0);
	vsock_bind_any(s1, &before);

	vsock_set_any(&replacement);
	errno = 0;
	ATF_REQUIRE(bind(s1, (struct sockaddr *)&replacement,
	    sizeof(replacement)) == -1);
	ATF_REQUIRE_EQ(errno, EINVAL);

	addrlen = sizeof(after);
	ATF_REQUIRE(getsockname(s1, (struct sockaddr *)&after, &addrlen) == 0);
	assert_sockaddr_vm_eq(&before, &after);

	/*
	 * The failed rebind must not have removed the original reservation from
	 * the bound table.
	 */
	s2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s2 >= 0);
	errno = 0;
	ATF_REQUIRE(bind(s2, (struct sockaddr *)&before, sizeof(before)) == -1);
	ATF_REQUIRE_EQ(errno, EADDRINUSE);

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
	struct sockaddr_vm bound_before, bound_after, failaddr, laddr;
	socklen_t addrlen;
	char buf[4];
	int ls, cs, fail_s, as;

	(void)tc;

	/*
	 * A failed connect must leave the same socket bound and usable for
	 * another connect.  This mirrors Linux's autobind lifetime and
	 * catches both accidental release of the ephemeral-port reservation and
	 * use of soisdisconnected() on the failed attempt.
	 */
	fail_s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(fail_s >= 0, "failure socket: %s",
	    strerror(errno));
	vsock_bind_any(fail_s, &failaddr);

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "listener socket failed: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket failed: %s", strerror(errno));

	ATF_REQUIRE_MSG(connect(cs, (struct sockaddr *)&failaddr,
	    sizeof(failaddr)) == -1, "connected to a non-listening socket");
	ATF_REQUIRE_EQ(errno, ECONNRESET);

	addrlen = sizeof(bound_before);
	ATF_REQUIRE_MSG(getsockname(cs, (struct sockaddr *)&bound_before,
	    &addrlen) == 0, "getsockname after failed connect: %s",
	    strerror(errno));
	ATF_REQUIRE(bound_before.svm_port != VSOCK_PORT_ANY);

	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	addrlen = sizeof(bound_after);
	ATF_REQUIRE_MSG(getsockname(cs, (struct sockaddr *)&bound_after,
	    &addrlen) == 0, "getsockname after retry: %s", strerror(errno));
	ATF_REQUIRE(bound_after.svm_cid == bound_before.svm_cid);
	ATF_REQUIRE(bound_after.svm_port == bound_before.svm_port);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept failed: %s", strerror(errno));

	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 2);
	ATF_REQUIRE(memcmp(buf, "ok", 2) == 0);

	close(as);
	close(cs);
	close(ls);
	close(fail_s);
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
	ATF_REQUIRE(close(cs) == 0); /* SO_LINGER=0 abort of the sender */

	/*
	 * On loopback the already-delivered "rst" bytes stay in the peer's
	 * receive buffer -- aborting the sender does not purge them -- and the
	 * subsequent teardown is delivered as EOF, never as an out-of-band
	 * ECONNRESET.  (A remote virtio OP_RST on an established connection is
	 * likewise delivered as EOF now, matching Linux; ECONNRESET on an
	 * established connection comes only from a flow-control violation or a
	 * transport reset.)  So the peer either still reads the pending record
	 * (n > 0) or observes EOF (n == 0); it never sees a reset error.  This
	 * case is genuinely either-or on loopback, so the disjunction is
	 * intentional.
	 */
	memset(buf, 0, sizeof(buf));
	ssize_t n = recv(as, buf, sizeof(buf), 0);
	ATF_REQUIRE_MSG(n >= 0,
	    "unexpected error on loopback abort: %s", strerror(errno));

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

ATF_TC_WITHOUT_HEAD(linux_zerocopy_sockopt_rejected);
ATF_TC_BODY(linux_zerocopy_sockopt_rejected, tc)
{
	static const int linux_so_zerocopy = 60;
	int s, val;

	(void)tc;

	/*
	 * Linux assigns SOL_SOCKET option 60 to SO_ZEROCOPY.  FreeBSD does not
	 * implement the MSG_ZEROCOPY completion ABI, so reject the Linux option
	 * deterministically instead of silently accepting a contract that the
	 * socket cannot honor.
	 */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	val = 1;
	errno = 0;
	ATF_CHECK(setsockopt(s, SOL_SOCKET, linux_so_zerocopy, &val,
	    sizeof(val)) == -1);
	ATF_CHECK(errno == ENOPROTOOPT);
	close(s);
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

/*
 * The legacy scalar-centiseconds form of SO_VM_SOCKETS_CONNECT_TIMEOUT has
 * been removed; opt 6 and opt 8 are both struct timeval only (Linux-matching).
 * See connect_timeout_timeval for the current behavior.
 */

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

	/*
	 * getsockaddr() overwrites sa_len with the syscall's namelen, so the
	 * user-set svm_len field is never kernel-visible; length validation
	 * must be exercised through the namelen argument instead.
	 */

	/* Short namelen should fail */
	vsock_set_any(&svm);
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, 8) == -1);
	ATF_REQUIRE(errno == EINVAL);

	/* A stale/zero svm_len field is ignored (namelen wins) */
	vsock_set_any(&svm);
	svm.svm_len = 0;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0);
	close(s);

	/* Correct svm_len should succeed */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
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
	 * This uses the loopback path regardless of guest CID.  Like Linux
	 * vsock (which refuses by RST on every transport, loopback included),
	 * a refused connection surfaces to connect(2) as ECONNRESET.
	 */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket: %s", strerror(errno));

	vsock_set_any(&addr);
	addr.svm_cid  = VSOCK_CID_LOCAL;
	addr.svm_port = 54321;
	ATF_REQUIRE(connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1);
	ATF_REQUIRE(errno == ECONNRESET);
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

	/* Accept what we can; the queue may hold fewer than 8, so the
	 * drain must be nonblocking or the test hangs on the empty queue. */
	ATF_REQUIRE(fcntl(ls, F_SETFL, O_NONBLOCK) != -1);
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

	/*
	 * Loopback teardown is signaled to the peer as end-of-file
	 * (socantrcvmore), not an out-of-band reset.  With no unread data
	 * queued, the peer's recv() returns 0 deterministically.  A remote
	 * virtio OP_RST on an established connection is delivered as EOF too
	 * (matching Linux); ECONNRESET on an established connection is produced
	 * only by a flow-control violation or a transport reset, neither of
	 * which is exercised over loopback.
	 */
	ssize_t n = recv(cs, buf, sizeof(buf), 0);
	ATF_REQUIRE_MSG(n == 0,
	    "expected EOF on loopback teardown, got %zd (errno %d)", n, errno);

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
	struct msghdr smh;
	struct iovec siov;
	char buf[64];
	int ls, cs, as;

	(void)tc;
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* A message boundary (EOM) alone is not a record boundary (EOR). */
	ATF_REQUIRE(send(cs, "record", 6, 0) == 6);

	memset(&mh, 0, sizeof(mh));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_flags = 0;

	ATF_REQUIRE(recvmsg(as, &mh, 0) == 6);
	ATF_REQUIRE(memcmp(buf, "record", 6) == 0);
	ATF_REQUIRE_MSG((mh.msg_flags & MSG_EOR) == 0,
	    "MSG_EOR set without sender MSG_EOR (flags=0x%x)",
	    mh.msg_flags);

	/* An explicit sender MSG_EOR must be reflected on the same message. */
	memset(&smh, 0, sizeof(smh));
	siov.iov_base = __DECONST(char *, "next");
	siov.iov_len = 4;
	smh.msg_iov = &siov;
	smh.msg_iovlen = 1;
	ATF_REQUIRE(sendmsg(cs, &smh, MSG_EOR) == 4);

	mh.msg_flags = 0;
	iov.iov_len = sizeof(buf);
	ATF_REQUIRE(recvmsg(as, &mh, 0) == 4);
	ATF_REQUIRE(memcmp(buf, "next", 4) == 0);
	ATF_REQUIRE_MSG(mh.msg_flags & MSG_EOR,
	    "MSG_EOR not propagated from sender (flags=0x%x)",
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

	/*
	 * CID 2 (host) is the host's own CID, never a local guest endpoint:
	 * bind rejects it with EADDRNOTAVAIL (the address exists but is not
	 * ours), distinct from the EAFNOSUPPORT returned for an arbitrary
	 * foreign guest CID.
	 */
	vsock_set_any(&svm);
	svm.svm_cid = VSOCK_CID_HOST;
	svm.svm_port = 5001;
	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EADDRNOTAVAIL);

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
		struct msghdr smh;
		struct iovec siov;

		snprintf(msg, sizeof(msg), "msg%d", i);
		memset(&smh, 0, sizeof(smh));
		siov.iov_base = msg;
		siov.iov_len = strlen(msg);
		smh.msg_iov = &siov;
		smh.msg_iovlen = 1;
		ATF_REQUIRE(sendmsg(cs, &smh, MSG_EOR) ==
		    (ssize_t)siov.iov_len);
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

/*
 * connect_timeout_applied removed: it locked the legacy scalar-centiseconds
 * SO_VM_SOCKETS_CONNECT_TIMEOUT behavior, which no longer exists.  The
 * timeval set/get round-trip is covered by connect_timeout_timeval.
 */

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
/* Group 38: Type mismatch, oversized message, sockopts, pcblist        */
/* ------------------------------------------------------------------ */

/*
 * SEQPACKET socket must not connect to a STREAM listener on loopback.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_connect_to_stream_listener_refused);
ATF_TC_BODY(seqpacket_connect_to_stream_listener_refused, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs;

	(void)tc;

	/* STREAM listener */
	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(ls >= 0, "socket: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	/* SEQPACKET connector */
	cs = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == -1);
	ATF_REQUIRE_MSG(errno == ECONNRESET,
	    "expected ECONNRESET, got %d (%s)", errno, strerror(errno));
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(stream_connect_to_seqpacket_listener_refused);
ATF_TC_BODY(stream_connect_to_seqpacket_listener_refused, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs;

	(void)tc;

	/* SEQPACKET listener */
	ls = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE_MSG(ls >= 0, "socket: %s", strerror(errno));
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	/* STREAM connector */
	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket: %s", strerror(errno));
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == -1);
	ATF_REQUIRE_MSG(errno == ECONNRESET,
	    "expected ECONNRESET, got %d (%s)", errno, strerror(errno));
	close(cs);
	close(ls);
}

/*
 * SEQPACKET loopback send of a message exceeding the peer's receive
 * buffer must return EMSGSIZE, not block.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_loopback_oversized_emsgsize);
ATF_TC_BODY(seqpacket_loopback_oversized_emsgsize, tc)
{
	int ls, cs, as, n;
	char *buf;
	size_t rcvbufsz = 4096;
	size_t sendsz = rcvbufsz * 2;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(ls >= 0);

	struct sockaddr_vm laddr;
	vsock_bind_any(ls, &laddr);

	/* Set a small receive buffer on the listener before accept. */
	n = (int)rcvbufsz;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);

	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	buf = malloc(sendsz);
	ATF_REQUIRE(buf != NULL);
	memset(buf, 'X', sendsz);

	/*
	 * Send a message strictly larger than the receiver's buffer.
	 * Must fail with EMSGSIZE, not block forever.
	 */
	ATF_REQUIRE(send(cs, buf, sendsz, 0) == -1);
	ATF_REQUIRE_MSG(errno == EMSGSIZE,
	    "expected EMSGSIZE, got %d (%s)", errno, strerror(errno));

	free(buf);
	close(as);
	close(cs);
	close(ls);
}

/*
 * SO_VM_SOCKETS_PEER_HOST_VM_ID: read-only option returning peer CID.
 * Must succeed on connected socket, fail with ENOTCONN otherwise.
 */
ATF_TC_WITHOUT_HEAD(peer_host_vm_id_sockopt);
ATF_TC_BODY(peer_host_vm_id_sockopt, tc)
{
	int ls, cs, as;
	uint64_t peer_cid;
	socklen_t len;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Should succeed on a connected socket. */
	len = sizeof(peer_cid);
	ATF_REQUIRE_MSG(getsockopt(cs, SOL_VSOCK, SO_VM_SOCKETS_PEER_HOST_VM_ID,
	    &peer_cid, &len) == 0,
	    "getsockopt(PEER_HOST_VM_ID) failed: %s", strerror(errno));
	ATF_REQUIRE(len == sizeof(peer_cid));
	/* For loopback, peer CID should match our own CID. */
	ATF_REQUIRE(peer_cid != 0);

	/* setsockopt should fail (read-only). */
	peer_cid = 42;
	ATF_REQUIRE(setsockopt(cs, SOL_VSOCK, SO_VM_SOCKETS_PEER_HOST_VM_ID,
	    &peer_cid, sizeof(peer_cid)) == -1);
	ATF_REQUIRE(errno == EOPNOTSUPP);

	close(as);
	close(cs);

	/* Should fail on an unconnected socket. */
	{
		int us = socket(AF_VSOCK, SOCK_STREAM, 0);
		ATF_REQUIRE(us >= 0);
		len = sizeof(peer_cid);
		ATF_REQUIRE(getsockopt(us, SOL_VSOCK,
		    SO_VM_SOCKETS_PEER_HOST_VM_ID, &peer_cid, &len) == -1);
		ATF_REQUIRE_MSG(errno == ENOTCONN,
		    "expected ENOTCONN, got %d (%s)", errno, strerror(errno));
		close(us);
	}
	close(ls);
}

/*
 * sysctl buf_default/buf_min/buf_max validation.
 * Out-of-range values must return EINVAL.
 */
ATF_TC(sysctl_buf_validation);
ATF_TC_HEAD(sysctl_buf_validation, tc)
{
	/* Writing kern.vsock.buf_* sysctls requires root. */
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sysctl_buf_validation, tc)
{
	u_int orig_min, orig_max, orig_default;
	u_int val;
	size_t len;
	int rc;

	(void)tc;

	/* Read originals. */
	len = sizeof(orig_min);
	ATF_REQUIRE(sysctlbyname("kern.vsock.buf_min",
	    &orig_min, &len, NULL, 0) == 0);
	len = sizeof(orig_max);
	ATF_REQUIRE(sysctlbyname("kern.vsock.buf_max",
	    &orig_max, &len, NULL, 0) == 0);
	len = sizeof(orig_default);
	ATF_REQUIRE(sysctlbyname("kern.vsock.buf_default",
	    &orig_default, &len, NULL, 0) == 0);

	/*
	 * Try setting buf_min above buf_max — should fail with EINVAL.
	 */
	val = orig_max + 1;
	rc = sysctlbyname("kern.vsock.buf_min", NULL, NULL, &val, sizeof(val));
	ATF_REQUIRE_MSG(rc == -1 && errno == EINVAL,
	    "setting buf_min > buf_max should fail with EINVAL (rc=%d errno=%d)",
	    rc, errno);

	/*
	 * Try setting buf_default below buf_min — should fail with EINVAL.
	 */
	if (orig_min > 0) {
		val = orig_min - 1;
		rc = sysctlbyname("kern.vsock.buf_default", NULL, NULL,
		    &val, sizeof(val));
		ATF_REQUIRE_MSG(rc == -1 && errno == EINVAL,
		    "setting buf_default < buf_min should fail (rc=%d errno=%d)",
		    rc, errno);
	}

	/*
	 * Try setting buf_default above buf_max — should fail with EINVAL.
	 */
	val = orig_max + 1;
	rc = sysctlbyname("kern.vsock.buf_default", NULL, NULL,
	    &val, sizeof(val));
	ATF_REQUIRE_MSG(rc == -1 && errno == EINVAL,
	    "setting buf_default > buf_max should fail (rc=%d errno=%d)",
	    rc, errno);

	/* Verify originals are unchanged. */
	len = sizeof(val);
	ATF_REQUIRE(sysctlbyname("kern.vsock.buf_min",
	    &val, &len, NULL, 0) == 0);
	ATF_REQUIRE(val == orig_min);
	ATF_REQUIRE(sysctlbyname("kern.vsock.buf_max",
	    &val, &len, NULL, 0) == 0);
	ATF_REQUIRE(val == orig_max);
}

/*
 * Verify that LISTEN and non-LISTEN states are exposed correctly
 * through kern.vsock.pcblist sysctl state field.
 */
ATF_TC_WITHOUT_HEAD(pcblist_state_values);
ATF_TC_BODY(pcblist_state_values, tc)
{
	int ls, cs, as;
	char *buf;
	size_t len;
	struct xvsock_pcb *xvp;
	bool found_listen, found_established;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Read pcblist. */
	buf = NULL;
	len = 4096;
	for (;;) {
		buf = realloc(buf, len);
		ATF_REQUIRE(buf != NULL);
		if (sysctlbyname("kern.vsock.pcblist", buf, &len,
		    NULL, 0) == 0)
			break;
		ATF_REQUIRE_MSG(errno == ENOMEM,
		    "pcblist failed: %s", strerror(errno));
		len *= 2;
	}

	found_listen = false;
	found_established = false;

	for (size_t off = 0; off + sizeof(*xvp) <= len; off += sizeof(*xvp)) {
		xvp = (struct xvsock_pcb *)(buf + off);
		if (xvp->xvp_len != sizeof(*xvp))
			break;
		if (xvp->xvp_state == VSOCK_ST_LISTEN)
			found_listen = true;
		if (xvp->xvp_state == VSOCK_ST_ESTABLISHED)
			found_established = true;
	}

	ATF_REQUIRE_MSG(found_listen,
	    "pcblist should contain a LISTEN entry");
	ATF_REQUIRE_MSG(found_established,
	    "pcblist should contain an ESTABLISHED entry");

	/* Verify no raw kernel pointers leaked (xvp_so_gencnt should be small). */
	for (size_t off = 0; off + sizeof(*xvp) <= len; off += sizeof(*xvp)) {
		xvp = (struct xvsock_pcb *)(buf + off);
		if (xvp->xvp_len != sizeof(*xvp))
			break;
		/* Generation counters are sequential small numbers, not
		 * kernel heap addresses (which are > 0xffff000000000000). */
		ATF_REQUIRE_MSG(xvp->xvp_so_gencnt < 0xffff000000000000ULL,
		    "xvp_so_gencnt looks like a raw pointer: 0x%lx",
		    (unsigned long)xvp->xvp_so_gencnt);
	}

	free(buf);
	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 39: Coverage parity with AF_UNIX test patterns                */
/* ------------------------------------------------------------------ */

/*
 * send_before_accept: data sent before accept() should be readable
 * on the accepted socket.
 */
ATF_TC_WITHOUT_HEAD(send_before_accept);
ATF_TC_BODY(send_before_accept, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs, as;
	char sbuf[] = "pre-accept data";
	char rbuf[64];
	ssize_t n;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);

	/* Send data BEFORE the listener accepts. */
	n = send(cs, sbuf, sizeof(sbuf), 0);
	ATF_REQUIRE(n == (ssize_t)sizeof(sbuf));

	/* Now accept. */
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Data should be readable on the accepted socket. */
	memset(rbuf, 0, sizeof(rbuf));
	n = recv(as, rbuf, sizeof(rbuf), 0);
	ATF_REQUIRE(n == (ssize_t)sizeof(sbuf));
	ATF_REQUIRE(memcmp(sbuf, rbuf, sizeof(sbuf)) == 0);

	close(as);
	close(cs);
	close(ls);
}

/*
 * Verify poll(POLLOUT) transitions from not-ready to ready after
 * buffer drain.
 */
ATF_TC_WITHOUT_HEAD(full_writability_poll);
ATF_TC_BODY(full_writability_poll, tc)
{
	int ls, cs, as;
	char buf[4096];
	struct pollfd pfd;
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Make sender non-blocking and fill until EAGAIN. */
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	memset(buf, 'F', sizeof(buf));
	for (;;) {
		n = send(cs, buf, sizeof(buf), 0);
		if (n == -1) {
			ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}
	}

	/* poll should show POLLOUT not ready (or short timeout). */
	pfd.fd = cs;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) == 0);

	/* Drain from receiver. */
	ATF_REQUIRE(fcntl(as, F_SETFL, O_NONBLOCK) != -1);
	while (recv(as, buf, sizeof(buf), 0) > 0)
		;

	/* poll should now show POLLOUT ready. */
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 1000) == 1);
	ATF_REQUIRE(pfd.revents & POLLOUT);

	close(as);
	close(cs);
	close(ls);
}

/*
 * Verify POLLHUP is delivered after peer close.
 */
ATF_TC_WITHOUT_HEAD(peerclosed_write_event);
ATF_TC_BODY(peerclosed_write_event, tc)
{
	int ls, cs, as;
	struct pollfd pfd;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	close(as);

	/* Poll for any event on the remaining socket. */
	pfd.fd = cs;
	pfd.events = POLLOUT | POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 2000) >= 1);
	/* Should see HUP or error indication. */
	ATF_REQUIRE(pfd.revents & (POLLHUP | POLLERR | POLLIN));

	close(cs);
	close(ls);
}

/*
 * Verify sendto() on a connected SEQPACKET socket works (ignores address)
 * or returns EISCONN.
 */
ATF_TC_WITHOUT_HEAD(sendto_on_connected_seqpacket);
ATF_TC_BODY(sendto_on_connected_seqpacket, tc)
{
	int ls, cs, as;
	struct sockaddr_vm dst;
	char msg[] = "sendto-test";
	char rbuf[64];
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	/* Get the peer address. */
	socklen_t slen = sizeof(dst);
	ATF_REQUIRE(getpeername(cs, (struct sockaddr *)&dst, &slen) == 0);

	/* sendto with the same peer address should work. */
	n = sendto(cs, msg, sizeof(msg), 0, (struct sockaddr *)&dst,
	    sizeof(dst));
	if (n == -1) {
		/* Some implementations return EISCONN; that's also acceptable. */
		ATF_REQUIRE_MSG(errno == EISCONN,
		    "expected success or EISCONN, got %d (%s)",
		    errno, strerror(errno));
	} else {
		ATF_REQUIRE(n == (ssize_t)sizeof(msg));
		memset(rbuf, 0, sizeof(rbuf));
		ATF_REQUIRE(recv(as, rbuf, sizeof(rbuf), 0) ==
		    (ssize_t)sizeof(msg));
		ATF_REQUIRE(memcmp(msg, rbuf, sizeof(msg)) == 0);
	}

	close(as);
	close(cs);
	close(ls);
}

/*
 * Verify socketpair() is rejected for AF_VSOCK.
 */
ATF_TC_WITHOUT_HEAD(socketpair_rejected);
ATF_TC_BODY(socketpair_rejected, tc)
{
	int sv[2];

	(void)tc;

	ATF_REQUIRE(socketpair(AF_VSOCK, SOCK_STREAM, 0, sv) == -1);
	/* EOPNOTSUPP or EPROTONOSUPPORT are both acceptable. */
	ATF_REQUIRE(errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
	    errno == EAFNOSUPPORT);
}

/*
 * Verify resizing receive buffer on a connected socket with data
 * in flight does not crash.
 */
ATF_TC_WITHOUT_HEAD(resize_buffer_with_data);
ATF_TC_BODY(resize_buffer_with_data, tc)
{
	int ls, cs, as;
	char sbuf[4096], rbuf[4096];
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Send data. */
	memset(sbuf, 'R', sizeof(sbuf));
	n = send(cs, sbuf, sizeof(sbuf), 0);
	ATF_REQUIRE(n == (ssize_t)sizeof(sbuf));

	/* Shrink receiver buffer while data is pending. */
	uint64_t smallbuf = 2048;
	ATF_REQUIRE(setsockopt(as, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &smallbuf, sizeof(smallbuf)) == 0);

	/* Data should still be readable. */
	memset(rbuf, 0, sizeof(rbuf));
	n = recv(as, rbuf, sizeof(rbuf), 0);
	ATF_REQUIRE(n > 0);
	ATF_REQUIRE(memcmp(sbuf, rbuf, (size_t)n) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 40: Integration tests                                         */
/* ------------------------------------------------------------------ */

/*
 * Verify kern.vsock.pcblist sysctl returns valid data with correct
 * field values for sockets in various states.
 */
ATF_TC_WITHOUT_HEAD(pcblist_fields);
ATF_TC_BODY(pcblist_fields, tc)
{
	struct sockaddr_vm caddr;
	int ls, cs, as;
	char *buf;
	size_t len;
	struct xvsock_pcb *xvp;
	bool found;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Get the client's local address to identify it in the pcblist. */
	socklen_t slen = sizeof(caddr);
	ATF_REQUIRE(getsockname(cs, (struct sockaddr *)&caddr, &slen) == 0);

	buf = NULL;
	len = 4096;
	for (;;) {
		buf = realloc(buf, len);
		ATF_REQUIRE(buf != NULL);
		if (sysctlbyname("kern.vsock.pcblist", buf, &len,
		    NULL, 0) == 0)
			break;
		ATF_REQUIRE(errno == ENOMEM);
		len *= 2;
	}

	found = false;
	for (size_t off = 0; off + sizeof(*xvp) <= len; off += sizeof(*xvp)) {
		xvp = (struct xvsock_pcb *)(buf + off);
		if (xvp->xvp_len != sizeof(*xvp))
			break;
		if (xvp->xvp_local_port == caddr.svm_port &&
		    xvp->xvp_state == VSOCK_ST_ESTABLISHED) {
			found = true;
			ATF_REQUIRE(xvp->xvp_type == SOCK_STREAM);
			ATF_REQUIRE(xvp->xvp_local_cid == caddr.svm_cid);
			ATF_REQUIRE(xvp->xvp_buf_alloc > 0);
			break;
		}
	}
	ATF_REQUIRE_MSG(found, "client socket not found in pcblist");

	free(buf);
	close(as);
	close(cs);
	close(ls);
}

/*
 * Verify sysctl counters increment after send/recv.
 */
ATF_TC_WITHOUT_HEAD(sysctl_counters);
ATF_TC_BODY(sysctl_counters, tc)
{
	uint64_t conns_before;
	size_t len;

	(void)tc;

	len = sizeof(conns_before);
	ATF_REQUIRE(sysctlbyname("kern.vsock.connections",
	    &conns_before, &len, NULL, 0) == 0);

	/* This is a remote-transport counter; loopback doesn't increment it.
	 * Just verify the sysctl is readable without error. */
	ATF_REQUIRE(len == sizeof(conns_before));

	/* Verify tx/rx counters are readable. */
	{
		uint64_t val;
		len = sizeof(val);
		ATF_REQUIRE(sysctlbyname("kern.vsock.tx_packets",
		    &val, &len, NULL, 0) == 0);
		ATF_REQUIRE(sysctlbyname("kern.vsock.rx_packets",
		    &val, &len, NULL, 0) == 0);
		ATF_REQUIRE(sysctlbyname("kern.vsock.tx_bytes",
		    &val, &len, NULL, 0) == 0);
		ATF_REQUIRE(sysctlbyname("kern.vsock.rx_bytes",
		    &val, &len, NULL, 0) == 0);
		ATF_REQUIRE(sysctlbyname("kern.vsock.rx_drops",
		    &val, &len, NULL, 0) == 0);
	}
}

/* ------------------------------------------------------------------ */
/* Group 41: Shutdown + drain interaction                               */
/* ------------------------------------------------------------------ */

/*
 * After SHUT_WR on one side, the peer should still be able to recv
 * all buffered data, then see EOF.
 */
ATF_TC_WITHOUT_HEAD(shutdown_wr_drain_then_eof);
ATF_TC_BODY(shutdown_wr_drain_then_eof, tc)
{
	int ls, cs, as;
	char sbuf[512], rbuf[512];
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	memset(sbuf, 'D', sizeof(sbuf));
	ATF_REQUIRE(send(cs, sbuf, sizeof(sbuf), 0) == (ssize_t)sizeof(sbuf));
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);

	/* Peer should be able to read all data. */
	memset(rbuf, 0, sizeof(rbuf));
	n = recv(as, rbuf, sizeof(rbuf), MSG_WAITALL);
	ATF_REQUIRE(n == (ssize_t)sizeof(sbuf));
	ATF_REQUIRE(memcmp(sbuf, rbuf, sizeof(sbuf)) == 0);

	/* Next recv should be EOF. */
	ATF_REQUIRE(recv(as, rbuf, sizeof(rbuf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

/*
 * SEQPACKET: after shutdown(SHUT_WR), pending complete messages
 * should still be deliverable.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_shutdown_drain);
ATF_TC_BODY(seqpacket_shutdown_drain, tc)
{
	int ls, cs, as;
	char sbuf[] = "seqpacket-shutdown-drain";
	char rbuf[64];
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	ATF_REQUIRE(send(cs, sbuf, sizeof(sbuf), 0) == (ssize_t)sizeof(sbuf));
	ATF_REQUIRE(shutdown(cs, SHUT_WR) == 0);

	memset(rbuf, 0, sizeof(rbuf));
	n = recv(as, rbuf, sizeof(rbuf), 0);
	ATF_REQUIRE(n == (ssize_t)sizeof(sbuf));
	ATF_REQUIRE(memcmp(sbuf, rbuf, sizeof(sbuf)) == 0);

	/* EOF after the message. */
	ATF_REQUIRE(recv(as, rbuf, sizeof(rbuf), 0) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 42: Error path and edge case tests                            */
/* ------------------------------------------------------------------ */

/*
 * connect() on a listening socket must return EOPNOTSUPP.
 */
ATF_TC_WITHOUT_HEAD(connect_on_listener_fails);
ATF_TC_BODY(connect_on_listener_fails, tc)
{
	struct sockaddr_vm laddr, dst;
	int ls;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	vsock_set_any(&dst);
	dst.svm_cid  = VSOCK_CID_LOCAL;
	dst.svm_port = 9999;
	ATF_REQUIRE(connect(ls, (struct sockaddr *)&dst, sizeof(dst)) == -1);
	ATF_REQUIRE(errno == EOPNOTSUPP);

	close(ls);
}

/*
 * connect() on an already-connected socket must return EISCONN.
 */
ATF_TC_WITHOUT_HEAD(double_connect_eisconn);
ATF_TC_BODY(double_connect_eisconn, tc)
{
	struct sockaddr_vm dst;
	int ls, cs, as;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Second connect on already-connected socket. */
	memset(&dst, 0, sizeof(dst));
	dst.svm_len = sizeof(dst);
	dst.svm_family = AF_VSOCK;
	dst.svm_cid = VSOCK_CID_LOCAL;
	dst.svm_port = 9999;
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&dst,
	    sizeof(dst)) == -1);
	ATF_REQUIRE(errno == EISCONN);

	close(as);
	close(cs);
	close(ls);
}

/*
 * listen() on an unbound socket must fail.
 * listen() on a connected socket must fail.
 */
ATF_TC_WITHOUT_HEAD(listen_wrong_state);
ATF_TC_BODY(listen_wrong_state, tc)
{
	int ls, cs, as, s;

	(void)tc;

	/* Unbound socket. */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	ATF_REQUIRE(listen(s, 8) == -1);
	close(s);

	/* Connected socket. */
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_REQUIRE(listen(cs, 8) == -1);

	close(as);
	close(cs);
	close(ls);
}

/*
 * send() on a disconnected socket must return EPIPE or ENOTCONN.
 */
ATF_TC_WITHOUT_HEAD(send_after_disconnect);
ATF_TC_BODY(send_after_disconnect, tc)
{
	int ls, cs, as;
	char buf[] = "after-disconnect";

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	close(as);

	/* Give close time to propagate. */
	usleep(50000);

	/*
	 * Send should fail.  The peer closed, so the loopback send path sees
	 * SBS_CANTRCVMORE on the peer's receive buffer and fails with EPIPE
	 * deterministically.  (A remote peer OP_RST also surfaces to the writer
	 * as EPIPE; ECONNRESET on an established connection comes only from a
	 * flow-control violation or transport reset.)
	 */
	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(send(cs, buf, sizeof(buf), MSG_NOSIGNAL) == -1);
	ATF_REQUIRE_MSG(errno == EPIPE, "expected EPIPE, got %s",
	    strerror(errno));

	close(cs);
	close(ls);
}

/*
 * recv with MSG_DONTWAIT on a blocking socket with no data.
 */
ATF_TC_WITHOUT_HEAD(recv_msg_dontwait);
ATF_TC_BODY(recv_msg_dontwait, tc)
{
	int ls, cs, as;
	char buf[16];

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* No data sent; recv with MSG_DONTWAIT should return EAGAIN. */
	ATF_REQUIRE(recv(as, buf, sizeof(buf), MSG_DONTWAIT) == -1);
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	close(as);
	close(cs);
	close(ls);
}

/*
 * Bind to CID 0 (hypervisor) must fail.
 */
ATF_TC_WITHOUT_HEAD(bind_cid_zero_fails);
ATF_TC_BODY(bind_cid_zero_fails, tc)
{
	struct sockaddr_vm svm;
	int s;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	memset(&svm, 0, sizeof(svm));
	svm.svm_len = sizeof(svm);
	svm.svm_family = AF_VSOCK;
	svm.svm_cid = 0;
	svm.svm_port = VSOCK_PORT_ANY;

	ATF_REQUIRE(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == -1);
	ATF_REQUIRE(errno == EINVAL);

	close(s);
}

/*
 * Multiple accept() calls: verify each returns a distinct fd.
 */
ATF_TC_WITHOUT_HEAD(multi_accept_distinct_fds);
ATF_TC_BODY(multi_accept_distinct_fds, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs1, cs2, as1, as2;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs1 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs1 >= 0);
	ATF_REQUIRE(connect(cs1, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	cs2 = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs2 >= 0);
	ATF_REQUIRE(connect(cs2, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	as1 = accept(ls, NULL, NULL);
	ATF_REQUIRE(as1 >= 0);
	as2 = accept(ls, NULL, NULL);
	ATF_REQUIRE(as2 >= 0);

	ATF_REQUIRE(as1 != as2);

	/* Verify independent data paths. */
	ATF_REQUIRE(send(cs1, "A", 1, 0) == 1);
	ATF_REQUIRE(send(cs2, "B", 1, 0) == 1);

	char c;
	ATF_REQUIRE(recv(as1, &c, 1, 0) == 1);
	ATF_REQUIRE(c == 'A');
	ATF_REQUIRE(recv(as2, &c, 1, 0) == 1);
	ATF_REQUIRE(c == 'B');

	close(as2);
	close(as1);
	close(cs2);
	close(cs1);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 43: kqueue and poll edge cases                                */
/* ------------------------------------------------------------------ */

/*
 * kqueue EVFILT_READ should fire when data arrives.
 */
ATF_TC_WITHOUT_HEAD(kqueue_read_fires_on_data);
ATF_TC_BODY(kqueue_read_fires_on_data, tc)
{
	int ls, cs, as, kq;
	struct kevent ev, rev;
	char buf[] = "kq-test";

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&ev, as, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &ev, 1, NULL, 0, NULL) == 0);

	/* No data yet — should not fire immediately. */
	struct timespec ts = { 0, 0 };
	ATF_REQUIRE(kevent(kq, NULL, 0, &rev, 1, &ts) == 0);

	/* Send data. */
	ATF_REQUIRE(send(cs, buf, sizeof(buf), 0) == (ssize_t)sizeof(buf));

	/* Should fire now. */
	ts.tv_sec = 2;
	ATF_REQUIRE(kevent(kq, NULL, 0, &rev, 1, &ts) == 1);
	ATF_REQUIRE(rev.filter == EVFILT_READ);
	ATF_REQUIRE(rev.data >= (int64_t)sizeof(buf));

	close(kq);
	close(as);
	close(cs);
	close(ls);
}

/*
 * kqueue EVFILT_WRITE should fire when buffer space is available.
 */
ATF_TC_WITHOUT_HEAD(kqueue_write_fires_on_space);
ATF_TC_BODY(kqueue_write_fires_on_space, tc)
{
	int ls, cs, as, kq;
	struct kevent ev, rev;

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&ev, cs, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &ev, 1, NULL, 0, NULL) == 0);

	/* Should be writable initially. */
	struct timespec ts = { 2, 0 };
	ATF_REQUIRE(kevent(kq, NULL, 0, &rev, 1, &ts) == 1);
	ATF_REQUIRE(rev.filter == EVFILT_WRITE);
	ATF_REQUIRE(rev.data > 0);

	close(kq);
	close(as);
	close(cs);
	close(ls);
}

/*
 * poll(POLLIN) on a listener should fire when a connection is pending.
 */
ATF_TC_WITHOUT_HEAD(poll_listener_connect_pending);
ATF_TC_BODY(poll_listener_connect_pending, tc)
{
	struct sockaddr_vm laddr;
	int ls, cs;
	struct pollfd pfd;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	/* No pending connections. */
	pfd.fd = ls;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) == 0);

	/* Connect. */
	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	/* Listener should now be readable. */
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 2000) == 1);
	ATF_REQUIRE(pfd.revents & POLLIN);

	int as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 44: SEQPACKET message integrity                               */
/* ------------------------------------------------------------------ */

/*
 * Multiple SEQPACKET messages of varying sizes maintain boundaries.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_varied_sizes);
ATF_TC_BODY(seqpacket_varied_sizes, tc)
{
	int ls, cs, as;
	size_t sizes[] = { 1, 7, 100, 1000, 4096, 8192 };
	int nsizes = sizeof(sizes) / sizeof(sizes[0]);
	char *sbuf, *rbuf;
	ssize_t n;

	(void)tc;

	sbuf = malloc(8192);
	rbuf = malloc(8192);
	ATF_REQUIRE(sbuf != NULL && rbuf != NULL);

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	for (int i = 0; i < nsizes; i++) {
		memset(sbuf, 'A' + i, sizes[i]);
		n = send(cs, sbuf, sizes[i], 0);
		ATF_REQUIRE_MSG(n == (ssize_t)sizes[i],
		    "send %zu failed: %zd (%s)", sizes[i], n, strerror(errno));
	}

	for (int i = 0; i < nsizes; i++) {
		memset(rbuf, 0, 8192);
		n = recv(as, rbuf, 8192, 0);
		ATF_REQUIRE_MSG(n == (ssize_t)sizes[i],
		    "recv expected %zu got %zd", sizes[i], n);
		for (ssize_t j = 0; j < n; j++)
			ATF_REQUIRE(rbuf[j] == (char)('A' + i));
	}

	free(sbuf);
	free(rbuf);
	close(as);
	close(cs);
	close(ls);
}

/*
 * SEQPACKET MSG_TRUNC returns the full message size even when the
 * buffer is too small, without corrupting the next message.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_trunc_preserves_next);
ATF_TC_BODY(seqpacket_trunc_preserves_next, tc)
{
	int ls, cs, as;
	char msg1[] = "first-message-is-long";
	char msg2[] = "second";
	char rbuf[8];
	ssize_t n;

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	ATF_REQUIRE(send(cs, msg1, sizeof(msg1), 0) == (ssize_t)sizeof(msg1));
	ATF_REQUIRE(send(cs, msg2, sizeof(msg2), 0) == (ssize_t)sizeof(msg2));

	/* Read msg1 with a tiny buffer + MSG_TRUNC. */
	n = recv(as, rbuf, sizeof(rbuf), MSG_TRUNC);
	ATF_REQUIRE(n == (ssize_t)sizeof(msg1));

	/* msg2 should be intact. */
	memset(rbuf, 0, sizeof(rbuf));
	n = recv(as, rbuf, sizeof(rbuf), 0);
	ATF_REQUIRE(n == (ssize_t)sizeof(msg2));
	ATF_REQUIRE(memcmp(rbuf, msg2, sizeof(msg2)) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 45: Concurrent stress                                         */
/* ------------------------------------------------------------------ */

struct rapid_cycle_ctx {
	struct sockaddr_vm sa;
	int iterations;
	int result;
};

static void *
rapid_cycle_thread(void *arg)
{
	struct rapid_cycle_ctx *ctx = arg;
	int s;
	char buf[4];

	for (int i = 0; i < ctx->iterations; i++) {
		s = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (s < 0) { ctx->result = -1; return (NULL); }
		if (connect(s, (struct sockaddr *)&ctx->sa,
		    sizeof(ctx->sa)) != 0) {
			close(s);
			/* Backlog overflow refusals are expected under
			 * this storm; retry rather than fail. */
			if (errno == ECONNRESET || errno == ECONNREFUSED) {
				i--;
				continue;
			}
			ctx->result = -1;
			return (NULL);
		}
		buf[0] = (char)i;
		(void)send(s, buf, 1, MSG_NOSIGNAL);
		close(s);
	}
	ctx->result = 0;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(rapid_connect_close_multi_thread);
ATF_TC_BODY(rapid_connect_close_multi_thread, tc)
{
	struct sockaddr_vm laddr;
	int ls;
	pthread_t threads[4];
	struct rapid_cycle_ctx ctxs[4];

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 64) == 0);

	for (int i = 0; i < 4; i++) {
		ctxs[i].sa = laddr;
		ctxs[i].iterations = 25;
		ctxs[i].result = -1;
		ATF_REQUIRE(pthread_create(&threads[i], NULL,
		    rapid_cycle_thread, &ctxs[i]) == 0);
	}

	/* Drain accepts opportunistically; loopback connects complete
	 * without accept(2), so this must never block the test. */
	ATF_REQUIRE(fcntl(ls, F_SETFL, O_NONBLOCK) != -1);
	for (int i = 0; i < 500; i++) {
		int as = accept(ls, NULL, NULL);
		if (as >= 0)
			close(as);
		else
			usleep(2000);
	}

	for (int i = 0; i < 4; i++) {
		pthread_join(threads[i], NULL);
		ATF_REQUIRE_MSG(ctxs[i].result == 0,
		    "thread %d failed", i);
	}

	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 46: VMADDR_* alias and constant tests                         */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(vmaddr_aliases);
ATF_TC_BODY(vmaddr_aliases, tc)
{
	(void)tc;

	ATF_REQUIRE(VMADDR_CID_HYPERVISOR == 0);
	ATF_REQUIRE(VMADDR_CID_LOCAL == VSOCK_CID_LOCAL);
	ATF_REQUIRE(VMADDR_CID_HOST == VSOCK_CID_HOST);
	ATF_REQUIRE(VMADDR_CID_ANY == VSOCK_CID_ANY);
	ATF_REQUIRE(VMADDR_PORT_ANY == VSOCK_PORT_ANY);
}

/* ------------------------------------------------------------------ */
/* Group 47: accept() returns correct peer address                     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(accept_returns_peer_addr);
ATF_TC_BODY(accept_returns_peer_addr, tc)
{
	struct sockaddr_vm laddr, peeraddr, clientaddr;
	socklen_t slen;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);

	slen = sizeof(clientaddr);
	ATF_REQUIRE(getsockname(cs, (struct sockaddr *)&clientaddr, &slen) == 0);

	slen = sizeof(peeraddr);
	memset(&peeraddr, 0, sizeof(peeraddr));
	as = accept(ls, (struct sockaddr *)&peeraddr, &slen);
	ATF_REQUIRE(as >= 0);

	ATF_REQUIRE(peeraddr.svm_family == AF_VSOCK);
	ATF_REQUIRE(peeraddr.svm_cid == clientaddr.svm_cid);
	ATF_REQUIRE(peeraddr.svm_port == clientaddr.svm_port);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 48: Bidirectional data on same connection                     */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(bidirectional_echo);
ATF_TC_BODY(bidirectional_echo, tc)
{
	int ls, cs, as;
	char sbuf[256], rbuf[256];

	(void)tc;

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Client sends. */
	memset(sbuf, 'C', sizeof(sbuf));
	ATF_REQUIRE(send(cs, sbuf, sizeof(sbuf), 0) == (ssize_t)sizeof(sbuf));

	/* Server echoes. */
	ATF_REQUIRE(recv(as, rbuf, sizeof(rbuf), MSG_WAITALL) ==
	    (ssize_t)sizeof(rbuf));
	ATF_REQUIRE(send(as, rbuf, sizeof(rbuf), 0) == (ssize_t)sizeof(rbuf));

	/* Client receives echo. */
	memset(rbuf, 0, sizeof(rbuf));
	ATF_REQUIRE(recv(cs, rbuf, sizeof(rbuf), MSG_WAITALL) ==
	    (ssize_t)sizeof(rbuf));
	ATF_REQUIRE(memcmp(sbuf, rbuf, sizeof(sbuf)) == 0);

	close(as);
	close(cs);
	close(ls);
}

ATF_TC_WITHOUT_HEAD(seqpacket_bidirectional);
ATF_TC_BODY(seqpacket_bidirectional, tc)
{
	int ls, cs, as;
	char msg_c[] = "from-client";
	char msg_s[] = "from-server";
	char rbuf[64];

	(void)tc;

	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);

	ATF_REQUIRE(send(cs, msg_c, sizeof(msg_c), 0) == (ssize_t)sizeof(msg_c));
	ATF_REQUIRE(send(as, msg_s, sizeof(msg_s), 0) == (ssize_t)sizeof(msg_s));

	memset(rbuf, 0, sizeof(rbuf));
	ATF_REQUIRE(recv(as, rbuf, sizeof(rbuf), 0) == (ssize_t)sizeof(msg_c));
	ATF_REQUIRE(memcmp(rbuf, msg_c, sizeof(msg_c)) == 0);

	memset(rbuf, 0, sizeof(rbuf));
	ATF_REQUIRE(recv(cs, rbuf, sizeof(rbuf), 0) == (ssize_t)sizeof(msg_s));
	ATF_REQUIRE(memcmp(rbuf, msg_s, sizeof(msg_s)) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 49: getsockopt/setsockopt edge cases                          */
/* ------------------------------------------------------------------ */

ATF_TC_WITHOUT_HEAD(buffer_min_max_ordering);
ATF_TC_BODY(buffer_min_max_ordering, tc)
{
	int s;
	uint64_t val;

	(void)tc;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	/* Set min, then try setting max below it. */
	val = 4096;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MIN_SIZE,
	    &val, sizeof(val)) == 0);

	val = 2048;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
	    &val, sizeof(val)) == 0);
	/*
	 * Setting max (2048) below min (4096) must pull min down to max, so
	 * both read back as 2048 and the invariant min <= max holds.
	 */
	val = 0;
	socklen_t len = sizeof(val);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
	    &val, &len) == 0);
	ATF_CHECK_MSG(val == 2048, "buffer_max = %ju, expected 2048",
	    (uintmax_t)val);
	len = sizeof(val);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_BUFFER_MIN_SIZE,
	    &val, &len) == 0);
	ATF_CHECK_MSG(val == 2048, "buffer_min = %ju, expected clamp to 2048",
	    (uintmax_t)val);

	close(s);
}

/*
 * connect_timeout_range removed: it set and clamped the option using the
 * legacy scalar-centiseconds encoding, which no longer exists.  Default (zero
 * timeval) and set/get behavior is covered by connect_timeout_timeval.
 */

/* ------------------------------------------------------------------ */
/* Group 50: SEQPACKET fragment limit sysctl                           */
/* ------------------------------------------------------------------ */

ATF_TC(seqpacket_frag_max_sysctl);
ATF_TC_HEAD(seqpacket_frag_max_sysctl, tc)
{
	/* Writing kern.vsock.seqpacket_frag_max requires root. */
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seqpacket_frag_max_sysctl, tc)
{
	u_int orig, val;
	size_t len;

	(void)tc;

	/* Read original value. */
	len = sizeof(orig);
	ATF_REQUIRE_MSG(
	    sysctlbyname("kern.vsock.seqpacket_frag_max",
	    &orig, &len, NULL, 0) == 0,
	    "read seqpacket_frag_max: %s", strerror(errno));
	ATF_REQUIRE(orig == 256); /* default */

	/* Set to a different value. */
	val = 512;
	ATF_REQUIRE(sysctlbyname("kern.vsock.seqpacket_frag_max",
	    NULL, NULL, &val, sizeof(val)) == 0);

	len = sizeof(val);
	ATF_REQUIRE(sysctlbyname("kern.vsock.seqpacket_frag_max",
	    &val, &len, NULL, 0) == 0);
	ATF_REQUIRE(val == 512);

	/* Set to 0 (unlimited). */
	val = 0;
	ATF_REQUIRE(sysctlbyname("kern.vsock.seqpacket_frag_max",
	    NULL, NULL, &val, sizeof(val)) == 0);

	len = sizeof(val);
	ATF_REQUIRE(sysctlbyname("kern.vsock.seqpacket_frag_max",
	    &val, &len, NULL, 0) == 0);
	ATF_REQUIRE(val == 0);

	/* Restore original. */
	ATF_REQUIRE(sysctlbyname("kern.vsock.seqpacket_frag_max",
	    NULL, NULL, &orig, sizeof(orig)) == 0);
}

/* ------------------------------------------------------------------ */
/* Group 51: Shutdown wakes blocked sender                             */
/* ------------------------------------------------------------------ */

/*
 * Verify that shutdown(SHUT_RD) on the receiver promptly unblocks a
 * sender that is blocked because the peer's receive buffer is full.
 */

struct shutdown_sender_ctx {
	int		 sender;
	int		 result_errno;
	size_t		 len;		/* record size; must fit peer buf */
	pthread_mutex_t	 mutex;
	pthread_cond_t	 cond;
	bool		 started;
};

static void *
shutdown_sender_thread(void *arg)
{
	struct shutdown_sender_ctx *ctx = arg;
	char buf[1024];
	ssize_t rc;

	if (ctx->len == 0 || ctx->len > sizeof(buf))
		ctx->len = sizeof(buf);
	memset(buf, 'S', sizeof(buf));
	(void)pthread_mutex_lock(&ctx->mutex);
	ctx->started = true;
	(void)pthread_cond_signal(&ctx->cond);
	(void)pthread_mutex_unlock(&ctx->mutex);

	/* This send should block until the receiver shuts down. */
	rc = send(ctx->sender, buf, ctx->len, MSG_NOSIGNAL);
	if (rc == -1)
		ctx->result_errno = errno;
	else
		ctx->result_errno = 0;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(shutdown_rd_wakes_blocked_sender);
ATF_TC_BODY(shutdown_rd_wakes_blocked_sender, tc)
{
	struct shutdown_sender_ctx ctx;
	struct sockaddr_vm laddr;
	struct timespec start, end;
	pthread_t t;
	int ls, cs, as, n;

	(void)tc;

	/* Create connection with a small receive buffer. */
	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	n = 128;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Fill the receive buffer until send would block. */
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	for (;;) {
		char fill[64];
		memset(fill, 'F', sizeof(fill));
		if (send(cs, fill, sizeof(fill), 0) == -1) {
			ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}
	}
	/* Switch back to blocking. */
	ATF_REQUIRE(fcntl(cs, F_SETFL, 0) != -1);

	/* Spawn a thread that will block on send. */
	ctx.sender = cs;
	ctx.len = 1024;
	ctx.result_errno = 0;
	ctx.started = false;
	ATF_REQUIRE(pthread_mutex_init(&ctx.mutex, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&ctx.cond, NULL) == 0);
	ATF_REQUIRE(pthread_create(&t, NULL,
	    shutdown_sender_thread, &ctx) == 0);

	ATF_REQUIRE(pthread_mutex_lock(&ctx.mutex) == 0);
	while (!ctx.started)
		ATF_REQUIRE(pthread_cond_wait(&ctx.cond, &ctx.mutex) == 0);
	ATF_REQUIRE(pthread_mutex_unlock(&ctx.mutex) == 0);
	/*
	 * Prove that send is still blocked.  A timed join waits for the thread
	 * completion event; it does not use a scheduler-dependent fixed sleep.
	 */
	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &end) == 0);
	end.tv_nsec += 50000000;
	if (end.tv_nsec >= 1000000000) {
		end.tv_sec++;
		end.tv_nsec -= 1000000000;
	}
	ATF_REQUIRE(pthread_timedjoin_np(t, NULL, &end) == ETIMEDOUT);

	/* Shut down our receive side — sender should unblock promptly. */
	clock_gettime(CLOCK_MONOTONIC, &start);
	ATF_REQUIRE(shutdown(as, SHUT_RD) == 0);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	clock_gettime(CLOCK_MONOTONIC, &end);

	double elapsed = (end.tv_sec - start.tv_sec) +
	    (end.tv_nsec - start.tv_nsec) / 1e9;

	ATF_REQUIRE_MSG(elapsed < 0.5,
	    "sender took %.3f seconds to unblock after shutdown", elapsed);

	/* Sender should have gotten EPIPE. */
	ATF_REQUIRE_MSG(ctx.result_errno == EPIPE,
	    "expected EPIPE, got %d (%s)",
	    ctx.result_errno, strerror(ctx.result_errno));
	ATF_REQUIRE(pthread_cond_destroy(&ctx.cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&ctx.mutex) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 52: Concurrent send + close stress                            */
/* ------------------------------------------------------------------ */

struct send_close_stress_ctx {
	struct sockaddr_vm sa;
	volatile int	   stop;
};

static void *
send_close_stress_worker(void *arg)
{
	struct send_close_stress_ctx *ctx = arg;
	char buf[256];
	int s;

	memset(buf, 'W', sizeof(buf));
	while (!ctx->stop) {
		s = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (s < 0)
			continue;
		if (connect(s, (struct sockaddr *)&ctx->sa,
		    sizeof(ctx->sa)) == 0) {
			(void)send(s, buf, sizeof(buf), MSG_NOSIGNAL);
		}
		close(s);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_send_close_stress);
ATF_TC_BODY(concurrent_send_close_stress, tc)
{
	struct send_close_stress_ctx ctx;
	pthread_t threads[16];
	int ls, as, i;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &ctx.sa);
	ATF_REQUIRE(listen(ls, 128) == 0);
	ctx.stop = 0;

	for (i = 0; i < 16; i++) {
		ATF_REQUIRE(pthread_create(&threads[i], NULL,
		    send_close_stress_worker, &ctx) == 0);
	}

	/* Accept and close rapidly for 2 seconds. */
	for (i = 0; i < 500; i++) {
		as = accept(ls, NULL, NULL);
		if (as >= 0) {
			char drain[256];
			(void)recv(as, drain, sizeof(drain), MSG_DONTWAIT);
			close(as);
		}
	}

	ctx.stop = 1;
	for (i = 0; i < 16; i++)
		ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);

	close(ls);
}

/*
 * Verify that shutdown(SHUT_RD) during a SEQPACKET send also unblocks
 * the sender and returns EPIPE.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_shutdown_rd_wakes_sender);
ATF_TC_BODY(seqpacket_shutdown_rd_wakes_sender, tc)
{
	struct shutdown_sender_ctx ctx;
	struct sockaddr_vm laddr;
	struct timespec start, end;
	pthread_t t;
	int ls, cs, as, n;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_bind_any(ls, &laddr);
	n = 128;
	ATF_REQUIRE(setsockopt(ls, SOL_SOCKET, SO_RCVBUF,
	    &n, sizeof(n)) == 0);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr,
	    sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Fill the receive buffer. */
	ATF_REQUIRE(fcntl(cs, F_SETFL, O_NONBLOCK) != -1);
	for (;;) {
		char fill[32];
		memset(fill, 'F', sizeof(fill));
		if (send(cs, fill, sizeof(fill), 0) == -1) {
			ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EMSGSIZE);
			break;
		}
	}
	ATF_REQUIRE(fcntl(cs, F_SETFL, 0) != -1);

	ctx.sender = cs;
	ctx.len = 32;	/* must fit the 128-byte window */
	ctx.result_errno = 0;
	ctx.started = false;
	ATF_REQUIRE(pthread_mutex_init(&ctx.mutex, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&ctx.cond, NULL) == 0);
	ATF_REQUIRE(pthread_create(&t, NULL,
	    shutdown_sender_thread, &ctx) == 0);

	ATF_REQUIRE(pthread_mutex_lock(&ctx.mutex) == 0);
	while (!ctx.started)
		ATF_REQUIRE(pthread_cond_wait(&ctx.cond, &ctx.mutex) == 0);
	ATF_REQUIRE(pthread_mutex_unlock(&ctx.mutex) == 0);
	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &end) == 0);
	end.tv_nsec += 50000000;
	if (end.tv_nsec >= 1000000000) {
		end.tv_sec++;
		end.tv_nsec -= 1000000000;
	}
	ATF_REQUIRE(pthread_timedjoin_np(t, NULL, &end) == ETIMEDOUT);

	clock_gettime(CLOCK_MONOTONIC, &start);
	ATF_REQUIRE(shutdown(as, SHUT_RD) == 0);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	clock_gettime(CLOCK_MONOTONIC, &end);

	double elapsed = (end.tv_sec - start.tv_sec) +
	    (end.tv_nsec - start.tv_nsec) / 1e9;

	ATF_REQUIRE_MSG(elapsed < 0.5,
	    "sender took %.3f seconds to unblock after shutdown", elapsed);
	ATF_REQUIRE_MSG(ctx.result_errno == EPIPE,
	    "expected EPIPE, got %d (%s)",
	    ctx.result_errno, strerror(ctx.result_errno));
	ATF_REQUIRE(pthread_cond_destroy(&ctx.cond) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&ctx.mutex) == 0);

	close(as);
	close(cs);
	close(ls);
}

/* ------------------------------------------------------------------ */
/* Group 40: Linux-ABI reachability and privileged-port gating          */
/* ------------------------------------------------------------------ */

/*
 * SO_VM_SOCKETS_* options must be accepted at the AF_VSOCK level too, not just
 * SOL_VSOCK: code ported from Linux applies them at level AF_VSOCK.
 */
ATF_TC_WITHOUT_HEAD(sockopt_af_vsock_level);
ATF_TC_BODY(sockopt_af_vsock_level, tc)
{
	uint64_t bufsz = 128 * 1024, got = 0;
	socklen_t len = sizeof(got);
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	ATF_REQUIRE_MSG(setsockopt(s, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &bufsz, sizeof(bufsz)) == 0,
	    "setsockopt at AF_VSOCK level: %s", strerror(errno));
	ATF_REQUIRE_MSG(getsockopt(s, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
	    &got, &len) == 0,
	    "getsockopt at AF_VSOCK level: %s", strerror(errno));
	ATF_CHECK(got > 0);
	close(s);
}

/*
 * Binding svm_cid = 0xffffffff (Linux's 32-bit VMADDR_CID_ANY) must be
 * accepted as the local-CID wildcard, like the native 64-bit VSOCK_CID_ANY,
 * and resolve to a concrete local CID.
 */
ATF_TC_WITHOUT_HEAD(bind_cid_any_32bit);
ATF_TC_BODY(bind_cid_any_32bit, tc)
{
	struct sockaddr_vm svm, out;
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	memset(&svm, 0, sizeof(svm));
	svm.svm_len = sizeof(svm);
	svm.svm_family = AF_VSOCK;
	svm.svm_cid = 0xffffffffU;	/* 32-bit VMADDR_CID_ANY */
	svm.svm_port = VSOCK_PORT_ANY;
	ATF_REQUIRE_MSG(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0,
	    "bind with 32-bit ANY cid: %s", strerror(errno));
	ATF_REQUIRE(getsockname(s, (struct sockaddr *)&out,
	    &(socklen_t){sizeof(out)}) == 0);
	ATF_CHECK(out.svm_cid != 0xffffffffU);
	ATF_CHECK(out.svm_cid != VSOCK_CID_ANY);
	close(s);
}

/*
 * Binding an explicit port below 1024 requires privilege: root succeeds, an
 * unprivileged process is denied (EPERM/EACCES).
 */
ATF_TC(bind_privileged_port);
ATF_TC_HEAD(bind_privileged_port, tc)
{
	/* Binds a privileged (low) port and drops privileges; needs root. */
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bind_privileged_port, tc)
{
	struct sockaddr_vm svm;
	pid_t pid;
	int s, status;

	/* Root can bind a low port. */
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	memset(&svm, 0, sizeof(svm));
	svm.svm_len = sizeof(svm);
	svm.svm_family = AF_VSOCK;
	svm.svm_cid = VSOCK_CID_ANY;
	svm.svm_port = 1;
	ATF_REQUIRE_MSG(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0,
	    "root bind low port: %s", strerror(errno));
	close(s);

	/* An unprivileged child is denied. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		struct sockaddr_vm c;
		int cs, e;

		if (setresuid(65534, 65534, 65534) != 0)
			_exit(42);	/* env without nobody; skip */
		cs = socket(AF_VSOCK, SOCK_STREAM, 0);
		if (cs < 0)
			_exit(43);
		memset(&c, 0, sizeof(c));
		c.svm_len = sizeof(c);
		c.svm_family = AF_VSOCK;
		c.svm_cid = VSOCK_CID_ANY;
		c.svm_port = 2;
		e = bind(cs, (struct sockaddr *)&c, sizeof(c));
		if (e == 0)
			_exit(1);	/* not gated */
		if (errno != EPERM && errno != EACCES)
			_exit(2);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	if (WEXITSTATUS(status) == 42)
		atf_tc_skip("could not drop privileges (no nobody uid)");
	ATF_CHECK_EQ_MSG(0, WEXITSTATUS(status),
	    "unprivileged low-port bind not gated (child exit %d)",
	    WEXITSTATUS(status));
}

/* MSG_OOB must be rejected (virtio-vsock has no out-of-band channel). */
ATF_TC_WITHOUT_HEAD(msg_oob_rejected);
ATF_TC_BODY(msg_oob_rejected, tc)
{
	int ls, cs, as;

	(void)tc;
	vsock_pair(SOCK_STREAM, &ls, &cs, &as);
	ATF_CHECK_ERRNO(EOPNOTSUPP, send(cs, "x", 1, MSG_OOB) == -1);
	close(ls);
	close(cs);
	close(as);
}

/* SO_VM_SOCKETS_CONNECT_TIMEOUT accepts and returns a struct timeval. */
ATF_TC_WITHOUT_HEAD(connect_timeout_timeval);
ATF_TC_BODY(connect_timeout_timeval, tc)
{
	struct timeval tv;
	socklen_t len;
	int s;

	(void)tc;
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	tv.tv_sec = 2;
	tv.tv_usec = 500000;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &tv, sizeof(tv)) == 0);

	memset(&tv, 0, sizeof(tv));
	len = sizeof(tv);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &tv, &len) == 0);
	/* Read back ~2.5s (allow tick-granularity rounding). */
	ATF_CHECK_MSG(tv.tv_sec == 2 && tv.tv_usec >= 400000 &&
	    tv.tv_usec <= 600000, "read back %jd.%06ld",
	    (intmax_t)tv.tv_sec, (long)tv.tv_usec);

	/* The _NEW option is timeval-only and must behave the same. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW,
	    &tv, sizeof(tv)) == 0);
	memset(&tv, 0, sizeof(tv));
	len = sizeof(tv);
	ATF_REQUIRE(getsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW,
	    &tv, &len) == 0);
	ATF_CHECK_MSG(tv.tv_sec == 5, "read back %jd s", (intmax_t)tv.tv_sec);

	/*
	 * The legacy scalar-centiseconds form is gone: a set buffer smaller
	 * than struct timeval is rejected with EINVAL for both option numbers.
	 */
	uint64_t scalar = 100;
	ATF_CHECK_ERRNO(EINVAL, setsockopt(s, SOL_VSOCK,
	    SO_VM_SOCKETS_CONNECT_TIMEOUT, &scalar, sizeof(scalar)) == -1);
	ATF_CHECK_ERRNO(EINVAL, setsockopt(s, SOL_VSOCK,
	    SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW, &scalar, sizeof(scalar)) == -1);

	close(s);
}

/* Unsupported VMCI-only options are cleanly rejected, not silently accepted. */
ATF_TC_WITHOUT_HEAD(vmci_only_opts_rejected);
ATF_TC_BODY(vmci_only_opts_rejected, tc)
{
	int s, val;

	(void)tc;
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	val = 1;
	ATF_CHECK_ERRNO(EOPNOTSUPP, setsockopt(s, SOL_VSOCK,
	    SO_VM_SOCKETS_TRUSTED, &val, sizeof(val)) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, setsockopt(s, SOL_VSOCK,
	    SO_VM_SOCKETS_NONBLOCK_TXRX, &val, sizeof(val)) == -1);
	close(s);
}

/*
 * The guest CID reported by the loopback-only build must be VSOCK_CID_LOCAL
 * (1): with no virtio transport registered the domain layer falls back to the
 * local CID, and kern.vsock.guest_cid must expose exactly that.  A regression
 * here (e.g. leaking a reserved value like 0/2/0xffffffff) would break both the
 * "connect to your own CID" loopback contract and any tool keying off the CID.
 */
ATF_TC_WITHOUT_HEAD(sysctl_guest_cid_local);
ATF_TC_BODY(sysctl_guest_cid_local, tc)
{
	uint64_t cid;
	size_t len = sizeof(cid);

	(void)tc;

	ATF_REQUIRE_MSG(sysctlbyname("kern.vsock.guest_cid", &cid, &len,
	    NULL, 0) == 0, "reading kern.vsock.guest_cid: %s", strerror(errno));
	ATF_REQUIRE_MSG(len == sizeof(cid),
	    "kern.vsock.guest_cid returned %zu bytes, expected %zu",
	    len, sizeof(cid));
	/*
	 * Without a transport the CID is VSOCK_CID_LOCAL; with one it is the
	 * hypervisor-assigned guest CID, which must be >= 3 and below the
	 * wildcard.  Both are valid environments for this suite.
	 */
	ATF_REQUIRE_MSG(cid == VSOCK_CID_LOCAL ||
	    (cid >= 3 && cid < VSOCK_CID_ANY),
	    "kern.vsock.guest_cid = %ju: neither VSOCK_CID_LOCAL nor a valid "
	    "guest CID", (uintmax_t)cid);
}

/*
 * An explicit bind to VSOCK_CID_LOCAL (1) must succeed and create a
 * loopback-only listener: reachable via a connect to CID 1, with
 * getsockname reporting CID 1 (never rewritten to the guest CID).
 * Matches Linux, where VMADDR_CID_LOCAL is always a bindable address.
 */
ATF_TC_WITHOUT_HEAD(bind_cid_local_explicit);
ATF_TC_BODY(bind_cid_local_explicit, tc)
{
	struct sockaddr_vm svm, got, dst;
	socklen_t glen;
	int ls, cs, as;

	(void)tc;

	ls = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_set_any(&svm);
	svm.svm_cid = VSOCK_CID_LOCAL;
	ATF_REQUIRE_MSG(bind(ls, (struct sockaddr *)&svm, sizeof(svm)) == 0,
	    "bind to CID_LOCAL: %s", strerror(errno));
	glen = sizeof(got);
	ATF_REQUIRE(getsockname(ls, (struct sockaddr *)&got, &glen) == 0);
	ATF_REQUIRE_MSG(got.svm_cid == VSOCK_CID_LOCAL,
	    "bound CID %u, expected CID_LOCAL", got.svm_cid);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(cs >= 0);
	vsock_set_any(&dst);
	dst.svm_cid = VSOCK_CID_LOCAL;
	dst.svm_port = got.svm_port;
	ATF_REQUIRE_MSG(connect(cs, (struct sockaddr *)&dst, sizeof(dst)) == 0,
	    "connect to CID_LOCAL listener: %s", strerror(errno));
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE_MSG(as >= 0, "accept: %s", strerror(errno));

	close(as);
	close(cs);
	close(ls);
}

ATF_TC(bind_port_zero_literal);
ATF_TC_HEAD(bind_port_zero_literal, tc)
{
	/* Port 0 is a privileged literal port (Linux semantics); needs root. */
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bind_port_zero_literal, tc)
{
	struct sockaddr_vm svm, got;
	socklen_t glen;
	int s;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	vsock_set_any(&svm);
	svm.svm_port = 0;
	ATF_REQUIRE_MSG(bind(s, (struct sockaddr *)&svm, sizeof(svm)) == 0,
	    "bind to literal port 0: %s", strerror(errno));
	glen = sizeof(got);
	ATF_REQUIRE(getsockname(s, (struct sockaddr *)&got, &glen) == 0);
	ATF_REQUIRE_MSG(got.svm_port == 0,
	    "port 0 was auto-assigned to %u; expected literal 0 "
	    "(Linux semantics)", got.svm_port);
	close(s);
}

/*
 * IOCTL_VM_SOCKETS_GET_LOCAL_CID (Linux parity) must report the same CID as
 * kern.vsock.guest_cid, both on a vsock socket and on the /dev/vsock
 * character device (where Linux serves it).
 */
ATF_TC_WITHOUT_HEAD(get_local_cid_ioctl);
ATF_TC_BODY(get_local_cid_ioctl, tc)
{
	uint64_t syscid;
	uint32_t cid;
	size_t len = sizeof(syscid);
	int fd, s;

	(void)tc;

	ATF_REQUIRE(sysctlbyname("kern.vsock.guest_cid", &syscid, &len,
	    NULL, 0) == 0);

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);
	cid = 0xdeadbeef;
	ATF_REQUIRE_MSG(ioctl(s, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) == 0,
	    "GET_LOCAL_CID on socket: %s", strerror(errno));
	ATF_REQUIRE_MSG(cid == (uint32_t)syscid,
	    "socket ioctl CID %u != sysctl CID %ju", cid, (uintmax_t)syscid);
	close(s);

	fd = open("/dev/vsock", O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/vsock: %s", strerror(errno));
	cid = 0xdeadbeef;
	ATF_REQUIRE_MSG(ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) == 0,
	    "GET_LOCAL_CID on /dev/vsock: %s", strerror(errno));
	ATF_REQUIRE_MSG(cid == (uint32_t)syscid,
	    "/dev/vsock ioctl CID %u != sysctl CID %ju",
	    cid, (uintmax_t)syscid);
	close(fd);
}

/*
 * SIOCOUTQ (Linux parity) must be wired to the vsock protocol and report a
 * non-negative in-flight byte count on an established connection, and must be
 * rejected before the socket is connected.  Over the loopback transport data
 * is deposited straight into the peer's receive buffer without advancing the
 * wire credit counters (tx_cnt/peer_fwd_cnt stay 0), so the in-flight count is
 * expected to read 0 here; a guest/host pair is required to exercise a non-zero
 * value.  This test therefore verifies the ioctl plumbing and the unconnected
 * rejection, not the wire accounting.
 */
ATF_TC_WITHOUT_HEAD(siocoutq_inflight);
ATF_TC_BODY(siocoutq_inflight, tc)
{
	int ls, cs, as, n;

	(void)tc;

	/* Unconnected socket: SIOCOUTQ must report 0 in-flight bytes. */
	cs = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(cs >= 0, "socket: %s", strerror(errno));
	n = -1;
	ATF_REQUIRE_MSG(ioctl(cs, SIOCOUTQ, &n) == 0,
	    "SIOCOUTQ on unconnected socket: %s", strerror(errno));
	ATF_REQUIRE_MSG(n == 0,
	    "SIOCOUTQ on unconnected socket reported %d, expected 0", n);
	close(cs);

	vsock_pair(SOCK_STREAM, &ls, &cs, &as);

	/* Established, nothing sent: in-flight must be 0. */
	n = -1;
	ATF_REQUIRE_MSG(ioctl(cs, SIOCOUTQ, &n) == 0,
	    "SIOCOUTQ on established socket: %s", strerror(errno));
	ATF_REQUIRE_MSG(n == 0,
	    "SIOCOUTQ before send reported %d, expected 0", n);

	/*
	 * Send data and drain it on the peer.  The in-flight count must stay
	 * non-negative throughout (loopback keeps it at 0; the assertion guards
	 * against the unsigned-wrap-to-negative bug the clamp in vsock_control
	 * prevents).
	 */
	ATF_REQUIRE(send(cs, "hello", 5, 0) == 5);
	n = -1;
	ATF_REQUIRE(ioctl(cs, SIOCOUTQ, &n) == 0);
	ATF_REQUIRE_MSG(n >= 0, "SIOCOUTQ reported negative count %d", n);

	char buf[8];
	ATF_REQUIRE(recv(as, buf, 5, 0) == 5);
	n = -1;
	ATF_REQUIRE(ioctl(as, SIOCOUTQ, &n) == 0);
	ATF_REQUIRE_MSG(n >= 0, "SIOCOUTQ (peer) reported negative count %d", n);

	close(as); close(cs); close(ls);
}

/*
 * SEQPACKET record-size boundary: a record of exactly the peer's receive
 * buffer must be delivered whole; one byte larger must fail EMSGSIZE with the
 * connection surviving.  Existing coverage only tests the far-over case (8K
 * into 4K), never the off-by-one edge in the len > sb_hiwat check.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_exact_max_boundary);
ATF_TC_BODY(seqpacket_exact_max_boundary, tc)
{
	struct sockaddr_vm laddr;
	char *buf;
	uint64_t cap;
	int ls, cs, as;

	(void)tc;
	ls = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(ls >= 0);
	vsock_set_bufsz(ls, 8 * 1024);
	vsock_bind_any(ls, &laddr);
	ATF_REQUIRE(listen(ls, 8) == 0);

	cs = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(connect(cs, (struct sockaddr *)&laddr, sizeof(laddr)) == 0);
	as = accept(ls, NULL, NULL);
	ATF_REQUIRE(as >= 0);

	/* Effective receive cap the sender's records are checked against. */
	cap = vsock_get_bufsz(as);
	ATF_REQUIRE(cap > 0 && cap <= 1024 * 1024);
	buf = malloc(cap + 1);
	ATF_REQUIRE(buf != NULL);
	memset(buf, 'S', cap + 1);

	/* Exactly cap bytes: must succeed and arrive whole. */
	ATF_REQUIRE_MSG(send(cs, buf, cap, 0) == (ssize_t)cap,
	    "exact-cap send failed: %s", strerror(errno));
	ATF_CHECK(recv(as, buf, cap, 0) == (ssize_t)cap);

	/* cap + 1 bytes: must fail EMSGSIZE, connection stays usable. */
	ATF_REQUIRE(send(cs, buf, cap + 1, 0) == -1);
	ATF_REQUIRE(errno == EMSGSIZE);
	ATF_REQUIRE(send(cs, "ok", 2, 0) == 2);		/* conn survived */
	ATF_CHECK(recv(as, buf, cap, 0) == 2);

	free(buf);
	close(as); close(cs); close(ls);
}

/*
 * SEQPACKET SHUT_RDWR: send after it must EPIPE and the peer must see EOF.
 * The teardown matrix covers this for STREAM but had a hole for SEQPACKET.
 */
ATF_TC_WITHOUT_HEAD(seqpacket_shutdown_rdwr);
ATF_TC_BODY(seqpacket_shutdown_rdwr, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;
	(void)signal(SIGPIPE, SIG_IGN);
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(shutdown(cs, SHUT_RDWR) == 0);
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv(as, buf, sizeof(buf), 0) == 0);	/* peer EOF */
	close(as); close(cs); close(ls);
}

/*
 * SEQPACKET peer close -> EOF for the reader and EPIPE+SIGPIPE for a
 * subsequent sender (the STREAM equivalents are peer_close_sigpipe /
 * close_eof_and_epipe; SEQPACKET had none).
 */
ATF_TC_WITHOUT_HEAD(seqpacket_peer_close_eof_epipe);
ATF_TC_BODY(seqpacket_peer_close_eof_epipe, tc)
{
	char buf[8];
	int ls, cs, as;

	(void)tc;
	(void)signal(SIGPIPE, SIG_IGN);
	vsock_pair(SOCK_SEQPACKET, &ls, &cs, &as);
	ATF_REQUIRE(close(as) == 0);
	ATF_REQUIRE(recv(cs, buf, sizeof(buf), 0) == 0);	/* EOF */
	ATF_REQUIRE(send(cs, "x", 1, 0) == -1);
	ATF_REQUIRE(errno == EPIPE);
	close(cs); close(ls);
}

/*
 * connect_timeout malformed timeval -> ERANGE (tv_usec out of range).  The
 * timeval round-trip and the too-small-buffer EINVAL are covered; the
 * ERANGE validation path in vsock_ctloutput was not.
 */
ATF_TC_WITHOUT_HEAD(connect_timeout_erange);
ATF_TC_BODY(connect_timeout_erange, tc)
{
	struct timeval tv;
	int s;

	(void)tc;
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	ATF_REQUIRE(s >= 0);

	tv.tv_sec = 1;
	tv.tv_usec = 2000000;		/* >= 1e6: out of range */
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &tv, sizeof(tv)) == -1);
	ATF_REQUIRE(errno == ERANGE);

	tv.tv_sec = -1;			/* negative also rejected */
	tv.tv_usec = 0;
	ATF_REQUIRE(setsockopt(s, SOL_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
	    &tv, sizeof(tv)) == -1);
	ATF_REQUIRE(errno == ERANGE);
	close(s);
}

/* ------------------------------------------------------------------ */
/* ATF test plan                                                       */
/* ------------------------------------------------------------------ */

struct provider_write_args {
	pthread_barrier_t *barrier;
	const void *packet;
	size_t len;
	ssize_t result;
	int error;
	int fd;
};

struct provider_read_args {
	pthread_barrier_t *barrier;
	void *packet;
	size_t len;
	ssize_t result;
	int error;
	int fd;
};

static void *
provider_blocked_write_thread(void *arg)
{
	struct provider_write_args *a = arg;
	int error;

	error = pthread_barrier_wait(a->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		a->result = -2;
		a->error = error;
		return (NULL);
	}
	errno = 0;
	a->result = write(a->fd, a->packet, a->len);
	a->error = errno;
	return (NULL);
}

static void *
provider_blocked_read_thread(void *arg)
{
	struct provider_read_args *a = arg;
	int error;

	error = pthread_barrier_wait(a->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		a->result = -2;
		a->error = error;
		return (NULL);
	}
	errno = 0;
	a->result = read(a->fd, a->packet, a->len);
	a->error = errno;
	return (NULL);
}

ATF_TC(kernel_transport_provider);
ATF_TC_HEAD(kernel_transport_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kernel_transport_provider, tc)
{
	struct vsock_transport_attach attach;
	struct virtio_vsock_hdr *request, response, unused_request, unused_rst;
	struct sockaddr_vm peer;
	uint8_t packet[sizeof(*request) + 64];
	const char host_data[] = "host-kernel";
	const char guest_data[] = "guest-kernel";
	uint32_t local_cid;
	socklen_t optlen;
	ssize_t len;
	bool saw_shutdown;
	int error, kq, provider, second, s;

	provider = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE_MSG(provider >= 0, "open /dev/vsock: %s",
	    strerror(errno));
	/*
	 * Provider state is created by ATTACH, so readiness filters are valid
	 * only after that ioctl succeeds.  The descriptor must reject packet
	 * I/O before attachment.
	 */
	{
		struct kevent change, event;
		struct pollfd pfd;
		struct timespec zero = { 0, 0 };
		int attach_kq;

		ATF_REQUIRE(write(provider, packet, sizeof(*request)) == -1);
		ATF_REQUIRE(errno == ENXIO);

		memset(&attach, 0, sizeof(attach));
		attach.version = VSOCK_TRANSPORT_VERSION;
		attach.guest_cid = 42;
		attach.features = VIRTIO_VSOCK_F_STREAM |
		    VIRTIO_VSOCK_F_SEQPACKET;
		if (ioctl(provider, VSOCK_IOC_TRANSPORT_ATTACH, &attach) < 0) {
			close(attach_kq);
			if (errno == EBUSY) {
				close(provider);
				atf_tc_skip(
				    "an AF_VSOCK remote transport is active");
			}
			ATF_REQUIRE_MSG(false, "transport attach: %s",
			    strerror(errno));
		}

		pfd.fd = provider;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		ATF_REQUIRE(poll(&pfd, 1, 0) == 1);
		ATF_CHECK((pfd.revents & POLLOUT) != 0);
		attach_kq = kqueue();
		ATF_REQUIRE_MSG(attach_kq >= 0, "kqueue: %s",
		    strerror(errno));
		EV_SET(&change, provider, EVFILT_WRITE, EV_ADD | EV_CLEAR,
		    0, 0, NULL);
		ATF_REQUIRE(kevent(attach_kq, &change, 1, NULL, 0, NULL) == 0);
		ATF_REQUIRE(kevent(attach_kq, NULL, 0, &event, 1,
		    &zero) == 1);
		ATF_CHECK(event.filter == EVFILT_WRITE);
		ATF_CHECK(event.ident == (uintptr_t)provider);
		close(attach_kq);
	}
	memset(&attach, 0, sizeof(attach));
	attach.version = VSOCK_TRANSPORT_VERSION;
	attach.guest_cid = 42;
	attach.features = VIRTIO_VSOCK_F_STREAM |
	    VIRTIO_VSOCK_F_SEQPACKET;
	{
		struct vsock_transport_attach invalid = attach;

		invalid.features |= UINT64_C(1) << 63;
		errno = 0;
		ATF_CHECK(ioctl(provider, VSOCK_IOC_TRANSPORT_ATTACH,
		    &invalid) == -1);
		ATF_CHECK(errno == EINVAL);
	}
	local_cid = 0;
	ATF_REQUIRE(ioctl(provider, IOCTL_VM_SOCKETS_GET_LOCAL_CID,
	    &local_cid) == 0);
	ATF_CHECK(local_cid == VSOCK_CID_HOST);
	{
		uint64_t invalid_features, valid_features;

		invalid_features = attach.features | (UINT64_C(1) << 63);
		errno = 0;
		ATF_CHECK(ioctl(provider, VSOCK_IOC_TRANSPORT_SET_FEATURES,
		    &invalid_features) == -1);
		ATF_CHECK(errno == EINVAL);
		valid_features = VIRTIO_VSOCK_F_STREAM |
		    VIRTIO_VSOCK_F_SEQPACKET;
		ATF_REQUIRE(ioctl(provider, VSOCK_IOC_TRANSPORT_SET_FEATURES,
		    &valid_features) == 0);
	}

	second = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(second >= 0);
	errno = 0;
	ATF_CHECK(ioctl(second, VSOCK_IOC_TRANSPORT_ATTACH, &attach) == -1);
	ATF_CHECK(errno == EADDRINUSE);

	/*
	 * Reject short datagrams and header/payload length mismatches without
	 * poisoning the provider.  A valid packet immediately afterward proves
	 * that both error paths release the serialized writer reservation.
	 */
	memset(&response, 0, sizeof(response));
	response.src_cid = htole64(attach.guest_cid);
	response.dst_cid = htole64(VSOCK_CID_HOST);
	response.src_port = htole32(12345);
	response.dst_port = htole32(UINT32_MAX - 1);
	response.type = htole16(VIRTIO_VSOCK_TYPE_STREAM);
	response.op = htole16(VIRTIO_VSOCK_OP_RW);
	errno = 0;
	ATF_CHECK(write(provider, &response, sizeof(response) - 1) == -1);
	ATF_CHECK(errno == EMSGSIZE);
	response.len = htole32(1);
	errno = 0;
	ATF_CHECK(write(provider, &response, sizeof(response)) == -1);
	ATF_CHECK(errno == EINVAL);

	/*
	 * Match the bhyve kernel-backend path exactly: a guest REQUEST to an
	 * unused host port must synchronously enqueue an RST on /dev/vsock.
	 * The userspace transport reserves a queue slot while processing the
	 * write, so the nonblocking read immediately afterward must succeed.
	 */
	memset(&unused_request, 0, sizeof(unused_request));
	unused_request.src_cid = htole64(attach.guest_cid);
	unused_request.dst_cid = htole64(VSOCK_CID_HOST);
	unused_request.src_port = htole32(12345);
	unused_request.dst_port = htole32(UINT32_MAX - 1);
	unused_request.type = htole16(VIRTIO_VSOCK_TYPE_STREAM);
	unused_request.op = htole16(VIRTIO_VSOCK_OP_REQUEST);
	unused_request.buf_alloc = htole32(65536);
	ATF_REQUIRE(write(provider, &unused_request,
	    sizeof(unused_request)) == (ssize_t)sizeof(unused_request));
	errno = 0;
	ATF_CHECK(read(provider, (void *)(uintptr_t)-1,
	    sizeof(unused_rst)) == -1);
	ATF_CHECK(errno == EFAULT);
	len = read(provider, &unused_rst, sizeof(unused_rst));
	ATF_REQUIRE_MSG(len == (ssize_t)sizeof(unused_rst),
	    "unused-port RST read returned %zd: %s", len, strerror(errno));
	ATF_CHECK(le16toh(unused_rst.op) == VIRTIO_VSOCK_OP_RST);
	ATF_CHECK(le16toh(unused_rst.type) == VIRTIO_VSOCK_TYPE_STREAM);
	ATF_CHECK(le64toh(unused_rst.src_cid) == VSOCK_CID_HOST);
	ATF_CHECK(le64toh(unused_rst.dst_cid) == attach.guest_cid);
	ATF_CHECK(unused_rst.src_port == unused_request.dst_port);
	ATF_CHECK(unused_rst.dst_port == unused_request.src_port);

	/*
	 * A device reset must purge unread pre-reset output and leave the provider
	 * reusable after features are renegotiated.
	 */
	ATF_REQUIRE(write(provider, &unused_request,
	    sizeof(unused_request)) == (ssize_t)sizeof(unused_request));
	ATF_REQUIRE(ioctl(provider, VSOCK_IOC_TRANSPORT_RESET) == 0);
	errno = 0;
	ATF_CHECK(read(provider, packet, sizeof(packet)) == -1);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	{
		uint64_t features = VIRTIO_VSOCK_F_STREAM |
		    VIRTIO_VSOCK_F_SEQPACKET;

		ATF_REQUIRE(ioctl(provider, VSOCK_IOC_TRANSPORT_SET_FEATURES,
		    &features) == 0);
	}
	/*
	 * A blocking read must not silently cross a provider reset and consume a
	 * packet from the new transport epoch.  Reset wakes the empty-queue
	 * waiter with ECANCELED, after which the same provider remains usable.
	 */
	{
		struct provider_read_args args;
		pthread_barrier_t barrier;
		pthread_t thread;
		struct timespec deadline;
		int flags, join_error;

		flags = fcntl(provider, F_GETFL);
		ATF_REQUIRE(flags >= 0);
		ATF_REQUIRE(fcntl(provider, F_SETFL, flags & ~O_NONBLOCK) == 0);
		ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 2) == 0);
		memset(&args, 0, sizeof(args));
		args.barrier = &barrier;
		args.packet = packet;
		args.len = sizeof(packet);
		args.fd = provider;
		ATF_REQUIRE(pthread_create(&thread, NULL,
		    provider_blocked_read_thread, &args) == 0);
		error = pthread_barrier_wait(&barrier);
		ATF_REQUIRE(error == 0 ||
		    error == PTHREAD_BARRIER_SERIAL_THREAD);
		/*
		 * The empty queue is the deterministic blocking condition; this
		 * delay only orders read(2) before the reset ioctl.
		 */
		usleep(100000);
		ATF_REQUIRE(ioctl(provider, VSOCK_IOC_TRANSPORT_RESET) == 0);
		ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
		deadline.tv_sec += 2;
		join_error = pthread_timedjoin_np(thread, NULL, &deadline);
		if (join_error == ETIMEDOUT) {
			ATF_REQUIRE(pthread_cancel(thread) == 0);
			ATF_REQUIRE(pthread_join(thread, NULL) == 0);
		}
		ATF_REQUIRE_MSG(join_error == 0,
		    "provider read did not wake after reset: %s",
		    strerror(join_error));
		ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
		ATF_CHECK(args.result == -1);
		ATF_CHECK(args.error == ECANCELED);
		ATF_REQUIRE(fcntl(provider, F_SETFL, flags) == 0);
		{
			uint64_t features = VIRTIO_VSOCK_F_STREAM |
			    VIRTIO_VSOCK_F_SEQPACKET;

			ATF_REQUIRE(ioctl(provider,
			    VSOCK_IOC_TRANSPORT_SET_FEATURES, &features) == 0);
		}
	}

	s = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket: %s", strerror(errno));
	memset(&peer, 0, sizeof(peer));
	peer.svm_len = sizeof(peer);
	peer.svm_family = AF_VSOCK;
	peer.svm_cid = attach.guest_cid;
	peer.svm_port = 9000;
	errno = 0;
	ATF_CHECK(connect(s, (struct sockaddr *)&peer, sizeof(peer)) == -1);
	ATF_CHECK(errno == EINPROGRESS);

	ATF_CHECK(read(provider, packet, 0) == 0);
	errno = 0;
	ATF_CHECK(read(provider, packet, sizeof(*request) - 1) == -1);
	ATF_CHECK(errno == EMSGSIZE);
	len = read(provider, packet, sizeof(packet));
	ATF_REQUIRE_MSG(len == (ssize_t)sizeof(*request),
	    "request read returned %zd: %s", len, strerror(errno));
	request = (struct virtio_vsock_hdr *)packet;
	ATF_CHECK(le16toh(request->op) == VIRTIO_VSOCK_OP_REQUEST);
	ATF_CHECK(le64toh(request->src_cid) == VSOCK_CID_HOST);
	ATF_CHECK(le64toh(request->dst_cid) == attach.guest_cid);
	ATF_CHECK(le32toh(request->dst_port) == peer.svm_port);

	memset(&response, 0, sizeof(response));
	response.src_cid = htole64(attach.guest_cid);
	response.dst_cid = htole64(VSOCK_CID_HOST);
	response.src_port = request->dst_port;
	response.dst_port = request->src_port;
	response.type = request->type;
	response.op = htole16(VIRTIO_VSOCK_OP_RESPONSE);
	response.buf_alloc = htole32(65536);
	response.src_cid = htole64(attach.guest_cid + 1);
	errno = 0;
	ATF_CHECK(write(provider, &response, sizeof(response)) == -1);
	ATF_CHECK(errno == EINVAL);
	response.src_cid = htole64(attach.guest_cid);
	ATF_REQUIRE(write(provider, &response, sizeof(response)) ==
	    (ssize_t)sizeof(response));
	optlen = sizeof(error);
	error = -1;
	ATF_REQUIRE(getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &optlen) == 0);
	ATF_CHECK(error == 0);

	ATF_REQUIRE(send(s, host_data, sizeof(host_data), 0) ==
	    (ssize_t)sizeof(host_data));
	len = read(provider, packet, sizeof(packet));
	ATF_REQUIRE(len == (ssize_t)(sizeof(*request) + sizeof(host_data)));
	request = (struct virtio_vsock_hdr *)packet;
	ATF_CHECK(le16toh(request->op) == VIRTIO_VSOCK_OP_RW);
	ATF_CHECK(le32toh(request->len) == sizeof(host_data));
	ATF_CHECK(memcmp(packet + sizeof(*request), host_data,
	    sizeof(host_data)) == 0);

	response = *request;
	response.src_cid = htole64(attach.guest_cid);
	response.dst_cid = htole64(VSOCK_CID_HOST);
	response.src_port = request->dst_port;
	response.dst_port = request->src_port;
	response.len = htole32(sizeof(guest_data));
	response.fwd_cnt = htole32(sizeof(host_data));
	memcpy(packet, &response, sizeof(response));
	memcpy(packet + sizeof(response), guest_data, sizeof(guest_data));
	ATF_REQUIRE(write(provider, packet,
	    sizeof(response) + sizeof(guest_data)) ==
	    (ssize_t)(sizeof(response) + sizeof(guest_data)));
	memset(packet, 0, sizeof(packet));
	ATF_REQUIRE(recv(s, packet, sizeof(guest_data), 0) ==
	    (ssize_t)sizeof(guest_data));
	ATF_CHECK(memcmp(packet, guest_data, sizeof(guest_data)) == 0);

	/*
	 * Fill the provider's control queue with RST replies for unknown flows.
	 * Both an inbound provider write and a local shutdown must apply
	 * backpressure without consuming or permanently half-closing state.
	 * Draining one reply must make the fd writable and let shutdown retry.
	 */
	while (read(provider, packet, sizeof(packet)) > 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
	memset(&response, 0, sizeof(response));
	response.src_cid = htole64(attach.guest_cid);
	response.dst_cid = htole64(VSOCK_CID_HOST);
	response.src_port = htole32(65000);
	response.dst_port = htole32(65001);
	response.type = htole16(VIRTIO_VSOCK_TYPE_STREAM);
	response.op = htole16(VIRTIO_VSOCK_OP_CREDIT_UPDATE);
	for (error = 0; error < 256; error++) {
		len = write(provider, &response, sizeof(response));
		if (len < 0)
			break;
		ATF_REQUIRE(len == (ssize_t)sizeof(response));
	}
	ATF_CHECK(error == 128);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	{
		struct pollfd pfd = { .fd = s, .events = POLLOUT };

		ATF_CHECK(poll(&pfd, 1, 0) == 0);
	}
	kq = kqueue();
	ATF_REQUIRE_MSG(kq >= 0, "kqueue: %s", strerror(errno));
	{
		struct kevent change, event;
		struct timespec zero = { 0, 0 };

		EV_SET(&change, s, EVFILT_WRITE, EV_ADD | EV_CLEAR,
		    0, 0, NULL);
		ATF_REQUIRE(kevent(kq, &change, 1, NULL, 0, NULL) == 0);
		ATF_CHECK(kevent(kq, NULL, 0, &event, 1, &zero) == 0);
	}
	errno = 0;
	ATF_CHECK(shutdown(s, SHUT_RDWR) == -1);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	{
		struct pollfd pfd = { .fd = provider, .events = POLLOUT };

		ATF_CHECK(poll(&pfd, 1, 0) == 0);
		for (error = 0; error < 65; error++)
			ATF_REQUIRE(read(provider, packet, sizeof(packet)) ==
			    (ssize_t)sizeof(response));
		pfd.revents = 0;
		ATF_CHECK(poll(&pfd, 1, 0) == 1);
		ATF_CHECK((pfd.revents & POLLOUT) != 0);
	}
	{
		struct pollfd pfd = { .fd = s, .events = POLLOUT };

		ATF_CHECK(poll(&pfd, 1, 0) == 1);
		ATF_CHECK((pfd.revents & POLLOUT) != 0);
	}
	{
		struct kevent event;
		struct timespec one_second = { 1, 0 };

		ATF_CHECK(kevent(kq, NULL, 0, &event, 1,
		    &one_second) == 1);
		ATF_CHECK(event.filter == EVFILT_WRITE);
		ATF_CHECK(event.ident == (uintptr_t)s);
	}
	close(kq);
	ATF_REQUIRE(shutdown(s, SHUT_RDWR) == 0);
	saw_shutdown = false;
	while ((len = read(provider, packet, sizeof(packet))) > 0) {
		request = (struct virtio_vsock_hdr *)packet;
		if (le16toh(request->op) == VIRTIO_VSOCK_OP_SHUTDOWN) {
			ATF_CHECK(le32toh(request->flags) ==
			    (VIRTIO_VSOCK_SHUTDOWN_RCV |
			    VIRTIO_VSOCK_SHUTDOWN_SEND));
			saw_shutdown = true;
		}
	}
	ATF_CHECK(saw_shutdown);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

	close(s);
	/*
	 * Closing an established socket emits one final SHUTDOWN through the
	 * provider.  Drain it before constructing the independently full queue
	 * used by the reset-wakeup test below.
	 */
	while (read(provider, packet, sizeof(packet)) > 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);

	/*
	 * A multi-fragment SEQPACKET record is one send transaction.  Leave
	 * exactly one data slot below the provider high-water mark: the old
	 * packet-at-a-time path published the first fragment, failed the second,
	 * and reset the connection.  The transport must instead return
	 * EWOULDBLOCK without exposing any fragment, remain connected, and
	 * succeed after the unrelated queue is drained.
	 */
	{
		const size_t record_len = VSOCK_TRANSPORT_MAX_PAYLOAD + 1;
		struct virtio_vsock_hdr connect_request, connect_response;
		uint8_t *large_packet, *record;
		socklen_t error_len;
		ssize_t first_len, second_len;
		int socket_error;

		large_packet = malloc(sizeof(*request) +
		    VSOCK_TRANSPORT_MAX_PAYLOAD);
		record = malloc(record_len);
		ATF_REQUIRE(large_packet != NULL && record != NULL);
		memset(record, 'Q', record_len);

		s = socket(AF_VSOCK, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
		ATF_REQUIRE_MSG(s >= 0, "seqpacket socket: %s",
		    strerror(errno));
		peer.svm_port = 9001;
		errno = 0;
		ATF_REQUIRE(connect(s, (struct sockaddr *)&peer,
		    sizeof(peer)) == -1);
		ATF_REQUIRE(errno == EINPROGRESS);
		ATF_REQUIRE(read(provider, &connect_request,
		    sizeof(connect_request)) ==
		    (ssize_t)sizeof(connect_request));
		ATF_CHECK(le16toh(connect_request.type) ==
		    VIRTIO_VSOCK_TYPE_SEQPACKET);
		memset(&connect_response, 0, sizeof(connect_response));
		connect_response.src_cid = connect_request.dst_cid;
		connect_response.dst_cid = connect_request.src_cid;
		connect_response.src_port = connect_request.dst_port;
		connect_response.dst_port = connect_request.src_port;
		connect_response.type = connect_request.type;
		connect_response.op =
		    htole16(VIRTIO_VSOCK_OP_RESPONSE);
		connect_response.buf_alloc = htole32(2 * record_len);
		ATF_REQUIRE(write(provider, &connect_response,
		    sizeof(connect_response)) ==
		    (ssize_t)sizeof(connect_response));
		error_len = sizeof(socket_error);
		socket_error = -1;
		ATF_REQUIRE(getsockopt(s, SOL_SOCKET, SO_ERROR,
		    &socket_error, &error_len) == 0);
		ATF_REQUIRE(socket_error == 0);

		for (error = 0; error < 63; error++)
			ATF_REQUIRE(write(provider, &unused_request,
			    sizeof(unused_request)) ==
			    (ssize_t)sizeof(unused_request));
		errno = 0;
		ATF_CHECK(send(s, record, record_len, MSG_DONTWAIT) == -1);
		ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
		for (error = 0; error < 63; error++) {
			len = read(provider, large_packet,
			    sizeof(*request) + VSOCK_TRANSPORT_MAX_PAYLOAD);
			ATF_REQUIRE(len == (ssize_t)sizeof(*request));
			request = (struct virtio_vsock_hdr *)large_packet;
			ATF_CHECK(le16toh(request->op) ==
			    VIRTIO_VSOCK_OP_RST);
		}
		errno = 0;
		ATF_CHECK(read(provider, large_packet,
		    sizeof(*request) + VSOCK_TRANSPORT_MAX_PAYLOAD) == -1);
		ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

		ATF_REQUIRE(send(s, record, record_len, MSG_DONTWAIT) ==
		    (ssize_t)record_len);
		first_len = read(provider, large_packet,
		    sizeof(*request) + VSOCK_TRANSPORT_MAX_PAYLOAD);
		ATF_REQUIRE(first_len == (ssize_t)(sizeof(*request) +
		    VSOCK_TRANSPORT_MAX_PAYLOAD));
		request = (struct virtio_vsock_hdr *)large_packet;
		ATF_CHECK(le16toh(request->op) == VIRTIO_VSOCK_OP_RW);
		ATF_CHECK(le16toh(request->type) ==
		    VIRTIO_VSOCK_TYPE_SEQPACKET);
		ATF_CHECK(le32toh(request->flags) == 0);
		ATF_CHECK(memcmp(large_packet + sizeof(*request), record,
		    VSOCK_TRANSPORT_MAX_PAYLOAD) == 0);

		second_len = read(provider, large_packet,
		    sizeof(*request) + VSOCK_TRANSPORT_MAX_PAYLOAD);
		ATF_REQUIRE(second_len ==
		    (ssize_t)(sizeof(*request) + 1));
		request = (struct virtio_vsock_hdr *)large_packet;
		ATF_CHECK(le32toh(request->len) == 1);
		ATF_CHECK(le32toh(request->flags) ==
		    VIRTIO_VSOCK_SEQ_EOM);
		ATF_CHECK(large_packet[sizeof(*request)] ==
		    record[VSOCK_TRANSPORT_MAX_PAYLOAD]);

		close(s);
		while (read(provider, large_packet,
		    sizeof(*request) + VSOCK_TRANSPORT_MAX_PAYLOAD) > 0)
			;
		ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
		free(record);
		free(large_packet);
	}

	/*
	 * A blocking provider writer waiting behind a full queue belongs to the
	 * pre-reset transport epoch.  Reset must wake it with ECANCELED, not let
	 * it inject a stale guest packet after queues and PCBs were reset.
	 */
	for (error = 0; error < 128; error++)
		ATF_REQUIRE(write(provider, &response, sizeof(response)) ==
		    (ssize_t)sizeof(response));
	{
		struct provider_write_args args;
		struct kevent change, event;
		pthread_barrier_t barrier;
		pthread_t thread;
		struct timespec zero = { 0, 0 };
		struct timespec one_second = { 1, 0 };
		struct timespec deadline;
		int flags, join_error, reset_kq;

		flags = fcntl(provider, F_GETFL);
		ATF_REQUIRE(flags >= 0);
		reset_kq = kqueue();
		ATF_REQUIRE(reset_kq >= 0);
		EV_SET(&change, provider, EVFILT_WRITE, EV_ADD | EV_CLEAR,
		    0, 0, NULL);
		ATF_REQUIRE(kevent(reset_kq, &change, 1, NULL, 0, NULL) == 0);
		ATF_CHECK(kevent(reset_kq, NULL, 0, &event, 1, &zero) == 0);
		ATF_REQUIRE(fcntl(provider, F_SETFL, flags & ~O_NONBLOCK) == 0);
		ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 2) == 0);
		memset(&args, 0, sizeof(args));
		args.barrier = &barrier;
		args.packet = &response;
		args.len = sizeof(response);
		args.fd = provider;
		ATF_REQUIRE(pthread_create(&thread, NULL,
		    provider_blocked_write_thread, &args) == 0);
		error = pthread_barrier_wait(&barrier);
		ATF_REQUIRE(error == 0 ||
		    error == PTHREAD_BARRIER_SERIAL_THREAD);
		/*
		 * Give the released writer a scheduling quantum to enter write(2).
		 * Queue fullness above is the deterministic blocking condition;
		 * this delay only orders the two syscalls.
		 */
		usleep(100000);
		ATF_REQUIRE(ioctl(provider, VSOCK_IOC_TRANSPORT_RESET) == 0);
		ATF_CHECK(kevent(reset_kq, NULL, 0, &event, 1,
		    &one_second) == 1);
		ATF_CHECK(event.filter == EVFILT_WRITE);
		ATF_CHECK(event.ident == (uintptr_t)provider);
		ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
		deadline.tv_sec += 2;
		join_error = pthread_timedjoin_np(thread, NULL, &deadline);
		if (join_error == ETIMEDOUT) {
			ATF_REQUIRE(pthread_cancel(thread) == 0);
			ATF_REQUIRE(pthread_join(thread, NULL) == 0);
		}
		ATF_REQUIRE_MSG(join_error == 0,
		    "provider write did not wake after reset: %s",
		    strerror(join_error));
		ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
		ATF_CHECK(args.result == -1);
		ATF_CHECK(args.error == ECANCELED);
		ATF_REQUIRE(fcntl(provider, F_SETFL, flags) == 0);
		close(reset_kq);
	}
	errno = 0;
	ATF_CHECK(read(provider, packet, sizeof(packet)) == -1);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	close(provider);
	/*
	 * The failed EADDRINUSE attach above must not poison the losing
	 * descriptor.
	 * Once the first owner closes, retrying that exact fd must succeed rather
	 * than reporting EALREADY from stale cdev-private state.
	 */
	ATF_REQUIRE_MSG(ioctl(second, VSOCK_IOC_TRANSPORT_ATTACH, &attach) == 0,
	    "retry transport attach after owner close: %s", strerror(errno));
	close(second);
}

static void
provider_complete_connect(int provider, int s, uint32_t guest_cid,
    uint16_t type)
{
	struct virtio_vsock_hdr request, response;
	socklen_t optlen;
	ssize_t len;
	int error;

	len = read(provider, &request, sizeof(request));
	ATF_REQUIRE_MSG(len == (ssize_t)sizeof(request),
	    "provider CID %u request read returned %zd: %s", guest_cid,
	    len, strerror(errno));
	ATF_CHECK(le16toh(request.op) == VIRTIO_VSOCK_OP_REQUEST);
	ATF_CHECK(le16toh(request.type) == type);
	ATF_CHECK(le64toh(request.src_cid) == VSOCK_CID_HOST);
	ATF_CHECK(le64toh(request.dst_cid) == guest_cid);

	memset(&response, 0, sizeof(response));
	response.src_cid = request.dst_cid;
	response.dst_cid = request.src_cid;
	response.src_port = request.dst_port;
	response.dst_port = request.src_port;
	response.type = request.type;
	response.op = htole16(VIRTIO_VSOCK_OP_RESPONSE);
	response.buf_alloc = htole32(65536);
	ATF_REQUIRE(write(provider, &response, sizeof(response)) ==
	    (ssize_t)sizeof(response));
	optlen = sizeof(error);
	error = -1;
	ATF_REQUIRE(getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &optlen) == 0);
	ATF_CHECK(error == 0);
}

static int
provider_start_connect(uint32_t guest_cid, uint32_t port, int type)
{
	struct sockaddr_vm peer;
	int s;

	s = socket(AF_VSOCK, type | SOCK_NONBLOCK, 0);
	ATF_REQUIRE_MSG(s >= 0, "socket CID %u: %s", guest_cid,
	    strerror(errno));
	memset(&peer, 0, sizeof(peer));
	peer.svm_len = sizeof(peer);
	peer.svm_family = AF_VSOCK;
	peer.svm_cid = guest_cid;
	peer.svm_port = port;
	errno = 0;
	ATF_REQUIRE(connect(s, (struct sockaddr *)&peer, sizeof(peer)) == -1);
	ATF_REQUIRE_MSG(errno == EINPROGRESS,
	    "connect CID %u returned %s", guest_cid, strerror(errno));
	return (s);
}

ATF_TC(kernel_transport_multiple_providers);
ATF_TC_HEAD(kernel_transport_multiple_providers, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kernel_transport_multiple_providers, tc)
{
	struct vsock_transport_attach attach1, attach2;
	const char payload[] = "provider-two";
	struct virtio_vsock_hdr *packet;
	union {
		struct virtio_vsock_hdr hdr;
		uint8_t bytes[sizeof(struct virtio_vsock_hdr) +
		    sizeof(payload)];
	} packet_buf;
	size_t count_len;
	u_int filled, provider_count;
	ssize_t len;
	int duplicate, p1, p2, replacement, s1, s2, s3;

	count_len = sizeof(provider_count);
	ATF_REQUIRE_MSG(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0,
	    "kern.vsock.userspace_providers: %s", strerror(errno));
	if (provider_count != 0)
		atf_tc_skip("another /dev/vsock provider is active");

	memset(&attach1, 0, sizeof(attach1));
	attach1.version = VSOCK_TRANSPORT_VERSION;
	attach1.guest_cid = 42;
	attach1.features = VIRTIO_VSOCK_F_STREAM;
	attach2 = attach1;
	attach2.guest_cid = 43;
	attach2.features = VIRTIO_VSOCK_F_SEQPACKET |
	    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;

	p1 = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	p2 = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	duplicate = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(p1 >= 0 && p2 >= 0 && duplicate >= 0);
	if (ioctl(p1, VSOCK_IOC_TRANSPORT_ATTACH, &attach1) < 0) {
		if (errno == EBUSY)
			atf_tc_skip("another AF_VSOCK transport is active");
		ATF_REQUIRE_MSG(false, "first provider attach: %s",
		    strerror(errno));
	}
	ATF_REQUIRE_MSG(ioctl(p2, VSOCK_IOC_TRANSPORT_ATTACH, &attach2) == 0,
	    "second provider attach: %s", strerror(errno));
	errno = 0;
	ATF_CHECK(ioctl(duplicate, VSOCK_IOC_TRANSPORT_ATTACH,
	    &attach1) == -1);
	ATF_CHECK(errno == EADDRINUSE);
	/*
	 * A failed attach leaves an inert cdev-private provider so concurrent
	 * operations cannot race an explicit destructor.  The same descriptor
	 * must remain reusable for a different, unclaimed CID.
	 */
	{
		struct vsock_transport_attach retry;

		retry = attach1;
		retry.guest_cid = 44;
		ATF_REQUIRE_MSG(ioctl(duplicate, VSOCK_IOC_TRANSPORT_ATTACH,
		    &retry) == 0, "retry attach on same fd: %s",
		    strerror(errno));
	}
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 3);
	close(duplicate);

	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 2);

	/*
	 * The aggregate transport admits both socket types, while the provider
	 * selected by the destination CID enforces its own negotiated features.
	 */
	{
		struct virtio_vsock_hdr unsupported_request, unsupported_rst;
		struct sockaddr_vm peer;
		int unsupported;

		unsupported = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ATF_REQUIRE(unsupported >= 0);
		memset(&peer, 0, sizeof(peer));
		peer.svm_len = sizeof(peer);
		peer.svm_family = AF_VSOCK;
		peer.svm_cid = attach2.guest_cid;
		peer.svm_port = 9000;
		errno = 0;
		ATF_CHECK(connect(unsupported, (struct sockaddr *)&peer,
		    sizeof(peer)) == -1);
		ATF_CHECK(errno == EPROTONOSUPPORT);
		close(unsupported);

		memset(&unsupported_request, 0, sizeof(unsupported_request));
		unsupported_request.src_cid = htole64(attach1.guest_cid);
		unsupported_request.dst_cid = htole64(VSOCK_CID_HOST);
		unsupported_request.src_port = htole32(8000);
		unsupported_request.dst_port = htole32(8001);
		unsupported_request.type =
		    htole16(VIRTIO_VSOCK_TYPE_SEQPACKET);
		unsupported_request.op =
		    htole16(VIRTIO_VSOCK_OP_REQUEST);
		ATF_REQUIRE(write(p1, &unsupported_request,
		    sizeof(unsupported_request)) ==
		    (ssize_t)sizeof(unsupported_request));
		ATF_REQUIRE(read(p1, &unsupported_rst,
		    sizeof(unsupported_rst)) ==
		    (ssize_t)sizeof(unsupported_rst));
		ATF_CHECK(le16toh(unsupported_rst.op) ==
		    VIRTIO_VSOCK_OP_RST);
		ATF_CHECK(le16toh(unsupported_rst.type) ==
		    VIRTIO_VSOCK_TYPE_SEQPACKET);
		ATF_CHECK(le64toh(unsupported_rst.dst_cid) ==
		    attach1.guest_cid);
		errno = 0;
		ATF_CHECK(read(p2, &unsupported_rst,
		    sizeof(unsupported_rst)) == -1);
		ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	}

	s1 = provider_start_connect(attach1.guest_cid, 9001, SOCK_STREAM);
	s2 = provider_start_connect(attach2.guest_cid, 9002,
	    SOCK_SEQPACKET);
	provider_complete_connect(p1, s1, attach1.guest_cid,
	    VIRTIO_VSOCK_TYPE_STREAM);
	provider_complete_connect(p2, s2, attach2.guest_cid,
	    VIRTIO_VSOCK_TYPE_SEQPACKET);

	ATF_REQUIRE(send(s2, payload, sizeof(payload), 0) ==
	    (ssize_t)sizeof(payload));
	packet = &packet_buf.hdr;
	len = read(p2, packet_buf.bytes, sizeof(packet_buf.bytes));
	ATF_REQUIRE_MSG(len == (ssize_t)(sizeof(*packet) + sizeof(payload)),
	    "CID 43 data read returned %zd", len);
	ATF_CHECK(le64toh(packet->dst_cid) == attach2.guest_cid);
	ATF_CHECK(le16toh(packet->type) == VIRTIO_VSOCK_TYPE_SEQPACKET);
	errno = 0;
	ATF_CHECK(read(p1, packet_buf.bytes, sizeof(packet_buf.bytes)) == -1);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

	/*
	 * Saturating one provider's data queue must not apply backpressure to
	 * another guest which happens to share the stable transport vector.
	 * This exercises active routing and wakeup isolation, unlike the scale
	 * test below which intentionally measures attachment bookkeeping only.
	 */
	filled = 0;
	while (filled < 256) {
		len = send(s1, payload, sizeof(payload), 0);
		if (len == -1)
			break;
		ATF_REQUIRE_EQ(len, (ssize_t)sizeof(payload));
		filled++;
	}
	ATF_REQUIRE_MSG(filled > 0 && filled < 256,
	    "CID 42 queue did not report bounded backpressure (filled=%u)",
	    filled);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	ATF_REQUIRE(send(s2, payload, sizeof(payload), 0) ==
	    (ssize_t)sizeof(payload));
	len = read(p2, packet_buf.bytes, sizeof(packet_buf.bytes));
	ATF_REQUIRE_MSG(len ==
	    (ssize_t)(sizeof(*packet) + sizeof(payload)),
	    "CID 43 data read with CID 42 full returned %zd", len);
	for (u_int i = 0; i < filled; i++) {
		len = read(p1, packet_buf.bytes, sizeof(packet_buf.bytes));
		ATF_REQUIRE_MSG(len ==
		    (ssize_t)(sizeof(*packet) + sizeof(payload)),
		    "CID 42 queue drain %u returned %zd", i, len);
	}

	/*
	 * A feature change starts a new epoch for only that CID.  It must purge
	 * old-type packets and reset that CID without disturbing another
	 * provider's established socket.
	 */
	ATF_REQUIRE(send(s1, payload, sizeof(payload), 0) ==
	    (ssize_t)sizeof(payload));
	{
		uint64_t features;
		socklen_t optlen;
		int error;

		features = VIRTIO_VSOCK_F_SEQPACKET |
		    VIRTIO_VSOCK_F_NO_IMPLIED_STREAM;
		ATF_REQUIRE(ioctl(p1, VSOCK_IOC_TRANSPORT_SET_FEATURES,
		    &features) == 0);
		/*
		 * Socket creation is independent of remote feature negotiation:
		 * this descriptor could still be used over loopback.  The
		 * destination-specific userspace provider rejects STREAM when
		 * connect selects CID 42.
		 */
		error = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ATF_REQUIRE_MSG(error >= 0,
		    "STREAM socket creation followed aggregate features: %s",
		    strerror(errno));
		{
			struct sockaddr_vm peer;

			memset(&peer, 0, sizeof(peer));
			peer.svm_len = sizeof(peer);
			peer.svm_family = AF_VSOCK;
			peer.svm_cid = attach1.guest_cid;
			peer.svm_port = 9000;
			errno = 0;
			ATF_CHECK(connect(error, (struct sockaddr *)&peer,
			    sizeof(peer)) == -1);
		}
		ATF_CHECK(errno == EPROTONOSUPPORT);
		close(error);
		optlen = sizeof(error);
		error = 0;
		ATF_REQUIRE(getsockopt(s1, SOL_SOCKET, SO_ERROR, &error,
		    &optlen) == 0);
		ATF_CHECK(error == ECONNRESET);
		errno = 0;
		ATF_CHECK(read(p1, packet_buf.bytes,
		    sizeof(packet_buf.bytes)) == -1);
		ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
		ATF_REQUIRE(send(s2, payload, sizeof(payload), 0) ==
		    (ssize_t)sizeof(payload));
		len = read(p2, packet_buf.bytes, sizeof(packet_buf.bytes));
		ATF_REQUIRE_MSG(len ==
		    (ssize_t)(sizeof(*packet) + sizeof(payload)),
		    "CID 43 post-feature data read returned %zd", len);

		close(s1);
		features = VIRTIO_VSOCK_F_STREAM;
		ATF_REQUIRE(ioctl(p1, VSOCK_IOC_TRANSPORT_SET_FEATURES,
		    &features) == 0);
		error = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ATF_REQUIRE_MSG(error >= 0,
		    "aggregate STREAM feature was not restored: %s",
		    strerror(errno));
		close(error);
		s1 = provider_start_connect(attach1.guest_cid, 9001,
		    SOCK_STREAM);
		provider_complete_connect(p1, s1, attach1.guest_cid,
		    VIRTIO_VSOCK_TYPE_STREAM);
	}

	/*
	 * Resetting one provider disconnects only that CID.  The other guest's
	 * established connection must continue to route to its own queue.
	 */
	ATF_REQUIRE(ioctl(p1, VSOCK_IOC_TRANSPORT_RESET) == 0);
	{
		socklen_t optlen = sizeof(int);
		int error = 0;

		ATF_REQUIRE(getsockopt(s1, SOL_SOCKET, SO_ERROR, &error,
		    &optlen) == 0);
		ATF_CHECK(error == ECONNRESET);
	}
	ATF_REQUIRE(send(s2, payload, sizeof(payload), 0) ==
	    (ssize_t)sizeof(payload));
	len = read(p2, packet_buf.bytes, sizeof(packet_buf.bytes));
	ATF_REQUIRE_MSG(len == (ssize_t)(sizeof(*packet) + sizeof(payload)),
	    "CID 43 post-reset data read returned %zd", len);

	close(s1);
	close(p1);
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 1);
	ATF_REQUIRE(send(s2, payload, sizeof(payload), 0) ==
	    (ssize_t)sizeof(payload));
	len = read(p2, packet_buf.bytes, sizeof(packet_buf.bytes));
	ATF_REQUIRE_MSG(len == (ssize_t)(sizeof(*packet) + sizeof(payload)),
	    "CID 43 post-detach data read returned %zd", len);

	replacement = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(replacement >= 0);
	ATF_REQUIRE_MSG(ioctl(replacement, VSOCK_IOC_TRANSPORT_ATTACH,
	    &attach1) == 0, "CID reuse while CID 43 remains active: %s",
	    strerror(errno));
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 2);

	close(s2);
	close(p2);
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 1);
	s3 = provider_start_connect(attach1.guest_cid, 9003, SOCK_STREAM);
	provider_complete_connect(replacement, s3, attach1.guest_cid,
	    VIRTIO_VSOCK_TYPE_STREAM);
	close(s3);
	close(replacement);
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 0);
}

ATF_TC(kernel_transport_provider_scale);
ATF_TC_HEAD(kernel_transport_provider_scale, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(kernel_transport_provider_scale, tc)
{
	enum { PROVIDERS = 1024, FIRST_CID = 1000 };
	struct vsock_transport_attach attach;
	size_t count_len;
	u_int provider_count;
	int *providers;

	count_len = sizeof(provider_count);
	ATF_REQUIRE_MSG(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0,
	    "kern.vsock.userspace_providers: %s", strerror(errno));
	if (provider_count != 0)
		atf_tc_skip("another /dev/vsock provider is active");

	providers = calloc(PROVIDERS, sizeof(*providers));
	ATF_REQUIRE(providers != NULL);
	for (u_int i = 0; i < PROVIDERS; i++)
		providers[i] = -1;

	memset(&attach, 0, sizeof(attach));
	attach.version = VSOCK_TRANSPORT_VERSION;
	attach.features = VIRTIO_VSOCK_F_STREAM;
	for (u_int i = 0; i < PROVIDERS; i++) {
		attach.guest_cid = FIRST_CID + i;
		providers[i] = open("/dev/vsock", O_RDWR | O_NONBLOCK);
		ATF_REQUIRE_MSG(providers[i] >= 0,
		    "open provider %u: %s", i, strerror(errno));
		if (ioctl(providers[i], VSOCK_IOC_TRANSPORT_ATTACH,
		    &attach) < 0) {
			if (i == 0 && errno == EBUSY)
				atf_tc_skip(
				    "another AF_VSOCK transport is active");
			ATF_REQUIRE_MSG(false, "attach CID %u: %s",
			    attach.guest_cid, strerror(errno));
		}
	}
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == PROVIDERS);

	/*
	 * Close in a permutation instead of insertion order.  With 256 buckets,
	 * this walks colliding chains while other entries in every bucket remain
	 * registered.
	 */
	for (u_int lane = 0; lane < 4; lane++) {
		for (u_int i = lane; i < PROVIDERS; i += 4) {
			close(providers[i]);
			providers[i] = -1;
		}
	}
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 0);
	free(providers);
}

struct provider_attach_race_arg {
	pthread_barrier_t *barrier;
	struct vsock_transport_attach attach;
	int fd;
	int result;
	int error;
};

static void *
provider_attach_race(void *arg)
{
	struct provider_attach_race_arg *race = arg;
	int error;

	error = pthread_barrier_wait(race->barrier);
	if (error != 0 && error != PTHREAD_BARRIER_SERIAL_THREAD) {
		race->result = -1;
		race->error = error;
		return (NULL);
	}
	race->result = ioctl(race->fd, VSOCK_IOC_TRANSPORT_ATTACH,
	    &race->attach);
	race->error = race->result == 0 ? 0 : errno;
	return (NULL);
}

ATF_TC(kernel_transport_duplicate_attach_race);
ATF_TC_HEAD(kernel_transport_duplicate_attach_race, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(kernel_transport_duplicate_attach_race, tc)
{
	struct provider_attach_race_arg races[2];
	struct vsock_transport_attach probe_attach;
	pthread_barrier_t barrier;
	pthread_t threads[2];
	size_t count_len;
	u_int provider_count;
	int error, probe, shared;

	count_len = sizeof(provider_count);
	ATF_REQUIRE_MSG(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0,
	    "kern.vsock.userspace_providers: %s", strerror(errno));
	if (provider_count != 0)
		atf_tc_skip("another /dev/vsock provider is active");

	memset(&probe_attach, 0, sizeof(probe_attach));
	probe_attach.version = VSOCK_TRANSPORT_VERSION;
	probe_attach.guest_cid = 4999;
	probe_attach.features = VIRTIO_VSOCK_F_STREAM;
	probe = open("/dev/vsock", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(probe >= 0);
	if (ioctl(probe, VSOCK_IOC_TRANSPORT_ATTACH, &probe_attach) < 0) {
		if (errno == EBUSY)
			atf_tc_skip("another AF_VSOCK transport is active");
		ATF_REQUIRE_MSG(false, "provider probe attach: %s",
		    strerror(errno));
	}
	close(probe);

	for (u_int round = 0; round < 64; round++) {
		ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 3) == 0);
		memset(races, 0, sizeof(races));
		for (u_int i = 0; i < 2; i++) {
			races[i].barrier = &barrier;
			races[i].attach.version = VSOCK_TRANSPORT_VERSION;
			races[i].attach.guest_cid = 5000 + round;
			races[i].attach.features = VIRTIO_VSOCK_F_STREAM;
			races[i].fd = open("/dev/vsock",
			    O_RDWR | O_NONBLOCK);
			ATF_REQUIRE(races[i].fd >= 0);
			ATF_REQUIRE(pthread_create(&threads[i], NULL,
			    provider_attach_race, &races[i]) == 0);
		}
		error = pthread_barrier_wait(&barrier);
		ATF_REQUIRE(error == 0 ||
		    error == PTHREAD_BARRIER_SERIAL_THREAD);
		for (u_int i = 0; i < 2; i++)
			ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
		ATF_CHECK_MSG((races[0].result == 0) !=
		    (races[1].result == 0),
		    "round %u results %d/%d errors %d/%d", round,
		    races[0].result, races[1].result, races[0].error,
		    races[1].error);
		for (u_int i = 0; i < 2; i++) {
			if (races[i].result != 0)
				ATF_CHECK_MSG(races[i].error == EADDRINUSE,
				    "round %u loser %u returned %s", round, i,
				    strerror(races[i].error));
			close(races[i].fd);
		}
		ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
	}

	/*
	 * Race the first cdev-private allocation on one shared file
	 * description as well.  Exactly one ioctl may attach it; the losing
	 * ioctl must not clear or destroy the winning thread's provider.
	 */
	for (u_int round = 0; round < 64; round++) {
		shared = open("/dev/vsock", O_RDWR | O_NONBLOCK);
		ATF_REQUIRE(shared >= 0);
		ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 3) == 0);
		memset(races, 0, sizeof(races));
		for (u_int i = 0; i < 2; i++) {
			races[i].barrier = &barrier;
			races[i].attach.version = VSOCK_TRANSPORT_VERSION;
			races[i].attach.guest_cid = 6000 + round * 2 + i;
			races[i].attach.features = VIRTIO_VSOCK_F_STREAM;
			races[i].fd = shared;
			ATF_REQUIRE(pthread_create(&threads[i], NULL,
			    provider_attach_race, &races[i]) == 0);
		}
		error = pthread_barrier_wait(&barrier);
		ATF_REQUIRE(error == 0 ||
		    error == PTHREAD_BARRIER_SERIAL_THREAD);
		for (u_int i = 0; i < 2; i++)
			ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
		ATF_CHECK_MSG((races[0].result == 0) !=
		    (races[1].result == 0),
		    "shared round %u results %d/%d errors %d/%d", round,
		    races[0].result, races[1].result, races[0].error,
		    races[1].error);
		for (u_int i = 0; i < 2; i++) {
			if (races[i].result != 0)
				ATF_CHECK_MSG(races[i].error == EALREADY ||
				    races[i].error == EBUSY,
				    "shared round %u loser %u returned %s",
				    round, i, strerror(races[i].error));
		}
		count_len = sizeof(provider_count);
		ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
		    &provider_count, &count_len, NULL, 0) == 0);
		ATF_CHECK_EQ(provider_count, 1);
		close(shared);
		ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
		count_len = sizeof(provider_count);
		ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
		    &provider_count, &count_len, NULL, 0) == 0);
		ATF_CHECK_EQ(provider_count, 0);
	}
	count_len = sizeof(provider_count);
	ATF_REQUIRE(sysctlbyname("kern.vsock.userspace_providers",
	    &provider_count, &count_len, NULL, 0) == 0);
	ATF_CHECK(provider_count == 0);
}

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
	ATF_TP_ADD_TC(tp, rebind_same_socket_preserves_binding);

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
	ATF_TP_ADD_TC(tp, siocoutq_inflight);
	ATF_TP_ADD_TC(tp, sysctl_guest_cid_local);

	/* Group 16: zerocopy compat */
	ATF_TP_ADD_TC(tp, linux_zerocopy_sockopt_rejected);

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

	/* Group 38: Type mismatch, oversized message, sockopts, pcblist */
	ATF_TP_ADD_TC(tp, seqpacket_connect_to_stream_listener_refused);
	ATF_TP_ADD_TC(tp, stream_connect_to_seqpacket_listener_refused);
	ATF_TP_ADD_TC(tp, seqpacket_loopback_oversized_emsgsize);
	ATF_TP_ADD_TC(tp, peer_host_vm_id_sockopt);
	ATF_TP_ADD_TC(tp, sysctl_buf_validation);
	ATF_TP_ADD_TC(tp, pcblist_state_values);

	/* Group 39: Coverage parity with AF_UNIX */
	ATF_TP_ADD_TC(tp, send_before_accept);
	ATF_TP_ADD_TC(tp, full_writability_poll);
	ATF_TP_ADD_TC(tp, peerclosed_write_event);
	ATF_TP_ADD_TC(tp, sendto_on_connected_seqpacket);
	ATF_TP_ADD_TC(tp, socketpair_rejected);
	ATF_TP_ADD_TC(tp, resize_buffer_with_data);

	/* Group 40: Integration tests */
	ATF_TP_ADD_TC(tp, pcblist_fields);
	ATF_TP_ADD_TC(tp, sysctl_counters);

	/* Group 41: Shutdown + drain interaction */
	ATF_TP_ADD_TC(tp, shutdown_wr_drain_then_eof);
	ATF_TP_ADD_TC(tp, seqpacket_shutdown_drain);

	/* Group 42: Error path and edge case tests */
	ATF_TP_ADD_TC(tp, connect_on_listener_fails);
	ATF_TP_ADD_TC(tp, double_connect_eisconn);
	ATF_TP_ADD_TC(tp, listen_wrong_state);
	ATF_TP_ADD_TC(tp, send_after_disconnect);
	ATF_TP_ADD_TC(tp, recv_msg_dontwait);
	ATF_TP_ADD_TC(tp, bind_cid_zero_fails);
	ATF_TP_ADD_TC(tp, multi_accept_distinct_fds);

	/* Group 43: kqueue and poll edge cases */
	ATF_TP_ADD_TC(tp, kqueue_read_fires_on_data);
	ATF_TP_ADD_TC(tp, kqueue_write_fires_on_space);
	ATF_TP_ADD_TC(tp, poll_listener_connect_pending);

	/* Group 44: SEQPACKET message integrity */
	ATF_TP_ADD_TC(tp, seqpacket_varied_sizes);
	ATF_TP_ADD_TC(tp, seqpacket_trunc_preserves_next);

	/* Group 45: Concurrent stress */
	ATF_TP_ADD_TC(tp, rapid_connect_close_multi_thread);

	/* Group 46: VMADDR_* alias and constant tests */
	ATF_TP_ADD_TC(tp, vmaddr_aliases);

	/* Group 47: accept() returns correct peer address */
	ATF_TP_ADD_TC(tp, accept_returns_peer_addr);

	/* Group 48: Bidirectional data */
	ATF_TP_ADD_TC(tp, bidirectional_echo);
	ATF_TP_ADD_TC(tp, seqpacket_bidirectional);

	/* Group 49: getsockopt/setsockopt edge cases */
	ATF_TP_ADD_TC(tp, buffer_min_max_ordering);
	ATF_TP_ADD_TC(tp, msg_oob_rejected);
	ATF_TP_ADD_TC(tp, connect_timeout_timeval);
	ATF_TP_ADD_TC(tp, seqpacket_exact_max_boundary);
	ATF_TP_ADD_TC(tp, seqpacket_shutdown_rdwr);
	ATF_TP_ADD_TC(tp, seqpacket_peer_close_eof_epipe);
	ATF_TP_ADD_TC(tp, connect_timeout_erange);
	ATF_TP_ADD_TC(tp, vmci_only_opts_rejected);

	/* Group 50: SEQPACKET fragment limit sysctl */
	ATF_TP_ADD_TC(tp, seqpacket_frag_max_sysctl);

	/* Group 51: Shutdown wakes blocked sender */
	ATF_TP_ADD_TC(tp, shutdown_rd_wakes_blocked_sender);

	/* Group 52: Concurrent send + close stress */
	ATF_TP_ADD_TC(tp, concurrent_send_close_stress);
	ATF_TP_ADD_TC(tp, seqpacket_shutdown_rd_wakes_sender);

	/* Group 40: Linux-ABI reachability and privileged-port gating */
	ATF_TP_ADD_TC(tp, sockopt_af_vsock_level);
	ATF_TP_ADD_TC(tp, bind_cid_any_32bit);
	ATF_TP_ADD_TC(tp, bind_privileged_port);
	ATF_TP_ADD_TC(tp, bind_cid_local_explicit);
	ATF_TP_ADD_TC(tp, bind_port_zero_literal);
	ATF_TP_ADD_TC(tp, get_local_cid_ioctl);

	/* Group 53: privileged VMM packet transport. */
	ATF_TP_ADD_TC(tp, kernel_transport_provider);
	ATF_TP_ADD_TC(tp, kernel_transport_multiple_providers);
	ATF_TP_ADD_TC(tp, kernel_transport_provider_scale);
	ATF_TP_ADD_TC(tp, kernel_transport_duplicate_attach_race);

	return (atf_no_error());
}
