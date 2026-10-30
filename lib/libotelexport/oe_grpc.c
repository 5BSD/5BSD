/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A minimal gRPC unary client for OTLP/gRPC: one call per connection,
 * HTTP/2 framing by nghttp2, cleartext with prior knowledge for http://
 * endpoints and TLS (base OpenSSL, peer and host name verified, ALPN
 * "h2") for https:// endpoints.  It sends one length-prefixed message,
 * optionally gzip-compressed (grpc-encoding), with a grpc-timeout, and
 * reports the call's status as the gRPC protocol defines it:
 * grpc-status and grpc-message from the trailers (or a Trailers-Only
 * response), the RetryInfo of grpc-status-details-bin, a status mapped
 * from a non-200 HTTP status or a stream reset, and the response
 * message for the caller to decode.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlppb.h"

/* Bounds on what the server may send back. */
#define	GRPC_MAX_RESPONSE	(4 * 1024 * 1024)
#define	GRPC_MAX_DETAILS	4096
#define	GRPC_READ_CHUNK		16384

struct gconn {
	int		 fd;
	SSL_CTX		*ctx;
	SSL		*ssl;
	struct timespec	 deadline;
};

struct gcall {
	struct gconn	*conn;
	int32_t		 stream_id;
	/* Request body: the framed message. */
	const unsigned char *req;
	size_t		 req_len, req_off;
	/* Response. */
	int		 http_status;
	char		 content_type[64];
	int		 have_status;
	int		 grpc_status;
	char		 grpc_message[256];
	char		 grpc_encoding[32];
	char		 details[GRPC_MAX_DETAILS];
	size_t		 details_len;
	struct oe_buf	 body;
	int		 body_overflow;
	int		 closed;
	uint32_t	 close_error;
};

static int
remaining_ms(struct gconn *c)
{
	struct timespec now;
	int64_t ms;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (int64_t)(c->deadline.tv_sec - now.tv_sec) * 1000 +
	    (c->deadline.tv_nsec - now.tv_nsec) / 1000000;
	if (ms <= 0)
		return (0);
	/* The deadline is at most an int of milliseconds away. */
	return ((int)ms);
}

static void
gconn_close(struct gconn *c)
{

	if (c->ssl != NULL) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}
	if (c->ctx != NULL)
		SSL_CTX_free(c->ctx);
	if (c->fd >= 0)
		close(c->fd);
	c->ssl = NULL;
	c->ctx = NULL;
	c->fd = -1;
}

/* Wait until the socket is readable or writable, within the deadline. */
static int
gconn_wait(struct gconn *c, short events)
{
	struct pollfd pfd;

	/*
	 * A zero timeout polls once.  The calling thread blocks signals
	 * (oe_otlp.c), so a failed poll means the deadline passed.
	 */
	pfd.fd = c->fd;
	pfd.events = events;
	pfd.revents = 0;
	return (poll(&pfd, 1, remaining_ms(c)) > 0 ? 0 : -1);
}

static int
gconn_open(struct gconn *c, const struct oe_url *u, char *err, size_t errlen)
{
	static const unsigned char alpn[] = "\x02h2";
	const unsigned char *sel;
	unsigned int sellen;
	unsigned long ec;
	const char *reason;
	struct timeval tv;
	int ms;

	c->fd = oe_tcp_connect(u, remaining_ms(c));
	if (c->fd < 0) {
		snprintf(err, errlen, "connect to %s:%d failed", u->host,
		    u->port);
		return (-1);
	}
	/* Blocking reads and writes never outlast the call. */
	ms = remaining_ms(c);
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (!u->tls)
		return (0);

	if ((c->ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		goto tlsfail;
	SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
	SSL_CTX_set_default_verify_paths(c->ctx);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_alpn_protos(c->ctx, alpn, sizeof(alpn) - 1) != 0 ||
	    (c->ssl = SSL_new(c->ctx)) == NULL)
		goto tlsfail;
	SSL_set_fd(c->ssl, c->fd);
	SSL_set_tlsext_host_name(c->ssl, __DECONST(char *, u->host));
	SSL_set1_host(c->ssl, u->host);
	if (SSL_connect(c->ssl) != 1)
		goto tlsfail;
	/* OpenSSL accepts only a protocol we offered: "h2" or none. */
	SSL_get0_alpn_selected(c->ssl, &sel, &sellen);
	if (sellen == 0) {
		snprintf(err, errlen, "TLS server %s did not negotiate "
		    "HTTP/2 (ALPN h2)", u->host);
		gconn_close(c);
		return (-1);
	}
	return (0);

tlsfail:
	ec = ERR_get_error();
	reason = ERR_reason_error_string(ec);
	snprintf(err, errlen, "TLS handshake with %s failed: %s", u->host,
	    reason != NULL ? reason : "unknown error");
	ERR_clear_error();
	gconn_close(c);
	return (-1);
}

/* ---------------------------------------------------------------- */
/* nghttp2 callbacks							*/

/*
 * nghttp2 allocates the session through the library's allocator, like
 * everything else here (and so the tests' allocation-failure sweeps
 * reach it).
 */
static void *
ng_malloc(size_t size, void *ud __unused)
{

	return (malloc(size));
}

static void
ng_free(void *p, void *ud __unused)
{

	free(p);
}

static void *
ng_calloc(size_t n, size_t size, void *ud __unused)
{

	return (calloc(n, size));
}

static void *
ng_realloc(void *p, size_t size, void *ud __unused)
{

	return (realloc(p, size));
}

static nghttp2_mem ng_mem = {
	.malloc = ng_malloc,
	.free = ng_free,
	.calloc = ng_calloc,
	.realloc = ng_realloc,
};

static nghttp2_ssize
send_cb(nghttp2_session *s __unused, const uint8_t *data, size_t len,
    int flags __unused, void *arg)
{
	struct gcall *g = arg;
	struct gconn *c = g->conn;
	size_t off;
	ssize_t n;

	for (off = 0; off < len; off += (size_t)n) {
		if (gconn_wait(c, POLLOUT) != 0)
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
		n = c->ssl != NULL ? SSL_write(c->ssl, data + off,
		    (int)(len - off)) : write(c->fd, data + off, len - off);
		if (n <= 0)
			return (NGHTTP2_ERR_CALLBACK_FAILURE);
	}
	return ((nghttp2_ssize)len);
}

static nghttp2_ssize
read_body_cb(nghttp2_session *s __unused, int32_t id __unused, uint8_t *buf,
    size_t length, uint32_t *flags, nghttp2_data_source *src __unused,
    void *arg)
{
	struct gcall *g = arg;
	size_t n;

	n = g->req_len - g->req_off;
	if (n > length)
		n = length;
	memcpy(buf, g->req + g->req_off, n);
	g->req_off += n;
	if (g->req_off == g->req_len)
		*flags |= NGHTTP2_DATA_FLAG_EOF;
	return ((nghttp2_ssize)n);
}

static void
copy_value(char *dst, size_t dstlen, const uint8_t *v, size_t len)
{

	snprintf(dst, dstlen, "%.*s", (int)len, (const char *)v);
}

static int
header_cb(nghttp2_session *s __unused, const nghttp2_frame *frame __unused,
    const uint8_t *name, size_t namelen, const uint8_t *value,
    size_t valuelen, uint8_t flags __unused, void *arg)
{
	struct gcall *g = arg;
	char num[16];

	/*
	 * The call is the session's only stream (push is disabled), so
	 * every header, data and close callback is about it.
	 */
#define	IS(lit)	(namelen == sizeof(lit) - 1 && memcmp(name, lit, namelen) == 0)
	if (IS(":status")) {
		copy_value(num, sizeof(num), value, valuelen);
		g->http_status = atoi(num);
	} else if (IS("content-type"))
		copy_value(g->content_type, sizeof(g->content_type), value,
		    valuelen);
	else if (IS("grpc-status")) {
		copy_value(num, sizeof(num), value, valuelen);
		g->grpc_status = atoi(num);
		g->have_status = 1;
	} else if (IS("grpc-message"))
		copy_value(g->grpc_message, sizeof(g->grpc_message), value,
		    valuelen);
	else if (IS("grpc-encoding"))
		copy_value(g->grpc_encoding, sizeof(g->grpc_encoding), value,
		    valuelen);
	else if (IS("grpc-status-details-bin") &&
	    valuelen <= sizeof(g->details)) {
		memcpy(g->details, value, valuelen);
		g->details_len = valuelen;
	}
#undef IS
	return (0);
}

static int
data_cb(nghttp2_session *s __unused, uint8_t flags __unused,
    int32_t id __unused,
    const uint8_t *data, size_t len, void *arg)
{
	struct gcall *g = arg;

	if (g->body.len + len > GRPC_MAX_RESPONSE) {
		g->body_overflow = 1;
		return (0);
	}
	oe_buf_append(&g->body, (const char *)data, len);
	return (0);
}

static int
close_cb(nghttp2_session *s __unused, int32_t id __unused, uint32_t error,
    void *arg)
{
	struct gcall *g = arg;

	g->closed = 1;
	g->close_error = error;
	return (0);
}

/* ---------------------------------------------------------------- */
/* Status								*/

/* gRPC's mapping of HTTP status codes (doc/http-grpc-status-mapping.md). */
static int
status_from_http(int http)
{

	switch (http) {
	case 400:
		return (OE_GRPC_INTERNAL);
	case 401:
		return (OE_GRPC_UNAUTHENTICATED);
	case 403:
		return (OE_GRPC_PERMISSION_DENIED);
	case 404:
		return (OE_GRPC_UNIMPLEMENTED);
	case 429:
	case 502:
	case 503:
	case 504:
		return (OE_GRPC_UNAVAILABLE);
	default:
		return (OE_GRPC_UNKNOWN);
	}
}

/* ... and of HTTP/2 stream resets (doc/PROTOCOL-HTTP2.md). */
static int
status_from_reset(uint32_t error)
{

	switch (error) {
	case NGHTTP2_REFUSED_STREAM:
		return (OE_GRPC_UNAVAILABLE);
	case NGHTTP2_CANCEL:
		return (OE_GRPC_CANCELLED);
	case NGHTTP2_ENHANCE_YOUR_CALM:
		return (OE_GRPC_RESOURCE_EXHAUSTED);
	case NGHTTP2_INADEQUATE_SECURITY:
		return (OE_GRPC_PERMISSION_DENIED);
	default:
		return (OE_GRPC_INTERNAL);
	}
}

int
oe_grpc_retryable(int status, double retry_delay)
{

	/*
	 * OTLP/gRPC: these are retryable; RESOURCE_EXHAUSTED only when the
	 * server says it can recover by sending RetryInfo.
	 */
	switch (status) {
	case OE_GRPC_CANCELLED:
	case OE_GRPC_DEADLINE_EXCEEDED:
	case OE_GRPC_ABORTED:
	case OE_GRPC_OUT_OF_RANGE:
	case OE_GRPC_UNAVAILABLE:
	case OE_GRPC_DATA_LOSS:
		return (1);
	case OE_GRPC_RESOURCE_EXHAUSTED:
		return (retry_delay >= 0);
	default:
		return (0);
	}
}

/* grpc-message is percent-encoded (RFC 3986 unreserved passes). */
static void
percent_decode(char *s)
{
	char *in, *out;
	int hi, lo;

	for (in = out = s; *in != '\0'; in++) {
		if (in[0] == '%' && in[1] != '\0' && in[2] != '\0') {
			hi = in[1] <= '9' ? in[1] - '0' : (in[1] | 0x20) - 'a' +
			    10;
			lo = in[2] <= '9' ? in[2] - '0' : (in[2] | 0x20) - 'a' +
			    10;
			if (hi >= 0 && hi < 16 && lo >= 0 && lo < 16) {
				*out++ = (char)(hi << 4 | lo);
				in += 2;
				continue;
			}
		}
		*out++ = *in;
	}
	*out = '\0';
}

/* The response message: the first length-prefixed frame of the body. */
static void
take_message(struct gcall *g, struct oe_grpc_result *r)
{
	const unsigned char *p;
	size_t len;

	if (g->body.len == 0)
		return;
	p = (const unsigned char *)g->body.data;
	if (g->body_overflow || g->body.len < 5) {
		snprintf(r->errmsg, sizeof(r->errmsg), "malformed response "
		    "message");
		return;
	}
	len = (size_t)p[1] << 24 | (size_t)p[2] << 16 | (size_t)p[3] << 8 |
	    p[4];
	if (len > g->body.len - 5 || p[0] > 1 || (p[0] == 1 &&
	    strcasecmp(g->grpc_encoding, "gzip") != 0)) {
		snprintf(r->errmsg, sizeof(r->errmsg), "malformed response "
		    "message");
		return;
	}
	if (p[0] == 1) {
		r->body = oe_gunzip(p + 5, len, GRPC_MAX_RESPONSE,
		    &r->body_len);
		if (r->body == NULL)
			snprintf(r->errmsg, sizeof(r->errmsg), "response "
			    "message does not decompress");
		return;
	}
	/* Never NULL for a decoded message, even an empty one. */
	if ((r->body = malloc(len + 1)) == NULL)
		return;
	memcpy(r->body, p + 5, len);
	r->body_len = len;
}

static void
finish(struct gcall *g, struct oe_grpc_result *r)
{
	struct oe_rpc_status st;
	unsigned char details[GRPC_MAX_DETAILS];
	size_t dlen;

	r->transport = 0;
	if (g->http_status != 0 && g->http_status != 200) {
		r->status = status_from_http(g->http_status);
		snprintf(r->message, sizeof(r->message), "HTTP status %d",
		    g->http_status);
		return;
	}
	if (g->http_status == 200 && strncasecmp(g->content_type,
	    "application/grpc", 16) != 0) {
		r->status = OE_GRPC_UNKNOWN;
		snprintf(r->message, sizeof(r->message), "unexpected "
		    "content-type \"%s\"", g->content_type);
		return;
	}
	if (!g->have_status) {
		r->status = g->close_error != NGHTTP2_NO_ERROR ?
		    status_from_reset(g->close_error) : OE_GRPC_INTERNAL;
		snprintf(r->message, sizeof(r->message), "%s",
		    g->close_error != NGHTTP2_NO_ERROR ?
		    nghttp2_http2_strerror(g->close_error) :
		    "no grpc-status in the response");
		return;
	}
	r->status = g->grpc_status;
	snprintf(r->message, sizeof(r->message), "%s", g->grpc_message);
	percent_decode(r->message);
	if (g->details_len > 0 && oe_base64_decode(g->details,
	    g->details_len, details, &dlen) == 0 &&
	    oe_rpc_status_parse(details, dlen, &st) == 0)
		r->retry_delay = st.retry_delay;
	take_message(g, r);
}

/* ---------------------------------------------------------------- */
/* The call								*/

#define	NV(n, v, vl) {							\
	.name = (uint8_t *)__DECONST(char *, (n)),			\
	.value = (uint8_t *)__DECONST(char *, (v)),			\
	.namelen = strlen(n), .valuelen = (vl),				\
	.flags = NGHTTP2_NV_FLAG_NONE }

/* Metadata a caller may not set: HTTP/2 and gRPC framing headers. */
static int
reserved_header(const char *name)
{
	static const char *const names[] = { "host", "connection", "te",
	    "content-type", "content-length", "transfer-encoding",
	    "keep-alive", "upgrade", "proxy-connection", "user-agent",
	    "grpc-timeout", "grpc-encoding", "grpc-accept-encoding" };
	size_t i;

	if (name[0] == ':')
		return (1);
	for (i = 0; i < nitems(names); i++)
		if (strcasecmp(name, names[i]) == 0)
			return (1);
	return (0);
}

int
oe_grpc_unary(const struct oe_grpc_call *call, struct oe_grpc_result *r)
{
	nghttp2_session_callbacks *cbs;
	nghttp2_session *session;
	nghttp2_settings_entry iv[1];
	nghttp2_data_provider2 dp;
	nghttp2_nv *nva;
	struct gconn conn;
	struct gcall g;
	unsigned char *frame, *gz;
	const unsigned char *payload;
	char authority[300], timeout[24], **lower, buf[GRPC_READ_CHUNK];
	size_t i, nnv, paylen;
	ssize_t n;
	int64_t ns;
	int rv;

	memset(r, 0, sizeof(*r));
	r->transport = -1;
	r->retry_delay = -1;
	memset(&g, 0, sizeof(g));
	memset(&conn, 0, sizeof(conn));
	conn.fd = -1;
	oe_buf_init(&g.body);
	g.conn = &conn;
	session = NULL;
	cbs = NULL;
	frame = gz = NULL;
	nva = NULL;
	lower = NULL;
	clock_gettime(CLOCK_MONOTONIC, &conn.deadline);
	ns = conn.deadline.tv_nsec + (int64_t)(call->timeout_ms % 1000) *
	    1000000;
	conn.deadline.tv_sec += call->timeout_ms / 1000 + ns / 1000000000;
	conn.deadline.tv_nsec = (long)(ns % 1000000000);

	/* Length-prefixed message, compressed when asked. */
	payload = call->msg;
	paylen = call->len;
	if (call->gzip) {
		if ((gz = oe_gzip(call->msg, call->len, &paylen)) == NULL)
			goto nomem;
		payload = gz;
	}
	if ((frame = malloc(paylen + 5)) == NULL)
		goto nomem;
	frame[0] = call->gzip ? 1 : 0;
	frame[1] = (unsigned char)(paylen >> 24);
	frame[2] = (unsigned char)(paylen >> 16);
	frame[3] = (unsigned char)(paylen >> 8);
	frame[4] = (unsigned char)paylen;
	memcpy(frame + 5, payload, paylen);
	g.req = frame;
	g.req_len = paylen + 5;

	snprintf(authority, sizeof(authority), "%s%s%s:%d",
	    strchr(call->url->host, ':') != NULL ? "[" : "", call->url->host,
	    strchr(call->url->host, ':') != NULL ? "]" : "", call->url->port);
	snprintf(timeout, sizeof(timeout), "%dm", call->timeout_ms);
	if ((nva = calloc(call->nheaders + 10, sizeof(*nva))) == NULL ||
	    (lower = calloc(call->nheaders + 1, sizeof(*lower))) == NULL)
		goto nomem;
	nnv = 0;
	nva[nnv++] = (nghttp2_nv)NV(":method", "POST", 4);
	nva[nnv++] = (nghttp2_nv)NV(":scheme", call->url->tls ? "https" :
	    "http", call->url->tls ? 5 : 4);
	nva[nnv++] = (nghttp2_nv)NV(":path", call->method,
	    strlen(call->method));
	nva[nnv++] = (nghttp2_nv)NV(":authority", authority,
	    strlen(authority));
	nva[nnv++] = (nghttp2_nv)NV("content-type", "application/grpc", 16);
	nva[nnv++] = (nghttp2_nv)NV("te", "trailers", 8);
	nva[nnv++] = (nghttp2_nv)NV("user-agent", call->user_agent,
	    strlen(call->user_agent));
	nva[nnv++] = (nghttp2_nv)NV("grpc-timeout", timeout, strlen(timeout));
	nva[nnv++] = (nghttp2_nv)NV("grpc-accept-encoding", "gzip,identity",
	    13);
	if (call->gzip)
		nva[nnv++] = (nghttp2_nv)NV("grpc-encoding", "gzip", 4);
	for (i = 0; i < call->nheaders; i++) {
		/* HTTP/2 field names are lowercase. */
		if (reserved_header(call->headers[i].name))
			continue;
		if ((lower[i] = strdup(call->headers[i].name)) == NULL)
			goto nomem;
		for (n = 0; lower[i][n] != '\0'; n++)
			if (lower[i][n] >= 'A' && lower[i][n] <= 'Z')
				lower[i][n] |= 0x20;
		nva[nnv++] = (nghttp2_nv)NV(lower[i], call->headers[i].value,
		    strlen(call->headers[i].value));
	}

	if (gconn_open(&conn, call->url, r->errmsg, sizeof(r->errmsg)) != 0)
		goto out;

	if (nghttp2_session_callbacks_new(&cbs) != 0)
		goto nomem;
	nghttp2_session_callbacks_set_send_callback2(cbs, send_cb);
	nghttp2_session_callbacks_set_on_header_callback(cbs, header_cb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, data_cb);
	nghttp2_session_callbacks_set_on_stream_close_callback(cbs, close_cb);
	if (nghttp2_session_client_new3(&session, cbs, &g, NULL,
	    &ng_mem) != 0)
		goto nomem;
	iv[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
	iv[0].value = 0;
	dp.source.ptr = NULL;
	dp.read_callback = read_body_cb;
	if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1) != 0 ||
	    (g.stream_id = nghttp2_submit_request2(session, NULL, nva, nnv,
	    &dp, NULL)) < 0)
		goto nomem;

	while (!g.closed) {
		if ((rv = nghttp2_session_send(session)) != 0) {
			snprintf(r->errmsg, sizeof(r->errmsg), "send to %s:%d "
			    "failed", call->url->host, call->url->port);
			goto out;
		}
		if (!nghttp2_session_want_read(session))
			break;
		if ((conn.ssl == NULL || SSL_pending(conn.ssl) == 0) &&
		    gconn_wait(&conn, POLLIN) != 0) {
			snprintf(r->errmsg, sizeof(r->errmsg), "no response "
			    "from %s:%d within %d ms", call->url->host,
			    call->url->port, call->timeout_ms);
			goto out;
		}
		n = conn.ssl != NULL ? SSL_read(conn.ssl, buf, sizeof(buf)) :
		    read(conn.fd, buf, sizeof(buf));
		if (n <= 0) {
			snprintf(r->errmsg, sizeof(r->errmsg), "connection to "
			    "%s:%d lost", call->url->host, call->url->port);
			goto out;
		}
		if (nghttp2_session_mem_recv2(session, (const uint8_t *)buf,
		    (size_t)n) < 0) {
			snprintf(r->errmsg, sizeof(r->errmsg),
			    "HTTP/2 protocol error from %s:%d",
			    call->url->host, call->url->port);
			goto out;
		}
	}
	if (!g.closed) {
		/* The server ended the session (GOAWAY) without a reply. */
		snprintf(r->errmsg, sizeof(r->errmsg), "%s:%d closed the "
		    "session", call->url->host, call->url->port);
		goto out;
	}
	finish(&g, r);
	goto out;

nomem:
	snprintf(r->errmsg, sizeof(r->errmsg), "out of memory");
out:
	if (session != NULL)
		nghttp2_session_del(session);
	if (cbs != NULL)
		nghttp2_session_callbacks_del(cbs);
	gconn_close(&conn);
	if (lower != NULL)
		for (i = 0; i < call->nheaders; i++)
			free(lower[i]);
	free(lower);
	free(nva);
	free(frame);
	free(gz);
	oe_buf_free(&g.body);
	return (r->transport);
}

void
oe_grpc_result_free(struct oe_grpc_result *r)
{

	free(r->body);
	r->body = NULL;
	r->body_len = 0;
}
