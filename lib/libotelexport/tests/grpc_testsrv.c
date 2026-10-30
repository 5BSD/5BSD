/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Loopback OTLP/gRPC test server; see grpc_testsrv.h.  It allocates
 * with the __real_ allocators so the tests' allocation-failure
 * injection never hits the server side.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <zlib.h>

#include <nghttp2/nghttp2.h>

#include "grpc_testsrv.h"
#include "otel_testutil.h"

void	*__real_malloc(size_t);
void	*__real_realloc(void *, size_t);
char	*__real_strdup(const char *);

struct sconn {
	struct gsrv	*s;
	int		 fd;
	SSL		*ssl;
	nghttp2_session	*ses;
	int32_t		 sid;
	char		 path[256];
	char		*hdrs;
	size_t		 hlen;
	unsigned char	*body;
	size_t		 blen;
	/* Response message frame being sent. */
	unsigned char	*resp;
	size_t		 rlen, roff;
	struct gsrv_reply rep;
	int		 closing;
	int		 close_after_send;
};

static void
append(unsigned char **buf, size_t *len, const void *p, size_t n)
{

	*buf = __real_realloc(*buf, *len + n + 1);
	memcpy(*buf + *len, p, n);
	*len += n;
	(*buf)[*len] = '\0';
}

static void
swrite(struct sconn *c, const void *p, size_t n)
{
	const char *b = p;
	ssize_t w;

	while (n > 0) {
		w = c->ssl != NULL ? SSL_write(c->ssl, b, (int)n) :
		    write(c->fd, b, n);
		if (w <= 0)
			return;
		b += w;
		n -= (size_t)w;
	}
}

static unsigned char *
zip(const unsigned char *in, size_t len, size_t *outlen, int inflating)
{
	z_stream zs;
	unsigned char *out;
	size_t cap;
	int rc;

	memset(&zs, 0, sizeof(zs));
	if ((inflating ? inflateInit2(&zs, 16 + MAX_WBITS) :
	    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
	    16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY)) != Z_OK)
		return (NULL);
	cap = len * 8 + 1024;
	out = __real_malloc(cap);
	zs.next_in = (unsigned char *)(uintptr_t)in;
	zs.avail_in = (uInt)len;
	zs.next_out = out;
	zs.avail_out = (uInt)cap;
	rc = inflating ? inflate(&zs, Z_FINISH) : deflate(&zs, Z_FINISH);
	*outlen = zs.total_out;
	if (inflating)
		inflateEnd(&zs);
	else
		deflateEnd(&zs);
	if (rc != Z_STREAM_END) {
		free(out);
		return (NULL);
	}
	return (out);
}

static nghttp2_ssize
send_cb(nghttp2_session *ses __unused, const uint8_t *data, size_t len,
    int flags __unused, void *arg)
{

	swrite(arg, data, len);
	return ((nghttp2_ssize)len);
}

static int
header_cb(nghttp2_session *ses __unused, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value,
    size_t valuelen, uint8_t flags __unused, void *arg)
{
	struct sconn *c = arg;

	c->sid = frame->hd.stream_id;
	if (namelen == 5 && memcmp(name, ":path", 5) == 0)
		snprintf(c->path, sizeof(c->path), "%.*s", (int)valuelen,
		    (const char *)value);
	append((unsigned char **)&c->hdrs, &c->hlen, name, namelen);
	append((unsigned char **)&c->hdrs, &c->hlen, ": ", 2);
	append((unsigned char **)&c->hdrs, &c->hlen, value, valuelen);
	append((unsigned char **)&c->hdrs, &c->hlen, "\n", 1);
	return (0);
}

static int
data_cb(nghttp2_session *ses __unused, uint8_t flags __unused,
    int32_t sid __unused, const uint8_t *data, size_t len, void *arg)
{
	struct sconn *c = arg;

	append(&c->body, &c->blen, data, len);
	return (0);
}

static void
add_nv(nghttp2_nv *nv, size_t *n, const char *name, const char *value,
    size_t vlen)
{

	nv[*n].name = (uint8_t *)(uintptr_t)name;
	nv[*n].namelen = strlen(name);
	nv[*n].value = (uint8_t *)(uintptr_t)value;
	nv[*n].valuelen = vlen;
	nv[*n].flags = NGHTTP2_NV_FLAG_NONE;
	(*n)++;
}

/* grpc-status, grpc-message and grpc-status-details-bin. */
static size_t
status_nv(struct sconn *c, nghttp2_nv *nv, size_t n, char *num, char *b64)
{
	static const char tab[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const unsigned char *d = c->rep.details;
	size_t i, o;
	unsigned v;

	/* Decoys as long as the fields the client looks for. */
	add_nv(nv, &n, "x-decoy-abc", "1", 1);
	add_nv(nv, &n, "x-decoy-abcd", "1", 1);
	add_nv(nv, &n, "x-decoy-abcde", "1", 1);
	add_nv(nv, &n, "x-decoy-0123456789abcde", "1", 1);
	snprintf(num, 16, "%d", c->rep.status);
	add_nv(nv, &n, "grpc-status", num, strlen(num));
	if (c->rep.message != NULL)
		add_nv(nv, &n, "grpc-message", c->rep.message,
		    strlen(c->rep.message));
	if (c->rep.details_raw != NULL)
		add_nv(nv, &n, "grpc-status-details-bin", c->rep.details_raw,
		    strlen(c->rep.details_raw));
	else if (c->rep.details_len > 0) {
		/* Unpadded base64, as gRPC sends binary metadata. */
		for (i = o = 0; i < c->rep.details_len; i += 3) {
			v = (unsigned)d[i] << 16;
			if (i + 1 < c->rep.details_len)
				v |= (unsigned)d[i + 1] << 8;
			if (i + 2 < c->rep.details_len)
				v |= d[i + 2];
			b64[o++] = tab[v >> 18 & 63];
			b64[o++] = tab[v >> 12 & 63];
			if (i + 1 < c->rep.details_len)
				b64[o++] = tab[v >> 6 & 63];
			if (i + 2 < c->rep.details_len)
				b64[o++] = tab[v & 63];
		}
		add_nv(nv, &n, "grpc-status-details-bin", b64, o);
	}
	return (n);
}

static char trailer_num[16], trailer_b64[16384];

static nghttp2_ssize
resp_read_cb(nghttp2_session *ses, int32_t sid, uint8_t *buf, size_t len,
    uint32_t *flags, nghttp2_data_source *src __unused, void *arg)
{
	struct sconn *c = arg;
	nghttp2_nv nv[12];
	size_t n;

	n = MIN(len, c->rlen - c->roff);
	memcpy(buf, c->resp + c->roff, n);
	c->roff += n;
	if (c->roff == c->rlen) {
		*flags |= NGHTTP2_DATA_FLAG_EOF;
		if (c->rep.mode != GSRV_NO_STATUS) {
			*flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
			nghttp2_submit_trailer(ses, sid, nv, status_nv(c, nv, 0,
			    trailer_num, trailer_b64));
		}
	}
	return ((nghttp2_ssize)n);
}

static void
record(struct sconn *c)
{
	struct gsrv *s = c->s;
	struct gsrv_req *rq;
	size_t len;

	pthread_mutex_lock(&s->lock);
	if (s->next < s->nscript)
		c->rep = s->script[s->next++];
	else {
		memset(&c->rep, 0, sizeof(c->rep));
		c->rep.mode = GSRV_NORMAL;
	}
	if (s->nreqs >= GSRV_MAX_REQ)
		s->nlost++;
	if (s->nreqs < GSRV_MAX_REQ) {
		rq = &s->reqs[s->nreqs++];
		memset(rq, 0, sizeof(*rq));
		snprintf(rq->path, sizeof(rq->path), "%s", c->path);
		rq->headers = __real_strdup(c->hdrs != NULL ? c->hdrs : "");
		if (c->blen >= 5) {
			len = (size_t)c->body[1] << 24 | (size_t)c->body[2] <<
			    16 | (size_t)c->body[3] << 8 | c->body[4];
			rq->compressed = c->body[0];
			if (len > c->blen - 5)
				len = c->blen - 5;
			if (rq->compressed)
				rq->msg = (char *)zip(c->body + 5, len,
				    &rq->msglen, 1);
			else {
				rq->msg = __real_malloc(len + 1);
				memcpy(rq->msg, c->body + 5, len);
				rq->msglen = len;
			}
		}
	}
	pthread_mutex_unlock(&s->lock);
}

static void
respond(struct sconn *c)
{
	static char num[16], b64[16384];
	nghttp2_nv nv[16];
	nghttp2_data_provider2 dp;
	unsigned char *msg;
	size_t n, mlen;

	record(c);
	if (c->rep.delay_ms > 0)
		usleep((useconds_t)c->rep.delay_ms * 1000);
	n = 0;
	switch (c->rep.mode) {
	case GSRV_CLOSE:
		c->closing = 1;
		return;
	case GSRV_GARBAGE:
		swrite(c, "HTTP/1.1 400 Bad\r\n\r\n", 20);
		c->closing = 1;
		return;
	case GSRV_GOAWAY:
		nghttp2_submit_goaway(c->ses, NGHTTP2_FLAG_NONE, 0,
		    NGHTTP2_NO_ERROR, NULL, 0);
		c->close_after_send = 1;
		return;
	case GSRV_RST:
		nghttp2_submit_rst_stream(c->ses, NGHTTP2_FLAG_NONE, c->sid,
		    c->rep.rst_code);
		return;
	case GSRV_HTTP_STATUS:
		snprintf(num, sizeof(num), "%d", c->rep.status);
		add_nv(nv, &n, ":status", num, strlen(num));
		nghttp2_submit_response2(c->ses, c->sid, nv, n, NULL);
		return;
	case GSRV_TRAILERS_ONLY:
		add_nv(nv, &n, ":status", "200", 3);
		add_nv(nv, &n, "content-type", "application/grpc", 16);
		n = status_nv(c, nv, n, num, b64);
		nghttp2_submit_response2(c->ses, c->sid, nv, n, NULL);
		return;
	default:
		break;
	}
	add_nv(nv, &n, ":status", "200", 3);
	if (c->rep.mode == GSRV_BAD_CT)
		add_nv(nv, &n, "content-type", "text/plain", 10);
	else
		add_nv(nv, &n, "content-type", "application/grpc+proto", 22);
	if (c->rep.gzip)
		add_nv(nv, &n, "grpc-encoding", "gzip", 4);
	if (c->rep.mode == GSRV_CLOSE_HEADERS) {
		nghttp2_submit_headers(c->ses, NGHTTP2_FLAG_NONE, c->sid, NULL,
		    nv, n, NULL);
		c->close_after_send = 1;
		return;
	}
	if (c->rep.body == NULL && !c->rep.bad_frame) {
		/* Headers, then the trailers: no message at all. */
		if (c->rep.mode != GSRV_NO_STATUS)
			nghttp2_submit_headers(c->ses, NGHTTP2_FLAG_NONE,
			    c->sid, NULL, nv, n, NULL);
		if (c->rep.mode == GSRV_NO_STATUS)
			nghttp2_submit_response2(c->ses, c->sid, nv, n, NULL);
		else {
			n = status_nv(c, nv, 0, num, b64);
			nghttp2_submit_trailer(c->ses, c->sid, nv, n);
		}
		return;
	}
	msg = (unsigned char *)(uintptr_t)c->rep.body;
	mlen = c->rep.body_len;
	if (c->rep.gzip)
		msg = zip(c->rep.body, c->rep.body_len, &mlen, 0);
	c->resp = __real_malloc(mlen + 5);
	c->resp[0] = c->rep.gzip || c->rep.bad_flag ? 1 : 0;
	n = c->rep.bad_frame ? mlen + 100 : mlen;
	c->resp[1] = (unsigned char)(n >> 24);
	c->resp[2] = (unsigned char)(n >> 16);
	c->resp[3] = (unsigned char)(n >> 8);
	c->resp[4] = (unsigned char)n;
	if (mlen > 0)
		memcpy(c->resp + 5, msg, mlen);
	c->rlen = mlen + 5;
	c->roff = 0;
	if (msg != c->rep.body)
		free(msg);
	dp.source.ptr = NULL;
	dp.read_callback = resp_read_cb;
	n = 0;
	add_nv(nv, &n, ":status", "200", 3);
	add_nv(nv, &n, "x-decoy", "1", 1);
	if (c->rep.mode == GSRV_BAD_CT)
		add_nv(nv, &n, "content-type", "text/plain", 10);
	else
		add_nv(nv, &n, "content-type", "application/grpc+proto", 22);
	if (c->rep.gzip)
		add_nv(nv, &n, "grpc-encoding", "gzip", 4);
	if (c->rep.raw) {
		/* The body bytes as they are, no message frame. */
		memcpy(c->resp, c->rep.body, c->rep.body_len);
		c->rlen = c->rep.body_len;
	}
	nghttp2_submit_response2(c->ses, c->sid, nv, n, &dp);
}

static int
frame_cb(nghttp2_session *ses __unused, const nghttp2_frame *frame,
    void *arg)
{

	if ((frame->hd.type == NGHTTP2_DATA ||
	    frame->hd.type == NGHTTP2_HEADERS) &&
	    (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0)
		respond(arg);
	return (0);
}

static int
select_alpn(SSL *ssl __unused, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
	struct gsrv *s = arg;
	unsigned int i;

	if (s->alpn == NULL)
		return (SSL_TLSEXT_ERR_NOACK);
	for (i = 0; i < inlen; i += 1 + in[i])
		if (in[i] == strlen(s->alpn) &&
		    memcmp(in + i + 1, s->alpn, in[i]) == 0) {
			*out = in + i + 1;
			*outlen = in[i];
			return (SSL_TLSEXT_ERR_OK);
		}
	return (SSL_TLSEXT_ERR_NOACK);
}

static void
serve(struct gsrv *s, int fd)
{
	nghttp2_session_callbacks *cbs;
	struct sconn c;
	struct pollfd pfd;
	unsigned char buf[16384];
	ssize_t n;

	memset(&c, 0, sizeof(c));
	c.s = s;
	c.fd = fd;
	if (s->tls) {
		c.ssl = SSL_new(s->ssl_ctx);
		SSL_set_fd(c.ssl, fd);
		if (SSL_accept(c.ssl) != 1) {
			SSL_free(c.ssl);
			return;
		}
	}
	nghttp2_session_callbacks_new(&cbs);
	nghttp2_session_callbacks_set_send_callback2(cbs, send_cb);
	nghttp2_session_callbacks_set_on_header_callback(cbs, header_cb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
	    data_cb);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frame_cb);
	nghttp2_session_server_new(&c.ses, cbs, &c);
	nghttp2_session_callbacks_del(cbs);
	nghttp2_submit_settings(c.ses, NGHTTP2_FLAG_NONE, NULL, 0);
	while (!c.closing && !s->stop) {
		if (nghttp2_session_send(c.ses) != 0)
			break;
		if (c.close_after_send ||
		    (!nghttp2_session_want_read(c.ses) &&
		    !nghttp2_session_want_write(c.ses)))
			break;
		if (c.ssl == NULL || SSL_pending(c.ssl) == 0) {
			pfd.fd = fd;
			pfd.events = POLLIN;
			if (poll(&pfd, 1, 100) != 1)
				continue;
		}
		n = c.ssl != NULL ? SSL_read(c.ssl, buf, sizeof(buf)) :
		    read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		if (nghttp2_session_mem_recv2(c.ses, buf, (size_t)n) < 0)
			break;
	}
	nghttp2_session_del(c.ses);
	if (c.ssl != NULL) {
		if (!c.closing)
			SSL_shutdown(c.ssl);
		SSL_free(c.ssl);
	}
	free(c.hdrs);
	free(c.body);
	free(c.resp);
}

static void *
gsrv_main(void *arg)
{
	struct gsrv *s = arg;
	struct pollfd pfd;
	int fd, one = 1;

	while (!s->stop) {
		pfd.fd = s->lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) != 1)
			continue;
		if ((fd = accept(s->lfd, NULL, NULL)) < 0)
			continue;
		/* A client that hangs up must not kill the test. */
		(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
		    sizeof(one));
		serve(s, fd);
		close(fd);
	}
	return (NULL);
}

int
gsrv_start(struct gsrv *s, int tls, const char *certfile, const char *alpn)
{
	struct sockaddr_in sin;
	socklen_t slen;
	int one = 1;

	memset(s, 0, sizeof(*s));
	pthread_mutex_init(&s->lock, NULL);
	s->tls = tls;
	s->alpn = alpn;
	if (tls) {
		s->ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (s->ssl_ctx == NULL || coll_make_cert(s->ssl_ctx,
		    certfile) != 0)
			return (-1);
		SSL_CTX_set_alpn_select_cb(s->ssl_ctx, select_alpn, s);
	}
	s->lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s->lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
	    listen(s->lfd, 16) != 0)
		return (-1);
	slen = sizeof(sin);
	getsockname(s->lfd, (struct sockaddr *)&sin, &slen);
	s->port = ntohs(sin.sin_port);
	return (pthread_create(&s->thread, NULL, gsrv_main, s) == 0 ? 0 : -1);
}

void
gsrv_script(struct gsrv *s, const struct gsrv_reply *r, int n)
{

	pthread_mutex_lock(&s->lock);
	memcpy(s->script, r, (size_t)n * sizeof(*r));
	s->nscript = n;
	s->next = 0;
	pthread_mutex_unlock(&s->lock);
}

int
gsrv_nreqs(struct gsrv *s)
{
	int n;

	pthread_mutex_lock(&s->lock);
	n = s->nreqs;
	pthread_mutex_unlock(&s->lock);
	return (n);
}

void
gsrv_stop(struct gsrv *s)
{
	int i;

	s->stop = 1;
	pthread_join(s->thread, NULL);
	close(s->lfd);
	for (i = 0; i < s->nreqs; i++) {
		free(s->reqs[i].headers);
		free(s->reqs[i].msg);
	}
	if (s->ssl_ctx != NULL)
		SSL_CTX_free(s->ssl_ctx);
	pthread_mutex_destroy(&s->lock);
}
