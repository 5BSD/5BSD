/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Test helpers for libotelexport; see otel_testutil.h.
 */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <zlib.h>

#include "otel_testutil.h"

/* ---------------------------------------------------------------- */
/* Allocation failure injection (-Wl,--wrap=...)		 	*/

void	*__real_malloc(size_t);
void	*__real_calloc(size_t, size_t);
void	*__real_realloc(void *, size_t);
char	*__real_strdup(const char *);
char	*__real_strndup(const char *, size_t);
void	*__wrap_malloc(size_t);
void	*__wrap_calloc(size_t, size_t);
void	*__wrap_realloc(void *, size_t);
char	*__wrap_strdup(const char *);
char	*__wrap_strndup(const char *, size_t);

static int fail_countdown;	/* 0: disarmed */
static int fail_fired;
static pthread_mutex_t fail_lock = PTHREAD_MUTEX_INITIALIZER;

void
failalloc_arm(int nth)
{

	pthread_mutex_lock(&fail_lock);
	fail_countdown = nth;
	fail_fired = 0;
	pthread_mutex_unlock(&fail_lock);
}

int
failalloc_hit(void)
{

	return (fail_fired);
}

static int
should_fail(void)
{
	int fail = 0;

	pthread_mutex_lock(&fail_lock);
	if (fail_countdown > 0 && --fail_countdown == 0) {
		fail = 1;
		fail_fired = 1;
	}
	pthread_mutex_unlock(&fail_lock);
	return (fail);
}

void *
__wrap_malloc(size_t n)
{

	return (should_fail() ? NULL : __real_malloc(n));
}

void *
__wrap_calloc(size_t n, size_t sz)
{

	return (should_fail() ? NULL : __real_calloc(n, sz));
}

void *
__wrap_realloc(void *p, size_t n)
{

	return (should_fail() ? NULL : __real_realloc(p, n));
}

char *
__wrap_strdup(const char *s)
{

	return (should_fail() ? NULL : __real_strdup(s));
}

char *
__wrap_strndup(const char *s, size_t n)
{

	return (should_fail() ? NULL : __real_strndup(s, n));
}

/* ---------------------------------------------------------------- */
/* Loopback collector						 	*/

static int
make_cert(SSL_CTX *ctx, const char *certfile)
{
	EVP_PKEY *key;
	X509 *x;
	X509_NAME *name;
	X509_EXTENSION *ext;
	FILE *fp;
	int ok = 0;

	key = EVP_RSA_gen(2048);
	x = X509_new();
	if (key == NULL || x == NULL)
		goto out;
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), -3600);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, key);
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	    (const unsigned char *)"localhost", -1, -1, 0);
	X509_set_issuer_name(x, name);
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
	    "DNS:localhost");
	X509_add_ext(x, ext, -1);
	X509_EXTENSION_free(ext);
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
	    "critical,CA:TRUE");
	X509_add_ext(x, ext, -1);
	X509_EXTENSION_free(ext);
	if (X509_sign(x, key, EVP_sha256()) == 0)
		goto out;
	if (SSL_CTX_use_certificate(ctx, x) != 1 ||
	    SSL_CTX_use_PrivateKey(ctx, key) != 1)
		goto out;
	fp = fopen(certfile, "w");
	if (fp == NULL)
		goto out;
	PEM_write_X509(fp, x);
	fclose(fp);
	ok = 1;
out:
	X509_free(x);
	EVP_PKEY_free(key);
	return (ok ? 0 : -1);
}

struct cconn {
	int	 fd;
	SSL	*ssl;
};

static ssize_t
c_read(struct cconn *c, void *buf, size_t len)
{

	if (c->ssl != NULL)
		return (SSL_read(c->ssl, buf, (int)len));
	return (read(c->fd, buf, len));
}

static void
c_write(struct cconn *c, const void *buf, size_t len)
{

	if (c->ssl != NULL)
		(void)SSL_write(c->ssl, buf, (int)len);
	else
		(void)write(c->fd, buf, len);
}

static char *
gunzip(const char *in, size_t inlen, size_t *outlen)
{
	z_stream zs;
	char *out;
	size_t cap;
	int rc;

	cap = inlen * 8 + 1024;
	out = __real_malloc(cap);
	memset(&zs, 0, sizeof(zs));
	if (out == NULL || inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
		free(out);
		return (NULL);
	}
	zs.next_in = (unsigned char *)(uintptr_t)in;
	zs.avail_in = (uInt)inlen;
	for (;;) {
		zs.next_out = (unsigned char *)out + zs.total_out;
		zs.avail_out = (uInt)(cap - zs.total_out - 1);
		rc = inflate(&zs, Z_NO_FLUSH);
		if (rc == Z_STREAM_END)
			break;
		if (rc != Z_OK) {
			inflateEnd(&zs);
			free(out);
			return (NULL);
		}
		cap *= 2;
		out = __real_realloc(out, cap);
	}
	*outlen = zs.total_out;
	out[*outlen] = '\0';
	inflateEnd(&zs);
	return (out);
}

static void
serve_one(struct collector *co, int fd)
{
	struct cconn c;
	struct coll_reply rep;
	struct coll_req *rq;
	char *buf, *hdrend, *cl, resp[1024];
	size_t cap, len, need, hlen;
	ssize_t n;

	memset(&c, 0, sizeof(c));
	c.fd = fd;
	pthread_mutex_lock(&co->lock);
	if (co->next < co->nscript && co->script[co->next].hangup) {
		/* Reset the connection before reading the request. */
		struct linger l = { 1, 0 };

		co->next++;
		pthread_mutex_unlock(&co->lock);
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
		return;
	}
	pthread_mutex_unlock(&co->lock);
	if (co->tls) {
		c.ssl = SSL_new(co->ssl_ctx);
		SSL_set_fd(c.ssl, fd);
		if (SSL_accept(c.ssl) != 1) {
			SSL_free(c.ssl);
			return;
		}
	}
	cap = 1 << 20;
	buf = __real_malloc(cap);
	len = 0;
	hdrend = NULL;
	need = 0;
	for (;;) {
		n = c_read(&c, buf + len, cap - len - 1);
		if (n <= 0)
			break;
		len += (size_t)n;
		buf[len] = '\0';
		if (hdrend == NULL && (hdrend = strstr(buf, "\r\n\r\n")) !=
		    NULL) {
			hlen = (size_t)(hdrend - buf) + 4;
			cl = strcasestr(buf, "Content-Length:");
			need = hlen + (cl != NULL ? strtoul(cl + 15, NULL,
			    10) : 0);
			if (need + 1 > cap) {
				cap = need + 1;
				buf = __real_realloc(buf, cap);
				hdrend = buf + hlen - 4;
			}
		}
		if (hdrend != NULL && len >= need)
			break;
	}
	pthread_mutex_lock(&co->lock);
	if (co->next < co->nscript)
		rep = co->script[co->next++];
	else {
		memset(&rep, 0, sizeof(rep));
		rep.status = 200;
		rep.body = "{}";
	}
	if (hdrend != NULL && co->nreqs < COLL_MAX_REQ) {
		rq = &co->reqs[co->nreqs++];
		memset(rq, 0, sizeof(*rq));
		sscanf(buf, "POST %255s", rq->path);
		hlen = (size_t)(hdrend - buf);
		rq->headers = __real_strndup(buf, hlen);
		rq->gzipped = strcasestr(rq->headers,
		    "Content-Encoding: gzip") != NULL;
		if (rq->gzipped)
			rq->body = gunzip(hdrend + 4, len - hlen - 4,
			    &rq->bodylen);
		else {
			rq->bodylen = len - hlen - 4;
			rq->body = __real_strndup(hdrend + 4, rq->bodylen);
		}
	}
	pthread_mutex_unlock(&co->lock);
	if (rep.garbage)
		c_write(&c, "SMTP ready\r\n\r\n", 14);
	else if (rep.no_header_end) {
		snprintf(resp, sizeof(resp), "HTTP/1.1 %d OK\r\n",
		    rep.status);
		c_write(&c, resp, strlen(resp));
	} else if (rep.status != 0) {
		snprintf(resp, sizeof(resp), "HTTP/1.1 %d X\r\n"
		    "Content-Length: %zu\r\n%s\r\n%s", rep.status,
		    rep.bigbody > 0 ? rep.bigbody :
		    rep.body != NULL ? strlen(rep.body) : 0,
		    rep.headers != NULL ? rep.headers : "",
		    rep.body != NULL ? rep.body : "");
		c_write(&c, resp, strlen(resp));
		if (rep.bigbody > 0) {
			char *pad = __real_calloc(1, rep.bigbody);

			memset(pad, ' ', rep.bigbody);
			c_write(&c, pad, rep.bigbody);
			free(pad);
		}
	}
	free(buf);
	if (c.ssl != NULL) {
		SSL_shutdown(c.ssl);
		SSL_free(c.ssl);
	}
}

static void *
coll_main(void *arg)
{
	struct collector *co = arg;
	struct pollfd pfd;
	int fd;

	while (!co->stop) {
		pfd.fd = co->lfd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 50) != 1)
			continue;
		fd = accept(co->lfd, NULL, NULL);
		if (fd < 0)
			continue;
		serve_one(co, fd);
		close(fd);
	}
	return (NULL);
}

int
coll_start(struct collector *co, int port, int tls, const char *certfile)
{
	struct sockaddr_in sin;
	socklen_t slen;
	int one = 1;

	memset(co, 0, sizeof(*co));
	pthread_mutex_init(&co->lock, NULL);
	co->tls = tls;
	if (tls) {
		co->ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (co->ssl_ctx == NULL || make_cert(co->ssl_ctx,
		    certfile) != 0)
			return (-1);
	}
	co->lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(co->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_port = htons((uint16_t)port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(co->lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 ||
	    listen(co->lfd, 16) != 0)
		return (-1);
	slen = sizeof(sin);
	getsockname(co->lfd, (struct sockaddr *)&sin, &slen);
	co->port = ntohs(sin.sin_port);
	return (pthread_create(&co->thread, NULL, coll_main, co) == 0 ? 0 :
	    -1);
}

void
coll_script(struct collector *co, const struct coll_reply *r, int n)
{

	pthread_mutex_lock(&co->lock);
	memcpy(co->script, r, (size_t)n * sizeof(*r));
	co->nscript = n;
	co->next = 0;
	pthread_mutex_unlock(&co->lock);
}

int
coll_nreqs(struct collector *co)
{
	int n;

	pthread_mutex_lock(&co->lock);
	n = co->nreqs;
	pthread_mutex_unlock(&co->lock);
	return (n);
}

int
coll_wait(struct collector *co, int n, int ms)
{
	struct timespec ts = { 0, 10 * 1000000 };

	for (; ms > 0; ms -= 10) {
		if (coll_nreqs(co) >= n)
			return (0);
		nanosleep(&ts, NULL);
	}
	return (coll_nreqs(co) >= n ? 0 : -1);
}

void
coll_stop(struct collector *co)
{
	int i;

	co->stop = 1;
	pthread_join(co->thread, NULL);
	close(co->lfd);
	for (i = 0; i < co->nreqs; i++) {
		free(co->reqs[i].headers);
		free(co->reqs[i].body);
	}
	if (co->ssl_ctx != NULL)
		SSL_CTX_free(co->ssl_ctx);
	pthread_mutex_destroy(&co->lock);
}

int
closed_port(void)
{
	struct sockaddr_in sin;
	socklen_t slen;
	int fd, port;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	slen = sizeof(sin);
	getsockname(fd, (struct sockaddr *)&sin, &slen);
	port = ntohs(sin.sin_port);
	close(fd);
	return (port);
}
