/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Minimal HTTP/1.1 POST client for the OTLP exporter.  One request
 * per connection (Connection: close), http and https (via OpenSSL),
 * connect/read timeouts, status code + Retry-After extraction, and
 * a bounded response body for partial-success checking.
 */

#include <sys/socket.h>
#include <sys/time.h>

#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "otelexport.h"
#include "oe_http.h"

#define	HTTP_MAX_BODY	65536

int
oe_url_parse(const char *url, struct oe_url *u)
{
	const char *p, *hoststart, *hostend, *pathstart;
	size_t len;

	memset(u, 0, sizeof(*u));
	if (strncasecmp(url, "http://", 7) == 0) {
		u->tls = 0;
		u->port = 80;
		hoststart = url + 7;
	} else if (strncasecmp(url, "https://", 8) == 0) {
		u->tls = 1;
		u->port = 443;
		hoststart = url + 8;
	} else
		return (-1);

	pathstart = strchr(hoststart, '/');
	hostend = pathstart != NULL ? pathstart : hoststart + strlen(hoststart);
	if (*hoststart == '[') {
		/*
		 * Bracketed IPv6 literal: the host is everything
		 * inside the brackets (colons and all); an optional
		 * :port follows the closing bracket.
		 */
		const char *close;

		hoststart++;
		close = memchr(hoststart, ']',
		    (size_t)(hostend - hoststart));
		if (close == NULL)
			return (-1);
		if (close + 1 < hostend) {
			if (close[1] != ':')
				return (-1);
			u->port = atoi(close + 2);
			if (u->port <= 0 || u->port > 65535)
				return (-1);
		}
		hostend = close;
	} else {
		/* Optional :port. */
		p = memchr(hoststart, ':', (size_t)(hostend - hoststart));
		if (p != NULL) {
			u->port = atoi(p + 1);
			if (u->port <= 0 || u->port > 65535)
				return (-1);
			hostend = p;
		}
	}
	len = (size_t)(hostend - hoststart);
	if (len == 0 || len >= sizeof(u->host))
		return (-1);
	memcpy(u->host, hoststart, len);
	u->host[len] = '\0';

	if (pathstart == NULL || pathstart[0] == '\0')
		strlcpy(u->basepath, "", sizeof(u->basepath));
	else {
		/* A truncated path would POST to the wrong URL. */
		if (strlcpy(u->basepath, pathstart,
		    sizeof(u->basepath)) >= sizeof(u->basepath))
			return (-1);
		/* Drop a trailing slash so path joining stays simple. */
		len = strlen(u->basepath);
		if (len > 0 && u->basepath[len - 1] == '/')
			u->basepath[len - 1] = '\0';
	}
	return (0);
}

static int
tcp_connect(const struct oe_url *u, int timeout_ms)
{
	struct addrinfo hints, *res, *ai;
	struct pollfd pfd;
	char portstr[8];
	int fd, error, flags;
	socklen_t elen;

	snprintf(portstr, sizeof(portstr), "%d", u->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(u->host, portstr, &hints, &res) != 0)
		return (-1);
	fd = -1;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		flags = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		if (errno == EINPROGRESS) {
			pfd.fd = fd;
			pfd.events = POLLOUT;
			if (poll(&pfd, 1, timeout_ms) == 1) {
				error = 0;
				elen = sizeof(error);
				if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
				    &error, &elen) == 0 && error == 0)
					break;
			}
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd >= 0)
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
	return (fd);
}

struct conn {
	int	 fd;
	SSL_CTX	*ctx;
	SSL	*ssl;
};

static ssize_t
conn_write(struct conn *c, const void *buf, size_t len)
{

	if (c->ssl != NULL)
		return (SSL_write(c->ssl, buf, (int)len));
	return (write(c->fd, buf, len));
}

static ssize_t
conn_read(struct conn *c, void *buf, size_t len)
{

	if (c->ssl != NULL)
		return (SSL_read(c->ssl, buf, (int)len));
	return (read(c->fd, buf, len));
}

static void
conn_close(struct conn *c)
{

	if (c->ssl != NULL) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}
	if (c->ctx != NULL)
		SSL_CTX_free(c->ctx);
	if (c->fd >= 0)
		close(c->fd);
}

static int
conn_open(struct conn *c, const struct oe_url *u, int timeout_ms,
    char *errbuf, size_t errlen)
{
	struct timeval tv;

	memset(c, 0, sizeof(*c));
	c->fd = tcp_connect(u, timeout_ms);
	if (c->fd < 0) {
		snprintf(errbuf, errlen, "connect to %s:%d failed",
		    u->host, u->port);
		return (-1);
	}
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (!u->tls)
		return (0);

	c->ctx = SSL_CTX_new(TLS_client_method());
	if (c->ctx == NULL)
		goto tlsfail;
	SSL_CTX_set_default_verify_paths(c->ctx);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	c->ssl = SSL_new(c->ctx);
	if (c->ssl == NULL)
		goto tlsfail;
	SSL_set_fd(c->ssl, c->fd);
	SSL_set_tlsext_host_name(c->ssl, __DECONST(char *, u->host));
	SSL_set1_host(c->ssl, u->host);
	if (SSL_connect(c->ssl) != 1)
		goto tlsfail;
	return (0);

tlsfail:
	{
		unsigned long ec = ERR_get_error();
		const char *reason = ERR_reason_error_string(ec);

		snprintf(errbuf, errlen, "TLS handshake with %s failed: %s",
		    u->host, reason != NULL ? reason : "unknown error");
	}
	conn_close(c);
	return (-1);
}

/*
 * POST "body" to <base URL>/<path>.  Returns 0 with resp filled in
 * when an HTTP response was received (any status), -1 on transport
 * error (connect/TLS/send/receive) with a message in resp->errmsg.
 */
int
oe_http_post(const struct oe_url *u, const char *path,
    const struct oe_attr *headers, size_t nheaders,
    const char *user_agent, const void *body, size_t bodylen,
    int gzipped, int timeout_ms, struct oe_http_response *resp)
{
	struct conn c;
	struct oe_buf req, in;
	char chunk[4096], *hdrend, *line, *next;
	ssize_t n;
	size_t i, off;
	int ret;

	memset(resp, 0, sizeof(*resp));
	resp->status = -1;
	resp->retry_after = -1.0;

	if (conn_open(&c, u, timeout_ms, resp->errmsg,
	    sizeof(resp->errmsg)) != 0)
		return (-1);

	oe_buf_init(&req);
	oe_buf_appendf(&req, "POST %s/%s HTTP/1.1\r\n", u->basepath, path);
	oe_buf_appendf(&req, "Host: %s:%d\r\n", u->host, u->port);
	oe_buf_appendf(&req, "User-Agent: %s\r\n", user_agent);
	oe_buf_appendstr(&req, "Content-Type: application/json\r\n");
	if (gzipped)
		oe_buf_appendstr(&req, "Content-Encoding: gzip\r\n");
	for (i = 0; i < nheaders; i++)
		oe_buf_appendf(&req, "%s: %s\r\n", headers[i].name,
		    headers[i].value);
	oe_buf_appendf(&req, "Content-Length: %zu\r\n", bodylen);
	oe_buf_appendstr(&req, "Connection: close\r\n\r\n");
	if (req.error) {
		snprintf(resp->errmsg, sizeof(resp->errmsg), "out of memory");
		oe_buf_free(&req);
		conn_close(&c);
		return (-1);
	}

	ret = -1;
	off = 0;
	while (off < req.len) {
		n = conn_write(&c, req.data + off, req.len - off);
		if (n <= 0) {
			snprintf(resp->errmsg, sizeof(resp->errmsg),
			    "send to %s:%d failed", u->host, u->port);
			goto out_req;
		}
		off += (size_t)n;
	}
	off = 0;
	while (off < bodylen) {
		n = conn_write(&c, (const char *)body + off, bodylen - off);
		if (n <= 0) {
			snprintf(resp->errmsg, sizeof(resp->errmsg),
			    "send to %s:%d failed", u->host, u->port);
			goto out_req;
		}
		off += (size_t)n;
	}

	/* Read the whole response (bounded). */
	oe_buf_init(&in);
	while (in.len < HTTP_MAX_BODY) {
		n = conn_read(&c, chunk, sizeof(chunk));
		if (n <= 0)
			break;
		oe_buf_append(&in, chunk, (size_t)n);
	}
	if (in.len == 0 || in.data == NULL) {
		snprintf(resp->errmsg, sizeof(resp->errmsg),
		    "no response from %s:%d", u->host, u->port);
		oe_buf_free(&in);
		goto out_req;
	}

	if (sscanf(in.data, "HTTP/%*d.%*d %d", &resp->status) != 1) {
		snprintf(resp->errmsg, sizeof(resp->errmsg),
		    "malformed response from %s:%d", u->host, u->port);
		oe_buf_free(&in);
		goto out_req;
	}

	hdrend = strstr(in.data, "\r\n\r\n");
	if (hdrend != NULL) {
		*hdrend = '\0';
		/* Scan headers for Retry-After. */
		for (line = in.data; line != NULL; line = next) {
			next = strstr(line, "\r\n");
			if (next != NULL) {
				*next = '\0';
				next += 2;
			}
			if (strncasecmp(line, "Retry-After:", 12) == 0)
				resp->retry_after = strtod(line + 12, NULL);
		}
		/*
		 * Keep a copy of the body for partial-success checks.
		 * Ignores chunked framing markers; the check is a
		 * best-effort substring scan.
		 */
		strlcpy(resp->body, hdrend + 4, sizeof(resp->body));
	}
	ret = 0;

out_req:
	oe_buf_free(&req);
	if (ret == 0)
		oe_buf_free(&in);
	conn_close(&c);
	return (ret);
}
