/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal HTTP client interface shared by oe_otlp.c and oe_http.c.
 */

#ifndef _OE_HTTP_H_
#define	_OE_HTTP_H_

struct oe_url {
	int	 tls;
	int	 port;
	char	 host[256];
	char	 basepath[512];
};

struct oe_http_response {
	int	 status;	/* HTTP status, -1 on transport error */
	double	 retry_after;	/* seconds from Retry-After, -1 if absent */
	char	 body[4096];	/* leading response body bytes */
	char	 errmsg[256];	/* transport error description */
};

int	oe_url_parse(const char *, struct oe_url *);
int	oe_http_post(const struct oe_url *, const char *path,
	    const struct oe_attr *headers, size_t nheaders,
	    const char *user_agent, const void *body, size_t bodylen,
	    int gzipped, int timeout_ms, struct oe_http_response *);

#endif /* !_OE_HTTP_H_ */
