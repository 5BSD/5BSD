/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Test helpers for libotelexport: a loopback OTLP/HTTP collector
 * (plain or TLS) that records decoded requests and answers from a
 * script, and an allocation-failure injector driven through the
 * linker's --wrap of malloc, calloc, realloc, strdup and strndup.
 */

#ifndef _OTEL_TESTUTIL_H_
#define	_OTEL_TESTUTIL_H_

#include <pthread.h>
#include <stddef.h>

#define	COLL_MAX_REQ	64
#define	COLL_MAX_SCRIPT	16

/* What the collector does with one request. */
struct coll_reply {
	int		 status;	/* 0: close without answering */
	const char	*headers;	/* extra header lines, CRLF-ended */
	const char	*body;
	int		 garbage;	/* answer with a non-HTTP line */
	int		 no_header_end;	/* answer without CRLFCRLF */
	int		 hangup;	/* close at once, reading nothing */
	size_t		 bigbody;	/* pad the body to this many bytes */
};

struct coll_req {
	char		 path[256];
	char		*headers;	/* raw header block */
	char		*body;		/* gunzipped if gzip-encoded */
	size_t		 bodylen;
	int		 gzipped;
};

struct collector {
	int		 lfd;
	int		 port;
	int		 tls;
	void		*ssl_ctx;
	pthread_t	 thread;
	volatile int	 stop;
	pthread_mutex_t	 lock;
	struct coll_reply script[COLL_MAX_SCRIPT];
	int		 nscript, next;
	struct coll_req	 reqs[COLL_MAX_REQ];
	int		 nreqs;
};

/*
 * Start on 127.0.0.1 (port 0 = any).  With tls, a self-signed
 * certificate for "localhost" is generated and its PEM written to
 * certfile so the client can trust it through SSL_CERT_FILE.
 */
int	 coll_start(struct collector *, int port, int tls,
	    const char *certfile);
void	 coll_script(struct collector *, const struct coll_reply *, int);
void	 coll_stop(struct collector *);
int	 coll_nreqs(struct collector *);
/* Wait (up to ms) until at least n requests arrived. */
int	 coll_wait(struct collector *, int n, int ms);
/* A loopback port with nothing listening on it. */
int	 closed_port(void);

/* Fail the nth (1-based) wrapped allocation from now on; 0 disarms. */
void	 failalloc_arm(int nth);
int	 failalloc_hit(void);	/* did the armed failure fire? */

#endif /* !_OTEL_TESTUTIL_H_ */
