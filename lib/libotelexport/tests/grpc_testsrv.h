/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A loopback OTLP/gRPC server for the libotelexport tests: HTTP/2 by
 * nghttp2's server side, cleartext with prior knowledge or TLS with
 * ALPN, recording each call's metadata and (deframed, decompressed)
 * request message and answering from a script with every response
 * shape the gRPC protocol allows, and the broken ones a client must
 * survive.  Requests are recorded as bytes; their content is checked
 * with the independent C++ oracle (pbcpp/otlp_pb_oracle).
 */

#ifndef _GRPC_TESTSRV_H_
#define	_GRPC_TESTSRV_H_

#include <pthread.h>
#include <stddef.h>

#define	GSRV_MAX_REQ	64
#define	GSRV_MAX_SCRIPT	16

enum gsrv_mode {
	GSRV_NORMAL,		/* 200, message (if any), trailers */
	GSRV_TRAILERS_ONLY,	/* one HEADERS frame with grpc-status */
	GSRV_HTTP_STATUS,	/* a non-200 :status, no gRPC status */
	GSRV_BAD_CT,		/* 200 with content-type text/plain */
	GSRV_NO_STATUS,		/* 200, message, end without trailers */
	GSRV_RST,		/* RST_STREAM with rst_code */
	GSRV_GOAWAY,		/* GOAWAY refusing the stream, then close */
	GSRV_CLOSE,		/* close the connection without answering */
	GSRV_CLOSE_HEADERS,	/* send the response headers, then close */
	GSRV_GARBAGE		/* answer with bytes that are not HTTP/2 */
};

struct gsrv_reply {
	enum gsrv_mode	 mode;
	int		 status;	/* grpc-status, or :status for HTTP */
	const char	*message;	/* grpc-message as sent (encoded) */
	const void	*details;	/* grpc-status-details-bin bytes */
	size_t		 details_len;
	const void	*body;		/* response message bytes */
	size_t		 body_len;
	int		 gzip;		/* compress the response message */
	int		 bad_frame;	/* send a truncated message frame */
	int		 bad_flag;	/* compressed flag without encoding */
	unsigned	 rst_code;
	int		 delay_ms;	/* wait before answering */
	int		 raw;		/* send body without the frame prefix */
	const char	*details_raw;	/* grpc-status-details-bin verbatim */
};

struct gsrv_req {
	char		 path[256];
	char		*headers;	/* "name: value\n" lines */
	char		*msg;		/* deframed, decompressed */
	size_t		 msglen;
	int		 compressed;	/* the message frame flag */
};

struct gsrv {
	int		 lfd;
	int		 port;
	int		 tls;
	const char	*alpn;		/* protocol the server selects */
	void		*ssl_ctx;
	pthread_t	 thread;
	volatile int	 stop;
	pthread_mutex_t	 lock;
	struct gsrv_reply script[GSRV_MAX_SCRIPT];
	int		 nscript, next;
	struct gsrv_req	 reqs[GSRV_MAX_REQ];
	int		 nreqs;
};

/*
 * Start on 127.0.0.1.  With tls, a self-signed certificate for
 * "localhost" is written to certfile (trust it with SSL_CERT_FILE); alpn
 * is the protocol the server selects ("h2"; NULL selects none).
 */
int	 gsrv_start(struct gsrv *, int tls, const char *certfile,
	    const char *alpn);
void	 gsrv_script(struct gsrv *, const struct gsrv_reply *, int);
int	 gsrv_nreqs(struct gsrv *);
void	 gsrv_stop(struct gsrv *);

#endif /* !_GRPC_TESTSRV_H_ */
