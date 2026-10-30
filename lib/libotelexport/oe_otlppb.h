/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface of the OTLP protobuf transports: OTLP/HTTP with
 * binary protobuf bodies (http/protobuf) and OTLP/gRPC (grpc).
 *
 * The exporter (oe_otlp.c) batches and spools OTLP JSON requests built
 * by the shared encoder (oe_otlpenc.c) for every protocol.  For the
 * protobuf protocols, oe_otlppb_post() transcodes each request to the
 * binary Export*ServiceRequest (oe_otlppb.c, through upb reflection over
 * the opentelemetry-proto definitions generated at build time) and sends
 * it with retries (oe_otlppost.c), over HTTP/1.1 (oe_http.c) or HTTP/2
 * (oe_grpc.c, nghttp2).  The spool format is the same OTLP JSON for every
 * protocol, so a spool written under one protocol replays under another.
 */

#ifndef _OE_OTLPPB_H_
#define	_OE_OTLPPB_H_

#include <stdint.h>

enum oe_signal;
struct oe_attr;
struct oe_url;

/* OTEL_EXPORTER_OTLP_PROTOCOL values. */
enum oe_otlp_protocol {
	OE_PROTO_HTTP_JSON,
	OE_PROTO_HTTP_PROTOBUF,
	OE_PROTO_GRPC
};

/* "grpc", "http/protobuf" or "http/json"; -1 for anything else. */
int	 oe_otlp_protocol_parse(const char *);
const char *oe_otlp_protocol_name(enum oe_otlp_protocol);

/* ---------------------------------------------------------------- */
/* Transcoding (oe_otlppb.c)						*/

struct upb_DefPool;
struct upb_MessageDef;

struct oe_otlppb_defs {
	struct upb_DefPool	*pool;
	const struct upb_MessageDef *request[3];	/* by enum oe_signal */
	const struct upb_MessageDef *response[3];
};

int	 oe_otlppb_defs_init(struct oe_otlppb_defs *);
void	 oe_otlppb_defs_fini(struct oe_otlppb_defs *);

/*
 * Transcode one OTLP JSON request (the OTLP/HTTP JSON encoding: proto3
 * JSON with hex trace and span ids) of the given signal to the binary
 * Export*ServiceRequest.  Returns 0 with a malloc'd buffer in *outp, or
 * -1 with a reason in err.
 */
int	 oe_otlppb_encode(const struct oe_otlppb_defs *, enum oe_signal,
	    const char *json, size_t len, char **outp, size_t *outlenp,
	    char *err, size_t errlen);

/*
 * Decode the partial_success of a binary Export*ServiceResponse.
 * Returns 0 with the rejected count (0 when absent) and error_message
 * (empty when absent), or -1 when the response does not decode.
 */
int	 oe_otlppb_partial(const struct oe_otlppb_defs *, enum oe_signal,
	    const void *buf, size_t len, int64_t *rejected, char *msg,
	    size_t msglen);

/*
 * google.rpc.Status, as an OTLP/HTTP error body or gRPC
 * grpc-status-details-bin: the code, the message and, when a
 * google.rpc.RetryInfo detail is present, its retry delay in seconds
 * (otherwise -1).  Returns 0, or -1 when the bytes do not decode.
 */
struct oe_rpc_status {
	int32_t	 code;
	char	 message[256];
	double	 retry_delay;
};

int	 oe_rpc_status_parse(const void *, size_t, struct oe_rpc_status *);

/*
 * Base64 (standard or URL-safe alphabet, padding optional) into out,
 * which has room for len bytes; 0, or -1 when malformed.
 */
int	 oe_base64_decode(const char *, size_t, unsigned char *out,
	    size_t *outlen);

/* ---------------------------------------------------------------- */
/* gRPC unary client (oe_grpc.c)					*/

/* gRPC status codes used by the retry policy. */
#define	OE_GRPC_OK			0
#define	OE_GRPC_CANCELLED		1
#define	OE_GRPC_UNKNOWN			2
#define	OE_GRPC_INVALID_ARGUMENT	3
#define	OE_GRPC_DEADLINE_EXCEEDED	4
#define	OE_GRPC_PERMISSION_DENIED	7
#define	OE_GRPC_RESOURCE_EXHAUSTED	8
#define	OE_GRPC_ABORTED			10
#define	OE_GRPC_OUT_OF_RANGE		11
#define	OE_GRPC_UNIMPLEMENTED		12
#define	OE_GRPC_INTERNAL		13
#define	OE_GRPC_UNAVAILABLE		14
#define	OE_GRPC_DATA_LOSS		15
#define	OE_GRPC_UNAUTHENTICATED		16

struct oe_grpc_call {
	const struct oe_url	*url;
	const char	*method;	/* "/package.Service/Method" */
	const struct oe_attr *headers;	/* extra metadata */
	size_t		 nheaders;
	const char	*user_agent;
	const void	*msg;		/* serialized request message */
	size_t		 len;
	int		 gzip;		/* gzip the message (grpc-encoding) */
	int		 timeout_ms;	/* whole call; grpc-timeout */
};

struct oe_grpc_result {
	/*
	 * 0: a gRPC status was determined (status, message), including
	 * one mapped from the HTTP status or a stream reset; -1: transport
	 * failure before any (errmsg).
	 */
	int		 transport;
	int		 status;
	char		 message[256];	/* grpc-message, percent-decoded */
	double		 retry_delay;	/* RetryInfo seconds, or -1 */
	void		*body;		/* response message (malloc'd) */
	size_t		 body_len;
	char		 errmsg[256];
};

int	 oe_grpc_unary(const struct oe_grpc_call *, struct oe_grpc_result *);
void	 oe_grpc_result_free(struct oe_grpc_result *);
/* The OTLP retry policy for a gRPC status. */
int	 oe_grpc_retryable(int status, double retry_delay);

/* ---------------------------------------------------------------- */
/* Sending with retries (oe_otlppost.c)					*/

struct oe_otlppb;

/* The outcome of oe_otlppb_post(), as the exporter's post_result. */
#define	OE_OTLPPB_OK		0	/* accepted */
#define	OE_OTLPPB_REJECTED	1	/* not retryable: drop */
#define	OE_OTLPPB_FAILED	2	/* transport or retries exhausted */

/*
 * The transport for an OTEL_EXPORTER_OTLP_PROTOCOL value (NULL is
 * http/json, kept for library callers that predate the setting):
 * *pbp is NULL for http/json, which the exporter sends itself.  The
 * URL, headers and user agent are borrowed.  Returns 0, or -1 with a
 * message on stderr for an unknown protocol or allocation failure.
 */
int	 oe_otlppb_open(const char *protocol, const struct oe_url *,
	    const struct oe_attr *headers, size_t nheaders,
	    const char *user_agent, int timeout_ms, int max_retries, int gzip,
	    struct oe_otlppb **pbp);
int	 oe_otlppb_post(struct oe_otlppb *, enum oe_signal, const char *json,
	    size_t len);
void	 oe_otlppb_free(struct oe_otlppb *);

/* gzip (RFC 1952) of a buffer and its inverse, malloc'd; NULL on error. */
void	*oe_gzip(const void *, size_t, size_t *);
void	*oe_gunzip(const void *, size_t, size_t limit, size_t *);

#endif /* !_OE_OTLPPB_H_ */
