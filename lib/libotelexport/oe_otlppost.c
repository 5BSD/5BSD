/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Sending OTLP requests over the protobuf transports, with the retry
 * policy of the OTLP specification:
 *
 *  http/protobuf  POST <endpoint>/v1/<signal>, Content-Type
 *                 application/x-protobuf; 2xx is success (the body is an
 *                 Export*ServiceResponse whose partial_success is
 *                 reported), 429/502/503/504 are retried honoring
 *                 Retry-After, other statuses are final (the body is a
 *                 google.rpc.Status whose message is reported).
 *  grpc           the Export method of the signal's collector service
 *                 (oe_grpc.c); OK is success with partial_success,
 *                 CANCELLED, DEADLINE_EXCEEDED, ABORTED, OUT_OF_RANGE,
 *                 UNAVAILABLE and DATA_LOSS are retried, and
 *                 RESOURCE_EXHAUSTED only with a RetryInfo, whose delay
 *                 is honored; other statuses are final.
 *
 * Transport failures are retried.  Retries back off exponentially with
 * jitter, as the JSON transport does (oe_otlp.c).
 */

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zlib.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"

struct oe_otlppb_config {
	enum oe_otlp_protocol	 protocol;
	const struct oe_url	*url;
	int			 exact;	/* post to the URL's own path */
	const struct oe_attr	*headers;
	size_t			 nheaders;
	const char		*user_agent;
	int			 timeout_ms;
	int			 max_retries;
	int			 gzip;
};

struct oe_otlppb {
	struct oe_otlppb_config	 cfg;
	struct oe_otlppb_defs	 defs;
};

/* The Export method of each signal's collector service. */
static const char *const grpc_methods[] = {
	"/opentelemetry.proto.collector.logs.v1.LogsService/Export",
	"/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
	"/opentelemetry.proto.collector.trace.v1.TraceService/Export",
	("/opentelemetry.proto.collector.profiles.v1development."
	    "ProfilesService/Export"),
};
_Static_assert(nitems(grpc_methods) == OE_NSIGNALS,
    "a gRPC method per signal");

/*
 * zlib allocates through the library's allocator, like everything else
 * here (and so the tests' allocation-failure sweeps reach it).
 */
static voidpf
gz_alloc(voidpf opaque __unused, uInt n, uInt size)
{

	return (calloc(n, size));
}

static void
gz_free(voidpf opaque __unused, voidpf p)
{

	free(p);
}

void *
oe_gzip(const void *data, size_t len, size_t *outlenp)
{
	z_stream zs;
	unsigned char *out;
	uLong bound;

	memset(&zs, 0, sizeof(zs));
	zs.zalloc = gz_alloc;
	zs.zfree = gz_free;
	if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
	    15 + 16 /* gzip wrapper */, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		return (NULL);
	/* deflateBound() covers the gzip wrapper set above. */
	bound = deflateBound(&zs, len);
	if ((out = malloc(bound)) == NULL) {
		deflateEnd(&zs);
		return (NULL);
	}
	zs.next_in = __DECONST(unsigned char *, data);
	zs.avail_in = len;
	zs.next_out = out;
	zs.avail_out = bound;
	/*
	 * With deflateBound() bytes of output, deflate(Z_FINISH) completes
	 * in one call (zlib.h), and it allocates nothing after init.
	 */
	(void)deflate(&zs, Z_FINISH);
	*outlenp = zs.total_out;
	deflateEnd(&zs);
	return (out);
}

void *
oe_gunzip(const void *data, size_t len, size_t limit, size_t *outlenp)
{
	z_stream zs;
	unsigned char *out, *p;
	size_t cap;
	int rv;

	memset(&zs, 0, sizeof(zs));
	zs.zalloc = gz_alloc;
	zs.zfree = gz_free;
	if (inflateInit2(&zs, 15 + 16) != Z_OK)
		return (NULL);
	cap = len * 4 + 64;
	if (cap > limit)
		cap = limit;
	out = NULL;
	zs.next_in = __DECONST(unsigned char *, data);
	zs.avail_in = len;
	for (;;) {
		if ((p = realloc(out, cap + 1)) == NULL)
			break;
		out = p;
		zs.next_out = out + zs.total_out;
		zs.avail_out = cap - zs.total_out;
		rv = inflate(&zs, Z_FINISH);
		if (rv == Z_STREAM_END) {
			*outlenp = zs.total_out;
			inflateEnd(&zs);
			return (out);
		}
		/*
		 * Out of room: grow up to the limit; anything else fails.
		 * With Z_FINISH an unfinished inflate() never returns Z_OK.
		 */
		if (rv != Z_BUF_ERROR || zs.avail_in == 0 || cap >= limit)
			break;
		cap = cap * 2 > limit ? limit : cap * 2;
	}
	inflateEnd(&zs);
	free(out);
	return (NULL);
}

int
oe_otlppb_open(const char *protocol, const struct oe_url *url, int exact,
    const struct oe_attr *headers, size_t nheaders, const char *user_agent,
    int timeout_ms, int max_retries, int gzip, struct oe_otlppb **pbp)
{
	struct oe_otlppb *p;
	int proto;

	*pbp = NULL;
	proto = protocol == NULL ? OE_PROTO_HTTP_JSON :
	    oe_otlp_protocol_parse(protocol);
	if (proto < 0) {
		fprintf(stderr, "otlp: unknown protocol \"%s\" (expected "
		    "grpc, http/protobuf or http/json)\n", protocol);
		return (-1);
	}
	if (proto == OE_PROTO_HTTP_JSON)
		return (0);
	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    oe_otlppb_defs_init(&p->defs) != 0) {
		free(p);
		fprintf(stderr, "otlp: out of memory\n");
		return (-1);
	}
	p->cfg.protocol = (enum oe_otlp_protocol)proto;
	p->cfg.url = url;
	p->cfg.exact = exact;
	p->cfg.headers = headers;
	p->cfg.nheaders = nheaders;
	p->cfg.user_agent = user_agent;
	p->cfg.timeout_ms = timeout_ms;
	p->cfg.max_retries = max_retries;
	p->cfg.gzip = gzip;
	*pbp = p;
	return (0);
}

void
oe_otlppb_free(struct oe_otlppb *p)
{

	if (p == NULL)
		return;
	oe_otlppb_defs_fini(&p->defs);
	free(p);
}

static void
sleep_seconds(double secs)
{
	struct timespec ts;

	if (secs <= 0)
		return;
	ts.tv_sec = (time_t)secs;
	ts.tv_nsec = (long)((secs - (double)ts.tv_sec) * 1e9);
	nanosleep(&ts, NULL);
}

static void
backoff(int attempt, double server_delay)
{
	double ms;

	/* As oe_otlp.c: 100 ms doubling, with up to 50% jitter. */
	ms = 100.0 * (double)(1U << (attempt > 20 ? 20 : attempt - 1));
	ms += (double)arc4random_uniform((uint32_t)(ms * 0.5) + 1);
	sleep_seconds(ms / 1000.0);
	sleep_seconds(server_delay);
}

/*
 * The request path as messages show it, after a "/": the signal's
 * path, or a signal endpoint's own path without its leading slash.
 */
static const char *
shown_path(const struct oe_otlppb *p, enum oe_signal sig)
{

	return (p->cfg.exact ? p->cfg.url->rawpath + 1 : oe_enc_path(sig));
}

static void
report_partial(struct oe_otlppb *p, enum oe_signal sig, const void *body,
    size_t len)
{
	char msg[256];
	int64_t rejected;

	if (oe_otlppb_partial(&p->defs, sig, body, len, &rejected, msg,
	    sizeof(msg)) != 0) {
		fprintf(stderr, "otlp: /%s: malformed %s response (ignored)\n",
		    shown_path(p, sig), oe_otlp_protocol_name(p->cfg.protocol));
		return;
	}
	/* The specification asks to report a rejection or a warning. */
	if (rejected > 0 || msg[0] != '\0')
		fprintf(stderr, "otlp: /%s partial success: %jd records "
		    "rejected%s%s\n", shown_path(p, sig), (intmax_t)rejected,
		    msg[0] != '\0' ? ": " : "", msg);
}

static int
http_status_retryable(int status)
{

	return (status == 429 || status == 502 || status == 503 ||
	    status == 504);
}

/* One http/protobuf attempt; *delay is the server's Retry-After or -1. */
static int
attempt_http(struct oe_otlppb *p, enum oe_signal sig, const void *payload,
    size_t paylen, int gzipped, int last, double *delay)
{
	struct oe_http_response resp;
	struct oe_rpc_status st;
	const char *path;

	path = shown_path(p, sig);
	*delay = -1;
	if (oe_http_post_type(p->cfg.url, p->cfg.exact ? NULL : path,
	    "application/x-protobuf",
	    p->cfg.headers, p->cfg.nheaders, p->cfg.user_agent, payload,
	    paylen, gzipped, p->cfg.timeout_ms, &resp) != 0) {
		if (last)
			fprintf(stderr, "otlp: POST /%s failed: %s (after %d "
			    "attempts)\n", path, resp.errmsg,
			    p->cfg.max_retries + 1);
		return (OE_OTLPPB_FAILED);
	}
	if (resp.status >= 200 && resp.status < 300) {
		/* The leading bytes suffice for a partial_success. */
		if (resp.body_len > 0)
			report_partial(p, sig, resp.body, resp.body_len);
		return (OE_OTLPPB_OK);
	}
	*delay = resp.retry_after;
	if (resp.body_len == 0 ||
	    oe_rpc_status_parse(resp.body, resp.body_len, &st) != 0)
		st.message[0] = '\0';
	if (!http_status_retryable(resp.status)) {
		fprintf(stderr, "otlp: POST /%s returned %d (non-retryable)"
		    "%s%s\n", path, resp.status, st.message[0] != '\0' ?
		    ": " : "", st.message);
		return (OE_OTLPPB_REJECTED);
	}
	if (last)
		fprintf(stderr, "otlp: POST /%s returned %d (after %d "
		    "attempts)%s%s\n", path, resp.status,
		    p->cfg.max_retries + 1, st.message[0] != '\0' ? ": " : "",
		    st.message);
	return (OE_OTLPPB_FAILED);
}

/* One grpc attempt. */
static int
attempt_grpc(struct oe_otlppb *p, enum oe_signal sig, const void *msg,
    size_t len, int last, double *delay)
{
	struct oe_grpc_call call;
	struct oe_grpc_result res;
	const char *m;
	int ret;

	m = grpc_methods[sig];
	*delay = -1;
	memset(&call, 0, sizeof(call));
	call.url = p->cfg.url;
	call.method = m;
	call.headers = p->cfg.headers;
	call.nheaders = p->cfg.nheaders;
	call.user_agent = p->cfg.user_agent;
	call.msg = msg;
	call.len = len;
	call.gzip = p->cfg.gzip;
	call.timeout_ms = p->cfg.timeout_ms;
	if (oe_grpc_unary(&call, &res) != 0) {
		if (last)
			fprintf(stderr, "otlp: gRPC %s failed: %s (after %d "
			    "attempts)\n", m, res.errmsg,
			    p->cfg.max_retries + 1);
		oe_grpc_result_free(&res);
		return (OE_OTLPPB_FAILED);
	}
	if (res.status == OE_GRPC_OK) {
		if (res.body != NULL)
			report_partial(p, sig, res.body, res.body_len);
		else if (res.errmsg[0] != '\0')
			fprintf(stderr, "otlp: gRPC %s: %s (ignored)\n", m,
			    res.errmsg);
		ret = OE_OTLPPB_OK;
	} else if (!oe_grpc_retryable(res.status, res.retry_delay)) {
		fprintf(stderr, "otlp: gRPC %s returned status %d "
		    "(non-retryable)%s%s\n", m, res.status,
		    res.message[0] != '\0' ? ": " : "", res.message);
		ret = OE_OTLPPB_REJECTED;
	} else {
		*delay = res.retry_delay;
		if (last)
			fprintf(stderr, "otlp: gRPC %s returned status %d "
			    "(after %d attempts)%s%s\n", m, res.status,
			    p->cfg.max_retries + 1, res.message[0] != '\0' ?
			    ": " : "", res.message);
		ret = OE_OTLPPB_FAILED;
	}
	oe_grpc_result_free(&res);
	return (ret);
}

int
oe_otlppb_post(struct oe_otlppb *p, enum oe_signal sig, const char *json,
    size_t len)
{
	char err[256], *pb;
	void *gz;
	const void *payload;
	size_t pblen, paylen;
	double delay;
	int attempt, gzipped, result;

	if (oe_otlppb_encode(&p->defs, sig, json, len, &pb, &pblen, err,
	    sizeof(err)) != 0) {
		/* Resending cannot make the request valid. */
		fprintf(stderr, "otlp: /%s batch dropped: %s\n",
		    shown_path(p, sig), err);
		return (OE_OTLPPB_REJECTED);
	}
	/* gRPC compresses per message (oe_grpc.c); HTTP per body. */
	gz = NULL;
	gzipped = 0;
	payload = pb;
	paylen = pblen;
	if (p->cfg.protocol == OE_PROTO_HTTP_PROTOBUF && p->cfg.gzip &&
	    (gz = oe_gzip(pb, pblen, &paylen)) != NULL) {
		payload = gz;
		gzipped = 1;
	} else
		paylen = pblen;

	result = OE_OTLPPB_FAILED;
	delay = -1;
	for (attempt = 0; attempt <= p->cfg.max_retries; attempt++) {
		if (attempt > 0)
			backoff(attempt, delay);
		if (p->cfg.protocol == OE_PROTO_GRPC)
			result = attempt_grpc(p, sig, pb, pblen,
			    attempt == p->cfg.max_retries, &delay);
		else
			result = attempt_http(p, sig, payload, paylen, gzipped,
			    attempt == p->cfg.max_retries, &delay);
		if (result != OE_OTLPPB_FAILED)
			break;
	}
	free(gz);
	free(pb);
	return (result);
}
