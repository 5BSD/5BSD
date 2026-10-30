/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests of the OTLP protobuf transports (oe_otlppb.c, oe_otlppost.c,
 * oe_grpc.c): the JSON to protobuf transcoder, the response and
 * google.rpc.Status decoders, gzip, the gRPC client against a loopback
 * HTTP/2 server with scripted faults (grpc_testsrv.c), OTLP/HTTP
 * protobuf against the loopback collector (otel_testutil.c), the
 * exporter end to end with retries and the spool, protocol resolution
 * across the configuration layers, and allocation failures.
 *
 * The protobuf the library produces is checked by the independent C++
 * oracle (pbcpp/otlp_pb_oracle, the C++ protobuf runtime), never by
 * decoding it with upb.  Expected response and Status messages are
 * encoded by hand here.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <pthread.h>

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlpenc.h"
#include "oe_otlppb.h"
#include "grpc_testsrv.h"
#include "otel_testutil.h"

/* ---------------------------------------------------------------- */
/* Helpers								*/

/* A hand-built protobuf message. */
struct pbw {
	unsigned char	 b[4096];
	size_t		 n;
};

static void
pb_varint(struct pbw *w, uint64_t v)
{

	do {
		w->b[w->n++] = (unsigned char)((v & 0x7f) | (v > 0x7f ? 0x80 :
		    0));
		v >>= 7;
	} while (v != 0);
}

static void
pb_key(struct pbw *w, unsigned num, unsigned type)
{

	pb_varint(w, (uint64_t)num << 3 | type);
}

static void
pb_bytes(struct pbw *w, unsigned num, const void *p, size_t len)
{

	pb_key(w, num, 2);
	pb_varint(w, len);
	memcpy(w->b + w->n, p, len);
	w->n += len;
}

static void
pb_uint(struct pbw *w, unsigned num, uint64_t v)
{

	pb_key(w, num, 0);
	pb_varint(w, v);
}

/* An Export*ServiceResponse with partial_success {rejected, msg}. */
static void
partial_response(struct pbw *w, int64_t rejected, const char *msg)
{
	struct pbw ps;

	memset(&ps, 0, sizeof(ps));
	w->n = 0;
	if (rejected != 0)
		pb_uint(&ps, 1, (uint64_t)rejected);
	if (msg != NULL)
		pb_bytes(&ps, 2, msg, strlen(msg));
	pb_bytes(w, 1, ps.b, ps.n);
}

/* google.rpc.Status {code, message, details: [RetryInfo]}. */
static void
rpc_status(struct pbw *w, int code, const char *msg, int64_t secs,
    int32_t nanos, int with_retry)
{
	static const char url[] =
	    "type.googleapis.com/google.rpc.RetryInfo";
	struct pbw dur, ri, any;

	memset(&dur, 0, sizeof(dur));
	memset(&ri, 0, sizeof(ri));
	memset(&any, 0, sizeof(any));
	w->n = 0;
	pb_uint(w, 1, (uint64_t)code);
	if (msg != NULL)
		pb_bytes(w, 2, msg, strlen(msg));
	if (with_retry) {
		pb_uint(&dur, 1, (uint64_t)secs);
		pb_uint(&dur, 2, (uint64_t)nanos);
		pb_bytes(&ri, 1, dur.b, dur.n);
		pb_bytes(&any, 1, url, sizeof(url) - 1);
		pb_bytes(&any, 2, ri.b, ri.n);
		pb_bytes(w, 3, any.b, any.n);
	}
}

static const char *
oracle(const atf_tc_t *tc)
{
	static char path[PATH_MAX];
	const char *srcdir = atf_tc_get_config_var(tc, "srcdir");

	snprintf(path, sizeof(path), "%s/otlp_pb_oracle", srcdir);
	if (access(path, X_OK) != 0)
		snprintf(path, sizeof(path), "%s/pbcpp/otlp_pb_oracle", srcdir);
	return (path);
}

static void
write_file(const char *path, const void *p, size_t len)
{
	FILE *fp;

	ATF_REQUIRE((fp = fopen(path, "w")) != NULL);
	ATF_REQUIRE_EQ(len, fwrite(p, 1, len, fp));
	ATF_REQUIRE_EQ(0, fclose(fp));
}

static char *
read_file(const char *path)
{
	struct stat st;
	char *buf;
	int fd;

	ATF_REQUIRE((fd = open(path, O_RDONLY)) >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &st));
	ATF_REQUIRE((buf = calloc(1, (size_t)st.st_size + 1)) != NULL);
	ATF_REQUIRE_EQ(st.st_size, read(fd, buf, (size_t)st.st_size));
	close(fd);
	return (buf);
}

/* Run the oracle; returns its exit status, its stdout in out. */
static int
run_oracle(const atf_tc_t *tc, const char *args, const char *out)
{
	char cmd[2048];
	int st;

	snprintf(cmd, sizeof(cmd), "%s %s > %s 2>&1", oracle(tc), args, out);
	st = system(cmd);
	return (WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

/* The oracle's proto3 JSON of a request message the server received. */
static char *
decode_request(const atf_tc_t *tc, const char *signal, const void *msg,
    size_t len)
{
	char args[256];

	write_file("got.pb", msg, len);
	snprintf(args, sizeof(args), "decode %s got.pb", signal);
	ATF_REQUIRE_EQ_MSG(0, run_oracle(tc, args, "got.json"), "%s",
	    read_file("got.json"));
	return (read_file("got.json"));
}

/* stderr into a file for the duration of a test step. */
static int saved_stderr = -1;

static void
capture_start(void)
{
	int fd;

	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	fd = open("stderr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

static char *
capture_end(void)
{
	char *s;

	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);
	s = read_file("stderr.txt");
	/* Show it in the test log too. */
	fprintf(stderr, "%s", s);
	return (s);
}

static void
url_of(struct oe_url *u, int tls, int port)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%s://%s:%d", tls ? "https" : "http",
	    tls ? "localhost" : "127.0.0.1", port);
	ATF_REQUIRE_EQ(0, oe_url_parse(buf, u));
}

/* ---------------------------------------------------------------- */
/* Small pieces								*/

ATF_TC_WITHOUT_HEAD(protocol_names);
ATF_TC_BODY(protocol_names, tc)
{

	ATF_CHECK_EQ(OE_PROTO_GRPC, oe_otlp_protocol_parse("grpc"));
	ATF_CHECK_EQ(OE_PROTO_HTTP_PROTOBUF,
	    oe_otlp_protocol_parse("http/protobuf"));
	ATF_CHECK_EQ(OE_PROTO_HTTP_JSON, oe_otlp_protocol_parse("http/json"));
	ATF_CHECK_EQ(-1, oe_otlp_protocol_parse("http"));
	ATF_CHECK_EQ(-1, oe_otlp_protocol_parse("GRPC"));
	ATF_CHECK_EQ(-1, oe_otlp_protocol_parse(NULL));
	ATF_CHECK_STREQ("grpc", oe_otlp_protocol_name(OE_PROTO_GRPC));
	ATF_CHECK_STREQ("http/protobuf",
	    oe_otlp_protocol_name(OE_PROTO_HTTP_PROTOBUF));
	ATF_CHECK_STREQ("http/json",
	    oe_otlp_protocol_name(OE_PROTO_HTTP_JSON));
}

ATF_TC_WITHOUT_HEAD(base64);
ATF_TC_BODY(base64, tc)
{
	unsigned char out[64];
	size_t n;

	ATF_REQUIRE_EQ(0, oe_base64_decode("aGVsbG8=", 8, out, &n));
	ATF_CHECK(n == 5 && memcmp(out, "hello", 5) == 0);
	ATF_REQUIRE_EQ(0, oe_base64_decode("aGVsbG8", 7, out, &n));
	ATF_CHECK(n == 5 && memcmp(out, "hello", 5) == 0);
	/* Standard and URL-safe alphabets: 0xfb 0xff 0xbf. */
	ATF_REQUIRE_EQ(0, oe_base64_decode("+/+/", 4, out, &n));
	ATF_CHECK(n == 3 && out[0] == 0xfb && out[1] == 0xff &&
	    out[2] == 0xbf);
	ATF_REQUIRE_EQ(0, oe_base64_decode("-_-_", 4, out, &n));
	ATF_CHECK(n == 3 && out[0] == 0xfb && out[1] == 0xff &&
	    out[2] == 0xbf);
	ATF_REQUIRE_EQ(0, oe_base64_decode("AZaz09", 6, out, &n));
	ATF_CHECK_EQ(4, n);
	ATF_REQUIRE_EQ(0, oe_base64_decode("", 0, out, &n));
	ATF_CHECK_EQ(0, n);
	ATF_CHECK_EQ(-1, oe_base64_decode("abcde", 5, out, &n));
	ATF_CHECK_EQ(-1, oe_base64_decode("ab*d", 4, out, &n));
}

ATF_TC_WITHOUT_HEAD(retryable);
ATF_TC_BODY(retryable, tc)
{
	int s;

	for (s = 0; s <= 16; s++) {
		switch (s) {
		case OE_GRPC_CANCELLED:
		case OE_GRPC_DEADLINE_EXCEEDED:
		case OE_GRPC_ABORTED:
		case OE_GRPC_OUT_OF_RANGE:
		case OE_GRPC_UNAVAILABLE:
		case OE_GRPC_DATA_LOSS:
			ATF_CHECK_MSG(oe_grpc_retryable(s, -1), "status %d",
			    s);
			break;
		case OE_GRPC_RESOURCE_EXHAUSTED:
			ATF_CHECK(!oe_grpc_retryable(s, -1));
			ATF_CHECK(oe_grpc_retryable(s, 0));
			ATF_CHECK(oe_grpc_retryable(s, 2.5));
			break;
		default:
			ATF_CHECK_MSG(!oe_grpc_retryable(s, 1), "status %d",
			    s);
		}
	}
}

ATF_TC_WITHOUT_HEAD(rpc_status);
ATF_TC_BODY(rpc_status, tc)
{
	struct oe_rpc_status st;
	struct pbw w, any;
	char big[400];
	static const unsigned char trunc_varint[] = { 0x08, 0x80 };
	static const unsigned char bad_type[] = { 0x0b };
	static const unsigned char field0[] = { 0x00, 0x01 };
	static const unsigned char long_len[] = { 0x12, 0x05, 'a' };
	static const unsigned char short_fixed64[] = { 0x09, 1, 2, 3 };
	static const unsigned char short_fixed32[] = { 0x0d, 1 };
	static const unsigned char huge_field[] = { 0x80, 0x80, 0x80, 0x80,
	    0x80, 0x01, 0x00 };
	static const unsigned char long_varint[] = { 0x08, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };

	rpc_status(&w, 14, "try later", 1, 500000000, 1);
	ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
	ATF_CHECK_EQ(14, st.code);
	ATF_CHECK_STREQ("try later", st.message);
	ATF_CHECK(st.retry_delay > 1.49 && st.retry_delay < 1.51);

	rpc_status(&w, 8, NULL, 0, 0, 0);
	ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
	ATF_CHECK_EQ(8, st.code);
	ATF_CHECK_STREQ("", st.message);
	ATF_CHECK_EQ(-1, st.retry_delay);

	/* Other details, unknown fields of every wire type are skipped. */
	memset(&any, 0, sizeof(any));
	pb_bytes(&any, 1, "type.googleapis.com/google.rpc.DebugInfo", 40);
	pb_bytes(&any, 2, "x", 1);
	pb_uint(&any, 9, 1);
	rpc_status(&w, 3, "bad", 0, 0, 0);
	pb_bytes(&w, 3, any.b, any.n);
	pb_key(&w, 7, 1);
	memcpy(w.b + w.n, "12345678", 8);
	w.n += 8;
	pb_key(&w, 8, 5);
	memcpy(w.b + w.n, "1234", 4);
	w.n += 4;
	pb_bytes(&w, 9, "zz", 2);
	pb_uint(&w, 2, 5);		/* message with the wrong type */
	ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
	ATF_CHECK_EQ(3, st.code);
	ATF_CHECK_STREQ("bad", st.message);
	ATF_CHECK_EQ(-1, st.retry_delay);

	/* RetryInfo: no delay, a delay of a wrong type, unknown fields. */
	{
		static const char url[] = "/google.rpc.RetryInfo";
		struct pbw ri, dur;

		memset(&any, 0, sizeof(any));
		pb_bytes(&any, 1, url, sizeof(url) - 1);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
		ATF_CHECK_EQ(0, st.retry_delay);

		memset(&ri, 0, sizeof(ri));
		memset(&dur, 0, sizeof(dur));
		pb_uint(&dur, 3, 9);
		pb_bytes(&dur, 1, "x", 1);
		pb_uint(&ri, 1, 7);
		pb_bytes(&ri, 2, "y", 1);
		pb_bytes(&ri, 1, dur.b, dur.n);
		pb_bytes(&any, 2, ri.b, ri.n);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
		ATF_CHECK_EQ(0, st.retry_delay);

		/* A negative delay, and a malformed RetryInfo. */
		rpc_status(&w, 8, NULL, -1, 0, 1);
		ATF_CHECK_EQ(-1, oe_rpc_status_parse(w.b, w.n, &st));
		memset(&any, 0, sizeof(any));
		pb_bytes(&any, 1, url, sizeof(url) - 1);
		pb_bytes(&any, 2, "\x0a\x05", 2);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_CHECK_EQ(-1, oe_rpc_status_parse(w.b, w.n, &st));
		memset(&any, 0, sizeof(any));
		pb_bytes(&any, 1, url, sizeof(url) - 1);
		pb_bytes(&any, 2, "\x0a\x02\x08\x80", 4);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_CHECK_EQ(-1, oe_rpc_status_parse(w.b, w.n, &st));
		/* A type URL shorter than the suffix. */
		memset(&any, 0, sizeof(any));
		pb_bytes(&any, 1, "Retry", 5);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_CHECK_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
		/* A malformed Any. */
		w.n = 0;
		pb_bytes(&w, 3, "\x0a\x09", 2);
		ATF_CHECK_EQ(-1, oe_rpc_status_parse(w.b, w.n, &st));
	}

	/* An over-long message is cut to the buffer. */
	memset(big, 'm', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	rpc_status(&w, 2, big, 0, 0, 0);
	ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
	ATF_CHECK_EQ(sizeof(st.message) - 1, strlen(st.message));

	ATF_CHECK_EQ(0, oe_rpc_status_parse("", 0, &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(trunc_varint,
	    sizeof(trunc_varint), &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(bad_type, sizeof(bad_type),
	    &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(field0, sizeof(field0), &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(long_len, sizeof(long_len),
	    &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(short_fixed64,
	    sizeof(short_fixed64), &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(short_fixed32,
	    sizeof(short_fixed32), &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(huge_field, sizeof(huge_field),
	    &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse(long_varint,
	    sizeof(long_varint), &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse("<html>", 6, &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse("\x80", 1, &st));
	ATF_CHECK_EQ(-1, oe_rpc_status_parse("\x12\x80", 2, &st));

	/* Known field numbers with other wire types are skipped. */
	w.n = 0;
	pb_bytes(&w, 1, "x", 1);
	pb_uint(&w, 3, 1);
	memset(&any, 0, sizeof(any));
	pb_uint(&any, 1, 1);
	pb_uint(&any, 2, 1);
	pb_bytes(&w, 3, any.b, any.n);
	ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
	ATF_CHECK_EQ(0, st.code);
	{
		static const char url[] = "/google.rpc.RetryInfo";
		struct pbw ri, dur;

		/* Duration.nanos of the wrong type; a negative nanos. */
		memset(&dur, 0, sizeof(dur));
		memset(&ri, 0, sizeof(ri));
		memset(&any, 0, sizeof(any));
		pb_uint(&dur, 1, 2);
		pb_bytes(&dur, 2, "x", 1);
		pb_bytes(&ri, 1, dur.b, dur.n);
		pb_bytes(&any, 1, url, sizeof(url) - 1);
		pb_bytes(&any, 2, ri.b, ri.n);
		w.n = 0;
		pb_bytes(&w, 3, any.b, any.n);
		ATF_REQUIRE_EQ(0, oe_rpc_status_parse(w.b, w.n, &st));
		ATF_CHECK_EQ(2, st.retry_delay);
		rpc_status(&w, 8, NULL, 1, -1, 1);
		ATF_CHECK_EQ(-1, oe_rpc_status_parse(w.b, w.n, &st));
	}
}

ATF_TC_WITHOUT_HEAD(partial_success);
ATF_TC_BODY(partial_success, tc)
{
	struct oe_otlppb_defs d;
	struct pbw w;
	char msg[64];
	int64_t rej;
	int sig;

	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));
	for (sig = OE_SIGNAL_LOGS; sig <= OE_SIGNAL_TRACES; sig++) {
		partial_response(&w, 3, "three dropped");
		ATF_REQUIRE_EQ(0, oe_otlppb_partial(&d, sig, w.b, w.n, &rej,
		    msg, sizeof(msg)));
		ATF_CHECK_EQ(3, rej);
		ATF_CHECK_STREQ("three dropped", msg);
		partial_response(&w, 0, "just a warning");
		ATF_REQUIRE_EQ(0, oe_otlppb_partial(&d, sig, w.b, w.n, &rej,
		    msg, sizeof(msg)));
		ATF_CHECK_EQ(0, rej);
		ATF_CHECK_STREQ("just a warning", msg);
		/* No partial_success: an empty response. */
		ATF_REQUIRE_EQ(0, oe_otlppb_partial(&d, sig, "", 0, &rej, msg,
		    sizeof(msg)));
		ATF_CHECK_EQ(0, rej);
		ATF_CHECK_STREQ("", msg);
		ATF_CHECK_EQ(-1, oe_otlppb_partial(&d, sig, "\x0a\x09", 2,
		    &rej, msg, sizeof(msg)));
	}
	oe_otlppb_defs_fini(&d);
}

ATF_TC_WITHOUT_HEAD(gzip);
ATF_TC_BODY(gzip, tc)
{
	char *in, *z, *out;
	size_t i, zlen, olen;

	ATF_REQUIRE((in = malloc(100000)) != NULL);
	for (i = 0; i < 100000; i++)
		in[i] = (char)(i % 7 == 0 ? 'a' + i % 26 : 'x');
	ATF_REQUIRE((z = oe_gzip(in, 100000, &zlen)) != NULL);
	ATF_CHECK(zlen < 100000);
	/* Growth from the initial guess up to the size. */
	ATF_REQUIRE((out = oe_gunzip(z, zlen, 1 << 20, &olen)) != NULL);
	ATF_CHECK(olen == 100000 && memcmp(in, out, olen) == 0);
	free(out);
	/* Exactly at the limit, and one byte under it. */
	ATF_REQUIRE((out = oe_gunzip(z, zlen, 100000, &olen)) != NULL);
	free(out);
	ATF_CHECK(oe_gunzip(z, zlen, 99999, &olen) == NULL);
	/* Corrupt and truncated input. */
	z[zlen / 2] ^= 0x55;
	z[zlen / 2 + 1] ^= 0x55;
	ATF_CHECK(oe_gunzip(z, zlen, 1 << 20, &olen) == NULL);
	ATF_CHECK(oe_gunzip(z, 10, 1 << 20, &olen) == NULL);
	ATF_CHECK(oe_gunzip("not gzip", 8, 1 << 20, &olen) == NULL);
	free(z);
	/* Empty input compresses and comes back empty. */
	ATF_REQUIRE((z = oe_gzip("", 0, &zlen)) != NULL);
	ATF_REQUIRE((out = oe_gunzip(z, zlen, 16, &olen)) != NULL);
	ATF_CHECK_EQ(0, olen);
	free(out);
	free(z);
	free(in);
}

/* ---------------------------------------------------------------- */
/* Transcoding								*/

#define	TID	"\"traceId\":\"5b8efff798038103d269b633813fc60c\""
#define	SID	"\"spanId\":\"eee19b7ec3c1b174\""

/* Valid requests, each compared with the oracle. */
static const struct {
	const char	*name;
	const char	*json;
} good[] = {
	{ "logs_all_fields",
	  "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"k\","
	  "\"value\":{\"stringValue\":\"v\"}}],\"droppedAttributesCount\":2},"
	  "\"schemaUrl\":\"https://s\",\"scopeLogs\":[{\"scope\":{\"name\":"
	  "\"n\",\"version\":\"1\",\"attributes\":[],"
	  "\"droppedAttributesCount\":0},\"schemaUrl\":\"u\",\"logRecords\":"
	  "[{\"timeUnixNano\":\"1700000000000000001\","
	  "\"observedTimeUnixNano\":1700000000000000002,"
	  "\"severityNumber\":\"SEVERITY_NUMBER_WARN\",\"severityText\":"
	  "\"WARN\",\"body\":{\"kvlistValue\":{\"values\":[{\"key\":\"a\","
	  "\"value\":{\"arrayValue\":{\"values\":[{\"intValue\":\"-5\"},"
	  "{\"intValue\":7},{\"doubleValue\":1.5},{\"doubleValue\":\"NaN\"},"
	  "{\"doubleValue\":\"Infinity\"},{\"doubleValue\":\"-Infinity\"},"
	  "{\"doubleValue\":\"2.25\"},{\"doubleValue\":3},"
	  "{\"boolValue\":true},{\"bytesValue\":\"aGVsbG8=\"},"
	  "{\"bytesValue\":\"-_8\"},{\"stringValue\":\"\\u00e9\\\"\\n\"},"
	  "{}]}}}]}},\"attributes\":[],\"droppedAttributesCount\":1,"
	  "\"flags\":1," TID "," SID ",\"eventName\":\"e\"}]}]}]}" },
	{ "logs_proto_names",
	  "{\"resource_logs\":[{\"scope_logs\":[{\"log_records\":[{"
	  "\"time_unix_nano\":\"5\",\"severity_number\":9,"
	  "\"trace_id\":\"\",\"span_id\":\"\",\"body\":null}]}]}]}" },
	{ "metrics_all_kinds",
	  "{\"resourceMetrics\":[{\"resource\":{},\"scopeMetrics\":[{"
	  "\"scope\":{\"name\":\"s\"},\"metrics\":["
	  "{\"name\":\"g\",\"description\":\"d\",\"unit\":\"1\",\"gauge\":"
	  "{\"dataPoints\":[{\"timeUnixNano\":\"3\",\"asDouble\":0.5,"
	  "\"attributes\":[{\"key\":\"x\",\"value\":{\"intValue\":\"1\"}}],"
	  "\"exemplars\":[{\"filteredAttributes\":[],\"timeUnixNano\":\"2\","
	  "\"asInt\":\"4\"," SID "," TID "}],\"flags\":1}]},\"metadata\":[]},"
	  "{\"name\":\"s\",\"sum\":{\"dataPoints\":[{\"startTimeUnixNano\":"
	  "\"1\",\"timeUnixNano\":\"2\",\"asInt\":\"-9223372036854775808\"}],"
	  "\"aggregationTemporality\":\"AGGREGATION_TEMPORALITY_DELTA\","
	  "\"isMonotonic\":false}},"
	  "{\"name\":\"h\",\"histogram\":{\"dataPoints\":[{\"count\":\"3\","
	  "\"sum\":6,\"bucketCounts\":[\"1\",2],\"explicitBounds\":[1.0],"
	  "\"min\":1,\"max\":4}],\"aggregationTemporality\":2}},"
	  "{\"name\":\"e\",\"exponentialHistogram\":{\"dataPoints\":[{"
	  "\"count\":\"5\",\"scale\":-2,\"zeroCount\":\"1\",\"positive\":{"
	  "\"offset\":-1,\"bucketCounts\":[\"1\",\"3\"]},\"negative\":{},"
	  "\"zeroThreshold\":1e-9}],\"aggregationTemporality\":1}},"
	  "{\"name\":\"q\",\"summary\":{\"dataPoints\":[{\"count\":\"2\","
	  "\"sum\":3.5,\"quantileValues\":[{\"quantile\":0.5,\"value\":1},"
	  "{\"quantile\":1,\"value\":2.5}]}]}}]}]}]}" },
	{ "traces_events_links",
	  "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{" TID "," SID
	  ",\"traceState\":\"a=b\",\"parentSpanId\":\"0102030405060708\","
	  "\"flags\":257,\"name\":\"op\",\"kind\":\"SPAN_KIND_SERVER\","
	  "\"startTimeUnixNano\":\"1\",\"endTimeUnixNano\":\"2\","
	  "\"attributes\":[],\"droppedAttributesCount\":0,\"events\":[{"
	  "\"timeUnixNano\":\"1\",\"name\":\"ev\",\"attributes\":[{\"key\":"
	  "\"b\",\"value\":{\"boolValue\":false}}]}],\"droppedEventsCount\":3,"
	  "\"links\":[{" TID ",\"spanId\":\"EEE19B7EC3C1B174\",\"traceState\":"
	  "\"\",\"attributes\":[],\"flags\":1}],\"droppedLinksCount\":4,"
	  "\"status\":{\"message\":\"m\",\"code\":\"STATUS_CODE_ERROR\"}}]}]}]}"
	},
	{ "numbers_as_floats",
	  "{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{\"name\":"
	  "\"n\",\"sum\":{\"dataPoints\":[{\"timeUnixNano\":1e3,\"asInt\":"
	  "2.0,\"flags\":4.0}],\"aggregationTemporality\":2.0}}]}]}]}" },
	{ "empty_request", "{}" },
};

/* Requests the transcoder must refuse, with the reason it gives. */
static const struct {
	int		 sig;
	const char	*json;
	const char	*why;
} bad[] = {
	{ OE_SIGNAL_LOGS, "{\"resourceLogz\":[]}", "unknown field" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":{}}", "expected an array" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[1]}", "expected an object" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[],\"resourceLogs\":[]}",
	  "expected an object" },
	{ OE_SIGNAL_LOGS, "[1]", "not a JSON object" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[", "invalid JSON" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"traceId\":\"abc\"}]}]}]}", "invalid hex id" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"spanId\":\"zz\"}]}]}]}", "invalid hex id" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"spanId\":\"0z\"}]}]}]}", "invalid hex id" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"name\":5}]}]}]}", "expected a string" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"kind\":\"SPAN_KIND_NOPE\"}]}]}]}", "unknown enum name" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"kind\":4294967296}]}]}]}", "out of range" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"kind\":true}]}]}]}", "expected an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"flags\":-1}]}]}]}", "negative value" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"flags\":4294967296}]}]}]}", "out of range" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":\"-1\"}]}]}]}", "negative value" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":\"12x\"}]}]}]}", "not an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":\"99999999999999999999\"}]}]}]}",
	  "not an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":1.5}]}]}]}", "not an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":-1.0}]}]}]}", "not an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"startTimeUnixNano\":1e30}]}]}]}", "not an integer" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"status\":{\"code\":3.5}}]}]}]}", "not an integer" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"severityNumber\":\"x1\"}]}]}]}", "unknown enum name" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"severityNumber\":2147483648}]}]}]}", "out of range" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"timeUnixNano\":{}}]}]}]}", "expected an integer" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"boolValue\":1}}]}]}]}", "expected true or false" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"nan\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"1e999\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":[]}}]}]}]}", "expected a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"bytesValue\":\"a*\"}}]}]}]}", "invalid base64" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"intValue\":\"1\"},\"body\":{}}]}]}]}",
	  "expected an object" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"histogram\":{\"dataPoints\":[{\"explicitBounds\":"
	  "[\"x\"]}]}}]}]}]}", "not a number" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"histogram\":{\"dataPoints\":[{\"bucketCounts\":"
	  "[true]}]}}]}]}]}", "expected an integer" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"exponentialHistogram\":{\"dataPoints\":[{\"scale\":"
	  "\"x\"}]}}]}]}]}", "not an integer" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"exponentialHistogram\":{\"dataPoints\":[{\"scale\":"
	  "2147483648}]}}]}]}]}", "out of range" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"sum\":{\"dataPoints\":[{\"flags\":\"x\"}]}}]}]}]}",
	  "not an integer" },
	{ OE_SIGNAL_METRICS, "{\"resourceMetrics\":[{\"scopeMetrics\":[{"
	  "\"metrics\":[{\"exponentialHistogram\":{\"dataPoints\":[{\"scale\":"
	  "-2147483649}]}}]}]}]}", "out of range" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"severityNumber\":-2147483649}]}]}]}", "out of range" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"spanId\":\"0 \"}]}]}]}", "invalid hex id" },
	{ OE_SIGNAL_TRACES, "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":"
	  "[{\"spanId\":\"0:\"}]}]}]}", "invalid hex id" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"bytesValue\":\"ab~d\"}}]}]}]}", "invalid base64" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"inf\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"-inf\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"NAN\"}}]}]}]}", "not a number" },
	{ OE_SIGNAL_LOGS, "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":"
	  "[{\"body\":{\"doubleValue\":\"1.5x\"}}]}]}]}", "not a number" },
};

static void
encode_ok(const atf_tc_t *tc, struct oe_otlppb_defs *d, const char *name,
    const char *json)
{
	char err[256], *pb, args[256];
	size_t len;
	int sig;

	sig = strstr(json, "esourceLogs") != NULL ||
	    strstr(json, "esource_logs") != NULL ? OE_SIGNAL_LOGS :
	    strstr(json, "esourceMetrics") != NULL ? OE_SIGNAL_METRICS :
	    OE_SIGNAL_TRACES;
	ATF_REQUIRE_EQ_MSG(0, oe_otlppb_encode(d, sig, json, strlen(json),
	    &pb, &len, err, sizeof(err)), "%s: %s", name, err);
	write_file("req.json", json, strlen(json));
	write_file("req.pb", pb, len);
	free(pb);
	snprintf(args, sizeof(args), "compare req.json req.pb");
	ATF_CHECK_EQ_MSG(0, run_oracle(tc, args, "oracle.out"), "%s: %s",
	    name, read_file("oracle.out"));
}

ATF_TC_WITHOUT_HEAD(transcode_fixtures);
ATF_TC_BODY(transcode_fixtures, tc)
{
	struct oe_otlppb_defs d;
	char err[256], *pb;
	size_t i, len;

	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));
	for (i = 0; i < nitems(good); i++)
		encode_ok(tc, &d, good[i].name, good[i].json);
	for (i = 0; i < nitems(bad); i++) {
		pb = NULL;
		ATF_CHECK_EQ_MSG(-1, oe_otlppb_encode(&d, bad[i].sig,
		    bad[i].json, strlen(bad[i].json), &pb, &len, err,
		    sizeof(err)), "bad[%zu] accepted", i);
		ATF_CHECK(pb == NULL);
		ATF_CHECK_MSG(strstr(err, bad[i].why) != NULL,
		    "bad[%zu]: \"%s\" lacks \"%s\"", i, err, bad[i].why);
	}
	oe_otlppb_defs_fini(&d);
	/* Releasing definitions that were never loaded. */
	memset(&d, 0, sizeof(d));
	oe_otlppb_defs_fini(&d);
}

/* Nesting beyond the limit is refused, within it accepted. */
ATF_TC_WITHOUT_HEAD(transcode_depth);
ATF_TC_BODY(transcode_depth, tc)
{
	struct oe_otlppb_defs d;
	struct oe_buf b;
	char err[256], *pb;
	size_t len;
	int i, depth;

	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));
	for (depth = 10; depth <= 40; depth += 30) {
		oe_buf_init(&b);
		oe_buf_appendstr(&b, "{\"resourceLogs\":[{\"scopeLogs\":[{"
		    "\"logRecords\":[{\"body\":");
		for (i = 0; i < depth; i++)
			oe_buf_appendstr(&b, "{\"arrayValue\":{\"values\":[");
		oe_buf_appendstr(&b, "{\"intValue\":\"1\"}");
		for (i = 0; i < depth; i++)
			oe_buf_appendstr(&b, "]}}");
		oe_buf_appendstr(&b, "}]}]}]}");
		if (depth == 10)
			encode_ok(tc, &d, "depth10", b.data);
		else {
			ATF_CHECK_EQ(-1, oe_otlppb_encode(&d, OE_SIGNAL_LOGS,
			    b.data, b.len, &pb, &len, err, sizeof(err)));
			ATF_CHECK(strstr(err, "nested too deeply") != NULL);
		}
		oe_buf_free(&b);
	}
	oe_otlppb_defs_fini(&d);
}

/* The library's own encoder output, for records of every kind. */
ATF_TC_WITHOUT_HEAD(transcode_encoder_output);
ATF_TC_BODY(transcode_encoder_output, tc)
{
	struct oe_otlppb_defs d;
	struct oe_otlpenc enc;
	struct oe_resource r;
	struct oe_attr custom[] = { { "deployment.environment", "test" } };
	struct oe_kv kv[] = {
		{ "s", OE_VAL_STRING, "caf\xc3\xa9 \"q\"\n\x01", 0, 0 },
		{ "i", OE_VAL_INT, NULL, -42, 0 },
		{ "b", OE_VAL_BOOL, NULL, 1, 0 },
		{ "d", OE_VAL_DOUBLE, NULL, 0, 0.1 },
		{ "nan", OE_VAL_DOUBLE, NULL, 0, 0 },
		{ "inf", OE_VAL_DOUBLE, NULL, 0, 0 },
		{ "ninf", OE_VAL_DOUBLE, NULL, 0, 0 },
	};
	struct oe_attr dims[] = { { "process.pid", "42" }, { "k", "v" } };
	struct oe_bucket buckets[] = { { 8, 2 }, { 1, 1 }, { 4, 5 } };
	struct oe_datapoint scalar = { dims, 2, 0, 17, NULL, 0 };
	struct oe_datapoint hist = { dims, 2, 1, 0, buckets, 3 };
	struct oe_event ev;
	struct oe_snapshot sn;
	struct oe_span sp;
	char *frags[4], *req;
	size_t len;
	int kind;

	kv[4].d = NAN;
	kv[5].d = INFINITY;
	kv[6].d = -INFINITY;
	memset(&r, 0, sizeof(r));
	r.service_name = "svc";
	r.service_version = "1.0";
	r.host_name = "h";
	r.custom = custom;
	r.ncustom = 1;
	ATF_REQUIRE_EQ(0, oe_enc_init(&enc, &r, "tool"));
	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));

	memset(&ev, 0, sizeof(ev));
	ev.ts.tv_sec = 1700000000;
	ev.observed.tv_sec = 1700000001;
	ev.profile = "p";
	ev.probe = "syscall::read:entry";
	ev.pid = 7;
	ev.execname = "sh";
	ev.body = "line \xe2\x82\xac \\ \t";
	ev.severity = OE_SEV_ERROR + 1;
	ev.attrs = kv;
	ev.nattrs = nitems(kv);
	ev.ctx.flags = OE_CTX_TID | OE_CTX_CPU | OE_CTX_JAIL | OE_CTX_UID;
	ev.ctx.tid = 100001;
	ev.ctx.cpu = 3;
	ev.ctx.jid = 5;
	ev.ctx.jail_name = "web";
	frags[0] = oe_enc_log_record(&enc, &ev);
	ev.severity = OE_SEV_UNSPECIFIED;
	ev.attrs = NULL;
	ev.nattrs = 0;
	frags[1] = oe_enc_log_record(&enc, &ev);
	/* With a drops counter spliced into the first record. */
	req = oe_enc_request(&enc, OE_SIGNAL_LOGS, frags, 2, 12, &len);
	encode_ok(tc, &d, "encoder logs", req);
	free(req);
	free(frags[0]);
	free(frags[1]);

	for (kind = OE_AGG_COUNT; kind <= OE_AGG_LLQUANTIZE; kind++) {
		memset(&sn, 0, sizeof(sn));
		sn.ts.tv_sec = 1700000000;
		sn.start.tv_sec = 1699999990;
		sn.profile = "p";
		sn.name = kind == OE_AGG_SUM ? "" : "agg";
		sn.kind = kind;
		sn.points = kind >= OE_AGG_QUANTIZE ? &hist : &scalar;
		sn.npoints = 1;
		frags[kind % 4] = oe_enc_metric(&enc, &sn);
		req = oe_enc_request(&enc, OE_SIGNAL_METRICS, &frags[kind % 4],
		    1, 0, &len);
		encode_ok(tc, &d, "encoder metric", req);
		free(req);
		free(frags[kind % 4]);
	}

	memset(&sp, 0, sizeof(sp));
	sp.name = "work";
	sp.profile = "p";
	sp.probe = "fbt::x:return";
	sp.start.tv_sec = 1700000000;
	sp.end.tv_sec = 1700000001;
	oe_id_random(sp.trace_id, OE_TRACE_ID_LEN);
	oe_id_random(sp.span_id, OE_SPAN_ID_LEN);
	sp.kind = OE_SPAN_CLIENT;
	sp.status = OE_STATUS_ERROR;
	sp.status_message = "failed \"badly\"";
	sp.attrs = kv;
	sp.nattrs = 3;
	frags[0] = oe_enc_span(&enc, &sp);
	oe_id_random(sp.parent_span_id, OE_SPAN_ID_LEN);
	sp.status = OE_STATUS_OK;
	sp.status_message = NULL;
	sp.probe = "";
	frags[1] = oe_enc_span(&enc, &sp);
	req = oe_enc_request(&enc, OE_SIGNAL_TRACES, frags, 2, 0, &len);
	encode_ok(tc, &d, "encoder spans", req);
	free(req);
	free(frags[0]);
	free(frags[1]);

	oe_otlppb_defs_fini(&d);
	oe_enc_fini(&enc);
}

/* ---------------------------------------------------------------- */
/* gRPC client								*/

static const char simple_logs[] =
    "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{\"body\":"
    "{\"stringValue\":\"hello grpc\"}}]}]}]}";

static void
grpc_call(struct gsrv *s, int tls, int gzip, int timeout_ms,
    const struct oe_attr *h, size_t nh, struct oe_grpc_result *r)
{
	struct oe_otlppb_defs d;
	struct oe_grpc_call call;
	struct oe_url u;
	char err[128], *pb;
	size_t len;

	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));
	ATF_REQUIRE_EQ(0, oe_otlppb_encode(&d, OE_SIGNAL_LOGS, simple_logs,
	    strlen(simple_logs), &pb, &len, err, sizeof(err)));
	oe_otlppb_defs_fini(&d);
	url_of(&u, tls, s->port);
	memset(&call, 0, sizeof(call));
	call.url = &u;
	call.method = "/opentelemetry.proto.collector.logs.v1.LogsService/"
	    "Export";
	call.headers = h;
	call.nheaders = nh;
	call.user_agent = "otlppb-test/1";
	call.msg = pb;
	call.len = len;
	call.gzip = gzip;
	call.timeout_ms = timeout_ms;
	(void)oe_grpc_unary(&call, r);
	free(pb);
}

ATF_TC_WITHOUT_HEAD(grpc_ok);
ATF_TC_BODY(grpc_ok, tc)
{
	struct gsrv s;
	struct gsrv_reply rep[3];
	struct oe_grpc_result r;
	struct oe_attr h[] = { { "Authorization", "Bearer t" },
	    { "x-tenant", "a" }, { "Content-Type", "evil" },
	    { ":path", "/evil" } };
	struct pbw w;
	char *json;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	partial_response(&w, 1, "one");
	memset(rep, 0, sizeof(rep));
	rep[0].body = w.b;
	rep[0].body_len = w.n;
	rep[1].body = w.b;
	rep[1].body_len = w.n;
	rep[1].gzip = 1;
	rep[2].body = "";
	rep[2].body_len = 0;
	gsrv_script(&s, rep, 3);

	grpc_call(&s, 0, 1, 5000, h, nitems(h), &r);
	ATF_REQUIRE_EQ_MSG(0, r.transport, "%s", r.errmsg);
	ATF_CHECK_EQ(OE_GRPC_OK, r.status);
	ATF_CHECK(r.body_len == w.n && memcmp(r.body, w.b, w.n) == 0);
	oe_grpc_result_free(&r);
	ATF_REQUIRE_EQ(1, gsrv_nreqs(&s));
	ATF_CHECK_STREQ("/opentelemetry.proto.collector.logs.v1.LogsService/"
	    "Export", s.reqs[0].path);
	ATF_CHECK(strstr(s.reqs[0].headers, "content-type: application/grpc"
	    "\n") != NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "te: trailers\n") != NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "grpc-encoding: gzip\n") != NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "grpc-timeout: 5000m\n") != NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "authorization: Bearer t\n") !=
	    NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "x-tenant: a\n") != NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, "evil") == NULL);
	ATF_CHECK(strstr(s.reqs[0].headers, ":authority: 127.0.0.1:") !=
	    NULL);
	ATF_CHECK_EQ(1, s.reqs[0].compressed);
	json = decode_request(tc, "logs", s.reqs[0].msg, s.reqs[0].msglen);
	ATF_CHECK(strstr(json, "hello grpc") != NULL);

	/* A compressed response, uncompressed request. */
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_REQUIRE_EQ_MSG(0, r.transport, "%s", r.errmsg);
	ATF_CHECK(r.body_len == w.n && memcmp(r.body, w.b, w.n) == 0);
	oe_grpc_result_free(&r);
	ATF_CHECK_EQ(0, s.reqs[1].compressed);
	ATF_CHECK(strstr(s.reqs[1].headers, "grpc-encoding") == NULL);

	/* An empty response message. */
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(OE_GRPC_OK, r.status);
	ATF_CHECK(r.body != NULL && r.body_len == 0);
	oe_grpc_result_free(&r);
	gsrv_stop(&s);
}

/* Every status shape: trailers, Trailers-Only, mapped HTTP and resets. */
ATF_TC_WITHOUT_HEAD(grpc_statuses);
ATF_TC_BODY(grpc_statuses, tc)
{
	static const struct {
		struct gsrv_reply rep;
		int		 status;
		const char	*message;
	} cases[] = {
		{ { .mode = GSRV_NORMAL, .status = 3,
		    .message = "bad%20thing%3a%zz%4" }, 3,
		    "bad thing:%zz%4" },
		{ { .mode = GSRV_TRAILERS_ONLY, .status = 14,
		    .message = "later" }, 14, "later" },
		{ { .mode = GSRV_HTTP_STATUS, .status = 400 }, 13, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 401 }, 16, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 403 }, 7, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 404 }, 12, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 429 }, 14, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 502 }, 14, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 503 }, 14, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 504 }, 14, NULL },
		{ { .mode = GSRV_HTTP_STATUS, .status = 500 }, 2, NULL },
		{ { .mode = GSRV_BAD_CT }, 2, "unexpected content-type" },
		{ { .mode = GSRV_NO_STATUS }, 13, "no grpc-status" },
		{ { .mode = GSRV_RST, .rst_code = 7 }, 14, NULL },
		{ { .mode = GSRV_RST, .rst_code = 8 }, 1, NULL },
		{ { .mode = GSRV_RST, .rst_code = 11 }, 8, NULL },
		{ { .mode = GSRV_RST, .rst_code = 12 }, 7, NULL },
		{ { .mode = GSRV_RST, .rst_code = 1 }, 13, NULL },
		{ { .mode = GSRV_GOAWAY }, 14, NULL },
	};
	struct gsrv s;
	struct oe_grpc_result r;
	size_t i;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	for (i = 0; i < nitems(cases); i++) {
		gsrv_script(&s, &cases[i].rep, 1);
		grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
		ATF_CHECK_EQ_MSG(0, r.transport, "case %zu: %s", i, r.errmsg);
		ATF_CHECK_EQ_MSG(cases[i].status, r.status,
		    "case %zu: status %d", i, r.status);
		if (cases[i].message != NULL)
			ATF_CHECK_MSG(strstr(r.message, cases[i].message) !=
			    NULL, "case %zu: message \"%s\"", i, r.message);
		oe_grpc_result_free(&r);
	}
	gsrv_stop(&s);
}

/* RetryInfo and the response message edge cases. */
ATF_TC_WITHOUT_HEAD(grpc_details_and_messages);
ATF_TC_BODY(grpc_details_and_messages, tc)
{
	struct gsrv s;
	struct gsrv_reply rep;
	struct oe_grpc_result r;
	struct pbw st;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	rpc_status(&st, 8, "slow down", 0, 250000000, 1);
	memset(&rep, 0, sizeof(rep));
	rep.mode = GSRV_TRAILERS_ONLY;
	rep.status = 8;
	rep.details = st.b;
	rep.details_len = st.n;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(8, r.status);
	ATF_CHECK(r.retry_delay > 0.24 && r.retry_delay < 0.26);
	oe_grpc_result_free(&r);

	/* Undecodable details: no delay. */
	rep.details = "\x0a\x09";
	rep.details_len = 2;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(-1, r.retry_delay);
	oe_grpc_result_free(&r);

	/* A truncated frame, a compressed flag without encoding. */
	memset(&rep, 0, sizeof(rep));
	rep.body = "abc";
	rep.body_len = 3;
	rep.bad_frame = 1;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(OE_GRPC_OK, r.status);
	ATF_CHECK(r.body == NULL);
	ATF_CHECK(strstr(r.errmsg, "malformed response") != NULL);
	oe_grpc_result_free(&r);
	rep.bad_frame = 0;
	rep.bad_flag = 1;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK(r.body == NULL);
	ATF_CHECK(strstr(r.errmsg, "malformed response") != NULL);
	oe_grpc_result_free(&r);
	/* A body shorter than a frame header. */
	rep.bad_flag = 0;
	rep.mode = GSRV_NO_STATUS;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(13, r.status);
	oe_grpc_result_free(&r);
	gsrv_stop(&s);
}

/* A TCP peer that accepts one connection and resets or ignores it. */
struct rawpeer {
	int	lfd;
	int	reset;
};

static void *
rawpeer_main(void *arg)
{
	struct rawpeer *p = arg;
	struct linger l = { 1, 0 };
	int fd;

	if ((fd = accept(p->lfd, NULL, NULL)) < 0)
		return (NULL);
	if (p->reset)
		setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
	else
		sleep(2);
	close(fd);
	return (NULL);
}

static void
send_failure(int reset)
{
	struct sockaddr_in sin;
	struct rawpeer p;
	struct oe_grpc_call call;
	struct oe_grpc_result r;
	struct oe_url u;
	socklen_t slen;
	pthread_t t;
	char *big;
	int small = 4096;

	p.reset = reset;
	ATF_REQUIRE((p.lfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* Small buffers fill quickly when the peer does not read. */
	setsockopt(p.lfd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
	ATF_REQUIRE_EQ(0, bind(p.lfd, (struct sockaddr *)&sin, sizeof(sin)));
	ATF_REQUIRE_EQ(0, listen(p.lfd, 1));
	slen = sizeof(sin);
	ATF_REQUIRE_EQ(0, getsockname(p.lfd, (struct sockaddr *)&sin, &slen));
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, rawpeer_main, &p));
	ATF_REQUIRE((big = calloc(1, 16 * 1024 * 1024)) != NULL);
	ATF_REQUIRE_EQ(0, oe_url_parse("http://127.0.0.1:1", &u));
	u.port = ntohs(sin.sin_port);
	memset(&call, 0, sizeof(call));
	call.url = &u;
	call.method = "/x/Export";
	call.user_agent = "t";
	call.msg = big;
	call.len = 16 * 1024 * 1024;
	call.timeout_ms = 500;
	ATF_CHECK_EQ(-1, oe_grpc_unary(&call, &r));
	/*
	 * Where the failure shows depends on how much the kernel buffers:
	 * the send, the connection, or the wait for a response.
	 */
	ATF_CHECK_MSG(strstr(r.errmsg, "send to") != NULL ||
	    strstr(r.errmsg, "lost") != NULL ||
	    strstr(r.errmsg, "within 500 ms") != NULL, "%s", r.errmsg);
	oe_grpc_result_free(&r);
	pthread_join(t, NULL);
	close(p.lfd);
	free(big);
}

/* Connection-level failures: transport errors, not statuses. */
ATF_TC_WITHOUT_HEAD(grpc_transport_failures);
ATF_TC_BODY(grpc_transport_failures, tc)
{
	static const struct {
		struct gsrv_reply rep;
		const char	*why;
	} cases[] = {
		{ { .mode = GSRV_CLOSE }, "lost" },
		{ { .mode = GSRV_CLOSE_HEADERS }, "lost" },
		{ { .mode = GSRV_GARBAGE }, "closed the session" },
		{ { .mode = GSRV_NORMAL, .delay_ms = 1500 }, "within 500 ms" },
	};
	struct gsrv s;
	struct oe_grpc_result r;
	struct oe_grpc_call call;
	struct oe_url u;
	size_t i;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	for (i = 0; i < nitems(cases); i++) {
		gsrv_script(&s, &cases[i].rep, 1);
		grpc_call(&s, 0, 0, 500, NULL, 0, &r);
		ATF_CHECK_EQ_MSG(-1, r.transport, "case %zu", i);
		ATF_CHECK_MSG(strstr(r.errmsg, cases[i].why) != NULL,
		    "case %zu: \"%s\"", i, r.errmsg);
		oe_grpc_result_free(&r);
	}
	gsrv_stop(&s);

	/* Nothing listening; an IPv6 literal authority. */
	memset(&call, 0, sizeof(call));
	ATF_REQUIRE_EQ(0, oe_url_parse("http://127.0.0.1:1", &u));
	u.port = closed_port();
	call.url = &u;
	call.method = "/x/Export";
	call.user_agent = "t";
	call.msg = "";
	call.timeout_ms = 1000;
	ATF_CHECK_EQ(-1, oe_grpc_unary(&call, &r));
	ATF_CHECK(strstr(r.errmsg, "connect to") != NULL);
	ATF_REQUIRE_EQ(0, oe_url_parse("http://[::1]:1", &u));
	u.port = closed_port();
	ATF_CHECK_EQ(-1, oe_grpc_unary(&call, &r));
	/* A deadline already past. */
	call.timeout_ms = 0;
	ATF_CHECK_EQ(-1, oe_grpc_unary(&call, &r));

	/*
	 * Sending fails: a peer that resets the connection, and one that
	 * never reads, so a large request outlasts the deadline.
	 */
	send_failure(1);
	send_failure(0);
}

ATF_TC_WITHOUT_HEAD(grpc_tls);
ATF_TC_BODY(grpc_tls, tc)
{
	struct gsrv s, other;
	struct oe_grpc_result r;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 1, "ca.pem", "h2"));
	setenv("SSL_CERT_FILE", "ca.pem", 1);
	grpc_call(&s, 1, 1, 5000, NULL, 0, &r);
	ATF_CHECK_EQ_MSG(0, r.transport, "%s", r.errmsg);
	ATF_CHECK_EQ(OE_GRPC_OK, r.status);
	oe_grpc_result_free(&r);
	ATF_REQUIRE_EQ(1, gsrv_nreqs(&s));
	ATF_CHECK(strstr(s.reqs[0].headers, ":scheme: https\n") != NULL);

	/* A certificate from another CA. */
	ATF_REQUIRE_EQ(0, gsrv_start(&other, 1, "other.pem", "h2"));
	grpc_call(&other, 1, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(-1, r.transport);
	ATF_CHECK(strstr(r.errmsg, "TLS handshake") != NULL);
	gsrv_stop(&other);
	gsrv_stop(&s);

	/* A server that does not select h2. */
	ATF_REQUIRE_EQ(0, gsrv_start(&s, 1, "ca.pem", NULL));
	grpc_call(&s, 1, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(-1, r.transport);
	ATF_CHECK(strstr(r.errmsg, "ALPN h2") != NULL);
	gsrv_stop(&s);
	unsetenv("SSL_CERT_FILE");
}

/* ---------------------------------------------------------------- */
/* The exporter end to end						*/

static struct oe_exporter *
exporter(const char *protocol, const char *endpoint, const char *spool,
    int retries, const char *compression)
{
	static struct oe_resource r;
	static struct oe_attr h[] = { { "X-Api-Key", "k1" } };
	struct oe_otlp_config cfg;

	memset(&r, 0, sizeof(r));
	r.service_name = "svc";
	r.service_version = "9.9";
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = endpoint;
	cfg.profile = "p";
	cfg.resource = &r;
	cfg.batch_size = 100;
	cfg.flush_interval = 30;
	cfg.max_retries = retries;
	cfg.timeout = 2;
	cfg.headers = h;
	cfg.nheaders = 1;
	cfg.compression = compression;
	cfg.spool_path = spool;
	cfg.protocol = protocol;
	cfg.scope_name = "tool";
	return (oe_otlp_new(&cfg));
}

static void
emit_all(struct oe_exporter *e, const char *body)
{
	struct oe_event ev;
	struct oe_snapshot sn;
	struct oe_span sp;
	struct oe_datapoint dp = { NULL, 0, 0, 5, NULL, 0 };

	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.profile = "p";
	ev.probe = "";
	ev.execname = "";
	ev.body = body;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	memset(&sn, 0, sizeof(sn));
	sn.ts = ev.ts;
	sn.profile = "p";
	sn.name = "count";
	sn.kind = OE_AGG_COUNT;
	sn.points = &dp;
	sn.npoints = 1;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	memset(&sp, 0, sizeof(sp));
	sp.name = "s";
	sp.profile = "p";
	sp.probe = "";
	sp.execname = "";
	sp.start = sp.end = ev.ts;
	oe_id_random(sp.trace_id, OE_TRACE_ID_LEN);
	oe_id_random(sp.span_id, OE_SPAN_ID_LEN);
	sp.kind = OE_SPAN_INTERNAL;
	ATF_REQUIRE_EQ(0, oe_span(e, &sp));
}

ATF_TC_WITHOUT_HEAD(export_grpc);
ATF_TC_BODY(export_grpc, tc)
{
	struct gsrv s;
	struct gsrv_reply rep[4];
	struct oe_exporter *e;
	struct pbw w, st;
	char ep[64], *json, *err;
	int i;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	partial_response(&w, 2, "two spans refused");
	rpc_status(&st, 8, NULL, 0, 1000000, 1);
	memset(rep, 0, sizeof(rep));
	/* Logs: UNAVAILABLE, then OK. */
	rep[0].mode = GSRV_TRAILERS_ONLY;
	rep[0].status = 14;
	/* Metrics: RESOURCE_EXHAUSTED with RetryInfo, then OK. */
	rep[2].mode = GSRV_TRAILERS_ONLY;
	rep[2].status = 8;
	rep[2].details = st.b;
	rep[2].details_len = st.n;
	/* Traces: OK with a partial success. */
	rep[3].body = w.b;
	rep[3].body_len = w.n;
	gsrv_script(&s, rep, 4);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	ATF_REQUIRE((e = exporter("grpc", ep, NULL, 2, NULL)) != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	emit_all(e, "via grpc");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(5, gsrv_nreqs(&s));
	ATF_CHECK(strstr(err, "partial success: 2 records rejected: two "
	    "spans refused") != NULL);
	json = decode_request(tc, "logs", s.reqs[1].msg, s.reqs[1].msglen);
	ATF_CHECK(strstr(json, "via grpc") != NULL);
	ATF_CHECK(strstr(json, "\"service.name\"") != NULL);
	ATF_CHECK(strstr(s.reqs[2].path, "MetricsService") != NULL);
	json = decode_request(tc, "metrics", s.reqs[3].msg, s.reqs[3].msglen);
	ATF_CHECK(strstr(json, "tool.p.count") != NULL);
	ATF_CHECK(strstr(s.reqs[4].path, "TraceService") != NULL);
	for (i = 0; i < 5; i++) {
		ATF_CHECK(strstr(s.reqs[i].headers, "x-api-key: k1\n") !=
		    NULL);
		ATF_CHECK_EQ(1, s.reqs[i].compressed);
	}
	gsrv_stop(&s);
}

/* Final statuses are not retried; exhausted retries are reported. */
ATF_TC_WITHOUT_HEAD(export_grpc_failures);
ATF_TC_BODY(export_grpc_failures, tc)
{
	struct gsrv s;
	struct gsrv_reply rep[6];
	struct oe_exporter *e;
	char ep[64], *err;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	memset(rep, 0, sizeof(rep));
	/* Logs: RESOURCE_EXHAUSTED without RetryInfo is final. */
	rep[0].mode = GSRV_TRAILERS_ONLY;
	rep[0].status = 8;
	rep[0].message = "quota";
	/* Metrics: UNAVAILABLE twice: retries exhausted. */
	rep[1].mode = GSRV_TRAILERS_ONLY;
	rep[1].status = 14;
	rep[2].mode = GSRV_TRAILERS_ONLY;
	rep[2].status = 14;
	/* Traces: a transport failure, then a malformed OK response. */
	rep[3].mode = GSRV_CLOSE;
	rep[4].body = "\x0a\x09";
	rep[4].body_len = 2;
	gsrv_script(&s, rep, 5);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	ATF_REQUIRE((e = exporter("grpc", ep, NULL, 1, "none")) != NULL);
	emit_all(e, "x");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "status 8 (non-retryable): quota") != NULL);
	ATF_CHECK(strstr(err, "status 14 (after 2 attempts)") != NULL);
	ATF_CHECK(strstr(err, "malformed grpc response") != NULL);
	ATF_REQUIRE_EQ(5, gsrv_nreqs(&s));
	ATF_CHECK_EQ(0, s.reqs[0].compressed);

	/* A malformed message frame in an OK response is reported. */
	memset(rep, 0, sizeof(rep));
	rep[0].body = "abc";
	rep[0].body_len = 3;
	rep[0].bad_frame = 1;
	gsrv_script(&s, rep, 3);
	emit_all(e, "y");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "malformed response message (ignored)") !=
	    NULL);
	gsrv_stop(&s);

	/* Nothing listening: transport failure after the retries. */
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", closed_port());
	oe_exporter_free(e);
	ATF_REQUIRE((e = exporter("grpc", ep, NULL, 0, NULL)) != NULL);
	emit_all(e, "z");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "failed: connect to") != NULL);
	oe_exporter_free(e);
}

ATF_TC_WITHOUT_HEAD(export_http_protobuf);
ATF_TC_BODY(export_http_protobuf, tc)
{
	struct collector co;
	struct coll_reply rep[5];
	struct oe_exporter *e;
	struct pbw w, st;
	char ep[64], *json, *err;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	partial_response(&w, 4, "four points");
	rpc_status(&st, 3, "bad span", 0, 0, 0);
	memset(rep, 0, sizeof(rep));
	/* Logs: 503 with Retry-After, then accepted (empty body). */
	rep[0].status = 503;
	rep[0].headers = "Retry-After: 0\r\n";
	rep[1].status = 200;
	rep[1].body = "";
	/* Metrics: a chunked partial success. */
	rep[2].status = 200;
	rep[2].body = (const char *)w.b;
	/* Traces: refused with a google.rpc.Status. */
	rep[3].status = 400;
	rep[3].body = (const char *)st.b;
	coll_script(&co, rep, 4);
	coll_script_body(&co, 2, w.n, 1);
	coll_script_body(&co, 3, st.n, 0);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d/base/", co.port);
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 2, NULL)) !=
	    NULL);
	emit_all(e, "via http/protobuf");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_REQUIRE_EQ(4, coll_nreqs(&co));
	ATF_CHECK_STREQ("/base/v1/logs", co.reqs[0].path);
	ATF_CHECK(strstr(co.reqs[0].headers, "Content-Type: "
	    "application/x-protobuf") != NULL);
	ATF_CHECK(co.reqs[0].gzipped);
	ATF_CHECK(strstr(co.reqs[0].headers, "X-Api-Key: k1") != NULL);
	json = decode_request(tc, "logs", co.reqs[1].body, co.reqs[1].bodylen);
	ATF_CHECK(strstr(json, "via http/protobuf") != NULL);
	ATF_CHECK_STREQ("/base/v1/metrics", co.reqs[2].path);
	ATF_CHECK(strstr(err, "/v1/metrics partial success: 4 records "
	    "rejected: four points") != NULL);
	ATF_CHECK(strstr(err, "POST /v1/traces returned 400 (non-retryable): "
	    "bad span") != NULL);

	/* No gzip; 503 until retries run out; a malformed 2xx body. */
	oe_exporter_free(e);
	memset(rep, 0, sizeof(rep));
	rep[0].status = 503;
	rep[0].body = "<html>";
	rep[1].status = 503;
	rep[2].status = 200;
	rep[2].body = "\x0a\x09";
	rep[3].status = 415;
	rep[3].body = "plain text";
	coll_script(&co, rep, 4);
	coll_script_body(&co, 2, 2, 0);
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 1, "none")) !=
	    NULL);
	emit_all(e, "plain");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	ATF_CHECK(!co.reqs[4].gzipped);
	ATF_CHECK(strstr(err, "/v1/logs returned 503 (after 2 attempts)\n") !=
	    NULL);
	ATF_CHECK(strstr(err, "malformed http/protobuf response") != NULL);
	ATF_CHECK(strstr(err, "returned 415 (non-retryable)\n") != NULL);
	oe_exporter_free(e);
	coll_stop(&co);

	/* Nothing listening. */
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", closed_port());
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 0, NULL)) !=
	    NULL);
	emit_all(e, "z");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "POST /v1/logs failed: connect to") != NULL);
	oe_exporter_free(e);
}

/* Failed batches spool as OTLP JSON and replay over protobuf. */
static void
spool_replay(const atf_tc_t *tc, const char *protocol)
{
	struct gsrv s;
	struct collector co;
	struct gsrv_reply grep[2];
	struct coll_reply crep[2];
	struct oe_exporter *e;
	struct stat sb;
	char ep[64], *json, *spooled;
	int grpc, n;

	grpc = strcmp(protocol, "grpc") == 0;
	memset(grep, 0, sizeof(grep));
	memset(crep, 0, sizeof(crep));
	if (grpc) {
		ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
		grep[0].mode = GSRV_TRAILERS_ONLY;
		grep[0].status = 14;
		gsrv_script(&s, grep, 1);
		snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	} else {
		ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
		crep[0].status = 503;
		coll_script(&co, crep, 1);
		snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", co.port);
	}
	ATF_REQUIRE((e = exporter(protocol, ep, "spool", 0, NULL)) != NULL);
	{
		struct oe_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.profile = "p";
		ev.body = "spooled record";
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		ATF_REQUIRE_EQ(0, oe_flush(e));
		ATF_REQUIRE_EQ(0, stat("spool", &sb));
		ATF_REQUIRE(sb.st_size > 0);
		spooled = read_file("spool");
		ATF_CHECK(strncmp(spooled, "{\"resourceLogs\":", 16) == 0);
		/* The next accepted batch replays the spool. */
		ev.body = "fresh record";
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		ATF_REQUIRE_EQ(0, oe_flush(e));
	}
	ATF_REQUIRE_EQ(0, stat("spool", &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	n = grpc ? gsrv_nreqs(&s) : coll_nreqs(&co);
	ATF_REQUIRE_EQ(3, n);
	json = grpc ? decode_request(tc, "logs", s.reqs[2].msg,
	    s.reqs[2].msglen) : decode_request(tc, "logs", co.reqs[2].body,
	    co.reqs[2].bodylen);
	ATF_CHECK(strstr(json, "spooled record") != NULL);
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	if (grpc)
		gsrv_stop(&s);
	else
		coll_stop(&co);
}

ATF_TC_WITHOUT_HEAD(spool_replay_grpc);
ATF_TC_BODY(spool_replay_grpc, tc)
{

	spool_replay(tc, "grpc");
}

ATF_TC_WITHOUT_HEAD(spool_replay_http_protobuf);
ATF_TC_BODY(spool_replay_http_protobuf, tc)
{

	spool_replay(tc, "http/protobuf");
}

/* A spool line that does not transcode is dropped, not resent forever. */
ATF_TC_WITHOUT_HEAD(spool_untranscodable);
ATF_TC_BODY(spool_untranscodable, tc)
{
	struct gsrv s;
	struct oe_exporter *e;
	struct stat sb;
	struct oe_event ev;
	char ep[64], *err;

	write_file("spool", "{\"resourceLogs\":[{\"bogus\":1}]}\n", 31);
	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	ATF_REQUIRE((e = exporter("grpc", ep, "spool", 0, NULL)) != NULL);
	memset(&ev, 0, sizeof(ev));
	ev.profile = "p";
	ev.body = "b";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "/v1/logs batch dropped: ResourceLogs: unknown "
	    "field \"bogus\"") != NULL);
	ATF_REQUIRE_EQ(0, stat("spool", &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	ATF_CHECK_EQ(1, gsrv_nreqs(&s));
	oe_exporter_free(e);
	gsrv_stop(&s);
}

ATF_TC_WITHOUT_HEAD(open_protocols);
ATF_TC_BODY(open_protocols, tc)
{
	struct oe_otlppb *pb;
	struct oe_url u;
	struct oe_exporter *e;
	char *err;

	ATF_REQUIRE_EQ(0, oe_url_parse("http://127.0.0.1:4318", &u));
	ATF_CHECK_EQ(0, oe_otlppb_open(NULL, &u, NULL, 0, "ua", 1000, 0, 0,
	    &pb));
	ATF_CHECK(pb == NULL);
	ATF_CHECK_EQ(0, oe_otlppb_open("http/json", &u, NULL, 0, "ua", 1000,
	    0, 0, &pb));
	ATF_CHECK(pb == NULL);
	ATF_REQUIRE_EQ(0, oe_otlppb_open("grpc", &u, NULL, 0, "ua", 1000, 0,
	    0, &pb));
	ATF_CHECK(pb != NULL);
	oe_otlppb_free(pb);
	oe_otlppb_free(NULL);
	capture_start();
	ATF_CHECK_EQ(-1, oe_otlppb_open("thrift", &u, NULL, 0, "ua", 1000, 0,
	    0, &pb));
	ATF_CHECK(exporter("http/xml", "http://127.0.0.1:1", NULL, 0, NULL) ==
	    NULL);
	err = capture_end();
	ATF_CHECK(strstr(err, "unknown protocol \"thrift\"") != NULL);
	ATF_CHECK(strstr(err, "unknown protocol \"http/xml\"") != NULL);
	/* JSON keeps the JSON transport. */
	ATF_REQUIRE((e = exporter("http/json", "http://127.0.0.1:1", NULL, 0,
	    NULL)) != NULL);
	oe_exporter_free(e);
}

/* ---------------------------------------------------------------- */
/* Configuration							*/

static void
config(const char *conf, const char *env, const char *cli,
    struct oe_env *e, int expect)
{
	struct oe_config_request req;
	char err[256];

	if (conf != NULL)
		write_file("otel.conf", conf, strlen(conf));
	setenv("OTELCONF_DEFAULTS", "/nonexistent/otel.conf", 1);
	setenv("OTELCONF_FILE", conf != NULL ? "otel.conf" :
	    "/nonexistent/otel.conf", 1);
	unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	if (env != NULL)
		setenv("OTEL_EXPORTER_OTLP_PROTOCOL", env, 1);
	else
		unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL");
	memset(&req, 0, sizeof(req));
	req.scope = "t";
	req.system = conf != NULL;
	req.protocol = cli;
	ATF_REQUIRE_EQ_MSG(expect, oe_config_load(e, &req, err, sizeof(err)),
	    "%s", err);
	if (expect != 0)
		ATF_CHECK(strstr(err, "unknown OTLP protocol") != NULL);
}

ATF_TC_WITHOUT_HEAD(config_protocol);
ATF_TC_BODY(config_protocol, tc)
{
	struct oe_env e;
	struct oe_otlp_config cfg;
	char *err;

	/* Built-in default: http/protobuf to 4318. */
	config(NULL, NULL, NULL, &e, 0);
	ATF_CHECK_STREQ("http/protobuf", e.protocol);
	ATF_CHECK_STREQ("http://localhost:4318", e.endpoint);
	memset(&cfg, 0, sizeof(cfg));
	oe_otlp_config_env(&cfg, &e);
	ATF_CHECK_STREQ("http/protobuf", cfg.protocol);
	oe_env_free(&e);
	/* oe_otlp_config_env() of a bare environment. */
	oe_env_load(&e);
	oe_otlp_config_env(&cfg, &e);
	ATF_CHECK_STREQ("http/protobuf", cfg.protocol);
	oe_env_free(&e);

	/* gRPC defaults to 4317; an explicit endpoint is kept. */
	config(NULL, "grpc", NULL, &e, 0);
	ATF_CHECK_STREQ("grpc", e.protocol);
	ATF_CHECK_STREQ("http://localhost:4317", e.endpoint);
	oe_env_free(&e);

	/* otel.conf, overridden by the environment, by the command line. */
	config("protocol = \"grpc\";\nendpoint = \"http://c:1\";\n", NULL,
	    NULL, &e, 0);
	ATF_CHECK_STREQ("grpc", e.protocol);
	ATF_CHECK_STREQ("http://c:1", e.endpoint);
	oe_env_free(&e);
	config("protocol = \"grpc\";\n", "http/json", NULL, &e, 0);
	ATF_CHECK_STREQ("http/json", e.protocol);
	oe_env_free(&e);
	config("protocol = \"grpc\";\n", "http/json", "http/protobuf", &e, 0);
	ATF_CHECK_STREQ("http/protobuf", e.protocol);
	oe_env_free(&e);
	config("protocol = \"http/protobuf\";\n", NULL, NULL, &e, 0);
	ATF_CHECK_STREQ("http/protobuf", e.protocol);
	oe_env_free(&e);
	/* otel.conf disabled: its protocol does not apply. */
	config("enable = false;\nprotocol = \"grpc\";\n", NULL, NULL, &e, 0);
	ATF_CHECK_STREQ("http/protobuf", e.protocol);
	oe_env_free(&e);

	/* Invalid values: the environment is ignored, the CLI refused. */
	capture_start();
	config(NULL, "carrier-pigeon", NULL, &e, 0);
	err = capture_end();
	ATF_CHECK_STREQ("http/protobuf", e.protocol);
	ATF_CHECK(strstr(err, "ignoring OTEL_EXPORTER_OTLP_PROTOCOL="
	    "carrier-pigeon") != NULL);
	oe_env_free(&e);
	config(NULL, NULL, "grpcs", &e, -1);
	unsetenv("OTEL_EXPORTER_OTLP_PROTOCOL");
}

/* ---------------------------------------------------------------- */
/* Allocation failures							*/

/* Fail the 1st, 2nd, ... allocation until the operation succeeds. */
#define	OOM_SWEEP(op, ok) do {						\
	int _n, _r, _hit;						\
	for (_n = 1; _n < 100000; _n++) {				\
		failalloc_arm(_n);					\
		_r = (op);						\
		_hit = failalloc_hit();					\
		failalloc_arm(0);					\
		if (!_hit) {						\
			ATF_CHECK_MSG(_r == (ok), "no failure, result %d",\
			    _r);					\
			break;						\
		}							\
	}								\
	ATF_CHECK(_n < 100000);						\
} while (0)

/*
 * The same with each attempt in a child process, for operations that
 * reach upb_DefPool_New() and _upb_DefPool_LoadDefInitEx(): upstream
 * upb crashed when their upb_Arena_New() failed (fixed locally,
 * tools/build/protobuf/patches/protobuf-upb-defpool-oom.patch), so a
 * crash of the child is a failure of the test.
 */
static int oom_upb_crashes;

static void
oom_sweep_fork(int (*op)(void))
{
	pid_t pid;
	int n, st, r, hit;

	for (n = 1; n < 100000; n++) {
		fflush(stdout);
		fflush(stderr);
		ATF_REQUIRE((pid = fork()) >= 0);
		if (pid == 0) {
			failalloc_arm(n);
			r = op();
			hit = failalloc_hit();
			failalloc_arm(0);
			/* exit(), not _exit(): coverage data is written. */
			exit(hit ? 2 : r == 0 ? 0 : 1);
		}
		ATF_REQUIRE_EQ(pid, waitpid(pid, &st, 0));
		if (WIFSIGNALED(st)) {
			oom_upb_crashes++;
			fprintf(stderr, "allocation failure %d: signal %d\n",
			    n, WTERMSIG(st));
			continue;
		}
		ATF_REQUIRE(WIFEXITED(st));
		if (WEXITSTATUS(st) == 2)
			continue;
		ATF_CHECK_EQ_MSG(0, WEXITSTATUS(st), "no failure, but failed");
		break;
	}
	ATF_CHECK(n < 100000);
}

static struct oe_otlppb_defs *oom_defs;
static const char *oom_json;
static int oom_sig;
static int
oom_encode(void)
{
	char err[256], *pb;
	size_t len;

	if (oe_otlppb_encode(oom_defs, oom_sig, oom_json,
	    strlen(oom_json), &pb, &len, err, sizeof(err)) != 0) {
		fprintf(stderr, "oom_encode: %s\n", err);
		return (-1);
	}
	free(pb);
	return (0);
}

static int
oom_defs_init(void)
{
	struct oe_otlppb_defs d;

	if (oe_otlppb_defs_init(&d) != 0)
		return (-1);
	oe_otlppb_defs_fini(&d);
	return (0);
}

static int
oom_partial(void)
{
	struct pbw w;
	char msg[64];
	int64_t rej;

	partial_response(&w, 3, "m");
	return (oe_otlppb_partial(oom_defs, OE_SIGNAL_LOGS, w.b, w.n, &rej,
	    msg, sizeof(msg)));
}

static int
oom_gzip(void)
{
	char in[5000], *z, *out;
	size_t zlen, olen;

	memset(in, 'a', sizeof(in));
	if ((z = oe_gzip(in, sizeof(in), &zlen)) == NULL)
		return (-1);
	out = oe_gunzip(z, zlen, 1 << 20, &olen);
	free(z);
	if (out == NULL)
		return (-1);
	free(out);
	return (0);
}

static int
oom_open(void)
{
	struct oe_otlppb *pb;
	struct oe_url u;

	oe_url_parse("http://127.0.0.1:1", &u);
	if (oe_otlppb_open("grpc", &u, NULL, 0, "ua", 1000, 0, 0, &pb) != 0)
		return (-1);
	oe_otlppb_free(pb);
	return (0);
}

static struct oe_otlppb *oom_pb;
static int
oom_post(void)
{

	return (oe_otlppb_post(oom_pb, OE_SIGNAL_LOGS, simple_logs,
	    strlen(simple_logs)) == OE_OTLPPB_OK ? 0 : -1);
}

static struct gsrv *oom_srv;
static int
oom_grpc(void)
{
	static struct oe_attr h[] = { { "a", "b" } };
	struct oe_grpc_call call;
	struct oe_grpc_result r;
	struct oe_url u;
	int ret;

	url_of(&u, 0, oom_srv->port);
	memset(&call, 0, sizeof(call));
	call.url = &u;
	call.method = "/x/Export";
	call.headers = h;
	call.nheaders = 1;
	call.user_agent = "t";
	call.msg = "\x0a\x00";
	call.len = 2;
	call.gzip = 1;
	call.timeout_ms = 5000;
	ret = oe_grpc_unary(&call, &r) == 0 && r.body != NULL ? 0 : -1;
	oe_grpc_result_free(&r);
	return (ret);
}

ATF_TC_WITHOUT_HEAD(oom);
ATF_TC_BODY(oom, tc)
{
	struct oe_otlppb_defs d;
	struct gsrv s;
	struct gsrv_reply rep;
	struct pbw w;

	ATF_REQUIRE_EQ(0, oe_otlppb_defs_init(&d));
	oom_defs = &d;
	oom_json = good[3].json;
	oom_sig = OE_SIGNAL_TRACES;
	OOM_SWEEP(oom_encode(), 0);
	oom_json = good[0].json;
	oom_sig = OE_SIGNAL_LOGS;
	OOM_SWEEP(oom_encode(), 0);
	oom_json = good[2].json;
	oom_sig = OE_SIGNAL_METRICS;
	OOM_SWEEP(oom_encode(), 0);
	oom_sweep_fork(oom_defs_init);
	OOM_SWEEP(oom_partial(), 0);
	OOM_SWEEP(oom_gzip(), 0);
	oom_sweep_fork(oom_open);
	ATF_CHECK_EQ_MSG(0, oom_upb_crashes, "%d allocation failures crashed",
	    oom_upb_crashes);

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	partial_response(&w, 1, "x");
	memset(&rep, 0, sizeof(rep));
	rep.body = w.b;
	rep.body_len = w.n;
	rep.gzip = 1;
	gsrv_script(&s, &rep, 1);
	/* Every call is answered the same way. */
	s.nscript = 0;
	memcpy(&s.script[0], &rep, sizeof(rep));
	oom_srv = &s;
	OOM_SWEEP((gsrv_script(&s, &rep, 1), oom_grpc()), 0);
	rep.gzip = 0;
	OOM_SWEEP((gsrv_script(&s, &rep, 1), oom_grpc()), 0);

	/* Sending with retries, both protocols. */
	{
		struct collector co;
		struct oe_url u;

		url_of(&u, 0, s.port);
		ATF_REQUIRE_EQ(0, oe_otlppb_open("grpc", &u, NULL, 0, "ua",
		    5000, 0, 1, &oom_pb));
		OOM_SWEEP((gsrv_script(&s, &rep, 1), oom_post()), 0);
		oe_otlppb_free(oom_pb);
		ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
		url_of(&u, 0, co.port);
		ATF_REQUIRE_EQ(0, oe_otlppb_open("http/protobuf", &u, NULL, 0,
		    "ua", 5000, 0, 1, &oom_pb));
		OOM_SWEEP(oom_post(), 0);
		oe_otlppb_free(oom_pb);
		coll_stop(&co);
	}
	gsrv_stop(&s);

	/* Requests that make the upb arena grow: strings and arrays. */
	{
		struct oe_buf b;
		int i;

		oe_buf_init(&b);
		oe_buf_appendstr(&b, "{\"resourceLogs\":[{\"scopeLogs\":[{"
		    "\"logRecords\":[{\"severityText\":\"");
		for (i = 0; i < 20000; i++)
			oe_buf_appendstr(&b, "abcd");
		oe_buf_appendstr(&b, "\",\"body\":{\"arrayValue\":{"
		    "\"values\":[");
		for (i = 0; i < 3000; i++)
			oe_buf_appendf(&b, "%s{\"intValue\":\"%d\"}",
			    i > 0 ? "," : "", i);
		oe_buf_appendstr(&b, "]}}}]}]}]}");
		oom_json = b.data;
		oom_sig = OE_SIGNAL_LOGS;
		OOM_SWEEP(oom_encode(), 0);
		oe_buf_free(&b);
	}
	oe_otlppb_defs_fini(&d);
}

/* Response shapes at the edges of the gRPC client. */
ATF_TC_WITHOUT_HEAD(grpc_edges);
ATF_TC_BODY(grpc_edges, tc)
{
	struct gsrv s;
	struct gsrv_reply rep;
	struct oe_grpc_result r;
	struct oe_grpc_call call;
	struct oe_url u;
	struct pbw st;
	char *big;
	size_t i;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	/* grpc-message escapes that are not escapes. */
	memset(&rep, 0, sizeof(rep));
	rep.mode = GSRV_TRAILERS_ONLY;
	rep.status = 3;
	rep.message = "a%!0b%0!c%0zd%";
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_STREQ("a%!0b%0!c%0zd%", r.message);
	oe_grpc_result_free(&r);

	/* Details beyond the client's bound, and not base64. */
	rpc_status(&st, 8, NULL, 1, 0, 1);
	ATF_REQUIRE((big = calloc(1, 4000)) != NULL);
	memcpy(big, st.b, st.n);
	/* Pad with an unknown length-delimited field. */
	big[st.n] = 0x4a;
	big[st.n + 1] = (char)0x80 | (3990 - st.n - 3) % 128;
	big[st.n + 2] = (char)((3990 - st.n - 3) / 128);
	rep.status = 8;
	rep.details = big;
	rep.details_len = 3990;
	rep.message = NULL;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(8, r.status);
	ATF_CHECK_EQ(-1, r.retry_delay);
	oe_grpc_result_free(&r);
	free(big);
	rep.details = NULL;
	rep.details_len = 0;
	rep.details_raw = "!!!";
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_EQ(-1, r.retry_delay);
	oe_grpc_result_free(&r);

	/* Bodies too short for a frame header, a bad frame flag. */
	memset(&rep, 0, sizeof(rep));
	rep.raw = 1;
	rep.body = "\x00\x00\x00";
	rep.body_len = 3;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK(r.body == NULL);
	ATF_CHECK_MSG(strstr(r.errmsg, "malformed") != NULL, "%s", r.errmsg);
	oe_grpc_result_free(&r);
	rep.body = "\x02\x00\x00\x00\x00";
	rep.body_len = 5;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_MSG(strstr(r.errmsg, "malformed") != NULL, "%s", r.errmsg);
	oe_grpc_result_free(&r);
	/* A compressed message that does not decompress. */
	rep.body = "\x01\x00\x00\x00\x03xyz";
	rep.body_len = 8;
	gsrv_script(&s, &rep, 1);
	{
		struct gsrv_reply r2 = rep;

		r2.gzip = 0;
		gsrv_script(&s, &r2, 1);
	}
	grpc_call(&s, 0, 0, 5000, NULL, 0, &r);
	ATF_CHECK_MSG(strstr(r.errmsg, "malformed") != NULL, "%s", r.errmsg);
	oe_grpc_result_free(&r);

	/* A response beyond the 4 MiB bound. */
	ATF_REQUIRE((big = calloc(1, 5 << 20)) != NULL);
	memset(&rep, 0, sizeof(rep));
	rep.body = big;
	rep.body_len = 5 << 20;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 0, 0, 20000, NULL, 0, &r);
	ATF_CHECK_EQ(OE_GRPC_OK, r.status);
	ATF_CHECK(r.body == NULL);
	ATF_CHECK_MSG(strstr(r.errmsg, "malformed") != NULL, "%s", r.errmsg);
	oe_grpc_result_free(&r);

	/* A request larger than one DATA frame. */
	url_of(&u, 0, s.port);
	memset(&call, 0, sizeof(call));
	call.url = &u;
	call.method = "/x/Export";
	call.user_agent = "t";
	call.msg = big;
	call.len = 100000;
	call.timeout_ms = 20000;
	ATF_CHECK_EQ(0, oe_grpc_unary(&call, &r));
	oe_grpc_result_free(&r);
	ATF_CHECK_EQ(100000, s.reqs[s.nreqs - 1].msglen);
	/* So short a deadline that the call times out at once. */
	call.len = 10;
	call.timeout_ms = 1;
	for (i = 0; i < 20; i++) {
		(void)oe_grpc_unary(&call, &r);
		oe_grpc_result_free(&r);
	}
	gsrv_stop(&s);

	/* TLS with a response larger than one TLS read. */
	ATF_REQUIRE_EQ(0, gsrv_start(&s, 1, "ca.pem", "h2"));
	setenv("SSL_CERT_FILE", "ca.pem", 1);
	memset(&rep, 0, sizeof(rep));
	rep.body = big;
	rep.body_len = 200000;
	gsrv_script(&s, &rep, 1);
	grpc_call(&s, 1, 0, 20000, NULL, 0, &r);
	ATF_CHECK_EQ(200000, r.body_len);
	oe_grpc_result_free(&r);
	gsrv_stop(&s);
	free(big);

	/* TLS to a server that hangs up without TLS. */
	{
		struct collector co;
		struct coll_reply cr;

		ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
		memset(&cr, 0, sizeof(cr));
		cr.hangup = 1;
		coll_script(&co, &cr, 1);
		ATF_REQUIRE_EQ(0, oe_url_parse("https://localhost:1", &u));
		u.port = co.port;
		call.url = &u;
		call.timeout_ms = 5000;
		ATF_CHECK_EQ(-1, oe_grpc_unary(&call, &r));
		ATF_CHECK_MSG(strstr(r.errmsg, "TLS handshake") != NULL, "%s",
		    r.errmsg);
		coll_stop(&co);
	}
	unsetenv("SSL_CERT_FILE");
}

/* Exporter outcomes not covered above. */
ATF_TC_WITHOUT_HEAD(export_edges);
ATF_TC_BODY(export_edges, tc)
{
	struct gsrv s;
	struct gsrv_reply rep[5];
	struct collector co;
	struct coll_reply crep[8];
	struct oe_exporter *e;
	struct pbw w, st;
	char ep[64], *err;

	ATF_REQUIRE_EQ(0, gsrv_start(&s, 0, NULL, NULL));
	partial_response(&w, 5, NULL);
	memset(rep, 0, sizeof(rep));
	/* Logs: an empty response; metrics: rejection without a message. */
	rep[0].body = "";
	rep[1].mode = GSRV_TRAILERS_ONLY;
	rep[1].status = 3;
	/* Traces: UNAVAILABLE with a message until the retries run out. */
	rep[2].mode = GSRV_TRAILERS_ONLY;
	rep[2].status = 14;
	rep[2].message = "busy";
	rep[3] = rep[2];
	gsrv_script(&s, rep, 4);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", s.port);
	ATF_REQUIRE((e = exporter("grpc", ep, NULL, 1, NULL)) != NULL);
	emit_all(e, "x");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "/v1/logs partial") == NULL);
	ATF_CHECK(strstr(err, "status 3 (non-retryable)\n") != NULL);
	ATF_CHECK(strstr(err, "status 14 (after 2 attempts): busy") != NULL);
	/* A rejection count without a message. */
	memset(rep, 0, sizeof(rep));
	rep[0].body = w.b;
	rep[0].body_len = w.n;
	gsrv_script(&s, rep, 1);
	emit_all(e, "y");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "/v1/logs partial success: 5 records "
	    "rejected\n") != NULL);
	/* An empty partial_success is no rejection: nothing reported. */
	partial_response(&w, 0, NULL);
	memset(rep, 0, sizeof(rep));
	rep[0].body = w.b;
	rep[0].body_len = w.n;
	gsrv_script(&s, rep, 1);
	emit_all(e, "z");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "partial success") == NULL);
	/* A warning without a rejection is still reported. */
	partial_response(&w, 0, "deprecated attribute");
	memset(rep, 0, sizeof(rep));
	rep[0].body = w.b;
	rep[0].body_len = w.n;
	gsrv_script(&s, rep, 1);
	emit_all(e, "w");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "/v1/logs partial success: 0 records "
	    "rejected: deprecated attribute\n") != NULL);
	oe_exporter_free(e);
	gsrv_stop(&s);

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	rpc_status(&st, 14, "overloaded", 0, 0, 0);
	memset(crep, 0, sizeof(crep));
	crep[0].status = 429;
	crep[1].status = 502;
	crep[2].status = 200;
	crep[3].status = 504;
	crep[4].status = 200;
	crep[5].status = 199;
	crep[6].status = 503;
	crep[6].body = (const char *)st.b;
	crep[7].status = 503;
	crep[7].body = (const char *)st.b;
	coll_script(&co, crep, 8);
	coll_script_body(&co, 6, st.n, 0);
	coll_script_body(&co, 7, st.n, 0);
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", co.port);
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 2, NULL)) !=
	    NULL);
	emit_all(e, "z");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "returned 199 (non-retryable)") != NULL);
	oe_exporter_free(e);
	/* Retries exhausted with a Status message. */
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 1, NULL)) !=
	    NULL);
	coll_script(&co, crep + 6, 2);
	coll_script_body(&co, 0, st.n, 0);
	coll_script_body(&co, 1, st.n, 0);
	{
		struct oe_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.profile = "p";
		ev.body = "b";
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	}
	capture_start();
	ATF_REQUIRE_EQ(0, oe_flush(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "returned 503 (after 2 attempts): overloaded") !=
	    NULL);
	oe_exporter_free(e);
	coll_stop(&co);

	/* A transport failure retried, http/protobuf. */
	snprintf(ep, sizeof(ep), "http://127.0.0.1:%d", closed_port());
	ATF_REQUIRE((e = exporter("http/protobuf", ep, NULL, 1, NULL)) !=
	    NULL);
	emit_all(e, "w");
	capture_start();
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	err = capture_end();
	ATF_CHECK(strstr(err, "(after 2 attempts)") != NULL);
	oe_exporter_free(e);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, protocol_names);
	ATF_TP_ADD_TC(tp, base64);
	ATF_TP_ADD_TC(tp, retryable);
	ATF_TP_ADD_TC(tp, rpc_status);
	ATF_TP_ADD_TC(tp, partial_success);
	ATF_TP_ADD_TC(tp, gzip);
	ATF_TP_ADD_TC(tp, transcode_fixtures);
	ATF_TP_ADD_TC(tp, transcode_depth);
	ATF_TP_ADD_TC(tp, transcode_encoder_output);
	ATF_TP_ADD_TC(tp, grpc_ok);
	ATF_TP_ADD_TC(tp, grpc_statuses);
	ATF_TP_ADD_TC(tp, grpc_details_and_messages);
	ATF_TP_ADD_TC(tp, grpc_transport_failures);
	ATF_TP_ADD_TC(tp, grpc_tls);
	ATF_TP_ADD_TC(tp, export_grpc);
	ATF_TP_ADD_TC(tp, export_grpc_failures);
	ATF_TP_ADD_TC(tp, export_http_protobuf);
	ATF_TP_ADD_TC(tp, spool_replay_grpc);
	ATF_TP_ADD_TC(tp, spool_replay_http_protobuf);
	ATF_TP_ADD_TC(tp, spool_untranscodable);
	ATF_TP_ADD_TC(tp, open_protocols);
	ATF_TP_ADD_TC(tp, config_protocol);
	ATF_TP_ADD_TC(tp, grpc_edges);
	ATF_TP_ADD_TC(tp, export_edges);
	ATF_TP_ADD_TC(tp, oom);
	return (atf_no_error());
}
