/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Unit tests for libotelexport: string buffer, JSON escaping, frame
 * formatting, OTel environment parsing, URL parsing, the stream
 * exporters (text, JSONL, collapsed), output sinks (rotation,
 * durability, write failures), the OTLP JSON Lines file exporter, and
 * the OTLP/HTTP exporter against a loopback collector (retries,
 * spool and resend, TLS).
 *
 * OTLP output is checked by the independent validator in
 * otlp_validate.c (its own JSON parser and schema tables), never by
 * re-reading it with library code.  Allocation-failure paths are
 * driven through the linker's --wrap of the allocator.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_otlpenc.h"
#include "otlp_validate.h"
#include "otel_testutil.h"

ATF_TC_WITHOUT_HEAD(buf_basic);
ATF_TC_BODY(buf_basic, tc)
{
	struct oe_buf b;
	int i;

	oe_buf_init(&b);
	ATF_REQUIRE_EQ(0, oe_buf_appendstr(&b, "hello"));
	ATF_REQUIRE_EQ(0, oe_buf_appendf(&b, " %d %s", 42, "world"));
	ATF_REQUIRE_STREQ("hello 42 world", b.data);
	ATF_REQUIRE_EQ(strlen("hello 42 world"), b.len);
	/* Force several growth cycles. */
	for (i = 0; i < 1000; i++)
		ATF_REQUIRE_EQ(0, oe_buf_appendstr(&b, "0123456789"));
	ATF_REQUIRE_EQ(strlen("hello 42 world") + 10000, b.len);
	ATF_REQUIRE_EQ(0, b.error);
	oe_buf_free(&b);
	ATF_REQUIRE_EQ(0, b.len);
}

ATF_TC_WITHOUT_HEAD(json_escaping);
ATF_TC_BODY(json_escaping, tc)
{
	struct oe_buf b;

	oe_buf_init(&b);
	oe_buf_appendjson(&b, "a\"b\\c\nd\te\rf\bg\fh");
	ATF_REQUIRE_STREQ("a\\\"b\\\\c\\nd\\te\\rf\\bg\\fh", b.data);
	oe_buf_free(&b);

	/* Control characters below 0x20 become \u00xx. */
	oe_buf_init(&b);
	oe_buf_appendjson(&b, "x\001y\037z");
	ATF_REQUIRE_STREQ("x\\u0001y\\u001fz", b.data);
	oe_buf_free(&b);

	/*
	 * Bytes >= 0x80 are escaped: DTrace strings are arbitrary
	 * bytes, and raw non-UTF-8 would make the document invalid
	 * JSON.  (Lossy for real UTF-8, but always valid.)
	 */
	oe_buf_init(&b);
	oe_buf_appendjson(&b, "caf\xc3\xa9");
	ATF_REQUIRE_STREQ("caf\\u00c3\\u00a9", b.data);
	oe_buf_free(&b);

	/* NULL is a no-op. */
	oe_buf_init(&b);
	ATF_REQUIRE_EQ(0, oe_buf_appendjson(&b, NULL));
	ATF_REQUIRE_EQ(0, b.len);
	oe_buf_free(&b);
}

ATF_TC_WITHOUT_HEAD(frame_format);
ATF_TC_BODY(frame_format, tc)
{
	struct oe_frame f;
	char buf[256];

	memset(&f, 0, sizeof(f));
	f.module = __DECONST(char *, "kernel");
	f.symbol = __DECONST(char *, "vn_open");
	f.offset = 0x42;
	f.has_offset = 1;
	oe_frame_format(&f, buf, sizeof(buf));
	ATF_REQUIRE_STREQ("kernel`vn_open+0x42", buf);

	f.has_offset = 0;
	oe_frame_format(&f, buf, sizeof(buf));
	ATF_REQUIRE_STREQ("kernel`vn_open", buf);

	memset(&f, 0, sizeof(f));
	f.symbol = __DECONST(char *, "malloc");
	oe_frame_format(&f, buf, sizeof(buf));
	ATF_REQUIRE_STREQ("malloc", buf);

	memset(&f, 0, sizeof(f));
	f.addr = 0xdeadbeef;
	oe_frame_format(&f, buf, sizeof(buf));
	ATF_REQUIRE_STREQ("0x00000000deadbeef", buf);
}

ATF_TC_WITHOUT_HEAD(env_parsing);
ATF_TC_BODY(env_parsing, tc)
{
	struct oe_env env;

	setenv("OTEL_SERVICE_NAME", "mysvc", 1);
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318", 1);
	setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "2500", 1);
	setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "none", 1);
	setenv("OTEL_RESOURCE_ATTRIBUTES", " env = prod ,team=kernel,,", 1);
	setenv("OTEL_EXPORTER_OTLP_HEADERS",
	    "Authorization=Basic%20dXNlcjpwYXNz", 1);
	oe_env_load(&env);
	ATF_REQUIRE_STREQ("mysvc", env.service_name);
	ATF_REQUIRE_STREQ("http://collector:4318", env.endpoint);
	ATF_REQUIRE_STREQ("none", env.compression);
	ATF_REQUIRE_EQ(2500, env.timeout_ms);
	/* Blanks trimmed, empty entries tolerated. */
	ATF_REQUIRE_EQ(2, env.nresource_attrs);
	ATF_REQUIRE_STREQ("env", env.resource_attrs[0].name);
	ATF_REQUIRE_STREQ("prod", env.resource_attrs[0].value);
	ATF_REQUIRE_STREQ("team", env.resource_attrs[1].name);
	/* Values are percent-decoded (W3C Baggage format). */
	ATF_REQUIRE_EQ(1, env.nheaders);
	ATF_REQUIRE_STREQ("Authorization", env.headers[0].name);
	ATF_REQUIRE_STREQ("Basic dXNlcjpwYXNz", env.headers[0].value);
	oe_env_free(&env);

	/* Empty strings count as unset. */
	setenv("OTEL_SERVICE_NAME", "", 1);
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "", 1);
	unsetenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	unsetenv("OTEL_EXPORTER_OTLP_COMPRESSION");
	setenv("OTEL_RESOURCE_ATTRIBUTES", "", 1);
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	oe_env_load(&env);
	ATF_REQUIRE(env.service_name == NULL);
	ATF_REQUIRE(env.endpoint == NULL);
	ATF_REQUIRE(env.compression == NULL);
	ATF_REQUIRE_EQ(-1, env.timeout_ms);
	ATF_REQUIRE_EQ(0, env.nresource_attrs);
	ATF_REQUIRE_EQ(0, env.nheaders);
	oe_env_free(&env);
}

/*
 * Malformed variables are rejected whole, per the OTel spec, and
 * never half-applied; header values that could inject request lines
 * are refused.
 */
ATF_TC_WITHOUT_HEAD(env_malformed);
ATF_TC_BODY(env_malformed, tc)
{
	static const char *const bad_attrs[] = {
		"noequals,a=b", "=v", "a=%zz", "a=%4", "k%=v",
	};
	static const char *const bad_headers[] = {
		"X-Evil=a%0d%0aHost: x", "Bad Name=v", "X=a%01b", "=v",
		"(x)=1",
	};
	static const char *const bad_timeouts[] = {
		"abc", "-5", "10ms", "", "99999999999999999999",
	};
	struct oe_env env;
	size_t i;

	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	for (i = 0; i < nitems(bad_attrs); i++) {
		setenv("OTEL_RESOURCE_ATTRIBUTES", bad_attrs[i], 1);
		oe_env_load(&env);
		ATF_REQUIRE_EQ_MSG(0, env.nresource_attrs, "%s",
		    bad_attrs[i]);
		ATF_REQUIRE(env.resource_attrs == NULL);
		oe_env_free(&env);
	}
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
	for (i = 0; i < nitems(bad_headers); i++) {
		setenv("OTEL_EXPORTER_OTLP_HEADERS", bad_headers[i], 1);
		oe_env_load(&env);
		ATF_REQUIRE_EQ_MSG(0, env.nheaders, "%s", bad_headers[i]);
		oe_env_free(&env);
	}
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
	for (i = 0; i < nitems(bad_timeouts); i++) {
		setenv("OTEL_EXPORTER_OTLP_TIMEOUT", bad_timeouts[i], 1);
		oe_env_load(&env);
		ATF_REQUIRE_EQ_MSG(-1, env.timeout_ms, "%s", bad_timeouts[i]);
		oe_env_free(&env);
	}
	unsetenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "brotli", 1);
	oe_env_load(&env);
	ATF_REQUIRE(env.compression == NULL);
	oe_env_free(&env);
	setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "GZIP", 1);
	oe_env_load(&env);
	ATF_REQUIRE_STREQ("GZIP", env.compression);
	oe_env_free(&env);
	unsetenv("OTEL_EXPORTER_OTLP_COMPRESSION");

	/* Allocation failure while parsing drops the variable. */
	setenv("OTEL_RESOURCE_ATTRIBUTES", "a=b,c=d", 1);
	for (i = 1; i <= 6; i++) {
		failalloc_arm((int)i);
		oe_env_load(&env);
		failalloc_arm(0);
		ATF_REQUIRE(env.nresource_attrs == 0 ||
		    env.nresource_attrs == 2);
		oe_env_free(&env);
	}
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
}

ATF_TC_WITHOUT_HEAD(url_parse);
ATF_TC_BODY(url_parse, tc)
{
	struct oe_url u;

	ATF_REQUIRE_EQ(0, oe_url_parse("http://localhost:4318", &u));
	ATF_REQUIRE_EQ(0, u.tls);
	ATF_REQUIRE_EQ(4318, u.port);
	ATF_REQUIRE_STREQ("localhost", u.host);
	ATF_REQUIRE_STREQ("", u.basepath);

	ATF_REQUIRE_EQ(0, oe_url_parse("https://otlp.example.com/otlp/",
	    &u));
	ATF_REQUIRE_EQ(1, u.tls);
	ATF_REQUIRE_EQ(443, u.port);
	ATF_REQUIRE_STREQ("otlp.example.com", u.host);
	/* Trailing slash is dropped for clean path joins. */
	ATF_REQUIRE_STREQ("/otlp", u.basepath);

	ATF_REQUIRE_EQ(0, oe_url_parse("http://10.0.0.1:80/base", &u));
	ATF_REQUIRE_STREQ("/base", u.basepath);

	/* Bracketed IPv6 literals, with and without a port. */
	ATF_REQUIRE_EQ(0, oe_url_parse("http://[::1]:4318/v", &u));
	ATF_REQUIRE_STREQ("::1", u.host);
	ATF_REQUIRE_EQ(4318, u.port);
	ATF_REQUIRE_EQ(0, oe_url_parse("https://[fe80::1]", &u));
	ATF_REQUIRE_STREQ("fe80::1", u.host);
	ATF_REQUIRE_EQ(443, u.port);
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://[::1", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://[::1]x", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://[::1]:0", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://h:0/", &u));
	{
		char longurl[1200];

		/* Over-long host or path is refused, not truncated. */
		memset(longurl, 0, sizeof(longurl));
		strcpy(longurl, "http://");
		memset(longurl + 7, 'h', 300);
		ATF_REQUIRE_EQ(-1, oe_url_parse(longurl, &u));
		strcpy(longurl, "http://h/");
		memset(longurl + 9, 'p', 600);
		ATF_REQUIRE_EQ(-1, oe_url_parse(longurl, &u));
	}
	ATF_REQUIRE_EQ(-1, oe_url_parse("ftp://host/", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("http://host:99999", &u));
	ATF_REQUIRE_EQ(-1, oe_url_parse("localhost:4318", &u));
}

static struct oe_event
make_event(void)
{
	static struct oe_frame kframes[2] = {
		{ 0, __DECONST(char *, "kernel"),
		  __DECONST(char *, "vn_open"), 0x42, 1 },
		{ 0, __DECONST(char *, "kernel"),
		  __DECONST(char *, "syscall"), 0, 0 },
	};
	static struct oe_frame uframes[1] = {
		{ 0xdeadbeef, NULL, NULL, 0, 0 },
	};
	struct oe_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.ts.tv_sec = 1700000000;
	ev.profile = "test-prof";
	ev.probe = "syscall::open:entry";
	ev.pid = 123;
	ev.execname = "nginx";
	ev.body = "nginx[123]: opened \"/etc/passwd\"";
	ev.stack = kframes;
	ev.nstack = 2;
	ev.ustack = uframes;
	ev.nustack = 1;
	return (ev);
}

ATF_TC_WITHOUT_HEAD(text_exporter);
ATF_TC_BODY(text_exporter, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	ATF_REQUIRE(fp != NULL);
	e = oe_text_new(fp);
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_start(e));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE_STREQ(
	    "nginx[123]: opened \"/etc/passwd\"\n"
	    "    [k] kernel`vn_open+0x42\n"
	    "    [k] kernel`syscall\n"
	    "    [u] 0x00000000deadbeef\n", out);
	free(out);
}

ATF_TC_WITHOUT_HEAD(text_exporter_empty_body);
ATF_TC_BODY(text_exporter_empty_body, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_text_new(fp);
	ev = make_event();
	ev.body = NULL;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.body = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);
	/* Events without a body are dropped, not printed. */
	ATF_REQUIRE_EQ(0, outlen);
	free(out);
}

ATF_TC_WITHOUT_HEAD(jsonl_exporter);
ATF_TC_BODY(jsonl_exporter, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "test-prof");
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);

	ATF_REQUIRE(strstr(out, "\"profile\":\"test-prof\"") != NULL);
	ATF_REQUIRE(strstr(out,
	    "\"body\":\"nginx[123]: opened \\\"/etc/passwd\\\"\"") != NULL);
	ATF_REQUIRE(strstr(out,
	    "\"stack\":[\"kernel`vn_open+0x42\",\"kernel`syscall\"]") !=
	    NULL);
	ATF_REQUIRE(strstr(out,
	    "\"ustack\":[\"0x00000000deadbeef\"]") != NULL);
	/* One line, newline-terminated. */
	ATF_REQUIRE_EQ('\n', out[outlen - 1]);
	ATF_REQUIRE(strchr(out, '\n') == out + outlen - 1);
	free(out);
}

ATF_TC_WITHOUT_HEAD(collapsed_exporter);
ATF_TC_BODY(collapsed_exporter, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_collapsed_new(fp);
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	/* Same stack twice folds to count 2. */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* Different execname is a different folded line. */
	ev.execname = "apache";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* No stacks at all: ignored. */
	ev.nstack = 0;
	ev.nustack = 0;
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);

	/*
	 * Frames are root-first (reversed), kernel below user with a
	 * "--" separator, sorted by stack path.
	 */
	ATF_REQUIRE_STREQ(
	    "apache;kernel`syscall;kernel`vn_open+0x42;--;"
	    "0x00000000deadbeef 1\n"
	    "nginx;kernel`syscall;kernel`vn_open+0x42;--;"
	    "0x00000000deadbeef 2\n", out);
	free(out);
}

ATF_TC_WITHOUT_HEAD(iso8601_shape);
ATF_TC_BODY(iso8601_shape, tc)
{
	struct timespec ts;
	char buf[64];

	ts.tv_sec = 1700000000;
	ts.tv_nsec = 123456789;
	oe_iso8601(&ts, buf, sizeof(buf));
	/* YYYY-MM-DDTHH:MM:SS.mmm+ZZ:ZZ — check the punctuation. */
	ATF_REQUIRE_EQ('-', buf[4]);
	ATF_REQUIRE_EQ('-', buf[7]);
	ATF_REQUIRE_EQ('T', buf[10]);
	ATF_REQUIRE_EQ(':', buf[13]);
	ATF_REQUIRE_EQ(':', buf[16]);
	ATF_REQUIRE_EQ('.', buf[19]);
	ATF_REQUIRE(strstr(buf, ".123") != NULL);
}

ATF_TC_WITHOUT_HEAD(otlp_config_validation);
ATF_TC_BODY(otlp_config_validation, tc)
{
	struct oe_resource res;
	struct oe_otlp_config cfg;
	struct oe_exporter *e;

	memset(&res, 0, sizeof(res));
	res.service_name = "t";
	res.host_name = "h";
	res.host_arch = "amd64";
	res.os_name = "freebsd";
	res.os_version = "16";
	res.service_version = "0";

	/* Invalid endpoint URL is rejected at construction. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = "gopher://x";
	cfg.profile = "p";
	cfg.resource = &res;
	e = oe_otlp_new(&cfg);
	ATF_REQUIRE(e == NULL);

	/* Valid config constructs and can be torn down unstarted. */
	cfg.endpoint = "http://localhost:1";
	e = oe_otlp_new(&cfg);
	ATF_REQUIRE(e != NULL);
	/* Nothing batched: shutdown must not attempt a POST. */
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
}

/* ---------------------------------------------------------------- */
/* Shared fixtures							*/

static const struct oe_resource test_resource = {
	.service_name = "t",
	.service_instance_id = NULL,
	.host_name = "h",
	.host_arch = "amd64",
	.os_name = "freebsd",
	.os_version = "16",
	.service_version = "0",
};

static char *
slurp(const char *path, size_t *lenp)
{
	FILE *fp;
	char *buf;
	long n;

	fp = fopen(path, "r");
	if (fp == NULL)
		return (NULL);
	fseek(fp, 0, SEEK_END);
	n = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = malloc((size_t)n + 1);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE_EQ((size_t)n, fread(buf, 1, (size_t)n, fp));
	buf[n] = '\0';
	fclose(fp);
	if (lenp != NULL)
		*lenp = (size_t)n;
	return (buf);
}

/*
 * Validate every line of an OTLP JSON Lines text with the independent
 * validator; optionally match it line by line against a golden file
 * from the source directory.
 */
static struct otlp_counts
check_otlp_lines(const atf_tc_t *tc, const char *text, const char *golden)
{
	struct otlp_counts c;
	struct jv *v, *g;
	char err[1024], path[PATH_MAX], *gtext, *gline, *glast, *copy,
	    *line, *last;
	int lineno;

	memset(&c, 0, sizeof(c));
	gtext = NULL;
	gline = NULL;
	glast = NULL;
	if (golden != NULL) {
		snprintf(path, sizeof(path), "%s/golden/%s",
		    atf_tc_get_config_var(tc, "srcdir"), golden);
		gtext = slurp(path, NULL);
		ATF_REQUIRE_MSG(gtext != NULL, "golden %s missing", path);
		gline = strtok_r(gtext, "\n", &glast);
	}
	copy = strdup(text);
	ATF_REQUIRE(copy != NULL);
	lineno = 0;
	for (line = strtok_r(copy, "\n", &last); line != NULL;
	    line = strtok_r(NULL, "\n", &last)) {
		lineno++;
		v = jv_parse(line, strlen(line), err, sizeof(err));
		ATF_REQUIRE_MSG(v != NULL, "line %d: %s", lineno, err);
		ATF_REQUIRE_MSG(otlp_validate_request(v, &c, err,
		    sizeof(err)) == 0, "line %d: %s", lineno, err);
		if (golden != NULL) {
			ATF_REQUIRE_MSG(gline != NULL, "line %d beyond golden",
			    lineno);
			g = jv_parse(gline, strlen(gline), err, sizeof(err));
			ATF_REQUIRE_MSG(g != NULL, "golden %d: %s", lineno,
			    err);
			ATF_REQUIRE_MSG(jv_match(g, v, err, sizeof(err)) == 0,
			    "line %d vs golden: %s", lineno, err);
			jv_free(g);
			gline = strtok_r(NULL, "\n", &glast);
		}
		jv_free(v);
	}
	if (golden != NULL)
		ATF_REQUIRE_MSG(gline == NULL, "golden has more lines than "
		    "output (%d)", lineno);
	free(copy);
	free(gtext);
	return (c);
}

static struct oe_snapshot
make_snapshot(enum oe_agg_kind kind, const char *name)
{
	static struct oe_attr attrs[2] = {
		{ "process.executable.name", "nginx" },
		{ "syscall", "read" },
	};
	static struct oe_bucket buckets[3] = {
		{ 7, 4 }, { 1, 2 }, { INT64_MAX, 1 },
	};
	static struct oe_datapoint points[2];
	struct oe_snapshot sn;

	memset(points, 0, sizeof(points));
	points[0].attrs = attrs;
	points[0].nattrs = 2;
	points[0].scalar = 42;
	points[1].attrs = attrs;
	points[1].nattrs = 1;
	points[1].is_histogram = 1;
	points[1].buckets = buckets;
	points[1].nbuckets = 3;
	if (kind >= OE_AGG_QUANTIZE) {
		points[0].is_histogram = 1;
		points[0].buckets = buckets;
		points[0].nbuckets = 3;
	}
	memset(&sn, 0, sizeof(sn));
	sn.ts.tv_sec = 1700000010;
	sn.start.tv_sec = 1700000000;
	sn.profile = "test-prof";
	sn.name = name;
	sn.kind = kind;
	sn.points = points;
	sn.npoints = 2;
	return (sn);
}

/* ---------------------------------------------------------------- */
/* Stream exporters, more						*/

ATF_TC_WITHOUT_HEAD(text_snapshot);
ATF_TC_BODY(text_snapshot, tc)
{
	struct oe_exporter *e;
	struct oe_snapshot sn;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_text_new(fp);
	ATF_REQUIRE(e != NULL);
	sn = make_snapshot(OE_AGG_COUNT, "calls");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn = make_snapshot(OE_AGG_QUANTIZE, "lat");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "--- aggregation: @calls (count) "
	    "profile=test-prof ---\n  [nginx, read] 42\n") != NULL);
	ATF_REQUIRE(strstr(out, "@lat (quantize)") != NULL);
	ATF_REQUIRE(strstr(out, "    <= 7: 4\n") != NULL);
	free(out);
}

ATF_TC_WITHOUT_HEAD(jsonl_observed_probe);
ATF_TC_BODY(jsonl_observed_probe, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	FILE *fp;
	char *out;
	size_t outlen;

	fp = open_memstream(&out, &outlen);
	e = oe_jsonl_new(fp, "test-prof");
	ev = make_event();
	ev.ts.tv_nsec = 5000000;
	ev.observed.tv_sec = 1700000001;
	ATF_REQUIRE_EQ(0, oe_start(e));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* Snapshots are not part of the JSONL event stream. */
	sn = make_snapshot(OE_AGG_SUM, "bytes");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ev.body = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	oe_shutdown(e);
	oe_exporter_free(e);
	fclose(fp);
	ATF_REQUIRE(strstr(out, "\"time\":\"2023-11-14T22:13:20.005Z\"") !=
	    NULL);
	ATF_REQUIRE(strstr(out, "\"observed\":\"2023-11-14T22:13:21.000Z\"")
	    != NULL);
	ATF_REQUIRE(strstr(out, "\"probe\":\"syscall::open:entry\"") != NULL);
	ATF_REQUIRE_EQ('\n', out[outlen - 1]);
	ATF_REQUIRE(strchr(out, '\n') == out + outlen - 1);
	free(out);
}

/* ---------------------------------------------------------------- */
/* Sinks								*/

static size_t
count_lines(const char *path)
{
	char *t, *p;
	size_t n = 0;

	t = slurp(path, NULL);
	if (t == NULL)
		return ((size_t)-1);
	for (p = t; *p != '\0'; p++)
		if (*p == '\n')
			n++;
	free(t);
	return (n);
}

ATF_TC_WITHOUT_HEAD(sink_stream_default);
ATF_TC_BODY(sink_stream_default, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;

	memset(&sc, 0, sizeof(sc));
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE(oe_sink_stream(s) == stdout);
	ATF_REQUIRE(oe_sink_path(s) == NULL);
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "", 0));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	sc.path = "-";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL && oe_sink_stream(s) == stdout);
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_REQUIRE_EQ(0, oe_sink_close(NULL));
}

ATF_TC_WITHOUT_HEAD(sink_rotate_size);
ATF_TC_BODY(sink_rotate_size, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct stat st;
	char rec[64];
	int i;

	memset(&sc, 0, sizeof(sc));
	sc.path = "out.log";
	sc.rotate_size = 100;
	sc.rotate_keep = 3;
	sc.durable = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_STREQ("out.log", oe_sink_path(s));
	/* 30 records of 30 bytes: 3 per 100-byte file, never split. */
	for (i = 0; i < 30; i++) {
		snprintf(rec, sizeof(rec), "record %02d %19s\n", i, "x");
		ATF_REQUIRE_EQ(30, strlen(rec));
		ATF_REQUIRE_EQ(0, oe_sink_write(s, rec, strlen(rec)));
	}
	ATF_REQUIRE_EQ(0, oe_sink_flush(s));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_REQUIRE_EQ(3, count_lines("out.log"));
	ATF_REQUIRE_EQ(3, count_lines("out.log.1"));
	ATF_REQUIRE_EQ(3, count_lines("out.log.3"));
	/* Only rotate_keep rotated files survive. */
	ATF_REQUIRE(stat("out.log.4", &st) != 0 && errno == ENOENT);
	/* The newest rotated file holds the records just before. */
	{
		char *t = slurp("out.log.1", NULL);

		ATF_REQUIRE(strncmp(t, "record 24", 9) == 0);
		free(t);
	}
	/* A record larger than the limit still goes out whole. */
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	memset(rec, 'y', 63);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, rec, 63));
	ATF_REQUIRE_EQ(0, oe_sink_write(s, rec, 63));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_REQUIRE(stat("out.log", &st) == 0 && st.st_size == 63);
}

ATF_TC_WITHOUT_HEAD(sink_rotate_interval);
ATF_TC_BODY(sink_rotate_interval, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct stat st;

	memset(&sc, 0, sizeof(sc));
	sc.path = "t.log";
	sc.rotate_interval = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "a\n", 2));
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE(stat("t.log.1", &st) != 0);
	sleep(2);
	/* Age rotation happens at the next record boundary... */
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "b\n", 2));
	ATF_REQUIRE(stat("t.log.1", &st) == 0 && st.st_size == 2);
	sleep(2);
	/* ...or when polled. */
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE(stat("t.log.2", &st) == 0);
	ATF_REQUIRE(stat("t.log", &st) == 0 && st.st_size == 0);
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
}

/*
 * A writer that bypasses oe_sink_write (libdtrace text output writes
 * to the stream directly) is caught up by oe_sink_poll().
 */
ATF_TC_WITHOUT_HEAD(sink_poll_external_writer);
ATF_TC_BODY(sink_poll_external_writer, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct stat st;

	memset(&sc, 0, sizeof(sc));
	sc.path = "x.log";
	sc.rotate_size = 10;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	fputs("0123456789abc\n", oe_sink_stream(s));
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE(stat("x.log.1", &st) == 0 && st.st_size == 14);
	ATF_REQUIRE(stat("x.log", &st) == 0 && st.st_size == 0);
	/* Nothing new: no further rotation. */
	ATF_REQUIRE_EQ(0, oe_sink_poll(s));
	ATF_REQUIRE(stat("x.log.2", &st) != 0);
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
}

ATF_TC_WITHOUT_HEAD(sink_append_existing);
ATF_TC_BODY(sink_append_existing, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	FILE *fp;

	fp = fopen("a.log", "w");
	fputs("old line one\n", fp);
	fclose(fp);
	memset(&sc, 0, sizeof(sc));
	sc.path = "a.log";
	sc.rotate_size = 20;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	/* Existing size counts: 13 + 13 > 20 rotates first. */
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "new line one\n", 13));
	ATF_REQUIRE_EQ(0, oe_sink_close(s));
	ATF_REQUIRE_EQ(1, count_lines("a.log.1"));
	ATF_REQUIRE_EQ(1, count_lines("a.log"));
}

ATF_TC_WITHOUT_HEAD(sink_open_errors);
ATF_TC_BODY(sink_open_errors, tc)
{
	struct oe_sink_config sc;
	char longpath[PATH_MAX + 10];

	memset(&sc, 0, sizeof(sc));
	/* Missing directory. */
	sc.path = "nodir/out.log";
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	/* A directory and a device are not rotatable regular files. */
	ATF_REQUIRE_EQ(0, mkdir("adir", 0755));
	sc.path = "adir";
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	sc.path = "/dev/null";
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	/* No room for the rotation suffix. */
	memset(longpath, 'p', sizeof(longpath) - 1);
	longpath[sizeof(longpath) - 1] = '\0';
	sc.path = longpath;
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	/* Keep count bound. */
	sc.path = "k.log";
	sc.rotate_keep = 1000;
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	sc.rotate_keep = 0;
	/* Absolute paths and paths in "/" keep their directory. */
	{
		struct oe_sink *s;
		char cwd[PATH_MAX], abs[PATH_MAX + 16];

		ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
		snprintf(abs, sizeof(abs), "%s/abs.log", cwd);
		sc.path = abs;
		sc.durable = 1;
		sc.rotate_size = 1;
		s = oe_sink_open(&sc);
		ATF_REQUIRE(s != NULL);
		ATF_REQUIRE_EQ(0, oe_sink_write(s, "1\n", 2));
		ATF_REQUIRE_EQ(0, oe_sink_write(s, "2\n", 2));
		ATF_REQUIRE_EQ(0, oe_sink_close(s));
		ATF_REQUIRE_EQ(1, count_lines("abs.log.1"));
		/* "/" as the directory is accepted at open time. */
		sc.path = "/nonexistent-otel-test-file";
		sc.durable = 0;
		ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	}
	/* Allocation failures at open. */
	sc.path = "m.log";
	for (int i = 1; i <= 3; i++) {
		failalloc_arm(i);
		ATF_REQUIRE(oe_sink_open(&sc) == NULL);
		failalloc_arm(0);
	}
}

ATF_TC(sink_unwritable);
ATF_TC_HEAD(sink_unwritable, tc)
{

	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(sink_unwritable, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;

	ATF_REQUIRE_EQ(0, mkdir("ro", 0755));
	memset(&sc, 0, sizeof(sc));
	sc.path = "ro/out.log";
	sc.rotate_size = 4;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "abcd", 4));
	/* Rotation needs to rename inside the directory. */
	ATF_REQUIRE_EQ(0, chmod("ro", 0555));
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, "efgh", 4));
	/* The error is sticky. */
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, "i", 1));
	ATF_REQUIRE_EQ(-1, oe_sink_flush(s));
	ATF_REQUIRE_EQ(-1, oe_sink_poll(s));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	/* And an unwritable file cannot be opened at all. */
	sc.path = "ro/new.log";
	ATF_REQUIRE(oe_sink_open(&sc) == NULL);
	ATF_REQUIRE_EQ(0, chmod("ro", 0755));
}

/*
 * Disk-full style failure: RLIMIT_FSIZE makes the kernel refuse the
 * write past the limit (EFBIG), exactly as a full disk refuses it
 * with ENOSPC, without interposing on libc.
 */
ATF_TC_WITHOUT_HEAD(sink_write_efbig);
ATF_TC_BODY(sink_write_efbig, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *s;
	struct rlimit rl;
	char big[8192];

	signal(SIGXFSZ, SIG_IGN);
	rl.rlim_cur = 4096;
	rl.rlim_max = RLIM_INFINITY;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_FSIZE, &rl));
	memset(&sc, 0, sizeof(sc));
	sc.path = "full.log";
	sc.durable = 1;
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	memset(big, 'z', sizeof(big));
	/* stdio may buffer the first write; the flush must fail. */
	if (oe_sink_write(s, big, sizeof(big)) == 0)
		ATF_REQUIRE_EQ(-1, oe_sink_flush(s));
	ATF_REQUIRE_EQ(-1, oe_sink_write(s, "x", 1));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));

	/*
	 * The same failure surfaces at close when nothing flushed.  The
	 * kernel refuses a write crossing the limit outright, so fill
	 * the file to exactly the limit first.
	 */
	{
		int fd = open("full.log", O_WRONLY | O_TRUNC);

		ATF_REQUIRE_EQ(4096, write(fd, big, 4096));
		close(fd);
	}
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	ATF_REQUIRE_EQ(0, oe_sink_write(s, "x", 1));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	/* And through the poll path. */
	sc.path = "full2.log";
	s = oe_sink_open(&sc);
	ATF_REQUIRE(s != NULL);
	fwrite(big, 1, 4000, oe_sink_stream(s));
	fwrite(big, 1, 4000, oe_sink_stream(s));
	ATF_REQUIRE_EQ(-1, oe_sink_poll(s));
	ATF_REQUIRE_EQ(-1, oe_sink_close(s));
	rl.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &rl);
}

static int
enospc_write(void *cookie __unused, const char *buf __unused, int len
    __unused)
{

	errno = ENOSPC;
	return (-1);
}

/* A borrowed stream whose writes fail with ENOSPC. */
ATF_TC_WITHOUT_HEAD(sink_stream_enospc);
ATF_TC_BODY(sink_stream_enospc, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	FILE *fp;

	fp = fwopen(NULL, enospc_write);
	ATF_REQUIRE(fp != NULL);
	setvbuf(fp, NULL, _IONBF, 0);
	ev = make_event();
	e = oe_text_new(fp);
	ATF_REQUIRE_EQ(-1, oe_event(e, &ev));
	sn = make_snapshot(OE_AGG_COUNT, "c");
	ATF_REQUIRE_EQ(-1, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(-1, oe_flush(e));
	oe_exporter_free(e);
	e = oe_jsonl_new(fp, "p");
	ATF_REQUIRE_EQ(-1, oe_event(e, &ev));
	ATF_REQUIRE_EQ(-1, oe_shutdown(e));
	oe_exporter_free(e);
	e = oe_collapsed_new(fp);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(-1, oe_shutdown(e));
	oe_exporter_free(e);
	fclose(fp);
}

ATF_TC_WITHOUT_HEAD(exporters_alloc_failure);
ATF_TC_BODY(exporters_alloc_failure, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	FILE *fp;
	char *out;
	size_t outlen;
	int i, ret;

	fp = open_memstream(&out, &outlen);
	ev = make_event();
	sn = make_snapshot(OE_AGG_QUANTIZE, "q");
	/* Constructors fail cleanly at every allocation. */
	for (i = 1; i <= 4; i++) {
		failalloc_arm(i);
		e = oe_text_new(fp);
		failalloc_arm(0);
		if (e != NULL)
			oe_exporter_free(e);
		failalloc_arm(i);
		e = oe_jsonl_new(fp, "p");
		failalloc_arm(0);
		if (e != NULL)
			oe_exporter_free(e);
		failalloc_arm(i);
		e = oe_collapsed_new(fp);
		failalloc_arm(0);
		if (e != NULL)
			oe_exporter_free(e);
	}
	/* Operations report failure instead of writing partial output. */
	for (i = 1; i <= 8; i++) {
		e = oe_collapsed_new(fp);
		ATF_REQUIRE(e != NULL);
		failalloc_arm(i);
		ret = oe_event(e, &ev);
		failalloc_arm(0);
		ATF_REQUIRE(ret == 0 || ret == -1);
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		failalloc_arm(i);
		ret = oe_shutdown(e);
		failalloc_arm(0);
		oe_exporter_free(e);

		e = oe_text_new(fp);
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		failalloc_arm(0);
		failalloc_arm(i);
		(void)oe_snapshot(e, &sn);
		failalloc_arm(0);
		oe_exporter_free(e);

		e = oe_jsonl_new(fp, "p");
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		failalloc_arm(0);
		oe_exporter_free(e);
	}
	fclose(fp);
	free(out);
}

/* ---------------------------------------------------------------- */
/* OTLP JSON Lines file exporter				 	*/

static struct oe_exporter *
otlpjson_on(struct oe_sink *sink, int batch)
{
	struct oe_otlpjson_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.sink = sink;
	cfg.profile = "test-prof";
	cfg.resource = &test_resource;
	cfg.batch_size = batch;
	return (oe_otlpjson_new(&cfg));
}

static void
fixed_event_times(struct oe_event *ev)
{

	ev->ts.tv_sec = 1700000000;
	ev->ts.tv_nsec = 5;
	ev->observed.tv_sec = 1700000001;
	ev->observed.tv_nsec = 0;
}

ATF_TC_WITHOUT_HEAD(otlpjson_golden);
ATF_TC_BODY(otlpjson_golden, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	struct otlp_counts c;
	char *text;
	enum oe_agg_kind k;

	memset(&sc, 0, sizeof(sc));
	sc.path = "out.jsonl";
	sc.durable = 1;
	sink = oe_sink_open(&sc);
	ATF_REQUIRE(sink != NULL);
	e = otlpjson_on(sink, 0);
	ATF_REQUIRE(e != NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	ev = make_event();
	fixed_event_times(&ev);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.body = "second \"quoted\"\nline\001";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ev.body = NULL;		/* skipped */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	for (k = OE_AGG_COUNT; k <= OE_AGG_LLQUANTIZE; k++) {
		static const char *const names[] = { "calls", "bytes", "lo",
		    "hi", "", "dev", "lat", "llat", "lllat" };

		/* An anonymous aggregation is named after its kind. */
		sn = make_snapshot(k, names[k]);
		ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	}
	sn.npoints = 0;		/* skipped */
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	oe_exporter_free(e);
	ATF_REQUIRE_EQ(0, oe_sink_close(sink));
	text = slurp("out.jsonl", NULL);
	c = check_otlp_lines(tc, text, "otlpjson-basic.jsonl");
	ATF_REQUIRE_EQ(2, c.requests);
	ATF_REQUIRE_EQ(2, c.logs);
	ATF_REQUIRE_EQ(9, c.metrics);
	free(text);
}

ATF_TC_WITHOUT_HEAD(otlpjson_batching);
ATF_TC_BODY(otlpjson_batching, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct otlp_counts c;
	char *text;
	int i;

	memset(&sc, 0, sizeof(sc));
	sc.path = "b.jsonl";
	sink = oe_sink_open(&sc);
	e = otlpjson_on(sink, 2);
	ev = make_event();
	for (i = 0; i < 5; i++)
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	/* Two full lines are out before any flush. */
	ATF_REQUIRE_EQ(0, oe_sink_flush(sink));
	ATF_REQUIRE_EQ(2, count_lines("b.jsonl"));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(3, count_lines("b.jsonl"));
	/* Flushing with nothing pending writes nothing. */
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(3, count_lines("b.jsonl"));
	oe_exporter_free(e);
	oe_sink_close(sink);
	text = slurp("b.jsonl", NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_REQUIRE_EQ(5, c.logs);
	free(text);
}

ATF_TC_WITHOUT_HEAD(otlpjson_errors);
ATF_TC_BODY(otlpjson_errors, tc)
{
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	FILE *fp;
	int i;

	/* Write failure surfaces from the call that hit it. */
	fp = fwopen(NULL, enospc_write);
	setvbuf(fp, NULL, _IONBF, 0);
	memset(&sc, 0, sizeof(sc));
	sc.fp = fp;
	sink = oe_sink_open(&sc);
	e = otlpjson_on(sink, 1);
	ev = make_event();
	ATF_REQUIRE_EQ(-1, oe_event(e, &ev));
	ATF_REQUIRE_EQ(-1, oe_flush(e));
	oe_exporter_free(e);
	oe_sink_close(sink);
	fclose(fp);

	/* Allocation failures: constructor and every queue path. */
	memset(&sc, 0, sizeof(sc));
	sc.path = "e.jsonl";
	sink = oe_sink_open(&sc);
	sn = make_snapshot(OE_AGG_LQUANTIZE, "l");
	for (i = 1; i <= 12; i++) {
		failalloc_arm(i);
		e = otlpjson_on(sink, 2);
		failalloc_arm(0);
		if (e == NULL)
			continue;
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		(void)oe_event(e, &ev);
		failalloc_arm(0);
		failalloc_arm(i);
		(void)oe_snapshot(e, &sn);
		(void)oe_flush(e);
		failalloc_arm(0);
		oe_exporter_free(e);
	}
	oe_sink_close(sink);
}

/* ---------------------------------------------------------------- */
/* OTLP/HTTP exporter against a loopback collector		 	*/

static struct oe_exporter *
otlp_to(int port, const char *scheme, const char *spool, uint64_t spool_max,
    int retries, const char *compression)
{
	static const struct oe_attr hdrs[] = {
		{ "Authorization", "Bearer t0k" },
	};
	struct oe_otlp_config cfg;
	char url[128];

	snprintf(url, sizeof(url), "%s://%s:%d/base/", scheme,
	    strcmp(scheme, "https") == 0 ? "localhost" : "127.0.0.1", port);
	memset(&cfg, 0, sizeof(cfg));
	cfg.endpoint = url;
	cfg.profile = "test-prof";
	cfg.resource = &test_resource;
	cfg.batch_size = 2;
	cfg.flush_interval = 0.1;
	cfg.max_retries = retries;
	cfg.timeout = 2;
	cfg.headers = hdrs;
	cfg.nheaders = 1;
	cfg.compression = compression;
	cfg.spool_path = spool;
	cfg.spool_max = spool_max;
	return (oe_otlp_new(&cfg));
}

/*
 * The HTTP body and the file line for the same input are identical:
 * both come from the shared encoder.
 */
ATF_TC_WITHOUT_HEAD(otlp_http_matches_file);
ATF_TC_BODY(otlp_http_matches_file, tc)
{
	struct collector co;
	struct oe_exporter *e, *f;
	struct oe_sink_config sc;
	struct oe_sink *sink;
	struct oe_event ev;
	struct oe_snapshot sn;
	struct otlp_counts c;
	char *file, *line2;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	e = otlp_to(co.port, "http", NULL, 0, 0, "none");
	ATF_REQUIRE(e != NULL);
	memset(&sc, 0, sizeof(sc));
	sc.path = "same.jsonl";
	sink = oe_sink_open(&sc);
	f = otlpjson_on(sink, 0);
	ev = make_event();
	fixed_event_times(&ev);
	sn = make_snapshot(OE_AGG_SUM, "bytes");
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, oe_event(f, &ev));
	ATF_REQUIRE_EQ(0, oe_snapshot(f, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(f));
	ATF_REQUIRE_EQ(2, coll_nreqs(&co));
	ATF_REQUIRE_STREQ("/base/v1/logs", co.reqs[0].path);
	ATF_REQUIRE_STREQ("/base/v1/metrics", co.reqs[1].path);
	ATF_REQUIRE(!co.reqs[0].gzipped);
	ATF_REQUIRE(strstr(co.reqs[0].headers,
	    "Authorization: Bearer t0k") != NULL);
	ATF_REQUIRE(strstr(co.reqs[0].headers,
	    "Content-Type: application/json") != NULL);
	file = slurp("same.jsonl", NULL);
	line2 = strchr(file, '\n');
	ATF_REQUIRE(line2 != NULL);
	*line2++ = '\0';
	ATF_REQUIRE_STREQ(file, co.reqs[0].body);
	line2[strlen(line2) - 1] = '\0';
	ATF_REQUIRE_STREQ(line2, co.reqs[1].body);
	c = check_otlp_lines(tc, co.reqs[0].body, NULL);
	ATF_REQUIRE_EQ(1, c.logs);
	free(file);
	oe_exporter_free(f);
	oe_sink_close(sink);
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

/* Batching thread, gzip, drop reporting, time-based flush. */
ATF_TC_WITHOUT_HEAD(otlp_http_sender);
ATF_TC_BODY(otlp_http_sender, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	int i;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	e = otlp_to(co.port, "http", NULL, 0, 1, NULL);
	ATF_REQUIRE_EQ(0, oe_start(e));
	ATF_REQUIRE_EQ(0, oe_start(e));		/* idempotent */
	/* Drops with no logs pending are carried to the next batch. */
	oe_report_drops(e, 7);
	usleep(300000);
	ev = make_event();
	ev.body = "";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));	/* empty body: ignored */
	ev = make_event();
	for (i = 0; i < 2; i++)
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, coll_wait(&co, 1, 3000));
	ATF_REQUIRE(co.reqs[0].gzipped);
	ATF_REQUIRE(strstr(co.reqs[0].body,
	    "{\"key\":\"t.drops\",\"value\":{\"intValue\":\"7\"}}") != NULL);
	check_otlp_lines(tc, co.reqs[0].body, NULL);
	/* Time-based flush picks up a lone record and a snapshot. */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	sn = make_snapshot(OE_AGG_MAX, "m");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	sn.npoints = 0;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, coll_wait(&co, 3, 3000));
	/* Drops reported while only metrics are pending survive too. */
	oe_report_drops(e, 3);
	sn.npoints = 2;
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, coll_wait(&co, 4, 3000));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_shutdown(e));
	ATF_REQUIRE_EQ(5, coll_nreqs(&co));
	ATF_REQUIRE(strstr(co.reqs[4].body, "\"t.drops\"") != NULL);
	for (i = 0; i < 5; i++)
		check_otlp_lines(tc, co.reqs[i].body, NULL);
	oe_exporter_free(e);
	/* Drops on a non-OTLP exporter are a no-op. */
	e = oe_text_new(stdout);
	oe_report_drops(e, 1);
	oe_report_drops(NULL, 1);
	oe_exporter_free(e);
	coll_stop(&co);
}

ATF_TC_WITHOUT_HEAD(otlp_http_statuses);
ATF_TC_BODY(otlp_http_statuses, tc)
{
	static const struct coll_reply script[] = {
		/* retryable, honoring Retry-After, then accepted */
		{ 503, "Retry-After: 0\r\n", "busy", 0, 0 },
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedLogRecords\":"
		    " \"3\"}}", 0, 0 },
		/* non-retryable: dropped at once */
		{ 400, NULL, "bad", 0, 0 },
		/* retries exhausted */
		{ 429, NULL, "", 0, 0 },
		{ 502, NULL, "", 0, 0 },
		/* no answer, then garbage, then an unterminated header */
		{ 0, NULL, NULL, 0, 0 },
		{ 200, NULL, NULL, 1, 0 },
		{ 200, NULL, NULL, 0, 1 },
		/* partial success with metrics / spans keys and none */
		{ 200, NULL, "{\"partialSuccess\":{\"rejectedDataPoints\":2}}",
		    0, 0 },
		{ 200, NULL, "{\"partialSuccess\":{}}", 0, 0 },
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	coll_script(&co, script, nitems(script));
	e = otlp_to(co.port, "http", NULL, 0, 1, "gzip");
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* 503 -> 200 */
	ATF_REQUIRE_EQ(2, coll_nreqs(&co));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* 400 */
	ATF_REQUIRE_EQ(3, coll_nreqs(&co));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* 429, 502 */
	ATF_REQUIRE_EQ(5, coll_nreqs(&co));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* close, garbage */
	ATF_REQUIRE_EQ(7, coll_nreqs(&co));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* unterminated: accepted */
	sn = make_snapshot(OE_AGG_COUNT, "c");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(10, coll_nreqs(&co));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

/*
 * Collector unreachable: batches spool to the file (as valid OTLP
 * JSON Lines); once the collector is back, the next accepted request
 * triggers a replay of the spool, oldest first, and the spool
 * empties.
 */
ATF_TC_WITHOUT_HEAD(otlp_spool_resend);
ATF_TC_BODY(otlp_spool_resend, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	struct otlp_counts c;
	struct stat st;
	char *text;
	int port;

	port = closed_port();
	e = otlp_to(port, "http", "spool.jsonl", 0, 1, NULL);
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ev.body = "first";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	sn = make_snapshot(OE_AGG_SUM, "s");
	ATF_REQUIRE_EQ(0, oe_snapshot(e, &sn));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ev.body = "second";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	text = slurp("spool.jsonl", NULL);
	c = check_otlp_lines(tc, text, NULL);
	ATF_REQUIRE_EQ(3, c.requests);
	ATF_REQUIRE_EQ(2, c.logs);
	free(text);

	ATF_REQUIRE_EQ(0, coll_start(&co, port, 0, NULL));
	ev.body = "third";
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	/* third, then the replay of first, s, second. */
	ATF_REQUIRE_EQ(4, coll_nreqs(&co));
	ATF_REQUIRE(strstr(co.reqs[0].body, "\"third\"") != NULL);
	ATF_REQUIRE(strstr(co.reqs[1].body, "\"first\"") != NULL);
	ATF_REQUIRE_STREQ("/base/v1/metrics", co.reqs[2].path);
	ATF_REQUIRE(strstr(co.reqs[3].body, "\"second\"") != NULL);
	ATF_REQUIRE(stat("spool.jsonl", &st) == 0 && st.st_size == 0);
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

/* A spool left by an earlier run, including damage, is replayed. */
ATF_TC_WITHOUT_HEAD(otlp_spool_previous_run);
ATF_TC_BODY(otlp_spool_previous_run, tc)
{
	static const struct coll_reply script[] = {
		{ 200, NULL, "{}", 0, 0 },	/* new batch */
		{ 200, NULL, "{}", 0, 0 },	/* spooled line 1 */
		{ 503, NULL, "", 0, 0 },	/* spooled line 2 fails */
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct stat st;
	FILE *fp;
	char *text;
	const char *good = "{\"resourceLogs\":[]}";

	fp = fopen("old.jsonl", "w");
	fprintf(fp, "%s\nnot otlp\n%s\n{\"resourceSpans\":[]}\n{\"partial",
	    good, good);
	fclose(fp);
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	coll_script(&co, script, nitems(script));
	e = otlp_to(co.port, "http", "old.jsonl", 0, 0, "none");
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	/* new, good #1, (skip garbage), good #2 refused: stop there. */
	ATF_REQUIRE_EQ(3, coll_nreqs(&co));
	text = slurp("old.jsonl", NULL);
	ATF_REQUIRE_MSG(strncmp(text, good, strlen(good)) == 0, "%s", text);
	ATF_REQUIRE_MSG(strstr(text, "resourceSpans") != NULL, "%s", text);
	ATF_REQUIRE(strstr(text, "not otlp") == NULL);
	free(text);
	/* Next success drains the rest; the partial tail is dropped. */
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(6, coll_nreqs(&co));
	ATF_REQUIRE_STREQ("/base/v1/traces", co.reqs[5].path);
	ATF_REQUIRE(stat("old.jsonl", &st) == 0 && st.st_size == 0);
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

ATF_TC_WITHOUT_HEAD(otlp_spool_bounded);
ATF_TC_BODY(otlp_spool_bounded, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct stat st;
	off_t first;
	int port, i;

	port = closed_port();
	/* Room for exactly one request line. */
	e = otlp_to(port, "http", "small.jsonl", 2000, 0, NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE(stat("small.jsonl", &st) == 0 && st.st_size > 0);
	first = st.st_size;
	ATF_REQUIRE(first < 2000);
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(0, oe_event(e, &ev));
		ATF_REQUIRE_EQ(0, oe_flush(e));
	}
	ATF_REQUIRE(stat("small.jsonl", &st) == 0 && st.st_size == first);
	/* Drained: the drop count is reported and reset. */
	ATF_REQUIRE_EQ(0, coll_start(&co, port, 0, NULL));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(2, coll_nreqs(&co));
	ATF_REQUIRE(stat("small.jsonl", &st) == 0 && st.st_size == 0);
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

/* While idle, the sender thread probes the collector and replays. */
ATF_TC(otlp_spool_idle_replay);
ATF_TC_HEAD(otlp_spool_idle_replay, tc)
{

	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(otlp_spool_idle_replay, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	int port;

	port = closed_port();
	e = otlp_to(port, "http", "idle.jsonl", 0, 0, NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, coll_start(&co, port, 0, NULL));
	ATF_REQUIRE_EQ(0, oe_start(e));
	/* The idle cadence is five seconds. */
	ATF_REQUIRE_EQ(0, coll_wait(&co, 1, 15000));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

ATF_TC(otlp_spool_errors);
ATF_TC_HEAD(otlp_spool_errors, tc)
{

	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(otlp_spool_errors, tc)
{
	struct oe_exporter *e;
	struct oe_event ev;
	struct rlimit rl;
	struct stat st;
	char longpath[PATH_MAX + 10];
	int port;

	port = closed_port();
	/* Unusable spool paths fail at construction. */
	ATF_REQUIRE(otlp_to(port, "http", "nodir/s.jsonl", 0, 0, NULL) ==
	    NULL);
	ATF_REQUIRE_EQ(0, mkdir("d", 0755));
	ATF_REQUIRE(otlp_to(port, "http", "d", 0, 0, NULL) == NULL);
	memset(longpath, 's', sizeof(longpath) - 1);
	longpath[sizeof(longpath) - 1] = '\0';
	ATF_REQUIRE(otlp_to(port, "http", longpath, 0, 0, NULL) == NULL);

	/* The spool becomes unwritable during the outage. */
	e = otlp_to(port, "http", "d/s.jsonl", 0, 0, NULL);
	ATF_REQUIRE(e != NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, chmod("d/s.jsonl", 0400));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));		/* open fails: lost */
	ATF_REQUIRE_EQ(0, chmod("d/s.jsonl", 0600));
	/* Disk-full while spooling leaves no partial line behind. */
	signal(SIGXFSZ, SIG_IGN);
	rl.rlim_cur = 100;
	rl.rlim_max = RLIM_INFINITY;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_FSIZE, &rl));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	rl.rlim_cur = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &rl);
	ATF_REQUIRE(stat("d/s.jsonl", &st) == 0 && st.st_size == 0);
	oe_shutdown(e);
	oe_exporter_free(e);
}

/* A replay whose rewrite fails keeps the spool for another try. */
ATF_TC(otlp_spool_rewrite_fail);
ATF_TC_HEAD(otlp_spool_rewrite_fail, tc)
{

	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}
ATF_TC_BODY(otlp_spool_rewrite_fail, tc)
{
	static const struct coll_reply script[] = {
		{ 200, NULL, "{}", 0, 0 },
		{ 200, NULL, "{}", 0, 0 },
		{ 503, NULL, "", 0, 0 },
	};
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	FILE *fp;
	const char *good = "{\"resourceLogs\":[]}";

	ATF_REQUIRE_EQ(0, mkdir("rw", 0755));
	fp = fopen("rw/s.jsonl", "w");
	fprintf(fp, "%s\n%s\n", good, good);
	fclose(fp);
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	coll_script(&co, script, nitems(script));
	e = otlp_to(co.port, "http", "rw/s.jsonl", 0, 0, NULL);
	ATF_REQUIRE(e != NULL);
	/* The temporary sibling cannot be created. */
	ATF_REQUIRE_EQ(0, chmod("rw", 0555));
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(3, coll_nreqs(&co));
	ATF_REQUIRE_EQ(0, chmod("rw", 0755));
	ATF_REQUIRE_EQ(2, count_lines("rw/s.jsonl"));
	/* Full replay with a read-only file: truncate fails. */
	ATF_REQUIRE_EQ(0, chmod("rw/s.jsonl", 0400));
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(0, chmod("rw/s.jsonl", 0600));
	ATF_REQUIRE_EQ(2, count_lines("rw/s.jsonl"));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);
}

ATF_TC_WITHOUT_HEAD(otlp_tls);
ATF_TC_BODY(otlp_tls, tc)
{
	struct collector co, plain;
	struct oe_exporter *e;
	struct oe_event ev;
	char cert[PATH_MAX + 16], cwd[PATH_MAX];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(cert, sizeof(cert), "%s/ca.pem", cwd);
	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 1, cert));
	setenv("SSL_CERT_FILE", cert, 1);
	e = otlp_to(co.port, "https", NULL, 0, 0, NULL);
	ev = make_event();
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	ATF_REQUIRE_EQ(1, coll_nreqs(&co));
	ATF_REQUIRE(co.reqs[0].gzipped);
	check_otlp_lines(tc, co.reqs[0].body, NULL);
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&co);

	/* TLS to a plain HTTP listener: the handshake fails. */
	ATF_REQUIRE_EQ(0, coll_start(&plain, 0, 0, NULL));
	e = otlp_to(plain.port, "https", NULL, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, oe_event(e, &ev));
	ATF_REQUIRE_EQ(0, oe_flush(e));
	oe_shutdown(e);
	oe_exporter_free(e);
	coll_stop(&plain);
	unsetenv("SSL_CERT_FILE");
}

ATF_TC_WITHOUT_HEAD(otlp_alloc_failure);
ATF_TC_BODY(otlp_alloc_failure, tc)
{
	struct collector co;
	struct oe_exporter *e;
	struct oe_event ev;
	struct oe_snapshot sn;
	int i;

	ATF_REQUIRE_EQ(0, coll_start(&co, 0, 0, NULL));
	ev = make_event();
	sn = make_snapshot(OE_AGG_LLQUANTIZE, "ll");
	for (i = 1; i <= 40; i++) {
		failalloc_arm(i);
		e = otlp_to(co.port, "http", "a.jsonl", 0, 0, NULL);
		failalloc_arm(0);
		if (e == NULL)
			continue;
		failalloc_arm(i);
		(void)oe_event(e, &ev);
		(void)oe_event(e, &ev);
		(void)oe_snapshot(e, &sn);
		(void)oe_flush(e);
		failalloc_arm(0);
		oe_shutdown(e);
		oe_exporter_free(e);
	}
	coll_stop(&co);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, buf_basic);
	ATF_TP_ADD_TC(tp, json_escaping);
	ATF_TP_ADD_TC(tp, frame_format);
	ATF_TP_ADD_TC(tp, env_parsing);
	ATF_TP_ADD_TC(tp, url_parse);
	ATF_TP_ADD_TC(tp, text_exporter);
	ATF_TP_ADD_TC(tp, text_exporter_empty_body);
	ATF_TP_ADD_TC(tp, jsonl_exporter);
	ATF_TP_ADD_TC(tp, collapsed_exporter);
	ATF_TP_ADD_TC(tp, iso8601_shape);
	ATF_TP_ADD_TC(tp, otlp_config_validation);
	ATF_TP_ADD_TC(tp, env_malformed);
	ATF_TP_ADD_TC(tp, text_snapshot);
	ATF_TP_ADD_TC(tp, jsonl_observed_probe);
	ATF_TP_ADD_TC(tp, sink_stream_default);
	ATF_TP_ADD_TC(tp, sink_rotate_size);
	ATF_TP_ADD_TC(tp, sink_rotate_interval);
	ATF_TP_ADD_TC(tp, sink_poll_external_writer);
	ATF_TP_ADD_TC(tp, sink_append_existing);
	ATF_TP_ADD_TC(tp, sink_open_errors);
	ATF_TP_ADD_TC(tp, sink_unwritable);
	ATF_TP_ADD_TC(tp, sink_write_efbig);
	ATF_TP_ADD_TC(tp, sink_stream_enospc);
	ATF_TP_ADD_TC(tp, exporters_alloc_failure);
	ATF_TP_ADD_TC(tp, otlpjson_golden);
	ATF_TP_ADD_TC(tp, otlpjson_batching);
	ATF_TP_ADD_TC(tp, otlpjson_errors);
	ATF_TP_ADD_TC(tp, otlp_http_matches_file);
	ATF_TP_ADD_TC(tp, otlp_http_sender);
	ATF_TP_ADD_TC(tp, otlp_http_statuses);
	ATF_TP_ADD_TC(tp, otlp_spool_resend);
	ATF_TP_ADD_TC(tp, otlp_spool_previous_run);
	ATF_TP_ADD_TC(tp, otlp_spool_bounded);
	ATF_TP_ADD_TC(tp, otlp_spool_idle_replay);
	ATF_TP_ADD_TC(tp, otlp_spool_errors);
	ATF_TP_ADD_TC(tp, otlp_spool_rewrite_fail);
	ATF_TP_ADD_TC(tp, otlp_tls);
	ATF_TP_ADD_TC(tp, otlp_alloc_failure);
	return (atf_no_error());
}
